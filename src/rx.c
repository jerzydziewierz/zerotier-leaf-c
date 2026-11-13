/* SPDX-License-Identifier: Apache-2.0 */
#include "ztl/node.h"

_Static_assert(ZTL_PEERS >= 1u && ZTL_PEERS <= 255u, "peer index is stored in 8 bits");
/* RAM budget: all state of the node is in struct ztl_node. Own address and
 * padding 8, each peer 38 (address, flag, key), each reassembly slot one
 * packet and 24, six counters 24. */
_Static_assert(sizeof(struct ztl_peer) == ZTL_ADDR_LEN + 1u + ZTL_KEY_LEN, "peer entry without padding");
_Static_assert(sizeof(struct ztl_node) <=
		       8u + ZTL_PEERS * 38u + ZTL_RX_SLOTS * (ZTL_PKT_MAX + 24u) + 24u,
	       "node RAM budget");
#if defined(__arm__) && ZTL_PKT_MAX == 2048u && ZTL_PEERS == 7u && ZTL_RX_SLOTS == 2u
_Static_assert(sizeof(struct ztl_node) == 4440u, "node RAM on the target changed");
#endif

/*@ requires \valid(c);
  @ assigns *c;
  @ ensures \old(*c) <= *c <= \old(*c) + 1;
  @*/
static void count(uint32_t *c)
{
	if (*c != UINT32_MAX) {
		(*c)++;
	}
}

/* Addresses are public values: a plain comparison, no constant-time need. */
/*@ requires \valid_read(a + (0 .. ZTL_ADDR_LEN - 1)) && \valid_read(b + (0 .. ZTL_ADDR_LEN - 1));
  @ assigns \nothing;
  @ ensures \result == 0 || \result == 1;
  @ ensures \result == 1 <==> ztl_addr_same(a, b);
  @*/
static int addr_eq(const uint8_t *a, const uint8_t *b)
{
	/*@ loop invariant 0 <= i <= ZTL_ADDR_LEN;
	  @ loop invariant \forall integer k; 0 <= k < i ==> a[k] == b[k];
	  @ loop assigns i;
	  @ loop variant ZTL_ADDR_LEN - i;
	  @*/
	for (unsigned int i = 0; i < ZTL_ADDR_LEN; i++) {
		if (a[i] != b[i]) {
			return 0;
		}
	}
	return 1;
}

/* Index of the pinned peer with this address, or ZTL_PEERS. */
/*@ requires \valid_read(n) && \valid_read(addr + (0 .. ZTL_ADDR_LEN - 1));
  @ assigns \nothing;
  @ ensures 0 <= \result <= ZTL_PEERS;
  @ ensures \result < ZTL_PEERS ==>
  @   n->peer[\result].pinned != 0 && ztl_addr_same(&n->peer[\result].addr[0], addr);
  @ ensures \result == ZTL_PEERS ==>
  @   \forall integer k; 0 <= k < ZTL_PEERS ==>
  @     !(n->peer[k].pinned != 0 && ztl_addr_same(&n->peer[k].addr[0], addr));
  @*/
static unsigned int peer_find(const struct ztl_node *n, const uint8_t *addr)
{
	/*@ loop invariant 0 <= i <= ZTL_PEERS;
	  @ loop invariant \forall integer k; 0 <= k < i ==>
	  @   !(n->peer[k].pinned != 0 && ztl_addr_same(&n->peer[k].addr[0], addr));
	  @ loop assigns i;
	  @ loop variant ZTL_PEERS - i;
	  @*/
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		if (n->peer[i].pinned && addr_eq(n->peer[i].addr, addr)) {
			return i;
		}
	}
	return ZTL_PEERS;
}

/* Fill the output record; nothing else changes. */
/*@ requires \valid(out) && p < ZTL_PEERS && body_len <= ZTL_PKT_MAX - ZTL_PKT_MIN;
  @ requires encrypted == 0 || encrypted == 1;
  @ assigns *out;
  @ ensures out->peer == p && out->verb == (vb & ZTL_VERB_MASK) &&
  @   out->verb_flags == (vb & ZTL_VERB_FLAGS) && out->encrypted == encrypted &&
  @   out->body == body && out->body_len == body_len;
  @*/
static void deliver(struct ztl_rx_packet *out, unsigned int p, uint8_t vb, int encrypted,
		    const uint8_t *body, size_t body_len)
{
	out->peer = (uint8_t)p;
	out->verb = vb & ZTL_VERB_MASK;
	out->verb_flags = vb & ZTL_VERB_FLAGS;
	out->encrypted = (uint8_t)encrypted;
	out->body = body;
	out->body_len = (uint16_t)body_len;
}

int ztl_rx(struct ztl_node *n, uint8_t *dgram, size_t len, uint32_t now_ms,
	   struct ztl_rx_packet *out)
{
	/*@ ghost ztl_gh_auth_calls = 0; */
	struct ztl_view v;
	const enum ztl_kind kind = ztl_classify(dgram, len, &v);

	if (kind == ZTL_DROP) {
		count(&n->rx.not_wire);
		/*@ assert reasm_r1: ztl_reasm_valid(&n->reasm); */
		return 0;
	}
	/* A leaf does not relay: only packets to this node, and none that
	 * claim to come from it. */
	if (!addr_eq(v.dest, n->self) || (kind == ZTL_HEAD && addr_eq(v.src, n->self))) {
		count(&n->rx.not_ours);
		/*@ assert reasm_r2: ztl_reasm_valid(&n->reasm); */
		return 0;
	}

	uint8_t *pkt = NULL;
	const size_t plen = ztl_reasm_input(&n->reasm, kind, &v, dgram, len, now_ms, &pkt);

	if (plen == 0u) {
		/*@ assert reasm_r3: ztl_reasm_valid(&n->reasm); */
		return 0; /* stored, or dropped by the reassembly rules */
	}
	/*@ assert pkt_where: pkt == dgram ||
	  @   (\exists integer i; 0 <= i < ZTL_RX_SLOTS && pkt == &n->reasm.slot[i].buf[0]); */
	/*@ assert pkt_valid: ZTL_PKT_MIN <= plen <= ZTL_PKT_MAX && \valid(pkt + (0 .. plen - 1)); */
	/*@ assert reasm_kept: ztl_reasm_valid(&n->reasm); */
	/*@ assert pkt_sep: \separated(out, pkt + (0 .. plen - 1)); */

	/* pkt is a complete packet: a head datagram that passed ztl_classify(),
	 * possibly followed by fragment payload. Read its header again here;
	 * nothing from v is used after this point. The address rule is applied
	 * to the complete packet too: this function then does not depend on
	 * what an earlier call left in the reassembly memory. */
	if (!addr_eq(&pkt[ZTL_PKT_IDX_DEST], n->self) || addr_eq(&pkt[ZTL_PKT_IDX_SRC], n->self)) {
		count(&n->rx.not_ours);
		/*@ assert reasm_r4: ztl_reasm_valid(&n->reasm); */
		return 0;
	}

	const unsigned int p = peer_find(n, &pkt[ZTL_PKT_IDX_SRC]);

	if (p == ZTL_PEERS) {
		count(&n->rx.no_peer);
		/*@ assert reasm_r5: ztl_reasm_valid(&n->reasm); */
		return 0;
	}

	const uint8_t flags = pkt[ZTL_PKT_IDX_FLAGS];

	/* The suite rule of the classifier, applied to the complete packet for
	 * the same reason as the address rule. */
	if ((flags & ZTL_FLAG_CIPHER_HIGH) != 0u ||
	    (flags & ZTL_FLAG_EXT_ARMOR_MASK) == ZTL_FLAG_BIT7) {
		count(&n->rx.not_wire);
		/*@ assert reasm_r9: ztl_reasm_valid(&n->reasm); */
		return 0;
	}

	const int encrypted = (flags & ZTL_FLAG_CIPHER_LOW) != 0u;

	if (!encrypted) {
		/* Suite 0: the verb byte is readable before authentication.
		 * Only HELLO may come without encryption. */
		if ((pkt[ZTL_PKT_IDX_VERB] & ZTL_VERB_MASK) != ZTL_VERB_HELLO) {
			count(&n->rx.bad_suite);
			/*@ assert reasm_r6: ztl_reasm_valid(&n->reasm); */
		return 0;
		}
	}

	/*@ assert before_auth: n->peer[p].pinned != 0 &&
	  @   ztl_addr_same(&n->peer[p].addr[0], pkt + ZTL_PKT_IDX_SRC) &&
	  @   ztl_addr_same(&n->self[0], pkt + ZTL_PKT_IDX_DEST); */
	if (!ztl_auth_open(n->peer[p].key, pkt, plen, encrypted)) {
		count(&n->rx.bad_auth);
		/*@ assert reasm_r7: ztl_reasm_valid(&n->reasm); */
		return 0;
	}
	/*@ assert after_auth: n->peer[p].pinned != 0 &&
	  @   ztl_addr_same(&n->peer[p].addr[0], pkt + ZTL_PKT_IDX_SRC) &&
	  @   ztl_addr_same(&n->self[0], pkt + ZTL_PKT_IDX_DEST); */
	/*@ assert reasm_still: ztl_reasm_valid(&n->reasm); */

	const uint8_t vb = pkt[ZTL_PKT_IDX_VERB];

	if (!encrypted && (vb & ZTL_VERB_MASK) != ZTL_VERB_HELLO) {
		/* Cannot happen: a failed or plain open does not change pkt. Kept
		 * so that the rule does not depend on that property of the primitive. */
		count(&n->rx.bad_suite);
		/*@ assert reasm_r8: ztl_reasm_valid(&n->reasm); */
		return 0;
	}

	deliver(out, p, vb, encrypted, &pkt[ZTL_PKT_MIN], plen - ZTL_PKT_MIN);
	/*@ assert deliver_yes: ztl_gh_auth_yes == 1 && ztl_gh_auth_key == &n->peer[p].key[0]; */
	/*@ assert deliver_pinned: n->peer[p].pinned != 0; */
	/*@ assert deliver_src: ztl_addr_same(&n->peer[p].addr[0], pkt + ZTL_PKT_IDX_SRC); */
	/*@ assert deliver_dest: ztl_addr_same(&n->self[0], pkt + ZTL_PKT_IDX_DEST); */
	/*@ assert reasm_out: ztl_reasm_valid(&n->reasm); */
	count(&n->rx.ok);
	/*@ assert reasm_end: ztl_reasm_valid(&n->reasm); */
	return 1;
}
