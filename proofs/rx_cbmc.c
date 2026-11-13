/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CBMC harness for the receive gate ztl_rx() (-DH_GATE): "authentication
 * before effects".
 *
 * The node starts in ANY state whose reassembly memory is valid, and gets any
 * one datagram at any clock value. The authentication primitive is replaced
 * by a stub that may answer yes or no for any input (so the proof does not
 * depend on the cryptography) and that obeys the primitive's contract: a "no"
 * leaves the packet unchanged, a "yes" may rewrite the encrypted part.
 *
 * Proved for every such case:
 *  - The primitive is called at most once, only with the key of a pinned
 *    peer whose address equals the packet's source address, and only for a
 *    packet addressed to this node.
 *  - A packet is delivered only if the primitive said yes in that call.
 *  - An unencrypted packet is given to the primitive, and delivered, only if
 *    its verb is HELLO.
 *  - The gate never changes the node's own address or any peer entry.
 *  - Without delivery: *out is not written, and at most one counter grows,
 *    by one. With delivery: only the "ok" counter grows.
 *  - The reassembly memory stays valid.
 */
#include "ztl/node.h"

#ifdef H_COVER
#define COVER(c) __CPROVER_cover(c)
#else
#define COVER(c) ((void)0)
#endif

size_t nondet_size(void);
uint32_t nondet_u32(void);
int nondet_int(void);
uint8_t nondet_u8(void);
struct ztl_node nondet_node(void);
struct ztl_rx_packet nondet_out(void);

static struct ztl_node *g_node;
static unsigned int g_calls;
static int g_answer, g_decrypt, g_peer_ok;
static unsigned int g_peer;
static uint8_t *g_pkt;
static size_t g_len;
static uint8_t g_verb_before;

int ztl_auth_open(const uint8_t key[ZTL_KEY_LEN], uint8_t *pkt, size_t len, int decrypt)
{
	g_calls++;
	g_pkt = pkt;
	g_len = len;
	g_decrypt = decrypt;
	__CPROVER_assert(len > ZTL_PKT_IDX_VERB && len <= ZTL_PKT_MAX, "primitive gets a packet of legal length");
	g_verb_before = pkt[ZTL_PKT_IDX_VERB];

	/* Which peer's key is this? It must be a pinned peer with the packet's source address. */
	g_peer_ok = 0;
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		if (key == g_node->peer[i].key) {
			int same = 1;

			for (unsigned int k = 0; k < ZTL_ADDR_LEN; k++) {
				same &= g_node->peer[i].addr[k] == pkt[ZTL_PKT_IDX_SRC + k];
			}
			g_peer = i;
			g_peer_ok = g_node->peer[i].pinned && same;
		}
	}
	__CPROVER_assert(g_peer_ok, "key belongs to a pinned peer with the packet's source address");

	int to_us = 1;

	for (unsigned int k = 0; k < ZTL_ADDR_LEN; k++) {
		to_us &= g_node->self[k] == pkt[ZTL_PKT_IDX_DEST + k];
	}
	__CPROVER_assert(to_us, "packet is addressed to this node");
	__CPROVER_assert(decrypt || (g_verb_before & ZTL_VERB_MASK) == ZTL_VERB_HELLO,
			 "an unencrypted packet reaches the primitive only as HELLO");

	g_answer = nondet_int() != 0;
	if (g_answer && decrypt) {
		/* Decryption may give any bytes: change the verb byte and one more. */
		size_t i = nondet_size();

		pkt[ZTL_PKT_IDX_VERB] = nondet_u8();
		if (i > ZTL_PKT_IDX_VERB && i < len) {
			pkt[i] = nondet_u8();
		}
	}
	return g_answer;
}

static int peers_same(const struct ztl_node *a, const struct ztl_node *b)
{
	int same = 1;

	for (unsigned int k = 0; k < ZTL_ADDR_LEN; k++) {
		same &= a->self[k] == b->self[k];
	}
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		same &= a->peer[i].pinned == b->peer[i].pinned;
		for (unsigned int k = 0; k < ZTL_ADDR_LEN; k++) {
			same &= a->peer[i].addr[k] == b->peer[i].addr[k];
		}
		for (unsigned int k = 0; k < ZTL_KEY_LEN; k++) {
			same &= a->peer[i].key[k] == b->peer[i].key[k];
		}
	}
	return same;
}

int main(void)
{
	static struct ztl_node n, n0;
	static uint8_t dgram[ZTL_PKT_MAX];

	n = nondet_node();
	__CPROVER_assume(ztl_reasm_ok(&n.reasm));
	n0 = n;
	g_node = &n;

	size_t len = nondet_size();
	__CPROVER_assume(len <= ZTL_PKT_MAX);
	/* dgram is static storage; give it any contents. */
	__CPROVER_havoc_object(dgram);

	struct ztl_rx_packet out = nondet_out();
	const struct ztl_rx_packet out0 = out;

	int r = ztl_rx(&n, dgram, len, nondet_u32(), &out);

	__CPROVER_assert(g_calls <= 1u, "primitive is called at most once");
	__CPROVER_assert(peers_same(&n, &n0), "own address and peer table are never changed");
	__CPROVER_assert(ztl_reasm_ok(&n.reasm), "reassembly memory stays valid");

	const uint32_t d_ok = n.rx.ok - n0.rx.ok, d_wire = n.rx.not_wire - n0.rx.not_wire,
		       d_ours = n.rx.not_ours - n0.rx.not_ours, d_peer = n.rx.no_peer - n0.rx.no_peer,
		       d_suite = n.rx.bad_suite - n0.rx.bad_suite, d_auth = n.rx.bad_auth - n0.rx.bad_auth;

	if (r) {
		__CPROVER_assert(g_calls == 1u && g_answer, "delivery only after the primitive said yes");
		__CPROVER_assert(out.peer == g_peer && g_peer_ok, "delivered packet names the authenticated peer");
		__CPROVER_assert(out.encrypted == (g_decrypt != 0), "encrypted flag matches the call");
		__CPROVER_assert(out.encrypted || out.verb == ZTL_VERB_HELLO, "unencrypted delivery is HELLO only");
		__CPROVER_assert(out.verb == (g_pkt[ZTL_PKT_IDX_VERB] & ZTL_VERB_MASK), "verb from the opened packet");
		__CPROVER_assert(out.body == g_pkt + ZTL_PKT_MIN && out.body + out.body_len == g_pkt + g_len,
				 "body is the rest of the authenticated packet");
		__CPROVER_assert(d_ok <= 1u && d_wire == 0u && d_ours == 0u && d_peer == 0u && d_suite == 0u && d_auth == 0u,
				 "delivery counts only as ok");
	} else {
		__CPROVER_assert(out.peer == out0.peer && out.verb == out0.verb && out.verb_flags == out0.verb_flags &&
				 out.encrypted == out0.encrypted && out.body == out0.body && out.body_len == out0.body_len,
				 "no delivery: output record not written");
		__CPROVER_assert(d_ok == 0u, "no delivery: ok counter unchanged");
		__CPROVER_assert((uint64_t)d_wire + d_ours + d_peer + d_suite + d_auth <= 1u, "at most one counter grows, by one");
		__CPROVER_assert(g_calls == 0u || !g_answer || d_suite == 1u, "a yes from the primitive is delivered");
	}
	COVER(r && out.encrypted);
	COVER(r && !out.encrypted);
	COVER(!r && d_auth == 1u);
	COVER(!r && d_suite == 1u);
	COVER(!r && d_peer == 1u);
	COVER(!r && d_ours == 1u);
	COVER(!r && d_wire == 1u);
	COVER(r && g_pkt != dgram); /* delivered from reassembly */
	return 0;
}
