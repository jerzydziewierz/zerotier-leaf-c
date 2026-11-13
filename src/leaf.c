/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Protocol messages of the leaf. What a stock peer expects, with the places
 * in the reference source: reports/PROTOCOL.md.
 *
 * Every packet that this file reads has passed ztl_rx(): it comes from a
 * pinned peer and has a right MAC. Its contents are still input to check:
 * a pinned peer can be faulty.
 */
#include "crypto_internal.h"
#include "leaf_internal.h"
#include "reasm_internal.h"
#include "ztl/lz4.h"

#define VERB_HELLO                  0x01u
#define VERB_ERROR                  0x02u
#define VERB_OK                     0x03u
#define VERB_FRAME                  0x06u
#define VERB_EXT_FRAME              0x07u
#define VERB_ECHO                   0x08u
#define VERB_MULTICAST_LIKE         0x09u
#define VERB_NETWORK_CREDENTIALS    0x0au
#define VERB_NETWORK_CONFIG_REQUEST 0x0bu
#define VERB_NETWORK_CONFIG         0x0cu
#define VERB_MULTICAST_FRAME        0x0eu
#define VERB_FLAG_COMPRESSED        0x80u

#define ERROR_OBJ_NOT_FOUND               0x03u
#define ERROR_NEED_MEMBERSHIP_CERTIFICATE 0x06u
#define ERROR_NETWORK_ACCESS_DENIED        0x07u
#define PROTO_VERSION_MIN                 4u /* as the reference: older peers are not answered */

#define ETHERTYPE_ARP 0x0806u

/* Lengths of the parts of messages (bytes). */
#define ID_LEN        8u  /* packet ID */
#define IDENTITY_LEN  71u /* address 5, type 1, public key 64, length of the secret part 1 */
#define HELLO_FIXED   13u /* version 1, major 1, minor 1, revision 2, time stamp 8 */
#define HELLO_LEN     (ZTL_PKT_MIN + HELLO_FIXED + IDENTITY_LEN + 1u + 16u)
#define OK_HDR        (1u + ID_LEN) /* verb and packet ID that the OK answers */
#define OK_HELLO_LEN  (ZTL_PKT_MIN + OK_HDR + 8u + 5u + 1u + 2u)
#define OK_EXT_LEN    (ZTL_PKT_MIN + OK_HDR + ZTL_NWID_LEN)
#define COM_SIG_LEN   96u
#define COM_TAIL      9u  /* end of the credential lists: 0, then four empty counts */
#define LIKE_ENTRY    (ZTL_NWID_LEN + ZTL_ETH_ALEN + 4u)
#define FRAME_HDR     (ZTL_NWID_LEN + 2u)
#define MC_FRAME_HDR  (ZTL_NWID_LEN + 1u + ZTL_ETH_ALEN + 4u + 2u)
#define CHUNK_TAIL    17u /* flags 1, update ID 8, total length 4, chunk index 4 */
#define CHUNK_SIG      (1u + 2u + COM_SIG_LEN) /* signature type 1, length (2), signature */

/* What this node tells the controller with a configuration request: the
 * format version it reads, and who it is. It names no rules engine (key
 * "revr"), so the controller sends one "accept" rule and no capabilities or
 * tags (reference controller, EmbeddedNetworkController.cpp: no rules
 * engine revision in the request): this leaf admits peers by pinning and
 * does not evaluate rules. */
static const char cfg_meta[] = "v=7\nvend=1\npv=b\nmajv=0\nminv=0\nrevv=1";
#define CFG_META_LEN (sizeof(cfg_meta) - 1u)
#define CFG_REQ_LEN  (ZTL_PKT_MIN + ZTL_NWID_LEN + 2u + CFG_META_LEN + 16u)

_Static_assert(ZTL_PROTO_VERSION == 11u && ZTL_VERSION_MAJOR == 0u && ZTL_VERSION_MINOR == 0u &&
		       ZTL_VERSION_REVISION == 1u,
	       "cfg_meta states the versions as text");
_Static_assert(ZTL_PKT_MIN + MC_FRAME_HDR + ZTL_MTU_MAX <= ZTL_PKT_MAX, "a frame of the largest MTU fits one packet");
_Static_assert(ZTL_PKT_MIN + ZTL_COM_MAX + COM_TAIL <= ZTL_UDP_MAX, "the certificate push fits one datagram");
_Static_assert(ZTL_PKT_MAX - ZTL_UDP_MAX + ZTL_FRAG_HDR <= ZTL_UDP_MAX, "two datagrams carry the largest packet");
_Static_assert(ZTL_PEERS <= 255u, "peer index in 8 bits");

static const uint8_t mac_broadcast[ZTL_ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/*@ requires \valid(c);
  @ assigns *c;
  @*/
static void count(uint32_t *c)
{
	if (*c != UINT32_MAX) {
		(*c)++;
	}
}

/*@ requires \valid(p + (0 .. n - 1)) && n <= ZTL_PKT_MAX;
  @ assigns p[0 .. n - 1];
  @ ensures \forall integer i; 0 <= i < n ==> p[i] == 0;
  @*/
static void zero(uint8_t *p, size_t n)
{
	/*@ loop invariant 0 <= i <= n;
	  @ loop invariant \forall integer k; 0 <= k < i ==> p[k] == 0;
	  @ loop assigns i, p[0 .. n - 1];
	  @ loop variant n - i;
	  @*/
	for (size_t i = 0; i < n; i++) {
		p[i] = 0;
		ZTL_KEEP_WRITES(p); /* else the compiler makes this loop a call to memset */
	}
}

void ztl_mac_of(uint8_t mac[ZTL_ETH_ALEN], const uint8_t addr[ZTL_ADDR_LEN], const uint8_t nwid[ZTL_NWID_LEN])
{
	/* First byte: from the last byte of the network ID, made "locally
	 * administered, one station"; 0x52 is avoided (used by virtual
	 * machine software). Then the address, mixed with network ID bytes
	 * (reference: MAC::fromAddress()). */
	const uint8_t first = (uint8_t)((nwid[7] & 0xfeu) | 0x02u);

	mac[0] = (first == 0x52u) ? 0x32u : first;
	/*@ loop invariant 1 <= i <= ZTL_ETH_ALEN;
	  @ loop assigns i, mac[1 .. ZTL_ETH_ALEN - 1];
	  @ loop variant ZTL_ETH_ALEN - i;
	  @*/
	for (unsigned int i = 1; i < ZTL_ETH_ALEN; i++) {
		mac[i] = addr[i - 1u] ^ nwid[7u - i];
	}
}

/* A peer that nothing was sent to and nothing was heard from. */
static void peer_state_clear(struct ztl_peer_state *s)
{
	s->hello_id = 0;
	s->hello_ms = 0;
	s->rx_ms = 0;
	s->com_ms = 0;
	s->like_ms = 0;
	s->hello_sent = 0;
	s->hello_wait = 0;
	s->seen = 0;
	s->com_sent = 0;
	s->like_sent = 0;
}

void ztl_init(struct ztl_leaf *l, const uint8_t self[ZTL_ADDR_LEN], const uint8_t pub[ZTL_PUB_LEN],
	      const uint8_t nwid[ZTL_NWID_LEN], uint64_t first_packet_id)
{
	ztl_copy_bytes(l->node.self, self, ZTL_ADDR_LEN);
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		l->node.peer[i].pinned = 0;
		peer_state_clear(&l->ps[i]);
	}
	ztl_reasm_init(&l->node.reasm);
	l->node.rx.ok = 0;
	l->node.rx.not_wire = 0;
	l->node.rx.not_ours = 0;
	l->node.rx.no_peer = 0;
	l->node.rx.bad_suite = 0;
	l->node.rx.bad_auth = 0;
	l->stats.rx_lz4 = 0;
	l->stats.rx_bad_lz4 = 0;
	l->stats.rx_bad_form = 0;
	l->stats.rx_no_config = 0;
	l->stats.rx_ignored = 0;
	l->stats.rx_frames = 0;
	l->stats.tx_packets = 0;
	l->stats.configs = 0;
	l->stats.config_bad = 0;
	l->next_id = first_packet_id;
	l->cfg_req_id = 0;
	l->cfg_ts = 0;
	l->cfg_req_ms = 0;
	l->mtu = 0;
	l->com_len = 0;
	l->have_config = 0;
	l->req_sent = 0;
	l->req_wait = 0;
	l->ctrl = (uint8_t)ZTL_PEERS;
	l->prefix = 0;
	zero(l->ip, sizeof(l->ip));
	ztl_copy_bytes(l->nwid, nwid, ZTL_NWID_LEN);
	ztl_copy_bytes(l->pub, pub, ZTL_PUB_LEN);
	ztl_mac_of(l->mac, self, nwid);
}

int ztl_pin(struct ztl_leaf *l, const uint8_t addr[ZTL_ADDR_LEN], const uint8_t key[ZTL_KEY_LEN])
{
	unsigned int free_at = ZTL_PEERS;

	if (ztl_bytes_eq(addr, l->node.self, ZTL_ADDR_LEN)) {
		return -1;
	}
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		if (!l->node.peer[i].pinned) {
			if (free_at == ZTL_PEERS) {
				free_at = i;
			}
		} else if (ztl_bytes_eq(addr, l->node.peer[i].addr, ZTL_ADDR_LEN)) {
			return -1;
		}
	}
	if (free_at == ZTL_PEERS) {
		return -1;
	}
	ztl_copy_bytes(l->node.peer[free_at].addr, addr, ZTL_ADDR_LEN);
	ztl_copy_bytes(l->node.peer[free_at].key, key, ZTL_KEY_LEN);
	l->node.peer[free_at].pinned = 1;
	peer_state_clear(&l->ps[free_at]);
	/* The controller's address is the upper 40 bits of the network ID. */
	if (ztl_bytes_eq(addr, l->nwid, ZTL_ADDR_LEN)) {
		l->ctrl = (uint8_t)free_at;
	}
	return (int)free_at;
}

/* ---- Sending ---- */

/* Start a packet to peer i: header with a new packet ID, flags and MAC zero. */
static uint64_t begin(struct ztl_leaf *l, unsigned int i, uint8_t *tx, uint8_t verb)
{
	const uint64_t id = l->next_id;

	l->next_id = (id == UINT64_MAX) ? 0u : id + 1u;
	ztl_put_be64(&tx[ZTL_PKT_IDX_IV], id);
	ztl_copy_bytes(&tx[ZTL_PKT_IDX_DEST], l->node.peer[i].addr, ZTL_ADDR_LEN);
	ztl_copy_bytes(&tx[ZTL_PKT_IDX_SRC], l->node.self, ZTL_ADDR_LEN);
	zero(&tx[ZTL_PKT_IDX_FLAGS], 1u + ZTL_MAC_LEN);
	tx[ZTL_PKT_IDX_VERB] = verb;
	return id;
}

/* Close a packet of len bytes to peer i: "fragmented" flag if it needs two
 * datagrams (the flag is part of the per-packet key), encryption, MAC. */
static size_t finish(struct ztl_leaf *l, unsigned int i, uint8_t *tx, size_t len, int encrypt)
{
	if (len > ZTL_UDP_MAX) {
		tx[ZTL_PKT_IDX_FLAGS] = ZTL_FLAG_FRAGMENTED;
	}
	ztl_auth_seal(l->node.peer[i].key, tx, len, encrypt);
	count(&l->stats.tx_packets);
	return len;
}

size_t ztl_tx_first(size_t len)
{
	return (len > ZTL_UDP_MAX) ? ZTL_UDP_MAX : len;
}

size_t ztl_tx_second(uint8_t pkt[ZTL_PKT_MAX], size_t len, size_t *at)
{
	if (len <= ZTL_UDP_MAX || len > ZTL_PKT_MAX) {
		return 0;
	}
	/* The fragment header goes right before the bytes that are still to
	 * send; it overwrites the end of the first datagram, which is gone. */
	const size_t h = ZTL_UDP_MAX - ZTL_FRAG_HDR;

	ztl_copy_bytes(&pkt[h], pkt, ID_LEN + ZTL_ADDR_LEN); /* packet ID, destination */
	pkt[h + ZTL_FRAG_IDX_INDICATOR] = ZTL_FRAG_INDICATOR;
	pkt[h + ZTL_FRAG_IDX_NO] = ZTL_FRAG_NO_1_OF_2;
	pkt[h + ZTL_FRAG_IDX_HOPS] = 0;
	*at = h;
	return len - h;
}

static size_t send_hello(struct ztl_leaf *l, unsigned int i, uint32_t now_ms, uint8_t *tx)
{
	const uint64_t id = begin(l, i, tx, VERB_HELLO);
	uint8_t *b = &tx[ZTL_PKT_MIN];

	b[0] = ZTL_PROTO_VERSION;
	b[1] = ZTL_VERSION_MAJOR;
	b[2] = ZTL_VERSION_MINOR;
	ztl_put_be16(&b[3], ZTL_VERSION_REVISION);
	ztl_put_be64(&b[5], now_ms); /* the peer only sends it back */
	/* Identity: address, type 0, public key, no secret part. */
	ztl_copy_bytes(&b[HELLO_FIXED], l->node.self, ZTL_ADDR_LEN);
	b[HELLO_FIXED + ZTL_ADDR_LEN] = 0;
	ztl_copy_bytes(&b[HELLO_FIXED + ZTL_ADDR_LEN + 1u], l->pub, ZTL_PUB_LEN);
	/* No secret part (1 byte 0); destination address as seen from here:
	 * none (1 byte 0); planet ID and time stamp 0: no root set wanted. */
	zero(&b[HELLO_FIXED + IDENTITY_LEN - 1u], 1u + 1u + 16u);
	l->ps[i].hello_id = id;
	l->ps[i].hello_ms = now_ms;
	l->ps[i].hello_sent = 1;
	l->ps[i].hello_wait = 1;
	return finish(l, i, tx, HELLO_LEN, 0);
}

static size_t send_config_request(struct ztl_leaf *l, unsigned int i, uint32_t now_ms, uint8_t *tx)
{
	const uint64_t id = begin(l, i, tx, VERB_NETWORK_CONFIG_REQUEST);
	uint8_t *b = &tx[ZTL_PKT_MIN];

	ztl_copy_bytes(b, l->nwid, ZTL_NWID_LEN);
	ztl_put_be16(&b[ZTL_NWID_LEN], (uint16_t)CFG_META_LEN);
	ztl_copy_bytes(&b[ZTL_NWID_LEN + 2u], (const uint8_t *)cfg_meta, CFG_META_LEN);
	/* Revision and time stamp of the configuration in use: the
	 * controller does not read them; zero. */
	zero(&b[ZTL_NWID_LEN + 2u + CFG_META_LEN], 16u);
	l->cfg_req_id = id;
	l->cfg_req_ms = now_ms;
	l->req_sent = 1;
	l->req_wait = 1;
	return finish(l, i, tx, CFG_REQ_LEN, 1);
}

/* NETWORK_CREDENTIALS with the own certificate of membership and nothing else. */
static size_t send_com(struct ztl_leaf *l, unsigned int i, uint32_t now_ms, uint8_t *tx)
{
	(void)begin(l, i, tx, VERB_NETWORK_CREDENTIALS);
	ztl_copy_bytes(&tx[ZTL_PKT_MIN], l->com, l->com_len);
	zero(&tx[ZTL_PKT_MIN + l->com_len], COM_TAIL);
	l->ps[i].com_ms = now_ms;
	l->ps[i].com_sent = 1;
	return finish(l, i, tx, ZTL_PKT_MIN + l->com_len + COM_TAIL, 1);
}

/* MULTICAST_LIKE: the groups this node listens to. Broadcast with the own
 * IPv4 address as extra group number is the group of ARP requests for
 * that address; broadcast with 0 is all other broadcast. */
static size_t send_like(struct ztl_leaf *l, unsigned int i, uint32_t now_ms, uint8_t *tx)
{
	size_t len = ZTL_PKT_MIN;

	(void)begin(l, i, tx, VERB_MULTICAST_LIKE);
	if (l->prefix != 0u) {
		ztl_copy_bytes(&tx[len], l->nwid, ZTL_NWID_LEN);
		ztl_copy_bytes(&tx[len + ZTL_NWID_LEN], mac_broadcast, ZTL_ETH_ALEN);
		ztl_copy_bytes(&tx[len + ZTL_NWID_LEN + ZTL_ETH_ALEN], l->ip, 4u);
		len += LIKE_ENTRY;
	}
	ztl_copy_bytes(&tx[len], l->nwid, ZTL_NWID_LEN);
	ztl_copy_bytes(&tx[len + ZTL_NWID_LEN], mac_broadcast, ZTL_ETH_ALEN);
	zero(&tx[len + ZTL_NWID_LEN + ZTL_ETH_ALEN], 4u);
	len += LIKE_ENTRY;
	l->ps[i].like_ms = now_ms;
	l->ps[i].like_sent = 1;
	return finish(l, i, tx, len, 1);
}

/* The packet that is due for peer i, or 0. */
static size_t poll_peer(struct ztl_leaf *l, unsigned int i, uint32_t now_ms, uint8_t *tx)
{
	struct ztl_peer_state *s = &l->ps[i];

	if (s->seen != 0u && ztl_age_ms(now_ms, s->rx_ms) > ZTL_PEER_TIMEOUT_MS) {
		s->seen = 0;
		s->com_sent = 0;
		s->like_sent = 0;
	}
	/* HELLO: at once, then again soon while no answer came, else at the
	 * normal period. A peer learns the way to this node from the OK to
	 * its own HELLO only, and may drop the first HELLO of a node that it
	 * does not know yet without a word. */
	const uint32_t period = (s->hello_wait != 0u || s->seen == 0u) ?
					ZTL_RETRY_MS : ZTL_HELLO_MS;

	if (s->hello_sent == 0u || ztl_age_ms(now_ms, s->hello_ms) >= period) {
		return send_hello(l, i, now_ms, tx);
	}
	/* All other packets are encrypted: the peer can read them only when
	 * it knows this node, which an authenticated packet from it shows. */
	if (s->seen == 0u) {
		return 0;
	}
	if (i == l->ctrl) {
		const uint32_t wait = (l->have_config != 0u && l->req_wait == 0u) ?
					      ZTL_CONFIG_MS : ZTL_RETRY_MS;

		if (l->req_sent == 0u || ztl_age_ms(now_ms, l->cfg_req_ms) >= wait) {
			return send_config_request(l, i, now_ms, tx);
		}
	}
	if (l->have_config == 0u) {
		return 0;
	}
	/* Certificate first: a peer accepts frames and subscriptions of this
	 * node only while it holds a certificate that agrees with its own. */
	if (s->com_sent == 0u || ztl_age_ms(now_ms, s->com_ms) >= ZTL_COM_MS) {
		return send_com(l, i, now_ms, tx);
	}
	if (s->like_sent == 0u || ztl_age_ms(now_ms, s->like_ms) >= ZTL_LIKE_MS) {
		return send_like(l, i, now_ms, tx);
	}
	return 0;
}

size_t ztl_poll(struct ztl_leaf *l, uint32_t now_ms, uint8_t tx[ZTL_PKT_MAX], unsigned int *peer)
{
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		if (l->node.peer[i].pinned) {
			const size_t n = poll_peer(l, i, now_ms, tx);

			if (n != 0u) {
				*peer = i;
				return n;
			}
		}
	}
	return 0;
}

size_t ztl_frame_to(struct ztl_leaf *l, unsigned int i, const uint8_t dst[ZTL_ETH_ALEN], uint16_t ethertype,
		    const uint8_t *data, size_t len, uint8_t tx[ZTL_PKT_MAX])
{
	uint8_t peer_mac[ZTL_ETH_ALEN];

	if (l->have_config == 0u || i >= ZTL_PEERS || !l->node.peer[i].pinned ||
	    l->ps[i].seen == 0u || len < 1u || len > l->mtu) {
		return 0;
	}
	if ((dst[0] & 0x01u) != 0u) {
		/* Group address: MULTICAST_FRAME, one copy to each reachable peer. */
		uint8_t *b = &tx[ZTL_PKT_MIN];

		(void)begin(l, i, tx, VERB_MULTICAST_FRAME);
		ztl_copy_bytes(b, l->nwid, ZTL_NWID_LEN);
		b[ZTL_NWID_LEN] = 0; /* no certificate, no gather request, source is the sender */
		ztl_copy_bytes(&b[ZTL_NWID_LEN + 1u], dst, ZTL_ETH_ALEN);
		/* Extra group number: for an ARP request, the address asked for. */
		static const uint8_t arp_request[8] = { 0, 1, 0x08, 0x00, 6, 4, 0, 1 }; /* Ethernet, IPv4, request */

		if (ethertype == ETHERTYPE_ARP && len >= 28u && ztl_bytes_eq(dst, mac_broadcast, ZTL_ETH_ALEN) &&
		    ztl_bytes_eq(data, arp_request, sizeof(arp_request))) {
			ztl_copy_bytes(&b[ZTL_NWID_LEN + 1u + ZTL_ETH_ALEN], &data[24], 4u);
		} else {
			zero(&b[ZTL_NWID_LEN + 1u + ZTL_ETH_ALEN], 4u);
		}
		ztl_put_be16(&b[MC_FRAME_HDR - 2u], ethertype);
		ztl_copy_bytes(&b[MC_FRAME_HDR], data, len);
		return finish(l, i, tx, ZTL_PKT_MIN + MC_FRAME_HDR + len, 1);
	}
	ztl_mac_of(peer_mac, l->node.peer[i].addr, l->nwid);
	if (!ztl_bytes_eq(dst, peer_mac, ZTL_ETH_ALEN)) {
		return 0;
	}
	(void)begin(l, i, tx, VERB_FRAME);
	ztl_copy_bytes(&tx[ZTL_PKT_MIN], l->nwid, ZTL_NWID_LEN);
	ztl_put_be16(&tx[ZTL_PKT_MIN + ZTL_NWID_LEN], ethertype);
	ztl_copy_bytes(&tx[ZTL_PKT_MIN + FRAME_HDR], data, len);
	return finish(l, i, tx, ZTL_PKT_MIN + FRAME_HDR + len, 1);
}

/* ---- Receiving ---- */

/* Length of the certificate of membership at c, if it is complete within
 * avail bytes; else 0. Layout: 1, count (2), count times three 8-byte
 * values, signer address (5), and a signature if the signer is not 0. */
static size_t com_len_at(const uint8_t *c, size_t avail)
{
	static const uint8_t no_signer[ZTL_ADDR_LEN];

	if (avail < 3u || c[0] != 1u) {
		return 0;
	}
	const size_t q = ztl_be16(&c[1]);

	if (q > 8u) {
		return 0;
	}
	size_t need = 3u + 24u * q + ZTL_ADDR_LEN;

	if (avail < need) {
		return 0;
	}
	if (!ztl_bytes_eq(&c[need - ZTL_ADDR_LEN], no_signer, ZTL_ADDR_LEN)) {
		need += COM_SIG_LEN;
	}
	return (avail < need) ? 0u : need;
}

/* The first IPv4 address with a network part of 1 to 32 bits in a list of
 * addresses (each: 4, address, 2 bytes prefix; or 6, 16 bytes, 2 bytes). */
static void first_ipv4(const uint8_t *v, size_t n, uint8_t ip[4], uint8_t *prefix)
{
	size_t i = 0;

	*prefix = 0;
	while (i < n) {
		if (v[i] == 4u && n - i >= 7u) {
			const uint16_t bits = ztl_be16(&v[i + 5u]);

			if (bits >= 1u && bits <= 32u) {
				ztl_copy_bytes(ip, &v[i + 1u], 4u);
				*prefix = (uint8_t)bits;
				return;
			}
			i += 7u;
		} else if (v[i] == 6u && n - i >= 19u) {
			i += 19u;
		} else {
			return;
		}
	}
}

/*
 * Take a network configuration (dictionary d of n bytes) from the
 * controller. It is used only if it is for this network and this node, the
 * network is private, the MTU is in range and the certificate is complete.
 * No configuration older than the newest one taken since the start is used
 * (also not as the answer to a request); a pushed one must be newer.
 * The signature of the controller is not checked: the packet came from the
 * pinned controller under the key shared with it (design decision D-8).
 */
static unsigned int config_apply(struct ztl_leaf *l, const uint8_t *d, size_t n, int pushed)
{
	uint64_t nwid = 0, id = 0, type = 0, mtu = 0, ts = 0;
	uint8_t addrs[64];
	uint8_t ip[4] = { 0, 0, 0, 0 };
	uint8_t prefix = 0;
	uint8_t self8[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	ztl_copy_bytes(&self8[3], l->node.self, ZTL_ADDR_LEN);
	(void)ztl_dict_get_hex(d, n, ZTL_KEY("t"), &type);  /* absent: private */
	(void)ztl_dict_get_hex(d, n, ZTL_KEY("ts"), &ts);
	if (!ztl_dict_get_hex(d, n, ZTL_KEY("nwid"), &nwid) || nwid != ztl_be64(l->nwid) ||
	    !ztl_dict_get_hex(d, n, ZTL_KEY("id"), &id) || id != ztl_be64(self8) || type != 0u ||
	    !ztl_dict_get_hex(d, n, ZTL_KEY("mtu"), &mtu) || mtu < ZTL_MTU_MIN || mtu > ZTL_MTU_MAX ||
	    ts < l->cfg_ts || (pushed && ts == l->cfg_ts)) {
		count(&l->stats.config_bad);
		return 0;
	}
	const int an = ztl_dict_get(d, n, ZTL_KEY("I"), addrs, sizeof(addrs));

	if (an > 0) {
		first_ipv4(addrs, (size_t)an, ip, &prefix);
	}
	/* The certificate goes straight to its place. If it is not complete,
	 * the node has no configuration until the next one comes. */
	const int cn = ztl_dict_get(d, n, ZTL_KEY("C"), l->com, ZTL_COM_MAX);

	if (cn < 1 || com_len_at(l->com, (size_t)cn) != (size_t)cn) {
		l->com_len = 0;
		l->have_config = 0;
		count(&l->stats.config_bad);
		return ZTL_IN_CONFIG;
	}
	/* A new certificate (the controller dates each one) and maybe another
	 * address: every peer gets the certificate and the groups again. */
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		l->ps[i].com_sent = 0;
		l->ps[i].like_sent = 0;
	}
	l->com_len = (uint16_t)cn;
	l->mtu = (uint16_t)mtu;
	l->prefix = prefix;
	ztl_copy_bytes(l->ip, ip, 4u);
	l->cfg_ts = ts;
	l->have_config = 1;
	count(&l->stats.configs);
	return ZTL_IN_CONFIG;
}

/* One configuration chunk: network ID, chunk length, chunk, and after it
 * (current controllers) flags, update ID, total length, chunk index and a
 * signature. Only a configuration that is complete in one chunk is used. */
static unsigned int on_config_chunk(struct ztl_leaf *l, const uint8_t *b, size_t n, int pushed)
{
	if (n < ZTL_NWID_LEN + 2u || !ztl_bytes_eq(b, l->nwid, ZTL_NWID_LEN)) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	const size_t chunk = ztl_be16(&b[ZTL_NWID_LEN]);
	const size_t rest = n - (ZTL_NWID_LEN + 2u);

	if (chunk < 1u || chunk > rest) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	if (rest != chunk) {
		const uint8_t *t = &b[ZTL_NWID_LEN + 2u + chunk];

		/* The signature is not verified (D-8), but its place must be right. */
		if (rest - chunk != CHUNK_TAIL + CHUNK_SIG || ztl_be32(&t[9]) != chunk || ztl_be32(&t[13]) != 0u ||
		    t[CHUNK_TAIL] != 1u || ztl_be16(&t[CHUNK_TAIL + 1u]) != COM_SIG_LEN) {
			count(&l->stats.rx_bad_form);
			return 0;
		}
	}
	return config_apply(l, &b[ZTL_NWID_LEN + 2u], chunk, pushed);
}

/* Start an OK packet that answers the packet pkt of peer i. */
static void begin_ok(struct ztl_leaf *l, unsigned int i, uint8_t *tx, uint8_t verb, const uint8_t *pkt)
{
	(void)begin(l, i, tx, VERB_OK);
	tx[ZTL_PKT_MIN] = verb;
	ztl_copy_bytes(&tx[ZTL_PKT_MIN + 1u], &pkt[ZTL_PKT_IDX_IV], ID_LEN);
}

/* HELLO from a pinned peer: answer OK(HELLO). The peer learns from this
 * answer that the way to this node works, and reads the version from it. */
static size_t on_hello(struct ztl_leaf *l, unsigned int i, const uint8_t *pkt, const uint8_t *b, size_t n,
		       uint8_t *tx)
{
	/* The identity in the HELLO must carry the sender's address, be of
	 * type 0 and have no secret part. Its public key is not needed: the
	 * MAC was made with the pairwise key. */
	if (n < HELLO_FIXED + IDENTITY_LEN || b[0] < PROTO_VERSION_MIN ||
	    !ztl_bytes_eq(&b[HELLO_FIXED], &pkt[ZTL_PKT_IDX_SRC], ZTL_ADDR_LEN) || b[HELLO_FIXED + ZTL_ADDR_LEN] != 0u ||
	    b[HELLO_FIXED + IDENTITY_LEN - 1u] != 0u) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	uint8_t *o = &tx[ZTL_PKT_MIN + OK_HDR];

	begin_ok(l, i, tx, VERB_HELLO, pkt);
	ztl_copy_bytes(o, &b[5], 8u); /* the peer's time stamp, sent back */
	o[8] = ZTL_PROTO_VERSION;
	o[9] = ZTL_VERSION_MAJOR;
	o[10] = ZTL_VERSION_MINOR;
	ztl_put_be16(&o[11], ZTL_VERSION_REVISION);
	/* Address of the peer as seen from here: none (0). Length of root
	 * set updates: 0. */
	zero(&o[13], 3u);
	return finish(l, i, tx, OK_HELLO_LEN, 1);
}

static unsigned int on_ok(struct ztl_leaf *l, unsigned int i, const uint8_t *b, size_t n)
{
	if (n < OK_HDR) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	const uint8_t verb = b[0];
	const uint64_t id = ztl_be64(&b[1]);

	/* An OK counts once, and only for the request that is waiting. */
	if (verb == VERB_HELLO) {
		/* Time stamp (8), version (1), major, minor (1 each), revision (2). */
		if (n >= OK_HDR + 13u && b[OK_HDR + 8u] >= PROTO_VERSION_MIN && l->ps[i].hello_wait != 0u &&
		    id == l->ps[i].hello_id) {
			l->ps[i].hello_wait = 0;
		}
	} else if (verb == VERB_NETWORK_CONFIG_REQUEST) {
		if (i == l->ctrl && l->req_wait != 0u && id == l->cfg_req_id) {
			const unsigned int r = on_config_chunk(l, &b[OK_HDR], n - OK_HDR, 0);

			/* Only an answer that was taken ends the wait: after a
			 * refused one the request goes out again soon. */
			if (r != 0u && l->have_config != 0u) {
				l->req_wait = 0;
			}
			return r;
		}
	} else {
		count(&l->stats.rx_ignored);
	}
	return 0;
}

static unsigned int on_error(struct ztl_leaf *l, unsigned int i, const uint8_t *b, size_t n)
{
	/* The controller refuses the configuration request that is waiting
	 * (access denied, or no such network): the node is not a member any
	 * more and stops using the network. Only for the waiting request, so
	 * that an old refusal sent again has no effect. */
	if (n >= OK_HDR + 1u + ZTL_NWID_LEN && i == l->ctrl && b[0] == VERB_NETWORK_CONFIG_REQUEST &&
	    (b[OK_HDR] == ERROR_NETWORK_ACCESS_DENIED || b[OK_HDR] == ERROR_OBJ_NOT_FOUND) &&
	    l->req_wait != 0u && ztl_be64(&b[1]) == l->cfg_req_id &&
	    ztl_bytes_eq(&b[OK_HDR + 1u], l->nwid, ZTL_NWID_LEN)) {
		const uint8_t had = l->have_config;

		l->have_config = 0;
		l->com_len = 0;
		count(&l->stats.config_bad);
		return (had != 0u) ? ZTL_IN_CONFIG : 0u;
	}
	/* Layout: verb and packet ID that failed, error code, then for this
	 * code the network. The peer wants the certificate again. */
	if (n >= OK_HDR + 1u + ZTL_NWID_LEN && b[OK_HDR] == ERROR_NEED_MEMBERSHIP_CERTIFICATE &&
	    ztl_bytes_eq(&b[OK_HDR + 1u], l->nwid, ZTL_NWID_LEN)) {
		l->ps[i].com_sent = 0;
		l->ps[i].like_sent = 0;
	} else {
		count(&l->stats.rx_ignored);
	}
	return 0;
}

/* Give a frame of peer i to the caller, if the node has a configuration
 * and the length is 1 .. mtu. src: the source in the packet, or NULL. A
 * frame is taken only with the peer's own Ethernet address as its source
 * (no bridging). */
static unsigned int deliver_frame(struct ztl_leaf *l, unsigned int i, const uint8_t *dst, const uint8_t *src,
				  uint16_t ethertype, const uint8_t *data, size_t len, struct ztl_frame *f)
{
	uint8_t peer_mac[ZTL_ETH_ALEN];

	if (l->have_config == 0u) {
		count(&l->stats.rx_no_config);
		return 0;
	}
	ztl_mac_of(peer_mac, l->node.peer[i].addr, l->nwid);
	if (len < 1u || len > l->mtu || (src != NULL && !ztl_bytes_eq(src, peer_mac, ZTL_ETH_ALEN))) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	ztl_copy_bytes(f->dst, dst, ZTL_ETH_ALEN);
	ztl_copy_bytes(f->src, peer_mac, ZTL_ETH_ALEN);
	f->ethertype = ethertype;
	f->len = (uint16_t)len;
	f->data = data;
	count(&l->stats.rx_frames);
	return ZTL_IN_FRAME;
}

/* FRAME: network, ethertype, data. To this node, from the sender. */
static unsigned int on_frame(struct ztl_leaf *l, unsigned int i, const uint8_t *b, size_t n, struct ztl_frame *f)
{
	if (n <= FRAME_HDR || !ztl_bytes_eq(b, l->nwid, ZTL_NWID_LEN)) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	return deliver_frame(l, i, l->mac, NULL, ztl_be16(&b[ZTL_NWID_LEN]), &b[FRAME_HDR], n - FRAME_HDR, f);
}

/* EXT_FRAME: network, flags, optional certificate (flag 0x01), destination,
 * source, ethertype, data. Flag 0x10: the sender wants an OK. */
static unsigned int on_ext_frame(struct ztl_leaf *l, unsigned int i, const uint8_t *pkt, const uint8_t *b, size_t n,
				 uint8_t *tx, size_t *tx_len, struct ztl_frame *f)
{
	size_t at = ZTL_NWID_LEN + 1u;

	if (n < at || !ztl_bytes_eq(b, l->nwid, ZTL_NWID_LEN)) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	const uint8_t flags = b[ZTL_NWID_LEN];

	if ((flags & 0x01u) != 0u) {
		const size_t c = com_len_at(&b[at], n - at);

		if (c == 0u) {
			count(&l->stats.rx_bad_form);
			return 0;
		}
		at += c;
	}
	if (n - at <= 2u * ZTL_ETH_ALEN + 2u) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	const uint8_t *to = &b[at];

	/* To this node or to a group; never a frame for a third station. */
	if (!ztl_bytes_eq(to, l->mac, ZTL_ETH_ALEN) && (to[0] & 0x01u) == 0u) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	const unsigned int r = deliver_frame(l, i, to, &b[at + ZTL_ETH_ALEN], ztl_be16(&b[at + 2u * ZTL_ETH_ALEN]),
					     &b[at + 2u * ZTL_ETH_ALEN + 2u], n - at - (2u * ZTL_ETH_ALEN + 2u), f);

	if (r != 0u && (flags & 0x10u) != 0u) {
		begin_ok(l, i, tx, VERB_EXT_FRAME, pkt);
		ztl_copy_bytes(&tx[ZTL_PKT_MIN + OK_HDR], l->nwid, ZTL_NWID_LEN);
		*tx_len = finish(l, i, tx, OK_EXT_LEN, 1);
		return r | ZTL_IN_REPLY;
	}
	return r;
}

/* MULTICAST_FRAME: network, flags, optional certificate (0x01), optional
 * gather limit (0x02, 4 bytes), optional source (0x04), destination group
 * address, extra group number (4), ethertype, data. */
static unsigned int on_multicast_frame(struct ztl_leaf *l, unsigned int i, const uint8_t *b, size_t n,
				       struct ztl_frame *f)
{
	size_t at = ZTL_NWID_LEN + 1u;
	const uint8_t *src = NULL;

	if (n < at || !ztl_bytes_eq(b, l->nwid, ZTL_NWID_LEN)) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	const uint8_t flags = b[ZTL_NWID_LEN];

	if ((flags & 0x01u) != 0u) {
		const size_t c = com_len_at(&b[at], n - at);

		if (c == 0u) {
			count(&l->stats.rx_bad_form);
			return 0;
		}
		at += c;
	}
	const size_t opt = (((flags & 0x02u) != 0u) ? 4u : 0u) + (((flags & 0x04u) != 0u) ? ZTL_ETH_ALEN : 0u);

	if (n - at <= opt + ZTL_ETH_ALEN + 4u + 2u) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	at += ((flags & 0x02u) != 0u) ? 4u : 0u;
	if ((flags & 0x04u) != 0u) {
		src = &b[at];
		at += ZTL_ETH_ALEN;
	}
	if ((b[at] & 0x01u) == 0u) {
		count(&l->stats.rx_bad_form); /* the destination must be a group address */
		return 0;
	}
	return deliver_frame(l, i, &b[at], src, ztl_be16(&b[at + ZTL_ETH_ALEN + 4u]), &b[at + ZTL_ETH_ALEN + 6u],
			     n - at - (ZTL_ETH_ALEN + 6u), f);
}

/* ECHO: answer OK with the same bytes. */
static size_t on_echo(struct ztl_leaf *l, unsigned int i, const uint8_t *pkt, const uint8_t *b, size_t n, uint8_t *tx)
{
	if (n > ZTL_PKT_MAX - (ZTL_PKT_MIN + OK_HDR)) {
		count(&l->stats.rx_bad_form);
		return 0;
	}
	begin_ok(l, i, tx, VERB_ECHO, pkt);
	ztl_copy_bytes(&tx[ZTL_PKT_MIN + OK_HDR], b, n);
	return finish(l, i, tx, ZTL_PKT_MIN + OK_HDR + n, 1);
}

unsigned int ztl_input(struct ztl_leaf *l, uint8_t *dgram, size_t len, uint32_t now_ms, uint8_t tx[ZTL_PKT_MAX],
		       size_t *tx_len, unsigned int *peer, struct ztl_frame *frame)
{
	struct ztl_rx_packet p;

	*tx_len = 0;
	if (!ztl_rx(&l->node, dgram, len, now_ms, &p)) {
		return 0;
	}
	const unsigned int i = p.peer;
	const uint8_t *const pkt = p.body - ZTL_PKT_MIN; /* the authenticated packet; its header is plain */
	const uint8_t *b = p.body;
	size_t n = p.body_len;

	*peer = i;
	l->ps[i].rx_ms = now_ms;
	l->ps[i].seen = 1;
	if ((p.verb_flags & VERB_FLAG_COMPRESSED) != 0u) {
		n = ztl_lz4_decode(l->plain, ZTL_PLAIN_MAX, b, n);
		if (n == 0u) {
			count(&l->stats.rx_bad_lz4);
			return 0;
		}
		count(&l->stats.rx_lz4);
		b = l->plain;
	}
	switch (p.verb) {
	case VERB_HELLO:
		*tx_len = on_hello(l, i, pkt, b, n, tx);
		return (*tx_len != 0u) ? ZTL_IN_REPLY : 0u;
	case VERB_OK:
		return on_ok(l, i, b, n);
	case VERB_ERROR:
		return on_error(l, i, b, n);
	case VERB_ECHO:
		*tx_len = on_echo(l, i, pkt, b, n, tx);
		return (*tx_len != 0u) ? ZTL_IN_REPLY : 0u;
	case VERB_NETWORK_CONFIG:
		/* A push, not asked for: from the controller only. */
		if (i == l->ctrl) {
			return on_config_chunk(l, b, n, 1);
		}
		count(&l->stats.rx_ignored);
		return 0;
	case VERB_FRAME:
		return on_frame(l, i, b, n, frame);
	case VERB_EXT_FRAME:
		return on_ext_frame(l, i, pkt, b, n, tx, tx_len, frame);
	case VERB_MULTICAST_FRAME:
		return on_multicast_frame(l, i, b, n, frame);
	default:
		/* Credentials and subscriptions of peers are not needed (peers
		 * are admitted by pinning); the other verbs are for roots,
		 * controllers and bonded links. */
		count(&l->stats.rx_ignored);
		return 0;
	}
}
