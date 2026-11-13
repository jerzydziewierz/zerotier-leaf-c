/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host test of the protocol layer. First fixed cases with known answers
 * (what must be answered, delivered, refused). Then random rounds: input
 * that a faulty or hostile pinned peer could send. Every packet here has a right MAC (the test knows the
 * keys), so it passes the receive gate and reaches the message parsers,
 * the LZ4 decoder and the dictionary reader. Bodies are random, or right
 * messages with random damage. A fixed pseudo-random sequence: every run is
 * the same.
 *
 * Each datagram is given in a heap block of its exact size, so the address
 * sanitizer sees any access outside it. Checked after each call:
 *  - a reply is a packet of 28 .. 2048 bytes that opens with the peer's key;
 *  - a frame is given only while the node has a configuration, has
 *    1 .. mtu bytes, the peer's own Ethernet address as source, and data
 *    inside the datagram or inside the leaf;
 *  - the reassembly state stays valid.
 * Usage: proto_test [number of rounds]. Exit status 0 only without failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ztl/leaf.h"
#include "ztl/lz4.h"

static unsigned long g_fail, g_checks;

#define CHECK(cond, ...) \
	do { \
		g_checks++; \
		if (!(cond)) { \
			g_fail++; \
			fprintf(stderr, "round %lu: ", g_round); \
			fprintf(stderr, __VA_ARGS__); \
			fputc('\n', stderr); \
		} \
	} while (0)

static unsigned long g_round;
static uint64_t g_state = 0x13198a2e03707344ULL;

static uint64_t rnd(void) /* splitmix64 */
{
	uint64_t z = (g_state += 0x9e3779b97f4a7c15ULL);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static void fill(uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		p[i] = (uint8_t)rnd();
	}
}

#define NPEERS 3u
static const uint8_t self_addr[ZTL_ADDR_LEN] = { 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
static const uint8_t nwid[ZTL_NWID_LEN] = { 0xc0, 0xff, 0xee, 0x00, 0x01, 0x00, 0x00, 0x01 };
static uint8_t peer_addr[NPEERS][ZTL_ADDR_LEN] = {
	{ 0xc0, 0xff, 0xee, 0x00, 0x01 }, /* the controller: first 5 bytes of the network ID */
	{ 0x11, 0x22, 0x33, 0x44, 0x55 },
	{ 0x0a, 0x0b, 0x0c, 0x0d, 0x0e },
};
static uint8_t peer_key[NPEERS][ZTL_KEY_LEN];
static struct ztl_leaf leaf;
static uint32_t now_ms = 1000;
static unsigned long n_reply, n_frame, n_config, n_lz4_ok, n_two_part;

/* A minimal literal-only LZ4 block of the plain bytes (always valid). */
static size_t lz4_store(uint8_t *out, const uint8_t *in, size_t n)
{
	size_t o = 0;

	if (n < 15u) {
		out[o++] = (uint8_t)(n << 4);
	} else {
		size_t rest = n - 15u;

		out[o++] = 0xf0;
		while (rest >= 255u) {
			out[o++] = 255;
			rest -= 255u;
		}
		out[o++] = (uint8_t)rest;
	}
	memcpy(out + o, in, n);
	return o + n;
}

static unsigned int g_mtu = 1280;

/* A configuration as a controller sends it, for this node and network.
 * damage: 1 MTU out of range, 2 certificate cut, 3 (in make_chunk) wrong
 * total length, 5 for another node, 6 for another network, 7 public network. */
static size_t make_config(uint8_t *out, uint64_t ts, int damage)
{
	uint8_t com[3 + 7 * 24 + 5 + 96];
	char head[160];
	size_t n;

	fill(com, sizeof(com));
	com[0] = 1;
	com[1] = 0;
	com[2] = 7;
	com[3 + 7 * 24] |= 1; /* signer not zero */
	n = (size_t)snprintf(head, sizeof(head), "v=7\nnwid=c0ffee000100000%d\nts=%llx\nr=1\nid=1a2b3c4d5%c\nt=%d\nmtu=%x\nI=",
			     (damage == 6) ? 2 : 1, (unsigned long long)ts, (damage == 5) ? 'f' : 'e', (damage == 7) ? 1 : 0,
			     (damage == 1) ? 9999u : g_mtu);
	memcpy(out, head, n);
	static const uint8_t ips[] = { 6, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 88, 4, 10, 11, 0, 13, 0, 24 };

	for (size_t i = 0; i < sizeof(ips); i++) { /* with the escapes of the dictionary format */
		if (ips[i] == 0) {
			out[n++] = '\\';
			out[n++] = '0';
		} else if (ips[i] == 10 || ips[i] == 13) {
			out[n++] = '\\';
			out[n++] = (ips[i] == 10) ? 'n' : 'r';
		} else {
			out[n++] = ips[i];
		}
	}
	out[n++] = '\n';
	out[n++] = 'C';
	out[n++] = '=';
	for (size_t i = 0; i < sizeof(com) - ((damage == 2) ? 10u : 0u); i++) {
		const uint8_t c = com[i];

		if (c == 0 || c == 10 || c == 13 || c == '\\' || c == '=') {
			out[n++] = '\\';
			out[n++] = (c == 0) ? '0' : (c == 10) ? 'n' : (c == 13) ? 'r' : (c == '=') ? 'e' : '\\';
		} else {
			out[n++] = c;
		}
	}
	return n;
}

/* Body of a configuration chunk message (after the OK header, if any). */
static size_t make_chunk(uint8_t *out, uint64_t ts, int damage)
{
	size_t n = 0, c;

	memcpy(out, nwid, 8);
	c = make_config(out + 10, ts, damage);
	out[8] = (uint8_t)(c >> 8);
	out[9] = (uint8_t)c;
	n = 10 + c;
	out[n++] = 0;       /* flags */
	fill(out + n, 8);   /* update ID */
	n += 8;
	out[n++] = 0;
	out[n++] = 0;
	out[n++] = (uint8_t)(c >> 8);
	out[n++] = (uint8_t)((damage == 3) ? c + 1u : c); /* total length */
	memset(out + n, 0, 4); /* chunk index */
	n += 4;
	out[n++] = 1;
	out[n++] = 0;
	out[n++] = 96;
	fill(out + n, 96);
	return n + 96;
}

static uint64_t g_ts = 100;

/* Make the body of one message of a chosen kind. Returns its length; *verb gets the verb byte. */
static size_t make_body(uint8_t *b, unsigned int peer, uint8_t *verb)
{
	const unsigned int kind = (unsigned int)(rnd() % 16u);
	size_t n = 0;

	switch (kind) {
	case 0: /* random verb, random body */
		*verb = (uint8_t)(rnd() & 0x1f);
		n = (size_t)(rnd() % ((rnd() & 7) ? 200u : 2021u));
		fill(b, n);
		break;
	case 1: /* HELLO */
		*verb = 0x01;
		n = 13 + 71 + (size_t)(rnd() % 40u);
		fill(b, n);
		memcpy(b + 13, peer_addr[peer], 5);
		if (rnd() & 7) {
			b[0] = 13;
			b[18] = 0;
			b[83] = 0;
		}
		break;
	case 2: /* OK(HELLO) for the waiting HELLO, or not */
		*verb = 0x03;
		n = 9 + (size_t)(rnd() % 30u);
		fill(b, n);
		b[0] = 0x01;
		if (rnd() & 1) {
			for (int i = 0; i < 8; i++) {
				b[1 + i] = (uint8_t)(leaf.ps[peer].hello_id >> (56 - 8 * i));
			}
		}
		break;
	case 3: /* OK(NETWORK_CONFIG_REQUEST), right or damaged */
	case 4: {
		const int damage = (rnd() % 3u == 0) ? (int)(rnd() % 8u) : 0;

		*verb = 0x03;
		b[0] = 0x0b;
		for (int i = 0; i < 8; i++) {
			b[1 + i] = (uint8_t)(leaf.cfg_req_id >> (56 - 8 * i));
		}
		n = 9 + make_chunk(b + 9, ++g_ts, damage);
		if (damage == 4) {
			n -= (size_t)(rnd() % 200u);
		}
		break;
	}
	case 5: /* NETWORK_CONFIG push */
		*verb = 0x0c;
		n = make_chunk(b, (rnd() & 1) ? ++g_ts : g_ts - 1u, 0);
		break;
	case 6: /* ECHO */
		*verb = 0x08;
		n = (size_t)(rnd() % 2021u);
		fill(b, n);
		break;
	case 7: /* ERROR */
		*verb = 0x02;
		n = 10 + (size_t)(rnd() % 12u);
		fill(b, n);
		b[9] = (rnd() & 1) ? 0x06 : (uint8_t)rnd();
		if (rnd() & 1) {
			memcpy(b + 10, nwid, (n - 10 < 8) ? n - 10 : 8);
		}
		break;
	case 8: /* FRAME */
	case 9:
		*verb = 0x06;
		n = 10 + (size_t)(rnd() % ((rnd() & 3) ? 1281u : 2011u));
		fill(b, n);
		memcpy(b, nwid, 8);
		break;
	case 10: /* EXT_FRAME */
	case 11: {
		uint8_t mac[6];

		*verb = 0x07;
		n = 9 + 14 + (size_t)(rnd() % 1300u);
		fill(b, n);
		memcpy(b, nwid, 8);
		b[8] = (rnd() & 3) ? (uint8_t)(rnd() & 0x10) : (uint8_t)rnd();
		if ((b[8] & 1) == 0) {
			memcpy(b + 9, (rnd() & 1) ? leaf.mac : (const uint8_t *)"\xff\xff\xff\xff\xff\xff", 6);
			ztl_mac_of(mac, peer_addr[peer], nwid);
			if (rnd() & 7) {
				memcpy(b + 15, mac, 6);
			}
		}
		break;
	}
	case 12: /* MULTICAST_FRAME */
	case 13: {
		*verb = 0x0e;
		n = 9 + 12 + 10 + (size_t)(rnd() % 1300u);
		fill(b, n);
		memcpy(b, nwid, 8);
		b[8] = (rnd() & 3) ? (uint8_t)(rnd() & 0x02) : (uint8_t)rnd();
		if ((b[8] & 5) == 0) {
			memset(b + 9 + ((b[8] & 2) ? 4 : 0), 0xff, 6);
		}
		break;
	}
	default: /* very short bodies of each verb */
		*verb = (uint8_t)(rnd() % 16u);
		n = (size_t)(rnd() % 12u);
		fill(b, n);
		break;
	}
	return n;
}

/* Give one datagram to the leaf from a heap block of its exact size and check the result. */
static uint8_t g_tx[ZTL_PKT_MAX], g_data[ZTL_PKT_MAX], g_id[8];
static size_t g_tx_len;
static struct ztl_frame g_frame;

static unsigned int input(const uint8_t *d, size_t len, int authentic, unsigned int from)
{
	uint8_t *dgram = malloc(len ? len : 1u);
	uint8_t *tx = malloc(ZTL_PKT_MAX);
	struct ztl_frame fr;
	size_t tx_len = 12345;
	unsigned int peer = 99;
	const uint8_t had_config = leaf.have_config;

	if (dgram == NULL || tx == NULL) {
		exit(2);
	}
	memcpy(dgram, d, len);
	memset(&fr, 0, sizeof(fr));
	const unsigned int r = ztl_input(&leaf, dgram, len, now_ms, tx, &tx_len, &peer, &fr);

	CHECK((r & ~7u) == 0, "unknown result bits %x", r);
	CHECK(authentic || r == 0, "result %x for a datagram without a right MAC", r);
	CHECK(ztl_reasm_ok(&leaf.node.reasm), "reassembly state not valid");
	if (r != 0) {
		CHECK(peer == from, "result for peer %u, packet from %u", peer, from);
	}
	if (r & ZTL_IN_REPLY) {
		n_reply++;
		CHECK(tx_len >= ZTL_PKT_MIN && tx_len <= ZTL_PKT_MAX, "reply length %zu", tx_len);
		if (tx_len >= ZTL_PKT_MIN && tx_len <= ZTL_PKT_MAX && peer < NPEERS) {
			CHECK(memcmp(tx + 8, peer_addr[peer], 5) == 0 && memcmp(tx + 13, self_addr, 5) == 0, "reply addresses");
			CHECK((tx[18] & 0x08) != 0, "reply not encrypted");
			CHECK(ztl_auth_open(peer_key[peer], tx, tx_len, 1) == 1, "reply does not open with the peer's key");
			memcpy(g_tx, tx, tx_len); /* opened: the body is plain */
			g_tx_len = tx_len;
		}
	} else {
		CHECK(tx_len == 0, "reply length %zu without a reply", tx_len);
	}
	if (r & ZTL_IN_FRAME) {
		uint8_t mac[6];
		const int in_dgram = fr.data >= dgram && fr.data + fr.len <= dgram + len;
		const int in_leaf = fr.data >= (const uint8_t *)&leaf && fr.data + fr.len <= (const uint8_t *)(&leaf + 1);

		n_frame++;
		CHECK(had_config, "frame without a configuration");
		CHECK(fr.len >= 1 && fr.len <= leaf.mtu, "frame length %u", fr.len);
		CHECK(in_dgram || in_leaf, "frame data outside the datagram and the leaf");
		ztl_mac_of(mac, peer_addr[from], nwid);
		CHECK(memcmp(fr.src, mac, 6) == 0, "frame source is not the peer");
		CHECK(memcmp(fr.dst, leaf.mac, 6) == 0 || (fr.dst[0] & 1), "frame for another station");
		if (in_dgram || in_leaf) {
			memcpy(g_data, fr.data, fr.len); /* reads all of it: the sanitizer checks */
			g_frame = fr;
			g_frame.data = g_data;
		}
	}
	if (r & ZTL_IN_CONFIG) {
		n_config++;
		if (leaf.have_config) {
			CHECK(leaf.mtu >= ZTL_MTU_MIN && leaf.mtu <= ZTL_MTU_MAX && leaf.com_len >= 1 &&
				      leaf.com_len <= ZTL_COM_MAX,
			      "configuration values out of range");
		}
	}
	free(dgram);
	free(tx);
	return r;
}

/* One sealed packet from a peer with this verb byte and body; returns the result of ztl_input(). */
static unsigned int from_peer(unsigned int peer, uint8_t verb, const uint8_t *body, size_t n, int encrypt)
{
	static uint8_t pkt[ZTL_PKT_MAX];

	fill(pkt, 8);
	memcpy(pkt + 8, self_addr, 5);
	memcpy(pkt + 13, peer_addr[peer], 5);
	memset(pkt + 18, 0, 9);
	pkt[27] = verb;
	memcpy(pkt + 28, body, n);
	ztl_auth_seal(peer_key[peer], pkt, 28 + n, encrypt);
	memcpy(g_id, pkt, 8); /* the packet ID, for the checks of the answer */
	return input(pkt, 28 + n, 1, peer);
}

static void put64(uint8_t *p, uint64_t v)
{
	for (int i = 0; i < 8; i++) {
		p[i] = (uint8_t)(v >> (56 - 8 * i));
	}
}

/* Fixed cases with known answers. Peer 0 is the controller. */
static void scenario(void)
{
	static uint8_t b[ZTL_PKT_MAX], tx[ZTL_PKT_MAX];
	uint8_t id[8], mac1[6], mac2[6];
	unsigned int peer = 99, r;
	size_t n;

	ztl_mac_of(mac1, peer_addr[1], nwid);
	ztl_mac_of(mac2, peer_addr[2], nwid);

	/* Start: one HELLO for each pinned peer, nothing else, and no second one at the same time. */
	for (unsigned int i = 0; i < NPEERS; i++) {
		n = ztl_poll(&leaf, now_ms, tx, &peer);
		CHECK(n == 129 && peer == i && tx[27] == 0x01 && (tx[18] & 0x38) == 0, "first HELLO for peer %u", i);
		CHECK(ztl_auth_open(peer_key[i], tx, n, 0) == 1 && tx[28] == 11 && memcmp(tx + 28 + 13, self_addr, 5) == 0 &&
			      tx[28 + 18] == 0 && memcmp(tx + 28 + 19, leaf.pub, 64) == 0 && tx[28 + 83] == 0,
		      "HELLO contents");
	}
	CHECK(ztl_poll(&leaf, now_ms, tx, &peer) == 0, "more than one HELLO for each peer");
	/* A frame before any configuration: not delivered. */
	memcpy(b, nwid, 8);
	b[8] = 8;
	b[9] = 0;
	fill(b + 10, 100);
	CHECK(from_peer(1, 0x06, b, 110, 1) == 0 && leaf.stats.rx_no_config == 1, "frame delivered without a configuration");
	/* Nothing goes to the controller but HELLO until it has answered. */
	now_ms += 100;
	CHECK(ztl_poll(&leaf, now_ms, tx, &peer) == 0, "packet to a peer that has not been heard");

	/* HELLO from peer 1: OK(HELLO) with the packet ID, the time stamp, and version 11. */
	fill(b, 13 + 71 + 17);
	b[0] = 13;
	memcpy(b + 13, peer_addr[1], 5);
	b[18] = 0;
	b[83] = 0;
	r = from_peer(1, 0x01, b, 13 + 71 + 17, 0);
	memcpy(id, g_id, 8);
	CHECK(r == ZTL_IN_REPLY && g_tx_len == 28 + 9 + 16, "answer to HELLO");
	CHECK(memcmp(g_tx + 29, id, 8) == 0, "OK(HELLO) does not name the packet it answers");
	CHECK(g_tx[27] == 0x03 && g_tx[28] == 0x01 && memcmp(g_tx + 37, b + 5, 8) == 0 && g_tx[45] == 11 && g_tx[46] == 0 &&
		      g_tx[47] == 0 && g_tx[48] == 0 && g_tx[49] == 1 && g_tx[50] == 0 && g_tx[51] == 0 && g_tx[52] == 0,
	      "OK(HELLO) contents");
	/* HELLO with another address in its identity: no answer. */
	b[13] ^= 1;
	CHECK(from_peer(1, 0x01, b, 13 + 71 + 17, 0) == 0, "HELLO with a foreign identity answered");

	/* ECHO: the same bytes come back. */
	fill(b, 300);
	r = from_peer(2, 0x08, b, 300, 1);
	CHECK(r == ZTL_IN_REPLY && g_tx_len == 28 + 9 + 300 && g_tx[28] == 0x08 && memcmp(g_tx + 29, g_id, 8) == 0 &&
		      memcmp(g_tx + 37, b, 300) == 0,
	      "answer to ECHO");

	/* The controller answers the HELLO; then the configuration request goes out. */
	b[0] = 0x01;
	put64(b + 1, leaf.ps[0].hello_id ^ 1u);
	fill(b + 9, 16);
	b[17] = 13;
	CHECK(from_peer(0, 0x03, b, 25, 1) == 0 && leaf.ps[0].hello_wait, "OK for another packet ID taken");
	put64(b + 1, leaf.ps[0].hello_id);
	CHECK(from_peer(0, 0x03, b, 25, 1) == 0 && !leaf.ps[0].hello_wait, "OK(HELLO) not taken");
	n = ztl_poll(&leaf, now_ms, tx, &peer);
	CHECK(n != 0 && peer == 0 && ztl_auth_open(peer_key[0], tx, n, 1) == 1 && tx[27] == 0x0b && memcmp(tx + 28, nwid, 8) == 0 &&
		      tx[36] == 0 && tx[37] == n - 28 - 10 - 16 && memcmp(tx + 38, "v=7\n", 4) == 0,
	      "configuration request");
	const uint64_t req = leaf.cfg_req_id;

	/* Refused configurations: a push from a peer that is not the controller; an
	 * answer for another request; wrong MTU; broken certificate; wrong total
	 * length; for another node; for another network; a public network. */
	n = make_chunk(b, 500, 0);
	CHECK(from_peer(1, 0x0c, b, n, 1) == 0 && !leaf.have_config, "configuration from a peer that is not the controller");
	b[0] = 0x0b;
	put64(b + 1, req ^ 1u);
	n = 9 + make_chunk(b + 9, 500, 0);
	CHECK(from_peer(0, 0x03, b, n, 1) == 0 && !leaf.have_config, "configuration for another request");
	for (int damage = 1; damage <= 7; damage++) {
		if (damage == 4) {
			continue;
		}
		put64(b + 1, leaf.cfg_req_id);
		n = 9 + make_chunk(b + 9, 500, damage);
		r = from_peer(0, 0x03, b, n, 1);
		CHECK(!leaf.have_config && (r & ~ZTL_IN_CONFIG) == 0, "damaged configuration %d accepted", damage);
		CHECK(leaf.req_wait, "a refused answer ended the wait for the configuration");
	}
	/* The right one, through the LZ4 decoder (stored form), then the same answer again. */
	put64(b + 1, leaf.cfg_req_id);
	n = 9 + make_chunk(b + 9, 500, 0);
	static uint8_t comp[ZTL_PKT_MAX];
	const size_t c = lz4_store(comp, b, n);

	r = from_peer(0, 0x03 | 0x80, comp, c, 1);
	CHECK(r == ZTL_IN_CONFIG && leaf.have_config && leaf.mtu == 1280 && leaf.prefix == 24 && leaf.ip[0] == 10 &&
		      leaf.ip[1] == 11 && leaf.ip[2] == 0 && leaf.ip[3] == 13 && leaf.com_len == 272 && leaf.cfg_ts == 500 &&
		      leaf.stats.rx_lz4 == 1,
	      "configuration not accepted (result %x)", r);
	CHECK(from_peer(0, 0x03 | 0x80, comp, c, 1) == 0 && leaf.stats.configs == 1, "the same configuration answer taken twice");
	/* A push: only if newer. */
	n = make_chunk(b, 499, 0);
	CHECK(from_peer(0, 0x0c, b, n, 1) == 0 && leaf.cfg_ts == 500, "older configuration push accepted");
	n = make_chunk(b, 501, 0);
	CHECK(from_peer(0, 0x0c, b, n, 1) == ZTL_IN_CONFIG && leaf.cfg_ts == 501, "newer configuration push refused");

	/* To each peer that was heard: certificate, then the two multicast groups. Peer 2 was heard through ECHO. */
	for (unsigned int i = 0; i < NPEERS; i++) {
		n = ztl_poll(&leaf, now_ms, tx, &peer);
		CHECK(n == 28 + 272 + 9 && peer == i && ztl_auth_open(peer_key[i], tx, n, 1) == 1 && tx[27] == 0x0a &&
			      memcmp(tx + 28, leaf.com, 272) == 0 && tx[300] == 0,
		      "certificate push to peer %u", i);
		n = ztl_poll(&leaf, now_ms, tx, &peer);
		CHECK(n == 28 + 36 && peer == i && ztl_auth_open(peer_key[i], tx, n, 1) == 1 && tx[27] == 0x09 &&
			      memcmp(tx + 28, nwid, 8) == 0 && tx[36] == 0xff && memcmp(tx + 42, leaf.ip, 4) == 0 &&
			      memcmp(tx + 46, nwid, 8) == 0 && tx[60] == 0 && tx[63] == 0,
		      "multicast subscription to peer %u", i);
	}
	CHECK(ztl_poll(&leaf, now_ms, tx, &peer) == 0, "packets without end");

	/* FRAME: delivered to the own address, from the peer's address. */
	memcpy(b, nwid, 8);
	b[8] = 0x08;
	b[9] = 0x00;
	fill(b + 10, 1280);
	r = from_peer(1, 0x06, b, 10 + 1280, 1);
	CHECK(r == ZTL_IN_FRAME && g_frame.len == 1280 && g_frame.ethertype == 0x0800 && memcmp(g_frame.data, b + 10, 1280) == 0 &&
		      memcmp(g_frame.dst, leaf.mac, 6) == 0 && memcmp(g_frame.src, mac1, 6) == 0,
	      "FRAME not delivered");
	CHECK(from_peer(1, 0x06, b, 10 + 1281, 1) == 0, "frame longer than the MTU delivered");
	CHECK(from_peer(1, 0x06, b, 10, 1) == 0, "empty frame delivered");
	b[7] ^= 1;
	CHECK(from_peer(1, 0x06, b, 10 + 100, 1) == 0, "frame of another network delivered");
	b[7] ^= 1;

	/* EXT_FRAME: to this node from the peer, with the OK that flag 0x10 asks for. */
	b[8] = 0x10;
	memcpy(b + 9, leaf.mac, 6);
	memcpy(b + 15, mac1, 6);
	b[21] = 0x08;
	b[22] = 0x06;
	fill(b + 23, 28);
	r = from_peer(1, 0x07, b, 23 + 28, 1);
	CHECK(r == (ZTL_IN_FRAME | ZTL_IN_REPLY) && g_frame.len == 28 && g_frame.ethertype == 0x0806 &&
		      memcmp(g_frame.data, b + 23, 28) == 0 && g_tx_len == 28 + 9 + 8 && g_tx[28] == 0x07 && memcmp(g_tx + 29, g_id, 8) == 0 &&
		      memcmp(g_tx + 37, nwid, 8) == 0,
	      "EXT_FRAME with acknowledgement");
	memcpy(b + 15, mac2, 6); /* source is another node: bridging is not accepted */
	CHECK(from_peer(1, 0x07, b, 23 + 28, 1) == 0, "frame with a foreign source delivered");
	memcpy(b + 15, mac1, 6);
	memcpy(b + 9, mac2, 6); /* destination is a third station */
	CHECK(from_peer(1, 0x07, b, 23 + 28, 1) == 0, "frame for a third station delivered");
	/* With a certificate in front (flag 0x01): skipped, the frame is found behind it. */
	b[8] = 0x01;
	memcpy(b + 9, leaf.com, 272);
	memcpy(b + 9 + 272, leaf.mac, 6);
	memcpy(b + 9 + 278, mac1, 6);
	b[9 + 284] = 0x08;
	b[9 + 285] = 0x00;
	fill(b + 9 + 286, 60);
	r = from_peer(1, 0x07, b, 9 + 286 + 60, 1);
	CHECK(r == ZTL_IN_FRAME && g_frame.len == 60 && memcmp(g_frame.data, b + 9 + 286, 60) == 0, "EXT_FRAME behind a certificate");
	CHECK(from_peer(1, 0x07, b, 9 + 200, 1) == 0, "EXT_FRAME with a cut certificate delivered");

	/* MULTICAST_FRAME: every optional field, then a destination that is no group address. */
	b[8] = 0x06; /* gather limit and source */
	fill(b + 9, 4);
	memcpy(b + 13, mac1, 6);
	memset(b + 19, 0xff, 6);
	fill(b + 25, 4);
	b[29] = 0x08;
	b[30] = 0x06;
	fill(b + 31, 28);
	r = from_peer(1, 0x0e, b, 31 + 28, 1);
	CHECK(r == ZTL_IN_FRAME && g_frame.len == 28 && g_frame.ethertype == 0x0806 && g_frame.dst[0] == 0xff &&
		      memcmp(g_frame.src, mac1, 6) == 0 && memcmp(g_frame.data, b + 31, 28) == 0,
	      "MULTICAST_FRAME not delivered");
	memcpy(b + 13, mac2, 6);
	CHECK(from_peer(1, 0x0e, b, 31 + 28, 1) == 0, "multicast frame with a foreign source delivered");
	memcpy(b + 13, mac1, 6);
	b[19] = 0xfe;
	CHECK(from_peer(1, 0x0e, b, 31 + 28, 1) == 0, "multicast frame to a single station delivered");

	/* ERROR "need certificate": the certificate goes out again at the next poll. */
	fill(b, 9);
	b[9] = 0x06;
	memcpy(b + 10, nwid, 8);
	CHECK(from_peer(1, 0x02, b, 18, 1) == 0, "ERROR gave a result");
	n = ztl_poll(&leaf, now_ms, tx, &peer);
	CHECK(n == 28 + 272 + 9 && peer == 1 && ztl_auth_open(peer_key[1], tx, n, 1) == 1 && tx[27] == 0x0a,
	      "certificate not sent again after the peer asked");
	(void)ztl_poll(&leaf, now_ms, tx, &peer); /* and the groups */

	/* Frames from the host. To one peer's address: FRAME to that peer only. */
	fill(b, 1280);
	CHECK(ztl_frame_to(&leaf, 2, mac1, 0x0800, b, 1280, tx) == 0, "frame sent to a peer that does not own the address");
	n = ztl_frame_to(&leaf, 1, mac1, 0x0800, b, 1280, tx);
	CHECK(n == 28 + 10 + 1280 && ztl_auth_open(peer_key[1], tx, n, 1) == 1 && tx[27] == 0x06 && memcmp(tx + 28, nwid, 8) == 0 &&
		      tx[36] == 0x08 && tx[37] == 0x00 && memcmp(tx + 38, b, 1280) == 0,
	      "FRAME to a peer");
	CHECK(ztl_frame_to(&leaf, 1, mac1, 0x0800, b, 1281, tx) == 0 && ztl_frame_to(&leaf, 1, mac1, 0x0800, b, 0, tx) == 0,
	      "frame of a wrong length sent");
	/* Broadcast ARP request: MULTICAST_FRAME to every peer, group number = the address asked for. */
	static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	memcpy(b, "\x00\x01\x08\x00\x06\x04\x00\x01", 8);
	for (unsigned int i = 0; i < NPEERS; i++) {
		n = ztl_frame_to(&leaf, i, bcast, 0x0806, b, 28, tx);
		CHECK(n == 28 + 21 + 28 && ztl_auth_open(peer_key[i], tx, n, 1) == 1 && tx[27] == 0x0e && tx[36] == 0 &&
			      memcmp(tx + 37, bcast, 6) == 0 && memcmp(tx + 43, b + 24, 4) == 0 && tx[47] == 0x08 && tx[48] == 0x06 &&
			      memcmp(tx + 49, b, 28) == 0,
		      "broadcast to peer %u", i);
	}
	CHECK(ztl_frame_to(&leaf, NPEERS, bcast, 0x0806, b, 28, tx) == 0 && ztl_frame_to(&leaf, ZTL_PEERS, bcast, 0x0806, b, 28, tx) == 0,
	      "frame sent to a peer that is not pinned");
	/* Packet IDs: each packet has the next number. */
	const uint64_t before = leaf.next_id;

	n = ztl_frame_to(&leaf, 1, mac1, 0x0800, b, 100, tx);
	put64(id, before);
	CHECK(n != 0 && memcmp(tx, id, 8) == 0 && leaf.next_id == before + 1u, "packet ID is not the counter");

	/* A peer that sends nothing for longer than the timeout gets HELLO only. */
	now_ms += ZTL_PEER_TIMEOUT_MS + 1u;
	n = ztl_poll(&leaf, now_ms, tx, &peer);
	CHECK(n == 129 && peer == 0 && tx[27] == 0x01, "no HELLO after the HELLO period"); /* HELLO is not encrypted */
	CHECK(ztl_frame_to(&leaf, 1, mac1, 0x0800, b, 100, tx) != 0, "peer state changed outside its own poll");
	(void)ztl_poll(&leaf, now_ms, tx, &peer);
	(void)ztl_poll(&leaf, now_ms, tx, &peer);
	CHECK(ztl_poll(&leaf, now_ms, tx, &peer) == 0, "packets to peers that were not heard");
	CHECK(ztl_frame_to(&leaf, 1, mac1, 0x0800, b, 100, tx) == 0, "frame sent to a peer that was not heard for too long");

	/* An ARP reply to the broadcast address is not an ARP request: group number 0. */
	fill(b, 9);
	CHECK(from_peer(2, 0x08, b, 9, 1) == ZTL_IN_REPLY, "ECHO");
	memcpy(b, "\x00\x01\x08\x00\x06\x04\x00\x02", 8);
	memset(b + 24, 0x55, 4);
	n = ztl_frame_to(&leaf, 2, bcast, 0x0806, b, 28, tx);
	CHECK(n != 0 && ztl_auth_open(peer_key[2], tx, n, 1) == 1 && tx[43] == 0 && tx[46] == 0, "ARP reply sent with an ARP request group");

	/* An answer to a request must not bring back a configuration older than a pushed one. */
	leaf.req_wait = 1;
	b[0] = 0x0b;
	put64(b + 1, leaf.cfg_req_id);
	n = 9 + make_chunk(b + 9, 400, 0);
	CHECK(from_peer(0, 0x03, b, n, 1) == 0 && leaf.cfg_ts == 501, "older configuration taken as the answer to a request");
	/* The controller refuses: first for another request (no effect), then for the waiting one. */
	b[0] = 0x0b;
	put64(b + 1, leaf.cfg_req_id ^ 1u);
	b[9] = 0x07;
	memcpy(b + 10, nwid, 8);
	CHECK(from_peer(0, 0x02, b, 18, 1) == 0 && leaf.have_config, "refusal for another request taken");
	CHECK(from_peer(1, 0x02, b, 18, 1) == 0 && leaf.have_config, "refusal from a peer that is not the controller taken");
	put64(b + 1, leaf.cfg_req_id);
	CHECK(from_peer(0, 0x02, b, 18, 1) == ZTL_IN_CONFIG && !leaf.have_config, "refusal by the controller ignored");
	memcpy(b, nwid, 8);
	b[8] = 8;
	b[9] = 0;
	CHECK(from_peer(2, 0x06, b, 110, 1) == 0, "frame delivered after the controller refused the node");
	g_ts = 600; /* the random rounds continue with newer configurations */
}

/* One authentic packet from a peer, sometimes compressed, sometimes in two parts. */
static void round_packet(void)
{
	static uint8_t body[ZTL_PKT_MAX + 64], pkt[ZTL_PKT_MAX + 64], comp[2 * ZTL_PKT_MAX];
	const unsigned int peer = (unsigned int)(rnd() % NPEERS);
	uint8_t verb = 0;
	size_t n = make_body(body, peer, &verb);
	int encrypt = 1;

	if (rnd() % 5u == 0) { /* compressed: stored form, or a damaged or random block */
		size_t c = lz4_store(comp, body, n);

		if (rnd() % 3u == 0) {
			const size_t hits = 1 + (size_t)(rnd() % 4u);

			for (size_t i = 0; i < hits && c > 0; i++) {
				comp[rnd() % c] = (uint8_t)rnd();
			}
		} else if (rnd() % 4u == 0) {
			c = (size_t)(rnd() % 300u);
			fill(comp, c);
		}
		if (c <= ZTL_PKT_MAX - ZTL_PKT_MIN) {
			memcpy(body, comp, c);
			n = c;
			verb |= 0x80;
		}
	}
	if (n > ZTL_PKT_MAX - ZTL_PKT_MIN) {
		n = ZTL_PKT_MAX - ZTL_PKT_MIN;
	}
	fill(pkt, 8);
	memcpy(pkt + 8, self_addr, 5);
	memcpy(pkt + 13, peer_addr[peer], 5);
	pkt[18] = 0;
	memset(pkt + 19, 0, 8);
	pkt[27] = verb;
	memcpy(pkt + 28, body, n);
	if ((verb & 0x1f) == 0x01 && (rnd() & 3)) {
		encrypt = 0; /* HELLO as stock peers send it */
	}
	const size_t len = 28 + n;
	const int split = len > 60 && (rnd() % 6u == 0);

	if (split) {
		pkt[18] = 0x40;
	}
	ztl_auth_seal(peer_key[peer], pkt, len, encrypt);
	if (!split && rnd() % 40u == 0) {
		/* One bit wrong: no effect, unless the bit is in the hop count
		 * (flag bits 0 .. 2), which relays change and the MAC does not cover. */
		const size_t at = (size_t)(rnd() % len);
		const unsigned int bit = (unsigned int)(rnd() % 8u);

		pkt[at] ^= (uint8_t)(1u << bit);
		(void)input(pkt, len, at == 18u && bit < 3u, peer);
		return;
	}
	if (!split) {
		(void)input(pkt, len, 1, peer);
		return;
	}
	/* Head and one fragment, in either order. */
	static uint8_t frag[ZTL_PKT_MAX];
	const size_t cut = 40 + (size_t)(rnd() % (len - 59));

	memcpy(frag, pkt, 8);
	memcpy(frag + 8, self_addr, 5);
	frag[13] = 0xff;
	frag[14] = 0x21;
	frag[15] = 0;
	memcpy(frag + 16, pkt + cut, len - cut);
	if (rnd() & 1) {
		(void)input(pkt, cut, 1, peer);
		(void)input(frag, 16 + len - cut, 1, peer);
	} else {
		(void)input(frag, 16 + len - cut, 1, peer);
		(void)input(pkt, cut, 1, peer);
	}
}

/* The decoder alone, on random and on damaged blocks, with exact heap blocks. */
static void round_lz4(void)
{
	const size_t n = (size_t)(rnd() % ((rnd() & 3) ? 64u : 2049u));
	const size_t cap = (size_t)(rnd() % ((rnd() & 3) ? 300u : 2049u));
	uint8_t *src = malloc(n ? n : 1u), *dst = malloc(cap ? cap : 1u);

	if (src == NULL || dst == NULL) {
		exit(2);
	}
	fill(src, n);
	if (n > 0 && (rnd() & 1)) { /* more runs that reach the match code: small offsets */
		src[0] = (uint8_t)((1u + rnd() % 14u) << 4 | (rnd() & 0x0f));
		for (size_t i = (size_t)(src[0] >> 4) + 1u; i + 1u < n; i += 2u + (size_t)(rnd() % 20u)) {
			src[i] = (uint8_t)(1u + rnd() % 8u);
			src[i + 1u] = 0;
		}
	}
	const size_t r = ztl_lz4_decode(dst, cap, src, n);

	CHECK(r <= cap, "LZ4 result %zu above the buffer size %zu", r, cap);
	if (r != 0) {
		volatile uint8_t sum = 0;

		n_lz4_ok++;
		for (size_t i = 0; i < r; i++) {
			sum = (uint8_t)(sum + dst[i]); /* all result bytes were written (memory sanitizer builds) */
		}
	}
	free(src);
	free(dst);
}

static void round_poll_and_send(void)
{
	static uint8_t tx[ZTL_PKT_MAX], data[ZTL_MTU_MAX + 8];
	unsigned int peer = 99;
	size_t n;
	int guard = 0;

	now_ms += (uint32_t)(rnd() % ((rnd() & 15) ? 3000u : 400000u));
	while ((n = ztl_poll(&leaf, now_ms, tx, &peer)) != 0) {
		CHECK(n >= ZTL_PKT_MIN && n <= ZTL_UDP_MAX && peer < NPEERS, "poll packet of %zu bytes for peer %u", n, peer);
		CHECK(++guard <= 4 * (int)ZTL_PEERS, "poll does not come to an end");
		if (guard > 4 * (int)ZTL_PEERS) {
			break;
		}
	}
	/* Frames from the host: every destination kind and length, also wrong ones. */
	uint8_t dst[6];
	const size_t len = (size_t)(rnd() % (ZTL_MTU_MAX + 8u));
	const unsigned int i = (unsigned int)(rnd() % (ZTL_PEERS + 2u));

	fill(data, len);
	if (rnd() & 1) {
		memset(dst, 0xff, 6);
	} else {
		ztl_mac_of(dst, peer_addr[rnd() % NPEERS], nwid);
	}
	n = ztl_frame_to(&leaf, i, dst, (rnd() & 1) ? 0x0806 : 0x0800, data, len, tx);
	CHECK(n <= ZTL_PKT_MAX, "frame packet of %zu bytes", n);
	if (n != 0) {
		size_t at = 0;
		const size_t first = ztl_tx_first(n);
		static uint8_t whole[ZTL_PKT_MAX];

		CHECK(i < NPEERS && leaf.have_config && len >= 1 && len <= leaf.mtu, "frame sent without reason");
		/* Join the two datagrams as a receiver does; the peer's key must open the result. */
		memcpy(whole, tx, first);
		const size_t second = ztl_tx_second(tx, n, &at);

		CHECK((n > ZTL_UDP_MAX) == (second != 0), "second datagram: %zu for a packet of %zu", second, n);
		CHECK(((whole[18] & 0x40) != 0) == (n > ZTL_UDP_MAX), "\"fragmented\" flag wrong for a packet of %zu bytes", n);
		if (second != 0) {
			n_two_part++;
			CHECK(second > 16 && second <= ZTL_UDP_MAX && tx[at + 13] == 0xff && tx[at + 14] == 0x21 &&
				      memcmp(tx + at, whole, 13) == 0,
			      "fragment header");
			memcpy(whole + first, tx + at + 16, second - 16);
		}
		if (i < NPEERS) {
			CHECK(ztl_auth_open(peer_key[i], whole, n, 1) == 1, "sent frame does not open with the peer's key");
		}
	}
}

int main(int argc, char **argv)
{
	static uint8_t pub[ZTL_PUB_LEN], junk[ZTL_PKT_MAX + 2];
	const unsigned long rounds = (argc > 1) ? strtoul(argv[1], NULL, 10) : 200000ul;

	fill(pub, sizeof(pub));
	ztl_init(&leaf, self_addr, pub, nwid, rnd());
	for (unsigned int i = 0; i < NPEERS; i++) {
		fill(peer_key[i], ZTL_KEY_LEN);
		if (ztl_pin(&leaf, peer_addr[i], peer_key[i]) != (int)i) {
			return 2;
		}
	}
	CHECK(leaf.ctrl == 0, "controller not found among the peers");
	CHECK(ztl_pin(&leaf, peer_addr[1], peer_key[1]) == -1 && ztl_pin(&leaf, self_addr, peer_key[1]) == -1,
	      "second pin of an address, or pin of the own address");
	scenario();
	const unsigned long fixed_checks = g_checks;

	for (g_round = 0; g_round < rounds; g_round++) {
		const unsigned int what = (unsigned int)(rnd() % 16u);

		g_mtu = (rnd() & 1) ? 1280u : 1500u; /* with 1500, long frames need two datagrams */
		if (what < 10u) {
			round_packet();
		} else if (what < 12u) {
			round_lz4();
		} else if (what < 15u) {
			round_poll_and_send();
		} else { /* a datagram that no peer made */
			const size_t n = (size_t)(rnd() % (ZTL_PKT_MAX + 2u));

			fill(junk, n);
			if (n > 18 && (rnd() & 1)) {
				memcpy(junk + 8, self_addr, 5);
				memcpy(junk + 13, peer_addr[rnd() % NPEERS], 5);
				junk[18] &= 0x4f;
			}
			if (n <= ZTL_PKT_MAX) {
				(void)input(junk, n, 0, 0);
			}
		}
	}
	printf("proto: %lu fixed checks; %lu random rounds, %lu replies, %lu frames, %lu configurations, %lu LZ4 blocks decoded, %lu packets sent in two parts, %u packets through the gate; %lu checks, %lu failed\n",
	       fixed_checks, rounds, n_reply, n_frame, n_config, n_lz4_ok, n_two_part, leaf.node.rx.ok, g_checks, g_fail);
	/* A run that never reached the parsers is a failure, not a pass. */
	return (g_fail == 0 && n_reply > 0 && n_frame > 0 && n_config > 0 && n_lz4_ok > 0 && n_two_part > 0) ? 0 : 1;
}
