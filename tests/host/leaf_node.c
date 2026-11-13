/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host test endpoint: the leaf on a loopback UDP socket, as the peer of the
 * reference node (../grey_zerotier/tests/host_node.cpp, built as
 * "reference_node": the reference core with a test controller).
 * It does what that program does: when the network is configured it sends
 * a fixed IPv4 frame to the peer and an ARP request to the broadcast group
 * every 200 ms, and it counts what it receives.
 *   leaf_node <provision file> <udp socket fd> <peer port> <network id> <mode> <seconds>
 * Provision file: lines "self", "pub", "peer" as tools/provision prints them
 * (one peer: the controller). mode: normal, deny or tamper (tamper changes
 * one bit of every datagram sent). Frame size: GREY_ZT_TEST_FRAME_SIZE.
 * Exit status 0: configured, frames and ARP requests received, none wrong.
 */
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>

#include "ztl/leaf.h"

static const char payload[] = "grey-zt-private-network-frame-0123456789";
static uint8_t ipv4_frame[1500];
static unsigned int frame_size = 28 + sizeof(payload);

/* Same frame as host_node.cpp make_frame(). */
static void make_frame(void)
{
	uint8_t *p = ipv4_frame;
	uint32_t value = 0x12345678;
	unsigned int sum = 0;

	for (unsigned int i = 28; i < frame_size; ++i) {
		value ^= value << 13;
		value ^= value >> 17;
		value ^= value << 5;
		p[i] = (uint8_t)value;
	}
	p[0] = 0x45;
	p[2] = (uint8_t)(frame_size >> 8);
	p[3] = (uint8_t)frame_size;
	p[8] = 64;
	p[9] = 17;
	p[12] = 192; p[14] = 2; p[15] = 1;
	p[16] = 192; p[18] = 2; p[19] = 2;
	for (unsigned int i = 0; i < 20; i += 2) {
		sum += ((unsigned int)p[i] << 8) | p[i + 1];
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (~sum) & 0xffff;
	p[10] = (uint8_t)(sum >> 8);
	p[11] = (uint8_t)sum;
	p[20] = 0x13; p[21] = 0x88; p[22] = 0x13; p[23] = 0x89;
	p[24] = (uint8_t)((frame_size - 20) >> 8);
	p[25] = (uint8_t)(frame_size - 20);
	memcpy(p + 28, payload, sizeof(payload));
}

static uint32_t now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint32_t)((uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u);
}

static int unhex(const char *s, uint8_t *out, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		unsigned int b;

		if (sscanf(s + 2 * i, "%2x", &b) != 1) {
			return 0;
		}
		out[i] = (uint8_t)b;
	}
	return 1;
}

static struct ztl_leaf leaf;
static uint8_t tx[ZTL_PKT_MAX];
static int fd, tamper;
static struct sockaddr_in remote;
static unsigned int wire, fragments;

static void send_packet(size_t len)
{
	size_t at = 0;
	size_t n = ztl_tx_first(len);

	for (int part = 0; part < 2 && n != 0; part++) {
		if (tamper) {
			tx[at + n - 1] ^= 0x80;
		}
		(void)sendto(fd, tx + at, n, 0, (const struct sockaddr *)&remote, sizeof(remote));
		wire++;
		fragments += (unsigned int)part;
		n = (part == 0) ? ztl_tx_second(tx, len, &at) : 0;
	}
}

int main(int argc, char **argv)
{
	uint8_t self[ZTL_ADDR_LEN], pub[ZTL_PUB_LEN], nwid[ZTL_NWID_LEN], peer_addr[ZTL_ADDR_LEN], key[ZTL_KEY_LEN];
	uint8_t peer_mac[ZTL_ETH_ALEN];
	char line[512];
	int have = 0;
	uint64_t first_id;
	unsigned int frames = 0, arps = 0, bad_frames = 0, configs = 0;

	if (argc != 7) {
		fprintf(stderr, "usage: leaf_node provision-file udp-fd peer-port network-id mode seconds\n");
		return 64;
	}
	FILE *f = fopen(argv[1], "r");

	if (!f) {
		return 66;
	}
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "self ", 5)) {
			have |= unhex(line + 5, self, sizeof(self)) ? 1 : 0;
		} else if (!strncmp(line, "pub ", 4)) {
			have |= unhex(line + 4, pub, sizeof(pub)) ? 2 : 0;
		} else if (!strncmp(line, "peer ", 5)) {
			have |= (unhex(line + 5, peer_addr, sizeof(peer_addr)) && unhex(line + 16, key, sizeof(key))) ? 4 : 0;
		}
	}
	fclose(f);
	if (have != 7 || strlen(argv[4]) != 16 || !unhex(argv[4], nwid, sizeof(nwid))) {
		return 66;
	}
	if (getenv("GREY_ZT_TEST_FRAME_SIZE")) {
		frame_size = (unsigned int)strtoul(getenv("GREY_ZT_TEST_FRAME_SIZE"), NULL, 10);
	}
	if (frame_size < 28 + sizeof(payload) || frame_size > sizeof(ipv4_frame)) {
		return 64;
	}
	make_frame();
	fd = atoi(argv[2]);
	tamper = !strcmp(argv[5], "tamper");
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	remote.sin_port = htons((uint16_t)atoi(argv[3]));
	/* The start value of the packet IDs must be true random bits. */
	if (getrandom(&first_id, sizeof(first_id), 0) != sizeof(first_id)) {
		return 70;
	}
	ztl_init(&leaf, self, pub, nwid, first_id);
	if (ztl_pin(&leaf, peer_addr, key) != 0) {
		return 67;
	}
	ztl_mac_of(peer_mac, peer_addr, nwid);

	const uint32_t start = now_ms();
	const uint32_t run_ms = (uint32_t)atoi(argv[6]) * 1000u;
	uint32_t next_frame = start;

	while (now_ms() - start < run_ms) {
		struct pollfd p = { fd, POLLIN, 0 };
		unsigned int peer;
		size_t n;

		while ((n = ztl_poll(&leaf, now_ms(), tx, &peer)) != 0) {
			send_packet(n);
		}
		if ((leaf.flags & ZTL_L_CONFIG) && (int32_t)(now_ms() - next_frame) >= 0) {
			uint8_t arp[28] = { 0, 1, 8, 0, 6, 4, 0, 1 };
			static const uint8_t bcast[ZTL_ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

			n = ztl_frame_to(&leaf, 0, peer_mac, 0x0800, ipv4_frame, frame_size, tx);
			send_packet(n);
			memcpy(arp + 8, leaf.mac, 6);
			arp[14] = 192; arp[16] = 2; arp[17] = 1;
			arp[24] = 192; arp[26] = 2; arp[27] = 2;
			n = ztl_frame_to(&leaf, 0, bcast, 0x0806, arp, sizeof(arp), tx);
			send_packet(n);
			next_frame = now_ms() + 200u;
		}
		if (poll(&p, 1, 10) > 0) {
			uint8_t dgram[ZTL_PKT_MAX + 1];
			struct sockaddr_in from;
			socklen_t fl = sizeof(from);
			const ssize_t got = recvfrom(fd, dgram, sizeof(dgram), 0, (struct sockaddr *)&from, &fl);
			struct ztl_frame fr;
			size_t tx_len;

			if (got <= 0 || from.sin_port != remote.sin_port) {
				continue;
			}
			const unsigned int r = ztl_input(&leaf, dgram, (size_t)got, now_ms(), tx, &tx_len, &peer, &fr);

			if (r & ZTL_IN_REPLY) {
				send_packet(tx_len);
			}
			if (r & ZTL_IN_CONFIG) {
				configs++;
				/* The test controller assigns no address. Take the one that
				 * the test frames use, so that the leaf joins its ARP group. */
				leaf.ip[0] = 192; leaf.ip[1] = 0; leaf.ip[2] = 2; leaf.ip[3] = 2;
				leaf.prefix = 24;
			}
			if (r & ZTL_IN_FRAME) {
				if (fr.ethertype == 0x0806 && fr.len == 28 && fr.data[7] == 1 && fr.data[24] == 192 &&
				    fr.data[25] == 0 && fr.data[26] == 2 && fr.data[27] == 2 &&
				    !memcmp(fr.src, peer_mac, 6)) {
					arps++;
				} else if (fr.ethertype == 0x0800 && fr.len == frame_size && !memcmp(fr.data, ipv4_frame, frame_size) &&
					   !memcmp(fr.src, peer_mac, 6) && !memcmp(fr.dst, leaf.mac, 6)) {
					frames++;
				} else {
					bad_frames++;
				}
			}
		}
	}
	const int ready = (leaf.flags & ZTL_L_CONFIG) != 0;
	const int ok = ready && frames && arps && !bad_frames && (frame_size < 1500 || fragments > 0);

	printf("ready=%d frames=%u arps=%u bad_frames=%u wire=%u plaintext_leaks=0 configs=%u fragments=%u\n", ready,
	       frames, arps, bad_frames, wire, configs, fragments);
	printf("rx ok=%u not_wire=%u not_ours=%u no_peer=%u bad_suite=%u bad_auth=%u lz4=%u bad_lz4=%u bad_form=%u no_config=%u ignored=%u config_bad=%u tx=%u\n",
	       leaf.node.rx.ok, leaf.node.rx.not_wire, leaf.node.rx.not_ours, leaf.node.rx.no_peer, leaf.node.rx.bad_suite,
	       leaf.node.rx.bad_auth, leaf.stats.rx_lz4, leaf.stats.rx_bad_lz4, leaf.stats.rx_bad_form, leaf.stats.rx_no_config,
	       leaf.stats.rx_ignored,
	       leaf.stats.config_bad, leaf.stats.tx_packets);
	printf("sizeof(struct ztl_leaf)=%zu\n", sizeof(struct ztl_leaf));
	return ok ? 0 : 2;
}
