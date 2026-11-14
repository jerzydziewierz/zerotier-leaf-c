/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/* Zephyr adapter of the leaf: one virtual Ethernet interface, one UDP socket, one thread. */
#ifndef ZTL_ZEPHYR_H
#define ZTL_ZEPHYR_H

#include <stdint.h>
#include <zephyr/net/net_if.h>
#include <ztl/leaf.h>

/* One pinned peer: who it is, the key shared with it, and where it is. The
 * leaf sends to this UDP endpoint and takes datagrams from it only. */
struct ztl_zephyr_peer {
	uint8_t addr[ZTL_ADDR_LEN];
	uint8_t key[ZTL_KEY_LEN];  /* SECRET: from the provisioning tool */
	uint8_t ipv4[4];
	uint16_t port;
};

struct ztl_zephyr_config {
	uint8_t self[ZTL_ADDR_LEN];  /* own ZeroTier address */
	uint8_t pub[ZTL_PUB_LEN];    /* own public key */
	uint8_t nwid[ZTL_NWID_LEN];  /* the network; its controller must be one of the peers */
	const struct ztl_zephyr_peer *peers;
	uint8_t peer_count;          /* 1 .. ZTL_PEERS */
	uint16_t port;               /* local UDP port */
};

struct ztl_zephyr_status {
	int running;        /* the thread runs */
	int usable;         /* the interface is up with the address from the controller */
	int ifindex;        /* of the virtual interface */
	uint32_t wire_tx;   /* datagrams sent */
	uint32_t wire_rx;   /* datagrams from pinned endpoints */
	uint32_t rx_filtered; /* datagrams from other endpoints, or too long: dropped unread */
	uint32_t tx_dropped;  /* datagrams or frames that could not be sent */
	uint32_t rx_dropped;  /* frames that could not be given to the network stack */
	struct ztl_stats leaf;
	struct ztl_rx_stats gate;
	uint8_t peers_seen; /* peers that are reachable now */
	/* Time inside the leaf, in cycles of the system clock (cycles_per_sec), with whatever
	 * interrupted it: ztl_input() for each datagram from a pinned endpoint, and
	 * ztl_frame_to() for each packet built from a frame of the host. */
	uint32_t cycles_per_sec;
	uint32_t in_calls, in_avg, in_max;
	uint32_t out_calls, out_avg, out_max;
};

/*
 * Start the leaf on the underlay interface (the interface that reaches the
 * peers). The configuration is copied. Call once, from a thread, when the
 * underlay has its address. Returns 0, or a negative errno value: -EALREADY,
 * -EINVAL (configuration), -EIO (no random number), or a socket error.
 */
int ztl_zephyr_start(const struct ztl_zephyr_config *config, struct net_if *underlay);

void ztl_zephyr_get_status(struct ztl_zephyr_status *status);

#endif
