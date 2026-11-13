/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The leaf as a whole: protocol messages on top of the receive gate.
 *
 * The leaf does no input or output and keeps no clock. The caller (an
 * adapter for one operating system) owns the UDP socket, knows where each
 * pinned peer is, and calls three functions from one thread:
 *   ztl_input()     for each received UDP payload,
 *   ztl_poll()      regularly (for example every 100 ms) until it returns 0,
 *   ztl_frame_to()  for each Ethernet frame that the host wants to send.
 * Each of them can fill one packet buffer of ZTL_PKT_MAX bytes; the caller
 * sends it with ztl_tx_first() and ztl_tx_second().
 */
#ifndef ZTL_LEAF_H
#define ZTL_LEAF_H

#include <stddef.h>
#include <stdint.h>
#include "ztl/annot.h"
#include "ztl/node.h"

/* What the leaf says about itself. Protocol version 11 is the last one
 * without AES; peers then use Salsa20/12 + Poly1305 with this node. The
 * software version is this software's own; peers and the controller only
 * record and show it (the protocol version decides what they send). */
#define ZTL_PROTO_VERSION 11u
#define ZTL_VERSION_MAJOR 0u
#define ZTL_VERSION_MINOR 0u
#define ZTL_VERSION_REVISION 1u

#define ZTL_UDP_MAX   1432u /* largest UDP payload sent (ZT_DEFAULT_PHYSMTU of the reference) */
#define ZTL_PUB_LEN   64u   /* public key of an identity */
#define ZTL_NWID_LEN  8u
#define ZTL_ETH_ALEN  6u
#define ZTL_COM_MAX   296u  /* certificate of membership: 8 qualifiers at most */
#define ZTL_PLAIN_MAX (ZTL_PKT_MAX - ZTL_PKT_MIN) /* body of a packet after decompression */
#define ZTL_MTU_MIN   1280u
#define ZTL_MTU_MAX   1500u

/* Times in milliseconds. */
#define ZTL_HELLO_MS        60000u  /* HELLO to each peer (ZT_PEER_PING_PERIOD) */
#define ZTL_RETRY_MS        5000u   /* HELLO or configuration request without an answer */
#define ZTL_PEER_TIMEOUT_MS 150000u /* a peer that sent nothing for this long is not reachable */
#define ZTL_CONFIG_MS       60000u  /* configuration refresh (ZT_NETWORK_AUTOCONF_DELAY) */
#define ZTL_COM_MS          120000u /* certificate push to each reachable peer; also after each new configuration.
				      * A peer needs a certificate not older than the network's window (5 min at least) */
#define ZTL_LIKE_MS         60000u  /* multicast subscription (ZT_MULTICAST_ANNOUNCE_PERIOD) */

/* Protocol state for one pinned peer. */
struct ztl_peer_state {
	uint64_t hello_id; /* packet ID of the last HELLO sent */
	uint32_t hello_ms; /* when it was sent */
	uint32_t rx_ms;    /* last authenticated packet from this peer */
	uint32_t com_ms;   /* last certificate push */
	uint32_t like_ms;  /* last multicast subscription */
	/* Each of these is 0 or 1 (separate bytes, not bits of one byte: the
	 * provers then need no bit arithmetic). */
	uint8_t hello_sent;
	uint8_t hello_wait; /* the last HELLO has no OK yet */
	uint8_t seen;       /* the peer authenticated a packet to this node not long ago */
	uint8_t com_sent;
	uint8_t like_sent;
};

struct ztl_stats {
	uint32_t rx_lz4;       /* compressed packets decoded */
	uint32_t rx_bad_lz4;   /* compressed packet that did not decode */
	uint32_t rx_bad_form;  /* authenticated packet with a wrong layout or wrong network */
	uint32_t rx_no_config; /* frame while the node had no configuration */
	uint32_t rx_ignored;   /* verb that this leaf does not handle */
	uint32_t rx_frames;    /* frames given to the caller */
	uint32_t tx_packets;   /* packets built */
	uint32_t configs;      /* configurations accepted */
	uint32_t config_bad;   /* configurations refused */
};

struct ztl_leaf {
	struct ztl_node node; /* own address, pinned peers, reassembly: the receive gate */
	struct ztl_peer_state ps[ZTL_PEERS];
	uint64_t next_id;     /* packet ID of the next packet sent */
	uint64_t cfg_req_id;  /* packet ID of the configuration request that waits for its answer */
	uint64_t cfg_ts;      /* newest configuration time stamp taken since the start (controller clock) */
	uint32_t cfg_req_ms;  /* when the last configuration request was sent */
	struct ztl_stats stats;
	uint16_t mtu;         /* of the network, from the configuration */
	uint16_t com_len;
	uint8_t have_config;  /* 0 or 1: a configuration is in use */
	uint8_t req_sent;     /* 0 or 1: a configuration request was sent */
	uint8_t req_wait;     /* 0 or 1: the last configuration request has no answer yet */
	uint8_t ctrl;         /* index of the controller in node.peer, or ZTL_PEERS */
	uint8_t prefix;       /* bits of the network part of ip; 0: no address assigned */
	uint8_t ip[4];        /* own IPv4 address on the network */
	uint8_t mac[ZTL_ETH_ALEN];   /* own Ethernet address on the network */
	uint8_t nwid[ZTL_NWID_LEN];  /* the one network, most significant byte first */
	uint8_t pub[ZTL_PUB_LEN];    /* own public key (sent in HELLO; not a secret) */
	uint8_t com[ZTL_COM_MAX];    /* own certificate of membership, as the controller sent it */
	uint8_t plain[ZTL_PLAIN_MAX];/* body of the packet in work, after decompression */
};
/* One Ethernet frame of the virtual network. data points into the datagram
 * given to ztl_input() or into the leaf and is valid until the next call. */
struct ztl_frame {
	uint8_t dst[ZTL_ETH_ALEN];
	uint8_t src[ZTL_ETH_ALEN];
	uint16_t ethertype;
	uint16_t len;
	const uint8_t *data;
};

/* Results of ztl_input(), combined with "|". */
#define ZTL_IN_REPLY  0x01u /* tx holds a packet for the peer */
#define ZTL_IN_FRAME  0x02u /* *frame holds a frame for the host */
#define ZTL_IN_CONFIG 0x04u /* the configuration changed: read mtu, ip, prefix, mac again */

/*
 * Start. self: own address. pub: own public key. nwid: the network.
 * first_packet_id: 64 bits that the platform must take from a true random
 * source at each start. Packet IDs then count up from it; a packet ID is
 * the nonce of the packet's encryption, so a start value that repeats
 * after a restart would repeat key streams. No peer is pinned yet.
 */
void ztl_init(struct ztl_leaf *ZTL_EXCL l, const uint8_t self[ZTL_ADDR_LEN], const uint8_t pub[ZTL_PUB_LEN],
	      const uint8_t nwid[ZTL_NWID_LEN], uint64_t first_packet_id);

/*
 * Pin one peer: its address and the 32-byte key shared with it (made by the
 * provisioning tool). The peer whose address is the first 5 bytes of the
 * network ID is the controller. Returns the peer's index, or -1 if the
 * table is full or the address is the node's own or already pinned.
 */
int ztl_pin(struct ztl_leaf *ZTL_EXCL l, const uint8_t addr[ZTL_ADDR_LEN], const uint8_t key[ZTL_KEY_LEN]);

/*
 * One received UDP payload (it may be changed). Returns ZTL_IN_... flags.
 * With ZTL_IN_REPLY, tx[0 .. *tx_len) is a packet for peer *peer. With
 * ZTL_IN_FRAME, *frame is a frame from peer *peer for the host. Nothing is
 * delivered or answered unless the packet passed the receive gate (pinned
 * peer, right MAC).
 */
unsigned int ztl_input(struct ztl_leaf *ZTL_EXCL l, uint8_t *ZTL_COUNT(len) dgram, size_t len, uint32_t now_ms,
		       uint8_t tx[ZTL_PKT_MAX], size_t *ZTL_EXCL tx_len, unsigned int *ZTL_EXCL peer,
		       struct ztl_frame *ZTL_EXCL frame);

/*
 * Periodic work. Returns the length of a packet in tx for peer *peer, or 0
 * when nothing is due. Call again until it returns 0 (at most 4 packets for
 * each pinned peer in a row).
 */
size_t ztl_poll(struct ztl_leaf *ZTL_EXCL l, uint32_t now_ms, uint8_t tx[ZTL_PKT_MAX], unsigned int *ZTL_EXCL peer);

/*
 * The packet that carries one Ethernet frame from the host to peer i, or 0
 * if this frame does not go to peer i (other destination, peer not
 * reachable, no configuration, length outside 1 .. mtu). The source of the
 * frame is always this node's own address (no bridging). Call it for every
 * i below ZTL_PEERS: a frame to a group address goes to every reachable
 * peer, a frame to one address to the peer that owns it.
 */
size_t ztl_frame_to(struct ztl_leaf *ZTL_EXCL l, unsigned int i, const uint8_t dst[ZTL_ETH_ALEN], uint16_t ethertype,
		    const uint8_t *ZTL_COUNT(len) data, size_t len, uint8_t tx[ZTL_PKT_MAX]);

/* Length of the first UDP payload of a packet of len bytes: the packet starts with it. */
size_t ztl_tx_first(size_t len);

/*
 * After the first UDP payload was sent: if the packet needs a second one,
 * make it inside pkt (this overwrites bytes already sent) and return its
 * length, with its start in *at. Returns 0 if the packet had one part.
 */
size_t ztl_tx_second(uint8_t pkt[ZTL_PKT_MAX], size_t len, size_t *ZTL_EXCL at);

/* The Ethernet address of the node with this ZeroTier address on this network. */
void ztl_mac_of(uint8_t mac[ZTL_ETH_ALEN], const uint8_t addr[ZTL_ADDR_LEN], const uint8_t nwid[ZTL_NWID_LEN]);

#endif
