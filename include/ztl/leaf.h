/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * The leaf as a whole: protocol messages on top of the receive gate.
 *
 * The leaf does no input or output and keeps no clock. The caller (an
 * adapter for one operating system) owns the UDP socket, knows where each
 * pinned peer is, and calls three functions, one call at a time:
 *   ztl_input()     for each received UDP payload,
 *   ztl_poll()      regularly (for example every 100 ms) until it returns 0,
 *   ztl_frame_to()  for each Ethernet frame that the host wants to send.
 * The leaf has no lock of its own, and every proof here is about one call
 * that nothing interrupts: an adapter with more than one thread must guard
 * the leaf and the packet buffer (the Zephyr adapter uses one mutex).
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
/*@ // Data invariant of the leaf: true after ztl_init() and after every call.
  @ predicate ztl_leaf_ok(struct ztl_leaf *l) =
  @   ztl_reasm_valid(&l->node.reasm) && l->com_len <= ZTL_COM_MAX && l->ctrl <= ZTL_PEERS &&
  @   (l->have_config != 0 ==> ZTL_MTU_MIN <= l->mtu <= ZTL_MTU_MAX && 1 <= l->com_len);
  @*/
#define ZTL_SPEC_NEXT_ID(old) (((old) == 18446744073709551615) ? 0 : (old) + 1)

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
/*@ requires \valid(l) && \valid_read(self + (0 .. ZTL_ADDR_LEN - 1)) && \valid_read(pub + (0 .. ZTL_PUB_LEN - 1)) &&
  @   \valid_read(nwid + (0 .. ZTL_NWID_LEN - 1));
  @ requires \separated(l, self + (0 .. ZTL_ADDR_LEN - 1)) && \separated(l, pub + (0 .. ZTL_PUB_LEN - 1)) &&
  @   \separated(l, nwid + (0 .. ZTL_NWID_LEN - 1));
  @ assigns *l;
  @ ensures ztl_leaf_ok(l) && l->next_id == first_packet_id && l->have_config == 0;
  @ ensures \forall integer k; 0 <= k < ZTL_PEERS ==> l->node.peer[k].pinned == 0;
  @*/
void ztl_init(struct ztl_leaf *ZTL_EXCL l, const uint8_t self[ZTL_ADDR_LEN], const uint8_t pub[ZTL_PUB_LEN],
	      const uint8_t nwid[ZTL_NWID_LEN], uint64_t first_packet_id);

/*
 * Pin one peer: its address and the 32-byte key shared with it (made by the
 * provisioning tool). The peer whose address is the first 5 bytes of the
 * network ID is the controller. Returns the peer's index, or -1 if the
 * table is full or the address is the node's own or already pinned.
 */
/*@ requires \valid(l) && ztl_leaf_ok(l) && \valid_read(addr + (0 .. ZTL_ADDR_LEN - 1)) &&
  @   \valid_read(key + (0 .. ZTL_KEY_LEN - 1));
  @ requires \separated(l, addr + (0 .. ZTL_ADDR_LEN - 1)) && \separated(l, key + (0 .. ZTL_KEY_LEN - 1));
  @ assigns l->node.peer[0 .. ZTL_PEERS - 1], l->ps[0 .. ZTL_PEERS - 1], l->ctrl;
  @ ensures -1 <= \result < ZTL_PEERS && ztl_leaf_ok(l);
  @*/
int ztl_pin(struct ztl_leaf *ZTL_EXCL l, const uint8_t addr[ZTL_ADDR_LEN], const uint8_t key[ZTL_KEY_LEN]);

/*
 * One received UDP payload (it may be changed). Returns ZTL_IN_... flags.
 * With ZTL_IN_REPLY, tx[0 .. *tx_len) is a packet for peer *peer. With
 * ZTL_IN_FRAME, *frame is a frame from peer *peer for the host. Nothing is
 * delivered or answered unless the packet passed the receive gate (pinned
 * peer, right MAC).
 */
/*@ requires \valid(l) && ztl_leaf_ok(l) && \valid(dgram + (0 .. len - 1)) && \valid(tx + (0 .. ZTL_PKT_MAX - 1)) &&
  @   \valid(tx_len) && \valid(peer) && \valid(frame);
  @ requires \separated(l, dgram + (0 .. len - 1), tx + (0 .. ZTL_PKT_MAX - 1), tx_len, peer, frame);
  @ // Never written: own address, pinned peers and their keys, public key, network, controller index.
  @ assigns l->node.rx, l->node.reasm.slot[0 .. ZTL_RX_SLOTS - 1], l->ps[0 .. ZTL_PEERS - 1], l->stats,
  @         l->plain[0 .. ZTL_PLAIN_MAX - 1], l->com[0 .. ZTL_COM_MAX - 1], l->com_len, l->have_config, l->req_wait,
  @         l->mtu, l->prefix, l->ip[0 .. 3], l->cfg_ts, l->next_id,
  @         dgram[0 .. len - 1], tx[0 .. ZTL_PKT_MAX - 1], *tx_len, *peer, *frame,
  @         ztl_gh_auth_calls, ztl_gh_auth_yes, ztl_gh_auth_key, ztl_gh_auth_pkt, ztl_gh_auth_len;
  @ ensures ztl_leaf_ok(l);
  @ ensures *tx_len == 0 || ZTL_PKT_MIN <= *tx_len <= ZTL_PKT_MAX;
  @ // frame->len is 0 (no frame) or the length of a frame that can be read.
  @ ensures frame->len <= ZTL_MTU_MAX;
  @ ensures frame->len != 0 ==> \valid_read(frame->data + (0 .. frame->len - 1));
  @ // Authentication before effects, for the whole leaf: a reply or a frame
  @ // comes only from a datagram that completed a packet which the receive
  @ // gate authenticated (one call of the primitive, answer yes).
  @ ensures (*tx_len != 0 || frame->len != 0) ==> ztl_gh_auth_calls == 1 && ztl_gh_auth_yes == 1;
  @ // A packet ID is used only for a reply, and then exactly one.
  @ ensures *tx_len == 0 ==> l->next_id == \old(l->next_id);
  @ ensures *tx_len != 0 ==> l->next_id == ZTL_SPEC_NEXT_ID(\old(l->next_id));
  @*/
unsigned int ztl_input(struct ztl_leaf *ZTL_EXCL l, uint8_t *ZTL_COUNT(len) dgram, size_t len, uint32_t now_ms,
		       uint8_t tx[ZTL_PKT_MAX], size_t *ZTL_EXCL tx_len, unsigned int *ZTL_EXCL peer,
		       struct ztl_frame *ZTL_EXCL frame);

/*
 * Periodic work. Returns the length of a packet in tx for peer *peer, or 0
 * when nothing is due. Call again until it returns 0 (at most 4 packets for
 * each pinned peer in a row).
 */
/*@ requires \valid(l) && ztl_leaf_ok(l) && \valid(tx + (0 .. ZTL_PKT_MAX - 1)) && \valid(peer);
  @ requires \separated(l, tx + (0 .. ZTL_PKT_MAX - 1), peer);
  @ assigns tx[0 .. ZTL_PKT_MAX - 1], *peer, l->next_id, l->stats.tx_packets, l->ps[0 .. ZTL_PEERS - 1],
  @         l->cfg_req_id, l->cfg_req_ms, l->req_sent, l->req_wait;
  @ ensures \result == 0 || ZTL_PKT_MIN <= \result <= ZTL_UDP_MAX;
  @ ensures \result != 0 ==> *peer < ZTL_PEERS && l->node.peer[*peer].pinned != 0;
  @ ensures ztl_leaf_ok(l);
  @ // One packet ID for each packet, and none without a packet.
  @ ensures \result == 0 ==> l->next_id == \old(l->next_id);
  @ ensures \result != 0 ==> l->next_id == ZTL_SPEC_NEXT_ID(\old(l->next_id));
  @*/
size_t ztl_poll(struct ztl_leaf *ZTL_EXCL l, uint32_t now_ms, uint8_t tx[ZTL_PKT_MAX], unsigned int *ZTL_EXCL peer);

/*
 * The packet that carries one Ethernet frame from the host to peer i, or 0
 * if this frame does not go to peer i (other destination, peer not
 * reachable, no configuration, length outside 1 .. mtu). The source of the
 * frame is always this node's own address (no bridging). Call it for every
 * i below ZTL_PEERS: a frame to a group address goes to every reachable
 * peer, a frame to one address to the peer that owns it.
 */
/*@ requires \valid(l) && ztl_leaf_ok(l) && \valid_read(dst + (0 .. ZTL_ETH_ALEN - 1)) &&
  @   \valid_read(data + (0 .. len - 1)) && \valid(tx + (0 .. ZTL_PKT_MAX - 1));
  @ requires \separated(l, tx + (0 .. ZTL_PKT_MAX - 1)) && \separated(data + (0 .. len - 1), tx + (0 .. ZTL_PKT_MAX - 1)) &&
  @   \separated(dst + (0 .. ZTL_ETH_ALEN - 1), tx + (0 .. ZTL_PKT_MAX - 1));
  @ assigns tx[0 .. ZTL_PKT_MAX - 1], l->next_id, l->stats.tx_packets;
  @ ensures \result == 0 || ZTL_PKT_MIN < \result <= ZTL_PKT_MAX;
  @ // A frame goes out only with a configuration, to a pinned peer that was heard, with 1 .. MTU bytes.
  @ ensures \result != 0 ==> l->have_config != 0 && i < ZTL_PEERS && l->node.peer[i].pinned != 0 &&
  @   l->ps[i].seen != 0 && 1 <= len <= l->mtu;
  @ ensures ztl_leaf_ok(l);
  @ ensures \result == 0 ==> l->next_id == \old(l->next_id);
  @ ensures \result != 0 ==> l->next_id == ZTL_SPEC_NEXT_ID(\old(l->next_id));
  @*/
size_t ztl_frame_to(struct ztl_leaf *ZTL_EXCL l, unsigned int i, const uint8_t dst[ZTL_ETH_ALEN], uint16_t ethertype,
		    const uint8_t *ZTL_COUNT(len) data, size_t len, uint8_t tx[ZTL_PKT_MAX]);

/* Length of the first UDP payload of a packet of len bytes: the packet starts with it. */
/*@ assigns \nothing;
  @ ensures \result == (len > ZTL_UDP_MAX ? ZTL_UDP_MAX : len);
  @*/
size_t ztl_tx_first(size_t len);

/*
 * After the first UDP payload was sent: if the packet needs a second one,
 * make it inside pkt (this overwrites bytes already sent) and return its
 * length, with its start in *at. Returns 0 if the packet had one part.
 */
/*@ requires \valid(pkt + (0 .. ZTL_PKT_MAX - 1)) && \valid(at) && \separated(at, pkt + (0 .. ZTL_PKT_MAX - 1));
  @ assigns pkt[ZTL_UDP_MAX - ZTL_FRAG_HDR .. ZTL_UDP_MAX - 1], *at;
  @ behavior one_part:
  @   assumes len <= ZTL_UDP_MAX || len > ZTL_PKT_MAX;
  @   assigns \nothing;
  @   ensures \result == 0;
  @ behavior two_parts:
  @   assumes ZTL_UDP_MAX < len <= ZTL_PKT_MAX;
  @   // The second datagram: a 16-byte header, then exactly the bytes that the first one did not carry.
  @   ensures *at == ZTL_UDP_MAX - ZTL_FRAG_HDR && \result == len - ZTL_UDP_MAX + ZTL_FRAG_HDR &&
  @     ZTL_FRAG_HDR < \result <= ZTL_UDP_MAX;
  @   ensures pkt[*at + ZTL_FRAG_IDX_INDICATOR] == ZTL_FRAG_INDICATOR && pkt[*at + ZTL_FRAG_IDX_NO] == ZTL_FRAG_NO_1_OF_2;
  @   ensures \forall integer k; 0 <= k < 13 ==> pkt[*at + k] == \old(pkt[k]);
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
size_t ztl_tx_second(uint8_t pkt[ZTL_PKT_MAX], size_t len, size_t *ZTL_EXCL at);

/* The Ethernet address of the node with this ZeroTier address on this network. */
/*@ requires \valid(mac + (0 .. ZTL_ETH_ALEN - 1)) && \valid_read(addr + (0 .. ZTL_ADDR_LEN - 1)) &&
  @   \valid_read(nwid + (0 .. ZTL_NWID_LEN - 1));
  @ requires \separated(mac + (0 .. ZTL_ETH_ALEN - 1), addr + (0 .. ZTL_ADDR_LEN - 1)) &&
  @   \separated(mac + (0 .. ZTL_ETH_ALEN - 1), nwid + (0 .. ZTL_NWID_LEN - 1));
  @ assigns mac[0 .. ZTL_ETH_ALEN - 1];
  @*/
void ztl_mac_of(uint8_t mac[ZTL_ETH_ALEN], const uint8_t addr[ZTL_ADDR_LEN], const uint8_t nwid[ZTL_NWID_LEN]);

#endif
