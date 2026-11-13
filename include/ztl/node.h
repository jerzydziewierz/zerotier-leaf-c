/* SPDX-License-Identifier: Apache-2.0 */
/* Node state and the receive gate: nothing passes without authentication. */
#ifndef ZTL_NODE_H
#define ZTL_NODE_H

#include <stddef.h>
#include <stdint.h>
#include "ztl/annot.h"
#include "ztl/crypto.h"
#include "ztl/reasm.h"
#include "ztl/wire.h"

#ifndef ZTL_PEERS
#define ZTL_PEERS 7u /* pinned remote identities; never learned from the network */
#endif
#define ZTL_VERB_MASK 0x1fu
#define ZTL_VERB_FLAGS 0xe0u /* 0x80: payload compressed */
#define ZTL_VERB_HELLO 0x01u

struct ztl_peer {
	uint8_t addr[ZTL_ADDR_LEN];
	uint8_t pinned;            /* 0: slot not used */
	uint8_t key[ZTL_KEY_LEN];  /* long-term shared secret with this peer */
};

/* Receive counters. They stop at their maximum (no wrap). */
struct ztl_rx_stats {
	uint32_t ok;        /* packets passed to the caller */
	uint32_t not_wire;  /* not a head or fragment this leaf accepts */
	uint32_t not_ours;  /* not addressed to this node, or sent "from" this node */
	uint32_t no_peer;   /* source is not a pinned peer */
	uint32_t bad_suite; /* unencrypted packet that is not HELLO */
	uint32_t bad_auth;  /* authentication failed */
};

struct ztl_node {
	uint8_t self[ZTL_ADDR_LEN];
	struct ztl_peer peer[ZTL_PEERS];
	struct ztl_reasm reasm;
	struct ztl_rx_stats rx;
};

/* One authenticated packet. Pointers refer into the datagram or into the
 * node's reassembly memory and are valid until the next ztl_rx() call. */
struct ztl_rx_packet {
	uint8_t peer;      /* index into node->peer */
	uint8_t verb;      /* verb number, flags removed */
	uint8_t verb_flags;/* upper bits of the verb byte (0x80: compressed) */
	uint8_t encrypted; /* 0: HELLO sent in the clear with a MAC; 1: suite 1 */
	const uint8_t *body; /* after the verb byte */
	uint16_t body_len;
};

/*@ predicate ztl_addr_same{L}(uint8_t *a, uint8_t *b) =
  @   \forall integer i; 0 <= i < ZTL_ADDR_LEN ==> a[i] == b[i];
  @*/

/* Proof-only record of what the authentication primitive did (ghost state:
 * it exists for the provers, not in the program). */
//@ ghost int ztl_gh_auth_calls;
//@ ghost int ztl_gh_auth_yes;
//@ ghost const uint8_t *ztl_gh_auth_key;

/*
 * Authentication primitive (Salsa20/12 + Poly1305 as ZeroTier composes them,
 * src/auth.c). pkt is a complete packet of len bytes.
 * Returns 1 if the 8-byte MAC is right for this key; then, if decrypt is not
 * zero, the bytes from the verb byte onward are decrypted in place.
 * Returns 0 otherwise and then does not change pkt.
 * A packet may be opened without decryption only if its verb is HELLO.
 */
/*@ requires ZTL_PKT_MIN <= len <= ZTL_PKT_MAX;
  @ requires \valid_read(key + (0 .. ZTL_KEY_LEN - 1));
  @ requires \valid(pkt + (0 .. len - 1));
  @ requires \separated(key + (0 .. ZTL_KEY_LEN - 1), pkt + (0 .. len - 1));
  @ requires decrypt == 0 ==> (pkt[ZTL_PKT_IDX_VERB] & ZTL_VERB_MASK) == ZTL_VERB_HELLO;
  @ requires ztl_gh_auth_calls < 2147483647;
  @ assigns pkt[ZTL_PKT_IDX_VERB .. len - 1], ztl_gh_auth_calls, ztl_gh_auth_yes, ztl_gh_auth_key;
  @ ensures \result == 0 || \result == 1;
  @ ensures ztl_gh_auth_calls == \old(ztl_gh_auth_calls) + 1 && ztl_gh_auth_yes == \result;
  @ ensures ztl_gh_auth_key == key;
  @ ensures (\result == 0 || decrypt == 0) ==>
  @   \forall integer i; ZTL_PKT_IDX_VERB <= i < len ==> pkt[i] == \old(pkt[i]);
  @*/
int ztl_auth_open(const uint8_t key[ZTL_KEY_LEN], uint8_t *ZTL_COUNT(len) pkt, size_t len, int decrypt);

/* Flag bits that ztl_auth_seal() keeps: "fragmented" and the hop count. */
#define ZTL_FLAGS_SEAL_KEEP (ZTL_FLAG_FRAGMENTED | 0x07u)

/*
 * Make a packet ready to send: set the cipher suite in the flags (1 if
 * encrypt is not zero, else 0), encrypt the bytes from the verb byte onward
 * in place (suite 1 only) and write the 8-byte MAC. The caller has filled
 * the packet ID, both addresses, the "fragmented" flag and the payload.
 * A packet may be sealed without encryption only if its verb is HELLO.
 */
/*@ requires ZTL_PKT_MIN <= len <= ZTL_PKT_MAX;
  @ requires \valid_read(key + (0 .. ZTL_KEY_LEN - 1));
  @ requires \valid(pkt + (0 .. len - 1));
  @ requires \separated(key + (0 .. ZTL_KEY_LEN - 1), pkt + (0 .. len - 1));
  @ requires encrypt == 0 ==> (pkt[ZTL_PKT_IDX_VERB] & ZTL_VERB_MASK) == ZTL_VERB_HELLO;
  @ assigns pkt[ZTL_PKT_IDX_FLAGS .. len - 1];
  @ ensures pkt[ZTL_PKT_IDX_FLAGS] ==
  @   ((\old(pkt[ZTL_PKT_IDX_FLAGS]) & ZTL_FLAGS_SEAL_KEEP) | (encrypt != 0 ? ZTL_FLAG_CIPHER_LOW : 0));
  @ ensures encrypt == 0 ==>
  @   \forall integer i; ZTL_PKT_IDX_VERB <= i < len ==> pkt[i] == \old(pkt[i]);
  @*/
void ztl_auth_seal(const uint8_t key[ZTL_KEY_LEN], uint8_t *ZTL_COUNT(len) pkt, size_t len, int encrypt);

/*
 * Receive gate. Give one UDP payload (the buffer may be changed: decryption
 * is in place). Returns 1 and fills *out when the datagram completed a packet
 * that is addressed to this node, comes from a pinned peer and is
 * authenticated with that peer's key. Returns 0 in every other case; then
 * *out is not written, and the only node state that can change is the
 * matching counter in node->rx and the reassembly memory.
 */
/*@ requires \valid(n) && ztl_reasm_valid(&n->reasm) && \valid(out);
  @ requires \valid(dgram + (0 .. len - 1));
  @ requires \separated(n, out, dgram + (0 .. len - 1));
  @ assigns n->rx, n->reasm.slot[0 .. ZTL_RX_SLOTS - 1], dgram[0 .. len - 1], *out,
  @         ztl_gh_auth_calls, ztl_gh_auth_yes, ztl_gh_auth_key;
  @ ensures \result == 0 || \result == 1;
  @ ensures ztl_reasm_valid(&n->reasm);
  @ // The primitive is called at most once (the proof-only counter starts at 0 in each call).
  @ ensures 0 <= ztl_gh_auth_calls <= 1;
  @ // Delivery: only after one call that answered yes, for a pinned peer whose
  @ // address is the packet's source, in a packet addressed to this node; an
  @ // unencrypted delivery is HELLO.
  @ ensures \result == 1 ==>
  @   ztl_gh_auth_calls == 1 && ztl_gh_auth_yes == 1 &&
  @   out->peer < ZTL_PEERS && n->peer[out->peer].pinned != 0 &&
  @   ztl_gh_auth_key == &n->peer[out->peer].key[0] &&
  @   ztl_addr_same(&n->peer[out->peer].addr[0], out->body - (ZTL_PKT_MIN - ZTL_PKT_IDX_SRC)) &&
  @   ztl_addr_same(&n->self[0], out->body - (ZTL_PKT_MIN - ZTL_PKT_IDX_DEST)) &&
  @   (out->encrypted == 0 ==> out->verb == ZTL_VERB_HELLO) &&
  @   out->body_len <= ZTL_PKT_MAX - ZTL_PKT_MIN;
  @ // No delivery: the output record is not written.
  @ ensures \result == 0 ==>
  @   out->peer == \old(out->peer) && out->verb == \old(out->verb) &&
  @   out->verb_flags == \old(out->verb_flags) && out->encrypted == \old(out->encrypted) &&
  @   out->body == \old(out->body) && out->body_len == \old(out->body_len);
  @ // A yes from the primitive is never thrown away.
  @ ensures (ztl_gh_auth_calls == 1 && ztl_gh_auth_yes == 1) ==> \result == 1;
  @ // Counters: delivery counts only as ok; otherwise at most one refusal counter grows, by one.
  @ ensures \result == 1 ==>
  @   n->rx.not_wire == \old(n->rx.not_wire) && n->rx.not_ours == \old(n->rx.not_ours) &&
  @   n->rx.no_peer == \old(n->rx.no_peer) && n->rx.bad_suite == \old(n->rx.bad_suite) &&
  @   n->rx.bad_auth == \old(n->rx.bad_auth) &&
  @   \old(n->rx.ok) <= n->rx.ok <= \old(n->rx.ok) + 1;
  @ ensures \result == 0 ==>
  @   n->rx.ok == \old(n->rx.ok) &&
  @   n->rx.not_wire + n->rx.not_ours + n->rx.no_peer + n->rx.bad_suite + n->rx.bad_auth <=
  @     \old(n->rx.not_wire + n->rx.not_ours + n->rx.no_peer + n->rx.bad_suite + n->rx.bad_auth) + 1 &&
  @   n->rx.not_wire >= \old(n->rx.not_wire) && n->rx.not_ours >= \old(n->rx.not_ours) &&
  @   n->rx.no_peer >= \old(n->rx.no_peer) && n->rx.bad_suite >= \old(n->rx.bad_suite) &&
  @   n->rx.bad_auth >= \old(n->rx.bad_auth);
  @*/
int ztl_rx(struct ztl_node *ZTL_EXCL n, uint8_t *ZTL_COUNT(len) dgram, size_t len,
	   uint32_t now_ms, struct ztl_rx_packet *ZTL_EXCL out);

#endif
