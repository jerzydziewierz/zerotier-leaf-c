/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * Proof-only code for Frama-C WP, theorem T4 of CHECKLIST.md: what the leaf
 * builds, the leaf's own parser reads back unchanged. This file covers the
 * parts that are not encrypted: the packet header, and the split of a long
 * packet into two datagrams.
 *
 * T4_SENT(pkt, len, enc) (ZTL_SPEC_SENT in include/ztl/leaf.h) states a packet
 * as the leaf sends it: the source address does not start with the reserved
 * byte 0xff, and the flags byte has
 * "fragmented" (0x40) exactly when the packet needs two datagrams, cipher
 * suite 1 (0x08) when encrypted, else suite 0, and hop count 0: one of four
 * values, written as constants so that the provers need no bit arithmetic. The functions below are proved
 * from the contracts of ztl_classify(), ztl_tx_first(), ztl_tx_second() and
 * the reassembly slot (src/reasm_internal.h), at the full packet size.
 * The last functions join this to the senders: what ztl_poll() and
 * ztl_frame_to() send (their contracts in include/ztl/leaf.h, proved in
 * src/leaf.c) is read back with the packet ID, destination and source that
 * the leaf put in.
 */
#include "ztl/leaf.h"
#include "ztl/wire.h"
#include "bytes_internal.h"
#include "reasm_internal.h"
#include "reasm_wp.c" /* the two orders of arrival, proved in their own unit too */

#define T4_SENT(pkt, len, enc) ZTL_SPEC_SENT(pkt, len, enc) /* include/ztl/leaf.h */

/* The first datagram of a sent packet is read back as a head with the same
 * packet ID, destination, source, cipher suite and "fragmented" flag. */
/*@ requires ZTL_PKT_MIN <= len <= ZTL_PKT_MAX && (enc == 0 || enc == 1);
  @ requires \valid_read(pkt + (0 .. len - 1)) && \valid(out) && \separated(out, pkt + (0 .. len - 1));
  @ requires T4_SENT(pkt, len, enc);
  @ assigns *out;
  @ ensures \result == ZTL_HEAD;
  @ ensures out->packet_id == ZTL_SPEC_BE64(pkt);
  @ ensures out->dest == pkt + ZTL_PKT_IDX_DEST && out->src == pkt + ZTL_PKT_IDX_SRC;
  @ ensures out->cipher == enc && out->fragmented == (len > ZTL_UDP_MAX ? 1 : 0);
  @ ensures out->payload == pkt + ZTL_PKT_IDX_VERB &&
  @   out->payload_len == (len > ZTL_UDP_MAX ? ZTL_UDP_MAX : len) - ZTL_PKT_IDX_VERB;
  @*/
enum ztl_kind ztl_t4_head(const uint8_t *pkt, size_t len, int enc, struct ztl_view *out)
{
	/*@ assert flags_one_of_four: pkt[ZTL_PKT_IDX_FLAGS] == 0x00 || pkt[ZTL_PKT_IDX_FLAGS] == 0x08 || pkt[ZTL_PKT_IDX_FLAGS] == 0x40 || pkt[ZTL_PKT_IDX_FLAGS] == 0x48; */
	/*@ assert flags_0x00: pkt[ZTL_PKT_IDX_FLAGS] == 0x00 ==> (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 && (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) == 0; */
	/*@ assert flags_0x08: pkt[ZTL_PKT_IDX_FLAGS] == 0x08 ==> (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 && (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) != 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) == 0; */
	/*@ assert flags_0x40: pkt[ZTL_PKT_IDX_FLAGS] == 0x40 ==> (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 && (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) != 0; */
	/*@ assert flags_0x48: pkt[ZTL_PKT_IDX_FLAGS] == 0x48 ==> (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 && (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) != 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) != 0; */
	/*@ assert flag_bits: (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 &&
	  @   ((pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) != 0 <==> enc == 1) &&
	  @   ((pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) != 0 <==> len > ZTL_UDP_MAX); */
	return ztl_classify(pkt, ztl_tx_first(len), out);
}

/* Send a packet in two datagrams as the adapter does (the first datagram
 * leaves before ztl_tx_second() writes the fragment header over its end) and
 * classify both: the first datagram is pkt[0 .. 1431], copied to first; the
 * second starts at pkt + 1416. */
/*@ requires ZTL_UDP_MAX < len <= ZTL_PKT_MAX && (enc == 0 || enc == 1);
  @ requires \valid(pkt + (0 .. ZTL_PKT_MAX - 1)) && \valid(first + (0 .. ZTL_UDP_MAX - 1));
  @ requires \valid(va) && \valid(vb);
  @ requires \separated(pkt + (0 .. ZTL_PKT_MAX - 1), first + (0 .. ZTL_UDP_MAX - 1), va, vb);
  @ requires T4_SENT(pkt, len, enc);
  @ assigns pkt[ZTL_UDP_MAX - ZTL_FRAG_HDR .. ZTL_UDP_MAX - 1], first[0 .. ZTL_UDP_MAX - 1], *va, *vb;
  @ ensures \forall integer k; 0 <= k < ZTL_UDP_MAX ==> first[k] == \old(pkt[k]);
  @ ensures \forall integer k; ZTL_UDP_MAX <= k < len ==> pkt[k] == \old(pkt[k]);
  @ ensures va->packet_id == ZTL_SPEC_BE64(first) && vb->packet_id == va->packet_id;
  @ ensures va->fragmented == 1 && va->dest == first + ZTL_PKT_IDX_DEST;
  @ ensures vb->frag_no == 1 && vb->frag_total == 2 && vb->dest == pkt + (ZTL_UDP_MAX - ZTL_FRAG_HDR + ZTL_PKT_IDX_DEST);
  @ ensures \forall integer k; 0 <= k < ZTL_ADDR_LEN ==> va->dest[k] == vb->dest[k];
  @ ensures vb->payload == pkt + ZTL_UDP_MAX && vb->payload_len == len - ZTL_UDP_MAX;
  @*/
void ztl_t4_send_two(uint8_t *pkt, size_t len, int enc, uint8_t *first, struct ztl_view *va,
		     struct ztl_view *vb)
{
	size_t at = 0;

	/*@ assert flags_one_of_four: pkt[ZTL_PKT_IDX_FLAGS] == 0x00 || pkt[ZTL_PKT_IDX_FLAGS] == 0x08 || pkt[ZTL_PKT_IDX_FLAGS] == 0x40 || pkt[ZTL_PKT_IDX_FLAGS] == 0x48; */
	/*@ assert flags_0x00: pkt[ZTL_PKT_IDX_FLAGS] == 0x00 ==> (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 && (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) == 0; */
	/*@ assert flags_0x08: pkt[ZTL_PKT_IDX_FLAGS] == 0x08 ==> (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 && (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) != 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) == 0; */
	/*@ assert flags_0x40: pkt[ZTL_PKT_IDX_FLAGS] == 0x40 ==> (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 && (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) != 0; */
	/*@ assert flags_0x48: pkt[ZTL_PKT_IDX_FLAGS] == 0x48 ==> (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 && (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) != 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) != 0; */
	/*@ assert flag_bits: (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 &&
	  @   (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7 &&
	  @   ((pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) != 0 <==> enc == 1) &&
	  @   ((pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) != 0 <==> len > ZTL_UDP_MAX); */
	ztl_copy_bytes(first, pkt, ZTL_UDP_MAX); /* the first datagram leaves */
	/*@ assert first_is_pkt: \forall integer k; 0 <= k < ZTL_UDP_MAX ==> first[k] == pkt[k]; */
	(void)ztl_classify(first, ztl_tx_first(len), va);
	const size_t m = ztl_tx_second(pkt, len, &at);
	/*@ assert at_value: at == ZTL_UDP_MAX - ZTL_FRAG_HDR && m == len - at; */
	/*@ assert id_dest_copied: pkt[at + 0] == first[0] && pkt[at + 1] == first[1] && pkt[at + 2] == first[2] &&
	  @   pkt[at + 3] == first[3] && pkt[at + 4] == first[4] && pkt[at + 5] == first[5] &&
	  @   pkt[at + 6] == first[6] && pkt[at + 7] == first[7] && pkt[at + 8] == first[8] &&
	  @   pkt[at + 9] == first[9] && pkt[at + 10] == first[10] && pkt[at + 11] == first[11] &&
	  @   pkt[at + 12] == first[12]; */
	/*@ assert same_id: ZTL_SPEC_BE64(pkt + at) == ZTL_SPEC_BE64(first); */
	(void)ztl_classify(pkt + at, m, vb);
}

/* T4 for a packet in two datagrams, received head first: both datagrams name
 * the same packet ID and destination, and the reassembly gives back exactly
 * the packet that was sent. */
/*@ requires ZTL_UDP_MAX < len <= ZTL_PKT_MAX && (enc == 0 || enc == 1);
  @ requires \valid(pkt + (0 .. ZTL_PKT_MAX - 1)) && \valid(first + (0 .. ZTL_UDP_MAX - 1));
  @ requires \valid(s) && s->have == 0 && \valid(va) && \valid(vb);
  @ requires \separated(pkt + (0 .. ZTL_PKT_MAX - 1), first + (0 .. ZTL_UDP_MAX - 1), s, va, vb);
  @ requires T4_SENT(pkt, len, enc);
  @ assigns pkt[ZTL_UDP_MAX - ZTL_FRAG_HDR .. ZTL_UDP_MAX - 1], first[0 .. ZTL_UDP_MAX - 1], *va, *vb,
  @   s->buf[0 .. ZTL_PKT_MAX - 1], s->head_len, s->frag_len, s->have;
  @ ensures \result == len;
  @ ensures va->packet_id == vb->packet_id;
  @ ensures \forall integer k; 0 <= k < ZTL_ADDR_LEN ==> va->dest[k] == vb->dest[k];
  @ // The reassembled packet is the sent packet: bytes 0 .. 1431, then bytes 1432 .. len - 1.
  @ ensures \forall integer j; 0 <= j < ZTL_UDP_MAX ==> s->buf[j] == \old(pkt[j]);
  @ ensures \forall integer j; 0 <= j < len - ZTL_UDP_MAX ==> s->buf[ZTL_UDP_MAX + j] == \old(pkt[ZTL_UDP_MAX + j]);
  @*/
size_t ztl_t4_split_head_first(uint8_t *pkt, size_t len, int enc, uint8_t *first, struct ztl_view *va,
			       struct ztl_view *vb, struct ztl_reasm_slot *s)
{
	ztl_t4_send_two(pkt, len, enc, first, va, vb);
	/*@ assert sent_head: \forall integer k; 0 <= k < ZTL_UDP_MAX ==> first[k] == \at(pkt[k], Pre); */
	/*@ assert sent_tail: \forall integer k; 0 <= k < len - ZTL_UDP_MAX ==>
	  @   pkt[ZTL_UDP_MAX + k] == \at(pkt[ZTL_UDP_MAX + k], Pre); */
	const size_t r = ztl_scn_head_first(s, first, ZTL_UDP_MAX, pkt + ZTL_UDP_MAX, len - ZTL_UDP_MAX);
	/*@ assert got_head: \forall integer j; 0 <= j < ZTL_UDP_MAX ==> s->buf[j] == \at(pkt[j], Pre); */
	/*@ assert got_tail: \forall integer j; 0 <= j < len - ZTL_UDP_MAX ==>
	  @   s->buf[ZTL_UDP_MAX + j] == \at(pkt[ZTL_UDP_MAX + j], Pre); */
	return r;
}

/* The same, received fragment first. */
/*@ requires ZTL_UDP_MAX < len <= ZTL_PKT_MAX && (enc == 0 || enc == 1);
  @ requires \valid(pkt + (0 .. ZTL_PKT_MAX - 1)) && \valid(first + (0 .. ZTL_UDP_MAX - 1));
  @ requires \valid(s) && s->have == 0 && \valid(va) && \valid(vb);
  @ requires \separated(pkt + (0 .. ZTL_PKT_MAX - 1), first + (0 .. ZTL_UDP_MAX - 1), s, va, vb);
  @ requires T4_SENT(pkt, len, enc);
  @ assigns pkt[ZTL_UDP_MAX - ZTL_FRAG_HDR .. ZTL_UDP_MAX - 1], first[0 .. ZTL_UDP_MAX - 1], *va, *vb,
  @   s->buf[0 .. ZTL_PKT_MAX - 1], s->head_len, s->frag_len, s->have;
  @ ensures \result == len;
  @ // The reassembled packet is the sent packet: bytes 0 .. 1431, then bytes 1432 .. len - 1.
  @ ensures \forall integer j; 0 <= j < ZTL_UDP_MAX ==> s->buf[j] == \old(pkt[j]);
  @ ensures \forall integer j; 0 <= j < len - ZTL_UDP_MAX ==> s->buf[ZTL_UDP_MAX + j] == \old(pkt[ZTL_UDP_MAX + j]);
  @*/
size_t ztl_t4_split_frag_first(uint8_t *pkt, size_t len, int enc, uint8_t *first, struct ztl_view *va,
			       struct ztl_view *vb, struct ztl_reasm_slot *s)
{
	ztl_t4_send_two(pkt, len, enc, first, va, vb);
	/*@ assert sent_head: \forall integer k; 0 <= k < ZTL_UDP_MAX ==> first[k] == \at(pkt[k], Pre); */
	/*@ assert sent_tail: \forall integer k; 0 <= k < len - ZTL_UDP_MAX ==>
	  @   pkt[ZTL_UDP_MAX + k] == \at(pkt[ZTL_UDP_MAX + k], Pre); */
	const size_t r = ztl_scn_frag_first(s, first, ZTL_UDP_MAX, pkt + ZTL_UDP_MAX, len - ZTL_UDP_MAX);
	/*@ assert got_head: \forall integer j; 0 <= j < ZTL_UDP_MAX ==> s->buf[j] == \at(pkt[j], Pre); */
	/*@ assert got_tail: \forall integer j; 0 <= j < len - ZTL_UDP_MAX ==>
	  @   s->buf[ZTL_UDP_MAX + j] == \at(pkt[ZTL_UDP_MAX + j], Pre); */
	return r;
}

/* The cipher suite of a sent packet, read from its flags byte without bit arithmetic. */
#define T4_ENC(f) (((f) == 0x08u || (f) == 0x48u) ? 1 : 0)

/* T4 for every packet that ztl_poll() sends (all fit in one datagram). */
/*@ requires \valid(l) && ztl_leaf_ok(l) && l->node.self[0] != ZTL_FRAG_INDICATOR;
  @ requires \valid(tx + (0 .. ZTL_PKT_MAX - 1)) && \valid(peer) && \valid(out);
  @ requires \separated(l, tx + (0 .. ZTL_PKT_MAX - 1), peer, out);
  @ assigns tx[0 .. ZTL_PKT_MAX - 1], *peer, *out, l->next_id, l->stats.tx_packets, l->ps[0 .. ZTL_PEERS - 1],
  @         l->cfg_req_id, l->cfg_req_ms, l->req_sent, l->req_wait;
  @ ensures \result != 0 ==> *peer < ZTL_PEERS && out->packet_id == \old(l->next_id) && out->fragmented == 0 &&
  @   \forall integer k; 0 <= k < ZTL_ADDR_LEN ==>
  @     out->dest[k] == l->node.peer[*peer].addr[k] && out->src[k] == l->node.self[k];
  @*/
size_t ztl_t4_poll(struct ztl_leaf *l, uint32_t now_ms, uint8_t *tx, unsigned int *peer, struct ztl_view *out)
{
	const size_t n = ztl_poll(l, now_ms, tx, peer);

	if (n != 0u) {
		(void)ztl_t4_head(tx, n, T4_ENC(tx[ZTL_PKT_IDX_FLAGS]), out);
	}
	return n;
}

/* T4 for every packet that ztl_frame_to() sends: its first datagram is read
 * back with the header that the leaf put in. */
/*@ requires \valid(l) && ztl_leaf_ok(l) && l->node.self[0] != ZTL_FRAG_INDICATOR;
  @ requires \valid_read(dst + (0 .. ZTL_ETH_ALEN - 1)) && \valid_read(data + (0 .. len - 1));
  @ requires \valid(tx + (0 .. ZTL_PKT_MAX - 1)) && \valid(out);
  @ requires \separated(l, tx + (0 .. ZTL_PKT_MAX - 1), out) && \separated(data + (0 .. len - 1), tx + (0 .. ZTL_PKT_MAX - 1), out) &&
  @   \separated(dst + (0 .. ZTL_ETH_ALEN - 1), tx + (0 .. ZTL_PKT_MAX - 1), out);
  @ assigns tx[0 .. ZTL_PKT_MAX - 1], *out, l->next_id, l->stats.tx_packets;
  @ ensures \result != 0 ==> out->packet_id == \old(l->next_id) && out->cipher == 1 &&
  @   out->fragmented == (\result > ZTL_UDP_MAX ? 1 : 0) &&
  @   \forall integer k; 0 <= k < ZTL_ADDR_LEN ==>
  @     out->dest[k] == l->node.peer[i].addr[k] && out->src[k] == l->node.self[k];
  @*/
size_t ztl_t4_frame(struct ztl_leaf *l, unsigned int i, const uint8_t *dst, uint16_t ethertype, const uint8_t *data,
		    size_t len, uint8_t *tx, struct ztl_view *out)
{
	const size_t n = ztl_frame_to(l, i, dst, ethertype, data, len, tx);

	if (n != 0u) {
		(void)ztl_t4_head(tx, n, T4_ENC(tx[ZTL_PKT_IDX_FLAGS]), out);
	}
	return n;
}
