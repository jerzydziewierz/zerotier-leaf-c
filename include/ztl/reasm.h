/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/* Reassembly of packets that arrive as a head and one fragment. */
#ifndef ZTL_REASM_H
#define ZTL_REASM_H

#include <stddef.h>
#include <stdint.h>
#include "ztl/annot.h"
#include "ztl/wire.h"

#ifndef ZTL_RX_SLOTS
#define ZTL_RX_SLOTS 2u /* packets that can wait for their other part */
#endif
#define ZTL_REASM_TIMEOUT_MS 5000u /* as ZT_RECEIVE_QUEUE_TIMEOUT in the reference */
#define ZTL_FRAG_PAYLOAD_MAX (ZTL_PKT_MAX - ZTL_FRAG_HDR)

#define ZTL_SLOT_HEAD 0x01u /* head bytes are in buf[0 .. head_len) */
#define ZTL_SLOT_FRAG 0x02u /* fragment payload is stored, see struct */

/*
 * One waiting packet. Layout of buf:
 *   head only:      head at buf[0 .. head_len)
 *   fragment only:  payload right-aligned, at buf[ZTL_PKT_MAX - frag_len .. ZTL_PKT_MAX)
 *   complete:       head, then payload, at buf[0 .. head_len + frag_len)
 * have == 0 means the slot is free; the other fields are then not used.
 */
struct ztl_reasm_slot {
	uint64_t id;       /* packet ID of the head */
	uint32_t t_ms;     /* time of the first part */
	uint16_t head_len; /* 0, or ZTL_PKT_MIN .. ZTL_PKT_MAX */
	uint16_t frag_len; /* 0, or 1 .. ZTL_FRAG_PAYLOAD_MAX */
	uint8_t have;      /* ZTL_SLOT_HEAD | ZTL_SLOT_FRAG */
	uint8_t buf[ZTL_PKT_MAX];
};

struct ztl_reasm {
	struct ztl_reasm_slot slot[ZTL_RX_SLOTS];
};

/* Time from t to now on the 32-bit millisecond clock (contracts only). */
#define ZTL_SPEC_AGE(now, t) ((4294967296 + (now) - (t)) % 4294967296)

/*@ // Slot i holds a part that is not older than the timeout.
  @ predicate ztl_slot_live{L}(struct ztl_reasm *r, integer i, integer now) =
  @   r->slot[i].have != 0 && ZTL_SPEC_AGE(now, r->slot[i].t_ms) <= ZTL_REASM_TIMEOUT_MS;
  @*/

/*@ predicate ztl_slot_ok(struct ztl_reasm_slot *s) =
  @   s->have == 0 ||
  @   (s->have == ZTL_SLOT_HEAD && ZTL_PKT_MIN <= s->head_len <= ZTL_PKT_MAX) ||
  @   (s->have == ZTL_SLOT_FRAG && 1 <= s->frag_len <= ZTL_FRAG_PAYLOAD_MAX);
  @ predicate ztl_reasm_valid(struct ztl_reasm *r) =
  @   \forall integer i; 0 <= i < ZTL_RX_SLOTS ==> ztl_slot_ok(&r->slot[i]);
  @*/

/* Make every slot free. */
/*@ requires \valid(r);
  @ assigns r->slot[0 .. ZTL_RX_SLOTS - 1].have;
  @ ensures \forall integer i; 0 <= i < ZTL_RX_SLOTS ==> r->slot[i].have == 0;
  @ ensures ztl_reasm_valid(r);
  @*/
void ztl_reasm_init(struct ztl_reasm *ZTL_EXCL r);

/* Data invariant of the reassembly state; true after init and after every input. */
int ztl_reasm_ok(const struct ztl_reasm *ZTL_SHAR r);

/*
 * Give one classified datagram (kind is not ZTL_DROP, v from ztl_classify()
 * on the same dgram and len) to the reassembly.
 *
 * Returns the length of a complete packet and sets *pkt to it, or returns 0.
 *  - Head without the "fragmented" flag: the packet is the datagram itself;
 *    the state is not changed.
 *  - Otherwise the part is stored. When head and fragment of the same packet
 *    ID are both present and head_len + fragment payload <= ZTL_PKT_MAX, the
 *    packet is head bytes followed by the fragment payload, in either order
 *    of arrival; *pkt then points into the state and is valid until the next
 *    call. A longer total is dropped and the slot is freed.
 *  - A second head or a second fragment for a waiting packet is ignored.
 *  - A slot older than ZTL_REASM_TIMEOUT_MS is freed first. Call at least
 *    once per 2^31 ms (wrap-around of now_ms).
 *  - With no free slot, the oldest waiting packet is replaced.
 * The packet is not authenticated: fragments carry no MAC of their own, so
 * a wrong part gives a packet that fails authentication later.
 */
/*@ requires \valid(r) && ztl_reasm_valid(r) && \valid_read(v) && \valid(pkt);
  @ requires \separated(r, pkt, v) && \separated(r, dgram + (0 .. len - 1));
  @ requires kind == ZTL_HEAD ==>
  @   ZTL_PKT_MIN <= len <= ZTL_PKT_MAX && \valid(dgram + (0 .. len - 1));
  @ requires kind == ZTL_FRAGMENT ==>
  @   1 <= v->payload_len <= ZTL_FRAG_PAYLOAD_MAX &&
  @   \valid_read(v->payload + (0 .. v->payload_len - 1)) &&
  @   \separated(r, v->payload + (0 .. v->payload_len - 1));
  @ assigns r->slot[0 .. ZTL_RX_SLOTS - 1], *pkt;
  @ ensures ztl_reasm_valid(r);
  @ ensures \result <= ZTL_PKT_MAX;
  @ ensures \result != 0 ==> \result >= ZTL_PKT_MIN && \valid(*pkt + (0 .. \result - 1));
  @ ensures \result != 0 ==>
  @   (*pkt == dgram && \result == len) ||
  @   (\exists integer i; 0 <= i < ZTL_RX_SLOTS && *pkt == &r->slot[i].buf[0] &&
  @      r->slot[i].have == 0 && \result > ZTL_PKT_MIN);
  @*/
size_t ztl_reasm_input(struct ztl_reasm *ZTL_EXCL r, enum ztl_kind kind,
		       const struct ztl_view *ZTL_SHAR v,
		       uint8_t *ZTL_COUNT(len) dgram, size_t len,
		       uint32_t now_ms, uint8_t **ZTL_EXCL pkt);

#endif
