/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * Parts of the reassembly, each with its own contract. Every function is
 * proved against its contract alone; a caller is proved with the contracts
 * of what it calls, not with their code. Not a public interface.
 */
#ifndef ZTL_REASM_INTERNAL_H
#define ZTL_REASM_INTERNAL_H

#include "ztl/reasm.h"

/* Copy n bytes between two ranges that do not overlap. */
/*@ requires n <= ZTL_PKT_MAX;
  @ requires \valid(dst + (0 .. n - 1));
  @ requires \valid_read(src + (0 .. n - 1));
  @ requires \separated(dst + (0 .. n - 1), src + (0 .. n - 1));
  @ assigns dst[0 .. n - 1];
  @ ensures \forall integer j; 0 <= j < n ==> dst[j] == \old(src[j]);
  @*/
void ztl_copy_bytes(uint8_t *dst, const uint8_t *src, size_t n);

/* Move n bytes inside one packet buffer from offset from down to offset to. */
/*@ requires to <= from && from + n <= ZTL_PKT_MAX;
  @ requires \valid(buf + (0 .. ZTL_PKT_MAX - 1));
  @ assigns buf[to .. to + n - 1];
  @ ensures \forall integer j; 0 <= j < n ==> buf[to + j] == \old(buf[from + j]);
  @*/
void ztl_move_down(uint8_t *buf, size_t to, size_t from, size_t n);

/*
 * Index of the slot that waits for packet id, or of the slot to use for a
 * new packet (then that slot is free). Only "have" fields change, and only
 * to 0. Rules, all in the contract:
 *  - A part older than the timeout does not count as waiting ("live"); its
 *    slot is freed when the scan reaches it (the scan stops at a match).
 *  - match: a live slot with this id exists. The result is the first one. No
 *    live slot is freed.
 *  - no_match: the result slot is free. If any slot was free or too old, no
 *    live slot is freed. If every slot was live, the result is a slot of the
 *    greatest age, and it is the only slot that is freed.
 */
/*@ requires \valid(r) && ztl_reasm_valid(r);
  @ assigns r->slot[0 .. ZTL_RX_SLOTS - 1].have;
  @ ensures 0 <= \result < ZTL_RX_SLOTS;
  @ ensures \forall integer i; 0 <= i < ZTL_RX_SLOTS ==>
  @   r->slot[i].have == 0 || r->slot[i].have == \old(r->slot[i].have);
  @ ensures r->slot[\result].have != 0 ==> r->slot[\result].id == id;
  @ ensures ztl_reasm_valid(r);
  @ behavior match:
  @   assumes \exists integer i; 0 <= i < ZTL_RX_SLOTS && ztl_slot_live(r, i, now_ms) && r->slot[i].id == id;
  @   ensures ztl_slot_live{Pre}(r, \result, now_ms) && r->slot[\result].id == id;
  @   ensures \forall integer i; 0 <= i < \result ==>
  @     !(ztl_slot_live{Pre}(r, i, now_ms) && r->slot[i].id == id);
  @   ensures \forall integer i; 0 <= i < ZTL_RX_SLOTS ==>
  @     ztl_slot_live{Pre}(r, i, now_ms) ==> r->slot[i].have == \old(r->slot[i].have);
  @ behavior no_match:
  @   assumes !(\exists integer i; 0 <= i < ZTL_RX_SLOTS && ztl_slot_live(r, i, now_ms) && r->slot[i].id == id);
  @   ensures r->slot[\result].have == 0;
  @   ensures (\exists integer i; 0 <= i < ZTL_RX_SLOTS && !ztl_slot_live{Pre}(r, i, now_ms)) ==>
  @     \forall integer i; 0 <= i < ZTL_RX_SLOTS ==>
  @       ztl_slot_live{Pre}(r, i, now_ms) ==> r->slot[i].have == \old(r->slot[i].have);
  @   ensures (\forall integer i; 0 <= i < ZTL_RX_SLOTS ==> ztl_slot_live{Pre}(r, i, now_ms)) ==>
  @     (\forall integer i; 0 <= i < ZTL_RX_SLOTS && i != \result ==>
  @        r->slot[i].have == \old(r->slot[i].have)) &&
  @     (\forall integer i; 0 <= i < ZTL_RX_SLOTS ==>
  @        ZTL_SPEC_AGE(now_ms, r->slot[i].t_ms) <= ZTL_SPEC_AGE(now_ms, r->slot[\result].t_ms));
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
unsigned int ztl_slot_for(struct ztl_reasm *r, uint64_t id, uint32_t now_ms);

/*
 * Put a head of len bytes into a slot that holds no head. Returns the length
 * of the complete packet, or 0.
 */
/*@ requires \valid(s) && ztl_slot_ok(s) && (s->have == 0 || s->have == ZTL_SLOT_FRAG);
  @ requires ZTL_PKT_MIN <= len <= ZTL_PKT_MAX;
  @ requires \valid_read(head + (0 .. len - 1));
  @ requires \separated(s, head + (0 .. len - 1));
  @ assigns s->buf[0 .. ZTL_PKT_MAX - 1], s->head_len, s->have;
  @ ensures ztl_slot_ok(s);
  @ behavior first:
  @   assumes s->have == 0;
  @   ensures \result == 0 && s->have == ZTL_SLOT_HEAD && s->head_len == len;
  @   ensures \forall integer j; 0 <= j < len ==> s->buf[j] == \old(head[j]);
  @ behavior join:
  @   assumes s->have == ZTL_SLOT_FRAG && len + s->frag_len <= ZTL_PKT_MAX;
  @   ensures \result == len + s->frag_len && s->have == 0;
  @   ensures \forall integer j; 0 <= j < len ==> s->buf[j] == \old(head[j]);
  @   ensures \forall integer j; 0 <= j < s->frag_len ==>
  @     s->buf[len + j] == \old(s->buf[ZTL_PKT_MAX - s->frag_len + j]);
  @ behavior too_long:
  @   assumes s->have == ZTL_SLOT_FRAG && len + s->frag_len > ZTL_PKT_MAX;
  @   ensures \result == 0 && s->have == 0;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
size_t ztl_slot_put_head(struct ztl_reasm_slot *s, const uint8_t *head, size_t len);

/*
 * Put a fragment payload of n bytes into a slot that holds no fragment.
 * Returns the length of the complete packet, or 0.
 */
/*@ requires \valid(s) && ztl_slot_ok(s) && (s->have == 0 || s->have == ZTL_SLOT_HEAD);
  @ requires 1 <= n <= ZTL_FRAG_PAYLOAD_MAX;
  @ requires \valid_read(payload + (0 .. n - 1));
  @ requires \separated(s, payload + (0 .. n - 1));
  @ assigns s->buf[0 .. ZTL_PKT_MAX - 1], s->frag_len, s->have;
  @ ensures ztl_slot_ok(s);
  @ behavior first:
  @   assumes s->have == 0;
  @   ensures \result == 0 && s->have == ZTL_SLOT_FRAG && s->frag_len == n;
  @   ensures \forall integer j; 0 <= j < n ==> s->buf[ZTL_PKT_MAX - n + j] == \old(payload[j]);
  @ behavior join:
  @   assumes s->have == ZTL_SLOT_HEAD && s->head_len + n <= ZTL_PKT_MAX;
  @   ensures \result == s->head_len + n && s->have == 0;
  @   ensures \forall integer j; 0 <= j < s->head_len ==> s->buf[j] == \old(s->buf[j]);
  @   ensures \forall integer j; 0 <= j < n ==> s->buf[s->head_len + j] == \old(payload[j]);
  @ behavior too_long:
  @   assumes s->have == ZTL_SLOT_HEAD && s->head_len + n > ZTL_PKT_MAX;
  @   ensures \result == 0 && s->have == 0;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
size_t ztl_slot_put_frag(struct ztl_reasm_slot *s, const uint8_t *payload, size_t n);

#endif
