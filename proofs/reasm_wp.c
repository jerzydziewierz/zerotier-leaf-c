/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * Proof-only code for Frama-C WP: the two orders of arrival of one packet,
 * written as two small functions. WP proves each from the CONTRACTS of
 * ztl_slot_put_head() and ztl_slot_put_frag() (src/reasm_internal.h), at the
 * full packet size: both orders give exactly the head bytes followed by the
 * fragment payload when the total fits, and nothing when it does not.
 */
#include "reasm_internal.h"

/*@ requires \valid(s) && s->have == 0;
  @ requires ZTL_PKT_MIN <= hl <= ZTL_PKT_MAX && 1 <= n <= ZTL_FRAG_PAYLOAD_MAX;
  @ requires \valid_read(head + (0 .. hl - 1)) && \valid_read(payload + (0 .. n - 1));
  @ requires \separated(s, head + (0 .. hl - 1)) && \separated(s, payload + (0 .. n - 1));
  @ assigns s->buf[0 .. ZTL_PKT_MAX - 1], s->head_len, s->frag_len, s->have;
  @ ensures s->have == 0;
  @ behavior fits:
  @   assumes hl + n <= ZTL_PKT_MAX;
  @   ensures \result == hl + n;
  @   ensures \forall integer j; 0 <= j < hl ==> s->buf[j] == \old(head[j]);
  @   ensures \forall integer j; 0 <= j < n ==> s->buf[hl + j] == \old(payload[j]);
  @ behavior too_long:
  @   assumes hl + n > ZTL_PKT_MAX;
  @   ensures \result == 0;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
size_t ztl_scn_head_first(struct ztl_reasm_slot *s, const uint8_t *head, size_t hl,
			  const uint8_t *payload, size_t n)
{
	(void)ztl_slot_put_head(s, head, hl);
	return ztl_slot_put_frag(s, payload, n);
}

/*@ requires \valid(s) && s->have == 0;
  @ requires ZTL_PKT_MIN <= hl <= ZTL_PKT_MAX && 1 <= n <= ZTL_FRAG_PAYLOAD_MAX;
  @ requires \valid_read(head + (0 .. hl - 1)) && \valid_read(payload + (0 .. n - 1));
  @ requires \separated(s, head + (0 .. hl - 1)) && \separated(s, payload + (0 .. n - 1));
  @ assigns s->buf[0 .. ZTL_PKT_MAX - 1], s->head_len, s->frag_len, s->have;
  @ ensures s->have == 0;
  @ behavior fits:
  @   assumes hl + n <= ZTL_PKT_MAX;
  @   ensures \result == hl + n;
  @   ensures \forall integer j; 0 <= j < hl ==> s->buf[j] == \old(head[j]);
  @   ensures \forall integer j; 0 <= j < n ==> s->buf[hl + j] == \old(payload[j]);
  @ behavior too_long:
  @   assumes hl + n > ZTL_PKT_MAX;
  @   ensures \result == 0;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
size_t ztl_scn_frag_first(struct ztl_reasm_slot *s, const uint8_t *head, size_t hl,
			  const uint8_t *payload, size_t n)
{
	(void)ztl_slot_put_frag(s, payload, n);
	return ztl_slot_put_head(s, head, hl);
}
