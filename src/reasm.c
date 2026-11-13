/* SPDX-License-Identifier: Apache-2.0 */
#include "reasm_internal.h"

_Static_assert(ZTL_RX_SLOTS >= 1u && ZTL_RX_SLOTS <= 16u, "slot count out of range");
_Static_assert(ZTL_PKT_MAX <= UINT16_MAX, "lengths are stored in 16 bits");
/* RAM budget of this module: one packet buffer and 24 bytes per slot. */
_Static_assert(sizeof(struct ztl_reasm) <= ZTL_RX_SLOTS * (ZTL_PKT_MAX + 24u), "reassembly RAM budget");

/* Plain loops with constant bounds: the provers analyse this code itself,
 * not a model of the C library's memcpy and memmove. */
void ztl_copy_bytes(uint8_t *dst, const uint8_t *src, size_t n)
{
	/*@ loop invariant 0 <= i <= n;
	  @ loop invariant \forall integer j; 0 <= j < i ==> dst[j] == \at(src[j], Pre);
	  @ loop assigns i, dst[0 .. n - 1];
	  @ loop variant n - i;
	  @*/
	for (size_t i = 0; i < n; i++) {
		dst[i] = src[i];
	}
}

void ztl_move_down(uint8_t *buf, size_t to, size_t from, size_t n)
{
	/*@ loop invariant 0 <= i <= n;
	  @ loop invariant \forall integer j; 0 <= j < i ==> buf[to + j] == \at(buf[from + j], Pre);
	  @ loop invariant \forall integer j; to + i <= j < ZTL_PKT_MAX ==> buf[j] == \at(buf[j], Pre);
	  @ loop assigns i, buf[to .. to + n - 1];
	  @ loop variant n - i;
	  @*/
	for (size_t i = 0; i < n; i++) {
		buf[to + i] = buf[from + i];
	}
}

/*@ requires \valid(r);
  @ assigns r->slot[0 .. ZTL_RX_SLOTS - 1].have;
  @ ensures \forall integer i; 0 <= i < ZTL_RX_SLOTS ==> r->slot[i].have == 0;
  @ ensures ztl_reasm_valid(r);
  @*/
void ztl_reasm_init(struct ztl_reasm *r)
{
	/*@ loop invariant 0 <= i <= ZTL_RX_SLOTS;
	  @ loop invariant \forall integer k; 0 <= k < i ==> r->slot[k].have == 0;
	  @ loop assigns i, r->slot[0 .. ZTL_RX_SLOTS - 1].have;
	  @ loop variant ZTL_RX_SLOTS - i;
	  @*/
	for (unsigned int i = 0; i < ZTL_RX_SLOTS; i++) {
		r->slot[i].have = 0;
	}
}

/*@ requires \valid_read(s);
  @ assigns \nothing;
  @ ensures \result != 0 <==> ztl_slot_ok(s);
  @*/
static int slot_ok(const struct ztl_reasm_slot *s)
{
	if (s->have == 0u) {
		return 1;
	}
	if (s->have == ZTL_SLOT_HEAD) {
		return s->head_len >= ZTL_PKT_MIN && s->head_len <= ZTL_PKT_MAX;
	}
	if (s->have == ZTL_SLOT_FRAG) {
		return s->frag_len >= 1u && s->frag_len <= ZTL_FRAG_PAYLOAD_MAX;
	}
	return 0; /* a complete packet never stays in a slot */
}

/*@ requires \valid_read(r);
  @ assigns \nothing;
  @ ensures \result != 0 <==> ztl_reasm_valid(r);
  @*/
int ztl_reasm_ok(const struct ztl_reasm *r)
{
	/*@ loop invariant 0 <= i <= ZTL_RX_SLOTS;
	  @ loop invariant \forall integer k; 0 <= k < i ==> ztl_slot_ok(&r->slot[k]);
	  @ loop assigns i;
	  @ loop variant ZTL_RX_SLOTS - i;
	  @*/
	for (unsigned int i = 0; i < ZTL_RX_SLOTS; i++) {
		if (!slot_ok(&r->slot[i])) {
			return 0;
		}
	}
	return 1;
}

/* Time from then to now on the 32-bit millisecond clock: the difference
 * modulo 2^32, which is correct across the wrap of the clock. Written with
 * 64-bit arithmetic so that no operation wraps. */
/*@ assigns \nothing;
  @ ensures \result == ZTL_SPEC_AGE(now_ms, then_ms);
  @*/
static uint32_t age_ms(uint32_t now_ms, uint32_t then_ms)
{
	return (uint32_t)((UINT64_C(4294967296) + now_ms - then_ms) % UINT64_C(4294967296));
}

unsigned int ztl_slot_for(struct ztl_reasm *r, uint64_t id, uint32_t now_ms)
{
	unsigned int use = 0;
	uint32_t use_age = 0;
	int use_free = 0;

	/*@ loop invariant 0 <= i <= ZTL_RX_SLOTS;
	  @ loop invariant 0 <= use < ZTL_RX_SLOTS;
	  @ loop invariant use_free == 0 || use_free == 1;
	  @ // So far only slots that were too old are freed; the rest of the table is as before.
	  @ loop invariant only_old: \forall integer k; 0 <= k < ZTL_RX_SLOTS ==>
	  @   r->slot[k].have == \at(r->slot[k].have, Pre) ||
	  @   (k < i && r->slot[k].have == 0 && !ztl_slot_live{Pre}(r, k, now_ms));
	  @ loop invariant kept: \forall integer k; 0 <= k < i ==>
	  @   ztl_slot_live{Pre}(r, k, now_ms) ==> r->slot[k].have == \at(r->slot[k].have, Pre);
	  @ loop invariant freed: \forall integer k; 0 <= k < i ==>
	  @   !ztl_slot_live{Pre}(r, k, now_ms) ==> r->slot[k].have == 0;
	  @ // No slot so far waits for this packet.
	  @ loop invariant other: \forall integer k; 0 <= k < i ==>
	  @   !(ztl_slot_live{Pre}(r, k, now_ms) && r->slot[k].id == id);
	  @ // use: the first free slot so far, or else the oldest slot so far.
	  @ loop invariant found: use_free == 1 ==>
	  @   use < i && r->slot[use].have == 0 && !ztl_slot_live{Pre}(r, use, now_ms);
	  @ loop invariant all_live: use_free == 0 ==>
	  @   \forall integer k; 0 <= k < i ==> ztl_slot_live{Pre}(r, k, now_ms);
	  @ loop invariant oldest: use_free == 0 ==>
	  @   (\forall integer k; 0 <= k < i ==> ZTL_SPEC_AGE(now_ms, r->slot[k].t_ms) <= use_age) &&
	  @   (i == 0 ==> use == 0 && use_age == 0) &&
	  @   (i > 0 ==> use < i && use_age == ZTL_SPEC_AGE(now_ms, r->slot[use].t_ms));
	  @ loop assigns i, use, use_age, use_free, r->slot[0 .. ZTL_RX_SLOTS - 1].have;
	  @ loop variant ZTL_RX_SLOTS - i;
	  @*/
	for (unsigned int i = 0; i < ZTL_RX_SLOTS; i++) {
		struct ztl_reasm_slot *s = &r->slot[i];
		uint32_t age = 0;

		/* The time of a free slot has no meaning and is not read
		 * (ztl_reasm_init() does not write it). */
		if (s->have != 0u) {
			age = age_ms(now_ms, s->t_ms);
			if (age > ZTL_REASM_TIMEOUT_MS) {
				s->have = 0;
			}
		}
		if (s->have != 0u && s->id == id) {
			return i;
		}
		if (s->have == 0u) {
			if (!use_free) {
				use = i;
				use_free = 1;
			}
		} else if (!use_free && age >= use_age) {
			use = i;
			use_age = age;
		}
	}
	r->slot[use].have = 0;
	return use;
}

size_t ztl_slot_put_head(struct ztl_reasm_slot *s, const uint8_t *head, size_t len)
{
	size_t f = 0;

	if (s->have == ZTL_SLOT_FRAG) {
		f = s->frag_len;
	}

	if (len + f > ZTL_PKT_MAX) {
		s->have = 0;
		return 0;
	}
	if (f != 0u) {
		/* Payload moves from the end of buf to its place after the head. */
		ztl_move_down(s->buf, len, ZTL_PKT_MAX - f, f);
	}
	/*@ assert moved: \forall integer j; 0 <= j < f ==>
	  @   s->buf[len + j] == \at(s->buf[\at(ZTL_PKT_MAX - f + j, Here)], Pre); */
	ztl_copy_bytes(s->buf, head, len);
	/*@ assert kept: \forall integer j; 0 <= j < f ==>
	  @   s->buf[len + j] == \at(s->buf[\at(ZTL_PKT_MAX - f + j, Here)], Pre); */
	if (f != 0u) {
		s->have = 0; /* complete; the bytes stay valid until the slot is used again */
		return len + f;
	}
	s->head_len = (uint16_t)len;
	s->have = ZTL_SLOT_HEAD;
	return 0;
}

size_t ztl_slot_put_frag(struct ztl_reasm_slot *s, const uint8_t *payload, size_t n)
{
	if (s->have == ZTL_SLOT_HEAD) {
		const size_t h = s->head_len;

		s->have = 0; /* complete, or too long: free in both cases */
		if (h + n > ZTL_PKT_MAX) {
			return 0;
		}
		ztl_copy_bytes(&s->buf[h], payload, n);
		return h + n;
	}
	ztl_copy_bytes(&s->buf[ZTL_PKT_MAX - n], payload, n);
	s->frag_len = (uint16_t)n;
	s->have = ZTL_SLOT_FRAG;
	return 0;
}

size_t ztl_reasm_input(struct ztl_reasm *r, enum ztl_kind kind, const struct ztl_view *v,
		       uint8_t *dgram, size_t len, uint32_t now_ms, uint8_t **pkt)
{
	if (kind == ZTL_HEAD && !v->fragmented) {
		*pkt = dgram;
		return len;
	}
	if (kind != ZTL_HEAD && kind != ZTL_FRAGMENT) {
		return 0;
	}

	struct ztl_reasm_slot *s = &r->slot[ztl_slot_for(r, v->packet_id, now_ms)];

	if (s->have == 0u) {
		s->id = v->packet_id;
		s->t_ms = now_ms;
	}

	size_t total;

	if (kind == ZTL_HEAD) {
		if (s->have == ZTL_SLOT_HEAD) {
			return 0; /* second head: ignored */
		}
		total = ztl_slot_put_head(s, dgram, len);
	} else {
		if (s->have == ZTL_SLOT_FRAG) {
			return 0; /* second fragment: ignored */
		}
		total = ztl_slot_put_frag(s, v->payload, v->payload_len);
	}
	if (total != 0u) {
		*pkt = s->buf;
	}
	return total;
}
