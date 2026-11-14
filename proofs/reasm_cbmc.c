/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * CBMC harnesses for ztl_reasm_input(). Select one with -DH_STEP, -DH_ORDER,
 * -DH_DUP or -DH_TIMEOUT (proofs/run.sh runs all).
 *
 * H_STEP    One input on ANY state that satisfies the data invariant
 *           ztl_reasm_ok(): no undefined behaviour, the invariant holds
 *           again, and a returned packet lies inside the datagram or inside
 *           one slot. With ztl_reasm_init() this is an induction: it covers
 *           input sequences of every length.
 * H_ORDER   Head then fragment, and fragment then head, within the timeout:
 *           both give the same packet = head bytes followed by the fragment
 *           payload, exactly when the total is <= ZTL_PKT_MAX; a longer
 *           total gives no packet and leaves every slot free.
 * H_DUP     A second head, or a second fragment, with the same packet ID but
 *           other contents does not change the result.
 * H_TIMEOUT Parts further apart than the timeout are not joined, for every
 *           value of the 32-bit clock including its wrap-around.
 */
#include <stdlib.h>
#include "ztl/reasm.h"

/* Reachability targets are active only in a cover run (-DH_COVER --cover cover). */
#ifdef H_COVER
#define COVER(c) __CPROVER_cover(c)
#else
#define COVER(c) ((void)0)
#endif

size_t nondet_size(void);
uint32_t nondet_u32(void);
struct ztl_reasm nondet_reasm(void);

/*
 * A datagram is a fixed array of the maximum size with a free length: CBMC
 * handles copies from fixed-size objects far better than from objects of
 * unknown size (the first version used malloc(len) and needed more than
 * 16 GB even for 128-byte packets). The price: a read between len and the
 * array end is not an error here. The expected-byte checks below still fix
 * which bytes must be used, and the classifier keeps its exact-size harness.
 */
struct dg {
	uint8_t b[ZTL_PKT_MAX];
	size_t len;
	struct ztl_view v;
	enum ztl_kind k;
};

/* Fill *d with any contents and any length, and classify it in place (the
 * view holds pointers into d->b, so d must not be copied afterwards). */
static void any_datagram(struct dg *d)
{
	d->len = nondet_size();
	__CPROVER_assume(d->len <= ZTL_PKT_MAX);
	d->k = ztl_classify(d->b, d->len, &d->v);
}

static size_t feed(struct ztl_reasm *r, struct dg *d, uint32_t now, uint8_t **p)
{
	return ztl_reasm_input(r, d->k, &d->v, d->b, d->len, now, p);
}

/* Time from t1 to t2 on the 32-bit clock; the wrap is intended. */
static uint32_t elapsed(uint32_t t1, uint32_t t2)
{
#pragma CPROVER check push
#pragma CPROVER check disable "unsigned-overflow"
	return t2 - t1;
#pragma CPROVER check pop
}

static int all_free(const struct ztl_reasm *r)
{
	for (unsigned int i = 0; i < ZTL_RX_SLOTS; i++) {
		if (r->slot[i].have != 0u) {
			return 0;
		}
	}
	return 1;
}

/* Byte i of the expected packet: head bytes, then the fragment payload. */
static uint8_t expect(const struct dg *h, const struct dg *f, size_t i)
{
	return i < h->len ? h->b[i] : f->b[ZTL_FRAG_HDR + (i - h->len)];
}

int main(void)
{
#if defined(H_STEP)
	struct ztl_reasm r = nondet_reasm();
	__CPROVER_assume(ztl_reasm_ok(&r));

	struct dg d;
	any_datagram(&d);
	__CPROVER_assume(d.k != ZTL_DROP);

	uint8_t *p = NULL;
	size_t n = feed(&r, &d, nondet_u32(), &p);

	__CPROVER_assert(ztl_reasm_ok(&r), "invariant holds after any input");
	if (n != 0u) {
		int in_dgram = p == d.b && n == d.len;
		int in_slot = 0;

		for (unsigned int i = 0; i < ZTL_RX_SLOTS; i++) {
			in_slot |= p == r.slot[i].buf && n <= ZTL_PKT_MAX && r.slot[i].have == 0u;
		}
		__CPROVER_assert(in_dgram || in_slot, "returned packet is the datagram or one freed slot");
		__CPROVER_assert(n > ZTL_PKT_IDX_VERB, "returned packet has a verb byte");
	}
	COVER(n != 0u && p != d.b);
	COVER(n != 0u && p == d.b);
	COVER(n == 0u && d.k == ZTL_HEAD);
	COVER(n == 0u && d.k == ZTL_FRAGMENT);
#else
	struct dg h, f;
	any_datagram(&h);
	any_datagram(&f);
	__CPROVER_assume(h.k == ZTL_HEAD && h.v.fragmented);
	__CPROVER_assume(f.k == ZTL_FRAGMENT && f.v.packet_id == h.v.packet_id);

	const size_t total = h.len + (f.len - ZTL_FRAG_HDR);
	uint32_t t1 = nondet_u32(), t2 = nondet_u32();
	uint8_t *p1 = NULL, *p2 = NULL;
	size_t i = nondet_size();

#if defined(H_ORDER)
	__CPROVER_assume(elapsed(t1, t2) <= ZTL_REASM_TIMEOUT_MS);
	struct ztl_reasm r1, r2;
	ztl_reasm_init(&r1);
	ztl_reasm_init(&r2);

	size_t a = feed(&r1, &h, t1, &p1);
	__CPROVER_assert(a == 0u, "a fragmented head alone gives no packet");
	size_t n1 = feed(&r1, &f, t2, &p1);

	size_t b = feed(&r2, &f, t1, &p2);
	__CPROVER_assert(b == 0u, "a fragment alone gives no packet");
	size_t n2 = feed(&r2, &h, t2, &p2);

	if (total <= ZTL_PKT_MAX) {
		__CPROVER_assert(n1 == total && n2 == total, "both orders give the full length");
		__CPROVER_assume(i < total);
		__CPROVER_assert(p1[i] == expect(&h, &f, i), "head then fragment: every byte right");
		__CPROVER_assert(p2[i] == expect(&h, &f, i), "fragment then head: every byte right");
	} else {
		__CPROVER_assert(n1 == 0u && n2 == 0u, "a total above the limit gives no packet");
	}
	__CPROVER_assert(all_free(&r1) && all_free(&r2), "no slot stays in use");
	COVER(total == ZTL_PKT_MAX);
	COVER(total == ZTL_PKT_MAX + 1u);
	COVER(total == ZTL_PKT_MIN + 1u);
#elif defined(H_DUP)
	__CPROVER_assume(elapsed(t1, t2) <= ZTL_REASM_TIMEOUT_MS);
	__CPROVER_assume(total <= ZTL_PKT_MAX);
	struct dg h2, f2;
	any_datagram(&h2);
	any_datagram(&f2);
	__CPROVER_assume(h2.k == ZTL_HEAD && h2.v.fragmented && h2.v.packet_id == h.v.packet_id);
	__CPROVER_assume(f2.k == ZTL_FRAGMENT && f2.v.packet_id == h.v.packet_id);
	struct ztl_reasm r1, r2;
	ztl_reasm_init(&r1);
	ztl_reasm_init(&r2);

	(void)feed(&r1, &h, t1, &p1);
	size_t d1 = feed(&r1, &h2, t1, &p1);
	size_t n1 = feed(&r1, &f, t2, &p1);

	(void)feed(&r2, &f, t1, &p2);
	size_t d2 = feed(&r2, &f2, t1, &p2);
	size_t n2 = feed(&r2, &h, t2, &p2);

	__CPROVER_assert(d1 == 0u && d2 == 0u, "a second head or fragment gives no packet");
	__CPROVER_assert(n1 == total && n2 == total, "the first parts still complete");
	__CPROVER_assume(i < total);
	__CPROVER_assert(p1[i] == expect(&h, &f, i), "second head did not replace the first");
	__CPROVER_assert(p2[i] == expect(&h, &f, i), "second fragment did not replace the first");
#elif defined(H_TIMEOUT)
	__CPROVER_assume(elapsed(t1, t2) > ZTL_REASM_TIMEOUT_MS);
	struct ztl_reasm r1, r2;
	ztl_reasm_init(&r1);
	ztl_reasm_init(&r2);

	(void)feed(&r1, &h, t1, &p1);
	size_t n1 = feed(&r1, &f, t2, &p1);
	(void)feed(&r2, &f, t1, &p2);
	size_t n2 = feed(&r2, &h, t2, &p2);

	__CPROVER_assert(n1 == 0u && n2 == 0u, "parts further apart than the timeout are not joined");
	COVER(t2 < t1); /* the clock wrapped between the parts */
#else
#error "select a harness"
#endif
#endif
	return 0;
}
