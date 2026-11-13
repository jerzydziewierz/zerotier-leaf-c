/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Poly1305 (D. J. Bernstein). With r and s the two halves of the one-time
 * key and c_1 .. c_q the message blocks (each with a 1 appended):
 *   tag = ((c_1 r^q + c_2 r^(q-1) + ... + c_q r) mod 2^130 - 5) + s  mod 2^128
 *
 * A number of 130 bits is held as five limbs of 26 bits, least significant
 * first (the layout of poly1305-donna, 32-bit version). Between steps limb 1
 * may be a little larger than 26 bits.
 *
 * The code uses "/" and "%" by powers of two where one would expect shifts
 * and masks. The compiler emits the same instructions; the provers get
 * plain arithmetic and can show that no sum or product leaves its type.
 */
#include "crypto_internal.h"

#define P26 67108864u /* 2^26 */

/* Numbers used in the contracts (annotations only). */
#define ZTL_2P24  16777216
#define ZTL_2P25  33554432
#define ZTL_2P26  67108864
#define ZTL_2P28  268435456
#define ZTL_2P29  536870912
#define ZTL_2P32  4294967296
#define ZTL_2P52  4503599627370496
#define ZTL_2P57  144115188075855872
#define ZTL_2P64  18446744073709551616
#define ZTL_2P78  302231454903657293676544
#define ZTL_2P96  79228162514264337593543950336
#define ZTL_2P104 20282409603651670423947251286016
#define ZTL_2P128 340282366920938463463374607431768211456
#define ZTL_P1305 1361129467683753853853498429727072845819 /* 2^130 - 5 */
/* Limb 1 may exceed 26 bits by this much after a step. */
#define ZTL_H1_SLACK 4096
/* The number that five limbs stand for. */
#define ZTL_VAL5(x0, x1, x2, x3, x4) \
	((x0) + (x1) * ZTL_2P26 + (x2) * ZTL_2P52 + (x3) * ZTL_2P78 + (x4) * ZTL_2P104)
/* The number that 4 and 16 bytes stand for, least significant byte first. */
#define ZTL_LE32(p) ((p)[0] + 256 * (p)[1] + 65536 * (p)[2] + 16777216 * (p)[3])
#define ZTL_LE128(p) \
	(ZTL_LE32(p) + ZTL_LE32((p) + 4) * ZTL_2P32 + ZTL_LE32((p) + 8) * ZTL_2P64 + ZTL_LE32((p) + 12) * ZTL_2P96)

/* The same for limbs in memory. A macro, not an ACSL logic function: the
 * provers then get the sum itself and need not unfold a definition. */
#define ZTL_VAL5P(l) ZTL_VAL5((l)[0], (l)[1], (l)[2], (l)[3], (l)[4])

/*@ predicate ztl_poly_h_ok{L}(uint32_t *h) =
  @   h[0] < ZTL_2P26 && h[1] < ZTL_2P26 + ZTL_H1_SLACK && h[2] < ZTL_2P26 &&
  @   h[3] < ZTL_2P26 && h[4] < ZTL_2P26;
  @ predicate ztl_poly_r_ok{L}(uint32_t *r) =
  @   \forall integer i; 0 <= i < 5 ==> r[i] < ZTL_2P26;
  @ lemma ztl_mod_add: \forall integer x, y; 0 <= x && 0 <= y ==>
  @   ((x % ZTL_2P128) + y) % ZTL_2P128 == (x + y) % ZTL_2P128;
  @*/

/* Product of two bounded 32-bit numbers, as one 32 x 32 -> 64 multiplication. */
/*@ requires a < ZTL_2P28 && b < ZTL_2P29;
  @ assigns \nothing;
  @ ensures \result == a * b;
  @ ensures \result < ZTL_2P57;
  @*/
static inline uint64_t mul(uint32_t a, uint32_t b)
{
	return (uint64_t)a * b;
}

/* Split the 128-bit number t0 + 2^32 t1 + 2^64 t2 + 2^96 t3 into limbs. */
/*@ requires \valid(l + (0 .. 4));
  @ assigns l[0 .. 4];
  @ ensures l[0] < ZTL_2P26 && l[1] < ZTL_2P26 && l[2] < ZTL_2P26 && l[3] < ZTL_2P26;
  @ ensures l[4] < ZTL_2P24;
  @ ensures value: ZTL_VAL5P(l) == t0 + t1 * ZTL_2P32 + t2 * ZTL_2P64 + t3 * ZTL_2P96;
  @*/
static void limbs128(uint32_t l[5], uint32_t t0, uint32_t t1, uint32_t t2, uint32_t t3)
{
	l[0] = t0 % P26;                              /* bits 0 .. 25 */
	l[1] = t0 / P26 + (t1 % 1048576u) * 64u;      /* 6 bits of t0, 20 bits of t1 */
	l[2] = t1 / 1048576u + (t2 % 16384u) * 4096u; /* 12 bits of t1, 14 bits of t2 */
	l[3] = t2 / 16384u + (t3 % 256u) * 262144u;   /* 18 bits of t2, 8 bits of t3 */
	l[4] = t3 / 256u;                             /* 24 bits */
}

/*
 * r = key bytes 0 .. 15 with the clamp of the definition: the top four bits
 * of each 32-bit word are zero, and so are the low two bits of words 1 .. 3.
 */
/*@ requires \valid(r + (0 .. 4)) && \valid_read(key + (0 .. 15));
  @ requires \separated(r + (0 .. 4), key + (0 .. 15));
  @ assigns r[0 .. 4];
  @ ensures ztl_poly_r_ok(r);
  @*/
static void poly_key(uint32_t r[5], const uint8_t *key)
{
	const uint32_t t0 = ztl_le32(&key[0]) % 268435456u;
	const uint32_t t1 = ztl_le32(&key[4]) % 268435456u / 4u * 4u;
	const uint32_t t2 = ztl_le32(&key[8]) % 268435456u / 4u * 4u;
	const uint32_t t3 = ztl_le32(&key[12]) % 268435456u / 4u * 4u;

	limbs128(r, t0, t1, t2, t3);
}

/* One 16-byte block as limbs. top is 2^24 for a full message block (the
 * appended 1 at bit 128), or 0 when the 1 is already among the bytes. */
/*@ requires \valid(b + (0 .. 4)) && \valid_read(p + (0 .. 15));
  @ requires \separated(b + (0 .. 4), p + (0 .. 15));
  @ requires top == 0 || top == ZTL_2P24;
  @ assigns b[0 .. 4];
  @ ensures b[0] < ZTL_2P26 && b[1] < ZTL_2P26 && b[2] < ZTL_2P26 && b[3] < ZTL_2P26;
  @ ensures b[4] < ZTL_2P25;
  @ ensures value: ZTL_VAL5P(b) == ZTL_LE128(p) + top * ZTL_2P104;
  @*/
static void poly_load(uint32_t b[5], const uint8_t *p, uint32_t top)
{
	limbs128(b, ztl_le32(&p[0]), ztl_le32(&p[4]), ztl_le32(&p[8]), ztl_le32(&p[12]));
	b[4] += top;
}

/* h = h + m, limb by limb. */
/*@ requires \valid(h + (0 .. 4)) && \valid_read(m + (0 .. 4));
  @ requires \separated(h + (0 .. 4), m + (0 .. 4));
  @ requires ztl_poly_h_ok(h);
  @ requires \forall integer i; 0 <= i < 5 ==> m[i] < ZTL_2P26;
  @ assigns h[0 .. 4];
  @ ensures \forall integer i; 0 <= i < 5 ==> h[i] == \old(h[i]) + m[i];
  @ ensures \forall integer i; 0 <= i < 5 ==> h[i] < ZTL_2P28;
  @ ensures value: ZTL_VAL5P(h) == \old(ZTL_VAL5P(h)) + ZTL_VAL5P(m);
  @*/
static void poly_add(uint32_t h[5], const uint32_t m[5])
{
	h[0] += m[0];
	h[1] += m[1];
	h[2] += m[2];
	h[3] += m[3];
	h[4] += m[4];
}

/* The part of a five-limb product a r that lies at 2^130 and above, as a
 * number (limb products 5 .. 8). */
#define ZTL_FOLD(a1, a2, a3, a4, r1, r2, r3, r4) \
	(((a1) * (r4) + (a2) * (r3) + (a3) * (r2) + (a4) * (r1)) + \
	 ((a2) * (r4) + (a3) * (r3) + (a4) * (r2)) * ZTL_2P26 + \
	 ((a3) * (r4) + (a4) * (r3)) * ZTL_2P52 + ((a4) * (r4)) * ZTL_2P78)

/*
 * h = h r modulo 2^130 - 5, not fully reduced. Exactly: the new h is the
 * product minus a multiple of 2^130 - 5, and the contract names the
 * multiplier: the part of the product at 2^130 and above, plus the last
 * carry (*carry, a proof-only output; it does not exist in the program).
 */
/*@ requires \valid(h + (0 .. 4)) && \valid_read(r + (0 .. 4)) && \valid(carry);
  @ requires \separated(h + (0 .. 4), r + (0 .. 4));
  @ requires \forall integer i; 0 <= i < 5 ==> h[i] < ZTL_2P28;
  @ requires ztl_poly_r_ok(r);
  @ assigns h[0 .. 4], *carry;
  @ ensures ztl_poly_h_ok(h);
  @ ensures value: ZTL_VAL5P(h) == \old(ZTL_VAL5P(h)) * ZTL_VAL5P(r) -
  @   ZTL_P1305 * (ZTL_FOLD(\old(h[1]), \old(h[2]), \old(h[3]), \old(h[4]), r[1], r[2], r[3], r[4]) + *carry);
  @*/
static void poly_mul(uint32_t h[5], const uint32_t r[5]) /*@ ghost (uint64_t \ghost *carry) */
{
	const uint32_t a0 = h[0], a1 = h[1], a2 = h[2], a3 = h[3], a4 = h[4];
	const uint32_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
	/* 2^130 = 5 modulo 2^130 - 5: a product that lands at limb 5 or
	 * above comes back to limb 0 and above, times 5. */
	const uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;

	const uint64_t d0 = mul(a0, r0) + mul(a1, s4) + mul(a2, s3) + mul(a3, s2) + mul(a4, s1);
	const uint64_t d1 = mul(a0, r1) + mul(a1, r0) + mul(a2, s4) + mul(a3, s3) + mul(a4, s2);
	const uint64_t d2 = mul(a0, r2) + mul(a1, r1) + mul(a2, r0) + mul(a3, s4) + mul(a4, s3);
	const uint64_t d3 = mul(a0, r3) + mul(a1, r2) + mul(a2, r1) + mul(a3, r0) + mul(a4, s4);
	const uint64_t d4 = mul(a0, r4) + mul(a1, r3) + mul(a2, r2) + mul(a3, r1) + mul(a4, r0);
	/* The five sums are the product a r with every term from limb 5
	 * upward folded back: they differ from it by a multiple of 2^130 - 5
	 * (the multiplier is the part of the product at 2^130 and above). */
	/*@ assert product: ZTL_VAL5(d0, d1, d2, d3, d4) ==
	  @   ZTL_VAL5(a0, a1, a2, a3, a4) * ZTL_VAL5(r0, r1, r2, r3, r4) -
	  @   ZTL_P1305 * ZTL_FOLD(a1, a2, a3, a4, r1, r2, r3, r4); */

	/* Carry: each limb keeps 26 bits, the rest goes to the next limb. */
	const uint64_t e1 = d1 + d0 / P26;
	const uint64_t e2 = d2 + e1 / P26;
	const uint64_t e3 = d3 + e2 / P26;
	const uint64_t e4 = d4 + e3 / P26;
	/* The carry out of limb 4 is at 2^130: back to limb 0, times 5. */
	const uint64_t t = d0 % P26 + (e4 / P26) * 5u;

	h[0] = (uint32_t)(t % P26);
	h[1] = (uint32_t)(e1 % P26 + t / P26);
	h[2] = (uint32_t)(e2 % P26);
	h[3] = (uint32_t)(e3 % P26);
	h[4] = (uint32_t)(e4 % P26);
	/*@ assert carry: ZTL_VAL5P(h) == ZTL_VAL5(d0, d1, d2, d3, d4) - (e4 / ZTL_2P26) * ZTL_P1305; */
	/*@ ghost *carry = e4 / P26; */
}

/* tag = ((h modulo 2^130 - 5) + pad) modulo 2^128, least significant byte first. */
/*@ requires \valid(tag + (0 .. 15)) && \valid_read(h + (0 .. 4)) && \valid_read(pad + (0 .. 15));
  @ requires \separated(tag + (0 .. 15), pad + (0 .. 15)) && \separated(tag + (0 .. 15), h + (0 .. 4));
  @ requires ztl_poly_h_ok(h);
  @ assigns tag[0 .. 15];
  @ // By the lemma ztl_mod_add this is (h % p + pad) % 2^128, the form of the definition.
  @ ensures value: ZTL_LE128(tag) ==
  @   ((ZTL_VAL5P(h) % ZTL_P1305) % ZTL_2P128 + ZTL_LE128(pad)) % ZTL_2P128;
  @*/
static void poly_finish(uint8_t *tag, const uint32_t h[5], const uint8_t *pad)
{
	/* Carry once around, so that every limb is below 2^26. */
	const uint32_t i2 = h[2] + h[1] / P26;
	const uint32_t i3 = h[3] + i2 / P26;
	const uint32_t i4 = h[4] + i3 / P26;
	const uint32_t i0 = h[0] + (i4 / P26) * 5u;
	const uint32_t c0 = i0 % P26, c1 = h[1] % P26 + i0 / P26, c2 = i2 % P26, c3 = i3 % P26,
		       c4 = i4 % P26;
	/*@ assert carried: c0 < ZTL_2P26 && c1 < ZTL_2P26 && c2 < ZTL_2P26 && c3 < ZTL_2P26 &&
	  @   c4 < ZTL_2P26; */
	/*@ assert carried_value: ZTL_VAL5(c0, c1, c2, c3, c4) == ZTL_VAL5P(h) - (i4 / ZTL_2P26) * ZTL_P1305; */

	/* j = c + 5. Its part at 2^130 says whether c >= 2^130 - 5; then the
	 * result is c - (2^130 - 5), which is j without that part; else c. */
	const uint32_t j0 = c0 + 5u;
	const uint32_t j1 = c1 + j0 / P26;
	const uint32_t j2 = c2 + j1 / P26;
	const uint32_t j3 = c3 + j2 / P26;
	const uint32_t j4 = c4 + j3 / P26;
	const uint32_t take_j = j4 / P26; /* 0 or 1 */
	/*@ assert choice: take_j == 0 || take_j == 1; */
	/*@ assert j_value: ZTL_VAL5(j0 % ZTL_2P26, j1 % ZTL_2P26, j2 % ZTL_2P26, j3 % ZTL_2P26, j4 % ZTL_2P26) ==
	  @   ZTL_VAL5(c0, c1, c2, c3, c4) + 5 - take_j * (ZTL_P1305 + 5); */
	const uint32_t take_c = 1u - take_j;

	/* Selection by multiplication with 0 or 1: no branch on secret data. */
	const uint32_t v0 = c0 * take_c + (j0 % P26) * take_j;
	const uint32_t v1 = c1 * take_c + (j1 % P26) * take_j;
	const uint32_t v2 = c2 * take_c + (j2 % P26) * take_j;
	const uint32_t v3 = c3 * take_c + (j3 % P26) * take_j;
	const uint32_t v4 = c4 * take_c + (j4 % P26) * take_j;
	/*@ assert selected: v0 < ZTL_2P26 && v1 < ZTL_2P26 && v2 < ZTL_2P26 && v3 < ZTL_2P26 &&
	  @   v4 < ZTL_2P26; */
	/*@ assert selected_value: ZTL_VAL5(v0, v1, v2, v3, v4) ==
	  @   ZTL_VAL5(c0, c1, c2, c3, c4) - take_j * ZTL_P1305; */
	/*@ assert reduced: 0 <= ZTL_VAL5(v0, v1, v2, v3, v4) < ZTL_P1305; */
	/*@ assert reduced_value: ZTL_VAL5(v0, v1, v2, v3, v4) == ZTL_VAL5P(h) % ZTL_P1305; */

	/* The low 128 bits of v as four 32-bit words. */
	const uint32_t w0 = v0 + (v1 % 64u) * P26;                  /* 26 + 6 bits */
	const uint32_t w1 = v1 / 64u + (v2 % 4096u) * 1048576u;     /* 20 + 12 bits */
	const uint32_t w2 = v2 / 4096u + (v3 % 262144u) * 16384u;   /* 14 + 18 bits */
	const uint32_t w3 = v3 / 262144u + (v4 % 16777216u) * 256u; /* 8 + 24 bits */
	/*@ assert words: w0 + w1 * ZTL_2P32 + w2 * ZTL_2P64 + w3 * ZTL_2P96 ==
	  @   ZTL_VAL5(v0, v1, v2, v3, v4) % ZTL_2P128; */

	/* Add pad with carry from word to word; the carry out of word 3 is dropped. */
	const uint32_t p0 = ztl_le32(&pad[0]), p1 = ztl_le32(&pad[4]), p2 = ztl_le32(&pad[8]),
		       p3 = ztl_le32(&pad[12]);
	/*@ assert pad_words: p0 + p1 * ZTL_2P32 + p2 * ZTL_2P64 + p3 * ZTL_2P96 == ZTL_LE128(pad); */
	const uint64_t f0 = (uint64_t)w0 + p0;
	const uint64_t f1 = (uint64_t)w1 + p1 + f0 / UINT64_C(4294967296);
	const uint64_t f2 = (uint64_t)w2 + p2 + f1 / UINT64_C(4294967296);
	const uint64_t f3 = (uint64_t)w3 + p3 + f2 / UINT64_C(4294967296);
	/*@ assert added: f0 % ZTL_2P32 + (f1 % ZTL_2P32) * ZTL_2P32 + (f2 % ZTL_2P32) * ZTL_2P64 +
	  @   (f3 % ZTL_2P32) * ZTL_2P96 ==
	  @   (w0 + w1 * ZTL_2P32 + w2 * ZTL_2P64 + w3 * ZTL_2P96 +
	  @    (p0 + p1 * ZTL_2P32 + p2 * ZTL_2P64 + p3 * ZTL_2P96)) % ZTL_2P128; */

	ztl_put_le32(&tag[0], (uint32_t)(f0 % UINT64_C(4294967296)));
	ztl_put_le32(&tag[4], (uint32_t)(f1 % UINT64_C(4294967296)));
	ztl_put_le32(&tag[8], (uint32_t)(f2 % UINT64_C(4294967296)));
	ztl_put_le32(&tag[12], (uint32_t)(f3 % UINT64_C(4294967296)));
	/*@ assert stored: ZTL_LE128(tag) == f0 % ZTL_2P32 + (f1 % ZTL_2P32) * ZTL_2P32 +
	  @   (f2 % ZTL_2P32) * ZTL_2P64 + (f3 % ZTL_2P32) * ZTL_2P96; */
	/*@ assert pad_frame: \forall integer i; 0 <= i < 16 ==> pad[i] == \at(pad[i], Pre); */
	/*@ assert pad_kept: p0 + p1 * ZTL_2P32 + p2 * ZTL_2P64 + p3 * ZTL_2P96 == ZTL_LE128(pad); */
	/*@ assert chain_low: ZTL_LE128(tag) ==
	  @   (ZTL_VAL5(v0, v1, v2, v3, v4) % ZTL_2P128 + ZTL_LE128(pad)) % ZTL_2P128; */
}

void ztl_poly1305(uint8_t tag[ZTL_POLY_TAG_LEN], const uint8_t *m, size_t n,
		  const uint8_t key[ZTL_POLY_KEY_LEN])
{
	uint32_t r[5];
	uint32_t h[5];
	uint32_t b[5];
	uint8_t last[16];
	/*@ ghost uint64_t carry; */
	const size_t full = n / 16u;
	const size_t rest = n % 16u;

	poly_key(r, key);
	ztl_wipe32(h, 5); /* h = 0 */
	/*@ loop invariant 0 <= i <= full;
	  @ loop invariant ztl_poly_h_ok(&h[0]) && ztl_poly_r_ok(&r[0]);
	  @ loop assigns i, h[0 .. 4], b[0 .. 4], carry;
	  @ loop variant full - i;
	  @*/
	for (size_t i = 0; i < full; i++) {
		poly_load(b, &m[16u * i], 16777216u);
		poly_add(h, b);
		poly_mul(h, r) /*@ ghost (&carry) */;
	}
	if (rest != 0u) {
		/* Last, short block: the bytes, then a 1, then zeros. */
		/*@ loop invariant 0 <= j <= 16;
		  @ loop assigns j, last[0 .. 15];
		  @ loop variant 16 - j;
		  @*/
		for (size_t j = 0; j < 16u; j++) {
			last[j] = (j < rest) ? m[16u * full + j] : ((j == rest) ? 1u : 0u);
		}
		poly_load(b, last, 0u);
		poly_add(h, b);
		poly_mul(h, r) /*@ ghost (&carry) */;
	}
	poly_finish(tag, h, &key[16]);
	ztl_wipe32(r, 5);
	ztl_wipe32(h, 5);
	ztl_wipe32(b, 5);
	ztl_wipe(last, 16);
}
