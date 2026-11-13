/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CBMC harnesses for the cryptographic code. They share no contract text
 * with the WP proofs.
 *
 *  -DH_SALSA      ztl_salsa2012_block() gives the same 64 bytes as a model in
 *                 the form of D. J. Bernstein's public-domain reference code
 *                 (the form the reference core uses), for every key, IV and
 *                 block number.
 *  -DH_POLY       ztl_poly1305() gives the same tag as a model in the form of
 *                 poly1305-donna, 32-bit version (A. Moon, public domain; the
 *                 form the reference core uses), for every key and every
 *                 message of 0 .. H_POLY_MAX bytes.
 *  -DH_POLY_STEP  one block step from ANY limb values inside the stated
 *                 limits, any block and any clamped key: no sum or product
 *                 leaves its type, and the limits hold again afterwards
 *                 (induction step: covers messages of every length).
 *  -DH_ROUNDTRIP  ztl_auth_seal() then ztl_auth_open() with the same key:
 *                 accepted, and the payload is the original again, for every
 *                 key and packet up to ZTL_PKT_MAX (set it small).
 *
 * The models keep the shifts, masks and wrap-around of their sources, so the
 * overflow and conversion checks are off inside them and on everywhere else.
 */
#include "poly.c" /* the unit under test, with its static functions */
#include "ztl/node.h"

#ifndef H_POLY_MAX
#define H_POLY_MAX 33u /* two full blocks and one byte */
#endif

size_t nondet_size(void);
uint32_t nondet_u32(void);
int nondet_int(void);

#pragma CPROVER check push
#pragma CPROVER check disable "unsigned-overflow"
#pragma CPROVER check disable "conversion"

#define M_U8TO32(p) \
	(((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define M_U32TO8(p, v) \
	do { \
		(p)[0] = (uint8_t)((v)); \
		(p)[1] = (uint8_t)((v) >> 8); \
		(p)[2] = (uint8_t)((v) >> 16); \
		(p)[3] = (uint8_t)((v) >> 24); \
	} while (0)

#if defined(H_SALSA)
#define M_ROTATE(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define M_XOR(v, w)    ((v) ^ (w))
#define M_PLUS(v, w)   ((uint32_t)((v) + (w)))

static void model_salsa2012_block(uint8_t *c, const uint8_t *k, const uint8_t *iv, uint32_t block)
{
	static const uint8_t sigma[16] = { 'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k' };
	uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
	uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
	int i;

	j0 = M_U8TO32(sigma + 0);
	j1 = M_U8TO32(k + 0);
	j2 = M_U8TO32(k + 4);
	j3 = M_U8TO32(k + 8);
	j4 = M_U8TO32(k + 12);
	j5 = M_U8TO32(sigma + 4);
	j6 = M_U8TO32(iv + 0);
	j7 = M_U8TO32(iv + 4);
	j8 = block;
	j9 = 0;
	j10 = M_U8TO32(sigma + 8);
	j11 = M_U8TO32(k + 16);
	j12 = M_U8TO32(k + 20);
	j13 = M_U8TO32(k + 24);
	j14 = M_U8TO32(k + 28);
	j15 = M_U8TO32(sigma + 12);

	x0 = j0; x1 = j1; x2 = j2; x3 = j3; x4 = j4; x5 = j5; x6 = j6; x7 = j7;
	x8 = j8; x9 = j9; x10 = j10; x11 = j11; x12 = j12; x13 = j13; x14 = j14; x15 = j15;
	for (i = 12; i > 0; i -= 2) {
		x4 = M_XOR(x4, M_ROTATE(M_PLUS(x0, x12), 7));
		x8 = M_XOR(x8, M_ROTATE(M_PLUS(x4, x0), 9));
		x12 = M_XOR(x12, M_ROTATE(M_PLUS(x8, x4), 13));
		x0 = M_XOR(x0, M_ROTATE(M_PLUS(x12, x8), 18));
		x9 = M_XOR(x9, M_ROTATE(M_PLUS(x5, x1), 7));
		x13 = M_XOR(x13, M_ROTATE(M_PLUS(x9, x5), 9));
		x1 = M_XOR(x1, M_ROTATE(M_PLUS(x13, x9), 13));
		x5 = M_XOR(x5, M_ROTATE(M_PLUS(x1, x13), 18));
		x14 = M_XOR(x14, M_ROTATE(M_PLUS(x10, x6), 7));
		x2 = M_XOR(x2, M_ROTATE(M_PLUS(x14, x10), 9));
		x6 = M_XOR(x6, M_ROTATE(M_PLUS(x2, x14), 13));
		x10 = M_XOR(x10, M_ROTATE(M_PLUS(x6, x2), 18));
		x3 = M_XOR(x3, M_ROTATE(M_PLUS(x15, x11), 7));
		x7 = M_XOR(x7, M_ROTATE(M_PLUS(x3, x15), 9));
		x11 = M_XOR(x11, M_ROTATE(M_PLUS(x7, x3), 13));
		x15 = M_XOR(x15, M_ROTATE(M_PLUS(x11, x7), 18));
		x1 = M_XOR(x1, M_ROTATE(M_PLUS(x0, x3), 7));
		x2 = M_XOR(x2, M_ROTATE(M_PLUS(x1, x0), 9));
		x3 = M_XOR(x3, M_ROTATE(M_PLUS(x2, x1), 13));
		x0 = M_XOR(x0, M_ROTATE(M_PLUS(x3, x2), 18));
		x6 = M_XOR(x6, M_ROTATE(M_PLUS(x5, x4), 7));
		x7 = M_XOR(x7, M_ROTATE(M_PLUS(x6, x5), 9));
		x4 = M_XOR(x4, M_ROTATE(M_PLUS(x7, x6), 13));
		x5 = M_XOR(x5, M_ROTATE(M_PLUS(x4, x7), 18));
		x11 = M_XOR(x11, M_ROTATE(M_PLUS(x10, x9), 7));
		x8 = M_XOR(x8, M_ROTATE(M_PLUS(x11, x10), 9));
		x9 = M_XOR(x9, M_ROTATE(M_PLUS(x8, x11), 13));
		x10 = M_XOR(x10, M_ROTATE(M_PLUS(x9, x8), 18));
		x12 = M_XOR(x12, M_ROTATE(M_PLUS(x15, x14), 7));
		x13 = M_XOR(x13, M_ROTATE(M_PLUS(x12, x15), 9));
		x14 = M_XOR(x14, M_ROTATE(M_PLUS(x13, x12), 13));
		x15 = M_XOR(x15, M_ROTATE(M_PLUS(x14, x13), 18));
	}
	x0 = M_PLUS(x0, j0); x1 = M_PLUS(x1, j1); x2 = M_PLUS(x2, j2); x3 = M_PLUS(x3, j3);
	x4 = M_PLUS(x4, j4); x5 = M_PLUS(x5, j5); x6 = M_PLUS(x6, j6); x7 = M_PLUS(x7, j7);
	x8 = M_PLUS(x8, j8); x9 = M_PLUS(x9, j9); x10 = M_PLUS(x10, j10); x11 = M_PLUS(x11, j11);
	x12 = M_PLUS(x12, j12); x13 = M_PLUS(x13, j13); x14 = M_PLUS(x14, j14); x15 = M_PLUS(x15, j15);
	M_U32TO8(c + 0, x0); M_U32TO8(c + 4, x1); M_U32TO8(c + 8, x2); M_U32TO8(c + 12, x3);
	M_U32TO8(c + 16, x4); M_U32TO8(c + 20, x5); M_U32TO8(c + 24, x6); M_U32TO8(c + 28, x7);
	M_U32TO8(c + 32, x8); M_U32TO8(c + 36, x9); M_U32TO8(c + 40, x10); M_U32TO8(c + 44, x11);
	M_U32TO8(c + 48, x12); M_U32TO8(c + 52, x13); M_U32TO8(c + 56, x14); M_U32TO8(c + 60, x15);
}
#endif

#if defined(H_POLY)
struct model_poly {
	uint32_t r[5], h[5], pad[4];
};

static void model_poly_blocks(struct model_poly *st, const uint8_t *m, size_t bytes, int final)
{
	const uint32_t hibit = final ? 0 : (1u << 24); /* 1 << 128 */
	uint32_t r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4, c;
	uint64_t d0, d1, d2, d3, d4;

	r0 = st->r[0]; r1 = st->r[1]; r2 = st->r[2]; r3 = st->r[3]; r4 = st->r[4];
	s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;
	h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];
	while (bytes >= 16) {
		h0 += (M_U8TO32(m + 0)) & 0x3ffffff;
		h1 += (M_U8TO32(m + 3) >> 2) & 0x3ffffff;
		h2 += (M_U8TO32(m + 6) >> 4) & 0x3ffffff;
		h3 += (M_U8TO32(m + 9) >> 6) & 0x3ffffff;
		h4 += (M_U8TO32(m + 12) >> 8) | hibit;
		d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
		d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
		d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
		d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
		d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);
		c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
		d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
		d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
		d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
		d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
		h0 += c * 5; c = (h0 >> 26); h0 = h0 & 0x3ffffff;
		h1 += c;
		m += 16;
		bytes -= 16;
	}
	st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void model_poly1305(uint8_t mac[16], const uint8_t *m, size_t bytes, const uint8_t key[32])
{
	struct model_poly st;
	uint8_t buffer[16];
	uint32_t h0, h1, h2, h3, h4, c, g0, g1, g2, g3, g4, mask;
	uint64_t f;
	size_t i;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	st.r[0] = (M_U8TO32(&key[0])) & 0x3ffffff;
	st.r[1] = (M_U8TO32(&key[3]) >> 2) & 0x3ffff03;
	st.r[2] = (M_U8TO32(&key[6]) >> 4) & 0x3ffc0ff;
	st.r[3] = (M_U8TO32(&key[9]) >> 6) & 0x3f03fff;
	st.r[4] = (M_U8TO32(&key[12]) >> 8) & 0x00fffff;
	st.h[0] = 0; st.h[1] = 0; st.h[2] = 0; st.h[3] = 0; st.h[4] = 0;
	st.pad[0] = M_U8TO32(&key[16]);
	st.pad[1] = M_U8TO32(&key[20]);
	st.pad[2] = M_U8TO32(&key[24]);
	st.pad[3] = M_U8TO32(&key[28]);

	const size_t want = bytes & ~(size_t)15;

	model_poly_blocks(&st, m, want, 0);
	if (bytes > want) {
		const size_t left = bytes - want;

		for (i = 0; i < left; i++) {
			buffer[i] = m[want + i];
		}
		buffer[i++] = 1;
		for (; i < 16; i++) {
			buffer[i] = 0;
		}
		model_poly_blocks(&st, buffer, 16, 1);
	}

	h0 = st.h[0]; h1 = st.h[1]; h2 = st.h[2]; h3 = st.h[3]; h4 = st.h[4];
	c = h1 >> 26; h1 = h1 & 0x3ffffff;
	h2 += c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
	h3 += c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
	h4 += c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
	h1 += c;
	/* compute h + -p */
	g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1u << 26);
	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> 31) - 1;
	g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
	/* h = h % (2^128) */
	h0 = ((h0) | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;
	/* mac = (h + pad) % (2^128) */
	f = (uint64_t)h0 + st.pad[0]; h0 = (uint32_t)f;
	f = (uint64_t)h1 + st.pad[1] + (f >> 32); h1 = (uint32_t)f;
	f = (uint64_t)h2 + st.pad[2] + (f >> 32); h2 = (uint32_t)f;
	f = (uint64_t)h3 + st.pad[3] + (f >> 32); h3 = (uint32_t)f;
	M_U32TO8(mac + 0, h0);
	M_U32TO8(mac + 4, h1);
	M_U32TO8(mac + 8, h2);
	M_U32TO8(mac + 12, h3);
}
#endif
#pragma CPROVER check pop

int main(void)
{
#if defined(H_SALSA)
	static uint8_t key[ZTL_KEY_LEN], iv[ZTL_IV_LEN], a[ZTL_SALSA_BLOCK], b[ZTL_SALSA_BLOCK];
	const uint32_t block = nondet_u32();

	__CPROVER_havoc_object(key);
	__CPROVER_havoc_object(iv);
	ztl_salsa2012_block(a, key, iv, block);
	model_salsa2012_block(b, key, iv, block);
	for (unsigned int i = 0; i < ZTL_SALSA_BLOCK; i++) {
		__CPROVER_assert(a[i] == b[i], "key stream block equals the reference form");
	}
#elif defined(H_POLY)
	static uint8_t key[ZTL_POLY_KEY_LEN], m[H_POLY_MAX], a[ZTL_POLY_TAG_LEN], b[ZTL_POLY_TAG_LEN];
	const size_t n = nondet_size();

	__CPROVER_assume(n <= H_POLY_MAX);
	__CPROVER_havoc_object(key);
	__CPROVER_havoc_object(m);
	ztl_poly1305(a, m, n, key);
	model_poly1305(b, m, n, key);
	for (unsigned int i = 0; i < ZTL_POLY_TAG_LEN; i++) {
		__CPROVER_assert(a[i] == b[i], "tag equals the reference form");
	}
#elif defined(H_POLY_STEP)
	static uint32_t h[5], r[5], m[5];
	static uint8_t key[16];

	__CPROVER_havoc_object(h);
	__CPROVER_havoc_object(m);
	__CPROVER_havoc_object(key);
	__CPROVER_assume(h[0] < P26 && h[1] < P26 + ZTL_H1_SLACK && h[2] < P26 && h[3] < P26 && h[4] < P26);
	__CPROVER_assume(m[0] < P26 && m[1] < P26 && m[2] < P26 && m[3] < P26 && m[4] < P26);
	poly_key(r, key); /* any clamped key */
	poly_add(h, m);
	poly_mul(h, r);
	__CPROVER_assert(h[0] < P26 && h[1] < P26 + ZTL_H1_SLACK && h[2] < P26 && h[3] < P26 && h[4] < P26,
			 "limb limits hold again after a step");
#elif defined(H_ROUNDTRIP)
	static uint8_t key[ZTL_KEY_LEN], pkt[ZTL_PKT_MAX], plain[ZTL_PKT_MAX];
	const size_t len = nondet_size();
	const int encrypt = nondet_int() != 0;

	__CPROVER_assume(len >= ZTL_PKT_MIN && len <= ZTL_PKT_MAX);
	__CPROVER_havoc_object(key);
	__CPROVER_havoc_object(pkt);
	__CPROVER_assume(encrypt || (pkt[ZTL_PKT_IDX_VERB] & ZTL_VERB_MASK) == ZTL_VERB_HELLO);
	for (size_t i = 0; i < ZTL_PKT_MAX; i++) {
		plain[i] = pkt[i];
	}
	ztl_auth_seal(key, pkt, len, encrypt);
	__CPROVER_assert((pkt[ZTL_PKT_IDX_FLAGS] & 0xb8u) == (encrypt ? ZTL_FLAG_CIPHER_LOW : 0u),
			 "sealed packet has suite 0 or 1 and bit 7 clear");
	const int r = ztl_auth_open(key, pkt, len, encrypt);

	__CPROVER_assert(r == 1, "a sealed packet opens with the same key");
	for (size_t i = 0; i < ZTL_PKT_MAX; i++) {
		if (i < len && (i < ZTL_PKT_IDX_FLAGS || i >= ZTL_PKT_IDX_VERB)) {
			__CPROVER_assert(pkt[i] == plain[i], "addresses, packet ID and payload are the original");
		}
	}
#else
#error "select a harness: -DH_SALSA, -DH_POLY, -DH_POLY_STEP or -DH_ROUNDTRIP"
#endif
	return 0;
}
