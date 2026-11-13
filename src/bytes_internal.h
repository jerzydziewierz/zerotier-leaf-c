/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Numbers to and from bytes, most significant byte first (the order of the
 * ZeroTier wire format), and the clock difference. Written as arithmetic
 * with no wrap, as the rest of the leaf. Not a public interface.
 */
#ifndef ZTL_BYTES_INTERNAL_H
#define ZTL_BYTES_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/*@ requires \valid_read(p + (0 .. 1));
  @ assigns \nothing;
  @ ensures \result == 256 * p[0] + p[1];
  @*/
static inline uint16_t ztl_be16(const uint8_t *p)
{
	return (uint16_t)(256u * p[0] + p[1]);
}

/*@ requires \valid_read(p + (0 .. 3));
  @ assigns \nothing;
  @ ensures \result == 16777216 * p[0] + 65536 * p[1] + 256 * p[2] + p[3];
  @*/
static inline uint32_t ztl_be32(const uint8_t *p)
{
	return 16777216u * p[0] + 65536u * p[1] + 256u * p[2] + p[3];
}

/*@ requires \valid_read(p + (0 .. 7));
  @ assigns \nothing;
  @*/
static inline uint64_t ztl_be64(const uint8_t *p)
{
	return UINT64_C(4294967296) * ztl_be32(p) + ztl_be32(p + 4);
}

/*@ requires \valid(p + (0 .. 1));
  @ assigns p[0 .. 1];
  @ ensures 256 * p[0] + p[1] == v;
  @*/
static inline void ztl_put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v / 256u);
	p[1] = (uint8_t)(v % 256u);
}

/*@ requires \valid(p + (0 .. 3));
  @ assigns p[0 .. 3];
  @*/
static inline void ztl_put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v / 16777216u);
	p[1] = (uint8_t)((v / 65536u) % 256u);
	p[2] = (uint8_t)((v / 256u) % 256u);
	p[3] = (uint8_t)(v % 256u);
}

/*@ requires \valid(p + (0 .. 7));
  @ assigns p[0 .. 7];
  @*/
static inline void ztl_put_be64(uint8_t *p, uint64_t v)
{
	ztl_put_be32(p, (uint32_t)(v / UINT64_C(4294967296)));
	ztl_put_be32(p + 4, (uint32_t)(v % UINT64_C(4294967296)));
}

/* Time from then to now on the 32-bit millisecond clock, which wraps. */
/*@ assigns \nothing;
  @ ensures \result == (4294967296 + now_ms - then_ms) % 4294967296;
  @*/
static inline uint32_t ztl_age_ms(uint32_t now_ms, uint32_t then_ms)
{
	return (uint32_t)((UINT64_C(4294967296) + now_ms - then_ms) % UINT64_C(4294967296));
}

/* 1 if the n bytes at a and b are equal. For public values only (not constant time). */
/*@ requires \valid_read(a + (0 .. n - 1)) && \valid_read(b + (0 .. n - 1));
  @ assigns \nothing;
  @ ensures \result == 0 || \result == 1;
  @ ensures \result == 1 <==> (\forall integer i; 0 <= i < n ==> a[i] == b[i]);
  @*/
static inline int ztl_bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	/*@ loop invariant 0 <= i <= n;
	  @ loop invariant \forall integer k; 0 <= k < i ==> a[k] == b[k];
	  @ loop assigns i;
	  @ loop variant n - i;
	  @*/
	for (size_t i = 0; i < n; i++) {
		if (a[i] != b[i]) {
			return 0;
		}
	}
	return 1;
}

#endif
