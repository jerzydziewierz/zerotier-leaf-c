/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/* Byte order helpers and wipe for the cryptographic code. Not a public interface. */
#ifndef ZTL_CRYPTO_INTERNAL_H
#define ZTL_CRYPTO_INTERNAL_H

#include "ztl/crypto.h"

/* Four bytes, least significant first, as a number. Written as arithmetic:
 * the sum cannot exceed 2^32 - 1, and the provers need no bit reasoning. */
/*@ requires \valid_read(p + (0 .. 3));
  @ assigns \nothing;
  @ ensures \result == p[0] + 256 * p[1] + 65536 * p[2] + 16777216 * p[3];
  @*/
static inline uint32_t ztl_le32(const uint8_t *p)
{
	return p[0] + 256u * p[1] + 65536u * p[2] + 16777216u * p[3];
}

/*@ requires \valid(p + (0 .. 3));
  @ assigns p[0 .. 3];
  @ ensures p[0] + 256 * p[1] + 65536 * p[2] + 16777216 * p[3] == v;
  @*/
static inline void ztl_put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v % 256u);
	p[1] = (uint8_t)((v / 256u) % 256u);
	p[2] = (uint8_t)((v / 65536u) % 256u);
	p[3] = (uint8_t)(v / 16777216u);
}

/*
 * In a wipe loop, after each write: tell the compiler that the memory may be
 * read, so that it keeps the write although the object is not used again,
 * and does not replace the loop with a call to memset. The provers see
 * plain C.
 */
#if defined(__FRAMAC__) || defined(__CPROVER__)
#define ZTL_KEEP_WRITES(p) ((void)(p))
#elif defined(__GNUC__)
#define ZTL_KEEP_WRITES(p) __asm__ __volatile__("" : : "r"(p) : "memory")
#else
#error "ZTL_KEEP_WRITES: no way known to keep wipe writes with this compiler"
#endif

/* Overwrite n words with zero. */
/*@ requires n <= 16;
  @ requires \valid(p + (0 .. n - 1));
  @ assigns p[0 .. n - 1];
  @ ensures \forall integer i; 0 <= i < n ==> p[i] == 0;
  @*/
static inline void ztl_wipe32(uint32_t *p, unsigned int n)
{
	/*@ loop invariant 0 <= i <= n;
	  @ loop invariant \forall integer k; 0 <= k < i ==> p[k] == 0;
	  @ loop assigns i, p[0 .. n - 1];
	  @ loop variant n - i;
	  @*/
	for (unsigned int i = 0; i < n; i++) {
		p[i] = 0;
		ZTL_KEEP_WRITES(p);
	}
}

#endif
