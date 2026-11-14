/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
#include "ztl/lz4.h"

#define LZ4_MIN_MATCH 4u
#define LZ4_NIBBLE_MORE 15u /* this half of the token is extended by more bytes */
#define LZ4_BYTE_MORE 255u  /* an extension byte of this value is followed by another */

/*
 * Extended length: add the bytes at src[*ip ...] to len until one is below
 * 255. Returns 0 if the input ends first or the length exceeds max;
 * otherwise 1, with the sum in *out and *ip after the last byte read.
 */
/*@ requires n <= ZTL_PKT_MAX && max <= ZTL_PKT_MAX && len <= 19;
  @ requires \valid(ip) && \valid(out) && *ip <= n;
  @ requires \valid_read(src + (0 .. n - 1));
  @ requires \separated(ip, out, src + (0 .. n - 1));
  @ assigns *ip, *out;
  @ ensures \result == 0 || \result == 1;
  @ ensures \old(*ip) <= *ip <= n;
  @ ensures \result == 1 ==> *out <= max;
  @*/
static int lz4_more(const uint8_t *src, size_t n, size_t *ip, size_t len, size_t max, size_t *out)
{
	size_t i = *ip;

	/*@ loop invariant \at(*ip, Pre) <= i <= n;
	  @ loop invariant len <= max + 19;
	  @ loop assigns i, len;
	  @ loop variant n - i;
	  @*/
	while (i < n) {
		const uint8_t b = src[i];

		i++;
		len += b;
		if (len > max) {
			break;
		}
		if (b != LZ4_BYTE_MORE) {
			*ip = i;
			*out = len;
			return 1;
		}
	}
	*ip = i;
	return 0;
}

size_t ztl_lz4_decode(uint8_t *dst, size_t cap, const uint8_t *src, size_t n)
{
	size_t ip = 0; /* bytes of src read */
	size_t op = 0; /* bytes of dst written */

	/*@ loop invariant 0 <= ip <= n && 0 <= op <= cap;
	  @ loop assigns ip, op, dst[0 .. cap - 1];
	  @ loop variant n - ip;
	  @*/
	while (ip < n) {
		const uint8_t token = src[ip];
		size_t lit = token / 16u;
		size_t len = token % 16u + LZ4_MIN_MATCH;

		ip++;
		if (lit == LZ4_NIBBLE_MORE && !lz4_more(src, n, &ip, lit, cap, &lit)) {
			return 0;
		}
		if (lit > n - ip || lit > cap - op) {
			return 0;
		}
		/*@ loop invariant 0 <= i <= lit;
		  @ loop assigns i, dst[op .. op + lit - 1];
		  @ loop variant lit - i;
		  @*/
		for (size_t i = 0; i < lit; i++) {
			dst[op + i] = src[ip + i];
		}
		ip += lit;
		op += lit;
		if (ip == n) {
			return op; /* the last sequence has no match */
		}
		if (n - ip < 2u) {
			return 0;
		}
		const size_t off = src[ip] + 256u * src[ip + 1u];

		ip += 2u;
		if (off == 0u || off > op) {
			return 0; /* a match can only copy what was written */
		}
		if (len == LZ4_NIBBLE_MORE + LZ4_MIN_MATCH && !lz4_more(src, n, &ip, len, cap, &len)) {
			return 0;
		}
		if (len > cap - op) {
			return 0;
		}
		/* Byte by byte, upward: a match may overlap the bytes it writes
		 * (offset below length repeats a pattern). */
		/*@ loop invariant 0 <= i <= len;
		  @ loop assigns i, dst[op .. op + len - 1];
		  @ loop variant len - i;
		  @*/
		for (size_t i = 0; i < len; i++) {
			dst[op + i] = dst[op + i - off];
		}
		op += len;
	}
	return 0; /* the block ended after a match, or was empty */
}
