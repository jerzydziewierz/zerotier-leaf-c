/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Reader for the ZeroTier dictionary format (network configuration):
 * lines "key=value", separated by a line feed. In a value, the bytes 0, 10,
 * 13, '=' and '\' are written as '\' followed by '0', 'n', 'r', 'e', '\'.
 * The dictionary ends at its length or at a zero byte.
 */
#include "leaf_internal.h"

#define DICT_LF 10u
#define DICT_CR 13u

/*@ assigns \nothing; */
static int line_end(uint8_t c)
{
	return c == 0u || c == DICT_LF || c == DICT_CR;
}

/* Copy the value that starts at d[at] to out, without the escapes. */
/*@ requires n <= ZTL_PKT_MAX && at <= n && cap <= ZTL_PKT_MAX;
  @ requires \valid_read(d + (0 .. n - 1)) && \valid(out + (0 .. cap - 1));
  @ requires \separated(d + (0 .. n - 1), out + (0 .. cap - 1));
  @ assigns out[0 .. cap - 1];
  @ ensures -1 <= \result <= cap;
  @*/
static int value_copy(const uint8_t *d, size_t n, size_t at, uint8_t *out, size_t cap)
{
	size_t j = 0;
	int esc = 0;

	/*@ loop invariant at <= p <= n && 0 <= j <= cap;
	  @ loop assigns p, j, esc, out[0 .. cap - 1];
	  @ loop variant n - p;
	  @*/
	for (size_t p = at; p < n && !line_end(d[p]); p++) {
		uint8_t c = d[p];

		if (esc) {
			esc = 0;
			c = (c == 'r') ? DICT_CR : (c == 'n') ? DICT_LF : (c == '0') ? 0u : (c == 'e') ? '=' : c;
		} else if (c == '\\') {
			esc = 1;
			continue;
		}
		if (j == cap) {
			return -1; /* the value does not fit */
		}
		out[j] = c;
		j++;
	}
	return (int)j;
}

int ztl_dict_get(const uint8_t *d, size_t n, const char *key, size_t klen, uint8_t *out, size_t cap)
{
	size_t i = 0;

	/*@ loop invariant 0 <= i <= n;
	  @ loop assigns i, out[0 .. cap - 1];
	  @ loop variant n - i;
	  @*/
	while (i < n && d[i] != 0u) {
		/* i is the start of a line */
		if (klen < n - i && d[i + klen] == '=' && ztl_bytes_eq(&d[i], (const uint8_t *)key, klen)) {
			return value_copy(d, n, i + klen + 1u, out, cap);
		}
		/*@ loop invariant \at(i, LoopCurrent) <= i <= n;
		  @ loop assigns i;
		  @ loop variant n - i;
		  @*/
		while (i < n && !line_end(d[i])) {
			i++;
		}
		if (i < n && d[i] != 0u) {
			i++;
		}
	}
	return -1;
}

int ztl_dict_get_hex(const uint8_t *d, size_t n, const char *key, size_t klen, uint64_t *v)
{
	uint8_t t[16];
	const int len = ztl_dict_get(d, n, key, klen, t, sizeof(t));
	uint64_t x = 0;

	if (len < 1) {
		return 0;
	}
	/*@ loop invariant 0 <= i <= len;
	  @ loop assigns i, x;
	  @ loop variant len - i;
	  @*/
	for (int i = 0; i < len; i++) {
		const uint8_t c = t[i];
		uint8_t digit;

		if (c >= '0' && c <= '9') {
			digit = (uint8_t)(c - '0');
		} else if (c >= 'a' && c <= 'f') {
			digit = (uint8_t)(c - 'a' + 10u);
		} else if (c >= 'A' && c <= 'F') {
			digit = (uint8_t)(c - 'A' + 10u);
		} else {
			return 0;
		}
		if (x > UINT64_C(0x0fffffffffffffff)) {
			return 0; /* cannot happen with 16 digits; keeps the sum inside 64 bits */
		}
		x = x * 16u + digit;
	}
	*v = x;
	return 1;
}
