/* SPDX-License-Identifier: Apache-2.0 */
/* Parts of the protocol layer that have their own contracts. Not a public interface. */
#ifndef ZTL_LEAF_INTERNAL_H
#define ZTL_LEAF_INTERNAL_H

#include "bytes_internal.h"
#include "ztl/leaf.h"

/*
 * Look for "key=" at the start of a line of the dictionary d[0 .. n) and
 * copy its value, without the escapes, to out[0 .. cap). key has klen bytes.
 * Returns the length of the value, or -1 if the key is absent or the value
 * is longer than cap (out then holds no defined data).
 */
/*@ requires n <= ZTL_PKT_MAX && cap <= ZTL_PKT_MAX && klen <= 8;
  @ requires \valid_read(d + (0 .. n - 1)) && \valid_read(key + (0 .. klen - 1));
  @ requires \valid(out + (0 .. cap - 1));
  @ requires \separated(d + (0 .. n - 1), out + (0 .. cap - 1));
  @ assigns out[0 .. cap - 1];
  @ ensures -1 <= \result <= cap;
  @*/
int ztl_dict_get(const uint8_t *d, size_t n, const uint8_t *key, size_t klen, uint8_t *out, size_t cap);

/*
 * The value of a key as a number written with 1 to 16 hexadecimal digits.
 * Returns 1 and sets *v, or returns 0 (key absent, empty, too long or not
 * hexadecimal) and leaves *v as it was.
 */
/*@ requires n <= ZTL_PKT_MAX && klen <= 8;
  @ requires \valid_read(d + (0 .. n - 1)) && \valid_read(key + (0 .. klen - 1)) && \valid(v);
  @ requires \separated(d + (0 .. n - 1), v);
  @ assigns *v;
  @ ensures \result == 0 || \result == 1;
  @*/
int ztl_dict_get_hex(const uint8_t *d, size_t n, const uint8_t *key, size_t klen, uint64_t *v);

#endif
