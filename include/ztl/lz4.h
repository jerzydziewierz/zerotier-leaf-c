/* SPDX-License-Identifier: Apache-2.0 */
/* Bounded decoder for one LZ4 block (the form in which ZeroTier compresses a packet payload). */
#ifndef ZTL_LZ4_H
#define ZTL_LZ4_H

#include <stddef.h>
#include <stdint.h>
#include "ztl/annot.h"
#include "ztl/wire.h"

/*
 * Decode the LZ4 block src[0 .. n) into dst[0 .. cap).
 * Returns the number of bytes written (1 .. cap), or 0 if the block is not
 * well formed, is empty, or does not fit; dst then holds no defined data.
 * Reads only src[0 .. n), writes only dst[0 .. cap), for every input.
 * Every loop consumes input or is bounded by cap, so the work is at most
 * n + cap steps. The two buffers must not overlap.
 *
 * Format (one block, no frame header): a list of sequences. Each sequence is
 * a token byte (high half: number of literal bytes, low half: match length
 * minus 4; a half of 15 is extended by following bytes, each added, until a
 * byte below 255), the literal bytes, then a 2-byte offset (least
 * significant byte first, 1 .. bytes written so far) of a match to copy
 * from the output. The last sequence ends after its literals.
 */
/*@ requires n <= ZTL_PKT_MAX && cap <= ZTL_PKT_MAX;
  @ requires \valid(dst + (0 .. cap - 1));
  @ requires \valid_read(src + (0 .. n - 1));
  @ requires \separated(dst + (0 .. cap - 1), src + (0 .. n - 1));
  @ assigns dst[0 .. cap - 1];
  @ ensures \result <= cap;
  @*/
size_t ztl_lz4_decode(uint8_t *ZTL_COUNT(cap) dst, size_t cap, const uint8_t *ZTL_SHAR ZTL_COUNT(n) src,
		      size_t n);

#endif
