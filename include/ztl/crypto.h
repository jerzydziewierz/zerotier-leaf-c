/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Cryptographic parts behind ztl_auth_open() and ztl_auth_seal(): Salsa20/12
 * key stream, Poly1305 one-time authenticator, comparison in constant time,
 * wipe. Each part has its own contract and is proved alone.
 *
 * Style rule for this code: no arithmetic wraps. Every addition and
 * multiplication is shown to stay inside its type, and where the algorithm
 * wants a result modulo 2^32, the code says so with "%". The provers can then
 * keep all their overflow checks on.
 */
#ifndef ZTL_CRYPTO_H
#define ZTL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "ztl/annot.h"
#include "ztl/wire.h"

#define ZTL_KEY_LEN        32u
#define ZTL_IV_LEN         8u
#define ZTL_SALSA_BLOCK    64u
#define ZTL_POLY_KEY_LEN   32u
#define ZTL_POLY_TAG_LEN   16u
#define ZTL_MAC_LEN        8u  /* ZeroTier keeps the first 8 bytes of the tag */
#define ZTL_MANGLE_LEN     21u /* key bytes 0 .. 20 are mixed with header fields */
#define ZTL_FLAGS_KEY_MASK 0xf8u /* flags without the hop count */

/*
 * One 64-byte block of Salsa20/12 key stream (six double rounds) for a
 * 256-bit key, a 64-bit IV and a block number.
 */
/*@ requires \valid(out + (0 .. ZTL_SALSA_BLOCK - 1));
  @ requires \valid_read(key + (0 .. ZTL_KEY_LEN - 1)) && \valid_read(iv + (0 .. ZTL_IV_LEN - 1));
  @ requires \separated(out + (0 .. ZTL_SALSA_BLOCK - 1), key + (0 .. ZTL_KEY_LEN - 1));
  @ requires \separated(out + (0 .. ZTL_SALSA_BLOCK - 1), iv + (0 .. ZTL_IV_LEN - 1));
  @ assigns out[0 .. ZTL_SALSA_BLOCK - 1];
  @*/
void ztl_salsa2012_block(uint8_t out[ZTL_SALSA_BLOCK], const uint8_t key[ZTL_KEY_LEN],
			 const uint8_t iv[ZTL_IV_LEN], uint32_t block);

/*
 * XOR n bytes of buf with the key stream that starts at block 1. Block 0 is
 * never used here: its first half is the Poly1305 key of the same packet.
 */
/*@ requires n <= ZTL_PKT_MAX;
  @ requires \valid(buf + (0 .. n - 1));
  @ requires \valid_read(key + (0 .. ZTL_KEY_LEN - 1)) && \valid_read(iv + (0 .. ZTL_IV_LEN - 1));
  @ requires \separated(buf + (0 .. n - 1), key + (0 .. ZTL_KEY_LEN - 1));
  @ requires \separated(buf + (0 .. n - 1), iv + (0 .. ZTL_IV_LEN - 1));
  @ assigns buf[0 .. n - 1];
  @*/
void ztl_salsa2012_xor(uint8_t *ZTL_COUNT(n) buf, size_t n, const uint8_t key[ZTL_KEY_LEN],
		       const uint8_t iv[ZTL_IV_LEN]);

/* Poly1305 tag of n message bytes under a one-time key. */
/*@ requires n <= ZTL_PKT_MAX;
  @ requires \valid(tag + (0 .. ZTL_POLY_TAG_LEN - 1));
  @ requires \valid_read(m + (0 .. n - 1));
  @ requires \valid_read(key + (0 .. ZTL_POLY_KEY_LEN - 1));
  @ requires \separated(tag + (0 .. ZTL_POLY_TAG_LEN - 1), m + (0 .. n - 1));
  @ requires \separated(tag + (0 .. ZTL_POLY_TAG_LEN - 1), key + (0 .. ZTL_POLY_KEY_LEN - 1));
  @ assigns tag[0 .. ZTL_POLY_TAG_LEN - 1];
  @*/
void ztl_poly1305(uint8_t tag[ZTL_POLY_TAG_LEN], const uint8_t *ZTL_COUNT(n) m, size_t n,
		  const uint8_t key[ZTL_POLY_KEY_LEN]);

/*
 * 1 if the n bytes at a and b are equal, else 0. The run time and the
 * memory accesses do not depend on the contents.
 */
/*@ requires n <= ZTL_POLY_TAG_LEN;
  @ requires \valid_read(a + (0 .. n - 1)) && \valid_read(b + (0 .. n - 1));
  @ assigns \nothing;
  @ ensures \result == 0 || \result == 1;
  @ ensures \result == 1 <==> (\forall integer i; 0 <= i < n ==> a[i] == b[i]);
  @*/
int ztl_ct_eq(const uint8_t *ZTL_COUNT(n) a, const uint8_t *ZTL_COUNT(n) b, size_t n);

/* Overwrite n bytes with zero; the compiler may not remove the writes. */
/*@ requires n <= ZTL_SALSA_BLOCK;
  @ requires \valid(p + (0 .. n - 1));
  @ assigns p[0 .. n - 1];
  @ ensures \forall integer i; 0 <= i < n ==> p[i] == 0;
  @*/
void ztl_wipe(uint8_t *ZTL_COUNT(n) p, size_t n);

/*
 * Per-packet key: the peer key with header fields mixed into bytes 0 .. 20
 * (packet ID, both addresses, flags without the hop count, packet length).
 * pkt is a complete packet of len bytes; only its first 19 bytes are read.
 */
/*@ requires ZTL_PKT_MIN <= len <= ZTL_PKT_MAX;
  @ requires \valid(out + (0 .. ZTL_KEY_LEN - 1));
  @ requires \valid_read(key + (0 .. ZTL_KEY_LEN - 1));
  @ requires \valid_read(pkt + (0 .. len - 1));
  @ requires \separated(out + (0 .. ZTL_KEY_LEN - 1), key + (0 .. ZTL_KEY_LEN - 1));
  @ requires \separated(out + (0 .. ZTL_KEY_LEN - 1), pkt + (0 .. len - 1));
  @ assigns out[0 .. ZTL_KEY_LEN - 1];
  @*/
void ztl_mangle_key(uint8_t out[ZTL_KEY_LEN], const uint8_t key[ZTL_KEY_LEN],
		    const uint8_t *ZTL_COUNT(len) pkt, size_t len);

#endif
