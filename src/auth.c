/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * Packet authentication and encryption as ZeroTier composes them for cipher
 * suites 0 and 1 (reference: Packet::armor() and Packet::dearmor()):
 *   per-packet key = peer key mixed with header fields (ztl_mangle_key);
 *   Salsa20/12 with that key and the packet ID as IV;
 *   key stream block 0, first half: one-time Poly1305 key;
 *   key stream from block 1: XOR with the payload (suite 1 only);
 *   MAC = first 8 bytes of the Poly1305 tag of the payload as it is on the
 *   wire (the ciphertext for suite 1), from the verb byte to the end.
 */
#include "crypto_internal.h"
#include "reasm_internal.h"
#include "ztl/node.h"

int ztl_ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	unsigned int diff = 0;

	/*@ loop invariant 0 <= i <= n;
	  @ loop invariant diff == 0 <==> (\forall integer k; 0 <= k < i ==> a[k] == b[k]);
	  @ loop invariant diff <= 255 * i;
	  @ loop assigns i, diff;
	  @ loop variant n - i;
	  @*/
	for (size_t i = 0; i < n; i++) {
		/* (a - b) modulo 256: zero only for equal bytes; no branch. */
		diff += (a[i] + 256u - b[i]) % 256u;
	}
	return diff == 0u;
}

void ztl_wipe(uint8_t *p, size_t n)
{
	/*@ loop invariant 0 <= i <= n;
	  @ loop invariant \forall integer k; 0 <= k < i ==> p[k] == 0;
	  @ loop assigns i, p[0 .. n - 1];
	  @ loop variant n - i;
	  @*/
	for (size_t i = 0; i < n; i++) {
		p[i] = 0;
		ZTL_KEEP_WRITES(p);
	}
}

void ztl_mangle_key(uint8_t out[ZTL_KEY_LEN], const uint8_t key[ZTL_KEY_LEN], const uint8_t *pkt,
		    size_t len)
{
	_Static_assert(ZTL_PKT_IDX_FLAGS == 18u && ZTL_MANGLE_LEN == 21u, "key mixing layout");
	_Static_assert(ZTL_PKT_MAX <= 65535u, "the packet length is mixed in as two bytes");

	/* Packet ID and both addresses. */
	/*@ loop invariant 0 <= i <= ZTL_PKT_IDX_FLAGS;
	  @ loop assigns i, out[0 .. ZTL_PKT_IDX_FLAGS - 1];
	  @ loop variant ZTL_PKT_IDX_FLAGS - i;
	  @*/
	for (unsigned int i = 0; i < ZTL_PKT_IDX_FLAGS; i++) {
		out[i] = key[i] ^ pkt[i];
	}
	/* Flags without the hop count, which relays change. */
	out[18] = key[18] ^ (pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAGS_KEY_MASK);
	/* Packet length, least significant byte first. */
	out[19] = key[19] ^ (uint8_t)(len % 256u);
	out[20] = key[20] ^ (uint8_t)((len / 256u) % 256u);
	/*@ loop invariant ZTL_MANGLE_LEN <= i <= ZTL_KEY_LEN;
	  @ loop assigns i, out[ZTL_MANGLE_LEN .. ZTL_KEY_LEN - 1];
	  @ loop variant ZTL_KEY_LEN - i;
	  @*/
	for (unsigned int i = ZTL_MANGLE_LEN; i < ZTL_KEY_LEN; i++) {
		out[i] = key[i];
	}
}

/* Poly1305 tag of the payload of pkt under the one-time key of this packet. */
/*@ requires ZTL_PKT_MIN <= len <= ZTL_PKT_MAX;
  @ requires \valid(tag + (0 .. ZTL_POLY_TAG_LEN - 1));
  @ requires \valid_read(mkey + (0 .. ZTL_KEY_LEN - 1));
  @ requires \valid_read(pkt + (0 .. len - 1));
  @ requires \separated(tag + (0 .. ZTL_POLY_TAG_LEN - 1), mkey + (0 .. ZTL_KEY_LEN - 1));
  @ requires \separated(tag + (0 .. ZTL_POLY_TAG_LEN - 1), pkt + (0 .. len - 1));
  @ assigns tag[0 .. ZTL_POLY_TAG_LEN - 1];
  @*/
static void packet_tag(uint8_t tag[ZTL_POLY_TAG_LEN], const uint8_t mkey[ZTL_KEY_LEN],
		       const uint8_t *pkt, size_t len)
{
	uint8_t ks[ZTL_SALSA_BLOCK];

	ztl_salsa2012_block(ks, mkey, &pkt[ZTL_PKT_IDX_IV], 0);
	ztl_poly1305(tag, &pkt[ZTL_PKT_IDX_VERB], len - ZTL_PKT_IDX_VERB, ks);
	ztl_wipe(ks, ZTL_SALSA_BLOCK);
}

int ztl_auth_open(const uint8_t key[ZTL_KEY_LEN], uint8_t *pkt, size_t len, int decrypt)
{
	uint8_t mkey[ZTL_KEY_LEN];
	uint8_t tag[ZTL_POLY_TAG_LEN];

	ztl_mangle_key(mkey, key, pkt, len);
	packet_tag(tag, mkey, pkt, len);

	/* The answer itself is public: the sender sees whether a reply comes. */
	const int ok = ztl_ct_eq(tag, &pkt[ZTL_PKT_IDX_MAC], ZTL_MAC_LEN);

	if (ok && decrypt) {
		ztl_salsa2012_xor(&pkt[ZTL_PKT_IDX_VERB], len - ZTL_PKT_IDX_VERB, mkey,
				  &pkt[ZTL_PKT_IDX_IV]);
	}
	ztl_wipe(mkey, ZTL_KEY_LEN);
	ztl_wipe(tag, ZTL_POLY_TAG_LEN);
	/*@ ghost ztl_gh_auth_calls++; */
	/*@ ghost ztl_gh_auth_yes = ok; */
	/*@ ghost ztl_gh_auth_key = key; */
	/*@ ghost ztl_gh_auth_pkt = pkt; */
	/*@ ghost ztl_gh_auth_len = len; */
	return ok;
}

void ztl_auth_seal(const uint8_t key[ZTL_KEY_LEN], uint8_t *pkt, size_t len, int encrypt)
{
	uint8_t mkey[ZTL_KEY_LEN];
	uint8_t tag[ZTL_POLY_TAG_LEN];

	/* The cipher suite goes into the flags first: the flags are part of
	 * the per-packet key. Bit 7 and the suite bits for AES stay clear. */
	pkt[ZTL_PKT_IDX_FLAGS] = (uint8_t)((pkt[ZTL_PKT_IDX_FLAGS] & ZTL_FLAGS_SEAL_KEEP) |
					   (encrypt ? ZTL_FLAG_CIPHER_LOW : 0u));
	ztl_mangle_key(mkey, key, pkt, len);
	if (encrypt) {
		ztl_salsa2012_xor(&pkt[ZTL_PKT_IDX_VERB], len - ZTL_PKT_IDX_VERB, mkey,
				  &pkt[ZTL_PKT_IDX_IV]);
	}
	packet_tag(tag, mkey, pkt, len);
	ztl_copy_bytes(&pkt[ZTL_PKT_IDX_MAC], tag, ZTL_MAC_LEN);
	ztl_wipe(mkey, ZTL_KEY_LEN);
	ztl_wipe(tag, ZTL_POLY_TAG_LEN);
}
