/* SPDX-License-Identifier: Apache-2.0 */
/* ZeroTier protocol v1 datagram framing: sizes, offsets, classification. */
#ifndef ZTL_WIRE_H
#define ZTL_WIRE_H

#include <stddef.h>
#include <stdint.h>
#include "ztl/annot.h"

#define ZTL_ADDR_LEN            5u
#ifndef ZTL_PKT_MAX /* proofs may use a smaller value to stay small */
#define ZTL_PKT_MAX             2048u /* leaf limit: one packet, any datagram */
#endif
#define ZTL_PKT_IDX_IV          0u
#define ZTL_PKT_IDX_DEST        8u
#define ZTL_PKT_IDX_SRC         13u
#define ZTL_PKT_IDX_FLAGS       18u
#define ZTL_PKT_IDX_MAC         19u
#define ZTL_PKT_IDX_VERB        27u
#define ZTL_PKT_MIN             28u   /* header with verb, empty payload */
#define ZTL_FRAG_IDX_INDICATOR  13u
#define ZTL_FRAG_IDX_NO         14u
#define ZTL_FRAG_IDX_HOPS       15u
#define ZTL_FRAG_HDR            16u   /* fragment header length */
#define ZTL_FRAG_MIN            17u   /* header and at least one payload byte */
#define ZTL_FRAG_INDICATOR      0xffu /* reserved address prefix */
#define ZTL_FRAG_TOTAL_MAX      2u    /* leaf limit: head + one fragment */

#define ZTL_FRAG_NO_1_OF_2       0x21u /* byte 14: part 1 of 2 */

/* Bit 7 has two meanings. With suite 0 (protocol 13): extended armor, a second
 * AES-CTR pass with an ephemeral key. With suite 1: the old "encrypted" flag,
 * which every peer up to 1.14 sets on each encrypted packet and which the
 * reference ignores. So bit 7 is refused only together with suite 0. */
#define ZTL_FLAG_BIT7           0x80u
#define ZTL_FLAG_EXT_ARMOR_MASK (ZTL_FLAG_BIT7 | ZTL_FLAG_CIPHER_LOW)
#define ZTL_FLAG_FRAGMENTED     0x40u
#define ZTL_FLAG_CIPHER_HIGH    0x30u /* set for cipher suites 2..7 */
#define ZTL_FLAG_CIPHER_LOW     0x08u /* suite 1 when the high bits are clear */
#define ZTL_CIPHER_POLY1305_NONE       0u /* HELLO: authenticated, not encrypted */
#define ZTL_CIPHER_POLY1305_SALSA2012  1u

enum ztl_kind {
	ZTL_DROP = 0, /* not a datagram this leaf accepts; *out is not written */
	ZTL_HEAD,     /* packet head (complete packet, or first part) */
	ZTL_FRAGMENT, /* later part of a fragmented packet */
};

/* Fields of one datagram. Pointers refer into the caller's buffer. */
struct ztl_view {
	uint64_t packet_id;      /* IV of the head, big-endian on the wire */
	const uint8_t *dest;     /* ZTL_ADDR_LEN bytes */
	const uint8_t *src;      /* ZTL_ADDR_LEN bytes; head only, else NULL */
	const uint8_t *payload;  /* head: starts at the verb byte */
	uint16_t payload_len;
	uint8_t cipher;          /* head only */
	uint8_t fragmented;      /* head only: more parts follow */
	uint8_t frag_no;         /* fragment only: 1..frag_total-1 */
	uint8_t frag_total;      /* fragment only: 2..ZTL_FRAG_TOTAL_MAX */
};

/*
 * Exact acceptance rules, used in the contract below. Macros, not ACSL
 * predicates: the provers then see the same terms as in the code. The CBMC
 * harness states the cipher rule in the wire-format form (bits 3..5 as a
 * number, at most 1) and so links the two forms.
 */
#define ZTL_SPEC_BE32(p) (16777216 * (p)[0] + 65536 * (p)[1] + 256 * (p)[2] + (p)[3])
#define ZTL_SPEC_BE64(p) (4294967296 * ZTL_SPEC_BE32(p) + ZTL_SPEC_BE32((p) + 4))
#define ZTL_SPEC_IS_FRAGMENT(buf, len) \
	(ZTL_FRAG_MIN <= (len) && (len) <= ZTL_PKT_MAX && \
	 (buf)[ZTL_FRAG_IDX_INDICATOR] == ZTL_FRAG_INDICATOR && \
	 (buf)[ZTL_FRAG_IDX_NO] == ZTL_FRAG_NO_1_OF_2)
#define ZTL_SPEC_IS_HEAD(buf, len) \
	(ZTL_PKT_MIN <= (len) && (len) <= ZTL_PKT_MAX && \
	 (buf)[ZTL_FRAG_IDX_INDICATOR] != ZTL_FRAG_INDICATOR && \
	 ((buf)[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_HIGH) == 0 && \
	 ((buf)[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_EXT_ARMOR_MASK) != ZTL_FLAG_BIT7)

/*
 * Classify one received UDP payload. Reads at most len bytes of buf.
 * Accepts only candidates that this leaf can go on to process: heads with
 * cipher suite 1, or suite 0 without extended armor (the leaf has no AES), and
 * the second part of a packet with two parts. A fragment needs at least one
 * payload byte, as in the reference receive path (Switch.cpp: len > 16).
 * Writes *out only when the result is not ZTL_DROP.
 * Authentication is a later step; all fields are untrusted.
 */
/*@ requires \valid_read(buf + (0 .. len - 1));
  @ requires \valid(out);
  @ requires \separated(out, buf + (0 .. len - 1));
  @ behavior fragment:
  @   assumes ZTL_SPEC_IS_FRAGMENT(buf, len);
  @   assigns *out;
  @   ensures \result == ZTL_FRAGMENT;
  @   ensures out->packet_id == ZTL_SPEC_BE64(buf);
  @   ensures out->dest == buf + ZTL_PKT_IDX_DEST && out->src == \null;
  @   ensures out->payload == buf + ZTL_FRAG_HDR && out->payload_len == len - ZTL_FRAG_HDR;
  @   ensures out->frag_no == 1 && out->frag_total == 2;
  @   ensures out->cipher == 0 && out->fragmented == 0;
  @ behavior head:
  @   assumes ZTL_SPEC_IS_HEAD(buf, len);
  @   assigns *out;
  @   ensures \result == ZTL_HEAD;
  @   ensures out->packet_id == ZTL_SPEC_BE64(buf);
  @   ensures out->dest == buf + ZTL_PKT_IDX_DEST && out->src == buf + ZTL_PKT_IDX_SRC;
  @   ensures out->payload == buf + ZTL_PKT_IDX_VERB && out->payload_len == len - ZTL_PKT_IDX_VERB;
  @   ensures out->cipher == ((buf[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_CIPHER_LOW) != 0 ? 1 : 0);
  @   ensures out->fragmented == ((buf[ZTL_PKT_IDX_FLAGS] & ZTL_FLAG_FRAGMENTED) != 0 ? 1 : 0);
  @   ensures out->frag_no == 0 && out->frag_total == 0;
  @ behavior drop:
  @   assumes !ZTL_SPEC_IS_FRAGMENT(buf, len) && !ZTL_SPEC_IS_HEAD(buf, len);
  @   assigns \nothing;
  @   ensures \result == ZTL_DROP;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
enum ztl_kind ztl_classify(const uint8_t *ZTL_SHAR ZTL_COUNT(len) buf, size_t len,
			   struct ztl_view *ZTL_EXCL out);

#endif
