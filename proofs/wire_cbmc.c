/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CBMC harness: ztl_classify() for every buffer of every length
 * 0..ZTL_PKT_MAX+1. The harness holds a model of the reference receive path
 * (ref_model) and checks the result against it in both directions: the leaf
 * accepts exactly what the reference would authenticate without AES, with
 * exact fields; every other datagram is dropped and the output object is not
 * changed. The two listed differences (AES packets) are dropped.
 */
#include <stdlib.h>
#include "ztl/wire.h"

size_t nondet_size(void);
struct ztl_view nondet_view(void);

static int same_view(const struct ztl_view *a, const struct ztl_view *b)
{
	return a->packet_id == b->packet_id && a->dest == b->dest && a->src == b->src &&
	       a->payload == b->payload && a->payload_len == b->payload_len &&
	       a->cipher == b->cipher && a->fragmented == b->fragmented &&
	       a->frag_no == b->frag_no && a->frag_total == b->frag_total;
}

/*
 * Model of the reference receive path for a datagram addressed to this node,
 * written from ZeroTier One 1.16.2 with the leaf's fragment limit, line by
 * line and in the reference's own form (nibbles, shifts):
 *   Switch.cpp onRemotePacket: len > 16; byte 13 == 0xff -> fragment with
 *     total <= ZT_MAX_PACKET_FRAGMENTS (2), 0 < no < total, total > 1;
 *     else len >= 28 -> packet head.
 *   IncomingPacket.cpp tryDecode + Packet.cpp dearmor: suite 2 (trusted path)
 *     is refused without trusted paths; suite 0 with bit 7 -> AES-CTR with an
 *     ephemeral key; suites 0 and 1 -> Poly1305 (bit 7 ignored with suite 1:
 *     peers up to 1.14 set it on every encrypted packet); suite 3 -> AES-GMAC-SIV;
 *     suites 4..7 -> refused.
 * Not modelled (no local identity here): source == self, destination != self.
 */
enum ref_kind { REF_IGNORE, REF_FRAGMENT, REF_HEAD_POLY, REF_HEAD_AES_GMAC, REF_HEAD_EXT_ARMOR };

static enum ref_kind ref_model(const uint8_t *data, size_t len)
{
	if (len > 2048u) { /* leaf limit; the reference buffer is also 2048 */
		return REF_IGNORE;
	}
	if (len > 16u) {
		if (data[13] == 0xffu) {
			unsigned int no = data[14] & 0xfu;
			unsigned int total = (data[14] >> 4) & 0xfu;

			if (total <= 2u && no < total && no > 0u && total > 1u) {
				return REF_FRAGMENT;
			}
			return REF_IGNORE;
		} else if (len >= 28u) {
			unsigned int cs = (data[18] & 0x38u) >> 3;
			int bit7 = (data[18] & 0x80u) != 0u;

			if (cs == 0u) {
				return bit7 ? REF_HEAD_EXT_ARMOR : REF_HEAD_POLY;
			}
			if (cs == 1u) {
				return REF_HEAD_POLY;
			}
			if (cs == 3u) {
				return REF_HEAD_AES_GMAC;
			}
			return REF_IGNORE;
		}
	}
	return REF_IGNORE;
}

int main(void)
{
	size_t len = nondet_size();
	__CPROVER_assume(len <= ZTL_PKT_MAX + 1u);

	uint8_t *buf = malloc(len); /* exact size: any read past len is an error */
	__CPROVER_assume(buf != NULL);

	struct ztl_view v = nondet_view();
	const struct ztl_view before = v;
	enum ztl_kind k = ztl_classify(buf, len, &v);

	/* What the reference does with this datagram (ref_model above). */
	enum ref_kind r = ref_model(buf, len);

	__CPROVER_assert((k == ZTL_FRAGMENT) == (r == REF_FRAGMENT), "fragment exactly when the reference takes a fragment");
	__CPROVER_assert((k == ZTL_HEAD) == (r == REF_HEAD_POLY), "head exactly when the reference authenticates with Poly1305 only");
	/* Listed differences: the reference goes on, the leaf drops (no AES). */
	__CPROVER_assert((r == REF_HEAD_AES_GMAC || r == REF_HEAD_EXT_ARMOR) ? k == ZTL_DROP : 1, "AES packets are dropped");
	__CPROVER_assert(k == ZTL_DROP || k == ZTL_HEAD || k == ZTL_FRAGMENT, "result is one of three kinds");

	if (k == ZTL_DROP) {
		__CPROVER_assert(same_view(&v, &before), "drop leaves the output object unchanged");
	} else {
		uint64_t id = 0;
		for (unsigned int i = 0; i < 8u; i++) {
			id += (uint64_t)buf[i] << (8u * (7u - i));
		}
		__CPROVER_assert(v.packet_id == id, "packet id is the first 8 bytes, big-endian");
		__CPROVER_assert(v.dest == buf + 8, "destination address at offset 8");
		__CPROVER_assert(v.payload + v.payload_len == buf + len, "payload ends at buffer end");
	}
	if (k == ZTL_HEAD) {
		__CPROVER_assert(v.src == buf + 13, "source address at offset 13");
		__CPROVER_assert(v.payload == buf + 27 && v.payload_len >= 1u, "payload starts at the verb byte");
		__CPROVER_assert(v.cipher == ((buf[18] >> 3) & 7u), "cipher suite from flags bits 3..5");
		__CPROVER_assert(v.fragmented == ((buf[18] & 0x40u) ? 1u : 0u), "fragmented flag from flags bit 6");
		__CPROVER_assert(v.frag_no == 0u && v.frag_total == 0u, "head has no fragment numbers");
	}
	if (k == ZTL_FRAGMENT) {
		__CPROVER_assert(v.src == NULL, "fragment has no source address");
		__CPROVER_assert(v.payload == buf + 16 && v.payload_len >= 1u, "fragment payload at offset 16, not empty");
		__CPROVER_assert(v.frag_no == 1u && v.frag_total == 2u, "fragment is part 1 of 2");
	}

	/* Reachability: each must be coverable, or the checks above are vacuous. */
	__CPROVER_cover(k == ZTL_DROP && len == 0u);
	__CPROVER_cover(k == ZTL_DROP && len == ZTL_PKT_MAX + 1u);
	__CPROVER_cover(k == ZTL_HEAD && len == ZTL_PKT_MIN);
	__CPROVER_cover(k == ZTL_HEAD && len == ZTL_PKT_MAX && v.cipher == 1u && v.fragmented);
	__CPROVER_cover(k == ZTL_FRAGMENT && len == ZTL_FRAG_MIN);
	__CPROVER_cover(k == ZTL_DROP && len == ZTL_FRAG_HDR && buf[13] == 0xffu && buf[14] == 0x21u);
	__CPROVER_cover(k == ZTL_DROP && r == REF_HEAD_EXT_ARMOR);
	__CPROVER_cover(k == ZTL_DROP && r == REF_HEAD_AES_GMAC);
	__CPROVER_cover(k == ZTL_HEAD && buf[18] == 0x88u); /* suite 1 with the old "encrypted" flag */
	__CPROVER_cover(k == ZTL_HEAD && v.cipher == 0u);
	__CPROVER_cover(k == ZTL_FRAGMENT && len == ZTL_PKT_MAX);
	return 0;
}
