/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
#include "ztl/wire.h"

/* Target data layout (ARM EABI, 32-bit). The proofs run with other data
 * models too; this pins the layout that the target compiler must produce. */
#if defined(__arm__)
_Static_assert(sizeof(size_t) == 4 && sizeof(void *) == 4, "ILP32 expected");
_Static_assert(sizeof(struct ztl_view) == 32 && _Alignof(struct ztl_view) == 8,
	       "struct ztl_view layout changed");
#endif

/* Four bytes, most significant first, as a number (plain arithmetic: the
 * sum cannot exceed 2^32 - 1). */
/*@ requires \valid_read(p + (0 .. 3));
  @ assigns \nothing;
  @ ensures \result == ZTL_SPEC_BE32(p);
  @*/
static uint32_t be32(const uint8_t *p)
{
	return 16777216u * p[0] + 65536u * p[1] + 256u * p[2] + p[3];
}

/*@ requires \valid_read(p + (0 .. 7));
  @ assigns \nothing;
  @ ensures \result == ZTL_SPEC_BE64(p);
  @*/
static uint64_t be64(const uint8_t *p)
{
	return UINT64_C(4294967296) * be32(p) + be32(p + 4);
}

enum ztl_kind ztl_classify(const uint8_t *buf, size_t len, struct ztl_view *out)
{
	if (len < ZTL_FRAG_MIN || len > ZTL_PKT_MAX) {
		return ZTL_DROP;
	}

	if (buf[ZTL_FRAG_IDX_INDICATOR] == ZTL_FRAG_INDICATOR) {
		/* High nibble: total parts; low nibble: this part. With two
		 * parts at most, the only legal value is part 1 of 2. */
		_Static_assert(ZTL_FRAG_TOTAL_MAX == 2u, "fragment rule assumes two parts");
		if (buf[ZTL_FRAG_IDX_NO] != ZTL_FRAG_NO_1_OF_2) {
			return ZTL_DROP;
		}
		out->packet_id = be64(buf);
		out->dest = buf + ZTL_PKT_IDX_DEST;
		out->src = NULL;
		out->payload = buf + ZTL_FRAG_HDR;
		out->payload_len = (uint16_t)(len - ZTL_FRAG_HDR);
		out->cipher = 0;
		out->fragmented = 0;
		out->frag_no = 1;
		out->frag_total = 2;
		return ZTL_FRAGMENT;
	}

	if (len < ZTL_PKT_MIN) {
		return ZTL_DROP;
	}

	const uint8_t flags = buf[ZTL_PKT_IDX_FLAGS];

	/* Cipher suite = flags bits 3..5. Suites 0 and 1 have bits 4 and 5 clear. */
	if ((flags & ZTL_FLAG_CIPHER_HIGH) != 0u) {
		return ZTL_DROP;
	}
	/* Suite 0 with bit 7 is extended armor: needs AES, which this leaf does not have. */
	if ((flags & ZTL_FLAG_EXT_ARMOR_MASK) == ZTL_FLAG_BIT7) {
		return ZTL_DROP;
	}
	const uint8_t cipher = (flags & ZTL_FLAG_CIPHER_LOW) != 0u;

	out->packet_id = be64(buf);
	out->dest = buf + ZTL_PKT_IDX_DEST;
	out->src = buf + ZTL_PKT_IDX_SRC;
	out->payload = buf + ZTL_PKT_IDX_VERB;
	out->payload_len = (uint16_t)(len - ZTL_PKT_IDX_VERB);
	out->cipher = cipher;
	out->fragmented = (flags & ZTL_FLAG_FRAGMENTED) != 0u;
	out->frag_no = 0;
	out->frag_total = 0;
	return ZTL_HEAD;
}
