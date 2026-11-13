/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Frama-C Eva harness: ztl_classify() on unknown contents, len 0..ZTL_PKT_MAX+1.
 * Purpose: absence of run-time errors, and the preconditions at the call.
 * Limits: (1) the array always has ZTL_PKT_MAX+1 bytes, so a read between len
 * and the array end is not an alarm here; the CBMC harness uses an exact-size
 * buffer. (2) Eva cannot decide which contract behaviour applies to unknown
 * buffer contents, so it reports the behaviour postconditions as "may be
 * inactive"; those are proved by WP and checked by CBMC, and proofs/run.sh
 * does not count them for Eva. (3) It cannot decide the value of the packet
 * ID either ("postcondition got status unknown" for be32 and be64); WP
 * proves it.
 */
#include "__fc_builtin.h"
#include "ztl/wire.h"

int main(void)
{
	uint8_t buf[ZTL_PKT_MAX + 1u];
	struct ztl_view v;

	Frama_C_make_unknown((char *)buf, sizeof(buf));
	size_t len = (size_t)Frama_C_interval(0, (int)ZTL_PKT_MAX + 1);
	return (int)ztl_classify(buf, len, &v);
}
