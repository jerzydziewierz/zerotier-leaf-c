#!/usr/bin/env bash
# Run every proof. Exit status 0 only if every tool ran, exited 0 and
# reported the expected result (a tool that proves nothing is a failure).
# Usage: proofs/run.sh [cbmc|cbmc32|cover|eva|wp|wp32|target|vectors|mutate]...
# Default: cbmc cbmc32 cover eva wp wp32 target vectors. cbmc32 and wp32 repeat the
# proofs with a 32-bit data model (CBMC: arm, on sources preprocessed by the
# target compiler; WP: gcc_x86_32, the nearest ILP32 model that Frama-C has;
# its struct layout is not the ARM one). "mutate" applies deliberate errors to
# src/wire.c one at a time (it restores the file) and needs each to be rejected.
# ZTL_CC: target C compiler (default: Zephyr SDK arm-zephyr-eabi-gcc beside this repo).
set -u
cd "$(dirname "$0")/.."
# Provers do not run on the workstation: start this script through
# proofs/on-remote.sh, which sets ZTL_ON_REMOTE and a memory limit for the run.
[ "${ZTL_ON_REMOTE:-}" = 1 ] || { echo "run.sh: use proofs/on-remote.sh start [steps] (no local prover runs)"; exit 2; }
tools=("$@"); [ ${#tools[@]} -eq 0 ] && tools=(cbmc cbmc32 cover eva wp wp32 target vectors)
FC0="opam exec --switch ztl -- frama-c -cpp-extra-args=-Iinclude -cpp-extra-args=-Isrc"
# Units proved by WP, each alone: a function is proved against its contract,
# and callers use the contracts of what they call.
WP_UNITS=${ZTL_WP_UNITS:-"src/wire.c src/reasm.c proofs/reasm_wp.c src/rx.c src/salsa.c src/poly.c src/auth.c"}
# WP also proves that no unsigned sum or product wraps and that no conversion
# to a narrower unsigned type loses bits (C defines both, the code never wants them).
WP_STRICT="-warn-unsigned-overflow -warn-unsigned-downcast"
CBMC_SRC="-Iinclude src/wire.c proofs/wire_cbmc.c --unwind 9"
ZTL_CC=${ZTL_CC:-../dl/sdk/zephyr-sdk-1.0.1/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc}
FC="$FC0"
LIM="" # the memory limit is on the whole run (proofs/on-remote.sh)
rc=0
for t in "${tools[@]}"; do
	o=proofs/out-$t.txt
	case "$t" in
	cbmc|cbmc32) src=$CBMC_SRC
		if [ $t = cbmc32 ]; then
			# Preprocess with the target compiler, so that the target's own headers
			# give the types (the host headers make uint64_t 32 bits wide in an
			# ILP32 model). The target layout assertion in src/wire.c is then checked too.
			src="--arch arm --unwind 9"
			for f in src/wire.c proofs/wire_cbmc.c; do
				i=proofs/out-$(basename $f .c).arm.i
				"$ZTL_CC" -E -mcpu=cortex-m7 -mthumb -std=c11 -Iinclude $f -o $i 2> $o || src="$src MISSING"
				src="$src $i"
			done
		fi
		$LIM cbmc $src --bounds-check --pointer-check --pointer-overflow-check \
		--signed-overflow-check --unsigned-overflow-check --conversion-check \
		--div-by-zero-check --undefined-shift-check --unwinding-assertions > $o 2>&1
		s=$?; grep -q '^VERIFICATION SUCCESSFUL$' $o || s=1
		grep -qE '^\*\* 0 of [1-9][0-9]* failed' $o || s=1 ;;
	cover) $LIM cbmc $CBMC_SRC --cover cover > $o 2>&1
		s=$?; grep -qE '^\*\* ([1-9][0-9]*) of \1 covered' $o || s=1 ;;
	eva) $LIM $FC src/wire.c proofs/wire_eva.c -eva -eva-precision 5 > $o 2>&1
		s=$?
		# Any alarm fails, except postconditions that Eva cannot decide (see wire_eva.c):
		# they are proved by WP. A postcondition that Eva finds invalid still fails.
		grep -A1 'eva:alarm' $o | grep -vE 'eva:alarm|^--$|Behavior may be inactive|postcondition got status unknown' | grep -q . && s=1
		grep -qE '^ +0 alarms generated' $o || s=1
		grep -E '^ +(Assertions|Preconditions|Postconditions)' $o | grep -qvE ' 0 unknown +0 invalid' && s=1
		# Fail closed: the summaries must be present and non-empty.
		grep -qE '^ +Preconditions +[1-9][0-9]* valid' $o || s=1
		grep -qE 'statements reached \(out of ([0-9]+)\): 100% coverage' $o || s=1 ;;
	wp|wp32) m=; [ $t = wp32 ] && m='-machdep gcc_x86_32'
		: > $o; s=0; total=0
		for u in $WP_UNITS; do
			$LIM $FC $m $WP_STRICT $u -wp -wp-rte -wp-prover alt-ergo,z3,cvc5 -wp-timeout 60 -wp-cache none > $o.unit 2>&1 || s=1
			g=$(sed -nE 's/.*Proved goals: +([0-9]+) \/ ([0-9]+)$/\1 \2/p' $o.unit)
			set -- $g; [ $# -eq 2 ] && [ "$1" = "$2" ] && [ "$1" -gt 0 ] || s=1
			total=$((total + ${1:-0})); echo "$u: Proved goals: ${1:-?} / ${2:-?}" >> $o
			grep -E 'Timeout|Failed|rror' $o.unit >> $o
		done
		echo "all units: $total goals" >> $o; rm -f $o.unit ;;
	target) # Compile for the Cortex-M7 with all warnings as errors; report code size and stack.
		: > $o; s=0
		for f in src/*.c; do
			b=proofs/out-$(basename $f .c)
			"$ZTL_CC" -std=c11 -Os -mcpu=cortex-m7 -mthumb -Wall -Wextra -Wpedantic -Werror \
				-Iinclude -Isrc -fstack-usage -c $f -o $b.o >> $o 2>&1 || { s=1; continue; }
			echo "$f text bytes: $("${ZTL_CC%gcc}size" $b.o | awk 'NR==2{print $1}'), stack bytes: $(awk '{print $1, $2}' $b.su | sed 's/.*://' | tr '\n' ',')" >> $o
			# No call into a C library may remain.
			u=$("${ZTL_CC%gcc}nm" -u $b.o | grep -vE ' ztl_' | tr -d '\n'); [ -z "$u" ] || { echo "undefined: $u" >> $o; s=1; }
		done ;;
	vectors) # Host build with sanitizers; the code against test vectors from the reference.
		cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -Wpedantic -Werror \
			-Iinclude -Isrc src/*.c tests/vectors_test.c -o proofs/out-vectors-test > $o 2>&1 \
			&& proofs/out-vectors-test tests/vectors/reference.txt >> $o 2>&1
		s=$?; grep -qE '^vectors: [1-9][0-9]* Poly1305, [1-9][0-9]* Salsa20/12, [1-9][0-9]* packets; [1-9][0-9]* checks, 0 failed$' $o || s=1 ;;
	mutate) # Each error is applied to a COPY of the sources (proofs/out-mut), never
		# to the sources themselves: a stopped run cannot leave a changed file.
		: > $o; s=0; M=proofs/out-mut
		while IFS='|' read -r file tools name expr; do
			[ -n "$file" ] || continue
			rm -rf $M; mkdir -p $M/proofs
			cp -r include src tests $M/ && cp proofs/*.c proofs/run.sh $M/proofs/
			sed -i "$expr" $M/$file
			# WP proves each unit alone, so only the changed unit can notice the error.
			if cmp -s $file $M/$file; then echo "NOT APPLIED: $name" >> $o; s=1
			elif ZTL_WP_UNITS=$file $M/proofs/run.sh $tools > /dev/null 2>&1; then echo "SURVIVED ($tools): $name" >> $o; s=1
			else echo "rejected ($tools): $name" >> $o; fi
		done <<'MUT'
src/wire.c|cbmc cover wp|head accepted one byte too short|s/if (len < ZTL_PKT_MIN) {/if (len < ZTL_PKT_MIN - 1u) {/
src/wire.c|cbmc cover wp|packet id halves in the wrong order|s/return UINT64_C(4294967296) \* be32(p) + be32(p + 4);/return UINT64_C(4294967296) * be32(p + 4) + be32(p);/
src/wire.c|cbmc cover wp|packet id bytes in the wrong order|s/return 16777216u \* p\[0\] + 65536u \* p\[1\] + 256u \* p\[2\] + p\[3\];/return 16777216u * p[3] + 65536u * p[2] + 256u * p[1] + p[0];/
src/wire.c|cbmc cover wp|always drop|s/if (len < ZTL_FRAG_MIN || len > ZTL_PKT_MAX) {/if (1) {/
src/wire.c|cbmc cover wp|record written, then drop|s/out->src = NULL;/out->src = NULL; if (len == 100u) { return ZTL_DROP; }/
src/wire.c|cbmc cover wp|payload pointer one byte too far|s/out->payload = buf + ZTL_PKT_IDX_VERB;/out->payload = buf + ZTL_PKT_IDX_VERB + 1u;/
src/wire.c|cbmc cover wp|empty fragment accepted|s/if (len < ZTL_FRAG_MIN || len > ZTL_PKT_MAX) {/if (len < ZTL_FRAG_HDR || len > ZTL_PKT_MAX) {/
src/wire.c|cbmc cover wp|extended armor accepted|s/if ((flags \& ZTL_FLAG_EXT_ARMOR_MASK) == ZTL_FLAG_BIT7) {/if (0) {/
src/wire.c|cbmc cover wp|suite 1 with old encrypted flag refused|s/if ((flags \& ZTL_FLAG_EXT_ARMOR_MASK) == ZTL_FLAG_BIT7) {/if ((flags \& ZTL_FLAG_BIT7) != 0u) {/
src/wire.c|cbmc cover wp|suite 3 accepted|s/if ((flags \& ZTL_FLAG_CIPHER_HIGH) != 0u) {/if ((flags \& 0x20u) != 0u) {/
src/reasm.c|wp|reassembly: total may exceed the limit by one|s/if (len + f > ZTL_PKT_MAX) {/if (len + f > ZTL_PKT_MAX + 1u) {/
src/reasm.c|wp|reassembly: payload moved from the wrong place|s/ztl_move_down(s->buf, len, ZTL_PKT_MAX - f, f);/ztl_move_down(s->buf, len, ZTL_PKT_MAX - f - 1u, f);/
src/reasm.c|wp|reassembly: last head byte not copied|s/ztl_copy_bytes(s->buf, head, len);/ztl_copy_bytes(s->buf, head, len - 1u);/
src/reasm.c|wp|reassembly: fragment stored one byte too far|s/ztl_copy_bytes(\&s->buf\[h\], payload, n);/ztl_copy_bytes(\&s->buf[h + 1u], payload, n);/
src/reasm.c|wp|reassembly: copy loop stops one byte early|0,/for (size_t i = 0; i < n; i++) {/s//for (size_t i = 0; i + 1u < n; i++) {/
src/reasm.c|wp|reassembly: slot kept after a join|s/s->have = 0; \/\* complete; the bytes stay valid until the slot is used again \*\//s->have = ZTL_SLOT_HEAD;/
src/reasm.c|wp|reassembly: validity check accepts a zero-length fragment|s/return s->frag_len >= 1u \&\& s->frag_len <= ZTL_FRAG_PAYLOAD_MAX;/return s->frag_len <= ZTL_FRAG_PAYLOAD_MAX;/
src/rx.c|wp|gate: unencrypted packet of any verb goes to the primitive|0,/if ((pkt\[ZTL_PKT_IDX_VERB\] \& ZTL_VERB_MASK) != ZTL_VERB_HELLO) {/s//if (0) {/
src/rx.c|wp|gate: delivery although the primitive said no|s/if (!ztl_auth_open(n->peer\[p\].key, pkt, plen, encrypted)) {/(void)ztl_auth_open(n->peer[p].key, pkt, plen, encrypted); if (0) {/
src/rx.c|wp|gate: key of another peer|s/if (!ztl_auth_open(n->peer\[p\].key, pkt, plen, encrypted)) {/if (!ztl_auth_open(n->peer[0].key, pkt, plen, encrypted)) {/
src/rx.c|wp|gate: address rule not applied to the complete packet|s/if (!addr_eq(\&pkt\[ZTL_PKT_IDX_DEST\], n->self) || addr_eq(\&pkt\[ZTL_PKT_IDX_SRC\], n->self)) {/if (0) {/
src/rx.c|wp|gate: peer that is not pinned accepted|s/if (n->peer\[i\].pinned \&\& addr_eq(n->peer\[i\].addr, addr)) {/if (addr_eq(n->peer[i].addr, addr)) {/
src/rx.c|wp|gate: two counters grow for one refusal|s/count(\&n->rx.bad_auth);/count(\&n->rx.bad_auth); count(\&n->rx.no_peer);/
src/rx.c|wp|gate: address compare ignores the last byte|s/for (unsigned int i = 0; i < ZTL_ADDR_LEN; i++) {\n\t\tif (a/X/;0,/for (unsigned int i = 0; i < ZTL_ADDR_LEN; i++) {/s//for (unsigned int i = 0; i + 1u < ZTL_ADDR_LEN; i++) {/
src/salsa.c|vectors|salsa: five double rounds|s/#define ZTL_SALSA_DOUBLE_ROUNDS 6u/#define ZTL_SALSA_DOUBLE_ROUNDS 5u/
src/salsa.c|vectors|salsa: one rotation by 9 instead of 7|s/x\[b\] ^= ROTL7(t);/x[b] ^= ROTL9(t);/
src/salsa.c|vectors|salsa: block number not used|s/in\[8\] = block;/in[8] = 0;/
src/salsa.c|vectors|salsa: payload key stream starts at block 0 (the block of the MAC key)|s/ztl_salsa2012_block(ks, key, iv, (uint32_t)(b + 1u));/ztl_salsa2012_block(ks, key, iv, (uint32_t)b);/
src/salsa.c|wp|salsa: XOR runs one byte past the buffer|s/for (size_t i = 0; i < take; i++) {/for (size_t i = 0; i <= take; i++) {/
src/poly.c|wp|poly: one folded product without the factor 5|s/s3 = r3 \* 5u, s4 = r4 \* 5u;/s3 = r3 * 5u, s4 = r4 * 4u;/
src/poly.c|vectors|poly: one folded product without the factor 5|s/s3 = r3 \* 5u, s4 = r4 \* 5u;/s3 = r3 * 5u, s4 = r4 * 4u;/
src/poly.c|wp|poly: last carry comes back without the factor 5|s/const uint64_t t = d0 % P26 + (e4 \/ P26) \* 5u;/const uint64_t t = d0 % P26 + (e4 \/ P26);/
src/poly.c|vectors|poly: last carry comes back without the factor 5|s/const uint64_t t = d0 % P26 + (e4 \/ P26) \* 5u;/const uint64_t t = d0 % P26 + (e4 \/ P26);/
src/poly.c|wp|poly: no final reduction when h >= 2^130 - 5|s/const uint32_t take_j = j4 \/ P26; \/\* 0 or 1 \*\//const uint32_t take_j = 0u * (j4 \/ P26);/
src/poly.c|vectors|poly: no final reduction when h >= 2^130 - 5|s/const uint32_t take_j = j4 \/ P26; \/\* 0 or 1 \*\//const uint32_t take_j = 0u * (j4 \/ P26);/
src/poly.c|wp|poly: limb 2 taken from the wrong bits|s/l\[2\] = t1 \/ 1048576u + (t2 % 16384u) \* 4096u;/l[2] = t1 \/ 1048576u + (t2 % 16384u) * 2048u;/
src/poly.c|wp|poly: a sum that can leave 32 bits|s/	h\[4\] += m\[4\];/	h[4] += m[4] * 64u;/
src/poly.c|vectors|poly: clamp of r forgotten on one word|s/const uint32_t t1 = ztl_le32(&key\[4\]) % 268435456u \/ 4u \* 4u;/const uint32_t t1 = ztl_le32(\&key[4]);/
src/poly.c|vectors|poly: the 1 after a full block is missing|s/poly_load(b, &m\[16u \* i\], 16777216u);/poly_load(b, \&m[16u * i], 0u);/
src/poly.c|vectors|poly: the 1 after the last short block is missing|s/last\[j\] = (j < rest) ? m\[16u \* full + j\] : ((j == rest) ? 1u : 0u);/last[j] = (j < rest) ? m[16u * full + j] : 0u;/
src/auth.c|vectors|auth: only 7 of the 8 MAC bytes compared|s/const int ok = ztl_ct_eq(tag, &pkt\[ZTL_PKT_IDX_MAC\], ZTL_MAC_LEN);/const int ok = ztl_ct_eq(tag, \&pkt[ZTL_PKT_IDX_MAC], ZTL_MAC_LEN - 1u);/
src/auth.c|wp|auth: compare ignores the last byte|0,/for (size_t i = 0; i < n; i++) {/s//for (size_t i = 0; i + 1u < n; i++) {/
src/auth.c|vectors|auth: compare ignores the last byte|0,/for (size_t i = 0; i < n; i++) {/s//for (size_t i = 0; i + 1u < n; i++) {/
src/auth.c|wp|auth: decryption although the MAC is wrong|s/if (ok && decrypt) {/if (decrypt) {/
src/auth.c|vectors|auth: decryption although the MAC is wrong|s/if (ok && decrypt) {/if (decrypt) {/
src/auth.c|vectors|auth: hop count mixed into the key|s/out\[18\] = key\[18\] ^ (pkt\[ZTL_PKT_IDX_FLAGS\] & ZTL_FLAGS_KEY_MASK);/out[18] = key[18] ^ pkt[ZTL_PKT_IDX_FLAGS];/
src/auth.c|vectors|auth: packet length not mixed into the key|s/out\[19\] = key\[19\] ^ (uint8_t)(len % 256u);/out[19] = key[19];/
src/auth.c|wp|auth: seal leaves suite bits of the caller in the flags|s/(pkt\[ZTL_PKT_IDX_FLAGS\] & ZTL_FLAGS_SEAL_KEEP) |/(pkt[ZTL_PKT_IDX_FLAGS] \& 0xf7u) |/
src/auth.c|vectors|auth: seal leaves suite bits of the caller in the flags|s/(pkt\[ZTL_PKT_IDX_FLAGS\] & ZTL_FLAGS_SEAL_KEEP) |/(pkt[ZTL_PKT_IDX_FLAGS] \& 0xf7u) |/
MUT
		rm -rf $M ;;
	*) echo "unknown tool $t"; exit 2 ;;
	esac
	[ $s -ne 0 ] && rc=1
	echo "== $t $([ $s -eq 0 ] && echo PASS || echo FAIL): $(grep -E 'VERIFICATION|failed|covered|Proved goals|alarms? generated|unknown +[0-9]+ invalid|Timeout|Failed|bytes:|rejected|SURVIVED|NOT APPLIED|rror' $o | tr -s ' ' | tr '\n' ';')"
done
exit $rc
