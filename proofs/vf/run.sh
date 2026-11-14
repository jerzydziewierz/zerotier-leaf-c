#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AllRightsReserved
# Check the VeriFast model of the lock discipline of the Zephyr adapter.
# The good model must verify. Each variant must fail, with the expected
# message of VeriFast, in the expected function. Each case runs with both
# provers of VeriFast. Exit status 0 only if every case is as expected.
#
# Run this on a host that has VeriFast (proof tools do not run on the
# workstation: copy this directory to the host and run it there).
# Usage: ./run.sh
set -u
cd "$(dirname "$0")" || exit 2
if ! command -v verifast >/dev/null 2>&1; then
	echo "run.sh: verifast not found in PATH; run this on a host that has VeriFast" >&2
	exit 2
fi
verifast -help 2>&1 | head -n 1

MODEL=ztl_zephyr_model.c
TARGET=ILP32 # the board is a 32-bit target
bad=0
trap 'echo "run.sh: stopped" >&2; exit 130' INT TERM

# case NAME EXPECT FUNCTION MESSAGE
#   NAME      "good" or the macro of a variant
#   EXPECT    pass | fail
#   FUNCTION  for fail: the function in which VeriFast must stop
#   MESSAGE   for fail: text that the first error line must hold
run_case() {
	local name=$1 expect=$2 fn=$3 msg=$4 prover out status t0 t1 verdict
	local -a flags=(-c -target "$TARGET")
	[ "$name" != good ] && flags+=(-D "$name")
	for prover in redux z3v4.5; do
		t0=$(date +%s.%N)
		out=$(verifast "${flags[@]}" -prover "$prover" "$MODEL" 2>&1)
		status=$?
		t1=$(date +%s.%N)
		verdict=UNEXPECTED
		if [ "$expect" = pass ]; then
			if [ $status -eq 0 ] && grep -Eq '^0 errors found \([1-9][0-9]* statements verified\)' <<<"$out"; then
				verdict=ok
			fi
		elif [ $status -ne 0 ] && grep -m1 'error:' <<<"$out" | grep -Fq "$msg" &&
			grep -Fq "Verifying function '$fn'" <<<"$out"; then
			verdict=ok
		fi
		[ $verdict = ok ] || bad=1
		printf '%-10s %-22s %-7s expect %-4s  %s  (%.2f s)\n' "$verdict" "$name" "$prover" "$expect" \
			"$(grep -m1 -E 'error:|errors found' <<<"$out" | sed -E 's/^.*error: //' | cut -c1-90)" \
			"$(echo "$t1 - $t0" | bc)"
	done
}

run_case good                pass - -
# Deliberate errors.
run_case VF_BAD_NO_LOCK      fail ztl_dev_send     'No matching heap chunks: ztl_leaf_core(leaf)'
run_case VF_BAD_STACK_LOCKED fail worker           'No matching heap chunks: k_mutex_not_held('
run_case VF_BAD_EARLY_RETURN fail ztl_dev_send     'No matching heap chunks: [q]k_mutex(lock, leaf_inv)'
run_case VF_BAD_LOOP_KEEPS   fail worker           'k_mutex(lock, leaf_inv)'
run_case VF_BAD_RX_BUF       fail ztl_dev_send     'No matching heap chunks: integer__(rx_buf'
run_case VF_BAD_START_LOCKED fail ztl_zephyr_start 'No matching heap chunks: k_mutex_not_held('
run_case VF_BAD_SOCK_UNLOCKED fail ztl_zephyr_start 'Writing to a global variable requires full permission.'
run_case VF_BAD_WRITE_ENDPOINT fail worker         'Assignment requires full permission.'
run_case VF_BAD_WRITE_PINNED fail ztl_dev_send     'Assignment requires full permission.'
# The one accepted exception (zsock_sendto() under the lock) against the strict
# rule: the real order of calls, not a deliberate error.
run_case VF_STRICT_SEND      fail worker           'No matching heap chunks: k_mutex_not_held('

if [ $bad -eq 0 ]; then
	echo "run.sh: all cases as expected"
	exit 0
fi
echo "run.sh: at least one case is NOT as expected" >&2
exit 1
