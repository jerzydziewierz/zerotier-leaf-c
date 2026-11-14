#!/usr/bin/env bash
# Run the memory-heavy CBMC harnesses on another host, each as a transient
# systemd unit with a memory limit and a time limit, so that a run that grows
# too large stops alone.
# Usage: proofs/remote.sh start|status|stop|fetch [harness...]
#   ZTL_REMOTE_BIG  ssh target of a host with much memory, from .env (no default; without it
#                ZTL_REMOTE is used); needs passwordless sudo, cbmc
#   ZTL_MEM      memory limit per harness (default 96G)
#   ZTL_TIME     time limit per harness in seconds (default 14400)
#   ZTL_DEFS     extra compiler definitions, for example -DZTL_PKT_MAX=256u
#   ZTL_XARGS    extra cbmc options, for example "--sat-solver cadical" or "--z3"
#   ZTL_TAG      suffix for unit and result names, to run variants side by side
# Harnesses (default: the first five): H_STEP H_ORDER H_DUP H_TIMEOUT (proofs/reasm_cbmc.c),
#   H_GATE (proofs/rx_cbmc.c), H_SALSA H_POLY H_POLY_STEP H_ROUNDTRIP (proofs/crypto_cbmc.c;
#   set ZTL_UNWIND_ALL=65, and for H_ROUNDTRIP a small packet size in ZTL_DEFS).
#   ZTL_COVER=1 runs reachability targets instead of checks.
# Results: proofs/out-remote-<harness>.txt after "fetch".
set -u
cd "$(dirname "$0")/.."
# The ssh target comes from the file .env beside this repository's README (not in Git;
# see .env.example), so that no host name is in the sources and none is a machine-wide
# setting. A value on the command line (ZTL_REMOTE=... proofs/remote.sh ...) wins for one call.
envget() { [ -f .env ] && sed -n "s/^$1=//p" .env | tail -n 1; }
H=${ZTL_REMOTE_BIG:-$(envget ZTL_REMOTE_BIG)}; H=${H:-${ZTL_REMOTE:-$(envget ZTL_REMOTE)}}
[ -n "$H" ] || { echo "remote.sh: set ZTL_REMOTE_BIG=<ssh target> in .env (see .env.example)"; exit 2; }
MEM=${ZTL_MEM:-96G}; TMO=${ZTL_TIME:-14400}; DEFS=${ZTL_DEFS:-}
D=ztl-proofs
cmd=${1:-status}; shift || true
hs=("$@"); [ ${#hs[@]} -eq 0 ] && hs=(H_STEP H_ORDER H_DUP H_TIMEOUT H_GATE)
# crypto_cbmc.c includes src/poly.c (it needs its static functions).
srcs() { case $1 in H_GATE) echo "src/wire.c src/reasm.c src/rx.c proofs/rx_cbmc.c" ;;
	H_SALSA|H_POLY|H_POLY_STEP|H_ROUNDTRIP) echo "src/salsa.c src/auth.c src/reasm.c proofs/crypto_cbmc.c" ;;
	*) echo "src/wire.c src/reasm.c proofs/reasm_cbmc.c" ;; esac; }
TAG=${ZTL_TAG:-}; XARGS=${ZTL_XARGS:-}
unit() { echo "ztl-$(echo "$1" | tr 'A-Z_' 'a-z-')$TAG"; }
# ZTL_UNWIND: loop bound for the copy loop = packet size + 1 (default 2049)
CHECKS="--bounds-check --pointer-check --pointer-overflow-check --signed-overflow-check --unsigned-overflow-check --conversion-check --undefined-shift-check --div-by-zero-check --unwind ${ZTL_UNWIND_ALL:-33} --unwindset ztl_copy_bytes.0:${ZTL_UNWIND:-2049},ztl_move_down.0:${ZTL_UNWIND:-2049} --unwinding-assertions"
[ -n "${ZTL_COVER:-}" ] && { CHECKS="--unwind 33 --unwindset ztl_copy_bytes.0:${ZTL_UNWIND:-2049},ztl_move_down.0:${ZTL_UNWIND:-2049} --cover cover"; DEFS="$DEFS -DH_COVER"; }
case "$cmd" in
start)
	rsync -a --delete --exclude 'out-*' include src proofs "$H:$D/" || exit 1
	for h in "${hs[@]}"; do
		u=$(unit "$h")
		ssh "$H" "cd $D && sudo systemctl reset-failed $u 2>/dev/null; sudo systemd-run --quiet --unit=$u \
			-p User=\$(id -un) -p WorkingDirectory=\$PWD -p MemoryMax=$MEM -p MemorySwapMax=0 \
			-p RuntimeMaxSec=$TMO -p StandardOutput=truncate:\$PWD/out-$h$TAG.txt -p StandardError=inherit \
			cbmc -D$h $DEFS -Iinclude -Isrc $(srcs $h) $CHECKS $XARGS" \
			&& echo "started $u on $H (limit $MEM, $TMO s)"
	done ;;
status)
	for h in "${hs[@]}"; do
		u=$(unit "$h")
		ssh "$H" "printf '%-14s ' $u; systemctl show $u -p ActiveState -p Result -p MemoryPeak --value 2>/dev/null | tr '\n' ' '; echo; tail -n 2 $D/out-$h$TAG.txt 2>/dev/null"
	done ;;
stop)
	for h in "${hs[@]}"; do ssh "$H" "sudo systemctl stop $(unit "$h") 2>/dev/null; echo stopped $(unit "$h")"; done ;;
fetch)
	for h in "${hs[@]}"; do
		scp -q "$H:$D/out-$h$TAG.txt" "proofs/out-remote-$h$TAG.txt" 2>/dev/null
		echo "== $h: $(grep -E '^VERIFICATION|^\*\* .*(failed|covered)' "proofs/out-remote-$h$TAG.txt" 2>/dev/null | tr '\n' ' ')"
	done ;;
*) sed -n '2,12p' "$0"; exit 2 ;;
esac
