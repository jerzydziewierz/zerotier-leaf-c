#!/usr/bin/env bash
# Run proofs/run.sh on another host. No prover runs on the workstation.
# The whole run is one systemd unit ("ztl-run") with a memory and a time
# limit; it keeps running if this terminal or the ssh link goes away.
# Usage: proofs/on-remote.sh start [run.sh arguments...]   copy sources, start
#        proofs/on-remote.sh status | stop | fetch | wait
#   ZTL_REMOTE  ssh target (default prover-host): needs passwordless sudo, cbmc, the
#               opam switch "ztl" (proofs/opam-setup.sh) and the ARM toolchain
#               in ~/ztl-sdk/arm-zephyr-eabi
#   ZTL_MEM     memory limit for the run (default 20G)
#   ZTL_TIME    time limit in seconds (default 7200)
#   ZTL_WP_UNITS  one source file: the wp steps prove only this unit (quick
#               repeat while a proof is written; a full run needs it unset)
#   ZTL_TAG     suffix for the remote directory and unit, to run a second
#               copy beside a long run (for example ZTL_TAG=-b)
# "fetch" copies proofs/out-* back; "wait" polls until the unit ends, then fetches.
set -u
cd "$(dirname "$0")/.."
H=${ZTL_REMOTE:-prover-host}; MEM=${ZTL_MEM:-20G}; TMO=${ZTL_TIME:-7200}; D=ztl${ZTL_TAG:-}; U=ztl-run${ZTL_TAG:-}
# Run a command on the remote host; the exit status is that of ssh (grep
# alone would report failure whenever the command prints nothing).
r() { ssh -o BatchMode=yes "$H" "$@" 2>&1 | { grep -v '^Pseudo-terminal' || true; }; return "${PIPESTATUS[0]}"; }
cmd=${1:-status}; shift || true
case "$cmd" in
start)
	rsync -a --delete --exclude '.git' --exclude 'proofs/out-*' --exclude '.frama-c' ./ "$H:$D/" || exit 1
	r "cd $D && rm -f proofs/out-*; sudo systemctl reset-failed $U 2>/dev/null; sudo systemd-run --quiet --unit=$U \
		-p User=\$(id -un) -p WorkingDirectory=\$PWD -p MemoryMax=$MEM -p MemorySwapMax=0 -p RuntimeMaxSec=$TMO \
		-p StandardOutput=truncate:\$PWD/proofs/out-run.txt -p StandardError=inherit \
		-E HOME=\$HOME -E PATH=\$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin -E ZTL_ON_REMOTE=1 ${ZTL_WP_UNITS:+-E ZTL_WP_UNITS=$ZTL_WP_UNITS} \
		-E ZTL_CC=\$HOME/ztl-sdk/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc \
		proofs/run.sh $*" && echo "started $U on $H (limit $MEM, $TMO s): run.sh $*" ;;
status) r "systemctl show $U -p ActiveState -p Result -p MemoryPeak --value | tr '\n' ' '; echo; cat $D/proofs/out-run.txt 2>/dev/null | cut -c1-220" ;;
stop) r "sudo systemctl stop $U; echo stopped $U" ;;
fetch) rsync -a "$H:$D/proofs/out-*" proofs/ && cut -c1-220 proofs/out-run.txt ;;
wait)
	while :; do
		st=$(r "systemctl show $U -p ActiveState --value")
		case "$st" in active|activating|deactivating) sleep 15 ;; *) break ;; esac
	done
	rsync -a "$H:$D/proofs/out-*" proofs/; cut -c1-220 proofs/out-run.txt
	[ "$(r "systemctl show $U -p Result --value")" = success ] ;;
*) sed -n '2,14p' "$0"; exit 2 ;;
esac
