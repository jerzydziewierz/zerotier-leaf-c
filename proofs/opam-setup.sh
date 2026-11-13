#!/usr/bin/env bash
# Install current Frama-C (with WP) and Alt-Ergo into the opam switch "ztl".
# Usage: proofs/opam-setup.sh start|status|stop|log
# Safe to stop and start again: opam keeps finished packages.
# System libraries are never installed from here (no sudo): a missing one
# makes the build fail and the log names it.
set -u
N=ztl-opam; PID=/tmp/$N.pid; LOG=/tmp/$N.log
alive() { [ -f "$PID" ] && kill -0 -- "-$(cat "$PID")" 2>/dev/null; }
case "${1:-status}" in
start)
	alive && { echo "already running, pgid $(cat "$PID")"; exit 0; }
	setsid bash -c "echo \$\$ > $PID; exec bash -c '
		set -e
		[ -d ~/.opam ] || opam init -y --bare --disable-shell-hook --no-setup
		opam switch list --short | grep -qx ztl || opam switch create ztl ocaml-base-compiler.4.14.2 -y
		opam install --switch ztl -y --assume-depexts frama-c alt-ergo
		echo ZTL-OPAM-DONE'" > "$LOG" 2>&1 &
	sleep 1; echo "started, pgid $(cat "$PID"), log $LOG" ;;
status)
	if alive; then echo "running, pgid $(cat "$PID")"; else echo "not running"; fi
	tail -n 3 "$LOG" 2>/dev/null ;;
stop)
	alive || { echo "not running"; exit 0; }
	g=$(cat "$PID"); kill -TERM -- "-$g"
	for _ in $(seq 20); do kill -0 -- "-$g" 2>/dev/null || break; sleep 1; done
	kill -0 -- "-$g" 2>/dev/null && kill -KILL -- "-$g"
	echo "stopped" ;;
log) tail -n 40 "$LOG" ;;
*) sed -n '2,6p' "$0"; exit 2 ;;
esac
