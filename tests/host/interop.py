#!/usr/bin/env python3
"""The C leaf against the reference node on loopback UDP, with throw-away identities.

usage: interop.py <dir with leaf_node and ztl_provision> <reference_node> [--mode normal|deny|tamper]
       [--seconds N] [--frame-size 69|1280|1500]

The reference node is the reference core (version 13, with AES) with a test
controller: ../grey_zerotier/tests/host_node.cpp built as "reference_node".
normal: both sides must get frames and ARP requests of the other (exit 0 each).
deny: the controller refuses the leaf. tamper: each side changes one bit of
every datagram it sends. In both, no frame may be delivered on either side.
"""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("leaf_dir", type=Path)
    parser.add_argument("reference_node", type=Path)
    parser.add_argument("--mode", choices=("normal", "deny", "tamper"), default="normal")
    parser.add_argument("--seconds", type=int, default=6)
    parser.add_argument("--frame-size", type=int, choices=(69, 1280, 1500), default=69)
    args = parser.parse_args()
    leaf_dir = args.leaf_dir.resolve()
    # Identity secrets and pairwise keys stay in a temporary directory.
    with tempfile.TemporaryDirectory(prefix="ztl-interop-") as temp:
        root = Path(temp)
        for name in ("leaf", "controller"):
            subprocess.run(["zerotier-idtool", "generate", str(root / f"{name}.secret"),
                            str(root / f"{name}.public")], check=True, capture_output=True)
            os.chmod(root / f"{name}.secret", 0o600)
        network = (root / "controller.public").read_text().split(":")[0] + "000001"
        provision = root / "leaf.provision"
        with open(os.open(provision, os.O_WRONLY | os.O_CREAT, 0o600), "w") as out:
            subprocess.run([str(leaf_dir / "ztl_provision"), str(root / "leaf.secret"),
                            str(root / "controller.public")], check=True, stdout=out)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as leaf_sock, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as controller_sock:
            leaf_sock.bind(("127.0.0.1", 0))
            controller_sock.bind(("127.0.0.1", 0))
            env = dict(os.environ, GREY_ZT_TEST_FRAME_SIZE=str(args.frame_size))
            commands = {
                "controller": ([str(args.reference_node.resolve()), str(root / "controller.secret"),
                                str(root / "controller.public"), str(root / "leaf.public"),
                                str(controller_sock.fileno()), str(leaf_sock.getsockname()[1]),
                                network, args.mode, str(args.seconds)], controller_sock),
                "leaf": ([str(leaf_dir / "leaf_node"), str(provision), str(leaf_sock.fileno()),
                          str(controller_sock.getsockname()[1]), network, args.mode, str(args.seconds)], leaf_sock),
            }
            processes = [(name, subprocess.Popen(command, env=env, pass_fds=(sock.fileno(),),
                                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
                         for name, (command, sock) in commands.items()]
            failures = []
            try:
                for name, proc in processes:
                    output, _ = proc.communicate(timeout=args.seconds + 15)
                    print(f"{name} ({args.mode}, frame {args.frame_size}): exit={proc.returncode}\n{output}", end="")
                    expected = 0 if args.mode == "normal" else 2
                    if proc.returncode != expected:
                        failures.append(f"{name}: exit {proc.returncode}, expected {expected}")
                    if "bad_frames=0" not in output or "plaintext_leaks=0" not in output:
                        failures.append(f"{name}: wrong or exposed payload")
                    if args.mode != "normal" and " frames=0 " not in output:
                        failures.append(f"{name}: frame delivered without authorization")
            finally:
                for _, proc in processes:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
            if failures:
                print("FAIL: " + "; ".join(failures))
                return 1
            print("PASS")
            return 0


if __name__ == "__main__":
    sys.exit(main())
