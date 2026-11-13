#!/usr/bin/env python3
"""Write the provisioning header of the Zephyr adapter for one board.

usage: ztl_header.py <board directory> <ztl_provision program>

The board directory holds identity.secret (the board's key pair) and
board.json (network, addresses, and for each peer its public identity and
UDP endpoint), as the board tool of the reference solution makes them
(grey_zerotier/tools/ztboard.py). The result is <board directory>/ztl_provision.h.

SECRET: the header holds the pairwise keys of the board. Keep it, and every
firmware image built from it, on trusted hosts. The board's own secret key is
not in the header: with this design it never leaves the provisioning host.
Nothing secret is printed.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def c_bytes(hexstr):
    return ", ".join(f"0x{hexstr[i:i + 2]}" for i in range(0, len(hexstr), 2))


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    board_dir, tool = Path(sys.argv[1]), Path(sys.argv[2])
    board = json.loads((board_dir / "board.json").read_text())
    with tempfile.TemporaryDirectory(prefix="ztl-header-") as temp:
        publics = []
        for i, peer in enumerate(board["peers"]):
            path = Path(temp) / f"peer{i}.public"
            path.write_text(peer["identity"] + "\n")
            publics.append(str(path))
        out = subprocess.run([str(tool), str(board_dir / "identity.secret"), *publics],
                             check=True, capture_output=True, text=True).stdout
    values = {"peer": []}
    for line in out.splitlines():
        kind, *rest = line.split()
        if kind == "peer":
            values["peer"].append(rest)
        else:
            values[kind] = rest[0]
    if values.get("self") != board["address"] or len(values["peer"]) != len(board["peers"]):
        sys.exit("the provisioning tool and board.json do not agree")
    lines = [
        "/* SECRET: pairwise keys of one board. Made by tools/provision/ztl_header.py; do not edit,",
        " * do not publish, and do not publish firmware built with it. */",
        "static const struct ztl_zephyr_peer ztl_provision_peers[] = {",
    ]
    for peer, (address, key) in zip(board["peers"], values["peer"]):
        if address != peer["address"]:
            sys.exit("peer order changed")
        ip = ", ".join(peer["ipv4"].split("."))
        lines.append(f"\t{{ .addr = {{ {c_bytes(address)} }}, .ipv4 = {{ {ip} }}, .port = {peer['port']}, /* {peer['host']} */")
        lines.append(f"\t  .key = {{ {c_bytes(key)} }} }},")
    lines += [
        "};",
        "static const struct ztl_zephyr_config ztl_provision = {",
        f"\t.self = {{ {c_bytes(values['self'])} }},",
        f"\t.pub = {{ {c_bytes(values['pub'])} }},",
        f"\t.nwid = {{ {c_bytes(board['network'])} }},",
        "\t.peers = ztl_provision_peers,",
        f"\t.peer_count = {len(board['peers'])},",
        f"\t.port = {board['port']},",
        "};",
        f"#define ZTL_PROVISION_UNDERLAY_IPV4 \"{board['underlay_ip']}\"",
        "",
    ]
    target = board_dir / "ztl_provision.h"
    temp_path = board_dir / "ztl_provision.h.tmp"
    with open(os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        f.write("\n".join(lines))
    os.replace(temp_path, target)
    print(f"{target}: board {board['name']} ({board['address']}), network {board['network']}, {len(board['peers'])} peers")


if __name__ == "__main__":
    main()
