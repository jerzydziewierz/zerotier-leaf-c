#!/usr/bin/env bash
# Build the host test endpoint (with sanitizers) and the provisioning tool.
# Usage: tests/host/build.sh <ZeroTier One source tree> <output directory>
set -eu
cd "$(dirname "$0")/../.."
ZT=${1:?ZeroTier One source tree}; OUT=${2:?output directory}
mkdir -p "$OUT"
cc -std=c11 -D_GNU_SOURCE -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -Wpedantic -Werror \
	-Iinclude -Isrc src/*.c tests/host/leaf_node.c -o "$OUT/leaf_node"
[ -x "$OUT/ztl_provision" ] && [ "$OUT/ztl_provision" -nt tools/provision/ztl_provision.cpp ] || tools/provision/build.sh "$ZT" "$OUT/ztl_provision"
