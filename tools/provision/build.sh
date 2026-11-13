#!/usr/bin/env bash
# Build the provisioning tool against the reference source.
# Usage: tools/provision/build.sh <ZeroTier One source tree> <output file>
set -eu
cd "$(dirname "$0")/../.."
ZT=${1:?ZeroTier One source tree}; OUT=${2:?output file}
SRC=""
for f in Identity ECC SHA512 Utils Salsa20 AES AES_aesni AES_armcrypto; do SRC="$SRC $ZT/node/$f.cpp"; done
g++ -std=c++17 -O2 -DZT_NO_PEER_METRICS -DOMIT_JSON_SUPPORT -I"$ZT/node" -I"$ZT/include" -I"$ZT/ext" \
	tools/provision/ztl_provision.cpp $SRC -o "$OUT" -lpthread
