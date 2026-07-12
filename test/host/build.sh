#!/usr/bin/env bash
# Regenerates the ground-truth vectors from the real `rns` package, builds
# the host-native protocol/crypto test binary, and runs it.
#
# Requires: python3 with `pip install rns==1.3.7`, and a C++17 compiler.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(cd ../.. && pwd)"

PYTHON="${PYTHON:-python3}"
"$PYTHON" "$ROOT/test/vectors/make_vectors.py" --header vectors_generated.h > vectors.json

CXX="${CXX:-g++}"
"$CXX" -std=c++17 -Wall -Wextra -DRNSC_HOST_TEST=1 \
    -I . \
    -I "$ROOT/lib/Reticulum/src" \
    -I "$ROOT/lib/Monocypher" \
    -I "$ROOT/lib/TinyAES" \
    -I "$ROOT/lib/cmp" \
    test_main.cpp \
    "$ROOT/lib/Monocypher/monocypher.c" \
    "$ROOT/lib/Monocypher/monocypher-ed25519.c" \
    "$ROOT/lib/Reticulum/src/sha256.cpp" \
    "$ROOT/lib/TinyAES/aes.c" \
    "$ROOT/lib/cmp/cmp.c" \
    -o rnsc_host_tests

./rnsc_host_tests

# Separate compile/smoke check for RetiLXMF.h -- needs the filesystem mock
# (FsShim.h), which is deliberately kept out of the main vector-driven binary
# above (see test/README.md).
"$CXX" -std=c++17 -Wall -Wextra -DRNSC_HOST_TEST=1 \
    -I . \
    -I "$ROOT/lib/Reticulum/src" \
    -I "$ROOT/lib/Monocypher" \
    -I "$ROOT/lib/TinyAES" \
    -I "$ROOT/lib/cmp" \
    test_lxmf_compile.cpp \
    "$ROOT/lib/Monocypher/monocypher.c" \
    "$ROOT/lib/Monocypher/monocypher-ed25519.c" \
    "$ROOT/lib/Reticulum/src/sha256.cpp" \
    "$ROOT/lib/TinyAES/aes.c" \
    "$ROOT/lib/cmp/cmp.c" \
    -o rnsc_lxmf_compile_test

./rnsc_lxmf_compile_test
