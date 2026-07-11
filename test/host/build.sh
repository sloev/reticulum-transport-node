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
"$CXX" -std=c++17 -Wall -Wextra \
    -I . \
    -I "$ROOT/lib/Reticulum/src" \
    -I "$ROOT/lib/Monocypher" \
    -I "$ROOT/lib/TinyAES" \
    -I "$ROOT/lib/cmp" \
    test_main.cpp \
    "$ROOT/lib/Monocypher/monocypher.c" \
    "$ROOT/lib/Monocypher/monocypher-ed25519.c" \
    -o rnsc_host_tests

./rnsc_host_tests
