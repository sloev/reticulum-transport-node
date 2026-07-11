# Protocol compliance tests

RNS-C's wire format, cryptography, and framing are checked against the
official `rns` Python package, not against our own assumptions about the
spec. This is the only place in the repo allowed to depend on that package.

    pip install rns==1.3.7
    ./test/host/build.sh

What this does:

1. `test/vectors/make_vectors.py` drives real `RNS.Identity`, `RNS.Destination`,
   `RNS.Packet`, `RNS.Link`, and `RNS.Cryptography` objects to produce
   ground-truth byte vectors (identity/destination hashes, a signed announce
   packet later re-validated by `RNS.Identity.validate_announce`, packet
   framing cases, HKDF/Token/X25519/Ed25519 vectors), and emits them as a
   generated C++ header.
2. `test/host/test_main.cpp` builds `lib/Reticulum`'s protocol/crypto headers
   as a native binary (`RNSC_HOST_TEST`, via `test/host/ArduinoShim.h`) and
   checks its output against those vectors byte-for-byte.

Nothing here is committed -- `build.sh` regenerates the vectors fresh against
a pinned `rns` version every run (also on CI, see `.github/workflows/main.yml`),
so they can't quietly drift from the spec version this firmware claims to
support.

Scope: this covers the protocol/crypto layer (`RetiCommon`, `RetiCrypto`,
`RetiPacket`, `RetiIdentity`, `RetiDestination`, `RetiLink`). Board-specific
code (`RetiBLE`, `RetiWiFi`, `RetiSerial`, `RetiStorage`, `RetiLoRa`,
`RetiESPNow`, `main.cpp`) has no meaningful host equivalent and stays covered
by the real device builds in CI instead.
