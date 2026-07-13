# Protocol compliance tests

RNS-C's wire format, cryptography, and framing are checked against the
official `rns` Python package, not against our own assumptions about the
spec. This is the only place in the repo allowed to depend on that package.

    pip install rns==1.3.7
    ./test/host/build.sh

What this does:

1. `test/vectors/make_vectors.py` drives real `RNS.Identity`, `RNS.Destination`,
   `RNS.Packet`, `RNS.Link`, `RNS.Resource`, and `RNS.Cryptography` objects
   (plus `RNS.Identity.encrypt`/`decrypt` with ratchets) to produce
   ground-truth byte vectors -- identity/destination hashes, signed announce
   packets (with and without a ratchet) re-validated by
   `RNS.Identity.validate_announce`, packet framing cases, HKDF/Token/
   X25519/Ed25519 vectors, and real `RNS.ResourceAdvertisement.pack()`
   output -- and emits them as a generated C++ header.
2. `test/host/test_main.cpp` builds `lib/Reticulum`'s protocol/crypto headers
   (`RetiCommon`, `RetiCrypto`, `RetiPacket`, `RetiIdentity`, `RetiDestination`,
   `RetiAnnounce`, `RetiLink`, `RetiMsgpack`, `RetiRequest`, `RetiResource`,
   `RetiInterface`) as a native binary (`RNSC_HOST_TEST`, via
   `test/host/ArduinoShim.h`) and checks its output against those vectors
   byte-for-byte.
3. `test/host/test_lxmf_compile.cpp` builds a second native binary that adds
   `RetiLXMF.h` on top, using an in-memory filesystem mock (`FsShim.h`) the
   first binary deliberately does without -- it drives full message
   cache/list/get, large-message Resource-receive, and `/offer` peer-sync
   flows through the real dispatch code with a real (if synthetic) Link.

Nothing here is committed -- `build.sh` regenerates the vectors fresh against
a pinned `rns`/`lxmf` version every run (also on CI, see
`.github/workflows/main.yml`), so they can't quietly drift from the spec
version this firmware claims to support.

Scope: this covers the protocol/crypto layer and the LXMF propagation node
logic built on it. Board-specific code (`RetiBLE`, `RetiWiFi`, `RetiSerial`,
`RetiStorage`, `RetiLoRa`, `RetiESPNow`, `main.cpp`) has no meaningful host
equivalent and stays covered by the real device builds in CI instead.
