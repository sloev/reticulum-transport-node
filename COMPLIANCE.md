# Compliance Ledger

What this firmware actually implements, checked against the reference
implementation, not what an earlier draft of this document claimed. Every
row marked **verified** has a corresponding host-test check in
`test/host/test_main.cpp` (or `test_lxmf_compile.cpp`) that runs against a
byte-exact vector generated from the real `rns` 1.3.7 / `lxmf` 1.0.1 Python
packages on every CI run — see `test/vectors/make_vectors.py`. Nothing here
is asserted from reading the manual alone.

Spec reference: [Reticulum Network Stack Manual](https://reticulum.network/manual/), LXMF 1.0.1 source.

---

## 1. Identity & Cryptography

| Component | RNS requirement | Implementation | Status |
|---|---|---|---|
| Identity | Paired X25519(32B) + Ed25519(32B) keys, not one key doing both jobs | `RetiIdentity.h`: 64-byte private key blob (`x25519_priv \|\| ed25519_seed`), 64-byte public key (`x25519_pub \|\| ed25519_pub`) | **verified** |
| Address / identity hash | `SHA256(public_key)[:16]` | `Identity::derive()` | **verified** |
| Signing | Ed25519 | Monocypher `crypto_ed25519_sign`/`crypto_ed25519_check` | **verified** |
| Key exchange | X25519 ECDH | Monocypher `crypto_x25519` | **verified** |
| Identity-level encryption | `RNS.Identity.encrypt/decrypt`: ephemeral X25519 → HKDF(shared, target_hash) → Token | `Identity::encryptTo`/`decrypt` | **verified** |
| Link encryption (Token) | `IV(16) \|\| AES-256-CBC ciphertext \|\| HMAC-SHA256(32)`, signing key first half of derived material, encryption key second half | `Crypto::tokenEncrypt`/`tokenDecrypt` | **verified** |
| HMAC verification | Every decrypt must reject on MAC mismatch | `tokenDecrypt` uses constant-time compare, returns empty on failure | **verified** |
| Entropy source | CSPRNG, not a seeded/deterministic PRNG | ESP32: `esp_random()` (HW RNG). nRF52840: SoftDevice `sd_rand_application_vector_get` when BLE is up, else `NRF_RNG` peripheral directly | manual review (no host-testable RNG hardware) |

## 2. Packet & Destination

| Component | RNS requirement | Implementation | Status |
|---|---|---|---|
| Header bits | flags byte incl. header type, context flag, propagation/destination type, transport type | `RetiPacket.h` | **verified** |
| HEADER_2 addressing | two 16-byte fields (`transport_id \|\| dest_hash`), not one 32-byte field | `Packet::parse` | **verified** |
| Context byte | always present after the address field(s), not conditional | `Packet::parse`/`serialize` | **verified** |
| Truncated hash / dedup key | `SHA256(hashable_part)[:16]`, `hashable_part = flags&0x0F \|\| raw[2:]` (hops excluded) | `Packet::getTruncatedHash`/`getHashablePart` | **verified** |
| Destination naming | `name_hash = SHA256("app.aspect")[:10]`, `dest_hash = SHA256(name_hash \|\| identity_hash)[:16]` | `RetiDestination.h` | **verified** |

## 3. Announce

| Component | RNS requirement | Implementation | Status |
|---|---|---|---|
| Payload shape | `pubkey(64) \|\| name_hash(10) \|\| random_hash(10) \|\| sig(64) \|\| app_data` | `RetiAnnounce.h` | **verified** |
| Signature | over `dest_hash \|\| pubkey \|\| name_hash \|\| random_hash \|\| app_data` | `Announce::build`, cross-checked against `RNS.Identity.validate_announce` | **verified** |
| Rebroadcast | jittered (200–1000ms) forward, not immediate, so neighbors that heard the same announce don't retransmit in lockstep | `Router::process`/`loop` | manual review (timing behavior, not vector-testable) |
| Ratcheted announces | optional `ratchet(32)` field between `random_hash` and `sig`, `context_flag` set when present, signed data extended to include it | `Announce::build`/`validate`, `Identity::rotateRatchets`/`latestRatchetPublic` | **verified** (both directions: parses a real RNS-signed ratcheted announce, and our own construction validates) |
| Ratchet retention/rotation | RNS retains up to 512 keys, rotates every 30 minutes, persists to a signed file | `Identity`: retains 8 (constant `RATCHET_COUNT`), same 30-minute interval, **not persisted across reboots** — see class comment in `RetiIdentity.h` | manual review; smaller retention and no persistence are deliberate embedded-resource simplifications, not wire gaps (nothing currently decrypts against this node's own identity, so there's no functional consumer yet to lose continuity for) |
| Ratchet-aware decrypt | a receiver tries retained ratchet keys before falling back to the static key | `Identity::decrypt` | **verified** (decrypts a real RNS token that was encrypted to a ratchet key, not the static key) |

## 4. Routing

| Component | RNS requirement | Implementation | Status |
|---|---|---|---|
| Dedup | on truncated hash of the hashable part (hops legitimately differ hop to hop, so raw-byte hashing would treat one logical packet arriving by two paths as two packets) | `Router::process` | **verified** |
| Hop accounting | increment on forward, drop at a sane ceiling | `Router::MAX_HOPS = 128` | manual review |

## 5. Link

Responder role only — this firmware never initiates a link. `RNS.Link`'s
initiator code path (sending a LINK_REQ, verifying LRPROOF) is not
implemented, because nothing here needs to open a link to another node.

| Component | RNS requirement | Implementation | Status |
|---|---|---|---|
| Link ID | `SHA256(hashable_part_of_LR_packet, with trailing MTU-signalling bytes past the 64B ephemeral-pubkey block stripped)[:16]` | `Link::linkIdFromRequest` | **verified** |
| Handshake | ECDH(our ephemeral X25519, peer's X25519) → HKDF(shared, salt=link_id, 64B) → signing/encryption key split | `Link::accept` | **verified** |
| LRPROOF | `sig(link_id \|\| x_pub \|\| owner_ed25519_pub \|\| signalling) \|\| x_pub \|\| signalling`, signed with the node's real (static) identity key, not an ephemeral one | `Link::buildProof` | **verified** |
| Signalling bytes | 3 bytes: top 3 bits of byte 0 = mode, remaining 21 bits = MTU | `Link::signallingBytes` | **verified** |
| Link mode | AES-256-CBC (`MODE_AES256_CBC`) — the RNS default | `LINK_MODE_AES256_CBC` | **verified** |
| LINKIDENTIFY | `pubkey(64) \|\| sig(link_id \|\| pubkey)`, Ed25519-verified against the announced-or-claimed pubkey | `Link::handleIdentify` | **verified** |
| LINKCLOSE | sets link to closed, torn down on next `Router`/`LXMFPropagationNode::loop()` pass | `Link::handleClose` | manual review |
| Keepalive / staleness | inbound traffic refreshes `lastInbound`; link considered stale after 300s idle | `Link::touch`/`isStale` | manual review |
| Packet-delivery proof | `full_hash(packet's hashable part, 32B) \|\| sig`, signed with the link owner's static identity key, unencrypted, PROOF type addressed to the link — what a sender's `PacketReceipt` waits on before marking a link-delivered packet (e.g. a propagation upload) as delivered instead of timing out | `Link::buildPacketProof` | **verified** (structure and self-consistency checked in `test_lxmf_compile.cpp`, not against a live RNS receipt) |

## 6. Request / Response

| Component | RNS requirement | Implementation | Status |
|---|---|---|---|
| Request envelope | encrypted msgpack `[timestamp, path_hash(16), data]` | `RetiRequest.h` | **verified** |
| Response envelope | `[request_id, response]`, `request_id = truncated_hash(request_packet)` | `Request::handleRequest` | **verified** |
| Oversized response | if the envelope exceeds one packet's SDU, hand off to a Resource instead of dropping it | `RequestResult::needsResource` path | manual review |

## 7. Resource

Both directions now. Send side is used for oversized Request/Response
replies; receive side is used for large LXMF propagation uploads and the
follow-up transfer after a successful `/offer` (see section 8).

Receive-side scope, stated plainly: single-segment (`i=1, l=1`) and
single-hashmap-page transfers only — up to `HASHMAP_MAX_LEN` parts (~74
with RNS's default link MDU, ~34KB) in one advertisement, with no support
for `HASHMAP_IS_EXHAUSTED`/HMU pagination to request further hashmap pages
for bigger transfers, and no multi-segment support. LXMF only sends a
message as a single link packet at all if its content fits in 319 bytes
(`LXMessage.LINK_PACKET_MAX_CONTENT`); anything longer goes through
Resource, so this scope boundary is the practical ceiling on how large an
uploaded message (or attachment) can be before this node can't accept it.
An out-of-scope advertisement is rejected outright (`acceptAdvertisement`
returns `nullptr`) rather than mishandled — the sender's own advertisement
retry/timeout logic takes over, the transfer just never completes.

| Component | RNS requirement | Implementation | Status |
|---|---|---|---|
| Payload encryption | the *whole* payload (`random_hash \|\| data`) is Token-encrypted once; the resulting stream is sliced into raw SDU-sized chunks, not re-encrypted per chunk | `Resource::create`/`assemble` | **verified** both directions (send: cross-checked against a live RNS Resource capture and `attermann/microReticulum`'s `Resource.cpp`; receive: round-trips through a real `RNS.ResourceAdvertisement.pack()` blob and our own send-side output) |
| Hash orderings | `hash = full_hash(data \|\| random_hash)`; `map_hash = full_hash(chunk \|\| random_hash)[:4]` — data and random_hash swap order between the two | `Resource::create`/`mapHash`/`receivePart` | **verified** |
| Advertisement | msgpack map, keys `t,d,n,h,r,o,i,l,q,f,m`, single-segment only (`i=1, l=1`) | `Resource::buildAdvertisement`/`acceptAdvertisement` | **verified** both directions, receive side against a real `RNS.ResourceAdvertisement.pack()` blob |
| Part retransmission (send side) | `RESOURCE_REQ` → matching wanted map-hashes → resend those parts | `Resource::handleRequest` | manual review |
| Part request (receive side) | requests every part of a single-page transfer in one `RESOURCE_REQ` — valid since RNS's sender fulfills an explicit request in full regardless of its own window, which only throttles *unprompted* pushes | `Resource::buildRequestForAllParts` | **verified** (round-trips against `Resource::handleRequest`, matching RNS's `Resource.request()` fulfillment behavior read from source) |
| Receive completion / proof | `RESOURCE_PRF`: `hash(32) \|\| full_hash(data\|\|hash)(32)`, unencrypted, sent once all parts assembled and the advertised hash verifies | `Resource::assemble`/`buildReceiveProof` | **verified** against real RNS-computed hash values |
| Compression | not implemented (send or receive) — encrypted LXMF payloads don't compress, so RNS senders' `auto_compress` never actually sticks for this data (`if compressed_size < uncompressed_size`, which encrypted/high-entropy data essentially never satisfies) — verified by reading `RNS.Resource.__init__`'s compression logic, not by testing a real compressed transfer; a compressed advertisement (flag `c` set) is rejected on receive rather than silently mishandled | n/a | **intentional gap**, documented |
| Segmented resources / HMU hashmap pagination | multi-segment transfer, and requesting further hashmap pages for a single segment with more parts than fit in one advertisement | not implemented — see scope note above | **gap** |

## 8. LXMF Propagation Node

| Component | RNS requirement | Implementation | Status |
|---|---|---|---|
| Destination | `lxmf.propagation` name hash, `dest_hash = SHA256(name_hash \|\| identity_hash)[:16]` | `LXMFPropagationNode` constructor | **verified** |
| Announce app_data | `[legacy_pn, timebase, hosting, per_transfer_kb, per_sync_kb, [stamp_cost×3], metadata]`, the shape Sideband/NomadNet check before treating an announce as a real PN | `buildAnnounceAppData` | manual review (shape matches `LXMRouter.get_propagation_node_app_data`; no RTC on-device so `timebase` is uptime, not wall clock) |
| Upload transport | a client sends `msgpack([timestamp, [lxmf_data, ...]])` as a plain (context NONE) Link-encrypted DATA packet over an established Link to the propagation destination — *not* a bare packet addressed to the destination hash — matching `LXMessage.__as_packet()`/`LXMRouter.propagation_packet` for method=PROPAGATED, representation=PACKET | `handlePropagationUpload` (dispatched from `handleLinkPacket` on context NONE) | **verified** (structure checked against LXMF source and driven end-to-end in `test_lxmf_compile.cpp` using a real link) |
| Upload acknowledgement | reply with a packet-delivery proof so the sender's `PacketReceipt` resolves instead of timing out and retrying | `Link::buildPacketProof`, sent from `handlePropagationUpload` | **verified** |
| Inbound caching | each `lxmf_data` entry (`dest_hash(16) \|\| Identity.encrypt()'d-to-the-recipient bytes` — already end-to-end encrypted to whoever the message is for, never decrypted by this node) stored keyed by `SHA256(lxmf_data)` (full 32-byte hash, no truncation), destination hash read from the first 16 bytes | `cacheIncomingMessage` | **verified** |
| `MESSAGE_GET` — list | `data=[nil, nil]` → transient IDs + sizes for the identified client's delivery hash | `handleMessageGet` | manual review |
| `MESSAGE_GET` — want/have | purge `haves`, stream `wants` within a per-call byte budget | `handleMessageGet` | manual review |
| Link identification required | an unidentified link can't be attributed to a delivery hash, so it gets nothing | `handleMessageGet` early return | **verified** |
| Storage quota | fixed cap (40 messages), oldest evicted first | `MAX_STORED_MESSAGES` | manual review |
| Large uploads | representation=RESOURCE uploads (message content over 319 bytes, e.g. with an attachment) accepted via the Resource-receive path within its documented scope (section 7) | `handleInboundResourceAdvertisement`/`handleInboundResourcePart` → `processMessageArray` (shared with the direct-packet path) | **verified** end-to-end in `test_lxmf_compile.cpp`: advertisement → request → parts (fed out of order) → cached → receive proof sent |
| `/offer` — receiving | `data=[peering_key, transient_ids]`, requires LINKIDENTIFY (else `ERROR_NO_IDENTITY`), responds `false`/`true`/an array of the transient IDs not already cached, matching `LXMPeer.offer_request`'s return contract | `handleOffer` | **verified**: unidentified-link rejection, and all three response shapes (want-none/want-all/want-some), against the exact msgpack encoding `LXMPeer.offer_response` expects |
| `/offer` — peering key validation | real peers PoW-stamp the key to meet `LXStamper.validate_peering_key`'s target cost | not checked — this node always announces `peering_cost=0`, and at cost 0 the validation target exceeds any possible 256-bit hash, making the check unconditionally true regardless of the key's contents (read from `LXStamper.stamp_valid`'s math, not tested against a real stamped key) | **intentional gap**, documented — there's nothing to check at cost 0 |
| `/offer` — follow-up transfer | the messages an offer accepted always arrive as a Resource (`LXMPeer.offer_response` never uses a plain packet), regardless of size | reuses the same Resource-receive path as a large direct upload | **verified** in `test_lxmf_compile.cpp` |
| `/offer` — sending (outbound peering) | this node proactively offering its cache to other propagation nodes it discovers | not implemented — would need to generate a valid peering key against each peer's own declared (possibly nonzero) cost, real proof-of-work this firmware doesn't implement | **gap** |
| Anti-spam stamps (`LXStamper`) | proof-of-work cost on inbound messages | not implemented — this node enforces no stamp cost and expects none | **intentional gap**, documented |
| Whitelist / access control | restrict caching to known identities | not implemented — accepts anything addressed to its propagation destination | **gap** |

---

## Why vendored crypto, not a system library

`lib/Monocypher` (X25519, Ed25519) and `lib/TinyAES` (AES-256-CBC,
compile-time configured for 256-bit keys specifically — most Arduino AES
libraries default to 128) are committed source, not registry dependencies.
Two reasons: the RNS wire format is unforgiving about exact primitive
behavior (key splits, IV placement, hash truncation points), so pinning
the actual bytes under test beats trusting a platform crypto library to
keep matching; and a vendored, single-purpose implementation is something
a reviewer can read start to finish, not a black box pulled from a
package index at build time.

## Field verification

Host-side, every push: `test/host/build.sh` regenerates ground-truth
vectors from `rns==1.3.7`/`lxmf==1.0.1`, builds two native binaries
(protocol/crypto suite, LXMF compile-and-smoke-test), and runs both.

Device-side, manually: flash either target, add it as a serial or BLE
interface to a host running `rnsd -vv` or the Sideband/NomadNet app, and
confirm an announce is received and a Link can be established. This isn't
yet automated — no physical hardware is available in this project's build
environment — so treat the host-test suite as proof of wire-format
correctness, and a manual pairing session as proof the radio/BLE/serial
transport underneath it actually carries those bytes.
