# LXMF Propagation Node — Status

This document tracked the plan for building a propagation node into this
firmware. It's now a status report: `lib/Reticulum/src/RetiLXMF.h`
implements the sections marked **done** below; the rest is scoped out and
listed honestly rather than left implied.

For wire-format detail and what's checked against the reference
implementation, see `COMPLIANCE.md` section 8. This document covers the
on-device architecture; that one covers spec conformance.

---

## Addressing — done

Destination is `lxmf.propagation`, hashed the standard RNS way:
`name_hash = SHA256("lxmf.propagation")[:10]`,
`dest_hash = SHA256(name_hash || node_identity_hash)[:16]`. The node signs
and broadcasts an announce on boot carrying the LXMF propagation-node
`app_data` shape (`[legacy_pn, timebase, hosting, transfer_limits,
stamp_cost, metadata]`) that Sideband and NomadNet check before listing an
announce as a real PN, not just any destination.

## Inbound message handling — done

A client uploads a message over an established Link to the propagation
destination, not as a plain packet addressed to the destination hash
directly (an earlier draft of this firmware got that wrong — see the
"messages sent to a plain destination-addressed packet" note below). This
matches `LXMessage.send()`/`LXMRouter.propagation_packet`: for
method=PROPAGATED, representation=PACKET, the client sends a plain
(context NONE) Link-encrypted DATA packet on the link, whose plaintext is
`msgpack([timestamp, [lxmf_data, ...]])`. The firmware:

1. Token-decrypts the packet with the link's own key (`Link::decrypt`,
   the ordinary link encryption every packet on the link uses) and
   msgpack-unpacks the `[timestamp, messages]` envelope.
2. For each `lxmf_data` entry (already `dest_hash(16) ||
   Identity.encrypt()`'d-to-the-*recipient*'s identity — LXMF's own
   end-to-end layer, which this node never touches or decrypts):
   computes `transient_id = SHA256(lxmf_data)` (full 32 bytes, no
   truncation) and skips it if already cached.
3. Writes the raw bytes to `/lxmf/<64-hex-transient-id>.msg` and adds an
   entry to the in-RAM index (`destination_hash` = first 16 bytes of the
   payload, read back out of the filename + file header on boot so the
   index survives a reset without re-hashing every stored file).
4. Evicts the oldest entry if storage exceeds `MAX_STORED_MESSAGES` (40,
   a fixed cap — flash is small, and this isn't a general-purpose relay).
5. Replies with a generic packet-delivery proof (`Link::buildPacketProof`)
   so the sender's transfer resolves as delivered instead of timing out.

**Size limit, stated plainly:** LXMF only uses the single-packet path
above when the message content fits in 319 bytes
(`LXMessage.LINK_PACKET_MAX_CONTENT`). Anything longer — or carrying an
attachment — gets sent as a Resource upload instead. This firmware
accepts that too now (`handleInboundResourceAdvertisement`/
`handleInboundResourcePart` in `RetiLXMF.h`, built on `RetiResource.h`'s
receive-side state machine), within a documented size ceiling: single
segment, single hashmap page, roughly 34KB with RNS's default link MDU —
see `COMPLIANCE.md` section 7. Both paths funnel into the same
`processMessageArray` cache logic, so list/get/purge behave identically
regardless of how a message arrived.

## Sync protocol — done

A client opens a Link to the propagation destination, sends
LINKIDENTIFY, then issues `MESSAGE_GET` requests over Request/Response
(path `/get`), matching `LXMPeer.message_get_request` on the Python side:

- `data = [nil, nil]` → list mode: return `[transient_id, size]` for
  every cached message whose destination hash matches the identified
  client's `lxmf.delivery` hash.
- `data = [wants, haves]` → purge everything in `haves` from storage
  (the client is confirming pickup), then stream the raw blobs for
  everything in `wants` back, within a fixed per-call byte budget
  (`MAX_RESPONSE_BUDGET`, 8000 bytes — large syncs take multiple round
  trips rather than one unbounded transfer).

An unidentified link gets nothing back from `/get` — there's no
delivery hash to attribute a list or fetch to.

## Peer-to-peer sync — receiving half done

Real propagation nodes gossip their caches with each other over `/offer`
so a message reaches every PN a recipient might check, not just the one
their sender happened to upload to. This firmware implements the half of
that where another PN (or peer) pushes messages *into* this node's cache
(`handleOffer` in `RetiLXMF.h`), matching `LXMPeer.offer_request`:

1. Requires LINKIDENTIFY, same as `/get` — an unidentified offer gets
   `ERROR_NO_IDENTITY` (`0xf0`), not a real answer.
2. `data = [peering_key, transient_ids]`. The `peering_key` is read and
   discarded: real peers PoW-stamp it to satisfy the receiving node's
   declared peering cost (`LXStamper.validate_peering_key`), but this
   node always announces `peering_cost=0`, and at cost 0 that validation
   is unconditionally true no matter what the key contains — there's
   nothing to check.
3. Responds `false` (already have everything offered), `true` (want
   everything), or an array of just the transient IDs not already
   cached — the exact three-way contract `LXMPeer.offer_response`
   expects.
4. Whatever gets accepted always arrives as a Resource next
   (`LXMPeer.offer_response` never uses a plain packet, regardless of
   size), so it's handled by the same Resource-receive path as a large
   direct upload — see the section above.

**Not built: this node offering its own cache to other PNs.** Outbound
peering would mean generating a valid peering key against *each peer's*
own declared cost, which could be nonzero — real proof-of-work this
firmware doesn't implement (see the anti-spam stamps note below; it's the
same underlying mechanism). This node is a receiver in the peer mesh, not
yet a participant that pushes outward.

## What's deliberately not built

- **Anti-spam stamps (`LXStamper`).** RNS's PoW-based anti-spam layer
  isn't implemented. This node enforces no stamp cost on inbound
  messages and doesn't check for one. It's built to be one person's
  private courier, reachable by a small known set of correspondents —
  not an open relay on a public mesh. Don't treat it as one.
- **Outbound peer sync.** See above — this node accepts what other PNs
  offer it, but doesn't offer its own cache back.
- **Access control / whitelisting.** An earlier draft of this document
  described an admin whitelist gating what gets cached. That was never
  built, and isn't present now — every message addressed to the
  propagation destination is cached (or offered and accepted via
  `/offer`). If you need to restrict who can fill your device's flash,
  that's still open work.

## Storage layout (as built, not as originally planned)

```
/lxmf/<64-char-hex-transient-id>.msg
```

Flat, not nested under a per-recipient directory as an earlier draft of
this document proposed — the destination hash needed to filter a list or
fetch request is already indexed in RAM at boot (read from each file's
first 16 bytes), so a directory-per-recipient layout wasn't needed and
would have cost more flash-metadata overhead on a 1MB filesystem.

Reads and writes go through the `LittleFS`/`InternalFS` File API directly,
one buffer's worth at a time — nothing here holds a full message in RAM
beyond what a single cached blob (bounded by `MAX_RESPONSE_BUDGET`)
requires for one sync response.

## Encoding

Wire messages (announce app_data, Request/Response envelopes, Resource
advertisements) are msgpack, via the vendored `cmp` library
(`lib/cmp`) — not `ArduinoJson`'s MsgPack mode, which can't reliably
round-trip raw `bin` fields that the RNS/LXMF wire format depends on
throughout (hashes, signatures, encrypted payloads are all `bin`, not
strings).
