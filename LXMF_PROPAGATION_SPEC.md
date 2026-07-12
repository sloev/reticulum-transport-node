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

A message addressed to the propagation destination arrives as a plain
packet (not a Link upload — LXMF deliveries to a PN don't go through the
Resource protocol). The firmware:

1. Decrypts the packet with the node's own identity (`Identity::decrypt`)
   — this is the RNS-transport-layer wrapper, separate from and outside
   LXMF's own end-to-end encryption of the message body to its actual
   recipient, which this node never touches.
2. Computes `transient_id = SHA256(lxmf_data)` (full 32 bytes, no
   truncation) and skips it if already cached.
3. Writes the raw bytes to `/lxmf/<64-hex-transient-id>.msg` and adds an
   entry to the in-RAM index (`destination_hash` = first 16 bytes of the
   payload, read back out of the filename + file header on boot so the
   index survives a reset without re-hashing every stored file).
4. Evicts the oldest entry if storage exceeds `MAX_STORED_MESSAGES` (40,
   a fixed cap — flash is small, and this isn't a general-purpose relay).

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

## What's deliberately not built

- **Anti-spam stamps (`LXStamper`).** RNS's PoW-based anti-spam layer
  isn't implemented. This node enforces no stamp cost on inbound
  messages and doesn't check for one. It's built to be one person's
  private courier, reachable by a small known set of correspondents —
  not an open relay on a public mesh. Don't treat it as one.
- **Peer-to-peer propagation sync (the `/offer` path).** Real PNs gossip
  their caches with each other so a message reaches every PN a
  recipient might check. This node only serves the client directly;
  it doesn't participate in that gossip.
- **Ratcheted announces.** Not implemented at the announce layer in
  general — see `COMPLIANCE.md` section 3.
- **Access control / whitelisting.** An earlier draft of this document
  described an admin whitelist gating what gets cached. That was never
  built, and isn't present now — every message addressed to the
  propagation destination is cached. If you need to restrict who can
  fill your device's flash, that's still open work.

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
