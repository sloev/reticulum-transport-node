# RNS-C

Bare-metal Reticulum Network Stack and LXMF propagation node. No app, no
cloud account, no phone-home. Runs standalone on a coin-sized radio and
talks the wire protocol straight — a real Sideband or NomadNet client syncs
with it exactly as it would with a `rnsd` node on a laptop.

Two boards, one firmware tree:

- **Heltec WiFi LoRa 32 V3** — ESP32-S3, SX1262
- **SenseCAP Card Tracker T1000-E** — nRF52840, LR1110

**[Releases → firmware.uf2 / firmware_merged.bin](https://github.com/sloev/reticulum-transport-node/releases/latest)**

---

## THE CARD

```
      .-------------------------------.
     ( o )                             \
      '   .-------------------------.   \
      |   |                         |    )   <- keychain loop
      |   |     SenseCAP T1000-E    |   /
      |   |   nRF52840 + LR1110     |  /
      |   |                         | /
      |   '-------------------------'/
      |        (( LED ))   [BTN]    |
      |______________________________|
       |   ___________  |    .-.
       |  | usb-c port| |   ( ' )  <- sub-GHz antenna
       '--'-----------'-'----'-'---'
```

Card format, single button, one status LED, USB-C for power and serial.
No screen — status goes out over BLE and the console UART, not a display.
Runs for days on the mesh, longer sitting idle in a pocket.

---

## WHAT IT ACTUALLY DOES

Verified byte-for-byte against the reference `rns` 1.3.7 / `lxmf` 1.0.1
Python packages, not just "should be compatible" — see `test/host/`.

- **Wire-correct packets.** Header bits, address fields, context byte,
  hop counting, truncated-hash dedup — matches what `RNS.Packet` emits
  and parses.
- **Real identities.** Paired X25519 (exchange) + Ed25519 (signing) keys,
  64-byte public key, SHA-256 address hash — not a single Ed25519 key
  standing in for both.
- **Signed announces**, validated the same way `RNS.Identity.validate_announce`
  validates them, with jittered rebroadcast so a mesh of these doesn't
  self-collide retransmitting the same announce in the same instant.
- **A working Link handshake** (responder side): LRPROOF, AES-256-CBC
  Token encryption with mandatory HMAC verification on every decrypt,
  LINKIDENTIFY, LINKCLOSE, keepalive, staleness timeout.
- **Request/Response and Resource transfer** over an active Link — the
  layer Sideband and NomadNet actually use to pull a message list and
  fetch messages, not just the announce.
- **A real LXMF propagation node.** Caches inbound messages to flash
  under their transient ID, answers `MESSAGE_GET` (list / want / have)
  the way a Python `LXMRouter` peer does, purges on acknowledged pickup.
- **Hardware entropy.** Identity keys, ephemeral link keys, and IVs come
  from the nRF52840's RNG peripheral (or ESP32's) — not `random()`.

## WHAT IT DOESN'T DO YET

Said plainly, not buried:

- No anti-spam stamps (`LXStamper`). This node accepts anything addressed
  to it. Don't leave it wide open on a public mesh.
- No propagation-node-to-propagation-node sync (the `/offer` path). It
  serves clients directly; it doesn't gossip caches with other PNs.
- No ratcheted announces.
- No Resource *receive* path. It can send Resources but not accept one —
  and LXMF only sends a message as a single link packet if it's under
  319 bytes; anything longer, or carrying an attachment, uploads as a
  Resource instead. Short messages sync fine. Longer ones or anything
  with an attachment will fail to upload until this is built.

Full line-item ledger, with the RNS manual section each row maps to:
`COMPLIANCE.md`.

---

## INTERFACES

| Interface | Framing | Notes |
|---|---|---|
| LoRa | raw Reticulum packets on the PHY | SX1262 (Heltec) / LR1110 (T1000-E). This is a full node transmitting directly, not an RNode modem waiting on a host. |
| Serial (USB) | KISS (FEND/FESC), 500B MTU | Plug into a host running `rnsd` — looks like any other serial interface. |
| BLE | Nordic UART Service, KISS over 20B notify chunks | What Sideband's "Bluetooth Serial" interface talks to. |
| WiFi / ESP-NOW | — | Heltec only. The T1000-E has neither radio. |

---

## PROVISIONING

1. Pull `firmware.uf2` (T1000-E) or `firmware_merged.bin` (Heltec) from
   the latest release.
2. **T1000-E:** double-tap the button to mount the `T1000EBOOT` drive,
   drag the `.uf2` onto it.
   **Heltec:** flash `firmware_merged.bin` at offset `0x0` with
   `esptool`, or the [Espressif web flasher](https://espressif.github.io/esptool-js/).
3. Power on. First boot generates an identity from hardware entropy and
   starts announcing on every interface.

## SYNCING FROM SIDEBAND

1. Add a Bluetooth interface in Sideband and select the device.
2. Once its announce comes in, add it as a Propagation Node under
   Sideband's LXMF settings.
3. Sync pulls whatever's cached under your identity's hash; the node
   purges what you've collected once it's confirmed picked up.

---

## BUILDING

```sh
pio run -e heltec_wifi_lora_32_V3
pio run -e sensecap_t1000
```

The protocol and crypto layer is checked against fixed vectors generated
fresh from the real `rns`/`lxmf` packages on every run — not trusted on
faith, and never allowed to drift quietly from the spec version this
firmware claims to speak.

```sh
pip install rns==1.3.7 lxmf==1.0.1
./test/host/build.sh
```

---

License: MIT.
