# Audit Log: RNS-C v0.2

| Component | Status | Notes |
| :--- | :--- | :--- |
| **PHY / LoRa** | ✅ PASS | Split-packet header `[Seq<<4 | 1]`. |
| **PHY / ESP-NOW** | ✅ PASS | Cluster mode enabled. |
| **Routing** | ✅ PASS | Flood routing with SHA-256 deduplication (Cap: 512). |
| **Handshake** | ✅ PASS | HKDF Salt == RequestHash. |
| **Encryption** | ✅ PASS | Fernet `0x80` Header + HMAC scope verified. |
| **Persistence** | ✅ PASS | RAM Write-Back Cache implemented. |

**Checksums:**
* **Address**: SHA-256 (Truncated 128-bit)
* **Proof**: Ed25519(`RequestHash` + `EphemeralKey`)
* **Packet**: MDU 500b -> LoRa MTU 255b transparent splitting.

## Interoperability Test Procedure

To verify this firmware against the reference implementation (`rnsd`):

### 1. The Gateway (Node A)
* **Role:** Bridge LoRa <-> UDP.
* **Config:** WiFi credentials flashed.
* **State:** NTP Sync Active. Fernet tokens generated here will have valid timestamps.

### 2. The Remote (Node B)
* **Role:** Deep Mesh endpoint.
* **Config:** No WiFi.
* **Test:** Send 500 byte payload.
* **Expectation:** Node B splits packet (255+245+headers). Node A reassembles and forwards to UDP.

### 3. The Control (PC)
* **Software:** `rnx` (Reticulum Utility).
* **Command:** `rnx --link <NODE_B_HASH>`
* **Success:** Green Link status indicates full crypto compliance.