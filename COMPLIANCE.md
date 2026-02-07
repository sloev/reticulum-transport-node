# 🛡️ RNS-C Compliance & Audit Matrix

**Firmware Version:** 0.3.0-RC1 (33C3 Edition)
**Target Hardware:** Heltec WiFi LoRa 32 V3 (ESP32-S3)
**Spec Reference:** [Reticulum Network Stack Manual v1.1.3](https://reticulum.network/manual/)

---

## 1. Cryptography & Identity (The Iron Core)
*Reference: Manual v1.1.3, Chapter 6 (Identities) & Chapter 6.7.5 (Cryptographic Primitives)*

We employ a **vendored** implementation of `Monocypher 4.0.2` to ensure binary reproducibility and strictly enforce the primitives defined in the RNS spec. We do not rely on platform-specific crypto libraries where consistency is critical.

| Component | RNS Spec v1.1.3 Requirement | RNS-C Implementation | Status |
| :--- | :--- | :--- | :--- |
| **Identity Generation** | Ed25519 Public Key derived from 32-byte seed. | `lib/Monocypher`: `crypto_ed25519_key_pair` acting on a persisted 32-byte random seed in flash. | ✅ **STRICT** |
| **Addressing** | SHA-256 hash of Public Key (truncated to 16 bytes). | `RetiIdentity.h`: `sha256(pub_key)[0..16]`. Matches `rnsd` hashing exactly. | ✅ **MATCH** |
| **Signatures** | Ed25519 (Schnorr). | `monocypher-ed25519`: `crypto_ed25519_sign`. | ✅ **MATCH** |
| **Key Exchange** | X25519 (Curve25519 ECDH). | `monocypher`: `crypto_x25519`. Ephemeral keys generated per Link Request. | ✅ **MATCH** |
| **Encryption** | AES-128-CBC (PKCS7 Padding). | `mbedtls` (Hardware Accelerated). Compatible with RNS default `Fernet` logic. | ✅ **MATCH** |

---

## 2. Interface Specifications
*Reference: Manual v1.1.3, Chapter 8 (Interfaces) & Chapter 7.2 (RNode)*

### A. RNode LoRa Interface (PHY)
The firmware implements the raw `RNode` framing protocol. This ensures the device is recognized as a valid interface by any standard Reticulum instance.

* **Framing:** Raw RNode Protocol.
* **Header:** `[ 1 byte ]` $\to$ `(SequenceNumber << 4) | (Flags & 0x0F)`
* **MTU:** 500 Bytes (Strict enforcement).
* **Modulation Parameters (Fast Mesh / Default):**
    * **Frequency:** 867.2 MHz (EU868) / 915.0 MHz (US915)
    * **Spreading Factor:** SF7
    * **Bandwidth:** 125 kHz
    * **Coding Rate:** 4/5

### B. Transport & Routing
*Reference: Manual v1.1.3, Chapter 6.7.4 (Announce Propagation Rules)*

* **Announce Propagation:** Implements the jittered rebroadcast mechanism (200ms-1000ms delay) to prevent packet storms (CSMA/CA software emulation).
* **Hop Limits:** Decrements TTL on all forwarded packets; drops packet if TTL=0.

---

## 3. Supply Chain Security: Why Monocypher?

We have explicitly **vendored** (embedded) the Monocypher v4.0.2 source code into `lib/Monocypher` rather than relying on an external library manager or the ESP-IDF default crypto for core primitives.

1.  **Auditability:** The security-critical code is committed directly to the repo. It is immutable and open for inspection by any reviewer (including Linus) without needing to chase down dependencies.
2.  **API Stability:** It protects us from upstream API breaks or "improvements" in system libraries that might break backward compatibility with the Reticulum spec.
3.  **Size & Efficiency:** Monocypher compiles to <45KB, leaving maximum IRAM available for the Reticulum packet buffer and WiFi stack.

---

## 4. Field Verification Procedure

**Objective:** Prove interoperability with a Linux host running the official `rnsd`.

### Prerequisites
* Linux Host with Python 3.
* Reticulum installed: `pip install rns`
* Hardware: 1x Heltec V3 (Flashed with RNS-C)

### Step 1: Configuration
Connect the Heltec V3 via USB. Identify the port (e.g., `/dev/ttyACM0`).
Edit `~/.reticulum/config` on the host to add the interface:

```ini
[[RNS_C_Test_Interface]]
  type = RNodeInterface
  interface_enabled = yes
  outgoing = true
  port = /dev/ttyACM0
  frequency = 867200000
  bandwidth = 125000
  spreading_factor = 7
  coding_rate = 5
```

### Step 2: Execution
Run the Reticulum daemon in verbose mode to see the handshake:

```bash
rnsd -vv
```

### Step 3: Success Criteria
Observe the log output for the following sequence:

* [SerialInterface] Opened port /dev/ttyACM0...
* [RNodeInterface] Configured RNode interface...
* CRITICAL: [Transport] Interface RNS_C_Test_Interface is now active

Finally, run rnstatus in a separate terminal. The device should appear in the interface list, and if the firmware is functioning correctly, you should see announces propagating from the mesh:


| Status  | Name                 | Mode   | Rate    | Peers |
| --------|----------------------|--------|---------|-------|
| Up      | RNS_C_Test_Interface | Access | 21 kbps |     1 |

