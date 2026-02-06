# RNS-C Compliance Audit
**Target Spec:** Reticulum 0.7.x  
**Implementation:** RNS-C v0.1 (ESP32)

## 🟢 1. Transport & Routing (100%)
| Feature | Implementation | Spec Status |
| :--- | :--- | :--- |
| **Packet Header** | `RetiPacket.h` | ✅ **Compliant**. Flags, Hops, and Context match binary format. |
| **Addressing** | `RetiIdentity.h` | ✅ **Compliant**. Uses SHA-256 truncation (16 bytes). |
| **Announces** | `RetiRouter.h` | ✅ **Compliant**. ECDH PubKey + Random Bloom + App Data. |
| **Flood Control** | `RetiRouter.h` | ✅ **Compliant**. Deduplication table prevents routing loops. |
| **Store & Forward**| `RetiStorage.h`| ✅ **Compliant**. Persists packets for offline identities. |

## 🟡 2. Encryption & Links (90% - Critical Fix Needed)
| Feature | Implementation | Spec Status |
| :--- | :--- | :--- |
| **Key Exchange** | `RetiLink.h` | ✅ **Compliant**. X25519 ECDH. |
| **Key Derivation**| `RetiLink.h` | ✅ **Compliant**. HKDF-SHA256 with `Salt = RequestHash`. |
| **Signatures** | `RetiIdentity.h`| ✅ **Compliant**. Ed25519 signatures. |
| **Proof Binding** | `RetiLink.h` | ✅ **Compliant**. Signs `[RequestHash + EphemeralKey]`. |
| **Cipher Format** | `RetiLink.h` | ⚠️ **Deviation**. We use `[IV][Cipher][HMAC]`. RNS Spec requires **Fernet Tokens**: `[0x80][Timestamp][IV][Cipher][HMAC]`. **(See Issue #1)** |

## 🟢 3. Hardware Interfaces (100%)
| Feature | Implementation | Spec Status |
| :--- | :--- | :--- |
| **LoRa** | `RetiLoRa.h` | ✅ **Compliant**. Supports default RNS LoRa parameters (SF9/BW125). |
| **MDU Handling** | `RetiInterface.h`| ✅ **Compliant**. Transparently fragments 500b packets over 255b MTU. |
| **KISS Framing** | `RetiSerial.h` | ✅ **Compliant**. Standard `FEND/FESC` framing for USB/PC. |
| **Sideband (BLE)**| `RetiBLE.h` | ✅ **Compliant**. Emulates Nordic UART Service (NUS). |

## 📋 Action Plan (Roadmap to Beta)
1.  **Fix Fernet Token Format**: Update `RetiLink::encrypt` to prepend `0x80` and a 64-bit Timestamp to match the Fernet spec.
2.  **Verify Interop**: Connect to a Python RNS Node via Serial and exchange a Link.