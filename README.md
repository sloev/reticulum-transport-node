# RNS-C

Native C++ implementation of the [Reticulum Network Stack](https://reticulum.network/) for the ESP32 architecture.

## Specifications

* **Platform**: Espressif ESP32 (Xtensa LX6/LX7)
* **Target Board**: Heltec WiFi LoRa 32 V3 (SX1262)
* **Compliance**: RNS v0.7.x
* **License**: MIT

## Interfaces

| Interface | Protocol | MTU | Details |
| :--- | :--- | :--- | :--- |
| **LoRa** | RNode PHY | 255 | Automatic fragmentation for 500b MDU. |
| **Serial** | KISS | 500 | `115200 8N1`. Compatible with `rnsd`. |
| **BLE** | NUS | 500 | Nordic UART Service. UUID `6E400001...`. |
| **WiFi** | RNS/UDP | 1200 | UDP Broadcast on Port 4242. |
| **ESP-NOW** | Raw | 250 | Cluster transport. Auto-channel sync. |

## Build

```bash
# Requirements: PlatformIO
pio run -t upload
```

## Usage
Autonomous Repeater
Power on. The node automatically generates an Identity (/id.key) and bridges packets between all active interfaces using flood routing with SHA-256 deduplication.

USB Modem (rnsd)
Connect via USB.

```Ini, TOML

[[Serial_Interface]]
  type = KISSInterface
  port = /dev/ttyUSB0
  speed = 115200
```

## Encryption Support

* Primitives: X25519, Ed25519, AES-128-CBC, HMAC-SHA256, HKDF.
* Token: Standard Fernet spec (0x80 versioning).
* Time: NTP synchronization via WiFi required for valid Fernet timestamps. Fallback to 0 if offline.

## Flash Storage

Packets destined for offline nodes are cached in RAM. If RAM pressure exceeds 512 entries, or upon shutdown, packets are flushed to LittleFS.