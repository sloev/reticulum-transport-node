# RNS-C

Native C++ Reticulum Network Stack for ESP32 (Heltec V3).
Implements full routing, encryption, and multi-interface bridging.

## Hardware Support
* **Heltec WiFi LoRa 32 V3** (SX1262)
* **T-Beam** (SX1276) - *Requires BoardConfig change*

## Interface Matrix

| Interface | Protocol | MTU | Note |
| :--- | :--- | :--- | :--- |
| **LoRa** | RNode PHY | 255 | Automatic fragmentation for 500b packets. |
| **USB** | KISS | 500 | Compatible with `nomadnet` / `rnsd`. |
| **BLE** | NUS | 500 | Compatible with Sideband (Android). |
| **WiFi** | RNS/UDP | 1200 | Port 4242 broadcast. |
| **ESP-NOW**| RNS/Raw | 250 | Local cluster transport. |

## Build & Flash
Requires PlatformIO.

```bash
pio run -t upload
```

## Configuration
Connect Pin 0 (BOOT) to GND during startup to enter Config AP mode. SSID: RNS-Config-Node IP: 192.168.4.1
