#pragma once

// RNSC_HOST_TEST builds the protocol/crypto layer as a native binary (see
// test/host/) against ground-truth vectors generated from the real `rns`
// package -- no board, no filesystem, no radio.
#if defined(RNSC_HOST_TEST)
    #include "ArduinoShim.h"
#else
    #include <Arduino.h>
#endif
#include <vector>

#ifdef RNS_LOGGING_ENABLED
    #define RNS_LOG(...) Serial.printf("[RNS] " __VA_ARGS__); Serial.println()
    #define RNS_ERR(...) Serial.printf("[ERR] " __VA_ARGS__); Serial.println()
#else
    #define RNS_LOG(...)
    #define RNS_ERR(...)
#endif

#if defined(RNSC_HOST_TEST)
    #define RETI_RANDOM() random(256)
    #define IRAM_ATTR
#elif defined(BOARD_SENSECAP_T1000)
    // random(256) is Arduino's unseeded, deterministic PRNG -- every boot
    // produces the exact same sequence. That is not acceptable for identity
    // keys, ephemeral link keys, or IVs, so pull bytes from the nRF52840's
    // hardware RNG peripheral instead. Once the SoftDevice (Bluefruit) is
    // enabled it owns NRF_RNG, so route through its application-RNG call in
    // that case and only touch the peripheral directly beforehand.
    #include <nrf_soc.h>
    static inline uint8_t reti_hw_random_byte() {
        uint8_t sd_enabled = 0;
        if (sd_softdevice_is_enabled(&sd_enabled) == NRF_SUCCESS && sd_enabled) {
            uint8_t b;
            if (sd_rand_application_vector_get(&b, 1) == NRF_SUCCESS) return b;
        }
        NRF_RNG->TASKS_START = 1;
        while (NRF_RNG->EVENTS_VALRDY == 0) {}
        NRF_RNG->EVENTS_VALRDY = 0;
        uint8_t b = (uint8_t)NRF_RNG->VALUE;
        NRF_RNG->TASKS_STOP = 1;
        return b;
    }
    #define RETI_RANDOM() reti_hw_random_byte()

    // nRF52840 (Adafruit core): the ESP32-only IRAM_ATTR is undefined here.
    #if !defined(IRAM_ATTR)
        #define IRAM_ATTR
    #endif

    // nRF52840 (Adafruit core) ships its own LittleFS wrapper with a
    // different API shape (File open-mode flags, no formatOnFail argument)
    // instead of the ESP32 LittleFS library.
    #include <Adafruit_LittleFS.h>
    #include <InternalFileSystem.h>
    #define LittleFS InternalFS
    using namespace Adafruit_LittleFS_Namespace;
    #define RETI_FS_BEGIN() LittleFS.begin()
#else
    #define RETI_RANDOM() esp_random()
    #include <LittleFS.h>
    #define RETI_FS_BEGIN() LittleFS.begin(true)
#endif

namespace Reticulum {

// Fixed-size Packet Buffer to avoid Heap Fragmentation
const size_t MAX_PACKET_SIZE = 512;

struct PacketBuffer {
    uint8_t data[MAX_PACKET_SIZE];
    size_t len = 0;

    void clear() { len = 0; }
    
    bool append(const uint8_t* buf, size_t size) {
        if (len + size > MAX_PACKET_SIZE) return false;
        memcpy(data + len, buf, size);
        len += size;
        return true;
    }
    
    std::vector<uint8_t> toVector() const {
        return std::vector<uint8_t>(data, data + len);
    }
    
    void fromVector(const std::vector<uint8_t>& v) {
        len = min(v.size(), MAX_PACKET_SIZE);
        memcpy(data, v.data(), len);
    }
};

static String toHex(const std::vector<uint8_t>& d) {
    String s; s.reserve(d.size()*2);
    for(uint8_t b : d) {
        if(b<16) s+="0";
        s += String(b, HEX);
    }
    return s;
}

}
