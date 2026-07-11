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
    #define RETI_RANDOM() random(256)

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
