#pragma once
#include <Arduino.h>
#include <vector>

#ifdef RNS_LOGGING
    #define RNS_LOG(...) Serial.printf("[RNS] " __VA_ARGS__); Serial.println()
#else
    #define RNS_LOG(...)
#endif

namespace Reticulum {
const size_t MAX_PACKET_SIZE = 512;

struct PacketBuffer {
    uint8_t data[MAX_PACKET_SIZE];
    size_t len = 0;
    void fromVector(const std::vector<uint8_t>& v) {
        len = min(v.size(), MAX_PACKET_SIZE);
        memcpy(data, v.data(), len);
    }
    std::vector<uint8_t> toVector() const {
        return std::vector<uint8_t>(data, data + len);
    }
};

static String toHex(const std::vector<uint8_t>& d) {
    String s; s.reserve(d.size()*2);
    for(uint8_t b : d) {
        if(b < 16) s += "0";
        s += String(b, HEX);
    }
    return s;
}
}
