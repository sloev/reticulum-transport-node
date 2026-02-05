#pragma once
#include <Arduino.h>
#include <vector>

#ifdef RNS_LOGGING_ENABLED
    #define RNS_LOG(...) Serial.printf("[RNS] " __VA_ARGS__); Serial.println()
    #define RNS_ERR(...) Serial.printf("[ERR] " __VA_ARGS__); Serial.println()
#else
    #define RNS_LOG(...)
    #define RNS_ERR(...)
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
