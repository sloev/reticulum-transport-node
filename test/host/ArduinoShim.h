#pragma once
// Minimal stand-in for Arduino.h, just enough surface area for the
// protocol/crypto layer (RetiCommon, RetiCrypto, RetiPacket, RetiIdentity,
// RetiDestination) to compile and run as a native host binary under g++.
//
// This intentionally does NOT cover Stream/File/BLE/WiFi/SPI -- those stay
// firmware-only and are exercised by the real device builds in CI, not here.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <chrono>
#include <cstdlib>
#include <algorithm>

inline unsigned long millis() {
    using namespace std::chrono;
    static const auto t0 = steady_clock::now();
    return (unsigned long)duration_cast<milliseconds>(steady_clock::now() - t0).count();
}

inline void delay(unsigned long) {}

// Deterministic by default so host tests are reproducible; RETI_RANDOM_SEED
// lets a test override it before pulling randomness.
inline long random(long bound) { return bound > 0 ? (std::rand() % bound) : 0; }

using std::min;
using std::max;

#define HEX 16

class String {
    std::string s_;
public:
    String() = default;
    String(const char* c) : s_(c ? c : "") {}
    String(const std::string& s) : s_(s) {}
    // Matches real Arduino String(byte, HEX): no zero-padding.
    String(uint8_t v, int base) {
        char buf[4];
        snprintf(buf, sizeof(buf), base == HEX ? "%x" : "%d", (unsigned)v);
        s_ = buf;
    }
    String(unsigned long v) : s_(std::to_string(v)) {}
    String(int v) : s_(std::to_string(v)) {}

    const char* c_str() const { return s_.c_str(); }
    size_t length() const { return s_.size(); }
    void reserve(size_t n) { s_.reserve(n); }
    bool startsWith(const String& p) const { return s_.rfind(p.s_, 0) == 0; }
    bool operator==(const String& o) const { return s_ == o.s_; }
    String operator+(const String& o) const { return String(s_ + o.s_); }
    String& operator+=(const String& o) { s_ += o.s_; return *this; }
    operator std::string() const { return s_; }
};

inline String operator+(const char* a, const String& b) { return String(a) + b; }
