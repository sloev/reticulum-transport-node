#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>

namespace TestUtil {

inline std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back((uint8_t)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    }
    return out;
}

inline std::string bytesToHex(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) { s += d[c >> 4]; s += d[c & 0xF]; }
    return s;
}

inline int g_failures = 0;
inline int g_checks = 0;

inline void check(bool cond, const char* what) {
    g_checks++;
    if (!cond) {
        g_failures++;
        std::printf("  FAIL: %s\n", what);
    }
}

inline void checkHexEq(const std::vector<uint8_t>& got, const std::string& want_hex, const char* what) {
    std::string got_hex = bytesToHex(got);
    g_checks++;
    if (got_hex != want_hex) {
        g_failures++;
        std::printf("  FAIL: %s\n    got:  %s\n    want: %s\n", what, got_hex.c_str(), want_hex.c_str());
    }
}

} // namespace TestUtil
