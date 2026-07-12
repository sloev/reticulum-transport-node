#pragma once
#include "RetiCrypto.h"

namespace Reticulum {

const size_t NAME_HASH_LEN = 10;
const size_t DEST_HASH_LEN = 16;

// RNS destination naming: see RNS.Destination.expand_name/__init__.
// name_hash = SHA256(app_name + "." + aspect)[:10]
// destination_hash (SINGLE) = SHA256(name_hash(10) || identity_hash(16))[:16]
class Destination {
public:
    static std::vector<uint8_t> nameHash(const String& appName, const String& aspect) {
        String full = appName + "." + aspect;
        std::vector<uint8_t> in(full.c_str(), full.c_str() + full.length());
        std::vector<uint8_t> h = Crypto::sha256(in);
        h.resize(NAME_HASH_LEN);
        return h;
    }

    static std::vector<uint8_t> hash(const std::vector<uint8_t>& nameHash10,
                                      const std::vector<uint8_t>& identityHash16) {
        std::vector<uint8_t> in = nameHash10;
        in.insert(in.end(), identityHash16.begin(), identityHash16.end());
        std::vector<uint8_t> h = Crypto::sha256(in);
        h.resize(DEST_HASH_LEN);
        return h;
    }
};
}
