#pragma once
#include "RetiCrypto.h"
#include <LittleFS.h>
#include "RetiCommon.h"

namespace Reticulum {
class Identity {
    std::vector<uint8_t> priv, pub, addr;
public:
    Identity() {
        if(LittleFS.exists("/id.key")) {
            File f = LittleFS.open("/id.key", "r");
            priv.resize(32); f.read(priv.data(), 32); f.close();
            RNS_LOG("ID Loaded.");
        } else {
            priv.resize(32); for(int i=0; i<32; i++) priv[i] = (uint8_t)esp_random();
            File f = LittleFS.open("/id.key", "w");
            f.write(priv.data(), 32); f.close();
            RNS_LOG("ID Created.");
        }
        pub.resize(32);
        uint8_t exp[64];
        crypto_eddsa_key_pair(exp, pub.data(), priv.data());
        std::vector<uint8_t> h = Crypto::sha256(pub);
        addr.assign(h.begin(), h.begin()+16);
    }
    std::vector<uint8_t> sign(const std::vector<uint8_t>& m) {
        std::vector<uint8_t> sig(64);
        uint8_t exp[64];
        crypto_eddsa_key_pair(exp, pub.data(), priv.data());
        crypto_eddsa_sign(sig.data(), exp, m.data(), m.size());
        return sig;
    }
    std::vector<uint8_t> getAddress() { return addr; }
    std::vector<uint8_t> getPublicKey() { return pub; }
};
}
