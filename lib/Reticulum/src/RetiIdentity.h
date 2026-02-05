#pragma once
#include "RetiCrypto.h"
#include <LittleFS.h>

namespace Reticulum {
class Identity {
private:
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> address;

public:
    Identity() {
        if(LittleFS.exists("/id.key")) {
            File f = LittleFS.open("/id.key", "r");
            privateKey.resize(32);
            f.read(privateKey.data(), 32);
            f.close();
            RNS_LOG("Identity Loaded.");
        } else {
            privateKey.resize(32);
            for(int i=0; i<32; i++) privateKey[i] = (uint8_t)esp_random();
            File f = LittleFS.open("/id.key", "w");
            f.write(privateKey.data(), 32);
            f.close();
            RNS_LOG("New Identity Generated.");
        }
        derive();
    }

    void derive() {
        publicKey.resize(32);
        uint8_t exp[64];
        crypto_eddsa_key_pair(exp, publicKey.data(), privateKey.data());
        std::vector<uint8_t> hash = Crypto::sha256(publicKey);
        address.assign(hash.begin(), hash.begin()+16);
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) {
        std::vector<uint8_t> sig(64);
        uint8_t exp[64];
        crypto_eddsa_key_pair(exp, publicKey.data(), privateKey.data());
        crypto_eddsa_sign(sig.data(), exp, msg.data(), msg.size());
        return sig;
    }
    
    std::vector<uint8_t> getAddress() const { return address; }
    std::vector<uint8_t> getPublicKey() const { return publicKey; }
};
}
