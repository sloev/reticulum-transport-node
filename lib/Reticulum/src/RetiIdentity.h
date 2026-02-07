#pragma once
#include "RetiCrypto.h"
#include <LittleFS.h>

namespace Reticulum {
class Identity {
private:
    std::vector<uint8_t> seed;       // 32 bytes (Persisted to disk)
    std::vector<uint8_t> privateKey; // 64 bytes (Expanded in RAM)
    std::vector<uint8_t> publicKey;  // 32 bytes
    std::vector<uint8_t> address;    // 16 bytes

public:
    Identity() {
        if(LittleFS.exists("/id.key")) {
            File f = LittleFS.open("/id.key", "r");
            seed.resize(32);
            f.read(seed.data(), 32);
            f.close();
            RNS_LOG("Identity Loaded.");
        } else {
            seed.resize(32);
            for(int i=0; i<32; i++) seed[i] = (uint8_t)esp_random();
            File f = LittleFS.open("/id.key", "w");
            f.write(seed.data(), 32);
            f.close();
            RNS_LOG("New Identity Generated.");
        }
        derive();
    }

    void derive() {
        publicKey.resize(32);
        privateKey.resize(64); // Expand seed to 64-byte secret
        
        // This function from your header generates the 64-byte secret and 32-byte public key from the 32-byte seed
        // void crypto_ed25519_key_pair(uint8_t secret_key[64], uint8_t public_key[32], uint8_t seed[32]);
        crypto_ed25519_key_pair(privateKey.data(), publicKey.data(), seed.data());
        
        std::vector<uint8_t> hash = Crypto::sha256(publicKey);
        address.assign(hash.begin(), hash.begin()+16);
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) {
        std::vector<uint8_t> sig(64);
        
        // Now we pass the 64-byte expanded private key
        // void crypto_ed25519_sign(uint8_t signature[64], const uint8_t secret_key[64], const uint8_t *message, size_t message_size);
        crypto_ed25519_sign(sig.data(), privateKey.data(), msg.data(), msg.size());
        
        return sig;
    }
    
    std::vector<uint8_t> getAddress() const { return address; }
    std::vector<uint8_t> getPublicKey() const { return publicKey; }
};
}