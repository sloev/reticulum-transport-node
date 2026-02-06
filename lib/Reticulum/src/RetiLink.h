#pragma once
#include "RetiCrypto.h"
#include "RetiPacket.h"
#include <time.h>

namespace Reticulum {
class Link {
public:
    bool active = false;
    std::vector<uint8_t> remote_addr;
    std::vector<uint8_t> enc_key, auth_key;
    std::vector<uint8_t> req_hash;
    std::vector<uint8_t> my_pub, my_priv;

    Link(std::vector<uint8_t> peer) : remote_addr(peer) { 
        Crypto::genKeys(my_pub, my_priv); 
    }

    void accept(std::vector<uint8_t> peer_pub, std::vector<uint8_t> salt) {
        req_hash = salt;
        std::vector<uint8_t> shared = Crypto::x25519_shared(my_priv, peer_pub);
        std::vector<uint8_t> derived = Crypto::hkdf(shared, req_hash, 64);
        
        enc_key.assign(derived.begin(), derived.begin()+32);
        auth_key.assign(derived.begin()+32, derived.end());
        active = true;
    }

    Packet encrypt(std::vector<uint8_t> payload, uint8_t context=0) {
        if(!active) return Packet();

        // 1. IV Generation
        std::vector<uint8_t> iv(16);
        for(int i=0; i<16; i++) iv[i] = (uint8_t)esp_random();

        // 2. Ciphertext Generation (AES-128-CBC)
        std::vector<uint8_t> plaintext = {context};
        plaintext.insert(plaintext.end(), payload.begin(), payload.end());
        std::vector<uint8_t> cipher = Crypto::aes_encrypt(enc_key, iv, plaintext);

        // 3. Fernet Token Construction
        // Spec: [0x80] [TS(8)] [IV(16)] [Cipher(N)] [HMAC(32)]
        std::vector<uint8_t> token;
        token.reserve(57 + cipher.size());
        
        token.push_back(0x80); // Version

        // Timestamp (Big Endian)
        time_t now; 
        time(&now);
        uint64_t ts = (now > 1672531200) ? (uint64_t)now : 0; // Epoch check (2023)
        for(int i=7; i>=0; i--) token.push_back((ts >> (i*8)) & 0xFF);

        token.insert(token.end(), iv.begin(), iv.end());
        token.insert(token.end(), cipher.begin(), cipher.end());

        // 4. HMAC Signature
        std::vector<uint8_t> mac = Crypto::hmac_sha256(auth_key, token);
        token.insert(token.end(), mac.begin(), mac.end());

        Packet p;
        p.type = DATA;
        p.destType = LINK;
        p.addresses = remote_addr;
        p.data = token;
        return p;
    }
};
}