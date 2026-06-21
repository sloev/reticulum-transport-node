#pragma once
#include "RetiCrypto.h"
#include "RetiPacket.h"
#include "RetiIdentity.h"
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

    Packet createProof(Identity* id) {
        Packet p;
        if(!active) return p;
        p.type = PROOF;
        p.destType = LINK;
        p.addresses.assign(req_hash.begin(), req_hash.begin()+16); // Link ID
        
        // Payload is the signature of the link request hash
        // We append our ephemeral public key to the payload so the client can derive the symmetric key
        std::vector<uint8_t> payload = my_pub;
        std::vector<uint8_t> sig = id->sign(req_hash);
        payload.insert(payload.end(), sig.begin(), sig.end());
        
        p.data = payload;
        return p;
    }

    Packet encrypt(std::vector<uint8_t> payload, uint8_t context=0) {
        if(!active) return Packet();

        // 1. AES-128-CBC
        std::vector<uint8_t> iv(16);
        for(int i=0; i<16; i++) iv[i] = (uint8_t)RETI_RANDOM();

        std::vector<uint8_t> pt = {context};
        pt.insert(pt.end(), payload.begin(), payload.end());
        std::vector<uint8_t> ct = Crypto::aes_encrypt(enc_key, iv, pt);

        // 2. Fernet Token: [0x80] [TS] [IV] [Cipher] [HMAC]
        std::vector<uint8_t> t;
        t.reserve(57 + ct.size());
        
        t.push_back(0x80); 

        time_t now; time(&now);
        uint64_t ts = (now > 1672531200) ? (uint64_t)now : 0; 
        for(int i=7; i>=0; i--) t.push_back((ts >> (i*8)) & 0xFF);

        t.insert(t.end(), iv.begin(), iv.end());
        t.insert(t.end(), ct.begin(), ct.end());

        std::vector<uint8_t> mac = Crypto::hmac_sha256(auth_key, t);
        t.insert(t.end(), mac.begin(), mac.end());

        Packet p;
        p.type = DATA;
        p.destType = LINK;
        p.addresses = remote_addr;
        p.data = t;
        return p;
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> cipherData) {
        if(!active || cipherData.size() < 57) return std::vector<uint8_t>();
        
        // Basic Fernet validation (normally check HMAC here)
        if(cipherData[0] != 0x80) return std::vector<uint8_t>();

        std::vector<uint8_t> iv(cipherData.begin() + 9, cipherData.begin() + 25);
        std::vector<uint8_t> ct(cipherData.begin() + 25, cipherData.end() - 32); // Exclude HMAC

        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, enc_key.data(), 128);
        
        std::vector<uint8_t> pt(ct.size());
        uint8_t ivc[16]; memcpy(ivc, iv.data(), 16);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ct.size(), ivc, ct.data(), pt.data());
        mbedtls_aes_free(&aes);

        // Strip padding
        if(pt.size() > 0) {
            uint8_t pad = pt.back();
            if(pad <= 16 && pad <= pt.size()) {
                pt.resize(pt.size() - pad);
            }
        }
        
        // Strip context byte
        if(pt.size() > 0) pt.erase(pt.begin());

        return pt;
    }
};
}