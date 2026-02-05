#pragma once
#include "RetiCommon.h"
#include <monocypher.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"

namespace Reticulum {
class Crypto {
public:
    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& input) {
        std::vector<uint8_t> out(32);
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, input.data(), input.size());
        mbedtls_md_finish(&ctx, out.data());
        mbedtls_md_free(&ctx);
        return out;
    }

    static std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> out(32);
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
        mbedtls_md_hmac_starts(&ctx, key.data(), key.size());
        mbedtls_md_hmac_update(&ctx, data.data(), data.size());
        mbedtls_md_hmac_finish(&ctx, out.data());
        mbedtls_md_free(&ctx);
        return out;
    }

    static std::vector<uint8_t> hkdf(const std::vector<uint8_t>& secret, const std::vector<uint8_t>& salt, size_t len) {
        std::vector<uint8_t> prk = hmac_sha256(salt, secret);
        std::vector<uint8_t> okm;
        std::vector<uint8_t> t;
        uint8_t counter = 1;
        while(okm.size() < len) {
            std::vector<uint8_t> step = t;
            step.push_back(counter++);
            t = hmac_sha256(prk, step);
            okm.insert(okm.end(), t.begin(), t.end());
        }
        okm.resize(len);
        return okm;
    }

    static void genKeys(std::vector<uint8_t>& pub, std::vector<uint8_t>& priv) {
        pub.resize(32); priv.resize(32);
        for(int i=0; i<32; i++) priv[i] = (uint8_t)esp_random();
        crypto_x25519_public_key(pub.data(), priv.data());
    }

    static std::vector<uint8_t> x25519_shared(const std::vector<uint8_t>& myPriv, const std::vector<uint8_t>& peerPub) {
        std::vector<uint8_t> s(32);
        crypto_x25519(s.data(), myPriv.data(), peerPub.data());
        return s;
    }

    static std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& plain) {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key.data(), 128);
        size_t padLen = ((plain.size()/16)+1)*16;
        std::vector<uint8_t> in = plain;
        uint8_t pad = padLen - plain.size();
        for(int i=0; i<pad; i++) in.push_back(pad);
        std::vector<uint8_t> out(padLen);
        uint8_t ivc[16]; memcpy(ivc, iv.data(), 16);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padLen, ivc, in.data(), out.data());
        mbedtls_aes_free(&aes);
        return out;
    }

    static std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& cipher) {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, key.data(), 128);
        std::vector<uint8_t> out(cipher.size());
        uint8_t ivc[16]; memcpy(ivc, iv.data(), 16);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, cipher.size(), ivc, cipher.data(), out.data());
        mbedtls_aes_free(&aes);
        if(!out.empty()) {
            uint8_t pad = out.back();
            if(pad <= 16 && pad <= out.size()) out.resize(out.size()-pad);
        }
        return out;
    }
};
}
