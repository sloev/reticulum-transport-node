#pragma once
#include "RetiCommon.h"

// CRITICAL: Use quotes to force using the local lib/Monocypher files
#include "monocypher.h"
#include "monocypher-ed25519.h"

#if defined(BOARD_SENSECAP_T1000)
// The Adafruit nRF52 core has no mbedTLS, so SHA-256/AES are vendored instead.
extern "C" {
#include "aes.h"
}
#include "sha256.h"
#else
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#endif

namespace Reticulum {
class Crypto {
public:
    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& input) {
        std::vector<uint8_t> out(32);
#if defined(BOARD_SENSECAP_T1000)
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, input.data(), input.size());
        sha256_final(&ctx, out.data());
#else
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, input.data(), input.size());
        mbedtls_md_finish(&ctx, out.data());
        mbedtls_md_free(&ctx);
#endif
        return out;
    }

    static std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
#if defined(BOARD_SENSECAP_T1000)
        // No hardware/mbedTLS HMAC helper on this core; do it by hand from sha256().
        std::vector<uint8_t> k = key;
        if(k.size() > 64) k = sha256(k);
        if(k.size() < 64) k.resize(64, 0x00);

        std::vector<uint8_t> o_key_pad(64), i_key_pad(64);
        for(int i=0; i<64; i++) {
            o_key_pad[i] = k[i] ^ 0x5c;
            i_key_pad[i] = k[i] ^ 0x36;
        }

        std::vector<uint8_t> inner_data = i_key_pad;
        inner_data.insert(inner_data.end(), data.begin(), data.end());
        std::vector<uint8_t> inner_hash = sha256(inner_data);

        std::vector<uint8_t> outer_data = o_key_pad;
        outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());
        return sha256(outer_data);
#else
        std::vector<uint8_t> out(32);
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
        mbedtls_md_hmac_starts(&ctx, key.data(), key.size());
        mbedtls_md_hmac_update(&ctx, data.data(), data.size());
        mbedtls_md_hmac_finish(&ctx, out.data());
        mbedtls_md_free(&ctx);
        return out;
#endif
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
        for(int i=0; i<32; i++) priv[i] = (uint8_t)RETI_RANDOM();

        // Monocypher v4 API (Local)
        crypto_x25519_public_key(pub.data(), priv.data());
    }

    static std::vector<uint8_t> x25519_shared(const std::vector<uint8_t>& myPriv, const std::vector<uint8_t>& peerPub) {
        std::vector<uint8_t> s(32);
        crypto_x25519(s.data(), myPriv.data(), peerPub.data());
        return s;
    }

    static std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& plain) {
        size_t padLen = ((plain.size()/16)+1)*16;
        std::vector<uint8_t> in = plain;
        uint8_t pad = padLen - plain.size();
        for(int i=0; i<pad; i++) in.push_back(pad);
        std::vector<uint8_t> out(padLen);
        uint8_t ivc[16]; memcpy(ivc, iv.data(), 16);

#if defined(BOARD_SENSECAP_T1000)
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key.data(), ivc);
        memcpy(out.data(), in.data(), padLen);
        AES_CBC_encrypt_buffer(&ctx, out.data(), padLen);
#else
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key.data(), 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padLen, ivc, in.data(), out.data());
        mbedtls_aes_free(&aes);
#endif
        return out;
    }

    static std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& cipher) {
        std::vector<uint8_t> plain(cipher.size());
        uint8_t ivc[16]; memcpy(ivc, iv.data(), 16);

#if defined(BOARD_SENSECAP_T1000)
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key.data(), ivc);
        memcpy(plain.data(), cipher.data(), cipher.size());
        AES_CBC_decrypt_buffer(&ctx, plain.data(), cipher.size());
#else
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, key.data(), 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, cipher.size(), ivc, cipher.data(), plain.data());
        mbedtls_aes_free(&aes);
#endif

        // Strip PKCS7-style padding
        if(plain.size() > 0) {
            uint8_t pad = plain.back();
            if(pad > 0 && pad <= 16 && pad <= plain.size()) {
                plain.resize(plain.size() - pad);
            }
        }
        return plain;
    }
};
}
