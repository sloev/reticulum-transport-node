#pragma once
#include "RetiCrypto.h"

namespace Reticulum {

// RNS identities are a *pair* of independent keys, not one derived from the
// other: a 32-byte X25519 key (used for Diffie-Hellman/encryption) and a
// 32-byte Ed25519 key (used for signing). The 64-byte public key is
// X25519_pub(32) || Ed25519_pub(32), and identity/destination hashes are
// SHA256(that 64-byte public key)[:16]. See RNS.Identity.load_private_key /
// get_public_key in the reference implementation.
class Identity {
private:
    std::vector<uint8_t> x25519Priv;   // 32 bytes (persisted)
    std::vector<uint8_t> ed25519Seed;  // 32 bytes (persisted)
    std::vector<uint8_t> ed25519Priv;  // 64 bytes (expanded from seed, RAM only)
    std::vector<uint8_t> publicKey;    // 64 bytes: x25519Pub(32) || ed25519Pub(32)
    std::vector<uint8_t> address;      // 16 bytes: SHA256(publicKey)[:16]

public:
    // Pure key derivation, no filesystem: given 64 bytes of private key
    // material (x25519Priv(32) || ed25519Seed(32)), produce the 64-byte
    // public key and 16-byte hash. Exposed so the host test harness can
    // verify this against RNS.Identity.load_private_key() without touching
    // a board's filesystem.
    static void derive(const std::vector<uint8_t>& privBytes64,
                        std::vector<uint8_t>& pubOut64,
                        std::vector<uint8_t>& hashOut16) {
        // Monocypher's C API isn't const-correct on these inputs (it doesn't
        // mutate them, but doesn't say so), so work off local copies.
        uint8_t x25519Priv[32], ed25519Seed[32];
        memcpy(x25519Priv, privBytes64.data(), 32);
        memcpy(ed25519Seed, privBytes64.data() + 32, 32);

        uint8_t x25519Pub[32];
        crypto_x25519_public_key(x25519Pub, x25519Priv);

        uint8_t ed25519PrivExpanded[64], ed25519Pub[32];
        crypto_ed25519_key_pair(ed25519PrivExpanded, ed25519Pub, ed25519Seed);

        pubOut64.resize(64);
        memcpy(pubOut64.data(), x25519Pub, 32);
        memcpy(pubOut64.data() + 32, ed25519Pub, 32);

        std::vector<uint8_t> hash = Crypto::sha256(pubOut64);
        hashOut16.assign(hash.begin(), hash.begin() + 16);
    }

#if defined(RNSC_HOST_TEST)
    // Host tests exercise derive() directly against RNS-generated vectors;
    // there's no meaningful filesystem to persist keys to off-device.
    explicit Identity(const std::vector<uint8_t>& privBytes64) {
        x25519Priv.assign(privBytes64.begin(), privBytes64.begin() + 32);
        ed25519Seed.assign(privBytes64.begin() + 32, privBytes64.end());
        uint8_t ed25519PubDiscard[32];
        ed25519Priv.resize(64);
        crypto_ed25519_key_pair(ed25519Priv.data(), ed25519PubDiscard, ed25519Seed.data());
        derive(privBytes64, publicKey, address);
    }
#else
    Identity() {
        std::vector<uint8_t> privBytes64;

        if (LittleFS.exists("/id.key")) {
#if defined(BOARD_SENSECAP_T1000)
            File f(LittleFS.open("/id.key", FILE_O_READ));
#else
            File f = LittleFS.open("/id.key", "r");
#endif
            privBytes64.resize(64);
            f.read(privBytes64.data(), 64);
            f.close();
            RNS_LOG("Identity Loaded.");
        } else {
            privBytes64.resize(64);
            for (int i = 0; i < 64; i++) privBytes64[i] = (uint8_t)RETI_RANDOM();
#if defined(BOARD_SENSECAP_T1000)
            File f(LittleFS.open("/id.key", FILE_O_WRITE));
#else
            File f = LittleFS.open("/id.key", "w");
#endif
            f.write(privBytes64.data(), 64);
            f.close();
            RNS_LOG("New Identity Generated.");
        }

        x25519Priv.assign(privBytes64.begin(), privBytes64.begin() + 32);
        ed25519Seed.assign(privBytes64.begin() + 32, privBytes64.end());

        uint8_t ed25519PubDiscard[32];
        ed25519Priv.resize(64);
        crypto_ed25519_key_pair(ed25519Priv.data(), ed25519PubDiscard, ed25519Seed.data());

        derive(privBytes64, publicKey, address);
    }
#endif

    std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) {
        std::vector<uint8_t> sig(64);
        crypto_ed25519_sign(sig.data(), ed25519Priv.data(), msg.data(), msg.size());
        return sig;
    }

    std::vector<uint8_t> getAddress() const { return address; }
    std::vector<uint8_t> getPublicKey() const { return publicKey; }
    std::vector<uint8_t> getX25519PublicKey() const {
        return std::vector<uint8_t>(publicKey.begin(), publicKey.begin() + 32);
    }
    std::vector<uint8_t> getEd25519PublicKey() const {
        return std::vector<uint8_t>(publicKey.begin() + 32, publicKey.end());
    }
};
}
