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

    // Ratchets (RNS.Destination.rotate_ratchets()/enable_ratchets()):
    // periodically-rotated X25519 keypairs offered in this identity's
    // announces, giving forward secrecy to anything Identity-encrypted to
    // this node outside a Link (a Link already gets its own per-session
    // ephemeral keys, so ratchets matter for opportunistic/direct
    // Identity.encrypt() traffic specifically). Most recent first, RAM only
    // -- not persisted to flash. RNS retains up to 512 and signs the
    // persisted file; this firmware retains far fewer (flash/RAM budget on
    // an embedded target) and doesn't persist across reboots at all, since
    // nothing in this firmware currently issues Identity-level ciphertext
    // to itself that would need an old ratchet recovered after a restart --
    // see COMPLIANCE.md.
    std::vector<std::vector<uint8_t>> ratchets;
    unsigned long lastRatchetRotation = 0;

public:
    static constexpr size_t RATCHET_COUNT = 8;
    static constexpr unsigned long RATCHET_INTERVAL_MS = 30UL * 60UL * 1000UL; // matches RNS's default 30 minutes

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
    // Test-only: injects a specific ratchet private key (bypassing
    // rotateRatchets()'s random generation) so a host test can decrypt
    // against a real RNS-generated ciphertext_token known to have used that
    // exact ratchet's public key.
    void addRatchetForTesting(const std::vector<uint8_t>& ratchetPriv32) {
        ratchets.insert(ratchets.begin(), ratchetPriv32);
    }

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

    // RNS.Identity.encrypt(): single-shot asymmetric encryption to this
    // identity's X25519 public key -- an ephemeral X25519 keypair is
    // generated per call, ECDH'd against the target, and the shared secret
    // HKDF'd (salt = target identity hash) into a 64-byte Token key. Output
    // is ephemeral_pub(32) || token. Used for e.g. RNS.Destination-level
    // encryption to a SINGLE destination's identity (as opposed to Link
    // encryption, which uses per-link ephemeral keys on both sides).
    static std::vector<uint8_t> encryptTo(const std::vector<uint8_t>& targetX25519Pub,
                                           const std::vector<uint8_t>& targetIdentityHash16,
                                           const std::vector<uint8_t>& plaintext) {
        std::vector<uint8_t> ephemeralPub, ephemeralPriv;
        Crypto::genKeys(ephemeralPub, ephemeralPriv);

        std::vector<uint8_t> shared = Crypto::x25519_shared(ephemeralPriv, targetX25519Pub);
        std::vector<uint8_t> derived = Crypto::hkdf(shared, targetIdentityHash16, 64);
        std::vector<uint8_t> signingKey(derived.begin(), derived.begin() + 32);
        std::vector<uint8_t> encryptionKey(derived.begin() + 32, derived.end());

        std::vector<uint8_t> token = Crypto::tokenEncrypt(signingKey, encryptionKey, plaintext);
        std::vector<uint8_t> out = ephemeralPub;
        out.insert(out.end(), token.begin(), token.end());
        return out;
    }

    // RNS.Identity.decrypt(): the inverse, using this identity's own X25519
    // private key (or, first, any retained ratchet private key -- see
    // RNS.Identity.decrypt()'s ratchets= parameter). Tries ratchets newest
    // first, falls back to the static key. Returns empty on failure
    // (malformed input, or the HMAC not matching any tried key).
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertextToken) const {
        if (ciphertextToken.size() <= 32) return std::vector<uint8_t>();
        std::vector<uint8_t> ephemeralPub(ciphertextToken.begin(), ciphertextToken.begin() + 32);
        std::vector<uint8_t> token(ciphertextToken.begin() + 32, ciphertextToken.end());

        for (auto& ratchetPriv : ratchets) {
            std::vector<uint8_t> shared = Crypto::x25519_shared(ratchetPriv, ephemeralPub);
            std::vector<uint8_t> derived = Crypto::hkdf(shared, address, 64);
            std::vector<uint8_t> signingKey(derived.begin(), derived.begin() + 32);
            std::vector<uint8_t> encryptionKey(derived.begin() + 32, derived.end());
            std::vector<uint8_t> plaintext = Crypto::tokenDecrypt(signingKey, encryptionKey, token);
            if (!plaintext.empty()) return plaintext;
        }

        std::vector<uint8_t> shared = Crypto::x25519_shared(x25519Priv, ephemeralPub);
        std::vector<uint8_t> derived = Crypto::hkdf(shared, address, 64);
        std::vector<uint8_t> signingKey(derived.begin(), derived.begin() + 32);
        std::vector<uint8_t> encryptionKey(derived.begin() + 32, derived.end());

        return Crypto::tokenDecrypt(signingKey, encryptionKey, token);
    }

    // Generates a fresh X25519 ratchet keypair if none exists yet or
    // RATCHET_INTERVAL_MS has elapsed since the last one, keeping only the
    // RATCHET_COUNT most recent (see the class comment on `ratchets`).
    void rotateRatchets() {
        if (!ratchets.empty() && millis() - lastRatchetRotation < RATCHET_INTERVAL_MS) return;

        std::vector<uint8_t> pub, priv;
        Crypto::genKeys(pub, priv);
        ratchets.insert(ratchets.begin(), priv);
        if (ratchets.size() > RATCHET_COUNT) ratchets.resize(RATCHET_COUNT);
        lastRatchetRotation = millis();
    }

    // The public half of the most recently generated ratchet, for inclusion
    // in an announce. Empty if rotateRatchets() has never been called.
    std::vector<uint8_t> latestRatchetPublic() const {
        if (ratchets.empty()) return std::vector<uint8_t>();
        uint8_t pub[32];
        crypto_x25519_public_key(pub, ratchets[0].data());
        return std::vector<uint8_t>(pub, pub + 32);
    }
};
}
