#pragma once
#include "RetiIdentity.h"
#include "RetiDestination.h"
#include "RetiPacket.h"

namespace Reticulum {

// Announce packet build/validate, per RNS.Destination.announce() /
// RNS.Identity.validate_announce(). Deliberately has no dependency on
// Storage/Link/Interface -- it's pure protocol logic, and the host test
// harness exercises it directly against RNS-generated vectors.
class Announce {
public:
    // data = pubkey(64) || name_hash(10) || random_hash(10) || [ratchet(32)] ||
    // sig(64) || app_data, signed over dest_hash || pubkey || name_hash ||
    // random_hash || [ratchet] || app_data -- see RNS.Destination.announce().
    // ratchet is optional: pass an empty vector for the no-ratchet path
    // (valid RNS subset), or a 32-byte X25519 public key to include one and
    // set contextFlag, matching RNS's forward-secrecy announce extension.
    static Packet build(Identity* id, const std::vector<uint8_t>& destHash,
                         const std::vector<uint8_t>& nameHash10,
                         const std::vector<uint8_t>& appData = std::vector<uint8_t>(),
                         const std::vector<uint8_t>& ratchet = std::vector<uint8_t>()) {
        std::vector<uint8_t> randomHash(10);
        for (int i = 0; i < 10; i++) randomHash[i] = (uint8_t)RETI_RANDOM();

        std::vector<uint8_t> pub = id->getPublicKey(); // 64 bytes

        std::vector<uint8_t> signedData = destHash;
        signedData.insert(signedData.end(), pub.begin(), pub.end());
        signedData.insert(signedData.end(), nameHash10.begin(), nameHash10.end());
        signedData.insert(signedData.end(), randomHash.begin(), randomHash.end());
        if (ratchet.size() == 32) signedData.insert(signedData.end(), ratchet.begin(), ratchet.end());
        signedData.insert(signedData.end(), appData.begin(), appData.end());
        std::vector<uint8_t> sig = id->sign(signedData);

        Packet p;
        p.type = ANNOUNCE;
        p.destType = SINGLE;
        p.contextFlag = (ratchet.size() == 32);
        p.addresses = destHash;
        p.data = pub;
        p.data.insert(p.data.end(), nameHash10.begin(), nameHash10.end());
        p.data.insert(p.data.end(), randomHash.begin(), randomHash.end());
        if (ratchet.size() == 32) p.data.insert(p.data.end(), ratchet.begin(), ratchet.end());
        p.data.insert(p.data.end(), sig.begin(), sig.end());
        p.data.insert(p.data.end(), appData.begin(), appData.end());
        return p;
    }

    // Pulls the 64-byte public key out of the payload and checks the
    // Ed25519 signature over dest_hash || pubkey || name_hash ||
    // random_hash || [ratchet] || app_data. On success, fills
    // announcedPubKeyOut with the announcer's 64-byte public key (callers
    // can derive its identity/destination hash from that), ratchetOut with
    // the 32-byte ratchet key if p.contextFlag was set (empty otherwise),
    // and returns true.
    static bool validate(const Packet& p, std::vector<uint8_t>& announcedPubKeyOut,
                          std::vector<uint8_t>& ratchetOut) {
        if (p.type != ANNOUNCE) return false;
        if (p.addresses.size() != 16) return false;
        size_t ratchetLen = p.contextFlag ? 32 : 0;
        if (p.data.size() < 64 + NAME_HASH_LEN + 10 + ratchetLen + 64) return false;

        size_t off = 0;
        std::vector<uint8_t> pub(p.data.begin(), p.data.begin() + 64); off += 64;
        std::vector<uint8_t> nameHash10(p.data.begin() + off, p.data.begin() + off + NAME_HASH_LEN); off += NAME_HASH_LEN;
        std::vector<uint8_t> randomHash10(p.data.begin() + off, p.data.begin() + off + 10); off += 10;
        std::vector<uint8_t> ratchet;
        if (ratchetLen) { ratchet.assign(p.data.begin() + off, p.data.begin() + off + 32); off += 32; }
        std::vector<uint8_t> sig(p.data.begin() + off, p.data.begin() + off + 64); off += 64;
        std::vector<uint8_t> appData(p.data.begin() + off, p.data.end());

        std::vector<uint8_t> signedData = p.addresses;
        signedData.insert(signedData.end(), pub.begin(), pub.end());
        signedData.insert(signedData.end(), nameHash10.begin(), nameHash10.end());
        signedData.insert(signedData.end(), randomHash10.begin(), randomHash10.end());
        if (ratchetLen) signedData.insert(signedData.end(), ratchet.begin(), ratchet.end());
        signedData.insert(signedData.end(), appData.begin(), appData.end());

        std::vector<uint8_t> edPub(pub.begin() + 32, pub.end());
        int ok = crypto_ed25519_check(sig.data(), edPub.data(), signedData.data(), signedData.size());
        if (ok != 0) return false;

        announcedPubKeyOut = pub;
        ratchetOut = ratchet;
        return true;
    }

    // Convenience overload for callers that don't care about the ratchet field.
    static bool validate(const Packet& p, std::vector<uint8_t>& announcedPubKeyOut) {
        std::vector<uint8_t> ratchetDiscard;
        return validate(p, announcedPubKeyOut, ratchetDiscard);
    }
};
}
