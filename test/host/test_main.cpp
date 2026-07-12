// Host-native protocol/crypto compliance tests. Build with test/host/build.sh.
// Checks the firmware's crypto primitives against vectors generated straight
// from the official `rns` package (see test/vectors/make_vectors.py) --
// nothing in here trusts our own implementation for what the "right answer"
// is.
#define RNSC_HOST_TEST 1

#include "TestUtil.h"
#include "vectors_generated.h"
#include "RetiCommon.h"

// CRITICAL: quotes, not angle brackets, to pick up the vendored copies.
#include "monocypher.h"
#include "monocypher-ed25519.h"

#include "RetiCrypto.h"
#include "RetiIdentity.h"
#include "RetiDestination.h"
#include "RetiPacket.h"
#include "RetiAnnounce.h"
#include "RetiLink.h"

#include <cstdio>

using namespace TestUtil;
using namespace Reticulum;

static void test_x25519_shared_secret() {
    std::printf("test_x25519_shared_secret\n");
    auto priv_a = hexToBytes(TestVectors::X25519_PRIV_A_HEX);
    auto priv_b = hexToBytes(TestVectors::X25519_PRIV_B_HEX);

    uint8_t pub_a[32], pub_b[32], shared_ab[32], shared_ba[32];
    crypto_x25519_public_key(pub_a, priv_a.data());
    crypto_x25519_public_key(pub_b, priv_b.data());

    checkHexEq({pub_a, pub_a + 32}, TestVectors::X25519_PUB_A_HEX, "pub_a matches RNS");
    checkHexEq({pub_b, pub_b + 32}, TestVectors::X25519_PUB_B_HEX, "pub_b matches RNS");

    crypto_x25519(shared_ab, priv_a.data(), pub_b);
    crypto_x25519(shared_ba, priv_b.data(), pub_a);

    check(std::vector<uint8_t>(shared_ab, shared_ab + 32) ==
          std::vector<uint8_t>(shared_ba, shared_ba + 32), "shared_ab == shared_ba");
    checkHexEq({shared_ab, shared_ab + 32}, TestVectors::X25519_SHARED_SECRET_HEX, "shared secret matches RNS");
}

static void test_ed25519_deterministic_signature() {
    std::printf("test_ed25519_deterministic_signature\n");
    auto seed = hexToBytes(TestVectors::ED25519_SEED_HEX);
    auto message = hexToBytes(TestVectors::ED25519_MESSAGE_HEX);

    uint8_t secret_key[64], public_key[32], signature[64];
    crypto_ed25519_key_pair(secret_key, public_key, seed.data());

    checkHexEq({public_key, public_key + 32}, TestVectors::ED25519_PUBLIC_KEY_HEX, "public key matches RNS");

    crypto_ed25519_sign(signature, secret_key, message.data(), message.size());

    // Deterministic EdDSA (RFC 8032): byte-exact match is expected, not just
    // "verifies" -- a subtly wrong implementation could still verify its own
    // signatures while producing a different, non-interoperable signature.
    checkHexEq({signature, signature + 64}, TestVectors::ED25519_SIGNATURE_HEX, "signature byte-exact match with RNS");

    int ok = crypto_ed25519_check(signature, public_key, message.data(), message.size());
    check(ok == 0, "signature verifies (crypto_ed25519_check == 0)");
}

static void test_hex_roundtrip() {
    std::printf("test_hex_roundtrip\n");
    std::vector<uint8_t> data = {0x00, 0x01, 0xAB, 0xFF, 0x10};
    String s = Reticulum::toHex(data);
    check(std::string(s.c_str()) == "0001abff10", "Reticulum::toHex output");
    check(hexToBytes(s.c_str()) == data, "TestUtil::hexToBytes round trip");
}

static void test_hkdf() {
    std::printf("test_hkdf\n");
    auto secret = hexToBytes(TestVectors::HKDF_SECRET_HEX);
    auto salt = hexToBytes(TestVectors::HKDF_SALT_HEX);
    auto out = Crypto::hkdf(secret, salt, TestVectors::HKDF_LENGTH);
    checkHexEq(out, TestVectors::HKDF_OUTPUT_HEX, "hkdf output matches RNS");
}

static void test_identity_derive() {
    std::printf("test_identity_derive\n");
    auto priv = hexToBytes(TestVectors::IDENTITY_PRIVATE_KEY_HEX);
    std::vector<uint8_t> pub, hash;
    Identity::derive(priv, pub, hash);
    checkHexEq(pub, TestVectors::IDENTITY_PUBLIC_KEY_HEX, "Identity::derive public key matches RNS");
    checkHexEq(hash, TestVectors::IDENTITY_HASH_HEX, "Identity::derive hash matches RNS");

    // Also check the host-test constructor and sign() work end to end.
    Identity id(priv);
    checkHexEq(id.getPublicKey(), TestVectors::IDENTITY_PUBLIC_KEY_HEX, "Identity ctor public key matches RNS");
    checkHexEq(id.getAddress(), TestVectors::IDENTITY_HASH_HEX, "Identity ctor address matches RNS");
}

static void test_destination_hash() {
    std::printf("test_destination_hash\n");
    auto nameHash = Destination::nameHash(TestVectors::DEST_APP_NAME, TestVectors::DEST_ASPECT);
    checkHexEq(nameHash, TestVectors::DEST_NAME_HASH_HEX, "Destination::nameHash matches RNS");

    auto identityHash = hexToBytes(TestVectors::IDENTITY_HASH_HEX);
    auto destHash = Destination::hash(nameHash, identityHash);
    checkHexEq(destHash, TestVectors::DEST_HASH_HEX, "Destination::hash matches RNS");
}

static void test_packet_parse_cases() {
    std::printf("test_packet_parse_cases\n");
    for (int i = 0; i < TestVectors::PACKET_CASES_COUNT; i++) {
        const auto& c = TestVectors::PACKET_CASES[i];
        Packet p = Packet::parse(hexToBytes(c.raw_hex));
        std::string n = c.name;

        check(p.headerType == c.header_type, (n + ": headerType").c_str());
        check(p.contextFlag == (bool)c.context_flag, (n + ": contextFlag").c_str());
        check(p.transportType == c.transport_type, (n + ": transportType").c_str());
        check(p.destType == c.destination_type, (n + ": destType").c_str());
        check(p.type == c.packet_type, (n + ": type").c_str());
        check(p.hops == c.hops, (n + ": hops").c_str());
        check(p.context == c.context, (n + ": context").c_str());
        checkHexEq(p.addresses, c.destination_hash_hex, (n + ": addresses").c_str());
        checkHexEq(p.data, c.data_hex, (n + ": data").c_str());
        if (std::string(c.transport_id_hex).length() > 0) {
            checkHexEq(p.transportId, c.transport_id_hex, (n + ": transportId").c_str());
        }
    }
}

static void test_announce_validated_by_construction() {
    // Cross-validates against a real, RNS-signed announce packet: parse it
    // and check our Ed25519 verification accepts it. This is the strongest
    // evidence available in a host test that our wire format actually
    // matches the spec, short of a live interop run against Python RNS
    // (see test/host/README or the interop step in CI).
    std::printf("test_announce_validated_by_construction\n");
    Packet p = Packet::parse(hexToBytes(TestVectors::ANNOUNCE_RAW_PACKET_HEX));
    check(p.type == ANNOUNCE, "parsed packet is an ANNOUNCE");

    std::vector<uint8_t> announcedPub;
    bool ok = Announce::validate(p, announcedPub);
    check(ok, "Announce::validate accepts a real RNS-signed announce");
    checkHexEq(announcedPub, TestVectors::IDENTITY_PUBLIC_KEY_HEX, "announced public key matches RNS");
}

static void test_token_decrypt() {
    // Decrypt direction is fully deterministic (no IV to generate), so this
    // is checked byte-exact. Encrypt direction is covered structurally by
    // the round-trip test below, since its IV is randomly generated.
    std::printf("test_token_decrypt\n");
    auto signingKey = hexToBytes(TestVectors::TOKEN_SIGNING_KEY_HEX);
    auto encryptionKey = hexToBytes(TestVectors::TOKEN_ENCRYPTION_KEY_HEX);
    auto token = hexToBytes(TestVectors::TOKEN_HEX);

    auto plain = Crypto::tokenDecrypt(signingKey, encryptionKey, token);
    checkHexEq(plain, TestVectors::TOKEN_PLAINTEXT_HEX, "Crypto::tokenDecrypt matches RNS Token plaintext");

    // Tampering with any byte must be rejected by the HMAC check.
    auto tampered = token;
    tampered[0] ^= 0xFF;
    check(Crypto::tokenDecrypt(signingKey, encryptionKey, tampered).empty(),
          "Crypto::tokenDecrypt rejects a tampered token");
}

static void test_token_round_trip() {
    std::printf("test_token_round_trip\n");
    auto signingKey = hexToBytes(TestVectors::TOKEN_SIGNING_KEY_HEX);
    auto encryptionKey = hexToBytes(TestVectors::TOKEN_ENCRYPTION_KEY_HEX);
    std::vector<uint8_t> plaintext = {'r', 'o', 'u', 'n', 'd', '-', 't', 'r', 'i', 'p'};

    auto token = Crypto::tokenEncrypt(signingKey, encryptionKey, plaintext);
    auto decrypted = Crypto::tokenDecrypt(signingKey, encryptionKey, token);
    check(decrypted == plaintext, "tokenEncrypt -> tokenDecrypt round trip");
}

static void test_link_id_from_request() {
    std::printf("test_link_id_from_request\n");
    Packet lr = Packet::parse(hexToBytes(TestVectors::LINK_RAW_LR_PACKET_HEX));
    check(lr.type == LINK_REQ, "parsed packet is a LINK_REQ");

    auto linkId = Link::linkIdFromRequest(lr);
    checkHexEq(linkId, TestVectors::LINK_ID_HEX, "Link::linkIdFromRequest matches RNS.Link.link_id_from_lr_packet");
}

static void test_link_signalling_bytes() {
    std::printf("test_link_signalling_bytes\n");
    auto signalling = Link::signallingBytes(TestVectors::LINK_SIGNALLING_MTU, TestVectors::LINK_SIGNALLING_MODE);
    checkHexEq(signalling, TestVectors::LINK_SIGNALLING_BYTES_HEX, "Link::signallingBytes matches RNS.Link.signalling_bytes");
}

static void test_link_accept_and_proof() {
    std::printf("test_link_accept_and_proof\n");
    Packet lr = Packet::parse(hexToBytes(TestVectors::LINK_RAW_LR_PACKET_HEX));
    Link* link = Link::accept(lr);
    check(link != nullptr, "Link::accept succeeds on a real LR packet");
    if (!link) return;

    checkHexEq(link->linkId, TestVectors::LINK_ID_HEX, "accepted link's linkId matches RNS");
    check(link->status == Link::ACTIVE, "accepted link is ACTIVE");
    check(link->signingKey.size() == 32 && link->encryptionKey.size() == 32,
          "accepted link derived 32-byte signing/encryption keys");

    Identity serverId(hexToBytes(TestVectors::LINK_SERVER_IDENTITY_PRIVATE_HEX));
    Packet proof = link->buildProof(&serverId, TestVectors::LINK_SIGNALLING_MTU);
    check(proof.type == PROOF, "proof packet type is PROOF");
    check(proof.context == CTX_LRPROOF, "proof context is LRPROOF");
    checkHexEq(proof.addresses, TestVectors::LINK_ID_HEX, "proof is addressed to the link ID");
    check(proof.data.size() == 64 + 32 + 3, "proof payload is sig(64) || x_pub(32) || signalling(3)");

    // The proof must self-verify: signed_data = link_id || x_pub || sig_pub || signalling.
    std::vector<uint8_t> sig(proof.data.begin(), proof.data.begin() + 64);
    std::vector<uint8_t> xPub(proof.data.begin() + 64, proof.data.begin() + 96);
    std::vector<uint8_t> signalling(proof.data.begin() + 96, proof.data.end());
    std::vector<uint8_t> sigPub = serverId.getEd25519PublicKey();

    std::vector<uint8_t> signedData = link->linkId;
    signedData.insert(signedData.end(), xPub.begin(), xPub.end());
    signedData.insert(signedData.end(), sigPub.begin(), sigPub.end());
    signedData.insert(signedData.end(), signalling.begin(), signalling.end());

    int ok = crypto_ed25519_check(sig.data(), sigPub.data(), signedData.data(), signedData.size());
    check(ok == 0, "proof signature self-verifies against the server identity");
}

int main() {
    test_hex_roundtrip();
    test_x25519_shared_secret();
    test_ed25519_deterministic_signature();
    test_hkdf();
    test_identity_derive();
    test_destination_hash();
    test_packet_parse_cases();
    test_announce_validated_by_construction();
    test_token_decrypt();
    test_token_round_trip();
    test_link_id_from_request();
    test_link_signalling_bytes();
    test_link_accept_and_proof();

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
