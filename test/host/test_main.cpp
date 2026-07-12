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
#include "RetiMsgpack.h"
#include "RetiRequest.h"
#include "RetiResource.h"
#include "RetiInterface.h"

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

static void test_identity_decrypt() {
    std::printf("test_identity_decrypt\n");
    Identity id(hexToBytes(TestVectors::IDENTITY_ENCRYPT_PRIVATE_KEY_HEX));
    auto token = hexToBytes(TestVectors::IDENTITY_ENCRYPT_CIPHERTEXT_TOKEN_HEX);

    auto plain = id.decrypt(token);
    checkHexEq(plain, TestVectors::IDENTITY_ENCRYPT_PLAINTEXT_HEX, "Identity::decrypt matches RNS Identity.encrypt() output");
}

static void test_identity_encrypt_decrypt_round_trip() {
    std::printf("test_identity_encrypt_decrypt_round_trip\n");
    auto priv = hexToBytes(TestVectors::IDENTITY_PRIVATE_KEY_HEX);
    Identity id(priv);

    std::vector<uint8_t> plaintext = {'r', 'o', 'u', 'n', 'd', '-', 't', 'r', 'i', 'p'};
    auto token = Identity::encryptTo(id.getX25519PublicKey(), id.getAddress(), plaintext);
    auto decrypted = id.decrypt(token);
    check(decrypted == plaintext, "Identity::encryptTo -> Identity::decrypt round trip");
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

static void test_request_envelope_parse() {
    std::printf("test_request_envelope_parse\n");
    auto plaintext = hexToBytes(TestVectors::REQUEST_PLAINTEXT_HEX);

    RequestEnvelope env;
    bool ok = Request::parseEnvelope(plaintext, env);
    check(ok, "Request::parseEnvelope succeeds on a real RNS request plaintext");
    checkHexEq(env.pathHash, TestVectors::REQUEST_PATH_HASH_HEX, "parsed path_hash matches RNS");
    check(env.timestamp == TestVectors::REQUEST_TIMESTAMP, "parsed timestamp matches RNS");

    auto pathHash = Request::pathHash(TestVectors::REQUEST_PATH);
    checkHexEq(pathHash, TestVectors::REQUEST_PATH_HASH_HEX, "Request::pathHash matches RNS.Identity.truncated_hash(path)");
}

static void test_resource_hash_orderings() {
    std::printf("test_resource_hash_orderings\n");
    auto data = hexToBytes(TestVectors::RESOURCE_DATA_HEX);
    auto randomHash = hexToBytes(TestVectors::RESOURCE_RANDOM_HASH_HEX);
    auto chunk = hexToBytes(TestVectors::RESOURCE_CHUNK_HEX);

    // resource hash = full_hash(data || random_hash) -- data first.
    std::vector<uint8_t> hashInput = data;
    hashInput.insert(hashInput.end(), randomHash.begin(), randomHash.end());
    checkHexEq(Crypto::sha256(hashInput), TestVectors::RESOURCE_HASH_HEX, "resource hash ordering (data || random_hash)");

    // encrypted payload = random_hash || data -- random_hash first.
    std::vector<uint8_t> payload = randomHash;
    payload.insert(payload.end(), data.begin(), data.end());
    checkHexEq(payload, TestVectors::RESOURCE_PAYLOAD_TO_ENCRYPT_HEX, "encrypted payload ordering (random_hash || data)");

    // map_hash = full_hash(chunk || random_hash)[:4] -- chunk first.
    auto mh = Resource::mapHash(chunk, randomHash);
    checkHexEq(mh, TestVectors::RESOURCE_MAP_HASH_HEX, "Resource::mapHash ordering (chunk || random_hash)");
}

static void test_resource_advertisement_self_consistency() {
    // No live RNS-generated Resource vector (would need a timing-sensitive
    // simulated transfer, see test/vectors/make_vectors.py comments) --
    // real cross-implementation validation of the advertisement happens in
    // the Stage 7 live interop test. This checks internal self-consistency:
    // building a resource and re-reading its own advertisement back out.
    std::printf("test_resource_advertisement_self_consistency\n");

    Packet lr = Packet::parse(hexToBytes(TestVectors::LINK_RAW_LR_PACKET_HEX));
    Link* link = Link::accept(lr);
    check(link != nullptr, "Link::accept succeeds");
    if (!link) return;

    std::vector<uint8_t> data(1000);
    for (size_t i = 0; i < data.size(); i++) data[i] = (uint8_t)(i * 7);

    Resource* res = Resource::create(link, data, true, link->linkId);
    check(res->totalParts > 1, "1000-byte payload splits into multiple SDU parts");
    check(res->hashmap.size() == res->totalParts * Resource::MAPHASH_LEN, "hashmap sized to totalParts * MAPHASH_LEN");

    Packet adv = res->buildAdvertisement();
    check(adv.context == CTX_RESOURCE_ADV, "advertisement packet context is RESOURCE_ADV");

    cmp_ctx_t ctx;
    MsgpackBuffer buf;
    // The packet's data is already Link-encrypted; decrypt it back like a
    // receiver would before reading the msgpack map.
    std::vector<uint8_t> advPlain = link->decrypt(adv.data);
    msgpackInitReader(&ctx, &buf, advPlain);

    uint32_t mapSize = 0;
    check(cmp_read_map(&ctx, &mapSize) && mapSize == 11, "advertisement is an 11-entry msgpack map");

    // Round-trip the "t"/"n"/"h" fields by walking key/value pairs.
    bool sawTransferSize = false, sawParts = false, sawHash = false;
    for (uint32_t i = 0; i < mapSize; i++) {
        uint32_t keyLen = 0;
        char key[4] = {0};
        cmp_read_str_size(&ctx, &keyLen);
        ctx.read(&ctx, key, keyLen);

        if (key[0] == 't' && keyLen == 1) {
            uint64_t t = 0;
            cmp_read_uinteger(&ctx, &t);
            check(t == res->encryptedStream.size(), "advertisement 't' matches encrypted stream size");
            sawTransferSize = true;
        } else if (key[0] == 'n' && keyLen == 1) {
            uint64_t n = 0;
            cmp_read_uinteger(&ctx, &n);
            check(n == res->totalParts, "advertisement 'n' matches totalParts");
            sawParts = true;
        } else if (key[0] == 'h' && keyLen == 1) {
            std::vector<uint8_t> h;
            cmpReadBin(&ctx, h, 64);
            check(h == res->hash, "advertisement 'h' matches resource hash");
            sawHash = true;
        } else {
            // Skip whatever value type this is. cmp_read_object() only reads
            // the type/size marker for bin/str values, not the payload
            // bytes, so those need an explicit skip or later reads desync.
            cmp_object_t obj;
            cmp_read_object(&ctx, &obj);
            if (obj.type == CMP_TYPE_BIN8 || obj.type == CMP_TYPE_BIN16 || obj.type == CMP_TYPE_BIN32) {
                ctx.skip(&ctx, obj.as.bin_size);
            } else if (obj.type == CMP_TYPE_STR8 || obj.type == CMP_TYPE_STR16 || obj.type == CMP_TYPE_STR32 ||
                       obj.type == CMP_TYPE_FIXSTR) {
                ctx.skip(&ctx, obj.as.str_size);
            }
        }
    }
    check(sawTransferSize && sawParts && sawHash, "advertisement contained t/n/h fields");
}

// Regression check for a real bug found while designing the interop test:
// a non-fragmenting interface (Serial/BLE, mtu == RNS packet size) must
// pass every inbound frame straight to onPacket. ANNOUNCE (type=1) and
// PROOF (type=3) packets always have their header byte's low bit set, so
// if useFragmentation were mistakenly left on for such an interface, every
// announce and proof arriving on it would be silently swallowed as a
// bogus split-fragment instead of delivered.
class RecordingInterface : public Interface {
public:
    std::vector<std::vector<uint8_t>> received;
    RecordingInterface() : Interface("Test", 500) {}
    void sendRaw(const std::vector<uint8_t>&) override {}
};

void test_interface_passthrough_for_odd_typed_packets() {
    RecordingInterface iface;
    iface.onPacket = [&](const std::vector<uint8_t>& d, Interface*) { iface.received.push_back(d); };

    // ANNOUNCE, HEADER_1, SINGLE dest: header byte = 0b00000001 -> low bit set.
    std::vector<uint8_t> announceLike = {0x01, 0x00};
    announceLike.insert(announceLike.end(), 40, 0xAB);
    iface.receive(announceLike);
    check(iface.received.size() == 1 && iface.received[0] == announceLike,
          "non-fragmenting interface passes an ANNOUNCE-shaped frame straight through");

    // PROOF, HEADER_1, LINK dest: header byte = 0b00001111 -> also low bit set.
    std::vector<uint8_t> proofLike = {0x0F, 0x00};
    proofLike.insert(proofLike.end(), 20, 0xCD);
    iface.receive(proofLike);
    check(iface.received.size() == 2 && iface.received[1] == proofLike,
          "non-fragmenting interface passes a PROOF-shaped frame straight through");
}

int main() {
    test_hex_roundtrip();
    test_x25519_shared_secret();
    test_ed25519_deterministic_signature();
    test_hkdf();
    test_identity_derive();
    test_identity_decrypt();
    test_identity_encrypt_decrypt_round_trip();
    test_destination_hash();
    test_packet_parse_cases();
    test_announce_validated_by_construction();
    test_token_decrypt();
    test_token_round_trip();
    test_link_id_from_request();
    test_link_signalling_bytes();
    test_link_accept_and_proof();
    test_request_envelope_parse();
    test_resource_hash_orderings();
    test_resource_advertisement_self_consistency();
    test_interface_passthrough_for_odd_typed_packets();

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
