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

#include <cstdio>

using namespace TestUtil;

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

int main() {
    test_hex_roundtrip();
    test_x25519_shared_secret();
    test_ed25519_deterministic_signature();

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
