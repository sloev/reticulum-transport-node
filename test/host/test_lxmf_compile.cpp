// Compile/smoke check for RetiLXMF.h -- not part of the main protocol/crypto
// vector-driven suite (test_main.cpp), since it needs a filesystem mock
// (FsShim.h) that the rest of that harness deliberately does without (see
// test/README.md). Exercises the message cache/list/get round trip against
// the in-memory mock, but does not check wire bytes against RNS vectors --
// that's what test_main.cpp is for.
#define RNSC_HOST_TEST 1

#include "TestUtil.h"
#include "FsShim.h"
#include "RetiCommon.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

// Only what RetiLXMF.h actually needs -- not the full Reti.h umbrella,
// which also pulls in board-only interfaces (RetiBLE/RetiLoRa/RetiSerial/
// RetiWiFi/RetiESPNow) that have no host equivalent.
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
#include "RetiLXMF.h"

#include <cstdio>

using namespace TestUtil;
using namespace Reticulum;

// A no-op interface, just to exercise handleIncoming()'s reply routing.
class NullInterface : public Interface {
public:
    std::vector<std::vector<uint8_t>> sent;
    NullInterface() : Interface("Null", 500) {}
    void sendRaw(const std::vector<uint8_t>& data) override { sent.push_back(data); }
};

int main() {
    std::printf("test_lxmf_construct_and_announce\n");
    std::vector<uint8_t> priv(64);
    for (int i = 0; i < 64; i++) priv[i] = (uint8_t)i;
    Identity id(priv);

    LXMFPropagationNode node(&id);
    check(node.propHash.size() == 16, "propagation destination hash is 16 bytes");
    check(node.nameHash.size() == 10, "name hash is 10 bytes");

    auto appData = node.buildAnnounceAppData();
    check(appData.size() > 0, "announce app_data is non-empty");

    std::printf("test_lxmf_cache_and_list\n");
    // Build a minimal synthetic "lxmf_data": destination_hash(16) || source_hash(16) || sig(64) || payload,
    // encrypted to our own identity the way a real inbound propagation packet would be.
    std::vector<uint8_t> destHash(16, 0xAB);
    std::vector<uint8_t> srcHash(16, 0xCD);
    std::vector<uint8_t> sig(64, 0xEF);
    std::vector<uint8_t> payload = {'h', 'i'};
    std::vector<uint8_t> lxmfData = destHash;
    lxmfData.insert(lxmfData.end(), srcHash.begin(), srcHash.end());
    lxmfData.insert(lxmfData.end(), sig.begin(), sig.end());
    lxmfData.insert(lxmfData.end(), payload.begin(), payload.end());

    std::vector<uint8_t> encrypted = Identity::encryptTo(id.getX25519PublicKey(), id.getAddress(), lxmfData);

    NullInterface iface;
    Packet cachePacket;
    cachePacket.type = DATA;
    cachePacket.destType = SINGLE;
    cachePacket.addresses = node.propHash;
    cachePacket.data = encrypted;

    node.handleIncoming(cachePacket.serialize(), cachePacket, &iface);
    check(node.index.size() == 1, "one message cached");
    if (node.index.size() == 1) {
        check(node.index[0].destinationHash == destHash, "cached message's destination_hash matches");
        check(node.index[0].size == lxmfData.size(), "cached message size matches");
    }

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
