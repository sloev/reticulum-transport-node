// Compile/smoke check for RetiLXMF.h -- not part of the main protocol/crypto
// vector-driven suite (test_main.cpp), since it needs a filesystem mock
// (FsShim.h) that the rest of that harness deliberately does without (see
// test/README.md). Exercises the message cache/list/get round trip against
// the in-memory mock. Reuses the same real RNS-derived link-request vector
// as test_main.cpp's link tests to establish a genuine link, so the
// propagation-upload path is driven with real derived keys, not synthetic
// ones -- though the overall message shape ([timestamp, [lxmf_data]]) is
// asserted by hand against LXMF.LXMessage's packing logic, not a byte-exact
// vector from the real `lxmf` package.
#define RNSC_HOST_TEST 1

#include "TestUtil.h"
#include "vectors_generated.h"
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

    std::printf("test_lxmf_link_upload_cache_and_list\n");

    // Establish a link the same way an inbound LINK_REQ from a real client
    // would (Link::accept() itself is already exercised end-to-end against
    // this exact vector in test_main.cpp's test_link_accept_and_proof, so
    // here it's just reused to get a link with ground-truth derived keys,
    // registered directly rather than routed through handleIncoming's
    // destination-address gate, which cares about the *outer* Packet's
    // address field, not the LR payload this vector actually carries).
    NullInterface iface;
    Packet lr = Packet::parse(hexToBytes(TestVectors::LINK_RAW_LR_PACKET_HEX));
    Link* link = Link::accept(lr);
    check(link != nullptr, "Link::accept succeeds on the real LR vector");
    if (!link) { std::printf("\n%d checks, %d failures\n", g_checks, g_failures); return 1; }
    node.activeLinks[link->linkId] = link;
    node.linkInterface[link] = &iface;

    // A client uploading a message for propagation sends a plain (context
    // NONE) Link-encrypted DATA packet whose plaintext is
    // msgpack([timestamp, [lxmf_data, ...]]) -- see LXMRouter.propagation_packet
    // and LXMessage.__as_packet() for method=PROPAGATED. lxmf_data itself is
    // dest_hash(16) || source_hash(16) || sig(64) || encrypted-payload,
    // already end-to-end encrypted to its real recipient -- this node never
    // decrypts that part, so synthetic bytes stand in for it here.
    std::vector<uint8_t> destHash(16, 0xAB);
    std::vector<uint8_t> srcHash(16, 0xCD);
    std::vector<uint8_t> sig(64, 0xEF);
    std::vector<uint8_t> payload = {'h', 'i'};
    std::vector<uint8_t> lxmfData = destHash;
    lxmfData.insert(lxmfData.end(), srcHash.begin(), srcHash.end());
    lxmfData.insert(lxmfData.end(), sig.begin(), sig.end());
    lxmfData.insert(lxmfData.end(), payload.begin(), payload.end());

    cmp_ctx_t wctx;
    MsgpackBuffer wbuf;
    msgpackInitWriter(&wctx, &wbuf);
    cmp_write_array(&wctx, 2);
    cmp_write_float(&wctx, 1752000000.0);
    cmp_write_array(&wctx, 1);
    cmp_write_bin(&wctx, lxmfData.data(), (uint32_t)lxmfData.size());

    Packet upload = link->wrapData(wbuf.out, CTX_NONE);
    node.handleIncoming(upload.serialize(), upload, &iface);

    check(node.index.size() == 1, "one message cached from the upload");
    if (node.index.size() == 1) {
        check(node.index[0].destinationHash == destHash, "cached message's destination_hash matches");
        check(node.index[0].size == lxmfData.size(), "cached message size matches");
    }
    check(iface.sent.size() == 1, "a packet-delivery proof was sent for the upload");
    if (iface.sent.size() == 1) {
        Packet proof = Packet::parse(iface.sent[0]);
        check(proof.type == PROOF, "upload proof packet type is PROOF");
        check(proof.destType == LINK, "upload proof is addressed to the link");
        check(proof.addresses == link->linkId, "upload proof addresses this link's ID");
        check(proof.data.size() == 32 + 64, "upload proof payload is packet_hash(32) || sig(64)");
    }

    // A now-identified client listing messages (MESSAGE_GET, data=[nil,nil])
    // should see the just-cached message addressed to its delivery hash.
    std::vector<uint8_t> clientPriv(64);
    for (int i = 0; i < 64; i++) clientPriv[i] = (uint8_t)(200 + i);
    Identity clientId(clientPriv);
    std::vector<uint8_t> clientPub = clientId.getPublicKey();
    std::vector<uint8_t> identifyPlain = clientPub;
    std::vector<uint8_t> identifySig = clientId.sign([&]{
        std::vector<uint8_t> signedData = link->linkId;
        signedData.insert(signedData.end(), clientPub.begin(), clientPub.end());
        return signedData;
    }());
    identifyPlain.insert(identifyPlain.end(), identifySig.begin(), identifySig.end());
    Packet identifyPkt = link->wrapData(identifyPlain, CTX_LINKIDENTIFY);
    node.handleIncoming(identifyPkt.serialize(), identifyPkt, &iface);
    check(link->remoteIdentified, "link identified after LINKIDENTIFY");

    // Make the cached message's destination_hash match this client's
    // lxmf.delivery hash, so the list call actually returns it.
    std::vector<uint8_t> deliveryNameHash = Destination::nameHash("lxmf", "delivery");
    node.index[0].destinationHash = Destination::hash(deliveryNameHash, clientId.getAddress());

    cmp_ctx_t rctx;
    MsgpackBuffer rbuf;
    msgpackInitWriter(&rctx, &rbuf);
    cmp_write_array(&rctx, 2);
    cmp_write_nil(&rctx);
    cmp_write_nil(&rctx);
    std::vector<uint8_t> pathHash = Request::pathHash("/get");
    cmp_ctx_t ectx;
    MsgpackBuffer ebuf;
    msgpackInitWriter(&ectx, &ebuf);
    cmp_write_array(&ectx, 3);
    cmp_write_double(&ectx, 1752000000.0);
    cmp_write_bin(&ectx, pathHash.data(), (uint32_t)pathHash.size());
    ebuf.out.insert(ebuf.out.end(), rbuf.out.begin(), rbuf.out.end());

    Packet listReq = link->wrapData(ebuf.out, CTX_REQUEST);
    node.handleIncoming(listReq.serialize(), listReq, &iface);
    check(iface.sent.size() == 2, "a RESPONSE packet was sent for the list request");
    if (iface.sent.size() == 2) {
        Packet resp = Packet::parse(iface.sent[1]);
        std::vector<uint8_t> respPlain = link->decrypt(resp.data);
        cmp_ctx_t pctx;
        MsgpackBuffer pbuf;
        msgpackInitReader(&pctx, &pbuf, respPlain);
        uint32_t envLen = 0;
        cmp_read_array(&pctx, &envLen);
        std::vector<uint8_t> reqId;
        cmpReadBin(&pctx, reqId, 32);
        uint32_t listLen = 0;
        check(cmp_read_array(&pctx, &listLen) && listLen == 1, "list response contains exactly one entry");
    }

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
