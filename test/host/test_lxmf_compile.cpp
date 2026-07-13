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

    std::printf("test_lxmf_resource_upload_cache\n");
    // A large message (or the follow-up after a successful /offer) always
    // arrives as a Resource, not a single packet -- see
    // LXMessage.__as_resource() / LXMPeer.offer_response. Build one the
    // same way a real sender would: [timestamp, [lxmf_data]] msgpack,
    // large enough to span multiple SDU-sized parts.
    std::vector<uint8_t> bigDestHash(16, 0x11);
    std::vector<uint8_t> bigSrcHash(16, 0x22);
    std::vector<uint8_t> bigSig(64, 0x33);
    std::vector<uint8_t> bigPayload(900, 0x44);
    std::vector<uint8_t> bigLxmfData = bigDestHash;
    bigLxmfData.insert(bigLxmfData.end(), bigSrcHash.begin(), bigSrcHash.end());
    bigLxmfData.insert(bigLxmfData.end(), bigSig.begin(), bigSig.end());
    bigLxmfData.insert(bigLxmfData.end(), bigPayload.begin(), bigPayload.end());

    cmp_ctx_t bwctx;
    MsgpackBuffer bwbuf;
    msgpackInitWriter(&bwctx, &bwbuf);
    cmp_write_array(&bwctx, 2);
    cmp_write_double(&bwctx, 1752000000.0);
    cmp_write_array(&bwctx, 1);
    cmp_write_bin(&bwctx, bigLxmfData.data(), (uint32_t)bigLxmfData.size());

    // Play the sender's side with our own already-verified send-side
    // Resource (test_resource_receive_round_trip in test_main.cpp checks
    // this same encode/decode pairing against real RNS bytes).
    Resource* sender = Resource::create(link, bwbuf.out);
    check(sender->totalParts > 1, "the synthetic upload spans multiple SDU parts");
    Packet adv = sender->buildAdvertisement();

    size_t sentBefore = iface.sent.size();
    node.handleIncoming(adv.serialize(), adv, &iface);
    check(node.activeResources.size() == 1, "advertisement registers one receiving resource");
    check(iface.sent.size() == sentBefore + 1, "a RESOURCE_REQ was sent in response to the advertisement");

    Packet req = Packet::parse(iface.sent.back());
    check(req.context == CTX_RESOURCE_REQ, "the reply to the advertisement is a RESOURCE_REQ");
    std::vector<uint8_t> reqPlain = link->decrypt(req.data);
    std::vector<Packet> parts = sender->handleRequest(reqPlain);
    check(parts.size() == sender->totalParts, "sender answered every requested part");

    for (auto& part : parts) {
        node.handleIncoming(part.serialize(), part, &iface);
    }

    check(node.activeResources.empty(), "receiving resource is cleaned up once assembled");
    check(node.index.size() == 2, "the resource-delivered message was cached alongside the earlier packet upload");

    bool foundBig = false;
    for (auto& m : node.index) {
        if (m.destinationHash == bigDestHash) { foundBig = true; check(m.size == bigLxmfData.size(), "cached resource-delivered message size matches"); }
    }
    check(foundBig, "the resource-delivered message's destination_hash was cached correctly");

    Packet receiveProof = Packet::parse(iface.sent.back());
    check(receiveProof.type == PROOF, "a receive proof was sent for the completed resource");
    check(receiveProof.context == CTX_RESOURCE_PRF, "receive proof context is RESOURCE_PRF");

    delete sender;

    std::printf("test_lxmf_offer_peer_sync\n");
    // LXMPeer.offer_request: data=[peering_key, transient_ids]. This link is
    // already identified from the earlier list test, so ERROR_NO_IDENTITY
    // isn't exercised here directly -- see the unidentified-link case below
    // via a second, fresh link.
    std::vector<uint8_t> haveTid = node.index[0].transientId;   // already cached
    std::vector<uint8_t> wantTid(32, 0x99);                     // not cached

    auto buildOfferRequest = [&](const std::vector<std::vector<uint8_t>>& tids) {
        cmp_ctx_t offctx; MsgpackBuffer offbuf;
        msgpackInitWriter(&offctx, &offbuf);
        cmp_write_array(&offctx, 2);
        cmp_write_bin(&offctx, (const uint8_t*)"pk", 2); // peering_key: never inspected, see handleOffer
        cmp_write_array(&offctx, (uint32_t)tids.size());
        for (auto& t : tids) cmp_write_bin(&offctx, t.data(), (uint32_t)t.size());

        std::vector<uint8_t> pathHash = Request::pathHash("/offer");
        cmp_ctx_t envctx; MsgpackBuffer envbuf;
        msgpackInitWriter(&envctx, &envbuf);
        cmp_write_array(&envctx, 3);
        cmp_write_double(&envctx, 1752000000.0);
        cmp_write_bin(&envctx, pathHash.data(), (uint32_t)pathHash.size());
        envbuf.out.insert(envbuf.out.end(), offbuf.out.begin(), offbuf.out.end());
        return link->wrapData(envbuf.out, CTX_REQUEST);
    };

    // Returns the response *value* bytes (after the [request_id, ...]
    // envelope's first element), so callers can init their own fresh
    // msgpack reader over still-in-scope storage.
    auto readOfferResponseValue = [&](const std::vector<uint8_t>& raw) {
        Packet resp = Packet::parse(raw);
        std::vector<uint8_t> plain = link->decrypt(resp.data);
        cmp_ctx_t pctx; MsgpackBuffer pbuf;
        msgpackInitReader(&pctx, &pbuf, plain);
        uint32_t envLen = 0;
        cmp_read_array(&pctx, &envLen);
        std::vector<uint8_t> reqId;
        cmpReadBin(&pctx, reqId, 32);
        return std::vector<uint8_t>(plain.begin() + pbuf.inPos, plain.end());
    };

    // Offering only a message we already have -> false (want nothing).
    size_t before = iface.sent.size();
    Packet offerAllHave = buildOfferRequest({haveTid});
    node.handleIncoming(offerAllHave.serialize(), offerAllHave, &iface);
    check(iface.sent.size() == before + 1, "offer (all already have) got a response");
    {
        std::vector<uint8_t> value = readOfferResponseValue(iface.sent.back());
        cmp_ctx_t pctx; MsgpackBuffer pbuf;
        msgpackInitReader(&pctx, &pbuf, value);
        cmp_object_t obj;
        check(cmp_read_object(&pctx, &obj) && obj.type == CMP_TYPE_BOOLEAN && obj.as.boolean == false,
              "offering an already-cached message responds false");
    }

    // Offering only a message we don't have -> true (want everything).
    before = iface.sent.size();
    Packet offerAllWant = buildOfferRequest({wantTid});
    node.handleIncoming(offerAllWant.serialize(), offerAllWant, &iface);
    {
        std::vector<uint8_t> value = readOfferResponseValue(iface.sent.back());
        cmp_ctx_t pctx; MsgpackBuffer pbuf;
        msgpackInitReader(&pctx, &pbuf, value);
        cmp_object_t obj;
        check(cmp_read_object(&pctx, &obj) && obj.type == CMP_TYPE_BOOLEAN && obj.as.boolean == true,
              "offering an entirely new message responds true");
    }

    // Offering a mix -> array containing only the wanted one.
    before = iface.sent.size();
    Packet offerMixed = buildOfferRequest({haveTid, wantTid});
    node.handleIncoming(offerMixed.serialize(), offerMixed, &iface);
    {
        std::vector<uint8_t> value = readOfferResponseValue(iface.sent.back());
        cmp_ctx_t pctx; MsgpackBuffer pbuf;
        msgpackInitReader(&pctx, &pbuf, value);
        uint32_t n = 0;
        check(cmp_read_array(&pctx, &n) && n == 1, "offering a mix responds with an array of exactly the wanted ones");
        if (n == 1) {
            std::vector<uint8_t> got;
            cmpReadBin(&pctx, got, 32);
            check(got == wantTid, "the wanted entry in a mixed offer response is the uncached one");
        }
    }

    // An unidentified link gets ERROR_NO_IDENTITY (0xf0), same requirement as /get.
    // Deliberately NOT the same LR vector as `link`: Link::linkIdFromRequest()
    // is a pure function of the LR packet's bytes, and Link::accept() derives
    // its Token keys from a fresh ephemeral keypair on *this* node's side --
    // reusing the same vector here would give freshLink the identical linkId
    // as `link` (silently clobbering node.activeLinks[link->linkId] with a
    // link that has different derived keys) while still being a distinct
    // Link object with incompatible encryption, breaking every later use of
    // the original `link`.
    std::vector<uint8_t> lr2Raw = hexToBytes(TestVectors::LINK_RAW_LR_PACKET_HEX);
    lr2Raw[2] ^= 0xFF; // first byte of the LR payload -- flips the derived linkId
    Packet lr2 = Packet::parse(lr2Raw);
    Link* freshLink = Link::accept(lr2);
    node.activeLinks[freshLink->linkId] = freshLink;
    node.linkInterface[freshLink] = &iface;
    Packet offerUnidentified = freshLink->wrapData([&]{
        cmp_ctx_t offctx; MsgpackBuffer offbuf;
        msgpackInitWriter(&offctx, &offbuf);
        cmp_write_array(&offctx, 2);
        cmp_write_bin(&offctx, (const uint8_t*)"pk", 2);
        cmp_write_array(&offctx, 0);
        std::vector<uint8_t> pathHash = Request::pathHash("/offer");
        cmp_ctx_t envctx; MsgpackBuffer envbuf;
        msgpackInitWriter(&envctx, &envbuf);
        cmp_write_array(&envctx, 3);
        cmp_write_double(&envctx, 1752000000.0);
        cmp_write_bin(&envctx, pathHash.data(), (uint32_t)pathHash.size());
        envbuf.out.insert(envbuf.out.end(), offbuf.out.begin(), offbuf.out.end());
        return envbuf.out;
    }(), CTX_REQUEST);
    before = iface.sent.size();
    node.handleIncoming(offerUnidentified.serialize(), offerUnidentified, &iface);
    {
        Packet resp = Packet::parse(iface.sent.back());
        std::vector<uint8_t> plain = freshLink->decrypt(resp.data);
        cmp_ctx_t pctx; MsgpackBuffer pbuf;
        msgpackInitReader(&pctx, &pbuf, plain);
        uint32_t envLen = 0;
        cmp_read_array(&pctx, &envLen);
        std::vector<uint8_t> reqId;
        cmpReadBin(&pctx, reqId, 32);
        uint64_t code = 0;
        check(cmp_read_uinteger(&pctx, &code) && code == 0xf0,
              "offer on an unidentified link responds with ERROR_NO_IDENTITY");
    }

    // A wanted offer is followed by the actual transfer as a Resource,
    // exactly like a large direct upload -- LXMPeer.offer_response never
    // uses a plain packet.
    std::vector<uint8_t> peerDestHash(16, 0x55);
    std::vector<uint8_t> peerLxmfData = peerDestHash;
    peerLxmfData.insert(peerLxmfData.end(), 16 + 64, 0x66);
    cmp_ctx_t pwctx; MsgpackBuffer pwbuf;
    msgpackInitWriter(&pwctx, &pwbuf);
    cmp_write_array(&pwctx, 2);
    cmp_write_double(&pwctx, 1752000000.0);
    cmp_write_array(&pwctx, 1);
    cmp_write_bin(&pwctx, peerLxmfData.data(), (uint32_t)peerLxmfData.size());

    Resource* peerSender = Resource::create(link, pwbuf.out);
    Packet peerAdv = peerSender->buildAdvertisement();
    size_t sentBeforePeerAdv = iface.sent.size();
    node.handleIncoming(peerAdv.serialize(), peerAdv, &iface);
    check(node.activeResources.size() == 1, "offer-triggered advertisement registered a receiving resource");
    check(iface.sent.size() == sentBeforePeerAdv + 1, "offer-triggered advertisement got a reply");
    Packet peerReq = Packet::parse(iface.sent.back());
    check(peerReq.context == CTX_RESOURCE_REQ, "offer-triggered reply is a RESOURCE_REQ");
    std::vector<uint8_t> peerReqPlain = link->decrypt(peerReq.data);
    check(!peerReqPlain.empty(), "offer-triggered RESOURCE_REQ decrypts");
    std::vector<Packet> peerParts = peerSender->handleRequest(peerReqPlain);
    check(peerParts.size() == peerSender->totalParts, "sender answered every requested part for the offer transfer");
    for (auto& part : peerParts) node.handleIncoming(part.serialize(), part, &iface);
    check(node.activeResources.empty(), "offer-triggered receiving resource cleaned up");

    bool foundPeerMsg = false;
    for (auto& m : node.index) if (m.destinationHash == peerDestHash) foundPeerMsg = true;
    check(foundPeerMsg, "a message delivered via the offer-triggered resource transfer was cached");
    delete peerSender;

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
