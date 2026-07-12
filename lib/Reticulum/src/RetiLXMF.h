#pragma once
#include "RetiCommon.h"
#include "RetiIdentity.h"
#include "RetiDestination.h"
#include "RetiPacket.h"
#include "RetiLink.h"
#include "RetiRequest.h"
#include "RetiResource.h"
#include "RetiInterface.h"
#include "RetiMsgpack.h"
#include <vector>
#include <map>

namespace Reticulum {

// LXMF wire constants -- see LXMF.LXMessage.
const size_t LXMF_DESTINATION_LENGTH = 16;
const size_t LXMF_SIGNATURE_LENGTH = 64;
const size_t LXMF_MIN_SIZE = LXMF_DESTINATION_LENGTH * 2 + LXMF_SIGNATURE_LENGTH; // dest+src+sig, before payload

struct StoredMessage {
    std::vector<uint8_t> transientId;    // 32 bytes: SHA256(raw lxmf_data), full hash -- see RNS.Identity.full_hash
    std::vector<uint8_t> destinationHash; // 16 bytes: lxmf_data[:16], the recipient's lxmf.delivery destination
    size_t size = 0;
    String filename;
};

// Micro-LXMF Propagation Node: caches messages addressed to destinations it
// doesn't hold the keys for, and serves them back to their rightful owner
// over an authenticated Link. This device is a "private courier" for one
// or a few known users, not an open public relay -- see
// LXMF_PROPAGATION_SPEC.md.
//
// Scope, stated plainly: implements the MESSAGE_GET path (list, fetch,
// purge) that Sideband/NomadNet use to sync with a propagation node. Does
// NOT implement: anti-spam stamps (LXStamper; this device enforces none
// and expects none), peer-to-peer PN-to-PN sync (the /offer path), or
// ratcheted announces. All are honestly called out in COMPLIANCE.md.
class LXMFPropagationNode {
public:
    std::vector<uint8_t> nameHash;  // 10 bytes: SHA256("lxmf.propagation")[:10]
    std::vector<uint8_t> propHash;  // 16 bytes: SHA256(nameHash || identity_hash)[:16]
    std::vector<uint8_t> deliveryNameHash; // 10 bytes: SHA256("lxmf.delivery")[:10], used to compute *clients'* hashes

    Identity* id;
    Request requestHandler;

    std::map<std::vector<uint8_t>, Link*> activeLinks;       // keyed by linkId
    std::map<Link*, Interface*> linkInterface;                // reply routing: which interface a link's peer is reachable on
    std::map<std::vector<uint8_t>, Resource*> activeResources; // keyed by resource hash

    std::vector<StoredMessage> index; // in-RAM index of what's cached in /lxmf on flash

    static const size_t MAX_STORED_MESSAGES = 40;   // quota: oldest evicted first past this count
    static const size_t MAX_RESPONSE_BUDGET = 8000; // bytes served per MESSAGE_GET call, like RNS's client_transfer_limit

    LXMFPropagationNode(Identity* node_id) : id(node_id) {
        nameHash = Destination::nameHash("lxmf", "propagation");
        propHash = Destination::hash(nameHash, id->getAddress());
        deliveryNameHash = Destination::nameHash("lxmf", "delivery");

        if (!LittleFS.exists("/lxmf")) LittleFS.mkdir("/lxmf");
        rebuildIndex();

        requestHandler.registerHandler("/get", [this](const std::vector<uint8_t>& dataPayload, Link* link) {
            return this->handleMessageGet(dataPayload, link);
        });
    }

    // RNS.LXMRouter.get_propagation_node_app_data(): [legacy_pn(false),
    // timebase(int), hosting(bool), per_transfer_limit_kb(int),
    // per_sync_limit_kb(int), [stamp_cost, flexibility, peering_cost],
    // metadata]. Sideband/NomadNet check this shape (pn_announce_data_is_valid)
    // before treating an announce as a real propagation node.
    std::vector<uint8_t> buildAnnounceAppData() const {
        cmp_ctx_t ctx;
        MsgpackBuffer buf;
        msgpackInitWriter(&ctx, &buf);

        cmp_write_array(&ctx, 7);
        cmp_write_false(&ctx);                 // 0: legacy PN support
        cmp_write_uinteger(&ctx, (uint64_t)(millis() / 1000)); // 1: timebase (no RTC -- uptime, not wall clock)
        cmp_write_true(&ctx);                  // 2: hosting a propagation node
        cmp_write_uinteger(&ctx, 32);           // 3: per-transfer limit, KB
        cmp_write_uinteger(&ctx, 32);           // 4: per-sync limit, KB
        cmp_write_array(&ctx, 3);               // 5: stamp cost -- 0 everywhere, no PoW required
        cmp_write_uinteger(&ctx, 0);
        cmp_write_uinteger(&ctx, 0);
        cmp_write_uinteger(&ctx, 0);
        cmp_write_nil(&ctx);                    // 6: metadata (none)

        return buf.out;
    }

    // Called from Router::onLocalDelivery for every packet: filters to what
    // this node cares about (its own propagation destination, or an active
    // link) and dispatches. `src` is the interface the packet arrived on,
    // used to route replies back the same way.
    void handleIncoming(const std::vector<uint8_t>& rawPacket, const Packet& p, Interface* src) {
        (void)rawPacket; // kept in the signature to match Router::onLocalDelivery's callback shape
        if (p.destType == LINK) {
            handleLinkPacket(p, src);
            return;
        }

        if (p.addresses.size() != 16) return;
        if (!std::equal(propHash.begin(), propHash.end(), p.addresses.begin())) return;

        if (p.type == LINK_REQ) {
            Link* link = Link::accept(p);
            if (!link) return;
            activeLinks[link->linkId] = link;
            linkInterface[link] = src;
            Packet proof = link->buildProof(id);
            src->send(proof.serialize());
            RNS_LOG("LXMF: link established, PROOF sent.");
            return;
        }

        // Nothing else arrives addressed to the bare propagation
        // destination: LXMRouter always uploads messages over an
        // established Link (see handlePropagationUpload), never as a
        // plain packet to the destination hash.
    }

    void loop() {
        // Drop links that have gone quiet -- the client's own link will
        // independently notice and re-establish if it still wants to sync.
        for (auto it = activeLinks.begin(); it != activeLinks.end(); ) {
            if (it->second->isStale() || it->second->status == Link::CLOSED) {
                linkInterface.erase(it->second);
                for (auto rit = activeResources.begin(); rit != activeResources.end(); ) {
                    if (rit->second->link == it->second) { delete rit->second; rit = activeResources.erase(rit); }
                    else ++rit;
                }
                delete it->second;
                it = activeLinks.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    void handleLinkPacket(const Packet& p, Interface* src) {
        auto it = activeLinks.find(p.addresses);
        if (it == activeLinks.end()) return;
        Link* link = it->second;
        link->touch();

        if (p.context == CTX_LINKIDENTIFY) {
            link->handleIdentify(p.data);
        } else if (p.context == CTX_LINKCLOSE) {
            link->handleClose();
        } else if (p.context == CTX_REQUEST) {
            RequestResult result = requestHandler.handleRequest(link, p);
            if (!result.handled) return;
            if (result.needsResource) {
                Resource* res = Resource::create(link, result.resourceEnvelope, true, result.requestId);
                activeResources[res->hash] = res;
                Packet adv = res->buildAdvertisement();
                src->send(adv.serialize());
            } else if (result.responsePacket.data.size() > 0) {
                src->send(result.responsePacket.serialize());
            }
        } else if (p.context == CTX_RESOURCE_REQ) {
            std::vector<uint8_t> plaintext = link->decrypt(p.data);
            if (plaintext.empty()) return;
            for (auto& kv : activeResources) {
                if (kv.second->link != link) continue;
                std::vector<Packet> parts = kv.second->handleRequest(plaintext);
                for (auto& part : parts) src->send(part.serialize());
            }
        } else if (p.context == CTX_NONE) {
            handlePropagationUpload(p, link, src);
        }
        // KEEPALIVE: link->touch() above already covers it, no reply needed.
    }

    // A message upload from a client: LXMessage.send() for method=PROPAGATED,
    // representation=PACKET sends a plain (context NONE) Link-encrypted DATA
    // packet whose plaintext is msgpack([timestamp, [lxmf_data, ...]]) --
    // see LXMRouter.propagation_packet. Each lxmf_data entry is already
    // dest_hash(16) || Identity.encrypt()'d-to-the-recipient bytes: this
    // node stores it as-is (see cacheIncomingMessage) without decrypting it
    // itself, since it's encrypted to the message's actual recipient, not
    // to this node. On success, replies with a generic packet-delivery
    // proof so the client's PacketReceipt resolves instead of timing out.
    void handlePropagationUpload(const Packet& p, Link* link, Interface* src) {
        std::vector<uint8_t> plaintext = link->decrypt(p.data);
        if (plaintext.empty()) return;

        cmp_ctx_t ctx;
        MsgpackBuffer buf;
        msgpackInitReader(&ctx, &buf, plaintext);
        uint32_t arrLen = 0;
        if (!cmp_read_array(&ctx, &arrLen) || arrLen < 2) return;

        // [0]: remote timebase (float) -- not used, this node has no RTC.
        cmp_object_t obj;
        if (!cmp_read_object(&ctx, &obj)) return;

        std::vector<std::vector<uint8_t>> messages;
        bool wasNil = false;
        if (!cmpReadOptionalBinArray(&ctx, messages, wasNil, 4096) || wasNil) return;

        for (auto& lxmfData : messages) cacheIncomingMessage(lxmfData);

        Packet proof = link->buildPacketProof(id, p);
        src->send(proof.serialize());
    }

    // MESSAGE_GET ("/get"): data = [wants_or_nil, haves_or_nil]. [nil, nil]
    // lists what's available; otherwise haves are purged and wants are
    // streamed back -- see LXMPeer.message_get_request.
    std::vector<uint8_t> handleMessageGet(const std::vector<uint8_t>& dataPayload, Link* link) {
        // Requires LINKIDENTIFY: an anonymous link can't be attributed to a
        // delivery destination, so it can neither list nor fetch anything.
        if (!link->remoteIdentified) return std::vector<uint8_t>();

        std::vector<uint8_t> remoteDeliveryHash = Destination::hash(deliveryNameHash, link->remoteIdentityHash);

        cmp_ctx_t ctx;
        MsgpackBuffer buf;
        msgpackInitReader(&ctx, &buf, dataPayload);
        uint32_t arrLen = 0;
        if (!cmp_read_array(&ctx, &arrLen) || arrLen < 2) return std::vector<uint8_t>();

        std::vector<std::vector<uint8_t>> wants, haves;
        bool wantsNil = true, havesNil = true;
        if (!cmpReadOptionalBinArray(&ctx, wants, wantsNil, 32)) return std::vector<uint8_t>();
        if (!cmpReadOptionalBinArray(&ctx, haves, havesNil, 32)) return std::vector<uint8_t>();

        cmp_ctx_t wctx;
        MsgpackBuffer wbuf;
        msgpackInitWriter(&wctx, &wbuf);

        if (wantsNil && havesNil) {
            std::vector<StoredMessage*> matches;
            for (auto& m : index) {
                if (m.destinationHash == remoteDeliveryHash) matches.push_back(&m);
            }
            cmp_write_array(&wctx, (uint32_t)matches.size());
            for (auto* m : matches) {
                cmp_write_array(&wctx, 2);
                cmp_write_bin(&wctx, m->transientId.data(), (uint32_t)m->transientId.size());
                cmp_write_uinteger(&wctx, (uint64_t)m->size);
            }
            return wbuf.out;
        }

        for (auto& h : haves) removeStoredMessage(h);

        size_t budget = MAX_RESPONSE_BUDGET;
        std::vector<std::vector<uint8_t>> blobs;
        for (auto& w : wants) {
            StoredMessage* m = findByTransientId(w);
            if (!m || m->destinationHash != remoteDeliveryHash) continue;
            if (m->size > budget) continue;
            std::vector<uint8_t> blob = readMessageFile(*m);
            if (blob.empty()) continue;
            blobs.push_back(blob);
            budget -= m->size;
        }
        cmp_write_array(&wctx, (uint32_t)blobs.size());
        for (auto& blob : blobs) cmpWriteBin(&wctx, blob);
        return wbuf.out;
    }

    // Caches one message extracted from an inbound propagation upload.
    // `lxmfData` is dest_hash(16) || Identity.encrypt()'d-to-the-*recipient*
    // bytes -- LXMF's own end-to-end encryption, addressed to whoever the
    // message is actually for. This node never holds that recipient's
    // private key, so it stores the blob opaquely rather than decrypting
    // it (a propagation node is a courier, not a reader).
    void cacheIncomingMessage(const std::vector<uint8_t>& lxmfData) {
        if (lxmfData.size() < LXMF_MIN_SIZE) return;

        std::vector<uint8_t> transientIdFull = Crypto::sha256(lxmfData);
        if (findByTransientId(transientIdFull)) return; // already have it

        std::vector<uint8_t> destinationHash(lxmfData.begin(), lxmfData.begin() + LXMF_DESTINATION_LENGTH);

        if (index.size() >= MAX_STORED_MESSAGES) evictOldest();

        String filename = "/lxmf/" + toHex(transientIdFull) + ".msg";
#if defined(BOARD_SENSECAP_T1000)
        File f(LittleFS.open(filename.c_str(), FILE_O_WRITE));
#else
        File f = LittleFS.open(filename, "w");
#endif
        if (!f) return;
        f.write(lxmfData.data(), lxmfData.size());
        f.close();

        StoredMessage m;
        m.transientId = transientIdFull;
        m.destinationHash = destinationHash;
        m.size = lxmfData.size();
        m.filename = filename;
        index.push_back(m);

        RNS_LOG("LXMF: cached message %s (%u bytes)", toHex(transientIdFull).c_str(), (unsigned)m.size);
    }

    StoredMessage* findByTransientId(const std::vector<uint8_t>& transientId) {
        for (auto& m : index) {
            if (m.transientId == transientId) return &m;
        }
        return nullptr;
    }

    std::vector<uint8_t> readMessageFile(const StoredMessage& m) {
#if defined(BOARD_SENSECAP_T1000)
        File f(LittleFS.open(m.filename.c_str(), FILE_O_READ));
#else
        File f = LittleFS.open(m.filename, "r");
#endif
        if (!f) return std::vector<uint8_t>();
        std::vector<uint8_t> buf(m.size);
        f.read(buf.data(), m.size);
        f.close();
        return buf;
    }

    void removeStoredMessage(const std::vector<uint8_t>& transientId) {
        for (auto it = index.begin(); it != index.end(); ++it) {
            if (it->transientId != transientId) continue;
#if defined(BOARD_SENSECAP_T1000)
            LittleFS.remove(it->filename.c_str());
#else
            LittleFS.remove(it->filename);
#endif
            index.erase(it);
            return;
        }
    }

    void evictOldest() {
        if (index.empty()) return;
        removeStoredMessage(index.front().transientId);
    }

    // Scans /lxmf on boot to rebuild the in-RAM index (destination_hash is
    // the first 16 bytes of every stored file; transient_id is recovered
    // from the filename rather than re-hashing the whole file).
    void rebuildIndex() {
        index.clear();
#if defined(BOARD_SENSECAP_T1000)
        File root(LittleFS.open("/lxmf", FILE_O_READ));
        if (!root || !root.isDirectory()) return;
        File file = root.openNextFile(FILE_O_READ);
#else
        File root = LittleFS.open("/lxmf");
        if (!root || !root.isDirectory()) return;
        File file = root.openNextFile();
#endif
        while (file) {
            if (!file.isDirectory() && file.size() >= LXMF_DESTINATION_LENGTH) {
                StoredMessage m;
                m.size = file.size();
                m.filename = String("/lxmf/") + file.name();
                m.destinationHash.resize(LXMF_DESTINATION_LENGTH);
                file.read(m.destinationHash.data(), LXMF_DESTINATION_LENGTH);

                String nameOnly = file.name();
                int dot = nameOnly.length();
                for (int i = 0; i < (int)nameOnly.length(); i++) {
                    if (nameOnly.c_str()[i] == '.') { dot = i; break; }
                }
                m.transientId = hexToBytesLocal(nameOnly.c_str(), dot);
                if (m.transientId.size() == 32) index.push_back(m);
            }
#if defined(BOARD_SENSECAP_T1000)
            file = root.openNextFile(FILE_O_READ);
#else
            file = root.openNextFile();
#endif
        }
    }

    static std::vector<uint8_t> hexToBytesLocal(const char* s, int len) {
        std::vector<uint8_t> out;
        for (int i = 0; i + 1 < len; i += 2) {
            char hi = s[i], lo = s[i + 1];
            auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hv = nib(hi), lv = nib(lo);
            if (hv < 0 || lv < 0) return std::vector<uint8_t>();
            out.push_back((uint8_t)((hv << 4) | lv));
        }
        return out;
    }
};

}
