#pragma once
#include "RetiIdentity.h"
#include "RetiAnnounce.h"
#include "RetiLink.h"
#include "RetiStorage.h"
#include "RetiPacket.h"
#include <map>

namespace Reticulum {

class LXMFPropagationNode;

class Router {
public:
    // Matches RNS's conventional path-hop bound (RNS.Transport.PATHFINDER_M);
    // hops is a full wire byte (0-255), so this is a sanity ceiling against
    // routing loops/garbage, not a tuned mesh-diameter estimate.
    static constexpr uint8_t MAX_HOPS = 128;

    Identity* id;
    Storage storage;
    std::vector<Interface*> interfaces;
    std::function<void(const std::vector<uint8_t>&, const Packet&, Interface*)> onLocalDelivery;

    // Flood Control: Packet Hash (16 bytes) -> Timestamp
    // Cap size to prevent heap exhaustion under flood attacks.
    std::map<std::vector<uint8_t>, unsigned long> seen;
    const size_t MAX_SEEN_ENTRIES = 512;

    std::map<String, Link*> links;

    struct PendingBroadcast {
        std::vector<uint8_t> raw;
        Interface* excludeSrc;
        unsigned long dueAt;
    };
    std::vector<PendingBroadcast> pendingBroadcasts;

    Router(Identity* i) : id(i) {}

    void addInterface(Interface* i) {
        interfaces.push_back(i);
        i->onPacket = [this](const std::vector<uint8_t>& d, Interface* src) {
            this->process(d, src);
        };
    }

    void process(const std::vector<uint8_t>& raw, Interface* src) {
        Packet p = Packet::parse(raw);

        // 1. Flood Control. Dedup on the hashable part (RNS.Packet.getTruncatedHash),
        // not the raw bytes: hops (and header flags) legitimately change as a packet
        // is forwarded hop to hop, so hashing raw bytes would treat the same
        // logical packet arriving via two different paths as two different packets.
        std::vector<uint8_t> h = p.getTruncatedHash();
        if (seen.count(h)) return;

        // Hard Limit: If table full, force GC immediately, else drop oldest
        if (seen.size() >= MAX_SEEN_ENTRIES) cleanup(true);
        seen[h] = millis();

        // Local Delivery Hook (e.g. for LXMF)
        if (onLocalDelivery) {
            onLocalDelivery(raw, p, src);
        }

        // Link Establishment (Simplified)
        if (p.type == LINK_REQ) {
            // In a full implementation, check if destination matches 'id'
            // For repeater mode, we generally just forward.
        }

        // 3. Forwarding. Increment hops and drop packets that have travelled
        // too far (loop/garbage protection -- see RNS Manual 6.7.4).
        if (p.hops >= MAX_HOPS) return;
        std::vector<uint8_t> forwarded = raw;
        forwarded[1] = p.hops + 1;

        if (p.type == ANNOUNCE) {
            // Jittered rebroadcast to avoid every neighbour that heard the
            // same announce retransmitting in the same instant and colliding
            // on a shared-medium mesh -- see RNS Manual 6.7.4, Announce
            // Propagation Rules.
            unsigned long jitter = 200 + ((unsigned long)RETI_RANDOM() * 800UL / 255UL);
            pendingBroadcasts.push_back({forwarded, src, millis() + jitter});
        } else {
            for (auto* iface : interfaces) {
                if (iface != src) iface->send(forwarded);
            }
        }
    }

    // Builds, signs, and transmits an announce for a SINGLE destination. See
    // RetiAnnounce.h for the wire format (RNS.Destination.announce()).
    void sendAnnounce(const std::vector<uint8_t>& destHash, const std::vector<uint8_t>& nameHash10,
                       const std::vector<uint8_t>& appData = std::vector<uint8_t>()) {
        id->rotateRatchets();
        Packet p = Announce::build(id, destHash, nameHash10, appData, id->latestRatchetPublic());
        std::vector<uint8_t> raw = p.serialize();
        for (auto* iface : interfaces) iface->send(raw);
    }

    void loop() {
        unsigned long now = millis();

        // Flush any jittered announce rebroadcasts that have come due.
        for (auto it = pendingBroadcasts.begin(); it != pendingBroadcasts.end(); ) {
            if (now >= it->dueAt) {
                for (auto* iface : interfaces) {
                    if (iface != it->excludeSrc) iface->send(it->raw);
                }
                it = pendingBroadcasts.erase(it);
            } else {
                ++it;
            }
        }

        // Periodic cleanup (every 10s)
        static unsigned long last_gc = 0;
        if (now - last_gc > 10000) {
            cleanup(false);
            last_gc = now;
        }
    }

private:
    void cleanup(bool force) {
        unsigned long now = millis();
        auto it = seen.begin();
        while (it != seen.end()) {
            // Drop if older than 60s, or if forcing space (drop oldest)
            if (force || (now - it->second > 60000)) {
                it = seen.erase(it);
                if (force) return; // Deleted one, good enough
            } else {
                ++it;
            }
        }
    }
};
}
