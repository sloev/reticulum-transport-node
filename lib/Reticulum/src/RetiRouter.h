#pragma once
#include "RetiIdentity.h"
#include "RetiLink.h"
#include "RetiStorage.h"
#include "RetiPacket.h"
#include <map>

namespace Reticulum {

class Router {
public:
    Identity* id;
    Storage storage;
    std::vector<Interface*> interfaces;
    
    // Flood Control: Packet Hash (16 bytes) -> Timestamp
    // Cap size to prevent heap exhaustion under flood attacks.
    std::map<std::vector<uint8_t>, unsigned long> seen;
    const size_t MAX_SEEN_ENTRIES = 512;
    
    std::map<String, Link*> links;

    Router(Identity* i) : id(i) {}

    void addInterface(Interface* i) {
        interfaces.push_back(i);
        i->onPacket = [this](const std::vector<uint8_t>& d, Interface* src) {
            this->process(d, src);
        };
    }

    void process(const std::vector<uint8_t>& raw, Interface* src) {
        // 1. Flood Control
        std::vector<uint8_t> h = Crypto::sha256(raw);
        h.resize(16); // Truncate to 128-bit for storage efficiency
        
        if(seen.count(h)) return;

        // Hard Limit: If table full, force GC immediately, else drop oldest
        if (seen.size() >= MAX_SEEN_ENTRIES) cleanup(true);
        seen[h] = millis();

        // 2. Parse & Logic
        Packet p = Packet::parse(raw);
        
        // Link Establishment (Simplified)
        if(p.type == LINK_REQ) {
             // In a full implementation, check if destination matches 'id'
             // For repeater mode, we generally just forward.
        }
        
        // 3. Forwarding
        for(auto* iface : interfaces) {
            if(iface != src) iface->send(raw);
        }
    }
    
    void sendAnnounce() {
        Packet p; p.type=ANNOUNCE; p.destType=PLAIN;
        p.data = id->getPublicKey();
        // Add random bloom noise
        for(int i=0;i<10;i++) p.data.push_back((uint8_t)esp_random());
        
        std::vector<uint8_t> raw = p.serialize();
        for(auto* iface : interfaces) iface->send(raw);
    }
    
    void loop() {
        // Periodic cleanup (every 10s)
        static unsigned long last_gc = 0;
        if (millis() - last_gc > 10000) {
            cleanup(false);
            last_gc = millis();
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