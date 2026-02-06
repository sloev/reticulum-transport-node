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
    
    // Hash (Binary) -> Timestamp
    std::map<std::vector<uint8_t>, unsigned long> seen;
    
    // Active Links
    std::map<String, Link*> links;

    Router(Identity* i) : id(i) {}

    void addInterface(Interface* i) {
        interfaces.push_back(i);
        i->onPacket = [this](const std::vector<uint8_t>& d, Interface* src) {
            this->process(d, src);
        };
    }

    void process(const std::vector<uint8_t>& raw, Interface* src) {
        // 1. Flood Control (Memory Optimized)
        std::vector<uint8_t> h = Crypto::sha256(raw);
        
        // Truncate hash to 16 bytes to save RAM (RNS collisions negligible here)
        h.resize(16); 
        
        if(seen.count(h)) return;
        seen[h] = millis();

        Packet p = Packet::parse(raw);
        bool forMe = false; // Add destination check logic here if needed
        
        if(p.type == LINK_REQ && forMe) {
             Link* l = new Link(p.addresses);
             // Use full hash for crypto binding
             l->accept(p.data, Crypto::sha256(raw)); 
             links[toHex(p.addresses)] = l;
        }
        
        if(!forMe) {
             // Flood to all other interfaces
             for(auto* iface : interfaces) {
                 if(iface != src) iface->send(raw);
             }
        }
    }
    
    void sendAnnounce() {
        Packet p; p.type=ANNOUNCE; p.destType=PLAIN;
        p.data = id->getPublicKey();
        for(int i=0;i<10;i++) p.data.push_back((uint8_t)esp_random());
        std::vector<uint8_t> raw = p.serialize();
        for(auto* iface : interfaces) iface->send(raw);
    }
    
    void loop() {
        // 1. Storage Maintenance
        // storage.loop();

        // 2. Routing Table Garbage Collection (CRITICAL)
        // Run every 10 seconds
        static unsigned long last_gc = 0;
        if (millis() - last_gc > 10000) {
            last_gc = millis();
            auto it = seen.begin();
            while (it != seen.end()) {
                // RNS packet lifetime is usually short, drop after 60s
                if (millis() - it->second > 60000) {
                    it = seen.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
};
}