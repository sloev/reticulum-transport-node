#pragma once
#include "RetiIdentity.h"
#include "RetiLink.h"
#include "RetiStorage.h"
#include "RetiPacket.h"

namespace Reticulum {
class Router {
public:
    Identity* id;
    Storage storage;
    std::vector<Interface*> interfaces;
    
    // Hash -> Interface
    std::map<String, Interface*> table; 
    
    // Seen Packets (Flood Control)
    std::map<String, unsigned long> seen;

    // Links
    std::map<String, Link*> links;

    Router(Identity* i) : id(i) {}

    void addInterface(Interface* i) {
        interfaces.push_back(i);
        i->onPacket = [this](const std::vector<uint8_t>& d, Interface* src) {
            this->process(d, src);
        };
    }

    void process(const std::vector<uint8_t>& raw, Interface* src) {
        std::vector<uint8_t> h = Crypto::sha256(raw);
        String hStr = toHex(h);
        if(seen.count(hStr)) return;
        seen[hStr] = millis();

        Packet p = Packet::parse(raw);
        bool forMe = false; // Logic simplified for brevity
        
        if(p.type == LINK_REQ && forMe) {
             Link* l = new Link(p.addresses);
             l->accept(p.data, h);
             links[toHex(p.addresses)] = l;
             // Send Proof...
        }
        
        if(!forMe) {
             // Forward logic
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
        // Storage maintenance
    }
};

// Implement Packet::createAnnounce logic if needed, but simplified above.
// Implement Link::createProof logic here to handle circular dependency if strict.
}
