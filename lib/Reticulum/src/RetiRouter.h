#pragma once
#include "RetiLink.h"
#include "RetiStorage.h"
namespace Reticulum {
class Router {
    Identity* id;
public:
    Storage st;
    std::vector<Interface*> ifs;
    std::map<String, Link*> links;
    std::map<String, Interface*> table;
    std::map<String, unsigned long> seen;

    Router(Identity* i) : id(i) {}
    void add(Interface* i) { ifs.push_back(i); i->cb = [this](std::vector<uint8_t> d, Interface* s){ process(d,s); }; }
    
    void process(std::vector<uint8_t> raw, Interface* src) {
        String h = toHex(Crypto::sha256(raw));
        if(seen.count(h)) return; seen[h]=millis();
        
        Packet p = Packet::parse(raw);
        bool forMe = false;
        
        if(p.type == LINK_REQ && forMe) {
            Link* l = new Link(p.addresses);
            l->accept(p.data, Crypto::sha256(raw)); 
            links[toHex(p.addresses)] = l;
            src->send(l->createProof(*id).serialize());
        }
        
        if(!forMe) {
             for(auto* i : ifs) if(i!=src) i->send(raw);
        }
    }
    
    void announce() {
        std::vector<uint8_t> d = Packet::createAnnounce(*id).serialize();
        for(auto* i : ifs) i->send(d);
    }
    
    void loop() { st.flush(); }
};
}
