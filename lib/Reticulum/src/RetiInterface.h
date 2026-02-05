#pragma once
#include "RetiCommon.h"
#include <map>
#include <functional>

namespace Reticulum {
const uint8_t FRAG_MAGIC = 0xBB;
const size_t HW_MTU = 240;

class Interface {
    struct Frag { uint8_t tot, cnt; std::map<uint8_t,std::vector<uint8_t>> p; };
    std::map<uint8_t, Frag> pend;
public:
    String name;
    std::function<void(std::vector<uint8_t>, Interface*)> cb;
    Interface(String n) : name(n) {}
    virtual void tx(std::vector<uint8_t> d) = 0;

    void send(std::vector<uint8_t> d) {
        if(d.size() <= HW_MTU) { tx(d); return; }
        uint8_t ref = esp_random();
        uint8_t tot = (d.size()+HW_MTU-1)/HW_MTU;
        for(uint8_t i=0; i<tot; i++) {
            size_t off = i*HW_MTU;
            size_t len = min(HW_MTU, d.size()-off);
            std::vector<uint8_t> f = {FRAG_MAGIC, tot, ref, i};
            f.insert(f.end(), d.begin()+off, d.begin()+off+len);
            tx(f); delay(15);
        }
    }

    void rx(std::vector<uint8_t> d) {
        if(d.size()>4 && d[0]==FRAG_MAGIC) {
            uint8_t tot=d[1], ref=d[2], seq=d[3];
            Frag& f = pend[ref]; f.tot=tot;
            if(f.p.find(seq)==f.p.end()) { f.p[seq].assign(d.begin()+4, d.end()); f.cnt++; }
            if(f.cnt==tot) {
                std::vector<uint8_t> full;
                for(int i=0;i<tot;i++) full.insert(full.end(), f.p[i].begin(), f.p[i].end());
                if(cb) cb(full, this);
                pend.erase(ref);
            }
        } else if(cb) cb(d, this);
    }
};
}
