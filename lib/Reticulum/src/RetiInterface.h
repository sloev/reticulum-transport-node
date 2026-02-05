#pragma once
#include "RetiCommon.h"
#include <map>
#include <functional>

namespace Reticulum {

const uint8_t FRAG_MAGIC = 0xBB;
const size_t HW_MTU = 240; 

class Interface {
protected:
    struct FragState {
        uint8_t total;
        uint8_t count;
        unsigned long ts;
        std::map<uint8_t, std::vector<uint8_t>> parts;
    };
    std::map<uint8_t, FragState> frags;

public:
    String name;
    std::function<void(const std::vector<uint8_t>&, Interface*)> onPacket;

    Interface(String n) : name(n) {}
    virtual void sendRaw(const std::vector<uint8_t>& data) = 0;

    void send(const std::vector<uint8_t>& packet) {
        if (packet.size() <= HW_MTU) {
            sendRaw(packet);
        } else {
            // Fragment
            uint8_t ref = esp_random() & 0xFF;
            uint8_t total = (packet.size() + HW_MTU - 1) / HW_MTU;
            for(uint8_t i=0; i<total; i++) {
                size_t offset = i * HW_MTU;
                size_t len = min(HW_MTU, packet.size() - offset);
                std::vector<uint8_t> f = {FRAG_MAGIC, total, ref, i};
                f.insert(f.end(), packet.begin()+offset, packet.begin()+offset+len);
                sendRaw(f);
                delay(10); // Small airtime gap
            }
        }
    }

    void receive(const std::vector<uint8_t>& data) {
        if(data.size() > 4 && data[0] == FRAG_MAGIC) {
            uint8_t total=data[1], ref=data[2], seq=data[3];
            FragState& s = frags[ref];
            s.total = total; s.ts = millis();
            
            if(s.parts.find(seq) == s.parts.end()) {
                s.parts[seq] = std::vector<uint8_t>(data.begin()+4, data.end());
                s.count++;
            }
            
            if(s.count == total) {
                std::vector<uint8_t> full;
                for(int i=0; i<total; i++) full.insert(full.end(), s.parts[i].begin(), s.parts[i].end());
                if(onPacket) onPacket(full, this);
                frags.erase(ref);
            }
        } else {
            if(onPacket) onPacket(data, this);
        }
    }
};
}
