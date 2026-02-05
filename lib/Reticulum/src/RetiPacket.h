#pragma once
#include <vector>
#include <Arduino.h>

namespace Reticulum {
enum PacketType { DATA=0, ANNOUNCE=1, LINK_REQ=2, PROOF=3 };
enum DestType { SINGLE=0, GROUP=1, PLAIN=2, LINK=3 };

class Packet {
public:
    uint8_t hops=0;
    uint8_t type=DATA, destType=SINGLE;
    bool contextFlag=false;
    uint8_t context=0;
    std::vector<uint8_t> addresses;
    std::vector<uint8_t> data;

    static Packet parse(const std::vector<uint8_t>& raw) {
        Packet p;
        if(raw.size()<2) return p;
        uint8_t h = raw[0];
        p.hops = raw[1];
        bool headerType = (h>>6)&1;
        p.contextFlag = (h>>5)&1;
        p.destType = (h>>2)&3;
        p.type = h&3;
        
        size_t ptr = 2;
        int addrLen = headerType ? 32 : 16;
        if(ptr+addrLen <= raw.size()) {
            p.addresses.assign(raw.begin()+ptr, raw.begin()+ptr+addrLen);
            ptr+=addrLen;
        }
        if(p.contextFlag && ptr < raw.size()) p.context = raw[ptr++];
        if(ptr < raw.size()) p.data.assign(raw.begin()+ptr, raw.end());
        return p;
    }
    
    std::vector<uint8_t> serialize() {
        std::vector<uint8_t> b;
        uint8_t h = (0<<7) | ( (addresses.size()==32?1:0)<<6 ) | ( (contextFlag?1:0)<<5 ) | 0;
        h |= (destType&3)<<2;
        h |= (type&3);
        b.push_back(h);
        b.push_back(hops);
        b.insert(b.end(), addresses.begin(), addresses.end());
        if(contextFlag) b.push_back(context);
        b.insert(b.end(), data.begin(), data.end());
        return b;
    }
    
    static Packet createAnnounce(Identity& id) {
        Packet p; p.type=ANNOUNCE; p.destType=PLAIN;
        p.data = id.getPublicKey();
        for(int i=0;i<10;i++) p.data.push_back((uint8_t)esp_random());
        return p;
    }
};
}
