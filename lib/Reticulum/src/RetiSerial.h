#pragma once
#include "RetiInterface.h"
namespace Reticulum {
const uint8_t FEND=0xC0, FESC=0xDB, TFEND=0xDC, TFESC=0xDD;
class SerialInterface : public Interface {
    Stream* s;
    std::vector<uint8_t> buf;
    bool esc=false;
public:
    SerialInterface(Stream* st) : Interface("Serial"), s(st) {}
    void sendRaw(const std::vector<uint8_t>& d) override {
        s->write(FEND); s->write(0x00);
        for(uint8_t b:d) {
            if(b==FEND) { s->write(FESC); s->write(TFEND); }
            else if(b==FESC) { s->write(FESC); s->write(TFESC); }
            else s->write(b);
        }
        s->write(FEND);
    }
    void loop() {
        while(s->available()) {
            uint8_t b = s->read();
            if(b==FEND) { if(buf.size()>1) receive({buf.begin()+1, buf.end()}); buf.clear(); esc=false; }
            else if(b==FESC) esc=true;
            else { if(esc) { b=(b==TFEND)?FEND:FESC; esc=false; } buf.push_back(b); }
        }
    }
};
}
