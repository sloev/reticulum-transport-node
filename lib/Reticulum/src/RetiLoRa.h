#pragma once
#include <RadioLib.h>
#include "RetiInterface.h"
namespace Reticulum {
class LoRaInterface : public Interface {
    SX1262* r;
    volatile bool f = false;
public:
    LoRaInterface(SX1262* radio) : Interface("LoRa"), r(radio) {}
    bool begin(float freq) {
        if(r->begin(freq, 125.0, 9, 5, 0x12, 22, 8) != RADIOLIB_ERR_NONE) return false;
        r->setDio2AsRfSwitch(true); r->setCRC(true); return true;
    }
    void start(void (*isr)()) { r->setPacketReceivedAction(isr); r->startReceive(); }
    void setFlag() { f = true; }
    void tx(std::vector<uint8_t> d) override { r->standby(); r->transmit(d.data(), d.size()); r->startReceive(); }
    void handle() {
        if(f) { f=false; size_t l=r->getPacketLength(); uint8_t b[256]; r->readData(b,l); rx({b,b+l}); r->startReceive(); }
    }
};
}
