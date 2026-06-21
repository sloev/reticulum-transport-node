#pragma once
#include <RadioLib.h>
#include "RetiInterface.h"

namespace Reticulum {

#if defined(BOARD_SENSECAP_T1000)
typedef LR1110 RadioType;
#else
typedef SX1262 RadioType;
#endif

class LoRaInterface : public Interface {
    RadioType* radio;
    volatile bool rxFlag = false;

public:
    // MTU 255 triggers split logic for 500-byte packets
    LoRaInterface(RadioType* r) : Interface("LoRa", 255), radio(r) {}

    bool begin(float freq) {
        int state = radio->begin(freq, 125.0, 9, 5, 0x12, 22, 8);
        if(state != RADIOLIB_ERR_NONE) return false;
        
#if !defined(BOARD_SENSECAP_T1000)
        radio->setDio2AsRfSwitch(true);
#endif
        radio->setCRC(true);
        return true;
    }

    void start(void (*isr)()) {
        radio->setPacketReceivedAction(isr);
        radio->startReceive();
    }
    
    void setFlag() { rxFlag = true; }

    void sendRaw(const std::vector<uint8_t>& data) override {
        radio->standby();
        radio->transmit(const_cast<uint8_t*>(data.data()), data.size());
        radio->startReceive();
    }

    void handle() {
        if(rxFlag) {
            rxFlag = false;
            size_t len = radio->getPacketLength();
            uint8_t buf[256];
            radio->readData(buf, len);
            receive(std::vector<uint8_t>(buf, buf+len));
            radio->startReceive();
        }
    }
};
}