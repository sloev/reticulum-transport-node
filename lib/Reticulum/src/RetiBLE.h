#pragma once
#include "RetiInterface.h"

#if defined(BOARD_SENSECAP_T1000)
// NimBLE-Arduino targets ESP32; the Adafruit nRF52 core brings its own
// Bluefruit BLE stack (with the softdevice), so we drive that instead.
#include <bluefruit.h>

namespace Reticulum {

class BLEInterface : public Interface {
    BLEUart bleuart;
    bool connected = false;
    std::vector<uint8_t> buf;

public:
    BLEInterface() : Interface("BLE", 500) {}

    void begin() {
        Bluefruit.begin();
        Bluefruit.setName("RNS Node");

        bleuart.begin();

        Bluefruit.Advertising.addFlags(BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE);
        Bluefruit.Advertising.addTxPower();
        Bluefruit.Advertising.addService(bleuart);
        Bluefruit.Advertising.addName();
        Bluefruit.Advertising.restartOnDisconnect(true);
        Bluefruit.Advertising.setInterval(32, 244);
        Bluefruit.Advertising.setFastTimeout(30);
        Bluefruit.Advertising.start(0);
    }

    void loop() {
        connected = Bluefruit.connected();
        if(!connected) return;

        while(bleuart.available()) {
            uint8_t b = bleuart.read();
            if(b==0xC0) { if(buf.size()>0) receive(buf); buf.clear(); }
            else buf.push_back(b);
        }
    }

    void sendRaw(const std::vector<uint8_t>& d) override {
        if(!connected) return;
        std::vector<uint8_t> k = {0xC0};
        for(uint8_t b:d) { if(b==0xC0){k.push_back(0xDB);k.push_back(0xDC);} else k.push_back(b); }
        k.push_back(0xC0);
        for(size_t i=0; i<k.size(); i+=20) {
            bleuart.write(k.data()+i, min((size_t)20, k.size()-i));
            delay(5);
        }
    }
};
}

#else
#include <NimBLEDevice.h>

namespace Reticulum {

class BLEInterface : public Interface, public NimBLEServerCallbacks, public NimBLECharacteristicCallbacks {
    NimBLECharacteristic *pTx, *pRx;
    bool connected = false;
    std::vector<uint8_t> buf;
    bool esc=false;

public:
    // FIX: Added MTU 500 (Standard Sideband/NUS MTU)
    BLEInterface() : Interface("BLE", 500) {}

    void begin() {
        NimBLEDevice::init("RNS Node");
        NimBLEServer* pServer = NimBLEDevice::createServer();
        pServer->setCallbacks(this);
        NimBLEService* pSvc = pServer->createService("6E400001-B5A3-F393-E0A9-E50E24DCCA9E");
        pTx = pSvc->createCharacteristic("6E400003-B5A3-F393-E0A9-E50E24DCCA9E", NIMBLE_PROPERTY::NOTIFY);
        pRx = pSvc->createCharacteristic("6E400002-B5A3-F393-E0A9-E50E24DCCA9E", NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
        pRx->setCallbacks(this);
        pSvc->start();
        NimBLEDevice::startAdvertising();
    }
    void onConnect(NimBLEServer*) override { connected=true; }
    void onDisconnect(NimBLEServer*) override { connected=false; NimBLEDevice::startAdvertising(); }
    void onWrite(NimBLECharacteristic* pC) override {
        std::string v = pC->getValue();
        for(char c : v) {
            uint8_t b = (uint8_t)c;
            if(b==0xC0) { if(buf.size()>0) receive(buf); buf.clear(); esc=false; }
            else buf.push_back(b);
        }
    }
    void sendRaw(const std::vector<uint8_t>& d) override {
        if(!connected) return;
        std::vector<uint8_t> k = {0xC0};
        for(uint8_t b:d) { if(b==0xC0){k.push_back(0xDB);k.push_back(0xDC);} else k.push_back(b); }
        k.push_back(0xC0);
        for(size_t i=0; i<k.size(); i+=20) {
            pTx->setValue(k.data()+i, min((size_t)20, k.size()-i));
            pTx->notify();
            delay(5);
        }
    }
};
}
#endif
