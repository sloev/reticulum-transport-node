#include <Arduino.h>
#include <RadioLib.h>
#include <LittleFS.h>
#include "BoardConfig.h"
#include "Reti.h"

// Hardware
SX1262 radio = new Module(PIN_LORA_NSS, PIN_LORA_DIO1, PIN_LORA_RST, PIN_LORA_BUSY);

// Stack
Reticulum::Identity* id;
Reticulum::Config config;
Reticulum::Router* router;

// Interfaces
Reticulum::LoRaInterface* lora;
Reticulum::SerialInterface* usb;
Reticulum::BLEInterface* ble;
Reticulum::WiFiDriver* wifi;
Reticulum::ESPNowInterface* espnow;

void IRAM_ATTR isr_lora() { if(lora) lora->setFlag(); }

void setup() {
    Serial.begin(115200);
    delay(1000);
    LittleFS.begin(true);
    config.load();

    // 1. Core
    id = new Reticulum::Identity();
    
    // 2. Hardware Drivers
    SPI.begin(PIN_LORA_SCK, PIN_LORA_MISO, PIN_LORA_MOSI, PIN_LORA_NSS);
    lora = new Reticulum::LoRaInterface(&radio);
    if(!lora->begin(config.loraFreq)) while(1);
    lora->start(isr_lora);

    usb = new Reticulum::SerialInterface(&Serial);
    ble = new Reticulum::BLEInterface(); ble->begin();
    
    // 3. Network Drivers (WiFi + ESP-NOW)
    wifi = new Reticulum::WiFiDriver(); wifi->begin(config);
    espnow = new Reticulum::ESPNowInterface(); espnow->begin();

    // 4. Routing
    router = new Reticulum::Router(id);
    router->addInterface(lora);
    router->addInterface(usb);
    router->addInterface(ble);
    router->addInterface(wifi);
    router->addInterface(espnow);
    
    router->storage.begin();
    router->sendAnnounce();
    
    RNS_LOG("RNS Node Online. Addr: %s", Reticulum::toHex(id->getAddress()).c_str());
}

void loop() {
    lora->handle();
    usb->loop();
    wifi->loop();
    router->loop();
}