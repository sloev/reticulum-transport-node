#include <Arduino.h>
#include <RadioLib.h>
#include <LittleFS.h>
#include "BoardConfig.h"
#include "Reti.h"

// Hardware
SX1262 radio = new Module(PIN_LORA_NSS, PIN_LORA_DIO1, PIN_LORA_RST, PIN_LORA_BUSY);

Reticulum::Identity* id;
Reticulum::Config config;
Reticulum::LoRaInterface* lora;
Reticulum::SerialInterface* usb;
Reticulum::BLEInterface* ble;
Reticulum::WiFiDriver* wifi;
Reticulum::Router* router;

void IRAM_ATTR setRx() { if(lora) lora->setFlag(); }

void setup() {
    Serial.begin(115200);
    delay(1000);
    LittleFS.begin(true);
    config.load();

    id = new Reticulum::Identity();
    
    SPI.begin(PIN_LORA_SCK, PIN_LORA_MISO, PIN_LORA_MOSI, PIN_LORA_NSS);
    lora = new Reticulum::LoRaInterface(&radio);
    if(!lora->begin(config.loraFreq)) while(1);
    lora->start(setRx);
    
    usb = new Reticulum::SerialInterface(&Serial);
    ble = new Reticulum::BLEInterface(); ble->begin();
    wifi = new Reticulum::WiFiDriver(); wifi->begin(config);
    
    router = new Reticulum::Router(id);
    router->addInterface(lora);
    router->addInterface(usb);
    router->addInterface(ble);
    router->addInterface(wifi);
    router->storage.begin();
    
    router->sendAnnounce();
    RNS_LOG("Node Active.");
}

void loop() {
    lora->handle();
    usb->loop();
    wifi->loop();
    router->loop();
}
