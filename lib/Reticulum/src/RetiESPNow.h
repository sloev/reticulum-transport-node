#pragma once
#include <esp_now.h>
#include <WiFi.h>
#include "RetiInterface.h"

namespace Reticulum {

class ESPNowInterface : public Interface {
    static ESPNowInterface* instance;
public:
    ESPNowInterface() : Interface("ESP-NOW", 250) { instance = this; }

    bool begin() {
        if (WiFi.getMode() == WIFI_MODE_NULL) {
            WiFi.mode(WIFI_STA);
        }
        
        if (esp_now_init() != ESP_OK) return false;

        esp_now_peer_info_t peer = {};
        memset(&peer, 0, sizeof(peer));
        for(int i=0; i<6; i++) peer.peer_addr[i] = 0xFF; // Broadcast
        peer.channel = 0; // Must match WiFi channel
        peer.encrypt = false;

        if (esp_now_add_peer(&peer) != ESP_OK) return false;
        
        esp_now_register_recv_cb(on_recv);
        return true;
    }

    static void on_recv(const uint8_t *mac, const uint8_t *data, int len) {
        if (instance) instance->receive(std::vector<uint8_t>(data, data+len));
    }

    void sendRaw(const std::vector<uint8_t>& data) override {
        const uint8_t dest[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        esp_now_send(dest, data.data(), data.size());
    }
};
ESPNowInterface* ESPNowInterface::instance = nullptr;
}