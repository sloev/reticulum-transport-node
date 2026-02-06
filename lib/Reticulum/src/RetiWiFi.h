#pragma once
#include <WiFi.h>
#include <WiFiUdp.h>
#include "RetiInterface.h"
#include "RetiConfig.h"

namespace Reticulum {
class WiFiDriver : public Interface {
    WiFiUDP udp;
    bool active = false;
public:
    WiFiDriver() : Interface("WiFi_UDP", 1200) {} // Standard RNS UDP MTU

    void begin(Config& cfg) {
        if(cfg.networks.empty()) return;
        
        WiFi.mode(WIFI_STA);
        for(auto& n : cfg.networks) WiFi.begin(n.ssid.c_str(), n.pass.c_str());
        
        // NTP Sync for Crypto
        configTime(0, 0, "pool.ntp.org", "time.nist.gov");
        
        udp.begin(4242);
        active = true;
    }

    void sendRaw(const std::vector<uint8_t>& data) override {
        if(WiFi.status() == WL_CONNECTED && active) {
            udp.beginPacket(IPAddress(255,255,255,255), 4242);
            udp.write(data.data(), data.size());
            udp.endPacket();
        }
    }

    void loop() {
        if(active) {
            int len = udp.parsePacket();
            if(len > 0) {
                std::vector<uint8_t> buf(len);
                udp.read(buf.data(), len);
                receive(buf);
            }
        }
    }
};
}