#pragma once
#include "RetiCommon.h"
#include <ArduinoJson.h>
#include <vector>

namespace Reticulum {
struct WiFiCred { String ssid; String pass; };
struct Config {
    float loraFreq = 915.0;
    std::vector<WiFiCred> networks;
    void load() {
        if (!LittleFS.exists("/config.json")) { save(); return; }
#if defined(BOARD_SENSECAP_T1000)
        File f(LittleFS.open("/config.json", FILE_O_READ));
#else
        File f = LittleFS.open("/config.json", "r");
#endif
        DynamicJsonDocument doc(2048);
        deserializeJson(doc, f);
        f.close();
        loraFreq = doc["lora"]["freq"] | 915.0;
        networks.clear();
        JsonArray nets = doc["wifi"].as<JsonArray>();
        for (JsonObject n : nets) {
            WiFiCred c; c.ssid = n["ssid"].as<String>(); c.pass = n["pass"].as<String>();
            networks.push_back(c);
        }
    }
    void save() {
        DynamicJsonDocument doc(2048);
        doc["lora"]["freq"] = loraFreq;
        JsonArray nets = doc.createNestedArray("wifi");
        for (const auto& c : networks) {
            JsonObject n = nets.createNestedObject(); n["ssid"] = c.ssid; n["pass"] = c.pass;
        }
#if defined(BOARD_SENSECAP_T1000)
        File f(LittleFS.open("/config.json", FILE_O_WRITE));
#else
        File f = LittleFS.open("/config.json", "w");
#endif
        serializeJson(doc, f);
        f.close();
    }
};
}
