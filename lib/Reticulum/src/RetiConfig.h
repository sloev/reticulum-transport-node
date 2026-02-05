#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <vector>

namespace Reticulum {
struct WiFiCred { String ssid; String pass; };
struct Config {
    float loraFreq = 915.0;
    std::vector<WiFiCred> networks; 
    void load() {
        if (!LittleFS.exists("/config.json")) { save(); return; }
        File f = LittleFS.open("/config.json", "r");
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
        File f = LittleFS.open("/config.json", "w");
        serializeJson(doc, f);
        f.close();
    }
};
}
