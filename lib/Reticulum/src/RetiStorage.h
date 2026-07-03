#pragma once
#include "RetiCommon.h"
#include <list>

namespace Reticulum {

struct CachedMsg {
    String dest;
    std::vector<uint8_t> data;
    unsigned long ts;
    bool dirty;
};

class Storage {
    std::list<CachedMsg> cache;
    const size_t MAX_CACHE = 15;

public:
    void begin() { RETI_FS_BEGIN(); if(!LittleFS.exists("/msg")) LittleFS.mkdir("/msg"); }

    void store(const String& dest, const std::vector<uint8_t>& pkt) {
        if(cache.size() >= MAX_CACHE) flushOne();
        cache.push_back({dest, pkt, millis(), true});
        RNS_LOG("Stored packet in RAM cache.");
    }

    std::vector<std::vector<uint8_t>> retrieve(const String& dest) {
        std::vector<std::vector<uint8_t>> res;

        // 1. RAM
        auto it = cache.begin();
        while(it != cache.end()) {
            if(it->dest == dest) {
                res.push_back(it->data);
                it = cache.erase(it);
            } else ++it;
        }

        // 2. Disk
#if defined(BOARD_SENSECAP_T1000)
        File root(LittleFS.open("/msg", FILE_O_READ));
        File f = root.openNextFile(FILE_O_READ);
#else
        File root = LittleFS.open("/msg");
        File f = root.openNextFile();
#endif
        while(f) {
            String name = f.name();
            if(name.startsWith(dest)) {
                size_t sz = f.size();
                std::vector<uint8_t> buf(sz);
                f.read(buf.data(), sz);
                res.push_back(buf);
#if defined(BOARD_SENSECAP_T1000)
                LittleFS.remove((String("/msg/")+name).c_str());
#else
                LittleFS.remove(String("/msg/")+name);
#endif
            }
#if defined(BOARD_SENSECAP_T1000)
            f = root.openNextFile(FILE_O_READ);
#else
            f = root.openNextFile();
#endif
        }
        return res;
    }

    void flushOne() {
        for(auto& m : cache) {
            if(m.dirty) {
                String path = "/msg/" + m.dest + "_" + String(millis());
#if defined(BOARD_SENSECAP_T1000)
                File f(LittleFS.open(path.c_str(), FILE_O_WRITE));
#else
                File f = LittleFS.open(path, "w");
#endif
                f.write(m.data.data(), m.data.size());
                f.close();
                m.dirty = false;
                return;
            }
        }
        cache.pop_front();
    }
    
    void loop() {
         // Periodic flush logic can go here
    }
};
}
