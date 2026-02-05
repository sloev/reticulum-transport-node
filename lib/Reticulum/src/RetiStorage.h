#pragma once
#include "RetiCommon.h"
#include <LittleFS.h>
#include <list>
namespace Reticulum {
struct Cache { String d; std::vector<uint8_t> p; bool dirty; };
class Storage {
    std::list<Cache> c;
public:
    void begin() { LittleFS.begin(true); if(!LittleFS.exists("/m")) LittleFS.mkdir("/m"); }
    void store(String d, std::vector<uint8_t> p) {
        c.push_back({d,p,true});
        if(c.size()>20) flush();
    }
    std::vector<std::vector<uint8_t>> get(String d) {
        std::vector<std::vector<uint8_t>> r;
        File root=LittleFS.open("/m"); File f=root.openNextFile();
        while(f) {
            if(String(f.name()).startsWith(d)) {
                std::vector<uint8_t> b(f.size()); f.read(b.data(), f.size());
                r.push_back(b); LittleFS.remove(String("/m/")+f.name());
            }
            f=root.openNextFile();
        }
        return r;
    }
    void flush() {
        for(auto& i:c) { if(i.dirty){ File f=LittleFS.open("/m/"+i.d+"_"+String(millis()),"w"); f.write(i.p.data(),i.p.size()); f.close(); i.dirty=false; } }
        c.clear();
    }
};
}
