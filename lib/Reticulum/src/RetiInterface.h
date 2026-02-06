#pragma once
#include "RetiCommon.h"
#include <functional>
#include <map>

namespace Reticulum {

class Interface {
protected:
    struct ReassemblyBuffer {
        unsigned long ts;
        std::vector<uint8_t> data;
    };
    std::map<uint8_t, ReassemblyBuffer> rx_buffer;

public:
    String name;
    size_t mtu;
    std::function<void(const std::vector<uint8_t>&, Interface*)> onPacket;

    Interface(String n, size_t m) : name(n), mtu(m) {}
    virtual void sendRaw(const std::vector<uint8_t>& data) = 0;

    void send(const std::vector<uint8_t>& packet) {
        if (packet.size() <= mtu) {
            sendRaw(packet);
            return;
        }

        // RNode Physical Fragmentation (Seq | Flag)
        // Flag=1 denotes a split fragment. Both frames carry Flag=1.
        uint8_t seq = esp_random() & 0x0F;
        size_t split_idx = mtu - 1; 

        // Frame A
        std::vector<uint8_t> fa;
        fa.reserve(mtu);
        fa.push_back((seq << 4) | 0x01);
        fa.insert(fa.end(), packet.begin(), packet.begin() + split_idx);
        sendRaw(fa);

        delay(10); // Minimal atomic spacing

        // Frame B
        std::vector<uint8_t> fb;
        fb.reserve(packet.size() - split_idx + 1);
        fb.push_back((seq << 4) | 0x01); 
        fb.insert(fb.end(), packet.begin() + split_idx, packet.end());
        sendRaw(fb);
    }

    void receive(const std::vector<uint8_t>& data) {
        if (data.empty()) return;
        
        // GC Stale Buffers
        static unsigned long last_clean = 0;
        if (millis() - last_clean > 5000) {
            last_clean = millis();
            for (auto it = rx_buffer.begin(); it != rx_buffer.end(); ) {
                if (millis() - it->second.ts > 3000) it = rx_buffer.erase(it);
                else ++it;
            }
        }

        uint8_t header = data[0];
        uint8_t seq = (header >> 4) & 0x0F;
        bool is_split = (header & 0x01) == 1;

        if (is_split) {
            if (rx_buffer.count(seq)) {
                // Reassembly Complete
                auto& buf = rx_buffer[seq];
                buf.data.insert(buf.data.end(), data.begin() + 1, data.end());
                if (onPacket) onPacket(buf.data, this);
                rx_buffer.erase(seq);
            } 
            else if (data.size() == mtu) {
                // Buffer Start
                auto& buf = rx_buffer[seq];
                buf.ts = millis();
                buf.data.assign(data.begin() + 1, data.end());
            }
        } else {
            // Passthrough
            if(onPacket) onPacket(data, this);
        }
    }
};
}