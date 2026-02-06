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

        // RNode Physical Layer Fragmentation
        // Header: [ Seq(4) | Reserved(3) | SplitFlag(1) ]
        // Logic: SplitFlag 1 = First Part. SplitFlag 0 = Second Part.
        
        uint8_t seq = esp_random() & 0x0F;
        size_t split_idx = mtu - 1; 

        // Frame A (Start)
        std::vector<uint8_t> fa;
        fa.reserve(mtu);
        fa.push_back((seq << 4) | 0x01);
        fa.insert(fa.end(), packet.begin(), packet.begin() + split_idx);
        sendRaw(fa);

        delay(10); // Airtime throttle

        // Frame B (End)
        std::vector<uint8_t> fb;
        fb.reserve(packet.size() - split_idx + 1);
        fb.push_back((seq << 4) | 0x00);
        fb.insert(fb.end(), packet.begin() + split_idx, packet.end());
        sendRaw(fb);
    }

    void receive(const std::vector<uint8_t>& data) {
        if (data.empty()) return;

        uint8_t header = data[0];
        uint8_t seq = (header >> 4) & 0x0F;
        bool is_split = (header & 0x01) == 1;
        bool is_rnode_frame = false;

        // Heuristic: RNode split frames are usually max MTU
        if (is_split && data.size() == mtu) {
            auto& buf = rx_buffer[seq];
            buf.ts = millis();
            buf.data.assign(data.begin() + 1, data.end());
            is_rnode_frame = true;
        } 
        else if (!is_split && rx_buffer.count(seq)) {
            auto& buf = rx_buffer[seq];
            if (millis() - buf.ts < 2000) {
                buf.data.insert(buf.data.end(), data.begin() + 1, data.end());
                if (onPacket) onPacket(buf.data, this);
            }
            rx_buffer.erase(seq);
            is_rnode_frame = true;
        }

        if (!is_rnode_frame && onPacket) {
            onPacket(data, this);
        }
    }
};
}