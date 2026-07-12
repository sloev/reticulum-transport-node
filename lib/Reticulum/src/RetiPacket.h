#pragma once
#include "RetiCommon.h"
#include "RetiCrypto.h"
#include <vector>

namespace Reticulum {
enum PacketType { DATA=0, ANNOUNCE=1, LINK_REQ=2, PROOF=3 };
enum DestType { SINGLE=0, GROUP=1, PLAIN=2, LINK=3 };

// RNS.Packet context byte values that this firmware cares about. Full list
// per RNS.Packet -- only a subset is used by the Link/Request layers.
enum PacketContext {
    CTX_NONE           = 0x00,
    CTX_RESOURCE       = 0x01,
    CTX_RESOURCE_ADV   = 0x02,
    CTX_RESOURCE_REQ   = 0x03,
    CTX_RESOURCE_HMU   = 0x04,
    CTX_RESOURCE_PRF   = 0x05,
    CTX_RESOURCE_ICL   = 0x06,
    CTX_RESOURCE_RCL   = 0x07,
    CTX_CACHE_REQUEST  = 0x08,
    CTX_REQUEST        = 0x09,
    CTX_RESPONSE       = 0x0A,
    CTX_PATH_RESPONSE  = 0x0B,
    CTX_KEEPALIVE      = 0xFA,
    CTX_LINKIDENTIFY   = 0xFB,
    CTX_LINKCLOSE      = 0xFC,
    CTX_LRRTT          = 0xFE,
    CTX_LRPROOF        = 0xFF,
};

class Packet {
public:
    uint8_t headerType = 0;    // 0 = HEADER_1, 1 = HEADER_2 (see RNS.Packet.HEADER_1/HEADER_2)
    uint8_t hops = 0;
    uint8_t type = DATA, destType = SINGLE;
    uint8_t transportType = 0; // 0 = BROADCAST, 1 = TRANSPORT. Parsed/preserved only -- this
                                // firmware is a leaf RNode-style interface, not an RNS.Transport
                                // hop, so it never acts as a next-hop router for HEADER_2 packets.
    // Per-context meaning, NOT "is the context byte present" -- the context
    // byte is always present after the address field(s) regardless of this
    // flag. On ANNOUNCE it signals a ratchet is included in the payload.
    bool contextFlag = false;
    uint8_t context = 0;
    std::vector<uint8_t> transportId; // 16 bytes, HEADER_2 only
    std::vector<uint8_t> addresses;   // 16 bytes: destination hash (or link_id for link-context packets)
    std::vector<uint8_t> data;
    std::vector<uint8_t> raw;         // last packed/parsed bytes, kept for hashing

    static Packet parse(const std::vector<uint8_t>& rawIn) {
        Packet p;
        p.raw = rawIn;
        if (rawIn.size() < 2) return p;

        uint8_t h = rawIn[0];
        p.headerType    = (h >> 6) & 1;
        p.contextFlag   = (h >> 5) & 1;
        p.transportType = (h >> 4) & 1;
        p.destType      = (h >> 2) & 3;
        p.type          = h & 3;
        p.hops          = rawIn[1];

        size_t ptr = 2;
        if (p.headerType == 1) {
            if (ptr + 16 > rawIn.size()) return p;
            p.transportId.assign(rawIn.begin() + ptr, rawIn.begin() + ptr + 16);
            ptr += 16;
        }

        if (ptr + 16 > rawIn.size()) return p;
        p.addresses.assign(rawIn.begin() + ptr, rawIn.begin() + ptr + 16);
        ptr += 16;

        // The context byte is ALWAYS present after the address field(s),
        // regardless of contextFlag -- see RNS.Packet.pack()/unpack().
        if (ptr >= rawIn.size()) return p;
        p.context = rawIn[ptr++];

        if (ptr < rawIn.size()) p.data.assign(rawIn.begin() + ptr, rawIn.end());
        return p;
    }

    // Outbound packets are always HEADER_1: this firmware doesn't maintain
    // an RNS.Transport routing table, so it never has a transport_id to
    // signal and never needs to address one.
    std::vector<uint8_t> serialize() {
        std::vector<uint8_t> b;
        uint8_t h = (0 << 6) | ((contextFlag ? 1 : 0) << 5) | ((transportType & 1) << 4)
                  | ((destType & 3) << 2) | (type & 3);
        b.push_back(h);
        b.push_back(hops);
        b.insert(b.end(), addresses.begin(), addresses.end());
        b.push_back(context);
        b.insert(b.end(), data.begin(), data.end());
        raw = b;
        return b;
    }

    // RNS.Packet.get_hashable_part(): [flags & 0x0F] || everything after the
    // 2-byte header. Masking off header_type/context_flag/transport_type
    // (top nibble) means packets that only differ by hop count or those
    // flags -- e.g. the same packet re-broadcast by another hop -- still
    // hash identically, which is what flood-dedup and link-id derivation
    // both rely on.
    std::vector<uint8_t> getHashablePart() const {
        std::vector<uint8_t> out;
        if (raw.size() < 2) return out;
        out.push_back(raw[0] & 0x0F);
        out.insert(out.end(), raw.begin() + 2, raw.end());
        return out;
    }

    // RNS.Packet.getTruncatedHash(): SHA256(hashable_part)[:16]. Used for
    // flood-dedup and, over a link-request packet specifically, to derive
    // the link ID (see RNS.Link.link_id_from_lr_packet).
    std::vector<uint8_t> getTruncatedHash() const {
        std::vector<uint8_t> h = Crypto::sha256(getHashablePart());
        h.resize(16);
        return h;
    }
};
}
