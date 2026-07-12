#pragma once
#include "RetiMsgpack.h"
#include "RetiLink.h"

namespace Reticulum {

// RNS.Resource -- SEND side only. This firmware never needs to *receive* a
// resource: inbound LXMF propagation messages arrive as plain single
// packets on the propagation destination (RNS.Destination.set_packet_callback
// style), not via a Link+Resource upload, and this device never issues
// outbound requests of its own that could draw a Resource-sized response.
//
// Wire format, cross-checked against both a live capture of a real RNS
// Resource transfer and the attermann/microReticulum C++ port's
// Resource.cpp (see commit message for specifics): the *whole* payload
// (random_hash || data) is Token-encrypted once; the resulting IV||
// ciphertext||HMAC stream is then sliced into SDU-sized chunks and each
// chunk is sent as-is (not individually re-encrypted) in a RESOURCE-context
// packet. Compression is never used (LXMF payloads are already encrypted
// and don't compress), so this never needs a bz2 implementation.
class Resource {
public:
    static constexpr size_t SDU = 464;         // matches RNS.Packet.MDU for the 500-byte default Reticulum MTU
    static constexpr size_t MAPHASH_LEN = 4;
    static constexpr size_t HASH_LEN = 32;     // full (untruncated) SHA-256

    Link* link;
    bool isResponse = false;
    std::vector<uint8_t> requestId;   // 16 bytes, only meaningful if isResponse

    std::vector<uint8_t> hash;        // 32 bytes: full_hash(data || random_hash)
    std::vector<uint8_t> randomHash;  // 4 bytes
    size_t dataSize = 0;               // original plaintext size (RNS "d")
    std::vector<uint8_t> encryptedStream; // full Token bytes (RNS "t" = its size)
    std::vector<std::vector<uint8_t>> parts;
    std::vector<uint8_t> hashmap;     // totalParts * MAPHASH_LEN bytes
    size_t totalParts = 0;
    size_t sentParts = 0;

    static std::vector<uint8_t> mapHash(const std::vector<uint8_t>& chunk, const std::vector<uint8_t>& randomHash) {
        std::vector<uint8_t> in = chunk;
        in.insert(in.end(), randomHash.begin(), randomHash.end());
        std::vector<uint8_t> h = Crypto::sha256(in);
        h.resize(MAPHASH_LEN);
        return h;
    }

    // Builds an outbound resource for `data`, ready to advertise. If
    // isResponse, requestId must be the original request's truncated hash
    // (see Request::handleRequest) -- this is how the receiver's pending
    // request gets matched to this resource (RNS.ResourceAdvertisement.q/p).
    static Resource* create(Link* link, const std::vector<uint8_t>& data,
                             bool isResponse = false, const std::vector<uint8_t>& requestId = std::vector<uint8_t>()) {
        Resource* r = new Resource();
        r->link = link;
        r->isResponse = isResponse;
        r->requestId = requestId;
        r->dataSize = data.size();

        r->randomHash.resize(4);
        for (int i = 0; i < 4; i++) r->randomHash[i] = (uint8_t)RETI_RANDOM();

        // hash = full_hash(data || random_hash) -- data first.
        std::vector<uint8_t> hashInput = data;
        hashInput.insert(hashInput.end(), r->randomHash.begin(), r->randomHash.end());
        r->hash = Crypto::sha256(hashInput);

        // encrypted payload = Token(random_hash || data) -- random_hash first.
        std::vector<uint8_t> payload = r->randomHash;
        payload.insert(payload.end(), data.begin(), data.end());
        r->encryptedStream = link->encrypt(payload);

        r->totalParts = (r->encryptedStream.size() + SDU - 1) / SDU;
        r->parts.reserve(r->totalParts);
        for (size_t i = 0; i < r->totalParts; i++) {
            size_t offset = i * SDU;
            size_t chunkSize = std::min(SDU, r->encryptedStream.size() - offset);
            std::vector<uint8_t> chunk(r->encryptedStream.begin() + offset, r->encryptedStream.begin() + offset + chunkSize);
            std::vector<uint8_t> mh = mapHash(chunk, r->randomHash);
            r->hashmap.insert(r->hashmap.end(), mh.begin(), mh.end());
            r->parts.push_back(chunk);
        }
        return r;
    }

    // RNS.ResourceAdvertisement.pack(): msgpack map with keys
    // t,d,n,h,r,o,i,l,q,f,m. Single-segment only (i=1, l=1) -- our
    // payloads are always small enough not to need Resource's segment
    // splitting, so that path is not implemented.
    Packet buildAdvertisement() const {
        cmp_ctx_t ctx;
        MsgpackBuffer buf;
        msgpackInitWriter(&ctx, &buf);

        cmp_write_map(&ctx, 11);
        cmp_write_str(&ctx, "t", 1); cmp_write_uinteger(&ctx, (uint64_t)encryptedStream.size());
        cmp_write_str(&ctx, "d", 1); cmp_write_uinteger(&ctx, (uint64_t)dataSize);
        cmp_write_str(&ctx, "n", 1); cmp_write_uinteger(&ctx, (uint64_t)totalParts);
        cmp_write_str(&ctx, "h", 1); cmp_write_bin(&ctx, hash.data(), (uint32_t)hash.size());
        cmp_write_str(&ctx, "r", 1); cmp_write_bin(&ctx, randomHash.data(), (uint32_t)randomHash.size());
        cmp_write_str(&ctx, "o", 1); cmp_write_bin(&ctx, hash.data(), (uint32_t)hash.size()); // original_hash == hash (single segment)
        cmp_write_str(&ctx, "i", 1); cmp_write_uinteger(&ctx, 1);
        cmp_write_str(&ctx, "l", 1); cmp_write_uinteger(&ctx, 1);
        cmp_write_str(&ctx, "q", 1);
        if (isResponse) cmp_write_bin(&ctx, requestId.data(), (uint32_t)requestId.size());
        else cmp_write_nil(&ctx);
        // flags: bit0 e(encrypted)=1 always (Link.encrypt() is always used here),
        // bit1 c(compressed)=0 always, bit4 p(is_response) set when applicable.
        uint8_t f = 0x01 | (isResponse ? 0x10 : 0x00);
        cmp_write_str(&ctx, "f", 1); cmp_write_uinteger(&ctx, f);
        cmp_write_str(&ctx, "m", 1); cmp_write_bin(&ctx, hashmap.data(), (uint32_t)hashmap.size());

        return link->wrapData(buf.out, CTX_RESOURCE_ADV);
    }

    // Handles an inbound RESOURCE_REQ: [flag(1)][resource_hash(32)]
    // [wanted_map_hash(4) x N]. Only the non-HMU-extension case is handled
    // (flag must be 0x00) -- HASHMAP_IS_EXHAUSTED only matters when a
    // resource has more parts than fit in one advertisement's hashmap,
    // which our small responses never do.
    std::vector<Packet> handleRequest(const std::vector<uint8_t>& plaintext) {
        std::vector<Packet> out;
        if (plaintext.size() < 1 + HASH_LEN) return out;
        if (plaintext[0] != 0x00) return out;

        std::vector<uint8_t> reqHash(plaintext.begin() + 1, plaintext.begin() + 1 + HASH_LEN);
        if (reqHash != hash) return out;

        std::vector<uint8_t> wanted(plaintext.begin() + 1 + HASH_LEN, plaintext.end());
        size_t n = wanted.size() / MAPHASH_LEN;
        for (size_t w = 0; w < n; w++) {
            std::vector<uint8_t> wantHash(wanted.begin() + w * MAPHASH_LEN, wanted.begin() + (w + 1) * MAPHASH_LEN);
            for (size_t i = 0; i < totalParts; i++) {
                std::vector<uint8_t> partMapHash(hashmap.begin() + i * MAPHASH_LEN, hashmap.begin() + (i + 1) * MAPHASH_LEN);
                if (partMapHash == wantHash) {
                    Packet p;
                    p.type = DATA;
                    p.destType = LINK;
                    p.addresses = link->linkId;
                    p.context = CTX_RESOURCE;
                    p.data = parts[i]; // raw chunk of the already-Token-encrypted stream, not re-encrypted
                    out.push_back(p);
                    sentParts++;
                    break;
                }
            }
        }
        return out;
    }

    bool complete() const { return sentParts >= totalParts; }
};
}
