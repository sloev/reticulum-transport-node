#pragma once
#include "RetiMsgpack.h"
#include "RetiLink.h"

namespace Reticulum {

// RNS.Resource -- both directions. Wire format, cross-checked against both
// a live capture of a real RNS Resource transfer and the attermann/
// microReticulum C++ port's Resource.cpp (see commit message for
// specifics): the *whole* payload (random_hash || data) is Token-encrypted
// once; the resulting IV||ciphertext||HMAC stream is then sliced into
// SDU-sized chunks and each chunk is sent as-is (not individually
// re-encrypted) in a RESOURCE-context packet.
//
// Receive side scope, stated plainly: single-segment (i=1, l=1) and
// single-hashmap-page (n*MAPHASH_LEN == the "m" field's length, i.e. no
// HASHMAP_IS_EXHAUSTED/HMU pagination) transfers only -- everything up to
// ~74 parts / ~34KB with RNS's default link MDU, which covers ordinary
// LXMF messages and modest attachments. Larger uploads are rejected
// (ignored; the sender's advertisement retries then times out) rather than
// silently mishandled. Compression is never used or accepted: encrypted
// LXMF payloads don't shrink under bz2, so real senders' auto_compress
// never actually sticks for this data in practice, and this firmware
// doesn't carry a bz2 implementation to decode one if it ever did.
class Resource {
public:
    static constexpr size_t SDU = 464;         // matches RNS.Packet.MDU for the 500-byte default Reticulum MTU
    static constexpr size_t MAPHASH_LEN = 4;
    static constexpr size_t HASH_LEN = 32;     // full (untruncated) SHA-256
    static constexpr size_t RANDOM_HASH_LEN = 4;
    static constexpr size_t MAX_RECEIVE_PARTS = 128; // sanity ceiling well above one hashmap page

    Link* link;
    bool isResponse = false;
    bool isReceiving = false;
    std::vector<uint8_t> requestId;   // 16 bytes, only meaningful if isResponse

    std::vector<uint8_t> hash;        // 32 bytes: full_hash(data || random_hash)
    std::vector<uint8_t> randomHash;  // 4 bytes
    size_t dataSize = 0;               // original plaintext size (RNS "d")
    size_t transferSize = 0;           // encrypted stream size (RNS "t")
    std::vector<uint8_t> encryptedStream; // full Token bytes (RNS "t" = its size)
    std::vector<std::vector<uint8_t>> parts;
    std::vector<uint8_t> hashmap;     // totalParts * MAPHASH_LEN bytes
    size_t totalParts = 0;
    size_t sentParts = 0;

    // Receive-side accounting: parts[i] doubles as the receive buffer (see
    // acceptAdvertisement), populated as RESOURCE-context packets arrive.
    std::vector<bool> partReceived;
    size_t receivedCount = 0;

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

    // Parses an inbound RESOURCE_ADV (already Link-decrypted plaintext) and,
    // if it's within this firmware's supported scope, returns a receiving
    // Resource ready to have buildRequestForAllParts() sent. Returns
    // nullptr on any malformed or out-of-scope (multi-segment, HMU-paged,
    // compressed, has-metadata) advertisement -- see the class comment.
    static Resource* acceptAdvertisement(Link* link, const std::vector<uint8_t>& plaintext) {
        cmp_ctx_t ctx;
        MsgpackBuffer buf;
        msgpackInitReader(&ctx, &buf, plaintext);

        uint32_t mapSize = 0;
        if (!cmp_read_map(&ctx, &mapSize)) return nullptr;

        Resource* r = new Resource();
        r->link = link;
        r->isReceiving = true;

        bool haveT = false, haveD = false, haveN = false, haveH = false;
        bool haveR = false, haveF = false, haveM = false, haveI = false, haveL = false;
        uint64_t iVal = 0, lVal = 0, fVal = 0;

        for (uint32_t k = 0; k < mapSize; k++) {
            uint32_t keyLen = 0;
            char key[4] = {0};
            if (!cmp_read_str_size(&ctx, &keyLen) || keyLen > 3 || !ctx.read(&ctx, key, keyLen)) {
                delete r; return nullptr;
            }

            bool ok = true;
            if (keyLen == 1 && key[0] == 't') { uint64_t v; ok = cmp_read_uinteger(&ctx, &v); r->transferSize = (size_t)v; haveT = true; }
            else if (keyLen == 1 && key[0] == 'd') { uint64_t v; ok = cmp_read_uinteger(&ctx, &v); r->dataSize = (size_t)v; haveD = true; }
            else if (keyLen == 1 && key[0] == 'n') { uint64_t v; ok = cmp_read_uinteger(&ctx, &v); r->totalParts = (size_t)v; haveN = true; }
            else if (keyLen == 1 && key[0] == 'h') { ok = cmpReadBin(&ctx, r->hash, HASH_LEN); haveH = true; }
            else if (keyLen == 1 && key[0] == 'r') { ok = cmpReadBin(&ctx, r->randomHash, RANDOM_HASH_LEN); haveR = true; }
            else if (keyLen == 1 && key[0] == 'o') { std::vector<uint8_t> discard; ok = cmpReadBin(&ctx, discard, HASH_LEN); }
            else if (keyLen == 1 && key[0] == 'i') { ok = cmp_read_uinteger(&ctx, &iVal); haveI = true; }
            else if (keyLen == 1 && key[0] == 'l') { ok = cmp_read_uinteger(&ctx, &lVal); haveL = true; }
            else if (keyLen == 1 && key[0] == 'f') { ok = cmp_read_uinteger(&ctx, &fVal); haveF = true; }
            else if (keyLen == 1 && key[0] == 'm') { ok = cmpReadBin(&ctx, r->hashmap, MAX_RECEIVE_PARTS * MAPHASH_LEN); haveM = true; }
            else if (keyLen == 1 && key[0] == 'q') {
                cmp_object_t obj;
                ok = cmp_read_object(&ctx, &obj);
                if (ok && (obj.type == CMP_TYPE_BIN8 || obj.type == CMP_TYPE_BIN16 || obj.type == CMP_TYPE_BIN32)) {
                    ok = ctx.skip(&ctx, obj.as.bin_size);
                }
            } else {
                cmp_object_t obj;
                ok = cmp_read_object(&ctx, &obj);
                if (ok) {
                    if (obj.type == CMP_TYPE_BIN8 || obj.type == CMP_TYPE_BIN16 || obj.type == CMP_TYPE_BIN32) ok = ctx.skip(&ctx, obj.as.bin_size);
                    else if (obj.type == CMP_TYPE_STR8 || obj.type == CMP_TYPE_STR16 || obj.type == CMP_TYPE_STR32 || obj.type == CMP_TYPE_FIXSTR) ok = ctx.skip(&ctx, obj.as.str_size);
                }
            }
            if (!ok) { delete r; return nullptr; }
        }

        if (!(haveT && haveD && haveN && haveH && haveR && haveF && haveM && haveI && haveL)) { delete r; return nullptr; }
        if (iVal != 1 || lVal != 1) { delete r; return nullptr; }              // multi-segment: out of scope
        if (r->totalParts == 0 || r->totalParts > MAX_RECEIVE_PARTS) { delete r; return nullptr; }
        if (r->hashmap.size() != r->totalParts * MAPHASH_LEN) { delete r; return nullptr; } // HMU pagination needed: out of scope
        if (fVal & 0x02) { delete r; return nullptr; }                          // compressed: out of scope
        if (fVal & 0x20) { delete r; return nullptr; }                          // has_metadata: out of scope

        r->parts.resize(r->totalParts);
        r->partReceived.assign(r->totalParts, false);
        return r;
    }

    // [flag(0x00, not requesting a further hashmap page) || resource_hash(32)
    // || every map-hash in our hashmap] -- since acceptAdvertisement() only
    // ever accepts single-page transfers, the full hashmap is always already
    // in hand, so this always asks for every part in one round (RNS's own
    // sender fulfills a request like this in one burst -- see
    // RNS.Resource.request(), which isn't window-limited for an explicit
    // request, only for its own unprompted pushes).
    Packet buildRequestForAllParts() const {
        std::vector<uint8_t> plaintext;
        plaintext.push_back(0x00);
        plaintext.insert(plaintext.end(), hash.begin(), hash.end());
        plaintext.insert(plaintext.end(), hashmap.begin(), hashmap.end());
        return link->wrapData(plaintext, CTX_RESOURCE_REQ);
    }

    // Places an inbound RESOURCE-context part into its slot by matching
    // map-hash, mirroring RNS.Resource.receive_part(). `p.data` is the raw
    // chunk, not separately encrypted (see class comment).
    void receivePart(const Packet& p) {
        std::vector<uint8_t> partMapHash = mapHash(p.data, randomHash);
        for (size_t i = 0; i < totalParts; i++) {
            std::vector<uint8_t> want(hashmap.begin() + i * MAPHASH_LEN, hashmap.begin() + (i + 1) * MAPHASH_LEN);
            if (want == partMapHash) {
                if (!partReceived[i]) {
                    parts[i] = p.data;
                    partReceived[i] = true;
                    receivedCount++;
                }
                return;
            }
        }
    }

    bool receiveComplete() const { return receivedCount == totalParts; }

    // RNS.Resource.assemble(): join parts in order, Link-decrypt the whole
    // stream, strip the random_hash prefix, and verify against the
    // advertised hash (full_hash(data || random_hash)). Returns false (and
    // leaves dataOut untouched) on any mismatch -- corrupt/incomplete/
    // tampered transfer.
    bool assemble(std::vector<uint8_t>& dataOut) const {
        std::vector<uint8_t> stream;
        for (auto& part : parts) stream.insert(stream.end(), part.begin(), part.end());

        std::vector<uint8_t> decrypted = link->decrypt(stream);
        if (decrypted.size() < randomHash.size()) return false;

        std::vector<uint8_t> data(decrypted.begin() + randomHash.size(), decrypted.end());
        std::vector<uint8_t> hashInput = data;
        hashInput.insert(hashInput.end(), randomHash.begin(), randomHash.end());
        if (Crypto::sha256(hashInput) != hash) return false;

        dataOut = data;
        return true;
    }

    // RNS.Resource.prove(): proof = full_hash(data || hash), proof_data =
    // hash(32) || proof(32), sent unencrypted (PROOF/RESOURCE_PRF packets
    // over a link are never Token-encrypted -- see RNS.Packet.pack()).
    Packet buildReceiveProof(const std::vector<uint8_t>& assembledData) const {
        std::vector<uint8_t> proofInput = assembledData;
        proofInput.insert(proofInput.end(), hash.begin(), hash.end());
        std::vector<uint8_t> proof = Crypto::sha256(proofInput);

        Packet p;
        p.type = PROOF;
        p.destType = LINK;
        p.addresses = link->linkId;
        p.context = CTX_RESOURCE_PRF;
        p.data = hash;
        p.data.insert(p.data.end(), proof.begin(), proof.end());
        return p;
    }
};
}
