#pragma once
#include "RetiCommon.h"
#include "cmp.h"

namespace Reticulum {

// Minimal in-memory buffer backend for cmp (the vendored msgpack library).
// RNS/LXMF wire messages are small, fixed-shape structures (a handful of
// known fields), so callers write/read them directly with cmp's primitive
// calls rather than going through a generic msgpack DOM.
struct MsgpackBuffer {
    std::vector<uint8_t> out;   // accumulates written bytes
    const uint8_t* in = nullptr;
    size_t inLen = 0, inPos = 0;
};

inline bool msgpackRead(cmp_ctx_t* ctx, void* data, size_t limit) {
    MsgpackBuffer* b = (MsgpackBuffer*)ctx->buf;
    if (b->inPos + limit > b->inLen) return false;
    memcpy(data, b->in + b->inPos, limit);
    b->inPos += limit;
    return true;
}

inline bool msgpackSkip(cmp_ctx_t* ctx, size_t count) {
    MsgpackBuffer* b = (MsgpackBuffer*)ctx->buf;
    if (b->inPos + count > b->inLen) return false;
    b->inPos += count;
    return true;
}

inline size_t msgpackWrite(cmp_ctx_t* ctx, const void* data, size_t count) {
    MsgpackBuffer* b = (MsgpackBuffer*)ctx->buf;
    const uint8_t* p = (const uint8_t*)data;
    b->out.insert(b->out.end(), p, p + count);
    return count;
}

inline void msgpackInitWriter(cmp_ctx_t* ctx, MsgpackBuffer* buf) {
    buf->out.clear();
    cmp_init(ctx, buf, msgpackRead, msgpackSkip, msgpackWrite);
}

inline void msgpackInitReader(cmp_ctx_t* ctx, MsgpackBuffer* buf, const std::vector<uint8_t>& data) {
    buf->in = data.data();
    buf->inLen = data.size();
    buf->inPos = 0;
    cmp_init(ctx, buf, msgpackRead, msgpackSkip, msgpackWrite);
}

inline bool cmpWriteBin(cmp_ctx_t* ctx, const std::vector<uint8_t>& v) {
    return cmp_write_bin(ctx, v.data(), (uint32_t)v.size());
}

inline bool cmpReadBin(cmp_ctx_t* ctx, std::vector<uint8_t>& out, uint32_t maxLen = 4096) {
    uint32_t size = 0;
    if (!cmp_read_bin_size(ctx, &size)) return false;
    if (size > maxLen) return false;
    out.resize(size);
    if (size == 0) return true;
    return ctx->read(ctx, out.data(), size);
}

// Reads a value that is either nil or an array of bin entries (used for
// LXMF's MESSAGE_GET "wants"/"haves" fields, each an array of transient IDs
// or None). Sets wasNil accordingly; on a real array, out is filled with
// each entry's bytes.
inline bool cmpReadOptionalBinArray(cmp_ctx_t* ctx, std::vector<std::vector<uint8_t>>& out, bool& wasNil, uint32_t maxEntryLen = 64) {
    cmp_object_t obj;
    if (!cmp_read_object(ctx, &obj)) return false;

    if (obj.type == CMP_TYPE_NIL) {
        wasNil = true;
        return true;
    }
    wasNil = false;

    if (obj.type != CMP_TYPE_FIXARRAY && obj.type != CMP_TYPE_ARRAY16 && obj.type != CMP_TYPE_ARRAY32) {
        return false;
    }

    for (uint32_t i = 0; i < obj.as.array_size; i++) {
        std::vector<uint8_t> entry;
        if (!cmpReadBin(ctx, entry, maxEntryLen)) return false;
        out.push_back(entry);
    }
    return true;
}

}
