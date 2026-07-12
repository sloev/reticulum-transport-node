#pragma once
#include "RetiMsgpack.h"
#include "RetiLink.h"
#include "RetiResource.h"
#include <map>
#include <functional>

namespace Reticulum {

// RNS.Link.request()/handle_request(): an inbound REQUEST is decrypted to
// msgpack [timestamp(float64), path_hash(16 bytes), data]. This firmware
// never issues its own outbound requests (it only answers them as an LXMF
// propagation node), so only the inbound/response half is implemented.
struct RequestEnvelope {
    double timestamp = 0;
    std::vector<uint8_t> pathHash; // 16 bytes
    std::vector<uint8_t> dataPayload; // raw msgpack bytes of the "data" value, schema depends on path
};

// A handled request's outcome: either a ready-to-send small RESPONSE
// packet, or -- when the [request_id, response] envelope is too big for
// one packet -- the raw envelope bytes for the caller to hand to
// Resource::create(link, envelope, true, requestId) instead (matches
// RNS.Link.handle_request()'s size check).
struct RequestResult {
    bool handled = false;
    bool needsResource = false;
    Packet responsePacket;
    std::vector<uint8_t> resourceEnvelope;
    std::vector<uint8_t> requestId;
};

class Request {
public:
    // Returns raw msgpack-encoded bytes for the response *value* (schema
    // depends on path, same as dataPayload) -- handleRequest() wraps it in
    // the [request_id, response] envelope.
    using Handler = std::function<std::vector<uint8_t>(const std::vector<uint8_t>& dataPayload, Link* link)>;

    std::map<std::vector<uint8_t>, Handler> handlers;

    static std::vector<uint8_t> pathHash(const String& path) {
        std::vector<uint8_t> pathBytes(path.c_str(), path.c_str() + path.length());
        std::vector<uint8_t> h = Crypto::sha256(pathBytes);
        h.resize(16);
        return h;
    }

    void registerHandler(const String& path, Handler h) {
        handlers[pathHash(path)] = h;
    }

    static bool parseEnvelope(const std::vector<uint8_t>& plaintext, RequestEnvelope& out) {
        cmp_ctx_t ctx;
        MsgpackBuffer buf;
        msgpackInitReader(&ctx, &buf, plaintext);

        uint32_t arrLen = 0;
        if (!cmp_read_array(&ctx, &arrLen) || arrLen < 3) return false;
        if (!cmp_read_decimal(&ctx, &out.timestamp)) return false;
        if (!cmpReadBin(&ctx, out.pathHash, 16) || out.pathHash.size() != 16) return false;

        // Whatever's left is the raw encoding of the "data" value -- handed
        // to a path-specific decoder rather than parsed generically here.
        if (buf.inPos > plaintext.size()) return false;
        out.dataPayload.assign(plaintext.begin() + buf.inPos, plaintext.end());
        return true;
    }

    // Handles an inbound REQUEST packet on an active link: decrypts,
    // dispatches to the registered handler by path hash, and builds the
    // [request_id, response] envelope. If it fits in one packet, returns it
    // pre-wrapped as a RESPONSE packet; otherwise returns the raw envelope
    // for the caller to send via Resource (both cases carry the *same*
    // envelope -- RNS.Link.handle_request() does this too: the Resource's
    // request_id parameter is only for advertisement-level matching, the
    // resource's actual data is still the full envelope).
    RequestResult handleRequest(Link* link, const Packet& reqPacket) {
        RequestResult result;

        std::vector<uint8_t> plaintext = link->decrypt(reqPacket.data);
        RequestEnvelope env;
        if (plaintext.empty() || !parseEnvelope(plaintext, env)) return result;

        auto it = handlers.find(env.pathHash);
        if (it == handlers.end()) return result;

        std::vector<uint8_t> responsePayload = it->second(env.dataPayload, link);
        result.requestId = reqPacket.getTruncatedHash();
        result.handled = true;

        cmp_ctx_t ctx;
        MsgpackBuffer buf;
        msgpackInitWriter(&ctx, &buf);
        cmp_write_array(&ctx, 2);
        cmp_write_bin(&ctx, result.requestId.data(), (uint32_t)result.requestId.size());
        buf.out.insert(buf.out.end(), responsePayload.begin(), responsePayload.end());

        if (buf.out.size() > Resource::SDU) {
            result.needsResource = true;
            result.resourceEnvelope = buf.out;
        } else {
            result.responsePacket = link->wrapData(buf.out, CTX_RESPONSE);
        }
        return result;
    }
};
}
