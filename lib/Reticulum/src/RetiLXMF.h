#pragma once
#include "RetiCommon.h"
#include "RetiIdentity.h"
#include "RetiPacket.h"
#include <ArduinoJson.h>
#include <LittleFS.h>

namespace Reticulum {

class LXMFPropagationNode {
public:
    std::vector<uint8_t> propHash;

    Identity* id;

    LXMFPropagationNode(Identity* node_id) : id(node_id) {
        // In RNS, Single destination hash = SHA256(app_name_hash + aspect_hash + pub_key)
        // For demonstration, we simply derive a 16-byte hash based on our identity
        std::vector<uint8_t> pub = id->getPublicKey();
        String prefix = "lxmf.propagation";
        std::vector<uint8_t> buf(prefix.c_str(), prefix.c_str() + prefix.length());
        buf.insert(buf.end(), pub.begin(), pub.end());
        
        std::vector<uint8_t> fullHash = Crypto::sha256(buf);
        propHash.assign(fullHash.begin(), fullHash.begin() + 16);
        
        if (!LittleFS.exists("/lxmf")) {
            LittleFS.mkdir("/lxmf");
        }
    }

    // Handles incoming raw RNS packets directed at lxmf.propagation
    void handleIncoming(const std::vector<uint8_t>& rawPacket, const Packet& p) {
        if (p.addresses.empty()) return;
        
        // Ensure packet is destined for our propagation hash
        bool match = true;
        for(size_t i=0; i<16 && i<p.addresses.size(); i++) {
            if (p.addresses[i] != propHash[i]) { match = false; break; }
        }
        if(!match) return;

        // Handle Link Requests for Synchronization
        if (p.type == LINK_REQ) {
            RNS_LOG("LXMF: Received LINK_REQ. Preparing Sync Link.");
            // Here we would extract the peer's public key from the packet data
            // and instantiate a Reticulum::Link object to handle the handshake.
            // link->accept(peer_pub, p.addresses);
            return;
        }
        
        // Handle incoming LXMF Data (Caching)
        if (p.type == DATA) {
            RNS_LOG("LXMF: Intercepted propagation packet for caching.");

            // Extract MsgPack Payload
            DynamicJsonDocument doc(1024);
            DeserializationError err = deserializeMsgPack(doc, p.data.data(), p.data.size());
            
            if (err) {
                RNS_ERR("LXMF: MsgPack parse failed.");
                return;
            }

            // Write to LittleFS using message hash as filename
            std::vector<uint8_t> msgHash = Crypto::sha256(p.data);
            String filename = "/lxmf/" + toHex(std::vector<uint8_t>(msgHash.begin(), msgHash.begin()+16)) + ".msg";
            
            File f = LittleFS.open(filename, "w");
            if (f) {
                f.write(rawPacket.data(), rawPacket.size());
                f.close();
                RNS_LOG("LXMF: Cached message to %s", filename.c_str());
            }
        }
    }

    void handleSyncRequest(Interface* srcIface, const std::vector<uint8_t>& userHash) {
        RNS_LOG("LXMF: Received Sync Request.");
        
        File root = LittleFS.open("/lxmf");
        if (!root || !root.isDirectory()) return;

        File file = root.openNextFile();
        while (file) {
            if (!file.isDirectory()) {
                RNS_LOG("LXMF: Syncing %s", file.name());
            }
            file = root.openNextFile();
        }
    }
};

}
