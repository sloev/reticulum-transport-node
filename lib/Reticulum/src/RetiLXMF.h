#pragma once
#include "RetiCommon.h"
#include "RetiIdentity.h"
#include "RetiPacket.h"
#include "RetiLink.h"
#include <ArduinoJson.h>
#include <LittleFS.h>

namespace Reticulum {

class LXMFPropagationNode {
public:
    std::vector<uint8_t> propHash;

    Identity* id;
    std::vector<Link*> activeSyncLinks;

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
            RNS_LOG("LXMF: Received LINK_REQ. Establishing Sync Link.");
            if (p.data.size() >= 32) {
                std::vector<uint8_t> peer_pub(p.data.begin(), p.data.begin()+32);
                std::vector<uint8_t> req_hash = Crypto::sha256(rawPacket); // Simplified hash

                Link* syncLink = new Link(p.addresses);
                syncLink->accept(peer_pub, req_hash);

                // Create and send PROOF packet
                Packet proof = syncLink->createProof(id);
                // We would normally pass this back to the router to transmit
                // For this embedded LXMF layer, we assume the router will pick it up or we call interface->send()
                // Here we just log its successful generation.
                RNS_LOG("LXMF: Link established. PROOF generated.");
                
                // Keep the link object for the incoming SYNC request
                activeSyncLinks.push_back(syncLink);
            }
            return;
        }

        // Handle incoming data over an established Link (The Sync Request)
        if (p.type == DATA && p.destType == LINK) {
            for (auto* link : activeSyncLinks) {
                // Link ID is the first 16 bytes of req_hash
                bool match = true;
                for (size_t i = 0; i < 16 && i < p.addresses.size(); i++) {
                    if (p.addresses[i] != link->req_hash[i]) { match = false; break; }
                }
                
                if (match) {
                    std::vector<uint8_t> plain = link->decrypt(p.data);
                    if (plain.size() > 0) {
                        RNS_LOG("LXMF: Decrypted Sync Request payload.");
                        // The payload contains the identity hash of the user requesting sync.
                        // We trigger the file stream here.
                        handleSyncRequest(src, plain, link);
                    }
                    return;
                }
            }
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

    void handleSyncRequest(Interface* srcIface, const std::vector<uint8_t>& userHash, Link* link) {
        RNS_LOG("LXMF: Sync Request triggered for identity.");
        
        File root = LittleFS.open("/lxmf");
        if (!root || !root.isDirectory()) return;

        File file = root.openNextFile();
        while (file) {
            if (!file.isDirectory()) {
                RNS_LOG("LXMF: Syncing %s", file.name());
                // Read chunks and stream through link
                std::vector<uint8_t> payload;
                while(file.available()) {
                    payload.push_back(file.read());
                }
                
                // Encrypt payload and send (in a production environment, chunking is required)
                Packet p = link->encrypt(payload, 0);
                if (p.data.size() > 0) {
                    // Send back to srcIface (would require Interface API hook here)
                    // srcIface->send(p.serialize());
                }
            }
            file = root.openNextFile();
        }
    }
};

}
