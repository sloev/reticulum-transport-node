#pragma once
#include "RetiCrypto.h"
#include "RetiPacket.h"
#include "RetiIdentity.h"

namespace Reticulum {

// Only the RNS default link mode is implemented -- see RNS.Link.MODE_AES256_CBC.
const uint8_t LINK_MODE_AES256_CBC = 0x01;
const size_t LINK_ECPUBSIZE = 64; // x25519 pub(32) + ed25519 pub(32), per RNS.Link.ECPUBSIZE

// This firmware only ever answers incoming link requests (it never
// initiates links to other nodes), so this implements RNS.Link's responder
// role only: validate_request() -> handshake() -> prove(), then
// encrypt()/decrypt() over the established link, plus LINKIDENTIFY and
// LINKCLOSE handling. There is no outbound-link / initiator code path.
class Link {
public:
    enum Status { HANDSHAKE, ACTIVE, CLOSED };
    Status status = HANDSHAKE;

    std::vector<uint8_t> linkId;      // 16 bytes
    std::vector<uint8_t> peerXPub;    // peer's ephemeral X25519 public key (32 bytes)
    std::vector<uint8_t> peerEdPub;   // peer's static Ed25519 public key, from the LR payload (32 bytes)
    std::vector<uint8_t> myXPub, myXPriv; // our ephemeral X25519 keypair (32 bytes each)

    std::vector<uint8_t> signingKey, encryptionKey; // Token halves, 32 bytes each (AES-256)

    // Set once a LINKIDENTIFY packet from the peer has been verified --
    // Stage 5 (LXMF) uses this to authorize/attribute propagation requests.
    bool remoteIdentified = false;
    std::vector<uint8_t> remoteIdentityHash; // 16 bytes

    unsigned long lastInbound = 0;

    // RNS.Link.link_id_from_lr_packet: truncated_hash(hashable_part), with
    // any trailing MTU-signalling bytes beyond the 64-byte ephemeral pubkey
    // block stripped first.
    static std::vector<uint8_t> linkIdFromRequest(const Packet& lrPacket) {
        std::vector<uint8_t> hashable = lrPacket.getHashablePart();
        if (lrPacket.data.size() > LINK_ECPUBSIZE) {
            size_t diff = lrPacket.data.size() - LINK_ECPUBSIZE;
            if (diff < hashable.size()) hashable.resize(hashable.size() - diff);
        }
        std::vector<uint8_t> h = Crypto::sha256(hashable);
        h.resize(16);
        return h;
    }

    // Link.signalling_bytes(mtu, mode): 3 bytes, top 3 bits of byte[0] carry
    // the mode, the remaining 21 bits carry the MTU.
    static std::vector<uint8_t> signallingBytes(uint32_t mtu, uint8_t mode) {
        uint32_t value = (mtu & 0x1FFFFF) | (((uint32_t)(mode << 5) & 0xE0) << 16);
        return { (uint8_t)((value >> 16) & 0xFF), (uint8_t)((value >> 8) & 0xFF), (uint8_t)(value & 0xFF) };
    }

    // Validates and accepts an incoming link request: derives the link ID,
    // generates our ephemeral X25519 keypair, and performs the ECDH+HKDF
    // handshake -- see RNS.Link.validate_request()/handshake(). Returns
    // nullptr if the request is malformed.
    static Link* accept(const Packet& lrPacket) {
        if (lrPacket.type != LINK_REQ) return nullptr;
        if (lrPacket.data.size() < LINK_ECPUBSIZE) return nullptr;

        Link* link = new Link();
        link->linkId = linkIdFromRequest(lrPacket);
        link->peerXPub.assign(lrPacket.data.begin(), lrPacket.data.begin() + 32);
        link->peerEdPub.assign(lrPacket.data.begin() + 32, lrPacket.data.begin() + 64);

        Crypto::genKeys(link->myXPub, link->myXPriv);

        std::vector<uint8_t> shared = Crypto::x25519_shared(link->myXPriv, link->peerXPub);
        // RNS.Link.get_salt(): salt = link_id.
        std::vector<uint8_t> derived = Crypto::hkdf(shared, link->linkId, 64);
        link->signingKey.assign(derived.begin(), derived.begin() + 32);
        link->encryptionKey.assign(derived.begin() + 32, derived.end());

        link->status = ACTIVE;
        link->lastInbound = millis();
        return link;
    }

    // Builds the LRPROOF packet: RNS.Link.prove(): signed_data =
    // link_id || x_pub || sig_pub || signalling_bytes, signed with the
    // *node's own static identity* (a Link's signing key is always the
    // owner's real Ed25519 key, not a fresh ephemeral one -- see
    // RNS.Link.__init__: "self.sig_prv = self.owner.identity.sig_prv").
    // proof_data = signature || x_pub || signalling_bytes (sig_pub is
    // deliberately not retransmitted: the initiator already resolved it via
    // the destination's earlier announce).
    Packet buildProof(Identity* id, uint32_t mtu = 500) const {
        std::vector<uint8_t> signalling = signallingBytes(mtu, LINK_MODE_AES256_CBC);
        std::vector<uint8_t> sigPub = id->getEd25519PublicKey();

        std::vector<uint8_t> signedData = linkId;
        signedData.insert(signedData.end(), myXPub.begin(), myXPub.end());
        signedData.insert(signedData.end(), sigPub.begin(), sigPub.end());
        signedData.insert(signedData.end(), signalling.begin(), signalling.end());
        std::vector<uint8_t> sig = id->sign(signedData);

        Packet p;
        p.type = PROOF;
        p.context = CTX_LRPROOF;
        p.addresses = linkId;
        p.data = sig;
        p.data.insert(p.data.end(), myXPub.begin(), myXPub.end());
        p.data.insert(p.data.end(), signalling.begin(), signalling.end());
        return p;
    }

    // Token-wraps plaintext for transmission over this link. The context
    // byte lives on the outer Packet (see wrapData()), not inside the
    // ciphertext -- RNS.Link.encrypt() is just Token.encrypt().
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) const {
        if (status != ACTIVE) return std::vector<uint8_t>();
        return Crypto::tokenEncrypt(signingKey, encryptionKey, plaintext);
    }

    // Returns the decrypted plaintext, or empty if the token doesn't verify.
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& tokenBytes) const {
        if (status != ACTIVE) return std::vector<uint8_t>();
        return Crypto::tokenDecrypt(signingKey, encryptionKey, tokenBytes);
    }

    // Convenience: builds a DATA packet addressed to this link with the
    // given plaintext encrypted and the given context set on the packet
    // itself (RNS.Packet.NONE for plain data, CTX_REQUEST/CTX_RESPONSE for
    // the request layer, etc).
    Packet wrapData(const std::vector<uint8_t>& plaintext, uint8_t context = CTX_NONE) const {
        Packet p;
        p.type = DATA;
        p.destType = LINK;
        p.addresses = linkId;
        p.context = context;
        p.data = encrypt(plaintext);
        return p;
    }

    // Builds a generic packet-delivery proof for an inbound DATA packet on
    // this link (RNS.Link.prove_packet()): proof_data = full_hash(packet's
    // hashable part, 32 bytes, untruncated) || sig(link_id owner's static
    // identity signs that hash). Sent back as a PROOF packet addressed to
    // this link, context NONE, *unencrypted* -- RNS.Packet.pack() special-
    // cases "packet proofs over links are not encrypted". This is what a
    // sender's PacketReceipt waits on to mark opportunistic/propagated
    // delivery as complete; without it, a real LXMF client would see the
    // send time out and retry even though this node already stored the
    // message.
    Packet buildPacketProof(Identity* id, const Packet& p) const {
        std::vector<uint8_t> packetHash = Crypto::sha256(p.getHashablePart());
        std::vector<uint8_t> sig = id->sign(packetHash);

        Packet proof;
        proof.type = PROOF;
        proof.destType = LINK;
        proof.addresses = linkId;
        proof.context = CTX_NONE;
        proof.data = packetHash;
        proof.data.insert(proof.data.end(), sig.begin(), sig.end());
        return proof;
    }

    // Verifies an inbound LINKIDENTIFY packet (RNS.Link.identify()):
    // plaintext = pubkey(64) || sig(64), signed_data = link_id || pubkey.
    // On success, remoteIdentityHash is set to SHA256(pubkey)[:16].
    bool handleIdentify(const std::vector<uint8_t>& tokenBytes) {
        std::vector<uint8_t> plaintext = decrypt(tokenBytes);
        if (plaintext.size() != 64 + 64) return false;

        std::vector<uint8_t> pub(plaintext.begin(), plaintext.begin() + 64);
        std::vector<uint8_t> sig(plaintext.begin() + 64, plaintext.end());

        std::vector<uint8_t> signedData = linkId;
        signedData.insert(signedData.end(), pub.begin(), pub.end());

        std::vector<uint8_t> edPub(pub.begin() + 32, pub.end());
        if (crypto_ed25519_check(sig.data(), edPub.data(), signedData.data(), signedData.size()) != 0) {
            return false;
        }

        std::vector<uint8_t> hash = Crypto::sha256(pub);
        remoteIdentityHash.assign(hash.begin(), hash.begin() + 16);
        remoteIdentified = true;
        return true;
    }

    void handleClose() { status = CLOSED; }

    // Any inbound packet on this link (data, keepalive, etc) refreshes
    // liveness -- see RNS.Link.receive()/last_inbound.
    void touch() { lastInbound = millis(); }

    bool isStale(unsigned long staleAfterMs = 300000) const {
        return status == ACTIVE && (millis() - lastInbound) > staleAfterMs;
    }
};
}
