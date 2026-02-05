#pragma once
#include "RetiCrypto.h"
#include "RetiPacket.h"

namespace Reticulum {
class Link {
public:
    bool active = false;
    std::vector<uint8_t> remote, encKey, authKey, reqHash, myPub, myPriv;

    Link(std::vector<uint8_t> r) : remote(r) { Crypto::genKeys(myPub, myPriv); }

    void accept(std::vector<uint8_t> peerPub, std::vector<uint8_t> hash) {
        reqHash = hash; 
        std::vector<uint8_t> s = Crypto::x25519_shared(myPriv, peerPub);
        std::vector<uint8_t> k = Crypto::hkdf(s, reqHash, 64);
        encKey.assign(k.begin(), k.begin()+32);
        authKey.assign(k.begin()+32, k.end());
        active = true;
    }

    Packet createProof(Identity& id) {
        std::vector<uint8_t> t = reqHash;
        t.insert(t.end(), myPub.begin(), myPub.end());
        std::vector<uint8_t> sig = id.sign(t);
        Packet p; p.type=PROOF; p.destType=SINGLE; p.addresses=remote;
        p.data = myPub; p.data.insert(p.data.end(), sig.begin(), sig.end());
        return p;
    }

    Packet encrypt(std::vector<uint8_t> pl, uint8_t ctx=0) {
        if(!active) return Packet();
        std::vector<uint8_t> iv(16); for(int i=0;i<16;i++) iv[i]=(uint8_t)esp_random();
        std::vector<uint8_t> in = {ctx}; in.insert(in.end(), pl.begin(), pl.end());
        std::vector<uint8_t> c = Crypto::aes_encrypt(encKey, iv, in);
        std::vector<uint8_t> d = iv; d.insert(d.end(), c.begin(), c.end());
        std::vector<uint8_t> m = Crypto::hmac_sha256(authKey, d);
        d.insert(d.end(), m.begin(), m.end());
        Packet p; p.type=DATA; p.destType=LINK; p.addresses=remote; p.data=d;
        return p;
    }
};
}
