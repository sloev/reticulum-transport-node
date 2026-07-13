#!/usr/bin/env python3
"""
Generates ground-truth test vectors from the official `rns` package.

RNS-C's C++ implementation is checked against these vectors by the host
test runner in test/host/. This script is the *only* place that is allowed
to depend on the real Reticulum implementation for correctness -- nothing
in the firmware does.

Usage:
    pip install rns==1.3.7 lxmf==1.0.1
    python3 test/vectors/make_vectors.py > test/vectors/vectors.json

The output is not committed; CI regenerates it fresh against a pinned rns
version on every run, so vectors can never quietly drift from the spec
version this firmware claims to support.
"""
import sys
import json
import os
import binascii
import importlib

import RNS
from RNS.Cryptography import hkdf as rns_hkdf
from RNS.vendor import umsgpack

# RNS.Cryptography.__init__ does `from .Token import Token`, which rebinds the
# `Token` attribute on the RNS.Cryptography package to the *class*. That means
# `import RNS.Cryptography.Token as TokMod` (or any dotted-attribute access)
# resolves to the class, not the Token.py module -- so pull the real module
# straight out of sys.modules instead.
importlib.import_module("RNS.Cryptography.Token")
TokMod = sys.modules["RNS.Cryptography.Token"]
importlib.import_module("RNS.Resource")
ResourceMod = sys.modules["RNS.Resource"]

RNS_VERSION = getattr(RNS, "__version__", "unknown")


def hx(b):
    return binascii.hexlify(b).decode("ascii")


def make_reticulum_instance(tmp_dir):
    cfg_dir = os.path.join(tmp_dir, "rns_config")
    os.makedirs(cfg_dir, exist_ok=True)
    with open(os.path.join(cfg_dir, "config"), "w") as f:
        f.write(
            "[reticulum]\n"
            "enable_transport = False\n"
            "share_instance = False\n"
            "panic_on_interface_error = False\n"
            "\n[logging]\nloglevel = 0\n\n[interfaces]\n"
        )
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def vec_identity():
    prv_bytes = bytes(range(64))
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(prv_bytes)
    return {
        "private_key": hx(prv_bytes),
        "public_key": hx(identity.get_public_key()),
        "x25519_public": hx(identity.pub_bytes),
        "ed25519_public": hx(identity.sig_pub_bytes),
        "hash": hx(identity.hash),
        "note": "private_key[0:32] = X25519 raw private scalar, "
                "private_key[32:64] = Ed25519 seed. "
                "hash = SHA256(x25519_pub(32) || ed25519_pub(32))[:16].",
    }


def vec_destination(identity_hash_hex):
    name_hash = RNS.Identity.full_hash("lxmf.propagation".encode("utf-8"))[
        : RNS.Identity.NAME_HASH_LENGTH // 8
    ]
    identity_hash = binascii.unhexlify(identity_hash_hex)
    dest_hash = RNS.Identity.full_hash(name_hash + identity_hash)[
        : RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
    ]
    return {
        "app_name": "lxmf",
        "aspects": ["propagation"],
        "name_hash": hx(name_hash),
        "destination_hash": hx(dest_hash),
        "note": "name_hash = SHA256('lxmf.propagation')[:10]. "
                "destination_hash = SHA256(name_hash(10) || identity_hash(16))[:16].",
    }


def vec_announce():
    captured = []
    RNS.Transport.outbound = staticmethod(lambda packet: captured.append(packet.raw) or True)

    prv_bytes = bytes(range(64))
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(prv_bytes)
    destination = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "propagation"
    )
    app_data = b"rns-c-test-app-data"
    destination.announce(app_data=app_data)

    raw = captured[0]

    # Reverse-validate with the real implementation: proves a packet built
    # to this exact layout is accepted by unmodified RNS.
    p = RNS.Packet(None, raw)
    p.unpack()
    valid = RNS.Identity.validate_announce(p)

    return {
        "private_key": hx(prv_bytes),
        "app_data": hx(app_data),
        "raw_packet": hx(raw),
        "validated_by_rns": bool(valid),
        "note": "Byte layout: [flags(1)][hops(1)][dest_hash(16)][context(1)]"
                "[pubkey(64)][name_hash(10)][random_hash(10)][sig(64)][app_data]. "
                "signed_data = dest_hash || pubkey || name_hash || random_hash || app_data.",
    }


def vec_packet_parse_cases():
    cases = []

    # HEADER_1, DATA packet, PLAIN destination, context NONE
    destination_hash = bytes(range(16))
    flags = (0 << 6) | (0 << 5) | (0 << 4) | (RNS.Destination.PLAIN << 2) | RNS.Packet.DATA
    raw = bytes([flags, 3]) + destination_hash + bytes([RNS.Packet.NONE]) + b"hello-plain"
    cases.append({
        "name": "header1_plain_data",
        "raw": hx(raw),
        "expect": {
            "header_type": 0, "context_flag": 0, "transport_type": 0,
            "destination_type": RNS.Destination.PLAIN, "packet_type": RNS.Packet.DATA,
            "hops": 3, "destination_hash": hx(destination_hash),
            "context": RNS.Packet.NONE, "data": hx(b"hello-plain"),
        },
    })

    # HEADER_1, ANNOUNCE with context_flag set (ratchet present) -- flag bit only,
    # no ratchet payload needed to test the *parser*.
    flags2 = (0 << 6) | (1 << 5) | (0 << 4) | (RNS.Destination.SINGLE << 2) | RNS.Packet.ANNOUNCE
    raw2 = bytes([flags2, 0]) + destination_hash + bytes([RNS.Packet.NONE]) + b"ann-data"
    cases.append({
        "name": "header1_announce_context_flag_set",
        "raw": hx(raw2),
        "expect": {
            "header_type": 0, "context_flag": 1, "transport_type": 0,
            "destination_type": RNS.Destination.SINGLE, "packet_type": RNS.Packet.ANNOUNCE,
            "hops": 0, "destination_hash": hx(destination_hash),
            "context": RNS.Packet.NONE, "data": hx(b"ann-data"),
        },
    })

    # HEADER_2: transport_id(16) + destination_hash(16) + context + data
    transport_id = bytes(range(100, 116))
    flags3 = (1 << 6) | (0 << 5) | (1 << 4) | (RNS.Destination.SINGLE << 2) | RNS.Packet.DATA
    raw3 = bytes([flags3, 1]) + transport_id + destination_hash + bytes([RNS.Packet.NONE]) + b"transported"
    cases.append({
        "name": "header2_transport",
        "raw": hx(raw3),
        "expect": {
            "header_type": 1, "context_flag": 0, "transport_type": 1,
            "destination_type": RNS.Destination.SINGLE, "packet_type": RNS.Packet.DATA,
            "hops": 1, "transport_id": hx(transport_id),
            "destination_hash": hx(destination_hash),
            "context": RNS.Packet.NONE, "data": hx(b"transported"),
        },
    })

    return cases


def vec_identity_encrypt():
    # Fixed target identity + a captured real ciphertext token (ephemeral
    # key is random per RNS.Identity.encrypt() call, so this checks
    # decrypt() -- the deterministic direction -- against a real token
    # rather than trying to reproduce encrypt()'s output byte-for-byte.
    prv_bytes = bytes(range(64))
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(prv_bytes)

    plaintext = b"lxmf-propagation-payload-secret"
    token = identity.encrypt(plaintext)
    decrypted = identity.decrypt(token)
    assert decrypted == plaintext

    return {
        "private_key": hx(prv_bytes),
        "plaintext": hx(plaintext),
        "ciphertext_token": hx(token),
        "note": "ciphertext_token = ephemeral_x25519_pub(32) || Token(HKDF(ECDH(ephemeral_priv, identity_pub), "
                "salt=identity_hash, length=64)).encrypt(plaintext)",
    }


def vec_x25519_ed25519():
    from RNS.Cryptography import X25519PrivateKey, Ed25519PrivateKey

    priv_a = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    priv_b = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    shared = priv_a.exchange(priv_b.public_key())

    seed = bytes(range(64, 96))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    message = b"sign-me-please"
    signature = sk.sign(message)

    return {
        "x25519": {
            "priv_a": hx(bytes(range(32))),
            "pub_a": hx(priv_a.public_key().public_bytes()),
            "priv_b": hx(bytes(range(32, 64))),
            "pub_b": hx(priv_b.public_key().public_bytes()),
            "shared_secret": hx(shared),
        },
        "ed25519": {
            "seed": hx(seed),
            "public_key": hx(sk.public_key().public_bytes()),
            "message": hx(message),
            "signature": hx(signature),
            "note": "Deterministic EdDSA (RFC 8032): signature bytes must match "
                    "exactly across conforming implementations, not just verify.",
        },
    }


def vec_hkdf():
    secret = b"shared-secret-material-32bytes!!"
    salt = b"linkid-salt-16by"
    out = rns_hkdf(length=64, derive_from=secret, salt=salt, context=None)
    return {
        "secret": hx(secret),
        "salt": hx(salt),
        "length": 64,
        "output": hx(out),
    }


def vec_token_aes256():
    key = bytes(range(64))  # first 32 = signing, last 32 = encryption
    t = TokMod.Token(key=key, mode=TokMod.AES)

    orig_urandom = TokMod.os.urandom
    TokMod.os.urandom = lambda n: bytes(range(n))
    try:
        plaintext = b"the quick brown fox jumps"
        token = t.encrypt(plaintext)
    finally:
        TokMod.os.urandom = orig_urandom

    return {
        "key": hx(key),
        "signing_key": hx(t._signing_key),
        "encryption_key": hx(t._encryption_key),
        "iv": hx(bytes(range(16))),
        "plaintext": hx(plaintext),
        "token": hx(token),
        "note": "token = IV(16) || AES-256-CBC(PKCS7(plaintext)) || HMAC-SHA256(signing_key, IV||ciphertext)(32). "
                "No version byte, no timestamp (unlike classic Fernet).",
    }


def vec_link_signalling():
    mtu = RNS.Reticulum.MTU  # 500
    mode = RNS.Link.MODE_AES256_CBC
    signalling = RNS.Link.signalling_bytes(mtu, mode)
    return {
        "mtu": mtu,
        "mode": mode,
        "signalling_bytes": hx(signalling),
    }


def vec_request_envelope():
    # Decoupled from the Link/Token machinery (already verified elsewhere):
    # this is exactly the plaintext RNS.Link.request() would hand to
    # Token.encrypt(), captured before encryption, so it tests msgpack
    # parsing on its own.
    from RNS.vendor import umsgpack

    path = "/pn/get/stats"
    path_hash = RNS.Identity.truncated_hash(path.encode("utf-8"))
    timestamp = 1783840999.708162
    data = [None, None]
    plaintext = umsgpack.packb([timestamp, path_hash, data])

    return {
        "path": path,
        "path_hash": hx(path_hash),
        "timestamp": timestamp,
        "plaintext": hx(plaintext),
        "note": "RNS.Link.request() plaintext (pre-Token-encryption): "
                "msgpack [timestamp(float64), path_hash(16 bytes), data]. "
                "path_hash = RNS.Identity.truncated_hash(path.encode())[:16].",
    }


def vec_resource_hash_orderings():
    # Cross-checked against attermann/microReticulum's Resource.cpp: the
    # overall resource hash and the encrypted payload use *different*
    # concatenation orders of data and random_hash. Easy to get backwards.
    data = b"resource-payload-bytes-for-testing"
    random_hash = bytes(range(4))

    resource_hash = RNS.Identity.full_hash(data + random_hash)  # data THEN random_hash
    payload_to_encrypt = random_hash + data  # random_hash THEN data

    chunk = data[:16]
    map_hash = RNS.Identity.full_hash(chunk + random_hash)[:4]  # chunk THEN random_hash

    return {
        "data": hx(data),
        "random_hash": hx(random_hash),
        "resource_hash": hx(resource_hash),
        "payload_to_encrypt": hx(payload_to_encrypt),
        "chunk": hx(chunk),
        "map_hash": hx(map_hash),
    }


def vec_link_request(reticulum):
    captured = []
    RNS.Transport.outbound = staticmethod(lambda packet: captured.append(packet.raw) or True)

    server_prv = bytes(range(64))
    server_identity = RNS.Identity(create_keys=False)
    server_identity.load_private_key(server_prv)

    out_destination = RNS.Destination(
        server_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "propagation"
    )

    link = RNS.Link(out_destination)
    raw = captured[-1]

    p = RNS.Packet(None, raw)
    p.unpack()
    link_id = RNS.Link.link_id_from_lr_packet(p)

    return {
        "server_identity_private": hx(server_prv),
        "raw_lr_packet": hx(raw),
        "link_id": hx(link_id),
        "initiator_x25519_priv": hx(link.prv.private_bytes()),
        "initiator_x25519_pub": hx(link.pub_bytes),
        "initiator_ed25519_pub": hx(link.sig_pub_bytes),
        "note": "link_id = truncated_hash(hashable_part), where hashable_part = "
                "[flags & 0x0F] || raw[2:] (everything after the hops byte), "
                "with any trailing MTU-signalling bytes beyond the 64-byte "
                "pubkey block stripped first.",
    }


def vec_resource_advertisement_receive():
    # Ground truth for the *parser*: a real ResourceMod.ResourceAdvertisement,
    # packed from a synthetic resource with fixed field values (no real Link
    # needed -- ResourceAdvertisement only reads the attributes below).
    class FakeResource:
        pass

    r = FakeResource()
    r.size = 928              # transfer size (t)
    r.total_size = 900        # data size (d)
    r.hash = RNS.Identity.full_hash(b"resource-adv-test-data")
    r.random_hash = bytes(range(4))
    r.original_hash = r.hash
    r.parts = [b"\x00" * 4] * 4  # n = 4
    r.hashmap = b"".join(RNS.Identity.full_hash(bytes([i]) + r.random_hash)[:4] for i in range(4))
    r.compressed = False
    r.encrypted = True
    r.split = False
    r.has_metadata = False
    r.segment_index = 1
    r.total_segments = 1
    r.request_id = None
    r.is_response = False

    adv = ResourceMod.ResourceAdvertisement(r)
    packed = adv.pack()

    # Reverse-check: unpack with the real class too, so this vector can't
    # silently encode something RNS itself wouldn't parse back correctly.
    reparsed = ResourceMod.ResourceAdvertisement.unpack(packed)
    assert reparsed.h == r.hash and reparsed.n == 4 and reparsed.f == 0x01

    return {
        "packed": hx(packed),
        "t": r.size, "d": r.total_size, "n": 4,
        "hash": hx(r.hash), "random_hash": hx(r.random_hash),
        "hashmap": hx(r.hashmap), "flags": reparsed.f,
        "note": "msgpack map, keys t,d,n,h,r,o,i,l,q,f,m. flags: bit0=encrypted, "
                "bit1=compressed, bit2=split, bit3=is_request, bit4=is_response, bit5=has_metadata.",
    }


def vec_resource_receive_proof():
    # RNS.Resource.assemble()/prove(): calculated_hash = full_hash(data + random_hash),
    # then proof = full_hash(data + hash), proof_data = hash(32) || proof(32),
    # sent unencrypted as a PROOF packet with context RESOURCE_PRF.
    data = b"assembled-resource-payload-bytes"
    random_hash = bytes(range(10, 14))
    resource_hash = RNS.Identity.full_hash(data + random_hash)
    proof = RNS.Identity.full_hash(data + resource_hash)
    proof_data = resource_hash + proof

    return {
        "data": hx(data),
        "random_hash": hx(random_hash),
        "resource_hash": hx(resource_hash),
        "proof_data": hx(proof_data),
    }


def vec_ratchet_announce():
    import tempfile

    captured = []
    RNS.Transport.outbound = staticmethod(lambda packet: captured.append(packet.raw) or True)

    # A distinct identity from vec_announce()'s: RNS.Transport keeps a
    # process-global registry keyed by destination hash, and registering two
    # Destinations for the same identity+name/aspect raises.
    prv_bytes = bytes((i + 1) % 256 for i in range(64))
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(prv_bytes)
    destination = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "propagation"
    )
    with tempfile.TemporaryDirectory() as ratchet_tmp:
        destination.enable_ratchets(os.path.join(ratchet_tmp, "ratchets"))

        app_data = b"ratchet-test-app-data"
        destination.announce(app_data=app_data)

        raw = captured[0]
        p = RNS.Packet(None, raw)
        p.unpack()
        valid = RNS.Identity.validate_announce(p)
        ratchet_pub = RNS.Identity._ratchet_public_bytes(destination.ratchets[0])

        return {
            "private_key": hx(prv_bytes),
            "app_data": hx(app_data),
            "raw_packet": hx(raw),
            "ratchet_public": hx(ratchet_pub),
            "validated_by_rns": bool(valid),
            "note": "With a ratchet, byte layout is [flags(1, context_flag set)][hops(1)]"
                    "[dest_hash(16)][context(1)][pubkey(64)][name_hash(10)][random_hash(10)]"
                    "[ratchet(32)][sig(64)][app_data]. signed_data = dest_hash || pubkey || "
                    "name_hash || random_hash || ratchet || app_data.",
        }


def vec_ratchet_identity_encrypt():
    # Deterministic direction only (decrypt), same rationale as vec_identity_encrypt:
    # encrypt() uses a random ephemeral key, so only decrypt() output is checked
    # byte-for-byte. Here the *target's* ratchet key is used instead of its
    # static X25519 key -- proves a receiver must try retained ratchet privkeys,
    # not just its long-term key, to decrypt this token.
    prv_bytes = bytes(range(64))
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(prv_bytes)

    ratchet_prv = RNS.Identity._generate_ratchet()
    ratchet_pub = RNS.Identity._ratchet_public_bytes(ratchet_prv)

    plaintext = b"ratchet-encrypted-payload-secret"
    token = identity.encrypt(plaintext, ratchet=ratchet_pub)
    decrypted = identity.decrypt(token, ratchets=[ratchet_prv])
    assert decrypted == plaintext

    return {
        "identity_private_key": hx(prv_bytes),
        "ratchet_private": hx(ratchet_prv),
        "ratchet_public": hx(ratchet_pub),
        "plaintext": hx(plaintext),
        "ciphertext_token": hx(token),
        "note": "Same Identity.encrypt()/decrypt() as vec_identity_encrypt, but the "
                "target public key used for ECDH is a ratchet key, not the identity's "
                "static X25519 key. A receiver must try its retained ratchet private "
                "keys (not just its static key) to decrypt this.",
    }


def _cstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit_cpp_header(vectors, path):
    """Emits the same vectors as a C++ header of hex-string constants, so the
    host test binary needs no JSON parser -- it just includes this and hands
    the hex strings to a hexToBytes() helper."""
    lines = []
    lines.append("#pragma once")
    lines.append(f"// AUTO-GENERATED by test/vectors/make_vectors.py against rns=={vectors['rns_version']}.")
    lines.append("// Do not edit by hand -- regenerate instead.")
    lines.append("")
    lines.append("namespace TestVectors {")
    lines.append("")

    xed = vectors["x25519_ed25519"]
    lines.append(f'constexpr const char* X25519_PRIV_A_HEX = {_cstr(xed["x25519"]["priv_a"])};')
    lines.append(f'constexpr const char* X25519_PUB_A_HEX = {_cstr(xed["x25519"]["pub_a"])};')
    lines.append(f'constexpr const char* X25519_PRIV_B_HEX = {_cstr(xed["x25519"]["priv_b"])};')
    lines.append(f'constexpr const char* X25519_PUB_B_HEX = {_cstr(xed["x25519"]["pub_b"])};')
    lines.append(f'constexpr const char* X25519_SHARED_SECRET_HEX = {_cstr(xed["x25519"]["shared_secret"])};')
    lines.append(f'constexpr const char* ED25519_SEED_HEX = {_cstr(xed["ed25519"]["seed"])};')
    lines.append(f'constexpr const char* ED25519_PUBLIC_KEY_HEX = {_cstr(xed["ed25519"]["public_key"])};')
    lines.append(f'constexpr const char* ED25519_MESSAGE_HEX = {_cstr(xed["ed25519"]["message"])};')
    lines.append(f'constexpr const char* ED25519_SIGNATURE_HEX = {_cstr(xed["ed25519"]["signature"])};')
    lines.append("")

    idn = vectors["identity"]
    lines.append(f'constexpr const char* IDENTITY_PRIVATE_KEY_HEX = {_cstr(idn["private_key"])};')
    lines.append(f'constexpr const char* IDENTITY_PUBLIC_KEY_HEX = {_cstr(idn["public_key"])};')
    lines.append(f'constexpr const char* IDENTITY_X25519_PUBLIC_HEX = {_cstr(idn["x25519_public"])};')
    lines.append(f'constexpr const char* IDENTITY_ED25519_PUBLIC_HEX = {_cstr(idn["ed25519_public"])};')
    lines.append(f'constexpr const char* IDENTITY_HASH_HEX = {_cstr(idn["hash"])};')
    lines.append("")

    dst = vectors["destination"]
    lines.append(f'constexpr const char* DEST_APP_NAME = {_cstr(dst["app_name"])};')
    lines.append(f'constexpr const char* DEST_ASPECT = {_cstr(dst["aspects"][0])};')
    lines.append(f'constexpr const char* DEST_NAME_HASH_HEX = {_cstr(dst["name_hash"])};')
    lines.append(f'constexpr const char* DEST_HASH_HEX = {_cstr(dst["destination_hash"])};')
    lines.append("")

    ann = vectors["announce"]
    lines.append(f'constexpr const char* ANNOUNCE_PRIVATE_KEY_HEX = {_cstr(ann["private_key"])};')
    lines.append(f'constexpr const char* ANNOUNCE_APP_DATA_HEX = {_cstr(ann["app_data"])};')
    lines.append(f'constexpr const char* ANNOUNCE_RAW_PACKET_HEX = {_cstr(ann["raw_packet"])};')
    lines.append(f'constexpr bool ANNOUNCE_VALIDATED_BY_RNS = {"true" if ann["validated_by_rns"] else "false"};')
    lines.append("")

    hk = vectors["hkdf"]
    lines.append(f'constexpr const char* HKDF_SECRET_HEX = {_cstr(hk["secret"])};')
    lines.append(f'constexpr const char* HKDF_SALT_HEX = {_cstr(hk["salt"])};')
    lines.append(f'constexpr int HKDF_LENGTH = {hk["length"]};')
    lines.append(f'constexpr const char* HKDF_OUTPUT_HEX = {_cstr(hk["output"])};')
    lines.append("")

    tok = vectors["token_aes256"]
    lines.append(f'constexpr const char* TOKEN_KEY_HEX = {_cstr(tok["key"])};')
    lines.append(f'constexpr const char* TOKEN_SIGNING_KEY_HEX = {_cstr(tok["signing_key"])};')
    lines.append(f'constexpr const char* TOKEN_ENCRYPTION_KEY_HEX = {_cstr(tok["encryption_key"])};')
    lines.append(f'constexpr const char* TOKEN_IV_HEX = {_cstr(tok["iv"])};')
    lines.append(f'constexpr const char* TOKEN_PLAINTEXT_HEX = {_cstr(tok["plaintext"])};')
    lines.append(f'constexpr const char* TOKEN_HEX = {_cstr(tok["token"])};')
    lines.append("")

    ienc = vectors["identity_encrypt"]
    lines.append(f'constexpr const char* IDENTITY_ENCRYPT_PRIVATE_KEY_HEX = {_cstr(ienc["private_key"])};')
    lines.append(f'constexpr const char* IDENTITY_ENCRYPT_PLAINTEXT_HEX = {_cstr(ienc["plaintext"])};')
    lines.append(f'constexpr const char* IDENTITY_ENCRYPT_CIPHERTEXT_TOKEN_HEX = {_cstr(ienc["ciphertext_token"])};')
    lines.append("")

    lr = vectors["link_request"]
    lines.append(f'constexpr const char* LINK_SERVER_IDENTITY_PRIVATE_HEX = {_cstr(lr["server_identity_private"])};')
    lines.append(f'constexpr const char* LINK_RAW_LR_PACKET_HEX = {_cstr(lr["raw_lr_packet"])};')
    lines.append(f'constexpr const char* LINK_ID_HEX = {_cstr(lr["link_id"])};')
    lines.append("")

    lsig = vectors["link_signalling"]
    lines.append(f'constexpr int LINK_SIGNALLING_MTU = {lsig["mtu"]};')
    lines.append(f'constexpr int LINK_SIGNALLING_MODE = {lsig["mode"]};')
    lines.append(f'constexpr const char* LINK_SIGNALLING_BYTES_HEX = {_cstr(lsig["signalling_bytes"])};')
    lines.append("")

    rq = vectors["request_envelope"]
    lines.append(f'constexpr const char* REQUEST_PATH = {_cstr(rq["path"])};')
    lines.append(f'constexpr const char* REQUEST_PATH_HASH_HEX = {_cstr(rq["path_hash"])};')
    lines.append(f'constexpr double REQUEST_TIMESTAMP = {rq["timestamp"]};')
    lines.append(f'constexpr const char* REQUEST_PLAINTEXT_HEX = {_cstr(rq["plaintext"])};')
    lines.append("")

    rh = vectors["resource_hash_orderings"]
    lines.append(f'constexpr const char* RESOURCE_DATA_HEX = {_cstr(rh["data"])};')
    lines.append(f'constexpr const char* RESOURCE_RANDOM_HASH_HEX = {_cstr(rh["random_hash"])};')
    lines.append(f'constexpr const char* RESOURCE_HASH_HEX = {_cstr(rh["resource_hash"])};')
    lines.append(f'constexpr const char* RESOURCE_PAYLOAD_TO_ENCRYPT_HEX = {_cstr(rh["payload_to_encrypt"])};')
    lines.append(f'constexpr const char* RESOURCE_CHUNK_HEX = {_cstr(rh["chunk"])};')
    lines.append(f'constexpr const char* RESOURCE_MAP_HASH_HEX = {_cstr(rh["map_hash"])};')
    lines.append("")

    rar = vectors["resource_adv_receive"]
    lines.append(f'constexpr const char* RESOURCE_ADV_RECEIVE_PACKED_HEX = {_cstr(rar["packed"])};')
    lines.append(f'constexpr int RESOURCE_ADV_RECEIVE_T = {rar["t"]};')
    lines.append(f'constexpr int RESOURCE_ADV_RECEIVE_D = {rar["d"]};')
    lines.append(f'constexpr int RESOURCE_ADV_RECEIVE_N = {rar["n"]};')
    lines.append(f'constexpr const char* RESOURCE_ADV_RECEIVE_HASH_HEX = {_cstr(rar["hash"])};')
    lines.append(f'constexpr const char* RESOURCE_ADV_RECEIVE_RANDOM_HASH_HEX = {_cstr(rar["random_hash"])};')
    lines.append(f'constexpr const char* RESOURCE_ADV_RECEIVE_HASHMAP_HEX = {_cstr(rar["hashmap"])};')
    lines.append(f'constexpr int RESOURCE_ADV_RECEIVE_FLAGS = {rar["flags"]};')
    lines.append("")

    rrp = vectors["resource_receive_proof"]
    lines.append(f'constexpr const char* RESOURCE_RECEIVE_PROOF_DATA_HEX = {_cstr(rrp["data"])};')
    lines.append(f'constexpr const char* RESOURCE_RECEIVE_PROOF_RANDOM_HASH_HEX = {_cstr(rrp["random_hash"])};')
    lines.append(f'constexpr const char* RESOURCE_RECEIVE_PROOF_RESOURCE_HASH_HEX = {_cstr(rrp["resource_hash"])};')
    lines.append(f'constexpr const char* RESOURCE_RECEIVE_PROOF_DATA_OUT_HEX = {_cstr(rrp["proof_data"])};')
    lines.append("")

    ratann = vectors["ratchet_announce"]
    lines.append(f'constexpr const char* RATCHET_ANNOUNCE_PRIVATE_KEY_HEX = {_cstr(ratann["private_key"])};')
    lines.append(f'constexpr const char* RATCHET_ANNOUNCE_APP_DATA_HEX = {_cstr(ratann["app_data"])};')
    lines.append(f'constexpr const char* RATCHET_ANNOUNCE_RAW_PACKET_HEX = {_cstr(ratann["raw_packet"])};')
    lines.append(f'constexpr const char* RATCHET_ANNOUNCE_RATCHET_PUBLIC_HEX = {_cstr(ratann["ratchet_public"])};')
    lines.append(f'constexpr bool RATCHET_ANNOUNCE_VALIDATED_BY_RNS = {"true" if ratann["validated_by_rns"] else "false"};')
    lines.append("")

    rie = vectors["ratchet_identity_encrypt"]
    lines.append(f'constexpr const char* RATCHET_IDENTITY_ENCRYPT_PRIVATE_KEY_HEX = {_cstr(rie["identity_private_key"])};')
    lines.append(f'constexpr const char* RATCHET_IDENTITY_ENCRYPT_RATCHET_PRIVATE_HEX = {_cstr(rie["ratchet_private"])};')
    lines.append(f'constexpr const char* RATCHET_IDENTITY_ENCRYPT_RATCHET_PUBLIC_HEX = {_cstr(rie["ratchet_public"])};')
    lines.append(f'constexpr const char* RATCHET_IDENTITY_ENCRYPT_PLAINTEXT_HEX = {_cstr(rie["plaintext"])};')
    lines.append(f'constexpr const char* RATCHET_IDENTITY_ENCRYPT_CIPHERTEXT_TOKEN_HEX = {_cstr(rie["ciphertext_token"])};')
    lines.append("")

    lines.append("struct PacketCase {")
    lines.append("    const char* name;")
    lines.append("    const char* raw_hex;")
    lines.append("    int header_type, context_flag, transport_type, destination_type, packet_type, hops, context;")
    lines.append("    const char* transport_id_hex;")
    lines.append("    const char* destination_hash_hex;")
    lines.append("    const char* data_hex;")
    lines.append("};")
    lines.append("")
    lines.append("constexpr PacketCase PACKET_CASES[] = {")
    for c in vectors["packet_parse_cases"]:
        e = c["expect"]
        tid = e.get("transport_id", "")
        lines.append(
            "    { %s, %s, %d, %d, %d, %d, %d, %d, %d, %s, %s, %s }," % (
                _cstr(c["name"]), _cstr(c["raw"]),
                e["header_type"], e["context_flag"], e["transport_type"],
                e["destination_type"], e["packet_type"], e["hops"], e["context"],
                _cstr(tid), _cstr(e["destination_hash"]), _cstr(e["data"]),
            )
        )
    lines.append("};")
    lines.append(f"constexpr int PACKET_CASES_COUNT = {len(vectors['packet_parse_cases'])};")
    lines.append("")
    lines.append("} // namespace TestVectors")
    lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))


def main():
    import argparse
    import tempfile

    parser = argparse.ArgumentParser()
    parser.add_argument("--header", help="also emit a C++ header of the vectors to this path")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        reticulum = make_reticulum_instance(tmp)

        x25519_ed25519 = vec_x25519_ed25519()
        identity = vec_identity()
        destination = vec_destination(identity["hash"])
        announce = vec_announce()
        packet_cases = vec_packet_parse_cases()
        hkdf_vec = vec_hkdf()
        token_vec = vec_token_aes256()
        link_vec = vec_link_request(reticulum)
        link_signalling = vec_link_signalling()
        request_envelope = vec_request_envelope()
        resource_hash_orderings = vec_resource_hash_orderings()
        identity_encrypt = vec_identity_encrypt()
        resource_adv_receive = vec_resource_advertisement_receive()
        resource_receive_proof = vec_resource_receive_proof()
        ratchet_announce = vec_ratchet_announce()
        ratchet_identity_encrypt = vec_ratchet_identity_encrypt()

    vectors = {
        "rns_version": RNS_VERSION,
        "x25519_ed25519": x25519_ed25519,
        "identity": identity,
        "destination": destination,
        "announce": announce,
        "packet_parse_cases": packet_cases,
        "hkdf": hkdf_vec,
        "token_aes256": token_vec,
        "link_request": link_vec,
        "link_signalling": link_signalling,
        "request_envelope": request_envelope,
        "resource_hash_orderings": resource_hash_orderings,
        "identity_encrypt": identity_encrypt,
        "resource_adv_receive": resource_adv_receive,
        "resource_receive_proof": resource_receive_proof,
        "ratchet_announce": ratchet_announce,
        "ratchet_identity_encrypt": ratchet_identity_encrypt,
    }

    json.dump(vectors, sys.stdout, indent=2)
    sys.stdout.write("\n")

    if args.header:
        emit_cpp_header(vectors, args.header)


if __name__ == "__main__":
    main()
