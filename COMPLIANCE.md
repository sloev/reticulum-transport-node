# Compliance Audit

* **Packet Format**: Compliant (Binary headers, flags).
* **Addressing**: Compliant (SHA-256 truncation).
* **Link Crypto**: Strict Compliance (HKDF Salt = RequestHash).
* **Encryption**: AES-128-CBC + HMAC-SHA256.
* **Resources**: MDU Fragmentation supported.
