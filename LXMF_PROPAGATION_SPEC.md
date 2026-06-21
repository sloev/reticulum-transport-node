# Micro-LXMF Propagation Node (C++ Spec)

This document outlines the technical architecture and implementation plan for building a **Micro-LXMF** (Lightweight Extensible Message Format) Propagation Node inside a bare-metal C++ firmware (RNS-C) targeting the SenseCAP T1000-E (nRF52840).

---

## 1. Architectural Overview

Reticulum operates at Layer 3 (Network). LXMF operates at Layer 7 (Application). Our current firmware (`RNS-C`) perfectly handles Layer 3 routing. To support offline message caching, we must implement a lightweight subset of the Python `LXMRouter` class directly on the MCU.

The SenseCAP will run a background service that listens for Reticulum packets directed to a specific application hash (`lxmf.propagation`), decodes them, saves them to flash, and serves them back when requested by a verified client.

## 2. Protocol Details (The "Sync" Process)

### A. Destination and Addressing
In LXMF, Propagation Nodes do not use IP addresses or ports. They register a Reticulum **Destination** with the specific naming convention:
* **App Name:** `lxmf`
* **Aspect:** `propagation`

When the node boots, it hashes `lxmf.propagation` along with its public key to generate its listener address. It then broadcasts a Reticulum `ANNOUNCE` packet, allowing Sideband/NomadNet to discover it.

### B. Inbound Message Handling (Caching)
When a user sends an offline message, their app encrypts it with the recipient's public key. The app then wraps this ciphertext in a delivery request and sends it to the Propagation Node's hash.

Our C++ implementation must:
1. Register an `Reticulum::Destination` listening for incoming data.
2. Intercept incoming packets on the `lxmf.propagation` aspect.
3. Validate the payload against the LXMF protocol constraints (ensure it has a valid Destination, Source, Signature, and encrypted payload blob).
4. Persist the encrypted blob directly to `LittleFS` without decrypting it (Propagation Nodes never hold the private keys to read the messages).

### C. The Sync Protocol (Retrieval)
When you get home and open Sideband, Sideband sends an LXMF Sync Request to the tracker.
1. **The Request:** Sideband establishes a Reticulum **Link** to the tracker's `lxmf.propagation` destination and sends a `sync_request` containing your Identity Hash.
2. **The Response:** The C++ firmware reads the `LittleFS` directory for any files matching that Identity Hash.
3. **The Transfer:** The firmware streams the encrypted message blobs back over the Reticulum Link in chunks.
4. **The Cleanup:** Once Sideband acknowledges receipt, the C++ firmware deletes the files to free up the 1MB flash storage.

---

## 3. C++ Implementation Details

To achieve this cleanly on an embedded device, we will construct a new module: `lib/Reticulum/src/RetiLXMF.h`.

### Step 1: Storage Layer (LittleFS)
We will map messages to the filesystem using their hashes as filenames to ensure instant lookup times (O(1)) without needing a SQLite database.

```cpp
// Example Directory Structure on nRF52 Flash
/lxmf/
  /pending/
    /<Recipient_Hash_16Bytes>/
       <Message_ID_16Bytes>.msg
       <Message_ID_16Bytes>.msg
```

### Step 2: MessagePack Decoding
LXMF strictly uses **MessagePack** (a binary alternative to JSON) to pack message headers efficiently. We will need to include a lightweight embedded MessagePack parser (e.g., `ArduinoJson` which has MsgPack support, or `cmp`).

```cpp
// Pseudocode for Inbound LXMF parsing
void on_lxmf_receive(const std::vector<uint8_t>& raw_data) {
    // 1. Unpack MsgPack
    DynamicJsonDocument doc(512);
    deserializeMsgPack(doc, raw_data.data(), raw_data.size());
    
    // 2. Extract Routing
    String destHash = toHex(doc["destination"]);
    String msgId = toHex(Crypto::sha256(raw_data));
    
    // 3. Write to Disk
    File f = LittleFS.open("/lxmf/pending/" + destHash + "/" + msgId + ".msg", "w");
    f.write(raw_data.data(), raw_data.size());
    f.close();
}
```

### Step 3: Security & Whitelisting (The "Private" Inbox)
Since 1MB of flash memory is small, an open Propagation Node could be spammed, filling the memory and crashing the node. 

We will implement an **Admin Whitelist**.
* In `RetiConfig.h`, we define a list of accepted `Identity` hashes.
* If `on_lxmf_receive` sees a `destHash` that is *not* yours, it instantly drops the packet.
* This ensures the SenseCAP acts exclusively as *your* private courier.

### Step 4: Memory Constraints & Asynchronous I/O
The nRF52840 has 256KB of RAM. An LXMF message with attachments could theoretically be large (though usually <10KB).
* The C++ sync loop must never buffer the entire message in RAM. 
* We will implement a chunked file reader that streams `255-byte` blocks directly from `LittleFS` to the `Reticulum::Link` socket.

---

## 4. Phase Rollout

1. **Phase 1: Dependencies** - Integrate `ArduinoJson` MsgPack deserialization.
2. **Phase 2: RNS Destination Hooks** - Expose the `Reticulum::Destination` class in `RNS-C` to allow the LXMF module to listen for `lxmf.propagation`.
3. **Phase 3: File System** - Build the `LittleFS` inbox/outbox queues.
4. **Phase 4: Sync Logic** - Implement the Reticulum Link callbacks to handle client sync requests.
