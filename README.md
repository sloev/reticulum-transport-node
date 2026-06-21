<h1>RNS-C</h1>
<hr>
<p>Standalone Reticulum and Micro-LXMF Node for SenseCAP T1000-E.</p>

<h3><a href="https://github.com/sloev/reticulum-transport-node/releases/latest/download/firmware.uf2">[ DOWNLOAD FIRMWARE.UF2 ]</a></h3>

<hr>

<h2>OVERVIEW</h2>
<pre>
RNS-C is a bare-metal C++ implementation of the Reticulum Network Stack (RNS) 
and the LXMF messaging protocol. Designed for the SenseCAP T1000-E (nRF52840 / LR1110).

Features:
- Pure L3 Mesh Routing
- Sub-GHz and BLE Bridging
- Micro-LXMF Inbox (Offline Caching)
- X25519 Ephemeral Key Exchange
- Ed25519 Signatures
- AES-128-CBC Fernet Links
</pre>

<hr>

<h2>ARCHITECTURE</h2>
<pre>
[LORA MESH] <---> [SENSECAP T1000-E (L3 ROUTER)] <---> [LittleFS CACHE]
                          |
                          v
                    [BLE UART] <---> [SIDEBAND APP]
</pre>

<hr>

<h2>INSTALLATION</h2>
<p>1. Download the firmware.uf2 file.</p>
<p>2. Double tap the power button on the SenseCAP T1000-E.</p>
<p>3. A drive named T1000EBOOT will appear on your computer.</p>
<p>4. Drag and drop the UF2 file into the drive.</p>
<p>5. The device will reboot into RNS-C.</p>

<hr>

<h2>USAGE</h2>
<p>1. Power on the device.</p>
<p>2. Open Sideband app on your phone.</p>
<p>3. Add "Bluetooth Serial" interface and select "SenseCAP RNode".</p>
<p>4. Sync will begin automatically for cached messages.</p>

<hr>

<p><small>License: MIT</small></p>