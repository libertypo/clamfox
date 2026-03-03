# ClamFox
Firefox extension to filter traffic and downloads

## 🛡️ Hybrid Architecture
ClamFox supports a **Dual-Mode** deployment:
1. **Standalone (AMO Mode)**: Works purely inside Firefox. Provides Visual Anti-Phishing, Prompt Injection Shields, Honeypots, and Privacy Hardening.
2. **Total Defense (Core Mode)**: When the **ClamFox Native Bridge** is present, the extension unlocks OS-level ClamAV scanning, atomic file locking, and system-wide clipboard protection.

---

==================================================
CLAMFOX - PRIVACY ARCHITECTURE SUMMARY
==================================================

This extension was designed with a "Privacy-First" model, 
aiming to provide protection without the massive 
data collection typical of commercial software.
All due dilligence was exerted to insure no private data
is neither collected nor transmited outside the local 
context of execution.

--------------------------------------------------
                THE PRIVACY
--------------------------------------------------

1. 100% LOCAL FILE SCANNING (ClamAV)
   - Unlike cloud AVs, your files are NEVER uploaded to a server
     for analysis. Scanning happens entirely on your CPU.
   
2. PRIVATE BROWSING PROTECTION (URLhaus Local Cache)
   - Your web history is 100% private. 
   - We download the entire malware blocklist to your SSD. 
   - Every site you visit is checked against this local file.
   - ZERO URLs are sent to URLhaus/abuse.ch during browsing.
   - "Strict Blocking" mode ensures the site is checked BEFORE 
     the browser even connects to the server. No more "flash" of 
     malicious content.

3. LOCAL-ONLY BLOCK HISTORY
   - The "Block History" and scan logs are stored EXCLUSIVELY in 
     your browser's local storage. This data is never synced
     to the cloud or shared with third parties.

4. SECURE HANDSHAKE & ANTI-TAMPER
   - A unique, cryptographically random secret is generated on 
     your machine during install. This "Handshake" ensures that 
     only the extension can talk to your scanner bridge.
   - Host script integrity is verified locally before any scan.

5. NO USER ACCOUNTS OR TRACKING
   - No registration, no analytics, and no telemetry.
   - The extension does not generate a unique User ID.

6. OPEN SOURCE & TRANSPARENT
   - All communication between the browser and the host is 
     visible in the project code (Python/JS).

--------------------------------------------------
                 🚀 SETUP & DEPLOYMENT
--------------------------------------------------

1. **Prerequisites**: Python 3.8+, ClamAV (clamscan), and standard Linux build tools.
2. **Setup**:
   - Run `cd host && ./install.sh` to register the native messaging host.
   - This generates a machine-unique secret and registers the JSON manifest.
3. **Hardware Trust (ERT)**:
   - If a TPM 2.0 is present, the engine will attempt to use it for hardware-anchored module signing.
4. **Build**:
   - Run `./package.sh` to generate production-ready `.xpi` and source bundles.
   - This script automatically injects unique supply-chain canaries.

--------------------------------------------------
                  ⚖️ LICENSE
--------------------------------------------------
This project is licensed under the [GNU General Public License v3](LICENSE).

## 📦 Requirements
- **OS**: Linux (standard, Snap, and Flatpak supported).
- **Engine**: ClamAV (`clamd` supported).
- **Native**: Python 3.8+.
- **Browser**: Firefox 128+ (ESR supported).
