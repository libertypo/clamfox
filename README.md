# ClamFox (v0.0.5.7)
### Professional Real-Time Defense & Offensive Counter-Intelligence

ClamFox is not just a scanner; it is a comprehensive **Hybrid Security Engine** for Firefox that bridges the gap between browser sandboxing and OS-level endpoint protection.

## 🛡️ Hybrid Architecture
ClamFox now supports a **Dual-Mode** deployment:
1. **Standalone (AMO Mode)**: Works purely inside Firefox. Provides Visual Anti-Phishing, Prompt Injection Shields, Honeypots, and Privacy Hardening without any local installation.
2. **Total Defense (Core Mode)**: When the **ClamFox Native Bridge** is present, the extension unlocks OS-level ClamAV scanning, atomic file locking, and system-wide clipboard protection.

## 🔥 Key Technical achievements
- **Offensive Intelligence**: Honeypot Decoys, Canvas Fingerprint Poisoning, and C2 Beacon Activity Detection.
- **EDR Atomic Locking**: Downloads are physically sealed (`chmod 000`) at the OS level until verified clean.
- **Hardware-Level Scaling**: Multi-core parallel container analysis (ISO/VHD/ZIP) using `ProcessPoolExecutor`.
- **Privacy First**: Conditional forensic encryption for "Community Burns" (active when no VPN/Tor is detected).
- **Prompt Shielding**: Specialized defense against background prompt injection in LLM portals.

## 🚀 Installation

### 1. Simple (Browser Only)
- Install the `clamfox_standalone_*.xpi` file.
- Total phishing and privacy protection is active immediately.

### 2. Pro (ClamAV Integration)
To unlock real-time binary scanning and EDR features:
1. Ensure `clamav` and `7-zip` are installed.
2. Navigate to the `host/` directory.
3. Run `./install.sh`.

## 📦 Requirements
- **OS**: Linux (Optimized for standard, Snap, and Flatpak).
- **Engine**: ClamAV (`clamd` supported).
- **Native**: Python 3.8+.
- **Browser**: Firefox 142+.

---
*Developed with a focus on Privacy, Transparency, and Hardware Performance.*
