# ClamFox
Firefox extension to filter traffic and scan downloads using ClamAV.

## 🛡️ Hybrid Architecture
ClamFox is designed around a **native-host architecture**.

The Firefox extension provides browser-side shields, while the **ClamFox Native Bridge** enables ClamAV scanning, file locking, and host-backed intelligence workflows.

---

## 🔒 Privacy First

ClamFox is designed with a "Privacy-First" model — protection without data collection.

- **100% local file scanning** — files are never uploaded; ClamAV runs on your CPU.
- **Local threat cache** — the full URLhaus blocklist is downloaded to your disk. Zero URLs are sent to external servers during browsing.
- **Local-only history** — block history and scan logs live exclusively in browser local storage; never synced.
- **Secure handshake** — a machine-unique cryptographic secret is generated at install time; only your extension can talk to your scanner bridge.
- **No accounts or tracking** — no registration, no analytics, no telemetry, no user ID.
- **Open source** — all browser↔host communication is visible in this repository.

> See [PRIVACY_SUMMARY.txt](PRIVACY_SUMMARY.txt) for a full privacy architecture summary including known trade-offs.

---

## 📦 Requirements

| Component | Minimum |
|-----------|---------|
| OS        | Linux (native install) |
| Browser   | Firefox 128+ (ESR supported) |
| Engine    | ClamAV (`clamscan` or `clamd`) |
| Native    | Python 3.8+ |

> [!IMPORTANT]
> The native host installation (`host/install.sh`) is required for full ClamFox operation.

> [!NOTE]
> **Container Support**: Snap and Flatpak browsers are currently not supported for the host scan engine due to sandbox restrictions. Sorry folks, only native Firefox for now. Snap and Flatpak support is planned for future releases.

---

## 🚀 Setup & Deployment

```bash
# 1. Register the native messaging host (generates machine-unique secret)
cd host && ./install.sh

# 2. (Optional) Build the WASM shield from source
./build_wasm.sh

# 3. Package for distribution
./package.sh   # produces .xpi and AMO source bundles
```

**Hardware Trust (ERT)**: If a TPM 2.0 is present, the engine uses it for hardware-anchored module signing.

---

## ⚖️ License

GNU General Public License v3 — see [LICENSE](LICENSE).

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security vulnerability privately, see [SECURITY.md](SECURITY.md).

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full history of changes.
