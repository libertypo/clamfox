ClamFox

Firefox extension to filter traffic and scan downloads using ClamAV.

Architecture

ClamFox is designed around a native-host architecture.
The Firefox extension provides browser-side shields.
The ClamFox Native Bridge enables ClamAV scanning, file locking, and host-backed intelligence workflows.

Privacy First

ClamFox is designed with a privacy-first model and no data collection.

100 percent local file scanning. Files are never uploaded. ClamAV runs on your CPU.
Local threat cache. The full URLhaus blocklist is downloaded to your disk. Zero URLs are sent to external servers during browsing.
Local-only history. Block history and scan logs stay in browser local storage and are never synced.
Secure handshake. A machine-unique cryptographic secret is generated at install time so only your extension can talk to your scanner bridge.
No accounts or tracking. No registration, analytics, telemetry, or user ID.
Open source. Browser-to-host communication is visible in this repository.

See PRIVACY_SUMMARY.txt for a full privacy architecture summary including known trade-offs.

Requirements

OS: Linux (native install)
Browser: Firefox 128 or newer, ESR supported
Engine: ClamAV (clamscan or clamd)
Native host runtime: Python 3.8 or newer

The native host installation in host/install.sh is required for full ClamFox operation.

Container support note:
Snap and Flatpak browsers are currently not supported for the host scan engine due to sandbox restrictions.
Native Firefox is currently required.

Setup and Deployment

Register the native messaging host (generates machine-unique secret):
cd host && ./install.sh

Optional. Build the WASM shield from source:
./build_wasm.sh

Package for distribution:
./package.sh

Hardware trust (ERT):
If a TPM 2.0 is present, the engine uses it for hardware-anchored module signing.

License

GNU General Public License v3. See LICENSE.

Contributing

See CONTRIBUTING.md.
To report a security vulnerability privately, see SECURITY.md.

Changelog

See CHANGELOG.md for full change history.
