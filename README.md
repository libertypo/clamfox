ClamFox

Firefox extension to filter traffic and scan downloads using ClamAV.

Architecture

ClamFox is designed around a native-host architecture.
The Firefox extension provides browser-side shields.
The ClamFox Native Bridge enables ClamAV scanning, file locking, and host-backed intelligence workflows.


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
