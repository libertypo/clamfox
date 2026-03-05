Security Policy

Supported Versions

Version 0.0.6.x is currently supported.
Versions older than 0.0.6 are no longer maintained.

Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Report security issues privately by email:
obvi84@gmail.com
Use subject: ClamFox Security

Include as much detail as possible:
Description of the vulnerability.
Steps to reproduce.
Affected component, such as extension JavaScript, native host Python, WASM shield, or installer.
Potential impact.

Acknowledgement target is within 72 hours.
Fix target is within 14 days after confirmed report.
You may request credit in release notes.

Security Design

ClamFox assumes a threat model where the local machine may be semi-hostile.
Core security properties:

Handshake authentication.
A machine-unique random secret is generated at install time.
Every request from extension to native host is authenticated with this secret.
Replay and local injection attempts are rejected.

Host integrity verification.
The native host binary hash is verified by the extension before each scan.

WASM sandboxing.
Performance-critical checks such as homograph and DGA detection run inside Firefox WebAssembly sandbox with no direct OS access.

Bubblewrap and AppArmor.
The native host can run inside bubblewrap sandbox or AppArmor profile at host/clamfox.apparmor for least-privilege filesystem access.

TPM sealing, ERT.
On systems with TPM 2.0, session keys are hardware-sealed.
Extraction requires physical access.

No bundled secrets.
Signature databases and machine keys are generated at runtime and are not committed to the repository.

Known Limitations

See TODO.txt for open hardening items including runtime integrity checksums and native IPC hardening roadmap.
