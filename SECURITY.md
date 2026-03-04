# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.0.6.x | ✅ Current |
| < 0.0.6 | ❌ No longer maintained |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues privately via email:

**`obvi84@gmail.com`** — Subject: `[ClamFox Security]`

Include as much detail as possible:
- A description of the vulnerability
- Steps to reproduce
- Affected component (extension JS, native host Python, WASM shield, installer)
- Potential impact

You will receive an acknowledgement within **72 hours**. We aim to release a fix within **14 days** of a confirmed report. You are welcome to request credit in the release notes.

## Security Design

ClamFox is designed around a threat model that assumes the local machine may be semi-hostile. Key security properties:

- **Handshake authentication**: A machine-unique random secret is generated at install time. Every request from the extension to the native host is authenticated with this secret. Replays and injection from other local processes are rejected.
- **Host integrity verification**: The native host binary hash is verified by the extension before each scan.
- **WASM sandboxing**: Performance-critical checks (homograph, DGA detection) run inside Firefox's WebAssembly sandbox, isolated from OS access.
- **Bubblewrap / AppArmor**: The native host optionally runs inside a `bubblewrap` sandbox or AppArmor profile (`host/clamfox.apparmor`) to enforce least-privilege filesystem access.
- **TPM sealing (ERT)**: On machines with a TPM 2.0, the session key is hardware-sealed. Extraction requires physical access.
- **No bundled secrets**: Signature databases and machine keys are generated at runtime and are never committed to the repository.

## Known Limitations

See `TODO.txt` for open hardening items (runtime integrity checksums, Rust rewrite of native IPC).
