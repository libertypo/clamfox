# Changelog

All notable changes to ClamFox are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.0.6.5] — 2026-03-04

### Added
- YARA rule auto-sync integrated into the installer: YARA signatures are now fetched and sanitized on every `install.sh` run.
- `yara_sanitizer.py` hardened for full LibClamAV compatibility: strips unsupported `xor`/`base64` modifiers, empty string patterns, and other incompatible constructs.
- Installer now detects and removes stale XOR-scrambled maldet signature files on reinstall (prevents "Malformed database" clamscan errors after machine migration).

### Fixed
- Removed lingering debug `console.log` statements from extension JS.
- Phase 9 security audit finding S-1: cleared all remaining bare `except` clauses in the native host.

---

## [0.0.6.3] — 2026-03-03

### Security (9-phase audit)
- **Phase 8**: Fixed hydration directory `chmod` (R-1) and bare `except` clauses (R-2).
- **Phase 7**: Fixed findings Q-1 through Q-3 (subprocess hardening, path validation).
- **Phase 6**: Fixed findings P-1 through P-4 (input sanitisation, error handling).
- **Phase 5**: Minimised payload data (O-1) and suppressed debug output in `yara_sanitizer` (O-2).
- **Phase 4**: Fixed findings N-1 through N-4 (binary path reliability, reference sanitisation).
- **Phase 3**: Fixed findings C-1 through L-5 (broad hardening across native host and extension).
- **Phase 1–2**: Binary path reliability and general compliance hardening.

### Added
- GPLv3 license and updated README documentation.
- Public Suffix List (PSL) domain matching for more accurate phishing detection.
- Maldet (LMD) signature databases integrated for enhanced Linux malware detection.
- Unified quarantine directory (`~/.clamfox_quarantine`) with stale lock recovery.
- Subprocess timeouts for `freshclam` and `ert_signer`.

---

## [0.0.6.0] — 2026-03-01

### Added
- **EC-DSA Log Shield**: Authenticated log encryption with machine-bound P-256 keys stored in the system keyring.
- **FS-Verity Kernel Integrity**: Read-only lock on signature and block databases via `fsverity`.
- **Opportunistic Bubblewrap Sandboxing**: Native host runs inside a `bwrap` container when available.
- **High-Speed WASM Security Shield**: Homograph and DGA detection ported to WebAssembly.
- **Anti-Freeze protection**: Time-lock signed headers on threat databases prevent replay/freeze attacks.
- **Zero-Knowledge domain whitelist**: Trusted domains stored as salted hashes, never in plaintext.
- Session key rotation every 6 hours with honeypot decoys.
- On-access scanning status detection (`clamonacc` / `clamav-daemon`).

### Changed
- Removed unused `scripting` and `cookies` browser permissions.
- Clickjacking shield hardened with numeric/alpha analysis and broader interactive element detection.

---

## [0.0.5.9] and earlier

- TPM 2.0 / P-256 ECDSA sealing (ERT).
- Secure session key rotation with honeypot decoys.
- Keylogger detection, DOM anomaly protection, visual spoofing detectors.
- Tor/SOCKS5 update routing and Canvas/WebGL fingerprint poisoning.
- SHA-256 integrity verification during cross-filesystem deployment.
- Shannon entropy & N-gram robotic domain detection (DGA heuristics).
- Privacy-preserving global threat lookups (k-anonymity prefix model).
- New-domain phishing detection via Certificate Transparency logs.
- Privacy-first trusted domain storage.
