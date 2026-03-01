# 🛡️ ClamFox Security Audit & TODO

This document tracks identified security "loose ends" and architectural best practices required for a production-grade security tool.

HIGH PRIORITY (Critical Fixes)
- [x] **Harden URL Database Permissions**: `install.sh` currently sets `666` (world-writable) for `urldb.txt`. This allows any local user/malware to "poison" the trust list. 
    *   *Fix*: Change to `644` in `install.sh`. (DONE)
- [x] **Path Traversal Protection**: The native host handles paths sent from the browser. It must strictly verify that paths are within allowed directories (e.g., `~/Downloads` or `/tmp`) using absolute normalization.
    *   *Fix*: Implement `verify_safe_path()` in `clamav_engine.py`. (DONE)
- [x] **C2 Exfiltration Bypass**: `background.js` exempts major telemetry domains (Analytics, FB, etc.) from Beacon detection. Attackers often "live off the land" by using these domains for data theft.
    *   *Fix*: Remove hardcoded exemptions and implement a "throttle-mode" instead of a total bypass. (DONE)

MEDIUM PRIORITY (Hardening)
- [x] **Secret Negotiation**: Honeypot secrets are currently stored in `browser.storage.local`.
    *   *Fix*: Handshake with the host on extension boot to generate a rolling session secret. (DONE)
- [x] **Fail-Open Timeout**: The synchronous `webRequestBlocking` check can hang the browser if the host is unresponsive.
    *   *Fix*: Implement a `Promise.race` in `background.js` to allow requests if the host takes > 3 seconds. (DONE)
- [x] **Manifest Cleanup**: Remove `host/trust_db.json` from `web_accessible_resources` as it's not needed by the front-end and exposes internal logic to web pages. (DONE)
- [x] **ZIP Bomb Protection**: `yara_sanitizer.py` extracts rule bundles without checking for decompression size limits.
    *   *Fix*: Implement `shutil.unpack_archive` with a strictly limited total size or use `ZipFile.testzip()`. (DONE)
- [x] **Memory Management**: Background caches (certificate info, beacon locks) lacked cleanup on tab closure.
    *   *Fix*: Implemented `onRemoved` listeners and enhanced garbage collection in `background.js`. (DONE)

LOW PRIORITY (Cleanliness & Compliance)
- [x] **Host Obfuscation**: Exposing the heuristic thresholds (like the 45% overlap rule) allows targeted evasion.
    *   *Decision*: Dismissed. PyInstaller obfuscation is trivial for determined black-hats to reverse-engineer and adds unnecessary weight/complexity. Transparency serves as a better defense here.
- [x] **Redundant Code**: `check_name.py` is a duplicate of `clamav_engine.py`.
    *   *Fix*: Delete the redundant module to prevent "Logic Drift" (where one is updated and the other is not). (DONE)
- [x] **Enterprise Policy Perception**: Force-installing the extension via `/etc/firefox/policies` can be flagged by AVs as "Browser Hijacker" behavior.
    *   *Best Practice*: Provide a standard `.xpi` for manual install or use `normal_installed` (removable) mode. (DONE)
- [x] **Regex Optimization**: Review all content script matchers for potential ReDoS (Regular Expression Denial of Service) vulnerabilities. (DONE)
- [x] **Cryptographic Signal Analysis**: Implement certificate verification to detect "young" or mismatched TLS certificates for phishing detection. (DONE)
- [x] **Comprehensive Legitimacy Block**: Enforce a full-page block if Visual, Reputation, and Cryptographic checks all fail simultaneously. (DONE)
- [x] **Safe Directory Extraction**: Added `is_within_directory` check to ZIP/TAR extraction to prevent Tar Slip. (DONE)
- [x] **ZIP Bomb Protection**: Implemented uncompressed size and file count limits for archive analysis. (DONE)
- [x] **Consistent Path Validation**: Added `is_safe_path` checks to all critical host actions (scan, lock, restore). (DONE)
- [x] **Elevated Command Hardening**: Secured `pkexec` calls to use `tee` instead of shell interpolation. (DONE)

---

