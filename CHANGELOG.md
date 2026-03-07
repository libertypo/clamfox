Changelog

DISCLAIMER OF WARRANTY AND LIMITATION OF LIABILITY
THIS SOFTWARE IS PROVIDED ON AN "AS IS" AND "AS AVAILABLE" BASIS, IN ALPHA/EXPERIMENTAL STATE, WITH ALL FAULTS AND WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING, WITHOUT LIMITATION, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, RELIABILITY, OR SECURITY.
BY USING THIS SOFTWARE, THE USER ACKNOWLEDGES THAT IT IS PRE-RELEASE, MAY CONTAIN DEFECTS, ERRORS, OR VULNERABILITIES, AND IS NOT WARRANTED FOR PRODUCTION, CRITICAL, OR SAFETY-SENSITIVE USE.
TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE AUTHORS, MAINTAINERS, CONTRIBUTORS, AND DISTRIBUTORS DISCLAIM ANY AND ALL RESPONSIBILITY AND SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF DATA, PROFITS, BUSINESS, OR REPUTATION, ARISING OUT OF OR IN CONNECTION WITH THE USE OF, INABILITY TO USE, OR PERFORMANCE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
THE USER ASSUMES SOLE RESPONSIBILITY FOR INSTALLATION, CONFIGURATION, OPERATION, COMPLIANCE, AND ANY RESULTS OBTAINED FROM USE OF THE SOFTWARE.
THIS NOTICE DOES NOT LIMIT OR ALTER ANY RIGHTS GRANTED UNDER THE GPL LICENSE.

All notable changes to ClamFox are documented here.
Format follows Keep a Changelog.
Reference: https://keepachangelog.com/en/1.0.0/

Version 0.0.6.8
Date: 2026-03-07

Changed
Public-readiness cleanup for repository publication.
Aligned version references with manifests.
Removed remaining inline HTML formatting from legal notice.
Expanded .gitignore coverage for root local development artifacts.

Version 0.0.6.5
Date: 2026-03-04

Added
YARA rule auto-sync integrated into installer. Signatures are fetched and sanitized on each install.sh run.
yara_sanitizer.py hardened for LibClamAV compatibility by removing unsupported xor and base64 modifiers, empty string patterns, and incompatible constructs.
Installer detects and removes stale XOR-scrambled maldet signature files during reinstall to prevent malformed database errors.

Fixed
Removed lingering debug console.log statements from extension JavaScript.
Security audit Phase 9 finding S-1 resolved by removing remaining bare except clauses in native host.

Version 0.0.6.3
Date: 2026-03-03

Security audit, 9-phase set
Phase 8 fixed hydration directory chmod issue R-1 and bare except issue R-2.
Phase 7 fixed findings Q-1 through Q-3, including subprocess hardening and path validation.
Phase 6 fixed findings P-1 through P-4, including input sanitization and error handling.
Phase 5 minimized payload data O-1 and suppressed debug output in yara_sanitizer O-2.
Phase 4 fixed findings N-1 through N-4, including binary path reliability and reference sanitization.
Phase 3 fixed findings C-1 through L-5 across native host and extension.
Phase 1 and Phase 2 delivered binary path reliability and general compliance hardening.

Added
GPLv3 license and updated README documentation.
Public Suffix List domain matching for more accurate phishing detection.
Maldet signature database integration for enhanced Linux malware detection.
Unified quarantine directory with stale lock recovery.
Subprocess timeouts for freshclam and ert_signer.

Version 0.0.6.0
Date: 2026-03-01

Added
EC-DSA log shield with authenticated log encryption and machine-bound P-256 keys in system keyring.
FS-Verity kernel integrity support for read-only lock on signature and block databases.
Opportunistic bubblewrap sandboxing for native host when available.
High-speed WASM security shield for homograph and DGA detection.
Anti-freeze protection with time-lock signed headers on threat databases to prevent replay and freeze attacks.
Zero-knowledge domain whitelist with salted hashes instead of plaintext domains.
Session key rotation every six hours with honeypot decoys.
On-access scanning status detection for clamonacc and clamav-daemon.

Changed
Removed unused scripting and cookies browser permissions.
Hardened clickjacking shield with numeric and alpha analysis plus broader interactive element detection.

Version 0.0.5.9 and earlier

TPM 2.0 and P-256 ECDSA sealing, ERT.
Secure session key rotation with honeypot decoys.
Keylogger detection, DOM anomaly protection, and visual spoofing detectors.
Tor and SOCKS5 update routing plus Canvas and WebGL fingerprint poisoning.
SHA-256 integrity verification during cross-filesystem deployment.
Shannon entropy and N-gram robotic domain detection, DGA heuristics.
Privacy-preserving global threat lookups using k-anonymity prefix model.
New-domain phishing detection via Certificate Transparency logs.
Privacy-first trusted domain storage.
