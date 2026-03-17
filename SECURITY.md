Security Policy

DISCLAIMER OF WARRANTY AND LIMITATION OF LIABILITY
THIS SOFTWARE IS PROVIDED ON AN "AS IS" AND "AS AVAILABLE" BASIS, IN ALPHA/EXPERIMENTAL STATE, WITH ALL FAULTS AND WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING, WITHOUT LIMITATION, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, RELIABILITY, OR SECURITY.
BY USING THIS SOFTWARE, THE USER ACKNOWLEDGES THAT IT IS PRE-RELEASE, MAY CONTAIN DEFECTS, ERRORS, OR VULNERABILITIES, AND IS NOT WARRANTED FOR PRODUCTION, CRITICAL, OR SAFETY-SENSITIVE USE.
TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE AUTHORS, MAINTAINERS, CONTRIBUTORS, AND DISTRIBUTORS DISCLAIM ANY AND ALL RESPONSIBILITY AND SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF DATA, PROFITS, BUSINESS, OR REPUTATION, ARISING OUT OF OR IN CONNECTION WITH THE USE OF, INABILITY TO USE, OR PERFORMANCE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
THE USER ASSUMES SOLE RESPONSIBILITY FOR INSTALLATION, CONFIGURATION, OPERATION, COMPLIANCE, AND ANY RESULTS OBTAINED FROM USE OF THE SOFTWARE.
THIS NOTICE DOES NOT LIMIT OR ALTER ANY RIGHTS GRANTED UNDER THE GPL LICENSE.

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

Operational Best Practices

Security-critical CI gates.
Critical invariants run first in `.github/workflows/security-tests.yml`.
Extended regression jobs depend on the critical gate.

Release hygiene.
Use `scripts/local_hygiene.sh` before packaging to remove local runtime artifacts safely.

Fail-closed cryptography.
The native host bridge must not emit unsigned responses.
Startup fails fast if machine signing key provisioning is unavailable.

Structured observability.
High-signal host failures include stable `error_code` values for troubleshooting without exposing sensitive data.

Reproducible release discipline.
Use `SECURITY_RELEASE_CHECKLIST.md` before tagging releases.
