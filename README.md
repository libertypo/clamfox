ClamFox

DISCLAIMER OF WARRANTY AND LIMITATION OF LIABILITY
THIS SOFTWARE IS PROVIDED ON AN "AS IS" AND "AS AVAILABLE" BASIS, IN ALPHA/EXPERIMENTAL STATE, WITH ALL FAULTS AND WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING, WITHOUT LIMITATION, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, RELIABILITY, OR SECURITY.
BY USING THIS SOFTWARE, THE USER ACKNOWLEDGES THAT IT IS PRE-RELEASE, MAY CONTAIN DEFECTS, ERRORS, OR VULNERABILITIES, AND IS NOT WARRANTED FOR PRODUCTION, CRITICAL, OR SAFETY-SENSITIVE USE.
TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE AUTHORS, MAINTAINERS, CONTRIBUTORS, AND DISTRIBUTORS DISCLAIM ANY AND ALL RESPONSIBILITY AND SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF DATA, PROFITS, BUSINESS, OR REPUTATION, ARISING OUT OF OR IN CONNECTION WITH THE USE OF, INABILITY TO USE, OR PERFORMANCE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
THE USER ASSUMES SOLE RESPONSIBILITY FOR INSTALLATION, CONFIGURATION, OPERATION, COMPLIANCE, AND ANY RESULTS OBTAINED FROM USE OF THE SOFTWARE.
THIS NOTICE DOES NOT LIMIT OR ALTER ANY RIGHTS GRANTED UNDER THE GPL LICENSE.

Firefox extension to filter traffic and scan downloads using ClamAV.

Architecture

ClamFox is designed around a native-host architecture.
The Firefox extension provides browser-side shields.
The ClamFox Native Bridge enables ClamAV scanning, file locking, and host-backed intelligence workflows.

WASM Shield

ClamFox also includes a WebAssembly (WASM) module (`wasm_shield/clamfox_shield.wasm`) used as a fast in-browser pre-scan engine.
It is compiled from Rust sources in `wasm-shield/` and loaded by `background.js` at startup.
Because it runs inside the Firefox extension sandbox, it belongs to the extension build/package pipeline (not native host installation).

What it does:
- Performs homograph detection (for example, punycode and suspicious non-ASCII domain patterns).
- Performs statistical DGA-style detection (entropy, digit density, and consonant density heuristics).
- Runs these checks before native-host URL reputation lookups to reduce latency for obvious threats.
- Verifies WASM integrity using a SHA-256 hash injected at packaging time; if integrity fails, the WASM path is disabled and ClamFox falls back to native checks.


Requirements

OS: Linux (native install)
Browser: Firefox 142+  supported
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

Note: this step is for extension artifacts. `host/install.sh` does not compile WASM.

Package for distribution:
./package.sh

Hardware trust (ERT):
If TPM 2.0 is present AND ERT is enabled/configured, the engine uses TPM-backed (hardware-anchored) module signing verification at startup.

License

GNU General Public License v3. See LICENSE.




