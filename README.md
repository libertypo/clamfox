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

Package for distribution:
./package.sh

Hardware trust (ERT):
If TPM 2.0 is present AND ERT is enabled/configured, the engine uses TPM-backed (hardware-anchored) module signing verification at startup.

License

GNU General Public License v3. See LICENSE.




