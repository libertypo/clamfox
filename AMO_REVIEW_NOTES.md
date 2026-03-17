ClamFox AMO Review Notes

Scope
- Target package for AMO: `clamfox_standalone_<version>.xpi`.
- Native host is required for full malware-scanning functionality.

Potential AMO Blocker 1: `nativeMessaging` Permission
- Why it exists:
  ClamFox uses a native host (`clamav_host`) to run local ClamAV scans and quarantine workflows that WebExtensions cannot perform alone.
- User impact:
  Without the host, extension UI still loads but security scanning is degraded and host-missing guidance is shown.
- Data handling:
  Browser-host communication is local IPC, with session secret validation.

Potential AMO Blocker 2: `webRequestBlocking` + Broad Host Permissions
- Why it exists:
  The extension must inspect and block malicious navigations/downloads before content is opened.
- Current scope:
  `http://*/*` and `https://*/*` are used for protection coverage.
- Reviewer context:
  This is a security-filtering extension; broad scope is functional, not tracking-oriented.

Potential AMO Blocker 3: In-Page Hooking of `eval` / `Function` / `document.write`
- Why it exists:
  Behavioral shield logic in `content.js` detects exploit-like payload construction and HTML smuggling indicators.
- Safety posture:
  Hooks are deterministic and local; there is no remote script fetch/eval pipeline.

Potential AMO Blocker 4: Host Dependency / Degraded Mode
- Why it exists:
  ClamAV scanning and quarantine require local host access.
- User transparency:
  Host-missing and communication-error states are surfaced in popup/localized messages.

Potential AMO Blocker 5: Network/Privacy Claims
- Extension-side:
  No remote script loading; extension CSP is `script-src 'self'`.
- Host-side:
  Threat intelligence updates and optional reputation checks are documented in `PRIVACY_SUMMARY.txt` and `README.md`.

Potential AMO Blocker 6: Stale Generated `build_amo` Artifacts
- Risk:
  Submitting stale local build folders can diverge from source manifests.
- Mitigation:
  Submit freshly generated artifacts from `package.sh` only; integration checks validate drift if `build_amo/manifest_amo.json` is present.

Best-Practice Evidence For Review
- Critical security invariants are enforced by `scripts/critical_invariants.sh` and run in CI before extended regression tests.
- Release preflight in `.github/workflows/release.yml` includes critical invariants, local hygiene dry-run, and clean-tree checks.
- Local runtime artifacts are removed via `scripts/local_hygiene.sh` to prevent accidental packaging of host runtime state.
- Native-host failures return stable `error_code` fields to improve supportability without exposing secret material.
- Final release sign-off uses `SECURITY_RELEASE_CHECKLIST.md` for deterministic pre-release verification.
