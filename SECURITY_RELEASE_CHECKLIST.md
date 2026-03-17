Security Release Checklist

Run this checklist before tagging a release.

1. Fail-closed crypto invariants
- Command: `./scripts/critical_invariants.sh`
- Expectation: no insecure fallback phrasing, no high-risk execution anti-patterns.

2. Security-critical vs extended CI gates
- File check: `.github/workflows/security-tests.yml`
- Expectation:
  - `critical-invariants` job exists and runs first.
  - `extended-regression` depends on `needs: critical-invariants`.

3. Release hygiene as code
- Command: `./scripts/local_hygiene.sh`
- Optional apply: `./scripts/local_hygiene.sh --apply`
- Expectation: runtime artifacts are listed or removed safely (guarded by git tracking/ignore checks).

4. Installer determinism
- File check: `host/install.sh`
- Expectation:
  - script uses `set -euo pipefail`.
  - ambiguous operator chains are avoided for permission/init flows.

5. Least privilege review
- File check: `manifest.json`, `manifest_amo.json`, `AMO_REVIEW_NOTES.md`
- Expectation: permissions are justified and reviewed each release.

6. Abuse-case regression tests
- Command: `python3 -m pytest -q test_security_suite.py integration_tests.py`
- Command: `node test_security_suite.js`
- Expectation: all suites pass.

7. Observability without data leakage
- File check: `host/clamav_engine.py`
- Expectation: standardized `error_code` fields are present for auth/rate/input validation failures, with no secret leakage.

8. Reproducible release discipline
- Command: `git status --porcelain`
- Expectation: clean tree before release build.
- Command: `bash package.sh`
- Expectation: deterministic env setup (`LC_ALL`, `TZ`, `SOURCE_DATE_EPOCH`) and successful placeholder guards.

Release workflow performs automated preflight in `.github/workflows/release.yml`.
