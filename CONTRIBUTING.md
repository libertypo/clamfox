# Contributing to ClamFox

Thank you for your interest in contributing! ClamFox is a privacy-first security extension built on ClamAV. All contributions should uphold its core design principles.

## Core Principles

- **Privacy by design**: No telemetry, no remote data leaks, no user tracking.
- **Local-first**: All scanning and threat lookups use locally cached data wherever possible.
- **Minimal permissions**: Only request OS/browser permissions that are strictly necessary.

## Getting Started

1. **Fork** the repository and clone your fork.
2. **Read the code** — start with `background.js`, `host/clamav_engine.py`, and `host/install.sh`.
3. **Set up the native host** by running `cd host && ./install.sh` (requires Python 3.8+, ClamAV, and standard Linux build tools).
4. **Build the WASM shield** with `./build_wasm.sh` (requires Rust + wasm-pack).
5. **Package** with `./package.sh` to produce `.xpi` and source bundles.

## Submitting Changes

- Target the `main` branch with your pull request.
- Keep commits small and focused — one logical change per commit.
- Write clear commit messages (imperative mood, ≤72 chars subject line).
- Do **not** commit generated files: `.xpi`, `.zip`, `wasm_shield/*.wasm`, or any file listed in `.gitignore`.
- Do **not** commit runtime-generated secrets or machine-specific files (`host/config.json`, TPM key files, signature databases).

## Security-Sensitive Changes

If your change touches any of the following areas, please open an issue first to discuss the approach:

- Native messaging protocol or handshake
- Cryptographic key generation / TPM integration (`host/tpm_provider.py`, `host/ert_signer.py`)
- WASM shield (`wasm-shield/src/lib.rs`)
- Signature hydration / update logic (`update_intelligence()`)
- Content Security Policy or manifest permissions

Please also read [`SECURITY.md`](SECURITY.md) if you discover a vulnerability.

## Code Style

- **JavaScript**: ES2020+, no external dependencies, no build step required.
- **Python**: Python 3.8+ compatible, type hints welcome, `subprocess` calls must use argument lists (no shell=True).
- **Rust**: Stable toolchain, keep WASM binary size minimal.
- **Shell**: POSIX-compatible `#!/usr/bin/env bash`, quote all variables, `set -euo pipefail`.

## License

By submitting a pull request you agree that your contribution will be licensed under the [GNU General Public License v3](LICENSE).
