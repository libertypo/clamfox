Contributing to ClamFox

Thank you for your interest in contributing.
ClamFox is a privacy-first security extension built on ClamAV.
All contributions should uphold its core design principles.

Core Principles

Privacy by design: no telemetry, no remote data leaks, no user tracking.
Local first: scanning and threat lookups should use locally cached data where possible.
Minimal permissions: request only the OS and browser permissions that are strictly necessary.

Getting Started

Fork the repository and clone your fork.
Read the code first, especially background.js, host/clamav_engine.py, and host/install.sh.
Set up the native host with:
cd host && ./install.sh
This requires Python 3.8 or newer, ClamAV, and standard Linux build tools.

Build the WASM shield with:
./build_wasm.sh
This requires Rust and wasm-pack.

Package with:
./package.sh
This produces XPI and source bundles.

Submitting Changes

Target the main branch with your pull request.
Keep commits small and focused, one logical change per commit.
Use clear commit messages in imperative mood with a short subject line.
Do not commit generated files such as XPI, ZIP, wasm_shield/*.wasm, or anything listed in .gitignore.
Do not commit runtime-generated secrets or machine-specific files such as host/config.json, TPM key files, or signature databases.

Security-Sensitive Changes

If your change touches any of these areas, open an issue first to discuss the approach:
Native messaging protocol or handshake.
Cryptographic key generation or TPM integration in host/tpm_provider.py and host/ert_signer.py.
WASM shield code in wasm-shield/src/lib.rs.
Signature hydration or update logic in update_intelligence().
Content Security Policy or manifest permissions.

If you discover a vulnerability, read SECURITY.md and report it privately.

Code Style

JavaScript: ES2020 or newer, no external dependencies, no build step required.
Python: Python 3.8 or newer, type hints welcome, subprocess calls must use argument lists and never shell=True.
Rust: stable toolchain, keep WASM binary size minimal.
Shell: use POSIX-compatible /usr/bin/env bash, quote variables, and use set -euo pipefail.

License

By submitting a pull request, you agree your contribution is licensed under GNU General Public License v3.
See LICENSE.
