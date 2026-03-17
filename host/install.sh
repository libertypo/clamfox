#!/bin/bash

# ClamFox Pro Installer - Vicious Hardening Edition
# Moves the host to /opt/clamfox and registers it globally.

set -euo pipefail

INSTALL_DIR="/opt/clamfox"
HOST_NAME="clamav_host"
MANIFEST_FILE="${HOST_NAME}.json"
GLOBAL_MANIFEST_DIR="/usr/lib/mozilla/native-messaging-hosts"

# 1. Ensure Root Privileges
if [[ $EUID -ne 0 ]]; then
   echo "🛡️  ClamFox Pro Installer requires root privileges for system hardening."
   exec sudo "$0" "$@"
fi

echo "=================================================="
echo "      CLAMFOX: Hardening & Installation           "
echo "=================================================="

# 2. Dependency Check & Auto-Install
echo "🔍 Verifying System Dependencies..."
MISSING_DEPS=()

# Detect package manager once so install paths and later zip bootstrap are consistent.
PKG_INSTALL_CMD=()
PKG_UPDATE_CMD=()
CLAM_PKG="clamav"
CLAM_DAEMON_PKG=""
PY_REQUESTS_PKG="python3-requests"
PY_CRYPTO_PKG="python3-cryptography"
P7ZIP_PKG="p7zip-full"

if command -v apt-get &> /dev/null; then
    PKG_INSTALL_CMD=(apt-get install -y)
    PKG_UPDATE_CMD=(apt-get update)
    CLAM_DAEMON_PKG="clamav-daemon"
elif command -v dnf &> /dev/null; then
    PKG_INSTALL_CMD=(dnf install -y)
    P7ZIP_PKG="p7zip"
elif command -v pacman &> /dev/null; then
    PKG_INSTALL_CMD=(pacman -S --noconfirm)
    PY_REQUESTS_PKG="python-requests"
    PY_CRYPTO_PKG="python-cryptography"
    P7ZIP_PKG="p7zip"
else
    echo "⚠️  Unknown package manager. Please install dependencies manually."
    exit 1
fi

add_dep() {
    local dep="$1"
    [ -n "$dep" ] || return 0
    for existing in "${MISSING_DEPS[@]}"; do
        [ "$existing" = "$dep" ] && return 0
    done
    MISSING_DEPS+=("$dep")
}

# Command-to-package checks
if ! command -v clamscan &> /dev/null; then
    echo "🚩 Missing: clamscan"
    add_dep "$CLAM_PKG"
    add_dep "$CLAM_DAEMON_PKG"
fi
if ! command -v curl &> /dev/null; then
    echo "🚩 Missing: curl"
    add_dep "curl"
fi
if ! command -v file &> /dev/null; then
    echo "🚩 Missing: file"
    add_dep "file"
fi
if ! command -v 7z &> /dev/null; then
    echo "🚩 Missing: 7z"
    add_dep "$P7ZIP_PKG"
fi
if ! command -v gettext &> /dev/null; then
    echo "🚩 Missing: gettext"
    add_dep "gettext"
fi
if ! command -v tpm2_getcap &> /dev/null; then
    echo "🚩 Missing: tpm2_getcap"
    add_dep "tpm2-tools"
fi
if ! command -v python3 &> /dev/null; then
    echo "🚩 Missing: python3"
    add_dep "python3"
fi

# Python runtime module checks (system-packages only; no pip/venv behavior differences)
if command -v python3 &> /dev/null; then
    if ! python3 -c "import requests" &> /dev/null; then
        echo "🚩 Missing Python module: requests"
        add_dep "$PY_REQUESTS_PKG"
    fi
    if ! python3 -c "import cryptography" &> /dev/null; then
        echo "🚩 Missing Python module: cryptography"
        add_dep "$PY_CRYPTO_PKG"
    fi
fi

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    echo "📦 The following dependencies are missing: ${MISSING_DEPS[*]}"
    echo "⚙️  Automatically installing missing dependencies using ${PKG_INSTALL_CMD[*]}..."
    if [[ ${#PKG_UPDATE_CMD[@]} -gt 0 ]]; then
        "${PKG_UPDATE_CMD[@]}"
    fi
    "${PKG_INSTALL_CMD[@]}" "${MISSING_DEPS[@]}"
else
    echo "✅ All dependencies present."
fi

# 3. Provision /opt/clamfox
echo "🏗️  Provisioning $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/locales"
mkdir -p "$INSTALL_DIR/signatures"
mkdir -p "$INSTALL_DIR/quarantine"

# 4. Extract/Migrate Files
echo "🚚 Migrating host files to system storage..."
DIR="$(cd "$(dirname "$0")" && pwd)"

# Security: Capture source hash BEFORE copy to prevent TOCTOU attacks.
# If the file is tampered between hash-time and copy-time, the verification below will catch it.
SRC_HASH_PRE=$(sha256sum "$DIR/clamav_engine.py" | cut -d' ' -f1)

cp "$DIR/clamav_engine.py" "$INSTALL_DIR/$HOST_NAME.py"
cp "$DIR/yara_sanitizer.py" "$INSTALL_DIR/"
cp "$DIR/tpm_provider.py" "$INSTALL_DIR/"
cp "$DIR/ert_signer.py" "$INSTALL_DIR/"
# Ensure host runtime has trust DB even when installed outside the repo tree.
if [ -f "$DIR/trust_db.json" ]; then
    cp "$DIR/trust_db.json" "$INSTALL_DIR/trust_db.json"
elif [ -f "$DIR/../data/trust_db.json" ]; then
    cp "$DIR/../data/trust_db.json" "$INSTALL_DIR/trust_db.json"
fi
if [ -d "$DIR/locales" ]; then
    cp -r "$DIR/locales/"* "$INSTALL_DIR/locales/"
fi
if [ -d "$DIR/signatures" ]; then
    # Security: Clean up stale/legacy signatures in target
    find "$INSTALL_DIR/signatures" -maxdepth 1 -type f \( -name "*.old" -o -name "*.tmp" \) -delete

    # 🛡️ Stale Maldet Check: .hdb/.ndb files are XOR-scrambled with a machine-specific
    # key at download time. A reinstall on the same or different machine may have
    # pre-scrambled files that no longer match the current machine key — causing
    # clamscan to reject them as "Malformed database" and triggering a scan failure.
    # We detect this by checking if the stored file is valid ASCII (plain ClamAV format).
    # Binary/scrambled files are purged; the host will re-download them on first update.
    echo "🔍 Checking for stale/scrambled maldet signature files..."
    for stale_sig in "$INSTALL_DIR/signatures/"*.hdb "$INSTALL_DIR/signatures/"*.ndb; do
        [ -f "$stale_sig" ] || continue
        if ! file "$stale_sig" | grep -qiE 'ASCII|text'; then
            echo "   ⚠️  Removing stale scrambled sig: $(basename "$stale_sig") (binary/machine-key mismatch)"
            rm -f "$stale_sig"
        fi
    done

    cp -r "$DIR/signatures/"* "$INSTALL_DIR/signatures/"
fi

# Verify copy integrity: hash the destination and compare with source hash
DST_HASH_POST=$(sha256sum "$INSTALL_DIR/$HOST_NAME.py" | cut -d' ' -f1)
if [ "$SRC_HASH_PRE" != "$DST_HASH_POST" ]; then
    echo "❌ INTEGRITY ERROR: Host script copy failed verification! Source and destination hashes do not match."
    echo "   This may indicate a TOCTOU attack or disk error. Aborting installation."
    exit 1
fi
echo "✅ Copy integrity verified (SHA-256 match)."

# Migration of config or generation of new one
echo "🔐 Performing Vicious Baseline Seal..."
SCRIPT_HASH=$(python3 -c "import hashlib; print(hashlib.sha256(open('$INSTALL_DIR/$HOST_NAME.py','rb').read()).hexdigest())")
CLAM_PATH=$(command -v clamdscan || command -v clamscan)
CLAM_HASH=$(python3 -c "import hashlib; print(hashlib.sha256(open('$CLAM_PATH','rb').read()).hexdigest())")
ACTUAL_USER=${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}
USER_GROUP=$(id -gn "$ACTUAL_USER")
USER_HOME=$(getent passwd "$ACTUAL_USER" | cut -d: -f6)
if [ -z "$USER_HOME" ]; then
    USER_HOME="/home/$ACTUAL_USER"
fi
USER_QUARANTINE_DIR="$USER_HOME/.clamfox_quarantine"

if [ -f "$DIR/config.json" ]; then
    cp "$DIR/config.json" "$INSTALL_DIR/"
    # Filter sensitive keys during migration
    python3 -c "import json; c=json.load(open('$INSTALL_DIR/config.json')); c={k:v for k,v in c.items() if k not in ['secret', 'integrity_hash', 'honeypot_secret']}; c['integrity_hash']='$SCRIPT_HASH'; c['binary_hash']='$CLAM_HASH'; json.dump(c, open('$INSTALL_DIR/config.json','w'), indent=4)"
else
    # Create empty public config; engine will generate and keyring-store secrets on first run
    echo "{\"anti_tamper\": true, \"last_rotation\": $(date +%s), \"integrity_hash\": \"$SCRIPT_HASH\", \"binary_hash\": \"$CLAM_HASH\"}" > "$INSTALL_DIR/config.json"
fi

# Hardening: Ensure config.json is never world-readable
chown "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/config.json"
chmod 600 "$INSTALL_DIR/config.json"

# 4.5 Ephemeral Root Trust (ERT) Activation
if command -v tpm2_getcap &> /dev/null; then
    echo "🛡️  TPM 2.0 Detected. Initializing Ephemeral Root Trust (ERT)..."
    python3 "$INSTALL_DIR/ert_signer.py" || echo "⚠️  ERT Initialization failed. Falling back to Software Vault."
else
    echo "ℹ️  TPM 2.0 not found. ERT Hardware Sealing will be disabled."
fi

# 5. Hardening Permissions
echo "🔒 Hardening Filesystem Permissions..."
chown -R root:root "$INSTALL_DIR"
chown -R "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/quarantine"
chown -R "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/signatures"
chmod 755 "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR/$HOST_NAME.py"
chmod 755 "$INSTALL_DIR/ert_signer.py"
chmod 755 "$INSTALL_DIR/tpm_provider.py"
chown "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/config.json"
chmod 600 "$INSTALL_DIR/config.json"
chmod 644 "$INSTALL_DIR/trust_db.json" 2>/dev/null || true
chmod 700 "$INSTALL_DIR/quarantine" 
chmod 755 "$INSTALL_DIR/signatures"
if ! chmod 644 "$INSTALL_DIR/urldb.txt" 2>/dev/null; then
    touch "$INSTALL_DIR/urldb.txt"
    chmod 644 "$INSTALL_DIR/urldb.txt"
fi
chown "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/urldb.txt" "$INSTALL_DIR/phishdb.txt" "$INSTALL_DIR/whitelistdb.txt" 2>/dev/null || true
chmod 644 "$INSTALL_DIR/phishdb.txt" "$INSTALL_DIR/whitelistdb.txt" 2>/dev/null || true

# Runtime host path hardening: the engine stages downloads in ~/.clamfox_quarantine.
# If this directory is missing or root-owned from prior runs, secure pre-scan staging fails.
mkdir -p "$USER_QUARANTINE_DIR"
chown -R "$ACTUAL_USER:$USER_GROUP" "$USER_QUARANTINE_DIR"
chmod 700 "$USER_QUARANTINE_DIR"

# 5.5 Supply-Chain Canary Provisioning
echo "🛡️  Planting Supply-Chain Canary..."
CANARY_FILE="$INSTALL_DIR/signatures/.canary"
echo "ClamFox Genuine Build: $(date)" > "$CANARY_FILE"
chmod 644 "$CANARY_FILE"
chown root:root "$CANARY_FILE"

# 5.6 FS-Verity Kernel Integrity (Optional/Opportunistic)
if command -v fsverity >/dev/null 2>&1; then
    echo "🛡️  FS-VERITY: Detecting Kernel support for Immutability..."
    for f in "$INSTALL_DIR/clamav_host.py" "$INSTALL_DIR/tpm_provider.py" "$INSTALL_DIR/yara_sanitizer.py"; do
        if [ -f "$f" ]; then
             fsverity enable "$f" 2>/dev/null && echo "   [OK] Kernel-level lock active for $(basename "$f")" || echo "   [SKIP] Storage/Kernel does not support verity for $(basename "$f")"
        fi
    done
fi

# 6. Global Registration
echo "📋 Cleaning up conflicting local manifests..."
# Aggressively remove any user-local or profile-specific manifests that might override the global one
USER_HOME=$(getent passwd "$ACTUAL_USER" | cut -d: -f6)
if [ -z "$USER_HOME" ]; then
    echo "❌ Unable to resolve home directory for user: $ACTUAL_USER"
    exit 1
fi
find "$USER_HOME/.mozilla" -name "$MANIFEST_FILE" -exec rm -f {} + 2>/dev/null || true

# Force extension payload refresh on next Firefox start/reload.
# With installation_mode=normal_installed, Firefox can keep a cached profile XPI
# if version doesn't advance, causing stale background.js behavior.
find "$USER_HOME/.mozilla/firefox" -path "*/extensions/clamfox@ovidio.me.xpi" -exec rm -f {} + 2>/dev/null || true

echo "📋 Registering Native Messaging Host globally..."
mkdir -p "$GLOBAL_MANIFEST_DIR"

MANIFEST_SRC="$DIR/$MANIFEST_FILE"
SCRIPT_PATH="$INSTALL_DIR/$HOST_NAME.py"

sed "s|\"path\": \".*\"|\"path\": \"$SCRIPT_PATH\"|" "$MANIFEST_SRC" > "$GLOBAL_MANIFEST_DIR/$MANIFEST_FILE"
chmod 644 "$GLOBAL_MANIFEST_DIR/$MANIFEST_FILE"

# 8. Managed Extension Sideloading (Enterprise Policy)
echo "📦 Packaging and Sideloading Extension (Non-Forced)..."
echo "   (Using 'normal_installed' mode to allow user control while ensuring availability)"

if ! command -v zip &> /dev/null; then
    "${PKG_INSTALL_CMD[@]}" zip
fi

PARENT_DIR="$(cd "$DIR/.." && pwd)"
TEMP_BUILD=$(mktemp -d /tmp/clamfox_build.XXXXXX)
trap 'rm -rf "$TEMP_BUILD"' EXIT
cp -r "$PARENT_DIR/background.js" "$PARENT_DIR/content.js" "$PARENT_DIR/content.css" \
      "$PARENT_DIR/design_tokens.css" "$PARENT_DIR/manifest.json" "$PARENT_DIR/popup" \
      "$PARENT_DIR/icons" "$PARENT_DIR/_locales" "$TEMP_BUILD/"

(cd "$TEMP_BUILD" && zip -r "$INSTALL_DIR/clamfox.xpi" ./* > /dev/null)
rm -rf "$TEMP_BUILD"
trap - EXIT
chmod 644 "$INSTALL_DIR/clamfox.xpi"

POLICY_DIR="/etc/firefox/policies"
mkdir -p "$POLICY_DIR"
POLICY_FILE="$POLICY_DIR/policies.json"

CLAMFOX_POLICY_FILE="$POLICY_FILE" CLAMFOX_USER_HOME="$USER_HOME" python3 - <<'PYEOF'
import json
import os

path = os.environ.get("CLAMFOX_POLICY_FILE")
user_home = os.environ.get("CLAMFOX_USER_HOME")
if not path:
    raise RuntimeError("Missing CLAMFOX_POLICY_FILE")
if not user_home:
    raise RuntimeError("Missing CLAMFOX_USER_HOME")

download_dir = os.path.join(user_home, "Downloads")

data = {}
if os.path.exists(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}

policies = data.setdefault("policies", {})
ext_settings = policies.setdefault("ExtensionSettings", {})
ext_settings["clamfox@ovidio.me"] = {
    "installation_mode": "normal_installed",
    "install_url": "file:///opt/clamfox/clamfox.xpi"
}

# Force download behavior at browser level (stable alternative to webRequest
# cancel/re-download hooks): disable internal inline viewers so files land on
# disk and are scanned by the post-download shield.
prefs = policies.setdefault("Preferences", {})
prefs["pdfjs.disabled"] = {"Value": True, "Status": "locked"}
prefs["browser.download.viewableInternally.enabledTypes"] = {"Value": "", "Status": "locked"}
prefs["browser.download.useDownloadDir"] = {"Value": True, "Status": "locked"}
prefs["browser.download.folderList"] = {"Value": 2, "Status": "locked"}
prefs["browser.download.always_ask_before_handling_new_types"] = {"Value": False, "Status": "locked"}
prefs["browser.download.dir"] = {"Value": download_dir, "Status": "locked"}
prefs["browser.download.lastDir"] = {"Value": download_dir, "Status": "locked"}

tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
PYEOF
chmod 644 "$POLICY_FILE"
# 8.5 Initial YARA Signature Sync
echo "📡 Syncing YARA community rules (background, may take a moment)..."
YARA_URL="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
SIG_DIR="$INSTALL_DIR/signatures"
python3 - <<PYEOF 2>/dev/null &
import sys
sys.path.insert(0, '$INSTALL_DIR')
try:
    from yara_sanitizer import YaraSanitizer
    s = YaraSanitizer('$SIG_DIR')
    ok, msg = s.sync_from_url('$YARA_URL', 'yara-rules-core.yar')
    # Silent: do not print — stdout is captured by shell, not native messaging
except Exception:
    pass
PYEOF
echo "   (YARA sync running in background — rules will be ready shortly)"

# 9. Mandatory Access Control (AppArmor/SELinux)
MAC_MODE="${CLAMFOX_MAC_MODE:-auto}"  # auto|apparmor|selinux|disable
APPARMOR_PROFILE_DST="/etc/apparmor.d/opt.clamfox.clamav_host"
APPARMOR_PROFILE_SRC="$DIR/clamfox.apparmor"
SELINUX_POLICY_SRC="$DIR/clamfox_host.cil"

echo "🛡️  Configuring Mandatory Access Control (mode: $MAC_MODE)..."

if [[ "$MAC_MODE" == "disable" ]]; then
    echo "⚠️  MAC explicitly disabled by CLAMFOX_MAC_MODE=disable"
elif [[ "$MAC_MODE" == "apparmor" ]] || { [[ "$MAC_MODE" == "auto" ]] && command -v apparmor_parser &> /dev/null && [ -f "$APPARMOR_PROFILE_SRC" ]; }; then
    cp "$APPARMOR_PROFILE_SRC" "$APPARMOR_PROFILE_DST"
    apparmor_parser -r "$APPARMOR_PROFILE_DST"
    echo "✅ AppArmor profile loaded: $APPARMOR_PROFILE_DST"
elif [[ "$MAC_MODE" == "selinux" ]] || { [[ "$MAC_MODE" == "auto" ]] && command -v selinuxenabled &> /dev/null && selinuxenabled; }; then
    SELINUX_EXPLICIT=false
    if [[ "$MAC_MODE" == "selinux" ]]; then
        SELINUX_EXPLICIT=true
    fi

    if ! command -v semodule &> /dev/null || [ ! -f "$SELINUX_POLICY_SRC" ]; then
        if [[ "$SELINUX_EXPLICIT" == true ]]; then
            echo "❌ SELinux mode requires semodule and policy file: $SELINUX_POLICY_SRC"
            echo "   Install required SELinux tooling/policy or choose CLAMFOX_MAC_MODE=disable"
            exit 1
        fi
        echo "⚠️  SELinux selected but semodule/module file unavailable; confinement may be limited."
    else
        if ! semodule -i "$SELINUX_POLICY_SRC"; then
            if [[ "$SELINUX_EXPLICIT" == true ]]; then
                echo "❌ Failed to load SELinux module from $SELINUX_POLICY_SRC in explicit selinux mode"
                exit 1
            fi
            echo "⚠️  Failed to load SELinux module from $SELINUX_POLICY_SRC"
        fi
    fi

    if command -v semanage &> /dev/null; then
        semanage fcontext -a -t clamfox_host_exec_t "$INSTALL_DIR/clamav_host.py" 2>/dev/null || \
        semanage fcontext -m -t clamfox_host_exec_t "$INSTALL_DIR/clamav_host.py" 2>/dev/null || true
    fi

    if command -v restorecon &> /dev/null; then
        restorecon -v "$INSTALL_DIR/clamav_host.py" || true
        restorecon -RF "$INSTALL_DIR" || true
    fi

    if command -v getenforce &> /dev/null; then
        echo "✅ SELinux detected ($(getenforce)); attempted dedicated clamfox_host policy load."
    else
        echo "✅ SELinux mode selected; attempted dedicated clamfox_host policy load."
    fi
else
    echo "❌ No supported MAC backend detected. Refusing unconfined install in mode: $MAC_MODE"
    echo "   Install AppArmor or enable SELinux, or explicitly opt out with CLAMFOX_MAC_MODE=disable"
    exit 1
fi

# 10. Final Summary
echo "=================================================="
echo "✅ ClamFox Host installed in /opt/clamfox"
echo "✅ Registered for Firefox (Native Host)"
echo "✅ Extension sideloaded (Removable by user)"
echo "✅ Privacy Shield & Anti-Tamper Ready"
echo "--------------------------------------------------"
echo "🚀 IMPORTANT: Restart Firefox to activate the persistent shield."
echo "🚀 Performance Tip:"
echo "   sudo systemctl enable --now clamav-daemon"
echo "=================================================="
