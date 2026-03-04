#!/bin/bash

# ClamFox Pro Installer - Vicious Hardening Edition
# Moves the host to /opt/clamfox and registers it globally.

set -e

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

# Map commands to package names
declare -A pkg_map
pkg_map=( 
    ["clamscan"]="clamav clamav-daemon" 
    ["curl"]="curl" 
    ["file"]="file" 
    ["7z"]="p7zip-full" 
    ["xclip"]="xclip" 
    ["gettext"]="gettext" 
    ["tpm2_getcap"]="tpm2-tools"
    ["python3"]="python3-requests" # Ensure requests for YARA sync
)

for cmd in "${!pkg_map[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo "🚩 Missing: $cmd"
        MISSING_DEPS+=("${pkg_map[$cmd]}")
    fi
done

# Special check for requests library if python3 itself exists
if command -v python3 &> /dev/null; then
    if ! python3 -c "import requests" &> /dev/null; then
        echo "🚩 Missing: python3-requests"
        MISSING_DEPS+=("python3-requests")
    fi
fi

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    echo "📦 The following dependencies are missing: ${MISSING_DEPS[*]}"
    
    # Detect Package Manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get install -y"
        update_cmd="apt-get update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf install -y"
        update_cmd=""
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman -S --noconfirm"
        update_cmd=""
    else
        echo "⚠️  Unknown package manager. Please install dependencies manually: ${MISSING_DEPS[*]}"
        exit 1
    fi

    echo "⚙️  Automatically installing missing dependencies using $PKG_MANAGER..."
    if [[ -n "$update_cmd" ]]; then $update_cmd; fi
    $PKG_MANAGER "${MISSING_DEPS[@]}"
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
if [ -d "$DIR/locales" ]; then
    cp -r "$DIR/locales/"* "$INSTALL_DIR/locales/"
fi
if [ -d "$DIR/signatures" ]; then
    # Security: Clean up signatures in target to avoid legacy AV-blocked files
    rm -f "$INSTALL_DIR/signatures/"*.hdb "$INSTALL_DIR/signatures/"*.ndb "$INSTALL_DIR/signatures/"*.old "$INSTALL_DIR/signatures/"*.tmp
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

if [ -f "$DIR/config.json" ]; then
    cp "$DIR/config.json" "$INSTALL_DIR/"
    python3 -c "import json; c=json.load(open('$INSTALL_DIR/config.json')); c['integrity_hash']='$SCRIPT_HASH'; c['binary_hash']='$CLAM_HASH'; json.dump(c, open('$INSTALL_DIR/config.json','w'), indent=4)"
else
    SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
    echo "{\"secret\": \"$SECRET\", \"anti_tamper\": true, \"last_rotation\": $(date +%s), \"integrity_hash\": \"$SCRIPT_HASH\", \"binary_hash\": \"$CLAM_HASH\"}" > "$INSTALL_DIR/config.json"
fi

# 4.5 Ephemeral Root Trust (ERT) Activation
if command -v tpm2_getcap &> /dev/null; then
    echo "🛡️  TPM 2.0 Detected. Initializing Ephemeral Root Trust (ERT)..."
    python3 "$INSTALL_DIR/ert_signer.py" || echo "⚠️  ERT Initialization failed. Falling back to Software Vault."
else
    echo "ℹ️  TPM 2.0 not found. ERT Hardware Sealing will be disabled."
fi

# 5. Hardening Permissions
echo "🔒 Hardening Filesystem Permissions..."
ACTUAL_USER=${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}
USER_GROUP=$(id -gn "$ACTUAL_USER")

chown -R root:root "$INSTALL_DIR"
chown -R "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/quarantine"
chown -R "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/signatures"
chmod 755 "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR/$HOST_NAME.py"
chmod 755 "$INSTALL_DIR/ert_signer.py"
chmod 755 "$INSTALL_DIR/tpm_provider.py"
chown "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/config.json"
chmod 600 "$INSTALL_DIR/config.json"
chmod 700 "$INSTALL_DIR/quarantine" 
chmod 755 "$INSTALL_DIR/signatures"
chmod 644 "$INSTALL_DIR/urldb.txt" 2>/dev/null || touch "$INSTALL_DIR/urldb.txt" && chmod 644 "$INSTALL_DIR/urldb.txt"
chown "$ACTUAL_USER:$USER_GROUP" "$INSTALL_DIR/urldb.txt" "$INSTALL_DIR/phishdb.txt" "$INSTALL_DIR/whitelistdb.txt" 2>/dev/null || true
chmod 644 "$INSTALL_DIR/phishdb.txt" "$INSTALL_DIR/whitelistdb.txt" 2>/dev/null || true

# 5.5 Supply-Chain Canary Provisioning
echo "🛡️  Planting Supply-Chain Canary..."
CANARY_FILE="$INSTALL_DIR/signatures/.canary"
echo "ClamFox Genuine Build: $(date)" > "$CANARY_FILE"
chmod 644 "$CANARY_FILE"
chown root:root "$CANARY_FILE"

# 5.6 FS-Verity Kernel Integrity (Optional/Opportunistic)
if command -v fsverity >/dev/null 2>&1; then
    echo "🛡️  FS-VERITY: Detecting Kernel support for Immutability..."
    for f in "$INSTALL_DIR/clamav_engine.py" "$INSTALL_DIR/tpm_provider.py" "$INSTALL_DIR/yara_sanitizer.py"; do
        if [ -f "$f" ]; then
             fsverity enable "$f" 2>/dev/null && echo "   [OK] Kernel-level lock active for $(basename "$f")" || echo "   [SKIP] Storage/Kernel does not support verity for $(basename "$f")"
        fi
    done
fi

# 6. Global Registration
echo "📋 Cleaning up conflicting local manifests..."
# Aggressively remove any user-local or profile-specific manifests that might override the global one
USER_HOME=$(eval echo "~$ACTUAL_USER")
find "$USER_HOME/.mozilla" -name "$MANIFEST_FILE" -exec rm -f {} + 2>/dev/null || true

echo "📋 Registering Native Messaging Host globally..."
mkdir -p "$GLOBAL_MANIFEST_DIR"

MANIFEST_SRC="$DIR/$MANIFEST_FILE"
SCRIPT_PATH="$INSTALL_DIR/$HOST_NAME.py"

sed "s|\"path\": \".*\"|\"path\": \"$SCRIPT_PATH\"|" "$MANIFEST_SRC" > "$GLOBAL_MANIFEST_DIR/$MANIFEST_FILE"
chmod 644 "$GLOBAL_MANIFEST_DIR/$MANIFEST_FILE"

# 7. Snap/Flatpak Bridge (Host registration)
USER_HOME=$(eval echo "~$ACTUAL_USER")
# Snap Firefox
SNAP_DIR="$USER_HOME/snap/firefox/common/.mozilla/native-messaging-hosts"
if [ -d "$USER_HOME/snap/firefox" ]; then
    mkdir -p "$SNAP_DIR"
    cp "$GLOBAL_MANIFEST_DIR/$MANIFEST_FILE" "$SNAP_DIR/"
    chown -R "$ACTUAL_USER:$USER_GROUP" "$SNAP_DIR"
fi
# Flatpak Firefox
FLATPAK_DIR="$USER_HOME/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts"
if [ -d "$USER_HOME/.var/app/org.mozilla.firefox" ]; then
    echo "📦  Configuring Flatpak Firefox Bridge..."
    mkdir -p "$FLATPAK_DIR"
    WRAPPER_PATH="$INSTALL_DIR/clamav_host_wrapper.sh"
    # Ensure wrapper exists in INSTALL_DIR
    cp "$DIR/host/clamav_host_wrapper.sh" "$WRAPPER_PATH" 2>/dev/null || cp "$DIR/clamav_host_wrapper.sh" "$WRAPPER_PATH" 2>/dev/null
    chmod 755 "$WRAPPER_PATH"
    chown "root:root" "$WRAPPER_PATH"
    
    # Create Flatpak-specific manifest pointing to the WRAPPER
    sed "s|\"path\": \".*\"|\"path\": \"$WRAPPER_PATH\"|" "$MANIFEST_SRC" > "$FLATPAK_DIR/$MANIFEST_FILE"
    chmod 644 "$FLATPAK_DIR/$MANIFEST_FILE"
    chown "$ACTUAL_USER:$USER_GROUP" "$FLATPAK_DIR/$MANIFEST_FILE"
fi

# 8. Managed Extension Sideloading (Enterprise Policy)
echo "📦 Packaging and Sideloading Extension (Non-Forced)..."
echo "   (Using 'normal_installed' mode to allow user control while ensuring availability)"

if ! command -v zip &> /dev/null; then
    $PKG_MANAGER zip
fi

PARENT_DIR="$(cd "$DIR/.." && pwd)"
TEMP_BUILD="/tmp/clamfox_build"
rm -rf "$TEMP_BUILD"
mkdir -p "$TEMP_BUILD"
cp -r "$PARENT_DIR/background.js" "$PARENT_DIR/content.js" "$PARENT_DIR/content.css" \
      "$PARENT_DIR/design_tokens.css" "$PARENT_DIR/manifest.json" "$PARENT_DIR/popup" \
      "$PARENT_DIR/icons" "$PARENT_DIR/_locales" "$TEMP_BUILD/"

(cd "$TEMP_BUILD" && zip -r "$INSTALL_DIR/clamfox.xpi" ./* > /dev/null)
rm -rf "$TEMP_BUILD"
chmod 644 "$INSTALL_DIR/clamfox.xpi"

POLICY_DIR="/etc/firefox/policies"
mkdir -p "$POLICY_DIR"

cat <<EOF > "$POLICY_DIR/policies.json"
{
  "policies": {
    "ExtensionSettings": {
      "clamfox@ovidio.me": {
        "installation_mode": "normal_installed",
        "install_url": "file:///opt/clamfox/clamfox.xpi"
      }
    }
  }
}
EOF

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
# ─────────────────────────────────────────────────────────────────────────────
# ⚠️  SECURITY RISK NOTICE (Audit finding L-4):
#   AppArmor has been intentionally disabled for cross-distro compatibility.
#   Without a MAC profile, a compromised clamav_engine.py process has full
#   user-level filesystem access.
#
#   This trade-off was accepted by the project maintainer.
#   To re-enable AppArmor in a future release:
#     1. Restore host/clamfox.apparmor to /etc/apparmor.d/opt.clamfox.clamav_host
#     2. Run: apparmor_parser -r /etc/apparmor.d/opt.clamfox.clamav_host
#     3. Remove this removal block.
# ─────────────────────────────────────────────────────────────────────────────
echo "🛡️  Clearing legacy Mandatory Access Control (MAC) policies..."
APPARMOR_PROFILE="/etc/apparmor.d/opt.clamfox.clamav_engine.py"
if [ -f "$APPARMOR_PROFILE" ]; then
    echo "🗑️  Removing legacy AppArmor profile..."
    rm -f "$APPARMOR_PROFILE"
    if command -v apparmor_parser &> /dev/null; then
        # Use -R to remove it from the kernel
        apparmor_parser -R "$APPARMOR_PROFILE" 2>/dev/null || true
    fi
fi
echo "✅ Native protection active (MAC bypassed for stability)."

# 10. Final Summary
echo "=================================================="
echo "✅ ClamFox Host installed in /opt/clamfox"
echo "✅ Registered for all Firefox variants (Deb, Snap, Flatpak)"
echo "✅ Extension sideloaded (Removable by user)"
echo "✅ Privacy Shield & Anti-Tamper Ready"
echo "--------------------------------------------------"
echo "🚀 IMPORTANT: Restart Firefox to activate the persistent shield."
echo "🚀 Performance Tip:"
echo "   sudo systemctl enable --now clamav-daemon"
echo "=================================================="
