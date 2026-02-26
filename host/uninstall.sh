#!/bin/bash

# ClamFox Uninstaller
# Reverts system hardening and removes the host.

set -e

INSTALL_DIR="/opt/clamfox"
HOST_NAME="clamav_host"
MANIFEST_FILE="${HOST_NAME}.json"
GLOBAL_MANIFEST_DIR="/usr/lib/mozilla/native-messaging-hosts"
POLICY_FILE="/etc/firefox/policies/policies.json"

# 1. Ensure Root Privileges
if [[ $EUID -ne 0 ]]; then
   echo "🛡️  ClamFox Uninstaller requires root privileges."
   exec sudo "$0" "$@"
fi

echo "=================================================="
echo "      CLAMFOX: Reverting & Uninstalling           "
echo "=================================================="

# 2. Remove Global Native Messaging Host
echo "📋 Removing Native Messaging Host registration..."
rm -f "$GLOBAL_MANIFEST_DIR/$MANIFEST_FILE"

# 3. Remove Snap/Flatpak Bridges
ACTUAL_USER=${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}
USER_HOME=$(eval echo "~$ACTUAL_USER")

# Snap Firefox
SNAP_DIR="$USER_HOME/snap/firefox/common/.mozilla/native-messaging-hosts"
if [ -f "$SNAP_DIR/$MANIFEST_FILE" ]; then
    echo "🌐 Cleaning up Snap Firefox bridge..."
    rm -f "$SNAP_DIR/$MANIFEST_FILE"
fi

# Flatpak Firefox
FLATPAK_DIR="$USER_HOME/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts"
if [ -f "$FLATPAK_DIR/$MANIFEST_FILE" ]; then
    echo "🌐 Cleaning up Flatpak Firefox bridge..."
    rm -f "$FLATPAK_DIR/$MANIFEST_FILE"
fi

# 4. Remove Enterprise Policy
if [ -f "$POLICY_FILE" ]; then
    echo "📋 Removing Enterprise Policy..."
    # If the policy file only contains ClamFox, we remove the whole file.
    # Otherwise, we use python to surgically remove only our extension entry.
    if grep -q "clamfox@ovidio.me" "$POLICY_FILE"; then
        python3 -c "
import json, os
policy_path = '$POLICY_FILE'
try:
    with open(policy_path, 'r') as f:
        data = json.load(f)
    if 'policies' in data and 'ExtensionSettings' in data['policies']:
        if 'clamfox@ovidio.me' in data['policies']['ExtensionSettings']:
            del data['policies']['ExtensionSettings']['clamfox@ovidio.me']
            # If ExtensionSettings is now empty, remove it
            if not data['policies']['ExtensionSettings']:
                del data['policies']['ExtensionSettings']
            # If policies is now empty, we can remove the file
            if not data['policies']:
                os.remove(policy_path)
            else:
                with open(policy_path, 'w') as f:
                    json.dump(data, f, indent=4)
except Exception:
    pass
"
    fi
fi

# 5. Remove Application Files
echo "🏗️  Removing $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"

# 6. Revert MAC Policies (AppArmor/SELinux)
echo "🛡️  Reverting Mandatory Access Control policies..."
APPARMOR_PROFILE="/etc/apparmor.d/opt.clamfox.clamav_engine.py"
if [ -f "$APPARMOR_PROFILE" ]; then
    echo "🛡️  Removing AppArmor profile..."
    rm -f "$APPARMOR_PROFILE"
    if command -v apparmor_parser &> /dev/null; then
        # Use --remove to unload from kernel
        apparmor_parser --remove "$APPARMOR_PROFILE" 2>/dev/null || true
    fi
fi

if command -v semanage &> /dev/null; then
    echo "🛡️  Cleaning up SELinux contexts..."
    semanage fcontext -d "$INSTALL_DIR(/.*)?" 2>/dev/null || true
fi

# 7. Cleanup Logs
LOG_FILE="$USER_HOME/.clamfox_host.log"
if [ -f "$LOG_FILE" ]; then
    echo "📝 Cleaning up host logs..."
    rm -f "$LOG_FILE"
fi

echo "=================================================="
echo "✅ ClamFox Host has been uninstalled."
echo "🚀 Restart Firefox to complete the cleanup."
echo "=================================================="
