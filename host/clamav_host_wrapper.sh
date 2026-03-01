#!/bin/bash
# Wrapper to run the native host from within Flatpak Firefox
# Note: flatpak-spawn --host is used to breakout of the sandbox
/usr/bin/flatpak-spawn --host /usr/bin/python3 /opt/clamfox/clamav_host.py "$@"
