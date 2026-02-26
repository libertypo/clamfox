#!/bin/bash
# Wrapper to run the native host from within Flatpak Firefox
/usr/bin/flatpak-spawn --host /usr/bin/python3 /home/ovidio/firefox_clamav/host/clamav_engine.py "$@"
