#!/bin/bash
################################################################################
# Clear WirePlumber State Cache
# Removes cached WirePlumber state to fix audio/bluetooth routing issues.
# WirePlumber will regenerate its state on next login or service restart.
################################################################################

CACHE_DIR="$HOME/.local/state/wireplumber"

if [ ! -d "$CACHE_DIR" ]; then
    echo "Nothing to clear: $CACHE_DIR does not exist."
    exit 0
fi

echo "This will remove the WirePlumber state cache at:"
echo "  $CACHE_DIR"
echo ""
echo "This fixes common audio/bluetooth device routing issues."
echo "WirePlumber will regenerate its state on next restart."
echo ""
read -p "Proceed? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 1
fi

rm -rf "$CACHE_DIR"
echo "Cache cleared."

if systemctl --user is-active wireplumber &>/dev/null; then
    read -p "WirePlumber is running. Restart it now? (y/N): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl --user restart wireplumber
        echo "WirePlumber restarted."
    else
        echo "Remember to restart WirePlumber or log out/in for changes to take effect."
    fi
fi
