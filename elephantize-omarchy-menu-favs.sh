#!/bin/bash
################################################################################
# Omarchy Desktop Files Installer
# Creates .desktop files for common Omarchy menu functions
# Makes them accessible through the app launcher (Super + Space)
#
# Usage: ./elephantize-omarchy-menu-favs.sh [item1 item2 ...]
# Available items: audio bluetooth install-package install-aur wifi suspend lock config
# If no items specified, all items are installed by default.
################################################################################

# Default list of items to install (override by passing items as arguments)
DEFAULT_ITEMS=(audio bluetooth install-package install-aur wifi suspend lock config)

# All known/valid item identifiers
KNOWN_ITEMS=(audio bluetooth install-package install-aur wifi suspend lock config)

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║          OMARCHY DESKTOP FILES INSTALLER                      ║
║          Making Omarchy menu functions accessible             ║
║          through the app launcher (Super + Space)             ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Determine which items to install
if [ $# -gt 0 ]; then
    ITEMS=("$@")
else
    ITEMS=("${DEFAULT_ITEMS[@]}")
fi

# Validate all items against the known list
INVALID_ITEMS=()
VALID_ITEMS=()
for item in "${ITEMS[@]}"; do
    found=false
    for known in "${KNOWN_ITEMS[@]}"; do
        if [ "$item" = "$known" ]; then
            found=true
            break
        fi
    done
    if $found; then
        VALID_ITEMS+=("$item")
    else
        INVALID_ITEMS+=("$item")
    fi
done

if [ ${#INVALID_ITEMS[@]} -gt 0 ]; then
    echo -e "${RED}Error: Unknown item(s):${NC}"
    for item in "${INVALID_ITEMS[@]}"; do
        echo -e "   ${RED}•${NC} $item"
    done
    echo -e "\n${BLUE}Valid items:${NC} ${KNOWN_ITEMS[*]}"
    exit 1
fi

if [ ${#VALID_ITEMS[@]} -eq 0 ]; then
    echo -e "${RED}Error: No items to install.${NC}"
    exit 1
fi

# Validate that corresponding system menu entries can be created
# (check that required commands/tools are available)
MISSING_DEPS=()
for item in "${VALID_ITEMS[@]}"; do
    case "$item" in
        audio)           command -v wiremix &>/dev/null || MISSING_DEPS+=("wiremix (for audio)") ;;
        bluetooth)       command -v bluetui &>/dev/null || MISSING_DEPS+=("bluetui (for bluetooth)") ;;
        install-package) command -v fzf &>/dev/null    || MISSING_DEPS+=("fzf (for install-package)") ;;
        install-aur)     command -v yay &>/dev/null    || MISSING_DEPS+=("yay (for install-aur)") ;;
        wifi)            command -v impala &>/dev/null  || MISSING_DEPS+=("impala (for wifi)") ;;
        suspend)         command -v systemctl &>/dev/null || MISSING_DEPS+=("systemctl (for suspend)") ;;
        lock)            command -v hyprlock &>/dev/null || MISSING_DEPS+=("hyprlock (for lock)") ;;
        config)          command -v fzf &>/dev/null    || MISSING_DEPS+=("fzf (for config)") ;;
    esac
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Warning: The following dependencies are missing:${NC}"
    for dep in "${MISSING_DEPS[@]}"; do
        echo -e "   ${YELLOW}•${NC} $dep"
    done
    echo ""
fi

# Show what will be installed and get confirmation
APPS_DIR="$HOME/.local/share/applications"

echo -e "${BLUE}The following desktop entries will be created in:${NC} $APPS_DIR\n"
for item in "${VALID_ITEMS[@]}"; do
    label=""
    case "$item" in
        audio)           label="Omarchy Audio (wiremix)" ;;
        bluetooth)       label="Omarchy Bluetooth (BlueTUI)" ;;
        install-package) label="Install Package (fzf)" ;;
        install-aur)     label="Install AUR Package (fzf)" ;;
        wifi)            label="Omarchy WiFi (Impala)" ;;
        suspend)         label="Suspend System" ;;
        lock)            label="Lock Screen (hyprlock)" ;;
        config)          label="Omarchy Config (config selector)" ;;
    esac
    existing=""
    if [ -f "$APPS_DIR/omarchy-${item}.desktop" ]; then
        existing=" ${YELLOW}(overwrite)${NC}"
    fi
    echo -e "   ${BLUE}•${NC} ${label}${existing}"
done

echo ""
read -p "Proceed with installation? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Installation cancelled.${NC}"
    exit 1
fi
echo ""

# Create the applications directory if it doesn't exist
mkdir -p "$APPS_DIR"

################################################################################
# Desktop file creation functions
################################################################################

install_audio() {
    cat > "$APPS_DIR/omarchy-audio.desktop" << 'EOF'
[Desktop Entry]
Name=Omarchy Audio
Comment=Configure audio settings with wiremix
Exec=sh -c 'alacritty -e bash -c "wiremix; exec bash"'
Icon=audio-card
Terminal=false
Type=Application
Categories=Settings;Audio;Omarchy;
Keywords=audio;sound;volume;mixer;pulseaudio;pipewire;wiremix;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Omarchy Audio (using wiremix)"
}

install_bluetooth() {
    cat > "$APPS_DIR/omarchy-bluetooth.desktop" << 'EOF'
[Desktop Entry]
Name=Omarchy Bluetooth
Comment=Manage Bluetooth connections with BlueTUI
Exec=sh -c 'alacritty -e bash -c "bluetui; exec bash"'
Icon=bluetooth
Terminal=false
Type=Application
Categories=Settings;Network;Omarchy;
Keywords=bluetooth;wireless;devices;pairing;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Omarchy Bluetooth"
}

install_install-package() {
    cat > "$APPS_DIR/omarchy-install-package.desktop" << 'EOF'
[Desktop Entry]
Name=Install Package
Comment=Install packages from Arch repositories (interactive)
Exec=sh -c 'alacritty -e bash -c "pacman -Slq | fzf --preview '\''pacman -Si {}'\'' --preview-window=right:60%:wrap --prompt='\''Install Package > '\'' --header='\''Select package(s) to install (TAB to multi-select, ENTER to install)'\'' -m | xargs -ro sudo pacman -S; echo; echo '\''Press Enter to close...'\''; read"'
Icon=system-software-install
Terminal=false
Type=Application
Categories=System;PackageManager;Omarchy;
Keywords=install;package;pacman;software;arch;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Install Package (using fzf)"
}

install_install-aur() {
    cat > "$APPS_DIR/omarchy-install-aur.desktop" << 'EOF'
[Desktop Entry]
Name=Install AUR Package
Comment=Install packages from Arch User Repository (interactive)
Exec=sh -c 'alacritty -e bash -c "yay -Slq | fzf --preview '\''yay -Si {}'\'' --preview-window=right:60%:wrap --prompt='\''Install AUR Package > '\'' --header='\''Select package(s) to install (TAB to multi-select, ENTER to install)'\'' -m | xargs -ro yay -S; echo; echo '\''Press Enter to close...'\''; read"'
Icon=system-software-install
Terminal=false
Type=Application
Categories=System;PackageManager;Omarchy;
Keywords=install;aur;package;yay;software;arch;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Install AUR Package (using fzf)"
}

install_wifi() {
    cat > "$APPS_DIR/omarchy-wifi.desktop" << 'EOF'
[Desktop Entry]
Name=Omarchy WiFi
Comment=Manage WiFi connections with Impala
Exec=sh -c 'alacritty -e bash -c "impala; exec bash"'
Icon=network-wireless
Terminal=false
Type=Application
Categories=Settings;Network;Omarchy;
Keywords=wifi;wireless;network;connection;impala;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Omarchy WiFi"
}

install_suspend() {
    cat > "$APPS_DIR/omarchy-suspend.desktop" << 'EOF'
[Desktop Entry]
Name=Suspend System
Comment=Suspend the system to sleep mode
Exec=systemctl suspend
Icon=system-suspend
Terminal=false
Type=Application
Categories=System;Omarchy;
Keywords=suspend;sleep;hibernate;power;
StartupNotify=false
EOF
    echo -e "${GREEN}✓${NC} Suspend System"
}

install_lock() {
    cat > "$APPS_DIR/omarchy-lock.desktop" << 'EOF'
[Desktop Entry]
Name=Lock Screen
Comment=Lock the screen with hyprlock
Exec=hyprlock
Icon=system-lock-screen
Terminal=false
Type=Application
Categories=System;Omarchy;
Keywords=lock;screen;security;hyprlock;
StartupNotify=false
EOF
    echo -e "${GREEN}✓${NC} Lock Screen"
}

install_config() {
    cat > "$APPS_DIR/omarchy-config.desktop" << 'EOF'
[Desktop Entry]
Name=Omarchy Config
Comment=Open Omarchy configuration menu (Setup > Configs)
Exec=sh -c 'alacritty -e bash -c "echo '\''Select config to edit:'\''; echo; configs=(hyprland waybar mako btop ghostty alacritty kitty neovim walker); selected=$(printf '\''%s\\n'\'' \"${configs[@]}\" | fzf --prompt='\''Config > '\'' --header='\''Choose a configuration file to edit'\''); if [ -n \"$selected\" ]; then case $selected in hyprland) nvim ~/.config/hypr/hyprland.conf ;; waybar) nvim ~/.config/waybar/config ;; mako) nvim ~/.config/mako/config ;; btop) nvim ~/.config/btop/btop.conf ;; ghostty) nvim ~/.config/ghostty/config ;; alacritty) nvim ~/.config/alacritty/alacritty.toml ;; kitty) nvim ~/.config/kitty/kitty.conf ;; neovim) nvim ~/.config/nvim/init.lua ;; walker) nvim ~/.config/walker/config.toml ;; esac; fi; exec bash"'
Icon=preferences-system
Terminal=false
Type=Application
Categories=Settings;System;Omarchy;
Keywords=config;configuration;settings;hyprland;setup;edit;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Omarchy Config"
}

################################################################################
# Install selected items
################################################################################

echo -e "${BLUE}Installing desktop files...${NC}\n"

for item in "${VALID_ITEMS[@]}"; do
    "install_${item}"
done

################################################################################
# POST-INSTALLATION
################################################################################

# Make them executable
chmod +x "$APPS_DIR"/omarchy-*.desktop

# Update desktop database
echo ""
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$APPS_DIR"
    echo -e "${GREEN}✓${NC} Desktop database updated"
else
    echo -e "${YELLOW}⚠${NC} update-desktop-database not found. You may need to log out and back in."
fi

# Restart elephant if it's running (to pick up new applications)
if pgrep -x "elephant" > /dev/null; then
    echo -e "\n${BLUE}Restarting Elephant service...${NC}"
    pkill elephant
    sleep 1
    elephant &> /dev/null &
    disown
    echo -e "${GREEN}✓${NC} Elephant restarted"
fi

# Final summary
echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║               Installation Complete!                      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo -e "\nInstalled items are now available in your app launcher (${BLUE}Super + Space${NC})."

echo -e "\n${YELLOW}Tips:${NC}"
echo -e "  • If they don't show up immediately, run: ${BLUE}omarchy-restart-walker${NC}"
echo -e "  • Desktop files are located in: ${BLUE}$APPS_DIR${NC}"

echo -e "\n${YELLOW}To re-run and update:${NC}"
echo -e "  Just run this script again - it will ask before overwriting"

echo -e "\n${YELLOW}To uninstall:${NC}"
echo -e "  rm $APPS_DIR/omarchy-*.desktop"
echo -e "  update-desktop-database $APPS_DIR"
echo -e "  omarchy-restart-walker"
