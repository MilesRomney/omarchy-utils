#!/bin/bash
################################################################################
# Omarchy Desktop Files Installer
# Creates .desktop files for common Omarchy menu functions
# Makes them accessible through the app launcher (Super + Space)
#
# Pre-Quattro only (Walker/Elephant). Omarchy 4+ has a built-in Omarchy menu;
# this installer exits instead of creating duplicate .desktop stubs.
#
# Usage: ./elephantize-omarchy-menu-favs.sh [item1 item2 ...]
# Available items: audio bluetooth install-package install-aur wifi suspend lock config
# If no items specified, all items are installed by default.
################################################################################

# Elephant/Walker is not part of Omarchy 4+ (Quattro). The built-in Omarchy
# menu already covers these items; installing the old .desktop stubs creates
# duplicate and outdated entries.
omarchy_major_version() {
    local v
    v=$(grep -E '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    if [[ -z "$v" ]] && command -v omarchy >/dev/null 2>&1; then
        v=$(omarchy version 2>/dev/null | head -n1)
    fi
    v=${v%%-*}
    echo "${v%%.*}"
}

OMARCHY_MAJOR=$(omarchy_major_version)
if [[ "$OMARCHY_MAJOR" =~ ^[0-9]+$ ]] && (( OMARCHY_MAJOR >= 4 )); then
    echo "elephantize-omarchy-menu-favs is not needed on Omarchy ${OMARCHY_MAJOR}+ (Quattro)."
    echo "The Elephant/Walker launcher is no longer part of the Omarchy package;"
    echo "these actions live in the built-in Omarchy menu. Installing these"
    echo ".desktop files would create duplicate/outdated menu entries."
    echo "Nothing was changed."
    exit 1
fi

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

launch_terminal() {
    # Quote a command so a .desktop Exec= line can run it in the user's terminal.
    local cmd="$1"
    if command -v omarchy-launch-tui >/dev/null 2>&1; then
        printf 'omarchy-launch-tui %s' "$cmd"
    elif command -v xdg-terminal-exec >/dev/null 2>&1; then
        printf "xdg-terminal-exec --app-id=org.omarchy.terminal -e %s" "$cmd"
    else
        printf "alacritty -e bash -c %s" "'$cmd; exec bash'"
    fi
}

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
        audio)
            command -v omarchy-shell &>/dev/null \
                || command -v wiremix &>/dev/null \
                || MISSING_DEPS+=("omarchy-shell or wiremix (for audio)")
            ;;
        bluetooth)
            command -v omarchy-shell &>/dev/null \
                || command -v bluetui &>/dev/null \
                || MISSING_DEPS+=("omarchy-shell or bluetui (for bluetooth)")
            ;;
        install-package)
            command -v omarchy-pkg-install &>/dev/null \
                || command -v fzf &>/dev/null \
                || MISSING_DEPS+=("omarchy-pkg-install or fzf (for install-package)")
            ;;
        install-aur)
            command -v omarchy-pkg-aur-install &>/dev/null \
                || command -v yay &>/dev/null \
                || MISSING_DEPS+=("omarchy-pkg-aur-install or yay (for install-aur)")
            ;;
        wifi)
            command -v omarchy-shell &>/dev/null \
                || command -v impala &>/dev/null \
                || command -v nmtui &>/dev/null \
                || MISSING_DEPS+=("omarchy-shell, impala, or nmtui (for wifi)")
            ;;
        suspend)
            command -v systemctl &>/dev/null || MISSING_DEPS+=("systemctl (for suspend)")
            ;;
        lock)
            command -v omarchy-system-lock &>/dev/null \
                || command -v hyprlock &>/dev/null \
                || MISSING_DEPS+=("omarchy-system-lock or hyprlock (for lock)")
            ;;
        config)
            command -v omarchy-menu &>/dev/null \
                || command -v fzf &>/dev/null \
                || MISSING_DEPS+=("omarchy-menu or fzf (for config)")
            ;;
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
        audio)
            if command -v omarchy-shell &>/dev/null; then
                label="Omarchy Audio (shell panel)"
            else
                label="Omarchy Audio (wiremix)"
            fi
            ;;
        bluetooth)
            if command -v omarchy-shell &>/dev/null; then
                label="Omarchy Bluetooth (shell panel)"
            else
                label="Omarchy Bluetooth (BlueTUI)"
            fi
            ;;
        install-package)
            if command -v omarchy-pkg-install &>/dev/null; then
                label="Install Package (omarchy pkg install)"
            else
                label="Install Package (fzf)"
            fi
            ;;
        install-aur)
            if command -v omarchy-pkg-aur-install &>/dev/null; then
                label="Install AUR Package (omarchy pkg aur install)"
            else
                label="Install AUR Package (fzf)"
            fi
            ;;
        wifi)
            if command -v omarchy-shell &>/dev/null; then
                label="Omarchy WiFi (shell panel)"
            elif command -v impala &>/dev/null; then
                label="Omarchy WiFi (Impala)"
            else
                label="Omarchy WiFi (nmtui)"
            fi
            ;;
        suspend)         label="Suspend System" ;;
        lock)
            if command -v omarchy-system-lock &>/dev/null; then
                label="Lock Screen (omarchy-system-lock)"
            else
                label="Lock Screen (hyprlock)"
            fi
            ;;
        config)
            if command -v omarchy-menu &>/dev/null; then
                label="Omarchy Config (Setup > Config)"
            else
                label="Omarchy Config (config selector)"
            fi
            ;;
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
    local exec_line
    if command -v omarchy-shell &>/dev/null; then
        exec_line="omarchy-shell shell summon omarchy.audio"
    else
        exec_line="sh -c '$(launch_terminal wiremix)'"
    fi
    cat > "$APPS_DIR/omarchy-audio.desktop" << EOF
[Desktop Entry]
Name=Omarchy Audio
Comment=Configure audio settings
Exec=$exec_line
Icon=audio-card
Terminal=false
Type=Application
Categories=Settings;Audio;Omarchy;
Keywords=audio;sound;volume;mixer;pulseaudio;pipewire;wiremix;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Omarchy Audio"
}

install_bluetooth() {
    local exec_line
    if command -v omarchy-shell &>/dev/null; then
        exec_line="omarchy-shell shell summon omarchy.bluetooth"
    else
        exec_line="sh -c '$(launch_terminal bluetui)'"
    fi
    cat > "$APPS_DIR/omarchy-bluetooth.desktop" << EOF
[Desktop Entry]
Name=Omarchy Bluetooth
Comment=Manage Bluetooth connections
Exec=$exec_line
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
    local exec_line
    if command -v omarchy-pkg-install &>/dev/null; then
        if command -v xdg-terminal-exec &>/dev/null; then
            exec_line="xdg-terminal-exec --app-id=org.omarchy.terminal omarchy-pkg-install"
        else
            exec_line="sh -c '$(launch_terminal omarchy-pkg-install)'"
        fi
    else
        exec_line="sh -c 'alacritty -e bash -c \"pacman -Slq | fzf --preview '\\''pacman -Si {}'\\'' --preview-window=right:60%:wrap --prompt='\\''Install Package > '\\'' --header='\\''Select package(s) to install (TAB to multi-select, ENTER to install)'\\'' -m | xargs -ro sudo pacman -S; echo; echo '\\''Press Enter to close...'\\''; read\"'"
    fi
    cat > "$APPS_DIR/omarchy-install-package.desktop" << EOF
[Desktop Entry]
Name=Install Package
Comment=Install packages from Arch repositories (interactive)
Exec=$exec_line
Icon=system-software-install
Terminal=false
Type=Application
Categories=System;PackageManager;Omarchy;
Keywords=install;package;pacman;software;arch;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Install Package"
}

install_install-aur() {
    local exec_line
    if command -v omarchy-pkg-aur-install &>/dev/null; then
        if command -v xdg-terminal-exec &>/dev/null; then
            exec_line="xdg-terminal-exec --app-id=org.omarchy.terminal omarchy-pkg-aur-install"
        else
            exec_line="sh -c '$(launch_terminal omarchy-pkg-aur-install)'"
        fi
    else
        exec_line="sh -c 'alacritty -e bash -c \"yay -Slq | fzf --preview '\\''yay -Si {}'\\'' --preview-window=right:60%:wrap --prompt='\\''Install AUR Package > '\\'' --header='\\''Select package(s) to install (TAB to multi-select, ENTER to install)'\\'' -m | xargs -ro yay -S; echo; echo '\\''Press Enter to close...'\\''; read\"'"
    fi
    cat > "$APPS_DIR/omarchy-install-aur.desktop" << EOF
[Desktop Entry]
Name=Install AUR Package
Comment=Install packages from Arch User Repository (interactive)
Exec=$exec_line
Icon=system-software-install
Terminal=false
Type=Application
Categories=System;PackageManager;Omarchy;
Keywords=install;aur;package;yay;software;arch;
StartupNotify=true
EOF
    echo -e "${GREEN}✓${NC} Install AUR Package"
}

install_wifi() {
    local exec_line
    if command -v omarchy-shell &>/dev/null; then
        exec_line="omarchy-shell shell summon omarchy.network"
    elif command -v impala &>/dev/null; then
        exec_line="sh -c '$(launch_terminal impala)'"
    else
        exec_line="sh -c '$(launch_terminal nmtui)'"
    fi
    cat > "$APPS_DIR/omarchy-wifi.desktop" << EOF
[Desktop Entry]
Name=Omarchy WiFi
Comment=Manage WiFi connections
Exec=$exec_line
Icon=network-wireless
Terminal=false
Type=Application
Categories=Settings;Network;Omarchy;
Keywords=wifi;wireless;network;connection;impala;nmtui;
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
    local exec_line comment keywords
    if command -v omarchy-system-lock &>/dev/null; then
        exec_line="omarchy-system-lock"
        comment="Lock the screen with Omarchy"
        keywords="lock;screen;security;omarchy;"
    else
        exec_line="hyprlock"
        comment="Lock the screen with hyprlock"
        keywords="lock;screen;security;hyprlock;"
    fi
    cat > "$APPS_DIR/omarchy-lock.desktop" << EOF
[Desktop Entry]
Name=Lock Screen
Comment=$comment
Exec=$exec_line
Icon=system-lock-screen
Terminal=false
Type=Application
Categories=System;Omarchy;
Keywords=$keywords
StartupNotify=false
EOF
    echo -e "${GREEN}✓${NC} Lock Screen"
}

install_config() {
    local exec_line
    if command -v omarchy-menu &>/dev/null; then
        exec_line="omarchy menu summon setup.config"
    else
        exec_line="sh -c 'alacritty -e bash -c \"echo '\\''Select config to edit:'\\''; echo; configs=(hyprland waybar mako btop ghostty alacritty kitty neovim walker); selected=\$(printf '\\''%s\\\\n'\\'' \\\"\${configs[@]}\\\" | fzf --prompt='\\''Config > '\\'' --header='\\''Choose a configuration file to edit'\\''); if [ -n \\\"\$selected\\\" ]; then case \$selected in hyprland) nvim ~/.config/hypr/hyprland.conf ;; waybar) nvim ~/.config/waybar/config ;; mako) nvim ~/.config/mako/config ;; btop) nvim ~/.config/btop/btop.conf ;; ghostty) nvim ~/.config/ghostty/config ;; alacritty) nvim ~/.config/alacritty/alacritty.toml ;; kitty) nvim ~/.config/kitty/kitty.conf ;; neovim) nvim ~/.config/nvim/init.lua ;; walker) nvim ~/.config/walker/config.toml ;; esac; fi; exec bash\"'"
    fi
    cat > "$APPS_DIR/omarchy-config.desktop" << EOF
[Desktop Entry]
Name=Omarchy Config
Comment=Open Omarchy configuration menu (Setup > Configs)
Exec=$exec_line
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

# Refresh the launcher so new .desktop files appear without a session restart.
if command -v omarchy-menu >/dev/null 2>&1; then
    echo -e "\n${BLUE}Refreshing Omarchy menu...${NC}"
    omarchy menu refresh >/dev/null 2>&1 || true
    echo -e "${GREEN}✓${NC} Omarchy menu refreshed"
elif pgrep -x "elephant" > /dev/null; then
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
if command -v omarchy-restart-shell >/dev/null 2>&1; then
    echo -e "  • If they don't show up immediately, run: ${BLUE}omarchy restart shell${NC}"
    echo -e "    or ${BLUE}omarchy menu refresh${NC}"
elif command -v omarchy-restart-walker >/dev/null 2>&1; then
    echo -e "  • If they don't show up immediately, run: ${BLUE}omarchy-restart-walker${NC}"
else
    echo -e "  • If they don't show up immediately, log out and back in"
fi
echo -e "  • Desktop files are located in: ${BLUE}$APPS_DIR${NC}"

echo -e "\n${YELLOW}To re-run and update:${NC}"
echo -e "  Just run this script again - it will ask before overwriting"

echo -e "\n${YELLOW}To uninstall:${NC}"
echo -e "  rm $APPS_DIR/omarchy-*.desktop"
echo -e "  update-desktop-database $APPS_DIR"
if command -v omarchy-restart-shell >/dev/null 2>&1; then
    echo -e "  omarchy restart shell"
elif command -v omarchy-restart-walker >/dev/null 2>&1; then
    echo -e "  omarchy-restart-walker"
fi
