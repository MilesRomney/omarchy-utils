#!/bin/bash

# Omarchy Unified Setup Script
# Comprehensive configuration for Omarchy Linux servers and remote access

set -e  # Exit on error

# Reattach stdin to terminal if piped
if [ ! -t 0 ]; then
    exec < /dev/tty
fi

echo "================================================="
echo "  Omarchy Unattended Access Configuration Helper"
echo "================================================="
echo ""
echo "This configuration helper will assist you in configuring your Omarchy instance for"
echo "unattended remote access (or as a server). You will have these options:"
echo ""
echo "  1. Configure networking for a static IP, and set up SSH access"
echo "  2. Install additional packages through the pacman package manager"
echo "  3. Manage keybindings"
echo "  4. Configure Neovim arrow-key line wrapping"
echo "  5. Configure disk auto-decryption on boot (with options for mitigating security risk)"
echo "  6. Configure headless boot (boot to text console; GUI launches on demand)"
echo "  7. Disable system suspend/hibernate (recommended for unattended servers)"
echo "  8. Enable persistent system journal logging"
echo "  9. Install common AI workstation packages (Python, Docker, monitoring tools)"
echo ""
echo "Brought to you by Miles David Romney at V42 and The Chief Innovator:"
echo "https://www.linkedin.com/in/miles-david-romney-8b11a4/"
echo ""
echo "Press Enter to continue..."
read

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Check if running on Omarchy Linux
if [[ ! -f /etc/os-release ]] || ! grep -qi "ID=arch" /etc/os-release; then
   echo "ERROR: This script is designed for Omarchy Linux only."
   echo "It appears you are not running Omarchy Linux."
   echo ""
   if [[ -f /etc/os-release ]]; then
       echo "Detected OS:"
       grep "^PRETTY_NAME=" /etc/os-release | cut -d= -f2 | tr -d '"'
   fi
   echo ""
   echo "Please run this script on an Omarchy Linux system."
   exit 1
fi

# Detect or ask for the primary user
echo "Detecting primary user..."
# Try to detect non-root user with UID >= 1000
PRIMARY_USER=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}' /etc/passwd)

if [[ -z "$PRIMARY_USER" ]]; then
    echo "⚠ Could not automatically detect primary user"
    read -p "Enter the username for this Omarchy installation [omarchy]: " PRIMARY_USER
    PRIMARY_USER=${PRIMARY_USER:-omarchy}
else
    echo "Detected primary user: $PRIMARY_USER"
    read -p "Is this correct? [Y/n]: " CONFIRM_USER
    CONFIRM_USER=${CONFIRM_USER:-Y}
    if [[ ! "$CONFIRM_USER" =~ ^[Yy]$ ]]; then
        read -p "Enter the correct username: " PRIMARY_USER
    fi
fi

echo "Using primary user: $PRIMARY_USER"
echo ""

# ============================================
# HYPRLAND AUTO-LOCK HELPERS
# Support legacy hyprland.conf (hyprlang) and modern hyprland.lua (0.55+/0.57)
# ============================================

HYPR_AUTOLOCK_CONF_MARKER="# Auto-lock screen after autologin for security"
HYPR_AUTOLOCK_CONF_LINE="exec-once = sleep 3 && hyprlock"
HYPR_AUTOLOCK_LUA_MARKER="-- Auto-lock screen after autologin for security"
HYPR_AUTOLOCK_LUA_END_MARKER="-- End Auto-lock screen after autologin for security"
HYPR_AUTOLOCK_CMD="sleep 3 && hyprlock"
HYPR_AUTOLOCK_LUA_EXEC='hl.exec_cmd("sleep 3 && hyprlock")'

# Strip our marked auto-lock block from a hyprland.lua file (idempotent).
hypr_strip_autolock_lua() {
    local lua_config="$1"
    local tmp_file

    [[ -f "$lua_config" ]] || return 0

    tmp_file=$(mktemp)
    awk -v start="$HYPR_AUTOLOCK_LUA_MARKER" -v end="$HYPR_AUTOLOCK_LUA_END_MARKER" '
        $0 == start { in_block = 1; next }
        in_block && $0 == end { in_block = 0; next }
        in_block { next }
        { print }
    ' "$lua_config" > "$tmp_file"
    mv "$tmp_file" "$lua_config"
}

# Write/replace the marked auto-lock block in a hyprland.lua file.
hypr_write_autolock_lua() {
    local lua_config="$1"
    local tmp_file

    if [[ -f "$lua_config" ]]; then
        hypr_strip_autolock_lua "$lua_config"
        tmp_file=$(mktemp)
        cat "$lua_config" > "$tmp_file"
        if [[ -s "$tmp_file" ]]; then
            # Ensure exactly one trailing newline, then a blank separator line.
            if [[ -n "$(tail -c 1 "$tmp_file" 2>/dev/null)" ]]; then
                printf '\n' >> "$tmp_file"
            fi
            printf '\n' >> "$tmp_file"
        fi
    else
        tmp_file=$(mktemp)
        : > "$tmp_file"
    fi

    cat >> "$tmp_file" <<LUA_EOF
${HYPR_AUTOLOCK_LUA_MARKER}
hl.on("hyprland.start", function ()
  hl.exec_cmd("${HYPR_AUTOLOCK_CMD}")
end)
${HYPR_AUTOLOCK_LUA_END_MARKER}
LUA_EOF

    mv "$tmp_file" "$lua_config"
}

# Write/replace the marked auto-lock lines in a hyprland.conf file.
hypr_write_autolock_conf() {
    local conf_config="$1"

    if [[ -f "$conf_config" ]]; then
        if [[ ! -f "${conf_config}.backup" ]]; then
            cp "$conf_config" "${conf_config}.backup"
        fi
        # Remove any existing autolock entries first (idempotent).
        sed -i '\|# Auto-lock screen after autologin for security|d' "$conf_config"
        sed -i '/exec-once.*hyprlock/d' "$conf_config"
        if [[ -s "$conf_config" ]]; then
            if [[ -n "$(tail -c 1 "$conf_config" 2>/dev/null)" ]]; then
                printf '\n' >> "$conf_config"
            fi
            printf '\n' >> "$conf_config"
        fi
    fi

    {
        echo "$HYPR_AUTOLOCK_CONF_MARKER"
        echo "$HYPR_AUTOLOCK_CONF_LINE"
    } >> "$conf_config"
}

# Add auto-lock to hyprland.conf and/or hyprland.lua for the given user home.
# Dual-writes when safe so older Hyprland (conf) and 0.55+/0.57 (lua) both work.
hypr_add_autolock() {
    local user_home="$1"
    local hypr_dir="$user_home/.config/hypr"
    local conf_config="$hypr_dir/hyprland.conf"
    local lua_config="$hypr_dir/hyprland.lua"
    local conf_exists=false
    local lua_exists=false
    local touch_conf=false
    local touch_lua=false

    mkdir -p "$hypr_dir"

    [[ -f "$conf_config" ]] && conf_exists=true
    [[ -f "$lua_config" ]] && lua_exists=true

    if [[ "$conf_exists" == true && "$lua_exists" == true ]]; then
        touch_conf=true
        touch_lua=true
    elif [[ "$lua_exists" == true ]]; then
        # Lua takes precedence when present; conf would be ignored by Hyprland.
        touch_lua=true
    elif [[ "$conf_exists" == true ]]; then
        # Keep conf working on older Hyprland; also write companion lua for 0.57.
        touch_conf=true
        touch_lua=true
    else
        # Minimal create path: both formats for broad compatibility.
        touch_conf=true
        touch_lua=true
    fi

    if [[ "$touch_conf" == true ]]; then
        hypr_write_autolock_conf "$conf_config"
        echo "✓ Added hyprlock autostart to Hyprland conf ($conf_config)"
    fi

    if [[ "$touch_lua" == true ]]; then
        if [[ -f "$lua_config" && ! -f "${lua_config}.backup" ]]; then
            cp "$lua_config" "${lua_config}.backup"
        fi
        hypr_write_autolock_lua "$lua_config"
        echo "✓ Added hyprlock autostart to Hyprland lua ($lua_config)"
    fi
}

# Remove auto-lock markers from both conf and lua if present.
hypr_remove_autolock() {
    local user_home="$1"
    local hypr_dir="$user_home/.config/hypr"
    local conf_config="$hypr_dir/hyprland.conf"
    local lua_config="$hypr_dir/hyprland.lua"
    local removed=false

    if [[ -f "$conf_config" ]]; then
        if grep -qF -- "$HYPR_AUTOLOCK_CONF_MARKER" "$conf_config" || grep -q 'exec-once.*hyprlock' "$conf_config"; then
            sed -i '\|# Auto-lock screen after autologin for security|d' "$conf_config"
            sed -i '/exec-once.*hyprlock/d' "$conf_config"
            removed=true
        fi
    fi

    if [[ -f "$lua_config" ]]; then
        if grep -qF -- "$HYPR_AUTOLOCK_LUA_MARKER" "$lua_config" || grep -qF -- "$HYPR_AUTOLOCK_LUA_EXEC" "$lua_config"; then
            hypr_strip_autolock_lua "$lua_config"
            removed=true
        fi
    fi

    if [[ "$removed" == true ]]; then
        echo "✓ Removed auto-lock from Hyprland config"
    fi
}

# ============================================
# SECTION 1: NETWORK CONFIGURATION
# ============================================

read -p "Would you like to configure networking for a static IP? [Y/n]: " CONFIGURE_NETWORK
CONFIGURE_NETWORK=${CONFIGURE_NETWORK:-Y}

if [[ "$CONFIGURE_NETWORK" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== Network Configuration ==="
    echo ""

    # Discover available interfaces and current IPv4 addresses
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    mapfile -t AVAILABLE_INTERFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v '^lo$')

    if [[ ${#AVAILABLE_INTERFACES[@]} -eq 0 ]]; then
        echo "Could not detect network interfaces automatically."
        read -p "Enter network interface name (e.g., enp86s0, eth0): " INTERFACE
    else
        echo "Available network interfaces:"
        for IFACE in "${AVAILABLE_INTERFACES[@]}"; do
            CURRENT_IP=$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | paste -sd ', ' -)
            CURRENT_IP=${CURRENT_IP:-none}
            if [[ "$IFACE" == "$DEFAULT_INTERFACE" ]]; then
                echo "  - $IFACE (current IPv4: $CURRENT_IP) [default route]"
            else
                echo "  - $IFACE (current IPv4: $CURRENT_IP)"
            fi
        done
        echo ""
        read -p "Network interface to configure [${DEFAULT_INTERFACE:-${AVAILABLE_INTERFACES[0]}}]: " INTERFACE
        INTERFACE=${INTERFACE:-${DEFAULT_INTERFACE:-${AVAILABLE_INTERFACES[0]}}}

        while ! printf '%s\n' "${AVAILABLE_INTERFACES[@]}" | grep -qx "$INTERFACE"; do
            echo "Invalid interface: $INTERFACE"
            read -p "Choose one of the listed interfaces: " INTERFACE
        done
    fi
    
    read -p "SSH port [22]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}

    read -p "Network gateway [192.168.1.1]: " GATEWAY
    GATEWAY=${GATEWAY:-192.168.1.1}

    read -p "Static IP address (required): " STATIC_IP
    while [[ -z "$STATIC_IP" ]]; do
        echo "Static IP address is required!"
        read -p "Static IP address: " STATIC_IP
    done

    echo ""
    echo "Configuration Summary:"
    echo "  SSH Port: $SSH_PORT"
    echo "  Network Interface: $INTERFACE"
    echo "  Static IP: $STATIC_IP"
    echo "  Gateway: $GATEWAY"
    echo "  DNS: 8.8.8.8, 8.8.4.4"
    echo ""
    read -p "Continue with this configuration? [Y/n]: " CONFIRM
    CONFIRM=${CONFIRM:-Y}
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Network configuration skipped."
    else
        echo ""
        echo "[Network 1/6] Installing essential packages..."
        pacman -S --needed --noconfirm openssh

        echo "[Network 2/6] Configuring static IP address..."
        mkdir -p /etc/systemd/network
        cat > /etc/systemd/network/10-static.network <<EOF
[Match]
Name=$INTERFACE

[Network]
Address=$STATIC_IP/24
Gateway=$GATEWAY
DNS=8.8.8.8
DNS=8.8.4.4
EOF

        systemctl enable systemd-networkd
        systemctl restart systemd-networkd

        echo "[Network 3/6] Configuring SSH to use port $SSH_PORT..."
        if grep -q "^Port " /etc/ssh/sshd_config; then
            sed -i "s/^Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
        elif grep -q "^#Port " /etc/ssh/sshd_config; then
            sed -i "s/^#Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
        else
            echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
        fi
        if command -v ufw >/dev/null 2>&1; then
            ufw allow "$SSH_PORT"/tcp
        fi

        echo "[Network 4/6] Enabling and starting SSH service..."
        systemctl enable sshd
        systemctl restart sshd

        echo "[Network 5/6] Configuring passwordless sudo for user '$PRIMARY_USER'..."
        if [ ! -d /etc/sudoers.d ]; then
            mkdir -p /etc/sudoers.d
        fi
        echo "$PRIMARY_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$PRIMARY_USER
        chmod 440 /etc/sudoers.d/$PRIMARY_USER

        echo "[Network 6/6] Configuring SSH public key for $PRIMARY_USER user..."
        OMARCHY_HOME=$(eval echo ~$PRIMARY_USER)
        mkdir -p "$OMARCHY_HOME/.ssh"
        
        echo ""
        echo "Would you like to add a public key to your SSH authorized_keys?"
        echo "If so, paste it here. (default: none)"
        read -p "SSH public key: " SSH_PUBLIC_KEY
        
        if [[ -n "$SSH_PUBLIC_KEY" ]]; then
            read -p "Comment it with a name or label? (default: none): " SSH_KEY_COMMENT
            
            # Create or append to authorized_keys
            if [[ -n "$SSH_KEY_COMMENT" ]]; then
                echo "# $SSH_KEY_COMMENT" >> "$OMARCHY_HOME/.ssh/authorized_keys"
            fi
            echo "$SSH_PUBLIC_KEY" >> "$OMARCHY_HOME/.ssh/authorized_keys"
            
            chmod 600 "$OMARCHY_HOME/.ssh/authorized_keys"
            chown -R $PRIMARY_USER:$PRIMARY_USER "$OMARCHY_HOME/.ssh"
            echo "✓ SSH public key added"
        else
            echo "No SSH public key added"
        fi

        sleep 2
        if ss -tlnp | grep -q ":$SSH_PORT"; then
            echo "✓ SSH is running on port $SSH_PORT"
        else
            echo "⚠ Warning: SSH may not be listening on port $SSH_PORT"
        fi

        echo ""
        echo "=== Network Configuration Complete ==="
        echo "✓ Static IP configured: $STATIC_IP on $INTERFACE"
        echo "✓ SSH configured on port $SSH_PORT"
        if [[ -n "$SSH_PUBLIC_KEY" ]]; then
            echo "✓ SSH public key added for $PRIMARY_USER user"
        fi
        echo "✓ Passwordless sudo configured"
        echo ""
        echo "You can now SSH in with:"
        echo "  ssh -p $SSH_PORT $PRIMARY_USER@$STATIC_IP"
        echo ""
    fi
else
    echo "Network configuration skipped."
fi

# ============================================
# SECTION 2: PACKAGE INSTALLATION
# ============================================

echo ""
read -p "List any packages you would like to install, comma separated [none]: " PACKAGES
PACKAGES=${PACKAGES:-none}

if [[ "$PACKAGES" != "none" && -n "$PACKAGES" ]]; then
    echo ""
    echo "=== Package Installation ==="
    echo ""
    
    # Convert comma-separated list to space-separated
    PACKAGE_LIST=$(echo "$PACKAGES" | tr ',' ' ')
    
    echo "Installing packages: $PACKAGE_LIST"
    if pacman -S --needed --noconfirm $PACKAGE_LIST; then
        echo "✓ Packages installed successfully"
    else
        echo "⚠ Some packages failed to install"
    fi
else
    echo "Package installation skipped."
fi

# ============================================
# SECTION 3: KEYBINDING CONFIGURATION
# ============================================

echo ""
read -p "Would you like to swap the SPECIAL and ALT keybindings? If you're a Mac user, you may find this helpful. If you're a Windows user, you will not. [y/N]: " SWAP_KEYS
SWAP_KEYS=${SWAP_KEYS:-N}

if [[ "$SWAP_KEYS" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== Keybinding Configuration ==="
    echo ""
    
    # Install keyd
    echo "Installing keyd..."
    if ! command -v keyd &> /dev/null; then
        pacman -S --needed --noconfirm keyd
        echo "✓ keyd installed"
    else
        echo "✓ keyd already installed"
    fi
    
    # Create keyd config directory if it doesn't exist
    echo "Creating keyd configuration..."
    mkdir -p /etc/keyd
    
    # Create the configuration file
    tee /etc/keyd/default.conf > /dev/null << 'EOF'
[ids]
*

[main]
# Swap Super (Meta) and Alt keys
leftmeta = leftalt
leftalt = leftmeta
rightmeta = rightalt
rightalt = rightmeta
EOF
    
    echo "✓ Configuration file created at /etc/keyd/default.conf"
    
    # Enable and start keyd service
    echo "Enabling and starting keyd service..."
    systemctl enable keyd
    systemctl restart keyd
    
    # Check if service is running
    if systemctl is-active --quiet keyd; then
        echo "✓ keyd service is running"
        echo "✓ Super and Alt keys are now swapped system-wide"
        echo ""
        echo "  To undo: sudo systemctl stop keyd && sudo systemctl disable keyd"
        echo "  To modify: edit /etc/keyd/default.conf then sudo systemctl restart keyd"
    else
        echo "⚠ Warning: keyd service failed to start"
        echo "  Check logs with: journalctl -u keyd"
    fi
else
    echo "Keybinding configuration skipped."
fi

# ============================================
# SECTION 4: NEOVIM CONFIGURATION
# ============================================

echo ""
read -p "Would you like to configure Neovim arrow-key line wrapping? [Y/n]: " CONFIGURE_NVIM
CONFIGURE_NVIM=${CONFIGURE_NVIM:-Y}

if [[ "$CONFIGURE_NVIM" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== Neovim Configuration ==="
    echo ""

    NVIM_HOME=$(eval echo ~$PRIMARY_USER)
    NVIM_CONFIG_DIR="$NVIM_HOME/.config/nvim"
    NVIM_LUA_CONFIG_DIR="$NVIM_CONFIG_DIR/lua/config"
    NVIM_OPTIONS_FILE="$NVIM_LUA_CONFIG_DIR/options.lua"
    NVIM_KEYMAPS_FILE="$NVIM_LUA_CONFIG_DIR/keymaps.lua"

    mkdir -p "$NVIM_LUA_CONFIG_DIR"

    if [[ ! -f "$NVIM_OPTIONS_FILE" ]]; then
        cat > "$NVIM_OPTIONS_FILE" <<'EOF'
-- Options are automatically loaded before lazy.nvim startup
-- Add any additional options here
EOF
    fi

    if ! grep -Fq 'vim.opt.whichwrap:append("<,>,[,]")' "$NVIM_OPTIONS_FILE"; then
        echo 'vim.opt.whichwrap:append("<,>,[,]")' >> "$NVIM_OPTIONS_FILE"
        echo "✓ Enabled left/right arrow wrapping across line boundaries"
    else
        echo "✓ Left/right arrow wrapping is already configured"
    fi

    if [[ ! -f "$NVIM_KEYMAPS_FILE" ]]; then
        cat > "$NVIM_KEYMAPS_FILE" <<'EOF'
-- Keymaps are automatically loaded on the VeryLazy event
-- Add any additional keymaps here
EOF
    fi

    if ! grep -Fq 'Move down or to end of final line' "$NVIM_KEYMAPS_FILE"; then
        cat >> "$NVIM_KEYMAPS_FILE" <<'EOF'
vim.keymap.set("n", "<Down>", function()
  if vim.fn.line(".") == vim.fn.line("$") then
    return "$"
  end

  return "j"
end, { expr = true, desc = "Move down or to end of final line" })
EOF
        echo "✓ Configured down arrow to move to the end of the final line"
    else
        echo "✓ Final-line down arrow behavior is already configured"
    fi

    chown -R $PRIMARY_USER:$PRIMARY_USER "$NVIM_CONFIG_DIR"
    echo "✓ Neovim configuration updated for $PRIMARY_USER"
else
    echo "Neovim configuration skipped."
fi

# ============================================
# SECTION 5: DISK AUTO-DECRYPTION
# ============================================

echo ""
read -p "Would you like to configure disk auto-decrypt on boot, and choose a security option? This is necessary for enabling remote shell access after boot without physically typing a decryption password locally. [Y/n]: " CONFIGURE_LUKS
CONFIGURE_LUKS=${CONFIGURE_LUKS:-Y}

if [[ "$CONFIGURE_LUKS" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== LUKS Keyfile Auto-Unlock Setup ==="
    echo ""
    echo "This will configure automatic disk decryption using a keyfile."
    echo "The keyfile will be embedded in the initramfs for auto-unlock at boot."
    echo ""
    echo "⚠ WARNING: This reduces security if someone gains physical access to your machine."
    echo "The disk will auto-decrypt without requiring a password at boot. (Though this"
    echo "script will offer options for mitigating this security risk.)"
    echo ""
    echo "=== Omarchy-Specific Configuration Notes ==="
    echo ""
    echo "Omarchy Linux has several unique characteristics that differ from standard Arch:"
    echo ""
    echo "1. Kernel Command Line Storage:"
    echo "   • Standard Arch: /etc/kernel/cmdline"
    echo "   • Omarchy: /etc/default/limine (KERNEL_CMDLINE[default])"
    echo "   → This script will update /etc/default/limine, which is what Omarchy actually uses"
    echo ""
    echo "2. Initramfs Build System:"
    echo "   • Standard Arch: mkinitcpio -P"
    echo "   • Omarchy: limine-mkinitcpio (custom wrapper)"
    echo "   → This script uses the Omarchy-specific build command"
    echo ""
    echo "3. Boot Configuration:"
    echo "   • Omarchy uses Limine bootloader with UKI (Unified Kernel Image)"
    echo "   • The limine-entry-tool manages boot entries (Java-based)"
    echo "   • Boot configs are auto-generated, not manually edited"
    echo ""
    echo "4. Configuration Overrides:"
    echo "   • Omarchy uses /etc/mkinitcpio.conf.d/omarchy_hooks.conf"
    echo "   • This overrides the main /etc/mkinitcpio.conf"
    echo "   → This script will modify the correct override file"
    echo ""
    echo "As a result of this script:"
    echo "   ✓ Keyfile will be added to LUKS device"
    echo "   ✓ Keyfile will be embedded in initramfs via FILES=()"
    echo "   ✓ cryptkey=rootfs:/root/cryptkey.bin will be added to /etc/default/limine"
    echo "   ✓ UKI will be rebuilt with the new configuration"
    echo "   ✓ System will auto-decrypt on boot without password prompt"
    echo ""
    
    read -p "Continue with automatic decryption setup? [y/N]: " CONFIRM_LUKS
    if [[ ! "$CONFIRM_LUKS" =~ ^[Yy]$ ]]; then
        echo "Disk auto-decryption skipped."
    else
        # Detect encrypted device
        ENCRYPTED_DEV=$(lsblk -no NAME,FSTYPE | grep crypto_LUKS | head -n1 | awk '{print $1}' | sed 's/[^a-zA-Z0-9]//g')
        if [[ -z "$ENCRYPTED_DEV" ]]; then
            echo "Error: Could not detect LUKS encrypted device"
            echo "Please specify the device manually:"
            read -p "LUKS device path (e.g., /dev/nvme0n1p2): " ENCRYPTED_PATH
            if [[ ! -b "$ENCRYPTED_PATH" ]]; then
                echo "Error: $ENCRYPTED_PATH is not a valid block device"
                echo "Disk auto-decryption skipped."
                CONFIGURE_LUKS="N"
            fi
        else
            ENCRYPTED_PATH="/dev/$ENCRYPTED_DEV"
        fi
        
        if [[ "$CONFIGURE_LUKS" =~ ^[Yy]$ ]]; then
            echo "Detected LUKS device: $ENCRYPTED_PATH"
            
            # Get LUKS UUID
            LUKS_UUID=$(cryptsetup luksUUID "$ENCRYPTED_PATH")
            echo "LUKS UUID: $LUKS_UUID"
            echo ""
            
            echo "[1/6] Creating keyfile..."
            KEYFILE="/root/cryptkey.bin"
            KEYFILE_EXISTS=false
            if [[ -f "$KEYFILE" ]]; then
                KEYFILE_EXISTS=true
                echo "⚠ Keyfile already exists at $KEYFILE"
                read -p "Overwrite existing keyfile? [y/N]: " OVERWRITE
                if [[ ! "$OVERWRITE" =~ ^[Yy]$ ]]; then
                    echo "Using existing keyfile"
                else
                    dd bs=512 count=4 if=/dev/random of="$KEYFILE" iflag=fullblock 2>/dev/null
                    chmod 000 "$KEYFILE"
                    echo "✓ New keyfile created"
                    KEYFILE_EXISTS=false
                fi
            else
                dd bs=512 count=4 if=/dev/random of="$KEYFILE" iflag=fullblock 2>/dev/null
                chmod 000 "$KEYFILE"
                echo "✓ Keyfile created at $KEYFILE"
            fi
            
            echo ""
            echo "[2/6] Adding keyfile to LUKS device..."
            # Check if keyfile is already added to LUKS
            if [[ "$KEYFILE_EXISTS" == true ]]; then
                echo "Checking if keyfile is already enrolled in LUKS..."
                if cryptsetup open --test-passphrase "$ENCRYPTED_PATH" --key-file "$KEYFILE" 2>/dev/null; then
                    echo "✓ Keyfile is already enrolled in LUKS device"
                else
                    echo "Keyfile exists but is not enrolled. You will be prompted for your LUKS passphrase:"
                    if cryptsetup luksAddKey "$ENCRYPTED_PATH" "$KEYFILE"; then
                        echo "✓ Keyfile added to LUKS device"
                    else
                        echo "✗ Failed to add keyfile to LUKS device"
                        echo "Disk auto-decryption skipped."
                        CONFIGURE_LUKS="N"
                    fi
                fi
            else
                echo "You will be prompted for your current LUKS passphrase:"
                if cryptsetup luksAddKey "$ENCRYPTED_PATH" "$KEYFILE"; then
                    echo "✓ Keyfile added to LUKS device"
                else
                    echo "✗ Failed to add keyfile to LUKS device"
                    echo "Disk auto-decryption skipped."
                    CONFIGURE_LUKS="N"
                fi
            fi
            
            if [[ "$CONFIGURE_LUKS" =~ ^[Yy]$ ]]; then
                echo ""
                echo "[3/6] Backing up current mkinitcpio configuration..."
                MKINITCPIO_CONF="/etc/mkinitcpio.conf.d/omarchy_hooks.conf"
                if [[ -f "$MKINITCPIO_CONF" ]]; then
                    cp "$MKINITCPIO_CONF" "${MKINITCPIO_CONF}.backup"
                    echo "✓ Backup created: ${MKINITCPIO_CONF}.backup"
                else
                    MKINITCPIO_CONF="/etc/mkinitcpio.conf"
                    cp "$MKINITCPIO_CONF" "${MKINITCPIO_CONF}.backup"
                    echo "✓ Backup created: ${MKINITCPIO_CONF}.backup"
                fi
                
                echo ""
                echo "[4/6] Adding keyfile to initramfs..."
                # Update FILES array in mkinitcpio.conf without clobbering existing entries
                if grep -q "^FILES=(" "$MKINITCPIO_CONF"; then
                    if grep -Fq "$KEYFILE" "$MKINITCPIO_CONF"; then
                        echo "✓ Keyfile already present in mkinitcpio FILES"
                    else
                        sed -i "s|^FILES=(\\(.*\\))|FILES=(\\1 $KEYFILE)|" "$MKINITCPIO_CONF"
                        echo "✓ Added keyfile to existing mkinitcpio FILES"
                    fi
                else
                    echo "FILES=($KEYFILE)" >> "$MKINITCPIO_CONF"
                    echo "✓ Created mkinitcpio FILES with keyfile"
                fi
                
                echo ""
                echo "[5/6] Updating kernel command line in Omarchy configuration..."
                LIMINE_CONFIG="/etc/default/limine"
                
                # Backup limine config
                cp "$LIMINE_CONFIG" "${LIMINE_CONFIG}.backup"
                echo "✓ Backup created: ${LIMINE_CONFIG}.backup"
                
                # Check if cryptkey parameter already exists
                if grep -q "cryptkey=" "$LIMINE_CONFIG"; then
                    echo "✓ cryptkey parameter already present in configuration"
                else
                    # Add cryptkey before cryptdevice in either:
                    #   KERNEL_CMDLINE[default]="..."
                    #   KERNEL_CMDLINE[default]+="..."
                    if grep -q 'KERNEL_CMDLINE\[default\].*cryptdevice=' "$LIMINE_CONFIG"; then
                        sed -i -E '0,/KERNEL_CMDLINE\[default\].*cryptdevice=/{s|(KERNEL_CMDLINE\[default\]\+?=")([^"]*?)cryptdevice=|\1\2cryptkey=rootfs:'"$KEYFILE"' cryptdevice=|}' "$LIMINE_CONFIG"
                        echo "✓ Added cryptkey parameter to existing KERNEL_CMDLINE[default] entry"
                    else
                        # Fallback for newer layouts where cryptdevice may be elsewhere.
                        # Add a standalone default cmdline append line.
                        echo "KERNEL_CMDLINE[default]+=\"cryptkey=rootfs:$KEYFILE\"" >> "$LIMINE_CONFIG"
                        echo "✓ Added cryptkey parameter as a new KERNEL_CMDLINE[default]+ entry"
                    fi
                fi
                
                # Also update /etc/kernel/cmdline for consistency (even though it's not used by Omarchy)
                CMDLINE_FILE="/etc/kernel/cmdline"
                if [[ -f "$CMDLINE_FILE" ]]; then
                    cp "$CMDLINE_FILE" "${CMDLINE_FILE}.backup"
                    if ! grep -q "cryptkey=" "$CMDLINE_FILE"; then
                        sed -i "s|cryptdevice=|cryptkey=rootfs:$KEYFILE cryptdevice=|" "$CMDLINE_FILE"
                    fi
                fi
                
                echo ""
                echo "[6/6] Rebuilding initramfs..."
                if command -v limine-mkinitcpio >/dev/null 2>&1; then
                    limine-mkinitcpio
                    echo "✓ Initramfs rebuilt with Limine"
                else
                    mkinitcpio -P
                    echo "✓ Initramfs rebuilt"
                fi
                if command -v limine-update >/dev/null 2>&1; then
                    limine-update
                    echo "✓ Limine entries updated"
                fi
                
                echo ""
                echo "=== LUKS Auto-Decrypt Complete ==="
                echo ""
                echo "✓ Keyfile created and added to LUKS device"
                echo "✓ Keyfile embedded in initramfs"
                echo "✓ Kernel command line updated"
                echo "✓ Initramfs rebuilt"
                echo ""
                echo "Backups created:"
                echo "  - ${MKINITCPIO_CONF}.backup"
                echo "  - ${LIMINE_CONFIG}.backup"
                if [[ -f "${CMDLINE_FILE}.backup" ]]; then
                    echo "  - ${CMDLINE_FILE}.backup"
                fi
                
                # Security configuration
                echo ""
                echo "=== Security Configuration ==="
                echo ""
                echo "⚠ IMPORTANT: Disk decryption is now automatic on boot. This presents a security"
                echo "risk, given that Omarchy's stock configuration includes SDDM autologin."
                echo ""
                echo "Current SDDM configuration:"
                if ls /etc/sddm.conf.d/*.conf 2>/dev/null | grep -q .; then
                    for conf in /etc/sddm.conf.d/*.conf; do
                        echo "  Active: $(basename $conf)"
                        cat "$conf" | sed 's/^/    /'
                    done
                else
                    echo "  No active .conf files found"
                fi
                if ls /etc/sddm.conf.d/*.disabled 2>/dev/null | grep -q .; then
                    for conf in /etc/sddm.conf.d/*.disabled; do
                        echo "  Disabled: $(basename $conf)"
                    done
                fi
                echo ""
                echo "Would you like to:"
                echo "  1. Keep SDDM autologin, but automatically lock the screen (recommended)"
                echo "  2. Disable SDDM autologin entirely"
                echo "     Note: Omarchy has not applied its theme to the login screen, so you will"
                echo "     see the default Arch/SDDM UI"
                echo "  3. Do nothing, and accept the security risk of automatic disk decryption + autologin"
                echo ""
                read -p "Enter your choice [1-3] (default: 1): " SECURITY_CHOICE
                SECURITY_CHOICE=${SECURITY_CHOICE:-1}
                
                case $SECURITY_CHOICE in
                    1)
                        echo ""
                        echo "[Security] Configuring automatic screen lock after autologin..."
                        
                        # Get the username from SDDM config (check all possible locations)
                        # First try uncommented User= lines
                        AUTOLOGIN_USER=$(grep -h "^User=" /etc/sddm.conf.d/*.conf /etc/sddm.conf.d/*.disabled /etc/sddm.conf.d/*.backup /etc/sddm.conf 2>/dev/null | head -n1 | cut -d= -f2)
                        # If not found, try commented #User= lines
                        if [[ -z "$AUTOLOGIN_USER" ]]; then
                            AUTOLOGIN_USER=$(grep -h "^#User=" /etc/sddm.conf.d/*.conf /etc/sddm.conf.d/*.disabled /etc/sddm.conf.d/*.backup 2>/dev/null | head -n1 | sed 's/^#User=//')
                        fi
                        # If still not found, ask the user
                        if [[ -z "$AUTOLOGIN_USER" ]]; then
                            echo "⚠ Could not detect autologin user from SDDM configuration"
                            read -p "Enter autologin username [omarchy]: " AUTOLOGIN_USER
                            AUTOLOGIN_USER=${AUTOLOGIN_USER:-omarchy}
                            echo "Using autologin user: $AUTOLOGIN_USER"
                        else
                            echo "Detected autologin user: $AUTOLOGIN_USER"
                        fi
                        
                        USER_HOME=$(eval echo ~$AUTOLOGIN_USER)
                        
                        SDDM_CHANGED=false
                        
                        # Remove /etc/sddm.conf if it exists (was used to disable autologin)
                        if [[ -f /etc/sddm.conf ]]; then
                            echo "Found /etc/sddm.conf - removing to re-enable autologin..."
                            rm /etc/sddm.conf
                            echo "✓ Removed /etc/sddm.conf"
                            SDDM_CHANGED=true
                        else
                            echo "No /etc/sddm.conf found (already removed or never created)"
                        fi
                        
                        # Re-enable SDDM autologin (re-enable if disabled)
                        echo "Checking for disabled SDDM configs..."
                        SDDM_DISABLED=$(find /etc/sddm.conf.d/ -name "*.disabled" 2>/dev/null)
                        if [[ -n "$SDDM_DISABLED" ]]; then
                            echo "Found disabled configs, re-enabling..."
                            for disabled_conf in $SDDM_DISABLED; do
                                if grep -q "User=" "$disabled_conf" || grep -q "Session=" "$disabled_conf" || grep -q "\[Autologin\]" "$disabled_conf"; then
                                    # Rename back to .conf to enable it
                                    enabled_conf="${disabled_conf%.disabled}"
                                    mv "$disabled_conf" "$enabled_conf"
                                    echo "✓ Re-enabled autologin config: $disabled_conf -> $enabled_conf"
                                    SDDM_CHANGED=true
                                fi
                            done
                        else
                            echo "No disabled configs found"
                        fi
                        
                        # Uncomment User= and Session= lines in active .conf files
                        echo "Checking for commented autologin settings..."
                        SDDM_CONFIGS=$(find /etc/sddm.conf.d/ -name "*.conf" 2>/dev/null)
                        if [[ -n "$SDDM_CONFIGS" ]]; then
                            for conf in $SDDM_CONFIGS; do
                                echo "Checking $conf..."
                                if grep -q "^#User=" "$conf" || grep -q "^#Session=" "$conf"; then
                                    echo "Found commented lines, uncommenting..."
                                    sed -i 's/^#User=/User=/' "$conf"
                                    sed -i 's/^#Session=/Session=/' "$conf"
                                    echo "✓ Uncommented autologin settings in $conf"
                                    SDDM_CHANGED=true
                                else
                                    echo "No commented autologin lines found in $conf"
                                fi
                            done
                        else
                            echo "No .conf files found in /etc/sddm.conf.d/"
                        fi
                        
                        # Check if hyprlock is installed
                        if ! command -v hyprlock >/dev/null 2>&1; then
                            echo "⚠ Warning: hyprlock not found. Installing..."
                            pacman -S --needed --noconfirm hyprlock hypridle
                        fi
                        
                        # Add autolock to Hyprland config (legacy conf + modern lua)
                        hypr_add_autolock "$USER_HOME"
                        
                        chown -R $AUTOLOGIN_USER:$AUTOLOGIN_USER "$USER_HOME/.config/hypr"
                        
                        echo "✓ Auto-lock configured for user '$AUTOLOGIN_USER'"
                        echo "  The screen will lock 3 seconds after login using hyprlock"
                        
                        if [[ "$SDDM_CHANGED" == true ]]; then
                            echo ""
                            echo "⚠ SDDM autologin was re-enabled. You must reboot for changes to take effect."
                        fi
                        ;;
                        
                    2)
                        echo ""
                        echo "[Security] Disabling SDDM autologin..."
                        
                        # Get the username to clean up their Hyprland config
                        AUTOLOGIN_USER=$(grep -h "^User=\|^#User=" /etc/sddm.conf.d/*.conf /etc/sddm.conf.d/*.disabled /etc/sddm.conf 2>/dev/null | head -n1 | sed 's/^#//' | cut -d= -f2)
                        if [[ -n "$AUTOLOGIN_USER" ]]; then
                            USER_HOME=$(eval echo ~$AUTOLOGIN_USER)
                            # Remove autolock from Hyprland conf + lua if present
                            hypr_remove_autolock "$USER_HOME"
                        fi
                        
                        # Disable autologin by renaming config files in /etc/sddm.conf.d/
                        SDDM_CONFIGS=$(find /etc/sddm.conf.d/ -name "*.conf" ! -name "*.disabled" 2>/dev/null)
                        SDDM_CHANGED=false
                        if [[ -n "$SDDM_CONFIGS" ]]; then
                            for conf in $SDDM_CONFIGS; do
                                if grep -q "User=" "$conf" || grep -q "Session=" "$conf" || grep -q "\[Autologin\]" "$conf"; then
                                    # Comment out User= and Session= lines if not already commented
                                    # This ensures the .disabled file has them commented for later restoration
                                    sed -i 's/^User=/#User=/' "$conf"
                                    sed -i 's/^Session=/#Session=/' "$conf"
                                    
                                    # Rename the file to disable it
                                    mv "$conf" "${conf}.disabled"
                                    echo "✓ Disabled autologin config: $conf -> ${conf}.disabled"
                                    SDDM_CHANGED=true
                                fi
                            done
                        fi
                        
                        # Create /etc/sddm.conf to explicitly disable autologin
                        # This prevents SDDM from using sddm-autologin PAM module
                        echo "Creating /etc/sddm.conf to explicitly disable autologin..."
                        if [[ -f /etc/sddm.conf ]]; then
                            cp /etc/sddm.conf /etc/sddm.conf.backup
                        fi
                        
                        cat > /etc/sddm.conf <<'SDDM_CONF_EOF'
[Autologin]
# Explicitly disable autologin
User=
Session=
Relogin=false
SDDM_CONF_EOF
                        
                        echo "✓ Created /etc/sddm.conf with autologin disabled"
                        SDDM_CHANGED=true
                        
                        if [[ "$SDDM_CHANGED" == true ]]; then
                            echo ""
                            echo "⚠ IMPORTANT: You must reboot for autologin to be fully disabled."
                            echo "After reboot, you will see the SDDM login screen."
                            echo "Note: Omarchy has not applied its theme to the login screen."
                        fi
                        ;;
                        
                    3)
                        echo ""
                        echo "[Security] Removing security restrictions..."
                        
                        # Get the username (check all possible locations, including commented lines)
                        AUTOLOGIN_USER=$(grep -h "^User=\|^#User=" /etc/sddm.conf.d/*.conf /etc/sddm.conf.d/*.disabled /etc/sddm.conf.d/*.backup /etc/sddm.conf 2>/dev/null | grep -v "^#" | head -n1 | cut -d= -f2)
                        if [[ -z "$AUTOLOGIN_USER" ]]; then
                            # Try to find even commented User lines
                            AUTOLOGIN_USER=$(grep -h "^#User=" /etc/sddm.conf.d/*.conf /etc/sddm.conf.d/*.disabled /etc/sddm.conf.d/*.backup 2>/dev/null | head -n1 | sed 's/^#User=//')
                        fi
                        if [[ -z "$AUTOLOGIN_USER" ]]; then
                            echo "⚠ Could not detect autologin user from SDDM configuration"
                            read -p "Enter autologin username [omarchy]: " AUTOLOGIN_USER
                            AUTOLOGIN_USER=${AUTOLOGIN_USER:-omarchy}
                        fi
                        
                        USER_HOME=$(eval echo ~$AUTOLOGIN_USER)
                        
                        SDDM_CHANGED=false
                        
                        # Remove /etc/sddm.conf if it exists (was used to disable autologin)
                        if [[ -f /etc/sddm.conf ]]; then
                            echo "Removing /etc/sddm.conf (autologin disable override)..."
                            rm /etc/sddm.conf
                            SDDM_CHANGED=true
                        fi
                        
                        # Ensure SDDM autologin is enabled (re-enable if disabled)
                        echo "Ensuring SDDM autologin is enabled..."
                        SDDM_DISABLED=$(find /etc/sddm.conf.d/ -name "*.disabled" 2>/dev/null)
                        if [[ -n "$SDDM_DISABLED" ]]; then
                            for disabled_conf in $SDDM_DISABLED; do
                                if grep -q "User=" "$disabled_conf" || grep -q "Session=" "$disabled_conf" || grep -q "\[Autologin\]" "$disabled_conf"; then
                                    # Rename back to .conf to enable it
                                    enabled_conf="${disabled_conf%.disabled}"
                                    mv "$disabled_conf" "$enabled_conf"
                                    echo "✓ Re-enabled autologin config: $disabled_conf -> $enabled_conf"
                                    SDDM_CHANGED=true
                                fi
                            done
                        fi
                        
                        # Uncomment User= and Session= lines in active .conf files
                        SDDM_CONFIGS=$(find /etc/sddm.conf.d/ -name "*.conf" 2>/dev/null)
                        if [[ -n "$SDDM_CONFIGS" ]]; then
                            for conf in $SDDM_CONFIGS; do
                                if grep -q "^#User=" "$conf" || grep -q "^#Session=" "$conf"; then
                                    echo "Uncommenting autologin settings in $conf..."
                                    sed -i 's/^#User=/User=/' "$conf"
                                    sed -i 's/^#Session=/Session=/' "$conf"
                                    echo "✓ Uncommented autologin settings"
                                    SDDM_CHANGED=true
                                fi
                            done
                        fi
                        
                        # Remove autolock from Hyprland conf + lua if present
                        hypr_remove_autolock "$USER_HOME"
                        
                        echo "⚠ No security protections active."
                        echo "Your system will boot directly to the desktop without authentication."
                        
                        if [[ "$SDDM_CHANGED" == true ]]; then
                            echo ""
                            echo "⚠ SDDM autologin was re-enabled. You must reboot for changes to take effect."
                        fi
                        ;;
                        
                    *)
                        echo ""
                        echo "Invalid choice. No security changes made."
                        ;;
                esac
                
                echo ""
                echo "⚠ If something goes wrong and the system doesn't boot:"
                echo "1. Boot from a live USB or select a snapshot from the Limine boot menu"
                echo "2. Decrypt and mount your drive manually"
                echo "3. Restore from backups:"
                echo "   cp ${MKINITCPIO_CONF}.backup ${MKINITCPIO_CONF}"
                echo "   cp ${LIMINE_CONFIG}.backup ${LIMINE_CONFIG}"
                echo "4. Rebuild initramfs: chroot and run 'limine-mkinitcpio'"
            fi
        fi
    fi
else
    echo "Disk auto-decryption skipped."
fi

# ============================================
# SECTION 6: HEADLESS BOOT MODE
# ============================================

echo ""
read -p "Would you like to configure headless boot (boot to text console instead of GUI)? [Y/n]: " CONFIGURE_HEADLESS
CONFIGURE_HEADLESS=${CONFIGURE_HEADLESS:-Y}

if [[ "$CONFIGURE_HEADLESS" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== Headless Boot Configuration ==="
    echo ""
    echo "This will configure the system to boot to a text console login on tty1,"
    echo "rather than starting SDDM/Hyprland on boot."
    echo ""
    echo "After applying:"
    echo "  - System boots to text console (tty1)"
    echo "  - All GPU drivers (NVIDIA/AMD), CUDA, and ROCm remain fully available"
    echo "  - To launch Hyprland on demand: type 'gui' at the console"
    echo "  - To start SDDM on demand: 'sudo systemctl start sddm'"
    echo ""
    echo "This is recommended for AI workstation / server use, where you primarily"
    echo "interact via SSH and don't need a desktop running 24/7."
    echo ""
    read -p "Apply headless boot mode? [Y/n]: " CONFIRM_HEADLESS
    CONFIRM_HEADLESS=${CONFIRM_HEADLESS:-Y}

    if [[ "$CONFIRM_HEADLESS" =~ ^[Yy]$ ]]; then
        echo "[Headless 1/4] Backing up current default systemd target..."
        CURRENT_TARGET=$(systemctl get-default)
        echo "Current default target: $CURRENT_TARGET"
        echo "$CURRENT_TARGET" > /etc/.previous-systemd-target.backup
        echo "✓ Previous target saved to /etc/.previous-systemd-target.backup"

        echo "[Headless 2/4] Setting default target to multi-user.target..."
        systemctl set-default multi-user.target
        echo "✓ Default target set to multi-user.target (text console)"

        echo "[Headless 3/4] Disabling SDDM service on boot..."
        if systemctl is-enabled sddm.service &>/dev/null; then
            systemctl disable sddm.service
            echo "✓ SDDM disabled (can still be started manually with 'sudo systemctl start sddm')"
        else
            echo "✓ SDDM was already disabled"
        fi

        # Ensure getty@tty1 is enabled (it normally is, but verify)
        systemctl enable getty@tty1.service &>/dev/null
        echo "✓ Console login on tty1 enabled"

        echo "[Headless 4/4] Installing 'gui' convenience launcher for Hyprland..."
        GUI_LAUNCHER="/usr/local/bin/gui"
        cat > "$GUI_LAUNCHER" <<'GUI_EOF'
#!/bin/bash
# Launch Hyprland on demand from a TTY.
# Hyprland's exec-once directives handle starting ancillary services
# (pipewire, waybar, mako, etc.) automatically.

if [[ -n "$WAYLAND_DISPLAY" ]] || [[ -n "$DISPLAY" ]]; then
    echo "A GUI session appears to already be running."
    echo "WAYLAND_DISPLAY=$WAYLAND_DISPLAY DISPLAY=$DISPLAY"
    exit 1
fi

if [[ -z "$XDG_VTNR" ]] || [[ "$XDG_VTNR" -eq 0 ]]; then
    echo "ERROR: 'gui' must be run from a physical TTY, not over SSH."
    echo "If you need a GUI over the network, consider VNC, RDP, or x11vnc instead."
    exit 1
fi

# Set up minimal Wayland environment
export XDG_SESSION_TYPE=wayland
export XDG_SESSION_DESKTOP=Hyprland
export XDG_CURRENT_DESKTOP=Hyprland

# Hand off to Hyprland
exec Hyprland
GUI_EOF
        chmod +x "$GUI_LAUNCHER"
        echo "✓ Created $GUI_LAUNCHER"

        echo ""
        echo "✓ Headless boot mode configured."
        echo ""
        echo "After reboot:"
        echo "  • System will boot to text console login on tty1"
        echo "  • Log in with username/password (or SSH from another machine)"
        echo "  • To launch GUI: type 'gui' at the console"
        echo "  • To re-enable graphical boot:"
        echo "      sudo systemctl set-default graphical.target"
        echo "      sudo systemctl enable sddm.service"
    else
        echo "Headless boot configuration skipped."
        CONFIGURE_HEADLESS="N"
    fi
else
    echo "Headless boot configuration skipped."
fi

# ============================================
# SECTION 7: DISABLE SUSPEND/HIBERNATE
# ============================================

echo ""
read -p "Would you like to disable system suspend/hibernate? Recommended for unattended servers. [Y/n]: " DISABLE_SUSPEND
DISABLE_SUSPEND=${DISABLE_SUSPEND:-Y}

if [[ "$DISABLE_SUSPEND" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== Disabling Suspend/Hibernate ==="
    echo ""
    echo "This prevents the system from sleeping during long-running operations"
    echo "(training runs, batch inference, scheduled jobs, etc.)."
    echo ""

    systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
    echo "✓ Suspend, hibernate, and hybrid-sleep targets masked"

    # Also configure logind to not act on lid close (for laptops repurposed as servers)
    LOGIND_CONF="/etc/systemd/logind.conf.d/headless-server.conf"
    mkdir -p /etc/systemd/logind.conf.d
    cat > "$LOGIND_CONF" <<'LOGIND_EOF'
# Headless server configuration: ignore power button and lid events
# Prevents accidental shutdown/sleep on hardware that has these
[Login]
HandlePowerKey=ignore
HandleLidSwitch=ignore
HandleLidSwitchDocked=ignore
HandleLidSwitchExternalPower=ignore
IdleAction=ignore
LOGIND_EOF
    systemctl restart systemd-logind &>/dev/null || true
    echo "✓ logind configured to ignore power/lid events"

    echo ""
    echo "✓ System will no longer suspend, hibernate, or respond to power/lid events."
    echo ""
    echo "To revert:"
    echo "  sudo systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target"
    echo "  sudo rm $LOGIND_CONF"
    echo "  sudo systemctl restart systemd-logind"
else
    echo "Suspend/hibernate left enabled."
fi

# ============================================
# SECTION 8: PERSISTENT JOURNAL LOGGING
# ============================================

echo ""
read -p "Would you like to enable persistent system journal logging? Useful for debugging crashes that survive reboot. [Y/n]: " ENABLE_PERSISTENT_LOGS
ENABLE_PERSISTENT_LOGS=${ENABLE_PERSISTENT_LOGS:-Y}

if [[ "$ENABLE_PERSISTENT_LOGS" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== Persistent Journal Configuration ==="
    echo ""
    echo "By default, systemd-journald logs to /run/log/journal (volatile, lost on reboot)."
    echo "This configures it to log to /var/log/journal instead, retained across reboots."
    echo "Logs are capped at 2GB total to prevent unbounded disk usage."
    echo ""

    # Create the persistent journal directory
    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal &>/dev/null

    # Configure retention limits
    JOURNAL_CONF="/etc/systemd/journald.conf.d/persistent.conf"
    mkdir -p /etc/systemd/journald.conf.d
    cat > "$JOURNAL_CONF" <<'JOURNAL_EOF'
# Persistent journal with bounded disk usage
[Journal]
Storage=persistent
SystemMaxUse=2G
SystemKeepFree=2G
SystemMaxFileSize=128M
MaxRetentionSec=1month
JOURNAL_EOF

    systemctl restart systemd-journald
    echo "✓ Persistent journal enabled (max 2GB, 1-month retention)"
    echo ""
    echo "Useful commands:"
    echo "  journalctl -b               # Logs from current boot"
    echo "  journalctl -b -1            # Logs from previous boot"
    echo "  journalctl --list-boots     # List all boots in journal"
    echo "  journalctl --disk-usage     # Show current journal size"
else
    echo "Journal kept at default (volatile/ephemeral) configuration."
fi

# ============================================
# SECTION 9: AI WORKSTATION PACKAGES
# ============================================

echo ""
read -p "Would you like to install additional AI workstation packages? (Python tooling, monitoring, etc.) [y/N]: " INSTALL_AI_PACKAGES
INSTALL_AI_PACKAGES=${INSTALL_AI_PACKAGES:-N}

if [[ "$INSTALL_AI_PACKAGES" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== Installing AI Workstation Packages ==="
    echo ""
    echo "This will install packages commonly needed for AI work that are NOT already"
    echo "shipped with Omarchy's base install."
    echo ""
    echo "Already provided by Omarchy (will NOT be reinstalled):"
    echo "  Python (via base deps), git, btop, tmux, jq, docker, docker-compose"
    echo "  (Omarchy also pre-configures docker group membership for your user.)"
    echo ""
    echo "Additional packages to install:"
    echo ""
    echo "  Python ecosystem (beyond what Omarchy ships):"
    echo "    python-pip python-virtualenv python-pipx"
    echo ""
    echo "  Build tools:"
    echo "    base-devel  (gcc, make, autotools — needed to build Python wheels"
    echo "                 with native components, e.g., flash-attn, bitsandbytes)"
    echo ""
    echo "  Monitoring (beyond btop):"
    echo "    nvtop       (real-time NVIDIA GPU monitoring)"
    echo "    iotop       (per-process disk I/O monitoring)"
    echo "    htop        (some prefer over btop)"
    echo "    lm_sensors  (CPU/motherboard temperature reading)"
    echo "    smartmontools (SSD health monitoring; smartctl)"
    echo ""
    echo "  Utilities:"
    echo "    rsync       (efficient file sync, useful for moving model files)"
    echo "    mosh        (resilient SSH replacement; survives network drops)"
    echo ""
    read -p "Proceed with installation? [Y/n]: " CONFIRM_AI_PACKAGES
    CONFIRM_AI_PACKAGES=${CONFIRM_AI_PACKAGES:-Y}

    if [[ "$CONFIRM_AI_PACKAGES" =~ ^[Yy]$ ]]; then
        echo "Installing packages (this may take a few minutes)..."
        pacman -S --needed --noconfirm \
            python-pip python-virtualenv python-pipx \
            base-devel \
            nvtop iotop htop \
            lm_sensors smartmontools \
            rsync mosh

        if [[ $? -eq 0 ]]; then
            echo "✓ Packages installed"
        else
            echo "⚠ Some packages may have failed; check output above"
        fi

        # Verify docker is functional (Omarchy should have done this, but verify)
        echo ""
        echo "Verifying Docker configuration (Omarchy normally handles this)..."
        if systemctl is-enabled docker.service &>/dev/null; then
            echo "✓ Docker service is enabled"
        else
            echo "Docker service not enabled; enabling now..."
            systemctl enable docker.service
            echo "✓ Docker service enabled"
        fi

        if groups "$PRIMARY_USER" | grep -q docker; then
            echo "✓ $PRIMARY_USER is in docker group"
        else
            echo "$PRIMARY_USER not in docker group; adding..."
            usermod -aG docker "$PRIMARY_USER"
            echo "✓ Added $PRIMARY_USER to docker group (log out/in to take effect)"
        fi

        echo ""
        echo "✓ AI workstation packages configured."
        echo ""
        echo "Quick references:"
        echo "  Python isolated environments:"
        echo "    python -m venv ~/.venvs/myenv && source ~/.venvs/myenv/bin/activate"
        echo "    pipx install <tool>          # for CLI tools in isolation"
        echo "  GPU monitoring:"
        echo "    nvtop                        # NVIDIA GPUs (interactive)"
        echo "    nvidia-smi -l 1              # NVIDIA, refreshing every second"
        echo "  System monitoring:"
        echo "    btop                         # general system (Omarchy default)"
        echo "    iotop                        # disk I/O per process"
        echo "    sensors                      # CPU/board temps (run sensors-detect first)"
        echo "    smartctl -a /dev/nvme0       # SSD health"
        echo "  Resilient remote sessions:"
        echo "    mosh user@host               # SSH replacement that survives reconnects"
    else
        echo "AI workstation packages skipped."
        INSTALL_AI_PACKAGES="N"
    fi
else
    echo "AI workstation packages skipped."
fi

# ============================================
# FINAL SUMMARY
# ============================================

echo ""
echo "=========================================="
echo "  Configuration Complete!"
echo "=========================================="
echo ""
echo "Summary of changes:"
if [[ "$CONFIGURE_NETWORK" =~ ^[Yy]$ ]]; then
    echo "  ✓ Network configured with static IP"
fi
if [[ "$PACKAGES" != "none" && -n "$PACKAGES" ]]; then
    echo "  ✓ Additional packages installed"
fi
if [[ "$SWAP_KEYS" =~ ^[Yy]$ ]]; then
    echo "  ✓ Keybindings swapped (SUPER ↔ ALT)"
fi
if [[ "$CONFIGURE_NVIM" =~ ^[Yy]$ ]]; then
    echo "  ✓ Neovim arrow-key behavior configured"
fi
if [[ "$CONFIGURE_LUKS" =~ ^[Yy]$ ]]; then
    echo "  ✓ Disk auto-decryption configured"
fi
if [[ "$CONFIGURE_HEADLESS" =~ ^[Yy]$ ]]; then
    echo "  ✓ Headless boot configured (boots to console; 'gui' launches Hyprland)"
fi
if [[ "$DISABLE_SUSPEND" =~ ^[Yy]$ ]]; then
    echo "  ✓ Suspend/hibernate disabled"
fi
if [[ "$ENABLE_PERSISTENT_LOGS" =~ ^[Yy]$ ]]; then
    echo "  ✓ Persistent journal logging enabled"
fi
if [[ "$INSTALL_AI_PACKAGES" =~ ^[Yy]$ ]]; then
    echo "  ✓ AI workstation packages installed"
fi
echo ""
read -p "Would you like to reboot now to apply all changes? [y/N]: " REBOOT_NOW
if [[ "$REBOOT_NOW" =~ ^[Yy]$ ]]; then
    echo "Rebooting..."
    reboot
else
    echo "Remember to reboot to apply all changes!"
    echo ""
    echo "Thank you for using the Omarchy Configuration Helper!"
fi