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
echo "  4. Configure disk auto-decryption on boot (with options for mitigating security risk)"
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
# SECTION 1: NETWORK CONFIGURATION
# ============================================

read -p "Would you like to configure networking for a static IP? [Y/n]: " CONFIGURE_NETWORK
CONFIGURE_NETWORK=${CONFIGURE_NETWORK:-Y}

if [[ "$CONFIGURE_NETWORK" =~ ^[Yy]$ ]]; then
    echo ""
    echo "=== Network Configuration ==="
    echo ""
    
    read -p "SSH port [22]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}

    read -p "Network gateway [192.168.1.1]: " GATEWAY
    GATEWAY=${GATEWAY:-192.168.1.1}

    read -p "Static IP address (required): " STATIC_IP
    while [[ -z "$STATIC_IP" ]]; do
        echo "Static IP address is required!"
        read -p "Static IP address: " STATIC_IP
    done

    # Detect primary network interface
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$INTERFACE" ]]; then
        echo "Could not detect network interface automatically."
        read -p "Enter network interface name (e.g., enp86s0, eth0): " INTERFACE
    fi

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
# SECTION 4: DISK AUTO-DECRYPTION
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
                # Update FILES array in mkinitcpio.conf
                if grep -q "^FILES=(" "$MKINITCPIO_CONF"; then
                    sed -i "s|^FILES=(.*)|FILES=($KEYFILE)|" "$MKINITCPIO_CONF"
                else
                    echo "FILES=($KEYFILE)" >> "$MKINITCPIO_CONF"
                fi
                echo "✓ Keyfile added to mkinitcpio FILES"
                
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
                    # Add cryptkey parameter to the first KERNEL_CMDLINE[default] line
                    # Insert it right after the opening quote, before cryptdevice
                    sed -i "0,/KERNEL_CMDLINE\[default\]=\"cryptdevice=/s|KERNEL_CMDLINE\[default\]=\"cryptdevice=|KERNEL_CMDLINE[default]=\"cryptkey=rootfs:$KEYFILE cryptdevice=|" "$LIMINE_CONFIG"
                    echo "✓ Added cryptkey parameter to kernel command line"
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
                        
                        # Create Hyprland config directory if needed
                        mkdir -p "$USER_HOME/.config/hypr"
                        
                        # Check if hyprlock is installed
                        if ! command -v hyprlock >/dev/null 2>&1; then
                            echo "⚠ Warning: hyprlock not found. Installing..."
                            pacman -S --needed --noconfirm hyprlock hypridle
                        fi
                        
                        # Add autolock to Hyprland config
                        HYPR_CONFIG="$USER_HOME/.config/hypr/hyprland.conf"
                        if [[ -f "$HYPR_CONFIG" ]]; then
                            # Backup the config if not already backed up
                            if [[ ! -f "${HYPR_CONFIG}.backup" ]]; then
                                cp "$HYPR_CONFIG" "${HYPR_CONFIG}.backup"
                            fi
                            
                            # Remove any existing autolock entries first
                            sed -i '/# Auto-lock screen after autologin for security/d' "$HYPR_CONFIG"
                            sed -i '/exec-once.*hyprlock/d' "$HYPR_CONFIG"
                            
                            # Add exec-once at the end of the config
                            echo "" >> "$HYPR_CONFIG"
                            echo "# Auto-lock screen after autologin for security" >> "$HYPR_CONFIG"
                            echo "exec-once = sleep 3 && hyprlock" >> "$HYPR_CONFIG"
                            echo "✓ Added hyprlock autostart to Hyprland config"
                        else
                            echo "⚠ Hyprland config not found at $HYPR_CONFIG"
                            echo "  Creating minimal config with autolock..."
                            cat > "$HYPR_CONFIG" <<'HYPR_EOF'
# Auto-lock screen after autologin for security
exec-once = sleep 3 && hyprlock
HYPR_EOF
                        fi
                        
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
                            HYPR_CONFIG="$USER_HOME/.config/hypr/hyprland.conf"
                            
                            # Remove autolock from Hyprland config if it exists
                            if [[ -f "$HYPR_CONFIG" ]]; then
                                if grep -q "exec-once.*hyprlock" "$HYPR_CONFIG"; then
                                    sed -i '/# Auto-lock screen after autologin for security/d' "$HYPR_CONFIG"
                                    sed -i '/exec-once.*hyprlock/d' "$HYPR_CONFIG"
                                    echo "✓ Removed auto-lock from Hyprland config"
                                fi
                            fi
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
                        HYPR_CONFIG="$USER_HOME/.config/hypr/hyprland.conf"
                        
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
                        
                        # Remove autolock from Hyprland config if it exists
                        if [[ -f "$HYPR_CONFIG" ]]; then
                            if grep -q "exec-once.*hyprlock" "$HYPR_CONFIG"; then
                                sed -i '/# Auto-lock screen after autologin for security/d' "$HYPR_CONFIG"
                                sed -i '/exec-once.*hyprlock/d' "$HYPR_CONFIG"
                                echo "✓ Removed auto-lock from Hyprland config"
                            fi
                        fi
                        
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
if [[ "$CONFIGURE_LUKS" =~ ^[Yy]$ ]]; then
    echo "  ✓ Disk auto-decryption configured"
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