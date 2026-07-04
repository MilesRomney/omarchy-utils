#!/bin/bash

# Omarchy Hyprland Configuration Preset Switcher
# Switch between Omarchy, upstream Hyprland, and common Hyprland dotfile presets.

set -e

# Reattach stdin to terminal if piped
if [ ! -t 0 ]; then
    exec < /dev/tty
fi

echo "================================================="
echo "  Omarchy Hyprland Configuration Preset Helper"
echo "================================================="
echo ""
echo "This helper switches ~/.config/hypr between versioned Hyprland configuration"
echo "presets, backing up the active preset before making changes."
echo ""
echo "When switching to a preset, this script checks the preset's authoritative"
echo "GitHub publication and offers to use the newest version or the last backup."
echo ""
echo "Press Enter to continue..."
read

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Check if running on Arch/Omarchy Linux
if [[ ! -f /etc/os-release ]] || ! grep -qi "ID=arch" /etc/os-release; then
   echo "ERROR: This script is designed for Omarchy Linux only."
   echo "It appears you are not running Arch/Omarchy Linux."
   echo ""
   if [[ -f /etc/os-release ]]; then
       echo "Detected OS:"
       grep "^PRETTY_NAME=" /etc/os-release | cut -d= -f2 | tr -d '"'
   fi
   echo ""
   echo "Please run this script on an Omarchy Linux system."
   exit 1
fi

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $1"
        exit 1
    fi
}

require_command curl
require_command git
require_command tar
require_command diff
require_command patch

copy_dir_contents() {
    local src=$1
    local dest=$2

    rm -rf "$dest"
    mkdir -p "$dest"
    if [[ -d "$src" ]]; then
        cp -a "$src"/. "$dest"/
    fi
}

copy_path_contents() {
    local src=$1
    local dest=$2

    rm -rf "$dest"
    mkdir -p "$(dirname "$dest")"
    if [[ -d "$src" ]]; then
        mkdir -p "$dest"
        cp -a "$src"/. "$dest"/
    elif [[ -f "$src" ]]; then
        cp -a "$src" "$dest"
    fi
}

detect_primary_user() {
    PRIMARY_USER=""

    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        PRIMARY_USER=$SUDO_USER
    else
        PRIMARY_USER=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}' /etc/passwd)
    fi

    if [[ -z "$PRIMARY_USER" ]]; then
        echo "Could not automatically detect primary user"
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

    if ! id "$PRIMARY_USER" >/dev/null 2>&1; then
        echo "ERROR: User '$PRIMARY_USER' does not exist"
        exit 1
    fi
}

latest_remote_ref() {
    local repo=$1
    local branch=$2
    local sha

    sha=$(git ls-remote "https://github.com/${repo}.git" "refs/heads/${branch}" | awk '{print $1}' | head -n1)
    if [[ -z "$sha" ]]; then
        echo "ERROR: Could not find branch '$branch' for https://github.com/${repo}" >&2
        return 1
    fi

    printf '%s' "$sha"
}

remote_version_label() {
    local repo=$1
    local sha=$2
    local date

    date=$(curl -fsSL "https://api.github.com/repos/${repo}/commits/${sha}" \
        | sed -n 's/.*"date": "\([^T]*\)T.*/\1/p' \
        | head -n1 || true)

    if [[ -n "$date" ]]; then
        printf 'v%s-%s' "$(printf '%s' "$date" | tr -d '-')" "${sha:0:7}"
    else
        printf 'v%s' "${sha:0:12}"
    fi
}

extract_preset_hypr_dir() {
    local repo_dir=$1
    local configured_path=$2
    local candidate

    if [[ "$configured_path" != "auto" && ( -f "$repo_dir/$configured_path/hyprland.conf" || -f "$repo_dir/$configured_path/hyprland.lua" ) ]]; then
        printf '%s' "$repo_dir/$configured_path"
        return 0
    fi

    while IFS= read -r candidate; do
        if [[ "$candidate" == */.config/hypr ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done < <(find "$repo_dir" -type f \( -name hyprland.conf -o -name hyprland.lua \) -not -path '*/.git/*' -printf '%h\n' | sort)

    while IFS= read -r candidate; do
        if [[ "$candidate" == */config/hypr || "$candidate" == */hypr ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done < <(find "$repo_dir" -type f \( -name hyprland.conf -o -name hyprland.lua \) -not -path '*/.git/*' -printf '%h\n' | sort)

    candidate=$(find "$repo_dir" -type f \( -name hyprland.conf -o -name hyprland.lua \) -not -path '*/.git/*' -printf '%h\n' | sort | head -n1)
    if [[ -n "$candidate" ]]; then
        printf '%s' "$candidate"
        return 0
    fi

    return 1
}

cache_extra_path() {
    local repo_dir=$1
    local extra_path=$2
    local target_root=$3
    local src="$repo_dir/$extra_path"
    local dest_rel

    if [[ ! -e "$src" ]]; then
        echo "  Companion path not found, skipping: $extra_path"
        return 0
    fi

    case "$extra_path" in
        dots/*) dest_rel="${extra_path#dots/}" ;;
        *) dest_rel="$extra_path" ;;
    esac

    echo "  Caching companion config: $extra_path -> ~/$dest_rel"
    copy_path_contents "$src" "$target_root/extra/$dest_rel"
    printf '%s\n' "$dest_rel" >> "$target_root/extra/.omarchy-utils-paths"
}

download_preset() {
    local key=$1
    local repo=$2
    local ref=$3
    local source_path=$4
    local target_dir=$5
    local extra_paths=${6:-}
    local tmp_dir
    local hypr_dir

    tmp_dir=$(mktemp -d)

    echo "Downloading https://github.com/${repo} at ${ref:0:12}..."
    curl -fsSL "https://github.com/${repo}/archive/${ref}.tar.gz" | tar -xz -C "$tmp_dir" --strip-components=1

    hypr_dir=$(extract_preset_hypr_dir "$tmp_dir" "$source_path") || {
        echo "ERROR: Could not locate a Hyprland config directory in $repo"
        rm -rf "$tmp_dir"
        return 1
    }

    rm -rf "$target_dir"
    mkdir -p "$target_dir"
    copy_dir_contents "$hypr_dir" "$target_dir/hypr"

    if [[ -n "$extra_paths" ]]; then
        while IFS= read -r extra_path; do
            [[ -n "$extra_path" ]] || continue
            cache_extra_path "$tmp_dir" "$extra_path" "$target_dir"
        done < <(printf '%s' "$extra_paths" | tr ',' '\n')
    fi

    cat > "$target_dir/hypr/.omarchy-utils-preset-source" <<EOF
preset=$key
repo=$repo
source_ref=$ref
source_path=${hypr_dir#$tmp_dir/}
extra_paths=$extra_paths
downloaded_at=$(date -Iseconds)
EOF
    rm -rf "$tmp_dir"
}

latest_backup_dir() {
    local key=$1
    local backup_root=$2

    find "$backup_root/$key" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n1
}

backup_active_preset() {
    local active_key=$1
    local hypr_dir=$2
    local backup_root=$3
    local timestamp
    local backup_dir

    if [[ ! -d "$hypr_dir" ]]; then
        echo "No existing Hyprland config found at $hypr_dir; no active preset backup needed."
        return 0
    fi

    timestamp=$(date +%Y%m%d-%H%M%S)
    backup_dir="$backup_root/$active_key/$timestamp"
    mkdir -p "$backup_dir"
    copy_dir_contents "$hypr_dir" "$backup_dir/hypr"

    if [[ -f "$hypr_dir/.omarchy-utils-preset-source" ]]; then
        cp "$hypr_dir/.omarchy-utils-preset-source" "$backup_dir/source"
    fi

    echo "Backed up active preset '$active_key' to:"
    echo "  $backup_dir"
}

backup_datetime() {
    local backup_dir=$1
    basename "$backup_dir" | sed 's/-/ /'
}

apply_backup_as_patch() {
    local base_dir=$1
    local backup_hypr=$2
    local dest_dir=$3
    local tmp_dir
    local patch_file

    tmp_dir=$(mktemp -d)
    patch_file="$tmp_dir/local-changes.patch"
    mkdir -p "$tmp_dir/base" "$tmp_dir/backup"
    cp -a "$base_dir"/. "$tmp_dir/base"/
    cp -a "$backup_hypr"/. "$tmp_dir/backup"/

    (
        cd "$tmp_dir"
        diff -ruN base backup > "$patch_file" || true
    )

    if [[ ! -s "$patch_file" ]]; then
        rm -rf "$tmp_dir"
        echo "Last backup has no local changes to apply."
        return 0
    fi

    if patch -s -p1 -d "$dest_dir" < "$patch_file"; then
        rm -rf "$tmp_dir"
        echo "Applied last backup changes as a patch."
        return 0
    fi

    rm -rf "$tmp_dir"
    echo "Patch application failed; overlaying the backup files instead."
    cp -a "$backup_hypr"/. "$dest_dir"/
}

write_active_metadata() {
    local key=$1
    local name=$2
    local repo=$3
    local ref=$4
    local label=$5
    local mode=$6
    local hypr_dir=$7

    cat > "$hypr_dir/.omarchy-utils-preset" <<EOF
preset=$key
name=$name
repo=$repo
source_ref=$ref
version=$label
mode=$mode
installed_at=$(date -Iseconds)
EOF
}

write_source_metadata() {
    local key=$1
    local repo=$2
    local ref=$3
    local mode=$4
    local hypr_dir=$5

    cat > "$hypr_dir/.omarchy-utils-preset-source" <<EOF
preset=$key
repo=$repo
source_ref=$ref
source_mode=$mode
downloaded_at=$(date -Iseconds)
EOF
}

chown_hypr_dir() {
    local user=$1
    local hypr_dir=$2
    chown -R "$user:$user" "$hypr_dir"
}

preserve_keyboard_config() {
    local current_hypr=$1
    local new_hypr=$2
    local file

    for file in bindings.conf input.conf custom/keybinds.lua custom/env.lua custom/variables.lua; do
        if [[ -f "$current_hypr/$file" ]]; then
            mkdir -p "$new_hypr/$(dirname "$file")"
            cp -a "$current_hypr/$file" "$new_hypr/$file"
            echo "  Preserved $file"
        fi
    done
}

install_companion_configs() {
    local extra_root=$1
    local home_dir=$2
    local backup_root=$3
    local user=$4
    local timestamp=$5
    local rel
    local src
    local dest
    local backup_dir="$backup_root/$timestamp"

    [[ -d "$extra_root" ]] || return 0
    [[ -f "$extra_root/.omarchy-utils-paths" ]] || return 0

    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        src="$extra_root/$rel"
        dest="$home_dir/$rel"

        [[ -e "$src" ]] || continue

        if [[ -e "$dest" ]]; then
            mkdir -p "$backup_dir/$(dirname "$rel")"
            cp -a "$dest" "$backup_dir/$rel"
        fi

        echo "  Installing companion config: ~/$rel"
        copy_path_contents "$src" "$dest"
        chown -R "$user:$user" "$dest"
    done < "$extra_root/.omarchy-utils-paths"

    if [[ -d "$backup_dir" ]]; then
        chown -R "$user:$user" "$backup_dir"
        echo "  Existing companion configs were backed up to:"
        echo "    $backup_dir"
    fi
}

run_hyprctl_as_user() {
    local user=$1
    local subcommand=$2
    local uid
    local runtime_dir
    local sig
    local socket
    local ran=false

    if ! command -v hyprctl >/dev/null 2>&1; then
        echo "hyprctl is not installed; cannot run hyprctl $subcommand."
        return 1
    fi

    uid=$(id -u "$user")
    runtime_dir="/run/user/$uid"

    if [[ -n "${HYPRLAND_INSTANCE_SIGNATURE:-}" ]]; then
        hyprctl "$subcommand" || true
        ran=true
    fi

    if [[ -d "$runtime_dir/hypr" ]]; then
        while IFS= read -r socket; do
            sig=$(basename "$(dirname "$socket")")
            if command -v runuser >/dev/null 2>&1; then
                runuser -u "$user" -- env XDG_RUNTIME_DIR="$runtime_dir" HYPRLAND_INSTANCE_SIGNATURE="$sig" hyprctl "$subcommand" || true
            else
                sudo -u "$user" env XDG_RUNTIME_DIR="$runtime_dir" HYPRLAND_INSTANCE_SIGNATURE="$sig" hyprctl "$subcommand" || true
            fi
            ran=true
        done < <(find "$runtime_dir/hypr" -mindepth 2 -maxdepth 2 -name '.socket.sock' 2>/dev/null | sort)
    fi

    if [[ "$ran" != true ]]; then
        echo "Hyprland is not currently reachable via hyprctl; $subcommand skipped."
        return 1
    fi
}

validate_hyprland() {
    local user=$1

    echo "Reloading Hyprland..."
    run_hyprctl_as_user "$user" reload || true
    echo "Checking Hyprland config errors..."
    run_hyprctl_as_user "$user" configerrors || true
}

PRESETS=(
    "omarchy|Omarchy|basecamp/omarchy|master|config/hypr|"
    "hyprland|Hyprland upstream Lua example|hyprwm/Hyprland|main|example|"
    "jakoolit|JaKooLit Hyprland-Dots|JaKooLit/Hyprland-Dots|main|auto|"
    "hyde|HyDE Project|HyDE-Project/HyDE|master|auto|"
    "ml4w|ML4W dotfiles|mylinuxforwork/dotfiles|main|auto|"
    "end4|end-4 dots-hyprland|end-4/dots-hyprland|main|dots/.config/hypr|dots/.config/quickshell,dots/.config/fuzzel,dots/.config/matugen,dots/.config/wlogout"
)

echo "Detecting primary user..."
detect_primary_user
PRIMARY_HOME=$(eval echo "~$PRIMARY_USER")
HYPR_DIR="$PRIMARY_HOME/.config/hypr"
STATE_DIR="$PRIMARY_HOME/.local/share/omarchy-utils/hyprland-config"
CACHE_DIR="$STATE_DIR/presets"
BACKUP_ROOT="$STATE_DIR/backups"
ACTIVE_META="$HYPR_DIR/.omarchy-utils-preset"

mkdir -p "$CACHE_DIR" "$BACKUP_ROOT"

if [[ -f "$ACTIVE_META" ]]; then
    ACTIVE_PRESET=$(sed -n 's/^preset=//p' "$ACTIVE_META" | head -n1)
else
    ACTIVE_PRESET="manual"
fi
ACTIVE_PRESET=${ACTIVE_PRESET:-manual}

echo ""
echo "Current active preset: $ACTIVE_PRESET"
echo ""
echo "Switch to which Hyprland configuration preset?"
echo ""
for i in "${!PRESETS[@]}"; do
    preset_key=$(printf '%s' "${PRESETS[$i]}" | cut -d'|' -f1)
    preset_name=$(printf '%s' "${PRESETS[$i]}" | cut -d'|' -f2)
    printf "  %d. %s\n" "$((i + 1))" "$preset_name"
done
echo ""
read -p "Enter your choice [1-${#PRESETS[@]}]: " PRESET_CHOICE

if ! [[ "$PRESET_CHOICE" =~ ^[0-9]+$ ]] || (( PRESET_CHOICE < 1 || PRESET_CHOICE > ${#PRESETS[@]} )); then
    echo "Invalid choice."
    exit 1
fi

SELECTED_ROW=${PRESETS[$((PRESET_CHOICE - 1))]}
SELECTED_KEY=$(printf '%s' "$SELECTED_ROW" | cut -d'|' -f1)
SELECTED_NAME=$(printf '%s' "$SELECTED_ROW" | cut -d'|' -f2)
SELECTED_REPO=$(printf '%s' "$SELECTED_ROW" | cut -d'|' -f3)
SELECTED_BRANCH=$(printf '%s' "$SELECTED_ROW" | cut -d'|' -f4)
SELECTED_PATH=$(printf '%s' "$SELECTED_ROW" | cut -d'|' -f5)
SELECTED_EXTRA_PATHS=$(printf '%s' "$SELECTED_ROW" | cut -d'|' -f6)

echo ""
echo "Selected preset: $SELECTED_NAME"
echo "Authoritative source: https://github.com/$SELECTED_REPO ($SELECTED_BRANCH)"
echo ""

echo "Checking authoritative cloud publication..."
REMOTE_REF=$(latest_remote_ref "$SELECTED_REPO" "$SELECTED_BRANCH")
REMOTE_LABEL=$(remote_version_label "$SELECTED_REPO" "$REMOTE_REF")
INSTALLED_REF=""
if [[ -f "$CACHE_DIR/$SELECTED_KEY/current-ref" ]]; then
    INSTALLED_REF=$(cat "$CACHE_DIR/$SELECTED_KEY/current-ref")
fi

LATEST_BACKUP=$(latest_backup_dir "$SELECTED_KEY" "$BACKUP_ROOT")
INSTALL_MODE="newest"
USE_REF="$REMOTE_REF"
USE_LABEL="$REMOTE_LABEL"

if [[ -n "$INSTALLED_REF" && "$INSTALLED_REF" != "$REMOTE_REF" ]]; then
    echo "A newer version is available for $SELECTED_NAME."
    echo "  Installed/configured: v${INSTALLED_REF:0:12}"
    echo "  Newest available:     $REMOTE_LABEL"
    echo ""

    if [[ -n "$LATEST_BACKUP" ]]; then
        LAST_BACKUP_LABEL=$(backup_datetime "$LATEST_BACKUP")
        echo "Choose how to switch:"
        echo "  1. Use newest version ($REMOTE_LABEL)"
        echo "  2. Use last backup ($LAST_BACKUP_LABEL)"
        echo "  3. Use newest version ($REMOTE_LABEL) and apply last backup ($LAST_BACKUP_LABEL)"
        echo ""
        read -p "Enter your choice [1-3] (default: 1): " VERSION_CHOICE
        VERSION_CHOICE=${VERSION_CHOICE:-1}
        case "$VERSION_CHOICE" in
            1) INSTALL_MODE="newest" ;;
            2) INSTALL_MODE="backup" ;;
            3) INSTALL_MODE="newest-plus-backup" ;;
            *)
                echo "Invalid choice."
                exit 1
                ;;
        esac
    else
        echo "No backup exists yet for $SELECTED_NAME."
        read -p "Use newest version ($REMOTE_LABEL)? [Y/n]: " USE_NEWEST
        USE_NEWEST=${USE_NEWEST:-Y}
        if [[ ! "$USE_NEWEST" =~ ^[Yy]$ ]]; then
            echo "Cancelled."
            exit 0
        fi
    fi
elif [[ -z "$INSTALLED_REF" ]]; then
    echo "No local installed version is recorded for $SELECTED_NAME."
    if [[ -n "$LATEST_BACKUP" ]]; then
        LAST_BACKUP_LABEL=$(backup_datetime "$LATEST_BACKUP")
        echo "Choose how to switch:"
        echo "  1. Use newest version ($REMOTE_LABEL)"
        echo "  2. Use last backup ($LAST_BACKUP_LABEL)"
        echo "  3. Use newest version ($REMOTE_LABEL) and apply last backup ($LAST_BACKUP_LABEL)"
        echo ""
        read -p "Enter your choice [1-3] (default: 1): " VERSION_CHOICE
        VERSION_CHOICE=${VERSION_CHOICE:-1}
        case "$VERSION_CHOICE" in
            1) INSTALL_MODE="newest" ;;
            2) INSTALL_MODE="backup" ;;
            3) INSTALL_MODE="newest-plus-backup" ;;
            *)
                echo "Invalid choice."
                exit 1
                ;;
        esac
    else
        echo "Newest available: $REMOTE_LABEL"
    fi
else
    echo "$SELECTED_NAME is already at the newest recorded version ($REMOTE_LABEL)."
    if [[ -n "$LATEST_BACKUP" ]]; then
        LAST_BACKUP_LABEL=$(backup_datetime "$LATEST_BACKUP")
        read -p "Use last backup instead of the installed cache? [y/N]: " USE_BACKUP
        USE_BACKUP=${USE_BACKUP:-N}
        if [[ "$USE_BACKUP" =~ ^[Yy]$ ]]; then
            INSTALL_MODE="backup"
        fi
    fi
fi

echo ""
echo "Configuration Summary:"
echo "  User: $PRIMARY_USER"
echo "  Hyprland config: $HYPR_DIR"
echo "  Target preset: $SELECTED_NAME"
echo "  Mode: $INSTALL_MODE"
echo "  Source version: $REMOTE_LABEL"
if [[ -n "$SELECTED_EXTRA_PATHS" ]]; then
    echo "  Companion configs: $SELECTED_EXTRA_PATHS"
fi
echo ""
read -p "Keep your custom keybindings and keyboard config? [Y/n]: " KEEP_KEYBOARD_CONFIG
KEEP_KEYBOARD_CONFIG=${KEEP_KEYBOARD_CONFIG:-Y}
echo ""
read -p "Continue with this configuration switch? [Y/n]: " CONFIRM
CONFIRM=${CONFIRM:-Y}
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Hyprland configuration switch cancelled."
    exit 0
fi

echo ""
echo "[1/5] Backing up active preset..."
backup_active_preset "$ACTIVE_PRESET" "$HYPR_DIR" "$BACKUP_ROOT"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
NEW_HYPR="$WORK_DIR/hypr"

echo ""
echo "[2/5] Preparing selected preset..."
case "$INSTALL_MODE" in
    newest|newest-plus-backup)
        download_preset "$SELECTED_KEY" "$SELECTED_REPO" "$REMOTE_REF" "$SELECTED_PATH" "$CACHE_DIR/$SELECTED_KEY/$REMOTE_REF" "$SELECTED_EXTRA_PATHS"
        echo "$REMOTE_REF" > "$CACHE_DIR/$SELECTED_KEY/current-ref"
        copy_dir_contents "$CACHE_DIR/$SELECTED_KEY/$REMOTE_REF/hypr" "$NEW_HYPR"
        ;;
    backup)
        if [[ -z "$LATEST_BACKUP" || ! -d "$LATEST_BACKUP/hypr" ]]; then
            echo "ERROR: No valid backup found for $SELECTED_NAME"
            exit 1
        fi
        copy_dir_contents "$LATEST_BACKUP/hypr" "$NEW_HYPR"
        USE_LABEL="backup-$(basename "$LATEST_BACKUP")"
        if [[ -f "$LATEST_BACKUP/source" ]]; then
            USE_REF=$(sed -n 's/^source_ref=//p' "$LATEST_BACKUP/source" | head -n1)
        fi
        ;;
esac

if [[ "$INSTALL_MODE" == "newest-plus-backup" ]]; then
    echo ""
    echo "[3/5] Applying last backup changes..."
    BACKUP_SOURCE_REF=""
    if [[ -f "$LATEST_BACKUP/source" ]]; then
        BACKUP_SOURCE_REF=$(sed -n 's/^source_ref=//p' "$LATEST_BACKUP/source" | head -n1)
    fi

    if [[ -n "$BACKUP_SOURCE_REF" && -d "$CACHE_DIR/$SELECTED_KEY/$BACKUP_SOURCE_REF/hypr" ]]; then
        apply_backup_as_patch "$CACHE_DIR/$SELECTED_KEY/$BACKUP_SOURCE_REF/hypr" "$LATEST_BACKUP/hypr" "$NEW_HYPR"
    else
        echo "Original base version for the backup is unavailable; overlaying backup files."
        cp -a "$LATEST_BACKUP/hypr"/. "$NEW_HYPR"/
    fi
else
    echo ""
    echo "[3/5] Backup overlay not requested."
fi

write_source_metadata "$SELECTED_KEY" "$SELECTED_REPO" "$USE_REF" "$INSTALL_MODE" "$NEW_HYPR"

if [[ "$KEEP_KEYBOARD_CONFIG" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Preserving custom keybindings and keyboard config..."
    preserve_keyboard_config "$HYPR_DIR" "$NEW_HYPR"
fi

echo ""
echo "[4/5] Installing preset into $HYPR_DIR..."
copy_dir_contents "$NEW_HYPR" "$HYPR_DIR"
write_active_metadata "$SELECTED_KEY" "$SELECTED_NAME" "$SELECTED_REPO" "$USE_REF" "$USE_LABEL" "$INSTALL_MODE" "$HYPR_DIR"
chown_hypr_dir "$PRIMARY_USER" "$HYPR_DIR"

if [[ -d "$CACHE_DIR/$SELECTED_KEY/$USE_REF/extra" && "$INSTALL_MODE" != "backup" ]]; then
    echo ""
    echo "Installing companion configs for $SELECTED_NAME..."
    install_companion_configs "$CACHE_DIR/$SELECTED_KEY/$USE_REF/extra" "$PRIMARY_HOME" "$STATE_DIR/companion-backups/$SELECTED_KEY" "$PRIMARY_USER" "$(date +%Y%m%d-%H%M%S)"
fi

chown -R "$PRIMARY_USER:$PRIMARY_USER" "$STATE_DIR"

if [[ ! -f "$HYPR_DIR/hyprland.conf" && -f "$HYPR_DIR/hyprland.lua" ]]; then
    echo ""
    echo "Note: This preset uses hyprland.lua instead of hyprland.conf."
    echo "Make sure your installed Hyprland version supports Lua configuration."
fi

echo ""
echo "[5/5] Validating configuration..."
validate_hyprland "$PRIMARY_USER"

echo ""
echo "=========================================="
echo "  Hyprland Preset Switch Complete"
echo "=========================================="
echo ""
echo "Active preset: $SELECTED_NAME"
echo "Mode: $INSTALL_MODE"
echo "Version: $USE_LABEL"
echo ""
echo "Backups are stored in:"
echo "  $BACKUP_ROOT"
echo ""
echo "If Hyprland is already running, it should reload automatically. If needed, run:"
echo "  hyprctl reload"
