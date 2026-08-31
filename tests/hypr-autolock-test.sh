#!/bin/bash

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/hypr-autolock-test.XXXXXX")
LIB_FILE="$TEST_ROOT/hypr-autolock-lib.sh"
TEST_OWNER=$(id -un)
HYPR_LOCK_CMD_OVERRIDE="fixture-lock"
PASS_COUNT=0
FAIL_COUNT=0

trap 'rm -rf "$TEST_ROOT"' EXIT

sed -n '/^# >>> HYPR AUTOLOCK LIB >>>/,/^# <<< HYPR AUTOLOCK LIB <<</p' \
    "$REPO_DIR/unattended-setup.sh" > "$LIB_FILE"
# shellcheck source=/dev/null
source "$LIB_FILE"

fail() {
    echo "    $*" >&2
    return 1
}

new_home() {
    local name="$1"
    local home="$TEST_ROOT/$name/home"

    mkdir -p "$home/.config/hypr"
    printf '%s\n' "$home"
}

write_omarchy_entrypoint() {
    local target="$1"

    cat > "$target" <<'EOF'
dofile((os.getenv("OMARCHY_PATH") or "/usr/share/omarchy") .. "/default/hypr/bootstrap.lua")
require("default.hypr.omarchy")
require("hypr.monitors")
require("hypr.input")
require("hypr.bindings")
require("hypr.looknfeel")
require("hypr.autostart")
require("default.hypr.toggles")
EOF
}

write_autostart_original() {
    local target="$1"

    cat > "$target" <<'EOF'
-- Extra autostart processes.
-- o.launch_on_start("my-service")
EOF
}

append_expected_lua_helper_block() {
    local source="$1"
    local target="$2"

    cp "$source" "$target"
    cat >> "$target" <<'EOF'
-- Auto-lock screen after autologin for security
o.exec_on_start("sleep 3 && fixture-lock")
-- End Auto-lock screen after autologin for security
EOF
}

append_expected_lua_raw_block() {
    local source="$1"
    local target="$2"

    cp "$source" "$target"
    cat >> "$target" <<'EOF'
-- Auto-lock screen after autologin for security
hl.on("hyprland.start", function() hl.exec_cmd("sleep 3 && fixture-lock") end)
-- End Auto-lock screen after autologin for security
EOF
}

append_expected_conf_block() {
    local source="$1"
    local target="$2"

    cp "$source" "$target"
    cat >> "$target" <<'EOF'
# Auto-lock screen after autologin for security
exec-once = sleep 3 && fixture-lock
# End Auto-lock screen after autologin for security
EOF
}

assert_same() {
    local expected="$1"
    local actual="$2"

    [[ -f "$actual" ]] || fail "missing file: $actual" || return 1
    cmp -s "$expected" "$actual" || fail "file differs: $actual" || return 1
}

assert_absent() {
    local target="$1"

    [[ ! -e "$target" ]] || fail "unexpected path exists: $target" || return 1
}

assert_marker_count() {
    local target="$1"
    local marker="$2"
    local expected="$3"
    local actual

    actual=$(grep -cF -- "$marker" "$target" || true)
    [[ "$actual" -eq "$expected" ]] || fail "expected $expected marker(s), found $actual in $target" || return 1
}

file_mode() {
    local target="$1"

    if stat -f '%Lp' "$target" >/dev/null 2>&1; then
        stat -f '%Lp' "$target"
    else
        stat -c '%a' "$target"
    fi
}

case_quattro_layout() {
    local home
    local expected_entry="$TEST_ROOT/case1-entry.expected"
    local original_autostart="$TEST_ROOT/case1-autostart.original"
    local expected_autostart="$TEST_ROOT/case1-autostart.expected"

    home=$(new_home case1)
    write_omarchy_entrypoint "$home/.config/hypr/hyprland.lua"
    write_autostart_original "$home/.config/hypr/autostart.lua"
    cp "$home/.config/hypr/hyprland.lua" "$expected_entry"
    cp "$home/.config/hypr/autostart.lua" "$original_autostart"
    append_expected_lua_helper_block "$original_autostart" "$expected_autostart"

    hypr_add_autolock "$home" "$TEST_OWNER" >/dev/null || return 1
    assert_same "$expected_entry" "$home/.config/hypr/hyprland.lua" || return 1
    assert_same "$expected_autostart" "$home/.config/hypr/autostart.lua" || return 1
    assert_absent "$home/.config/hypr/hyprland.conf"
}

case_both_formats() {
    local home
    local expected_entry="$TEST_ROOT/case2-entry.expected"
    local expected_conf="$TEST_ROOT/case2-conf.expected"
    local original_autostart="$TEST_ROOT/case2-autostart.original"
    local expected_autostart="$TEST_ROOT/case2-autostart.expected"

    home=$(new_home case2)
    write_omarchy_entrypoint "$home/.config/hypr/hyprland.lua"
    write_autostart_original "$home/.config/hypr/autostart.lua"
    printf 'source = ~/.config/hypr/legacy.conf\n' > "$home/.config/hypr/hyprland.conf"
    cp "$home/.config/hypr/hyprland.lua" "$expected_entry"
    cp "$home/.config/hypr/hyprland.conf" "$expected_conf"
    cp "$home/.config/hypr/autostart.lua" "$original_autostart"
    append_expected_lua_helper_block "$original_autostart" "$expected_autostart"

    hypr_add_autolock "$home" "$TEST_OWNER" >/dev/null || return 1
    assert_same "$expected_entry" "$home/.config/hypr/hyprland.lua" || return 1
    assert_same "$expected_conf" "$home/.config/hypr/hyprland.conf" || return 1
    assert_same "$expected_autostart" "$home/.config/hypr/autostart.lua"
}

case_conf_only() {
    local home
    local original="$TEST_ROOT/case3-conf.original"
    local expected="$TEST_ROOT/case3-conf.expected"

    home=$(new_home case3)
    printf 'source = ~/.config/hypr/base.conf\n' > "$home/.config/hypr/hyprland.conf"
    cp "$home/.config/hypr/hyprland.conf" "$original"
    append_expected_conf_block "$original" "$expected"

    hypr_add_autolock "$home" "$TEST_OWNER" >/dev/null || return 1
    assert_same "$expected" "$home/.config/hypr/hyprland.conf" || return 1
    assert_absent "$home/.config/hypr/hyprland.lua"
}

case_no_config() {
    local home

    home=$(new_home case4)
    if hypr_add_autolock "$home" "$TEST_OWNER" >/dev/null 2>&1; then
        fail "helper succeeded without a Hyprland config"
        return 1
    fi
    [[ -z "$(find "$home/.config/hypr" -mindepth 1 -print -quit)" ]] || fail "helper created files without a Hyprland config"
}

case_custom_lua() {
    local home
    local original="$TEST_ROOT/case5-lua.original"
    local expected="$TEST_ROOT/case5-lua.expected"

    home=$(new_home case5)
    printf 'hl.on("hyprland.start", function() print("custom") end)\n' > "$home/.config/hypr/hyprland.lua"
    cp "$home/.config/hypr/hyprland.lua" "$original"
    append_expected_lua_raw_block "$original" "$expected"

    hypr_add_autolock "$home" "$TEST_OWNER" >/dev/null || return 1
    assert_same "$expected" "$home/.config/hypr/hyprland.lua" || return 1
    grep -qF 'hl.on("hyprland.start", function() hl.exec_cmd("sleep 3 && fixture-lock") end)' "$home/.config/hypr/hyprland.lua" || fail "raw hl.on form was not used"
}

case_idempotency() {
    local home_quattro
    local home_conf
    local home_custom

    home_quattro=$(new_home case6-quattro)
    write_omarchy_entrypoint "$home_quattro/.config/hypr/hyprland.lua"
    write_autostart_original "$home_quattro/.config/hypr/autostart.lua"
    hypr_add_autolock "$home_quattro" "$TEST_OWNER" >/dev/null || return 1
    hypr_add_autolock "$home_quattro" "$TEST_OWNER" >/dev/null || return 1
    assert_marker_count "$home_quattro/.config/hypr/autostart.lua" "$HYPR_AUTOLOCK_LUA_MARKER" 1 || return 1

    home_conf=$(new_home case6-conf)
    printf 'monitor = preferred,auto,1\n' > "$home_conf/.config/hypr/hyprland.conf"
    hypr_add_autolock "$home_conf" "$TEST_OWNER" >/dev/null || return 1
    hypr_add_autolock "$home_conf" "$TEST_OWNER" >/dev/null || return 1
    assert_marker_count "$home_conf/.config/hypr/hyprland.conf" "$HYPR_AUTOLOCK_CONF_MARKER" 1 || return 1

    home_custom=$(new_home case6-custom)
    printf 'print("custom")\n' > "$home_custom/.config/hypr/hyprland.lua"
    hypr_add_autolock "$home_custom" "$TEST_OWNER" >/dev/null || return 1
    hypr_add_autolock "$home_custom" "$TEST_OWNER" >/dev/null || return 1
    assert_marker_count "$home_custom/.config/hypr/hyprland.lua" "$HYPR_AUTOLOCK_LUA_MARKER" 1
}

case_removal() {
    local home_quattro
    local home_conf
    local home_custom
    local home_legacy
    local expected_entry="$TEST_ROOT/case7-entry.expected"
    local expected_autostart="$TEST_ROOT/case7-autostart.expected"
    local expected_conf="$TEST_ROOT/case7-conf.expected"
    local expected_custom="$TEST_ROOT/case7-custom.expected"

    home_quattro=$(new_home case7-quattro)
    write_omarchy_entrypoint "$home_quattro/.config/hypr/hyprland.lua"
    write_autostart_original "$home_quattro/.config/hypr/autostart.lua"
    cp "$home_quattro/.config/hypr/hyprland.lua" "$expected_entry"
    cp "$home_quattro/.config/hypr/autostart.lua" "$expected_autostart"
    hypr_add_autolock "$home_quattro" "$TEST_OWNER" >/dev/null || return 1
    hypr_remove_autolock "$home_quattro" "$TEST_OWNER" >/dev/null || return 1
    assert_same "$expected_entry" "$home_quattro/.config/hypr/hyprland.lua" || return 1
    assert_same "$expected_autostart" "$home_quattro/.config/hypr/autostart.lua" || return 1

    home_conf=$(new_home case7-conf)
    printf 'input { kb_layout = us }\n' > "$home_conf/.config/hypr/hyprland.conf"
    cp "$home_conf/.config/hypr/hyprland.conf" "$expected_conf"
    hypr_add_autolock "$home_conf" "$TEST_OWNER" >/dev/null || return 1
    hypr_remove_autolock "$home_conf" "$TEST_OWNER" >/dev/null || return 1
    assert_same "$expected_conf" "$home_conf/.config/hypr/hyprland.conf" || return 1

    home_custom=$(new_home case7-custom)
    printf 'print("custom")\n' > "$home_custom/.config/hypr/hyprland.lua"
    cp "$home_custom/.config/hypr/hyprland.lua" "$expected_custom"
    hypr_add_autolock "$home_custom" "$TEST_OWNER" >/dev/null || return 1
    hypr_remove_autolock "$home_custom" "$TEST_OWNER" >/dev/null || return 1
    assert_same "$expected_custom" "$home_custom/.config/hypr/hyprland.lua" || return 1

    home_legacy=$(new_home case7-legacy)
    printf 'monitor = preferred,auto,1\nexec-once = sleep 3 && hyprlock\nbind = SUPER, Q, exec, kitty\n' > "$home_legacy/.config/hypr/hyprland.conf"
    hypr_remove_autolock "$home_legacy" "$TEST_OWNER" >/dev/null || return 1
    if grep -q 'exec-once.*hyprlock' "$home_legacy/.config/hypr/hyprland.conf"; then
        fail "legacy unmarked hyprlock line survived removal"
        return 1
    fi
    grep -qF 'bind = SUPER, Q, exec, kitty' "$home_legacy/.config/hypr/hyprland.conf" || fail "legacy cleanup removed unrelated config"
}

case_stub_repair() {
    local home
    local original_conf="$TEST_ROOT/case8-conf.original"
    local expected_conf="$TEST_ROOT/case8-conf.expected"

    home=$(new_home case8)
    cat > "$home/.config/hypr/hyprland.lua" <<'EOF'
-- Auto-lock screen after autologin for security
hl.on("hyprland.start", function() hl.exec_cmd("sleep 3 && hyprlock") end)
-- End Auto-lock screen after autologin for security
EOF
    printf 'broken backup\n' > "$home/.config/hypr/hyprland.lua.backup"
    printf 'source = ~/.config/hypr/real.conf\n' > "$home/.config/hypr/hyprland.conf"
    cp "$home/.config/hypr/hyprland.conf" "$original_conf"
    append_expected_conf_block "$original_conf" "$expected_conf"

    hypr_add_autolock "$home" "$TEST_OWNER" >/dev/null || return 1
    assert_absent "$home/.config/hypr/hyprland.lua" || return 1
    assert_absent "$home/.config/hypr/hyprland.lua.backup" || return 1
    assert_same "$expected_conf" "$home/.config/hypr/hyprland.conf"
}

case_permissions() {
    local home_quattro
    local home_conf
    local home_custom

    home_quattro=$(new_home case9-quattro)
    write_omarchy_entrypoint "$home_quattro/.config/hypr/hyprland.lua"
    hypr_add_autolock "$home_quattro" "$TEST_OWNER" >/dev/null || return 1
    [[ "$(file_mode "$home_quattro/.config/hypr/autostart.lua")" == 644 ]] || fail "created autostart.lua is not mode 0644" || return 1

    home_conf=$(new_home case9-conf)
    printf 'monitor = preferred,auto,1\n' > "$home_conf/.config/hypr/hyprland.conf"
    chmod 0600 "$home_conf/.config/hypr/hyprland.conf"
    hypr_add_autolock "$home_conf" "$TEST_OWNER" >/dev/null || return 1
    [[ "$(file_mode "$home_conf/.config/hypr/hyprland.conf")" == 644 ]] || fail "written hyprland.conf is not mode 0644" || return 1

    home_custom=$(new_home case9-custom)
    printf 'print("custom")\n' > "$home_custom/.config/hypr/hyprland.lua"
    chmod 0600 "$home_custom/.config/hypr/hyprland.lua"
    hypr_add_autolock "$home_custom" "$TEST_OWNER" >/dev/null || return 1
    [[ "$(file_mode "$home_custom/.config/hypr/hyprland.lua")" == 644 ]] || fail "written hyprland.lua is not mode 0644"
}

run_case() {
    local number="$1"
    local description="$2"
    local function_name="$3"

    if "$function_name"; then
        echo "PASS $number - $description"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL $number - $description"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

run_case 1 "Omarchy quattro writes only autostart.lua" case_quattro_layout
run_case 2 "Lua wins when both config formats exist" case_both_formats
run_case 3 "conf-only layout never creates hyprland.lua" case_conf_only
run_case 4 "missing config returns non-zero and creates nothing" case_no_config
run_case 5 "custom Lua uses the raw Hyprland API" case_custom_lua
run_case 6 "add is idempotent in all supported layouts" case_idempotency
run_case 7 "remove restores original config bytes" case_removal
run_case 8 "broken hyprland.lua stub is repaired" case_stub_repair
run_case 9 "all written files use mode 0644" case_permissions

echo "$PASS_COUNT passed, $FAIL_COUNT failed"
[[ "$FAIL_COUNT" -eq 0 ]]
