#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

STATE_DIR=/run/ph4ntxm
MODE_FILE=$STATE_DIR/mode
READY_FILE=$STATE_DIR/tor-browser-verified
EMPTY_DIR=$STATE_DIR/browser-mask-empty
TOR_DIR=/opt/ph4ntxm/tor-browser
FIREFOX_DIR=/usr/lib/firefox-esr
METADATA_DIR=/usr/lib/ph4ntxm/browser-mode
MANIFEST=$METADATA_DIR/tor-browser.sha256
SYSTEM_DESKTOP=/usr/share/applications/firefox-esr.desktop
SKEL_DESKTOP=/etc/skel/.config/panel/launcher-9/firefox-esr.desktop

protected_file() {
    local path=$1 owner mode
    [[ -f "$path" && ! -L "$path" && -r "$path" ]] || return 1
    owner=$(stat -c '%u' "$path") || return 1
    mode=$(stat -c '%a' "$path") || return 1
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (((8#$mode & 0022) == 0))
}

unmask_path() {
    local target=$1
    if mountpoint -q "$target"; then
        umount -- "$target"
    fi
    ! mountpoint -q "$target"
}

mask_path() {
    local target=$1 options
    [[ -d "$target" && ! -L "$target" ]]
    mount --bind "$EMPTY_DIR" "$target"
    mount -o remount,bind,ro,nosuid,nodev,noexec "$target"
    options=$(findmnt -rn -o OPTIONS --mountpoint "$target")
    [[ ",$options," == *,ro,* ]]
    [[ ",$options," == *,nosuid,* ]]
    [[ ",$options," == *,nodev,* ]]
    [[ ",$options," == *,noexec,* ]]
}

install_desktop() {
    local source=$1 target=$2 target_dir tmp
    protected_file "$source"
    target_dir=$(dirname "$target")
    [[ -d "$target_dir" && ! -L "$target_dir" ]]
    tmp=$(mktemp "$target_dir/.ph4ntxm-browser.XXXXXX")
    install -o root -g root -m 0644 "$source" "$tmp"
    mv -f "$tmp" "$target"
}

verify_tor_browser() (
    local current_manifest= expected_manifest invalid_entry
    trap 'if [[ -n "$current_manifest" ]]; then rm -f -- "$current_manifest"; fi' EXIT
    protected_file "$MANIFEST" || return 1
    protected_file "$METADATA_DIR/tor-browser.version" || return 1
    [[ -d "$TOR_DIR" && ! -L "$TOR_DIR" ]] || return 1
    [[ -x "$TOR_DIR/Browser/start-tor-browser" ]] || return 1
    [[ -x "$TOR_DIR/Browser/firefox" ]] || return 1
    [[ -x "$TOR_DIR/Browser/firefox.real" ]] || return 1
    [[ -f "$TOR_DIR/Browser/is-packaged-app" && ! -L "$TOR_DIR/Browser/is-packaged-app" ]] || return 1
    [[ -x "$TOR_DIR/Browser/TorBrowser/Tor/tor" ]] || return 1
    [[ -f "$TOR_DIR/Browser/browser/chrome/icons/default/default128.png" ]] || return 1
    invalid_entry=$(find "$TOR_DIR" \( ! -user root -o -type l -o -perm /0022 -o -perm /7000 \
        -o \( ! -type f ! -type d \) -o \( -type d ! -perm 0755 \) \
        -o \( -type f ! \( -perm 0644 -o -perm 0755 \) \) \) -printf x -quit) || return 1
    [[ -z "$invalid_entry" ]] || return 1
    current_manifest=$(mktemp "$STATE_DIR/.tor-browser-manifest.XXXXXX") || return 1
    (
        cd "${TOR_DIR%/*}" || exit 1
        find "${TOR_DIR##*/}" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
    ) >"$current_manifest" || return 1
    cmp -s "$MANIFEST" "$current_manifest" || return 1
    rm -f -- "$current_manifest" || return 1
    current_manifest=
    expected_manifest=$(sha256sum "$MANIFEST") || return 1
    expected_manifest=${expected_manifest%% *}
    [[ "$expected_manifest" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$expected_manifest"
)

fail_closed() {
    rm -f "$READY_FILE"
    for target in "$TOR_DIR" "$FIREFOX_DIR"; do
        if [[ -d "$target" && ! -L "$target" ]] && ! mountpoint -q "$target"; then
            mask_path "$target" >/dev/null 2>&1 || true
        fi
    done
}

[[ "$(id -u)" == 0 ]]
install -d -o root -g root -m 0755 "$STATE_DIR" "$EMPTY_DIR"
rm -f "$READY_FILE"
trap fail_closed ERR
trap 'fail_closed; exit 1' INT TERM HUP
unmask_path "$TOR_DIR"
unmask_path "$FIREFOX_DIR"
mask_path "$TOR_DIR"
mask_path "$FIREFOX_DIR"

protected_file "$MODE_FILE"
MODE=$(tr -d '\n' <"$MODE_FILE")
case "$MODE" in
    linux | windows | lonewolf) ;;
    *) false ;;
esac

if [[ "$MODE" == lonewolf ]]; then
    unmask_path "$TOR_DIR"
    if ! MANIFEST_HASH=$(verify_tor_browser); then
        fail_closed
        exit 1
    fi
    install_desktop "$METADATA_DIR/tor-system.desktop" "$SYSTEM_DESKTOP"
    install_desktop "$METADATA_DIR/tor-panel.desktop" "$SKEL_DESKTOP"
    READY_TMP=$(mktemp "$STATE_DIR/.tor-browser-verified.XXXXXX")
    printf 'MODE=lonewolf\nMANIFEST_SHA256=%s\nUPTIME_SECONDS=%s\n' "$MANIFEST_HASH" "$(cut -d. -f1 /proc/uptime)" >"$READY_TMP"
    chown root:root "$READY_TMP"
    chmod 0644 "$READY_TMP"
    mv -f "$READY_TMP" "$READY_FILE"
else
    unmask_path "$FIREFOX_DIR"
    install_desktop "$METADATA_DIR/firefox-system.desktop" "$SYSTEM_DESKTOP"
    install_desktop "$METADATA_DIR/firefox-panel.desktop" "$SKEL_DESKTOP"
fi
trap - ERR INT TERM HUP
