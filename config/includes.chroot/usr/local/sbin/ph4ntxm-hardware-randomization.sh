#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail
safe() { "$@" >/dev/null 2>&1 || true; }

STATE_DIR="/run/ph4ntxm"

MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' <"$MODE_FILE")"
case "$MODE" in
    linux | windows) ;;
    lonewolf) exit 0 ;;
    *) exit 1 ;;
esac

PERSONA_SEED_FILE="$STATE_DIR/persona_seed"
HARDWARE_PROFILE_FILE="$STATE_DIR/hardware_profile"
[[ -f "$PERSONA_SEED_FILE" ]] || exit 1
[[ -f "$HARDWARE_PROFILE_FILE" ]] || exit 1

SEED=$(cat "$PERSONA_SEED_FILE")
source "$HARDWARE_PROFILE_FILE"

BOOT_JITTER_FILE="$STATE_DIR/boot_jitter"

if [[ ! -s "$BOOT_JITTER_FILE" ]]; then
    tmp=$(mktemp "$STATE_DIR/.boot-jitter.XXXXXX")
    chmod 0600 "$tmp"
    hexdump -n 8 -e '8/1 "%02x"' /dev/urandom 2>/dev/null >"$tmp" || printf '%s\n' deadbeef >"$tmp"
    mv -f "$tmp" "$BOOT_JITTER_FILE"
fi

BOOT_JITTER=$(cat "$BOOT_JITTER_FILE")

get_id() {
    local salt="$1" len="$2" layer="${3:-session}"
    case "$layer" in
        stable) echo -n "$SEED$salt" | sha256sum | cut -c1-"$len" ;;
        *) echo -n "$SEED$salt$BOOT_JITTER" | sha256sum | cut -c1-"$len" ;;
    esac | tr '[:lower:]' '[:upper:]'
}

UUID_RAW=$(get_id "uuid-base" 32 "session")
VAR_CHARS="89AB"
VAR_PICK=${VAR_CHARS:$((16#$(get_id "u-var" 1 "session") % 4)):1}
UUID="${UUID_RAW:0:8}-${UUID_RAW:8:4}-4${UUID_RAW:13:3}-${VAR_PICK}${UUID_RAW:17:3}-${UUID_RAW:20:12}"
[[ -n "${PROFILE_ID:-}" ]] || exit 1

case "$VENDOR" in
    "lenovo") SERIAL="PF$(get_id "s1" 8 "session")" ;;
    "dell") SERIAL="$(get_id "s1" 7 "session")" ;;
    "hp") SERIAL="5CG$(get_id "s1" 8 "session")" ;;
    "asus") SERIAL="M$(get_id "s1" 11 "session")" ;;
    "acer") SERIAL="NX$(get_id "s1" 10 "session")" ;;
    "msi") SERIAL="9S6$(get_id "s1" 9 "session")" ;;
    "razer") SERIAL="BY$(get_id "s1" 10 "session")" ;;
    "fujitsu") SERIAL="DS$(get_id "s1" 10 "session")" ;;
    "toshiba") SERIAL="Z$(get_id "s1" 11 "session")" ;;
    "samsung") SERIAL="S$(get_id "s1" 11 "session")" ;;
    "apple") SERIAL="C02$(get_id "s1" 9 "session")" ;;
    "google") SERIAL="GGL$(get_id "s1" 9 "session")" ;;
    "microsoft") SERIAL="$(get_id "s1" 12 "session")" ;;
    "lg") SERIAL="S$(get_id "s1" 11 "session")" ;;
    "intel") SERIAL="G$(get_id "s1" 11 "session")" ;;
    "ibm") SERIAL="LV$(get_id "s1" 10 "session")" ;;
    "origin") SERIAL="OPC$(get_id "s1" 9 "session")" ;;
    *) SERIAL="$(get_id "s1" 12 "session")" ;;
esac

BOARD_SERIAL="MB-${SERIAL:0:10}"
DMI_DIR="$STATE_DIR/fake_dmi"
mkdir -p "$DMI_DIR"

modalias_token() {
    printf '%s' "$1" | tr -cd '[:alnum:].,_-'
}

MODALIAS="dmi:bvn$(modalias_token "$BIOS_VENDOR"):bvr$(modalias_token "$BIOS_VERSION"):bd$(modalias_token "$BIOS_DATE"):br$(modalias_token "$BIOS_RELEASE"):efr$(modalias_token "$EC_FIRMWARE_RELEASE"):svn$(modalias_token "$SYS_VENDOR"):pn$(modalias_token "$PRODUCT_NAME"):pvr$(modalias_token "$PRODUCT_VERSION"):rvn$(modalias_token "$BOARD_VENDOR"):rn$(modalias_token "$BOARD_NAME"):rvr$(modalias_token "$BOARD_VERSION"):cvn$(modalias_token "$CHASSIS_VENDOR"):ct$(modalias_token "$CHASSIS_TYPE"):cvr$(modalias_token "$CHASSIS_VERSION"):sku$(modalias_token "$PRODUCT_SKU"):"

declare -A DMI_VALS=(
    [product_name]="$PRODUCT_NAME"
    [product_serial]="$SERIAL"
    [product_uuid]="$UUID"
    [product_version]="$PRODUCT_VERSION"
    [product_family]="$PRODUCT_FAMILY"
    [product_sku]="$PRODUCT_SKU"

    [board_serial]="$BOARD_SERIAL"
    [board_name]="$BOARD_NAME"
    [board_vendor]="$BOARD_VENDOR"
    [board_version]="$BOARD_VERSION"
    [board_asset_tag]="$BOARD_ASSET_TAG"

    [bios_vendor]="$BIOS_VENDOR"
    [bios_version]="$BIOS_VERSION"
    [bios_date]="$BIOS_DATE"
    [bios_release]="$BIOS_RELEASE"
    [ec_firmware_release]="$EC_FIRMWARE_RELEASE"

    [sys_vendor]="$SYS_VENDOR"

    [chassis_serial]="$SERIAL"
    [chassis_vendor]="$CHASSIS_VENDOR"
    [chassis_type]="$CHASSIS_TYPE"
    [chassis_version]="$CHASSIS_VERSION"
    [chassis_asset_tag]="$CHASSIS_ASSET_TAG"
    [modalias]="$MODALIAS"
    [uevent]="MODALIAS=$MODALIAS"
)

for key in "${!DMI_VALS[@]}"; do
    echo -n "${DMI_VALS[$key]}" >"$DMI_DIR/$key"
    chmod 0444 "$DMI_DIR/$key"
done

mounted_targets=()
cleanup_partial_mounts() {
    local target
    for ((idx = ${#mounted_targets[@]} - 1; idx >= 0; idx--)); do
        target=${mounted_targets[$idx]}
        umount "$target" >/dev/null 2>&1 || true
    done
}
trap cleanup_partial_mounts ERR

for key in "${!DMI_VALS[@]}"; do
    target="/sys/class/dmi/id/$key"
    [[ -f "$target" ]] || continue
    umount "$target" >/dev/null 2>&1 || true
    mount --bind "$DMI_DIR/$key" "$target"
    mounted_targets+=("$target")
    mount -o remount,ro,bind "$target"
done

trap - ERR

exit 0
