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

if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

SEED_FILE="$STATE_DIR/lonewolf_seed"
JITTER_FILE="$STATE_DIR/boot_jitter"

[[ -s "$SEED_FILE" ]] || exit 1
SEED=$(tr -d '\n' <"$SEED_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1

if [[ -s "$JITTER_FILE" ]]; then
    BOOT_JITTER=$(tr -d '\n' <"$JITTER_FILE")
else
    BOOT_JITTER=$(hexdump -n 8 -e '8/1 "%02x"' /dev/urandom)
    jitter_tmp=$(mktemp "$STATE_DIR/.boot-jitter.XXXXXX")
    printf '%s\n' "$BOOT_JITTER" >"$jitter_tmp"
    chmod 0600 "$jitter_tmp"
    mv -f "$jitter_tmp" "$JITTER_FILE"
fi
[[ "$BOOT_JITTER" =~ ^[0-9a-f]{16}$ ]] || exit 1

get_id() {
    local salt="$1" len="$2"
    echo -n "$SEED$salt$BOOT_JITTER" | sha256sum | cut -c1-"$len" | tr '[:lower:]' '[:upper:]'
}

UUID_RAW=$(get_id "uuid-base" 32)
VAR_CHARS="89AB"
VAR_PICK=${VAR_CHARS:$((16#${UUID_RAW:0:1} % 4)):1}
UUID="${UUID_RAW:0:8}-${UUID_RAW:8:4}-4${UUID_RAW:13:3}-${VAR_PICK}${UUID_RAW:17:3}-${UUID_RAW:20:12}"

HARDWARE_PROFILE_FILE="$STATE_DIR/hardware_profile"
profile_tmp=$(mktemp "$STATE_DIR/.hardware-profile.XXXXXX")
if ! /usr/bin/python3 /usr/lib/ph4ntxm/hardware/persona.py select "$MODE" "$SEED" >"$profile_tmp"; then
    rm -f "$profile_tmp"
    exit 1
fi
chmod 0644 "$profile_tmp"
mv -f "$profile_tmp" "$HARDWARE_PROFILE_FILE"
source "$HARDWARE_PROFILE_FILE"

case "$VENDOR" in
    "lenovo") SERIAL="PF$(get_id "s1" 8)" ;;
    "dell") SERIAL="$(get_id "s1" 7)" ;;
    "hp") SERIAL="5CG$(get_id "s1" 8)" ;;
    "asus") SERIAL="M$(get_id "s1" 11)" ;;
    "acer") SERIAL="NX$(get_id "s1" 10)" ;;
    "msi") SERIAL="9S6$(get_id "s1" 9)" ;;
    "razer") SERIAL="BY$(get_id "s1" 10)" ;;
    "fujitsu") SERIAL="DS$(get_id "s1" 10)" ;;
    "toshiba") SERIAL="Z$(get_id "s1" 11)" ;;
    "samsung") SERIAL="S$(get_id "s1" 11)" ;;
    "apple") SERIAL="C02$(get_id "s1" 9)" ;;
    "google") SERIAL="GGL$(get_id "s1" 9)" ;;
    "microsoft") SERIAL="$(get_id "s1" 12)" ;;
    "lg") SERIAL="S$(get_id "s1" 11)" ;;
    "intel") SERIAL="G$(get_id "s1" 11)" ;;
    "ibm") SERIAL="LV$(get_id "s1" 10)" ;;
    "origin") SERIAL="OPC$(get_id "s1" 9)" ;;
    *) SERIAL="$(get_id "s1" 12)" ;;
esac

BOARD_SERIAL="MB-$(get_id "brd" 12)"
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
    [board_vendor]="$BOARD_VENDOR"
    [board_version]="$BOARD_VERSION"
    [board_asset_tag]="$BOARD_ASSET_TAG"
    [bios_vendor]="$BIOS_VENDOR"
    [bios_version]="$BIOS_VERSION"
    [bios_date]="$BIOS_DATE"
    [bios_release]="$BIOS_RELEASE"
    [ec_firmware_release]="$EC_FIRMWARE_RELEASE"
    [sys_vendor]="$SYS_VENDOR"
    [board_name]="$BOARD_NAME"
    [chassis_serial]="$SERIAL"
    [chassis_type]="$CHASSIS_TYPE"
    [chassis_vendor]="$CHASSIS_VENDOR"
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
