#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
STATE_DIR=/run/ph4ntxm

[ "$(id -u)" -eq 0 ] || exit 1
[ "$#" -eq 1 ] || exit 2

iface=$1
case "$iface" in
    ""|lo|*/*|*..*|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-]*) exit 2 ;;
esac

device_path="/sys/class/net/$iface"
[ -d "$device_path/device" ] || exit 0

protected=0
trap 'if [ "$protected" -ne 1 ]; then ip link set dev "$iface" down >/dev/null 2>&1 || true; fi' EXIT
trap 'exit 1' HUP INT TERM
[ "$(cat /sys/kernel/kexec_crash_loaded 2>/dev/null || echo 0)" = 1 ] || exit 1
[ "$(cat /proc/sys/kernel/kexec_load_disabled 2>/dev/null || echo 0)" = 1 ] || exit 1

mode=$(tr -d '\n' < "$STATE_DIR/mode" 2>/dev/null || true)
case "$mode" in
    linux|windows)
        seed_file=$STATE_DIR/persona_seed
        boot_mac_file=$STATE_DIR/boot_mac
        [ -s "$seed_file" ] && [ -f "$boot_mac_file" ] || exit 1
        seed=$(cat "$seed_file")
        prefix=$(cut -d: -f1-3 "$boot_mac_file")
        m4=$(printf '%s%s' "$seed" "m4-$iface" | sha256sum | cut -c7-8)
        m5=$(printf '%s%s' "$seed" "m5-$iface" | sha256sum | cut -c7-8)
        m6=$(printf '%s%s' "$seed" "m6-$iface" | sha256sum | cut -c7-8)
        target_mac="$prefix:$m4:$m5:$m6"
        ;;
    lonewolf)
        seed_file=$STATE_DIR/lonewolf_seed
        mac_dir=$STATE_DIR/boot_mac
        [ -s "$seed_file" ] || exit 1
        install -d -o root -g root -m 0700 "$mac_dir"
        mac_file=$mac_dir/$iface
        if [ ! -s "$mac_file" ]; then
            hex=$(printf '%s%s' "$(cat "$seed_file")" "mac-$iface" \
                | sha256sum | cut -c1-10)
            target_mac=$(printf '02:%s:%s:%s:%s:%s' \
                "$(printf '%s' "$hex" | cut -c1-2)" \
                "$(printf '%s' "$hex" | cut -c3-4)" \
                "$(printf '%s' "$hex" | cut -c5-6)" \
                "$(printf '%s' "$hex" | cut -c7-8)" \
                "$(printf '%s' "$hex" | cut -c9-10)")
            mac_tmp=$(mktemp "$mac_dir/.mac.XXXXXX")
            printf '%s\n' "$target_mac" > "$mac_tmp"
            chmod 0600 "$mac_tmp"
            mv -f "$mac_tmp" "$mac_file"
        else
            target_mac=$(tr -d '\n' < "$mac_file")
        fi
        ;;
    *)
        exit 1
        ;;
esac

case "$target_mac" in
    [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]) ;;
    *) exit 1 ;;
esac

current_mac=$(tr -d '\n' < "$device_path/address" 2>/dev/null || true)
if [ "$current_mac" != "$target_mac" ]; then
    ip link set dev "$iface" down >/dev/null 2>&1
    ip link set dev "$iface" address "$target_mac"
fi
current_mac=$(tr -d '\n' < "$device_path/address" 2>/dev/null || true)
[ "$current_mac" = "$target_mac" ] || exit 1
case "$mode" in
    linux|windows)
        /usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh enforce "$iface" >/dev/null
        /usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh verify "$iface" >/dev/null
        ;;
esac
protected=1
printf '%s\n' protected
