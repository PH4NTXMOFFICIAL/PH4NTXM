#!/bin/sh
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin

[ "$(id -u)" -eq 0 ] || exit 1
[ "$#" -eq 0 ] || exit 2

. /usr/lib/ph4ntxm/ph4ntxm-usb-nuke-state.sh
USB_NUKE_TOKEN=

restore_arm() {
    usb_nuke_unlock
    [ -n "$USB_NUKE_TOKEN" ] || return 0
    usb_nuke_restore "$USB_NUKE_TOKEN" \
        || printf 'PH4NTXM: USB Nuke arm restoration failed.\n' >&2
}

trap restore_arm EXIT
trap 'exit 1' HUP INT TERM
usb_nuke_lock || exit 1
if [ ! -e "$USB_NUKE_ARMED_FILE" ] && [ ! -L "$USB_NUKE_ARMED_FILE" ]; then
    usb_nuke_unlock
    exit 0
fi
usb_nuke_read_token "$USB_NUKE_ARMED_FILE" || exit 1
usb_nuke_new_token
USB_NUKE_TOKEN=$USB_NUKE_NEW_TOKEN
usb_nuke_write_arm "$USB_NUKE_TOKEN"
mv -f -- "$USB_NUKE_ARMED_FILE" "$USB_NUKE_TRIGGER_FILE"
if /usr/bin/timeout -k 1 5 /bin/systemctl --no-block start \
    "ph4ntxm-usb-nuke-dispatch@$USB_NUKE_TOKEN.service" 9>&-; then
    trap - EXIT HUP INT TERM
    usb_nuke_unlock
else
    exit 1
fi
