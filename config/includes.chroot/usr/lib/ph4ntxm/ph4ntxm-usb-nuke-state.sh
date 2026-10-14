# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

USB_NUKE_STATE_DIR=/run/ph4ntxm
USB_NUKE_ARMED_FILE=$USB_NUKE_STATE_DIR/usb-nuke-armed
USB_NUKE_TRIGGER_FILE=$USB_NUKE_STATE_DIR/usb-nuke-triggered
USB_NUKE_LOCKED=0

usb_nuke_token_valid() {
    [ "${#1}" -eq 32 ] || return 1
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
    esac
}

usb_nuke_protected_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    usb_nuke_mode=$(stat -c '%a' -- "$1") || return 1
    [ "$(stat -c '%u' -- "$1")" -eq 0 ] \
        && [ $((0$usb_nuke_mode & 0022)) -eq 0 ]
}

usb_nuke_protected_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    usb_nuke_mode=$(stat -c '%a' -- "$1") || return 1
    [ "$(stat -c '%u' -- "$1")" -eq 0 ] \
        && [ $((0$usb_nuke_mode & 0022)) -eq 0 ]
}

usb_nuke_lock() {
    [ "$USB_NUKE_LOCKED" -eq 0 ] || return 0
    usb_nuke_protected_directory /run || return 1
    usb_nuke_protected_directory "$USB_NUKE_STATE_DIR" || return 1
    if [ -e "$USB_NUKE_STATE_DIR/usb-nuke.lock" ] || [ -L "$USB_NUKE_STATE_DIR/usb-nuke.lock" ]; then
        usb_nuke_protected_file "$USB_NUKE_STATE_DIR/usb-nuke.lock" || return 1
    fi
    umask 077
    exec 9>>"$USB_NUKE_STATE_DIR/usb-nuke.lock" || return 1
    if ! flock -x -w 5 9; then
        exec 9>&-
        return 1
    fi
    USB_NUKE_LOCKED=1
}

usb_nuke_unlock() {
    [ "$USB_NUKE_LOCKED" -eq 1 ] || return 0
    exec 9>&-
    USB_NUKE_LOCKED=0
}

usb_nuke_new_token() {
    USB_NUKE_NEW_TOKEN=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || return 1
    usb_nuke_token_valid "$USB_NUKE_NEW_TOKEN"
}

usb_nuke_read_token() {
    usb_nuke_protected_file "$1" || return 1
    [ "$(stat -c '%s' -- "$1")" -eq 33 ] || return 1
    USB_NUKE_READ_TOKEN=$(cat -- "$1") || return 1
    usb_nuke_token_valid "$USB_NUKE_READ_TOKEN"
}

usb_nuke_write_arm() {
    usb_nuke_token_valid "$1" || return 1
    usb_nuke_tmp=$(mktemp "$USB_NUKE_STATE_DIR/usb-nuke-state.XXXXXX") || return 1
    if ! printf '%s\n' "$1" >"$usb_nuke_tmp" \
        || ! chmod 0644 "$usb_nuke_tmp" \
        || ! mv -f -- "$usb_nuke_tmp" "$USB_NUKE_ARMED_FILE"; then
        rm -f -- "$usb_nuke_tmp"
        return 1
    fi
}

usb_nuke_restore() {
    usb_nuke_token_valid "$1" || return 1
    usb_nuke_lock || return 1
    usb_nuke_restore_result=0
    if [ ! -e "$USB_NUKE_ARMED_FILE" ] && [ ! -L "$USB_NUKE_ARMED_FILE" ] \
        && { [ -e "$USB_NUKE_TRIGGER_FILE" ] || [ -L "$USB_NUKE_TRIGGER_FILE" ]; }; then
        if ! usb_nuke_read_token "$USB_NUKE_TRIGGER_FILE"; then
            usb_nuke_restore_result=1
        elif [ "$USB_NUKE_READ_TOKEN" = "$1" ]; then
            mv -f -- "$USB_NUKE_TRIGGER_FILE" "$USB_NUKE_ARMED_FILE" || usb_nuke_restore_result=1
        fi
    fi
    usb_nuke_unlock
    return "$usb_nuke_restore_result"
}
