#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' <"$MODE_FILE")"

if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

STATE_DIR="/run/ph4ntxm"
SESSION_FILE="$STATE_DIR/session_dhcp"
NM_CONF_DIR=/run/NetworkManager/conf.d
NM_CONF_FILE=$NM_CONF_DIR/90-ph4ntxm-session.conf

TIMEOUT="60"
TOR="enabled"

install -d -o root -g root -m 0755 "$NM_CONF_DIR"
session_tmp=$(mktemp "$STATE_DIR/.session-dhcp.XXXXXX")
nm_tmp=$(mktemp "$NM_CONF_DIR/.ph4ntxm-session.XXXXXX")

printf 'MODE=%q\nTIMEOUT=%q\nTOR=%q\n' "$MODE" "$TIMEOUT" "$TOR" >"$session_tmp"

cat >"$nm_tmp" <<EOF
[connection-ph4ntxm-session]
ipv4.dhcp-client-id=mac
ipv4.dhcp-send-hostname=false
ipv4.dhcp-timeout=$TIMEOUT
ipv6.dhcp-send-hostname=false
ethernet.cloned-mac-address=preserve
wifi.cloned-mac-address=preserve
EOF

chmod 0600 "$session_tmp"
chmod 0644 "$nm_tmp"
mv -f "$session_tmp" "$SESSION_FILE"
mv -f "$nm_tmp" "$NM_CONF_FILE"

exit 0
