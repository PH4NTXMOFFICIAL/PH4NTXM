#!/usr/bin/env bash
set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"

if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

STATE_DIR="/run/ph4ntxm"
SESSION_FILE="$STATE_DIR/session_dhcp"
NM_CONF_DIR=/run/NetworkManager/conf.d
NM_CONF_FILE=$NM_CONF_DIR/90-ph4ntxm-session.conf
DHCLIENT_CONF=/etc/dhcp/dhclient.conf

TIMEOUT="60"
PRL="subnet-mask, routers, domain-name-servers, domain-name, broadcast-address"
TOR="enabled"

install -d -o root -g root -m 0755 "$NM_CONF_DIR" /etc/dhcp
session_tmp=$(mktemp "$STATE_DIR/.session-dhcp.XXXXXX")
nm_tmp=$(mktemp "$NM_CONF_DIR/.ph4ntxm-session.XXXXXX")
dhclient_tmp=$(mktemp /etc/dhcp/.ph4ntxm-dhclient.XXXXXX)

printf 'MODE=%q\nTIMEOUT=%q\nPRL=%q\nTOR=%q\n' "$MODE" "$TIMEOUT" "$PRL" "$TOR" > "$session_tmp"

cat > "$nm_tmp" <<EOF
[connection-ph4ntxm-session]
ipv4.dhcp-client-id=mac
ipv4.dhcp-send-hostname=false
ipv4.dhcp-timeout=$TIMEOUT
ipv6.method=disabled
ipv6.dhcp-send-hostname=false
ethernet.cloned-mac-address=preserve
wifi.cloned-mac-address=preserve
EOF

cat > "$dhclient_tmp" <<EOF
request $PRL;
timeout $TIMEOUT;
EOF
chmod 0600 "$session_tmp"
chmod 0644 "$nm_tmp" "$dhclient_tmp"
mv -f "$session_tmp" "$SESSION_FILE"
mv -f "$nm_tmp" "$NM_CONF_FILE"
mv -f "$dhclient_tmp" "$DHCLIENT_CONF"

exit 0
