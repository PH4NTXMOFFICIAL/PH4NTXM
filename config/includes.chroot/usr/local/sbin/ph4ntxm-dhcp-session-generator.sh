#!/usr/bin/env bash
set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"

if [[ "$MODE" == "lonewolf" ]]; then
    exit 0
fi

SESSION_FILE=/run/ph4ntxm/session_dhcp
NM_CONF_DIR=/run/NetworkManager/conf.d
NM_CONF_FILE=$NM_CONF_DIR/90-ph4ntxm-session.conf
DHCLIENT_CONF=/etc/dhcp/dhclient.conf

HOSTNAME="$(cat /etc/hostname 2>/dev/null || echo unknown)"

case "$MODE" in
    linux)
        VENDOR="dhclient"
        TIMEOUT=60
        DUID="ll"
        REQUESTS="subnet-mask, broadcast-address, routers, domain-name, domain-name-servers, host-name"
        ;;
    windows)
        VENDOR="MSFT 5.0"
        TIMEOUT=45
        DUID="stable-uuid"
        REQUESTS="subnet-mask, routers, domain-name-servers, host-name, domain-name, broadcast-address"
        ;;
    *)
        exit 1
        ;;
esac

install -d -o root -g root -m 0755 "$NM_CONF_DIR" /etc/dhcp
session_tmp=$(mktemp /run/ph4ntxm/.session-dhcp.XXXXXX)
nm_tmp=$(mktemp "$NM_CONF_DIR/.ph4ntxm-session.XXXXXX")
dhclient_tmp=$(mktemp /etc/dhcp/.ph4ntxm-dhclient.XXXXXX)

printf 'MODE=%q\nVENDOR=%q\nHOSTNAME=%q\nTIMEOUT=%q\nDUID=%q\n' \
    "$MODE" "$VENDOR" "$HOSTNAME" "$TIMEOUT" "$DUID" > "$session_tmp"

cat > "$nm_tmp" <<EOF
[connection-ph4ntxm-session]
ipv4.dhcp-client-id=mac
ipv4.dhcp-vendor-class-identifier=$VENDOR
ipv4.dhcp-send-hostname=true
ipv4.dhcp-timeout=$TIMEOUT
ipv6.dhcp-duid=$DUID
ipv6.dhcp-send-hostname=true
ethernet.cloned-mac-address=preserve
wifi.cloned-mac-address=preserve
ipv6.ip6-privacy=2
EOF

cat > "$dhclient_tmp" <<EOF
send host-name "$HOSTNAME";
send vendor-class-identifier "$VENDOR";
request $REQUESTS;
timeout $TIMEOUT;
EOF
chmod 0600 "$session_tmp"
chmod 0644 "$nm_tmp" "$dhclient_tmp"
mv -f "$session_tmp" "$SESSION_FILE"
mv -f "$nm_tmp" "$NM_CONF_FILE"
mv -f "$dhclient_tmp" "$DHCLIENT_CONF"

exit 0
