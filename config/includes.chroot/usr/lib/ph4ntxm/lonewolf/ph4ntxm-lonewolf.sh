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

systemctl stop unbound.service 2>/dev/null || true
systemctl --runtime mask unbound.service 2>/dev/null || true

/usr/sbin/sysctl -w net.ipv6.conf.all.disable_ipv6=1
/usr/sbin/sysctl -w net.ipv6.conf.default.disable_ipv6=1

for iface in /proc/sys/net/ipv6/conf/*; do
    [[ -f "$iface/disable_ipv6" ]] || continue
    printf '1\n' > "$iface/disable_ipv6"
    [[ "$(cat "$iface/disable_ipv6")" == "1" ]]
done

RULES=/usr/lib/ph4ntxm/lonewolf/lonewolf.nft
MANIFEST=/usr/lib/ph4ntxm/lonewolf/lonewolf.nft.sha256
[[ -f "$RULES" && -f "$MANIFEST" && ! -L "$RULES" && ! -L "$MANIFEST" ]]
EXPECTED_HASH=$(tr -d '\n' < "$MANIFEST")
[[ "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]]
[[ "$(/usr/bin/sha256sum "$RULES" | awk '{print $1}')" == "$EXPECTED_HASH" ]]

resolv_tmp=$(mktemp /etc/.resolv.conf.XXXXXX)
printf "nameserver 127.0.0.1\noptions edns0\n" > "$resolv_tmp"
chmod 0644 "$resolv_tmp"
mv -f "$resolv_tmp" /etc/resolv.conf

/usr/sbin/nft -c -f "$RULES"
/usr/sbin/nft -f "$RULES"
/usr/sbin/conntrack -F >/dev/null 2>&1 || true
