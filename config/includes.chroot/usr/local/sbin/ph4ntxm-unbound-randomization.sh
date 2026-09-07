#!/usr/bin/env bash
set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"

case "$MODE" in
    linux|windows) ;;
    lonewolf) exit 0 ;;
    *) exit 1 ;;
esac

UNBOUND_CONF="/etc/unbound/unbound.conf.d/ph4ntxm.conf"
mkdir -p /etc/unbound/unbound.conf.d

resolv_tmp=$(mktemp /etc/.resolv.conf.XXXXXX)
echo "nameserver 127.0.0.1" > "$resolv_tmp"
chmod 0644 "$resolv_tmp"
mv -f "$resolv_tmp" /etc/resolv.conf

case "$MODE" in
    windows)
        PROVIDERS=(
        "1.1.1.1@853#one.one.one.one"
        "1.0.0.1@853#one.one.one.one"
        "8.8.8.8@853#dns.google"
        "8.8.4.4@853#dns.google"
        )
        ;;
    linux)
        PROVIDERS=(
        "9.9.9.10@853#dns10.quad9.net"
        "149.112.112.10@853#dns10.quad9.net"
        "194.242.2.2@853#dns.mullvad.net"
        )
        ;;
esac

unbound_tmp=$(mktemp /etc/unbound/unbound.conf.d/.ph4ntxm.XXXXXX)
cat > "$unbound_tmp" <<EOF
server:
    interface: 127.0.0.1
    access-control: 127.0.0.0/8 allow

    msg-cache-size: 64m
    rrset-cache-size: 128m
    num-threads: 2

    cache-min-ttl: 600
    cache-max-ttl: 14400

    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    harden-dnssec-stripped: yes
    harden-glue: yes
    use-caps-for-id: yes
    
    prefetch: yes
    prefetch-key: yes

    edns-tcp-keepalive: yes
    infra-keep-probing: yes

    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt
    
    do-ip4: yes
    do-ip6: no
    prefer-ip6: no
    infra-host-ttl: 60
    
    tcp-upstream: yes
    edns-buffer-size: 1232

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-first: no
EOF

for provider in "${PROVIDERS[@]}"; do
    echo "    forward-addr: $provider" >> "$unbound_tmp"
done

chmod 0644 "$unbound_tmp"
mv -f "$unbound_tmp" "$UNBOUND_CONF"

if [[ -n "${NOTIFY_SOCKET:-}" ]]; then
    systemd-notify --ready --status="Encrypted DNS profile active in $MODE mode"
fi

while true; do
    sleep 30
    if host -W 2 localhost 127.0.0.1 >/dev/null 2>&1; then
        continue
    fi
    if ip route | grep -q '^default '; then
        logger -t ph4ntxm-unbound "Unbound not responding, restarting"
        systemctl restart unbound.service >/dev/null 2>&1 || true
        sleep 10
    fi
done
