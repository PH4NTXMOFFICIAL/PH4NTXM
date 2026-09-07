#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

child=0

cleanup() {
    if (( child > 0 )) && kill -0 "$child" 2>/dev/null; then
        kill "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    rm -f /run/ph4ntxm/tor-ready
}

trap cleanup EXIT INT TERM HUP

tcp_listener() {
    local port=$1
    /usr/bin/ss -H -ltn4 "sport = :$port" | /usr/bin/awk -v endpoint="127.0.0.1:$port" '$4 == endpoint {found=1} END {exit !found}'
}

udp_listener() {
    local port=$1
    /usr/bin/ss -H -lun4 "sport = :$port" | /usr/bin/awk -v endpoint="127.0.0.1:$port" '$4 == endpoint {found=1} END {exit !found}'
}

listeners_ready() {
    tcp_listener 53 && udp_listener 53 && udp_listener 5353 && tcp_listener 9040 && tcp_listener 9050
}

publish_ready() {
    local ready_tmp
    ready_tmp=$(mktemp /run/ph4ntxm/.tor-ready.XXXXXX)
    printf 'STATUS=ready\nBOOTSTRAP=100\nUPTIME_SECONDS=%s\n' "$(cut -d. -f1 /proc/uptime)" > "$ready_tmp"
    chown root:root "$ready_tmp"
    chmod 0644 "$ready_tmp"
    mv -f "$ready_tmp" /run/ph4ntxm/tor-ready
}

/usr/sbin/dnsmasq --no-daemon --log-facility=- --conf-file=/usr/lib/ph4ntxm/lonewolf/dnsmasq.conf &
child=$!

ready_sent=0
attempts=0
while true; do
    if ! kill -0 "$child" 2>/dev/null; then
        wait "$child"
        exit $?
    fi
    if listeners_ready && /usr/sbin/runuser -u debian-tor -- /usr/local/sbin/ph4ntxm-tor-bootstrap-ready.py; then
        publish_ready
        if (( ready_sent == 0 )); then
            /usr/bin/systemd-notify --ready --status="Tor bootstrap complete; DNS and proxy listeners verified"
            ready_sent=1
        fi
    elif (( ready_sent == 1 )); then
        exit 1
    else
        rm -f /run/ph4ntxm/tor-ready
        (( attempts++ )) || true
        (( attempts < 180 )) || exit 1
    fi
    sleep 2
done
