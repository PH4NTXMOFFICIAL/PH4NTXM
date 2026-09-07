#!/usr/bin/env bash
set -euo pipefail

ip route flush cache 2>/dev/null || true
ip neigh flush all 2>/dev/null || true
/usr/sbin/sysctl -q -w net.ipv4.tcp_no_metrics_save=1 || true

exit 0
