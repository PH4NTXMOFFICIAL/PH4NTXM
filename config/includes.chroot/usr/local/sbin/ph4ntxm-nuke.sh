#!/bin/sh
set -u

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[ "$(id -u)" -eq 0 ] || exit 1

/usr/bin/timeout -k 1 5 /usr/local/sbin/ph4ntxm-firewall-control enable >/dev/null 2>&1 || \
    /usr/bin/timeout -k 1 5 /usr/sbin/nft -f /etc/firewall/lockdown.nft >/dev/null 2>&1 || true

/usr/sbin/rfkill block all >/dev/null 2>&1 || true
for path in /sys/class/net/*; do
    [ -e "$path" ] || continue
    iface=${path##*/}
    [ "$iface" = lo ] && continue
    /usr/sbin/ip link set dev "$iface" down >/dev/null 2>&1 || true
done

/usr/bin/loginctl terminate-user ph4ntxm >/dev/null 2>&1 || {
    user_id=$(/usr/bin/id -u ph4ntxm 2>/dev/null || true)
    [ -z "$user_id" ] || /usr/bin/pkill -KILL -u "$user_id" >/dev/null 2>&1 || true
}
/usr/bin/systemctl stop ph4ntxm-ram-seeding-engine.service >/dev/null 2>&1 || true
/sbin/swapoff -a >/dev/null 2>&1 || true
/bin/sync
[ ! -w /proc/sys/vm/drop_caches ] || printf '3\n' > /proc/sys/vm/drop_caches 2>/dev/null || true
/usr/local/sbin/ph4ntxm-ram-scrub >/dev/null 2>&1 || true
/bin/sync
