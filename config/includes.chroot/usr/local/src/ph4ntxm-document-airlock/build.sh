#!/bin/sh
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -eu

for tool in debootstrap mksquashfs modprobe depmod cpio gzip python3; do
    command -v "$tool" >/dev/null
done

SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUTPUT=${1:-/usr/local/share/ph4ntxm-document-airlock}
WORK=$(mktemp -d /tmp/ph4ntxm-airlock-build.XXXXXX)
GUEST="$WORK/guest"
INITRD="$WORK/initrd"
KVER=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' \
    | sed 's/^vmlinuz-//' | sort -V | tail -n 1)
[ -n "$KVER" ]
cleanup() {
    for target in "$GUEST/dev/pts" "$GUEST/dev" "$GUEST/proc"; do
        if mountpoint -q "$target"; then
            umount "$target" || return
        fi
    done
    rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

install -d -m 0755 "$OUTPUT" "$INITRD/bin" "$INITRD/dev" \
    "$INITRD/proc" "$INITRD/sys" "$INITRD/root" "$INITRD/lib/modules/$KVER"

debootstrap --arch=amd64 --variant=minbase \
    --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
    trixie "$GUEST" https://deb.debian.org/debian
mount -t tmpfs -o mode=0755,nosuid tmpfs "$GUEST/dev"
for name in null zero random urandom; do
    cp -a "/dev/$name" "$GUEST/dev/$name"
done
mkdir -p "$GUEST/dev/pts"
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts "$GUEST/dev/pts"
ln -s pts/ptmx "$GUEST/dev/ptmx"
mount -t proc -o ro,nosuid,nodev,noexec proc "$GUEST/proc"
printf '#!/bin/sh\nexit 101\n' >"$GUEST/usr/sbin/policy-rc.d"
chmod 0755 "$GUEST/usr/sbin/policy-rc.d"
cat >"$GUEST/etc/apt/sources.list" <<'EOF'
deb https://deb.debian.org/debian trixie main
deb https://deb.debian.org/debian-security trixie-security main
deb https://deb.debian.org/debian trixie-updates main
EOF
install -d "$GUEST/etc/ssl/certs"
install -m 0644 /etc/ssl/certs/ca-certificates.crt "$GUEST/etc/ssl/certs/ca-certificates.crt"
chroot "$GUEST" apt-get update
chroot "$GUEST" /usr/bin/env DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
    ca-certificates busybox-static python3 python3-pil poppler-utils \
    libreoffice-writer libreoffice-calc libreoffice-impress libreoffice-draw \
    fonts-dejavu-core fonts-liberation fonts-noto-core

install -d -m 0755 "$GUEST/usr/local/lib/ph4ntxm-document-airlock" \
    "$GUEST/usr/local/sbin" "$GUEST/run" "$GUEST/tmp"
install -m 0644 "$SOURCE/airlock.py" "$SOURCE/guest.py" \
    "$GUEST/usr/local/lib/ph4ntxm-document-airlock/"
install -m 0755 "$SOURCE/guest-init" "$GUEST/usr/local/sbin/ph4ntxm-airlock-init"
chroot "$GUEST" dpkg-query -W -f='${Package}\t${Version}\n' >"$OUTPUT/guest-packages.txt"
chroot "$GUEST" apt-get clean
umount "$GUEST/dev/pts"
umount "$GUEST/dev"
umount "$GUEST/proc"
rm -rf "$GUEST/var/lib/apt/lists" "$GUEST/usr/share/man"
find "$GUEST/usr/share/doc" -type f ! -name copyright -delete
rm -f "$GUEST/etc/machine-id" "$GUEST/var/lib/dbus/machine-id"
printf 'ph4ntxm-airlock\n' >"$GUEST/etc/hostname"
printf '127.0.0.1 localhost ph4ntxm-airlock\n' >"$GUEST/etc/hosts"
: >"$GUEST/etc/resolv.conf"
find "$GUEST/var/log" -type f -exec truncate -s 0 {} +

install -m 0755 "$GUEST/bin/busybox" "$INITRD/bin/busybox"
install -m 0755 "$SOURCE/init" "$INITRD/init"
for module in virtio_pci virtio_blk virtio_console squashfs; do
    modprobe --show-depends --set-version "$KVER" "$module" \
        | awk '$1 == "insmod" {print $2}' >>"$WORK/modules.list"
done
sort -u "$WORK/modules.list" | while IFS= read -r module_path; do
    relative=${module_path#*/lib/modules/}
    install -D -m 0644 "$module_path" "$INITRD/lib/modules/$relative"
done
for name in modules.builtin modules.builtin.modinfo modules.order; do
    if [ -f "/lib/modules/$KVER/$name" ]; then
        install -m 0644 "/lib/modules/$KVER/$name" "$INITRD/lib/modules/$KVER/$name"
    fi
done
depmod -b "$INITRD" "$KVER"
(cd "$INITRD" && find . -print0 | cpio --null -o -H newc 2>/dev/null \
    | gzip -1 >"$OUTPUT/initrd")
install -m 0644 "/boot/vmlinuz-$KVER" "$OUTPUT/kernel"
mksquashfs "$GUEST" "$OUTPUT/root.squashfs" \
    -noappend -all-root -no-xattrs -comp zstd -processors 2 -quiet
python3 - "$OUTPUT" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest = {}
for name in ("kernel", "initrd", "root.squashfs"):
    with (root / name).open("rb") as handle:
        manifest[name] = hashlib.file_digest(handle, "sha256").hexdigest()
(root / "manifest.json").write_text(json.dumps(manifest, indent=4) + "\n", encoding="utf-8")
PY
chmod 0644 "$OUTPUT/"*
