#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check_workspace(root, edition):
    build = root / "build"
    work = build / edition
    for path in (build, work, build / f".{edition}.lock", root / "output"):
        if path.is_symlink():
            raise ValueError(f"Refusing a symbolic link at {path}")
    if work.exists():
        marker = work / ".ph4ntxm-edition"
        if marker.is_symlink() or not marker.is_file() or marker.read_text().strip() != edition:
            raise ValueError(f"Refusing an unmanaged build directory: {work}")
        for name in ("config", ".build", "chroot", "binary", "cache", "auto", "local"):
            if (work / name).is_symlink():
                raise ValueError(f"Refusing a symbolic link at {work / name}")
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), line.split()[4])
        mount = Path(target)
        if mount == work or work in mount.parents:
            raise ValueError(f"A filesystem is still mounted in {work}; unmount it before rebuilding.")
    return work


def prepare(root, edition):
    work = check_workspace(root, edition)
    if any((work / name).exists() for name in ("chroot", "binary")) or ((work / ".build").exists() and any((work / ".build").iterdir())):
        raise ValueError("Clean the previous live-build before preparing a new configuration.")
    profile = json.loads((root / "editions" / edition / "edition.json").read_text())
    if profile["name"] != edition:
        raise ValueError("Edition profile does not match its directory.")
    work.mkdir(parents=True, exist_ok=True)
    (work / ".ph4ntxm-edition").write_text(edition + "\n")
    stage = Path(tempfile.mkdtemp(prefix=".prepare-", dir=work))
    try:
        config = stage / "config"
        shutil.copytree(root / "config", config, symlinks=True)
        overlay = root / "editions" / edition / "config"
        if not overlay.is_dir():
            raise ValueError(f"Missing edition configuration: {edition}")
        shutil.copytree(overlay, config, symlinks=True, dirs_exist_ok=True)
        common = config / "common"
        text = common.read_text()
        text, count = re.subn(r'^LB_IMAGE_NAME="[^"]*"$', f'LB_IMAGE_NAME="ph4ntxm-{edition}"', text, flags=re.M)
        if count != 1:
            raise ValueError("Expected exactly one LB_IMAGE_NAME in config/common.")
        common.write_text(text)
        includes = config / "includes.chroot"
        assets = (f"usr/share/themes/{profile['theme']}", profile["wallpaper"].lstrip("/"), profile["login_background"].lstrip("/"))
        for name in assets:
            if not (includes / name).exists():
                raise ValueError(f"Missing {edition} asset: {name}")
        metadata = includes / "usr/share/ph4ntxm/edition"
        metadata.parent.mkdir(parents=True, exist_ok=True)
        metadata.write_text(edition + "\n")
        if (work / "config").exists():
            shutil.rmtree(work / "config")
        config.rename(work / "config")
    finally:
        shutil.rmtree(stage)
    return work


def reserve_export(output, edition, stamp):
    lock_path = output / f".{edition}-export.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        counter = output / f".{edition}-sequence"
        if counter.is_symlink():
            raise ValueError(f"Refusing a symbolic link at {counter}")
        sequence = 0
        if counter.exists():
            value = counter.read_text().strip()
            if not re.fullmatch(r"[0-9]+", value):
                raise ValueError(f"Invalid export counter: {counter}")
            sequence = int(value)
        pattern = rf"{re.escape(edition)}-[0-9]{{8}}T[0-9]{{6}}Z-([0-9]{{3,}})"
        for path in output.iterdir():
            match = re.fullmatch(pattern, path.name)
            if match:
                sequence = max(sequence, int(match[1]))
        while True:
            sequence += 1
            destination = output / f"{edition}-{stamp}-{sequence:03d}"
            try:
                destination.mkdir(mode=0o700)
                break
            except FileExistsError:
                continue
        temporary = None
        try:
            descriptor, name = tempfile.mkstemp(
                prefix=f".{edition}-sequence-", dir=output
            )
            temporary = Path(name)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(f"{sequence}\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(counter)
        except BaseException:
            destination.rmdir()
            raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return destination


def publish(root, edition):
    work = check_workspace(root, edition)
    iso = work / f"ph4ntxm-{edition}-amd64.hybrid.iso"
    if iso.is_symlink() or not iso.is_file():
        raise ValueError(f"Expected ISO was not produced: {iso.name}")
    output = root / "output"
    output.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = reserve_export(output, edition, stamp)
    for pattern in (f"ph4ntxm-{edition}-amd64.*",):
        for source in sorted(work.glob(pattern)):
            if source.is_file() and not source.is_symlink():
                shutil.copy2(source, destination / source.name)
    digest = hashlib.sha256()
    with (destination / iso.name).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    (destination / "SHA256SUMS").write_text(f"{digest.hexdigest()}  {iso.name}\n")
    if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit() and os.environ.get("SUDO_GID", "").isdigit():
        for path in (destination, *destination.iterdir()):
            os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    print(f"ISO and checksum: {destination}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--edition", choices=("abyss", "ghost"), required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            check_workspace(ROOT, args.edition)
        elif args.publish:
            publish(ROOT, args.edition)
        else:
            prepare(ROOT, args.edition)
    except (OSError, ValueError, KeyError) as error:
        print(f"Build preparation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
