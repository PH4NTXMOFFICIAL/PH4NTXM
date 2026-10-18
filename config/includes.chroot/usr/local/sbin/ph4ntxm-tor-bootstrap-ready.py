#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import os
import pathlib
import pwd
import re
import shlex
import socket
import stat
import sys

COOKIE = "/run/tor/control.authcookie"
CONTROL = "/run/tor/control"

sys.path.insert(0, "/usr/lib/ph4ntxm")
from tor_connection import ConnectionError, TORRC, verify


def read_reply(channel):
    lines = []
    total = 0
    code = None
    while True:
        raw = channel.readline(4097)
        if not raw or len(raw) > 4096:
            raise OSError("invalid control reply")
        total += len(raw)
        if total > 16384 or not raw.endswith(b"\r\n"):
            raise OSError("oversized control reply")
        line = raw[:-2].decode("ascii", "strict")
        match = re.fullmatch(r"([0-9]{3})([ +\-])(.*)", line)
        if not match:
            raise OSError("malformed control reply")
        current = int(match.group(1))
        if code is None:
            code = current
        elif current != code:
            raise OSError("mixed control reply")
        separator = match.group(2)
        lines.append(match.group(3))
        if separator == "+":
            while True:
                data = channel.readline(4097)
                if not data or len(data) > 4096:
                    raise OSError("invalid control data")
                total += len(data)
                if total > 16384 or not data.endswith(b"\r\n"):
                    raise OSError("oversized control data")
                if data == b".\r\n":
                    break
        if separator == " ":
            return code, lines


def command(channel, request):
    channel.write(request.encode("ascii") + b"\r\n")
    channel.flush()
    return read_reply(channel)


def connection_matches(channel):
    verify()
    expected = {}
    for line in TORRC.read_text(encoding="ascii").splitlines():
        key, value = line.split(" ", 1)
        if key in {"UseBridges", "DisableNetwork", "Bridge", "ClientTransportPlugin"}:
            expected.setdefault(key, []).append(shlex.split(value))
    code, lines = command(
        channel, "GETCONF UseBridges DisableNetwork Bridge ClientTransportPlugin"
    )
    if code != 250:
        return False
    actual = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if key not in {"UseBridges", "DisableNetwork", "Bridge", "ClientTransportPlugin"}:
            return False
        if separator:
            actual.setdefault(key, []).append(shlex.split(value))
        elif key not in {"Bridge", "ClientTransportPlugin"}:
            return False
    if actual != expected:
        return False
    verify()
    return True


def main():
    try:
        verify()
        tor_account = pwd.getpwnam("debian-tor")
        tor_uid = tor_account.pw_uid
        tor_gid = tor_account.pw_gid
        if os.geteuid() != tor_uid:
            return 1
        cookie_path = pathlib.Path(COOKIE)
        cookie_stat = cookie_path.lstat()
        control_stat = pathlib.Path(CONTROL).lstat()
        if not stat.S_ISREG(cookie_stat.st_mode) or stat.S_ISLNK(cookie_stat.st_mode):
            return 1
        if not stat.S_ISSOCK(control_stat.st_mode) or stat.S_ISLNK(
            control_stat.st_mode
        ):
            return 1
        if (
            cookie_stat.st_uid != tor_uid
            or cookie_stat.st_gid != tor_gid
            or control_stat.st_uid != tor_uid
            or control_stat.st_gid != tor_gid
        ):
            return 1
        if cookie_stat.st_mode & 0o027:
            return 1
        if stat.S_IMODE(control_stat.st_mode) != 0o660:
            return 1
        cookie_bytes = cookie_path.read_bytes()
        if len(cookie_bytes) != 32:
            return 1
        cookie = cookie_bytes.hex()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(3)
            channel.connect(CONTROL)
            stream = channel.makefile("rwb", buffering=0)
            auth_code, auth_lines = command(stream, f"AUTHENTICATE {cookie}")
            if auth_code != 250 or auth_lines != ["OK"]:
                return 1
            info_code, info_lines = command(stream, "GETINFO status/bootstrap-phase")
            if info_code != 250 or len(info_lines) != 2 or info_lines[-1] != "OK":
                return 1
            prefix = "status/bootstrap-phase="
            if not info_lines[0].startswith(prefix):
                return 1
            fields = shlex.split(info_lines[0][len(prefix) :], posix=True)
            if len(fields) < 4 or fields[1] != "BOOTSTRAP":
                return 1
            values = dict(item.split("=", 1) for item in fields[2:] if "=" in item)
            if values.get("PROGRESS") != "100" or values.get("TAG") != "done":
                return 1
            if not connection_matches(stream):
                return 1
            command(stream, "QUIT")
    except (ConnectionError, KeyError, OSError, UnicodeError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
