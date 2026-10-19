# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat

IDENTITY = Path("/run/ph4ntxm")
NM_PROFILE = Path("/run/NetworkManager/conf.d/90-ph4ntxm-session.conf")
NET_CLASS = Path("/sys/class/net")
PROC_SYS = Path("/proc/sys")
MAX_INPUT = 16384
MAX_INTERFACES = 128
TITLES = {
    "mac": "Physical adapter MAC consistency",
    "dhcp": "DHCP session identity",
    "network_profile": "Network persona settings",
}
CLOCK_LIMITS = {
    "linux": (-20, 20, 9994, 10006),
    "windows": (-60, 60, 9988, 10012),
    "lonewolf": (-90, 90, 9985, 10015),
}


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def result(code, problems, information=()):
    detail = " ".join(problems if problems else information)
    return {
        "code": code,
        "title": TITLES[code],
        "healthy": not problems,
        "status": "failed" if problems else "healthy",
        "detail": detail[:2048],
    }


def read_text(path, private=False, kernel=False, limit=MAX_INPUT):
    path = Path(path)
    if not kernel:
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise ValueError("Untrusted directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Untrusted file")
        if private and info.st_mode & 0o077:
            raise ValueError("Untrusted private file")
        if not kernel and info.st_size > limit:
            raise ValueError("Oversized file")
        value = os.read(fd, limit + 1)
        if len(value) > limit:
            raise ValueError("Oversized file")
        return value.decode("ascii").strip()
    finally:
        os.close(fd)


def environment(content):
    values = {}
    for line in content.splitlines():
        name, separator, encoded = line.partition("=")
        if not separator or not re.fullmatch("[A-Z][A-Z0-9_]*", name) or name in values:
            raise ValueError("Invalid session data")
        tokens = shlex.split(encoded, comments=False, posix=True)
        if len(tokens) != 1:
            raise ValueError("Invalid session value")
        values[name] = tokens[0]
    return values


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def physical_adapters():
    adapters = {}
    paths = list(NET_CLASS.iterdir())
    if len(paths) > MAX_INTERFACES:
        raise ValueError("Too many interfaces")
    for path in sorted(paths):
        name = path.name
        if not re.fullmatch("[a-zA-Z0-9_.:-]{1,15}", name):
            raise ValueError("Invalid interface name")
        device = path / "device"
        if not device.is_dir():
            continue
        try:
            if read_text(path / "type", kernel=True, limit=32) != "1":
                continue
            device_path = device.resolve(strict=True)
            node_info = path.stat()
            device_info = device_path.stat()
            index = read_text(path / "ifindex", kernel=True, limit=32)
            address = read_text(path / "address", kernel=True, limit=32).lower()
            if not re.fullmatch("[1-9][0-9]{0,9}", index):
                raise ValueError("Invalid interface index")
            if not re.fullmatch("[0-9a-f]{2}(?::[0-9a-f]{2}){5}", address):
                raise ValueError("Invalid adapter address")
            if address in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or int(address[:2], 16) & 1:
                raise ValueError("Invalid adapter address")
            after = path.stat()
            after_device = device_path.stat()
            if (node_info.st_dev, node_info.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError("Adapter changed during observation")
            if (device_info.st_dev, device_info.st_ino, device_info.st_ctime_ns) != (
                after_device.st_dev, after_device.st_ino, after_device.st_ctime_ns
            ):
                raise ValueError("Adapter changed during observation")
            key = digest(json.dumps([
                str(device_path), node_info.st_dev, node_info.st_ino, index,
                device_info.st_dev, device_info.st_ino, device_info.st_ctime_ns,
            ], separators=(",", ":")))
            if key in adapters:
                raise ValueError("Duplicate adapter identity")
            adapters[key] = {"address": digest(address), "name": name}
        except FileNotFoundError:
            continue
    return adapters


def mac_check(baseline):
    problems = []
    information = []
    evidence = None
    expected = None
    if baseline is not None:
        record = baseline.get("mac") if isinstance(baseline, dict) else None
        if (
            not isinstance(record, dict)
            or set(record) != {"adapters"}
            or not isinstance(record["adapters"], dict)
            or len(record["adapters"]) > MAX_INTERFACES
            or any(not valid_digest(key) or not valid_digest(value) for key, value in record["adapters"].items())
        ):
            problems.append("Physical adapter activation baseline is missing or invalid.")
        else:
            expected = record["adapters"]
            evidence = {"adapters": dict(expected)}
    try:
        observed = physical_adapters()
    except (OSError, ValueError, UnicodeError):
        problems.append("Physical adapter addresses could not be observed safely.")
        return result("mac", problems), evidence
    if baseline is None:
        evidence = {"adapters": {key: value["address"] for key, value in observed.items()}}
    elif expected is not None:
        for key, value in observed.items():
            if key in expected and value["address"] != expected[key]:
                problems.append("Physical adapter " + value["name"] + " MAC changed from the activation baseline.")
        missing = len(set(expected) - set(observed))
        added = len(set(observed) - set(expected))
        if missing:
            information.append("An activation adapter is absent; its MAC baseline is retained for this session.")
        if added:
            problems.append("New physical network adapter appeared after monitoring was enabled.")
    if not observed:
        information.append("No physical network adapter is currently present.")
    return result("mac", problems, information), evidence


def dhcp_check(mode, baseline):
    problems = []
    evidence = None
    try:
        values = environment(read_text(IDENTITY / "session_dhcp", private=True))
        expected = {"MODE": mode, "TIMEOUT": "60", "TOR": "enabled"}
        profile = {
            "ipv4.dhcp-client-id": "mac",
            "ipv4.dhcp-send-hostname": "false",
            "ipv4.dhcp-timeout": "60",
            "ipv6.dhcp-send-hostname": "false",
            "ethernet.cloned-mac-address": "preserve",
            "wifi.cloned-mac-address": "preserve",
        }
        if mode in ("linux", "windows"):
            hostname = read_text(IDENTITY / "boot_hostname", private=True, limit=80)
            if not re.fullmatch("[a-z0-9][a-z0-9-]{0,62}", hostname):
                raise ValueError("Invalid hostname")
            vendor, timeout, duid = ("dhclient", "60", "ll") if mode == "linux" else ("MSFT 5.0", "45", "stable-uuid")
            expected = {"MODE": mode, "VENDOR": vendor, "HOSTNAME": hostname, "TIMEOUT": timeout, "DUID": duid}
            profile.update({
                "ipv4.dhcp-vendor-class-identifier": vendor,
                "ipv4.dhcp-send-hostname": "true",
                "ipv4.dhcp-timeout": timeout,
                "ipv6.dhcp-duid": duid,
                "ipv6.dhcp-send-hostname": "true",
                "ipv6.ip6-privacy": "2",
            })
        elif mode != "lonewolf":
            raise ValueError("Invalid mode")
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_file(io.StringIO(read_text(NM_PROFILE)))
        section = "connection-ph4ntxm-session"
        if parser.defaults() or parser.sections() != [section]:
            raise ValueError("Invalid NetworkManager profile")
        actual_profile = dict(parser.items(section))
        if values != expected:
            problems.append("Generated DHCP session identity does not match the session mode or protected hostname.")
        if actual_profile != profile:
            problems.append("Generated NetworkManager DHCP defaults do not match the session policy.")
        if not problems:
            evidence = {"profile": digest(json.dumps([values, actual_profile], sort_keys=True, separators=(",", ":")))}
    except (OSError, ValueError, UnicodeError, configparser.Error):
        problems.append("Protected DHCP session data or NetworkManager defaults are missing, unreadable or malformed.")
    if baseline is not None:
        expected = baseline.get("dhcp") if isinstance(baseline, dict) else None
        if not isinstance(expected, dict) or set(expected) != {"profile"} or not valid_digest(expected["profile"]):
            problems.append("DHCP activation baseline is missing or invalid.")
        elif evidence is not None and evidence != expected:
            problems.append("DHCP session identity changed from the activation baseline.")
    return result("dhcp", problems), evidence


def network_specs(mode):
    common = {
        "net.ipv4.ip_default_ttl": "64",
        "net.ipv4.tcp_keepalive_intvl": "15",
        "net.ipv4.tcp_keepalive_probes": "5",
        "net.ipv4.tcp_mtu_probing": "1",
        "net.ipv4.tcp_fastopen": "1",
        "net.ipv4.tcp_ecn": "0",
        "net.ipv4.tcp_window_scaling": "1",
        "net.ipv4.tcp_sack": "1",
        "net.ipv4.tcp_timestamps": "1",
        "net.ipv4.tcp_congestion_control": "cubic",
    }
    if mode == "lonewolf":
        common.update({
            "net.ipv4.ip_local_port_range": ((30000, 42000), (60999, 60999)),
            "net.ipv4.tcp_syn_retries": (4, 6),
            "net.ipv4.tcp_synack_retries": (4, 6),
            "net.ipv4.tcp_fin_timeout": (20, 40),
            "net.ipv4.tcp_keepalive_time": (1800, 5400),
            "net.ipv4.tcp_keepalive_intvl": "30",
            "net.ipv4.tcp_fastopen": "0",
            "net.ipv4.tcp_timestamps": "0",
            "net.ipv4.icmp_ratelimit": (500, 1500),
            "net.ipv6.conf.all.disable_ipv6": "1",
            "net.ipv6.conf.default.disable_ipv6": "1",
            "net.ipv6.conf.lo.disable_ipv6": "1",
        })
    elif mode in ("linux", "windows"):
        windows = mode == "windows"
        common.update({
            "net.ipv4.ip_default_ttl": "128" if windows else "64",
            "net.ipv6.conf.all.hop_limit": "128" if windows else "64",
            "net.ipv6.conf.default.hop_limit": "128" if windows else "64",
            "net.ipv4.ip_local_port_range": ((49152, 49200), (65535, 65535)) if windows else ((21000, 29000), (64000, 64000)),
            "net.ipv4.tcp_syn_retries": (2, 4) if windows else (5, 7),
            "net.ipv4.tcp_synack_retries": (2, 4) if windows else (5, 7),
            "net.ipv4.tcp_fin_timeout": (35, 55) if windows else (30, 50),
            "net.ipv4.tcp_keepalive_time": (6600, 7800) if windows else (4800, 6000),
            "net.ipv4.tcp_keepalive_intvl": "1" if windows else "15",
            "net.ipv4.tcp_keepalive_probes": "10" if windows else "5",
            "net.ipv4.tcp_mtu_probing": "0" if windows else "1",
            "net.ipv4.tcp_fastopen": "0" if windows else "1",
            "net.ipv4.tcp_timestamps": "0" if windows else "1",
            "net.ipv4.tcp_no_metrics_save": "1",
            "net.ipv4.tcp_adv_win_scale": "2",
            "net.ipv4.tcp_rmem": ((4096, 6144), (65536, 196608), (5242880, 7340032)),
            "net.ipv4.tcp_wmem": ((2048, 6144), (65536, 196608), (5242880, 7340032)),
            "net.ipv4.icmp_ratelimit": "1000",
        })
    else:
        raise ValueError("Invalid network mode")
    optional = {}
    if mode != "lonewolf":
        optional["net.mptcp.enabled"] = "0"
        if mode == "windows":
            optional["net.ipv4.tcp_fack"] = "0"
    return common, optional


def matches(value, expected):
    if isinstance(expected, str):
        return value == expected
    if isinstance(expected[0], tuple):
        parts = value.split()
        return (
            len(parts) == len(expected)
            and all(matches(part, bounds) for part, bounds in zip(parts, expected))
            and all(int(left) <= int(right) for left, right in zip(parts, parts[1:]))
        )
    return re.fullmatch("[0-9]{1,10}", value) is not None and expected[0] <= int(value) <= expected[1]


def network_check(mode, baseline):
    problems = []
    present = []
    observed_values = {}
    try:
        required, optional = network_specs(mode)
    except ValueError:
        return result("network_profile", ["Network settings cannot be matched to a valid session mode."]), None
    expected_optional = None
    expected_values = None
    if baseline is not None:
        previous = baseline.get("network_profile") if isinstance(baseline, dict) else None
        if (
            not isinstance(previous, dict)
            or set(previous) != {"mode", "optional", "values"}
            or previous["mode"] != digest(mode)
            or not isinstance(previous["optional"], list)
            or any(not isinstance(key, str) or key not in optional for key in previous["optional"])
            or previous["optional"] != sorted(set(previous["optional"]))
            or not isinstance(previous["values"], dict)
            or set(previous["values"]) != set(required) | set(previous["optional"])
            or any(not valid_digest(value) for value in previous["values"].values())
        ):
            problems.append("Network settings activation baseline is missing or invalid.")
        else:
            expected_optional = previous["optional"]
            expected_values = previous["values"]
    for key, expected in {**required, **optional}.items():
        try:
            value = " ".join(read_text(PROC_SYS.joinpath(*key.split(".")), kernel=True, limit=256).split())
            observed_values[key] = digest(value)
            if key in optional:
                present.append(key)
                if expected_optional is not None and key not in expected_optional:
                    problems.append("Network setting " + key + " appeared after monitoring was enabled.")
            if not matches(value, expected):
                problems.append("Network setting " + key + " no longer matches the session policy.")
            if expected_values is not None and key in expected_values and observed_values[key] != expected_values[key]:
                problems.append("Network setting " + key + " changed from the activation baseline.")
        except FileNotFoundError:
            if expected_optional is not None and key in expected_optional:
                problems.append("Network setting " + key + " disappeared after monitoring was enabled.")
            elif key in required:
                problems.append("Network setting " + key + " is unavailable.")
        except (OSError, ValueError, UnicodeError):
            problems.append("Network setting " + key + " could not be observed safely.")
    evidence = {"mode": digest(mode), "optional": sorted(present), "values": observed_values}
    if expected_values is not None:
        evidence = {"mode": digest(mode), "optional": list(expected_optional), "values": dict(expected_values)}
    return result("network_profile", problems), evidence


def clock_problems(mode, values):
    keys = {"MODE", "OFFSET_SECONDS", "INITIAL_TICK", "CURRENT_TICK", "MIN_TICK", "MAX_TICK", "SKEW_APPLIED"}
    if mode not in CLOCK_LIMITS:
        return ["Clock Fuzz cannot be matched to a valid session mode."]
    if not isinstance(values, dict) or set(values) != keys:
        return ["Clock Fuzz profile fields are missing or malformed."]
    problems = []
    if values["MODE"] != mode:
        problems.append("Clock Fuzz profile mode does not match this session.")
    if values["SKEW_APPLIED"] != "1":
        problems.append("Initial clock skew is not confirmed (SKEW_APPLIED).")
    for key in ("OFFSET_SECONDS", "INITIAL_TICK", "CURRENT_TICK", "MIN_TICK", "MAX_TICK"):
        pattern = "-?[0-9]{1,10}" if key == "OFFSET_SECONDS" else "[0-9]{1,10}"
        if not isinstance(values[key], str) or not re.fullmatch(pattern, values[key]):
            return problems + ["Clock Fuzz numeric profile fields are malformed."]
    offset_min, offset_max, tick_min, tick_max = CLOCK_LIMITS[mode]
    if not offset_min <= int(values["OFFSET_SECONDS"]) <= offset_max:
        problems.append("Clock Fuzz initial offset is outside the session mode bounds.")
    if int(values["MIN_TICK"]) != tick_min or int(values["MAX_TICK"]) != tick_max:
        problems.append("Clock Fuzz tick bounds do not match the session mode.")
    if any(not tick_min <= int(values[key]) <= tick_max for key in ("INITIAL_TICK", "CURRENT_TICK")):
        problems.append("Clock Fuzz tick is outside the session mode bounds.")
    return problems


def collect(mode, seed, baseline=None):
    checks = []
    evidence = {}
    for operation, arguments in (
        (mac_check, (baseline,)),
        (dhcp_check, (mode, baseline)),
        (network_check, (mode, baseline)),
    ):
        check, value = operation(*arguments)
        checks.append(check)
        if value is not None:
            evidence[check["code"]] = value
    return checks, evidence
