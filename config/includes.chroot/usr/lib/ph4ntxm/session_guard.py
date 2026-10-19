# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

import session_guard_network
import session_guard_persona

RUNTIME = Path("/run/ph4ntxm-session-guard")
PUBLIC = RUNTIME / "status.json"
CONTROL = RUNTIME / "control.sock"
STATE = RUNTIME / "state.json"
IDENTITY = Path("/run/ph4ntxm")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
KERNEL_VALUES = frozenset((
    Path("/sys/kernel/kexec_crash_loaded"),
    Path("/proc/sys/kernel/kexec_load_disabled"),
    Path("/proc/sys/kernel/hostname"),
    BOOT_ID,
))
INTERVAL = 10
MAX_HISTORY = 64
MAX_INPUT = 4096
MAX_PUBLIC = 262144
MAX_STATE = 524288
HOSTS = Path("/etc/hosts")
DBUS_ID = Path("/var/lib/dbus/machine-id")
READY_AGE = 30
TRANSITION_AGE = 30
SCHEMA = 1
PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ConditionResult",
    "ExecMainStatus",
    "ExecMainStartTimestampMonotonic",
    "MainPID",
    "Type",
    "Job",
)
COMMON_UNITS = {
    "ph4ntxm-mode.service": "oneshot",
    "ph4ntxm-clock-fuzz.service": "continuous",
    "ph4ntxm-arm-nuke.service": "oneshot"
}
NORMAL_UNITS = {
    "ph4ntxm-hardware-randomization.service": "oneshot",
    "ph4ntxm-gpu-randomization.service": "oneshot",
    "ph4ntxm-cores-randomization.service": "oneshot",
    "ph4ntxm-cpu-spoof.service": "oneshot",
    "ph4ntxm-screen-randomization.service": "oneshot",
    "ph4ntxm-identity-randomization.service": "oneshot",
    "ph4ntxm-net-randomization.service": "oneshot",
    "ph4ntxm-dhcp-session-generator.service": "oneshot",
    "ph4ntxm-nft-rules.service": "oneshot",
    "ph4ntxm-unbound-randomization.service": "continuous",
    "unbound.service": "continuous",
    "ph4ntxm-packet-transformation-engine.service": "continuous",
    "ph4ntxm-packet-transformation-engine-guard.service": "continuous",
    "ph4ntxm-firewall-guard.service": "continuous"
}
LONEWOLF_UNITS = {
    "ph4ntxm-lonewolf-hardware-randomization.service": "oneshot",
    "ph4ntxm-lonewolf-gpu-randomization.service": "oneshot",
    "ph4ntxm-lonewolf-cores-randomization.service": "oneshot",
    "ph4ntxm-lonewolf-cpu-spoof.service": "oneshot",
    "ph4ntxm-lonewolf-screen-randomization.service": "oneshot",
    "ph4ntxm-lonewolf-identity-randomization.service": "oneshot",
    "ph4ntxm-lonewolf-net-randomization.service": "oneshot",
    "ph4ntxm-lonewolf-dhcp-session-generator.service": "oneshot",
    "ph4ntxm-lonewolf-sysctl.service": "oneshot",
    "ph4ntxm-lonewolf.service": "oneshot",
    "ph4ntxm-lonewolf-firewall-guard.service": "continuous"
}
CATALOG = {
    "mode": (
        "Boot mode consistency",
        "The protected boot mode is unavailable or no longer matches this session.",
    ),
    "identity": (
        "Session identity consistency",
        "Protected identity readiness, seed, machine identity or hostname no longer matches this session.",
    ),
    "services": (
        "Protection services",
        "A required protection service is unavailable, failed or no longer running.",
    ),
    "clock": (
        "Clock Fuzz readiness",
        "The Clock Fuzz runtime profile is unavailable or inconsistent with this session.",
    ),
    "nuke": (
        "Nuke readiness",
        "The mandatory Nuke crash kernel is not loaded with the loader locked.",
    ),
    "firewall": (
        "Firewall readiness",
        "The firewall guardian has no fresh, protected readiness record for a supported policy.",
    ),
    "packet_engine": (
        "Packet Transformation Engine readiness",
        "The Packet Transformation Engine guardian has no fresh, protected readiness record.",
    ),
    "name_resolution": (
        "Local identity bindings",
        "Hostname resolution or the D-Bus machine identity no longer matches this session.",
    ),
    "persona": (
        "Hardware persona consistency",
        "Generated hardware and CPU identity no longer matches this session.",
    ),
    "dmi": (
        "DMI identity consistency",
        "Generated or exposed DMI identity no longer matches this session.",
    ),
    "graphics": (
        "Graphics identity consistency",
        "Generated GPU or display identity no longer matches this session.",
    ),
    "mac": (
        "Physical adapter MAC consistency",
        "Physical adapter identity changed after monitoring was enabled.",
    ),
    "dhcp": (
        "DHCP session identity",
        "DHCP identity no longer matches the generated session configuration.",
    ),
    "network_profile": (
        "Network persona settings",
        "Network identity settings no longer match this session.",
    ),
    "observer": (
        "Session Guard observation",
        "Session Guard could not complete a trusted protection check.",
    ),
}
ERRORS = {
    "unavailable": "Session Guard is unavailable.",
    "request": "The Session Guard request is invalid.",
    "permission": "Root authorization is required.",
    "stale": "Session Guard changed. Refresh its status and try again.",
    "not_ready": "Required session protections are not ready. Enable Session Guard after the checks are healthy.",
    "state": "Session Guard private state could not be verified.",
}


class GuardError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(ERRORS[code])


def boottime():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def protected_directory(path, private=False):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise GuardError("state")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise GuardError("state")


def ensure_runtime():
    try:
        RUNTIME.mkdir(mode=0o755)
        created = True
    except FileExistsError:
        created = False
    protected_directory(RUNTIME)
    if created:
        os.chmod(RUNTIME, 0o755)


def read_protected(path, limit=MAX_INPUT, private=False):
    protected_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise GuardError("state")
        if private and info.st_mode & 0o077:
            raise GuardError("state")
        if info.st_size > limit and path not in KERNEL_VALUES:
            raise GuardError("state")
        value = os.read(fd, limit + 1)
        if len(value) > limit:
            raise GuardError("state")
        return value
    finally:
        os.close(fd)


def read_text(path, limit=MAX_INPUT, private=False):
    return read_protected(path, limit, private).decode("ascii").strip()


def atomic_json(path, value, mode):
    protected_directory(path.parent)
    fd, name = tempfile.mkstemp(prefix=".session-guard-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            json.dump(value, output, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def key_values(path):
    result = {}
    for line in read_text(path).splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in result:
            raise GuardError("state")
        result[key] = value
    return result


def readiness_problems(path, profiles, now, packet=False):
    try:
        values = key_values(path)
    except (OSError, ValueError, UnicodeError, GuardError):
        return ["Readiness record is missing, unreadable, malformed or not trusted."]
    problems = []
    try:
        stamp = int(values.get("UPTIME_SECONDS", "-1"))
        if stamp < 0:
            problems.append("Readiness timestamp is missing or invalid.")
        elif now < stamp:
            problems.append("Readiness timestamp is in the future.")
        elif now - stamp > READY_AGE:
            problems.append("Readiness record is older than 30 seconds.")
    except ValueError:
        problems.append("Readiness timestamp is missing or invalid.")
    if values.get("PROFILE") not in profiles:
        problems.append("Readiness policy profile does not match this session.")
    if packet:
        if values.get("STATUS") != "ready":
            problems.append("Packet engine STATUS is not ready.")
        if not values.get("INTERFACES", "").isdigit():
            problems.append("Packet engine interface count is missing or invalid.")
    elif not re.fullmatch("[0-9a-f]{64}", values.get("RULESET_SHA256", "")):
        problems.append("Firewall ruleset digest is missing or invalid.")
    return problems


def readiness_lock(states, mode):
    guard_name = (
        "ph4ntxm-lonewolf-firewall-guard.service"
        if mode == "lonewolf"
        else "ph4ntxm-firewall-guard.service"
    )
    guardian_healthy = unit_healthy(states.get(guard_name, {}), "continuous")
    descriptor = None
    try:
        protected_directory(IDENTITY)
        descriptor = os.open(
            IDENTITY / "firewall.lock",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise GuardError("state")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            return None, guardian_healthy
        return descriptor, False
    except (OSError, GuardError):
        if descriptor is not None:
            os.close(descriptor)
        return None, False


def unit_states(units):
    command = ["/usr/bin/systemctl", "show", "--no-pager", "--property=" + ",".join(PROPERTIES)]
    command.extend(sorted(units))
    result = subprocess.run(
        command,
        capture_output=True,
        timeout=4,
        check=False,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "SYSTEMD_COLORS": "0",
        },
    )
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise GuardError("unavailable")
    states = {}
    for block in result.stdout.decode("ascii").strip().split("\n\n"):
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in fields or key not in PROPERTIES:
                raise GuardError("unavailable")
            fields[key] = value
        name = fields.get("Id")
        if name not in units or name in states:
            raise GuardError("unavailable")
        states[name] = fields
    return states


def unit_healthy(state, kind):
    if state.get("LoadState") != "loaded" or state.get("Result") != "success":
        return False
    if state.get("ConditionResult") != "yes" or state.get("ExecMainStatus") != "0":
        return False
    if kind == "oneshot":
        return (
            state.get("Type") == "oneshot"
            and state.get("ActiveState") in ("active", "inactive")
            and state.get("SubState") in ("exited", "dead")
            and state.get("ExecMainStartTimestampMonotonic", "0").isdigit()
            and int(state.get("ExecMainStartTimestampMonotonic", "0")) > 0
        )
    return (
        state.get("ActiveState") == "active"
        and state.get("SubState") == "running"
        and state.get("MainPID", "0").isdigit()
        and int(state.get("MainPID", "0")) > 0
    )


def unit_pending(state):
    job = (state.get("Job", "0").split() or ["0"])[0]
    return state.get("ActiveState") in ("activating", "reloading", "deactivating") or job != "0"


def check_result(code, healthy, pending=False, detail=None):
    title, fallback = CATALOG[code]
    status = "healthy" if healthy else "pending" if pending else "failed"
    if detail is None:
        detail = (
            "A protection transition is in progress. Wait for it to finish."
            if pending else fallback
        )
    return {
        "code": code,
        "title": title,
        "healthy": bool(healthy),
        "status": status,
        "detail": "Healthy." if healthy else detail,
    }


def observed_text(path, label, problems, limit=MAX_INPUT, private=False):
    try:
        return read_text(path, limit, private)
    except FileNotFoundError:
        reason = " is missing."
    except PermissionError:
        reason = " cannot be read (permission denied)."
    except GuardError:
        reason = " failed ownership, permissions or file-type validation."
    except UnicodeError:
        reason = " is not valid ASCII text."
    except ValueError:
        reason = " has an invalid format."
    except OSError:
        reason = " could not be read."
    problems.append(label + reason)
    return None


def service_problem(state, kind):
    if not state:
        return "status unavailable"
    if state.get("LoadState") != "loaded":
        return "unit is not loaded"
    if state.get("Result") != "success":
        status = state.get("ExecMainStatus", "")
        return "last run failed" + (" with exit status " + status if status.isdigit() else "")
    if state.get("ConditionResult") != "yes":
        return "startup conditions were not met"
    if state.get("ExecMainStatus") != "0":
        return "last execution did not exit successfully"
    if unit_pending(state):
        return "service transition is in progress"
    if kind == "continuous":
        return "service is not running"
    return "successful one-shot completion could not be verified"


def binding_check(hostname, baseline=None):
    problems = []
    content = observed_text(HOSTS, "Local hosts file", problems, 65536)
    if hostname is None:
        problems.append("Local hostname bindings cannot be verified without the session hostname.")
    elif content is not None:
        names = []
        for line in content.splitlines():
            fields = line.partition("#")[0].split()
            if fields and fields[0] == "127.0.1.1":
                names.append(fields[1] if len(fields) > 1 else "")
        if not names or any(name != hostname for name in names):
            problems.append("The 127.0.1.1 hostname in /etc/hosts does not match this session.")
    try:
        protected_directory(DBUS_ID.parent)
        if not DBUS_ID.is_symlink() or DBUS_ID.readlink() != Path("/etc/machine-id"):
            problems.append("D-Bus machine ID no longer links to the system machine ID.")
    except (OSError, GuardError):
        problems.append("D-Bus machine-ID binding is missing or not trusted.")
    evidence = {"hostname": digest(hostname)} if hostname is not None else {}
    if baseline is not None and baseline != evidence:
        problems.append("Local identity activation baseline is missing or no longer matches.")
    return check_result("name_resolution", not problems, detail=" ".join(problems)), evidence


def collect_generated(mode, seed, hostname, baseline=None):
    previous = baseline if isinstance(baseline, dict) else {}
    if mode not in ("linux", "windows", "lonewolf") or not isinstance(seed, str) or not re.fullmatch("[0-9a-f]{64}", seed):
        codes = ("persona", "dmi", "graphics", "mac", "dhcp", "network_profile", "name_resolution")
        return [check_result(
            code, False,
            detail="Generated identity cannot be verified until the session mode and seed are ready.",
        ) for code in codes], {}
    hardware_checks, hardware = session_guard_persona.collect(
        mode, seed, None if baseline is None else previous.get("persona", {})
    )
    network_checks, network = session_guard_network.collect(
        mode, seed, None if baseline is None else previous.get("network", {})
    )
    binding, bindings = binding_check(
        hostname, None if baseline is None else previous.get("name_resolution", {})
    )
    return hardware_checks + network_checks + [binding], {
        "persona": hardware,
        "network": network,
        "name_resolution": bindings,
    }


def collect(baseline=None):
    checks = []
    evidence = {}
    mode = "unknown"
    mode_problems = []
    mode = observed_text(IDENTITY / "mode", "Boot mode record", mode_problems, 16)
    if mode is not None:
        if mode not in ("linux", "windows", "lonewolf"):
            mode_problems.append("Boot mode record contains an unsupported mode.")
        else:
            evidence["mode"] = digest(mode)
            if baseline and evidence["mode"] != baseline.get("mode"):
                mode_problems.append("Boot mode changed from the activation baseline.")
    checks.append(check_result("mode", not mode_problems, detail=" ".join(mode_problems)))
    valid_mode = mode in ("linux", "windows", "lonewolf")
    if not valid_mode:
        mode = baseline["runtime_mode"] if baseline else "unknown"
    expected_mode = baseline.get("runtime_mode", mode) if baseline else mode
    units = dict(COMMON_UNITS)
    units.update(LONEWOLF_UNITS if expected_mode == "lonewolf" else NORMAL_UNITS)
    states = {}
    try:
        states = unit_states(units)
        services_ok = all(
            unit_healthy(states.get(name, {}), kind)
            and not unit_pending(states.get(name, {}))
            for name, kind in units.items()
        )
        services_pending = not services_ok and all(
            unit_healthy(states.get(name, {}), kind)
            or unit_pending(states.get(name, {}))
            for name, kind in units.items()
        )
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, GuardError):
        services_ok = False
        services_pending = False
    service_check = check_result("services", services_ok, services_pending)
    if not services_ok:
        if states:
            failed = [
                name + ": " + service_problem(states.get(name, {}), kind)
                for name, kind in sorted(units.items())
                if not unit_healthy(states.get(name, {}), kind)
                or unit_pending(states.get(name, {}))
            ]
            service_check["detail"] = ". ".join(failed) + "."
        else:
            service_check["detail"] = "Protection service status could not be read from systemd."
    checks.append(service_check)
    identity_problems = []
    seed_name = "lonewolf_seed" if expected_mode == "lonewolf" else "persona_seed"
    fields = (
        ("seed", IDENTITY / seed_name, "Session seed", 80, True),
        ("ready", IDENTITY / "identity-ready", "Identity readiness record", 16, False),
        ("boot_mid", IDENTITY / "boot_machine_id", "Boot machine ID", 40, False),
        ("machine_id", Path("/etc/machine-id"), "System machine ID (/etc/machine-id)", 40, False),
        ("boot_host", IDENTITY / "boot_hostname", "Boot hostname", 80, True),
        ("hostname", Path("/proc/sys/kernel/hostname"), "Kernel hostname", 80, False),
        ("stored_hostname", Path("/etc/hostname"), "Stored hostname (/etc/hostname)", 80, False),
    )
    values = {
        key: observed_text(path, label, identity_problems, limit, private)
        for key, path, label, limit, private in fields
    }
    for key, pattern, label in (
        ("seed", "[0-9a-f]{64}", "Session seed"),
        ("boot_mid", "[0-9a-f]{32}", "Boot machine ID"),
        ("boot_host", "[a-z0-9][a-z0-9-]{0,62}", "Boot hostname"),
    ):
        value = values[key]
        if value is not None and (
            not re.fullmatch(pattern, value) or (key == "boot_mid" and value == "0" * 32)
        ):
            identity_problems.append(label + " has an invalid format.")
    if not valid_mode:
        identity_problems.append("Identity cannot be matched to a valid boot mode.")
    elif values["ready"] is not None and values["ready"] != mode:
        identity_problems.append("Identity readiness mode does not match the boot mode.")
    if baseline:
        for key, label, baseline_key in (
            ("seed", "Session seed", "seed"),
            ("boot_mid", "Boot machine ID", "machine_id"),
            ("machine_id", "System machine ID (/etc/machine-id)", "machine_id"),
            ("boot_host", "Boot hostname", "hostname"),
            ("hostname", "Kernel hostname", "hostname"),
            ("stored_hostname", "Stored hostname (/etc/hostname)", "hostname"),
        ):
            value = values[key]
            if value is not None and digest(value) != baseline.get(baseline_key):
                identity_problems.append(label + " changed from the activation baseline.")
    else:
        for key, reference, label in (
            ("machine_id", "boot_mid", "System machine ID does not match the boot machine ID."),
            ("hostname", "boot_host", "Kernel hostname does not match the boot hostname."),
            ("stored_hostname", "boot_host", "Stored hostname does not match the boot hostname."),
        ):
            if values[key] is not None and values[reference] is not None:
                if values[key] != values[reference]:
                    identity_problems.append(label)
    if not identity_problems:
        evidence.update({
            "seed": digest(values["seed"]),
            "machine_id": digest(values["machine_id"]),
            "hostname": digest(values["hostname"]),
        })
    checks.append(check_result(
        "identity", not identity_problems, detail=" ".join(identity_problems)
    ))
    clock_problems = []
    clock_evidence = {}
    try:
        profile = key_values(IDENTITY / "clock-fuzz-profile")
        clock_problems.extend(session_guard_network.clock_problems(expected_mode, profile))
        if not clock_problems:
            clock_evidence = {
                key: digest(value) for key, value in profile.items() if key != "CURRENT_TICK"
            }
            if baseline is not None:
                previous_generated = baseline.get("generated_identity", {})
                previous_clock = (
                    previous_generated.get("clock_profile", {})
                    if isinstance(previous_generated, dict) else {}
                )
                for key, value in clock_evidence.items():
                    if not isinstance(previous_clock, dict) or previous_clock.get(key) != value:
                        clock_problems.append("Clock Fuzz " + key + " changed or lacks a verified activation baseline.")
    except (OSError, ValueError, UnicodeError, GuardError):
        clock_problems.append("Clock Fuzz profile is missing, unreadable, malformed or not trusted.")
    checks.append(check_result("clock", not clock_problems, detail=" ".join(clock_problems)))
    nuke_problems = []
    for path, label, failure in (
        (Path("/sys/kernel/kexec_crash_loaded"), "Crash-kernel status", "Nuke crash kernel is not loaded."),
        (Path("/proc/sys/kernel/kexec_load_disabled"), "Kexec loader status", "Kexec loader is not locked."),
    ):
        value = observed_text(path, label, nuke_problems, 8)
        if value is not None and value != "1":
            nuke_problems.append(failure)
    checks.append(check_result("nuke", not nuke_problems, detail=" ".join(nuke_problems)))
    lock_descriptor, firewall_pending = readiness_lock(states, expected_mode)
    profiles = ("lonewolf", "lockdown") if expected_mode == "lonewolf" else ("normal", "lockdown")
    firewall_problems = readiness_problems(IDENTITY / "firewall-ready", profiles, boottime())
    checks.append(check_result(
        "firewall", not firewall_problems, detail=" ".join(firewall_problems)
    ))
    if expected_mode != "lonewolf":
        packet_problems = readiness_problems(
            IDENTITY / "packet-transformation-engine-guard-ready",
            ("normal", "lockdown"), boottime(), True,
        )
        checks.append(check_result(
            "packet_engine", not packet_problems, detail=" ".join(packet_problems)
        ))
    if lock_descriptor is not None:
        os.close(lock_descriptor)
    if firewall_pending:
        checks = [
            check_result(
                item["code"], False, True,
                detail="A firewall policy update holds the shared firewall lock.",
            )
            if item["code"] in ("firewall", "packet_engine")
            else item
            for item in checks
        ]
    prefix = "ph4ntxm-lonewolf" if expected_mode == "lonewolf" else "ph4ntxm"
    dependencies = {
        "mode": ("ph4ntxm-mode.service",),
        "identity": (prefix + "-identity-randomization.service",),
        "clock": ("ph4ntxm-clock-fuzz.service",),
        "nuke": ("ph4ntxm-arm-nuke.service",),
        "firewall": (prefix + "-firewall-guard.service", "ph4ntxm-lonewolf.service" if expected_mode == "lonewolf" else "ph4ntxm-nft-rules.service"),
        "packet_engine": ("ph4ntxm-packet-transformation-engine.service", "ph4ntxm-packet-transformation-engine-guard.service"),
    }
    checks = [
        check_result(
            item["code"], False, True,
            detail="Waiting for service transitions: " + ", ".join(
                name for name in dependencies.get(item["code"], ())
                if unit_pending(states.get(name, {}))
            ) + ".",
        )
        if not item["healthy"] and any(
            unit_pending(states.get(name, {}))
            for name in dependencies.get(item["code"], ())
        )
        else item
        for item in checks
    ]
    generated_checks, generated = collect_generated(
        expected_mode, values["seed"], values["boot_host"],
        None if baseline is None else baseline.get("generated_identity", {}),
    )
    checks.extend(generated_checks)
    generated["clock_profile"] = clock_evidence
    evidence["generated_identity"] = generated
    generated_dependencies = {
        "persona": (prefix + "-hardware-randomization.service", prefix + "-cores-randomization.service", prefix + "-cpu-spoof.service"),
        "dmi": (prefix + "-hardware-randomization.service",),
        "graphics": (prefix + "-gpu-randomization.service", prefix + "-screen-randomization.service"),
        "mac": (prefix + "-identity-randomization.service",),
        "dhcp": (prefix + "-dhcp-session-generator.service",),
        "network_profile": (prefix + "-net-randomization.service",),
        "name_resolution": (prefix + "-identity-randomization.service",),
    }
    for item in generated_checks:
        pending = [
            name for name in generated_dependencies[item["code"]]
            if unit_pending(states.get(name, {}))
        ]
        if not item["healthy"] and pending:
            item.update(check_result(
                item["code"], False, True,
                detail="Waiting for service transitions: " + ", ".join(pending) + ".",
            ))
    evidence["runtime_mode"] = mode
    return mode, checks, evidence


def new_state(boot_id):
    return {
        "schema": SCHEMA,
        "boot_id": boot_id,
        "enabled": False,
        "generation": uuid.uuid4().hex,
        "baseline": None,
        "checks": [],
        "incidents": [],
        "pending_since": {},
        "sequence": 0,
        "mode": "unknown",
        "last_poll": None,
        "available": True,
    }


def validate_state(value, boot_id):
    if (
        not isinstance(value, dict)
        or value.get("schema") != SCHEMA
        or value.get("boot_id") != boot_id
        or type(value.get("enabled")) is not bool
        or not re.fullmatch("[0-9a-f]{32}", str(value.get("generation", "")))
        or not isinstance(value.get("incidents"), list)
        or len(value["incidents"]) > MAX_HISTORY
        or not isinstance(value.get("checks"), list)
        or not isinstance(value.get("pending_since"), dict)
        or type(value.get("sequence")) is not int
    ):
        raise GuardError("state")
    baseline = value.get("baseline")
    if value["enabled"]:
        if (
            not isinstance(baseline, dict)
            or baseline.get("runtime_mode") not in ("linux", "windows", "lonewolf")
            or any(
                not re.fullmatch("[0-9a-f]{64}", str(baseline.get(key, "")))
                for key in ("mode", "seed", "machine_id", "hostname")
            )
        ):
            raise GuardError("state")
    for incident in value["incidents"]:
        if (
            not isinstance(incident, dict)
            or incident.get("code") not in CATALOG
            or type(incident.get("active")) is not bool
            or not re.fullmatch("[0-9a-f]{32}", str(incident.get("id", "")))
        ):
            raise GuardError("state")
    return value


def snapshot(state):
    return {
        "ok": True,
        "schema": SCHEMA,
        "available": state["available"],
        "enabled": state["enabled"],
        "generation": state["generation"],
        "mode": state["mode"],
        "sequence": state["sequence"],
        "last_poll_boottime": state["last_poll"],
        "poll_interval": INTERVAL,
        "checks": state["checks"],
        "incidents": state["incidents"],
    }


def advance(state, mode, checks, now):
    state["mode"] = mode
    state["checks"] = checks
    state["last_poll"] = now
    state["sequence"] += 1
    state["available"] = True
    if not state["enabled"]:
        return
    if not any(item["code"] == "observer" for item in checks):
        for incident in state["incidents"]:
            if incident["code"] == "observer" and incident["active"]:
                incident["active"] = False
                incident["resolved_boottime"] = now
    for check in checks:
        code = check["code"]
        active = next((item for item in state["incidents"] if item["code"] == code and item["active"]), None)
        if check["status"] == "pending":
            started = state["pending_since"].setdefault(code, now)
            if now - started < TRANSITION_AGE:
                continue
            check["status"] = "failed"
            check["detail"] += " The transition did not finish within 30 seconds."
        else:
            state["pending_since"].pop(code, None)
        if check["healthy"]:
            if active:
                active["active"] = False
                active["resolved_boottime"] = now
        elif active:
            active["detail"] = check["detail"]
        else:
            title, detail = CATALOG[code]
            state["incidents"].append({
                "id": uuid.uuid4().hex,
                "code": code,
                "severity": "warning",
                "title": title,
                "detail": check["detail"],
                "mode": mode,
                "active": True,
                "first_seen_boottime": now,
                "resolved_boottime": None,
            })
    if len(state["incidents"]) > MAX_HISTORY:
        inactive = [item for item in state["incidents"] if not item["active"]]
        active = [item for item in state["incidents"] if item["active"]]
        if len(active) < MAX_HISTORY:
            state["incidents"] = inactive[-(MAX_HISTORY - len(active)):] + active
        else:
            state["incidents"] = active[-MAX_HISTORY:]


class Store:
    def __init__(self):
        protected_directory(Path("/run"))
        ensure_runtime()
        boot_id = read_text(BOOT_ID, 64)
        if STATE.exists() or STATE.is_symlink():
            self.state = validate_state(json.loads(read_protected(STATE, MAX_STATE, private=True)), boot_id)
        else:
            self.state = new_state(boot_id)
        self.persist()

    def persist(self):
        atomic_json(STATE, self.state, 0o600)
        atomic_json(PUBLIC, snapshot(self.state), 0o644)

    def poll(self):
        try:
            mode, checks, evidence = collect(
                self.state["baseline"] if self.state["enabled"] else None
            )
            if mode == "unknown" and self.state["mode"] in ("linux", "windows", "lonewolf"):
                mode = self.state["mode"]
        except Exception:
            mode, checks = self.state["mode"], [check_result("observer", False)]
        advance(self.state, mode, checks, boottime())
        self.persist()

    def request(self, request):
        if (
            not isinstance(request, dict)
            or set(request) != {"action", "generation"}
            or request["action"] not in ("enable", "disable")
            or not isinstance(request["generation"], str)
        ):
            raise GuardError("request")
        if request["generation"] != self.state["generation"]:
            raise GuardError("stale")
        enabled = request["action"] == "enable"
        if enabled == self.state["enabled"]:
            return snapshot(self.state)
        if enabled:
            mode, checks, evidence = collect()
            if not checks or not all(item["healthy"] for item in checks):
                advance(self.state, mode, checks, boottime())
                self.persist()
                raise GuardError("not_ready")
            self.state["baseline"] = evidence
            self.state["mode"] = mode
            self.state["checks"] = checks
        else:
            self.state["baseline"] = None
            for incident in self.state["incidents"]:
                if incident["active"]:
                    incident["active"] = False
                    incident["resolved_boottime"] = boottime()
        self.state["enabled"] = enabled
        self.state["generation"] = uuid.uuid4().hex
        self.state["pending_since"] = {}
        self.state["sequence"] += 1
        self.persist()
        return snapshot(self.state)


def receive(connection):
    connection.settimeout(2)
    data = bytearray()
    while b"\n" not in data:
        chunk = connection.recv(MAX_INPUT + 1 - len(data))
        if not chunk:
            raise GuardError("request")
        data.extend(chunk)
        if len(data) > MAX_INPUT:
            raise GuardError("request")
    line, separator, trailing = data.partition(b"\n")
    if trailing:
        raise GuardError("request")
    return json.loads(line)


def error_result(code):
    return {"ok": False, "error": code, "message": ERRORS[code]}


def serve():
    if os.geteuid() != 0:
        raise GuardError("permission")
    os.umask(0o077)
    ensure_runtime()
    lock_fd = os.open(RUNTIME / "daemon.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    store = Store()
    if CONTROL.exists() or CONTROL.is_symlink():
        info = CONTROL.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            raise GuardError("state")
        CONTROL.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(CONTROL))
        os.chmod(CONTROL, 0o600)
        server.listen(4)
        server.setblocking(False)
        selector = selectors.DefaultSelector()
        selector.register(server, selectors.EVENT_READ)
        next_poll = 0.0
        while True:
            now = boottime()
            if now >= next_poll:
                store.poll()
                next_poll = boottime() + INTERVAL
            events = selector.select(max(0.0, min(INTERVAL, next_poll - boottime())))
            for key, mask in events:
                connection, address = server.accept()
                with connection:
                    try:
                        pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        if uid != 0:
                            raise GuardError("permission")
                        result = store.request(receive(connection))
                    except GuardError as error:
                        result = error_result(error.code)
                    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
                        result = error_result("unavailable")
                    try:
                        connection.sendall(json.dumps(result, separators=(",", ":")).encode("ascii") + b"\n")
                    except OSError:
                        pass


def entry():
    try:
        if sys.argv[1:] == ["daemon"]:
            serve()
            return 0
        if sys.argv[1:] == ["status"]:
            result = json.loads(read_protected(PUBLIC, MAX_PUBLIC))
        elif len(sys.argv) == 2 and sys.argv[1] in ("enable", "disable"):
            if os.geteuid() != 0:
                raise GuardError("permission")
            data = sys.stdin.buffer.read(MAX_INPUT + 1)
            if len(data) > MAX_INPUT:
                raise GuardError("request")
            request = json.loads(data)
            if (
                not isinstance(request, dict)
                or set(request) != {"generation"}
                or not re.fullmatch("[0-9a-f]{32}", str(request["generation"]))
            ):
                raise GuardError("request")
            protected_directory(RUNTIME)
            info = CONTROL.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
                raise GuardError("unavailable")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(8)
                client.connect(str(CONTROL))
                client.sendall(json.dumps({"action": sys.argv[1], "generation": request["generation"]}).encode("ascii") + b"\n")
                response = bytearray()
                while b"\n" not in response:
                    chunk = client.recv(MAX_PUBLIC + 1 - len(response))
                    if not chunk or len(response) + len(chunk) > MAX_PUBLIC:
                        raise GuardError("unavailable")
                    response.extend(chunk)
                result = json.loads(response)
        else:
            raise GuardError("request")
    except GuardError as error:
        result = error_result(error.code)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        result = error_result("unavailable")
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("ok") else 1
