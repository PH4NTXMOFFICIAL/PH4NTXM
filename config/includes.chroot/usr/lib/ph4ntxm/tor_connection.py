# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import base64
import binascii
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid

RUNTIME = Path("/run/ph4ntxm-tor-connection")
STATE = RUNTIME / "state.json"
PUBLIC = RUNTIME / "snapshot.json"
EXPECTATION = RUNTIME / "expectation.json"
TORRC = RUNTIME / "torrc"
MODE = Path("/run/ph4ntxm/mode")
LOCK = Path("/run/ph4ntxm/firewall.lock")
TOR_READY = Path("/run/ph4ntxm/tor-ready")
FIREWALL_READY = Path("/run/ph4ntxm/firewall-ready")
LOCKDOWN_STATUS = Path("/run/ph4ntxm-lockdown-status.json")
SOURCE = Path("/usr/lib/ph4ntxm/lonewolf/lonewolf.nft")
SOURCE_HASH = "2456fc9ebef498d86d8a33c497242577494704e947dec00b006262bca9688fcc"
LOCKDOWN = Path("/etc/firewall/lockdown.nft")
LOCKDOWN_HASH = "7fe94742884f1b20f84980701594811371a2c8c4a0b255cb0071a6eadab36d26"
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
TRANSPORT = Path("/usr/bin/obfs4proxy")
ACCEPT = '        meta skuid "debian-tor" meta l4proto tcp accept'
MAX_INPUT = 16384
ERROR = "Tor connection could not be activated. Network access remains blocked."


class ConnectionError(Exception):
    pass


def digest(value):
    return hashlib.sha256(value).hexdigest()


def protected_directory(path, modes=None):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ConnectionError("Trusted runtime directory is unavailable.")
    if modes is not None and stat.S_IMODE(info.st_mode) not in modes:
        raise ConnectionError("Trusted runtime directory is unavailable.")


def read_protected(path, limit=MAX_INPUT, mode=None, group=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ConnectionError("Trusted configuration is unavailable.")
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            raise ConnectionError("Trusted configuration is unavailable.")
        if group is not None and info.st_gid != group:
            raise ConnectionError("Trusted configuration is unavailable.")
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise ConnectionError("Configuration exceeds its size limit.")
        return data


def atomic(path, data, mode, group=0):
    descriptor, temporary = tempfile.mkstemp(prefix=".connection-", dir=RUNTIME)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchown(handle.fileno(), 0, group)
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def decode(data):
    def pairs(items):
        values = {}
        for key, value in items:
            if key in values:
                raise ValueError("duplicate key")
            values[key] = value
        return values

    return json.loads(data.decode("ascii"), object_pairs_hook=pairs)


def boot_id():
    value = BOOT_ID.read_text(encoding="ascii").strip()
    if str(uuid.UUID(value)) != value:
        raise ConnectionError("Boot identity is unavailable.")
    return value


def lonewolf():
    if read_protected(MODE, 32) != b"lonewolf\n":
        raise ConnectionError("Lone Wolf mode is required.")


def root():
    if os.geteuid() != 0:
        raise ConnectionError("Administrator authentication is required.")


@contextlib.contextmanager
def locked():
    protected_directory(LOCK.parent)
    descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ConnectionError("Firewall lock is unavailable.")
        deadline = time.monotonic() + 10
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ConnectionError(
                        "Another network operation is still active."
                    ) from None
                time.sleep(0.05)
        yield
    finally:
        os.close(descriptor)


def runtime():
    protected_directory(RUNTIME.parent)
    try:
        RUNTIME.mkdir(mode=0o755)
        RUNTIME.chmod(0o755)
    except FileExistsError:
        pass
    protected_directory(RUNTIME, {0o755})


def parse_bridges(text):
    if not isinstance(text, str) or len(text) > 8192 or not text.isascii():
        raise ConnectionError("Enter up to eight valid obfs4 bridge lines.")
    if any(
        (ord(char) < 32 and char not in "\t\r\n") or ord(char) == 127
        for char in text
    ):
        raise ConnectionError("Bridge lines contain unsupported control characters.")
    if "\r" in text.replace("\r\n", ""):
        raise ConnectionError("Use a new line between obfs4 bridge entries.")
    bridges = []
    endpoints = set()
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        fields = line.split()
        if fields and fields[0] == "Bridge":
            fields.pop(0)
        if len(fields) not in (4, 5) or fields[0] != "obfs4":
            raise ConnectionError("Only obfs4 bridge lines are supported.")
        match = re.fullmatch(r"([0-9.]+):([0-9]{1,5})", fields[1])
        if not match:
            raise ConnectionError("A public IPv4 bridge address and port are required.")
        try:
            address = ipaddress.IPv4Address(match[1])
        except ipaddress.AddressValueError:
            raise ConnectionError(
                "A public IPv4 bridge address and port are required."
            ) from None
        port = int(match[2])
        blocked = (
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        )
        if (
            not address.is_global
            or address.is_multicast
            or address.is_reserved
            or any(address in ipaddress.IPv4Network(network) for network in blocked)
            or not 1 <= port <= 65535
        ):
            raise ConnectionError("A public IPv4 bridge address and port are required.")
        fingerprint = ""
        options = fields[2:]
        if len(fields) == 5:
            if not re.fullmatch(r"[0-9A-Fa-f]{40}", options[0]):
                raise ConnectionError("The bridge fingerprint is invalid.")
            fingerprint = options.pop(0).upper()
        values = {}
        for option in options:
            key, separator, value = option.partition("=")
            if not separator or key not in {"cert", "iat-mode"} or key in values:
                raise ConnectionError("The obfs4 certificate or iat-mode is invalid.")
            values[key] = value
        if (
            set(values) != {"cert", "iat-mode"}
            or not re.fullmatch(r"[A-Za-z0-9+/]{70}", values["cert"])
            or not re.fullmatch(r"[012]", values["iat-mode"])
        ):
            raise ConnectionError("The obfs4 certificate or iat-mode is invalid.")
        certificate = values["cert"]
        try:
            decoded = base64.b64decode(certificate + "==", validate=True)
        except binascii.Error:
            raise ConnectionError("The obfs4 certificate is invalid.") from None
        if (
            len(decoded) != 52
            or base64.b64encode(decoded).decode("ascii").rstrip("=") != certificate
        ):
            raise ConnectionError("The obfs4 certificate is invalid.")
        endpoint = (str(address), port)
        if endpoint in endpoints:
            raise ConnectionError("Duplicate bridge endpoints are not allowed.")
        endpoints.add(endpoint)
        normalized = ["obfs4", f"{address}:{port}"]
        if fingerprint:
            normalized.append(fingerprint)
        normalized.extend([f"cert={certificate}", f"iat-mode={values['iat-mode']}"])
        bridges.append(" ".join(normalized))
        if len(bridges) > 8:
            raise ConnectionError("Enter up to eight obfs4 bridges.")
    if not bridges:
        raise ConnectionError("At least one obfs4 bridge is required.")
    return bridges


def new_state(mode="pending", bridges=None, phase="configuring", error=""):
    return {
        "boot_id": boot_id(),
        "generation": str(uuid.uuid4()),
        "mode": mode,
        "phase": phase,
        "bridges": bridges or [],
        "error": error,
    }


def validate_state(state):
    if not isinstance(state, dict) or set(state) != {
        "boot_id",
        "generation",
        "mode",
        "phase",
        "bridges",
        "error",
    }:
        raise ConnectionError("Connection state is unavailable.")
    if (
        state["boot_id"] != boot_id()
        or not isinstance(state["generation"], str)
        or str(uuid.UUID(state["generation"])) != state["generation"]
    ):
        raise ConnectionError("Connection state is unavailable.")
    if state["mode"] not in {"pending", "direct", "obfs4"} or state["phase"] not in {
        "configuring",
        "connecting",
        "error",
    }:
        raise ConnectionError("Connection state is unavailable.")
    if not isinstance(state["bridges"], list) or not all(
        isinstance(line, str) for line in state["bridges"]
    ):
        raise ConnectionError("Connection state is unavailable.")
    if state["mode"] == "obfs4":
        if parse_bridges("\n".join(state["bridges"])) != state["bridges"]:
            raise ConnectionError("Connection state is unavailable.")
    elif state["bridges"]:
        raise ConnectionError("Connection state is unavailable.")
    if state["error"] not in {"", ERROR} or (
        state["mode"] == "pending" and state["phase"] == "connecting"
    ):
        raise ConnectionError("Connection state is unavailable.")
    return state


def load_state():
    protected_directory(RUNTIME, {0o755})
    return validate_state(decode(read_protected(STATE, mode=0o600)))


def render(state):
    source = read_protected(SOURCE, 16384)
    if digest(source) != SOURCE_HASH:
        raise ConnectionError("Lone Wolf firewall verification failed.")
    text = source.decode("ascii")
    if text.count(ACCEPT + "\n") != 1:
        raise ConnectionError("Lone Wolf firewall verification failed.")
    replacement = ""
    if state["phase"] == "connecting":
        if state["mode"] == "direct":
            replacement = ACCEPT + "\n"
        elif state["mode"] == "obfs4":
            endpoints = [line.split()[1].split(":") for line in state["bridges"]]
            tuples = ", ".join(f"{address} . {int(port)}" for address, port in endpoints)
            replacement = (
                '        meta skuid "debian-tor" '
                f"ip daddr . tcp dport {{ {tuples} }} accept\n"
            )
    return text.replace(ACCEPT + "\n", replacement).encode("ascii")


def tor_config(state):
    if state["phase"] != "connecting":
        return b"DisableNetwork 1\nUseBridges 0\n"
    if state["mode"] == "direct":
        return b"DisableNetwork 0\nUseBridges 0\n"
    if state["mode"] != "obfs4":
        raise ConnectionError("Connection state is unavailable.")
    lines = [
        "DisableNetwork 0",
        "UseBridges 1",
        "UpdateBridgesFromAuthority 0",
        "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy",
    ]
    lines.extend("Bridge " + line for line in state["bridges"])
    return ("\n".join(lines) + "\n").encode("ascii")


def public_state(state):
    return {
        "ok": True,
        "generation": state["generation"],
        "mode": state["mode"],
        "phase": state["phase"],
        "bridge_count": len(state["bridges"]),
        "error": state["error"],
    }


def publish(state):
    atomic(STATE, encoded(state), 0o600)
    atomic(PUBLIC, encoded(public_state(state)), 0o644)


def configure(state):
    config = tor_config(state)
    atomic(TORRC, config, 0o640, pwd.getpwnam("debian-tor").pw_gid)
    expectation = {key: state[key] for key in ("boot_id", "generation", "mode", "phase")}
    expectation["config_sha256"] = digest(config)
    expectation["policy_sha256"] = digest(render(state))
    atomic(EXPECTATION, encoded(expectation), 0o644)


def clear_ready():
    for path in (TOR_READY, FIREWALL_READY):
        path.unlink(missing_ok=True)


def run(arguments, data=None):
    result = subprocess.run(
        arguments,
        input=data,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise ConnectionError(ERROR)


def lockdown_enabled():
    try:
        value = decode(read_protected(LOCKDOWN_STATUS, 128))
        return (
            not isinstance(value, dict)
            or value != {"enabled": False}
            or type(value.get("enabled")) is not bool
        )
    except FileNotFoundError:
        return False
    except (OSError, ConnectionError, ValueError, TypeError, AttributeError):
        return True


def apply_policy(state):
    lonewolf()
    data = render(state)
    if lockdown_enabled():
        data = read_protected(LOCKDOWN, 4096)
        if digest(data) != LOCKDOWN_HASH:
            raise ConnectionError("Lockdown firewall verification failed.")
    run(["/usr/sbin/nft", "-c", "-f", "-"], data)
    run(["/usr/sbin/nft", "-f", "-"], data)
    try:
        run(["/usr/sbin/conntrack", "-F"])
    except (ConnectionError, OSError, subprocess.SubprocessError):
        pass


def stop():
    run(["/usr/bin/systemctl", "stop", "tor@default.service"])


def emergency():
    lonewolf()
    data = (
        b"flush ruleset\n"
        b"table inet ph4ntxm_emergency {\n"
        b"chain input { type filter hook input priority 0; policy drop; }\n"
        b"chain forward { type filter hook forward priority 0; policy drop; }\n"
        b"chain output { type filter hook output priority 0; policy drop; }\n"
        b"}\n"
    )
    run(["/usr/sbin/nft", "-f", "-"], data)


def contain(state):
    try:
        apply_policy(state)
    except (OSError, ValueError, TypeError, ConnectionError, subprocess.SubprocessError):
        emergency()


def failed(state):
    state["phase"] = "error"
    state["error"] = ERROR
    operations = (
        clear_ready,
        lambda: publish(state),
        lambda: configure(state),
        lambda: contain(state),
        stop,
    )
    for operation in operations:
        try:
            operation()
        except (OSError, ValueError, TypeError, ConnectionError, subprocess.SubprocessError):
            pass


def initialize():
    root()
    lonewolf()
    runtime()
    with locked():
        lonewolf()
        try:
            state = load_state()
            if state["phase"] == "configuring":
                if state["mode"] == "pending":
                    configure(state)
                    clear_ready()
                    return public_state(state)
                failed(state)
                return public_state(state)
            if state["phase"] == "connecting":
                verify()
            return public_state(state)
        except FileNotFoundError:
            if not STATE.exists():
                state = new_state()
                publish(state)
                configure(state)
                clear_ready()
                return public_state(state)
        except (OSError, ValueError, TypeError, ConnectionError):
            pass
        state = new_state(phase="error", error=ERROR)
        failed(state)
        raise ConnectionError(ERROR)


def apply(request):
    root()
    lonewolf()
    if not isinstance(request, dict) or set(request) != {"generation", "mode", "bridges"}:
        raise ConnectionError("Invalid connection request.")
    if (
        request["mode"] not in {"direct", "obfs4"}
        or not isinstance(request["generation"], str)
        or not isinstance(request["bridges"], str)
    ):
        raise ConnectionError("Invalid connection request.")
    bridges = parse_bridges(request["bridges"]) if request["mode"] == "obfs4" else []
    if request["mode"] == "direct" and request["bridges"].strip():
        raise ConnectionError("Direct mode does not accept bridge lines.")
    if request["mode"] == "obfs4":
        info = TRANSPORT.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or not info.st_mode & 0o111
        ):
            raise ConnectionError("The system obfs4 transport is unavailable.")
    with locked():
        lonewolf()
        previous = load_state()
        if request["generation"] != previous["generation"]:
            raise ConnectionError("Connection settings changed. Refresh and try again.")
        state = new_state(request["mode"], bridges)
        try:
            publish(state)
            clear_ready()
            apply_policy(state)
            stop()
            configure(state)
            candidate = dict(state, phase="connecting")
            configure(candidate)
            run(
                [
                    "/usr/bin/tor",
                    "--defaults-torrc",
                    "/usr/share/tor/tor-service-defaults-torrc",
                    "-f",
                    "/etc/tor/torrc",
                    "--RunAsDaemon",
                    "0",
                    "--verify-config",
                ]
            )
            lonewolf()
            publish(candidate)
            apply_policy(candidate)
            run(["/usr/bin/systemctl", "--no-block", "start", "tor@default.service"])
            return public_state(candidate)
        except (
            OSError,
            ValueError,
            TypeError,
            ConnectionError,
            subprocess.SubprocessError,
        ):
            failed(state)
            raise ConnectionError(ERROR) from None


def snapshot():
    lonewolf()
    protected_directory(RUNTIME, {0o755})
    value = decode(read_protected(PUBLIC, 2048, mode=0o644))
    if not isinstance(value, dict) or set(value) != {
        "ok",
        "generation",
        "mode",
        "phase",
        "bridge_count",
        "error",
    }:
        raise ConnectionError("Connection status is unavailable.")
    if (
        value["ok"] is not True
        or value["mode"] not in {"pending", "direct", "obfs4"}
        or value["phase"] not in {"configuring", "connecting", "error"}
        or type(value["bridge_count"]) is not int
        or not 0 <= value["bridge_count"] <= 8
        or value["error"] not in {"", ERROR}
    ):
        raise ConnectionError("Connection status is unavailable.")
    if (
        not isinstance(value["generation"], str)
        or str(uuid.UUID(value["generation"])) != value["generation"]
    ):
        raise ConnectionError("Connection status is unavailable.")
    return value


def verify():
    lonewolf()
    protected_directory(RUNTIME, {0o755})
    value = decode(read_protected(EXPECTATION, 2048, mode=0o644))
    if not isinstance(value, dict) or set(value) != {
        "boot_id",
        "generation",
        "mode",
        "phase",
        "config_sha256",
        "policy_sha256",
    }:
        raise ConnectionError("Connection configuration is unavailable.")
    if (
        value["boot_id"] != boot_id()
        or value["phase"] != "connecting"
        or value["mode"] not in {"direct", "obfs4"}
    ):
        raise ConnectionError("Tor connection is not ready.")
    public = snapshot()
    if any(public[key] != value[key] for key in ("generation", "mode", "phase")):
        raise ConnectionError("Connection configuration is stale.")
    group = pwd.getpwnam("debian-tor").pw_gid
    config = read_protected(TORRC, mode=0o640, group=group)
    if digest(config) != value["config_sha256"] or not re.fullmatch(
        r"[0-9a-f]{64}", value["policy_sha256"]
    ):
        raise ConnectionError("Connection configuration is stale.")
    if os.geteuid() == 0:
        state = load_state()
        if (
            public != public_state(state)
            or config != tor_config(state)
            or digest(render(state)) != value["policy_sha256"]
        ):
            raise ConnectionError("Connection configuration is stale.")


def entry():
    try:
        if len(sys.argv) != 2:
            raise ConnectionError("Choose a supported connection command.")
        command = sys.argv[1]
        if command == "initialize":
            result = initialize()
        elif command == "apply":
            root()
            data = sys.stdin.buffer.read(MAX_INPUT + 1)
            if len(data) > MAX_INPUT:
                raise ConnectionError("Connection request exceeds its size limit.")
            result = apply(decode(data))
        elif command == "snapshot":
            result = snapshot()
        elif command in {"render", "policy-hash"}:
            root()
            lonewolf()
            data = render(load_state())
            sys.stdout.buffer.write(
                data if command == "render" else (digest(data) + "\n").encode("ascii")
            )
            return 0
        elif command == "verify":
            verify()
            return 0
        else:
            raise ConnectionError("Choose a supported connection command.")
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except ConnectionError as error:
        print(json.dumps({"ok": False, "error": str(error)}, separators=(",", ":")))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print(json.dumps({"ok": False, "error": ERROR}, separators=(",", ":")))
    return 1
