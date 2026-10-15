# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import os
import re
import select
import stat
import subprocess
import time

from .browser_check import parse_preferences, read_protected

STATE = Path("/run/ph4ntxm")
METADATA = Path("/usr/lib/ph4ntxm/browser-mode")
BROWSER = Path("/opt/ph4ntxm/tor-browser/Browser")
PROC_DIRECTORY = Path("/proc")
RUNTIME_DIRECTORY = Path("/run/user")


def read_bounded(path, limit, owner=None):
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("The report source is not a regular file")
        if owner is not None and (metadata.st_uid != owner or metadata.st_mode & 0o022):
            raise ValueError("The report source has unsafe ownership or permissions")
        content = bytearray()
        while len(content) <= limit:
            chunk = os.read(descriptor, min(8192, limit + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > limit:
            raise ValueError("The report source exceeds the size limit")
        return bytes(content)
    finally:
        os.close(descriptor)


def fields(content):
    result = {}
    for line in content.splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if not match or match.group(1) in result:
            raise ValueError("Invalid or duplicate readiness field")
        result[match.group(1)] = match.group(2)
    return result


def current_uptime():
    value = read_bounded(PROC_DIRECTORY / "uptime", 128).decode("ascii").split()[0]
    return int(value.split(".")[0])


def age(record, maximum=None):
    value = record.get("UPTIME_SECONDS", "")
    if not re.fullmatch(r"[0-9]{1,16}", value):
        raise ValueError("The readiness timestamp is invalid")
    elapsed = current_uptime() - int(value)
    if elapsed < 0 or maximum is not None and elapsed > maximum:
        raise ValueError("The readiness record is stale or from the future")
    return elapsed


def command(arguments, timeout=3, limit=65536):
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        close_fds=True,
    )
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("The local status command timed out")
            readable, _, _ = select.select([process.stdout], [], [], remaining)
            if not readable:
                raise TimeoutError("The local status command timed out")
            chunk = os.read(process.stdout.fileno(), 8192)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                raise ValueError("The local status output exceeds the size limit")
        result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return result, output.decode("utf-8", "replace")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        process.stdout.close()


def service_states():
    names = (
        "ph4ntxm-browser-mode.service",
        "ph4ntxm-lonewolf-firewall-guard.service",
        "tor@default.service",
        "ph4ntxm-lonewolf-dns.service",
    )
    _, output = command(["/usr/bin/systemctl", "is-active", *names])
    values = output.splitlines()
    if len(values) != len(names):
        raise ValueError("Service state could not be read")
    return dict(zip(names, values))


def private_directory(path, owner, strict=False):
    metadata = path.lstat()
    mask = 0o077 if strict else 0o022
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner
        or metadata.st_mode & mask
    ):
        raise ValueError("The temporary browser directory is not private")


def held_session_lock(runtime, owner):
    metadata = (runtime / "ph4ntxm-tor-browser.lock").lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner:
        raise ValueError("The browser lock file is unavailable")
    content = read_bounded(PROC_DIRECTORY / "locks", 1024 * 1024).decode("ascii")
    identity = (os.major(metadata.st_dev), os.minor(metadata.st_dev), metadata.st_ino)
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[1:4] != ["FLOCK", "ADVISORY", "WRITE"]:
            continue
        device = parts[5].split(":")
        if len(device) == 3:
            found = (int(device[0], 16), int(device[1], 16), int(device[2]))
            if found == identity:
                return True
    return False


def selected_profile(process, home, owner):
    content = read_bounded(PROC_DIRECTORY / "locks", 1024 * 1024).decode("ascii")
    held = set()
    for line in content.splitlines():
        parts = line.split()
        if (
            len(parts) < 8
            or parts[1:4] != ["POSIX", "ADVISORY", "WRITE"]
            or parts[4] != process.name
        ):
            continue
        device = parts[5].split(":")
        if len(device) == 3:
            held.add((int(device[0], 16), int(device[1], 16), int(device[2])))
    if not held:
        return None
    profiles = set()
    for index, descriptor in enumerate((process / "fd").iterdir()):
        if index >= 4096:
            raise ValueError("The browser descriptor snapshot exceeds the size limit")
        if not descriptor.name.isdecimal():
            continue
        try:
            target = Path(os.readlink(descriptor))
            if target.name != ".parentlock" or not target.is_relative_to(home):
                continue
            opened = descriptor.stat()
            stored = target.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(stored.st_mode)
                or stored.st_uid != owner
                or stored.st_mode & 0o022
                or (opened.st_dev, opened.st_ino) != (stored.st_dev, stored.st_ino)
            ):
                continue
            identity = (os.major(stored.st_dev), os.minor(stored.st_dev), stored.st_ino)
            if identity in held:
                profiles.add(target.parent)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return next(iter(profiles)) if len(profiles) == 1 else None


def process_owned_by(process, owner):
    content = read_bounded(process / "status", 65536).decode("ascii", "replace")
    match = re.search(
        r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", content, re.MULTILINE
    )
    if match is None:
        raise ValueError("The process user could not be identified")
    return all(int(value) == owner for value in match.groups())


def locked_runtime_session(runtime, owner):
    try:
        if not held_session_lock(runtime, owner):
            return None
    except FileNotFoundError:
        return None
    content = read_bounded(PROC_DIRECTORY / "locks", 1024 * 1024).decode("ascii")
    locks = {}
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[1:4] != ["POSIX", "ADVISORY", "WRITE"]:
            continue
        if not parts[4].isdecimal() or parts[6:8] != ["0", "EOF"]:
            continue
        device = parts[5].split(":")
        if len(device) == 3:
            identity = (int(device[0], 16), int(device[1], 16), int(device[2]))
            locks[identity] = parts[4]
    matches = []
    visited = 0
    for index, directory in enumerate(runtime.iterdir()):
        if index >= 4096:
            raise ValueError("The runtime directory snapshot exceeds the size limit")
        if not re.fullmatch(r"ph4ntxm-tor-browser\.[A-Za-z0-9]{6}", directory.name):
            continue
        home = directory / "home"
        browser_home = home / ".tor-browser"
        try:
            for required in (directory, home, browser_home):
                private_directory(required, owner, strict=True)
        except FileNotFoundError:
            continue
        pending = [(browser_home, 0)]
        while pending:
            current, depth = pending.pop()
            directories = []
            matched = False
            for child in current.iterdir():
                visited += 1
                if visited > 8192:
                    raise ValueError(
                        "The private profile snapshot exceeds the size limit"
                    )
                metadata = child.lstat()
                if stat.S_ISDIR(metadata.st_mode) and depth < 5:
                    if metadata.st_uid == owner and not metadata.st_mode & 0o022:
                        directories.append((child, depth + 1))
                if child.name != ".parentlock" or not stat.S_ISREG(metadata.st_mode):
                    continue
                if metadata.st_uid != owner or metadata.st_mode & 0o022:
                    continue
                identity = (
                    os.major(metadata.st_dev),
                    os.minor(metadata.st_dev),
                    metadata.st_ino,
                )
                process_id = locks.get(identity)
                if process_id is None:
                    continue
                process = PROC_DIRECTORY / process_id
                if not process_owned_by(process, owner):
                    continue
                arguments = read_bounded(process / "cmdline", 65536).split(b"\0")
                name = Path(os.fsdecode(arguments[0])).name if arguments[0] else ""
                if (
                    name not in ("firefox", "firefox.real")
                    or b"-contentproc" in arguments
                ):
                    continue
                try:
                    if os.readlink(process / "exe") != str(BROWSER / "firefox.real"):
                        continue
                except PermissionError:
                    pass
                matches.append(
                    {
                        "home": home,
                        "profile": current,
                        "lock_held": True,
                        "evidence": "private_locks",
                    }
                )
                matched = True
            if not matched:
                pending.extend(directories)
    if len(matches) > 1:
        raise ValueError("More than one locked private browser profile was found")
    if not matches:
        raise ValueError(
            "The launcher is active but its locked profile could not be identified"
        )
    return matches[0]


def active_session(owner):
    runtime = RUNTIME_DIRECTORY / str(owner)
    private_directory(runtime, owner, strict=True)
    candidates = []
    unreadable_candidate = False
    for index, entry in enumerate(PROC_DIRECTORY.iterdir()):
        if index >= 16384:
            raise ValueError("The process snapshot exceeds the size limit")
        if not entry.name.isdecimal():
            continue
        try:
            if not process_owned_by(entry, owner):
                continue
            try:
                executable = os.readlink(entry / "exe")
            except PermissionError:
                try:
                    arguments = read_bounded(entry / "cmdline", 65536).split(b"\0")
                except (OSError, ValueError):
                    unreadable_candidate = True
                    continue
                name = Path(os.fsdecode(arguments[0])).name if arguments[0] else ""
                if b"-contentproc" not in arguments and name in (
                    "firefox",
                    "firefox.real",
                ):
                    unreadable_candidate = True
                continue
            if executable != str(BROWSER / "firefox.real"):
                continue
            arguments = read_bounded(entry / "cmdline", 65536).split(b"\0")
            if b"-contentproc" in arguments:
                continue
            environment = read_bounded(entry / "environ", 65536).split(b"\0")
            home_values = [
                item[5:] for item in environment if item.startswith(b"HOME=")
            ]
            originals = [
                item[len(b"BB_ORIGINAL_HOME=") :]
                for item in environment
                if item.startswith(b"BB_ORIGINAL_HOME=")
            ]
            if len(home_values) != 1 or len(originals) > 1:
                raise ValueError("The active browser home could not be identified")
            browser_home = Path(os.fsdecode(home_values[0]))
            home = Path(os.fsdecode(originals[0])) if originals else browser_home
            if originals and browser_home != home / ".tor-browser":
                raise ValueError(
                    "The packaged browser home does not match the launcher"
                )
            if home.name != "home" or home.parent.parent != runtime:
                raise ValueError("The active browser is outside its temporary home")
            if not re.fullmatch(
                r"ph4ntxm-tor-browser\.[A-Za-z0-9]{6}", home.parent.name
            ):
                raise ValueError("The active browser temporary home is invalid")
            private_directory(home.parent, owner, strict=True)
            private_directory(home, owner, strict=True)
            private_directory(browser_home, owner, strict=True)
            profile_values = []
            for position, argument in enumerate(arguments[:-1]):
                if argument.lower() in (b"-profile", b"--profile"):
                    profile_values.append(Path(os.fsdecode(arguments[position + 1])))
            profile = profile_values[0] if len(profile_values) == 1 else None
            selectors = {b"-p", b"-profilemanager", b"--profilemanager"}
            if (
                not profile_values
                and originals
                and not any(argument.lower() in selectors for argument in arguments)
            ):
                try:
                    profile = selected_profile(entry, home, owner)
                except (OSError, ValueError):
                    profile = None
            if profile is not None:
                if (
                    not profile.is_absolute()
                    or ".." in profile.parts
                    or not profile.is_relative_to(home)
                ):
                    raise ValueError(
                        "The active browser profile is outside its temporary home"
                    )
                path = home
                for part in profile.relative_to(home).parts:
                    path /= part
                    private_directory(path, owner)
            candidates.append({"home": home, "profile": profile})
        except PermissionError:
            unreadable_candidate = True
            continue
        except (FileNotFoundError, ProcessLookupError):
            continue
    if len(candidates) > 1:
        raise ValueError("More than one Tor Browser session was found")
    if not candidates or candidates[0]["profile"] is None:
        fallback = locked_runtime_session(runtime, owner)
        if fallback is not None:
            if candidates and fallback["home"] != candidates[0]["home"]:
                raise ValueError(
                    "The locked profile does not match the active browser home"
                )
            return fallback
    if not candidates:
        if unreadable_candidate:
            raise ValueError("A possible browser process could not be inspected")
        return None
    candidates[0]["lock_held"] = held_session_lock(runtime, owner)
    return candidates[0]


def tor_browser_report():
    owner = os.geteuid()
    if owner == 0:
        raise RuntimeError("Run Browser Check as the desktop user, without sudo")
    if read_protected(STATE / "mode", 128).strip() != "lonewolf":
        raise ValueError("This report is available in Lone Wolf mode")
    rows = []

    def add(label, expected, observed, status, detail=""):
        rows.append(
            {
                "label": label,
                "expected": expected,
                "observed": observed,
                "status": status,
                "detail": detail,
            }
        )

    def inspect(label, expected, operation, detail=""):
        try:
            status, observed = operation()
        except (
            OSError,
            ValueError,
            KeyError,
            TimeoutError,
            subprocess.SubprocessError,
        ):
            add(label, expected, "Unavailable", "unavailable", detail)
        else:
            add(label, expected, observed, status, detail)

    def version():
        installed = read_protected(METADATA / "tor-browser.version", 128).strip()
        if not re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z]+)+", installed):
            raise ValueError("Invalid installed version")
        return "info", installed

    inspect("Installed Tor Browser", "Protected installation metadata", version)

    def verification():
        record = fields(read_protected(STATE / "tor-browser-verified", 4096))
        manifest = read_protected(METADATA / "tor-browser.sha256", 4 * 1024 * 1024)
        digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
        age(record)
        good = (
            record.get("MODE") == "lonewolf" and record.get("MANIFEST_SHA256") == digest
        )
        return (
            ("match", "Verified at boot")
            if good
            else ("different", "Verification does not match")
        )

    inspect(
        "Boot verification",
        "Current protected manifest",
        verification,
        "Checks the boot verification record and manifest hash. It does not re-hash the browser bundle.",
    )
    try:
        services = service_states()
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
        services = {}

    def browser_gate():
        if "ph4ntxm-browser-mode.service" not in services:
            raise ValueError("Browser service status is unavailable")
        _, output = command(
            [
                "/usr/bin/findmnt",
                "-rn",
                "-o",
                "OPTIONS",
                "--mountpoint",
                "/usr/lib/firefox-esr",
            ]
        )
        options = set(output.strip().split(","))
        active = services.get("ph4ntxm-browser-mode.service") == "active"
        masked = {"ro", "nosuid", "nodev", "noexec"}.issubset(options)
        return (
            ("match", "Active, ordinary Firefox masked")
            if active and masked
            else ("different", "Gate or Firefox mask is not ready")
        )

    inspect(
        "Browser mode gate", "Active gate and restricted Firefox mount", browser_gate
    )

    def firewall():
        if "ph4ntxm-lonewolf-firewall-guard.service" not in services:
            raise ValueError("Firewall service status is unavailable")
        record = fields(read_protected(STATE / "firewall-ready", 4096))
        source = read_protected(
            "/usr/lib/ph4ntxm/lonewolf/lonewolf.nft.sha256", 128
        ).strip()
        age(record, 6)
        good = (
            record.get("PROFILE") == "lonewolf"
            and re.fullmatch(r"[0-9a-f]{64}", source)
            and record.get("SOURCE_SHA256") == source
            and re.fullmatch(r"[0-9a-f]{64}", record.get("RULESET_SHA256", ""))
            and services.get("ph4ntxm-lonewolf-firewall-guard.service") == "active"
        )
        return (
            ("match", "Fresh Lone Wolf readiness")
            if good
            else ("different", "Not ready")
        )

    inspect("Firewall guardian", "Active and fresh within 6 seconds", firewall)

    def bootstrap():
        if "tor@default.service" not in services:
            raise ValueError("Tor service status is unavailable")
        record = fields(read_protected(STATE / "tor-ready", 4096))
        age(record, 6)
        good = (
            record.get("STATUS") == "ready"
            and record.get("BOOTSTRAP") == "100"
            and services.get("tor@default.service") == "active"
        )
        return (
            ("match", "Ready, bootstrap 100%") if good else ("different", "Not ready")
        )

    inspect("Tor readiness", "Active Tor and fresh bootstrap state", bootstrap)

    def listeners():
        if "ph4ntxm-lonewolf-dns.service" not in services:
            raise ValueError("DNS service status is unavailable")
        found = []
        for flag, ports in (("-ltn4", (53, 9040, 9050)), ("-lun4", (53, 5353))):
            expression = "( " + " or ".join(f"sport = :{port}" for port in ports) + " )"
            code, output = command(["/usr/bin/ss", "-H", flag, expression])
            if code != 0:
                raise ValueError("Listener snapshot failed")
            endpoints = {
                line.split()[3]
                for line in output.splitlines()
                if len(line.split()) >= 4
            }
            found.extend(
                f"{flag[2]}:{port}"
                for port in ports
                if f"127.0.0.1:{port}" in endpoints
            )
        good = (
            len(found) == 5 and services.get("ph4ntxm-lonewolf-dns.service") == "active"
        )
        return (
            ("match", "DNS and Tor loopback listeners ready")
            if good
            else ("different", "One or more local listeners are missing")
        )

    inspect(
        "Local connection points",
        "DNS 53/5353, Tor 9040/9050 on 127.0.0.1",
        listeners,
        "Checks existing local listeners and the DNS service. No connection or network probe is sent.",
    )

    def safest_default():
        content = read_protected(
            BROWSER / "browser/defaults/preferences/00-ph4ntxm-safest.js"
        )
        content = re.sub(r"^pref\(", "user_pref(", content, flags=re.MULTILINE)
        defaults = parse_preferences(content)
        good = (
            type(defaults.get("browser.security_level.security_slider")) is int
            and defaults.get("browser.security_level.security_slider") == 1
            and defaults.get("browser.security_level.security_custom") is False
        )
        return (
            ("info", "Safest prepared")
            if good
            else ("different", "Safest default is not configured")
        )

    inspect(
        "Installed security default",
        "Safest",
        safest_default,
        "This is the installed default. It does not prove the current in-memory browser setting.",
    )
    try:
        session = active_session(owner)
    except (OSError, ValueError):
        session = None
        session_unknown = True
        add(
            "Temporary browser session",
            "Private home under /run/user",
            "Browser session could not be inspected",
            "unavailable",
            "This check requires an open Tor Browser. If it is closed, open it and run "
            "the check again. Access to its temporary session could not be verified.",
        )
    else:
        session_unknown = False
        if session is None:
            add(
                "Temporary browser session",
                "Private home under /run/user",
                "Open Tor Browser and run the check again",
                "info",
                "This check requires an open Tor Browser session.",
            )
        elif session.get("evidence") == "private_locks":
            add(
                "Temporary browser session",
                "Private home and held session locks",
                "Private session and browser profile locks are held",
                "info",
                "Observed from private files and same-user process locks. "
                "The browser executable and environment could not be fully inspected.",
            )
        else:
            add(
                "Temporary browser session",
                "Private home and launcher lock",
                (
                    "Private session with lock held"
                    if session["lock_held"]
                    else "Private home, launcher lock not held"
                ),
                "match" if session["lock_held"] else "different",
            )
    saved = None
    if session is not None and session["profile"] is not None:
        try:
            saved = parse_preferences(
                read_bounded(
                    session["profile"] / "prefs.js",
                    1024 * 1024,
                    owner,
                ).decode("utf-8", "strict")
            )
        except (OSError, ValueError, UnicodeError):
            pass
    if saved is None:
        state = "unavailable" if session is not None or session_unknown else "info"
        if session is not None:
            observed = "Tor Browser is open; saved profile settings could not be read"
            detail = (
                "Keep Tor Browser open and run the check again after startup completes. "
                "These checks require a readable saved profile; no live browser interrogation is performed."
            )
        elif session_unknown:
            observed = "Browser session could not be inspected"
            detail = (
                "These checks require an open Tor Browser and a readable saved profile. "
                "If the browser is closed, open it and run the check again."
            )
        else:
            observed = "Open Tor Browser and run the check again"
            detail = "These checks require an open Tor Browser and its saved profile."
        add("Saved security setting", "Safest", observed, state, detail)
        add(
            "Saved download location", "Temporary browser home", observed, state, detail
        )
    else:
        level = saved.get("browser.security_level.security_slider")
        custom = saved.get("browser.security_level.security_custom")
        if level is None:
            add(
                "Saved security setting", "Safest", "No explicit saved override", "info"
            )
        else:
            name = {1: "Safest", 2: "Safer", 4: "Standard"}.get(level, str(level))
            state = (
                "different"
                if type(level) is not int or level != 1 or custom is True
                else "info"
            )
            add(
                "Saved security setting",
                "Safest",
                name,
                state,
                "Last saved profile value. Changes still in browser memory may not be reflected here.",
            )
        destination = saved.get("browser.download.dir")
        folder = saved.get("browser.download.folderList")
        if saved.get("browser.download.useDownloadDir") is False:
            add(
                "Saved download location",
                "User-selected destination",
                "Ask where to save",
                "info",
            )
        elif folder in (0, 1):
            name = "Desktop" if folder == 0 else "Downloads"
            add(
                "Saved download location",
                "Temporary browser home",
                f"{name} selected",
                "info",
                "Saved folder choice. Its resolved desktop path is not inspected.",
            )
        elif (
            folder == 2
            and isinstance(destination, str)
            and Path(destination).is_absolute()
        ):
            inside = Path(destination).resolve().is_relative_to(session["home"])
            add(
                "Saved download location",
                "Temporary browser home",
                (
                    "Inside the temporary home"
                    if inside
                    else "A location outside the temporary home is selected"
                ),
                "info",
                "This inspects the saved preference, not download history or current file dialogs.",
            )
        else:
            add(
                "Saved download location",
                "Temporary browser home",
                "No explicit saved directory",
                "info",
            )
    return {
        "mode": "lonewolf",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "rows": rows,
        "scope": "Local Tor Browser readiness and saved settings only. "
        "No JavaScript, external requests or browser security changes.",
    }
