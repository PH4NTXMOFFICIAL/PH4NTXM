# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import hashlib
import json
import math
import os
import pwd
import re
import secrets
import select
import shlex
import stat
import subprocess
import time

STATE = Path("/run/ph4ntxm")
METADATA = Path("/usr/lib/ph4ntxm/browser-mode")
TEMPLATES = Path("/etc/firefox-esr/mode")
POLICY = Path("/etc/firefox/policies/policies.json")
FIREFOX = Path("/usr/bin/firefox-esr-real")
TOR_BROWSER = Path("/opt/ph4ntxm/tor-browser")
FIREWALL_MANIFEST = Path("/usr/lib/ph4ntxm/lonewolf/lonewolf.nft.sha256")
GL_LIBRARY = Path("/usr/local/lib/libph4ntxm-gl-spoof.so")
OWNER = 0
CACHE_DIRECTORY = Path("/tmp")
PRELOAD = "case \":${LD_PRELOAD:-}:\" in *:/usr/local/lib/libph4ntxm-gl-spoof.so:*) ;; *) export LD_PRELOAD=\"/usr/local/lib/libph4ntxm-gl-spoof.so${LD_PRELOAD:+:$LD_PRELOAD}\" ;; esac"
GPU_KEYS = frozenset((
    "__GLX_VENDOR_LIBRARY_NAME", "__GL_VENDOR", "__GL_RENDERER_STRING",
    "MESA_GL_VERSION_OVERRIDE", "MESA_GLSL_VERSION_OVERRIDE",
    "MESA_GLES_VERSION_OVERRIDE", "MESA_EXTENSION_OVERRIDE",
    "MESA_VENDOR_OVERRIDE", "MESA_RENDERER_OVERRIDE", "PH4NTXM_GPU_VENDOR",
    "PH4NTXM_GPU_FAMILY", "PH4NTXM_GPU_MODEL", "PH4NTXM_GPU_STACK",
    "PH4NTXM_GL_VENDOR", "PH4NTXM_GL_RENDERER",
))
SERVICES = (
    "ph4ntxm-browser-mode.service",
    "ph4ntxm-lonewolf-firewall-guard.service",
    "tor@default.service",
    "ph4ntxm-lonewolf-dns.service",
)


@dataclass(frozen=True)
class BrowserPlan:
    mode: str
    command: tuple
    environment: dict
    readonly_paths: tuple
    profile_path: str | None = None
    source_digests: tuple = ()


class ProfileError(ValueError):
    pass


def protected_directory(path):
    info = Path(path).lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
        raise ProfileError(f"Unprotected browser directory: {path}")


def read_protected(path, limit=65536):
    path = Path(path)
    protected_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
            raise ProfileError(f"Unprotected browser state: {path.name}")
        content = bytearray()
        while len(content) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(content)))
            if not chunk:
                return bytes(content)
            content.extend(chunk)
        raise ProfileError(f"Browser state exceeds the size limit: {path.name}")
    finally:
        os.close(descriptor)


def protected_executable(path):
    resolved = Path(path).resolve(strict=True)
    protected_directory(resolved.parent)
    info = resolved.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != OWNER
        or info.st_mode & 0o7022
        or not info.st_mode & 0o111
    ):
        raise ProfileError(f"Trusted browser executable is unavailable: {path}")


def parse_exports(raw, kind):
    content = raw.decode("ascii", "strict")
    if len(content.splitlines()) > 128:
        raise ProfileError("Too many browser identity fields")
    values = {}
    preload = False
    for line in content.splitlines():
        if kind == "gpu" and line == PRELOAD and not preload:
            preload = True
            continue
        words = shlex.split(line, posix=True)
        if len(words) != 2 or words[0] != "export":
            raise ProfileError("Invalid browser identity export")
        key, separator, value = words[1].partition("=")
        if (
            not separator
            or key in values
            or len(value) > 8192
            or any(ord(char) < 32 for char in value)
            or (kind == "gpu" and key not in GPU_KEYS)
            or (kind != "gpu" and not re.fullmatch(r"PH4_[A-Z0-9_]{1,60}", key))
        ):
            raise ProfileError("Invalid browser identity field")
        values[key] = value
    if kind == "gpu":
        required = {"PH4NTXM_GL_VENDOR", "PH4NTXM_GL_RENDERER", "PH4NTXM_GPU_STACK"}
        if not preload or any(not values.get(key) for key in required):
            raise ProfileError("The browser GPU identity is incomplete")
        values["LD_PRELOAD"] = str(GL_LIBRARY)
    return values


def command(arguments, timeout=4, limit=65536):
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise ProfileError("Browser prerequisite check timed out")
            chunk = os.read(process.stdout.fileno(), 8192)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                raise ProfileError("Browser prerequisite output exceeds the size limit")
        result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if result:
            raise ProfileError("Browser prerequisite check failed")
        return output.decode("utf-8", "strict")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        process.stdout.close()


def render_preferences(template, browser, cores, version):
    try:
        dpr = browser["PH4_DEVICE_PIXEL_RATIO"]
        count = cores["PH4_REPORTED_CORES"]
        architecture = cores["PH4_CPU_ARCHITECTURE"]
        valid = (
            re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", dpr)
            and math.isfinite(float(dpr))
            and 0 < float(dpr) <= 16
            and re.fullmatch(r"[1-9][0-9]{0,5}", count)
            and 1 <= int(count) <= 65536
            and architecture in ("x86_64", "aarch64")
        )
    except (KeyError, ValueError, OverflowError):
        valid = False
    if not valid:
        raise ProfileError("The session browser identity is incomplete or invalid")
    major = re.search(r"\b([0-9]{1,6})(?:\.[0-9]+)+(?:esr)?\b", version)
    if not major:
        raise ProfileError("Unable to determine the installed Firefox version")
    replacements = {"DPR": dpr, "CORES": count, "ARCH": architecture, "FIREFOX_MAJOR": major[1]}
    for key, value in replacements.items():
        template = template.replace("{{" + key + "}}", value)
    if "{{" in template or "}}" in template:
        raise ProfileError("The browser template has unresolved identity fields")
    preferences = {
        "browser.download.dir": "/workspace/downloads",
        "browser.download.folderList": 2,
        "browser.download.useDownloadDir": True,
        "browser.download.always_ask_before_handling_new_types": True,
    }
    return template.rstrip() + "\n" + "".join(
        f"user_pref({json.dumps(key)}, {json.dumps(value)});\n"
        for key, value in preferences.items()
    )


def validate_identity(browser, gpu):
    dimensions = ("PH4_SCREEN_WIDTH", "PH4_SCREEN_HEIGHT", "PH4_VIEWPORT_WIDTH", "PH4_VIEWPORT_HEIGHT")
    for key in dimensions:
        if not re.fullmatch(r"[1-9][0-9]{0,5}", browser.get(key, "")) or int(browser[key]) > 131072:
            raise ProfileError("The session browser display identity is incomplete or invalid")
    if (
        int(browser["PH4_VIEWPORT_WIDTH"]) > int(browser["PH4_SCREEN_WIDTH"])
        or int(browser["PH4_VIEWPORT_HEIGHT"]) > int(browser["PH4_SCREEN_HEIGHT"])
        or browser.get("PH4_DISPLAY_COUNT") not in ("1", "2")
        or not browser.get("PH4_PRIMARY_DISPLAY")
        or not browser.get("PH4_SECONDARY_DISPLAY")
    ):
        raise ProfileError("The session browser display identity is incomplete or invalid")
    common = ("PH4NTXM_GPU_VENDOR", "PH4NTXM_GPU_FAMILY", "PH4NTXM_GPU_MODEL", "PH4NTXM_GL_VENDOR", "PH4NTXM_GL_RENDERER")
    if any(not gpu.get(key) for key in common):
        raise ProfileError("The browser GPU identity is incomplete")
    stack = gpu.get("PH4NTXM_GPU_STACK")
    if stack == "nvidia":
        if gpu.get("__GLX_VENDOR_LIBRARY_NAME") != "nvidia":
            raise ProfileError("The browser NVIDIA identity is incomplete")
        required = {"__GL_VENDOR": gpu["PH4NTXM_GL_VENDOR"], "__GL_RENDERER_STRING": gpu["PH4NTXM_GL_RENDERER"]}
    elif stack in ("mesa", "mesa-radv", "mesa-asahi"):
        required = {"MESA_VENDOR_OVERRIDE": gpu["PH4NTXM_GL_VENDOR"], "MESA_RENDERER_OVERRIDE": gpu["PH4NTXM_GL_RENDERER"]}
        for key in ("MESA_GL_VERSION_OVERRIDE", "MESA_GLSL_VERSION_OVERRIDE", "MESA_EXTENSION_OVERRIDE"):
            if not gpu.get(key):
                raise ProfileError("The browser Mesa identity is incomplete")
    else:
        raise ProfileError("The browser GPU stack is invalid")
    if any(gpu.get(key) != value for key, value in required.items()):
        raise ProfileError("The browser GPU identity is inconsistent")


def readiness_fields(raw):
    values = {}
    for line in raw.decode("ascii", "strict").splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if not match or match[1] in values:
            raise ProfileError("Invalid Tor Browser readiness state")
        values[match[1]] = match[2]
    return values


def check_age(record, uptime, maximum=None):
    value = record.get("UPTIME_SECONDS", "")
    if not re.fullmatch(r"[0-9]{1,16}", value):
        raise ProfileError("Invalid Tor Browser readiness time")
    age = uptime - int(value)
    if age < 0 or maximum is not None and age > maximum:
        raise ProfileError("Tor Browser readiness state is stale")


def verify_tor_installation():
    manifest = read_protected(METADATA / "tor-browser.sha256", 8388608)
    version = read_protected(METADATA / "tor-browser.version", 128).decode("ascii").strip()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version):
        raise ProfileError("Invalid Tor Browser installation version")
    protected_directory(TOR_BROWSER)
    if stat.S_IMODE(TOR_BROWSER.lstat().st_mode) != 0o755:
        raise ProfileError("Invalid Tor Browser installation permissions")
    required = (
        "Browser/start-tor-browser", "Browser/firefox", "Browser/firefox.real",
        "Browser/TorBrowser/Tor/tor",
    )
    for relative in required:
        protected_executable(TOR_BROWSER / relative)
    files = []
    count = 0
    total = 0
    for directory, directories, names in os.walk(TOR_BROWSER, followlinks=False):
        for name in directories + names:
            path = Path(directory) / name
            info = path.lstat()
            count += 1
            if count > 65536 or info.st_uid != OWNER:
                raise ProfileError("Invalid Tor Browser installation tree")
            permissions = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode) and permissions == 0o755:
                continue
            if not stat.S_ISREG(info.st_mode) or permissions not in (0o644, 0o755):
                raise ProfileError("Unsafe Tor Browser installation entry")
            relative = path.relative_to(TOR_BROWSER.parent).as_posix()
            if any(ord(char) < 32 or char == "\\" for char in relative):
                raise ProfileError("Unsupported Tor Browser installation filename")
            total += info.st_size
            if total > 2147483648:
                raise ProfileError("Tor Browser installation exceeds the size limit")
            files.append((relative, path))
    lines = []
    hashed_bytes = 0
    for relative, path in sorted(files, key=lambda item: item[0].encode("utf-8")):
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o7022:
                raise ProfileError("Tor Browser installation changed during verification")
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1048576):
                hashed_bytes += len(chunk)
                if hashed_bytes > 2147483648:
                    raise ProfileError("Tor Browser installation exceeds the size limit")
                digest.update(chunk)
        finally:
            os.close(descriptor)
        lines.append(f"{digest.hexdigest()}  {relative}\n")
    if "".join(lines).encode("utf-8") != manifest:
        raise ProfileError("Tor Browser installation does not match its manifest")
    names = {relative for relative, path in files}
    for relative in (
        "tor-browser/Browser/is-packaged-app",
        "tor-browser/Browser/browser/chrome/icons/default/default128.png",
    ):
        if relative not in names:
            raise ProfileError("The verified Tor Browser installation is incomplete")
    return hashlib.sha256(manifest).hexdigest()


def validate_tor_readiness(manifest_hash, uptime=None):
    connection = json.loads(command(["/usr/local/sbin/ph4ntxm-tor-connection-control", "snapshot"]))
    if not isinstance(connection, dict) or connection.get("mode") == "pending":
        raise ProfileError("Choose the Tor connection in Boot Pilot")
    browser = readiness_fields(read_protected(STATE / "tor-browser-verified"))
    firewall = readiness_fields(read_protected(STATE / "firewall-ready"))
    tor = readiness_fields(read_protected(STATE / "tor-ready"))
    source = read_protected(FIREWALL_MANIFEST, 128).decode("ascii").strip()
    if uptime is None:
        uptime = int(Path("/proc/uptime").read_text(encoding="ascii").split(".")[0])
    if browser.get("MODE") != "lonewolf" or browser.get("MANIFEST_SHA256") != manifest_hash:
        raise ProfileError("Tor Browser integrity readiness is stale")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", source)
        or firewall.get("PROFILE") != "lonewolf"
        or firewall.get("SOURCE_SHA256") != source
        or not re.fullmatch(r"[0-9a-f]{64}", firewall.get("RULESET_SHA256", ""))
    ):
        raise ProfileError("Lone Wolf firewall readiness is invalid")
    if tor.get("STATUS") != "ready" or tor.get("BOOTSTRAP") != "100":
        raise ProfileError("Tor bootstrap is incomplete")
    check_age(browser, uptime)
    check_age(firewall, uptime, 6)
    check_age(tor, uptime, 6)
    states = command(["/usr/bin/systemctl", "is-active", *SERVICES]).splitlines()
    if states != ["active"] * len(SERVICES):
        raise ProfileError("Required Lone Wolf services are inactive")
    for protocol, port in (("tcp", 53), ("udp", 53), ("udp", 5353), ("tcp", 9040), ("tcp", 9050)):
        flag = "-ltn4" if protocol == "tcp" else "-lun4"
        output = command(["/usr/bin/ss", "-H", flag, f"sport = :{port}"])
        if not any(len(parts := line.split()) >= 4 and parts[3] == f"127.0.0.1:{port}" for line in output.splitlines()):
            raise ProfileError(f"Required Tor {protocol.upper()} listener is unavailable: {port}")


def source_digests(paths):
    return tuple((str(path), hashlib.sha256(read_protected(path, 8388608)).hexdigest()) for path in paths)


def private_directory_at(parent, name, create=True):
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    except OSError as error:
        raise ProfileError("The Firefox RAM profile directory is unavailable or unsafe") from error
    info = os.fstat(descriptor)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor)
        raise ProfileError("The Firefox RAM profile directory must be private and owned by this account")
    return descriptor


def cached_profile(mode, create=True):
    if mode not in ("linux", "windows"):
        raise ProfileError("Invalid Firefox RAM profile mode")
    root = os.open(CACHE_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    cache = None
    try:
        info = os.fstat(root)
        if info.st_uid != OWNER or stat.S_IMODE(info.st_mode) != 0o1777:
            raise ProfileError("The Firefox RAM profile requires a protected temporary directory")
        name = f"ph4ntxm-firefox-{os.getuid()}-{mode}"
        cache = private_directory_at(root, name, create)
        descriptor = private_directory_at(cache, "profile", create)
        return CACHE_DIRECTORY / name / "profile", descriptor
    finally:
        if cache is not None:
            os.close(cache)
        os.close(root)


def atomic_preferences(directory, content):
    try:
        info = os.stat("user.js", dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ProfileError("The retained Firefox preferences file is unsafe")
    temporary = ".user.js." + secrets.token_hex(16)
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        pending = memoryview(content.encode("utf-8"))
        while pending:
            count = os.write(descriptor, pending)
            if count <= 0:
                raise ProfileError("The Firefox preferences could not be written")
            pending = pending[count:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, "user.js", src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def revalidate_browser(plan):
    mode = read_protected(STATE / "mode", 128).decode("ascii").strip()
    if mode != plan.mode:
        raise ProfileError("The PH4NTXM browser mode changed")
    expected = CACHE_DIRECTORY / f"ph4ntxm-firefox-{os.getuid()}-{mode}" / "profile"
    if mode in ("linux", "windows") and plan.profile_path == str(expected):
        path, descriptor = cached_profile(mode, create=False)
        os.close(descriptor)
    for path, expected in plan.source_digests:
        if hashlib.sha256(read_protected(path, 8388608)).hexdigest() != expected:
            raise ProfileError("The protected browser profile sources changed")
    if mode == "lonewolf":
        manifest = read_protected(METADATA / "tor-browser.sha256", 8388608)
        validate_tor_readiness(hashlib.sha256(manifest).hexdigest())


def prepare_browser(home_directory, sandbox_home="/home/ph4ntxm", username=None, profile_path=None):
    home_directory = Path(home_directory)
    info = home_directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or any(home_directory.iterdir())
    ):
        raise ProfileError("Browser Airlock requires a fresh private home")
    if str(PurePosixPath(sandbox_home)) != sandbox_home or not sandbox_home.startswith(("/home/", "/run/user/")) or ".." in PurePosixPath(sandbox_home).parts:
        raise ProfileError("Invalid isolated browser home")
    username = username or pwd.getpwuid(os.getuid()).pw_name
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise ProfileError("Invalid browser account")
    mode = read_protected(STATE / "mode", 128).decode("ascii").strip()
    if mode not in ("linux", "windows", "lonewolf"):
        raise ProfileError("The PH4NTXM browser mode is unavailable")
    if mode == "lonewolf":
        sandbox_home = str(home_directory.absolute())
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
        "HOME": sandbox_home, "USER": username, "LOGNAME": username,
        "XDG_CONFIG_HOME": sandbox_home + "/.config",
        "XDG_CACHE_HOME": sandbox_home + "/.cache",
        "XDG_DATA_HOME": sandbox_home + "/.local/share",
        "MOZ_DBUS_REMOTE": "1", "GTK_USE_PORTAL": "0",
    }
    if mode == "lonewolf":
        if os.getuid() == 0:
            raise ProfileError("Tor Browser refuses to run as root")
        manifest_hash = verify_tor_installation()
        validate_tor_readiness(manifest_hash)
        browser_home = home_directory / ".tor-browser"
        tor_directory = browser_home / "TorBrowser/Tor"
        browser_home.mkdir(mode=0o700)
        (browser_home / "TorBrowser").mkdir(mode=0o700)
        tor_directory.mkdir(mode=0o700)
        (tor_directory / "tor").touch(mode=0o600)
        environment["PATH"] = "/run/ph4ntxm-browser-tools:" + environment["PATH"]
        environment.update({"TOR_PROVIDER": "none", "TOR_SOCKS_HOST": "127.0.0.1", "TOR_SOCKS_PORT": "9050"})
        digests = source_digests((METADATA / "tor-browser.sha256", METADATA / "tor-browser.version"))
        return BrowserPlan(mode, (str(TOR_BROWSER / "Browser/start-tor-browser"),), environment, (str(TOR_BROWSER),), None, digests)
    private_profile = str(home_directory.absolute() / "profile")
    expected_cache = str(CACHE_DIRECTORY / f"ph4ntxm-firefox-{os.getuid()}-{mode}" / "profile")
    if profile_path is not None and profile_path not in (private_profile, expected_cache):
        raise ProfileError("Invalid isolated Firefox profile path")
    protected_executable(FIREFOX)
    paths = (STATE / "browser_env", STATE / "cores_env", STATE / "gpu_env", STATE / "fonts-active/fonts.conf", GL_LIBRARY, POLICY, TEMPLATES / mode / "user.js")
    sources = {path: read_protected(path, 8388608 if path == GL_LIBRARY else 65536) for path in paths}
    browser = parse_exports(sources[STATE / "browser_env"], "browser")
    cores = parse_exports(sources[STATE / "cores_env"], "cores")
    gpu = parse_exports(sources[STATE / "gpu_env"], "gpu")
    validate_identity(browser, gpu)
    library = sources[GL_LIBRARY]
    if len(library) < 4 or library[:4] != b"\x7fELF":
        raise ProfileError("The browser GL identity library is unavailable")
    template = sources[TEMPLATES / mode / "user.js"].decode("utf-8", "strict")
    preferences = render_preferences(template, browser, cores, command([str(FIREFOX), "--version"], timeout=10))
    digests = tuple((str(path), hashlib.sha256(raw).hexdigest()) for path, raw in sources.items())
    if profile_path == private_profile:
        parent = os.open(home_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            directory = private_directory_at(parent, "profile")
        finally:
            os.close(parent)
    else:
        profile, directory = cached_profile(mode)
        profile_path = str(profile)
    try:
        atomic_preferences(directory, preferences)
    finally:
        os.close(directory)
    environment.update(browser)
    environment.update(cores)
    environment.update(gpu)
    environment.update({"FONTCONFIG_PATH": str(STATE / "fonts-active"), "FONTCONFIG_FILE": str(STATE / "fonts-active/fonts.conf")})
    environment["MOZ_DBUS_REMOTE"] = "1"
    readonly = (str(STATE / "fonts-active"), "/usr/share/fonts", str(GL_LIBRARY), "/usr/lib/firefox-esr", "/etc/firefox-esr", "/etc/firefox/policies")
    return BrowserPlan(mode, (str(FIREFOX), "-profile", profile_path), environment, readonly, profile_path, digests)
