# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import re
import shlex
import stat
import sys

IDENTITY = Path("/run/ph4ntxm")
HARDWARE = Path("/usr/lib/ph4ntxm/hardware")
DMI = Path("/sys/class/dmi/id")
CPUINFO = Path("/proc/cpuinfo")
CPU_SYSFS = Path("/sys/devices/system/cpu")
MOUNTINFO = Path("/proc/1/mountinfo")
GL_LIBRARY = Path("/usr/local/lib/libph4ntxm-gl-spoof.so")
OWNER = 0
PRELOAD = "case \":${LD_PRELOAD:-}:\" in *:/usr/local/lib/libph4ntxm-gl-spoof.so:*) ;; *) export LD_PRELOAD=\"/usr/local/lib/libph4ntxm-gl-spoof.so${LD_PRELOAD:+:$LD_PRELOAD}\" ;; esac"
TITLES = {
    "persona": "Hardware persona consistency",
    "dmi": "DMI identity consistency",
    "graphics": "Graphics identity consistency",
}
_CACHE = None


class ObservationError(ValueError):
    pass


class ProtectedLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return compile(read(Path(self.path), 262144), self.path, "exec", dont_inherit=True)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
        raise ValueError("directory")


def read(path, limit=32768, kernel=False):
    if path == MOUNTINFO:
        path = path.resolve(strict=True)
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
            raise ValueError("file")
        if not kernel and info.st_size > limit:
            raise ValueError("size")
        chunks = []
        size = 0
        while size <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            size += len(chunk)
        raise ValueError("size")
    finally:
        os.close(fd)


def exports(raw, preload=False):
    result = {}
    lines = raw.decode("ascii").splitlines()
    if len(lines) > 128:
        raise ValueError("lines")
    found = False
    for line in lines:
        if preload and line == PRELOAD and not found:
            found = True
            continue
        parts = shlex.split(line, posix=True)
        if len(parts) != 2 or parts[0] != "export":
            raise ValueError("export")
        key, separator, value = parts[1].partition("=")
        if not separator or not re.fullmatch("[A-Z_][A-Z0-9_]{0,63}", key) or key in result:
            raise ValueError("key")
        if len(value) > 8192 or any(ord(char) < 32 for char in value):
            raise ValueError("value")
        result[key] = value
    if preload and not found:
        raise ValueError("preload")
    return result


def checked_read(path, label, limit=32768, kernel=False):
    try:
        return read(path, limit, kernel)
    except (OSError, ValueError):
        raise ObservationError(label + " is unavailable or unprotected.") from None


def checked_directory(path, label):
    try:
        directory(path)
    except (OSError, ValueError):
        raise ObservationError(label + " directory is unavailable or unprotected.") from None


def checked_exports(raw, label, preload=False):
    try:
        return exports(raw, preload)
    except (ValueError, UnicodeError):
        raise ObservationError(label + " export format is invalid.") from None


def require_exports(observed, expected, label):
    changed = [key for key in sorted(expected) if observed.get(key) != expected[key]]
    details = []
    if changed:
        details.append(label + " differs in " + ", ".join(changed[:16]) + ".")
    if set(observed) - set(expected):
        details.append(label + " contains unexpected export fields.")
    if details:
        raise ObservationError(" ".join(details))


def diagnostic(error, fallback):
    return str(error) if isinstance(error, ObservationError) else fallback


def catalog(expected_sources=None):
    global _CACHE
    files = {
        name: digest(checked_read(HARDWARE / name, "Hardware catalog " + name, 262144))
        for name in ("persona.py", "cpu_profile.py", "personas.json", "inventory.py")
    }
    if expected_sources is not None and files != expected_sources:
        changed = [name for name in files if files[name] != expected_sources.get(name)]
        raise ObservationError("Hardware catalog activation baseline differs in " + ", ".join(changed) + "." if changed else "Hardware catalog activation baseline contains unexpected fields.")
    if _CACHE is not None and _CACHE[0] == files:
        return _CACHE[1], files
    previous = sys.modules.get("cpu_profile")
    previous_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location(
            "cpu_profile",
            HARDWARE / "cpu_profile.py",
            loader=ProtectedLoader("cpu_profile", str(HARDWARE / "cpu_profile.py")),
        )
        cpu = importlib.util.module_from_spec(spec)
        sys.modules["cpu_profile"] = cpu
        spec.loader.exec_module(cpu)
        spec = importlib.util.spec_from_file_location(
            "_ph4_guard_persona",
            HARDWARE / "persona.py",
            loader=ProtectedLoader("_ph4_guard_persona", str(HARDWARE / "persona.py")),
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        spec = importlib.util.spec_from_file_location(
            "_ph4_guard_inventory",
            HARDWARE / "inventory.py",
            loader=ProtectedLoader("_ph4_guard_inventory", str(HARDWARE / "inventory.py")),
        )
        inventory = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inventory)
        module.cpuinfo = inventory.cpuinfo
    finally:
        sys.dont_write_bytecode = previous_bytecode
        if previous is None:
            sys.modules.pop("cpu_profile", None)
        else:
            sys.modules["cpu_profile"] = previous
    _CACHE = files, module
    return module, files


def strings(values):
    return {key: str(value) for key, value in values.items()}


def random_value(seed, salt, maximum):
    return int(hashlib.sha256((seed + salt).encode("ascii")).hexdigest()[:8], 16) % maximum


def dmi_values(mode, seed, jitter, profile):
    def identifier(salt, length):
        return hashlib.sha256((seed + salt + jitter).encode("ascii")).hexdigest()[:length].upper()

    raw = identifier("uuid-base", 32)
    variant = "89AB"[int(raw[0] if mode == "lonewolf" else identifier("u-var", 1), 16) % 4]
    uuid = raw[:8] + "-" + raw[8:12] + "-4" + raw[13:16] + "-" + variant + raw[17:20] + "-" + raw[20:32]
    prefix, length = {
        "lenovo": ("PF", 8),
        "dell": ("", 7),
        "hp": ("5CG", 8),
        "asus": ("M", 11),
        "acer": ("NX", 10),
        "msi": ("9S6", 9),
        "razer": ("BY", 10),
        "fujitsu": ("DS", 10),
        "toshiba": ("Z", 11),
        "samsung": ("S", 11),
        "apple": ("C02", 9),
        "google": ("GGL", 9),
        "microsoft": ("", 12),
        "lg": ("S", 11),
        "intel": ("G", 11),
        "ibm": ("LV", 10),
        "origin": ("OPC", 9),
    }.get(profile["VENDOR"], ("", 12))
    serial = prefix + identifier("s1", length)
    values = {
        key.lower(): profile[key]
        for key in (
            "PRODUCT_NAME", "PRODUCT_VERSION", "PRODUCT_FAMILY", "PRODUCT_SKU",
            "BOARD_NAME", "BOARD_VENDOR", "BOARD_VERSION", "BOARD_ASSET_TAG",
            "BIOS_VENDOR", "BIOS_VERSION", "BIOS_DATE", "BIOS_RELEASE",
            "EC_FIRMWARE_RELEASE", "SYS_VENDOR", "CHASSIS_VENDOR", "CHASSIS_TYPE",
            "CHASSIS_VERSION", "CHASSIS_ASSET_TAG",
        )
    }
    values.update(
        product_serial=serial,
        chassis_serial=serial,
        product_uuid=uuid,
        board_serial="MB-" + (identifier("brd", 12) if mode == "lonewolf" else serial[:10]),
    )
    fields = (
        ("bvn", "BIOS_VENDOR"), ("bvr", "BIOS_VERSION"), ("bd", "BIOS_DATE"),
        ("br", "BIOS_RELEASE"), ("efr", "EC_FIRMWARE_RELEASE"), ("svn", "SYS_VENDOR"),
        ("pn", "PRODUCT_NAME"), ("pvr", "PRODUCT_VERSION"), ("rvn", "BOARD_VENDOR"),
        ("rn", "BOARD_NAME"), ("rvr", "BOARD_VERSION"), ("cvn", "CHASSIS_VENDOR"),
        ("ct", "CHASSIS_TYPE"), ("cvr", "CHASSIS_VERSION"), ("sku", "PRODUCT_SKU"),
    )
    modalias = "dmi:" + "".join(prefix + re.sub("[^A-Za-z0-9.,_-]", "", profile[key]) + ":" for prefix, key in fields)
    values.update(modalias=modalias, uevent="MODALIAS=" + modalias)
    return values


def mount_records():
    raw = checked_read(MOUNTINFO, "Identity mount inventory", 1048576, kernel=True)
    records = {}
    lines = [os.fsdecode(line) for line in raw.split(b"\n") if line]
    if len(lines) > 16384:
        raise ObservationError("Identity mount inventory exceeds its record limit.")
    for line in lines:
        fields = line.split(" ")
        if "-" not in fields:
            raise ObservationError("Identity mount inventory format is invalid.")
        separator = fields.index("-")
        if separator < 6 or len(fields) < separator + 4:
            raise ObservationError("Identity mount inventory format is invalid.")
        target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        records.setdefault(target, []).append(fields)
    return records


def readonly_binding(source, target, raw, records, label):
    try:
        info = target.lstat()
    except OSError:
        raise ObservationError(label + " target is unavailable.") from None
    if not stat.S_ISREG(info.st_mode):
        raise ObservationError(label + " target is not a regular file.")
    source_info = source.stat()
    mounts = records.get(str(target), [])
    if len(mounts) != 1:
        raise ObservationError(label + " mount is missing or ambiguous.")
    mount = mounts[0]
    if "ro" not in mount[5].split(",") or "rw" in mount[5].split(","):
        raise ObservationError(label + " mount is not read-only.")
    if (info.st_dev, info.st_ino) != (source_info.st_dev, source_info.st_ino):
        raise ObservationError(label + " mount backing does not match its generated artifact.")
    if mount[2] != str(os.major(info.st_dev)) + ":" + str(os.minor(info.st_dev)):
        raise ObservationError(label + " mount device is inconsistent.")
    if checked_read(target, label + " exposed identity", max(4096, len(raw)), kernel=True) != raw:
        raise ObservationError(label + " exposed identity differs from its generated artifact.")
    return {
        "inode": str(source_info.st_ino),
        "device": mount[2],
        "root": digest(os.fsencode(mount[3])),
    }


def observed_cpu(module, resources):
    count = int(resources["PH4_REPORTED_CORES"])
    if not 1 <= count <= 4096:
        raise ValueError("CPU count")
    cpuinfo = module.cpuinfo(resources).encode("ascii")
    online = ("0" if count == 1 else "0-" + str(count - 1)).encode("ascii") + b"\n"
    expected = {"fake_cpuinfo": cpuinfo, "fake_online": online}
    files = {}
    for field, value in expected.items():
        source = IDENTITY / field
        raw = checked_read(source, "CPU " + field, 262144)
        if raw != value:
            raise ObservationError("CPU " + field + " does not match the generated profile.")
        if stat.S_IMODE(source.stat().st_mode) != 0o444:
            raise ObservationError("CPU " + field + " permissions are not read-only.")
        files[field] = digest(raw)
    records = mount_records()
    targets = {"cpuinfo": readonly_binding(IDENTITY / "fake_cpuinfo", CPUINFO, cpuinfo, records, "CPU cpuinfo")}
    canonical = CPU_SYSFS.resolve(strict=True)
    checked_directory(canonical, "CPU exposed identity")
    for field in ("online", "present", "possible"):
        targets[field] = readonly_binding(IDENTITY / "fake_online", canonical / field, online, records, "CPU " + field)
    return {"files": files, "targets": targets}


def observed_dmi(expected):
    checked_directory(IDENTITY, "Session identity")
    backing = IDENTITY / "fake_dmi"
    checked_directory(backing, "DMI artifacts")
    canonical = DMI.resolve(strict=False)
    if canonical.exists():
        if not str(canonical).startswith("/sys/devices/") and DMI == Path("/sys/class/dmi/id"):
            raise ObservationError("DMI exposed identity directory has an invalid canonical path.")
        checked_directory(canonical, "DMI exposed identity")
    entries = []
    for entry in backing.iterdir():
        entries.append(entry)
        if len(entries) > len(expected):
            raise ObservationError("DMI artifact inventory contains unexpected fields.")
    if len(entries) != len(expected) or {entry.name for entry in entries} != set(expected):
        missing = sorted(set(expected) - {entry.name for entry in entries})
        if missing:
            raise ObservationError("DMI artifact inventory is missing " + ", ".join(missing) + ".")
        raise ObservationError("DMI artifact inventory contains unexpected fields.")
    records = mount_records()
    files = {}
    targets = {}
    for field, value in expected.items():
        source = backing / field
        raw = checked_read(source, "DMI " + field, 4096)
        if raw != value.encode("ascii"):
            raise ObservationError("DMI " + field + " does not match the generated profile.")
        if stat.S_IMODE(source.stat().st_mode) != 0o444:
            raise ObservationError("DMI " + field + " permissions are not read-only.")
        files[field] = digest(raw)
        target = canonical / field
        try:
            info = target.lstat()
        except FileNotFoundError:
            continue
        targets[field] = readonly_binding(source, target, raw, records, "DMI " + field)
    return {"files": files, "targets": targets}


def gpu_values(mode, seed, profile, stack):
    vendor, family = profile["GPU_VENDOR"], profile["GPU_FAMILY"]
    allowed = {
        "intel": "mesa",
        "amd": "mesa-radv",
        "aspeed": "mesa",
        "matrox": "mesa",
    }
    default = (
        "mesa-asahi"
        if mode != "lonewolf" and vendor == "apple" and family != "intel"
        else "mesa"
    )
    if vendor == "nvidia":
        if stack not in ("nvidia", "mesa"):
            raise ObservationError("GPU profile PH4NTXM_GPU_STACK is inconsistent.")
    elif stack != allowed.get(vendor, default):
        raise ObservationError("GPU profile PH4NTXM_GPU_STACK is inconsistent.")
    gl, glsl, extension = "4.6", "460", "-GL_NV_shader_buffer_load"
    if vendor == "nvidia":
        extension = "-GL_ARB_parallel_shader_compile"
    elif vendor in ("aspeed", "matrox"):
        gl, glsl, extension = "3.1", "140", "-GL_ARB_tessellation_shader"
    elif vendor == "apple" and mode != "lonewolf":
        gl, glsl, extension = "4.1", "410", "-GL_ARB_tessellation_shader"
    elif mode == "lonewolf" and vendor not in ("intel", "amd"):
        extension = "-GL_ARB_get_program_binary"
    if mode == "lonewolf":
        vendor_string = {
            "intel": (
                "Intel Inc."
                if family == "uhd"
                else "Intel Open Source Technology Center"
                if family in ("iris", "xe")
                else "Mesa"
            ),
            "amd": "AMD",
            "nvidia": "NVIDIA Corporation",
            "aspeed": "ASPEED Technology, Inc.",
            "matrox": "Matrox Graphics Inc.",
        }.get(vendor, "Mesa")
    else:
        vendor_string = {
            "intel": "Intel",
            "amd": "AMD",
            "nvidia": "NVIDIA Corporation",
            "apple": "Intel Inc." if family == "intel" else "Apple",
            "aspeed": "ASPEED Technology, Inc.",
            "matrox": "Matrox Graphics Inc.",
        }.get(vendor, "Unknown")
        extension += " " + (
            "-GL_ARB_get_program_binary",
            "-GL_EXT_framebuffer_object",
        )[random_value(seed, "extmask", 2)]
    values = {
        "PH4NTXM_GPU_VENDOR": vendor,
        "PH4NTXM_GPU_FAMILY": family,
        "PH4NTXM_GPU_MODEL": profile["GPU_MODEL"],
        "PH4NTXM_GPU_STACK": stack,
        "PH4NTXM_GL_VENDOR": vendor_string,
        "PH4NTXM_GL_RENDERER": profile["GPU_MODEL"],
    }
    if mode == "lonewolf" or stack != "nvidia":
        values.update(
            MESA_GL_VERSION_OVERRIDE=gl,
            MESA_GLSL_VERSION_OVERRIDE=glsl,
            MESA_EXTENSION_OVERRIDE=extension,
            MESA_VENDOR_OVERRIDE=vendor_string,
            MESA_RENDERER_OVERRIDE=profile["GPU_MODEL"],
        )
    if mode == "lonewolf" or stack == "nvidia":
        values.update(__GL_VENDOR=vendor_string, __GL_RENDERER_STRING=profile["GPU_MODEL"])
    if stack == "nvidia":
        values["__GLX_VENDOR_LIBRARY_NAME"] = "nvidia"
    return values


def screen_values(mode, seed, jitter, profile):
    vendor = profile["GPU_VENDOR"]
    device = profile["DEVICE_CLASS"]
    if mode == "lonewolf":
        families = {
            "business": ("thinkpad", "latitude", "elitebook", "lifebook", "portege"),
            "consumer": ("modern", "swift", "galaxybook"),
            "ultrabook": ("zenbook", "book", "surface", "gram", "pixelbook"),
            "apple_desktop": ("macmini",),
            "desktop": ("nuc", "chronos"),
            "server": ("x3650",),
        }
        display = next(key for key, values in families.items() if profile["FAMILY"] in values)
        panels = {
            "business": ("panel_biz", ((1920, 1080, 60), (1366, 768, 60), (2560, 1440, 60))),
            "consumer": ("panel_cons", ((1920, 1080, 60), (1366, 768, 60), (1600, 900, 60))),
            "ultrabook": ("panel_ultra", ((1920, 1080, 60), (2560, 1600, 60), (2880, 1800, 90))),
            "apple_desktop": ("panel_mac_d", ((3840, 2160, 60), (5120, 2880, 60), (2560, 1440, 60))),
            "desktop": ("panel_desktop", ((1920, 1080, 60), (2560, 1440, 60), (3840, 2160, 60))),
            "server": ("", ((1920, 1080, 60),)),
        }
        salt, choices = panels[display]
        width, height, refresh = choices[random_value(seed + jitter, salt, len(choices))]
        if vendor not in ("amd", "nvidia"):
            refresh = min(refresh, 60)
        if vendor == "intel" and display != "apple_desktop" and width >= 3500:
            width, height, refresh = 2560, 1440, 60
        ratio = "1.0"
        if display in ("business", "consumer") and width >= 2500:
            ratio = "1.25"
        if display == "ultrabook":
            ratio = "1.5" if width >= 2500 else "1.25"
        return strings({
            "PH4_DISPLAY_WIDTH": width,
            "PH4_DISPLAY_HEIGHT": height,
            "PH4_DEVICE_PIXEL_RATIO": ratio,
            "PH4_PRIMARY_DISPLAY": "DISPLAY-1",
            "PH4_DEVICE_CLASS": device,
            "PH4_DISPLAY_CLASS": display,
            "PH4_GPU_VENDOR": vendor,
            "PH4_DISPLAY_REFRESH": refresh,
        })
    laptop = device == "laptop"
    externals = (
        ["DP-1"]
        if not laptop and profile["VENDOR"] == "apple"
        else ["HDMI-1", "DP-1"]
    )
    if random_value(seed, "no_ext", 100) < 50:
        externals = []

    def panel(internal):
        if not internal and profile["VENDOR"] == "apple":
            return 2560, 1440, 60
        if vendor in ("amd", "nvidia"):
            choices = (
                ((1920, 1080, 144), (2560, 1440, 144), (2560, 1600, 120))
                if internal
                else ((2560, 1440, 144), (3840, 2160, 60), (2560, 1440, 165))
            )
            return choices[random_value(seed, "int_hi" if internal else "ext_hi", 3)]
        return 1920, 1080, 60

    width, height, refresh = panel(laptop)
    primary = "eDP-1" if laptop else externals[0] if externals else "HDMI-1"
    secondary = ""
    if laptop and externals and random_value(seed, "dual", 100) < 60:
        secondary = externals[0]
    if not laptop and len(externals) > 1 and random_value(seed, "dual_ext", 100) < 40:
        secondary = externals[1]
    values = strings({
        "PH4_PRIMARY_DISPLAY": primary,
        "PH4_SECONDARY_DISPLAY": secondary,
        "PH4_DISPLAY_WIDTH": width,
        "PH4_DISPLAY_HEIGHT": height,
        "PH4_DISPLAY_REFRESH": refresh,
        "PH4_DEVICE_PIXEL_RATIO": (
            "1.5"
            if width >= 2500
            else "1.25"
            if width >= 1920
            else "1.0"
        ),
        "PH4_DEVICE_CLASS": device,
        "PH4_FORM_FACTOR": "laptop" if laptop else "desktop",
    })
    if secondary:
        sw, sh, sr = panel(False)
        values["PH4_SECONDARY_RES"] = str(sw) + "x" + str(sh) + "@" + str(sr)
    return values


def baseline_detail(code, current, saved):
    fields = []
    if code == "persona":
        fields.extend((key, label) for key, label in (
            (("hardware",), "Hardware profile"),
            (("cores",), "CPU and memory profile"),
        ))
        for name in ("persona.py", "cpu_profile.py", "personas.json", "inventory.py"):
            fields.append((("sources", name), "Hardware catalog " + name))
        for name in ("fake_cpuinfo", "fake_online"):
            fields.append((("cpu", "files", name), "CPU " + name + " artifact"))
        targets = ("cpuinfo", "online", "present", "possible")
        prefix = ("cpu", "targets")
        label = "CPU "
    elif code == "dmi":
        fields.append((("jitter",), "Boot jitter"))
        targets = tuple(current.get("files", {}))
        for name in targets:
            fields.append((("files", name), "DMI " + name + " artifact"))
        prefix = ("targets",)
        label = "DMI "
    else:
        fields.extend((key, label) for key, label in (
            (("gpu",), "GPU profile"),
            (("screen",), "Screen profile"),
            (("library",), "GL identity library"),
        ))
        targets = ()
        prefix = ()
        label = ""

    def lookup(value, path):
        for name in path:
            if not isinstance(value, dict) or name not in value:
                return None
            value = value[name]
        return value

    for name in targets:
        path = prefix + (name,)
        before = lookup(saved, path)
        after = lookup(current, path)
        if not isinstance(before, dict) or not isinstance(after, dict):
            fields.append((path, label + name + " mount coverage"))
        else:
            for part in ("inode", "device", "root"):
                fields.append((path + (part,), label + name + " mount " + part))
    changes = [label for path, label in fields if lookup(current, path) != lookup(saved, path)]
    if changes:
        return "Activation baseline changed: " + ", ".join(changes[:16]) + "."
    return TITLES[code] + " activation baseline contains unexpected fields."


def collect(mode, seed, baseline=None):
    checks = []
    evidence = {}
    problems = {code: [] for code in TITLES}
    profile = None
    jitter = None
    if mode not in ("linux", "windows", "lonewolf") or not isinstance(seed, str) or not re.fullmatch("[0-9a-f]{64}", seed):
        for code in problems:
            problems[code].append("Protected session mode or seed is unavailable.")
    else:
        try:
            checked_directory(IDENTITY, "Session identity")
            expected_sources = None
            if baseline is not None:
                expected_sources = {}
                if isinstance(baseline, dict) and isinstance(baseline.get("persona"), dict):
                    saved_sources = baseline["persona"].get("sources", {})
                    if isinstance(saved_sources, dict):
                        expected_sources = saved_sources
            module, sources = catalog(expected_sources)
            profile = strings(module.identity(module.choose(mode, seed)))
            hardware = checked_read(IDENTITY / "hardware_profile", "Hardware profile")
            require_exports(checked_exports(hardware, "Hardware profile"), profile, "Hardware profile")
            cores = checked_read(IDENTITY / "cores_env", "CPU and memory profile")
            resources = strings(module.resources(module.profile(profile["PROFILE_ID"])))
            require_exports(checked_exports(cores, "CPU and memory profile"), resources, "CPU and memory profile")
            cpu = observed_cpu(module, resources)
            evidence["persona"] = {
                "hardware": digest(hardware),
                "cores": digest(cores),
                "sources": sources,
                "cpu": cpu,
            }
        except (OSError, ValueError, UnicodeError, KeyError, ImportError, StopIteration, TypeError, SyntaxError, AttributeError) as error:
            problems["persona"].append(diagnostic(error, "Hardware catalog selection or CPU resource definition is invalid."))
        try:
            jitter_raw = checked_read(IDENTITY / "boot_jitter", "Boot jitter", 32)
            jitter = jitter_raw.decode("ascii").strip()
            if not re.fullmatch("[0-9a-f]{16}", jitter):
                raise ObservationError("Boot jitter format is invalid.")
            if profile is None:
                raise ObservationError("DMI hardware profile dependency is unavailable.")
            evidence["dmi"] = observed_dmi(dmi_values(mode, seed, jitter, profile))
            evidence["dmi"]["jitter"] = digest(jitter_raw)
        except (OSError, ValueError, UnicodeError, KeyError) as error:
            problems["dmi"].append(diagnostic(error, "DMI generated profile definition is invalid."))
        try:
            if profile is None or jitter is None:
                raise ObservationError("Graphics hardware profile or boot jitter dependency is unavailable.")
            gpu = checked_read(IDENTITY / "gpu_env", "GPU profile")
            observed = checked_exports(gpu, "GPU profile", preload=True)
            expected = gpu_values(mode, seed, profile, observed.get("PH4NTXM_GPU_STACK"))
            require_exports(observed, expected, "GPU profile")
            screen = checked_read(IDENTITY / "screen_env", "Screen profile")
            require_exports(checked_exports(screen, "Screen profile"), screen_values(mode, seed, jitter, profile), "Screen profile")
            library = checked_read(GL_LIBRARY, "GL identity library", 8388608)
            if len(library) < 4 or library[:4] != b"\x7fELF":
                raise ObservationError("GL identity library ELF header is invalid.")
            evidence["graphics"] = {
                "gpu": digest(gpu),
                "screen": digest(screen),
                "library": digest(library),
            }
        except (OSError, ValueError, UnicodeError, KeyError, StopIteration) as error:
            problems["graphics"].append(diagnostic(error, "GPU or screen generated profile definition is invalid."))
    for code, title in TITLES.items():
        if baseline is not None:
            if not isinstance(baseline, dict) or code not in baseline or not isinstance(baseline[code], dict):
                problems[code].append("Required activation baseline is unavailable.")
            elif code in evidence and evidence[code] != baseline[code]:
                problems[code].append(baseline_detail(code, evidence[code], baseline[code]))
        healthy = not problems[code]
        checks.append({
            "code": code,
            "title": title,
            "healthy": healthy,
            "status": "healthy" if healthy else "failed",
            "detail": " ".join(problems[code])[:2048],
        })
    return checks, evidence
