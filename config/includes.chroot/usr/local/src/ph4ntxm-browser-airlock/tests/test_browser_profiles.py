#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from pathlib import Path
import hashlib
import os
import shlex
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "browser_profiles.py"
sys.path.insert(0, str(MODULE.parent))
import browser_profiles as profiles


SOURCE = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path("/")


class BrowserProfilesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.metadata = self.root / "metadata"
        self.home = self.root / "home"
        self.bundle = self.root / "tor-browser"
        self.cache_root = self.root / "cache-root"
        self.cache_root.mkdir()
        self.cache_root.chmod(0o1777)
        for path in (self.state, self.metadata, self.home, self.bundle):
            path.mkdir(mode=0o700 if path == self.home else 0o755)
        self.patchers = (
            patch.object(profiles, "OWNER", os.getuid()),
            patch.object(profiles, "STATE", self.state),
            patch.object(profiles, "METADATA", self.metadata),
            patch.object(profiles, "TOR_BROWSER", self.bundle),
            patch.object(profiles, "CACHE_DIRECTORY", self.cache_root),
            patch.object(profiles, "FIREWALL_MANIFEST", self.metadata / "lonewolf.sha256"),
        )
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, path, content, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in path.parents:
            if parent == self.root:
                break
            if parent != self.home:
                parent.chmod(0o755)
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        path.chmod(mode)

    def exports(self, values):
        return "".join(f"export {key}={shlex.quote(value)}\n" for key, value in values.items())

    def normal_fixture(self, mode="linux"):
        self.write(self.state / "mode", mode + "\n")
        self.write(self.state / "browser_env", self.exports({
            "PH4_SCREEN_WIDTH": "1920", "PH4_SCREEN_HEIGHT": "1080",
            "PH4_DEVICE_PIXEL_RATIO": "1.25", "PH4_PRIMARY_DISPLAY": "Internal Display",
            "PH4_VIEWPORT_WIDTH": "1900", "PH4_VIEWPORT_HEIGHT": "980",
            "PH4_DISPLAY_COUNT": "1", "PH4_SECONDARY_DISPLAY": "none",
        }))
        self.write(self.state / "cores_env", self.exports({
            "PH4_REPORTED_CORES": "8", "PH4_CPU_ARCHITECTURE": "x86_64",
            "PH4_CPU_MODEL_NAME": "Intel(R) Core(TM) i7-1185G7", "PH4_REPORTED_RAM": "16",
        }))
        self.write(self.state / "gpu_env", self.exports({
            "PH4NTXM_GL_VENDOR": "Intel", "PH4NTXM_GL_RENDERER": "Intel Iris Xe Graphics",
            "PH4NTXM_GPU_STACK": "mesa", "MESA_GL_VERSION_OVERRIDE": "4.6",
            "MESA_EXTENSION_OVERRIDE": "-GL_EXT_framebuffer_object -GL_NV_shader_buffer_load",
            "PH4NTXM_GPU_VENDOR": "intel", "PH4NTXM_GPU_FAMILY": "integrated",
            "PH4NTXM_GPU_MODEL": "Intel Iris Xe Graphics", "MESA_GLSL_VERSION_OVERRIDE": "460",
            "MESA_VENDOR_OVERRIDE": "Intel", "MESA_RENDERER_OVERRIDE": "Intel Iris Xe Graphics",
        }) + profiles.PRELOAD + "\n")
        self.write(self.state / "fonts-active/fonts.conf", "<fontconfig/>")
        binary = self.root / "firefox-esr-real"
        library = self.root / "libph4ntxm-gl-spoof.so"
        policy = self.root / "policies.json"
        templates = self.root / "templates"
        self.write(binary, "#!/bin/sh\n", 0o755)
        self.write(library, b"\x7fELFfake fixture")
        self.write(policy, "{}")
        self.write(templates / mode / "user.js", (SOURCE / f"etc/firefox-esr/mode/{mode}/user.js").read_bytes())
        for key, value in (("FIREFOX", binary), ("GL_LIBRARY", library), ("POLICY", policy), ("TEMPLATES", templates)):
            patcher = patch.object(profiles, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def tor_fixture(self):
        for relative in (
            "Browser/start-tor-browser", "Browser/firefox", "Browser/firefox.real",
            "Browser/TorBrowser/Tor/tor", "Browser/is-packaged-app",
            "Browser/browser/chrome/icons/default/default128.png",
        ):
            mode = 0o644 if relative.endswith(("is-packaged-app", ".png")) else 0o755
            self.write(self.bundle / relative, "fixture\n", mode)
        manifest = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.bundle.parent).as_posix()}\n"
            for path in sorted(self.bundle.rglob("*")) if path.is_file()
        )
        self.write(self.metadata / "tor-browser.sha256", manifest)
        self.write(self.metadata / "tor-browser.version", "15.0.21\n")
        return hashlib.sha256(manifest.encode()).hexdigest()

    def ready_fixture(self, digest):
        self.write(self.state / "mode", "lonewolf\n")
        self.write(self.state / "tor-browser-verified", f"MODE=lonewolf\nMANIFEST_SHA256={digest}\nUPTIME_SECONDS=1\n")
        self.write(self.metadata / "lonewolf.sha256", "a" * 64 + "\n")
        self.write(self.state / "firewall-ready", "PROFILE=lonewolf\nSOURCE_SHA256=" + "a" * 64 + "\nRULESET_SHA256=" + "b" * 64 + "\nUPTIME_SECONDS=100\n")
        self.write(self.state / "tor-ready", "STATUS=ready\nBOOTSTRAP=100\nUPTIME_SECONDS=100\n")

    def ready_command(self, arguments):
        if arguments[0].endswith("ph4ntxm-tor-connection-control"):
            return '{"mode":"direct"}'
        if arguments[0].endswith("systemctl"):
            return "active\n" * 4
        port = arguments[-1].split(":")[-1]
        return f"LISTEN 0 0 127.0.0.1:{port} 0.0.0.0:*\n"

    def test_normal_modes_keep_original_identity_and_private_transport(self):
        for mode in ("linux", "windows"):
            with self.subTest(mode=mode):
                self.normal_fixture(mode)
                with patch.object(profiles, "command", return_value="Mozilla Firefox 140.4.0esr"):
                    plan = profiles.prepare_browser(self.home, profile_path=str(self.home / "profile"))
                preferences = (self.home / "profile/user.js").read_text()
                self.assertNotIn("{{", preferences)
                self.assertIn("Windows NT 10.0" if mode == "windows" else "X11; Linux x86_64", preferences)
                self.assertIn('user_pref("layout.css.devPixelsPerPx", "1.25")', preferences)
                self.assertIn('user_pref("dom.maxHardwareConcurrency", 8)', preferences)
                self.assertEqual(plan.environment["MESA_GL_VERSION_OVERRIDE"], "4.6")
                self.assertEqual(plan.environment["PH4_CPU_MODEL_NAME"], "Intel(R) Core(TM) i7-1185G7")
                self.assertEqual(plan.environment["LD_PRELOAD"], str(profiles.GL_LIBRARY))
                self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", plan.environment)
                self.assertEqual(plan.environment["MOZ_DBUS_REMOTE"], "1")
                self.assertEqual(plan.command[-1], plan.profile_path)
                self.assertEqual(stat.S_IMODE((self.home / "profile/user.js").stat().st_mode), 0o600)
                (self.home / "profile/user.js").unlink()
                (self.home / "profile").rmdir()

    def test_rejects_unsafe_files_and_shell_or_loader_exports(self):
        target = self.state / "mode"
        self.write(target, "linux", 0o666)
        with self.assertRaises(profiles.ProfileError):
            profiles.read_protected(target)
        target.unlink()
        target.symlink_to(self.metadata / "missing")
        with self.assertRaises(OSError):
            profiles.read_protected(target)
        for content in ("export LD_PRELOAD=evil\n", "echo injected\n", "export PH4_CORES=8\nexport PH4_CORES=9\n"):
            with self.subTest(content=content), self.assertRaises(profiles.ProfileError):
                profiles.parse_exports(content.encode(), "cores")
        raw = b"export PH4_MODEL=$(touch\\ /tmp/not-created)\n"
        self.assertEqual(profiles.parse_exports(raw, "cores")["PH4_MODEL"], "$(touch /tmp/not-created)")

    def test_read_is_bounded_and_private_home_must_be_fresh(self):
        self.write(self.state / "mode", "linux")
        with self.assertRaises(profiles.ProfileError):
            profiles.read_protected(self.state / "mode", 4)
        self.write(self.home / "old", "old")
        with self.assertRaises(profiles.ProfileError):
            profiles.prepare_browser(self.home)

    def test_tor_exact_manifest_rejects_mutation_extra_file_and_symlink(self):
        digest = self.tor_fixture()
        self.assertEqual(profiles.verify_tor_installation(), digest)
        target = self.bundle / "Browser/firefox"
        target.write_text("changed\n")
        with self.assertRaises(profiles.ProfileError):
            profiles.verify_tor_installation()
        target.write_text("fixture\n")
        self.write(self.bundle / "extra", "extra")
        with self.assertRaises(profiles.ProfileError):
            profiles.verify_tor_installation()
        (self.bundle / "extra").unlink()
        (self.bundle / "extra").symlink_to(target)
        with self.assertRaises(profiles.ProfileError):
            profiles.verify_tor_installation()

    def test_tor_readiness_fails_closed_for_stale_pending_and_bad_listeners(self):
        digest = self.tor_fixture()
        self.ready_fixture(digest)
        with patch.object(profiles, "command", side_effect=self.ready_command):
            profiles.validate_tor_readiness(digest, 106)
            with self.assertRaises(profiles.ProfileError):
                profiles.validate_tor_readiness(digest, 107)
        with patch.object(profiles, "command", return_value='{"mode":"pending"}'):
            with self.assertRaises(profiles.ProfileError):
                profiles.validate_tor_readiness(digest, 100)
        def wrong_listener(arguments):
            return self.ready_command(arguments).replace("127.0.0.1", "0.0.0.0")
        with patch.object(profiles, "command", side_effect=wrong_listener):
            with self.assertRaises(profiles.ProfileError):
                profiles.validate_tor_readiness(digest, 100)

    def test_tor_plan_keeps_fresh_home_and_excludes_normal_persona(self):
        digest = self.tor_fixture()
        self.ready_fixture(digest)
        uid = os.getuid() or 1000
        if os.getuid() == 0:
            os.chown(self.home, uid, -1)
        with patch.object(profiles.os, "getuid", return_value=uid), patch.object(profiles, "validate_tor_readiness") as readiness:
            plan = profiles.prepare_browser(self.home, username="ph4ntxm")
        readiness.assert_called_once_with(digest)
        self.assertEqual([path.name for path in self.home.iterdir()], [".tor-browser"])
        tor = self.home / ".tor-browser/TorBrowser/Tor/tor"
        self.assertTrue(tor.is_file())
        self.assertFalse(tor.is_symlink())
        self.assertEqual(tor.read_bytes(), b"")
        self.assertEqual(stat.S_IMODE(tor.stat().st_mode), 0o600)
        for directory in (tor.parent, tor.parent.parent, self.home / ".tor-browser"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertTrue(plan.environment["PATH"].startswith("/run/ph4ntxm-browser-tools:"))
        self.assertEqual(plan.environment["TOR_SOCKS_PORT"], "9050")
        self.assertEqual(plan.environment["TOR_PROVIDER"], "none")
        self.assertEqual(plan.command, (str(self.bundle / "Browser/start-tor-browser"),))
        self.assertFalse(any(key.startswith(("PH4", "MESA", "LD_", "FONTCONFIG")) for key in plan.environment))

    def test_tor_plan_rejects_root(self):
        self.write(self.state / "mode", "lonewolf\n")
        original_lstat = Path.lstat
        def home_stat(path, *args, **kwargs):
            if path == self.home:
                return os.stat_result((stat.S_IFDIR | 0o700, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            return original_lstat(path, *args, **kwargs)
        with patch.object(profiles.os, "getuid", return_value=0), patch.object(Path, "lstat", home_stat):
            with self.assertRaisesRegex(profiles.ProfileError, "refuses to run as root"):
                profiles.prepare_browser(self.home, username="root")

    def test_repeated_launch_revalidates_sources_without_recreating_profile(self):
        self.normal_fixture()
        with patch.object(profiles, "command", return_value="Mozilla Firefox 140.4.0esr"):
            plan = profiles.prepare_browser(self.home)
        saved = Path(plan.profile_path) / "prefs.js"
        saved.write_text("saved preferences")
        profiles.revalidate_browser(plan)
        self.write(self.state / "cores_env", "export PH4_REPORTED_CORES=16\n")
        with self.assertRaises(profiles.ProfileError):
            profiles.revalidate_browser(plan)
        self.assertEqual(saved.read_text(), "saved preferences")

    def test_cache_reopens_preserves_profile_and_atomic_failure_preserves_old_preferences(self):
        self.normal_fixture()
        with patch.object(profiles, "command", return_value="Mozilla Firefox 140.4.0esr"):
            first = profiles.prepare_browser(self.home)
            profile = Path(first.profile_path)
            marker = profile / "cookies.sqlite"
            marker.write_bytes(b"retained fixture")
            previous = (profile / "user.js").read_bytes()
            other_home = self.root / "other-home"
            other_home.mkdir(mode=0o700)
            second = profiles.prepare_browser(other_home)
            self.assertEqual(first.profile_path, second.profile_path)
            self.assertEqual(marker.read_bytes(), b"retained fixture")
            with patch.object(profiles.os, "write", side_effect=OSError("Interrupted write")):
                with self.assertRaises(OSError):
                    profiles.prepare_browser(other_home)
            self.assertEqual((profile / "user.js").read_bytes(), previous)
            self.assertEqual(marker.read_bytes(), b"retained fixture")
            self.assertEqual(list(profile.glob(".user.js.*")), [])
            with patch.object(profiles.os, "replace", side_effect=OSError("Interrupted rename")):
                with self.assertRaises(OSError):
                    profiles.prepare_browser(other_home)
            self.assertEqual((profile / "user.js").read_bytes(), previous)
            self.assertEqual(marker.read_bytes(), b"retained fixture")

    def test_cache_rejects_symlinks_unsafe_permissions_and_foreign_owner(self):
        path, descriptor = profiles.cached_profile("linux")
        os.close(descriptor)
        path.chmod(0o755)
        with self.assertRaises(profiles.ProfileError):
            profiles.cached_profile("linux")
        path.chmod(0o700)
        path.rmdir()
        target = self.root / "foreign"
        target.mkdir(mode=0o700)
        path.symlink_to(target, target_is_directory=True)
        with self.assertRaises(profiles.ProfileError):
            profiles.cached_profile("linux")
        path.unlink()
        path.mkdir(mode=0o700)
        original_fstat = profiles.os.fstat
        def foreign_owner(fd):
            info = original_fstat(fd)
            if info.st_ino == path.stat().st_ino:
                values = list(info)
                values[4] = os.getuid() + 1
                return os.stat_result(values)
            return info
        with patch.object(profiles.os, "fstat", side_effect=foreign_owner):
            with self.assertRaises(profiles.ProfileError):
                profiles.cached_profile("linux")

    def test_each_consumed_identity_field_must_be_present_and_valid(self):
        self.normal_fixture()
        browser = profiles.parse_exports((self.state / "browser_env").read_bytes(), "browser")
        cores = profiles.parse_exports((self.state / "cores_env").read_bytes(), "cores")
        gpu = profiles.parse_exports((self.state / "gpu_env").read_bytes(), "gpu")
        profiles.validate_identity(browser, gpu)
        for key in browser:
            changed = dict(browser)
            changed.pop(key)
            with self.subTest(missing=key), self.assertRaises(profiles.ProfileError):
                profiles.validate_identity(changed, gpu)
                profiles.render_preferences("{{CORES}} {{ARCH}} {{DPR}} {{FIREFOX_MAJOR}}", changed, cores, "Firefox 140.1")
        for key in ("PH4_REPORTED_CORES", "PH4_CPU_ARCHITECTURE"):
            changed = dict(cores)
            changed.pop(key)
            with self.subTest(missing=key), self.assertRaises(profiles.ProfileError):
                profiles.render_preferences("{{CORES}}", browser, changed, "Firefox 140.1")
        for key in ("PH4NTXM_GPU_VENDOR", "PH4NTXM_GPU_FAMILY", "PH4NTXM_GPU_MODEL", "PH4NTXM_GL_VENDOR", "PH4NTXM_GL_RENDERER", "PH4NTXM_GPU_STACK", "MESA_GL_VERSION_OVERRIDE", "MESA_GLSL_VERSION_OVERRIDE", "MESA_EXTENSION_OVERRIDE", "MESA_VENDOR_OVERRIDE", "MESA_RENDERER_OVERRIDE"):
            changed = dict(gpu)
            changed.pop(key)
            with self.subTest(missing=key), self.assertRaises(profiles.ProfileError):
                profiles.validate_identity(browser, changed)
        for key, value in (("PH4_DEVICE_PIXEL_RATIO", "nan"), ("PH4_DEVICE_PIXEL_RATIO", "0"), ("PH4_DEVICE_PIXEL_RATIO", "17"), ("PH4_REPORTED_CORES", "0"), ("PH4_REPORTED_CORES", "65537"), ("PH4_CPU_ARCHITECTURE", "bad")):
            changed_browser = dict(browser)
            changed_cores = dict(cores)
            (changed_cores if key in cores else changed_browser)[key] = value
            with self.subTest(invalid=key, value=value), self.assertRaises(profiles.ProfileError):
                profiles.render_preferences("{{CORES}}", changed_browser, changed_cores, "Firefox 140.1")

    def test_invalid_mode_duplicate_readiness_and_profile_redirect_fail(self):
        self.write(self.state / "mode", "invalid")
        with self.assertRaises(profiles.ProfileError):
            profiles.prepare_browser(self.home)
        self.write(self.state / "mode", "linux")
        with self.assertRaises(profiles.ProfileError):
            profiles.prepare_browser(self.home, profile_path="/home/debian/.mozilla/profile")
        with self.assertRaises(profiles.ProfileError):
            profiles.readiness_fields(b"STATUS=ready\nSTATUS=ready\n")
        with self.assertRaises(profiles.ProfileError):
            profiles.check_age({"UPTIME_SECONDS": "107"}, 106)
        with self.assertRaises(profiles.ProfileError):
            profiles.render_preferences("{{UNKNOWN}}", {"PH4_DEVICE_PIXEL_RATIO": "1"}, {"PH4_REPORTED_CORES": "8", "PH4_CPU_ARCHITECTURE": "x86_64"}, "Firefox 140.1")


if __name__ == "__main__":
    unittest.main()
