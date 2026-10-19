# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

if len(sys.argv) > 1 and sys.argv[1].endswith(".py"):
    MODULE = Path(sys.argv.pop(1))
else:
    MODULE = next(path for path in (
        Path(__file__).resolve().parents[4] / "lib/ph4ntxm/session_guard_persona.py",
        Path("config/includes.chroot/usr/lib/ph4ntxm/session_guard_persona.py"),
        Path("/usr/lib/ph4ntxm/session_guard_persona.py"),
    ) if path.is_file())
spec = importlib.util.spec_from_file_location("session_guard_persona", MODULE)
persona = importlib.util.module_from_spec(spec)
spec.loader.exec_module(persona)
HARDWARE = next(path for path in (
    MODULE.parent / "hardware",
    Path("config/includes.chroot/usr/lib/ph4ntxm/hardware"),
    Path("/usr/lib/ph4ntxm/hardware"),
) if (path / "personas.json").is_file())


def shell(values, preload=False):
    return "".join("export " + key + "=" + shlex.quote(str(value)) + "\n" for key, value in values.items()) + (persona.PRELOAD + "\n" if preload else "")


class PersonaTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.identity = self.root / "identity"
        self.identity.mkdir()
        self.hardware = self.root / "hardware"
        self.hardware.mkdir()
        for name in ("persona.py", "cpu_profile.py", "personas.json", "inventory.py"):
            shutil.copyfile(HARDWARE / name, self.hardware / name)
        self.dmi = self.root / "sysfs"
        self.dmi.mkdir()
        self.mountinfo = self.root / "mountinfo"
        self.cpuinfo = self.root / "cpuinfo"
        self.cpu_sysfs = self.root / "cpu"
        self.cpu_sysfs.mkdir()
        self.library = self.root / "gl.so"
        self.library.write_bytes(b"\x7fELF" + b"fixture" * 8)
        self.patches = [patch.object(persona, key, value) for key, value in {
            "IDENTITY": self.identity, "HARDWARE": self.hardware, "DMI": self.dmi,
            "MOUNTINFO": self.mountinfo, "GL_LIBRARY": self.library,
            "CPUINFO": self.cpuinfo, "CPU_SYSFS": self.cpu_sysfs,
            "OWNER": os.getuid(), "_CACHE": None,
        }.items()]
        for item in self.patches:
            item.start()
        self.mode = "linux"
        self.seed = "1" * 64
        self.jitter = "0123456789abcdef"
        self.populate()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()
        os.umask(self.previous_umask)

    def populate(self):
        module, _ = persona.catalog()
        self.profile = persona.strings(module.identity(module.choose(self.mode, self.seed)))
        self.resources = persona.strings(module.resources(module.profile(self.profile["PROFILE_ID"])))
        (self.identity / "hardware_profile").write_text(shell(self.profile))
        (self.identity / "cores_env").write_text(shell(self.resources))
        (self.identity / "boot_jitter").write_text(self.jitter + "\n")
        backing = self.identity / "fake_dmi"
        backing.mkdir(exist_ok=True)
        for target in self.dmi.iterdir():
            target.unlink()
        for target in backing.iterdir():
            target.unlink()
        expected = persona.dmi_values(self.mode, self.seed, self.jitter, self.profile)
        lines = []
        for index, (field, value) in enumerate(expected.items()):
            source = backing / field
            source.write_text(value)
            source.chmod(0o444)
            if field in ("sys_vendor", "product_name", "product_uuid"):
                target = self.dmi / field
                os.link(source, target)
                info = source.stat()
                device = str(os.major(info.st_dev)) + ":" + str(os.minor(info.st_dev))
                escaped = str(target).replace(" ", "\\040")
                lines.append(str(index + 10) + " 1 " + device + " /ph4ntxm/fake_dmi/" + field + " " + escaped + " ro,nosuid - tmpfs tmpfs rw\n")
        if self.cpuinfo.exists():
            self.cpuinfo.unlink()
        for target in self.cpu_sysfs.iterdir():
            target.unlink()
        for name in ("fake_cpuinfo", "fake_online"):
            source = self.identity / name
            if source.exists():
                source.unlink()
        (self.identity / "fake_cpuinfo").write_text(module.cpuinfo(self.resources))
        count = int(self.resources["PH4_REPORTED_CORES"])
        (self.identity / "fake_online").write_text(("0" if count == 1 else "0-" + str(count - 1)) + "\n")
        for name, target in (("fake_cpuinfo", self.cpuinfo), ("fake_online", self.cpu_sysfs / "online"), ("fake_online", self.cpu_sysfs / "present"), ("fake_online", self.cpu_sysfs / "possible")):
            source = self.identity / name
            source.chmod(0o444)
            os.link(source, target)
            info = source.stat()
            device = str(os.major(info.st_dev)) + ":" + str(os.minor(info.st_dev))
            lines.append(str(100 + len(lines)) + " 1 " + device + " /ph4ntxm/" + name + " " + str(target).replace(" ", "\\040") + " ro,nosuid - tmpfs tmpfs rw\n")
        self.mountinfo.write_text("".join(lines))
        vendor = self.profile["GPU_VENDOR"]
        stack = "mesa-radv" if vendor == "amd" else "mesa-asahi" if vendor == "apple" and self.profile["GPU_FAMILY"] != "intel" and self.mode != "lonewolf" else "mesa"
        (self.identity / "gpu_env").write_text(shell(persona.gpu_values(self.mode, self.seed, self.profile, stack), True))
        (self.identity / "screen_env").write_text(shell(persona.screen_values(self.mode, self.seed, self.jitter, self.profile)))

    def collect(self, baseline=None):
        return persona.collect(self.mode, self.seed, baseline)

    def assert_failed(self, checks, code):
        check = next(item for item in checks if item["code"] == code)
        self.assertFalse(check["healthy"])
        self.assertEqual(check["status"], "failed")
        self.assertLessEqual(len(check["detail"]), 2048)

    def test_all_modes_initialize_and_compare(self):
        for mode in ("linux", "windows", "lonewolf"):
            with self.subTest(mode=mode):
                self.mode = mode
                self.populate()
                checks, baseline = self.collect()
                self.assertTrue(all(item["healthy"] for item in checks), checks)
                self.assertEqual(set(baseline), {"persona", "dmi", "graphics"})
                self.assertTrue(all(item["healthy"] for item in self.collect(baseline)[0]))

    def test_public_details_and_private_evidence_exclude_identity_values(self):
        checks, baseline = self.collect()
        data = json.dumps([checks, baseline])
        for value in (self.seed, self.jitter, self.profile["PRODUCT_NAME"], (self.identity / "fake_dmi/product_uuid").read_text()):
            self.assertNotIn(value, data)
        (self.identity / "hardware_profile").write_text("secret-invalid-profile")
        self.assertNotIn("secret-invalid-profile", json.dumps(self.collect(baseline)[0]))

    def test_missing_and_partial_baselines_never_adopt(self):
        baseline = self.collect()[1]
        for code in baseline:
            for altered in ({key: value for key, value in baseline.items() if key != code}, {**baseline, code: {}}, {**baseline, code: None}):
                with self.subTest(code=code, baseline=altered):
                    self.assert_failed(self.collect(altered)[0], code)
        self.assertTrue(all(not item["healthy"] for item in self.collect({})[0]))

    def test_valid_alternate_profile_is_rejected(self):
        module, _ = persona.catalog()
        alternate = next(item for item in module.CATALOG if item["id"] != self.profile["PROFILE_ID"])
        (self.identity / "hardware_profile").write_text(shell(module.identity(alternate)))
        (self.identity / "cores_env").write_text(shell(module.resources(alternate)))
        self.assert_failed(self.collect()[0], "persona")

    def test_core_cache_tampering_rejected(self):
        baseline = self.collect()[1]
        self.resources["PH4_CACHE_L2"] = "1"
        (self.identity / "cores_env").write_text(shell(self.resources))
        self.assert_failed(self.collect(baseline)[0], "persona")

    def test_cpu_exposed_artifacts_and_mounts_are_required(self):
        baseline = self.collect()[1]
        for field in ("fake_cpuinfo", "fake_online"):
            with self.subTest(field=field):
                source = self.identity / field
                original = source.read_bytes()
                source.chmod(0o644)
                source.write_bytes(b"inconsistent\n")
                source.chmod(0o444)
                self.assert_failed(self.collect()[0], "persona")
                source.chmod(0o644)
                source.write_bytes(original)
                source.chmod(0o444)
        original = self.mountinfo.read_text()
        for target in (self.cpuinfo, *(self.cpu_sysfs / field for field in ("online", "present", "possible"))):
            with self.subTest(target=target):
                self.mountinfo.write_text("\n".join(line for line in original.splitlines() if str(target) not in line) + "\n")
                self.assert_failed(self.collect(baseline)[0], "persona")
        self.mountinfo.write_text(original)

    def test_cpu_same_content_wrong_backing_rejected(self):
        original = self.cpuinfo.read_bytes()
        self.cpuinfo.unlink()
        self.cpuinfo.write_bytes(original)
        self.cpuinfo.chmod(0o444)
        self.assert_failed(self.collect()[0], "persona")

    def test_cpu_online_range_exactly_matches_selected_thread_count(self):
        source = self.identity / "fake_online"
        source.chmod(0o644)
        source.write_text("0-999\n")
        source.chmod(0o444)
        self.assert_failed(self.collect()[0], "persona")

    def test_seqfile_short_reads_are_consumed_to_bounded_eof(self):
        original = os.read
        with patch.object(persona.os, "read", side_effect=lambda descriptor, size: original(descriptor, min(size, 37))):
            self.assertTrue(all(item["healthy"] for item in self.collect()[0]))

    def test_unrelated_filesystem_names_do_not_invalidate_identity_mounts(self):
        baseline = self.collect()[1]
        original = self.mountinfo.read_bytes()
        for label in (b"R\xc3\xa9sum\xc3\xa9", b"reports\xe2\x80\xa82026", b"backup\xff"):
            with self.subTest(label=label):
                self.mountinfo.write_bytes(original + b"9999 1 0:900 / /media/user/" + label + b" ro - tmpfs tmpfs rw\n")
                checks = self.collect(baseline)[0]
                self.assertTrue(all(item["healthy"] for item in checks), checks)

    def test_different_valid_seed_rejected(self):
        baseline = self.collect()[1]
        self.seed = "2" * 64
        checks = self.collect(baseline)[0]
        self.assertTrue(any(not item["healthy"] for item in checks))

    def test_catalog_drift_rejected_after_activation(self):
        baseline = self.collect()[1]
        path = self.hardware / "personas.json"
        path.write_text(path.read_text() + "\n")
        self.assert_failed(self.collect(baseline)[0], "persona")

    def test_no_import_bytecode_is_written(self):
        self.collect()
        self.assertFalse((self.hardware / "__pycache__").exists())

    def test_changed_catalog_source_is_not_executed_after_activation(self):
        baseline = self.collect()[1]
        source = self.hardware / "persona.py"
        source.write_text("raise RuntimeError('must not execute changed catalog source')\n")
        self.assert_failed(self.collect(baseline)[0], "persona")

    def test_missing_catalog_baseline_is_not_relearned(self):
        baseline = self.collect()[1]
        baseline["persona"]["sources"] = None
        with patch.object(persona.ProtectedLoader, "exec_module", side_effect=AssertionError("must not import")):
            self.assert_failed(self.collect(baseline)[0], "persona")

    def test_invalid_modes_and_seeds_fail_all_groups(self):
        for mode, seed in (("invalid", self.seed), ("linux", "x" * 64), ("linux", None)):
            checks, _ = persona.collect(mode, seed)
            self.assertTrue(all(not item["healthy"] for item in checks))

    def test_identity_directory_permissions_rejected(self):
        self.identity.chmod(0o777)
        self.assertTrue(all(not item["healthy"] for item in self.collect()[0]))

    def test_environment_symlink_and_writable_files_rejected(self):
        for name, code in (("hardware_profile", "persona"), ("cores_env", "persona"), ("gpu_env", "graphics"), ("screen_env", "graphics")):
            with self.subTest(name=name):
                path = self.identity / name
                value = path.read_text()
                path.chmod(0o666)
                self.assert_failed(self.collect()[0], code)
                path.chmod(0o644)
                alternate = self.root / "alternate"
                alternate.write_text(value)
                path.unlink()
                path.symlink_to(alternate)
                self.assert_failed(self.collect()[0], code)
                path.unlink()
                path.write_text(value)

    def test_export_parser_never_accepts_executable_shell(self):
        for value in (b"export KEY=value\ntouch /tmp/unwanted\n", b"export KEY=value; touch /tmp/unwanted\n", b"export KEY=value\nexport KEY=other\n", b"source /tmp/unwanted\n"):
            with self.assertRaises(ValueError):
                persona.exports(value)
        self.assertEqual(persona.exports(b"export VALUE='$(touch /tmp/unwanted)'\n"), {"VALUE": "$(touch /tmp/unwanted)"})

    def test_dmi_mount_lost_or_writable_rejected(self):
        baseline = self.collect()[1]
        original = self.mountinfo.read_text()
        self.mountinfo.write_text("\n".join(original.splitlines()[1:]) + "\n")
        self.assert_failed(self.collect(baseline)[0], "dmi")
        self.mountinfo.write_text(original.replace(" ro,nosuid ", " rw,nosuid "))
        self.assert_failed(self.collect(baseline)[0], "dmi")

    def test_dmi_same_content_wrong_backing_rejected(self):
        baseline = self.collect()[1]
        target = self.dmi / "product_name"
        value = target.read_text()
        target.unlink()
        target.write_text(value)
        target.chmod(0o444)
        self.assert_failed(self.collect(baseline)[0], "dmi")

    def test_namespace_mount_id_changes_preserve_same_backing(self):
        baseline = self.collect()[1]
        text = self.mountinfo.read_text()
        self.mountinfo.write_text("\n".join(str(900 + index) + line[line.index(" "):] for index, line in enumerate(text.splitlines())) + "\n")
        self.assertTrue(all(item["healthy"] for item in self.collect(baseline)[0]))

    def test_dmi_mount_root_changes_rejected(self):
        baseline = self.collect()[1]
        text = self.mountinfo.read_text()
        self.mountinfo.write_text(text.replace("/ph4ntxm/fake_dmi/", "/different-root/"))
        self.assert_failed(self.collect(baseline)[0], "dmi")

    def test_dmi_missing_and_extra_artifacts_rejected(self):
        path = self.identity / "fake_dmi/board_name"
        raw = path.read_bytes()
        path.unlink()
        self.assert_failed(self.collect()[0], "dmi")
        path.write_bytes(raw)
        path.chmod(0o444)
        (self.identity / "fake_dmi/unexpected").write_text("value")
        self.assert_failed(self.collect()[0], "dmi")

    def test_dmi_values_and_jitter_are_checked_without_baseline(self):
        uuid = self.identity / "fake_dmi/product_uuid"
        uuid.chmod(0o644)
        uuid.write_text("00000000-0000-4000-8000-000000000000")
        uuid.chmod(0o444)
        self.assert_failed(self.collect()[0], "dmi")
        self.populate()
        (self.identity / "boot_jitter").write_text("invalid")
        self.assert_failed(self.collect()[0], "dmi")

    def test_host_unsupported_dmi_fields_are_skipped(self):
        checks, evidence = self.collect()
        self.assertTrue(next(item for item in checks if item["code"] == "dmi")["healthy"])
        self.assertEqual(set(evidence["dmi"]["targets"]), {"sys_vendor", "product_name", "product_uuid"})
        for path in self.dmi.iterdir():
            path.unlink()
        self.mountinfo.write_text("")
        checks, evidence = self.collect()
        self.assertTrue(next(item for item in checks if item["code"] == "dmi")["healthy"])
        self.assertEqual(evidence["dmi"]["targets"], {})
        self.dmi.rmdir()
        self.assertTrue(next(item for item in self.collect()[0] if item["code"] == "dmi")["healthy"])

    def test_dmi_supported_target_disappearance_rejected(self):
        baseline = self.collect()[1]
        (self.dmi / "product_uuid").unlink()
        self.assert_failed(self.collect(baseline)[0], "dmi")

    def test_dynamic_dmi_algorithms_match_mode_specific_contract(self):
        profile = dict(self.profile, VENDOR="lenovo")
        raw = hashlib.sha256((self.seed + "uuid-base" + self.jitter).encode()).hexdigest().upper()
        serial = "PF" + hashlib.sha256((self.seed + "s1" + self.jitter).encode()).hexdigest()[:8].upper()
        for mode in ("linux", "windows", "lonewolf"):
            values = persona.dmi_values(mode, self.seed, self.jitter, profile)
            self.assertEqual(values["product_serial"], serial)
            self.assertEqual(values["chassis_serial"], serial)
            self.assertEqual(values["product_uuid"][:15], raw[:8] + "-" + raw[8:12] + "-4")
            expected = "MB-" + (hashlib.sha256((self.seed + "brd" + self.jitter).encode()).hexdigest()[:12].upper() if mode == "lonewolf" else serial[:10])
            self.assertEqual(values["board_serial"], expected)

    def test_gpu_model_and_screen_mutations_rejected(self):
        for name, key, replacement in (("gpu_env", "PH4NTXM_GPU_MODEL", "changed-model"), ("screen_env", "PH4_DISPLAY_WIDTH", "1234"), ("screen_env", "PH4_DEVICE_CLASS", "server")):
            with self.subTest(name=name, key=key):
                path = self.identity / name
                raw = path.read_text()
                values = persona.exports(raw.encode(), preload=name == "gpu_env")
                values[key] = replacement
                path.write_text(shell(values, name == "gpu_env"))
                self.assert_failed(self.collect()[0], "graphics")
                path.write_text(raw)

    def test_gpu_stack_is_pinned_without_host_module_queries(self):
        profile = dict(self.profile, GPU_VENDOR="nvidia", GPU_FAMILY="gtx", GPU_MODEL="test-nvidia")
        mesa = persona.gpu_values("linux", self.seed, profile, "mesa")
        nvidia = persona.gpu_values("linux", self.seed, profile, "nvidia")
        self.assertNotIn("__GLX_VENDOR_LIBRARY_NAME", mesa)
        self.assertEqual(nvidia["__GLX_VENDOR_LIBRARY_NAME"], "nvidia")
        self.assertNotIn("MESA_GL_VERSION_OVERRIDE", nvidia)
        with self.assertRaises(ValueError):
            persona.gpu_values("linux", self.seed, profile, "arbitrary")

    def test_mode_specific_gpu_contract(self):
        profile = dict(self.profile, GPU_VENDOR="apple", GPU_FAMILY="intel", GPU_MODEL="Intel model")
        normal = persona.gpu_values("linux", self.seed, profile, "mesa")
        lonewolf = persona.gpu_values("lonewolf", self.seed, profile, "mesa")
        self.assertEqual(normal["PH4NTXM_GL_VENDOR"], "Intel Inc.")
        self.assertEqual(normal["MESA_GL_VERSION_OVERRIDE"], "4.1")
        self.assertEqual(lonewolf["PH4NTXM_GL_VENDOR"], "Mesa")
        self.assertEqual(lonewolf["MESA_GL_VERSION_OVERRIDE"], "4.6")
        self.assertNotIn("__GL_VENDOR", normal)
        self.assertEqual(lonewolf["__GL_VENDOR"], "Mesa")

    def test_normal_and_lonewolf_screen_contracts(self):
        profile = dict(self.profile, FAMILY="thinkpad", DEVICE_CLASS="laptop", GPU_VENDOR="intel", VENDOR="lenovo")
        normal = persona.screen_values("windows", self.seed, self.jitter, profile)
        self.assertEqual((normal["PH4_PRIMARY_DISPLAY"], normal["PH4_DISPLAY_WIDTH"], normal["PH4_DISPLAY_HEIGHT"], normal["PH4_DISPLAY_REFRESH"], normal["PH4_DEVICE_PIXEL_RATIO"]), ("eDP-1", "1920", "1080", "60", "1.25"))
        lonewolf = persona.screen_values("lonewolf", self.seed, self.jitter, profile)
        self.assertEqual(lonewolf["PH4_PRIMARY_DISPLAY"], "DISPLAY-1")
        self.assertEqual(lonewolf["PH4_DISPLAY_CLASS"], "business")
        self.assertNotIn("PH4_SECONDARY_DISPLAY", lonewolf)
        self.assertEqual(lonewolf["PH4_DISPLAY_REFRESH"], "60")

    def test_gl_library_drift_and_missing_preload_rejected(self):
        baseline = self.collect()[1]
        self.library.write_bytes(b"\x7fELFchanged")
        self.assert_failed(self.collect(baseline)[0], "graphics")
        gpu = self.identity / "gpu_env"
        gpu.write_text(gpu.read_text().replace(persona.PRELOAD, ""))
        self.assert_failed(self.collect()[0], "graphics")

    def test_all_catalog_personas_have_valid_profiles_without_host_capacity_checks(self):
        module, _ = persona.catalog()
        for item in module.CATALOG:
            profile = persona.strings(module.identity(item))
            resources = persona.strings(module.resources(item))
            self.assertGreater(int(resources["PH4_USABLE_RAM_BYTES"]), 0)
            for mode in ("linux", "windows", "lonewolf"):
                with self.subTest(profile=item["id"], mode=mode):
                    screen = persona.screen_values(mode, self.seed, self.jitter, profile)
                    self.assertGreater(int(screen["PH4_DISPLAY_WIDTH"]), 0)
                    self.assertGreater(int(screen["PH4_DISPLAY_HEIGHT"]), 0)
                    self.assertGreater(float(screen["PH4_DEVICE_PIXEL_RATIO"]), 0)

    def test_environment_and_mountinfo_size_limits(self):
        (self.identity / "cores_env").write_bytes(b"x" * 32769)
        self.assert_failed(self.collect()[0], "persona")
        self.mountinfo.write_bytes(b"x" * 1048577)
        self.assert_failed(self.collect()[0], "dmi")

    def test_diagnostics_identify_cpu_mount_and_dmi_uuid(self):
        original = self.mountinfo.read_text()
        target = self.cpu_sysfs / "possible"
        self.mountinfo.write_text("\n".join(line for line in original.splitlines() if str(target) not in line) + "\n")
        detail = next(item["detail"] for item in self.collect()[0] if item["code"] == "persona")
        self.assertIn("CPU possible mount", detail)
        self.mountinfo.write_text(original)
        path = self.identity / "fake_dmi/product_uuid"
        path.chmod(0o644)
        path.write_text("private-invalid-uuid")
        path.chmod(0o444)
        detail = next(item["detail"] for item in self.collect()[0] if item["code"] == "dmi")
        self.assertIn("DMI product_uuid", detail)
        self.assertNotIn("private-invalid-uuid", detail)

    def test_diagnostics_identify_gpu_and_screen_export_fields(self):
        for name, field in (("gpu_env", "PH4NTXM_GPU_MODEL"), ("screen_env", "PH4_DISPLAY_WIDTH")):
            path = self.identity / name
            original = path.read_bytes()
            values = persona.exports(original, preload=name == "gpu_env")
            values[field] = "private-invalid-value"
            path.write_text(shell(values, name == "gpu_env"))
            detail = next(item["detail"] for item in self.collect()[0] if item["code"] == "graphics")
            self.assertIn(field, detail)
            self.assertNotIn("private-invalid-value", detail)
            path.write_bytes(original)

    def test_baseline_diagnostics_identify_mount_root_and_library(self):
        baseline = self.collect()[1]
        original = self.mountinfo.read_text()
        self.mountinfo.write_text(original.replace("/ph4ntxm/fake_dmi/product_uuid", "/other-root/product_uuid"))
        detail = next(item["detail"] for item in self.collect(baseline)[0] if item["code"] == "dmi")
        self.assertIn("DMI product_uuid mount root", detail)
        self.mountinfo.write_text(original)
        self.library.write_bytes(b"\x7fELFchanged")
        detail = next(item["detail"] for item in self.collect(baseline)[0] if item["code"] == "graphics")
        self.assertIn("GL identity library", detail)


if __name__ == "__main__":
    unittest.main()
