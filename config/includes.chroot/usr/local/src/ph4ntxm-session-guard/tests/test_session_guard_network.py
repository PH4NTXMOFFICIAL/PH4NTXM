# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


def module_path():
    if len(sys.argv) > 1 and sys.argv[1].endswith(".py"):
        return Path(sys.argv.pop(1))
    for root in Path(__file__).resolve().parents:
        candidate = root / "config/includes.chroot/usr/lib/ph4ntxm/session_guard_network.py"
        if candidate.is_file():
            return candidate
    return Path("/usr/lib/ph4ntxm/session_guard_network.py")


spec = importlib.util.spec_from_file_location("session_guard_network", module_path())
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.identity = self.root / "identity"
        self.nm = self.root / "nm" / "90-ph4ntxm-session.conf"
        self.net = self.root / "net"
        self.proc = self.root / "proc"
        for path in (self.identity, self.nm.parent, self.net, self.proc):
            path.mkdir(mode=0o755, parents=True)
        self.patches = [
            patch.object(network, "IDENTITY", self.identity),
            patch.object(network, "NM_PROFILE", self.nm),
            patch.object(network, "NET_CLASS", self.net),
            patch.object(network, "PROC_SYS", self.proc),
        ]
        for item in self.patches:
            item.start()
        self.seed = "a" * 64
        self.real_reader = network.read_text
        self.real_fstat = os.fstat
        self.real_lstat = Path.lstat
        self.calls = []
        self.reader = patch.object(network, "read_text", side_effect=self.fixture_read)
        self.reader.start()
        self.prepare("linux")
        self.adapter("eth0")

    def tearDown(self):
        self.reader.stop()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def root_owned(self, info):
        values = list(info)
        values[4] = 0
        return os.stat_result(values)

    def fixture_read(self, path, **kwargs):
        path = Path(path)
        self.assertTrue(path.is_relative_to(self.root))
        self.calls.append(path)
        original_lstat = self.real_lstat
        root_owned = self.root_owned
        with patch.object(network.os, "fstat", side_effect=lambda fd: root_owned(self.real_fstat(fd))), patch.object(
            Path, "lstat", lambda target: root_owned(original_lstat(target))
        ):
            return self.real_reader(path, **kwargs)

    def write(self, path, content, mode=0o600):
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)

    def prepare(self, mode):
        self.mode = mode
        self.write(self.identity / "boot_hostname", "private-host")
        session = {"MODE": mode, "TIMEOUT": "60", "TOR": "enabled"}
        profile = {
            "ipv4.dhcp-client-id": "mac", "ipv4.dhcp-send-hostname": "false",
            "ipv4.dhcp-timeout": "60", "ipv6.dhcp-send-hostname": "false",
            "ethernet.cloned-mac-address": "preserve", "wifi.cloned-mac-address": "preserve",
        }
        if mode in ("linux", "windows"):
            vendor, timeout, duid = ("dhclient", "60", "ll") if mode == "linux" else ("MSFT 5.0", "45", "stable-uuid")
            session = {"MODE": mode, "VENDOR": vendor, "HOSTNAME": "private-host", "TIMEOUT": timeout, "DUID": duid}
            profile.update({
                "ipv4.dhcp-vendor-class-identifier": vendor,
                "ipv4.dhcp-send-hostname": "true", "ipv4.dhcp-timeout": timeout,
                "ipv6.dhcp-duid": duid, "ipv6.dhcp-send-hostname": "true", "ipv6.ip6-privacy": "2",
            })
        self.write(self.identity / "session_dhcp", "\n".join(key + "=" + shlex.quote(value) for key, value in session.items()))
        self.write(self.nm, "[connection-ph4ntxm-session]\n" + "\n".join(key + "=" + value for key, value in profile.items()), 0o644)
        required, optional = network.network_specs(mode)
        for key, expected in {**required, **optional}.items():
            if isinstance(expected, str):
                value = expected
            elif isinstance(expected[0], tuple):
                value = "\t".join(str(bounds[0]) for bounds in expected)
            else:
                value = str(expected[0])
            self.write(self.proc.joinpath(*key.split(".")), value, 0o644)

    def adapter(self, name, address="02:12:34:56:78:90", index="2", device_name="card0", kind="1"):
        device = self.root / "devices" / device_name
        node = device / "net" / name
        node.mkdir(mode=0o755, parents=True)
        (node / "device").symlink_to(device, target_is_directory=True)
        (self.net / name).symlink_to(node, target_is_directory=True)
        self.write(node / "address", address, 0o644)
        self.write(node / "ifindex", index, 0o644)
        self.write(node / "type", kind, 0o644)
        return node

    def collect(self, baseline=None):
        checks, evidence = network.collect(self.mode, self.seed, baseline)
        return {item["code"]: item for item in checks}, evidence

    def test_all_modes_start_with_complete_evidence(self):
        for mode in ("linux", "windows", "lonewolf"):
            with self.subTest(mode=mode):
                self.prepare(mode)
                checks, baseline = self.collect()
                self.assertTrue(all(item["healthy"] for item in checks.values()), checks)
                self.assertEqual(set(baseline), {"mac", "dhcp", "network_profile"})
                self.assertTrue(all(item["healthy"] for item in self.collect(baseline)[0].values()))

    def test_mac_change_including_manual_change_is_reported_without_addresses(self):
        checks, baseline = self.collect()
        self.write(self.net / "eth0" / "address", "02:aa:bb:cc:dd:ee", 0o644)
        checks, evidence = self.collect(baseline)
        self.assertFalse(checks["mac"]["healthy"])
        self.assertIn("eth0 MAC changed", checks["mac"]["detail"])
        self.assertEqual(evidence["mac"], baseline["mac"])
        public = json.dumps(checks)
        for value in ("02:aa:bb:cc:dd:ee", "02:12:34:56:78:90", self.seed, "private-host"):
            self.assertNotIn(value, public)
        self.assertNotIn("02:12:34:56:78:90", json.dumps(baseline))

    def test_new_adapter_is_distinct_from_mac_change_and_is_not_adopted(self):
        checks, baseline = self.collect()
        self.adapter("eth1", "02:aa:bb:cc:dd:ee", "3", "card1")
        checks, evidence = self.collect(baseline)
        self.assertFalse(checks["mac"]["healthy"])
        self.assertIn("New physical network adapter appeared", checks["mac"]["detail"])
        self.assertNotIn("MAC changed", checks["mac"]["detail"])
        self.assertEqual(evidence["mac"], baseline["mac"])
        self.assertFalse(self.collect(baseline)[0]["mac"]["healthy"])

    def test_unplug_and_reconnect_do_not_change_baseline(self):
        checks, baseline = self.collect()
        old_node = (self.net / "eth0").resolve()
        (self.net / "eth0").unlink()
        checks, evidence = self.collect(baseline)
        self.assertTrue(checks["mac"]["healthy"])
        self.assertIn("absent", checks["mac"]["detail"])
        self.assertEqual(evidence["mac"], baseline["mac"])
        (self.net / "eth0").symlink_to(old_node, target_is_directory=True)
        self.assertTrue(self.collect(baseline)[0]["mac"]["healthy"])

    def test_ifname_and_index_reuse_for_replacement_are_not_mac_change(self):
        checks, baseline = self.collect()
        (self.net / "eth0").unlink()
        self.adapter("eth0", "02:aa:bb:cc:dd:ee", "2", "replacement")
        checks, evidence = self.collect(baseline)
        self.assertFalse(checks["mac"]["healthy"])
        self.assertIn("New physical", checks["mac"]["detail"])
        self.assertNotIn("MAC changed", checks["mac"]["detail"])

    def test_renamed_existing_netdev_still_compares_mac(self):
        checks, baseline = self.collect()
        node = (self.net / "eth0").resolve()
        new_node = node.with_name("renamed0")
        node.rename(new_node)
        (self.net / "eth0").unlink()
        (self.net / "renamed0").symlink_to(new_node, target_is_directory=True)
        self.assertTrue(self.collect(baseline)[0]["mac"]["healthy"])
        self.write(new_node / "address", "02:aa:bb:cc:dd:ee", 0o644)
        checks, evidence = self.collect(baseline)
        self.assertIn("renamed0 MAC changed", checks["mac"]["detail"])

    def test_no_interfaces_or_non_ethernet_adapters_are_valid(self):
        (self.net / "eth0").unlink()
        self.adapter("wwan0", "invalid", "3", "modem", kind="65534")
        checks, evidence = self.collect()
        self.assertTrue(checks["mac"]["healthy"])
        self.assertEqual(evidence["mac"], {"adapters": {}})

    def test_explicit_empty_or_missing_baselines_never_initialize(self):
        for baseline in ({}, {"mac": {}}, {"dhcp": {}}, {"network_profile": {}}):
            with self.subTest(baseline=baseline):
                checks, evidence = self.collect(baseline)
                self.assertTrue(all(not item["healthy"] for item in checks.values()))
                self.assertTrue(all("baseline" in item["detail"] for item in checks.values()))

    def test_malformed_nested_baselines_fail_without_exception(self):
        checks, baseline = self.collect()
        cases = (
            ("mac", {"adapters": {"bad": "bad"}}),
            ("dhcp", {"profile": None}),
            ("network_profile", {"mode": network.digest("linux"), "optional": [{}]}),
        )
        for code, record in cases:
            with self.subTest(code=code):
                changed = dict(baseline)
                changed[code] = record
                self.assertFalse(self.collect(changed)[0][code]["healthy"])

    def test_dhcp_mode_hostname_vendor_and_networkmanager_drift(self):
        checks, baseline = self.collect()
        for path, before, after in (
            (self.identity / "session_dhcp", "dhclient", "other"),
            (self.identity / "session_dhcp", "private-host", "changed-host"),
            (self.nm, "ipv4.dhcp-send-hostname=true", "ipv4.dhcp-send-hostname=false"),
        ):
            with self.subTest(path=path, value=after):
                original = path.read_text()
                path.write_text(original.replace(before, after))
                checks, evidence = self.collect(baseline)
                self.assertFalse(checks["dhcp"]["healthy"])
                self.assertNotIn(after, checks["dhcp"]["detail"])
                path.write_text(original)

    def test_dhcp_duplicate_or_shell_payload_is_not_evaluated(self):
        payload = self.root / "unexpected"
        for value in ("MODE=linux\nMODE=windows", "MODE=$(touch " + str(payload) + ")"):
            self.write(self.identity / "session_dhcp", value)
            self.assertFalse(self.collect()[0]["dhcp"]["healthy"])
            self.assertFalse(payload.exists())

    def test_lonewolf_does_not_require_hostname(self):
        self.prepare("lonewolf")
        (self.identity / "boot_hostname").unlink()
        self.assertTrue(self.collect()[0]["dhcp"]["healthy"])

    def test_bounded_values_are_admitted_but_frozen_after_activation(self):
        checks, baseline = self.collect()
        key = self.proc / "net/ipv4/tcp_fin_timeout"
        self.write(key, "50", 0o644)
        self.assertTrue(self.collect()[0]["network_profile"]["healthy"])
        checks, evidence = self.collect(baseline)
        self.assertFalse(checks["network_profile"]["healthy"])
        self.assertIn("tcp_fin_timeout changed", checks["network_profile"]["detail"])
        self.assertEqual(evidence["network_profile"], baseline["network_profile"])
        self.write(key, "51", 0o644)
        self.assertFalse(self.collect(baseline)[0]["network_profile"]["healthy"])
        self.write(key, "40", 0o644)
        self.write(self.proc / "net/ipv4/tcp_timestamps", "0", 0o644)
        self.assertFalse(self.collect(baseline)[0]["network_profile"]["healthy"])

    def test_normal_mode_buffers_are_read_and_hashed_without_writes(self):
        paths = [self.proc / "net/ipv4/tcp_rmem", self.proc / "net/ipv4/tcp_wmem"]
        before = {path: path.read_bytes() for path in paths}
        checks, baseline = self.collect()
        self.assertTrue(all(path in self.calls for path in paths))
        self.assertEqual(before, {path: path.read_bytes() for path in paths})
        for path in paths:
            key = "net.ipv4." + path.name
            self.assertTrue(network.valid_digest(baseline["network_profile"]["values"][key]))
            self.assertNotIn(path.read_text(), json.dumps(baseline))

    def test_within_range_buffer_and_random_scalar_drift_is_detected_in_all_modes(self):
        for mode in ("linux", "windows", "lonewolf"):
            self.prepare(mode)
            checks, baseline = self.collect()
            paths = [self.proc / "net/ipv4/tcp_fin_timeout"]
            if mode != "lonewolf":
                paths.extend([self.proc / "net/ipv4/tcp_rmem", self.proc / "net/ipv4/tcp_wmem"])
            for path in paths:
                with self.subTest(mode=mode, key=path.name):
                    original = path.read_text()
                    parts = original.split()
                    parts[0] = str(int(parts[0]) + 1)
                    self.write(path, " ".join(parts), 0o644)
                    self.assertTrue(self.collect()[0]["network_profile"]["healthy"])
                    checks, evidence = self.collect(baseline)
                    self.assertFalse(checks["network_profile"]["healthy"])
                    self.assertIn(path.name + " changed", checks["network_profile"]["detail"])
                    self.assertEqual(evidence["network_profile"], baseline["network_profile"])
                    self.write(path, original, 0o644)

    def test_buffer_minimum_clamp_floor_and_triad_schema(self):
        path = self.proc / "net/ipv4/tcp_rmem"
        for mode in ("linux", "windows"):
            self.prepare(mode)
            self.write(path, "4096 65536 5242880", 0o644)
            self.assertTrue(self.collect()[0]["network_profile"]["healthy"])
            for value in ("2048 65536 5242880", "4096 65536", "4096 5242880 65536", "4096 bad 5242880"):
                with self.subTest(mode=mode, value=value):
                    self.write(path, value, 0o644)
                    self.assertFalse(self.collect()[0]["network_profile"]["healthy"])

    def test_buffer_whitespace_normalization_does_not_trigger_drift(self):
        checks, baseline = self.collect()
        path = self.proc / "net/ipv4/tcp_rmem"
        self.write(path, "  " + "   ".join(path.read_text().split()) + "\n", 0o644)
        self.assertTrue(self.collect(baseline)[0]["network_profile"]["healthy"])

    def test_missing_or_corrupt_frozen_sysctl_evidence_never_adopts(self):
        checks, baseline = self.collect()
        for replacement in (None, {}, {"net.ipv4.ip_default_ttl": "bad"}):
            changed = dict(baseline)
            changed["network_profile"] = dict(baseline["network_profile"], values=replacement)
            checks, evidence = self.collect(changed)
            self.assertFalse(checks["network_profile"]["healthy"])
            self.assertIn("baseline", checks["network_profile"]["detail"])

    def test_optional_knob_missing_at_activation_is_supported_but_disappearance_is_detected(self):
        optional = self.proc / "net/mptcp/enabled"
        optional.unlink()
        checks, baseline = self.collect()
        self.assertTrue(checks["network_profile"]["healthy"])
        self.assertEqual(baseline["network_profile"]["optional"], [])
        self.assertTrue(self.collect(baseline)[0]["network_profile"]["healthy"])
        self.write(optional, "0", 0o644)
        appeared = self.collect(baseline)[0]["network_profile"]
        self.assertFalse(appeared["healthy"])
        self.assertIn("appeared after", appeared["detail"])
        checks, with_optional = self.collect()
        optional.unlink()
        disappeared = self.collect(with_optional)[0]["network_profile"]
        self.assertFalse(disappeared["healthy"])
        self.assertIn("disappeared after", disappeared["detail"])

    def test_optional_present_knob_is_validated_even_if_absent_at_activation(self):
        optional = self.proc / "net/mptcp/enabled"
        optional.unlink()
        checks, baseline = self.collect()
        self.write(optional, "1", 0o644)
        self.assertFalse(self.collect(baseline)[0]["network_profile"]["healthy"])

    def test_required_knob_missing_is_failure(self):
        (self.proc / "net/ipv4/ip_default_ttl").unlink()
        self.assertFalse(self.collect()[0]["network_profile"]["healthy"])

    def test_protected_dhcp_permissions_symlink_and_size_are_rejected(self):
        path = self.identity / "session_dhcp"
        path.chmod(0o644)
        self.assertFalse(self.collect()[0]["dhcp"]["healthy"])
        path.chmod(0o600)
        target = path.with_name("target")
        path.rename(target)
        path.symlink_to(target)
        self.assertFalse(self.collect()[0]["dhcp"]["healthy"])
        path.unlink()
        self.write(path, "x" * (network.MAX_INPUT + 1))
        self.assertFalse(self.collect()[0]["dhcp"]["healthy"])

    def test_read_errors_and_detail_are_bounded(self):
        with patch.object(network, "physical_adapters", side_effect=PermissionError("private address")):
            checks, evidence = self.collect()
        self.assertFalse(checks["mac"]["healthy"])
        self.assertNotIn("private address", json.dumps(checks))
        self.assertLessEqual(len(network.result("mac", ["x" * 10000])["detail"]), 2048)


class ClockTests(unittest.TestCase):
    def profile(self, mode):
        offset_min, offset_max, tick_min, tick_max = network.CLOCK_LIMITS[mode]
        return {
            "MODE": mode, "OFFSET_SECONDS": str(offset_max), "INITIAL_TICK": str(tick_min),
            "CURRENT_TICK": str(tick_max), "MIN_TICK": str(tick_min), "MAX_TICK": str(tick_max),
            "SKEW_APPLIED": "1",
        }

    def test_all_mode_ranges_accept_deliberate_tick_variation(self):
        for mode in network.CLOCK_LIMITS:
            with self.subTest(mode=mode):
                profile = self.profile(mode)
                self.assertEqual(network.clock_problems(mode, profile), [])
                profile["CURRENT_TICK"] = profile["INITIAL_TICK"]
                self.assertEqual(network.clock_problems(mode, profile), [])

    def test_numeric_and_mode_drift(self):
        for key, value in (
            ("MODE", "windows"), ("SKEW_APPLIED", "0"), ("OFFSET_SECONDS", "21"),
            ("INITIAL_TICK", "9993"), ("CURRENT_TICK", "10007"), ("MIN_TICK", "9993"),
            ("MAX_TICK", "10007"), ("CURRENT_TICK", "bad"), ("OFFSET_SECONDS", "9" * 10000),
        ):
            with self.subTest(key=key):
                profile = self.profile("linux")
                profile[key] = value
                self.assertTrue(network.clock_problems("linux", profile))

    def test_missing_extra_and_invalid_fields(self):
        profile = self.profile("linux")
        del profile["CURRENT_TICK"]
        self.assertTrue(network.clock_problems("linux", profile))
        profile = self.profile("linux")
        profile["EXTRA"] = "1"
        self.assertTrue(network.clock_problems("linux", profile))
        self.assertTrue(network.clock_problems("unknown", {}))
        self.assertTrue(network.clock_problems("linux", None))


if __name__ == "__main__":
    unittest.main()
