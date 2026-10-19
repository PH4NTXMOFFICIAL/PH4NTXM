# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.util
import copy
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

MODULE = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path("config/includes.chroot/usr/lib/ph4ntxm/session_guard.py")
sys.path.insert(0, str(MODULE.parent))
spec = importlib.util.spec_from_file_location("session_guard", MODULE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def clock_profile(mode="linux", applied="1"):
    low, high = {"linux": (9994, 10006), "windows": (9988, 10012), "lonewolf": (9985, 10015)}[mode]
    return (
        "MODE=" + mode + "\nOFFSET_SECONDS=0\nINITIAL_TICK=10000\nCURRENT_TICK=10000"
        + "\nMIN_TICK=" + str(low) + "\nMAX_TICK=" + str(high) + "\nSKEW_APPLIED=" + applied
    )


def healthy_unit(kind="continuous"):
    return {
        "LoadState": "loaded",
        "Result": "success",
        "ConditionResult": "yes",
        "ExecMainStatus": "0",
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": "42",
        "Type": "notify",
        "ExecMainStartTimestampMonotonic": "100",
        "Job": "0 /",
    } if kind == "continuous" else {
            "LoadState": "loaded", "Result": "success", "ConditionResult": "yes", "ExecMainStatus": "0",
            "ActiveState": "inactive", "SubState": "dead", "Type": "oneshot",
            "ExecMainStartTimestampMonotonic": "100", "Job": "0 /"}


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.identity = self.root / "identity"
        self.identity.mkdir()
        self.runtime = self.root / "guard"
        self.runtime.mkdir(mode=0o755)
        self.boot_id = self.root / "boot-id"
        self.boot_id.write_text("a" * 32)
        self.public = self.runtime / "status.json"
        self.patches = [patch.object(guard, "RUNTIME", self.runtime), patch.object(guard, "STATE", self.runtime / "state.json"),
                        patch.object(guard, "PUBLIC", self.public), patch.object(guard, "BOOT_ID", self.boot_id),
                        patch.object(guard, "IDENTITY", self.identity)]
        self.patches.append(patch.object(guard, "collect_generated", side_effect=lambda *args: ([], {})))
        for item in self.patches:
            item.start()
        self.fake = {
            "mode": "linux", "identity-ready": "linux", "persona_seed": "1" * 64,
            "boot_machine_id": "2" * 32, "machine-id": "2" * 32,
            "boot_hostname": "private-host", "hostname": "private-host",
            "clock-fuzz-profile": clock_profile(),
            "kexec_crash_loaded": "1", "kexec_load_disabled": "1",
            "firewall-ready": "PROFILE=normal\nRULESET_SHA256=" + "3" * 64 + "\nUPTIME_SECONDS=99",
            "packet-transformation-engine-guard-ready": "STATUS=ready\nPROFILE=normal\nINTERFACES=1\nUPTIME_SECONDS=99",
        }
        self.reader = patch.object(guard, "read_text", side_effect=lambda path, *args, **kwargs: self.fake[path.name])
        self.units = patch.object(guard, "unit_states", side_effect=lambda units: {name: healthy_unit(kind) for name, kind in units.items()})
        self.clock = patch.object(guard, "boottime", return_value=100.0)

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def collect_context(self):
        return self.reader, self.units, self.clock

    def test_ready_arm_and_identity_drift(self):
        with self.reader, self.units, self.clock:
            mode, checks, baseline = guard.collect()
            self.assertTrue(all(item["healthy"] for item in checks))
            self.fake["persona_seed"] = "f" * 64
            mode, checks, evidence = guard.collect(baseline)
            self.assertFalse(next(item for item in checks if item["code"] == "identity")["healthy"])
            self.assertNotIn("private-host", json.dumps(checks))
            self.assertNotIn("f" * 64, json.dumps(checks))

    def test_all_identity_values_are_compared(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]
            for names, value in [(["boot_machine_id", "machine-id"], "4" * 32), (["boot_hostname", "hostname"], "changed-host")]:
                original = {name: self.fake[name] for name in names}
                self.fake.update({name: value for name in names})
                checks = guard.collect(baseline)[1]
                self.assertFalse(next(item for item in checks if item["code"] == "identity")["healthy"])
                self.fake.update(original)

    def test_identity_details_name_only_changed_fields_without_values(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]
            cases = (
                (self.identity / "persona_seed", "f" * 64, "Session seed"),
                (self.identity / "boot_machine_id", "4" * 32, "Boot machine ID"),
                (Path("/etc/machine-id"), "5" * 32, "System machine ID (/etc/machine-id)"),
                (self.identity / "boot_hostname", "changed-boot", "Boot hostname"),
                (Path("/proc/sys/kernel/hostname"), "changed-kernel", "Kernel hostname"),
                (Path("/etc/hostname"), "changed-stored", "Stored hostname (/etc/hostname)"),
            )
            for changed_path, changed_value, label in cases:
                with self.subTest(field=label):
                    guard.read_text.side_effect = lambda path, *args, **kwargs: (
                        changed_value if path == changed_path else self.fake[path.name]
                    )
                    checks = guard.collect(baseline)[1]
                    item = next(check for check in checks if check["code"] == "identity")
                    self.assertEqual(item["status"], "failed")
                    self.assertIn(label + " changed", item["detail"])
                    self.assertNotIn(changed_value, item["detail"])
                    self.assertNotIn("private-host", item["detail"])
                    self.assertNotIn("1" * 64, item["detail"])
                    self.assertLess(len(item["detail"]), 2048)

    def test_unreadable_identity_field_is_named_without_falsely_claiming_change(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]

            def read(path, *args, **kwargs):
                if path == Path("/etc/machine-id"):
                    raise PermissionError("private exception contents")
                return self.fake[path.name]

            guard.read_text.side_effect = read
            item = next(check for check in guard.collect(baseline)[1] if check["code"] == "identity")
            self.assertIn("System machine ID (/etc/machine-id) cannot be read (permission denied)", item["detail"])
            self.assertNotIn("changed", item["detail"])
            self.assertNotIn("private exception contents", item["detail"])
            self.assertNotIn("hostname", item["detail"])

    def test_services_clock_and_nuke_report_specific_causes(self):
        with self.reader, self.units, self.clock:
            states = {
                name: healthy_unit(kind)
                for name, kind in {**guard.COMMON_UNITS, **guard.NORMAL_UNITS}.items()
            }
            states["ph4ntxm-clock-fuzz.service"].update(
                ActiveState="failed", Result="exit-code", ExecMainStatus="3"
            )
            states["unbound.service"]["LoadState"] = "not-found"
            guard.unit_states.side_effect = lambda units: states
            self.fake["clock-fuzz-profile"] = clock_profile("windows", "0")
            self.fake["kexec_crash_loaded"] = "0"
            self.fake["kexec_load_disabled"] = "0"
            checks = {item["code"]: item for item in guard.collect()[1]}
            self.assertIn("ph4ntxm-clock-fuzz.service: last run failed with exit status 3", checks["services"]["detail"])
            self.assertIn("unbound.service: unit is not loaded", checks["services"]["detail"])
            self.assertIn("profile mode does not match", checks["clock"]["detail"])
            self.assertIn("SKEW_APPLIED", checks["clock"]["detail"])
            self.assertIn("crash kernel is not loaded", checks["nuke"]["detail"])
            self.assertIn("loader is not locked", checks["nuke"]["detail"])

    def test_readiness_details_separate_age_profile_and_proof_failures(self):
        with self.reader, self.units, self.clock:
            self.fake["firewall-ready"] = "PROFILE=lonewolf\nRULESET_SHA256=invalid\nUPTIME_SECONDS=0"
            self.fake["packet-transformation-engine-guard-ready"] = "PROFILE=normal\nSTATUS=failed\nINTERFACES=invalid\nUPTIME_SECONDS=101"
            checks = {item["code"]: item for item in guard.collect()[1]}
            self.assertIn("older than 30 seconds", checks["firewall"]["detail"])
            self.assertIn("policy profile does not match", checks["firewall"]["detail"])
            self.assertIn("ruleset digest is missing or invalid", checks["firewall"]["detail"])
            self.assertIn("timestamp is in the future", checks["packet_engine"]["detail"])
            self.assertIn("STATUS is not ready", checks["packet_engine"]["detail"])
            self.assertIn("interface count is missing or invalid", checks["packet_engine"]["detail"])

    def test_active_incident_details_follow_current_failures_without_new_episode(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]
            state = guard.new_state("boot")
            state["enabled"] = True
            self.fake["persona_seed"] = "f" * 64
            guard.advance(state, "linux", guard.collect(baseline)[1], 100)
            incident = next(item for item in state["incidents"] if item["code"] == "identity")
            incident_id = incident["id"]
            self.assertIn("Session seed changed", incident["detail"])
            self.fake["persona_seed"] = "1" * 64
            self.fake["hostname"] = "changed-host"
            guard.advance(state, "linux", guard.collect(baseline)[1], 110)
            self.assertEqual(len(state["incidents"]), 1)
            self.assertEqual(incident["id"], incident_id)
            self.assertEqual(incident["first_seen_boottime"], 100)
            self.assertIn("Kernel hostname changed", incident["detail"])
            self.assertNotIn("Session seed changed", incident["detail"])
            self.fake["hostname"] = "private-host"
            guard.advance(state, "linux", guard.collect(baseline)[1], 120)
            self.assertFalse(incident["active"])
            self.assertIn("Kernel hostname changed", incident["detail"])

    def test_lockdown_and_offline_lonewolf_are_healthy(self):
        with self.reader, self.units, self.clock:
            self.fake["firewall-ready"] = self.fake["firewall-ready"].replace("normal", "lockdown")
            self.fake["packet-transformation-engine-guard-ready"] = self.fake["packet-transformation-engine-guard-ready"].replace("normal", "lockdown")
            self.assertTrue(all(item["healthy"] for item in guard.collect()[1]))
            self.fake.update({
                "mode": "lonewolf",
                "identity-ready": "lonewolf",
                "lonewolf_seed": "5" * 64,
                "clock-fuzz-profile": clock_profile("lonewolf"),
            })
            checks = guard.collect()[1]
            self.assertTrue(all(item["healthy"] for item in checks))
            self.assertNotIn("packet_engine", [item["code"] for item in checks])
            units = self.units.target.unit_states.call_args.args[0]
            self.assertNotIn("tor@default.service", units)
            self.assertNotIn("ph4ntxm-lonewolf-dns.service", units)

    def test_prerequisite_failures_refuse_baseline(self):
        with self.reader, self.units, self.clock:
            store = guard.Store.__new__(guard.Store)
            store.state = guard.new_state("boot")
            store.persist = lambda: None
            self.fake["kexec_crash_loaded"] = "0"
            with self.assertRaises(guard.GuardError) as error:
                store.request({"action": "enable", "generation": store.state["generation"]})
            self.assertEqual(error.exception.code, "not_ready")
            self.assertFalse(store.state["enabled"])
            self.assertIsNone(store.state["baseline"])
            self.fake["kexec_crash_loaded"] = "1"
            first = store.state["generation"]
            result = store.request({"action": "enable", "generation": first})
            self.assertTrue(result["enabled"])
            self.assertNotEqual(first, result["generation"])
            with self.assertRaises(guard.GuardError):
                store.request({"action": "disable", "generation": first})
            result = store.request({"action": "disable", "generation": result["generation"]})
            self.assertFalse(result["enabled"])
            self.assertIsNone(store.state["baseline"])

    def test_immediate_incident_dedup_resolution_and_recurrence(self):
        state = guard.new_state("boot")
        state["enabled"] = True
        bad = [guard.check_result("nuke", False)]
        guard.advance(state, "linux", bad, 10)
        self.assertEqual(len(state["incidents"]), 1)
        incident_id = state["incidents"][0]["id"]
        guard.advance(state, "linux", bad, 20)
        self.assertEqual(len(state["incidents"]), 1)
        guard.advance(state, "linux", [guard.check_result("nuke", True)], 30)
        self.assertFalse(state["incidents"][0]["active"])
        guard.advance(state, "linux", bad, 40)
        self.assertEqual(len(state["incidents"]), 2)
        self.assertNotEqual(incident_id, state["incidents"][1]["id"])
        self.assertEqual(state["incidents"][1]["mode"], "linux")

    def test_pending_transition_has_bounded_grace(self):
        state = guard.new_state("boot")
        state["enabled"] = True
        guard.advance(state, "linux", [guard.check_result("services", False, True)], 10)
        guard.advance(state, "linux", [guard.check_result("services", False, True)], 30)
        self.assertEqual(state["incidents"], [])
        guard.advance(state, "linux", [guard.check_result("services", False, True)], 40)
        self.assertEqual(len(state["incidents"]), 1)
        self.assertIn("30 seconds", state["incidents"][0]["detail"])
        guard.advance(state, "linux", [guard.check_result("services", True)], 50)
        self.assertFalse(state["incidents"][0]["active"])

    def test_history_and_snapshot_are_bounded_and_private(self):
        state = guard.new_state("boot")
        state["enabled"] = True
        state["baseline"] = {"seed": "private-seed", "hostname": "private-host"}
        for number in range(100):
            guard.advance(state, "linux", [guard.check_result("nuke", False)], number * 20)
            guard.advance(state, "linux", [guard.check_result("nuke", True)], number * 20 + 10)
        self.assertEqual(len(state["incidents"]), 64)
        self.assertIs(type(guard.snapshot(state)["poll_interval"]), int)
        public = json.dumps(guard.snapshot(state))
        self.assertNotIn("private-seed", public)
        self.assertNotIn("private-host", public)

    def test_oneshot_and_continuous_health(self):
        self.assertTrue(guard.unit_healthy(healthy_unit("oneshot"), "oneshot"))
        state = healthy_unit("oneshot")
        state["ExecMainStartTimestampMonotonic"] = "0"
        self.assertFalse(guard.unit_healthy(state, "oneshot"))
        state = healthy_unit()
        state["ActiveState"] = "activating"
        self.assertFalse(guard.unit_healthy(state, "continuous"))
        self.assertTrue(guard.unit_pending(state))
        state = healthy_unit()
        state["Job"] = "14 /org/freedesktop/systemd1/job/14"
        self.assertTrue(guard.unit_pending(state))

    def test_dependent_pending_does_not_mask_unrelated_failure(self):
        with self.reader, self.units, self.clock:
            states = {name: healthy_unit(kind) for name, kind in {**guard.COMMON_UNITS, **guard.NORMAL_UNITS}.items()}
            states["ph4ntxm-clock-fuzz.service"]["ActiveState"] = "activating"
            self.units.target.unit_states.side_effect = lambda units: states
            self.fake["clock-fuzz-profile"] = clock_profile("linux", "0")
            self.fake["kexec_crash_loaded"] = "0"
            checks = {item["code"]: item for item in guard.collect()[1]}
            self.assertEqual(checks["clock"]["status"], "pending")
            self.assertEqual(checks["nuke"]["status"], "failed")

    def test_observer_failure_resolves_after_successful_observation(self):
        state = guard.new_state("boot")
        state["enabled"] = True
        guard.advance(state, "linux", [guard.check_result("observer", False)], 10)
        guard.advance(state, "linux", [guard.check_result("nuke", True)], 20)
        self.assertFalse(state["incidents"][0]["active"])

    def test_invalid_mode_preserves_baseline_label_and_reports_failure(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]
            self.fake["mode"] = "invalid-private-value"
            mode, checks, evidence = guard.collect(baseline)
            checks = {item["code"]: item for item in checks}
            self.assertEqual(mode, "linux")
            self.assertFalse(checks["mode"]["healthy"])
            self.assertFalse(checks["identity"]["healthy"])
            self.assertNotIn("invalid-private-value", json.dumps(checks))

    def test_firewall_lock_transition_is_pending_and_then_resolves(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]
            self.fake["firewall-ready"] = self.fake["firewall-ready"].replace("SECONDS=99", "SECONDS=0")
            with patch.object(guard, "readiness_lock", return_value=(None, True)):
                checks = guard.collect(baseline)[1]
            statuses = {item["code"]: item["status"] for item in checks}
            self.assertEqual(statuses["firewall"], "pending")
            self.assertEqual(statuses["packet_engine"], "pending")
            state = guard.new_state("boot")
            state["enabled"] = True
            guard.advance(state, "linux", checks, 10)
            self.assertEqual(state["incidents"], [])
            with patch.object(guard, "readiness_lock", return_value=(None, False)):
                checks = guard.collect(baseline)[1]
            self.assertEqual(next(item for item in checks if item["code"] == "firewall")["status"], "failed")
            guard.advance(state, "linux", checks, 20)
            self.assertEqual(state["incidents"][0]["code"], "firewall")
            self.fake["firewall-ready"] = self.fake["firewall-ready"].replace("SECONDS=0", "SECONDS=99")
            guard.advance(state, "linux", guard.collect(baseline)[1], 30)
            self.assertFalse(state["incidents"][0]["active"])

    def test_firewall_lock_is_existing_readonly_and_busy_requires_healthy_guardian(self):
        states = {"ph4ntxm-firewall-guard.service": healthy_unit()}
        info = Mock(st_mode=0o100600, st_uid=0)
        with patch.object(guard, "protected_directory"), patch.object(guard.os, "open", return_value=91) as opened, \
                patch.object(guard.os, "fstat", return_value=info), patch.object(guard.os, "close") as closed, \
                patch.object(guard.fcntl, "flock", side_effect=BlockingIOError(errno.EWOULDBLOCK, "busy")):
            self.assertEqual(guard.readiness_lock(states, "linux"), (None, True))
            flags = opened.call_args.args[1]
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertFalse(flags & os.O_CREAT)
            self.assertEqual(guard.readiness_lock({}, "linux"), (None, False))
            self.assertEqual(closed.call_count, 2)
        with patch.object(guard, "protected_directory"), patch.object(guard.os, "open", side_effect=FileNotFoundError):
            self.assertEqual(guard.readiness_lock(states, "linux"), (None, False))

    def test_stale_future_and_unsupported_ready_records(self):
        with self.reader:
            self.assertFalse(guard.readiness_problems(self.identity / "firewall-ready", ("normal", "lockdown"), 100))
            self.assertTrue(guard.readiness_problems(self.identity / "firewall-ready", ("normal",), 140))
            self.assertTrue(guard.readiness_problems(self.identity / "firewall-ready", ("normal",), 90))
            self.assertTrue(guard.readiness_problems(self.identity / "firewall-ready", ("lonewolf",), 100))

    def test_dynamic_tick_allowed_but_initial_clock_identity_is_pinned(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]
            self.fake["clock-fuzz-profile"] = clock_profile().replace("CURRENT_TICK=10000", "CURRENT_TICK=10001")
            check = next(item for item in guard.collect(baseline)[1] if item["code"] == "clock")
            self.assertTrue(check["healthy"])
            for original, changed, field in (
                ("OFFSET_SECONDS=0", "OFFSET_SECONDS=1", "OFFSET_SECONDS"),
                ("INITIAL_TICK=10000", "INITIAL_TICK=10001", "INITIAL_TICK"),
            ):
                self.fake["clock-fuzz-profile"] = clock_profile().replace(original, changed)
                check = next(item for item in guard.collect(baseline)[1] if item["code"] == "clock")
                self.assertFalse(check["healthy"])
                self.assertIn(field + " changed", check["detail"])
            self.assertNotIn("CURRENT_TICK", baseline["generated_identity"]["clock_profile"])

    def test_malformed_extended_baseline_reports_missing_evidence_without_exception(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]
            baseline["generated_identity"] = []
            checks = guard.collect(baseline)[1]
            clock = next(item for item in checks if item["code"] == "clock")
            self.assertFalse(clock["healthy"])
            self.assertIn("activation baseline", clock["detail"])

    def test_upgrade_does_not_adopt_new_evidence_during_poll(self):
        with self.reader, self.units, self.clock:
            baseline = guard.collect()[2]
            baseline.pop("generated_identity")
            store = guard.Store.__new__(guard.Store)
            store.state = guard.new_state("boot")
            store.state.update(enabled=True, baseline=copy.deepcopy(baseline), mode="linux")
            store.persist = Mock()
            store.poll()
            self.assertEqual(store.state["baseline"], baseline)
            self.assertNotIn("generated_identity", store.state["baseline"])
            clock = next(item for item in store.state["checks"] if item["code"] == "clock")
            self.assertFalse(clock["healthy"])
            self.assertIn("activation baseline", clock["detail"])

    def test_root_owned_atomic_store_and_restart_republishes_private_authority(self):
        if os.geteuid() != 0:
            self.skipTest("Root-owned fixture test requires a root build environment")
        store = guard.Store()
        generation = store.state["generation"]
        store.state["enabled"] = False
        store.state["sequence"] = 17
        store.persist()
        self.public.write_text('{"ok":false}')
        loaded = guard.Store()
        self.assertEqual(loaded.state["generation"], generation)
        self.assertEqual(json.loads(self.public.read_text())["sequence"], 17)
        self.assertEqual((self.runtime / "state.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.public.stat().st_mode & 0o777, 0o644)

    def test_fixed_virtual_values_bound_content_instead_of_sysfs_metadata_size(self):
        value = self.root / "virtual-value"
        value.write_bytes(b"1\n")
        info = Mock(st_mode=0o100444, st_uid=0, st_size=4096)
        descriptor = os.open(value, os.O_RDONLY)
        with patch.object(guard, "protected_directory"), patch.object(guard.os, "open", return_value=descriptor), \
                patch.object(guard.os, "fstat", return_value=info):
            self.assertEqual(guard.read_text(Path("/sys/kernel/kexec_crash_loaded"), 8), "1")
        descriptor = os.open(value, os.O_RDONLY)
        with patch.object(guard, "protected_directory"), patch.object(guard.os, "open", return_value=descriptor), \
                patch.object(guard.os, "fstat", return_value=info):
            with self.assertRaises(guard.GuardError):
                guard.read_text(self.identity / "persona_seed", 8)
        value.write_bytes(b"123456789")
        descriptor = os.open(value, os.O_RDONLY)
        with patch.object(guard, "protected_directory"), patch.object(guard.os, "open", return_value=descriptor), \
                patch.object(guard.os, "fstat", return_value=info):
            with self.assertRaises(guard.GuardError):
                guard.read_text(Path("/sys/kernel/kexec_crash_loaded"), 8)

    def test_request_schema_does_not_accept_paths_or_commands(self):
        store = guard.Store.__new__(guard.Store)
        store.state = guard.new_state("boot")
        for request in [{"action": "daemon", "generation": store.state["generation"]},
                        {"action": "enable", "generation": store.state["generation"], "path": "/tmp/x"}]:
            with self.assertRaises(guard.GuardError) as error:
                store.request(request)
            self.assertEqual(error.exception.code, "request")

    def test_socket_request_is_bounded(self):
        connection = Mock()
        connection.recv.return_value = b"x" * (guard.MAX_INPUT + 1)
        with self.assertRaises(guard.GuardError):
            guard.receive(connection)
        connection.recv.return_value = b'{"action":"disable","generation":"a"}\ntrailing'
        with self.assertRaises(guard.GuardError):
            guard.receive(connection)


class GeneratedIntegrationTests(unittest.TestCase):
    def test_generated_groups_receive_explicit_baselines_and_capture_private_evidence(self):
        evidence = {"persona": {"opaque": "a" * 64}, "network": {"opaque": "b" * 64}, "name_resolution": {"opaque": "c" * 64}}
        with (
            patch.object(guard.session_guard_persona, "collect", return_value=([], evidence["persona"])) as persona,
            patch.object(guard.session_guard_network, "collect", return_value=([], evidence["network"])) as network,
            patch.object(guard, "binding_check", return_value=(guard.check_result("name_resolution", True), evidence["name_resolution"])) as bindings,
        ):
            checks, captured = guard.collect_generated("linux", "1" * 64, "fixture", None)
            self.assertEqual(captured, evidence)
            self.assertIsNone(persona.call_args.args[2])
            self.assertIsNone(network.call_args.args[2])
            guard.collect_generated("linux", "1" * 64, "fixture", {})
            self.assertEqual(persona.call_args.args[2], {})
            self.assertEqual(network.call_args.args[2], {})
            self.assertEqual(bindings.call_args.args[1], {})
            guard.collect_generated("linux", "1" * 64, "fixture", evidence)
            self.assertEqual(persona.call_args.args[2], evidence["persona"])
            self.assertEqual(network.call_args.args[2], evidence["network"])

    def test_unready_core_identity_never_crashes_generated_checks(self):
        with patch.object(guard.session_guard_persona, "collect") as persona:
            checks, evidence = guard.collect_generated("unknown", None, None)
        persona.assert_not_called()
        self.assertEqual(len(checks), 7)
        self.assertTrue(all(not item["healthy"] for item in checks))
        self.assertEqual(evidence, {})

    def test_local_bindings_are_specific_and_ignore_unrelated_hosts_entries(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "machine-id"
            target.symlink_to("/etc/machine-id")
            with (
                patch.object(guard, "DBUS_ID", target),
                patch.object(guard, "protected_directory"),
                patch.object(guard, "read_text", return_value="127.0.0.1 localhost\n127.0.1.1 fixture alias\n") as read,
            ):
                check, baseline = guard.binding_check("fixture")
                self.assertTrue(check["healthy"])
                read.return_value = "127.0.1.1 changed\n"
                check, _ = guard.binding_check("fixture", baseline)
                self.assertFalse(check["healthy"])
                self.assertIn("127.0.1.1 hostname", check["detail"])
                self.assertNotIn("changed", check["detail"])
                target.unlink()
                target.symlink_to("/wrong")
                read.return_value = "127.0.1.1 fixture\n"
                check, _ = guard.binding_check("fixture", baseline)
                self.assertIn("D-Bus machine ID", check["detail"])


if __name__ == "__main__":
    unittest.main()
