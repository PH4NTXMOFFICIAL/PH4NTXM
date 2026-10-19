# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = next(
    (
        base / "config/includes.chroot/usr/lib/ph4ntxm/tor_connection.py"
        for base in Path(__file__).resolve().parents
        if (base / "config/includes.chroot/usr/lib/ph4ntxm/tor_connection.py").is_file()
    ),
    Path("/usr/lib/ph4ntxm/tor_connection.py"),
)
SPEC = importlib.util.spec_from_file_location("tor_connection", SOURCE)
connection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(connection)
CERT = base64.b64encode(bytes(range(52))).decode("ascii").rstrip("=")
BRIDGE = f"obfs4 8.8.8.8:443 {'A' * 40} cert={CERT} iat-mode=0"


class ParsingTests(unittest.TestCase):
    def test_normalization_and_optional_fingerprint(self):
        self.assertEqual(
            connection.parse_bridges("Bridge " + BRIDGE.replace("A" * 40, "a" * 40)),
            [BRIDGE],
        )
        short = BRIDGE.replace("A" * 40 + " ", "")
        self.assertEqual(connection.parse_bridges("\n\t" + short + "\r\n"), [short])

    def test_non_public_addresses_and_invalid_ports(self):
        for endpoint in (
            "127.0.0.1:443",
            "10.1.2.3:443",
            "100.64.0.1:443",
            "192.0.0.9:443",
            "192.0.2.1:443",
            "198.18.0.1:443",
            "224.0.0.1:443",
            "240.0.0.1:443",
            "8.8.8.8:0",
            "8.8.8.8:65536",
            "[::ffff:8.8.8.8]:443",
            "bridge.example:443",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(
                connection.ConnectionError
            ):
                connection.parse_bridges(BRIDGE.replace("8.8.8.8:443", endpoint))

    def test_injection_certificates_duplicates_and_limit(self):
        invalid = (
            "",
            BRIDGE + "\nUseBridges 0",
            BRIDGE + " extra=1",
            BRIDGE.replace("obfs4", "snowflake"),
            BRIDGE.replace("iat-mode=0", "iat-mode=3"),
            BRIDGE.replace(CERT, CERT[:-1] + "B"),
            BRIDGE + "\n" + BRIDGE,
            "\n".join(
                BRIDGE.replace("8.8.8.8", f"8.8.8.{n}") for n in range(1, 10)
            ),
        )
        for text in invalid:
            with self.subTest(text=text[:30]), self.assertRaises(connection.ConnectionError):
                connection.parse_bridges(text)

    def test_json_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            connection.decode(b'{"mode":"obfs4","mode":"direct"}')

    def test_hidden_control_characters_and_bare_carriage_returns_are_rejected(self):
        for code in (*range(32), 127):
            if code in (9, 10, 13):
                continue
            with self.subTest(code=code), self.assertRaises(connection.ConnectionError):
                connection.parse_bridges(BRIDGE + chr(code))
        for text in (BRIDGE + "\r", BRIDGE + "\r" + BRIDGE):
            with self.subTest(text=text[-10:]), self.assertRaises(connection.ConnectionError):
                connection.parse_bridges(text)

    def test_invalid_ipv4_has_actionable_error(self):
        with self.assertRaisesRegex(connection.ConnectionError, "public IPv4"):
            connection.parse_bridges(BRIDGE.replace("8.8.8.8", "999.888.1.1"))

    def test_padded_certificate_is_rejected(self):
        with self.assertRaises(connection.ConnectionError):
            connection.parse_bridges(BRIDGE.replace(CERT, CERT + "=="))

    def test_reversed_option_order_has_identical_normalized_output(self):
        for line in (BRIDGE, BRIDGE.replace("A" * 40 + " ", "")):
            reversed_options = line.replace(
                f"cert={CERT} iat-mode=0", f"iat-mode=0 cert={CERT}"
            )
            with self.subTest(fingerprint="A" * 40 in line):
                self.assertEqual(connection.parse_bridges(reversed_options), [line])

    def test_duplicate_and_unknown_bridge_options_are_rejected(self):
        for line in (
            BRIDGE.replace("iat-mode=0", f"cert={CERT}"),
            BRIDGE.replace(f"cert={CERT}", "iat-mode=1"),
            BRIDGE.replace("iat-mode=0", "unknown=0"),
        ):
            with self.subTest(line=line[-30:]), self.assertRaises(
                connection.ConnectionError
            ):
                connection.parse_bridges(line)

    def test_root_files_reject_symlinks_and_writable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("secret")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                connection.read_protected(link)
            target.chmod(0o666)
            with self.assertRaises(connection.ConnectionError):
                connection.read_protected(target)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.runtime = self.base / "connection"
        self.runtime.mkdir()
        self.shared = self.base / "shared"
        self.shared.mkdir()
        self.calls = []
        self.fail_on = None
        self.fstat = os.fstat
        names = {
            "RUNTIME": self.runtime,
            "STATE": self.runtime / "state.json",
            "PUBLIC": self.runtime / "snapshot.json",
            "EXPECTATION": self.runtime / "expectation.json",
            "TORRC": self.runtime / "torrc",
            "MODE": self.shared / "mode",
            "LOCK": self.shared / "firewall.lock",
            "TOR_READY": self.shared / "tor-ready",
            "FIREWALL_READY": self.shared / "firewall-ready",
            "LOCKDOWN_STATUS": self.shared / "lockdown.json",
            "BOOT_ID": self.base / "boot-id",
            "SOURCE": self.base / "lonewolf.nft",
            "LOCKDOWN": self.base / "lockdown.nft",
            "TRANSPORT": self.base / "obfs4proxy",
        }
        self.patches = [patch.object(connection, name, path) for name, path in names.items()]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        for item in (
            patch.object(connection, "root"),
            patch.object(connection, "protected_directory"),
            patch.object(connection, "read_protected", side_effect=self.read),
            patch.object(connection.os, "fchown"),
            patch.object(connection.os, "geteuid", return_value=0),
            patch.object(connection.os, "fstat", side_effect=self.file_stat),
            patch.object(
                connection.pwd,
                "getpwnam",
                return_value=types.SimpleNamespace(pw_gid=os.getgid()),
            ),
            patch.object(connection, "run", side_effect=self.run_command),
        ):
            item.start()
            self.addCleanup(item.stop)
        connection.MODE.write_text("lonewolf\n")
        connection.BOOT_ID.write_text("11111111-1111-4111-8111-111111111111\n")
        source = (
            "flush ruleset\ntable inet filter {\n    chain output {\n"
            + connection.ACCEPT
            + "\n    }\n}\n"
        ).encode()
        connection.SOURCE.write_bytes(source)
        source_patch = patch.object(connection, "SOURCE_HASH", connection.digest(source))
        source_patch.start()
        self.addCleanup(source_patch.stop)
        connection.LOCKDOWN.write_text("flush ruleset\n")
        connection.TRANSPORT.write_text("transport")
        for path in (
            connection.MODE,
            connection.BOOT_ID,
            connection.SOURCE,
            connection.LOCKDOWN,
        ):
            path.chmod(0o644)
        connection.TRANSPORT.chmod(0o755)
        self.state = connection.initialize()
        self.calls.clear()

    def read(self, path, limit=connection.MAX_INPUT, mode=None, group=None):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise connection.ConnectionError("Invalid fixture file.")
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            raise connection.ConnectionError("Invalid fixture permissions.")
        data = path.read_bytes()
        if len(data) > limit:
            raise connection.ConnectionError("Oversized fixture.")
        return data

    def file_stat(self, descriptor):
        values = list(self.fstat(descriptor))
        values[4] = 0
        return os.stat_result(values)

    def run_command(self, arguments, data=None):
        self.calls.append((arguments, data))
        if self.fail_on and self.fail_on(arguments):
            self.fail_on = None
            raise connection.ConnectionError(connection.ERROR)

    def request(self, mode="obfs4", bridges=BRIDGE):
        return {
            "generation": connection.snapshot()["generation"],
            "mode": mode,
            "bridges": bridges,
        }

    def transport_owner(self):
        original = Path.lstat
        target = connection.TRANSPORT

        def inspect(path):
            info = original(path)
            if path == target:
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0)
            return info

        return patch.object(Path, "lstat", inspect)

    def test_pending_is_blocked_and_initialization_is_idempotent(self):
        self.assertEqual(connection.initialize(), self.state)
        self.assertNotIn(
            connection.ACCEPT.encode(), connection.render(connection.load_state())
        )
        self.assertIn(b"DisableNetwork 1", connection.TORRC.read_bytes())
        with self.assertRaises(connection.ConnectionError):
            connection.verify()

    def test_obfs4_transaction_endpoint_policy_and_public_privacy(self):
        with self.transport_owner():
            result = connection.apply(self.request())
        self.assertEqual(
            (result["mode"], result["phase"], result["bridge_count"]),
            ("obfs4", "connecting", 1),
        )
        self.assertIn(b"UseBridges 1", connection.TORRC.read_bytes())
        policies = [data for args, data in self.calls if args[:2] == ["/usr/sbin/nft", "-f"]]
        self.assertNotIn(connection.ACCEPT.encode(), policies[0])
        self.assertIn(b"8.8.8.8 . 443", policies[-1])
        self.assertNotIn(connection.ACCEPT.encode(), policies[-1])
        self.assertEqual(
            self.calls[-1][0],
            ["/usr/bin/systemctl", "--no-block", "start", "tor@default.service"],
        )
        for path in (connection.PUBLIC, connection.EXPECTATION):
            self.assertNotIn(CERT, path.read_text())
            self.assertNotIn("8.8.8.8", path.read_text())
        connection.verify()

    def test_direct_requires_explicit_request(self):
        result = connection.apply(self.request("direct", ""))
        self.assertEqual(result["mode"], "direct")
        self.assertIn(connection.ACCEPT.encode(), connection.render(connection.load_state()))
        self.assertEqual(connection.TORRC.read_bytes(), b"DisableNetwork 0\nUseBridges 0\n")

    def test_validation_and_stale_generation_do_not_mutate(self):
        initial = connection.STATE.read_bytes()
        with self.assertRaises(connection.ConnectionError):
            connection.apply(self.request("direct", BRIDGE))
        request = self.request("direct", "")
        request["generation"] = "stale"
        with self.assertRaises(connection.ConnectionError):
            connection.apply(request)
        self.assertEqual(connection.STATE.read_bytes(), initial)
        self.assertFalse(self.calls)

    def test_competing_apply_with_old_generation_cannot_overwrite_selection(self):
        stale = self.request("direct", "")
        with self.transport_owner():
            selected = connection.apply(self.request())
        self.calls.clear()
        with self.assertRaises(connection.ConnectionError):
            connection.apply(stale)
        self.assertEqual(connection.snapshot(), selected)
        self.assertFalse(self.calls)

    def test_torn_publication_repairs_snapshot_but_rejects_stale_approval(self):
        for mode, bridges in (("obfs4", BRIDGE), ("direct", "")):
            with self.subTest(mode=mode):
                request = self.request(mode, bridges)
                original_atomic = connection.atomic

                def interrupted(path, data, mode, group=0):
                    if path == connection.PUBLIC:
                        raise SystemExit("Interrupted publication")
                    return original_atomic(path, data, mode, group)

                with self.transport_owner(), patch.object(
                    connection, "atomic", side_effect=interrupted
                ), self.assertRaises(SystemExit):
                    connection.apply(request)
                state = connection.load_state()
                self.assertNotEqual(
                    connection.snapshot()["generation"], state["generation"]
                )
                unchanged = {
                    path: path.read_bytes()
                    for path in (connection.STATE, connection.TORRC, connection.EXPECTATION)
                }
                self.calls.clear()
                with self.transport_owner(), self.assertRaises(connection.ConnectionError):
                    connection.apply(request)
                self.assertEqual(connection.snapshot(), connection.public_state(state))
                self.assertFalse(self.calls)
                for path, contents in unchanged.items():
                    self.assertEqual(path.read_bytes(), contents)
                self.assertEqual(stat.S_IMODE(connection.PUBLIC.stat().st_mode), 0o644)
                self.assertNotIn(CERT, connection.PUBLIC.read_text())
                with self.transport_owner(), self.assertRaises(connection.ConnectionError):
                    connection.apply(request)
                with self.transport_owner():
                    result = connection.apply(self.request(mode, bridges))
                self.assertEqual((result["mode"], result["phase"]), (mode, "connecting"))
                connection.verify()

    def test_snapshot_recovery_write_failure_does_not_change_connection(self):
        state = connection.new_state("obfs4", [BRIDGE])
        connection.atomic(connection.STATE, connection.encoded(state), 0o600)
        unchanged = {
            path: path.read_bytes()
            for path in (
                connection.STATE, connection.PUBLIC, connection.TORRC, connection.EXPECTATION
            )
        }
        with patch.object(
            connection, "atomic", side_effect=OSError("Unavailable storage")
        ), self.assertRaises(OSError):
            connection.apply(self.request("direct", ""))
        self.assertFalse(self.calls)
        for path, contents in unchanged.items():
            self.assertEqual(path.read_bytes(), contents)

    def test_failed_verify_or_start_retains_target_blocked(self):
        for failure in (lambda args: args[0] == "/usr/bin/tor", lambda args: "start" in args):
            with self.subTest(failure=failure):
                self.fail_on = failure
                with self.transport_owner(), self.assertRaises(connection.ConnectionError):
                    connection.apply(self.request())
                state = connection.load_state()
                self.assertEqual((state["mode"], state["phase"]), ("obfs4", "error"))
                self.assertIn(b"DisableNetwork 1", connection.TORRC.read_bytes())
                self.assertNotIn(connection.ACCEPT.encode(), connection.render(state))
                self.assertEqual(
                    self.calls[-1][0],
                    ["/usr/bin/systemctl", "stop", "tor@default.service"],
                )

    def test_interrupted_transaction_does_not_restore_direct(self):
        state = connection.new_state("obfs4", [BRIDGE])
        connection.publish(state)
        connection.configure(dict(state, phase="connecting"))
        result = connection.initialize()
        self.assertEqual((result["mode"], result["phase"]), ("obfs4", "error"))
        self.assertIn(b"DisableNetwork 1", connection.TORRC.read_bytes())

    def test_readiness_rejects_changed_runtime_configuration(self):
        connection.apply(self.request("direct", ""))
        connection.TORRC.write_bytes(b"DisableNetwork 1\n")
        with self.assertRaises(connection.ConnectionError):
            connection.verify()

    def test_readiness_rejects_old_generation_even_with_valid_config_hash(self):
        connection.apply(self.request("direct", ""))
        value = json.loads(connection.EXPECTATION.read_text())
        value["generation"] = self.state["generation"]
        connection.EXPECTATION.write_text(json.dumps(value))
        with self.assertRaises(connection.ConnectionError):
            connection.verify()

    def test_source_corruption_uses_emergency_drop_and_stops_tor(self):
        connection.SOURCE.write_text("flush ruleset\n")
        with self.assertRaises(connection.ConnectionError):
            connection.apply(self.request("direct", ""))
        state = connection.load_state()
        self.assertEqual(state["phase"], "error")
        policies = [body for args, body in self.calls if args[:2] == ["/usr/sbin/nft", "-f"]]
        self.assertEqual(len(policies), 1)
        self.assertIn(b"ph4ntxm_emergency", policies[0])
        self.assertEqual(
            self.calls[-1][0],
            ["/usr/bin/systemctl", "stop", "tor@default.service"],
        )

    def test_lost_mode_prevents_all_apply_mutations(self):
        connection.MODE.write_text("linux\n")
        with self.assertRaises(connection.ConnectionError):
            connection.apply(
                {"generation": self.state["generation"], "mode": "direct", "bridges": ""}
            )
        self.assertFalse(self.calls)

    def test_malformed_state_is_contained_without_direct_fallback(self):
        connection.STATE.write_text("broken")
        with self.assertRaises(connection.ConnectionError):
            connection.initialize()
        state = connection.load_state()
        self.assertEqual((state["mode"], state["phase"]), ("pending", "error"))
        self.assertNotIn(connection.ACCEPT.encode(), connection.render(state))

    def test_lockdown_is_authoritative_and_malformed_status_means_enabled(self):
        for data in (b'{"enabled":true}', b"broken", b'{"enabled":0}'):
            connection.LOCKDOWN_STATUS.write_bytes(data)
            with patch.object(
                connection,
                "LOCKDOWN_HASH",
                connection.digest(connection.LOCKDOWN.read_bytes()),
            ):
                connection.apply(self.request("direct", ""))
            policies = [
                body
                for args, body in self.calls
                if args[:2] == ["/usr/sbin/nft", "-f"]
            ]
            self.assertTrue(all(body == connection.LOCKDOWN.read_bytes() for body in policies))
            self.calls.clear()


if __name__ == "__main__":
    unittest.main()
