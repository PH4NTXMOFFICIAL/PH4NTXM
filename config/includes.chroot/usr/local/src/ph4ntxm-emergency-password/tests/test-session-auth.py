#!/usr/bin/python3 -I
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


broker = load("session_password", sys.argv[1])
status = load("session_status", sys.argv[2])
sys.argv = sys.argv[:1]


def request(password="Normal-test-2026!", emergency="Emergency-test-2026!", **updates):
    data = {
        "password": password,
        "confirmation": password,
        "emergency_password": emergency,
        "emergency_confirmation": emergency,
    }
    data.update(updates)
    return json.dumps(data, ensure_ascii=False).encode() + b"\n"


class Requests(unittest.TestCase):
    def test_opt_out_and_enabled(self):
        self.assertEqual(broker.request_password(request(emergency="")), ("Normal-test-2026!", ""))
        self.assertEqual(broker.request_password(request()), ("Normal-test-2026!", "Emergency-test-2026!"))

    def test_rejected_credentials(self):
        for raw in (
            request(password="short"),
            request(password="a" * 257),
            request(emergency="short"),
            request(emergency="a" * 257),
            request(emergency="Normal-test-2026!"),
            request(confirmation="different"),
            request(emergency_confirmation="different"),
            request(emergency_password="", emergency_confirmation="different"),
            request(password="normal\npassword"),
            request(emergency="emergency\x00password"),
            request(emergency="emergency\x7fpassword"),
            request(emergency=None),
            request(emergency_password=17),
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                broker.request_password(raw)

    def test_framing_and_schema(self):
        for raw in (b"{}\n", b"[]\n", b"null\n", b"{bad}\n", b"\xff\n", request(extra=True), request()[:-1], b"x" * 4097 + b"\n"):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                broker.request_password(raw)

    def test_multibyte_boundaries(self):
        valid = chr(0x1F600) * 127 + "abc"
        invalid = valid + "d"
        self.assertEqual(len(valid.encode()), 511)
        self.assertTrue(broker.valid_password(valid))
        self.assertFalse(broker.valid_password(invalid))
        self.assertLess(len(request(password=valid, emergency="x" + valid[:-1])), broker.MAX_REQUEST)
        self.assertFalse(broker.valid_password("abcd\ud800ef"))

    def test_salted_hash_matches_exact_secret(self):
        secret = "Emergency-test-2026!"
        first = broker.emergency_record(secret)
        second = broker.emergency_record(secret)
        self.assertNotEqual(first, second)
        self.assertNotIn(secret.encode(), first)
        self.assertIsNotNone(broker.HASH_PATTERN.fullmatch(first[:-1].decode()))
        lib = ctypes.CDLL("libcrypt.so.1")
        lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.crypt.restype = ctypes.c_char_p
        self.assertEqual(lib.crypt(secret.encode(), first[:-1]), first[:-1])
        self.assertNotEqual(lib.crypt(b"wrong-password", first[:-1]), first[:-1])
        self.assertEqual(broker.emergency_record(""), b"disabled\n")

    def test_hash_failure(self):
        with patch.object(broker.ctypes, "CDLL") as library:
            library.return_value.crypt.return_value = 0
            with self.assertRaises(ValueError):
                broker.emergency_record("Emergency-test-2026!")


class Publication(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="session-auth-test-")
        self.root = Path(self.directory.name)
        self.patches = [
            patch.object(broker, "STATE", self.root),
            patch.object(broker, "READY", self.root / "ready"),
            patch.object(broker, "EMERGENCY", self.root / "emergency"),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.directory.cleanup()

    def test_ready_after_private_record(self):
        events = []
        publish = broker.publish_record
        def track(path, data, mode):
            events.append(path.name)
            if path.name == "ready":
                self.assertEqual((self.root / "emergency").read_bytes(), b"disabled\n")
            publish(path, data, mode)
        with patch.object(broker, "set_password", return_value=True), patch.object(broker, "publish_record", side_effect=track):
            self.assertTrue(broker.configure_passwords("Normal-test-2026!", ""))
        self.assertEqual(events, ["emergency", "ready"])
        self.assertEqual(stat.S_IMODE((self.root / "emergency").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / "ready").stat().st_mode), 0o644)
        self.assertFalse(list(self.root.glob(".auth-*")))

    def test_no_publication_on_password_failure(self):
        with patch.object(broker, "set_password", return_value=False):
            self.assertFalse(broker.configure_passwords("Normal-test-2026!", ""))
        self.assertFalse(list(self.root.iterdir()))

    def test_no_password_change_on_hash_failure(self):
        with patch.object(broker, "emergency_record", side_effect=ValueError), patch.object(broker, "set_password") as update:
            with self.assertRaises(ValueError):
                broker.configure_passwords("Normal-test-2026!", "Emergency-test-2026!")
            update.assert_not_called()

    def test_opt_out_replaces_old_hash(self):
        (self.root / "emergency").write_bytes(b"old-test-hash\n")
        with patch.object(broker, "set_password", return_value=True):
            self.assertTrue(broker.configure_passwords("Normal-test-2026!", ""))
        self.assertEqual((self.root / "emergency").read_bytes(), b"disabled\n")

    def test_no_ready_on_private_record_failure(self):
        with patch.object(broker, "set_password", return_value=True), patch.object(broker, "publish_record", side_effect=OSError):
            with self.assertRaises(OSError):
                broker.configure_passwords("Normal-test-2026!", "")
        self.assertFalse((self.root / "ready").exists())

    def test_retry_and_redacted_replies(self):
        output = io.BytesIO()
        with patch.object(broker, "configure_passwords", side_effect=[False, True]):
            self.assertTrue(broker.conversation(io.BytesIO(request() + request()), output))
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertFalse(replies[0]["ok"])
        self.assertTrue(replies[1]["ok"])
        self.assertNotIn(b"Normal-test-2026!", output.getvalue())
        self.assertNotIn(b"Emergency-test-2026!", output.getvalue())

    def test_unframed_request_stops_conversation(self):
        output = io.BytesIO()
        with patch.object(broker, "configure_passwords") as configure:
            self.assertFalse(broker.conversation(io.BytesIO(request()[:-1]), output))
            configure.assert_not_called()
        self.assertEqual(output.getvalue(), b"")


class Readiness(unittest.TestCase):
    def test_opt_out_enabled_and_invalid(self):
        valid_hash = broker.emergency_record("Emergency-test-2026!")
        for record, expected in ((b"disabled\n", 0), (valid_hash, 0), (b"disabled", 1), (b"bad\n", 1), (valid_hash + b"extra", 1)):
            def read(path, private=False):
                if path.endswith("/ready"):
                    return b"ready\n"
                if path.endswith("/emergency"):
                    self.assertTrue(private)
                    return record
                if path == "/etc/shadow":
                    return b"ph4ntxm:$6$synthetic-hash:0:0:0:0:0:0:0\n"
                raise AssertionError(path)
            with self.subTest(record=record), patch.object(status.os, "geteuid", return_value=0), patch.object(status, "read_protected", side_effect=read):
                self.assertEqual(status.main(["auth-ready"]), expected)

    def test_private_record_never_exposed(self):
        self.assertFalse(status.allowed("read", "/run/ph4ntxm-session-auth/emergency"))
        self.assertFalse(status.allowed("nonempty", "/run/ph4ntxm-session-auth/emergency"))


if __name__ == "__main__":
    unittest.main()
