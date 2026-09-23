#!/usr/bin/env python3
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'config/includes.chroot'

def load(name):
    path = BASE / 'usr/local/sbin' / ('ph4ntxm-' + name)
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod

status = load('session-status')
password = load('session-password')

class PolicyTests(unittest.TestCase):
    def test_parsed_policy_has_no_general_passwordless_access(self):
        result = subprocess.run(['cvtsudoers', '-f', 'json', str(BASE/'etc/sudoers.d/ph4ntxm')], capture_output=True, text=True, check=True)
        policy = json.loads(result.stdout)
        specs = [c for u in policy['User_Specs'] for c in u['Cmnd_Specs']]
        full = [c for c in specs if {'command': 'ALL'} in c['Commands']]
        self.assertEqual(len(full), 1)
        self.assertIn({'authenticate': True}, full[0]['Options'])
        self.assertIn({'setenv': False}, full[0]['Options'])
        allowed = {c['command'] for s in specs if {'authenticate': False} in s['Options'] for c in s['Commands']}
        self.assertEqual(allowed, {
            '/usr/local/sbin/ph4ntxm-session-status *',
            '/usr/local/sbin/ph4ntxm-firewall-control enable',
            '/usr/local/sbin/ph4ntxm-usb-nuke-control enable',
            '/usr/bin/systemctl start ph4ntxm-panic.service',
            '/usr/local/sbin/ph4ntxm-wifi-control list --enable --rescan',
            '/usr/local/sbin/ph4ntxm-wifi-control connect',
        })
        self.assertTrue(any({'timestamp_timeout': '0'} in d['Options'] for d in policy['Defaults']))

    def test_read_allowlist_rejects_traversal_and_arbitrary_files(self):
        for action, path in [('read','/etc/shadow'), ('read','/run/ph4ntxm/boot_mac/..'), ('read','/run/ph4ntxm/boot_mac/../persona_seed'), ('read','/run/ph4ntxm/lonewolf_seed'), ('nonempty','/etc/shadow')]:
            self.assertFalse(status.allowed(action, path))
        self.assertTrue(status.allowed('read','/run/ph4ntxm/boot_mac/wlan0'))

    def test_password_validation(self):
        for value in ['', 'a'*5, 'a'*257, 'a'*6+'\n', 'a'*6+'\x00']:
            self.assertFalse(password.valid_password(value))
        self.assertTrue(password.valid_password('a'*6))
        self.assertTrue(password.valid_password('a'*256))
        self.assertTrue(password.valid_password('a long test passphrase'))

@unittest.skipUnless(os.geteuid() == 0, 'Run in an isolated user namespace with unshare -Ur')
class StatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        previous_umask = os.umask(0o022)
        self.addCleanup(os.umask, previous_umask)
        self.root = Path(self.temp.name)
        for name in ('run/ph4ntxm', 'run/ph4ntxm-session-auth', 'etc'):
            (self.root/name).mkdir(parents=True, exist_ok=True)
        self.file = self.root/'run/ph4ntxm/persona_seed'
        self.file.write_bytes(b'fixture-seed\n')
        self.file.chmod(0o600)
        real_open = os.open
        def fixture_open(path, flags, *args, **kwargs):
            return real_open(str(self.root) if path == '/' else path, flags, *args, **kwargs)
        self.mock_open = patch.object(status.os, 'open', side_effect=fixture_open)
        self.mock_open.start()
        self.addCleanup(self.mock_open.stop)

    def test_read_and_nonempty(self):
        self.assertEqual(status.read_protected('/run/ph4ntxm/persona_seed'), b'fixture-seed\n')
        self.assertEqual(status.main(['nonempty','/run/ph4ntxm/persona_seed']), 0)
        self.file.write_bytes(b'')
        self.assertEqual(status.main(['nonempty','/run/ph4ntxm/persona_seed']), 1)

    def test_rejects_symlink_file(self):
        self.file.unlink()
        self.file.symlink_to('/etc/shadow')
        with self.assertRaises(OSError):
            status.read_protected('/run/ph4ntxm/persona_seed')

    def test_rejects_symlink_parent(self):
        self.file.unlink()
        self.file.parent.rmdir()
        self.file.parent.symlink_to(self.root/'etc')
        with self.assertRaises(OSError):
            status.read_protected('/run/ph4ntxm/persona_seed')

    def test_rejects_writable_file_and_parent(self):
        self.file.chmod(0o666)
        with self.assertRaises(ValueError):
            status.read_protected('/run/ph4ntxm/persona_seed')
        self.file.chmod(0o600)
        self.file.parent.chmod(0o777)
        with self.assertRaises(ValueError):
            status.read_protected('/run/ph4ntxm/persona_seed')

    def test_rejects_oversized_and_special_files(self):
        self.file.write_bytes(b'x'*65537)
        with self.assertRaises(ValueError):
            status.read_protected('/run/ph4ntxm/persona_seed')
        self.file.unlink()
        os.mkfifo(self.file)
        with self.assertRaises(ValueError):
            status.read_protected('/run/ph4ntxm/persona_seed')

    def test_auth_requires_marker_and_password_hash(self):
        (self.root/'run/ph4ntxm-session-auth/ready').write_bytes(b'ready\n')
        shadow = self.root/'etc/shadow'
        for field, expected in [('!',1), ('',1), ('$y$fixture',0)]:
            shadow.write_text('ph4ntxm:'+field+':0:0:99999:7:::\n')
            self.assertEqual(status.main(['auth-ready']), expected)
        self.assertEqual(status.main(['read','/etc/shadow']), 2)
        self.assertEqual(status.main(['auth-ready','extra']), 2)

class SetupTests(unittest.TestCase):
    def request(self, password='abcdef', confirmation='abcdef', **extra):
        return (json.dumps(dict(password=password, confirmation=confirmation, **extra))+'\n').encode()

    def test_valid_request_and_fixed_account(self):
        self.assertEqual(password.request_password(self.request()), 'abcdef')
        with patch.object(password.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)) as run:
            self.assertTrue(password.set_password('abcdef'))
        self.assertEqual(run.call_args.args[0], ['/usr/sbin/chpasswd'])
        self.assertEqual(run.call_args.kwargs['input'], b'ph4ntxm:abcdef\n')
        self.assertNotIn('abcdef', str(run.call_args.args))

    def test_rejects_mismatch_short_input_and_extra_account(self):
        for raw in [self.request('abcde','abcde'), self.request('abcdef','different'), self.request(account='root'), b'[]\n', b'{}', b'x'*4097, self.request('abc\n123','abc\n123')]:
            with self.assertRaises(ValueError):
                password.request_password(raw)

    def converse(self, frames, results):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)/'ready'
            writer = io.BytesIO()
            def update(value):
                self.assertFalse(marker.exists())
                return next(results)
            with patch.object(password, 'READY', marker), patch.object(password, 'set_password', side_effect=update) as setter:
                success = password.conversation(io.BytesIO(frames), writer)
            self.assertEqual(marker.exists(), success)
            if success:
                self.assertEqual(marker.read_text(), 'ready\n')
                self.assertEqual(marker.stat().st_mode & 0o777, 0o644)
            return success, setter.call_count, [json.loads(line) for line in writer.getvalue().splitlines()]

    def test_mismatch_does_not_update_password(self):
        success, calls, replies = self.converse(self.request('abcdef','different'), iter([]))
        self.assertFalse(success)
        self.assertEqual(calls, 0)
        self.assertFalse(replies[0]['ok'])

    def test_backend_failure_can_retry(self):
        success, calls, replies = self.converse(self.request()*2, iter([False,True]))
        self.assertTrue(success)
        self.assertEqual(calls, 2)
        self.assertEqual([r['ok'] for r in replies], [False,True])

    def test_eof_and_oversized_frame_leave_gate_closed(self):
        for raw in [b'', b'x'*4097, b'{"password":']:
            success, calls, _ = self.converse(raw, iter([]))
            self.assertFalse(success)
            self.assertEqual(calls, 0)

    def test_chpasswd_timeout_is_not_success(self):
        with patch.object(password.subprocess, 'run', side_effect=subprocess.TimeoutExpired('chpasswd',15)):
            self.assertFalse(password.set_password('abcdef'))

    def test_vt_switch_requires_valid_local_x_property(self):
        for output in ['', 'XFree86_VT(INTEGER) = 0', 'XFree86_VT(INTEGER) = 64', 'XFree86_VT(INTEGER) = 7; command']:
            with patch.object(password.subprocess, 'run', return_value=types.SimpleNamespace(stdout=output)) as run:
                with self.assertRaises(ValueError):
                    password.activate_display({})
                self.assertEqual(run.call_count, 1)
        with patch.object(password.subprocess, 'run', return_value=types.SimpleNamespace(stdout='XFree86_VT(INTEGER) = 7\n')) as run:
            password.activate_display({})
            self.assertEqual(run.call_args.args[0], ['/usr/bin/chvt','7'])

    def test_lightdm_gates_before_session_and_drops_gui_privileges(self):
        config = (BASE/'etc/lightdm/lightdm.conf').read_text()
        self.assertIn('display-setup-script=/usr/local/sbin/ph4ntxm-session-password', config)
        self.assertIn('session-setup-script=/usr/local/sbin/ph4ntxm-session-status auth-ready', config)
        broker = (BASE/'usr/local/sbin/ph4ntxm-session-password').read_text()
        self.assertIn("'--clear-groups', '--no-new-privs'", broker)
        self.assertFalse((BASE/'etc/systemd/system/ph4ntxm-session-password.service').exists())

if __name__ == '__main__':
    unittest.main(verbosity=2)
