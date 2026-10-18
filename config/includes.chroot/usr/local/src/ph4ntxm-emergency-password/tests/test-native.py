#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import argparse
import ctypes
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]
PARSER = argparse.ArgumentParser()
PARSER.add_argument('--pam-include', type=Path, default=Path('/usr/include'))
PARSER.add_argument('--broker', type=Path, default=Path('/usr/local/sbin/ph4ntxm-session-password'))
ARGS, TEST_ARGS = PARSER.parse_known_args()


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='ph4-emergency-native-test-')
        cls.build = Path(cls.temporary.name)
        cls.parent = cls.build / 'protected'
        cls.parent.mkdir(mode=0o700)
        cls.state = cls.parent / 'ph4ntxm-session-auth'
        cls.state.mkdir(mode=0o755)
        cls.record = cls.state / 'emergency'
        cls.dispatch_log = cls.build / 'dispatch.log'
        cls.helper = cls.build / 'check-test'
        cls.harness = cls.build / 'pam-harness'
        cls.log_path = json.dumps(str(cls.dispatch_log))
        config = '\n'.join([
            '#define PH4_STATE_PARENT ' + json.dumps(str(cls.parent)),
            '#define PH4_STATE_NAME "ph4ntxm-session-auth"',
            '#define PH4_DISPATCH_PATH ' + json.dumps(str(cls.build / 'dispatch-test')),
            '#define PH4_HELPER_PATH ' + json.dumps(str(cls.helper)),
            '#define PH4_OWNER ' + str(os.getuid()),
        ])
        (cls.build / 'test_config.h').write_text(config + '\n')
        for name in ('check.c', 'pam_emergency.c', 'protocol.h'):
            shutil.copyfile(SOURCE / name, cls.build / name)
        dispatcher = '''
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv) {
    int fd;
    if (argc != 4 || strcmp(argv[1], "start") || strcmp(argv[2], "--no-block") ||
        strcmp(argv[3], "ph4ntxm-panic.service") || !environ[0] || !environ[1] || environ[2] ||
        strcmp(environ[0], "PATH=/usr/sbin:/usr/bin:/sbin:/bin") || strcmp(environ[1], "LANG=C"))
        return 90;
    fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd < 0 || write(fd, "requested\\n", 10) != 10)
        return 91;
    close(fd);
    return 1;
}
'''
        (cls.build / 'dispatch.c').write_text(dispatcher)
        flags = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wformat=2',
                 '-fstack-protector-strong', '-D_FORTIFY_SOURCE=3', '-Wl,-z,relro,-z,now']
        cls.compile(flags + ['-DLOG_PATH=' + cls.log_path, str(cls.build / 'dispatch.c'),
                             '-o', str(cls.build / 'dispatch-test')])
        cls.compile(flags + ['-DPH4_TEST', '-fPIE', '-pie', str(cls.build / 'check.c'),
                             '-lcrypt', '-o', str(cls.helper)])
        cls.compile(flags + ['-DPH4_TEST', '-I' + str(ARGS.pam_include), '-I' + str(cls.build),
                             str(cls.build / 'pam_emergency.c'), str(SOURCE / 'tests/pam_harness.c'),
                             '-o', str(cls.harness)])
        cls.compile(flags + ['-fPIE', '-pie', str(SOURCE / 'check.c'), '-lcrypt',
                             '-o', str(cls.build / 'check-release')])
        cls.compile(flags + ['-fPIC', '-shared', '-I' + str(ARGS.pam_include),
                             str(SOURCE / 'pam_emergency.c'), '-Wl,-l:libpam.so.0',
                             '-o', str(cls.build / 'pam-release.so')])
        cls.compile(flags + ['-DPH4_TEST', '-fPIC', '-shared', '-I' + str(ARGS.pam_include),
                             str(cls.build / 'pam_emergency.c'), '-Wl,-l:libpam.so.0',
                             '-o', str(cls.build / 'pam-test.so')])
        for deny in (False, True):
            name = 'pam-test-deny.so' if deny else 'pam-test-unix.so'
            cls.compile(flags + (['-DPH4_TEST_DENY'] if deny else []) +
                        ['-fPIC', '-shared', '-I' + str(ARGS.pam_include),
                         str(SOURCE / 'tests/pam_test_auth.c'), '-Wl,-l:libpam.so.0',
                         '-o', str(cls.build / name)])
        cls.stack_harness = cls.build / 'pam-stack-harness'
        cls.compile(flags + ['-I' + str(ARGS.pam_include), str(SOURCE / 'tests/pam_stack_harness.c'),
                             '-Wl,--export-dynamic-symbol=audit_open', '-Wl,-l:libpam.so.0',
                             '-o', str(cls.stack_harness)])
        cls.pamdir = cls.build / 'pam.d'
        cls.pamdir.mkdir()
        cls.crypt = ctypes.CDLL('libcrypt.so.1')
        cls.crypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        cls.crypt.crypt.restype = ctypes.c_char_p
        cls.password = b'Clear-Only-For-Synthetic-Tests'
        cls.hash = cls.make_hash(cls.password)

    @classmethod
    def compile(cls, command):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode())

    @classmethod
    def make_hash(cls, password):
        value = cls.crypt.crypt(password, b'$6$rounds=100000$1234567890abcdef$')
        if not value or not value.startswith(b'$6$'):
            raise RuntimeError('Synthetic test hash creation failed')
        return value

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.state.chmod(0o755)
        if self.record.is_symlink() or self.record.exists():
            self.record.unlink()
        self.record.write_bytes(self.hash + b'\n')
        self.record.chmod(0o600)
        self.dispatch_log.unlink(missing_ok=True)
        self.write_stack()

    def write_stack(self, accept_any=False):
        suffix = ' accept-any' if accept_any else ''
        policy = '\n'.join([
            'auth [success=done default=ignore] ' + str(self.build / 'pam-test-unix.so') + suffix,
            'auth requisite ' + str(self.build / 'pam-test.so'),
            'auth requisite ' + str(self.build / 'pam-test-deny.so'),
        ])
        (self.pamdir / 'xfce4-screensaver').write_text(policy + '\n')

    def stack(self, token, expected):
        result = subprocess.run([str(self.stack_harness), str(self.pamdir)], input=token,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, str(expected).encode() + b' 1\n')
        self.assertEqual(result.stderr, b'')

    def framed(self, token):
        return struct.pack('!I', len(token)) + token

    def check(self, token, expected, frame=None, extra_args=()):
        result = subprocess.run([str(self.helper), *extra_args], input=self.framed(token) if frame is None else frame,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        self.assertEqual(result.returncode, expected)
        self.assertEqual(result.stdout + result.stderr, b'')

    def module(self, token, expected, scenario='normal'):
        result = subprocess.run([str(self.harness), scenario], input=token,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, str(expected).encode() + b'\n')
        self.assertEqual(result.stderr, b'')

    def no_dispatch(self):
        self.assertFalse(self.dispatch_log.exists())

    def test_exact_match_requests_panic_and_denies_even_dispatch_failure(self):
        self.check(self.password, 3)
        self.assertEqual(self.dispatch_log.read_bytes(), b'requested\n')
        self.module(self.password, 7)
        self.assertEqual(self.dispatch_log.read_bytes(), b'requested\nrequested\n')

    def test_real_pam_stack_normal_password_shortcircuits_emergency(self):
        self.stack(b'Synthetic-Normal-Password', 0)
        self.no_dispatch()

    def test_real_pam_stack_emergency_denies_with_one_prompt(self):
        self.stack(self.password, 7)
        self.assertEqual(self.dispatch_log.read_bytes(), b'requested\n')

    def test_real_pam_stack_wrong_password_denies_with_one_prompt(self):
        self.stack(b'Wrong-Synthetic-Password', 7)
        self.no_dispatch()

    def test_real_pam_stack_later_equal_normal_password_wins(self):
        self.write_stack(accept_any=True)
        self.stack(self.password, 0)
        self.no_dispatch()

    def test_nonmatch_never_dispatches_or_authenticates(self):
        self.check(b'Another-Password', 1)
        self.module(b'Another-Password', 25)
        self.no_dispatch()

    def test_dispatch_exec_failure_still_denies(self):
        dispatcher = self.build / 'dispatch-test'
        moved = self.build / 'dispatch-hidden'
        dispatcher.rename(moved)
        try:
            self.check(self.password, 3)
            self.module(self.password, 7)
        finally:
            moved.rename(dispatcher)
        self.no_dispatch()

    def test_missing_helper_still_denies(self):
        moved = self.build / 'helper-hidden'
        self.helper.rename(moved)
        try:
            self.module(self.password, 7)
        finally:
            moved.rename(self.helper)
        self.no_dispatch()

    def test_optout(self):
        self.record.write_bytes(b'disabled\n')
        self.check(self.password, 2)
        self.module(self.password, 25)
        self.no_dispatch()

    @unittest.skipUnless(ARGS.broker.is_file(), 'Provide --broker to check the setup broker hash format')
    def test_actual_broker_record_interoperates_with_native_verifier(self):
        loader = importlib.machinery.SourceFileLoader('ph4_native_test_broker', str(ARGS.broker))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        broker = importlib.util.module_from_spec(spec)
        loader.exec_module(broker)
        for password in ('Synthetic-Interop-Password', '\U0001f47b' * 125 + 'abcdef', '\u00e9' * 255 + 'a'):
            with self.subTest(bytes=len(password.encode())):
                self.assertTrue(broker.valid_password(password))
                self.record.write_bytes(broker.emergency_record(password))
                self.check(password.encode(), 3)
                self.module(password.encode(), 7)
                self.check(b'Wrong-Synthetic-Interop-Password', 1)
        self.assertEqual(self.dispatch_log.read_bytes(), b'requested\n' * 6)
        self.dispatch_log.unlink()
        self.record.write_bytes(broker.emergency_record(''))
        self.check(self.password, 2)
        self.module(self.password, 25)
        self.no_dispatch()

    def test_exact_full_utf8_token_matches(self):
        password = ('\U0001f47b' * 125 + 'abcdef').encode()
        self.record.write_bytes(self.make_hash(password) + b'\n')
        self.check(password, 3)
        self.assertEqual(self.dispatch_log.read_bytes(), b'requested\n')

    def test_libcrypt_full_length_boundary(self):
        password = ('\u00e9' * 255 + 'a').encode()
        self.assertEqual(len(password), 511)
        self.record.write_bytes(self.make_hash(password) + b'\n')
        self.check(password, 3)
        self.assertEqual(self.dispatch_log.read_bytes(), b'requested\n')

    def test_invalid_tokens_rejected_without_truncation(self):
        cases = [b'', b'abcde', b'a' * 257, b'a' * 512, ('\u00e9' * 256).encode(),
                 b'abcde\x00f', b'abcde\nf', b'abcde\x7ff', b'abcde\xff',
                 b'abcde\xc0\x80', b'abcde\xed\xa0\x80', b'abcde\xf4\x90\x80\x80']
        for token in cases:
            with self.subTest(length=len(token), prefix=token[:5]):
                self.check(token, 4)
                if b'\x00' not in token:
                    self.module(token, 7)
        self.no_dispatch()

    def test_malformed_frames(self):
        cases = [b'', b'\x00\x00', struct.pack('!I', 0), struct.pack('!I', 0xffffffff),
                 struct.pack('!I', len(self.password) + 1) + self.password,
                 self.framed(self.password) + b'x']
        for frame in cases:
            with self.subTest(frame_length=len(frame)):
                self.check(b'', 4, frame=frame)
        self.no_dispatch()

    def test_no_caller_arguments(self):
        self.check(self.password, 4, extra_args=('anything',))
        self.no_dispatch()

    def test_other_services_users_missing_tokens_and_pam_errors(self):
        for scenario in ('service', 'user', 'missing', 'item-error', 'null-service', 'null-user', 'arguments'):
            with self.subTest(scenario=scenario):
                self.module(self.password, 7, scenario)
        self.module(self.password, 25, 'setcred')
        self.no_dispatch()

    def test_missing_record_fails_closed(self):
        self.record.unlink()
        self.check(self.password, 4)
        self.module(self.password, 7)
        self.no_dispatch()

    def test_file_mode_symlink_and_hardlink_rejected(self):
        self.record.chmod(0o644)
        self.check(self.password, 4)
        self.record.chmod(0o600)
        alias = self.state / 'alias'
        try:
            os.link(self.record, alias)
            self.check(self.password, 4)
            self.record.unlink()
            self.record.symlink_to(alias)
            self.check(self.password, 4)
        finally:
            alias.unlink(missing_ok=True)
        self.no_dispatch()

    def test_writable_state_directory_rejected(self):
        self.state.chmod(0o777)
        self.check(self.password, 4)
        self.module(self.password, 7)
        self.no_dispatch()

    def test_symlink_state_directory_rejected(self):
        moved = self.parent / 'actual-state'
        self.state.rename(moved)
        self.state.symlink_to(moved)
        try:
            self.check(self.password, 4)
        finally:
            self.state.unlink()
            moved.rename(self.state)
        self.no_dispatch()

    def test_malformed_or_unbounded_hash_records_rejected(self):
        cases = [b'', b'disabled', b'disabled\nextra\n', b'disabled\x00\n',
                 self.hash, self.hash + b'\nextra\n', b'x' * 200 + b'\n',
                 self.hash.replace(b'rounds=100000', b'rounds=999999999') + b'\n',
                 self.hash.replace(b'$6$', b'$5$', 1) + b'\n',
                 self.hash.replace(b'1234567890abcdef', b'short') + b'\n',
                 self.hash[:-1] + b'!\n']
        for value in cases:
            with self.subTest(size=len(value)):
                self.record.write_bytes(value)
                self.check(self.password, 4)
                self.module(self.password, 7)
        self.no_dispatch()

    def test_release_binaries_have_only_fixed_production_paths(self):
        helper = (self.build / 'check-release').read_bytes()
        module = (self.build / 'pam-release.so').read_bytes()
        self.assertIn(b'/usr/bin/systemctl\0', helper)
        self.assertIn(b'/run\0', helper)
        self.assertIn(b'ph4ntxm-session-auth\0', helper)
        self.assertIn(b'/usr/local/libexec/ph4ntxm-emergency-check\0', module)
        self.assertNotIn(str(self.build).encode(), helper)
        self.assertNotIn(str(self.build).encode(), module)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *TEST_ARGS])
