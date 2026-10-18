#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.machinery
import importlib.util
import io
import json
import sys
from pathlib import Path
import types
import unittest
from unittest.mock import patch


path = Path(sys.argv.pop(1))
loader = importlib.machinery.SourceFileLoader('session_setup', str(path))
spec = importlib.util.spec_from_loader(loader.name, loader)
setup = importlib.util.module_from_spec(spec)
loader.exec_module(setup)


class Widget:
    def __init__(self, text='', active=False):
        self.text = text
        self.active = active
        self.sensitive = True
        self.visible = False
        self.focused = False
        self.revealed = False

    def get_text(self):
        return self.text

    def set_text(self, text):
        self.text = text

    def get_active(self):
        return self.active

    def set_sensitive(self, sensitive):
        self.sensitive = sensitive

    def set_visibility(self, visible):
        self.visible = visible

    def set_reveal_child(self, revealed):
        self.revealed = revealed

    def grab_focus(self):
        self.focused = True

    def set_opacity(self, opacity):
        pass

    def start(self):
        pass

    def stop(self):
        pass


class Window:
    password_entries = setup.SetupWindow.password_entries
    clear_passwords = setup.SetupWindow.clear_passwords
    toggle_emergency = setup.SetupWindow.toggle_emergency
    toggle_visibility = setup.SetupWindow.toggle_visibility
    validate = setup.SetupWindow.validate
    submit = setup.SetupWindow.submit
    finish = setup.SetupWindow.finish

    def __init__(self):
        self.busy = False
        self.completed = False
        self.password = Widget('normal-password')
        self.confirmation = Widget('normal-password')
        self.emergency_password = Widget()
        self.emergency_confirmation = Widget()
        self.emergency_enabled = Widget()
        self.emergency_fields = Widget()
        self.reveal = Widget()
        self.feedback = Widget()
        self.foot = Widget()
        self.start = Widget()
        self.spinner = Widget()
        self.requests = []
        self.exchange = self.exchange_request

    def exchange_request(self, *passwords):
        self.requests.append(passwords)
        return {'ok': True}


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.window = Window()

    def enable(self, password='emergency-password', confirmation=None):
        window = self.window
        window.emergency_enabled.active = True
        window.toggle_emergency(window.emergency_enabled)
        window.emergency_password.text = password
        window.emergency_confirmation.text = password if confirmation is None else confirmation
        window.validate()

    def test_normal_only(self):
        self.window.validate()
        self.assertTrue(self.window.start.sensitive)
        self.assertFalse(self.window.emergency_enabled.active)

    def test_enabled_requires_valid_distinct_pair(self):
        for password, confirmation in [('', ''), ('short', 'short'), ('different-password', 'mismatching'),
                                       ('normal-password', 'normal-password'), ('control\nvalue', 'control\nvalue'),
                                       ('control\x7fvalue', 'control\x7fvalue')]:
            with self.subTest(password=password):
                self.enable(password, confirmation)
                self.assertFalse(self.window.start.sensitive)
                self.window.submit()
                self.assertFalse(self.window.busy)
                self.assertEqual(self.window.requests, [])
        self.enable()
        self.assertTrue(self.window.start.sensitive)

    def test_length_boundaries_and_unicode(self):
        for length in [6, 256]:
            self.enable('x' * length)
            self.assertTrue(self.window.start.sensitive)
        self.enable('x' * 257)
        self.assertFalse(self.window.start.sensitive)
        for suffix, valid in [('abc', True), ('abcd', False)]:
            password = chr(0x1f600) * 127 + suffix
            self.assertEqual(len(password.encode('utf-8')), 508 + len(suffix))
            self.enable(password)
            self.assertEqual(self.window.start.sensitive, valid)
            if not valid:
                self.assertEqual(self.window.feedback.text, 'Password is too long. Use fewer characters.')
            self.window.emergency_enabled.active = False
            self.window.password.text = password
            self.window.confirmation.text = password
            self.window.validate()
            self.assertEqual(self.window.start.sensitive, valid)
            if not valid:
                self.assertEqual(self.window.feedback.text, 'Password is too long. Use fewer characters.')
        self.assertFalse(setup.valid_pair(chr(0xd800) * 6, chr(0xd800) * 6))

    def test_normal_password_still_required(self):
        self.enable()
        self.window.confirmation.text = 'mismatch'
        self.window.validate()
        self.assertFalse(self.window.start.sensitive)
        self.window.submit()
        self.assertFalse(self.window.busy)

    def test_toggle_clears_and_reveals(self):
        self.enable()
        self.assertTrue(self.window.emergency_fields.revealed)
        self.assertEqual(self.window.foot.text, 'Emergency password triggers Panic/Nuke at screen unlock. No confirmation.')
        self.assertTrue(self.window.emergency_password.focused)
        self.window.emergency_enabled.active = False
        self.window.toggle_emergency(self.window.emergency_enabled)
        self.assertFalse(self.window.emergency_fields.revealed)
        self.assertEqual(self.window.foot.text, 'A new boot starts a new session and password setup.')
        self.assertEqual(self.window.emergency_password.text, '')
        self.assertEqual(self.window.emergency_confirmation.text, '')
        self.assertTrue(self.window.start.sensitive)

    def test_show_password_applies_to_all_entries(self):
        for active in [True, False]:
            self.window.reveal.active = active
            self.window.toggle_visibility(self.window.reveal)
            self.assertTrue(all(entry.visible == active for entry in self.window.password_entries()))

    def submit(self):
        workers = []
        callbacks = []
        def start_thread(**kwargs):
            workers.append(kwargs['target'])
            return types.SimpleNamespace(start=lambda: None)
        with patch.object(setup.threading, 'Thread', side_effect=start_thread), \
             patch.object(setup.GLib, 'idle_add', side_effect=lambda *args: callbacks.append(args)):
            self.window.submit()
            self.assertEqual(len(workers), 1)
            self.assertTrue(all(entry.text == '' for entry in self.window.password_entries()))
            self.assertFalse(self.window.emergency_enabled.sensitive)
            self.assertTrue(all(not entry.sensitive for entry in self.window.password_entries()))
            workers[0]()
        for cell in workers[0].__closure__:
            if isinstance(cell.cell_contents, str):
                self.assertEqual(cell.cell_contents, '')
        return callbacks

    def test_submit_enabled_and_success(self):
        self.enable()
        callbacks = self.submit()
        self.assertEqual(self.window.requests, [('normal-password', 'normal-password', 'emergency-password', 'emergency-password')])
        with patch.object(setup.Gtk, 'main_quit') as quit_main:
            callback, result = callbacks[0]
            callback(result)
            quit_main.assert_called_once()
        self.assertTrue(self.window.completed)
        self.assertTrue(all(entry.text == '' for entry in self.window.password_entries()))

    def test_submit_disabled_sends_empty_emergency_fields(self):
        self.window.emergency_password.text = 'stale-value'
        self.window.emergency_confirmation.text = 'stale-value'
        self.submit()
        self.assertEqual(self.window.requests, [('normal-password', 'normal-password', '', '')])

    def test_failure_reenables_entries(self):
        self.enable()
        self.window.exchange = lambda *args: {'ok': False, 'error': 'Try again.'}
        callbacks = self.submit()
        callback, result = callbacks[0]
        callback(result)
        self.assertFalse(self.window.busy)
        self.assertTrue(self.window.emergency_enabled.sensitive)
        self.assertTrue(all(entry.sensitive for entry in self.window.password_entries()))
        self.assertEqual(self.window.feedback.text, 'Try again.')
        self.assertTrue(self.window.password.focused)

    def test_fatal_failure_keeps_form_disabled(self):
        self.enable()
        def interrupted(*args):
            raise OSError()
        self.window.exchange = interrupted
        callbacks = self.submit()
        callback, result = callbacks[0]
        callback(result)
        self.assertTrue(self.window.busy)
        self.assertFalse(self.window.emergency_enabled.sensitive)
        self.assertTrue(all(entry.text == '' for entry in self.window.password_entries()))

    def test_clear_on_destroy(self):
        self.enable()
        self.window.clear_passwords(self.window)
        self.assertTrue(all(entry.text == '' for entry in self.window.password_entries()))

    def test_broker_exact_four_fields_and_unicode(self):
        password = chr(0x1f600) * 127 + 'abc'
        emergency = chr(0x1f601) * 127 + 'abc'
        output = types.SimpleNamespace(buffer=io.BytesIO())
        incoming = types.SimpleNamespace(buffer=io.BytesIO(b'{"ok":true}\n'))
        with patch.object(setup.sys, 'stdout', output), patch.object(setup.sys, 'stdin', incoming):
            result = setup.SetupWindow.broker_exchange(password, password, emergency, emergency)
        self.assertTrue(result['ok'])
        payload = output.buffer.getvalue()
        self.assertLess(len(payload), 4096)
        self.assertEqual(json.loads(payload), {'password': password, 'confirmation': password,
                                             'emergency_password': emergency, 'emergency_confirmation': emergency})


if __name__ == '__main__':
    unittest.main()
