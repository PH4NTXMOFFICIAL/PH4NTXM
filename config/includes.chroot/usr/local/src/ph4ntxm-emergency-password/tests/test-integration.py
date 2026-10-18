#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.
import argparse
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
args = parser.parse_args()
ROOT = args.root
INCLUDES = ROOT / 'config/includes.chroot'
HOOK = ROOT / 'config/hooks/normal/0033-build-ph4ntxm-emergency-password.chroot'
XML = INCLUDES / 'etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml'


def props(path):
    root = ET.parse(path).getroot()
    result = {}
    def walk(element, prefix=''):
        for child in element:
            name = prefix + '/' + child.attrib['name']
            if name in result:
                raise ValueError('Duplicate XFConf property ' + name)
            result[name] = child.attrib
            walk(child, name)
    walk(root)
    return result


class IntegrationTests(unittest.TestCase):
    def test_only_locker_pam_service_has_detector(self):
        paths = list((INCLUDES / 'etc/pam.d').glob('*'))
        detector_paths = [p.name for p in paths if 'pam_ph4ntxm_emergency' in p.read_text()]
        self.assertEqual(detector_paths, ['xfce4-screensaver'])
        pam = (INCLUDES / 'etc/pam.d/xfce4-screensaver').read_text().splitlines()
        self.assertEqual(pam, [
            'auth [success=done default=ignore] pam_unix.so',
            'auth requisite pam_ph4ntxm_emergency.so',
            'auth requisite pam_deny.so',
            'account include common-account',
        ])
        self.assertNotIn('pam_exec', '\n'.join(pam))

    def test_lock_entries_are_explicit(self):
        session = props(XML / 'xfce4-session.xml')
        self.assertEqual(session['/general/LockCommand']['value'], '/usr/bin/xfce4-screensaver-command --lock')
        self.assertEqual(session['/shutdown/LockScreen']['value'], 'true')
        power = props(XML / 'xfce4-power-manager.xml')
        self.assertEqual(power['/xfce4-power-manager/lock-screen-suspend-hibernate']['value'], 'true')

    def test_screensaver_locks_without_greeter_switch_button(self):
        values = props(XML / 'xfce4-screensaver.xml')
        for name in ('/saver/enabled', '/saver/idle-activation/enabled', '/lock/enabled', '/lock/sleep-activation', '/lock/saver-activation/enabled'):
            self.assertEqual(values[name]['value'], 'true', name)
        self.assertEqual(values['/lock/saver-activation/delay']['value'], '0')
        self.assertEqual(values['/lock/user-switching/enabled']['value'], 'false')
        self.assertEqual(values['/lock/logout/enabled']['value'], 'false')

    def test_competing_autostart_disabled(self):
        desktop = (INCLUDES / 'etc/skel/.config/autostart/light-locker.desktop').read_text()
        self.assertIn('Hidden=true\n', desktop)
        self.assertNotIn('Exec=', desktop)
        hook = HOOK.read_text()
        self.assertIn('apt-get --simulate purge --no-auto-remove light-locker', hook)
        self.assertIn('apt-get purge -y --no-auto-remove light-locker', hook)
        self.assertIn('test ! -x /usr/bin/light-locker', hook)

    def test_runtime_package_survives_cleanup(self):
        packages = (ROOT / 'config/package-lists/ph4ntxm-tools.list.chroot').read_text().splitlines()
        for name in ('xfce4-screensaver', 'libpam0g-dev', 'libcrypt-dev'):
            self.assertIn(name, packages)
        cleanup = (ROOT / 'config/hooks/normal/9997-purge-build-tools.chroot').read_text()
        manual, purge = cleanup.split('PURGE_PACKAGES="', 1)
        self.assertRegex(manual, re.compile(r'^\s+xfce4-screensaver \\$', re.M))
        purge = purge.split('"', 1)[0].splitlines()
        self.assertIn('libpam0g-dev', purge)
        self.assertNotIn('libcrypt-dev', purge)
        self.assertNotIn('xfce4-screensaver', purge)

    def test_build_never_invokes_panic(self):
        hook = HOOK.read_text()
        self.assertNotIn('PH4_TEST', hook)
        self.assertNotRegex(hook, r'(?m)^\s*(?:sudo\s+)?(?:systemctl|/usr/bin/systemctl)\s+')
        self.assertNotIn('ph4ntxm-panic.sh', hook)
        self.assertIn('chmod 4755 "$HELPER"', hook)
        self.assertIn('-fPIC -shared', hook)
        self.assertIn('-lcrypt -pie', hook)
        self.assertIn('python3 -B -I "$SOURCE/tests/test-native.py"', hook)
        for line in hook.splitlines():
            if line.startswith('cat >/etc/pam.d/'):
                self.assertEqual(line, "cat >/etc/pam.d/xfce4-screensaver <<'PAM'")


unittest.main(argv=['test-integration.py'])
