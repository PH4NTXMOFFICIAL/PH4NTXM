#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import os
import re
import struct
import sys
import time
from pathlib import Path

from gi.repository import Gio, GLib

BUS = 'org.freedesktop.DBus'
BUS_PATH = '/org/freedesktop/DBus'
RUNTIME = Path('/run/user') / str(os.getuid())


def command_line(arguments):
    arguments = ['firefox'] + arguments
    token = os.environ.get('DESKTOP_STARTUP_ID', '')
    if token:
        arguments[0] += ' STARTUP_TOKEN=' + token
    data = os.fsencode(os.getcwd()) + b'\0'
    offsets = []
    header_size = 4 * (len(arguments) + 1)
    for argument in arguments:
        offsets.append(header_size + len(data))
        data += os.fsencode(argument) + b'\0'
    return struct.pack('<' + 'I' * (len(arguments) + 1), len(arguments), *offsets) + data


def matches_browser(pid):
    process = Path('/proc') / str(pid)
    if process.stat().st_uid != os.getuid():
        return False
    executable = process.joinpath('exe').readlink()
    if executable != Path('/usr/lib/firefox-esr/firefox-esr'):
        return False
    arguments = process.joinpath('cmdline').read_bytes().split(b'\0')
    profile = os.fsencode(RUNTIME / 'ph4ntxm-firefox-profile')
    return any(arguments[index] in (b'-profile', b'--profile') and
               arguments[index + 1] == profile for index in range(len(arguments) - 1))


def main():
    connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)

    def bus_call(method, arguments=None):
        return connection.call_sync(BUS, BUS_PATH, BUS, method, arguments, None,
                                    Gio.DBusCallFlags.NO_AUTO_START, 1000, None).unpack()[0]

    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        targets = set()
        for name in bus_call('ListNames'):
            match = re.fullmatch(r'org\.mozilla\.([A-Za-z0-9_]+)\.[A-Za-z0-9_]+', name)
            if not match:
                continue
            try:
                owner = bus_call('GetNameOwner', GLib.Variant('(s)', (name,)))
                pid = bus_call('GetConnectionUnixProcessID', GLib.Variant('(s)', (owner,)))
                if matches_browser(pid):
                    targets.add((owner, match.group(1)))
            except (OSError, GLib.Error):
                continue
        if len(targets) > 1:
            raise ValueError('More than one matching browser session is active.')
        if targets:
            owner, application = targets.pop()
            connection.call_sync(owner, '/org/mozilla/' + application + '/Remote',
                                 'org.mozilla.' + application, 'OpenURL',
                                 GLib.Variant('(ay)', (command_line(sys.argv[1:]),)), None,
                                 Gio.DBusCallFlags.NO_AUTO_START, 5000, None)
            return 0
        time.sleep(0.1)
    raise ValueError('The active browser is not ready to receive links. Try again.')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, GLib.Error) as error:
        print('PH4NTXM Browser: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
