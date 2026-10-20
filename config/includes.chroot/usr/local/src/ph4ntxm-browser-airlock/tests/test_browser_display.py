#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import browser_display as display


class Call:
    def __init__(self, function):
        self.function = function
        self.calls = []

    def __call__(self, *arguments):
        self.calls.append(arguments)
        return self.function(*arguments)


class Libraries:
    def __init__(self):
        self.events = []
        self.mode = 1
        self.rotation = 4
        self.status = 0
        self.sizes = (display.ScreenSize * 2)(display.ScreenSize(800, 600, 200, 150), display.ScreenSize(1200, 950, 300, 240))
        self.xlib = types.SimpleNamespace(
            XOpenDisplay=Call(lambda *_: 7),
            XDefaultRootWindow=Call(lambda *_: 42),
            XSelectInput=Call(lambda *_: 1),
            XPending=Call(lambda *_: len(self.events)),
            XNextEvent=Call(self.next_event),
            XFlush=Call(lambda *_: 1),
            XCloseDisplay=Call(lambda *_: 1),
        )
        self.randr = types.SimpleNamespace(
            XRRGetScreenInfo=Call(lambda *_: 99),
            XRRConfigCurrentConfiguration=Call(self.current),
            XRRConfigSizes=Call(self.config_sizes),
            XRRSetScreenConfig=Call(lambda *_: self.status),
            XRRFreeScreenConfigInfo=Call(lambda *_: None),
        )

    def current(self, _, pointer):
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_ushort)).contents.value = self.rotation
        return self.mode

    def config_sizes(self, _, pointer):
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int)).contents.value = 2
        return self.sizes

    def next_event(self, _, pointer):
        event = self.events.pop(0)
        ctypes.memmove(pointer, ctypes.byref(event), ctypes.sizeof(event))
        return 0

    def event(self, window=42, synthetic=False):
        event = display.Event()
        event.configure.type = 22
        event.configure.window = window
        event.configure.send_event = synthetic
        self.events.append(event)


class DisplayTests(unittest.TestCase):
    def setUp(self):
        self.library = Libraries()
        self.environment = patch.dict("os.environ", {"DISPLAY": ":180"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.loading = patch.object(display.ctypes, "CDLL", side_effect=lambda name: self.library.xlib if name == "libX11.so.6" else self.library.randr)
        self.loading.start()
        self.addCleanup(self.loading.stop)

    def connection(self):
        connection = display.DisplaySync()
        self.addCleanup(connection.close)
        return connection

    def test_initial_sync_preserves_mode_rotation_and_local_display(self):
        connection = self.connection()
        connection.poll()
        self.assertEqual(connection.dimensions, (1200, 950))
        self.assertEqual(self.library.xlib.XOpenDisplay.calls, [(b":180",)])
        self.assertEqual(self.library.xlib.XSelectInput.calls, [(7, 42, 1 << 17)])
        arguments = self.library.randr.XRRSetScreenConfig.calls[0]
        self.assertEqual(arguments[:4], (7, 99, 42, 1))
        self.assertEqual(arguments[4].value, 4)
        self.assertEqual(arguments[5], 0)
        self.assertEqual(self.library.randr.XRRFreeScreenConfigInfo.calls, [(99,)])

    def test_idle_and_synthetic_events_do_not_reconfigure(self):
        connection = self.connection()
        connection.poll()
        initial = len(self.library.randr.XRRGetScreenInfo.calls)
        self.library.event(window=8)
        self.library.event(synthetic=True)
        for _ in range(20):
            connection.poll()
        self.assertEqual(len(self.library.randr.XRRGetScreenInfo.calls), initial)

    def test_resize_burst_synchronizes_actual_current_size_once(self):
        connection = self.connection()
        connection.poll()
        self.library.sizes[1].width = 1300
        self.library.sizes[1].height = 1000
        for _ in range(20):
            self.library.event()
        connection.poll()
        self.assertEqual(connection.dimensions, (1300, 1000))
        self.assertEqual(len(self.library.randr.XRRSetScreenConfig.calls), 2)
        self.library.event()
        connection.poll()
        self.assertEqual(len(self.library.randr.XRRSetScreenConfig.calls), 2)

    def test_transient_configuration_race_retries_then_stops(self):
        connection = self.connection()
        self.library.status = 2
        connection.poll()
        self.assertIsNone(connection.dimensions)
        self.library.status = 0
        connection.poll()
        self.assertEqual(connection.dimensions, (1200, 950))
        self.library.status = 2
        self.library.sizes[1].width = 1350
        self.library.event()
        for _ in range(9):
            connection.poll()
        with self.assertRaisesRegex(display.DisplayError, "synchronize input"):
            connection.poll()
        self.assertEqual(len(self.library.randr.XRRGetScreenInfo.calls), len(self.library.randr.XRRFreeScreenConfigInfo.calls))

    def test_changing_resize_target_does_not_exhaust_retries(self):
        connection = self.connection()
        self.library.status = 2
        for index in range(20):
            self.library.event()
            self.library.events[-1].configure.width = 1200 + index
            self.library.events[-1].configure.height = 900
            connection.poll()
            self.assertEqual(connection.retries, 1)
        self.library.status = 0
        connection.poll()
        self.assertEqual(connection.dimensions, (1200, 950))

    def test_invalid_configuration_releases_native_data(self):
        connection = self.connection()
        self.library.mode = 65535
        for _ in range(9):
            connection.poll()
        with self.assertRaisesRegex(display.DisplayError, "mode"):
            connection.poll()
        self.assertEqual(self.library.randr.XRRFreeScreenConfigInfo.calls, [(99,)] * 10)
        self.assertEqual(self.library.randr.XRRSetScreenConfig.calls, [])

    def test_unavailable_or_remote_display_is_rejected_and_close_is_idempotent(self):
        self.library.xlib.XOpenDisplay.function = lambda *_: None
        with self.assertRaisesRegex(display.DisplayError, "connection"):
            display.DisplaySync()
        self.assertEqual(self.library.xlib.XDefaultRootWindow.calls, [])
        with patch.dict("os.environ", {"DISPLAY": "example.org:100"}):
            with self.assertRaisesRegex(display.DisplayError, "local"):
                display.DisplaySync()
        self.library.xlib.XOpenDisplay.function = lambda *_: 7
        connection = self.connection()
        connection.close()
        connection.close()
        self.assertEqual(self.library.xlib.XCloseDisplay.calls, [(7,)])


if __name__ == "__main__":
    unittest.main()
