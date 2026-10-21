#!/usr/bin/python3 -I
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


path = Path(sys.argv.pop(1)) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else Path("/usr/lib/ph4ntxm")
if path.is_dir():
    path /= "clipboard_guard_x11.py"
sys.path.insert(0, str(path.parent))
spec = importlib.util.spec_from_file_location("clipboard_guard_x11", path)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class Resource:
    def __init__(self, status=0, count=1, pid=4242):
        self.status, self.count, self.pid = status, count, pid
        self.values = (backend.ClientIdValue * max(1, count))()
        self.values[0].spec.mask = 2
        self.values[0].length = 4
        self.XResQueryVersion = Mock(side_effect=self.version)
        self.XResQueryClientIds = Mock(side_effect=self.query)
        self.XResGetClientPid = Mock(return_value=pid)
        self.XResClientIdsDestroy = Mock()

    def version(self, display, major, minor):
        major._obj.value, minor._obj.value = 1, 2
        return 1

    def query(self, display, size, request, count, values):
        count._obj.value = self.count
        ctypes.cast(values, ctypes.POINTER(ctypes.POINTER(backend.ClientIdValue)))[0] = ctypes.cast(self.values, ctypes.POINTER(backend.ClientIdValue))
        return self.status


class X11BackendTest(unittest.TestCase):
    def make_backend(self, owners):
        self.worker = object.__new__(backend.X11Backend)
        self.worker.display = 123
        self.worker.window = 44
        self.worker.watch = 7
        self.worker.idle = 8
        self.worker.atoms = {"MANAGER": 90}
        self.worker.callback = Mock()
        self.worker.xlib = SimpleNamespace(
            XGetSelectionOwner=Mock(side_effect=owners),
            XConnectionNumber=Mock(return_value=12),
            XDestroyWindow=Mock(), XCloseDisplay=Mock(),
        )
        self.worker.glib = SimpleNamespace(
            IOCondition=SimpleNamespace(IN=1, HUP=2, ERR=4), source_remove=Mock()
        )
        return self.worker

    def test_success_zero_maps_owner_and_frees_results(self):
        worker = self.make_backend([44, 44, 0])
        resource = Resource()
        with patch.object(backend.ctypes, "CDLL", return_value=resource), patch.object(backend, "pause_clipman", return_value=1) as pause:
            worker.pause_manager()
        pause.assert_called_once_with(4242)
        resource.XResClientIdsDestroy.assert_called_once()
        self.assertEqual(resource.XResClientIdsDestroy.call_args.args[0].value, 1)
        request = resource.XResQueryClientIds.call_args.args[2]._obj
        self.assertEqual((request.client, request.mask), (44, 2))
        self.assertIs(backend.ClientIdSpec._fields_[1][1], ctypes.c_uint)

    def test_failed_or_ambiguous_mapping_never_signals(self):
        for status, count, pid in ((1, 1, 4242), (0, 0, 4242), (0, 2, 4242), (0, 1, -1), (0, 1, 0)):
            with self.subTest(status=status, count=count, pid=pid):
                worker = self.make_backend([44, 44])
                resource = Resource(status, count, pid)
                with patch.object(backend.ctypes, "CDLL", return_value=resource), patch.object(backend, "pause_clipman") as pause:
                    with self.assertRaises(backend.GuardError):
                        worker.pause_manager()
                pause.assert_not_called()
                resource.XResClientIdsDestroy.assert_called_once()

    def test_owner_change_refuses_without_signaling(self):
        worker = self.make_backend([44, 45])
        resource = Resource()
        with patch.object(backend.ctypes, "CDLL", return_value=resource), patch.object(backend, "pause_clipman") as pause:
            with self.assertRaises(backend.GuardError):
                worker.pause_manager()
        pause.assert_not_called()
        resource.XResClientIdsDestroy.assert_called_once()

    def test_no_manager_avoids_resource_library_and_helper(self):
        worker = self.make_backend([0])
        with patch.object(backend.ctypes, "CDLL") as library, patch.object(backend, "pause_clipman") as pause:
            worker.pause_manager()
        library.assert_not_called()
        pause.assert_not_called()

    def test_unknown_process_is_refused(self):
        worker = self.make_backend([44, 44])
        resource = Resource()
        with patch.object(backend.ctypes, "CDLL", return_value=resource), patch.object(backend, "pause_clipman", return_value=0) as pause, patch.object(backend, "disable_xfce_clipboard", return_value=0):
            with self.assertRaises(backend.GuardError):
                worker.pause_manager()
        pause.assert_called_once_with(4242)
        resource.XResClientIdsDestroy.assert_called_once()

    def test_missing_resource_library_refuses_without_helper(self):
        worker = self.make_backend([44])
        with patch.object(backend.ctypes, "CDLL", side_effect=OSError()), patch.object(backend, "pause_clipman") as pause:
            with self.assertRaises(backend.GuardError):
                worker.pause_manager()
        pause.assert_not_called()

    def test_connection_loss_abandons_without_x_requests(self):
        for condition in (2, 4, 6):
            with self.subTest(condition=condition):
                worker = self.make_backend([])
                with patch.object(backend.os, "close") as close:
                    self.assertFalse(worker.ready(12, condition))
                    worker.close()
                self.assertIsNone(worker.display)
                self.assertEqual(worker.window, 0)
                close.assert_called_once_with(12)
                worker.xlib.XDestroyWindow.assert_not_called()
                worker.xlib.XCloseDisplay.assert_not_called()
                worker.xlib.XGetSelectionOwner.assert_not_called()
                worker.callback.assert_called_once()
                self.assertIn("error", worker.callback.call_args.args[0])


    def test_xfce_replacement_waits_for_manager_release(self):
        worker = self.make_backend([44, 44, 44, 0, 0])
        with patch.object(backend.ctypes, "CDLL", return_value=Resource()), patch.object(backend, "pause_clipman", return_value=0), patch.object(backend, "disable_xfce_clipboard", return_value=1) as disable, patch.object(backend.time, "sleep"):
            worker.pause_manager()
        disable.assert_called_once_with(4242)

    def test_xfce_replacement_without_release_reports_failure(self):
        worker = self.make_backend([44, 44, 44])
        with patch.object(backend.ctypes, "CDLL", return_value=Resource()), patch.object(backend, "pause_clipman", return_value=0), patch.object(backend, "disable_xfce_clipboard", return_value=1), patch.object(backend.time, "monotonic", side_effect=[0, 3]):
            with self.assertRaises(backend.GuardError):
                worker.pause_manager()


if __name__ == "__main__":
    unittest.main()
