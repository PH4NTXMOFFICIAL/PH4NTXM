#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import base64
import configparser
import ctypes
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import threading
import traceback
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('media', ROOT / 'media.py')
media = importlib.util.module_from_spec(spec)
spec.loader.exec_module(media)
FILTER = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else ROOT / 'filter'


class MediaTests(unittest.TestCase):
    def test_edition_configuration(self):
        class Settings:
            def __init__(self, theme):
                self.theme = theme

            def get_property(self, key):
                return {'gtk-theme-name': self.theme, 'gtk-icon-theme-name': 'Lyra-blue-dark',
                        'gtk-font-name': 'Sans 10'}[key]

        for theme in ['PH4NTXM-Abyss', 'PH4NTXM-Ghost']:
            with tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / 'config'
                media.configure(config, Settings(theme))
                self.assertIn(theme, (config / 'home/gtk-3.0/settings.ini').read_text())
                self.assertFalse((config / 'host.auth').exists())
                self.assertIn('allow-module-loading=no', (config / 'home/pulse/daemon.conf').read_text())
                self.assertIn('format=s16le rate=48000 channels=2', (config / 'pulse.pa').read_text())

    def test_image_formats_and_webp_decoding(self):
        import gi
        gi.require_version('GdkPixbuf', '2.0')
        from gi.repository import GdkPixbuf

        desktop = ROOT.parents[2] / 'share/applications/ph4ntxm-image-viewer.desktop'
        entries = configparser.ConfigParser(interpolation=None)
        entries.read(desktop)
        declared = set(entries['Desktop Entry']['MimeType'].strip(';').split(';'))
        supported = {mime for item in GdkPixbuf.Pixbuf.get_formats() for mime in item.get_mime_types()}
        self.assertFalse(declared - supported, 'Missing image loaders: ' + ', '.join(sorted(declared - supported)))
        loader = GdkPixbuf.PixbufLoader.new_with_type('webp')
        loader.write(base64.b64decode('UklGRhwAAABXRUJQVlA4TBAAAAAvA8AAEAfQ1eh/AQMR0f8A'))
        loader.close()
        image = loader.get_pixbuf()
        self.assertEqual((image.get_width(), image.get_height()), (4, 4))
        self.assertTrue(image.get_has_alpha())
        self.assertEqual(bytes(image.get_pixels()[:4]), bytes((0, 171, 255, 128)))

    def test_local_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '-image with spaces.png'
            path.write_bytes(b'image')
            entries = media.open_files([path.as_uri()], 'image')
            try:
                self.assertEqual(entries[0][0], path)
                self.assertEqual(os.read(entries[0][1], 5), b'image')
            finally:
                os.close(entries[0][1])
            for value in ['https://example.invalid/video', 'file://remote/a', 'file:///tmp/a?query', directory]:
                with self.assertRaises((media.MediaError, OSError)):
                    media.open_files([value], 'image')
            fifo = Path(directory) / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(media.MediaError):
                media.open_files([str(fifo)], 'image')
            with path.open('wb') as stream:
                stream.truncate(media.MAX_IMAGE_BYTES + 1)
            with self.assertRaises(media.MediaError):
                media.open_files([str(path)], 'image')

    def test_mount_boundary(self):
        args = media.sandbox(10)
        for flag in ['--unshare-all', '--clearenv', '--die-with-parent', '--seccomp']:
            self.assertIn(flag, args)
        self.assertNotIn('/home', args)
        self.assertNotIn('/run/user', args)
        self.assertNotIn('/dev/dri', args)
        self.assertNotIn('/dev/snd', args)
        self.assertNotIn('--share-net', args)
        self.assertNotIn('--proc', args)
        self.assertEqual(args[args.index('/proc') - 1], '--dir')
        self.assertIn('/usr/share/dbus-1/services', args)

    def test_syscalls_and_threads(self):
        data = subprocess.check_output([str(FILTER)])
        pid = os.fork()
        if pid == 0:
            try:
                class Filter(ctypes.Structure):
                    _fields_ = [('length', ctypes.c_ushort), ('instructions', ctypes.c_void_p)]
                buffer = ctypes.create_string_buffer(data)
                program = Filter(len(data) // 8, ctypes.cast(buffer, ctypes.c_void_p))
                libc = ctypes.CDLL(None, use_errno=True)
                assert libc.prctl(38, 1, 0, 0, 0) == 0
                assert libc.prctl(22, 2, ctypes.byref(program), 0, 0) == 0
                for family in [socket.AF_INET, socket.AF_INET6, socket.AF_NETLINK, socket.AF_PACKET]:
                    try:
                        socket.socket(family, socket.SOCK_DGRAM)
                    except PermissionError:
                        pass
                    else:
                        raise AssertionError('network socket allowed')
                a, b = socket.socketpair()
                a.send(b'ok')
                assert b.recv(2) == b'ok'
                a.close()
                b.close()
                called = []
                thread = threading.Thread(target=lambda: called.append(True))
                thread.start()
                thread.join()
                assert called == [True]
                assert subprocess.run(['/usr/bin/true']).returncode == 0
                assert libc.syscall(272, 0x10000000) == -1
                os._exit(0)
            except BaseException:
                traceback.print_exc()
                os._exit(1)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)


if __name__ == '__main__':
    unittest.main()
