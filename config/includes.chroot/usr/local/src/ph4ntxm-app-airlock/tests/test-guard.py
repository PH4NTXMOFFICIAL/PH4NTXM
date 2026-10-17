#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import base64
import ctypes
import errno
import json
import os
import resource
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


class FilterProgram(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.c_void_p)]


def apply_filter(data):
    buffer = ctypes.create_string_buffer(data)
    program = FilterProgram(len(data) // 8, ctypes.cast(buffer, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), "Could not install the syscall filter")
    return libc


def syscall_probe(data, x32=False):
    libc = apply_filter(data)
    if x32:
        libc.syscall(0x40000027)
        raise AssertionError("The x32 syscall was not terminated")
    for family in (
        socket.AF_INET,
        socket.AF_INET6,
        socket.AF_NETLINK,
        socket.AF_PACKET,
    ):
        try:
            socket.socket(family, socket.SOCK_DGRAM)
        except PermissionError:
            pass
        else:
            raise AssertionError("An external socket family was allowed")
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
        left, right = socket.socketpair(socket.AF_UNIX, kind)
        left.send(b"airlock")
        assert right.recv(7) == b"airlock"
        left.close()
        right.close()
    for factory in (
        lambda: socket.socket(socket.AF_UNIX, socket.SOCK_RAW),
        lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_RAW),
        lambda: socket.socketpair(socket.AF_INET, socket.SOCK_STREAM),
    ):
        try:
            factory()
        except PermissionError:
            pass
        else:
            raise AssertionError("An unsafe socket type was allowed")
    for call, args in (
        (101, (0, 0, 0, 0)),
        (272, (0,)),
        (308, (-1, 0)),
        (321, (0, 0, 0)),
        (425, (0, 0)),
        (438, (-1, 0, 0)),
        (16, (-1, 0x5412, 0)),
        (16, (-1, 0x541C, 0)),
    ):
        ctypes.set_errno(0)
        assert libc.syscall(call, *args) == -1
        assert ctypes.get_errno() == errno.EPERM, (call, ctypes.get_errno())
    ctypes.set_errno(0)
    assert libc.syscall(435, 0, 0) == -1
    assert ctypes.get_errno() == errno.ENOSYS
    for flag in (0x10000000, 0x00020000, 0x40000000, 0x20000000):
        ctypes.set_errno(0)
        assert libc.syscall(56, flag, 0, 0, 0, 0) == -1
        assert ctypes.get_errno() == errno.EPERM
    completed = []
    child = threading.Thread(target=lambda: completed.append(True))
    child.start()
    child.join()
    assert completed == [True]
    assert subprocess.run(["/usr/bin/true"], check=False).returncode == 0
    print("Offline syscall and process checks passed")


def bpf_result(data, number, arch=0xC000003E, args=()):
    values = tuple(args) + (0,) * (6 - len(args))
    context = struct.pack("=iI7Q", number, arch, 0, *values)
    instructions = list(struct.iter_unpack("=HBBI", data))
    accumulator = 0
    index = 0
    for _ in range(len(instructions) + 1):
        code, yes, no, value = instructions[index]
        index += 1
        if code == 0x20:
            accumulator = struct.unpack_from("=I", context, value)[0]
        elif code == 0x54:
            accumulator &= value
        elif code == 0x15:
            index += yes if accumulator == value else no
        elif code == 0x35:
            index += yes if accumulator >= value else no
        elif code == 0x45:
            index += yes if accumulator & value else no
        elif code == 0x06:
            return value
        else:
            raise AssertionError("Unexpected BPF instruction")
    raise AssertionError("The BPF program did not return")


if len(sys.argv) >= 3 and sys.argv[1] in ("--syscalls", "--x32"):
    syscall_probe(base64.b64decode(sys.argv[2]), sys.argv[1] == "--x32")
    raise SystemExit(0)

if len(sys.argv) >= 3 and sys.argv[1] == "--without-close-range":
    data = b"".join(
        struct.pack("=HBBI", *entry)
        for entry in (
            (0x20, 0, 0, 0),
            (0x15, 0, 1, 436),
            (0x06, 0, 0, 0x50000 | errno.ENOSYS),
            (0x06, 0, 0, 0x7FFF0000),
        )
    )
    apply_filter(data)
    os.execv(sys.argv[2], sys.argv[2:])

GUARD = (
    Path(sys.argv.pop(1)).resolve()
    if len(sys.argv) > 1
    else Path(__file__).resolve().parents[1] / "guard"
)


class GuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.filter = subprocess.check_output([str(GUARD), "filter"])

    def test_filter_structure_and_architectures(self):
        self.assertTrue(self.filter)
        self.assertEqual(len(self.filter) % 8, 0)
        self.assertLessEqual(len(self.filter), 32768)
        for arch in (0x40000003, 0xC00000B7, 0):
            self.assertEqual(bpf_result(self.filter, 39, arch), 0x80000000)
        self.assertEqual(bpf_result(self.filter, 0x40000027), 0x80000000)
        self.assertEqual(bpf_result(self.filter, 39), 0x7FFF0000)
        for call, args in (
            (41, (socket.AF_INET, socket.SOCK_STREAM)),
            (41, (socket.AF_UNIX, socket.SOCK_RAW)),
            (53, (socket.AF_INET, socket.SOCK_STREAM)),
        ):
            self.assertEqual(bpf_result(self.filter, call, args=args), 0x50001)
        self.assertEqual(
            bpf_result(
                self.filter,
                41,
                args=(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC),
            ),
            0x7FFF0000,
        )

    def test_runtime_filter_and_threads(self):
        result = subprocess.run(
            [
                str(GUARD),
                "run",
                "--",
                sys.executable,
                "-I",
                str(Path(__file__).resolve()),
                "--syscalls",
                base64.b64encode(self.filter).decode(),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Offline syscall and process checks passed", result.stdout)

    def test_x32_is_terminated(self):
        result = subprocess.run(
            [
                str(GUARD),
                "run",
                "--",
                sys.executable,
                "-I",
                str(Path(__file__).resolve()),
                "--x32",
                base64.b64encode(self.filter).decode(),
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(
            result.returncode,
            -signal.SIGSYS,
            result.stderr.decode(errors="replace"),
        )

    def test_run_closes_descriptors_and_restricts_privilege(self):
        with tempfile.TemporaryFile() as stream:
            inherited = 199
            os.dup2(stream.fileno(), inherited)
            try:
                code = (
                    "import ctypes,errno,json,os,resource,sys\n"
                    "try: os.fstat(int(sys.argv[1]))\n"
                    "except OSError as error: assert error.errno == errno.EBADF\n"
                    "else: raise AssertionError('Inherited descriptor survived')\n"
                    "assert resource.getrlimit(resource.RLIMIT_CORE) == (0,0)\n"
                    "assert ctypes.CDLL(None).prctl(39,0,0,0,0) == 1\n"
                    "print(json.dumps(sys.argv[2:]))\n"
                )
                args = [
                    str(GUARD),
                    "run",
                    "--",
                    sys.executable,
                    "-I",
                    "-c",
                    code,
                    str(inherited),
                    "with spaces",
                    "$(literal)",
                    "-option",
                ]
                fallback = [
                    sys.executable,
                    "-I",
                    str(Path(__file__).resolve()),
                    "--without-close-range",
                ]
                for prefix in ([], fallback):
                    with self.subTest(close_range=not prefix):
                        result = subprocess.run(
                            prefix + args,
                            pass_fds=(inherited,),
                            capture_output=True,
                            text=True,
                            timeout=15,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(
                            json.loads(result.stdout),
                            ["with spaces", "$(literal)", "-option"],
                        )
            finally:
                os.close(inherited)

    def test_argument_validation(self):
        for arguments in ([], ["filter", "extra"], ["run"], ["run", "--"]):
            result = subprocess.run(
                [str(GUARD), *arguments], capture_output=True, timeout=5
            )
            self.assertEqual(result.returncode, 2)
        result = subprocess.run(
            [str(GUARD), "run", "--", "/missing-airlock-command"],
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 1)

    def test_bwrap_offline_boundary(self):
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            self.skipTest("Bubblewrap is not installed in the build environment")
        probe = subprocess.run(
            [
                bwrap,
                "--unshare-all",
                "--die-with-parent",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "/usr/bin/true",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if probe.returncode:
            self.skipTest(
                "Build environment cannot create the sandbox: "
                + probe.stderr.strip()[-200:]
            )
        server = socket.socket(socket.AF_UNIX)
        address = "\0ph4ntxm-app-airlock-check-%d" % os.getpid()
        try:
            server.bind(address)
            server.listen()
            descriptor = os.memfd_create("ph4ntxm-app-airlock-filter", os.MFD_CLOEXEC)
            try:
                os.write(descriptor, self.filter)
                os.lseek(descriptor, 0, os.SEEK_SET)
                code = (
                    "import errno,os,socket,sys\n"
                    "assert not os.listdir('/proc')\n"
                    "assert not os.path.exists('/run/user')\n"
                    "assert not os.path.exists('/dev/dri')\n"
                    "for family in (socket.AF_INET,socket.AF_INET6,socket.AF_NETLINK):\n"
                    " try: socket.socket(family,socket.SOCK_DGRAM)\n"
                    " except PermissionError: pass\n"
                    " else: raise AssertionError('External socket allowed')\n"
                    "client=socket.socket(socket.AF_UNIX)\n"
                    "try: client.connect(bytes.fromhex(sys.argv[1]))\n"
                    "except OSError as error: assert error.errno == errno.ECONNREFUSED\n"
                    "else: raise AssertionError('Host abstract socket reached')\n"
                    "a,b=socket.socketpair()\n"
                    "a.send(b'ok')\n"
                    "assert b.recv(2)==b'ok'\n"
                    "print('Offline namespace boundary passed')\n"
                )
                args = [
                    bwrap,
                    "--unshare-all",
                    "--die-with-parent",
                    "--new-session",
                    "--cap-drop",
                    "ALL",
                    "--clearenv",
                    "--ro-bind",
                    "/usr",
                    "/usr",
                    "--symlink",
                    "usr/bin",
                    "/bin",
                    "--symlink",
                    "usr/lib",
                    "/lib",
                    "--symlink",
                    "usr/lib64",
                    "/lib64",
                    "--dir",
                    "/proc",
                    "--dev",
                    "/dev",
                    "--tmpfs",
                    "/tmp",
                    "--tmpfs",
                    "/run",
                    "--tmpfs",
                    "/home/airlock",
                    "--dir",
                    "/etc",
                    "--chdir",
                    "/home/airlock",
                    "--setenv",
                    "PATH",
                    "/usr/bin:/bin",
                    "--setenv",
                    "HOME",
                    "/home/airlock",
                    "--ro-bind",
                    str(GUARD),
                    "/guard",
                    "--seccomp",
                    str(descriptor),
                    "/guard",
                    "run",
                    "--",
                    "/usr/bin/python3",
                    "-I",
                    "-c",
                    code,
                    address.encode().hex(),
                ]
                result = subprocess.run(
                    args,
                    pass_fds=(descriptor,),
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Offline namespace boundary passed", result.stdout)
            finally:
                os.close(descriptor)
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
