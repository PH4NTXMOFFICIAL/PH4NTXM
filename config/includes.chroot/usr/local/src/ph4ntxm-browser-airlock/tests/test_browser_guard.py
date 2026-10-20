#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import base64
import ctypes
import errno
import json
import os
from pathlib import Path
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


class FilterProgram(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.c_void_p)]


def apply_filter(data):
    buffer = ctypes.create_string_buffer(data)
    program = FilterProgram(len(data) // 8, ctypes.cast(buffer, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), "Could not install the browser syscall filter")
    return libc


def bpf_result(data, number, args=(), arch=0xC000003E):
    context = struct.pack("=iI7Q", number, arch, 0, *(tuple(args) + (0,) * (6 - len(args))))
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
    raise AssertionError("The browser filter did not return")


def syscall_probe(data):
    libc = apply_filter(data)
    for family in (socket.AF_NETLINK, socket.AF_PACKET):
        try:
            socket.socket(family, socket.SOCK_DGRAM)
        except PermissionError:
            pass
        else:
            raise AssertionError("An administrative socket family was allowed")
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
        left, right = socket.socketpair(socket.AF_UNIX, kind)
        left.send(b"browser")
        assert right.recv(7) == b"browser"
        left.close()
        right.close()
    for call, args in ((101, (0, 0, 0, 0)), (308, (-1, 0)), (321, (0, 0, 0)), (425, (0, 0)), (438, (-1, 0, 0)), (16, (-1, 0x5412, 0))):
        ctypes.set_errno(0)
        assert libc.syscall(call, *args) == -1
        assert ctypes.get_errno() == errno.EPERM, (call, ctypes.get_errno())
    ctypes.set_errno(0)
    assert libc.syscall(435, 0, 0) == -1
    assert ctypes.get_errno() == errno.ENOSYS
    completed = []
    child = threading.Thread(target=lambda: completed.append(True))
    child.start()
    child.join()
    assert completed == [True]
    assert subprocess.run(["/usr/bin/true"]).returncode == 0


if len(sys.argv) >= 3 and sys.argv[1] == "--syscalls":
    syscall_probe(base64.b64decode(sys.argv[2]))
    raise SystemExit(0)

if len(sys.argv) >= 3 and sys.argv[1] == "--without-landlock":
    data = b"".join(struct.pack("=HBBI", *instruction) for instruction in (
        (0x20, 0, 0, 0), (0x15, 0, 1, 444),
        (0x06, 0, 0, 0x50000 | errno.ENOSYS), (0x06, 0, 0, 0x7FFF0000),
    ))
    apply_filter(data)
    os.execv(sys.argv[2], sys.argv[2:])

if len(sys.argv) >= 4 and sys.argv[1] == "--landlock-child":
    abstract, pathname = sys.argv[2:4]
    client = socket.socket(socket.AF_UNIX)
    try:
        client.connect(bytes.fromhex(abstract))
    except PermissionError:
        pass
    else:
        raise AssertionError("The host abstract socket was reached")
    client.close()
    client = socket.socket(socket.AF_UNIX)
    client.connect(pathname)
    client.close()
    raise SystemExit(0)

GUARD = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "guard"


class BrowserGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.online = subprocess.check_output([str(GUARD), "filter"])
        cls.offline = subprocess.check_output([str(GUARD), "offline-filter"])
        cls.abi = ctypes.CDLL(None).syscall(444, 0, 0, 1)

    def test_filter_architecture_and_administrative_syscalls(self):
        for data in (self.online, self.offline):
            self.assertTrue(data)
            self.assertEqual(len(data) % 8, 0)
            self.assertLessEqual(len(data), 32768)
            for arch in (0x40000003, 0xC00000B7, 0):
                self.assertEqual(bpf_result(data, 39, arch=arch), 0x80000000)
            self.assertEqual(bpf_result(data, 0x40000027), 0x80000000)
            for call in (101, 165, 166, 308, 310, 311, 321, 425, 438):
                self.assertEqual(bpf_result(data, call), 0x50001)
            self.assertEqual(bpf_result(data, 435), 0x50000 | errno.ENOSYS)

    def test_firefox_child_sandbox_namespaces_and_chroot_remain_available(self):
        for flags in (0x10000000, 0x10000000 | 0x40000000, 0x10000000 | 0x08000000 | 0x40000000):
            self.assertEqual(bpf_result(self.online, 56, args=(flags,)), 0x7FFF0000)
            self.assertEqual(bpf_result(self.online, 272, args=(flags,)), 0x7FFF0000)
        self.assertEqual(bpf_result(self.online, 161), 0x7FFF0000)
        self.assertEqual(bpf_result(self.online, 317), 0x7FFF0000)

    def test_socket_families_and_types(self):
        for family in (socket.AF_UNIX, socket.AF_INET, socket.AF_INET6):
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
                self.assertEqual(bpf_result(self.online, 41, (family, kind | socket.SOCK_CLOEXEC)), 0x7FFF0000)
        for family in (socket.AF_NETLINK, socket.AF_PACKET):
            self.assertEqual(bpf_result(self.online, 41, (family, socket.SOCK_DGRAM)), 0x50001)
        for family in (socket.AF_INET, socket.AF_INET6, socket.AF_NETLINK, socket.AF_PACKET):
            self.assertEqual(bpf_result(self.offline, 41, (family, socket.SOCK_STREAM)), 0x50001)
        for data in (self.online, self.offline):
            self.assertEqual(bpf_result(data, 41, (socket.AF_UNIX, socket.SOCK_RAW)), 0x50001)
            self.assertEqual(bpf_result(data, 53, (socket.AF_INET, socket.SOCK_STREAM)), 0x50001)
            self.assertEqual(bpf_result(data, 53, (socket.AF_UNIX, socket.SOCK_STREAM)), 0x7FFF0000)

    def test_runtime_filter_and_threads(self):
        result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--syscalls", base64.b64encode(self.online).decode()], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsupported_landlock_fails_closed(self):
        result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--without-landlock", str(GUARD), "run", "--", "/usr/bin/true"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires Landlock ABI 6", result.stderr)

    def test_landlock_blocks_abstract_sockets_and_is_inherited(self):
        if self.abi < 6:
            self.skipTest("Build kernel has no Landlock ABI 6")
        with tempfile.TemporaryDirectory(prefix="browser-guard-review-") as directory:
            abstract = "\0ph4ntxm-browser-guard-%d" % os.getpid()
            pathname = str(Path(directory) / "display")
            with socket.socket(socket.AF_UNIX) as outside, socket.socket(socket.AF_UNIX) as named, socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as datagram:
                outside.bind(abstract)
                outside.listen(4)
                datagram.bind(abstract + "-datagram")
                named.bind(pathname)
                named.listen(4)
                code = (
                    "import os,socket,subprocess,sys\n"
                    "address=bytes.fromhex(sys.argv[1])\n"
                    "client=socket.socket(socket.AF_UNIX)\n"
                    "try: client.connect(address)\n"
                    "except PermissionError: pass\n"
                    "else: raise AssertionError('Host abstract stream reached')\n"
                    "client.close()\n"
                    "client=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)\n"
                    "try: client.sendto(b'blocked',bytes.fromhex(sys.argv[4]))\n"
                    "except PermissionError: pass\n"
                    "else: raise AssertionError('Host abstract datagram reached')\n"
                    "client.close()\n"
                    "try: os.kill(int(sys.argv[5]),18)\n"
                    "except PermissionError: pass\n"
                    "else: raise AssertionError('Host signal scope escaped')\n"
                    "inside=socket.socket(socket.AF_UNIX)\n"
                    "internal=b'\\0browser-guard-internal-'+str(os.getpid()).encode()\n"
                    "inside.bind(internal); inside.listen()\n"
                    "client=socket.socket(socket.AF_UNIX); client.connect(internal); client.close()\n"
                    "child=subprocess.run([sys.executable,'-I',sys.argv[3],'--landlock-child',sys.argv[1],sys.argv[2]])\n"
                    "assert child.returncode==0\n"
                )
                result = subprocess.run([str(GUARD), "run", "--", sys.executable, "-I", "-c", code, abstract.encode().hex(), pathname, str(Path(__file__).resolve()), (abstract + "-datagram").encode().hex(), str(os.getpid())], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_run_closes_descriptors_and_disables_core_dumps(self):
        if self.abi < 6:
            self.skipTest("Build kernel has no Landlock ABI 6")
        with tempfile.TemporaryFile() as stream:
            code = (
                "import ctypes,errno,os,resource,sys\n"
                "try: os.fstat(int(sys.argv[1]))\n"
                "except OSError as error: assert error.errno==errno.EBADF\n"
                "else: raise AssertionError('Inherited descriptor survived')\n"
                "assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)\n"
                "assert ctypes.CDLL(None).prctl(39,0,0,0,0)==1\n"
                "assert sys.argv[2]=='$(literal)'\n"
            )
            result = subprocess.run([str(GUARD), "run", "--", sys.executable, "-I", "-c", code, str(stream.fileno()), "$(literal)"], pass_fds=(stream.fileno(),), capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_bwrap_keeps_host_network_but_isolates_processes_and_home(self):
        if self.abi < 6:
            self.skipTest("Build kernel has no Landlock ABI 6")
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            self.skipTest("Bubblewrap is unavailable in the build environment")
        prefix = [bwrap, "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run", "--dir", "/etc", "--tmpfs", "/home/private", "--ro-bind", str(GUARD), "/guard"]
        probe = subprocess.run(prefix + ["/usr/bin/true"], capture_output=True, text=True, timeout=10)
        if probe.returncode:
            self.skipTest("Build environment cannot create namespaces: " + probe.stderr.strip()[-200:])
        descriptor = os.memfd_create("browser-guard-review", os.MFD_CLOEXEC)
        try:
            os.write(descriptor, self.online)
            os.lseek(descriptor, 0, os.SEEK_SET)
            code = (
                "import os,sys\n"
                "assert os.readlink('/proc/self/ns/net')==sys.argv[1]\n"
                "assert os.readlink('/proc/self/ns/user')!=sys.argv[2]\n"
                "assert os.uname().nodename==sys.argv[3]\n"
                "assert len([name for name in os.listdir('/proc') if name.isdigit()])<=4\n"
                "assert not os.path.exists('/run/user')\n"
                "assert not os.path.exists('/etc/shadow')\n"
                "assert not os.path.exists('/dev/dri')\n"
                "assert not os.path.exists('/tmp/.X11-unix')\n"
            )
            result = subprocess.run(prefix + ["--seccomp", str(descriptor), "/guard", "run", "--", "/usr/bin/python3", "-I", "-c", code, os.readlink("/proc/self/ns/net"), os.readlink("/proc/self/ns/user"), os.uname().nodename], pass_fds=(descriptor,), capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main(verbosity=2)
