#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
from contextlib import contextmanager
import fcntl
import errno
import json
import os
import select
import resource
from pathlib import Path
import signal
import struct
import socket
import subprocess
import sys
import tempfile
import time

SOURCE = Path(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else Path(__file__).resolve().parents[1] / "bootstrap.c"


def sealed_filter(sealed=True):
    fd = os.memfd_create("airlock-filter", os.MFD_ALLOW_SEALING)
    os.write(fd, struct.pack("HBBI", 0x06, 0, 0, 0x7fff0000))
    os.lseek(fd, 0, os.SEEK_SET)
    if sealed:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    return fd


@contextmanager
def native_root(libc):
    with tempfile.TemporaryDirectory(prefix="airlock-bootstrap-") as temporary:
        target = os.fsencode(temporary)
        if libc.mount(b"tmpfs", target, b"tmpfs", 4, b"size=67108864,mode=0755"):
            raise OSError(ctypes.get_errno(), "private suid-enabled runtime required")
        try:
            yield temporary
        finally:
            if libc.umount2(target, 2):
                raise OSError(ctypes.get_errno(), "private runtime unmount failed")


def main():
    with tempfile.TemporaryDirectory(prefix="airlock-bootstrap-compile-") as temporary:
        binary = Path(temporary) / "bootstrap"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic", str(SOURCE), "-o", str(binary)], check=True)
        assert subprocess.run([str(binary), "3", "--version"], check=False, capture_output=True).returncode == 125
    print("PASS: compilation and caller privilege validation.")
    if os.geteuid() != 0:
        print("SKIP: native bootstrap fixture requires root.")
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x00020000):
        error = ctypes.get_errno()
        if error in (errno.EPERM, errno.ENOSYS):
            print("SKIP: native bootstrap fixture requires mount namespace capability.")
            return
        raise OSError(error, "private mount namespace required")
    if libc.mount(None, b"/", None, 0x4000 | (1 << 18), None):
        error = ctypes.get_errno()
        mountpoints = [line.split()[4] for line in Path("/proc/self/mountinfo").read_bytes().splitlines()]
        if error == errno.EINVAL and b"/" not in mountpoints:
            print("SKIP: native bootstrap fixture requires a mount point at /, unavailable in this build chroot.")
            return
        raise OSError(error, "private mount propagation required")
    with native_root(libc) as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        state = root / "state"
        state.mkdir(mode=0o755)
        (state / "mode").write_text("linux\n")
        fake = state / "fake_cpuinfo"
        fake.write_text("PH4NTXM-BOOTSTRAP-CPU\n")
        fake.chmod(0o644)
        if libc.mount(os.fsencode(fake), b"/proc/cpuinfo", None, 4096, None):
            raise OSError(ctypes.get_errno(), "fixture cpuinfo bind")
        wrapper = root / "bwrap"
        wrapper.write_text("""#!/bin/sh
if [ -e /proc/self/fd/128 ]; then exit 124; fi
/usr/bin/python3 -I -c 'import os, stat, fcntl; info = os.fstat(2); flags = fcntl.fcntl(2, fcntl.F_GETFL); assert (stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3)) or (stat.S_ISFIFO(info.st_mode) and flags & os.O_ACCMODE == os.O_WRONLY)' || exit 123
exec /usr/bin/bwrap "$@" 2>"%s/output/bwrap.stderr"
""" % root)
        wrapper.chmod(0o755)
        binary = root / "bootstrap"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-DAIRLOCK_UID=65534", '-DAIRLOCK_STATE="%s"' % state, '-DAIRLOCK_BWRAP="%s"' % wrapper, str(SOURCE), "-o", str(binary)], check=True)
        binary.chmod(0o4755)
        output = root / "output"
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        probe = root / "probe.py"
        probe.write_text('''import ctypes, errno, json, os, pathlib, time
status = pathlib.Path("/proc/self/status").read_text()
try:
    os.setuid(0)
    recover = True
except OSError as error:
    if error.errno not in (errno.EPERM, errno.EINVAL):
        raise
    recover = False
fds = []
for name in os.listdir("/proc/self/fd"):
    try:
        os.fstat(int(name))
        fds.append(int(name))
    except OSError:
        pass
nested_reader, nested_writer = os.pipe()
nested = os.fork()
if nested == 0:
    os.close(nested_reader)
    result = {}
    try:
        old_user = os.readlink("/proc/self/ns/user")
        old_net = os.readlink("/proc/self/ns/net")
        uid, gid = os.getuid(), os.getgid()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.unshare(0x10000000):
            raise OSError(ctypes.get_errno(), "native child user namespace")
        pathlib.Path("/proc/self/setgroups").write_text("deny")
        pathlib.Path("/proc/self/uid_map").write_text("%d %d 1" % (uid, uid))
        pathlib.Path("/proc/self/gid_map").write_text("%d %d 1" % (gid, gid))
        result["mapped"] = os.getuid() == uid and os.getgid() == gid and uid != 0
        result["user_changed"] = os.readlink("/proc/self/ns/user") != old_user
        if libc.unshare(0x40000000):
            error = ctypes.get_errno()
            if error not in (errno.EPERM, errno.EACCES):
                raise OSError(error, "native child network namespace")
            result["network"] = "restricted"
        else:
            result["network"] = os.readlink("/proc/self/ns/net") != old_net
        result["cpu_readonly"] = False
        try:
            descriptor = os.open("/proc/cpuinfo", os.O_WRONLY)
        except OSError as error:
            result["cpu_readonly"] = error.errno in (errno.EROFS, errno.EPERM, errno.EACCES)
        else:
            os.close(descriptor)
        result["cpu_readonly_mount"] = any(line.split()[4] == "/proc/cpuinfo" and "ro" in line.split()[5].split(",") for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines())
    except OSError as error:
        result["error"] = "%s: errno %d" % (error.strerror, error.errno)
    os.write(nested_writer, json.dumps(result).encode())
    os._exit(0)
os.close(nested_writer)
nested_result = json.loads(os.read(nested_reader, 4096))
os.close(nested_reader)
os.waitpid(nested, 0)
own_root = os.stat("/")
host_roots = []
for pid in [name for name in os.listdir("/proc") if name.isdigit()]:
    try:
        root = os.open("/proc/%s/root" % pid, os.O_PATH | os.O_DIRECTORY)
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        continue
    info = os.fstat(root)
    if (info.st_dev, info.st_ino) != (own_root.st_dev, own_root.st_ino):
        host_roots.append(pid)
    os.close(root)
orphan_reaped = None
if pathlib.Path("/out/orphan").exists():
    reader, writer = os.pipe()
    first = os.fork()
    if first == 0:
        os.close(reader)
        second = os.fork()
        if second == 0:
            os.write(writer, str(os.getpid()).encode())
        os._exit(0)
    os.close(writer)
    orphan = int(os.read(reader, 32))
    os.close(reader)
    os.waitpid(first, 0)
    deadline = time.monotonic() + 3
    while pathlib.Path("/proc/%d" % orphan).exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    orphan_reaped = not pathlib.Path("/proc/%d" % orphan).exists()
result = {"nested": nested_result, "orphan_reaped": orphan_reaped, "host_roots": host_roots, "uid_map": pathlib.Path("/proc/self/uid_map").read_text(), "cpu": pathlib.Path("/proc/cpuinfo").read_text(), "pids": [p for p in os.listdir("/proc") if p.isdigit()], "status": status, "recover": recover, "fds": fds}
pathlib.Path("/out/result.json").write_text(json.dumps(result))
if pathlib.Path("/out/sleep").exists():
    time.sleep(60)
''')
        def demote(lower_limit):
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            if lower_limit:
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        def launch(sealed=True, extra=(), payload=None, lower_limit=True, stderr=None):
            fd = sealed_filter(sealed)
            original = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY)
            leak = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 128)
            os.close(original)
            args = [str(binary), str(fd), "--unshare-user", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--bind", "/proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run", "--setenv", "HOME", "/out/home", "--bind", str(output), "/out", "--ro-bind", str(probe), "/probe.py", "--seccomp", str(fd), *extra, *(payload or ["/usr/bin/python3", "-I", "/probe.py"])]
            try:
                return subprocess.Popen(args, pass_fds=(fd, leak), preexec_fn=lambda: demote(lower_limit), stderr=stderr)
            finally:
                os.close(fd)
                os.close(leak)
        assert Path("/proc/cpuinfo").read_text() == "PH4NTXM-BOOTSTRAP-CPU\n"
        process = launch()
        code = process.wait(timeout=15)
        assert code == 0, "native bootstrap first launch exited %d: %s" % (code, (output / "bwrap.stderr").read_text() if (output / "bwrap.stderr").exists() else "bwrap was not reached")
        result = json.loads((output / "result.json").read_text())
        assert result["cpu"] == "PH4NTXM-BOOTSTRAP-CPU\n"
        assert len(result["pids"]) <= 5, result
        assert "error" not in result["nested"], result["nested"]
        assert result["nested"]["mapped"] and result["nested"]["user_changed"], result["nested"]
        assert result["nested"]["network"] is True or result["nested"]["network"] == "restricted", result["nested"]
        assert result["nested"]["cpu_readonly"] and result["nested"]["cpu_readonly_mount"], result["nested"]
        assert len(result["uid_map"].splitlines()) == 1 and result["uid_map"].split()[-1] == "1", result
        assert not result["recover"] and not result["host_roots"] and max(result["fds"]) <= 2, result
        assert "NoNewPrivs:\t1" in result["status"] and "CapEff:\t0000000000000000" in result["status"], result
        invalid = launch(sealed=False, stderr=subprocess.PIPE)
        _, diagnostic = invalid.communicate(timeout=10)
        assert invalid.returncode == 125 and b"Browser Airlock bootstrap: descriptor isolation failed (errno " in diagnostic
        assert os.fsencode(root) not in diagnostic
        directory = os.open("/", os.O_PATH | os.O_DIRECTORY)
        try:
            assert launch(stderr=directory).wait(timeout=10) == 0
        finally:
            os.close(directory)
        endpoint, peer = socket.socketpair()
        with endpoint, peer:
            assert launch(stderr=endpoint).wait(timeout=10) == 0
        with (output / "unsafe-stderr").open("wb") as regular:
            assert launch(stderr=regular).wait(timeout=10) == 0
        fifo = output / "unsafe-fifo"
        os.mkfifo(fifo, 0o600)
        readwrite = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        try:
            assert launch(stderr=readwrite).wait(timeout=10) == 0
        finally:
            os.close(readwrite)

        (state / "mode").write_text("invalid\n")
        assert launch(stderr=subprocess.DEVNULL).wait(timeout=10) == 125
        (state / "mode").write_text("linux\n")
        fake.chmod(0o666)
        assert launch(stderr=subprocess.DEVNULL).wait(timeout=10) == 125
        fake.chmod(0o644)
        backup = state / "original_cpuinfo"
        fake.rename(backup)
        fake.symlink_to(backup)
        assert launch(stderr=subprocess.DEVNULL).wait(timeout=10) == 125
        fake.unlink()
        backup.rename(fake)
        (output / "result.json").unlink()
        (output / "sleep").touch()
        (output / "orphan").touch()
        process = launch()
        deadline = time.monotonic() + 10
        while not (output / "result.json").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert (output / "result.json").exists()
        assert process.poll() is None
        assert json.loads((output / "result.json").read_text())["orphan_reaped"], "PID1 did not reap adopted orphan while payload remained alive"
        def descendants(pid):
            children = Path("/proc/%d/task/%d/children" % (pid, pid)).read_text().split()
            return [int(child) for child in children] + [nested for child in children for nested in descendants(int(child))]
        descendants_fds = [os.pidfd_open(pid) for pid in descendants(process.pid)]
        assert descendants_fds
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=5) == 128 + signal.SIGTERM
        for fd in descendants_fds:
            assert select.select([fd], [], [], 5)[0], "descendant survived supervisor termination"
            os.close(fd)
        (output / "result.json").unlink()
        process = launch()
        deadline = time.monotonic() + 10
        while not (output / "result.json").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert (output / "result.json").exists()
        descendants_fds = [os.pidfd_open(pid) for pid in descendants(process.pid)]
        process.kill()
        assert process.wait(timeout=5) == -signal.SIGKILL
        for fd in descendants_fds:
            assert select.select([fd], [], [], 5)[0], "descendant survived parent death"
            os.close(fd)
        (output / "sleep").unlink()
        (output / "orphan").unlink()
        (state / "mode").write_text("lonewolf\n")
        fake.unlink()
        assert launch().wait(timeout=10) == 0
        if "--firefox" in sys.argv:
            (state / "mode").write_text("linux\n")
            fake.write_text("PH4NTXM-BOOTSTRAP-CPU\n")
            fake.chmod(0o644)
            profile = output / "firefox-profile"
            profile.mkdir(mode=0o777)
            profile.chmod(0o777)
            firefox = "/usr/lib/firefox-esr/firefox-esr"
            assert Path(firefox).is_file()
            process = launch(lower_limit=False, payload=[firefox, "--headless", "--no-remote", "--profile", "/out/firefox-profile", "--screenshot", "/out/firefox.png", "data:text/html,<html><body>Airlock native test</body></html>"])
            assert process.wait(timeout=45) == 0, "native Firefox failed"
            assert (output / "firefox.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
            print("PASS: actual Firefox headless content rendering through native bootstrap.")
        print("PASS: native masked proc, PID/user namespace, UID/capabilities, descriptor isolation, invalid input, termination, adopted orphans, nested browser namespaces, LoneWolf.")


if __name__ == "__main__":
    main()
