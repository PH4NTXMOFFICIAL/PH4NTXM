# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import math
import os
import select
import signal
import stat
import subprocess
import time

from clipboard_guard import GuardError


CLIPMAN_BINARY = "/usr/bin/xfce4-clipman"
STOP_TIMEOUT_SECONDS = 1.0
XFSETTINGS_BINARY = "/usr/bin/xfsettingsd"


def disable_xfce_clipboard(pid):
    if type(pid) is not int or not 1 <= pid <= 2147483647:
        raise GuardError("The clipboard manager process could not be verified.")
    uid = os.getuid()
    if uid == 0 or os.geteuid() != uid:
        raise GuardError("Clipboard Guard must run as the desktop user without elevated privileges.")
    binary_fd = None
    try:
        binary_fd = os.open(XFSETTINGS_BINARY, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
        binary = os.fstat(binary_fd)
        if not process_matches(pid, uid, binary):
            return 0
        if not stat.S_ISREG(binary.st_mode) or binary.st_uid != 0 or binary.st_mode & 0o022:
            raise GuardError("The installed Xfce settings daemon is not trusted.")
        environment = dict(os.environ)
        environment["XFSETTINGSD_NO_CLIPBOARD"] = "1"
        subprocess.run(
            [f"/proc/self/fd/{binary_fd}", "--replace", "--daemon"],
            env=environment, pass_fds=(binary_fd,), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=2, check=True,
        )
        return 1
    except (FileNotFoundError, ProcessLookupError):
        return 0
    except (OSError, subprocess.SubprocessError) as error:
        raise GuardError("The Xfce clipboard component could not be disabled safely.") from error
    finally:
        if binary_fd is not None:
            os.close(binary_fd)


def process_matches(pid, uid, binary):
    try:
        process = os.stat(f"/proc/{pid}", follow_symlinks=False)
        if not stat.S_ISDIR(process.st_mode) or process.st_uid != uid:
            return False
        executable = os.stat(f"/proc/{pid}/exe")
        return (
            stat.S_ISREG(executable.st_mode)
            and executable.st_dev == binary.st_dev
            and executable.st_ino == binary.st_ino
        )
    except (FileNotFoundError, ProcessLookupError):
        return False


def pause_clipman(pid):
    if type(pid) is not int or not 1 <= pid <= 2147483647:
        raise GuardError("The clipboard manager process could not be verified.")
    uid = os.getuid()
    if uid == 0 or os.geteuid() != uid:
        raise GuardError("Clipboard Guard must run as the desktop user without elevated privileges.")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise GuardError("Stopping Clipman safely requires Linux process handles. Close the manager manually.")
    binary_fd = None
    process_fd = None
    try:
        binary_fd = os.open(CLIPMAN_BINARY, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
        binary = os.fstat(binary_fd)
        if not stat.S_ISREG(binary.st_mode) or binary.st_uid != 0 or binary.st_mode & 0o022:
            raise GuardError("The installed Clipman executable is not trusted. Close the clipboard manager manually.")
        if not process_matches(pid, uid, binary):
            return 0
        try:
            process_fd = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            return 0
        if not process_matches(pid, uid, binary):
            return 0
        try:
            signal.pidfd_send_signal(process_fd, signal.SIGTERM, None, 0)
        except ProcessLookupError:
            return 0
        deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
        watcher = select.poll()
        watcher.register(process_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GuardError(
                    "Clipman did not stop within one second. "
                    "Close it manually before enabling protection."
                )
            timeout = max(0, math.floor(remaining * 1000))
            events = watcher.poll(timeout)
            for descriptor, flags in events:
                if descriptor != process_fd:
                    continue
                if flags & select.POLLNVAL:
                    raise GuardError("The clipboard manager process handle became unavailable.")
                if flags & (select.POLLIN | select.POLLHUP):
                    return 1
                if flags & select.POLLERR:
                    raise GuardError("The clipboard manager process could not be observed safely.")
            if timeout == 0:
                raise GuardError(
                    "Clipman did not stop within one second. "
                    "Close it manually before enabling protection."
                )
    except (FileNotFoundError, ProcessLookupError):
        return 0
    except OSError as error:
        raise GuardError("Clipman could not be stopped safely. Close the clipboard manager manually.") from error
    finally:
        if process_fd is not None:
            os.close(process_fd)
        if binary_fd is not None:
            os.close(binary_fd)
