import errno
import json
import os
import secrets
import stat
import string
import tempfile

MARK_FILE = "/dev/shm/ph4-shred-marked.json"
LOCK_FILE = "/dev/shm/ph4-shred.lock"
MAX_PASSES = 7
DEFAULT_PASSES = 3
BLOCK_SIZE = 1024 * 1024


def _normalize(path):
    return os.path.normpath(os.path.abspath(os.path.expanduser(path)))


def _load_marks():
    try:
        with open(MARK_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, str)]


def _save_marks(files):
    directory = os.path.dirname(MARK_FILE)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=directory,
            prefix=".ph4-shred-marks.",
            delete=False,
        ) as handle:
            temp_path = handle.name
            os.fchmod(handle.fileno(), 0o600)
            json.dump(files, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, MARK_FILE)
        return True
    except OSError:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        return False


def mark(file_path):
    file_path = _normalize(file_path)
    if (
        not os.path.lexists(file_path)
        or file_path == "/"
        or file_path in (MARK_FILE, LOCK_FILE)
    ):
        return False

    files = _load_marks()
    if file_path in files:
        return False
    files.append(file_path)
    return _save_marks(files)


def unmark(file_path):
    file_path = _normalize(file_path)
    files = _load_marks()
    if file_path not in files:
        return False
    files.remove(file_path)
    return _save_marks(files)


def unmark_all():
    return _save_marks([])


def list_marks():
    return _load_marks()


def _random_name(length=16):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _write_repeated(handle, size, byte):
    chunk = byte * BLOCK_SIZE
    remaining = size
    while remaining:
        write_size = min(BLOCK_SIZE, remaining)
        written = handle.write(chunk[:write_size])
        if written != write_size:
            raise OSError("short write during overwrite")
        remaining -= written


def _write_random(handle, size):
    remaining = size
    while remaining:
        chunk = os.urandom(min(BLOCK_SIZE, remaining))
        written = handle.write(chunk)
        if written != len(chunk):
            raise OSError("short write during random overwrite")
        remaining -= written


def _overwrite_file(path, passes, callback=None):
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "r+b", buffering=0) as handle:
        identity = os.fstat(handle.fileno())
        if not stat.S_ISREG(identity.st_mode):
            raise ValueError("overwrite target is not a regular file")
        size = identity.st_size
        for pass_index in range(passes):
            handle.seek(0)
            if pass_index == 0:
                _write_repeated(handle, size, b"\x00")
            elif pass_index == 1:
                _write_repeated(handle, size, b"\xff")
            else:
                _write_random(handle, size)
            handle.flush()
            os.fsync(handle.fileno())
            if callback:
                callback(path, int(((pass_index + 1) / passes) * 100))
    return identity.st_dev, identity.st_ino


def _path_matches(path, identity):
    try:
        current = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(current.st_mode)
        and (current.st_dev, current.st_ino) == identity
    )


def _sync_parent(path):
    try:
        directory_fd = os.open(
            os.path.dirname(path) or ".",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def _shred_item(path, passes, callback=None):
    if os.path.islink(path):
        os.unlink(path)
        _sync_parent(path)
        return
    if not os.path.isfile(path):
        raise ValueError("target is not a regular file")

    identity = _overwrite_file(path, passes, callback)

    if not _path_matches(path, identity):
        raise OSError("target identity changed after overwrite; deletion cancelled")

    current_path = path
    renamed = False
    for _ in range(3):
        for _attempt in range(16):
            candidate = os.path.join(
                os.path.dirname(current_path),
                _random_name(),
            )
            if os.path.lexists(candidate):
                continue
            try:
                if not _path_matches(current_path, identity):
                    raise OSError("target identity changed before rename")
                os.rename(current_path, candidate)
                current_path = candidate
                renamed = True
            except OSError:
                pass
            break

    if not renamed:
        raise OSError("could not move target to a private deletion name")

    try:
        if not _path_matches(current_path, identity):
            raise OSError("target identity changed before deletion")
        descriptor = os.open(
            current_path,
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        )
        with os.fdopen(descriptor, "r+b", buffering=0) as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != identity:
                raise OSError("target identity changed while opening for deletion")
            handle.truncate(0)
            handle.flush()
            os.fsync(handle.fileno())
        os.unlink(current_path)
        _sync_parent(current_path)
    except OSError as exc:
        if current_path != path and not os.path.lexists(path):
            try:
                os.rename(current_path, path)
                current_path = path
            except OSError:
                pass
        raise OSError(f"final deletion failed for {current_path}: {exc}") from exc


def _shred_directory(path, passes, callback=None):
    failures = []
    for root, directories, filenames in os.walk(
        path,
        topdown=False,
        followlinks=False,
    ):
        for name in filenames:
            child = os.path.join(root, name)
            try:
                _shred_item(child, passes, callback)
            except Exception as exc:
                failures.append(f"{child}: {exc}")

        for name in directories:
            child = os.path.join(root, name)
            try:
                if os.path.islink(child):
                    os.unlink(child)
                else:
                    os.rmdir(child)
            except OSError as exc:
                failures.append(f"{child}: {exc}")

    if failures:
        preview = "; ".join(failures[:3])
        if len(failures) > 3:
            preview += f"; and {len(failures) - 3} more"
        raise OSError(f"directory only partially shredded: {preview}")

    os.rmdir(path)
    _sync_parent(path)


def _lock_owner_alive():
    try:
        with open(LOCK_FILE, "r", encoding="ascii") as handle:
            pid = int(handle.read().strip())
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ValueError, ProcessLookupError):
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _acquire_lock():
    for _ in range(2):
        try:
            descriptor = os.open(
                LOCK_FILE,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.write(descriptor, str(os.getpid()).encode("ascii"))
            os.fsync(descriptor)
            return descriptor
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            if _lock_owner_alive():
                return None
            try:
                os.unlink(LOCK_FILE)
            except OSError:
                return None
    return None


def shred_all(passes=DEFAULT_PASSES, progress_callback=None):
    passes = max(1, min(MAX_PASSES, int(passes)))
    descriptor = _acquire_lock()
    if descriptor is None:
        return [("error", "System", "Another shred process is running")]

    try:
        files = _load_marks()
        results = []
        for path in list(files):
            try:
                if not os.path.lexists(path):
                    results.append(("missing", path))
                elif os.path.islink(path) or os.path.isfile(path):
                    _shred_item(path, passes, progress_callback)
                    results.append(("shredded", path))
                elif os.path.isdir(path):
                    _shred_directory(path, passes, progress_callback)
                    results.append(("shredded_dir", path))
                else:
                    raise ValueError("unsupported file type")
            except Exception as exc:
                results.append(("error", path, str(exc)))
                continue

            files.remove(path)
            if not _save_marks(files):
                results.append(("error", path, "could not update the mark queue"))
        return results
    finally:
        os.close(descriptor)
        try:
            with open(LOCK_FILE, "r", encoding="ascii") as handle:
                owned = handle.read().strip() == str(os.getpid())
            if owned:
                os.unlink(LOCK_FILE)
        except OSError:
            pass
