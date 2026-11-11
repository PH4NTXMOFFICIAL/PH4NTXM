# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import stat
import sys


def initialize_profile(profile, template=None):
    profile = Path(profile)
    if template is not None:
        template = Path(template)
        if template.is_symlink() or not template.is_dir():
            raise OSError("The bundled Tor Browser profile is unavailable")
        for path in template.rglob("*"):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise OSError("The bundled Tor Browser profile is unsafe")
        shutil.copytree(template, profile, copy_function=shutil.copyfile)
        profile.chmod(0o700)
        for path in profile.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
    directory = os.open(profile, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = ".content-prefs." + secrets.token_hex(16)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError("The browser zoom requires a private profile directory")
        try:
            info = os.stat("content-prefs.sqlite", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_nlink != 1:
                raise OSError("The browser content preferences database is unsafe")
            return
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        os.close(descriptor)
        connection = sqlite3.connect(f"/proc/self/fd/{directory}/{temporary}")
        try:
            connection.executescript("""
                CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
                CREATE TABLE settings (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
                CREATE TABLE prefs (
                    id INTEGER PRIMARY KEY,
                    groupID INTEGER REFERENCES groups(id),
                    settingID INTEGER NOT NULL REFERENCES settings(id),
                    value BLOB,
                    timestamp INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX groups_idx ON groups(name);
                CREATE INDEX settings_idx ON settings(name);
                CREATE INDEX prefs_idx ON prefs(timestamp, groupID, settingID);
                INSERT INTO settings (id, name) VALUES (1, 'browser.content.full-zoom');
                INSERT INTO prefs (groupID, settingID, value) VALUES (NULL, 1, 0.8);
                PRAGMA user_version = 6;
            """)
        finally:
            connection.close()
        os.link(temporary, "content-prefs.sqlite", src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("Expected a profile directory and optional Tor Browser template")
    initialize_profile(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)
