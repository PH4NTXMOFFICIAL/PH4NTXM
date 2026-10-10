#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from contextlib import contextmanager
from ctypes import c_int
import io
import json
import logging
from pathlib import Path
import struct
import sys
from zlib import crc32

from libarchive import ffi
from libarchive.entry import ArchiveEntry
from libarchive.exception import ArchiveError

from airlock import AirlockError, read_exact
from archive_protocol import (
    ACK_MAGIC,
    CHUNK_SIZE,
    DATA_MAGIC,
    END_MAGIC,
    ERROR_MAGIC,
    LIST_INDEX,
    LIST_MAGIC,
    MAX_ENTRIES,
    MAX_INPUT,
    MAX_METADATA,
    MAX_NAME,
    MAX_OUTPUT,
    safe_name,
)

FORMAT_LABELS = {0x30000: "TAR", 0x50000: "ZIP", 0xD0000: "RAR", 0xE0000: "7z", 0x100000: "RAR"}
FORMAT_READERS = ("zip", "rar", "rar5", "7zip", "tar")
FILTER_READERS = ("none", "gzip", "bzip2", "xz", "zstd")
ARCHIVE_PATH = Path("/tmp/job/archive")
archive_format = ffi.ffi("format", [ffi.c_archive_p], c_int)
entry_is_encrypted = ffi.ffi("entry_is_encrypted", [ffi.c_archive_entry_p], c_int)
logging.getLogger("libarchive").disabled = True


class ArchiveRejected(ValueError):
    pass


def read_rar_bytes(source, size):
    try:
        return read_exact(source, size)
    except AirlockError as error:
        raise ArchiveRejected("The RAR header is damaged or unsupported.") from error


def rar_vint(source, limit=10):
    value = 0
    encoded = bytearray()
    for offset in range(limit):
        byte = read_rar_bytes(source, 1)[0]
        encoded.append(byte)
        if offset == 9 and byte > 1:
            raise ArchiveRejected("The RAR header is damaged or unsupported.")
        value |= (byte & 0x7F) << (offset * 7)
        if byte < 0x80:
            return value, bytes(encoded)
    raise ArchiveRejected("The RAR header is damaged or unsupported.")


def validate_rar_volume(path, pointer, family):
    if any(ffi.filter_name(pointer, index) != b"none" for index in range(ffi.filter_count(pointer))):
        raise ArchiveRejected("Compressed wrappers around RAR archives are not supported.")
    signature, scan_limit = {
        0xD0000: (b"Rar!\x1a\x07\x00", 128 * 1024),
        0x100000: (b"Rar!\x1a\x07\x01\x00", 512 * 1024),
    }[family]
    with Path(path).open("rb") as source:
        prefix = source.read(8)
        if prefix.startswith(signature):
            offset = 0
        elif prefix.startswith((b"MZ", b"\x7fELF")):
            source.seek(0)
            prefix = source.read(scan_limit)
            offset = next((position for position in range(0, len(prefix) - len(signature) + 1, 16) if prefix[position : position + len(signature)] == signature), None)
            if offset is None:
                raise ArchiveRejected("The self-extracting RAR header could not be verified.")
        else:
            raise ArchiveRejected("The RAR header could not be verified.")
        source.seek(offset + len(signature))
        if family == 0xD0000:
            header = read_rar_bytes(source, 7)
            checksum, header_type, flags, size = struct.unpack("<HBHH", header)
            if header_type != 0x73 or size < 13:
                raise ArchiveRejected("The RAR header is damaged or unsupported.")
            header += read_rar_bytes(source, size - len(header))
            if crc32(header[2:]) & 0xFFFF != checksum:
                raise ArchiveRejected("The RAR header is damaged or unsupported.")
            multipart = bool(flags & 0x0001)
        else:
            checksum = struct.unpack("<I", read_rar_bytes(source, 4))[0]
            size, encoded_size = rar_vint(source, 3)
            if not 3 <= size < 2 * 1024 * 1024:
                raise ArchiveRejected("The RAR header is damaged or unsupported.")
            header = read_rar_bytes(source, size)
            if crc32(encoded_size + header) != checksum:
                raise ArchiveRejected("The RAR header is damaged or unsupported.")
            fields = io.BytesIO(header)
            header_type, _ = rar_vint(fields)
            header_flags, _ = rar_vint(fields)
            if header_type != 1 or header_flags & 0x001A:
                raise ArchiveRejected("The RAR header is damaged or unsupported.")
            extra_size = rar_vint(fields)[0] if header_flags & 0x0001 else 0
            if extra_size >= len(header) - fields.tell():
                raise ArchiveRejected("The RAR header is damaged or unsupported.")
            main_fields = io.BytesIO(header[fields.tell() : len(header) - extra_size])
            flags, _ = rar_vint(main_fields)
            multipart = bool(flags & 0x0003)
        if multipart:
            raise ArchiveRejected("Multipart RAR archives are not supported. Choose a single-volume archive.")


class ArchiveReader:
    def __init__(self, pointer, path):
        self.pointer = pointer
        self.path = path
        self.volume_checked = False

    def __iter__(self):
        while True:
            entry = ArchiveEntry(self.pointer)
            result = ffi.read_next_header2(self.pointer, entry._entry_p)
            if result not in (ffi.ARCHIVE_OK, ffi.ARCHIVE_EOF):
                raise ArchiveRejected("The archive is damaged or unsupported.")
            if not self.volume_checked:
                family = archive_format(self.pointer) & 0xFF0000
                if family in (0xD0000, 0x100000):
                    validate_rar_volume(self.path, self.pointer, family)
                self.volume_checked = True
            if result == ffi.ARCHIVE_EOF:
                return
            yield entry

    def format_label(self):
        family = archive_format(self.pointer) & 0xFF0000
        if family not in FORMAT_LABELS:
            raise ArchiveRejected("This archive format is not supported.")
        return FORMAT_LABELS[family]


@contextmanager
def archive_reader(path):
    pointer = ffi.read_new()
    try:
        for name in FORMAT_READERS:
            if ffi.get_read_format_function(name)(pointer) != ffi.ARCHIVE_OK:
                raise ArchiveRejected("The archive reader is unavailable.")
        for name in FILTER_READERS:
            if ffi.get_read_filter_function(name)(pointer) != ffi.ARCHIVE_OK:
                raise ArchiveRejected("The archive reader is unavailable.")
        if ffi.read_open_filename_w(pointer, str(path), CHUNK_SIZE) != ffi.ARCHIVE_OK:
            raise ArchiveRejected("The archive is damaged or unsupported.")
        yield ArchiveReader(pointer, path)
    finally:
        ffi.read_free(pointer)


def entry_record(entry, index):
    name = entry.pathname
    name_valid = isinstance(name, str) and len(name) <= MAX_NAME
    if name_valid:
        while name.startswith("./"):
            name = name[2:]
        try:
            name_valid = safe_name(name)
        except (UnicodeError, ValueError):
            name_valid = False
    size = entry.size
    if size is not None and (not isinstance(size, int) or size < 0):
        size = None
    record = {
        "index": index,
        "name": name if name_valid else "Blocked entry %d" % (index + 1),
        "size": size,
        "kind": "blocked",
        "reason": "",
    }
    if not name_valid:
        record["reason"] = "Unsafe or unreadable file name"
    elif entry_is_encrypted(entry._entry_p):
        record["reason"] = "Encrypted files are not supported"
    elif entry.islnk or entry.issym:
        record["reason"] = "Links are not opened"
    elif entry.isdir:
        record["kind"] = "directory"
    elif not entry.isreg:
        record["reason"] = "Special files are not opened"
    elif size is not None and size > MAX_OUTPUT:
        record["reason"] = "File exceeds the output limit"
    else:
        record["kind"] = "file"
    return record


def receive_source(incoming):
    size, index = struct.unpack("!II", read_exact(incoming, 8))
    if not 0 < size <= MAX_INPUT or (index != LIST_INDEX and index >= MAX_ENTRIES):
        raise ArchiveRejected("The archive request exceeds the supported limits.")
    with ARCHIVE_PATH.open("xb") as target:
        remaining = size
        while remaining:
            block = read_exact(incoming, min(CHUNK_SIZE, remaining))
            target.write(block)
            remaining -= len(block)
    return index


def list_archive(path):
    entries = []
    metadata_size = 0
    with archive_reader(path) as archive:
        for index, entry in enumerate(archive):
            if index >= MAX_ENTRIES:
                raise ArchiveRejected("The archive contains too many entries.")
            archive.format_label()
            record = entry_record(entry, index)
            metadata_size += len(json.dumps(record, ensure_ascii=False).encode("utf-8")) + 1
            if metadata_size > MAX_METADATA - 128:
                raise ArchiveRejected("The archive listing exceeds the supported limits.")
            entries.append(record)
        return {"format": archive.format_label(), "entries": entries}


class Response:
    def __init__(self, outgoing):
        self.outgoing = outgoing
        self.started = False

    def metadata(self, magic, value):
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_METADATA:
            raise ArchiveRejected("The archive listing exceeds the supported limits.")
        self.started = True
        self.outgoing.write(magic + struct.pack("!I", len(data)) + data)

    def extract(self, path, selection):
        with archive_reader(path) as archive:
            for index, entry in enumerate(archive):
                if index >= MAX_ENTRIES:
                    raise ArchiveRejected("The archive contains too many entries.")
                archive.format_label()
                if index != selection:
                    continue
                record = entry_record(entry, index)
                if record["kind"] != "file":
                    raise ArchiveRejected("The selected entry cannot be opened.")
                total = 0
                for block in entry.get_blocks(block_size=CHUNK_SIZE):
                    if not 0 < len(block) <= CHUNK_SIZE:
                        raise ArchiveRejected("The archive returned invalid file data.")
                    total += len(block)
                    if total > MAX_OUTPUT:
                        raise ArchiveRejected("The selected file exceeds the output limit.")
                    if not self.started:
                        self.started = True
                        self.outgoing.write(DATA_MAGIC)
                    self.outgoing.write(struct.pack("!I", len(block)) + block)
                    self.outgoing.flush()
                if not self.started:
                    self.started = True
                    self.outgoing.write(DATA_MAGIC)
                self.outgoing.write(struct.pack("!I", 0))
                return
        raise ArchiveRejected("The selected entry is no longer available.")

    def finish(self, incoming):
        self.outgoing.write(END_MAGIC)
        self.outgoing.flush()
        if read_exact(incoming, len(ACK_MAGIC)) != ACK_MAGIC:
            raise ValueError("Invalid host acknowledgement")


def main():
    incoming = sys.stdin.buffer
    response = Response(sys.stdout.buffer)
    try:
        selection = receive_source(incoming)
        if selection == LIST_INDEX:
            response.metadata(LIST_MAGIC, list_archive(ARCHIVE_PATH))
        else:
            response.extract(ARCHIVE_PATH, selection)
    except ArchiveRejected as error:
        if response.started:
            return
        response.metadata(ERROR_MAGIC, {"error": str(error)})
    except (ArchiveError, OSError, ValueError, UnicodeError, MemoryError, OverflowError):
        if response.started:
            return
        response.metadata(ERROR_MAGIC, {"error": "The archive is damaged, encrypted or unsupported."})
    response.finish(incoming)


if __name__ == "__main__":
    main()
