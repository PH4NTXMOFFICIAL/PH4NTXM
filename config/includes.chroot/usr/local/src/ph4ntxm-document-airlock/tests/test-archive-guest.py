#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from contextlib import contextmanager
import gzip
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import warnings
from unittest.mock import patch
import zipfile
from zlib import crc32

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import archive_guest as archive
import archive_protocol as protocol
import guest
from airlock import ACK_MAGIC, END_MAGIC, INPUT_MAGIC, OUTPUT_MAGIC


class ArchiveGuestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def zip_archive(self, records):
        target = self.root / "source.zip"
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as writer:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                for name, data in records:
                    writer.writestr(name, data)
        return target

    def rar4_block(self, header_type, flags, payload=b""):
        body = struct.pack("<BHH", header_type, flags, 7 + len(payload)) + payload
        return struct.pack("<H", crc32(body) & 0xFFFF) + body

    def vint(self, value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)

    def rar5_block(self, body):
        value = self.vint(len(body)) + body
        return struct.pack("<I", crc32(value)) + value

    def rar_archive(self, version, flags):
        if version == 4:
            return b"Rar!\x1a\x07\x00" + self.rar4_block(0x73, flags, b"\0" * 6) + self.rar4_block(0x7B, 0)
        body = b"\x01\x00" + self.vint(flags)
        if flags & 2:
            body += b"\x01"
        return b"Rar!\x1a\x07\x01\x00" + self.rar5_block(body) + self.rar5_block(b"\x05\x04\x00")

    def unpack_response(self, data):
        source = io.BytesIO(data)
        self.assertEqual(source.read(8), protocol.DATA_MAGIC)
        output = bytearray()
        while True:
            size = struct.unpack("!I", source.read(4))[0]
            if not size:
                break
            self.assertLessEqual(size, protocol.CHUNK_SIZE)
            output.extend(source.read(size))
        self.assertEqual(source.read(), b"")
        return bytes(output)

    def test_selected_ordinal_and_duplicate_names(self):
        target = self.zip_archive((("first.txt", b"first"), ("folder/second.txt", b"second"), ("first.txt", b"duplicate")))
        report = archive.list_archive(target)
        self.assertEqual(report["format"], "ZIP")
        self.assertEqual([row["index"] for row in report["entries"]], [0, 1, 2])
        for index, expected in ((1, b"second"), (2, b"duplicate")):
            response = archive.Response(io.BytesIO())
            response.extract(target, index)
            self.assertEqual(self.unpack_response(response.outgoing.getvalue()), expected)

    def test_zip_paths_and_symlink_are_blocked(self):
        outside = self.root.parent / (self.root.name + "-escape.txt")
        target = self.zip_archive((("../" + outside.name, b"a"), ("/absolute.txt", b"b"), ("C:/drive.txt", b"c"), ("dir\\..\\escape.txt", b"d"), ("control\n.txt", b"e")))
        with zipfile.ZipFile(target, "a") as writer:
            entry = zipfile.ZipInfo("link.txt")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            writer.writestr(entry, "target.txt")
        rows = archive.list_archive(target)["entries"]
        self.assertTrue(all(row["kind"] == "blocked" for row in rows))
        self.assertTrue(all(row["name"] == "Blocked entry %d" % (index + 1) for index, row in enumerate(rows[:5])))
        for index in range(len(rows)):
            with self.assertRaises(archive.ArchiveRejected):
                archive.Response(io.BytesIO()).extract(target, index)
        self.assertFalse(outside.exists())

    def test_tar_links_special_files_and_normalized_paths(self):
        target = self.root / "source.tar"
        with tarfile.open(target, "w") as writer:
            regular = tarfile.TarInfo("./folder/file.txt")
            regular.size = 5
            writer.addfile(regular, io.BytesIO(b"hello"))
            directory = tarfile.TarInfo("./folder/")
            directory.type = tarfile.DIRTYPE
            writer.addfile(directory)
            for name, kind in (("symlink.txt", tarfile.SYMTYPE), ("hardlink.txt", tarfile.LNKTYPE), ("pipe", tarfile.FIFOTYPE), ("device", tarfile.CHRTYPE)):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "folder/file.txt"
                writer.addfile(entry)
            entry = tarfile.TarInfo("./../escape.txt")
            entry.size = 1
            writer.addfile(entry, io.BytesIO(b"x"))
        report = archive.list_archive(target)
        self.assertEqual(report["format"], "TAR")
        rows = report["entries"]
        self.assertEqual(rows[0]["name"], "folder/file.txt")
        self.assertEqual(rows[1]["kind"], "directory")
        self.assertTrue(all(row["kind"] == "blocked" for row in rows[2:]))
        output = io.BytesIO()
        archive.Response(output).extract(target, 0)
        self.assertEqual(self.unpack_response(output.getvalue()), b"hello")

    def test_tar_compression_families(self):
        for compression in ("gz", "bz2", "xz"):
            target = self.root / ("source.tar." + compression)
            with tarfile.open(target, "w:" + compression) as writer:
                entry = tarfile.TarInfo("file.txt")
                entry.size = 4
                writer.addfile(entry, io.BytesIO(b"data"))
            self.assertEqual(archive.list_archive(target)["format"], "TAR")
            output = io.BytesIO()
            archive.Response(output).extract(target, 0)
            self.assertEqual(self.unpack_response(output.getvalue()), b"data")

    def test_encrypted_zip_entry_is_blocked(self):
        target = self.zip_archive((("secret.txt", b"secret"),))
        data = bytearray(target.read_bytes())
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            position = data.index(signature) + offset
            flags = struct.unpack_from("<H", data, position)[0]
            struct.pack_into("<H", data, position, flags | 1)
        target.write_bytes(data)
        row = archive.list_archive(target)["entries"][0]
        self.assertEqual(row["kind"], "blocked")
        self.assertIn("Encrypted", row["reason"])
        with self.assertRaises(archive.ArchiveRejected):
            archive.Response(io.BytesIO()).extract(target, 0)

    def test_empty_archive_and_unsupported_input(self):
        target = self.zip_archive(())
        self.assertEqual(archive.list_archive(target), {"format": "ZIP", "entries": []})
        target.write_bytes(b"this is plain text")
        with self.assertRaises((archive.ArchiveError, archive.ArchiveRejected)):
            archive.list_archive(target)

    def test_multipart_rar_rejected_before_listing_or_extraction(self):
        for version, flags in ((4, 1), (4, 0x101), (5, 1), (5, 3)):
            target = self.root / "source.rar"
            target.write_bytes(self.rar_archive(version, flags))
            with self.subTest(version=version, flags=flags):
                with self.assertRaisesRegex(archive.ArchiveRejected, "Multipart RAR"):
                    archive.list_archive(target)
                outgoing = io.BytesIO()
                with self.assertRaisesRegex(archive.ArchiveRejected, "Multipart RAR"):
                    archive.Response(outgoing).extract(target, 0)
                self.assertEqual(outgoing.getvalue(), b"")

    def test_single_volume_rar_and_rar5_headers_still_open(self):
        for version, flags in ((4, 0), (4, 0x100), (5, 0), (5, 4)):
            target = self.root / "source.rar"
            target.write_bytes(self.rar_archive(version, flags))
            with self.subTest(version=version, flags=flags):
                self.assertEqual(archive.list_archive(target), {"format": "RAR", "entries": []})

    def test_sfx_scan_matches_aligned_native_signature(self):
        for version in (4, 5):
            target = self.root / "source.rar"
            prefix = bytearray(b"MZ" + b"\0" * (65536 - 2))
            fake = self.rar_archive(version, 1)
            prefix[17 : 17 + len(fake)] = fake
            target.write_bytes(prefix + self.rar_archive(version, 0) + b"\0" * 1024)
            with self.subTest(version=version):
                self.assertEqual(archive.list_archive(target), {"format": "RAR", "entries": []})
                fake = self.rar_archive(version, 0)
                prefix[17 : 17 + len(fake)] = fake
                target.write_bytes(prefix + self.rar_archive(version, 1) + b"\0" * 1024)
                with self.assertRaisesRegex(archive.ArchiveRejected, "Multipart RAR"):
                    archive.list_archive(target)

    def test_embedded_rar_markers_do_not_change_container_format(self):
        for version in (4, 5):
            payload = self.rar_archive(version, 1)
            target = self.zip_archive((("part.rar", payload),))
            self.assertEqual(archive.list_archive(target)["format"], "ZIP")
            target = self.root / "source.tar"
            with tarfile.open(target, "w") as writer:
                entry = tarfile.TarInfo("part.rar")
                entry.size = len(payload)
                writer.addfile(entry, io.BytesIO(payload))
            self.assertEqual(archive.list_archive(target)["format"], "TAR")

    def test_filtered_rar_cannot_bypass_volume_check(self):
        for version in (4, 5):
            for flags in (0, 1):
                target = self.root / "wrapped.rar"
                target.write_bytes(gzip.compress(self.rar_archive(version, flags)))
                with self.subTest(version=version, flags=flags):
                    with self.assertRaisesRegex(archive.ArchiveRejected, "Compressed wrappers"):
                        archive.list_archive(target)

    def test_rar_header_crc_bounds_and_parser_agreement(self):
        malformed = [
            b"Rar!\x1a\x07\x00" + b"\0" * 3,
            b"Rar!\x1a\x07\x01\x00" + b"\0" * 4 + b"\x80" * 3,
            b"Rar!\x1a\x07\x01\x00" + self.rar5_block(b"\x01\x02\x01\x00"),
            b"Rar!\x1a\x07\x01\x00" + self.rar5_block(b"\x01\x08\x00"),
            b"Rar!\x1a\x07\x01\x00" + self.rar5_block(b"\x01\x10\x00"),
            b"Rar!\x1a\x07\x01\x00" + self.rar5_block(b"\x01\x01\x05\x00"),
        ]
        bad_crc = bytearray(self.rar_archive(5, 0))
        bad_crc[8] ^= 1
        malformed.append(bytes(bad_crc))
        with patch.object(archive.ffi, "filter_count", return_value=1), patch.object(archive.ffi, "filter_name", return_value=b"none"):
            for data in malformed:
                target = self.root / "malformed.rar"
                target.write_bytes(data)
                family = 0x100000 if data[6] == 1 else 0xD0000
                with self.subTest(data=data):
                    with self.assertRaises(archive.ArchiveRejected):
                        archive.validate_rar_volume(target, None, family)
        self.assertEqual(archive.rar_vint(io.BytesIO(b"\xff" * 9 + b"\x01"))[0], 2 ** 64 - 1)
        for data in (b"\xff" * 9 + b"\x02", b"\x80" * 10, b""):
            with self.assertRaises(archive.ArchiveRejected):
                archive.rar_vint(io.BytesIO(data))

    def test_multipart_error_response_preserves_protocol_handshake(self):
        source = self.rar_archive(4, 1)
        incoming = io.BytesIO(struct.pack("!II", len(source), protocol.LIST_INDEX) + source + protocol.ACK_MAGIC)
        outgoing = io.BytesIO()
        with patch.object(archive, "ARCHIVE_PATH", self.root / "received"), patch.object(archive.sys, "stdin", SimpleNamespace(buffer=incoming)), patch.object(archive.sys, "stdout", SimpleNamespace(buffer=outgoing)):
            archive.main()
        stream = io.BytesIO(outgoing.getvalue())
        self.assertEqual(stream.read(8), protocol.ERROR_MAGIC)
        size = struct.unpack("!I", stream.read(4))[0]
        self.assertIn("Multipart RAR", json.loads(stream.read(size))["error"])
        self.assertEqual(stream.read(), protocol.END_MAGIC)
        self.assertEqual(incoming.read(), b"")

    def test_name_entry_metadata_and_declared_size_limits(self):
        target = self.zip_archive((("x" * (protocol.MAX_NAME + 1) + ".txt", b"x"),))
        self.assertEqual(archive.list_archive(target)["entries"][0]["kind"], "blocked")
        target = self.zip_archive((("one.txt", b"1234"), ("two.txt", b"2")))
        with patch.object(archive, "MAX_ENTRIES", 1), self.assertRaises(archive.ArchiveRejected):
            archive.list_archive(target)
        with patch.object(archive, "MAX_METADATA", 130), self.assertRaises(archive.ArchiveRejected):
            archive.list_archive(target)
        with patch.object(archive, "MAX_OUTPUT", 3):
            self.assertEqual(archive.list_archive(target)["entries"][0]["kind"], "blocked")
            with self.assertRaises(archive.ArchiveRejected):
                archive.Response(io.BytesIO()).extract(target, 0)

    def test_unreadable_names_are_replaced(self):
        entry = SimpleNamespace(pathname="bad\udcff.txt", size=1, _entry_p=None)
        row = archive.entry_record(entry, 0)
        self.assertEqual(row["name"], "Blocked entry 1")
        self.assertEqual(row["kind"], "blocked")

    def test_actual_stream_limit_independent_of_declared_size(self):
        entry = SimpleNamespace(pathname="small.txt", size=1, _entry_p=None, islnk=False, issym=False, isdir=False, isreg=True, get_blocks=lambda block_size: iter((b"1234", b"5678")))
        class FakeArchive:
            def __iter__(self):
                return iter((entry,))

            def format_label(self):
                return "ZIP"

        @contextmanager
        def reader(path):
            yield FakeArchive()

        output = io.BytesIO()
        with patch.object(archive, "archive_reader", reader), patch.object(archive, "entry_is_encrypted", return_value=0), patch.object(archive, "MAX_OUTPUT", 7), patch.object(archive, "CHUNK_SIZE", 4):
            with self.assertRaises(archive.ArchiveRejected):
                archive.Response(output).extract(self.root / "unused", 0)
        self.assertEqual(output.getvalue(), protocol.DATA_MAGIC + struct.pack("!I", 4) + b"1234")

    def test_request_limits_reject_before_writing_source(self):
        for size, index in ((protocol.MAX_INPUT + 1, protocol.LIST_INDEX), (1, protocol.MAX_ENTRIES), (0, protocol.LIST_INDEX)):
            target = self.root / "received"
            with patch.object(archive, "ARCHIVE_PATH", target), self.assertRaises(archive.ArchiveRejected):
                archive.receive_source(io.BytesIO(struct.pack("!II", size, index)))
            self.assertFalse(target.exists())
        source = b"x" * (protocol.CHUNK_SIZE + 1)
        target = self.root / "received"
        requests = []

        class Input(io.BytesIO):
            def read(self, size=-1):
                requests.append(size)
                return super().read(size)

        with patch.object(archive, "ARCHIVE_PATH", target):
            index = archive.receive_source(Input(struct.pack("!II", len(source), 0) + source))
        self.assertEqual(index, 0)
        self.assertEqual(target.read_bytes(), source)
        self.assertLessEqual(max(requests), protocol.CHUNK_SIZE)

    def test_main_listing_ack_and_fixed_error(self):
        target = self.zip_archive((("file.txt", b"hello"),))
        source = target.read_bytes()
        incoming = io.BytesIO(struct.pack("!II", len(source), protocol.LIST_INDEX) + source + protocol.ACK_MAGIC)
        outgoing = io.BytesIO()
        with patch.object(archive, "ARCHIVE_PATH", self.root / "received"), patch.object(archive.sys, "stdin", SimpleNamespace(buffer=incoming)), patch.object(archive.sys, "stdout", SimpleNamespace(buffer=outgoing)):
            archive.main()
        stream = io.BytesIO(outgoing.getvalue())
        self.assertEqual(stream.read(8), protocol.LIST_MAGIC)
        size = struct.unpack("!I", stream.read(4))[0]
        report = json.loads(stream.read(size))
        self.assertEqual(report["entries"][0]["name"], "file.txt")
        self.assertEqual(stream.read(), protocol.END_MAGIC)
        self.assertEqual(incoming.read(), b"")
        incoming = io.BytesIO(struct.pack("!II", 0, protocol.LIST_INDEX) + protocol.ACK_MAGIC)
        outgoing = io.BytesIO()
        with patch.object(archive.sys, "stdin", SimpleNamespace(buffer=incoming)), patch.object(archive.sys, "stdout", SimpleNamespace(buffer=outgoing)):
            archive.main()
        self.assertTrue(outgoing.getvalue().startswith(protocol.ERROR_MAGIC))
        self.assertTrue(outgoing.getvalue().endswith(protocol.END_MAGIC))

    def test_document_dispatcher_keeps_original_wire_protocol(self):
        source = b"%PDF-1.4 fixture"
        incoming = io.BytesIO(struct.pack("!8sI16s", INPUT_MAGIC, len(source), b".pdf") + source + ACK_MAGIC)
        outgoing = io.BytesIO()
        real_path = Path

        def mapped_path(value):
            return self.root / str(value).removeprefix("/tmp/")

        def renderer(arguments):
            if arguments[0] == "/usr/bin/pdfinfo":
                return b"Pages: 1\nPage 1 size: 72 x 72 pts\n"
            if arguments[0] == "/usr/bin/pdftoppm":
                return b"P6\n1 1\n255\n\x01\x02\x03"
            self.fail("Unexpected document renderer command")

        with patch.object(guest, "Path", mapped_path), patch.object(guest.os, "chdir"), patch.object(guest.os, "umask"), patch.object(guest, "run", renderer), patch.object(guest.sys, "stdin", SimpleNamespace(buffer=incoming)), patch.object(guest.sys, "stdout", SimpleNamespace(buffer=outgoing)):
            guest.main()
        self.assertEqual(outgoing.getvalue(), OUTPUT_MAGIC + struct.pack("!III", 1, 1, 1) + b"\x01\x02\x03" + END_MAGIC)
        self.assertEqual((real_path(self.root) / "job/document.pdf").read_bytes(), source)

    def test_archive_dispatcher_consumes_only_magic(self):
        incoming = io.BytesIO(protocol.INPUT_MAGIC + b"remaining")
        with patch.object(guest, "Path", lambda value: self.root / str(value).removeprefix("/tmp/")), patch.object(guest.os, "chdir"), patch.object(guest.os, "umask"), patch.object(guest.sys, "stdin", SimpleNamespace(buffer=incoming)), patch.object(archive, "main") as handler:
            guest.main()
        handler.assert_called_once_with()
        self.assertEqual(incoming.read(), b"remaining")


if __name__ == "__main__":
    unittest.main()
