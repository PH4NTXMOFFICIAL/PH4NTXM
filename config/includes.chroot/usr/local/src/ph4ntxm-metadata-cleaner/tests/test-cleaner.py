#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import copy
import io
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

import cairo
from PIL import Image, PngImagePlugin
from libmat2 import parser_factory
from mutagen.apev2 import APEv2, APENoHeaderError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cleaner_protocol as protocol
import worker
import cleaner


class CleanerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.original_parser = parser_factory.get_parser

    def job(self, source, operation="clean"):
        workspace = self.directory / ("job-" + str(len(list(self.directory.iterdir()))))
        workspace.mkdir()
        suffix = protocol.suffix_for(source.name)
        original = source.read_bytes()
        with mock.patch.object(parser_factory, "get_parser", self.original_parser):
            report = worker.run_job(source, workspace, suffix, operation)
        self.assertEqual(source.read_bytes(), original)
        self.assertIs(protocol.validate_report(report, operation), report)
        return report, workspace / ("result" + suffix)

    def write_archive(self, path, members):
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return path

    def test_protocol_and_display_bounds(self):
        self.assertEqual(protocol.suffix_for("REPORT.TAR.GZ"), ".tar.gz")
        with self.assertRaises(ValueError):
            protocol.suffix_for("report.txt")
        rows, truncated = worker.fields(
            {"key": "a\x00b\u202ec" + "x" * protocol.MAX_TEXT}
        )
        self.assertTrue(truncated)
        self.assertEqual(len(rows[0][1]), protocol.MAX_TEXT)
        self.assertNotIn("\x00", rows[0][1])
        self.assertNotIn("\u202e", rows[0][1])
        rows, truncated = worker.fields(list(range(protocol.MAX_FIELDS + 1)))
        self.assertEqual(len(rows), protocol.MAX_FIELDS)
        self.assertTrue(truncated)
        report = {
            "ok": True,
            "kind": "image",
            "mime": "image/png",
            "cleaned": False,
            "output_size": 0,
            "before": [],
            "after": [],
            "before_truncated": False,
            "after_truncated": False,
        }
        self.assertIs(protocol.validate_report(report, "inspect"), report)
        for changes in (
            {"output_size": True},
            {"cleaned": True},
            {"before": [["key", "x" * (protocol.MAX_TEXT + 1)]]},
            {"after": [["key", "bad\nvalue"]]},
            {"before": [["key", "value"]] * (protocol.MAX_FIELDS + 1)},
            {"before_truncated": 1},
        ):
            with self.subTest(changes=list(changes)):
                invalid = copy.deepcopy(report)
                invalid.update(changes)
                with self.assertRaises(ValueError):
                    protocol.validate_report(invalid, "inspect")

    def test_png_cleaning_preserves_pixels_and_source(self):
        source = self.directory / "photo.png"
        metadata = PngImagePlugin.PngInfo()
        metadata.add_text("Author", "PRIVATE_PNG_AUTHOR")
        Image.new("RGBA", (24, 16), (12, 45, 90, 255)).save(source, pnginfo=metadata)
        inspected, unused = self.job(source, "inspect")
        self.assertFalse(inspected["cleaned"])
        report, output = self.job(source)
        self.assertIn("PRIVATE_PNG_AUTHOR", str(report["before"]))
        self.assertNotIn("PRIVATE_PNG_AUTHOR", str(report["after"]))
        with Image.open(source) as before, Image.open(output) as after:
            self.assertEqual(before.size, after.size)
            self.assertEqual(
                before.convert("RGBA").tobytes(), after.convert("RGBA").tobytes()
            )
            self.assertNotIn("Author", after.info)

    def test_svg_preserves_nonsquare_canvas(self):
        for size in ('width="160" height="100"', 'viewBox="10 20 160 100"'):
            source = self.directory / "drawing.svg"
            source.write_text(
                '<svg xmlns="http://www.w3.org/2000/svg" '
                + size
                + '><rect width="160" height="100" fill="red"/></svg>'
            )
            report, output = self.job(source)
            self.assertEqual(
                ET.parse(output).getroot().attrib["viewBox"], "0 0 160 100"
            )
            self.assertTrue(report["cleaned"])

    def test_mp3_inspects_and_removes_apev2(self):
        source = self.directory / "audio.mp3"
        subprocess.run(
            [
                "/usr/bin/ffmpeg",
                "-v",
                "error",
                "-f",
                "lavfi",
                "-i",
                "anullsrc=r=44100:cl=mono",
                "-t",
                "0.1",
                "-c:a",
                "libmp3lame",
                "-metadata",
                "artist=PRIVATE_ID3_AUTHOR",
                str(source),
            ],
            check=True,
            timeout=15,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        tags = APEv2()
        tags["Artist"] = "PRIVATE_APE_AUTHOR"
        tags.save(source)
        report, output = self.job(source)
        self.assertIn("PRIVATE_ID3_AUTHOR", str(report["before"]))
        self.assertIn("PRIVATE_APE_AUTHOR", str(report["before"]))
        self.assertFalse(report["after"])
        with self.assertRaises(APENoHeaderError):
            APEv2(output)

    def test_embedded_workbook_is_cleaned(self):
        types = '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>'
        core = '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>PRIVATE_WORKBOOK_AUTHOR</dc:creator></cp:coreProperties>'
        embedded = self.write_archive(
            self.directory / "embedded.xlsx",
            {
                "[Content_Types].xml": types,
                "docProps/core.xml": core,
                "xl/workbook.xml": '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>',
            },
        )
        source = self.write_archive(
            self.directory / "slides.pptx",
            {
                "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
                "ppt/presentation.xml": '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>',
                "ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx": embedded.read_bytes(),
            },
        )
        report, output = self.job(source)
        self.assertIn("PRIVATE_WORKBOOK_AUTHOR", str(report["before"]))
        self.assertNotIn("PRIVATE_WORKBOOK_AUTHOR", str(report["after"]))
        with zipfile.ZipFile(output) as archive:
            with zipfile.ZipFile(
                io.BytesIO(
                    archive.read("ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx")
                )
            ) as workbook:
                self.assertNotIn(
                    b"PRIVATE_WORKBOOK_AUTHOR", workbook.read("docProps/core.xml")
                )

    def test_odf_comment_authors_are_removed(self):
        content = '<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><office:body><office:text><text:p>Visible text<office:annotation office:name="a"><dc:creator>PRIVATE_ODF_AUTHOR</dc:creator><text:p>Private comment</text:p></office:annotation><office:annotation-end office:name="a"/></text:p></office:text></office:body></office:document-content>'
        source = self.write_archive(
            self.directory / "document.odt",
            {
                "mimetype": "application/vnd.oasis.opendocument.text",
                "content.xml": content,
            },
        )
        report, output = self.job(source)
        with zipfile.ZipFile(output) as archive:
            cleaned = archive.read("content.xml")
            self.assertIn(b"Visible text", cleaned)
            self.assertNotIn(b"PRIVATE_ODF_AUTHOR", cleaned)
            self.assertNotIn(b"annotation", cleaned)

    def test_pdf_author_is_removed(self):
        source = self.directory / "document.pdf"
        surface = cairo.PDFSurface(str(source), 120, 80)
        surface.set_metadata(cairo.PDF_METADATA_AUTHOR, "PRIVATE_PDF_AUTHOR")
        context = cairo.Context(surface)
        context.rectangle(10, 10, 40, 20)
        context.fill()
        surface.finish()
        report, output = self.job(source)
        self.assertIn("PRIVATE_PDF_AUTHOR", str(report["before"]))
        self.assertNotIn("PRIVATE_PDF_AUTHOR", str(report["after"]))
        self.assertTrue(output.read_bytes().startswith(b"%PDF-"))

    def test_unknown_archive_members_abort(self):
        source = self.write_archive(
            self.directory / "unknown.zip",
            {"private.unknown": b"private unsupported payload"},
        )
        with self.assertRaisesRegex(worker.WorkerError, "Unsupported archive members"):
            self.job(source)
        self.assertFalse(any(self.directory.glob("job-*/result.zip")))

    def test_multipage_tiff_cleaning_is_rejected(self):
        source = self.directory / "pages.tiff"
        first = Image.new("RGB", (8, 8), "red")
        first.save(
            source, save_all=True, append_images=[Image.new("RGB", (8, 8), "blue")]
        )
        original = source.read_bytes()
        with self.assertRaisesRegex(worker.WorkerError, "multipage TIFF"):
            self.job(source)
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse(any(self.directory.glob("job-*/result.tiff")))


class CleanerResourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(
            cleaner.Path, "read_text", return_value="Filename Type Size Used Priority\n"
        ).start()
        mock.patch.object(
            cleaner.airlock, "available_memory_mib", return_value=704
        ).start()
        self.space = mock.patch.object(
            cleaner.os,
            "statvfs",
            return_value=SimpleNamespace(f_bavail=1024 * 1024 * 1024, f_frsize=1),
        ).start()

    def test_working_memory_accounts_for_workspace_once(self):
        cleaner.check_budget(
            self.directory, protocol.MAX_INPUT + protocol.MAX_OUTPUT * 2, working=True
        )
        with mock.patch.object(
            cleaner.airlock, "available_memory_mib", return_value=703
        ):
            with self.assertRaisesRegex(
                cleaner.CleanerError, "704 MiB required, 703 MiB available"
            ):
                cleaner.check_budget(self.directory, working=True)

    def test_working_storage_keeps_full_cgroup_reservation(self):
        self.space.return_value.f_bavail = 527 * 1024 * 1024
        with self.assertRaisesRegex(
            cleaner.CleanerError, "528 MiB required, 527 MiB available"
        ):
            cleaner.check_budget(self.directory, working=True)
        self.space.return_value.f_bavail = 528 * 1024 * 1024
        cleaner.check_budget(self.directory, working=True)

    def test_small_copy_fits_small_runtime(self):
        self.space.return_value.f_bavail = 170 * 1024 * 1024
        with mock.patch.object(
            cleaner.airlock, "available_memory_mib", return_value=194
        ):
            cleaner.check_budget(self.directory, 2 * 1024 * 1024)

    def test_readiness_checks_storage_instead_of_small_user_runtime(self):
        runtime = Path("/run/user/1000")
        self.space.side_effect = lambda directory: SimpleNamespace(
            f_bavail=(170 if Path(directory) == runtime else 1024) * 1024 * 1024,
            f_frsize=1,
        )
        with (
            mock.patch.object(cleaner.os, "geteuid", return_value=1000),
            mock.patch.object(
                cleaner.airlock, "runtime_directory", return_value=runtime
            ),
            mock.patch.object(cleaner, "check_components"),
            mock.patch.object(cleaner, "storage_directory", return_value=Path("/tmp")),
            mock.patch.object(
                cleaner.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
        ):
            self.assertEqual(cleaner.check_ready(), runtime)
        self.space.assert_called_once_with(Path("/tmp"))

    def test_enabled_swap_still_rejects_ram_storage(self):
        with mock.patch.object(
            cleaner.Path,
            "read_text",
            return_value="Filename Type Size Used Priority\n/dev/dummy partition 1 0 -1\n",
        ):
            with self.assertRaisesRegex(cleaner.CleanerError, "Disable swap"):
                cleaner.check_budget(self.directory, working=True)

    def test_verified_storage_requires_root_sticky_real_tmpfs(self):
        metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
        with (
            mock.patch.object(cleaner.Path, "lstat", return_value=metadata),
            mock.patch.object(
                cleaner.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "tmpfs\n", ""),
            ),
        ):
            self.assertEqual(cleaner.storage_directory(), Path("/tmp"))

    def test_storage_rejects_symlink_untrusted_owner_and_permissions(self):
        for mode, uid in (
            (stat.S_IFLNK | 0o1777, 0),
            (stat.S_IFREG | 0o1777, 0),
            (stat.S_IFDIR | 0o1777, 1000),
            (stat.S_IFDIR | 0o777, 0),
            (stat.S_IFDIR | 0o1775, 0),
        ):
            with self.subTest(mode=mode, uid=uid):
                with (
                    mock.patch.object(
                        cleaner.Path,
                        "lstat",
                        return_value=SimpleNamespace(st_mode=mode, st_uid=uid),
                    ),
                    mock.patch.object(cleaner.subprocess, "run") as mount,
                ):
                    with self.assertRaises(cleaner.CleanerError):
                        cleaner.storage_directory()
                    mount.assert_not_called()

    def test_storage_rejects_persistent_or_unverifiable_mount(self):
        metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
        for filesystem in ("ext4\n", "overlay\n", ""):
            with self.subTest(filesystem=filesystem):
                with (
                    mock.patch.object(cleaner.Path, "lstat", return_value=metadata),
                    mock.patch.object(
                        cleaner.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], 0, filesystem, ""),
                    ),
                ):
                    with self.assertRaisesRegex(cleaner.CleanerError, "reside in RAM"):
                        cleaner.storage_directory()
        with (
            mock.patch.object(cleaner.Path, "lstat", return_value=metadata),
            mock.patch.object(
                cleaner.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired("findmnt", 5),
            ),
        ):
            with self.assertRaisesRegex(cleaner.CleanerError, "could not be verified"):
                cleaner.storage_directory()

    def test_session_storage_is_separate_from_user_manager_runtime(self):
        runtime = self.directory / "runtime"
        runtime.mkdir()
        with mock.patch.object(
            cleaner, "storage_directory", return_value=self.directory
        ):
            session = cleaner.CleanerSession(runtime)
        self.addCleanup(session.close)
        self.assertEqual(session.directory.parent, self.directory)
        self.assertEqual(stat.S_IMODE(session.directory.stat().st_mode), 0o700)
        self.assertEqual(session.runtime, runtime)
        self.assertEqual(session.environment["XDG_RUNTIME_DIR"], str(runtime))
        self.assertEqual(
            session.environment["DBUS_SESSION_BUS_ADDRESS"],
            "unix:path=" + str(runtime / "bus"),
        )
        source = session.directory / "source.png"
        source.write_bytes(b"dummy")
        with mock.patch.object(cleaner, "check_budget") as budget:
            session.copy_file(source, runtime / "preview.png", protocol.MAX_INPUT)
        budget.assert_called_once_with(runtime, 5)


if __name__ == "__main__":
    unittest.main()
