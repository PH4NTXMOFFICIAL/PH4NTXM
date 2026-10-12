#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from pathlib import Path
import sys
import tempfile
import unittest

import pikepdf
import uno

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest
from office_guest import properties, start_office, stop_office


class DocumentGuestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.password = "Airlock-Κωδικός-42\nsecond line"
        self.addCleanup(self.temporary.cleanup)

    def pdf(self, name, password):
        target = self.root / name
        with pikepdf.Pdf.new() as document:
            document.add_blank_page(page_size=(72, 72))
            options = {}
            if password is not None:
                options["encryption"] = pikepdf.Encryption(
                    owner="owner-secret", user=password, R=6
                )
            document.save(target, **options)
        return target

    def assert_password_error(self, callback, password, expected):
        with self.assertRaises(guest.GuestConversionError) as result:
            callback(password)
        self.assertEqual(result.exception.code, expected)

    def test_encrypted_pdf(self):
        source = self.pdf("encrypted.pdf", self.password)
        convert = lambda password: guest.prepare_pdf(source, password)
        self.assert_password_error(convert, None, "password_required")
        self.assert_password_error(convert, "incorrect", "password_incorrect")
        output = convert(self.password)
        self.assertEqual(guest.pdf_metadata(output)[0], 1)
        with pikepdf.Pdf.open(output) as document:
            self.assertFalse(document.is_encrypted)

    def test_empty_user_password_and_plain_pdf(self):
        for name, password in (("empty.pdf", ""), ("plain.pdf", None)):
            source = self.pdf(name, password)
            output = guest.prepare_pdf(source, None)
            self.assertEqual(guest.pdf_metadata(output)[0], 1)

    def test_encrypted_odt_and_docx(self):
        process, desktop = start_office(self.root)
        document = None
        try:
            document = desktop.loadComponentFromURL(
                "private:factory/swriter", "_blank", 0, properties({"Hidden": True})
            )
            document.Text.String = "Encrypted document fixture"
            for name, export_filter in (
                ("encrypted.odt", "writer8"),
                ("encrypted.docx", "Office Open XML Text"),
            ):
                document.storeToURL(
                    uno.systemPathToFileUrl(str(self.root / name)),
                    properties(
                        {"FilterName": export_filter, "Password": self.password, "Overwrite": True}
                    ),
                )
        finally:
            if document is not None:
                document.close(True)
            desktop.terminate()
            stop_office(process)
        for name in ("encrypted.odt", "encrypted.docx"):
            with self.subTest(name=name):
                source = self.root / name
                convert = lambda password: guest.prepare_office(source, password)
                self.assert_password_error(convert, None, "password_required")
                self.assert_password_error(convert, "incorrect", "password_incorrect")
                self.assertEqual(guest.pdf_metadata(convert(self.password))[0], 1)


if __name__ == "__main__":
    unittest.main()
