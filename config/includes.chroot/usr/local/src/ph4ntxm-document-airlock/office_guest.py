#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import os
import secrets
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import uno
import unohelper
from com.sun.star.task import PasswordRequest, XInteractionHandler


class OfficeConversionError(Exception):
    def __init__(self, code="conversion"):
        self.code = code
        super().__init__(code)


class RejectInteractions(unohelper.Base, XInteractionHandler):
    def __init__(self):
        self.password_requested = False
        self.blocked = False

    def handle(self, interaction):
        request = interaction.getRequest()
        if isinstance(request, PasswordRequest) and not getattr(
            request, "IsRequestPasswordToModify", False
        ):
            self.password_requested = True
        self.blocked = True
        abort_type = uno.getTypeByName("com.sun.star.task.XInteractionAbort")
        for continuation in interaction.getContinuations():
            abort = continuation.queryInterface(abort_type)
            if abort is not None:
                abort.select()
                break


def properties(values):
    result = []
    for name, value in values.items():
        item = uno.createUnoStruct("com.sun.star.beans.PropertyValue")
        item.Name = name
        item.Value = value
        result.append(item)
    return tuple(result)


def start_office(directory):
    pipe_name = "ph4ntxm_airlock_" + secrets.token_hex(16)
    profile = uno.systemPathToFileUrl(str(directory / "libreoffice"))
    process = subprocess.Popen(
        [
            "/usr/bin/libreoffice",
            "--headless",
            "--nologo",
            "--nodefault",
            "--nolockcheck",
            "--norestore",
            "--invisible",
            "-env:UserInstallation=" + profile,
            "--accept=pipe,name=" + pipe_name + ";urp;StarOffice.ComponentContext",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(directory),
            "LANG": "C.UTF-8",
        },
    )
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local
    )
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise OfficeConversionError()
            try:
                context = resolver.resolve(
                    "uno:pipe,name=" + pipe_name + ";urp;StarOffice.ComponentContext"
                )
                desktop = context.ServiceManager.createInstanceWithContext(
                    "com.sun.star.frame.Desktop", context
                )
                return process, desktop
            except uno.getClass("com.sun.star.connection.NoConnectException"):
                time.sleep(0.1)
        raise OfficeConversionError()
    except Exception:
        stop_office(process)
        raise


def stop_office(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def encrypted_office(source):
    if source.suffix in {".odt", ".ods", ".odp", ".odg"}:
        try:
            with zipfile.ZipFile(source) as archive:
                metadata = archive.getinfo("META-INF/manifest.xml")
                if metadata.file_size > 2 * 1024 * 1024:
                    raise OfficeConversionError()
                with archive.open(metadata) as stream:
                    data = stream.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise OfficeConversionError()
                manifest = ET.fromstring(data)
                return (
                    manifest.find(
                        ".//{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}encryption-data"
                    )
                    is not None
                )
        except (KeyError, OSError, RuntimeError, zipfile.BadZipFile, ET.ParseError):
            raise OfficeConversionError() from None
    if source.suffix in {".docx", ".xlsx", ".pptx"}:
        import olefile

        with source.open("rb") as stream:
            if stream.read(8) != olefile.MAGIC:
                return False
        try:
            with olefile.OleFileIO(
                source, raise_defects=olefile.DEFECT_INCORRECT
            ) as compound:
                return compound.exists("EncryptionInfo") and compound.exists(
                    "EncryptedPackage"
                )
        except (OSError, ValueError, olefile.OleFileError):
            raise OfficeConversionError() from None
    return False


def convert_office(source, destination, password=None):
    encrypted = encrypted_office(source)
    if encrypted and not password:
        raise OfficeConversionError("password_required")
    process, desktop = start_office(source.parent)
    document = None
    handler = RejectInteractions()
    options = {
        "Hidden": True,
        "ReadOnly": True,
        "PickListEntry": False,
        "MacroExecutionMode": uno.getConstantByName(
            "com.sun.star.document.MacroExecMode.NEVER_EXECUTE"
        ),
        "UpdateDocMode": uno.getConstantByName(
            "com.sun.star.document.UpdateDocMode.NO_UPDATE"
        ),
        "InteractionHandler": handler,
    }
    if password:
        options["Password"] = password
    try:
        try:
            document = desktop.loadComponentFromURL(
                uno.systemPathToFileUrl(str(source)), "_blank", 0, properties(options)
            )
        except Exception:
            document = None
        if handler.password_requested:
            raise OfficeConversionError(
                "password_incorrect" if password else "password_required"
            )
        if document is None or handler.blocked:
            raise OfficeConversionError(
                "password_incorrect" if encrypted else "conversion"
            )
        if document.supportsService("com.sun.star.text.TextDocument"):
            export_filter = "writer_pdf_Export"
        elif document.supportsService("com.sun.star.sheet.SpreadsheetDocument"):
            export_filter = "calc_pdf_Export"
        elif document.supportsService("com.sun.star.presentation.PresentationDocument"):
            export_filter = "impress_pdf_Export"
        elif document.supportsService("com.sun.star.drawing.DrawingDocument"):
            export_filter = "draw_pdf_Export"
        else:
            raise OfficeConversionError("unsupported")
        document.storeToURL(
            uno.systemPathToFileUrl(str(destination)),
            properties({"FilterName": export_filter, "Overwrite": True}),
        )
        if not destination.is_file() or destination.stat().st_size == 0:
            raise OfficeConversionError()
    except OfficeConversionError:
        raise
    except Exception:
        raise OfficeConversionError() from None
    finally:
        if document is not None:
            try:
                document.close(True)
            except Exception:
                pass
        try:
            desktop.terminate()
        except Exception:
            pass
        stop_office(process)


def main():
    os.umask(0o077)
    try:
        if len(sys.argv) != 3:
            raise OfficeConversionError()
        encoded = sys.stdin.buffer.read(1025)
        if len(encoded) > 1024 or b"\0" in encoded:
            raise OfficeConversionError()
        password = encoded.decode("utf-8") or None
        source, destination = map(lambda value: Path(value).resolve(), sys.argv[1:])
        convert_office(source, destination, password)
        sys.stdout.write("ok")
    except Exception as error:
        code = error.code if isinstance(error, OfficeConversionError) else "conversion"
        sys.stdout.write(code)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
