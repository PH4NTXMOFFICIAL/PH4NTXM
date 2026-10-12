#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import json
import os
import math
import re
import signal
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/usr/local/lib/ph4ntxm-document-airlock")
from airlock import (
    ACK_MAGIC,
    END_MAGIC,
    ERROR_MAGIC,
    IMAGE_SUFFIXES,
    INPUT_MAGIC,
    MAX_DIMENSION,
    MAX_INPUT,
    MAX_PAGES,
    MAX_PASSWORD_BYTES,
    MAX_TOTAL_RGB,
    OUTPUT_MAGIC,
    SUFFIXES,
    read_exact,
)


def run(arguments):
    return subprocess.run(
        arguments,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=120,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp/home", "LANG": "C.UTF-8"},
    ).stdout


def ppm_pixels(data):
    match = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255\n", data)
    if not match:
        raise ValueError("Invalid renderer output")
    width, height = map(int, match.groups())
    if not 1 <= width <= MAX_DIMENSION or not 1 <= height <= MAX_DIMENSION:
        raise ValueError("Page dimensions exceed the limit")
    pixels = data[match.end() :]
    if len(pixels) != width * height * 3:
        raise ValueError("Invalid pixel count")
    return width, height, pixels


class GuestConversionError(Exception):
    def __init__(self, code="conversion"):
        self.code = code
        super().__init__(code)


def error_response(code):
    messages = {
        "password_required": "This document requires a password.",
        "password_incorrect": "The document password is incorrect.",
        "conversion": "The isolated document conversion failed.",
        "unsupported": "This document type or encryption is not supported.",
    }
    code = code if code in messages else "conversion"
    payload = json.dumps({"code": code, "error": messages[code]}).encode("utf-8")
    output = sys.stdout.buffer
    output.write(ERROR_MAGIC + struct.pack("!I", len(payload)) + payload + END_MAGIC)
    output.flush()
    if read_exact(sys.stdin.buffer, 8) != ACK_MAGIC:
        raise ValueError("Invalid host acknowledgement")


def prepare_pdf(source, password):
    import pikepdf

    try:
        with pikepdf.Pdf.open(
            source, password=password or "", suppress_warnings=True
        ) as document:
            if not 1 <= len(document.pages) <= MAX_PAGES:
                raise GuestConversionError()
            if not document.is_encrypted:
                return source
            destination = source.with_name("render.pdf")
            document.save(destination, encryption=False)
            return destination
    except pikepdf.PasswordError:
        raise GuestConversionError(
            "password_incorrect" if password else "password_required"
        ) from None
    except pikepdf.PdfError:
        raise GuestConversionError() from None


def prepare_office(source, password):
    destination = source.with_name("render.pdf")
    process = subprocess.Popen(
        [
            "/usr/bin/python3",
            "/usr/local/lib/ph4ntxm-document-airlock/office_guest.py",
            str(source),
            str(destination),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp/home", "LANG": "C.UTF-8"},
    )
    try:
        result, _ = process.communicate((password or "").encode("utf-8"), timeout=120)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise GuestConversionError() from None
    if process.returncode != 0 or result != b"ok":
        code = result.decode("ascii", errors="ignore")
        raise GuestConversionError(
            code if code in {"password_required", "password_incorrect", "unsupported"}
            else "conversion"
        )
    return destination


def prepare_image(source):
    from PIL import Image, ImageOps

    Image.MAX_IMAGE_PIXELS = 40_000_000
    with Image.open(source) as picture:
        if getattr(picture, "n_frames", 1) != 1:
            raise ValueError("Multi-frame images are not supported")
        if picture.width * picture.height > Image.MAX_IMAGE_PIXELS:
            raise ValueError("Image pixel count exceeds the limit")
        picture.thumbnail((MAX_DIMENSION, MAX_DIMENSION))
        picture = ImageOps.exif_transpose(picture).convert("RGBA")
        flattened = Image.new("RGB", picture.size, "white")
        flattened.paste(picture, mask=picture.getchannel("A"))
        return flattened


def main():
    os.umask(0o077)
    Path("/tmp/home").mkdir()
    Path("/tmp/job").mkdir()
    os.chdir("/tmp/job")
    magic = read_exact(sys.stdin.buffer, 8)
    from archive_protocol import INPUT_MAGIC as ARCHIVE_INPUT_MAGIC

    if magic == ARCHIVE_INPUT_MAGIC:
        from archive_guest import main as archive_main

        archive_main()
        return
    try:
        if magic != INPUT_MAGIC:
            raise ValueError("Invalid request")
        size, suffix, password_size = struct.unpack(
            "!I16sH", read_exact(sys.stdin.buffer, 22)
        )
        suffix = suffix.rstrip(b"\x00").decode("ascii")
        if not 0 < size <= MAX_INPUT or suffix not in SUFFIXES:
            raise ValueError("Invalid request")
        if password_size > MAX_PASSWORD_BYTES:
            raise ValueError("Invalid password length")
        encoded_password = read_exact(sys.stdin.buffer, password_size)
        if b"\x00" in encoded_password:
            raise ValueError("Invalid password")
        password = encoded_password.decode("utf-8") or None
        source = Path("/tmp/job/document" + suffix)
        source.write_bytes(read_exact(sys.stdin.buffer, size))
        image = None
        if suffix in IMAGE_SUFFIXES:
            image = prepare_image(source)
        elif suffix == ".pdf":
            pdf = prepare_pdf(source, password)
        else:
            pdf = prepare_office(source, password)
        if image is None:
            count, dimensions = pdf_metadata(pdf)
    except Exception as error:
        code = error.code if isinstance(error, GuestConversionError) else "conversion"
        error_response(code)
        return
    output = sys.stdout.buffer
    if image is not None:
        output.write(OUTPUT_MAGIC + struct.pack("!III", 1, *image.size))
        output.write(image.tobytes())
        output.write(END_MAGIC)
        output.flush()
        if read_exact(sys.stdin.buffer, 8) != ACK_MAGIC:
            raise ValueError("Invalid host acknowledgement")
        return
    render_pdf(pdf, count, dimensions)


def pdf_metadata(pdf):
    metadata = run(["/usr/bin/pdfinfo", "-f", "1", "-l", str(MAX_PAGES), str(pdf)])
    match = re.search(rb"^Pages:\s+(\d+)$", metadata, re.MULTILINE)
    if not match or not 1 <= int(match.group(1)) <= MAX_PAGES:
        raise ValueError("Page count exceeds the limit")
    count = int(match.group(1))
    dimensions = {
        int(number): (float(width), float(height))
        for number, width, height in re.findall(
            rb"^Page\s+(\d+) size:\s+([0-9.]+) x ([0-9.]+) pts",
            metadata,
            re.MULTILINE,
        )
    }
    if set(dimensions) != set(range(1, count + 1)):
        raise ValueError("Invalid page dimensions")
    for width, height in dimensions.values():
        if not math.isfinite(width) or not math.isfinite(height) or min(width, height) <= 0:
            raise ValueError("Invalid page size")
    return count, dimensions


def render_pdf(pdf, count, dimensions):
    output = sys.stdout.buffer
    output.write(OUTPUT_MAGIC + struct.pack("!I", count))
    total = 0
    for number in range(1, count + 1):
        largest = max(dimensions[number])
        if not math.isfinite(largest) or largest <= 0:
            raise ValueError("Invalid page size")
        resolution = min(150, (MAX_DIMENSION - 1) * 72 / largest)
        if resolution < 1:
            raise ValueError("Page size exceeds the rendering limit")
        page = run(
            [
                "/usr/bin/pdftoppm",
                "-r",
                "%.6f" % resolution,
                "-f",
                str(number),
                "-l",
                str(number),
                "-singlefile",
                str(pdf),
            ]
        )
        width, height, pixels = ppm_pixels(page)
        total += len(pixels)
        if total > MAX_TOTAL_RGB:
            raise ValueError("Pixel budget exceeded")
        output.write(struct.pack("!II", width, height))
        output.write(pixels)
        output.flush()
    output.write(END_MAGIC)
    output.flush()
    if read_exact(sys.stdin.buffer, 8) != ACK_MAGIC:
        raise ValueError("Invalid host acknowledgement")


if __name__ == "__main__":
    main()
