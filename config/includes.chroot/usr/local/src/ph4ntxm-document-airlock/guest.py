#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import os
import math
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/usr/local/lib/ph4ntxm-document-airlock")
from airlock import (
    ACK_MAGIC,
    END_MAGIC,
    IMAGE_SUFFIXES,
    INPUT_MAGIC,
    MAX_DIMENSION,
    MAX_INPUT,
    MAX_PAGES,
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


def main():
    os.umask(0o077)
    Path("/tmp/home").mkdir()
    Path("/tmp/job").mkdir()
    os.chdir("/tmp/job")
    magic, size, suffix = struct.unpack("!8sI16s", read_exact(sys.stdin.buffer, 28))
    suffix = suffix.rstrip(b"\x00").decode("ascii")
    if magic != INPUT_MAGIC or not 0 < size <= MAX_INPUT or suffix not in SUFFIXES:
        raise ValueError("Invalid request")
    source = Path("/tmp/job/document" + suffix)
    source.write_bytes(read_exact(sys.stdin.buffer, size))
    pdf = Path("/tmp/job/document.pdf")
    if suffix in IMAGE_SUFFIXES:
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
            output = sys.stdout.buffer
            output.write(OUTPUT_MAGIC + struct.pack("!III", 1, *flattened.size))
            output.write(flattened.tobytes())
            output.write(END_MAGIC)
            output.flush()
            if read_exact(sys.stdin.buffer, 8) != ACK_MAGIC:
                raise ValueError("Invalid host acknowledgement")
            return
    elif suffix != ".pdf":
        run(
            [
                "/usr/bin/libreoffice",
                "--headless",
                "--safe-mode",
                "--nologo",
                "--nodefault",
                "--nolockcheck",
                "--norestore",
                "-env:UserInstallation=file:///tmp/home/libreoffice",
                "--convert-to",
                "pdf",
                "--outdir",
                "/tmp/job",
                str(source),
            ]
        )
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
