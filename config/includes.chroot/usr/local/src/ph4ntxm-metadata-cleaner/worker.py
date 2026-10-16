# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import subprocess
import sys
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cleaner_protocol import (
    FORMATS,
    MAX_INPUT,
    MAX_OUTPUT,
    MAX_MEMORY,
    MAX_FIELDS,
    MAX_TEXT,
    MAX_REPORT,
)

FILTER = "/usr/local/libexec/ph4ntxm-media/filter"


class WorkerError(Exception):
    pass


def display_text(value):
    return "".join(
        character if unicodedata.category(character) not in {"Cc", "Cf", "Cs"} else " "
        for character in str(value)[:MAX_TEXT]
    )


def fields(value):
    rows = []
    truncated = False

    def visit(item, path, depth):
        nonlocal truncated
        if len(rows) >= MAX_FIELDS or depth > 8:
            truncated = True
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if len(str(key)) > MAX_TEXT:
                    truncated = True
                visit(child, path + [display_text(key)], depth + 1)
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                visit(child, path + [str(index + 1)], depth + 1)
        else:
            text = str(item)
            if len(" / ".join(path)) > MAX_TEXT:
                truncated = True
            if len(text) > MAX_TEXT:
                truncated = True
            rows.append([display_text(" / ".join(path)), display_text(text)])

    visit(value, [], 0)
    return rows, truncated


def contained():
    membership = Path("/proc/self/cgroup").read_text(encoding="ascii")
    for line in membership.splitlines():
        if line.startswith("0::/"):
            group = Path("/sys/fs/cgroup") / line[4:]
            limit = (group / "memory.max").read_text().strip()
            swap = (group / "memory.swap.max").read_text().strip()
            if limit.isdecimal() and 0 < int(limit) <= MAX_MEMORY and swap == "0":
                return
    raise WorkerError("The worker memory limits are not active.")


def install_filter():
    data = subprocess.check_output([FILTER], timeout=5)
    if not data or len(data) % 8 or len(data) > 32768:
        raise WorkerError("The worker syscall filter is unavailable.")

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.c_void_p)]

    buffer = ctypes.create_string_buffer(data)
    program = Program(len(data) // 8, ctypes.cast(buffer, ctypes.c_void_p))
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(38, 1, 0, 0, 0) or library.prctl(
        22, 2, ctypes.byref(program), 0, 0
    ):
        raise WorkerError("The worker syscall filter could not be installed.")


def clean_svg(parser):
    import math
    import cairo
    from gi.repository import Rsvg

    svg = Rsvg.Handle.new_from_file(parser.filename)
    has_size, width, height = svg.get_intrinsic_size_in_pixels()
    if not has_size:
        _, _, _, _, has_viewbox, viewbox = svg.get_intrinsic_dimensions()
        if not has_viewbox:
            raise WorkerError(
                "This SVG needs explicit dimensions or a viewBox before cleaning."
            )
        width, height = viewbox.width, viewbox.height
    if (
        not math.isfinite(width)
        or not math.isfinite(height)
        or width <= 0
        or height <= 0
        or width * height > 32 * 1024 * 1024
    ):
        raise WorkerError(
            "This SVG has invalid dimensions or exceeds the 32-megapixel limit."
        )
    viewport = Rsvg.Rectangle()
    viewport.x, viewport.y, viewport.width, viewport.height = 0, 0, width, height
    surface = cairo.SVGSurface(parser.output_filename, width, height)
    context = cairo.Context(surface)
    try:
        if not svg.render_document(context, viewport):
            raise WorkerError("This SVG could not be rendered for cleaning.")
    finally:
        surface.finish()
    return True


def mp3_metadata(parser):
    from libmat2.audio import MP3Parser
    from mutagen.apev2 import APEv2, APENoHeaderError

    metadata = MP3Parser.get_meta(parser)
    try:
        tags = APEv2(parser.filename)
    except APENoHeaderError:
        return metadata
    metadata["APEv2"] = {key: str(value) for key, value in tags.items()}
    return metadata


def clean_mp3(parser):
    from libmat2.audio import MP3Parser
    from mutagen.apev2 import delete

    if MP3Parser.remove_all(parser) is not True:
        return False
    delete(parser.output_filename)
    return True


def clean_office(parser):
    import zipfile
    import xml.etree.ElementTree as ET
    from libmat2.office import MSOfficeParser

    if MSOfficeParser.remove_all(parser) is not True:
        return False
    namespaces = {
        "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "http://purl.oclc.org/ooxml/wordprocessingml/main",
    }
    attribution = {
        "{" + namespace + "}" + name
        for namespace in namespaces
        for name in ("author", "date", "initials")
    }
    with zipfile.ZipFile(parser.output_filename) as archive:
        for name in archive.namelist():
            if name.endswith(".xml"):
                root = ET.fromstring(archive.read(name))
                if any(
                    attribution.intersection(element.attrib) for element in root.iter()
                ):
                    raise WorkerError(
                        "Accept tracked changes and remove revision attribution before cleaning this Office file."
                    )
    return True


def clean_open_document_member(parser, filename):
    import xml.etree.ElementTree as ET
    from libmat2.office import LibreOfficeParser

    if Path(filename).name == "content.xml":
        tree = ET.parse(filename)
        namespaces = {
            "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
            "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
            "table": "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
        }
        remove = {
            "{" + namespaces[namespace] + "}" + name
            for namespace, name in (
                ("office", "annotation"),
                ("office", "annotation-end"),
                ("text", "tracked-changes"),
                ("table", "tracked-changes"),
            )
        }
        changed = False
        for parent in tree.iter():
            for child in list(parent):
                if child.tag in remove:
                    parent.remove(child)
                    changed = True
        if changed:
            tree.write(filename, xml_declaration=True, encoding="utf-8")
    return LibreOfficeParser._specific_cleanup(parser, filename)


def guard_parsers(operation):
    from libmat2 import parser_factory
    from libmat2.audio import MP3Parser
    from libmat2.images import SVGParser
    from libmat2.office import MSOfficeParser, LibreOfficeParser
    from types import MethodType
    from PIL import Image

    original = parser_factory.get_parser
    Image.MAX_IMAGE_PIXELS = 32 * 1024 * 1024

    def guarded(filename):
        extension = Path(filename).suffix.lower()
        if extension in {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".gif"}:
            with Image.open(filename) as image:
                if image.width * image.height > Image.MAX_IMAGE_PIXELS:
                    raise WorkerError("This image exceeds the 32-megapixel limit.")
                if operation == "clean":
                    if (
                        extension in {".png", ".tif", ".tiff"}
                        and getattr(image, "n_frames", 1) != 1
                    ):
                        raise WorkerError(
                            "Animated PNG and multipage TIFF cleaning are not supported."
                        )
                    if extension == ".png" and image.getexif().get(274, 1) != 1:
                        raise WorkerError(
                            "Normalize PNG orientation before cleaning this image."
                        )
        parser, mime = original(filename)
        if isinstance(parser, SVGParser):
            parser.remove_all = MethodType(clean_svg, parser)
        elif isinstance(parser, MP3Parser):
            parser.get_meta = MethodType(mp3_metadata, parser)
            parser.remove_all = MethodType(clean_mp3, parser)
        elif isinstance(parser, MSOfficeParser):
            parser.files_to_keep = {
                pattern
                for pattern in parser.files_to_keep
                if "/embeddings/" not in pattern.pattern
            }
            parser.remove_all = MethodType(clean_office, parser)
        elif isinstance(parser, LibreOfficeParser):
            parser._specific_cleanup = MethodType(clean_open_document_member, parser)
        return parser, mime

    parser_factory.get_parser = guarded


def parser_for(path):
    from libmat2 import parser_factory
    from libmat2 import UnknownMemberPolicy

    parser, mime = parser_factory.get_parser(str(path))
    if parser is None or parser.__class__.__name__ == "HarmlessParser":
        raise WorkerError("This file format has no supported metadata cleaner.")
    parser.sandbox = False
    if hasattr(parser, "unknown_member_policy"):
        parser.unknown_member_policy = UnknownMemberPolicy.ABORT
    return parser, mime


def run_job(source, workspace, suffix, operation):
    if suffix not in FORMATS or operation not in {"inspect", "clean"}:
        raise WorkerError("The metadata request is invalid.")
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_INPUT:
        raise WorkerError("Select a nonempty regular file up to 64 MiB.")
    canonical = {".tgz": ".tar.gz", ".tbz2": ".tar.bz2", ".txz": ".tar.xz"}.get(
        suffix, suffix
    )
    local = workspace / ("source" + canonical)
    shutil.copyfile(source, local)
    local.chmod(0o600)
    result = {
        "ok": True,
        "kind": FORMATS[suffix],
        "mime": "",
        "before": [],
        "after": [],
        "before_truncated": False,
        "after_truncated": False,
        "cleaned": False,
        "output_size": 0,
    }
    guard_parsers(operation)
    parser, result["mime"] = parser_for(local)
    result["before"], result["before_truncated"] = fields(parser.get_meta())
    if operation == "clean":
        if parser.remove_all() is not True:
            raise WorkerError(
                "Cleaning stopped. Unsupported archive members or file features may be present."
            )
        output = Path(parser.output_filename)
        info = output.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not 0 < info.st_size <= MAX_OUTPUT
            or output.parent.resolve() != workspace.resolve()
        ):
            raise WorkerError("The cleaned output could not be verified.")
        check, _ = parser_for(output)
        result["after"], result["after_truncated"] = fields(check.get_meta())
        target = workspace / ("result" + suffix)
        os.rename(output, target)
        target.chmod(0o600)
        result["cleaned"] = True
        result["output_size"] = info.st_size
    return result


def main():
    protocol = os.dup(sys.stdout.fileno())
    with open(os.devnull, "wb") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    result = {"ok": False, "error": "The file is malformed, encrypted or unsupported."}
    try:
        if (
            len(sys.argv) != 3
            or sys.argv[1] not in {"inspect", "clean"}
            or sys.argv[2] not in FORMATS
        ):
            raise WorkerError("The metadata request is invalid.")
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        contained()
        install_filter()
        result = run_job(
            Path("/input/source" + sys.argv[2]), Path("/work"), sys.argv[2], sys.argv[1]
        )
    except WorkerError as error:
        result = {"ok": False, "error": str(error)}
    except (Exception, SystemExit):
        pass
    data = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
    if len(data) > MAX_REPORT:
        data = b'{"ok":false,"error":"The metadata report exceeds its limit."}\n'
    with os.fdopen(protocol, "wb") as stream:
        stream.write(data)
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
