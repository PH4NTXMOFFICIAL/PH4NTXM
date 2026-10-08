# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from pathlib import PurePosixPath
import re
import unicodedata

INPUT_MAGIC = b"PH4ARI01"
LIST_MAGIC = b"PH4ARL01"
DATA_MAGIC = b"PH4ARD01"
ERROR_MAGIC = b"PH4ARE01"
END_MAGIC = b"PH4AREN1"
ACK_MAGIC = b"PH4ARA01"
LIST_INDEX = 0xFFFFFFFF
MAX_INPUT = 128 * 1024 * 1024
MAX_OUTPUT = 128 * 1024 * 1024
MAX_ENTRIES = 1000
MAX_NAME = 1024
MAX_METADATA = 2 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
GUEST_RAM_MIB = 512
TIMEOUT = 180
ARCHIVE_SUFFIXES = (".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar.xz", ".txz", ".tar.zst", ".tzst")
DOCUMENT_SUFFIXES = {".pdf", ".doc", ".docx", ".odt", ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".odp", ".odg", ".rtf"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg", ".svgz", ".ico", ".icns", ".tga", ".xbm", ".xpm", ".pbm", ".pgm", ".ppm", ".pnm"}
MEDIA_SUFFIXES = {".mp4", ".mkv", ".webm", ".mov", ".avi", ".mpeg", ".mpg", ".ts", ".ogv", ".flv", ".wmv", ".mp3", ".m4a", ".flac", ".ogg", ".wav"}
TEXT_SUFFIXES = {".txt", ".csv", ".log", ".md"}


def safe_name(value):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_NAME:
        return False
    if "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        return False
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value):
        return False
    parts = value.rstrip("/").split("/")
    return bool(parts) and all(part and part not in {".", ".."} for part in parts)


def viewer_kind(name):
    suffix = PurePosixPath(name).suffix.lower()
    for kind, suffixes in (("document", DOCUMENT_SUFFIXES), ("image", IMAGE_SUFFIXES), ("media", MEDIA_SUFFIXES), ("text", TEXT_SUFFIXES)):
        if suffix in suffixes:
            return kind
    return None
