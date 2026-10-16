# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import unicodedata

MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 128 * 1024 * 1024
MAX_MEMORY = 512 * 1024 * 1024
MAX_FIELDS = 512
MAX_TEXT = 512
MAX_REPORT = 1024 * 1024
FORMATS = {
    ".jpg": "image",
    ".jpeg": "image",
    ".png": "image",
    ".gif": "image",
    ".tif": "image",
    ".tiff": "image",
    ".svg": "image",
    ".heic": "image",
    ".pdf": "document",
    ".docx": "document",
    ".xlsx": "document",
    ".pptx": "document",
    ".odt": "document",
    ".ods": "document",
    ".odp": "document",
    ".odg": "document",
    ".epub": "document",
    ".zip": "archive",
    ".tar": "archive",
    ".tar.gz": "archive",
    ".tgz": "archive",
    ".tar.bz2": "archive",
    ".tbz2": "archive",
    ".tar.xz": "archive",
    ".txz": "archive",
    ".mp3": "audio",
    ".flac": "audio",
    ".ogg": "audio",
    ".opus": "audio",
    ".wav": "audio",
    ".aif": "audio",
    ".aiff": "audio",
    ".mp4": "video",
    ".avi": "video",
    ".wmv": "video",
}


def suffix_for(name):
    lower = str(name).lower()
    for suffix in sorted(FORMATS, key=len, reverse=True):
        if lower.endswith(suffix):
            return suffix
    raise ValueError("This file extension is not supported by Metadata Cleaner.")


def validate_report(data, operation):
    if not isinstance(data, dict) or type(data.get("ok")) is not bool:
        raise ValueError("The metadata worker returned an invalid response.")
    if not data["ok"]:
        text = data.get("error")
        if not isinstance(text, str) or len(text) > 512:
            raise ValueError("The metadata worker could not process this file.")
        raise ValueError(text)
    if (
        data.get("kind") not in set(FORMATS.values())
        or not isinstance(data.get("mime"), str)
        or len(data["mime"]) > 256
        or type(data.get("cleaned")) is not bool
        or data["cleaned"] != (operation == "clean")
        or type(data.get("output_size")) is not int
        or not 0 <= data["output_size"] <= MAX_OUTPUT
        or (data["cleaned"] and not data["output_size"])
        or (not data["cleaned"] and data["output_size"])
    ):
        raise ValueError("The metadata worker returned invalid file details.")
    for key in ("before", "after"):
        rows = data.get(key)
        if not isinstance(rows, list) or len(rows) > MAX_FIELDS:
            raise ValueError("The metadata worker report exceeds its field limit.")
        for row in rows:
            if (
                not isinstance(row, list)
                or len(row) != 2
                or any(
                    not isinstance(value, str) or len(value) > MAX_TEXT for value in row
                )
                or any(
                    unicodedata.category(c) in {"Cc", "Cf", "Cs"}
                    for value in row
                    for c in value
                )
            ):
                raise ValueError("The metadata worker returned invalid fields.")
        if type(data.get(key + "_truncated")) is not bool:
            raise ValueError(
                "The metadata worker returned an invalid truncation state."
            )
    return data
