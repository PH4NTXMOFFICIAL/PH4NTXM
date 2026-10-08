# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime, timezone
import os
import stat

from ph4ntxm_opsec_shredder import shredder as sh

STORAGE_LIMITATIONS = (
    "Best-effort overwrite and deletion cannot guarantee physical erasure on SSD, "
    "flash, copy-on-write, journaled, compressed, remote or wear-levelled storage."
)


def describe_target(path):
    try:
        evidence = os.lstat(path)
    except FileNotFoundError:
        return {"path": path, "kind": "Unavailable", "state": "Missing", "detail": "Path no longer exists"}
    except OSError as error:
        return {"path": path, "kind": "Unavailable", "state": "Unavailable", "detail": str(error)}
    if stat.S_ISLNK(evidence.st_mode):
        kind = "Symbolic link"
        detail = "The link itself is removed; its target is not followed"
    elif stat.S_ISREG(evidence.st_mode):
        kind = "File"
        detail = f"{evidence.st_size:,} bytes"
    elif stat.S_ISDIR(evidence.st_mode):
        kind = "Folder"
        detail = "Recursive overwrite and deletion of folder contents"
    else:
        return {"path": path, "kind": "Special file", "state": "Unsupported", "detail": "The backend refuses unsupported file types"}
    return {"path": path, "kind": kind, "state": "Marked", "detail": detail}


def collect_report(progress=None, passes=sh.DEFAULT_PASSES, last_run=None):
    if progress is not None:
        progress("Reading marked paths")
    marked_paths = sh.list_marks()
    targets = [describe_target(path) for path in marked_paths]
    try:
        with open("/run/ph4ntxm/mode", "r", encoding="ascii") as handle:
            mode = handle.read().strip()
    except (OSError, UnicodeError):
        mode = None
    return {
        "mode": mode,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "marked_paths": marked_paths,
        "targets": targets,
        "passes": passes,
        "storage_limitations": STORAGE_LIMITATIONS,
        "last_run": last_run,
    }


def execution_summary(run):
    results = run.get("results", [])
    errors = sum(item[0] == "error" for item in results)
    missing = sum(item[0] == "missing" for item in results)
    completed = sum(item[0] in ("shredded", "shredded_dir") for item in results)
    detail = f"{completed} completed · {missing} missing · {errors} errors"
    if errors:
        return "Overwrite and deletion finished with errors", "bad", detail
    if missing:
        return "Overwrite and deletion finished with missing targets", "warn", detail
    return "Overwrite and deletion complete", "good", detail


def plain_report(report):
    lines = [
        "PH4NTXM OpSec Shredder",
        f"Collected: {report['collected_at']}",
        f"Overwrite passes: {report['passes']}",
        "",
        "Marked paths",
    ]
    for target in report["targets"]:
        lines.append(f"{target['path']} [{target['kind']}; {target['state']}] {target['detail']}")
    if not report["targets"]:
        lines.append("No paths marked")
    run = report.get("last_run")
    if run:
        title, status, detail = execution_summary(run)
        lines.extend(["", title, detail, f"Finished: {run['finished_at']}", f"Passes: {run['passes']}"])
        for result in run["results"]:
            message = result[2] if len(result) > 2 else ""
            lines.append(f"{result[0]}: {result[1]} {message}".rstrip())
    lines.extend(["", report["storage_limitations"]])
    return "\n".join(lines)
