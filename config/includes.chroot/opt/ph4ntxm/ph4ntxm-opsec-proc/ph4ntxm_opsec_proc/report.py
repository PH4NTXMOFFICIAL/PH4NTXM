# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime, timezone
import os

from ph4ntxm_opsec_proc import checks
from ph4ntxm_opsec_proc.remediation import available_actions


def collect_report(progress=None):
    if progress:
        progress("Reading current processes")
    processes = checks.list_processes()
    if progress:
        progress("Analyzing process evidence")
    analysis = checks.analyze_processes(processes)
    if progress:
        progress("Assessing process visibility")
    assessment = checks.assess_system(analysis)
    unavailable = []
    for name, outcome in (
        ("Process enumeration", processes),
        ("Process analysis", analysis),
        ("System assessment", assessment),
    ):
        if not outcome["ok"]:
            unavailable.append(
                f"{name} is unavailable: {outcome.get('error') or 'No error details'}"
            )
        unavailable.extend(str(item) for item in outcome.get("warnings", []))
    listed = processes["data"].get("processes", [])
    identities_missing = sum(
        proc.get("start_time_ticks") is None for proc in listed
    )
    if identities_missing:
        noun = "process" if identities_missing == 1 else "processes"
        unavailable.append(
            f"Process identity is unavailable for {identities_missing} {noun}."
        )
    suspicious = analysis["data"].get("suspicious", [])
    actions = {
        str(proc["pid"]): (
            available_actions(proc)
            if proc.get("start_time_ticks") is not None and proc["pid"] > 1
            else []
        )
        for proc in suspicious
    }
    return {
        "processes": processes,
        "analysis": analysis,
        "assessment": assessment,
        "actions": actions,
        "privileged": os.geteuid() == 0,
        "unavailable": list(dict.fromkeys(unavailable)),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
