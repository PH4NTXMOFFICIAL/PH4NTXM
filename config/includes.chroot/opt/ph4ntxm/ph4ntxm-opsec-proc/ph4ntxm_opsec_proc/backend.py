# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import argparse
import json
import os

from ph4ntxm_opsec_proc import checks, remediation
from ph4ntxm_opsec_proc.report import collect_report


class BackendParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def positive_integer(value):
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("A positive integer is required") from error
    if number <= 0:
        raise argparse.ArgumentTypeError("A positive integer is required")
    return number


def apply_action(action, pid, start_time_ticks):
    if os.geteuid() != 0:
        return remediation.result(False, error="Administrator access is required")
    if action not in remediation.PROCESS_ACTIONS:
        return remediation.result(False, error="Unknown process action")
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 1
        or not isinstance(start_time_ticks, int)
        or isinstance(start_time_ticks, bool)
        or start_time_ticks <= 0
    ):
        return remediation.result(False, error="A valid process identity is required")
    current = checks.get_process_info(pid)
    if not isinstance(current, dict):
        return remediation.result(False, error="The selected process is unavailable")
    if current.get("start_time_ticks") != start_time_ticks:
        return remediation.result(
            False, error="The selected process identity changed; action cancelled"
        )
    analysis = checks.analyze_processes(
        checks.result(True, data={"processes": [current]})
    )
    if not analysis["ok"]:
        return remediation.result(
            False, error=analysis.get("error") or "Current findings are unavailable"
        )
    candidates = analysis["data"].get("suspicious", [])
    target = next((proc for proc in candidates if proc.get("pid") == pid), None)
    if target is None or action not in remediation.available_actions(target):
        return remediation.result(
            False, error="The action is no longer allowed for this process"
        )
    if target.get("start_time_ticks") != start_time_ticks:
        return remediation.result(
            False, error="Current process identity is unavailable"
        )
    return remediation.PROCESS_ACTIONS[action]["action"](target)


def main(argv=None):
    parser = BackendParser(prog="ph4ntxm-opsec-proc-backend")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("report")
    action_parser = commands.add_parser("action")
    action_parser.add_argument("action", choices=tuple(remediation.PROCESS_ACTIONS))
    action_parser.add_argument("pid", type=positive_integer)
    action_parser.add_argument("start_time_ticks", type=positive_integer)
    try:
        arguments = parser.parse_args(argv)
        if os.geteuid() != 0:
            outcome = remediation.result(
                False, error="Administrator access is required"
            )
        else:
            outcome = (
                {"ok": True, **collect_report()}
                if arguments.command == "report"
                else apply_action(
                    arguments.action, arguments.pid, arguments.start_time_ticks
                )
            )
    except Exception as error:
        outcome = remediation.result(False, error=str(error))
    print(json.dumps(outcome, ensure_ascii=True))
    return 0 if outcome.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
