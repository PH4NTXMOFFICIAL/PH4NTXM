# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import argparse
import json
import os
import sys

from ph4ntxm_opsec_radio import checks
from ph4ntxm_opsec_radio.remediation import REMEDIATIONS
from ph4ntxm_opsec_radio.report import RADIO_ACTIONS, collect_report


class ActionParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def apply_action(name):
    definition = RADIO_ACTIONS.get(name)
    if definition is None:
        return {"ok": False, "error": "Unknown radio action."}
    if os.geteuid() != 0:
        return {"ok": False, "error": "Radio actions require administrator access."}
    try:
        outcome = getattr(checks, definition["check"])()
        if not outcome["ok"]:
            return {
                "ok": False,
                "error": "The current radio state could not be verified: "
                + (outcome.get("error") or "Check failed."),
            }
        current = set(outcome.get("findings", []))
        if not current.intersection(definition["findings"]):
            return {
                "ok": False,
                "error": "This action is no longer applicable. Check the report again.",
            }
        remediation = REMEDIATIONS[definition["remediation"]]
        outcome = remediation["action"]()
        return {
            "ok": bool(outcome["ok"]),
            "action": name,
            "message": outcome.get("message") or remediation["label"],
            "error": outcome.get("error"),
        }
    except Exception as exc:
        return {"ok": False, "action": name, "error": str(exc)}


def main(argv=None):
    parser = ActionParser(prog="ph4ntxm-opsec-radio-backend")
    parser.add_argument("action", choices=("report", *RADIO_ACTIONS))
    try:
        args = parser.parse_args(argv)
        if args.action == "report":
            if os.geteuid() != 0:
                outcome = {
                    "ok": False,
                    "error": "Radio reports require administrator access.",
                }
            else:
                outcome = {"ok": True, **collect_report()}
        else:
            outcome = apply_action(args.action)
    except Exception as exc:
        outcome = {"ok": False, "error": str(exc)}
    print(json.dumps(outcome))
    return 0 if outcome["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
