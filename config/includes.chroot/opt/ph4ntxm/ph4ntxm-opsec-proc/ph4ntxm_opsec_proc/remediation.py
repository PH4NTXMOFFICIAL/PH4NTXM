import os
import signal
import time

TERMINATION_TIMEOUT = 3

def result(ok, message=None, error=None):
    return {
        "ok": ok,
        "message": message,
        "error": error
    }

def read_start_time(pid):
    try:
        with open(f"/proc/{int(pid)}/stat", "r") as handle:
            stat = handle.read()
        close_paren = stat.rfind(")")
        fields = stat[close_paren + 1:].strip().split()
        return int(fields[19]) if close_paren >= 0 and len(fields) >= 20 else None
    except (OSError, TypeError, ValueError):
        return None

def process_exists(pid, expected_start_time=None):

    try:
        pid = int(pid)

    except (TypeError, ValueError):
        return False

    try:
        os.kill(pid, 0)
    except PermissionError:
        pass
    except ProcessLookupError:
        return False
    except OSError:
        return False

    if expected_start_time is not None:
        return read_start_time(pid) == int(expected_start_time)

    return True

def get_child_processes(pid):

    try:
        pid = int(pid)

    except (TypeError, ValueError):
        return []

    children = set()

    try:
        process_map = {}
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat", "r") as handle:
                    stat = handle.read()
                close_paren = stat.rfind(")")
                fields = stat[close_paren + 1:].strip().split()
                child_pid = int(entry)
                parent_pid = int(fields[1])
                process_map.setdefault(parent_pid, []).append(child_pid)
            except (OSError, ValueError, IndexError):
                continue

        stack = [pid]

        while stack:

            current = stack.pop()

            for child in process_map.get(current, []):

                if child not in children:
                    children.add(child)
                    stack.append(child)

    except Exception:
        pass

    identities = []
    for child in sorted(children):
        start_time = read_start_time(child)
        if start_time is not None:
            identities.append({"pid": child, "start_time_ticks": start_time})
    return identities

def get_child_pids(pid):
    return [child["pid"] for child in get_child_processes(pid)]

def terminate_pid(pid, expected_start_time=None):

    try:
        pid = int(pid)

    except (TypeError, ValueError):

        return result(
            False,
            error="Invalid pid"
        )

    if pid <= 1:
        return result(False, error="Refusing to terminate kernel/init process")

    if expected_start_time is not None and read_start_time(pid) != int(expected_start_time):
        return result(False, error=f"Pid {pid} identity changed; action cancelled")

    if not process_exists(pid, expected_start_time):
        return result(
            True,
            message=f"Pid {pid} already exited"
        )

    try:
        os.kill(pid, signal.SIGTERM)

    except Exception as exc:
        return result(
            False,
            error=str(exc)
        )

    try:
        for _ in range(TERMINATION_TIMEOUT * 10):

            if not process_exists(pid, expected_start_time):
                if expected_start_time is not None and read_start_time(pid) is not None:
                    return result(False, error=f"Pid {pid} identity changed after SIGTERM")
                return result(
                    True,
                    message=f"Pid {pid} terminated"
                )

            time.sleep(0.1)

        if expected_start_time is not None and read_start_time(pid) != int(expected_start_time):
            return result(False, error=f"Pid {pid} identity changed; SIGKILL cancelled")
        os.kill(pid, signal.SIGKILL)

        return result(
            True,
            message=f"Pid {pid} force killed"
        )

    except Exception as exc:
        return result(
            False,
            error=str(exc)
        )

def terminate_process(proc):

    try:
        pid = int(proc.get("pid"))

    except (TypeError, ValueError):

        return result(
            False,
            error="Invalid pid"
        )

    return terminate_pid(pid, proc.get("start_time_ticks"))

def terminate_process_tree(proc):

    try:
        pid = int(proc.get("pid"))

    except (TypeError, ValueError):

        return result(
            False,
            error="Invalid pid"
        )

    expected_start_time = proc.get("start_time_ticks")
    if expected_start_time is not None and read_start_time(pid) != int(expected_start_time):
        return result(False, error=f"Pid {pid} identity changed; action cancelled")

    targets = get_child_processes(pid)
    targets.reverse()

    terminated = []

    for child in targets:
        child_pid = child["pid"]

        child_result = terminate_pid(child_pid, child.get("start_time_ticks"))

        if child_result["ok"]:
            terminated.append(str(child_pid))

    parent_result = terminate_pid(pid, expected_start_time)

    if not parent_result["ok"]:
        return parent_result

    if terminated:

        return result(
            True,
            message=(
                f"Process tree terminated "
                f"(children: {', '.join(terminated)})"
            )
        )

    return result(
        True,
        message="Process terminated"
    )

def freeze_process(proc):

    try:
        pid = int(proc.get("pid"))

    except (TypeError, ValueError):

        return result(
            False,
            error="Invalid pid"
        )

    try:
        if pid <= 1:
            return result(False, error="Refusing to freeze kernel/init process")

        expected_start_time = proc.get("start_time_ticks")
        if expected_start_time is not None and read_start_time(pid) != int(expected_start_time):
            return result(False, error=f"Pid {pid} identity changed; action cancelled")

        os.kill(pid, signal.SIGSTOP)

        return result(
            True,
            message=f"Pid {pid} frozen"
        )

    except Exception as exc:
        return result(
            False,
            error=str(exc)
        )

def available_actions(proc):

    reasons = set(proc.get("reasons", []))

    actions = []

    if reasons.intersection({
        "memfd_execution",
        "deleted_executable",
        "ephemeral_executable",
        "detached_shell",
        "untrusted_executable_path",
    }):

        actions.extend([
            "terminate",
            "terminate_tree",
            "freeze",
        ])

    return actions

PROCESS_ACTIONS = {
    "terminate": {
        "label": "Terminate Process",
        "description": "Send SIGTERM/SIGKILL to process",
        "severity": "bad",
        "action": terminate_process,
    },

    "terminate_tree": {
        "label": "Terminate Process Tree",
        "description": "Kill process and all child processes",
        "severity": "bad",
        "action": terminate_process_tree,
    },

    "freeze": {
        "label": "Freeze Process",
        "description": "Suspend process using SIGSTOP",
        "severity": "warn",
        "action": freeze_process,
    },
}
