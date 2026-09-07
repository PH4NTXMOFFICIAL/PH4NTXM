import os
import errno

SEVERITY = {
    "memfd_execution": 40,
    "deleted_executable": 30,
    "ephemeral_executable": 25,
    "untrusted_executable_path": 15,
    "suspicious_processes_present": 10,
    "process_masquerading": 35,
    "detached_shell": 30,
    "hidden_process_detected": 0,
    "process_visibility_mismatch": 30,
}

TRUSTED_PATH_PREFIXES = (
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/libexec/",
    "/opt/",
)

SYSTEM_NAMES = ("kworker", "ksoftirqd", "kthreadd", "migration")
SHELL_NAMES = ("bash", "sh", "zsh")


def result(ok, data=None, error=None, warnings=None, evidence=None, findings=None):
    return {
        "ok": ok,
        "data": data or {},
        "error": error,
        "warnings": warnings or [],
        "evidence": evidence or [],
        "findings": findings or [],
    }


def safe_read(path, binary=False):
    try:
        mode = "rb" if binary else "r"
        with open(path, mode) as handle:
            return handle.read()
    except Exception:
        return None


def get_process_info(pid):
    base = f"/proc/{pid}"

    try:
        comm = safe_read(f"{base}/comm")
        cmdline_raw = safe_read(f"{base}/cmdline", binary=True)
        status = safe_read(f"{base}/status")
        stat = safe_read(f"{base}/stat")

        if not stat:
            return None

        exe = None

        try:
            exe = os.readlink(f"{base}/exe")
        except Exception:
            pass

        cmdline = ""

        if cmdline_raw:
            try:
                cmdline = (
                    cmdline_raw
                    .replace(b"\x00", b" ")
                    .decode(errors="ignore")
                    .strip()
                )
            except Exception:
                pass

        uid = None

        if status:
            for line in status.splitlines():
                if line.startswith("Uid:"):
                    parts = line.split()

                    if len(parts) >= 2:
                        try:
                            uid = int(parts[1])
                        except ValueError:
                            uid = None

        close_paren = stat.rfind(")")
        stat_parts = stat[close_paren + 1:].strip().split() if close_paren >= 0 else []

        ppid = None
        state = None

        start_time_ticks = None
        if len(stat_parts) >= 20:
            state = stat_parts[0]
            try:
                ppid = int(stat_parts[1])
                start_time_ticks = int(stat_parts[19])
            except ValueError:
                ppid = None
                start_time_ticks = None

        return {
            "pid": int(pid),
            "ppid": ppid,
            "name": comm.strip() if comm else None,
            "cmdline": cmdline,
            "exe": exe,
            "uid": uid,
            "state": state,
            "start_time_ticks": start_time_ticks,
        }

    except (FileNotFoundError, ProcessLookupError, PermissionError) as e:
        return f"Error getting process info for {pid}: {str(e)}"

    except Exception as e:
        return f"Error in get_process_info: {str(e)}"


def list_processes():
    processes = []

    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue

            proc = get_process_info(entry)

            if isinstance(proc, dict):
                processes.append(proc)
            else:
                pass

        return result(
            True,
            data={"processes": sorted(processes, key=lambda x: x["pid"])}
        )

    except Exception as exc:
        return result(False, error=f"Error listing processes: {str(exc)}")


def is_audit_parent(ppid):
    try:
        with open(f"/proc/{ppid}/cmdline", "rb") as f:
            cmd = (
                f.read()
                .replace(b"\x00", b" ")
                .decode(errors="ignore")
                .lower()
            )

        return cmd.startswith("ph4ntxm-")

    except Exception:
        return False


def analyze_processes(process_data):
    if not process_data["ok"]:
        return process_data

    suspicious = []

    for proc in process_data["data"].get("processes", []):
        reasons = []

        exe = proc.get("exe") or ""
        name = (proc.get("name") or "").lower()
        uid = proc.get("uid")
        ppid = proc.get("ppid")
        cmdline = (proc.get("cmdline") or "").lower()

        if exe:

            if exe.startswith(("/tmp/", "/dev/shm/")):
                reasons.append("ephemeral_executable")

            if exe.endswith(" (deleted)"):
                reasons.append("deleted_executable")

            if "memfd:" in exe or "memfd:" in cmdline:
                reasons.append("memfd_execution")

            if not exe.startswith(TRUSTED_PATH_PREFIXES):
                reasons.append("untrusted_executable_path")

        if any(sn in name for sn in SYSTEM_NAMES):

            if exe or (uid is not None and uid != 0):
                reasons.append("process_masquerading")

        if name in SHELL_NAMES and ppid == 1:

            suspicious_shell = False

            if exe.endswith(" (deleted)"):
                suspicious_shell = True

            if "memfd:" in exe or "memfd:" in cmdline:
                suspicious_shell = True

            if exe.startswith(("/tmp/", "/dev/shm/")):
                suspicious_shell = True

            if exe and not exe.startswith(TRUSTED_PATH_PREFIXES):
                suspicious_shell = True

            if suspicious_shell and not is_audit_parent(ppid):
                reasons.append("detached_shell")

        if reasons:
            proc_copy = dict(proc)
            proc_copy["reasons"] = reasons
            suspicious.append(proc_copy)

    return result(True, data={"suspicious": suspicious})


def find_visibility_mismatches():
    mismatches = []

    try:
        proc_pids = {
            int(p)
            for p in os.listdir("/proc")
            if p.isdigit()
        }

    except Exception:
        return []

    for pid in proc_pids:

        try:
            os.stat(f"/proc/{pid}")

        except FileNotFoundError:

            try:
                os.kill(pid, 0)
                if os.path.exists(f"/proc/{pid}"):
                    continue
                mismatches.append(pid)

            except OSError as err:
                if err.errno == errno.EPERM:
                    if os.path.exists(f"/proc/{pid}"):
                        continue
                    mismatches.append(pid)

    return mismatches

def find_hidden_pids():
    return find_visibility_mismatches()


def assess_system(process_analysis):
    if not process_analysis["ok"]:
        return process_analysis

    findings = []
    score = 100

    suspicious = process_analysis["data"].get("suspicious", [])

    if suspicious:
        findings.append("suspicious_processes_present")

    for proc in suspicious:
        findings.extend(proc.get("reasons", []))

    mismatches = find_visibility_mismatches()

    if mismatches:
        findings.append("hidden_process_detected")
        findings.append("process_visibility_mismatch")

    findings = sorted(set(findings))

    for f in findings:
        score -= SEVERITY.get(f, 0)

    score = max(0, min(100, score))

    return result(
        True,
        data={
            "score": score,
            "hidden_pids": mismatches,
            "visibility_mismatch_pids": mismatches,
            "findings": findings,
        },
        findings=findings
    )
