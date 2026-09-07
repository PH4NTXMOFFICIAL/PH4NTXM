import sys
import os
import time
import signal
import threading
from ph4ntxm_opsec_shredder import shredder as sh

RESET = "\033[0m"
BOLD = "\033[1m"
PH4NTXM_CYAN = "\033[38;2;0;171;255m"
PH4NTXM_MAGENTA = "\033[38;2;255;61;251m"
GREEN = "\033[38;2;68;209;122m"
AMBER = "\033[38;2;255;176;32m"
RED = "\033[38;2;255;77;90m"
GRAY = "\033[38;2;165;175;195m"

_shred_start_time = None
_current_path = ""
_current_progress = 0
_stop_spinner = False

HELP_TEXT = f"""
{PH4NTXM_CYAN}{BOLD}PH4NTXM OPSEC SHREDDER{RESET}

{GRAY}Best-effort file overwrite and deletion tool.
Supports recursive directory processing and metadata renaming.{RESET}

{PH4NTXM_MAGENTA}USAGE:{RESET}
  {GREEN}ph4-shred m <path>{RESET}          {GRAY}Mark file/folder for shredding{RESET}
  {GREEN}ph4-shred u <path>{RESET}          {GRAY}Unmark a path{RESET}
  {GREEN}ph4-shred ua{RESET}                {GRAY}Unmark ALL paths{RESET}
  {GREEN}ph4-shred l{RESET}                 {GRAY}List all marked paths{RESET}

  {GREEN}ph4-shred s [OPTIONS]{RESET}       {GRAY}Execute overwrite and deletion{RESET}

{PH4NTXM_MAGENTA}OPTIONS:{RESET}
  {GREEN}--pass N{RESET}   {GRAY}Overwrite passes (1–7, default: 3){RESET}
  {GREEN}--info{RESET}       {GRAY}Show storage reliability limitations{RESET}

{PH4NTXM_MAGENTA}OVERWRITE LOGIC:{RESET}
{GRAY}- Pass 1: Zero Fill (0x00)
- Pass 2: One Fill (0xFF)
- Pass 3+: OS Entropy Random Data
- Metadata: up to 3 random renames before deletion

No userspace overwrite can guarantee physical erasure on SSD, flash,
copy-on-write, journaled, compressed, remote or wear-levelled storage.{RESET}
"""

def signal_handler(sig, frame):
    global _stop_spinner
    _stop_spinner = True
    sys.stdout.write(f"\n{RED}Process interrupted. Current target may be incomplete.{RESET}\n")
    sys.exit(130)

signal.signal(signal.SIGINT, signal_handler)

def spinner_thread():
    global _stop_spinner, _current_path, _current_progress, _shred_start_time
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not _stop_spinner:
        if _shred_start_time and _current_path:
            elapsed = time.time() - _shred_start_time
            speed = _current_progress / elapsed if elapsed > 0 else 0
            eta = (100 - _current_progress) / speed if speed > 0 else 0
            eta_str = f"{int(eta // 60):02d}:{int(eta % 60):02d}"
            basename = os.path.basename(_current_path)
            if len(basename) > 20: basename = basename[:17] + "..."
            
            sys.stdout.write(
                f"\r{PH4NTXM_MAGENTA}{chars[idx % len(chars)]}{RESET} {GRAY}Shredding {PH4NTXM_CYAN}{basename:<20}{RESET} "
                f"{GRAY}|{RESET} {_current_progress:>3}% "
                f"{GRAY}| Speed:{RESET} {speed:.1f}%/s "
                f"{GRAY}| ETA:{RESET} {AMBER}{eta_str}{RESET} "
            )
            sys.stdout.flush()
            idx += 1
        time.sleep(0.08)

def progress_bar(path, progress):
    global _shred_start_time, _current_path, _current_progress
    _current_path = path
    _current_progress = progress
    if _shred_start_time is None:
        _shred_start_time = time.time()
    if progress >= 100:
        time.sleep(0.1)
        print()
        _shred_start_time = None

def _norm(p):
    return os.path.normpath(os.path.abspath(os.path.expanduser(p)))

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h"):
        print(HELP_TEXT); return
    cmd = args[0]
    if cmd == "m" and len(args) > 1:
        path = _norm(args[1])
        if sh.mark(path): print(f"{GREEN}Marked:{RESET} {path}")
        else: print(f"{RED}Error marking:{RESET} {path}")
    elif cmd == "u" and len(args) > 1:
        path = _norm(args[1])
        if sh.unmark(path): print(f"Unmarked: {path}")
        else: print(f"Not marked: {path}")
    elif cmd == "l":
        files = sh.list_marks()
        if files:
            print(f"{PH4NTXM_MAGENTA}Marked for destruction:{RESET}")
            for f in files: print(f"  {f}")
        else: print("No paths marked.")
    elif cmd == "ua":
        confirm = input(f"Clear all marked paths? (y/N): {RESET}")
        if confirm.lower() == 'y':
            sh.unmark_all()
            print(f"{GREEN}Queue cleared.{RESET}") 
        else:
            print("Operation cancelled.")
    elif cmd == "s":
        files = sh.list_marks()
        if not files:
            print("Queue empty."); return
        passes = 3
        info = False
        i = 1
        while i < len(args):
            if args[i].startswith("--pass="):
                try:
                    passes = int(args[i].split("=", 1)[1])
                except ValueError:
                    print(f"{RED}Invalid pass count.{RESET}")
                    return
            elif args[i] == "--pass":
                if i + 1 >= len(args):
                    print(f"{RED}Missing pass count.{RESET}")
                    return
                try:
                    passes = int(args[i + 1])
                except ValueError:
                    print(f"{RED}Invalid pass count.{RESET}")
                    return
                i += 1
            elif args[i] == "--info": info = True
            i += 1
        if not 1 <= passes <= sh.MAX_PASSES:
            print(f"{RED}Pass count must be between 1 and {sh.MAX_PASSES}.{RESET}")
            return
        if info:
            print(
                f"{AMBER}Storage note:{RESET} Overwrite success confirms logical writes only; "
                "physical remapped or historical blocks may remain on SSD, flash, COW and "
                "journaled storage. Full-device encryption and key disposal are stronger.\n"
            )
        confirm = input(f"{RED}{BOLD}DANGER:{RESET} Destroy {len(files)} path(s)? (y/N): ")
        if confirm.lower() == "y":
            global _stop_spinner
            _stop_spinner = False
            t = threading.Thread(target=spinner_thread, daemon=True)
            t.start()
            try:
                results = sh.shred_all(passes=passes, progress_callback=progress_bar)
            finally:
                _stop_spinner = True
                t.join()
            print(f"\n{PH4NTXM_MAGENTA}Execution Report:{RESET}")
            for r in results:
                status, path = r[0], r[1]
                if status in ("shredded", "shredded_dir"):
                    print(f"{GREEN}[OK]{RESET} {path}")
                elif status == "missing":
                    print(f"{AMBER}[MISSING]{RESET} {path}")
                else:
                    msg = r[2] if len(r) > 2 else "Error"
                    print(f"  {RED}[FAIL]{RESET} {path} ({msg})")
            failures = sum(1 for result in results if result[0] == "error")
            if failures:
                print(f"\n{AMBER}Shred completed with {failures} failure(s).{RESET}")
            else:
                print(f"\n{GREEN}Shred complete.{RESET}")
        else:
            print("Operation cancelled.")
    else:
        print("Invalid command.")

if __name__ == "__main__":
    main()
