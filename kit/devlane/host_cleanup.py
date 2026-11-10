"""Remove coordinator-side runner scratch after the isolated supervisor exits."""

import argparse
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import isolated_cleanup


"""The client must always be able to finish its bounded recovery path before this deadline."""
HOST_DEADLINE_SECONDS = isolated_cleanup.CLEANUP_BUDGET_SECONDS + 30


def _fail():
    raise RuntimeError("cleanup-incomplete")


def _kill_incomplete_supervisor(state):
    pid_file = state / "host-pid"
    if not pid_file.exists():
        return
    try:
        raw = pid_file.read_text(encoding="ascii")
        if not raw.isdecimal() or len(raw) > 10:
            _fail()
        pid = int(raw)
        command = Path("/proc") / str(pid) / "cmdline"
        cmdline = command.read_bytes().replace(b"\x00", b" ")
        if b"kit/devlane/supervisor.py" not in cmdline or b"_serve" not in cmdline:
            _fail()
        subprocess.run(["sudo", "-n", "kill", "--", "-" + str(pid)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5, check=False,
                       env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)
        _fail()
    except (OSError, subprocess.SubprocessError, ValueError):
        _fail()


def clean(root_arg, runner_temp):
    root = Path(root_arg)
    base = Path(runner_temp)
    if not root.is_absolute() or not base.is_absolute() or root.parent != base:
        _fail()
    if root.name != "devlane-" + os.environ.get("GITHUB_RUN_ID", ""):
        _fail()
    if root.is_symlink():
        _fail()
    if not root.exists():
        print("cleanup_receipt=confirmed")
        return
    state = root / "state"
    ready = state / "ready.json"
    if ready.is_file() or (state / "host-pid").is_file():
        control = Path(os.environ.get("GITHUB_WORKSPACE", ".")) / "kit/devlane/isolated_cleanup.py"
        result = subprocess.run(
            ["sudo", "-n", sys.executable, "-I", "-S", "-B", str(control),
             "--state-dir", str(state)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=HOST_DEADLINE_SECONDS, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if result.returncode != 0 or result.stdout.count(b"cleanup_receipt=confirmed") != 1:
            _fail()
    else:
        _kill_incomplete_supervisor(state)
    try:
        shutil.rmtree(root)
    except OSError:
        _fail()
    if root.exists() or root.is_symlink():
        _fail()
    print("cleanup_receipt=confirmed")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--runner-temp", required=True)
    args = parser.parse_args(argv)
    try:
        clean(args.root, args.runner_temp)
        return 0
    except Exception:
        print("cleanup_receipt=unconfirmed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
