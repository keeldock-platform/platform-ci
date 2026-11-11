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
import owned_tree_cleanup
import deadline as deadline_budget
import node_tool_snapshot


"""The client must always be able to finish its bounded recovery path before this deadline."""
HOST_DEADLINE_SECONDS = isolated_cleanup.CLEANUP_BUDGET_SECONDS + 30
PROC_ROOT = Path("/proc")


def _fail():
    raise RuntimeError("cleanup-incomplete")


def _cleanup_timeout(deadline_file, cap):
    if not deadline_file:
        _fail()
    try:
        return min(cap, deadline_budget.cleanup_remaining(deadline_file))
    except deadline_budget.DeadlineRefusal:
        _fail()


def _kill_incomplete_supervisor(state, deadline_file):
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
                       stderr=subprocess.DEVNULL, timeout=_cleanup_timeout(deadline_file, 5), check=False,
                       env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        deadline = time.monotonic() + _cleanup_timeout(deadline_file, 5)
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)
        _fail()
    except (OSError, subprocess.SubprocessError, ValueError):
        _fail()


def _confirm_supervisor_absent(state):
    try:
        process_ids = [entry.name for entry in PROC_ROOT.iterdir() if entry.name.isdecimal()]
    except OSError:
        _fail()
    for process_id in process_ids:
        try:
            command = (PROC_ROOT / process_id / "cmdline").read_bytes()
        except FileNotFoundError:
            continue
        except OSError:
            _fail()
        if b"supervisor.py" in command and b"_serve" in command:
            _fail()
    if os.path.ismount(state / "namespace-root"):
        _fail()


def clean_node_snapshot(snapshot_id, deadline_file):
    if not node_tool_snapshot.valid_snapshot_id(snapshot_id):
        _fail()
    control = Path(__file__).resolve(strict=True)
    result = subprocess.run(
        ["sudo", "-n", sys.executable, "-B", str(control), "--snapshot-only",
         "--node-snapshot-id", snapshot_id, "--owner-uid", str(os.getuid()),
         "--deadline-file", str(Path(deadline_file).resolve(strict=True))],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=_cleanup_timeout(deadline_file, HOST_DEADLINE_SECONDS), check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if result.returncode != 0 or result.stdout != b"node_snapshot_cleanup=confirmed\n":
        _fail()
    return True


def clean(root_arg, runner_temp, deadline_file, node_snapshot_id=""):
    root = Path(root_arg)
    base = Path(runner_temp)
    if not root.is_absolute() or not base.is_absolute() or root.parent != base:
        _fail()
    if root.name != "devlane-" + os.environ.get("GITHUB_RUN_ID", ""):
        _fail()
    if root.is_symlink():
        _fail()
    if not root.exists():
        _confirm_supervisor_absent(root / "state")
        if node_snapshot_id:
            clean_node_snapshot(node_snapshot_id, deadline_file)
        print("cleanup_receipt=confirmed")
        return
    try:
        root_metadata = root.stat()
        base_metadata = base.stat()
    except OSError:
        _fail()
    if (not stat.S_ISDIR(root_metadata.st_mode) or root_metadata.st_uid != os.getuid()
            or not stat.S_ISDIR(base_metadata.st_mode) or base_metadata.st_uid != os.getuid()):
        _fail()
    state = root / "state"
    if state.is_symlink() or (state.exists() and not state.is_dir()):
        _fail()
    ready = state / "ready.json"
    if ready.is_file() or (state / "host-pid").is_file():
        control = Path(os.environ.get("GITHUB_WORKSPACE", ".")) / "kit/devlane/isolated_cleanup.py"
        result = subprocess.run(
            ["sudo", "-n", sys.executable, "-I", "-S", "-B", str(control),
             "--state-dir", str(state)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=_cleanup_timeout(deadline_file, HOST_DEADLINE_SECONDS), check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if result.returncode != 0 or result.stdout.count(b"cleanup_receipt=confirmed") != 1:
            _fail()
    else:
        _kill_incomplete_supervisor(state, deadline_file)
    _confirm_supervisor_absent(state)
    prepared = root / "prepared"
    if prepared.exists() or prepared.is_symlink():
        if prepared.is_symlink():
            _fail()
        owned_tree_cleanup.remove_owned_tree(prepared, root, prefix="prepared-cleanup-")
    if prepared.exists() or prepared.is_symlink():
        _fail()
    if node_snapshot_id:
        clean_node_snapshot(node_snapshot_id, deadline_file)
    try:
        shutil.rmtree(root)
    except OSError:
        _fail()
    if root.exists() or root.is_symlink():
        _fail()
    print("cleanup_receipt=confirmed")


def _argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="")
    parser.add_argument("--runner-temp", default="")
    parser.add_argument("--deadline-file", required=True)
    parser.add_argument("--node-snapshot-id", default="")
    parser.add_argument("--owner-uid", type=int)
    parser.add_argument("--snapshot-only", action="store_true")
    return parser


def main(argv=None):
    parser = _argument_parser()
    args = parser.parse_args(argv)
    if args.snapshot_only:
        if not args.node_snapshot_id:
            parser.error("the following arguments are required: --node-snapshot-id")
        if args.owner_uid is None:
            parser.error("the following arguments are required: --owner-uid")
    else:
        if not args.root:
            parser.error("the following arguments are required: --root")
        if not args.runner_temp:
            parser.error("the following arguments are required: --runner-temp")
    try:
        if args.snapshot_only:
            if os.geteuid() != 0:
                _fail()
            node_tool_snapshot.remove_snapshot(
                args.node_snapshot_id, args.deadline_file, owner_uid=args.owner_uid,
            )
            print("node_snapshot_cleanup=confirmed")
            return 0
        if not args.root or not args.runner_temp:
            _fail()
        clean(args.root, args.runner_temp, args.deadline_file, args.node_snapshot_id)
        return 0
    except Exception:
        print("cleanup_receipt=unconfirmed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
