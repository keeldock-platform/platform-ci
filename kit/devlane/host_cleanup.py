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
import diagnostic_contract
import node_tool_snapshot
import node_vendor_source


"""The 14-minute child cap leaves one minute inside the workflow's 15-minute cleanup watchdog."""
HOST_DEADLINE_SECONDS = 840
PROC_ROOT = Path("/proc")


def _fail(reason="tree-remove"):
    error = RuntimeError("cleanup-incomplete")
    error.cleanup_reason = reason if reason in diagnostic_contract.CLEANUP_SUBREASONS else ""
    raise error


def _isolated_cleanup_reason(stderr):
    if type(stderr) is not bytes or len(stderr) > 256:
        return ""
    lines = stderr.splitlines()
    if len(lines) != 2 or not lines[0].startswith(b"cleanup_reason=") \
            or lines[1] != b"cleanup_receipt=unconfirmed":
        return ""
    try:
        value = lines[0].partition(b"=")[2].decode("ascii", "strict")
    except UnicodeDecodeError:
        return ""
    return value if value in diagnostic_contract.CLEANUP_SUBREASONS else ""


def _cleanup_timeout(deadline_file, cap):
    if not deadline_file:
        _fail("process-alive")
    try:
        return min(cap, deadline_budget.cleanup_remaining(deadline_file))
    except deadline_budget.DeadlineRefusal:
        _fail("process-alive")


def _kill_incomplete_supervisor(state, deadline_file):
    pid_file = state / "host-pid"
    if not pid_file.exists():
        return
    try:
        raw = pid_file.read_text(encoding="ascii")
        if not raw.isdecimal() or len(raw) > 10:
            _fail("process-alive")
        pid = int(raw)
        command = Path("/proc") / str(pid) / "cmdline"
        cmdline = command.read_bytes().replace(b"\x00", b" ")
        if b"kit/devlane/supervisor.py" not in cmdline or b"_serve" not in cmdline:
            _fail("process-alive")
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
        _fail("process-alive")
    except (OSError, subprocess.SubprocessError, ValueError):
        _fail("process-alive")


def _confirm_supervisor_absent(state):
    try:
        process_ids = [entry.name for entry in PROC_ROOT.iterdir() if entry.name.isdecimal()]
    except OSError:
        _fail("process-alive")
    for process_id in process_ids:
        try:
            command = (PROC_ROOT / process_id / "cmdline").read_bytes()
        except FileNotFoundError:
            continue
        except OSError:
            _fail("process-alive")
        if b"supervisor.py" in command and b"_serve" in command:
            _fail("process-alive")
    if os.path.ismount(state / "namespace-root"):
        _fail("umount-busy")


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
    if result.returncode != 0 or result.stdout != (
            b"node_snapshot_cleanup=confirmed\nnode_vendor_cleanup=confirmed\n"):
        _fail("tree-remove")
    return True


def clean_node_vendor_source(snapshot_id, *, control_uid=0):
    if not node_tool_snapshot.valid_snapshot_id(snapshot_id):
        _fail()
    base = node_vendor_source.PROTECTED_BASE
    area = base / snapshot_id
    try:
        base_metadata = os.lstat(base)
    except FileNotFoundError:
        return True
    except OSError:
        _fail("tree-remove")
    if (not stat.S_ISDIR(base_metadata.st_mode) or stat.S_ISLNK(base_metadata.st_mode)
            or base_metadata.st_uid != control_uid or stat.S_IMODE(base_metadata.st_mode) & 0o022):
        _fail()
    try:
        metadata = os.stat(area, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        _fail()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != control_uid:
        _fail()
    owned_tree_cleanup.remove_owned_tree(area, base, prefix="node-vendor-cleanup-")
    if area.exists() or area.is_symlink():
        _fail()
    return True


def clean(root_arg, runner_temp, deadline_file, node_snapshot_id="", node_vendor_id=""):
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
        if node_vendor_id:
            clean_node_vendor_source(node_vendor_id)
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
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=_cleanup_timeout(deadline_file, HOST_DEADLINE_SECONDS), check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if result.returncode != 0 or result.stdout.count(b"cleanup_receipt=confirmed") != 1:
            _fail(_isolated_cleanup_reason(result.stderr) or "process-alive")
    else:
        _kill_incomplete_supervisor(state, deadline_file)
    _confirm_supervisor_absent(state)
    prepared = root / "prepared"
    if prepared.exists() or prepared.is_symlink():
        if prepared.is_symlink():
            _fail()
        owned_tree_cleanup.remove_owned_tree(prepared, root, prefix="prepared-cleanup-")
    if prepared.exists() or prepared.is_symlink():
        _fail("tree-remove")
    if node_snapshot_id:
        clean_node_snapshot(node_snapshot_id, deadline_file)
    if node_vendor_id:
        clean_node_vendor_source(node_vendor_id)
    try:
        shutil.rmtree(root)
    except OSError:
        _fail("tree-remove")
    if root.exists() or root.is_symlink():
        _fail("tree-remove")
    print("cleanup_receipt=confirmed")


def _argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="")
    parser.add_argument("--runner-temp", default="")
    parser.add_argument("--deadline-file", required=True)
    parser.add_argument("--node-snapshot-id", default="")
    parser.add_argument("--node-vendor-id", default="")
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
            clean_node_vendor_source(args.node_vendor_id or args.node_snapshot_id)
            print("node_snapshot_cleanup=confirmed")
            print("node_vendor_cleanup=confirmed")
            return 0
        if not args.root or not args.runner_temp:
            _fail()
        clean(args.root, args.runner_temp, args.deadline_file, args.node_snapshot_id,
              args.node_vendor_id)
        return 0
    except Exception as error:
        reason = getattr(error, "cleanup_reason", "")
        if reason in diagnostic_contract.CLEANUP_SUBREASONS:
            print("cleanup_reason=" + reason, file=sys.stderr)
        print("cleanup_receipt=unconfirmed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
