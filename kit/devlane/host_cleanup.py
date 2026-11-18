"""Remove coordinator-side runner scratch after the isolated supervisor exits."""

import argparse
import os
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
MAX_PROC_INVENTORY = 100000
MAX_PROC_CMDLINE_BYTES = 65536


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
    _deadline_check(deadline_file)
    pid_file = state / "host-pid"
    if not pid_file.exists():
        return
    try:
        with pid_file.open("rb") as pid_handle:
            raw_bytes = pid_handle.read(11)
        raw = raw_bytes.decode("ascii", "strict")
        if not raw.isdecimal() or len(raw_bytes) > 10:
            _fail("process-alive")
        pid = int(raw)
        command = Path("/proc") / str(pid) / "cmdline"
        with command.open("rb") as command_handle:
            cmdline = command_handle.read(MAX_PROC_CMDLINE_BYTES + 1).replace(b"\x00", b" ")
        if len(cmdline) > MAX_PROC_CMDLINE_BYTES:
            _fail("process-alive")
        _deadline_check(deadline_file)
        if b"kit/devlane/supervisor.py" not in cmdline or b"_serve" not in cmdline:
            _fail("process-alive")
        subprocess.run(["sudo", "-n", "kill", "--", "-" + str(pid)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=_cleanup_timeout(deadline_file, 5), check=False,
                       env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        deadline = time.monotonic() + _cleanup_timeout(deadline_file, 5)
        while time.monotonic() < deadline:
            _deadline_check(deadline_file)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)
        _fail("process-alive")
    except (OSError, subprocess.SubprocessError, ValueError):
        _fail("process-alive")


def _same_path(left, right):
    try:
        return os.path.realpath(left) == os.path.realpath(right)
    except (OSError, ValueError):
        return left == right


def _supervisor_serves_state(command, state):
    if type(command) is not bytes:
        return False
    arguments = command.rstrip(b"\x00").split(b"\x00")
    script_indexes = [index for index, argument in enumerate(arguments)
                      if argument.rsplit(b"/", 1)[-1] == b"supervisor.py"]
    if (len(script_indexes) != 1 or script_indexes[0] + 1 >= len(arguments)
            or arguments[script_indexes[0] + 1] != b"_serve"):
        return False
    state_values = []
    index = script_indexes[0] + 2
    while index < len(arguments):
        argument = arguments[index]
        if argument == b"--state-dir":
            if index + 1 >= len(arguments):
                return False
            state_values.append(arguments[index + 1])
            index += 2
            continue
        if argument.startswith(b"--state-dir="):
            state_values.append(argument.partition(b"=")[2])
        index += 1
    if not state_values:
        return False
    expected_state = os.fsencode(str(state))
    return any(_same_path(value, expected_state) for value in state_values)


def _deadline_check(deadline_file):
    _cleanup_timeout(deadline_file, HOST_DEADLINE_SECONDS)


def _cleanup_deadline_cutoff(deadline_file):
    try:
        value = deadline_budget._read(deadline_file)
    except (OSError, deadline_budget.DeadlineRefusal, ValueError, UnicodeError):
        _fail("process-alive")
    return value["work_deadline"] + value["cleanup_reserve"] - min(
        deadline_budget.KILL_REAP_SECONDS, value["cleanup_reserve"])


def _supervisor_present(state, deadline_file):
    _deadline_check(deadline_file)
    entries_seen = 0
    found = False
    try:
        process_entries = os.scandir(PROC_ROOT)
    except OSError:
        _fail("process-alive")
    try:
        with process_entries:
            for entry in process_entries:
                _deadline_check(deadline_file)
                if not entry.name.isdecimal():
                    continue
                entries_seen += 1
                if entries_seen > MAX_PROC_INVENTORY:
                    _fail("process-alive")
                try:
                    with (PROC_ROOT / entry.name / "cmdline").open("rb") as command_file:
                        command = command_file.read(MAX_PROC_CMDLINE_BYTES + 1)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except OSError:
                    _fail("process-alive")
                if len(command) > MAX_PROC_CMDLINE_BYTES:
                    _fail("process-alive")
                if _supervisor_serves_state(command, state):
                    found = True
                    break
    except OSError:
        _fail("process-alive")
    _deadline_check(deadline_file)
    return found


SUPERVISOR_EXIT_SETTLE_SECONDS = 3


def _confirm_supervisor_absent(state, deadline_file):
    """A just-killed supervisor may still be exiting; wait briefly for this state's process only."""
    settle = time.monotonic() + _cleanup_timeout(deadline_file, SUPERVISOR_EXIT_SETTLE_SECONDS)
    while _supervisor_present(state, deadline_file):
        now = time.monotonic()
        if now >= settle:
            _fail("process-alive")
        try:
            cleanup_remaining = deadline_budget.cleanup_remaining(deadline_file)
        except deadline_budget.DeadlineRefusal:
            _fail("process-alive")
        time.sleep(min(0.1, settle - now, cleanup_remaining))
    _deadline_check(deadline_file)
    if os.path.ismount(state / "namespace-root"):
        _fail("umount-busy")
    _deadline_check(deadline_file)


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


def clean_node_vendor_source(snapshot_id, *, control_uid=0, deadline_file=None):
    if not node_tool_snapshot.valid_snapshot_id(snapshot_id):
        _fail()
    if deadline_file:
        _deadline_check(deadline_file)
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
    owned_tree_cleanup.remove_owned_tree(
        area, base, prefix="node-vendor-cleanup-",
        deadline_check=(lambda: _deadline_check(deadline_file)) if deadline_file else None,
    )
    if deadline_file:
        _deadline_check(deadline_file)
    if area.exists() or area.is_symlink():
        _fail()
    return True


def clean(root_arg, runner_temp, deadline_file, node_snapshot_id="", node_vendor_id=""):
    root = Path(root_arg)
    base = Path(runner_temp)
    deadline_cutoff = _cleanup_deadline_cutoff(deadline_file)
    deadline_path = Path(deadline_file)
    if not root.is_absolute() or not base.is_absolute() or root.parent != base:
        _fail()
    if root.name != "devlane-" + os.environ.get("GITHUB_RUN_ID", ""):
        _fail()
    if root.is_symlink():
        _fail()
    if not root.exists():
        _confirm_supervisor_absent(root / "state", deadline_file)
        if node_snapshot_id:
            clean_node_snapshot(node_snapshot_id, deadline_file)
        if node_vendor_id:
            clean_node_vendor_source(node_vendor_id, deadline_file=deadline_file)
        _deadline_check(deadline_file)
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
    _confirm_supervisor_absent(state, deadline_file)
    prepared = root / "prepared"
    if prepared.exists() or prepared.is_symlink():
        if prepared.is_symlink():
            _fail()
        owned_tree_cleanup.remove_owned_tree(
            prepared, root, prefix="prepared-cleanup-", deadline_check=lambda: _deadline_check(deadline_file),
        )
        _deadline_check(deadline_file)
    if prepared.exists() or prepared.is_symlink():
        _fail("tree-remove")
    if node_snapshot_id:
        clean_node_snapshot(node_snapshot_id, deadline_file)
    if node_vendor_id:
        clean_node_vendor_source(node_vendor_id, deadline_file=deadline_file)
    _deadline_check(deadline_file)
    last_name = None
    if deadline_path.parent == root and deadline_path.name == "deadline.json":
        last_name = deadline_path.name

    def final_tree_deadline_check():
        if last_name is not None and not deadline_path.exists():
            if time.monotonic() >= deadline_cutoff:
                _fail("process-alive")
            return
        _deadline_check(deadline_file)

    try:
        owned_tree_cleanup.remove_owned_tree(
            root, base, prefix="runner-cleanup-", deadline_check=final_tree_deadline_check,
            last_name=last_name,
        )
    except RuntimeError as error:
        if getattr(error, "cleanup_reason", ""):
            raise
        if "deadline" in str(error):
            _fail("process-alive")
        _fail("tree-remove")
    if root.exists() or root.is_symlink():
        _fail("tree-remove")
    if time.monotonic() >= deadline_cutoff:
        _fail("process-alive")
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
