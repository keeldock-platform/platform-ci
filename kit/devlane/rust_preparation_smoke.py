"""Linux-only public registry and offline Cargo compatibility proof."""

import argparse
import json
import os
from pathlib import Path
import resource
import re
import signal
import subprocess
import sys
import tempfile
import time

import bundle
import constraint_resolver
import deadline
import project
import rust_preparation_v2


SMOKE_PHASES = frozenset((
    "smoke-argument-parse", "smoke-linux-check", "smoke-deadline-check",
    "smoke-temp-create", "smoke-projection-envelope", "smoke-projection-write",
    "smoke-prepare-run", "smoke-fixture-create", "smoke-tool-root",
    "smoke-tool-bind", "smoke-tool-seal", "smoke-offline-run",
    "smoke-registry-record", "smoke-lock-check", "smoke-cleanup-unmount",
    "smoke-cleanup-remove", "smoke-protocol",
))
SMOKE_PHASE = "smoke-argument-parse"
SMOKE_FAILURE_PHASE = None
SMOKE_CLEANUP_UNCONFIRMED = False
SMOKE_CLEANUP_UNMOUNT = "not-started"
SMOKE_CLEANUP_FDS = 0
SMOKE_CLEANUP_TREE = "not-started"
SMOKE_CHILD_REAP = "confirmed"
SMOKE_CHILD_PROCESS = None
SMOKE_CHILD_PROCESS_GROUP = None
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
_CLEANUP_TREE_SCRIPT = (
    "import os, shutil, stat, sys\n"
    "path = sys.argv[1]\n"
    "try:\n"
    "    metadata = os.lstat(path)\n"
    "    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():\n"
    "        raise SystemExit(2)\n"
    "    shutil.rmtree(path)\n"
    "except OSError as error:\n"
    "    number = error.errno if type(error.errno) is int and 0 <= error.errno <= 9999 else 0\n"
    "    sys.stdout.write('cleanup-errno=%d\\n' % number)\n"
    "    raise SystemExit(3)\n"
)
_CLEANUP_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}


def set_smoke_phase(phase):
    global SMOKE_PHASE
    SMOKE_PHASE = phase if phase in SMOKE_PHASES else "smoke-protocol"


def failure_diagnostic(error):
    global_status = ""
    if isinstance(error, bundle.Refusal):
        code = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else "unclassified"
        code = code if re.fullmatch(r"[a-z][a-z0-9-]{0,79}", code) else "unclassified"
    elif isinstance(error, OSError):
        number = error.errno if type(error.errno) is int and error.errno >= 0 else 0
        code = "unexpected-filesystem-" + (SMOKE_FAILURE_PHASE or SMOKE_PHASE) + "-errno-" + str(number)
    else:
        code = "unexpected-" + rust_preparation_v2.failure_code(error)
    if SMOKE_CHILD_REAP != "confirmed":
        global_status += "-children-" + SMOKE_CHILD_REAP
    if SMOKE_CLEANUP_UNCONFIRMED:
        global_status += ("-cleanup-unmount-" + SMOKE_CLEANUP_UNMOUNT
                          + "-fds-" + str(SMOKE_CLEANUP_FDS)
                          + "-tree-" + SMOKE_CLEANUP_TREE)
    code += global_status
    return code


def _error_number(error):
    value = getattr(error, "errno", None)
    return value if type(value) is int and 0 <= value <= 9999 else 0


def _cleanup_exception_status(error):
    if isinstance(error, OSError):
        return "errno-" + str(_error_number(error))
    return "unexpected"


def _process_group_alive(process_group):
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return None
    return True


def _reap_group_children(process_group, exclude_pid=None):
    reaped = False
    while True:
        try:
            observed = os.waitid(
                os.P_PGID, process_group, os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            break
        except OSError:
            return None
        if observed is None or observed.si_pid == 0:
            break
        child = observed.si_pid
        if child == exclude_pid:
            break
        try:
            reaped_pid, _status = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            continue
        except OSError:
            return None
        if reaped_pid == 0:
            break
        reaped = True
    return reaped


def _hard_cleanup_remaining(deadline_file):
    value = deadline._read(deadline_file)
    return max(0.0, value["work_deadline"] + value["cleanup_reserve"] - time.monotonic()), min(
        float(deadline.KILL_REAP_SECONDS), float(value["cleanup_reserve"]),
    )


def _stop_and_reap_group(process_group, deadline_file, process=None):
    """Stop only the dedicated child group and confirm it no longer holds mounts."""
    process_pid = getattr(process, "pid", process_group) if process is not None else None
    if process is not None:
        try:
            direct_status = process.poll()
        except (OSError, subprocess.SubprocessError):
            return "unconfirmed"
    else:
        direct_status = 0
    state = _process_group_alive(process_group)
    if state is False:
        return "confirmed" if direct_status is not None else "unconfirmed"
    if state is None:
        return "unconfirmed"
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        if process is None:
            return "confirmed"
        try:
            return "confirmed" if process.poll() is not None else "unconfirmed"
        except (OSError, subprocess.SubprocessError):
            return "unconfirmed"
    except OSError:
        return "unconfirmed"
    try:
        remaining, kill_reserve = _hard_cleanup_remaining(deadline_file)
        term_budget = min(1.0, max(0.0, remaining - kill_reserve))
    except (deadline.DeadlineRefusal, OSError, ValueError):
        kill_reserve = 0.0
        term_budget = 0.0
    term_end = time.monotonic() + max(0.0, term_budget)
    while time.monotonic() < term_end:
        if process is not None:
            try:
                process.poll()
            except (OSError, subprocess.SubprocessError):
                return "unconfirmed"
        if _reap_group_children(process_group, process_pid) is None:
            return "unconfirmed"
        state = _process_group_alive(process_group)
        if state is False:
            return "reaped"
        if state is None:
            return "unconfirmed"
        time.sleep(min(0.05, max(0.0, term_end - time.monotonic())))
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        return "unconfirmed"
    try:
        remaining, available_reserve = _hard_cleanup_remaining(deadline_file)
        reap_budget = min(float(deadline.KILL_REAP_SECONDS), available_reserve, remaining)
    except (deadline.DeadlineRefusal, OSError, ValueError):
        reap_budget = 0.0
    reap_end = time.monotonic() + max(0.0, reap_budget)
    while True:
        if process is not None:
            try:
                process.poll()
            except (OSError, subprocess.SubprocessError):
                return "unconfirmed"
        if _reap_group_children(process_group, process_pid) is None:
            return "unconfirmed"
        state = _process_group_alive(process_group)
        if state is False:
            return "reaped"
        if state is None or time.monotonic() >= reap_end:
            return "unconfirmed"
        time.sleep(min(0.05, max(0.0, reap_end - time.monotonic())))


def _mountpoints_beneath(root):
    """Read exact mountpoints from procfs without exposing names in diagnostics."""
    try:
        with Path("/proc/self/mountinfo").open("rb") as source:
            payload = source.read(MAX_MOUNTINFO_BYTES + 1)
    except OSError as error:
        return None, "errno-" + str(_error_number(error))
    if len(payload) > MAX_MOUNTINFO_BYTES:
        return None, "size"
    try:
        text = payload.decode("ascii", "strict")
    except UnicodeDecodeError:
        return None, "encoding"
    root = Path(root)
    mounts = []
    for line in text.splitlines():
        fields = line.split()
        separator = fields.index("-") if "-" in fields else -1
        if (len(fields) < 10 or separator < 6 or separator + 3 >= len(fields)
                or not fields[0].isdecimal() or not fields[1].isdecimal()
                or not re.fullmatch(r"[0-9]+:[0-9]+", fields[2])):
            return None, "shape"
        raw = fields[4]
        try:
            decoded = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), raw)
            mountpoint = Path(decoded)
        except (ValueError, OSError):
            return None, "encoding"
        if mountpoint == root or mountpoint.is_relative_to(root):
            mounts.append(mountpoint)
    return tuple(mounts), "ok"


def _mount_fd_count(target):
    """Count this process's descriptors and cwd/root/exe references below target."""
    target = Path(target)
    try:
        descriptors = os.listdir("/proc/self/fd")
    except OSError:
        return None
    references = descriptors + ["cwd", "root", "exe"]
    count = 0
    prefix = str(target) + "/"
    for descriptor in references:
        try:
            destination = os.readlink("/proc/self/fd/" + descriptor)
        except FileNotFoundError:
            continue
        except OSError:
            return None
        if destination.endswith(" (deleted)"):
            destination = destination[:-10]
        if destination == str(target) or destination.startswith(prefix):
            count += 1
    return min(count, 999)


def _bounded_cleanup_command(argv, deadline_file, *, timeout_cap=30, capture_errno=False):
    try:
        timeout = min(timeout_cap, deadline.cleanup_remaining(deadline_file))
    except (deadline.DeadlineRefusal, OSError, ValueError):
        return "budget"
    if timeout <= 0:
        return "budget"
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_errno else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_CLEANUP_ENVIRONMENT, close_fds=True, start_new_session=True,
        )
    except OSError as error:
        return "errno-" + str(_error_number(error))
    try:
        output, _errors = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        state = _stop_and_reap_group(process.pid, deadline_file, process)
        return "timeout" if state in ("confirmed", "reaped") else "reap-unconfirmed"
    except (OSError, subprocess.SubprocessError):
        state = _stop_and_reap_group(process.pid, deadline_file, process)
        return "process-error" if state in ("confirmed", "reaped") else "reap-unconfirmed"
    returncode = process.returncode
    if type(returncode) is not int:
        return "process-unconfirmed"
    state = _process_group_alive(process.pid)
    if state is True:
        state = _stop_and_reap_group(process.pid, deadline_file, process)
        if state == "unconfirmed":
            return "reap-unconfirmed"
        return "children-remained"
    if state is None:
        return "reap-unconfirmed"
    if returncode == 0:
        return "ok" if not capture_errno or output == b"" else "output-invalid"
    if capture_errno and (type(output) is not bytes or len(output) > 32):
        return "output-invalid"
    if capture_errno and returncode == 3 and type(output) is bytes:
        match = re.fullmatch(rb"cleanup-errno=([0-9]{1,4})\n", output)
        if match:
            return "errno-" + match[1].decode("ascii")
        if output:
            return "output-invalid"
    return ("signal-" + str(abs(returncode))) if returncode < 0 else ("exit-" + str(returncode))


def run(argv, root, stage, deadline_file, environment):
    global SMOKE_CHILD_REAP, SMOKE_CHILD_PROCESS, SMOKE_CHILD_PROCESS_GROUP
    run_phases = {
        "prepare": "smoke-prepare-run", "tool-bind": "smoke-tool-bind",
        "tool-seal": "smoke-tool-seal", "offline": "smoke-offline-run",
    }
    set_smoke_phase(run_phases.get(stage, "smoke-protocol"))
    log = root / (stage + ".log")
    timeout = deadline.remaining(deadline_file)
    with log.open("xb") as output:
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 256 * 1024 * 1024))
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                 env=environment, close_fds=True, start_new_session=True,
                                 preexec_fn=limits)
        process_group = getattr(child, "pid", None)
        if type(process_group) is int and process_group > 1:
            SMOKE_CHILD_PROCESS = child
            SMOKE_CHILD_PROCESS_GROUP = process_group
        try:
            result = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            SMOKE_CHILD_REAP = (
                _stop_and_reap_group(process_group, deadline_file, child)
                if type(process_group) is int and process_group > 1 else "unconfirmed"
            )
            if SMOKE_CHILD_REAP in ("confirmed", "reaped"):
                SMOKE_CHILD_PROCESS = None
                SMOKE_CHILD_PROCESS_GROUP = None
            raise bundle.Refusal("rust-preparation-smoke-timeout")
        if type(process_group) is int and process_group > 1:
            group_state = _process_group_alive(process_group)
            if group_state is True:
                SMOKE_CHILD_REAP = _stop_and_reap_group(process_group, deadline_file, child)
                if SMOKE_CHILD_REAP in ("confirmed", "reaped"):
                    SMOKE_CHILD_PROCESS = None
                    SMOKE_CHILD_PROCESS_GROUP = None
                if SMOKE_CHILD_REAP not in ("confirmed", "reaped"):
                    raise bundle.Refusal("rust-preparation-smoke-child-reap-unconfirmed")
                raise bundle.Refusal("rust-preparation-smoke-child-group-remained")
            if group_state is None:
                SMOKE_CHILD_REAP = "unconfirmed"
                raise bundle.Refusal("rust-preparation-smoke-child-reap-unconfirmed")
            SMOKE_CHILD_REAP = "confirmed"
            SMOKE_CHILD_PROCESS = None
            SMOKE_CHILD_PROCESS_GROUP = None
    if result != 0 or log.stat().st_size > 4 * 1024 * 1024:
        with log.open("rb") as source:
            code = rust_preparation_v2.diagnostic_code(source.read(1024 * 1024 + 1))
        raise bundle.Refusal("rust-preparation-smoke-" + stage + ("-" + code if code else ""))


def smoke(args, root):
    set_smoke_phase("smoke-projection-envelope")
    envelope = constraint_resolver.build_constraint_envelope(
        source_commit=bundle.CORE_RUST_SOURCE_REVISION, control_sha=args.control_sha,
        constraints=[{"id": "d000001", "package": "serde", "version_req": "^1.0"}])
    baseline = constraint_resolver.build_constraint_envelope(
        source_commit=bundle.CORE_RUST_BASELINE_REVISION, control_sha=args.control_sha,
        constraints=[], resolver_version="3", allow_empty=True)
    projection = project.build_projection({
        "schema": 2, "profile": "core-rust", "control_sha": args.control_sha,
        "tools": {"cargo": "1.99.1", "rustc": "1.99.1"},
        "source_sets": bundle._expected_core_rust_source_sets(),
        "manifest_constraints": {"candidate": envelope, "baseline_runtime": baseline}})
    projection_path = root / "projection.json"
    set_smoke_phase("smoke-projection-write")
    projection_path.write_bytes(projection)
    prepared = root / "prepared"
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
    run([sys.executable, "-B", str(Path(__file__).with_name("prepare.py")),
         "--projection", str(projection_path), "--output", str(prepared), "--profile", "core-rust",
         "--control-sha", args.control_sha, "--deadline-file", args.deadline_file,
         "--owner-uid", str(args.owner_uid), "--owner-gid", str(args.owner_gid),
         "--cargo-path", args.cargo_path, "--rustc-path", args.rustc_path],
        root, "prepare", args.deadline_file, env)
    crate = root / "offline-project"
    set_smoke_phase("smoke-fixture-create")
    crate.mkdir(mode=0o755)
    (crate / "src").mkdir(mode=0o755)
    (crate / "src/lib.rs").write_bytes(b"pub fn public_fixture() {}\n")
    (crate / "Cargo.toml").write_bytes(
        b'[package]\nname="public-registry-proof"\nversion="0.0.0"\nedition="2024"\n'
        b'[dependencies]\nserde="^1.0"\n')
    home = root / "cargo-home"
    home.mkdir(mode=0o755)
    for path in (crate, crate / "src", crate / "src/lib.rs", crate / "Cargo.toml", home):
        os.chown(path, 65534, 65534)
    tools = root / "toolchain"
    set_smoke_phase("smoke-tool-root")
    tools.mkdir(mode=0o755)
    original_tools = Path(args.cargo_path).resolve(strict=True).parent.parent
    if Path(args.rustc_path).resolve(strict=True).parent.parent != original_tools:
        raise bundle.Refusal("rust-preparation-smoke-tool-layout")
    set_smoke_phase("smoke-tool-bind")
    run(["/usr/bin/mount", "--bind", str(original_tools), str(tools)],
        root, "tool-bind", args.deadline_file, env)
    set_smoke_phase("smoke-tool-seal")
    run(["/usr/bin/mount", "-o", "remount,bind,ro,nosuid,nodev", str(tools)],
        root, "tool-seal", args.deadline_file, env)
    command = ["/usr/bin/unshare", "--net", "--fork", "/usr/bin/setpriv",
               "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs",
               "--bounding-set=-all", "--", str(tools / "bin/cargo"), "generate-lockfile", "--offline",
               "--manifest-path", str(crate / "Cargo.toml"),
               "--config", 'source.crates-io.replace-with="prepared-registry"',
               "--config", 'source.prepared-registry.local-registry=' + json.dumps(
                   str(prepared / "cargo-local-registry")),
               "--config", "net.offline=true", "--config", "net.retry=0"]
    set_smoke_phase("smoke-offline-run")
    run(command, root, "offline", args.deadline_file,
        dict(env, CARGO_HOME=str(home), HOME=str(home), RUSTC=str(tools / "bin/rustc"),
             LD_LIBRARY_PATH=str(tools / "lib"),
             CARGO_NET_OFFLINE="true"))
    set_smoke_phase("smoke-registry-record")
    record = bundle.strict_json((prepared / "registry-preparation.json").read_bytes(), 4 * 1024 * 1024)
    available = {tuple(row[key] for key in ("name", "version", "checksum")) for row in record["packages"]}
    set_smoke_phase("smoke-lock-check")
    rows = constraint_resolver.lock_package_rows((crate / "Cargo.lock").read_bytes())
    if not rows or any(tuple(row[key] for key in ("name", "version", "checksum")) not in available for row in rows):
        raise bundle.Refusal("rust-preparation-smoke-lock-binding")


def _cleanup_root(root, deadline_file):
    global SMOKE_CLEANUP_UNMOUNT, SMOKE_CLEANUP_FDS, SMOKE_CLEANUP_TREE
    global SMOKE_CHILD_REAP, SMOKE_CHILD_PROCESS, SMOKE_CHILD_PROCESS_GROUP
    set_smoke_phase("smoke-cleanup-unmount")
    if SMOKE_CHILD_PROCESS_GROUP is not None:
        child_state = _stop_and_reap_group(
            SMOKE_CHILD_PROCESS_GROUP, deadline_file, SMOKE_CHILD_PROCESS,
        )
        SMOKE_CHILD_REAP = child_state
        if child_state in ("confirmed", "reaped"):
            SMOKE_CHILD_PROCESS = None
            SMOKE_CHILD_PROCESS_GROUP = None
        else:
            SMOKE_CLEANUP_UNMOUNT = "children-" + child_state
            SMOKE_CLEANUP_TREE = "skipped-unsafe"
            return
    elif SMOKE_CHILD_REAP == "unconfirmed":
        SMOKE_CLEANUP_UNMOUNT = "children-unconfirmed"
        SMOKE_CLEANUP_TREE = "skipped-unsafe"
        return
    mountpoints, mountinfo_state = _mountpoints_beneath(root)
    toolchain = root / "toolchain"
    if mountpoints is None:
        SMOKE_CLEANUP_UNMOUNT = "mountinfo-" + mountinfo_state
        SMOKE_CLEANUP_TREE = "skipped-unsafe"
        return
    if any(path != toolchain for path in mountpoints):
        SMOKE_CLEANUP_UNMOUNT = "unexpected-mounts-" + str(min(len(mountpoints), 99))
        SMOKE_CLEANUP_TREE = "skipped-unsafe"
        return
    if toolchain in mountpoints:
        SMOKE_CLEANUP_FDS = _mount_fd_count(toolchain)
        if SMOKE_CLEANUP_FDS is None:
            SMOKE_CLEANUP_FDS = 999
        unmount = _bounded_cleanup_command(
            ["/usr/bin/umount", "--", str(toolchain)], deadline_file,
        )
        after_unmount, after_state = _mountpoints_beneath(root)
        if after_unmount is None:
            SMOKE_CLEANUP_UNMOUNT = "verify-" + after_state
            SMOKE_CLEANUP_TREE = "skipped-unsafe"
            return
        if after_unmount:
            if any(path != toolchain for path in after_unmount):
                SMOKE_CLEANUP_UNMOUNT = "unexpected-postmounts-" + str(min(len(after_unmount), 99))
                SMOKE_CLEANUP_TREE = "skipped-unsafe"
                return
            if unmount == "ok":
                SMOKE_CLEANUP_UNMOUNT = "still-mounted-" + str(min(len(after_unmount), 99))
            else:
                SMOKE_CLEANUP_UNMOUNT = "umount-" + unmount + "-mounted-" + str(
                    min(len(after_unmount), 99))
            SMOKE_CLEANUP_TREE = "skipped-mounted"
            return
        if unmount in ("reap-unconfirmed", "process-unconfirmed"):
            SMOKE_CLEANUP_UNMOUNT = "released-helper-unconfirmed"
            SMOKE_CLEANUP_TREE = "skipped-unsafe"
            return
        SMOKE_CLEANUP_UNMOUNT = "released"
    else:
        SMOKE_CLEANUP_UNMOUNT = "not-mounted"

    set_smoke_phase("smoke-cleanup-remove")
    remove = _bounded_cleanup_command(
        [sys.executable, "-I", "-S", "-B", "-c", _CLEANUP_TREE_SCRIPT, str(root)],
        deadline_file, capture_errno=True,
    )
    if remove != "ok":
        SMOKE_CLEANUP_TREE = remove
    elif os.path.lexists(root):
        SMOKE_CLEANUP_TREE = "verify-remains"
    else:
        SMOKE_CLEANUP_TREE = "removed"


def main(argv=None):
    global SMOKE_CLEANUP_UNCONFIRMED, SMOKE_FAILURE_PHASE
    global SMOKE_CLEANUP_UNMOUNT, SMOKE_CLEANUP_FDS, SMOKE_CLEANUP_TREE, SMOKE_CHILD_REAP
    global SMOKE_CHILD_PROCESS, SMOKE_CHILD_PROCESS_GROUP
    SMOKE_CLEANUP_UNCONFIRMED = False
    SMOKE_FAILURE_PHASE = None
    SMOKE_CLEANUP_UNMOUNT = "not-started"
    SMOKE_CLEANUP_FDS = 0
    SMOKE_CLEANUP_TREE = "not-started"
    SMOKE_CHILD_REAP = "confirmed"
    SMOKE_CHILD_PROCESS = None
    SMOKE_CHILD_PROCESS_GROUP = None
    set_smoke_phase("smoke-argument-parse")
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-path", required=True)
    parser.add_argument("--rustc-path", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--deadline-file", required=True)
    parser.add_argument("--owner-uid", type=int, required=True)
    parser.add_argument("--owner-gid", type=int, required=True)
    args = parser.parse_args(argv)
    set_smoke_phase("smoke-linux-check")
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise bundle.Refusal("linux-root-required")
    set_smoke_phase("smoke-deadline-check")
    deadline.remaining(args.deadline_file)
    root = None
    primary_error = None
    try:
        set_smoke_phase("smoke-temp-create")
        root = Path(tempfile.mkdtemp(prefix="public-registry-proof-", dir="/tmp"))
        os.chmod(root, 0o755)
        smoke(args, root)
    except BaseException as error:
        primary_error = error
        SMOKE_FAILURE_PHASE = SMOKE_PHASE
    finally:
        if root is not None:
            try:
                _cleanup_root(root, args.deadline_file)
            except BaseException as error:
                if SMOKE_PHASE == "smoke-cleanup-remove":
                    SMOKE_CLEANUP_TREE = "error-" + _cleanup_exception_status(error)
                else:
                    SMOKE_CLEANUP_UNMOUNT = "error-" + _cleanup_exception_status(error)
                    if SMOKE_CLEANUP_TREE == "not-started":
                        SMOKE_CLEANUP_TREE = "skipped-unsafe"
        if root is not None:
            SMOKE_CLEANUP_UNCONFIRMED = not (
                SMOKE_CLEANUP_UNMOUNT in ("released", "not-mounted")
                and SMOKE_CLEANUP_TREE == "removed"
            )
        if primary_error is None and SMOKE_CLEANUP_UNCONFIRMED:
            primary_error = bundle.Refusal("rust-preparation-smoke-cleanup")
            SMOKE_FAILURE_PHASE = SMOKE_PHASE
    if primary_error is not None:
        raise primary_error
    print("rust_preparation_v2_public_smoke=pass")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except bundle.Refusal as error:
        print("rust_preparation_v2_public_smoke=refused code=" + failure_diagnostic(error))
        raise SystemExit(2)
    except Exception as error:
        print("rust_preparation_v2_public_smoke=refused code=" + failure_diagnostic(error))
        raise SystemExit(2)
