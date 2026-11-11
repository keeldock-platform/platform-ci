"""Linux-only supervisor for the encrypted, offline development lane.

The public runner process controls this service over a root-owned, mode-0600
Unix socket. The workload root does not mount that socket, runner home,
GitHub command files, the host /proc, or any Actions credential path.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import bundle
import deadline as deadline_budget
import fetch
import filter as output_filter
import network_probe
import prepare as node_tool_prepare
import node_tool_snapshot


MAX_RPC = 32 * 1024
MAX_SUMMARY = output_filter.MAX_SUMMARY_BYTES
SOCKET_NAME = "control.sock"
READY_NAME = "ready.json"
PID_NAME = "host-pid"
STARTUP_REFUSAL_NAME = "startup-refusal.json"
WORKER_UID = 65534
WORKER_GID = 65534
PROFILE_FILE = "ci/devlane-profiles.json"
ACTIVE_CHILDREN = set()
ACTIVE_CHILDREN_LOCK = threading.Lock()
CANCEL_REQUESTED = threading.Event()
SERVICE_LOCK = threading.RLock()
MOUNT_TARGETS = []
ACTIVE_DEADLINE_FILE = ""

REFUSAL_CODES = frozenset((
    "allowlisted-file-too-large", "allowlisted-file-unavailable", "browser-profile-command",
    "bundle-binding-mismatch", "cargo-lock-binding-missing", "cargo-lock-projection-invalid",
    "cargo-projection-mismatch", "cargo-vendor-missing", "cargo-workspace-count-mismatch",
    "cargo-workspace-lock-set", "cargo-workspace-projection-invalid", "cargo-workspace-projection-mismatch",
    "cleanup-incomplete", "cleanup-process-remains", "cleanup-receipt-invalid", "cleanup-root-invalid",
    "control-operation-invalid", "control-protocol-size", "control-protocol-truncated",
    "control-request-invalid", "control-response-invalid", "deadline-file-invalid", "decrypt-key-unavailable",
    "decrypt-manifest-unavailable", "decrypt-order", "decrypt-rejected", "decrypt-timeout",
    "dispatch-context-invalid", "dispatch-context-unavailable", "execution-cancelled", "execution-order",
    "firewall-unavailable", "input-size", "input-unavailable", "key-invalid", "linux-root-required",
    "linux-runner-required", "mount-source-unavailable", "network-namespace-changed",
    "network-namespace-not-isolated", "network-probe-failed", "node-tool-layout",
    "node-snapshot-base-invalid", "node-snapshot-base-owner", "node-snapshot-base-unavailable",
    "node-snapshot-content-changed", "node-snapshot-content-invalid", "node-snapshot-deadline",
    "node-snapshot-id", "node-snapshot-layout", "node-snapshot-limit", "node-snapshot-link-invalid",
    "node-snapshot-manifest-invalid", "node-snapshot-missing", "node-snapshot-seal-invalid",
    "node-toolchain-executable", "node-toolchain-missing", "node-toolchain-owner",
    "node-toolchain-directory-control-access", "node-toolchain-directory-scan-access",
    "node-toolchain-file-control-access",
    "node-toolchain-version", "npm-lock-binding-missing",
    "node-toolchain-source-anchor-write-mode", "node-toolchain-source-cache-root-write-mode",
    "node-toolchain-source-root-anchor-write-mode", "node-toolchain-source-opt-anchor-write-mode",
    "node-toolchain-source-node-layout-write-mode", "node-toolchain-source-npm-layout-write-mode",
    "node-toolchain-source-npm-tree-write-mode", "node-toolchain-source-node-file-write-mode",
    "node-toolchain-source-npm-file-write-mode",
    "npm-lock-projection-invalid", "npm-projection-mismatch", "positive-control-failed",
    "positive-control-unavailable", "prepared-file-count", "prepared-input-invalid", "prepared-link-invalid",
    "prepared-member-type", "prepared-tree-size", "probe-replay", "profile-command-invalid",
    "profile-command-set", "profile-config-invalid", "profile-config-unavailable", "profile-unknown",
    "projection-binding-mismatch", "projection-invalid", "raw-record-size", "record-count",
    "report-file-changed", "report-file-invalid", "report-file-size", "rust-matrix-coverage-incomplete",
    "rust-matrix-report-exists", "rust-matrix-report-incomplete", "rust-matrix-report-invalid",
    "rust-matrix-report-unavailable", "rust-matrix-status-mismatch", "rust-tool-layout",
    "rust-toolchain-missing", "rust-toolchain-path", "state-directory-not-empty",
    "state-directory-permissions", "summary-catalog-invalid", "summary-not-ready",
    "summary-response-invalid", "supervisor-failed", "supervisor-operation-failed",
    "supervisor-start-failed", "supervisor-start-timeout", "supervisor-unavailable", "swap-enabled",
    "swap-state-unavailable", "tool-manifest-invalid", "tool-path-invalid", "tool-version-mismatch",
    "tool-version-unavailable", "total-deadline-exhausted", "total-deadline-unavailable",
    "typescript-report-incomplete",
))
STARTUP_REFUSAL_CODES = frozenset((
    "deadline-file-invalid", "dispatch-context-invalid", "dispatch-context-unavailable",
    "firewall-unavailable", "input-size", "input-unavailable", "linux-root-required",
    "linux-runner-required", "mount-source-unavailable", "node-tool-layout",
    "node-snapshot-base-invalid", "node-snapshot-base-owner", "node-snapshot-base-unavailable",
    "node-snapshot-content-changed", "node-snapshot-content-invalid", "node-snapshot-deadline",
    "node-snapshot-id", "node-snapshot-layout", "node-snapshot-limit", "node-snapshot-link-invalid",
    "node-snapshot-manifest-invalid", "node-snapshot-missing", "node-snapshot-seal-invalid",
    "node-toolchain-executable",
    "node-toolchain-directory-control-access", "node-toolchain-directory-scan-access",
    "node-toolchain-file-control-access",
    "node-toolchain-missing", "node-toolchain-owner",
    "node-toolchain-source-anchor-write-mode", "node-toolchain-source-cache-root-write-mode",
    "node-toolchain-source-root-anchor-write-mode", "node-toolchain-source-opt-anchor-write-mode",
    "node-toolchain-source-node-layout-write-mode", "node-toolchain-source-npm-layout-write-mode",
    "node-toolchain-source-npm-tree-write-mode", "node-toolchain-source-node-file-write-mode",
    "node-toolchain-source-npm-file-write-mode",
    "node-toolchain-version",
    "positive-control-failed", "positive-control-unavailable",
    "profile-config-invalid", "profile-config-unavailable", "profile-unknown",
    "projection-binding-mismatch", "projection-invalid", "report-file-changed", "report-file-invalid",
    "report-file-size", "rust-tool-layout", "rust-toolchain-missing", "rust-toolchain-path",
    "state-directory-not-empty", "state-directory-permissions", "supervisor-failed",
    "supervisor-operation-failed", "supervisor-start-failed", "supervisor-start-timeout",
    "swap-enabled", "swap-state-unavailable", "tool-manifest-invalid", "tool-path-invalid",
    "tool-version-mismatch", "tool-version-unavailable", "total-deadline-exhausted",
    "total-deadline-unavailable",
))
STARTUP_DIAGNOSTIC_PHASES = frozenset((
    "construct", "deadline", "projection", "linux", "swap", "priv-mount", "firewall",
    "root-mount", "bundle-bind", "tools", "profile", "versions", "socket", "listen",
    "ready", "serve", "parent",
))
_STARTUP_EXCEPTION_LABELS = {
    AssertionError: "assertion", AttributeError: "attribute", FileExistsError: "file-exists",
    FileNotFoundError: "file-missing", IsADirectoryError: "is-directory", KeyError: "key",
    NameError: "name", NotADirectoryError: "not-directory", OSError: "os",
    PermissionError: "permission", RuntimeError: "runtime", TimeoutError: "timeout",
    TypeError: "type", ValueError: "value", UnicodeError: "unicode",
    UnicodeDecodeError: "unicode-decode", json.JSONDecodeError: "json-decode",
    subprocess.SubprocessError: "subprocess", subprocess.TimeoutExpired: "proc-timeout",
    subprocess.CalledProcessError: "proc-exit", ImportError: "import", ModuleNotFoundError: "module-missing",
    MemoryError: "memory", OverflowError: "overflow", IndexError: "index",
}
STARTUP_DIAGNOSTIC_CODES = frozenset(
    "child-" + phase + "-" + label
    for phase in STARTUP_DIAGNOSTIC_PHASES
    for label in {*_STARTUP_EXCEPTION_LABELS.values(), "unclassified"}
)


def _startup_exception_code(phase, error):
    trusted_phase = phase if phase in STARTUP_DIAGNOSTIC_PHASES else "serve"
    label = _STARTUP_EXCEPTION_LABELS.get(type(error), "unclassified")
    return "child-" + trusted_phase + "-" + label


def _record_startup_refusal(state_dir, owner_uid, code):
    if code not in STARTUP_REFUSAL_CODES and code not in STARTUP_DIAGNOSTIC_CODES:
        code = "supervisor-failed"
    refusal_path = Path(state_dir) / STARTUP_REFUSAL_NAME
    payload = json.dumps({"code": code}, sort_keys=True, separators=(",", ":")).encode("ascii")
    descriptor = os.open(refusal_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as output:
        os.fchown(output.fileno(), owner_uid, -1)
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


class SupervisorRefusal(ValueError):
    def __init__(self, code="supervisor-failed"):
        super().__init__(code)
        self.code = code


def _refuse(code):
    raise SupervisorRefusal(code)


def _bounded_timeout(timeout, *, cleanup=False):
    if not ACTIVE_DEADLINE_FILE:
        return timeout
    try:
        remaining = (deadline_budget.cleanup_remaining(ACTIVE_DEADLINE_FILE) if cleanup
                     else deadline_budget.remaining(ACTIVE_DEADLINE_FILE))
    except deadline_budget.DeadlineRefusal:
        _refuse("total-deadline-exhausted")
    return min(timeout, remaining)


def _run(argv, timeout=10, input_bytes=None, env=None, *, cleanup=False):
    timeout = _bounded_timeout(timeout, cleanup=cleanup)
    try:
        result = subprocess.run(
            argv, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=timeout, env=env or {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        _refuse("supervisor-operation-failed")
    if result.returncode != 0:
        _refuse("supervisor-operation-failed")
    return result.stdout


def _read_regular(path, maximum):
    descriptor = None
    try:
        """lstat first and open non-blocking: opening a FIFO for reading would otherwise block before the type could be checked."""
        if not stat.S_ISREG(os.lstat(str(path)).st_mode):
            _refuse("report-file-invalid")
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            _refuse("report-file-invalid")
        output = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > maximum:
                _refuse("report-file-size")
        if len(output) != metadata.st_size:
            _refuse("report-file-changed")
        return bytes(output)
    except SupervisorRefusal:
        raise
    except OSError:
        _refuse("report-file-invalid")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_exact(connection, amount):
    data = bytearray()
    while len(data) < amount:
        chunk = connection.recv(amount - len(data))
        if not chunk:
            _refuse("control-protocol-truncated")
        data.extend(chunk)
    return bytes(data)


def _send_frame(connection, payload):
    if len(payload) > MAX_RPC:
        _refuse("control-protocol-size")
    connection.sendall(len(payload).to_bytes(4, "big") + payload)


def _recv_frame(connection):
    length = int.from_bytes(_read_exact(connection, 4), "big")
    if length < 2 or length > MAX_RPC:
        _refuse("control-protocol-size")
    return _read_exact(connection, length)


def _rpc(state_dir, request):
    payload = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(payload) > MAX_RPC:
        _refuse("control-protocol-size")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    operation = request.get("op") if type(request) is dict else None
    timeout = 9900 if operation == "execute" else 10 * 60 if operation == "decrypt" else 90
    connection.settimeout(timeout)
    try:
        connection.connect(str(Path(state_dir) / SOCKET_NAME))
        _send_frame(connection, payload)
        response = bundle.strict_json(_recv_frame(connection), MAX_RPC)
    except (OSError, bundle.Refusal):
        _refuse("supervisor-unavailable")
    finally:
        connection.close()
    if type(response) is not dict or set(response) - {"ok", "code", "status", "summary", "catalogs"}:
        _refuse("control-response-invalid")
    if response.get("ok") is not True:
        _refuse(response.get("code") if type(response.get("code")) is str else "supervisor-failed")
    return response


def _context_from_file(path):
    try:
        value = bundle.strict_json(Path(path).read_bytes(), 64 * 1024)
    except (OSError, bundle.Refusal):
        _refuse("dispatch-context-unavailable")
    try:
        fetch.validate_dispatch(value)
    except (fetch.Refusal, TypeError, KeyError):
        _refuse("dispatch-context-invalid")
    return value


def _require_linux_root():
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        _refuse("linux-root-required")


def _require_swap_disabled():
    try:
        lines = Path("/proc/swaps").read_text(encoding="ascii").splitlines()
    except OSError:
        _refuse("swap-state-unavailable")
    if len(lines) != 1:
        _refuse("swap-enabled")


def _mount_private():
    _run(["mount", "--make-rprivate", "/"])


def _configure_firewall():
    _run(["ip", "link", "set", "lo", "up"])
    script = (
        "add table inet devlane\n"
        "add chain inet devlane input { type filter hook input priority 0; policy drop; }\n"
        "add chain inet devlane output { type filter hook output priority 0; policy drop; }\n"
        "add chain inet devlane forward { type filter hook forward priority 0; policy drop; }\n"
        "add rule inet devlane input iifname \"lo\" accept\n"
        "add rule inet devlane output oifname \"lo\" accept\n"
    ).encode("ascii")
    _run(["nft", "-f", "-"], input_bytes=script)


def _ensure_directory(path, mode=0o755):
    Path(path).mkdir(mode=mode, parents=True, exist_ok=True)


def _mount_bind(source, destination, readonly=False):
    source = Path(source)
    try:
        source = source.resolve(strict=True)
    except OSError:
        _refuse("mount-source-unavailable")
    destination = Path(destination)
    if not source.exists():
        _refuse("mount-source-unavailable")
    _run(["mount", "--bind", str(source), str(destination)])
    MOUNT_TARGETS.append(destination)
    if readonly:
        _run(["mount", "-o", "remount,bind,ro,nosuid,nodev", str(destination)])


def _mount_tmpfs(destination, size, mode="0700", options=""):
    option_list = ["size=" + size, "mode=" + mode]
    if options:
        option_list.extend(options.split(","))
    _run(["mount", "-t", "tmpfs", "-o", ",".join(option_list), "tmpfs", str(destination)])
    MOUNT_TARGETS.append(Path(destination))


def _mount_minimal_root(root, workspace, prepared, control_root):
    _ensure_directory(root)
    _mount_tmpfs(root, "2g", "0755", "nosuid,nodev")
    for name in (
        "bin", "sbin", "lib", "lib64", "usr", "opt", "etc", "dev", "proc", "run",
        "tmp", "home", "devlane-home", "control", "prepared", "workspace", "scratch", "var", "tools",
    ):
        _ensure_directory(root / name, 0o755)
    for host, guest in (("/usr", root / "usr"), ("/lib", root / "lib"), ("/lib64", root / "lib64")):
        if Path(host).exists():
            _mount_bind(host, guest, readonly=True)
    for name in ("bin", "sbin"):
        target = "usr/bin" if name == "bin" else "usr/sbin"
        link = root / name
        try:
            link.rmdir()
        except OSError:
            pass
        if not link.is_symlink():
            link.symlink_to(target)
    _ensure_directory(root / "etc/ssl/certs")
    certs = Path("/etc/ssl/certs")
    if certs.is_dir():
        _mount_bind(certs, root / "etc/ssl/certs", readonly=True)
    passwd = "root:x:0:0:root:/root:/usr/sbin/nologin\ndevlane:x:65534:65534:devlane:/devlane-home:/usr/sbin/nologin\n"
    group = "root:x:0:\ndevlane:x:65534:\n"
    (root / "etc/passwd").write_text(passwd, encoding="ascii")
    (root / "etc/group").write_text(group, encoding="ascii")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost\n", encoding="ascii")
    _mount_tmpfs(root / "dev", "64m", "0755")
    for name, mode, major, minor in (("null", 0o666, 1, 3), ("zero", 0o666, 1, 5),
                                     ("random", 0o444, 1, 8), ("urandom", 0o444, 1, 9)):
        os.mknod(str(root / "dev" / name), stat.S_IFCHR | mode, os.makedev(major, minor))
    _ensure_directory(root / "dev/shm", 0o1777)
    _mount_tmpfs(root / "dev/shm", "512m", "01777")
    _mount_tmpfs(root / "workspace", "4g", "0755", "nosuid,nodev")
    _mount_tmpfs(root / "scratch", "4g", "0755", "nosuid,nodev")
    _mount_bind(prepared, root / "prepared", readonly=True)
    _ensure_directory(root / "control/devlane")
    (root / "control/bundle.enc").write_bytes(b"")
    _mount_bind(control_root / "kit/devlane", root / "control/devlane", readonly=True)
    (root / "control/profiles.json").write_text("{}", encoding="ascii")
    _mount_bind(control_root / "ci/devlane-profiles.json", root / "control/profiles.json", readonly=True)
    _run(["mount", "-t", "proc", "-o", "hidepid=2,subset=pid", "proc", str(root / "proc")])
    MOUNT_TARGETS.append(root / "proc")
    _ensure_directory(root / "devlane-home", 0o700)
    os.chown(str(root / "devlane-home"), WORKER_UID, WORKER_GID)
    _ensure_directory(root / "workspace/source", 0o700)
    """The decryptor runs as the unprivileged worker and extracts straight into this directory."""
    os.chown(str(root / "workspace/source"), WORKER_UID, WORKER_GID)
    _ensure_directory(root / "workspace/raw", 0o755)
    _ensure_directory(root / "scratch/tmp", 0o700)
    return root


def _hash_file(path, maximum):
    digest = hashlib.sha256()
    size = 0
    try:
        with Path(path).open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    _refuse("input-size")
                digest.update(chunk)
    except OSError:
        _refuse("input-unavailable")
    return size, digest.hexdigest()


def _bound_projection(context, path):
    """Read the projection without following its final path component and bind it to dispatch."""
    payload = _read_regular(path, fetch.MAX_PROJECTION)
    if (len(payload) != context["projection_size"]
            or hashlib.sha256(payload).hexdigest() != context["projection_sha256"]):
        _refuse("projection-binding-mismatch")
    try:
        value = fetch.validate_projection(payload, context["profile"])
    except (fetch.Refusal, TypeError, KeyError, RecursionError):
        _refuse("projection-invalid")
    return payload, value


def _read_profiles(root):
    path = root / "control/profiles.json"
    try:
        data = path.read_bytes()
        value = bundle.strict_json(data, 128 * 1024)
    except (OSError, bundle.Refusal):
        _refuse("profile-config-unavailable")
    if type(value) is not dict or value.get("schema") != 1 or type(value.get("profiles")) is not dict:
        _refuse("profile-config-invalid")
    return value


def _worker_environment(stage, root, tools):
    node_path = tools.get("node_dir")
    rust_path = tools.get("rust_dir")
    path = ["/usr/bin", "/bin"]
    if node_path:
        path.insert(0, node_path)
    if rust_path:
        path.insert(0, rust_path)
    env = {
        "PATH": ":".join(path),
        "HOME": "/devlane-home",
        "TMPDIR": "/scratch/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C",
        "CI": "1",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_HOME": "/scratch/cargo-home",
        "CARGO_TARGET_DIR": "/scratch/target",
        "NPM_CONFIG_OFFLINE": "true",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_CACHE": "/scratch/npm-cache",
        "PLAYWRIGHT_BROWSERS_PATH": "/prepared/ms-playwright",
        "DEVLANE_STAGE": stage,
    }
    return env


def _limited_child(cpu_seconds=1200):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (bundle.MAX_EXPANDED // 2, bundle.MAX_EXPANDED // 2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
    resource.setrlimit(resource.RLIMIT_NPROC, (1024, 1024))
    if type(cpu_seconds) is not int or not 1 <= cpu_seconds <= 9900:
        raise ValueError("cpu-limit-invalid")
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    os.umask(0o077)


def _chroot_worker_command(root, command):
    if type(command) is not list or not command or any(type(part) is not str or not part for part in command):
        _refuse("profile-command-invalid")
    return [
        "/usr/sbin/chroot", str(root), "/usr/bin/setpriv",
        "--reuid=%d" % WORKER_UID, "--regid=%d" % WORKER_GID, "--clear-groups",
        "--no-new-privs", "--bounding-set=-all", "--",
        "/bin/sh", "-c", 'cd /workspace/source && exec "$@"', "devlane-workload",
    ] + command


def _kill_workload_descendants():
    with ACTIVE_CHILDREN_LOCK:
        process_groups = tuple(ACTIVE_CHILDREN)
    for process_group in process_groups:
        try:
            os.killpg(process_group, signal.SIGTERM)
        except OSError:
            pass
    try:
        os.kill(-1, signal.SIGTERM)
    except OSError:
        pass
    time.sleep(0.05)
    try:
        os.kill(-1, signal.SIGKILL)
    except OSError:
        pass
    while True:
        try:
            os.waitpid(-1, 0)
        except ChildProcessError:
            break


def _wait_child(process, timeout):
    deadline = time.monotonic() + timeout
    while True:
        status = process.poll()
        if status is not None:
            return status
        if CANCEL_REQUESTED.is_set():
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            return 130
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            return 124
        time.sleep(min(0.1, remaining))


def _run_profile_command(root, command, stage, log_path, tools, timeout=1200, deadline=None):
    environment = _worker_environment(stage, root, tools)
    if CANCEL_REQUESTED.is_set():
        return 130
    if deadline is None:
        try:
            timeout = _bounded_timeout(timeout)
        except SupervisorRefusal:
            return 124
    else:
        try:
            timeout = min(timeout, deadline_budget.remaining(deadline))
        except deadline_budget.DeadlineRefusal:
            return 124
    argv = _chroot_worker_command(root, command)
    target = root / log_path.lstrip("/")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    error_target = target.with_name(target.stem + ".stderr.log")
    with target.open("xb") as log, error_target.open("xb") as error_log:
        try:
            process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=log, stderr=error_log,
                env=environment, cwd="/", close_fds=True,
                start_new_session=True, preexec_fn=_limited_child,
            )
        except OSError:
            return 125
        with ACTIVE_CHILDREN_LOCK:
            ACTIVE_CHILDREN.add(process.pid)
        code = _wait_child(process, timeout)
        with ACTIVE_CHILDREN_LOCK:
            ACTIVE_CHILDREN.discard(process.pid)
    _kill_workload_descendants()
    try:
        os.chmod(target, 0o444)
        os.chmod(error_target, 0o444)
    except OSError:
        return 125
    if target.stat().st_size > output_filter.MAX_RAW_CAPTURE_BYTES or error_target.stat().st_size > output_filter.MAX_RAW_CAPTURE_BYTES:
        return 125
    return code


def _run_control_adapter(root, command, stage, tools, log_name, timeout=60, deadline=None, cpu_seconds=1200):
    if CANCEL_REQUESTED.is_set():
        return 130
    if deadline is None:
        try:
            timeout = _bounded_timeout(timeout)
        except SupervisorRefusal:
            return 124
    else:
        try:
            timeout = min(timeout, deadline_budget.remaining(deadline))
        except deadline_budget.DeadlineRefusal:
            return 124
    target = root / "workspace/raw" / log_name
    with target.open("xb") as log:
        try:
            process = subprocess.Popen(
                _chroot_worker_command(root, command), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                env=_worker_environment(stage, root, tools), cwd="/", close_fds=True,
                start_new_session=True, preexec_fn=lambda: _limited_child(cpu_seconds),
            )
        except OSError:
            return 125
        with ACTIVE_CHILDREN_LOCK:
            ACTIVE_CHILDREN.add(process.pid)
        code = _wait_child(process, timeout)
        with ACTIVE_CHILDREN_LOCK:
            ACTIVE_CHILDREN.discard(process.pid)
    _kill_workload_descendants()
    if target.stat().st_size > 1024 * 1024:
        return 125
    return code


def _manifest_allowlists(manifest, profile, source_root):
    max_lines = {}
    for relative in manifest["allowed_files"]:
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            _refuse("allowlisted-file-unavailable")
        try:
            count = 0
            with path.open("rb") as source:
                for line in source:
                    count += 1
                    if count > 10_000_000:
                        _refuse("allowlisted-file-too-large")
            max_lines[relative] = max(1, count)
        except OSError:
            _refuse("allowlisted-file-unavailable")
    codes = list(profile.get("diagnostic_codes", []))
    if "DEVLANE_FAILURE" not in codes:
        codes.append("DEVLANE_FAILURE")
    stages = list(profile["stages"])
    if manifest["frames"]:
        if profile.get("browser_command") is None:
            _refuse("browser-profile-command")
        stages.append("browser")
    return {
        "files": manifest["allowed_files"],
        "tests": {public_id: public_id for public_id in manifest["allowed_tests"].values()},
        "frames": {public_id: public_id for public_id in manifest["frames"].values()},
        "stages": stages,
        "codes": sorted(set(codes)),
        "suites": sorted(profile.get("rust_matrix", {}).get("coverage_ids", [])),
        "max_lines": max_lines,
    }


def _copy_prepared_tree(source, destination, *, max_bytes=4 * 1024 * 1024 * 1024, max_files=250_000):
    source = Path(source)
    destination = Path(destination)
    if not source.is_dir() or source.is_symlink() or destination.exists() or destination.is_symlink():
        _refuse("prepared-input-invalid")
    source_root = source.resolve(strict=True)
    total = 0
    count = 0
    destination.mkdir(mode=0o700, parents=True)
    for current, directories, files in os.walk(source_root, topdown=True, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(source_root)
        target_dir = destination / relative_dir
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        retained = []
        for name in directories:
            entry = current_path / name
            target = target_dir / name
            if entry.is_symlink():
                link = os.readlink(entry)
                if os.path.isabs(link):
                    _refuse("prepared-link-invalid")
                resolved = (entry.parent / link).resolve(strict=True)
                if not resolved.is_relative_to(source_root):
                    _refuse("prepared-link-invalid")
                target.symlink_to(link, target_is_directory=True)
            else:
                target.mkdir(mode=0o700, exist_ok=True)
                retained.append(name)
            count += 1
            if count > max_files:
                _refuse("prepared-file-count")
        directories[:] = retained
        for name in files:
            entry = current_path / name
            target = target_dir / name
            mode = entry.lstat().st_mode
            if stat.S_ISLNK(mode):
                link = os.readlink(entry)
                if os.path.isabs(link):
                    _refuse("prepared-link-invalid")
                resolved = (entry.parent / link).resolve(strict=True)
                if not resolved.is_relative_to(source_root):
                    _refuse("prepared-link-invalid")
                target.symlink_to(link)
            elif stat.S_ISREG(mode):
                total += entry.stat().st_size
                count += 1
                if total > max_bytes or count > max_files:
                    _refuse("prepared-tree-size")
                shutil.copyfile(entry, target, follow_symlinks=False)
                os.chmod(target, 0o600 | (stat.S_IMODE(mode) & 0o111))
            else:
                _refuse("prepared-member-type")
    return total


def _chown_tree(root, uid=WORKER_UID, gid=WORKER_GID):
    root = Path(root)
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        os.chown(current, uid, gid, follow_symlinks=False)
        for name in directories + files:
            path = Path(current) / name
            os.chown(path, uid, gid, follow_symlinks=False)


def _prepare_trusted_files(root, manifest):
    trusted = root / "trusted"
    trusted.mkdir(mode=0o755, exist_ok=True)
    manifest_bytes = bundle.canonical_json(manifest)
    adapter_config = {
        "tests": [[name, public_id] for name, public_id in manifest["allowed_tests"].items()],
        "frames": [[name, public_id] for name, public_id in manifest["frames"].items()],
    }
    for name, payload in (
        ("manifest.json", manifest_bytes),
        ("adapter-config.json", bundle.canonical_json(adapter_config)),
    ):
        path = trusted / name
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())


def _prepare_writable_scratch(root):
    for relative in ("scratch/reports", "scratch/target", "scratch/tmp", "scratch/npm-cache", "scratch/cargo-home"):
        path = root / relative
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(str(path), WORKER_UID, WORKER_GID)
    cargo_config = root / "scratch/cargo-home/config.toml"
    cargo_config.write_text(
        '[source.crates-io]\nreplace-with = "vendored-sources"\n'
        '[source.vendored-sources]\ndirectory = "/prepared/cargo-vendor"\n'
        '[net]\noffline = true\n',
        encoding="ascii",
    )
    os.chmod(cargo_config, 0o444)


def _copy_prepared_dependencies(root, profile):
    if profile == "core-node":
        source = root / "prepared/node_modules"
        destination = root / "workspace/source/node_modules"
        _copy_prepared_tree(source, destination)
        _chown_tree(destination)
    elif profile == "core-rust":
        vendor = root / "prepared/cargo-vendor"
        if not vendor.is_dir() or vendor.is_symlink():
            _refuse("cargo-vendor-missing")


def _read_internal_records(root):
    path = root / "scratch/reports/filtered-input.jsonl"
    if not os.path.lexists(path):
        return []
    payload = _read_regular(path, output_filter.MAX_RAW_CAPTURE_BYTES)
    records = []
    for line in payload.splitlines(keepends=True):
        if not line.endswith(b"\n") or len(line) > output_filter.MAX_RAW_RECORD_BYTES + 1:
            _refuse("raw-record-size")
        records.append(line[:-1])
        if len(records) > output_filter.MAX_RECORDS:
            _refuse("record-count")
    return records


def _summary_failed(summary):
    for line in summary.splitlines():
        try:
            record = output_filter._parse_record(line)
        except output_filter.FilterRefusal:
            return True
        if (record.get("kind") == "test"
                or record.get("kind") == "coverage" and (record.get("failed", 0) > 0 or record.get("ignored", 0) > 0)
                or record.get("kind") == "frame" and record.get("status") == "fail"
                or record.get("kind") == "control" and record.get("status") == "fail"
                or record.get("kind") == "diagnostic" and record.get("level") == "error"):
            return True
    return False


def _node_snapshot_versions(snapshot_id, owner_uid):
    if not node_tool_snapshot.valid_snapshot_id(snapshot_id):
        _refuse("node-snapshot-id")
    try:
        validated = node_tool_snapshot.validate_snapshot(
            snapshot_id, ACTIVE_DEADLINE_FILE, owner_uid=owner_uid,
        )
    except node_tool_snapshot.SnapshotRefusal as error:
        _refuse(error.code)

    def run(argv, *, env):
        try:
            return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10),
                                  check=False, env=env)
        except (OSError, subprocess.SubprocessError):
            _refuse("tool-version-unavailable")

    try:
        results = node_tool_prepare.run_node_versions(validated, run)
    except bundle.Refusal as error:
        _refuse(str(error))
    versions = {}
    for name, result in results.items():
        if result.returncode != 0:
            _refuse("tool-version-unavailable")
        try:
            versions[name] = result.stdout.decode("ascii", "strict").strip()
        except UnicodeDecodeError:
            _refuse("tool-version-unavailable")
    return validated, versions


def _preflight_tools(profile, projection, tool_paths, owner_uid=None):
    """Keep the selected profile pinned to already prepared executable paths."""
    paths = dict(tool_paths)
    if profile == "core-node" and not node_tool_snapshot.valid_snapshot_id(paths.get("node_snapshot_id")):
        _refuse("node-snapshot-id")
    if profile == "core-rust" and (not paths["cargo"] or not paths["rustc"]):
        _refuse("rust-toolchain-missing")
    if type(projection) is not dict or type(projection.get("tools")) is not dict:
        _refuse("tool-manifest-invalid")
    required = {"node", "npm"} if profile == "core-node" else ({"cargo", "rustc"} if profile == "core-rust" else set())
    if set(projection["tools"]) != required:
        _refuse("tool-manifest-invalid")
    node_root = None
    node_versions = None
    if profile == "core-node":
        node_tool_info, node_versions = _node_snapshot_versions(paths["node_snapshot_id"], owner_uid)
        node_root = Path(node_tool_info["root"])
        paths.update({name: node_tool_info[name] for name in ("node", "npm", "npm_cli")})
    for name in ("node", "npm", "cargo", "rustc"):
        path = paths.get(name)
        if path is None or path == "":
            continue
        try:
            real = Path(path).resolve(strict=True)
        except OSError:
            _refuse("tool-path-invalid")
        if not real.is_file() or real.is_symlink():
            _refuse("tool-path-invalid")
    for name, expected_version in projection["tools"].items():
        if name not in paths or not paths[name] or type(expected_version) is not str:
            _refuse("tool-manifest-invalid")
        expected_text = ("v" + expected_version) if name == "node" else expected_version
        if profile == "core-node":
            actual_version = node_versions[name]
        else:
            try:
                output = subprocess.run([paths[name], "--version"], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        timeout=_bounded_timeout(10), check=False,
                                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).stdout
                version = output.decode("ascii", "strict").strip()
            except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
                _refuse("tool-version-unavailable")
            if name in ("cargo", "rustc"):
                words = version.split()
                actual_version = words[1] if len(words) >= 2 else ""
            else:
                actual_version = version
        if name == "node" and actual_version != expected_text:
            _refuse("tool-version-mismatch")
        if name != "node" and actual_version != expected_version:
            _refuse("tool-version-mismatch")
        _hash_file(paths["npm_cli"] if profile == "core-node" and name == "npm" else paths[name],
                   256 * 1024 * 1024)
    rust_root = None
    if node_root:
        node_root = str(node_root)
    if paths.get("cargo"):
        rust_root = str(Path(paths["cargo"]).resolve().parent.parent)
        if not Path(paths["rustc"]).resolve().is_relative_to(Path(rust_root)):
            _refuse("rust-tool-layout")
    return {
        "node_dir": "/tools/node/bin" if node_root else None,
        "rust_dir": "/tools/rust/bin" if rust_root else None,
        "paths": paths,
        "node_root": node_root,
        "node_snapshot_id": paths.get("node_snapshot_id", ""),
        "rust_root": rust_root,
    }


def _control_failure(stage):
    return json.dumps({"kind": "control", "stage": stage, "status": "fail",
                       "code": "DEVLANE_FAILURE"}, separators=(",", ":")).encode("ascii")


def _adapter_lines(output, result, stage, *, rule):
    """Records from a control adapter, only if the adapter demonstrably completed.

    A report file that merely exists proves nothing: it may be precreated, truncated by a
    crash or a timeout, or written by the workload. The adapter must have exited with one of
    its two defined statuses, left a complete newline-terminated regular file, and its
    status must agree with the records it wrote. Anything else is one fixed failure.
    """
    try:
        if result not in (0, 1) or not os.path.lexists(output):
            return [_control_failure(stage)]
        payload = _read_regular(output, output_filter.MAX_RAW_CAPTURE_BYTES)
        if payload and not payload.endswith(b"\n"):
            return [_control_failure(stage)]
        lines = payload.splitlines()
        parsed = [bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES) for line in lines]
        if any(type(item) is not dict for item in parsed):
            return [_control_failure(stage)]
        control_failed = any(item.get("kind") == "control" and item.get("status") == "fail" for item in parsed)
        if rule == "tests":
            """Rust: status 1 means at least one failing test record; 0 means no records at all."""
            consistent = (result == 1) == bool(lines) and not control_failed
        else:
            """Node adapters: status 1 means a fixed control failure; otherwise none may appear."""
            consistent = (result == 1) == control_failed
        if not consistent:
            return [_control_failure(stage)]
        return lines
    except (SupervisorRefusal, bundle.Refusal, OSError):
        return [_control_failure(stage)]


def _adapter_records(root, profile, manifest, outcomes, tools, adapter_results=None):
    adapter_results = adapter_results or {}
    records = []
    if profile == "core-rust":
        output = root / "scratch/reports/rust-matrix.jsonl"
        result = adapter_results.get("rust_matrix", 125)
        try:
            if result not in (0, 1) or not os.path.lexists(output):
                _refuse("rust-matrix-report-unavailable")
            payload = _read_regular(output, output_filter.MAX_RAW_CAPTURE_BYTES)
            if payload and not payload.endswith(b"\n"):
                _refuse("rust-matrix-report-incomplete")
            records = [bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES)
                       for line in payload.splitlines()]
            if any(type(record) is not dict for record in records) or len(records) > output_filter.MAX_RECORDS:
                _refuse("rust-matrix-report-invalid")
            profile_path = root / "control/profiles.json"
            profile_document = bundle.strict_json(_read_regular(profile_path, 1024 * 1024), 1024 * 1024)
            matrix = profile_document["profiles"]["core-rust"]["rust_matrix"]
            expected = matrix["coverage_ids"]
            coverage = [record for record in records if record.get("kind") == "coverage"]
            suites = [record.get("suite") for record in coverage]
            if len(suites) != len(set(suites)) or set(suites) != set(expected):
                _refuse("rust-matrix-coverage-incomplete")
            failed = any(record.get("kind") == "test"
                         or record.get("kind") == "control" and record.get("status") == "fail"
                         or record.get("kind") == "coverage" and (record.get("failed", 0) > 0 or record.get("ignored", 0) > 0)
                         for record in records)
            if (result == 0) == failed:
                _refuse("rust-matrix-status-mismatch")
            records = [json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                       for record in records]
        except (SupervisorRefusal, bundle.Refusal, OSError, KeyError, TypeError):
            records = [_control_failure("unit")]
    if profile == "core-node":
        typescript_report = root / "scratch/reports/typescript.jsonl"
        if adapter_results.get("typescript") == 0 and os.path.lexists(typescript_report):
            try:
                typescript_bytes = _read_regular(typescript_report, output_filter.MAX_RAW_CAPTURE_BYTES)
                if typescript_bytes and not typescript_bytes.endswith(b"\n"):
                    raise SupervisorRefusal("typescript-report-incomplete")
                records.extend(line.rstrip(b"\n") for line in typescript_bytes.splitlines())
            except (SupervisorRefusal, OSError):
                records.append(_control_failure("typecheck"))
        else:
            records.append(_control_failure("typecheck"))
        report = root / "scratch/reports/vitest.json"
        if os.path.lexists(report):
            output = root / "scratch/reports/adapter.jsonl"
            if os.path.lexists(output):
                output.unlink()
            command = [
                "node", "/control/devlane/test_adapters.mjs", "vitest",
                "/scratch/reports/vitest.json", "/scratch/reports/adapter.jsonl",
            ]
            result = _run_control_adapter(root, command, "unit", tools, "adapter-run.log", timeout=30)
            records.extend(_adapter_lines(output, result, "unit", rule="node"))
        else:
            records.append(_control_failure("unit"))
        if manifest["frames"]:
            output = root / "scratch/reports/playwright.jsonl"
            if os.path.lexists(output):
                output.unlink()
            command = [
                "node",
                "/control/devlane/test_adapters.mjs", "playwright", "/workspace/raw/browser.log",
                "/scratch/reports/playwright.jsonl",
            ]
            result = _run_control_adapter(root, command, "browser", tools, "browser-adapter.log", timeout=30)
            records.extend(_adapter_lines(output, result, "browser", rule="node"))
    for stage, code in outcomes:
        if code != 0:
            records.append(_control_failure(stage))
    return records


def _shred_tree(root):
    failures = 0
    root = Path(root)
    if not root.exists():
        return True
    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        for filename in files:
            path = Path(current) / filename
            try:
                mode = path.lstat().st_mode
                if stat.S_ISREG(mode):
                    size = path.stat().st_size
                    with path.open("r+b", buffering=0) as stream:
                        remaining = size
                        zeros = bytes(65536)
                        while remaining:
                            amount = min(len(zeros), remaining)
                            stream.write(zeros[:amount])
                            remaining -= amount
                        stream.flush()
                        os.fsync(stream.fileno())
                path.unlink()
            except OSError:
                failures += 1
        for directory in directories:
            path = Path(current) / directory
            try:
                if path.is_symlink():
                    path.unlink()
                else:
                    path.rmdir()
            except OSError:
                failures += 1
    try:
        root.rmdir()
    except OSError:
        failures += 1
    return failures == 0


class Service:
    def __init__(self, state_dir, context_path, workspace, prepared, bundle_path, projection_path,
                 host_net_inode, owner_uid, tool_paths, deadline_file):
        global ACTIVE_DEADLINE_FILE
        self.startup_phase = "construct"
        self.state_dir = Path(state_dir)
        self.context = _context_from_file(context_path)
        self.workspace = Path(workspace).resolve(strict=True)
        self.prepared = Path(prepared).resolve(strict=True)
        self.bundle_path = Path(bundle_path).resolve(strict=True)
        self.projection_path = Path(projection_path).absolute()
        self.host_net_inode = host_net_inode
        self.owner_uid = owner_uid
        self.tool_paths = tool_paths
        self.deadline_file = Path(deadline_file).resolve(strict=True)
        ACTIVE_DEADLINE_FILE = str(self.deadline_file)
        self.deadline = None
        self.root = self.state_dir / "namespace-root"
        self.manifest = None
        self.profile_config = None
        self.tool_info = None
        self.probe_passed = False
        self.probe_namespace_inode = None
        self.decrypted = False
        self.execution_done = False
        self.summary = None
        self.outcomes = []
        self.mounts = []

    def prepare(self):
        self.startup_phase = "deadline"
        try:
            self.deadline = deadline_budget._read(self.deadline_file)["work_deadline"]
            deadline_budget.remaining(self.deadline_file)
        except (OSError, deadline_budget.DeadlineRefusal):
            _refuse("total-deadline-unavailable")
        self.startup_phase = "projection"
        _projection_bytes, projection_value = _bound_projection(self.context, self.projection_path)
        self.startup_phase = "linux"
        _require_linux_root()
        self.startup_phase = "swap"
        _require_swap_disabled()
        self.startup_phase = "priv-mount"
        _mount_private()
        self.startup_phase = "firewall"
        _configure_firewall()
        self.startup_phase = "root-mount"
        _mount_minimal_root(self.root, self.workspace, self.prepared, self.workspace)
        self.startup_phase = "bundle-bind"
        _mount_bind(self.bundle_path, self.root / "control/bundle.enc", readonly=True)
        self.startup_phase = "tools"
        _ensure_directory(self.root / "tools/node")
        _ensure_directory(self.root / "tools/rust")
        self.tool_info = _preflight_tools(self.context["profile"], projection_value,
                                         self.tool_paths, self.owner_uid)
        if self.tool_info["node_root"]:
            _mount_bind(self.tool_info["node_root"], self.root / "tools/node", readonly=True)
        if self.tool_info["rust_root"]:
            _mount_bind(self.tool_info["rust_root"], self.root / "tools/rust", readonly=True)
        self.mounts = [
            self.root / "proc", self.root / "dev/shm", self.root / "dev", self.root / "workspace",
            self.root / "scratch", self.root / "prepared", self.root / "control/profiles.json",
            self.root / "control/devlane", self.root / "etc/ssl/certs",
            self.root / "tools/rust", self.root / "tools/node", self.root / "lib64", self.root / "lib",
            self.root / "usr", self.root,
        ]
        self.startup_phase = "profile"
        self.profile_config = _read_profiles(self.root)
        self.projection_value = projection_value
        if self.context["profile"] == "core-node":
            self.startup_phase = "versions"
            _node_info, versions = _node_snapshot_versions(self.tool_info["node_snapshot_id"], self.owner_uid)
            if versions != {"node": "v" + node_tool_prepare.NODE_VERSION,
                            "npm": node_tool_prepare.NPM_VERSION}:
                _refuse("node-toolchain-version")
        self.startup_phase = "ready"
        return True

    def _probe(self):
        if self.probe_passed:
            _refuse("probe-replay")
        self._verify_network_cut()
        self.probe_passed = True
        return {"ok": True}

    def _verify_network_cut(self):
        try:
            firewall = network_probe.firewall_snapshot()
        except network_probe.ProbeRefusal:
            _refuse("firewall-unavailable")
        if firewall["netns_inode"] == self.host_net_inode:
            _refuse("network-namespace-not-isolated")
        if self.probe_namespace_inode is not None and firewall["netns_inode"] != self.probe_namespace_inode:
            _refuse("network-namespace-changed")
        try:
            evidence = _run([
                "/usr/sbin/chroot", str(self.root), "/usr/bin/setpriv",
                "--reuid=%d" % WORKER_UID, "--regid=%d" % WORKER_GID,
                "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--",
                "/usr/bin/python3", "-B", "-I", "-S", "/control/devlane/network_probe.py",
                "check", "--host-net-inode", str(self.host_net_inode),
            ], timeout=30)
        except SupervisorRefusal:
            _refuse("network-probe-failed")
        if evidence.strip() != b"network_probe=pass":
            _refuse("network-probe-failed")
        if os.stat("/proc/self/ns/net").st_ino != firewall["netns_inode"]:
            _refuse("network-namespace-changed")
        self.probe_namespace_inode = firewall["netns_inode"]
        return True

    def _decrypt(self, key_hex):
        if not self.probe_passed or self.decrypted or self.execution_done:
            _refuse("decrypt-order")
        try:
            decrypt_timeout = min(120, deadline_budget.remaining(self.deadline_file))
        except deadline_budget.DeadlineRefusal:
            _refuse("total-deadline-exhausted")
        self._verify_network_cut()
        if type(key_hex) is not str or len(key_hex) != 64 or any(char not in "0123456789abcdef" for char in key_hex):
            _refuse("key-invalid")
        size, digest = _hash_file(self.bundle_path, bundle.MAX_CIPHERTEXT)
        if size != self.context["bundle_size"] or digest != self.context["bundle_sha256"]:
            _refuse("bundle-binding-mismatch")
        expected = {
            "format": "kd-public-devlane-aesgcm-v1",
            "repository_id": self.context["repository_id"],
            "control_sha": self.context["control_sha"],
            "workflow_path": fetch.WORKFLOW_PATH,
            "profile": self.context["profile"],
            "wave_id": self.context["wave_id"],
            "bundle_id": self.context["bundle_id"],
            "fetch_sha256": self.context["projection_sha256"],
            "expires": self.context["expires"],
        }
        request = bytearray(bundle.canonical_json({"key": key_hex, "expected": expected}))
        key_hex = ""
        command = [
            "/usr/sbin/chroot", str(self.root), "/usr/bin/setpriv",
            "--reuid=%d" % WORKER_UID, "--regid=%d" % WORKER_GID, "--clear-groups",
            "--no-new-privs", "--bounding-set=-all", "--",
            "/usr/bin/python3", "-B", "-I", "/control/devlane/decrypt_once.py",
        ]
        process = None
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
                close_fds=True, start_new_session=True,
            )
            output, _ = process.communicate(bytes(request), timeout=decrypt_timeout)
        except subprocess.TimeoutExpired:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        pass
            _refuse("decrypt-timeout")
        except (OSError, subprocess.SubprocessError):
            _refuse("decrypt-rejected")
        finally:
            for index in range(len(request)):
                request[index] = 0
        if process.returncode != 0 or len(output) > 4 * 1024 * 1024:
            _refuse("decrypt-rejected")
        try:
            receipt = bundle.strict_json(output, 4 * 1024 * 1024)
        except bundle.Refusal:
            _refuse("decrypt-rejected")
        if (type(receipt) is not dict or set(receipt) != {"status", "manifest"}
                or receipt["status"] != "accepted" or type(receipt["manifest"]) is not dict):
            _refuse("decrypt-manifest-unavailable")
        self.manifest = receipt["manifest"]
        output = b""
        receipt = None
        self._verify_projection_bindings()
        _copy_prepared_dependencies(self.root, self.context["profile"])
        _chown_tree(self.root / "workspace/source")
        _prepare_trusted_files(self.root, self.manifest)
        _prepare_writable_scratch(self.root)
        self.decrypted = True
        return {"ok": True}

    def _verify_projection_bindings(self):
        source = self.root / "workspace/source"
        if self.context["profile"] == "core-node":
            package_path = source / "package.json"
            lock_path = source / "package-lock.json"
            if (package_path.is_symlink() or not package_path.is_file()
                    or "package-lock.json" not in self.manifest["original_lockfiles"]):
                _refuse("npm-lock-binding-missing")
            try:
                fetch.validate_npm_manifest_binding(package_path.read_bytes(), self.projection_value["npm_package"])
                package, lock, _ = fetch.project_npm_lock(lock_path.read_bytes())
            except (OSError, fetch.Refusal):
                _refuse("npm-lock-projection-invalid")
            if package != self.projection_value["npm_package"] or lock != self.projection_value["npm_lock"]:
                _refuse("npm-projection-mismatch")
        else:
            lock_path = source / "Cargo.lock"
            if "Cargo.lock" not in self.manifest["original_lockfiles"]:
                _refuse("cargo-lock-binding-missing")
            try:
                manifest, lock, _ = fetch.project_cargo_lock(lock_path.read_bytes())
            except (OSError, fetch.Refusal):
                _refuse("cargo-lock-projection-invalid")
            if manifest != self.projection_value["cargo_manifest"] or lock != self.projection_value["cargo_lock"]:
                _refuse("cargo-projection-mismatch")
            workspace_locks = ["fuzz/Cargo.lock", "runtime/Cargo.lock"]
            if set(self.manifest["original_lockfiles"]) != {"Cargo.lock", *workspace_locks}:
                _refuse("cargo-workspace-lock-set")
            workspace_projections = self.projection_value["cargo_workspaces"]
            if ([item.get("path") for item in workspace_projections] != workspace_locks):
                _refuse("cargo-workspace-count-mismatch")
            for path, workspace_projection in zip(workspace_locks, workspace_projections):
                try:
                    workspace_manifest, workspace_lock, _ = fetch.project_cargo_lock((source / path).read_bytes())
                except (OSError, fetch.Refusal):
                    _refuse("cargo-workspace-projection-invalid")
                if (workspace_manifest != workspace_projection["manifest"]
                        or workspace_lock != workspace_projection["lock"]):
                    _refuse("cargo-workspace-projection-mismatch")

    def _execute(self):
        if not self.probe_passed or not self.decrypted or self.execution_done:
            _refuse("execution-order")
        profile_name = self.context["profile"]
        profile = self.profile_config["profiles"].get(profile_name)
        if type(profile) is not dict or profile.get("revision") != 1:
            _refuse("profile-unknown")
        try:
            deadline_budget.remaining(self.deadline_file)
        except deadline_budget.DeadlineRefusal:
            _refuse("total-deadline-exhausted")
        source_root = self.root / "workspace/source"
        commands = profile.get("commands")
        stages = profile.get("stages")
        if profile_name == "core-rust":
            if commands != [] or stages != ["format", "deny", "audit", "vet", "unit"]:
                _refuse("profile-command-set")
            output = self.root / "scratch/reports/rust-matrix.jsonl"
            if os.path.lexists(output):
                _refuse("rust-matrix-report-exists")
            command = [
                "/usr/bin/python3", "-B", "-I", "-S", "/control/devlane/rust_matrix_runner.py",
                "/control/profiles.json", "/trusted/adapter-config.json", "/scratch/reports/rust-matrix.jsonl",
                "--deadline", str(self.deadline),
            ]
            try:
                matrix_timeout = deadline_budget.remaining(self.deadline_file)
            except deadline_budget.DeadlineRefusal:
                _refuse("total-deadline-exhausted")
            result = _run_control_adapter(self.root, command, "unit", self.tool_info,
                                          "rust-matrix-adapter.log", timeout=matrix_timeout,
                                          deadline=self.deadline_file, cpu_seconds=9900)
            adapter_results = {"rust_matrix": result}
            self.outcomes = [("unit", result)]
            allowlists = _manifest_allowlists(self.manifest, profile, source_root)
            records = _adapter_records(self.root, profile_name, self.manifest, [],
                                       self.tool_info, adapter_results)
            try:
                self.summary = output_filter.filter_records(records, allowlists)
                filter_failed = False
            except output_filter.FilterRefusal:
                filter_failed = True
                self.summary = output_filter._ascii_json({
                    "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
                })
            self.execution_done = True
            status = "pass" if result == 0 and not filter_failed and not _summary_failed(self.summary) else "fail"
            catalogs = {
                "files": sorted(set(self.manifest["allowed_files"].values())),
                "tests": sorted(set(self.manifest["allowed_tests"].values())),
                "frames": sorted(set(self.manifest["frames"].values())),
                "stages": list(profile["stages"]),
                "codes": sorted(set(profile.get("diagnostic_codes", []) + ["DEVLANE_FAILURE"])),
                "suites": sorted(profile["rust_matrix"]["coverage_ids"]),
            }
            return {"ok": True, "status": status,
                    "summary": base64.b64encode(self.summary).decode("ascii"), "catalogs": catalogs}
        if self.manifest["frames"]:
            commands = commands + [profile.get("browser_command")]
            stages = stages + ["browser"]
        if type(commands) is not list or type(stages) is not list or len(commands) != len(stages):
            _refuse("profile-command-set")
        outcomes = []
        for index, command in enumerate(commands):
            if CANCEL_REQUESTED.is_set():
                _refuse("execution-cancelled")
            stage = stages[index]
            try:
                phase_timeout = min(1200, deadline_budget.remaining(self.deadline_file))
            except deadline_budget.DeadlineRefusal:
                result = 124
            else:
                result = _run_profile_command(self.root, command, stage, "/workspace/raw/" + stage + ".log",
                                              self.tool_info, timeout=phase_timeout, deadline=self.deadline_file)
            if result == 130:
                _refuse("execution-cancelled")
            outcomes.append((stage, result))
            _kill_workload_descendants()
        adapter_results = {}
        if profile_name == "core-node":
            ts_output = self.root / "scratch/reports/typescript.jsonl"
            if ts_output.is_symlink() or ts_output.exists():
                ts_output.unlink()
            command = [
                "node", "/control/devlane/typescript_reporter.mjs", "/workspace/source",
                "/trusted/manifest.json", "/scratch/reports/typescript.jsonl",
                "/prepared/node_modules/typescript/lib/typescript.js",
            ]
            try:
                ts_timeout = min(600, deadline_budget.remaining(self.deadline_file))
            except deadline_budget.DeadlineRefusal:
                ts_timeout = 0
            ts_result = _run_control_adapter(self.root, command, "typecheck", self.tool_info,
                                             "typecheck-adapter.log", timeout=ts_timeout,
                                             deadline=self.deadline_file)
            adapter_results["typescript"] = ts_result
            if ts_result != 0:
                outcomes.append(("typecheck", 1))
        self.outcomes = outcomes
        allowlists = _manifest_allowlists(self.manifest, profile, source_root)
        records = _adapter_records(self.root, profile_name, self.manifest, outcomes, self.tool_info,
                                   adapter_results)
        filter_failed = False
        try:
            self.summary = output_filter.filter_records(records, allowlists, self.manifest["frames"].values())
        except output_filter.FilterRefusal:
            filter_failed = True
            self.summary = output_filter._ascii_json({
                "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
            })
        self.execution_done = True
        status = "pass" if all(code == 0 for _, code in outcomes) and not filter_failed and not _summary_failed(self.summary) else "fail"
        catalogs = {
            "files": sorted(set(self.manifest["allowed_files"].values())),
            "tests": sorted(set(self.manifest["allowed_tests"].values())),
            "frames": sorted(set(self.manifest["frames"].values())),
            "stages": list(profile["stages"]) + (["browser"] if self.manifest["frames"] else []),
            "codes": sorted(set(profile.get("diagnostic_codes", []) + ["DEVLANE_FAILURE"])),
        "suites": sorted(profile.get("rust_matrix", {}).get("coverage_ids", [])),
        }
        return {"ok": True, "status": status, "summary": base64.b64encode(self.summary).decode("ascii"),
                "catalogs": catalogs}

    def _summary(self):
        if not self.execution_done or self.summary is None:
            _refuse("summary-not-ready")
        return {"ok": True, "status": "pass" if all(code == 0 for _, code in self.outcomes) else "fail",
                "summary": base64.b64encode(self.summary).decode("ascii")}

    def _cleanup(self):
        CANCEL_REQUESTED.set()
        _kill_workload_descendants()
        failures = 0
        if self.root.is_symlink():
            _refuse("cleanup-root-invalid")
        for relative in (
            "workspace/source", "workspace/raw", "trusted", "scratch/tmp", "scratch/target",
            "scratch/reports", "scratch/npm-cache", "scratch/cargo-home",
        ):
            if not _shred_tree(self.root / relative):
                failures += 1
        for mount in reversed(tuple(dict.fromkeys(MOUNT_TARGETS))):
            if not os.path.ismount(mount):
                continue
            try:
                _run(["umount", str(mount)], timeout=8, cleanup=True)
            except SupervisorRefusal:
                try:
                    _run(["umount", "-l", str(mount)], timeout=8, cleanup=True)
                except SupervisorRefusal:
                    pass
            if os.path.ismount(mount):
                failures += 1
        MOUNT_TARGETS.clear()
        try:
            if self.root.exists():
                self.root.rmdir()
        except OSError:
            failures += 1
        if self.root.exists() or os.path.ismount(self.root):
            failures += 1
        if failures:
            _refuse("cleanup-incomplete")
        return {"ok": True, "status": "cleanup-confirmed"}

    def request(self, value):
        if type(value) is not dict or type(value.get("op")) is not str:
            _refuse("control-request-invalid")
        op = value["op"]
        if op == "cancel" and set(value) == {"op"}:
            CANCEL_REQUESTED.set()
            _kill_workload_descendants()
            return {"ok": True, "status": "cancellation-requested"}
        if op == "probe" and set(value) == {"op"}:
            return self._probe()
        if op == "decrypt" and set(value) == {"op", "key"}:
            return self._decrypt(value["key"])
        if op == "execute" and set(value) == {"op"}:
            return self._execute()
        if op == "summary" and set(value) == {"op"}:
            return self._summary()
        if op == "cleanup" and set(value) == {"op"}:
            CANCEL_REQUESTED.set()
            _kill_workload_descendants()
            response = self._cleanup()
            response["shutdown"] = True
            return response
        _refuse("control-operation-invalid")


def _serve(args):
    service = None
    server = None
    workers = []
    shutdown = threading.Event()
    result = 2
    startup_phase = "construct"
    ready = False
    try:
        service = Service(
            args.state_dir, args.context, args.workspace, args.prepared,
            args.bundle, args.projection, args.host_net_inode, args.owner_uid,
            {"node_snapshot_id": args.node_snapshot_id or "",
             "cargo": args.cargo_path or None, "rustc": args.rustc_path or None}, args.deadline_file,
        )
        startup_phase = "prepare"
        service.prepare()
        startup_phase = "socket"
        socket_path = Path(args.state_dir) / SOCKET_NAME
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        os.chown(str(socket_path), args.owner_uid, -1)
        os.chmod(str(socket_path), 0o600)
        startup_phase = "listen"
        server.listen(8)
        server.settimeout(0.5)
        startup_phase = "ready"
        ready_path = Path(args.state_dir) / READY_NAME
        """The supervisor's PID inside its own namespace is not a host identity; the privileged cleanup client resolves the host PID from the host /proc."""
        ready_path.write_text(json.dumps({"ready": True}), encoding="ascii")
        os.chown(str(ready_path), args.owner_uid, -1)
        os.chmod(str(ready_path), 0o600)
        ready = True
        startup_phase = "serve"

        def handle(connection):
            with connection:
                connection.settimeout(9900)
                try:
                    request = bundle.strict_json(_recv_frame(connection), MAX_RPC)
                    operation = request.get("op") if type(request) is dict else None
                    if operation == "cancel":
                        response = service.request(request)
                    else:
                        if operation == "cleanup":
                            CANCEL_REQUESTED.set()
                            _kill_workload_descendants()
                        with SERVICE_LOCK:
                            response = service.request(request)
                    stop = response.pop("shutdown", False) or operation == "cleanup"
                    _send_frame(connection, json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
                    if stop:
                        shutdown.set()
                except SupervisorRefusal as error:
                    payload = json.dumps({"ok": False, "code": error.code}, separators=(",", ":")).encode("ascii")
                    try:
                        _send_frame(connection, payload)
                    except OSError:
                        pass
                    if 'operation' in locals() and operation == "cleanup":
                        shutdown.set()
                except Exception:
                    try:
                        _send_frame(connection, b'{"ok":false,"code":"supervisor-failed"}')
                    except OSError:
                        pass
                    if 'operation' in locals() and operation == "cleanup":
                        shutdown.set()

        while not shutdown.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=handle, args=(connection,), daemon=True)
            workers.append(worker)
            worker.start()
        result = 0
    except SupervisorRefusal as error:
        if not ready:
            try:
                _record_startup_refusal(args.state_dir, args.owner_uid, error.code)
            except OSError:
                pass
        result = 2
    except Exception as error:
        if not ready:
            phase = service.startup_phase if startup_phase == "prepare" and service is not None else startup_phase
            try:
                _record_startup_refusal(
                    args.state_dir, args.owner_uid, _startup_exception_code(phase, error),
                )
            except OSError:
                pass
        result = 2
    finally:
        shutdown.set()
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        CANCEL_REQUESTED.set()
        _kill_workload_descendants()
        for worker in workers:
            worker.join(timeout=5)
        if service is not None:
            try:
                with SERVICE_LOCK:
                    service._cleanup()
            except Exception:
                result = 2
        for name in (SOCKET_NAME, READY_NAME):
            path = Path(args.state_dir) / name
            try:
                path.unlink()
            except OSError:
                pass
    return result


def _start(args):
    if not sys.platform.startswith("linux"):
        _refuse("linux-runner-required")
    try:
        start_deadline = time.monotonic() + min(30, deadline_budget.remaining(args.deadline_file))
    except deadline_budget.DeadlineRefusal:
        _refuse("total-deadline-unavailable")
    context = _context_from_file(args.context)
    _projection_bytes, projection_value = _bound_projection(context, args.projection)
    state_dir = Path(args.state_dir)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_dir.is_symlink() or state_dir.stat().st_uid != os.getuid() or stat.S_IMODE(state_dir.stat().st_mode) & 0o077:
        _refuse("state-directory-permissions")
    if any(state_dir.iterdir()):
        _refuse("state-directory-not-empty")
    try:
        positive = bundle.strict_json(Path(args.positive_control).read_bytes(), 1024)
    except (OSError, bundle.Refusal):
        _refuse("positive-control-unavailable")
    if positive != {"connected": True, "target": "public-tls-control"}:
        _refuse("positive-control-failed")
    if context["profile"] == "core-node":
        if not node_tool_snapshot.valid_snapshot_id(args.node_snapshot_id):
            _refuse("node-snapshot-id")
        tool_paths = {
            "node_snapshot_id": args.node_snapshot_id, "cargo": "", "rustc": "",
        }
    else:
        if args.node_snapshot_id:
            _refuse("node-snapshot-id")
        tool_paths = {
            "cargo": getattr(args, "cargo_path") or shutil.which("cargo") or "",
            "rustc": getattr(args, "rustc_path") or shutil.which("rustc") or "",
        }
    if context["profile"] == "core-rust":
        try:
            for name in ("cargo", "rustc"):
                """Real toolchain binaries only: a rustup proxy cannot run in the offline root."""
                target = Path(tool_paths[name]).resolve(strict=True)
                if not tool_paths[name] or not target.is_file() or target.name != name:
                    _refuse("rust-toolchain-path")
                tool_paths[name] = str(target)
            if not Path(tool_paths["rustc"]).is_relative_to(Path(tool_paths["cargo"]).parent.parent):
                _refuse("rust-toolchain-path")
        except (OSError, fetch.Refusal):
            _refuse("rust-toolchain-path")
    host_net_inode = os.stat("/proc/self/ns/net").st_ino
    command = [
        "sudo", "-n", "unshare", "--net", "--mount", "--pid", "--ipc", "--fork", "--mount-proc",
        "--kill-child",
        sys.executable, str(Path(__file__).resolve()), "_serve",
        "--state-dir", str(state_dir), "--context", str(Path(args.context).resolve()),
        "--workspace", str(Path(args.workspace).resolve(strict=True)),
        "--prepared", str(Path(args.prepared).resolve(strict=True)),
        "--bundle", str(Path(args.bundle).resolve(strict=True)),
        "--projection", str(Path(args.projection).absolute()),
        "--deadline-file", str(Path(args.deadline_file).resolve(strict=True)),
        "--host-net-inode", str(host_net_inode), "--owner-uid", str(os.getuid()),
        "--node-snapshot-id", tool_paths.get("node_snapshot_id", ""),
        "--cargo-path", tool_paths["cargo"], "--rustc-path", tool_paths["rustc"],
    ]
    try:
        start_deadline = min(start_deadline,
                             time.monotonic() + deadline_budget.remaining(args.deadline_file))
    except deadline_budget.DeadlineRefusal:
        _refuse("total-deadline-exhausted")
    try:
        child = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        (state_dir / PID_NAME).write_text(str(child.pid), encoding="ascii")
        os.chmod(state_dir / PID_NAME, 0o600)
        while time.monotonic() < start_deadline:
            if (state_dir / READY_NAME).is_file():
                print("offline_supervisor=ready")
                return 0
            if child.poll() is not None:
                refusal_path = state_dir / STARTUP_REFUSAL_NAME
                code = "supervisor-start-failed"
                try:
                    refusal = bundle.strict_json(refusal_path.read_bytes(), 1024)
                    if (type(refusal) is dict and set(refusal) == {"code"}
                            and type(refusal["code"]) is str
                            and (refusal["code"] in STARTUP_REFUSAL_CODES
                                 or refusal["code"] in STARTUP_DIAGNOSTIC_CODES)):
                        code = refusal["code"]
                except (OSError, bundle.Refusal):
                    pass
                try:
                    (state_dir / PID_NAME).unlink()
                except OSError:
                    pass
                _refuse(code)
            time.sleep(min(0.1, max(0, start_deadline - time.monotonic())))
        try:
            child.terminate()
            child.wait(timeout=3)
        except Exception:
            pass
        _refuse("supervisor-start-timeout")
    except SupervisorRefusal:
        raise
    except Exception as error:
        _refuse(_startup_exception_code("parent", error))


def _client(args):
    if args.operation == "probe":
        response = _rpc(args.state_dir, {"op": "probe"})
        print("network_cut_probe=pass")
        return 0
    if args.operation == "decrypt":
        key = os.environ.get("DEVLANE_DECRYPT_KEY", "")
        if not key:
            _refuse("decrypt-key-unavailable")
        try:
            response = _rpc(args.state_dir, {"op": "decrypt", "key": key})
        finally:
            os.environ.pop("DEVLANE_DECRYPT_KEY", None)
            key = ""
        print("authenticated_decryption=pass")
        return 0
    if args.operation == "execute":
        response = _rpc(args.state_dir, {"op": "execute"})
        if response.get("status") not in ("pass", "fail"):
            _refuse("summary-response-invalid")
        encoded = response.get("summary")
        if type(encoded) is not str or len(encoded) > 4 * MAX_SUMMARY:
            _refuse("summary-response-invalid")
        try:
            summary = base64.b64decode(encoded, validate=True)
        except Exception:
            _refuse("summary-response-invalid")
        context = _context_from_file(args.context)
        profiles = json.loads((Path(__file__).resolve().parents[2] / PROFILE_FILE).read_text(encoding="utf-8"))
        profile = profiles["profiles"][context["profile"]]
        catalogs = response.get("catalogs")
        if type(catalogs) is not dict or set(catalogs) != {"files", "tests", "frames", "stages", "codes", "suites"}:
            _refuse("summary-catalog-invalid")
        for name in ("files", "tests", "frames", "codes", "suites"):
            values = catalogs[name]
            if type(values) is not list or len(values) > 10_000 or any(type(item) is not str for item in values):
                _refuse("summary-catalog-invalid")
            if values != sorted(set(values)):
                _refuse("summary-catalog-invalid")
        if (any(not output_filter.IDENTIFIER.fullmatch(item) for key in ("files", "tests", "frames") for item in catalogs[key])
                or any(item not in output_filter.ALLOWED_STAGES for item in catalogs["stages"])
                or any(not output_filter.CODE.fullmatch(item) for item in catalogs["codes"])):
            _refuse("summary-catalog-invalid")
        expected_stages = list(profile["stages"])
        if catalogs["frames"]:
            expected_stages.append("browser")
        expected_codes = sorted(set(profile.get("diagnostic_codes", []) + ["DEVLANE_FAILURE"]))
        expected_suites = sorted(profile.get("rust_matrix", {}).get("coverage_ids", []))
        if (type(catalogs["stages"]) is not list or catalogs["stages"] != expected_stages
                or catalogs["codes"] != expected_codes or catalogs["suites"] != expected_suites):
            _refuse("summary-catalog-invalid")
        allowlists = {
            "files": {identifier: identifier for identifier in catalogs["files"]},
            "tests": {identifier: identifier for identifier in catalogs["tests"]},
            "frames": {identifier: identifier for identifier in catalogs["frames"]},
            "stages": catalogs["stages"], "codes": catalogs["codes"],
            "max_lines": {identifier: 10_000_000 for identifier in catalogs["files"]},
            "suites": catalogs["suites"],
        }
        _validate_host_records(summary, allowlists, profile)
        sys.stdout.buffer.write(summary)
        sys.stdout.buffer.flush()
        return 0 if response.get("status") == "pass" else 1
    if args.operation == "cleanup":
        _rpc(args.state_dir, {"op": "cleanup"})
        pid_path = Path(args.state_dir) / PID_NAME
        try:
            pid = int(pid_path.read_text(encoding="ascii"))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                _refuse("cleanup-process-remains")
        except (OSError, ValueError):
            _refuse("cleanup-receipt-invalid")
        try:
            pid_path.unlink()
            (Path(args.state_dir) / READY_NAME).unlink()
            Path(args.state_dir).rmdir()
        except OSError:
            _refuse("cleanup-incomplete")
        print("cleanup_receipt=confirmed")
        return 0
    _refuse("control-operation-invalid")


def _validate_host_records(payload, allowlists, profile):
    try:
        output_filter.validate_public_summary(payload, allowlists, allowlists["frames"].values())
    except output_filter.FilterRefusal:
        _refuse("summary-response-invalid")


def _argument_parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    start = sub.add_parser("start")
    for name in ("state-dir", "context", "workspace", "prepared", "bundle", "projection"):
        start.add_argument("--" + name, required=True)
    start.add_argument("--positive-control", required=True)
    start.add_argument("--deadline-file", required=True)
    start.add_argument("--node-snapshot-id", default="")
    for name in ("cargo-path", "rustc-path"):
        start.add_argument("--" + name, default="")
    client = sub.add_parser("_serve")
    for name in ("state-dir", "context", "workspace", "prepared", "bundle", "projection"):
        client.add_argument("--" + name, required=True)
    client.add_argument("--deadline-file", required=True)
    client.add_argument("--host-net-inode", type=int, required=True)
    client.add_argument("--owner-uid", type=int, required=True)
    client.add_argument("--node-snapshot-id", default="")
    for name in ("cargo-path", "rustc-path"):
        client.add_argument("--" + name, default="")
    for operation in ("probe", "decrypt", "execute", "cleanup"):
        command = sub.add_parser(operation)
        command.add_argument("--state-dir", required=True)
        if operation == "execute":
            command.add_argument("--context", required=True)
    return parser


def main(argv=None):
    args = _argument_parser().parse_args(argv)
    try:
        if args.operation == "start":
            return _start(args)
        if args.operation == "_serve":
            return _serve(args)
        return _client(args)
    except SupervisorRefusal as error:
        print("devlane_supervisor_refusal=" + error.code, file=sys.stderr)
        return 2
    except Exception as error:
        code = (_startup_exception_code("parent", error) if args.operation == "start"
                else "supervisor-failed")
        print("devlane_supervisor_refusal=" + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
