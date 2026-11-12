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
import struct
from pathlib import PurePosixPath
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import bundle
import bounded_registry_io
import deadline as deadline_budget
import fetch
import rust_lock_generation
import semver_stage
import semver_cargo_wrapper
import semver_offline_cache
import temp_project_checkpoints
import filter as output_filter
import network_probe
import prepare as node_tool_prepare
import node_tool_snapshot


MAX_RPC = 32 * 1024
MAX_SUMMARY = output_filter.MAX_SUMMARY_BYTES
MAX_SYNTHETIC_DIAGNOSTIC_LOGS = 48
MAX_SYNTHETIC_NODE_DIAGNOSTIC_LOGS = 16
MAX_SYNTHETIC_DIAGNOSTIC_TAIL_LINES = 120
MAX_SYNTHETIC_RUST_DIAGNOSTIC_TAIL_LINES = 40
MAX_SYNTHETIC_DIAGNOSTIC_TAIL_BYTES = 64 * 1024
MAX_SYNTHETIC_DIAGNOSTIC_LINE_BYTES = 128
MAX_SYNTHETIC_DIAGNOSTIC_REPORTS = 64
MAX_SYNTHETIC_DIAGNOSTIC_FILE_BYTES = 4 * 1024 * 1024
SOCKET_NAME = "control.sock"
READY_NAME = "ready.json"
PID_NAME = "host-pid"
STARTUP_REFUSAL_NAME = "startup-refusal.json"
WORKER_UID = 65534
WORKER_GID = 65534
SEMVER_TARGET_ROOT = "/scratch/semver-target"
SEMVER_PROJECT_ROOT = SEMVER_TARGET_ROOT + "/semver-checks"
SEMVER_CHECKPOINT_REPORT = "semver-checkpoints.json"
SEMVER_WORKER_SOCKET = "/scratch/semver-state/matrix-worker.sock"
SEMVER_CGROUP_ROOT = Path("/sys/fs/cgroup")
SEMVER_LOG_MAX = 256 * 1024 * 1024
SEMVER_MOUNTINFO_MAX = 4 * 1024 * 1024
MAX_CGROUP_ROSTER_BYTES = 16 * 1024
MAX_CGROUP_ROSTER_PIDS = 1024
PROFILE_FILE = "ci/devlane-profiles.json"
ACTIVE_CHILDREN = set()
ACTIVE_CHILDREN_LOCK = threading.Lock()
CANCEL_REQUESTED = threading.Event()
SERVICE_LOCK = threading.RLock()
MOUNT_TARGETS = []
ACTIVE_DEADLINE_FILE = ""
CLEANUP_SUBREASONS = frozenset((
    "umount-busy", "umount-missing", "tree-remove", "process-alive", "cgroup-nonempty",
))

REFUSAL_CODES = frozenset((
    "matrix-semver-cgroup-unavailable",
    "matrix-semver-cgroup-cleanup",
    "matrix-semver-context-write",
    "matrix-semver-cargo-home",
    "matrix-semver-inputs",
    "matrix-semver-process",
    "matrix-semver-runner-identity",
    "matrix-semver-runner-order",
    "matrix-semver-target",
    "matrix-semver-tool-binding",
    "matrix-semver-worker-channel",
    "matrix-semver-worker-peer",
    "source-free-diagnostics-context",
    "source-free-diagnostics-path",
    'matrix-semver-checkpoint-cgroup',
    'matrix-semver-checkpoint-cgroup-not-quiescent',
    'matrix-semver-checkpoint-command',
    'matrix-semver-checkpoint-contract',
    'matrix-semver-checkpoint-incomplete',
    'matrix-semver-checkpoint-lock-outside-closure',
    'matrix-semver-checkpoint-missing',
    'matrix-semver-checkpoint-order',
    'matrix-semver-checkpoint-peer',
    'matrix-semver-checkpoint-project-count',
    'matrix-semver-checkpoint-record-exists',
    'matrix-semver-checkpoint-record-size',
    'matrix-semver-checkpoint-record-write',
    'matrix-semver-checkpoint-request',
    'matrix-semver-checkpoint-snapshot',

    "allowlisted-file-too-large", "allowlisted-file-unavailable", "browser-profile-command",
    "bundle-binding-mismatch", "cargo-lock-binding-missing", "cargo-lock-projection-invalid",
    "offline-lock-generation-failed", "cargo-projection-mismatch", "cargo-vendor-missing", "cargo-workspace-count-mismatch",
    "cargo-workspace-lock-set", "cargo-workspace-projection-invalid", "cargo-workspace-projection-mismatch",
    "cleanup-incomplete", "cleanup-process-remains", "cleanup-receipt-invalid", "cleanup-root-invalid",
    "control-operation-invalid", "control-protocol-size", "control-protocol-truncated",
    "control-request-invalid", "control-response-invalid", "deadline-file-invalid", "decrypt-key-unavailable",
    "decrypt-manifest-unavailable", "decrypt-order", "decrypt-rejected", "decrypt-timeout",
    "dispatch-context-invalid", "dispatch-context-unavailable", "execution-cancelled", "execution-order",
    "firewall-unavailable", "input-size", "input-unavailable", "key-invalid", "linux-root-required",
    "linux-runner-required", "mount-source-unavailable", "network-namespace-changed",
    "network-namespace-not-isolated", "node-tool-layout",
    "node-snapshot-base-invalid", "node-snapshot-base-owner", "node-snapshot-base-unavailable",
    "node-snapshot-content-changed", "node-snapshot-content-invalid", "node-snapshot-deadline",
    "node-snapshot-id", "node-snapshot-layout", "node-snapshot-limit", "node-snapshot-link-invalid",
    "node-snapshot-manifest-invalid", "node-snapshot-manifest-invalid:link-row-path",
    "node-snapshot-manifest-invalid:source-row-kind",
    "node-snapshot-manifest-invalid:manifest-open",
    "node-snapshot-manifest-invalid:manifest-metadata",
    "node-snapshot-manifest-invalid:manifest-race",
    "node-snapshot-manifest-invalid:manifest-missing",
    "node-snapshot-manifest-invalid:manifest-shape",
    "node-snapshot-manifest-invalid:manifest-digest",
    "node-snapshot-manifest-invalid:unlisted-site",
    "node-snapshot-missing", "node-snapshot-seal-invalid",
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
    "semver-temporary-input-missing", "source-set-projection-mismatch",
    "summary-response-invalid", "supervisor-failed", "supervisor-operation-failed",
    "supervisor-start-failed", "supervisor-start-timeout", "supervisor-unavailable", "swap-enabled",
    "swap-state-unavailable", "tool-manifest-invalid", "tool-path-invalid", "tool-version-mismatch",
    "tool-version-unavailable", "total-deadline-exhausted", "total-deadline-unavailable",
    "typescript-report-incomplete",
))
NETWORK_PROBE_REFUSAL_CODES = frozenset(
    "network-probe-refusal:" + code for code in network_probe.REFUSAL_CODES
)
NETWORK_PROBE_DIAGNOSTIC_CODES = NETWORK_PROBE_REFUSAL_CODES | frozenset((
    "network-probe-command-failed", "network-probe-output-invalid",
))
REFUSAL_CODES |= NETWORK_PROBE_DIAGNOSTIC_CODES
REFUSAL_CODES |= frozenset("cleanup-incomplete:" + reason for reason in CLEANUP_SUBREASONS)
STARTUP_REFUSAL_CODES = frozenset((
    "deadline-file-invalid", "dispatch-context-invalid", "dispatch-context-unavailable",
    "firewall-unavailable", "input-size", "input-unavailable", "linux-root-required",
    "linux-runner-required", "mount-source-unavailable", "node-tool-layout",
    "node-snapshot-base-invalid", "node-snapshot-base-owner", "node-snapshot-base-unavailable",
    "node-snapshot-content-changed", "node-snapshot-content-invalid", "node-snapshot-deadline",
    "node-snapshot-id", "node-snapshot-layout", "node-snapshot-limit", "node-snapshot-link-invalid",
    "node-snapshot-manifest-invalid", "node-snapshot-manifest-invalid:link-row-path",
    "node-snapshot-manifest-invalid:source-row-kind",
    "node-snapshot-manifest-invalid:manifest-open",
    "node-snapshot-manifest-invalid:manifest-metadata",
    "node-snapshot-manifest-invalid:manifest-race",
    "node-snapshot-manifest-invalid:manifest-missing",
    "node-snapshot-manifest-invalid:manifest-shape",
    "node-snapshot-manifest-invalid:manifest-digest",
    "node-snapshot-manifest-invalid:unlisted-site",
    "node-snapshot-missing", "node-snapshot-seal-invalid",
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
    "source-free-diagnostics-context", "source-free-diagnostics-path",
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


class SemverCgroupJob:
    def __init__(self, path, attach_fd):
        self.path = Path(path)
        self.attach_fd = attach_fd

    def close_attach(self):
        if self.attach_fd is not None:
            os.close(self.attach_fd)
            self.attach_fd = None


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


SYNTHETIC_NODE_UNIT_DIAGNOSTIC_REASONS = frozenset(("report-missing", "adapter-failed", "vitest-failed"))


def _synthetic_failure_reason(summary, profile):
    if type(summary) is not bytes or len(summary) > MAX_SUMMARY:
        return ""
    if profile not in ("core-node", "core-rust"):
        return ""
    for line in summary.splitlines():
        try:
            record = bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES)
        except bundle.Refusal:
            continue
        if (type(record) is dict and record.get("kind") == "control"
                and record.get("stage") == "unit" and record.get("status") == "fail"
                and record.get("code") == "DEVLANE_FAILURE"):
            subreason = record.get("subreason")
            if (profile == "core-node" and subreason in SYNTHETIC_NODE_UNIT_DIAGNOSTIC_REASONS):
                return subreason
            if (profile == "core-rust" and subreason in ("report-missing", "adapter-failed")):
                return "rust-matrix-" + subreason
        if profile == "core-rust" and type(record) is dict:
            if (record.get("kind") == "control" and record.get("status") == "fail"
                    and record.get("stage") != "semver"):
                return "rust-matrix-failed"
            if record.get("kind") == "test" and record.get("stage") == "unit":
                return "rust-matrix-failed"
            if (record.get("kind") == "control" and record.get("status") == "fail"
                    and record.get("stage") == "semver"):
                return "rust-matrix-failed"
            if (record.get("kind") == "coverage"
                    and type(record.get("failed")) is int and record["failed"] > 0):
                return "rust-matrix-failed"
            if (record.get("kind") == "diagnostic"
                    and record.get("level") == "error"):
                return "rust-matrix-failed"
    return ""


_SYNTHETIC_RUST_MATRIX_LOG_STEMS = tuple(
    [prefix + "-" + workspace for prefix in ("fmt", "deny", "audit", "vet")
     for workspace in ("root", "runtime", "fuzz")]
    + ["compile-" + scope + "-" + feature for scope in ("root", "runtime", "fuzz", "listener")
       for feature in ("default", "all-features")]
    + ["replay-fuzz-replay-default", "replay-fuzz-replay-all-features"]
)


_SYNTHETIC_DIAGNOSTIC_CANARIES = (
    b"SYNTHETIC_SOURCE_CANARY", b"PRIVATE_SOURCE_CANARY",
    b"SYNTHETIC_KEY_CANARY", b"PRIVATE_KEY_CANARY", b"KEYCANARY-73A10X",
    (b"KEYCANARY-73A10X" + bytes(range(16))).hex().encode("ascii"),
    (b"KEYCANARY-73A10X" + bytes(range(16))).hex().upper().encode("ascii"),
    b"::add-mask::SYNTHETIC_SOURCE_CANARY_7f8c",
    b"::error::SYNTHETIC_SOURCE_CANARY_7f8c",
    bytes((35, 35)) + b"[group]SYNTHETIC_SOURCE_CANARY_7f8c",
    b"::set-output name=x::SYNTHETIC_SOURCE_CANARY_7f8c",
)


def _synthetic_diagnostic_line_safe(line):
    return not any(canary in line for canary in _SYNTHETIC_DIAGNOSTIC_CANARIES)


def _synthetic_rust_diagnostic_log_stems(summary):
    stems = set()
    if type(summary) is not bytes or len(summary) > MAX_SUMMARY:
        return stems
    for line in summary.splitlines():
        try:
            record = bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES)
        except bundle.Refusal:
            continue
        if type(record) is not dict:
            continue
        if (record.get("kind") == "control" and record.get("status") == "fail"
                and record.get("stage") != "semver"):
            continue
        if (record.get("kind") == "control" and record.get("status") == "fail"
                and record.get("stage") == "semver"):
            stems.add("semver-analyzer")
            continue
        if record.get("kind") != "coverage":
            continue
        suite = record.get("suite")
        if type(record.get("failed")) is not int or record["failed"] <= 0:
            continue
        if record.get("stage") == "semver":
            stems.add("semver-analyzer")
            continue
        if type(suite) is not str:
            continue
        if re.fullmatch(r"(?:fmt|deny|audit|vet)-(?:root|runtime|fuzz)", suite):
            stems.add(suite)
        elif re.fullmatch(r"fuzz-replay-(?:default|all-features)", suite):
            stems.add("replay-" + suite)
        elif re.fullmatch(r"(?:root|runtime|fuzz|listener)-(?:default|all-features)", suite):
            stems.add("compile-" + suite)
    return stems


def _synthetic_rust_adapter_log_requested(summary):
    if type(summary) is not bytes or len(summary) > MAX_SUMMARY:
        return False
    for line in summary.splitlines():
        try:
            record = bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES)
        except bundle.Refusal:
            continue
        if (type(record) is dict and record.get("kind") == "control"
                and record.get("status") == "fail" and record.get("stage") != "semver"):
            return True
    return False


def _synthetic_diagnostic_log_tail(path, max_lines=MAX_SYNTHETIC_DIAGNOSTIC_TAIL_LINES):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                return None
            start = max(0, metadata.st_size - MAX_SYNTHETIC_DIAGNOSTIC_TAIL_BYTES)
            if start:
                source.seek(start - 1)
                on_boundary = source.read(1) == b"\n"
            else:
                on_boundary = True
            source.seek(start)
            payload = source.read(MAX_SYNTHETIC_DIAGNOSTIC_TAIL_BYTES)
    except OSError:
        return None
    lines = payload.split(b"\n")
    if not on_boundary and lines:
        lines = lines[1:]
    if lines and lines[-1] == b"":
        lines.pop()
    selected = []
    for line in lines[-max_lines:]:
        if _synthetic_diagnostic_line_safe(line):
            selected.append(line[:MAX_SYNTHETIC_DIAGNOSTIC_LINE_BYTES])
    return selected


def _synthetic_diagnostic_reports(root):
    reports = Path(root) / "scratch/reports"
    try:
        metadata = reports.lstat()
    except OSError:
        return [{"name": "reports", "kind": "missing", "bytes": 0}]
    if stat.S_ISLNK(metadata.st_mode):
        return [{"name": "reports", "kind": "symlink", "bytes": 0}]
    if not stat.S_ISDIR(metadata.st_mode):
        return [{"name": "reports", "kind": "other", "bytes": 0}]
    result = [{"name": "reports", "kind": "directory", "bytes": 0}]
    try:
        entries = sorted(reports.iterdir(), key=lambda item: item.name)[:MAX_SYNTHETIC_DIAGNOSTIC_REPORTS]
    except OSError:
        entries = []
    for path in entries:
        try:
            metadata = path.lstat()
        except OSError:
            kind, size = "missing", 0
        else:
            if stat.S_ISLNK(metadata.st_mode):
                kind, size = "symlink", 0
            elif stat.S_ISDIR(metadata.st_mode):
                kind, size = "directory", 0
            elif stat.S_ISREG(metadata.st_mode):
                kind, size = "file", min(metadata.st_size, 999_999_999_999)
            else:
                kind, size = "other", 0
        result.append({"name": path.name, "kind": kind, "bytes": size})
    return result


def _capture_source_free_failure_diagnostics(root, destination, owner_uid, wave_class, profile, summary,
                                            *, execution_failed=False):
    """Copy bounded synthetic-only diagnostics before the private namespace is shredded."""
    if profile not in ("core-node", "core-rust"):
        return False
    subreason = _synthetic_failure_reason(summary, profile)
    if not subreason and execution_failed:
        subreason = "execute-failed"
    if (wave_class != fetch.SOURCE_FREE_WAVE_CLASS or not subreason or not destination):
        return False
    path = Path(destination)
    if (not path.is_absolute()
            or re.fullmatch(r"devlane-(?:vitest|rust-matrix)-[A-Za-z0-9_-]{1,128}\.json", path.name) is None):
        return False
    logs = []
    if profile == "core-node":
        raw_root = Path(root) / "workspace/raw"
        patterns = ("*.log",)
        candidates = []
        try:
            if stat.S_ISDIR(raw_root.lstat().st_mode):
                candidates = sorted(
                    (path for pattern in patterns for path in raw_root.glob(pattern)),
                    key=lambda item: item.name,
                )
        except OSError:
            pass
        scratch_raw = Path(root) / "scratch/raw"
        try:
            if stat.S_ISDIR(scratch_raw.lstat().st_mode):
                candidates.extend(
                    path for path in sorted(scratch_raw.iterdir(), key=lambda item: item.name)
                    if path.suffix in (".log", ".stdout", ".stderr")
                )
        except OSError:
            pass
    else:
        raw_root = Path(root) / "scratch/raw"
        candidates = []
        adapter_requested = (_synthetic_rust_adapter_log_requested(summary) or execution_failed)
        stems = _synthetic_rust_diagnostic_log_stems(summary)
        if adapter_requested:
            stems.update(_SYNTHETIC_RUST_MATRIX_LOG_STEMS)
        try:
            raw_root_available = stat.S_ISDIR(raw_root.lstat().st_mode)
        except OSError:
            raw_root_available = False
        if raw_root_available:
            for stem in sorted(stems):
                if stem == "semver-analyzer":
                    continue
                candidates.extend((raw_root / (stem + ".stdout"), raw_root / (stem + ".stderr")))
        adapter_log = Path(root) / "workspace/raw/rust-matrix-adapter.log"
        if adapter_requested:
            try:
                if stat.S_ISDIR(adapter_log.parent.lstat().st_mode):
                    candidates.insert(0, adapter_log)
            except OSError:
                pass
        if "semver-analyzer" in stems or adapter_requested:
            semver_log = Path(root) / "workspace/raw/semver-analyzer.log"
            try:
                if stat.S_ISDIR(semver_log.parent.lstat().st_mode):
                    candidates.append(semver_log)
            except OSError:
                pass
    max_logs = (MAX_SYNTHETIC_NODE_DIAGNOSTIC_LOGS
                if profile == "core-node" else MAX_SYNTHETIC_DIAGNOSTIC_LOGS)
    for log_path in candidates[:max_logs]:
        max_tail_lines = (MAX_SYNTHETIC_RUST_DIAGNOSTIC_TAIL_LINES
                          if profile == "core-rust" else MAX_SYNTHETIC_DIAGNOSTIC_TAIL_LINES)
        tail = _synthetic_diagnostic_log_tail(log_path, max_tail_lines)
        if tail is not None:
            logs.append({"name": log_path.name,
                         "lines": [base64.b64encode(line).decode("ascii") for line in tail]})
    document = {
        "schema": 1,
        "wave_class": fetch.SOURCE_FREE_WAVE_CLASS,
        "subreason": subreason,
        "logs": logs,
        "reports": _synthetic_diagnostic_reports(root),
    }
    try:
        payload = bundle.canonical_json(document) + b"\n"
        if len(payload) > MAX_SYNTHETIC_DIAGNOSTIC_FILE_BYTES:
            return False
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    except (OSError, bundle.Refusal):
        return False
    created = True
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("diagnostic-write-failed")
            view = view[written:]
        os.fsync(descriptor)
        os.fchown(descriptor, owner_uid, -1)
        os.fchmod(descriptor, 0o600)
        return True
    except OSError:
        if created:
            try:
                os.unlink(path)
            except OSError:
                pass
        return False
    finally:
        os.close(descriptor)


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


def _mount_fs(argv, destination):
    _run(argv)
    MOUNT_TARGETS.append(Path(destination))


def _make_worker_devices(dev):
    """Create only the worker's standard devices with modes unaffected by umask."""
    for name, mode, major, minor in (("null", 0o666, 1, 3), ("zero", 0o666, 1, 5),
                                     ("random", 0o444, 1, 8), ("urandom", 0o444, 1, 9)):
        device = Path(dev) / name
        os.mknod(str(device), stat.S_IFCHR | mode, os.makedev(major, minor))
        os.chmod(device, mode)


def _host_toolchain_mounts(root):
    mounts = [("/usr", root / "usr"), ("/lib", root / "lib"), ("/lib64", root / "lib64")]
    alternatives = Path("/etc/alternatives")
    if alternatives.is_dir():
        mounts.append((alternatives, root / "etc/alternatives"))
    return tuple(mounts)


def _unmount_tracked_mounts(mounts=None):
    """Release every tracked mount leaf-first and return a path-free failure class."""
    targets = MOUNT_TARGETS if mounts is None else mounts
    reason = ""
    for mount in reversed(tuple(dict.fromkeys(Path(target) for target in targets))):
        if not mount.exists() and not os.path.ismount(mount):
            reason = reason or "umount-missing"
            continue
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
            reason = reason or "umount-busy"
    return reason


def _mount_minimal_root(root, workspace, prepared, control_root):
    _ensure_directory(root)
    _mount_tmpfs(root, "2g", "0755", "nosuid,nodev")
    for name in (
        "bin", "sbin", "lib", "lib64", "usr", "opt", "etc", "dev", "proc", "run",
        "tmp", "home", "devlane-home", "control", "prepared", "workspace", "scratch", "var", "tools", "sys",
    ):
        _ensure_directory(root / name, 0o755)
    for host, guest in _host_toolchain_mounts(root):
        if Path(host).exists():
            if guest == root / "etc/alternatives":
                _ensure_directory(guest)
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
    _make_worker_devices(root / "dev")
    _ensure_directory(root / "dev/shm", 0o1777)
    _mount_tmpfs(root / "dev/shm", "512m", "01777")
    _mount_tmpfs(root / "tmp", "512m", "01777", "nosuid,nodev")
    _mount_tmpfs(root / "workspace", "4g", "0755", "nosuid,nodev")
    _mount_tmpfs(root / "scratch", "4g", "0755", "nosuid,nodev")
    _mount_bind(prepared, root / "prepared", readonly=True)
    _ensure_directory(root / "control/devlane")
    (root / "control/bundle.enc").write_bytes(b"")
    _mount_bind(control_root / "kit/devlane", root / "control/devlane", readonly=True)
    (root / "control/profiles.json").write_text("{}", encoding="ascii")
    _mount_bind(control_root / "ci/devlane-profiles.json", root / "control/profiles.json", readonly=True)
    _mount_fs(["mount", "-t", "proc", "-o", "ro,hidepid=2,subset=pid", "proc", str(root / "proc")],
              root / "proc")
    _mount_fs(["mount", "-t", "sysfs", "-o", "ro,nosuid,nodev,noexec", "sysfs", str(root / "sys")],
              root / "sys")
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
        value = fetch.validate_projection(
            payload, context["profile"], expected_control_sha=context["control_sha"],
        )
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
        "XDG_CACHE_HOME": "/scratch/tmp",
        "PLAYWRIGHT_BROWSERS_PATH": "/prepared/ms-playwright",
        "DEVLANE_STAGE": stage,
    }
    if rust_path:
        env["LD_LIBRARY_PATH"] = "/tools/rust/lib"
        env["CC"] = "/usr/bin/cc"
        env["CARGO_TARGET_" + "X" + "86_64_UNKNOWN_LINUX_GNU_LINKER"] = "/usr/bin/cc"
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
    if not sys.platform.startswith("linux") or os.getpid() != 1:
        _refuse("linux-runner-required")
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


def _signal_workload_descendants():
    """Request termination without stealing wait status from active Popen owners."""
    if not sys.platform.startswith("linux") or os.getpid() != 1:
        _refuse("linux-runner-required")
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


def _run_control_adapter(root, command, stage, tools, log_name, timeout=60, deadline=None,
                         cpu_seconds=1200, on_spawn=None):
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
        if on_spawn is not None:
            on_spawn(process)
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


def _seal_tree_root_readonly(root):
    root = Path(root)
    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        current_path = Path(current)
        if current_path.is_symlink() or not current_path.is_dir():
            _refuse("prepared-input-invalid")
        for name in files:
            path = current_path / name
            try:
                metadata = path.lstat()
            except OSError:
                _refuse("prepared-input-invalid")
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                _refuse("prepared-input-invalid")
            try:
                os.chown(path, 0, 0, follow_symlinks=False)
                os.chmod(path, 0o444, follow_symlinks=False)
            except OSError:
                _refuse("prepared-input-invalid")
        for name in directories:
            path = current_path / name
            if path.is_symlink() or not path.is_dir():
                _refuse("prepared-input-invalid")
            try:
                os.chown(path, 0, 0, follow_symlinks=False)
                os.chmod(path, 0o555, follow_symlinks=False)
            except OSError:
                _refuse("prepared-input-invalid")
        try:
            os.chown(current_path, 0, 0, follow_symlinks=False)
            os.chmod(current_path, 0o555, follow_symlinks=False)
        except OSError:
            _refuse("prepared-input-invalid")


def _stage_baseline_runtime_after_cut(source_root, namespace_root, source_sets):
    """Move the authenticated baseline into a root-owned read-only post-cut mount."""
    baseline = source_sets["baseline_runtime"]
    source_parent = Path(source_root) / ".devlane"
    source = source_parent / "baseline-runtime"
    private_root = Path(namespace_root) / "workspace/.devlane-baseline-input/runtime"
    mountpoint = Path(namespace_root) / "workspace/semver-baseline/runtime"
    try:
        if (source_parent.is_symlink() or not source_parent.is_dir()
                or sorted(os.listdir(source_parent)) != ["baseline-runtime"]
                or source.is_symlink() or not source.is_dir()
                or private_root.exists() or private_root.is_symlink()
                or mountpoint.exists() or mountpoint.is_symlink()):
            _refuse("prepared-input-invalid")
        files, total = bundle._read_regular_tree(source)
        hashes = {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()}
        if (len(files) != baseline["file_count"] or total != baseline["bytes"]
                or bundle.r4_source_map_sha256(hashes) != baseline["map_sha256"]
                or hashes.get("Cargo.toml") != baseline["runtime_manifest_sha256"]
                or hashes.get("Cargo.lock") != baseline["runtime_lock_sha256"]):
            _refuse("prepared-input-invalid")
        if os.stat(source).st_dev != os.stat(private_root.parent.parent).st_dev:
            _refuse("prepared-input-invalid")
        private_root.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.rename(source, private_root)
        source_parent.rmdir()
        _seal_tree_root_readonly(private_root)
        mountpoint.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
        mountpoint.mkdir(mode=0o700)
        _mount_bind(private_root, mountpoint, readonly=True)
    except SupervisorRefusal:
        raise
    except (OSError, bundle.Refusal, KeyError, TypeError):
        _refuse("prepared-input-invalid")
    return mountpoint


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


def _prepare_writable_scratch(root, *, registry_v2=False):
    for relative in ("scratch/reports", "scratch/raw", "scratch/target", "scratch/tmp", "scratch/tmp/vitest-cache",
                     "scratch/npm-cache", "scratch/cargo-home"):
        path = root / relative
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(str(path), WORKER_UID, WORKER_GID)
    cargo_config = root / "scratch/cargo-home/config.toml"
    if registry_v2:
        config = ('[source.crates-io]\nreplace-with = "prepared-registry"\n'
                  '[source.prepared-registry]\nlocal-registry = "/prepared/cargo-local-registry"\n'
                  '[net]\noffline = true\nretry = 0\n')
    else:
        config = ('[source.crates-io]\nreplace-with = "vendored-sources"\n'
                  '[source.vendored-sources]\ndirectory = "/prepared/cargo-vendor"\n'
                  '[net]\noffline = true\n')
    cargo_config.write_text(config, encoding="ascii")
    os.chmod(cargo_config, 0o444)


def _copy_prepared_dependencies(root, profile, *, registry_v2=False):
    if profile == "core-node":
        source = root / "prepared/node_modules"
        destination = root / "workspace/source/node_modules"
        _copy_prepared_tree(source, destination)
        _chown_tree(destination)
    elif profile == "core-rust":
        vendor = root / ("prepared/cargo-local-registry" if registry_v2 else "prepared/cargo-vendor")
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


UNIT_FAILURE_SUBREASONS = frozenset((
    "report-missing", "adapter-failed", "filter-refused", "vitest-failed",
))
BROWSER_MEDIA_SUFFIXES = frozenset((
    ".avif", ".bmp", ".gif", ".har", ".jpeg", ".jpg", ".mkv", ".mov", ".mp4",
    ".png", ".tif", ".tiff", ".trace", ".webm", ".zip",
))


def _control_failure(stage, subreason=None):
    record = {"kind": "control", "stage": stage, "status": "fail", "code": "DEVLANE_FAILURE"}
    if subreason is not None:
        if stage != "unit" or subreason not in UNIT_FAILURE_SUBREASONS:
            raise ValueError("invalid unit failure subreason")
        record["subreason"] = subreason
    return json.dumps(record, separators=(",", ":")).encode("ascii")


def _browser_media_outputs_present(root):
    for relative in ("scratch/playwright-results", "scratch/reports"):
        directory = Path(root) / relative
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return True
        if not stat.S_ISDIR(metadata.st_mode):
            return True
        pending = [directory]
        while pending:
            current = pending.pop()
            try:
                entries = list(os.scandir(current))
            except OSError:
                return True
            for entry in entries:
                try:
                    entry_mode = entry.stat(follow_symlinks=False).st_mode
                except OSError:
                    return True
                if stat.S_ISDIR(entry_mode):
                    pending.append(Path(entry.path))
                elif not stat.S_ISREG(entry_mode):
                    return True
                elif Path(entry.name).suffix.lower() in BROWSER_MEDIA_SUFFIXES:
                    return True
    return False


def _filter_failure_summary():
    return output_filter._ascii_json({
        "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
        "subreason": "filter-refused",
    })


def _adapter_lines(output, result, stage, *, rule):
    """Records from a control adapter, only if the adapter demonstrably completed.

    A report file that merely exists proves nothing: it may be precreated, truncated by a
    crash or a timeout, or written by the workload. The adapter must have exited with one of
    its two defined statuses, left a complete newline-terminated regular file, and its
    status must agree with the records it wrote. Anything else is one fixed failure.
    """
    failure = _control_failure(stage, "adapter-failed") if stage == "unit" else _control_failure(stage)
    try:
        if result not in (0, 1) or not os.path.lexists(output):
            return [failure]
        payload = _read_regular(output, output_filter.MAX_RAW_CAPTURE_BYTES)
        if payload and not payload.endswith(b"\n"):
            return [failure]
        lines = payload.splitlines()
        parsed = [bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES) for line in lines]
        if any(type(item) is not dict for item in parsed):
            return [failure]
        control_failed = any(item.get("kind") == "control" and item.get("status") == "fail" for item in parsed)
        if rule == "tests":
            """Rust: status 1 means at least one failing test record; 0 means no records at all."""
            consistent = (result == 1) == bool(lines) and not control_failed
        else:
            """Node adapters: status 1 means a fixed control failure; otherwise none may appear."""
            consistent = (result == 1) == control_failed
        if not consistent:
            return [failure]
        if control_failed:
            return [failure]
        return lines
    except (SupervisorRefusal, bundle.Refusal, OSError):
        return [failure]


def _adapter_records(root, profile, manifest, outcomes, tools, adapter_results=None):
    adapter_results = adapter_results or {}
    records = []
    if profile == "core-rust":
        output = root / "scratch/reports/rust-matrix.jsonl"
        result = adapter_results.get("rust_matrix", 125)
        failure_subreason = "adapter-failed"
        try:
            if not os.path.lexists(output):
                failure_subreason = "report-missing"
                _refuse("rust-matrix-report-unavailable")
            if result not in (0, 1):
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
            for record in records:
                if (record.get("kind") == "control" and record.get("stage") == "unit"
                        and record.get("status") == "fail" and "subreason" not in record):
                    record["subreason"] = "adapter-failed"
            records = [json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                       for record in records]
        except (SupervisorRefusal, bundle.Refusal, OSError, KeyError, TypeError):
            records = [_control_failure("unit", failure_subreason)]
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
            unit_records = _adapter_lines(output, result, "unit", rule="node")
            records.extend(unit_records)
            if (any(stage == "unit" and code != 0 for stage, code in outcomes)
                    and not any(b'"kind":"control"' in record for record in unit_records)):
                records.append(_control_failure("unit", "vitest-failed"))
        else:
            records.append(_control_failure("unit", "report-missing"))
        if manifest["frames"]:
            if _browser_media_outputs_present(root):
                records.append(_control_failure("browser"))
            else:
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
        if code != 0 and not (profile == "core-node" and stage == "unit"):
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
                 host_net_inode, owner_uid, tool_paths, deadline_file, failure_diagnostics_file=None):
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
        self.failure_diagnostics_file = failure_diagnostics_file
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
        self.baseline_staged = False
        self.semver_temporary_project_ready = False
        self.execution_done = False
        self.semver_active = None
        self.semver_active_lock = threading.Lock()
        self.semver_checkpoint_record = None
        self.matrix_runner_active = None
        self.matrix_runner_lock = threading.Lock()
        self.matrix_runner_ready = threading.Event()
        self.semver_worker_socket = None
        self.semver_worker_socket_path = None
        self.semver_worker_accept_thread = None
        self.semver_worker_threads = []
        self.semver_worker_threads_lock = threading.Lock()
        self.summary = None
        self.outcomes = []
        self.mounts = []

    def _capture_failure_diagnostics(self, *, execution_failed=False):
        try:
            return _capture_source_free_failure_diagnostics(
                self.root, self.failure_diagnostics_file, self.owner_uid,
                self.context.get("wave_class"), self.context.get("profile"), self.summary,
                execution_failed=execution_failed,
            )
        except Exception:
            return False

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
            self.root / "proc", self.root / "sys", self.root / "dev/shm", self.root / "dev", self.root / "tmp", self.root / "workspace",
            self.root / "scratch", self.root / "prepared", self.root / "control/profiles.json",
            self.root / "control/devlane", self.root / "etc/ssl/certs", self.root / "etc/alternatives",
            self.root / "tools/rust", self.root / "tools/node", self.root / "lib64", self.root / "lib",
            self.root / "usr", self.root,
        ]
        self.startup_phase = "profile"
        self.profile_config = _read_profiles(self.root)
        self.projection_value = projection_value
        if self.context["profile"] == "core-rust":
            try:
                self.semver_tool_path = semver_stage.verify_tool(
                    self.root / "prepared/devlane-tools",
                )
            except semver_stage.SemverRefusal:
                _refuse("matrix-semver-tool-binding")
        if self.context["profile"] == "core-node":
            self.startup_phase = "versions"
            _node_info, versions = _node_snapshot_versions(self.tool_info["node_snapshot_id"], self.owner_uid)
            if versions != {"node": "v" + node_tool_prepare.NODE_VERSION,
                            "npm": node_tool_prepare.NPM_VERSION}:
                _refuse("node-toolchain-version")
        self.startup_phase = "ready"
        return True

    def start_semver_worker_socket(self):
        if self.context["profile"] != "core-rust":
            return None
        path = self.root / "scratch/semver-state/matrix-worker.sock"
        server = None
        try:
            path.parent.mkdir(mode=0o711, parents=False, exist_ok=False)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            os.chown(str(path), WORKER_UID, WORKER_GID)
            os.chmod(str(path), 0o600)
            server.listen(16)
            server.settimeout(0.5)
        except OSError:
            try:
                server.close()
            except (OSError, UnboundLocalError):
                pass
            _refuse("matrix-semver-worker-channel")
        self.semver_worker_socket = server
        self.semver_worker_socket_path = path
        return server

    def stop_semver_worker_socket(self):
        server = self.semver_worker_socket
        self.semver_worker_socket = None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        path = self.semver_worker_socket_path
        self.semver_worker_socket_path = None
        if path is not None:
            try:
                metadata = path.lstat()
                if not stat.S_ISSOCK(metadata.st_mode):
                    _refuse("matrix-semver-worker-channel")
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                _refuse("matrix-semver-worker-channel")

    def _handle_semver_worker_connection(self, connection):
        with connection:
            connection.settimeout(10)
            try:
                credentials = connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"),
                )
                if len(credentials) != struct.calcsize("3i"):
                    _refuse("matrix-semver-worker-peer")
                peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
                if peer_uid != WORKER_UID or peer_gid != WORKER_GID:
                    _refuse("matrix-semver-worker-peer")
                request = bundle.strict_json(_recv_frame(connection), MAX_RPC)
                response = self.dispatch_semver_worker(
                    request, peer_pid, peer_uid, peer_gid,
                )
                payload = bundle.canonical_json(response)
            except SupervisorRefusal as error:
                payload = bundle.canonical_json({"ok": False, "code": error.code})
            except Exception:
                payload = b'{"code":"matrix-semver-worker-channel","ok":false}'
            try:
                _send_frame(connection, payload)
            except (OSError, SupervisorRefusal):
                pass

    def _shutdown_semver_workers(self):
        self.stop_semver_worker_socket()
        accept_thread = self.semver_worker_accept_thread
        if accept_thread is not None and accept_thread is not threading.current_thread():
            accept_thread.join(timeout=5)
            if accept_thread.is_alive():
                _refuse("matrix-semver-worker-channel")
        with self.semver_worker_threads_lock:
            workers = tuple(self.semver_worker_threads)
        while True:
            with self.semver_active_lock:
                active = self.semver_active
            if active is None:
                break
            job = active.get("job")
            owner_done = active.get("owner_done")
            if owner_done is not None and owner_done.is_set():
                try:
                    budget = bounded_registry_io.PhaseBudget(
                        active["work_deadline"], active["cleanup_deadline"],
                        cancelled=lambda: False,
                    )
                    cleaned = self._semver_cleanup_cgroup(
                        active, active.get("process"), budget,
                    )
                except Exception:
                    cleaned = False
                if cleaned:
                    with self.semver_active_lock:
                        if self.semver_active is active:
                            self.semver_active = None
                    process = active.get("process")
                    if process is not None:
                        with ACTIVE_CHILDREN_LOCK:
                            ACTIVE_CHILDREN.discard(process.pid)
                    active["ready"].set()
                    continue
            if job is not None:
                try:
                    self._semver_kill_cgroup(job)
                except SupervisorRefusal:
                    pass
            if time.monotonic() >= active.get("cleanup_deadline", 0):
                _refuse("matrix-semver-cgroup-cleanup")
            time.sleep(0.01)
        for worker in workers:
            if worker is threading.current_thread():
                continue
            worker.join(timeout=5)
            if worker.is_alive():
                _refuse("matrix-semver-worker-channel")

    def dispatch_semver_worker(self, request, peer_pid, peer_uid, peer_gid):
        if (type(request) is not dict or type(request.get("op")) is not str
                or type(peer_pid) is not int or peer_pid <= 1
                or peer_uid != WORKER_UID or peer_gid != WORKER_GID):
            _refuse("matrix-semver-worker-peer")
        if request["op"] == "semver-stage":
            if set(request) != {"op"}:
                _refuse("matrix-semver-runner-order")
            return self._semver_stage_request(peer_pid)
        if request["op"] == "semver-checkpoint":
            return self._semver_checkpoint(request, peer_pid, peer_uid)
        _refuse("matrix-semver-worker-channel")

    def _semver_stage_request(self, peer_pid):
        if not self.matrix_runner_ready.wait(timeout=5):
            _refuse("matrix-semver-runner-order")
        with self.matrix_runner_lock:
            active = self.matrix_runner_active
            if (active is None or active.get("pid") != peer_pid
                    or active.get("semver_requested")):
                _refuse("matrix-semver-runner-order")
            active["semver_requested"] = True
        try:
            outer = deadline_budget._read(self.deadline_file)
            peer_budget = bounded_registry_io.PhaseBudget.from_outer_deadlines(
                outer["work_deadline"],
                outer["work_deadline"] + outer["cleanup_reserve"],
            )
            status = self._semver_proc_bytes(
                peer_pid, "status", 64 * 1024, peer_budget,
            ).decode("ascii", "strict")
            parent = None
            effective_uid = None
            for line in status.splitlines()[:64]:
                if line.startswith("PPid:"):
                    value = line[5:].strip()
                    parent = int(value) if value.isascii() and value.isdecimal() else None
                elif line.startswith("Uid:"):
                    values = line[4:].split()
                    if len(values) >= 2 and values[1].isascii() and values[1].isdecimal():
                        effective_uid = int(values[1])
            arguments = self._semver_proc_bytes(
                peer_pid, "cmdline", 16 * 1024, peer_budget,
            ).split(b"\x00")
            if arguments and arguments[-1] == b"":
                arguments.pop()
            words = [item.decode("utf-8", "strict") for item in arguments]
            expected_words = [
                "/usr/bin/python3", "-B", "-I", "-S",
                "/control/devlane/rust_matrix_runner.py",
                "/control/profiles.json", "/trusted/adapter-config.json",
                "/scratch/reports/rust-matrix.jsonl", "--deadline", str(self.deadline),
            ]
            if (parent != os.getpid() or effective_uid != WORKER_UID
                    or words != expected_words):
                _refuse("matrix-semver-runner-identity")
        except (SupervisorRefusal, OSError, UnicodeError, ValueError):
            _refuse("matrix-semver-runner-identity")
        try:
            records = self._run_semver_stage()
        except (SupervisorRefusal, semver_stage.SemverRefusal,
                semver_offline_cache.Refusal, bounded_registry_io.Refusal):
            records = semver_stage.records_for_exit(101)
        with self.semver_active_lock:
            if self.semver_active is not None:
                CANCEL_REQUESTED.set()
                _refuse("matrix-semver-cgroup-cleanup")
        return {"ok": True, "records": records}

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
            result = subprocess.run([
                "/usr/sbin/chroot", str(self.root), "/usr/bin/setpriv",
                "--reuid=%d" % WORKER_UID, "--regid=%d" % WORKER_GID,
                "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--",
                "/usr/bin/python3", "-B", "-I", "-S", "/control/devlane/network_probe.py",
                "check", "--host-net-inode", str(self.host_net_inode),
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                timeout=_bounded_timeout(30), close_fds=True,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                     "PYTHONDONTWRITEBYTECODE": "1"},
            )
        except (OSError, subprocess.TimeoutExpired):
            _refuse("network-probe-command-failed")
        if result.returncode != 0:
            refusal = network_probe.refusal_message_from_result(
                result.returncode, result.stdout, result.stderr,
            )
            if refusal is not None:
                _refuse("network-probe-refusal:" + refusal)
            _refuse("network-probe-command-failed")
        if result.stdout != b"network_probe=pass\n" or result.stderr:
            _refuse("network-probe-output-invalid")
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
        if self.manifest["schema"] == 2:
            _stage_baseline_runtime_after_cut(
                self.root / "workspace/source", self.root, self.manifest["source_sets"],
            )
            self.baseline_staged = True
        _copy_prepared_dependencies(
            self.root, self.context["profile"], registry_v2=self.manifest["schema"] == 2)
        _chown_tree(self.root / "workspace/source")
        _prepare_trusted_files(self.root, self.manifest)
        _prepare_writable_scratch(self.root, registry_v2=self.manifest["schema"] == 2)
        if self.manifest["schema"] == 2:
            self._generate_offline_locks()
        self.decrypted = True
        return {"ok": True}

    def _generate_offline_locks(self):
        self._verify_network_cut()
        record_path = self.root / "prepared/registry-preparation.json"
        preparation = bundle.strict_json(_read_regular(record_path, fetch.MAX_PROJECTION),
                                         fetch.MAX_PROJECTION)
        try:
            packages = rust_lock_generation.validate_preparation(
                preparation, self.projection_value, self.context["control_sha"])
            for name in ("cargo", "rustc"):
                _size, digest = _hash_file(
                    self.root / "tools/rust/bin" / name, 256 * 1024 * 1024)
                if digest != preparation["tool_hashes"][name + "_sha256"]:
                    _refuse("offline-lock-generation-failed")
            outer = deadline_budget._read(self.deadline_file)
            budget = bounded_registry_io.PhaseBudget.from_outer_deadlines(
                outer["work_deadline"], outer["work_deadline"] + outer["cleanup_reserve"])
            bounded_registry_io.verify_bounded_registry_tree(
                self.root / "prepared/cargo-local-registry", packages, budget)
        except (bundle.Refusal, ValueError, KeyError, TypeError):
            _refuse("offline-lock-generation-failed")
        for index, (manifest, _lock) in enumerate(rust_lock_generation.LOCKS):
            result = _run_profile_command(
                self.root, rust_lock_generation.command(manifest), "rust-lock-generation",
                "/scratch/reports/lock-generation-%d.log" % index, self.tool_info,
                timeout=1200, deadline=self.deadline_file)
            if result != 0:
                _refuse("offline-lock-generation-failed")
        locks = {name: _read_regular(self.root / "workspace/source" / name, 8 * 1024 * 1024)
                 for _manifest, name in rust_lock_generation.LOCKS}
        try:
            record = rust_lock_generation.output_record(
                locks, preparation, self.projection_value, self.context["control_sha"])
        except (bundle.Refusal, ValueError, KeyError, TypeError):
            _refuse("offline-lock-generation-failed")
        destination = self.root / "trusted/generated-locks.json"
        with destination.open("xb") as output:
            output.write(bundle.canonical_json(record))
        os.chmod(destination, 0o444)

    def _verify_projection_bindings(self):
        source = self.root / "workspace/source"
        if self.manifest["schema"] == 2:
            if (self.context["profile"] != "core-rust"
                    or self.projection_value.get("schema") != 2
                    or self.projection_value.get("source_sets") != self.manifest.get("source_sets")):
                _refuse("source-set-projection-mismatch")
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
            if self.manifest["schema"] == 2:
                try:
                    source_files, _source_bytes = bundle._read_regular_tree(source)
                    inventory = {path: (len(payload), hashlib.sha256(payload).hexdigest())
                                 for path, payload in source_files.items()}
                    bundle._validate_core_rust_source_sets(self.manifest["source_sets"], inventory)
                    rust_lock_generation.verify_manifest_constraints(
                        source_files, self.projection_value, self.context["control_sha"])
                except (OSError, bundle.Refusal, KeyError, TypeError):
                    _refuse("source-set-projection-mismatch")
                if set(self.manifest["original_lockfiles"]) != {
                        "Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock"}:
                    _refuse("cargo-workspace-lock-set")
                return
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
        self._verify_network_cut()
        profile_name = self.context["profile"]
        profile = self.profile_config["profiles"].get(profile_name)
        expected_revision = 2 if profile_name == "core-rust" else 1
        if type(profile) is not dict or profile.get("revision") != expected_revision:
            _refuse("profile-unknown")
        try:
            deadline_budget.remaining(self.deadline_file)
        except deadline_budget.DeadlineRefusal:
            _refuse("total-deadline-exhausted")
        source_root = self.root / "workspace/source"
        commands = profile.get("commands")
        stages = profile.get("stages")
        if profile_name == "core-rust":
            if self.manifest["schema"] == 2:
                if not self.baseline_staged:
                    _refuse("execution-order")
            if commands != [] or stages != ["format", "deny", "audit", "vet", "unit", "semver"]:
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
            self.matrix_runner_ready.clear()
            runner_state = {"pid": None, "semver_requested": False}
            with self.matrix_runner_lock:
                if self.matrix_runner_active is not None:
                    _refuse("matrix-semver-runner-order")
                self.matrix_runner_active = runner_state

            def register_matrix_runner(process):
                with self.matrix_runner_lock:
                    runner_state["pid"] = process.pid
                    self.matrix_runner_ready.set()

            try:
                result = _run_control_adapter(
                    self.root, command, "unit", self.tool_info,
                    "rust-matrix-adapter.log", timeout=matrix_timeout,
                    deadline=self.deadline_file, cpu_seconds=9900,
                    on_spawn=register_matrix_runner,
                )
            finally:
                with self.matrix_runner_lock:
                    self.matrix_runner_active = None
                    self.matrix_runner_ready.set()
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
                self.summary = _filter_failure_summary()
            status = "pass" if result == 0 and not filter_failed and not _summary_failed(self.summary) else "fail"
            self._capture_failure_diagnostics(execution_failed=(status == "fail"))
            self.execution_done = True
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
            self.summary = _filter_failure_summary()
        status = "pass" if all(code == 0 for _, code in outcomes) and not filter_failed and not _summary_failed(self.summary) else "fail"
        self._capture_failure_diagnostics(execution_failed=(status == "fail"))
        self.execution_done = True
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

    def _semver_proc_bytes(self, pid, name, maximum, budget=None):
        if type(pid) is not int or pid <= 1 or name not in {"status", "cmdline", "cgroup"}:
            _refuse("matrix-semver-checkpoint-peer")
        descriptor = None
        try:
            path = "/proc/%d/%s" % (pid, name)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                                 | getattr(os, "O_CLOEXEC", 0))
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                _refuse("matrix-semver-checkpoint-peer")
            data = bytearray()
            deadline = time.monotonic() + 5.0
            while True:
                if time.monotonic() >= deadline:
                    _refuse("matrix-semver-checkpoint-peer")
                try:
                    if budget is not None:
                        budget.remaining()
                    else:
                        deadline_budget.remaining(self.deadline_file)
                except (deadline_budget.DeadlineRefusal, bounded_registry_io.Refusal):
                    _refuse("matrix-semver-checkpoint-peer")
                chunk = os.read(descriptor, min(4096, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > maximum:
                    _refuse("matrix-semver-checkpoint-peer")
            after = os.fstat(descriptor)
            if (after.st_dev != metadata.st_dev or after.st_ino != metadata.st_ino
                    or after.st_nlink != 1):
                _refuse("matrix-semver-checkpoint-peer")
            return bytes(data)
        except SupervisorRefusal:
            raise
        except OSError:
            _refuse("matrix-semver-checkpoint-peer")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _semver_mountinfo_text(self, budget):
        path = Path("/proc/self/mountinfo")
        descriptor = None
        try:
            before = path.lstat()
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            nonblock = getattr(os, "O_NONBLOCK", 0)
            if (not nofollow or not nonblock or not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1 or before.st_size > SEMVER_MOUNTINFO_MAX):
                _refuse("matrix-semver-cgroup-unavailable")
            descriptor = os.open(str(path), os.O_RDONLY | nofollow | nonblock
                                 | getattr(os, "O_CLOEXEC", 0))
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino
                    or opened.st_size > SEMVER_MOUNTINFO_MAX):
                _refuse("matrix-semver-cgroup-unavailable")
            payload = bytearray()
            local_deadline = time.monotonic() + 5.0
            while True:
                if time.monotonic() >= local_deadline:
                    _refuse("matrix-semver-cgroup-unavailable")
                budget.remaining()
                chunk = os.read(descriptor, min(16_384, SEMVER_MOUNTINFO_MAX + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > SEMVER_MOUNTINFO_MAX:
                    _refuse("matrix-semver-cgroup-unavailable")
            after = os.fstat(descriptor)
            after_path = path.lstat()
            if (not stat.S_ISREG(after_path.st_mode) or after_path.st_nlink != 1
                    or after.st_dev != opened.st_dev or after.st_ino != opened.st_ino
                    or after.st_nlink != 1 or after.st_size > SEMVER_MOUNTINFO_MAX
                    or after_path.st_dev != opened.st_dev or after_path.st_ino != opened.st_ino):
                _refuse("matrix-semver-cgroup-unavailable")
            return bytes(payload).decode("ascii", "strict")
        except SupervisorRefusal:
            raise
        except (OSError, UnicodeError, bounded_registry_io.Refusal):
            _refuse("matrix-semver-cgroup-unavailable")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _semver_read_cgroup_roster(self, path, maximum=MAX_CGROUP_ROSTER_BYTES,
                                   budget=None, cleanup=False):
        descriptor = None
        try:
            path = Path(path)
            before = path.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > maximum):
                _refuse("matrix-semver-checkpoint-cgroup")
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            nonblock = getattr(os, "O_NONBLOCK", 0)
            if not nofollow or not nonblock:
                _refuse("matrix-semver-checkpoint-cgroup")
            descriptor = os.open(str(path), os.O_RDONLY | nofollow | nonblock
                                 | getattr(os, "O_CLOEXEC", 0))
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino
                    or opened.st_size != before.st_size or opened.st_size > maximum):
                _refuse("matrix-semver-checkpoint-cgroup")
            deadline = time.monotonic() + 5.0
            data = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    _refuse("matrix-semver-checkpoint-cgroup")
                try:
                    budget.remaining(cleanup=cleanup) if budget is not None else deadline_budget.remaining(self.deadline_file)
                except (deadline_budget.DeadlineRefusal, bounded_registry_io.Refusal):
                    _refuse("matrix-semver-checkpoint-cgroup")
                chunk = os.read(descriptor, min(4096, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > maximum:
                    _refuse("matrix-semver-checkpoint-cgroup")
            after = os.fstat(descriptor)
            after_path = path.lstat()
            if (not stat.S_ISREG(after_path.st_mode) or after_path.st_nlink != 1
                    or after.st_dev != opened.st_dev or after.st_ino != opened.st_ino
                    or after.st_nlink != 1 or after.st_mtime_ns != opened.st_mtime_ns
                    or after.st_ctime_ns != opened.st_ctime_ns
                    or after_path.st_dev != opened.st_dev or after_path.st_ino != opened.st_ino):
                _refuse("matrix-semver-checkpoint-cgroup")
            text = bytes(data).decode("ascii", "strict")
            if not text:
                return frozenset()
            if not text.endswith("\n"):
                _refuse("matrix-semver-checkpoint-cgroup")
            rows = text[:-1].split("\n")
            if not rows or len(rows) > MAX_CGROUP_ROSTER_PIDS:
                _refuse("matrix-semver-checkpoint-cgroup")
            pids = []
            for row in rows:
                if re.fullmatch(r"[1-9][0-9]{0,9}", row) is None:
                    _refuse("matrix-semver-checkpoint-cgroup")
                pid = int(row)
                if pid > 2 ** 31 - 1:
                    _refuse("matrix-semver-checkpoint-cgroup")
                pids.append(pid)
            if len(set(pids)) != len(pids):
                _refuse("matrix-semver-checkpoint-cgroup")
            return frozenset(pids)
        except SupervisorRefusal:
            raise
        except (OSError, UnicodeError, ValueError, OverflowError):
            _refuse("matrix-semver-checkpoint-cgroup")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _semver_checkpoint_peer(self, peer_pid, request, active):
            budget = bounded_registry_io.PhaseBudget.from_outer_deadlines(
                active["work_deadline"], active["cleanup_deadline"],
                cancelled=CANCEL_REQUESTED.is_set,
            )
            status = self._semver_proc_bytes(
                peer_pid, "status", 64 * 1024, budget,
            ).decode("ascii", "strict")
            parent = None
            effective_uid = None
            for line in status.splitlines()[:64]:
                if line.startswith("PPid:"):
                    value = line[5:].strip()
                    parent = int(value) if value.isascii() and value.isdecimal() else None
                elif line.startswith("Uid:"):
                    fields = line[4:].split()
                    if len(fields) >= 2 and fields[1].isascii() and fields[1].isdecimal():
                        effective_uid = int(fields[1])
            if parent != active["pid"] or effective_uid != WORKER_UID:
                _refuse("matrix-semver-checkpoint-peer")
            arguments = self._semver_proc_bytes(
                peer_pid, "cmdline", 16 * 1024, budget,
            ).split(b"\x00")
            if arguments and arguments[-1] == b"":
                arguments.pop()
            try:
                words = [item.decode("utf-8", "strict") for item in arguments]
            except UnicodeDecodeError:
                _refuse("matrix-semver-checkpoint-peer")
            if (len(words) < 7 or words[0] != "/usr/bin/python3" or words[1:5] != [
                    "-B", "-I", "-S", "/control/devlane/semver_cargo_wrapper.py"]):
                _refuse("matrix-semver-checkpoint-peer")
            cargo_arguments = words[5:]
            try:
                parsed = semver_cargo_wrapper._parse_cargo_arguments(cargo_arguments)
            except semver_cargo_wrapper.WrapperRefusal:
                _refuse("matrix-semver-checkpoint-command")
            if (parsed["operation"] != request["operation"]
                    or parsed["manifest"] != request["manifest"]
                    or parsed["project_kind"] not in {"local", "registry"}):
                _refuse("matrix-semver-checkpoint-command")
            allowed_events = {
                "local": {
                    "update": {"before-update", "after-update"},
                    "metadata": {"after-metadata"},
                    "doc": {"after-doc"},
                },
                "registry": {
                    "metadata": {"before-metadata", "after-metadata"},
                    "doc": {"after-doc"},
                },
            }
            if request["event"] not in allowed_events[parsed["project_kind"]].get(
                    parsed["operation"], set()):
                _refuse("matrix-semver-checkpoint-order")
            cgroup_text = self._semver_proc_bytes(
                peer_pid, "cgroup", 16 * 1024, budget,
            ).decode("ascii", "strict")
            if not any(row.endswith("::/" + active["job"].path.name)
                       for row in cgroup_text.splitlines()):
                _refuse("matrix-semver-checkpoint-peer")
            pids = self._semver_read_cgroup_roster(
                active["job"].path / "cgroup.procs", budget=budget,
            )
            if pids != frozenset({active["pid"], peer_pid}):
                _refuse("matrix-semver-checkpoint-cgroup-not-quiescent")
            active["observed_pids"].update(pids)
            return parsed

    def _semver_checkpoint_snapshot(self, virtual_root, active):
            root = self.root / virtual_root.lstrip("/")
            try:
                root = semver_offline_cache._require_canonical_directory(
                    root, "matrix-semver-checkpoint-project",
                )
                budget = bounded_registry_io.PhaseBudget.from_outer_deadlines(
                    active["work_deadline"], active["cleanup_deadline"],
                    cancelled=CANCEL_REQUESTED.is_set,
                )
                manifest_bytes = semver_offline_cache._read_file(
                    root / "Cargo.toml", semver_offline_cache.MAX_FILE_BYTES, budget,
                )
                map_without_lock, count_without_lock, bytes_without_lock = (
                    semver_offline_cache.source_map_digest(
                        root, budget, omit_root_cargo_lock=True,
                        allow_missing_root_cargo_lock=True,
                        root_relative_keys=True,
                    )
                )
                project_map, project_count, project_bytes = semver_offline_cache.source_map_digest(
                    root, budget,
                )
                lock_path = root / "Cargo.lock"
                try:
                    lock_path.lstat()
                except FileNotFoundError:
                    lock_sha = None
                    lock_size = None
                    rows = None
                else:
                    lock_bytes = semver_offline_cache._read_file(
                        lock_path, semver_offline_cache.MAX_FILE_BYTES, budget,
                    )
                    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
                    lock_size = len(lock_bytes)
                    rows = constraint_resolver.lock_package_rows(lock_bytes)
                    available = {
                        (row["name"], row["version"]): row["checksum"]
                        for row in active["registry_package_rows"]
                    }
                    if any(
                            available.get((row["name"], row["version"])) != row["checksum"]
                            for row in rows):
                        _refuse("matrix-semver-checkpoint-lock-outside-closure")
                return {
                    "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                    "project_map_without_lock_sha256": map_without_lock,
                    "project_file_count_without_lock": count_without_lock,
                    "project_tree_bytes_without_lock": bytes_without_lock,
                    "project_map_sha256": project_map,
                    "project_file_count": project_count,
                    "project_tree_bytes": project_bytes,
                    "lock_sha256": lock_sha,
                    "lock_size": lock_size,
                }
            except (OSError, bounded_registry_io.Refusal, semver_offline_cache.Refusal,
                    constraint_resolver.Refusal):
                _refuse("matrix-semver-checkpoint-snapshot")

    def _semver_checkpoint(self, request, peer_pid, peer_uid):
            if (type(request) is not dict or set(request) != {
                    "op", "event", "operation", "manifest"} or request.get("op") != "semver-checkpoint"
                    or type(request.get("event")) is not str
                    or type(request.get("operation")) is not str
                    or type(request.get("manifest")) is not str
                    or len(request["manifest"]) > 4096):
                _refuse("matrix-semver-checkpoint-request")
            with self.semver_active_lock:
                pending = self.semver_active
                ready = pending.get("ready") if pending is not None else None
            if ready is None or not ready.wait(timeout=5):
                _refuse("matrix-semver-checkpoint-order")
            with self.semver_active_lock:
                active = self.semver_active
                if (peer_uid != WORKER_UID or active is None or active is not pending
                        or CANCEL_REQUESTED.is_set()):
                    _refuse("matrix-semver-checkpoint-order")
                parsed = self._semver_checkpoint_peer(peer_pid, request, active)
                project_root = str(PurePosixPath(request["manifest"]).parent)
                snapshot = self._semver_checkpoint_snapshot(project_root, active)
                tracker = active["trackers"].get(project_root)
                new_tracker = tracker is None
                if new_tracker:
                    if len(active["trackers"]) >= 4096:
                        _refuse("matrix-semver-checkpoint-project-count")
                    binding = active["checkpoint_binding"]
                    tracker = temp_project_checkpoints.CheckpointTracker(
                        binding, parsed["project_kind"],
                    )
                try:
                    record = tracker.observe(
                        request["event"], operation=request["operation"],
                        project_root=project_root, **snapshot,
                    )
                except temp_project_checkpoints.CheckpointRefusal:
                    _refuse("matrix-semver-checkpoint-contract")
                if new_tracker:
                    active["trackers"][project_root] = tracker
                active["events"].append(record)
            return {"ok": True}

    def _write_semver_checkpoint_record(self, active, *, require_complete):
            trackers = active["trackers"]
            if require_complete and not trackers:
                _refuse("matrix-semver-checkpoint-missing")
            if not trackers:
                return
            projects = []
            for tracker in trackers.values():
                try:
                    projects.append(tracker.finish())
                except temp_project_checkpoints.CheckpointRefusal:
                    if require_complete:
                        _refuse("matrix-semver-checkpoint-incomplete")
                    return
            projects.sort(key=lambda item: (
                item["project_kind"], item["temporary_manifest_sha256"],
                item["temporary_project_map_sha256"], item["temporary_lock_sha256"],
            ))
            record = {
                "schema": "keeldock.semver-project-checkpoints.v2",
                "status": "complete",
                "source_commit": active["checkpoint_binding"]["source_commit"],
                "control_sha": active["checkpoint_binding"]["control_sha"],
                "manifest_projection_sha256": active["checkpoint_binding"]["manifest_projection_sha256"],
                "candidate_git_tree_map_sha256": active["checkpoint_binding"]["candidate_git_tree_map_sha256"],
                "candidate_transfer_map_sha256": active["checkpoint_binding"]["candidate_transfer_map_sha256"],
                "baseline_source_map_sha256": active["checkpoint_binding"]["baseline_source_map_sha256"],
                "semver_tool_binary_sha256": active["checkpoint_binding"]["semver_tool_binary_sha256"],
                "candidate_selected_map_after_ephemeral_lock_overlay":
                    active["candidate_selected_map_after_ephemeral_lock_overlay"],
                "generated_lock_status": active["generated_lock_status"],
                "generated_lock_sha256": active["generated_lock_sha256"],
                "rust_tool_hashes": active["rust_tool_hashes"],
                "rust_tool_provenance_status": active["rust_tool_provenance_status"],
                "registry_tree_sha256": active["registry_tree_sha256"],
                "project_count": len(projects),
                "projects": projects,
                "raw_source_retained": False,
            }
            payload = bundle.canonical_json(record)
            if len(payload) > 4 * 1024 * 1024:
                _refuse("matrix-semver-checkpoint-record-size")
            report = self.root / "trusted" / SEMVER_CHECKPOINT_REPORT
            try:
                descriptor = os.open(
                    str(report), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0), 0o440,
                )
                try:
                    os.fchown(descriptor, 0, 0)
                    os.fchmod(descriptor, 0o440)
                    view = memoryview(payload)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            _refuse("matrix-semver-checkpoint-record-write")
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except FileExistsError:
                _refuse("matrix-semver-checkpoint-record-exists")
            except SupervisorRefusal:
                raise
            except OSError:
                _refuse("matrix-semver-checkpoint-record-write")
            self.semver_checkpoint_record = record

    def _create_semver_cgroup(self, mountinfo, budget):
        root = SEMVER_CGROUP_ROOT
        path = None
        attach_fd = None
        try:
            metadata = root.lstat()
            if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
                    or not os.path.ismount(root)):
                _refuse("matrix-semver-cgroup-unavailable")
            if type(mountinfo) is not str or len(mountinfo) > SEMVER_MOUNTINFO_MAX:
                _refuse("matrix-semver-cgroup-unavailable")
            budget.remaining()
            mounted = False
            for line in mountinfo.splitlines():
                budget.remaining()
                fields = line.split()
                if "-" not in fields:
                    continue
                separator = fields.index("-")
                if (separator + 1 < len(fields) and fields[separator + 1] == "cgroup2"
                        and len(fields) > 4 and fields[4] == str(root)):
                    mounted = True
                    break
            if not mounted:
                _refuse("matrix-semver-cgroup-unavailable")
            name = "semver-job-%d-%s" % (os.getpid(), os.urandom(8).hex())
            path = root / name
            path.mkdir(mode=0o700)
            for child in ("cgroup.procs", "cgroup.events", "cgroup.kill"):
                item = path / child
                item_mode = item.lstat().st_mode
                if not stat.S_ISREG(item_mode) or item.is_symlink():
                    _refuse("matrix-semver-cgroup-unavailable")
            flags = os.O_WRONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            attach_fd = os.open(str(path / "cgroup.procs"), flags)
            opened = os.fstat(attach_fd)
            if not stat.S_ISREG(opened.st_mode):
                os.close(attach_fd)
                attach_fd = None
                _refuse("matrix-semver-cgroup-unavailable")
            return SemverCgroupJob(path, attach_fd)
        except SupervisorRefusal:
            if attach_fd is not None:
                os.close(attach_fd)
            if path is not None:
                try:
                    path.rmdir()
                except OSError:
                    pass
            raise
        except OSError:
            if attach_fd is not None:
                os.close(attach_fd)
            if path is not None:
                try:
                    path.rmdir()
                except OSError:
                    pass
            _refuse("matrix-semver-cgroup-unavailable")

    def _prepare_semver_scratch(self, binding, expected_source_maps, work_deadline,
                                cleanup_deadline):
        scratch = self.root / "scratch"
        cargo_home = scratch / "semver-cargo-home"
        cargo_bin = scratch / "semver-cargo-bin"
        target_root = scratch / "semver-target"
        context_path = scratch / "semver-state/context.json"
        for path in (cargo_home, cargo_bin, target_root, context_path):
            if os.path.lexists(path):
                _refuse("matrix-semver-cargo-home")
        try:
            cargo_home.mkdir(mode=0o1777)
            os.chmod(cargo_home, 0o1777)
            cargo_bin.mkdir(mode=0o755)
            os.chmod(cargo_bin, 0o755)
            target_root.mkdir(mode=0o700)
            os.chown(target_root, WORKER_UID, WORKER_GID)
            payload = semver_offline_cache.CARGO_CONFIG
            for config_name in ("config.toml", "config"):
                config_path = cargo_home / config_name
                descriptor = os.open(str(config_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | getattr(os, "O_NOFOLLOW", 0), 0o440)
                try:
                    os.fchown(descriptor, 0, WORKER_GID)
                    os.fchmod(descriptor, 0o440)
                    if os.write(descriptor, payload) != len(payload):
                        _refuse("matrix-semver-cargo-home")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            shim = cargo_bin / "cargo"
            shim_payload = (
                bytes((35,)) + b"!/bin/sh\nexec /usr/bin/python3 -B -I -S "
                b"/control/devlane/semver_cargo_wrapper.py \"$@\"\n"
            )
            descriptor = os.open(str(shim), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0), 0o555)
            try:
                os.fchmod(descriptor, 0o555)
                if os.write(descriptor, shim_payload) != len(shim_payload):
                    _refuse("matrix-semver-cargo-home")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            context = {
                "schema": "keeldock.semver-worker-context.v2",
                "authenticated_binding": binding,
                "expected_source_maps": expected_source_maps,
                "work_deadline": work_deadline,
                "cleanup_deadline": cleanup_deadline,
            }
            payload = bundle.canonical_json(context)
            descriptor = os.open(str(context_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0), 0o440)
            try:
                os.fchown(descriptor, 0, WORKER_GID)
                os.fchmod(descriptor, 0o440)
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        _refuse("matrix-semver-context-write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except SupervisorRefusal:
            raise
        except OSError:
            _refuse("matrix-semver-context-write")

    def _semver_launch_environment(self):
        environment = semver_cargo_wrapper._cargo_environment()
        environment["PATH"] = "/scratch/semver-cargo-bin:" + environment["PATH"]
        return environment

    def _semver_launch_command(self, attach_fd):
        tool_argv = semver_stage.fixed_argv()
        return [
            "/usr/sbin/chroot", str(self.root), "/usr/bin/python3", "-B", "-I", "-S",
            "/control/devlane/cgroup_exec.py", "--cgroup-fd", str(attach_fd), "--",
            "/usr/bin/setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
            "--no-new-privs", "--bounding-set=-all", "--", *tool_argv,
        ]

    def _semver_kill_cgroup(self, job):
        descriptor = None
        try:
            target = job.path / "cgroup.kill"
            metadata = target.lstat()
            if not stat.S_ISREG(metadata.st_mode) or target.is_symlink():
                _refuse("matrix-semver-cgroup-cleanup")
            descriptor = os.open(str(target), os.O_WRONLY | os.O_NONBLOCK
                                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            if os.write(descriptor, b"1\n") != 2:
                _refuse("matrix-semver-cgroup-cleanup")
        except SupervisorRefusal:
            raise
        except OSError:
            _refuse("matrix-semver-cgroup-cleanup")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _semver_cgroup_events(self, path, budget, *, cleanup=False):
        descriptor = None
        try:
            path = Path(path)
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > 1024:
                _refuse("matrix-semver-cgroup-cleanup")
            descriptor = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK
                                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > 1024):
                _refuse("matrix-semver-cgroup-cleanup")
            result = bytearray()
            while True:
                budget.remaining(cleanup=cleanup)
                chunk = os.read(descriptor, 1025 - len(result))
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > 1024:
                    _refuse("matrix-semver-cgroup-cleanup")
            values = {}
            for line in bytes(result).decode("ascii", "strict").splitlines():
                fields = line.split()
                if len(fields) != 2 or fields[0] in values or fields[1] not in {"0", "1"}:
                    _refuse("matrix-semver-cgroup-cleanup")
                values[fields[0]] = fields[1]
            if set(values) != {"populated", "frozen"}:
                _refuse("matrix-semver-cgroup-cleanup")
            return values
        except SupervisorRefusal:
            raise
        except (OSError, UnicodeError, bounded_registry_io.Refusal):
            _refuse("matrix-semver-cgroup-cleanup")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _semver_cleanup_cgroup(self, active, process, budget):
        job = active["job"]
        known_pids = set(active.get("observed_pids", ()))
        if process is not None:
            known_pids.add(process.pid)
        try:
            known_pids.update(self._semver_read_cgroup_roster(
                job.path / "cgroup.procs", budget=budget, cleanup=True,
            ))
            self._semver_kill_cgroup(job)
            job.close_attach()
            empty_observations = 0
            while budget.remaining(cleanup=True) > 0:
                if process is not None and process.poll() is None:
                    try:
                        process.wait(timeout=min(0.1, budget.remaining(cleanup=True)))
                    except subprocess.TimeoutExpired:
                        pass
                for pid in tuple(known_pids):
                    if process is not None and pid == process.pid:
                        continue
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                    except OSError as error:
                        if error.errno != 10:
                            raise
                current = self._semver_read_cgroup_roster(
                    job.path / "cgroup.procs", budget=budget, cleanup=True,
                )
                known_pids.update(current)
                events = self._semver_cgroup_events(
                    job.path / "cgroup.events", budget, cleanup=True,
                )
                if not current and events["populated"] == "0":
                    empty_observations += 1
                    if empty_observations >= 2:
                        if process is not None and process.poll() is None:
                            process.wait(timeout=budget.remaining(cleanup=True))
                        job.path.rmdir()
                        return True
                else:
                    empty_observations = 0
                time.sleep(min(0.02, budget.remaining(cleanup=True)))
        except (SupervisorRefusal, bounded_registry_io.Refusal,
                OSError, subprocess.SubprocessError):
            try:
                job.close_attach()
            except OSError:
                pass
            return False
        return False

    def _run_semver_stage(self):
        if (self.context.get("profile") != "core-rust" or self.manifest.get("schema") != 2
                or not self.baseline_staged or CANCEL_REQUESTED.is_set()):
            return semver_stage.records_for_exit(101)
        active = None
        process = None
        job = None
        code = 101
        cleaned = False
        report_written = False
        try:
            outer = deadline_budget._read(self.deadline_file)
            work_deadline = outer["work_deadline"]
            cleanup_deadline = work_deadline + outer["cleanup_reserve"]
            budget = bounded_registry_io.PhaseBudget.from_outer_deadlines(
                work_deadline, cleanup_deadline, cancelled=CANCEL_REQUESTED.is_set,
            )
            source_revision = self.manifest.get("source_revision")
            control_sha = self.context.get("control_sha")
            projection_sha = self.projection_value.get("manifest_projection_sha256")
            if (source_revision != semver_stage.SOURCE_REVISION
                    or type(control_sha) is not str
                    or projection_sha != self.manifest.get("fetch_sha256")):
                _refuse("matrix-semver-inputs")
            tool_root = self.root / "prepared/devlane-tools"
            tool = semver_stage.verify_tool(tool_root, budget)
            receipt = bundle.strict_json(semver_offline_cache._read_file(
                tool_root / "semver-tool-receipt.json", 4096, budget,
            ), 4096)
            binary_sha = receipt.get("binary_sha256") if type(receipt) is dict else None
            if type(binary_sha) is not str:
                _refuse("matrix-semver-tool-binding")
            identity = semver_stage.offline_cache_input_identity(
                control_sha, projection_sha, binary_sha,
            )
            source_maps = semver_stage.offline_cache_source_maps(budget)
            source_sets = semver_stage.offline_cache_source_sets(budget)
            mountinfo = self._semver_mountinfo_text(budget)
            binding = {
                "source_commit": identity["source_commit"],
                "control_sha": identity["control_sha"],
                "manifest_projection_sha256": identity["manifest_projection_sha256"],
                "candidate_git_tree_map_sha256": source_sets["candidate"]["full_map_sha256"],
                "candidate_transfer_map_sha256": identity["candidate_full_source_map_sha256"],
                "baseline_source_map_sha256": identity["baseline_source_map_sha256"],
                "semver_tool_binary_sha256": identity["semver_tool_binary_sha256"],
            }
            self._prepare_semver_scratch(binding, source_maps, work_deadline, cleanup_deadline)
            preparation = bundle.strict_json(semver_offline_cache._read_file(
                self.root / "prepared/registry-preparation.json", semver_offline_cache.MAX_CONTRACT_BYTES, budget,
            ), semver_offline_cache.MAX_CONTRACT_BYTES)
            generated = bundle.strict_json(semver_offline_cache._read_file(
                self.root / "trusted/generated-locks.json", semver_offline_cache.MAX_CONTRACT_BYTES, budget,
            ), semver_offline_cache.MAX_CONTRACT_BYTES)
            prepared = semver_offline_cache.validate_rust_v2_semver_inputs(
                self.root / "prepared", self.root / "workspace/source",
                self.root / "workspace/semver-baseline/runtime",
                self.root / "scratch/semver-cargo-home", self.root / "scratch/cargo-home",
                self.root / "tools/rust", self.manifest, self.projection_value,
                preparation, generated, identity, source_sets, source_maps, budget,
                expected_source_sha=source_revision, expected_control_sha=control_sha,
                expected_projection_sha256=projection_sha,
                mountinfo=mountinfo,
            )
            semver_stage.verify_run_inputs(
                self.root / "workspace/source/runtime",
                self.root / "workspace/semver-baseline/runtime", tool_root, budget,
            )
            candidate_post_lock_map = prepared[
                "candidate_selected_map_after_ephemeral_lock_overlay"
            ]
            job = self._create_semver_cgroup(mountinfo, budget)
            active = {
                "owner_done": threading.Event(),
                "pid": None,
                "job": job,
                "ready": threading.Event(),
                "trackers": {},
                "events": [],
                "observed_pids": set(),
                "checkpoint_binding": binding,
                "candidate_selected_map_after_ephemeral_lock_overlay": candidate_post_lock_map,
                "generated_lock_status": prepared["generated_lock_status"],
                "generated_lock_sha256": prepared["generated_lock_sha256"],
                "rust_tool_hashes": prepared["rust_tool_hashes"],
                "rust_tool_provenance_status": prepared["rust_tool_provenance_status"],
                "registry_tree_sha256": prepared["registry_tree_sha256"],
                "registry_package_rows": prepared["_registry_package_rows"],
                "work_deadline": work_deadline,
                "cleanup_deadline": cleanup_deadline,
            }
            with self.semver_active_lock:
                if self.semver_active is not None:
                    _refuse("matrix-semver-runner-order")
                self.semver_active = active
            raw_log = self.root / "workspace/raw/semver-analyzer.log"
            descriptor = os.open(str(raw_log), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                log = os.fdopen(descriptor, "wb")
                descriptor = None
                with log:
                    attach_fd = job.attach_fd
                    command = self._semver_launch_command(attach_fd)
                    process = subprocess.Popen(
                        command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                        env=self._semver_launch_environment(), cwd="/", close_fds=True,
                        pass_fds=(attach_fd,), start_new_session=True,
                    )
                    with ACTIVE_CHILDREN_LOCK:
                        ACTIVE_CHILDREN.add(process.pid)
                    with self.semver_active_lock:
                        active["pid"] = process.pid
                        active["process"] = process
                        active["ready"].set()
                    timeout = min(semver_stage.CHECK_SECONDS, budget.remaining())
                    end = time.monotonic() + timeout
                    while True:
                        if CANCEL_REQUESTED.is_set():
                            code = 130
                            break
                        remaining = end - time.monotonic()
                        if remaining <= 0:
                            code = 124
                            break
                        try:
                            code = process.wait(timeout=min(0.2, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                    log.flush()
                    if os.fstat(log.fileno()).st_size > SEMVER_LOG_MAX:
                        code = 101
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                try:
                    job.close_attach()
                except OSError:
                    pass
            budget.cleanup_deadline = cleanup_deadline
            cleaned = self._semver_cleanup_cgroup(active, process, budget)
            if not cleaned:
                _refuse("matrix-semver-cgroup-cleanup")
            with ACTIVE_CHILDREN_LOCK:
                if process is not None:
                    ACTIVE_CHILDREN.discard(process.pid)
            with self.semver_active_lock:
                if self.semver_active is active:
                    self.semver_active = None
            active["ready"].set()
            if code in (124, 130) or CANCEL_REQUESTED.is_set():
                return semver_stage.records_for_exit(101)
            try:
                self._write_semver_checkpoint_record(active, require_complete=True)
                report_written = True
            except SupervisorRefusal:
                return semver_stage.records_for_exit(101)
            return semver_stage.records_for_exit(code)
        except (SupervisorRefusal, semver_stage.SemverRefusal, semver_offline_cache.Refusal,
                bounded_registry_io.Refusal, bundle.Refusal, OSError, ValueError,
                subprocess.SubprocessError):
            return semver_stage.records_for_exit(101)
        finally:
            if active is not None:
                if not cleaned and job is not None:
                    try:
                        budget = bounded_registry_io.PhaseBudget(
                            active["work_deadline"], active["cleanup_deadline"],
                            cancelled=lambda: False,
                        )
                        cleaned = self._semver_cleanup_cgroup(active, process, budget)
                    except Exception:
                        cleaned = False
                with self.semver_active_lock:
                    if self.semver_active is active:
                        if cleaned:
                            self.semver_active = None
                        else:
                            active["cleanup_failed"] = True
                            active["process"] = process
                active["ready"].set()
                if not cleaned:
                    active["owner_done"].set()
                    CANCEL_REQUESTED.set()
                    _refuse("matrix-semver-cgroup-cleanup")
                if process is not None:
                    with ACTIVE_CHILDREN_LOCK:
                        ACTIVE_CHILDREN.discard(process.pid)
                active["owner_done"].set()
            elif job is not None:
                try:
                    job.close_attach()
                except OSError:
                    pass
                try:
                    self._semver_kill_cgroup(job)
                    job.path.rmdir()
                except (SupervisorRefusal, OSError):
                    pass

    def _summary(self):
        if not self.execution_done or self.summary is None:
            _refuse("summary-not-ready")
        return {"ok": True, "status": "pass" if all(code == 0 for _, code in self.outcomes) else "fail",
                "summary": base64.b64encode(self.summary).decode("ascii")}

    def _cleanup(self):
        CANCEL_REQUESTED.set()
        _signal_workload_descendants()
        failures = 0
        cleanup_reason = ""
        shutdown_failed = False
        try:
            self._shutdown_semver_workers()
        except (SupervisorRefusal, OSError):
            shutdown_failed = True
            failures += 1
            cleanup_reason = (
                "cgroup-nonempty" if getattr(self, "semver_active", None) is not None else "process-alive"
            )
        try:
            _kill_workload_descendants()
        except (SupervisorRefusal, OSError):
            failures += 1
            cleanup_reason = cleanup_reason or "process-alive"
        if shutdown_failed:
            try:
                self._shutdown_semver_workers()
            except (SupervisorRefusal, OSError):
                failures += 1
        if self.root.is_symlink():
            _refuse("cleanup-root-invalid")
        baseline_mount = self.root / "workspace/semver-baseline/runtime"
        if os.path.ismount(baseline_mount):
            try:
                _run(["umount", str(baseline_mount)], timeout=8, cleanup=True)
            except SupervisorRefusal:
                try:
                    _run(["umount", "-l", str(baseline_mount)], timeout=8, cleanup=True)
                except SupervisorRefusal:
                    pass
            if os.path.ismount(baseline_mount):
                failures += 1
                cleanup_reason = cleanup_reason or "umount-busy"
        for relative in (
            "workspace/source", "workspace/raw", "workspace/.devlane-baseline-input",
            "workspace/semver-baseline", "workspace/semver-temporary-project",
            "trusted", "scratch/tmp", "scratch/target",
            "scratch/reports", "scratch/npm-cache", "scratch/cargo-home",
            "scratch/semver-cargo-home", "scratch/semver-cargo-bin",
            "scratch/semver-target", "scratch/semver-state",
        ):
            if not _shred_tree(self.root / relative):
                failures += 1
                cleanup_reason = cleanup_reason or "tree-remove"
        mount_reason = _unmount_tracked_mounts()
        if mount_reason:
            failures += 1
            cleanup_reason = cleanup_reason or mount_reason
        MOUNT_TARGETS.clear()
        try:
            if self.root.exists():
                self.root.rmdir()
        except OSError:
            failures += 1
            cleanup_reason = cleanup_reason or "tree-remove"
        if self.root.exists() or os.path.ismount(self.root):
            failures += 1
            cleanup_reason = cleanup_reason or "tree-remove"
        if failures:
            reason = cleanup_reason if cleanup_reason in CLEANUP_SUBREASONS else "tree-remove"
            _refuse("cleanup-incomplete:" + reason)
        return {"ok": True, "status": "cleanup-confirmed"}

    def request(self, value):
        if type(value) is not dict or type(value.get("op")) is not str:
            _refuse("control-request-invalid")
        op = value["op"]
        if op == "cancel" and set(value) == {"op"}:
            CANCEL_REQUESTED.set()
            _signal_workload_descendants()
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
            _signal_workload_descendants()
            response = self._cleanup()
            response["shutdown"] = True
            return response
        _refuse("control-operation-invalid")


def _serve_semver_worker(service, shutdown):
    server = service.semver_worker_socket
    if server is None:
        return
    while not shutdown.is_set():
        try:
            connection, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        with service.semver_worker_threads_lock:
            service.semver_worker_threads = [
                worker for worker in service.semver_worker_threads if worker.is_alive()
            ]
            if len(service.semver_worker_threads) >= 16:
                connection.close()
                continue
            worker = threading.Thread(
                target=service._handle_semver_worker_connection,
                args=(connection,), daemon=True,
                name="devlane-semver-worker-request",
            )
            service.semver_worker_threads.append(worker)
            worker.start()


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
            getattr(args, "failure_diagnostics_file", None),
        )
        startup_phase = "prepare"
        service.prepare()
        startup_phase = "socket"
        if service.context["profile"] == "core-rust":
            service.start_semver_worker_socket()
            service.semver_worker_accept_thread = threading.Thread(
                target=_serve_semver_worker, args=(service, shutdown),
                daemon=True, name="devlane-semver-worker-listener",
            )
            service.semver_worker_accept_thread.start()
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
                operation = None
                try:
                    request = bundle.strict_json(_recv_frame(connection), MAX_RPC)
                    operation = request.get("op") if type(request) is dict else None
                    if operation == "cancel":
                        response = service.request(request)
                    else:
                        if operation == "cleanup":
                            CANCEL_REQUESTED.set()
                            _signal_workload_descendants()
                        with SERVICE_LOCK:
                            response = service.request(request)
                    stop = response.pop("shutdown", False) or operation == "cleanup"
                    _send_frame(connection, json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
                    if stop:
                        shutdown.set()
                except SupervisorRefusal as error:
                    if operation == "execute":
                        service._capture_failure_diagnostics(execution_failed=True)
                    payload = json.dumps({"ok": False, "code": error.code}, separators=(",", ":")).encode("ascii")
                    try:
                        _send_frame(connection, payload)
                    except OSError:
                        pass
                    if 'operation' in locals() and operation == "cleanup":
                        shutdown.set()
                except Exception:
                    if operation == "execute":
                        service._capture_failure_diagnostics(execution_failed=True)
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
        _signal_workload_descendants()
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


def _source_free_diagnostics_context(context):
    return (type(context) is dict
            and context.get("wave_class") == fetch.SOURCE_FREE_WAVE_CLASS
            and context.get("profile") in ("core-node", "core-rust"))


def _start(args):
    if not sys.platform.startswith("linux"):
        _refuse("linux-runner-required")
    try:
        start_deadline = time.monotonic() + min(30, deadline_budget.remaining(args.deadline_file))
    except deadline_budget.DeadlineRefusal:
        _refuse("total-deadline-unavailable")
    context = _context_from_file(args.context)
    _projection_bytes, projection_value = _bound_projection(context, args.projection)
    failure_diagnostics_file = ""
    runner_temp_path = None
    if getattr(args, "failure_diagnostics_file", ""):
        if not _source_free_diagnostics_context(context):
            _refuse("source-free-diagnostics-context")
        diagnostic_path = Path(args.failure_diagnostics_file)
        runner_temp = os.environ.get("RUNNER_TEMP", "")
        try:
            runner_temp_path = Path(runner_temp).resolve(strict=True)
            parent = diagnostic_path.parent.resolve(strict=True)
            parent_metadata = parent.stat()
            if (not diagnostic_path.is_absolute() or parent != runner_temp_path
                    or not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != os.getuid()
                    or re.fullmatch(r"devlane-(?:vitest|rust-matrix)-[A-Za-z0-9_-]{1,128}\.json",
                                    diagnostic_path.name) is None
                    or os.path.lexists(diagnostic_path)):
                _refuse("source-free-diagnostics-path")
        except OSError:
            _refuse("source-free-diagnostics-path")
        failure_diagnostics_file = str(diagnostic_path)
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
    command = ["sudo", "-n"]
    if failure_diagnostics_file:
        command.append("--preserve-env=RUNNER_TEMP")
    command.extend([
        "unshare", "--net", "--mount", "--pid", "--ipc", "--fork", "--mount-proc",
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
    ])
    if failure_diagnostics_file:
        command.extend(("--failure-diagnostics-file", failure_diagnostics_file))
    try:
        start_deadline = min(start_deadline,
                             time.monotonic() + deadline_budget.remaining(args.deadline_file))
    except deadline_budget.DeadlineRefusal:
        _refuse("total-deadline-exhausted")
    try:
        supervisor_environment = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
        }
        if failure_diagnostics_file:
            supervisor_environment["RUNNER_TEMP"] = str(runner_temp_path)
        child = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, start_new_session=True,
            env=supervisor_environment,
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
            _refuse("cleanup-incomplete:tree-remove")
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
    start.add_argument("--failure-diagnostics-file", default="")
    start.add_argument("--node-snapshot-id", default="")
    for name in ("cargo-path", "rustc-path"):
        start.add_argument("--" + name, default="")
    client = sub.add_parser("_serve")
    for name in ("state-dir", "context", "workspace", "prepared", "bundle", "projection"):
        client.add_argument("--" + name, required=True)
    client.add_argument("--deadline-file", required=True)
    client.add_argument("--failure-diagnostics-file", default="")
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
