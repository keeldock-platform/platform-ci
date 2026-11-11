"""Fixed Cargo child for the pinned API checker.

The supervisor binds this source by digest and launches it after the prepared
cache passes validation. The child accepts a fixed Cargo operation set and
reports the temporary project at each required boundary.
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath

if sys.flags.isolated:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

CONTEXT_PATH = "/scratch/semver-state/context.json"
REAL_CARGO = "/tools/rust/bin/cargo"
TEMP_ROOT = "/scratch/tmp"
TARGET_ROOT = "/scratch/semver-target"
PROJECT_ROOT = TARGET_ROOT + "/semver-checks"
CHECKPOINT_SOCKET = "/control/matrix-worker.sock"
TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
MAX_CONTEXT_BYTES = 64 * 1024
MAX_ARGUMENTS = 32
MAX_ARGUMENT_BYTES = 4096
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}@[0-9A-Za-z][0-9A-Za-z.+-]{0,127}\Z")


class WrapperRefusal(ValueError):
    """Fixed refusal without a path, package name or tool output."""


def _refuse(code="semver-cargo-wrapper-refused"):
    raise WrapperRefusal(code)


def _duplicate_free(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _refuse()
        value[key] = item
    return value


def _read_context(path=CONTEXT_PATH):
    descriptor = None
    try:
        path = Path(path)
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > MAX_CONTEXT_BYTES):
            _refuse()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_dev != before.st_dev or metadata.st_ino != before.st_ino
                or metadata.st_size != before.st_size or metadata.st_uid != 0
                or metadata.st_gid != 65534 or stat.S_IMODE(metadata.st_mode) != 0o440
                or metadata.st_size > MAX_CONTEXT_BYTES):
            _refuse()
        payload = bytearray()
        deadline = time.monotonic() + 2.0
        while len(payload) <= MAX_CONTEXT_BYTES:
            if time.monotonic() >= deadline:
                _refuse()
            chunk = os.read(descriptor, min(16_384, MAX_CONTEXT_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        try:
            after_path = path.lstat()
        except OSError:
            _refuse()
        if (len(payload) != metadata.st_size or len(payload) > MAX_CONTEXT_BYTES
                or not stat.S_ISREG(after_path.st_mode) or after_path.st_nlink != 1
                or after.st_dev != metadata.st_dev or after.st_ino != metadata.st_ino
                or after.st_size != metadata.st_size or after.st_nlink != 1
                or after.st_mtime_ns != metadata.st_mtime_ns
                or after.st_ctime_ns != metadata.st_ctime_ns
                or after_path.st_dev != metadata.st_dev or after_path.st_ino != metadata.st_ino):
            _refuse()
        value = json.loads(payload.decode("ascii", "strict"), object_pairs_hook=_duplicate_free)
    except WrapperRefusal:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        _refuse()
    finally:
        if descriptor is not None:
            os.close(descriptor)
    fields = {
        "schema", "authenticated_binding", "expected_source_maps",
        "work_deadline", "cleanup_deadline",
    }
    if type(value) is not dict or set(value) != fields:
        _refuse()
    if (value["schema"] != "keeldock.semver-worker-context.v2"
            or type(value["authenticated_binding"]) is not dict
            or type(value["expected_source_maps"]) is not dict
            or set(value["expected_source_maps"]) != {
                "baseline_source_map_sha256", "candidate_source_map_sha256",
                "candidate_full_source_map_sha256",
            }
            or any(type(item) is not str or _HEX.fullmatch(item) is None
                   for item in value["expected_source_maps"].values())
            or type(value["work_deadline"]) not in (int, float)
            or type(value["cleanup_deadline"]) not in (int, float)
            or not math.isfinite(value["work_deadline"])
            or not math.isfinite(value["cleanup_deadline"])
            or value["cleanup_deadline"] < value["work_deadline"]):
        _refuse()
    return value


def _parse_cargo_arguments(arguments):
    if (type(arguments) is not list or not arguments or len(arguments) > MAX_ARGUMENTS
            or any(type(item) is not str or not item or len(item) > MAX_ARGUMENT_BYTES
                   or "\x00" in item for item in arguments)):
        _refuse("semver-cargo-command-invalid")
    if arguments in (["--version"], ["-V"], ["--version", "--verbose"]):
        return {"operation": "version", "manifest": None, "argv": list(arguments)}

    operation = arguments[0]
    allowed = {
        "update": {"--offline", "--manifest-path", "--color"},
        "metadata": {"--offline", "--locked", "--no-deps", "--format-version",
                     "--manifest-path"},
        "doc": {"--offline", "--locked", "--manifest-path", "--color", "--target-dir",
                "--package", "--target", "--lib", "--no-deps"},
    }
    if operation not in allowed:
        _refuse("semver-cargo-command-invalid")
    options = allowed[operation]
    manifest = None
    normalized = [operation]
    seen = set()
    index = 1
    while index < len(arguments):
        token = arguments[index]
        if token.startswith("--manifest-path="):
            if manifest is not None or "--manifest-path" in seen:
                _refuse("semver-cargo-command-invalid")
            manifest = token.split("=", 1)[1]
            seen.add("--manifest-path")
            index += 1
            continue
        if token.startswith("--color="):
            if ("--color" not in options or "--color" in seen
                    or token.split("=", 1)[1] not in {"never", "always"}):
                _refuse("semver-cargo-command-invalid")
            seen.add("--color")
            normalized.append(token)
            index += 1
            continue
        if token == "--manifest-path":
            if manifest is not None or "--manifest-path" in seen or index + 1 >= len(arguments):
                _refuse("semver-cargo-command-invalid")
            manifest = arguments[index + 1]
            seen.add("--manifest-path")
            index += 2
            continue
        if token not in options:
            _refuse("semver-cargo-command-invalid")
        if token in seen:
            _refuse("semver-cargo-command-invalid")
        seen.add(token)
        if token in ("--package", "--format-version", "--target-dir", "--target", "--color"):
            if index + 1 >= len(arguments):
                _refuse("semver-cargo-command-invalid")
            value = arguments[index + 1]
            if token == "--format-version" and value != "1":
                _refuse("semver-cargo-command-invalid")
            if token == "--package" and _PACKAGE.fullmatch(value) is None:
                _refuse("semver-cargo-command-invalid")
            if token == "--target-dir" and value != TARGET_ROOT:
                _refuse("semver-cargo-command-invalid")
            if token == "--target" and value != TARGET_TRIPLE:
                _refuse("semver-cargo-command-invalid")
            if token == "--color" and value not in {"never", "always"}:
                _refuse("semver-cargo-command-invalid")
            normalized.extend(("--color=" + value,) if token == "--color" else (token, value))
            index += 2
            continue
        normalized.append(token)
        index += 1

    if manifest is None:
        _refuse("semver-cargo-command-invalid")
    manifest_path = PurePosixPath(manifest)
    if (not manifest_path.is_absolute() or ".." in manifest_path.parts
            or manifest_path.name != "Cargo.toml" or str(manifest_path) != manifest):
        _refuse("semver-cargo-manifest-invalid")
    manifest = str(manifest_path)
    if manifest in {
        "/workspace/source/runtime/Cargo.toml",
        "/workspace/semver-baseline/runtime/Cargo.toml",
        "/prepared/semver-baseline/runtime/Cargo.toml",
    }:
        project_kind = "workspace"
        if operation == "update":
            _refuse("semver-cargo-command-invalid")
    elif manifest.startswith(PROJECT_ROOT + "/"):
        project_path = PurePosixPath(manifest)
        if (project_path.name != "Cargo.toml"
                or project_path.parent.parent != PurePosixPath(PROJECT_ROOT)
                or len(project_path.parts) != len(PurePosixPath(PROJECT_ROOT).parts) + 2):
            _refuse("semver-cargo-manifest-invalid")
        basename = project_path.parent.name
        if basename.startswith("local-"):
            project_kind = "local"
        elif basename.startswith("registry-"):
            project_kind = "registry"
        else:
            _refuse("semver-cargo-manifest-invalid")
    else:
        _refuse("semver-cargo-manifest-invalid")

    if operation == "update" and project_kind != "local":
        _refuse("semver-cargo-command-invalid")
    if operation == "doc":
        required = {"--package", "--target-dir", "--target", "--lib", "--no-deps", "--color"}
        if not required.issubset(seen):
            _refuse("semver-cargo-command-invalid")
    if operation == "metadata" and "--format-version" not in seen:
        _refuse("semver-cargo-command-invalid")

    if "--offline" not in normalized:
        normalized.append("--offline")
    if (operation == "doc" or operation == "metadata" and
            (project_kind == "workspace" or project_kind == "local")) and "--locked" not in normalized:
        normalized.append("--locked")
    normalized.extend(("--manifest-path", manifest))
    return {"operation": operation, "manifest": manifest,
            "project_kind": project_kind, "argv": normalized}


def _project_root(manifest):
    path = PurePosixPath(manifest)
    if path.parent.parent != PurePosixPath(PROJECT_ROOT):
        _refuse("semver-cargo-temporary-project-invalid")
    return str(path.parent)


def _send_checkpoint(event, operation, manifest):
    payload = json.dumps({
        "op": "semver-checkpoint", "event": event,
        "operation": operation, "manifest": manifest,
    }, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(payload) > 16 * 1024:
        _refuse("semver-cargo-checkpoint-invalid")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(60)
    try:
        connection.connect(CHECKPOINT_SOCKET)
        connection.sendall(len(payload).to_bytes(4, "big") + payload)
        size_bytes = bytearray()
        while len(size_bytes) < 4:
            chunk = connection.recv(4 - len(size_bytes))
            if not chunk:
                _refuse("semver-cargo-checkpoint-unavailable")
            size_bytes.extend(chunk)
        size = int.from_bytes(size_bytes, "big")
        if size < 2 or size > 1024:
            _refuse("semver-cargo-checkpoint-response")
        response_bytes = bytearray()
        while len(response_bytes) < size:
            chunk = connection.recv(size - len(response_bytes))
            if not chunk:
                _refuse("semver-cargo-checkpoint-response")
            response_bytes.extend(chunk)
        response = json.loads(response_bytes.decode("ascii", "strict"))
    except WrapperRefusal:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        _refuse("semver-cargo-checkpoint-unavailable")
    finally:
        connection.close()
    if type(response) is not dict or response != {"ok": True}:
        _refuse("semver-cargo-checkpoint-refused")


def _checkpoint_events(command):
    if command["project_kind"] == "local":
        return (("before-update", "update"), ("after-update", "update"),
                ("after-metadata", "metadata"), ("after-doc", "doc"))
    if command["project_kind"] == "registry":
        return (("before-metadata", "metadata"), ("after-metadata", "metadata"),
                ("after-doc", "doc"))
    return ()


def _run(arguments, *, context=None, run_process=None):
    """Validate a fixed operation, run only pinned Cargo, then check its temp project."""
    command = _parse_cargo_arguments(arguments)
    if command["operation"] == "version":
        invocation = [REAL_CARGO, *command["argv"]]
        runner = subprocess.run if run_process is None else run_process
        try:
            result = runner(invocation, cwd="/workspace/source", env=_cargo_environment(),
                            stdin=subprocess.DEVNULL, check=False, close_fds=True)
        except OSError:
            _refuse("semver-cargo-launch-failed")
        return result.returncode

    if command["project_kind"] in {"local", "registry"}:
        if context is None:
            context = _read_context()
        for event, operation in _checkpoint_events(command):
            if operation == command["operation"] and event.startswith("before-"):
                _send_checkpoint(event, operation, command["manifest"])

    runner = subprocess.run if run_process is None else run_process
    invocation = [REAL_CARGO, *command["argv"]]
    try:
        result = runner(invocation, cwd="/workspace/source", env=_cargo_environment(),
                        stdin=subprocess.DEVNULL, check=False, close_fds=True)
    except OSError:
        _refuse("semver-cargo-launch-failed")

    if command["project_kind"] in {"local", "registry"}:
        for event, operation in _checkpoint_events(command):
            if operation == command["operation"] and event.startswith("after-"):
                _send_checkpoint(event, operation, command["manifest"])
    return result.returncode


def _cargo_environment():
    return {
        "PATH": "/tools/rust/bin:/usr/bin:/bin",
        "LD_LIBRARY_PATH": "/tools/rust/lib",
        "HOME": "/scratch/semver-cargo-home",
        "TMPDIR": TEMP_ROOT,
        "CARGO_HOME": "/scratch/semver-cargo-home",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": TARGET_ROOT,
        "CARGO_BUILD_TARGET": TARGET_TRIPLE,
        "RUSTUP_HOME": "/tools/rust",
        "CARGO_TERM_COLOR": "never",
        "RUSTC_BOOTSTRAP": "1",
        "RUSTDOCFLAGS": (
            "-Z unstable-options --document-private-items --document-hidden-items "
            "--output-format=json --cap-lints=allow"
        ),
        "RUSTFLAGS": "--cap-lints=allow",
        "CI": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def main(arguments=None):
    try:
        return _run(sys.argv[1:] if arguments is None else list(arguments))
    except WrapperRefusal:
        return 125
    except (OSError, ValueError):
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
