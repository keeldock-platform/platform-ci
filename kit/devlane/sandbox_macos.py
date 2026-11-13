"""macOS worker adapter for one encrypted core-node devlane wave."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

CONTROL_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CONTROL_ROOT / "kit" / "confinement"))
sys.path.insert(0, str(CONTROL_ROOT / "kit" / "devlane"))

import bundle
import fetch
import deadline as deadline_budget
import macos_boundary_guard as boundary_guard
import filter as output_filter
import supervisor as linux_supervisor
import refusal_codes

WORKER_NAME_PREFIX = "kddevlane"
WORKER_GROUP = 20
DARWIN_SIGNED_UID_MIN = -(1 << 31)
DARWIN_UID_MAX = (1 << 32) - 1
DARWIN_UID_MODULUS = 1 << 32
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_LOG_BYTES = 256 * 1024 * 1024
MAX_PATH_BYTES = 4096
RUN_ID_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
PROFILE_NAME = "core-node"
PROFILE_FILE = "ci/devlane-profiles.json"
SBPL_FILE = "worker.sb"
STATE_FILE = "worker.json"
IDENTITY_FILE = "identity.json"
CLEANUP_INTENT_FILE = "cleanup-intent.json"
PF_STATE_FILE = "pf.json"
ANCHOR_NAME = "com.apple/devlane-private"
MACOS_ROOT_DIRECTORY = chr(47) + "private" + chr(47) + "var" + chr(47) + "root"
CLT_DEVELOPER_DIRECTORY = "/Library/Developer/CommandLineTools"
CLT_BIN_DIRECTORY = CLT_DEVELOPER_DIRECTORY + "/usr/bin"
CLT_CLANG_PATH = CLT_DEVELOPER_DIRECTORY + "/usr/bin/clang"


DECRYPT_REFUSAL_CODES = frozenset((
    "archive-invalid", "auth-tag", "binding-mismatch", "crypto-unavailable",
    "decrypt-failed", "decrypt-timeout", "expired", "invalid-envelope", "key-format",
    "request-invalid", "truncated",
))

MACOS_PREFLIGHT_REFUSAL_CODES = refusal_codes.MACOS_PREFLIGHT_REFUSAL_CODES

MACOS_ROOT_IDENTITY_REFUSAL_CODES = frozenset(
    code for code in MACOS_PREFLIGHT_REFUSAL_CODES if code.startswith("macos-")
) | frozenset(("state-directory-permissions", "dispatch-context-invalid",
               "tool-file-type-invalid", "tool-owner-invalid", "tool-mode-invalid", "tool-symlink", "tool-path-resolve-mismatch",
               "tool-file-unavailable",
               "clt-missing", "developer-dir-unexpected", "developer-dir-trust-invalid", "clang-path-invalid",
               "developer-clang-mismatch",
               "tool-version-unavailable", "node-toolchain-missing", "node-toolchain-version",
               "npm-toolchain-version", "supervisor-operation-failed", "raw-record-size"))


class Refusal(ValueError):
    def __init__(self, code="supervisor-failed", decrypt_refusal=None):
        super().__init__(code)
        self.code = code
        self.decrypt_refusal = decrypt_refusal


def _refuse(code="supervisor-failed", *, decrypt_refusal=None):
    raise Refusal(code, decrypt_refusal=decrypt_refusal)


def _safe_path(value, *, must_exist=False):
    try:
        path = Path(value)
        if not path.is_absolute() or len(os.fsencode(path)) > MAX_PATH_BYTES or ".." in path.parts:
            _refuse("input-unavailable")
        resolved = path.resolve(strict=must_exist)
        if resolved != path:
            _refuse("input-unavailable")
        return path
    except (OSError, RuntimeError, ValueError):
        _refuse("input-unavailable")


def _read_json(path, maximum=65536):
    descriptor = None
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            _refuse("input-unavailable")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > maximum:
                _refuse("input-unavailable")
        return bundle.strict_json(bytes(payload), maximum)
    except (OSError, bundle.Refusal):
        _refuse("input-unavailable")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_json(path, value, *, mode=0o600, exclusive=True):
    target = Path(path)
    directory_descriptor = descriptor = None
    try:
        directory_descriptor = os.open(
            str(target.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        flags |= os.O_EXCL if exclusive else os.O_TRUNC
        descriptor = os.open(target.name, flags, mode, dir_fd=directory_descriptor)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(bundle.canonical_json(value) + b"\n")
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), mode)
        os.fsync(directory_descriptor)
    except (OSError, bundle.Refusal):
        _refuse("state-directory-permissions")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _state_paths(state_dir):
    state = _safe_path(state_dir, must_exist=True)
    if state.is_symlink() or not state.is_dir():
        _refuse("state-directory-permissions")
    return state, state.parent


def _identity(state):
    value = _read_json(state / IDENTITY_FILE, 4096)
    fields = {"schema", "run_id", "runner_uid", "uid", "gid", "account", "home", "node", "npm_cli",
              "node_sha256", "npm_sha256", "developer_directory", "clang", "host_identity"}
    if (type(value) is not dict or set(value) != fields or value.get("schema") != 1
            or not RUN_ID_RE.fullmatch(str(value.get("run_id", "")))
            or type(value.get("runner_uid")) is not int or value["runner_uid"] <= 0
            or type(value.get("uid")) is not int or not 1 <= value["uid"] < 60000
            or value.get("gid") != WORKER_GROUP
            or type(value.get("account")) is not str
            or re.fullmatch(WORKER_NAME_PREFIX + r"[0-9]{1,19}", value["account"]) is None
            or type(value.get("host_identity")) is not dict):
        _refuse("dispatch-context-invalid")
    return value


def _cleanup_intent(state):
    value = _read_json(state / CLEANUP_INTENT_FILE, 2048)
    fields = {"schema", "run_id", "runner_uid", "uid", "gid", "account", "home"}
    if (type(value) is not dict or set(value) != fields or value.get("schema") != 1
            or not RUN_ID_RE.fullmatch(str(value.get("run_id", "")))
            or type(value.get("runner_uid")) is not int or value["runner_uid"] <= 0
            or type(value.get("uid")) is not int or not 1 <= value["uid"] < 60000
            or value.get("gid") != WORKER_GROUP
            or value.get("account") != WORKER_NAME_PREFIX + str(value["run_id"])
            or value.get("home") != str(state.parent / "worker-home")):
        _refuse("cleanup-intent-invalid")
    return value


def _account_is_listed(payload, account):
    try:
        rows = [line.split() for line in payload.decode("ascii", "strict").splitlines() if line.strip()]
    except (AttributeError, UnicodeDecodeError):
        _refuse("cleanup-incomplete")
    if any(len(row) != 2 or not row[1].isdecimal() for row in rows):
        _refuse("cleanup-incomplete")
    return any(row[0] == account for row in rows)


def _worker_state(state):
    value = _read_json(state / STATE_FILE, 32768)
    required = {"schema", "profile", "run_id", "runner_uid", "worker_uid", "worker_gid", "node", "npm_cli",
                "node_sha256", "npm_sha256", "source", "prepared", "scratch", "home", "control", "profile_sha256",
                "probe_complete", "decrypted", "execution_complete", "pf_rules_file"}
    if (type(value) is not dict or set(value) != required or value.get("schema") != 1
            or value.get("profile") != PROFILE_NAME or not RUN_ID_RE.fullmatch(str(value.get("run_id", "")))
            or type(value.get("probe_complete")) is not bool or type(value.get("decrypted")) is not bool
            or type(value.get("execution_complete")) is not bool):
        _refuse("dispatch-context-invalid")
    return value


def _write_state(state, value):
    _write_json(state / STATE_FILE, value, mode=0o600, exclusive=False)


def _run(argv, *, timeout=20, env=None, cwd=None, user=None, group=None, capture_limit=MAX_OUTPUT_BYTES):
    process = None
    output_path = None
    try:
        process = subprocess.Popen(
            [str(item) for item in argv], cwd=str(cwd) if cwd is not None else None,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, close_fds=True, start_new_session=True,
            user=user, group=group, extra_groups=() if user is not None else None,
        )
        stdout, stderr = process.communicate(timeout=timeout)
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
        _refuse("total-deadline-exhausted")
    except (OSError, subprocess.SubprocessError, TypeError):
        _refuse("supervisor-operation-failed")
    if len(stdout) > capture_limit or len(stderr) > capture_limit:
        _refuse("raw-record-size")
    return process.returncode, stdout, stderr


def _run_root_helper(operation, arguments, *, preserve=()):
    command = ["/usr/bin/sudo", "-n"]
    if preserve:
        command.append("--preserve-env=" + ",".join(preserve))
    command.extend((sys.executable, "-B", str(Path(__file__).resolve()), operation))
    for name, value in arguments.items():
        command.extend(("--" + name.replace("_", "-"), str(value)))
    result = subprocess.run(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"), "LC_ALL": "C",
             "ImageOS": os.environ.get("ImageOS", ""), "ImageVersion": os.environ.get("ImageVersion", ""),
             **({"DEVLANE_DECRYPT_KEY": os.environ.get("DEVLANE_DECRYPT_KEY", "")} if preserve else {})},
        timeout=120, check=False,
    )
    if result.returncode != 0:
        try:
            lines = result.stderr.decode("ascii", "strict").splitlines()
        except UnicodeDecodeError:
            lines = []
        if len(lines) == 1 and lines[0].startswith("devlane_macos_root_refusal="):
            code = lines[0].removeprefix("devlane_macos_root_refusal=")
            if code in MACOS_ROOT_IDENTITY_REFUSAL_CODES:
                _refuse(code)
        _refuse("macos-preflight-root-helper")
    return result.stdout


def _clean_env(state, *, preparation=False):
    ident = _identity(state)
    return {
        "PATH": str(Path(ident["node"]).parent) + ":" + CLT_BIN_DIRECTORY + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(Path(state.parent) / "preparation-home") if preparation else str(Path(ident["home"])),
        "TMPDIR": str(state.parent / "preparation-tmp") if preparation else str(Path(_worker_state(state)["scratch"])),
        "LC_ALL": "C", "LANG": "C", "CI": "1", "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_AUDIT": "false", "NPM_CONFIG_FUND": "false", "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "PLAYWRIGHT_BROWSERS_PATH": str(Path(state.parent) / "prepared" / "ms-playwright"),
        "DEVELOPER_DIR": CLT_DEVELOPER_DIRECTORY,
    }


def _sha256_file(path, maximum=256 * 1024 * 1024):
    digest = hashlib.sha256()
    total = 0
    try:
        with Path(path).open("rb") as source:
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    _refuse("input-size")
                digest.update(chunk)
    except OSError:
        _refuse("tool-version-unavailable")
    return digest.hexdigest()


def _trusted_file(path, *, executable=False, owners=None):
    candidate = Path(path)
    try:
        info = candidate.lstat()
        allowed_owners = set((0, os.getuid()) if owners is None else owners)
        if stat.S_ISLNK(info.st_mode):
            _refuse("tool-symlink")
        if not stat.S_ISREG(info.st_mode):
            _refuse("tool-file-type-invalid")
        if info.st_uid not in allowed_owners:
            _refuse("tool-owner-invalid")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 or executable and not mode & 0o111:
            _refuse("tool-mode-invalid")
        real = candidate.resolve(strict=True)
        if real != candidate:
            _refuse("tool-path-resolve-mismatch")
    except OSError:
        _refuse("tool-file-unavailable")
    return candidate


def _command_output(argv, *, env, expected_code=0, timeout=15, maximum=4096):
    code, stdout, stderr = _run(argv, env=env, timeout=timeout, capture_limit=maximum)
    if code != expected_code or stderr:
        _refuse("tool-version-unavailable")
    try:
        return stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        _refuse("tool-version-unavailable")


def _find_node_tools():
    node_name = shutil.which("node")
    npm_name = shutil.which("npm")
    if not node_name or not npm_name:
        _refuse("node-toolchain-missing")
    node = _trusted_file(Path(node_name), executable=True)
    npm_launcher = Path(npm_name).resolve(strict=True)
    if npm_launcher.name == "npm-cli.js":
        npm_entry = npm_launcher
    else:
        npm_root = npm_launcher.parent.parent if npm_launcher.parent.name == "bin" else npm_launcher.parent
        npm_entry = npm_root / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
    npm_cli = _trusted_file(npm_entry)
    _trusted_worker_readonly_tree(npm_entry.parents[4])
    version_env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    if _command_output((str(node), "--version"), env=version_env) != "v24.22.1":
        _refuse("node-toolchain-version")
    if _command_output((str(node), str(npm_cli), "--version"), env=version_env) != "11.19.1":
        _refuse("npm-toolchain-version")
    return node, npm_cli


def _trusted_worker_readonly_tree(root):
    """Require the hosted npm prefix to be traversable but not worker-writable."""
    root = Path(root)
    owners = {0, os.getuid()}
    try:
        parent = root.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
                or parent.st_uid not in owners or parent.st_mode & 0o022):
            _refuse("tool-mode-invalid")
        root_info = root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
                or root_info.st_uid not in owners or root_info.st_mode & 0o022
                or root_info.st_mode & 0o005 != 0o005):
            _refuse("tool-mode-invalid")
        pending = [root]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        resolved = path.resolve(strict=True)
                        if not resolved.is_relative_to(root):
                            _refuse("tool-path-resolve-mismatch")
                        target = resolved.lstat()
                        if (target.st_uid not in owners or target.st_mode & 0o022
                                or not stat.S_ISREG(target.st_mode) or target.st_mode & 0o004 != 0o004):
                            _refuse("tool-mode-invalid")
                        continue
                    if info.st_uid not in owners or info.st_mode & 0o022:
                        _refuse("tool-mode-invalid")
                    if stat.S_ISDIR(info.st_mode):
                        if info.st_mode & 0o005 != 0o005:
                            _refuse("tool-mode-invalid")
                        pending.append(path)
                    elif stat.S_ISREG(info.st_mode):
                        if info.st_mode & 0o004 != 0o004:
                            _refuse("tool-mode-invalid")
                    else:
                        _refuse("tool-file-type-invalid")
    except Refusal:
        raise
    except OSError:
        _refuse("tool-file-unavailable")


def _directory_service_group_ids(account):
    result = _directory_service(
        ("/usr/bin/id", "-G", account), "developer-dir-trust-invalid", timeout=5,
    )
    try:
        groups = result.stdout.decode("ascii", "strict").split()
        if (not groups or any(re.fullmatch(r"[0-9]+", group) is None for group in groups)
                or any(int(group, 10) > DARWIN_UID_MAX for group in groups)):
            _refuse("developer-dir-trust-invalid")
        return frozenset(int(group, 10) for group in groups)
    except (UnicodeDecodeError, ValueError):
        _refuse("developer-dir-trust-invalid")


def _trusted_developer_directory(path, anchor, *, worker_account=None, defer_group_membership=False):
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
    current = Path(path)
    anchor = Path(anchor)
    directories = []
    while True:
        directories.append(current)
        if current == anchor:
            break
        parent = current.parent
        if parent == current or not current.is_relative_to(anchor):
            _refuse("developer-dir-trust-invalid")
        current = parent
    write_rights = frozenset((
        "add_file", "add_subdirectory", "append", "chown", "delete", "delete_child",
        "write", "writeattr", "writeextattr", "writesecurity",
    ))
    worker_groups = None

    def groups():
        nonlocal worker_groups
        if worker_groups is None:
            if worker_account is None:
                if defer_group_membership:
                    return None
                _refuse("developer-dir-trust-invalid")
            worker_groups = _directory_service_group_ids(worker_account)
        return worker_groups

    for directory in directories:
        try:
            metadata = directory.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != 0 or metadata.st_mode & 0o002):
                _refuse("developer-dir-trust-invalid")
            if metadata.st_mode & 0o020:
                if metadata.st_gid not in (0, 80):
                    _refuse("developer-dir-trust-invalid")
                memberships = groups()
                if memberships is not None and metadata.st_gid in memberships:
                    _refuse("developer-dir-trust-invalid")
            output = _command_output(("/bin/ls", "-lde", str(directory)), env=env, maximum=16384)
        except Refusal:
            _refuse("developer-dir-trust-invalid")
        except OSError:
            _refuse("developer-dir-trust-invalid")
        lines = output.splitlines()
        if not lines or not lines[0].endswith(str(directory)):
            _refuse("developer-dir-trust-invalid")
        for line in lines[1:]:
            if not line.strip():
                continue
            match = re.fullmatch(r"\s*[0-9]+:\s+(.*?)\s+(allow|deny)\s+(.+)", line)
            if match is None:
                _refuse("developer-dir-trust-invalid")
            if match.group(2) == "allow":
                rights = {part.strip().lower() for part in match.group(3).split(",")}
                if rights & write_rights:
                    principal = match.group(1).strip().lower()
                    if principal == "user:root":
                        continue
                    if principal == "group:admin":
                        memberships = groups()
                        if memberships is None or 80 not in memberships:
                            continue
                    _refuse("developer-dir-trust-invalid")


def _validate_clt(*, worker_account=None, defer_group_membership=False):
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
    try:
        developer_path = Path(CLT_DEVELOPER_DIRECTORY)
        developer_path.lstat()
    except FileNotFoundError:
        _refuse("clt-missing")
    except OSError:
        _refuse("developer-dir-trust-invalid")
    developer = CLT_DEVELOPER_DIRECTORY
    _trusted_developer_directory(
        developer_path, Path("/Library"), worker_account=worker_account,
        defer_group_membership=defer_group_membership,
    )
    clang_name = _command_output(
        ("/usr/bin/xcrun", "--find", "clang"), env={**env, "DEVELOPER_DIR": CLT_DEVELOPER_DIRECTORY},
    )
    if clang_name != CLT_CLANG_PATH:
        _refuse("clang-path-invalid")
    try:
        clang_path = Path(clang_name).resolve(strict=True)
    except OSError:
        _refuse("clang-path-invalid")
    if not clang_path.is_relative_to(developer_path):
        _refuse("clang-path-invalid")
    _trusted_developer_directory(
        clang_path.parent, developer_path, worker_account=worker_account,
        defer_group_membership=defer_group_membership,
    )
    clang = _trusted_file(clang_path, executable=True, owners=(0,))
    return developer, str(clang)


def _host_preflight(state, workspace, profile, run_id):
    if sys.platform != "darwin" or platform.machine() not in ("arm64", "aarch64"):
        _refuse("macos-runner-required")
    if profile != PROFILE_NAME or not RUN_ID_RE.fullmatch(run_id):
        _refuse("profile-unknown")
    root = _safe_path(workspace, must_exist=True)
    runner_uid = root.stat().st_uid
    if runner_uid == 0 or runner_uid != os.getuid():
        _refuse("dispatch-context-invalid")
    try:
        node, npm_cli = _find_node_tools()
    except Refusal:
        raise
    except Exception:
        _refuse("macos-preflight-node-tools")
    try:
        developer, clang = _validate_clt(defer_group_membership=True)
    except Refusal:
        raise
    except Exception:
        _refuse("macos-preflight-command-line-tools")
    try:
        host = boundary_guard.check_platform()
    except boundary_guard.GuardError as error:
        _refuse("macos-runner-required" if error.reason == "platform_unapproved"
                else "macos-preflight-platform-policy")
    except Exception:
        _refuse("macos-preflight-platform-policy")
    try:
        state.parent.chmod(0o711)
    except OSError:
        _refuse("macos-preflight-temp-permissions")
    try:
        _run_root_helper("root-identity", {
            "state_dir": state, "workspace": root, "run_id": run_id, "runner_uid": runner_uid,
            "node": node, "npm_cli": npm_cli, "node_sha256": _sha256_file(node),
            "npm_sha256": _sha256_file(npm_cli), "developer_directory": developer, "clang": clang,
            "image_os": host.image_os, "image_version": host.image_version,
            "product_version": host.product_version, "architecture": host.architecture,
        })
    except Refusal:
        raise
    except Exception:
        _refuse("macos-preflight-root-helper")
    if not (state / IDENTITY_FILE).is_file():
        _refuse("macos-preflight-state-record")
    for name in ("preparation-home", "preparation-tmp"):
        path = state.parent / name
        try:
            path.mkdir(mode=0o700, exist_ok=True)
        except OSError:
            _refuse("macos-preflight-temp-permissions")
    print("devlane_macos=preflight-ready")


def _validate_projection_file(path, profile, control_sha):
    try:
        payload = Path(path).read_bytes()
        value = fetch.validate_projection(payload, profile, control_sha)
    except (OSError, fetch.Refusal):
        _refuse("projection-invalid")
    return value


def preparation_profile_text(*, project, prepared, cache, home, temporary, node, npm_cli):
    node_root = Path(node).parent
    npm_root = Path(npm_cli).parent.parent
    readable = {
        "/System/Library", "/System/Volumes/Preboot/Cryptexes/OS", "/usr/lib", "/usr/share",
        "/usr/bin", "/bin", "/dev", CLT_DEVELOPER_DIRECTORY, str(node_root), str(npm_root), str(project),
        str(prepared), str(cache), str(home), str(temporary),
    }
    executable = {
        "/bin/sh", "/bin/bash", "/usr/bin/env", "/usr/bin/sandbox-exec", "/usr/bin/xcrun",
        CLT_CLANG_PATH, str(node),
    }
    writable = {str(project), str(prepared), str(cache), str(home), str(temporary)}
    lines = [
        "(version 1)", "(deny default)", "(allow process-fork)",
        "(allow network-outbound)", "(deny network-inbound)",
        "(allow signal (target same-sandbox))",
    ]
    lines.extend("(allow process-exec (literal " + _quote(path) + "))" for path in sorted(executable))
    lines.extend("(allow file-read* (subpath " + _quote(path) + "))" for path in sorted(readable))
    lines.extend("(allow file-write* (subpath " + _quote(path) + "))" for path in sorted(writable))
    lines.extend((
        "(allow file-read* (literal \"/dev/null\") (literal \"/dev/urandom\") "
        + "(literal \"/dev/random\") (literal \"/dev/zero\"))",
        "(allow file-map-executable (subpath " + _quote(project) + ") (subpath " + _quote(prepared) + "))",
    ))
    return "\n".join(lines) + "\n"


def _preparation_env(ident, *, home, temporary, cache, prepared):
    return {
        "PATH": str(Path(ident["node"]).parent) + ":" + CLT_BIN_DIRECTORY + ":/usr/bin:/bin",
        "DEVELOPER_DIR": CLT_DEVELOPER_DIRECTORY,
        "HOME": str(home), "TMPDIR": str(temporary), "NPM_CONFIG_CACHE": str(cache),
        "NPM_CONFIG_IGNORE_SCRIPTS": "true", "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false", "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "CI": "1", "LC_ALL": "C", "LANG": "C",
        "PLAYWRIGHT_BROWSERS_PATH": str(Path(prepared) / "ms-playwright"),
    }


def _npm_preparation_command(ident):
    return (
        ident["node"], ident["npm_cli"], "ci", "--ignore-scripts", "--include=dev",
        "--include=optional", "--no-audit", "--no-fund",
    )


def _run_preparation_process(argv, *, ident, profile, cwd, env, output, timeout):
    command = ["/usr/bin/sandbox-exec", "-f", str(profile), *map(str, argv)]
    process = None
    try:
        process = subprocess.Popen(
            command, cwd=str(cwd), stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            env=env, close_fds=True, start_new_session=True,
            user=ident["uid"], group=ident["gid"], extra_groups=(), preexec_fn=_worker_limits,
        )
        process.wait(timeout=timeout)
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
                    _refuse("process-cleanup-incomplete")
        _refuse("total-deadline-exhausted")
    except (OSError, subprocess.SubprocessError, TypeError):
        _refuse("dependency-preparation-refused")
    _terminate_worker_processes(ident["uid"])
    return process.returncode


def _readonly_tree(root):
    base = Path(root)
    for current, directories, files in os.walk(base, topdown=False, followlinks=False):
        for name in files:
            path = Path(current) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                _refuse("prepared-member-type")
            os.chmod(path, 0o555 if info.st_mode & 0o111 else 0o444)
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink():
                os.chmod(path, 0o555)
    os.chmod(base, 0o555)


def _tree_limits(root, *, max_files=250000, max_bytes=4 * 1024 * 1024 * 1024):
    total = count = 0
    base = Path(root)
    for current, directories, files in os.walk(base, followlinks=False):
        for name in directories + files:
            path = Path(current) / name
            info = path.lstat()
            count += 1
            if count > max_files:
                _refuse("prepared-file-count")
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                if os.path.isabs(target) or not (path.parent / target).resolve(strict=True).is_relative_to(base.resolve(strict=True)):
                    _refuse("prepared-link-invalid")
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > max_bytes:
                    _refuse("prepared-tree-size")
            elif not stat.S_ISDIR(info.st_mode):
                _refuse("prepared-member-type")
    return count, total


def _prepare(state, projection_path, output_path, profile, control_sha, deadline_file):
    if os.geteuid() != 0:
        _refuse("macos-root-required")
    ident = _identity(state)
    if profile != PROFILE_NAME:
        _refuse("profile-unknown")
    deadline_budget.remaining(deadline_file)
    projection = _validate_projection_file(projection_path, profile, control_sha)
    root = state.parent
    output = _safe_path(output_path)
    project = root / "preparation-project"
    prepared = root / "prepared"
    cache = root / "preparation-npm-cache"
    home = root / "preparation-home"
    temporary = root / "preparation-tmp"
    profile_path = root / "preparation.sb"
    log = root / "preparation.log"
    if output != prepared:
        _refuse("prepared-output-invalid")
    for path in (project, prepared, cache, profile_path, log):
        if path.exists() or path.is_symlink():
            _refuse("prepared-output-exists")
    for path in (home, temporary):
        try:
            info = path.lstat()
        except OSError:
            _refuse("preparation-path-invalid")
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            _refuse("preparation-path-invalid")
    project.mkdir(mode=0o700)
    prepared.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    (project / "package.json").write_bytes(bundle.canonical_json(projection["npm_package"]) + b"\n")
    (project / "package-lock.json").write_bytes(bundle.canonical_json(projection["npm_lock"]) + b"\n")
    (project / ".npmrc").write_text(
        "ignore-scripts=true\naudit=false\nfund=false\nupdate-notifier=false\nregistry=https://registry.npmjs.org/\n",
        encoding="ascii",
    )
    for path in (project, prepared, cache, home, temporary):
        _chown_tree(path, ident["uid"], ident["gid"])
    profile_path.write_text(preparation_profile_text(
        project=project, prepared=prepared, cache=cache, home=home, temporary=temporary,
        node=ident["node"], npm_cli=ident["npm_cli"],
    ), encoding="utf-8")
    os.chmod(profile_path, 0o444)
    env = _preparation_env(ident, home=home, temporary=temporary, cache=cache, prepared=prepared)
    timeout = min(3600, deadline_budget.remaining(deadline_file))
    with log.open("xb") as output_log:
        code = _run_preparation_process(
            _npm_preparation_command(ident),
            ident=ident, profile=profile_path, cwd=project, env=env, output=output_log, timeout=timeout,
        )
    if log.stat().st_size > MAX_LOG_BYTES or code != 0:
        _refuse("dependency-preparation-refused")
    if projection["playwright"]:
        candidates = (
            project / "node_modules" / "playwright" / "cli.js",
            project / "node_modules" / "@playwright" / "test" / "cli.js",
        )
        cli = next((path for path in candidates if path.is_file() and not path.is_symlink()), None)
        if cli is None:
            _refuse("prepared-input-invalid")
        with log.open("ab") as output_log:
            code = _run_preparation_process(
                (ident["node"], cli, "install", *projection["playwright"]),
                ident=ident, profile=profile_path, cwd=project, env=env, output=output_log,
                timeout=min(1800, deadline_budget.remaining(deadline_file)),
            )
        if code != 0 or log.stat().st_size > MAX_LOG_BYTES:
            _refuse("dependency-preparation-refused")
        if not (prepared / "ms-playwright").is_dir():
            _refuse("prepared-input-invalid")
    source_modules = project / "node_modules"
    if not source_modules.is_dir() or source_modules.is_symlink():
        _refuse("prepared-input-invalid")
    shutil.move(str(source_modules), str(prepared / "node_modules"))
    (prepared / "projection.json").write_bytes(bundle.canonical_json(projection) + b"\n")
    _tree_limits(prepared)
    _readonly_tree(prepared)
    try:
        shutil.rmtree(project)
        shutil.rmtree(cache)
        shutil.rmtree(home)
        shutil.rmtree(temporary)
        profile_path.unlink()
        log.unlink()
    except OSError:
        _refuse("cleanup-incomplete")
    print("dependency_preparation=complete")



def _quote(path):
    value = str(path)
    if not value.startswith("/") or any(character in value for character in ("\n", "\r", "\x00", '"')):
        _refuse("profile-config-invalid")
    return '"' + value.replace("\\", "\\\\") + '"'


def profile_text(*, workspace, prepared, scratch, home, control, node, developer, clang, npm_cli=None):
    node_root = Path(node).parent
    allowed_reads = {
        "/System/Library", "/System/Volumes/Preboot/Cryptexes/OS", "/usr/lib", "/usr/share", "/usr/bin",
        "/bin", str(Path(workspace)), str(Path(prepared)), str(Path(control)), str(Path(home)),
        str(Path(developer)), str(node_root), str(Path(workspace).parent / "trusted"), str(Path(scratch)),
    }
    if npm_cli is not None:
        allowed_reads.add(str(Path(npm_cli).parent.parent))
    allowed_exec = {
        "/bin/sh", "/bin/bash", "/usr/bin/env", "/usr/bin/sandbox-exec", "/usr/bin/xcrun",
        str(Path(node)), str(Path(clang)),
    }
    lines = [
        "(version 1)", "(deny default)", "(allow process-fork)", "(deny network*)", "(deny lsopen)",
        "(deny mach-lookup)", "(deny mach-register)", "(allow signal (target same-sandbox))",
    ]
    lines.extend("(allow process-exec (literal " + _quote(path) + "))" for path in sorted(allowed_exec))
    process_roots = {
        str(Path(developer)), str(Path(prepared) / "node_modules"), str(Path(prepared) / "ms-playwright"),
        str(Path(workspace) / "source"), str(Path(scratch)),
    }
    lines.extend("(allow process-exec (subpath " + _quote(path) + "))" for path in sorted(process_roots))
    lines.extend("(allow file-read* (subpath " + _quote(path) + "))" for path in sorted(allowed_reads))
    scratch_writes = {
        str(Path(scratch) / "reports"), str(Path(scratch) / "playwright-results"),
        str(Path(scratch) / "tmp"), str(Path(scratch) / "npm-cache"),
    }
    write_roots = {str(Path(workspace) / "source"), str(Path(home)), *scratch_writes}
    lines.extend((
        "(allow file-read* (literal \"/dev/null\") (literal \"/dev/urandom\") "
        + "(literal \"/dev/random\") (literal \"/dev/zero\"))",
        "(allow file-write* " + " ".join("(subpath " + _quote(path) + ")" for path in sorted(write_roots))
        + " (literal \"/dev/null\") (literal \"/dev/dtracehelper\"))",
        "(allow file-map-executable (subpath " + _quote(Path(prepared) / "node_modules") + ") "
        + "(subpath " + _quote(Path(workspace) / "source") + "))",
        "(allow sysctl-read (sysctl-name \"hw.machine\") (sysctl-name \"hw.ncpu\") (sysctl-name \"kern.ostype\") "
        + "(sysctl-name \"kern.osrelease\") (sysctl-name \"kern.osversion\"))",
    ))
    return "\n".join(lines) + "\n"


def _check_public_control(state, context, profile, control_sha):
    if (context.get("repository") != fetch.REPOSITORY or context.get("repository_id") != fetch.REPOSITORY_ID
            or context.get("server_url") != "https://github.com" or context.get("event") != "workflow_dispatch"
            or context.get("ref") != "refs/heads/main" or context.get("profile") != profile
            or context.get("control_sha") != control_sha or not bundle.GIT_SHA.fullmatch(control_sha)):
        _refuse("dispatch-context-invalid")


def _copy_tree_safe(source, destination):
    source, destination = Path(source), Path(destination)
    if not source.is_dir() or source.is_symlink() or destination.exists() or destination.is_symlink():
        _refuse("prepared-input-invalid")
    root = source.resolve(strict=True)
    destination.mkdir(mode=0o700, parents=True)
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        target_dir = destination / current_path.relative_to(root)
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        kept = []
        for name in directories:
            entry, target = current_path / name, target_dir / name
            if entry.is_symlink():
                link = os.readlink(entry)
                if os.path.isabs(link) or not (entry.parent / link).resolve(strict=True).is_relative_to(root):
                    _refuse("prepared-link-invalid")
                target.symlink_to(link, target_is_directory=True)
            else:
                target.mkdir(mode=0o700, exist_ok=True)
                kept.append(name)
        directories[:] = kept
        for name in files:
            entry, target = current_path / name, target_dir / name
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode):
                link = os.readlink(entry)
                if os.path.isabs(link) or not (entry.parent / link).resolve(strict=True).is_relative_to(root):
                    _refuse("prepared-link-invalid")
                target.symlink_to(link)
            elif stat.S_ISREG(info.st_mode):
                shutil.copyfile(entry, target, follow_symlinks=False)
                os.chmod(target, 0o700 if info.st_mode & 0o111 else 0o600)
            else:
                _refuse("prepared-member-type")


def _chown_tree(root, uid, gid, *, readonly=False):
    base = Path(root)
    for current, directories, files in os.walk(base, topdown=False, followlinks=False):
        for name in files:
            path = Path(current) / name
            info = path.lstat()
            os.chown(path, uid, gid, follow_symlinks=False)
            if not stat.S_ISLNK(info.st_mode):
                os.chmod(path, (0o555 if info.st_mode & 0o111 else 0o444) if readonly
                         else (0o700 if info.st_mode & 0o111 else 0o600))
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink():
                os.chown(path, uid, gid)
                os.chmod(path, 0o555 if readonly else 0o700)
    os.chown(base, uid, gid)
    os.chmod(base, 0o555 if readonly else 0o700)


def _pf_guard_from_file(state, ident):
    record = _read_json(state / PF_STATE_FILE, 8192)
    required = {"schema", "uid", "token", "rules_file", "host_identity", "loaded"}
    if (type(record) is not dict or set(record) != required or record.get("schema") != 1
            or record.get("uid") != ident["uid"] or type(record.get("token")) is not str
            or not record["token"].isdecimal() or type(record.get("loaded")) is not bool):
        _refuse("firewall-unavailable")
    boundary_guard.PF_ANCHOR = ANCHOR_NAME
    host = record["host_identity"]
    identity = boundary_guard.PlatformIdentity(
        product_version=host["product_version"], image_os=host["image_os"],
        runner_image_os=boundary_guard.APPROVED_RUNNER_IMAGE_OS,
        image_version=host["image_version"], architecture=host["architecture"],
    )
    guard = boundary_guard.PFGuard(ident["uid"], record["token"], boundary_guard._rules_for_uid(ident["uid"]),
                                   record["rules_file"], identity)
    guard._load_attempted = record["loaded"]
    return guard, record


def _install_pf(state, ident):
    boundary_guard.PF_ANCHOR = ANCHOR_NAME
    rules_file = MACOS_ROOT_DIRECTORY + "/kd-devlane-pf-" + ident["run_id"] + ".rules"
    prior = {name: os.environ.get(name) for name in ("ImageOS", "ImageVersion")}
    os.environ["ImageOS"] = ident["host_identity"]["image_os"]
    os.environ["ImageVersion"] = ident["host_identity"]["image_version"]
    try:
        guard = boundary_guard.install_pf(ident["uid"], rules_file)
    except boundary_guard.GuardError:
        _refuse("firewall-unavailable")
    finally:
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    record = {
        "schema": 1, "uid": ident["uid"], "token": guard.token,
        "rules_file": str(guard.rules_file), "host_identity": ident["host_identity"], "loaded": True,
    }
    try:
        _write_json(state / PF_STATE_FILE, record, mode=0o600)
        guard.verify()
    except BaseException:
        guard.close()
        raise


def _probe_pf(state, ident):
    script = (
        "import socket\n"
        "tcp_blocked=False\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(0.4)\n"
        "try:\n s.connect(('192.0.2.1',443))\n"
        "except OSError:\n tcp_blocked=True\n"
        "finally:\n s.close()\n"
        "u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        "try:\n u.sendto(b'x',('192.0.2.1',53))\n"
        "except OSError:\n pass\n"
        "finally:\n u.close()\n"
        "print('KD-PF:' + ('pass' if tcp_blocked else 'fail'))\n"
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": ident["home"], "TMPDIR": ident["home"], "LC_ALL": "C", "LANG": "C"}
    code, stdout, stderr = _run((sys.executable, "-I", "-S", "-B", "-c", script),
                                env=env, user=ident["uid"], group=ident["gid"], timeout=10, capture_limit=4096)
    if code != 0 or stderr or stdout != b"KD-PF:pass\n":
        _refuse("firewall-unavailable")
    guard, _ = _pf_guard_from_file(state, ident)
    counters = guard.verify()
    if (counters is None or len(counters) != 4 or counters[0][1] == 0 or counters[1][1] == 0):
        _refuse("firewall-unavailable")


def _directory_service(argv, refusal, *, timeout=10):
    try:
        result = boundary_guard._run_command(argv, timeout=timeout)
    except boundary_guard.GuardError:
        _refuse(refusal)
    if result.returncode != 0 or result.stderr:
        _refuse(refusal)
    return result


def _parse_darwin_uid(value):
    if re.fullmatch(r"-?[0-9]+", value) is None:
        return None
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    if parsed < DARWIN_SIGNED_UID_MIN or parsed > DARWIN_UID_MAX:
        return None
    return parsed, parsed % DARWIN_UID_MODULUS


def _directory_service_uid_inventory(payload):
    try:
        lines = payload.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        _refuse("macos-user-list")
    raw_ids = []
    normalized_ids = set()
    names = set()
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or re.fullmatch(r"[A-Za-z0-9._-]+", fields[0]) is None:
            _refuse("macos-user-list")
        parsed = _parse_darwin_uid(fields[1])
        if parsed is None or fields[0] in names:
            _refuse("macos-user-list")
        names.add(fields[0])
        raw_ids.append(parsed[0])
        normalized_ids.add(parsed[1])
    return names, raw_ids, normalized_ids


def _root_identity(args):
    state, _ = _state_paths(args.state_dir)
    workspace = _safe_path(args.workspace, must_exist=True)
    run_id = args.run_id
    if (os.geteuid() != 0 or not RUN_ID_RE.fullmatch(run_id)
            or workspace.stat().st_uid != int(args.runner_uid) or not 0 < int(args.runner_uid) < 60000):
        _refuse("dispatch-context-invalid")
    prior = {name: os.environ.get(name) for name in ("ImageOS", "ImageVersion")}
    os.environ["ImageOS"] = args.image_os
    os.environ["ImageVersion"] = args.image_version
    try:
        host = boundary_guard.check_platform()
    except boundary_guard.GuardError:
        _refuse("macos-runner-required")
    finally:
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    if (host.image_os != args.image_os or host.image_version != args.image_version
            or host.product_version != args.product_version or host.architecture != args.architecture):
        _refuse("macos-preflight-host-identity")
    runner_uid = int(args.runner_uid)
    node = _trusted_file(args.node, executable=True, owners=(0, runner_uid))
    npm_cli = _trusted_file(args.npm_cli, owners=(0, runner_uid))
    if (not SHA256_RE.fullmatch(args.node_sha256) or not SHA256_RE.fullmatch(args.npm_sha256)
            or args.node_sha256 != _sha256_file(node) or args.npm_sha256 != _sha256_file(npm_cli)):
        _refuse("tool-digest-mismatch")
    version_env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    if (_command_output((str(node), "--version"), env=version_env) != "v24.22.1"
            or _command_output((str(node), str(npm_cli), "--version"), env=version_env) != "11.19.1"):
        _refuse("tool-version-unavailable")
    account = WORKER_NAME_PREFIX + run_id
    listing = _directory_service(("/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"), "macos-user-list")
    names, raw_ids, normalized_ids = _directory_service_uid_inventory(listing.stdout)
    if account in names:
        _refuse("macos-user-name-conflict")
    uid = max((item for item in raw_ids if 500 <= item < 60000), default=500) + 1
    while uid in normalized_ids and uid < 60000:
        uid += 1
    if uid >= 60000:
        _refuse("macos-user-id-exhausted")
    host_identity = {
        "product_version": host.product_version, "image_os": host.image_os,
        "image_version": host.image_version, "architecture": host.architecture,
    }
    home = str(state.parent / "worker-home")
    intent = {
        "schema": 1, "run_id": run_id, "runner_uid": runner_uid,
        "uid": uid, "gid": WORKER_GROUP, "account": account, "home": home,
    }
    try:
        _write_json(state / CLEANUP_INTENT_FILE, intent, mode=0o644)
    except Refusal:
        _refuse("macos-cleanup-intent-write")
    try:
        os.mkdir(home, 0o700)
    except OSError:
        _refuse("macos-worker-home-create")
    _directory_service(("/usr/bin/dscl", ".", "-create", "/Users/" + account), "macos-user-create")
    for key, value in (("UniqueID", str(uid)), ("PrimaryGroupID", str(WORKER_GROUP)),
                       ("NFSHomeDirectory", home), ("UserShell", "/usr/bin/false"),
                       ("RealName", "Private Devlane Worker"), ("IsHidden", "1")):
        _directory_service(("/usr/bin/dscl", ".", "-create", "/Users/" + account, key, value),
                           "macos-user-attribute-set")
    try:
        os.chown(home, uid, WORKER_GROUP)
        os.chmod(home, 0o700)
    except OSError:
        _refuse("macos-worker-home-permissions")
    actual_uid = _directory_service(("/usr/bin/id", "-u", account), "macos-user-verify", timeout=5)
    if actual_uid.stdout != (str(uid) + "\n").encode("ascii"):
        _refuse("macos-user-verify")
    developer, clang = _validate_clt(worker_account=account)
    if developer != args.developer_directory or clang != args.clang:
        _refuse("developer-clang-mismatch")
    try:
        _write_json(state / IDENTITY_FILE, {
            "schema": 1, "run_id": run_id, "runner_uid": runner_uid, "uid": uid,
            "gid": WORKER_GROUP, "account": account, "home": home, "node": args.node, "npm_cli": args.npm_cli,
            "node_sha256": args.node_sha256, "npm_sha256": args.npm_sha256,
            "developer_directory": args.developer_directory, "clang": args.clang,
            "host_identity": host_identity,
        }, mode=0o644)
    except Refusal:
        _refuse("macos-identity-record-write")
    return 0


def _validate_context(path):
    value = _read_json(path, 8192)
    try:
        return fetch.validate_dispatch(value)
    except fetch.Refusal:
        _refuse("dispatch-context-invalid")


def _build_profile(state, ident, context, workspace):
    root = state.parent
    source = root / "workspace" / "source"
    prepared = root / "prepared"
    scratch = root / "scratch"
    control = CONTROL_ROOT
    text = profile_text(
        workspace=root / "workspace", prepared=prepared, scratch=scratch,
        home=Path(ident["home"]), control=control, node=ident["node"],
        developer=ident["developer_directory"], clang=ident["clang"], npm_cli=ident["npm_cli"],
    )
    profile_path = root / SBPL_FILE
    _write_json(state / "profile-integrity.json", {"schema": 1, "sha256": hashlib.sha256(text.encode()).hexdigest()})
    descriptor = os.open(str(profile_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o444)
    with os.fdopen(descriptor, "wb") as output:
        output.write(text.encode("utf-8"))
        output.flush()
        os.fsync(output.fileno())
    os.chmod(profile_path, 0o444)
    state_value = {
        "schema": 1, "profile": context["profile"], "run_id": ident["run_id"],
        "runner_uid": ident["runner_uid"], "worker_uid": ident["uid"], "worker_gid": ident["gid"],
        "node": ident["node"], "npm_cli": ident["npm_cli"], "node_sha256": ident["node_sha256"],
        "npm_sha256": ident["npm_sha256"], "source": str(source), "prepared": str(prepared),
        "scratch": str(scratch), "home": ident["home"], "control": str(control),
        "profile_sha256": hashlib.sha256(text.encode()).hexdigest(), "probe_complete": False,
        "decrypted": False, "execution_complete": False,
        "pf_rules_file": MACOS_ROOT_DIRECTORY + "/kd-devlane-pf-" + ident["run_id"] + ".rules",
    }
    _write_state(state, state_value)
    return state_value


def _validate_profile(state, worker):
    profile = state.parent / SBPL_FILE
    candidate = _trusted_file(profile)
    try:
        metadata = candidate.lstat()
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o444:
            _refuse("profile-config-invalid")
        digest = _sha256_file(candidate, 65536)
    except OSError:
        _refuse("profile-config-invalid")
    if digest != worker["profile_sha256"]:
        _refuse("profile-config-invalid")


def _deny_probe_script():
    return (
        "const fs=require('node:fs');const net=require('node:net');const dgram=require('node:dgram');"
        "const child=require('node:child_process');"
        "const [scratch,outside,fakeUser,fakeKeychain,fakeFolders,detached,rawLog]=process.argv.slice(1);"
        "const result={};const denied=e=>['EACCES','EPERM'].includes(e.code);"
        "try{fs.writeFileSync(scratch+'/reports/vitest.json',JSON.stringify({numPassedTests:1}));"
        "result.inside_write=true;}catch{result.inside_write=false;}"
        "try{result.scratch_report_read=JSON.parse(fs.readFileSync(scratch+'/reports/vitest.json','utf8')).numPassedTests===1;}"
        "catch{result.scratch_report_read=false;}"
        "try{result.raw_log_read=fs.readFileSync(rawLog,'utf8')==='probe-log-readable';}catch{result.raw_log_read=false;}"
        "try{fs.writeFileSync(outside,'no');result.outside_write=false;}catch(e){result.outside_write=denied(e);}"
        "try{fs.readFileSync(outside);result.outside_read=false;}catch(e){result.outside_read=denied(e);}"
        "const deniedRead=p=>{try{const fd=fs.openSync(p,'r');fs.closeSync(fd);return false;}"
        "catch(e){return denied(e);}};"
        "result.other_home_read=deniedRead(fakeUser+'/probe-file');"
        "result.keychain_read=deniedRead(fakeKeychain);"
        "result.private_folders_read=deniedRead(fakeFolders);"
        "const tcp=(host,family)=>new Promise(resolve=>{let done=false;const finish=value=>{if(done)return;done=true;resolve(value);};"
        "const s=net.createConnection({host,port:9,family,timeout:700});"
        "s.on('connect',()=>{s.destroy();finish(false);});s.on('timeout',()=>{s.destroy();finish(false);});"
        "s.on('error',e=>finish(denied(e)));});"
        "const udp=(kind,address)=>new Promise(resolve=>{let done=false;const finish=value=>{if(done)return;done=true;"
        "try{s.close();}catch{}resolve(value);};const s=dgram.createSocket(kind);s.on('error',e=>finish(denied(e)));"
        "s.send(Buffer.from('probe'),9,address,e=>finish(e?denied(e):false));"
        "setTimeout(()=>finish(false),700);});"
        "try{child.spawn(process.execPath,['-e',\"setTimeout(()=>require('node:fs').writeFileSync(process.argv[1],'alive'),1200)\",detached],"
        "{detached:true,stdio:'ignore'}).unref();result.detached_spawned=true;}catch{result.detached_spawned=false;}"
        "Promise.all([tcp('192.0.2.1',4),tcp('2001:db8::1',6),tcp('127.0.0.1',4),"
        "udp('udp4','192.0.2.1'),udp('udp6','2001:db8::1')]).then(values=>{"
        "[result.ipv4_network,result.ipv6_network,result.loopback_network,result.udp4_network,result.udp6_network]=values;"
        "process.stdout.write('KD-SBPL:'+JSON.stringify(result)+'\\n');});"
    )


def _deny_probe(state, worker, ident):
    root = state.parent
    path = root / SBPL_FILE
    fake_user = chr(47) + "Users" + chr(47) + "devlane-probe-" + ident["run_id"]
    fake_keychain = fake_user + "/Library/Keychains/devlane-probe-" + ident["run_id"] + ".keychain-db"
    fake_folders = (chr(47) + "private" + chr(47) + "var" + chr(47) + "folders/devlane-probe-"
                    + ident["run_id"] + "/T/probe-file")
    outside_dir = root / "outside-canary-dir"
    outside = outside_dir / "outside-canary"
    detached = Path(worker["scratch"]) / "detached-probe-marker"
    raw_canary = Path(worker["scratch"]) / "raw" / "probe.log"
    if any(item.exists() or item.is_symlink() for item in (outside_dir, detached, raw_canary)):
        _refuse("positive-control-failed")
    outside_dir.mkdir(mode=0o700)
    outside.write_bytes(b"outside-canary")
    raw_canary.write_bytes(b"probe-log-readable")
    os.chown(outside_dir, worker["worker_uid"], worker["worker_gid"])
    os.chown(outside, worker["worker_uid"], worker["worker_gid"])
    os.chmod(outside_dir, 0o700)
    os.chmod(outside, 0o600)
    os.chmod(raw_canary, 0o444)
    script = _deny_probe_script()
    command = ("/usr/bin/sandbox-exec", "-f", str(path), worker["node"], "-e", script,
               worker["scratch"], str(outside), fake_user, fake_keychain, fake_folders,
               str(detached), str(raw_canary))
    code, stdout, stderr = _run(
        command, env={"PATH": "/usr/bin:/bin", "HOME": ident["home"], "TMPDIR": worker["scratch"], "LC_ALL": "C"},
        user=worker["worker_uid"], group=worker["worker_gid"], timeout=20, capture_limit=4096,
    )
    _terminate_worker_processes(worker["worker_uid"])
    time.sleep(1.3)
    try:
        row = [line[len(b"KD-SBPL:"):] for line in stdout.splitlines() if line.startswith(b"KD-SBPL:")]
        result = json.loads(row[0].decode("ascii")) if len(row) == 1 else None
    except (ValueError, UnicodeDecodeError):
        result = None
    unchanged = False
    try:
        unchanged = outside.read_bytes() == b"outside-canary"
        outside.unlink()
        outside_dir.rmdir()
        raw_canary.unlink()
        (Path(worker["scratch"]) / "reports" / "vitest.json").unlink(missing_ok=True)
    except OSError:
        _refuse("positive-control-failed")
    expected = {
        "inside_write": True, "scratch_report_read": True, "raw_log_read": True,
        "outside_write": True, "outside_read": True, "other_home_read": True,
        "keychain_read": True, "private_folders_read": True, "ipv4_network": True,
        "ipv6_network": True, "loopback_network": True, "udp4_network": True,
        "udp6_network": True, "detached_spawned": True,
    }
    if code != 0 or stderr or not unchanged or result != expected or detached.exists() or outside.exists():
        _refuse("positive-control-failed")



def _start(state, context_path, workspace, prepared_path, bundle_path, projection_path, positive_path,
           deadline_file, run_id):
    if os.geteuid() != 0:
        _refuse("macos-root-required")
    ident = _identity(state)
    context = _validate_context(context_path)
    _check_public_control(state, context, context["profile"], context["control_sha"])
    if (ident["run_id"] != run_id or context["profile"] != PROFILE_NAME
            or context["bundle_sha256"] != _sha256_file(bundle_path, bundle.MAX_CIPHERTEXT)):
        _refuse("dispatch-context-invalid")
    projection = _validate_projection_file(projection_path, context["profile"], context["control_sha"])
    if (projection.get("tools") != {"node": "24.22.1", "npm": "11.19.1"}
            or _read_json(positive_path, 1024) != {"connected": True, "target": "public-tls-control"}):
        _refuse("positive-control-failed")
    if (ident["node_sha256"] != _sha256_file(ident["node"])
            or ident["npm_sha256"] != _sha256_file(ident["npm_cli"])):
        _refuse("tool-version-mismatch")
    profile_doc = _read_json(CONTROL_ROOT / PROFILE_FILE, 1024 * 1024)
    profile = profile_doc.get("profiles", {}).get(PROFILE_NAME)
    if type(profile) is not dict or profile.get("revision") != 1:
        _refuse("profile-config-invalid")
    root = state.parent
    prepared = _safe_path(prepared_path, must_exist=True)
    if prepared != root / "prepared" or not (prepared / "node_modules").is_dir():
        _refuse("prepared-input-invalid")
    (root / "workspace").mkdir(mode=0o700)
    (root / "scratch").mkdir(mode=0o700)
    for name in ("reports", "raw", "playwright-results", "tmp", "npm-cache"):
        (root / "scratch" / name).mkdir(mode=0o700)
    (root / "scratch" / "tmp" / "vitest-cache").mkdir(mode=0o700)
    _chown_tree(root / "workspace", ident["uid"], ident["gid"])
    _chown_tree(root / "scratch", ident["uid"], ident["gid"])
    os.chown(root / "scratch", 0, 0)
    os.chmod(root / "scratch", 0o755)
    raw_directory = root / "scratch" / "raw"
    os.chown(raw_directory, 0, 0)
    os.chmod(raw_directory, 0o755)
    _install_pf(state, ident)
    state_value = _build_profile(state, ident, context, workspace)
    state_value["pf_rules_file"] = _read_json(state / PF_STATE_FILE, 8192)["rules_file"]
    _write_state(state, state_value)
    print("offline_supervisor=ready")


def _probe(state):
    if os.geteuid() != 0:
        _refuse("macos-root-required")
    ident = _identity(state)
    worker = _worker_state(state)
    if worker["probe_complete"] or worker["decrypted"]:
        _refuse("probe-replay")
    _probe_pf(state, ident)
    _validate_profile(state, worker)
    _deny_probe(state, worker, ident)
    worker["probe_complete"] = True
    _write_state(state, worker)
    print("network_cut_probe=pass")


def _expected_envelope(context):
    return {
        "format": "kd-public-devlane-aesgcm-v2", "repository_id": context["repository_id"],
        "control_sha": context["control_sha"], "workflow_path": fetch.WORKFLOW_PATH,
        "platform": context["platform"], "profile": context["profile"],
        "wave_id": context["wave_id"], "bundle_id": context["bundle_id"],
        "fetch_sha256": context["projection_sha256"], "expires": context["expires"],
    }


def _public_decrypt_refusal(error):
    code = str(error) if isinstance(error, bundle.Refusal) else ""
    if code == "authentication-failed":
        return "auth-tag"
    if code == "key-invalid":
        return "key-format"
    if code == "request-expired":
        return "expired"
    if code in ("envelope-truncated", "decrypt-input"):
        return "truncated"
    if code == "crypto-unavailable":
        return "crypto-unavailable"
    if code in ("binding-mismatch", "inner-binding-mismatch") or code.startswith("binding-"):
        return "binding-mismatch"
    if code == "ciphertext-size":
        return "invalid-envelope"
    if code == "decrypt-request" or code.startswith("json-"):
        return "request-invalid"
    return "archive-invalid"


def _decrypt(state, context_path, bundle_path, projection_path, deadline_file):
    if os.geteuid() != 0:
        _refuse("macos-root-required")
    ident = _identity(state)
    worker = _worker_state(state)
    if not worker["probe_complete"] or worker["decrypted"] or worker["execution_complete"]:
        _refuse("decrypt-order")
    context = _validate_context(context_path)
    _check_public_control(state, context, context["profile"], context["control_sha"])
    _probe_pf(state, ident)
    _terminate_worker_processes(ident["uid"])
    key_hex = os.environ.get("DEVLANE_DECRYPT_KEY", "")
    if re.fullmatch(r"[a-f0-9]{64}", key_hex) is None:
        _refuse("decrypt-rejected", decrypt_refusal="key-format")
    if _sha256_file(bundle_path, bundle.MAX_CIPHERTEXT) != context["bundle_sha256"]:
        _refuse("bundle-binding-mismatch")
    projection = _validate_projection_file(projection_path, context["profile"], context["control_sha"])
    key = bytearray.fromhex(key_hex)
    key_hex = ""
    os.environ.pop("DEVLANE_DECRYPT_KEY", None)
    try:
        deadline_budget.remaining(deadline_file)
        envelope = Path(bundle_path).read_bytes()
        archive = bundle.parse_envelope(envelope, bytes(key), _expected_envelope(context))
        envelope = b""
        source = Path(worker["source"])
        source.mkdir(mode=0o700, parents=False, exist_ok=False)
        manifest = bundle.extract_authenticated_archive(archive, source, _expected_envelope(context))
        archive = b""
    except deadline_budget.DeadlineRefusal:
        _refuse("decrypt-timeout", decrypt_refusal="decrypt-timeout")
    except (OSError, bundle.Refusal) as error:
        _refuse("decrypt-rejected", decrypt_refusal=_public_decrypt_refusal(error))
    finally:
        for index in range(len(key)):
            key[index] = 0
    if ("package-lock.json" not in manifest["original_lockfiles"] or "package.json" not in manifest["files"]):
        _refuse("decrypt-rejected", decrypt_refusal="archive-invalid")
    try:
        package_path = source / "package.json"
        lock_path = source / "package-lock.json"
        fetch.validate_npm_manifest_binding(package_path.read_bytes(), projection["npm_package"])
        package, lock, _ = fetch.project_npm_lock(lock_path.read_bytes())
    except (OSError, fetch.Refusal):
        _refuse("decrypt-rejected", decrypt_refusal="binding-mismatch")
    if package != projection["npm_package"] or lock != projection["npm_lock"]:
        _refuse("decrypt-rejected", decrypt_refusal="binding-mismatch")
    _copy_tree_safe(Path(worker["prepared"]) / "node_modules", source / "node_modules")
    trusted = state.parent / "trusted"
    trusted.mkdir(mode=0o700)
    _write_json(trusted / "manifest.json", manifest, mode=0o444)
    adapter = {"tests": [[name, identifier] for name, identifier in sorted(manifest["allowed_tests"].items())],
               "frames": [[name, identifier] for name, identifier in sorted(manifest["frames"].items())]}
    _write_json(trusted / "adapter-config.json", adapter, mode=0o444)
    _chown_tree(source, ident["uid"], ident["gid"])
    _chown_tree(trusted, ident["uid"], ident["gid"], readonly=True)
    worker["decrypted"] = True
    _write_state(state, worker)
    print("authenticated_decryption=pass")


def _mapped_command(command, worker):
    mapping = {
        "/workspace/source": worker["source"], "/prepared": worker["prepared"],
        "/scratch": worker["scratch"], "/trusted": str(Path(worker["source"]).parents[1] / "trusted"),
    }
    result = []
    for item in command:
        if type(item) is not str:
            _refuse("profile-command-invalid")
        value = item
        for old, new in mapping.items():
            offset = value.find(old)
            if offset >= 0 and (offset == 0 or value[offset - 1] == "="):
                suffix = value[offset + len(old):]
                if not suffix or suffix.startswith("/"):
                    value = value[:offset] + new + suffix
                    break
        result.append(value)
    return result


def _worker_env(worker, ident):
    return {
        "PATH": str(Path(worker["node"]).parent) + ":" + CLT_BIN_DIRECTORY + ":/usr/bin:/bin",
        "DEVELOPER_DIR": CLT_DEVELOPER_DIRECTORY,
        "HOME": worker["home"], "TMPDIR": str(Path(worker["scratch"]) / "tmp"),
        "CI": "1", "LC_ALL": "C", "LANG": "C", "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_AUDIT": "false", "NPM_CONFIG_FUND": "false", "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "NPM_CONFIG_CACHE": str(Path(worker["scratch"]) / "npm-cache"),
        "PLAYWRIGHT_BROWSERS_PATH": str(Path(worker["prepared"]) / "ms-playwright"),
        "XDG_CACHE_HOME": str(Path(worker["scratch"]) / "tmp" / "xdg-cache"),
    }


def _capture_command(argv, *, worker, ident, stage, timeout):
    scratch = Path(worker["scratch"])
    raw_directory = scratch / "raw"
    target_name = stage + ".log"
    if Path(target_name).name != target_name:
        _refuse("report-file-exists")
    env = _worker_env(worker, ident)
    if argv and argv[0] == "npm":
        argv = [worker["node"], worker["npm_cli"], *argv[1:]]
    command = ["/usr/bin/sandbox-exec", "-f", str(state_path(worker).parent / SBPL_FILE), *argv]
    directory_descriptor = descriptor = None
    try:
        directory_descriptor = os.open(
            str(raw_directory), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_metadata = os.fstat(directory_descriptor)
        if (not stat.S_ISDIR(directory_metadata.st_mode) or directory_metadata.st_uid != 0
                or directory_metadata.st_mode & 0o022):
            _refuse("report-file-invalid")
        descriptor = os.open(
            target_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600, dir_fd=directory_descriptor,
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                       cwd=str(Path(worker["source"])), env=env, close_fds=True,
                                       start_new_session=True, user=worker["worker_uid"],
                                       group=worker["worker_gid"], extra_groups=(),
                                       preexec_fn=_worker_limits)
            process.wait(timeout=timeout)
            _stop_process_group(process.pid)
            _terminate_worker_processes(worker["worker_uid"])
            if os.fstat(output.fileno()).st_size > MAX_LOG_BYTES:
                return 125
            _finalize_capture_log(output.fileno(), worker["worker_uid"], worker["worker_gid"])
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            _stop_process_group(process.pid)
        except Refusal:
            return 125
        _terminate_worker_processes(worker["worker_uid"])
        return 124
    except Refusal:
        return 125
    except (OSError, subprocess.SubprocessError, TypeError):
        return 125
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    return process.returncode


def _finalize_capture_log(descriptor, uid, gid):
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        _refuse("report-file-invalid")
    os.fchown(descriptor, uid, gid)
    os.fchmod(descriptor, 0o444)


def _worker_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG_BYTES, MAX_LOG_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))
    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
    os.umask(0o077)


def _stop_process_group(process_group):
    for signum, seconds in ((signal.SIGTERM, 1), (signal.SIGKILL, 2)):
        try:
            os.killpg(process_group, signum)
        except ProcessLookupError:
            return
        except OSError:
            _refuse("process-cleanup-incomplete")
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                os.killpg(process_group, 0)
            except (ProcessLookupError, PermissionError):
                break
            time.sleep(0.05)
    try:
        os.killpg(process_group, 0)
    except (ProcessLookupError, PermissionError):
        return
    _refuse("process-cleanup-incomplete")


def _worker_process_ids(uid):
    code, stdout, stderr = _run(
        ("/bin/ps", "-axo", "uid=,pid="),
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/var/empty"},
        timeout=10, capture_limit=MAX_OUTPUT_BYTES,
    )
    if code != 0 or stderr:
        _refuse("cleanup-process-inventory")
    try:
        rows = [line.split() for line in stdout.decode("ascii", "strict").splitlines() if line.strip()]
        if any(len(row) != 2 or not row[0].isdecimal() or not row[1].isdecimal() for row in rows):
            _refuse("cleanup-process-inventory")
        return [int(row[1]) for row in rows if int(row[0]) == uid]
    except UnicodeDecodeError:
        _refuse("cleanup-process-inventory")


def _terminate_worker_processes(uid):
    if type(uid) is not int or not 1 <= uid < 60000:
        _refuse("cleanup-process-inventory")
    for _attempt in range(3):
        if not _worker_process_ids(uid):
            return
        for signame in ("TERM", "KILL"):
            result = _run(
                ("/usr/bin/pkill", "-" + signame, "-U", str(uid)),
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/var/empty"},
                timeout=10, capture_limit=4096,
            )
            if result[0] not in (0, 1) or result[2]:
                _refuse("cleanup-process-termination")
            deadline = time.monotonic() + (1.5 if signame == "TERM" else 2.0)
            while time.monotonic() < deadline:
                if not _worker_process_ids(uid):
                    return
                time.sleep(0.05)
    if _worker_process_ids(uid):
        _refuse("cleanup-process-incomplete")


def state_path(worker):
    source = Path(worker["source"])
    return source.parents[1] / "state"


def _run_adapter(command, worker, ident, stage):
    return _capture_command(command, worker=worker, ident=ident, stage=stage, timeout=60)


def _read_jsonl(path, maximum=output_filter.MAX_RAW_CAPTURE_BYTES):
    target = Path(path)
    try:
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            _refuse("report-file-invalid")
        payload = target.read_bytes()
        if payload and not payload.endswith(b"\n"):
            _refuse("report-file-incomplete")
        lines = payload.splitlines()
        if len(lines) > output_filter.MAX_RECORDS:
            _refuse("record-count")
        return lines
    except OSError:
        _refuse("report-file-unavailable")


def _filter_summary(records, allowlists, required_frames=()):
    serialized = []
    for record in records:
        if type(record) is bytes:
            serialized.append(record)
        elif type(record) is dict:
            serialized.append(bundle.canonical_json(record))
        else:
            _refuse("summary-record-invalid")
    summary = output_filter.filter_records(serialized, allowlists, required_frames)
    output_filter.validate_public_summary(summary, allowlists, required_frames)
    return summary


def _execute(state, context_path, deadline_file):
    if os.geteuid() != 0:
        _refuse("macos-root-required")
    ident = _identity(state)
    worker = _worker_state(state)
    if not worker["probe_complete"] or not worker["decrypted"] or worker["execution_complete"]:
        _refuse("execution-order")
    context = _validate_context(context_path)
    if context["profile"] != PROFILE_NAME:
        _refuse("profile-unknown")
    _validate_profile(state, worker)
    _probe_pf(state, ident)
    if (ident["node_sha256"] != _sha256_file(worker["node"])
            or ident["npm_sha256"] != _sha256_file(worker["npm_cli"])):
        _refuse("tool-version-mismatch")
    profile_doc = _read_json(CONTROL_ROOT / PROFILE_FILE, 1024 * 1024)
    profile = profile_doc["profiles"][PROFILE_NAME]
    manifest = _read_json(Path(worker["source"]).parents[1] / "trusted" / "manifest.json", 4 * 1024 * 1024)
    outcomes = []
    for stage, command in zip(profile["stages"], profile["commands"]):
        try:
            timeout = min(1200, int(deadline_budget.remaining(deadline_file)))
        except deadline_budget.DeadlineRefusal:
            outcomes.append((stage, 124))
            continue
        outcomes.append((stage, _capture_command(_mapped_command(command, worker), worker=worker,
                                                  ident=ident, stage=stage, timeout=timeout)))
    scratch = Path(worker["scratch"])
    reports = scratch / "reports"
    if manifest["frames"]:
        try:
            browser_timeout = min(1200, int(deadline_budget.remaining(deadline_file)))
        except deadline_budget.DeadlineRefusal:
            browser_timeout = 0
        browser_code = 124 if browser_timeout <= 0 else _capture_command(
            _mapped_command(profile["browser_command"], worker), worker=worker, ident=ident,
            stage="browser", timeout=browser_timeout,
        )
        outcomes.append(("browser", browser_code))
    else:
        browser_code = 0
    reporter = CONTROL_ROOT / "kit" / "devlane" / "typescript_reporter.mjs"
    type_script = [worker["node"], str(reporter), worker["source"],
                   str(Path(worker["source"]).parents[1] / "trusted" / "manifest.json"),
                   str(reports / "typescript.jsonl"),
                   str(Path(worker["prepared"]) / "node_modules" / "typescript" / "lib" / "typescript.js"),
                   str(Path(worker["prepared"]) / "node_modules")]
    type_result = _run_adapter(type_script, worker, ident, "typescript-adapter")
    adapter_config = Path(worker["source"]).parents[1] / "trusted" / "adapter-config.json"
    test_adapter = CONTROL_ROOT / "kit" / "devlane" / "test_adapters.mjs"
    unit_result = 0
    vitest = reports / "vitest.json"
    adapter_output = reports / "adapter.jsonl"
    if vitest.exists():
        unit_command = [worker["node"], str(test_adapter), "vitest", str(vitest), str(adapter_output), str(adapter_config)]
        unit_result = _run_adapter(unit_command, worker, ident, "unit-adapter")
    browser_output = reports / "playwright.jsonl"
    browser_adapter_result = 0
    if manifest["frames"]:
        browser_command = [worker["node"], str(test_adapter), "playwright",
                           str(scratch / "raw" / "browser.log"), str(browser_output), str(adapter_config)]
        browser_adapter_result = _run_adapter(browser_command, worker, ident, "browser-adapter")
    records = []
    if type_result == 0 and (reports / "typescript.jsonl").exists():
        records.extend(_read_jsonl(reports / "typescript.jsonl"))
    else:
        records.append({"kind": "control", "stage": "typecheck", "status": "fail", "code": "DEVLANE_FAILURE"})
    if vitest.exists() and adapter_output.exists():
        unit_records = _read_jsonl(adapter_output)
        records.extend(bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES) for line in unit_records)
        if unit_result != 0 and not any(b'"kind":"control"' in line for line in unit_records):
            records.append({"kind": "control", "stage": "unit", "status": "fail", "subreason": "vitest-failed"})
    else:
        records.append({"kind": "control", "stage": "unit", "status": "fail", "subreason": "report-missing"})
    if manifest["frames"]:
        if browser_output.exists():
            records.extend(bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES
                                               ) for line in _read_jsonl(browser_output))
        else:
            records.append({"kind": "control", "stage": "browser", "status": "fail", "code": "DEVLANE_FAILURE"})
        if browser_adapter_result not in (0, 1):
            records.append({"kind": "control", "stage": "browser", "status": "fail", "code": "DEVLANE_FAILURE"})
    for stage, code in outcomes:
        if code != 0 and not (stage == "unit" and unit_result in (0, 1)):
            records.append({"kind": "control", "stage": stage, "status": "fail", "code": "DEVLANE_FAILURE"})
    source = Path(worker["source"])
    try:
        allowlists = linux_supervisor._manifest_allowlists(manifest, profile, source)
        summary = _filter_summary(records, allowlists, manifest["frames"].values())
    except Exception:
        fallback = [{"kind": "control", "stage": "unit", "status": "fail", "subreason": "filter-refused"}]
        fallback_allowlists = {
            "files": {}, "tests": {}, "frames": {}, "stages": profile["stages"],
            "codes": ["DEVLANE_FAILURE"], "suites": [], "max_lines": {},
        }
        try:
            summary = _filter_summary(fallback, fallback_allowlists)
        except Exception:
            _refuse("summary-response-invalid")
        outcomes.append(("filter", 1))
    worker["execution_complete"] = True
    _write_state(state, worker)
    sys.stdout.buffer.write(summary)
    sys.stdout.buffer.flush()
    failed = any(code != 0 for _, code in outcomes) or unit_result not in (0, 1) or any(
        item.get("status") == "fail" or item.get("level") == "error"
        for item in (bundle.strict_json(line, output_filter.MAX_RAW_RECORD_BYTES) for line in summary.splitlines())
    )
    return 1 if failed else 0


def _clean_tree(root):
    base = Path(root)
    if not base.exists() and not base.is_symlink():
        return
    if base.is_symlink() or not base.is_dir():
        _refuse("cleanup-root-invalid")
    for current, directories, files in os.walk(base, topdown=False, followlinks=False):
        for name in files:
            path = Path(current) / name
            try:
                info = path.lstat()
                if stat.S_ISREG(info.st_mode):
                    with path.open("r+b", buffering=0) as output:
                        remaining = info.st_size
                        block = bytes(min(65536, remaining))
                        while remaining:
                            count = min(len(block), remaining)
                            output.write(block[:count])
                            remaining -= count
                        output.flush()
                        os.fsync(output.fileno())
                path.unlink()
            except OSError:
                _refuse("cleanup-incomplete")
        for name in directories:
            path = Path(current) / name
            try:
                if path.is_symlink():
                    path.unlink()
                else:
                    path.rmdir()
            except OSError:
                _refuse("cleanup-incomplete")
    try:
        base.rmdir()
    except OSError:
        _refuse("cleanup-incomplete")



def _directory_users():
    result = boundary_guard._run_command(("/usr/bin/dscl", ".", "-list", "/Users"), timeout=10)
    if result.returncode != 0 or result.stderr:
        _refuse("cleanup-incomplete")
    try:
        names = result.stdout.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        _refuse("cleanup-incomplete")
    if any(not name or any(character.isspace() for character in name) for name in names):
        _refuse("cleanup-incomplete")
    return set(names)


def _worker_account_attributes(account):
    result = boundary_guard._run_command(
        ("/usr/bin/dscl", ".", "-read", "/Users/" + account,
         "UniqueID", "PrimaryGroupID", "NFSHomeDirectory"), timeout=5,
    )
    if result.returncode != 0 or result.stderr:
        _refuse("cleanup-incomplete")
    attributes = {}
    try:
        for line in result.stdout.decode("ascii", "strict").splitlines():
            if not line:
                continue
            key, separator, value = line.partition(": ")
            if not separator or key not in ("UniqueID", "PrimaryGroupID", "NFSHomeDirectory") or key in attributes:
                _refuse("cleanup-incomplete")
            attributes[key] = value
    except UnicodeDecodeError:
        _refuse("cleanup-incomplete")
    return attributes


def _delete_worker_account(intent):
    names = _directory_users()
    account = intent["account"]
    if account not in names:
        return
    attributes = _worker_account_attributes(account)
    for name, expected in (("UniqueID", str(intent["uid"])),
                           ("PrimaryGroupID", str(intent["gid"])),
                           ("NFSHomeDirectory", intent["home"])):
        if name in attributes and attributes[name] != expected:
            _refuse("cleanup-incomplete")
    deleted = boundary_guard._run_command(("/usr/bin/dscl", ".", "-delete", "/Users/" + account), timeout=10)
    if deleted.returncode != 0 or deleted.stderr:
        _refuse("cleanup-incomplete")
    if account in _directory_users():
        _refuse("cleanup-incomplete")


def _root_cleanup(state_dir, root_dir, runner_temp, workspace, run_id):
    if os.geteuid() != 0:
        _refuse("macos-root-required")
    root = _safe_path(root_dir)
    requested_state = _safe_path(state_dir)
    temp = _safe_path(runner_temp, must_exist=True)
    workspace = _safe_path(workspace, must_exist=True)
    workspace_uid = workspace.stat().st_uid
    if (not RUN_ID_RE.fullmatch(run_id) or root.parent != temp or root.name != "devlane-" + run_id
            or requested_state != root / "state" or not 0 < workspace_uid < 60000):
        _refuse("cleanup-root-invalid")
    state = root / "state"
    if state.is_symlink() or state.exists() and not state.is_dir():
        _refuse("cleanup-root-invalid")
    errors = []
    intent = None
    identity = None
    intent_path = state / CLEANUP_INTENT_FILE
    identity_path = state / IDENTITY_FILE
    if intent_path.is_file() and not intent_path.is_symlink():
        intent = _cleanup_intent(state)
    if identity_path.is_file() and not identity_path.is_symlink():
        try:
            identity = _identity(state)
        except Refusal:
            if intent is None:
                raise
        if identity is not None:
            identity_intent = {
                "schema": 1, "run_id": identity["run_id"], "runner_uid": identity["runner_uid"],
                "uid": identity["uid"], "gid": identity["gid"], "account": identity["account"],
                "home": identity["home"],
            }
            if intent is not None and intent != identity_intent:
                _refuse("cleanup-intent-invalid")
            intent = identity_intent
    if intent is not None and intent["run_id"] != run_id:
        _refuse("cleanup-intent-invalid")
    if intent is None:
        account = WORKER_NAME_PREFIX + run_id
        if account in _directory_users():
            errors.append("cleanup-intent-missing")
    workers_gone = True
    if intent is not None:
        try:
            _terminate_worker_processes(intent["uid"])
        except Refusal:
            workers_gone = False
            errors.append("worker-processes")
    pf_path = state / PF_STATE_FILE
    if pf_path.is_file() and not pf_path.is_symlink():
        if workers_gone and identity is not None:
            try:
                guard, record = _pf_guard_from_file(state, identity)
                guard.close()
                Path(record["rules_file"]).unlink(missing_ok=True)
                pf_path.unlink(missing_ok=True)
            except Exception:
                errors.append("firewall")
        else:
            errors.append("firewall")
    if intent is not None and workers_gone:
        try:
            _delete_worker_account(intent)
        except Exception:
            errors.append("account")
    elif intent is not None:
        errors.append("account")
    if workers_gone:
        try:
            _clean_tree(root)
        except Exception:
            errors.append("tree")
    else:
        errors.append("tree")
    if root.exists() or root.is_symlink():
        errors.append("tree-remains")
    if intent is not None:
        try:
            if intent["account"] in _directory_users():
                errors.append("account-remains")
        except Exception:
            errors.append("account-check")
        try:
            if _worker_process_ids(intent["uid"]):
                errors.append("worker-processes-remain")
        except Exception:
            errors.append("worker-process-check")
    if errors:
        _refuse("cleanup-incomplete")
    print("cleanup_receipt=confirmed")
    return 0


def _root_pf_cleanup(args):
    state, _ = _state_paths(args.state_dir)
    ident = _identity(state)
    guard, record = _pf_guard_from_file(state, ident)
    guard.close()
    Path(record["rules_file"]).unlink(missing_ok=True)
    (state / PF_STATE_FILE).unlink(missing_ok=True)
    return 0


def _argument_parser():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="operation", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--state-dir", required=True)
    preflight.add_argument("--workspace", required=True)
    preflight.add_argument("--profile", required=True)
    preflight.add_argument("--run-id", required=True)
    preflight.add_argument("--control-sha", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--state-dir", required=True)
    prepare.add_argument("--projection", required=True)
    prepare.add_argument("--output", required=True)
    prepare.add_argument("--profile", required=True)
    prepare.add_argument("--control-sha", required=True)
    prepare.add_argument("--deadline-file", required=True)
    start = commands.add_parser("start")
    for name in ("state-dir", "context", "workspace", "prepared", "bundle", "projection", "positive-control", "deadline-file", "run-id"):
        start.add_argument("--" + name, required=True)
    probe = commands.add_parser("probe")
    probe.add_argument("--state-dir", required=True)
    decrypt = commands.add_parser("decrypt")
    for name in ("state-dir", "context", "bundle", "projection", "deadline-file"):
        decrypt.add_argument("--" + name, required=True)
    execute = commands.add_parser("execute")
    execute.add_argument("--state-dir", required=True)
    execute.add_argument("--context", required=True)
    execute.add_argument("--deadline-file", required=True)
    cleanup = commands.add_parser("cleanup")
    for name in ("state-dir", "root", "runner-temp", "workspace", "run-id"):
        cleanup.add_argument("--" + name, required=True)
    helper = commands.add_parser("root-identity")
    for name in ("state-dir", "workspace", "run-id", "runner-uid", "node", "npm-cli", "node-sha256", "npm-sha256",
                 "developer-directory", "clang", "image-os", "image-version", "product-version", "architecture"):
        helper.add_argument("--" + name, required=True)
    pf_cleanup = commands.add_parser("root-pf-cleanup")
    pf_cleanup.add_argument("--state-dir", required=True)
    return parser


def main(argv=None):
    args = _argument_parser().parse_args(argv)
    try:
        if args.operation == "preflight":
            state, _ = _state_paths(args.state_dir)
            host = boundary_guard.check_platform()
            if (os.environ.get("CI_REPOSITORY") != fetch.REPOSITORY
                    or os.environ.get("CI_EVENT_NAME") != "workflow_dispatch"
                    or os.environ.get("CI_REF") != "refs/heads/main"
                    or os.environ.get("CI_SHA") != args.control_sha):
                _refuse("dispatch-context-invalid")
            _host_preflight(state, args.workspace, args.profile, args.run_id)
            return 0
        if args.operation == "root-identity":
            args.run_id = args.run_id
            args.runner_uid = args.runner_uid
            args.product_version = args.product_version
            args.image_os = args.image_os
            args.image_version = args.image_version
            args.architecture = args.architecture
            args.node = args.node
            args.npm_cli = args.npm_cli
            args.node_sha256 = args.node_sha256
            args.npm_sha256 = args.npm_sha256
            args.developer_directory = args.developer_directory
            args.clang = args.clang
            return _root_identity(args)
        if args.operation == "cleanup":
            return _root_cleanup(args.state_dir, args.root, args.runner_temp, args.workspace, args.run_id)
        state, _ = _state_paths(args.state_dir)
        if args.operation == "prepare":
            _prepare(state, args.projection, args.output, args.profile, args.control_sha, args.deadline_file)
            return 0
        if args.operation == "start":
            boundary_guard._check_trusted_system_file(boundary_guard.SANDBOX_EXEC_PATH, executable=True)
            _start(state, args.context, args.workspace, args.prepared, args.bundle, args.projection,
                   args.positive_control, args.deadline_file, args.run_id)
            return 0
        if args.operation == "probe":
            _probe(state)
            return 0
        if args.operation == "decrypt":
            try:
                return _decrypt(state, args.context, args.bundle, args.projection, args.deadline_file)
            finally:
                os.environ.pop("DEVLANE_DECRYPT_KEY", None)
        if args.operation == "execute":
            return _execute(state, args.context, args.deadline_file)
        if args.operation == "root-pf-cleanup":
            return _root_pf_cleanup(args)
        _refuse("control-operation-invalid")
    except Refusal as error:
        if args.operation == "root-identity":
            code = error.code if error.code in MACOS_ROOT_IDENTITY_REFUSAL_CODES else "macos-root-identity-internal"
            print("devlane_macos_root_refusal=" + code, file=sys.stderr)
            return 2
        if args.operation == "preflight":
            code = error.code if error.code in MACOS_PREFLIGHT_REFUSAL_CODES else "macos-preflight-internal"
            print("devlane_macos_preflight_refusal=" + code, file=sys.stderr)
            return 2
        if args.operation == "decrypt":
            print("devlane_supervisor_refusal=" + error.code, file=sys.stderr)
            if error.decrypt_refusal in DECRYPT_REFUSAL_CODES:
                print("decrypt_refusal=" + error.decrypt_refusal, file=sys.stderr)
        else:
            print("devlane_supervisor_refusal=supervisor-failed", file=sys.stderr)
        return 2
    except boundary_guard.GuardError as error:
        if args.operation == "preflight":
            code = ("macos-runner-required" if error.reason == "platform_unapproved"
                    else "macos-preflight-platform-policy")
            print("devlane_macos_preflight_refusal=" + code, file=sys.stderr)
            return 2
        if args.operation == "root-identity":
            print("devlane_macos_root_refusal=macos-root-identity-internal", file=sys.stderr)
            return 2
        print("devlane_supervisor_refusal=supervisor-failed", file=sys.stderr)
        return 2
    except Exception:
        if args.operation == "root-identity":
            print("devlane_macos_root_refusal=macos-root-identity-internal", file=sys.stderr)
            return 2
        if args.operation == "preflight":
            print("devlane_macos_preflight_refusal=macos-preflight-internal", file=sys.stderr)
            return 2
        print("devlane_supervisor_refusal=supervisor-failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
