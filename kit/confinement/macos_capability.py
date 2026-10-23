import argparse
import ctypes
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time


CONTROL_SHA = re.compile(r"[a-f0-9]{40}\Z")
USERNAME = "ci-sandbox-probe"
APP_IDENTIFIER = "org.example.sandboxcapability"
CHILD_IDENTIFIER = APP_IDENTIFIER + ".CapabilityChild"
MAX_CAPTURE_BYTES = 65536
MAX_PROBE_SECONDS = 45
MAX_RUNNER_ANCESTORS = 16
MAX_PROCESS_PATH_BYTES = 4096
LSOF_NON_DESCRIPTOR_ENTRIES = frozenset(("cwd", "rtd", "txt", "mem", "ltx"))
PROC_PIDLISTFDS = 1
PROC_PIDFDPIPEINFO = 6
PROX_FDTYPE_PIPE = 6
FREAD = 1
FWRITE = 2
REASONS = frozenset(
    (
        "control_identity_invalid",
        "native_preflight_unavailable",
        "runner_control_unavailable",
        "developer_mode_unavailable",
        "probe_identity_unavailable",
        "sandbox_signing_unavailable",
        "sandbox_behavior_unavailable",
        "descriptor_readback_unavailable",
        "probe_timeout",
    )
)
RUNNER_CONTROL_CHECKS = frozenset(
    (
        "temp_reference",
        "workspace_layout",
        "diagnostics_access",
        "diagnostics_layout",
        "diagnostics_worker_uid",
        "diagnostics_worker_bin",
        "diagnostics_root_family",
        "diagnostics_root_outside_home",
        "diagnostics_root_parent_component",
        "diagnostics_root_actions_runner",
        "diagnostics_root_cached_versioned",
        "diagnostics_root_extracted_versioned",
        "diagnostics_root_other",
        "diagnostics_home_owner",
        "diagnostics_component_owner",
        "diagnostics_process_changed",
        "workspace_owner",
        "directory_type_owner",
        "directory_permissions",
        "file_reference",
        "file_type_owner",
        "file_permissions",
        "probe_access",
    )
)


class ProbeFailure(Exception):
    def __init__(self, reason, cleanup_complete=True, check=None):
        super().__init__(reason if reason in REASONS else "native_preflight_unavailable")
        self.reason = reason if reason in REASONS else "native_preflight_unavailable"
        self.cleanup_complete = cleanup_complete
        self.check = check if self.reason == "runner_control_unavailable" and check in RUNNER_CONTROL_CHECKS else None


class _ProcFdInfo(ctypes.Structure):
    _fields_ = (("fd", ctypes.c_int32), ("type", ctypes.c_uint32))


class _ProcFileInfo(ctypes.Structure):
    _fields_ = (
        ("openflags", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
        ("offset", ctypes.c_int64),
        ("type", ctypes.c_int32),
        ("guardflags", ctypes.c_uint32),
    )


class _VInfoStat(ctypes.Structure):
    _fields_ = (
        ("dev", ctypes.c_uint32),
        ("mode", ctypes.c_uint16),
        ("nlink", ctypes.c_uint16),
        ("ino", ctypes.c_uint64),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("atime", ctypes.c_int64),
        ("atimensec", ctypes.c_int64),
        ("mtime", ctypes.c_int64),
        ("mtimensec", ctypes.c_int64),
        ("ctime", ctypes.c_int64),
        ("ctimensec", ctypes.c_int64),
        ("birthtime", ctypes.c_int64),
        ("birthtimensec", ctypes.c_int64),
        ("size", ctypes.c_int64),
        ("blocks", ctypes.c_int64),
        ("blksize", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
        ("gen", ctypes.c_uint32),
        ("rdev", ctypes.c_uint32),
        ("qspare", ctypes.c_int64 * 2),
    )


class _PipeInfo(ctypes.Structure):
    _fields_ = (
        ("stat", _VInfoStat),
        ("handle", ctypes.c_uint64),
        ("peerhandle", ctypes.c_uint64),
        ("status", ctypes.c_int32),
        ("reserved", ctypes.c_int32),
    )


class _PipeFdInfo(ctypes.Structure):
    _fields_ = (("pfi", _ProcFileInfo), ("pipeinfo", _PipeInfo))


def valid_sha(value):
    return type(value) is str and CONTROL_SHA.fullmatch(value) is not None


def safe_output(observed, reason="native_preflight_unavailable", check=None):
    capability = "macos-capability=observed" if observed else "macos-capability=refused"
    if not observed:
        if reason not in REASONS:
            reason = "native_preflight_unavailable"
        capability += " reason=" + reason
        if reason == "runner_control_unavailable" and check in RUNNER_CONTROL_CHECKS:
            capability += " check=" + check
    return capability + "\nmacos-confinement=refused reason=incomplete_channel_evidence\n"


def _run(argv, *, cwd=None, env=None, timeout=30):
    try:
        return subprocess.run(
            [str(part) for part in argv],
            cwd=str(cwd) if cwd is not None else None,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise ProbeFailure("native_preflight_unavailable")


def _require_success(result, reason):
    if result.returncode != 0:
        raise ProbeFailure(reason)
    return result


def _check_context(control_sha, workspace):
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise ProbeFailure("native_preflight_unavailable")
    values = {
        "CI_EVENT_NAME": "workflow_dispatch",
        "CI_REF": "refs/heads/main",
        "CI_REPOSITORY": "keeldock-platform/platform-ci",
        "CI_SERVER_URL": "https://github.com",
    }
    if not valid_sha(control_sha) or os.environ.get("CI_SHA") != control_sha:
        raise ProbeFailure("control_identity_invalid")
    if any(os.environ.get(key) != expected for key, expected in values.items()):
        raise ProbeFailure("control_identity_invalid")
    root = Path(__file__).resolve().parents[2]
    if root != Path(workspace).resolve() or Path.cwd().resolve() != root:
        raise ProbeFailure("control_identity_invalid")
    result = _run(["/usr/bin/git", "rev-parse", "--verify", "HEAD"], cwd=root, timeout=5)
    _require_success(result, "control_identity_invalid")
    if result.stdout.decode("ascii", "ignore").strip() != control_sha:
        raise ProbeFailure("control_identity_invalid")
    return root


def _runner_paths(workspace):
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise ProbeFailure("runner_control_unavailable", check="temp_reference")
    workspace = Path(workspace).resolve()
    if len(workspace.parents) < 3:
        raise ProbeFailure("runner_control_unavailable", check="workspace_layout")
    diagnostics = _runner_diagnostics(workspace)
    work_temp = workspace.parents[1] / "_temp"
    return (Path(runner_temp), work_temp, diagnostics)


def _parent_pid_and_uid(pid):
    try:
        result = _run(["/bin/ps", "-p", str(pid), "-o", "ppid=,uid="], timeout=5)
    except ProbeFailure:
        raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
    fields = result.stdout.decode("ascii", "ignore").split()
    if result.returncode != 0 or len(result.stdout) > 128 or len(fields) != 2 or not all(field.isdecimal() for field in fields):
        raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
    return int(fields[0]), int(fields[1])


def _process_executable(pid):
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        library.proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(MAX_PROCESS_PATH_BYTES)
        size = library.proc_pidpath(pid, buffer, len(buffer))
        if size <= 0 or size >= len(buffer):
            raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
        raw = buffer.raw[:size].split(b"\0", 1)[0].decode("utf-8")
        if not raw or not Path(raw).is_absolute():
            raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
        return Path(raw)
    except (OSError, AttributeError, UnicodeDecodeError, ValueError):
        raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")


def _runner_diagnostics(workspace):
    try:
        runner_uid = workspace.stat().st_uid
    except OSError:
        raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
    runner_home = workspace.parents[2]
    pid = os.getppid()
    seen = set()
    for _ in range(MAX_RUNNER_ANCESTORS):
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        parent, uid = _parent_pid_and_uid(pid)
        executable = _process_executable(pid)
        if executable.name == "Runner.Worker":
            if uid != runner_uid:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_worker_uid")
            if executable.parent.name != "bin":
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_worker_bin")
            root = executable.parent.parent
            try:
                relative = root.relative_to(runner_home)
            except ValueError:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_root_outside_home")
            allowed_root = relative.parts in (("actions-runner", "cached"), ("actions-runner", "extracted")) or (
                len(relative.parts) == 2
                and relative.parts[0] == "runners"
                and re.fullmatch(r"2\.[0-9]+\.[0-9]+", relative.parts[1]) is not None
            )
            if not allowed_root or ".." in executable.parts:
                if ".." in executable.parts:
                    check = "diagnostics_root_parent_component"
                elif relative.parts == ("actions-runner",):
                    check = "diagnostics_root_actions_runner"
                elif (
                    len(relative.parts) == 3
                    and relative.parts[:2] in (("actions-runner", "cached"), ("actions-runner", "extracted"))
                    and re.fullmatch(r"2\.[0-9]+\.[0-9]+", relative.parts[2]) is not None
                ):
                    check = (
                        "diagnostics_root_cached_versioned"
                        if relative.parts[1] == "cached"
                        else "diagnostics_root_extracted_versioned"
                    )
                else:
                    check = "diagnostics_root_other"
                raise ProbeFailure("runner_control_unavailable", check=check)
            path = runner_home
            try:
                home_info = path.lstat()
            except OSError:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_home_owner")
            if not stat.S_ISDIR(home_info.st_mode) or home_info.st_uid != runner_uid:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_home_owner")
            for component in relative.parts + ("bin", "Runner.Worker"):
                path = path / component
                try:
                    info = path.lstat()
                except OSError:
                    raise ProbeFailure("runner_control_unavailable", check="diagnostics_component_owner")
                required = stat.S_ISREG if path == executable else stat.S_ISDIR
                if not required(info.st_mode) or info.st_uid != runner_uid:
                    raise ProbeFailure("runner_control_unavailable", check="diagnostics_component_owner")
            if _parent_pid_and_uid(pid) != (parent, uid) or _process_executable(pid) != executable:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_process_changed")
            return root / "_diag"
        pid = parent
    raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")


def _open_control_nofollow(path, directory):
    path = Path(path)
    if not path.is_absolute() or len(path.parts) < 2:
        raise OSError("control path is not absolute")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None or not hasattr(os, "fchmod"):
        raise OSError("no-follow file controls unavailable")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    current = os.open(path.anchor, flags | directory_flag)
    try:
        for index, component in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            following = os.open(component, flags | (directory_flag if directory or not last else 0), dir_fd=current)
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def _protect_runner_controls(workspace):
    try:
        runner_uid = os.stat(workspace).st_uid
    except OSError:
        raise ProbeFailure("runner_control_unavailable", check="workspace_owner")
    if runner_uid == 0:
        raise ProbeFailure("runner_control_unavailable", check="workspace_owner")
    directories = set(_runner_paths(workspace))
    for path in directories:
        try:
            named = path.lstat()
            if not stat.S_ISDIR(named.st_mode) or named.st_uid != runner_uid:
                raise ProbeFailure("runner_control_unavailable", check="directory_type_owner")
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="directory_permissions")
        try:
            descriptor = _open_control_nofollow(path, True)
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="directory_permissions")
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != runner_uid
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise ProbeFailure("runner_control_unavailable", check="directory_type_owner")
            os.fchmod(descriptor, stat.S_IMODE(info.st_mode) & 0o700)
            checked = os.fstat(descriptor)
            named = path.lstat()
            if (checked.st_dev, checked.st_ino) != (named.st_dev, named.st_ino) or stat.S_IMODE(checked.st_mode) & 0o077:
                raise ProbeFailure("runner_control_unavailable", check="directory_permissions")
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="directory_permissions")
        finally:
            os.close(descriptor)
    control_files = ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY")
    for key in control_files:
        value = os.environ.get(key)
        if not value:
            raise ProbeFailure("runner_control_unavailable", check="file_reference")
        path = Path(value)
        try:
            named = path.lstat()
            if not stat.S_ISREG(named.st_mode) or named.st_uid != runner_uid:
                raise ProbeFailure("runner_control_unavailable", check="file_type_owner")
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="file_permissions")
        try:
            descriptor = _open_control_nofollow(path, False)
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="file_permissions")
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != runner_uid
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise ProbeFailure("runner_control_unavailable", check="file_type_owner")
            os.fchmod(descriptor, stat.S_IMODE(info.st_mode) & 0o600)
            checked = os.fstat(descriptor)
            named = path.lstat()
            if (checked.st_dev, checked.st_ino) != (named.st_dev, named.st_ino) or stat.S_IMODE(checked.st_mode) & 0o077:
                raise ProbeFailure("runner_control_unavailable", check="file_permissions")
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="file_permissions")
        finally:
            os.close(descriptor)
    return runner_uid, tuple(sorted(directories)), tuple(Path(os.environ[key]) for key in control_files)


def _create_probe_identity(workspace):
    if os.geteuid() != 0:
        raise ProbeFailure("probe_identity_unavailable")
    account = "/Users/" + USERNAME
    existing = _run(["/usr/bin/dscl", ".", "-read", account], timeout=10)
    if existing.returncode == 0:
        raise ProbeFailure("probe_identity_unavailable")
    listed = _require_success(_run(["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"], timeout=10), "probe_identity_unavailable")
    ids = []
    for line in listed.stdout.decode("utf-8", "ignore").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit():
            ids.append(int(fields[1]))
    uid = max(ids or [500]) + 1
    if uid >= 60000:
        raise ProbeFailure("probe_identity_unavailable")
    home_parent = Path(tempfile.mkdtemp(prefix="sandbox-capability-home-", dir="/tmp"))
    home = home_parent / "home"
    try:
        home.mkdir(mode=0o700)
        _require_success(_run(["/usr/bin/dscl", ".", "-create", account], timeout=10), "probe_identity_unavailable")
        for key, value in (
            ("UniqueID", str(uid)),
            ("PrimaryGroupID", "20"),
            ("NFSHomeDirectory", str(home)),
            ("UserShell", "/usr/bin/false"),
            ("RealName", "Capability Probe"),
            ("IsHidden", "1"),
        ):
            _require_success(_run(["/usr/bin/dscl", ".", "-create", account, key, value], timeout=10), "probe_identity_unavailable")
        os.chown(home_parent, uid, 20)
        os.chown(home, uid, 20)
        os.chmod(home_parent, 0o700)
        os.chmod(home, 0o700)
        group_result = _require_success(_run(["/usr/bin/id", "-Gn", USERNAME], timeout=5), "probe_identity_unavailable")
        groups = group_result.stdout.decode("ascii", "ignore").split()
        uid_result = _require_success(_run(["/usr/bin/id", "-u", USERNAME], timeout=5), "probe_identity_unavailable")
        if "admin" in groups or uid_result.stdout.decode("ascii", "ignore").strip() != str(uid) or uid == runner_uid_for_workspace(workspace):
            raise ProbeFailure("probe_identity_unavailable")
        user_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "LANG": "C"}
        privilege_check = (
            "import subprocess; result = subprocess.run(['/usr/bin/sudo', '-n', '-l'], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
            "raise SystemExit(0 if result.returncode != 0 else 1)"
        )
        _run_as_probe_user(["/usr/bin/python3", "-c", privilege_check], uid, env=user_env, timeout=5)
    except BaseException:
        try:
            _run(["/usr/bin/dscl", ".", "-delete", account], timeout=10)
        except Exception:
            pass
        shutil.rmtree(home_parent, ignore_errors=True)
        raise
    return uid, home_parent, home


def runner_uid_for_workspace(workspace):
    try:
        return os.stat(workspace).st_uid
    except OSError:
        raise ProbeFailure("runner_control_unavailable")


def _run_as_probe_user(argv, uid, env=None, timeout=10):
    result = _run(["/usr/bin/sudo", "-n", "-u", USERNAME, "--"] + list(argv), env=env, timeout=timeout)
    _require_success(result, "probe_identity_unavailable")
    if uid <= 0:
        raise ProbeFailure("probe_identity_unavailable")
    return result


def _verify_runner_controls_are_private(paths, uid):
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/tmp"}
    script = "import os,sys; raise SystemExit(1 if os.access(sys.argv[1], os.R_OK) else 0)"
    for path in paths:
        result = _run(["/usr/bin/sudo", "-n", "-u", USERNAME, "--", "/usr/bin/python3", "-c", script, str(path)], env=env, timeout=5)
        if result.returncode != 0:
            raise ProbeFailure("runner_control_unavailable", check="probe_access")
    if uid == 0:
        raise ProbeFailure("probe_identity_unavailable")


def _disable_developer_mode():
    _require_success(_run(["/usr/sbin/DevToolsSecurity", "-disable"], timeout=10), "developer_mode_unavailable")
    result = _require_success(_run(["/usr/sbin/DevToolsSecurity", "-status"], timeout=10), "developer_mode_unavailable")
    status = (result.stdout + result.stderr).decode("ascii", "ignore").lower()
    if "disabled" not in status or "enabled" in status:
        raise ProbeFailure("developer_mode_unavailable")


def _codesign_info(path, identifier, expected_entitlements):
    result = _require_success(
        _run(["/usr/bin/codesign", "-d", "--verbose=4", "--entitlements", ":-", str(path)], timeout=10),
        "sandbox_signing_unavailable",
    )
    details = (result.stdout + b"\n" + result.stderr).decode("utf-8", "ignore")
    if "Identifier=" + identifier not in details or "Signature=adhoc" not in details:
        raise ProbeFailure("sandbox_signing_unavailable")
    start = details.find("<?xml")
    if start < 0:
        raise ProbeFailure("sandbox_signing_unavailable")
    end = details.find("</plist>", start)
    if end < 0:
        raise ProbeFailure("sandbox_signing_unavailable")
    try:
        entitlements = plistlib.loads(details[start : end + len("</plist>")].encode("utf-8"))
    except (plistlib.InvalidFileException, ValueError, TypeError):
        raise ProbeFailure("sandbox_signing_unavailable")
    if entitlements != expected_entitlements:
        raise ProbeFailure("sandbox_signing_unavailable")
    if "com.apple.security.network.client" in entitlements or "com.apple.security.network.server" in entitlements:
        raise ProbeFailure("sandbox_signing_unavailable")


def _build_signed_probe(root, scratch):
    source = root / "kit/confinement/macos_capability.swift"
    main_entitlements = root / "kit/confinement/macos_capability.entitlements.plist"
    child_entitlements = root / "kit/confinement/macos_capability_child.entitlements.plist"
    info = root / "kit/confinement/macos_capability_info.plist"
    app = scratch / "CapabilityProbe.app"
    contents = app / "Contents"
    binaries = contents / "MacOS"
    binaries.mkdir(parents=True)
    shutil.copy2(info, contents / "Info.plist")
    executable = binaries / "CapabilityProbe"
    child = binaries / "CapabilityChild"
    compiled = scratch / "CapabilityProbe.unbundled"
    build = _require_success(
        _run(["/usr/bin/swiftc", "-O", "-o", compiled, source], cwd=root, timeout=120),
        "sandbox_signing_unavailable",
    )
    del build
    shutil.copy2(compiled, executable)
    shutil.copy2(compiled, child)
    os.chmod(executable, 0o755)
    os.chmod(child, 0o755)
    _require_success(
        _run(
            ["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", CHILD_IDENTIFIER, "--entitlements", child_entitlements, child],
            timeout=20,
        ),
        "sandbox_signing_unavailable",
    )
    _require_success(
        _run(
            ["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", APP_IDENTIFIER, "--entitlements", main_entitlements, app],
            timeout=20,
        ),
        "sandbox_signing_unavailable",
    )
    for path in (app, child):
        _require_success(_run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=0", path], timeout=15), "sandbox_signing_unavailable")
    _codesign_info(app, APP_IDENTIFIER, {"com.apple.security.app-sandbox": True})
    _codesign_info(
        child,
        CHILD_IDENTIFIER,
        {"com.apple.security.app-sandbox": True, "com.apple.security.inherit": True},
    )
    return executable


def _process_table():
    result = _require_success(_run(["/bin/ps", "-axo", "pid=,ppid=,uid=,comm="], timeout=5), "descriptor_readback_unavailable")
    rows = {}
    for line in result.stdout.decode("utf-8", "ignore").splitlines():
        fields = line.strip().split(maxsplit=3)
        if len(fields) != 4 or not fields[0].isdigit() or not fields[1].isdigit() or not fields[2].isdigit():
            continue
        rows[int(fields[0])] = (int(fields[1]), int(fields[2]), fields[3])
    return rows


def _descendants(root_pid, rows):
    children = {}
    for pid, (parent, uid, command) in rows.items():
        children.setdefault(parent, []).append(pid)
    result = []
    pending = list(children.get(root_pid, ()))
    while pending:
        pid = pending.pop()
        result.append(pid)
        pending.extend(children.get(pid, ()))
    return result


def _load_libproc():
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int)
        library.proc_pidinfo.restype = ctypes.c_int
        library.proc_pidfdinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
        library.proc_pidfdinfo.restype = ctypes.c_int
        return library
    except (OSError, AttributeError):
        raise ProbeFailure("descriptor_readback_unavailable")


def _native_descriptor_snapshot(pid):
    library = _load_libproc()
    buffer = ctypes.create_string_buffer(8192)
    returned = library.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer, len(buffer))
    if returned <= 0 or returned >= len(buffer) or returned % ctypes.sizeof(_ProcFdInfo):
        raise ProbeFailure("descriptor_readback_unavailable")
    descriptors = {}
    for offset in range(0, returned, ctypes.sizeof(_ProcFdInfo)):
        item = _ProcFdInfo.from_buffer_copy(buffer.raw[offset : offset + ctypes.sizeof(_ProcFdInfo)])
        if item.fd < 0 or item.fd in descriptors:
            raise ProbeFailure("descriptor_readback_unavailable")
        descriptors[item.fd] = item.type
    if set(descriptors) != {1, 2}:
        raise ProbeFailure("descriptor_readback_unavailable")
    if descriptors != {1: PROX_FDTYPE_PIPE, 2: PROX_FDTYPE_PIPE}:
        raise ProbeFailure("descriptor_readback_unavailable")

    observations = {}
    pipe_handles = set()
    for fd in (1, 2):
        pipe_buffer = ctypes.create_string_buffer(ctypes.sizeof(_PipeFdInfo))
        returned = library.proc_pidfdinfo(pid, fd, PROC_PIDFDPIPEINFO, pipe_buffer, len(pipe_buffer))
        if returned != ctypes.sizeof(_PipeFdInfo):
            raise ProbeFailure("descriptor_readback_unavailable")
        pipe = _PipeFdInfo.from_buffer_copy(pipe_buffer.raw)
        if pipe.pfi.type != PROX_FDTYPE_PIPE or pipe.pfi.openflags & (FREAD | FWRITE) != FWRITE:
            raise ProbeFailure("descriptor_readback_unavailable")
        handles = (pipe.pipeinfo.handle, pipe.pipeinfo.peerhandle)
        if not all(handles) or handles[0] == handles[1] or pipe_handles.intersection(handles):
            raise ProbeFailure("descriptor_readback_unavailable")
        pipe_handles.update(handles)
        observations[fd] = {
            "mode": "w",
            "type": "PIPE",
            "name": "->0x" + format(handles[0], "x"),
        }
    return observations


def _descriptor_snapshot(pids):
    if not pids or len(set(pids)) != len(pids):
        raise ProbeFailure("descriptor_readback_unavailable")
    joined = ",".join(str(pid) for pid in pids)
    result = _run(["/usr/sbin/lsof", "-nP", "-Fpfnt", "-p", joined], timeout=10)
    if result.returncode not in (0, 1):
        raise ProbeFailure("descriptor_readback_unavailable")
    lsof = {}
    current_pid = None
    current_fd = None
    current_special_entry = False
    for line in result.stdout.decode("utf-8", "ignore").splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current_pid = int(line[1:])
            if current_pid in lsof:
                raise ProbeFailure("descriptor_readback_unavailable")
            lsof[current_pid] = {}
            current_fd = None
            current_special_entry = False
        elif current_pid is not None and line.startswith("f"):
            descriptor = line[1:]
            match = re.fullmatch(r"(\d+)", descriptor)
            if match is None and descriptor not in LSOF_NON_DESCRIPTOR_ENTRIES:
                raise ProbeFailure("descriptor_readback_unavailable")
            if match is None:
                current_fd = None
                current_special_entry = True
            else:
                current_fd = int(match.group(1))
                current_special_entry = False
                if current_fd in lsof[current_pid]:
                    raise ProbeFailure("descriptor_readback_unavailable")
                lsof[current_pid][current_fd] = {"type": "", "name": ""}
        elif current_pid is not None and current_special_entry and line.startswith(("t", "n")):
            if not line[1:]:
                raise ProbeFailure("descriptor_readback_unavailable")
        elif current_pid is not None and current_fd is not None and line.startswith("t"):
            entry = lsof[current_pid][current_fd]
            if entry["type"] or not line[1:]:
                raise ProbeFailure("descriptor_readback_unavailable")
            entry["type"] = line[1:]
        elif current_pid is not None and current_fd is not None and line.startswith("n"):
            entry = lsof[current_pid][current_fd]
            if entry["name"] or not line[1:]:
                raise ProbeFailure("descriptor_readback_unavailable")
            entry["name"] = line[1:]
        else:
            raise ProbeFailure("descriptor_readback_unavailable")
    if set(lsof) != set(pids):
        raise ProbeFailure("descriptor_readback_unavailable")
    observations = {}
    for pid in pids:
        native = _native_descriptor_snapshot(pid)
        if set(lsof[pid]) != set(native):
            raise ProbeFailure("descriptor_readback_unavailable")
        if any(lsof[pid][fd]["type"] != "PIPE" or not lsof[pid][fd]["name"].startswith("->") for fd in (1, 2)):
            raise ProbeFailure("descriptor_readback_unavailable")
        if lsof[pid][1]["name"] == lsof[pid][2]["name"]:
            raise ProbeFailure("descriptor_readback_unavailable")
        if native[1]["name"] == native[2]["name"]:
            raise ProbeFailure("descriptor_readback_unavailable")
        for fd in (1, 2):
            if native[fd]["type"] != lsof[pid][fd]["type"]:
                raise ProbeFailure("descriptor_readback_unavailable")
            if native[fd]["mode"] != "w":
                raise ProbeFailure("descriptor_readback_unavailable")
        observations[pid] = native
    return observations


def _role_names(rows, pids):
    return {Path(rows[pid][2]).name.lower() for pid in pids if pid in rows}


def _observe_roles(names, counts):
    roles = set()
    roles.update(name for name in names if name in {"capabilityprobe", "capabilitychild", "sh", "sleep", "capability-child"})
    if any(name.startswith("python3") for name in names):
        roles.add("python3")
    if any(name.startswith("clang") for name in names):
        roles.add("clang")
    if counts.get("capability-child", 0) >= 2:
        roles.add("forked-grandchild")
    return roles


def _roles_complete(roles):
    return {
        "capabilityprobe",
        "capabilitychild",
        "sh",
        "sleep",
        "capability-child",
        "forked-grandchild",
        "python3",
        "clang",
    }.issubset(roles)


class _Capture:
    def __init__(self, stream):
        self.stream = stream
        self.data = bytearray()
        self.overflow = False
        self.thread = threading.Thread(target=self._drain, daemon=True)

    def start(self):
        self.thread.start()

    def _drain(self):
        while True:
            try:
                chunk = self.stream.read(4096)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            if len(self.data) + len(chunk) <= MAX_CAPTURE_BYTES:
                self.data.extend(chunk)
            else:
                self.overflow = True

    def join(self):
        if self.thread.ident is None:
            return True
        self.thread.join(timeout=5)
        return not self.thread.is_alive()


def _probe_group_exists(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _signal_probe_group(process, signum):
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.send_signal(signum)
        except OSError:
            pass


def _wait_probe_group_gone(process, timeout):
    deadline = time.monotonic() + timeout
    while _probe_group_exists(process.pid) and time.monotonic() < deadline:
        if process.poll() is None:
            try:
                process.wait(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
        else:
            time.sleep(min(0.05, max(0.001, deadline - time.monotonic())))
    return not _probe_group_exists(process.pid)


def _terminate_probe_tree(process):
    _signal_probe_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        return False
    if not _wait_probe_group_gone(process, 2):
        _signal_probe_group(process, signal.SIGKILL)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        except OSError:
            return False
        if not _wait_probe_group_gone(process, 2):
            return False
    return process.poll() is not None


def _observe_probe(executable, marker, writable_directory, uid, home):
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "LANG": "C"}
    argv = [
        "/usr/bin/sudo",
        "-n",
        "-u",
        USERNAME,
        "--",
        "/usr/bin/env",
        "HOME=" + str(home),
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG=C",
        str(executable),
        "--marker",
        str(marker),
        "--writable-directory",
        str(writable_directory),
    ]
    try:
        process = subprocess.Popen(
            argv,
            cwd="/tmp",
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        raise ProbeFailure("sandbox_behavior_unavailable")
    captures = []
    try:
        out_capture = _Capture(process.stdout)
        err_capture = _Capture(process.stderr)
        captures.extend((out_capture, err_capture))
        out_capture.start()
        err_capture.start()
        deadline = time.monotonic() + MAX_PROBE_SECONDS
        observed_roles = set()
        while time.monotonic() < deadline and process.poll() is None:
            rows = _process_table()
            pids = [pid for pid in _descendants(process.pid, rows) if rows[pid][1] == uid]
            if process.pid in rows and rows[process.pid][1] == uid:
                pids.insert(0, process.pid)
            if pids:
                try:
                    _descriptor_snapshot(pids)
                    counts = {}
                    for pid in pids:
                        name = Path(rows[pid][2]).name.lower()
                        counts[name] = counts.get(name, 0) + 1
                    names = set(counts)
                    observed_roles.update(_observe_roles(names, counts))
                except ProbeFailure:
                    pass
            if out_capture.overflow or err_capture.overflow:
                break
            if _roles_complete(observed_roles):
                break
            time.sleep(0.08)
        if out_capture.overflow or err_capture.overflow:
            raise ProbeFailure("sandbox_behavior_unavailable")
        try:
            process.wait(timeout=max(1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ProbeFailure("probe_timeout")
        if process.returncode != 0:
            raise ProbeFailure("sandbox_behavior_unavailable")
        if not _roles_complete(observed_roles):
            raise ProbeFailure("descriptor_readback_unavailable")
        if out_capture.overflow or err_capture.overflow:
            raise ProbeFailure("sandbox_behavior_unavailable")
    finally:
        tree_stopped = _terminate_probe_tree(process)
        captures_joined = True
        for capture in captures:
            if not capture.join():
                captures_joined = False
        if not tree_stopped or not captures_joined:
            raise ProbeFailure("sandbox_behavior_unavailable", cleanup_complete=False)
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass


def run_native_probe(control_sha):
    workspace = os.environ.get("CI_WORKSPACE")
    if not workspace:
        raise ProbeFailure("runner_control_unavailable")
    root = _check_context(control_sha, workspace)
    _disable_developer_mode()
    runner_uid, protected_directories, protected_files = _protect_runner_controls(root)
    probe_uid, home_parent, home = _create_probe_identity(root)
    scratch = None
    outside = None
    cleanup_safe = True
    try:
        scratch = Path(tempfile.mkdtemp(prefix="sandbox-capability-", dir="/tmp"))
        outside = Path(tempfile.mkdtemp(prefix="sandbox-capability-write-", dir="/tmp"))
        os.chmod(scratch, 0o755)
        os.chmod(outside, 0o1777)
        _verify_runner_controls_are_private(protected_directories + protected_files, probe_uid)
        marker = root / "kit/confinement/macos_capability.swift"
        if not marker.is_file() or not (marker.stat().st_mode & stat.S_IROTH):
            raise ProbeFailure("sandbox_behavior_unavailable")
        user_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "LANG": "C"}
        positive_read = "import sys; open(sys.argv[1], 'rb').close()"
        _run_as_probe_user(["/usr/bin/python3", "-c", positive_read, str(marker)], probe_uid, env=user_env, timeout=10)
        positive_write = "import sys; open(sys.argv[1], 'wb').close()"
        positive_file = outside / "positive-control"
        _run_as_probe_user(["/usr/bin/python3", "-c", positive_write, str(positive_file)], probe_uid, env=user_env, timeout=10)
        executable = _build_signed_probe(root, scratch)
        _observe_probe(executable, marker, outside, probe_uid, home)
    except ProbeFailure as error:
        if not error.cleanup_complete:
            cleanup_safe = False
        raise
    finally:
        if cleanup_safe:
            cleanup_failure = False
            try:
                delete_user = _run(["/usr/bin/dscl", ".", "-delete", "/Users/" + USERNAME], timeout=10)
                cleanup_failure = delete_user.returncode != 0
            except Exception:
                cleanup_failure = True
            shutil.rmtree(home_parent, ignore_errors=True)
            if scratch is not None:
                shutil.rmtree(scratch, ignore_errors=True)
            if outside is not None:
                shutil.rmtree(outside, ignore_errors=True)
            if cleanup_failure:
                raise ProbeFailure("probe_identity_unavailable")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-sha", required=True)
    arguments = parser.parse_args(argv)
    try:
        run_native_probe(arguments.control_sha)
    except ProbeFailure as error:
        print(safe_output(False, error.reason, error.check), end="")
        return 1
    except BaseException:
        print("macos-capability=refused reason=native_preflight_unavailable")
        print("macos-confinement=refused reason=incomplete_channel_evidence")
        return 1
    print(safe_output(True), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
