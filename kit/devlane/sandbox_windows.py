"""Hosted Windows LPAC boundary and core-node adapter for encrypted devlane runs."""

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path, PureWindowsPath

import bundle
import fetch
import filter as output_filter
import refusal_codes


WINDOWS_IMAGE = "windows-2025"
PROFILE_PATTERN = re.compile(r"^KDDevLane[a-f0-9]{32}$")
PACKAGE_SID_PATTERN = re.compile(r"^S-1-15-2-(?:[0-9]+-){6}[0-9]+$")
MAX_COMMANDS = 32
MAX_COMMAND_ARGUMENTS = 128
MAX_COMMAND_LINE = 30000
MAX_CHILD_SECONDS = 10800
WINDOWS_CLEANUP_STEP_SECONDS = 900
WINDOWS_SHRED_RESERVE_SECONDS = 300
WINDOWS_PROFILE_CLEANUP_TIMEOUT_SECONDS = WINDOWS_CLEANUP_STEP_SECONDS - WINDOWS_SHRED_RESERVE_SECONDS
WINDOWS_PREPARE_HEARTBEAT_SECONDS = 60
WINDOWS_PROCESS_CLASSES = {
    "node.exe": "node", "npm.exe": "npm", "npm.cmd": "npm", "cmd.exe": "cmd",
    "powershell.exe": "powershell", "pwsh.exe": "powershell", "git.exe": "git",
    "esbuild.exe": "esbuild", "playwright.exe": "playwright",
}
SAFE_ENVIRONMENT = frozenset((
    "PATH", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOME", "CI",
    "SystemRoot", "WINDIR", "ComSpec",
    "NPM_CONFIG_CACHE", "NPM_CONFIG_IGNORE_SCRIPTS", "NPM_CONFIG_AUDIT", "NPM_CONFIG_FUND",
    "NPM_CONFIG_OFFLINE", "NPM_CONFIG_UPDATE_NOTIFIER", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_LOGS_DIR",
    "NPM_CONFIG_PREFIX", "NPM_CONFIG_YES", "NPM_CONFIG_PROMPT", "GIT_TERMINAL_PROMPT",
    "PLAYWRIGHT_BROWSERS_PATH", "PLAYWRIGHT_JSON_OUTPUT_FILE",
    "NO_COLOR", "TERM", "PYTHONDONTWRITEBYTECODE",
))
PROHIBITED_ENVIRONMENT = frozenset((
    "DEVLANE_DECRYPT_KEY", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_RESULTS_URL", "ACTIONS_CACHE_URL", "RUNNER_TEMP", "GITHUB_ENV", "GITHUB_OUTPUT",
    "GITHUB_PATH", "GITHUB_WORKSPACE", "GITHUB_STEP_SUMMARY",
))
NPM_INSTALL_ARGUMENTS = (
    "ci", "--yes", "--ignore-scripts", "--include=dev", "--include=optional", "--no-audit", "--no-fund",
)
BROWSER_MEDIA_SUFFIXES = frozenset((".avif", ".bmp", ".gif", ".har", ".jpeg", ".jpg", ".mkv", ".mov",
                                    ".mp4", ".png", ".tif", ".tiff", ".trace", ".webm", ".zip"))


class WindowsBoundaryRefusal(ValueError):
    def __init__(self, code="windows-boundary", reason="other"):
        super().__init__(code)
        self.code = code
        self.reason = reason if reason in refusal_codes.WINDOWS_CLEANUP_REASON_CLASSES else "other"


def _refuse(code="windows-boundary", reason="other"):
    raise WindowsBoundaryRefusal(code, reason)


def _emit_windows_prepare_refusal(error):
    code = (error.code if error.code in refusal_codes.WINDOWS_PREPARE_REFUSAL_CODES
            else "windows-prepare-internal")
    print("devlane_refusal=" + code, file=sys.stderr, flush=True)
    error._prepare_refusal_emitted = True


def _windows_cleanup_error_reason(error):
    winerror = getattr(error, "winerror", None)
    error_number = getattr(error, "errno", None)
    if winerror in (32, 33):
        return "sharing-violation"
    if winerror == 5 or error_number in (errno.EACCES, errno.EPERM):
        return "access-denied"
    if winerror in (2, 3) or error_number == errno.ENOENT:
        return "not-found"
    return "other"


def _retry_windows_cleanup(operation):
    for attempt in range(4):
        try:
            return operation()
        except OSError as error:
            if (_windows_cleanup_error_reason(error) != "sharing-violation" or attempt == 3):
                raise
            time.sleep((0.05, 0.1, 0.2)[attempt])


def validate_profile(profile):
    if profile != "core-node":
        _refuse("profile-unavailable")
    return profile


def validate_profile_name(value):
    if type(value) is not str or not PROFILE_PATTERN.fullmatch(value):
        _refuse("profile-name")
    return value


def validate_package_sid(value):
    if type(value) is not str or not PACKAGE_SID_PATTERN.fullmatch(value):
        _refuse("package-sid")
    return value


def validate_environment(entries, *, allow_internet=False):
    if type(entries) is not list or len(entries) > 128:
        _refuse("child-environment")
    result = {}
    for entry in entries:
        if type(entry) is not str or "=" not in entry or "\x00" in entry or "\r" in entry or "\n" in entry:
            _refuse("child-environment")
        name, value = entry.split("=", 1)
        if name not in SAFE_ENVIRONMENT or name in PROHIBITED_ENVIRONMENT or name in result or len(value) > 8192:
            _refuse("child-environment")
        result[name] = value
    if result.get("NPM_CONFIG_IGNORE_SCRIPTS") != "true":
        _refuse("lifecycle-scripts-enabled")
    if result.get("NPM_CONFIG_OFFLINE") != ("false" if allow_internet else "true"):
        _refuse("offline-mode-disabled")
    return tuple(name + "=" + result[name] for name in sorted(result, key=str.lower))


def _path_within(path, root):
    path = PureWindowsPath(str(path))
    root = PureWindowsPath(str(root))
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _owned_path_within(path, root):
    path_text = str(path)
    root_text = str(root)
    try:
        path_object = Path(path_text)
        root_object = Path(root_text)
        if path_object.is_absolute() and root_object.is_absolute():
            path_object.relative_to(root_object)
            return True
    except ValueError:
        pass
    if PureWindowsPath(path_text).is_absolute() and PureWindowsPath(root_text).is_absolute():
        return _path_within(path_text, root_text)
    return False


def validate_command(command, *, node, npm_cli, source, scratch, stages):
    if type(command) is not list or not command or len(command) > MAX_COMMAND_ARGUMENTS:
        _refuse("profile-command")
    if any(type(value) is not str or "\x00" in value or len(value) > 4096 for value in command):
        _refuse("profile-command")
    node = PureWindowsPath(str(node))
    if command[0] == "npm":
        if len(command) < 3 or command[1] != "--prefix":
            _refuse("profile-command")
        args = list(command[1:])
        if len(args) < 2 or args[0] != "--prefix":
            _refuse("profile-command")
        prefix = args[1]
        if prefix == "/workspace/source":
            args[1] = str(source)
        elif prefix.startswith("/workspace/source/"):
            suffix = prefix[len("/workspace/source/"):]
            if any(part in ("", ".", "..") for part in suffix.split("/")):
                _refuse("profile-command")
            args[1] = str(PureWindowsPath(str(source)).joinpath(*suffix.split("/")))
        else:
            _refuse("profile-command")
        args = [_translate_embedded_path(value, source, scratch) for value in args]
        executable = str(node)
        arguments = [str(npm_cli), *args]
    elif command[0] == "node":
        executable = str(node)
        arguments = []
        for value in command[1:]:
            arguments.append(_translate_embedded_path(value, source, scratch))
    else:
        _refuse("profile-command")
    if len(arguments) > MAX_COMMAND_ARGUMENTS or sum(map(len, arguments)) + len(executable) > MAX_COMMAND_LINE:
        _refuse("profile-command-size")
    if not _path_within(executable, node.parent):
        _refuse("profile-tool-path")
    for index, argument in enumerate(arguments):
        if argument.startswith("/") and argument.startswith("/workspace/"):
            _refuse("profile-path-unmapped")
        if argument.startswith("/scratch/"):
            _refuse("profile-path-unmapped")
    return executable, arguments


def _translate_embedded_path(value, source, scratch):
    translated = value
    for marker, root in (("/workspace/source", source), ("/scratch", scratch)):
        index = translated.find(marker)
        if index < 0:
            continue
        end = index + len(marker)
        if end < len(translated) and translated[end] not in ("/", "=", ":"):
            continue
        suffix = translated[end + 1:] if end < len(translated) and translated[end] == "/" else ""
        if suffix and any(part in ("", ".", "..") for part in suffix.split("/")):
            _refuse("profile-command")
        mapped = str(PureWindowsPath(str(root)).joinpath(*suffix.split("/"))) if suffix else str(root)
        consumed_end = end + (1 + len(suffix) if suffix else 0)
        translated = translated[:index] + mapped + translated[consumed_end:]
    if "/workspace/" in translated or translated.startswith("/scratch/"):
        _refuse("profile-path-unmapped")
    return translated


def profile_commands(profile, source, scratch, node, npm_cli):
    validate_profile(profile)
    path = Path(__file__).resolve().parents[2] / "ci/devlane-profiles.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        configured = document["profiles"][profile]
    except (OSError, ValueError, KeyError, TypeError):
        _refuse("profile-config")
    commands = configured.get("commands")
    stages = configured.get("stages")
    if type(commands) is not list or type(stages) is not list or len(commands) != len(stages) or not commands:
        _refuse("profile-command-set")
    if len(commands) > MAX_COMMANDS or any(stage not in ("typecheck", "unit", "style") for stage in stages):
        _refuse("profile-command-set")
    translated = [validate_command(command, node=node, npm_cli=npm_cli, source=source, scratch=scratch, stages=stages)
                  for command in commands]
    return configured, list(zip(stages, translated))


def allowlists(manifest, profile, source_root=None):
    validate_profile(profile)
    if type(manifest) is not dict:
        _refuse("manifest-shape")
    allowed_files = manifest.get("allowed_files")
    allowed_tests = manifest.get("allowed_tests")
    frames = manifest.get("frames")
    if any(type(value) is not dict for value in (allowed_files, allowed_tests, frames)):
        _refuse("manifest-allowlists")
    profile_file = Path(__file__).resolve().parents[2] / "ci/devlane-profiles.json"
    try:
        profile_record = json.loads(profile_file.read_text(encoding="utf-8"))["profiles"][profile]
    except (OSError, ValueError, KeyError, TypeError):
        _refuse("profile-config")
    source_root = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[2]
    max_lines = {}
    for relative in allowed_files:
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            _refuse("allowlist-file")
        count = 0
        try:
            with path.open("rb") as content:
                for _line in content:
                    count += 1
                    if count > 10_000_000:
                        _refuse("allowlist-file-size")
        except OSError:
            _refuse("allowlist-file")
        max_lines[relative] = max(1, count)
    return {
        "files": allowed_files,
        "tests": {public_id: public_id for public_id in allowed_tests.values()},
        "frames": {public_id: public_id for public_id in frames.values()},
        "stages": list(dict.fromkeys(profile_record.get("stages", []) + (["browser"] if frames else []))),
        "codes": sorted(set(profile_record.get("diagnostic_codes", []) + ["DEVLANE_FAILURE"])),
        "max_lines": max_lines,
        "suites": [],
    }


def filtered_summary(manifest, profile, outcomes, source_root=None, *, extra_records=(), unit_failure_subreason=None):
    lines = []
    for stage, result in outcomes:
        if stage not in output_filter.ALLOWED_STAGES or result not in ("pass", "fail"):
            _refuse("outcome-invalid")
        record = {"kind": "control", "stage": stage, "status": result}
        if result == "fail":
            record["code"] = "DEVLANE_FAILURE"
        lines.append(bundle.canonical_json(record).rstrip(b"\n"))
    if unit_failure_subreason is not None:
        if unit_failure_subreason not in output_filter.UNIT_FAILURE_SUBREASONS:
            _refuse("unit-failure-subreason")
        lines.append(bundle.canonical_json({
            "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
            "subreason": unit_failure_subreason,
        }).rstrip(b"\n"))
    frames = manifest.get("frames", {})
    if type(frames) is not dict:
        _refuse("manifest-frames")
    browser = next((result for stage, result in outcomes if stage == "browser"), None)
    if frames and browser not in ("pass", "fail"):
        _refuse("browser-outcome")
    if type(extra_records) not in (list, tuple) or len(extra_records) > output_filter.MAX_RECORDS:
        _refuse("summary-records")
    for record in extra_records:
        if type(record) is not dict:
            _refuse("summary-records")
        lines.append(bundle.canonical_json(record).rstrip(b"\n"))
    try:
        frame_ids = sorted(set(frames.values()))
        allowed = allowlists(manifest, profile, source_root)
        summary = output_filter.filter_records(lines, allowed, frame_ids)
        output_filter.validate_public_summary(summary, allowed, frame_ids)
    except (output_filter.FilterRefusal, bundle.Refusal):
        return output_filter._ascii_json({
            "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
            "subreason": "filter-refused",
        })
    return summary


def positive_connectivity(timeout=4):
    if type(timeout) is not int or timeout < 1 or timeout > 10:
        _refuse("positive-timeout")
    connected = False
    for address in ((socket.AF_INET, ("1.1.1.1", 443)), (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0))):
        family, target = address
        try:
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(timeout)
                client.connect(target)
                connected = True
                break
        except OSError:
            continue
    try:
        socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
        resolved = True
    except OSError:
        resolved = False
    if not connected or not resolved:
        _refuse("positive-control-unavailable")
    return "windows_public_connectivity=proved\n"


def probe_script(result_path, *, listener_port, outside_canary, outside_write,
                 other_drive_canary, other_drive_write, pipe_path):
    target = json.dumps(str(result_path))
    outside_canary = json.dumps(str(outside_canary))
    outside_write = json.dumps(str(outside_write))
    other_drive_canary = json.dumps(str(other_drive_canary))
    other_drive_write = json.dumps(str(other_drive_write))
    pipe_path = json.dumps(str(pipe_path))
    return (
        "const net=require('net'),dns=require('dns'),fs=require('fs');"
        "const attempt=(host,port,family)=>new Promise(resolve=>{const s=net.createConnection({host,port,family});"
        "const timer=setTimeout(()=>{s.destroy();resolve('blocked')},3000);"
        "s.once('connect',()=>{clearTimeout(timer);s.destroy();resolve('open')});"
        "s.once('error',()=>{clearTimeout(timer);resolve('blocked')})});"
        "const readProbe=path=>{try{fs.readFileSync(path);return 'open'}catch(_){return 'blocked'}};"
        "const writeProbe=path=>{try{fs.writeFileSync(path,'unexpected');return 'open'}catch(_){return 'blocked'}};"
        "const pipeProbe=path=>new Promise(resolve=>{const s=net.createConnection({path});"
        "const timer=setTimeout(()=>{s.destroy();resolve('blocked')},3000);"
        "s.once('connect',()=>{clearTimeout(timer);s.destroy();resolve('open')});"
        "s.once('error',()=>{clearTimeout(timer);resolve('blocked')})});"
        "(async()=>{const outcomes=[];outcomes.push(await attempt('1.1.1.1',443,4));"
        "outcomes.push(await attempt('2606:4700:4700::1111',443,6));"
        "outcomes.push(await attempt('127.0.0.1'," + str(listener_port) + ",4));"
        "outcomes.push(await attempt('127.0.0.1',445,4));"
        "outcomes.push(await pipeProbe(" + pipe_path + "));"
        "await new Promise(resolve=>dns.resolve4('example.com',error=>{outcomes.push(error?'blocked':'open');resolve()}));"
        "outcomes.push(readProbe(" + outside_canary + "));outcomes.push(writeProbe(" + outside_write + "));"
        "outcomes.push(readProbe(" + other_drive_canary + "));outcomes.push(writeProbe(" + other_drive_write + "));"
        "fs.writeFileSync(" + target + ",outcomes.join(' '),'ascii');"
        "process.exitCode=outcomes.every(value=>value==='blocked')?0:19})().catch(()=>{process.exitCode=20});"
    )


def _read_json(path, maximum):
    try:
        target = Path(path)
        if target.is_symlink() or not target.is_file() or target.stat().st_size > maximum:
            _refuse("input-invalid")
        return bundle.strict_json(target.read_bytes(), maximum)
    except OSError:
        _refuse("input-unavailable")


def _validate_cleanup_roots(state_path):
    try:
        state = _read_json(state_path, 4 * 1024 * 1024)
        grants = state.get("acl_grants") if type(state) is dict else None
        integrity_roots = state.get("integrity_grants") if type(state) is dict else None
        owned_roots = state.get("owned_roots") if type(state) is dict else None
        if (type(state) is not dict or state.get("schema") != 1
                or type(grants) is not list or type(integrity_roots) is not list
                or type(owned_roots) is not list or len(owned_roots) > 128
                or state.get("job_state") not in ("none", "terminated-empty")
                or len(grants) + len(integrity_roots) > 10000):
            _refuse("profile-cleanup", reason="other")
        for root in owned_roots:
            if type(root) is not str or not root or len(root) > 4096 or "\x00" in root:
                _refuse("profile-cleanup", reason="other")
            if not Path(root).is_absolute() and not PureWindowsPath(root).is_absolute():
                _refuse("profile-cleanup", reason="other")
        for root in owned_roots:
            if PureWindowsPath(root).is_absolute() and os.name != "nt":
                continue
            current = Path(root)
            while True:
                try:
                    metadata = os.stat(current, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError:
                    _refuse("profile-cleanup", reason="other")
                else:
                    if (stat.S_ISLNK(metadata.st_mode)
                            or getattr(metadata, "st_file_attributes", 0) & 0x400):
                        _refuse("profile-cleanup", reason="other")
                parent = current.parent
                if parent == current:
                    break
                current = parent
        roots = []
        for grant in grants:
            if type(grant) is not dict:
                _refuse("profile-cleanup", reason="other")
            roots.append(grant.get("path"))
        roots.extend(integrity_roots)
        for value in roots:
            if type(value) is not str or not value or len(value) > 4096 or "\x00" in value:
                _refuse("profile-cleanup", reason="other")
            path = Path(value)
            if not path.is_absolute():
                if not PureWindowsPath(value).is_absolute():
                    _refuse("profile-cleanup", reason="other")
            if not any(_owned_path_within(value, owned_root) for owned_root in owned_roots):
                _refuse("profile-cleanup", reason="other")
            current = path
            while True:
                try:
                    metadata = os.stat(current, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError:
                    _refuse("profile-cleanup", reason="other")
                else:
                    if (stat.S_ISLNK(metadata.st_mode)
                            or getattr(metadata, "st_file_attributes", 0) & 0x400):
                        _refuse("profile-cleanup", reason="other")
                parent = current.parent
                if parent == current:
                    break
                current = parent
    except (bundle.Refusal, OSError, ValueError, TypeError):
        _refuse("profile-cleanup", reason="other")


def _is_reparse(path):
    path = Path(path)
    try:
        return path.is_symlink() or bool(getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400)
    except OSError:
        _refuse("path-unavailable")


def _windows_archive_name(name):
    if type(name) is not str or len(name) > 240:
        _refuse("archive-path")
    for component in name.split("/"):
        base = component.split(".", 1)[0].upper()
        if (not component or component.endswith((".", " ")) or any(character in component for character in '<>:"|?*')
                or re.fullmatch(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])", base)):
            _refuse("archive-path")
    return name


def _extract_windows_archive(archive_bytes, destination, expected):
    manifest, contents, directories = bundle.inspect_archive(archive_bytes, expected)
    for name in set(contents) | set(directories):
        _windows_archive_name(name)
    root = Path(destination)
    if root.is_symlink() or root.exists() and _is_reparse(root):
        _refuse("workspace-reparse")
    if root.exists() and any(root.iterdir()):
        _refuse("workspace-not-empty")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for relative in sorted(directories, key=lambda item: (item.count("/"), item)):
        target = root.joinpath(*relative.split("/"))
        if _is_reparse(target.parent):
            _refuse("workspace-reparse")
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _is_reparse(target):
            _refuse("workspace-reparse")
    for relative, payload in contents.items():
        target = root.joinpath(*relative.split("/"))
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _is_reparse(target.parent):
            _refuse("workspace-reparse")
        descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
    return manifest


def _windows_process_summary(root_pid):
    if sys.platform != "win32":
        return 0, "other"
    try:
        from ctypes import wintypes

        class ProcessEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        snapshot_call = kernel32.CreateToolhelp32Snapshot
        snapshot_call.argtypes = (wintypes.DWORD, wintypes.DWORD)
        snapshot_call.restype = wintypes.HANDLE
        first = kernel32.Process32FirstW
        first.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry32))
        first.restype = wintypes.BOOL
        following = kernel32.Process32NextW
        following.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry32))
        following.restype = wintypes.BOOL
        close = kernel32.CloseHandle
        close.argtypes = (wintypes.HANDLE,)
        close.restype = wintypes.BOOL
        snapshot = snapshot_call(0x00000002, 0)
        if snapshot == wintypes.HANDLE(-1).value:
            return 0, "other"
        entries = []
        root_image = ""
        try:
            entry = ProcessEntry32()
            entry.dwSize = ctypes.sizeof(ProcessEntry32)
            ok = first(snapshot, ctypes.byref(entry))
            while ok:
                pid = int(entry.th32ProcessID)
                image = entry.szExeFile
                if pid == int(root_pid):
                    root_image = image
                entries.append((pid, int(entry.th32ParentProcessID), image))
                ok = following(snapshot, ctypes.byref(entry))
        finally:
            close(snapshot)
        children = {}
        for pid, parent, image in entries:
            children.setdefault(parent, []).append((pid, image))
        descendants = []
        pending = [(int(root_pid), 0)]
        while pending:
            parent, depth = pending.pop(0)
            for child_pid, image in sorted(children.get(parent, ()), key=lambda value: value[0]):
                descendants.append((child_pid, depth + 1, image))
                pending.append((child_pid, depth + 1))
        if not descendants:
            return 0, WINDOWS_PROCESS_CLASSES.get(str(root_image).lower(), "other")
        _pid, _depth, image = max(descendants, key=lambda value: (value[1], value[0]))
        return len(descendants), WINDOWS_PROCESS_CLASSES.get(str(image).lower(), "other")
    except Exception:
        return 0, "other"


def _run_powershell(mode, state_path, request_path=None, timeout=MAX_CHILD_SECONDS + 300,
                    failure_prefix=None, monitor_stage=None):
    script = Path(__file__).with_name("sandbox_windows.ps1").resolve(strict=True)
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script),
            "-Mode", mode, "-StateFile", str(Path(state_path).resolve())]
    if request_path is not None:
        argv.extend(("-RequestFile", str(Path(request_path).resolve())))
    host_environment = os.environ
    names = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "PSModulePath", "CI_RUN_ID")
    child_environment = {name: host_environment[name] for name in names if host_environment.get(name)}
    phase_line = re.compile(rb"windows_launcher_phase=(types-load|appcontainer-sid|token-create|acl-grant|job-create|"
                            rb"process-create-suspended|job-assign|resume|wait|exit)\r?\n?\Z")
    captured = bytearray()
    overflow = [False]
    output_lock = threading.Lock()
    process = None
    reader = None

    def drain_stdout():
        while True:
            line = process.stdout.readline()
            if not line:
                return
            if phase_line.fullmatch(line):
                with output_lock:
                    sys.stdout.write(line.decode("ascii", "strict"))
                    sys.stdout.flush()
                continue
            if len(captured) + len(line) > 8192:
                overflow[0] = True
            elif not overflow[0]:
                captured.extend(line)

    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=child_environment)
        reader = threading.Thread(target=drain_stdout, name="devlane-powershell-output", daemon=True)
        reader.start()
        started = time.monotonic()
        next_heartbeat = WINDOWS_PREPARE_HEARTBEAT_SECONDS
        timed_out = False
        while True:
            elapsed = time.monotonic() - started
            remaining = timeout - elapsed
            wait_for = min(remaining, next_heartbeat - elapsed) if monitor_stage is not None else remaining
            if wait_for <= 0 and elapsed >= timeout:
                timed_out = True
                process.kill()
                process.wait()
                break
            try:
                process.wait(timeout=max(0.01, wait_for))
                break
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - started
                if elapsed >= timeout:
                    timed_out = True
                    process.kill()
                    process.wait()
                    break
                if monitor_stage is not None and elapsed >= next_heartbeat:
                    children, top = _windows_process_summary(process.pid)
                    print("windows_prepare_heartbeat stage=" + monitor_stage
                          + " elapsed=" + str(int(elapsed)) + " children=" + str(children)
                          + " top=" + top, flush=True)
                    next_heartbeat += WINDOWS_PREPARE_HEARTBEAT_SECONDS
        reader.join(timeout=5)
        if reader.is_alive():
            raise subprocess.SubprocessError("powershell-output-drain")
        if overflow[0]:
            captured.extend(b"x" * (8193 - len(captured)))
        result = subprocess.CompletedProcess(argv, process.returncode, bytes(captured), b"")
        if timed_out:
            if failure_prefix == "windows-prepare":
                print("windows_prepare_timeout limit=powershell seconds=" + str(int(timeout)), flush=True)
            _refuse((failure_prefix or "windows") + "-powershell-timeout")
    except OSError:
        _refuse((failure_prefix or "windows") + "-powershell-start-failed")
    except subprocess.SubprocessError:
        _refuse("powershell-unavailable")
    if result.returncode != 0 or len(result.stdout) > 8192:
        if mode == "delete" and len(result.stdout) <= 8192:
            match = re.fullmatch(
                rb"(?:windows_cleanup_reason=(sharing-violation|access-denied|not-found|other)\r?\n)?"
                rb"windows_sandbox=refused code=boundary\r?\n?",
                result.stdout,
            )
            if match is not None and match.group(1) is not None:
                reason = match.group(1).decode("ascii")
                marker = ("windows_prepare_cleanup_reason=" if failure_prefix == "windows-prepare"
                          else "windows_profile_cleanup_reason=")
                print(marker + reason, flush=True)
                error = WindowsBoundaryRefusal((failure_prefix or "windows") + "-powershell-nonzero", reason=reason)
                error._cleanup_reason_emitted = True
                raise error
        _refuse((failure_prefix or "windows") + "-powershell-nonzero")
    try:
        return result.stdout.decode("utf-8", "strict").strip()
    except UnicodeError:
        _refuse("native-boundary-output")

def create_profile(state_path, *, failure_prefix=None, monitor_stage=None):
    if sys.platform != "win32":
        _refuse("windows-host-required")
    _run_powershell("create", state_path, timeout=30, failure_prefix=failure_prefix,
                    monitor_stage=monitor_stage)
    state = _read_json(state_path, 4096)
    if (type(state) is not dict or set(state) != {
            "schema", "profile_name", "package_sid", "firewall_rule", "owned_roots", "acl_grants",
            "integrity_grants", "job_state",
    }
            or state["schema"] != 1 or not PROFILE_PATTERN.fullmatch(state["profile_name"])
            or not PACKAGE_SID_PATTERN.fullmatch(state["package_sid"])
            or type(state["owned_roots"]) is not list or state["owned_roots"]
            or type(state["acl_grants"]) is not list
            or type(state["integrity_grants"]) is not list
            or state["job_state"] != "none"
            or any(type(path) is not str or len(path) > 260 for path in state["integrity_grants"])):
        _refuse("profile-state")
    return state


def install_firewall(state_path):
    line = _run_powershell("firewall-install", state_path, timeout=90)
    if line != "windows_firewall=installed direction=outbound action=block package=verified remote=any":
        _refuse("firewall-readback")
    return line + "\n"


def remove_firewall(state_path):
    line = _run_powershell("firewall-remove", state_path, timeout=90)
    if line != "windows_firewall=removed":
        _refuse("firewall-cleanup")
    return line + "\n"


def _native_run(state_path, request, run_root, *, failure_prefix=None, monitor_stage=None):
    state = _read_json(state_path, 4096)
    validate_profile_name(state.get("profile_name"))
    validate_package_sid(state.get("package_sid"))
    request = dict(request)
    request.update({"schema": 1, "profile_name": state["profile_name"], "package_sid": state["package_sid"]})
    if (type(request.get("executable")) is not str or len(request["executable"]) > 260
            or type(request.get("working_directory")) is not str or len(request["working_directory"]) > 260
            or type(request.get("arguments")) is not list or len(request["arguments"]) > MAX_COMMAND_ARGUMENTS
            or type(request.get("timeout_milliseconds")) is not int
            or not 1000 <= request["timeout_milliseconds"] <= MAX_CHILD_SECONDS * 1000):
        _refuse("native-request")
    if sys.platform == "win32":
        owned_root = PureWindowsPath(str(run_root))
        request_root = PureWindowsPath(str(request.get("access_root", "")))
        if (not owned_root.is_absolute() or len(owned_root.drive) != 2
                or not request_root.is_absolute() or len(request_root.drive) != 2
                or not _path_within(request_root, owned_root) or not _path_within(owned_root, request_root)):
            _refuse("native-request")
        path_values = [request.get("executable"), request.get("working_directory")]
        for key in ("read_paths", "write_paths"):
            values = request.get(key)
            if type(values) is not list or len(values) > 128:
                _refuse("native-request")
            path_values.extend(values)
        for value in path_values:
            if (type(value) is not str or not PureWindowsPath(value).is_absolute()
                    or len(PureWindowsPath(value).drive) != 2 or not _path_within(value, owned_root)):
                _refuse("native-request")
    internet_client = request.get("internet_client", False)
    if type(internet_client) is not bool:
        _refuse("native-request")
    request["environment"] = list(validate_environment(request.get("environment"), allow_internet=internet_client))
    request_path = Path(run_root) / "state" / ("windows-request-" + str(os.getpid()) + ".json")
    payload = bundle.canonical_json(request)
    if len(payload) > 64 * 1024:
        _refuse("native-request-size")
    descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    try:
        stdout = _run_powershell("run", state_path, request_path,
                                 timeout=request["timeout_milliseconds"] // 1000 + 30,
                                 failure_prefix=failure_prefix, monitor_stage=monitor_stage)
    finally:
        try:
            request_path.unlink()
        except OSError:
            _refuse("native-request-cleanup")
    try:
        result = bundle.strict_json(stdout.encode("utf-8"), 4096)
    except bundle.Refusal:
        _refuse("native-result")
    if (type(result) is not dict or set(result) != {"status", "exit_code", "token", "job"}
            or result.get("status") not in ("pass", "fail", "timeout", "process-start-failed",
                                             "token-bypass-traverse-absent")
            or type(result.get("exit_code")) is not int
            or (result.get("status") != "process-start-failed" and
                (not str(result.get("token", "")).startswith("lpac=verified")
                 or not str(result.get("job", "")).startswith("assigned kill_on_close=enabled breakaway=disabled")))
            or (result.get("status") == "process-start-failed"
                and (result.get("exit_code") != 0 or result.get("token") or result.get("job")))
            or (result.get("status") == "token-bypass-traverse-absent"
                and _token_bypass_traverse_status(result.get("token", "")) != "absent")
            or (result.get("status") not in ("process-start-failed", "token-bypass-traverse-absent")
                and _token_bypass_traverse_status(result.get("token", "")) != "present")):
        _refuse("native-result")
    return result


def _token_bypass_traverse_status(token):
    if type(token) is not str:
        return None
    match = re.search(r"(?:^| )bypass_traverse=(present|absent)(?: |$)", token)
    return match.group(1) if match else None


def run_network_probe(state_path, run_root, *, node_path, scratch, environment):
    result_path = Path(scratch) / "network-probe.txt"
    if result_path.exists():
        _refuse("probe-output-exists")
    run_root = Path(run_root)
    outside_root = run_root.parent
    outside_canary = outside_root / ("outside-canary-" + os.urandom(8).hex())
    outside_write = outside_root / ("outside-write-" + os.urandom(8).hex())
    system_root = Path(os.environ.get("SystemRoot", "C:\\Windows"))
    other_drive = system_root.drive if system_root.drive.lower() != run_root.drive.lower() else "D:"
    if other_drive.lower() == run_root.drive.lower() or not Path(other_drive + "\\").is_dir():
        _refuse("other-drive-unavailable")
    other_temp = Path(other_drive + "\\Windows\\Temp")
    other_drive_canary = other_temp / ("outside-canary-" + os.urandom(8).hex())
    other_drive_write = other_temp / ("outside-write-" + os.urandom(8).hex())
    created = []
    try:
        outside_canary.write_text("host-canary", encoding="ascii")
        created.append(outside_canary)
        other_drive_canary.write_text("host-canary", encoding="ascii")
        created.append(other_drive_canary)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(8)
            listener_port = listener.getsockname()[1]

            def accept_local():
                try:
                    connection, _address = listener.accept()
                    connection.close()
                except OSError:
                    pass

            accepted = threading.Thread(target=accept_local, name="devlane-loopback-probe", daemon=True)
            accepted.start()
            source = probe_script(
                result_path, listener_port=listener_port, outside_canary=outside_canary,
                outside_write=outside_write, other_drive_canary=other_drive_canary,
                other_drive_write=other_drive_write, pipe_path=r"\\.\pipe\spoolss",
            )
            request = {
                "executable": str(node_path), "arguments": ["-e", source],
                "working_directory": str(scratch), "environment": environment,
                "access_root": str(run_root), "read_paths": [str(node_path)],
                "write_paths": [str(scratch)], "timeout_milliseconds": 15000,
            }
            result = _native_run(state_path, request, run_root)
            accepted.join(timeout=1)
        report = result_path.read_text(encoding="ascii")
        canaries_intact = (outside_canary.read_text(encoding="ascii") == "host-canary"
                           and other_drive_canary.read_text(encoding="ascii") == "host-canary")
        writes_blocked = not outside_write.exists() and not other_drive_write.exists()
        passed = (result["status"] == "pass" and report == " ".join(["blocked"] * 10)
                  and canaries_intact and writes_blocked)
    except (OSError, UnicodeError):
        passed = False
    finally:
        for path in (outside_canary, outside_write, other_drive_canary, other_drive_write, result_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                _refuse("probe-cleanup")
    if not passed:
        _refuse("network-cut-unproven")
    return ("windows_network_probe=pass ipv4=blocked ipv6=blocked dns=blocked loopback=blocked "
            "local_listener=blocked named_pipe=blocked smb=blocked outside_read=blocked outside_write=blocked "
            "other_drive_read=blocked other_drive_write=blocked firewall=verified\n")


def _npm_tools():
    node_text = shutil.which("node")
    npm_text = shutil.which("npm") or shutil.which("npm.cmd")
    if not node_text or not npm_text:
        _refuse("windows-prepare-toolchain-unavailable")
    node = Path(node_text).resolve(strict=True)
    npm_launcher = Path(npm_text)
    npm_cli = npm_launcher.parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
    if not npm_cli.is_file() or npm_cli.is_symlink():
        _refuse("windows-prepare-toolchain-unavailable")
    try:
        node_result = subprocess.run([str(node), "--version"], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
        npm_result = subprocess.run([str(node), str(npm_cli), "--version"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        _refuse("windows-prepare-toolchain-process-timeout")
    except OSError:
        _refuse("windows-prepare-toolchain-process-start-failed")
    if (node_result.returncode != 0 or node_result.stdout.strip() != b"v24.22.1"
            or npm_result.returncode != 0 or npm_result.stdout.strip() != b"11.19.1"):
        _refuse("windows-prepare-toolchain-version-invalid")
    return node, npm_cli


def _system_cmd_path():
    return Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "cmd.exe"


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_tree(root):
    root = Path(root)
    digest = hashlib.sha256()
    count = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories:
            path = Path(current) / name
            metadata = path.stat(follow_symlinks=False)
            if path.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
                _refuse("windows-prepare-toolchain-invalid")
            count += 1
            if count > 250000:
                _refuse("windows-prepare-toolchain-invalid")
            relative = path.relative_to(root).as_posix().encode("utf-8", "strict")
            digest.update(b"D" + len(relative).to_bytes(4, "big") + relative)
        for name in files:
            path = Path(current) / name
            metadata = path.stat(follow_symlinks=False)
            if (path.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400
                    or not stat.S_ISREG(metadata.st_mode)):
                _refuse("windows-prepare-toolchain-invalid")
            count += 1
            if count > 250000:
                _refuse("windows-prepare-toolchain-invalid")
            relative = path.relative_to(root).as_posix().encode("utf-8", "strict")
            digest.update(b"F" + len(relative).to_bytes(4, "big") + relative)
            digest.update(metadata.st_size.to_bytes(8, "big"))
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def _copy_pinned_windows_toolchain(node, npm_cli, destination, *, cmd_path=None):
    node = Path(node)
    npm_cli = Path(npm_cli)
    npm_root = npm_cli.parent.parent
    cmd_path = Path(cmd_path) if cmd_path is not None else _system_cmd_path()
    destination = Path(destination)
    try:
        for source in (node, npm_cli, cmd_path):
            metadata = source.stat(follow_symlinks=False)
            if (source.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400
                    or not stat.S_ISREG(metadata.st_mode)):
                _refuse("windows-prepare-toolchain-invalid")
        _reject_reparse_tree(npm_root)
        if not _owned_path_within(npm_cli, npm_root):
            _refuse("windows-prepare-toolchain-invalid")
        destination.mkdir(mode=0o700)
        copied_node = destination / "node.exe"
        copied_cmd = destination / "cmd.exe"
        copied_npm_root = destination / "node_modules" / "npm"
        copied_npm_root.parent.mkdir(mode=0o700)
        shutil.copyfile(node, copied_node)
        shutil.copyfile(cmd_path, copied_cmd)
        shutil.copytree(npm_root, copied_npm_root, symlinks=False)
        copied_npm_cli = copied_npm_root / npm_cli.relative_to(npm_root)
        hashes = {
            "node_sha256": _sha256_file(copied_node),
            "npm_tree_sha256": _sha256_tree(copied_npm_root),
            "cmd_sha256": _sha256_file(copied_cmd),
        }
        if (hashes["node_sha256"] != _sha256_file(node)
                or hashes["npm_tree_sha256"] != _sha256_tree(npm_root)
                or hashes["cmd_sha256"] != _sha256_file(cmd_path)
                or not copied_npm_cli.is_file() or copied_npm_cli.is_symlink()):
            _refuse("windows-prepare-toolchain-invalid")
        return copied_node, copied_npm_cli, copied_cmd, hashes
    except WindowsBoundaryRefusal as error:
        if error.code == "windows-prepare-toolchain-invalid":
            raise
        _refuse("windows-prepare-toolchain-invalid")
    except (OSError, UnicodeError, ValueError, OverflowError):
        _refuse("windows-prepare-toolchain-invalid")


def _copy_reporter_support(destination):
    destination = Path(destination)
    try:
        destination.mkdir(mode=0o700)
        names = ("sandbox_windows_reporter.mjs", "safe_json.mjs", "test_adapters.mjs",
                 "typescript_reporter.mjs")
        copied = {}
        for name in names:
            source = Path(__file__).with_name(name)
            metadata = source.stat(follow_symlinks=False)
            if (source.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400
                    or not stat.S_ISREG(metadata.st_mode)):
                _refuse("windows-prepare-toolchain-invalid")
            target = destination / name
            shutil.copyfile(source, target)
            if _sha256_file(source) != _sha256_file(target):
                _refuse("windows-prepare-toolchain-invalid")
            copied[name] = target
        return copied
    except WindowsBoundaryRefusal:
        raise
    except (OSError, UnicodeError, ValueError):
        _refuse("windows-prepare-toolchain-invalid")


def _validate_windows_toolchain(toolchain_path, prepared_root, run_root):
    record = _read_json(toolchain_path, 4096)
    if (type(record) is not dict or set(record) != {"node", "npm_cli", "cmd", "hashes"}
            or type(record["hashes"]) is not dict
            or set(record["hashes"]) != {"node_sha256", "npm_tree_sha256", "cmd_sha256"}):
        _refuse("windows-prepare-toolchain-invalid")
    prepared_root = str(Path(prepared_root))
    run_root = str(Path(run_root))
    for name in ("node", "npm_cli", "cmd"):
        value = record.get(name)
        if (type(value) is not str or not Path(value).is_absolute()
                or not _owned_path_within(value, prepared_root)
                or not _owned_path_within(value, run_root)):
            _refuse("windows-prepare-toolchain-invalid")
    node = Path(record["node"])
    npm_cli = Path(record["npm_cli"])
    cmd = Path(record["cmd"])
    npm_root = npm_cli.parent.parent
    if (node.name.lower() != "node.exe" or cmd != node.parent / "cmd.exe"
            or npm_cli.name.lower() != "npm-cli.js"
            or not _owned_path_within(npm_cli, npm_root)):
        _refuse("windows-prepare-toolchain-invalid")
    try:
        for path in (node, npm_cli, cmd, npm_root):
            metadata = path.stat(follow_symlinks=False)
            if (path.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400
                    or (path == npm_root and not stat.S_ISDIR(metadata.st_mode))
                    or (path != npm_root and not stat.S_ISREG(metadata.st_mode))):
                _refuse("windows-prepare-toolchain-invalid")
        hashes = record["hashes"]
        if (any(type(value) is not str or not re.fullmatch(r"[a-f0-9]{64}", value)
                for value in hashes.values())
                or _sha256_file(node) != hashes["node_sha256"]
                or _sha256_tree(npm_root) != hashes["npm_tree_sha256"]
                or _sha256_file(cmd) != hashes["cmd_sha256"]):
            _refuse("windows-prepare-toolchain-invalid")
    except (OSError, ValueError):
        _refuse("windows-prepare-toolchain-invalid")
    return record


def _npm_preparation_error_class(log_root):
    root = Path(log_root)
    try:
        candidates = sorted(root.glob("*.log"), key=lambda path: path.stat().st_mtime_ns, reverse=True)
    except OSError:
        return "other"
    for path in candidates[:8]:
        try:
            metadata = path.lstat()
            if not path.is_file() or path.is_symlink():
                continue
            with path.open("rb") as stream:
                if metadata.st_size > 1024 * 1024:
                    stream.seek(metadata.st_size - 1024 * 1024)
                payload = stream.read(1024 * 1024 + 1)
        except OSError:
            continue
        text = payload.decode("utf-8", "replace")
        for match in re.finditer(r"(?m)^[0-9]+ error code ([A-Z][A-Z0-9_]*)\r?$", text):
            if match.group(1) in refusal_codes.WINDOWS_PREPARATION_ERROR_CLASSES:
                return match.group(1)
    return "other"


def prepare_dependencies(projection_path, output_root, deadline_file, state_path):
    if sys.platform != "win32":
        _refuse("windows-host-required")
    try:
        projection_bytes = Path(projection_path).read_bytes()
        projection = fetch.validate_projection(projection_bytes, "core-node")
    except (OSError, fetch.Refusal):
        _refuse("windows-prepare-projection-invalid")
    node, npm_cli = _npm_tools()
    root = Path(output_root)
    if root.exists() or root.is_symlink():
        _refuse("windows-prepare-output-invalid")
    project = root / "project"
    prepared = root / "prepared"
    cache = root / "npm-cache"
    toolchain_root = prepared / "toolchain"
    try:
        project.mkdir(mode=0o700, parents=True)
        prepared.mkdir(mode=0o700)
        browser_root = prepared / "ms-playwright"
        browser_root.mkdir(mode=0o700)
        (project / "package.json").write_bytes(bundle.canonical_json(projection["npm_package"]) + b"\n")
        (project / "package-lock.json").write_bytes(bundle.canonical_json(projection["npm_lock"]) + b"\n")
        (project / ".npmrc").write_text(
            "ignore-scripts=true\naudit=false\nfund=false\nupdate-notifier=false\nregistry=https://registry.npmjs.org/\n",
            encoding="ascii",
        )
        cache.mkdir(mode=0o700)
    except OSError:
        _refuse("windows-prepare-output-invalid")
    node, npm_cli, cmd_path, toolchain_hashes = _copy_pinned_windows_toolchain(
        node, npm_cli, toolchain_root,
    )
    system_root = Path(os.environ.get("SystemRoot", "C:\\Windows"))
    environment = [
        "PATH=" + str(node.parent),
        "TEMP=" + str(cache), "TMP=" + str(cache), "USERPROFILE=" + str(project),
        "APPDATA=" + str(project), "LOCALAPPDATA=" + str(project), "HOME=" + str(project), "CI=1",
        "SystemRoot=" + str(system_root), "WINDIR=" + str(system_root),
        "ComSpec=" + str(cmd_path),
        "NPM_CONFIG_CACHE=" + str(cache), "NPM_CONFIG_PREFIX=" + str(project),
        "NPM_CONFIG_IGNORE_SCRIPTS=true",
        "NPM_CONFIG_AUDIT=false", "NPM_CONFIG_FUND=false", "NPM_CONFIG_OFFLINE=false",
        "NPM_CONFIG_UPDATE_NOTIFIER=false", "NPM_CONFIG_USERCONFIG=" + str(project / ".npmrc"),
        "NPM_CONFIG_YES=true", "NPM_CONFIG_PROMPT=false", "GIT_TERMINAL_PROMPT=0",
        "NPM_CONFIG_LOGS_DIR=" + str(cache / "_logs"),
        "PLAYWRIGHT_BROWSERS_PATH=" + str(browser_root), "PYTHONDONTWRITEBYTECODE=1",
        "NO_COLOR=1", "TERM=dumb",
    ]
    runner_root = Path(state_path).resolve().parents[1]
    created_profile = False
    bypass_traverse_reported = False
    prepare_failure = None
    cleanup_failure = None
    try:
        try:
            print("windows_prepare_stage_start=profile-create", flush=True)
            try:
                create_profile(state_path, failure_prefix="windows-prepare", monitor_stage="profile-create")
            except WindowsBoundaryRefusal as error:
                if error.code not in (
                        "windows-prepare-powershell-start-failed", "windows-prepare-powershell-timeout",
                        "windows-prepare-powershell-nonzero"):
                    _refuse("windows-prepare-profile-create-failed")
                raise
            created_profile = True
            print("windows_prepare_stage=none", flush=True)
            remaining = max(1, int(_deadline_remaining(deadline_file)))
            request = {
                "executable": str(node), "arguments": [str(npm_cli), *NPM_INSTALL_ARGUMENTS],
                "working_directory": str(project), "environment": environment, "access_root": str(runner_root),
                "read_paths": [str(toolchain_root), str(project)],
                "write_paths": [str(project), str(cache), str(browser_root)],
                "timeout_milliseconds": min(3_600_000, max(1000, int(remaining * 1000))), "internet_client": True,
            }
            print("windows_prepare_stage_start=npm-ci", flush=True)
            limit = "npm-child" if request["timeout_milliseconds"] == 3_600_000 else "work-deadline"
            child_seconds = request["timeout_milliseconds"] // 1000
            print("windows_prepare_limit stage=npm-ci limit=" + limit + " seconds=" + str(child_seconds)
                  + " powershell-seconds=" + str(child_seconds + 30), flush=True)
            result = _native_run(
                state_path, request, runner_root, failure_prefix="windows-prepare", monitor_stage="npm-ci",
            )
            bypass_status = _token_bypass_traverse_status(result.get("token", ""))
            if bypass_status is not None:
                if not bypass_traverse_reported:
                    print("windows_token_bypass_traverse=" + bypass_status, flush=True)
                    bypass_traverse_reported = True
                if bypass_status != "present":
                    _refuse("windows-prepare-token-bypass-traverse-absent")
            print("windows_prepare_job=empty", flush=True)
            if result["status"] == "process-start-failed":
                _refuse("windows-prepare-npm-process-start-failed")
            if result["status"] == "timeout":
                limit = "npm-child" if request["timeout_milliseconds"] == 3_600_000 else "work-deadline"
                print("windows_prepare_timeout limit=" + limit + " seconds="
                      + str((request["timeout_milliseconds"] + 999) // 1000), flush=True)
                _refuse("windows-prepare-npm-child-timeout-3600s" if request["timeout_milliseconds"] == 3_600_000
                        else "windows-prepare-npm-work-deadline")
            if result["status"] == "fail":
                _refuse("windows-prepare-npm-failed-" + _npm_preparation_error_class(cache / "_logs"))
            print("windows_prepare_stage=npm-ci", flush=True)
            if projection["playwright"]:
                candidates = (
                    project / "node_modules" / "playwright" / "cli.js",
                    project / "node_modules" / "@playwright" / "test" / "cli.js",
                )
                cli = next((item for item in candidates if item.is_file() and not item.is_symlink()), None)
                if cli is None:
                    _refuse("windows-prepare-playwright-cli-missing")
                remaining = max(1, int(_deadline_remaining(deadline_file)))
                request.update({
                    "arguments": [str(cli), "install", *projection["playwright"]],
                    "working_directory": str(project),
                    "timeout_milliseconds": min(1_800_000, max(1000, int(remaining * 1000))),
                })
                print("windows_prepare_stage_start=playwright", flush=True)
                limit = "playwright-child" if request["timeout_milliseconds"] == 1_800_000 else "work-deadline"
                child_seconds = request["timeout_milliseconds"] // 1000
                print("windows_prepare_limit stage=playwright limit=" + limit + " seconds=" + str(child_seconds)
                      + " powershell-seconds=" + str(child_seconds + 30), flush=True)
                result = _native_run(
                    state_path, request, runner_root, failure_prefix="windows-prepare", monitor_stage="playwright",
                )
                print("windows_prepare_job=empty", flush=True)
                if result["status"] == "process-start-failed":
                    _refuse("windows-prepare-playwright-process-start-failed")
                if result["status"] == "timeout":
                    limit = "playwright-child" if request["timeout_milliseconds"] == 1_800_000 else "work-deadline"
                    print("windows_prepare_timeout limit=" + limit + " seconds="
                          + str((request["timeout_milliseconds"] + 999) // 1000), flush=True)
                    _refuse("windows-prepare-playwright-child-timeout-1800s"
                            if request["timeout_milliseconds"] == 1_800_000
                            else "windows-prepare-playwright-work-deadline")
                if result["status"] == "fail":
                    _refuse("windows-prepare-playwright-failed-other")
                print("windows_prepare_stage=playwright", flush=True)
            print("windows_prepare_stage=done", flush=True)
        except WindowsBoundaryRefusal as error:
            prepare_failure = error
        except (OSError, subprocess.SubprocessError):
            prepare_failure = WindowsBoundaryRefusal("windows-prepare-internal")
        if prepare_failure is not None:
            _emit_windows_prepare_refusal(prepare_failure)
    finally:
        if created_profile:
            try:
                print("windows_prepare_stage_start=profile-cleanup", flush=True)
                delete_profile(state_path, failure_prefix="windows-prepare", monitor_stage="profile-cleanup")
            except Exception as error:
                reason = error.reason if isinstance(error, WindowsBoundaryRefusal) else _windows_cleanup_error_reason(error)
                cleanup_failure = WindowsBoundaryRefusal("windows-prepare-profile-cleanup-failed", reason=reason)
    if cleanup_failure is not None:
        raise cleanup_failure
    if prepare_failure is not None:
        raise prepare_failure
    node_modules = project / "node_modules"
    try:
        print("windows_prepare_stage_start=copy", flush=True)
        _reject_reparse_tree(node_modules)
        shutil.copytree(node_modules, prepared / "node_modules", symlinks=False)
        _copy_reporter_support(prepared / "support")
    except Exception:
        _refuse("windows-prepare-workspace-copy-failed")
    try:
        _write_private_json(prepared / "projection.json", projection)
        _write_private_json(prepared / "toolchain.json", {
            "node": str(node), "npm_cli": str(npm_cli), "cmd": str(cmd_path),
            "hashes": toolchain_hashes,
        })
    except OSError:
        _refuse("windows-prepare-output-invalid")
    return prepared, node, npm_cli


def _reject_reparse_tree(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        _refuse("prepared-tree-invalid")
    count = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        for name in directories + files:
            path = Path(current) / name
            count += 1
            if count > 250000 or path.is_symlink():
                _refuse("prepared-tree-invalid")
            try:
                attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
            except OSError:
                _refuse("prepared-tree-invalid")
            if attributes & 0x400:
                _refuse("prepared-tree-invalid")


def _deadline_remaining(path):
    try:
        record = bundle.strict_json(Path(path).read_bytes(), 1024)
        remaining = record["work_deadline"] - time.monotonic()
    except (OSError, bundle.Refusal, KeyError, TypeError):
        _refuse("deadline-invalid")
    if type(remaining) not in (int, float) or remaining <= 0:
        _refuse("deadline-exhausted")
    return remaining


def _write_private_json(path, value):
    path = Path(path)
    payload = bundle.canonical_json(value)
    if len(payload) > 4 * 1024 * 1024:
        _refuse("adapter-config-size")
    try:
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        _refuse("adapter-config-write")


def _remove_adapter_output(path):
    path = Path(path)
    if os.path.lexists(path) and _is_reparse(path):
        _refuse("adapter-output-reparse")
    if not os.path.lexists(path):
        return
    try:
        if not path.is_file():
            _refuse("adapter-output-type")
        path.unlink()
    except OSError:
        _refuse("adapter-output-remove")


def _read_adapter_records(path):
    path = Path(path)
    if not os.path.lexists(path) or _is_reparse(path) or not path.is_file():
        _refuse("adapter-output-invalid")
    try:
        payload = path.read_bytes()
    except OSError:
        _refuse("adapter-output-read")
    if len(payload) > output_filter.MAX_SUMMARY_BYTES or payload and not payload.endswith(b"\n"):
        _refuse("adapter-output-size")
    records = []
    for line in payload.splitlines():
        if len(line) > output_filter.MAX_RECORD_BYTES:
            _refuse("adapter-output-record-size")
        try:
            record = bundle.strict_json(line, output_filter.MAX_RECORD_BYTES)
        except bundle.Refusal:
            _refuse("adapter-output-record")
        if type(record) is not dict or len(records) >= output_filter.MAX_RECORDS:
            _refuse("adapter-output-record")
        records.append(record)
    return records


def _run_reporter(mode, input_path, *, state_path, run_root, scratch, source_path, prepared_path,
                  node, environment, manifest_path, config_path, typescript_path, timeout_milliseconds):
    if mode not in ("typescript", "vitest", "playwright"):
        _refuse("adapter-mode")
    reporter = Path(prepared_path) / "support" / "sandbox_windows_reporter.mjs"
    output_path = Path(scratch) / "reports" / (mode + "-adapter.jsonl")
    _remove_adapter_output(output_path)
    support_paths = [Path(prepared_path) / "support" / name for name in (
        "safe_json.mjs", "test_adapters.mjs", "typescript_reporter.mjs",
    )]
    if mode == "typescript":
        arguments = [str(reporter), mode, str(source_path), str(manifest_path), str(output_path), str(typescript_path)]
    else:
        arguments = [str(reporter), mode, str(input_path), str(config_path), str(output_path)]
    request = {
        "executable": str(node), "arguments": arguments,
        "working_directory": str(source_path), "environment": list(environment),
        "access_root": str(Path(run_root)),
        "read_paths": [str(Path(source_path)), str(Path(prepared_path)), str(Path(manifest_path)),
                       str(Path(config_path)) if config_path is not None else str(Path(manifest_path)),
                       str(Path(scratch)), str(Path(node)),
                       *(str(path) for path in support_paths), str(reporter)],
        "write_paths": [str(scratch)], "timeout_milliseconds": timeout_milliseconds,
    }
    result = _native_run(state_path, request, run_root)
    try:
        records = _read_adapter_records(output_path)
    except WindowsBoundaryRefusal:
        records = None
    return result, records


def _browser_media_outputs_present(scratch):
    for relative in ("playwright-results", "reports"):
        root = Path(scratch) / relative
        if os.path.lexists(root) and _is_reparse(root):
            return True
        if not root.exists():
            continue
        if not root.is_dir():
            return True
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            for name in directories + files:
                path = Path(current) / name
                try:
                    if _is_reparse(path):
                        return True
                    if path.is_file() and path.suffix.lower() in BROWSER_MEDIA_SUFFIXES:
                        return True
                except OSError:
                    return True
    return False


def _summary_failed(summary):
    for line in summary.splitlines():
        try:
            record = output_filter._parse_record(line)
        except output_filter.FilterRefusal:
            return True
        if (record.get("kind") == "test"
                or record.get("kind") == "frame" and record.get("status") == "fail"
                or record.get("kind") == "control" and record.get("status") == "fail"
                or record.get("kind") == "diagnostic" and record.get("level") == "error"):
            return True
    return False


def _public_decrypt_refusal(error):
    if isinstance(error, bundle.Refusal):
        code = str(error)
        if code.startswith("projection-"):
            return "binding-mismatch"
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
    if isinstance(error, WindowsBoundaryRefusal):
        if error.code == "key-invalid":
            return "key-format"
        if error.code in ("bundle-binding", "lockfile-binding", "projection-source-mismatch"):
            return "binding-mismatch"
        if error.code == "manifest-profile":
            return "archive-invalid"
    if isinstance(error, fetch.Refusal):
        return "binding-mismatch"
    return "archive-invalid"


def decrypt_bundle(context_path, bundle_path, source_path, manifest_path):
    context = _read_json(context_path, 65536)
    identity = fetch.validate_dispatch(context, expected_profile="core-node")
    key_hex = os.environ.pop("DEVLANE_DECRYPT_KEY", "")
    if len(key_hex) != 64 or any(character not in "0123456789abcdef" for character in key_hex):
        _refuse("key-invalid")
    key = bytearray.fromhex(key_hex)
    key_hex = ""
    try:
        envelope_path = Path(bundle_path)
        if envelope_path.is_symlink() or not envelope_path.is_file() or envelope_path.stat().st_size != identity["bundle_size"]:
            _refuse("bundle-binding")
        envelope = envelope_path.read_bytes()
        if hashlib.sha256(envelope).hexdigest() != identity["bundle_sha256"]:
            _refuse("bundle-binding")
        expected = {
            "format": "kd-public-devlane-aesgcm-v2", "repository_id": identity["repository_id"],
            "control_sha": identity["control_sha"], "workflow_path": fetch.WORKFLOW_PATH,
            "platform": identity["platform"], "profile": identity["profile"], "wave_id": identity["wave_id"],
            "bundle_id": identity["bundle_id"], "fetch_sha256": identity["projection_sha256"],
            "expires": identity["expires"],
        }
        archive = bundle.parse_envelope(envelope, bytes(key), expected)
        manifest = _extract_windows_archive(archive, source_path, expected)
        if manifest.get("profile") != "core-node" or manifest.get("schema") != 1:
            _refuse("manifest-profile")
        lock_path = Path(source_path) / "package-lock.json"
        lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
        if manifest.get("original_lockfiles") != {"package-lock.json": lock_digest}:
            _refuse("lockfile-binding")
        projection = fetch.validate_projection(Path(context_path).with_name("projection.json").read_bytes(), "core-node")
        projected_package, projected_lock, _coordinates = fetch.project_npm_lock(lock_path.read_bytes())
        if projected_package != projection["npm_package"] or projected_lock != projection["npm_lock"]:
            _refuse("projection-source-mismatch")
        manifest_descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(manifest_descriptor, "wb") as output:
            output.write(bundle.canonical_json(manifest) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        return "windows_decrypt=accepted manifest=bound\n"
    except (OSError, fetch.Refusal, bundle.Refusal) as error:
        _refuse("decrypt-rejected:" + _public_decrypt_refusal(error))
    finally:
        for index in range(len(key)):
            key[index] = 0
        envelope = b""
        archive = b""


def run_profile(context_path, manifest_path, source_root, prepared_root, scratch, run_root, state_path,
                deadline_file, node, npm_cli):
    context = _read_json(context_path, 65536)
    identity = fetch.validate_dispatch(context, expected_profile="core-node")
    manifest = _read_json(manifest_path, 4 * 1024 * 1024)
    configured, commands = profile_commands("core-node", source_root, scratch, node, npm_cli)
    Path(scratch).mkdir(mode=0o700, parents=True, exist_ok=True)
    source_path = Path(source_root)
    prepared_path = Path(prepared_root)
    if source_path.is_symlink() or prepared_path.is_symlink():
        _refuse("workload-root")
    cmd_path = Path(node).parent / "cmd.exe"
    module_path = source_path / "node_modules"
    if not module_path.exists():
        _reject_reparse_tree(prepared_path / "node_modules")
        shutil.copytree(prepared_path / "node_modules", module_path, symlinks=False)
    _reject_reparse_tree(module_path)
    environment = {
        "PATH": str(Path(node).parent),
        "TEMP": str(scratch), "TMP": str(scratch), "USERPROFILE": str(Path(scratch) / "profile"),
        "APPDATA": str(Path(scratch) / "appdata"), "LOCALAPPDATA": str(Path(scratch) / "localappdata"),
        "HOME": str(Path(scratch) / "profile"), "CI": "1",
        "SystemRoot": os.environ.get("SystemRoot", "C:\\Windows"),
        "WINDIR": os.environ.get("SystemRoot", "C:\\Windows"),
        "ComSpec": str(cmd_path),
        "NPM_CONFIG_CACHE": str(Path(scratch) / "npm-cache"),
        "NPM_CONFIG_IGNORE_SCRIPTS": "true", "NPM_CONFIG_AUDIT": "false", "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_OFFLINE": "true", "PLAYWRIGHT_BROWSERS_PATH": str(Path(prepared_root) / "ms-playwright"),
        "PLAYWRIGHT_JSON_OUTPUT_FILE": str(Path(scratch) / "reports" / "playwright.json"),
        "NO_COLOR": "1", "TERM": "dumb", "PYTHONDONTWRITEBYTECODE": "1",
    }
    for directory in (Path(scratch) / "profile", Path(scratch) / "appdata", Path(scratch) / "localappdata",
                      Path(scratch) / "npm-cache", Path(scratch) / "reports",
                      Path(scratch) / "playwright-results"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    entries = validate_environment([name + "=" + value for name, value in environment.items()])
    outcomes = []
    for stage, (executable, arguments) in commands:
        remaining = int(_deadline_remaining(deadline_file))
        request = {
            "executable": executable, "arguments": arguments,
            "working_directory": str(source_path), "environment": list(entries),
            "access_root": str(Path(run_root)),
            "read_paths": [str(source_path), str(prepared_path), str(Path(node)),
                           str(Path(npm_cli).parent.parent), str(cmd_path)],
            "write_paths": [str(scratch)],
            "timeout_milliseconds": min(3_600_000, remaining * 1000),
        }
        result = _native_run(state_path, request, run_root)
        outcomes.append((stage, "pass" if result["status"] == "pass" else "fail"))
    frames = manifest.get("frames", {})
    if frames:
        if not projection_has_browsers(Path(prepared_path) / "projection.json"):
            _refuse("browser-projection")
        executable, arguments = validate_command(
            configured.get("browser_command"), node=node, npm_cli=npm_cli,
            source=source_path, scratch=scratch, stages=["browser"],
        )
        remaining = int(_deadline_remaining(deadline_file))
        request = {
            "executable": executable, "arguments": arguments,
            "working_directory": str(source_path), "environment": list(entries),
            "access_root": str(Path(run_root)),
            "read_paths": [str(source_path), str(prepared_path), str(Path(node)),
                           str(Path(npm_cli).parent.parent), str(cmd_path)],
            "write_paths": [str(scratch)],
            "timeout_milliseconds": min(3_600_000, remaining * 1000),
        }
        result = _native_run(state_path, request, run_root)
        outcomes.append(("browser", "pass" if result["status"] == "pass" else "fail"))

    adapter_config = Path(scratch) / "reports" / "adapter-config.json"
    _write_private_json(adapter_config, {
        "tests": [[name, public_id] for name, public_id in manifest["allowed_tests"].items()],
        "frames": [[name, public_id] for name, public_id in frames.items()],
    })
    extra_records = []
    typecheck_result, typecheck_records = _run_reporter(
        "typescript", None, state_path=state_path, run_root=run_root, scratch=scratch,
        source_path=source_path, prepared_path=prepared_path, node=node, environment=entries,
        manifest_path=manifest_path, config_path=None,
        typescript_path=Path(prepared_path) / "node_modules" / "typescript" / "lib" / "typescript.js",
        timeout_milliseconds=min(600_000, int(_deadline_remaining(deadline_file) * 1000)),
    )
    if typecheck_result["status"] == "pass" and typecheck_records is not None:
        extra_records.extend(typecheck_records)
    else:
        outcomes.append(("typecheck", "fail"))
        extra_records.append({"kind": "control", "stage": "typecheck", "status": "fail",
                             "code": "DEVLANE_FAILURE"})

    unit_failure_subreason = None
    unit_report = Path(scratch) / "reports" / "vitest.json"
    if not os.path.lexists(unit_report):
        unit_failure_subreason = "report-missing"
    else:
        unit_result, unit_records = _run_reporter(
            "vitest", unit_report, state_path=state_path, run_root=run_root, scratch=scratch,
            source_path=source_path, prepared_path=prepared_path, node=node, environment=entries,
            manifest_path=manifest_path, config_path=adapter_config, typescript_path=None,
            timeout_milliseconds=min(30_000, int(_deadline_remaining(deadline_file) * 1000)),
        )
        if unit_result["status"] == "pass" and unit_records is not None:
            extra_records.extend(unit_records)
            if any(stage == "unit" and status == "fail" for stage, status in outcomes):
                unit_failure_subreason = "vitest-failed"
        else:
            unit_failure_subreason = "adapter-failed"

    if frames:
        browser_report = Path(scratch) / "reports" / "playwright.json"
        if _browser_media_outputs_present(scratch):
            extra_records.append({"kind": "control", "stage": "browser", "status": "fail",
                                 "code": "DEVLANE_FAILURE"})
        elif not os.path.lexists(browser_report):
            extra_records.append({"kind": "control", "stage": "browser", "status": "fail",
                                 "code": "DEVLANE_FAILURE"})
        else:
            browser_result, browser_records = _run_reporter(
                "playwright", browser_report, state_path=state_path, run_root=run_root, scratch=scratch,
                source_path=source_path, prepared_path=prepared_path, node=node, environment=entries,
                manifest_path=manifest_path, config_path=adapter_config, typescript_path=None,
                timeout_milliseconds=min(30_000, int(_deadline_remaining(deadline_file) * 1000)),
            )
            if browser_result["status"] == "pass" and browser_records is not None:
                extra_records.extend(browser_records)
            else:
                extra_records.append({"kind": "control", "stage": "browser", "status": "fail",
                                     "code": "DEVLANE_FAILURE"})

    summary = filtered_summary(manifest, "core-node", outcomes, source_path,
                               extra_records=extra_records,
                               unit_failure_subreason=unit_failure_subreason)
    try:
        sys.stdout.buffer.write(summary)
        sys.stdout.buffer.flush()
    except (OSError, BrokenPipeError):
        _refuse("summary-output")
    return 0 if all(result == "pass" for _stage, result in outcomes) and not _summary_failed(summary) else 1


def shred_tree(root, plaintext_root=None, overwrite_limit=1024 * 1024 * 1024):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        _refuse("shred-root-invalid")
    plaintext_root = Path(plaintext_root) if plaintext_root else None
    total = 0
    files = []
    directory_paths = []
    reparse_entries = []
    failures = []
    failure_reasons = []

    def record_failure(code, error=None):
        failures.append(code)
        failure_reasons.append(_windows_cleanup_error_reason(error) if error is not None else "other")

    def walk_error(error):
        record_failure("shred-enumerate-failed", error)
    for current, child_directories, names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        for name in list(child_directories):
            path = Path(current) / name
            try:
                metadata = path.stat(follow_symlinks=False)
                is_symlink = path.is_symlink()
                reparse = is_symlink or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
            except OSError as error:
                child_directories.remove(name)
                record_failure("shred-entry-inspection-failed", error)
                continue
            if reparse:
                child_directories.remove(name)
                reparse_entries.append((path, True, is_symlink))
            else:
                directory_paths.append(path)
        for name in names:
            path = Path(current) / name
            try:
                metadata = path.stat(follow_symlinks=False)
                is_symlink = path.is_symlink()
                reparse = is_symlink or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
            except OSError as error:
                record_failure("shred-entry-inspection-failed", error)
                continue
            if reparse:
                reparse_entries.append((path, False, is_symlink))
            elif not path.is_file():
                record_failure("shred-entry-inspection-failed")
            else:
                size = metadata.st_size
                total += size
                files.append((path, size))
    files.sort(key=lambda item: (0 if plaintext_root and item[0].is_relative_to(plaintext_root) else 1,
                                 len(item[0].parts), str(item[0])))
    cleaned = 0
    for path, is_directory, is_symlink in reparse_entries:
        try:
            _retry_windows_cleanup(lambda: path.rmdir() if is_directory and not is_symlink else path.unlink())
            cleaned += 1
        except OSError as error:
            record_failure("shred-reparse-remove-failed", error)
    for path, size in files:
        if size <= overwrite_limit:
            try:
                def overwrite_file():
                    remaining = size
                    with path.open("r+b", buffering=0) as output:
                        while remaining:
                            chunk = os.urandom(min(1024 * 1024, remaining))
                            output.write(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                _retry_windows_cleanup(overwrite_file)
            except OSError as error:
                record_failure("shred-overwrite-failed", error)
                try:
                    _retry_windows_cleanup(path.unlink)
                    cleaned += 1
                except OSError as retry_error:
                    record_failure("shred-file-remove-failed", retry_error)
                continue
        try:
            _retry_windows_cleanup(path.unlink)
            cleaned += 1
        except OSError as error:
            record_failure("shred-file-remove-failed", error)
    for path in reversed(directory_paths):
        try:
            _retry_windows_cleanup(path.rmdir)
        except OSError as error:
            record_failure("shred-directory-remove-failed", error)
    try:
        _retry_windows_cleanup(root.rmdir)
    except OSError as error:
        record_failure("shred-root-remove-failed", error)
    if failures:
        reason = failure_reasons[0] if failure_reasons else "other"
        print("windows_cleanup_reason=" + reason, flush=True)
        _refuse(failures[0], reason=reason)
    return "windows_runner_shred=confirmed files=%d bytes=%d reparse=%d\n" % (cleaned, total, len(reparse_entries))


def cleanup_runner(state_path, root, plaintext_root=None):
    errors = []
    error_reasons = []
    state = Path(state_path)
    if state.is_file():
        try:
            remove_firewall(state)
        except WindowsBoundaryRefusal as error:
            errors.append("windows-cleanup-firewall-failed")
            error_reasons.append(error.reason)
        except Exception:
            errors.append("windows-cleanup-firewall-failed")
            error_reasons.append("other")
        try:
            delete_profile(state)
        except WindowsBoundaryRefusal as error:
            errors.append("windows-cleanup-profile-failed")
            error_reasons.append(error.reason)
        except Exception:
            errors.append("windows-cleanup-profile-failed")
            error_reasons.append("other")
    shred_receipt = None
    try:
        shred_receipt = shred_tree(root, plaintext_root=plaintext_root)
    except WindowsBoundaryRefusal as error:
        errors.append("windows-cleanup-" + error.code)
        error_reasons.append(error.reason)
    except Exception:
        errors.append("windows-cleanup-shred-internal")
        error_reasons.append("other")
    if errors:
        _refuse(errors[0], reason=error_reasons[0])
    return "windows_sandbox_cleanup=confirmed firewall=removed profile=deleted\n" + shred_receipt


def projection_has_browsers(path):
    projection = _read_json(path, fetch.MAX_PROJECTION)
    return (type(projection) is dict and type(projection.get("playwright")) is list
            and bool(projection["playwright"]))


def remove_tree(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        _refuse("cleanup-root")
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        for name in directories + names:
            path = Path(current) / name
            if path.is_symlink() or getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400:
                _refuse("cleanup-reparse")
    try:
        shutil.rmtree(root)
    except OSError:
        _refuse("cleanup-remove")


def delete_profile(state_path, *, failure_prefix="windows-cleanup", monitor_stage=None):
    if sys.platform != "win32":
        _refuse("windows-host-required")
    _validate_cleanup_roots(state_path)
    try:
        line = _run_powershell("delete", state_path, timeout=WINDOWS_PROFILE_CLEANUP_TIMEOUT_SECONDS,
                               failure_prefix=failure_prefix,
                               monitor_stage=monitor_stage)
    except WindowsBoundaryRefusal as error:
        if failure_prefix == "windows-prepare" and not getattr(error, "_cleanup_reason_emitted", False):
            print("windows_prepare_cleanup_reason=" + error.reason, flush=True)
            error._cleanup_reason_emitted = True
        raise
    try:
        _retry_windows_cleanup(lambda: Path(state_path).unlink(missing_ok=True))
    except OSError as error:
        reason = _windows_cleanup_error_reason(error)
        marker = ("windows_prepare_cleanup_reason=" if failure_prefix == "windows-prepare"
                  else "windows_profile_cleanup_reason=")
        print(marker + reason, flush=True)
        _refuse("profile-cleanup", reason=reason)
    return line + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    positive = sub.add_parser("positive-control")
    positive.add_argument("--timeout", type=int, default=4)
    create = sub.add_parser("create-profile")
    create.add_argument("--state", required=True)
    firewall = sub.add_parser("firewall-install")
    firewall.add_argument("--state", required=True)
    probe = sub.add_parser("probe")
    probe.add_argument("--state", required=True)
    probe.add_argument("--run-root", required=True)
    probe.add_argument("--prepared", required=True)
    probe.add_argument("--scratch", required=True)
    remove = sub.add_parser("firewall-remove")
    remove.add_argument("--state", required=True)
    cleanup = sub.add_parser("delete-profile")
    cleanup.add_argument("--state", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--projection", required=True)
    prepare.add_argument("--output", required=True)
    prepare.add_argument("--deadline", required=True)
    prepare.add_argument("--state", required=True)
    decrypt = sub.add_parser("decrypt")
    decrypt.add_argument("--context", required=True)
    decrypt.add_argument("--bundle", required=True)
    decrypt.add_argument("--source", required=True)
    decrypt.add_argument("--manifest", required=True)
    execute = sub.add_parser("execute")
    execute.add_argument("--context", required=True)
    execute.add_argument("--manifest", required=True)
    execute.add_argument("--source", required=True)
    execute.add_argument("--prepared", required=True)
    execute.add_argument("--scratch", required=True)
    execute.add_argument("--run-root", required=True)
    execute.add_argument("--state", required=True)
    execute.add_argument("--deadline", required=True)
    shred = sub.add_parser("shred")
    shred.add_argument("--state", required=True)
    shred.add_argument("--root", required=True)
    shred.add_argument("--workspace", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "positive-control":
            sys.stdout.write(positive_connectivity(args.timeout))
        elif args.operation == "create-profile":
            create_profile(args.state)
            sys.stdout.write("windows_sandbox_profile=created appcontainer=lpac capabilities=empty\n")
        elif args.operation == "firewall-install":
            sys.stdout.write(install_firewall(args.state))
        elif args.operation == "probe":
            system_root = os.environ.get("SystemRoot", "C:\\Windows")
            toolchain = _validate_windows_toolchain(
                Path(args.prepared) / "toolchain.json", args.prepared, args.run_root,
            )
            node = Path(toolchain["node"])
            cmd_path = Path(toolchain["cmd"])
            environment = [
                "PATH=" + str(node.parent),
                "TEMP=" + str(args.scratch), "TMP=" + str(args.scratch),
                "USERPROFILE=" + str(Path(args.scratch) / "profile"),
                "APPDATA=" + str(Path(args.scratch) / "appdata"),
                "LOCALAPPDATA=" + str(Path(args.scratch) / "localappdata"),
                "HOME=" + str(Path(args.scratch) / "profile"), "CI=1",
                "SystemRoot=" + system_root, "WINDIR=" + system_root,
                "ComSpec=" + str(cmd_path),
                "NPM_CONFIG_CACHE=" + str(Path(args.scratch) / "npm-cache"),
                "NPM_CONFIG_IGNORE_SCRIPTS=true", "NPM_CONFIG_AUDIT=false", "NPM_CONFIG_FUND=false",
                "NPM_CONFIG_OFFLINE=true", "NO_COLOR=1", "TERM=dumb", "PYTHONDONTWRITEBYTECODE=1",
            ]
            for directory in (Path(args.scratch) / "profile", Path(args.scratch) / "appdata",
                              Path(args.scratch) / "localappdata", Path(args.scratch) / "npm-cache"):
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            sys.stdout.write(run_network_probe(args.state, args.run_root, node_path=node,
                                                scratch=args.scratch, environment=environment))
        elif args.operation == "firewall-remove":
            sys.stdout.write(remove_firewall(args.state))
        elif args.operation == "delete-profile":
            sys.stdout.write(delete_profile(args.state))
        elif args.operation == "prepare":
            prepare_dependencies(args.projection, args.output, args.deadline, args.state)
            sys.stdout.write("windows_prepare=complete lifecycle_scripts=disabled identity=lpac network=outbound-only\n")
        elif args.operation == "decrypt":
            sys.stdout.write(decrypt_bundle(args.context, args.bundle, args.source, args.manifest))
        elif args.operation == "execute":
            toolchain = _validate_windows_toolchain(
                Path(args.prepared) / "toolchain.json", args.prepared, args.run_root,
            )
            if type(toolchain) is not dict or set(toolchain) != {"node", "npm_cli", "cmd", "hashes"}:
                _refuse("toolchain-record")
            return run_profile(args.context, args.manifest, args.source, args.prepared, args.scratch,
                               args.run_root, args.state, args.deadline, toolchain["node"], toolchain["npm_cli"])
        elif args.operation == "shred":
            sys.stdout.write(cleanup_runner(args.state, args.root, args.workspace))
            sys.stdout.write("cleanup_receipt=confirmed\n")
            sys.stdout.write("devlane_job=completed public_output=filtered cleanup=confirmed\n")
        return 0
    except WindowsBoundaryRefusal as error:
        if args.operation == "decrypt":
            reason = (error.code.split(":", 1)[1]
                      if error.code.startswith("decrypt-rejected:")
                      else _public_decrypt_refusal(error))
            print("devlane_supervisor_refusal=decrypt-rejected", file=sys.stderr)
            print("decrypt_refusal=" + reason, file=sys.stderr)
        elif args.operation == "prepare":
            code = error.code if error.code in refusal_codes.WINDOWS_PREPARE_REFUSAL_CODES else "windows-prepare-internal"
            if not getattr(error, "_prepare_refusal_emitted", False):
                print("devlane_refusal=" + code, file=sys.stderr)
        elif args.operation == "shred":
            code = error.code if error.code in refusal_codes.WINDOWS_SHRED_REFUSAL_CODES else "windows-cleanup-internal"
            if code.startswith("windows-cleanup-shred-"):
                print("windows_sandbox_cleanup=failed stage=shred")
                print("cleanup_receipt=failed stage=windows-shred reason=" + error.reason)
                print("devlane_job=completed public_output=filtered cleanup=failed")
            print("devlane_refusal=" + code, file=sys.stderr)
        else:
            print("devlane_refusal=windows-runner-failed", file=sys.stderr)
        return 1
    except Exception:
        if args.operation == "decrypt":
            print("devlane_supervisor_refusal=decrypt-rejected", file=sys.stderr)
            print("decrypt_refusal=archive-invalid", file=sys.stderr)
        elif args.operation == "prepare":
            print("devlane_refusal=windows-prepare-internal", file=sys.stderr)
        elif args.operation == "shred":
            print("devlane_refusal=windows-cleanup-internal", file=sys.stderr)
        else:
            print("devlane_refusal=boundary", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
