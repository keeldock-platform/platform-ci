"""Hosted Windows LPAC boundary and core-node adapter for encrypted devlane runs."""

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path, PureWindowsPath

import bundle
import fetch
import filter as output_filter


WINDOWS_IMAGE = "windows-2025"
PROFILE_PATTERN = re.compile(r"^KDDevLane[a-f0-9]{32}$")
PACKAGE_SID_PATTERN = re.compile(r"^S-1-15-2-(?:[0-9]+-){6}[0-9]+$")
MAX_COMMANDS = 32
MAX_COMMAND_ARGUMENTS = 128
MAX_COMMAND_LINE = 30000
MAX_CHILD_SECONDS = 10800
SAFE_ENVIRONMENT = frozenset((
    "PATH", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOME", "CI",
    "SystemRoot", "WINDIR", "ComSpec",
    "NPM_CONFIG_CACHE", "NPM_CONFIG_IGNORE_SCRIPTS", "NPM_CONFIG_AUDIT", "NPM_CONFIG_FUND",
    "NPM_CONFIG_OFFLINE", "NPM_CONFIG_UPDATE_NOTIFIER", "NPM_CONFIG_USERCONFIG",
    "PLAYWRIGHT_BROWSERS_PATH", "PLAYWRIGHT_JSON_OUTPUT_FILE",
    "NO_COLOR", "TERM", "PYTHONDONTWRITEBYTECODE",
))
PROHIBITED_ENVIRONMENT = frozenset((
    "DEVLANE_DECRYPT_KEY", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_RESULTS_URL", "ACTIONS_CACHE_URL", "RUNNER_TEMP", "GITHUB_ENV", "GITHUB_OUTPUT",
    "GITHUB_PATH", "GITHUB_WORKSPACE", "GITHUB_STEP_SUMMARY",
))
NPM_INSTALL_ARGUMENTS = ("ci", "--ignore-scripts", "--include=dev", "--include=optional", "--no-audit", "--no-fund")
BROWSER_MEDIA_SUFFIXES = frozenset((".avif", ".bmp", ".gif", ".har", ".jpeg", ".jpg", ".mkv", ".mov",
                                    ".mp4", ".png", ".tif", ".tiff", ".trace", ".webm", ".zip"))


class WindowsBoundaryRefusal(ValueError):
    def __init__(self, code="windows-boundary"):
        super().__init__(code)
        self.code = code


def _refuse(code="windows-boundary"):
    raise WindowsBoundaryRefusal(code)


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


def _run_powershell(mode, state_path, request_path=None, timeout=MAX_CHILD_SECONDS + 300):
    script = Path(__file__).with_name("sandbox_windows.ps1").resolve(strict=True)
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script),
            "-Mode", mode, "-StateFile", str(Path(state_path).resolve())]
    if request_path is not None:
        argv.extend(("-RequestFile", str(Path(request_path).resolve())))
    host_environment = os.environ
    names = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "PSModulePath", "CI_RUN_ID")
    child_environment = {name: host_environment[name] for name in names if host_environment.get(name)}
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                                env=child_environment)
    except (OSError, subprocess.SubprocessError):
        _refuse("powershell-unavailable")
    if result.returncode != 0 or len(result.stdout) > 8192:
        _refuse("native-boundary-failed")
    try:
        return result.stdout.decode("utf-8", "strict").strip()
    except UnicodeError:
        _refuse("native-boundary-output")


def create_profile(state_path):
    if sys.platform != "win32":
        _refuse("windows-host-required")
    _run_powershell("create", state_path, timeout=30)
    state = _read_json(state_path, 4096)
    if (type(state) is not dict or set(state) != {"schema", "profile_name", "package_sid", "firewall_rule", "acl_grants"}
            or state["schema"] != 1 or not PROFILE_PATTERN.fullmatch(state["profile_name"])
            or not PACKAGE_SID_PATTERN.fullmatch(state["package_sid"]) or type(state["acl_grants"]) is not list):
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


def _native_run(state_path, request, run_root):
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
        stdout = _run_powershell("run", state_path, request_path, timeout=request["timeout_milliseconds"] // 1000 + 30)
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
            or result.get("status") not in ("pass", "fail", "timeout")
            or type(result.get("exit_code")) is not int
            or not str(result.get("token", "")).startswith("lpac=verified")
            or not str(result.get("job", "")).startswith("assigned kill_on_close=enabled breakaway=disabled")):
        _refuse("native-result")
    return result


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
                "access_root": str(run_root), "read_paths": [str(Path(node_path).parent), str(system_root / "System32")],
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
        _refuse("node-toolchain-missing")
    node = Path(node_text).resolve(strict=True)
    npm_launcher = Path(npm_text)
    npm_cli = npm_launcher.parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
    if not npm_cli.is_file() or npm_cli.is_symlink():
        _refuse("npm-toolchain-missing")
    node_result = subprocess.run([str(node), "--version"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
    npm_result = subprocess.run([str(node), str(npm_cli), "--version"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False)
    if (node_result.returncode != 0 or node_result.stdout.strip() != b"v24.22.1"
            or npm_result.returncode != 0 or npm_result.stdout.strip() != b"11.19.1"):
        _refuse("node-toolchain-version")
    return node, npm_cli


def prepare_dependencies(projection_path, output_root, deadline_file, state_path):
    if sys.platform != "win32":
        _refuse("windows-host-required")
    try:
        projection_bytes = Path(projection_path).read_bytes()
        projection = fetch.validate_projection(projection_bytes, "core-node")
    except (OSError, fetch.Refusal):
        _refuse("projection-invalid")
    node, npm_cli = _npm_tools()
    root = Path(output_root)
    if root.exists() or root.is_symlink():
        _refuse("prepared-output-exists")
    project = root / "project"
    prepared = root / "prepared"
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
    cache = root / "npm-cache"
    cache.mkdir(mode=0o700)
    system_root = Path(os.environ.get("SystemRoot", "C:\\Windows"))
    environment = [
        "PATH=" + str(node.parent) + os.pathsep + str(system_root / "System32"),
        "TEMP=" + str(cache), "TMP=" + str(cache), "USERPROFILE=" + str(project),
        "APPDATA=" + str(project), "LOCALAPPDATA=" + str(project), "HOME=" + str(project), "CI=1",
        "SystemRoot=" + str(system_root), "WINDIR=" + str(system_root),
        "ComSpec=" + str(system_root / "System32" / "cmd.exe"),
        "NPM_CONFIG_CACHE=" + str(cache), "NPM_CONFIG_IGNORE_SCRIPTS=true",
        "NPM_CONFIG_AUDIT=false", "NPM_CONFIG_FUND=false", "NPM_CONFIG_OFFLINE=false",
        "NPM_CONFIG_UPDATE_NOTIFIER=false", "NPM_CONFIG_USERCONFIG=" + str(project / ".npmrc"),
        "PLAYWRIGHT_BROWSERS_PATH=" + str(browser_root), "PYTHONDONTWRITEBYTECODE=1",
        "NO_COLOR=1", "TERM=dumb",
    ]
    runner_root = Path(state_path).resolve().parents[1]
    created_profile = False
    try:
        create_profile(state_path)
        created_profile = True
        remaining = max(1, int(_deadline_remaining(deadline_file)))
        request = {
            "executable": str(node), "arguments": [str(npm_cli), *NPM_INSTALL_ARGUMENTS],
            "working_directory": str(project), "environment": environment, "access_root": str(runner_root),
            "read_paths": [str(system_root / "System32"), str(node.parent), str(project), str(npm_cli)],
            "write_paths": [str(project), str(cache), str(browser_root)],
            "timeout_milliseconds": min(3_600_000, max(1000, int(remaining * 1000))), "internet_client": True,
        }
        result = _native_run(state_path, request, runner_root)
        if result["status"] != "pass":
            _refuse("dependency-preparation-failed")
        if projection["playwright"]:
            candidates = (
                project / "node_modules" / "playwright" / "cli.js",
                project / "node_modules" / "@playwright" / "test" / "cli.js",
            )
            cli = next((item for item in candidates if item.is_file() and not item.is_symlink()), None)
            if cli is None:
                _refuse("playwright-cli-missing")
            remaining = max(1, int(_deadline_remaining(deadline_file)))
            request.update({
                "arguments": [str(cli), "install", *projection["playwright"]],
                "working_directory": str(project),
                "timeout_milliseconds": min(1_800_000, max(1000, int(remaining * 1000))),
            })
            result = _native_run(state_path, request, runner_root)
            if result["status"] != "pass":
                _refuse("browser-preparation-failed")
    except (OSError, subprocess.SubprocessError):
        _refuse("dependency-preparation-failed")
    finally:
        if created_profile:
            delete_profile(state_path)
    node_modules = project / "node_modules"
    _reject_reparse_tree(node_modules)
    shutil.copytree(node_modules, prepared / "node_modules", symlinks=False)
    _write_private_json(prepared / "projection.json", projection)
    _write_private_json(prepared / "toolchain.json", {
        "node": str(node), "npm_cli": str(npm_cli),
    })
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
    reporter = Path(__file__).with_name("sandbox_windows_reporter.mjs").resolve(strict=True)
    output_path = Path(scratch) / "reports" / (mode + "-adapter.jsonl")
    _remove_adapter_output(output_path)
    support_paths = [Path(__file__).with_name(name).resolve(strict=True) for name in (
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
                       str(Path(scratch)), str(Path(node).parent),
                       str(Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"),
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
    module_path = source_path / "node_modules"
    if not module_path.exists():
        _reject_reparse_tree(prepared_path / "node_modules")
        shutil.copytree(prepared_path / "node_modules", module_path, symlinks=False)
    _reject_reparse_tree(module_path)
    environment = {
        "PATH": str(Path(node).parent) + os.pathsep + str(Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"),
        "TEMP": str(scratch), "TMP": str(scratch), "USERPROFILE": str(Path(scratch) / "profile"),
        "APPDATA": str(Path(scratch) / "appdata"), "LOCALAPPDATA": str(Path(scratch) / "localappdata"),
        "HOME": str(Path(scratch) / "profile"), "CI": "1",
        "SystemRoot": os.environ.get("SystemRoot", "C:\\Windows"),
        "WINDIR": os.environ.get("SystemRoot", "C:\\Windows"),
        "ComSpec": str(Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "cmd.exe"),
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
            "read_paths": [str(source_path), str(prepared_path), str(Path(node).parent),
                           str(Path(npm_cli).parent.parent.parent),
                           str(Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32")],
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
            "read_paths": [str(source_path), str(prepared_path), str(Path(node).parent),
                           str(Path(npm_cli).parent.parent.parent),
                           str(Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32")],
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
        _refuse("cleanup-root")
    plaintext_root = Path(plaintext_root) if plaintext_root else None
    total = 0
    files = []
    directory_paths = []
    reparse_entries = []
    failures = []
    for current, child_directories, names in os.walk(root, topdown=True, followlinks=False):
        for name in list(child_directories):
            path = Path(current) / name
            try:
                metadata = path.stat(follow_symlinks=False)
                is_symlink = path.is_symlink()
                reparse = is_symlink or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
            except OSError:
                child_directories.remove(name)
                failures.append(path)
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
            except OSError:
                failures.append(path)
                continue
            if reparse:
                reparse_entries.append((path, False, is_symlink))
            elif not path.is_file():
                failures.append(path)
            else:
                size = metadata.st_size
                total += size
                files.append((path, size))
    files.sort(key=lambda item: (0 if plaintext_root and item[0].is_relative_to(plaintext_root) else 1,
                                 len(item[0].parts), str(item[0])))
    cleaned = 0
    for path, is_directory, is_symlink in reparse_entries:
        try:
            if is_directory and not is_symlink:
                path.rmdir()
            else:
                path.unlink()
            cleaned += 1
        except OSError:
            failures.append(path)
    for path, size in files:
        try:
            if size <= overwrite_limit:
                remaining = size
                with path.open("r+b", buffering=0) as output:
                    while remaining:
                        chunk = os.urandom(min(1024 * 1024, remaining))
                        output.write(chunk)
                        remaining -= len(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            path.unlink()
            cleaned += 1
        except OSError:
            failures.append(path)
            try:
                path.unlink()
            except OSError:
                pass
    for path in reversed(directory_paths):
        try:
            path.rmdir()
        except OSError:
            failures.append(path)
    try:
        root.rmdir()
    except OSError:
        failures.append(root)
    if failures:
        _refuse("cleanup-incomplete")
    return "windows_runner_shred=confirmed files=%d bytes=%d reparse=%d\n" % (cleaned, total, len(reparse_entries))


def cleanup_runner(state_path, root, plaintext_root=None):
    errors = []
    state = Path(state_path)
    if state.is_file():
        try:
            remove_firewall(state)
        except Exception:
            errors.append("firewall")
        try:
            delete_profile(state)
        except Exception:
            errors.append("profile")
    shred_receipt = None
    try:
        shred_receipt = shred_tree(root, plaintext_root=plaintext_root)
    except Exception:
        errors.append("plaintext-tree")
    if errors:
        _refuse("cleanup-incomplete")
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


def delete_profile(state_path):
    if sys.platform != "win32":
        _refuse("windows-host-required")
    line = _run_powershell("delete", state_path, timeout=90)
    try:
        Path(state_path).unlink(missing_ok=True)
    except OSError:
        _refuse("profile-cleanup")
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
    probe.add_argument("--node", required=True)
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
            environment = [
                "PATH=" + str(Path(args.node).parent) + os.pathsep + str(Path(system_root) / "System32"),
                "TEMP=" + str(args.scratch), "TMP=" + str(args.scratch),
                "USERPROFILE=" + str(Path(args.scratch) / "profile"),
                "APPDATA=" + str(Path(args.scratch) / "appdata"),
                "LOCALAPPDATA=" + str(Path(args.scratch) / "localappdata"),
                "HOME=" + str(Path(args.scratch) / "profile"), "CI=1",
                "SystemRoot=" + system_root, "WINDIR=" + system_root,
                "ComSpec=" + str(Path(system_root) / "System32" / "cmd.exe"),
                "NPM_CONFIG_CACHE=" + str(Path(args.scratch) / "npm-cache"),
                "NPM_CONFIG_IGNORE_SCRIPTS=true", "NPM_CONFIG_AUDIT=false", "NPM_CONFIG_FUND=false",
                "NPM_CONFIG_OFFLINE=true", "NO_COLOR=1", "TERM=dumb", "PYTHONDONTWRITEBYTECODE=1",
            ]
            for directory in (Path(args.scratch) / "profile", Path(args.scratch) / "appdata",
                              Path(args.scratch) / "localappdata", Path(args.scratch) / "npm-cache"):
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            sys.stdout.write(run_network_probe(args.state, args.run_root, node_path=args.node,
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
            toolchain = _read_json(Path(args.prepared) / "toolchain.json", 4096)
            if type(toolchain) is not dict or set(toolchain) != {"node", "npm_cli"}:
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
        else:
            print("devlane_refusal=windows-runner-failed", file=sys.stderr)
        return 1
    except Exception:
        if args.operation == "decrypt":
            print("devlane_supervisor_refusal=decrypt-rejected", file=sys.stderr)
            print("decrypt_refusal=archive-invalid", file=sys.stderr)
        else:
            print("devlane_refusal=boundary", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
