import base64
import glob
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import time

import linux_harness
from linux_channels import BoundaryRefusal


CANARY_ENV_NAME = "KD_CANARY_SECRET"
STANDIN_VALUE = "kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd"
PROJECT_UID = linux_harness.CHILD_UID
MIN_CANARY_BYTES = 16
MAX_CANARY_BYTES = 256
MAX_SCAN_BYTES = 33554432
SCAN_CHUNK = 4194304
TOTAL_SCAN_BUDGET = 2147483648
WALK_SECONDS = 240
ENVIRON_BYTES = 1048576
MAX_REQUEST_BYTES = 4194304
MAX_REPLY_BYTES = 1048576
MAX_HITS = 50
JOB_START_SLACK_NS = 10000000000
BOOT_SLACK_NS = 60000000000
SKIP_ROOTS = ("/proc", "/sys", "/dev")
EXTRA_ROOTS = ("/dev/shm",)
GROUP_SECRET = 0
GROUP_READABLE_CONTROL = 1
GROUP_PRIVATE_CONTROL = 2
RUNNER_GLOBS = (
    "runners/*/_diag",
    "runners/*/.credentials",
    "runners/*/.credentials_rsaparams",
    "runners/*/.runner",
    "runners/*",
    ".ssh",
)
ABSOLUTE_PATH = re.compile(r"/[A-Za-z0-9._/@+=-]{1,400}")
WALKER_ENV = {"PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}


def valid_canary(value):
    if type(value) is not str:
        return False
    if not MIN_CANARY_BYTES <= len(value) <= MAX_CANARY_BYTES:
        return False
    return all(0x21 <= ord(character) <= 0x7e for character in value)


def load_canary(environ):
    value = environ.get(CANARY_ENV_NAME)
    if not valid_canary(value):
        raise BoundaryRefusal("environment")
    return value


def needles_for(value):
    if not valid_canary(value):
        raise ValueError("canary")
    raw = value.encode("utf-8")
    standard = base64.b64encode(raw)
    urlsafe = base64.urlsafe_b64encode(raw)
    variants = {
        raw,
        raw.hex().encode("ascii"),
        standard,
        standard.rstrip(b"="),
        urlsafe,
        urlsafe.rstrip(b"="),
        value.encode("utf-16-le"),
    }
    return tuple(sorted(variants))


def derive_canary(secret, label):
    if not valid_canary(secret) or type(label) is not str or not label:
        raise ValueError("canary")
    return hmac.new(secret.encode("utf-8"), label.encode("ascii"), hashlib.sha256).hexdigest()


def new_nonce_canary():
    return "kd-nonce-" + os.urandom(16).hex()


def control_token(kind, nonce):
    if kind not in ("readable", "private", "environ"):
        raise ValueError("kind")
    return "kd-control-" + kind + "-" + nonce


def place_canaries(directory, values, world_readable=False):
    os.makedirs(directory, mode=0o755, exist_ok=True)
    os.chmod(directory, 0o755)
    placed = []
    for index, (name, mode) in enumerate((("env-file", 0o600), ("script-file", 0o700))):
        path = os.path.join(directory, name)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.fchmod(descriptor, mode)
            os.write(descriptor, "".join(value + chr(10) for value in values).encode("utf-8"))
        finally:
            os.close(descriptor)
        placed.append(path)
    if world_readable:
        path = os.path.join(directory, "leak-file")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.fchmod(descriptor, 0o644)
            os.write(descriptor, (values[0] + chr(10)).encode("utf-8"))
        finally:
            os.close(descriptor)
        placed.append(path)
    return placed


def plant_control_files(directory, nonce):
    os.makedirs(directory, mode=0o755, exist_ok=True)
    os.chmod(directory, 0o755)
    readable = os.path.join(directory, "control-readable")
    private = os.path.join(directory, "control-private")
    for path, mode, kind in ((readable, 0o644, "readable"), (private, 0o600, "private")):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.fchmod(descriptor, mode)
            os.write(descriptor, (control_token(kind, nonce) + chr(10)).encode("ascii"))
        finally:
            os.close(descriptor)
    return readable, private


def plant_writable_control(directory):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chown(directory, PROJECT_UID, PROJECT_UID)
    os.chmod(directory, 0o700)
    path = os.path.join(directory, "control-file")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchown(descriptor, PROJECT_UID, PROJECT_UID)
        os.write(descriptor, b"control" + bytes((10,)))
    finally:
        os.close(descriptor)
    return directory, path


def parse_stat_start_ticks(text):
    closing = text.rfind(")")
    if closing < 0:
        raise ValueError("stat")
    fields = text[closing + 1:].split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError("stat")
    return int(fields[19])


def parse_boot_time(text):
    for line in text.splitlines():
        if line.startswith("btime "):
            value = line.split()[1]
            if value.isdigit():
                return int(value)
    raise ValueError("btime")


def job_cutoff_ns(stat_text, boot_text, ticks_per_second):
    boot = parse_boot_time(boot_text)
    if stat_text is None:
        return boot * 1000000000 - BOOT_SLACK_NS
    start_ns = boot * 1000000000 + (parse_stat_start_ticks(stat_text) * 1000000000) // ticks_per_second
    return start_ns - JOB_START_SLACK_NS


def find_worker_pid():
    for item in os.listdir("/proc"):
        if not item.isdecimal():
            continue
        try:
            with open("/proc/" + item + "/comm", "rt", encoding="ascii", errors="replace") as source:
                name = source.read(64).strip()
        except OSError:
            continue
        if name == "Runner.Worker":
            return int(item)
    return None


def current_cutoff_ns():
    with open("/proc/stat", "rt", encoding="ascii") as source:
        boot_text = source.read(1048576)
    stat_text = None
    pid = find_worker_pid()
    if pid is not None:
        try:
            with open("/proc/" + str(pid) + "/stat", "rt", encoding="ascii", errors="replace") as source:
                stat_text = source.read(4096)
        except OSError:
            stat_text = None
    return job_cutoff_ns(stat_text, boot_text, os.sysconf("SC_CLK_TCK"))


def runner_root_from_exe(exe_path):
    if type(exe_path) is not str or ABSOLUTE_PATH.fullmatch(exe_path) is None:
        return None
    parent = os.path.dirname(exe_path)
    if os.path.basename(exe_path) != "Runner.Worker" or not os.path.basename(parent).startswith("bin"):
        return None
    return os.path.dirname(parent)


def runner_root():
    pid = find_worker_pid()
    if pid is None:
        return None
    try:
        return runner_root_from_exe(os.readlink("/proc/" + str(pid) + "/exe"))
    except OSError:
        return None


def required_unreadable(runner_temp, root):
    required = []
    if runner_temp:
        required.append(runner_temp)
    if root:
        required.append(os.path.join(root, "_diag"))
    return required


def runner_targets(home, runner_temp, root=None):
    candidates = []
    if runner_temp:
        candidates.append(runner_temp)
        candidates.append(os.path.dirname(runner_temp))
        candidates.extend(sorted(glob.glob(os.path.join(runner_temp, "_runner_file_commands", "*"))))
    if root:
        candidates.append(root)
        candidates.append(os.path.join(root, "_diag"))
        candidates.append(os.path.join(root, "_work"))
        candidates.append(os.path.join(root, "_work", "_temp"))
        for name in (".credentials", ".credentials_rsaparams", ".runner"):
            candidates.append(os.path.join(root, name))
    if home:
        for pattern in RUNNER_GLOBS:
            candidates.extend(sorted(glob.glob(os.path.join(home, pattern))))
        candidates.append(home)
    targets = []
    for path in candidates:
        if ABSOLUTE_PATH.fullmatch(path) is None or path in targets or not os.path.lexists(path):
            continue
        targets.append(path)
    return targets


def harden_runner_paths(targets):
    changed = 0
    for path in targets:
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            continue
        if info.st_mode & 0o007:
            os.chmod(path, info.st_mode & ~0o007 & 0o7777)
            changed += 1
        if os.lstat(path).st_mode & 0o007:
            raise BoundaryRefusal("readback_failed", "runner_files")
    return changed


def _scan_file(path, needles, longest):
    hits = set()
    carry = b""
    used = 0
    with open(path, "rb") as source:
        while used < MAX_SCAN_BYTES:
            chunk = source.read(SCAN_CHUNK)
            if not chunk:
                break
            used += len(chunk)
            data = carry + chunk
            for index, (group, needle) in enumerate(needles):
                if needle in data:
                    hits.add(index)
            carry = data[-(longest - 1):] if longest > 1 else b""
    return hits, used


def walk_tree(needles, cutoff_ns, deadline, roots=("/",)):
    longest = max(len(needle) for unused, needle in needles)
    skip = set(SKIP_ROOTS)
    hits = []
    visited = 0
    scanned = 0
    total = 0
    complete = True
    stack = list(roots) + list(EXTRA_ROOTS)
    while stack:
        if time.monotonic() > deadline or total > TOTAL_SCAN_BUDGET:
            complete = False
            break
        directory = stack.pop()
        try:
            iterator = os.scandir(directory)
        except OSError:
            continue
        with iterator:
            for entry in iterator:
                path = entry.path
                if path in skip:
                    continue
                visited += 1
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
                elif stat.S_ISREG(info.st_mode) and info.st_ctime_ns >= cutoff_ns:
                    try:
                        found, used = _scan_file(path, needles, longest)
                    except OSError:
                        continue
                    scanned += 1
                    total += used
                    for index in found:
                        if len(hits) < MAX_HITS:
                            hits.append([path, needles[index][0]])
    return {"hits": hits, "visited": visited, "scanned": scanned, "complete": complete}


def probe_paths(entries, nonce):
    tested = 0
    leaks = []
    for index, path in entries:
        tested += 1
        leaked = False
        try:
            if os.path.isdir(path):
                os.listdir(path)
            else:
                with open(path, "rb") as source:
                    source.read(1)
            leaked = True
        except OSError:
            pass
        try:
            if os.path.isdir(path):
                probe = os.path.join(path, "kd-write-" + nonce)
                descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(descriptor)
                os.unlink(probe)
            else:
                descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
                os.close(descriptor)
            leaked = True
        except OSError:
            pass
        if leaked:
            leaks.append(index)
    return {"tested": tested, "leaks": leaks}


def scan_processes(needles):
    hits = []
    readable = 0
    pids = 0
    for item in sorted(os.listdir("/proc")):
        if not item.isdecimal():
            continue
        pids += 1
        for name in ("environ", "cmdline"):
            try:
                with open("/proc/" + item + "/" + name, "rb") as source:
                    data = source.read(ENVIRON_BYTES)
            except OSError:
                continue
            readable += 1
            for group, needle in needles:
                if needle in data and len(hits) < MAX_HITS:
                    hits.append([int(item), group])
    return {"hits": hits, "readable": readable, "pids": pids}


def become_project_user():
    linux_harness._drop_child(limits=(), socket_filter=False)
    if os.getuid() != PROJECT_UID or os.geteuid() != PROJECT_UID or os.getgid() != PROJECT_UID:
        raise BoundaryRefusal("readback_failed")
    try:
        with open("/etc/shadow", "rb") as source:
            source.read(1)
    except OSError:
        return
    raise BoundaryRefusal("readback_failed")


def decode_needles(items):
    needles = []
    for entry in items:
        if type(entry) is not list or len(entry) != 2 or type(entry[0]) is not int or type(entry[1]) is not str:
            raise ValueError("needles")
        needle = bytes.fromhex(entry[1])
        if len(needle) < MIN_CANARY_BYTES:
            raise ValueError("needles")
        needles.append((entry[0], needle))
    if not needles:
        raise ValueError("needles")
    return needles


def encode_needles(groups):
    items = []
    for group, needle_set in groups:
        for needle in needle_set:
            items.append([group, needle.hex()])
    return items


def walker_main(stdin, stdout):
    request = json.loads(stdin.read(MAX_REQUEST_BYTES + 1).decode("utf-8"))
    if type(request) is not dict or os.geteuid() != 0:
        return 2
    mode = request.get("mode")
    if mode == "paths":
        targets = request["targets"]
        nonce = request["nonce"]
        if type(targets) is not list or not all(type(item) is str and ABSOLUTE_PATH.fullmatch(item) for item in targets):
            return 2
        if type(nonce) is not str or re.fullmatch(r"[a-f0-9]{24}", nonce) is None:
            return 2
        entries = [(index, item) for index, item in enumerate(targets) if os.path.lexists(item)]
        become_project_user()
        result = probe_paths(entries, nonce)
    elif mode == "walk":
        needles = decode_needles(request["needles"])
        deadline = time.monotonic() + float(request["seconds"])
        cutoff_ns = int(request["cutoff_ns"])
        become_project_user()
        result = walk_tree(needles, cutoff_ns, deadline)
    elif mode == "environ":
        needles = decode_needles(request["needles"])
        become_project_user()
        result = scan_processes(needles)
    else:
        return 2
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(payload) > MAX_REPLY_BYTES:
        return 2
    stdout.write(payload)
    stdout.flush()
    return 0


def run_walker(request, timeout):
    try:
        completed = subprocess.run(
            [sys.executable, "-B", os.path.abspath(__file__), "--walker"],
            input=json.dumps(request).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            close_fds=True,
            env=WALKER_ENV,
        )
    except (OSError, subprocess.SubprocessError):
        raise BoundaryRefusal("scan_incomplete")
    if completed.returncode != 0 or len(completed.stdout) > MAX_REPLY_BYTES:
        raise BoundaryRefusal("scan_incomplete")
    try:
        result = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeError, ValueError):
        raise BoundaryRefusal("scan_incomplete")
    if type(result) is not dict:
        raise BoundaryRefusal("scan_incomplete")
    return result


def evaluate_walk(result, secret_group=GROUP_SECRET):
    if type(result.get("hits")) is not list or result.get("complete") is not True:
        raise BoundaryRefusal("scan_incomplete", "runner_files")
    groups = set()
    for entry in result["hits"]:
        if type(entry) is not list or len(entry) != 2 or type(entry[1]) is not int:
            raise BoundaryRefusal("scan_incomplete", "runner_files")
        groups.add(entry[1])
    return {
        "secret": secret_group in groups,
        "readable_control": GROUP_READABLE_CONTROL in groups,
        "private_control": GROUP_PRIVATE_CONTROL in groups,
    }


def evaluate_environ(result):
    if type(result.get("hits")) is not list or type(result.get("readable")) is not int:
        raise BoundaryRefusal("scan_incomplete", "process_memory")
    groups = set()
    for entry in result["hits"]:
        if type(entry) is not list or len(entry) != 2 or type(entry[1]) is not int:
            raise BoundaryRefusal("scan_incomplete", "process_memory")
        groups.add(entry[1])
    return {
        "secret": GROUP_SECRET in groups,
        "readable_control": GROUP_READABLE_CONTROL in groups,
        "private_control": GROUP_PRIVATE_CONTROL in groups,
        "readable": result["readable"] > 0,
    }


if __name__ == "__main__":
    if sys.argv[1:] == ["--walker"]:
        raise SystemExit(walker_main(sys.stdin.buffer, sys.stdout.buffer))
    raise SystemExit(2)
