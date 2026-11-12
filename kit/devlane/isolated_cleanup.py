"""Standard-library-only cleanup client for the privileged supervisor."""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


CLEANUP_SUBREASONS = frozenset((
    "umount-busy", "umount-missing", "tree-remove", "process-alive", "cgroup-nonempty",
))


class CleanupRefusal(RuntimeError):
    def __init__(self, reason):
        self.reason = reason if reason in CLEANUP_SUBREASONS else "tree-remove"
        super().__init__("cleanup-incomplete")


SOCKET_NAME = "control.sock"
PID_NAME = "host-pid"
NAMESPACE_PID_NAME = "namespace-pid"
PROC = "/proc"
"""Every wait below is bounded; the host client's deadline is derived from them so the fallback path is always reachable before the caller kills this process."""
CANCEL_RPC_SECONDS = 5
CLEANUP_RPC_SECONDS = 45
EXIT_WAIT_SECONDS = 10
EXIT_WAITS = 3
FALLBACK_SECONDS = 60
CLEANUP_BUDGET_SECONDS = CANCEL_RPC_SECONDS + CLEANUP_RPC_SECONDS + EXIT_WAIT_SECONDS * EXIT_WAITS + FALLBACK_SECONDS


def _frame(value):
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return len(payload).to_bytes(4, "big") + payload


def _read_exact(connection, size):
    value = bytearray()
    while len(value) < size:
        chunk = connection.recv(size - len(value))
        if not chunk:
            raise RuntimeError("cleanup-unavailable")
        value.extend(chunk)
    return bytes(value)


def _rpc(state, request, timeout):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(str(state / SOCKET_NAME))
        connection.sendall(_frame(request))
        size = int.from_bytes(_read_exact(connection, 4), "big")
        if size < 2 or size > 32768:
            raise RuntimeError("cleanup-response-invalid")
        response = json.loads(_read_exact(connection, size).decode("ascii", "strict"))
    finally:
        connection.close()
    if type(response) is dict and response.get("ok") is not True:
        code = response.get("code")
        prefix = "cleanup-incomplete:"
        if type(code) is str and code.startswith(prefix):
            reason = code[len(prefix):]
            if reason in CLEANUP_SUBREASONS:
                raise CleanupRefusal(reason)
    if type(response) is not dict or response.get("ok") is not True:
        raise RuntimeError("cleanup-refused")
    return response


def _pid(state):
    path = state / PID_NAME
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("cleanup-pid-invalid")
    raw = path.read_text(encoding="ascii")
    if not raw.isdecimal() or len(raw) > 10 or int(raw) < 2:
        raise RuntimeError("cleanup-pid-invalid")
    return int(raw)


def _parent_pid(pid):
    try:
        fields = Path(PROC, str(pid), "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
        return int(fields[1])
    except (OSError, UnicodeDecodeError, IndexError, ValueError):
        return None


def _descendants(root_pid):
    """Host-visible descendants of root_pid, by parent links in the host /proc."""
    try:
        names = [int(name) for name in os.listdir(PROC) if name.isdecimal()]
    except OSError:
        raise RuntimeError("cleanup-process-scan") from None
    children = {}
    for pid in names:
        parent = _parent_pid(pid)
        if parent is not None:
            children.setdefault(parent, []).append(pid)
    found, queue = [], [root_pid]
    while queue:
        for child in children.get(queue.pop(), ()):
            if child not in found:
                found.append(child)
                queue.append(child)
    return found


def discover_namespace_pid(parent_pid, state):
    """Host PID of the supervisor that runs inside the unshared PID namespace.

    The supervisor cannot report this itself: inside its namespace its PID is 1 and
    procfs mounted there only shows namespace-relative IDs. The privileged cleanup
    client resolves it from the host /proc: a descendant of the launcher whose
    command line is the supervisor for this exact state directory and whose PID
    namespace differs from this process's own.
    """
    own = os.stat(Path(PROC, "self", "ns", "pid")).st_ino
    token = str(state).encode("utf-8")
    matches = []
    for pid in _descendants(parent_pid):
        command = _process_command(pid)
        if b"supervisor.py" not in command or b"_serve" not in command or token not in command:
            continue
        try:
            namespace = os.stat(Path(PROC, str(pid), "ns", "pid")).st_ino
        except OSError:
            continue
        if namespace != own:
            matches.append(pid)
    if len(matches) > 1:
        raise RuntimeError("cleanup-process-identity")
    return matches[0] if matches else None


def _process_command(pid):
    try:
        return Path(PROC, str(pid), "cmdline").read_bytes().replace(b"\x00", b" ")
    except OSError:
        return b""


def _namespace_inodes(pid):
    result = set()
    for namespace in ("pid", "mnt", "net"):
        try:
            result.add(os.stat(Path(PROC, str(pid), "ns", namespace)).st_ino)
        except OSError:
            pass
    return result


def _namespace_members(inodes):
    if not inodes:
        return False
    try:
        candidates = [name for name in os.listdir(PROC) if name.isdecimal()]
    except OSError:
        return True
    for name in candidates:
        for namespace in ("pid", "mnt", "net"):
            try:
                if os.stat(Path(PROC, name, "ns", namespace)).st_ino in inodes:
                    return True
            except OSError:
                continue
    return False


def _wait_namespaces_absent(inodes, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _namespace_members(inodes):
            return True
        time.sleep(0.1)
    return not _namespace_members(inodes)


def _wait_absent(pid, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.1)
    return False


def _process_group_members(process_group):
    members = set()
    try:
        names = [name for name in os.listdir(PROC) if name.isdecimal()]
    except OSError:
        return None
    for name in names:
        try:
            fields = Path(PROC, name, "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
            if len(fields) >= 3 and fields[2].isdecimal() and int(fields[2]) == process_group:
                members.add(int(name))
        except (OSError, UnicodeDecodeError, IndexError, ValueError):
            continue
    return members


def _wait_process_group_absent(process_group, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        members = _process_group_members(process_group)
        if members == set():
            return True
        if members is None:
            return False
        time.sleep(0.1)
    return _process_group_members(process_group) == set()


def _fallback_terminate(state, parent_pid, namespace_pid, namespace_inodes):
    for pid in (namespace_pid, parent_pid):
        if not pid:
            continue
        cmdline = _process_command(pid)
        if cmdline and (b"supervisor.py" not in cmdline or b"_serve" not in cmdline):
            raise RuntimeError("cleanup-process-identity")
    if _process_command(parent_pid):
        subprocess.run(
            ["sudo", "-n", "kill", "--", "-" + str(parent_pid)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    if namespace_pid and _process_command(namespace_pid):
        subprocess.run(
            ["sudo", "-n", "kill", "-TERM", str(namespace_pid)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    for pid in (namespace_pid, parent_pid):
        if pid and not _wait_absent(pid, 3) and _process_command(pid):
            subprocess.run(
                ["sudo", "-n", "kill", "-KILL", str(pid)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
    group_absent = _wait_process_group_absent(parent_pid, 5)
    namespace_absent = _wait_namespaces_absent(namespace_inodes, 5) if namespace_inodes else group_absent
    return ((not namespace_pid or _wait_absent(namespace_pid, 5))
            and _wait_absent(parent_pid, 5) and group_absent and namespace_absent)


def _remove_state(state):
    for name in (SOCKET_NAME, "ready.json", PID_NAME, NAMESPACE_PID_NAME):
        path = state / name
        if path.exists() or path.is_symlink():
            path.unlink()


def _require_fallback_termination(state, parent_pid, namespace_pid, namespace_inodes):
    try:
        absent = _fallback_terminate(state, parent_pid, namespace_pid, namespace_inodes)
    except Exception:
        raise CleanupRefusal("process-alive") from None
    if not absent:
        raise CleanupRefusal("process-alive")


def cleanup(state_arg):
    state = Path(state_arg)
    if not state.is_absolute() or state.is_symlink() or not state.is_dir():
        raise RuntimeError("cleanup-state-invalid")
    parent_pid = _pid(state)
    parent_command = _process_command(parent_pid)
    if parent_command and (b"supervisor.py" not in parent_command or b"_serve" not in parent_command
                           or str(state).encode("utf-8") not in parent_command):
        raise RuntimeError("cleanup-process-identity")
    namespace_pid = discover_namespace_pid(parent_pid, state) if parent_command else None
    namespace_inodes = _namespace_inodes(namespace_pid) if namespace_pid else set()
    try:
        _rpc(state, {"op": "cancel"}, timeout=CANCEL_RPC_SECONDS)
    except Exception:
        pass
    try:
        response = _rpc(state, {"op": "cleanup"}, timeout=CLEANUP_RPC_SECONDS)
        if response.get("status") != "cleanup-confirmed":
            raise RuntimeError("cleanup-receipt-invalid")
    except Exception:
        _require_fallback_termination(state, parent_pid, namespace_pid, namespace_inodes)
        if os.path.ismount(state / "namespace-root"):
            raise CleanupRefusal("umount-busy") from None
        try:
            _remove_state(state)
        except OSError:
            raise CleanupRefusal("tree-remove") from None
        print("cleanup_fallback=absence-verified")
        print("cleanup_receipt=confirmed")
        return
    if not _wait_absent(parent_pid, EXIT_WAIT_SECONDS) or (namespace_pid and not _wait_absent(namespace_pid, EXIT_WAIT_SECONDS)) or not _wait_namespaces_absent(namespace_inodes, EXIT_WAIT_SECONDS):
        _require_fallback_termination(state, parent_pid, namespace_pid, namespace_inodes)
    if os.path.ismount(state / "namespace-root"):
        raise CleanupRefusal("umount-busy")
    try:
        _remove_state(state)
    except OSError:
        raise CleanupRefusal("tree-remove") from None
    print("cleanup_receipt=confirmed")


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2 or arguments[0] != "--state-dir":
        return 2
    try:
        cleanup(arguments[1])
        return 0
    except Exception as error:
        if isinstance(error, CleanupRefusal):
            print("cleanup_reason=" + error.reason, file=sys.stderr)
        print("cleanup_receipt=unconfirmed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
