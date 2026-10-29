"""Owner-side one-use key, request, and authenticated feedback filesystem wrapper."""

import base64
import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import threading
import time

try:
    from . import feedback_request, node_lock_receipt
except ImportError:
    import feedback_request
    import node_lock_receipt

try:
    import fcntl
except ImportError:
    fcntl = None


EXCEPTION_END = feedback_request.EXCEPTION_END
NODE_VERSION = "v24.22.1"
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
LABEL_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
RUST_PATH_RE = re.compile(r"^(?:[A-Za-z0-9_-][A-Za-z0-9._-]*/)*[A-Za-z0-9_-][A-Za-z0-9._-]*\.rs$\Z")
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_PACKET_BYTES = 256 * 1024
MAX_RUNTIME_BYTES = 256 * 1024 * 1024
MAX_NODE_INPUT_BYTES = 8 * 1024 * 1024
MAX_NODE_PUBLIC_OUTPUT_BYTES = 4096
MAX_KEY_BYTES = 16 * 1024
MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024 - 64 * 1024
MAX_SAFE_INTEGER = feedback_request.MAX_SAFE_INTEGER
REQUEST_INPUT_FIELDS = frozenset((
    "kind", "repository_id", "source_sha", "base_sha", "control_sha",
    "base_branch", "reviewed_diff_sha256", "expiry",
))
REQUEST_INPUT_FIELDS_WITH_WORKSPACE = REQUEST_INPUT_FIELDS | frozenset(("workspace",))
PACKET_FIELDS = frozenset((
    "schema_version", "request", "expected_manifest", "reviewed_rust_paths",
    "review_confirmed", "review_confirmed_at",
))
SUMMARY_REVIEW_FIELDS = frozenset((
    "confirmed", "request_id", "protected_repository_id", "protected_ref", "source_sha",
    "control_sha", "run_id", "run_attempt", "artifact_id", "reviewed_at", "ledger_ref",
    "summary_sections",
))
EVIDENCE_FIELDS = frozenset((
    "receipt", "api_evidence", "producer_output", "archive_bytes", "ci_repository_id",
    "actor_login", "artifact_name", "now",
))


class FeedbackAdminRefusal(Exception):
    """A bounded refusal that never includes request, key, or payload values."""

    def __init__(self):
        self.reason = "feedback_operation_refused"
        super().__init__(self.reason)


def _refuse():
    raise FeedbackAdminRefusal()


def _exact_dict(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _safe_int(value, minimum=0, maximum=MAX_SAFE_INTEGER):
    return type(value) is int and minimum <= value <= maximum


def _json_bytes(value, limit):
    _validate_json_value(value, budget=[100_000, limit])
    try:
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True)
        raw = encoded.encode("ascii", "strict")
    except Exception:
        _refuse()
    if not raw or len(raw) > limit:
        _refuse()
    return raw


def _json_string_size(value, limit):
    size = 2
    for character in value:
        codepoint = ord(character)
        if character in ('"', "\\") or character in ("\b", "\t", "\n", "\f", "\r"):
            size += 2
        elif codepoint < 0x20 or codepoint > 0x7e and codepoint <= 0xffff:
            size += 6
        elif codepoint > 0xffff:
            size += 12
        else:
            size += 1
        if size > limit:
            return limit + 1
    return size


def _consume_json_budget(budget, amount):
    budget[1] -= amount
    if budget[1] < 0:
        _refuse()


def _validate_json_value(value, depth=0, budget=None):
    if budget is None:
        budget = [100_000, MAX_NODE_INPUT_BYTES]
    budget[0] -= 1
    if budget[0] < 0 or depth > 48:
        _refuse()
    if value is None or type(value) is bool:
        _consume_json_budget(budget, 4 if value is None or value is True else 5)
        return
    if type(value) is str:
        _consume_json_budget(budget, _json_string_size(value, budget[1]))
        return
    if type(value) is int:
        if value.bit_length() > 53:
            _refuse()
        _consume_json_budget(budget, len(str(value)))
        return
    if type(value) is list:
        if len(value) > 50_000:
            _refuse()
        _consume_json_budget(budget, 2 + max(0, len(value) - 1))
        for item in value:
            _validate_json_value(item, depth + 1, budget)
        return
    if type(value) is dict:
        if len(value) > 100_000 or any(type(key) is not str for key in value):
            _refuse()
        _consume_json_budget(budget, 2 + max(0, len(value) - 1) + len(value))
        for key, item in value.items():
            _validate_json_value(key, depth + 1, budget)
            _validate_json_value(item, depth + 1, budget)
        return
    _refuse()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse()
        result[key] = value
    return result


def _parse_json(raw, limit):
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        _refuse()
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object,
                           parse_constant=lambda unused: _refuse())
    except Exception:
        _refuse()
    return value


def _valid_runtime_hash(value):
    return type(value) is str and len(value) == 64 and HEX64_RE.fullmatch(value) is not None


def _secure_runtime_path(path):
    if type(path) is not str or not os.path.isabs(path) or "\x00" in path:
        _refuse()
    parts = path.split(os.sep)
    if any(part in (".", "..") for part in parts if part):
        _refuse()
    current = os.sep
    path_parts = [piece for piece in parts if piece]
    for index, part in enumerate(path_parts):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except OSError:
            _refuse()
        if (stat.S_ISLNK(info.st_mode)
                or (index < len(path_parts) - 1 and (
                    not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                        and not info.st_mode & stat.S_ISVTX)
                ))):
            _refuse()
    try:
        info = os.lstat(path)
    except OSError:
        _refuse()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or not info.st_mode & 0o111):
        _refuse()
    return path


def _hash_file(path):
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        _refuse()
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                or info.st_size < 1 or info.st_size > MAX_RUNTIME_BYTES):
            _refuse()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError:
        _refuse()
    finally:
        os.close(fd)
    return digest.hexdigest()


def _private_dir(path, *, create):
    if type(path) is not str or not os.path.isabs(path) or "\x00" in path:
        _refuse()
    components = path.split(os.sep)
    if any(part in (".", "..") for part in components if part):
        _refuse()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(os.sep, flags)
    except OSError:
        _refuse()
    try:
        names = [part for part in components if part]
        if not names:
            _refuse()
        for index, name in enumerate(names):
            final = index == len(names) - 1
            try:
                next_fd = os.open(name, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                if not (create and final):
                    _refuse()
                try:
                    os.mkdir(name, 0o700, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                    next_fd = os.open(name, flags, dir_fd=parent_fd)
                except OSError:
                    _refuse()
            except OSError:
                _refuse()
            info = os.fstat(next_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                        and not info.st_mode & stat.S_ISVTX)):
                os.close(next_fd)
                _refuse()
            if final and stat.S_IMODE(info.st_mode) != 0o700:
                os.close(next_fd)
                _refuse()
            if not final and (stat.S_IMODE(info.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
                              and not info.st_mode & stat.S_ISVTX):
                os.close(next_fd)
                _refuse()
            if final:
                if info.st_uid != os.getuid():
                    os.close(next_fd)
                    _refuse()
                return next_fd
            os.close(parent_fd)
            parent_fd = next_fd
    finally:
        try:
            os.close(parent_fd)
        except OSError:
            pass
    _refuse()


def _check_file_info(info, mode, max_bytes):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode
            or info.st_size < 0 or info.st_size > max_bytes):
        _refuse()


def _read_named(dir_fd, name, *, mode, limit):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError:
        _refuse()
    try:
        info = os.fstat(fd)
        _check_file_info(info, mode, limit)
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                _refuse()
            chunks.append(chunk)
        if total != info.st_size:
            _refuse()
        return b"".join(chunks)
    except OSError:
        _refuse()
    finally:
        os.close(fd)


def _write_all(fd, payload):
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        offset += os.write(fd, view[offset:])


def _create_named(dir_fd, name, payload, *, mode=0o600, limit=MAX_PACKET_BYTES):
    if (type(name) is not str or "/" in name or "\x00" in name
            or type(payload) not in (bytes, bytearray) or not 0 < len(payload) <= limit):
        _refuse()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, mode, dir_fd=dir_fd)
    except OSError:
        _refuse()
    try:
        _write_all(fd, payload)
        os.fchmod(fd, mode)
        os.fsync(fd)
        _check_file_info(os.fstat(fd), mode, limit)
        os.fsync(dir_fd)
    except OSError:
        try:
            os.unlink(name, dir_fd=dir_fd)
        except OSError:
            pass
        _refuse()
    finally:
        os.close(fd)


def _atomic_replace(dir_fd, name, payload, *, mode=0o600, limit=MAX_STATE_BYTES):
    if type(name) is not str or "/" in name or type(payload) is not bytes or not 0 < len(payload) <= limit:
        _refuse()
    temporary = ".tmp-" + os.urandom(16).hex()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    try:
        fd = os.open(temporary, flags, mode, dir_fd=dir_fd)
        _write_all(fd, payload)
        os.fchmod(fd, mode)
        os.fsync(fd)
        _check_file_info(os.fstat(fd), mode, limit)
        os.close(fd)
        fd = None
        os.replace(temporary, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary, dir_fd=dir_fd)
        except OSError:
            pass
        _refuse()


def _has_secure_named(dir_fd, name, *, mode, limit):
    flags = getattr(os, "O_NOFOLLOW", 0)
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        _refuse()
    _check_file_info(info, mode, limit)
    if stat.S_ISLNK(info.st_mode):
        _refuse()
    return True


def _unlink_named(dir_fd, name, *, mode, limit):
    if not _has_secure_named(dir_fd, name, mode=mode, limit=limit):
        return False
    try:
        os.unlink(name, dir_fd=dir_fd)
        os.fsync(dir_fd)
    except OSError:
        _refuse()
    return True


def _request_file(request_id):
    if type(request_id) is not str or len(request_id) != 64 or HEX64_RE.fullmatch(request_id) is None:
        _refuse()
    return "packet-" + request_id + ".json"


def _key_file(nonce):
    if type(nonce) is not str or len(nonce) != 64 or HEX64_RE.fullmatch(nonce) is None:
        _refuse()
    return "key-" + nonce + ".der"


def _state_from_bytes(raw):
    if raw is None:
        return feedback_request.empty_state()
    state = _parse_json(raw, MAX_STATE_BYTES)
    try:
        feedback_request._validate_state(state)
    except Exception:
        _refuse()
    return state


def _valid_reviewed_rust_paths(paths):
    if type(paths) is not list or not 1 <= len(paths) <= 512:
        return False
    if any(type(path) is not str or len(path) > 256 or RUST_PATH_RE.fullmatch(path) is None
           or any(part in (".", "..") for part in path.split("/")) for path in paths):
        return False
    return len(set(paths)) == len(paths)


def _packet_from_bytes(raw, *, now):
    packet = _parse_json(raw, MAX_PACKET_BYTES)
    if (not _exact_dict(packet, PACKET_FIELDS) or type(packet["schema_version"]) is not int
            or packet["schema_version"] != 1 or packet["review_confirmed"] is not True
            or not _safe_int(packet["review_confirmed_at"], minimum=1, maximum=min(now, EXCEPTION_END))):
        _refuse()
    try:
        profile = feedback_request.validate_request(packet["request"], now=now)
    except Exception:
        _refuse()
    if profile["kind"] == "lock":
        if packet["expected_manifest"] is None or packet["reviewed_rust_paths"] != []:
            _refuse()
    elif profile["kind"] == "rust_patch":
        if packet["expected_manifest"] is not None or type(packet["reviewed_rust_paths"]) is not list:
            _refuse()
        paths = packet["reviewed_rust_paths"]
        if not _valid_reviewed_rust_paths(paths):
            _refuse()
    elif packet["expected_manifest"] is not None or packet["reviewed_rust_paths"] != []:
        _refuse()
    return packet, profile


class FeedbackAdmin:
    """One-use owner-side administration with template-bound Summary job names.

    Runtime path/hash, actor, repository, ordered Summary-writing jobs, and per-request
    expectations are trusted local configuration derived from reviewed private records.
    """

    def __init__(self, state_directory, *, node_runtime_path, node_runtime_sha256,
                 ci_repository_id, actor_login, summary_job_names):
        if os.name != "posix" or fcntl is None:
            _refuse()
        if type(state_directory) is not str or not os.path.isabs(state_directory):
            _refuse()
        if not _valid_runtime_hash(node_runtime_sha256):
            _refuse()
        if type(ci_repository_id) is not int or not 1 <= ci_repository_id <= MAX_SAFE_INTEGER:
            _refuse()
        if type(actor_login) is not str or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", actor_login):
            _refuse()
        if (type(summary_job_names) not in (tuple, list) or not 1 <= len(summary_job_names) <= 64
                or any(type(name) is not str or LABEL_RE.fullmatch(name) is None for name in summary_job_names)
                or len(set(summary_job_names)) != len(summary_job_names)):
            _refuse()
        self.state_directory = state_directory
        self.node_runtime_path = node_runtime_path
        self.node_runtime_sha256 = node_runtime_sha256
        self.ci_repository_id = ci_repository_id
        self.actor_login = actor_login
        self.summary_job_names = tuple(summary_job_names)

    def _now(self, *, before_end=True):
        now = self._clock_now()
        if before_end and now >= EXCEPTION_END:
            self._retire_at_end(now)
            _refuse()
        return now

    def _clock_now(self):
        try:
            now = int(time.time())
        except Exception:
            _refuse()
        if not _safe_int(now, minimum=1):
            _refuse()
        return now

    def _now_in_directory(self, dir_fd):
        now = self._clock_now()
        if now >= EXCEPTION_END:
            state = self._read_state(dir_fd)
            self._recover(dir_fd, state, now)
            _refuse()
        return now

    def _refresh_request(self, dir_fd, request_id):
        now = self._clock_now()
        state = self._recover(dir_fd, self._read_state(dir_fd), now)
        entry = next((item for item in state["requests"] if item["request_id"] == request_id), None)
        if now >= EXCEPTION_END or entry is None or entry["status"] != feedback_request.ACTIVE_STATUS:
            _refuse()
        packet, profile = self._read_packet(dir_fd, request_id, now=now)
        return now, state, entry, packet, profile

    def _check_release_window(self, request, gate, now):
        if now >= EXCEPTION_END or now >= request["expiry"]:
            _refuse()
        self._validate_summary_claim(gate, request, now)

    def _retire_at_end(self, now):
        try:
            with self._locked_directory(create=False) as dir_fd:
                state = self._read_state(dir_fd)
                self._recover(dir_fd, state, now)
        except FeedbackAdminRefusal:
            try:
                os.lstat(self.state_directory)
            except FileNotFoundError:
                return
            raise

    def _qualified_node(self):
        path = _secure_runtime_path(self.node_runtime_path)
        if _hash_file(path) != self.node_runtime_sha256:
            _refuse()
        try:
            result = subprocess.run(
                [path, "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, cwd=os.sep, env={"PATH": os.defpath},
                timeout=5, check=False, close_fds=True,
            )
        except Exception:
            _refuse()
        if result.returncode != 0 or result.stdout not in (b"v24.22.1\n", b"v24.22.1\r\n"):
            _refuse()
        return path

    def _helper_path(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feedback_admin_crypto.mjs")
        try:
            info = os.lstat(path)
        except OSError:
            _refuse()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            _refuse()
        return path

    def _run_helper(self, message, *, plaintext_pipe=False):
        node = self._qualified_node()
        helper = self._helper_path()
        if message.get("operation") == "decrypt":
            context = message.get("context")
            now = self._clock_now()
            if (type(context) is not dict or not _safe_int(context.get("expiry"), minimum=1, maximum=EXCEPTION_END)
                    or now >= EXCEPTION_END or now >= context["expiry"]):
                _refuse()
            message = dict(message)
            message["now"] = now
        read_fd = write_fd = None
        payload = None
        overflow = [False]
        reader_error = [False]
        if plaintext_pipe:
            try:
                read_fd, write_fd = os.pipe()
            except OSError:
                _refuse()
            message = dict(message)
            message["plaintext_fd"] = write_fd
        reader = None
        captured = bytearray()
        try:
            payload = _json_bytes(message, MAX_NODE_INPUT_BYTES)
            child_env = {"PATH": os.defpath}
            child = subprocess.Popen(
                [node, helper], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, cwd=os.sep, env=child_env,
                close_fds=True, pass_fds=(() if write_fd is None else (write_fd,)),
            )
            if write_fd is not None:
                os.close(write_fd)
                write_fd = None

                def drain_plaintext():
                    try:
                        while True:
                            chunk = os.read(read_fd, 65536)
                            if not chunk:
                                break
                            if len(captured) + len(chunk) <= MAX_PLAINTEXT_BYTES:
                                captured.extend(chunk)
                            else:
                                overflow[0] = True
                    except OSError:
                        reader_error[0] = True

                reader = threading.Thread(target=drain_plaintext, daemon=True)
                reader.start()
            try:
                stdout, unused_stderr = child.communicate(input=payload, timeout=60)
            except Exception:
                child.kill()
                child.wait(timeout=5)
                _refuse()
            if reader is not None:
                reader.join(timeout=10)
                if reader.is_alive():
                    _refuse()
            if child.returncode != 0 or len(stdout) > MAX_NODE_PUBLIC_OUTPUT_BYTES or overflow[0] or reader_error[0]:
                _refuse()
            return stdout, captured
        except FeedbackAdminRefusal:
            captured[:] = b"\x00" * len(captured)
            raise
        except Exception:
            captured[:] = b"\x00" * len(captured)
            _refuse()
        finally:
            if write_fd is not None:
                os.close(write_fd)
            if read_fd is not None:
                os.close(read_fd)

    @contextlib.contextmanager
    def _locked_directory(self, *, create):
        dir_fd = _private_dir(self.state_directory, create=create)
        lock_fd = None
        try:
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            try:
                lock_fd = os.open("state.lock", flags, 0o600, dir_fd=dir_fd)
            except OSError:
                _refuse()
            _check_file_info(os.fstat(lock_fd), 0o600, 0)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield dir_fd
        except FeedbackAdminRefusal:
            raise
        except Exception:
            _refuse()
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)
                except OSError:
                    pass
            os.close(dir_fd)

    def _read_state(self, dir_fd):
        raw = _read_named(dir_fd, "state.json", mode=0o600, limit=MAX_STATE_BYTES)
        return _state_from_bytes(raw)

    def _write_state(self, dir_fd, state):
        try:
            feedback_request._validate_state(state)
        except Exception:
            _refuse()
        _atomic_replace(dir_fd, "state.json", _json_bytes(state, MAX_STATE_BYTES))

    def _read_packet(self, dir_fd, request_id, *, now):
        raw = _read_named(dir_fd, _request_file(request_id), mode=0o600, limit=MAX_PACKET_BYTES)
        if raw is None:
            _refuse()
        packet, profile = _packet_from_bytes(raw, now=now)
        if packet["request"]["request_id"] != request_id:
            _refuse()
        return packet, profile

    def _retire_entry(self, dir_fd, state, entry):
        _unlink_named(dir_fd, _key_file(entry["nonce"]), mode=0o400, limit=MAX_KEY_BYTES)
        _unlink_named(dir_fd, _request_file(entry["request_id"]), mode=0o600, limit=MAX_PACKET_BYTES)
        if entry["key_state"] == "retirement_required":
            try:
                state = feedback_request.mark_key_retired(state, entry["request_id"])
            except Exception:
                _refuse()
            self._write_state(dir_fd, state)
        return state

    def _recover(self, dir_fd, state, now):
        for entry in list(state["requests"]):
            current = next((item for item in state["requests"] if item["request_id"] == entry["request_id"]), None)
            if current is None:
                continue
            if current["status"] == feedback_request.ACTIVE_STATUS:
                if now >= current["expiry"]:
                    try:
                        state = feedback_request.expire_request(
                            state, current["request_id"], now=max(now, current["expiry"]),
                        )
                    except Exception:
                        _refuse()
                    self._write_state(dir_fd, state)
                    current = next(item for item in state["requests"] if item["request_id"] == entry["request_id"])
                    state = self._retire_entry(dir_fd, state, current)
                else:
                    packet_raw = _read_named(
                        dir_fd, _request_file(current["request_id"]), mode=0o600, limit=MAX_PACKET_BYTES,
                    )
                    key_exists = _has_secure_named(
                        dir_fd, _key_file(current["nonce"]), mode=0o400, limit=MAX_KEY_BYTES,
                    )
                    if packet_raw is None or not key_exists:
                        try:
                            state = feedback_request.abandon_request(state, current["request_id"])
                        except Exception:
                            _refuse()
                        self._write_state(dir_fd, state)
                        current = next(item for item in state["requests"] if item["request_id"] == entry["request_id"])
                        state = self._retire_entry(dir_fd, state, current)
            elif current["key_state"] == "retirement_required":
                state = self._retire_entry(dir_fd, state, current)
        state = self._cleanup_orphans(dir_fd, state)
        return state

    def _cleanup_orphans(self, dir_fd, state):
        live_keys = {
            _key_file(entry["nonce"])
            for entry in state["requests"] if entry["status"] == feedback_request.ACTIVE_STATUS
        }
        live_packets = {
            _request_file(entry["request_id"])
            for entry in state["requests"] if entry["status"] == feedback_request.ACTIVE_STATUS
        }
        try:
            names = os.listdir(dir_fd)
        except OSError:
            _refuse()
        for name in names:
            if name.startswith("key-") and name.endswith(".der") and name not in live_keys:
                if re.fullmatch(r"key-[a-f0-9]{64}\.der", name) is None:
                    _refuse()
                _unlink_named(dir_fd, name, mode=0o400, limit=MAX_KEY_BYTES)
            elif name.startswith("packet-") and name.endswith(".json") and name not in live_packets:
                if re.fullmatch(r"packet-[a-f0-9]{64}\.json", name) is None:
                    _refuse()
                _unlink_named(dir_fd, name, mode=0o600, limit=MAX_PACKET_BYTES)
            elif name.startswith(".tmp-"):
                if re.fullmatch(r"\.tmp-[a-f0-9]{32}", name) is None:
                    _refuse()
                _unlink_named(dir_fd, name, mode=0o600, limit=MAX_STATE_BYTES)
        return state

    def _create_key(self, dir_fd, nonce):
        key_name = _key_file(nonce)
        key_path = os.path.join(self.state_directory, key_name)
        try:
            stdout, unused_plaintext = self._run_helper({"operation": "keygen", "private_key_path": key_path})
            result = _parse_json(stdout, MAX_NODE_PUBLIC_OUTPUT_BYTES)
            required = {"schema_version", "public_spki_base64", "recipient_fingerprint", "modulus_length", "public_exponent"}
            if (not _exact_dict(result, required) or type(result["schema_version"]) is not int
                    or result["schema_version"] != 1 or result["modulus_length"] != 3072
                    or result["public_exponent"] != "65537"
                    or type(result["public_spki_base64"]) is not str
                    or type(result["recipient_fingerprint"]) is not str
                    or HEX64_RE.fullmatch(result["recipient_fingerprint"]) is None):
                _refuse()
            public_spki = base64.b64decode(result["public_spki_base64"], validate=True)
            if (not 256 <= len(public_spki) <= 1024
                    or base64.b64encode(public_spki).decode("ascii") != result["public_spki_base64"]
                    or hashlib.sha256(public_spki).hexdigest() != result["recipient_fingerprint"]
                    or not _has_secure_named(dir_fd, key_name, mode=0o400, limit=MAX_KEY_BYTES)):
                _refuse()
            return result, public_spki
        except Exception:
            _unlink_named(dir_fd, key_name, mode=0o400, limit=MAX_KEY_BYTES)
            _refuse()

    def create_request(self, reviewed_fields, *, expected_manifest=None,
                       reviewed_rust_paths=None, confirm_reviewed=False):
        """Persist a fresh reviewed request and return only its canonical record and public key."""
        now = self._now()
        input_fields = (
            REQUEST_INPUT_FIELDS_WITH_WORKSPACE
            if type(reviewed_fields) is dict and "workspace" in reviewed_fields
            else REQUEST_INPUT_FIELDS
        )
        if not _exact_dict(reviewed_fields, input_fields) or confirm_reviewed is not True:
            _refuse()
        packet_limit_value = {
            "schema_version": 1,
            "reviewed_fields": reviewed_fields,
            "expected_manifest": expected_manifest,
            "reviewed_rust_paths": [] if reviewed_rust_paths is None else reviewed_rust_paths,
            "review_confirmed": True,
            "review_confirmed_at": now,
        }
        packet_limit_value = _parse_json(_json_bytes(packet_limit_value, MAX_PACKET_BYTES), MAX_PACKET_BYTES)
        reviewed_fields = packet_limit_value["reviewed_fields"]
        expected_manifest = packet_limit_value["expected_manifest"]
        reviewed_rust_paths = packet_limit_value["reviewed_rust_paths"]
        kind = reviewed_fields["kind"]
        profile = feedback_request.PROFILE_BY_KIND.get(kind) if type(kind) is str else None
        if profile is None:
            _refuse()
        if kind == "lock":
            if expected_manifest is None or reviewed_rust_paths != []:
                _refuse()
        elif kind == "rust_patch":
            if expected_manifest is not None or not _valid_reviewed_rust_paths(reviewed_rust_paths):
                _refuse()
        elif expected_manifest is not None or reviewed_rust_paths != []:
            _refuse()
        with self._locked_directory(create=True) as dir_fd:
            now = self._now_in_directory(dir_fd)
            state = self._read_state(dir_fd)
            state = self._recover(dir_fd, state, now)
            if any(item["status"] == feedback_request.ACTIVE_STATUS for item in state["requests"]):
                _refuse()
            nonce = os.urandom(32).hex()
            request_id = None
            try:
                public_info, unused_public_spki = self._create_key(dir_fd, nonce)
                now = self._clock_now()
                if now >= EXCEPTION_END:
                    _refuse()
                request_fields = {
                    "kind": kind,
                    "concern": profile["concern"],
                    "ci_repository_id": str(self.ci_repository_id),
                    "workflow_path": profile["workflow_path"],
                    "workflow_ref": feedback_request.WORKFLOW_REF,
                    "repository_id": reviewed_fields["repository_id"],
                    "source_sha": reviewed_fields["source_sha"],
                    "base_sha": reviewed_fields["base_sha"],
                    "control_sha": reviewed_fields["control_sha"],
                    "base_branch": reviewed_fields["base_branch"],
                    "reviewed_diff_sha256": reviewed_fields["reviewed_diff_sha256"],
                    "recipient_fingerprint": public_info["recipient_fingerprint"],
                    "nonce": nonce,
                    "expiry": reviewed_fields["expiry"],
                }
                if "workspace" in reviewed_fields:
                    request_fields["workspace"] = reviewed_fields["workspace"]
                request = feedback_request.create_request(request_fields, now=now)
                request_id = request["request_id"]
                canonical = feedback_request.encode_request(request, now=now)
                packet = {
                    "schema_version": 1,
                    "request": request,
                    "expected_manifest": expected_manifest,
                    "reviewed_rust_paths": [] if reviewed_rust_paths is None else reviewed_rust_paths,
                    "review_confirmed": True,
                    "review_confirmed_at": now,
                }
                packet_bytes = _json_bytes(packet, MAX_PACKET_BYTES)
                packet_name = _request_file(request_id)
                state = feedback_request.register_request(state, request, now=now)
                _create_named(dir_fd, packet_name, packet_bytes, limit=MAX_PACKET_BYTES)
                self._write_state(dir_fd, state)
                feedback_request.validate_request(request, now=self._clock_now())
                return {
                    "request": dict(request),
                    "canonical_record": canonical,
                    "public_spki_base64": public_info["public_spki_base64"],
                    "recipient_fingerprint": public_info["recipient_fingerprint"],
                }
            except Exception:
                if request_id is not None:
                    try:
                        persisted = self._read_state(dir_fd)
                        entry = next((item for item in persisted["requests"]
                                      if item["request_id"] == request_id), None)
                        if entry is not None and entry["status"] == feedback_request.ACTIVE_STATUS:
                            persisted = feedback_request.abandon_request(persisted, request_id)
                            self._write_state(dir_fd, persisted)
                            entry = next(item for item in persisted["requests"]
                                         if item["request_id"] == request_id)
                            self._retire_entry(dir_fd, persisted, entry)
                        else:
                            _unlink_named(dir_fd, _request_file(request_id), mode=0o600, limit=MAX_PACKET_BYTES)
                            _unlink_named(dir_fd, _key_file(nonce), mode=0o400, limit=MAX_KEY_BYTES)
                    except Exception:
                        pass
                else:
                    _unlink_named(dir_fd, _key_file(nonce), mode=0o400, limit=MAX_KEY_BYTES)
                _refuse()

    def expire_requests(self):
        """Retire expired keys while preserving request tombstones through the exception end."""
        self._now(before_end=False)
        with self._locked_directory(create=False) as dir_fd:
            state = self._read_state(dir_fd)
            now = self._clock_now()
            before = sum(item["status"] == feedback_request.ACTIVE_STATUS for item in state["requests"])
            state = self._recover(dir_fd, state, now)
            after = sum(item["status"] == feedback_request.ACTIVE_STATUS for item in state["requests"])
            return before - after

    def abandon_request(self, request_id):
        """Cancel an active request and retire its key while retaining its replay tombstone."""
        self._now(before_end=False)
        if type(request_id) is not str or len(request_id) != 64 or HEX64_RE.fullmatch(request_id) is None:
            _refuse()
        with self._locked_directory(create=False) as dir_fd:
            now = self._clock_now()
            state = self._recover(dir_fd, self._read_state(dir_fd), now)
            entry = next((item for item in state["requests"] if item["request_id"] == request_id), None)
            if entry is None or entry["status"] != feedback_request.ACTIVE_STATUS:
                _refuse()
            try:
                state = feedback_request.abandon_request(state, request_id)
            except Exception:
                _refuse()
            self._write_state(dir_fd, state)
            entry = next(item for item in state["requests"] if item["request_id"] == request_id)
            state = self._retire_entry(dir_fd, state, entry)
            return {"request_id": request_id, "status": "abandoned"}

    def _validate_summary_claim(self, gate, request, now):
        if not _exact_dict(gate, SUMMARY_REVIEW_FIELDS) or gate["confirmed"] is not True:
            _refuse()
        sections = gate["summary_sections"]
        if type(sections) is not list or len(sections) != len(self.summary_job_names):
            _refuse()
        for index, section in enumerate(sections):
            if (not _exact_dict(section, {"job_name", "status", "complete", "observer_record_id"})
                    or section["job_name"] != self.summary_job_names[index]
                    or section["status"] != "completed"
                    or section["complete"] is not True
                    or type(section["observer_record_id"]) is not str
                    or LABEL_RE.fullmatch(section["observer_record_id"]) is None):
                _refuse()
        if (gate["request_id"] != request["request_id"]
                or gate["protected_repository_id"] != request["repository_id"]
                or gate["protected_ref"] != request["workflow_ref"]
                or gate["source_sha"] != request["source_sha"]
                or gate["control_sha"] != request["control_sha"]
                or not _safe_int(gate["run_id"], minimum=1)
                or type(gate["run_attempt"]) is not int or gate["run_attempt"] != 1
                or not _safe_int(gate["artifact_id"], minimum=1)
                or not _safe_int(gate["reviewed_at"], minimum=1, maximum=now)
                or now - gate["reviewed_at"] > feedback_request.MAX_REQUEST_TTL_SECONDS
                or type(gate["ledger_ref"]) is not str or LABEL_RE.fullmatch(gate["ledger_ref"]) is None):
            _refuse()

    def _validate_summary_evidence(self, gate, request, evidence, trusted_context):
        api_run = evidence["api_evidence"]["run"]
        receipt = evidence["receipt"]
        if (gate["run_id"] != api_run["id"]
                or gate["artifact_id"] != receipt["artifact_id"]
                or trusted_context["request_id"] != request["request_id"]
                or trusted_context["source_sha"] != request["source_sha"]
                or trusted_context["control_sha"] != request["control_sha"]):
            _refuse()

    def _write_summary_gate(self, dir_fd, request, gate):
        record = {
            "schema_version": 1,
            "request_id": request["request_id"],
            "protected_repository_id": request["repository_id"],
            "protected_ref": request["workflow_ref"],
            "source_sha": request["source_sha"],
            "run_id": gate["run_id"],
            "run_attempt": gate["run_attempt"],
            "control_sha": gate["control_sha"],
            "artifact_id": gate["artifact_id"],
            "reviewed_at": gate["reviewed_at"],
            "ledger_ref": gate["ledger_ref"],
            "summary_sections": gate["summary_sections"],
            "manual_ui_review_confirmed": True,
            "api_evidence_is_not_summary_evidence": True,
        }
        name = "summary-" + request["request_id"] + ".json"
        payload = _json_bytes(record, 4096)
        prior = _read_named(dir_fd, name, mode=0o600, limit=4096)
        if prior is not None:
            if prior != payload:
                _refuse()
            return
        _create_named(dir_fd, name, payload, limit=4096)

    def _abandon_and_retire(self, dir_fd, state, entry):
        if entry["status"] == feedback_request.ACTIVE_STATUS:
            try:
                state = feedback_request.abandon_request(state, entry["request_id"])
            except Exception:
                _refuse()
            self._write_state(dir_fd, state)
            entry = next(item for item in state["requests"] if item["request_id"] == entry["request_id"])
        return self._retire_entry(dir_fd, state, entry)

    def _release_private_output(self, dir_fd, request, profile, plaintext):
        if (type(profile.get("max_payload_bytes")) is not int
                or len(plaintext) > profile["max_payload_bytes"]):
            _refuse()
        suffix = (
            "lock" if profile["kind"] == "lock" else "patch" if profile["kind"] == "rust_patch"
            else "cargo-lock" if profile["kind"] == feedback_request.CARGO_LOCK_KIND else "diagnostics"
        )
        name = "return-" + request["request_id"] + "-" + suffix + ".payload"
        _create_named(dir_fd, name, plaintext, mode=0o600, limit=MAX_PLAINTEXT_BYTES)
        return os.path.join(self.state_directory, name)

    def consume_return(self, request_id, api_client, *, manual_summary_review):
        """Collect authenticated run evidence, require the manual Summary ledger, then release once."""
        self._now()
        if type(request_id) is not str or len(request_id) != 64 or HEX64_RE.fullmatch(request_id) is None:
            _refuse()
        try:
            manual_summary_review = _parse_json(
                _json_bytes(manual_summary_review, 4096), 4096,
            )
        except Exception:
            _refuse()
        plaintext = None
        with self._locked_directory(create=False) as dir_fd:
            now, state, entry, packet, profile = self._refresh_request(dir_fd, request_id)
            request = packet["request"]
            try:
                self._validate_summary_claim(manual_summary_review, request, now)
                collection_time = now
                try:
                    try:
                        from . import feedback_api
                    except ImportError:
                        import feedback_api
                    evidence = feedback_api.collect_feedback_evidence(
                        api_client, request, expected_actor_login=self.actor_login,
                        run_id=str(manual_summary_review["run_id"]),
                        run_attempt=1, now=collection_time,
                    )
                except Exception:
                    _refuse()
                now, state, entry, packet, profile = self._refresh_request(dir_fd, request_id)
                request = packet["request"]
                self._check_release_window(request, manual_summary_review, now)
                if (not _exact_dict(evidence, EVIDENCE_FIELDS)
                        or type(evidence["now"]) is not int or evidence["now"] != collection_time):
                    _refuse()
                if (evidence["ci_repository_id"] != self.ci_repository_id
                        or evidence["actor_login"] != self.actor_login):
                    _refuse()
                trusted = node_lock_receipt.validate_receipt(
                    request, evidence["receipt"], evidence["api_evidence"], evidence["producer_output"],
                    evidence["archive_bytes"], ci_repository_id=evidence["ci_repository_id"],
                    actor_login=evidence["actor_login"], artifact_name=evidence["artifact_name"], now=now,
                )
                if trusted["context"]["request_id"] != request_id:
                    _refuse()
                self._validate_summary_evidence(
                    manual_summary_review, request, evidence, trusted["context"],
                )
                message = {
                    "operation": "decrypt",
                    "private_key_path": os.path.join(self.state_directory, _key_file(entry["nonce"])),
                    "context": trusted["context"],
                    "now": now,
                    "envelope_base64": base64.b64encode(trusted["ciphertext"]).decode("ascii"),
                }
                if packet["expected_manifest"] is not None:
                    message["expected_manifest"] = packet["expected_manifest"]
                if packet["reviewed_rust_paths"]:
                    message["reviewed_rust_paths"] = packet["reviewed_rust_paths"]
                stdout, plaintext = self._run_helper(message, plaintext_pipe=True)
                response = _parse_json(stdout, MAX_NODE_PUBLIC_OUTPUT_BYTES)
                if not _exact_dict(response, {"schema_version", "ok"}) or response != {"schema_version": 1, "ok": True}:
                    _refuse()
                if not 0 < len(plaintext) <= MAX_PLAINTEXT_BYTES:
                    _refuse()

                now, state, entry, packet, profile = self._refresh_request(dir_fd, request_id)
                request = packet["request"]
                self._check_release_window(request, manual_summary_review, now)
                trusted = node_lock_receipt.validate_receipt(
                    request, evidence["receipt"], evidence["api_evidence"], evidence["producer_output"],
                    evidence["archive_bytes"], ci_repository_id=evidence["ci_repository_id"],
                    actor_login=evidence["actor_login"], artifact_name=evidence["artifact_name"], now=now,
                )
                self._validate_summary_evidence(
                    manual_summary_review, request, evidence, trusted["context"],
                )
                self._write_summary_gate(dir_fd, request, manual_summary_review)

                now = self._clock_now()
                self._check_release_window(request, manual_summary_review, now)
                state = feedback_request.consume_request(state, request_id, now=now)
                self._write_state(dir_fd, state)
                entry = next(item for item in state["requests"] if item["request_id"] == request_id)
                state = self._retire_entry(dir_fd, state, entry)

                now = self._clock_now()
                self._check_release_window(request, manual_summary_review, now)
                trusted = node_lock_receipt.validate_receipt(
                    request, evidence["receipt"], evidence["api_evidence"], evidence["producer_output"],
                    evidence["archive_bytes"], ci_repository_id=evidence["ci_repository_id"],
                    actor_login=evidence["actor_login"], artifact_name=evidence["artifact_name"], now=now,
                )
                self._validate_summary_evidence(
                    manual_summary_review, request, evidence, trusted["context"],
                )
                now = self._clock_now()
                self._check_release_window(request, manual_summary_review, now)
                output_path = self._release_private_output(dir_fd, request, profile, plaintext)
                try:
                    self._check_release_window(request, manual_summary_review, self._clock_now())
                except Exception:
                    try:
                        _unlink_named(
                            dir_fd, os.path.basename(output_path), mode=0o600,
                            limit=MAX_PLAINTEXT_BYTES,
                        )
                    except Exception:
                        pass
                    _refuse()
                return {
                    "request_id": request_id,
                    "kind": profile["kind"],
                    "private_output_path": output_path,
                    "bootstrap_lock_consumed": state["bootstrap_lock_consumed"],
                }
            except Exception:
                try:
                    self._recover(dir_fd, self._read_state(dir_fd), self._clock_now())
                except Exception:
                    pass
                _refuse()
            finally:
                if isinstance(plaintext, bytearray):
                    plaintext[:] = b"\x00" * len(plaintext)

