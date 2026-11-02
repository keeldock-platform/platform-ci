import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path


TIER = "quick"
ADMISSION = "never"
SCHEMA_VERSION = 1
CONCERN = "core-linux-quick-return"
KIND = "linux_quick"
PRODUCER_JOB = "core-linux-quick-return-producer"
WORKFLOW_REF = "refs/heads/untrusted"
MEMBER_NAME = "linux-quick-return-v1.enc"
UPLOAD_DIRECTORY = "kd-quick-upload"
RECORDS_DIRECTORY = "kd-records"
FRAME_PREFIX = b"KD-LINUX-QUICK-PAYLOAD 1 "
LENGTH_DIGITS = 8
HEADER_BYTES = len(FRAME_PREFIX) + LENGTH_DIGITS + 1
PADDED_BYTES = 4 * 1024 * 1024 - 64 * 1024
MAX_BODY_BYTES = PADDED_BYTES - HEADER_BYTES
MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024
MAX_NODE_INPUT_BYTES = 6 * 1024 * 1024
STREAM_TAIL_BYTES = 64 * 1024
MIN_GATES = 13
MAX_GATES = 16
MAX_RECORD_BYTES = 65536
CONTEXT_LIFETIME_SECONDS = 23 * 60 * 60
SCREENED = "[screened]"
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,15}\Z")
COUNT_RE = re.compile(r"0|[1-9][0-9]?\Z")
GATE_NAME_RE = re.compile(r"[a-z][a-z_]{0,47}\Z")
IMAGE_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
BRANCHES = ("main", "develop", "uat")
OUTCOMES = ("passed", "failed", "not-run")
CHANNEL_STATUSES = ("blocked", "observed-leak", "not-run")
CANARY_RESULTS = ("absent", "present", "not-run")
GATE_RECORD_FIELDS = frozenset((
    "schema_version", "selected_gates", "completed_gates", "gates", "gate_count", "failed",
))
REASONS = frozenset((
    "request", "recipient", "binding", "records", "payload", "limit", "encryptor", "output", "usage",
    "invalid",
))
TOKEN_SHAPE = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{16,}|npm_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16})"
    r"(?:$|[^A-Za-z0-9])"
)
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY-----")
CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b(?:authorization|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd"
    r"|api[_-]?key|private[_-]?key|secret|token|credential)\b\s*[:=]\s*(?:Bearer\s+)?[^\s,;]{8,}",
    re.IGNORECASE,
)
BEARER_TOKEN = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{24,}={0,2}")
CREDENTIAL_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)
CREDENTIAL_PATTERNS = (
    TOKEN_SHAPE, PRIVATE_KEY_HEADER, CREDENTIAL_ASSIGNMENT, BEARER_TOKEN, CREDENTIAL_URL,
)


class QuickRefusal(Exception):
    def __init__(self, reason="invalid"):
        self.reason = reason if reason in REASONS else "invalid"
        super().__init__(self.reason)


def quick_line(request_id, selected, passed, failed):
    if (HEX64_RE.fullmatch(request_id or "") is None
            or any(type(value) is not int or not 0 <= value <= MAX_GATES for value in (selected, passed, failed))
            or passed > selected or failed > selected):
        raise QuickRefusal("invalid")
    return (
        "KD-LINUX-QUICK schema=1 request-id=" + request_id + " tier=quick admission=never"
        + " gates-selected=" + str(selected) + " gates-passed=" + str(passed)
        + " failed=" + str(failed) + " status=encrypted"
    )


def refusal_line(reason):
    return "KD-LINUX-QUICK-REFUSAL schema=1 tier=quick admission=never reason=" + (
        reason if reason in REASONS else "invalid"
    )


def _strict_base64(encoded, limit):
    if (type(encoded) is not str or not encoded or len(encoded) % 4 != 0
            or len(encoded) > (limit // 3 + 1) * 4):
        raise QuickRefusal("recipient")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise QuickRefusal("recipient") from None
    if len(raw) > limit or base64.b64encode(raw).decode("ascii") != encoded:
        raise QuickRefusal("recipient")
    return raw


def request_binding(environ):
    request_id = environ.get("KD_QUICK_REQUEST_ID", "")
    if (HEX64_RE.fullmatch(request_id) is None
            or request_id != environ.get("KD_QUICK_ALLOWED_REQUEST_ID")):
        raise QuickRefusal("request")
    encoded = environ.get("KD_QUICK_RECIPIENT_SPKI_B64", "")
    der = _strict_base64(encoded, 4096)
    if len(der) < 256 or der[:2] != b"\x30\x82":
        raise QuickRefusal("recipient")
    fingerprint = hashlib.sha256(der).hexdigest()
    if fingerprint != environ.get("KD_QUICK_ALLOWED_RECIPIENT_FINGERPRINT"):
        raise QuickRefusal("recipient")
    return request_id, encoded, fingerprint


def source_binding(environ):
    values = {
        "control_sha": environ.get("CI_SHA", ""),
        "source_sha": environ.get("REQUESTED_SOURCE_SHA", ""),
        "base_sha": environ.get("REQUESTED_BASE_SHA", ""),
        "reviewed_diff_sha256": environ.get("REQUESTED_FINGERPRINT", ""),
        "base_branch": environ.get("REQUESTED_BASE_BRANCH", ""),
        "repository_id": environ.get("SOURCE_REPOSITORY_ID", ""),
        "run_id": environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    if (any(SHA_RE.fullmatch(values[name]) is None for name in ("control_sha", "source_sha", "base_sha"))
            or HEX64_RE.fullmatch(values["reviewed_diff_sha256"]) is None
            or values["base_branch"] not in BRANCHES
            or DECIMAL_RE.fullmatch(values["repository_id"]) is None
            or DECIMAL_RE.fullmatch(values["run_id"]) is None
            or values["run_attempt"] != "1"):
        raise QuickRefusal("binding")
    return values


def _read_regular(path, maximum, tail=False):
    descriptor = -1
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise QuickRefusal("records")
        size = info.st_size
        if size > maximum and not tail:
            raise QuickRefusal("records")
        offset = max(0, size - maximum)
        os.lseek(descriptor, offset, os.SEEK_SET)
        wanted = size - offset
        chunks = []
        received = 0
        while received < wanted:
            chunk = os.read(descriptor, min(65536, wanted - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
        return b"".join(chunks), size
    except FileNotFoundError:
        return None, 0
    except OSError:
        raise QuickRefusal("records") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_json(path, required=True):
    data, unused_size = _read_regular(path, MAX_RECORD_BYTES)
    if data is None:
        if required:
            raise QuickRefusal("records")
        return None
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeError, ValueError):
        raise QuickRefusal("records") from None
    if type(value) is not dict:
        raise QuickRefusal("records")
    return value


def _gate_records(records):
    gates = _read_json(records / "gates.json")
    selected = gates.get("selected_gates")
    outcomes = gates.get("gates")
    if (set(gates) != GATE_RECORD_FIELDS or gates.get("schema_version") != 1
            or type(selected) is not list or not MIN_GATES <= len(selected) <= MAX_GATES
            or any(type(name) is not str or GATE_NAME_RE.fullmatch(name) is None for name in selected)
            or len(set(selected)) != len(selected)
            or type(outcomes) is not dict or set(outcomes) != set(selected)
            or any(outcomes[name] not in OUTCOMES for name in selected)
            or type(gates.get("gate_count")) is not int or type(gates.get("failed")) is not int):
        raise QuickRefusal("records")
    passed = sum(outcomes[name] == "passed" for name in selected)
    failed = sum(outcomes[name] == "failed" for name in selected)
    if (gates["failed"] != failed or gates["gate_count"] != passed + failed
            or gates.get("completed_gates") != [name for name in selected if outcomes[name] == "passed"]):
        raise QuickRefusal("records")
    return list(selected), dict(outcomes), passed, failed


def _durations(records, selected):
    value = _read_json(records / "gate-durations.json", required=False)
    result = {}
    entries = value.get("durations_ms") if value is not None and value.get("schema_version") == 1 else None
    if type(entries) is dict:
        for name in selected:
            duration = entries.get(name)
            if type(duration) is int and 0 <= duration <= 24 * 60 * 60 * 1000:
                result[name] = duration
    return result


def _boundary(records):
    merged = _read_json(records / "merged.json", required=False)
    channels = merged.get("channels") if merged is not None else None
    if type(channels) is not dict or len(channels) > 32:
        return None
    summary = {}
    for name in sorted(channels):
        entry = channels[name]
        if (type(name) is not str or GATE_NAME_RE.fullmatch(name) is None or type(entry) is not dict
                or entry.get("status") not in CHANNEL_STATUSES
                or type(entry.get("before")) is not bool or type(entry.get("after")) is not bool):
            return None
        summary[name] = entry["status"] + "/" + str(int(entry["before"])) + "/" + str(int(entry["after"]))
    memory = merged.get("memory_canary")
    readable = merged.get("readable_file_canary")
    if memory not in CANARY_RESULTS or readable not in CANARY_RESULTS:
        return None
    return {"channels": summary, "memory_canary": memory, "readable_file_canary": readable}


def _revocation(records):
    receipt = _read_json(records / "revocation.json", required=False)
    if receipt is None:
        return None
    status = receipt.get("status")
    return {
        "status": status if status in ("confirmed", "unconfirmed", "refused") else "unknown",
        "rejected_after_revoke": receipt.get("rejected_after_revoke") is True,
    }


def _streams(records, selected, outcomes):
    streams = []
    for index, name in enumerate(selected):
        entry = {"stdout": (b"", 0), "stderr": (b"", 0)}
        if outcomes[name] != "not-run":
            for stream in ("stdout", "stderr"):
                data, size = _read_regular(records / ("gate-" + str(index) + "." + stream), STREAM_TAIL_BYTES, True)
                entry[stream] = (data or b"", size)
        streams.append(entry)
    return streams


def screen_text(text):
    lines = text.splitlines(True)
    screened = 0
    kept = []
    for line in lines:
        if any(pattern.search(line) is not None for pattern in CREDENTIAL_PATTERNS):
            kept.append(SCREENED + "\n")
            screened += 1
        else:
            kept.append(line)
    result = "".join(kept)
    if any(pattern.search(result) is not None for pattern in CREDENTIAL_PATTERNS):
        return SCREENED + "\n", max(1, len(lines))
    return result, screened


def _tail(raw, size, cap):
    if cap <= 0 or not raw:
        return "", size > 0, 0
    piece = raw[-cap:]
    cut = size > len(piece)
    start = 0
    if cut:
        while start < len(piece) and start < 4 and (piece[start] & 0xC0) == 0x80:
            start += 1
    text, screened = screen_text(piece[start:].decode("utf-8", "replace"))
    return text, cut, screened


def _document(meta, selected, outcomes, durations, streams, cap):
    gates = []
    for index, name in enumerate(selected):
        out_raw, out_size = streams[index]["stdout"]
        err_raw, err_size = streams[index]["stderr"]
        out_text, out_cut, out_screened = _tail(out_raw, out_size, cap)
        err_text, err_cut, err_screened = _tail(err_raw, err_size, cap)
        gates.append({
            "name": name, "outcome": outcomes[name], "duration_ms": durations.get(name),
            "stdout_bytes": out_size, "stderr_bytes": err_size,
            "stdout_tail": out_text, "stderr_tail": err_text,
            "stdout_cut": out_cut, "stderr_cut": err_cut,
            "screened_lines": out_screened + err_screened,
        })
    document = dict(meta)
    document["gates"] = gates
    return document


def frame_payload(body):
    if type(body) is not bytes or len(body) > MAX_BODY_BYTES:
        raise QuickRefusal("limit")
    header = FRAME_PREFIX + (b"%0" + str(LENGTH_DIGITS).encode("ascii") + b"d") % len(body) + b"\n"
    return header + body + b" " * (PADDED_BYTES - len(header) - len(body))


def unframe_payload(data):
    if (type(data) is not bytes or len(data) != PADDED_BYTES or data[:len(FRAME_PREFIX)] != FRAME_PREFIX
            or data[HEADER_BYTES - 1:HEADER_BYTES] != b"\n"):
        raise QuickRefusal("payload")
    digits = data[len(FRAME_PREFIX):HEADER_BYTES - 1]
    if len(digits) != LENGTH_DIGITS or not digits.isdigit():
        raise QuickRefusal("payload")
    length = int(digits)
    body = data[HEADER_BYTES:HEADER_BYTES + length]
    if len(body) != length or data[HEADER_BYTES + length:].strip(b" ") != b"":
        raise QuickRefusal("payload")
    try:
        return json.loads(body.decode("ascii"))
    except (UnicodeError, ValueError):
        raise QuickRefusal("payload") from None


def build_payload(records, environ, request_id):
    records = Path(records)
    binding = source_binding(environ)
    selected, outcomes, passed, failed = _gate_records(records)
    durations = _durations(records, selected)
    streams = _streams(records, selected, outcomes)
    image_os = environ.get("ImageOS", "")
    image_version = environ.get("ImageVersion", "")
    meta = {
        "schema_version": SCHEMA_VERSION, "tier": TIER, "admission": ADMISSION, "concern": CONCERN,
        "request_id": request_id, "control_sha": binding["control_sha"],
        "source_sha": binding["source_sha"], "base_sha": binding["base_sha"],
        "base_branch": binding["base_branch"],
        "reviewed_diff_sha256": binding["reviewed_diff_sha256"],
        "run_id": int(binding["run_id"]), "run_attempt": 1,
        "image_os": image_os if IMAGE_RE.fullmatch(image_os) else "unknown",
        "image_version": image_version if IMAGE_RE.fullmatch(image_version) else "unknown",
        "gates_selected": len(selected), "gates_passed": passed, "gates_failed": failed,
        "revocation": _revocation(records), "boundary": _boundary(records),
    }
    cap = STREAM_TAIL_BYTES
    while True:
        document = _document(meta, selected, outcomes, durations, streams, cap)
        body = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if len(body) <= MAX_BODY_BYTES:
            return frame_payload(body), len(selected), passed, failed
        if cap == 0:
            raise QuickRefusal("limit")
        cap //= 2


def crypto_input(payload, request_id, recipient_spki_b64, fingerprint, binding, now, nonce):
    if type(payload) is not bytes or len(payload) != PADDED_BYTES or HEX64_RE.fullmatch(nonce) is None:
        raise QuickRefusal("payload")
    context = {
        "request_id": request_id, "nonce": nonce, "recipient_fingerprint": fingerprint,
        "concern": CONCERN, "kind": KIND, "repository_id": binding["repository_id"],
        "source_sha": binding["source_sha"], "base_sha": binding["base_sha"],
        "control_sha": binding["control_sha"], "base_branch": binding["base_branch"],
        "reviewed_diff_sha256": binding["reviewed_diff_sha256"], "workflow_ref": WORKFLOW_REF,
        "run_id": binding["run_id"], "producer_job": PRODUCER_JOB, "run_attempt": 1,
        "expiry": now + CONTEXT_LIFETIME_SECONDS,
    }
    return {
        "schema_version": 1, "kind": KIND,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "context": context, "recipient_spki_b64": recipient_spki_b64, "now": now,
    }


def encrypt_payload(input_record, node, helper, runner=subprocess.run):
    raw = json.dumps(input_record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_NODE_INPUT_BYTES:
        raise QuickRefusal("limit")
    node = Path(node)
    if not node.is_absolute() or node.name != "node":
        raise QuickRefusal("encryptor")
    try:
        result = runner(
            (str(node), str(helper)), input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": str(node.parent), "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C"},
            timeout=120, close_fds=True, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise QuickRefusal("encryptor") from None
    if result.returncode != 0 or result.stderr or not result.stdout or result.stdout[:4] != b"KDLE":
        raise QuickRefusal("encryptor")
    if len(result.stdout) > MAX_CIPHERTEXT_BYTES:
        raise QuickRefusal("limit")
    return bytes(result.stdout)


def write_ciphertext(runner_temp, data, uid, gid):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if (nofollow is None or directory_flag is None or type(data) is not bytes
            or not 1 <= len(data) <= MAX_CIPHERTEXT_BYTES
            or type(uid) is not int or type(gid) is not int):
        raise QuickRefusal("output")
    parent_fd = directory_fd = file_fd = -1
    try:
        parent_fd = os.open(str(runner_temp), os.O_RDONLY | directory_flag | nofollow)
        os.mkdir(UPLOAD_DIRECTORY, 0o700, dir_fd=parent_fd)
        directory_fd = os.open(UPLOAD_DIRECTORY, os.O_RDONLY | directory_flag | nofollow, dir_fd=parent_fd)
        os.fchown(directory_fd, uid, gid)
        os.fchmod(directory_fd, 0o700)
        file_fd = os.open(MEMBER_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600, dir_fd=directory_fd)
        os.fchown(file_fd, uid, gid)
        os.fchmod(file_fd, 0o400)
        offset = 0
        while offset < len(data):
            count = os.write(file_fd, data[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(file_fd)
        opened = os.fstat(file_fd)
        named = os.stat(MEMBER_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size != len(data) or stat.S_IMODE(opened.st_mode) != 0o400):
            raise OSError
        os.fsync(directory_fd)
    except (OSError, ValueError):
        raise QuickRefusal("output") from None
    finally:
        for descriptor in (file_fd, directory_fd, parent_fd):
            if descriptor >= 0:
                os.close(descriptor)
    return hashlib.sha256(data).hexdigest()


def _write_output(environ, values):
    path = environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "at", encoding="ascii") as sink:
        for key, value in values.items():
            sink.write(key + "=" + str(value) + "\n")


def _arguments(arguments, names):
    if len(arguments) != 2 * len(names):
        raise QuickRefusal("usage")
    values = {}
    for index, name in enumerate(names):
        if arguments[2 * index] != "--" + name or re.fullmatch(r"[0-9]{1,10}", arguments[2 * index + 1]) is None:
            raise QuickRefusal("usage")
        values[name] = int(arguments[2 * index + 1])
    return values


def run_preflight(environ):
    request_id, unused_spki, unused_fingerprint = request_binding(environ)
    source_binding(dict(environ, GITHUB_RUN_ATTEMPT="1"))
    return "KD-LINUX-QUICK-PREFLIGHT schema=1 request-id=" + request_id + " tier=quick admission=never status=verified"


def run_encrypt(environ, arguments, clock=time.time, randomness=os.urandom):
    ids = _arguments(arguments, ("reader-uid", "reader-gid"))
    request_id, spki, fingerprint = request_binding(environ)
    binding = source_binding(environ)
    runner_temp = environ.get("RUNNER_TEMP", "")
    node_bin = environ.get("NODE_BIN", "")
    if not runner_temp or not node_bin:
        raise QuickRefusal("binding")
    records = Path(runner_temp) / RECORDS_DIRECTORY
    payload, selected, passed, failed = build_payload(records, environ, request_id)
    now = int(clock())
    record = crypto_input(payload, request_id, spki, fingerprint, binding, now, randomness(32).hex())
    helper = Path(__file__).resolve().with_name("feedback_producer_crypto.mjs")
    ciphertext = encrypt_payload(record, Path(node_bin) / "node", helper)
    digest = write_ciphertext(runner_temp, ciphertext, ids["reader-uid"], ids["reader-gid"])
    _write_output(environ, {
        "gates_selected": selected, "gates_passed": passed, "gates_failed": failed,
        "ciphertext_sha256": digest,
    })
    return None


def run_record(environ):
    request_id = environ.get("KD_QUICK_REQUEST_ID", "")
    counts = []
    for name in ("KD_QUICK_GATES_SELECTED", "KD_QUICK_GATES_PASSED", "KD_QUICK_GATES_FAILED"):
        value = environ.get(name, "")
        if COUNT_RE.fullmatch(value) is None:
            raise QuickRefusal("invalid")
        counts.append(int(value))
    return quick_line(request_id, counts[0], counts[1], counts[2])


def main(arguments=None, environ=None, stdout=None):
    actual = list(sys.argv[1:] if arguments is None else arguments)
    env = os.environ if environ is None else environ
    sink = sys.stdout if stdout is None else stdout
    if not actual:
        sink.write(refusal_line("usage") + "\n")
        return 2
    try:
        if actual[0] == "preflight" and len(actual) == 1:
            line = run_preflight(env)
        elif actual[0] == "encrypt":
            line = run_encrypt(env, actual[1:])
        elif actual[0] == "record" and len(actual) == 1:
            line = run_record(env)
        else:
            raise QuickRefusal("usage")
    except QuickRefusal as error:
        sink.write(refusal_line(error.reason) + "\n")
        return 1
    except BaseException:
        sink.write(refusal_line("invalid") + "\n")
        return 1
    if line is not None:
        sink.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
