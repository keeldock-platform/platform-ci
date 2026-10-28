"""Closed eleven-channel confinement verdict shared by the Linux and Windows source-admission runs.

One record schema and one fixed public line. Every field has a closed vocabulary or a bounded
numeric form, the key set is exact, and the decoder refuses unknown, missing, duplicate, reordered,
oversized or inconsistent input with a closed reason that never reflects the input.

Line format, one line, single spaces, tokens in this fixed order:

    KD-CONFINEMENT-VERDICT schema=1 confinement=<accepted|refused> os=<linux|windows>
    boundary=<identity> control-sha=<40 hex> run-id=<decimal> run-attempt=<decimal>
    <channel>=<status>/<before>/<after> for each of the eleven channels
    memory-canary=<result> readable-file-canary=<result> handoff=<result>
    project-execution=<result> gates=<n> failed=<n> token-revocation=<result>

The confinement field is derived, never trusted: it is accepted only when every channel is
blocked, every positive control fired both before and after the project phase, both canaries are
absent and the handoff state fits the operating system. A producer cannot assert it independently.
"""

import re


SCHEMA_VERSION = 1
LINE_PREFIX = "KD-CONFINEMENT-VERDICT"
MAX_LINE_BYTES = 1024
REQUIRED_GATES = 13
MAX_RUN_ID = 9007199254740991
CHANNELS = (
    "https",
    "dns",
    "redirect",
    "proxy",
    "runner_ipc",
    "raw_logs",
    "artifact_upload",
    "cache_upload",
    "runner_files",
    "process_memory",
    "boundary_disablement",
)
CHANNEL_STATUSES = ("blocked", "observed-leak", "not-run")
CANARY_RESULTS = ("absent", "present", "not-run")
OPERATING_SYSTEMS = ("linux", "windows")
BOUNDARIES = {"linux": "linux-ns-seccomp-uid", "windows": "lpac-job"}
HANDOFF_RESULTS = ("not-applicable", "verified", "failed", "not-run")
PROJECT_EXECUTION_RESULTS = ("completed", "not_started", "failed")
TOKEN_REVOCATION_RESULTS = ("confirmed", "unconfirmed", "not-applicable")
CONFINEMENT_RESULTS = ("accepted", "refused")
REFUSAL_REASONS = frozenset((
    "malformed", "size", "duplicate", "unknown_field", "missing_field", "order",
    "value", "schema", "inconsistent",
))
RECORD_FIELDS = frozenset((
    "os", "boundary", "control_sha", "run_id", "run_attempt", "channels",
    "memory_canary", "readable_file_canary", "handoff", "project_execution",
    "gates", "failed", "token_revocation",
))
CHANNEL_FIELDS = frozenset(("status", "before", "after"))
FIELD_ORDER = (
    "schema", "confinement", "os", "boundary", "control-sha", "run-id", "run-attempt",
) + CHANNELS + (
    "memory-canary", "readable-file-canary", "handoff", "project-execution",
    "gates", "failed", "token-revocation",
)
SHA_RE = re.compile(r"[a-f0-9]{40}")
RUN_ID_RE = re.compile(r"[1-9][0-9]{0,15}")
ATTEMPT_RE = re.compile(r"[1-9][0-9]?")
COUNT_RE = re.compile(r"0|[1-9][0-9]?")
CHANNEL_VALUE_RE = re.compile(r"(blocked|observed-leak|not-run)/([01])/([01])")
LINE_RE = re.compile(r"[\x20-\x7e]+")
TIMESTAMP_PREFIX_RE = re.compile(rb"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,16}Z ")


class VerdictRefusal(Exception):
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in REFUSAL_REASONS else "malformed"
        super().__init__(self.reason)


def _refuse(reason):
    raise VerdictRefusal(reason)


def _exact_int(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _member(value, allowed):
    return type(value) is str and value in allowed


def validate_record(record):
    """Refuse any record that is not exactly the closed schema."""
    if type(record) is not dict or set(record) != RECORD_FIELDS:
        _refuse("schema")
    if not _member(record["os"], OPERATING_SYSTEMS):
        _refuse("value")
    if record["boundary"] != BOUNDARIES[record["os"]]:
        _refuse("value")
    if type(record["control_sha"]) is not str or SHA_RE.fullmatch(record["control_sha"]) is None:
        _refuse("value")
    if not _exact_int(record["run_id"], 1, MAX_RUN_ID) or not _exact_int(record["run_attempt"], 1, 99):
        _refuse("value")
    channels = record["channels"]
    if type(channels) is not dict or set(channels) != set(CHANNELS):
        _refuse("schema")
    for name in CHANNELS:
        entry = channels[name]
        if type(entry) is not dict or set(entry) != CHANNEL_FIELDS:
            _refuse("schema")
        if (not _member(entry["status"], CHANNEL_STATUSES)
                or type(entry["before"]) is not bool or type(entry["after"]) is not bool):
            _refuse("value")
        if entry["status"] == "not-run" and (entry["before"] or entry["after"]):
            _refuse("inconsistent")
    if (not _member(record["memory_canary"], CANARY_RESULTS)
            or not _member(record["readable_file_canary"], CANARY_RESULTS)
            or not _member(record["handoff"], HANDOFF_RESULTS)
            or not _member(record["project_execution"], PROJECT_EXECUTION_RESULTS)
            or not _member(record["token_revocation"], TOKEN_REVOCATION_RESULTS)):
        _refuse("value")
    if (record["os"] == "linux") != (record["handoff"] == "not-applicable"):
        _refuse("inconsistent")
    if not _exact_int(record["gates"], 0, REQUIRED_GATES) or not _exact_int(record["failed"], 0, REQUIRED_GATES):
        _refuse("value")
    if record["failed"] > record["gates"]:
        _refuse("inconsistent")
    if record["project_execution"] == "not_started" and record["gates"] != 0:
        _refuse("inconsistent")
    if record["project_execution"] == "completed" and record["gates"] < 1:
        _refuse("inconsistent")


def confinement_accepted(record):
    """True only when every channel and control proves the boundary."""
    validate_record(record)
    for name in CHANNELS:
        entry = record["channels"][name]
        if entry["status"] != "blocked" or not entry["before"] or not entry["after"]:
            return False
    required_handoff = "not-applicable" if record["os"] == "linux" else "verified"
    return (record["memory_canary"] == "absent"
            and record["readable_file_canary"] == "absent"
            and record["handoff"] == required_handoff)


def run_accepted(record):
    """True only when the boundary is proved and every project gate ran and passed."""
    return (confinement_accepted(record)
            and record["project_execution"] == "completed"
            and record["gates"] == REQUIRED_GATES
            and record["failed"] == 0
            and record["token_revocation"] == "confirmed")


def _tokens(record):
    verdict = "accepted" if confinement_accepted(record) else "refused"
    values = [
        ("schema", str(SCHEMA_VERSION)),
        ("confinement", verdict),
        ("os", record["os"]),
        ("boundary", record["boundary"]),
        ("control-sha", record["control_sha"]),
        ("run-id", str(record["run_id"])),
        ("run-attempt", str(record["run_attempt"])),
    ]
    for name in CHANNELS:
        entry = record["channels"][name]
        values.append((name, entry["status"] + "/" + str(int(entry["before"])) + "/" + str(int(entry["after"]))))
    values.extend((
        ("memory-canary", record["memory_canary"]),
        ("readable-file-canary", record["readable_file_canary"]),
        ("handoff", record["handoff"]),
        ("project-execution", record["project_execution"]),
        ("gates", str(record["gates"])),
        ("failed", str(record["failed"])),
        ("token-revocation", record["token_revocation"]),
    ))
    return values


def encode_line(record):
    """Return the single fixed public line for a valid record, without a newline."""
    validate_record(record)
    line = LINE_PREFIX + "".join(" " + key + "=" + value for key, value in _tokens(record))
    if len(line) > MAX_LINE_BYTES:
        _refuse("size")
    return line


def _decimal(pattern, value, minimum, maximum):
    if pattern.fullmatch(value) is None:
        _refuse("value")
    number = int(value)
    if not minimum <= number <= maximum:
        _refuse("value")
    return number


def decode_line(raw):
    """Parse one public line strictly and return the record, or refuse with a closed reason."""
    if type(raw) is bytes:
        if len(raw) > MAX_LINE_BYTES + 1:
            _refuse("size")
        try:
            text = raw.decode("ascii", "strict")
        except UnicodeError:
            _refuse("malformed")
    elif type(raw) is str:
        if len(raw) > MAX_LINE_BYTES + 1:
            _refuse("size")
        text = raw
    else:
        _refuse("malformed")
    if text.endswith("\n"):
        text = text[:-1]
    if not text:
        _refuse("malformed")
    if len(text) > MAX_LINE_BYTES:
        _refuse("size")
    if LINE_RE.fullmatch(text) is None or text.startswith(" ") or text.endswith(" ") or "  " in text:
        _refuse("malformed")
    parts = text.split(" ")
    if parts[0] != LINE_PREFIX:
        _refuse("malformed")
    pairs = []
    seen = set()
    for token in parts[1:]:
        key, separator, value = token.partition("=")
        if not separator or not key or not value or "=" in value:
            _refuse("malformed")
        if key in seen:
            _refuse("duplicate")
        seen.add(key)
        pairs.append((key, value))
    if not seen.issubset(FIELD_ORDER):
        _refuse("unknown_field")
    if seen != set(FIELD_ORDER):
        _refuse("missing_field")
    if [key for key, unused in pairs] != list(FIELD_ORDER):
        _refuse("order")
    fields = dict(pairs)
    if fields["schema"] != str(SCHEMA_VERSION):
        _refuse("value")
    if not _member(fields["confinement"], CONFINEMENT_RESULTS):
        _refuse("value")
    channels = {}
    for name in CHANNELS:
        matched = CHANNEL_VALUE_RE.fullmatch(fields[name])
        if matched is None:
            _refuse("value")
        channels[name] = {
            "status": matched.group(1),
            "before": matched.group(2) == "1",
            "after": matched.group(3) == "1",
        }
    if SHA_RE.fullmatch(fields["control-sha"]) is None:
        _refuse("value")
    record = {
        "os": fields["os"],
        "boundary": fields["boundary"],
        "control_sha": fields["control-sha"],
        "run_id": _decimal(RUN_ID_RE, fields["run-id"], 1, MAX_RUN_ID),
        "run_attempt": _decimal(ATTEMPT_RE, fields["run-attempt"], 1, 99),
        "channels": channels,
        "memory_canary": fields["memory-canary"],
        "readable_file_canary": fields["readable-file-canary"],
        "handoff": fields["handoff"],
        "project_execution": fields["project-execution"],
        "gates": _decimal(COUNT_RE, fields["gates"], 0, REQUIRED_GATES),
        "failed": _decimal(COUNT_RE, fields["failed"], 0, REQUIRED_GATES),
        "token_revocation": fields["token-revocation"],
    }
    validate_record(record)
    expected = "accepted" if confinement_accepted(record) else "refused"
    if fields["confinement"] != expected:
        _refuse("inconsistent")
    return record


def find_lines(log):
    """Return the verdict lines in a log, tolerating a leading timestamp on each line."""
    if type(log) is not bytes:
        _refuse("malformed")
    prefix = LINE_PREFIX.encode("ascii")
    if log.startswith(b"\xef\xbb\xbf"):
        log = log[3:]
    found = []
    for line in log.splitlines():
        stamped = TIMESTAMP_PREFIX_RE.match(line)
        candidate = line[stamped.end():] if stamped is not None else line
        if candidate.startswith(prefix):
            found.append(candidate)
    return found
