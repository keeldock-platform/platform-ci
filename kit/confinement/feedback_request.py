"""Pure canonical feedback request records and one-use state transitions."""

import hashlib
import re


SCHEMA_VERSION = 1
REQUEST_DOMAIN = "node-feedback-request-v1"
WORKFLOW_REF = "refs/heads/main"
MAX_REQUEST_TTL_SECONDS = 24 * 60 * 60
EXCEPTION_END = 1_800_835_200
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_REQUEST_BYTES = 2048
MAX_TRACKED_REQUESTS = 4096
HEX40_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")

PROFILE_FIELDS = (
    "profile_id", "kind", "concern", "workflow_path", "producer_job", "auditor_job",
    "member_name",
)
_PROFILE_ROWS = (
    (1, "lock", "core-node-lock-return", ".github/workflows/node-lock-return.yml",
     "node-lock-return", "node-lock-return-audit", "lock-return-v1.enc"),
    (2, "rust_patch", "core-rust-format-return", ".github/workflows/core-rust-format-return.yml",
     "core-rust-format-return", "core-rust-format-return-audit", "rust-format-return-v1.enc"),
    (3, "build_diagnostics", "core-build-diagnostic-return",
     ".github/workflows/core-build-diagnostic-return.yml", "core-build-diagnostic-return",
     "core-build-diagnostic-return-audit", "build-diagnostic-return-v1.enc"),
)
PROFILES = {
    row[2]: dict(zip(PROFILE_FIELDS, row))
    for row in _PROFILE_ROWS
}
PROFILE_BY_KIND = {profile["kind"]: profile for profile in PROFILES.values()}

REQUEST_FIELDS = (
    "kind", "concern", "ci_repository_id", "workflow_path", "workflow_ref",
    "repository_id", "source_sha", "base_sha", "control_sha", "base_branch",
    "reviewed_diff_sha256", "recipient_fingerprint", "nonce", "expiry",
)
REQUEST_RECORD_FIELDS = frozenset(REQUEST_FIELDS)
FULL_REQUEST_FIELDS = frozenset(("request_id",) + REQUEST_FIELDS)
STATE_FIELDS = frozenset(("schema_version", "bootstrap_lock_consumed", "requests"))
ENTRY_FIELDS = frozenset((
    "request_id", "nonce", "recipient_fingerprint", "kind", "expiry", "status",
    "key_state", "tombstone_until",
))
ACTIVE_STATUS = "active"
TERMINAL_STATUSES = frozenset(("consumed", "expired", "abandoned"))


class RequestRefusal(Exception):
    def __init__(self):
        self.reason = "request_invalid"
        super().__init__(self.reason)


def _refuse():
    raise RequestRefusal()


def _exact_dict(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _safe_int(value, minimum=0, maximum=MAX_SAFE_INTEGER):
    return type(value) is int and minimum <= value <= maximum


def _valid_decimal(value):
    return (
        type(value) is str and len(value) <= 19
        and DECIMAL_RE.fullmatch(value) is not None and int(value) <= MAX_SAFE_INTEGER
    )


def _valid_hex(value, size):
    if type(value) is not str or len(value) != size:
        return False
    pattern = HEX40_RE if size == 40 else HEX64_RE
    return pattern.fullmatch(value) is not None


def _profile_for_values(values):
    if type(values) is not dict:
        _refuse()
    concern = values.get("concern")
    if type(concern) is not str:
        _refuse()
    profile = PROFILES.get(concern)
    if profile is None or values.get("kind") != profile["kind"]:
        _refuse()
    return profile


def _validate_values(values, now):
    if not _exact_dict(values, REQUEST_RECORD_FIELDS) or not _safe_int(now, minimum=1):
        _refuse()
    profile = _profile_for_values(values)
    if (not _valid_decimal(values["ci_repository_id"])
            or not _valid_decimal(values["repository_id"])
            or values["ci_repository_id"] == values["repository_id"]
            or values["workflow_path"] != profile["workflow_path"]
            or values["workflow_ref"] != WORKFLOW_REF
            or type(values["workflow_path"]) is not str
            or type(values["workflow_ref"]) is not str):
        _refuse()
    if any(not _valid_hex(values[name], 40) for name in ("source_sha", "base_sha", "control_sha")):
        _refuse()
    if values["base_branch"] not in ("main", "develop", "uat"):
        _refuse()
    if type(values["base_branch"]) is not str:
        _refuse()
    if (not _valid_hex(values["reviewed_diff_sha256"], 64)
            or not _valid_hex(values["recipient_fingerprint"], 64)
            or not _valid_hex(values["nonce"], 64)):
        _refuse()
    expiry = values["expiry"]
    if (not _safe_int(expiry, minimum=1, maximum=EXCEPTION_END)
            or expiry <= now or expiry - now > MAX_REQUEST_TTL_SECONDS):
        _refuse()
    return profile


def canonical_request(fields, *, now):
    """Return the bounded, ordered preimage used to calculate request_id."""
    _validate_values(fields, now)
    lines = [REQUEST_DOMAIN + "\n"]
    for name in REQUEST_FIELDS:
        value = fields[name]
        if type(value) is int:
            value = str(value)
        if type(value) is not str:
            _refuse()
        lines.append(name + "=" + value + "\n")
    try:
        encoded = "".join(lines).encode("ascii", "strict")
    except UnicodeError:
        _refuse()
    if len(encoded) > MAX_REQUEST_BYTES:
        _refuse()
    return encoded


def create_request(fields, *, now):
    """Validate fields and derive the request ID over their canonical preimage."""
    preimage = canonical_request(fields, now=now)
    request = dict(fields)
    request["request_id"] = hashlib.sha256(preimage).hexdigest()
    return request


def validate_request(request, *, now):
    """Check exact request fields and recompute the canonical request ID."""
    if not _exact_dict(request, FULL_REQUEST_FIELDS):
        _refuse()
    values = {name: request[name] for name in REQUEST_FIELDS}
    preimage = canonical_request(values, now=now)
    if (not _valid_hex(request["request_id"], 64)
            or request["request_id"] != hashlib.sha256(preimage).hexdigest()):
        _refuse()
    return _profile_for_values(values)


def encode_request(request, *, now):
    """Encode a canonical record with its derived request ID as the final line."""
    validate_request(request, now=now)
    preimage = canonical_request({name: request[name] for name in REQUEST_FIELDS}, now=now)
    try:
        return preimage + ("request_id=" + request["request_id"] + "\n").encode("ascii")
    except UnicodeError:
        _refuse()


def parse_request(record, *, now):
    """Parse only the exact bounded ASCII record; duplicate and reordered fields refuse."""
    if type(record) is not bytes or not 0 < len(record) <= MAX_REQUEST_BYTES:
        _refuse()
    if not record.endswith(b"\n") or b"\r" in record or b"\x00" in record:
        _refuse()
    try:
        lines = record.decode("ascii", "strict").split("\n")
    except UnicodeError:
        _refuse()
    if (lines[0] != REQUEST_DOMAIN or lines[-1] != ""
            or len(lines) != len(REQUEST_FIELDS) + 3):
        _refuse()
    values = {}
    for line, name in zip(lines[1:-2], REQUEST_FIELDS):
        if line.count("=") != 1:
            _refuse()
        field, value = line.split("=", 1)
        if field != name or not value:
            _refuse()
        values[field] = value
    request_line = lines[-2]
    if request_line.count("=") != 1:
        _refuse()
    request_key, request_id = request_line.split("=", 1)
    if request_key != "request_id" or not _valid_hex(request_id, 64):
        _refuse()
    if not _valid_decimal(values.get("expiry")):
        _refuse()
    values["expiry"] = int(values["expiry"])
    request = dict(values)
    request["request_id"] = request_id
    validate_request(request, now=now)
    if encode_request(request, now=now) != record:
        _refuse()
    return request


def empty_state():
    """Return the initial pure request-state value."""
    return {"schema_version": SCHEMA_VERSION, "bootstrap_lock_consumed": False, "requests": []}


def _validate_state(state):
    if (not _exact_dict(state, STATE_FIELDS)
            or type(state["schema_version"]) is not int
            or state["schema_version"] != SCHEMA_VERSION
            or type(state["bootstrap_lock_consumed"]) is not bool
            or type(state["requests"]) is not list
            or len(state["requests"]) > MAX_TRACKED_REQUESTS):
        _refuse()
    seen = set()
    seen_nonces = set()
    seen_fingerprints = set()
    consumed_lock = False
    for entry in state["requests"]:
        if (not _exact_dict(entry, ENTRY_FIELDS)
                or not _valid_hex(entry["request_id"], 64)
                or entry["request_id"] in seen
                or not _valid_hex(entry["nonce"], 64)
                or entry["nonce"] in seen_nonces
                or not _valid_hex(entry["recipient_fingerprint"], 64)
                or entry["recipient_fingerprint"] in seen_fingerprints
                or type(entry["kind"]) is not str or entry["kind"] not in PROFILE_BY_KIND
                or not _safe_int(entry["expiry"], minimum=1, maximum=EXCEPTION_END)):
            _refuse()
        seen.add(entry["request_id"])
        seen_nonces.add(entry["nonce"])
        seen_fingerprints.add(entry["recipient_fingerprint"])
        if type(entry["status"]) is not str or type(entry["key_state"]) is not str:
            _refuse()
        if type(entry["tombstone_until"]) is not int:
            _refuse()
        if entry["status"] == ACTIVE_STATUS:
            if entry["key_state"] != "present" or entry["tombstone_until"] != 0:
                _refuse()
        elif entry["status"] in TERMINAL_STATUSES:
            if (entry["key_state"] not in ("retirement_required", "retired")
                    or entry["tombstone_until"] != EXCEPTION_END):
                _refuse()
        else:
            _refuse()
        if entry["kind"] == "lock" and entry["status"] == "consumed":
            consumed_lock = True
    if state["bootstrap_lock_consumed"] != consumed_lock:
        _refuse()


def _transition_state(state, request_id, *, status, now=None):
    _validate_state(state)
    if not _valid_hex(request_id, 64):
        _refuse()
    for index, entry in enumerate(state["requests"]):
        if entry["request_id"] == request_id:
            if entry["status"] != ACTIVE_STATUS:
                _refuse()
            if status == "consumed":
                if (not _safe_int(now, minimum=1) or now >= entry["expiry"]
                        or entry["kind"] == "lock" and state["bootstrap_lock_consumed"]):
                    _refuse()
            elif status == "expired":
                if not _safe_int(now, minimum=1) or now < entry["expiry"]:
                    _refuse()
            elif status != "abandoned":
                _refuse()
            requests = [dict(item) for item in state["requests"]]
            requests[index].update({
                "status": status,
                "key_state": "retirement_required",
                "tombstone_until": EXCEPTION_END,
            })
            updated = dict(state)
            updated["requests"] = requests
            if status == "consumed" and entry["kind"] == "lock":
                updated["bootstrap_lock_consumed"] = True
            return updated
    _refuse()


def register_request(state, request, *, now):
    """Record a new request; terminal IDs remain tombstoned through the exception end."""
    _validate_state(state)
    profile = validate_request(request, now=now)
    if now >= EXCEPTION_END or len(state["requests"]) >= MAX_TRACKED_REQUESTS:
        _refuse()
    if any(
        entry["status"] == ACTIVE_STATUS and entry["expiry"] <= now
        for entry in state["requests"]
    ):
        _refuse()
    if state["bootstrap_lock_consumed"] and profile["kind"] == "lock":
        _refuse()
    if any(
        entry["request_id"] == request["request_id"]
        or entry["nonce"] == request["nonce"]
        or entry["recipient_fingerprint"] == request["recipient_fingerprint"]
        for entry in state["requests"]
    ):
        _refuse()
    updated = dict(state)
    updated["requests"] = [dict(entry) for entry in state["requests"]] + [{
        "request_id": request["request_id"],
        "nonce": request["nonce"],
        "recipient_fingerprint": request["recipient_fingerprint"],
        "kind": profile["kind"],
        "expiry": request["expiry"],
        "status": ACTIVE_STATUS,
        "key_state": "present",
        "tombstone_until": 0,
    }]
    return updated


def consume_request(state, request_id, *, now):
    """Tombstone before the wrapper releases authenticated plaintext to its caller."""
    return _transition_state(state, request_id, status="consumed", now=now)


def expire_request(state, request_id, *, now):
    """Retire an expired request and retain its replay tombstone."""
    return _transition_state(state, request_id, status="expired", now=now)


def abandon_request(state, request_id):
    """Retire a refused attempt; a retry must use a fresh request ID and key binding."""
    return _transition_state(state, request_id, status="abandoned")


def mark_key_retired(state, request_id):
    """Record wrapper confirmation that a terminal request's private key was retired."""
    _validate_state(state)
    if not _valid_hex(request_id, 64):
        _refuse()
    for index, entry in enumerate(state["requests"]):
        if (entry["request_id"] == request_id
                and entry["status"] in TERMINAL_STATUSES
                and entry["key_state"] == "retirement_required"):
            requests = [dict(item) for item in state["requests"]]
            requests[index]["key_state"] = "retired"
            updated = dict(state)
            updated["requests"] = requests
            return updated
    _refuse()
