import json
import re


SCHEMA_VERSION = 1
LINE_PREFIX = "KD-LINUX"
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
PHASES = ("selftest", "recheck")
CHANNEL_STATUSES = ("blocked", "observed-leak", "not-run")
CANARY_RESULTS = ("absent", "present", "not-run")
PROJECT_RESULTS = ("not_started", "permitted")
REASONS = (
    "environment",
    "readback_failed",
    "session_failed",
    "control_not_fired",
    "channel_leak",
    "attempt_unexpected",
    "attempt_incomplete",
    "fixture_incomplete",
    "fixture_allowed",
    "canary_present",
    "scan_incomplete",
    "fault_mismatch",
)
DENIED = ("denied",)
CONTAINED = ("contained",)
ATTEMPT_RULES = {
    "https": (
        ("tls-ipv4", DENIED),
        ("tls-ipv6", DENIED),
        ("tls-hostname", DENIED),
    ),
    "dns": (
        ("getaddrinfo", DENIED),
        ("udp-query", DENIED),
        ("tcp-query", DENIED),
    ),
    "redirect": (
        ("http-redirect", DENIED),
    ),
    "proxy": (
        ("proxy-env-http", DENIED),
        ("proxy-connect", DENIED),
    ),
    "runner_ipc": (
        ("unix-path", DENIED),
        ("unix-abstract", DENIED),
        ("fd-inventory", DENIED),
    ),
    "raw_logs": (
        ("stdout-markers", CONTAINED),
        ("tty-open", DENIED),
        ("syslog-socket", DENIED),
        ("journal-socket", DENIED),
    ),
    "artifact_upload": (
        ("env-hunt", DENIED),
        ("endpoint-post", DENIED),
        ("staging-write", CONTAINED),
    ),
    "cache_upload": (
        ("env-hunt", DENIED),
        ("endpoint-post", DENIED),
        ("cache-write", CONTAINED),
    ),
    "process_memory": (
        ("mem-read", DENIED),
        ("environ-read", DENIED),
        ("ptrace-attach", DENIED),
        ("process-vm-readv", DENIED),
        ("control-self-memory", ("allowed",)),
        ("control-peer-environ", ("allowed",)),
    ),
    "boundary_disablement": (
        ("setuid-root", DENIED),
        ("unshare-user", DENIED),
        ("unshare-namespaces", DENIED),
        ("mount-tmpfs", DENIED),
        ("usr-remount-rw", DENIED),
        ("sysctl-write", DENIED),
        ("signal-init", DENIED),
        ("chroot-escape", DENIED),
        ("nnp-clear", DENIED),
        ("sudo", DENIED),
        ("docker", DENIED),
        ("ip-link", DENIED),
        ("nsenter", DENIED),
    ),
}
OPTIONAL_ATTEMPTS = {
    "boundary_disablement": ("sudo", "docker", "ip-link", "nsenter"),
}
BOUNDARY_CONTROL_ATTEMPTS = (
    "setuid-root",
    "mount-tmpfs",
    "usr-remount-rw",
    "sysctl-write",
    "signal-init",
    "chroot-escape",
)
NETWORK_CHANNELS = (
    "https",
    "dns",
    "redirect",
    "proxy",
    "runner_ipc",
    "artifact_upload",
    "cache_upload",
)
ATTEMPT_LINE = re.compile(r"KDATT ([a-z0-9-]{1,40}) (denied|allowed|contained|na|other)")
MAX_REFUSAL_DETAIL = 99


class BoundaryRefusal(Exception):
    def __init__(self, reason, channel=None, detail=None):
        if reason not in REASONS:
            reason = "environment"
        if channel is not None and channel not in CHANNELS:
            channel = None
        if detail is not None and (type(detail) is not int or detail < 0 or detail > MAX_REFUSAL_DETAIL):
            detail = None
        super().__init__(reason)
        self.reason = reason
        self.channel = channel
        self.detail = detail


def parse_attempts(output):
    results = []
    for raw in output.split(b"\n"):
        if not raw.startswith(b"KDATT "):
            continue
        try:
            line = raw.decode("ascii", "strict")
        except UnicodeError:
            results.append(("invalid", "other"))
            continue
        matched = ATTEMPT_LINE.fullmatch(line)
        if matched is None:
            results.append(("invalid", "other"))
        else:
            results.append((matched.group(1), matched.group(2)))
    return results


def judge_attempts(rules, output, optional=()):
    seen = {}
    for name, result in parse_attempts(output):
        if name in seen:
            return "unexpected"
        seen[name] = result
    expected = {name: accepted for name, accepted in rules}
    if set(seen) - set(expected):
        return "unexpected"
    if set(expected) - set(seen):
        return "incomplete"
    leaked = False
    for name, accepted in rules:
        result = seen[name]
        if name.startswith("control-"):
            continue
        if result == "na" and name in optional:
            continue
        if result in accepted:
            continue
        if result == "allowed":
            leaked = True
        else:
            return "unexpected"
    return "leak" if leaked else "ok"


def control_attempts_allowed(output, required):
    seen = dict(parse_attempts(output))
    return bool(required) and all(seen.get(name) == "allowed" for name in required)


def valid_nonce(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{24}", value) is not None


def channel_line(phase, channel, status, control):
    if phase not in PHASES or channel not in CHANNELS or status not in CHANNEL_STATUSES:
        raise ValueError("channel-line")
    return (
        LINE_PREFIX + "-CHANNEL schema=" + str(SCHEMA_VERSION)
        + " phase=" + phase + " channel=" + channel
        + " status=" + status + " control=" + str(int(bool(control)))
    )


def canary_line(phase, memory_canary, readable_file_canary):
    if phase not in PHASES or memory_canary not in CANARY_RESULTS or readable_file_canary not in CANARY_RESULTS:
        raise ValueError("canary-line")
    return (
        LINE_PREFIX + "-CANARY schema=" + str(SCHEMA_VERSION)
        + " phase=" + phase + " memory-canary=" + memory_canary
        + " readable-file-canary=" + readable_file_canary
    )


def readback_line(phase, fields):
    if phase not in PHASES:
        raise ValueError("readback-line")
    keys = ("ptrace-scope", "project-uid", "usr-submounts", "runner-uid-distinct")
    if tuple(key for key, unused in fields) != keys:
        raise ValueError("readback-line")
    for key, value in fields:
        if type(value) is not str or re.fullmatch(r"[a-z0-9-]{1,12}", value) is None:
            raise ValueError("readback-line")
    return LINE_PREFIX + "-READBACK schema=" + str(SCHEMA_VERSION) + " phase=" + phase + "".join(
        " " + key + "=" + value for key, value in fields
    )


def verdict_line(phase, refusal, blocked_count):
    if phase not in PHASES or type(blocked_count) is not int or not 0 <= blocked_count <= len(CHANNELS):
        raise ValueError("verdict-line")
    if refusal is None:
        return (
            "linux-source-boundary=accepted phase=" + phase
            + " channels=" + str(blocked_count) + "/" + str(len(CHANNELS))
            + " project-execution=permitted"
        )
    text = "linux-source-boundary=refused phase=" + phase + " reason=" + refusal.reason
    if refusal.channel is not None:
        text += " channel=" + refusal.channel
    if refusal.detail is not None:
        text += " detail=" + str(refusal.detail)
    return text + " project-execution=not_started"


def empty_record(phase):
    return {
        "schema": SCHEMA_VERSION,
        "phase": phase,
        "channels": {name: {"status": "not-run", "control": False} for name in CHANNELS},
        "memory_canary": "not-run",
        "readable_file_canary": "not-run",
        "fixtures": "not-run",
        "result": "refused",
        "reason": "environment",
    }


def validate_record(record):
    if type(record) is not dict:
        raise ValueError("record")
    if set(record) != {"schema", "phase", "channels", "memory_canary", "readable_file_canary", "fixtures", "result", "reason"}:
        raise ValueError("record")
    if record["schema"] != SCHEMA_VERSION or record["phase"] not in PHASES:
        raise ValueError("record")
    channels = record["channels"]
    if type(channels) is not dict or set(channels) != set(CHANNELS):
        raise ValueError("record")
    for name in CHANNELS:
        entry = channels[name]
        if type(entry) is not dict or set(entry) != {"status", "control"}:
            raise ValueError("record")
        if entry["status"] not in CHANNEL_STATUSES or type(entry["control"]) is not bool:
            raise ValueError("record")
        if entry["status"] == "not-run" and entry["control"]:
            raise ValueError("record")
    if record["memory_canary"] not in CANARY_RESULTS or record["readable_file_canary"] not in CANARY_RESULTS:
        raise ValueError("record")
    if record["fixtures"] not in ("complete", "not-run", "failed"):
        raise ValueError("record")
    if record["result"] not in ("accepted", "refused") or record["reason"] not in REASONS + ("none",):
        raise ValueError("record")
    if (record["result"] == "accepted") != (record["reason"] == "none"):
        raise ValueError("record")
    return record


def record_accepts(record, require_fixtures=True):
    validate_record(record)
    if record["result"] != "accepted":
        return False
    return (
        all(record["channels"][name]["status"] == "blocked" and record["channels"][name]["control"] for name in CHANNELS)
        and record["memory_canary"] == "absent"
        and record["readable_file_canary"] == "absent"
        and (record["fixtures"] == "complete" or not require_fixtures)
    )


def combine_canary(first, second):
    if "present" in (first, second):
        return "present"
    if first == "absent" and second == "absent":
        return "absent"
    return "not-run"


def dump_record(record):
    validate_record(record)
    return json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"


def load_record(text):
    if type(text) is not str or len(text) > 8192:
        raise ValueError("record")
    return validate_record(json.loads(text))


def merge_records(selftest, recheck):
    validate_record(selftest)
    validate_record(recheck)
    if selftest["phase"] != "selftest" or recheck["phase"] != "recheck":
        raise ValueError("merge")
    channels = {}
    for name in CHANNELS:
        first = selftest["channels"][name]
        second = recheck["channels"][name]
        if "observed-leak" in (first["status"], second["status"]):
            status = "observed-leak"
        elif "not-run" in (first["status"], second["status"]):
            status = "not-run"
        else:
            status = "blocked"
        channels[name] = {"status": status, "before": first["control"], "after": second["control"]}
    return {
        "channels": channels,
        "memory_canary": combine_canary(selftest["memory_canary"], recheck["memory_canary"]),
        "readable_file_canary": combine_canary(selftest["readable_file_canary"], recheck["readable_file_canary"]),
        "fixtures": selftest["fixtures"],
        "accepted": record_accepts(selftest) and record_accepts(recheck, require_fixtures=False),
    }


def control_markers(channel, nonce, ipv6):
    if not valid_nonce(nonce):
        raise ValueError("nonce")
    table = {
        "https": [("https4", "v4-" + nonce), ("https4", "host-" + nonce)],
        "dns": [("dns_udp", "g-" + nonce), ("dns_udp", "r-" + nonce), ("dns_tcp", "t-" + nonce)],
        "redirect": [("redirect_a", "redirect/x-" + nonce), ("redirect_b", "sink/x-" + nonce)],
        "proxy": [("proxy", "p-" + nonce), ("proxy", "c-" + nonce)],
        "runner_ipc": [("unix", "u-" + nonce), ("abstract", "a-" + nonce)],
        "artifact_upload": [("artifact", "art-" + nonce)],
        "cache_upload": [("cache", "cache-" + nonce)],
    }
    if channel not in table:
        raise ValueError("channel")
    markers = list(table[channel])
    if channel == "https" and ipv6:
        markers.append(("https6", "v6-" + nonce))
    return tuple(markers)


def extra_control_attempt(channel):
    return {"runner_ipc": "fd-inventory", "artifact_upload": "env-hunt", "cache_upload": "env-hunt"}.get(channel)


def control_names(channel):
    return tuple(name for name, accepted in ATTEMPT_RULES.get(channel, ()) if name.startswith("control-"))
