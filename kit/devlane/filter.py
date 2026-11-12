"""Closed-schema, bounded public diagnostic filter."""

import argparse
import json
import os
import re
import sys
from pathlib import Path


MAX_RECORDS = 100
MAX_RECORD_BYTES = 512
MAX_RAW_RECORD_BYTES = 1024 * 1024
MAX_RAW_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_SUMMARY_BYTES = 16 * 1024
SCHEMA_VERSION = 1
LEVELS = frozenset(("error", "warning"))
STATUS = frozenset(("pass", "fail", "skip"))
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
CODE = re.compile(r"(?:TS[0-9]{4,5}|E[0-9]{4}|DEVLANE_[A-Z_]{1,32})\Z")
ALLOWED_STAGES = frozenset(("fetch", "prepare", "network", "decrypt", "format", "deny", "audit", "vet", "semver", "typecheck", "style", "unit", "browser", "d15", "cleanup"))
RECORD_FIELDS = {
    "diagnostic": frozenset(("kind", "stage", "code", "file", "line", "level")),
    "test": frozenset(("kind", "stage", "test")),
    "frame": frozenset(("kind", "frame", "status")),
    "control": frozenset(("kind", "stage", "status", "code", "subreason")),
    "coverage": frozenset(("kind", "stage", "suite", "total", "passed", "failed", "ignored")),
}
UNIT_FAILURE_SUBREASONS = frozenset((
    "report-missing", "adapter-failed", "filter-refused", "vitest-failed",
))


class FilterRefusal(ValueError):
    def __init__(self, code="report-invalid"):
        super().__init__(code)
        self.code = code


def _reject(code="report-invalid"):
    raise FilterRefusal(code)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate-json-key")
        result[key] = value
    return result


def _parse_record(line):
    if type(line) is not bytes or len(line) > MAX_RAW_RECORD_BYTES:
        _reject("raw-record-size")
    if b"\r" in line or b"\x1b" in line or any(byte < 0x20 and byte != 0x09 for byte in line):
        _reject("raw-control-character")
    try:
        record = json.loads(line.decode("utf-8", "strict"), object_pairs_hook=_object)
    except FilterRefusal:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        _reject("raw-json-invalid")
    if type(record) is not dict:
        _reject("raw-record-shape")
    return record


def _ascii_json(value):
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    except (TypeError, ValueError, RecursionError):
        _reject("output-serialization")
    if len(result) - 1 > MAX_RECORD_BYTES:
        _reject("output-record-size")
    if any(byte < 0x20 and byte != 0x0a for byte in result) or b"\r" in result or b"\x1b" in result:
        _reject("output-control-character")
    return result


def _line_value(value, path):
    if type(value) is not int or value < 1 or value > path["max_line"]:
        return None
    return value


def _validate_allowlists(allowlists):
    required = {"files", "tests", "frames", "stages", "codes", "max_lines", "suites"}
    if type(allowlists) is not dict or set(allowlists) != required:
        _reject("allowlist-shape")
    for key in ("files", "tests", "frames"):
        if type(allowlists[key]) is not dict:
            _reject("allowlist-shape")
        for name, public_id in allowlists[key].items():
            if (type(name) is not str or not name.isascii() or not name or len(name) > 2048
                    or type(public_id) is not str or not IDENTIFIER.fullmatch(public_id)):
                _reject("allowlist-entry")
    if type(allowlists["max_lines"]) is not dict:
        _reject("allowlist-lines")
    for name, limit in allowlists["max_lines"].items():
        if name not in allowlists["files"] or type(limit) is not int or limit < 1 or limit > 10_000_000:
            _reject("allowlist-lines")
    for key in ("stages", "codes"):
        if type(allowlists[key]) is not list or len(allowlists[key]) > 512:
            _reject("allowlist-catalog")
    if not set(allowlists["stages"]).issubset(ALLOWED_STAGES):
        _reject("allowlist-stage")
    if any(type(code) is not str or not CODE.fullmatch(code) for code in allowlists["codes"]):
        _reject("allowlist-code")
    if (type(allowlists["suites"]) is not list or len(allowlists["suites"]) > 512
            or any(type(item) is not str or not IDENTIFIER.fullmatch(item) for item in allowlists["suites"])
            or allowlists["suites"] != sorted(set(allowlists["suites"]))):
        _reject("allowlist-suite")


def _normalize(record, allowlists):
    kind = record.get("kind")
    if type(kind) is not str or kind not in RECORD_FIELDS or set(record) - RECORD_FIELDS[kind]:
        _reject("raw-schema")
    if kind == "diagnostic":
        stage = record.get("stage")
        code = record.get("code")
        if stage not in allowlists["stages"] or type(code) is not str:
            _reject("diagnostic-identity")
        if code not in allowlists["codes"]:
            code = "DEVLANE_FAILURE"
        file_id = None
        line = None
        raw_file = record.get("file")
        if raw_file is not None:
            if type(raw_file) is not str or raw_file not in allowlists["files"]:
                _reject("diagnostic-file")
            file_id = allowlists["files"][raw_file]
            line = _line_value(record.get("line"), {"max_line": allowlists["max_lines"].get(raw_file, 0)})
        level = record.get("level")
        if "level" in record and level not in LEVELS:
            _reject("diagnostic-level")
        output = {"kind": "diagnostic", "stage": stage, "code": code}
        if file_id is not None:
            output["file"] = file_id
            if line is not None:
                output["line"] = line
        if level is not None:
            output["level"] = level
        return output
    if kind == "test":
        stage = record.get("stage")
        test = record.get("test")
        if stage not in allowlists["stages"] or type(test) is not str or test not in allowlists["tests"]:
            _reject("test-identity")
        return {"kind": "test", "stage": stage, "test": allowlists["tests"][test]}
    if kind == "frame":
        frame = record.get("frame")
        status = record.get("status")
        if type(frame) is not str or frame not in allowlists["frames"] or status not in ("pass", "fail"):
            _reject("frame-identity")
        return {"kind": "frame", "frame": allowlists["frames"][frame], "status": status}
    if kind == "coverage":
        stage = record.get("stage")
        suite = record.get("suite")
        counts = [record.get(name) for name in ("total", "passed", "failed", "ignored")]
        expected_stage = (
            "format" if type(suite) is str and suite.startswith("fmt-") else
            "deny" if type(suite) is str and suite.startswith("deny-") else
            "audit" if type(suite) is str and suite.startswith("audit-") else
            "vet" if type(suite) is str and suite.startswith("vet-") else
            "semver" if suite == "semver-runtime" else "unit"
        )
        if (stage not in allowlists["stages"] or suite not in allowlists["suites"]
                or stage != expected_stage
                or any(type(value) is not int or value < 0 or value > 1_000_000 for value in counts)
                or suite.startswith(("root-", "runtime-", "listener-")) and counts[0] < 1
                or suite.startswith("fuzz-replay-") and counts[0] < 1
                or counts[1] + counts[2] + counts[3] != counts[0]):
            _reject("coverage-identity")
        return {"kind": "coverage", "stage": stage, "suite": suite,
                "total": counts[0], "passed": counts[1], "failed": counts[2], "ignored": counts[3]}
    stage = record.get("stage")
    status = record.get("status")
    code = record.get("code")
    if stage not in allowlists["stages"] or status not in STATUS:
        _reject("control-identity")
    subreason = record.get("subreason")
    if "subreason" in record and (
            stage != "unit" or status != "fail" or type(subreason) is not str
            or subreason not in UNIT_FAILURE_SUBREASONS):
        _reject("control-subreason")
    result = {"kind": "control", "stage": stage, "status": status}
    if code is not None:
        if type(code) is not str or not CODE.fullmatch(code):
            _reject("control-code")
        result["code"] = code if code in allowlists["codes"] else "DEVLANE_FAILURE"
    if "subreason" in record:
        result["subreason"] = subreason
    return result


def filter_records(raw_lines, allowlists, required_frames=()):
    _validate_allowlists(allowlists)
    raw_total = 0
    normalized = []
    for line in raw_lines:
        raw_total += len(line) + 1
        if raw_total > MAX_RAW_CAPTURE_BYTES:
            _reject("raw-capture-size")
        normalized.append(_normalize(_parse_record(line), allowlists))
        if len(normalized) > MAX_RECORDS:
            _reject("record-count")
    failures = [item for item in normalized if item.get("status") == "fail" or item.get("level") == "error"]
    if len(failures) > MAX_RECORDS:
        _reject("failure-count")
    frames = [item["frame"] for item in normalized if item["kind"] == "frame"]
    if len(frames) != len(set(frames)) or set(frames) != set(required_frames):
        if required_frames:
            _reject("frame-coverage")
    output = sorted({canonical for canonical in (_ascii_json(item) for item in normalized)})
    if len(output) > MAX_RECORDS or sum(map(len, output)) > MAX_SUMMARY_BYTES:
        _reject("summary-overflow")
    return b"".join(output)


def validate_public_summary(payload, allowlists, required_frames=()):
    if type(payload) is not bytes or len(payload) > MAX_SUMMARY_BYTES:
        _reject("summary-size")
    if payload and not payload.endswith(b"\n"):
        _reject("summary-newline")
    lines = payload.splitlines(keepends=True)
    if len(lines) > MAX_RECORDS:
        _reject("summary-count")
    canonical = filter_records([line[:-1] for line in lines], allowlists, required_frames)
    if canonical != payload:
        _reject("summary-noncanonical")
    return payload


def is_public_summary_record(line):
    """Return whether one canonical line belongs to the public summary grammar."""
    if type(line) is not bytes or not line or len(line) > MAX_RECORD_BYTES:
        return False
    try:
        record = _parse_record(line)
        files = {}
        tests = {}
        frames = {}
        suites = []
        codes = {"DEVLANE_FAILURE"}
        for field, target in (("file", files), ("test", tests), ("frame", frames)):
            value = record.get(field)
            if type(value) is str:
                target[value] = value
        suite = record.get("suite")
        if type(suite) is str:
            suites.append(suite)
        code = record.get("code")
        if type(code) is str and CODE.fullmatch(code):
            codes.add(code)
        allowlists = {
            "files": files,
            "tests": tests,
            "frames": frames,
            "stages": sorted(ALLOWED_STAGES),
            "codes": sorted(codes),
            "max_lines": {name: 10_000_000 for name in files},
            "suites": sorted(set(suites)),
        }
        return filter_records([line], allowlists) == line + b"\n"
    except (FilterRefusal, ValueError, TypeError, RecursionError):
        return False


def load_allowlists(path):
    from bundle import strict_json, Refusal
    value = strict_json(Path(path).read_bytes(), 4 * 1024 * 1024)
    if type(value) is not dict:
        raise FilterRefusal("allowlist-invalid")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowlists", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        input_path = Path(args.input)
        if input_path.stat().st_size > MAX_RAW_CAPTURE_BYTES:
            _reject("raw-capture-size")
        with input_path.open("rb") as source:
            lines = []
            for line in source:
                if not line.endswith(b"\n") or len(line) > MAX_RAW_RECORD_BYTES + 1:
                    _reject("raw-record-size")
                lines.append(line[:-1])
        result = filter_records(lines, load_allowlists(args.allowlists))
        output_path = Path(args.output)
        descriptor = os.open(str(output_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(result)
            destination.flush()
            os.fsync(destination.fileno())
        sys.stdout.buffer.write(result)
        return 0
    except FilterRefusal as error:
        print("devlane_filter_refusal=" + error.code, file=sys.stderr)
        return 2
    except Exception:
        print("devlane_filter_refusal=filter-failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
