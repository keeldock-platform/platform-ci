"""Bounded public formatting for trusted core-driver refusals."""

import importlib.util
import json
from pathlib import Path
import sys


MAX_INPUT_BYTES = 16 * 1024
REFUSAL_PREFIX = b"KD-FEEDBACK-PRODUCER-REFUSAL "
RECORD_FIELDS = frozenset(("diagnostic", "reason", "schema_version", "stage", "status"))
UNAVAILABLE_RECORD = {
    "diagnostic": "unavailable",
    "reason": "internal_error",
    "schema_version": 1,
    "stage": "internal",
    "status": "refused",
}


def _load_core_contract():
    path = (Path(__file__).resolve(strict=True).parent / "macos_core_contract.py").resolve(strict=True)
    if path.parent != Path(__file__).resolve(strict=True).parent or not path.is_file():
        raise ImportError("refusal contract unavailable")
    spec = importlib.util.spec_from_file_location("_feedback_failure_core_contract", str(path))
    if spec is None or spec.loader is None:
        raise ImportError("refusal contract unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except BaseException:
        raise ImportError("refusal contract unavailable") from None
    return module


try:
    _CORE_CONTRACT = _load_core_contract()
except BaseException:
    _CORE_CONTRACT = None
REASONS = getattr(_CORE_CONTRACT, "REASONS", frozenset())
STAGES = getattr(_CORE_CONTRACT, "STAGES", frozenset())
DIAGNOSTICS = getattr(_CORE_CONTRACT, "DIAGNOSTICS", frozenset())
NO_OPERATION_STAGES = getattr(_CORE_CONTRACT, "NO_OPERATION_STAGES", frozenset())


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _canonical_json(record):
    return json.dumps(
        record, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True,
    ).encode("ascii")


def _parse_refusal(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES
            or not raw.endswith(b"\n") or raw.count(b"\n") != 1
            or not raw.startswith(REFUSAL_PREFIX)):
        return None
    encoded = raw[len(REFUSAL_PREFIX):-1]
    if not encoded:
        return None
    try:
        record = json.loads(
            encoded.decode("ascii", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda unused: (_ for _ in ()).throw(ValueError()),
        )
        canonical = _canonical_json(record)
    except BaseException:
        return None
    if (type(record) is not dict or set(record) != RECORD_FIELDS
            or canonical != encoded
            or type(record["schema_version"]) is not int or record["schema_version"] != 1
            or record["status"] != "refused"
            or type(record["reason"]) is not str or record["reason"] not in REASONS
            or type(record["stage"]) is not str or record["stage"] not in STAGES
            or type(record["diagnostic"]) is not str or record["diagnostic"] not in DIAGNOSTICS
            or record["diagnostic"] == "none" and record["stage"] not in NO_OPERATION_STAGES):
        return None
    return record


def _format_record(record):
    return REFUSAL_PREFIX + _canonical_json(record) + b"\n"


def normalize_refusal(raw):
    """Return one canonical allowlisted refusal line, or the fixed unavailable line."""
    record = _parse_refusal(raw)
    return _format_record(record if record is not None else UNAVAILABLE_RECORD)


def main(arguments=None, stdin=None, stdout=None):
    actual_arguments = sys.argv[1:] if arguments is None else arguments
    input_stream = sys.stdin.buffer if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    try:
        raw = input_stream.read(MAX_INPUT_BYTES + 1) if not actual_arguments else None
    except BaseException:
        raw = None
    line = normalize_refusal(raw)
    try:
        output_stream.write(line.decode("ascii", "strict"))
    except BaseException:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
