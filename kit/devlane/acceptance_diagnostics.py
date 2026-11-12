"""Print a bounded, workflow-safe tail from source-free synthetic stages."""

import argparse
import re
from pathlib import Path

import diagnostic_contract


MAX_TAIL_BYTES = 1024 * 1024
MAX_TAIL_LINES = 200
MAX_LINE_TEXT = 256
_ANSI = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])"
)
_WORKFLOW_GROUP_MARKER = chr(35) * 2 + "["
_SAFE_GROUP_MARKER = chr(35) + " " + chr(35) + "["
_KEY_CANARY = b"KEYCANARY-73A10X" + bytes(range(16))
_REDACTIONS = (
    "SYNTHETIC_SOURCE_CANARY",
    "PRIVATE_SOURCE_CANARY",
    "SYNTHETIC_KEY_CANARY",
    "PRIVATE_KEY_CANARY",
    "KEYCANARY-73A10X",
    _KEY_CANARY.hex(),
    _KEY_CANARY.hex().upper(),
)
_BYTE_REDACTIONS = (_KEY_CANARY,) + tuple(value.encode("ascii") for value in _REDACTIONS)


def _read_bounded_tail(path):
    with Path(path).open("rb") as source:
        source.seek(0, 2)
        size = source.tell()
        offset = max(0, size - MAX_TAIL_BYTES)
        source.seek(offset)
        payload = source.read(MAX_TAIL_BYTES)
    if offset:
        payload = payload.split(b"\n", 1)[-1]
    return payload, bool(offset)


def _safe_text(line):
    text = _ANSI.sub("", line)
    for redaction in _REDACTIONS:
        text = text.replace(redaction, "[synthetic-canary-redacted]")
    safe = []
    for character in text:
        value = ord(character)
        if character == "\t":
            safe.append("    ")
        elif value < 32 or value == 127:
            safe.append("\\x%02x" % value)
        elif value > 126:
            safe.append("\\u%04x" % value if value <= 0xFFFF else "\\U%08x" % value)
        else:
            safe.append(character)
    text = "".join(safe).replace("::", ": :").replace(_WORKFLOW_GROUP_MARKER, _SAFE_GROUP_MARKER)
    if len(text) > MAX_LINE_TEXT:
        text = text[:MAX_LINE_TEXT - 3] + "..."
    return text or "<blank>"


def failure_tail(stage, payload, *, earlier_bytes_omitted=False):
    """Return at most 200 short, sanitised detail lines for one accepted stage."""
    if stage not in diagnostic_contract.ACCEPTANCE_FAILURE_STAGES or type(payload) is not bytes:
        raise ValueError("acceptance-diagnostic-input-invalid")
    for canary in _BYTE_REDACTIONS:
        payload = payload.replace(canary, b"[synthetic-canary-redacted]")
    decoded = payload.decode("utf-8", "replace")
    lines = decoded.splitlines()
    omitted_lines = max(0, len(lines) - MAX_TAIL_LINES)
    lines = lines[-MAX_TAIL_LINES:]
    output = []
    if earlier_bytes_omitted:
        output.append(_format_line(stage, 0, "earlier-output-omitted"))
    if omitted_lines:
        output.append(_format_line(stage, 0, "%d earlier lines omitted" % omitted_lines))
    if not lines:
        lines = ["<empty output>"]
    for index, line in enumerate(lines, start=1):
        if (stage == "production-path-e2e"
                and diagnostic_contract.public_preparation_diagnostic(line)):
            output.append(line)
        else:
            output.append(_format_line(stage, index, _safe_text(line)))
    return output


def _format_line(stage, index, text):
    return "devlane_acceptance_detail stage=%s index=%d text=%s" % (stage, index, text)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True)
    parser.add_argument("--file", required=True)
    args = parser.parse_args(argv)
    if args.stage not in diagnostic_contract.ACCEPTANCE_FAILURE_STAGES:
        print("devlane_acceptance_detail stage=production-path-e2e index=0 text=diagnostic-stage-invalid")
        return 0
    try:
        payload, earlier = _read_bounded_tail(args.file)
        lines = failure_tail(args.stage, payload, earlier_bytes_omitted=earlier)
    except Exception:
        lines = [_format_line(args.stage, 0, "diagnostic-output-unavailable")]
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
