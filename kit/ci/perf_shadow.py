"""Deterministic stage-one performance harness in feedback-only mode."""

import argparse
import json
import sys
import time
import tracemalloc


SCHEMA_VERSION = 1
SAMPLE_ROWS = 10000
MAX_SAMPLE_ROWS = 50000
MAX_ELAPSED_SECONDS = 2.0
MAX_EXTRA_BYTES = 32 * 1024 * 1024


def run_harness(sample_rows=SAMPLE_ROWS):
    if type(sample_rows) is not int or not 1 <= sample_rows <= MAX_SAMPLE_ROWS:
        raise ValueError("sample-count-invalid")
    tracemalloc.start()
    baseline_current, unused = tracemalloc.get_traced_memory()
    started = time.perf_counter()
    rows = [
        {"id": index, "score": (index * 48271) % 2147483647, "label": "row-%05d" % index}
        for index in range(sample_rows)
    ]
    ordered = sorted(rows, key=lambda row: (row["score"], row["id"]))
    index = {row["id"]: row for row in ordered}
    if len(index) != sample_rows or (sample_rows and index[sample_rows - 1]["id"] != sample_rows - 1):
        raise RuntimeError("workload-integrity-failed")
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    extra_bytes = max(0, peak - baseline_current)
    timing_exceeded = elapsed_ms > MAX_ELAPSED_SECONDS * 1000.0
    allocation_exceeded = extra_bytes > MAX_EXTRA_BYTES
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "shadow",
        "status": "feedback-only",
        "samples": sample_rows,
        "elapsed_ms": round(elapsed_ms, 3),
        "extra_bytes": extra_bytes,
        "limits": {
            "elapsed_ms": int(MAX_ELAPSED_SECONDS * 1000),
            "extra_bytes": MAX_EXTRA_BYTES,
        },
        "would_exceed": {
            "elapsed_ms": timing_exceeded,
            "extra_bytes": allocation_exceeded,
        },
        "measurements_complete": True,
    }


def encode_result(result):
    if (type(result) is not dict or result.get("schema_version") != SCHEMA_VERSION
            or result.get("mode") != "shadow" or result.get("status") != "feedback-only"
            or result.get("measurements_complete") is not True):
        raise ValueError("perf-result-invalid")
    return json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--samples", type=int, default=SAMPLE_ROWS)
    arguments = parser.parse_args(argv)
    try:
        sys.stdout.write(encode_result(run_harness(arguments.samples)))
        return 0
    except Exception:
        sys.stdout.write('{"mode":"shadow","status":"refused"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
