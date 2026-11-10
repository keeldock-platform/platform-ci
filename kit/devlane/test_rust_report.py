"""Fail-closed tests for the fixed Core matrix's private-to-public report boundary."""

import json
import tempfile
import unittest
from pathlib import Path

import rust_matrix_runner
import filter as public_filter
import supervisor


def _coverage(suite, *, failed=0):
    stage = rust_matrix_runner._stage_for(suite)
    total = 0 if suite in ("fuzz-default", "fuzz-all-features") else 1
    return {
        "kind": "coverage", "stage": stage, "suite": suite, "total": total,
        "passed": total - failed, "failed": failed, "ignored": 0,
    }


class RustReportMappingTests(unittest.TestCase):
    def _fixture(self, root, records):
        control = root / "control"
        report = root / "scratch/reports/rust-matrix.jsonl"
        raw = root / "workspace/raw"
        control.mkdir(parents=True)
        report.parent.mkdir(parents=True)
        raw.mkdir(parents=True)
        (control / "profiles.json").write_text(json.dumps({
            "profiles": {"core-rust": {"rust_matrix": rust_matrix_runner.EXPECTED_MATRIX}},
        }), encoding="ascii")
        report.write_bytes(b"".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
            for row in records
        ))
        (raw / "private-adapter.log").write_text(
            "SYNTHETIC_SOURCE_CANARY SYNTHETIC_KEY_CANARY\n", encoding="ascii",
        )
        return report

    def test_complete_matrix_coverage_is_canonical_and_raw_logs_stay_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = [_coverage(suite) for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]]
            self._fixture(root, records)
            manifest = {"allowed_files": {}, "allowed_tests": {}, "frames": {}}
            public = supervisor._adapter_records(
                root, "core-rust", manifest, [], {}, {"rust_matrix": 0},
            )
            joined = b"\n".join(public)
            self.assertEqual(len(public), len(rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]))
            self.assertIn(b'"suite":"listener-all-features"', joined)
            self.assertNotIn(b"SYNTHETIC_SOURCE_CANARY", joined)
            self.assertNotIn(b"SYNTHETIC_KEY_CANARY", joined)

    def test_zero_exit_with_missing_or_failed_coverage_becomes_fixed_failure(self):
        for records in (
            [_coverage(suite) for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"][:-1]],
            [_coverage(suite, failed=1) for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]],
        ):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._fixture(root, records)
                public = supervisor._adapter_records(
                    root, "core-rust", {"allowed_files": {}, "allowed_tests": {}, "frames": {}},
                    [], {}, {"rust_matrix": 0},
                )
                self.assertEqual(len(public), 1)
                self.assertIn(b"DEVLANE_FAILURE", public[0])
                self.assertNotIn(b"SYNTHETIC_SOURCE_CANARY", public[0])

    def test_nonzero_matrix_exit_must_match_fixed_failure_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = [_coverage(suite) for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]]
            records.append({"kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE"})
            self._fixture(root, records)
            public = supervisor._adapter_records(
                root, "core-rust", {"allowed_files": {}, "allowed_tests": {}, "frames": {}},
                [], {}, {"rust_matrix": 1},
            )
            self.assertEqual(len(public), len(records))
            self.assertIn(b"DEVLANE_FAILURE", b"\n".join(public))

    def test_fuzz_unit_zero_is_reported_but_required_core_and_listener_tests_cannot_be_empty(self):
        allowlists = {
            "files": {}, "tests": {}, "frames": {}, "stages": ["unit"], "codes": ["DEVLANE_FAILURE"],
            "suites": ["fuzz-default", "listener-default", "root-default"], "max_lines": {},
        }
        zero_fuzz = json.dumps({
            "kind": "coverage", "stage": "unit", "suite": "fuzz-default",
            "total": 0, "passed": 0, "failed": 0, "ignored": 0,
        }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        self.assertEqual(public_filter.validate_public_summary(zero_fuzz, allowlists), zero_fuzz)
        for suite in ("root-default", "listener-default"):
            row = json.dumps({
                "kind": "coverage", "stage": "unit", "suite": suite,
                "total": 0, "passed": 0, "failed": 0, "ignored": 0,
            }, separators=(",", ":")).encode("ascii") + b"\n"
            with self.subTest(suite=suite), self.assertRaises(public_filter.FilterRefusal):
                public_filter.validate_public_summary(row, allowlists)


if __name__ == "__main__":
    unittest.main()
