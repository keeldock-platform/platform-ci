"""Fail-closed Rust compiler JSON mapping fixtures."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import supervisor


class RustReportMappingTests(unittest.TestCase):
    def _report(self, root, rows):
        raw = root / "workspace/raw"
        raw.mkdir(parents=True)
        (raw / "unit.log").write_bytes(b"".join(
            json.dumps(row, separators=(",", ":")).encode("ascii") + b"\n" for row in rows
        ))

    def test_compiler_message_is_reduced_at_the_mapping_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._report(root, [
                {"reason": "compiler-message", "message": {
                    "level": "error", "code": {"code": "E0308"},
                    "message": "SYNTHETIC_SOURCE_CANARY private diagnostic text",
                    "spans": [{"is_primary": True, "file_name": "/workspace/source/src/lib.rs",
                               "line_start": 7, "text": [{"text": "SYNTHETIC_KEY_CANARY"}]}],
                    "children": [{"message": "SYNTHETIC_SOURCE_CANARY"}],
                    "rendered": "SYNTHETIC_KEY_CANARY",
                }},
                {"reason": "build-finished", "success": True},
            ])

            def run_adapter(_root, _command, _stage, _tools, _log_name, timeout=60):
                output = root / "scratch/reports/rust-tests.jsonl"
                output.parent.mkdir(parents=True)
                output.write_bytes(b'{"kind":"test","stage":"unit","test":"case_0001"}\n')
                return 1

            manifest = {"allowed_files": {"src/lib.rs": "file_0001"}, "allowed_tests": {}, "frames": {}}
            with patch.object(supervisor, "_run_control_adapter", side_effect=run_adapter):
                records = supervisor._adapter_records(root, "core-rust", manifest, [("unit", 0)], {})
            joined = b"\n".join(records)
            self.assertIn(b'"file":"src/lib.rs"', joined)
            self.assertIn(b'"line":7', joined)
            self.assertIn(b'"test":"case_0001"', joined)
            self.assertNotIn(b"SYNTHETIC_SOURCE_CANARY", joined)
            self.assertNotIn(b"SYNTHETIC_KEY_CANARY", joined)

    def test_unrecognized_or_non_json_report_becomes_a_fixed_failure(self):
        for payload in (
                b'{"reason":"future-secret-bearing-record","value":"SYNTHETIC_SOURCE_CANARY"}\n',
                b"PRIVATE_SOURCE_CANARY raw output\n"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                raw = root / "workspace/raw"
                raw.mkdir(parents=True)
                (raw / "unit.log").write_bytes(payload)
                with patch.object(supervisor, "_run_control_adapter") as run_adapter:
                    records = supervisor._adapter_records(
                        root, "core-rust", {"allowed_files": {}, "allowed_tests": {}, "frames": {}},
                        [("unit", 0)], {},
                    )
                run_adapter.assert_not_called()
                self.assertEqual(len(records), 1)
                self.assertIn(b"DEVLANE_FAILURE", records[0])
                self.assertNotIn(b"SYNTHETIC_SOURCE_CANARY", records[0])
                self.assertNotIn(b"PRIVATE_SOURCE_CANARY", records[0])


if __name__ == "__main__":
    unittest.main()
