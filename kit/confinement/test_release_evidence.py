import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import log_canary
import release_evidence as subject


CANARY = "0123456789abcdef" * 4
CONFIG = log_canary.compute_config(CANARY)


def _entry(path, role, payload):
    return subject.EvidenceItem(path, role, len(payload), hashlib.sha256(payload).hexdigest())


def _manifest(items):
    return subject.EvidenceManifest(subject.SCHEMA_VERSION, tuple(items))


def _scan(root, manifest):
    with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
        return subject.scan_evidence(root, manifest)


def _write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return target


class ReleaseEvidenceTests(unittest.TestCase):
    def test_manifest_model_accepts_only_its_closed_shape(self):
        valid = {
            "schema_version": 1,
            "items": [{
                "path": "logs/build.log", "role": "log", "size": 3,
                "sha256": hashlib.sha256(b"log").hexdigest(),
            }],
        }
        model = subject.manifest_from_mapping(valid)
        self.assertEqual(model.items[0], _entry("logs/build.log", "log", b"log"))
        for changed in (
            dict(valid, extra="field"),
            {"schema_version": True, "items": valid["items"]},
            {"schema_version": 1, "items": [dict(valid["items"][0], path="../build.log")]},
            {"schema_version": 1, "items": [dict(valid["items"][0], role="other")]},
            {"schema_version": 1, "items": [dict(valid["items"][0], size=True)]},
            {"schema_version": 1, "items": valid["items"] * 2},
        ):
            with self.subTest(manifest_case="invalid"):
                with self.assertRaises(subject.EvidenceRefusal):
                    subject.manifest_from_mapping(changed)

    def test_every_listed_binary_and_log_file_is_streamed_and_hashed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = b"stage=build result=complete\n"
            artifact = b"\x00binary\xffpayload" * 3
            _write(root, "logs/build.log", log)
            _write(root, "artifacts/app.bin", artifact)
            manifest = _manifest((
                _entry("logs/build.log", "log", log),
                _entry("artifacts/app.bin", "artifact", artifact),
            ))
            original_feed = log_canary.Scanner.feed
            chunk_sizes = []

            def bounded_feed(scanner, chunk):
                chunk_sizes.append(len(chunk))
                return original_feed(scanner, chunk)

            with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
                with mock.patch.object(subject, "READ_CHUNK_BYTES", 5):
                    with mock.patch.object(log_canary.Scanner, "feed", bounded_feed):
                        verdict = subject.scan_evidence(root, manifest)
            self.assertTrue(verdict.accepted)
            self.assertEqual(verdict.reason, "none")
            self.assertEqual(verdict.files_scanned, 2)
            self.assertEqual(verdict.bytes_scanned, len(log) + len(artifact))
            self.assertLessEqual(max(chunk_sizes), 5)
            self.assertEqual(sum(chunk_sizes), len(log) + len(artifact))

    def test_pinned_canary_in_any_listed_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"binary-prefix\x00" + CANARY.encode("ascii") + b"\xffsuffix"
            _write(root, "artifacts/output.bin", payload)
            manifest = _manifest((_entry("artifacts/output.bin", "artifact", payload),))
            verdict = _scan(root, manifest)
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "canary_present")

    def test_default_configuration_reuses_the_pinned_config_and_refuses_when_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe log\n"
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
                self.assertTrue(subject.scan_evidence(root, manifest).accepted)
            with mock.patch.object(log_canary, "PINNED_CONFIG", None):
                verdict = subject.scan_evidence(root, manifest)
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "canary_config_invalid")

    def test_unlisted_and_missing_files_refuse_the_complete_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe\n"
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            _write(root, "unexpected.log", b"extra\n")
            verdict = _scan(root, manifest)
            self.assertEqual(verdict.reason, "file_unlisted")
            (root / "unexpected.log").unlink()
            (root / "unused-directory").mkdir()
            verdict = _scan(root, manifest)
            self.assertEqual(verdict.reason, "file_unlisted")
            (root / "unused-directory").rmdir()
            (root / "build.log").unlink()
            verdict = _scan(root, manifest)
            self.assertEqual(verdict.reason, "file_missing")

    def test_declared_size_and_digest_must_match_file_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe evidence\n"
            _write(root, "build.log", payload)
            wrong_size = _manifest((subject.EvidenceItem(
                "build.log", "log", len(payload) + 1, hashlib.sha256(payload).hexdigest()
            ),))
            self.assertEqual(
                _scan(root, wrong_size).reason,
                "file_size_mismatch",
            )
            wrong_digest = _manifest((subject.EvidenceItem(
                "build.log", "log", len(payload), "0" * 64
            ),))
            self.assertEqual(
                _scan(root, wrong_digest).reason,
                "file_digest_mismatch",
            )

    def test_empty_retained_files_are_not_mistaken_for_scanned_logs_or_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(root, "build.log", b"")
            manifest = _manifest((_entry("build.log", "log", b""),))
            self.assertEqual(_scan(root, manifest).reason, "manifest_invalid")

    def test_size_limits_are_checked_before_opening_any_evidence_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"larger than limit"
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            with mock.patch.object(subject, "MAX_LOG_BYTES", len(payload) - 1):
                with mock.patch.object(subject.os, "open") as open_file:
                    verdict = _scan(root, manifest)
            self.assertEqual(verdict.reason, "file_over_limit")
            open_file.assert_not_called()

    def test_total_evidence_limit_is_checked_before_opening_any_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = b"first"
            second = b"other"
            _write(root, "first.bin", first)
            _write(root, "second.bin", second)
            manifest = _manifest((
                _entry("first.bin", "artifact", first),
                _entry("second.bin", "artifact", second),
            ))
            with mock.patch.object(
                subject, "MAX_EVIDENCE_TOTAL_BYTES", len(first) + len(second) - 1
            ):
                with mock.patch.object(subject.os, "open") as open_file:
                    verdict = _scan(root, manifest)
            self.assertEqual(verdict.reason, "file_over_limit")
            open_file.assert_not_called()

    def test_unreadable_file_refuses_instead_of_reporting_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe evidence\n"
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            with mock.patch.object(subject.os, "open", side_effect=OSError("unavailable")):
                verdict = _scan(root, manifest)
            self.assertEqual(verdict.reason, "file_unreadable")

    def test_known_compressed_evidence_fails_closed_and_remains_an_open_question(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"\x1f\x8bcompressed bytes"
            for name in ("build.log.gz", "build.log"):
                _write(root, name, payload)
                manifest = _manifest((_entry(name, "log", payload),))
                verdict = _scan(root, manifest)
                self.assertEqual(verdict.reason, "compressed_unsupported")
                (root / name).unlink()
            self.assertTrue(subject.OPEN_QUESTIONS)

    def test_symlink_output_is_not_treated_as_a_regular_retained_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe evidence\n"
            _write(root, "source.log", payload)
            link = root / "build.log"
            try:
                link.symlink_to(root / "source.log")
            except OSError:
                self.skipTest("symlink creation is unavailable")
            manifest = _manifest((_entry("build.log", "log", payload),))
            self.assertEqual(_scan(root, manifest).reason, "tree_invalid")


if __name__ == "__main__":
    unittest.main()
