import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import log_canary
import release_evidence as subject


CANARY = "0123456789abcdef" * 4
CONFIG = log_canary.compute_config(CANARY)
PLAIN_LOG_PROFILE = (
    b"safe log", b"safe evidence", b"safe", b"first log", b"second log",
    b"stage=build result=complete", b"A" * len(CANARY),
)


def _entry(path, role, payload):
    return subject.EvidenceItem(path, role, len(payload), hashlib.sha256(payload).hexdigest())


def _manifest(items):
    return subject.EvidenceManifest(subject.SCHEMA_VERSION, tuple(items))


def _scan(root, manifest):
    with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
        with mock.patch.object(subject, "PINNED_PLAIN_LOG_LINES", PLAIN_LOG_PROFILE):
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

    def test_binary_artifact_is_scanned_but_refused_without_an_extraction_profile(self):
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
                with mock.patch.object(subject, "PINNED_PLAIN_LOG_LINES", PLAIN_LOG_PROFILE):
                    with mock.patch.object(subject, "READ_CHUNK_BYTES", 5):
                        with mock.patch.object(log_canary.Scanner, "feed", bounded_feed):
                            verdict = subject.scan_evidence(root, manifest)
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "compressed_unsupported")
            self.assertEqual(verdict.files_scanned, 2)
            self.assertEqual(verdict.bytes_scanned, len(log) + len(artifact))
            self.assertEqual(verdict.snapshots, ())
            self.assertLessEqual(max(chunk_sizes), 5)
            self.assertEqual(sum(chunk_sizes), len(log) + len(artifact))

    def test_accepted_log_snapshot_remains_immutable_after_source_rewrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe log\n"
            target = _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            verdict = _scan(root, manifest)
            self.assertTrue(verdict.accepted)
            self.assertEqual(verdict.reason, "none")
            self.assertEqual(len(verdict.snapshots), 1)
            self.assertNotIn("safe log", repr(verdict))
            target.write_bytes(CANARY.encode("ascii"))
            self.assertEqual(
                b"".join(verdict.snapshots[0].chunks), payload
            )

    def test_file_identity_includes_change_time(self):
        fields = {
            "st_dev": 1, "st_ino": 2, "st_size": 3,
            "st_mtime_ns": 4, "st_ctime_ns": 5,
        }
        before = SimpleNamespace(**fields)
        after = SimpleNamespace(**dict(fields, st_ctime_ns=6))
        self.assertNotEqual(subject._file_identity(before), subject._file_identity(after))

    def test_open_file_comparison_on_windows_ignores_only_change_time(self):
        fields = {
            "st_dev": 1, "st_ino": 2, "st_size": 3,
            "st_mtime_ns": 4, "st_ctime_ns": 5,
        }
        expected = SimpleNamespace(**fields)
        with mock.patch.object(subject, "_WINDOWS_IDENTITY", True):
            later = SimpleNamespace(**dict(fields, st_ctime_ns=9))
            self.assertTrue(subject._same_open_file(later, expected))
            self.assertTrue(subject._same_open_file(expected, expected))
            for name, value in (("st_size", 4), ("st_mtime_ns", 5),
                                ("st_ino", 7), ("st_dev", 8),
                                ("st_ino", 0)):
                with self.subTest(field=name, value=value):
                    changed = SimpleNamespace(**dict(fields, **{name: value}))
                    self.assertFalse(subject._same_open_file(changed, expected))
                    self.assertFalse(subject._same_open_file(expected, changed))
            unset = SimpleNamespace(**dict(fields, st_ino=0))
            self.assertFalse(subject._same_open_file(unset, unset))
        with mock.patch.object(subject, "_WINDOWS_IDENTITY", False):
            changed = SimpleNamespace(**dict(fields, st_ctime_ns=6))
            self.assertFalse(subject._same_open_file(changed, expected))

    @unittest.skipUnless(os.name == "nt", "Windows directory metadata only")
    def test_windows_inventory_keeps_full_file_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = _write(root, "build.log", b"safe log\n")
            files, directories = subject._inventory(root, None)
            self.assertEqual(directories, {})
            self.assertEqual(
                subject._file_identity(files["build.log"]),
                subject._file_identity(os.lstat(target)),
            )

    @unittest.skipUnless(os.name == "nt", "Windows tunnelled creation time only")
    def test_windows_recreated_log_with_a_tunnelled_change_time_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe log\n"
            target = _write(root, "build.log", payload)
            target.unlink()
            time.sleep(0.1)
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            verdict = _scan(root, manifest)
            self.assertTrue(verdict.accepted)
            self.assertEqual(verdict.reason, "none")

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
                with mock.patch.object(subject, "PINNED_PLAIN_LOG_LINES", PLAIN_LOG_PROFILE):
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
            original_open = os.open

            def refuse_file(path, flags, *args, **kwargs):
                if str(path).endswith("build.log"):
                    raise OSError("unavailable")
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(subject.os, "open", side_effect=refuse_file):
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

    def test_signatureless_brotli_renamed_as_log_requires_admitted_plain_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"\x06"
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
                unpinned = subject.scan_evidence(root, manifest)
            self.assertFalse(unpinned.accepted)
            self.assertEqual(unpinned.reason, "log_profile_unpinned")
            verdict = _scan(root, manifest)
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "log_profile_invalid")
            self.assertEqual(verdict.files_scanned, 1)

    def test_plain_log_profile_refuses_unreviewed_printable_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"unreviewed text\n"
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            verdict = _scan(root, manifest)
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "log_profile_invalid")

    def test_plain_log_profile_configuration_is_closed_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe log\n"
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            for profile in ("safe log", (), (b"safe log\n",),
                            (b"safe log", b"safe log"), (b"A" * 513,)):
                with self.subTest(profile=profile):
                    with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
                        with mock.patch.object(subject, "PINNED_PLAIN_LOG_LINES", profile):
                            verdict = subject.scan_evidence(root, manifest)
                    self.assertFalse(verdict.accepted)
                    self.assertEqual(verdict.reason, "log_profile_invalid")

    def test_container_signatures_refuse_renamed_evidence_files(self):
        signatures = (
            b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07\x00",
            b"Rar!\x1a\x07\x01\x00", b"MSCF", b"!<arch>\n",
            b"xar!", b"\x02\x21\x4c\x18", b"\x5f\x2a\x4d\x18",
            b"\x00" * 257 + b"ustar\x00",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for signature in signatures:
                with self.subTest(signature=signature[:8]):
                    payload = signature + b"compressed contents"
                    target = _write(root, "renamed.log", payload)
                    manifest = _manifest((_entry("renamed.log", "log", payload),))
                    verdict = _scan(root, manifest)
                    self.assertFalse(verdict.accepted)
                    self.assertEqual(verdict.reason, "compressed_unsupported")
                    target.unlink()

    def test_mid_scan_addition_is_rejected_by_final_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = b"first log\n"
            second = b"second log\n"
            _write(root, "logs/a.log", first)
            _write(root, "logs/b.log", second)
            manifest = _manifest((
                _entry("logs/a.log", "log", first),
                _entry("logs/b.log", "log", second),
            ))
            original_feed = log_canary.Scanner.feed
            added = [False]

            def add_during_scan(scanner, chunk):
                if b"second" in chunk and not added[0]:
                    _write(root, "logs/unexpected.log", b"new evidence\n")
                    added[0] = True
                return original_feed(scanner, chunk)

            with mock.patch.object(log_canary.Scanner, "feed", add_during_scan):
                verdict = _scan(root, manifest)
            self.assertTrue(added[0])
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "tree_changed")

    def test_mid_scan_replacement_is_rejected_before_reading_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = b"first log\n"
            second = b"second log\n"
            _write(root, "a.log", first)
            target = _write(root, "b.log", second)
            manifest = _manifest((_entry("a.log", "log", first), _entry("b.log", "log", second)))
            original_feed = log_canary.Scanner.feed
            replaced = [False]

            def replace_during_scan(scanner, chunk):
                if b"first" in chunk and not replaced[0]:
                    target.unlink()
                    target.write_bytes(second)
                    replaced[0] = True
                return original_feed(scanner, chunk)

            with mock.patch.object(log_canary.Scanner, "feed", replace_during_scan):
                verdict = _scan(root, manifest)
            self.assertTrue(replaced[0])
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "file_changed")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_mid_scan_fifo_replacement_cannot_block_file_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = b"first log\n"
            second = b"second log\n"
            _write(root, "a.log", first)
            target = _write(root, "b.log", second)
            manifest = _manifest((_entry("a.log", "log", first), _entry("b.log", "log", second)))
            original_feed = log_canary.Scanner.feed
            original_open = os.open
            replaced = [False]

            def replace_during_scan(scanner, chunk):
                if b"first log" in chunk and not replaced[0]:
                    target.unlink()
                    os.mkfifo(target)
                    replaced[0] = True
                return original_feed(scanner, chunk)

            def guarded_open(path, flags, *args, **kwargs):
                if str(path).endswith("b.log") and not flags & os.O_NONBLOCK:
                    raise AssertionError("blocking FIFO open")
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(subject.os, "open", side_effect=guarded_open):
                with mock.patch.object(log_canary.Scanner, "feed", replace_during_scan):
                    verdict = _scan(root, manifest)
            self.assertTrue(replaced[0])
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "file_not_regular")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_fifo_replacement_before_source_recheck_cannot_block(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe log\n"
            target = _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            original_verify = subject._verify_snapshot_source
            original_open = os.open
            replaced = [False]

            def replace_before_recheck(*args):
                if not replaced[0]:
                    target.unlink()
                    os.mkfifo(target)
                    replaced[0] = True
                return original_verify(*args)

            def guarded_open(path, flags, *args, **kwargs):
                if str(path).endswith("build.log") and not flags & os.O_NONBLOCK:
                    raise AssertionError("blocking FIFO open")
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(subject.os, "open", side_effect=guarded_open):
                with mock.patch.object(subject, "_verify_snapshot_source", replace_before_recheck):
                    verdict = _scan(root, manifest)
            self.assertTrue(replaced[0])
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "file_not_regular")

    def test_scanned_file_rewrite_with_restored_mtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = b"A" * len(CANARY) + b"\n"
            second = b"second log\n"
            target = _write(root, "a.log", first)
            _write(root, "b.log", second)
            manifest = _manifest((_entry("a.log", "log", first), _entry("b.log", "log", second)))
            original_feed = log_canary.Scanner.feed
            changed = [False]
            before = target.stat()

            def rewrite_during_scan(scanner, chunk):
                if b"second" in chunk and not changed[0]:
                    target.write_bytes(CANARY.encode("ascii") + b"\n")
                    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
                    changed[0] = True
                return original_feed(scanner, chunk)

            def old_metadata_identity(metadata):
                return (metadata.st_dev, metadata.st_ino, metadata.st_size,
                        metadata.st_mtime_ns)

            with mock.patch.object(subject, "_file_identity", old_metadata_identity):
                with mock.patch.object(log_canary.Scanner, "feed", rewrite_during_scan):
                    verdict = _scan(root, manifest)
            self.assertTrue(changed[0])
            self.assertEqual(target.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "tree_changed")
            self.assertEqual(verdict.snapshots, ())

    def test_canary_scanner_budget_refusals_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"safe evidence\n"
            _write(root, "build.log", payload)
            manifest = _manifest((_entry("build.log", "log", payload),))
            for method in ("feed", "finish"):
                with self.subTest(method=method):
                    refusal = log_canary.ScanRefusal("scan_limit")
                    with mock.patch.object(log_canary.Scanner, method, side_effect=refusal):
                        verdict = _scan(root, manifest)
                    self.assertFalse(verdict.accepted)
                    self.assertEqual(verdict.reason, "canary_unscanned")
                    self.assertEqual(verdict.files_scanned, 0)

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

    def test_symlink_root_with_trailing_separator_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "real"
            root.mkdir()
            payload = b"safe evidence\n"
            _write(root, "build.log", payload)
            link = parent / "link"
            try:
                link.symlink_to(root, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            manifest = _manifest((_entry("build.log", "log", payload),))
            verdict = _scan(str(link) + os.sep, manifest)
            self.assertFalse(verdict.accepted)
            self.assertEqual(verdict.reason, "tree_invalid")


if __name__ == "__main__":
    unittest.main()
