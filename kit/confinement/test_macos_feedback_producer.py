import base64
import hashlib
import importlib.util
import io
import shutil
import subprocess
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cargo_lock_bootstrap as cargo_bootstrap


MODULE_PATH = Path(__file__).resolve().parent / "macos_feedback_producer.py"
SPEC = importlib.util.spec_from_file_location("macos_feedback_producer", MODULE_PATH)
producer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = producer
SPEC.loader.exec_module(producer)
requests = producer.feedback_request

NOW = 1_798_000_000
SOURCE_SHA = "a" * 40
BASE_SHA = "b" * 40
CONTROL_SHA = "c" * 40
DIFF_SHA = "d" * 64
SPKI = b"synthetic-public-key-der"


def _dispatch(kind="build_diagnostics"):
    profile = producer.PROFILE_BY_KIND[kind]
    fingerprint = hashlib.sha256(SPKI).hexdigest()
    fields = {
        "kind": kind,
        "concern": profile["concern"],
        "ci_repository_id": "1234",
        "workflow_path": profile["workflow_path"],
        "workflow_ref": requests.workflow_ref_for_kind(kind),
        "repository_id": "5678",
        "source_sha": SOURCE_SHA,
        "base_sha": BASE_SHA,
        "control_sha": CONTROL_SHA,
        "base_branch": "develop",
        "reviewed_diff_sha256": DIFF_SHA,
        "recipient_fingerprint": fingerprint,
        "nonce": "e" * 64,
        "expiry": NOW + 3600,
    }
    request = requests.create_request(fields, now=NOW)
    environment = {
        producer.REQUEST_ENV: base64.b64encode(requests.encode_request(request, now=NOW)).decode("ascii"),
        producer.RECIPIENT_ENV: base64.b64encode(SPKI).decode("ascii"),
        "CI_SHA": CONTROL_SHA,
        "GITHUB_SHA": CONTROL_SHA,
        "GITHUB_REPOSITORY": "public/ci",
        "GITHUB_REPOSITORY_ID": "1234",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": "public/ci/" + profile["workflow_path"] + "@refs/heads/main",
        "GITHUB_JOB": profile["producer_job"],
        "GITHUB_RUN_ID": "9876",
        "GITHUB_RUN_ATTEMPT": "1",
        "SOURCE_REPOSITORY_ID": "5678",
        "CORE_CONTRACT_REVIEWED_SOURCE_SHA": SOURCE_SHA,
        "CORE_CONTRACT_REVIEWED_BASE_SHA": BASE_SHA,
        "CORE_CONTRACT_REVIEWED_BASE_BRANCH": "develop",
        "CORE_CONTRACT_REVIEWED_DIFF_SHA256": DIFF_SHA,
    }
    return request, environment


def _validated_dispatch(kind):
    _request, environment = _dispatch(kind)
    return producer.validate_dispatch(kind, environment, now=NOW)


class MacosFeedbackProducerTests(unittest.TestCase):
    def test_dispatch_binds_each_closed_profile_and_includes_kind_in_context(self):
        for kind in producer.PROFILE_BY_KIND:
            if kind == requests.LINUX_QUICK_KIND:
                continue
            request, environment = _dispatch(kind)
            result = producer.validate_dispatch(kind, environment, now=NOW)
            self.assertEqual(result["request"], request)
            self.assertEqual(result["profile"], producer.PROFILE_BY_KIND[kind])
            self.assertEqual(result["context"]["concern"], request["concern"])
            self.assertEqual(result["context"]["run_id"], "9876")
            self.assertEqual(result["context"]["producer_job"],
                             producer.PROFILE_BY_KIND[kind]["producer_job"])
            self.assertEqual(result["context"]["kind"], kind)

    def test_the_linux_quick_profile_is_never_accepted_as_a_macos_dispatch(self):
        request, environment = _dispatch(requests.LINUX_QUICK_KIND)
        self.assertEqual(request["workflow_ref"], "refs/heads/untrusted")
        with self.assertRaises(producer.FeedbackRefusal):
            producer.validate_dispatch(requests.LINUX_QUICK_KIND, environment, now=NOW)
        for kind in producer.PROFILE_BY_KIND:
            if kind != requests.LINUX_QUICK_KIND:
                self.assertEqual(_dispatch(kind)[0]["workflow_ref"], "refs/heads/main")

    def test_dispatch_rejects_run_profile_binding_and_recipient_mismatches(self):
        _, environment = _dispatch("build_diagnostics")
        for name, value in (
            ("GITHUB_JOB", "other-job"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_SHA", "f" * 40),
            ("SOURCE_REPOSITORY_ID", "0009"),
        ):
            changed = dict(environment)
            changed[name] = value
            with self.subTest(name=name), self.assertRaises(producer.FeedbackRefusal):
                producer.validate_dispatch("build_diagnostics", changed, now=NOW)

        changed = dict(environment)
        changed[producer.RECIPIENT_ENV] = base64.b64encode(b"different-key").decode("ascii")
        with self.assertRaises(producer.FeedbackRefusal):
            producer.validate_dispatch("build_diagnostics", changed, now=NOW)

    def test_producer_receipt_is_canonical_context_only_and_profile_closed(self):
        _, environment = _dispatch("rust_patch")
        dispatch = producer.validate_dispatch("rust_patch", environment, now=NOW)
        receipt = producer.producer_receipt(dispatch, {
            "member_name": "rust-format-return-v1.enc",
            "ciphertext_digest": "a" * 64,
            "member_size": 128,
        })
        record = json.loads(receipt)
        self.assertEqual(receipt, json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        self.assertEqual(record["status"], "encrypted")
        self.assertEqual(record["job_name"], "core-rust-format-return")
        self.assertEqual(record["member_name"], "rust-format-return-v1.enc")
        self.assertNotIn("path", record)
        self.assertNotIn("stdout", record)
        self.assertNotIn("stderr", record)

    def test_publisher_receipt_parser_requires_exact_single_profile_and_context(self):
        _, environment = _dispatch("build_diagnostics")
        dispatch = producer.validate_dispatch("build_diagnostics", environment, now=NOW)
        receipt = producer.producer_receipt(dispatch, {
            "member_name": "build-diagnostic-return-v1.enc",
            "ciphertext_digest": "b" * 64,
            "member_size": 256,
        })
        line = ("KD-FEEDBACK-PRODUCER " + receipt + "\n").encode("ascii")
        invalid_digest_line = line.replace(b"b" * 64, b"g" * 64)
        self.assertNotEqual(invalid_digest_line, line)
        with patch.object(producer.time, "time", return_value=NOW):
            checked, record, canonical = producer._parse_producer_line(
                line, "build_diagnostics", environment,
            )
            self.assertEqual(checked["context"], dispatch["context"])
            self.assertEqual(record["member_size"], 256)
            self.assertEqual(canonical, receipt)
            for altered, kind in (
                (line + line, "build_diagnostics"),
                (line, "rust_patch"),
                (invalid_digest_line, "build_diagnostics"),
            ):
                with self.subTest(kind=kind, size=len(altered)), self.assertRaises(producer.FeedbackRefusal):
                    producer._parse_producer_line(altered, kind, environment)

    def test_build_diagnostic_payload_marks_truncated_streams_and_keeps_failure_stage(self):
        stdout_prefix = (b"bounded stdout\n" + (b"x" * 63 + b"\n") * 600)[:32_768]
        stderr_prefix = (b"bounded stderr\n" + (b"y" * 63 + b"\n") * 600)[:32_768]
        self.assertEqual((len(stdout_prefix), len(stderr_prefix)), (32_768, 32_768))
        selected = producer.DIAGNOSTIC_GATE_SELECTIONS[-1]
        completed = selected[:selected.index("parser_replay")]
        payload = producer.build_diagnostic_payload({
            "failed_stage": "parser_replay",
            "selected_gates": selected,
            "completed": completed,
            "returncode": 9,
            "stdout": stdout_prefix,
            "stderr": stderr_prefix,
            "stdout_truncated": True,
            "stderr_truncated": True,
        })
        prefix = (
            "KD-BUILD-DIAGNOSTICS schema=1 stage=parser_replay stdout_truncated=true "
            "stderr_truncated=true exit=9 selected_gates=" + ",".join(selected)
            + " completed_gates=" + ",".join(completed) + "\n"
        ).encode("ascii")
        self.assertTrue(payload.startswith(prefix))
        self.assertIn(stdout_prefix, payload)
        self.assertIn(stderr_prefix, payload)
        self.assertLessEqual(len(payload), 512 * 1024)
        with self.assertRaises(producer.FeedbackRefusal):
            producer.build_diagnostic_payload({
                "failed_stage": "workspace_tests", "returncode": 9,
                "selected_gates": producer.DIAGNOSTIC_BASE_GATES,
                "completed": ("format", "clippy"),
                "stdout": b"x", "stderr": b"y", "stdout_truncated": "yes",
                "stderr_truncated": False,
            })

    def test_build_diagnostic_payload_accepts_the_clean_gate_timeout_outcome(self):
        selected = producer.DIAGNOSTIC_GATE_SELECTIONS[0]
        outcome = {
            "failed_stage": "workspace_tests",
            "selected_gates": selected,
            "completed": ("format", "clippy"),
            "returncode": 124,
            "stdout": b"",
            "stderr": b"kd-gate-timeout limit_seconds=300\n",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
        payload = producer.build_diagnostic_payload(outcome)
        self.assertEqual(
            payload,
            ("KD-BUILD-DIAGNOSTICS schema=1 stage=workspace_tests stdout_truncated=false "
             "stderr_truncated=false exit=124 selected_gates=" + ",".join(selected)
             + " completed_gates=format,clippy\nstdout:\n\nstderr:\nkd-gate-timeout limit_seconds=300\n").encode("ascii"),
        )

    def _failed_outcome(self, stdout=b"", stderr=b"", stdout_truncated=False, stderr_truncated=False):
        selected_gates = producer.DIAGNOSTIC_GATE_SELECTIONS[-1]
        return {
            "failed_stage": "parser_replay",
            "selected_gates": selected_gates,
            "completed": selected_gates[:selected_gates.index("parser_replay")],
            "returncode": 1, "stdout": stdout, "stderr": stderr,
            "stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated,
        }

    def _body(self, payload):
        return payload.split(b"\nstdout:\n", 1)[1]

    def test_build_diagnostic_payload_escapes_every_class_the_encryptor_refuses(self):
        raw = (b"a\x00b\rc\x1b[31md\x08e\x7ff\tg\nh"
               + "\u0080i\u0085j\u009fk\u2028l\u202em".encode("utf-8"))
        payload = producer.build_diagnostic_payload(self._failed_outcome(raw, raw))
        body = self._body(payload).decode("utf-8")
        expected = ("a\\u{00}b\\u{0d}c\\u{1b}[31md\\u{08}e\\u{7f}f\tg\nh"
                    "\\u{80}i\\u{85}j\\u{9f}k\u2028l\\u{202e}m")
        self.assertEqual(body, expected + "\nstderr:\n" + expected)
        self.assertIsNone(producer.UNSAFE_DIAGNOSTIC_RE.search(payload.decode("utf-8")))
        self.assertEqual(payload, producer.build_diagnostic_payload(self._failed_outcome(raw, raw)))

    def test_build_diagnostic_payload_escapes_invalid_utf8_in_the_middle_deterministically(self):
        payload = producer.build_diagnostic_payload(self._failed_outcome(b"ok\xc3(\xff\xfe end\n", b"\xed\xa0\x80\n"))
        self.assertEqual(
            self._body(payload).decode("ascii"), "ok\\xc3(\\xff\\xfe end\n\nstderr:\n\\xed\\xa0\\x80\n"
        )
        self.assertIn(b"stdout_truncated=false stderr_truncated=false", payload)

    def test_build_diagnostic_payload_trims_an_incomplete_trailing_sequence_only_when_truncated(self):
        for tail in (b"\xe2", b"\xe2\x8e", b"\xf0\x9f\x98", b"\xc3"):
            with self.subTest(tail=tail):
                payload = producer.build_diagnostic_payload(
                    self._failed_outcome(b"line\n" + tail, b"err\n" + tail, True, True))
                self.assertEqual(self._body(payload), b"line\n\nstderr:\nerr\n")
                self.assertIn(b"stdout_truncated=true stderr_truncated=true", payload)
        payload = producer.build_diagnostic_payload(
            self._failed_outcome(b"ok --", b"", True, False))
        self.assertEqual(self._body(payload), b"ok --\nstderr:\n")
        payload = producer.build_diagnostic_payload(self._failed_outcome(b"line\xe2\x8e", b"", False, False))
        self.assertEqual(self._body(payload), b"line\\xe2\\x8e\nstderr:\n")

    def test_build_diagnostic_payload_bounds_lines_after_escaping_and_marks_truncation(self):
        many_lines = b"\n" * 20_000
        long_line = b"z" * 20_000
        payload = producer.build_diagnostic_payload(
            self._failed_outcome(many_lines[:32_768], long_line, False, False))
        text = payload.decode("utf-8")
        self.assertLessEqual(text.count("\n") + 1, producer.DIAGNOSTIC_MAX_LINES)
        self.assertTrue(all(len(line) <= producer.DIAGNOSTIC_MAX_LINE_UNITS for line in text.split("\n")))
        self.assertIn(b"stdout_truncated=true stderr_truncated=true", payload)
        self.assertIn(b"z" * producer.DIAGNOSTIC_MAX_LINE_UNITS + b"\n", payload + b"\n")
        grown = producer.build_diagnostic_payload(self._failed_outcome(b"\x00" * 32_768, b"\x1b" * 32_768))
        self.assertLessEqual(len(grown), 512 * 1024)
        self.assertLessEqual(grown.decode("utf-8").count("\n") + 1, producer.DIAGNOSTIC_MAX_LINES)
        self.assertTrue(all(len(line) <= producer.DIAGNOSTIC_MAX_LINE_UNITS
                            for line in grown.decode("utf-8").split("\n")))

    def test_build_diagnostic_payload_still_refuses_bad_shape_before_sanitising(self):
        for stdout, stderr in ((b"x" * 32_769, b""), (b"", b"y" * 32_769)):
            with self.subTest(size=len(stdout) + len(stderr)), self.assertRaises(producer.FeedbackRefusal) as raised:
                producer.build_diagnostic_payload(self._failed_outcome(stdout, stderr))
            self.assertEqual(raised.exception.reason, "capture_invalid")
        for bad in ("x", bytearray(b"x"), None):
            with self.subTest(stream=bad), self.assertRaises(producer.FeedbackRefusal):
                producer.build_diagnostic_payload(self._failed_outcome(bad, b""))

    def test_encryptor_refusal_classes_are_known_node_details(self):
        for code in ("bom", "c0", "c1", "cr", "nul", "utf8"):
            with self.subTest(code=code):
                stderr = ("KD-FEEDBACK-ENCRYPTION-REFUSAL invalid_payload_" + code + "\n").encode("ascii")
                self.assertEqual(producer._node_detail(stderr), "node_invalid_payload_" + code)
                self.assertIn("node_invalid_payload_" + code, producer.NODE_DETAILS)
        self.assertEqual(
            producer._node_detail(b"KD-FEEDBACK-ENCRYPTION-REFUSAL invalid_payload\n"), "node_invalid_payload")
        self.assertEqual(
            producer._node_detail(b"KD-FEEDBACK-ENCRYPTION-REFUSAL invalid_payload_other\n"), "node_exit")

    def test_build_diagnostic_payload_reports_full_parser_selection_and_refuses_skipped_stages(self):
        selected = producer.DIAGNOSTIC_GATE_SELECTIONS[1]
        successful = producer.build_diagnostic_payload({
            "failed_stage": None, "selected_gates": selected, "completed": selected,
            "returncode": 0, "stdout": b"", "stderr": b"",
            "stdout_truncated": False, "stderr_truncated": False,
        })
        self.assertEqual(
            successful,
            ("KD-BUILD-DIAGNOSTICS schema=1 selected_gates=" + ",".join(selected)
             + " completed_gates=" + ",".join(selected) + " result=all-gates-completed\n").encode("ascii"),
        )
        for outcome in (
            {
                "failed_stage": None, "selected_gates": producer.DIAGNOSTIC_BASE_GATES,
                "completed": producer.DIAGNOSTIC_BASE_GATES, "returncode": 0,
                "stdout": b"", "stderr": b"", "stdout_truncated": False,
                "stderr_truncated": False,
            },
            {
                "failed_stage": "parser_replay", "selected_gates": producer.DIAGNOSTIC_BASE_GATES,
                "completed": producer.DIAGNOSTIC_BASE_GATES, "returncode": 9,
                "stdout": b"", "stderr": b"", "stdout_truncated": False,
                "stderr_truncated": False,
            },
            {
                "failed_stage": "parser_replay", "selected_gates": selected,
                "completed": selected[:-2], "returncode": 9,
                "stdout": b"", "stderr": b"", "stdout_truncated": False,
                "stderr_truncated": False,
            },
            {
                "failed_stage": None, "selected_gates": selected,
                "completed": selected[:-1], "returncode": 0, "stdout": b"", "stderr": b"",
                "stdout_truncated": False, "stderr_truncated": False,
            },
        ):
            with self.subTest(outcome=outcome), self.assertRaises(producer.FeedbackRefusal):
                producer.build_diagnostic_payload(outcome)

    def test_worker_refuses_invalid_capture_framing_without_publishing_output(self):
        error = RuntimeError("synthetic malformed frame")
        error.reason = "capture_invalid"

        def refuse(*unused_args, **unused_kwargs):
            raise error

        rust = SimpleNamespace(_run_worker_command=refuse)
        with self.assertRaises(producer.FeedbackRefusal) as raised:
            producer._run_worker(
                rust, ("cargo", "fmt", "--check"), 501, {}, "/trusted/python", object(),
                "feedback_format", 10**12, allow_nonzero_capture=True,
            )
        self.assertEqual(raised.exception.reason, "capture_invalid")

    def test_inventoried_native_inputs_are_candidate_bound_and_use_inventory_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            relative = "runtime/apps/test-shell-desktop/src-tauri/resources/app.bin"
            source_file = source / relative
            source_file.parent.mkdir(parents=True)
            source_file.write_bytes(b"native-input")
            source_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1)
            original_lstat = Path.lstat

            def source_lstat(path):
                if path == source_file:
                    return source_info
                return original_lstat(path)

            payload = b"native-input"
            object_id = hashlib.sha1(
                b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload,
            ).hexdigest()
            with patch.object(producer, "_make_worker_directory"), \
                    patch.object(producer, "_read_file", return_value=payload) as read_file, \
                    patch.object(producer, "_write_worker_file") as write_file, \
                    patch.object(Path, "lstat", new=source_lstat):
                producer._copy_reviewed_files(
                    source, root / "worker", (relative,), 501, 20,
                    candidate_files={relative: ("100644", object_id)},
                    inventoried_paths=frozenset((relative,)),
                    inventory_file_max_bytes=cargo_bootstrap.MAX_INVENTORY_FILE_BYTES,
                )
            self.assertEqual(
                read_file.call_args.kwargs["maximum"],
                cargo_bootstrap.MAX_INVENTORY_FILE_BYTES,
            )
            self.assertEqual(write_file.call_args.args[1], payload)

    def test_runtime_package_root_parser_admits_only_wave_70a_and_70b_profiles(self):
        cases = (
            producer.RUNTIME_PACKAGE_ROOTS,
            producer.RUNTIME_PACKAGE_ROOTS + producer.RUNTIME_WAVE_70_APP_ROOTS,
            producer.RUNTIME_PACKAGE_ROOTS + producer.RUNTIME_WAVE_70_APP_ROOTS
            + producer.RUNTIME_WAVE_70_CRATE_ROOTS,
        )
        for roots in cases:
            manifest = "[workspace]\nmembers = [\n" + "".join(
                '    "' + path.as_posix().removeprefix("runtime/") + '",\n'
                for path in roots
            ) + "]\n"
            with self.subTest(member_count=len(roots)), patch.object(
                    producer, "_read_file", return_value=manifest.encode("ascii")):
                self.assertEqual(producer._runtime_package_roots(Path("/source"), "runtime"), roots)
        invalid = cases[-1] + (Path("runtime/crates/host/registry"),)
        manifest = "[workspace]\nmembers = [\n" + "".join(
            '    "' + path.as_posix().removeprefix("runtime/") + '",\n'
            for path in invalid
        ) + "]\n"
        with patch.object(producer, "_read_file", return_value=manifest.encode("ascii")):
            with self.assertRaises(producer.FeedbackRefusal):
                producer._runtime_package_roots(Path("/source"), "runtime")

    def test_source_profile_failure_restores_source_cwd_and_never_returns_payload(self):
        dispatch = _validated_dispatch("rust_patch")
        calls = []

        def reject_command(*unused_args, **unused_kwargs):
            calls.append("command")
            raise producer.FeedbackRefusal("command_failed")

        with patch.object(producer, "_reviewed_rust_paths", return_value=("crates/host/api/src/lib.rs",)):
            with patch.object(producer, "_source_root_files", return_value=("Cargo.toml",)):
                with patch.object(producer, "_copy_reviewed_files", return_value=None):
                    with patch.object(producer, "_run_worker", side_effect=reject_command):
                        with patch.object(producer.os, "chdir", side_effect=lambda path: calls.append(path)):
                            with self.assertRaises(producer.FeedbackRefusal):
                                producer.run_source_profile(
                                    dispatch, Path("/synthetic-source"), Path("/synthetic-worker"), 501,
                                    {}, {"cargo": Path("/trusted/cargo")}, {"python": "/trusted/python"},
                                    SimpleNamespace(PROBE_PRIMARY_GID=20), object(), object(),
                                    10**12, Path("/trusted/node"),
                                )
        self.assertEqual(calls[0], Path("/synthetic-worker/feedback-rust-format"))
        self.assertEqual(calls[-1], Path("/synthetic-source"))
        self.assertIn("command", calls)

    def test_full_foundation_rust_formatter_copies_fuzz_workspace_and_returns_only_rust_paths(self):
        dispatch = _validated_dispatch("rust_patch")
        fuzz_paths = ("fuzz/src/main.rs",) + tuple(
            "fuzz/fuzz_targets/" + name + ".rs" for name in sorted(producer.FOUNDATION_FUZZ_TARGETS)
        ) + ("fuzz/fuzz_targets/new_target.rs",)
        reviewed_paths = tuple(sorted(("crates/host/api/src/lib.rs",) + fuzz_paths))
        calls = []
        command_result = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            worker_storage = root / "worker"
            worker_storage.mkdir()

            def record_copy(source_path, destination, relative_paths, worker_uid, primary_gid):
                calls.append(("copy", source_path, destination, tuple(relative_paths), worker_uid, primary_gid))

            def record_command(*args, **kwargs):
                calls.append(("command", args[1], args[6], kwargs))
                return command_result

            def record_patch(source_path, formatted, paths, worker_uid, deadline, original_sources=None):
                calls.append(("patch", source_path, formatted, tuple(paths), worker_uid))
                return b"synthetic-format-patch"

            with patch.object(producer, "_reviewed_rust_paths", return_value=reviewed_paths) as reviewed:
                with patch.object(producer, "_copy_reviewed_files", side_effect=record_copy):
                    with patch.object(producer, "_run_worker", side_effect=record_command):
                        with patch.object(producer, "_rust_format_patch", side_effect=record_patch):
                            with patch.object(producer.os, "chdir", side_effect=lambda path:
                                    calls.append(("cwd", path))):
                                result = producer.run_source_profile(
                                    dispatch, source, worker_storage, 501, {},
                                    {"cargo": Path("/trusted/cargo")}, {"python": "/trusted/python"},
                                    SimpleNamespace(PROBE_PRIMARY_GID=20), object(), object(),
                    10**12, Path("/trusted/node"),
                                    validated_fuzz_workspace=True,
                                )

        self.assertEqual(reviewed.call_args.kwargs, {"include_fuzz": True})
        copy_call = next(call for call in calls if call[0] == "copy")
        copied_paths = set(copy_call[3])
        self.assertTrue(set(producer.FOUNDATION_FUZZ_MANIFESTS).issubset(copied_paths))
        self.assertTrue(set(fuzz_paths).issubset(copied_paths))
        self.assertNotIn("fuzz/corpus/seed", copied_paths)
        format_calls = [call for call in calls if call[0] == "command"]
        self.assertEqual([call[2] for call in format_calls], ["feedback_format", "feedback_parser_format"])
        self.assertEqual(format_calls[0][1][1:3], ("--offline", "fmt"))
        self.assertEqual(format_calls[0][1][4], str(worker_storage / "feedback-rust-format/Cargo.toml"))
        self.assertEqual(format_calls[1][1][5], str(worker_storage / "feedback-rust-format/fuzz/Cargo.toml"))
        self.assertEqual(format_calls[1][1][1:3], ("--locked", "--offline"))
        self.assertTrue(all(call[3]["allow_nonzero_capture"] for call in format_calls))
        patch_call = next(call for call in calls if call[0] == "patch")
        self.assertEqual(patch_call[1], source)
        self.assertNotEqual(patch_call[2], source)
        self.assertEqual(patch_call[3], tuple(sorted(reviewed_paths)))
        self.assertEqual(result["payload_bytes"], b"synthetic-format-patch")
        self.assertEqual(result["reviewed_rust_paths"], list(sorted(reviewed_paths)))
        self.assertNotIn("fuzz/Cargo.toml", result["reviewed_rust_paths"])
        self.assertNotIn("fuzz/Cargo.lock", result["reviewed_rust_paths"])

    def test_reviewed_fuzz_rust_paths_keep_fixed_paths_and_valid_new_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            crate_source = source / "crates/host/api/src"
            crate_source.mkdir(parents=True)
            (crate_source / "lib.rs").touch()
            for package_root in producer.PACKAGE_ROOTS[1:]:
                (source / package_root / "src").mkdir(parents=True)

            fuzz_directory = source / "fuzz/fuzz_targets"
            fuzz_directory.mkdir(parents=True)
            names = set(producer.FOUNDATION_FUZZ_TARGETS) | {"new_target"}
            for name in names:
                (fuzz_directory / (name + ".rs")).touch()
            fuzz_paths = ("fuzz/src/main.rs",) + tuple(
                "fuzz/fuzz_targets/" + name + ".rs" for name in sorted(names)
            )
            expected_files = {source / path for path in fuzz_paths}
            crate_file = crate_source / "lib.rs"
            source_directories = {
                source / package_root / "src" for package_root in producer.PACKAGE_ROOTS
            }
            file_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=0, st_nlink=1)
            directory_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o500, st_uid=0, st_nlink=1)
            original_lstat = Path.lstat

            def fixture_lstat(path, *args, **kwargs):
                if path in expected_files or path == crate_file:
                    return file_info
                if path in source_directories or path == fuzz_directory:
                    return directory_info
                return original_lstat(path, *args, **kwargs)

            with patch.object(Path, "lstat", fixture_lstat):
                legacy = producer._reviewed_rust_paths(source)
                complete = producer._reviewed_rust_paths(source, include_fuzz=True)

            self.assertEqual(legacy, ("crates/host/api/src/lib.rs",))
            self.assertEqual(
                complete,
                tuple(sorted(("crates/host/api/src/lib.rs",) + fuzz_paths)),
            )

            extra_target = fuzz_directory / "new_target.rs"
            extra_target.unlink()
            with patch.object(Path, "lstat", fixture_lstat):
                fixed_complete = producer._reviewed_rust_paths(source, include_fuzz=True)
            self.assertEqual(
                fixed_complete,
                tuple(sorted(("crates/host/api/src/lib.rs",) + producer.FOUNDATION_FUZZ_RUST_PATHS)),
            )
            extra_target.touch()

            unsafe_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=0, st_nlink=2)
            unsafe_paths = (
                source / producer.FOUNDATION_FUZZ_RUST_PATHS[0],
                extra_target,
            )
            for unsafe_path in unsafe_paths:
                def unsafe_lstat(path, *args, **kwargs):
                    if path == unsafe_path:
                        return unsafe_info
                    return fixture_lstat(path, *args, **kwargs)

                with patch.object(Path, "lstat", unsafe_lstat):
                    with self.assertRaises(producer.FeedbackRefusal) as raised:
                        producer._reviewed_rust_paths(source, include_fuzz=True)
                self.assertEqual(raised.exception.reason, "manifest_invalid")

    @staticmethod
    def _regular_lstat():
        file_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=0, st_nlink=1)
        directory_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o500, st_uid=0, st_nlink=1)
        original_lstat = Path.lstat

        def fixture_lstat(path, *args, **kwargs):
            if path.is_dir():
                return directory_info
            if path.is_file():
                return file_info
            return original_lstat(path, *args, **kwargs)

        return fixture_lstat

    def test_reviewed_rust_paths_include_every_admitted_crate_and_only_rust_files(self):
        self.assertEqual(len(producer.PACKAGE_ROOTS), 4)
        self.assertEqual(producer.PACKAGE_ROOTS[-1], Path("crates/kernel/i18n"))
        self.assertIn("crates/kernel/i18n/Cargo.toml", producer._source_root_files())
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            for package_root in producer.PACKAGE_ROOTS:
                (source / package_root / "src").mkdir(parents=True)
            kernel = source / "crates/kernel/i18n"
            (kernel / "src/pattern").mkdir()
            (kernel / "tests").mkdir()
            (kernel / "src/lib.rs").touch()
            (kernel / "src/pattern/parser.rs").touch()
            (kernel / "src/cldr46_cardinal_rules.md").touch()
            (kernel / "tests/message_keys.rs").touch()
            (kernel / "build.rs").touch()
            with patch.object(Path, "lstat", self._regular_lstat()):
                paths = producer._reviewed_rust_paths(source)
        self.assertEqual(paths, (
            "crates/kernel/i18n/src/lib.rs",
            "crates/kernel/i18n/src/pattern/parser.rs",
            "crates/kernel/i18n/tests/message_keys.rs",
        ))

    def test_batch_seven_full_crate_trees_are_admitted_and_unlisted_paths_are_refused(self):
        expected_rust_paths = []
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            runtime_directory = source / "runtime"
            runtime_directory.mkdir()
            runtime_members = tuple(
                root.as_posix().removeprefix("runtime/") for root in producer.RUNTIME_PACKAGE_ROOTS
            )
            runtime_manifest = "[workspace]\nmembers = [\n" + "".join(
                '    "' + member + '",\n' for member in runtime_members
            ) + "]\n"
            (runtime_directory / "Cargo.toml").write_text(runtime_manifest, encoding="ascii")
            for package_root in producer.RUNTIME_PACKAGE_ROOTS:
                (source / package_root / "src").mkdir(parents=True)
            for crate_root in producer.RUNTIME_BATCH_SEVEN_CRATE_ROOTS:
                crate_name = crate_root.name.replace("-", "_")
                (source / crate_root / "src/modules").mkdir(parents=True)
                (source / crate_root / "tests").mkdir()
                (source / crate_root / "README.md").write_text(crate_name + " crate overview.\n", encoding="ascii")
                (source / crate_root / "CONTRACT.md").write_text("Contract.\n", encoding="ascii")
                (source / crate_root / "CHANGELOG.md").write_text("Initial crate release.\n", encoding="ascii")
                (source / crate_root / "Cargo.toml").write_text("[package]\n", encoding="ascii")
                (source / crate_root / "src/lib.rs").write_text("pub fn crate_api() {}\n", encoding="ascii")
                (source / crate_root / "src/modules/mod.rs").write_text("pub fn module() {}\n", encoding="ascii")
                (source / crate_root / "tests/runtime.rs").write_text("fn works() {}\n", encoding="ascii")
                expected_rust_paths.extend((
                    crate_root.as_posix() + "/src/lib.rs",
                    crate_root.as_posix() + "/src/modules/mod.rs",
                    crate_root.as_posix() + "/tests/runtime.rs",
                ))
            with patch.object(producer, "_read_file", return_value=runtime_manifest.encode("ascii")):
                self.assertEqual(
                    producer._runtime_package_roots(source, "runtime"),
                    producer.RUNTIME_PACKAGE_ROOTS,
                )
            with patch.object(Path, "lstat", self._regular_lstat()):
                paths = producer._reviewed_rust_paths(source, roots=producer.RUNTIME_PACKAGE_ROOTS)
        self.assertEqual(paths, tuple(sorted(expected_rust_paths)))

        for crate_root in producer.RUNTIME_BATCH_SEVEN_CRATE_ROOTS:
            with self.subTest(missing_changelog=crate_root), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary)
                for package_root in producer.RUNTIME_PACKAGE_ROOTS:
                    (source / package_root / "src").mkdir(parents=True)
                for batch_root in producer.RUNTIME_BATCH_SEVEN_CRATE_ROOTS:
                    (source / batch_root / "README.md").write_text("Read me.\n", encoding="ascii")
                    (source / batch_root / "CONTRACT.md").write_text("Contract.\n", encoding="ascii")
                    (source / batch_root / "CHANGELOG.md").write_text(
                        "Initial crate release.\n", encoding="ascii",
                    )
                    (source / batch_root / "Cargo.toml").write_text("[package]\n", encoding="ascii")
                    (source / batch_root / "src/lib.rs").touch()
                (source / crate_root / "CHANGELOG.md").unlink()
                with patch.object(Path, "lstat", self._regular_lstat()):
                    with self.assertRaises(producer.FeedbackRefusal):
                        producer._reviewed_rust_paths(source, roots=producer.RUNTIME_PACKAGE_ROOTS)

    def test_batch_seven_documents_are_required_only_for_present_crates(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            crates_root = source / "runtime/crates"
            crates_root.mkdir(parents=True)
            with patch.object(Path, "lstat", self._regular_lstat()):
                producer._validate_runtime_batch_seven_trees(source)

            crate_root = source / producer.RUNTIME_BATCH_SEVEN_CRATE_ROOTS[0]
            (crate_root / "src").mkdir(parents=True)
            (crate_root / "Cargo.toml").write_text("[package]\n", encoding="ascii")
            (crate_root / "src/lib.rs").write_text("pub fn crate_api() {}\n", encoding="ascii")
            for missing_document in producer.RUNTIME_BATCH_SEVEN_DOC_FILES:
                with self.subTest(missing_document=missing_document):
                    with patch.object(Path, "lstat", self._regular_lstat()):
                        with self.assertRaises(producer.FeedbackRefusal):
                            producer._validate_runtime_batch_seven_trees(source)
                    (crate_root / missing_document).write_text("Crate documentation.\n", encoding="ascii")

            with patch.object(Path, "lstat", self._regular_lstat()):
                producer._validate_runtime_batch_seven_trees(source)

        invalid = (
            ("runtime/crates/host/registry/build.rs", "fn build() {}\n"),
            ("runtime/crates/services/palette/src/data.json", "{}\n"),
            ("runtime/crates/host/core/src/README.md", "Nested doc.\n"),
            ("runtime/crates/services/palette/src/CHANGELOG.md", "Nested changelog.\n"),
            ("runtime/crates/services/other/README.md", "Unlisted.\n"),
        )
        for relative, contents in invalid:
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary)
                for package_root in producer.RUNTIME_PACKAGE_ROOTS:
                    (source / package_root / "src").mkdir(parents=True)
                for crate_root in producer.RUNTIME_BATCH_SEVEN_CRATE_ROOTS:
                    (source / crate_root / "README.md").write_text("Read me.\n", encoding="ascii")
                    (source / crate_root / "CONTRACT.md").write_text("Contract.\n", encoding="ascii")
                    (source / crate_root / "CHANGELOG.md").write_text("Initial crate release.\n", encoding="ascii")
                    (source / crate_root / "Cargo.toml").write_text("[package]\n", encoding="ascii")
                    (source / crate_root / "src/lib.rs").touch()
                extra = source / relative
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_text(contents, encoding="ascii")
                with patch.object(Path, "lstat", self._regular_lstat()):
                    with self.assertRaises(producer.FeedbackRefusal):
                        producer._reviewed_rust_paths(source, roots=producer.RUNTIME_PACKAGE_ROOTS)

    def test_source_profile_copies_and_formats_the_kernel_crate(self):
        dispatch = _validated_dispatch("rust_patch")
        kernel_paths = ("crates/kernel/i18n/src/lib.rs",)
        copied = []
        with patch.object(producer, "_reviewed_rust_paths", return_value=kernel_paths), \
                patch.object(producer, "_copy_reviewed_files",
                             side_effect=lambda *args: copied.append(args)), \
                patch.object(producer, "_run_worker",
                             return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b"")), \
                patch.object(producer, "_rust_format_patch",
                             return_value=b"synthetic-format-patch") as format_patch, \
                patch.object(producer.os, "chdir"):
            result = producer.run_source_profile(
                dispatch, Path("/synthetic-source"), Path("/synthetic-worker"), 501, {},
                {"cargo": Path("/trusted/cargo")}, {"python": "/trusted/python"},
                SimpleNamespace(PROBE_PRIMARY_GID=20), object(), object(),
                10**12, Path("/trusted/node"),
            )
        self.assertEqual(len(copied), 1)
        self.assertIn("crates/kernel/i18n/Cargo.toml", copied[0][2])
        self.assertIn(kernel_paths[0], copied[0][2])
        self.assertEqual(format_patch.call_args.args[2], kernel_paths)
        self.assertEqual(result["reviewed_rust_paths"], list(kernel_paths))
        self.assertEqual(result["payload_bytes"], b"synthetic-format-patch")

    @unittest.skipUnless(sys.platform != "win32", "the macOS producer path is POSIX only")
    def test_encrypt_after_cleanup_retries_credential_text_with_captured_source_bytes(self):
        dispatch = _validated_dispatch("rust_patch")
        result = {
            "payload_bytes": b"synthetic-format-patch",
            "reviewed_rust_paths": ["src/lib.rs", "src/unchanged.rs"],
            "original_rust_sources": {"src/lib.rs": b"let token=CancellationToken::new();\n"},
        }
        calls = []

        def encrypt_payload(encryptor, record, node):
            calls.append(dict(record))
            if len(calls) == 1:
                raise producer.FeedbackRefusal("payload_invalid", "node_credential_like_content")
            return b"synthetic-ciphertext"

        with patch.object(producer, "_encrypt_payload", side_effect=encrypt_payload):
            ciphertext = producer.encrypt_after_cleanup(dispatch, result, Path("/trusted/node"))
        self.assertEqual(ciphertext, b"synthetic-ciphertext")
        self.assertNotIn("original_rust_files_b64", calls[0])
        self.assertEqual(calls[1]["original_rust_files_b64"], [{
            "path": "src/lib.rs",
            "content_b64": base64.b64encode(b"let token=CancellationToken::new();\n").decode("ascii"),
        }])
        self.assertNotIn("original_rust_files_b64", dispatch["request"])

    def test_reviewed_rust_path_cap_admits_the_four_crate_contract_and_is_enforced_at_the_boundary(self):
        self.assertGreater(producer.MAX_RUST_PATHS, 368)
        self.assertEqual(producer.MAX_RUST_PATHS, 512)
        for count, accepted in ((producer.MAX_RUST_PATHS, True), (producer.MAX_RUST_PATHS + 1, False)):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary)
                for package_root in producer.PACKAGE_ROOTS:
                    (source / package_root / "src").mkdir(parents=True)
                kernel_source = source / "crates/kernel/i18n/src"
                for index in range(count):
                    (kernel_source / ("module_" + str(index) + ".rs")).touch()
                with patch.object(Path, "lstat", self._regular_lstat()):
                    if accepted:
                        self.assertEqual(len(producer._reviewed_rust_paths(source)), count)
                    else:
                        with self.assertRaises(producer.FeedbackRefusal) as raised:
                            producer._reviewed_rust_paths(source)
                        self.assertEqual(raised.exception.reason, "manifest_invalid")

    def test_format_patch_loop_refuses_an_expired_deadline_before_reading_files(self):
        with patch.object(producer, "_read_file") as read_file, \
                patch.object(producer, "_read_worker_file") as read_worker:
            for deadline in (time.monotonic() - 1, 0, None, "later"):
                with self.subTest(deadline=deadline), self.assertRaises(producer.FeedbackRefusal) as raised:
                    producer._rust_format_patch(
                        Path("/synthetic-source"), Path("/synthetic-formatted"),
                        ("crates/kernel/i18n/src/lib.rs",), 501, deadline,
                    )
                self.assertEqual(raised.exception.reason, "command_failed")
        read_file.assert_not_called()
        read_worker.assert_not_called()

    def test_format_patch_loop_runs_while_the_deadline_is_open(self):
        original_sources = {}
        with patch.object(producer, "_read_file", return_value=b"fn a(){}\n"), \
                patch.object(producer, "_read_worker_file", return_value=b"fn a() {}\n"):
            payload = producer._rust_format_patch(
                Path("/synthetic-source"), Path("/synthetic-formatted"),
                ("crates/kernel/i18n/src/lib.rs",), 501, time.monotonic() + 600,
                original_sources=original_sources,
            )
        self.assertTrue(payload.startswith(b"diff --git a/crates/kernel/i18n/src/lib.rs "))
        self.assertEqual(original_sources, {"crates/kernel/i18n/src/lib.rs": b"fn a(){}\n"})

    def test_format_patch_limit_matches_the_profile_and_is_enforced_at_the_boundary(self):
        self.assertEqual(producer.MAX_PATCH_BYTES, 4 * 1024 * 1024 - 64 * 1024)
        self.assertEqual(producer.MAX_PATCH_BYTES, producer.MAX_FEEDBACK_PAYLOAD_BYTES)
        self.assertEqual(producer.MAX_PATCH_BYTES, producer.PROFILE_BY_KIND["rust_patch"]["max_payload_bytes"])
        self.assertLessEqual(producer.MAX_PATCH_BYTES, producer.MAX_CIPHERTEXT_BYTES - 64 * 1024)
        self.assertLessEqual(
            4 * ((producer.MAX_PATCH_BYTES + 2) // 3) + 128 * 1024, producer.MAX_NODE_INPUT_BYTES,
        )
        relative = "crates/kernel/i18n/src/lib.rs"
        header = len(("diff --git a/" + relative + " b/" + relative + "\n").encode("ascii"))
        for extra, accepted in ((0, True), (1, False)):
            body = "x" * (producer.MAX_PATCH_BYTES - header - 1 + extra) + "\n"
            with self.subTest(extra=extra), \
                    patch.object(producer, "_read_file", return_value=b"fn a(){}\n"), \
                    patch.object(producer, "_read_worker_file", return_value=b"fn a() {}\n"), \
                    patch.object(producer.difflib, "unified_diff", return_value=[body]):
                if accepted:
                    payload = producer._rust_format_patch(
                        Path("/synthetic-source"), Path("/synthetic-formatted"),
                        (relative,), 501, time.monotonic() + 600,
                    )
                    self.assertEqual(len(payload), producer.MAX_PATCH_BYTES)
                else:
                    with self.assertRaises(producer.FeedbackRefusal) as raised:
                        producer._rust_format_patch(
                            Path("/synthetic-source"), Path("/synthetic-formatted"),
                            (relative,), 501, time.monotonic() + 600,
                        )
                    self.assertEqual(raised.exception.reason, "payload_invalid")

    def test_cli_accepts_only_fixed_run_and_publisher_shapes(self):
        kind, core_args = producer._parse_cli([
            "run", "--profile", "rust_patch", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ])
        self.assertEqual(kind, "rust_patch")
        self.assertEqual(core_args[0:2], ["run", "--token-stdin"])
        self.assertEqual(producer._parse_cli(["run", "--profile", "invalid"]), ("invalid", []))
