import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


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
        "workflow_ref": "refs/heads/main",
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


def _main_with_fake_core_execute(execute):
    arguments = [
        "run", "--profile", "lock", "--token-stdin", "--source-sha", SOURCE_SHA,
        "--base-sha", BASE_SHA, "--base-branch", "develop",
    ]
    _request, environment = _dispatch("lock")
    output = io.StringIO()
    original_spec = importlib.util.spec_from_file_location

    def core_spec(name, path, *args, **kwargs):
        spec = original_spec(name, path, *args, **kwargs)
        if name == "macos_core_contract":
            original_loader = spec.loader

            class Loader:
                def create_module(self, spec):
                    return None

                def exec_module(self, module):
                    original_loader.exec_module(module)
                    module._execute = lambda actual, environ, token, lifecycle, feedback_kind=None: execute(
                        module, actual, environ, token, lifecycle, feedback_kind,
                    )

            spec.loader = Loader()
        return spec

    with patch.dict(sys.modules):
        with patch.object(importlib.util, "spec_from_file_location", side_effect=core_spec):
            status = producer.main(
                arguments=arguments, environ=environment, stdin=io.BytesIO(b"fixture-token\n"),
                stdout=output,
            )
    return status, output.getvalue()


def _foundation_bootstrap_with_fakes(**options):
    path = MODULE_PATH.with_name("test_foundation_node_feedback.py")
    spec = importlib.util.spec_from_file_location("foundation_node_feedback_main_fixtures", path)
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    return fixtures.FoundationNodeFeedbackTests()._run(
        "bootstrap", "lock", validated_tree="core_node_lock_return", **options,
    )


class MacosFeedbackProducerTests(unittest.TestCase):
    def test_dispatch_binds_each_closed_profile_and_omits_lock_kind_from_context(self):
        for kind in producer.PROFILE_BY_KIND:
            request, environment = _dispatch(kind)
            result = producer.validate_dispatch(kind, environment, now=NOW)
            self.assertEqual(result["request"], request)
            self.assertEqual(result["profile"], producer.PROFILE_BY_KIND[kind])
            self.assertEqual(result["context"]["concern"], request["concern"])
            self.assertEqual(result["context"]["run_id"], "9876")
            self.assertEqual(result["context"]["producer_job"],
                             producer.PROFILE_BY_KIND[kind]["producer_job"])
            self.assertEqual("kind" in result["context"], kind != "lock")

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

    def test_source_manifest_parser_rejects_duplicate_keys_and_derives_expectation(self):
        with self.assertRaises(producer.FeedbackRefusal):
            producer._strict_json(b'{"name":"x","name":"y"}', 128)

        root = {
            "name": "synthetic-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        }
        workspace = {"name": "@synthetic/host-api", "version": "1.0.0"}
        kernel_workspace = {"name": "@synthetic/kernel-i18n", "version": "1.0.0"}
        source = Path("/synthetic-source")
        files = {
            source / "package.json": json.dumps(root).encode("utf-8"),
            source / "packages/host-api/package.json": json.dumps(workspace).encode("utf-8"),
            source / "packages/kernel-i18n/package.json": json.dumps(kernel_workspace).encode("utf-8"),
        }
        with patch.object(producer, "_read_file", side_effect=lambda path, **unused: files[path]):
            expected = producer._expected_manifest(source)
        self.assertEqual(expected["root"], {
            "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        })
        self.assertEqual(expected["workspaces"], [
            {"path": "packages/host-api", "name": "@synthetic/host-api", "version": "1.0.0"},
            {"path": "packages/kernel-i18n", "name": "@synthetic/kernel-i18n", "version": "1.0.0"},
        ])
        self.assertEqual(
            producer.WORKSPACE_PACKAGE_PATHS, ("packages/host-api", "packages/kernel-i18n"),
        )

    def test_source_manifest_requires_both_workspaces_and_only_the_package_glob(self):
        source = Path("/synthetic-source")

        def expected_for(workspaces, present):
            root = {"name": "synthetic-root", "version": "1.0.0", "workspaces": workspaces}
            files = {source / "package.json": json.dumps(root).encode("utf-8")}
            for name in present:
                files[source / "packages" / name / "package.json"] = json.dumps(
                    {"name": "@synthetic/" + name, "version": "1.0.0"}
                ).encode("utf-8")

            def read(path, **unused):
                if path not in files:
                    producer._refuse("manifest_invalid")
                return files[path]

            with patch.object(producer, "_read_file", side_effect=read):
                return producer._expected_manifest(source)

        self.assertEqual(
            len(expected_for(["packages/*"], ("host-api", "kernel-i18n"))["workspaces"]), 2,
        )
        for workspaces, present in (
            (["packages/*"], ("kernel-i18n",)),
            (["packages/*"], ("host-api",)),
            (["packages/host-api"], ("host-api", "kernel-i18n")),
            (["packages/host-api", "packages/kernel-i18n"], ("host-api", "kernel-i18n")),
            (["packages/kernel-i18n"], ("host-api", "kernel-i18n")),
            (["apps/*"], ("host-api", "kernel-i18n")),
        ):
            with self.subTest(workspaces=workspaces, present=present):
                with self.assertRaises(producer.FeedbackRefusal) as raised:
                    expected_for(workspaces, present)
                self.assertEqual(raised.exception.reason, "manifest_invalid")

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
        stdout_prefix = b"bounded stdout\n" + (b"x" * (32_768 - len(b"bounded stdout\n")))
        stderr_prefix = b"bounded stderr\n" + (b"y" * (32_768 - len(b"bounded stderr\n")))
        payload = producer.build_diagnostic_payload({
            "failed_stage": "workspace_tests",
            "selected_gates": producer.DIAGNOSTIC_BASE_GATES,
            "completed": ("format", "clippy"),
            "returncode": 9,
            "stdout": stdout_prefix,
            "stderr": stderr_prefix,
            "stdout_truncated": True,
            "stderr_truncated": True,
        })
        self.assertTrue(payload.startswith(
            b"KD-BUILD-DIAGNOSTICS schema=1 stage=workspace_tests stdout_truncated=true "
            b"stderr_truncated=true exit=9 selected_gates=format,clippy,workspace_tests,api_tests,"
            b"mock_tests,conformance_tests completed_gates=format,clippy\n"
        ))
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

    def test_build_diagnostic_payload_records_reviewed_typescript_paths_digest(self):
        selected = producer.DIAGNOSTIC_GATE_SELECTIONS[-1]
        outcome = {
            "failed_stage": None, "selected_gates": selected, "completed": selected,
            "returncode": 0, "stdout": b"", "stderr": b"",
            "stdout_truncated": False, "stderr_truncated": False,
            "node_reviewed_file_count": 24, "node_reviewed_paths_sha256": "a" * 64,
        }
        payload = producer.build_diagnostic_payload(outcome)
        self.assertIn(b"node_reviewed_file_count=24 node_reviewed_paths_sha256=" + b"a" * 64, payload)
        with self.assertRaises(producer.FeedbackRefusal):
            producer.build_diagnostic_payload({
                key: value for key, value in outcome.items()
                if key not in ("node_reviewed_file_count", "node_reviewed_paths_sha256")
            })

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

    def test_foundation_payload_requires_all_rust_parser_and_node_stages(self):
        import foundation_node_feedback as adapter
        import macos_node_contract as contract
        rust_result = {
            "selected_gates": adapter.RUST_FOUNDATION_GATES,
            "completed": adapter.RUST_FOUNDATION_GATES, "failed_stage": None,
            "returncode": 0, "stdout": b"", "stderr": b"",
            "stdout_truncated": False, "stderr_truncated": False,
        }
        outcome = adapter.extend_diagnostic_outcome(
            rust_result, lambda: {
                "mode": "verify", "status": "passed", "stages": adapter.NODE_GATE_NAMES,
                "node_reviewed_file_count": 24, "node_reviewed_paths_sha256": "a" * 64,
            },
            contract,
        )
        payload = producer.build_diagnostic_payload(outcome)
        self.assertIn(b"typescript_typecheck,typescript_tests", payload)
        self.assertIn(b"result=all-gates-completed", payload)
        self.assertEqual(outcome["completed"], adapter.FULL_FOUNDATION_GATES)
        for missing in (1, 2, 4):
            with self.subTest(missing=missing), self.assertRaises(producer.FeedbackRefusal):
                producer.build_diagnostic_payload({
                    **outcome, "completed": outcome["completed"][:-missing],
                })
        failed = {**outcome, "failed_stage": "typescript_tests", "completed": outcome["completed"][:-1],
                  "returncode": 1, "stdout": b"private bounded error", "stderr": b""}
        self.assertIn(b"stage=typescript_tests", producer.build_diagnostic_payload(failed))

    def test_legacy_lock_generator_refuses_before_copy_or_execution(self):
        dispatch = _validated_dispatch("lock")
        with patch.object(producer, "_copy_reviewed_files") as copy_files:
            with patch.object(producer, "_run_worker") as run_worker:
                with self.assertRaises(producer.FeedbackRefusal):
                    producer.run_source_profile(
                        dispatch, Path("/synthetic-source"), Path("/synthetic-worker"),
                        501, {}, {}, {"python": "/trusted/python"},
                        SimpleNamespace(PROBE_PRIMARY_GID=20), object(), object(),
                        10**12, Path("/trusted/node"), Path("/trusted/npm-cli.js"),
                    )
        copy_files.assert_not_called()
        run_worker.assert_not_called()

    def test_reviewed_typescript_copy_uses_validator_file_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(producer, "_make_worker_directory"), \
                    patch.object(producer, "_read_file", return_value=b"source") as read_file, \
                    patch.object(producer, "_write_worker_file"):
                producer._copy_reviewed_files(
                    root / "source", root / "worker",
                    ("packages/host-api/tests/new-test.test.ts",), 501, 20,
                )
        self.assertEqual(read_file.call_args.kwargs["maximum"], producer.MAX_RUST_FILE_BYTES)

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
                                    10**12, Path("/trusted/node"), None,
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

            def record_patch(source_path, formatted, paths, worker_uid, deadline):
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
                                    10**12, Path("/trusted/node"), None,
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
                10**12, Path("/trusted/node"), None,
            )
        self.assertEqual(len(copied), 1)
        self.assertIn("crates/kernel/i18n/Cargo.toml", copied[0][2])
        self.assertIn(kernel_paths[0], copied[0][2])
        self.assertEqual(format_patch.call_args.args[2], kernel_paths)
        self.assertEqual(result["reviewed_rust_paths"], list(kernel_paths))
        self.assertEqual(result["payload_bytes"], b"synthetic-format-patch")

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

    def test_node_reviewed_file_bound_matches_the_foundation_adapter_and_two_packages(self):
        spec = importlib.util.spec_from_file_location(
            "foundation_node_feedback_bound",
            Path(__file__).resolve().parent / "foundation_node_feedback.py",
        )
        foundation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(foundation)
        self.assertEqual(producer.MAX_NODE_REVIEWED_FILES, 10 + 2 * (64 + 64))
        self.assertEqual(producer.MAX_NODE_REVIEWED_FILES, foundation.MAX_NODE_REVIEWED_FILES)
        selected = producer.DIAGNOSTIC_GATE_SELECTIONS[-1]
        for count, accepted in (
            (4, False), (5, True), (producer.MAX_NODE_REVIEWED_FILES, True),
            (producer.MAX_NODE_REVIEWED_FILES + 1, False),
        ):
            outcome = {
                "failed_stage": None, "selected_gates": selected, "completed": selected,
                "returncode": 0, "stdout": b"", "stderr": b"",
                "stdout_truncated": False, "stderr_truncated": False,
                "node_reviewed_file_count": count, "node_reviewed_paths_sha256": "a" * 64,
            }
            with self.subTest(count=count):
                if accepted:
                    self.assertIn(
                        b"node_reviewed_file_count=" + str(count).encode("ascii"),
                        producer.build_diagnostic_payload(outcome),
                    )
                else:
                    with self.assertRaises(producer.FeedbackRefusal):
                        producer.build_diagnostic_payload(outcome)

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
        with patch.object(producer, "_read_file", return_value=b"fn a(){}\n"), \
                patch.object(producer, "_read_worker_file", return_value=b"fn a() {}\n"):
            payload = producer._rust_format_patch(
                Path("/synthetic-source"), Path("/synthetic-formatted"),
                ("crates/kernel/i18n/src/lib.rs",), 501, time.monotonic() + 600,
            )
        self.assertTrue(payload.startswith(b"diff --git a/crates/kernel/i18n/src/lib.rs "))

    def test_format_patch_limit_matches_the_profile_and_is_enforced_at_the_boundary(self):
        self.assertEqual(producer.MAX_PATCH_BYTES, 4 * 1024 * 1024 - 64 * 1024)
        self.assertEqual(producer.MAX_PATCH_BYTES, producer.MAX_LOCK_BYTES)
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
            "run", "--profile", "lock", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ])
        self.assertEqual(kind, "lock")
        self.assertEqual(core_args[0:2], ["run", "--token-stdin"])
        self.assertEqual(producer._parse_cli(["run", "--profile", "invalid"]), ("invalid", []))

    @unittest.skipUnless(sys.platform != "win32", "the macOS producer path is POSIX only")
    def test_main_lock_profile_publishes_the_public_result_line(self):
        receipt = None

        def execute(core, arguments, environment, token, lifecycle, feedback_kind):
            nonlocal receipt
            self.assertEqual(arguments, [
                "run", "--token-stdin", "--source-sha", SOURCE_SHA,
                "--base-sha", BASE_SHA, "--base-branch", "develop",
            ])
            self.assertEqual(token, "fixture-token")
            self.assertEqual(feedback_kind, "lock")
            dispatch = producer.validate_dispatch(feedback_kind, environment, now=NOW)
            self.assertEqual(dispatch["profile"], producer.PROFILE_BY_KIND["lock"])
            lock_result, _adapter_producer, contract = _foundation_bootstrap_with_fakes()
            self.assertEqual(lock_result["mode"], "bootstrap")
            self.assertEqual(lock_result["stages"], ("node_dependency_prepare", "node_dependency_audit"))
            self.assertEqual(lock_result["provenance_candidate"]["generation_attempts"], 1)
            self.assertEqual(contract.call[0], "bootstrap")
            self.assertIsNone(contract.call[1]["accepted_lock"])
            self.assertIsNone(contract.call[1]["accepted_provenance"])
            ciphertext = hashlib.sha256(lock_result["lock_bytes"]).digest()
            receipt = producer.producer_receipt(dispatch, {
                "member_name": "lock-return-v1.enc",
                "ciphertext_digest": hashlib.sha256(ciphertext).hexdigest(),
                "member_size": len(ciphertext),
            })
            return receipt.encode("ascii")

        status, output = _main_with_fake_core_execute(execute)
        self.assertEqual(status, 0)
        self.assertEqual(output, "KD-FEEDBACK-PRODUCER " + receipt + "\n")

    @unittest.skipUnless(sys.platform != "win32", "the macOS producer path is POSIX only")
    def test_main_publishes_real_node_toolchain_refusal_mapping(self):
        worker_calls = []

        def execute(core, arguments, environment, token, lifecycle, feedback_kind):
            self.assertEqual(feedback_kind, "lock")
            self.assertEqual(lifecycle["token_revocation"], "unconfirmed")
            lifecycle["token_revocation"] = "confirmed_before_execution"
            path = MODULE_PATH.with_name("macos_node_contract.py")
            spec = importlib.util.spec_from_file_location("macos_node_contract_main_test", path)
            contract = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(contract)

            def run_worker(argv, **unused):
                self.assertEqual(lifecycle["token_revocation"], "confirmed_before_execution")
                worker_calls.append(tuple(argv))
                return SimpleNamespace(
                    returncode=0, stdout=b"v0.0.0\n", stderr=b"",
                    stdout_truncated=False, stderr_truncated=False,
                )

            with self.assertRaises(contract.NodeContractRefusal) as caught:
                contract._tool_versions(
                    run_worker, Path("node"), Path("npm-cli"), Path("project"), {},
                    producer.time.monotonic() + 60,
                )
            try:
                _foundation_bootstrap_with_fakes(
                    contract_error=caught.exception, real_node_contract=contract,
                )
            except contract.NodeContractRefusal as refusal:
                raise core._toolchain_refusal(refusal, "worker_setup")
            self.fail("bootstrap accepted a real Node contract refusal")

        status, output = _main_with_fake_core_execute(execute)
        self.assertEqual(worker_calls, [("node", "--version")])
        self.assertEqual(status, 1)
        self.assertEqual(
            output,
            'KD-FEEDBACK-PRODUCER-REFUSAL '
            '{"diagnostic":"source_gates_node_runtime_version_toolchain_mismatch",'
            '"reason":"runner_unavailable","schema_version":1,"stage":"worker_setup",'
            '"status":"refused"}\n',
        )


class CargoLockProducerTests(unittest.TestCase):
    def setUp(self):
        import cargo_lock_bootstrap
        self.bootstrap = cargo_lock_bootstrap
        self.rust = SimpleNamespace(TARGET="aarch64-apple-darwin", COMPONENTS=(
            SimpleNamespace(name="cargo", sha256="a" * 64),
            SimpleNamespace(name="rustc", sha256="b" * 64),
        ))
        self.environment = {
            "HOME": "/worker/home", "PATH": "/toolchain/bin:/usr/bin", "CARGO_HOME": "/other",
            "CARGO_NET_OFFLINE": "true", "HTTPS_PROXY": "synthetic", "RUSTC_WRAPPER": "/wrapper",
        }
        self.source_environ = {"SOURCE_REPOSITORY_OWNER": "owner", "SOURCE_REPOSITORY_NAME": "repository"}

    def _expected_hash(self):
        return self.bootstrap.cargo.toolchain_hash(
            "aarch64-apple-darwin", (("cargo", "a" * 64), ("rustc", "b" * 64)),
        )

    def _run(self, *, returncode=0, config_error=None, bundle_error=None, kind="cargo_lock",
             manifest_error=None, members_error=None, workspace=None):
        dispatch = _validated_dispatch(kind)
        if workspace is not None:
            dispatch["request"] = dict(dispatch["request"], workspace=workspace)
        state = {"commands": [], "bundles": [], "chdir": []}

        def record_command(*args, **kwargs):
            state["commands"].append((args, kwargs))
            return SimpleNamespace(returncode=returncode, stdout=b"", stderr=b"")

        def record_bundle(lock_bytes, context, **kwargs):
            state["bundles"].append((lock_bytes, context, kwargs))
            if bundle_error is not None:
                raise bundle_error
            return b"bundle-bytes"

        with tempfile.TemporaryDirectory() as temporary:
            worker_storage = Path(temporary) / "worker"
            worker_storage.mkdir()
            source = Path(temporary) / "source"
            source.mkdir()
            state["source"] = source
            state["worker_storage"] = worker_storage
            with patch.object(producer, "_reviewed_rust_paths", return_value=("crates/host/api/src/lib.rs",)), \
                    patch.object(producer, "_copy_reviewed_files") as copy_files, \
                    patch.object(producer, "_make_worker_directory"), \
                    patch.object(producer, "_run_worker", side_effect=record_command), \
                    patch.object(producer, "_read_worker_file", return_value=b"lock-bytes") as read_lock, \
                    patch.object(producer.os, "chdir", side_effect=lambda path: state["chdir"].append(path)), \
                    patch.object(self.bootstrap, "refuse_cargo_config",
                                 side_effect=config_error, return_value=True) as refuse_config, \
                    patch.object(self.bootstrap, "require_fresh_directory", return_value=True), \
                    patch.object(producer, "_read_file", return_value=b"manifest"), \
                    patch.object(self.bootstrap, "check_manifests",
                                 side_effect=manifest_error, return_value=frozenset(("host-api",))) as check_manifests, \
                    patch.object(self.bootstrap, "check_lock_members",
                                 side_effect=members_error, return_value=True) as check_members, \
                    patch.object(self.bootstrap, "produce_bundle", side_effect=record_bundle):
                state["check_manifests"] = check_manifests
                state["check_members"] = check_members
                state["copy"] = copy_files
                state["read_lock"] = read_lock
                state["refuse_config"] = refuse_config
                try:
                    state["result"] = producer.run_cargo_lock_profile(
                        dispatch, source, worker_storage, 501, self.environment,
                        {"cargo": Path("/trusted/cargo")}, {"python": "/trusted/python"},
                        SimpleNamespace(PROBE_PRIMARY_GID=20), self.rust, 10**12, self.bootstrap,
                        self.source_environ,
                    )
                except producer.FeedbackRefusal as error:
                    state["refusal"] = error.reason
        state["dispatch"] = dispatch
        return state

    def test_runtime_selector_maps_to_the_fixed_runtime_root_and_member_list(self):
        state = self._run(workspace="runtime")
        self.assertNotIn("refusal", state)
        project = state["worker_storage"] / "feedback-cargo-lock"
        runtime_members = tuple(root.as_posix() for root in producer.RUNTIME_PACKAGE_ROOTS)
        copied = state["copy"].call_args.args[2]
        self.assertEqual(copied[0], "runtime/Cargo.toml")
        self.assertEqual(copied[1:1 + len(runtime_members)], tuple(path + "/Cargo.toml" for path in runtime_members))
        self.assertNotIn("Cargo.toml", copied)
        manifests, members, selector = state["check_manifests"].call_args.args
        self.assertEqual(sorted(manifests), sorted(("runtime/Cargo.toml",) + tuple(path + "/Cargo.toml" for path in runtime_members)))
        self.assertEqual(members, frozenset(runtime_members))
        self.assertEqual(selector, "runtime")
        command = state["commands"][0][0][1]
        self.assertEqual(command[-3:], ("generate-lockfile", "--manifest-path", str(project / "runtime/Cargo.toml")))
        self.assertEqual(state["read_lock"].call_args.args[0], project / "runtime" / "Cargo.lock")
        lock_bytes, context, kwargs = state["bundles"][0]
        self.assertEqual(context["workspace_path"], "runtime")

    def test_contract_request_keeps_the_root_path_and_two_argument_manifest_check(self):
        state = self._run()
        self.assertEqual(len(state["check_manifests"].call_args.args), 2)
        self.assertEqual(state["bundles"][0][1]["workspace_path"], ".")

    def test_unknown_selector_refuses_before_copy_or_execution(self):
        for value in ("other", "", "runtime/", "Runtime"):
            state = self._run(workspace=value)
            with self.subTest(value=value):
                self.assertEqual(state["refusal"], "request_invalid")
                state["copy"].assert_not_called()
                self.assertEqual(state["commands"], [])

    def test_other_profile_kinds_and_bad_inputs_refuse_before_copy_or_execution(self):
        state = self._run(kind="rust_patch")
        self.assertEqual(state["refusal"], "request_invalid")
        state["copy"].assert_not_called()
        self.assertEqual(state["commands"], [])
        with patch.object(producer, "_copy_reviewed_files") as copy_files:
            with self.assertRaises(producer.FeedbackRefusal):
                producer.run_cargo_lock_profile(
                    _validated_dispatch("cargo_lock"), Path("/s"), Path("/w"), 501, {}, {},
                    {"python": "/p"}, SimpleNamespace(PROBE_PRIMARY_GID=20), self.rust, 10**12,
                    self.bootstrap, None,
                )
        copy_files.assert_not_called()

    def test_lock_generation_runs_one_forced_command_in_a_fresh_environment(self):
        state = self._run()
        self.assertNotIn("refusal", state)
        project = state["worker_storage"] / "feedback-cargo-lock"
        copied = state["copy"].call_args.args[2]
        self.assertEqual(copied, (
            "Cargo.toml", "crates/host/api/Cargo.toml", "crates/host/mock/Cargo.toml",
            "crates/host/conformance/Cargo.toml", "crates/kernel/i18n/Cargo.toml", "crates/host/api/src/lib.rs",
        ))
        self.assertNotIn("Cargo.lock", copied)
        self.assertEqual(
            [call.args[0] for call in state["refuse_config"].call_args_list], [state["source"], project],
        )
        self.assertEqual(len(state["commands"]), 1)
        args, kwargs = state["commands"][0]
        self.assertEqual(args[0], self.rust)
        command, worker_uid, cargo_environment = args[1], args[2], args[3]
        self.assertEqual(worker_uid, 501)
        self.assertEqual(args[4:8], ("/trusted/python", args[5], "feedback_lock", 10**12))
        self.assertTrue(kwargs["allow_nonzero_capture"])
        self.assertEqual(command[0], str(Path("/trusted/cargo")))
        self.assertEqual(command[1:-3], self.bootstrap.bootstrap_config_arguments())
        self.assertEqual(command[-3:], ("generate-lockfile", "--manifest-path", str(project / "Cargo.toml")))
        self.assertEqual(
            set(cargo_environment), {"PATH", "HOME", "CARGO_HOME", "TMPDIR", "LANG", "LC_ALL"},
        )
        self.assertEqual(cargo_environment["CARGO_HOME"], str(state["worker_storage"] / "cargo-lock-home"))
        self.assertEqual(cargo_environment["PATH"], self.environment["PATH"])
        self.assertEqual(state["chdir"], [project, state["source"]])
        self.assertEqual(state["read_lock"].call_args.args, (
            project / "Cargo.lock", 501, self.bootstrap.MAX_LOCK_BYTES,
        ))

    def test_bundle_is_bound_to_the_request_toolchain_and_pending_policy(self):
        state = self._run()
        lock_bytes, context, kwargs = state["bundles"][0]
        request = state["dispatch"]["request"]
        self.assertEqual(lock_bytes, b"lock-bytes")
        self.assertEqual(context, {
            "repository": "owner/repository",
            "workspace_path": ".",
            "source_sha": request["source_sha"],
            "base_sha": request["base_sha"],
            "base_branch": request["base_branch"],
            "reviewed_diff_fingerprint": request["reviewed_diff_sha256"],
            "dependency_policy_revision": self.bootstrap.DEPENDENCY_POLICY_REVISION,
            "control_sha": request["control_sha"],
            "toolchain_hash": self._expected_hash(),
        })
        self.assertEqual(kwargs["toolchain_target"], "aarch64-apple-darwin")
        self.assertEqual(state["check_members"].call_args.args, (b"lock-bytes", frozenset(("host-api",))))
        manifests, members = state["check_manifests"].call_args.args
        self.assertEqual(sorted(manifests), sorted((
            "Cargo.toml", "crates/host/api/Cargo.toml", "crates/host/mock/Cargo.toml",
            "crates/host/conformance/Cargo.toml", "crates/kernel/i18n/Cargo.toml",
        )))
        self.assertEqual(members, frozenset((
            "crates/host/api", "crates/host/mock", "crates/host/conformance", "crates/kernel/i18n",
        )))
        self.assertEqual(kwargs["run_id"], "9876")
        self.assertEqual(kwargs["run_attempt"], 1)
        self.assertEqual(kwargs["expiry"], request["expiry"])
        self.assertEqual(kwargs["build_inputs"], {})
        self.assertIsInstance(kwargs["fetcher"], self.bootstrap.RegistryFetcher)
        self.assertEqual(state["result"], {
            "payload_bytes": b"bundle-bytes", "expected_manifest": None,
            "reviewed_rust_paths": None, "source_result": "command_completed",
        })

    def test_refusals_map_to_fixed_producer_reasons_and_restore_the_source_directory(self):
        failed = self._run(returncode=1)
        self.assertEqual(failed["refusal"], "command_failed")
        self.assertEqual(failed["chdir"][-1], failed["source"])
        self.assertEqual(failed["bundles"], [])

        config = self._run(config_error=self.bootstrap.BootstrapRefusal("bootstrap_config_refused"))
        self.assertEqual(config["refusal"], "manifest_invalid")
        self.assertEqual(config["commands"], [])

        for reason, expected in (
            ("bootstrap_network_refused", "command_failed"),
            ("bootstrap_package_too_young", "payload_invalid"),
            ("bootstrap_package_yanked", "payload_invalid"),
            ("bootstrap_mismatch", "payload_invalid"),
            ("bootstrap_payload_too_large", "payload_invalid"),
            ("bootstrap_source_refused", "manifest_invalid"),
        ):
            with self.subTest(reason=reason):
                state = self._run(bundle_error=self.bootstrap.BootstrapRefusal(reason))
                self.assertEqual(state["refusal"], expected)
                self.assertNotIn("result", state)

    def test_toolchain_hash_requires_the_pinned_component_table(self):
        self.assertEqual(
            producer._cargo_toolchain_hash(self.rust, self.bootstrap),
            ("aarch64-apple-darwin", self._expected_hash()),
        )
        other = SimpleNamespace(TARGET="x86_64-unknown-linux-gnu", COMPONENTS=self.rust.COMPONENTS)
        self.assertNotEqual(
            producer._cargo_toolchain_hash(other, self.bootstrap)[1], self._expected_hash(),
        )
        for components in (
            None, (), [], (SimpleNamespace(name="cargo", sha256="short"),),
            (SimpleNamespace(name=1, sha256="a" * 64),),
        ):
            with self.subTest(components=repr(components)):
                with self.assertRaises(producer.FeedbackRefusal):
                    producer._cargo_toolchain_hash(
                        SimpleNamespace(TARGET="aarch64-apple-darwin", COMPONENTS=components),
                        self.bootstrap,
                    )
        with self.assertRaises(producer.FeedbackRefusal):
            producer._cargo_toolchain_hash(
                SimpleNamespace(TARGET=None, COMPONENTS=self.rust.COMPONENTS), self.bootstrap,
            )

    def test_manifest_and_lock_member_refusals_stop_before_cargo_or_publication(self):
        for stage in ("check_manifests", "check_lock_members"):
            with self.subTest(stage=stage):
                refusal = self.bootstrap.BootstrapRefusal(
                    "bootstrap_manifest_refused" if stage == "check_manifests" else "bootstrap_lock_refused"
                )
                if stage == "check_manifests":
                    state = self._run(manifest_error=refusal)
                else:
                    state = self._run(members_error=refusal)
                self.assertNotIn("result", state)
                self.assertEqual(state["bundles"], [])
                if stage == "check_manifests":
                    self.assertEqual(state["refusal"], "manifest_invalid")
                    self.assertEqual(state["commands"], [])
                    state["copy"].assert_not_called()
                else:
                    self.assertEqual(state["refusal"], "payload_invalid")


if __name__ == "__main__":
    unittest.main()
