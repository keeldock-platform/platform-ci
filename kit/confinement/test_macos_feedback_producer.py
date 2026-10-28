import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
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
        source = Path("/synthetic-source")
        files = {
            source / "package.json": json.dumps(root).encode("utf-8"),
            source / "packages/host-api/package.json": json.dumps(workspace).encode("utf-8"),
        }
        with patch.object(producer, "_read_file", side_effect=lambda path, **unused: files[path]):
            expected = producer._expected_manifest(source)
        self.assertEqual(expected["root"], {
            "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        })
        self.assertEqual(expected["workspaces"], [{
            "path": "packages/host-api", "name": "@synthetic/host-api", "version": "1.0.0",
        }])

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
            rust_result, lambda: {"mode": "verify", "status": "passed", "stages": adapter.NODE_GATE_NAMES},
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
        fuzz_paths = producer.FOUNDATION_FUZZ_RUST_PATHS
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

            def record_patch(source_path, formatted, paths, worker_uid):
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
        self.assertEqual(format_calls[0][1][3], str(worker_storage / "feedback-rust-format/Cargo.toml"))
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

    def test_reviewed_fuzz_rust_paths_are_fixed_and_reject_unsafe_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            crate_source = source / "crates/host/api/src"
            crate_source.mkdir(parents=True)
            (crate_source / "lib.rs").touch()
            for package_root in producer.PACKAGE_ROOTS[1:]:
                (source / package_root / "src").mkdir(parents=True)

            expected_files = {source / path for path in producer.FOUNDATION_FUZZ_RUST_PATHS}
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
                if path in source_directories:
                    return directory_info
                return original_lstat(path, *args, **kwargs)

            with patch.object(Path, "lstat", fixture_lstat):
                legacy = producer._reviewed_rust_paths(source)
                complete = producer._reviewed_rust_paths(source, include_fuzz=True)

            self.assertEqual(legacy, ("crates/host/api/src/lib.rs",))
            self.assertEqual(
                complete,
                tuple(sorted(("crates/host/api/src/lib.rs",) + producer.FOUNDATION_FUZZ_RUST_PATHS)),
            )

            unsafe_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=0, st_nlink=2)
            unsafe_path = source / producer.FOUNDATION_FUZZ_RUST_PATHS[0]

            def unsafe_lstat(path, *args, **kwargs):
                if path == unsafe_path:
                    return unsafe_info
                return fixture_lstat(path, *args, **kwargs)

            with patch.object(Path, "lstat", unsafe_lstat):
                with self.assertRaises(producer.FeedbackRefusal) as raised:
                    producer._reviewed_rust_paths(source, include_fuzz=True)
            self.assertEqual(raised.exception.reason, "manifest_invalid")

    def test_cli_accepts_only_fixed_run_and_publisher_shapes(self):
        kind, core_args = producer._parse_cli([
            "run", "--profile", "lock", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ])
        self.assertEqual(kind, "lock")
        self.assertEqual(core_args[0:2], ["run", "--token-stdin"])
        self.assertEqual(producer._parse_cli(["run", "--profile", "invalid"]), ("invalid", []))

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

    def test_main_publishes_real_node_toolchain_refusal_mapping(self):
        worker_calls = []

        def execute(core, arguments, environment, token, lifecycle, feedback_kind):
            self.assertEqual(feedback_kind, "lock")
            path = MODULE_PATH.with_name("macos_node_contract.py")
            spec = importlib.util.spec_from_file_location("macos_node_contract_main_test", path)
            contract = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(contract)

            def run_worker(argv, **unused):
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


if __name__ == "__main__":
    unittest.main()
