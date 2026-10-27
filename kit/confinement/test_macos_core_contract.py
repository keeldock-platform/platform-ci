"""Contract tests for the fixed private-source core runner."""

import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace

import macos_core_contract as subject


SOURCE_SHA = "a" * 40
BASE_SHA = "b" * 40
CONTROL_SHA = "c" * 40
DIFF_SHA256 = "d" * 64
CANDIDATE_REF = "refs/heads/feat/core-host-api"


def _binding():
    return {
        "control_sha": CONTROL_SHA,
        "run_id": "12345",
        "run_attempt": "2",
        "image_os": "macos-15-arm64",
        "image_version": "15.6.1",
    }


def _request():
    return {
        "source_sha": SOURCE_SHA,
        "base_sha": BASE_SHA,
        "base_branch": "develop",
        "concern": "core-contract",
    }


def _lease_record():
    return {"repository_id": "67890", "candidate_class": "signed-descendant"}


def _success_record():
    versions = {"rustc": "1.99.1", "cargo": "1.99.1", "rustfmt": "1.10.0", "clippy": "0.1.99"}
    gates = {name: "passed" for name in subject.GATE_NAMES}
    record = subject._build_success_record(
        _binding(), _request(), _lease_record(), DIFF_SHA256, versions, gates,
    )
    return record, versions, gates


class CoreContractTests(unittest.TestCase):
    def test_cli_accepts_only_fixed_run_shape(self):
        args = [
            "run", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ]
        self.assertEqual(subject._parse_arguments(args), _request())
        for invalid in (
            args + ["--gate", "api"],
            ["run", "--source-sha", SOURCE_SHA, "--token-stdin", "--base-sha", BASE_SHA,
             "--base-branch", "develop"],
            args[:-1] + ["feature"],
        ):
            with self.subTest(arguments=invalid), self.assertRaises(subject.Refusal):
                subject._parse_arguments(invalid)

    def test_privilege_identity_accepts_the_native_primary_group_20(self):
        worker_uid = 504
        self.assertIn(subject.PRIVILEGE_IDENTITY_CHECK, subject.PRIVILEGE_SCRIPT)

        def check(real_uid, effective_uid, primary_gid):
            simulated_os = SimpleNamespace(
                getuid=lambda: real_uid,
                geteuid=lambda: effective_uid,
                getgid=lambda: primary_gid,
                getgroups=lambda: [20],
            )
            exec(subject.PRIVILEGE_IDENTITY_CHECK, {"os": simulated_os, "uid": worker_uid})

        check(worker_uid, worker_uid, 20)
        for real_uid, effective_uid, primary_gid in (
            (worker_uid + 1, worker_uid, 20),
            (worker_uid, worker_uid + 1, 20),
            (worker_uid, worker_uid, 21),
        ):
            with self.subTest(real_uid=real_uid, effective_uid=effective_uid, primary_gid=primary_gid):
                with self.assertRaises(SystemExit):
                    check(real_uid, effective_uid, primary_gid)

    def test_privilege_probe_preserves_helper_cleanup_failure(self):
        cleanup_error = subject.Refusal("cleanup_incomplete", "cleanup")

        def fail_probe(*unused_args, **unused_kwargs):
            raise cleanup_error

        reviewed = SimpleNamespace(
            _child_environment=lambda *unused_args: {},
            _probe_argv=lambda *unused_args: ("python",),
            _run_probe_step=fail_probe,
            _worker_census=lambda *unused_args: None,
        )
        with self.assertRaises(subject.Refusal) as raised:
            subject._run_privilege_probe(504, Path.cwd(), {"python": "/usr/bin/python3"}, reviewed)
        self.assertEqual(raised.exception.reason, "cleanup_incomplete")
        self.assertEqual(raised.exception.stage, "cleanup")
        self.assertEqual(raised.exception.diagnostic, "worker_privilege_probe")

    def test_privilege_census_cleanup_has_a_distinct_diagnostic(self):
        def fail_census(*unused_args):
            raise subject.Refusal("cleanup_incomplete", "cleanup")

        reviewed = SimpleNamespace(
            _child_environment=lambda *unused_args: {},
            _probe_argv=lambda *unused_args: ("python",),
            _run_probe_step=lambda *unused_args, **unused_kwargs: None,
            _worker_census=fail_census,
        )
        with self.assertRaises(subject.Refusal) as raised:
            subject._run_privilege_probe(504, Path.cwd(), {"python": "/usr/bin/python3"}, reviewed)
        self.assertEqual(raised.exception.reason, "cleanup_incomplete")
        self.assertEqual(raised.exception.diagnostic, "worker_privilege_census")

    def test_failure_diagnostics_are_closed_and_keep_first_cleanup_cause(self):
        diagnostics = subject._FailureDiagnostics()
        ordinary = diagnostics.attach(
            subject.Refusal("runner_unavailable", "worker_setup"), "worker_privilege_probe",
        )
        self.assertEqual(ordinary.diagnostic, "worker_privilege_probe")
        cleanup = diagnostics.attach(
            subject.Refusal("cleanup_incomplete", "cleanup"), "worker_cleanup", "cleanup_worker",
        )
        later_cleanup = diagnostics.attach(
            subject.Refusal("cleanup_incomplete", "cleanup"), "summary_guard_finish", "cleanup_summary_close",
        )
        self.assertEqual(cleanup.diagnostic, "cleanup_worker")
        self.assertEqual(later_cleanup.diagnostic, "cleanup_worker")

        empty = subject._FailureDiagnostics().attach(
            subject.Refusal("invalid_input", "arguments"), "arguments",
        )
        unclassified = subject._FailureDiagnostics().attach(RuntimeError("private"), "unavailable")
        self.assertEqual(empty.diagnostic, "none")
        self.assertEqual(unclassified.diagnostic, "unavailable")

    def test_lease_exit_preserves_earlier_body_cleanup_diagnostic(self):
        diagnostics = subject._FailureDiagnostics()
        cleanup_state = {"first": None}

        @contextmanager
        def failing_lease_exit():
            try:
                yield object()
            finally:
                raise subject.Refusal(
                    "cleanup_incomplete", "cleanup", diagnostic="source_lease_cleanup",
                )

        with self.assertRaises(subject.Refusal) as raised:
            with subject._lease_with_diagnostic_capture(
                failing_lease_exit(), diagnostics, lambda: "worker_privilege_probe", cleanup_state,
            ):
                raise subject.Refusal(
                    "cleanup_incomplete", "cleanup", diagnostic="worker_privilege_probe",
                )

        preserved = diagnostics.attach(raised.exception, "source_lease_cleanup", cleanup_state["first"])
        self.assertEqual(preserved.reason, "cleanup_incomplete")
        self.assertEqual(preserved.diagnostic, "worker_privilege_probe")

    def test_review_binding_requires_every_protected_value(self):
        request = _request()
        binding = _binding()
        runtime = SimpleNamespace(SOURCE_CANDIDATE_REF_ENV="SOURCE_CANDIDATE_REF")
        environ = {
            "CORE_CONTRACT_ALLOWED_SHA": SOURCE_SHA,
            "CORE_CONTRACT_ALLOWED_CONTROL_SHA": CONTROL_SHA,
            "CORE_CONTRACT_REVIEWED_SOURCE_SHA": SOURCE_SHA,
            "CORE_CONTRACT_REVIEWED_BASE_SHA": BASE_SHA,
            "CORE_CONTRACT_REVIEWED_BASE_BRANCH": "develop",
            "CORE_CONTRACT_REVIEWED_CANDIDATE_REF": CANDIDATE_REF,
            "CORE_CONTRACT_REVIEWED_DIFF_SHA256": DIFF_SHA256,
            "SOURCE_CANDIDATE_REF": CANDIDATE_REF,
        }
        self.assertEqual(
            subject._validate_review_gate(request, binding, environ, runtime),
            (DIFF_SHA256, CANDIDATE_REF),
        )
        for name in (
            "CORE_CONTRACT_ALLOWED_SHA", "CORE_CONTRACT_ALLOWED_CONTROL_SHA",
            "CORE_CONTRACT_REVIEWED_SOURCE_SHA", "CORE_CONTRACT_REVIEWED_BASE_SHA",
            "CORE_CONTRACT_REVIEWED_BASE_BRANCH", "CORE_CONTRACT_REVIEWED_CANDIDATE_REF",
            "CORE_CONTRACT_REVIEWED_DIFF_SHA256",
        ):
            altered = dict(environ)
            altered[name] = "mismatch"
            with self.subTest(field=name), self.assertRaises(subject.Refusal):
                subject._validate_review_gate(request, binding, altered, runtime)

    def test_rust_commands_are_fixed_offline_and_cover_all_six_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            test_root = Path(temporary)
            source = test_root / "source"
            tool_paths = {"cargo": test_root / "toolchain" / "bin" / "cargo"}
            commands = subject._source_commands(source, tool_paths)
        self.assertEqual(tuple(stage for stage, unused_argv in commands), subject.GATE_NAMES)
        for stage, argv in commands:
            self.assertEqual(argv[0], str(tool_paths["cargo"]))
            self.assertTrue(all(argument.isascii() for argument in argv))
            self.assertNotIn("--command", argv)
            if stage == "format":
                self.assertEqual(argv[-2:], ("--", "--check"))
                self.assertNotIn("--offline", argv)
            else:
                self.assertIn("--offline", argv)
                self.assertIn("--locked", argv)
        self.assertIn(str(source / "crates/host/api/Cargo.toml"), commands[3][1])
        self.assertIn(str(source / "crates/host/mock/Cargo.toml"), commands[4][1])
        self.assertIn(str(source / "crates/host/conformance/Cargo.toml"), commands[5][1])

    def test_source_cwd_is_restored_before_lease_removes_checkout_on_success_and_failure(self):
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve() / "source"
            source.mkdir()

            @contextmanager
            def deleting_lease():
                try:
                    yield source
                finally:
                    self.assertEqual(Path.cwd(), original_cwd)
                    shutil.rmtree(source)

            with deleting_lease() as leased_source:
                observed = subject._run_inside_source(
                    leased_source, original_cwd, lambda: Path.cwd(),
                )
            self.assertEqual(observed, source)
            self.assertFalse(source.exists())

            source.mkdir()

            def fail_gate():
                raise subject.Refusal("gate_failed", "api_tests")

            with self.assertRaises(subject.Refusal):
                with deleting_lease() as leased_source:
                    subject._run_inside_source(leased_source, original_cwd, fail_gate)
            self.assertEqual(Path.cwd(), original_cwd)
            self.assertFalse(source.exists())

    def test_success_receipt_uses_four_suites_and_exact_integer_counts(self):
        record, versions, gates = _success_record()
        validated = subject._validate_success_record(
            record, _binding(), _request(), _lease_record(), DIFF_SHA256,
            versions, gates, True, True,
        )
        self.assertEqual(validated["suites"], [
            "core.static", "core.host-api", "core.mock-host", "core.conformance",
        ])
        self.assertEqual(validated["gate_count"], 6)
        self.assertEqual(validated["suite_count"], 4)
        for field in ("gate_count", "gates_passed", "gates_failed", "suite_count", "suites_passed", "suites_failed"):
            invalid = copy.deepcopy(record)
            invalid[field] = bool(invalid[field])
            with self.subTest(field=field), self.assertRaises(subject.Refusal):
                subject._validate_success_record(
                    invalid, _binding(), _request(), _lease_record(), DIFF_SHA256,
                    versions, gates, True, True,
                )
        extra = copy.deepcopy(record)
        extra["candidate_ref"] = CANDIDATE_REF
        with self.assertRaises(subject.Refusal):
            subject._validate_success_record(
                extra, _binding(), _request(), _lease_record(), DIFF_SHA256,
                versions, gates, True, True,
            )

    def test_refusal_is_closed_canonical_and_never_echoes_diagnostics(self):
        error = subject.Refusal("arbitrary-private-value", "untrusted-stage")
        error.diagnostic = "untrusted-private-diagnostic"
        payload = subject._format_refusal(error)
        record = json.loads(payload)
        self.assertEqual(
            record,
            {"diagnostic": "unavailable", "reason": "internal_error", "schema_version": 1,
             "stage": "internal", "status": "refused"},
        )
        self.assertEqual(payload, subject._canonical_json(record)[:-1])
        self.assertNotIn(b"arbitrary-private-value", payload)
        self.assertNotIn(b"untrusted-stage", payload)
        self.assertNotIn(b"untrusted-private-diagnostic", payload)


if __name__ == "__main__":
    unittest.main()
