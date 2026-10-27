"""Contract tests for the fixed private-source core runner."""

import builtins
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import macos_core_contract as subject
import macos_private_validation as private_validation


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

    def test_worker_privilege_probe_runs_census_immediately_after_probe(self):
        calls = []
        reviewed = SimpleNamespace(
            _child_environment=lambda *unused_args: {},
            _probe_argv=lambda *args: ("python", "-I", "-S", "-B", "-c", args[1], args[2]),
            _run_probe_step=lambda *args, **kwargs: calls.append(("probe", args, kwargs)),
            _worker_census=lambda *args: calls.append(("census", args, {})),
        )

        subject._run_privilege_probe(504, Path.cwd(), {"python": "/usr/bin/python3"}, reviewed)

        self.assertEqual([call[0] for call in calls], ["probe", "census"])

    def test_developer_mode_failure_stops_before_worker_and_source_lease(self):
        calls = []

        def reject_developer_mode():
            calls.append("developer_mode")
            raise RuntimeError("private helper failure")

        capability = SimpleNamespace(
            _disable_developer_mode=reject_developer_mode,
            _resolve_trusted_toolchain=lambda: calls.append("toolchain"),
            _create_probe_identity=lambda *args: calls.append("worker_identity"),
        )
        runtime = SimpleNamespace(
            RevocationState=lambda: calls.append("revocation_state"),
            parse_request=lambda *args: calls.append("parse_request"),
            validated_source=lambda *args, **kwargs: calls.append("source_lease"),
        )
        rules = SimpleNamespace(
            _finish_summary_guard=lambda *args, **kwargs: calls.append("summary_guard_finish"),
        )
        controls = (SimpleNamespace(), capability, runtime, SimpleNamespace(), rules)
        with patch.object(subject.os, "geteuid", return_value=0, create=True):
            with patch.object(subject, "_check_temp_root", return_value=None):
                with self.assertRaises(subject.Refusal) as raised:
                    subject._run_source(
                        _request(), _binding(), Path.cwd(), Path.cwd(), {}, controls,
                        DIFF_SHA256, 10**12, {},
                    )

        self.assertEqual(
            (raised.exception.reason, raised.exception.stage, raised.exception.diagnostic),
            ("runner_unavailable", "worker_setup", "disable_developer_mode"),
        )
        self.assertNotIn("private helper failure", str(raised.exception))
        self.assertEqual(calls, ["developer_mode", "summary_guard_finish"])

    def _run_inventory_lifecycle(self, restore_fails=False, prepare_fails=False,
                                 fail_after_worker=False, worker_cleanup_fails=False):
        calls = []

        def prepare(*arguments):
            calls.append(("prepare", arguments))
            if prepare_fails:
                raise private_validation.Refusal("revocation_policy_invalid", "revocation")
            return object()

        def restore(unused_state):
            calls.append(("restore",))
            if restore_fails:
                raise RuntimeError("cleanup refused")

        def close_only(unused_state):
            calls.append(("close_only",))

        def create_worker(*unused):
            calls.append(("worker_identity",))
            if fail_after_worker:
                return 504, Path("/tmp/worker-parent"), Path("/tmp/worker-home")
            raise RuntimeError("worker setup failed")

        def cleanup(*unused):
            calls.append(("worker_cleanup",))
            if worker_cleanup_fails:
                raise RuntimeError("worker cleanup failed")

        capability = SimpleNamespace(
            _disable_developer_mode=lambda: calls.append(("developer_mode",)),
            _resolve_trusted_toolchain=lambda: calls.append(("toolchain",)) or {"python": "/usr/bin/python3"},
            _resolve_worker_tools=lambda *unused: calls.append(("worker_tools",)) or {},
            _create_probe_identity=create_worker,
        )
        runtime = SimpleNamespace(
            Refusal=private_validation.Refusal,
            REASONS=private_validation.REASONS,
            STAGES=private_validation.STAGES,
            RevocationState=lambda: calls.append(("revocation_state",)),
            parse_request=lambda *unused: _request(),
            validated_source=lambda *unused, **kwargs: calls.append(("source_lease",)),
            _prepare_control_inventory=prepare,
            _restore_control_inventory=restore,
            _close_control_inventory=close_only,
        )
        reviewed = SimpleNamespace(_cleanup=cleanup)
        rules = SimpleNamespace(
            _finish_summary_guard=lambda *unused, **kwargs: calls.append(("summary_guard_finish",)),
        )
        controls = (reviewed, capability, runtime, SimpleNamespace(), rules)
        with patch.object(subject.os, "geteuid", return_value=0, create=True):
            with patch.object(subject, "_check_temp_root", return_value=None):
                with patch.object(subject, "_make_directory",
                                  side_effect=subject.Refusal("runner_unavailable", "worker_setup")):
                    with self.assertRaises(subject.Refusal) as raised:
                        subject._run_source(
                            _request(), _binding(), Path.cwd(), Path.cwd(), {}, controls,
                            DIFF_SHA256, 10**12, {},
                        )
        return calls, raised.exception

    def test_inventory_is_prepared_before_worker_and_restored_after_cleanup(self):
        calls, refusal = self._run_inventory_lifecycle(fail_after_worker=True)
        labels = [call[0] for call in calls]
        self.assertEqual(
            labels,
            ["developer_mode", "toolchain", "worker_tools", "prepare", "worker_identity",
             "worker_cleanup", "summary_guard_finish", "restore"],
        )
        self.assertNotIn("source_lease", labels)
        self.assertEqual((refusal.reason, refusal.stage, refusal.diagnostic),
                         ("runner_unavailable", "worker_setup", "create_run_directory"))

    def test_inventory_preparation_failure_stops_before_worker_and_source_lease(self):
        calls, refusal = self._run_inventory_lifecycle(prepare_fails=True)
        labels = [call[0] for call in calls]
        self.assertNotIn("worker_identity", labels)
        self.assertNotIn("source_lease", labels)
        self.assertNotIn("restore", labels)
        self.assertEqual(
            (refusal.reason, refusal.stage, refusal.diagnostic),
            ("source_validation_failed", "source_validation",
             "source_runtime_revocation_revocation_policy_invalid"),
        )

    def test_inventory_restore_failure_takes_cleanup_priority(self):
        calls, refusal = self._run_inventory_lifecycle(restore_fails=True, fail_after_worker=True)
        self.assertEqual(calls[-1][0], "restore")
        self.assertEqual((refusal.reason, refusal.stage, refusal.diagnostic),
                         ("cleanup_incomplete", "cleanup", "worker_cleanup"))

    def test_unconfirmed_worker_cleanup_closes_without_restoring_ownership(self):
        calls, refusal = self._run_inventory_lifecycle(
            fail_after_worker=True, worker_cleanup_fails=True,
        )
        labels = [call[0] for call in calls]
        self.assertLess(labels.index("worker_cleanup"), labels.index("summary_guard_finish"))
        self.assertLess(labels.index("summary_guard_finish"), labels.index("close_only"))
        self.assertNotIn("restore", labels)
        self.assertNotIn("source_lease", labels)
        self.assertEqual((refusal.reason, refusal.stage), ("cleanup_incomplete", "cleanup"))

    def test_worker_sudo_check_accepts_only_explicit_denial(self):
        devnull = object()
        pipe = object()

        def run_probe(sudo_result):
            calls = []
            writes = []
            modules = {
                "os": SimpleNamespace(
                    getuid=lambda: 504,
                    geteuid=lambda: 504,
                    getgid=lambda: 20,
                    environ={"HOME": "/worker-home"},
                    write=lambda descriptor, payload: writes.append((descriptor, payload)) or len(payload),
                ),
                "subprocess": SimpleNamespace(
                    DEVNULL=devnull, PIPE=pipe,
                    run=lambda argv, **kwargs: calls.append((argv, kwargs)) or sudo_result,
                ),
                "sys": SimpleNamespace(argv=("probe", "504")),
            }

            def import_module(name, globals=None, locals=None, fromlist=(), level=0):
                if name in modules:
                    return modules[name]
                return builtins.__import__(name, globals, locals, fromlist, level)

            script_globals = {
                "__builtins__": {**builtins.__dict__, "__import__": import_module},
            }
            exec(subject.PRIVILEGE_SCRIPT, script_globals)
            return calls, writes

        denied = SimpleNamespace(
            returncode=1, stdout=b"", stderr=b"sudo: a password is required\n",
        )
        calls, writes = run_probe(denied)
        self.assertEqual(calls[0][0], ("/usr/bin/sudo", "-n", "/usr/bin/true"))
        self.assertEqual(calls[0][1]["timeout"], 3)
        self.assertEqual(calls[0][1]["stdin"], devnull)
        self.assertEqual(calls[0][1]["stdout"], pipe)
        self.assertEqual(calls[0][1]["stderr"], pipe)
        self.assertTrue(calls[0][1]["close_fds"])
        self.assertEqual(writes, [(1, subject.PRIVILEGE_MARKER)])

        malformed_results = (
            SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
            SimpleNamespace(returncode=1, stdout=b"unexpected", stderr=b"sudo: a password is required\n"),
            SimpleNamespace(returncode=1, stdout=b"", stderr=b"permission denied\n"),
        )
        for result in malformed_results:
            with self.subTest(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr):
                with self.assertRaises(SystemExit) as raised:
                    run_probe(result)
                self.assertEqual(raised.exception.code, 54)

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

    def test_privilege_probe_maps_only_the_closed_native_cleanup_checks(self):
        cases = (
            ("probe_process_group_cleanup", "worker_privilege_probe_group_cleanup"),
            ("probe_process_capture_cleanup", "worker_privilege_probe_capture_cleanup"),
            ("probe_process_census", "worker_privilege_probe_census"),
            ("probe_process_survivor", "worker_privilege_probe_survivor"),
            ("probe_process_timeout", "worker_privilege_probe_timeout"),
            ("untrusted-private-check", "worker_privilege_probe"),
            (None, "worker_privilege_probe"),
            (["probe_process_census"], "worker_privilege_probe"),
            ({"probe_process_census": True}, "worker_privilege_probe"),
            (7, "worker_privilege_probe"),
        )
        for probe_check, expected_diagnostic in cases:
            cleanup_error = subject.Refusal("cleanup_incomplete", "cleanup")
            cleanup_error.probe_check = probe_check

            def fail_probe(*unused_args, **unused_kwargs):
                raise cleanup_error

            reviewed = SimpleNamespace(
                _child_environment=lambda *unused_args: {},
                _probe_argv=lambda *unused_args: ("python",),
                _run_probe_step=fail_probe,
                _worker_census=lambda *unused_args: None,
            )
            with self.subTest(probe_check=probe_check), self.assertRaises(subject.Refusal) as raised:
                subject._run_privilege_probe(504, Path.cwd(), {"python": "/usr/bin/python3"}, reviewed)
            self.assertEqual(raised.exception.reason, "cleanup_incomplete")
            self.assertEqual(raised.exception.stage, "cleanup")
            self.assertEqual(raised.exception.diagnostic, expected_diagnostic)

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

    def test_source_failure_details_survive_outer_reattach_and_cleanup_keeps_first_cause(self):
        source_failures = (
            ("invalid_input", "source_validation", "source_runtime_input_invalid_input"),
            ("source_validation_failed", "source_validation", "source_fetch_git_init_process_failure"),
            ("source_validation_failed", "source_validation", "source_bootstrap_tree_entries"),
            ("source_validation_failed", "source_validation", "source_lease_open_permission_error"),
        )
        for reason, stage, diagnostic in source_failures:
            diagnostics = subject._FailureDiagnostics()
            failure = subject.Refusal(reason, stage, diagnostic=diagnostic)
            for operation in ("source_lease_open", "source_lease_record", "source_tree_probe"):
                failure = diagnostics.attach(failure, operation)
                with self.subTest(diagnostic=diagnostic, operation=operation):
                    self.assertEqual(failure.diagnostic, diagnostic)
            payload = subject._format_refusal(failure)
            record = json.loads(payload)
            self.assertEqual(record["diagnostic"], diagnostic)
            self.assertEqual(payload, subject._canonical_json(record)[:-1])

        diagnostics = subject._FailureDiagnostics()
        primary = diagnostics.attach(
            subject.Refusal(
                "source_validation_failed", "source_validation",
                diagnostic="source_fetch_git_init_process_failure",
            ),
            "source_lease_open",
        )
        cleanup = diagnostics.attach(
            subject.Refusal("cleanup_incomplete", "cleanup"),
            "source_lease_cleanup", "cleanup_lease",
        )
        later_cleanup = diagnostics.attach(
            subject.Refusal("cleanup_incomplete", "cleanup"),
            "worker_cleanup", "cleanup_worker",
        )
        self.assertEqual(primary.diagnostic, "source_fetch_git_init_process_failure")
        self.assertEqual(cleanup.diagnostic, "cleanup_lease")
        self.assertEqual(later_cleanup.diagnostic, "cleanup_lease")
        self.assertEqual(
            json.loads(subject._format_refusal(later_cleanup))["diagnostic"],
            "cleanup_lease",
        )

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

    def test_source_gate_diagnostics_map_closed_checks_and_preserve_the_refusal_schema(self):
        cases = (
            ("spawn_failure", "version_mismatch", "gate_failed", "source_gate_spawn_failure"),
            ("nonzero_exit", "version_mismatch", "gate_failed", "source_gate_nonzero_exit"),
            ("helper_failure", "version_mismatch", "gate_failed", "source_gate_helper_failure"),
            ("capture_invalid", "capture_invalid", "capture_invalid", "source_gate_capture_invalid"),
            ("capture_overflow", "version_mismatch", "gate_failed", "source_gate_capture_overflow"),
        )
        for command_check, cause_reason, expected_reason, expected_diagnostic in cases:
            with self.subTest(command_check=command_check):
                class CommandFailure(Exception):
                    def __init__(self):
                        self.reason = cause_reason
                        self.command_check = command_check

                def fail_command(*unused_args, **unused_kwargs):
                    raise CommandFailure()

                rust = SimpleNamespace(_run_worker_command=fail_command)
                with self.assertRaises(subject.Refusal) as raised:
                    subject._run_gates(
                        Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                        rust, {"cargo": Path("/toolchain/bin/cargo")}, subject.time.monotonic() + 30,
                    )
                self.assertEqual(raised.exception.reason, expected_reason)
                self.assertEqual(raised.exception.stage, "format")
                attached = subject._FailureDiagnostics().attach(raised.exception, "source_gates")
                payload = subject._format_refusal(attached)
                record = json.loads(payload)
                self.assertEqual(record["diagnostic"], expected_diagnostic)
                self.assertEqual(record["reason"], expected_reason)
                self.assertEqual(record["stage"], "format")
                self.assertEqual(set(record), {"diagnostic", "reason", "schema_version", "stage", "status"})
                self.assertEqual(payload, subject._canonical_json(record)[:-1])

    def test_source_gate_cleanup_failure_keeps_cleanup_priority_over_command_check(self):
        class CleanupFailure(Exception):
            reason = "cleanup_incomplete"
            command_check = "nonzero_exit"

        def fail_command(*unused_args, **unused_kwargs):
            raise CleanupFailure()

        rust = SimpleNamespace(_run_worker_command=fail_command)
        with self.assertRaises(subject.Refusal) as raised:
            subject._run_gates(
                Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                rust, {"cargo": Path("/toolchain/bin/cargo")}, subject.time.monotonic() + 30,
            )
        self.assertEqual(raised.exception.reason, "cleanup_incomplete")
        self.assertEqual(raised.exception.stage, "cleanup")
        attached = subject._FailureDiagnostics().attach(raised.exception, "source_gates")
        self.assertNotIn(attached.diagnostic, subject.SOURCE_GATE_DIAGNOSTICS)
        self.assertEqual(
            set(json.loads(subject._format_refusal(attached))),
            {"diagnostic", "reason", "schema_version", "stage", "status"},
        )

    def test_unexpected_command_error_keeps_capture_invalid_diagnostic_through_reattachment(self):
        rust = subject._load_control_sibling("macos_rust_toolchain")

        class ProbeFailure(Exception):
            pass

        def fail_command(*unused_args, **unused_kwargs):
            raise RuntimeError("private helper detail")

        capability = SimpleNamespace(ProbeFailure=ProbeFailure, _run_as_probe_user=fail_command)
        with self.assertRaises(subject.Refusal) as raised:
            subject._run_gates(
                Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, capability,
                rust, {"cargo": Path("/toolchain/bin/cargo")}, subject.time.monotonic() + 30,
            )
        attached = raised.exception
        diagnostics = subject._FailureDiagnostics()
        for operation in ("source_gates", "source_lease_open", "source_gates"):
            attached = diagnostics.attach(attached, operation)
        payload = subject._format_refusal(attached)
        record = json.loads(payload)
        self.assertEqual(
            record,
            {"diagnostic": "source_gate_capture_invalid", "reason": "capture_invalid",
             "schema_version": 1, "stage": "format", "status": "refused"},
        )
        self.assertEqual(payload, subject._canonical_json(record)[:-1])
        self.assertNotIn(b"private helper detail", payload)

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

    def test_private_runtime_diagnostic_enums_track_the_bound_validator(self):
        runtime = subject._load_control_sibling("macos_private_validation")
        self.assertEqual(subject.PRIVATE_VALIDATION_REASONS, runtime.REASONS)
        self.assertEqual(subject.PRIVATE_VALIDATION_STAGES, runtime.STAGES)
        self.assertEqual(subject.PRIVATE_FETCH_OPERATIONS, runtime.FETCH_DIAGNOSTIC_OPERATIONS)
        self.assertEqual(subject.PRIVATE_FETCH_CLASSES, runtime.FETCH_DIAGNOSTIC_CLASSES)
        self.assertEqual(subject.CORE_BOOTSTRAP_CHECKS, runtime.CORE_BOOTSTRAP_CHECKS)
        self.assertEqual(
            subject.SOURCE_RUNTIME_DIAGNOSTICS,
            frozenset(
                "source_runtime_" + stage + "_" + reason
                for stage in runtime.STAGES for reason in runtime.REASONS
            ),
        )
        self.assertEqual(
            subject.SOURCE_FETCH_DIAGNOSTICS,
            frozenset(
                "source_fetch_" + operation + "_" + failure_class
                for operation in runtime.FETCH_DIAGNOSTIC_OPERATIONS
                for failure_class in runtime.FETCH_DIAGNOSTIC_CLASSES
            ),
        )

    def test_private_runtime_reason_stage_failures_have_bounded_diagnostics(self):
        runtime = subject._load_control_sibling("macos_private_validation")
        expected_mapping = {
            "cleanup_incomplete": ("cleanup_incomplete", "cleanup"),
            "revocation_unconfirmed": ("token_revocation_unconfirmed", "source_validation"),
            "signature_invalid": ("source_binding_mismatch", "source_validation"),
            "base_invalid": ("source_binding_mismatch", "source_validation"),
            "bootstrap_not_approved": ("source_binding_mismatch", "source_validation"),
            "invalid_input": ("invalid_input", "source_validation"),
        }
        for reason in runtime.REASONS:
            for stage in runtime.STAGES:
                error = runtime.Refusal(reason, stage)
                with self.subTest(reason=reason, stage=stage):
                    diagnostic = subject._source_runtime_diagnostic(runtime, error)
                    self.assertEqual(diagnostic, "source_runtime_" + stage + "_" + reason)
                    mapped = subject._runtime_refusal(runtime, error)
                    self.assertEqual(
                        (mapped.reason, mapped.stage),
                        expected_mapping.get(reason, ("source_validation_failed", "source_validation")),
                    )
                    refusal = subject.Refusal(
                        mapped.reason, mapped.stage, diagnostic=diagnostic,
                    )
                    self.assertLessEqual(len(subject._format_refusal(refusal)), subject.MAX_REFUSAL_BYTES)

        for reason, stage in ((["invalid_input"], "input"), ("invalid_input", ["input"])):
            error = SimpleNamespace(reason=reason, stage=stage)
            with self.subTest(reason=reason, stage=stage):
                self.assertIsNone(subject._source_runtime_diagnostic(runtime, error))

    def test_private_runtime_fetch_diagnostic_preserves_only_closed_operation_classes(self):
        runtime = subject._load_control_sibling("macos_private_validation")
        for operation in runtime.FETCH_DIAGNOSTIC_OPERATIONS:
            for failure_class in runtime.FETCH_DIAGNOSTIC_CLASSES:
                error = runtime.Refusal(
                    "source_fetch_unavailable", "fetch", (operation, failure_class),
                )
                with self.subTest(operation=operation, failure_class=failure_class):
                    self.assertEqual(
                        subject._source_runtime_diagnostic(runtime, error),
                        "source_fetch_" + operation + "_" + failure_class,
                    )
        malformed = (
            ("untrusted-operation", "process_failure"),
            ("git_init", "untrusted-class"),
            ["git_init", "process_failure"],
            {"operation": "git_init", "class": "process_failure"},
            ("git_init",),
        )
        for source_diagnostic in malformed:
            error = SimpleNamespace(
                reason="source_fetch_unavailable", stage="fetch",
                source_diagnostic=source_diagnostic,
            )
            with self.subTest(source_diagnostic=source_diagnostic):
                self.assertEqual(
                    subject._source_runtime_diagnostic(runtime, error),
                    "source_runtime_fetch_source_fetch_unavailable",
                )

    def test_private_runtime_bootstrap_check_is_closed_and_bound_to_bootstrap_failure(self):
        runtime = subject._load_control_sibling("macos_private_validation")
        for check in subject.CORE_BOOTSTRAP_CHECKS:
            error = runtime.Refusal("bootstrap_snapshot_invalid", "bootstrap")
            error.core_check = check
            with self.subTest(check=check):
                self.assertEqual(
                    subject._source_runtime_diagnostic(runtime, error),
                    "source_bootstrap_" + check,
                )
        for check in ("untrusted-check", None, ["tree_entries"], {"tree_entries": True}, 7):
            error = runtime.Refusal("bootstrap_snapshot_invalid", "bootstrap")
            error.core_check = check
            with self.subTest(check=check):
                self.assertEqual(
                    subject._source_runtime_diagnostic(runtime, error),
                    "source_runtime_bootstrap_bootstrap_snapshot_invalid",
                )
        wrong_reason = runtime.Refusal("bootstrap_not_approved", "bootstrap")
        wrong_reason.core_check = "tree_entries"
        self.assertEqual(
            subject._source_runtime_diagnostic(runtime, wrong_reason),
            "source_runtime_bootstrap_bootstrap_not_approved",
        )

    def test_source_lease_open_unknown_exception_class_uses_only_fixed_type_labels(self):
        class CustomTypeError(TypeError):
            pass

        cases = (
            (TypeError("private message"), "source_lease_open_type_error"),
            (AttributeError("private path"), "source_lease_open_attribute_error"),
            (ValueError("private value"), "source_lease_open_value_error"),
            (PermissionError("private path"), "source_lease_open_permission_error"),
            (FileNotFoundError("private path"), "source_lease_open_not_found"),
            (TimeoutError("private timing"), "source_lease_open_timeout"),
            (OSError("private path"), "source_lease_open_os_error"),
            (CustomTypeError("private subclass"), "source_lease_open_other"),
            (RuntimeError("private message"), "source_lease_open_other"),
        )
        for error, expected in cases:
            with self.subTest(error_type=type(error).__name__):
                diagnostic = subject._source_lease_open_exception_diagnostic(error)
                self.assertEqual(diagnostic, expected)
                refusal = subject.Refusal(
                    "source_validation_failed", "source_validation", diagnostic=diagnostic,
                )
                payload = subject._format_refusal(refusal)
                self.assertLessEqual(len(payload), subject.MAX_REFUSAL_BYTES)
                self.assertNotIn(str(error).encode("utf-8"), payload)


if __name__ == "__main__":
    unittest.main()
