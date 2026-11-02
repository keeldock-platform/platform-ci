"""Contract tests for the fixed private-source core runner."""

import builtins
import copy
import hashlib
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import macos_core_contract as subject
import macos_private_validation as private_validation
import feedback_failure
import macos_node_contract as real_node_contract
import macos_rust_toolchain as real_rust
import test_foundation_node_feedback as foundation_tests


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


def _success_record(include_runtime=False):
    versions = {"rustc": "1.99.1", "cargo": "1.99.1", "rustfmt": "1.10.0", "clippy": "0.1.99"}
    gates = {name: "passed" for name in subject.GATE_NAMES}
    if include_runtime:
        gates.update({name: "passed" for name in subject.RUNTIME_GATE_NAMES})
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

    def test_source_gates_cleanup_diagnostics_are_a_closed_member_set(self):
        classes = (
            "python", "ps", "developer_shim", "helper_preferences", "helper_notifications",
            "helper_launch_services", "helper_security", "helper_trust", "helper_containers",
            "apple_system_path", "other", "unknown", "additional",
        )
        expected = frozenset("source_gates_survivor_" + name for name in classes) | frozenset((
            "source_gates_survivor_multiple", "source_gates_timeout", "source_gates_census",
            "source_gates_group_cleanup", "source_gates_capture_cleanup", "source_gates_restore",
            "source_gates_cleanup_unclassified", "source_gates_wait_uncertain",
            "source_gates_audit_request",
        ))
        self.assertEqual(subject.SOURCE_GATES_CLEANUP_DIAGNOSTICS, expected)
        self.assertTrue(expected <= subject.DIAGNOSTICS)
        self.assertTrue(expected <= subject.DETAILED_DIAGNOSTICS)
        self.assertNotIn("source_gates_survivor_private", subject.DIAGNOSTICS)

    def test_source_gates_survivor_classes_match_the_census_class_order(self):
        import macos_capability

        self.assertEqual(subject.SOURCE_GATES_SURVIVOR_CLASSES, tuple(macos_capability.SURVIVOR_CLASS_ORDER))

    def test_node_cleanup_refusal_carries_only_a_listed_source_gates_diagnostic(self):
        for diagnostic in sorted(subject.SOURCE_GATES_CLEANUP_DIAGNOSTICS):
            error = SimpleNamespace(reason="cleanup_incomplete", cleanup_diagnostic=diagnostic)
            with self.subTest(diagnostic=diagnostic):
                refusal = subject._toolchain_refusal(error, "worker_setup")
                self.assertEqual((refusal.reason, refusal.stage), ("cleanup_incomplete", "cleanup"))
                self.assertEqual(refusal.diagnostic, diagnostic)
                attached = subject._FailureDiagnostics().attach(refusal, "source_gates")
                self.assertEqual(attached.diagnostic, diagnostic)
                self.assertEqual((attached.reason, attached.stage), ("cleanup_incomplete", "cleanup"))
        for unlisted in ("source_gates_survivor_private", "source_gates", "worker_cleanup", 7, None):
            error = SimpleNamespace(reason="cleanup_incomplete", cleanup_diagnostic=unlisted)
            with self.subTest(unlisted=unlisted):
                refusal = subject._toolchain_refusal(error, "worker_setup")
                self.assertEqual((refusal.reason, refusal.stage), ("cleanup_incomplete", "cleanup"))
                self.assertEqual(refusal.diagnostic, "unavailable")
                attached = subject._FailureDiagnostics().attach(refusal, "source_gates")
                self.assertEqual(attached.diagnostic, "source_gates")

    def test_summary_guard_detail_requires_exact_rules_refusal_and_known_check(self):
        class RulesRefusal(Exception):
            def __init__(self, reason, stage, diagnostic):
                self.reason = reason
                self.stage = stage
                self.diagnostic = diagnostic

        class OtherRulesRefusal(RulesRefusal):
            pass

        class MaliciousError(Exception):
            @property
            def reason(self):
                raise AssertionError("untrusted exception attribute was read")

        rules = SimpleNamespace(Refusal=RulesRefusal)
        for check, expected_diagnostic in subject.SUMMARY_GUARD_DIAGNOSTIC_MAP.items():
            with self.subTest(check=check):
                error = RulesRefusal("summary_guard_failed", "summary_guard", check)
                self.assertEqual(
                    subject._summary_guard_diagnostic(error, rules), expected_diagnostic,
                )
                self.assertIn(expected_diagnostic, subject.DIAGNOSTICS)
        accepted = RulesRefusal(
            "summary_guard_failed", "summary_guard", "protect_controls_file_reference",
        )
        public_diagnostic = subject._summary_guard_diagnostic(accepted, rules)
        self.assertEqual(public_diagnostic, "summary_guard_protect_controls_file_reference")
        attached = subject._FailureDiagnostics().attach(
            subject.Refusal("summary_guard_failed", "summary_guard", diagnostic=public_diagnostic),
            "summary_guard_setup",
        )
        self.assertEqual(attached.diagnostic, "summary_guard_protect_controls_file_reference")
        unrelated = subject._FailureDiagnostics().attach(
            subject.Refusal("summary_guard_failed", "summary_guard", diagnostic=public_diagnostic),
            "source_lease_request",
        )
        self.assertEqual(unrelated.diagnostic, "summary_guard_protect_controls_file_reference")

        class OtherCoreRefusal(subject.Refusal):
            pass

        malformed = (
            subject.Refusal("runner_unavailable", "summary_guard", diagnostic=public_diagnostic),
            subject.Refusal("summary_guard_failed", "worker_setup", diagnostic=public_diagnostic),
            OtherCoreRefusal("summary_guard_failed", "summary_guard", diagnostic=public_diagnostic),
        )
        for error in malformed:
            with self.subTest(error_type=type(error).__name__, reason=error.reason, stage=error.stage):
                reattached = subject._FailureDiagnostics().attach(error, "source_gates")
                self.assertEqual(reattached.diagnostic, "source_gates")

        cleanup_detail = RulesRefusal("cleanup_incomplete", "cleanup_summary", "remove_scratch")
        self.assertEqual(
            subject._summary_guard_diagnostic(cleanup_detail, rules),
            "summary_guard_remove_scratch",
        )

        for error in (
            OtherRulesRefusal("summary_guard_failed", "summary_guard", "input"),
            RulesRefusal("summary_guard_failed", "summary_guard", "private detail"),
            RulesRefusal("cleanup_incomplete", "cleanup", "remove_scratch"),
            RulesRefusal("runner_unavailable", "worker_setup", "input"),
            RuntimeError("private exception text"), MaliciousError(),
        ):
            with self.subTest(error_type=type(error).__name__):
                self.assertIsNone(subject._summary_guard_diagnostic(error, rules))

        diagnostics = subject._FailureDiagnostics()
        original = diagnostics.attach(
            subject.Refusal("summary_guard_failed", "summary_guard", diagnostic=public_diagnostic),
            "summary_guard_setup",
        )
        self.assertEqual(original.diagnostic, "summary_guard_protect_controls_file_reference")
        cleanup = diagnostics.attach(
            subject.Refusal("cleanup_incomplete", "cleanup"), "summary_guard_finish", "cleanup_summary",
        )
        self.assertEqual((cleanup.reason, cleanup.stage, cleanup.diagnostic),
                         ("cleanup_incomplete", "cleanup", "cleanup_summary"))

    def test_verify_controls_token_lists_equal_the_rules_bootstrap_lists(self):
        import macos_rules_bootstrap as rules_bootstrap

        for name in (
            "SUMMARY_GUARD_VERIFY_DIRECTORY_CLASSES", "SUMMARY_GUARD_VERIFY_FILE_CLASSES",
            "SUMMARY_GUARD_VERIFY_FAILURES", "SUMMARY_GUARD_VERIFY_CHECKS", "SUMMARY_GUARD_CHECKS",
        ):
            with self.subTest(name=name):
                self.assertEqual(getattr(subject, name), getattr(rules_bootstrap, name))
        self.assertEqual(len(subject.SUMMARY_GUARD_VERIFY_CHECKS), 84)
        self.assertEqual(len(rules_bootstrap.SUMMARY_GUARD_VERIFY_CHECKS), 84)

    def test_verify_controls_diagnostics_are_closed_mirrored_and_preserved(self):
        class RulesRefusal(Exception):
            def __init__(self, reason, stage, diagnostic):
                self.reason = reason
                self.stage = stage
                self.diagnostic = diagnostic

        rules = SimpleNamespace(Refusal=RulesRefusal)
        verify_checks = subject.SUMMARY_GUARD_VERIFY_CHECKS
        self.assertEqual(len(verify_checks), 84)
        self.assertLessEqual(verify_checks, subject.SUMMARY_GUARD_CHECKS)
        self.assertEqual(
            {check for check in subject.SUMMARY_GUARD_CHECKS if check.startswith("verify_controls_")},
            set(verify_checks),
        )
        for check in sorted(verify_checks):
            diagnostic = "summary_guard_" + check
            with self.subTest(check=check):
                self.assertRegex(check, r"\Averify_controls_[a-z]+(_[a-z]+)*\Z")
                self.assertEqual(
                    subject._summary_guard_diagnostic(
                        RulesRefusal("summary_guard_failed", "summary_guard", check), rules,
                    ),
                    diagnostic,
                )
                self.assertIn(diagnostic, subject.DIAGNOSTICS)
                attached = subject._FailureDiagnostics().attach(
                    subject.Refusal("summary_guard_failed", "summary_guard", diagnostic=diagnostic),
                    "summary_guard_setup",
                )
                self.assertEqual(attached.diagnostic, diagnostic)
                record = {
                    "diagnostic": diagnostic, "reason": "summary_guard_failed",
                    "schema_version": 1, "stage": "summary_guard", "status": "refused",
                }
                encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")
                self.assertEqual(
                    feedback_failure._parse_refusal(
                        feedback_failure.REFUSAL_PREFIX + encoded + b"\n"
                    ),
                    record,
                )
        for invalid in (
            "verify_controls_work_dir_access", "verify_controls_temp_dir", "verify_controls_",
            "verify_controls_temp_dir_private detail",
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(subject._summary_guard_diagnostic(
                    RulesRefusal("summary_guard_failed", "summary_guard", invalid), rules,
                ))
                self.assertNotIn("summary_guard_" + invalid, subject.DIAGNOSTICS)

    def test_summary_guard_diagnostic_survives_source_and_main_reattach(self):
        class RulesRefusal(Exception):
            def __init__(self, reason, stage, diagnostic):
                self.reason = reason
                self.stage = stage
                self.diagnostic = diagnostic

        rules = SimpleNamespace(Refusal=RulesRefusal)
        diagnostic = subject._summary_guard_diagnostic(
            RulesRefusal("summary_guard_failed", "summary_guard", "input"), rules,
        )
        refusal = subject.Refusal("summary_guard_failed", "summary_guard", diagnostic=diagnostic)
        runtime = SimpleNamespace(SOURCE_CANDIDATE_REF_ENV="SOURCE_CANDIDATE_REF")
        controls = (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), runtime,
                    SimpleNamespace(), rules)

        def fail_source(*unused_args, **unused_kwargs):
            raise refusal

        arguments = (
            "run", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        )
        with patch.object(subject, "_load_controls", return_value=controls):
            with patch.object(subject, "_validate_context", return_value=({}, Path.cwd(), Path.cwd())):
                with patch.object(subject, "_validate_review_gate", return_value=(DIFF_SHA256, CANDIDATE_REF)):
                    with patch.object(subject, "_check_temp_root"):
                        with patch.object(subject, "_validate_smoke_receipt", return_value={"rustc": "fixture"}):
                            with patch.object(subject, "_run_source", side_effect=fail_source):
                                with patch.object(subject.os, "geteuid", return_value=0, create=True):
                                    with patch.object(subject.sys, "platform", "darwin"):
                                        with patch.object(subject.platform, "machine", return_value="arm64"):
                                            with self.assertRaises(subject.Refusal) as raised:
                                                subject._execute(arguments, {}, "x", {})
        self.assertEqual(
            (raised.exception.reason, raised.exception.stage, raised.exception.diagnostic),
            ("summary_guard_failed", "summary_guard", "summary_guard_input"),
        )

        output = io.StringIO()
        with patch.object(subject, "_execute", side_effect=raised.exception):
            with patch.dict(subject.os.environ, {}):
                status = subject.main(arguments=(), environ={}, stdin=io.BytesIO(), stdout=output)
        self.assertEqual(status, 1)
        self.assertIn('"diagnostic":"summary_guard_input"', output.getvalue())

    def test_producer_revocation_marker_follows_successful_cleanup_on_late_refusal(self):
        arguments = [
            "run", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ]
        events = []
        output = io.StringIO()
        error_output = io.StringIO()

        def revoke(unused_environment, unused_token):
            events.append("revoke")
            return True

        rules = SimpleNamespace(_revoke_pending_token=revoke)
        with patch.object(subject, "_execute", side_effect=subject.Refusal("runner_unavailable", "receipt")):
            with patch.object(subject, "_load_control_sibling", return_value=rules):
                status = subject.main(
                    arguments=arguments, environ={}, stdin=io.BytesIO(b"fixture-token\n"),
                    stdout=output, stderr=error_output,
                )
        self.assertEqual(status, 1)
        self.assertEqual(events, ["revoke"])
        self.assertEqual(error_output.getvalue(), "KD-PRODUCER-TOKEN-REVOCATION confirmed\n")
        self.assertTrue(output.getvalue().startswith("KD-CORE-CONTRACT-REFUSAL "))

    def test_producer_revocation_marker_is_absent_when_token_stdin_read_fails(self):
        arguments = [
            "run", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ]
        output = io.StringIO()
        error_output = io.StringIO()
        with patch.object(subject, "_execute") as execute:
            status = subject.main(
                arguments=arguments, environ={}, stdin=io.BytesIO(),
                stdout=output, stderr=error_output,
            )
        self.assertEqual(status, 1)
        execute.assert_not_called()
        self.assertEqual(error_output.getvalue(), "")

    def test_producer_revocation_marker_is_absent_when_revoke_fails(self):
        arguments = [
            "run", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ]
        output = io.StringIO()
        error_output = io.StringIO()
        rules = SimpleNamespace(_revoke_pending_token=lambda unused_environment, unused_token: False)
        with patch.object(subject, "_execute", side_effect=subject.Refusal("runner_unavailable", "receipt")):
            with patch.object(subject, "_load_control_sibling", return_value=rules):
                status = subject.main(
                    arguments=arguments, environ={}, stdin=io.BytesIO(b"fixture-token\n"),
                    stdout=output, stderr=error_output,
                )
        self.assertEqual(status, 1)
        self.assertEqual(error_output.getvalue(), "")

    def test_producer_revocation_marker_is_printed_on_a_confirmed_normal_path(self):
        arguments = [
            "run", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ]
        output = io.StringIO()
        error_output = io.StringIO()

        def successful_execute(unused_arguments, unused_environment, unused_token, lifecycle, **unused_kwargs):
            lifecycle["token_revocation"] = "confirmed_before_execution"
            return b'{"status":"passed"}'

        with patch.object(subject, "_execute", side_effect=successful_execute):
            status = subject.main(
                arguments=arguments, environ={}, stdin=io.BytesIO(b"fixture-token\n"),
                stdout=output, stderr=error_output,
            )
        self.assertEqual(status, 0)
        self.assertEqual(error_output.getvalue(), "KD-PRODUCER-TOKEN-REVOCATION confirmed\n")

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

    def _real_node_refusal(self, **options):
        harness = foundation_tests.FoundationNodeFeedbackTests()
        with self.assertRaises(real_node_contract.NodeContractRefusal) as caught:
            harness._run(
                "bootstrap", "lock", validated_tree="core_node_lock_return",
                real_node_contract=real_node_contract, **options,
            )
        return caught.exception

    def _follow_refusal_to_the_published_line(self, body_error, expected):
        diagnostics = subject._FailureDiagnostics()
        cleanup_state = {"first": None}

        @contextmanager
        def lease():
            yield object()

        with self.assertRaises(real_node_contract.NodeContractRefusal) as raised:
            with subject._lease_with_diagnostic_capture(
                lease(), diagnostics, lambda: "source_gates", cleanup_state,
            ):
                raise body_error
        attached = diagnostics.attach(
            subject._toolchain_refusal(raised.exception, "worker_setup"), "source_gates",
            cleanup_state["first"],
        )
        self.assertEqual((attached.reason, attached.stage), ("cleanup_incomplete", "cleanup"))
        self.assertEqual(attached.diagnostic, expected)
        later = diagnostics.attach(
            subject.Refusal("cleanup_incomplete", "cleanup"), "worker_cleanup", None,
        )
        self.assertEqual(later.diagnostic, expected)
        reattached = subject._FailureDiagnostics().attach(attached, "source_gates")
        self.assertEqual((reattached.reason, reattached.stage), ("cleanup_incomplete", "cleanup"))
        self.assertEqual(reattached.diagnostic, expected)
        payload = subject._format_refusal(reattached)
        self.assertEqual(json.loads(payload)["diagnostic"], expected)
        line = feedback_failure.REFUSAL_PREFIX + payload + b"\n"
        self.assertEqual(feedback_failure.normalize_refusal(line), line)

    @unittest.skipUnless(os.name == "posix", "Node worker cleanup harness requires POSIX paths")
    def test_real_worker_survivor_class_survives_lease_capture_and_reattach(self):
        command_error = real_rust.Refusal(
            "cleanup_incomplete", command_check="helper_failure",
            probe_check="probe_process_survivor", survivor_classes=("ps",),
        )
        node_refusal = self._real_node_refusal(command_error=command_error)
        self.assertEqual(node_refusal.reason, "cleanup_incomplete")
        self.assertEqual(node_refusal.cleanup_diagnostic, "source_gates_survivor_ps")
        self._follow_refusal_to_the_published_line(node_refusal, "source_gates_survivor_ps")

    @unittest.skipUnless(os.name == "posix", "Node worker cleanup harness requires POSIX paths")
    def test_real_audit_request_cleanup_failure_survives_to_the_published_line(self):
        contract_error = real_node_contract.NodeContractRefusal(
            "cleanup_incomplete", stage="node_dependency_audit", substage="bulk_audit",
        )
        node_refusal = self._real_node_refusal(contract_error=contract_error)
        self.assertEqual(node_refusal.cleanup_diagnostic, "source_gates_audit_request")
        self._follow_refusal_to_the_published_line(node_refusal, "source_gates_audit_request")

    @unittest.skipUnless(os.name == "posix", "Node worker cleanup harness requires POSIX paths")
    def test_other_unrecorded_node_cleanup_failure_uses_the_unclassified_fallback(self):
        contract_error = real_node_contract.NodeContractRefusal(
            "cleanup_incomplete", stage="node_dependency_prepare", substage="runtime_version",
        )
        node_refusal = self._real_node_refusal(contract_error=contract_error)
        self.assertEqual(node_refusal.cleanup_diagnostic, "source_gates_cleanup_unclassified")
        self._follow_refusal_to_the_published_line(node_refusal, "source_gates_cleanup_unclassified")

    def test_unlisted_cleanup_diagnostic_on_a_real_node_refusal_keeps_the_generic_value(self):
        for unlisted in ("source_gates_survivor_private", "worker_cleanup", 7, None):
            error = real_node_contract.NodeContractRefusal(
                "cleanup_incomplete", stage="node_dependency_audit", substage="bulk_audit",
            )
            error.cleanup_diagnostic = unlisted
            with self.subTest(unlisted=unlisted):
                self._follow_refusal_to_the_published_line(error, "source_gates")

    def test_node_diagnostic_vocabulary_is_a_closed_generated_set(self):
        generated = set()
        for substage, reasons in subject.SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE:
            self.assertEqual(len(reasons), len(set(reasons)))
            self.assertNotIn("cleanup_incomplete", reasons)
            for reason in reasons:
                generated.add("source_gates_node_" + substage + "_" + reason)
        for substage in subject.SOURCE_GATES_NODE_COMMAND_SUBSTAGES:
            for check in subject.SOURCE_GATES_NODE_COMMAND_CHECKS:
                generated.add("source_gates_node_" + substage + "_command_" + check)
        self.assertEqual(subject.SOURCE_GATES_NODE_DIAGNOSTICS, frozenset(generated))
        self.assertEqual(len(subject.SOURCE_GATES_NODE_DIAGNOSTICS), 90)
        self.assertEqual(set(subject.SOURCE_GATES_NODE_DIAGNOSTIC_REASONS), generated)
        self.assertTrue(subject.SOURCE_GATES_NODE_DIAGNOSTICS <= subject.DIAGNOSTICS)
        self.assertTrue(subject.SOURCE_GATES_NODE_DIAGNOSTICS <= subject.DETAILED_DIAGNOSTICS)
        self.assertTrue(subject.SOURCE_GATES_NODE_DIAGNOSTICS <= subject.PRESERVED_SOURCE_DIAGNOSTICS)
        self.assertFalse(subject.SOURCE_GATES_NODE_DIAGNOSTICS & subject.CLEANUP_DIAGNOSTICS)
        self.assertEqual(
            set(subject.SOURCE_GATES_NODE_DIAGNOSTIC_REASONS.values()),
            {"capture_invalid", "runner_unavailable"},
        )
        for value in subject.SOURCE_GATES_NODE_DIAGNOSTICS:
            self.assertRegex(value, r"\Asource_gates_node_[a-z_]+\Z")
        self.assertEqual(
            subject.SOURCE_GATES_NODE_COMMAND_CHECKS,
            ("spawn_failure", "nonzero_exit", "timeout", "capture_invalid", "capture_overflow",
             "helper_failure"),
        )
        self.assertEqual(frozenset(subject.SOURCE_GATES_NODE_COMMAND_CHECKS), real_node_contract.COMMAND_CHECKS)
        self.assertEqual(frozenset(subject.SOURCE_GATES_NODE_COMMAND_CHECKS), real_rust.COMMAND_CHECKS)
        node_substages = {"none"} | set(foundation_tests.subject.NODE_SUBSTAGES)
        self.assertEqual(
            {name for name, unused in subject.SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE}, node_substages,
        )
        node_reasons = set(foundation_tests.subject.NODE_REASONS) - {"cleanup_incomplete"}
        for substage, reasons in subject.SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE:
            self.assertTrue(set(reasons) <= node_reasons)
        self.assertTrue(
            set(subject.SOURCE_GATES_NODE_COMMAND_SUBSTAGES) <= set(foundation_tests.subject.NODE_SUBSTAGES)
        )
        self.assertNotIn("lock_validation", subject.SOURCE_GATES_NODE_COMMAND_SUBSTAGES)

    def _published_node_refusal(self, error, stage="worker_setup"):
        diagnostics = subject._FailureDiagnostics()
        cleanup_state = {"first": None}

        @contextmanager
        def lease():
            yield object()

        with self.assertRaises(type(error)) as raised:
            with subject._lease_with_diagnostic_capture(
                lease(), diagnostics, lambda: "source_gates", cleanup_state,
            ):
                raise error
        self.assertIsNone(cleanup_state["first"])
        attached = diagnostics.attach(
            subject._toolchain_refusal(raised.exception, stage), "source_gates",
            cleanup_state["first"],
        )
        reattached = subject._FailureDiagnostics().attach(attached, "source_gates")
        self.assertEqual((reattached.reason, reattached.stage, reattached.diagnostic),
                         (attached.reason, attached.stage, attached.diagnostic))
        final = subject._FailureDiagnostics().attach(
            reattached, getattr(reattached, "diagnostic", "unavailable"),
        )
        self.assertEqual((final.reason, final.stage, final.diagnostic),
                         (attached.reason, attached.stage, attached.diagnostic))
        payload = subject._format_refusal(final)
        record = json.loads(payload)
        self.assertEqual(record["diagnostic"], attached.diagnostic)
        line = feedback_failure.REFUSAL_PREFIX + payload + b"\n"
        return attached, record, feedback_failure.normalize_refusal(line) == line

    NODE_STAGE_BY_SUBSTAGE = (
        ("runtime_version", "node_dependency_prepare"), ("npm_version", "node_dependency_prepare"),
        ("lock_generation", "node_dependency_prepare"), ("lock_validation", "node_dependency_prepare"),
        ("bulk_audit", "node_dependency_audit"), ("npm_ci", "node_dependency_audit"),
        ("typecheck", "typescript_typecheck"), ("tests", "typescript_tests"),
    )

    def _expected_node_stage(self, expected):
        for substage, stage in self.NODE_STAGE_BY_SUBSTAGE:
            if expected.startswith("source_gates_node_" + substage + "_"):
                return stage
        return "worker_setup"

    def _expect_node_diagnostic(self, error, expected, public_reason="runner_unavailable"):
        attached, record, normalized = self._published_node_refusal(error)
        expected_stage = self._expected_node_stage(expected)
        self.assertEqual(attached.diagnostic, expected)
        self.assertEqual((attached.reason, attached.stage), (public_reason, expected_stage))
        self.assertEqual(
            (record["reason"], record["stage"], record["diagnostic"]),
            (public_reason, expected_stage, expected),
        )
        self.assertTrue(normalized)

    def _real_tool_version_refusal(self, npm_stdout):
        def run_worker(argv, *, stage, substage, cwd, env, deadline, timeout, allow_nonzero_capture):
            stdout = (("v" + real_node_contract.NODE_VERSION + "\n").encode("ascii")
                      if substage == "runtime_version" else npm_stdout)
            return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"",
                                   stdout_truncated=False, stderr_truncated=False)

        with self.assertRaises(real_node_contract.NodeContractRefusal) as caught:
            real_node_contract._tool_versions(
                run_worker, Path("node"), Path("npm-cli"), Path("project"), {}, time.monotonic() + 60,
            )
        return caught.exception

    def _real_worker_refusal(self, substage, command_error):
        def run_worker(*arguments, **options):
            raise command_error

        with self.assertRaises(real_node_contract.NodeContractRefusal) as caught:
            real_node_contract._worker_result(
                run_worker, ("fixed",), stage="node_dependency_prepare", substage=substage,
                project=Path("project"), environment={}, deadline=time.monotonic() + 60, timeout=10,
            )
        return caught.exception

    @unittest.skipUnless(os.name == "posix", "Node worker harness requires POSIX paths")
    def test_real_npm_version_mismatch_publishes_its_substage_through_run_node_profile(self):
        refusal = self._real_tool_version_refusal(b"0.0.0\n")
        self.assertEqual((refusal.reason, refusal.substage), ("toolchain_mismatch", "npm_version"))
        raised = self._real_node_refusal(contract_error=refusal)
        self.assertIs(raised, refusal)
        self._expect_node_diagnostic(raised, "source_gates_node_npm_version_toolchain_mismatch")

    @unittest.skipUnless(os.name == "posix", "Node worker harness requires POSIX paths")
    def test_real_runtime_command_check_survives_run_node_profile_to_the_published_line(self):
        for check in sorted(real_rust.COMMAND_CHECKS):
            command_error = real_rust.Refusal("version_mismatch", command_check=check)
            with self.subTest(check=check):
                refusal = self._real_node_refusal(command_error=command_error)
                self.assertEqual(
                    (refusal.reason, refusal.substage, refusal.command_check),
                    ("command_failed", "runtime_version", check),
                )
                self._expect_node_diagnostic(
                    refusal, "source_gates_node_runtime_version_command_" + check,
                )

    @unittest.skipUnless(os.name == "posix", "Node worker harness requires POSIX paths")
    def test_real_lock_generation_failures_publish_command_check_or_plain_command_failed(self):
        command_error = real_rust.Refusal("version_mismatch", command_check="helper_failure")
        refusal = self._real_worker_refusal("lock_generation", command_error)
        self.assertEqual(refusal.command_check, "helper_failure")
        raised = self._real_node_refusal(contract_error=refusal)
        self._expect_node_diagnostic(raised, "source_gates_node_lock_generation_command_helper_failure")
        no_check = self._real_worker_refusal("lock_generation", RuntimeError("private"))
        self.assertIsNone(no_check.command_check)
        self._expect_node_diagnostic(
            self._real_node_refusal(contract_error=no_check),
            "source_gates_node_lock_generation_command_failed",
        )
        with self.assertRaises(real_node_contract.NodeContractRefusal) as caught:
            real_node_contract._validate_stage_result(
                SimpleNamespace(returncode=1, stdout=b"", stderr=b"", stdout_truncated=False,
                                stderr_truncated=False),
                "node_dependency_prepare", "lock_generation",
            )
        self._expect_node_diagnostic(
            self._real_node_refusal(contract_error=caught.exception),
            "source_gates_node_lock_generation_command_failed",
        )

    @unittest.skipUnless(os.name == "posix", "Node worker harness requires POSIX paths")
    def test_real_capture_invalid_keeps_its_public_reason_and_gains_the_substage(self):
        refusal = real_node_contract.NodeContractRefusal(
            "capture_invalid", stage="node_dependency_audit", substage="bulk_audit",
        )
        self._expect_node_diagnostic(
            self._real_node_refusal(contract_error=refusal),
            "source_gates_node_bulk_audit_capture_invalid", public_reason="capture_invalid",
        )

    def test_every_listed_node_combination_publishes_its_bound_value(self):
        stage_for = dict(self.NODE_STAGE_BY_SUBSTAGE)
        for substage, reasons in subject.SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE:
            for reason in reasons:
                error = real_node_contract.NodeContractRefusal(
                    reason, substage=None if substage == "none" else substage,
                    stage=stage_for.get(substage, "node_dependency_prepare"),
                )
                expected = "source_gates_node_" + substage + "_" + reason
                with self.subTest(diagnostic=expected):
                    self._expect_node_diagnostic(
                        error, expected,
                        public_reason="capture_invalid" if reason == "capture_invalid"
                        else "runner_unavailable",
                    )
        for substage in subject.SOURCE_GATES_NODE_COMMAND_SUBSTAGES:
            for check in subject.SOURCE_GATES_NODE_COMMAND_CHECKS:
                error = real_node_contract.NodeContractRefusal(
                    "command_failed", substage=substage, command_check=check,
                    stage=stage_for[substage],
                )
                expected = "source_gates_node_" + substage + "_command_" + check
                with self.subTest(diagnostic=expected):
                    self._expect_node_diagnostic(error, expected)

    def test_node_substage_values_bind_to_exactly_one_node_stage(self):
        stage_for = dict(self.NODE_STAGE_BY_SUBSTAGE)
        self.assertEqual(subject.SOURCE_GATES_NODE_STAGE_BY_SUBSTAGE, stage_for)
        self.assertEqual(
            set(stage_for.values()),
            {"node_dependency_prepare", "node_dependency_audit", "typescript_typecheck",
             "typescript_tests"},
        )
        self.assertEqual(set(stage_for.values()), set(foundation_tests.subject.NODE_GATE_NAMES))
        generated = {}
        for substage, reasons in subject.SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE:
            if substage in stage_for:
                for reason in reasons:
                    generated["source_gates_node_" + substage + "_" + reason] = stage_for[substage]
        for substage in subject.SOURCE_GATES_NODE_COMMAND_SUBSTAGES:
            for check in subject.SOURCE_GATES_NODE_COMMAND_CHECKS:
                generated["source_gates_node_" + substage + "_command_" + check] = stage_for[substage]
        self.assertEqual(subject.SOURCE_GATES_NODE_DIAGNOSTIC_STAGES, generated)
        self.assertEqual(len(generated), 90 - 10)
        self.assertTrue(set(generated) <= subject.SOURCE_GATES_NODE_DIAGNOSTICS)
        for diagnostic in subject.SOURCE_GATES_NODE_DIAGNOSTICS - set(generated):
            self.assertTrue(diagnostic.startswith("source_gates_node_none_"), msg=diagnostic)

    def test_node_substage_refusals_keep_worker_setup_without_a_known_substage(self):
        refusal = real_node_contract.NodeContractRefusal
        for stage in sorted(real_node_contract.STAGES):
            for reason in ("invalid_input", "tool_unavailable", "capture_invalid"):
                with self.subTest(stage=stage, reason=reason):
                    self._expect_node_diagnostic(
                        refusal(reason, stage=stage), "source_gates_node_none_" + reason,
                        public_reason="capture_invalid" if reason == "capture_invalid"
                        else "runner_unavailable",
                    )

    def test_node_substage_refusal_at_a_disagreeing_stage_keeps_the_generic_value(self):
        refusal = real_node_contract.NodeContractRefusal
        stage_for = dict(self.NODE_STAGE_BY_SUBSTAGE)
        for substage, bound in sorted(stage_for.items()):
            for stage in sorted(real_node_contract.STAGES - {bound}):
                with self.subTest(substage=substage, stage=stage):
                    self._expect_node_diagnostic(
                        refusal("command_failed", stage=stage, substage=substage, command_check="timeout"),
                        "source_gates",
                    )
        refused = subject._toolchain_refusal(
            refusal("command_failed", stage="typescript_tests", substage="tests", command_check="timeout"),
            "worker_setup",
        )
        self.assertEqual(
            (refused.reason, refused.stage, refused.diagnostic),
            ("runner_unavailable", "typescript_tests", "source_gates_node_tests_command_timeout"),
        )
        other = subject._toolchain_refusal(
            refusal("command_failed", stage="typescript_tests", substage="tests", command_check="timeout"),
            "toolchain_install",
        )
        self.assertEqual((other.reason, other.stage), ("toolchain_install_failed", "toolchain_install"))
        self.assertEqual(other.diagnostic, "unavailable")

    def test_unlisted_node_combinations_keep_the_generic_source_gates_value(self):
        refusal = real_node_contract.NodeContractRefusal
        tampered_substage = refusal("command_failed", substage="lock_generation")
        tampered_substage.substage = "private_substage"
        tampered_check = refusal("command_failed", substage="lock_generation", command_check="timeout")
        tampered_check.command_check = "private_check"
        tampered_reason = refusal("command_failed", substage="lock_generation")
        tampered_reason.reason = 7
        for error in (
            refusal("contract_refused", substage="lock_validation"),
            refusal("toolchain_mismatch", substage="bulk_audit"),
            refusal("vulnerable_dependency", substage="npm_ci"),
            refusal("command_failed", substage="lock_validation", command_check="timeout"),
            tampered_substage, tampered_check, tampered_reason,
        ):
            with self.subTest(reason=error.reason, substage=error.substage):
                self._expect_node_diagnostic(error, "source_gates")
        generic = SimpleNamespace(reason="command_failed", substage="lock_generation",
                                  command_check="spawn_failure")
        refused = subject._toolchain_refusal(generic, "worker_setup")
        self.assertEqual((refused.reason, refused.stage, refused.diagnostic),
                         ("runner_unavailable", "worker_setup", "unavailable"))
        self.assertEqual(
            subject._FailureDiagnostics().attach(refused, "source_gates").diagnostic, "source_gates",
        )
        other_stage = subject._toolchain_refusal(
            refusal("command_failed", substage="lock_generation", command_check="timeout"),
            "toolchain_install",
        )
        self.assertEqual((other_stage.reason, other_stage.stage), ("toolchain_install_failed", "toolchain_install"))
        self.assertEqual(other_stage.diagnostic, "unavailable")
        for unlisted in ("source_gates_node_private_command_timeout", "source_gates_node_", "source_gates_node"):
            forced = subject.Refusal("runner_unavailable", "worker_setup", diagnostic=unlisted)
            self.assertEqual(forced.diagnostic, "unavailable")
            self.assertEqual(
                subject._FailureDiagnostics().attach(forced, "source_gates").diagnostic, "source_gates",
            )

    def test_node_cleanup_refusal_still_wins_over_the_node_substage_value(self):
        error = real_node_contract.NodeContractRefusal(
            "cleanup_incomplete", stage="node_dependency_audit", substage="bulk_audit",
        )
        refusal = subject._toolchain_refusal(error, "worker_setup")
        self.assertEqual((refusal.reason, refusal.stage), ("cleanup_incomplete", "cleanup"))
        self.assertNotIn(refusal.diagnostic, subject.SOURCE_GATES_NODE_DIAGNOSTICS)

    def test_step_diagnostic_vocabulary_is_closed_bound_and_separate_from_the_substage_set(self):
        generated = {"source_gates_payload_invalid", "source_gates_payload_capture_invalid"}
        generated |= {
            "source_gates_node_profile_" + reason
            for reason in ("manifest_invalid", "command_failed", "capture_invalid", "output_unavailable")
        }
        generated |= {
            "source_gates_node_outcome_" + check
            for check in ("rust", "stage", "capture", "substage", "verification", "reviewed_files")
        }
        self.assertEqual(subject.SOURCE_GATES_STEP_DIAGNOSTICS, frozenset(generated))
        self.assertEqual(len(subject.SOURCE_GATES_STEP_DIAGNOSTICS), 12)
        self.assertEqual(set(subject.SOURCE_GATES_STEP_DIAGNOSTIC_REASONS), generated)
        self.assertEqual(
            set(subject.SOURCE_GATES_STEP_DIAGNOSTIC_REASONS.values()), {"capture_invalid", "runner_unavailable"},
        )
        self.assertEqual(
            {name for name, reason in subject.SOURCE_GATES_STEP_DIAGNOSTIC_REASONS.items()
             if reason == "capture_invalid"},
            {"source_gates_payload_capture_invalid", "source_gates_node_profile_capture_invalid"},
        )
        self.assertFalse(subject.SOURCE_GATES_STEP_DIAGNOSTICS & subject.SOURCE_GATES_NODE_DIAGNOSTICS)
        self.assertFalse(subject.SOURCE_GATES_STEP_DIAGNOSTICS & subject.CLEANUP_DIAGNOSTICS)
        self.assertTrue(subject.SOURCE_GATES_STEP_DIAGNOSTICS <= subject.DIAGNOSTICS)
        self.assertTrue(subject.SOURCE_GATES_STEP_DIAGNOSTICS <= subject.DETAILED_DIAGNOSTICS)
        self.assertTrue(subject.SOURCE_GATES_STEP_DIAGNOSTICS <= subject.PRESERVED_SOURCE_DIAGNOSTICS)
        self.assertEqual(
            {key[0] for key in subject.SOURCE_GATES_STEP_DIAGNOSTICS_BY_KEY},
            {"payload", "node_profile", "node_outcome"},
        )
        for key, diagnostic in subject.SOURCE_GATES_STEP_DIAGNOSTICS_BY_KEY.items():
            self.assertRegex(diagnostic, r"\Asource_gates_[a-z_]+\Z")
            self.assertIn(diagnostic, subject.DIAGNOSTICS)

    def test_node_gate_names_are_refusal_stages(self):
        self.assertTrue(real_node_contract.STAGES <= subject.STAGES)
        self.assertTrue(set(foundation_tests.subject.NODE_GATE_NAMES) <= subject.STAGES)
        for stage in sorted(real_node_contract.STAGES):
            with self.subTest(stage=stage):
                refusal = subject.Refusal("runner_unavailable", stage)
                self.assertEqual(refusal.stage, stage)
        self.assertEqual(subject.Refusal("runner_unavailable", "typescript_private").stage, "internal")

    def _tagged_error(self, reason, step, key):
        error = Exception("synthetic")
        error.reason = reason
        error.source_gates_step = step
        error.source_gates_key = key
        return error

    def test_payload_failures_publish_their_fixed_step_diagnostic(self):
        self._expect_node_diagnostic(
            self._tagged_error("payload_invalid", "payload", "payload_invalid"),
            "source_gates_payload_invalid",
        )
        self._expect_node_diagnostic(
            self._tagged_error("capture_invalid", "payload", "capture_invalid"),
            "source_gates_payload_capture_invalid", public_reason="capture_invalid",
        )

    def test_node_profile_failures_publish_their_fixed_step_diagnostic(self):
        for reason in ("manifest_invalid", "command_failed", "capture_invalid", "output_unavailable"):
            with self.subTest(reason=reason):
                self._expect_node_diagnostic(
                    self._tagged_error(reason, "node_profile", reason),
                    "source_gates_node_profile_" + reason,
                    public_reason="capture_invalid" if reason == "capture_invalid" else "runner_unavailable",
                )

    def test_node_outcome_failures_publish_their_fixed_step_diagnostic(self):
        for check in subject.SOURCE_GATES_NODE_OUTCOME_CHECKS:
            with self.subTest(check=check):
                self._expect_node_diagnostic(
                    foundation_tests.subject.NodeOutcomeInvalid("synthetic", check),
                    "source_gates_node_outcome_" + check,
                )
        with self.assertRaises(foundation_tests.subject.NodeOutcomeInvalid) as caught:
            foundation_tests.subject.extend_diagnostic_outcome({}, lambda: None, SimpleNamespace())
        self._expect_node_diagnostic(caught.exception, "source_gates_node_outcome_rust")

    def test_unlisted_or_mismatched_step_tags_keep_the_generic_source_gates_value(self):
        for error in (
            self._tagged_error("payload_invalid", "payload", "private"),
            self._tagged_error("payload_invalid", "private", "payload_invalid"),
            self._tagged_error("payload_invalid", "payload", 7),
            self._tagged_error("payload_invalid", 7, "payload_invalid"),
            self._tagged_error("command_failed", "payload", "capture_invalid"),
            self._tagged_error("command_failed", "node_profile", "capture_invalid"),
            self._tagged_error(None, "node_outcome", "private"),
            self._tagged_error(None, None, None),
        ):
            with self.subTest(reason=error.reason, step=error.source_gates_step, key=error.source_gates_key):
                self._expect_node_diagnostic(error, "source_gates")

    def test_step_tags_never_override_cleanup_or_other_stages(self):
        tagged = self._tagged_error("cleanup_incomplete", "node_profile", "command_failed")
        refusal = subject._toolchain_refusal(tagged, "worker_setup")
        self.assertEqual((refusal.reason, refusal.stage), ("cleanup_incomplete", "cleanup"))
        self.assertNotIn(refusal.diagnostic, subject.SOURCE_GATES_STEP_DIAGNOSTICS)
        other_stage = subject._toolchain_refusal(
            self._tagged_error("payload_invalid", "payload", "payload_invalid"), "toolchain_install",
        )
        self.assertEqual((other_stage.reason, other_stage.stage), ("toolchain_install_failed", "toolchain_install"))
        self.assertEqual(other_stage.diagnostic, "unavailable")
        for unlisted in ("source_gates_payload_private", "source_gates_node_outcome_", "source_gates_node_profile"):
            forced = subject.Refusal("runner_unavailable", "worker_setup", diagnostic=unlisted)
            self.assertEqual(forced.diagnostic, "unavailable")

    def test_step_tag_helper_keeps_the_first_tag_and_never_raises(self):
        error = Exception("synthetic")
        subject._tag_source_gates_step(error, "payload", "payload_invalid")
        subject._tag_source_gates_step(error, "node_profile", "command_failed")
        self.assertEqual((error.source_gates_step, error.source_gates_key), ("payload", "payload_invalid"))
        subject._tag_source_gates_step(object(), "payload", "payload_invalid")
        self.assertIsNone(subject._source_gates_step_diagnostic(object()))
        self.assertEqual(subject._source_gates_step_diagnostic(error), "source_gates_payload_invalid")

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

    def test_rust_commands_are_fixed_offline_and_cover_all_eight_gates(self):
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
        self.assertIn(str(source / "crates/host/mock/Cargo.toml"), commands[6][1])
        self.assertIn(str(source / "crates/host/conformance/Cargo.toml"), commands[7][1])

    def test_api_feature_gates_follow_api_tests_and_pass_the_dev_feature_exactly(self):
        import macos_feedback_producer as producer_module

        with tempfile.TemporaryDirectory() as temporary:
            test_root = Path(temporary)
            source = test_root / "source"
            tool_paths = {"cargo": test_root / "toolchain" / "bin" / "cargo"}
            commands = dict(subject._source_commands(source, tool_paths))
        cargo = str(tool_paths["cargo"])
        manifest = str(source / "crates/host/api/Cargo.toml")
        self.assertEqual(commands["api_feature_clippy"], (
            cargo, "clippy", "--offline", "--manifest-path", manifest, "--all-targets",
            "--features", "dev-uat-policy-import", "--locked", "--", "-D", "warnings",
        ))
        self.assertEqual(commands["api_feature_tests"], (
            cargo, "test", "--offline", "--manifest-path", manifest, "--all-targets",
            "--features", "dev-uat-policy-import", "--locked",
        ))
        self.assertEqual(subject.API_FEATURE_GATE_NAMES, ("api_feature_clippy", "api_feature_tests"))
        self.assertEqual(
            subject.GATE_NAMES[3:6], ("api_tests", "api_feature_clippy", "api_feature_tests"),
        )
        for stage in subject.API_FEATURE_GATE_NAMES:
            self.assertIn(stage, subject.SOURCE_GATE_STAGES)
            self.assertIn(stage, subject.STAGES)
            self.assertIn(stage, real_rust.SOURCE_COMMAND_STAGES)
        self.assertIn("api_feature_tests", subject.TEST_GATE_STAGES)
        self.assertNotIn("api_feature_clippy", subject.TEST_GATE_STAGES)
        self.assertEqual(subject._gate_command_seconds("api_feature_tests"), 300)
        self.assertEqual(subject._gate_command_seconds("api_feature_clippy"), 120)
        self.assertEqual(foundation_tests.subject.RUST_GATE_NAMES, subject.GATE_NAMES)
        self.assertEqual(producer_module.DIAGNOSTIC_BASE_GATES, subject.GATE_NAMES)

    def test_runtime_commands_are_fixed_locked_offline_and_cover_all_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            test_root = Path(temporary)
            source = test_root / "source"
            runtime_root = source / "runtime"
            runtime_root.mkdir(parents=True)
            (runtime_root / "Cargo.toml").write_text("[workspace]\n", encoding="ascii")
            (runtime_root / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            tools = {"cargo": test_root / "toolchain" / "bin" / "cargo"}
            legacy = subject._source_commands(source, tools)
            enrolled = subject._source_commands(source, tools, include_runtime=True)
        self.assertEqual(tuple(stage for stage, unused_argv in legacy), subject.GATE_NAMES)
        self.assertEqual(
            tuple(stage for stage, unused_argv in enrolled),
            subject.GATE_NAMES + subject.RUNTIME_GATE_NAMES,
        )
        cargo = str(tools["cargo"])
        manifest = str(source / "runtime/Cargo.toml")
        self.assertEqual(enrolled[-3:], (
            ("runtime_format", (cargo, "--locked", "--offline", "fmt", "--manifest-path",
                                 manifest, "--all", "--", "--check")),
            ("runtime_clippy", (cargo, "clippy", "--offline", "--manifest-path", manifest,
                                 "--workspace", "--all-targets", "--locked", "--", "-D", "warnings")),
            ("runtime_tests", (cargo, "test", "--offline", "--manifest-path", manifest,
                                "--workspace", "--all-targets", "--locked")),
        ))
        with self.assertRaises(subject.Refusal):
            subject._source_commands(source, tools, include_runtime=1)

    def test_runtime_root_selection_requires_both_validated_root_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            self.assertFalse(subject._validated_runtime_workspace_present(source))
            runtime_root = source / "runtime"
            runtime_root.mkdir(parents=True)
            (runtime_root / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            with self.assertRaises(subject.Refusal):
                subject._validated_runtime_workspace_present(source)
            (runtime_root / "Cargo.toml").write_text("[workspace]\n", encoding="ascii")
            self.assertTrue(subject._validated_runtime_workspace_present(source))

    def test_runtime_stages_run_in_order_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            runtime_root = source / "runtime"
            runtime_root.mkdir(parents=True)
            (runtime_root / "Cargo.toml").write_text("[workspace]\n", encoding="ascii")
            (runtime_root / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            tools = {"cargo": Path("/toolchain/bin/cargo")}
            calls = []
            fail_runtime_clippy = [False]

            def run_command(argv, *unused_args, **kwargs):
                stage = kwargs["stage"]
                calls.append(stage)
                if fail_runtime_clippy[0] and stage == "runtime_clippy":
                    error = RuntimeError("bounded helper failure")
                    error.reason = "version_mismatch"
                    error.command_check = "nonzero_exit"
                    raise error
                return SimpleNamespace(
                    returncode=0, stdout=b"bounded", stderr=b"",
                )

            rust = SimpleNamespace(_run_worker_command=run_command)
            with patch.object(subject, "_load_control_sibling", return_value=SimpleNamespace(
                    _worker_census=lambda *args: None)):
                gates = subject._run_gates(
                    source, {}, 502, {"python": "/usr/bin/python3"}, object(), rust, tools,
                    subject.time.monotonic() + 30, include_runtime=True,
                )
                self.assertEqual(tuple(gates), subject.GATE_NAMES + subject.RUNTIME_GATE_NAMES)
                self.assertEqual(calls, list(subject.GATE_NAMES + subject.RUNTIME_GATE_NAMES))
                calls.clear()
                fail_runtime_clippy[0] = True
                with self.assertRaises(subject.Refusal) as raised:
                    subject._run_gates(
                        source, {}, 502, {"python": "/usr/bin/python3"}, object(), rust, tools,
                        subject.time.monotonic() + 30, include_runtime=True,
                    )
            self.assertEqual(raised.exception.reason, "gate_failed")
            self.assertEqual(raised.exception.stage, "runtime_clippy")
            self.assertEqual(raised.exception.diagnostic, "source_gate_nonzero_exit")
            self.assertEqual(calls, list(subject.GATE_NAMES + ("runtime_format", "runtime_clippy")))

    def test_foundation_parser_commands_are_fixed_offline_and_not_in_the_default_gate_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            test_root = Path(temporary)
            source = test_root / "source"
            tools = {"cargo": test_root / "toolchain" / "bin" / "cargo"}
            legacy = subject._source_commands(source, tools)
            foundation = subject._source_commands(source, tools, include_parser=True)
        self.assertEqual(tuple(stage for stage, unused_argv in legacy), subject.GATE_NAMES)
        self.assertEqual(tuple(stage for stage, unused_argv in foundation),
                         subject.GATE_NAMES + subject.PARSER_GATE_NAMES)
        parser_format, parser_clippy, parser_replay = foundation[-3:]
        self.assertEqual(parser_format[1], (
            str(tools["cargo"]), "--locked", "--offline", "fmt", "--manifest-path",
            str(source / "fuzz/Cargo.toml"), "--all", "--", "--check",
        ))
        self.assertEqual(parser_clippy[1], (
            str(tools["cargo"]), "clippy", "--offline", "--manifest-path",
            str(source / "fuzz/Cargo.toml"), "--all-targets", "--locked", "--", "-D", "warnings",
        ))
        self.assertEqual(parser_replay[1], (
            str(tools["cargo"]), "run", "--locked", "--offline", "--manifest-path",
            str(source / "fuzz/Cargo.toml"),
        ))
        with self.assertRaises(subject.Refusal):
            subject._source_commands(source, tools, include_parser=1)

    def test_locked_foundation_lease_marker_is_limited_to_diagnostics(self):
        request = {**_request(), "concern": "core-build-diagnostic-return"}
        binding = _binding()
        record = {
            **binding, **request, "repository_id": "67890", "candidate_class": "signed-descendant",
            "signature": "verified", "rules_lock": "present", "tree": subject.LOCKED_FOUNDATION_TREE,
            "source_execution": "not_run_at_yield", "app_build": "not_run", "cleanup": "lease_open",
            "repository_scope": "verified", "metadata": "verified",
            "token_revocation": "confirmed_before_yield", "signer_authority": "bound_base",
            "signatures": "all_new_commits_verified", "ancestry": "base_ancestor",
            "revocation_policy": "current_control_fingerprints", "worker_access": "uid_read_only",
        }
        self.assertEqual(subject._validate_source_lease(
            record, request, binding, 504, private_validation,
        )["tree"], subject.LOCKED_FOUNDATION_TREE)
        for concern in ("core-contract", "core-node-lock-return", "core-rust-format-return"):
            with self.subTest(concern=concern), self.assertRaises(subject.Refusal):
                subject._validate_source_lease(
                    {**record, "concern": concern}, {**request, "concern": concern},
                    binding, 504, private_validation,
                )
        for tree in ("core_build_diagnostic_return_v3", "core_node_lock_return"):
            with self.subTest(tree=tree), self.assertRaises(subject.Refusal):
                subject._validate_source_lease({**record, "tree": tree}, request, binding, 504, private_validation)
        with self.assertRaises(subject.Refusal):
            subject._validate_source_lease(record, request, binding, 504, SimpleNamespace())
        legacy = {**record, "tree": "core_build_diagnostic_return"}
        self.assertEqual(subject._validate_source_lease(
            legacy, request, binding, 504, private_validation,
        )["tree"], "core_build_diagnostic_return")

    def test_fuzz_workspace_selection_requires_a_validated_feedback_lease(self):
        source = Path("/synthetic-source")
        marker = source / "fuzz/Cargo.toml"
        required = frozenset((
            "fuzz/Cargo.toml", "fuzz/Cargo.lock", "fuzz/src/main.rs",
            "fuzz/fuzz_targets/identifiers.rs", "fuzz/fuzz_targets/tool_error_codes.rs",
            "fuzz/fuzz_targets/versions.rs",
        ))
        runtime = SimpleNamespace(CORE_CONTRACT_FOUNDATION_FILES=required)
        marker_info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o400, st_uid=0, st_nlink=1,
        )
        original_lstat = Path.lstat

        def marker_lstat(path, *args, **kwargs):
            if path == marker:
                return marker_info
            return original_lstat(path, *args, **kwargs)

        with patch.object(Path, "lstat", marker_lstat):
            self.assertTrue(subject._validated_fuzz_workspace(
                source, {"concern": "core-rust-format-return"}, runtime,
            ))
            self.assertFalse(subject._validated_fuzz_workspace(
                source, {"concern": "core-contract"}, runtime,
            ))
        with patch.object(Path, "lstat", side_effect=FileNotFoundError):
            self.assertFalse(subject._validated_fuzz_workspace(
                source, {"concern": "core-rust-format-return"}, runtime,
            ))
            with self.assertRaises(subject.Refusal):
                subject._validated_fuzz_workspace(
                    source, {"concern": "core-node-lock-return"}, runtime,
                )
            with self.assertRaises(subject.Refusal):
                subject._validated_fuzz_workspace(
                    source, {"concern": "core-rust-format-return"}, SimpleNamespace(),
                )

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

    def test_feedback_gate_capture_returns_only_bounded_failure_and_never_pass_map(self):
        calls = []

        def run_command(*unused_args, **kwargs):
            self.assertIs(kwargs["allow_nonzero_capture"], True)
            return SimpleNamespace(
                returncode=9, stdout=b"bounded stdout", stderr=b"bounded stderr",
                stdout_truncated=True, stderr_truncated=False,
            )

        rust = SimpleNamespace(_run_worker_command=run_command)
        with patch.object(subject, "_source_commands", return_value=(
                ("workspace_tests", ("cargo", "test", "--locked")),)):
            with patch.object(subject, "_load_control_sibling", return_value=SimpleNamespace(
                    _worker_census=lambda *args: calls.append(args[-1]))):
                outcome = subject._run_gates(
                    Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                    rust, {"cargo": Path("/toolchain/bin/cargo")}, subject.time.monotonic() + 30,
                    capture_failure=True,
                )
        self.assertEqual(outcome["failed_stage"], "workspace_tests")
        self.assertEqual(outcome["returncode"], 9)
        self.assertEqual(outcome["stdout"], b"bounded stdout")
        self.assertEqual(outcome["stderr"], b"bounded stderr")
        self.assertIs(outcome["stdout_truncated"], True)
        self.assertIs(outcome["stderr_truncated"], False)
        self.assertEqual(outcome["selected_gates"], ("workspace_tests",))
        self.assertEqual(outcome["completed"], ())
        self.assertNotIn("gates", outcome)
        self.assertEqual(calls, ["workspace_tests"])

    def _gate_cleanup_error(self, **attributes):
        class CleanupFailure(Exception):
            reason = "cleanup_incomplete"

        error = CleanupFailure()
        for name, value in attributes.items():
            setattr(error, name, value)
        return error

    def test_source_gate_cleanup_refusal_keeps_a_listed_source_gates_diagnostic(self):
        cases = (
            ({"probe_check": "probe_process_timeout", "command_check": "timeout",
              "survivor_classes": ()}, "source_gates_timeout"),
            ({"probe_check": "probe_process_timeout", "command_check": "helper_failure",
              "survivor_classes": ()}, "source_gates_wait_uncertain"),
            ({"probe_check": "probe_process_timeout"}, "source_gates_cleanup_unclassified"),
            ({"probe_check": "probe_process_group_cleanup"}, "source_gates_group_cleanup"),
            ({"probe_check": "probe_process_capture_cleanup"}, "source_gates_capture_cleanup"),
            ({"probe_check": "probe_process_census"}, "source_gates_census"),
            ({"probe_check": "probe_process_survivor", "survivor_classes": ("python",)},
             "source_gates_survivor_python"),
            ({"probe_check": "probe_process_survivor", "survivor_classes": ("python", "ps")},
             "source_gates_survivor_multiple"),
            ({"probe_check": "probe_process_survivor", "survivor_classes": ()},
             "source_gates_cleanup_unclassified"),
            ({"probe_check": "probe_process_survivor", "survivor_classes": ("private",)},
             "source_gates_cleanup_unclassified"),
            ({"command_check": "timeout"}, "source_gates_timeout"),
            ({"command_check": "nonzero_exit"}, "source_gates_cleanup_unclassified"),
            ({}, "source_gates_cleanup_unclassified"),
        )
        for capture_failure in (False, True):
            for attributes, expected in cases:
                with self.subTest(capture_failure=capture_failure, attributes=attributes):
                    cause = self._gate_cleanup_error(**attributes)

                    def fail_command(*unused_args, **unused_kwargs):
                        raise cause

                    rust = SimpleNamespace(_run_worker_command=fail_command)
                    if (capture_failure and expected == "source_gates_timeout"
                            and attributes.get("survivor_classes") == ()):
                        continue
                    with self.assertRaises(subject.Refusal) as raised:
                        subject._run_gates(
                            Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                            rust, {"cargo": Path("/toolchain/bin/cargo")},
                            subject.time.monotonic() + 30, capture_failure=capture_failure,
                        )
                    self.assertEqual(raised.exception.reason, "cleanup_incomplete")
                    self.assertEqual(raised.exception.stage, "cleanup")
                    self.assertEqual(raised.exception.diagnostic, expected)
                    self.assertIn(expected, subject.SOURCE_GATES_CLEANUP_DIAGNOSTICS)
                    attached = subject._FailureDiagnostics().attach(raised.exception, "source_gates")
                    self.assertEqual(attached.diagnostic, expected)
                    reattached = subject._FailureDiagnostics().attach(attached, "source_gates")
                    record = json.loads(subject._format_refusal(reattached))
                    self.assertEqual(record["diagnostic"], expected)
                    self.assertEqual((record["reason"], record["stage"]), ("cleanup_incomplete", "cleanup"))
                    self.assertEqual(
                        set(record), {"diagnostic", "reason", "schema_version", "stage", "status"},
                    )

    def test_source_gate_census_failure_keeps_a_listed_source_gates_diagnostic(self):
        class CensusFailure(Exception):
            def __init__(self, survivor_classes):
                self.survivor_classes = survivor_classes

        cases = (
            (("helper_trust",), "source_gates_survivor_helper_trust"),
            (("python", "ps"), "source_gates_survivor_multiple"),
            ((), "source_gates_cleanup_unclassified"),
            ("unclassified", "source_gates_survivor_unknown"),
            ("unavailable", "source_gates_census"),
            (None, "source_gates_census"),
        )
        for capture_failure in (False, True):
            for classes, expected in cases:
                with self.subTest(capture_failure=capture_failure, classes=classes):
                    def census(*unused_args):
                        raise CensusFailure(classes)

                    rust = SimpleNamespace(_run_worker_command=lambda *args, **kwargs: SimpleNamespace(
                        returncode=0, stdout=b"", stderr=b"",
                    ))
                    commands = (("workspace_tests", ("cargo", "test", "--locked")),)
                    if not capture_failure:
                        commands = subject._source_commands(
                            Path("/source"), {"cargo": Path("/toolchain/bin/cargo")},
                        )
                    with patch.object(subject, "_source_commands", return_value=commands):
                        with patch.object(subject, "_load_control_sibling", return_value=SimpleNamespace(
                                _worker_census=census)):
                            with self.assertRaises(subject.Refusal) as raised:
                                subject._run_gates(
                                    Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                                    rust, {"cargo": Path("/toolchain/bin/cargo")},
                                    subject.time.monotonic() + 30, capture_failure=capture_failure,
                                )
                    self.assertEqual(
                        (raised.exception.reason, raised.exception.stage, raised.exception.diagnostic),
                        ("cleanup_incomplete", "cleanup", expected),
                    )

    def test_clean_gate_timeout_in_capture_mode_is_a_gate_failure_with_a_timeout_marker(self):
        census_calls = []
        timeouts = []
        cause = self._gate_cleanup_error(
            probe_check="probe_process_timeout", command_check="timeout", survivor_classes=(),
        )

        def run_command(*unused_args, **kwargs):
            timeouts.append((kwargs["stage"], kwargs["timeout"]))
            self.assertIs(kwargs["allow_nonzero_capture"], True)
            if kwargs["stage"] == "format":
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            raise cause

        rust = SimpleNamespace(_run_worker_command=run_command)
        commands = (
            ("format", ("cargo", "fmt")),
            ("workspace_tests", ("cargo", "test", "--locked")),
            ("api_tests", ("cargo", "test", "--locked")),
        )
        with patch.object(subject, "_source_commands", return_value=commands):
            with patch.object(subject, "_load_control_sibling", return_value=SimpleNamespace(
                    _worker_census=lambda *args: census_calls.append(args[-1]))):
                outcome = subject._run_gates(
                    Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                    rust, {"cargo": Path("/toolchain/bin/cargo")}, subject.time.monotonic() + 30,
                    capture_failure=True,
                )
        self.assertEqual(outcome["failed_stage"], "workspace_tests")
        self.assertEqual(outcome["completed"], ("format",))
        self.assertEqual(outcome["selected_gates"], ("format", "workspace_tests", "api_tests"))
        self.assertEqual(outcome["returncode"], subject.GATE_TIMEOUT_RETURNCODE)
        self.assertEqual(outcome["returncode"], 124)
        self.assertEqual(outcome["stdout"], b"")
        self.assertEqual(outcome["stderr"], b"kd-gate-timeout limit_seconds=300\n")
        self.assertIs(outcome["stdout_truncated"], False)
        self.assertIs(outcome["stderr_truncated"], False)
        self.assertEqual(timeouts, [("format", 120), ("workspace_tests", 300)])
        self.assertEqual(census_calls, ["format", "workspace_tests"])
        self.assertNotIn("api_tests", census_calls)
        self.assertNotIn("gates", outcome)

    def test_gate_timeout_outcome_still_requires_a_clean_census(self):
        class CensusFailure(Exception):
            survivor_classes = ("python",)

        def census(*unused_args):
            raise CensusFailure()

        cause = self._gate_cleanup_error(
            probe_check="probe_process_timeout", command_check="timeout", survivor_classes=(),
        )

        def fail_command(*unused_args, **unused_kwargs):
            raise cause

        with patch.object(subject, "_source_commands", return_value=(
                ("workspace_tests", ("cargo", "test", "--locked")),)):
            with patch.object(subject, "_load_control_sibling", return_value=SimpleNamespace(
                    _worker_census=census)):
                with self.assertRaises(subject.Refusal) as raised:
                    subject._run_gates(
                        Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                        SimpleNamespace(_run_worker_command=fail_command),
                        {"cargo": Path("/toolchain/bin/cargo")}, subject.time.monotonic() + 30,
                        capture_failure=True,
                    )
        self.assertEqual(
            (raised.exception.reason, raised.exception.stage, raised.exception.diagnostic),
            ("cleanup_incomplete", "cleanup", "source_gates_survivor_python"),
        )

    def test_timeout_with_any_unverified_cleanup_still_refuses_in_capture_mode(self):
        base = {"probe_check": "probe_process_timeout", "command_check": "timeout"}
        cases = (
            ({**base, "survivor_classes": ("python",)}, "source_gates_timeout"),
            ({**base}, "source_gates_timeout"),
            ({"probe_check": "probe_process_group_cleanup", "command_check": "timeout",
              "survivor_classes": ()}, "source_gates_group_cleanup"),
            ({"probe_check": "probe_process_capture_cleanup", "command_check": "timeout",
              "survivor_classes": ()}, "source_gates_capture_cleanup"),
            ({"probe_check": "probe_process_census", "command_check": "timeout",
              "survivor_classes": ()}, "source_gates_census"),
            ({"probe_check": "probe_process_survivor", "command_check": "timeout",
              "survivor_classes": ("python",)}, "source_gates_survivor_python"),
            ({"probe_check": "probe_process_timeout", "command_check": "helper_failure",
              "survivor_classes": ()}, "source_gates_wait_uncertain"),
        )
        for attributes, expected in cases:
            with self.subTest(attributes=attributes):
                cause = self._gate_cleanup_error(**attributes)

                def fail_command(*unused_args, **unused_kwargs):
                    raise cause

                with patch.object(subject, "_source_commands", return_value=(
                        ("workspace_tests", ("cargo", "test", "--locked")),)):
                    with self.assertRaises(subject.Refusal) as raised:
                        subject._run_gates(
                            Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                            SimpleNamespace(_run_worker_command=fail_command),
                            {"cargo": Path("/toolchain/bin/cargo")}, subject.time.monotonic() + 30,
                            capture_failure=True,
                        )
                self.assertEqual(
                    (raised.exception.reason, raised.exception.stage, raised.exception.diagnostic),
                    ("cleanup_incomplete", "cleanup", expected),
                )

    def test_clean_timeout_after_the_job_deadline_still_refuses(self):
        cause = self._gate_cleanup_error(
            probe_check="probe_process_timeout", command_check="timeout", survivor_classes=(),
        )

        clock = {"now": 0.0}

        def fail_command(*unused_args, **kwargs):
            self.assertEqual(kwargs["deadline"], 50.0)
            clock["now"] = 100.0
            raise cause

        with patch.object(subject, "_source_commands", return_value=(
                ("workspace_tests", ("cargo", "test", "--locked")),)):
            with patch.object(subject, "time", SimpleNamespace(monotonic=lambda: clock["now"])):
                with self.assertRaises(subject.Refusal) as raised:
                    subject._run_gates(
                        Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                        SimpleNamespace(_run_worker_command=fail_command),
                        {"cargo": Path("/toolchain/bin/cargo")}, 50.0, capture_failure=True,
                    )
        self.assertEqual(
            (raised.exception.reason, raised.exception.stage, raised.exception.diagnostic),
            ("cleanup_incomplete", "cleanup", "source_gates_timeout"),
        )

    def test_clean_timeout_before_the_job_deadline_is_a_gate_failure(self):
        cause = self._gate_cleanup_error(
            probe_check="probe_process_timeout", command_check="timeout", survivor_classes=(),
        )
        clock = {"now": 0.0}

        def fail_command(*unused_args, **kwargs):
            self.assertEqual(kwargs["deadline"], 50.0)
            clock["now"] = 49.0
            raise cause

        with patch.object(subject, "_source_commands", return_value=(
                ("workspace_tests", ("cargo", "test", "--locked")),)):
            with patch.object(subject, "time", SimpleNamespace(monotonic=lambda: clock["now"])):
                with patch.object(subject, "_load_control_sibling", return_value=SimpleNamespace(
                        _worker_census=lambda *args: None)):
                    outcome = subject._run_gates(
                        Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                        SimpleNamespace(_run_worker_command=fail_command),
                        {"cargo": Path("/toolchain/bin/cargo")}, 50.0, capture_failure=True,
                    )
        self.assertEqual(outcome["failed_stage"], "workspace_tests")
        self.assertEqual(outcome["returncode"], 124)

    def test_gate_timeout_attribute_contract_matches_the_real_rust_refusal(self):
        clean = real_rust.Refusal(
            "cleanup_incomplete", command_check="timeout", probe_check="probe_process_timeout",
        )
        self.assertIs(subject._clean_gate_timeout(clean), True)
        for probe_check in (
            "probe_process_group_cleanup", "probe_process_capture_cleanup",
            "probe_process_census", "probe_process_survivor",
        ):
            with self.subTest(probe_check=probe_check):
                unclean = real_rust.Refusal(
                    "cleanup_incomplete", command_check="timeout", probe_check=probe_check,
                )
                self.assertIs(subject._clean_gate_timeout(unclean), False)

    def test_gate_diagnostic_helpers_match_the_node_feedback_helpers(self):
        node = foundation_tests.subject
        cleanup_shapes = (
            {"probe_check": "probe_process_timeout", "command_check": "timeout"},
            {"probe_check": "probe_process_timeout", "command_check": "helper_failure"},
            {"probe_check": "probe_process_timeout"},
            {"probe_check": "probe_process_group_cleanup"},
            {"probe_check": "probe_process_capture_cleanup"},
            {"probe_check": "probe_process_census"},
            {"probe_check": "probe_process_survivor", "survivor_classes": ("python",)},
            {"probe_check": "probe_process_survivor", "survivor_classes": ("python", "ps")},
            {"probe_check": "probe_process_survivor", "survivor_classes": ()},
            {"probe_check": "probe_process_survivor", "survivor_classes": ("private",)},
            {"command_check": "timeout"},
            {"command_check": "nonzero_exit"},
            {},
        )
        for attributes in cleanup_shapes:
            with self.subTest(attributes=attributes):
                error = self._gate_cleanup_error(**attributes)
                self.assertEqual(
                    subject._gate_cleanup_diagnostic(error), node._command_cleanup_diagnostic(error),
                )
        for classes in (("helper_trust",), ("python", "ps"), (), "unclassified", "unavailable", None):
            with self.subTest(classes=classes):
                error = SimpleNamespace(survivor_classes=classes)
                self.assertEqual(
                    subject._gate_census_diagnostic(error), node._census_diagnostic(error),
                )

    def test_test_gates_use_the_larger_command_limit_inside_the_job_deadline(self):
        self.assertEqual(subject.MAX_COMMAND_SECONDS, 120)
        self.assertEqual(subject.MAX_TEST_COMMAND_SECONDS, 300)
        self.assertEqual(
            subject.TEST_GATE_STAGES,
            frozenset(("workspace_tests", "api_tests", "api_feature_tests", "mock_tests",
                       "conformance_tests", "parser_replay", "runtime_tests")),
        )
        self.assertLessEqual(subject.TEST_GATE_STAGES, frozenset(subject.SOURCE_GATE_STAGES))
        self.assertLess(subject.MAX_TEST_COMMAND_SECONDS, subject.MAX_TOTAL_SECONDS)
        timeouts = {}

        def run_command(*unused_args, **kwargs):
            timeouts[kwargs["stage"]] = kwargs["timeout"]
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        commands = tuple((stage, ("cargo", stage)) for stage in subject.SOURCE_GATE_STAGES)
        with patch.object(subject, "_source_commands", return_value=commands):
            with patch.object(subject, "_load_control_sibling", return_value=SimpleNamespace(
                    _worker_census=lambda *args: None)):
                subject._run_gates(
                    Path("/source"), {}, 502, {"python": "/usr/bin/python3"}, object(),
                    SimpleNamespace(_run_worker_command=run_command),
                    {"cargo": Path("/toolchain/bin/cargo")}, subject.time.monotonic() + 30,
                    capture_failure=True, include_parser=True,
                )
        self.assertEqual(set(timeouts), set(subject.SOURCE_GATE_STAGES))
        for stage, seconds in timeouts.items():
            self.assertEqual(
                seconds, 300 if stage in subject.TEST_GATE_STAGES else 120, msg=stage,
            )
        for stage in ("format", "clippy", "parser_format", "parser_clippy", "runtime_format",
                      "runtime_clippy"):
            self.assertEqual(timeouts[stage], 120)

    def test_foundation_parser_failure_reports_selected_and_completed_stages(self):
        source = Path("/synthetic-source")
        tools = {"cargo": Path("/toolchain/bin/cargo")}
        commands = subject._source_commands(source, tools, include_parser=True)
        calls = []

        def run_command(argv, *unused_args, **kwargs):
            stage = kwargs["stage"]
            calls.append(stage)
            return SimpleNamespace(
                returncode=7 if stage == "parser_clippy" else 0,
                stdout=b"bounded", stderr=b"",
            )

        rust = SimpleNamespace(_run_worker_command=run_command)
        with patch.object(subject, "_source_commands", return_value=commands):
            with patch.object(subject, "_load_control_sibling", return_value=SimpleNamespace(
                    _worker_census=lambda *args: None)):
                outcome = subject._run_gates(
                    source, {}, 502, {"python": "/usr/bin/python3"}, object(), rust, tools,
                    subject.time.monotonic() + 30, capture_failure=True, include_parser=True,
                )
        self.assertEqual(outcome["selected_gates"], subject.GATE_NAMES + subject.PARSER_GATE_NAMES)
        self.assertEqual(outcome["completed"], subject.GATE_NAMES + ("parser_format",))
        self.assertEqual(outcome["failed_stage"], "parser_clippy")
        self.assertEqual(calls, list(subject.GATE_NAMES + ("parser_format", "parser_clippy")))
        self.assertNotIn("gates", outcome)
        with self.assertRaises(subject.Refusal):
            subject._run_gates(
                source, {}, 502, {"python": "/usr/bin/python3"}, object(), rust, tools,
                subject.time.monotonic() + 30, include_parser=True,
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

    def test_success_receipt_uses_dynamic_gate_counts_and_four_existing_suites(self):
        record, versions, gates = _success_record()
        validated = subject._validate_success_record(
            record, _binding(), _request(), _lease_record(), DIFF_SHA256,
            versions, gates, True, True,
        )
        self.assertEqual(validated["suites"], [
            "core.static", "core.host-api", "core.mock-host", "core.conformance",
        ])
        self.assertEqual(validated["gate_count"], 8)
        self.assertEqual(validated["selected_gates"], list(subject.GATE_NAMES))
        self.assertEqual(validated["completed_gates"], list(subject.GATE_NAMES))
        self.assertEqual(validated["suite_count"], 4)
        for field in ("gate_count", "gates_passed", "gates_failed", "suite_count", "suites_passed", "suites_failed"):
            invalid = copy.deepcopy(record)
            invalid[field] = bool(invalid[field])
            with self.subTest(field=field), self.assertRaises(subject.Refusal):
                subject._validate_success_record(
                    invalid, _binding(), _request(), _lease_record(), DIFF_SHA256,
                    versions, gates, True, True,
                )
        runtime_record, runtime_versions, runtime_gates = _success_record(include_runtime=True)
        runtime_validated = subject._validate_success_record(
            runtime_record, _binding(), _request(), _lease_record(), DIFF_SHA256,
            runtime_versions, runtime_gates, True, True,
        )
        self.assertEqual(runtime_validated["gate_count"], 11)
        self.assertEqual(runtime_validated["selected_gates"],
                         list(subject.GATE_NAMES + subject.RUNTIME_GATE_NAMES))
        self.assertEqual(runtime_validated["completed_gates"], runtime_validated["selected_gates"])
        missing_runtime = copy.deepcopy(runtime_record)
        missing_runtime["completed_gates"] = list(subject.GATE_NAMES + subject.RUNTIME_GATE_NAMES[:-1])
        with self.assertRaises(subject.Refusal):
            subject._validate_success_record(
                missing_runtime, _binding(), _request(), _lease_record(), DIFF_SHA256,
                runtime_versions, runtime_gates, True, True,
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


class _FakeSelector:
    def __init__(self):
        self.registered = {}

    def register(self, fileobj, events, data=None):
        self.registered[fileobj] = SimpleNamespace(fileobj=fileobj, events=events, data=data)

    def unregister(self, fileobj):
        del self.registered[fileobj]

    def get_map(self):
        return self.registered

    def select(self, timeout=None):
        return [(key, key.events) for key in list(self.registered.values())]

    def close(self):
        self.registered = {}


class _FakeStream:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.closed = False

    def fileno(self):
        return self.descriptor

    def close(self):
        self.closed = True


class DiffCapTests(unittest.TestCase):
    CAP = 4096

    def _stream(self, total):
        remaining = {101: total, 102: 0}

        def fake_read(descriptor, size):
            count = min(size, 1000, remaining[descriptor])
            remaining[descriptor] -= count
            return b"x" * count

        process = SimpleNamespace(
            stdout=_FakeStream(101), stderr=_FakeStream(102),
            pid=1, returncode=0, poll=lambda: 0, wait=lambda timeout=None: 0,
        )
        with patch.object(subject, "MAX_DIFF_BYTES", self.CAP), \
                patch.object(subject.selectors, "DefaultSelector", _FakeSelector), \
                patch.object(subject.os, "read", side_effect=fake_read), \
                patch.object(subject.subprocess, "Popen", return_value=process):
            return subject._stream_git_diff_hash(
                Path("/synthetic-source"), BASE_SHA, SOURCE_SHA,
                hashlib.sha256(b"x" * total).hexdigest(), "/usr/bin/git",
                time.monotonic() + 120,
            )

    def test_diff_cap_constant_admits_the_four_crate_contract_size(self):
        self.assertEqual(subject.MAX_DIFF_BYTES, 7 * 1024 * 1024)
        self.assertGreater(subject.MAX_DIFF_BYTES, 3_723_563)
        self.assertGreater(subject.MAX_DIFF_BYTES, 6_315_077)
        self.assertLess(subject.MAX_DIFF_BYTES, 8 * 1024 * 1024)

    def test_diff_cap_is_enforced_exactly_at_the_boundary(self):
        self.assertEqual(
            self._stream(self.CAP), hashlib.sha256(b"x" * self.CAP).hexdigest(),
        )
        with self.assertRaises(subject.Refusal) as refusal:
            self._stream(self.CAP + 1)
        self.assertEqual(refusal.exception.reason, "source_diff_mismatch")


if __name__ == "__main__":
    unittest.main()
