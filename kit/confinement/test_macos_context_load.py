import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


CONTROL_DIRECTORY = Path(__file__).resolve().parent
CONTROL_SHA = "a" * 40
PRODUCER_MODULES = (
    "macos_capability",
    "macos_reviewed_build",
    "macos_boundary_guard",
    "macos_private_validation",
    "macos_source_reader",
    "macos_network_observer",
    "macos_rust_toolchain",
    "macos_rules_bootstrap",
    "macos_feedback_producer",
    "macos_node_contract",
    "foundation_node_feedback",
    "cargo_lock_bootstrap",
    "npm_admission_bootstrap",
    "macos_core_bootstrap",
)
NOT_ROOT = hasattr(os, "geteuid") and os.geteuid() != 0


def load_module(name):
    path = CONTROL_DIRECTORY / (name + ".py")
    spec = importlib.util.spec_from_file_location(name + "_under_test", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_core():
    path = CONTROL_DIRECTORY / "macos_core_contract.py"
    spec = importlib.util.spec_from_file_location("macos_core_contract_under_test", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def context_environment(runner_temp):
    return {
        "CI_SHA": CONTROL_SHA,
        "CI_EVENT_NAME": "workflow_dispatch",
        "CI_REF": "refs/heads/main",
        "CI_REPOSITORY": "keeldock-platform/platform-ci",
        "CI_SERVER_URL": "https://github.com",
        "CI_WORKSPACE": str(CONTROL_DIRECTORY),
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_TEMP": str(runner_temp),
    }


class ProducerModuleLoadTests(unittest.TestCase):
    def test_every_module_the_producer_loads_executes_on_this_interpreter(self):
        core = load_core()
        self.assertEqual(
            set(PRODUCER_MODULES) - set(core.ALLOWED_CONTROL_SIBLINGS),
            {"macos_core_bootstrap"},
        )
        for name in PRODUCER_MODULES:
            if name == "macos_core_bootstrap":
                path = CONTROL_DIRECTORY / (name + ".py")
                spec = importlib.util.spec_from_file_location(name + "_under_test", str(path))
                module = importlib.util.module_from_spec(spec)
                with self.subTest(module=name):
                    spec.loader.exec_module(module)
                continue
            with self.subTest(module=name):
                self.assertIsNotNone(core._load_control_sibling(name))

    def test_load_controls_returns_every_control_and_a_reviewed_capability(self):
        core = load_core()
        controls = core._load_controls()
        self.assertEqual(len(controls), 6)
        self.assertTrue(all(control is not None for control in controls))
        self.assertIsNotNone(getattr(controls[0], "capability", None))


class ProducerContextTests(unittest.TestCase):
    def setUp(self):
        self.core = load_core()
        self.controls = self.core._load_controls()
        self.reviewed, self.capability, self.boundary, unused_runtime, self.rust, self.rules = self.controls
        self.runner_temp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, str(self.runner_temp), True)
        self.environment = context_environment(self.runner_temp)
        self.binding = {"control_sha": CONTROL_SHA, "run_id": "123456789", "run_attempt": "1"}
        self.identity = self.boundary.PlatformIdentity(
            product_version=self.boundary.APPROVED_HOST_RELEASES[0][0],
            image_os=self.boundary.APPROVED_IMAGE_OS,
            runner_image_os=self.boundary.APPROVED_RUNNER_IMAGE_OS,
            image_version=self.boundary.APPROVED_HOST_RELEASES[0][1],
            architecture="arm64",
        )

    def patched(self, identity=None, platform_error=None):
        platform_patch = (
            mock.patch.object(self.boundary, "check_platform", side_effect=platform_error)
            if platform_error is not None
            else mock.patch.object(
                self.boundary, "check_platform",
                return_value=self.identity if identity is None else identity)
        )
        return (
            mock.patch.object(self.reviewed, "_binding", return_value=dict(self.binding)),
            mock.patch.object(self.capability, "_check_context", return_value=CONTROL_DIRECTORY),
            platform_patch,
        )

    @unittest.skipUnless(NOT_ROOT, "the runner temporary directory must not be owned by root")
    def test_strict_context_accepts_a_real_unprivileged_runner_temp(self):
        run_id, run_attempt, path = self.rust._strict_context(self.environment, CONTROL_SHA)
        self.assertEqual((run_id, run_attempt, path), ("123456789", "1", self.runner_temp))

    @unittest.skipUnless(NOT_ROOT, "the runner temporary directory must not be owned by root")
    def test_strict_context_refuses_bad_run_values_and_a_missing_temp(self):
        for key, value in (
            ("GITHUB_RUN_ID", "0123"),
            ("GITHUB_RUN_ID", ""),
            ("GITHUB_RUN_ATTEMPT", "x"),
            ("RUNNER_TEMP", ""),
            ("RUNNER_TEMP", str(self.runner_temp / "missing")),
        ):
            with self.subTest(key=key, value=value):
                environment = dict(self.environment, **{key: value})
                with self.assertRaises(self.rust.Refusal):
                    self.rust._strict_context(environment, CONTROL_SHA)

    def test_public_context_binds_the_control_commit_and_an_arm64_host(self):
        binding_patch, capability_patch, platform_patch = self.patched()
        with binding_patch, capability_patch, platform_patch:
            binding, root = self.rules._public_context(
                self.environment, self.reviewed, self.capability, self.boundary)
        self.assertEqual(binding["control_sha"], CONTROL_SHA)
        self.assertEqual(root, CONTROL_DIRECTORY)

    def test_public_context_refuses_an_unapproved_platform_as_context_unavailable(self):
        error = self.boundary.GuardError("platform_unapproved")
        binding_patch, capability_patch, platform_patch = self.patched(platform_error=error)
        with binding_patch, capability_patch, platform_patch:
            with self.assertRaises(self.rules.Refusal) as raised:
                self.rules._public_context(
                    self.environment, self.reviewed, self.capability, self.boundary)
        self.assertEqual(raised.exception.reason, "context_unavailable")
        self.assertEqual(raised.exception.context_diagnostic, "context_guard_platform_unapproved")
        self.assertIsNone(raised.exception.diagnostic)

    def test_public_context_keeps_unknown_failures_opaque(self):
        binding_patch, capability_patch, platform_patch = self.patched(
            platform_error=RuntimeError("raw host text must not travel"))
        with binding_patch, capability_patch, platform_patch:
            with self.assertRaises(self.rules.Refusal) as raised:
                self.rules._public_context(
                    self.environment, self.reviewed, self.capability, self.boundary)
        self.assertEqual(raised.exception.reason, "context_unavailable")
        self.assertIsNone(raised.exception.context_diagnostic)

    def test_guard_reasons_outside_the_allowlist_carry_no_token(self):
        error = self.boundary.GuardError("platform_unapproved")
        error.reason = "free text with a path"
        self.assertIsNone(self.rules._guard_context_diagnostic(error, self.boundary))
        self.assertIsNone(self.rules._guard_context_diagnostic(ValueError("x"), self.boundary))
        for reason in self.boundary.GuardError._REASONS:
            with self.subTest(reason=reason):
                self.assertEqual(
                    self.rules._guard_context_diagnostic(
                        self.boundary.GuardError(reason), self.boundary),
                    "context_guard_" + reason,
                )

    @unittest.skipUnless(NOT_ROOT, "the runner temporary directory must not be owned by root")
    def test_validate_context_returns_binding_root_and_runner_temp(self):
        binding_patch, capability_patch, platform_patch = self.patched()
        with binding_patch, capability_patch, platform_patch:
            binding, root, runner_temp = self.core._validate_context(
                self.environment, self.reviewed, self.capability, self.boundary, self.rust)
        self.assertEqual(binding["run_id"], "123456789")
        self.assertEqual(root, CONTROL_DIRECTORY)
        self.assertEqual(runner_temp, self.runner_temp)

    @unittest.skipUnless(NOT_ROOT, "the runner temporary directory must not be owned by root")
    def test_validate_context_reports_a_non_core_refusal_as_runner_unavailable(self):
        error = self.boundary.GuardError("platform_unapproved")
        binding_patch, capability_patch, platform_patch = self.patched(platform_error=error)
        with binding_patch, capability_patch, platform_patch:
            with self.assertRaises(self.core.Refusal) as raised:
                self.core._validate_context(
                    self.environment, self.reviewed, self.capability, self.boundary, self.rust)
        self.assertEqual(
            (raised.exception.reason, raised.exception.stage),
            ("runner_unavailable", "context"),
        )
        self.assertEqual(raised.exception.diagnostic, "context_guard_platform_unapproved")

    @unittest.skipUnless(NOT_ROOT, "the runner temporary directory must not be owned by root")
    def test_validate_context_maps_unknown_exception_types_to_the_opaque_diagnostic(self):
        binding_patch, capability_patch, platform_patch = self.patched()
        with binding_patch, capability_patch, platform_patch, \
                mock.patch.object(self.rust, "_strict_context", side_effect=ValueError("raw text")):
            with self.assertRaises(self.core.Refusal) as raised:
                self.core._validate_context(
                    self.environment, self.reviewed, self.capability, self.boundary, self.rust)
        self.assertEqual(
            (raised.exception.reason, raised.exception.stage, raised.exception.diagnostic),
            ("runner_unavailable", "context", "none"),
        )

    @unittest.skipUnless(NOT_ROOT, "the runner temporary directory must not be owned by root")
    def test_validate_context_tags_known_foreign_refusals_by_module_and_reason(self):
        binding_patch, capability_patch, platform_patch = self.patched()
        for reason, token in (
            ("invalid_input", "context_rust_invalid_input"),
            ("runner_unavailable", "context_rust_runner_unavailable"),
        ):
            with self.subTest(reason=reason):
                with binding_patch, capability_patch, platform_patch, \
                        mock.patch.object(self.rust, "_strict_context", side_effect=self.rust.Refusal(reason)):
                    with self.assertRaises(self.core.Refusal) as raised:
                        self.core._validate_context(
                            self.environment, self.reviewed, self.capability, self.boundary, self.rust)
                self.assertEqual(raised.exception.diagnostic, token)
                binding_patch, capability_patch, platform_patch = self.patched()

    def test_foreign_context_diagnostics_survive_attach_formatting_and_normalisation(self):
        failure = self.core.Refusal(
            "runner_unavailable", "context", diagnostic="context_guard_platform_unapproved")
        attached = self.core._FailureDiagnostics().attach(failure, failure.diagnostic)
        self.assertEqual(attached.diagnostic, "context_guard_platform_unapproved")
        payload = self.core._format_refusal(attached)
        self.assertIn(b'"diagnostic":"context_guard_platform_unapproved"', payload)
        failure_module = load_module("feedback_failure")
        raw = b"KD-FEEDBACK-PRODUCER-REFUSAL " + payload + b"\n"
        self.assertEqual(failure_module.normalize_refusal(raw), raw)
        other_stage = self.core.Refusal(
            "runner_unavailable", "host", diagnostic="context_guard_platform_unapproved")
        reattached = self.core._FailureDiagnostics().attach(other_stage, other_stage.diagnostic)
        self.assertNotEqual(reattached.diagnostic, "context_guard_platform_unapproved")

    def test_foreign_context_tokens_match_the_public_audit_allowlist(self):
        audit = load_module("macos_public_audit")
        self.assertEqual(
            self.core.FOREIGN_CONTEXT_DIAGNOSTICS, audit.CORE_CONTRACT_FOREIGN_CONTEXT_DIAGNOSTICS)
        self.assertLessEqual(
            audit.CORE_CONTRACT_FOREIGN_CONTEXT_DIAGNOSTICS, audit.CORE_CONTRACT_REFUSAL_DIAGNOSTICS)
        self.assertLessEqual(self.core.FOREIGN_CONTEXT_DIAGNOSTICS, self.core.DIAGNOSTICS)
        self.assertEqual(len(self.core.FOREIGN_CONTEXT_DIAGNOSTICS), 9)
        for token in self.core.FOREIGN_CONTEXT_DIAGNOSTICS:
            self.assertRegex(token, r"\Acontext_(guard|rust|rules)_[a-z_]+\Z")

    def test_interpreter_is_recorded_for_the_hosted_run(self):
        self.assertGreaterEqual(sys.version_info[:2], (3, 9))


class ApprovedHostReleaseTableTests(unittest.TestCase):
    def test_the_three_approved_host_release_tables_are_identical_and_bounded(self):
        boundary = load_module("macos_boundary_guard")
        deny = load_module("macos_deny_default")
        audit = load_module("macos_public_audit")
        expected = (("15.7.9", "20260907.0337.1"), ("15.8.2", "20261028.0489.1"))
        self.assertEqual(boundary.APPROVED_HOST_RELEASES, expected)
        self.assertEqual(deny.APPROVED_HOST_RELEASES, expected)
        self.assertEqual(audit.APPROVED_HOST_RELEASES, expected)
        self.assertLessEqual(len(expected), 2)
        observed = {("15.8.2", "20261028.0489.1"): "40941660825"}
        self.assertEqual(boundary.APPROVED_HOST_RELEASE_FIRST_RUNS, observed)
        self.assertEqual(deny.APPROVED_HOST_RELEASE_FIRST_RUNS, observed)
        self.assertEqual(audit.APPROVED_HOST_RELEASE_FIRST_RUNS, observed)
        self.assertEqual(boundary.APPROVED_IMAGE_OS, deny.APPROVED_IMAGE_OS_VALUE)
        self.assertEqual(boundary.APPROVED_RUNNER_IMAGE_OS, deny.APPROVED_RUNNER_IMAGE_OS)
        self.assertEqual(boundary.APPROVED_ARCHITECTURE, deny.APPROVED_ARCH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
