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
    "macos_core_bootstrap",
)
NOT_ROOT = hasattr(os, "geteuid") and os.geteuid() != 0


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

    def test_interpreter_is_recorded_for_the_hosted_run(self):
        self.assertGreaterEqual(sys.version_info[:2], (3, 9))


if __name__ == "__main__":
    unittest.main(verbosity=2)
