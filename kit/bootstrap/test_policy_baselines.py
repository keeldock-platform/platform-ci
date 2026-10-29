import hashlib
import unittest
from pathlib import Path

import policy
import policy_baselines
from policy import PolicyError, validate_workflow_text
from public_tree import PINNED_FILE_SHA256, PLATFORM_FILES, scan_tree


__all__ = [
    "BaselinesWorkflowPolicyTests",
    "BaselinesLaneRegistryTests",
    "BaselinesLanePublicTreeTests",
]

ROOT = Path(__file__).resolve().parents[2]
BASELINES_WORKFLOW = ROOT / ".github/workflows/baselines-prepare.yml"
BASELINES_KIND = "baselines-prepare"
BASELINES_LANE_FILES = (
    ".github/workflows/baselines-prepare.yml",
    "kit/bootstrap/policy_baselines.py",
    "kit/bootstrap/test_policy_baselines.py",
    "kit/baselines/baselines_prepare.py",
    "kit/baselines/test_baselines_prepare.py",
)


class BaselinesWorkflowPolicyTests(unittest.TestCase):
    def test_actual_workflow_is_byte_identical_to_the_reviewed_template(self):
        workflow = BASELINES_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", BASELINES_KIND))
        self.assertEqual(
            BASELINES_WORKFLOW.read_bytes(),
            policy_baselines.BASELINES_PREPARE_WORKFLOW_TEMPLATE.encode("utf-8"),
        )
        self.assertEqual(
            PINNED_FILE_SHA256[".github/workflows/baselines-prepare.yml"],
            hashlib.sha256(workflow.encode("utf-8")).hexdigest(),
        )

    def test_workflow_is_manual_main_only_and_source_free(self):
        workflow = BASELINES_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(workflow.startswith("name: baselines-prepare\non:\n  workflow_dispatch:\n"))
        self.assertIn(
            "if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}",
            workflow,
        )
        self.assertIn("permissions: {}\n", workflow)
        self.assertEqual(workflow.count("cache-mode: none\n"), 2)
        self.assertIn("fail-fast: false", workflow)
        for forbidden in (
            "inputs:",
            "secrets.",
            "uses:",
            "upload-artifact",
            "download-artifact",
            "attest",
            "cache:",
            "outputs:",
            "contents: read",
            "persist-credentials",
            "workflow_call",
            "pull_request",
            "push:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        self.assertIn("kit/baselines/test_baselines_prepare.py", workflow)
        self.assertIn("kit/baselines/baselines_prepare.py", workflow)
        self.assertIn("git fetch --quiet --no-tags --depth=1 origin \"$CI_REF\"", workflow)

    def test_workflow_rejects_trigger_runner_permission_and_execution_changes(self):
        base = BASELINES_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  workflow_dispatch:\n", "  push:\n"),
            base.replace("github.event_name == 'workflow_dispatch'", "github.event_name == 'push'"),
            base.replace("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/feature'"),
            base.replace("runner: macos-15\n", "runner: macos-latest\n"),
            base.replace("runner: windows-2025\n", "runner: windows-latest\n"),
            base.replace("\npermissions: {}\n", "\npermissions:\n  contents: read\n", 1),
            base.replace("    permissions: {}\n", "    permissions:\n      contents: read\n", 1),
            base.replace("cache-mode: none\n", "", 1),
            base.replace("    fail-fast: false\n", "    fail-fast: true\n"),
            base.replace("      - name: Validate source-free control tree\n", ""),
            base.replace(
                "      - name: Run source-free baselines preparation\n",
                "      - name: Run source-free baselines preparation\n        continue-on-error: true\n",
            ),
            base.replace("git fetch --quiet --no-tags --depth=1 origin", "git fetch --quiet origin main"),
            base.replace('if [[ "$actual_sha" != "$CI_SHA" ]]; then', "if false; then"),
            base.replace("      CI_REPOSITORY: ${{ github.repository }}\n", "      CI_REPOSITORY: ${{ github.repository }}\n      EXTRA: ${{ secrets.EXTRA }}\n"),
            base + "  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                self.assertNotEqual(changed, base)
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(changed, "platform", BASELINES_KIND)


class BaselinesLaneRegistryTests(unittest.TestCase):
    def test_lane_declares_one_template_kind_and_no_digest_pins(self):
        self.assertIn(policy_baselines, policy.LANE_MODULES)
        self.assertEqual(
            dict(policy_baselines.WORKFLOW_TEMPLATES),
            {BASELINES_KIND: policy_baselines.BASELINES_PREPARE_WORKFLOW_TEMPLATE},
        )
        self.assertEqual(dict(policy_baselines.WORKFLOW_SHA256), {})
        self.assertEqual(
            policy_baselines.CANDIDATE_WORKFLOWS,
            (
                (
                    ".github/workflows/baselines-prepare.yml",
                    BASELINES_KIND,
                    "baselines-workflow-too-large",
                ),
            ),
        )

    def test_registry_routes_the_kind_to_the_lane(self):
        self.assertIs(policy.WORKFLOW_KIND_LANES[BASELINES_KIND], policy_baselines)
        self.assertEqual(
            policy.LANE_WORKFLOW_TEMPLATES[BASELINES_KIND],
            policy_baselines.BASELINES_PREPARE_WORKFLOW_TEMPLATE,
        )
        self.assertNotIn(BASELINES_KIND, policy.LANE_WORKFLOW_SHA256)
        self.assertNotIn(BASELINES_KIND, policy.SHARED_WORKFLOW_KINDS)
        for entry in policy_baselines.CANDIDATE_WORKFLOWS:
            self.assertIn(entry, policy.LANE_CANDIDATE_WORKFLOWS)

    def test_lane_module_exposes_the_lane_interface_and_the_template(self):
        public = sorted(name for name in vars(policy_baselines) if not name.startswith("_"))
        self.assertEqual(
            public,
            [
                "BASELINES_PREPARE_WORKFLOW_TEMPLATE",
                "CANDIDATE_WORKFLOWS",
                "WORKFLOW_SHA256",
                "WORKFLOW_TEMPLATES",
            ],
        )

    def test_dispatch_accepts_and_refuses_exactly_the_template(self):
        template = policy_baselines.BASELINES_PREPARE_WORKFLOW_TEMPLATE
        self.assertTrue(validate_workflow_text(template, "platform", BASELINES_KIND))
        for pool in ("connect", "workspace", "data"):
            with self.subTest(pool=pool):
                with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                    validate_workflow_text(template, pool, BASELINES_KIND)
        for changed in (template + "\n", template[:-1], template.replace("\n", "\r\n")):
            with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                validate_workflow_text(changed, "platform", BASELINES_KIND)
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(template, "platform")
        with self.assertRaisesRegex(PolicyError, "workflow-input"):
            validate_workflow_text(template.encode("utf-8"), "platform", BASELINES_KIND)

    def test_other_lane_workflows_are_refused_under_the_baselines_kind(self):
        for relative in (
            ".github/workflows/public-policy.yml",
            ".github/workflows/linux-confinement.yml",
            ".github/workflows/windows-native-preflight.yml",
            ".github/workflows/windows-handoff-synthetic.yml",
        ):
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(text, "platform", BASELINES_KIND)

    def test_template_is_refused_under_other_kinds(self):
        template = policy_baselines.BASELINES_PREPARE_WORKFLOW_TEMPLATE
        for kind in ("windows-native-preflight", "windows-handoff-synthetic", "macos-capability"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(template, "platform", kind)


class BaselinesLanePublicTreeTests(unittest.TestCase):
    def test_lane_files_are_in_the_platform_allowlist_pinned_and_scan_clean(self):
        result = scan_tree(ROOT, "platform")
        for name in BASELINES_LANE_FILES:
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, result)
        for name in (
            ".github/workflows/baselines-prepare.yml",
            "kit/baselines/baselines_prepare.py",
            "kit/baselines/test_baselines_prepare.py",
            "kit/bootstrap/policy_baselines.py",
            "kit/bootstrap/test_policy_baselines.py",
        ):
            with self.subTest(pinned=name):
                self.assertIn(name, PINNED_FILE_SHA256)
                self.assertEqual(
                    PINNED_FILE_SHA256[name],
                    hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                )

    def test_baselines_tests_are_discovered_by_the_source_free_action(self):
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertEqual(action.count('"test_baselines_prepare.py"'), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
