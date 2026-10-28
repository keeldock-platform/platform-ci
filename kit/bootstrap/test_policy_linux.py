import hashlib
import unittest
from pathlib import Path

import policy
import policy_linux
from policy import PolicyError, validate_workflow_text
from public_tree import PLATFORM_FILES, scan_tree


__all__ = ["LinuxWorkflowPolicyTests", "LinuxLaneRegistryTests", "LinuxLanePublicTreeTests"]

ROOT = Path(__file__).resolve().parents[2]
LINUX_WORKFLOW = ROOT / ".github/workflows/linux-confinement.yml"
LINUX_WORKFLOW_SHA256_BEFORE_SPLIT = "f7860a422e818f238232c395a100422ab32e5a6498737a8840d52a362b96b6ae"
LINUX_LANE_FILES = (
    ".github/workflows/linux-confinement.yml",
    "kit/bootstrap/policy_linux.py",
    "kit/bootstrap/test_policy_linux.py",
    "kit/confinement/linux_harness.py",
    "kit/confinement/test_linux_harness.py",
)


class LinuxWorkflowPolicyTests(unittest.TestCase):
    def test_actual_linux_workflow_matches_closed_supported_shape(self):
        workflow = LINUX_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", "linux-confinement"))
        static_lane, privileged_lane = workflow.split("  linux-confinement:\n", 1)
        self.assertNotIn("sudo ", static_lane)
        self.assertIn("needs: linux-policy", privileged_lane)
        self.assertIn("github.event_name == 'workflow_dispatch'", privileged_lane)
        self.assertIn("github.ref == 'refs/heads/main'", privileged_lane)
        self.assertNotIn("inputs:", workflow)
        self.assertIn('"$CI_REF" != "refs/heads/main"', privileged_lane)
        self.assertIn('"$CI_REPOSITORY" != "keeldock-platform/platform-ci"', privileged_lane)
        self.assertIn("CI_SHA: ${{ github.sha }}", privileged_lane)
        self.assertIn('if [[ "$actual_sha" != "$CI_SHA" ]]', privileged_lane)
        self.assertIn('git fetch --quiet --no-tags --depth=1 origin "$CI_REF"', privileged_lane)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "linux-confinement")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_linux_workflow_rejects_skips_masking_extra_execution_and_weak_permissions(self):
        base = LINUX_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("      - name: Run Linux synthetic confinement proof\n", "      - name: Extra execution\n        run: echo extra\n      - name: Run Linux synthetic confinement proof\n"),
            base.replace("      - name: Run Linux synthetic confinement proof\n        run: |", "      - name: Run Linux synthetic confinement proof\n        if: ${{ false }}\n        run: |"),
            base.replace("      - name: Run Linux synthetic confinement proof\n", "      - name: Run Linux synthetic confinement proof\n        continue-on-error: true\n"),
            base.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-latest\n"),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n"),
            base.replace("    timeout-minutes: 15\n", "    timeout-minutes: 0\n"),
            base.replace("  pull_request:\n", "  pull_request:\n    branches: []\n"),
            base + "  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n",
            base.replace("    needs: linux-policy\n", ""),
            base.replace("github.ref == 'refs/heads/main'", "always()"),
            base.replace('"$CI_REF" != "refs/heads/main"', '"$CI_REF" != "refs/heads/feature"'),
            base.replace('"$CI_REPOSITORY" != "keeldock-platform/platform-ci"', '"$CI_REPOSITORY" != "fork/platform-ci"'),
            base.replace("      - name: Run unprivileged source-free checks\n", "      - name: Run unprivileged source-free checks\n        run: sudo true\n"),
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "linux-confinement")


class LinuxLaneRegistryTests(unittest.TestCase):
    def test_moved_template_is_byte_for_byte_the_pre_split_template(self):
        template = policy_linux.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE
        self.assertEqual(
            hashlib.sha256(template.encode("utf-8")).hexdigest(),
            LINUX_WORKFLOW_SHA256_BEFORE_SPLIT,
        )
        self.assertEqual(template.encode("utf-8"), LINUX_WORKFLOW.read_bytes())
        self.assertEqual(
            hashlib.sha256(LINUX_WORKFLOW.read_bytes()).hexdigest(),
            LINUX_WORKFLOW_SHA256_BEFORE_SPLIT,
        )

    def test_shared_policy_reexports_the_moved_template_unchanged(self):
        self.assertIs(
            policy.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE,
            policy_linux.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE,
        )

    def test_lane_declares_only_the_linux_workflow_and_no_digest_pins(self):
        self.assertEqual(
            dict(policy_linux.WORKFLOW_TEMPLATES),
            {"linux-confinement": policy_linux.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE},
        )
        self.assertEqual(dict(policy_linux.WORKFLOW_SHA256), {})
        self.assertEqual(
            policy_linux.CANDIDATE_WORKFLOWS,
            ((".github/workflows/linux-confinement.yml", "linux-confinement", "linux-workflow-too-large"),),
        )

    def test_registry_routes_the_linux_kind_to_the_linux_lane(self):
        self.assertIs(policy.WORKFLOW_KIND_LANES["linux-confinement"], policy_linux)
        self.assertEqual(
            policy.LANE_WORKFLOW_TEMPLATES["linux-confinement"],
            policy_linux.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE,
        )
        for entry in policy_linux.CANDIDATE_WORKFLOWS:
            self.assertIn(entry, policy.LANE_CANDIDATE_WORKFLOWS)

    def test_dispatch_accepts_and_refuses_exactly_the_linux_template(self):
        template = policy_linux.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE
        self.assertTrue(validate_workflow_text(template, "platform", "linux-confinement"))
        for pool in ("connect", "workspace", "data"):
            with self.subTest(pool=pool):
                with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                    validate_workflow_text(template, pool, "linux-confinement")
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(template + "\n", "platform", "linux-confinement")
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(template[:-1], "platform", "linux-confinement")
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(template, "platform")
        with self.assertRaisesRegex(PolicyError, "workflow-input"):
            validate_workflow_text(template.encode("utf-8"), "platform", "linux-confinement")


class LinuxLanePublicTreeTests(unittest.TestCase):
    def test_linux_lane_files_are_in_the_platform_allowlist_and_scan_clean(self):
        result = scan_tree(ROOT, "platform")
        for name in LINUX_LANE_FILES:
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
