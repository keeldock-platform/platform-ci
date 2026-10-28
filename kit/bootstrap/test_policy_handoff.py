import hashlib
import unittest
from pathlib import Path

import policy
import policy_handoff
from policy import PolicyError, validate_workflow_text
from public_tree import PLATFORM_FILES, scan_tree


__all__ = ["HandoffWorkflowPolicyTests", "HandoffLaneRegistryTests", "HandoffLanePublicTreeTests"]

ROOT = Path(__file__).resolve().parents[2]
HANDOFF_WORKFLOW = ROOT / ".github/workflows/windows-handoff-synthetic.yml"
HANDOFF_KIND = "windows-handoff-synthetic"
HANDOFF_LANE_FILES = (
    ".github/workflows/windows-handoff-synthetic.yml",
    "kit/bootstrap/policy_handoff.py",
    "kit/bootstrap/test_policy_handoff.py",
    "kit/confinement/role_signer.py",
    "kit/confinement/test_role_signer.py",
    ".github/workflows/windows-source-admission.yml",
    ".github/workflows/lane-h-windows-receiver.yml",
    ".github/workflows/lane-h-linux-fetch-encrypt.yml",
    ".github/workflows/lane-h-capsule-attester.yml",
    ".github/workflows/attestation-role-signer-probe.yml",
    "kit/handoff/source_free.py",
    "kit/handoff/test_source_free.py",
)
WORKFLOW_PATHS = {
    "windows-handoff-synthetic": ".github/workflows/windows-handoff-synthetic.yml",
    "windows-source-admission": ".github/workflows/windows-source-admission.yml",
    "lane-h-windows-receiver": ".github/workflows/lane-h-windows-receiver.yml",
    "lane-h-linux-fetch-encrypt": ".github/workflows/lane-h-linux-fetch-encrypt.yml",
    "lane-h-capsule-attester": ".github/workflows/lane-h-capsule-attester.yml",
    "attestation-role-signer-probe": ".github/workflows/attestation-role-signer-probe.yml",
}


def declared_permission_lines(text):
    return [line for line in text.splitlines() if "permissions" in line]


class HandoffWorkflowPolicyTests(unittest.TestCase):
    def test_workflow_declares_exactly_one_empty_permissions_key(self):
        workflow = HANDOFF_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(declared_permission_lines(workflow), ["permissions: {}"])
        self.assertEqual(workflow.count("permissions"), 1)
        self.assertIn("\npermissions: {}\njobs:\n", workflow)
        for widened in (
            workflow.replace("    timeout-minutes: 10\n", "    timeout-minutes: 10\n    permissions: {}\n"),
            workflow.replace("permissions: {}\n", "permissions:\n  contents: read\n"),
            workflow.replace("permissions: {}\n", ""),
        ):
            with self.subTest(widened=len(widened)):
                self.assertNotEqual(declared_permission_lines(widened), ["permissions: {}"])

    def test_actual_handoff_workflow_matches_closed_source_free_shape(self):
        workflow = HANDOFF_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", HANDOFF_KIND))
        self.assertIn("permissions: {}", workflow)
        self.assertIn("kit/handoff/test_source_free.py", workflow)
        self.assertIn("kit/handoff/source_free.py", workflow)
        self.assertIn("- ubuntu-24.04", workflow)
        self.assertIn("- windows-2025", workflow)
        for forbidden in (
            "inputs:",
            "secrets.",
            "uses:",
            "id-token",
            "attestations",
            "contents:",
            "actions:",
            "upload-artifact",
            "download-artifact",
            "cache:",
            "outputs:",
            "pull_request_target",
            "continue-on-error",
            "needs:",
            "workflow_run",
            "environment:",
            "-latest",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", HANDOFF_KIND)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_handoff_workflow_rejects_trigger_runner_permission_and_step_changes(self):
        base = HANDOFF_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  pull_request:\n", "  pull_request_target:\n"),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n"),
            base.replace("          - windows-2025\n", "          - windows-latest\n"),
            base.replace("    timeout-minutes: 10\n", "    timeout-minutes: 360\n"),
            base.replace('"$python_bin" -B kit/handoff/test_source_free.py\n', "true\n"),
            base.replace("      - name: Generate local synthetic tree\n", "      - name: Generate local synthetic tree\n        continue-on-error: true\n"),
            base.replace("git fetch --quiet --no-tags --depth=1 origin", "git fetch --quiet origin"),
            base.replace('if [[ "$actual_sha" != "$CI_SHA" ]]; then', "if false; then"),
            base.replace("      CI_REPOSITORY: ${{ github.repository }}\n", "      CI_REPOSITORY: ${{ github.repository }}\n      EXTRA: ${{ secrets.EXTRA }}\n"),
            base + "  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                self.assertNotEqual(changed, base)
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(changed, "platform", HANDOFF_KIND)


class HandoffLaneRegistryTests(unittest.TestCase):
    def test_lane_is_registered_with_six_exact_workflow_digest_kinds(self):
        self.assertIn(policy_handoff, policy.LANE_MODULES)
        self.assertEqual(dict(policy_handoff.WORKFLOW_TEMPLATES), {})
        self.assertEqual(set(policy_handoff.WORKFLOW_SHA256), set(WORKFLOW_PATHS))
        for digest in policy_handoff.WORKFLOW_SHA256.values():
            self.assertRegex(digest, r"^[a-f0-9]{64}$")
        self.assertEqual(policy_handoff.CANDIDATE_WORKFLOWS, (
            (".github/workflows/windows-handoff-synthetic.yml", HANDOFF_KIND,
             "handoff-workflow-too-large"),
        ))

    def test_lane_contributes_only_closed_source_free_workflow_kinds(self):
        owned = [kind for kind, module in policy.WORKFLOW_KIND_LANES.items() if module is policy_handoff]
        self.assertEqual(set(owned), set(WORKFLOW_PATHS))
        templates, digests, owners, candidates = policy.build_lane_registry(
            (policy_handoff,), policy.SHARED_WORKFLOW_KINDS
        )
        self.assertEqual(dict(templates), {})
        self.assertEqual(dict(digests), dict(policy_handoff.WORKFLOW_SHA256))
        self.assertEqual(set(owners), set(WORKFLOW_PATHS))
        self.assertEqual(candidates, policy_handoff.CANDIDATE_WORKFLOWS)

    def test_workflow_kinds_match_exact_pinned_bytes(self):
        for kind, path in WORKFLOW_PATHS.items():
            with self.subTest(kind=kind):
                content = (ROOT / path).read_bytes()
                digest = hashlib.sha256(content).hexdigest()
                self.assertEqual(digest, policy_handoff.WORKFLOW_SHA256[kind])
                self.assertTrue(validate_workflow_text(content.decode("ascii"), "platform", kind))
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(content.decode("ascii") + "\n", "platform", kind)
                with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                    validate_workflow_text(content.decode("ascii"), "connect", kind)

    def test_registry_routes_the_handoff_kind_to_the_handoff_lane(self):
        owned = [kind for kind, module in policy.WORKFLOW_KIND_LANES.items() if module is policy_handoff]
        self.assertEqual(set(owned), set(WORKFLOW_PATHS))
        self.assertEqual(
            policy.LANE_WORKFLOW_SHA256[HANDOFF_KIND],
            policy_handoff.WORKFLOW_SHA256[HANDOFF_KIND],
        )
        self.assertNotIn(HANDOFF_KIND, policy.LANE_WORKFLOW_TEMPLATES)
        for entry in policy_handoff.CANDIDATE_WORKFLOWS:
            self.assertIn(entry, policy.LANE_CANDIDATE_WORKFLOWS)

    def test_lane_module_exposes_exactly_the_lane_interface(self):
        public = sorted(name for name in vars(policy_handoff) if not name.startswith("_"))
        self.assertEqual(public, ["CANDIDATE_WORKFLOWS", "WORKFLOW_SHA256", "WORKFLOW_TEMPLATES"])

    def test_dispatch_checks_the_handoff_digest_and_platform_pool(self):
        text = HANDOFF_WORKFLOW.read_text(encoding="utf-8")
        for pool in ("connect", "workspace", "data"):
            with self.subTest(pool=pool):
                with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                    validate_workflow_text(text, pool, HANDOFF_KIND)
        for changed in (text + "\n", text[:-1], text.replace("\n", "\r\n")):
            with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                validate_workflow_text(changed, "platform", HANDOFF_KIND)
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(text, "platform")
        with self.assertRaisesRegex(PolicyError, "workflow-input"):
            validate_workflow_text(text.encode("utf-8"), "platform", HANDOFF_KIND)

    def test_other_lane_workflows_are_refused_under_the_handoff_kind(self):
        for relative in (
            ".github/workflows/public-policy.yml",
            ".github/workflows/linux-confinement.yml",
            ".github/workflows/windows-native-preflight.yml",
            ".github/workflows/windows-attestation-permission-probe.yml",
        ):
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(text, "platform", HANDOFF_KIND)

    def test_unregistered_handoff_kinds_are_refused_by_dispatch(self):
        for kind in ("windows-handoff", "handoff", "windows-handoff-preflight", "lane-h-windows-fetch"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(PolicyError, "workflow-kind"):
                    validate_workflow_text("name: handoff\n", "platform", kind)


class HandoffLanePublicTreeTests(unittest.TestCase):
    def test_handoff_lane_files_are_in_the_platform_allowlist_and_scan_clean(self):
        result = scan_tree(ROOT, "platform")
        for name in HANDOFF_LANE_FILES:
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
