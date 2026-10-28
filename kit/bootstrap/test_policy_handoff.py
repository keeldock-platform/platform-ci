import unittest
import hashlib
from pathlib import Path

import policy
import policy_handoff
from policy import PolicyError, validate_workflow_text
from public_tree import PLATFORM_FILES, scan_tree


__all__ = ["HandoffLaneRegistryTests", "HandoffLanePublicTreeTests"]

ROOT = Path(__file__).resolve().parents[2]
HANDOFF_LANE_FILES = (
    "kit/bootstrap/policy_handoff.py",
    "kit/bootstrap/test_policy_handoff.py",
    "kit/confinement/role_signer.py",
    "kit/confinement/test_role_signer.py",
    ".github/workflows/windows-source-admission.yml",
    ".github/workflows/lane-h-windows-receiver.yml",
    ".github/workflows/lane-h-linux-fetch-encrypt.yml",
    ".github/workflows/lane-h-capsule-attester.yml",
    ".github/workflows/attestation-role-signer-probe.yml",
)
WORKFLOW_PATHS = {
    "windows-source-admission": ".github/workflows/windows-source-admission.yml",
    "lane-h-windows-receiver": ".github/workflows/lane-h-windows-receiver.yml",
    "lane-h-linux-fetch-encrypt": ".github/workflows/lane-h-linux-fetch-encrypt.yml",
    "lane-h-capsule-attester": ".github/workflows/lane-h-capsule-attester.yml",
    "attestation-role-signer-probe": ".github/workflows/attestation-role-signer-probe.yml",
}


class HandoffLaneRegistryTests(unittest.TestCase):
    def test_lane_is_registered_with_five_exact_workflow_digest_kinds(self):
        self.assertIn(policy_handoff, policy.LANE_MODULES)
        self.assertEqual(dict(policy_handoff.WORKFLOW_TEMPLATES), {})
        self.assertEqual(set(policy_handoff.WORKFLOW_SHA256), set(WORKFLOW_PATHS))
        for digest in policy_handoff.WORKFLOW_SHA256.values():
            self.assertRegex(digest, r"^[a-f0-9]{64}$")
        self.assertEqual(tuple(policy_handoff.CANDIDATE_WORKFLOWS), ())

    def test_lane_contributes_only_closed_source_free_workflow_kinds(self):
        owned = [kind for kind, module in policy.WORKFLOW_KIND_LANES.items() if module is policy_handoff]
        self.assertEqual(set(owned), set(WORKFLOW_PATHS))
        templates, digests, owners, candidates = policy.build_lane_registry(
            (policy_handoff,), policy.SHARED_WORKFLOW_KINDS
        )
        self.assertEqual(dict(templates), {})
        self.assertEqual(dict(digests), dict(policy_handoff.WORKFLOW_SHA256))
        self.assertEqual(set(owners), set(WORKFLOW_PATHS))
        self.assertEqual(candidates, ())

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

    def test_lane_module_exposes_exactly_the_lane_interface(self):
        public = sorted(name for name in vars(policy_handoff) if not name.startswith("_"))
        self.assertEqual(public, ["CANDIDATE_WORKFLOWS", "WORKFLOW_SHA256", "WORKFLOW_TEMPLATES"])

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
