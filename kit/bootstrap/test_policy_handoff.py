import unittest
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
)


class HandoffLaneRegistryTests(unittest.TestCase):
    def test_lane_is_registered_and_currently_declares_no_workflows(self):
        self.assertIn(policy_handoff, policy.LANE_MODULES)
        self.assertEqual(dict(policy_handoff.WORKFLOW_TEMPLATES), {})
        self.assertEqual(dict(policy_handoff.WORKFLOW_SHA256), {})
        self.assertEqual(tuple(policy_handoff.CANDIDATE_WORKFLOWS), ())

    def test_lane_contributes_nothing_to_the_registry(self):
        owned = [kind for kind, module in policy.WORKFLOW_KIND_LANES.items() if module is policy_handoff]
        self.assertEqual(owned, [])
        templates, digests, owners, candidates = policy.build_lane_registry(
            (policy_handoff,), policy.SHARED_WORKFLOW_KINDS
        )
        self.assertEqual((dict(templates), dict(digests), dict(owners), candidates), ({}, {}, {}, ()))

    def test_lane_module_exposes_exactly_the_lane_interface(self):
        public = sorted(name for name in vars(policy_handoff) if not name.startswith("_"))
        self.assertEqual(public, ["CANDIDATE_WORKFLOWS", "WORKFLOW_SHA256", "WORKFLOW_TEMPLATES"])

    def test_unregistered_handoff_kinds_are_refused_by_dispatch(self):
        for kind in ("windows-handoff", "handoff", "windows-handoff-preflight"):
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
