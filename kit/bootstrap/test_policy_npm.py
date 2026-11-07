import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kit" / "bootstrap"))
import policy
import policy_npm


class RetiredNpmAdmissionWorkflowTests(unittest.TestCase):
    def test_protected_npm_and_node_lock_returns_are_retired(self):
        self.assertFalse((ROOT / ".github/workflows/core-npm-admission-return.yml").exists())
        self.assertFalse((ROOT / ".github/workflows/node-lock-return.yml").exists())
        self.assertNotIn("core-npm-admission-return", policy.WORKFLOW_KIND_LANES)
        self.assertNotIn("node-lock-return", policy.WORKFLOW_KIND_LANES)
        self.assertEqual(policy_npm.WORKFLOW_TEMPLATES, {})
        self.assertEqual(policy_npm.WORKFLOW_SHA256, {})


if __name__ == "__main__":
    unittest.main()
