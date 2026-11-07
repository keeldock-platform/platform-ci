import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kit" / "bootstrap"))
import policy
import policy_rust


class RetiredRustLockWorkflowTests(unittest.TestCase):
    def test_protected_rust_lock_return_is_retired(self):
        self.assertFalse((ROOT / ".github/workflows/core-rust-lock-return.yml").exists())
        self.assertNotIn("core-rust-lock-return", policy.WORKFLOW_KIND_LANES)
        self.assertEqual(policy_rust.WORKFLOW_TEMPLATES, {})
        self.assertEqual(policy_rust.WORKFLOW_SHA256, {})


if __name__ == "__main__":
    unittest.main()
