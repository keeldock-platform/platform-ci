"""Source-free regressions for profile-specific Rust tooling log grammar."""

import unittest

import public_audit


IDENTITY = {
    "profile": "core-rust",
    "run_id": "12345",
    "control_sha": "a" * 40,
    "control_run_id": "9876",
    "wave_id": "wave-test-0001",
    "bundle_id": "bundle-test-0001",
    "cache_baseline_sha256": "b" * 64,
}


class RustPublicAuditTests(unittest.TestCase):
    def test_only_fixed_rust_tool_preparation_receipts_are_public(self):
        grammar = public_audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", public_audit.RUN_JOB, IDENTITY, "encrypted",
        )
        counts = {}
        self.assertTrue(grammar.step_output_ok(
            "Install pinned Rust toolchain", "rust_offline_tools=prepared", counts,
        ))
        self.assertTrue(grammar.step_output_ok(
            "Prepare dependencies before the cut", "dependency_preparation=complete", counts,
        ))
        self.assertTrue(grammar.step_output_ok(
            "Prepare dependencies before the cut", "rust_offline_tools=installed", counts,
        ))
        self.assertFalse(grammar.step_output_ok(
            "Prepare dependencies before the cut", "rust_offline_tools=installed", counts,
        ))
        self.assertFalse(grammar.step_output_ok(
            "Prepare dependencies before the cut", "candidate-output=installed", counts,
        ))

    def test_node_profile_does_not_accept_rust_tooling_receipt(self):
        identity = dict(IDENTITY, profile="core-node")
        grammar = public_audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", public_audit.RUN_JOB, identity, "encrypted",
        )
        self.assertFalse(grammar.step_output_ok(
            "Prepare dependencies before the cut", "rust_offline_tools=installed", {},
        ))


if __name__ == "__main__":
    unittest.main()
