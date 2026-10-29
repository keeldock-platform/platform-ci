import hashlib
import re
import unittest
from pathlib import Path

import policy
import policy_rust
from policy import PolicyError, validate_workflow_text
from public_tree import PINNED_FILE_SHA256, PLATFORM_FILES, scan_tree


__all__ = [
    "RustLockWorkflowPolicyTests",
    "RustLockLaneRegistryTests",
    "RustLockLanePublicTreeTests",
]

ROOT = Path(__file__).resolve().parents[2]
RUST_LOCK_WORKFLOW = ROOT / ".github/workflows/core-rust-lock-return.yml"
RUST_LOCK_PATH = ".github/workflows/core-rust-lock-return.yml"
RUST_LOCK_KIND = "core-rust-lock-return"
RUST_LOCK_LANE_FILES = (
    ".github/workflows/core-rust-lock-return.yml",
    "kit/bootstrap/policy_rust.py",
    "kit/bootstrap/test_policy_rust.py",
    "kit/confinement/cargo_lock_bootstrap.py",
    "kit/confinement/test_confinement_cargo_lock_bootstrap.py",
    "kit/confinement/cargo_lock_receipt.py",
    "kit/confinement/test_cargo_lock_receipt.py",
)


def job_blocks(text):
    jobs = text.split("\njobs:\n", 1)[1]
    blocks = {}
    current = None
    for line in jobs.splitlines(keepends=True):
        match = re.match(r"  ([a-z0-9-]+):\n\Z", line)
        if match:
            current = match.group(1)
            blocks[current] = ""
        elif current is not None:
            blocks[current] += line
    return blocks


class RustLockWorkflowPolicyTests(unittest.TestCase):
    def test_actual_workflow_is_the_exact_policy_template(self):
        workflow = RUST_LOCK_WORKFLOW.read_bytes()
        self.assertEqual(workflow, policy_rust.CORE_RUST_LOCK_RETURN_WORKFLOW_TEMPLATE.encode("utf-8"))
        self.assertTrue(validate_workflow_text(workflow.decode("utf-8"), "platform", RUST_LOCK_KIND))
        self.assertTrue(workflow.isascii())
        self.assertNotIn(chr(35).encode("ascii"), workflow)
        self.assertLess(len(workflow), 262144)

    def test_workflow_is_manual_main_only_with_no_privileged_default_permission(self):
        workflow = RUST_LOCK_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual([line for line in workflow.splitlines() if line.startswith("permissions")],
                         ["permissions: {}"])
        header = workflow.split("\njobs:\n", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:\n    inputs:\n", header)
        for trigger in ("push:", "pull_request", "schedule:", "workflow_run", "workflow_call", "repository_dispatch"):
            with self.subTest(trigger=trigger):
                self.assertNotIn(trigger, workflow)
        inputs = re.findall(r"^      ([a-z0-9_]+):\n        description:", header, flags=re.MULTILINE)
        self.assertEqual(inputs, ["request_id", "request_b64", "recipient_spki_b64"])
        for forbidden in ("ref:", "branch", "source_sha:", "base_sha:", "tag:", "url:"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn("\n      " + forbidden, header)
        blocks = job_blocks(workflow)
        self.assertEqual(sorted(blocks), [
            "core-rust-lock-return", "core-rust-lock-return-audit",
            "core-rust-lock-return-prepare", "core-rust-lock-return-settings",
        ])
        for name, block in blocks.items():
            with self.subTest(job=name):
                self.assertIn("github.event_name == 'workflow_dispatch'", block)
                self.assertIn("github.ref == 'refs/heads/main'", block)
                self.assertIn("cache-mode: none", block)
        self.assertIn("environment: source-read\n", blocks["core-rust-lock-return"])
        for name in ("core-rust-lock-return-settings", "core-rust-lock-return-prepare",
                     "core-rust-lock-return-audit"):
            self.assertNotIn("environment:", blocks[name])

    def test_only_the_request_inputs_are_read_and_never_expanded_into_commands(self):
        workflow = RUST_LOCK_WORKFLOW.read_text(encoding="utf-8")
        expressions = re.findall(r"\$\{\{\s*inputs\.([a-z0-9_]+)\s*\}\}", workflow)
        self.assertEqual(set(expressions), {"request_id", "request_b64", "recipient_spki_b64"})
        for line in workflow.splitlines():
            if "inputs." in line and "run:" not in line:
                self.assertTrue(
                    line.lstrip().startswith(("KD_FEEDBACK_", "run-name:", "name:")),
                    line,
                )
        run_bodies = re.findall(r"run: \|\n((?:          .*\n)+)", workflow)
        self.assertTrue(run_bodies)
        for body in run_bodies:
            self.assertNotIn("${{ inputs.", body)
            self.assertNotIn("${{ github.event.", body)

    def test_producer_uses_the_cargo_lock_profile_and_revokes_the_token_before_toolchain_use(self):
        workflow = RUST_LOCK_WORKFLOW.read_text(encoding="utf-8")
        producer = job_blocks(workflow)["core-rust-lock-return"]
        self.assertIn("macos_feedback_producer.py run --profile cargo_lock --token-stdin", producer)
        self.assertIn("macos_feedback_producer.py publish --profile cargo_lock", producer)
        self.assertNotIn("--profile lock", workflow)
        self.assertNotIn("profile=lock ", workflow)
        self.assertNotIn("lock-return-v1.enc", workflow.replace("rust-lock-return-v1.enc", ""))
        self.assertIn("name: feedback-cargo_lock-${{ inputs.request_id }}", producer)
        self.assertIn("core-feedback-upload/rust-lock-return-v1.enc", producer)
        self.assertIn("skip-token-revoke: true", producer)
        self.assertIn("name: Revoke token when producer did not confirm", producer)
        order = [producer.index(text) for text in (
            "name: Mint scoped source-reader token",
            "name: Run and publish encrypted feedback",
            "name: Revoke token when producer did not confirm",
        )]
        self.assertEqual(order, sorted(order))
        for forbidden in ("cargo ", "rustup", ".cargo", "CARGO_", "RUSTC", "HTTP_PROXY", "https_proxy"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)

    def test_every_action_is_pinned_to_a_full_commit_and_nothing_else_is_used(self):
        workflow = RUST_LOCK_WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses: (.*)$", workflow, flags=re.MULTILINE)
        self.assertEqual(len(uses), 4)
        for value in uses:
            with self.subTest(uses=value):
                self.assertRegex(value, r"^actions/[a-z-]+@[0-9a-f]{40}$")

    def test_workflow_rejects_widening_and_step_changes(self):
        base = RUST_LOCK_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  workflow_dispatch:\n", "  push:\n  workflow_dispatch:\n", 1),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n", 1),
            base.replace("github.ref == 'refs/heads/main'", "github.ref != ''", 1),
            base.replace("--profile cargo_lock --token-stdin", "--profile lock --token-stdin", 1),
            base.replace("skip-token-revoke: true\n", "", 1),
            base.replace("environment: source-read\n", "", 1),
            base.replace("      recipient_spki_b64:\n", "      extra_ref:\n        type: string\n      recipient_spki_b64:\n", 1),
            base.replace("timeout-minutes: 75", "timeout-minutes: 360", 1),
            base.replace('[[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]', "true", 1),
            base + "  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                self.assertNotEqual(changed, base)
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(changed, "platform", RUST_LOCK_KIND)


class RustLockLaneRegistryTests(unittest.TestCase):
    def test_lane_declares_exactly_one_exact_template_and_no_digest_pin(self):
        self.assertIn(policy_rust, policy.LANE_MODULES)
        self.assertEqual(
            dict(policy_rust.WORKFLOW_TEMPLATES),
            {RUST_LOCK_KIND: policy_rust.CORE_RUST_LOCK_RETURN_WORKFLOW_TEMPLATE},
        )
        self.assertEqual(dict(policy_rust.WORKFLOW_SHA256), {})
        self.assertEqual(policy_rust.CANDIDATE_WORKFLOWS, (
            (RUST_LOCK_PATH, RUST_LOCK_KIND, "rust-lock-return-workflow-too-large"),
        ))

    def test_registry_routes_the_kind_to_this_lane_only(self):
        owned = [kind for kind, module in policy.WORKFLOW_KIND_LANES.items() if module is policy_rust]
        self.assertEqual(owned, [RUST_LOCK_KIND])
        self.assertEqual(
            policy.LANE_WORKFLOW_TEMPLATES[RUST_LOCK_KIND],
            policy_rust.CORE_RUST_LOCK_RETURN_WORKFLOW_TEMPLATE,
        )
        self.assertNotIn(RUST_LOCK_KIND, policy.SHARED_WORKFLOW_KINDS)
        self.assertNotIn(RUST_LOCK_KIND, policy.FEEDBACK_RETURN_WORKFLOW_SHA256)
        self.assertIn(policy_rust.CANDIDATE_WORKFLOWS[0], policy.LANE_CANDIDATE_WORKFLOWS)
        templates, digests, owners, candidates = policy.build_lane_registry(
            (policy_rust,), policy.SHARED_WORKFLOW_KINDS,
        )
        self.assertEqual(dict(templates), dict(policy_rust.WORKFLOW_TEMPLATES))
        self.assertEqual(dict(digests), {})
        self.assertEqual(set(owners), {RUST_LOCK_KIND})
        self.assertEqual(candidates, policy_rust.CANDIDATE_WORKFLOWS)

    def test_lane_module_exposes_the_lane_interface_and_its_template_only(self):
        public = sorted(name for name in vars(policy_rust) if not name.startswith("_"))
        self.assertEqual(public, [
            "CANDIDATE_WORKFLOWS", "CORE_RUST_LOCK_RETURN_WORKFLOW_TEMPLATE",
            "WORKFLOW_SHA256", "WORKFLOW_TEMPLATES",
        ])
        self.assertFalse(hasattr(policy_rust, "PolicyError"))

    def test_dispatch_accepts_and_refuses_exactly_the_template(self):
        template = policy_rust.CORE_RUST_LOCK_RETURN_WORKFLOW_TEMPLATE
        self.assertTrue(validate_workflow_text(template, "platform", RUST_LOCK_KIND))
        for pool in ("connect", "workspace", "data"):
            with self.subTest(pool=pool):
                with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                    validate_workflow_text(template, pool, RUST_LOCK_KIND)
        for changed in (template + "\n", template[:-1], template.replace("\n", "\r\n")):
            with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                validate_workflow_text(changed, "platform", RUST_LOCK_KIND)
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(template, "platform")
        with self.assertRaisesRegex(PolicyError, "workflow-input"):
            validate_workflow_text(template.encode("utf-8"), "platform", RUST_LOCK_KIND)

    def test_sibling_return_workflows_are_refused_under_this_kind(self):
        for relative in (
            ".github/workflows/node-lock-return.yml",
            ".github/workflows/core-rust-format-return.yml",
            ".github/workflows/core-build-diagnostic-return.yml",
            ".github/workflows/public-policy.yml",
        ):
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(text, "platform", RUST_LOCK_KIND)

    def test_other_kinds_refuse_this_workflow(self):
        text = RUST_LOCK_WORKFLOW.read_text(encoding="utf-8")
        for kind in ("node-lock-return", "core-rust-format-return", "linux-confinement", "public-policy"):
            with self.subTest(kind=kind):
                with self.assertRaises(PolicyError):
                    validate_workflow_text(text, "platform", kind)


class RustLockLanePublicTreeTests(unittest.TestCase):
    def test_lane_files_are_in_the_platform_allowlist_and_scan_clean(self):
        result = scan_tree(ROOT, "platform")
        for name in RUST_LOCK_LANE_FILES:
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, result)

    def test_workflow_pin_matches_the_file_and_the_template(self):
        digest = hashlib.sha256(RUST_LOCK_WORKFLOW.read_bytes()).hexdigest()
        self.assertEqual(PINNED_FILE_SHA256[RUST_LOCK_PATH], digest)
        self.assertEqual(
            hashlib.sha256(policy_rust.CORE_RUST_LOCK_RETURN_WORKFLOW_TEMPLATE.encode("utf-8")).hexdigest(),
            digest,
        )


if __name__ == "__main__":
    unittest.main()
