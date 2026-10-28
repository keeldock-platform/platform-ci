import hashlib
import re
import unittest
from pathlib import Path

import policy
import policy_linux
from policy import PolicyError, validate_workflow_text
from public_tree import PLATFORM_FILES, scan_tree


__all__ = [
    "LinuxWorkflowPolicyTests",
    "LinuxLaneRegistryTests",
    "LinuxLanePublicTreeTests",
    "LinuxSourceAdmissionWorkflowTests",
]

ROOT = Path(__file__).resolve().parents[2]
LINUX_WORKFLOW = ROOT / ".github/workflows/linux-confinement.yml"
ADMISSION_WORKFLOW = ROOT / ".github/workflows/linux-source-admission.yml"
STANDIN = "kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd"
LINUX_WORKFLOW_SHA256_BEFORE_SPLIT = "f7860a422e818f238232c395a100422ab32e5a6498737a8840d52a362b96b6ae"
LINUX_LANE_FILES = (
    ".github/workflows/linux-confinement.yml",
    "kit/bootstrap/policy_linux.py",
    "kit/bootstrap/test_policy_linux.py",
    "kit/confinement/linux_harness.py",
    "kit/confinement/test_linux_harness.py",
    ".github/workflows/linux-source-admission.yml",
    "kit/confinement/linux_boundary.py",
    "kit/confinement/test_linux_boundary.py",
    "kit/confinement/linux_canaries.py",
    "kit/confinement/test_linux_canaries.py",
    "kit/confinement/linux_channels.py",
    "kit/confinement/test_linux_channels.py",
    "kit/confinement/linux_fixtures.py",
    "kit/confinement/test_linux_fixtures.py",
    "kit/confinement/linux_probes.py",
    "kit/confinement/linux_session.py",
    "kit/confinement/test_linux_session.py",
    "kit/confinement/linux_settings.py",
    "kit/confinement/test_linux_settings.py",
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

    def test_lane_declares_only_the_linux_workflows_and_no_digest_pins(self):
        self.assertEqual(
            dict(policy_linux.WORKFLOW_TEMPLATES),
            {
                "linux-confinement": policy_linux.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE,
                "linux-source-admission": policy_linux.LINUX_SOURCE_ADMISSION_WORKFLOW_TEMPLATE,
            },
        )
        self.assertEqual(dict(policy_linux.WORKFLOW_SHA256), {})
        self.assertEqual(
            policy_linux.CANDIDATE_WORKFLOWS,
            (
                (".github/workflows/linux-confinement.yml", "linux-confinement", "linux-workflow-too-large"),
                (
                    ".github/workflows/linux-source-admission.yml",
                    "linux-source-admission",
                    "linux-source-admission-workflow-too-large",
                ),
            ),
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



class LinuxSourceAdmissionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = ADMISSION_WORKFLOW.read_text(encoding="utf-8")

    def jobs(self):
        parts = re.split(r"(?m)^  (linux-source-admission-[a-z]+):\n", self.text)
        return {parts[index]: parts[index + 1] for index in range(1, len(parts), 2)}

    def test_template_is_byte_for_byte_the_workflow_and_validates_only_for_the_platform_pool(self):
        template = policy_linux.LINUX_SOURCE_ADMISSION_WORKFLOW_TEMPLATE
        self.assertEqual(template.encode("utf-8"), ADMISSION_WORKFLOW.read_bytes())
        self.assertTrue(validate_workflow_text(self.text, "platform", "linux-source-admission"))
        for pool in ("connect", "workspace", "data"):
            with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                validate_workflow_text(self.text, pool, "linux-source-admission")
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(self.text, "platform")

    def test_synthetic_mode_has_no_source_environment_secret_app_token_or_checkout_action(self):
        for forbidden in (
            "secrets.", "environment:", "create-github-app-token", "actions/checkout", "id-token", "pull_request",
            "inputs.", "source-read", "SOURCE_READER", "workflow_call",
        ):
            self.assertNotIn(forbidden, self.text)
        self.assertEqual(re.findall(r"(?m)^on:\n((?:  .*\n)+)", self.text), ["  workflow_dispatch:\n"])
        self.assertIn("\npermissions: {}\n", self.text)

    def test_no_step_uses_any_action_so_no_composite_markers_can_reach_the_verdict_log(self):
        self.assertIsNone(re.search(r"(?m)^\s*-?\s*uses:", self.text))
        self.assertNotIn("uses: ./", self.text)
        for job, body in self.jobs().items():
            self.assertNotIn("uses:", body, job)

    def test_four_jobs_with_least_privilege_and_cache_mode_none_everywhere(self):
        jobs = self.jobs()
        self.assertEqual(
            list(jobs),
            [
                "linux-source-admission-settings",
                "linux-source-admission-unit",
                "linux-source-admission-boundary",
                "linux-source-admission-audit",
            ],
        )
        self.assertEqual(self.text.count("cache-mode: none"), 5)
        self.assertIn("    permissions:\n      contents: read\n", jobs["linux-source-admission-settings"])
        for name in ("unit", "boundary", "audit"):
            self.assertIn("    permissions: {}\n", jobs["linux-source-admission-" + name])
        self.assertEqual(self.text.count("contents: read"), 1)
        self.assertEqual(self.text.count("runs-on: ubuntu-24.04"), 4)
        self.assertNotIn("latest", self.text)

    def test_only_the_boundary_job_uses_sudo_and_the_canary_stays_out_of_arguments(self):
        jobs = self.jobs()
        for name, body in jobs.items():
            self.assertEqual("sudo" in body, name.endswith("boundary"), name)
        boundary = jobs["linux-source-admission-boundary"]
        self.assertEqual(boundary.count("--preserve-env=KD_CANARY_SECRET"), 3)
        for line in boundary.splitlines():
            if "sudo" in line:
                self.assertNotIn("$KD_CANARY_SECRET", line)
                self.assertNotIn(STANDIN, line)
        self.assertEqual(self.text.count("KD_CANARY_SECRET: " + STANDIN), 3)
        self.assertNotIn("KD_CANARY_SECRET", jobs["linux-source-admission-settings"])
        self.assertNotIn("KD_CANARY_SECRET", jobs["linux-source-admission-unit"])
        self.assertNotIn("KD_CANARY_SECRET", jobs["linux-source-admission-audit"])

    def test_boundary_steps_run_in_the_required_order_with_controls_rerun_before_the_project_phase(self):
        boundary = self.jobs()["linux-source-admission-boundary"]
        names = re.findall(r"(?m)^      - name: (.*)$", boundary)
        self.assertEqual(
            names,
            [
                "Fetch exact public control",
                "Record runner image and resolve the preinstalled toolchain",
                "Boundary self-test with generated hostile fixtures and secret canaries",
                "Synthetic project phase marker",
                "Re-run positive controls immediately before the first project command",
                "Merge phase records",
                "Forced faults must fail closed",
            ],
        )
        self.assertLess(boundary.index("linux_boundary.py selftest"), boundary.index("linux_boundary.py recheck"))
        self.assertLess(boundary.index("linux_boundary.py recheck"), boundary.index("linux_boundary.py merge"))
        self.assertIn("--synthetic-standin", boundary)
        self.assertIn("project-execution=none", boundary)

    def test_audit_job_runs_always_and_only_reports_upstream_results(self):
        audit = self.jobs()["linux-source-admission-audit"]
        self.assertIn("if: ${{ always() &&", audit)
        for name in ("settings", "unit", "boundary"):
            self.assertIn("needs.linux-source-admission-" + name + ".result", audit)
        self.assertIn("status=placeholder", audit)
        self.assertNotIn("sudo", audit)
        self.assertNotIn("git ", audit)

    def test_verdict_prefix_is_never_printed_by_the_workflow_or_any_linux_module(self):
        prefix = "KD-CONFINEMENT" + "-VERDICT"
        self.assertNotIn(prefix, self.text)
        for path in (ROOT / "kit/confinement").glob("linux_*.py"):
            self.assertNotIn(prefix, path.read_text(encoding="utf-8"), path.name)

    def test_workflow_uses_only_kit_scripts_that_are_in_the_public_allowlist(self):
        for script in sorted(set(re.findall(r"kit/[a-z_/]+\.py", self.text))):
            with self.subTest(script=script):
                self.assertIn(script, PLATFORM_FILES)
                self.assertTrue((ROOT / script).is_file())

    def test_mutations_of_the_workflow_are_refused_as_template_mismatches(self):
        mutations = (
            self.text.replace("cache-mode: none\njobs:", "jobs:"),
            self.text.replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest", 1),
            self.text.replace("permissions: {}\ncache-mode", "permissions: write-all\ncache-mode", 1),
            self.text.replace("      - name: Synthetic project phase marker\n", "      - name: Synthetic project phase marker\n        uses: ./kit/bootstrap\n", 1),
            self.text.replace("      - name: Fetch exact public control\n", "      - name: Fetch exact public control\n        if: ${{ false }}\n", 1),
            self.text.replace("--synthetic-standin", "", 1),
            self.text.replace("workflow_dispatch:\n", "workflow_dispatch:\n  push:\n", 1),
            self.text + "  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(index=index):
                self.assertNotEqual(changed, self.text)
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(changed, "platform", "linux-source-admission")

    def test_composite_step_in_the_verdict_job_is_refused_at_policy_time(self):
        changed = self.text.replace(
            "      - name: Merge phase records\n",
            "      - name: Merge phase records\n        uses: ./kit/bootstrap\n",
            1,
        )
        self.assertIn("uses: ./", changed)
        with self.assertRaises(PolicyError):
            validate_workflow_text(changed, "platform", "linux-source-admission")


if __name__ == "__main__":
    unittest.main(verbosity=2)
