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
    "LinuxQuickReturnWorkflowTests",
]

ROOT = Path(__file__).resolve().parents[2]
LINUX_WORKFLOW = ROOT / ".github/workflows/linux-confinement.yml"
LINUX_DIAGNOSTIC_WORKFLOW = ROOT / ".github/workflows/linux-confinement-diagnostic.yml"
ADMISSION_WORKFLOW = ROOT / ".github/workflows/linux-source-admission.yml"
QUICK_WORKFLOW = ROOT / ".github/workflows/core-linux-quick-return.yml"
QUICK_MODULE = ROOT / "core-ci/linux_quick_return.py"
STANDIN = "kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd"
ENVIRONMENT_LINE = "    environment: ${{ inputs.mode == 'source' && 'linux-source-read' || '' }}\n"
MAIN_ENVIRONMENT_LINE = "    environment: ${{ inputs.mode == 'source' && github.ref == 'refs/heads/main' && 'linux-source-read-main' || inputs.mode == 'source' && 'linux-source-read' || '' }}\n"
LINUX_CONFINEMENT_WORKFLOW_SHA256 = "4911ae082a7afe855a24e3f5259db33c41c00e4d558a7a42b576a52595e3841c"
LINUX_LANE_FILES = (
    ".github/workflows/linux-confinement.yml",
    ".github/workflows/linux-confinement-diagnostic.yml",
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
    "kit/confinement/linux_source_build.py",
    "kit/confinement/test_linux_source_build.py",
    "kit/confinement/test_linux_source_build_tiers.py",
    ".github/workflows/core-linux-quick-return.yml",
    "core-ci/linux_quick_return.py",
    "core-ci/test_linux_quick_return.py",
    "core-ci/test_separation.py",
)


class LinuxWorkflowPolicyTests(unittest.TestCase):
    def test_actual_linux_workflow_matches_closed_supported_shape(self):
        workflow = LINUX_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", "linux-confinement"))
        trigger = workflow.split("jobs:", 1)[0]
        self.assertIn("on:\n  workflow_call:\n", trigger)
        self.assertNotIn("workflow_dispatch", trigger)
        self.assertNotIn("pull_request", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("promotion-check-reuse", workflow)
        self.assertNotIn("sudo ", workflow)
        self.assertNotIn("inputs:", workflow)
        diagnostic = LINUX_DIAGNOSTIC_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(diagnostic, "platform", "linux-confinement-diagnostic"))
        self.assertIn("github.event_name == 'workflow_dispatch'", diagnostic)
        self.assertIn("github.ref == 'refs/heads/main'", diagnostic)
        self.assertIn('"$CI_REF" != "refs/heads/main"', diagnostic)
        self.assertIn('"$CI_REPOSITORY" != "keeldock-platform/platform-ci"', diagnostic)
        self.assertIn("CI_SHA: ${{ github.sha }}", diagnostic)
        self.assertIn('if [[ "$actual_sha" != "$CI_SHA" ]]', diagnostic)
        self.assertIn('git fetch --quiet --no-tags --depth=1 origin "$CI_REF"', diagnostic)
        self.assertNotIn("linux-policy", diagnostic)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "linux-confinement")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_linux_workflow_rejects_skips_masking_extra_execution_and_weak_permissions(self):
        base = LINUX_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  workflow_call:\n", "  workflow_dispatch:\n", 1),
            base.replace("      - name: Run unprivileged source-free checks\n", "      - name: Extra execution\n        run: echo extra\n      - name: Run unprivileged source-free checks\n"),
            base.replace("      - name: Run unprivileged source-free checks\n        run: |", "      - name: Run unprivileged source-free checks\n        if: ${{ false }}\n        run: |"),
            base.replace("      - name: Run unprivileged source-free checks\n", "      - name: Run unprivileged source-free checks\n        continue-on-error: true\n"),
            base.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-latest\n"),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n"),
            base.replace("    timeout-minutes: 10\n", "    timeout-minutes: 0\n"),
            base + "  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n",
            base.replace("{1,200}", "{1,2}", 1),
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "linux-confinement")

    def test_linux_diagnostic_is_a_separate_manual_check(self):
        workflow = LINUX_DIAGNOSTIC_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", "linux-confinement-diagnostic"))
        self.assertEqual(
            workflow.encode("utf-8"),
            policy_linux.LINUX_CONFINEMENT_DIAGNOSTIC_WORKFLOW_TEMPLATE.encode("utf-8"),
        )
        self.assertNotIn("linux-policy", workflow)


class LinuxLaneRegistryTests(unittest.TestCase):
    def test_moved_template_matches_the_exact_workflow_digest(self):
        template = policy_linux.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE
        self.assertEqual(
            hashlib.sha256(template.encode("utf-8")).hexdigest(),
            LINUX_CONFINEMENT_WORKFLOW_SHA256,
        )
        self.assertEqual(template.encode("utf-8"), LINUX_WORKFLOW.read_bytes())
        self.assertEqual(
            hashlib.sha256(LINUX_WORKFLOW.read_bytes()).hexdigest(),
            LINUX_CONFINEMENT_WORKFLOW_SHA256,
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
                "linux-confinement-diagnostic": policy_linux.LINUX_CONFINEMENT_DIAGNOSTIC_WORKFLOW_TEMPLATE,
                "linux-source-admission": policy_linux.LINUX_SOURCE_ADMISSION_WORKFLOW_TEMPLATE,
                "core-linux-quick-return": policy_linux.LINUX_QUICK_RETURN_WORKFLOW_TEMPLATE,
            },
        )
        self.assertEqual(dict(policy_linux.WORKFLOW_SHA256), {})
        self.assertEqual(
            policy_linux.CANDIDATE_WORKFLOWS,
            (
                (".github/workflows/linux-confinement.yml", "linux-confinement", "linux-workflow-too-large"),
                (
                    ".github/workflows/linux-confinement-diagnostic.yml",
                    "linux-confinement-diagnostic",
                    "linux-confinement-diagnostic-workflow-too-large",
                ),
                (
                    ".github/workflows/linux-source-admission.yml",
                    "linux-source-admission",
                    "linux-source-admission-workflow-too-large",
                ),
                (
                    ".github/workflows/core-linux-quick-return.yml",
                    "core-linux-quick-return",
                    "core-linux-quick-return-workflow-too-large",
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
        parts = re.split(r"(?m)^  (linux-source-admission-[a-z-]+):\n", self.text)
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

    def test_synthetic_and_source_dispatch_conditions_and_environment_binding(self):
        self.assertIn("          - synthetic\n          - source", self.text)
        self.assertIn("github.ref == 'refs/heads/main'", self.jobs()["linux-source-admission-settings"])
        source = self.jobs()["linux-source-admission-source-read"]
        self.assertIn("github.ref == 'refs/heads/untrusted'", source)
        self.assertIn("inputs.mode == 'source'", source)
        self.assertIn("inputs.mode == 'synthetic' && github.ref == 'refs/heads/main'", source)
        self.assertIn(MAIN_ENVIRONMENT_LINE, source)
        self.assertIn("REQUESTED_ENVIRONMENT_NAME: ${{ inputs.environment_name }}", source)
        self.assertIn("LINUX_SOURCE_ENVIRONMENT_NAME: ${{ vars.LINUX_SOURCE_ENVIRONMENT_NAME }}", source)
        self.assertIn("LINUX_SOURCE_ENVIRONMENT_ID: ${{ vars.LINUX_SOURCE_ENVIRONMENT_ID }}", source)
        self.assertIn("LINUX_SOURCE_MAIN_BRANCH_POLICY_ID: ${{ vars.LINUX_SOURCE_MAIN_BRANCH_POLICY_ID }}", source)
        self.assertIn("LINUX_SOURCE_UNTRUSTED_BRANCH_POLICY_ID: ${{ vars.LINUX_SOURCE_UNTRUSTED_BRANCH_POLICY_ID }}", source)
        self.assertIn("LINUX_API_FEATURE_GATE_NAMES: api_feature_clippy,api_feature_tests", source)
        self.assertNotIn("pull_request:", self.text)
        self.assertNotIn("workflow_call:", self.text)

    def test_five_jobs_with_least_privilege_and_main_only_best_effort_cache_operations(self):
        jobs = self.jobs()
        self.assertEqual(
            list(jobs),
            [
                "linux-source-admission-settings",
                "linux-source-admission-unit",
                "linux-source-admission-source-read",
                "linux-source-admission-verdict",
                "linux-source-admission-audit",
            ],
        )
        self.assertNotIn("cache-mode:", self.text)
        cache_steps = [
            block for block in re.split(r"(?m)^      - name: ", self.text)
            if "actions/cache/" in block or "linux_source_build.py rust-cache-" in block
        ]
        self.assertEqual(len(cache_steps), 12)
        for block in cache_steps:
            self.assertIn("github.ref == 'refs/heads/main'", block)
            self.assertIn("continue-on-error: true", block)
        for name in ("settings", "source-read", "verdict"):
            body = jobs["linux-source-admission-" + name]
            self.assertIn("      actions: read\n      contents: read\n", body)
        self.assertIn("    permissions: {}\n", jobs["linux-source-admission-unit"])
        self.assertIn("      contents: read\n", jobs["linux-source-admission-verdict"])
        self.assertIn("      actions: read\n      checks: read\n", jobs["linux-source-admission-audit"])
        self.assertEqual(self.text.count("\n      contents: read\n"), 3)
        self.assertEqual(self.text.count("runs-on: ubuntu-24.04"), 5)
        self.assertNotIn("latest", self.text)

    def test_source_reader_secret_is_scoped_to_mint_and_canary_stays_out_of_arguments(self):
        source = self.jobs()["linux-source-admission-source-read"]
        mint = source.split("      - name: Mint scoped source-reader token\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: ${{ inputs.mode == 'source' }}", mint)
        self.assertIn("SOURCE_READER_PRIVATE_KEY: ${{ secrets.SOURCE_READER_PRIVATE_KEY }}", mint)
        self.assertEqual(self.text.count("secrets.SOURCE_READER_PRIVATE_KEY"), 2)
        self.assertIn("actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510", mint)
        self.assertIn("SOURCE_READER_TOKEN: ${{ steps.source-reader-token.outputs.token }}", source)
        self.assertIn("if: ${{ always() && steps.source-reader-token.outputs.token != '' }}", source)
        self.assertIn("linux_source_build.py revoke", source)
        self.assertIn("steps.source-reader-token.outputs.installation-id", source)
        verdict = self.jobs()["linux-source-admission-verdict"]
        verifier_mint = verdict.split("      - name: Mint verifier scoped source-reader token\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("SOURCE_READER_PRIVATE_KEY: ${{ secrets.SOURCE_READER_PRIVATE_KEY }}", verifier_mint)
        self.assertIn("linux_source_build.py mint-verifier-token", verifier_mint)
        for name, body in self.jobs().items():
            if name not in ("linux-source-admission-source-read", "linux-source-admission-verdict"):
                self.assertNotIn("SOURCE_READER_PRIVATE_KEY", body)
        self.assertEqual(self.text.count("KD_CANARY_SECRET: ${{ inputs.mode == 'synthetic'"), 4)
        source = self.jobs()["linux-source-admission-source-read"]
        self.assertEqual(source.count("--preserve-env=KD_CANARY_SECRET"), 3)
        for line in source.splitlines():
            if "sudo" in line:
                self.assertNotIn("$KD_CANARY_SECRET", line)
        self.assertNotIn("KD_CANARY_SECRET", self.jobs()["linux-source-admission-settings"])
        self.assertNotIn("KD_CANARY_SECRET", self.jobs()["linux-source-admission-unit"])

    def test_every_job_that_mints_a_verifier_token_has_both_source_reader_ids_in_job_scope(self):
        found = []
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if "linux_source_build.py mint-verifier-token" not in text:
                continue
            parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\n", text.split("\njobs:\n", 1)[1])
            for index in range(1, len(parts), 2):
                job = parts[index + 1]
                if "linux_source_build.py mint-verifier-token" not in job:
                    continue
                found.append((path.name, parts[index]))
                head = job.split("    steps:\n", 1)[0]
                for name in ("SOURCE_READER_CLIENT_ID", "SOURCE_READER_INSTALLATION_ID"):
                    with self.subTest(workflow=path.name, job=parts[index], variable=name):
                        self.assertIn("      " + name + ": ${{ vars." + name + " }}\n", head)
        self.assertEqual(found, [("linux-source-admission.yml", "linux-source-admission-verdict")])
        template = policy_linux.LINUX_SOURCE_ADMISSION_WORKFLOW_TEMPLATE
        verdict = template.split("\n  linux-source-admission-verdict:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertIn("      SOURCE_READER_CLIENT_ID: ${{ vars.SOURCE_READER_CLIENT_ID }}\n", verdict)
        self.assertIn("      SOURCE_READER_INSTALLATION_ID: ${{ vars.SOURCE_READER_INSTALLATION_ID }}\n", verdict)

    def test_private_source_owner_and_name_come_from_secrets_and_never_from_variables(self):
        self.assertNotIn("vars.LINUX_SOURCE_REPOSITORY", self.text)
        self.assertNotIn("vars.SOURCE_REPOSITORY_OWNER", self.text)
        self.assertNotIn("vars.SOURCE_REPOSITORY_NAME", self.text)
        self.assertEqual(self.text.count("secrets.SOURCE_REPOSITORY_OWNER"), 4)
        self.assertEqual(self.text.count("secrets.SOURCE_REPOSITORY_NAME"), 4)
        jobs = self.jobs()
        for name in ("settings", "source-read", "verdict"):
            body = jobs["linux-source-admission-" + name]
            with self.subTest(job=name):
                self.assertIn("      SOURCE_REPOSITORY_OWNER: ${{ secrets.SOURCE_REPOSITORY_OWNER }}\n", body)
                self.assertIn("      SOURCE_REPOSITORY_NAME: ${{ secrets.SOURCE_REPOSITORY_NAME }}\n", body)
                self.assertIn(ENVIRONMENT_LINE if name == "settings" else MAIN_ENVIRONMENT_LINE, body)
        for name in ("unit", "audit"):
            body = jobs["linux-source-admission-" + name]
            self.assertNotIn("SOURCE_REPOSITORY_OWNER", body)
            self.assertNotIn("SOURCE_REPOSITORY_NAME", body)
        mint = jobs["linux-source-admission-source-read"].split("      - name: Mint scoped source-reader token\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("          owner: ${{ secrets.SOURCE_REPOSITORY_OWNER }}\n", mint)
        self.assertIn("          repositories: ${{ secrets.SOURCE_REPOSITORY_NAME }}\n", mint)
        for line in self.text.splitlines():
            if line.lstrip().startswith("run:") or line.startswith("          "):
                if "secrets.SOURCE_REPOSITORY" in line:
                    self.assertTrue(line.lstrip().startswith(("owner:", "repositories:")), line)
        changed = self.text.replace("secrets.SOURCE_REPOSITORY_OWNER", "vars.LINUX_SOURCE_REPOSITORY_OWNER", 1)
        self.assertNotEqual(changed, self.text)
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(changed, "platform", "linux-source-admission")

    def test_every_job_binds_the_linux_environment_and_the_input_defaults_to_it(self):
        jobs = self.jobs()
        for name in ("settings", "source-read", "verdict", "audit"):
            with self.subTest(job=name):
                body = jobs["linux-source-admission-" + name]
                expected_environment = MAIN_ENVIRONMENT_LINE if name in ("source-read", "verdict") else ENVIRONMENT_LINE
                self.assertEqual(body.count(expected_environment), 1)
                self.assertNotIn("environment_name ||", body)
        self.assertNotIn("environment:", jobs["linux-source-admission-unit"])
        self.assertEqual(self.text.count(ENVIRONMENT_LINE), 2)
        self.assertEqual(self.text.count(MAIN_ENVIRONMENT_LINE), 2)
        self.assertEqual(self.text.count("linux-source-read"), 7)
        self.assertEqual(self.text.count("environment:"), 4)
        self.assertIn("KD_RUST_CACHE_MODE: ${{ github.ref == 'refs/heads/main' &&", self.text)
        self.assertIn("        description: Protected source-read environment\n        required: false\n        type: string\n        default: linux-source-read\n", self.text)
        self.assertNotIn("default: source-read", self.text)
        self.assertIn("REQUESTED_ENVIRONMENT_NAME: ${{ inputs.environment_name }}", self.text)
        self.assertIn('ENVIRONMENT_NAME = "linux-source-read"', (ROOT / "kit/confinement/linux_source_build.py").read_text(encoding="utf-8"))

    def test_synthetic_runs_get_no_environment_and_source_runs_get_the_linux_environment(self):
        expressions = {
            "settings": "${{ inputs.mode == 'source' && 'linux-source-read' || '' }}",
            "source-read": "${{ inputs.mode == 'source' && github.ref == 'refs/heads/main' && 'linux-source-read-main' || inputs.mode == 'source' && 'linux-source-read' || '' }}",
            "verdict": "${{ inputs.mode == 'source' && github.ref == 'refs/heads/main' && 'linux-source-read-main' || inputs.mode == 'source' && 'linux-source-read' || '' }}",
            "audit": "${{ inputs.mode == 'source' && 'linux-source-read' || '' }}",
        }
        for name in ("settings", "source-read", "verdict", "audit"):
            with self.subTest(job=name):
                body = self.jobs()["linux-source-admission-" + name]
                header = body.split("    steps:\n", 1)[0]
                self.assertEqual(re.findall(r"(?m)^    environment: (.*)$", header), [expressions[name]])
                self.assertNotIn("    environment: linux-source-read\n", header)
        self.assertNotIn("environment:", self.jobs()["linux-source-admission-unit"])
        self.assertEqual(
            re.findall(r"(?m)^\s+environment: (.*)$", self.text),
            [expressions[name] for name in ("settings", "source-read", "verdict", "audit")],
        )
        template = policy_linux.LINUX_SOURCE_ADMISSION_WORKFLOW_TEMPLATE
        self.assertEqual(template.count("    environment: " + expressions["settings"] + "\n"), 2)
        self.assertEqual(template.count("    environment: " + expressions["source-read"] + "\n"), 2)
        for line in self.text.splitlines():
            if "secrets.KD_LINUX_LOG_CANARY" in line:
                self.assertIn("inputs.mode == 'synthetic'", line)
        source_read = self.jobs()["linux-source-admission-source-read"]
        mint_marker = "      - name: Mint scoped source-reader token\n"
        self.assertEqual(source_read.count(mint_marker), 1)
        mint_block = source_read.split(mint_marker, 1)[1].split("      - name:", 1)[0]
        self.assertIn("\n        if: ${{ inputs.mode == 'source' }}\n", "\n" + mint_block)

    def test_source_read_steps_follow_the_required_order(self):
        source = self.jobs()["linux-source-admission-source-read"]
        names = re.findall(r"(?m)^      - name: (.*)$", source)
        self.assertEqual(
            names,
            [
                "Fetch exact public control",
                "Repeat preflight in source-read",
                "Record image and fetch pinned Rust and Node toolchains",
                "Harden runner paths before the proof",
                "Boundary self-test before source-reader mint",
                "Mint scoped source-reader token",
                "Verify selected installation identity",
                "Fetch exact source and verify binding, tree, signatures and committed locks",
                "Revoke source-reader token and verify rejection",
                "Derive Rust cache key",
                "Prepare runner-local Rust cache staging",
                "Restore exact Rust build cache",
                "Import validated Rust build cache",
                "Fetch Rust dependencies from the committed lockfiles",
                "Fetch npm tarballs by committed lock integrity",
                "Prepare offline project inputs",
                "Re-run positive controls immediately before the first project command",
                "Run all offline project gates",
                "Merge confinement phase records",
                "Export validated Rust build cache after confined work",
                "Package the Rust build cache",
                "Save the exact Rust build cache",
                "Forced faults must fail closed",
            ],
        )
        self.assertLess(source.index("linux_boundary.py selftest"), source.index("Mint scoped source-reader token"))
        self.assertLess(source.index("Fetch exact source"), source.index("linux_source_build.py revoke"))
        self.assertLess(source.index("linux_source_build.py revoke"), source.index("Fetch npm tarballs"))
        self.assertLess(source.index("Prepare offline project inputs"), source.index("linux_boundary.py recheck"))
        self.assertLess(source.index("linux_boundary.py recheck"), source.index("Run all offline project gates"))
        self.assertIn("sudo -n --preserve-env=WORKER_PATH,CARGO_HOME,RUST_ROOT,NODE_BIN,RUNNER_TEMP", source)
        self.assertIn("--synthetic-standin", source)

    def test_audit_job_runs_always_with_expected_identity_and_no_artifacts(self):
        audit = self.jobs()["linux-source-admission-audit"]
        self.assertIn("if: ${{ always() &&", audit)
        for name in ("settings", "unit", "source-read", "verdict"):
            self.assertIn("      - linux-source-admission-" + name + "\n", audit)
        self.assertIn("CONFINEMENT_AUDIT_EXPECTED: ${{ needs.linux-source-admission-settings.outputs.expected }}", audit)
        self.assertIn("CONFINEMENT_AUDIT_CACHE_KEYS:", audit)
        self.assertIn("needs.linux-source-admission-source-read.outputs.cache_key", audit)
        self.assertIn("needs.linux-source-admission-verdict.outputs.cache_key", audit)
        self.assertIn("linux_source_build.py audit", audit)
        self.assertNotIn("sudo", audit)
        self.assertIn('"artifact_names": ()', (ROOT / "kit/confinement/linux_source_build.py").read_text(encoding="utf-8"))
        self.assertIn('"cache_digest": cache_digest', (ROOT / "kit/confinement/linux_source_build.py").read_text(encoding="utf-8"))
        self.assertNotIn("upload-artifact", self.text)
        self.assertNotIn("download-artifact", self.text)

    def test_verdict_step_is_plain_run_and_the_verdict_job_has_no_composite_step(self):
        source = self.jobs()["linux-source-admission-source-read"]
        verdict = self.jobs()["linux-source-admission-verdict"]
        unit = self.jobs()["linux-source-admission-unit"]
        self.assertIn("python3 -B kit/confinement/test_linux_boundary.py", unit)
        self.assertIn(
            "    outputs:\n      cache_key: ${{ steps.rust-cache-key.outputs.cache_key }}\n", source,
        )
        self.assertIn(
            "    outputs:\n      cache_key: ${{ steps.verifier-rust-cache-key.outputs.cache_key }}\n", verdict,
        )
        self.assertNotIn("verdict_record", verdict)
        self.assertNotIn("needs.linux-source-admission-source-read.outputs", verdict)
        self.assertIn("PRODUCER_RESULT: ${{ needs.linux-source-admission-source-read.result }}", verdict)
        self.assertIn(MAIN_ENVIRONMENT_LINE, verdict)
        self.assertIn("linux_boundary.py selftest", verdict)
        self.assertIn("linux_boundary.py recheck", verdict)
        self.assertIn("linux_boundary.py merge", verdict)
        self.assertIn("--reader-uid \"$(id -u)\" --reader-gid \"$(id -g)\"", verdict)
        self.assertIn("linux_source_build.py verify-handoff", verdict)
        self.assertIn("linux_source_build.py gates", verdict)
        self.assertIn("run: python3 -B kit/confinement/linux_source_build.py verdict", verdict)
        self.assertEqual(verdict.count("      - name:"), 23)
        self.assertEqual(verdict.count("uses: actions/cache/restore@"), 1)
        self.assertEqual(verdict.count("uses: actions/cache/save@"), 1)
        self.assertNotIn("uses: ./", verdict)
        self.assertEqual(verdict.count("--preserve-env=KD_CANARY_SECRET"), 2)
        self.assertNotIn("KD-CONFINEMENT" + "-VERDICT", self.text)
        self.assertNotIn("KD-CONFINEMENT" + "-VERDICT", verdict)

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
            self.text.replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest", 1),
            self.text.replace("      - name: Publish confinement verdict\n", "      - name: Publish confinement verdict\n        uses: ./kit/bootstrap\n", 1),
            self.text.replace("      - name: Fetch exact public control\n", "      - name: Fetch exact public control\n        if: ${{ false }}\n", 1),
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
            "      - name: Publish confinement verdict\n",
            "      - name: Publish confinement verdict\n        uses: ./kit/bootstrap\n",
            1,
        )
        self.assertIn("uses: ./", changed)
        with self.assertRaises(PolicyError):
            validate_workflow_text(changed, "platform", "linux-source-admission")


class LinuxQuickReturnWorkflowTests(unittest.TestCase):
    PINNED_UPLOAD = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
    PINNED_MINT = "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510"

    def setUp(self):
        self.text = QUICK_WORKFLOW.read_text(encoding="utf-8")

    def jobs(self):
        parts = re.split(r"(?m)^  (core-linux-quick-return-[a-z-]+):\n", self.text)
        return {parts[index]: parts[index + 1] for index in range(1, len(parts), 2)}

    def test_template_is_byte_for_byte_the_workflow_and_validates_only_for_the_platform_pool(self):
        template = policy_linux.LINUX_QUICK_RETURN_WORKFLOW_TEMPLATE
        self.assertEqual(template.encode("utf-8"), QUICK_WORKFLOW.read_bytes())
        self.assertTrue(validate_workflow_text(self.text, "platform", "core-linux-quick-return"))
        for pool in ("connect", "workspace", "data"):
            with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                validate_workflow_text(self.text, pool, "core-linux-quick-return")
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(self.text, "platform")
        self.assertIs(policy.WORKFLOW_KIND_LANES["core-linux-quick-return"], policy_linux)
        self.assertIn(
            (".github/workflows/core-linux-quick-return.yml", "core-linux-quick-return",
             "core-linux-quick-return-workflow-too-large"),
            policy.LANE_CANDIDATE_WORKFLOWS,
        )

    def test_workflow_is_dispatch_only_and_runs_only_on_the_untrusted_ref(self):
        self.assertIn("on:\n  workflow_dispatch:\n    inputs:\n", self.text)
        for forbidden in ("pull_request", "workflow_call", "workflow_run", "push:", "schedule:", "refs/heads/main"):
            self.assertNotIn(forbidden, self.text)
        jobs = self.jobs()
        self.assertEqual(
            list(jobs),
            [
                "core-linux-quick-return-settings",
                "core-linux-quick-return-unit",
                "core-linux-quick-return-producer",
                "core-linux-quick-return-audit",
            ],
        )
        for name in ("settings", "producer", "audit"):
            header = jobs["core-linux-quick-return-" + name].split("    runs-on:", 1)[0]
            self.assertIn("github.ref == 'refs/heads/untrusted'", header)
        self.assertEqual(self.text.count('[[ "$CI_REF" == "refs/heads/untrusted" ]]'), 3)
        self.assertEqual(self.text.count("runs-on: ubuntu-24.04"), 4)
        self.assertNotIn("cache-mode:", self.text)
        self.assertNotIn("actions/cache/", self.text)
        self.assertNotIn("latest", self.text)
        self.assertIn("    permissions: {}\n", jobs["core-linux-quick-return-unit"])
        for name in ("settings", "producer"):
            body = jobs["core-linux-quick-return-" + name]
            self.assertIn("    permissions:\n      actions: read\n      contents: read\n", body)
            self.assertIn("    environment: linux-source-read\n", body)
        self.assertNotIn("environment:", jobs["core-linux-quick-return-unit"])

    def test_quick_tier_has_no_verdict_job_and_never_accepts_a_run(self):
        lowered = self.text.lower()
        for forbidden in ("verdict", "run_accepted", "verify-handoff", "confinement_public_audit",
                          "confinement_verdict"):
            self.assertNotIn(forbidden, lowered)
        self.assertNotIn("KD-CONFINEMENT" + "-VERDICT", self.text)
        for name in self.jobs():
            self.assertFalse(name.endswith("-verdict"), name)
        self.assertEqual(self.text.count("linux_source_build.py audit"), 1)
        module = QUICK_MODULE.read_text(encoding="utf-8")
        for forbidden in ("run_accepted", "confinement_verdict", "import linux_source_build", "KD-CONFINEMENT"):
            self.assertNotIn(forbidden, module)
        self.assertIn("tier=quick admission=never", module)
        self.assertNotIn("admission=accepted", module)
        self.assertNotIn("quick", policy_linux.LINUX_SOURCE_ADMISSION_WORKFLOW_TEMPLATE)
        for path in (ROOT / "kit/confinement").glob("linux_*.py"):
            if path.name != "linux_quick_return.py":
                self.assertNotIn("KD-LINUX-QUICK", path.read_text(encoding="utf-8"), path.name)

    def test_quick_tier_uses_its_own_binding_namespace_and_the_shared_reader_settings(self):
        self.assertNotIn("vars.LINUX_SOURCE_", self.text)
        self.assertNotIn("inputs.environment_name", self.text)
        mapped = (
            ("LINUX_SOURCE_ALLOWED_SHA", "LINUX_QUICK_ALLOWED_SHA"),
            ("LINUX_SOURCE_ALLOWED_BASE_SHA", "LINUX_QUICK_ALLOWED_BASE_SHA"),
            ("LINUX_SOURCE_ALLOWED_BASE_BRANCH", "LINUX_QUICK_ALLOWED_BASE_BRANCH"),
            ("LINUX_SOURCE_ALLOWED_FINGERPRINT", "LINUX_QUICK_ALLOWED_FINGERPRINT"),
            ("LINUX_SOURCE_ALLOWED_CONTROL_SHA", "LINUX_QUICK_ALLOWED_CONTROL_SHA"),
            ("LINUX_SOURCE_ENVIRONMENT_NAME", "LINUX_QUICK_ENVIRONMENT_NAME"),
            ("LINUX_SOURCE_ENVIRONMENT_ID", "LINUX_QUICK_ENVIRONMENT_ID"),
            ("LINUX_SOURCE_MAIN_BRANCH_POLICY_ID", "LINUX_QUICK_MAIN_BRANCH_POLICY_ID"),
            ("LINUX_SOURCE_UNTRUSTED_BRANCH_POLICY_ID", "LINUX_QUICK_UNTRUSTED_BRANCH_POLICY_ID"),
            ("KD_QUICK_ALLOWED_REQUEST_ID", "LINUX_QUICK_ALLOWED_REQUEST_ID"),
            ("KD_QUICK_ALLOWED_RECIPIENT_FINGERPRINT", "LINUX_QUICK_ALLOWED_RECIPIENT_FINGERPRINT"),
            ("KD_QUICK_ALLOWED_NONCE", "LINUX_QUICK_ALLOWED_NONCE"),
            ("KD_QUICK_ALLOWED_EXPIRY", "LINUX_QUICK_ALLOWED_EXPIRY"),
        )
        for name in ("settings", "producer"):
            body = self.jobs()["core-linux-quick-return-" + name]
            for process_name, variable in mapped:
                with self.subTest(job=name, variable=variable):
                    self.assertIn("      " + process_name + ": ${{ vars." + variable + " }}\n", body)
            self.assertIn("      KD_LINUX_TIER: quick\n", body)
            self.assertIn("      CI_MODE: source\n", body)
            self.assertIn("      REQUESTED_ENVIRONMENT_NAME: linux-source-read\n", body)
            self.assertIn("      LINUX_API_FEATURE_GATE_NAMES: api_feature_clippy,api_feature_tests\n", body)
            self.assertIn("      SOURCE_REPOSITORY_OWNER: ${{ secrets.SOURCE_REPOSITORY_OWNER }}\n", body)
            self.assertIn("      SOURCE_REPOSITORY_NAME: ${{ secrets.SOURCE_REPOSITORY_NAME }}\n", body)
        self.assertEqual(set(re.findall(r"vars\.([A-Z0-9_]+)", self.text)), {
            "SOURCE_REPOSITORY_ID", "SOURCE_READER_INSTALLATION_ID", "SOURCE_READER_CLIENT_ID",
            *(variable for unused, variable in mapped),
        })

    def test_settings_job_snapshots_the_cache_and_exports_the_expected_quick_run(self):
        settings = self.jobs()["core-linux-quick-return-settings"]
        self.assertIn("    outputs:\n      expected: ${{ steps.snapshot.outputs.expected }}\n", settings)
        self.assertIn("      cache_digest: ${{ steps.snapshot.outputs.cache_digest }}\n", settings)
        self.assertEqual(
            re.findall(r"(?m)^      - name: (.*)$", settings),
            [
                "Fetch exact public control",
                "Validate quick request and binding",
                "Snapshot cache inventory and validate preflight",
            ],
        )
        snapshot = settings.split("      - name: Snapshot cache inventory and validate preflight\n", 1)[1]
        self.assertIn("        id: snapshot\n", snapshot)
        self.assertIn("          GITHUB_TOKEN: ${{ github.token }}\n", snapshot)
        self.assertIn("        run: python3 -B kit/confinement/linux_source_build.py snapshot\n", snapshot)
        self.assertNotIn("linux_source_build.py preflight", settings)

    def test_audit_job_is_source_free_and_audits_the_one_artifact_without_a_verdict(self):
        audit = self.jobs()["core-linux-quick-return-audit"]
        self.assertIn(
            "    needs:\n      - core-linux-quick-return-settings\n      - core-linux-quick-return-unit\n"
            "      - core-linux-quick-return-producer\n",
            audit,
        )
        self.assertIn(
            "    if: ${{ always() && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/untrusted' }}\n",
            audit,
        )
        self.assertIn("    environment: linux-source-read\n", audit)
        self.assertIn("    permissions:\n      actions: read\n      checks: read\n", audit)
        self.assertNotIn("contents:", audit)
        self.assertIn("      KD_LINUX_TIER: quick\n", audit)
        self.assertIn(
            "      CONFINEMENT_AUDIT_EXPECTED: ${{ needs.core-linux-quick-return-settings.outputs.expected }}\n",
            audit,
        )
        self.assertEqual(
            re.findall(r"(?m)^      - name: (.*)$", audit),
            ["Fetch exact public control", "Audit logs, artifact, cache metadata and quick return"],
        )
        self.assertIn("          KD_LINUX_LOG_CANARY: ${{ secrets.KD_LINUX_LOG_CANARY }}\n", audit)
        self.assertIn("        run: python3 -B kit/confinement/linux_source_build.py audit\n", audit)
        for forbidden in ("uses:", "SOURCE_READER", "SOURCE_REPOSITORY", "sudo", "linux_quick_return.py", "vars."):
            self.assertNotIn(forbidden, audit)

    def test_secrets_stay_out_of_run_blocks_and_arguments(self):
        self.assertEqual(set(re.findall(r"secrets\.([A-Z_]+)", self.text)), {
            "SOURCE_REPOSITORY_OWNER", "SOURCE_REPOSITORY_NAME", "SOURCE_READER_PRIVATE_KEY",
            "KD_LINUX_LOG_CANARY",
        })
        self.assertNotIn("RUST_CACHE_", self.text)
        in_run = False
        for line in self.text.splitlines():
            if re.match(r"^        run: ", line):
                self.assertNotIn("secrets.", line)
                in_run = line.rstrip().endswith("|")
            elif in_run and line.startswith("          "):
                self.assertNotIn("secrets.", line)
            else:
                in_run = False
            if "sudo" in line:
                self.assertNotIn("$KD_CANARY_SECRET", line)
                self.assertNotIn("SOURCE_READER_PRIVATE_KEY", line)
        producer = self.jobs()["core-linux-quick-return-producer"]
        self.assertEqual(producer.count("--preserve-env=KD_CANARY_SECRET"), 2)
        self.assertEqual(self.text.count("KD_CANARY_SECRET: ${{ secrets.KD_LINUX_LOG_CANARY }}"), 2)
        self.assertNotIn("KD_CANARY_SECRET", self.jobs()["core-linux-quick-return-settings"])
        self.assertNotIn("SOURCE_READER_PRIVATE_KEY", self.jobs()["core-linux-quick-return-settings"])
        self.assertNotIn("SOURCE_READER_PRIVATE_KEY", self.jobs()["core-linux-quick-return-unit"])
        mint = producer.split("      - name: Mint scoped source-reader token\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("uses: " + self.PINNED_MINT + "\n", mint)
        self.assertIn("          owner: ${{ secrets.SOURCE_REPOSITORY_OWNER }}\n", mint)
        self.assertIn("          repositories: ${{ secrets.SOURCE_REPOSITORY_NAME }}\n", mint)

    def test_every_action_is_pinned_by_full_sha_and_only_two_actions_are_used(self):
        uses = re.findall(r"(?m)^\s+uses: (\S+)", self.text)
        self.assertEqual(len(uses), 2)
        for value in uses:
            self.assertRegex(value, r"^(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@[0-9a-f]{40}$")
        self.assertEqual(sorted(uses), sorted((self.PINNED_UPLOAD, self.PINNED_MINT)))
        self.assertNotIn("download-artifact", self.text)
        self.assertNotIn("actions/cache/", self.text)
        self.assertNotIn("RUST_CACHE_", self.text)
        self.assertNotIn("actions/checkout", self.text)

    def test_producer_steps_follow_the_required_order_and_encrypt_after_the_gates(self):
        producer = self.jobs()["core-linux-quick-return-producer"]
        names = re.findall(r"(?m)^      - name: (.*)$", producer)
        self.assertEqual(
            names,
            [
                "Fetch exact public control",
                "Repeat quick preflight before source read",
                "Record image and fetch pinned Rust and Node toolchains",
                "Harden runner paths before the proof",
                "Boundary self-test before source-reader mint",
                "Mint scoped source-reader token",
                "Verify selected installation identity",
                "Fetch exact source and verify binding, tree, signatures and committed locks",
                "Revoke source-reader token and verify rejection",
                "Fetch Rust dependencies from the committed lockfiles",
                "Fetch npm tarballs by committed lock integrity",
                "Prepare offline project inputs",
                "Re-run positive controls immediately before the first project command",
                "Run all offline project gates",
                "Merge confinement phase records",
                "Encrypt bounded quick return",
                "Upload the single encrypted member",
                "Record quick return counts",
                "Remove staged ciphertext",
            ],
        )
        self.assertLess(producer.index("linux_boundary.py selftest"), producer.index("Mint scoped source-reader token"))
        self.assertLess(producer.index("Fetch exact source"), producer.index("linux_source_build.py revoke"))
        self.assertLess(producer.index("linux_source_build.py revoke"), producer.index("Fetch npm tarballs"))
        self.assertLess(producer.index("linux_boundary.py recheck"), producer.index("Run all offline project gates"))
        self.assertLess(producer.index("linux_source_build.py gates"), producer.index("linux_quick_return.py encrypt"))
        self.assertLess(producer.index("linux_quick_return.py encrypt"), producer.index("Upload the single encrypted member"))
        self.assertIn("if: ${{ always() && steps.gates.outcome != 'skipped' }}", producer)
        self.assertIn("if: ${{ always() && steps.encrypt.outcome == 'success' }}", producer)
        self.assertIn("if: ${{ always() && steps.uploader.outcome == 'success' }}", producer)
        self.assertIn("if: ${{ always() && steps.source-reader-token.outputs.token != '' }}", producer)
        self.assertNotIn("continue-on-error", self.text)
        self.assertNotIn("--synthetic-standin", self.text)
        encrypt = producer.split("      - name: Encrypt bounded quick return\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("        run: python3 -B core-ci/linux_quick_return.py encrypt", encrypt)
        self.assertNotIn("sudo", encrypt)
        self.assertIn('linux_quick_return.py encrypt --reader-uid "$(id -u)" --reader-gid "$(id -g)"', encrypt)
        self.assertNotIn("secrets.", encrypt)
        self.assertNotIn("KD_CANARY_SECRET", encrypt)

    def test_the_encrypted_upload_directory_is_uploaded_for_one_day_without_overwrite_or_compression(self):
        self.assertEqual(self.text.count("uses: " + self.PINNED_UPLOAD + " " + "\x23" + " v7.0.2\n"), 1)
        upload = self.text.split("      - name: Upload the single encrypted member\n", 1)[1].split("      - name:", 1)[0]
        for line in (
            "          name: linux-quick-${{ inputs.request_id }}\n",
            "          path: ${{ runner.temp }}/kd-quick-upload/\n",
            "          archive: true\n",
            "          retention-days: 1\n",
            "          compression-level: 0\n",
            "          overwrite: false\n",
            "          include-hidden-files: false\n",
            "          if-no-files-found: error\n",
        ):
            self.assertIn(line, upload)
        self.assertEqual(self.text.count("retention-days:"), 1)
        self.assertEqual(self.text.count("upload-artifact"), 1)

    def test_public_output_is_only_the_fixed_quick_line_and_counts(self):
        record = self.text.split("      - name: Record quick return counts\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn('line="$(python3 -B core-ci/linux_quick_return.py record)"', record)
        self.assertEqual(record.count("printf '%s\\n' \"$line\""), 2)
        self.assertIn('>> "$GITHUB_STEP_SUMMARY"', record)
        module = QUICK_MODULE.read_text(encoding="utf-8")
        self.assertIn('" tier=quick admission=never"', module)
        self.assertIn('" gates-selected="', module)
        self.assertIn('" status=encrypted"', module)

    def test_workflow_uses_only_kit_scripts_that_are_in_the_public_allowlist(self):
        scripts = sorted(set(re.findall(r"(?:kit/[a-z_/]+|core-ci/[a-z_]+)\.py", self.text)))
        self.assertIn("core-ci/linux_quick_return.py", scripts)
        self.assertIn("core-ci/test_linux_quick_return.py", scripts)
        self.assertIn("core-ci/test_separation.py", scripts)
        for script in scripts:
            with self.subTest(script=script):
                self.assertIn(script, PLATFORM_FILES)
                self.assertTrue((ROOT / script).is_file())
        unit = self.jobs()["core-linux-quick-return-unit"]
        self.assertIn("python3 -B kit/", unit)
        for command in (
            "python3 -B kit/bootstrap/test_policy_linux.py",
            "python3 -B kit/confinement/test_linux_source_build.py",
            "python3 -B core-ci/test_linux_quick_return.py",
            "python3 -B core-ci/test_separation.py",
        ):
            self.assertIn(command, unit)

    def test_mutations_of_the_quick_workflow_are_refused_as_template_mismatches(self):
        mutations = (
            self.text.replace("refs/heads/untrusted", "refs/heads/main", 1),
            self.text.replace("retention-days: 1", "retention-days: 90", 1),
            self.text.replace("overwrite: false", "overwrite: true", 1),
            self.text + "\n",
            self.text.replace("    permissions: {}\n", "    permissions: write-all\n", 1),
            self.text.replace("      - name: Remove staged ciphertext\n", "      - name: Publish confinement verdict\n        run: echo verdict\n      - name: Remove staged ciphertext\n", 1),
            self.text.replace("vars.LINUX_QUICK_ALLOWED_SHA", "vars.LINUX_SOURCE_ALLOWED_SHA", 1),
            self.text.replace("    environment: linux-source-read\n", "", 1),
            self.text.replace("workflow_dispatch:\n", "workflow_dispatch:\n  push:\n", 1),
            self.text + "  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(index=index):
                self.assertNotEqual(changed, self.text)
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(changed, "platform", "core-linux-quick-return")


if __name__ == "__main__":
    unittest.main(verbosity=2)
