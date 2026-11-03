import hashlib
import re
import unittest
from pathlib import Path

import policy
import policy_handoff
from policy import PolicyError, validate_workflow_text
from public_tree import PLATFORM_FILES, scan_tree


__all__ = [
    "HandoffWorkflowPolicyTests", "HandoffLaneRegistryTests", "WindowsSourceWorkflowTests",
    "HandoffLanePublicTreeTests",
]

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
    "kit/handoff/source_free.py",
    "kit/handoff/test_source_free.py",
)
WORKFLOW_PATHS = {
    "windows-handoff-synthetic": ".github/workflows/windows-handoff-synthetic.yml",
    "windows-source-admission": ".github/workflows/windows-source-admission.yml",
    "lane-h-windows-receiver": ".github/workflows/lane-h-windows-receiver.yml",
    "lane-h-linux-fetch-encrypt": ".github/workflows/lane-h-linux-fetch-encrypt.yml",
    "lane-h-capsule-attester": ".github/workflows/lane-h-capsule-attester.yml",
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


WINDOWS_ADMISSION_PATH = ROOT / ".github/workflows/windows-source-admission.yml"
WINDOWS_RECEIVER_PATH = ROOT / ".github/workflows/lane-h-windows-receiver.yml"
LINUX_FETCH_PATH = ROOT / ".github/workflows/lane-h-linux-fetch-encrypt.yml"
CAPSULE_ATTESTER_PATH = ROOT / ".github/workflows/lane-h-capsule-attester.yml"
SOURCE_ADMISSION_PATHS = (
    WINDOWS_ADMISSION_PATH, WINDOWS_RECEIVER_PATH, LINUX_FETCH_PATH, CAPSULE_ATTESTER_PATH,
)
ADMISSION_JOB_IDS = (
    "settings", "windows-producer", "windows-verifier", "linux-fetch-encrypt",
    "capsule-attester", "verify-role-evidence", "audit",
)
ACTION_USE_PATTERN = re.compile(
    r"^\s*uses:\s+(?:\./\.github/workflows/[a-z0-9-]+\.yml"
    r"|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[a-f0-9]{40}\s+" + chr(35) + r"\s+v[0-9]+\.[0-9]+\.[0-9]+)$"
)
SOURCE_READ_ENVIRONMENT = "environment: ${{ inputs.mode == 'source' && 'linux-source-read' || '' }}"
WINDOWS_ENVIRONMENT = "environment: ${{ inputs.mode == 'source' && 'windows-source-exec' || '' }}"


def read_ascii(path):
    return path.read_text(encoding="ascii")


def job_ids(text):
    return re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\n", text.split("\njobs:\n", 1)[1])


def job_block(text, job_id):
    matched = re.search(
        r"(?ms)^  " + re.escape(job_id) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text,
    )
    return None if matched is None else matched.group(1)


class WindowsSourceWorkflowTests(unittest.TestCase):
    def test_windows_workflows_reference_no_source_reader_or_source_repository_secret(self):
        for path in (WINDOWS_ADMISSION_PATH, WINDOWS_RECEIVER_PATH):
            text = read_ascii(path)
            with self.subTest(path=path.name):
                self.assertNotRegex(text, r"secrets\.SOURCE_(READER|REPOSITORY)_")
                for name in (
                    "SOURCE_READER_PRIVATE_KEY", "SOURCE_REPOSITORY_OWNER", "SOURCE_REPOSITORY_NAME",
                    "linux-source-read", "KD_LINUX_LOG_CANARY", "create-github-app-token",
                    "secrets: inherit",
                ):
                    self.assertNotIn(name, text)
                self.assertLessEqual(
                    set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text)), {"KD_WINDOWS_LOG_CANARY"},
                )

    def test_the_source_secrets_exist_only_in_the_linux_fetch_job_and_its_environment(self):
        fetch = read_ascii(LINUX_FETCH_PATH)
        for name in ("SOURCE_READER_PRIVATE_KEY", "SOURCE_REPOSITORY_OWNER", "SOURCE_REPOSITORY_NAME"):
            self.assertIn("secrets." + name, fetch)
        self.assertEqual(fetch.count(SOURCE_READ_ENVIRONMENT), 1)
        self.assertEqual(fetch.count("environment:"), 1)
        self.assertNotIn("KD_WINDOWS_LOG_CANARY", fetch)
        attester = read_ascii(CAPSULE_ATTESTER_PATH)
        self.assertNotIn("secrets.", attester)
        self.assertNotIn("environment:", attester)
        self.assertNotIn("vars.", attester)
        admission = read_ascii(WINDOWS_ADMISSION_PATH)
        self.assertEqual(admission.count("environment:"), 1)
        self.assertEqual(admission.count(WINDOWS_ENVIRONMENT), 1)
        self.assertIn("windows-source-exec", admission)

    def test_the_settings_job_never_holds_the_source_identity_and_the_fetch_job_rebinds_it(self):
        settings = job_block(read_ascii(WINDOWS_ADMISSION_PATH), "settings")
        for name in (
            "SOURCE_REPOSITORY_ID", "SOURCE_REPOSITORY_OWNER", "SOURCE_REPOSITORY_NAME",
            "SOURCE_READER_INSTALLATION_ID", "SOURCE_READER_CLIENT_ID", "SOURCE_READER_PRIVATE_KEY",
            "SOURCE_READER_TOKEN", "vars.SOURCE_", "secrets.", "environment:", "source-read",
        ):
            with self.subTest(name=name):
                self.assertNotIn(name, settings)
        self.assertEqual(
            set(re.findall(r"vars\.([A-Z0-9_]+)", settings)),
            {
                "WINDOWS_SOURCE_ENVIRONMENT_NAME", "WINDOWS_SOURCE_ALLOWED_SHA",
                "WINDOWS_SOURCE_ALLOWED_BASE_SHA", "WINDOWS_SOURCE_ALLOWED_BASE_BRANCH",
                "WINDOWS_SOURCE_ALLOWED_FINGERPRINT", "WINDOWS_SOURCE_ALLOWED_CONTROL_SHA",
                "WINDOWS_SOURCE_ACCEPTED_NODE_LOCK_SHA256", "WINDOWS_SOURCE_ACCEPTED_MANIFEST_SHA256",
                "WINDOWS_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON",
            },
        )
        fetch = read_ascii(LINUX_FETCH_PATH)
        for name in (
            "SOURCE_REPOSITORY_ID: ${{ vars.SOURCE_REPOSITORY_ID }}",
            "SOURCE_REPOSITORY_OWNER: ${{ secrets.SOURCE_REPOSITORY_OWNER }}",
            "SOURCE_REPOSITORY_NAME: ${{ secrets.SOURCE_REPOSITORY_NAME }}",
            "SOURCE_READER_INSTALLATION_ID: ${{ vars.SOURCE_READER_INSTALLATION_ID }}",
            "SOURCE_READER_CLIENT_ID: ${{ vars.SOURCE_READER_CLIENT_ID }}",
        ):
            with self.subTest(name=name):
                self.assertEqual(fetch.count("      " + name + "\n"), 1)
        preflight = fetch.index("        run: python3 -B kit/confinement/linux_source_build.py windows-preflight\n")
        self.assertLess(fetch.index(SOURCE_READ_ENVIRONMENT), preflight)
        self.assertLess(preflight, fetch.index("      - name: Mint scoped source-reader token\n"))

    def test_top_level_permissions_are_empty_and_job_permissions_stay_least_privilege(self):
        for path in SOURCE_ADMISSION_PATHS:
            text = read_ascii(path)
            with self.subTest(path=path.name):
                self.assertEqual(text.count("\npermissions: {}\n"), 1)
                self.assertLess(text.index("\npermissions: {}\n"), text.index("\njobs:\n"))
                self.assertEqual(len(re.findall(r"(?m)^permissions:", text)), 1)
                self.assertLessEqual(
                    set(re.findall(r"(?m)^\s+([a-z-]+): write$", text)), {"id-token", "attestations"},
                )
                for widened in ("write-all", "contents: write", "actions: write", "checks: write", "packages:"):
                    self.assertNotIn(widened, text)

    def test_every_action_is_pinned_and_every_workflow_call_is_local(self):
        for path in SOURCE_ADMISSION_PATHS:
            lines = [line for line in read_ascii(path).splitlines() if re.match(r"\s*uses:", line)]
            self.assertTrue(lines)
            for line in lines:
                with self.subTest(path=path.name, line=line):
                    self.assertRegex(line, ACTION_USE_PATTERN)

    def test_no_pull_request_trigger_matrix_dynamic_call_or_masked_failure(self):
        for path in SOURCE_ADMISSION_PATHS:
            text = read_ascii(path)
            with self.subTest(path=path.name):
                for forbidden in ("pull_request", "strategy:", "matrix:", "workflow_run:", "-latest"):
                    self.assertNotIn(forbidden, text)
                self.assertIsNone(re.search(r"(?m)^\s*continue-on-error\s*:", text))
        admission = read_ascii(WINDOWS_ADMISSION_PATH)
        self.assertIn("\non:\n  workflow_dispatch:\n    inputs:\n", admission)
        self.assertEqual(admission.count("workflow_dispatch:"), 1)

    def test_the_caller_has_exactly_the_seven_jobs_in_the_designed_dependency_shape(self):
        text = read_ascii(WINDOWS_ADMISSION_PATH)
        self.assertEqual(tuple(job_ids(text)), ADMISSION_JOB_IDS)
        settings = job_block(text, "settings")
        self.assertNotIn("needs:", settings)
        self.assertNotIn("environment:", settings)
        self.assertIn("runs-on: ubuntu-24.04", settings)
        self.assertIn("KD_SOURCE_PREFIX: WINDOWS_SOURCE", settings)
        for job_id, role in (("windows-producer", "producer"), ("windows-verifier", "verifier")):
            block = job_block(text, job_id)
            with self.subTest(job=job_id):
                self.assertIn("    needs:\n      - settings\n", block)
                self.assertIn("uses: ./.github/workflows/lane-h-windows-receiver.yml\n", block)
                self.assertIn("      profile: candidate\n", block)
                self.assertIn("      role: " + role + "\n", block)
                self.assertNotIn("secrets:", block)
        fetch = job_block(text, "linux-fetch-encrypt")
        self.assertIn("    needs:\n      - settings\n    if:", fetch)
        self.assertIn("uses: ./.github/workflows/lane-h-linux-fetch-encrypt.yml\n", fetch)
        attester = job_block(text, "capsule-attester")
        self.assertIn("    needs:\n      - settings\n      - linux-fetch-encrypt\n", attester)
        self.assertIn("uses: ./.github/workflows/lane-h-capsule-attester.yml\n", attester)
        for block in (fetch, attester):
            self.assertIn("      profile: candidate\n", block)
        evidence = job_block(text, "verify-role-evidence")
        self.assertIn(
            "    needs:\n      - settings\n      - windows-producer\n      - windows-verifier\n"
            "      - linux-fetch-encrypt\n      - capsule-attester\n", evidence,
        )
        audit = job_block(text, "audit")
        self.assertIn(
            "    needs:\n      - settings\n      - windows-producer\n      - windows-verifier\n"
            "      - linux-fetch-encrypt\n      - capsule-attester\n      - verify-role-evidence\n", audit,
        )
        for block in (evidence, audit):
            self.assertIn("if: ${{ always() && ", block)

    def test_modes_run_on_their_own_refs_and_the_run_title_carries_the_bound_commit(self):
        text = read_ascii(WINDOWS_ADMISSION_PATH)
        self.assertIn(
            "run-name: Windows admission ${{ inputs.mode }} ${{ inputs.mode == 'source' && inputs.source_sha || 'synthetic' }}\n",
            text,
        )
        self.assertIn("        options:\n          - synthetic\n          - source\n        default: synthetic\n", text)
        self.assertIn("      environment_name:\n        description: Protected environment the source fetch job runs in\n        required: false\n        type: string\npermissions: {}\n", text)
        self.assertNotIn("default: windows-source-exec", text)
        gate = (
            "((inputs.mode == 'synthetic' && github.ref == 'refs/heads/main') || "
            "(inputs.mode == 'source' && github.ref == 'refs/heads/untrusted'))"
        )
        for job_id in ("settings", "windows-producer", "windows-verifier", "linux-fetch-encrypt", "capsule-attester"):
            self.assertIn(gate, job_block(text, job_id))
        for path in (LINUX_FETCH_PATH, CAPSULE_ATTESTER_PATH):
            role_text = read_ascii(path)
            self.assertIn("inputs.profile == 'candidate'", role_text)
            self.assertIn(
                "((inputs.mode == 'synthetic' && github.ref == 'refs/heads/main') || "
                "(inputs.mode == 'source' && github.ref == 'refs/heads/untrusted'))", role_text,
            )

    def test_the_linux_fetch_job_revokes_the_token_for_real_before_any_capsule_is_built(self):
        text = read_ascii(LINUX_FETCH_PATH)
        mint = text.index("      - name: Mint scoped source-reader token\n")
        checkout = text.index("      - name: Fetch exact source and verify binding")
        revoke = text.index("      - name: handoff-revoke-source-token-v1\n")
        verify = text.index("      - name: handoff-verify-token-rejection-v1\n")
        capsule = text.index("      - name: Build the two receiver-bound source capsules\n")
        self.assertLess(mint, checkout)
        self.assertLess(checkout, revoke)
        self.assertLess(revoke, verify)
        self.assertLess(verify, capsule)
        self.assertEqual(text.count("handoff-revocation=confirmed"), 1)
        self.assertGreater(text.index("handoff-revocation=confirmed"), verify)
        self.assertEqual(text.count("linux_source_build.py revoke"), 1)
        self.assertIn("skip-token-revoke: true", text)
        self.assertIn("if: ${{ always() && (inputs.mode == 'synthetic' || steps.source-reader-token.outputs.token != '') }}", text)

    def test_the_fetch_job_runs_the_windows_prefix_commands_and_seals_with_the_shared_capsule_cli(self):
        text = read_ascii(LINUX_FETCH_PATH)
        self.assertIn("linux_source_build.py windows-preflight", text)
        self.assertNotIn("linux_source_build.py preflight", text)
        self.assertIn('"$REQUESTED_ENVIRONMENT_NAME" == "linux-source-read"', text)
        self.assertEqual(text.count("source_capsule.py seal "), 1)
        self.assertNotIn("source_capsule.py build", text)
        for flag in ("--repository", "--source-sha", "--source-repository-id", "--bundle", "--key-record", "--output", "--summary"):
            self.assertIn(" " + flag + " ", text)
        self.assertIn("git -c core.hooksPath=/dev/null -C \"$repository\" bundle create \"$bundle\" refs/heads/kd-source", text)
        self.assertIn("-le 268435448", text)
        self.assertIn("KD_SOURCE_PREFIX: WINDOWS_SOURCE", text)
        for key in ("source_sha", "tree_id", "lock_sha256", "manifest_sha256"):
            self.assertIn(key + "=", text)
        capsule = text.index("      - name: Build the two receiver-bound source capsules\n")
        subject = text.index("      - name: Create the linux-fetch-encrypt role statement\n")
        self.assertLess(capsule, subject)
        settings = job_block(read_ascii(WINDOWS_ADMISSION_PATH), "settings")
        self.assertIn("linux_source_build.py windows-snapshot", settings)

    def test_the_receiver_workflow_has_one_job_and_matches_the_caller_inputs(self):
        receiver = read_ascii(WINDOWS_RECEIVER_PATH)
        self.assertEqual(job_ids(receiver), ["windows-candidate"])
        for name in ("profile", "role", "mode", "source_sha"):
            self.assertIn("      " + name + ":\n        required: ", receiver)
        caller = read_ascii(WINDOWS_ADMISSION_PATH)
        for job_id in ("windows-producer", "windows-verifier"):
            block = job_block(caller, job_id)
            for name in re.findall(r"(?m)^      ([a-z_]+): ", block.split("    with:\n", 1)[1].split("    permissions:", 1)[0]):
                self.assertIn("      " + name + ":\n", receiver.split("\njobs:\n", 1)[0])

    def test_the_receivers_get_a_synthetic_canary_that_differs_from_the_one_the_audit_scans_for(self):
        receiver = read_ascii(WINDOWS_RECEIVER_PATH)
        admission = read_ascii(WINDOWS_ADMISSION_PATH)
        pattern = re.compile(r"KD_WINDOWS_LOG_CANARY: \$\{\{ inputs.mode == 'synthetic' && '([0-9a-f]+)' \|\| secrets.KD_WINDOWS_LOG_CANARY \}\}")
        standin = pattern.findall(receiver)
        audited = pattern.findall(admission)
        self.assertEqual((len(standin), len(audited)), (1, 1))
        self.assertNotEqual(standin[0], audited[0])
        self.assertTrue(64 <= len(standin[0]) <= 256 and len(standin[0]) % 2 == 0)
        self.assertGreaterEqual(len(set(standin[0])), 12)
        self.assertNotIn(audited[0], receiver)
        self.assertNotIn(standin[0], admission)

    def test_the_fixed_pins_are_enforced_in_a_non_observing_check_before_release_and_at_the_end(self):
        attester = read_ascii(CAPSULE_ATTESTER_PATH)
        gates = [line for line in attester.splitlines() if "role_signer.py gate-transition --gate B" in line]
        self.assertEqual(len(gates), 2)
        self.assertEqual(sum(1 for line in gates if " --observe" in line), 1)
        plain = [line for line in gates if " --observe" not in line][0]
        self.assertIn('--linux-logs "$evidence/linux-logs.json"', plain)
        self.assertLess(attester.index(gates[1]), attester.index("      - name: Sign only the capsule-attester role statement"))
        evidence = job_block(read_ascii(WINDOWS_ADMISSION_PATH), "verify-role-evidence")
        finals = [line for line in evidence.splitlines() if "role_signer.py verify-snapshot" in line and " --observe" not in line]
        self.assertEqual(len(finals), 1)
        self.assertIn('--linux-logs "$RUNNER_TEMP/role-signer-evidence/linux-logs.json"', finals[0])

    def test_job_level_env_and_names_use_only_contexts_available_there(self):
        for path in SOURCE_ADMISSION_PATHS:
            text = read_ascii(path)
            with self.subTest(path=path.name):
                for block in re.findall(r"(?m)^    env:\n((?:      [^\n]*\n)+)", text):
                    for context in ("runner.", "steps.", "job.", "secrets."):
                        if context == "secrets." and path in (LINUX_FETCH_PATH,):
                            continue
                        self.assertNotIn(context, block)
                self.assertIsNone(re.search(r"(?m)^env:", text))
                for line in re.findall(r"(?m)^    (?:name|runs-on|timeout-minutes|environment): .*$", text):
                    self.assertNotIn("runner.", line)
                    self.assertNotIn("steps.", line)

    def test_the_capsule_artifacts_are_one_day_uncompressed_and_named_by_run_and_attempt(self):
        text = read_ascii(LINUX_FETCH_PATH)
        for role in ("producer", "verifier"):
            block = text[text.index("      - name: Upload the " + role + " source capsule\n"):]
            block = block.split("\n      - name: ", 1)[0] + "\n"
            with self.subTest(role=role):
                self.assertIn("name: source-capsule-" + role + "-${{ github.run_id }}-${{ github.run_attempt }}\n", block)
                self.assertIn("retention-days: 1\n", block)
                self.assertIn("compression-level: 0\n", block)
                self.assertIn("if-no-files-found: error\n", block)
        self.assertEqual(text.count("compression-level: 0"), 2)

    def test_each_role_workflow_has_one_job_one_signing_step_and_the_role_job_name(self):
        for path, job_id in ((LINUX_FETCH_PATH, "linux-fetch-encrypt"), (CAPSULE_ATTESTER_PATH, "capsule-attester")):
            text = read_ascii(path)
            with self.subTest(path=path.name):
                self.assertEqual(job_ids(text), [job_id])
                self.assertIn("    name: role-" + job_id + "-v1\n", text)
                self.assertEqual(text.count("uses: actions/attest@"), 1)
                self.assertEqual(text.count("workflow_call:"), 1)
                self.assertIn("      profile:\n        required: true\n        type: string\n", text)
        caller = read_ascii(WINDOWS_ADMISSION_PATH)
        for job_id in ("windows-producer", "windows-verifier", "linux-fetch-encrypt", "capsule-attester"):
            self.assertIn("    name: role-call-" + job_id + "-v1\n", job_block(caller, job_id))


class HandoffLanePublicTreeTests(unittest.TestCase):
    def test_handoff_lane_files_are_in_the_platform_allowlist_and_scan_clean(self):
        result = scan_tree(ROOT, "platform")
        for name in HANDOFF_LANE_FILES:
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
