import ast
import hashlib
import json
import os
import re
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from policy import (
    MACOS_CAPABILITY_WORKFLOW_TEMPLATE,
    MACOS_CACHE_PROOF_ACTION_SHA,
    MACOS_CACHE_PROOF_WORKFLOW_TEMPLATE,
    MACOS_RULES_SOURCE_READER_WORKFLOW_SHA256,
    MACOS_RULES_BOOTSTRAP_WORKFLOW_SHA256,
    MACOS_CORE_BOOTSTRAP_WORKFLOW_SHA256,
    MACOS_CORE_CONTRACT_WORKFLOW_SHA256,
    MACOS_REVIEWED_BUILD_WORKFLOW_TEMPLATE,
    MACOS_RUST_TOOLCHAIN_WORKFLOW_TEMPLATE,
    NODE_LOCK_SMOKE_WORKFLOW_TEMPLATE,
    MACOS_SOURCE_READER_ACTION_SHA,
    MACOS_SOURCE_READER_WORKFLOW_SHA256,
    PolicyError,
    encode_public_result,
    validate_control_sha,
    validate_policy_document,
    validate_public_result,
    validate_workflow_text,
    verify_git_head,
)
import policy
import policy_handoff
import policy_linux
import policy_windows
from test_policy_handoff import *
from test_policy_linux import *
from test_policy_windows import *


GOOD_SHA = "a" * 40
PLATFORM_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/public-policy.yml"
MACOS_CAPABILITY_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-capability.yml"
MACOS_REVIEWED_BUILD_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-reviewed-build.yml"
MACOS_RUST_TOOLCHAIN_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-rust-toolchain-smoke.yml"
MACOS_CACHE_PROOF_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-cache-proof.yml"
MACOS_SOURCE_READER_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-source-reader-preflight.yml"
MACOS_RULES_SOURCE_READER_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-rules-reader-preflight.yml"
MACOS_RULES_BOOTSTRAP_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-rules-bootstrap.yml"
MACOS_CORE_BOOTSTRAP_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-core-bootstrap.yml"
MACOS_CORE_CONTRACT_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-core-contract.yml"
NODE_LOCK_SMOKE_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/node-lock-smoke.yml"
MACOS_CORE_BOOTSTRAP_SOURCE = Path(__file__).resolve().parents[2] / "kit/confinement/macos_core_bootstrap.py"
MACOS_CACHE_CLIENT_ACTION = Path(__file__).resolve().parents[2] / "kit/confinement/macos_cache_client/action.yml"
MACOS_CACHE_CLIENT_SOURCE = Path(__file__).resolve().parents[2] / "kit/confinement/macos_cache_client/index.js"
PROBE_SOURCE = Path(__file__).resolve().parents[2] / "kit/confinement/macos_capability.py"
PLATFORM_ACTION = Path(__file__).resolve().parent / "action.yml"


def probe_child_flags(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_probe_user_command"
    ]
    if len(functions) != 1:
        raise AssertionError("expected exactly one _probe_user_command, found %d" % len(functions))
    returns = [
        node.value for node in ast.walk(functions[0])
        if isinstance(node, ast.Return) and isinstance(node.value, ast.List)
    ]
    if len(returns) != 1:
        raise AssertionError("expected exactly one argv list return, found %d" % len(returns))
    elements = returns[0].elts
    flags = []
    for element in elements[1:]:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            raise AssertionError("argv flag section ended before -c")
        if element.value == "-c":
            return flags
        flags.append(element.value)
    raise AssertionError("no -c in argv list")


def result(**changes):
    value = {
        "check_id": "public-policy",
        "status": "passed",
        "passed": 3,
        "failed": 0,
        "duration_ms": 12,
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class ControlShaTests(unittest.TestCase):
    def test_only_canonical_full_lowercase_sha_is_accepted(self):
        self.assertEqual(validate_control_sha(GOOD_SHA), GOOD_SHA)
        for value in (GOOD_SHA[:12], GOOD_SHA.upper(), "z" * 40, GOOD_SHA + "0", " " + GOOD_SHA, None):
            with self.subTest(value_type=type(value).__name__, length=len(value) if isinstance(value, str) else None):
                with self.assertRaisesRegex(PolicyError, "control-sha-invalid"):
                    validate_control_sha(value)

    @patch("policy.subprocess.run")
    def test_checkout_sha_uses_fixed_argv_and_matches_the_requested_control_sha(self, run):
        run.return_value.stdout = GOOD_SHA + "\n"
        self.assertEqual(verify_git_head("/public/workspace", GOOD_SHA), GOOD_SHA)
        self.assertEqual(run.call_args.args[0], ["git", "rev-parse", "--verify", "HEAD"])
        self.assertEqual(run.call_args.kwargs["cwd"], "/public/workspace")
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("policy.subprocess.run")
    def test_checkout_sha_mismatch_and_git_failure_refuse_without_raw_output(self, run):
        run.return_value.stdout = "b" * 40 + "\n"
        with self.assertRaisesRegex(PolicyError, "control-sha-mismatch"):
            verify_git_head("/public/workspace", GOOD_SHA)
        run.side_effect = subprocess.CalledProcessError(1, "git", stderr="raw diagnostic")
        with self.assertRaisesRegex(PolicyError, "control-head-unavailable") as error:
            verify_git_head("/public/workspace", GOOD_SHA)
        self.assertNotIn("raw diagnostic", str(error.exception))


class PolicyDocumentTests(unittest.TestCase):
    def test_public_pool_and_schema_version_are_fixed_fields(self):
        self.assertEqual(validate_policy_document({"pool": "platform", "schema_version": 1}), "platform")
        for value in (
            {"pool": "private", "schema_version": 1},
            {"pool": "platform", "schema_version": True},
            {"pool": "platform", "schema_version": 1, "source": "secret"},
        ):
            with self.subTest(fields=tuple(sorted(value))):
                with self.assertRaises(PolicyError):
                    validate_policy_document(value)
        with self.assertRaisesRegex(PolicyError, "policy-pool-mismatch"):
            validate_policy_document({"pool": "connect", "schema_version": 1}, "platform")


class WorkflowPolicyTests(unittest.TestCase):
    def _platform_workflow(self):
        return PLATFORM_WORKFLOW.read_text(encoding="utf-8")

    def test_feedback_return_workflows_require_exact_reviewed_platform_definitions(self):
        for kind in ("node-lock-return", "core-rust-format-return", "core-build-diagnostic-return"):
            with self.subTest(workflow=kind):
                path = Path(__file__).resolve().parents[2] / (".github/workflows/" + kind + ".yml")
                workflow = path.read_text(encoding="utf-8")
                self.assertTrue(validate_workflow_text(workflow, "platform", kind))
                for pool in ("connect", "workspace", "data"):
                    with self.assertRaises(PolicyError):
                        validate_workflow_text(workflow, pool, kind)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(workflow, "platform")
                mutations = (
                    workflow + "\npermissions: write-all\n",
                    workflow.replace("retention-days: 1", "retention-days: 90", 1),
                    workflow.replace("environment: source-read", "environment: unrestricted", 1),
                    workflow.replace("macos-15", "macos-latest", 1),
                )
                for changed in mutations:
                    self.assertNotEqual(changed, workflow)
                    with self.assertRaises(PolicyError):
                        validate_workflow_text(changed, "platform", kind)

    def test_development_feedback_smoke_requires_reviewed_platform_workflow(self):
        path = Path(__file__).resolve().parents[2] / ".github/workflows/development-feedback-smoke.yml"
        workflow = path.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", "development-feedback-smoke"))
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "development-feedback-smoke")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow + "\npermissions: write-all\n", "platform", "development-feedback-smoke")

    def test_attestation_probe_requires_exact_reviewed_workflow(self):
        path = Path(__file__).resolve().parents[2] / ".github/workflows/attestation-probe.yml"
        workflow = path.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", "attestation-probe"))
        self.assertIn("minimal_permissions[windows-2025]=$windowsPermissions", workflow)
        self.assertIn("$ubuntuPermissions = 'unavailable'", workflow)
        self.assertNotIn("$result = 'denied'", workflow)
        self.assertIn("permission-observation action=$result capability=$capability", workflow)
        self.assertLess(
            workflow.index("      - name: Discover verified certificate field names"),
            workflow.index("      - name: Verify signed statements and negative cases"),
        )
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "attestation-probe")
        mutations = (
            workflow.replace("  workflow_dispatch:\n", "  push:\n", 1),
            workflow.replace("          - windows-2025\n", "          - windows-latest\n", 1),
            workflow.replace("--deny-self-hosted-runners", ""),
            workflow.replace("if ($env:EVENT_NAME -ne 'workflow_dispatch' -or $env:EVENT_REF -ne 'refs/heads/main') {", "if ($false) {", 1),
            workflow.replace("      - name: Check the source-free verifier helper\n", "      - name: Extra shell step\n        run: echo extra\n      - name: Check the source-free verifier helper\n", 1),
            workflow.replace("  verify:\n", "  extra-job:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo extra\n\n  verify:\n", 1),
            workflow.replace("--cert-oidc-issuer 'https://token.actions.githubusercontent.com'", "--cert-oidc-issuer 'https://other.invalid'", 1),
            workflow.replace("      actions: read\n      attestations: read\n", "      actions: read\n      attestations: read\n      contents: write\n", 1),
            workflow.replace("[int]$response.StatusCode -eq 403", "[int]$response.StatusCode -ge 400", 1),
            workflow.replace("if ($result -notin @('failed', 'succeeded', 'ambiguous')) { throw 'classification-value' }", "if ($false) { throw 'classification-value' }", 1),
            workflow.replace("$result = 'failed'", "$result = 'denied'", 1),
            workflow.replace("Write-Output \"probe=leaf-summary runner=$runner $fieldText\"", "Write-Output 'probe=leaf-summary suppressed'", 1),
            workflow.replace("            $ubuntuPermissions = 'unavailable'\n            $windowsPermissions = 'unavailable'\n          }", "          }", 1),
            workflow.replace("if ($reductions[\"$runner/$missing\"] -eq 'succeeded')", "if ($false)", 1),
            workflow.replace("          ref: ${{ github.sha }}\n", "          ref: main\n", 1),
            workflow.replace(
                "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 " + chr(35) + " v4.2.2",
                "uses: actions/attest@v4",
                1,
            ),
            workflow + "\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(changed, workflow)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "attestation-probe")

    def test_existing_attestation_permission_probe_reports_observations_only(self):
        path = Path(__file__).resolve().parents[2] / ".github/workflows/windows-attestation-permission-probe.yml"
        workflow = path.read_text(encoding="utf-8")
        self.assertNotIn("probe=profile-selection", workflow)
        for profile in ("common-intersection", "github-guide", "actions-readme"):
            self.assertIn("probe=profile-comparison result=observed profile=" + profile, workflow)

    def test_actual_platform_workflow_matches_closed_supported_shape(self):
        self.assertTrue(validate_workflow_text(self._platform_workflow(), "platform"))

    def test_node_lock_smoke_workflow_is_closed_source_free_and_cross_platform(self):
        workflow = NODE_LOCK_SMOKE_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow, NODE_LOCK_SMOKE_WORKFLOW_TEMPLATE)
        self.assertIn("  pull_request:\n", workflow)
        self.assertEqual(workflow.count('test_sbom_normalizer.py"'), 2)
        self.assertLess(workflow.index("uses: actions/setup-node@"), workflow.index('test_sbom_normalizer.py"'))
        self.assertIn("Versions/3.9/bin/python3.9 -I -S -B -m unittest discover", workflow)
        self.assertTrue(validate_workflow_text(workflow, "platform", "node-lock-smoke"))
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "node-lock-smoke")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_node_lock_smoke_workflow_rejects_source_cache_and_runtime_changes(self):
        base = NODE_LOCK_SMOKE_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  workflow_dispatch:\n", "  pull_request:\n", 1),
            base.replace("  pull_request:\n", "", 1),
            base.replace("      - \"**\"\n", "      - main\n", 1),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n", 1),
            base.replace("          - macos-15\n", "          - macos-latest\n", 1),
            base.replace("      fail-fast: true\n", "      fail-fast: false\n", 1),
            base.replace("949feb2413d6458794dcd2491c4babbbce0c15c1", "a" * 40, 1),
            base.replace('node-version: "24.22.1"', 'node-version: "24"', 1),
            base.replace("check-latest: false", "check-latest: true", 1),
            base.replace('cache: ""', 'cache: "npm"', 1),
            base.replace("package-manager-cache: false", "package-manager-cache: true", 1),
            base.replace('== "11.19.1"', '== "11.19.0"', 1),
            base.replace("test_node_lock_manifest.mjs", "unreviewed.mjs", 1),
            base.replace('test_node_lock_receipt.py"', 'test_policy.py"', 1),
            base.replace('          "$python_command" -B -m unittest discover -s kit/confinement -p "test_sbom_normalizer.py"\n', "", 1),
            base.replace('            /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B -m unittest discover -s kit/confinement -p "test_sbom_normalizer.py"\n', "", 1),
            base.replace("      - name: Run source-free helper tests\n", "      - name: Extra step\n        run: echo extra\n      - name: Run source-free helper tests\n", 1),
            base.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n    inputs: {}\n", 1),
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                self.assertNotEqual(changed, base)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "node-lock-smoke")

    def test_actual_macos_capability_workflow_matches_closed_manual_shape(self):
        workflow = MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", "macos-capability"))
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("runs-on: macos-15", workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn('CI_SHA="$CI_SHA"', workflow)
        self.assertIn("CI_WORKSPACE: ${{ github.workspace }}", workflow)
        self.assertIn('CI_WORKSPACE="$CI_WORKSPACE"', workflow)
        self.assertNotIn("RUNNER_WORKSPACE: ${{ github.workspace }}", workflow)
        self.assertNotIn('RUNNER_WORKSPACE="$RUNNER_WORKSPACE"', workflow)
        self.assertIn("Validate source-free control tree", workflow)
        self.assertIn('check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"', workflow)
        self.assertNotIn("inputs:", workflow)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "macos-capability")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_macos_capability_workflow_rejects_trigger_runner_and_execution_changes(self):
        base = MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  workflow_dispatch:\n", "  push:\n"),
            base.replace("github.event_name == 'workflow_dispatch'", "github.event_name == 'push'"),
            base.replace("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/feature'"),
            base.replace("    runs-on: macos-15\n", "    runs-on: macos-latest\n"),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n"),
            base.replace("      CI_WORKSPACE: ${{ github.workspace }}\n", "      RUNNER_WORKSPACE: ${{ github.workspace }}\n"),
            base.replace('check_candidate.py --root "$CI_WORKSPACE"', 'check_candidate.py --root "$RUNNER_WORKSPACE"'),
            base.replace('            CI_WORKSPACE="$CI_WORKSPACE" \\\n', '            CI_WORKSPACE=/unreviewed \\\n'),
            base.replace("      - name: Validate source-free control tree\n", ""),
            base.replace("      - name: Run source-free capability experiment\n", "      - name: Extra execution\n        run: echo extra\n      - name: Run source-free capability experiment\n"),
            base.replace("            CI_SHA=\"$CI_SHA\" \\\n", ""),
            base + "  extra:\n    runs-on: macos-15\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "macos-capability")

    def test_macos_capability_privileged_step_uses_pinned_command_line_tools_interpreter(self):
        clt = (
            "/Library/Developer/CommandLineTools/Library/Frameworks/"
            "Python3.framework/Versions/3.9/bin/python3.9"
        )
        launch = " -I -S -B kit/confinement/macos_deny_default.py --control-sha \"$CI_SHA\""
        for text in (MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8"), MACOS_CAPABILITY_WORKFLOW_TEMPLATE):
            with self.subTest(source=text[:20]):
                self.assertEqual(text.count(clt + launch), 1)
                self.assertEqual(text.count("confinement/macos_deny_default.py"), 1)
                self.assertNotIn("/usr/bin/python3 -B kit/confinement/macos_deny_default.py", text)
                self.assertNotIn("Versions/Current", text)
                privileged = [line for line in text.splitlines() if "confinement/macos_deny_default.py" in line]
                self.assertEqual([line.strip() for line in privileged], [clt + launch])

    def test_macos_capability_workflow_file_equals_pinned_template(self):
        workflow = MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow, MACOS_CAPABILITY_WORKFLOW_TEMPLATE)
        self.assertTrue(validate_workflow_text(workflow, "platform", "macos-capability"))

    def test_macos_capability_workflow_reverting_to_shim_interpreter_is_rejected(self):
        workflow = MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8")
        clt = (
            "/Library/Developer/CommandLineTools/Library/Frameworks/"
            "Python3.framework/Versions/3.9/bin/python3.9"
        )
        for replacement in ("/usr/bin/python3", clt.replace("Versions/3.9", "Versions/Current")):
            with self.subTest(replacement=replacement):
                changed = workflow.replace(clt + " -I -S -B kit/confinement", replacement + " -I -S -B kit/confinement")
                self.assertNotEqual(changed, workflow)
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(changed, "platform", "macos-capability")

    def test_macos_capability_privileged_launch_flags_match_probe_child_flags(self):
        child_flags = probe_child_flags(PROBE_SOURCE)
        self.assertEqual(child_flags, ["-I", "-S", "-B"])
        for text in (MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8"), MACOS_CAPABILITY_WORKFLOW_TEMPLATE):
            with self.subTest(source=text[:20]):
                lines = [line.strip() for line in text.splitlines() if "confinement/macos_deny_default.py" in line]
                self.assertEqual(len(lines), 1)
                tokens = lines[0].split()
                script = tokens.index("kit/confinement/macos_deny_default.py")
                self.assertTrue(tokens[0].endswith("/bin/python3.9"))
                self.assertEqual(tokens[1:script], child_flags)

    def test_macos_capability_workflow_dropping_isolation_flags_is_rejected(self):
        workflow = MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8")
        for flags in ("-S -B", "-I -B", "-B", "-I -S", "-S -I -B"):
            with self.subTest(flags=flags):
                changed = workflow.replace("python3.9 -I -S -B kit/confinement", "python3.9 " + flags + " kit/confinement")
                self.assertNotEqual(changed, workflow)
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(changed, "platform", "macos-capability")

    def test_macos_audit_dependencies_tokens_and_final_gate_are_pinned(self):
        base = MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "    needs: macos-public-snapshot\n",
            "    needs: [macos-public-snapshot, macos-capability]\n",
            "    if: ${{ always() }}\n",
            "      receipt: ${{ steps.proof.outputs.receipt }}\n",
            "      MACOS_CACHE_SNAPSHOT: ${{ needs.macos-public-snapshot.outputs.cache_snapshot }}\n",
            "      MACOS_NATIVE_RECEIPT_B64URL: ${{ needs.macos-capability.outputs.receipt }}\n",
            '          sudo -n -- env -i ',
            '            RUNNER_HOME="$HOME" ',
            '        run: python3 -B kit/confinement/macos_harness.py --control-sha "$CI_SHA"',
        )
        for value in required:
            with self.subTest(fragment=value):
                self.assertIn(value, base)
                changed = base.replace(value, "", 1)
                self.assertNotEqual(changed, base)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "macos-capability")
        mutations = (
            base.replace("      checks: read\n", "      checks: write\n"),
            base.replace("      actions: read\n", "      actions: write\n"),
            base.replace("    permissions: {}\n", "    permissions:\n      actions: read\n", 1),
            base.replace('        id: proof\n', '        id: untrusted\n'),
            base.replace("    needs: macos-public-snapshot\n", "    needs: []\n"),
            base.replace("      GITHUB_TOKEN: ${{ github.token }}\n", ""),
            base.replace("macos_deny_default.py --control-sha", "macos_capability.py --control-sha"),
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(changed, base)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "macos-capability")

    def test_actual_macos_reviewed_build_workflow_has_source_free_smoke_and_independent_audit(self):
        workflow = MACOS_REVIEWED_BUILD_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow, MACOS_REVIEWED_BUILD_WORKFLOW_TEMPLATE)
        self.assertTrue(validate_workflow_text(workflow, "platform", "macos-reviewed-build"))
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("runs-on: macos-15", workflow)
        self.assertEqual(workflow.count("cache-mode: none"), 4)
        self.assertIn("permissions: {}", workflow)
        self.assertIn("needs: [macos-public-snapshot, macos-reviewed-smoke]", workflow)
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertIn("actions: read\n      checks: read", workflow)
        self.assertIn("python3 -B kit/confinement/macos_public_audit.py reviewed-snapshot", workflow)
        self.assertIn("python3 -B kit/confinement/macos_public_audit.py reviewed-audit", workflow)
        self.assertIn(
            "      - name: Snapshot cache inventory\n        id: snapshot\n        env:\n"
            "          GITHUB_TOKEN: ${{ github.token }}\n",
            workflow,
        )
        self.assertIn(
            "      - name: Audit public surfaces\n        env:\n"
            "          GITHUB_TOKEN: ${{ github.token }}\n",
            workflow,
        )
        self.assertIn("test_macos*.py", workflow)
        self.assertIn("kit/confinement/macos_reviewed_build.py --control-sha \"$CI_SHA\"", workflow)
        self.assertIn(
            "kit/confinement/macos_network_observer.py selftest",
            workflow,
        )
        self.assertIn('if [[ -z "${ImageOS:-}" || -z "${ImageVersion:-}" ]]', workflow)
        self.assertIn('ImageOS="$ImageOS"', workflow)
        self.assertIn('ImageVersion="$ImageVersion"', workflow)
        smoke = workflow.split("  macos-reviewed-smoke:\n", 1)[1].split(
            "  macos-public-surface-audit:\n", 1
        )[0]
        self.assertNotIn("GITHUB_TOKEN", smoke)
        observer = smoke.split("      - name: Prove source-free network observer\n", 1)[1].split(
            "      - name: Run source-free reviewed build smoke\n", 1
        )[0]
        self.assertIn('CI_SHA="$CI_SHA" \\', observer)
        self.assertIn('GITHUB_RUN_ID="$GITHUB_RUN_ID" \\', observer)
        self.assertIn('GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \\', observer)
        self.assertIn("sudo -n -- env -i", observer)
        self.assertIn("kit/confinement/macos_network_observer.py selftest", observer)
        self.assertNotIn("GITHUB_TOKEN", observer)
        self.assertNotIn("GITHUB_STEP_SUMMARY", observer)
        self.assertNotIn("GITHUB_OUTPUT", observer)
        self.assertIn('CI_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \\', smoke)
        self.assertIn('RUNNER_HOME="$HOME" \\', smoke)
        self.assertIn("      - name: Write trusted summary visibility control\n", smoke)
        self.assertIn('summary_prefix="macos-summary-"', smoke)
        self.assertIn(
            'summary_line="${summary_prefix}control=trusted-write schema=1 control-sha=$CI_SHA '
            'run-id=$GITHUB_RUN_ID run-attempt=$GITHUB_RUN_ATTEMPT"',
            smoke,
        )
        self.assertIn('printf \'%s\\n\' "$summary_line" >> "$GITHUB_STEP_SUMMARY"', smoke)
        self.assertIn('printf \'%s\\n\' "$summary_line"', smoke)
        self.assertNotRegex(workflow, r"(?m)^\s*GITHUB_STEP_SUMMARY:")
        self.assertLess(
            workflow.index("      - name: Prove source-free network observer\n"),
            workflow.index("      - name: Run source-free reviewed build smoke\n"),
        )
        self.assertLess(
            workflow.index("      - name: Validate source-free control tree\n"),
            workflow.index("      - name: Prove source-free network observer\n"),
        )
        self.assertLess(
            workflow.index("      - name: Run source-free reviewed build smoke\n"),
            workflow.index("      - name: Write trusted summary visibility control\n"),
        )
        snapshot = workflow.split("  macos-public-snapshot:\n", 1)[1].split(
            "  macos-reviewed-smoke:\n", 1
        )[0]
        self.assertNotIn("GITHUB_TOKEN", snapshot.split("      - name: Snapshot cache inventory\n", 1)[0])
        audit_job = workflow.split("  macos-public-surface-audit:\n", 1)[1]
        self.assertNotIn("GITHUB_TOKEN", audit_job.split("      - name: Audit public surfaces\n", 1)[0])
        for forbidden in (
            "secrets.",
            "source-read",
            "environment:",
            "inputs:",
            "actions/checkout",
            "upload-artifact",
            "download-artifact",
            "uses:",
            "continue-on-error:",
            "MACOS_NATIVE_RECEIPT_B64URL",
            "macos_deny_default.py",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "macos-reviewed-build")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_actual_macos_rust_toolchain_workflow_is_source_free_and_independently_audited(self):
        workflow = MACOS_RUST_TOOLCHAIN_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow, MACOS_RUST_TOOLCHAIN_WORKFLOW_TEMPLATE)
        self.assertTrue(validate_workflow_text(workflow, "platform", "macos-rust-toolchain-smoke"))
        self.assertIn("workflow_dispatch:\ncache-mode: none\npermissions: {}", workflow)
        self.assertEqual(workflow.count("cache-mode: none"), 4)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("runs-on: macos-15", workflow)
        self.assertIn("needs: macos-rust-toolchain-snapshot", workflow)
        self.assertIn(
            "needs: [macos-rust-toolchain-snapshot, macos-rust-toolchain-smoke]", workflow
        )
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertIn("actions: read\n      checks: read", workflow)
        self.assertIn("rust-toolchain-snapshot", workflow)
        self.assertIn("rust-toolchain-audit", workflow)
        self.assertIn("kit/confinement/macos_reviewed_build.py --control-sha", workflow)
        self.assertIn(
            "kit/confinement/macos_rust_toolchain.py --control-sha \"$CI_SHA\"", workflow
        )
        self.assertIn(
            "kit/confinement/macos_public_audit.py rust-toolchain-publish", workflow
        )
        self.assertIn(
            "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_public_audit.py rust-toolchain-publish",
            workflow,
        )
        self.assertIn(
            "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_rust_toolchain.py",
            workflow,
        )
        self.assertIn("GITHUB_RUN_ID=\"$GITHUB_RUN_ID\" \\\n", workflow)
        self.assertIn("GITHUB_RUN_ATTEMPT=\"$GITHUB_RUN_ATTEMPT\" \\\n", workflow)
        self.assertIn("CI_SHA=\"$CI_SHA\" \\\n", workflow)
        self.assertIn("GITHUB_SHA=\"$GITHUB_SHA\" \\\n", workflow)
        self.assertIn("GITHUB_REPOSITORY=\"$CI_REPOSITORY\" \\\n", workflow)
        self.assertIn("GITHUB_EVENT_NAME=\"$CI_EVENT_NAME\" \\\n", workflow)
        self.assertIn("GITHUB_REF=\"$CI_REF\" \\\n", workflow)
        self.assertIn('>"$stdout_file" 2>"$stderr_file"', workflow)
        self.assertIn(
            '<"$stdout_file" >"$validated_file" 2>"$validator_stderr_file"', workflow
        )
        self.assertIn(
            'printf \'%s\\n\' "$receipt_line" 2>/dev/null >> "$GITHUB_STEP_SUMMARY"',
            workflow,
        )
        self.assertIn('rust_marker_prefix="KD-RUST-"', workflow)
        self.assertIn('rust_success_prefix="${rust_marker_prefix}SMOKE "', workflow)
        self.assertIn('rust_refusal_prefix="${rust_marker_prefix}REFUSAL reason="', workflow)
        self.assertNotIn("KD-RUST-SMOKE ", workflow)
        self.assertNotIn("KD-RUST-REFUSAL", workflow)
        self.assertIn(
            'printf \'%s%s\\n\' "$rust_refusal_prefix" "capture_invalid"', workflow
        )
        self.assertIn(
            'printf \'%s%s\\n\' "$rust_refusal_prefix" "smoke_failed"', workflow
        )
        self.assertIn('summary_prefix="macos-summary-"', workflow)
        self.assertIn(
            'summary_line="${summary_prefix}control=trusted-write schema=1 control-sha=$CI_SHA run-id=$GITHUB_RUN_ID run-attempt=$GITHUB_RUN_ATTEMPT"',
            workflow,
        )
        self.assertIn("CI_WORKSPACE: ${{ github.workspace }}", workflow)
        self.assertIn(
            'check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"', workflow
        )
        self.assertNotIn("inputs:", workflow)
        for forbidden in (
            "secrets.",
            "source-read",
            "environment:",
            "actions/checkout",
            "upload-artifact",
            "download-artifact",
            "uses:",
            "continue-on-error:",
            "MACOS_NATIVE_RECEIPT_B64URL",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        snapshot = workflow.split("  macos-rust-toolchain-snapshot:\n", 1)[1].split(
            "  macos-rust-toolchain-smoke:\n", 1
        )[0]
        smoke = workflow.split("  macos-rust-toolchain-smoke:\n", 1)[1].split(
            "  macos-rust-toolchain-audit:\n", 1
        )[0]
        audit = workflow.split("  macos-rust-toolchain-audit:\n", 1)[1]
        self.assertIn("actions: read", snapshot)
        self.assertNotIn("checks: read", snapshot)
        self.assertNotIn("GITHUB_TOKEN", smoke)
        self.assertNotIn("GITHUB_TOKEN", audit.split("      - name: Audit public surfaces\n", 1)[0])
        self.assertLess(
            smoke.index("Validate source-free control tree"),
            smoke.index("Run source-free reviewed build smoke"),
        )
        self.assertLess(
            smoke.index("Run source-free reviewed build smoke"),
            smoke.index("Run source-free Rust toolchain smoke"),
        )
        self.assertLess(
            smoke.index("Run source-free Rust toolchain smoke"),
            smoke.index("Write trusted summary visibility control"),
        )
        rust_smoke = smoke.split("      - name: Run source-free Rust toolchain smoke\n", 1)[1].split(
            "      - name: Write trusted summary visibility control\n", 1
        )[0]
        publisher = rust_smoke.index("macos_public_audit.py rust-toolchain-publish")
        capture_cleanup = rust_smoke.index('if ! /bin/rm -rf "$capture_dir"')
        summary_publication = rust_smoke.index(
            'printf \'%s\\n\' "$receipt_line" 2>/dev/null >> "$GITHUB_STEP_SUMMARY"'
        )
        log_publication = rust_smoke.index('          printf \'%s\\n\' "$receipt_line"\n')
        self.assertLess(publisher, capture_cleanup)
        self.assertLess(capture_cleanup, summary_publication)
        self.assertLess(publisher, log_publication)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "macos-rust-toolchain-smoke")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_macos_rust_toolchain_workflow_rejects_source_cache_and_audit_bypasses(self):
        base = MACOS_RUST_TOOLCHAIN_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  workflow_dispatch:\n", "  push:\n"),
            base.replace("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/feature'"),
            base.replace("runs-on: macos-15", "runs-on: macos-latest"),
            base.replace("cache-mode: none\n", "cache-mode: read\n", 1),
            base.replace("    cache-mode: none\n", "", 1),
            base.replace("    if: ${{ always() }}\n", "    if: ${{ success() }}\n"),
            base.replace("      actions: read\n      checks: read\n", "      actions: write\n      checks: write\n"),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n", 1),
            base.replace("      - name: Run source-free Rust toolchain smoke\n", ""),
            base.replace("macos_public_audit.py rust-toolchain-publish", "macos_public_audit.py rust-toolchain-audit"),
            base.replace(
                "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_rust_toolchain.py",
                "/usr/bin/python3 -I -S -B kit/confinement/macos_rust_toolchain.py",
            ),
            base.replace("      - name: Write trusted summary visibility control\n", ""),
            base.replace("      - name: Validate source-free control tree\n", ""),
            base.replace("needs: [macos-rust-toolchain-snapshot, macos-rust-toolchain-smoke]", "needs: macos-rust-toolchain-smoke"),
            base.replace('  if: ${{ always() }}\n', '  if: ${{ success() }}\n'),
            base.replace("kit/confinement/macos_rust_toolchain.py --control-sha", "kit/confinement/macos_reviewed_build.py --control-sha"),
            base.replace('GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \\\n', ""),
            base.replace('>"$stdout_file" 2>"$stderr_file"', ""),
            base.replace("      - name: Run source-free reviewed build smoke\n", "      - name: Extra execution\n        run: echo extra\n      - name: Run source-free reviewed build smoke\n"),
            base.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-latest\n"),
            base + "  unexpected:\n    runs-on: ubuntu-24.04\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(changed, base)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "macos-rust-toolchain-smoke")

    def test_macos_reviewed_build_workflow_rejects_cache_source_and_audit_bypasses(self):
        base = MACOS_REVIEWED_BUILD_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("cache-mode: none\n", "cache-mode: read\n", 1),
            base.replace("    cache-mode: none\n", "", 1),
            base.replace("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/feature'"),
            base.replace("runs-on: macos-15", "runs-on: macos-latest"),
            base.replace("needs: [macos-public-snapshot, macos-reviewed-smoke]", "needs: macos-reviewed-smoke"),
            base.replace("    if: ${{ always() }}\n", "    if: ${{ success() }}\n"),
            base.replace("      actions: read\n      checks: read\n", "      actions: write\n      checks: write\n"),
            base.replace("      - name: Run source-free reviewed build smoke\n", ""),
            base.replace("      - name: Prove source-free network observer\n", ""),
            base.replace("      - name: Write trusted summary visibility control\n", ""),
            base.replace('            CI_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \\\n', ""),
            base.replace("      - name: Audit public surfaces\n", "      - name: Extra execution\n        run: echo unreviewed\n      - name: Audit public surfaces\n"),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n", 1),
            base.replace("      CI_WORKSPACE: ${{ github.workspace }}\n", "      GITHUB_TOKEN: ${{ github.token }}\n      CI_WORKSPACE: ${{ github.workspace }}\n"),
            base.replace("GITHUB_RUN_ATTEMPT=\"$GITHUB_RUN_ATTEMPT\" \\\n", ""),
            base.replace('          if [[ -z "${ImageOS:-}" || -z "${ImageVersion:-}" ]]; then\n            exit 1\n          fi\n', ""),
            base.replace("macos_reviewed_build.py --control-sha", "macos_deny_default.py --control-sha"),
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(changed, base)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "macos-reviewed-build")

    def test_actual_macos_cache_proof_workflow_is_manual_source_free_and_independently_audited(self):
        workflow = MACOS_CACHE_PROOF_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow, MACOS_CACHE_PROOF_WORKFLOW_TEMPLATE)
        self.assertTrue(validate_workflow_text(workflow, "platform", "macos-cache-proof"))
        self.assertIn("workflow_dispatch:\ncache-mode: none\npermissions: {}", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertEqual(workflow.count("runs-on: macos-15"), 3)
        self.assertEqual(workflow.count("cache-mode: none"), 5)
        self.assertIn("  macos-cache-seed:\n", workflow)
        self.assertIn("    cache-mode: write\n", workflow)
        self.assertIn("  macos-cache-positive:\n", workflow)
        self.assertIn("    cache-mode: read\n", workflow)
        self.assertIn("  macos-cache-none-probe:\n", workflow)
        self.assertNotIn("ACTIONS_CACHE_MODE:", workflow)
        self.assertIn("fail-on-cache-miss: true", workflow)
        self.assertIn("cmp -s", workflow)
        action_prefix = "uses: actions/cache/"
        self.assertEqual(workflow.count(action_prefix), 2)
        self.assertEqual(
            workflow.count("uses: actions/cache/restore@" + MACOS_CACHE_PROOF_ACTION_SHA),
            1,
        )
        self.assertEqual(
            workflow.count("uses: actions/cache/save@" + MACOS_CACHE_PROOF_ACTION_SHA),
            1,
        )
        self.assertIn('"${CI_SERVER_URL%/}/actions/cache.git"', workflow)
        self.assertIn("git -C \"$client_dir\" fetch --quiet --no-tags --depth=1 origin " + MACOS_CACHE_PROOF_ACTION_SHA, workflow)
        self.assertIn("macos-cache-client-source=verified schema=1 action-sha=", workflow)
        self.assertIn("uses: ./kit/confinement/macos_cache_client", workflow)
        self.assertIn("mode: read\n", workflow)
        self.assertIn("mode: write\n", workflow)
        self.assertIn("SAVE_OUTCOME: ${{ steps.denied-save.outcome }}", workflow)
        client_metadata = MACOS_CACHE_CLIENT_ACTION.read_text(encoding="utf-8")
        self.assertIn("description:", client_metadata)
        self.assertIn("using: node24", client_metadata)
        self.assertIn("main: index.js", client_metadata)
        self.assertIn("The cache operation to request.", client_metadata)
        self.assertIn("The public fixture path used by the cache operation.", client_metadata)
        self.assertIn("The exact run-scoped public cache key.", client_metadata)
        client_source = MACOS_CACHE_CLIENT_SOURCE.read_text(encoding="utf-8")
        self.assertIn('process.env.ACTIONS_CACHE_MODE !== "none"', client_source)
        self.assertIn("{ ACTIONS_CACHE_MODE: mode }", client_source)
        self.assertIn('"dist/restore-only/index.js"', client_source)
        self.assertIn('"dist/save-only/index.js"', client_source)
        self.assertIn('process.env.ACTIONS_RUNTIME_TOKEN', client_source)
        self.assertIn('"cache read denied:"', client_source)
        self.assertIn('"cache write denied:"', client_source)
        self.assertIn('"::warning::Failed to restore: " + denialPrefix', client_source)
        self.assertIn('"::warning::Failed to restore: Failed to GetCacheEntryDownloadURL: "', client_source)
        self.assertIn('"Received non-retryable error: "', client_source)
        self.assertIn('"::warning::Failed to save: Unable to reserve cache with key " + key', client_source)
        self.assertIn('". More details: " + denialPrefix', client_source)
        self.assertIn("line.startsWith(readV1Prefix)", client_source)
        self.assertIn("line.startsWith(readV2Prefix) && line.includes(denialPrefix)", client_source)
        self.assertIn(": line.startsWith(writePrefix)", client_source)
        self.assertIn('const nonDebugLines = lines.filter((line) => !line.startsWith("::debug::"));', client_source)
        self.assertIn('const warnings = nonDebugLines.filter((line) => line.startsWith("::warning::"));', client_source)
        self.assertIn('const commands = nonDebugLines.filter((line) => line.startsWith("::"));', client_source)
        self.assertIn('refuse("service_denial_unrecognized")', client_source)
        self.assertIn('refuse("service_denial_ambiguous")', client_source)
        self.assertIn('refuse("cache_miss")', client_source)
        self.assertIn("serviceEnvelope.length > 512", client_source)
        self.assertIn("suffix.length > 1024", client_source)
        self.assertIn("matching[0].length > 2048", client_source)
        self.assertIn('const expectedCacheMiss = "Cache not found for input keys: " + key;', client_source)
        self.assertIn('line.startsWith("Cache not found for input keys:")', client_source)
        self.assertIn("cacheMissLines[0] === expectedCacheMiss", client_source)
        self.assertNotIn('captured.includes("Cache not found for input keys: " + key)', client_source)
        self.assertIn('captured.includes("Cache restore skipped")', client_source)
        self.assertIn('captured.includes("Cache save skipped")', client_source)
        self.assertIn('captured.includes("Cache restored from key: " + key)', client_source)
        self.assertIn('captured.includes("Cache saved with key: " + key)', client_source)
        self.assertNotIn('(403) Forbidden', client_source)
        self.assertIn('" key=" + key + " control-sha="', client_source)
        self.assertIn('process.version.match(/^v24\\.', client_source)
        self.assertIn("cache-proof-snapshot", workflow)
        self.assertIn("cache-proof-audit", workflow)
        self.assertIn("cache-proof-cleanup", workflow)
        self.assertIn("actions: read\n      checks: read", workflow)
        self.assertEqual(workflow.count("actions: write"), 1)
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertIn(
            "needs: [macos-cache-public-snapshot, macos-cache-seed, macos-cache-positive, macos-cache-none-probe]",
            workflow,
        )
        self.assertIn("macos-cache-public-audit", workflow)
        seed = workflow.split("  macos-cache-seed:\n", 1)[1].split("  macos-cache-positive:\n", 1)[0]
        positive = workflow.split("  macos-cache-positive:\n", 1)[1].split("  macos-cache-none-probe:\n", 1)[0]
        probe = workflow.split("  macos-cache-none-probe:\n", 1)[1].split("  macos-cache-public-audit:\n", 1)[0]
        cleanup = workflow.split("  macos-cache-cleanup:\n", 1)[1]
        for runner_job in (seed, positive, probe):
            self.assertNotIn("GITHUB_TOKEN", runner_job)
            self.assertNotIn("secrets.", runner_job)
        self.assertNotIn("actions: write", workflow.split("  macos-cache-cleanup:\n", 1)[0])
        self.assertIn("actions: write", cleanup)
        self.assertIn("Fetch the exact pinned public cache client", probe)
        self.assertIn("Request the known fixture through the pinned cache client", probe)
        self.assertIn("Request a save through the pinned cache client", probe)
        self.assertNotIn("ACTIONS_CACHE_MODE", probe)
        for forbidden in (
            "source-read",
            "environment:",
            "inputs:",
            "actions/checkout",
            "upload-artifact",
            "download-artifact",
            "GITHUB_STEP_SUMMARY",
            "GITHUB_OUTPUT",
            "continue-on-error:",
            "uses: actions/cache@",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "macos-cache-proof")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_macos_cache_proof_rejects_mode_pin_scope_and_evidence_bypasses(self):
        base = MACOS_CACHE_PROOF_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("cache-mode: none\n", "cache-mode: read\n", 1),
            base.replace("    cache-mode: write\n", "    cache-mode: none\n", 1),
            base.replace("    cache-mode: read\n", "    cache-mode: none\n", 1),
            base.replace(
                "  macos-cache-none-probe:\n    needs: macos-cache-positive\n"
                "    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}\n"
                "    runs-on: macos-15\n    cache-mode: none\n",
                "  macos-cache-none-probe:\n    needs: macos-cache-positive\n"
                "    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}\n"
                "    runs-on: macos-15\n    cache-mode: read\n",
            ),
            base.replace("          mode: read\n          path: ${{ runner.temp }}/macos-public-cache/fixture.txt\n",
                         "          mode: write\n          path: ${{ runner.temp }}/macos-public-cache/fixture.txt\n"),
            base.replace("          mode: write\n          path: ${{ runner.temp }}/macos-public-cache-write/fixture.txt\n",
                         "          mode: read\n          path: ${{ runner.temp }}/macos-public-cache-write/fixture.txt\n"),
            base.replace("git -C \"$client_dir\" fetch --quiet --no-tags --depth=1 origin " + MACOS_CACHE_PROOF_ACTION_SHA,
                         "git -C \"$client_dir\" fetch --quiet --no-tags --depth=1 origin " + "0" * 40),
            base.replace("uses: ./kit/confinement/macos_cache_client",
                         "uses: actions/cache/restore@" + MACOS_CACHE_PROOF_ACTION_SHA, 1),
            base.replace(MACOS_CACHE_PROOF_ACTION_SHA, "0" * 40),
            base.replace("fail-on-cache-miss: true", "fail-on-cache-miss: false"),
            base.replace("cmp -s", "true " + chr(35) + " invalid-comment"),
            base.replace("needs: [macos-cache-public-snapshot, macos-cache-seed, macos-cache-positive, macos-cache-none-probe]", "needs: macos-cache-none-probe"),
            base.replace("if: ${{ always() }}", "if: ${{ success() }}"),
            base.replace("      actions: read\n      checks: read\n", "      actions: write\n      checks: write\n"),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n", 1),
            base.replace("macos-cache", "source-read", 1),
            base.replace("macos-cache-public-audit", "macos-cache-seed"),
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(changed, base)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "macos-cache-proof")

    def test_source_reader_workflows_are_fixed_manual_main_only_and_independently_audited(self):
        cases = (
            (
                MACOS_SOURCE_READER_WORKFLOW,
                "macos-source-reader",
                MACOS_SOURCE_READER_WORKFLOW_SHA256,
                "macos-source-reader-preflight",
                "source-read",
                "core",
            ),
            (
                MACOS_RULES_SOURCE_READER_WORKFLOW,
                "macos-rules-source-reader",
                MACOS_RULES_SOURCE_READER_WORKFLOW_SHA256,
                "macos-rules-reader-preflight",
                "rules-source-read",
                "rules",
            ),
        )
        for path, workflow_kind, expected_digest, workflow_name, environment, suffix in cases:
            with self.subTest(workflow=workflow_name):
                workflow = path.read_text(encoding="utf-8")
                self.assertEqual(hashlib.sha256(workflow.encode("utf-8")).hexdigest(), expected_digest)
                self.assertTrue(validate_workflow_text(workflow, "platform", workflow_kind))
                self.assertTrue(workflow.startswith(
                    "name: " + workflow_name + "\non:\n  workflow_dispatch:\n"
                ))
                self.assertIn("cache-mode: none\npermissions: {}", workflow)
                self.assertIn("github.ref == 'refs/heads/main'", workflow)
                self.assertIn("environment: " + environment, workflow)
                self.assertEqual(workflow.count("environment:"), 1)
                self.assertIn(
                    "source-reader-settings-" + suffix,
                    workflow,
                )
                self.assertIn("source-reader-snapshot-" + suffix, workflow)
                self.assertIn("source-reader-audit-" + suffix, workflow)
                self.assertIn("uses: actions/create-github-app-token@" + MACOS_SOURCE_READER_ACTION_SHA, workflow)
                self.assertIn("client-id: ${{ vars.SOURCE_READER_CLIENT_ID }}", workflow)
                self.assertIn("private-key: ${{ secrets.SOURCE_READER_PRIVATE_KEY }}", workflow)
                self.assertIn("owner: ${{ secrets.SOURCE_REPOSITORY_OWNER }}", workflow)
                self.assertIn("repositories: ${{ secrets.SOURCE_REPOSITORY_NAME }}", workflow)
                self.assertIn("permission-contents: read", workflow)
                self.assertNotIn("skip-token-revoke", workflow)
                self.assertIn("if: ${{ always() && steps.source-reader-token.outcome != 'skipped' }}", workflow)
                self.assertIn("env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C SOURCE_READER_TOKEN=", workflow)
                self.assertIn("kit/confinement/macos_source_reader.py", workflow)
                self.assertIn('summary_prefix="macos-summary-"', workflow)
                self.assertIn(
                    'summary_line="${summary_prefix}control=trusted-write schema=1 control-sha=$CI_SHA '
                    'run-id=$GITHUB_RUN_ID run-attempt=$GITHUB_RUN_ATTEMPT"',
                    workflow,
                )
                self.assertIn("expected_json='{\"meta''data\":\"verified\",\"reason\":\"ok\",'", workflow)
                self.assertNotIn('{"metadata":', workflow)
                self.assertIn("helper_status=$?", workflow)
                self.assertIn('if [[ -n "$helper_json" ]]; then', workflow)
                self.assertIn('if [[ "$helper_status" -ne 0 || "$helper_json" != "$expected_json" ]]; then', workflow)
                self.assertIn("needs: [macos-source-reader-settings, macos-source-reader-token]", workflow)
                self.assertIn("if: ${{ always() && github.event_name == 'workflow_dispatch'", workflow)
                self.assertIn("actions: read\n      checks: read", workflow)
                self.assertNotRegex(workflow, r"(?m)^\s*GITHUB_STEP_SUMMARY:")
                for forbidden in (
                    "inputs:",
                    "workflow_call:",
                    "pull_request:",
                    "pull_request_target:",
                    "push:\n",
                    "actions/checkout",
                    "upload-artifact",
                    "download-artifact",
                    "SOURCE_CANDIDATE_REF",
                ):
                    with self.subTest(forbidden=forbidden):
                        self.assertNotIn(forbidden, workflow)
                token_job = workflow.split("  macos-source-reader-token:\n", 1)[1].split(
                    "  macos-source-reader-audit:\n", 1
                )[0]
                settings_job = workflow.split("  macos-source-reader-settings:\n", 1)[1].split(
                    "  macos-source-reader-token:\n", 1
                )[0]
                self.assertNotIn("GITHUB_TOKEN", token_job)
                self.assertNotIn("secrets.", settings_job)
                self.assertNotIn("SOURCE_READER_PRIVATE_KEY", settings_job)
                self.assertNotIn("SOURCE_REPOSITORY_OWNER", settings_job)
                self.assertNotIn("SOURCE_REPOSITORY_NAME", settings_job)
                for changed in (
                    workflow.replace("environment: " + environment, "environment: invalid-environment"),
                    workflow.replace(MACOS_SOURCE_READER_ACTION_SHA, "0" * 40),
                    workflow.replace("permission-contents: read", "permission-contents: write"),
                    workflow.replace(
                        "if: ${{ always() && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}",
                        "if: ${{ success() && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}",
                        1,
                    ),
                    workflow.replace("repositories: ${{ secrets.SOURCE_REPOSITORY_NAME }}", "repositories: "),
                ):
                    with self.assertRaises(PolicyError):
                        validate_workflow_text(changed, "platform", workflow_kind)

    def test_bootstrap_workflows_are_fixed_manual_main_only_and_publicly_audited(self):
        cases = (
            (
                MACOS_RULES_BOOTSTRAP_WORKFLOW,
                "macos-rules-bootstrap",
                MACOS_RULES_BOOTSTRAP_WORKFLOW_SHA256,
                "rules-source-read",
                "macos-rules-bootstrap-settings",
                "macos-rules-bootstrap",
                "macos-rules-bootstrap-audit",
            ),
            (
                MACOS_CORE_BOOTSTRAP_WORKFLOW,
                "macos-core-bootstrap",
                MACOS_CORE_BOOTSTRAP_WORKFLOW_SHA256,
                "source-read",
                "macos-public-snapshot",
                "macos-core-bootstrap",
                "macos-core-bootstrap-audit",
            ),
        )
        for path, workflow_kind, digest, environment, settings_job, producer_job, audit_job in cases:
            with self.subTest(workflow=workflow_kind):
                workflow = path.read_text(encoding="utf-8")
                self.assertEqual(hashlib.sha256(workflow.encode("utf-8")).hexdigest(), digest)
                self.assertTrue(validate_workflow_text(workflow, "platform", workflow_kind))
                self.assertTrue(workflow.startswith(
                    "name: " + workflow_kind + "\non:\n  workflow_dispatch:\n"
                ))
                self.assertIn("cache-mode: none\npermissions: {}", workflow)
                self.assertIn("github.ref == 'refs/heads/main'", workflow)
                self.assertIn("environment: " + environment, workflow)
                self.assertEqual(workflow.count("environment:"), 1)
                self.assertIn("  " + settings_job + ":\n", workflow)
                self.assertIn("  " + producer_job + ":\n", workflow)
                self.assertIn("  " + audit_job + ":\n", workflow)
                self.assertIn("if: ${{ always() && github.event_name == 'workflow_dispatch'", workflow)
                self.assertIn("actions: read\n      checks: read", workflow)
                self.assertIn("uses: actions/create-github-app-token@" + MACOS_SOURCE_READER_ACTION_SHA, workflow)
                self.assertIn("permission-contents: read", workflow)
                self.assertNotIn("actions/checkout", workflow)
                self.assertNotIn("upload-artifact", workflow)
                self.assertNotIn("download-artifact", workflow)
                self.assertNotIn("workflow_call:", workflow)
                self.assertNotIn("pull_request:", workflow)
                self.assertNotIn("pull_request_target:", workflow)
                self.assertNotRegex(workflow, r"(?m)^\s*GITHUB_STEP_SUMMARY:")
                settings_section = workflow.split("  " + settings_job + ":\n", 1)[1].split(
                    "  " + producer_job + ":\n", 1
                )[0]
                audit_section = workflow.split("  " + audit_job + ":\n", 1)[1]
                self.assertNotIn("SOURCE_READER_PRIVATE_KEY", settings_section)
                self.assertNotIn("SOURCE_READER_APP_PRIVATE_KEY", settings_section)
                self.assertNotIn("SOURCE_READER_PRIVATE_KEY", audit_section)
                self.assertNotIn("SOURCE_READER_APP_PRIVATE_KEY", audit_section)
                if workflow_kind == "macos-rules-bootstrap":
                    refusal_pattern = next(
                        line for line in workflow.splitlines() if "refusal_re=" in line
                    )
                    for reason in (
                        "invalid_input",
                        "context_unavailable",
                        "configuration_unavailable",
                        "source_reader_unavailable",
                        "repository_scope_invalid",
                        "source_fetch_unavailable",
                        "revocation_unconfirmed",
                        "base_invalid",
                        "signature_invalid",
                        "revocation_policy_invalid",
                        "bootstrap_snapshot_invalid",
                        "bootstrap_not_approved",
                        "binding_invalid",
                        "interface_unavailable",
                        "observer_unavailable",
                        "capture_invalid",
                        "cleanup_incomplete",
                        "internal_error",
                    ):
                        self.assertIn(reason, refusal_pattern)
                    for stage in (
                        "observer_import",
                        "observer_interface_hardware",
                        "observer_interface_capture",
                        "observer_interface_address",
                        "observer_interface",
                        "observer_binding",
                        "observer_start",
                        "observer_finish",
                        "observer_parse",
                        "observer_record",
                        "observer_missing",
                        "cleanup_lease",
                        "cleanup_storage",
                        "cleanup_worker",
                        "cleanup_summary",
                        "cleanup_dash",
                        "cleanup_unknown",
                        "cleanup_summary_census",
                        "cleanup_summary_present",
                        "cleanup_summary_probe",
                        "cleanup_summary_restore",
                        "cleanup_summary_close",
                        "cleanup_summary_present_python",
                        "cleanup_summary_present_ps",
                        "cleanup_summary_present_developer_shim",
                        "cleanup_summary_present_helper_preferences",
                        "cleanup_summary_present_helper_notifications",
                        "cleanup_summary_present_helper_launch_services",
                        "cleanup_summary_present_helper_security",
                        "cleanup_summary_present_helper_trust",
                        "cleanup_summary_present_helper_containers",
                        "cleanup_summary_present_apple_system_path",
                        "cleanup",
                    ):
                        self.assertIn(stage, refusal_pattern)
                    for stage in (
                        "cleanup_cache",
                        "cleanup_private",
                        "cleanup_unknown_extra",
                        "cleanup_summary_present_unknown",
                    ):
                        self.assertNotIn(stage, refusal_pattern)
                    self.assertNotIn("arguments_invalid", refusal_pattern)
                    refusal_source = re.search(r'refusal_re="([^"]+)"', refusal_pattern).group(1)
                    refusal_source = refusal_source.replace(
                        "${marker_prefix}", "macos-rules-bootstrap="
                    ).replace("${refusal_state}", "refused")
                    refusal_parser = re.compile(refusal_source)
                    summary_cleanup_stages = (
                        "cleanup_summary_census",
                        "cleanup_summary_present",
                        "cleanup_summary_probe",
                        "cleanup_summary_restore",
                        "cleanup_summary_close",
                        "cleanup_summary_present_python",
                        "cleanup_summary_present_ps",
                        "cleanup_summary_present_developer_shim",
                        "cleanup_summary_present_helper_preferences",
                        "cleanup_summary_present_helper_notifications",
                        "cleanup_summary_present_helper_launch_services",
                        "cleanup_summary_present_helper_security",
                        "cleanup_summary_present_helper_trust",
                        "cleanup_summary_present_helper_containers",
                        "cleanup_summary_present_apple_system_path",
                    )
                    control_sha = "c" * 40
                    run_id = "103"
                    run_attempt = "2"
                    for stage in summary_cleanup_stages:
                        marker = (
                            "macos-rules-bootstrap=refused schema=1 reason=cleanup_incomplete "
                            f"stage={stage} control-sha={control_sha} run-id={run_id} "
                            f"run-attempt={run_attempt} token-revocation=confirmed"
                        )
                        match = refusal_parser.fullmatch(marker)
                        self.assertIsNotNone(match, stage)
                        self.assertEqual(len(match.groups()), 6)
                        self.assertEqual(
                            match.groups()[2:],
                            (control_sha, run_id, run_attempt, "confirmed"),
                        )
                    self.assertIsNone(
                        refusal_parser.fullmatch(
                            "macos-rules-bootstrap=refused schema=1 reason=cleanup_incomplete "
                            f"stage=cleanup_summary_present_unknown control-sha={control_sha} "
                            f"run-id={run_id} run-attempt={run_attempt} "
                            "token-revocation=confirmed"
                        )
                    )
                    self.assertIn("RULES_ID_DEFINITIONS", workflow)
                    self.assertIn("SOURCE_CANDIDATE_REF", workflow)
                    self.assertIn("Validate source-reader scope configuration", workflow)
                    self.assertIn("SOURCE_REPOSITORY_ID\" != \"1428198872\"", workflow)
                    self.assertIn("macos-rules-source-binding=", workflow)
                    self.assertIn("Revoke token if bootstrap did not confirm", workflow)
                    self.assertIn("run --token-stdin", workflow)
                    self.assertIn("--phase revoke --token-stdin", workflow)
                    self.assertNotIn('SOURCE_READER_TOKEN="$SOURCE_READER_TOKEN"', workflow)
                    self.assertIn("marker_prefix='macos-rules-bootstrap='", workflow)
                    self.assertIn('network_dns_count="${BASH_REMATCH[6]}"', workflow)
                    self.assertIn('network_tcp_count="${BASH_REMATCH[7]}"', workflow)
                    self.assertIn('network_dns_count="${BASH_REMATCH[6]}"', workflow)
                    self.assertIn('network_tcp_count="${BASH_REMATCH[7]}"', workflow)
                    self.assertIn('refusal_control="${BASH_REMATCH[3]}"', workflow)
                    self.assertIn('refusal_run="${BASH_REMATCH[4]}"', workflow)
                    self.assertIn('refusal_attempt="${BASH_REMATCH[5]}"', workflow)
                    self.assertIn('token_state="${BASH_REMATCH[6]}"', workflow)
                    self.assertNotIn("macos-rules-bootstrap=passed", workflow)
                    self.assertNotIn("macos-rules-bootstrap=refused", workflow)
                    self.assertNotIn('{"metadata":', workflow)
                    self.assertIn("Write trusted summary visibility control", workflow)
                else:
                    self.assertIn("core-bootstrap-settings", workflow)
                    self.assertIn("core-bootstrap-snapshot", workflow)
                    self.assertIn("Core preflight", workflow)
                    self.assertIn("      - name: Write trusted summary visibility control\n", workflow)
                    self.assertLess(
                        workflow.index("      - name: Core preflight\n"),
                        workflow.index("      - name: Write trusted summary visibility control\n"),
                    )
                    self.assertLess(
                        workflow.index("      - name: Write trusted summary visibility control\n"),
                        workflow.index("      - name: Validate reader settings\n"),
                    )
                    generic_summary = workflow.split(
                        "      - name: Write trusted summary visibility control\n", 1
                    )[1].split("      - name: Validate reader settings\n", 1)[0]
                    self.assertIn('summary_prefix="macos-summary-"', generic_summary)
                    self.assertIn("control=trusted-write schema=1 control-sha=$CI_SHA", generic_summary)
                    self.assertIn('printf \'%s\\n\' "$summary_line" >> "$GITHUB_STEP_SUMMARY"', generic_summary)
                    self.assertNotIn("source-sha", generic_summary)
                    self.assertIn("Validate reader settings", workflow)
                    self.assertIn('"$SOURCE_REPOSITORY_ID" != "1430959909"', workflow)
                    self.assertIn(
                        "SOURCE_TOKEN_INSTALLATION_ID: ${{ steps.source-token.outputs.installation-id }}",
                        workflow,
                    )
                    self.assertIn(
                        '"$SOURCE_TOKEN_INSTALLATION_ID" != "$SOURCE_READER_INSTALLATION_ID"',
                        workflow,
                    )
                    self.assertNotIn('SOURCE_READER_TOKEN="$SOURCE_READER_TOKEN"', workflow)
                    self.assertIn("macos-core-source-binding=", workflow)
                    self.assertIn("Validate core bootstrap", workflow)
                    core_tree = ast.parse(MACOS_CORE_BOOTSTRAP_SOURCE.read_text(encoding="utf-8"))
                    source_reasons = None
                    for statement in core_tree.body:
                        if not isinstance(statement, ast.Assign):
                            continue
                        if not any(
                            isinstance(target, ast.Name)
                            and target.id == "SOURCE_VALIDATION_REASONS"
                            for target in statement.targets
                        ):
                            continue
                        value = statement.value
                        if (not isinstance(value, ast.Call)
                                or not isinstance(value.func, ast.Name)
                                or value.func.id != "frozenset"
                                or len(value.args) != 1):
                            raise AssertionError("core source refusal reasons must be a closed literal set")
                        source_reasons = set(ast.literal_eval(value.args[0]))
                        break
                    self.assertIsNotNone(source_reasons)
                    refusal_line = next(
                        line for line in workflow.splitlines()
                        if line.strip().startswith("refusal_re=")
                    )
                    workflow_reasons = set(
                        refusal_line.split(" reason=(", 1)[1]
                        .split(") stage=", 1)[0]
                        .split("|")
                    )
                    self.assertTrue(source_reasons.issubset(workflow_reasons))
                    self.assertIn("--token-stdin", workflow)
                    self.assertIn("--phase revoke --token-stdin", workflow)
                    self.assertIn("token-revocation=(not-read|confirmed|unconfirmed)", workflow)
                    self.assertIn("marker_prefix='macos-core-bootstrap='", workflow)
                    self.assertIn("binding_prefix='macos-core-source-binding='", workflow)
                    self.assertNotIn("macos-core-bootstrap=verified", workflow)
                    self.assertNotIn("macos-core-bootstrap=refused", workflow)
                    self.assertNotIn("macos-core-source-binding=verified", workflow)
                    self.assertNotIn('{"metadata":', workflow)
                for changed in (
                    workflow.replace("cache-mode: none", "cache-mode: write", 1),
                    workflow.replace(environment, "invalid-environment", 1),
                    workflow.replace(MACOS_SOURCE_READER_ACTION_SHA, "0" * 40),
                    workflow.replace("actions: read\n      checks: read", "actions: write\n      checks: read"),
                    workflow.replace("always() && github.event_name", "success() && github.event_name", 1),
                ):
                    with self.assertRaises(PolicyError):
                        validate_workflow_text(changed, "platform", workflow_kind)

    def test_core_contract_workflow_is_a_fixed_protected_source_read_lane(self):
        workflow = MACOS_CORE_CONTRACT_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(workflow.encode("utf-8")).hexdigest(), MACOS_CORE_CONTRACT_WORKFLOW_SHA256)
        self.assertTrue(validate_workflow_text(workflow, "platform", "macos-core-contract"))
        self.assertTrue(workflow.startswith("name: macos-core-contract\non:\n  workflow_dispatch:\n"))
        self.assertIn("cache-mode: none\npermissions: {}", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("environment: source-read", workflow)
        self.assertEqual(workflow.count("environment:"), 1)
        for job in (
            "macos-core-contract-settings",
            "macos-core-contract",
            "macos-core-contract-audit",
        ):
            self.assertIn("  " + job + ":\n", workflow)
        self.assertIn("if: ${{ always() && github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn("actions: read\n      checks: read", workflow)
        self.assertIn("uses: actions/create-github-app-token@" + MACOS_SOURCE_READER_ACTION_SHA, workflow)
        self.assertIn("permission-contents: read", workflow)
        self.assertIn("permission-metadata: read", workflow)
        self.assertIn("CORE_CONTRACT_ALLOWED_SHA", workflow)
        self.assertIn("CORE_CONTRACT_ALLOWED_CONTROL_SHA", workflow)
        for binding in (
            "CORE_CONTRACT_REVIEWED_SOURCE_SHA",
            "CORE_CONTRACT_REVIEWED_BASE_SHA",
            "CORE_CONTRACT_REVIEWED_BASE_BRANCH",
            "CORE_CONTRACT_REVIEWED_CANDIDATE_REF",
            "CORE_CONTRACT_REVIEWED_DIFF_SHA256",
        ):
            self.assertIn(binding, workflow)
        self.assertLess(workflow.index("Run source-free reviewed build smoke"), workflow.index("Mint scoped source-reader token"))
        self.assertLess(workflow.index("Run source-free Rust toolchain smoke"), workflow.index("Mint scoped source-reader token"))
        self.assertLess(workflow.index("Validate protected contract binding"), workflow.index("Mint scoped source-reader token"))
        self.assertIn("--token-stdin", workflow)
        self.assertIn("--source-sha \"$REQUESTED_SOURCE_SHA\" --base-sha \"$REQUESTED_BASE_SHA\"", workflow)
        self.assertIn("--base-branch \"$REQUESTED_BASE_BRANCH\"", workflow)
        self.assertIn("core-contract-publish", workflow)
        self.assertIn(">\"$stdout_file\" 2>\"$stderr_file\"", workflow)
        self.assertIn("<\"$stdout_file\" >\"$validated_file\" 2>\"$validator_stderr_file\"", workflow)
        self.assertIn("Revoke token if contract did not confirm", workflow)
        self.assertIn("--phase revoke --token-stdin", workflow)
        self.assertIn('contract_prefix="macos-core-contract-"', workflow)
        self.assertIn("printf '%sbinding=verified", workflow)
        self.assertIn('cleanup_marker_prefix="macos-core-contract-"', workflow)
        self.assertIn("printf '%scleanup=confirmed", workflow)
        self.assertIn('2>/dev/null >> "$GITHUB_OUTPUT"', workflow)
        self.assertNotIn("KD-CORE-CONTRACT ", workflow)
        self.assertNotIn("KD-CORE-CONTRACT-REFUSAL ", workflow)
        self.assertNotIn("macos-core-contract-binding=", workflow)
        self.assertNotIn("macos-core-contract-cleanup=", workflow)
        binding_output = next(line for line in workflow.splitlines() if "candidate-class=%s reviewed-diff-sha256=%s" in line)
        self.assertNotIn("CORE_CONTRACT_REVIEWED_CANDIDATE_REF", binding_output)
        for forbidden in (
            "actions/checkout",
            "upload-artifact",
            "download-artifact",
            "workflow_call:",
            "pull_request:",
            "pull_request_target:",
            chr(47) + "Users/",
            "keeldock" + "-" + "core",
            "keeldock" + "-" + "host-api",
            "keeldock" + "-" + "host-mock",
            "keeldock" + "-" + "host-conformance",
            "/usr/bin/python3",
        ):
            self.assertNotIn(forbidden, workflow)
        for changed in (
            workflow.replace("cache-mode: none", "cache-mode: write", 1),
            workflow.replace("environment: source-read", "environment: untrusted", 1),
            workflow.replace(MACOS_SOURCE_READER_ACTION_SHA, "0" * 40),
            workflow.replace("actions: read\n      checks: read", "actions: write\n      checks: read"),
            workflow.replace("always() && github.event_name", "success() && github.event_name", 1),
            workflow.replace("permission-contents: read", "permission-contents: write", 1),
            workflow.replace("core-contract-publish", "missing-publisher", 1),
        ):
            with self.assertRaises(PolicyError):
                validate_workflow_text(changed, "platform", "macos-core-contract")

    def test_actual_workflow_rejects_skips_masking_extra_execution_and_filters(self):
        base = self._platform_workflow()
        mutations = (
            base.replace("        uses: ./kit/bootstrap\n", "        if: ${{ false }}\n        uses: ./kit/bootstrap\n"),
            base.replace("        uses: ./kit/bootstrap\n", "        continue-on-error: true\n        uses: ./kit/bootstrap\n"),
            base.replace(
                "      - name: Run source-free policy checks\n",
                "      - name: Extra execution\n        run: echo extra\n      - name: Run source-free policy checks\n",
            ),
            base.replace("      fail-fast: true\n", "      fail-fast: false\n"),
            base.replace("      fail-fast: true\n", "      fail-fast: true\n      excludes: []\n"),
            base.replace("  policy:\n", "  policy:\n    if: ${{ false }}\n"),
            base.replace("      - name: Fetch public candidate\n", ""),
            base.replace("      CI_SHA: ${{ github.sha }}\n", "      CI_SHA: ${{ github.ref }}\n"),
            base + "  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform")

    def test_consumer_workflow_requires_shared_platform_origin_and_full_sha(self):
        pin = "a" * 40
        shared_origin = "keeldock-platform/platform-ci/kit/bootstrap@" + pin
        workflow = (
            "name: public-policy\non:\n  push:\n    branches:\n      - \"**\"\n"
            "  pull_request:\n  workflow_dispatch:\npermissions: {}\njobs:\n"
            "  policy:\n    name: policy-${{ matrix.runner }}\n    strategy:\n"
            "      fail-fast: true\n      matrix:\n        runner:\n"
            "          - ubuntu-24.04\n          - macos-15\n          - windows-2025\n"
            "    runs-on: ${{ matrix.runner }}\n    timeout-minutes: 10\n"
            "    env:\n      CI_SHA: ${{ github.sha }}\n    steps:\n"
            "      - name: Run source-free policy checks\n        uses: " + shared_origin + "\n"
            "        with:\n          pool: connect\n"
        )
        self.assertTrue(validate_workflow_text(workflow, "connect"))
        wrong_origins = (
            "keeldock" + "-" + "connect/connect" + "-ci/kit/bootstrap@" + pin,
            "keeldock" + "-" + "workspace/workspace" + "-ci/kit/bootstrap@" + pin,
            "keeldock-platform/platform-ci/kit/bootstrap@" + pin[:12],
            "keeldock-platform/platform-ci/kit/bootstrap@main",
        )
        for origin in wrong_origins:
            with self.subTest(origin=origin.split("@")[0]):
                with self.assertRaises(PolicyError):
                    validate_workflow_text(workflow.replace(shared_origin, origin), "connect")

    def test_manual_checkout_paths_disable_autocrlf_before_fetch_and_checkout(self):
        expected = "git init -q . 2>/dev/null\n          git config core.autocrlf false 2>/dev/null\n          git remote add origin"
        workflow = PLATFORM_WORKFLOW.read_text(encoding="utf-8")
        action = PLATFORM_ACTION.read_text(encoding="utf-8")
        self.assertIn(expected, workflow)
        self.assertIn(expected, action)

    def test_workflow_binary_checkout_stays_lf_when_global_autocrlf_is_true(self):
        expected = PLATFORM_WORKFLOW.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            global_config = root / "global-config"
            global_config.write_text("[core]\n\tautocrlf = true\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                {
                    "GIT_CONFIG_GLOBAL": str(global_config),
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_AUTHOR_NAME": "Policy test",
                    "GIT_AUTHOR_EMAIL": "policy-test@example.invalid",
                    "GIT_COMMITTER_NAME": "Policy test",
                    "GIT_COMMITTER_EMAIL": "policy-test@example.invalid",
                }
            )

            def git(directory, *arguments):
                return subprocess.run(
                    ["git"] + list(arguments),
                    cwd=str(directory),
                    env=environment,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

            source = root / "source"
            source.mkdir()
            git(source, "init", "-q")
            git(source, "config", "core.autocrlf", "false")
            source_workflow = source / ".github/workflows/public-policy.yml"
            source_workflow.parent.mkdir(parents=True)
            source_workflow.write_bytes(expected)
            git(source, "add", ".github/workflows/public-policy.yml")
            git(source, "commit", "-q", "-m", "line-ending fixture")
            source_sha = git(source, "rev-parse", "HEAD").stdout.strip()

            checkout = root / "checkout"
            checkout.mkdir()
            git(checkout, "init", "-q")
            self.assertEqual(git(checkout, "config", "--get", "core.autocrlf").stdout.strip(), "true")
            git(checkout, "config", "core.autocrlf", "false")
            git(checkout, "remote", "add", "origin", str(source))
            git(checkout, "fetch", "--quiet", "--no-tags", "--depth=1", "origin", source_sha)
            git(checkout, "checkout", "--quiet", "--detach", "FETCH_HEAD")

            checked_out = (checkout / ".github/workflows/public-policy.yml").read_bytes()
            self.assertEqual(checked_out, expected)
            self.assertTrue(validate_workflow_text(checked_out.decode("utf-8"), "platform"))


class LaneRegistryTests(unittest.TestCase):
    def test_registry_is_a_fixed_static_set_of_the_three_lane_modules(self):
        self.assertEqual(policy.LANE_MODULES, (policy_linux, policy_windows, policy_handoff))
        self.assertIs(type(policy.LANE_MODULES), tuple)

    def test_registry_maps_each_lane_kind_to_exactly_one_lane(self):
        self.assertEqual(policy.LANE_MODULES, (policy_linux, policy_windows, policy_handoff))
        self.assertEqual(
            {kind: module for kind, module in policy.WORKFLOW_KIND_LANES.items()},
            {
                kind: module
                for module in policy.LANE_MODULES
                for kind in tuple(module.WORKFLOW_TEMPLATES) + tuple(module.WORKFLOW_SHA256)
            },
        )
        self.assertEqual(
            set(policy.WORKFLOW_KIND_LANES),
            {
                "linux-confinement",
                "windows-native-preflight",
                "windows-confinement",
                "windows-handoff-synthetic",
            },
        )
        self.assertIs(policy.WORKFLOW_KIND_LANES["linux-confinement"], policy_linux)
        self.assertIs(policy.WORKFLOW_KIND_LANES["windows-native-preflight"], policy_windows)
        self.assertIs(policy.WORKFLOW_KIND_LANES["windows-confinement"], policy_windows)
        self.assertIs(policy.WORKFLOW_KIND_LANES["windows-handoff-synthetic"], policy_handoff)
        self.assertEqual(
            set(policy.LANE_WORKFLOW_TEMPLATES) | set(policy.LANE_WORKFLOW_SHA256),
            set(policy.WORKFLOW_KIND_LANES),
        )
        self.assertFalse(set(policy.LANE_WORKFLOW_TEMPLATES) & set(policy.LANE_WORKFLOW_SHA256))

    def test_lane_kinds_never_overlap_the_shared_kinds(self):
        self.assertFalse(set(policy.WORKFLOW_KIND_LANES) & set(policy.SHARED_WORKFLOW_KINDS))
        self.assertIn("public-policy", policy.SHARED_WORKFLOW_KINDS)
        self.assertIn("node-lock-smoke", policy.SHARED_WORKFLOW_KINDS)
        self.assertIn("macos-capability", policy.SHARED_WORKFLOW_KINDS)

    def test_registry_views_are_read_only(self):
        for view in (
            policy.LANE_WORKFLOW_TEMPLATES,
            policy.LANE_WORKFLOW_SHA256,
            policy.WORKFLOW_KIND_LANES,
        ):
            with self.assertRaises(TypeError):
                view["injected"] = "value"

    def test_candidate_workflows_follow_lane_order(self):
        self.assertEqual(
            policy.LANE_CANDIDATE_WORKFLOWS,
            (
                (".github/workflows/linux-confinement.yml", "linux-confinement", "linux-workflow-too-large"),
                (
                    ".github/workflows/windows-native-preflight.yml",
                    "windows-native-preflight",
                    "windows-workflow-too-large",
                ),
                (
                    ".github/workflows/windows-confinement.yml",
                    "windows-confinement",
                    "windows-confinement-workflow-too-large",
                ),
                (
                    ".github/workflows/windows-handoff-synthetic.yml",
                    "windows-handoff-synthetic",
                    "handoff-workflow-too-large",
                ),
            ),
        )
        self.assertEqual(
            policy.LANE_CANDIDATE_WORKFLOWS,
            tuple(entry for module in policy.LANE_MODULES for entry in module.CANDIDATE_WORKFLOWS),
        )
        self.assertIn(
            (".github/workflows/linux-confinement.yml", "linux-confinement", "linux-workflow-too-large"),
            policy.LANE_CANDIDATE_WORKFLOWS,
        )
        self.assertIn(
            (
                ".github/workflows/windows-native-preflight.yml",
                "windows-native-preflight",
                "windows-workflow-too-large",
            ),
            policy.LANE_CANDIDATE_WORKFLOWS,
        )
        self.assertIn(
            (
                ".github/workflows/windows-confinement.yml",
                "windows-confinement",
                "windows-confinement-workflow-too-large",
            ),
            policy.LANE_CANDIDATE_WORKFLOWS,
        )
        self.assertIn(
            (
                ".github/workflows/windows-handoff-synthetic.yml",
                "windows-handoff-synthetic",
                "handoff-workflow-too-large",
            ),
            policy.LANE_CANDIDATE_WORKFLOWS,
        )

    def test_every_lane_module_exposes_the_same_interface(self):
        for module in policy.LANE_MODULES:
            with self.subTest(module=module.__name__):
                self.assertIsInstance(module.WORKFLOW_TEMPLATES, dict)
                self.assertIsInstance(module.WORKFLOW_SHA256, dict)
                self.assertIsInstance(module.CANDIDATE_WORKFLOWS, tuple)
                self.assertFalse(hasattr(module, "PolicyError"))

    def test_registry_construction_refuses_unsafe_lane_declarations(self):
        def lane(templates=None, digests=None, candidates=()):
            return types.SimpleNamespace(
                WORKFLOW_TEMPLATES=templates or {},
                WORKFLOW_SHA256=digests or {},
                CANDIDATE_WORKFLOWS=candidates,
            )

        shared = policy.SHARED_WORKFLOW_KINDS
        good_digest = "a" * 64
        self.assertEqual(
            policy.build_lane_registry((lane({"new-kind": "text"}),), shared)[0]["new-kind"],
            "text",
        )
        refused = (
            (lane({"public-policy": "text"}),),
            (lane({"macos-capability": "text"}),),
            (lane({"same-kind": "one"}), lane({"same-kind": "two"})),
            (lane({"same-kind": "one"}, {"same-kind": good_digest}),),
            (lane({1: "text"}),),
            (lane({"new-kind": 1}),),
            (lane(digests={"new-kind": "A" * 64}),),
            (lane(digests={"new-kind": "a" * 63}),),
            (lane(digests={"new-kind": good_digest + "\n"}),),
            (lane({"new-kind": "text"}, candidates=(("path", "other-kind", "code"),)),),
            (
                lane({"new-kind": "text"}),
                lane(candidates=(("path", "new-kind", "code"),)),
            ),
        )
        for lanes in refused:
            with self.subTest(lanes=repr(lanes)):
                with self.assertRaisesRegex(PolicyError, "workflow-registry"):
                    policy.build_lane_registry(lanes, shared)

    def test_digest_lane_kinds_are_checked_by_hash_and_platform_pool(self):
        text = "name: digest-lane\n"
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with patch.object(
            policy, "LANE_WORKFLOW_SHA256", {"digest-lane": digest}
        ), patch.object(policy, "LANE_WORKFLOW_TEMPLATES", {}):
            self.assertTrue(validate_workflow_text(text, "platform", "digest-lane"))
            with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                validate_workflow_text(text + " ", "platform", "digest-lane")
            with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                validate_workflow_text(text, "connect", "digest-lane")

    def test_unknown_workflow_kinds_are_still_refused(self):
        for kind in ("unknown", "windows-handoff", "", "Linux-Confinement"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(PolicyError, "workflow-kind"):
                    validate_workflow_text("name: x\n", "platform", kind)

    def test_moved_templates_keep_their_pre_split_digests_through_the_shared_module(self):
        self.assertEqual(
            hashlib.sha256(policy.LINUX_CONFINEMENT_WORKFLOW_TEMPLATE.encode("utf-8")).hexdigest(),
            "f7860a422e818f238232c395a100422ab32e5a6498737a8840d52a362b96b6ae",
        )
        self.assertEqual(
            hashlib.sha256(policy.WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE.encode("utf-8")).hexdigest(),
            "da294aadfc0e99cbe109aba90f9fb86df65867cd32d3325d26a9e9a5b035e5bb",
        )

    def test_shared_kinds_keep_accepting_and_refusing_as_before(self):
        root = Path(__file__).resolve().parents[2]
        shared_files = {
            "public-policy": ".github/workflows/public-policy.yml",
            "attestation-probe": ".github/workflows/attestation-probe.yml",
            "node-lock-smoke": ".github/workflows/node-lock-smoke.yml",
            "macos-capability": ".github/workflows/macos-capability.yml",
            "macos-reviewed-build": ".github/workflows/macos-reviewed-build.yml",
            "macos-rust-toolchain-smoke": ".github/workflows/macos-rust-toolchain-smoke.yml",
            "macos-cache-proof": ".github/workflows/macos-cache-proof.yml",
            "macos-source-reader": ".github/workflows/macos-source-reader-preflight.yml",
            "macos-rules-source-reader": ".github/workflows/macos-rules-reader-preflight.yml",
            "macos-rules-bootstrap": ".github/workflows/macos-rules-bootstrap.yml",
            "macos-core-bootstrap": ".github/workflows/macos-core-bootstrap.yml",
            "macos-core-contract": ".github/workflows/macos-core-contract.yml",
            "development-feedback-smoke": ".github/workflows/development-feedback-smoke.yml",
            "node-lock-return": ".github/workflows/node-lock-return.yml",
            "core-rust-format-return": ".github/workflows/core-rust-format-return.yml",
            "core-build-diagnostic-return": ".github/workflows/core-build-diagnostic-return.yml",
        }
        self.assertEqual(set(shared_files), set(policy.SHARED_WORKFLOW_KINDS))
        for kind, relative in shared_files.items():
            with self.subTest(kind=kind):
                text = (root / relative).read_text(encoding="utf-8")
                self.assertTrue(validate_workflow_text(text, "platform", kind))
                with self.assertRaises(PolicyError):
                    validate_workflow_text(text + "\n", "platform", kind)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(text, "connect", kind)
                for lane_kind in policy.WORKFLOW_KIND_LANES:
                    with self.assertRaises(PolicyError):
                        validate_workflow_text(text, "platform", lane_kind)


class PublicResultTests(unittest.TestCase):
    def test_safe_result_is_normalised_to_exact_public_fields(self):
        encoded = encode_public_result(result())
        self.assertEqual(
            json.loads(encoded),
            {"check_id": "public-policy", "status": "passed", "passed": 3, "failed": 0, "duration_ms": 12},
        )

    def test_unknown_ids_raw_fields_and_arbitrary_text_fail(self):
        value = json.loads(result())
        value["check_id"] = "unlisted-check"
        with self.assertRaisesRegex(PolicyError, "result-check-id"):
            validate_public_result(json.dumps(value).encode("utf-8"))
        for field in ("file", "title", "stdout", "stderr", "stack", "workspace", "token"):
            value = json.loads(result())
            value[field] = "opaque"
            with self.subTest(field_class="unknown"):
                with self.assertRaisesRegex(PolicyError, "result-fields"):
                    validate_public_result(json.dumps(value).encode("utf-8"))
        with self.assertRaisesRegex(PolicyError, "invalid-json"):
            validate_public_result(b"opaque private exception text")

    def test_duplicate_unknown_malformed_and_oversized_json_fail(self):
        with self.assertRaisesRegex(PolicyError, "duplicate-field"):
            validate_public_result(
                b'{"check_id":"public-policy","check_id":"other","status":"passed",'
                b'"passed":1,"failed":0,"duration_ms":1}'
            )
        with self.assertRaisesRegex(PolicyError, "result-fields"):
            validate_public_result(b"[]")
        with self.assertRaisesRegex(PolicyError, "invalid-number"):
            validate_public_result(
                b'{"check_id":"public-policy","status":"passed","passed":NaN,"failed":0,"duration_ms":1}'
            )
        with self.assertRaisesRegex(PolicyError, "invalid-json"):
            validate_public_result(b"\xff")
        with self.assertRaisesRegex(PolicyError, "input-too-large"):
            validate_public_result(b" " * 2049)

    def test_counts_status_and_duration_are_bounded_and_consistent(self):
        for changes, code in (
            ({"passed": True}, "result-count"),
            ({"passed": 100001}, "result-count"),
            ({"status": "passed", "failed": 1}, "result-status-counts"),
            ({"status": "failed", "failed": 0}, "result-status-counts"),
            ({"status": "skipped", "passed": 1}, "result-status-counts"),
            ({"duration_ms": -1}, "result-duration"),
            ({"duration_ms": 86400001}, "result-duration"),
        ):
            with self.subTest(code=code):
                with self.assertRaisesRegex(PolicyError, code):
                    validate_public_result(result(**changes))


if __name__ == "__main__":
    unittest.main(verbosity=2)
