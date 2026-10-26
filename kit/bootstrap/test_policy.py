import ast
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from policy import (
    MACOS_CAPABILITY_WORKFLOW_TEMPLATE,
    MACOS_CACHE_PROOF_ACTION_SHA,
    MACOS_CACHE_PROOF_WORKFLOW_TEMPLATE,
    MACOS_RULES_SOURCE_READER_WORKFLOW_SHA256,
    MACOS_REVIEWED_BUILD_WORKFLOW_TEMPLATE,
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


GOOD_SHA = "a" * 40
PLATFORM_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/public-policy.yml"
LINUX_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/linux-confinement.yml"
MACOS_CAPABILITY_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-capability.yml"
MACOS_REVIEWED_BUILD_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-reviewed-build.yml"
MACOS_CACHE_PROOF_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-cache-proof.yml"
MACOS_SOURCE_READER_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-source-reader-preflight.yml"
MACOS_RULES_SOURCE_READER_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/macos-rules-reader-preflight.yml"
MACOS_CACHE_CLIENT_ACTION = Path(__file__).resolve().parents[2] / "kit/confinement/macos_cache_client/action.yml"
MACOS_CACHE_CLIENT_SOURCE = Path(__file__).resolve().parents[2] / "kit/confinement/macos_cache_client/index.js"
WINDOWS_NATIVE_PREFLIGHT_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/windows-native-preflight.yml"
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

    def test_actual_platform_workflow_matches_closed_supported_shape(self):
        self.assertTrue(validate_workflow_text(self._platform_workflow(), "platform"))

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
        self.assertIn('if [[ -z "${ImageOS:-}" || -z "${ImageVersion:-}" ]]', workflow)
        self.assertIn('ImageOS="$ImageOS"', workflow)
        self.assertIn('ImageVersion="$ImageVersion"', workflow)
        smoke = workflow.split("  macos-reviewed-smoke:\n", 1)[1].split(
            "  macos-public-surface-audit:\n", 1
        )[0]
        self.assertNotIn("GITHUB_TOKEN", smoke)
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
                    'summary_line="${summary_prefix}control=trusted-write schema=1 control-sha=$CI_SHA run-id=$GITHUB_RUN_ID run-attempt=$GITHUB_RUN_ATTEMPT"',
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

    def test_actual_windows_native_preflight_matches_closed_manual_main_shape(self):
        workflow = WINDOWS_NATIVE_PREFLIGHT_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", "windows-native-preflight"))
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("runs-on: windows-2025", workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn("CI_WORKSPACE: ${{ github.workspace }}", workflow)
        self.assertIn("git fetch --quiet --no-tags --depth=1 origin $env:CI_REF", workflow)
        self.assertIn("$actualSha.Trim() -ne $env:CI_SHA", workflow)
        self.assertIn("test_windows_native_preflight.py", workflow)
        self.assertIn("windows_native_preflight.ps1", workflow)
        for forbidden in (
            "inputs:",
            "secrets.",
            "uses:",
            "upload-artifact",
            "download-artifact",
            "attest",
            "cache:",
            "outputs:",
            "contents: read",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "windows-native-preflight")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_windows_native_preflight_rejects_trigger_runner_and_execution_changes(self):
        base = WINDOWS_NATIVE_PREFLIGHT_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  workflow_dispatch:\n", "  push:\n"),
            base.replace("github.event_name == 'workflow_dispatch'", "github.event_name == 'push'"),
            base.replace("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/feature'"),
            base.replace("    runs-on: windows-2025\n", "    runs-on: windows-latest\n"),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n"),
            base.replace("      - name: Run source-free native diagnostic\n", ""),
            base.replace("python -B kit/confinement/test_windows_native_preflight.py\n", ""),
            base.replace("      - name: Validate source-free control tree\n", "      - name: Validate source-free control tree\n        continue-on-error: true\n"),
            base.replace("git fetch --quiet --no-tags --depth=1 origin $env:CI_REF", "git fetch --quiet origin main"),
            base.replace("$actualSha.Trim() -ne $env:CI_SHA", "$false"),
            base + "  extra:\n    runs-on: windows-2025\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "windows-native-preflight")

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
