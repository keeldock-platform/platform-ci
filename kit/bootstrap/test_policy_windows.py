import hashlib
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import policy
import policy_windows
from policy import PolicyError, validate_workflow_text
from public_tree import PINNED_FILE_SHA256, PLATFORM_FILES, scan_tree


__all__ = [
    "WindowsWorkflowPolicyTests",
    "WindowsConfinementWorkflowTests",
    "WindowsLaneRegistryTests",
    "WindowsLanePublicTreeTests",
]

ROOT = Path(__file__).resolve().parents[2]
WINDOWS_NATIVE_PREFLIGHT_WORKFLOW = ROOT / ".github/workflows/windows-native-preflight.yml"
WINDOWS_CONFINEMENT_WORKFLOW = ROOT / ".github/workflows/windows-confinement.yml"
CAPSULE_VECTORS_WORKFLOW = ROOT / ".github/workflows/capsule-vectors.yml"
CAPSULE_FRAME_WRAPPER = ROOT / "kit/confinement/capsule_frame.ps1"
WINDOWS_WORKFLOW_SHA256_BEFORE_SPLIT = "da294aadfc0e99cbe109aba90f9fb86df65867cd32d3325d26a9e9a5b035e5bb"
WINDOWS_LANE_FILES = (
    ".github/workflows/windows-native-preflight.yml",
    "kit/bootstrap/policy_windows.py",
    "kit/bootstrap/test_policy_windows.py",
    "kit/confinement/windows_native_preflight.cs",
    "kit/confinement/windows_native_preflight.ps1",
    "kit/confinement/test_windows_native_preflight.py",
    ".github/workflows/windows-confinement.yml",
    "kit/confinement/windows_confinement.cs",
    "kit/confinement/windows_confinement.ps1",
    "kit/confinement/windows_confinement_recovery.ps1",
    "kit/confinement/test_windows_confinement.py",
    "kit/confinement/test_windows_confinement_recovery.ps1",
    ".github/workflows/capsule-vectors.yml",
    "kit/confinement/capsule_frame_vector_gate.py",
)


class WindowsWorkflowPolicyTests(unittest.TestCase):
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


class WindowsConfinementWorkflowTests(unittest.TestCase):
    def test_actual_confinement_workflow_matches_the_reviewed_template(self):
        workflow = WINDOWS_CONFINEMENT_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(workflow, "platform", "windows-confinement"))
        self.assertEqual(
            workflow.encode("utf-8"),
            policy_windows.WINDOWS_CONFINEMENT_WORKFLOW_TEMPLATE.encode("utf-8"),
        )
        self.assertEqual(workflow.count("runs-on: windows-2025\n"), 2)
        self.assertIn("permissions: {}\n", workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn("  push:\n", workflow)
        self.assertIn("  pull_request:\n", workflow)
        self.assertIn(
            "if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}",
            workflow,
        )
        self.assertIn("windows_confinement.ps1 -Mode compile", workflow)
        self.assertIn("windows_confinement.ps1 -Mode spike", workflow)
        self.assertIn("test_windows_confinement.py", workflow)
        for forbidden in (
            "inputs:",
            "secrets.",
            "uses:",
            "upload-artifact",
            "download-artifact",
            "attest",
            "cache:",
            "outputs:",
            "contents:",
            "id-token",
            "environment:",
            "continue-on-error",
            "pull_request_target",
            chr(35),
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "connect", "windows-confinement")
        with self.assertRaises(PolicyError):
            validate_workflow_text(workflow, "platform")

    def test_confinement_workflow_rejects_trigger_runner_and_execution_changes(self):
        base = WINDOWS_CONFINEMENT_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            base.replace("  pull_request:\n", "  pull_request_target:\n"),
            base.replace("  workflow_dispatch:\n", ""),
            base.replace("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", "true"),
            base.replace("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/feature'"),
            base.replace("runs-on: windows-2025", "runs-on: windows-latest", 1),
            base.replace("permissions: {}\n", "permissions:\n  contents: read\n"),
            base.replace("-Mode spike", "-Mode compile"),
            base.replace("      - name: Compile native confinement module\n", ""),
            base.replace("python -B kit/confinement/test_windows_confinement.py\n", ""),
            base.replace("    needs: windows-policy\n", ""),
            base.replace("        run: |\n", "        continue-on-error: true\n        run: |\n", 1),
            base.replace("    steps:\n", "    environment: source-read\n    steps:\n", 1),
            base + "  extra:\n    runs-on: windows-2025\n    steps: []\n",
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation_index=index):
                self.assertNotEqual(changed, base)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(changed, "platform", "windows-confinement")


class WindowsLaneRegistryTests(unittest.TestCase):
    def _run_capsule_generate(
        self, compile_lines, compile_exit, vector_lines=(), vector_exit=0,
        compile_throws=False, vector_throws=False,
    ):
        workflow = CAPSULE_VECTORS_WORKFLOW.read_text(encoding="ascii")
        start = "      - name: Compile and generate independent vectors\n        id: generate\n        run: |\n"
        end = "      - name: Preserve generated vectors for review\n"
        run_block = textwrap.dedent(workflow.split(start, 1)[1].split(end, 1)[0])

        def mock_branch(lines, exit_code, throws):
            if throws:
                return "    throw 'controlled failure'\n"
            output = "    $global:LASTEXITCODE = " + str(exit_code) + "\n"
            for line in lines:
                output += "    Write-Output '" + line.replace("'", "''") + "'\n"
            return output

        mock = (
            "$script:Invocation = 0\n"
            "function pwsh {\n"
            "  $script:Invocation += 1\n"
            "  if ($script:Invocation -eq 1) {\n"
            + mock_branch(compile_lines, compile_exit, compile_throws)
            + "  } else {\n"
            + mock_branch(vector_lines, vector_exit, vector_throws)
            + "  }\n"
            + "}\n"
        )
        powershell = shutil.which("pwsh")
        self.assertIsNotNone(powershell)
        with tempfile.TemporaryDirectory() as temporary:
            script_path = Path(temporary) / "generate.ps1"
            script_path.write_text(mock + run_block, encoding="utf-8")
            environment = os.environ.copy()
            environment["RUNNER_TEMP"] = temporary
            environment["GITHUB_OUTPUT"] = str(Path(temporary) / "output")
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-File", str(script_path)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            self.assertFalse((Path(temporary) / "capsule_frame_vectors.json").exists())
            self.assertFalse(Path(environment["GITHUB_OUTPUT"]).exists())
            return result

    def _assert_capsule_refusal(self, result, reason):
        self.assertEqual(result.returncode, 1)
        expected = "capsule-frame=refused reason=" + reason + "\n"
        self.assertTrue(result.stdout == expected, "capsule refusal output differs")
        self.assertFalse(result.stderr, "capsule refusal stderr was not empty")

    def test_capsule_frame_refusal_subreasons_are_fixed_and_routed(self):
        wrapper = CAPSULE_FRAME_WRAPPER.read_text(encoding="ascii")
        workflow = CAPSULE_VECTORS_WORKFLOW.read_text(encoding="ascii")
        reasons = (
            "compiler_missing",
            "compile_failed",
            "vector_generation_failed",
            "vector_mismatch",
            "encoding",
        )
        expected_allowlist = "$script:RefusalReasons = @(\n" + "\n".join(
            "    '" + reason + "'," if index < len(reasons) - 1 else "    '" + reason + "'"
            for index, reason in enumerate(reasons)
        ) + "\n)"
        self.assertIn(expected_allowlist, wrapper)
        self.assertIn("capsule-frame=refused reason=' + $Reason", wrapper)
        self.assertIn("-notcontains $Reason", wrapper)
        self.assertIn(
            "^capsule-frame=refused reason=(compiler_missing|compile_failed|vector_generation_failed|vector_mismatch|encoding)$",
            workflow,
        )
        self.assertIn(r"'[^\x00-\x7F]'", workflow)
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assertIn("Write-Refusal '" + reason + "'", wrapper)
                self.assertIn("Write-CapsuleRefusal '" + reason + "'", workflow)
                self.assertIn(reason, workflow)
        self.assertIn("Forward-CapsuleRefusal $compileOutput 'compile_failed'", workflow)
        self.assertIn("Forward-CapsuleRefusal $vectorOutput 'vector_generation_failed'", workflow)
        self.assertIn("2>$null", workflow)

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell routing")
    def test_capsule_generate_forwards_only_allowlisted_refusals(self):
        compiled = ("capsule-frame-compile=observed result=compiled",)
        for reason in ("compiler_missing", "compile_failed"):
            with self.subTest(stage="compile", reason=reason):
                result = self._run_capsule_generate(
                    ("capsule-frame=refused reason=" + reason,), 1,
                )
                self._assert_capsule_refusal(result, reason)
        for reason in ("vector_generation_failed", "vector_mismatch", "encoding"):
            with self.subTest(stage="vectors", reason=reason):
                result = self._run_capsule_generate(
                    compiled, 0, ("capsule-frame=refused reason=" + reason,), 1,
                )
                self._assert_capsule_refusal(result, reason)

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell routing")
    def test_capsule_generate_suppresses_unexpected_child_output(self):
        compiled = ("capsule-frame-compile=observed result=compiled",)
        marker = "UNEXPECTED_OUTPUT_MARKER"
        cases = (
            ("compile_multiline", (marker, "capsule-frame=refused reason=compile_failed"),
             1, (), 0, "compile_failed"),
            ("compile_success", (marker,), 0, (), 0, "compile_failed"),
            ("vector_multiline", compiled, 0,
             (marker, "capsule-frame=refused reason=encoding"), 1, "vector_generation_failed"),
            ("vector_unlisted", compiled, 0,
             ("capsule-frame=refused reason=unlisted",), 1, "vector_generation_failed"),
            ("vector_success_multiline", compiled, 0, (marker, marker), 0, "vector_mismatch"),
            ("vector_success_singleline", compiled, 0, (marker,), 0, "vector_mismatch"),
            ("vector_refusal_with_success_exit", compiled, 0,
             ("capsule-frame=refused reason=encoding",), 0, "vector_mismatch"),
            ("vector_non_ascii", compiled, 0, ("value" + chr(233),), 0, "encoding"),
        )
        for name, compile_lines, compile_exit, vector_lines, vector_exit, reason in cases:
            with self.subTest(case=name):
                result = self._run_capsule_generate(
                    compile_lines, compile_exit, vector_lines, vector_exit,
                )
                self._assert_capsule_refusal(result, reason)
                self.assertFalse(
                    marker in result.stdout + result.stderr,
                    "unexpected child output was forwarded",
                )

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell routing")
    def test_capsule_generate_catches_child_errors_without_echoing_them(self):
        compiled = ("capsule-frame-compile=observed result=compiled",)
        for stage in ("compile", "vectors"):
            with self.subTest(stage=stage):
                result = self._run_capsule_generate(
                    compiled, 0, compile_throws=stage == "compile",
                    vector_throws=stage == "vectors",
                )
                self._assert_capsule_refusal(result, "compiler_missing")

    def test_capsule_vectors_exact_template_and_refusals(self):
        workflow = CAPSULE_VECTORS_WORKFLOW.read_text(encoding="ascii")
        self.assertEqual(workflow, policy_windows.CAPSULE_VECTORS_WORKFLOW_TEMPLATE)
        self.assertTrue(validate_workflow_text(workflow, "platform", "capsule-vectors"))
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn("runs-on: windows-2025", workflow)
        self.assertIn("capsule_frame.ps1 -Mode vectors", workflow)
        self.assertIn("capsule_frame_vector_gate.py", workflow)
        self.assertIn("capsule-vectors=refused reason=gate", workflow)
        self.assertNotIn("secrets.", workflow)
        for mutation in (
            workflow.replace("workflow_dispatch:", "push:"),
            workflow.replace("refs/heads/main", "refs/heads/feature"),
            workflow.replace("permissions: {}", "permissions:\n  contents: read", 1),
            workflow.replace("capsule_frame_vector_gate.py", "test_capsule_frame.py"),
            workflow.replace("capsule_frame.ps1 -Mode vectors", "capsule_frame.ps1 -Mode compile"),
            workflow.replace("capsule-vectors=refused reason=gate", "capsule-vectors=observed result=matched"),
            workflow + "\n",
        ):
            with self.subTest(mutation=mutation):
                self.assertNotEqual(mutation, workflow)
                with self.assertRaises(PolicyError):
                    validate_workflow_text(mutation, "platform", "capsule-vectors")
        with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
            validate_workflow_text(workflow, "connect", "capsule-vectors")

    def test_moved_template_is_byte_for_byte_the_pre_split_template(self):
        template = policy_windows.WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE
        self.assertEqual(
            hashlib.sha256(template.encode("utf-8")).hexdigest(),
            WINDOWS_WORKFLOW_SHA256_BEFORE_SPLIT,
        )
        self.assertEqual(
            PINNED_FILE_SHA256[".github/workflows/windows-native-preflight.yml"],
            WINDOWS_WORKFLOW_SHA256_BEFORE_SPLIT,
        )
        self.assertEqual(template.encode("utf-8"), WINDOWS_NATIVE_PREFLIGHT_WORKFLOW.read_bytes())

    def test_shared_policy_reexports_the_moved_template_unchanged(self):
        self.assertIs(
            policy.WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE,
            policy_windows.WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE,
        )

    def test_lane_declares_only_reviewed_windows_workflows_and_no_digest_pins(self):
        self.assertEqual(
            dict(policy_windows.WORKFLOW_TEMPLATES),
            {
                "windows-native-preflight": policy_windows.WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE,
                "windows-confinement": policy_windows.WINDOWS_CONFINEMENT_WORKFLOW_TEMPLATE,
                "capsule-vectors": policy_windows.CAPSULE_VECTORS_WORKFLOW_TEMPLATE,
            },
        )
        self.assertEqual(dict(policy_windows.WORKFLOW_SHA256), {})
        self.assertEqual(
            policy_windows.CANDIDATE_WORKFLOWS,
            (
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
                    ".github/workflows/capsule-vectors.yml",
                    "capsule-vectors",
                    "capsule-vectors-workflow-too-large",
                ),
            ),
        )

    def test_registry_routes_the_windows_kind_to_the_windows_lane(self):
        self.assertIs(policy.WORKFLOW_KIND_LANES["windows-native-preflight"], policy_windows)
        self.assertIs(policy.WORKFLOW_KIND_LANES["windows-confinement"], policy_windows)
        self.assertIs(policy.WORKFLOW_KIND_LANES["capsule-vectors"], policy_windows)
        self.assertEqual(
            policy.LANE_WORKFLOW_TEMPLATES["windows-confinement"],
            policy_windows.WINDOWS_CONFINEMENT_WORKFLOW_TEMPLATE,
        )
        self.assertEqual(
            policy.LANE_WORKFLOW_TEMPLATES["windows-native-preflight"],
            policy_windows.WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE,
        )
        self.assertEqual(
            policy.LANE_WORKFLOW_TEMPLATES["capsule-vectors"],
            policy_windows.CAPSULE_VECTORS_WORKFLOW_TEMPLATE,
        )
        for entry in policy_windows.CANDIDATE_WORKFLOWS:
            self.assertIn(entry, policy.LANE_CANDIDATE_WORKFLOWS)

    def test_dispatch_accepts_and_refuses_exactly_the_windows_template(self):
        template = policy_windows.WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE
        self.assertTrue(validate_workflow_text(template, "platform", "windows-native-preflight"))
        for pool in ("connect", "workspace", "data"):
            with self.subTest(pool=pool):
                with self.assertRaisesRegex(PolicyError, "workflow-kind-pool"):
                    validate_workflow_text(template, pool, "windows-native-preflight")
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(template + "\n", "platform", "windows-native-preflight")
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(template[:-1], "platform", "windows-native-preflight")
        with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
            validate_workflow_text(template, "platform")
        with self.assertRaisesRegex(PolicyError, "workflow-input"):
            validate_workflow_text(template.encode("utf-8"), "platform", "windows-native-preflight")


class WindowsLanePublicTreeTests(unittest.TestCase):
    def test_windows_lane_files_are_in_the_platform_allowlist_and_scan_clean(self):
        result = scan_tree(ROOT, "platform")
        for name in WINDOWS_LANE_FILES:
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
