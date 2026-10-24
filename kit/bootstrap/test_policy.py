import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from policy import (
    MACOS_CAPABILITY_WORKFLOW_TEMPLATE,
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
WINDOWS_NATIVE_PREFLIGHT_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/windows-native-preflight.yml"
PLATFORM_ACTION = Path(__file__).resolve().parent / "action.yml"


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
        launch = " -B kit/confinement/macos_capability.py --control-sha \"$CI_SHA\""
        for text in (MACOS_CAPABILITY_WORKFLOW.read_text(encoding="utf-8"), MACOS_CAPABILITY_WORKFLOW_TEMPLATE):
            with self.subTest(source=text[:20]):
                self.assertEqual(text.count(clt + launch), 1)
                self.assertEqual(text.count("confinement/macos_capability.py"), 1)
                self.assertNotIn("/usr/bin/python3 -B kit/confinement/macos_capability.py", text)
                self.assertNotIn("Versions/Current", text)
                privileged = [line for line in text.splitlines() if "confinement/macos_capability.py" in line]
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
                changed = workflow.replace(clt + " -B kit/confinement", replacement + " -B kit/confinement")
                self.assertNotEqual(changed, workflow)
                with self.assertRaisesRegex(PolicyError, "workflow-template-mismatch"):
                    validate_workflow_text(changed, "platform", "macos-capability")

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
