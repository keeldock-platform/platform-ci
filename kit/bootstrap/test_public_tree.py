import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
import re

import check_candidate
from public_tree import PINNED_FILE_SHA256, PLATFORM_FILES, PublicTreeError, inspect_text, scan_tree


ROOT = Path(__file__).resolve().parents[2]
PROBE_WORKFLOW = ROOT / ".github/workflows/windows-attestation-permission-probe.yml"
PROBE_ACTION_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"
PROBE_SUBJECT_SHA = "cf46dd9088c858970cef86ae444af8cf0dec8d4fdcbc36af595220011689a0c8"
PINNED_ACTION_LOG_SOURCE_CONTRACT = {
    "sha": PROBE_ACTION_SHA,
    "main_source_excerpt": (
        "logAttestation(subjects, att, sigstoreInstance)\n"
        "if (inputs.showSummary) {\n"
        "await logSummary(att)\n"
        "} catch (err) {\n"
        "core.setFailed(err instanceof Error ? err : `${err}`)"
    ),
}


class PublicTreeTests(unittest.TestCase):
    def test_parent_runner_workspace_is_not_a_valid_checkout_root(self):
        with tempfile.TemporaryDirectory(prefix="platform-workspace-root-") as temporary:
            runner_parent = Path(temporary) / "runner-workspace"
            checkout_root = runner_parent / "platform-ci"
            checkout_root.mkdir(parents=True)
            for name in PLATFORM_FILES:
                source = ROOT / name
                destination = checkout_root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)

            subprocess.run(
                ["git", "init", "--quiet", "--template=/dev/null", str(checkout_root)],
                check=True,
                capture_output=True,
                timeout=10,
            )
            for key, value in (
                ("user.name", "Platform fixture"),
                ("user.email", "platform-fixture@example.invalid"),
                ("commit.gpgsign", "false"),
                ("core.hooksPath", "/dev/null"),
            ):
                subprocess.run(
                    ["git", "config", key, value],
                    cwd=str(checkout_root),
                    check=True,
                    capture_output=True,
                    timeout=10,
                )
            subprocess.run(
                ["git", "add", "--force", "--all"],
                cwd=str(checkout_root),
                check=True,
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["git", "commit", "--quiet", "--no-gpg-sign", "-m", "source-free workspace fixture"],
                cwd=str(checkout_root),
                check=True,
                capture_output=True,
                timeout=10,
            )
            sha = subprocess.run(
                ["git", "rev-parse", "--verify", "HEAD"],
                cwd=str(checkout_root),
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()

            with self.assertRaises(check_candidate.PolicyError) as refused:
                check_candidate.verify_git_head(runner_parent, sha)
            self.assertEqual(refused.exception.code, "control-head-unavailable")

            environment = os.environ.copy()
            environment.update(
                {
                    "RUNNER_WORKSPACE": str(runner_parent),
                    "CI_WORKSPACE": str(checkout_root),
                }
            )
            checker = [sys.executable, "-B", str(ROOT / "kit/bootstrap/check_candidate.py")]
            arguments = ["--pool", "platform", "--sha", sha]
            old_root = subprocess.run(
                checker + ["--root", environment["RUNNER_WORKSPACE"]] + arguments,
                cwd=str(checkout_root),
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(old_root.returncode, 1)
            self.assertEqual(old_root.stdout, "candidate-policy=refused\n")
            self.assertEqual(old_root.stderr, "")

            checkout = subprocess.run(
                checker + ["--root", environment["CI_WORKSPACE"]] + arguments,
                cwd=str(checkout_root),
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(checkout.returncode, 0)
            self.assertEqual(checkout.stdout, "candidate-policy=accepted control-sha=" + sha + "\n")
            self.assertEqual(checkout.stderr, "")

    def test_platform_candidate_has_only_the_allowlisted_tree(self):
        result = scan_tree(ROOT, "platform")
        self.assertEqual(set(result), set(PLATFORM_FILES))
        self.assertIn("kit/bootstrap/policy.py", result)
        self.assertIn(".github/workflows/windows-attestation-permission-probe.yml", result)
        self.assertIn(".github/workflows/macos-capability.yml", result)
        self.assertIn(".github/workflows/macos-reviewed-build.yml", result)
        self.assertIn(".github/workflows/macos-cache-proof.yml", result)
        self.assertIn(".github/workflows/macos-source-reader-preflight.yml", result)
        self.assertIn(".github/workflows/macos-rules-reader-preflight.yml", result)
        self.assertIn("kit/confinement/macos_boundary_guard.py", result)
        self.assertIn("kit/confinement/test_macos_boundary_guard.py", result)
        self.assertIn("kit/confinement/macos_canary_scan.py", result)
        self.assertIn("kit/confinement/macos_deny_default.py", result)
        self.assertIn("kit/confinement/test_macos_deny_default.py", result)
        self.assertIn("kit/confinement/macos_public_audit.py", result)
        self.assertIn("kit/confinement/test_macos_public_audit.py", result)
        self.assertIn("kit/confinement/macos_cache_client/action.yml", result)
        self.assertIn("kit/confinement/macos_cache_client/index.js", result)
        self.assertIn("kit/confinement/macos_reviewed_build.py", result)
        self.assertIn("kit/confinement/test_macos_reviewed_build.py", result)
        self.assertIn("kit/confinement/macos_network_observer.py", result)
        self.assertIn("kit/confinement/test_macos_network_observer.py", result)
        self.assertIn("kit/confinement/macos_source_reader.py", result)
        self.assertIn("kit/confinement/test_macos_source_reader.py", result)
        self.assertIn("kit/confinement/macos_harness.py", result)
        self.assertIn("kit/confinement/macos_capability.py", result)
        self.assertIn("kit/confinement/macos_capability.swift", result)
        self.assertIn("kit/confinement/test_macos_capability.py", result)
        self.assertIn("kit/confinement/test_macos_descriptors.py", result)

    def test_platform_allowlist_rejects_an_unreviewed_extra_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in PLATFORM_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name in PINNED_FILE_SHA256:
                    shutil.copyfile(ROOT / name, path)
                else:
                    path.write_text("safe\n", encoding="utf-8")
            scan_tree(root, "platform")
            (root / "kit/confinement/unreviewed.py").write_text("safe\n", encoding="utf-8")
            with self.assertRaisesRegex(PublicTreeError, "tree-shape"):
                scan_tree(root, "platform")

    def test_reviewed_native_and_source_controls_have_public_tree_hash_pins(self):
        expected = {
            '.github/workflows/node-lock-return.yml',
            '.github/workflows/core-rust-format-return.yml',
            '.github/workflows/core-build-diagnostic-return.yml',
            '.github/workflows/attestation-role-signer-probe.yml',
            '.github/workflows/windows-source-admission.yml',
            '.github/workflows/lane-h-windows-receiver.yml',
            '.github/workflows/lane-h-linux-fetch-encrypt.yml',
            '.github/workflows/lane-h-capsule-attester.yml',
            'kit/confinement/foundation_node_feedback.py',
            'kit/confinement/test_foundation_node_feedback.py',
            'kit/confinement/macos_node_contract.py',
            'kit/confinement/test_macos_node_contract.py',
            'kit/confinement/node_contract_validation.mjs',
            'kit/confinement/test_node_contract_validation.mjs',
            'kit/confinement/macos_feedback_producer.py',
            'kit/confinement/test_macos_feedback_producer.py',
            'kit/confinement/feedback_producer_crypto.mjs',
            'kit/confinement/test_feedback_producer_crypto.mjs',
            'kit/confinement/feedback_admin.py',
            'kit/confinement/test_feedback_admin.py',
            'kit/confinement/feedback_admin_crypto.mjs',
            'kit/confinement/test_feedback_admin_crypto.mjs',
            'kit/confinement/test_feedback_admin_integration.py',
            'kit/confinement/feedback_api.py',
            'kit/confinement/test_feedback_api.py',
            'kit/confinement/feedback_failure.py',
            'kit/confinement/test_feedback_failure.py',
            'kit/confinement/feedback_public_audit.py',
            'kit/confinement/test_feedback_public_audit.py',
            '.github/workflows/node-lock-smoke.yml',
            '.github/workflows/development-feedback-smoke.yml',
            'kit/confinement/development_feedback.mjs',
            'kit/confinement/test_development_feedback.mjs',
            'kit/confinement/feedback_request.py',
            'kit/confinement/test_feedback_request.py',
            'kit/confinement/feedback_smoke.mjs',
            'kit/confinement/test_feedback_smoke.mjs',
            'kit/confinement/feedback_smoke_audit.py',
            'kit/confinement/test_feedback_smoke_audit.py',
            'kit/confinement/node_lock_envelope.mjs',
            'kit/confinement/test_node_lock_envelope.mjs',
            'kit/confinement/node_lock_manifest.mjs',
            'kit/confinement/test_node_lock_manifest.mjs',
            'kit/confinement/node_lock_receipt.py',
            'kit/confinement/test_node_lock_receipt.py',
            '.github/workflows/macos-core-contract.yml',
            'kit/confinement/macos_core_contract.py',
            'kit/confinement/test_macos_core_contract.py',
            '.github/workflows/macos-rust-toolchain-smoke.yml',
            'kit/confinement/macos_rust_toolchain.py',
            'kit/confinement/test_macos_rust_toolchain.py',
            'kit/confinement/macos_rules_bootstrap.py',
            'kit/confinement/test_macos_rules_bootstrap.py',
            'kit/confinement/macos_core_bootstrap.py',
            'kit/confinement/test_macos_core_bootstrap.py',
            'kit/confinement/macos_network_observer.py',
            'kit/confinement/test_macos_network_observer.py',
            '.github/workflows/macos-rules-bootstrap.yml',
            '.github/workflows/macos-core-bootstrap.yml',
            'kit/confinement/macos_private_validation.py',
            'kit/confinement/test_macos_private_validation.py',
            'ci/revoked-signer-fingerprints',
            ".github/workflows/windows-native-preflight.yml",
            "kit/confinement/windows_native_preflight.cs",
            "kit/confinement/windows_native_preflight.ps1",
            "kit/confinement/test_windows_native_preflight.py",
            "kit/confinement/macos_source_reader.py",
            "kit/confinement/test_macos_source_reader.py",
            "kit/confinement/role_signer.py",
            "kit/confinement/test_role_signer.py",
            "kit/bootstrap/policy_handoff.py",
            "kit/bootstrap/test_policy_handoff.py",
        }
        self.assertEqual(set(PINNED_FILE_SHA256), expected)
        self.assertTrue(expected.issubset(PLATFORM_FILES))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in PLATFORM_FILES:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            scan_tree(root, "platform")
            edited = root / "kit/confinement/windows_native_preflight.cs"
            edited.write_text(edited.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(PublicTreeError, "file-hash-mismatch"):
                scan_tree(root, "platform")

    def test_role_signer_suite_is_registered_in_source_free_ci(self):
        workflow = (ROOT / ".github/workflows/core-rust-format-return.yml").read_text(encoding="utf-8")
        self.assertIn('unittest discover -s kit/confinement -p "test_role_signer.py"', workflow)

    def test_pinned_action_version_comment_is_the_only_permitted_comment(self):
        version_pin = "uses: actions/attest@" + PROBE_ACTION_SHA + " " + chr(35) + " v4.2.2"
        inspect_text(version_pin, "platform")
        for fixture in (
            "uses: actions/attest@main " + chr(35) + " v4.2.2",
            "uses: actions/attest@" + PROBE_ACTION_SHA + " " + chr(35) + " latest",
            "purpose " + chr(35) + " comment",
        ):
            with self.subTest(comment_class="unapproved"):
                with self.assertRaisesRegex(PublicTreeError, "comment-present"):
                    inspect_text(fixture, "platform")

    def test_permission_probe_is_manual_source_free_and_uses_only_reviewed_profiles(self):
        workflow = PROBE_WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(
            workflow.startswith(
                "name: windows-attestation-permission-probe\n"
                "on:\n  workflow_dispatch:\npermissions: {}\njobs:\n"
            )
        )
        for forbidden_trigger in (
            "inputs:",
            "workflow_call:",
            "pull_request:",
            "pull_request_target:",
            "push:\n",
        ):
            with self.subTest(forbidden_trigger=forbidden_trigger):
                self.assertNotIn(forbidden_trigger, workflow)
        self.assertIn("EVENT_NAME: ${{ github.event_name }}", workflow)
        self.assertIn("EVENT_REF: ${{ github.ref }}", workflow)
        self.assertIn("$env:EVENT_REF -ne 'refs/heads/main'", workflow)
        self.assertIn("synthetic permission probe subject v1`n", workflow)
        self.assertIn(PROBE_SUBJECT_SHA, workflow)

        lines = workflow.splitlines()
        jobs_index = lines.index("jobs:")
        job_starts = [
            index
            for index in range(jobs_index + 1, len(lines))
            if re.fullmatch(r"  [a-z0-9-]+:", lines[index])
        ]
        jobs = {}
        for position, start in enumerate(job_starts):
            end = (
                job_starts[position + 1]
                if position + 1 < len(job_starts)
                else len(lines)
            )
            jobs[lines[start].strip()[:-1]] = lines[start + 1 : end]
        expected_jobs = {
            "require-reviewed-main",
            "compare-probe-results",
            "common-intersection-ubuntu",
            "common-intersection-windows",
            "github-guide-ubuntu",
            "github-guide-windows",
            "actions-readme-ubuntu",
            "actions-readme-windows",
        }
        self.assertEqual(set(jobs), expected_jobs)
        self.assertIn("    permissions: {}", jobs["require-reviewed-main"])
        self.assertIn("    permissions: {}", jobs["compare-probe-results"])
        self.assertIn("    if: always()", jobs["compare-probe-results"])

        profiles = {
            "common-intersection": ["id-token: write", "attestations: write"],
            "github-guide": ["id-token: write", "contents: read", "attestations: write"],
            "actions-readme": [
                "id-token: write",
                "attestations: write",
                "artifact-metadata: write",
            ],
        }
        runner_labels = {"ubuntu": "ubuntu-24.04", "windows": "windows-2025"}
        for profile, permission_values in profiles.items():
            for runner_key, runner_label in runner_labels.items():
                job_name = f"{profile}-{runner_key}"
                block = jobs[job_name]
                self.assertIn("    needs: require-reviewed-main", block)
                self.assertIn(f"    runs-on: {runner_label}", block)
                permission_index = block.index("    permissions:")
                actual_permissions = []
                for line in block[permission_index + 1 :]:
                    if not line.startswith("      "):
                        break
                    actual_permissions.append(line.strip())
                self.assertEqual(actual_permissions, permission_values)
                self.assertIn("      result: ${{ steps.classify.outputs.result }}", block)
                self.assertIn("        if: always()", block)
                self.assertIn("          $result = 'error'", block)
                self.assertIn("              $result = 'unverified'", block)
                self.assertIn("              $result = 'verified'", block)
                action_start = block.index("      - name: Attest synthetic subject")
                verify_start = block.index("      - name: Verify exact subject and signature")
                action_step = block[action_start:verify_start]
                self.assertIn(
                    "        uses: actions/attest@" + PROBE_ACTION_SHA + " " + chr(35) + " v4.2.2",
                    action_step,
                )
                self.assertNotIn("        run:", action_step)
                self.assertNotIn("        shell:", action_step)

        action_line = "uses: actions/attest@" + PROBE_ACTION_SHA + " " + chr(35) + " v4.2.2"
        self.assertEqual(workflow.count(action_line), 6)
        for expected in (
            "subject-path: ${{ runner.temp }}/attestation-permission-probe/probe.bin",
            "predicate-type: https://example.invalid/attestation-permission-probe/v1",
            "predicate: '{\"probe\":\"source-free-permission-probe-v1\"}'",
            "show-summary: false",
            "push-to-registry: false",
            "create-storage-record: false",
            "--deny-self-hosted-runners",
            "probe=profile-comparison result=blocked reason=failed-or-ambiguous-arm",
        ):
            with self.subTest(expected=expected):
                minimum_count = 6 if expected != "probe=profile-comparison result=blocked reason=failed-or-ambiguous-arm" else 1
                self.assertGreaterEqual(workflow.count(expected), minimum_count)
        self.assertNotIn("probe=profile-selection", workflow)
        self.assertEqual(workflow.count("gh attestation verify"), 6)
        self.assertEqual(workflow.count("continue-on-error: true"), 18)
        self.assertEqual(workflow.count("if: steps.attest.outcome == 'success'"), 6)
        self.assertEqual(workflow.count("VERIFY_RESULT: ${{ steps.verify.outputs.result }}"), 6)
        self.assertNotIn("*> $verificationPath", workflow)
        self.assertNotIn("tee ", workflow)

        gate = jobs["compare-probe-results"]
        self.assertIn(
            "if ($results.Values -contains 'unverified' -or $results.Values -contains 'error')",
            "\n".join(gate),
        )
        gate_text = "\n".join(gate)
        self.assertIn("- name: Refuse comparison after workflow cancellation", gate_text)
        self.assertIn("        if: cancelled()", gate_text)
        self.assertIn("if: ${{ success() && !cancelled() }}", gate_text)
        self.assertIn(
            "probe=profile-comparison result=blocked reason=workflow-cancelled",
            gate_text,
        )
        cancellation_step = gate_text.split(
            "- name: Compare only classified arm results", maxsplit=1
        )[0]
        self.assertIn("          exit 1", cancellation_step)
        conclusion_check = gate_text.index("if ($entry.Value -ne 'success')")
        output_map = gate_text.index("$results = [ordered]@{")
        self.assertLess(conclusion_check, output_map)
        for arm in (
            "common-intersection-ubuntu",
            "common-intersection-windows",
            "github-guide-ubuntu",
            "github-guide-windows",
            "actions-readme-ubuntu",
            "actions-readme-windows",
        ):
            with self.subTest(arm=arm):
                self.assertIn(f"needs.{arm}.result", gate_text)
        for arm, result_variable in (
            ("common_intersection_ubuntu", "COMMON_UBUNTU_JOB_RESULT"),
            ("common_intersection_windows", "COMMON_WINDOWS_JOB_RESULT"),
            ("github_guide_ubuntu", "GUIDE_UBUNTU_JOB_RESULT"),
            ("github_guide_windows", "GUIDE_WINDOWS_JOB_RESULT"),
            ("actions_readme_ubuntu", "README_UBUNTU_JOB_RESULT"),
            ("actions_readme_windows", "README_WINDOWS_JOB_RESULT"),
        ):
            with self.subTest(job_result=arm):
                self.assertIn(f"{arm} = $env:{result_variable}", gate_text)
        for job_name in expected_jobs - {"require-reviewed-main", "compare-probe-results"}:
            self.assertIn(f"      - {job_name}", gate)

        for forbidden in (
            "secrets.",
            "workflow_dispatch.inputs",
            "actions/checkout",
            "upload-artifact",
            "download-artifact",
            "cache:",
            "contents: write",
            "actions: write",
            "packages: write",
            "push-to-registry: true",
            "create-storage-record: true",
        ):
            with self.subTest(forbidden_class=forbidden):
                self.assertNotIn(forbidden, workflow)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required to execute the workflow gate")
    def test_final_gate_rejects_verified_output_when_arm_job_did_not_succeed(self):
        workflow = PROBE_WORKFLOW.read_text(encoding="utf-8")
        step_marker = "      - name: Compare only classified arm results\n"
        step_start = workflow.index(step_marker)
        run_marker = "        run: |\n"
        script_start = workflow.index(run_marker, step_start) + len(run_marker)
        script = textwrap.dedent(workflow[script_start:])
        arm_names = (
            "COMMON_UBUNTU",
            "COMMON_WINDOWS",
            "GUIDE_UBUNTU",
            "GUIDE_WINDOWS",
            "README_UBUNTU",
            "README_WINDOWS",
        )

        def run_gate(job_result_overrides=None):
            env = {
                "PATH": os.environ["PATH"],
                "MAIN_GUARD": "success",
            }
            for arm in arm_names:
                env[f"{arm}_JOB_RESULT"] = "success"
                env[arm] = "verified"
            for arm, result in (job_result_overrides or {}).items():
                env[f"{arm}_JOB_RESULT"] = result
            return subprocess.run(
                [shutil.which("pwsh"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

        for conclusion in ("cancelled", "failure", "skipped", ""):
            with self.subTest(conclusion=conclusion or "missing"):
                arm = "GUIDE_WINDOWS"
                result = run_gate({arm: conclusion})
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(
                    "probe=profile-comparison result=blocked reason=arm-job-not-success",
                    result.stdout,
                )

        success = run_gate()
        self.assertEqual(success.returncode, 0, success.stdout + success.stderr)
        self.assertIn(
            "probe=profile-comparison result=observed profile=common-intersection",
            success.stdout,
        )

    def test_pinned_action_public_log_contract_is_not_hidden_by_summary_setting(self):
        workflow = PROBE_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(PINNED_ACTION_LOG_SOURCE_CONTRACT["sha"], PROBE_ACTION_SHA)
        source_excerpt = PINNED_ACTION_LOG_SOURCE_CONTRACT["main_source_excerpt"]
        self.assertLess(
            source_excerpt.index("logAttestation(subjects, att, sigstoreInstance)"),
            source_excerpt.index("if (inputs.showSummary)"),
        )
        self.assertIn("core.setFailed(err instanceof Error ? err : `${err}`)", source_excerpt)
        self.assertEqual(workflow.count("uses: actions/attest@" + PROBE_ACTION_SHA), 6)
        self.assertEqual(workflow.count("show-summary: false"), 6)
        self.assertNotIn("fixed public output", workflow.lower())

    def test_consumer_shape_accepts_only_workflow_and_policy_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/public-policy.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: public-policy\n", encoding="utf-8")
            policy = root / "ci/policy.json"
            policy.parent.mkdir()
            policy.write_text('{"pool":"connect","schema_version":1}\n', encoding="utf-8")
            (root / ".git").write_text("gitdir: worktrees/example\n", encoding="utf-8")
            self.assertEqual(scan_tree(root, "connect"), (".github/workflows/public-policy.yml", "ci/policy.json"))
            (root / "README.md").write_text("text", encoding="utf-8")
            with self.assertRaisesRegex(PublicTreeError, "tree-shape"):
                scan_tree(root, "connect")

    def test_empty_docs_directory_and_symlink_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/public-policy.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: public-policy\n", encoding="utf-8")
            policy = root / "ci/policy.json"
            policy.parent.mkdir()
            policy.write_text('{"pool":"data","schema_version":1}\n', encoding="utf-8")
            (root / "docs").mkdir()
            with self.assertRaisesRegex(PublicTreeError, "tree-shape"):
                scan_tree(root, "data")
            (root / "docs").rmdir()
            link = root / "ci/linked"
            link.symlink_to(policy)
            with self.assertRaisesRegex(PublicTreeError, "tree-shape|symlink-present|non-regular-file"):
                scan_tree(root, "data")

    def test_identifying_content_fails_without_echoing_it(self):
        fixtures = (
            "purpose " + chr(35) + " comment",
            "rule " + "D" + "90",
            chr(47) + "Users" + chr(47) + "person" + chr(47) + "secret",
            "source " + "C:" + chr(92) + "Users" + chr(92) + "person" + chr(92) + "secret",
            "source " + "C:" + chr(47) + "Users" + chr(47) + "person" + chr(47) + "secret",
            "network " + chr(92) * 2 + "server" + chr(92) + "Users" + chr(92) + "person" + chr(92) + "secret",
            "network " + chr(47) * 2 + "server" + chr(47) + "Users" + chr(47) + "person" + chr(47) + "secret",
            "extended " + chr(92) * 2 + "?" + chr(92) + "UNC" + chr(92) + "server" + chr(92) + "Users" + chr(92) + "person" + chr(92) + "secret",
            "extended drive " + chr(92) * 2 + "?" + chr(92) + "C:" + chr(92) + "Users" + chr(92) + "person" + chr(92) + "secret",
            "prefix " + "keeldock" + "-" + "core",
            "https:" + chr(47) * 2 + "github.com" + chr(47) + "owner" + chr(47) + "private",
            "agents" + "-work/files/state",
        )
        for fixture in fixtures:
            with self.subTest(fixture_class="identifying"):
                with self.assertRaises(PublicTreeError):
                    inspect_text(fixture, "platform")

    def test_public_cross_pool_references_remain_allowed(self):
        inspect_text("uses: keeldock-platform/platform-ci/kit/bootstrap@" + "a" * 40, "connect")

    def test_file_bound_is_checked_before_full_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (".github/workflows/public-policy.yml", "ci/policy.json"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"x" * 262145)
            with self.assertRaisesRegex(PublicTreeError, "file-too-large"):
                scan_tree(root, "connect")


if __name__ == "__main__":
    unittest.main(verbosity=2)
