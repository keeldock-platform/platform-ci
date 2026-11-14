import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import check_candidate
from public_tree import (
    BINARY_FIXTURE_FILES,
    PINNED_FILE_SHA256,
    PLATFORM_FILES,
    PublicTreeError,
    SYNTHETIC_NPM_LOCK_PATH,
    inspect_text,
    scan_tree,
)


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


def _secret_job_output_flows(workflow):
    lines = workflow.splitlines()
    jobs_header = next((index for index, line in enumerate(lines) if line == "jobs:"), None)
    if jobs_header is None:
        return []
    jobs_end = next(
        (index for index in range(jobs_header + 1, len(lines))
         if lines[index] and not lines[index][0].isspace()),
        len(lines),
    )
    headers = [
        (index, match.group(1))
        for index in range(jobs_header + 1, jobs_end)
        if (match := re.match(r"^  ([A-Za-z0-9_-]+):[ \t]*$", lines[index]))
    ]
    violations = []
    secret_reference = re.compile(r"\$\{\{[^}]*\bsecrets(?:\.|\[)")
    step_output_reference = re.compile(r"\bstep[s]?\.([A-Za-z0-9_-]+)\.outputs\b")

    for header_index, (job_start, job_id) in enumerate(headers):
        job_end = headers[header_index + 1][0] if header_index + 1 < len(headers) else jobs_end
        job_lines = lines[job_start + 1:job_end]

        output_lines = []
        for index, line in enumerate(job_lines):
            if re.match(r"^    outputs:\s*$", line):
                for output_line in job_lines[index + 1:]:
                    if re.match(r"^    [A-Za-z0-9_-]+:\s*$", output_line):
                        break
                    output_lines.append(output_line)
                break
        if not output_lines:
            continue

        job_secret_env_names = set()
        env_start = next(
            (index for index, line in enumerate(job_lines) if re.match(r"^    env:\s*$", line)),
            None,
        )
        if env_start is not None:
            for line in job_lines[env_start + 1:]:
                if re.match(r"^    [A-Za-z0-9_-]+:\s*$", line):
                    break
                match = re.match(r"^      ([A-Za-z_][A-Za-z0-9_]*):", line)
                if match and secret_reference.search(line):
                    job_secret_env_names.add(match.group(1))

        step_headers = [
            (index, match.group(1))
            for index, line in enumerate(job_lines)
            if (match := re.match(r"^      - (.*)$", line))
        ]
        steps = {}
        for step_index, (relative_start, _) in enumerate(step_headers):
            relative_end = (
                step_headers[step_index + 1][0]
                if step_index + 1 < len(step_headers)
                else len(job_lines)
            )
            block = "\n".join(job_lines[relative_start:relative_end])
            id_match = re.search(
                r"(?m)^      - id:\s*['\"]?([A-Za-z0-9_-]+)|^        id:\s*['\"]?([A-Za-z0-9_-]+)",
                block,
            )
            if id_match:
                steps[id_match.group(1) or id_match.group(2)] = block

        tainted_steps = set()
        changed = True
        while changed:
            changed = False
            for step_id, block in steps.items():
                secret_env_names = set()
                env_start = re.search(r"(?m)^        env:\s*$", block)
                if env_start:
                    for line in block[env_start.end():].splitlines():
                        if re.match(r"^        [A-Za-z0-9_-]+:", line):
                            break
                        match = re.match(r"^          ([A-Za-z_][A-Za-z0-9_]*):", line)
                        if match and secret_reference.search(line):
                            secret_env_names.add(match.group(1))

                tainted_names = job_secret_env_names | secret_env_names
                block_lines = block.splitlines()
                uses_secret_action = bool(
                    re.search(r"(?m)^        uses:", block)
                    and (secret_reference.search(block)
                         or set(step_output_reference.findall(block)) & tainted_steps)
                )
                lines_changed = True
                while lines_changed:
                    lines_changed = False
                    for line in block_lines:
                        assignment = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
                        if not assignment or assignment.group(1) in tainted_names:
                            continue
                        rhs = assignment.group(2)
                        references_secret = secret_reference.search(rhs) or any(
                            re.search(rf"(?:\$\{{\{{\s*env\.{name}\s*\}}\}}|\$\{{?{name}\b)", rhs)
                            for name in tainted_names
                        )
                        references_secret = references_secret or bool(
                            set(step_output_reference.findall(rhs)) & tainted_steps
                        )
                        if references_secret:
                            tainted_names.add(assignment.group(1))
                            lines_changed = True

                output_write_has_secret = False
                for line in block_lines:
                    if "GITHUB_OUTPUT" not in line:
                        continue
                    if secret_reference.search(line) or set(step_output_reference.findall(line)) & tainted_steps:
                        output_write_has_secret = True
                    if any(
                        re.search(rf"(?:\$\{{\{{\s*env\.{name}\s*\}}\}}|\$\{{?{name}\b)", line)
                        for name in tainted_names
                    ):
                        output_write_has_secret = True

                if (uses_secret_action or output_write_has_secret) and step_id not in tainted_steps:
                    tainted_steps.add(step_id)
                    changed = True

        output_text = "\n".join(output_lines)
        if secret_reference.search(output_text):
            violations.append(f"{job_id}:direct-secret")
        for step_id in sorted(set(step_output_reference.findall(output_text)) & tainted_steps):
            violations.append(f"{job_id}:step-{step_id}")
    return violations


class PublicTreeTests(unittest.TestCase):
    def test_parent_runner_workspace_is_not_a_valid_checkout_root(self):
        with tempfile.TemporaryDirectory(prefix="platform-workspace-root-") as temporary:
            runner_parent = Path(temporary) / "runner-workspace"
            checkout_root = runner_parent / "platform-ci"
            checkout_root.mkdir(parents=True)
            empty_git_template = runner_parent / "empty-git-template"
            empty_git_template.mkdir()
            for name in PLATFORM_FILES:
                source = ROOT / name
                destination = checkout_root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)

            subprocess.run(
                [
                    "git", "init", "--quiet", "--template=" + str(empty_git_template),
                    str(checkout_root),
                ],
                check=True,
                capture_output=True,
                timeout=10,
            )
            for key, value in (
                ("user.name", "Platform fixture"),
                ("user.email", "platform-fixture@example.invalid"),
                ("commit.gpgsign", "false"),
                ("core.hooksPath", str(empty_git_template)),
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
                timeout=120,
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
            self.assertEqual(checkout.returncode, 0, (checkout.stdout, checkout.stderr))
            self.assertEqual(checkout.stdout, "candidate-policy=accepted control-sha=" + sha + "\n")
            self.assertEqual(checkout.stderr, "")

    def test_platform_candidate_has_only_the_allowlisted_tree(self):
        result = scan_tree(ROOT, "platform")
        self.assertEqual(set(result), set(PLATFORM_FILES))
        self.assertEqual(BINARY_FIXTURE_FILES, frozenset((
            "kit/devlane/fixtures/real-netns-rtnetlink-ipv4-ubuntu2404.bin",
            "kit/devlane/fixtures/real-netns-rtnetlink-ipv6-ubuntu2404.bin",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/icons/icon.png",
        )))
        self.assertTrue(BINARY_FIXTURE_FILES <= PLATFORM_FILES)
        self.assertTrue(BINARY_FIXTURE_FILES <= set(PINNED_FILE_SHA256))
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

    def test_public_tauri_smoke_fixture_and_workflow_are_registered_and_pinned(self):
        prefix = "kit/devlane/fixtures/desktop-tauri-smoke/"
        fixture_files = sorted(name for name in PLATFORM_FILES if name.startswith(prefix))
        expected_fixture = {
            "kit/devlane/fixtures/desktop-tauri-smoke/package-lock.json",
            "kit/devlane/fixtures/desktop-tauri-smoke/package.json",
            "kit/devlane/fixtures/desktop-tauri-smoke/build.mjs",
            "kit/devlane/fixtures/desktop-tauri-smoke/index.html",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.lock",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.toml",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/build.rs",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/icons/icon.png",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/src/lib.rs",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/src/main.rs",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/tauri.conf.json",
        }
        policy_files = {
            ".github/workflows/desktop-tauri-smoke.yml",
            "ci/policy.json",
            "kit/bootstrap/check_candidate.py",
            "kit/bootstrap/policy.py",
            "kit/bootstrap/public_tree.py",
            "kit/bootstrap/test_policy.py",
            "kit/bootstrap/test_public_tree.py",
        }
        self.assertEqual(set(fixture_files), expected_fixture)
        tree = scan_tree(ROOT, "platform")
        for name in fixture_files + sorted(policy_files):
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, tree)
                pin_key = ("platform", name) if name == "ci/policy.json" else name
                self.assertIn(pin_key, PINNED_FILE_SHA256)
        for name in fixture_files:
            if name.endswith(("Cargo.lock", "package-lock.json", ".png")):
                continue
            self.assertNotIn(chr(35), (ROOT / name).read_text(encoding="utf-8"))
        for name in (
            ".github/workflows/desktop-tauri-smoke.yml",
            "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.lock",
            "kit/devlane/fixtures/desktop-tauri-smoke/package-lock.json",
        ):
            self.assertNotIn(chr(35), (ROOT / name).read_text(encoding="utf-8"))

    def test_release_evidence_scanner_is_registered_and_discovered(self):
        self.assertIn("kit/confinement/release_evidence.py", PLATFORM_FILES)
        self.assertIn("kit/confinement/test_release_evidence.py", PLATFORM_FILES)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertEqual(action.count('"test_release_evidence.py"'), 2)

    def test_baselines_preparation_lane_is_registered_and_discovered(self):
        for name in (
            ".github/workflows/baselines-prepare.yml",
            "kit/baselines/baselines_prepare.py",
            "kit/baselines/test_baselines_prepare.py",
        ):
            self.assertIn(name, PLATFORM_FILES)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertEqual(action.count('"test_baselines_prepare.py"'), 2)

    def test_role_signer_suite_is_registered_and_discovered(self):
        self.assertIn("kit/confinement/role_signer.py", PLATFORM_FILES)
        self.assertIn("kit/confinement/test_role_signer.py", PLATFORM_FILES)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertEqual(action.count('"test_role_signer.py"'), 2)

    def test_windows_source_run_gate_table_and_capsule_suites_are_registered_and_discovered(self):
        for name in (
            "kit/confinement/windows_source_run.ps1",
            "kit/confinement/test_windows_source_run.py",
            "kit/confinement/gate_table.py",
            "kit/confinement/test_confinement_gate_table.py",
            "kit/handoff/source_capsule.py",
            "kit/handoff/test_source_capsule.py",
        ):
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, PINNED_FILE_SHA256)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertEqual(action.count('"test_confinement_gate_table.py"'), 2)
        self.assertEqual(action.count('"test_windows_source_run.py"'), 2)
        self.assertEqual(action.count('"test_source_capsule.py"'), 1)

    def test_the_sealer_dependencies_are_hash_pinned_once_and_installed_the_same_way_in_ci_and_the_workflow(self):
        requirements = (ROOT / "kit/handoff/provider_requirements.txt").read_text(encoding="ascii")
        lines = requirements.splitlines()
        self.assertEqual(len(lines), 3)
        for line, name in zip(lines, ("cryptography", "cffi", "pycparser")):
            self.assertRegex(line, r"^" + name + r"==[0-9]+(\.[0-9]+)+ --hash=sha256:[0-9a-f]{64}$")
        install = "--require-hashes --only-binary=:all: --no-deps --target"
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/lane-h-linux-fetch-encrypt.yml").read_text(encoding="ascii")
        self.assertEqual(action.count(install), 1)
        self.assertEqual(workflow.count(install), 1)
        self.assertEqual(action.count("provider_requirements.txt"), 1)
        self.assertEqual(workflow.count("kit/handoff/provider_requirements.txt"), 1)
        self.assertEqual(workflow.count('PYTHONPATH="$RUNNER_TEMP/kd-pydeps" python3 -B kit/handoff/source_capsule.py seal'), 1)
        block = action[action.index('if [[ "${RUNNER_OS:-}" == "Linux" ]]; then\n'):]
        block = block[:block.index("\n        fi\n")]
        self.assertIn('-p "test_source_capsule.py"', block)
        guard = '          if [[ "${CI_POOL:-}" == "platform" ]]; then\n'
        self.assertEqual(block.count(guard), 1)
        inner = block[block.index(guard):]
        inner = inner[:inner.index("\n          fi\n")]
        self.assertIn(install, inner)
        self.assertIn("provider_requirements.txt", inner)
        self.assertIn('-p "test_source_capsule.py"', inner)
        self.assertNotIn(install, block.replace(inner, ""))

    def test_synthetic_project_fixture_is_registered_pinned_and_discovered(self):
        prefix = "kit/confinement/synthetic_project/"
        fixture = sorted(name for name in PLATFORM_FILES if name.startswith(prefix))
        self.assertEqual(len(fixture), 33)
        for name in fixture + ["kit/confinement/test_confinement_synthetic_project.py"]:
            with self.subTest(name=name):
                self.assertIn(name, PINNED_FILE_SHA256)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertEqual(action.count('-p "test_confinement*.py"'), 2)

    def test_linux_source_build_suite_is_registered_and_discovered_at_push_time(self):
        self.assertIn("kit/confinement/linux_source_build.py", PLATFORM_FILES)
        self.assertIn("kit/confinement/test_linux_source_build.py", PLATFORM_FILES)
        self.assertIn("kit/confinement/test_linux_source_build_tiers.py", PLATFORM_FILES)
        suite = (ROOT / "kit/confinement/test_linux_source_build.py").read_text(encoding="utf-8")
        self.assertEqual(suite.count("\nfrom test_linux_source_build_tiers import *\n"), 1)
        tiers = (ROOT / "kit/confinement/test_linux_source_build_tiers.py").read_text(encoding="utf-8")
        self.assertIn('__all__ = ["WindowsSourceBindingTests", "LinuxBrowserTierTests"]', tiers)
        self.assertNotIn("import test_linux_source_build\n", tiers)
        self.assertNotIn("from test_linux_source_build import", tiers)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertEqual(action.count('"test_linux_source_build.py"'), 1)
        self.assertEqual(action.count('"test_rust_license_gate.py"'), 0)
        condition = 'if [[ "${RUNNER_OS:-}" == "Linux" ]]; then\n'
        self.assertEqual(action.count(condition), 1)
        start = action.index(condition)
        end = action.index("\n        fi\n", start)
        block = action[start:end]
        self.assertEqual(block.count('"test_linux_source_build.py"'), 1)
        self.assertEqual(block.count('"test_rust_license_gate.py"'), 0)
        self.assertIn('"$python_bin" -B -m unittest discover', block)
        self.assertNotIn("python3.9", block)
        self.assertLess(start, action.index('"${RUNNER_OS:-}" == "macOS"'))
        self.assertGreater(start, action.index('"test_role_signer.py"'))
        macos = action[action.index('"${RUNNER_OS:-}" == "macOS"'):]
        self.assertNotIn("test_linux_source_build.py", macos)
        self.assertNotIn("test_rust_license_gate.py", macos)

    def test_d145_profile_sources_and_regression_suites_are_registered_and_pinned(self):
        paths = (
            "kit/confinement/cargo_lock_bootstrap.py",
            "kit/confinement/test_confinement_cargo_lock_bootstrap.py",
            "kit/confinement/macos_feedback_producer.py",
            "kit/confinement/test_macos_feedback_producer.py",
            "kit/confinement/macos_private_validation.py",
            "kit/confinement/test_macos_private_validation.py",
            "kit/confinement/test_macos_wave70.py",
            "kit/confinement/macos_core_contract.py",
            "kit/confinement/test_macos_core_contract.py",
            "kit/confinement/linux_source_build.py",
            "kit/confinement/test_linux_source_build.py",
            "kit/confinement/windows_source_run.ps1",
            "kit/confinement/test_windows_source_run.py",
            "kit/bootstrap/test_public_tree.py",
        )
        for name in paths:
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, PINNED_FILE_SHA256)

        workflow = (ROOT / ".github/workflows/linux-source-admission.yml").read_text(encoding="utf-8")
        unit_start = workflow.index("  linux-source-admission-unit:")
        unit_end = workflow.index("  linux-source-admission-source-read:", unit_start)
        unit_job = workflow[unit_start:unit_end]
        self.assertIn("python3 -B kit/confinement/test_linux_source_build.py", unit_job)

    def test_core_ci_files_are_registered_and_the_suite_is_discovered_on_linux_only(self):
        for name in (
            ".github/workflows/core-linux-quick-return.yml",
            "core-ci/linux_quick_return.py",
            "core-ci/test_linux_quick_return.py",
            "core-ci/test_separation.py",
        ):
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, PINNED_FILE_SHA256)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertEqual(action.count('-s "$CI_ACTION_PATH/../../core-ci" -p "test_*.py"'), 1)
        condition = 'if [[ "${RUNNER_OS:-}" == "Linux" ]]; then\n'
        start = action.index(condition)
        end = action.index("\n        fi\n", start)
        self.assertEqual(action[start:end].count('-s "$CI_ACTION_PATH/../../core-ci" -p "test_*.py"'), 1)
        macos = action[action.index('"${RUNNER_OS:-}" == "macOS"'):]
        self.assertNotIn("core-ci", macos)
        workflow = (ROOT / ".github/workflows/core-linux-quick-return.yml").read_text(encoding="utf-8")
        self.assertIn("python3 -B core-ci/test_linux_quick_return.py", workflow)

    def test_branch_promotion_requires_exact_green_checks_and_verifies_the_remote_target(self):
        for name in (
            "kit/promotion/branch_promotion.py",
            "kit/promotion/test_branch_promotion.py",
            "docs/branch-promotion.md",
        ):
            self.assertIn(name, PLATFORM_FILES)
            self.assertIn(name, PINNED_FILE_SHA256)
        source = (ROOT / "kit/promotion/branch_promotion.py").read_text(encoding="utf-8")
        self.assertIn('"git", "push", "origin", sha + ":refs/heads/" + target', source)
        self.assertIn("verify_exact_target(sha, _remote_sha(root, target))", source)
        self.assertIn("green_required_checks(required", source)
        self.assertIn("--owner-approved", source)
        rules = (ROOT / "docs/branch-promotion.md").read_text(encoding="utf-8")
        self.assertIn("Require status checks to pass", rules)
        self.assertIn("15368", rules)
        self.assertNotIn("promotion-check-reuse", rules)
        self.assertIn("manual dispatch", rules)
        self.assertIn("any branch ref", rules)
        self.assertIn("One-time branch-rule setup", rules)
        self.assertIn("changes no GitHub settings", rules)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertIn('discover -s "$CI_ACTION_PATH/../promotion" -p "test_*.py"', action)

    def test_runtime_workspace_dependency_check_uses_the_confined_runner(self):
        workflow = (ROOT / ".github/workflows/core-dependency-checks.yml").read_text(encoding="utf-8")
        start = workflow.index("  runtime-workspace:")
        end = workflow.index("  npm:", start)
        job = workflow[start:end]
        self.assertIn("KD_INCLUDE_RUNTIME_NPM_LOCK: \"true\"", job)
        self.assertIn("linux_source_build.py runtime-workspace", job)
        self.assertIn("Run npm --prefix runtime run check:workspace in confinement", job)
        source_build = (ROOT / "kit/confinement/linux_source_build.py").read_text(encoding="utf-8")
        self.assertIn('"--prefix", "runtime", "run", "check:workspace"', source_build)
        self.assertIn('"CARGO_NET_OFFLINE": "true"', source_build)
        self.assertIn('"NPM_CONFIG_OFFLINE": "true"', source_build)
        self.assertIn("timeout=RUNTIME_WORKSPACE_TIMEOUT_SECONDS", source_build)

    def test_public_platform_workflow_caches_only_hash_scoped_trusted_rust_outputs(self):
        workflow = (ROOT / ".github/workflows/core-dependency-checks.yml").read_text(encoding="utf-8")
        self.assertIn("  workflow_call:\n", workflow)
        self.assertIn("github.repository == format('{0}/{1}-{2}', 'Moh-Bakr', 'keeldock', 'core')", workflow)
        self.assertEqual(workflow.count("uses: actions/cache/restore@"), 2)
        self.assertEqual(workflow.count("uses: actions/cache/save@"), 2)
        self.assertEqual(workflow.count("restore-keys:"), 0)
        self.assertEqual(workflow.count("timeout 10m sudo -n --preserve-env="), 2)
        for action in ("uses: actions/cache/restore@", "uses: actions/cache/save@"):
            offset = 0
            while True:
                offset = workflow.find(action, offset)
                if offset < 0:
                    break
                step_start = workflow.rfind("      - name:", 0, offset)
                condition = workflow[step_start:offset]
                if "restore@" in action:
                    self.assertIn("KD_RUST_CACHE_ENABLED == 'true'", condition)
                else:
                    self.assertIn("github.event_name == 'workflow_dispatch'", condition)
                    self.assertIn("github.ref == 'refs/heads/main'", condition)
                    self.assertNotIn("github.event_name == 'push'", condition)
                    self.assertNotIn("pull_request", condition)
                offset += len(action)
        self.assertIn("RUST_CACHE_TRUST_CLASS: primary", workflow)
        self.assertEqual(workflow.count("${{ runner.temp }}/kd-rust-cache/rust-cache.tar"), 4)
        self.assertEqual(workflow.count("KD_RUST_CACHE_DIR: ${{ runner.temp }}/kd-rust-cache"), 6)
        key_expression = (
            "KD_RUST_CACHE_ENCRYPTION_KEY_B64: ${{ github.repository == 'keeldock-platform/platform-ci' "
            "&& github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' "
            "&& secrets.RUST_CACHE_ENCRYPTION_KEY || '' }}"
        )
        self.assertEqual(workflow.count(key_expression), 4)
        for start, end in (
            ("  rust:\n", "  runtime-workspace:\n"),
            ("  runtime-workspace:\n", "  npm:\n"),
            ("  npm:\n", None),
        ):
            job = workflow.split(start, 1)[1]
            if end is not None:
                job = job.split(end, 1)[0]
            self.assertIn("linux-source-read-main", job)
            self.assertIn("github.ref == 'refs/heads/main'", job)
            self.assertIn("github.event_name == 'workflow_dispatch'", job)
        for action in ("actions/cache/restore@", "actions/cache/save@"):
            cursor = 0
            while True:
                cursor = workflow.find(f"uses: {action}", cursor)
                if cursor < 0:
                    break
                step_start = workflow.rfind("      - name:", 0, cursor)
                step_end = workflow.find("      - name:", cursor)
                step = workflow[step_start:step_end if step_end >= 0 else len(workflow)]
                self.assertIn("${{ runner.temp }}/kd-rust-cache/rust-cache.tar", step)
                self.assertNotIn("${{ runner.temp }}/kd-rust-cache/target", step)
                self.assertNotIn("${{ runner.temp }}/kd-rust-cache/cargo-home", step)
                cursor += len(action)
        self.assertNotIn("pull_request' && github.repository == 'keeldock-platform/platform-ci'", workflow)
        self.assertIn("linux_source_build.py rust-cache-import", workflow)
        self.assertIn("linux_source_build.py rust-cache-package", workflow)
        self.assertLess(workflow.index("uses: actions/cache/restore@"), workflow.index("linux_source_build.py rust-cache-import"))
        self.assertLess(workflow.index("linux_source_build.py rust-cache-import"), workflow.index("sudo -n --preserve-env=WORKER_PATH,CARGO_HOME,RUST_ROOT"))
        self.assertIn("CACHE_MODE: none", workflow)

    def test_workflows_never_forward_secret_values_through_job_outputs(self):
        direct_secret = "jobs:\n  direct:\n    outputs:\n      leaked: ${{ secrets.CACHE_KEY }}\n    steps:\n      - run: true\n"
        encoded_secret = (
            "jobs:\n  encoded:\n    outputs:\n      leaked: ${{ steps.encode.outputs.value }}\n    steps:\n"
            "      - id: encode\n        env:\n          CACHE_KEY: ${{ secrets.CACHE_KEY }}\n"
            "        run: printf 'value=%s\\n' \\\"$(printf '%s' \\\"$CACHE_KEY\\\" | base64)\\\" >> \\\"$GITHUB_OUTPUT\\\"\n"
        )
        self.assertEqual(_secret_job_output_flows(direct_secret), ["direct:direct-secret"])
        self.assertEqual(_secret_job_output_flows(encoded_secret), ["encoded:step-encode"])

        workflow_paths = sorted((ROOT / ".github/workflows").glob("*.yml"))
        workflow_paths += sorted((ROOT / ".github/workflows").glob("*.yaml"))
        violations = [
            f"{path.relative_to(ROOT).as_posix()}:{flow}"
            for path in workflow_paths
            for flow in _secret_job_output_flows(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(violations, [])

    def test_every_cargo_build_workflow_uses_pinned_exact_archive_caches_outside_confinement(self):
        expected = {
            ".github/workflows/core-dependency-checks.yml": (2, 2),
            ".github/workflows/linux-source-admission.yml": (2, 2),
            ".github/workflows/core-linux-quick-return.yml": (0, 0),
        }
        for relative, (restores, saves) in expected.items():
            workflow = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(workflow=relative):
                self.assertEqual(workflow.count("uses: actions/cache/restore@"), restores)
                self.assertEqual(workflow.count("uses: actions/cache/save@"), saves)
                if "core-linux-quick-return" in relative:
                    self.assertNotIn("actions/cache/", workflow)
                    self.assertNotIn("KD_RUST_CACHE_ENCRYPTION_KEY_B64", workflow)
                    continue
                self.assertEqual(workflow.count("restore-keys:"), 0)
                self.assertIn("3edfce9056124e459a23f683a21433670d47daca", workflow)
                self.assertIn("linux_source_build.py rust-cache-key", workflow)
                self.assertIn("linux_source_build.py rust-cache-import", workflow)
                self.assertIn("linux_source_build.py rust-cache-export", workflow)
                self.assertIn("linux_source_build.py rust-cache-package", workflow)
                self.assertIn("rust-cache.tar", workflow)
                if "core-dependency-checks" in relative:
                    self.assertEqual(workflow.count("KD_RUST_CACHE_ENCRYPTION_KEY_B64: ${{ github.repository =="), 4)
                else:
                    expected_secret_uses = 2 if "core-linux-quick-return" in relative else 4
                    self.assertEqual(
                        workflow.count("KD_RUST_CACHE_ENCRYPTION_KEY_B64: ${{ secrets.RUST_CACHE_ENCRYPTION_KEY }}"),
                        expected_secret_uses,
                    )
                if "linux-source-admission" in relative:
                    source_read = workflow.split("  linux-source-admission-source-read:\n", 1)[1].split(
                        "  linux-source-admission-verdict:\n", 1,
                    )[0]
                    verifier = workflow.split("  linux-source-admission-verdict:\n", 1)[1].split(
                        "  linux-source-admission-audit:\n", 1,
                    )[0]
                    self.assertLess(source_read.index("uses: actions/cache/restore@"), source_read.index("Run all offline project gates"))
                    self.assertLess(source_read.index("Run all offline project gates"), source_read.index("uses: actions/cache/save@"))
                    self.assertLess(verifier.index("uses: actions/cache/restore@"), verifier.index("Run independent offline project gates"))
                    self.assertLess(verifier.index("Run independent offline project gates"), verifier.index("uses: actions/cache/save@"))
                    self.assertNotIn("cache-mode:", workflow)
                elif "core-dependency-checks" in relative:
                    for start, end, build in (
                        ("  rust:\n", "  runtime-workspace:\n", "Build and test root and fuzz Rust workspaces with locks enforced"),
                        ("  runtime-workspace:\n", "  npm:\n", "Run npm --prefix runtime run check:workspace in confinement"),
                    ):
                        job = workflow.split(start, 1)[1].split(end, 1)[0]
                        self.assertLess(job.index("uses: actions/cache/restore@"), job.index(build))
                        self.assertLess(job.index(build), job.index("uses: actions/cache/save@"))
                for action in ("uses: actions/cache/restore@", "uses: actions/cache/save@"):
                    offset = 0
                    while True:
                        offset = workflow.find(action, offset)
                        if offset < 0:
                            break
                        start = workflow.rfind("      - name:", 0, offset)
                        end = workflow.find("      - name:", offset)
                        if end < 0:
                            end = len(workflow)
                        step = workflow[start:end]
                        self.assertIn("${{ runner.temp }}/kd-rust-cache/rust-cache.tar", step)
                        if "restore@" in action and "core-dependency-checks" not in relative and "linux-source-admission" not in relative:
                            self.assertLess(offset, workflow.index("Run all offline project gates"))
                        else:
                            condition = step.split("        if:", 1)[1].split("\n", 1)[0]
                            self.assertNotIn("pull_request", condition)
                        offset += len(action)
        source_build = (ROOT / "kit/confinement/linux_source_build.py").read_text(encoding="utf-8")
        self.assertIn('"rust-toolchain.toml"', source_build)
        self.assertIn('"Cargo.lock"', source_build)

    def test_platform_allowlist_rejects_an_unreviewed_extra_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in PLATFORM_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name in PINNED_FILE_SHA256 or ("platform", name) in PINNED_FILE_SHA256:
                    shutil.copyfile(ROOT / name, path)
                else:
                    path.write_text("safe\n", encoding="utf-8")
            scan_tree(root, "platform")
            (root / "kit/confinement/unreviewed.py").write_text("safe\n", encoding="utf-8")
            with self.assertRaisesRegex(PublicTreeError, "tree-shape"):
                scan_tree(root, "platform")

    def test_cache_policy_files_are_registered_and_test_discovery_is_active(self):
        result = scan_tree(ROOT, "platform")
        for name in ("kit/cache/policy.py", "kit/cache/test_policy.py"):
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, result)
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="utf-8")
        self.assertIn(
            'unittest discover -s "$CI_ACTION_PATH/../cache" -p "test_*.py"',
            action,
        )
        self.assertIn(
            'unittest discover -s "$CI_ACTION_PATH/../ci" -p "test_*.py"',
            action,
        )

    def test_wave71b_ci_workflows_and_helpers_are_pinned_and_discovered(self):
        expected = (
            ".github/workflows/ci-future-stages.yml",
            ".github/workflows/appium-ci.yml",
            ".github/workflows/performance-shadow.yml",
            "kit/selector/suite_selector.py",
            "kit/selector/test_suite_selector.py",
            "kit/selector/ci19_catalogue.py",
            "kit/selector/fixtures/ci19_mcp_feature_owners.json",
            "kit/ci/feature_states.py",
            "kit/ci/test_feature_states.py",
            "kit/ci/future_stage.py",
            "kit/ci/test_future_stage.py",
            "kit/ci/future-stage-inventory.json",
            "kit/ci/perf_shadow.py",
            "kit/ci/test_perf_shadow.py",
        )
        tree = scan_tree(ROOT, "platform")
        for name in expected:
            with self.subTest(name=name):
                self.assertIn(name, PLATFORM_FILES)
                self.assertIn(name, PINNED_FILE_SHA256)
                self.assertIn(name, tree)
        for name in (".github/workflows/ci-future-stages.yml", ".github/workflows/appium-ci.yml"):
            workflow = (ROOT / name).read_text(encoding="ascii")
            self.assertIn("--publish", workflow)
            self.assertIn("future-stage", workflow)
        future_stage = (ROOT / "kit/ci/future_stage.py").read_text(encoding="ascii")
        self.assertIn('"conclusion": "failure"', future_stage)
        self.assertIn('FUTURE_STAGE_GATE_EVIDENCE = "forbidden"', future_stage)
        self.assertIn('"gate_evidence": FUTURE_STAGE_GATE_EVIDENCE', future_stage)
        self.assertIn('"status": FUTURE_STAGE_STATUS', future_stage)
        self.assertNotIn('"conclusion": "neutral"', future_stage)
        self.assertNotIn('"conclusion": "success"', future_stage)
        self.assertIn("FUTURE_STAGE_JOB_EXIT_CODE = 78", future_stage)
        for name in (".github/workflows/ci-future-stages.yml", ".github/workflows/appium-ci.yml"):
            workflow = (ROOT / name).read_text(encoding="ascii")
            self.assertIn('if [[ "$probe_status" -eq 0 || "$probe_status" -eq 78 ]]; then', workflow)
            self.assertIn('exit 78', workflow)

    def test_reviewed_native_and_source_controls_have_public_tree_hash_pins(self):
        expected = {
            '.github/workflows/desktop-tauri-smoke.yml',
            ('platform', 'ci/policy.json'),
            'kit/bootstrap/check_candidate.py',
            'kit/bootstrap/test_public_tree.py',
            '.github/workflows/core-dependency-checks.yml',
            ('platform', '.github/workflows/public-policy.yml'),
            'docs/branch-promotion.md',
            '.github/workflows/linux-source-admission.yml',
            'kit/bootstrap/action.yml',
            'kit/bootstrap/policy.py',
            'kit/bootstrap/public_tree.py',
            'kit/bootstrap/test_policy.py',
            '.github/workflows/core-rust-format-return.yml',
            '.github/workflows/core-build-diagnostic-return.yml',
            '.github/workflows/windows-source-admission.yml',
            '.github/workflows/lane-h-windows-receiver.yml',
            '.github/workflows/lane-h-linux-fetch-encrypt.yml',
            '.github/workflows/lane-h-capsule-attester.yml',
            'kit/confinement/windows_source_run.ps1',
            'kit/confinement/test_windows_source_run.py',
            'kit/confinement/macos_feedback_producer.py',
            'kit/confinement/test_macos_feedback_producer.py',
            'kit/confinement/test_macos_feedback_output_limits.py',
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
            'kit/confinement/node_lock_inventory.mjs',
            'kit/confinement/node_lock_manifest.mjs',
            'kit/confinement/test_node_lock_manifest.mjs',
            'kit/confinement/sbom_normalizer.py',
            'kit/confinement/test_sbom_normalizer.py',
            'kit/confinement/node_lock_receipt.py',
            'kit/confinement/test_node_lock_receipt.py',
            '.github/workflows/macos-core-contract.yml',
            'kit/confinement/macos_core_contract.py',
            'kit/confinement/test_macos_core_contract.py',
            'kit/confinement/linux_source_build.py',
            'kit/confinement/test_linux_source_build.py',
            'kit/confinement/test_linux_source_build_tiers.py',
            'kit/confinement/linux_boundary.py',
            'kit/confinement/test_linux_boundary.py',
            'kit/confinement/linux_session.py',
            'kit/confinement/test_linux_session.py',
            'kit/confinement/linux_channels.py',
            'kit/confinement/test_linux_channels.py',
            'kit/bootstrap/policy_linux.py',
            'kit/bootstrap/test_policy_linux.py',
            'kit/confinement/fixtures/npm11_audit_report.json',
            '.github/workflows/core-linux-quick-return.yml',
            'core-ci/linux_quick_return.py',
            'core-ci/test_linux_quick_return.py',
            'core-ci/test_separation.py',
            'kit/promotion/branch_promotion.py',
            'kit/promotion/test_branch_promotion.py',
            'kit/confinement/cargo_lock_parser.py',
            'kit/confinement/test_cargo_lock_parser.py',
            'kit/bootstrap/test_public_tree.py',
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
            'kit/confinement/test_macos_wave70.py',
            'ci/revoked-signer-fingerprints',
            '.github/workflows/capsule-vectors.yml',
            'kit/confinement/capsule_frame.cs',
            'kit/confinement/capsule_frame.ps1',
            'kit/confinement/capsule_frame_vectors.json',
            ".github/workflows/windows-native-preflight.yml",
            "kit/confinement/windows_native_preflight.cs",
            "kit/confinement/windows_native_preflight.ps1",
            "kit/confinement/test_windows_native_preflight.py",
            "kit/confinement/windows_confinement.cs",
            "kit/confinement/windows_confinement.ps1",
            "kit/confinement/windows_probe.rs",
            "kit/confinement/windows_npm_link_shim.cjs",
            "kit/confinement/test_windows_confinement.py",
            "kit/confinement/macos_source_reader.py",
            "kit/confinement/test_macos_source_reader.py",
            "kit/confinement/release_provenance.py",
            "kit/confinement/test_confinement_release_provenance.py",
            "kit/confinement/role_signer.py",
            "kit/confinement/gate_table.py",
            "kit/confinement/test_confinement_gate_table.py",
            "kit/handoff/source_capsule.py",
            "kit/handoff/test_source_capsule.py",
            "kit/handoff/provider_requirements.txt",
            "kit/confinement/test_role_signer.py",
            "kit/bootstrap/policy_handoff.py",
            "kit/bootstrap/test_policy_handoff.py",
            "kit/confinement/release_build_verify.py",
            "kit/confinement/test_release_build_verify.py",
            'kit/bootstrap/policy_rust.py',
            'kit/bootstrap/test_policy_rust.py',
            'kit/bootstrap/policy_npm.py',
            'kit/bootstrap/test_policy_npm.py',
            'kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.toml',
            'kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.lock',
            'kit/confinement/fixtures/cargo-deny/issue-910-cycle/a/Cargo.toml',
            'kit/confinement/fixtures/cargo-deny/issue-910-cycle/a/src/lib.rs',
            'kit/confinement/fixtures/cargo-deny/issue-910-cycle/b/Cargo.toml',
            'kit/confinement/fixtures/cargo-deny/issue-910-cycle/b/src/lib.rs',
            'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.toml',
            'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.lock',
            'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/build.rs',
            'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/src/lib.rs',
            'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.toml',
            'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.lock',
            'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/build.rs',
            'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/src/lib.rs',
            'kit/confinement/cargo_lock_bootstrap.py',
            'kit/confinement/test_confinement_cargo_lock_bootstrap.py',
                "kit/confinement/release_evidence.py",
            "kit/confinement/test_release_evidence.py",
            "kit/confinement/release_tool_ledger.py",
            "kit/confinement/release_tool_ledger.json",
            "kit/confinement/test_release_tool_ledger.py",
            "kit/confinement/native_loopback_profile.py",
            "kit/confinement/test_native_loopback_profile.py",
            "kit/confinement/linux_harness.py",
            "kit/confinement/macos_deny_default.py",
            ".github/workflows/baselines-prepare.yml",
            "kit/baselines/baselines_prepare.py",
            "kit/baselines/test_baselines_prepare.py",
            "kit/bootstrap/policy_baselines.py",
            "kit/bootstrap/test_policy_baselines.py",
            "kit/confinement/synthetic_project/Cargo.lock",
            "kit/confinement/synthetic_project/Cargo.toml",
            "kit/confinement/synthetic_project/crates/host/api/Cargo.toml",
            "kit/confinement/synthetic_project/crates/host/api/src/lib.rs",
            "kit/confinement/synthetic_project/crates/host/api/tests/feature.rs",
            "kit/confinement/synthetic_project/crates/host/api/tests/surface.rs",
            "kit/confinement/synthetic_project/crates/host/conformance/Cargo.toml",
            "kit/confinement/synthetic_project/crates/host/conformance/src/lib.rs",
            "kit/confinement/synthetic_project/crates/host/conformance/tests/conformance.rs",
            "kit/confinement/synthetic_project/crates/host/conformance/tests/process_pipe.rs",
            "kit/confinement/synthetic_project/crates/host/mock/Cargo.toml",
            "kit/confinement/synthetic_project/crates/host/mock/src/lib.rs",
            "kit/confinement/synthetic_project/crates/host/mock/tests/mock.rs",
            "kit/confinement/synthetic_project/fuzz/Cargo.lock",
            "kit/confinement/synthetic_project/fuzz/Cargo.toml",
            "kit/confinement/synthetic_project/fuzz/src/main.rs",
            "kit/confinement/synthetic_project/package-lock.json",
            "kit/confinement/synthetic_project/package.json",
            "kit/confinement/synthetic_project/packages/host-api/package.json",
            "kit/confinement/synthetic_project/packages/host-api/src/index.js",
            "kit/confinement/synthetic_project/packages/host-api/src/index.ts",
            "kit/confinement/synthetic_project/packages/host-api/tests/run.js",
            "kit/confinement/synthetic_project/packages/host-api/tests/no-net-use.mjs",
            "kit/confinement/synthetic_project/packages/host-api/tests/vitest.test.ts",
            "kit/confinement/synthetic_project/packages/host-api/tsconfig.json",
            "kit/confinement/synthetic_project/packages/host-api/vitest.config.ts",
            "kit/confinement/synthetic_project/packages/kernel-i18n/package.json",
            "kit/confinement/synthetic_project/packages/kernel-i18n/src/index.js",
            "kit/confinement/synthetic_project/packages/kernel-i18n/tests/run.js",
            "kit/confinement/synthetic_project/runtime/Cargo.lock",
            "kit/confinement/synthetic_project/runtime/Cargo.toml",
            "kit/confinement/synthetic_project/runtime/src/lib.rs",
            "kit/confinement/synthetic_project/runtime/tests/runtime.rs",
            "kit/confinement/test_confinement_synthetic_project.py",
            "kit/confinement/confinement_public_audit.py",
            "kit/confinement/macos_public_audit.py",
            ".github/workflows/ci-future-stages.yml",
            ".github/workflows/appium-ci.yml",
            ".github/workflows/performance-shadow.yml",
            "kit/selector/suite_selector.py",
            "kit/selector/test_suite_selector.py",
            "kit/selector/ci19_catalogue.py",
            "kit/selector/fixtures/ci19_mcp_feature_owners.json",
            "kit/ci/feature_states.py",
            "kit/ci/test_feature_states.py",
            "kit/ci/future_stage.py",
            "kit/ci/test_future_stage.py",
            "kit/ci/future-stage-inventory.json",
            "kit/ci/perf_shadow.py",
            "kit/ci/test_perf_shadow.py",
        }
        expected.update({
            '.gitattributes',
            '.github/workflows/devlane-encrypted.yml',
            '.github/workflows/devlane-synthetic.yml',
            'ci/devlane-profiles.json',
            'kit/bootstrap/policy_devlane.py',
            'kit/devlane/__init__.py',
            'kit/devlane/rehearsal.py',
            'kit/devlane/test_rehearsal.py',
            'docs/devlane-procedure.md',
            'kit/devlane/bundle.py',
            'kit/devlane/control_audit.py',
            'kit/devlane/coordinator.py',
            'kit/devlane/decrypt_once.py',
            'kit/devlane/acceptance_diagnostics.py',
            'kit/devlane/diagnostic_contract.py',
            'kit/devlane/node_tool_snapshot.py',
            'kit/devlane/node_vendor_source.py',
            'kit/devlane/bounded_registry_io.py',
            'kit/devlane/cargo_projection.py',
            'kit/devlane/constraint_resolver.py',
            'kit/devlane/registry_prefetch.py',
            'kit/devlane/rust_preparation_v2.py',
            'kit/devlane/rust_lock_generation.py',
            'kit/devlane/test_rust_preparation_v2.py',
            'kit/devlane/test_rust_lock_generation.py',
            'kit/devlane/test_source_projection.py',
            'kit/devlane/rust_preparation_smoke.py',
            'kit/devlane/semver_stage.py',
            'kit/devlane/semver_offline_cache.py',
            'kit/devlane/semver_cargo_wrapper.py',
            'kit/devlane/semver-pins.json',
            'kit/devlane/temp_project_checkpoints.py',
            'kit/devlane/cgroup_exec.py',
            'kit/devlane/test_semver_review_fixes.py',
            'kit/devlane/test_node_vendor_source.py',
            'kit/devlane/test_node_vendor_source_r2.py',
            'kit/devlane/fetch.py',
            'kit/devlane/filter.py',
            'kit/devlane/host_cleanup.py',
            'kit/devlane/owned_tree_cleanup.py',
            'kit/devlane/isolated_cleanup.py',
            'kit/devlane/network_probe.py',
            'kit/devlane/refusal_codes.py',
            'kit/devlane/permit.py',
            'kit/devlane/prepare.py',
            'kit/devlane/project.py',
            'kit/devlane/public_audit.py',
            'kit/devlane/rust_test_runner.py',
            'kit/devlane/safe_json.mjs',
            'kit/devlane/supervisor.py',
            'kit/devlane/test_acceptance.py',
            'kit/devlane/test_worker_control_imports.py',
            'kit/devlane/test_adapters.mjs',
            'kit/devlane/test_audit_contracts.py',
            'kit/devlane/fixtures/control-synthetic-43245798187.log.hex',
            'kit/devlane/fixtures/encrypted-audit-43284558151.log.hex',
            'kit/devlane/fixtures/encrypted-run-43284558151-identity.json',
            'kit/devlane/fixtures/encrypted-run-43284558151-jobs.json.hex',
            'kit/devlane/fixtures/encrypted-run-43284558151.log.hex',
            'kit/devlane/fixtures/encrypted-workflow-43284558151.yml',
            'kit/devlane/fixtures/encrypted-workflow-f0ddd39554b2e48fbad7e61126319f5ffcdd2b84.yml',
            'kit/devlane/fixtures/synthetic-workflow-43245798187.yml',
            'kit/devlane/fixtures/encrypted-audit-43296698158.log.hex',
            'kit/devlane/fixtures/encrypted-run-43296698158-identity.json',
            'kit/devlane/fixtures/encrypted-run-43296698158-jobs.json.hex',
            'kit/devlane/fixtures/encrypted-run-43296698158.log.hex',
            'kit/devlane/test_coordinator.py',
            'kit/devlane/sandbox_windows.py',
            'kit/devlane/sandbox_windows.ps1',
            'kit/devlane/sandbox_windows_native.cs',
            'kit/devlane/sandbox_windows_reporter.mjs',
            'kit/devlane/test_windows_sandbox.py',
            'kit/devlane/test_e2e.py',
            'kit/devlane/rust_rehearsal_fixture.py',
            'kit/devlane/fixtures/real-netns-dump-ubuntu2404.txt',
            'kit/devlane/fixtures/real-netns-rtnetlink-ipv4-ubuntu2404.bin',
            'kit/devlane/fixtures/real-netns-rtnetlink-ipv6-ubuntu2404.bin',
            'kit/devlane/fixtures/core-rust-rehearsal/Cargo.lock',
            'kit/devlane/fixtures/core-rust-rehearsal/Cargo.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/build.rs',
            'kit/devlane/fixtures/core-rust-rehearsal/deny.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/crates/support/Cargo.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/crates/support/src/lib.rs',
            'kit/devlane/fixtures/core-rust-rehearsal/src/lib.rs',
            'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/audits.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/config.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/imports.lock',
            'kit/devlane/fixtures/core-rust-rehearsal/fuzz/Cargo.lock',
            'kit/devlane/fixtures/core-rust-rehearsal/fuzz/Cargo.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/fuzz/corpus/valid-array.json',
            'kit/devlane/fixtures/core-rust-rehearsal/fuzz/corpus/valid-object.json',
            'kit/devlane/fixtures/core-rust-rehearsal/fuzz/src/main.rs',
            'kit/devlane/fixtures/core-rust-rehearsal/runtime/Cargo.lock',
            'kit/devlane/fixtures/core-rust-rehearsal/runtime/Cargo.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/runtime/crates/services/listener/Cargo.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/runtime/crates/services/listener/src/lib.rs',
            'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/audits.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/config.toml',
            'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/imports.lock',
            'kit/devlane/test_linux_runtime.py',
            'kit/devlane/test_rust_report.py',
            'kit/devlane/test_rust_test_runner.py',
            'kit/devlane/test_desktop_profile.py',
            'kit/devlane/deadline.py',
            'kit/devlane/rust_matrix_runner.py',
            'kit/devlane/rust_tooling.py',
            'kit/devlane/test_deadline.py',
            'kit/devlane/test_powershell_static.py',
            'kit/devlane/test_powershell_live.py',
            'kit/devlane/test_network_probe.py',
            'kit/devlane/test_rust_matrix_runner.py',
            'kit/devlane/test_rust_public_audit.py',
            'kit/devlane/typescript_reporter.mjs',
            'kit/devlane/fixtures/desktop-tauri-smoke/package-lock.json',
            'kit/devlane/fixtures/desktop-tauri-smoke/package.json',
            'kit/devlane/fixtures/desktop-tauri-smoke/build.mjs',
            'kit/devlane/fixtures/desktop-tauri-smoke/index.html',
            'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.lock',
            'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.toml',
            'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/build.rs',
            'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/icons/icon.png',
            'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/src/lib.rs',
            'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/src/main.rs',
            'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/tauri.conf.json',
            'kit/confinement/macos_boundary_guard.py',
            'kit/confinement/test_macos_boundary_guard.py',
            'kit/confinement/test_macos_context_load.py',
            'kit/confinement/test_macos_deny_default.py',
            'kit/confinement/test_macos_public_audit.py',
            'kit/devlane/sandbox_macos.py',
            'kit/devlane/control-crypto-requirements.txt',
            'kit/devlane/test_sandbox_macos.py',
            'kit/devlane/control_python.py',
            'kit/devlane/test_control_python.py',
        })
        self.assertEqual(set(PINNED_FILE_SHA256), expected)
        self.assertTrue({name for name in expected if type(name) is str}.issubset(PLATFORM_FILES))
        self.assertIn(("platform", ".github/workflows/public-policy.yml"), expected)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in PLATFORM_FILES:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            scan_tree(root, "platform")
            for name in (
                "kit/bootstrap/public_tree.py",
                "kit/confinement/native_loopback_profile.py",
                "kit/confinement/test_native_loopback_profile.py",
                "kit/confinement/linux_harness.py",
                "kit/confinement/macos_deny_default.py",
            ):
                with self.subTest(file=name):
                    edited = root / name
                    original = edited.read_bytes()
                    edited.write_bytes(original + b"\n")
                    with self.assertRaisesRegex(PublicTreeError, "file-hash-mismatch"):
                        scan_tree(root, "platform")
                    edited.write_bytes(original)
            edited = root / "kit/confinement/windows_native_preflight.cs"
            edited.write_text(edited.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(PublicTreeError, "file-hash-mismatch"):
                scan_tree(root, "platform")

    def test_role_signer_suite_is_registered_in_source_free_ci(self):
        workflow = (ROOT / ".github/workflows/core-rust-format-return.yml").read_text(encoding="utf-8")
        self.assertIn('unittest discover -s kit/confinement -p "test_role_signer.py"', workflow)

    def test_pinned_action_version_comment_is_the_only_permitted_comment(self):
        version_pin = "uses: actions/attest@" + PROBE_ACTION_SHA + " " + "\x23" + " v4.2.2"
        inspect_text(version_pin, "platform")
        for fixture in (
            "uses: actions/attest@main " + "\x23" + " v4.2.2",
            "uses: actions/attest@" + PROBE_ACTION_SHA + " " + "\x23" + " latest",
            "purpose " + "\x23" + " comment",
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
                    "        uses: actions/attest@" + PROBE_ACTION_SHA + " " + "\x23" + " v4.2.2",
                    action_step,
                )
                self.assertNotIn("        run:", action_step)
                self.assertNotIn("        shell:", action_step)

        action_line = "uses: actions/attest@" + PROBE_ACTION_SHA + " " + "\x23" + " v4.2.2"
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
            "purpose " + "\x23" + " comment",
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

    def test_only_valid_sha512_integrity_values_in_the_exact_npm_lock_are_exempt(self):
        valid_sri = "sha512-" + "A" * 10 + "/R" + "77" + "B" * 72 + "=="
        valid_field = '{"integrity": "' + valid_sri + '"}'

        inspect_text(valid_field, "platform", SYNTHETIC_NPM_LOCK_PATH)
        inspect_text(
            valid_field,
            "platform",
            "kit/devlane/fixtures/desktop-tauri-smoke/package-lock.json",
        )

        for text, relative_path in (
            (
                '{"integrity": "' + valid_sri + '", "note": "' + valid_sri + '"}',
                SYNTHETIC_NPM_LOCK_PATH,
            ),
            ('{"checksum": "' + valid_sri + '"}', SYNTHETIC_NPM_LOCK_PATH),
            (valid_field, "other/package-lock.json"),
        ):
            with self.subTest(relative_path=relative_path, text_class="unexempted"):
                with self.assertRaisesRegex(PublicTreeError, "plan-id-present"):
                    inspect_text(text, "platform", relative_path)

        malformed_sri = "sha512-" + "A" * 10 + "/R" + "77" + "B" * 71 + "=="
        with self.assertRaisesRegex(PublicTreeError, "plan-id-present"):
            inspect_text(
                '{"integrity": "' + malformed_sri + '"}',
                "platform",
                SYNTHETIC_NPM_LOCK_PATH,
            )

    def test_synthetic_lock_escapes_preserve_decoded_sha512_integrity_values(self):
        lock_path = ROOT / SYNTHETIC_NPM_LOCK_PATH
        raw_text = lock_path.read_text(encoding="utf-8")
        lock = json.loads(raw_text)
        fsevents_integrity = lock["packages"]["node_modules/fsevents"]["integrity"]
        why_is_node_running_integrity = lock["packages"]["node_modules/why-is-node-running"]["integrity"]
        self.assertIn("R" + "77", fsevents_integrity)
        self.assertIn("X" + "1", why_is_node_running_integrity)
        self.assertIn(r"\u0052", raw_text)
        self.assertIn(r"\u0058", raw_text)

    def test_rust_tooling_allows_only_exact_public_destinations_at_the_owned_path(self):
        from public_tree import PINNED_RUST_TOOLING_URLS
        expected_urls = frozenset((
            "https:" + "//github.com/" + "EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz",
            "https:" + "//github.com/" + "RustSec/rustsec/releases/download/cargo-audit/v0.22.2/cargo-audit-x86_64-unknown-linux-gnu-v0.22.2.tgz",
            "https:" + "//github.com/" + "mozilla/cargo-vet/releases/download/v0.10.3/cargo-vet-x86_64-unknown-linux-gnu.tar.xz",
            "https:" + "//github.com/" + "obi1kenobi/cargo-semver-checks/releases/download/v0.51.0/cargo-semver-checks-x86_64-unknown-linux-gnu.tar.gz",
            "https:" + "//github.com/" + "RustSec/advisory-db.git",
        ))
        self.assertEqual(PINNED_RUST_TOOLING_URLS, expected_urls)
        actual_source = (ROOT / "kit/devlane/rust_tooling.py").read_text(encoding="ascii")
        inspect_text(actual_source, "platform", "kit/devlane/rust_tooling.py")
        source = "\n".join('destination = "' + url + '"' for url in sorted(PINNED_RUST_TOOLING_URLS))
        inspect_text(source, "platform", "kit/devlane/rust_tooling.py")
        bad_sources = (
            source.replace("0.20.2", "0.20.3"),
            source + '\ndestination = "https:' + '//github.com/unapproved/private-source"',
            source + '\ndestination = "https:' + '//github.com/RustSec/rustsec/private"',
            source.replace("advisory-db.git", "advisory-db.git?ref=changed"),
        )
        for text, pool, path in (
            *((text, "platform", "kit/devlane/rust_tooling.py") for text in bad_sources),
            (source, "platform", "kit/devlane/other.py"),
            (source, "connect", "kit/devlane/rust_tooling.py"),
        ):
            with self.subTest(pool=pool, path=path):
                with self.assertRaisesRegex(PublicTreeError, "repository-url-present"):
                    inspect_text(text, pool, path)

    def test_rust_rehearsal_deny_registry_url_is_scoped_to_its_fixture_file(self):
        path = "kit/devlane/fixtures/core-rust-rehearsal/deny.toml"
        source = (ROOT / path).read_text(encoding="utf-8")
        inspect_text(source, "platform", path)
        with self.assertRaisesRegex(PublicTreeError, "repository-url-present"):
            inspect_text(source, "platform", "kit/devlane/unreviewed-deny.toml")

    def test_cargo_vet_store_headers_are_allowed_only_for_pinned_store_files(self):
        hash_sign = chr(35)
        headers = {
            "kit/devlane/fixtures/core-rust-rehearsal/supply-chain/config.toml": "config file",
            "kit/devlane/fixtures/core-rust-rehearsal/supply-chain/audits.toml": "audits file",
            "kit/devlane/fixtures/core-rust-rehearsal/supply-chain/imports.lock": "imports lock",
            "kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/config.toml": "config file",
            "kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/audits.toml": "audits file",
            "kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/imports.lock": "imports lock",
        }
        for path, label in headers.items():
            header = hash_sign + " cargo-vet " + label
            accepted, rejected = ("\n" + header + "\n\n", "\n" + header + "\n")
            if label == "imports lock":
                accepted, rejected = rejected, accepted
            inspect_text(accepted, "platform", path)
            with self.assertRaisesRegex(PublicTreeError, "comment-present"):
                inspect_text(header + "\n\n", "platform", path)
            with self.assertRaisesRegex(PublicTreeError, "comment-present"):
                inspect_text(rejected, "platform", path)
            with self.assertRaisesRegex(PublicTreeError, "comment-present"):
                inspect_text(accepted, "platform", path + ".copy")
            with self.assertRaisesRegex(PublicTreeError, "comment-present"):
                inspect_text("\n" + header + "\n\n" + header + "\n", "platform", path)

    def test_rust_rehearsal_allows_only_test_attributes_in_its_fixed_sources(self):
        path = "kit/devlane/fixtures/core-rust-rehearsal/src/lib.rs"
        source = (ROOT / path).read_text(encoding="utf-8")
        inspect_text(source, "platform", path)
        with self.assertRaisesRegex(PublicTreeError, "comment-present"):
            inspect_text("fn test() {" + chr(35) + "[ignore]}", "platform", path)
        with self.assertRaisesRegex(PublicTreeError, "comment-present"):
            inspect_text(chr(35) + "[test]", "platform", "kit/devlane/unreviewed.rs")

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
