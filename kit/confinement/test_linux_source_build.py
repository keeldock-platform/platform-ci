import base64
import contextlib
import hashlib
import io
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import urllib.parse
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import linux_source_build

_LINUX_ONLY = not sys.platform.startswith("linux")
if not _LINUX_ONLY:
    import gate_table
    import confinement_public_audit
    import confinement_verdict
    import log_canary
    import macos_core_contract


_FIXTURE_BODY = base64.b64encode(b"\x30\x0b" + b"fixture-der").decode("ascii")
_SOURCE_TOKEN = "ghs_" + "T" * 36


def _path_only_lock(count, prefix="member"):
    names = [prefix + "-" + str(index) for index in range(count)]
    text = "version = 4\n"
    for index, name in enumerate(names):
        text += '\n[[package]]\nname = "' + name + '"\nversion = "0.1.0"\n'
        if index == 0 and count > 1:
            text += "dependencies = [\n"
            for dependency in names[1:]:
                text += ' "' + dependency + '",\n'
            text += "]\n"
    return text


def _registry_lock():
    return _path_only_lock(1) + (
        '\n[[package]]\nname = "serde"\nversion = "1.0.1"\nsource = "'
        + linux_source_build.cargo_lock_bootstrap.cargo.REGISTRY_SOURCE
        + '"\nchecksum = "' + "b" * 64 + '"\n'
    )


class RuntimeDependencyWorkflowTests(unittest.TestCase):
    def test_runtime_node_and_npm_are_pinned_and_staged_outside_the_hardened_runner_temp(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/core-dependency-checks.yml").read_text(encoding="utf-8")
        node_step = workflow.split("- name: Set up the committed runtime Node version\n", 1)[1].split(
            "- name: Install the pinned runtime npm version\n", 1,
        )[0]
        npm_step = workflow.split("- name: Install the pinned runtime npm version\n", 1)[1].split(
            "- name: Harden runner paths before confined runtime checks\n", 1,
        )[0]
        self.assertIn("id: runtime-node", node_step)
        self.assertIn("NODE_VERSION: 24.22.2", node_step)
        self.assertIn('node_root="/tmp/kd-toolchains/node/node-v${NODE_VERSION}-linux-x64"', node_step)
        self.assertIn('"https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"', node_step)
        self.assertIn(
            "48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75",
            node_step,
        )
        self.assertIn('sha256sum --check --status', node_step)
        self.assertIn('[[ "$("$node_bin/node" --version)" == "v${NODE_VERSION}" ]]', node_step)
        self.assertIn('chmod -R a+rX,go-w "$node_root"', node_step)
        self.assertIn("printf 'node_bin=%s\\n' \"$node_bin\" >> \"$GITHUB_OUTPUT\"", node_step)
        self.assertIn("NODE_BIN: ${{ steps.runtime-node.outputs.node_bin }}", npm_step)
        self.assertIn('npm_root="/tmp/kd-toolchains/runtime-npm12"', npm_step)
        self.assertNotIn("$RUNNER_TEMP", npm_step)
        self.assertIn('chmod -R a+rX,go-w "$npm_root"', npm_step)
        self.assertIn('"$("$NODE_BIN/node" "$npm12" --version)" == "12.2.2"', npm_step)
        self.assertIn('"$("$NODE_BIN/node" --version)" == "v24.22.2"', npm_step)
        self.assertIn("KD_NODE_BIN: ${{ steps.runtime-node.outputs.node_bin }}", workflow)
        harden_step = workflow.split("- name: Harden runner paths before confined runtime checks\n", 1)[1].split(
            "- name: Prepare kernel restrictions and run the independent boundary self-test\n", 1,
        )[0]
        self.assertNotIn("NODE_BIN:", harden_step)
        self.assertNotIn("--node-bin", harden_step)

    def test_source_cache_writer_serializes_inventory_updates_without_cancelling_runs(self):
        root = Path(__file__).resolve().parents[2] / ".github/workflows"
        workflow = (root / "linux-source-admission.yml").read_text(encoding="utf-8")
        group = (
            "group: ${{ github.repository == 'keeldock-platform/platform-ci' && "
            "'platform-rust-cache-inventory' || format('platform-ci-run-{0}-{1}-{2}', "
            "github.workflow, github.run_id, github.run_attempt) }}"
        )
        self.assertIn(group, workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        core_reusable = (root / "core-dependency-checks.yml").read_text(encoding="utf-8")
        self.assertNotIn(group, core_reusable)


class SourceReaderCallerValidationTests(unittest.TestCase):
    def test_core_pull_request_source_reader_uses_only_the_job_token(self):
        source_sha = "a" * 40
        repository = linux_source_build.RUST_CACHE_CORE_REPOSITORY
        for base_ref in ("develop", "uat", "main"):
            env = {
                "CI_REPOSITORY": repository,
                "CI_EVENT_NAME": "pull_request",
                "CI_REF": "refs/pull/42/merge",
                "CI_BASE_REF": base_ref,
                "GITHUB_REF": "refs/pull/42/merge",
                "GITHUB_BASE_REF": base_ref,
                "GITHUB_SHA": source_sha,
                "GITHUB_TOKEN": "read-only-job-token",
                "REQUESTED_SOURCE_SHA": source_sha,
                "CONTROL_SHA": "b" * 40,
                "CI_SHA": source_sha,
            }
            with self.subTest(base_ref=base_ref), patch.object(
                linux_source_build, "_api_request", side_effect=[
                    (200, {"private": True, "full_name": repository}),
                    (200, {"sha": source_sha}),
                ],
            ) as api, contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertTrue(linux_source_build._source_reader_caller_allowed(env))
                self.assertEqual(linux_source_build.verify_source_reader(env), 0)
                self.assertEqual(api.call_count, 2)
                self.assertIn("secret_reader=none", output.getvalue())
                self.assertTrue(all(call.args[1] == "read-only-job-token" for call in api.call_args_list))

        invalid = dict(env, CI_REF="refs/pull/0/merge", GITHUB_REF="refs/pull/0/merge")
        with patch.object(linux_source_build, "_api_request") as api, self.assertRaises(
            linux_source_build.SourceBuildRefusal,
        ):
            linux_source_build.verify_source_reader(invalid)
        api.assert_not_called()

        with patch.object(linux_source_build, "_api_request") as api, self.assertRaises(
            linux_source_build.SourceBuildRefusal,
        ):
            linux_source_build.verify_source_reader(dict(env, SOURCE_READER_TOKEN=_SOURCE_TOKEN))
        api.assert_not_called()

    def test_reusable_workflow_is_secret_free_for_pr_source_read_and_cache_disabled_for_core(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/core-dependency-checks.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("Verify untrusted Core pull request source without App secrets"), 3)
        self.assertEqual(workflow.count("Checkout the exact Core pull request commit with the job token"), 3)
        self.assertEqual(workflow.count("'linux-source-read-untrusted'"), 4)
        self.assertNotIn("github.event_name == 'push' && github.repository == format", workflow)
        for match in re.finditer(
            r"(?ms)^      - name: Verify untrusted Core pull request source without App secrets\n(.*?)(?=^      - name: )",
            workflow,
        ):
            self.assertNotIn("secrets.", match.group(1))
            self.assertIn("GITHUB_TOKEN: ${{ github.token }}", match.group(1))


class PromotionDocumentationTests(unittest.TestCase):
    def test_promotion_docs_match_current_control_and_bootstrap(self):
        root = Path(__file__).resolve().parents[2]
        docs = (root / "docs/branch-promotion.md").read_text(encoding="utf-8")
        promotion_source = (root / "kit/promotion/branch_promotion.py").read_text(encoding="utf-8")
        promotion_context_block = promotion_source.split("WORKFLOW_CHECKS = {", 1)[1].split("\n}", 1)[0]
        current_control_contexts = re.findall(r'^\s+"([^"]+)",$', promotion_context_block, re.MULTILINE)
        documented_context_block = docs.split("The contexts checked by the promotion tool are:", 1)[1].split(
            "Use the job check names GitHub reports:", 1
        )[0]
        documented_contexts = re.findall(r"^\s+- `([^`]+)`$", documented_context_block, re.MULTILINE)
        self.assertEqual(len(current_control_contexts), 18)
        self.assertEqual(len(documented_contexts), 18)
        self.assertEqual(len(current_control_contexts), len(set(current_control_contexts)))
        self.assertEqual(len(documented_contexts), len(set(documented_contexts)))
        self.assertEqual(set(current_control_contexts), set(documented_contexts))
        self.assertIn("pull request 173 merged by protected linear fast-forward", docs)
        self.assertIn("5ef503e19fbeb600c3bbef9b047a15c238602efc", docs)
        self.assertNotIn("current `main` copy has only `push` and `pull_request`", docs)
        self.assertIn("Use only the approved public encrypted devlane", docs)
        self.assertIn("Private product source must not run through private-repository Actions", docs)


    def test_promotion_docs_reject_duplicate_context(self):
        root = Path(__file__).resolve().parents[2]
        docs_path = root / "docs/branch-promotion.md"
        docs = docs_path.read_text(encoding="utf-8")
        before, remaining = docs.split("The contexts checked by the promotion tool are:", 1)
        contexts, after = remaining.split("Use the job check names GitHub reports:", 1)
        first = re.search(r"(?m)^\s+- `([^`]+)`$", contexts)
        self.assertIsNotNone(first)
        duplicated = contexts[:first.end()] + "\n" + first.group(0) + contexts[first.end():]
        altered = before + "The contexts checked by the promotion tool are:" + duplicated
        altered += "Use the job check names GitHub reports:" + after
        original_read = Path.read_text

        def read_with_duplicate(path, *args, **kwargs):
            if path == docs_path:
                return altered
            return original_read(path, *args, **kwargs)

        with patch.object(Path, "read_text", read_with_duplicate):
            with self.assertRaises(AssertionError):
                self.test_promotion_docs_match_current_control_and_bootstrap()


@unittest.skipIf(_LINUX_ONLY, "the Linux source build suite runs only on Linux")
class LinuxSourceBuildTests(unittest.TestCase):
    def _cache_identity(self, event="pull_request", ref="refs/pull/42/merge", trust_class="primary"):
        control_sha = "b" * 40
        return {
            "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "SOURCE_REPOSITORY_ID": "123456789",
            "REQUESTED_SOURCE_SHA": "a" * 40,
            "CONTROL_SHA": control_sha,
            "CI_SHA": control_sha,
            "RUST_CACHE_TRUST_CLASS": trust_class,
            "CI_REF": ref,
            "CI_EVENT_NAME": event,
        }

    def test_reusable_dependency_preflight_accepts_protected_core_branches_and_pull_requests(self):
        base = {
            "CI_REUSABLE_CALL": "true",
            "CI_REPOSITORY": ("Moh-Bakr/" + "keeldock" + "-core"),
            "CI_SERVER_URL": "https://github.com",
            "CI_EVENT_NAME": "push",
            "CI_REF": "refs/heads/develop",
            "CI_BASE_REF": "",
            "CI_SHA": "a" * 40,
            "GITHUB_SHA": "a" * 40,
            "CONTROL_SHA": "b" * 40,
            "REQUESTED_SOURCE_SHA": "a" * 40,
            "CACHE_MODE": "none",
            "GITHUB_TOKEN": "runner-token",
        }
        caller_workflow = (
            "jobs:\n  dependencies:\n    uses: "
            "keeldock-platform/platform-ci/.github/workflows/core-dependency-checks.yml@"
            + base["CONTROL_SHA"] + "\n    secrets: inherit\n    with:\n"
            "      source_sha: ${{ github.sha }}\n      control_sha: "
            + base["CONTROL_SHA"] + "\n"
        )
        caller_payload = {
            "path": ".github/workflows/dependency-checks.yml",
            "encoding": "base64",
            "content": base64.b64encode(caller_workflow.encode("utf-8")).decode("ascii"),
        }
        stream = io.StringIO()
        with patch.object(linux_source_build, "_api_request", return_value=(200, caller_payload)), \
                contextlib.redirect_stdout(stream):
            result = linux_source_build.verify_dependency_preflight(base)
        self.assertEqual(result, 0)
        self.assertEqual(stream.getvalue(), "linux-dependency-preflight=verified cache=none mode=reusable\n")
        self.assertNotIn("runner-token", stream.getvalue())

        for branch in ("develop", "uat", "main"):
            with self.subTest(push_branch=branch), patch.object(
                linux_source_build, "_api_request", return_value=(200, caller_payload),
            ), contextlib.redirect_stdout(io.StringIO()):
                push = dict(base, CI_REF="refs/heads/" + branch)
                self.assertEqual(linux_source_build.verify_dependency_preflight(push), 0)
        for base_ref in ("develop", "uat", "main"):
            with self.subTest(pull_request_base=base_ref), patch.object(
                linux_source_build, "_api_request", return_value=(200, caller_payload),
            ), contextlib.redirect_stdout(io.StringIO()):
                pull_request = dict(
                    base, CI_EVENT_NAME="pull_request", CI_REF="refs/pull/42/merge",
                    CI_BASE_REF=base_ref,
                )
                self.assertEqual(linux_source_build.verify_dependency_preflight(pull_request), 0)
        for changes in (
            {"CI_REPOSITORY": "other/core"},
            {"CI_REF": "refs/heads/feature"},
            {"CI_EVENT_NAME": "pull_request", "CI_REF": "refs/pull/42/merge", "CI_BASE_REF": "feature"},
            {"CI_EVENT_NAME": "pull_request", "CI_REF": "refs/pull/0/merge", "CI_BASE_REF": "develop"},
            {"CI_EVENT_NAME": "push", "CI_REF": "refs/heads/feature"},
            {"REQUESTED_SOURCE_SHA": "c" * 40},
            {"CONTROL_SHA": "invalid"},
            {"CACHE_MODE": "read"},
        ):
            with self.subTest(changes=changes), self.assertRaises(linux_source_build.SourceBuildRefusal):
                with patch.object(linux_source_build, "_api_request", return_value=(200, caller_payload)):
                    linux_source_build.verify_dependency_preflight(dict(base, **changes))
        bad_payload = dict(caller_payload, content=base64.b64encode(
            caller_workflow.replace(base["CONTROL_SHA"], "c" * 40).encode("utf-8"),
        ).decode("ascii"))
        with patch.object(linux_source_build, "_api_request", return_value=(200, bad_payload)), \
                self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
            linux_source_build.verify_dependency_preflight(base)

    def test_source_reader_verifier_binds_core_branches_and_pr_refs_before_api_access(self):
        core = linux_source_build.RUST_CACHE_CORE_REPOSITORY
        source_sha = "a" * 40
        repo = {"id": 123, "private": True, "full_name": "KeelDock/private-source"}
        installation = {
            "repositories": [{"id": 123, "full_name": "KeelDock/private-source"}],
            "total_count": 1,
        }
        base = {
            "SOURCE_READER_TOKEN": _SOURCE_TOKEN,
            "SOURCE_REPOSITORY_ID": "123",
            "SOURCE_REPOSITORY_OWNER": "KeelDock",
            "SOURCE_REPOSITORY_NAME": "private-source",
            "REQUESTED_SOURCE_SHA": source_sha,
            "CI_REPOSITORY": core,
        }
        callers = [
            dict(base, CI_EVENT_NAME="push", CI_REF="refs/heads/" + branch, CI_BASE_REF="")
            for branch in ("develop", "uat", "main")
        ] + [
            dict(base, CI_REPOSITORY=linux_source_build.REPOSITORY,
                 CI_EVENT_NAME="workflow_dispatch", CI_REF="refs/heads/main", CI_BASE_REF=""),
            dict(base, CI_REPOSITORY=linux_source_build.REPOSITORY,
                 CI_EVENT_NAME="workflow_dispatch", CI_REF="refs/heads/untrusted", CI_BASE_REF=""),
        ]
        for env in callers:
            with self.subTest(event=env["CI_EVENT_NAME"], ref=env["CI_REF"], base=env["CI_BASE_REF"]), \
                    patch.object(linux_source_build, "_api_request", side_effect=[(200, repo), (200, installation)]) as api, \
                    patch.object(linux_source_build, "_reference_sha", return_value=source_sha), \
                    patch.object(linux_source_build, "_comparison", return_value="identical"), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(linux_source_build.verify_source_reader(env), 0)
                self.assertEqual(api.call_count, 2)

        for branch in ("develop", "uat", "main"):
            env = {
                "CI_REPOSITORY": core,
                "CI_EVENT_NAME": "pull_request",
                "CI_REF": "refs/pull/42/merge",
                "CI_BASE_REF": branch,
                "GITHUB_REF": "refs/pull/42/merge",
                "GITHUB_BASE_REF": branch,
                "GITHUB_SHA": source_sha,
                "GITHUB_TOKEN": "read-only-job-token",
                "REQUESTED_SOURCE_SHA": source_sha,
                "CONTROL_SHA": "b" * 40,
                "CI_SHA": source_sha,
            }
            with self.subTest(untrusted_pull_request_base=branch), \
                    patch.object(linux_source_build, "_api_request", side_effect=[
                        (200, {"private": True, "full_name": core}),
                        (200, {"sha": source_sha}),
                    ]) as api, contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(linux_source_build.verify_source_reader(env), 0)
                self.assertEqual(api.call_count, 2)
                self.assertEqual(
                    output.getvalue(),
                    "linux-source-reader=verified repository=core pull_request=untrusted secret_reader=none\n",
                )
                for _, args, _ in api.mock_calls:
                    self.assertEqual(args[1], "read-only-job-token")

        pr_with_secret = {
            "CI_REPOSITORY": core,
            "CI_EVENT_NAME": "pull_request",
            "CI_REF": "refs/pull/42/merge",
            "CI_BASE_REF": "develop",
            "GITHUB_REF": "refs/pull/42/merge",
            "GITHUB_BASE_REF": "develop",
            "GITHUB_SHA": source_sha,
            "GITHUB_TOKEN": "read-only-job-token",
            "REQUESTED_SOURCE_SHA": source_sha,
            "CONTROL_SHA": "b" * 40,
            "CI_SHA": source_sha,
            "SOURCE_READER_TOKEN": _SOURCE_TOKEN,
        }
        with patch.object(linux_source_build, "_api_request") as api, \
                self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "token"):
            linux_source_build.verify_source_reader(pr_with_secret)
        api.assert_not_called()

        rejected = (
            dict(base, CI_EVENT_NAME="push", CI_REF="refs/heads/feature", CI_BASE_REF=""),
            dict(base, CI_EVENT_NAME="push", CI_REF="refs/heads/develop", CI_BASE_REF="main"),
            dict(base, CI_EVENT_NAME="pull_request", CI_REF="refs/pull/0/merge", CI_BASE_REF="develop"),
            dict(base, CI_EVENT_NAME="pull_request", CI_REF="refs/pull/42/merge", CI_BASE_REF="feature"),
            dict(base, CI_EVENT_NAME="pull_request", CI_REF="refs/heads/develop", CI_BASE_REF="develop"),
            dict(base, CI_REPOSITORY="other/core", CI_EVENT_NAME="push", CI_REF="refs/heads/main"),
            dict(base, CI_REPOSITORY=linux_source_build.REPOSITORY,
                 CI_EVENT_NAME="pull_request", CI_REF="refs/pull/42/merge", CI_BASE_REF="main"),
        )
        for env in rejected:
            with self.subTest(rejected=env), patch.object(linux_source_build, "_api_request") as api, \
                    self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "token"):
                linux_source_build.verify_source_reader(env)
            api.assert_not_called()

    def test_core_dependency_workflow_is_reusable_and_pr_source_reads_have_no_app_secrets(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/core-dependency-checks.yml").read_text(encoding="utf-8")
        self.assertIn("  workflow_call:\n", workflow)
        self.assertIn("github.repository == format('{0}/{1}-{2}', 'Moh-Bakr', 'keeldock', 'core')", workflow)
        self.assertIn("github.event_name == 'pull_request'", workflow)
        self.assertIn("github.ref == 'refs/heads/uat'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("github.base_ref == 'uat'", workflow)
        self.assertIn("github.base_ref == 'main'", workflow)
        self.assertIn("startsWith(github.ref, 'refs/pull/')", workflow)
        self.assertIn("endsWith(github.ref, '/merge')", workflow)
        self.assertEqual(workflow.count("Verify untrusted Core pull request source without App secrets"), 3)
        self.assertEqual(workflow.count("Checkout the exact Core pull request commit with the job token"), 3)
        app_token_steps = re.findall(
            r"(?ms)^      - name: Mint a scoped source-reader token\n(.*?)(?=^      - name: )",
            workflow,
        )
        self.assertEqual(len(app_token_steps), 3)
        for step in app_token_steps:
            self.assertIn("if: ${{ github.event_name != 'pull_request' }}", step)
            self.assertIn("uses: actions/create-github-app-token@", step)
            self.assertIn("SOURCE_READER_PRIVATE_KEY: ${{ secrets.SOURCE_READER_PRIVATE_KEY }}", step)
        self.assertEqual(workflow.count("'linux-source-read-untrusted'"), 4)
        self.assertEqual(workflow.count("uses: actions/cache/restore@"), 2)
        self.assertEqual(workflow.count("uses: actions/cache/save@"), 2)
        cache_enable_lines = re.findall(r"(?m)^\s+KD_RUST_CACHE_ENABLED: (.*)$", workflow)
        self.assertEqual(cache_enable_lines, [
            "${{ github.event_name == 'workflow_dispatch' && github.repository == 'keeldock-platform/platform-ci' && github.ref == 'refs/heads/main' }}",
            "${{ github.event_name == 'workflow_dispatch' && github.repository == 'keeldock-platform/platform-ci' && github.ref == 'refs/heads/main' }}",
        ])
        self.assertNotIn("github.event_name == 'push' && github.repository == format", workflow)
        for match in re.finditer(r"(?ms)^      - name: Verify untrusted Core pull request source without App secrets\n(.*?)(?=^      - name: )", workflow):
            self.assertNotIn("secrets.", match.group(1))
            self.assertIn("GITHUB_TOKEN: ${{ github.token }}", match.group(1))
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
                self.assertIn("3edfce9056124e459a23f683a21433670d47daca", step)
                self.assertIn("rust-cache.tar", step)
                if "restore@" in action:
                    self.assertIn("KD_RUST_CACHE_ENABLED == 'true'", step)
                else:
                    condition = step.split("        if:", 1)[1].split("\n", 1)[0]
                    self.assertNotIn("pull_request", condition)
                offset += len(action)
        for name in (
            "Derive the exact Rust cache key", "Prepare runner-local Rust cache staging",
            "Restore the exact Rust build cache", "Import the validated Rust build cache",
            "Prepare the Rust cache after confined work exits", "Package the Rust build cache",
            "Save the Rust build cache for protected main",
        ):
            start = workflow.index("      - name: " + name + "\n")
            end = workflow.find("\n      - name:", start + 1)
            step = workflow[start:end if end >= 0 else None]
            self.assertIn("continue-on-error: true", step, name)
        self.assertIn("steps.rust-cache-import.outcome == 'success'", workflow)
        self.assertIn("steps.runtime-cache-import.outcome == 'success'", workflow)

    def test_cache_and_working_directory_policies_match_the_checkout_layout(self):
        root = Path(__file__).resolve().parents[2]
        admission = (root / ".github/workflows/linux-source-admission.yml").read_text(encoding="utf-8")
        quick = (root / ".github/workflows/core-linux-quick-return.yml").read_text(encoding="utf-8")
        reusable = (root / ".github/workflows/core-dependency-checks.yml").read_text(encoding="utf-8")

        self.assertIn("'linux-source-read-main'", admission)
        self.assertIn("github.ref == 'refs/heads/main'", admission)
        self.assertNotIn("working-directory: control", admission)
        for name in (
            "Derive Rust cache key", "Prepare runner-local Rust cache staging",
            "Restore exact Rust build cache", "Import validated Rust build cache",
            "Export validated Rust build cache after confined work", "Package the Rust build cache",
            "Save the exact Rust build cache", "Derive independent verifier Rust cache key",
            "Prepare independent verifier Rust cache staging", "Restore the independent verifier Rust build cache",
            "Import the independent verifier Rust cache", "Export the independent verifier Rust cache after confined work",
            "Package the independent verifier Rust cache", "Save the independent verifier Rust cache",
        ):
            start = admission.index("      - name: " + name + "\n")
            end = admission.find("\n      - name:", start + 1)
            step = admission[start:end if end >= 0 else None]
            self.assertIn("continue-on-error: true", step, name)
        self.assertNotIn("actions/cache/", quick)
        self.assertNotIn("KD_RUST_CACHE_ENCRYPTION_KEY_B64", quick)
        self.assertNotIn("working-directory: control", quick)

        for workflow in (admission, quick, reusable):
            declared_paths = set(re.findall(r"^\s+path: ([A-Za-z0-9._/-]+)\s*$", workflow, re.MULTILINE))
            for directory in re.findall(r"^\s+working-directory: ([A-Za-z0-9._/-]+)\s*$", workflow, re.MULTILINE):
                self.assertTrue(
                    directory in declared_paths or any(directory.startswith(path + "/") for path in declared_paths),
                    f"{directory} has no matching checkout path",
                )

    def test_optional_cache_validation_refuses_cache_without_failing_the_uncached_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            invalid = {
                "KD_RUST_CACHE_MODE": "read",
                "KD_RUST_CACHE_DIR": str(Path(temporary) / "missing-cache"),
                "KD_RUST_CACHE_KEY": "missing-key",
                "KD_RUST_CACHE_HIT": "true",
                "RUST_CACHE_OS": "Linux-x64",
                "RUST_CACHE_SCOPE": "rust",
                "RUST_CACHE_TRUST_CLASS": "primary",
            }
            self.assertIsNone(linux_source_build._optional_rust_cache(invalid, source, "rust"))

    def test_rust_cache_validator_accepts_only_an_exact_hash_keyed_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "fuzz").mkdir()
            (source / "runtime").mkdir()
            (source / "rust-toolchain.toml").write_text("[toolchain]\nchannel = '1.99.1'\n", encoding="ascii")
            for relative in ("Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock"):
                (source / relative).write_text("version = 4\n", encoding="ascii")
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            cache_dir = runner_temp / "kd-rust-cache"
            cache_dir.mkdir()
            base = {
                "KD_RUST_CACHE_MODE": "read", "KD_RUST_CACHE_DIR": str(cache_dir),
                "KD_RUST_CACHE_HIT": "false", "RUST_CACHE_OS": "Linux-x64",
                "RUST_CACHE_SCOPE": "rust", "RUNNER_TEMP": str(runner_temp),
                **self._cache_identity(),
            }
            identity = linux_source_build._rust_cache_identity(base)
            key = linux_source_build._rust_cache_key(source, "Linux-x64", "rust", **identity)
            base["KD_RUST_CACHE_KEY"] = key
            accepted = linux_source_build._validate_rust_cache(base, source, "rust")
            self.assertEqual(accepted["key"], key)
            self.assertFalse(accepted["hit"])
            self.assertIsNone(linux_source_build._validate_rust_cache({"KD_RUST_CACHE_MODE": ""}, source))
            self.assertTrue(linux_source_build._rust_cache_read_allowed(base))
            self.assertFalse(linux_source_build._rust_cache_write_allowed(base))
            changed_revision = dict(
                base, REQUESTED_SOURCE_SHA="c" * 40, CONTROL_SHA="d" * 40, CI_SHA="e" * 40,
            )
            self.assertNotEqual(
                linux_source_build._rust_cache_key(
                    source, "Linux-x64", "rust", **linux_source_build._rust_cache_identity(changed_revision),
                ),
                key,
            )
            changed_control = dict(base, CONTROL_SHA="d" * 40, CI_SHA="d" * 40)
            self.assertNotEqual(
                linux_source_build._rust_cache_key(
                    source, "Linux-x64", "rust", **linux_source_build._rust_cache_identity(changed_control),
                ),
                key,
            )
            primary = dict(
                base, **self._cache_identity("push", "refs/heads/main", "primary"),
            )
            primary_identity = linux_source_build._rust_cache_identity(primary)
            primary_key = linux_source_build._rust_cache_key(
                source, "Linux-x64", "rust", **primary_identity,
            )
            self.assertEqual(primary_key, key)
            primary["KD_RUST_CACHE_KEY"] = primary_key
            self.assertEqual(
                linux_source_build._validate_rust_cache(primary, source, "rust")["key"], primary_key,
            )
            verifier = dict(
                base, **self._cache_identity("push", "refs/heads/main", "independent-verifier"),
            )
            verifier["CI_REPOSITORY"] = "keeldock-platform/platform-verifier"
            verifier_identity = linux_source_build._rust_cache_identity(verifier)
            verifier_key = linux_source_build._rust_cache_key(
                source, "Linux-x64", "rust", **verifier_identity,
            )
            self.assertNotEqual(verifier_key, primary_key)
            verifier["KD_RUST_CACHE_KEY"] = verifier_key
            self.assertEqual(
                linux_source_build._validate_rust_cache(verifier, source, "rust")["key"],
                verifier_key,
            )
            for changes in (
                {"KD_RUST_CACHE_MODE": "write"},
                {"KD_RUST_CACHE_KEY": key + "x"},
                {"KD_RUST_CACHE_HIT": ""},
                {"RUST_CACHE_SCOPE": "runtime-workspace"},
                {"KD_RUST_CACHE_DIR": str(root / "outside")},
                {"CI_REF": "invalid-ref", "CI_EVENT_NAME": "pull_request"},
                {"CI_REF": "refs/heads/main", "CI_EVENT_NAME": "schedule"},
                {"SOURCE_REPOSITORY_ID": "987654321"},
                {"CI_REPOSITORY": "another/platform-ci"},
                {"RUST_CACHE_TRUST_CLASS": "untrusted"},
                {"REQUESTED_SOURCE_SHA": "not-a-sha"},
            ):
                with self.subTest(changes=changes), self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._validate_rust_cache(dict(base, **changes), source, "rust")
            (source / "runtime/Cargo.lock").write_text("version = 5\n", encoding="ascii")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "cache"):
                linux_source_build._validate_rust_cache(base, source, "rust")

    def test_rust_cache_key_logs_only_a_sanitised_success_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "private-source-path"
            source.mkdir()
            (source / "rust-toolchain.toml").write_text("[toolchain]\nchannel = '1.99.1'\n", encoding="ascii")
            (source / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            output = root / "output"
            output.write_text("", encoding="ascii")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                result = linux_source_build.write_rust_cache_key({
                    "SOURCE_PATH": str(source), "RUST_CACHE_OS": "Linux-x64",
                    "RUST_CACHE_SCOPE": "rust", "GITHUB_OUTPUT": str(output),
                    **self._cache_identity(),
                })
            logged = stream.getvalue()
            self.assertEqual(result, 0)
            self.assertEqual(logged, "linux-rust-cache-key=verified\n")
            self.assertNotIn(str(source), logged)
            self.assertNotIn("cache_key=", logged)
            self.assertRegex(
                output.read_text(encoding="ascii"),
                r"^cache_key=kd-rust-v5-Linux-x64-rust-primary-[a-f0-9]{40}-[a-f0-9]{40}-"
                r"[a-f0-9]{64}-[a-f0-9]{64}-[a-f0-9]{64}\n$",
            )

    def test_rust_cache_write_is_limited_by_trust_class_and_branch(self):
        self.assertTrue(linux_source_build._rust_cache_write_allowed({
            "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "RUST_CACHE_TRUST_CLASS": "primary",
            "CI_EVENT_NAME": "push", "CI_REF": "refs/heads/main",
        }))
        self.assertTrue(linux_source_build._rust_cache_write_allowed({
            "CI_REPOSITORY": "keeldock-platform/platform-verifier",
            "RUST_CACHE_TRUST_CLASS": "independent-verifier",
            "CI_EVENT_NAME": "push", "CI_REF": "refs/heads/main",
        }))
        self.assertFalse(linux_source_build._rust_cache_write_allowed({
            "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "RUST_CACHE_TRUST_CLASS": "untrusted",
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REF": "refs/heads/untrusted",
        }))
        self.assertFalse(linux_source_build._rust_cache_write_allowed({
            "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "RUST_CACHE_TRUST_CLASS": "primary",
            "CI_EVENT_NAME": "pull_request", "CI_REF": "refs/pull/42/merge",
        }))
        for context in (
            {"CI_REPOSITORY": linux_source_build.REPOSITORY, "RUST_CACHE_TRUST_CLASS": "untrusted", "CI_EVENT_NAME": "pull_request", "CI_REF": "refs/pull/42/merge"},
            {"CI_REPOSITORY": linux_source_build.REPOSITORY, "RUST_CACHE_TRUST_CLASS": "untrusted", "CI_EVENT_NAME": "push", "CI_REF": "refs/heads/feature"},
            {"CI_REPOSITORY": linux_source_build.REPOSITORY, "RUST_CACHE_TRUST_CLASS": "untrusted", "CI_EVENT_NAME": "push", "CI_REF": "refs/heads/main"},
        ):
            with self.subTest(context=context):
                self.assertFalse(linux_source_build._rust_cache_write_allowed(context))

    def test_rust_cache_copy_rejects_a_symlink_that_escapes_the_cache_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "cache"
            source.mkdir()
            outside = root / "outside"
            outside.write_text("not cache data", encoding="ascii")
            (source / "escape").symlink_to(outside)
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "cache"):
                linux_source_build._copy_validated_cache_tree(source, root / "copy")

    def test_rust_cache_copy_breaks_internal_hardlinks_into_independent_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "cache"
            source.mkdir()
            original = source / "first.o"
            original.write_text("compiled output", encoding="ascii")
            os.link(original, source / "second.o")
            destination = root / "copy"

            linux_source_build._copy_validated_cache_tree(source, destination)

            copied_first = destination / "first.o"
            copied_second = destination / "second.o"
            self.assertEqual(copied_first.read_text(encoding="ascii"), "compiled output")
            self.assertEqual(copied_second.read_text(encoding="ascii"), "compiled output")
            self.assertNotEqual(copied_first.stat().st_ino, copied_second.stat().st_ino)
            self.assertEqual(copied_first.stat().st_nlink, 1)
            self.assertEqual(copied_second.stat().st_nlink, 1)

    def test_rust_cache_copy_rejects_a_hardlink_alias_outside_the_cache_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "cache"
            source.mkdir()
            cached = source / "compiled.o"
            cached.write_text("compiled output", encoding="ascii")
            os.link(cached, root / "outside.o")

            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "cache"):
                linux_source_build._copy_validated_cache_tree(source, root / "copy")

    def test_rust_cache_archive_import_accepts_only_bounded_tree_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "rust-cache.tar"
            destination = root / "cache"
            with tarfile.open(archive_path, "w") as archive:
                for name in ("target", "cargo-home", "target/lib.rmeta"):
                    info = tarfile.TarInfo(name)
                    if name == "target/lib.rmeta":
                        payload = b"cached object"
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
                    else:
                        info.type = tarfile.DIRTYPE
                        archive.addfile(info)
            linux_source_build._extract_rust_cache_archive(archive_path, destination)
            self.assertEqual((destination / "target/lib.rmeta").read_bytes(), b"cached object")
            self.assertTrue((destination / "cargo-home").is_dir())

    def test_rust_cache_archive_import_rejects_traversal_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, member_type, linkname in (
                ("../escaped", tarfile.REGTYPE, ""),
                ("target/escape", tarfile.SYMTYPE, "../../outside"),
            ):
                archive_path = root / ("cache-" + str(len(name)) + ".tar")
                with tarfile.open(archive_path, "w") as archive:
                    for folder in ("target", "cargo-home"):
                        info = tarfile.TarInfo(folder)
                        info.type = tarfile.DIRTYPE
                        archive.addfile(info)
                    malicious = tarfile.TarInfo(name)
                    malicious.type = member_type
                    malicious.linkname = linkname
                    archive.addfile(malicious, io.BytesIO(b"x") if member_type == tarfile.REGTYPE else None)
                with self.subTest(member=name), self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "cache"):
                    linux_source_build._extract_rust_cache_archive(archive_path, root / "destination")

    def test_cargo_cache_staging_preserves_runner_ownership_and_worker_copy_can_set_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_home = root / "source-home"
            registry = source_home / "registry" / "index"
            registry.mkdir(parents=True)
            (registry / "metadata").write_text("locked package index", encoding="ascii")
            destination = root / "runner-fetch-home"
            with patch.object(linux_source_build.os, "chown", side_effect=PermissionError("runner cannot chown")) as chown:
                linux_source_build._copy_cargo_registry_cache(source_home, destination)
            chown.assert_not_called()
            self.assertEqual(
                (destination / "registry/index/metadata").read_text(encoding="ascii"),
                "locked package index",
            )
            worker_destination = root / "worker-cargo-home"
            with patch.object(linux_source_build.os, "chown") as chown:
                linux_source_build._copy_cargo_registry_cache(
                    source_home, worker_destination, owner=(62000, 62000),
                )
            self.assertTrue(chown.called)
            self.assertEqual(chown.call_args_list[0].args[1:], (62000, 62000))

    def test_cold_rust_cache_export_uses_privileged_read_and_runner_owned_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner_uid, runner_gid = os.getuid(), os.getgid()
            control = root / "control"
            control.mkdir()
            worker = control / "source"
            target = worker / "target"
            target.mkdir(parents=True, mode=0o700)
            (target / "lib.rmeta").write_text("compiled output", encoding="ascii")
            cargo_home = worker / ".kd-cargo-home"
            registry = cargo_home / "registry" / "src" / "locked-package"
            registry.mkdir(parents=True)
            (registry / "package.crate").write_text("locked source", encoding="ascii")
            source = root / "source-checkout"
            source.mkdir()
            (source / "rust-toolchain.toml").write_text("[toolchain]\nchannel = '1.99.1'\n", encoding="ascii")
            (source / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            runner_temp = root / "runner-temp"
            cache_dir = runner_temp / "kd-rust-cache"
            (cache_dir / "target").mkdir(parents=True)
            (cache_dir / "cargo-home" / "registry").mkdir(parents=True)
            (cache_dir / "cargo-home" / "git").mkdir(parents=True)
            env = {
                "SOURCE_PATH": str(source), "WORKER_PATH": str(worker), "CARGO_HOME": str(cargo_home),
                "RUNNER_TEMP": str(runner_temp), "KD_RUST_CACHE_MODE": "read",
                "KD_RUST_CACHE_DIR": str(cache_dir), "KD_RUST_CACHE_HIT": "false",
                "RUST_CACHE_OS": "Linux-x64", "RUST_CACHE_SCOPE": "rust",
                "RUST_CACHE_TRUST_CLASS": "primary", "CI_REPOSITORY": linux_source_build.REPOSITORY,
                "SOURCE_REPOSITORY_ID": "123456789", "REQUESTED_SOURCE_SHA": "a" * 40,
                "CONTROL_SHA": "b" * 40, "CI_SHA": "b" * 40,
                "CI_REF": "refs/heads/main", "CI_EVENT_NAME": "push",
                "SUDO_UID": str(runner_uid), "SUDO_GID": str(runner_gid),
            }
            env["KD_RUST_CACHE_KEY"] = linux_source_build._rust_cache_key(
                source, "Linux-x64", "rust", **linux_source_build._rust_cache_identity(env),
            )
            stream = io.StringIO()
            with patch.object(linux_source_build, "PROJECT_ROOT", control), \
                    patch.object(linux_source_build.os, "geteuid", return_value=0), \
                    patch.object(linux_source_build.linux_harness, "CHILD_UID", runner_uid), \
                    patch.object(linux_source_build.linux_harness, "CHILD_GID", runner_gid), \
                    contextlib.redirect_stdout(stream):
                result = linux_source_build.export_rust_cache(env)
            self.assertEqual(result, 0, stream.getvalue())
            self.assertEqual(stream.getvalue(), "linux-rust-cache=prepared\n")
            self.assertEqual((cache_dir / "target/lib.rmeta").read_text(encoding="ascii"), "compiled output")
            self.assertEqual(
                (cache_dir / "cargo-home/registry/src/locked-package/package.crate").read_text(encoding="ascii"),
                "locked source",
            )
            self.assertEqual((target.stat().st_mode & 0o777), 0o700)
            self.assertEqual((cache_dir / "target").stat().st_uid, runner_uid)
            self.assertEqual((cache_dir / "target").stat().st_gid, runner_gid)

    def test_public_platform_dependency_workflow_uses_read_only_hash_scoped_cache(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/core-dependency-checks.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("uses: actions/cache/restore@"), 2)
        self.assertEqual(workflow.count("uses: actions/cache/save@"), 2)
        self.assertEqual(workflow.count("restore-keys:"), 0)
        self.assertEqual(workflow.count("timeout 10m sudo -n --preserve-env="), 2)
        self.assertIn("actions/cache/restore@3edfce9056124e459a23f683a21433670d47daca", workflow)
        self.assertIn("actions/cache/save@3edfce9056124e459a23f683a21433670d47daca", workflow)
        self.assertIn("github.event_name == 'pull_request'", workflow)
        self.assertIn("KD_RUST_CACHE_ENABLED", workflow)
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
                    self.assertNotIn("pull_request", condition)
                offset += len(action)
        self.assertIn("RUST_CACHE_TRUST_CLASS: primary", workflow)
        self.assertEqual(workflow.count("$" + "{{ runner.temp }}/kd-rust-cache/rust-cache.tar"), 4)
        key_expression = (
            "KD_RUST_CACHE_ENCRYPTION_KEY_B64: ${{ github.repository == 'keeldock-platform/platform-ci' "
            "&& github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' "
            "&& secrets.RUST_CACHE_ENCRYPTION_KEY || '' }}"
        )
        self.assertEqual(workflow.count(key_expression), 4)
        self.assertEqual(workflow.count("linux-source-read-main"), 3)
        self.assertIn("github.event_name == 'pull_request' && (github.base_ref == 'develop' || github.base_ref == 'uat' || github.base_ref == 'main')", workflow)
        self.assertIn("startsWith(github.ref, 'refs/pull/') && endsWith(github.ref, '/merge')", workflow)
        self.assertIn("github.repository == format('{0}/{1}-{2}', 'Moh-Bakr', 'keeldock', 'core')", workflow)
        self.assertNotIn("pull_request' && github.repository == 'keeldock-platform/platform-ci'", workflow)
        self.assertIn("linux_source_build.py rust-cache-import", workflow)
        self.assertIn("linux_source_build.py rust-cache-package", workflow)
        for action in ("uses: actions/cache/restore@", "uses: actions/cache/save@"):
            offset = 0
            while True:
                offset = workflow.find(action, offset)
                if offset < 0:
                    break
                step_start = workflow.rfind("      - name:", 0, offset)
                step_end = workflow.find("      - name:", offset)
                if step_end < 0:
                    step_end = len(workflow)
                cached_paths = workflow[step_start:step_end]
                self.assertIn("rust-cache.tar", cached_paths)
                self.assertNotIn("cargo-home/registry", cached_paths)
                self.assertNotIn("cargo-home/git", cached_paths)
                self.assertNotIn("/kd-rust-cache/target", cached_paths)
                offset += len(action)

    def test_public_rust_cache_encryption_is_required_and_round_trips(self):
        self.assertTrue(linux_source_build._rust_cache_requires_encryption({
            "CI_REPOSITORY": "keeldock-platform/platform-ci",
        }))
        self.assertFalse(linux_source_build._rust_cache_requires_encryption({
            "CI_REPOSITORY": ("Moh-Bakr/" + "keeldock" + "-core"),
        }))
        key = base64.b64encode(b"k" * 32).decode("ascii")
        self.assertEqual(
            linux_source_build._rust_cache_encryption_key({"KD_RUST_CACHE_ENCRYPTION_KEY_B64": key}), key,
        )
        with self.assertRaises(linux_source_build.SourceBuildRefusal):
            linux_source_build._rust_cache_encryption_key({"KD_RUST_CACHE_ENCRYPTION_KEY_B64": "invalid"})
        if shutil.which("gpg") is None:
            self.skipTest("gpg is unavailable")
        with tempfile.TemporaryDirectory(prefix="kd-cache-encryption-test-") as directory:
            root = Path(directory)
            original = root / "cache.tar"
            encrypted = root / "cache.tar.gpg"
            decrypted = root / "cache-restored.tar"
            original.write_bytes(b"private compiled cache fixture")
            linux_source_build._run_rust_cache_gpg("encrypt", original, encrypted, key, root / "gpg-encrypt")
            self.assertNotEqual(encrypted.read_bytes(), original.read_bytes())
            linux_source_build._run_rust_cache_gpg("decrypt", encrypted, decrypted, key, root / "gpg-decrypt")
            self.assertEqual(decrypted.read_bytes(), original.read_bytes())

    def test_gate_order_matches_the_shared_macos_contracts(self):
        expected = (
            macos_core_contract.GATE_NAMES
            + macos_core_contract.PARSER_GATE_NAMES
            + gate_table.NODE_GATE_NAMES
        )
        self.assertEqual(linux_source_build.GATES, expected)
        self.assertEqual(len(linux_source_build.GATES), 15)
        self.assertEqual(linux_source_build.API_FEATURE_GATE_NAMES, macos_core_contract.API_FEATURE_GATE_NAMES)

    def test_source_job_steps_match_the_policy_audit_contract(self):
        self.assertEqual(
            linux_source_build.SOURCE_STEP_NAMES,
            (
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
            ),
        )
        self.assertEqual(linux_source_build.VERDICT_STEP_NAMES, (
            "Fetch exact public control", "Repeat independent preflight",
            "Record verifier image and fetch pinned toolchains",
            "Harden verifier runner paths", "Run independent boundary self-test",
            "Mint verifier scoped source-reader token",
            "Verify source independently against binding, tree, signatures and lock",
            "Revoke verifier token and verify rejection",
            "Derive independent verifier Rust cache key",
            "Prepare independent verifier Rust cache staging",
            "Restore the independent verifier Rust build cache",
            "Import the independent verifier Rust cache",
            "Fetch verifier Rust dependencies from committed lockfiles",
            "Fetch independent npm tarballs by lock integrity",
            "Prepare independent offline project inputs",
            "Re-run independent positive controls before project execution",
            "Run independent offline project gates",
            "Merge independent confinement records",
            "Export the independent verifier Rust cache after confined work",
            "Package the independent verifier Rust cache",
            "Save the independent verifier Rust cache",
            "Verify unprivileged proof handoff",
            "Publish confinement verdict",
        ))
        self.assertEqual(
            linux_source_build.OPTIONAL_SOURCE_STEPS,
            frozenset((
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
                "Run all offline project gates",
                "Export validated Rust build cache after confined work",
                "Package the Rust build cache",
                "Save the exact Rust build cache",
                "Forced faults must fail closed",
            )),
        )

    def test_source_step_contract_matches_workflow_in_source_and_synthetic_modes(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/linux-source-admission.yml").read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^  linux-source-admission-source-read:\n(.*?)(?=^  linux-source-admission-verdict:)",
            workflow,
        )
        self.assertIsNotNone(match)
        producer = match.group(1)
        self.assertIn("cache_key: ${{ steps.rust-cache-key.outputs.cache_key }}", producer)
        self.assertIn("id: rust-cache-key", producer)
        self.assertIn("RUST_CACHE_SCOPE: linux-source-admission", producer)
        self.assertNotIn("steps.verifier-rust-cache-key.outputs.cache_key", producer)
        actual_steps = tuple(re.findall(r"^      - name: (.+)$", producer, re.MULTILINE))
        self.assertEqual(actual_steps, linux_source_build.SOURCE_STEP_NAMES)
        self.assertIn("Fetch Rust dependencies from the committed lockfiles", actual_steps)
        self.assertNotIn("Require trusted Rust licence admission", actual_steps)
        verdict_match = re.search(
            r"(?ms)^  linux-source-admission-verdict:\n(.*?)(?=^  linux-source-admission-audit:)",
            workflow,
        )
        self.assertIsNotNone(verdict_match)
        verifier = verdict_match.group(1)
        self.assertIn(
            "cache_key: ${{ steps.verifier-rust-cache-key.outputs.cache_key }}", verifier,
        )
        self.assertIn("id: verifier-rust-cache-key", verifier)
        self.assertIn("RUST_CACHE_SCOPE: linux-source-verifier", verifier)
        self.assertNotIn("steps.rust-cache-key.outputs.cache_key", verifier)
        audit_match = re.search(
            r"(?ms)^  linux-source-admission-audit:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow,
        )
        self.assertIsNotNone(audit_match)
        self.assertIn("needs.linux-source-admission-source-read.outputs.cache_key", audit_match.group(1))
        self.assertIn("needs.linux-source-admission-verdict.outputs.cache_key", audit_match.group(1))
        self.assertNotIn("steps.verifier-rust-cache-key.outputs.cache_key", audit_match.group(1))
        verdict_steps = tuple(re.findall(r"^      - name: (.+)$", verdict_match.group(1), re.MULTILINE))
        self.assertEqual(verdict_steps, linux_source_build.VERDICT_STEP_NAMES)
        self.assertIn("Fetch verifier Rust dependencies from committed lockfiles", verdict_steps)
        self.assertNotIn("Require trusted Rust licence admission independently", verdict_steps)
        for mode in ("source", "synthetic"):
            expected = linux_source_build._expected_run(
                {"CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1",
                 "CI_MODE": mode, "REQUESTED_SOURCE_SHA": "b" * 40},
                "c" * 64,
            )
            job = expected["jobs"]["linux-source-admission-source-read"]
            if mode == "source":
                self.assertEqual(
                    job["steps"],
                    ("Set up job",) + actual_steps + ("Post Mint scoped source-reader token", "Complete job"),
                )
                self.assertNotIn("Fetch Rust dependencies from the committed lockfiles", job["optional_steps"])
                self.assertEqual(
                    set(job["optional_steps"]),
                    set(linux_source_build.CACHE_SOURCE_STEPS) | {"Forced faults must fail closed"},
                )
                self.assertTrue(set(linux_source_build.GATES).isdisjoint(job["optional_steps"]))
            else:
                self.assertEqual(job["steps"], ("Set up job",) + actual_steps + ("Complete job",))
                self.assertIn("Fetch Rust dependencies from the committed lockfiles", job["optional_steps"])

    def test_producer_and_independent_verifier_fetch_committed_cargo_locks_before_preparation(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/linux-source-admission.yml").read_text(encoding="utf-8")
        rust_fetch = workflow.index("Fetch Rust dependencies from the committed lockfiles")
        npm_fetch = workflow.index("Fetch npm tarballs by committed lock integrity")
        prepare = workflow.index("Prepare offline project inputs")
        self.assertLess(rust_fetch, prepare)
        self.assertLess(npm_fetch, prepare)
        self.assertNotIn("KD_STAGED_INVENTORY_RECEIPT", workflow)
        self.assertNotIn("Require trusted Rust licence admission", workflow)
        code = Path(linux_source_build.__file__).read_text(encoding="ascii")
        self.assertIn('"fetch", "--locked", "--manifest-path"', code)
        self.assertNotIn("_check_d145_runtime_profile(", code)
        self.assertNotIn("_read_staged_inventory_receipt", code)
        self.assertLess(workflow.index("Fetch verifier Rust dependencies from committed lockfiles"),
                        workflow.index("Prepare independent offline project inputs"))

    def test_dependency_build_jobs_harden_and_recheck_the_runner_before_project_code(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/core-dependency-checks.yml").read_text(encoding="utf-8")
        rust_match = re.search(r"(?ms)^  rust:\n(.*?)(?=^  runtime-workspace:)", workflow)
        runtime_match = re.search(r"(?ms)^  runtime-workspace:\n(.*?)(?=^  npm:)", workflow)
        self.assertIsNotNone(rust_match)
        self.assertIsNotNone(runtime_match)
        for job, command in (
            (rust_match.group(1), "kit/confinement/linux_source_build.py dependency-locked-builds"),
            (runtime_match.group(1), "kit/confinement/linux_source_build.py runtime-workspace"),
        ):
            names = tuple(re.findall(r"^      - name: (.+)$", job, re.MULTILINE))
            harden = names.index("Harden runner paths before confined project checks") if "Harden runner paths before confined project checks" in names else names.index("Harden runner paths before confined runtime checks")
            selftest = names.index("Prepare kernel restrictions and run the independent boundary self-test")
            recheck = names.index("Re-run positive controls immediately before confined Rust checks") if "Re-run positive controls immediately before confined Rust checks" in names else names.index("Re-run positive controls immediately before runtime checks")
            build = names.index("Build and test root and fuzz Rust workspaces with locks enforced") if "Build and test root and fuzz Rust workspaces with locks enforced" in names else names.index("Run npm --prefix runtime run check:workspace in confinement")
            self.assertLess(harden, selftest)
            self.assertLess(selftest, recheck)
            self.assertLess(recheck, build)
            recheck_start = job.index("Re-run positive controls immediately before")
            build_start = job.index("- name: " + names[build])
            self.assertIn("linux_boundary.py recheck", job[recheck_start:build_start])
            build_block = job[build_start:]
            self.assertIn(command, build_block)
            self.assertIn("working-directory: control", build_block)
        self.assertIn('if [[ -d "$registry_cache" && ! -L "$registry_cache" ]]; then', workflow)
        self.assertIn('cp -R "$registry_cache" "$cargo_home/"', workflow)
        runtime_job = runtime_match.group(1)
        node_step = runtime_job.split("- name: Set up the committed runtime Node version\n", 1)[1].split(
            "- name: Install the pinned runtime npm version\n", 1,
        )[0]
        self.assertIn('npm_root="/tmp/kd-toolchains/runtime-npm12"', runtime_job)
        self.assertNotIn('$RUNNER_TEMP/kd-runtime-npm12', runtime_job)
        self.assertIn('chmod -R a+rX,go-w "$npm_root"', runtime_job)
        self.assertIn("id: runtime-node", node_step)
        self.assertIn("NODE_VERSION: 24.22.2", node_step)
        self.assertIn(
            "48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75",
            node_step,
        )
        self.assertIn('sha256sum --check --status', node_step)
        self.assertIn('[[ "$("$node_bin/node" --version)" == "v${NODE_VERSION}" ]]', node_step)
        self.assertIn('chmod -R a+rX,go-w "$node_root"', node_step)
        self.assertIn("printf 'node_bin=%s\\n' \"$node_bin\" >> \"$GITHUB_OUTPUT\"", node_step)
        self.assertIn("KD_NODE_BIN: ${{ steps.runtime-node.outputs.node_bin }}", runtime_job)
        self.assertIn("NODE_BIN: ${{ steps.runtime-node.outputs.node_bin }}", runtime_job)
        self.assertNotIn("steps.toolchains.outputs.node_bin", runtime_job)

    def test_expected_run_assigns_the_plain_verdict_job_and_action_post(self):
        base = {"CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"}
        source = linux_source_build._expected_run({**base, "CI_MODE": "source"}, "b" * 64)
        synthetic = linux_source_build._expected_run({**base, "CI_MODE": "synthetic"}, "b" * 64)
        self.assertEqual(source["verdict_job"], "linux-source-admission-verdict")
        edged_verdict = ("Set up job",) + linux_source_build.VERDICT_STEP_NAMES + ("Complete job",)
        self.assertEqual(source["jobs"][source["verdict_job"]]["steps"], edged_verdict)
        self.assertEqual(synthetic["jobs"][synthetic["verdict_job"]]["steps"], edged_verdict)
        for run in (source, synthetic):
            for name in ("settings", "unit"):
                steps = run["jobs"]["linux-source-admission-" + name]["steps"]
                self.assertEqual((steps[0], steps[-1]), ("Set up job", "Complete job"))
        self.assertEqual(
            source["jobs"][source["verdict_job"]]["optional_steps"],
            linux_source_build.CACHE_VERDICT_STEPS,
        )
        self.assertEqual(
            synthetic["jobs"][synthetic["verdict_job"]]["optional_steps"],
            linux_source_build.OPTIONAL_VERDICT_SYNTHETIC_STEPS,
        )
        source_steps = source["jobs"]["linux-source-admission-source-read"]["steps"]
        self.assertEqual(source_steps[0], "Set up job")
        self.assertEqual(source_steps[-2:], ("Post Mint scoped source-reader token", "Complete job"))
        synthetic_steps = synthetic["jobs"]["linux-source-admission-source-read"]["steps"]
        self.assertNotIn("Post Mint scoped source-reader token", synthetic_steps)
        self.assertEqual((synthetic_steps[0], synthetic_steps[-1]), ("Set up job", "Complete job"))

    def test_toolchain_versions_are_pinned_and_the_node_archive_digest_is_the_official_release_digest(self):
        self.assertEqual(linux_source_build.NODE_VERSION, "24.22.1")
        self.assertEqual(linux_source_build.NPM_VERSION, "11.19.1")
        self.assertRegex(linux_source_build.NODE_LINUX_TARBALL_SHA256, r"\A[a-f0-9]{64}\Z")
        self.assertEqual(
            linux_source_build.NODE_LINUX_TARBALL_SHA256,
            "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6",
        )
        source = Path(linux_source_build.__file__).read_text(encoding="utf-8")
        self.assertIn('"/node-v" + NODE_VERSION + "-linux-x64.tar.xz"', source)
        self.assertIn('node_archive = root / "node-linux-x64.tar.xz"', source)
        self.assertNotIn("COORDINATOR_FILL" + "_NODE", linux_source_build.NODE_LINUX_TARBALL_SHA256)
        self.assertEqual(len(linux_source_build.RUST_COMPONENTS), 5)
        for name, url, digest in linux_source_build.RUST_COMPONENTS:
            with self.subTest(component=name):
                self.assertIn("1.99.1-x86_64-unknown-linux-gnu.tar.gz", url)
                self.assertRegex(digest, r"\A[a-f0-9]{64}\Z")

    def test_project_read_paths_are_outside_runner_temp(self):
        self.assertEqual(str(linux_source_build.TOOLCHAIN_ROOT), "/tmp/kd-toolchains")
        self.assertEqual(str(linux_source_build.PROJECT_ROOT), "/tmp/kd-project-worker")
        self.assertNotIn("runner-temp", str(linux_source_build.TOOLCHAIN_ROOT))
        self.assertNotIn("runner-temp", str(linux_source_build.PROJECT_ROOT))

    def test_archive_path_checks_allow_directory_entries_and_safe_relative_links(self):
        self.assertTrue(linux_source_build._safe_tar_member("component/"))
        self.assertFalse(linux_source_build._safe_tar_member("../escape"))
        self.assertTrue(linux_source_build._safe_tar_link("../lib/node.js"))
        self.assertFalse(linux_source_build._safe_tar_link("/etc/passwd"))

    def test_cargo_lock_accepts_the_official_registry_and_rejects_git_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "Cargo.lock"
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n',
                encoding="utf-8",
            )
            linux_source_build._validate_cargo_lock_sources(temporary)
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
                'source = "registry+https://' + 'github.com/rust-lang/crates.io-index"\n'
                'checksum = "' + "b" * 64 + '"\n',
                encoding="utf-8",
            )
            self.assertIsNone(linux_source_build._validate_cargo_lock_sources(temporary))
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
                'source = "git+https://example.invalid/repo"\n',
                encoding="utf-8",
            )
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._validate_cargo_lock_sources(temporary)

    def _root_descriptor(self, root):
        descriptor = linux_source_build._open_source_root(root)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def test_cargo_lock_read_is_bounded_and_refuses_traversal_faults(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            lock = root / "Cargo.lock"
            lock.write_bytes(b"x" * 17)
            descriptor = self._root_descriptor(root)
            candidate = linux_source_build._rust_lock_paths(descriptor)[0]
            with patch.object(linux_source_build, "MAX_CARGO_LOCK_BYTES", 16):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

            lock.write_bytes(b"version = 4\n")
            candidate = linux_source_build._rust_lock_paths(descriptor)[0]
            self.assertEqual(
                linux_source_build._read_bounded_cargo_lock(descriptor, candidate),
                b"version = 4\n",
            )

            with patch.object(linux_source_build.os, "scandir",
                              side_effect=PermissionError("synthetic traversal refusal")):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._rust_lock_paths(descriptor)

            lock.write_text("changed after discovery\n", encoding="ascii")
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

            lock.write_text("version = 4\n", encoding="ascii")
            candidate = linux_source_build._rust_lock_paths(descriptor)[0]
            original_read = os.read

            def replace_after_read(handle, maximum):
                payload = original_read(handle, maximum)
                lock.unlink()
                lock.write_bytes(b"replacement lock\n")
                return payload

            with patch.object(linux_source_build.os, "read", side_effect=replace_after_read):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

    def test_cargo_lock_traversal_refuses_swapped_ancestor_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "Cargo.lock").write_bytes(b"outside lock\n")
            nested = root / "sub"
            nested.mkdir()
            (nested / "Cargo.lock").write_bytes(b"version = 4\n")
            descriptor = self._root_descriptor(root)
            candidate = linux_source_build._rust_lock_paths(descriptor)[0]
            self.assertEqual(candidate[0], ("sub", "Cargo.lock"))

            nested.rename(root / "moved")
            nested.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

            nested.unlink()
            nested.mkdir()
            (nested / "Cargo.lock").write_bytes(b"version = 4\n")
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

    def test_cargo_lock_discovery_refuses_a_directory_swapped_before_its_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "Cargo.lock").write_bytes(b"outside lock\n")
            nested = root / "sub"
            nested.mkdir()
            (root / "Cargo.lock").write_bytes(b"version = 4\n")
            descriptor = self._root_descriptor(root)
            original = linux_source_build._open_verified_directory
            swapped = []

            def swap_then_open(root_fd, parts, identities):
                if parts == ("sub",) and not swapped:
                    swapped.append(True)
                    nested.rename(root / "moved")
                    nested.symlink_to(outside, target_is_directory=True)
                return original(root_fd, parts, identities)

            with patch.object(linux_source_build, "_open_verified_directory",
                              side_effect=swap_then_open):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._rust_lock_paths(descriptor)
            self.assertEqual(swapped, [True])

    def test_cargo_lock_discovery_reports_a_vanished_directory_as_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "source"
            root.mkdir()
            nested = root / "sub"
            nested.mkdir()
            (root / "Cargo.lock").write_bytes(b"version = 4\n")
            descriptor = self._root_descriptor(root)
            original = linux_source_build._open_verified_directory

            def remove_then_open(root_fd, parts, identities):
                if parts == ("sub",) and nested.exists():
                    nested.rmdir()
                return original(root_fd, parts, identities)

            with patch.object(linux_source_build, "_open_verified_directory",
                              side_effect=remove_then_open):
                with self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
                    linux_source_build._rust_lock_paths(descriptor)
            self.assertEqual(refused.exception.reason, "lock")

    def test_cargo_lock_discovery_skips_the_npm_tarball_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "source"
            tarballs = root / ".kd-npm-tarballs"
            tarballs.mkdir(parents=True)
            (root / "Cargo.lock").write_bytes(b"version = 4\n")
            for index in range(3):
                (tarballs / ("pkg-" + str(index) + ".tgz")).write_bytes(b"x")
            descriptor = self._root_descriptor(root)
            with patch.object(linux_source_build, "MAX_DIRECTORY_ENTRIES", 2):
                found = linux_source_build._rust_lock_paths(descriptor)
            self.assertEqual([item[0] for item in found], [("Cargo.lock",)])

    def test_cargo_lock_discovery_scans_a_nested_npm_tarball_named_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "source"
            nested = root / "sub" / ".kd-npm-tarballs"
            nested.mkdir(parents=True)
            (root / "Cargo.lock").write_bytes(b"version = 4\n")
            (nested / "Cargo.lock").write_bytes(b"version = 4\n")
            descriptor = self._root_descriptor(root)
            found = linux_source_build._rust_lock_paths(descriptor)
            self.assertEqual(
                sorted(item[0] for item in found),
                [("Cargo.lock",), ("sub", ".kd-npm-tarballs", "Cargo.lock")],
            )

    def test_cargo_lock_directory_entry_materialization_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ("Cargo.lock", "one", "two"):
                (root / name).write_text("version = 4\n", encoding="ascii")
            descriptor = self._root_descriptor(root)
            with patch.object(linux_source_build, "MAX_DIRECTORY_ENTRIES", 2):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._rust_lock_paths(descriptor)

            (root / "first").mkdir()
            (root / "second").mkdir()
            with patch.object(linux_source_build, "MAX_PENDING_DIRECTORIES", 1):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._rust_lock_paths(descriptor)

    def test_project_config_files_are_refused_or_removed_before_tool_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / ".cargo"
            cargo.mkdir()
            cargo_config = cargo / "config.custom"
            cargo_config.write_text("[build]\njobs = 2\n", encoding="utf-8")
            npmrc = root / ".npmrc"
            npmrc.write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")
            linux_source_build._neutralize_config_files(root)
            self.assertFalse(cargo_config.exists())
            self.assertFalse(npmrc.exists())
            cargo_config.write_text(
                '[source.crates-io]\nreplace-with = "alternate"\n', encoding="utf-8"
            )
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._neutralize_config_files(root)

    def test_cargo_fetch_uses_a_fresh_config_outside_candidate_config_discovery(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            base = Path(temporary)
            source = base / "candidate"
            runner_temp = base / "runner-temp"
            source.mkdir()
            runner_temp.mkdir()
            (source / "Cargo.toml").write_text(
                '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2024"\n', encoding="ascii",
            )
            (source / "Cargo.lock").write_text(_registry_lock(), encoding="ascii")
            candidate_config = source / ".cargo" / "config.toml"
            candidate_config.parent.mkdir()
            candidate_config.write_text(
                '[source.crates-io]\nreplace-with = "attacker"\n[source.attacker]\nregistry = "https://example.invalid/index"\n',
                encoding="ascii",
            )
            cargo = base / "rust" / "bin" / "cargo"
            cargo.parent.mkdir(parents=True)
            cargo.write_text("trusted cargo fixture\n", encoding="ascii")
            fetch_home = runner_temp / "cargo-home"
            output = runner_temp / "github-output"
            environment = {
                "SOURCE_PATH": str(source), "REQUESTED_SOURCE_SHA": "a" * 40,
                "RUST_ROOT": str(cargo.parent.parent), "KD_CARGO_FETCH_HOME": str(fetch_home),
                "RUNNER_TEMP": str(runner_temp), "GITHUB_OUTPUT": str(output),
            }
            result = subprocess.CompletedProcess([], 0, b"", b"")
            root_flags = os.O_RDONLY | os.O_DIRECTORY
            with patch.object(linux_source_build, "_open_source_root", side_effect=lambda unused: os.open(source, root_flags)), \
                    patch.object(linux_source_build, "_require_source_root_identity"), \
                    patch.object(linux_source_build, "_require_confined_manifests"), \
                    patch.object(linux_source_build, "_rust_lock_paths", return_value=[(("Cargo.lock",), ())]), \
                    patch.object(linux_source_build, "_read_bounded_cargo_lock", return_value=_registry_lock().encode("ascii")), \
                    patch.object(linux_source_build, "_run", return_value=result) as run:
                self.assertEqual(linux_source_build.fetch_cargo_locks(environment), 0)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(Path(run.call_args.args[1]), fetch_home)
            self.assertEqual(run.call_args.args[2]["HOME"], str(fetch_home))
            self.assertEqual(run.call_args.args[2]["CARGO_HOME"], str(fetch_home))
            self.assertEqual((fetch_home / "config.toml").read_text(encoding="ascii"), "\n")
            self.assertEqual((fetch_home / "config.toml").stat().st_mode & 0o777, 0o600)
            self.assertIn("attacker", candidate_config.read_text(encoding="ascii"))

    def test_npm_tarball_fetch_includes_the_runtime_lock_for_confined_workspace_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "candidate"
            runner_temp = base / "runner-temp"
            source.mkdir()
            runner_temp.mkdir()
            payloads = {
                "https://registry.npmjs.org/root-fixture/-/root-fixture-1.0.0.tgz": b"root tarball",
                "https://registry.npmjs.org/runtime-fixture/-/runtime-fixture-1.0.0.tgz": b"runtime tarball",
            }
            locks = {}
            for relative, (url, payload) in zip(
                ("package-lock.json", "runtime/package-lock.json"), payloads.items(), strict=True,
            ):
                integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
                lock = {"name": relative, "lockfileVersion": 3, "packages": {"node_modules/fixture": {
                    "version": "1.0.0", "resolved": url, "integrity": integrity,
                }}}
                lock_bytes = (json.dumps(lock) + "\n").encode("ascii")
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(lock_bytes)
                locks[relative] = lock_bytes
            env = {
                "SOURCE_PATH": str(source), "REQUESTED_SOURCE_SHA": "a" * 40,
                "KD_DEPENDENCY_ONLY": "true", "KD_INCLUDE_RUNTIME_NPM_LOCK": "true",
                "EXPECTED_RUNTIME_NODE_LOCK_SHA256": hashlib.sha256(locks["runtime/package-lock.json"]).hexdigest(),
                "RUNNER_TEMP": str(runner_temp), "GITHUB_OUTPUT": str(runner_temp / "github-output"),
            }

            def write_tarball(url, unused_integrity, destination):
                Path(destination).write_bytes(payloads[url])
                Path(destination).chmod(0o400)

            with patch.object(linux_source_build, "_check_committed_node_lock", return_value=("b" * 64, "c" * 64)), \
                    patch.object(linux_source_build, "_download_integrity", side_effect=write_tarball):
                self.assertEqual(linux_source_build.fetch_npm_tarballs(env), 0)
            index = json.loads((runner_temp / "kd-records" / "npm-tarballs.json").read_text(encoding="ascii"))
            self.assertEqual(set(index), set(payloads))
            self.assertEqual(len(list((runner_temp / "kd-npm-tarballs").glob("*.tgz"))), 2)

    def test_inventory_authenticates_both_npm_roots_before_staging_sanitizes_them_without_receipts(self):
        bootstrap = linux_source_build.cargo_lock_bootstrap
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "candidate"
            source.mkdir()
            for path, contents in (
                (".npmrc", "registry=https://registry.npmjs.org/\n"),
                ("runtime/.npmrc", "registry=https://registry.npmjs.org/\n"),
                ("package-lock.json", '{ "name":"root", "lockfileVersion":3, "packages":{} }\n'),
                ("runtime/package-lock.json", '{ "name":"runtime", "lockfileVersion":3, "packages":{} }\n'),
                ("runtime/apps/test-shell-desktop/src-tauri/tauri.conf.json", "{}\n"),
                ("runtime/apps/test-shell-mobile/src-tauri/tauri.conf.json", "{}\n"),
            ):
                target = source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(contents, encoding="ascii")
            rows = []
            for path in sorted(bootstrap._source_inventory_required_paths(source)):
                digest = hashlib.sha256((source / path).read_bytes()).hexdigest()
                fields = {
                    "path": path, "sha256": digest, "owner": "10.i",
                    "package": "test-shell", "target": "all-platforms",
                    "generator": "", "generator_version": "", "provenance": "",
                }
                rows.append("[[files]]\n" + "".join(
                    key + ' = "' + fields[key] + '"\n'
                    for key in bootstrap.SOURCE_INVENTORY_FIELDS
                ))
            inventory_path = source / bootstrap.SOURCE_INVENTORY_PATH
            inventory_path.parent.mkdir(parents=True)
            inventory_path.write_bytes(("schema_version = 1\n" + "".join(rows)).encode("ascii"))
            source_sha = "a" * 40
            bootstrap.validate_runtime_source_inventory(source, source_sha)
            tarball_index = base / "tarball-index.json"
            tarball_index.write_text("{}\n", encoding="ascii")
            project_root = base / "worker-root"
            project_root.mkdir()
            worker = project_root / "source"

            def open_project_root():
                return os.open(project_root, os.O_RDONLY | os.O_DIRECTORY)

            with patch.object(linux_source_build, "PROJECT_ROOT", project_root), \
                    patch.object(linux_source_build, "_open_project_root", side_effect=open_project_root), \
                    patch.object(linux_source_build.linux_harness, "CHILD_UID", os.getuid()), \
                    patch.object(linux_source_build.linux_harness, "CHILD_GID", os.getgid()):
                linux_source_build._prepare_worker_tree(source, tarball_index, {
                    "REQUESTED_SOURCE_SHA": source_sha,
                })

            self.assertFalse((worker / ".npmrc").exists())
            self.assertFalse((worker / "runtime/.npmrc").exists())
            self.assertTrue((worker / "package-lock.json").is_file())
            self.assertTrue((worker / "runtime/package-lock.json").is_file())
            staged_inventory = (worker / bootstrap.SOURCE_INVENTORY_PATH).read_bytes()
            rows, unused_digest = bootstrap.parse_runtime_source_inventory(staged_inventory, source_sha)
            by_path = {row["path"]: row["sha256"] for row in rows}
            self.assertNotIn(".npmrc", by_path)
            self.assertNotIn("runtime/.npmrc", by_path)
            self.assertEqual(
                by_path["package-lock.json"],
                hashlib.sha256((worker / "package-lock.json").read_bytes()).hexdigest(),
            )
            self.assertEqual(
                by_path["runtime/package-lock.json"],
                hashlib.sha256((worker / "runtime/package-lock.json").read_bytes()).hexdigest(),
            )

    def test_confined_worker_rewrites_both_npm_locks_to_verified_local_tarballs(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            base = Path(temporary)
            source = base / "candidate"
            source.mkdir()
            payloads = {
                "https://registry.npmjs.org/root-fixture/-/root-fixture-1.0.0.tgz": b"root tarball",
                "https://registry.npmjs.org/runtime-fixture/-/runtime-fixture-1.0.0.tgz": b"runtime tarball",
            }
            mapping = {}
            for index, (url, payload) in enumerate(payloads.items()):
                integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
                lock = {"lockfileVersion": 3, "packages": {"node_modules/fixture": {
                    "version": "1.0.0", "resolved": url, "integrity": integrity,
                }}}
                relative = "package-lock.json" if index == 0 else "runtime/package-lock.json"
                lock_path = source / relative
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                lock_path.write_text(json.dumps(lock) + "\n", encoding="ascii")
                tarball = base / (str(index) + ".tgz")
                tarball.write_bytes(payload)
                mapping[url] = str(tarball)
            index_path = base / "npm-index.json"
            index_path.write_text(json.dumps(mapping), encoding="ascii")
            project_root = base / "worker-root"
            project_root.mkdir()
            worker = project_root / "source"

            def open_project_root():
                return os.open(project_root, os.O_RDONLY | os.O_DIRECTORY)

            with patch.object(linux_source_build, "PROJECT_ROOT", project_root), \
                    patch.object(linux_source_build, "_open_project_root", side_effect=open_project_root), \
                    patch.object(linux_source_build.linux_harness, "CHILD_UID", os.getuid()), \
                    patch.object(linux_source_build.linux_harness, "CHILD_GID", os.getgid()):
                linux_source_build._prepare_worker_tree(source, index_path, {
                    "REQUESTED_SOURCE_SHA": "a" * 40, "KD_INCLUDE_RUNTIME_NPM_LOCK": "true",
                })

            for relative in ("package-lock.json", "runtime/package-lock.json"):
                lock = json.loads((worker / relative).read_text(encoding="ascii"))
                resolved = lock["packages"]["node_modules/fixture"]["resolved"]
                self.assertTrue(resolved.startswith("file://"))
                self.assertTrue(Path(urllib.parse.urlsplit(resolved).path).is_file())

    def test_gate_commands_are_offline_after_dependency_preparation(self):
        commands = linux_source_build._gate_commands(Path("/work"), "/rust", "/node")
        self.assertEqual(tuple(name for name, argv in commands), linux_source_build.GATES)
        for name, argv in commands:
            with self.subTest(gate=name):
                self.assertIn("--offline", argv)
        by_name = dict(commands)
        for name in linux_source_build.API_FEATURE_GATE_NAMES:
            with self.subTest(feature_gate=name):
                index = by_name[name].index("--features")
                self.assertEqual(by_name[name][index + 1], gate_table.API_FEATURE_NAME)
        for name in ("node_dependency_prepare", "typescript_typecheck", "typescript_tests"):
            with self.subTest(gate=name):
                self.assertIn("--ignore-scripts", by_name[name])
        for name in ("node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests"):
            with self.subTest(gate=name):
                self.assertTrue(any(item.startswith("--workspaces") or item == "--workspaces" for item in by_name[name]))

    def test_runtime_gate_commands_are_selected_for_the_complete_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            runtime = project / "runtime"
            runtime.mkdir()
            (runtime / "Cargo.toml").write_text("[workspace]\n", encoding="ascii")
            (runtime / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            commands = linux_source_build._gate_commands(project, "/rust", "/node")
            self.assertEqual(
                tuple(name for name, argv in commands),
                linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES,
            )
            cargo = "/rust/bin/cargo"
            manifest = str(runtime / "Cargo.toml")
            self.assertEqual(commands[-3:], (
                ("runtime_format", (cargo, "--locked", "--offline", "fmt", "--manifest-path",
                                     manifest, "--all", "--", "--check")),
                ("runtime_clippy", (cargo, "clippy", "--offline", "--manifest-path", manifest,
                                     "--workspace", "--all-targets", "--locked", "--", "-D", "warnings")),
                ("runtime_tests", (cargo, "test", "--offline", "--manifest-path", manifest,
                                    "--workspace", "--all-targets", "--locked")),
            ))
            (runtime / "Cargo.lock").unlink()
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._gate_commands(project, "/rust", "/node")

    def test_locked_build_commands_cover_root_fuzz_and_runtime_workspaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            for manifest in ("Cargo.toml", "fuzz/Cargo.toml", "runtime/Cargo.toml"):
                target = project / manifest
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("[package]\nname = 'fixture'\nversion = '0.1.0'\n", encoding="utf-8")
            commands = linux_source_build._locked_build_commands(project, "/rust")
        self.assertEqual(tuple(name for name, _ in commands), (
            "root_build", "root_test", "fuzz_build", "fuzz_test", "runtime_build", "runtime_test",
        ))
        for name, argv in commands:
            self.assertEqual(argv[0], "/rust/bin/cargo")
            self.assertIn("--locked", argv)
            self.assertIn("--offline", argv)
            self.assertEqual(argv[1], "build" if name.endswith("build") else "test")
        self.assertIn("--all-targets", commands[0][1])
        self.assertIn("--all-targets", commands[1][1])

    def test_locked_build_runner_uses_no_network_project_sandbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner_temp = Path(temporary)
            worker = runner_temp / "source"
            worker.mkdir()
            for manifest in ("Cargo.toml", "fuzz/Cargo.toml", "runtime/Cargo.toml"):
                target = worker / manifest
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("[package]\nname = 'fixture'\nversion = '0.1.0'\n", encoding="utf-8")
            environment = {
                "WORKER_PATH": str(worker), "CARGO_HOME": str(worker / ".kd-cargo-home"),
                "RUST_ROOT": "/rust", "RUNNER_TEMP": str(runner_temp),
            }
            session_result = types.SimpleNamespace(exit_code=0, timed_out=False, stdout=b"", stderr=b"")
            with patch.object(linux_source_build, "_validate_cargo_lock_sources") as validate_locks, patch.object(
                linux_source_build, "_project_gate_directories"
            ) as validate_worker, patch.object(
                linux_source_build.linux_session, "run_host", return_value=session_result
            ) as run_host:
                self.assertEqual(linux_source_build.run_locked_builds(environment), 0)
            self.assertTrue(validate_locks.called)
            self.assertTrue(validate_worker.called)
            self.assertEqual(run_host.call_count, 6)
            for call in run_host.call_args_list:
                self.assertEqual(call.kwargs["limits"], linux_source_build.PROJECT_GATE_LIMITS)
                self.assertEqual(call.kwargs["timeout"], linux_source_build.LOCKED_BUILD_TIMEOUT_SECONDS)
                self.assertEqual(call.args[4], {})
                self.assertIn("--offline", call.args[2])

    def test_runtime_workspace_suite_uses_no_network_bounded_project_sandbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner_temp = Path(temporary)
            worker = runner_temp / "source"
            (worker / "runtime" / "scripts").mkdir(parents=True)
            (worker / "runtime" / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            (worker / "runtime" / "package-lock.json").write_text("{}\n", encoding="ascii")
            (worker / "runtime" / "scripts" / "check-workspace.mjs").write_text("\n", encoding="ascii")
            environment = {
                "WORKER_PATH": str(worker), "CARGO_HOME": str(worker / ".kd-cargo-home"),
                "RUST_ROOT": "/rust", "NODE_BIN": "/node/bin", "NPM_BIN": "/npm/bin",
                "RUNNER_TEMP": str(runner_temp),
            }
            session_result = types.SimpleNamespace(exit_code=0, timed_out=False, stdout=b"", stderr=b"")
            with patch.object(linux_source_build, "_validate_cargo_lock_sources") as validate_locks, \
                    patch.object(linux_source_build, "_project_gate_directories") as validate_worker, \
                    patch.object(linux_source_build.linux_session, "run_host", return_value=session_result) as run_host, \
                    patch.object(linux_source_build.sys, "stdout", io.StringIO()) as output:
                self.assertEqual(linux_source_build.run_runtime_workspace(environment), 0)
            self.assertTrue(validate_locks.called)
            self.assertTrue(validate_worker.called)
            self.assertEqual(run_host.call_count, 1)
            launch = run_host.call_args.args[2]
            project_env = run_host.call_args.args[3]
            self.assertEqual(
                launch[-5:],
                ("/npm/bin/npm", "--prefix", "runtime", "run", "check:workspace"),
            )
            self.assertEqual(project_env["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(project_env["NPM_CONFIG_OFFLINE"], "true")
            self.assertNotIn("sudo", project_env.get("PATH", ""))
            self.assertEqual(run_host.call_args.kwargs["limits"], linux_source_build.RUNTIME_GATE_LIMITS)
            self.assertEqual(run_host.call_args.kwargs["timeout"], linux_source_build.RUNTIME_WORKSPACE_TIMEOUT_SECONDS)
            self.assertEqual(run_host.call_args.kwargs["cwd"], str(worker))
            self.assertEqual(run_host.call_args.args[4], {})
            self.assertIn("linux-runtime-workspace=passed", output.getvalue())

    def test_project_root_refuses_a_hostile_symlink(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            link = root.parent / (root.name + "-link")
            link.symlink_to(root, target_is_directory=True)
            try:
                with patch.object(linux_source_build, "PROJECT_ROOT", link):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._open_project_root()
            finally:
                link.unlink()

    def test_gate_directories_refuse_hostile_symlinks_without_ownership_changes(self):
        for create in (False, True):
            with self.subTest(create=create), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                worker = root / "source"
                outside = Path(temporary) / "outside"
                worker.mkdir(parents=True)
                outside.mkdir()
                for name in (".tmp", "target", ".npm-cache", ".kd-cargo-home"):
                    (worker / name).mkdir()
                (worker / ".home").symlink_to(outside, target_is_directory=True)
                before = outside.stat()
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                with patch.object(linux_source_build, "PROJECT_ROOT", root), patch.object(
                    linux_source_build, "_open_project_root", side_effect=lambda: os.open(root, flags)
                ), patch.object(linux_source_build.linux_harness, "CHILD_UID", os.getuid()), patch.object(
                    linux_source_build.linux_harness, "CHILD_GID", os.getgid()
                ), patch.object(linux_source_build.os, "fchown", side_effect=AssertionError("unexpected chown")):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._project_gate_directories(worker, create=create)
                after = outside.stat()
                self.assertEqual((before.st_uid, before.st_gid, before.st_mode), (after.st_uid, after.st_gid, after.st_mode))

    def test_repeated_preflight_refuses_missing_binding_before_duplicate_check(self):
        sha = "a" * 40
        env = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "CI_REF": "refs/heads/untrusted", "CI_MODE": "source",
        }
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(linux_source_build, "_source_inputs", side_effect=linux_source_build.SourceBuildRefusal("binding")) as binding, patch.object(
            linux_source_build, "_require_no_duplicate"
        ) as duplicate:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build.validate_dispatch(env, "token")
            binding.assert_called_once_with(env, prefix="LINUX_SOURCE")
            duplicate.assert_not_called()

    def test_protected_source_binding_refuses_one_changed_fingerprint(self):
        sha = "a" * 40
        base = "b" * 40
        fingerprint = "c" * 64
        env = {
            "REQUESTED_SOURCE_SHA": sha, "REQUESTED_BASE_SHA": base,
            "REQUESTED_BASE_BRANCH": "main", "REQUESTED_FINGERPRINT": fingerprint,
            "CI_SHA": "d" * 40, "LINUX_SOURCE_ALLOWED_SHA": sha,
            "LINUX_SOURCE_ALLOWED_BASE_SHA": base, "LINUX_SOURCE_ALLOWED_BASE_BRANCH": "main",
            "LINUX_SOURCE_ALLOWED_FINGERPRINT": "e" * 64,
            "LINUX_SOURCE_ALLOWED_CONTROL_SHA": "d" * 40,
            "SOURCE_REPOSITORY_ID": "7", "SOURCE_REPOSITORY_OWNER": "owner",
            "SOURCE_REPOSITORY_NAME": "source", "SOURCE_READER_INSTALLATION_ID": "8",
            "SOURCE_READER_CLIENT_ID": "client",
            "LINUX_SOURCE_ENVIRONMENT_NAME": "linux-source-read", "REQUESTED_ENVIRONMENT_NAME": "linux-source-read",
        }
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
            linux_source_build._source_inputs(env)
        env["LINUX_SOURCE_ALLOWED_FINGERPRINT"] = fingerprint
        self.assertEqual(linux_source_build._source_inputs(env)["reviewed_diff_sha256"], fingerprint)
        self.assertEqual(env["LINUX_SOURCE_ENVIRONMENT_NAME"], linux_source_build.ENVIRONMENT_NAME)
        for name, value in (("LINUX_SOURCE_ENVIRONMENT_NAME", "source-read"), ("REQUESTED_ENVIRONMENT_NAME", "source-read")):
            with self.subTest(name=name):
                changed = dict(env, **{name: value})
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                    linux_source_build._source_inputs(changed)

    def _environment_calls(self, environment_updates=None, branch_names=("main", "untrusted"),
                           listing_updates=None, status=200):
        environment = {
            "id": 100, "name": "linux-source-read", "can_admins_bypass": False,
            "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
        }
        environment.update(environment_updates or {})
        policy_ids = {"main": 201, "untrusted": 202}
        entries = [{"id": policy_ids.get(name, 203), "name": name, "type": "branch"} for name in branch_names]
        listing = {"total_count": len(entries), "branch_policies": entries}
        listing.update(listing_updates or {})
        calls = []

        def fake(path, token, method="GET", payload=None, expected=(200,)):
            calls.append((path, method, token))
            if path.endswith("/deployment-branch-policies?per_page=100"):
                return 200, listing
            return status, (environment if status == 200 else None)

        return fake, calls

    def _environment_ids(self):
        return {
            linux_source_build.ENVIRONMENT_ID_NAME: "100",
            linux_source_build.ENVIRONMENT_BRANCH_POLICY_ID_NAMES["main"]: "201",
            linux_source_build.ENVIRONMENT_BRANCH_POLICY_ID_NAMES["untrusted"]: "202",
        }

    def test_environment_readback_accepts_only_the_reviewed_names_and_branch_policy(self):
        fake, calls = self._environment_calls()
        with patch.object(linux_source_build, "_api_request", side_effect=fake):
            self.assertIsNone(linux_source_build._verify_environment("token", environ=self._environment_ids()))
        base = "/repos/" + linux_source_build.REPOSITORY + "/environments/linux-source-read"
        self.assertEqual(calls, [
            (base, "GET", "token"),
            (base + "/deployment-branch-policies?per_page=100", "GET", "token"),
        ])
        self.assertEqual(linux_source_build.ENVIRONMENT_NAME, "linux-source-read")
        self.assertEqual(linux_source_build.ENVIRONMENT_BRANCHES, ("main", "untrusted"))
        fake, calls = self._environment_calls(branch_names=("untrusted", "main"))
        with patch.object(linux_source_build, "_api_request", side_effect=fake):
            self.assertIsNone(linux_source_build._verify_environment("token", environ=self._environment_ids()))

    def test_environment_readback_refuses_every_other_policy_shape(self):
        refused_policy = {"custom_branch_policies": True, "protected_branches": False}
        cases = (
            {"status": 404},
            {"environment_updates": {"id": 101}},
            {"environment_updates": {"name": "source-read"}},
            {"environment_updates": {"can_admins_bypass": True}},
            {"environment_updates": {"can_admins_bypass": None}},
            {"environment_updates": {"can_admins_bypass": "false"}},
            {"environment_updates": {"deployment_branch_policy": None}},
            {"environment_updates": {"deployment_branch_policy": dict(refused_policy, custom_branch_policies=False)}},
            {"environment_updates": {"deployment_branch_policy": dict(refused_policy, protected_branches=True)}},
            {"environment_updates": {"deployment_branch_policy": {"custom_branch_policies": True}}},
            {"branch_names": ("main",)},
            {"branch_names": ("untrusted",)},
            {"branch_names": ()},
            {"branch_names": ("main", "untrusted", "develop")},
            {"branch_names": ("main", "develop")},
            {"branch_names": ("main", "main")},
            {"branch_names": ("main", "untrusted*")},
            {"listing_updates": {"total_count": 3}},
            {"listing_updates": {"total_count": "2"}},
            {"listing_updates": {"branch_policies": "main"}},
            {"listing_updates": {"branch_policies": [{"name": "main", "type": "tag"}, {"name": "untrusted", "type": "branch"}]}},
            {"listing_updates": {"branch_policies": [{"id": 999, "name": "main", "type": "branch"}, {"id": 202, "name": "untrusted", "type": "branch"}]}},
            {"listing_updates": {"branch_policies": [{"name": 7, "type": "branch"}, {"name": "untrusted", "type": "branch"}]}},
            {"listing_updates": {"branch_policies": ["main", "untrusted"]}},
        )
        for index, case in enumerate(cases):
            with self.subTest(index=index, case=case):
                fake, calls = self._environment_calls(**case)
                with patch.object(linux_source_build, "_api_request", side_effect=fake):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._verify_environment("token", environ=self._environment_ids())
        with patch.object(linux_source_build, "_api_request", side_effect=AssertionError("no request")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._verify_environment("token", "source-read", self._environment_ids())

    def test_environment_readback_requires_configured_environment_and_branch_policy_ids(self):
        for variable, value in (
            (linux_source_build.ENVIRONMENT_ID_NAME, ""),
            (linux_source_build.ENVIRONMENT_ID_NAME, "01"),
            (linux_source_build.ENVIRONMENT_BRANCH_POLICY_ID_NAMES["main"], "not-an-id"),
        ):
            with self.subTest(variable=variable, value=value):
                expected = self._environment_ids()
                expected[variable] = value
                with patch.object(linux_source_build, "_api_request", side_effect=AssertionError("no request")):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._verify_environment("token", environ=expected)

    def test_api_path_check_refuses_traversal_but_accepts_the_compare_range(self):
        base = "a" * 40
        head = "b" * 40
        repository = linux_source_build.REPOSITORY
        accepted = (
            "/repos/" + repository + "/compare/" + base + "..." + head,
            "/repos/" + repository + "/git/ref/heads/main",
            "/repos/" + repository + "/environments/linux-source-read/deployment-branch-policies?per_page=100",
            "/repos/" + repository + "/actions/workflows/linux-source-admission.yml/runs?per_page=100&status=queued",
            "/installation/token",
        )
        for path in accepted:
            with self.subTest(path=path):
                self.assertTrue(linux_source_build._safe_api_path(path))
        refused = (
            "", "repos/x", "/", "/repos//x", "/repos/x/", "/repos/../x", "/repos/x/..", "/repos/./x",
            "/repos/%2e%2e/x", "/repos/%2E%2e/x", "/repos/x\\y", "/repos/x\x00", None, 7,
            "/repos/x%2Fy", "/repos/x%5Cy", "/repos/x%00", "/repos/x?a" + "\x23" + "b", "/repos/x y", "/repos/x\n",
            "/repos/caf\u00e9", "/repos/x?a?b", "/repos/x;y", "/repos/x:y", "/repos/x@y", "/repos/x+y",
        )
        for path in refused:
            with self.subTest(path=path):
                self.assertFalse(linux_source_build._safe_api_path(path))
        with patch.object(linux_source_build.urllib.request, "build_opener", side_effect=AssertionError("no request")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "network"):
                linux_source_build._api_request("/repos/../x", "token")

    def test_owner_and_name_patterns_refuse_a_leading_dot_and_odd_characters(self):
        for value in ("owner", "_owner", "o.w-n_er", "a" * 100, "7"):
            with self.subTest(value=value):
                self.assertIsNotNone(linux_source_build.OWNER_RE.fullmatch(value))
        for value in ("", ".", "..", ".hidden", "-x", "a" * 101, "a/b", "a b", "a%2e", "a\n", "caf\u00e9"):
            with self.subTest(value=value):
                self.assertIsNone(linux_source_build.OWNER_RE.fullmatch(value))

    def test_comparison_sends_the_range_to_the_api_and_refuses_non_commit_values(self):
        base = "a" * 40
        head = "b" * 40
        requests = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, kind, value, trace):
                return False

            def read(self, size=-1):
                return b'{"status":"ahead"}'

        class Opener:
            def open(self, request, timeout=None):
                requests.append(request.full_url)
                return Response()

        with patch.object(linux_source_build.urllib.request, "build_opener", return_value=Opener()):
            self.assertEqual(linux_source_build._comparison("token", linux_source_build.REPOSITORY, base, head), "ahead")
            self.assertEqual(requests, [
                linux_source_build.API_ROOT + "/repos/" + linux_source_build.REPOSITORY
                + "/compare/" + base + "..." + head,
            ])
            for bad_base, bad_head in (("main", head), (base, "../x"), (base[:-1], head), (None, head), (base, 7)):
                with self.subTest(base=bad_base, head=bad_head):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._comparison("token", linux_source_build.REPOSITORY, bad_base, bad_head)
            self.assertEqual(len(requests), 1)

    def test_synthetic_dispatch_reaches_the_environment_readback_through_the_real_comparison(self):
        sha = "a" * 40
        env = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "CI_REF": "refs/heads/main", "CI_MODE": "synthetic",
            "REQUESTED_ENVIRONMENT_NAME": "linux-source-read", "LINUX_SOURCE_ENVIRONMENT_NAME": "",
        }
        requests = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, kind, value, trace):
                return False

            def read(self, size=-1):
                return b'{"status":"identical"}'

        class Opener:
            def open(self, request, timeout=None):
                requests.append(request.full_url)
                return Response()

        with patch.object(linux_source_build, "_reference_sha", side_effect=[sha, sha]), patch.object(
            linux_source_build.urllib.request, "build_opener", return_value=Opener()
        ), patch.object(linux_source_build, "_verify_environment") as environment, patch.object(
            linux_source_build, "_source_inputs", side_effect=AssertionError("no source binding in synthetic")
        ):
            self.assertEqual(linux_source_build.validate_dispatch(env, "token"), "synthetic")
            environment.assert_called_once_with("token")
        self.assertEqual(requests, [
            linux_source_build.API_ROOT + "/repos/" + linux_source_build.REPOSITORY
            + "/compare/" + sha + "..." + sha,
        ])

    def test_dispatch_reads_back_the_environment_after_binding_and_before_the_duplicate_check(self):
        sha = "a" * 40
        env = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "CI_REF": "refs/heads/untrusted", "CI_MODE": "source",
        }
        order = []
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=lambda unused, prefix=None: order.append("binding") or {}
        ), patch.object(
            linux_source_build, "_verify_environment", side_effect=lambda token: order.append("environment")
        ), patch.object(
            linux_source_build, "_require_no_duplicate", side_effect=lambda token, unused: order.append("duplicate")
        ):
            self.assertEqual(linux_source_build.validate_dispatch(env, "token"), "source")
        self.assertEqual(order, ["binding", "environment", "duplicate"])
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(linux_source_build, "_source_inputs", return_value={}), patch.object(
            linux_source_build, "_verify_environment", side_effect=linux_source_build.SourceBuildRefusal("binding")
        ), patch.object(linux_source_build, "_require_no_duplicate") as duplicate:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build.validate_dispatch(env, "token")
            duplicate.assert_not_called()

    def test_quick_tier_is_untrusted_and_source_only_and_checks_duplicates_in_its_own_workflow(self):
        sha = "a" * 40
        base = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "KD_LINUX_TIER": "quick",
        }
        self.assertEqual(
            linux_source_build.TIERS["quick"], ("core-linux-quick-return.yml", "Linux quick source "),
        )
        self.assertEqual(
            linux_source_build.TIERS["admission"], ("linux-source-admission.yml", "Linux admission source "),
        )
        for ref, mode in (
            ("refs/heads/main", "source"), ("refs/heads/main", "synthetic"),
            ("refs/heads/untrusted", "synthetic"),
        ):
            with self.subTest(ref=ref, mode=mode), patch.object(
                linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]
            ), patch.object(linux_source_build, "_comparison", return_value="ahead"):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                    linux_source_build.validate_dispatch(dict(base, CI_REF=ref, CI_MODE=mode), "token")
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
            linux_source_build.validate_dispatch(
                dict(base, KD_LINUX_TIER="other", CI_REF="refs/heads/untrusted", CI_MODE="source"), "token",
            )
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(linux_source_build, "_source_inputs", return_value={}), patch.object(
            linux_source_build, "_verify_environment"
        ), patch.object(linux_source_build, "_require_no_duplicate") as duplicate:
            env = dict(base, CI_REF="refs/heads/untrusted", CI_MODE="source")
            self.assertEqual(linux_source_build.validate_dispatch(env, "token"), "source")
            duplicate.assert_called_once_with("token", env)
        calls = []

        def runs(title):
            def fake(path, token, method="GET", payload=None, expected=(200,)):
                calls.append(path)
                status = "queued" if path.endswith("status=queued") else "in_progress"
                return 200, {"total_count": 1, "workflow_runs": [{
                    "id": 9, "display_title": title + sha, "status": status, "event": "workflow_dispatch",
                }]}
            return fake

        environment = {"GITHUB_RUN_ID": "5", "REQUESTED_SOURCE_SHA": sha, "KD_LINUX_TIER": "quick"}
        with patch.object(linux_source_build, "_api_request", side_effect=runs("Linux quick source ")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                linux_source_build._require_no_duplicate("token", environment)
        self.assertTrue(calls[0].startswith(
            "/repos/" + linux_source_build.REPOSITORY + "/actions/workflows/core-linux-quick-return.yml/runs?"
        ))
        with patch.object(linux_source_build, "_api_request", side_effect=runs("Linux admission source ")):
            self.assertIsNone(linux_source_build._require_no_duplicate("token", environment))
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                linux_source_build._require_no_duplicate("token", {"GITHUB_RUN_ID": "5", "REQUESTED_SOURCE_SHA": sha})
        self.assertTrue(calls[-1].startswith(
            "/repos/" + linux_source_build.REPOSITORY + "/actions/workflows/linux-source-admission.yml/runs?"
        ))

    def test_quick_expected_run_describes_the_quick_workflow_and_never_a_verdict(self):
        request = "ab" * 32
        base = {
            "KD_LINUX_TIER": "quick", "KD_QUICK_REQUEST_ID": request, "CI_SHA": "a" * 40,
            "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "REQUESTED_SOURCE_SHA": "c" * 40,
            "CI_REF": "refs/heads/untrusted", "CI_MODE": "source",
        }
        expected = linux_source_build._expected_run(base, "b" * 64)
        self.assertEqual(expected["mode"], "quick")
        self.assertEqual(expected["os"], "linux")
        self.assertEqual(expected["ci_ref"], "untrusted")
        self.assertEqual(expected["workflow_path"], ".github/workflows/core-linux-quick-return.yml")
        self.assertEqual(expected["display_title"], "Linux quick source " + "c" * 40)
        self.assertEqual(expected["request_id"], request)
        self.assertEqual(expected["artifact_names"], ("linux-quick-" + request,))
        self.assertEqual(expected["cache_digest"], "b" * 64)
        self.assertEqual(expected["quick_job"], "core-linux-quick-return-producer")
        self.assertEqual(expected["auditor_job"], "core-linux-quick-return-audit")
        self.assertNotIn("verdict_job", expected)
        self.assertNotIn("verdict_step", expected)
        self.assertEqual(
            sorted(expected["jobs"]),
            [
                "core-linux-quick-return-producer", "core-linux-quick-return-settings",
                "core-linux-quick-return-unit",
            ],
        )
        producer = expected["jobs"]["core-linux-quick-return-producer"]["steps"]
        self.assertEqual(producer, linux_source_build.QUICK_PRODUCER_STEP_NAMES)
        self.assertEqual(producer[0], "Set up job")
        self.assertEqual(producer[-1], "Complete job")
        self.assertEqual(producer[-2], "Post Mint scoped source-reader token")
        for spec in expected["jobs"].values():
            self.assertEqual(spec["optional_steps"], ())
            self.assertFalse(any("verdict" in step.lower() for step in spec["steps"]))
        self.assertEqual(
            confinement_public_audit.parse_expected(json.dumps(expected), True), expected,
        )
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/core-linux-quick-return.yml").read_text(
            encoding="utf-8",
        )
        producer_text = workflow.split("  core-linux-quick-return-producer:\n", 1)[1].split("  core-linux-quick-return-audit:\n", 1)[0]
        names = re.findall(r"(?m)^      - name: (.*)$", producer_text)
        self.assertEqual(["Set up job"] + names + ["Post Mint scoped source-reader token", "Complete job"],
                         list(producer))
        settings = workflow.split("  core-linux-quick-return-settings:\n", 1)[1].split("  core-linux-quick-return-unit:\n", 1)[0]
        self.assertEqual(
            ["Set up job"] + re.findall(r"(?m)^      - name: (.*)$", settings) + ["Complete job"],
            list(linux_source_build.QUICK_SETTINGS_STEP_NAMES),
        )
        for broken in ({"KD_QUICK_REQUEST_ID": "short"}, {"KD_QUICK_REQUEST_ID": ""}):
            with self.subTest(broken=broken), self.assertRaises(confinement_public_audit.AuditRefusal):
                linux_source_build._expected_run({**base, **broken}, "b" * 64)
        admission = linux_source_build._expected_run(
            {"CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "source"}, "b" * 64,
        )
        self.assertEqual(admission["mode"], "candidate")
        self.assertIn("verdict_job", admission)

    def test_quick_audit_runs_the_quick_mode_of_the_public_audit(self):
        calls = []

        def fake_main(arguments=None, environ=None):
            calls.append(list(arguments))
            return 0

        canary = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        for tier, arguments in (("quick", ["quick"]), ("admission", [])):
            with self.subTest(tier=tier), patch.object(
                confinement_public_audit, "main", side_effect=fake_main,
            ), patch.object(log_canary, "PINNED_CONFIG", log_canary.PINNED_CONFIG):
                code = linux_source_build.run_audit({"KD_LINUX_TIER": tier, "KD_LINUX_LOG_CANARY": canary})
                self.assertEqual(code, 0)
                self.assertEqual(calls[-1], arguments)

    def test_default_checkout_environment_reaches_the_source_fetch(self):
        identity = {"owner": "owner", "name": "source", "repository_id": "7", "source_sha": "a" * 40}
        repository = {"id": 7, "private": True, "full_name": "owner/source"}
        marker = RuntimeError("source fetch reached")

        def git_call(unused_repo, *arguments, **unused_keywords):
            if arguments[:2] == ("remote", "add"):
                raise marker
            return subprocess.CompletedProcess(arguments, 0, b"", b"")

        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"RUNNER_TEMP": temporary, "CI_REF": "refs/heads/untrusted", "SOURCE_READER_TOKEN": _SOURCE_TOKEN}, clear=True
        ), patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build, "_api_request", return_value=(200, repository)
        ), patch.object(linux_source_build, "_git", side_effect=git_call):
            with self.assertRaisesRegex(RuntimeError, "source fetch reached"):
                linux_source_build.checkout_source()

    def test_checkout_rejects_a_bad_signature_before_lock_or_project_work(self):
        source_sha = "a" * 40
        base_sha = "b" * 40
        identity = {
            "owner": "owner", "name": "source", "repository_id": "7", "source_sha": source_sha,
            "base_sha": base_sha, "base_branch": "main", "reviewed_diff_sha256": hashlib.sha256(b"").hexdigest(),
        }

        def git_call(unused_repo, *arguments, **unused_keywords):
            output = b""
            if arguments[:2] == ("rev-parse", "--verify"):
                reference = arguments[2]
                output = ((base_sha if reference.startswith("refs/remotes/") else "c" * 40 if reference == "HEAD^{tree}" else source_sha) + "\n").encode("ascii")
            return subprocess.CompletedProcess(arguments, 0, output, b"")

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            linux_source_build, "_source_inputs", return_value=identity
        ), patch.object(linux_source_build, "_api_request", return_value=(200, {
            "id": 7, "private": True, "full_name": "owner/source",
        })), patch.object(linux_source_build, "_git", side_effect=git_call), patch.object(
            linux_source_build, "_verify_signatures", side_effect=linux_source_build.SourceBuildRefusal("signature")
        ) as signatures:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "signature"):
                linux_source_build.checkout_source({
                    "RUNNER_TEMP": temporary, "CI_REF": "refs/heads/untrusted", "SOURCE_READER_TOKEN": _SOURCE_TOKEN,
                    "CI_WORKSPACE": temporary,
                })
            signatures.assert_called_once()

    def test_revoke_requires_the_unauthorized_response_and_writes_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"SOURCE_READER_TOKEN": _SOURCE_TOKEN, "RUNNER_TEMP": temporary}
            with patch.object(linux_source_build, "_api_request", side_effect=[(204, {}), (401, {})]) as api:
                self.assertEqual(linux_source_build.revoke_token(env), 0)
                self.assertEqual(api.call_count, 2)
                self.assertEqual(api.call_args.args[0], "/installation/repositories?per_page=1")
            receipt = json.loads((Path(temporary) / "kd-records" / "revocation.json").read_text(encoding="ascii"))
            self.assertTrue(receipt["rejected_after_revoke"])
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            linux_source_build, "_api_request", side_effect=[(204, {}), (200, {})]
        ):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "revocation"):
                linux_source_build.revoke_token({"SOURCE_READER_TOKEN": _SOURCE_TOKEN, "RUNNER_TEMP": temporary})
            self.assertFalse((Path(temporary) / "kd-records" / "revocation.json").exists())

    def test_real_gates_use_the_shared_stopping_launcher(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            (worker / "Cargo.lock").write_text(_path_only_lock(4), encoding="ascii")
            source_sha = "a" * 40
            commands = tuple(
                (name, ("/usr/bin/true",)) for name in linux_source_build.GATES
            )
            with patch.object(linux_source_build, "_job_elapsed_seconds", return_value=0.0), patch.object(
                linux_source_build, "_project_gate_directories",
            ) as directories, patch.object(
                linux_source_build, "_gate_commands", return_value=commands,
            ), patch.object(
                linux_source_build, "_runtime_workspace_present", return_value=False,
            ), patch.object(
                linux_source_build.linux_session, "run_host",
                return_value=types.SimpleNamespace(
                    exit_code=0, timed_out=False, stdout=b"", stderr=b"",
                ),
            ) as session:
                self.assertEqual(linux_source_build.run_project_gates({
                    "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                    "CARGO_HOME": str(worker / ".kd-cargo-home"),
                    "RUST_ROOT": "/rust", "NODE_BIN": "/node",
                    "REQUESTED_SOURCE_SHA": source_sha,
                }), 0)
                self.assertEqual(directories.call_count, 15)
                self.assertEqual(session.call_count, 15)
                durations = json.loads((root / "kd-records" / "gate-durations.json").read_text(encoding="ascii"))
                self.assertEqual(durations["schema_version"], 1)
                self.assertEqual(set(durations["durations_ms"]), set(linux_source_build.GATES))
                self.assertTrue(all(type(value) is int and value >= 0 for value in durations["durations_ms"].values()))
                for invocation in session.call_args_list:
                    launch = invocation.args[2]
                    self.assertEqual(launch[:3], ("/usr/bin/python3", "-B", "-c"))
                    self.assertEqual(launch[3], linux_source_build.linux_probes.LAUNCHER_SOURCE)
                    self.assertEqual(launch[4:], ("/usr/bin/true",))
                    gate_env = invocation.args[3]
                    for user_name, global_name, notifier_name in (
                        ("NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG", "NPM_CONFIG_UPDATE_NOTIFIER"),
                        ("npm_config_userconfig", "npm_config_globalconfig", "npm_config_update_notifier"),
                    ):
                        self.assertNotEqual(gate_env[user_name], gate_env[global_name])
                        self.assertEqual(
                            Path(gate_env[user_name]), worker / ".home" / linux_source_build.NPM_USER_CONFIG_NAME,
                        )
                        self.assertEqual(
                            Path(gate_env[global_name]), worker / ".home" / linux_source_build.NPM_GLOBAL_CONFIG_NAME,
                        )
                        self.assertNotIn("/dev/null", (gate_env[user_name], gate_env[global_name]))
                        self.assertEqual(gate_env[notifier_name], "false")
                    self.assertEqual(gate_env["NPM_CONFIG_USERCONFIG"], gate_env["npm_config_userconfig"])
                    self.assertEqual(gate_env["NPM_CONFIG_GLOBALCONFIG"], gate_env["npm_config_globalconfig"])
                    self.assertLessEqual(set(gate_env), linux_source_build.linux_session.PROJECT_ENV_NAMES)

    def test_gate_directories_create_two_distinct_empty_owned_npm_configs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            worker = root / "source"
            worker.mkdir(parents=True)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            with patch.object(linux_source_build, "PROJECT_ROOT", root), patch.object(
                linux_source_build, "_open_project_root", side_effect=lambda: os.open(root, flags)
            ), patch.object(linux_source_build.linux_harness, "CHILD_UID", os.getuid()), patch.object(
                linux_source_build.linux_harness, "CHILD_GID", os.getgid()
            ), patch.object(linux_source_build, "GATE_CONFIG_UID", os.getuid()), patch.object(
                linux_source_build, "GATE_CONFIG_GID", os.getgid()
            ):
                (worker / ".kd-cargo-home").mkdir()
                linux_source_build._project_gate_directories(worker, create=True)
                paths = [worker / ".home" / name for name in (
                    linux_source_build.NPM_USER_CONFIG_NAME, linux_source_build.NPM_GLOBAL_CONFIG_NAME,
                )]
                identities = set()
                for path in paths:
                    details = path.lstat()
                    self.assertTrue(stat.S_ISREG(details.st_mode))
                    self.assertEqual((details.st_size, details.st_nlink, stat.S_IMODE(details.st_mode)), (0, 1, 0o444))
                    self.assertEqual((details.st_uid, details.st_gid), (os.getuid(), os.getgid()))
                    identities.add((details.st_dev, details.st_ino))
                self.assertEqual(len(identities), 2)
                linux_source_build._project_gate_directories(worker)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._project_gate_directories(worker, create=True)
                paths[0].chmod(0o644)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._project_gate_directories(worker)
                paths[0].chmod(0o444)
                paths[1].unlink()
                paths[1].symlink_to(paths[0])
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._project_gate_directories(worker)
                paths[1].unlink()
                os.link(paths[0], paths[1])
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._project_gate_directories(worker)
                paths[1].unlink()
                paths[0].unlink()
                paths[0].write_text("registry=fixture\n", encoding="ascii")
                paths[0].chmod(0o444)
                paths[1].write_text("", encoding="ascii")
                paths[1].chmod(0o444)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._project_gate_directories(worker)

    def test_gate_npm_configs_are_root_owned_and_a_foreign_owner_is_refused(self):
        self.assertEqual((linux_source_build.GATE_CONFIG_UID, linux_source_build.GATE_CONFIG_GID), (0, 0))
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for name in (linux_source_build.NPM_USER_CONFIG_NAME, linux_source_build.NPM_GLOBAL_CONFIG_NAME):
                (home / name).write_text("", encoding="ascii")
                (home / name).chmod(0o444)
            descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(linux_source_build, "GATE_CONFIG_UID", os.getuid()), patch.object(
                    linux_source_build, "GATE_CONFIG_GID", os.getgid()
                ):
                    linux_source_build._gate_npm_config_files(descriptor, False)
                with patch.object(linux_source_build, "GATE_CONFIG_UID", os.getuid() + 1), patch.object(
                    linux_source_build, "GATE_CONFIG_GID", os.getgid()
                ):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._gate_npm_config_files(descriptor, False)
            finally:
                os.close(descriptor)

    def _run_gates_with_second_gate(self, second):
        outputs = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            (worker / "Cargo.lock").write_text(_path_only_lock(4), encoding="ascii")
            commands = tuple((name, ("/usr/bin/true",)) for name in linux_source_build.GATES)
            first = types.SimpleNamespace(exit_code=0, timed_out=False, stdout=b"", stderr=b"")
            calls = []

            def host(*arguments, **keywords):
                calls.append(keywords)
                if len(calls) == 2:
                    if isinstance(second, BaseException):
                        raise second
                    return second
                return first

            with patch.object(linux_source_build, "_job_elapsed_seconds", return_value=0.0), patch.object(linux_source_build, "_project_gate_directories"), patch.object(
                linux_source_build, "_gate_commands", return_value=commands,
            ), patch.object(linux_source_build, "_runtime_workspace_present", return_value=False), patch.object(
                linux_source_build.linux_session, "run_host", side_effect=host,
            ):
                sink = io.StringIO()
                with contextlib.redirect_stdout(sink):
                    code = linux_source_build.run_project_gates({
                        "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                        "CARGO_HOME": str(worker / ".kd-cargo-home"),
                        "RUST_ROOT": "/rust", "NODE_BIN": "/node", "REQUESTED_SOURCE_SHA": "a" * 40,
                    })
                outputs.append((code, sink.getvalue(), calls))
        return outputs[0]

    def test_real_gates_run_with_the_project_limits_and_the_long_timeout(self):
        code, unused_text, calls = self._run_gates_with_second_gate(
            types.SimpleNamespace(exit_code=0, timed_out=False, stdout=b"", stderr=b""))
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 15)
        for keywords in calls:
            self.assertEqual(keywords["limits"], "project")
            self.assertEqual(keywords["timeout"], 1800)
        self.assertEqual(linux_source_build.PROJECT_GATE_TIMEOUT_SECONDS, 1800)

    def test_a_failed_gate_names_itself_and_one_fixed_cause_and_never_leaks_output(self):
        secret = b"kd-secret-" + bytes((47,)) + b"srv" + bytes((47,)) + b"runner-work-exit-code-137"
        for cause, result in (
            ("timeout", types.SimpleNamespace(exit_code=None, timed_out=True, stdout=secret, stderr=secret)),
            ("limit", types.SimpleNamespace(exit_code=-signal.SIGXCPU, timed_out=False, stdout=secret, stderr=secret)),
            ("limit", types.SimpleNamespace(exit_code=-signal.SIGXFSZ, timed_out=False, stdout=secret, stderr=secret)),
            ("limit", types.SimpleNamespace(exit_code=-signal.SIGKILL, timed_out=False, stdout=secret, stderr=secret)),
            ("signal", types.SimpleNamespace(exit_code=-signal.SIGSEGV, timed_out=False, stdout=secret, stderr=secret)),
            ("exit", types.SimpleNamespace(exit_code=101, timed_out=False, stdout=secret, stderr=secret)),
            ("exit", types.SimpleNamespace(exit_code=None, timed_out=False, stdout=secret, stderr=secret)),
            ("launch", OSError(chr(47) + "srv" + chr(47) + "runner secret path 137")),
        ):
            with self.subTest(cause=cause, result=repr(result)):
                code, text, unused_calls = self._run_gates_with_second_gate(result)
                self.assertEqual(code, 1)
                lines = text.splitlines()
                self.assertEqual(
                    lines[-1], "linux-project-gates=refused completed=2 failed=1 gate=clippy cause=" + cause)
                self.assertEqual(text.count("linux-project-gates="), 1)
                self.assertTrue(text.endswith("\n"))
                for forbidden in ("kd-secret", "srv", "137", "101", "secret"):
                    self.assertNotIn(forbidden, text)

    def _run_gates_with_clock(self, advance_after_first, job_elapsed=0.0):
        clock = [0.0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            (worker / "Cargo.lock").write_text(_path_only_lock(4), encoding="ascii")
            commands = tuple((name, ("/usr/bin/true",)) for name in linux_source_build.GATES)
            calls = []

            def host(*arguments, **keywords):
                calls.append(keywords)
                if len(calls) == 1:
                    clock[0] += advance_after_first
                return types.SimpleNamespace(exit_code=0, timed_out=False, stdout=b"", stderr=b"")

            with patch.object(linux_source_build, "_job_elapsed_seconds", return_value=job_elapsed), patch.object(linux_source_build, "_project_gate_directories"), patch.object(
                linux_source_build, "_gate_commands", return_value=commands,
            ), patch.object(linux_source_build, "_runtime_workspace_present", return_value=False), patch.object(
                linux_source_build.linux_session, "run_host", side_effect=host,
            ), patch.object(linux_source_build.time, "monotonic", side_effect=lambda: clock[0]):
                sink = io.StringIO()
                with contextlib.redirect_stdout(sink):
                    code = linux_source_build.run_project_gates({
                        "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                        "CARGO_HOME": str(worker / ".kd-cargo-home"),
                        "RUST_ROOT": "/rust", "NODE_BIN": "/node", "REQUESTED_SOURCE_SHA": "a" * 40,
                    })
                return code, sink.getvalue(), len(calls)

    def test_no_gate_starts_when_less_than_one_gate_timeout_remains_of_the_budget(self):
        budget = linux_source_build.PROJECT_GATE_BUDGET_SECONDS
        timeout = linux_source_build.PROJECT_GATE_TIMEOUT_SECONDS
        self.assertEqual(budget, 330 * 60)
        self.assertLess(budget, 350 * 60)
        code, text, calls = self._run_gates_with_clock(budget - timeout + 1)
        self.assertEqual((code, calls), (1, 1))
        self.assertEqual(
            text.splitlines()[-1], "linux-project-gates=refused completed=1 failed=0 gate=clippy cause=deadline")

    def test_a_gate_still_starts_when_exactly_one_gate_timeout_remains(self):
        budget = linux_source_build.PROJECT_GATE_BUDGET_SECONDS
        timeout = linux_source_build.PROJECT_GATE_TIMEOUT_SECONDS
        code, text, calls = self._run_gates_with_clock(budget - timeout)
        self.assertEqual((code, calls), (0, 15))
        self.assertIn("linux-project-gates=passed", text)

    def _proc_tree(self, root, processes, uptime="5000.25 9000.00"):
        for pid, (name, parent, start_ticks) in processes.items():
            directory = root / str(pid)
            directory.mkdir()
            fields = ["S", str(parent)] + ["0"] * 17 + [str(start_ticks)] + ["0"] * 10
            (directory / "stat").write_text(str(pid) + " (" + name + ") " + " ".join(fields) + "\n", encoding="ascii")
        (root / "uptime").write_text(uptime + "\n", encoding="ascii")

    def test_the_gate_budget_counts_from_the_runner_worker_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._proc_tree(root, {
                40: ("python3", 30, 480000), 30: ("sudo", 20, 470000), 20: ("bash) (x", 10, 460000),
                10: ("Runner.Worker", 1, 440000),
            })
            with patch.object(linux_source_build.os, "getppid", return_value=30), patch.object(
                linux_source_build.os, "sysconf", return_value=100,
            ):
                self.assertAlmostEqual(linux_source_build._job_elapsed_seconds(str(root)), 600.25)
        refusing = (
            {30: ("sudo", 20, 1), 20: ("bash", 1, 1)},
            {30: ("sudo", 20, 1), 20: ("bash", 30, 1)},
            {30: ("Runner.Worker", 1, 600000)},
            {30: ("Runner.Worker", 1, "x")},
            {30: ("Runner.Workers", 1, 1)},
            {},
        )
        for processes in refusing:
            with self.subTest(processes=processes):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self._proc_tree(root, processes)
                    with patch.object(linux_source_build.os, "getppid", return_value=30), patch.object(
                        linux_source_build.os, "sysconf", return_value=100,
                    ):
                        with self.assertRaises(linux_source_build.SourceBuildRefusal):
                            linux_source_build._job_elapsed_seconds(str(root))
        source = Path(linux_source_build.__file__).read_text(encoding="ascii")
        body = source[source.index("def run_project_gates("):source.index("for index, (name, argv) in enumerate(commands):")]
        self.assertIn("    job_elapsed = _job_elapsed_seconds()\n    budget_started = time.monotonic()\n", body)
        self.assertIn(
            "if PROJECT_GATE_BUDGET_SECONDS - job_elapsed - (time.monotonic() - budget_started) < PROJECT_GATE_TIMEOUT_SECONDS:",
            source)
        self.assertNotIn("run_rust_license_gate", source)


    @staticmethod
    def _write_runtime_gate_fixture_file(root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="ascii")

    @staticmethod
    def _runtime_fixture_lock(dependencies):
        text = "version = 4\n"
        for name in sorted(dependencies):
            text += '\n[[package]]\nname = "' + name + '"\nversion = "0.1.0"\n'
            if dependencies[name]:
                text += "dependencies = [\n" + "".join(
                    ' "' + dependency + ' 0.1.0",\n'
                    for dependency in dependencies[name]
                ) + "]\n"
        return text

    def _write_runtime_gate_fixture(self, root):
        bootstrap = linux_source_build.cargo_lock_bootstrap
        contract_members = sorted(bootstrap.CONTRACT_MEMBERS)
        contract_listing = "".join('    "' + member + '",\n' for member in contract_members)
        host_mock_package = "keeldock" + "-host-mock"
        contract_root = (
            "[workspace]\nmembers = [\n" + contract_listing + "]\n\n"
            '[workspace.package]\nversion = "0.1.0"\nedition = "2024"\n\n'
            "[workspace.dependencies]\n"
            + bootstrap.HOST_API_POLICY_API_PACKAGE + ' = { path = "crates/host/api" }\n'
            + host_mock_package + ' = { path = "crates/host/mock" }\n'
        )
        self._write_runtime_gate_fixture_file(root, "Cargo.toml", contract_root)
        host_api_package = bootstrap.HOST_API_POLICY_API_PACKAGE
        host_conformance_package = "keeldock" + "-host-conformance"
        kernel_i18n_package = "keeldock" + "-kernel-i18n"
        contract_dependencies = {
            host_api_package: (),
            host_mock_package: (host_api_package,),
            host_conformance_package: (host_api_package, host_mock_package),
            kernel_i18n_package: (),
        }
        for member in contract_members:
            name = bootstrap.CONTRACT_PACKAGE_NAMES[member]
            text = (
                "[package]\nname = \"" + name + "\"\n"
                "version.workspace = true\nedition.workspace = true\n"
            )
            dependencies = bootstrap.CONTRACT_MEMBER_DEPENDENCIES[member]
            ordinary = (
                {} if member == "crates/host/api"
                else dependencies.get("dependencies", {})
            )
            development = dependencies.get("dev-dependencies", {})
            if ordinary:
                text += "\n[dependencies]\n" + "".join(
                    dependency + " = { workspace = true }\n" for dependency in ordinary
                )
            if development:
                text += "\n[dev-dependencies]\n" + "".join(
                    dependency + " = { workspace = true }\n" for dependency in development
                )
            self._write_runtime_gate_fixture_file(root, member + "/Cargo.toml", text)
        self._write_runtime_gate_fixture_file(
            root, "Cargo.lock", self._runtime_fixture_lock(contract_dependencies),
        )

        runtime_members = bootstrap.HOST_API_POLICY_RUNTIME_REQUIRED_MEMBER_ROOTS
        runtime_listing = "".join(
            '    "' + member.removeprefix("runtime/") + '",\n'
            for member in runtime_members
        )
        runtime_root = (
            "[workspace]\nresolver = \"3\"\nmembers = [\n" + runtime_listing + "]\n\n"
            '[workspace.package]\nversion = "0.1.0"\nedition = "2024"\n'
            'rust-version = "1.99.1"\npublish = false\n\n'
            "[workspace.dependencies]\n"
            + bootstrap.HOST_API_POLICY_API_PACKAGE + ' = { path = "'
            + bootstrap.HOST_API_POLICY_API_PATH + '" }\n'
        )
        self._write_runtime_gate_fixture_file(root, "runtime/Cargo.toml", runtime_root)
        runtime_dependencies = {bootstrap.HOST_API_POLICY_API_PACKAGE: ()}
        for member in runtime_members:
            name = member.rsplit("/", 1)[-1]
            text = (
                "[package]\nname = \"" + name + "\"\n"
                "version.workspace = true\nedition.workspace = true\n"
                "rust-version.workspace = true\npublish.workspace = true\n"
            )
            if member in bootstrap.HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS:
                text += "\n[dependencies]\n" + bootstrap.HOST_API_POLICY_API_PACKAGE + " = { workspace = true }\n"
                runtime_dependencies[name] = (bootstrap.HOST_API_POLICY_API_PACKAGE,)
            else:
                runtime_dependencies[name] = ()
            self._write_runtime_gate_fixture_file(root, member + "/Cargo.toml", text)
        for member in bootstrap.RUNTIME_BATCH_SEVEN_CRATE_ROOTS:
            crate_name = member.rsplit("/", 1)[-1]
            self._write_runtime_gate_fixture_file(root, member + "/README.md", crate_name + " crate overview.\n")
            self._write_runtime_gate_fixture_file(root, member + "/CONTRACT.md", "Contract for " + crate_name + ".\n")
            self._write_runtime_gate_fixture_file(root, member + "/CHANGELOG.md", "Initial crate release.\n")
            self._write_runtime_gate_fixture_file(root, member + "/src/lib.rs", "pub fn " + crate_name.replace("-", "_") + "() {}\n")
            self._write_runtime_gate_fixture_file(root, member + "/src/modules/mod.rs", "pub fn module() {}\n")
            self._write_runtime_gate_fixture_file(root, member + "/tests/runtime.rs", "fn works() {}\n")
        self._write_runtime_gate_fixture_file(
            root, "runtime/Cargo.lock", self._runtime_fixture_lock(runtime_dependencies),
        )
        self._write_runtime_gate_fixture_file(root, "crates/host/api/src/lib.rs", "pub fn api() {}\n")



    def test_time_already_spent_by_the_job_before_the_gates_shortens_the_budget(self):
        budget = linux_source_build.PROJECT_GATE_BUDGET_SECONDS
        timeout = linux_source_build.PROJECT_GATE_TIMEOUT_SECONDS
        code, text, calls = self._run_gates_with_clock(0, float(budget - timeout + 1))
        self.assertEqual((code, calls), (1, 0))
        self.assertEqual(text.splitlines()[-1], "linux-project-gates=refused completed=0 failed=0 gate=format cause=deadline")

    def test_the_refusal_line_adds_only_public_gate_names_and_closed_causes(self):
        line = linux_source_build._gate_refusal_line
        self.assertEqual(line(3, 1, "format", "exit"), "linux-project-gates=refused completed=3 failed=1 gate=format cause=exit\n")
        self.assertEqual(line(3, 1, "runtime_tests", "limit"), "linux-project-gates=refused completed=3 failed=1 gate=runtime_tests cause=limit\n")
        for gate, cause in (("evil gate", "exit"), ("format", "137"), (None, None), ("format", None)):
            self.assertEqual(line(2, 1, gate, cause), "linux-project-gates=refused completed=2 failed=1\n")
        self.assertEqual(linux_source_build.GATE_CAUSES, ("timeout", "limit", "signal", "exit", "launch", "deadline"))








    def _gate_over_tree(self, files, links=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="ascii")
            for name, target in (links or {}).items():
                (root / name).symlink_to(target, target_is_directory=True)
            descriptor = linux_source_build._open_source_root(root)
            try:
                linux_source_build._require_confined_manifests(descriptor)
            finally:
                os.close(descriptor)
            return 0, ""

    def _assert_tree_refused(self, files, links=None):
        with self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
            self._gate_over_tree(files, links)
        self.assertEqual(refused.exception.reason, "lock")

    def test_manifests_that_reach_outside_the_root_or_patch_are_refused(self):
        member = '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2024"\n\n'
        cases = {
            "absolute_path": member + '[dependencies]\nfoo = { path = "/opt/outside/foo" }\n',
            "parent_path": member + '[dependencies]\nfoo = { path = "../../../outside" }\n',
            "dev_table": member + '[dev-dependencies.foo]\npath = "../../../outside"\n',
            "build_table": member + '[build-dependencies]\nfoo = { path = "../../../outside" }\n',
            "target_table": member + '[target.x86_64-unknown-linux-gnu.dependencies]\nfoo = { path = "../../../outside" }\n',
            "patch": member + '[patch.crates-io]\nfoo = { path = "vendor/foo" }\n',
            "replace": member + '[replace]\n',
            "unknown_shape": member + '[dependencies]\nfoo = 3\n',
        }
        for label, manifest in cases.items():
            with self.subTest(case=label):
                self._assert_tree_refused({
                    "Cargo.lock": _path_only_lock(1),
                    "crates/inner/Cargo.toml": manifest,
                })
        with self.subTest(case="workspace_member_outside"):
            self._assert_tree_refused({
                "Cargo.lock": _path_only_lock(1),
                "Cargo.toml": '[workspace]\nmembers = ["../outside"]\n',
            })

    def test_one_level_up_from_a_nested_manifest_stays_inside_and_passes(self):
        manifest = (
            '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[dependencies]\nfoo = { path = "../../outside" }\n'
        )
        self.assertEqual(
            self._gate_over_tree({
                "Cargo.lock": _path_only_lock(1), "crates/inner/Cargo.toml": manifest,
            }),
            (0, ""),
        )

    def test_paths_into_directories_the_walk_skips_are_refused(self):
        head = '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2024"\n\n'
        for name in ("node_modules", "target", ".git", ".kd-cargo-home", ".npm-cache",
                     ".kd-npm-tarballs", ".kd-other", ".cargo"):
            with self.subTest(directory=name):
                self._assert_tree_refused({
                    "Cargo.lock": _path_only_lock(1),
                    "Cargo.toml": head + '[dependencies]\nfoo = { path = "' + name + '/x" }\n',
                })
        with self.subTest(directory="nested"):
            self._assert_tree_refused({
                "Cargo.lock": _path_only_lock(1),
                "crates/inner/Cargo.toml": head
                + '[dependencies]\nfoo = { path = "../../node_modules/x" }\n',
            })

    def test_directory_symlinks_in_the_tree_are_refused(self):
        self._assert_tree_refused(
            {"Cargo.lock": _path_only_lock(1), "Cargo.toml": '[workspace]\nmembers = []\n'},
            links={"loop": "."},
        )

    def test_manifest_path_resolution_refuses_a_symlink_component(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "real").mkdir()
            (root / "real" / "lib.rs").write_text("", encoding="ascii")
            (root / "hop").symlink_to(".", target_is_directory=True)
            descriptor = self._root_descriptor(root)
            check = linux_source_build._require_physical_manifest_path
            check(descriptor, (), "real/lib.rs")
            check(descriptor, (), "real/missing/lib.rs")
            check(descriptor, ("real",), "../real/lib.rs")
            for value in ("hop/real/lib.rs", "hop/../x", "real/../hop/real", "../x"):
                with self.subTest(value=value):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
                        check(descriptor, (), value)
                    self.assertEqual(refused.exception.reason, "lock")

    def test_manifest_parser_behaviour_the_confinement_check_relies_on(self):
        parse = linux_source_build.cargo_lock_bootstrap._parse_manifest
        document = parse(
            b'[package]\nname = "a"\nbuild = false\n\n'
            b'[workspace]\nmembers = ["crates/*"]\n\n'
            b'[dependencies]\nfoo = { path = "../foo" }\n\n'
            b'[dev-dependencies.bar]\npath = "../bar"\n\n'
            b'[target.x86_64-unknown-linux-gnu.dependencies]\nbaz = { path = "../baz" }\n\n'
            b'[patch.crates-io]\nfoo = { path = "vendor/foo" }\n\n'
            b'[[bin]]\nname = "a"\npath = "src/main.rs"\n'
        )
        self.assertIs(document["package"]["build"], False)
        self.assertEqual(document["workspace"]["members"], ["crates/*"])
        self.assertEqual(document["dependencies"]["foo"], {"path": "../foo"})
        self.assertEqual(document["dev-dependencies"]["bar"], {"path": "../bar"})
        target = document["target"]["x86_64-unknown-linux-gnu"]
        self.assertEqual(target["dependencies"]["baz"], {"path": "../baz"})
        self.assertEqual(document["patch"]["crates-io"]["foo"], {"path": "vendor/foo"})
        self.assertEqual(document["bin"], [{"name": "a", "path": "src/main.rs"}])
        self.assertIn("replace", parse(b"[replace]\n"))
        refused = (
            b'a = "x\\y"\n', b'a = """x"""\n', b"[a]\n[a]\n", b"[[patch.unused]]\n",
            b"", b"a = \x00\n",
        )
        for data in refused:
            with self.subTest(data=data):
                with self.assertRaises(Exception):
                    parse(data)

    def test_in_root_path_dependencies_and_workspace_members_pass(self):
        files = {
            "Cargo.lock": _path_only_lock(2),
            "Cargo.toml": '[workspace]\nmembers = ["crates/inner", "crates/sibling"]\n',
            "crates/inner/Cargo.toml": (
                '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2024"\n\n'
                '[dependencies]\nsibling = { path = "../sibling" }\n'
            ),
            "crates/sibling/Cargo.toml": (
                '[package]\nname = "sibling"\nversion = "0.1.0"\nedition = "2024"\n'
            ),
        }
        self.assertEqual(
            self._gate_over_tree(files),
            (0, ""),
        )

    def test_tree_without_any_lock_refuses_with_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="ascii")
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._validate_cargo_lock_sources(root)


    def test_runtime_gate_receipt_records_every_selected_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            self._write_runtime_gate_fixture(worker)
            source_sha = "a" * 40
            commands = tuple(
                (name, ("/usr/bin/true",))
                for name in linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES
            )
            with patch.object(linux_source_build, "_job_elapsed_seconds", return_value=0.0), patch.object(
                linux_source_build, "_project_gate_directories"
            ), patch.object(
                linux_source_build, "_gate_commands", return_value=commands
            ), patch.object(linux_source_build.linux_session, "run_host", return_value=types.SimpleNamespace(
                exit_code=0, timed_out=False, stdout=b"", stderr=b""
            )):
                result = linux_source_build.run_project_gates({
                    "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                    "CARGO_HOME": str(worker / ".kd-cargo-home"), "RUST_ROOT": "/rust", "NODE_BIN": "/node",
                    "REQUESTED_SOURCE_SHA": source_sha,
                })
            self.assertEqual(result, 0)
            receipt = json.loads((Path(temporary) / "kd-records" / "gates.json").read_text(encoding="ascii"))
            self.assertEqual(receipt["selected_gates"], list(linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES))
            self.assertEqual(receipt["completed_gates"], receipt["selected_gates"])
            self.assertEqual(receipt["gate_count"], 18)

    @unittest.skipUnless(sys.platform.startswith("linux") and platform.system() == "Linux", "the shared launcher stop uses Linux process facilities")
    def test_shared_launcher_stops_before_the_command_and_gives_it_eof_stdin(self):
        stdout_reader, stdout_writer = os.pipe()
        stderr_reader, stderr_writer = os.pipe()
        launch = (
            "/usr/bin/python3", "-B", "-c", linux_source_build.linux_probes.LAUNCHER_SOURCE,
            "/usr/bin/python3", "-c", "import os; raise SystemExit(0 if os.read(0, 1) == b'' else 23)",
        )
        spec = {"mode": "open", "keep_root": True, "limits": "probe", "env": {"PATH": "/usr/bin"}, "timeout": 5}
        try:
            code, timed_out = linux_source_build.linux_session.launch_and_collect(
                spec, launch, "/", (None, stdout_writer), (None, stderr_writer), False,
            )
            self.assertEqual(code, 0)
            self.assertFalse(timed_out)
        finally:
            for descriptor in (stdout_reader, stdout_writer, stderr_reader, stderr_writer):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_audit_command_passes_empty_arguments_to_the_shared_cli(self):
        audit = types.SimpleNamespace(main=Mock(return_value=0))
        canary = types.SimpleNamespace(compute_config=Mock(return_value="config"), PINNED_CONFIG=None)
        with patch.object(linux_source_build, "_audit_modules", return_value=(audit, None, canary)):
            self.assertEqual(linux_source_build.main(["audit"]), 0)
        self.assertEqual(audit.main.call_args.kwargs["arguments"], [])
        self.assertIs(audit.main.call_args.kwargs["environ"], os.environ)

    def test_synthetic_entry_points_use_only_independent_proof_and_job_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in linux_source_build.linux_channels.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            (records / "merged.json").chmod(0o600)
            sha = "a" * 40
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": sha,
                "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "synthetic",
                "PRODUCER_RESULT": "success", "VERDICT_RECORD": "forged producer value",
                "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
                "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
                "GITHUB_SHA": sha, "CI_REF": "refs/heads/main", "GITHUB_TOKEN": "read-token",
            }
            with patch.dict(os.environ, env, clear=True), patch.object(
                linux_source_build, "_reference_sha", side_effect=[sha, "b" * 40]
            ) as references, patch.object(linux_source_build, "_comparison", return_value="ahead") as comparison, patch.object(
                linux_source_build, "_verify_environment"
            ) as environment:
                self.assertEqual(linux_source_build.main(["preflight"]), 0)
                self.assertEqual(references.call_count, 2)
                comparison.assert_called_once()
                environment.assert_called_once_with("read-token")
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(linux_source_build.main(["verdict"]), 0)
                record = confinement_verdict.decode_line(output.getvalue().strip())
                self.assertTrue(confinement_verdict.confinement_accepted(record))
                self.assertEqual(record["project_execution"], "not_started")
                self.assertEqual(record["token_revocation"], "not-applicable")

    def test_forged_producer_record_cannot_turn_a_failed_source_job_into_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in confinement_verdict.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            (records / "merged.json").chmod(0o600)
            forged = {
                "os": "linux", "boundary": "linux-ns-seccomp-uid", "control_sha": "a" * 40,
                "run_id": 7, "run_attempt": 1, "channels": merged["channels"],
                "memory_canary": "absent", "readable_file_canary": "absent",
                "handoff": "not-applicable", "project_execution": "completed",
                "gates": 15, "failed": 0, "token_revocation": "confirmed",
            }
            self.assertTrue(confinement_verdict.run_accepted(forged))
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "source", "PRODUCER_RESULT": "failure",
                "VERDICT_RECORD": json.dumps(forged),
            }
            output = io.StringIO()
            with patch.object(linux_source_build.sys, "stdout", output):
                self.assertEqual(linux_source_build.emit_verdict(env), 1)
            record = confinement_verdict.decode_line(output.getvalue().strip())
            self.assertEqual(record["project_execution"], "not_started")
            self.assertEqual(record["gates"], 0)
            self.assertEqual(record["token_revocation"], "unconfirmed")
            env["PRODUCER_RESULT"] = "success"
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")
            with patch.object(linux_source_build.sys, "stdout", io.StringIO()):
                self.assertEqual(linux_source_build.emit_verdict(env), 1)
            env["PRODUCER_RESULT"] = "forged"
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")

    def test_verifier_receipts_alone_establish_source_claims_and_producer_only_vetoes(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in confinement_verdict.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            (records / "merged.json").chmod(0o600)
            gates = {
                "schema_version": 1,
                "selected_gates": list(linux_source_build.GATES + linux_source_build.BROWSER_GATE_NAMES),
                "completed_gates": list(linux_source_build.GATES + linux_source_build.BROWSER_GATE_NAMES),
                "gates": {name: "passed" for name in linux_source_build.GATES + linux_source_build.BROWSER_GATE_NAMES},
                "gate_count": 16,
                "failed": 0,
            }
            receipt = {
                "schema_version": 1, "status": "confirmed", "control_sha": "a" * 40,
                "run_id": "7", "run_attempt": "1", "installation_id": "19",
                "rejected_after_revoke": True,
            }
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            (records / "revocation.json").write_text(json.dumps(receipt), encoding="ascii")
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "SOURCE_READER_INSTALLATION_ID": "19",
                "CI_MODE": "source", "PRODUCER_RESULT": "success",
                "LINUX_API_FEATURE_GATE_NAMES": ",".join(linux_source_build.API_FEATURE_GATE_NAMES),
            }
            trusted = linux_source_build._verdict_record(env)
            self.assertEqual(trusted["gates"], 15)
            self.assertTrue(confinement_verdict.run_accepted(trusted))
            featureless = tuple(
                name for name in linux_source_build.GATES
                if name not in linux_source_build.API_FEATURE_GATE_NAMES
            )
            selected_without_features = featureless + linux_source_build.BROWSER_GATE_NAMES
            (records / "gates.json").write_text(json.dumps({
                "schema_version": 1,
                "selected_gates": list(selected_without_features),
                "completed_gates": list(selected_without_features),
                "gates": {name: "passed" for name in selected_without_features},
                "gate_count": len(selected_without_features),
                "failed": 0,
            }), encoding="ascii")
            with patch.object(linux_source_build, "GATES", featureless):
                self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            missing_feature_readback = dict(env)
            del missing_feature_readback["LINUX_API_FEATURE_GATE_NAMES"]
            self.assertEqual(
                linux_source_build._verdict_record(missing_feature_readback)["project_execution"],
                "not_started",
            )
            with patch.object(linux_source_build.sys, "stdout", io.StringIO()):
                self.assertEqual(linux_source_build.emit_verdict(env), 0)
            env["PRODUCER_RESULT"] = "failure"
            self.assertEqual(linux_source_build._verdict_record(env), trusted)
            with patch.object(linux_source_build.sys, "stdout", io.StringIO()):
                self.assertEqual(linux_source_build.emit_verdict(env), 1)
            env["PRODUCER_RESULT"] = "success"
            gates["gates"]["format"] = "not-run"
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")
            gates["gates"]["format"] = "passed"
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            receipt["rejected_after_revoke"] = False
            (records / "revocation.json").write_text(json.dumps(receipt), encoding="ascii")
            self.assertEqual(linux_source_build._verdict_record(env)["token_revocation"], "unconfirmed")

    def test_runtime_receipt_records_all_three_stages_and_the_public_verdict_reports_sixteen_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in confinement_verdict.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            (records / "merged.json").chmod(0o600)
            selected = linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES + linux_source_build.BROWSER_GATE_NAMES
            gates = {
                "schema_version": 1,
                "selected_gates": list(selected),
                "completed_gates": list(selected),
                "gates": {name: "passed" for name in selected},
                "gate_count": len(selected),
                "failed": 0,
            }
            receipt = {
                "schema_version": 1, "status": "confirmed", "control_sha": "a" * 40,
                "run_id": "7", "run_attempt": "1", "installation_id": "19",
                "rejected_after_revoke": True,
            }
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            (records / "revocation.json").write_text(json.dumps(receipt), encoding="ascii")
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "SOURCE_READER_INSTALLATION_ID": "19",
                "CI_MODE": "source", "PRODUCER_RESULT": "success",
                "LINUX_API_FEATURE_GATE_NAMES": ",".join(linux_source_build.API_FEATURE_GATE_NAMES),
            }
            public_record = linux_source_build._verdict_record(env)
            self.assertEqual(public_record["gates"], 18)
            self.assertEqual(len(selected), 19)
            self.assertIn(" gates=18 failed=0 ", confinement_verdict.encode_line(public_record))
            self.assertTrue(confinement_verdict.run_accepted(public_record))
            gates["completed_gates"] = list(selected[:-1])
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")

    def test_unprivileged_handoff_refuses_wrong_owner_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            path = records / "merged.json"
            path.write_text('{"channels":{}}', encoding="ascii")
            path.chmod(0o600)
            reader = os.getuid()
            with patch.object(linux_source_build.os, "getuid", return_value=reader + 1):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build.verify_proof_handoff({"RUNNER_TEMP": temporary})
            self.assertEqual(linux_source_build.verify_proof_handoff({"RUNNER_TEMP": temporary}), 0)
            path.chmod(0o644)
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build.verify_proof_handoff({"RUNNER_TEMP": temporary})
            path.unlink()
            path.symlink_to(records / "missing.json")
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build.verify_proof_handoff({"RUNNER_TEMP": temporary})

    @unittest.skipUnless(hasattr(os, "memfd_create"), "the verifier key descriptor uses memfd_create, which only Linux provides")
    def test_verifier_mints_only_for_the_bound_installation_and_repository(self):
        token = "g" * 40
        identity = {"owner": "KeelDock", "name": "private-source", "repository_id": "41"}
        env = {
            "SOURCE_READER_CLIENT_ID": "Iv1.abc123", "SOURCE_READER_INSTALLATION_ID": "19",
            "SOURCE_READER_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\n" + _FIXTURE_BODY + "\n-----END PRIVATE KEY-----\n",
        }
        installation = {"id": 19, "account": {"login": "keeldock"}}
        issued = {"token": token, "permissions": {"contents": "read", "metadata": "read"}}
        repositories = {"total_count": 1, "repositories": [{"id": 41, "name": "private-source"}]}
        with patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=b"s" * 256)
        ), patch.object(linux_source_build, "_api_request", side_effect=[
            (200, installation), (201, issued), (200, repositories),
        ]) as api, patch.object(linux_source_build, "_write_output") as output:
            transcript = io.StringIO()
            with patch.object(linux_source_build.sys, "stdout", transcript):
                self.assertEqual(linux_source_build.mint_verifier_token(env), 0)
            self.assertIn("::add-mask::" + token, transcript.getvalue())
            self.assertNotIn(_FIXTURE_BODY, transcript.getvalue())
            output.assert_called_once_with(env, {"token": token, "installation_id": "19"})
            self.assertEqual(api.call_args_list[1].args[0], "/app/installations/19/access_tokens")
            self.assertEqual(api.call_args_list[1].kwargs["payload"], {
                "repositories": ["private-source"], "permissions": {"contents": "read"},
            })
        with patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=b"s" * 256)
        ), patch.object(linux_source_build, "_api_request", side_effect=[
            (200, installation), (201, issued), (200, {"total_count": 2, "repositories": repositories["repositories"]}),
        ]):
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build.mint_verifier_token(env)

    def test_source_token_shape_accepts_long_printable_tokens_and_refuses_unsafe_ones(self):
        for accepted in (
            "ghs_" + "T" * 36,
            "v1.abc-def_ghi" * 3,
            "a" * 20,
            "a" * 4096,
            "ghs_" + "ab-cd.ef" * 40,
            "x" * 19 + "~",
            "!" + "y" * 19,
            "p%0Aq" + "z" * 20,
        ):
            with self.subTest(accepted=accepted[:24], length=len(accepted)):
                self.assertTrue(linux_source_build._valid_source_token(accepted))
        for refused in (
            "", "a" * 19, "a" * 4097, "a" * 20 + " ", " " + "a" * 20, "a" * 10 + " " + "a" * 10,
            "a" * 10 + "\t" + "a" * 10, "a" * 20 + "\n", "a" * 10 + "\r" + "a" * 10,
            "a" * 10 + chr(0) + "a" * 10, "a" * 10 + chr(1) + "a" * 10, "a" * 10 + chr(127) + "a" * 10,
            "a" * 10 + ":" + "a" * 10, "a" * 10 + "," + "a" * 10, "a" * 10 + '"' + "a" * 10,
            "a" * 10 + chr(233) + "a" * 10, "a" * 10 + chr(8364) + "a" * 10,
            None, 7, b"a" * 20,
        ):
            with self.subTest(refused=repr(refused)[:24]):
                self.assertFalse(linux_source_build._valid_source_token(refused))

    def test_mask_line_is_one_line_and_escapes_the_runner_percent_encoding(self):
        plain = "ghs_" + "ab-cd.ef" * 10
        self.assertEqual(linux_source_build._mask_line(plain), "::add-mask::" + plain + "\n")
        encoded = "ab%0Acd%0Dxy%25z" + "q" * 20
        line = linux_source_build._mask_line(encoded)
        self.assertEqual(line, "::add-mask::ab%250Acd%250Dxy%2525z" + "q" * 20 + "\n")
        self.assertEqual(line.count("\n"), 1)
        self.assertNotIn("\r", line)
        for character in "!$&'()*+-./;<=>?@[\\]^_`{|}~" + "\x23" + "0123456789" + "AZaz":
            with self.subTest(character=character):
                value = "a" * 10 + character + "a" * 10
                self.assertTrue(linux_source_build._valid_source_token(value))
                self.assertEqual(linux_source_build._mask_line(value).count("\n"), 1)
                self.assertTrue(linux_source_build._mask_line(value).startswith("::add-mask::a"))

    @unittest.skipUnless(hasattr(os, "memfd_create"), "the verifier key descriptor uses memfd_create, which only Linux provides")
    def test_verifier_masks_a_long_token_with_dashes_and_dots_before_its_first_use(self):
        token = "v2.ab-cd." + "ef-gh.ij" * 30 + "%0A"
        identity = {"owner": "KeelDock", "name": "private-source", "repository_id": "41"}
        env = {
            "SOURCE_READER_CLIENT_ID": "Iv1.abc123", "SOURCE_READER_INSTALLATION_ID": "19",
            "SOURCE_READER_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\n" + _FIXTURE_BODY + "\n-----END PRIVATE KEY-----\n",
        }
        responses = [
            (200, {"id": 19, "account": {"login": "keeldock"}}),
            (201, {"token": token, "permissions": {"contents": "read", "metadata": "read"}}),
            (200, {"total_count": 1, "repositories": [{"id": 41, "name": "private-source"}]}),
        ]
        transcript = io.StringIO()
        seen = []

        def api(path, bearer, **unused_keywords):
            seen.append((path, bearer, transcript.getvalue()))
            return responses.pop(0)

        mask = "::add-mask::" + token.replace("%", "%25") + "\n"
        with patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=b"s" * 256)
        ), patch.object(linux_source_build, "_api_request", side_effect=api), patch.object(
            linux_source_build, "_write_output"
        ) as output, patch.object(linux_source_build.sys, "stdout", transcript):
            self.assertEqual(linux_source_build.mint_verifier_token(env), 0)
        self.assertEqual(len(seen), 3)
        self.assertEqual(seen[1][2], "")
        self.assertEqual(seen[2][0], "/installation/repositories?per_page=100")
        self.assertEqual(seen[2][1], token)
        self.assertEqual(seen[2][2], mask)
        self.assertEqual(
            transcript.getvalue(), mask + "linux-verifier-token=issued installation=verified scope=one-repository\n",
        )
        output.assert_called_once_with(env, {"token": token, "installation_id": "19"})

    def run_refused_mint(self, replies, expected=linux_source_build.SourceBuildRefusal):
        identity = {"owner": "KeelDock", "name": "private-source", "repository_id": "41"}
        env = {
            "SOURCE_READER_CLIENT_ID": "Iv1.abc123", "SOURCE_READER_INSTALLATION_ID": "19",
            "SOURCE_READER_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\n" + _FIXTURE_BODY + "\n-----END PRIVATE KEY-----\n",
        }
        transcript = io.StringIO()
        calls = []
        queue = list(replies)

        def api(path, bearer, **keywords):
            calls.append((path, bearer, keywords.get("method"), transcript.getvalue()))
            reply = queue.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply

        with patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=b"s" * 256)
        ), patch.object(linux_source_build, "_api_request", side_effect=api), patch.object(
            linux_source_build, "_write_output"
        ) as output, patch.object(linux_source_build.sys, "stdout", transcript):
            with self.assertRaises(expected) as raised:
                linux_source_build.mint_verifier_token(env)
        output.assert_not_called()
        return transcript.getvalue(), calls, raised.exception

    @unittest.skipUnless(hasattr(os, "memfd_create"), "the verifier key descriptor uses memfd_create, which only Linux provides")
    def test_an_unsafe_issued_token_is_refused_with_a_token_free_shape_line_and_revoked_when_header_safe(self):
        installation = (200, {"id": 19, "account": {"login": "keeldock"}})
        permissions = {"contents": "read", "metadata": "read"}
        stage = "linux-verifier-token-diag stage=issue"
        cases = (
            ("a" * 19, " present=yes type=str length=1-19 classes=letters", True),
            ("ab:cd" + "e" * 20, " present=yes type=str length=20-255 classes=letters,other", True),
            ("A9_-." + "," * 20, " present=yes type=str length=20-255 classes=letters,digits,underscore,dash,dot,other", True),
            ("a" * 300 + ":", " present=yes type=str length=256-1024 classes=letters,other", True),
            ("a" * 2000 + ":", " present=yes type=str length=1025-4096 classes=letters,other", True),
            ("a" * 4097, " present=yes type=str length=4097+ classes=letters", False),
            ("a" * 10 + " " + "a" * 10, " present=yes type=str length=20-255 classes=letters,other", False),
            ("a" * 10 + chr(233) + "a" * 10, " present=yes type=str length=20-255 classes=letters,other", False),
            ("", " present=yes type=str length=0 classes=none", False),
            (None, " present=yes type=other length=0 classes=none", False),
            (7, " present=yes type=other length=0 classes=none", False),
        )
        for bad, shape, header_safe in cases:
            with self.subTest(shape=shape):
                for delete_reply in ((204, None), linux_source_build.SourceBuildRefusal("network"), RuntimeError("boom")):
                    replies = [installation, (201, {"token": bad, "permissions": permissions})]
                    if header_safe:
                        replies.append(delete_reply)
                    text, calls, refusal = self.run_refused_mint(replies)
                    self.assertEqual(refusal.reason, "token")
                    diag = stage + shape + "\n"
                    if header_safe:
                        mask = linux_source_build._mask_line(bad)
                        discard = "linux-verifier-token-discard=" + ("deleted" if delete_reply == (204, None) else "failed") + "\n"
                        self.assertEqual(text, mask + discard + diag)
                        self.assertEqual(len(calls), 3)
                        self.assertEqual(calls[2][:3], ("/installation/token", bad, "DELETE"))
                        self.assertEqual(calls[2][3], mask)
                        self.assertNotIn(bad, diag)
                    else:
                        self.assertEqual(text, "linux-verifier-token-discard=skipped\n" + diag)
                        self.assertEqual(len(calls), 2)
        for issued, shape in (
            ({"permissions": permissions}, " present=no type=other length=0 classes=none"),
            ([], " present=no type=other length=0 classes=none"),
            (None, " present=no type=other length=0 classes=none"),
            ({"token": None}, " present=yes type=other length=0 classes=none"),
        ):
            with self.subTest(issued=repr(issued)[:20]):
                text, calls, refusal = self.run_refused_mint([installation, (201, issued)])
                self.assertEqual(text, "linux-verifier-token-discard=skipped\n" + stage + shape + "\n")
                self.assertEqual(len(calls), 2)

    def test_the_discard_reports_one_fixed_token_free_result_line(self):
        self.assertEqual(linux_source_build.TOKEN_DISCARD_RESULTS, ("deleted", "failed", "skipped"))
        token = "ghs_" + "ab-cd.ef" * 5
        for reply, masked, expected in (
            ((204, None), True, "deleted"), (RuntimeError("boom"), True, "failed"),
            (linux_source_build.SourceBuildRefusal("network"), True, "failed"), ((204, None), False, "deleted"),
        ):
            with self.subTest(expected=expected, masked=masked):
                transcript = io.StringIO()
                with patch.object(linux_source_build, "_api_request", side_effect=[reply] if isinstance(reply, BaseException) else None,
                                  return_value=reply) as api, patch.object(linux_source_build.sys, "stdout", transcript):
                    self.assertIsNone(linux_source_build._discard_issued_token(token, masked))
                prefix = "" if masked else linux_source_build._mask_line(token)
                self.assertEqual(transcript.getvalue(), prefix + "linux-verifier-token-discard=" + expected + "\n")
                self.assertEqual(api.call_args[0][:2], ("/installation/token", token))
        for bad in (None, 7, "", "a b", "x" * 4097):
            with self.subTest(bad=repr(bad)[:12]):
                transcript = io.StringIO()
                with patch.object(linux_source_build, "_api_request") as api, patch.object(linux_source_build.sys, "stdout", transcript):
                    linux_source_build._discard_issued_token(bad)
                self.assertEqual(transcript.getvalue(), "linux-verifier-token-discard=skipped\n")
                api.assert_not_called()
        transcript = io.StringIO()
        with patch.object(linux_source_build.sys, "stdout", transcript):
            linux_source_build._discard_result_line("revoked " + token)
        self.assertEqual(transcript.getvalue(), "linux-verifier-token-discard=failed\n")

    def test_length_buckets_are_a_closed_vocabulary(self):
        for length, bucket in (
            (0, "0"), (1, "1-19"), (19, "1-19"), (20, "20-255"), (255, "20-255"), (256, "256-1024"),
            (1024, "256-1024"), (1025, "1025-4096"), (4096, "1025-4096"), (4097, "4097+"), (100000, "4097+"),
        ):
            with self.subTest(length=length):
                self.assertEqual(linux_source_build._length_bucket(length), bucket)
        self.assertEqual(linux_source_build._token_classes("aZ09_-.~"), "letters,digits,underscore,dash,dot,other")
        self.assertEqual(linux_source_build._token_classes("-"), "dash")
        self.assertEqual(linux_source_build._token_classes(""), "none")

    @unittest.skipUnless(hasattr(os, "memfd_create"), "the verifier key descriptor uses memfd_create, which only Linux provides")
    def test_a_refusal_after_the_token_was_issued_makes_a_best_effort_delete_and_never_logs_the_token(self):
        token = "ghs_" + "ab-cd.ef" * 5
        installation = (200, {"id": 19, "account": {"login": "keeldock"}})
        good = (201, {"token": token, "permissions": {"contents": "read", "metadata": "read"}})
        bad_permissions = (201, {"token": token, "permissions": {"contents": "write"}})
        one_repository = (200, {"total_count": 1, "repositories": [{"id": 41, "name": "private-source"}]})
        two_repositories = (200, {"total_count": 2, "repositories": [{"id": 41, "name": "private-source"}]})
        mask = linux_source_build._mask_line(token)
        for name, replies, stage, expected_calls in (
            ("permissions", [installation, bad_permissions, (204, None)], "permissions", 3),
            ("permissions_delete_refused", [installation, bad_permissions, linux_source_build.SourceBuildRefusal("network")], "permissions", 3),
            ("permissions_delete_error", [installation, bad_permissions, OSError("down")], "permissions", 3),
            ("repositories", [installation, good, two_repositories, (204, None)], "repositories", 4),
            ("repositories_delete_refused", [installation, good, two_repositories, RuntimeError("boom")], "repositories", 4),
            ("repositories_wrong_id", [installation, good, (200, {"total_count": 1, "repositories": [{"id": 5, "name": "x"}]}), (204, None)], "repositories", 4),
        ):
            with self.subTest(case=name):
                text, calls, refusal = self.run_refused_mint(replies)
                self.assertEqual(refusal.reason, "token")
                discard = "linux-verifier-token-discard=" + ("deleted" if replies[-1] == (204, None) else "failed") + "\n"
                self.assertEqual(text, mask + discard + "linux-verifier-token-diag stage=" + stage + "\n")
                self.assertEqual(text.count(token.replace("%", "%25")), 1)
                self.assertEqual(len(calls), expected_calls)
                self.assertEqual(calls[-1][:3], ("/installation/token", token, "DELETE"))
                self.assertEqual(calls[-1][3], mask)
        text, calls, refusal = self.run_refused_mint([
            installation, good, linux_source_build.SourceBuildRefusal("network"), (204, None),
        ])
        self.assertEqual(refusal.reason, "network")
        self.assertEqual(text, mask + "linux-verifier-token-discard=deleted\n")
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[-1][:3], ("/installation/token", token, "DELETE"))

    @unittest.skipUnless(hasattr(os, "memfd_create"), "the verifier key descriptor uses memfd_create, which only Linux provides")
    def test_any_exception_from_the_repositories_request_deletes_the_issued_token_and_is_re_raised_unchanged(self):
        token = "ghs_" + "ab-cd.ef" * 5
        installation = (200, {"id": 19, "account": {"login": "keeldock"}})
        good = (201, {"token": token, "permissions": {"contents": "read", "metadata": "read"}})
        mask = linux_source_build._mask_line(token)
        for name, error in (
            ("runtime", RuntimeError("boom")), ("os", OSError("down")), ("value", ValueError("bad")),
            ("keyboard", KeyboardInterrupt()), ("refusal", linux_source_build.SourceBuildRefusal("network")),
        ):
            with self.subTest(error=name):
                text, calls, raised = self.run_refused_mint([installation, good, error, (204, None)], expected=type(error))
                self.assertIs(raised, error)
                self.assertEqual(text, mask + "linux-verifier-token-discard=deleted\n")
                self.assertEqual(len(calls), 4)
                self.assertEqual(calls[-1][:3], ("/installation/token", token, "DELETE"))
                self.assertEqual(calls[-1][3], mask)
        text, calls, raised = self.run_refused_mint(
            [installation, good, RuntimeError("boom"), OSError("delete failed")], expected=RuntimeError,
        )
        self.assertEqual(str(raised), "boom")
        self.assertEqual(text, mask + "linux-verifier-token-discard=failed\n")
        self.assertEqual(len(calls), 4)

    def test_checkout_refuses_an_unsafe_token_before_any_request(self):
        identity = {"owner": "owner", "name": "source", "repository_id": "7", "source_sha": "a" * 40}
        for bad in ("", "short", "a" * 4097, "a" * 10 + " " + "a" * 10, "a" * 10 + ":" + "a" * 10, "a" * 10 + chr(233) + "a" * 10):
            with self.subTest(bad=repr(bad)[:24]):
                with tempfile.TemporaryDirectory() as temporary, patch.object(
                    linux_source_build, "_source_inputs", return_value=identity
                ), patch.object(linux_source_build, "_api_request") as api, patch.object(linux_source_build, "_git") as git:
                    with self.assertRaises(linux_source_build.SourceBuildRefusal) as raised:
                        linux_source_build.checkout_source({"SOURCE_READER_TOKEN": bad, "RUNNER_TEMP": temporary})
                    self.assertEqual(raised.exception.reason, "token")
                    api.assert_not_called()
                    git.assert_not_called()
                    self.assertFalse((Path(temporary) / "kd-source-checkout").exists())

    def test_revoke_tries_any_header_safe_token_and_refuses_the_rest_before_any_request(self):
        for bad in (
            "", "a" * 4097, "a" * 10 + " " + "a" * 10, "a" * 10 + "\t" + "a" * 10, "a" * 10 + "\n",
            "a" * 10 + chr(0) + "a" * 10, "a" * 10 + chr(127) + "a" * 10, "a" * 10 + chr(233) + "a" * 10, None,
        ):
            with self.subTest(refused=repr(bad)[:24]):
                with tempfile.TemporaryDirectory() as temporary, patch.object(linux_source_build, "_api_request") as api:
                    with self.assertRaises(linux_source_build.SourceBuildRefusal) as raised:
                        linux_source_build.revoke_token({"SOURCE_READER_TOKEN": bad, "RUNNER_TEMP": temporary})
                    self.assertEqual(raised.exception.reason, "revocation")
                    api.assert_not_called()
                    self.assertFalse((Path(temporary) / "kd-records").exists())
        for token in ("x", "short", "a:b", "a,b", '"quoted"', "a" * 4096, "v2.ab-cd." + "ef-gh.ij" * 30, "ghs_" + "T" * 36):
            with self.subTest(accepted=repr(token)[:24]):
                with tempfile.TemporaryDirectory() as temporary:
                    with patch.object(linux_source_build, "_api_request", side_effect=[(204, {}), (401, {})]) as api:
                        self.assertEqual(linux_source_build.revoke_token({"SOURCE_READER_TOKEN": token, "RUNNER_TEMP": temporary}), 0)
                    self.assertEqual(api.call_args_list[0].args[:2], ("/installation/token", token))
                    self.assertEqual(api.call_args_list[1].args[:2], ("/installation/repositories?per_page=1", token))

    def test_the_old_alphanumeric_token_shape_is_gone_from_the_kit(self):
        source = Path(linux_source_build.__file__).read_text(encoding="ascii")
        self.assertNotIn("{20,1024}", source)
        self.assertNotIn("len(token) > 4096", source)
        self.assertEqual(source.count("SOURCE_TOKEN_RE.fullmatch("), 1)
        self.assertEqual(source.count("HEADER_TOKEN_RE.fullmatch("), 2)
        self.assertIn('HEADER_TOKEN_RE = re.compile(r"[!-~]{1,4096}\\Z")', source)
        self.assertEqual(source.count('"::add-mask::"'), 1)

    def test_verifier_key_forms_are_canonicalised_to_one_wrapped_pem(self):
        der = b"\x30\x82" + bytes(range(1, 120))
        encoded = base64.b64encode(der).decode("ascii")
        rows = [encoded[offset:offset + 64] for offset in range(0, len(encoded), 64)]
        for label in ("PRIVATE KEY", "RSA PRIVATE KEY"):
            canonical = "-----BEGIN " + label + "-----\n" + "\n".join(rows) + "\n-----END " + label + "-----\n"
            begin, end = "-----BEGIN " + label + "-----", "-----END " + label + "-----"
            forms = {
                "plain": canonical,
                "padded": "  \n" + canonical + "\n  ",
                "bom": chr(65279) + canonical,
                "quoted": '"' + canonical.strip() + '"',
                "crlf": canonical.replace("\n", "\r\n"),
                "escaped": canonical.strip().replace("\n", "\\n"),
                "escaped_crlf": canonical.strip().replace("\n", "\\r\\n"),
                "double_escaped": canonical.strip().replace("\n", "\\\\n"),
                "spaces": canonical.strip().replace("\n", " "),
                "one_line": begin + encoded + end,
            }
            for name, value in forms.items():
                with self.subTest(label=label, form=name):
                    self.assertEqual(linux_source_build._app_key_pem(value), canonical)
        for line in canonical.splitlines()[1:-1]:
            self.assertLessEqual(len(line), 64)
        certificate = "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n"
        public = "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n"
        wrong_start = base64.b64encode(b"\x31" + b"a" * 40).decode("ascii")
        oversized = base64.b64encode(b"\x30" + b"a" * 9000).decode("ascii")
        for name, bad in {
            "empty": "", "not_a_key": "not a key", "certificate": certificate, "public": public,
            "plain_base64_of_pem": base64.b64encode(canonical.encode("ascii")).decode("ascii"),
            "no_end": "-----BEGIN PRIVATE KEY-----\n" + encoded,
            "bad_base64": "-----BEGIN PRIVATE KEY-----\n@@@@\n-----END PRIVATE KEY-----\n",
            "empty_body": "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
            "wrong_der_start": "-----BEGIN PRIVATE KEY-----\n" + wrong_start + "\n-----END PRIVATE KEY-----\n",
            "oversized_der": "-----BEGIN PRIVATE KEY-----\n" + oversized + "\n-----END PRIVATE KEY-----\n",
            "oversized_raw": "-----BEGIN PRIVATE KEY-----\n" + "A" * 33000,
            "non_ascii": "-----BEGIN PRIVATE KEY-----\n" + chr(233) + encoded + "\n-----END PRIVATE KEY-----\n",
        }.items():
            with self.subTest(refused=name):
                self.assertEqual(linux_source_build._app_key_pem(bad), "")

    def test_a_token_refusal_names_one_stage_from_a_closed_vocabulary_and_never_prints_openssl_text(self):
        expected = {
            "input", "key_format", "key_write", "sign_exec", "sign_key", "sign_size",
            "installation", "issue", "permissions", "repositories",
        }
        self.assertEqual(set(linux_source_build.TOKEN_STAGES), expected)
        source = Path(linux_source_build.__file__).read_text(encoding="ascii")
        literals = set(re.findall(r'_token_refusal\("([a-z_]+)"[,)]', source))
        self.assertTrue(literals <= expected)
        self.assertEqual(literals | {"sign_key", "sign_exec"}, expected)
        for text, stage in (
            (b"Could not read private key from /proc/self/fd/5", "sign_key"),
            (b"error:1E08010C:DECODER routines::unsupported", "sign_key"),
            (b"Bad decrypt", "sign_key"),
            (b"no start line", "sign_key"),
            (b"", "sign_exec"),
            (b"unrelated failure", "sign_exec"),
        ):
            with self.subTest(stderr=text[:12]):
                signed = types.SimpleNamespace(returncode=1, stdout=b"", stderr=text)
                self.assertEqual(linux_source_build._sign_failure_stage(signed), stage)
        self.assertEqual(linux_source_build._sign_failure_stage(types.SimpleNamespace(returncode=1, stdout=b"")), "sign_exec")
        identity = {"owner": "KeelDock", "name": "private-source", "repository_id": "41"}
        key = "-----BEGIN PRIVATE KEY-----\n" + _FIXTURE_BODY + "\n-----END PRIVATE KEY-----\n"
        env = {
            "SOURCE_READER_CLIENT_ID": "Iv1.abc123", "SOURCE_READER_INSTALLATION_ID": "19",
            "SOURCE_READER_PRIVATE_KEY": key,
        }
        cases = (
            (dict(env, SOURCE_READER_PRIVATE_KEY="not a key"), None, "key_format"),
            (dict(env, SOURCE_READER_PRIVATE_KEY=key.replace(_FIXTURE_BODY, chr(233) + _FIXTURE_BODY)), None, "key_format"),
            ({"SOURCE_READER_INSTALLATION_ID": "19", "SOURCE_READER_PRIVATE_KEY": key}, None, "input"),
            (env, types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"unable to load Private Key"), "sign_key"),
            (env, types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"boom"), "sign_exec"),
            (env, types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""), "sign_exec"),
            (env, types.SimpleNamespace(returncode=0, stdout=b"s" * 10, stderr=b""), "sign_size"),
            (env, types.SimpleNamespace(returncode=0, stdout=b"s" * 2000, stderr=b""), "sign_size"),
        )
        for values, signed, stage in cases:
            with self.subTest(stage=stage):
                transcript = io.StringIO()
                with patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
                    linux_source_build.sys, "stdout", transcript
                ):
                    if signed is None:
                        with self.assertRaises(linux_source_build.SourceBuildRefusal) as raised:
                            linux_source_build.mint_verifier_token(values)
                    elif not hasattr(os, "memfd_create"):
                        continue
                    else:
                        with patch.object(linux_source_build.subprocess, "run", return_value=signed):
                            with self.assertRaises(linux_source_build.SourceBuildRefusal) as raised:
                                linux_source_build.mint_verifier_token(values)
                self.assertEqual(raised.exception.reason, "token")
                self.assertEqual(transcript.getvalue(), "linux-verifier-token-diag stage=" + stage + "\n")

    def test_shared_auditor_rejects_verdict_outside_the_plain_run_step(self):
        expected = linux_source_build._expected_run({
            "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "synthetic",
        }, "b" * 64)
        steps = [{"name": name, "conclusion": "success"} for name in linux_source_build.VERDICT_STEP_NAMES]
        job = {"steps": steps}
        line = confinement_verdict.encode_line({
            "os": "linux", "boundary": "linux-ns-seccomp-uid", "control_sha": "a" * 40,
            "run_id": 7, "run_attempt": 1,
            "channels": {name: {"status": "blocked", "before": True, "after": True}
                         for name in confinement_verdict.CHANNELS},
            "memory_canary": "absent", "readable_file_canary": "absent",
            "handoff": "not-applicable", "project_execution": "not_started",
            "gates": 0, "failed": 0, "token_revocation": "not-applicable",
        }).encode("ascii")
        headers = [bytes((35, 35)) + b"[group]Run verified command\n" for unused in steps]
        good = b"".join(headers) + line + b"\n"
        confinement_public_audit._check_section(good, job, expected)
        bad = b"".join(headers[:-1]) + line + b"\n" + headers[-1]
        with self.assertRaises(confinement_public_audit.AuditRefusal):
            confinement_public_audit._check_section(bad, job, expected)

    def _write_manifests(self, directory, root_extra=None, workspace_extra=None, kernel_extra=None):
        root = {
            "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        }
        root.update(root_extra or {})
        package = {"name": "@synthetic/host-api", "version": "1.0.0"}
        package.update(workspace_extra or {})
        base = Path(directory)
        (base / "packages/host-api").mkdir(parents=True)
        (base / "packages/kernel-i18n").mkdir(parents=True)
        kernel = {"name": "@synthetic/kernel-i18n", "version": "1.0.0"}
        kernel.update(kernel_extra or {})
        (base / "package.json").write_text(json.dumps(root), encoding="ascii")
        (base / "packages/host-api/package.json").write_text(json.dumps(package), encoding="ascii")
        (base / "packages/kernel-i18n/package.json").write_text(json.dumps(kernel), encoding="ascii")
        return base

    def test_manifest_digest_binds_the_exact_root_override_and_refuses_everything_else(self):
        with tempfile.TemporaryDirectory() as directory:
            plain = linux_source_build._manifest_digest(self._write_manifests(Path(directory) / "plain"))
        with tempfile.TemporaryDirectory() as directory:
            allowed = linux_source_build._manifest_digest(self._write_manifests(
                Path(directory) / "allowed", {"overrides": {"lightningcss": "1.33.0"}},
            ))
        self.assertNotEqual(plain, allowed)
        for index, root_extra in enumerate((
            {"overrides": {"lightningcss": "1.32.0"}}, {"overrides": {"lightningcss": "^1.33.0"}},
            {"overrides": {"lightningcss": {"x": "1.33.0"}}}, {"overrides": {"other": "1.33.0"}},
            {"overrides": {}}, {"overrides": ["lightningcss"]}, {"overrides": "1.33.0"}, {"overrides": None},
            {"overrides": {"lightningcss": "1.33.0", "other": "1.0.0"}},
            {"resolutions": {"a": "1.0.0"}}, {"bundleDependencies": ["a"]}, {"bundledDependencies": ["a"]},
        )):
            with self.subTest(root=root_extra), tempfile.TemporaryDirectory() as directory:
                base = self._write_manifests(Path(directory) / ("r%d" % index), root_extra)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._manifest_digest(base)
        for index, workspace_extra in enumerate((
            {"overrides": {"lightningcss": "1.33.0"}}, {"overrides": {}}, {"resolutions": {"a": "1.0.0"}},
        )):
            with self.subTest(workspace=workspace_extra), tempfile.TemporaryDirectory() as directory:
                base = self._write_manifests(Path(directory) / ("w%d" % index), None, workspace_extra)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._manifest_digest(base)

    def test_manifest_digest_binds_every_reviewed_workspace_in_the_shared_order(self):
        self.assertEqual(
            linux_source_build.MANIFEST_WORKSPACE_PATHS,
            ("packages/host-api", "packages/kernel-i18n"),
        )
        with tempfile.TemporaryDirectory() as directory:
            baseline = linux_source_build._manifest_digest(self._write_manifests(Path(directory) / "base"))
        expected = {
            "root": {
                "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
                "devDependencies": {"typescript": "6.0.3"},
            },
            "workspaces": [
                {"path": "packages/host-api", "name": "@synthetic/host-api", "version": "1.0.0"},
                {"path": "packages/kernel-i18n", "name": "@synthetic/kernel-i18n", "version": "1.0.0"},
            ],
        }
        encoded = json.dumps(
            expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        self.assertEqual(baseline, hashlib.sha256(encoded).hexdigest())
        for index, kernel_extra in enumerate((
            {"version": "1.0.1"}, {"name": "@synthetic/kernel-other"},
            {"dependencies": {"left-pad": "1.3.0"}}, {"devDependencies": {"typescript": "6.0.3"}},
        )):
            with self.subTest(kernel=kernel_extra), tempfile.TemporaryDirectory() as directory:
                changed = linux_source_build._manifest_digest(
                    self._write_manifests(Path(directory) / ("k%d" % index), None, None, kernel_extra)
                )
                self.assertNotEqual(changed, baseline)

    def test_manifest_digest_refuses_an_unreviewed_kernel_workspace_manifest(self):
        for index, kernel_extra in enumerate((
            {"overrides": {"lightningcss": "1.33.0"}}, {"resolutions": {"a": "1.0.0"}},
            {"bundleDependencies": ["a"]}, {"bundledDependencies": ["a"]},
            {"dependencies": {"left-pad": "git+https://example.invalid/left-pad.git"}},
            {"dependencies": {"left-pad": "file:../left-pad"}},
            {"dependencies": {"Bad Name": "1.0.0"}}, {"version": 1},
        )):
            with self.subTest(kernel=kernel_extra), tempfile.TemporaryDirectory() as directory:
                base = self._write_manifests(Path(directory) / ("k%d" % index), None, None, kernel_extra)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._manifest_digest(base)
        with tempfile.TemporaryDirectory() as directory:
            base = self._write_manifests(Path(directory) / "missing")
            (base / "packages/kernel-i18n/package.json").unlink()
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._manifest_digest(base)
        with tempfile.TemporaryDirectory() as directory:
            base = self._write_manifests(Path(directory) / "narrow", {"workspaces": ["packages/host-api"]})
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._manifest_digest(base)


LOCK_SHA = "5" * 64
IDENTITY = {"owner": "owner", "name": "source"}
RESOLVER = {"node_version": "24.22.1", "npm_version": "11.19.1"}
LOCKED = {
    "node_modules/fixture-lib": {"version": "1.5.0", "dev": True},
    "node_modules/tool-a": {"version": "9.0.0", "dev": True},
    "node_modules/tool-a/node_modules/fixture-lib": {"version": "1.5.0", "dev": True},
    "node_modules/runtime-lib": {"version": "1.0.0"},
}


@unittest.skipIf(_LINUX_ONLY, "the Linux source build suite runs only on Linux")
class ManifestReadAndLockGuardTests(unittest.TestCase):
    def test_manifest_json_reads_only_a_bounded_regular_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            good = root / "package.json"
            good.write_text('{"name":"x"}', encoding="ascii")
            self.assertEqual(linux_source_build._manifest_json(good), {"name": "x"})
            (root / "secret.json").write_text('{"name":"leak"}', encoding="ascii")
            (root / "link.json").symlink_to(root / "secret.json")
            (root / "empty.json").write_bytes(b"")
            (root / "big.json").write_bytes(b" " * (linux_source_build.MAX_PACKAGE_JSON_BYTES + 1))
            (root / "dir.json").mkdir()
            (root / "duplicate.json").write_text('{"a":1,"a":2}', encoding="ascii")
            os.mkfifo(root / "fifo.json")
            for name in ("link.json", "empty.json", "big.json", "dir.json", "duplicate.json", "fifo.json", "missing.json"):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
                        linux_source_build._manifest_json(root / name)

    def test_a_tree_with_no_cargo_lock_is_refused_by_the_explicit_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
                linux_source_build._validate_cargo_lock_sources(root)


@unittest.skipIf(_LINUX_ONLY, "the Linux source build suite runs only on Linux")
class QuickTierVerdictTests(unittest.TestCase):
    def test_the_quick_tier_can_never_emit_a_verdict(self):
        for mode in ("source", "synthetic", ""):
            env = {
                "KD_LINUX_TIER": "quick", "CI_MODE": mode, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "PRODUCER_RESULT": "success",
            }
            with self.subTest(mode=mode):
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                        linux_source_build.emit_verdict(env)
                self.assertEqual(output.getvalue(), "")
        output = io.StringIO()
        with patch.dict(os.environ, {"KD_LINUX_TIER": "quick"}), patch.object(linux_source_build.sys, "stdout", output):
            self.assertEqual(linux_source_build.main(["verdict"]), 1)
        self.assertEqual(output.getvalue(), "linux-source-build=refused phase=verdict reason=identity\n")
        self.assertNotIn("KD-CONFINEMENT-VERDICT", output.getvalue())


from test_linux_source_build_tiers import *


if __name__ == "__main__":
    unittest.main(verbosity=2)
