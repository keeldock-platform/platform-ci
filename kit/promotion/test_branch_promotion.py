import re
import unittest
from pathlib import Path
from unittest.mock import patch

import branch_promotion


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_CHECK_JOBS = {
    ".github/workflows/public-policy.yml": (
        "policy", "node-lock-smoke", "linux-confinement", "windows-confinement",
        "windows-handoff-synthetic", "development-feedback-smoke", "devlane-synthetic", "control-audit",
    ),
}
EXPECTED_REQUIRED_CONTEXTS = frozenset((
    "policy-ubuntu-24.04",
    "policy-macos-15",
    "policy-windows-2025",
    "node-lock-smoke / node-lock-smoke-ubuntu-24.04",
    "node-lock-smoke / node-lock-smoke-macos-15",
    "node-lock-smoke / node-lock-smoke-windows-2025",
    "linux-confinement / linux-policy",
    "linux-confinement / linux-harness",
    "windows-confinement / windows-policy",
    "windows-confinement / windows-native-synthetic",
    "windows-handoff-synthetic / handoff-unit-ubuntu-24.04",
    "windows-handoff-synthetic / handoff-unit-windows-2025",
    "development-feedback-smoke / feedback-smoke-producer ubuntu-24.04",
    "development-feedback-smoke / feedback-smoke-producer macos-15",
    "development-feedback-smoke / feedback-smoke-producer windows-2025",
    "development-feedback-smoke / feedback-smoke-audit",
    "devlane-synthetic / devlane-synthetic",
    "control-audit",
))


def _job_blocks(source):
    marker = "jobs:\n"
    if marker not in source:
        raise AssertionError("workflow has no jobs section")
    jobs_source = source.split(marker, 1)[1]
    headers = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*$", jobs_source))
    blocks = {}
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(jobs_source)
        blocks[header.group(1)] = jobs_source[header.end():end]
    return blocks


def _workflow_job_names(workflow_path, selected_jobs=None):
    source = workflow_path.read_text(encoding="utf-8")
    blocks = _job_blocks(source)
    selected_jobs = tuple(blocks) if selected_jobs is None else selected_jobs
    names = []
    for job_id in selected_jobs:
        if job_id not in blocks:
            raise AssertionError(f"{job_id} is missing from {workflow_path}")
        block = blocks[job_id]
        name_match = re.search(r"(?m)^    name:\s*(.*?)\s*$", block)
        name_template = name_match.group(1) if name_match else job_id
        matrix_runner_match = re.search(
            r"(?m)^        runner:\s*\n((?:          - [^\n]+\n?)+)", block,
        )
        runners = (
            re.findall(r"(?m)^          - ([^\n]+)$", matrix_runner_match.group(1))
            if matrix_runner_match else [None]
        )
        rendered_names = []
        for runner in runners:
            rendered = re.sub(r"\$\{\{\s*matrix\.runner\s*\}\}", runner or "", name_template)
            if runner is not None and "${{" not in name_template and not name_match:
                rendered += f" ({runner})"
            rendered_names.append(rendered)

        uses_match = re.search(r"(?m)^    uses:\s*(\S+)\s*$", block)
        if uses_match:
            uses_path = uses_match.group(1).split("@", 1)[0]
            workflow_marker = ".github/workflows/"
            if workflow_marker not in uses_path:
                raise AssertionError(f"cannot resolve reusable workflow in {workflow_path}: {uses_path}")
            callee_path = ROOT / workflow_marker / uses_path.split(workflow_marker, 1)[1]
            callee_names = _workflow_job_names(callee_path)
            rendered_names = [f"{caller} / {callee}" for caller in rendered_names for callee in callee_names]
        names.extend(rendered_names)
    return tuple(names)


class BranchPromotionTests(unittest.TestCase):
    def test_promotions_only_move_one_level_up(self):
        self.assertEqual(branch_promotion.promotion_branches("uat"), ("develop", "uat"))
        self.assertEqual(branch_promotion.promotion_branches("main"), ("uat", "main"))
        for target in ("develop", "feature", "", None):
            with self.subTest(target=target), self.assertRaises(branch_promotion.PromotionRefusal):
                branch_promotion.promotion_branches(target)

    def test_protection_must_declare_a_required_check(self):
        self.assertEqual(
            branch_promotion.required_checks({"contexts": ["dependency-checks / dependencies"], "checks": []}),
            {"dependency-checks / dependencies": None},
        )
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "protection"):
            branch_promotion.required_checks({"contexts": [], "checks": []})

    def test_source_and_target_must_have_the_same_required_check_contexts(self):
        develop = {"contexts": ["dependency-checks / dependencies"], "checks": []}
        uat = {"contexts": ["dependency-checks / dependencies"], "checks": []}
        self.assertEqual(branch_promotion.matching_required_checks(develop, uat), {
            "dependency-checks / dependencies": None,
        })
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "protection"):
            branch_promotion.matching_required_checks(develop, {"contexts": ["different"], "checks": []})

    def test_every_required_check_must_be_green_on_the_exact_sha(self):
        required = {"dependency-checks / dependencies": 15368, "policy-ubuntu-24.04": None}
        sha = "a" * 40
        runs = [
            {"name": "dependency-checks / dependencies", "status": "completed", "conclusion": "success",
             "head_sha": sha, "created_at": "2026-11-08T09:50:00Z",
             "completed_at": "2026-11-08T10:00:00Z", "id": 1, "app": {"id": 15368}},
            {"name": "dependency-checks / dependencies", "status": "completed", "conclusion": "failure",
             "head_sha": sha, "created_at": "2026-11-08T10:50:00Z",
             "completed_at": "2026-11-08T11:00:00Z", "id": 2, "app": {"id": 15368}},
            {"name": "policy-ubuntu-24.04", "status": "completed", "conclusion": "success",
             "head_sha": sha, "created_at": "2026-11-08T10:20:00Z",
             "completed_at": "2026-11-08T10:30:00Z", "id": 3, "app": {"id": 15368}},
            {"name": "policy-ubuntu-24.04", "status": "completed", "conclusion": "success",
             "head_sha": "b" * 40, "created_at": "2026-11-08T11:50:00Z",
             "completed_at": "2026-11-08T12:00:00Z", "id": 4, "app": {"id": 15368}},
        ]
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, runs, [], sha)
        runs[1]["conclusion"] = "success"
        self.assertTrue(branch_promotion.green_required_checks(required, runs, [], sha))

    def test_newer_queued_failing_or_skipped_attempt_overrides_an_older_success(self):
        required = {"dependency-checks / dependencies": 15368}
        sha = "a" * 40
        old_slow_success = {
            "name": "dependency-checks / dependencies", "status": "completed",
            "conclusion": "success", "head_sha": sha,
            "created_at": "2026-11-08T09:00:00Z", "started_at": "2026-11-08T09:01:00Z",
            "completed_at": "2026-11-08T12:00:00Z", "id": 100, "app": {"id": 15368},
        }
        newer_queued = {
            "name": "dependency-checks / dependencies", "status": "queued",
            "head_sha": sha, "started_at": None, "id": 101,
            "app": {"id": 15368},
        }
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [old_slow_success, newer_queued], [], sha)

        newer_failed = dict(
            newer_queued, status="completed", conclusion="failure",
            completed_at="2026-11-08T11:00:00Z",
        )
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [old_slow_success, newer_failed], [], sha)

        skipped = dict(
            newer_queued, status="completed", conclusion="skipped",
            completed_at="2026-11-08T11:00:00Z",
        )
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [old_slow_success, skipped], [], sha)
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [skipped], [], sha)

    def test_failing_legacy_status_cannot_be_hidden_by_a_successful_check_run(self):
        required = {"dependency-checks / dependencies": 15368}
        sha = "a" * 40
        run = {
            "name": "dependency-checks / dependencies", "status": "completed",
            "conclusion": "success", "head_sha": sha,
            "completed_at": "2026-11-08T10:00:00Z", "id": 10, "app": {"id": 15368},
        }
        status = {
            "context": "dependency-checks / dependencies", "sha": sha,
            "state": "failure", "created_at": "2026-11-08T10:01:00Z", "id": 11,
        }
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [run], [status], sha)
        status["state"] = "success"
        self.assertTrue(branch_promotion.green_required_checks(required, [run], [status], sha))

    def test_promotion_reuses_only_prior_green_checks_for_the_exact_sha(self):
        sha = "a" * 40
        contexts = branch_promotion.WORKFLOW_CHECKS["public-policy"]
        runs = [
            {"name": context, "status": "completed", "conclusion": "success",
             "head_sha": sha, "created_at": "2026-11-08T10:00:00Z",
             "completed_at": "2026-11-08T10:00:00Z",
             "id": index,
             "app": {"id": branch_promotion.GITHUB_ACTIONS_APP_ID},
             "details_url": "https://github.com/" + "keeldock" + "-platform/platform-ci/actions/runs/100"}
            for index, context in enumerate(contexts, start=1)
        ]
        runs.append({
            "name": contexts[0], "status": "in_progress", "head_sha": sha,
            "created_at": "2026-11-08T11:00:00Z", "started_at": "2026-11-08T11:00:00Z",
            "id": 200, "app": {"id": 15368},
            "details_url": "https://github.com/" + "keeldock" + "-platform/platform-ci/actions/runs/200",
        })
        runs.append({
            "name": contexts[0], "status": "completed", "conclusion": "skipped",
            "head_sha": sha, "created_at": "2026-11-08T10:30:00Z",
            "completed_at": "2026-11-08T10:30:00Z", "id": 150,
            "app": {"id": 15368},
            "details_url": "https://github.com/" + "keeldock" + "-platform/platform-ci/actions/runs/150",
        })
        payloads = [
            [{"check_runs": runs}],
            [[]],
        ]
        with patch.object(branch_promotion, "_api_json", side_effect=payloads) as api:
            self.assertFalse(branch_promotion.promotion_checks_reusable(
                "public-policy", "uat", sha, "keeldock-platform/platform-ci", "200",
            ))
        self.assertEqual(
            api.call_args_list[0].args,
            ("keeldock-platform/platform-ci", f"commits/{sha}/check-runs?filter=all&per_page=100"),
        )
        self.assertEqual(api.call_args_list[0].kwargs, {"paginate": True})

        successful_retry = runs + [{
            "name": contexts[0], "status": "completed", "conclusion": "success",
            "head_sha": sha, "created_at": "2026-11-08T11:15:00Z",
            "completed_at": "2026-11-08T11:15:00Z", "id": 250,
            "app": {"id": 15368},
            "details_url": "https://github.com/" + "keeldock" + "-platform/platform-ci/actions/runs/100",
        }]
        with patch.object(
            branch_promotion, "_api_json",
            side_effect=[[{"check_runs": successful_retry}], [[]]],
        ):
            self.assertTrue(branch_promotion.promotion_checks_reusable(
                "public-policy", "uat", sha, "keeldock-platform/platform-ci", "200",
            ))

        failed_then_skipped = successful_retry + [{
            "name": contexts[0], "status": "completed", "conclusion": "failure",
            "head_sha": sha, "created_at": "2026-11-08T11:20:00Z",
            "completed_at": "2026-11-08T11:20:00Z", "id": 275,
            "app": {"id": 15368},
            "details_url": "https://github.com/" + "keeldock" + "-platform/platform-ci/actions/runs/175",
        }]
        with patch.object(
            branch_promotion, "_api_json",
            side_effect=[[{"check_runs": failed_then_skipped}], [[]]],
        ):
            self.assertFalse(branch_promotion.promotion_checks_reusable(
                "public-policy", "main", sha,
                "keeldock-platform/platform-ci", "200",
            ))

        with patch.object(branch_promotion, "_api_json", side_effect=[[{"check_runs": runs[:-1]}], [[]]]):
            self.assertFalse(branch_promotion.promotion_checks_reusable(
                "public-policy", "main", "b" * 40,
                "keeldock-platform/platform-ci", "200",
            ))

    def test_promotion_control_is_manual_on_protected_branches(self):
        contexts = tuple(
            context
            for workflow_contexts in branch_promotion.WORKFLOW_CHECKS.values()
            for context in workflow_contexts
        )
        self.assertEqual(len(contexts), 18)
        self.assertEqual(set(contexts), EXPECTED_REQUIRED_CONTEXTS)
        workflow = (ROOT / ".github/workflows/public-policy.yml").read_text(encoding="utf-8")
        self.assertIn("on:\n  workflow_dispatch:", workflow)
        self.assertNotIn("  pull_request:\n", workflow)
        self.assertNotIn("  push:\n", workflow)
        self.assertIn('[[ "$CI_REF" =~ ^refs/heads/[A-Za-z0-9._/-]{1,200}$ ]]', workflow)

        diagnostics = {
            ".github/workflows/linux-confinement-diagnostic.yml": "linux-confinement",
            ".github/workflows/windows-confinement-diagnostic.yml": "windows-confinement-spike",
        }
        for relative, check_name in diagnostics.items():
            workflow = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(diagnostic=relative):
                self.assertIn("  workflow_dispatch:\n", workflow)
                self.assertIn(f"  {check_name}:\n", workflow)
                self.assertNotIn(check_name, EXPECTED_REQUIRED_CONTEXTS)

    def test_source_free_control_runs_on_any_branch_so_develop_checks_are_satisfiable(self):
        """develop requires the same 18 contexts as uat and main; a pull request head into develop can only
        satisfy them if the secret-free control may be dispatched from any branch, while the encrypted
        lane and the durable evidence stay on main."""
        branch_gate = "^refs/heads/[A-Za-z0-9._/-]{1,200}$"
        old_gate = "(develop|uat|main)"
        for relative in (
            "public-policy.yml", "node-lock-smoke.yml", "linux-confinement.yml", "windows-confinement.yml",
            "windows-handoff-synthetic.yml", "development-feedback-smoke.yml", "devlane-synthetic.yml",
        ):
            workflow = (ROOT / ".github/workflows" / relative).read_text(encoding="utf-8")
            with self.subTest(workflow=relative):
                self.assertIn(branch_gate, workflow)
                self.assertNotIn(old_gate, workflow)
                self.assertNotIn("secrets.", workflow)
                self.assertNotIn("environment:", workflow)
        control = (ROOT / ".github/workflows/public-policy.yml").read_text(encoding="utf-8")
        self.assertIn("if: ${{ github.ref == 'refs/heads/main' }}\n        uses: actions/cache/save@", control)
        self.assertEqual(control.count("actions/cache/save@"), 1)
        encrypted = (ROOT / ".github/workflows/devlane-encrypted.yml").read_text(encoding="utf-8")
        self.assertEqual(encrypted.count('[[ "$CI_REF" == "refs/heads/main" ]]'), 2)
        self.assertNotIn(branch_gate, encrypted)
        self.assertTrue(branch_promotion.control_dispatch_allowed("refs/heads/devlane/d1"))
        self.assertTrue(branch_promotion.control_dispatch_allowed("refs/heads/main"))
        for refused in ("refs/tags/v1", "refs/pull/1/merge", "refs/heads/", "refs/heads/a b", "main", None, ""):
            self.assertFalse(branch_promotion.control_dispatch_allowed(refused), refused)
        self.assertTrue(branch_promotion.durable_evidence_allowed("refs/heads/main"))
        self.assertFalse(branch_promotion.durable_evidence_allowed("refs/heads/develop"))
        full = {context: branch_promotion.GITHUB_ACTIONS_APP_ID for context in EXPECTED_REQUIRED_CONTEXTS}
        self.assertTrue(branch_promotion.required_checks_satisfiable_before_merge(full))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge({**full, "extra-required-check": None}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge({**full, "control-audit": 1}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge({}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge(
            {key: value for key, value in list(full.items())[1:]}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge({**full, "control-audit": None}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge(
            {**full, "control-audit": True}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge(None))
        document = (ROOT / "docs/branch-promotion.md").read_text(encoding="utf-8")
        listed = set(re.findall(r"(?m)^   - `([^`]+)`$", document))
        self.assertEqual(listed, set(EXPECTED_REQUIRED_CONTEXTS))
        self.assertIn("any branch", document)

    def test_promotion_refuses_a_required_context_the_control_cannot_produce(self):
        protections = {"contexts": ["policy-ubuntu-24.04", "extra-required-check"], "checks": []}
        sha = "a" * 40

        def fake_run(argv, cwd=None, timeout=30):
            argv = tuple(argv)
            if argv == ("git", "remote", "get-url", "origin"):
                return "https://github.com/" + "keeldock" + "-platform/platform-ci.git"
            if argv[:3] == ("git", "rev-parse", "refs/remotes/origin/develop"):
                return sha
            if argv[:3] == ("git", "rev-parse", "refs/remotes/origin/uat"):
                return "b" * 40
            return ""

        with patch.object(branch_promotion, "_run", side_effect=fake_run) as run, \
                patch.object(branch_promotion, "_api_json", side_effect=(protections, protections)), \
                patch.object(branch_promotion.subprocess, "run",
                             return_value=type("Result", (), {"returncode": 0})()):
            with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "protection"):
                branch_promotion.promote(str(ROOT), "uat", sha, True)
        self.assertFalse(any(call.args[0][:2] == ("git", "push") for call in run.call_args_list))

    def test_promotion_refuses_an_unchecked_sha_before_attempting_a_push(self):
        sha = "a" * 40
        previous = "b" * 40
        contexts = sorted(EXPECTED_REQUIRED_CONTEXTS)
        protections = {
            "contexts": [],
            "checks": [
                {"context": context, "app_id": branch_promotion.GITHUB_ACTIONS_APP_ID}
                for context in contexts
            ],
        }
        check_runs = [
            {
                "name": context,
                "status": "completed",
                "conclusion": "success",
                "head_sha": sha,
                "id": index,
                "app": {"id": branch_promotion.GITHUB_ACTIONS_APP_ID},
            }
            for index, context in enumerate(contexts[:-1], start=1)
        ]

        def fake_run(argv, cwd=None, timeout=30):
            argv = tuple(argv)
            if argv == ("git", "remote", "get-url", "origin"):
                return "https://github.com/" + "keeldock" + "-platform/platform-ci.git"
            if argv[:2] == ("git", "fetch"):
                return ""
            if argv[:3] == ("git", "rev-parse", "refs/remotes/origin/develop"):
                return sha
            if argv[:3] == ("git", "rev-parse", "refs/remotes/origin/uat"):
                return previous
            return ""

        with patch.object(branch_promotion, "_run", side_effect=fake_run) as run:
            with patch.object(
                branch_promotion,
                "_api_json",
                side_effect=(protections, protections, [{"check_runs": check_runs}], [[]]),
            ) as api:
                with patch.object(
                    branch_promotion.subprocess,
                    "run",
                    return_value=type("Result", (), {"returncode": 0})(),
                ):
                    with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
                        branch_promotion.promote(str(ROOT), "uat", sha, True)

        self.assertFalse(any(call.args[0][:2] == ("git", "push") for call in run.call_args_list))
        self.assertEqual(
            api.call_args_list[2].args,
            ("keeldock-platform/platform-ci", f"commits/{sha}/check-runs?filter=all&per_page=100"),
        )
        self.assertEqual(api.call_args_list[2].kwargs, {"paginate": True})

    def test_promotion_reuse_contexts_match_the_workflow_job_names(self):
        self.assertEqual(
            set(branch_promotion.WORKFLOW_CHECKS),
            {re.search(r"(?m)^name:\s*(.*?)\s*$", (ROOT / path).read_text(encoding="utf-8")).group(1)
             for path in WORKFLOW_CHECK_JOBS},
        )
        for path, job_ids in WORKFLOW_CHECK_JOBS.items():
            workflow = ROOT / path
            workflow_name = re.search(
                r"(?m)^name:\s*(.*?)\s*$", workflow.read_text(encoding="utf-8"),
            ).group(1)
            with self.subTest(workflow=workflow_name):
                self.assertEqual(
                    branch_promotion.WORKFLOW_CHECKS[workflow_name],
                    _workflow_job_names(workflow, job_ids),
                )

    def test_attempt_order_requires_numeric_ids_and_ignores_timestamps(self):
        required = {"dependency-checks / dependencies": 15368}
        sha = "a" * 40
        success = {
            "name": "dependency-checks / dependencies", "status": "completed",
            "conclusion": "success", "head_sha": sha, "id": 500,
            "created_at": "2026-11-08T12:00:00Z", "started_at": "2026-11-08T12:01:00Z",
            "completed_at": "2026-11-08T13:00:00Z", "app": {"id": 15368},
        }
        newer_queued_api_record = {
            "id": 501, "name": "dependency-checks / dependencies", "status": "queued",
            "conclusion": None, "head_sha": sha, "started_at": None,
            "app": {"id": 15368},
        }
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(
                required, [success, newer_queued_api_record], [], sha,
            )

        unordered_attempt = dict(newer_queued_api_record)
        del unordered_attempt["id"]
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [success, unordered_attempt], [], sha)

    def test_app_pinned_check_rejects_a_legacy_status_from_an_unverified_producer(self):
        required = {"dependency-checks / dependencies": 15368}
        sha = "a" * 40
        legacy_status = [{
            "context": "dependency-checks / dependencies",
            "sha": sha,
            "state": "success",
            "created_at": "2026-11-08T10:00:00Z",
        }]
        wrong_app_run = [{
            "name": "dependency-checks / dependencies",
            "status": "completed",
            "conclusion": "success",
            "head_sha": sha,
            "completed_at": "2026-11-08T10:01:00Z",
            "app": {"id": 99999},
        }]
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [], legacy_status, sha)
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, wrong_app_run, legacy_status, sha)

    def test_promotion_refuses_when_remote_target_does_not_equal_green_sha(self):
        sha = "a" * 40
        self.assertEqual(branch_promotion.verify_exact_target(sha, sha), sha)
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "head"):
            branch_promotion.verify_exact_target(sha, "b" * 40)
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "head"):
            branch_promotion.verify_exact_target("short", sha)


if __name__ == "__main__":
    unittest.main()
