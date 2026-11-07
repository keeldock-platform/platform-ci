import re
import unittest
from pathlib import Path
from unittest.mock import patch

import branch_promotion


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_CHECK_JOBS = {
    ".github/workflows/public-policy.yml": ("policy",),
    ".github/workflows/windows-handoff-synthetic.yml": ("handoff-unit",),
    ".github/workflows/linux-confinement.yml": ("linux-policy",),
    ".github/workflows/node-lock-smoke.yml": ("node-lock-smoke",),
    ".github/workflows/windows-confinement.yml": ("windows-policy",),
    ".github/workflows/development-feedback-smoke.yml": (
        "feedback-smoke-producer", "feedback-smoke-audit",
    ),
}


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
    selected_jobs = tuple(job for job in blocks if job != "promotion-check-reuse") \
        if selected_jobs is None else selected_jobs
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

    def test_newer_queued_or_failing_attempt_overrides_an_older_slow_success(self):
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
        self.assertTrue(branch_promotion.green_required_checks(required, [old_slow_success, skipped], [], sha))
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
        with patch.object(branch_promotion, "_api_json", side_effect=payloads):
            self.assertTrue(branch_promotion.promotion_checks_reusable(
                "public-policy", "uat", sha, "keeldock-platform/platform-ci", "200",
            ))

        failed_then_skipped = runs + [{
            "name": contexts[0], "status": "completed", "conclusion": "failure",
            "head_sha": sha, "created_at": "2026-11-08T10:45:00Z",
            "completed_at": "2026-11-08T10:45:00Z", "id": 175,
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
