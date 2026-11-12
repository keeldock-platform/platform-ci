import ast
import copy
import os
import re
import shutil
import subprocess
import textwrap
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
EXPECTED_CONTROL_CHECK_CONTEXTS = frozenset((
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
EXPECTED_REQUIRED_CONTEXTS = frozenset(("keeldock/control-verified",))
BASH_REF_GATE = re.compile(
    r"^[ \t]*\[\[\s*(?P<negate>!\s*)?\"\$CI_REF\"\s*=~\s*(?P<pattern>[^\s]+)\s*\]\][ \t]*$"
)
POWERSHELL_REF_GATE = re.compile(
    r"^[ \t]*if \(\$env:CI_REF -notmatch '([^']+)'\) \{ exit 1 \}[ \t]*$"
)
SAFE_BRANCH_PATTERN = re.compile(r"[A-Za-z0-9_./,*?^$()\[\]{}+|\\-]+\Z")
SOURCE_FREE_REFS = (
    "refs/heads/main", "refs/heads/develop", "refs/heads/fix/pr1-contract",
)
REFUSED_CONTROL_REFS = (
    "refs/pull/8/merge", "refs/tags/v1", "refs/heads/a b", "main",
)
EXPECTED_SHELL_GATE_COUNTS = {
    "public-policy.yml": 2,
    "node-lock-smoke.yml": 1,
    "linux-confinement.yml": 2,
    "windows-confinement.yml": 2,
    "windows-handoff-synthetic.yml": 1,
    "development-feedback-smoke.yml": 2,
}


def _workflow_python_dispatch_expression(workflow, job_name):
    source = workflow.read_text(encoding="utf-8")
    block = _job_blocks(source).get(job_name)
    if block is None:
        raise AssertionError("workflow job is missing")
    heredocs = re.findall(
        r"(?ms)^[ \t]*python3 -B - <<'PY'[ \t]*\n(.*?)^[ \t]*PY[ \t]*$", block,
    )
    matches = []
    for heredoc in heredocs:
        module = ast.parse(textwrap.dedent(heredoc))
        for node in ast.walk(module):
            if not isinstance(node, ast.If):
                continue
            refuses_dispatch = any(
                isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "refuse"
                and call.args and isinstance(call.args[0], ast.Constant)
                and call.args[0].value == "dispatch-identity"
                for statement in node.body for call in ast.walk(statement)
            )
            if refuses_dispatch:
                matches.append(copy.deepcopy(node.test))
    if len(matches) != 1:
        raise AssertionError("workflow must have one dispatch identity predicate")
    return matches[0]


def _python_condition_value(node, ref):
    environment = {
        "CI_REPOSITORY": "keeldock-platform/platform-ci",
        "CI_REPOSITORY_ID": "1430960557",
        "CI_SERVER_URL": "https://github.com",
        "CI_EVENT_NAME": "workflow_dispatch",
        "CI_REF": ref,
        "CI_SHA": "a" * 40,
        "CI_RUN_ID": "1",
        "CI_CONTROL_RUN_ID": "1",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    locals_map = {"run_id": "1", "attempt": "1"}

    def attribute_path(value):
        if isinstance(value, ast.Name):
            return value.id
        if isinstance(value, ast.Attribute):
            parent = attribute_path(value.value)
            return parent + "." + value.attr if parent else ""
        return ""

    def safe_value(value):
        if isinstance(value, ast.Constant) and type(value.value) in (str, int, bool, type(None)):
            return value.value
        if isinstance(value, ast.Name) and value.id in locals_map:
            return locals_map[value.id]
        if isinstance(value, ast.BoolOp) and type(value.op) in (ast.And, ast.Or):
            values = [safe_value(item) for item in value.values]
            return all(values) if isinstance(value.op, ast.And) else any(values)
        if isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not):
            return not safe_value(value.operand)
        if isinstance(value, ast.Call):
            call_name = attribute_path(value.func)
            if call_name == "os.environ.get" and 1 <= len(value.args) <= 2 and not value.keywords:
                key = safe_value(value.args[0])
                default = safe_value(value.args[1]) if len(value.args) == 2 else None
                if type(key) is not str or (len(value.args) == 2 and type(default) is not str):
                    raise AssertionError("unsupported environment lookup")
                return environment.get(key, default)
            if call_name == "re.fullmatch" and 2 <= len(value.args) <= 3 and not value.keywords:
                pattern = safe_value(value.args[0])
                candidate = safe_value(value.args[1])
                flags = safe_value(value.args[2]) if len(value.args) == 3 else 0
                if type(pattern) is not str or type(candidate) is not str or type(flags) is not int:
                    raise AssertionError("unsupported regular expression predicate")
                return re.fullmatch(pattern, candidate, flags)
            raise AssertionError("unsupported workflow predicate call")
        if isinstance(value, ast.Compare) and len(value.ops) == len(value.comparators):
            left = safe_value(value.left)
            for operation, comparator in zip(value.ops, value.comparators):
                right = safe_value(comparator)
                if isinstance(operation, ast.Eq):
                    matched = left == right
                elif isinstance(operation, ast.NotEq):
                    matched = left != right
                else:
                    raise AssertionError("unsupported workflow predicate comparison")
                if not matched:
                    return False
                left = right
            return True
        raise AssertionError("unsupported workflow dispatch predicate")

    return safe_value(node)


def _python_gate_allows(refusal_expression, ref):
    return not bool(_python_condition_value(refusal_expression, ref))


def _mutate_python_ref_pattern(expression, replacement):
    class Mutation(ast.NodeTransformer):
        changed = False

        def visit_Call(self, node):
            self.generic_visit(node)
            path = ""
            cursor = node.func
            while isinstance(cursor, ast.Attribute):
                path = "." + cursor.attr + path
                cursor = cursor.value
            if isinstance(cursor, ast.Name):
                path = cursor.id + path
            if (path == "re.fullmatch" and node.args and isinstance(node.args[0], ast.Constant)
                    and type(node.args[0].value) is str and node.args[0].value.startswith("refs/heads/")):
                node.args[0] = ast.Constant(value=replacement)
                self.changed = True
            return node

    transformer = Mutation()
    mutated = transformer.visit(copy.deepcopy(expression))
    if not transformer.changed:
        raise AssertionError("source-free Python branch pattern was not found")
    return mutated


def _mutate_python_main_refusal(expression, replacement):
    class Mutation(ast.NodeTransformer):
        changed = False

        def visit_Compare(self, node):
            self.generic_visit(node)
            left = node.left
            if (len(node.ops) == 1 and isinstance(node.ops[0], ast.NotEq)
                    and len(node.comparators) == 1 and isinstance(node.comparators[0], ast.Constant)
                    and node.comparators[0].value == "refs/heads/main"
                    and isinstance(left, ast.Call) and isinstance(left.func, ast.Attribute)
                    and left.func.attr == "get" and left.args and isinstance(left.args[0], ast.Constant)
                    and left.args[0].value == "CI_REF"):
                node.comparators[0] = ast.Constant(value=replacement)
                self.changed = True
            return node

    transformer = Mutation()
    mutated = transformer.visit(copy.deepcopy(expression))
    if not transformer.changed:
        raise AssertionError("main-only Python branch condition was not found")
    return mutated


def _shell_ref_gates(workflow):
    bash, powershell = [], []
    for line in workflow.read_text(encoding="utf-8").splitlines():
        bash_match = BASH_REF_GATE.fullmatch(line)
        if bash_match:
            pattern = bash_match.group("pattern")
            if SAFE_BRANCH_PATTERN.fullmatch(pattern) is None:
                raise AssertionError("unsupported Bash branch predicate")
            bash.append((pattern, bool(bash_match.group("negate"))))
        powershell_match = POWERSHELL_REF_GATE.fullmatch(line)
        if powershell_match:
            pattern = powershell_match.group(1)
            if SAFE_BRANCH_PATTERN.fullmatch(pattern) is None:
                raise AssertionError("unsupported PowerShell branch predicate")
            powershell.append(pattern)
    return bash, powershell


def _bash_gate_allows(pattern, negate, ref):
    bash = shutil.which("bash")
    if bash is None:
        raise AssertionError("Bash is required to validate shell branch predicates")
    expression = "[[ \"$CI_REF\" =~ " + pattern + " ]]"
    if negate:
        expression = "[[ ! \"$CI_REF\" =~ " + pattern + " ]]"
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-c", "set -euo pipefail; " + expression],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "CI_REF": ref}, timeout=5, check=False,
    )
    return result.returncode == 0


def _powershell_gate_allows(pattern, ref):
    if SAFE_BRANCH_PATTERN.fullmatch(pattern) is None:
        raise AssertionError("unsupported PowerShell branch predicate")
    return re.search(pattern, ref) is not None


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
        gate_status = {
            "id": 900, "context": branch_promotion.CONTROL_STATUS_CONTEXT,
            "state": "success", "creator": {"login": branch_promotion.CONTROL_STATUS_CREATOR, "type": "Bot"},
            "url": "https://api.github.com/repos/" + "keeldock" + "-platform/platform-ci/statuses/" + sha,
            "target_url": "https://github.com/" + "keeldock" + "-platform/platform-ci/actions/runs/99",
        }
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
            [[gate_status]],
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
            side_effect=[[{"check_runs": successful_retry}], [[gate_status]]],
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
            side_effect=[[{"check_runs": failed_then_skipped}], [[gate_status]]],
        ):
            self.assertFalse(branch_promotion.promotion_checks_reusable(
                "public-policy", "main", sha,
                "keeldock-platform/platform-ci", "200",
            ))

        with patch.object(branch_promotion, "_api_json", side_effect=[[{"check_runs": runs[:-1]}], [[gate_status]]]):
            self.assertFalse(branch_promotion.promotion_checks_reusable(
                "public-policy", "main", "b" * 40,
                "keeldock-platform/platform-ci", "200",
            ))

    def test_control_gate_requires_the_newest_actions_status_to_be_success(self):
        sha = "a" * 40
        required = {branch_promotion.CONTROL_STATUS_CONTEXT: branch_promotion.GITHUB_ACTIONS_APP_ID}
        success = {
            "id": 10, "context": branch_promotion.CONTROL_STATUS_CONTEXT, "state": "success",
            "creator": {"login": branch_promotion.CONTROL_STATUS_CREATOR, "type": "Bot"},
            "url": "https://api.github.com/repos/" + "keeldock" + "-platform/platform-ci/statuses/" + sha,
        }
        self.assertTrue(branch_promotion.green_required_checks(required, [], [success], sha))
        newer_failure = dict(success, id=11, state="failure")
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [], [success, newer_failure], sha)
        other_creator = dict(success, creator={"login": "octocat", "type": "User"})
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [], [other_creator], sha)
        wrong_sha = dict(success, sha="b" * 40)
        with self.assertRaisesRegex(branch_promotion.PromotionRefusal, "check"):
            branch_promotion.green_required_checks(required, [], [wrong_sha], sha)

    def test_promotion_control_is_manual_on_protected_branches(self):
        contexts = tuple(
            context
            for workflow_contexts in branch_promotion.WORKFLOW_CHECKS.values()
            for context in workflow_contexts
        )
        self.assertEqual(len(contexts), 18)
        self.assertEqual(set(contexts), EXPECTED_CONTROL_CHECK_CONTEXTS)
        self.assertEqual(branch_promotion.control_contexts(), EXPECTED_REQUIRED_CONTEXTS)
        self.assertEqual(len(branch_promotion.control_contexts()), 1)
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
        source_free = (
            "public-policy.yml", "node-lock-smoke.yml", "linux-confinement.yml", "windows-confinement.yml",
            "windows-handoff-synthetic.yml", "development-feedback-smoke.yml", "devlane-synthetic.yml",
        )
        seen_shell_kinds = set()
        for relative in (
            *source_free,
        ):
            path = ROOT / ".github/workflows" / relative
            workflow = path.read_text(encoding="utf-8")
            with self.subTest(workflow=relative):
                self.assertNotIn("secrets.", workflow)
                self.assertNotIn("environment:", workflow)
                bash_gates, powershell_gates = _shell_ref_gates(path)
                if relative == "devlane-synthetic.yml":
                    self.assertEqual((len(bash_gates), len(powershell_gates)), (0, 0))
                else:
                    self.assertEqual(
                        len(bash_gates) + len(powershell_gates),
                        EXPECTED_SHELL_GATE_COUNTS[relative],
                    )
                if bash_gates:
                    seen_shell_kinds.add("bash")
                if powershell_gates:
                    seen_shell_kinds.add("powershell")
                for pattern, negate in bash_gates:
                    for ref in SOURCE_FREE_REFS + REFUSED_CONTROL_REFS:
                        with self.subTest(workflow=relative, shell="bash", ref=ref):
                            self.assertEqual(
                                _bash_gate_allows(pattern, negate, ref),
                                branch_promotion.control_dispatch_allowed(ref),
                            )
                for pattern in powershell_gates:
                    for ref in SOURCE_FREE_REFS + REFUSED_CONTROL_REFS:
                        with self.subTest(workflow=relative, shell="powershell", ref=ref):
                            self.assertEqual(
                                _powershell_gate_allows(pattern, ref),
                                branch_promotion.control_dispatch_allowed(ref),
                            )
                if relative == "devlane-synthetic.yml":
                    expression = _workflow_python_dispatch_expression(path, "devlane-synthetic")
                    for ref in SOURCE_FREE_REFS + REFUSED_CONTROL_REFS:
                        with self.subTest(workflow=relative, shell="python", ref=ref):
                            self.assertEqual(
                                _python_gate_allows(expression, ref),
                                branch_promotion.control_dispatch_allowed(ref),
                            )
        self.assertEqual(seen_shell_kinds, {"bash", "powershell"})

        bash_pattern, bash_negate = _shell_ref_gates(ROOT / ".github/workflows/public-policy.yml")[0][0]
        restricted_shell = r"^refs/heads/(develop|uat|main)$"
        broad_shell = r"^refs/.*$"
        self.assertTrue(_bash_gate_allows(bash_pattern, bash_negate, "refs/heads/fix/pr1-contract"))
        self.assertFalse(_bash_gate_allows(restricted_shell, False, "refs/heads/fix/pr1-contract"))
        self.assertTrue(_bash_gate_allows(broad_shell, False, "refs/pull/8/merge"))

        powershell_pattern = _shell_ref_gates(ROOT / ".github/workflows/windows-confinement.yml")[1][0]
        self.assertTrue(_powershell_gate_allows(powershell_pattern, "refs/heads/fix/pr1-contract"))
        self.assertFalse(_powershell_gate_allows(restricted_shell, "refs/heads/fix/pr1-contract"))
        self.assertTrue(_powershell_gate_allows(broad_shell, "refs/pull/8/merge"))

        synthetic_path = ROOT / ".github/workflows/devlane-synthetic.yml"
        synthetic_gate = _workflow_python_dispatch_expression(synthetic_path, "devlane-synthetic")
        restricted_python = _mutate_python_ref_pattern(synthetic_gate, r"refs/heads/(develop|uat|main)")
        broad_python = _mutate_python_ref_pattern(synthetic_gate, r".*")
        self.assertFalse(_python_gate_allows(restricted_python, "refs/heads/fix/pr1-contract"))
        self.assertTrue(_python_gate_allows(broad_python, "refs/pull/8/merge"))

        control = (ROOT / ".github/workflows/public-policy.yml").read_text(encoding="utf-8")
        self.assertIn("if: ${{ github.ref == 'refs/heads/main' }}\n        uses: actions/cache/save@", control)
        self.assertEqual(control.count("actions/cache/save@"), 1)
        encrypted_path = ROOT / ".github/workflows/devlane-encrypted.yml"
        encrypted_gates = [
            _workflow_python_dispatch_expression(encrypted_path, "devlane-encrypted-run"),
            _workflow_python_dispatch_expression(encrypted_path, "devlane-encrypted-audit"),
        ]
        for index, expression in enumerate(encrypted_gates):
            for ref in ("refs/heads/main", "refs/heads/develop", "refs/heads/fix/pr1-contract",
                        "refs/pull/8/merge", "refs/tags/v1"):
                with self.subTest(encrypted_gate=index, ref=ref):
                    self.assertEqual(_python_gate_allows(expression, ref), ref == "refs/heads/main")
            moved_main_gate = _mutate_python_main_refusal(expression, "refs/heads/develop")
            self.assertTrue(_python_gate_allows(moved_main_gate, "refs/heads/develop"))
            self.assertFalse(_python_gate_allows(moved_main_gate, "refs/heads/main"))

        self.assertTrue(branch_promotion.control_dispatch_allowed("refs/heads/devlane/d1"))
        self.assertTrue(branch_promotion.control_dispatch_allowed("refs/heads/main"))
        for refused in ("refs/tags/v1", "refs/pull/1/merge", "refs/heads/", "refs/heads/a b", "main", None, ""):
            self.assertFalse(branch_promotion.control_dispatch_allowed(refused), refused)
        self.assertTrue(branch_promotion.durable_evidence_allowed("refs/heads/main"))
        self.assertFalse(branch_promotion.durable_evidence_allowed("refs/heads/develop"))
        full = {context: branch_promotion.GITHUB_ACTIONS_APP_ID for context in EXPECTED_REQUIRED_CONTEXTS}
        self.assertTrue(branch_promotion.required_checks_satisfiable_before_merge(full))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge({**full, "extra-required-check": None}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge({branch_promotion.CONTROL_STATUS_CONTEXT: 1}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge({}))
        self.assertFalse(branch_promotion.required_checks_satisfiable_before_merge(
            {branch_promotion.CONTROL_STATUS_CONTEXT: True}))
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
        contexts = sorted(EXPECTED_CONTROL_CHECK_CONTEXTS)
        protections = {
            "contexts": [],
            "checks": [{"context": branch_promotion.CONTROL_STATUS_CONTEXT,
                        "app_id": branch_promotion.GITHUB_ACTIONS_APP_ID}],
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
                side_effect=(protections, protections, [{"check_runs": check_runs}], [[{
                    "id": 999, "context": branch_promotion.CONTROL_STATUS_CONTEXT, "sha": sha,
                    "state": "success", "creator": {"login": branch_promotion.CONTROL_STATUS_CREATOR, "type": "Bot"},
                    "url": "https://api.github.com/repos/" + "keeldock" + "-platform/platform-ci/statuses/" + sha,
                }]]),
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
