"""Promote one already-green commit through the permanent branches without rewriting history."""

import argparse
import json
import os
import re
import subprocess
import sys


SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
TARGETS = {"uat": "develop", "main": "uat"}
WORKFLOW_CHECKS = {
    "public-policy": (
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
    ),
}
GITHUB_ACTIONS_APP_ID = 15368
SOURCE_FREE_CONTROL_REF = re.compile(r"refs/heads/[A-Za-z0-9._/-]{1,200}\Z")
MAIN_ONLY_REF = "refs/heads/main"
REFUSALS = frozenset((
    "approval", "branch", "check", "fast-forward", "head", "protection", "repository", "usage",
))


class PromotionRefusal(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REFUSALS else "usage"
        super().__init__(self.reason)


def control_dispatch_allowed(ref):
    """The source-free control holds no secret, so any branch may run it (a pull request head can then be checked)."""
    return type(ref) is str and SOURCE_FREE_CONTROL_REF.fullmatch(ref) is not None


def durable_evidence_allowed(ref):
    """Only main may save control evidence for the encrypted lane, and only main may dispatch that lane."""
    return ref == MAIN_ONLY_REF


def control_contexts():
    return frozenset(context for contexts in WORKFLOW_CHECKS.values() for context in contexts)


def required_checks_satisfiable_before_merge(required):
    """Exactly the contexts the source-free control produces, each pinned to the Actions app (no subset, no unpinned)."""
    if type(required) is not dict:
        return False
    return (set(required) == control_contexts()
            and all(type(app) is int and app == GITHUB_ACTIONS_APP_ID for app in required.values()))


def promotion_branches(target):
    source = TARGETS.get(target)
    if source is None:
        raise PromotionRefusal("branch")
    return source, target


def verify_exact_target(expected_sha, actual_sha):
    if (type(expected_sha) is not str or SHA_RE.fullmatch(expected_sha) is None
            or type(actual_sha) is not str or SHA_RE.fullmatch(actual_sha) is None
            or actual_sha != expected_sha):
        raise PromotionRefusal("head")
    return actual_sha


def _run(argv, *, cwd=None, timeout=30):
    try:
        result = subprocess.run(
            argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False, text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PromotionRefusal("check") from None
    if result.returncode != 0:
        raise PromotionRefusal("check")
    return result.stdout.strip()


def _repository(root):
    remote = _run(("git", "remote", "get-url", "origin"), cwd=root)
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?",
        remote,
    )
    if match is None or REPOSITORY_RE.fullmatch(match.group(1)) is None:
        raise PromotionRefusal("repository")
    return match.group(1)


def _pages(payload, field=None):
    if type(payload) is not list:
        raise PromotionRefusal("check")
    result = []
    for page in payload:
        values = page.get(field, []) if field is not None and type(page) is dict else page
        if type(values) is not list:
            raise PromotionRefusal("check")
        result.extend(values)
    return result


def required_checks(document):
    if type(document) is not dict:
        raise PromotionRefusal("protection")
    checks = {}
    contexts = document.get("contexts", [])
    pinned_checks = document.get("checks", [])
    if type(contexts) is not list or type(pinned_checks) is not list:
        raise PromotionRefusal("protection")
    for context in contexts:
        if type(context) is not str or not context:
            raise PromotionRefusal("protection")
        checks.setdefault(context, None)
    for item in pinned_checks:
        if (type(item) is not dict or type(item.get("context")) is not str or not item["context"]
                or (item.get("app_id") is not None and type(item.get("app_id")) is not int)):
            raise PromotionRefusal("protection")
        context = item["context"]
        checks[context] = item.get("app_id")
    if not checks:
        raise PromotionRefusal("protection")
    return checks


def matching_required_checks(source_document, target_document):
    source = required_checks(source_document)
    target = required_checks(target_document)
    if source != target:
        raise PromotionRefusal("protection")
    return target


def _latest(rows):
    if not rows:
        return None
    if any(type(row.get("id")) is not int or row["id"] <= 0 for row in rows):
        raise PromotionRefusal("check")
    return max(rows, key=lambda row: row["id"])


def green_required_checks(required, check_runs, statuses, expected_sha):
    if type(required) is not dict or not required:
        raise PromotionRefusal("protection")
    if type(expected_sha) is not str or SHA_RE.fullmatch(expected_sha) is None:
        raise PromotionRefusal("head")
    if type(check_runs) is not list or type(statuses) is not list:
        raise PromotionRefusal("check")
    for context, required_app in required.items():
        matches = [
            row for row in check_runs
            if type(row) is dict and row.get("name") == context
            and row.get("head_sha") == expected_sha
            and (required_app is None or (type(row.get("app")) is dict and row["app"].get("id") == required_app))
        ]
        status_matches = [
            row for row in statuses
            if type(row) is dict and row.get("context") == context and row.get("sha") == expected_sha
        ]
        attempts = matches
        if required_app is not None and not attempts:
            raise PromotionRefusal("check")
        if attempts:
            latest = _latest(attempts)
            if latest.get("status") != "completed" or latest.get("conclusion") != "success":
                raise PromotionRefusal("check")
        elif not status_matches:
            raise PromotionRefusal("check")
        if status_matches:
            latest = _latest(status_matches)
            if latest.get("state") != "success":
                raise PromotionRefusal("check")
    return True


def _belongs_to_workflow_run(row, run_id):
    if not run_id or type(row) is not dict:
        return False
    links = (row.get("details_url", ""), row.get("html_url", ""),
             row.get("target_url", ""), row.get("external_id", ""))
    run_suffix = "/actions/runs/" + run_id
    return any(type(value) is str and (run_suffix in value or value.startswith(run_id + ":"))
               for value in links)


def promotion_checks_reusable(workflow, target, expected_sha, repository, current_run_id=""):
    """Reuse only this workflow's completed checks from the exact promoted SHA."""
    contexts = WORKFLOW_CHECKS.get(workflow)
    if (contexts is None or target not in TARGETS
            or type(repository) is not str or REPOSITORY_RE.fullmatch(repository) is None
            or type(expected_sha) is not str or SHA_RE.fullmatch(expected_sha) is None):
        return False
    try:
        check_payload = _api_json(
            repository, "commits/" + expected_sha + "/check-runs?filter=all&per_page=100", paginate=True,
        )
        status_payload = _api_json(
            repository, "commits/" + expected_sha + "/statuses?per_page=100", paginate=True,
        )
        check_runs = [row for row in _pages(check_payload, "check_runs")
                      if not _belongs_to_workflow_run(row, current_run_id)]
        statuses = [row for row in _pages(status_payload)
                    if not _belongs_to_workflow_run(row, current_run_id)]
        required = {context: GITHUB_ACTIONS_APP_ID for context in contexts}
        return green_required_checks(required, check_runs, statuses, expected_sha)
    except (PromotionRefusal, TypeError, ValueError):
        return False


def _api_json(repository, endpoint, *, paginate=False):
    arguments = ["gh", "api"]
    if paginate:
        arguments.extend(("--paginate", "--slurp"))
    arguments.append("repos/" + repository + "/" + endpoint)
    output = _run(arguments)
    try:
        return json.loads(output)
    except (TypeError, ValueError):
        raise PromotionRefusal("check") from None


def _remote_sha(root, branch):
    output = _run(("git", "ls-remote", "--exit-code", "origin", "refs/heads/" + branch), cwd=root)
    fields = output.split()
    if len(fields) != 2 or fields[1] != "refs/heads/" + branch or SHA_RE.fullmatch(fields[0]) is None:
        raise PromotionRefusal("head")
    return fields[0]


def promote(root, target, sha, owner_approved):
    if owner_approved is not True:
        raise PromotionRefusal("approval")
    if type(sha) is not str or SHA_RE.fullmatch(sha) is None:
        raise PromotionRefusal("head")
    source, target = promotion_branches(target)
    repository = _repository(root)
    _run((
        "git", "fetch", "--no-tags", "origin",
        "refs/heads/" + source + ":refs/remotes/origin/" + source,
        "refs/heads/" + target + ":refs/remotes/origin/" + target,
    ), cwd=root)
    source_head = _run(("git", "rev-parse", "refs/remotes/origin/" + source), cwd=root)
    target_head = _run(("git", "rev-parse", "refs/remotes/origin/" + target), cwd=root)
    if source_head != sha:
        raise PromotionRefusal("head")
    try:
        ancestry = subprocess.run(
            ("git", "merge-base", "--is-ancestor", target_head, sha), cwd=root,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PromotionRefusal("fast-forward") from None
    if ancestry.returncode != 0:
        raise PromotionRefusal("fast-forward")

    source_protection = _api_json(repository, "branches/" + source + "/protection/required_status_checks")
    target_protection = _api_json(repository, "branches/" + target + "/protection/required_status_checks")
    required = matching_required_checks(source_protection, target_protection)
    if not required_checks_satisfiable_before_merge(required):
        raise PromotionRefusal("protection")
    check_payload = _api_json(repository, "commits/" + sha + "/check-runs?filter=all&per_page=100", paginate=True)
    status_payload = _api_json(repository, "commits/" + sha + "/statuses?per_page=100", paginate=True)
    green_required_checks(required, _pages(check_payload, "check_runs"), _pages(status_payload), sha)
    if _remote_sha(root, source) != sha:
        raise PromotionRefusal("head")
    _run(("git", "push", "origin", sha + ":refs/heads/" + target), cwd=root)
    verify_exact_target(sha, _remote_sha(root, target))
    return {"source": source, "target": target, "sha": sha, "checks": len(required)}


def main(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=tuple(TARGETS))
    parser.add_argument("--sha")
    parser.add_argument("--owner-approved", action="store_true")
    parser.add_argument("--reuse-checks-if-green", action="store_true")
    parser.add_argument("--workflow", choices=tuple(WORKFLOW_CHECKS))
    parser.add_argument("--root", default=".")
    options = parser.parse_args(arguments)
    if options.reuse_checks_if_green:
        if options.target is None or options.sha is None or options.workflow is None:
            parser.error("--reuse-checks-if-green requires --target, --sha, and --workflow")
        reusable = promotion_checks_reusable(
            options.workflow, options.target, options.sha,
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("GITHUB_RUN_ID", ""),
        )
        output = os.environ.get("GITHUB_OUTPUT", "")
        if output:
            try:
                with open(output, "at", encoding="ascii") as sink:
                    sink.write("skip_checks=" + ("true" if reusable else "false") + "\n")
            except OSError:
                reusable = False
        else:
            reusable = False
        print("promotion-checks=" + ("reused" if reusable else "run"))
        return 0
    if options.target is None or options.sha is None:
        parser.error("promotion requires --target and --sha")
    try:
        result = promote(options.root, options.target, options.sha, options.owner_approved)
        print("promotion=complete target=" + result["target"] + " sha=" + result["sha"]
              + " required-checks=" + str(result["checks"]))
        return 0
    except PromotionRefusal as error:
        print("promotion=refused reason=" + error.reason)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
