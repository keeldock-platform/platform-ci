import argparse
import json
import re
from collections import deque
from pathlib import Path


MAX_DOCUMENT_BYTES = 262144
WINDOW_SECONDS = 3600
SCOPE_NAMES = frozenset((
    "repository_token", "source_reader", "settings_auditor", "source_auditor", "pin_writer"
))
IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class BudgetError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BudgetError("duplicate-field")
        result[key] = value
    return result


def _reject_constant(value):
    raise BudgetError("invalid-number")


def _strict_json(payload):
    if type(payload) is not bytes or len(payload) > MAX_DOCUMENT_BYTES:
        raise BudgetError("document-size")
    try:
        text = payload.decode("ascii")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BudgetError("document-invalid")


def _is_integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _has_fields(value, expected):
    return type(value) is dict and set(value) == set(expected)


def _valid_identifier(value):
    return type(value) is str and IDENTIFIER.fullmatch(value) is not None


def validate_budget_document(document):
    if not _has_fields(document, ("schema_version", "window_seconds", "watcher", "credentials")):
        raise BudgetError("budget-schema")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise BudgetError("budget-version")
    if type(document["window_seconds"]) is not int or document["window_seconds"] != WINDOW_SECONDS:
        raise BudgetError("budget-window")
    watcher = document["watcher"]
    if not _has_fields(watcher, ("maximum_per_run", "minimum_interval_seconds")):
        raise BudgetError("watcher-schema")
    if watcher["maximum_per_run"] != 1 or type(watcher["maximum_per_run"]) is not int:
        raise BudgetError("watcher-count")
    if (not _is_integer(watcher["minimum_interval_seconds"], 300)
            or watcher["minimum_interval_seconds"] < 300):
        raise BudgetError("watcher-interval")
    credentials = document["credentials"]
    if type(credentials) is not dict or set(credentials) != set(SCOPE_NAMES):
        raise BudgetError("credential-scopes")
    for scope in SCOPE_NAMES:
        limits = credentials[scope]
        if not _has_fields(limits, ("per_run", "per_workflow", "per_hour")):
            raise BudgetError("limit-schema")
        for name in ("per_run", "per_workflow", "per_hour"):
            if not _is_integer(limits[name]):
                raise BudgetError("limit-value")
        if limits["per_run"] > limits["per_hour"] or limits["per_workflow"] > limits["per_hour"]:
            raise BudgetError("limit-order")
        if scope == "repository_token" and limits["per_hour"] > 1000:
            raise BudgetError("repository-token-limit")
    return document


def load_budget_document(path):
    try:
        with Path(path).open("rb") as source:
            payload = source.read(MAX_DOCUMENT_BYTES + 1)
    except OSError:
        raise BudgetError("budget-unavailable")
    return validate_budget_document(_strict_json(payload))


def _validate_ledger(document, budget):
    if not _has_fields(
        document,
        ("schema_version", "complete", "repository", "round_id", "watchers", "requests"),
    ):
        raise BudgetError("ledger-schema")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise BudgetError("ledger-version")
    if document["complete"] is not True:
        raise BudgetError("ledger-incomplete")
    if type(document["repository"]) is not str or REPOSITORY.fullmatch(document["repository"]) is None:
        raise BudgetError("ledger-repository")
    if not _valid_identifier(document["round_id"]):
        raise BudgetError("ledger-round")
    watchers = document["watchers"]
    requests = document["requests"]
    if type(watchers) is not list or type(requests) is not list:
        raise BudgetError("ledger-arrays")
    if len(watchers) > 10000 or len(requests) > 100000:
        raise BudgetError("ledger-count")
    watched = {}
    for watcher in watchers:
        if not _has_fields(watcher, ("run_id", "interval_seconds")):
            raise BudgetError("watcher-entry-schema")
        run_id = watcher["run_id"]
        if not _is_integer(run_id, 1) or run_id in watched:
            raise BudgetError("watcher-run")
        interval = watcher["interval_seconds"]
        if (not _is_integer(interval, 1)
                or interval < budget["watcher"]["minimum_interval_seconds"]):
            raise BudgetError("watcher-interval")
        watched[run_id] = interval
    if requests and not watchers:
        raise BudgetError("watcher-missing")

    request_ids = set()
    run_counts = {}
    workflow_counts = {}
    hour_windows = {}
    rate_snapshots = {}
    paused_until = {}
    credential_scopes = {}
    previous_timestamp = -1
    for request in requests:
        if not _has_fields(
            request,
            ("request_id", "run_id", "workflow", "credential_scope", "credential_id",
             "timestamp", "status_code", "rate_limit"),
        ):
            raise BudgetError("request-schema")
        request_id = request["request_id"]
        if not _valid_identifier(request_id) or request_id in request_ids:
            raise BudgetError("request-id")
        request_ids.add(request_id)
        run_id = request["run_id"]
        if not _is_integer(run_id, 1) or run_id not in watched:
            raise BudgetError("request-run")
        workflow = request["workflow"]
        if not _valid_identifier(workflow):
            raise BudgetError("request-workflow")
        scope = request["credential_scope"]
        if type(scope) is not str or scope not in budget["credentials"]:
            raise BudgetError("request-credential")
        credential_id = request["credential_id"]
        if not _valid_identifier(credential_id):
            raise BudgetError("request-credential-id")
        existing_scope = credential_scopes.get(credential_id)
        if existing_scope is not None and existing_scope != scope:
            raise BudgetError("credential-scope-changed")
        credential_scopes[credential_id] = scope
        timestamp = request["timestamp"]
        if not _is_integer(timestamp, 1) or timestamp < previous_timestamp:
            raise BudgetError("request-time")
        previous_timestamp = timestamp
        status = request["status_code"]
        if not _is_integer(status, 100) or status > 599:
            raise BudgetError("request-status")
        headers = request["rate_limit"]
        if not _has_fields(headers, ("resource", "limit", "remaining", "reset")):
            raise BudgetError("rate-limit-schema")
        resource = headers["resource"]
        if not _valid_identifier(resource):
            raise BudgetError("rate-limit-resource")
        limit = headers["limit"]
        remaining = headers["remaining"]
        reset = headers["reset"]
        if (not _is_integer(limit, 1) or not _is_integer(remaining)
                or remaining > limit or not _is_integer(reset, 1)
                or reset <= timestamp or reset > timestamp + budget["window_seconds"]):
            raise BudgetError("rate-limit-value")

        repository = document["repository"]
        run_key = (repository, run_id, credential_id)
        workflow_key = (repository, document["round_id"], workflow, credential_id)
        run_counts[run_key] = run_counts.get(run_key, 0) + 1
        workflow_counts[workflow_key] = workflow_counts.get(workflow_key, 0) + 1
        scope_limits = budget["credentials"][scope]
        if run_counts[run_key] > scope_limits["per_run"]:
            raise BudgetError("run-budget-exceeded")
        if workflow_counts[workflow_key] > scope_limits["per_workflow"]:
            raise BudgetError("workflow-budget-exceeded")
        credential_key = (repository, credential_id)
        window = hour_windows.setdefault(credential_key, deque())
        while window and window[0] <= timestamp - budget["window_seconds"]:
            window.popleft()
        window.append(timestamp)
        if len(window) > scope_limits["per_hour"]:
            raise BudgetError("hour-budget-exceeded")

        rate_key = (repository, credential_id, resource)
        previous = rate_snapshots.get(rate_key)
        if previous is not None:
            previous_reset, previous_limit, previous_remaining = previous
            if reset < previous_reset or (reset == previous_reset and limit != previous_limit):
                raise BudgetError("rate-limit-changed")
            if reset != previous_reset and timestamp < previous_reset:
                raise BudgetError("rate-window-changed-early")
            if reset == previous_reset and remaining > previous_remaining:
                raise BudgetError("rate-limit-increased")
        rate_snapshots[rate_key] = (reset, limit, remaining)

        pause_key = (repository, credential_id)
        resume_at = paused_until.get(pause_key)
        if resume_at is not None and timestamp < resume_at:
            raise BudgetError("request-before-reset")
        if resume_at is not None and timestamp >= resume_at:
            del paused_until[pause_key]
        if status == 403:
            if reset <= timestamp:
                raise BudgetError("reset-not-future")
            paused_until[pause_key] = reset

    return {
        "requests": len(requests),
        "runs": len({key[1] for key in run_counts}),
        "workflows": len({key[2] for key in workflow_counts}),
        "resume_at": tuple(sorted(set(paused_until.values()))),
    }


def check_api_budget(ledger, budget):
    validated_budget = validate_budget_document(budget)
    return _validate_ledger(ledger, validated_budget)


def check_api_budget_files(ledger_path, budget_path):
    budget = load_budget_document(budget_path)
    try:
        with Path(ledger_path).open("rb") as source:
            payload = source.read(MAX_DOCUMENT_BYTES + 1)
    except OSError:
        raise BudgetError("ledger-unavailable")
    return check_api_budget(_strict_json(payload), budget)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--budgets", required=True)
    arguments = parser.parse_args(argv)
    try:
        report = check_api_budget_files(arguments.ledger, arguments.budgets)
    except BudgetError as error:
        print("api-budget=refused code=" + error.code)
        return 1
    if report["resume_at"]:
        print(
            "api-budget=paused requests=%d runs=%d workflows=%d pending-resets=%d resume-after=%d"
            % (report["requests"], report["runs"], report["workflows"],
               len(report["resume_at"]), max(report["resume_at"]))
        )
        return 2
    print(
        "api-budget=within-limit requests=%d runs=%d workflows=%d pending-resets=0"
        % (report["requests"], report["runs"], report["workflows"])
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
