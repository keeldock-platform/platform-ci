"""Terminal control-wave audit for the exact 18-job graph."""

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "confinement"))

from macos_public_audit import GitHubAPI, _read_annotations
import permit
import public_audit


REPOSITORY = "keeldock-platform/platform-ci"
REPOSITORY_ID = 1430960557
WORKFLOW_PATH = ".github/workflows/public-policy.yml"
CONTROL_RUNNERS = ("ubuntu-24.04", "macos-15", "windows-2025")
RUN_JOB = "control-audit"
CONTROL_STATUS_CONTEXT = "keeldock/control-verified"
CONTROL_STATUS_DESCRIPTION = "18-job source-free control verified"
CONTROL_STATUS_CREATOR = "github-actions[bot]"
SYNTHETIC_JOB = "devlane-synthetic / devlane-synthetic"
MAX_MACOS_CAPACITY_NOTICES = 64
CONTROL_JOB_NAMES = frozenset(
    ["policy-" + runner for runner in CONTROL_RUNNERS]
    + ["node-lock-smoke / node-lock-smoke-" + runner for runner in CONTROL_RUNNERS]
    + ["linux-confinement / linux-policy", "linux-confinement / linux-harness"]
    + ["windows-confinement / windows-policy", "windows-confinement / windows-native-synthetic"]
    + ["windows-handoff-synthetic / handoff-unit-" + runner for runner in ("ubuntu-24.04", "windows-2025")]
    + ["development-feedback-smoke / feedback-smoke-producer " + runner for runner in CONTROL_RUNNERS]
    + ["development-feedback-smoke / feedback-smoke-audit"]
    + [SYNTHETIC_JOB, RUN_JOB]
)
assert len(CONTROL_JOB_NAMES) == 18
DECIMAL = re.compile(r"[1-9][0-9]{0,18}\Z")
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
OPAQUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,63}\Z")
SOURCE_FREE_BRANCH_REF = re.compile(r"refs/heads/[A-Za-z0-9._/-]{1,200}\Z")
"""Any branch may host the source-free control (it holds no secret and saves no durable evidence off main), so a pull request head can be checked before it merges."""
MARKER = re.compile(
    rb"(?m)^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z )?"
    rb"KD-PLATFORM-CONTROL schema=1 wave-id=([A-Za-z0-9][A-Za-z0-9_-]{7,63}) "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) attempt=1 runner=(Linux|macOS|Windows)$"
)
CONTROL_AUDIT_FINAL_STEPS = (
    "Fetch public control and validate manual protected-branch dispatch",
    "Audit the exact 18-job control graph",
    "Save exact source-free control evidence",
)
SYNTHETIC_STEP_NAMES = (
    "Fetch public control and validate protected-branch dispatch",
    "Prepare hosted Linux isolation state",
    "Reserve work time for pinned Node action",
    "Set up pinned Node toolchain",
    "Install fixed Rust acceptance toolchain",
    "Claim a synthetic bundle permit",
    "Reserve work time for permit cache save",
    "Save the synthetic permit through the Actions cache",
    "Discard the local synthetic permit",
    "Reserve work time for permit cache restore",
    "Restore the synthetic permit with the encrypted-lane path and key shape",
    "Verify the restored permit and refuse a second claim",
    "Run full source-free production-path acceptance",
    "Probe the loopback-only Linux network boundary",
)
POLICY_STEP_NAMES = (
    "Fetch public control and validate manual protected-branch dispatch",
    "Run source-free platform policy and candidate checks",
)
NODE_LOCK_STEP_NAMES = (
    "Fetch public candidate", "Set up the pinned Node runtime", "Run source-free helper tests",
    "Post Set up the pinned Node runtime",
)
LINUX_POLICY_STEP_NAMES = ("Fetch public candidate", "Run unprivileged source-free checks")
LINUX_HARNESS_STEP_NAMES = ("Fetch public candidate", "Run Linux namespace harness fixtures")
WINDOWS_POLICY_STEP_NAMES = ("Fetch public candidate", "Run unprivileged source-free checks")
WINDOWS_POLICY_JOB = "windows-confinement / windows-policy"
_WINDOWS_ACL_LIVE_LINE = re.compile(
    r"windows_acl_live=(pass cases=2|skipped platform|failed stage="
    r"(powershell-missing|fixture-create|protected-run|protected-parse|extra-writer-exit) "
    r"exit=(0|[1-9]|1[0-5]|other) stderr=(present|empty) "
    r"stdout=(empty|multiple-lines|not-sid|bom-or-whitespace|sid))\Z"
)
WINDOWS_NATIVE_STEP_NAMES = (
    "Fetch public candidate", "Parse every PowerShell file under kit", "Compile native confinement module",
)
HANDOFF_STEP_NAMES = (
    "Fetch public candidate", "Run handoff scanner and synthetic tree tests", "Generate local synthetic tree",
)
FEEDBACK_PRODUCER_STEP_NAMES = (
    "Fetch public control", "Set up the pinned Node runtime", "Run source-free feedback tests",
    "Create and round-trip encrypted fixture", "Upload the single macOS ciphertext fixture",
    "Record uploader identity", "Remove local encrypted fixture", "Post Set up the pinned Node runtime",
)
FEEDBACK_AUDIT_STEP_NAMES = ("Fetch public control", "Audit producer checks and uploaded ciphertext")
CONTROL_STEP_NAMES = {}
for _runner in CONTROL_RUNNERS:
    CONTROL_STEP_NAMES["policy-" + _runner] = POLICY_STEP_NAMES
    CONTROL_STEP_NAMES["node-lock-smoke / node-lock-smoke-" + _runner] = NODE_LOCK_STEP_NAMES
    CONTROL_STEP_NAMES["development-feedback-smoke / feedback-smoke-producer " + _runner] = FEEDBACK_PRODUCER_STEP_NAMES
CONTROL_STEP_NAMES.update({
    "linux-confinement / linux-policy": LINUX_POLICY_STEP_NAMES,
    "linux-confinement / linux-harness": LINUX_HARNESS_STEP_NAMES,
    "windows-confinement / windows-policy": WINDOWS_POLICY_STEP_NAMES,
    "windows-confinement / windows-native-synthetic": WINDOWS_NATIVE_STEP_NAMES,
    "windows-handoff-synthetic / handoff-unit-ubuntu-24.04": HANDOFF_STEP_NAMES,
    "windows-handoff-synthetic / handoff-unit-windows-2025": HANDOFF_STEP_NAMES,
    "development-feedback-smoke / feedback-smoke-audit": FEEDBACK_AUDIT_STEP_NAMES,
    "devlane-synthetic / devlane-synthetic": SYNTHETIC_STEP_NAMES + ("Post Set up pinned Node toolchain",),
})


def _step_rows(job):
    rows = job.get("steps")
    if type(rows) is not list or any(type(step) is not dict for step in rows):
        _refuse()
    return [step for step in rows if step.get("name") not in ("Set up job", "Complete job")]


def _validate_child_steps(name, job, *, require_main=True):
    steps = _step_rows(job)
    if [step.get("name") for step in steps] != list(CONTROL_STEP_NAMES[name]):
        _refuse()
    acceptance_failure = name == SYNTHETIC_JOB and job.get("conclusion") == "failure"
    for step in steps:
        skipped_feedback_upload = (
            name.startswith("development-feedback-smoke / feedback-smoke-producer ")
            and not name.endswith("macos-15")
            and step.get("name") in ("Upload the single macOS ciphertext fixture", "Record uploader identity")
        )
        skipped_control_cache = (
            name == RUN_JOB and step.get("name") == "Save exact source-free control evidence" and not require_main
        )
        expected = "skipped" if skipped_feedback_upload or skipped_control_cache else "success"
        if acceptance_failure and step.get("name") == "Run full source-free production-path acceptance":
            expected = "failure"
        elif acceptance_failure and step.get("name") == "Probe the loopback-only Linux network boundary":
            expected = "skipped"
        if step.get("status") != "completed" or step.get("conclusion") != expected:
            _refuse()


class ControlAuditRefusal(ValueError):
    STAGES = frozenset({
        "control-graph", "identity", "run-record", "job-graph", "synthetic-log",
        "policy-marker", "artifacts", "check-runs", "status-post", "internal",
    })

    def __init__(self, stage="control-graph"):
        self.stage = stage if stage in self.STAGES else "internal"
        super().__init__(self.stage)


def _refuse(stage="control-graph"):
    raise ControlAuditRefusal(stage)


def _under_stage(stage, function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except ControlAuditRefusal:
        raise ControlAuditRefusal(stage) from None


def control_identity(env):
    required = ("CI_REPOSITORY", "CI_REPOSITORY_ID", "CI_REF", "CI_SHA", "CI_SERVER_URL",
                "CI_EVENT_NAME", "CI_CONTROL_WAVE_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_TOKEN")
    if any(type(env.get(key)) is not str or not env.get(key) for key in required):
        _refuse()
    if (env["CI_REPOSITORY"] != REPOSITORY or env["CI_REPOSITORY_ID"] != str(REPOSITORY_ID)
            or not SOURCE_FREE_BRANCH_REF.fullmatch(env["CI_REF"]) or env["CI_SERVER_URL"] != "https://github.com"
            or env["CI_EVENT_NAME"] != "workflow_dispatch" or not SHA40.fullmatch(env["CI_SHA"])
            or not OPAQUE.fullmatch(env["CI_CONTROL_WAVE_ID"])
            or not DECIMAL.fullmatch(env["GITHUB_RUN_ID"]) or env["GITHUB_RUN_ATTEMPT"] != "1"):
        _refuse()
    return {
        "repository": REPOSITORY, "repository_id": REPOSITORY_ID,
        "ref": env["CI_REF"], "control_sha": env["CI_SHA"],
        "event": env["CI_EVENT_NAME"], "wave_id": env["CI_CONTROL_WAVE_ID"],
        "run_id": env["GITHUB_RUN_ID"], "attempt": 1,
    }


def validate_run_record(run, identity):
    if type(run) is not dict:
        _refuse()
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (str(run.get("id")) != identity["run_id"] or run.get("path") != WORKFLOW_PATH
            or run.get("display_title") != "public control=" + identity["wave_id"]
            or run.get("head_branch") != identity["ref"].removeprefix("refs/heads/") or run.get("head_sha") != identity["control_sha"]
            or run.get("event") != "workflow_dispatch" or run.get("run_attempt") != 1
            or run.get("status") not in ("queued", "in_progress") or run.get("conclusion") is not None
            or type(repository) is not dict or repository.get("full_name") != REPOSITORY
            or repository.get("id") != REPOSITORY_ID
            or type(head_repository) is not dict or head_repository.get("full_name") != REPOSITORY
            or head_repository.get("id") != REPOSITORY_ID):
        _refuse()


def validate_jobs(jobs, identity):
    if type(jobs) is not list or len(jobs) != 18:
        _refuse()
    by_name = {}
    for job in jobs:
        if type(job) is not dict or type(job.get("name")) is not str or job["name"] in by_name:
            _refuse()
        if (job.get("run_id") != int(identity["run_id"]) or job.get("run_attempt") != 1
                or job.get("head_sha") != identity["control_sha"]
                or type(job.get("id")) is not int or job["id"] < 1):
            _refuse()
        by_name[job["name"]] = job
    if set(by_name) != CONTROL_JOB_NAMES:
        _refuse()
    for name, job in by_name.items():
        if name != RUN_JOB:
            _validate_child_steps(name, job, require_main=identity["ref"] == "refs/heads/main")
        if name == RUN_JOB:
            if job.get("status") != "in_progress" or job.get("conclusion") is not None:
                _refuse()
            steps = [step for step in job.get("steps", []) if step.get("name") not in ("Set up job", "Complete job")]
            if ([step.get("name") for step in steps] != list(CONTROL_AUDIT_FINAL_STEPS)
                    or steps[0].get("status") != "completed" or steps[0].get("conclusion") != "success"
                    or steps[1].get("status") != "in_progress" or steps[1].get("conclusion") is not None):
                _refuse()
            not_reached = steps[2].get("status") in ("pending", "queued") and steps[2].get("conclusion") is None
            if identity["ref"] == "refs/heads/main":
                if not not_reached:
                    _refuse()
            elif not (not_reached or (steps[2].get("status") == "completed"
                                      and steps[2].get("conclusion") == "skipped")):
                _refuse()
        elif (name == SYNTHETIC_JOB and job.get("status") == "completed"
              and job.get("conclusion") == "failure"):
            pass
        elif job.get("status") != "completed" or job.get("conclusion") != "success":
            _refuse()
        url = job.get("check_run_url")
        parsed = urlsplit(url) if type(url) is str else None
        if (parsed is None or parsed.scheme != "https" or parsed.netloc != "api.github.com"
                or not re.fullmatch(r"/repos/keeldock-platform/platform-ci/check-runs/[1-9][0-9]{0,18}", parsed.path)
                or parsed.query or parsed.fragment):
            _refuse()
    return by_name


FEEDBACK_AUDIT_JOB = "development-feedback-smoke / feedback-smoke-audit"
NOT_STARTED = ("queued", "waiting", "pending", "requested")
TERMINAL_CONCLUSIONS = frozenset(
    {"success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral"}
)
FEEDBACK_PHASE_REQUIRED = frozenset(
    ["development-feedback-smoke / feedback-smoke-producer " + runner for runner in CONTROL_RUNNERS]
    + [FEEDBACK_AUDIT_JOB]
)


def validate_feedback_phase(jobs, identity):
    """Graph state while the composed feedback auditor itself is running.

    `control-audit` needs every child, including the feedback auditor, so it
    can only be unstarted here (or not yet materialised). Children that do not
    depend on the feedback auditor may be queued, running or finished; whether
    they succeed is the final control audit's decision, not this phase's.
    """
    if type(jobs) is not list or not 4 <= len(jobs) <= 18:
        _refuse()
    by_name = {}
    for job in jobs:
        if (type(job) is not dict or type(job.get("name")) is not str or job["name"] in by_name
                or job["name"] not in CONTROL_JOB_NAMES
                or job.get("run_id") != int(identity["run_id"]) or job.get("run_attempt") != 1
                or job.get("head_sha") != identity["control_sha"]
                or type(job.get("id")) is not int or job["id"] < 1):
            _refuse()
        by_name[job["name"]] = job
    if not FEEDBACK_PHASE_REQUIRED <= set(by_name):
        _refuse()
    ids = [job["id"] for job in by_name.values()]
    if len(ids) != len(set(ids)):
        _refuse()
    for name, job in by_name.items():
        steps = _step_rows(job)
        status, conclusion = job.get("status"), job.get("conclusion")
        if name == FEEDBACK_AUDIT_JOB:
            if ([step.get("name") for step in steps] != list(FEEDBACK_AUDIT_STEP_NAMES)
                    or status != "in_progress" or conclusion is not None
                    or steps[0].get("status") != "completed" or steps[0].get("conclusion") != "success"
                    or steps[1].get("status") != "in_progress" or steps[1].get("conclusion") is not None):
                _refuse()
        elif name == RUN_JOB:
            if (status not in NOT_STARTED or conclusion is not None
                    or any(step.get("status") not in NOT_STARTED or step.get("conclusion") is not None
                           for step in steps)):
                _refuse()
        elif name in FEEDBACK_PHASE_REQUIRED:
            _validate_child_steps(name, job, require_main=identity["ref"] == "refs/heads/main")
            if status != "completed" or conclusion != "success":
                _refuse()
        elif status in NOT_STARTED + ("in_progress",):
            if conclusion is not None:
                _refuse()
        elif status == "completed":
            if conclusion not in TERMINAL_CONCLUSIONS:
                _refuse()
            if conclusion == "success":
                _validate_child_steps(name, job, require_main=identity["ref"] == "refs/heads/main")
        else:
            _refuse()
        url = job.get("check_run_url")
        parsed = urlsplit(url) if type(url) is str else None
        if (parsed is None or parsed.scheme != "https" or parsed.netloc != "api.github.com"
                or not re.fullmatch(r"/repos/keeldock-platform/platform-ci/check-runs/[1-9][0-9]{0,18}", parsed.path)
                or parsed.query or parsed.fragment):
            _refuse()
    return by_name


def validate_terminal_control_run(run, jobs, control_run_id, control_sha, *, require_main=True,
                                  expected_wave_id=None):
    repository = run.get("repository") if type(run) is dict else None
    head_repository = run.get("head_repository") if type(run) is dict else None
    head_branch = run.get("head_branch") if type(run) is dict else None
    valid_branch = head_branch == "main" if require_main else (
        type(head_branch) is str and re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", head_branch) is not None)
    if (type(run) is not dict or str(run.get("id")) != str(control_run_id)
            or run.get("path") != WORKFLOW_PATH or run.get("event") != "workflow_dispatch"
            or (expected_wave_id is not None
                and (type(expected_wave_id) is not str or not OPAQUE.fullmatch(expected_wave_id)
                     or run.get("display_title") != "public control=" + expected_wave_id))
            or run.get("head_sha") != control_sha or run.get("run_attempt") != 1
            or run.get("status") != "completed" or run.get("conclusion") != "success" or not valid_branch
            or type(repository) is not dict or repository.get("full_name") != REPOSITORY
            or repository.get("id") != REPOSITORY_ID
            or type(head_repository) is not dict or head_repository.get("full_name") != REPOSITORY
            or head_repository.get("id") != REPOSITORY_ID):
        _refuse()
    if type(jobs) is not list or len(jobs) != 18:
        _refuse()
    by_name = {}
    ids = set()
    for job in jobs:
        if (type(job) is not dict or type(job.get("name")) is not str or job["name"] in by_name
                or job.get("run_id") != int(control_run_id) or job.get("run_attempt") != 1
                or job.get("head_sha") != control_sha or job.get("status") != "completed"
                or job.get("conclusion") != "success" or type(job.get("id")) is not int
                or job["id"] < 1 or job["id"] in ids):
            _refuse()
        by_name[job["name"]] = job
        ids.add(job["id"])
    if set(by_name) != CONTROL_JOB_NAMES:
        _refuse()
    for name, job in by_name.items():
        if name == RUN_JOB:
            continue
        _validate_child_steps(name, job, require_main=require_main)
    audit_steps = [step for step in by_name[RUN_JOB].get("steps", [])
                   if step.get("name") not in ("Set up job", "Complete job")]
    audit_names = [step.get("name") for step in audit_steps]
    if audit_names != list(CONTROL_AUDIT_FINAL_STEPS):
        _refuse()
    if (any(step.get("status") != "completed" or step.get("conclusion") != "success" for step in audit_steps[:2])
            or require_main and (audit_steps[2].get("status") != "completed" or audit_steps[2].get("conclusion") != "success")
            or not require_main and (audit_steps[2].get("status") != "completed" or audit_steps[2].get("conclusion") != "skipped")):
        _refuse()
    return by_name


def validate_control_marker(log, identity, expected_runner):
    if type(log) is not bytes or len(log) > 32 * 1024 * 1024:
        _refuse()
    log = log.replace(b"\r\n", b"\n")
    for sequence in public_audit.ANSI_SGR:
        log = log.replace(sequence, b"")
    if any(byte < 32 and byte != 10 or byte == 127 for byte in log) or b"\x1b" in log:
        _refuse()
    matches = list(MARKER.finditer(log))
    if len(matches) != 1:
        _refuse()
    wave_id, control_sha, run_id, runner = matches[0].groups()
    if (wave_id.decode("ascii") != identity["wave_id"]
            or control_sha.decode("ascii") != identity["control_sha"]
            or run_id.decode("ascii") != identity["run_id"]
            or runner.decode("ascii") != expected_runner):
        _refuse()


def windows_acl_live_outcome(log):
    if type(log) is not bytes or len(log) > 32 * 1024 * 1024:
        _refuse()
    log = log.replace(b"\r\n", b"\n")
    for sequence in public_audit.ANSI_SGR:
        log = log.replace(sequence, b"")
    matches = []
    for row in log.splitlines():
        try:
            line = row.decode("ascii", "strict")
        except UnicodeError:
            continue
        line = public_audit.TIME_PREFIX.sub("", line, count=1)
        if not line.startswith("windows_acl_live="):
            continue
        match = _WINDOWS_ACL_LIVE_LINE.fullmatch(line)
        if match is None:
            _refuse()
        value = match.group(1)
        matches.append("pass" if value == "pass cases=2" else
                       "skipped" if value == "skipped platform" else "failed")
    if len(matches) != 1:
        _refuse()
    return matches[0]


def validate_windows_policy_log(log):
    if windows_acl_live_outcome(log) != "pass":
        _refuse()


def validate_artifacts(value, identity):
    expected_name = "development-feedback-smoke-" + identity["run_id"] + "-1"
    if (type(value) is not dict or value.get("total_count") != 1
            or type(value.get("artifacts")) is not list or len(value["artifacts"]) != 1):
        _refuse()
    artifact = value["artifacts"][0]
    workflow_run = artifact.get("workflow_run") if type(artifact) is dict else None
    if (type(artifact) is not dict or type(artifact.get("id")) is not int or artifact["id"] < 1
            or artifact.get("name") != expected_name or artifact.get("expired") is not False
            or type(artifact.get("size_in_bytes")) is not int or artifact["size_in_bytes"] < 1
            or type(workflow_run) is not dict or workflow_run.get("id") != int(identity["run_id"])
            or workflow_run.get("head_sha") != identity["control_sha"]):
        _refuse()


def _macos_capacity_notice(control_sha):
    return {
        "annotation_level": "notice",
        "blob_href": f"https://github.com/{REPOSITORY}/blob/{control_sha}/.github",
        "end_column": None,
        "end_line": 1,
        "message": "Due to capacity constraints, jobs targeting macOS arm64 runners may experience longer queue times.",
        "path": ".github",
        "raw_details": "",
        "start_column": None,
        "start_line": 1,
        "title": "",
    }


def validate_control_annotations(job_name, control_sha, count, annotations):
    if type(count) is not int or count < 0 or type(annotations) is not list or len(annotations) != count:
        _refuse()
    macos_capacity_jobs = {
        "policy-macos-15",
        "node-lock-smoke / node-lock-smoke-macos-15",
        "development-feedback-smoke / feedback-smoke-producer macos-15",
    }
    if job_name in macos_capacity_jobs:
        if count > MAX_MACOS_CAPACITY_NOTICES or any(
                item != _macos_capacity_notice(control_sha) for item in annotations):
            _refuse()
    elif annotations:
        _refuse()


def validate_synthetic_log(log, identity, *, failed_acceptance=False):
    try:
        public_audit.validate_job_log_surface(
            log, "devlane-synthetic", {
                "run_id": identity["run_id"], "control_sha": identity["control_sha"], "ref": identity["ref"],
                "wave_id": identity.get("wave_id"),
            },
            completed=True, workflow="synthetic", failed_acceptance=failed_acceptance)
    except public_audit.AuditRefusal:
        _refuse()


def run_audit(api, identity):
    prefix = "/repos/" + REPOSITORY + "/actions/runs/" + identity["run_id"]
    run, _ = api.json(prefix)
    _under_stage("run-record", validate_run_record, run, identity)
    value, headers = api.json(prefix + "/jobs?filter=all&per_page=100&page=1")
    if (type(value) is not dict or value.get("total_count") != 18 or type(value.get("jobs")) is not list
            or len(value["jobs"]) != 18 or headers.get("Link")):
        _refuse("job-graph")
    jobs = _under_stage("job-graph", validate_jobs, value["jobs"], identity)
    """Hosted-output assertion: the real synthetic job log must satisfy the same closed contract the encrypted-lane auditor applies, so any drift in what GitHub actually prints (scaffolding, cache action, setup action, env blocks) fails the control, never a private run."""
    synthetic_job = jobs[SYNTHETIC_JOB]
    _under_stage("synthetic-log", validate_synthetic_log,
        api.log_text(synthetic_job["id"]), identity,
        failed_acceptance=synthetic_job["conclusion"] == "failure",
    )
    windows_policy_job = jobs[WINDOWS_POLICY_JOB]
    _under_stage("windows-policy-log", validate_windows_policy_log,
                 api.log_text(windows_policy_job["id"]))
    for runner in CONTROL_RUNNERS:
        name = "policy-" + runner
        log = api.log_text(jobs[name]["id"])
        expected_os = {"ubuntu-24.04": "Linux", "macos-15": "macOS", "windows-2025": "Windows"}[runner]
        _under_stage("policy-marker", validate_control_marker, log, identity, expected_os)
    artifacts, _ = api.json(prefix + "/artifacts?per_page=100&page=1")
    _under_stage("artifacts", validate_artifacts, artifacts, identity)
    for job in jobs.values():
        def check_job(check_job=job):
            check_id = int(check_job["check_run_url"].rsplit("/", 1)[1])
            check, _ = api.json("/repos/%s/check-runs/%d" % (REPOSITORY, check_id))
            output = check.get("output") if type(check) is dict else None
            if (type(check) is not dict or check.get("id") != check_id
                    or check.get("head_sha") != identity["control_sha"]
                    or check.get("status") != check_job.get("status")
                    or type(output) is not dict or type(output.get("annotations_count")) is not int):
                _refuse("check-runs")
            if check_job["name"] == RUN_JOB and check_job.get("status") == "in_progress":
                return
            annotations = _read_annotations(api, "/repos/%s/check-runs/%d/annotations" % (REPOSITORY, check_id))
            validate_control_annotations(
                check_job["name"], identity["control_sha"], output["annotations_count"], annotations,
            )
        _under_stage("check-runs", check_job)


def post_control_status(api, identity):
    target_url = "https://github.com/" + REPOSITORY + "/actions/runs/" + identity["run_id"]
    payload = json.dumps({
        "context": CONTROL_STATUS_CONTEXT,
        "state": "success",
        "description": CONTROL_STATUS_DESCRIPTION,
        "target_url": target_url,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPOSITORY + "/statuses/" + identity["control_sha"],
        data=payload,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + api._token,
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "public-control-audit",
            "Accept-Encoding": "identity",
        },
        method="POST",
    )
    try:
        response = api._opener.open(request, timeout=30)
    except Exception:
        _refuse("status-post")
    try:
        if response.status != 201:
            _refuse("status-post")
        content_type = response.headers.get_content_type()
        if content_type != "application/json" or response.headers.get("Content-Encoding", "identity").lower() != "identity":
            _refuse("status-post")
        raw = response.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            _refuse("status-post")
    except ControlAuditRefusal:
        raise
    except Exception:
        _refuse("status-post")
    finally:
        try:
            response.close()
        except Exception:
            pass
    status_url = "https://api.github.com/repos/" + REPOSITORY + "/statuses/" + identity["control_sha"]
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _refuse("status-post")
    creator = result.get("creator") if type(result) is dict else None
    if (type(result) is not dict or result.get("url") != status_url
            or result.get("context") != CONTROL_STATUS_CONTEXT or result.get("state") != "success"
            or result.get("description") != CONTROL_STATUS_DESCRIPTION or result.get("target_url") != target_url
            or type(creator) is not dict or creator.get("login") != CONTROL_STATUS_CREATOR
            or creator.get("type") != "Bot"):
        _refuse("status-post")


def main():
    try:
        identity = _under_stage("identity", control_identity, os.environ)
        api = GitHubAPI(os.environ["GITHUB_TOKEN"])
        run_audit(api, identity)
        if identity["ref"] == "refs/heads/main":
            evidence_path = os.environ.get("DEVLANE_CONTROL_EVIDENCE_PATH")
            if type(evidence_path) is not str or not evidence_path:
                _refuse()
            permit.create_control(evidence_path, identity["control_sha"], identity["run_id"], identity["ref"])
        post_control_status(api, identity)
        print("control_audit=accepted jobs=18 synthetic_artifacts=1")
        return 0
    except ControlAuditRefusal as error:
        print("control_audit=refused stage=" + error.stage)
        return 1
    except Exception:
        print("control_audit=refused stage=internal")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
