"""Exact two-job, read-only audit for one encrypted development wave."""

import os
import re
import sys
import json
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "confinement"))

from macos_public_audit import (
    API_ORIGIN,
    MAX_LOG_BYTES,
    GitHubAPI,
    _fetch_artifacts,
    _fetch_cache_entries,
    _read_annotations,
    cache_inventory_digest,
)
import diagnostic_contract


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "keeldock-platform/platform-ci"
REPOSITORY_ID = 1430960557
WORKFLOW_PATH = ".github/workflows/devlane-encrypted.yml"
RUN_JOB = "devlane-encrypted-run"
DECRYPT_ENVIRONMENT = "devlane-decrypt"
AUDIT_JOB = "devlane-encrypted-audit"
STEP_NAMES = (
    "Fetch public control and validate dispatch",
    "Reserve work time for control evidence cache restore",
    "Restore exact source-free control evidence",
    "Verify exact source-free control evidence",
    "Reserve work time for initial permit cache restore",
    "Restore one-run bundle permit",
    "Claim this bundle for one run before decryption",
    "Reserve work time for permit cache save",
    "Save one-run bundle permit",
    "Discard local permit copy before persisted verification",
    "Reserve work time for persisted permit cache restore",
    "Restore and verify persisted one-run permit",
    "Verify permit and emit bound dispatch marker",
    "Fetch ciphertext and sanitized dependency projection",
    "Install pinned Rust toolchain",
    "Prepare dependencies before the cut",
    "Prove public connectivity before the cut",
    "Cut network and start the isolated supervisor",
    "Probe isolation before decryption",
    "Decrypt authenticated bundle",
    "Execute offline profile and filter public summary",
    "Shred runner-local workspace",
)
AUDIT_STEP_NAMES = (
    "Fetch public control and validate dispatch",
    "Audit exact two-job graph and public surfaces",
)
PERMIT_MARKER = re.compile(
    rb"(?m)^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z )?"
    rb"devlane_permit=consumed run-id=([1-9][0-9]{0,18}) run-attempt=1$"
)
DISPATCH_MARKER = re.compile(
    rb"(?m)^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z )?"
    rb"KD-DEVLANE-DISPATCH schema=1 wave-id=([A-Za-z0-9][A-Za-z0-9_-]{7,63}) "
    rb"bundle-id=([A-Za-z0-9][A-Za-z0-9_-]{7,63}) control-sha=([a-f0-9]{40,64}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=1$"
)
DECIMAL = re.compile(r"[1-9][0-9]{0,18}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
TIME_PREFIX = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z ")
PUBLIC_FILE_ID = re.compile(r"file_[0-9]{4,6}\Z")
PUBLIC_TEST_ID = re.compile(r"case_[0-9]{4,6}\Z")
PUBLIC_SUITE_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
PUBLIC_FRAME_ID = re.compile(r"frame_[0-9]{4,6}\Z")
RUNNER_HOME = chr(47) + "home" + chr(47) + "runner"
TEMP = RUNNER_HOME + "/work/_temp"
HOSTED_TOOL_CACHE = "/opt/hostedtoolcache/node/24.22.1/x64"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
LOG_MARKER = chr(35) * 2
PROVIDER_GROUPS = frozenset((
    "Runner Image Provisioner", "Operating System", "Runner Image", "GITHUB_TOKEN Permissions", "Secret source",
))
"""Text the hosted runner itself prints while the job is being set up, before any step (and so any workload) has executed. It is accepted only inside that phase."""
PROVIDER_LINE = re.compile(r"[A-Za-z0-9 ._:/@%()+,='-]{1,240}\Z")
POST_JOB_LINE = re.compile(r"Cleaning up orphan processes\Z")
ENVIRONMENT_LINE = re.compile(r"(?:Deployment )?[Ee]nvironment: " + re.escape(DECRYPT_ENVIRONMENT) + r"\Z")
"""Provider scaffolding that names a deployment environment: only the one reviewed decryption environment, and only for the encrypted job."""
PUBLIC_CODES = frozenset({
    "TS1005", "TS2322", "TS2339", "TS2345", "TS2551", "TS7006", "TS2307", "TS2688",
    "E0001", "E0002", "E0277", "E0308", "E0425", "E0432", "E0599", "E0609",
    "DEVLANE_FAILURE",
})
REFUSAL_LINE = re.compile(
    r"(?:devlane_refusal|devlane_supervisor_refusal|dependency_preparation_refusal|network_probe_refusal)"
    r"=(?:[a-z0-9-]{1,64}|node-snapshot-manifest-invalid:"
    r"(?:link-row-path|source-row-kind|manifest-open|manifest-metadata|manifest-race|"
    r"manifest-missing|manifest-shape|manifest-digest|unlisted-site))\Z"
)
def cache_line_patterns(key):
    """Output lines of the pinned cache actions, bound to the one key the step may use."""
    escaped = re.escape(key)
    return (
        re.compile(r"Cache hit for: " + escaped + r"\Z"),
        re.compile(r"Cache restored from key: " + escaped + r"\Z"),
        re.compile(r"Cache restored successfully\Z"),
        re.compile(r"Cache saved with key: " + escaped + r"\Z"),
        re.compile(r"Cache saved successfully\Z"),
        re.compile(r"Cache not found for input keys: " + escaped + r"\Z"),
        re.compile(r"Cache Size: ~[0-9]+ MB \([0-9]+ B\)\Z"),
        re.compile(r"(?:Received|Sent) [0-9]+ of [0-9]+ \([0-9.]+%\), [0-9.]+ MBs/sec\Z"),
        re.compile(r"(?:" + LOG_MARKER + r")?\[command\]/usr/bin/tar (?:--posix -cf cache\.tzst|-xf " + re.escape(TEMP) + "/" + UUID
                   + r"/cache\.tzst)(?: [A-Za-z0-9_./=:+ -]{0,300})?\Z"),
    )


NODE_LINES = (
    re.compile(r"Found in cache @ " + re.escape(HOSTED_TOOL_CACHE) + r"\Z"),
    re.compile(r"Attempting to download 24\.22\.1\.\.\.\Z"),
    re.compile(r"Acquiring 24\.22\.1 - x64 from https://github\.com/actions/node-versions/releases/download/"
               r"24\.22\.1-[0-9]+/node-24\.22\.1-linux-x64\.tar\.gz\Z"),
    re.compile(r"Extracting \.\.\.\Z"),
    re.compile(r"Adding to the cache \.\.\.\Z"),
    re.compile(r"Successfully cached node to " + re.escape(HOSTED_TOOL_CACHE) + r"\Z"),
    re.compile(r"Added node to the tool cache\Z"),
    re.compile(r"(?:" + LOG_MARKER + r")?\[command\]/usr/bin/tar xz --strip 1 --warning=no-unknown-keyword --overwrite -C "
               + re.escape(TEMP) + "/" + UUID + " -f " + re.escape(TEMP) + "/" + UUID + r"\Z"),
    re.compile(r"Environment details\Z"),
    re.compile(r"(?:node: v24\.22\.1|npm: 11\.19\.1|yarn: [0-9]+\.[0-9]+\.[0-9]+)\Z"),
    re.compile(r"Finished\Z"),
    re.compile(r"Post job cleanup\.\Z"),
)
GITHUB_ASSET_LINE = re.compile(r"public_asset_verified=true bytes=[1-9][0-9]{0,9}\Z")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def parse_workflow(path):
    """Minimal line parser for this repository's own workflow files (two-space YAML)."""
    try:
        target = Path(path)
        lines = (target if target.is_absolute() else REPOSITORY_ROOT / target).read_text(encoding="utf-8").splitlines()
    except OSError:
        _refuse()
    jobs = {}
    job = step = None
    section = sub = None
    block_indent = None
    in_jobs = False
    for raw in lines:
        if not raw.strip():
            continue
        indent, text = _indent(raw), raw.strip()
        if indent == 0:
            in_jobs = text == "jobs:"
            job = step = section = sub = block_indent = None
            continue
        if not in_jobs:
            continue
        if block_indent is not None:
            if indent >= block_indent:
                step["run"].append(raw[block_indent:])
                continue
            block_indent = None
        if indent == 2 and text.endswith(":"):
            job = text[:-1]
            jobs[job] = {"env": {}, "steps": [], "timeout_minutes": None}
            step = section = sub = None
        elif job is None:
            continue
        elif indent == 4:
            section = text[:-1] if text.endswith(":") else None
            sub = None
            step = None
            if text.startswith("timeout-minutes: "):
                value = text[len("timeout-minutes: "):].strip()
                jobs[job]["timeout_minutes"] = int(value) if value.isdecimal() else None
            if text.startswith("environment: "):
                jobs[job]["environment"] = text[len("environment: "):].strip()
        elif section == "env" and indent == 6 and ": " in text:
            key, value = text.split(": ", 1)
            jobs[job]["env"][key] = value
        elif section == "steps" and indent == 6 and text.startswith("- name: "):
            step = {"name": text[len("- name: "):].strip(), "run": [], "uses": None,
                    "with": {}, "env": {}, "timeout_minutes": None}
            jobs[job]["steps"].append(step)
            sub = None
        elif section == "steps" and step is not None and indent == 8:
            sub = None
            if text.startswith("uses: "):
                step["uses"] = text[len("uses: "):].split()[0]
            elif text.startswith("timeout-minutes: "):
                value = text[len("timeout-minutes: "):].strip()
                step["timeout_minutes"] = int(value) if value.isdecimal() else None
            elif text == "run: |":
                block_indent = 10
            elif text.startswith("run: "):
                step["run"] = [text[len("run: "):].strip()]
            elif text in ("with:", "env:"):
                sub = text[:-1]
        elif section == "steps" and step is not None and indent == 10 and sub in ("with", "env"):
            key, _, value = text.partition(":")
            step[sub][key.strip()] = value.strip().strip('"')
    return jobs


class _Grammar:
    """The closed set of lines one reviewed workflow job may legitimately write to its log."""

    def __init__(self, workflow_path, job_key, identity, kind):
        jobs = parse_workflow(workflow_path)
        if job_key not in jobs:
            _refuse()
        self.job = jobs[job_key]
        self.environment = self.job.get("environment")
        if self.environment != (DECRYPT_ENVIRONMENT if kind == "encrypted" and job_key == RUN_JOB else None):
            _refuse()
        self.steps = self.job["steps"]
        if kind == "encrypted" and any(
                step["uses"] and step["uses"].startswith("actions/setup-node@") for step in self.steps):
            _refuse()
        self.names = [step["name"] for step in self.steps]
        self.identity = identity
        self.kind = kind
        self.script_lines = set()
        self.headers = {}
        for step in self.steps:
            if step["run"]:
                self.script_lines.update(line for line in step["run"])
                self.headers.setdefault(LOG_MARKER + "[group]Run " + step["run"][0].strip(), set()).add(step["name"])
            elif step["uses"]:
                self.headers.setdefault(LOG_MARKER + "[group]Run " + step["uses"], set()).add(step["name"])
        self.post = {"Post " + step["name"]: step for step in self.steps if step["uses"]
                     and step["uses"].startswith("actions/setup-node@")}

    def env_value_ok(self, name, value):
        identity, kind = self.identity, self.kind
        run_id = identity.get("run_id", "")
        fixed = {
            "CI_REPOSITORY": REPOSITORY, "CI_REPOSITORY_ID": str(REPOSITORY_ID),
            "CI_SERVER_URL": "https://github.com", "CI_EVENT_NAME": "workflow_dispatch",
            "CI_SHA": identity.get("control_sha"), "PYTHONDONTWRITEBYTECODE": "1",
            "CI_WORKSPACE": RUNNER_HOME + "/work/platform-ci/platform-ci",
            "CI_RUN_ID": run_id, "GITHUB_RUN_ID": run_id, "CI_RUN_ATTEMPT": "1", "GITHUB_RUN_ATTEMPT": "1",
        }
        if kind == "encrypted":
            fixed.update({
                "CI_REF": "refs/heads/main", "CI_CONTROL_RUN_ID": identity.get("control_run_id"),
                "DEVLANE_PROFILE": identity.get("profile"), "DEVLANE_WAVE_ID": identity.get("wave_id"),
                "DEVLANE_BUNDLE_ID": identity.get("bundle_id"),
                "DEVLANE_CACHE_BASELINE_SHA256": identity.get("cache_baseline_sha256"),
                "RUN_ROOT": TEMP + "/devlane-" + str(run_id),
            })
        else:
            fixed["CI_REF"] = identity.get("ref")
        if name in fixed:
            return fixed[name] is not None and value == fixed[name]
        if name in ("DEVLANE_DECRYPT_KEY", "GITHUB_TOKEN"):
            return value == "***"
        if name == "CI_REF":
            return re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]{1,200}", value) is not None
        if name in ("DEVLANE_BUNDLE_ASSET_ID", "DEVLANE_PROJECTION_ASSET_ID", "DEVLANE_BUNDLE_SIZE",
                    "DEVLANE_PROJECTION_SIZE", "DEVLANE_EXPIRES"):
            return DECIMAL.fullmatch(value) is not None
        if name in ("DEVLANE_BUNDLE_SHA256", "DEVLANE_PROJECTION_SHA256"):
            return SHA256.fullmatch(value) is not None
        return False

    def with_value_ok(self, step, key, value):
        declared = step["with"].get(key)
        if declared is None:
            return False
        if "${{" not in declared:
            return value == declared.strip('"') or (declared == "" and value == "")
        identity = self.identity
        if key == "path":
            prefix = "${{ runner.temp }}"
            suffix = declared[len(prefix):] if declared.startswith(prefix) else None
            return suffix in ("/devlane-control-evidence/permit.json", "/devlane-bundle-permit/permit.json") \
                and value == TEMP + suffix
        if key == "key":
            return value == self.expected_cache_key(step)
        return False

    def expected_cache_key(self, step):
        declared = step["with"].get("key", "")
        if "${{" not in declared:
            return declared or None
        identity = self.identity
        if self.kind == "synthetic":
            """The synthetic job uses the encrypted lane's permit key shape with a bundle id derived from its own run."""
            if declared == "devlane-permit-v1-synthetic-bundle-${{ github.run_id }}":
                return "devlane-permit-v1-synthetic-bundle-" + str(identity.get("run_id"))
            return None
        if declared == "devlane-control-v1-${{ inputs.control_run_id }}":
            return "devlane-control-v1-" + str(identity.get("control_run_id"))
        if declared == "devlane-permit-v1-${{ inputs.bundle_id }}":
            return "devlane-permit-v1-" + str(identity.get("bundle_id"))
        return None

    def step_output_ok(self, step_name, line, public_counts):
        """Fixed output lines, each bound to the step that is allowed to print it."""
        step = next((item for item in self.steps if item["name"] == step_name), None)
        uses = (step or {}).get("uses") or ""
        if uses.startswith("actions/cache/"):
            key = self.expected_cache_key(step)
            return key is not None and any(pattern.fullmatch(line) for pattern in cache_line_patterns(key))
        if uses.startswith("actions/setup-node@") or step_name.startswith("Post Set up"):
            return any(pattern.fullmatch(line) for pattern in NODE_LINES)
        exact = {
            "Fetch public control and validate dispatch": {"dispatch_context=validated"},
            "Verify exact source-free control evidence": {"devlane_permit=verify_control=pass"},
            "Claim this bundle for one run before decryption": {"devlane_permit=claim=pass"},
            "Install pinned Rust toolchain": {"rust_offline_tools=prepared"},
            "Prepare dependencies before the cut": {"dependency_preparation=complete"},
            "Prove public connectivity before the cut": {"network_positive_control=pass"},
            "Cut network and start the isolated supervisor": {"offline_supervisor=ready"},
            "Probe isolation before decryption": {"network_cut_probe=pass"},
            "Decrypt authenticated bundle": {"authenticated_decryption=pass"},
            "Shred runner-local workspace": {
                "cleanup_receipt=confirmed", "devlane_job=completed public_output=filtered cleanup=confirmed",
            },
            "Audit exact two-job graph and public surfaces": {
                "devlane_audit=accepted jobs=2 artifacts=0 cache=unchanged cleanup=confirmed",
            },
            "Claim a synthetic bundle permit": {"devlane_cache_permit=claimed"},
            "Verify the restored permit and refuse a second claim": {"devlane_cache_permit=restored-and-single-use"},
            "Run full source-free production-path acceptance": {"devlane_acceptance=pass"},
            "Probe the loopback-only Linux network boundary": {"devlane_linux_probe=pass"},
        }.get(step_name, set())
        if step_name == "Prepare dependencies before the cut" and self.identity.get("profile") == "core-rust":
            exact = exact | {"rust_offline_tools=installed"}
        if line in exact:
            public_counts[line] = public_counts.get(line, 0) + 1
            return public_counts[line] == 1
        if step_name == "Run full source-free production-path acceptance":
            if line.startswith("devlane_acceptance=refused stage="):
                stage = line.removeprefix("devlane_acceptance=refused stage=")
                if stage not in diagnostic_contract.ACCEPTANCE_FAILURE_STAGES:
                    return False
                public_counts["acceptance_refused"] = public_counts.get("acceptance_refused", 0) + 1
                public_counts["acceptance_refusal_stage"] = stage
                return public_counts["acceptance_refused"] == 1
            if self.kind == "synthetic":
                detail_stage = diagnostic_contract.acceptance_detail_stage(line)
                if (detail_stage is not None
                        and detail_stage == public_counts.get("acceptance_refusal_stage")):
                    public_counts["acceptance_detail_count"] = public_counts.get("acceptance_detail_count", 0) + 1
                    return True
                if line.startswith("devlane_acceptance_detail "):
                    return False
            return diagnostic_contract.public_preparation_diagnostic(line)
        if step_name == "Fetch ciphertext and sanitized dependency projection":
            if GITHUB_ASSET_LINE.fullmatch(line) or line == "fetch_projection_valid=true":
                return True
        if step_name == "Verify permit and emit bound dispatch marker":
            if line.startswith("devlane_permit=consumed "):
                public_counts["permit"] = public_counts.get("permit", 0) + 1
                return True
            if line.startswith("KD-DEVLANE-DISPATCH "):
                public_counts["dispatch"] = public_counts.get("dispatch", 0) + 1
                return True
        if REFUSAL_LINE.fullmatch(line) or line == "devlane_permit=refused":
            return True
        return False


def _record_ok(normalized):
    """One public summary record: closed schema and identifier formats."""
    try:
        record = json.loads(normalized)
        if type(record) is not dict:
            return False
        kind = record.get("kind")
        if kind == "diagnostic":
            if (record.get("code") not in PUBLIC_CODES
                    or "file" in record and (type(record["file"]) is not str
                                             or not PUBLIC_FILE_ID.fullmatch(record["file"]))):
                return False
        elif kind == "test":
            if type(record.get("test")) is not str or not PUBLIC_TEST_ID.fullmatch(record["test"]):
                return False
        elif kind == "frame":
            if type(record.get("frame")) is not str or not PUBLIC_FRAME_ID.fullmatch(record["frame"]):
                return False
        elif kind == "coverage":
            if (type(record.get("suite")) is not str or not PUBLIC_SUITE_ID.fullmatch(record["suite"])
                    or any(type(record.get(name)) is not int for name in ("total", "passed", "failed", "ignored"))):
                return False
        elif kind == "control":
            if record.get("code") not in (None, *PUBLIC_CODES):
                return False
        else:
            return False
        return True
    except ValueError:
        return False


def validate_summary_records(record_lines, profile):
    """The whole execution summary as one unit: count, bytes, canonical order, no duplicates."""
    import filter as output_filter
    payload = b"".join(line.encode("ascii") + b"\n" for line in record_lines)
    parsed = [json.loads(line) for line in record_lines]
    profile_config = json.loads((REPOSITORY_ROOT / "ci/devlane-profiles.json").read_text(encoding="utf-8"))["profiles"][profile]
    stages = list(profile_config["stages"]) + ["browser"]
    codes = sorted(set(profile_config.get("diagnostic_codes", []) + ["DEVLANE_FAILURE"]))
    files = {item["file"]: item["file"] for item in parsed if "file" in item}
    allowlists = {
        "files": files,
        "tests": {item["test"]: item["test"] for item in parsed if "test" in item},
        "frames": {item["frame"]: item["frame"] for item in parsed if "frame" in item},
        "stages": stages, "codes": codes, "max_lines": {name: 10_000_000 for name in files},
        "suites": sorted(profile_config.get("rust_matrix", {}).get("coverage_ids", [])),
    }
    try:
        output_filter.validate_public_summary(payload, allowlists)
    except output_filter.FilterRefusal:
        _refuse()


def validate_job_log_surface(log, job_name, identity, *, completed=True, workflow=None, failed_acceptance=False):
    """Closed contract for an encrypted-lane job log.

    Every line must be (a) text of the reviewed workflow, (b) exact hosted-runner scaffolding for
    this workflow (group markers, env/with blocks whose values are bound to the dispatch identity),
    (c) a fixed output line bound to the one step allowed to print it, or (d) a public summary
    record. The records, taken together, must form one valid canonical summary. Anything else,
    including plausible-looking paths or free text, refuses.
    """
    if (type(failed_acceptance) is not bool
            or (failed_acceptance and (workflow != "synthetic" or job_name != "devlane-synthetic"))):
        _refuse()
    if type(log) is not bytes or len(log) > MAX_LOG_BYTES or b"\x00" in log or b"\x1b" in log:
        _refuse()
    try:
        text = log.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _refuse()
    if text.startswith("﻿"):
        text = text[1:]
    kind = "synthetic" if workflow == "synthetic" else "encrypted"
    workflow_path = (".github/workflows/devlane-synthetic.yml" if kind == "synthetic"
                     else ".github/workflows/devlane-encrypted.yml")
    job_key = job_name if kind == "encrypted" else "devlane-synthetic"
    grammar = _Grammar(workflow_path, job_key, identity, kind)
    lines = text.splitlines()
    if len(lines) > 20_000 or any(len(line) > 16_384 for line in lines):
        _refuse()
    all_steps = list(grammar.names)
    postfix = ["Post " + step["name"] for step in grammar.steps if step["uses"]
               and step["uses"].startswith("actions/setup-node@")]
    section = None
    step_name = None
    in_header = False
    header_with = None
    mode = None
    position = -1
    seen_steps = set()
    counts = {}
    records = []
    for original in lines:
        normalized = TIME_PREFIX.sub("", original, count=1).rstrip()
        if not normalized.strip():
            continue
        if any(token in normalized for token in (
                "::warning::", "::error::", "::add-mask::", "::set-env::", "::add-path::", "::set-output::",
                "::debug::", "::notice::", "::stop-commands::", "::save-state::")):
            _refuse()
        if normalized.startswith(LOG_MARKER + "[section]Starting: "):
            name = normalized[len(LOG_MARKER + "[section]Starting: "):]
            if in_header:
                _refuse()
            if name == "Set up job":
                if section is not None:
                    _refuse()
                section = "setup"
            elif name == "Complete job":
                section = "complete"
            elif name in all_steps or name in postfix:
                index = all_steps.index(name) if name in all_steps else len(all_steps) + postfix.index(name)
                if name in seen_steps or index <= position:
                    _refuse()
                seen_steps.add(name)
                position = index
                section, step_name = "step", name
            else:
                _refuse()
            in_header = False
            mode = None
            continue
        if normalized.startswith(LOG_MARKER + "[section]Finishing: "):
            name = normalized[len(LOG_MARKER + "[section]Finishing: "):]
            if name not in ("Set up job", "Complete job") and name != step_name:
                _refuse()
            if in_header:
                _refuse()
            if name == step_name:
                step_name = None
            continue
        if section == "setup":
            if normalized.startswith(LOG_MARKER + "[group]"):
                if normalized[len(LOG_MARKER + "[group]"):] not in PROVIDER_GROUPS | {
                        "Set up job", "Prepare all required actions"}:
                    _refuse()
                continue
            if "nvironment" in normalized:
                if grammar.environment is not None and ENVIRONMENT_LINE.fullmatch(normalized):
                    continue
                _refuse()
            if normalized == LOG_MARKER + "[endgroup]" or PROVIDER_LINE.fullmatch(normalized):
                continue
            _refuse()
        if section == "complete":
            if normalized.startswith(LOG_MARKER + "[group]") or normalized == LOG_MARKER + "[endgroup]":
                if normalized not in (LOG_MARKER + "[group]Complete job", LOG_MARKER + "[endgroup]"):
                    _refuse()
                continue
            if POST_JOB_LINE.fullmatch(normalized):
                continue
            _refuse()
        if section != "step" or step_name is None:
            _refuse()
        step = next((item for item in grammar.steps if item["name"] == step_name), None)
        if step is None and step_name.startswith("Post "):
            step = grammar.post.get(step_name)
        if step is None:
            _refuse()
        if normalized == LOG_MARKER + "[endgroup]":
            if not in_header:
                _refuse()
            in_header = False
            mode = None
            continue
        if normalized.startswith(LOG_MARKER + "[group]"):
            owners = grammar.headers.get(normalized, set())
            if in_header or not owners & {step_name, step_name.replace("Post ", "", 1)}:
                _refuse()
            in_header, mode = True, None
            continue
        if in_header:
            if normalized in ("shell: /usr/bin/bash -e {0}", "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}"):
                mode = None
                continue
            if normalized == "env:":
                mode = "env"
                continue
            if normalized == "with:":
                mode = "with"
                continue
            if original and TIME_PREFIX.sub("", original, count=1).startswith("  ") and mode:
                key, separator, value = normalized.strip().partition(":")
                value = value.strip()
                if separator and mode == "env" and key in grammar.job["env"] | step["env"] \
                        and grammar.env_value_ok(key, value):
                    continue
                if separator and mode == "with" and grammar.with_value_ok(step, key, value):
                    continue
                _refuse()
            if TIME_PREFIX.sub("", original, count=1) in grammar.script_lines or normalized in grammar.script_lines \
                    or normalized.strip() in {item.strip() for item in grammar.script_lines}:
                mode = None
                continue
            _refuse()
        if re.fullmatch(r"\x23\x23\[error\]Process completed with exit code [0-9]+\.", normalized):
            continue
        if normalized.startswith("{"):
            if step_name != "Execute offline profile and filter public summary" or not _record_ok(normalized):
                _refuse()
            records.append(normalized)
            continue
        if grammar.step_output_ok(step_name, normalized, counts):
            continue
        _refuse()
    if in_header or section == "setup":
        _refuse()
    if len(records) > 100 or sum(len(record) + 1 for record in records) > 16 * 1024:
        _refuse()
    if records:
        profile = identity.get("profile")
        if profile not in ("core-node", "core-rust"):
            _refuse()
        validate_summary_records(records, profile)
    if kind == "encrypted" and job_name == RUN_JOB:
        if counts.get("dispatch") != 1 or counts.get("permit") != 1:
            _refuse()
        cleanup_line = "cleanup_receipt=confirmed"
        if counts.get(cleanup_line) != 1 or (completed and counts.get(
                "devlane_job=completed public_output=filtered cleanup=confirmed") != 1):
            _refuse()
    elif kind == "encrypted":
        if counts.get("dispatch") or counts.get("permit") or records:
            _refuse()
        audit_line = "devlane_audit=accepted jobs=2 artifacts=0 cache=unchanged cleanup=confirmed"
        if completed and counts.get(audit_line) != 1 or counts.get(audit_line, 0) > 1:
            _refuse()
    else:
        cache_markers = ("devlane_cache_permit=claimed", "devlane_cache_permit=restored-and-single-use")
        outcome_count = counts.get("devlane_acceptance=pass", 0) + counts.get("acceptance_refused", 0)
        if records or outcome_count != 1 or any(counts.get(line) != 1 for line in cache_markers):
            _refuse()
        if failed_acceptance:
            if (counts.get("acceptance_refused") != 1 or counts.get("devlane_acceptance=pass")
                    or counts.get("devlane_linux_probe=pass") or not counts.get("acceptance_detail_count")):
                _refuse()
        elif (counts.get("devlane_acceptance=pass") != 1 or counts.get("acceptance_refused")
              or counts.get("devlane_linux_probe=pass") != 1):
            _refuse()
    return {"records": [record.encode("ascii") for record in records]}


def validate_check_output(check, job, identity, *, completed):
    """Check-run output as GitHub documents it: no free text, no annotations.

    Actions-created check runs normally carry null title/summary/text; the documented
    `annotations_url` field is allowed. The completion line is verified in the job log, not via
    a step summary (which the runner does not attach to check-run output).
    """
    output = check.get("output") if type(check) is dict else None
    if (type(check) is not dict or check.get("head_sha") != identity["control_sha"]
            or check.get("name") != job.get("name") or check.get("status") != job.get("status")
            or type(output) is not dict
            or not {"title", "summary", "text", "annotations_count"} <= set(output)
            or set(output) - {"title", "summary", "text", "annotations_count", "annotations_url"}
            or output.get("title") not in (None, "", job["name"])
            or output.get("summary") not in (None, "") or output.get("text") not in (None, "")
            or output.get("annotations_count") != 0):
        _refuse()
    url = output.get("annotations_url")
    if url is not None and (type(url) is not str or not re.fullmatch(
            r"https://api\.github\.com/repos/keeldock-platform/platform-ci/check-runs/[1-9][0-9]{0,18}/annotations", url)):
        _refuse()


class AuditRefusal(ValueError):
    pass


def _refuse():
    raise AuditRefusal("audit-contract")


def _steps(job):
    values = job.get("steps")
    if type(values) is not list or len(values) > 32 or any(type(step) is not dict for step in values):
        _refuse()
    return [step for step in values if step.get("name") not in ("Set up job", "Complete job")]


def _expected_step_names(profile):
    return list(STEP_NAMES)


def validate_job_contract(jobs, identity, profile):
    if type(jobs) is not list or len(jobs) != 2:
        _refuse()
    by_name = {}
    for job in jobs:
        if type(job) is not dict or type(job.get("name")) is not str or job["name"] in by_name:
            _refuse()
        by_name[job["name"]] = job
    if set(by_name) != {RUN_JOB, AUDIT_JOB}:
        _refuse()
    run_job, audit_job = by_name[RUN_JOB], by_name[AUDIT_JOB]
    for job in (run_job, audit_job):
        if (job.get("run_id") != int(identity["run_id"])
                or job.get("run_attempt") != 1 or job.get("head_sha") != identity["control_sha"]
                or type(job.get("id")) is not int or job["id"] < 1):
            _refuse()
    if run_job.get("status") != "completed" or run_job.get("conclusion") not in {
        "success", "failure", "cancelled", "timed_out",
    }:
        _refuse()
    if audit_job.get("status") != "in_progress" or audit_job.get("conclusion") is not None:
        _refuse()
    audit_steps = _steps(audit_job)
    if [step.get("name") for step in audit_steps] != list(AUDIT_STEP_NAMES):
        _refuse()
    if (audit_steps[0].get("status") != "completed" or audit_steps[0].get("conclusion") != "success"
            or audit_steps[1].get("status") != "in_progress" or audit_steps[1].get("conclusion") is not None):
        _refuse()
    steps = _steps(run_job)
    expected_names = _expected_step_names(profile)
    if [step.get("name") for step in steps] != expected_names:
        _refuse()
    step_by_name = {step["name"]: step for step in steps}
    expected_tool_step = "Prepare dependencies before the cut" if profile == "core-node" else "Install pinned Rust toolchain"
    skipped_tool_step = "Install pinned Rust toolchain" if profile == "core-node" else None
    cleanup_step = step_by_name["Shred runner-local workspace"]
    if cleanup_step.get("status") != "completed" or cleanup_step.get("conclusion") != "success":
        _refuse()
    cancelled = run_job["conclusion"] in ("cancelled", "timed_out")
    for name, step in step_by_name.items():
        if skipped_tool_step is not None and name == skipped_tool_step:
            if step.get("status") != "completed" or step.get("conclusion") != "skipped":
                _refuse()
            continue
        if name == "Execute offline profile and filter public summary":
            if step.get("status") != "completed" or step.get("conclusion") not in ("success", "failure", "cancelled"):
                _refuse()
        elif step.get("status") != "completed" or step.get("conclusion") != "success":
            if not cancelled or name == "Shred runner-local workspace" or step.get("conclusion") not in ("cancelled", "skipped"):
                _refuse()
    if step_by_name[expected_tool_step].get("conclusion") != "success":
        _refuse()
    if run_job["conclusion"] in ("success", "failure"):
        expected_run_conclusion = (
            "failure" if step_by_name["Execute offline profile and filter public summary"].get("conclusion") == "failure"
            else "success"
        )
        if run_job.get("conclusion") != expected_run_conclusion:
            _refuse()
    for job in (run_job, audit_job):
        url = job.get("check_run_url")
        parsed = urlsplit(url) if type(url) is str else None
        if (parsed is None or parsed.scheme != "https" or parsed.netloc != "api.github.com"
                or not re.fullmatch(r"/repos/keeldock-platform/platform-ci/check-runs/[1-9][0-9]{0,18}", parsed.path)
                or parsed.query or parsed.fragment):
            _refuse()
    return by_name


def validate_terminal_job_contract(jobs, identity, profile):
    """Validate final job identities and return whether the in-run audit passed."""
    if type(jobs) is not list or len(jobs) != 2:
        _refuse()
    by_name = {job.get("name"): job for job in jobs if type(job) is dict}
    if len(by_name) != 2 or set(by_name) != {RUN_JOB, AUDIT_JOB}:
        _refuse()
    audit_job = by_name[AUDIT_JOB]
    audit_steps = _steps(audit_job)
    if [step.get("name") for step in audit_steps] != list(AUDIT_STEP_NAMES):
        _refuse()
    if audit_steps[0].get("status") != "completed" or audit_steps[0].get("conclusion") != "success":
        _refuse()
    if audit_job.get("status") != "completed" or audit_job.get("conclusion") not in {
        "success", "failure", "cancelled", "timed_out",
    }:
        _refuse()
    normalized = []
    for job in jobs:
        value = dict(job)
        value["steps"] = [dict(step) for step in _steps(job)]
        if value["name"] == AUDIT_JOB:
            value["status"] = "in_progress"
            value["conclusion"] = None
            value["steps"][-1]["status"] = "in_progress"
            value["steps"][-1]["conclusion"] = None
        normalized.append(value)
    validate_job_contract(normalized, identity, profile)
    audit_passed = audit_job.get("conclusion") == "success" and all(
        step.get("status") == "completed" and step.get("conclusion") == "success"
        for step in audit_steps
    )
    return by_name, audit_passed


def validate_run_record(run, identity):
    if type(run) is not dict:
        _refuse()
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (str(run.get("id")) != identity["run_id"] or run.get("path") != WORKFLOW_PATH
            or run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main"
            or run.get("head_sha") != identity["control_sha"] or run.get("run_attempt") != 1
            or run.get("status") != "in_progress" or run.get("conclusion") is not None
            or type(repository) is not dict or repository.get("full_name") != REPOSITORY
            or repository.get("id") != REPOSITORY_ID
            or type(head_repository) is not dict or head_repository.get("full_name") != REPOSITORY
            or head_repository.get("id") != REPOSITORY_ID):
        _refuse()


def validate_dispatch_marker(log, identity):
    if type(log) is not bytes or len(log) > MAX_LOG_BYTES or b"::warning::" in log or b"::error::" in log:
        _refuse()
    matches = list(DISPATCH_MARKER.finditer(log))
    if len(matches) != 1:
        _refuse()
    wave_id, bundle_id, control_sha, run_id = matches[0].groups()
    if (wave_id.decode("ascii") != identity["wave_id"] or bundle_id.decode("ascii") != identity["bundle_id"]
            or control_sha.decode("ascii") != identity["control_sha"]
            or run_id.decode("ascii") != identity["run_id"]):
        _refuse()
    if log.count(b"cleanup_receipt=confirmed") != 1:
        _refuse()
    permit_matches = list(PERMIT_MARKER.finditer(log))
    if len(permit_matches) != 1 or permit_matches[0].group(1).decode("ascii") != identity["run_id"]:
        _refuse()


def audit_environment(env):
    required = (
        "CI_REPOSITORY", "CI_REPOSITORY_ID", "CI_EVENT_NAME", "CI_REF", "CI_SHA", "CI_CONTROL_RUN_ID",
        "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "DEVLANE_PROFILE",
        "DEVLANE_WAVE_ID", "DEVLANE_BUNDLE_ID", "DEVLANE_CACHE_BASELINE_SHA256",
        "GITHUB_TOKEN",
    )
    if any(type(env.get(key)) is not str or not env.get(key) for key in required):
        _refuse()
    if (env["CI_REPOSITORY"] != REPOSITORY or env["CI_REPOSITORY_ID"] != str(REPOSITORY_ID)
            or env.get("CI_SERVER_URL") != "https://github.com"
            or env["CI_EVENT_NAME"] != "workflow_dispatch" or env["CI_REF"] != "refs/heads/main"
            or not re.fullmatch(r"[a-f0-9]{40}", env["CI_SHA"])
            or not DECIMAL.fullmatch(env["CI_CONTROL_RUN_ID"])
            or not DECIMAL.fullmatch(env["GITHUB_RUN_ID"]) or env["GITHUB_RUN_ATTEMPT"] != "1"
            or env["DEVLANE_PROFILE"] not in ("core-node", "core-rust")
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{7,63}", env["DEVLANE_WAVE_ID"])
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{7,63}", env["DEVLANE_BUNDLE_ID"])
            or not SHA256.fullmatch(env["DEVLANE_CACHE_BASELINE_SHA256"])):
        _refuse()
    return {
        "repository": env["CI_REPOSITORY"], "repository_id": REPOSITORY_ID,
        "event": env["CI_EVENT_NAME"], "ref": env["CI_REF"], "control_sha": env["CI_SHA"],
        "run_id": env["GITHUB_RUN_ID"], "run_attempt": 1, "profile": env["DEVLANE_PROFILE"],
        "control_run_id": env["CI_CONTROL_RUN_ID"],
        "wave_id": env["DEVLANE_WAVE_ID"], "bundle_id": env["DEVLANE_BUNDLE_ID"],
        "cache_baseline_sha256": env["DEVLANE_CACHE_BASELINE_SHA256"],
    }


def run_audit(api, identity):
    prefix = "/repos/" + REPOSITORY + "/actions/runs/" + identity["run_id"]
    run, _ = api.json(prefix)
    validate_run_record(run, identity)
    response, headers = api.json(prefix + "/jobs?filter=all&per_page=100&page=1")
    if (type(response) is not dict or type(response.get("jobs")) is not list
            or response.get("total_count") != 2 or len(response["jobs"]) != 2
            or headers.get("Link")):
        _refuse()
    jobs = validate_job_contract(response["jobs"], identity, identity["profile"])
    run_job = jobs[RUN_JOB]
    log = api.log_text(run_job["id"])
    validate_dispatch_marker(log, identity)
    validate_job_log_surface(log, RUN_JOB, identity, completed=True)
    artifacts, _ = api.json(prefix + "/artifacts?per_page=100&page=1")
    if (type(artifacts) is not dict or artifacts.get("total_count") != 0
            or artifacts.get("artifacts") != []):
        _refuse()
    caches = _fetch_cache_entries(api, identity["control_sha"])
    permit_key = "devlane-permit-v1-" + identity["bundle_id"]
    control_key = "devlane-control-v1-" + identity["control_run_id"]
    permit_entries = [cache for cache in caches if cache.get("key") == permit_key]
    control_entries = [cache for cache in caches if cache.get("key") == control_key]
    if (len(permit_entries) != 1 or permit_entries[0].get("size_in_bytes", 0) > 16 * 1024
            or len(control_entries) != 1 or control_entries[0].get("size_in_bytes", 0) > 16 * 1024):
        _refuse()
    baseline_caches = [cache for cache in caches if cache.get("key") != permit_key]
    if cache_inventory_digest(baseline_caches) != identity["cache_baseline_sha256"]:
        _refuse()
    for job in jobs.values():
        check_id = int(job["check_run_url"].rsplit("/", 1)[1])
        check, _ = api.json("/repos/%s/check-runs/%d" % (REPOSITORY, check_id))
        validate_check_output(check, job, identity, completed=(job["status"] == "completed"))
        annotations = _read_annotations(api, "/repos/%s/check-runs/%d/annotations" % (REPOSITORY, check_id))
        if annotations:
            _refuse()


def validate_final_public_surfaces(api, jobs, identity, profile):
    """Recheck both final job logs and check outputs immediately before cleanup."""
    if type(jobs) is not list or len(jobs) > 100:
        _refuse()
    collected, collection_failed = {}, False
    for job in jobs:
        if type(job) is not dict or job.get("status") != "completed":
            continue
        identifier = job.get("id")
        if type(identifier) is not int or identifier < 1:
            collection_failed = True
            continue
        surface = {}
        try:
            surface["log"] = api.log_text(identifier)
        except Exception:
            collection_failed = True
        url = job.get("check_run_url")
        parsed = urlsplit(url) if type(url) is str else None
        match = (re.fullmatch(r"/repos/keeldock-platform/platform-ci/check-runs/([1-9][0-9]{0,18})", parsed.path)
                 if parsed is not None and parsed.scheme == "https" and parsed.netloc == "api.github.com"
                 and not parsed.query and not parsed.fragment else None)
        if match is None:
            collection_failed = True
        else:
            check_id = int(match.group(1))
            try:
                surface["check"], _ = api.json("/repos/%s/check-runs/%d" % (REPOSITORY, check_id))
            except Exception:
                collection_failed = True
            try:
                surface["annotations"] = _read_annotations(
                    api, "/repos/%s/check-runs/%d/annotations" % (REPOSITORY, check_id)
                )
            except Exception:
                collection_failed = True
        collected[identifier] = surface
    if collection_failed:
        _refuse()

    validated, audit_passed = validate_terminal_job_contract(jobs, identity, profile)
    if not audit_passed:
        _refuse()
    for job_name in (RUN_JOB, AUDIT_JOB):
        job = validated[job_name]
        if job.get("status") != "completed" or job["id"] not in collected:
            _refuse()
        surface = collected[job["id"]]
        log = surface.get("log")
        surface_result = validate_job_log_surface(log, job_name, identity, completed=True)
        if job_name == RUN_JOB:
            public_records = surface_result["records"]
            validate_dispatch_marker(log, identity)
        check_id = int(job["check_run_url"].rsplit("/", 1)[1])
        validate_check_output(surface.get("check"), job, identity, completed=True)
        if surface.get("annotations"):
            _refuse()
    return {"records": public_records}


def main():
    try:
        identity = audit_environment(os.environ)
        api = GitHubAPI(os.environ["GITHUB_TOKEN"])
        run_audit(api, identity)
        print("devlane_audit=accepted jobs=2 artifacts=0 cache=unchanged cleanup=confirmed")
        return 0
    except Exception:
        print("devlane_audit=refused")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
