"""Exact four-job, read-only audit for one encrypted development wave."""

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
import network_probe


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUST_PROFILES = ("core-rust", "local-sync-rust")
ENCRYPTED_PROFILES = ("core-node", *RUST_PROFILES, "desktop")
REPOSITORY = "keeldock-platform/platform-ci"
REPOSITORY_ID = 1430960557
WORKFLOW_PATH = ".github/workflows/devlane-encrypted.yml"
LEGACY_ENCRYPTED_CONTROL_SHA = "fe3c58f903ad23006c4bda62a3945207f5f525ab"
LEGACY_ENCRYPTED_WORKFLOW_PATH = "kit/devlane/fixtures/encrypted-workflow-43284558151.yml"
LEGACY_ENCRYPTED_WORKFLOWS = {
    LEGACY_ENCRYPTED_CONTROL_SHA: LEGACY_ENCRYPTED_WORKFLOW_PATH,
    "f0ddd39554b2e48fbad7e61126319f5ffcdd2b84":
        "kit/devlane/fixtures/encrypted-workflow-f0ddd39554b2e48fbad7e61126319f5ffcdd2b84.yml",
}


def _legacy_encrypted_workflow_path(identity):
    return LEGACY_ENCRYPTED_WORKFLOWS.get(identity.get("control_sha"))
RUN_JOB = "devlane-encrypted-run"
MACOS_RUN_JOB = "devlane-encrypted-run-macos"
WINDOWS_RUN_JOB = "devlane-encrypted-run-windows"
PLATFORM_RUN_JOBS = {
    "linux": RUN_JOB, "macos": MACOS_RUN_JOB, "windows": WINDOWS_RUN_JOB,
}
PLATFORM_RUNNERS = {"linux": "ubuntu-24.04", "macos": "macos-15", "windows": "windows-2025"}
EXECUTION_JOBS = tuple(PLATFORM_RUN_JOBS.values())
DECRYPT_ENVIRONMENT = "devlane-decrypt"
AUDIT_JOB = "devlane-encrypted-audit"
STEP_NAMES = (
    "Fetch public control and validate dispatch",
    "Prepare hosted Linux isolation state",
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
    "Install Tauri Linux build dependencies",
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
    "Audit exact four-job graph and public surfaces",
)
MACOS_STEP_NAMES = tuple(
    "Prepare hosted runner isolation state" if name == "Prepare hosted Linux isolation state" else name
    for name in STEP_NAMES
)
MACOS_STEP_NAMES = (
    MACOS_STEP_NAMES[0], "Set up pinned macOS Node runtime", "Install pinned macOS npm runtime",
) + MACOS_STEP_NAMES[1:]
WINDOWS_STEP_NAMES = tuple(
    "Prepare hosted Windows isolation state" if name == "Prepare hosted Linux isolation state" else name
    for name in STEP_NAMES if name != "Install Tauri Linux build dependencies"
)
WINDOWS_STEP_NAMES = WINDOWS_STEP_NAMES[:2] + ("Set up pinned Windows Node runtime",) + WINDOWS_STEP_NAMES[2:]
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
PUBLIC_UNIT_FAILURE_SUBREASONS = frozenset((
    "report-missing", "adapter-failed", "filter-refused", "vitest-failed",
))
RUNNER_HOME = chr(47) + "home" + chr(47) + "runner"
TEMP = RUNNER_HOME + "/work/_temp"
MACOS_RUNNER_HOME = chr(47) + "Users" + chr(47) + "runner"
MACOS_TEMP = MACOS_RUNNER_HOME + "/work/_temp"
MACOS_HOSTED_TOOL_CACHE = MACOS_RUNNER_HOME + "/hostedtoolcache/node/24.22.1/arm64"
MACOS_GNU_TAR = chr(47) + "opt/homebrew/bin/gtar"
WINDOWS_RUNNER_HOME = r"D:\a\_work"
WINDOWS_TEMP = r"D:\a\_temp"
WINDOWS_PWSH = 'shell: C:\\Program Files\\PowerShell\\7\\pwsh.EXE -command ". \'{0}\'"'
HOSTED_TOOL_CACHE = "/opt/hostedtoolcache/node/24.22.1/x64"
WINDOWS_HOSTED_TOOL_CACHE = r"C:\hostedtoolcache\windows\node\24.22.1\x64"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
LOG_MARKER = chr(35) * 2
ANSI_SGR = (b"\x1b[0m", b"\x1b[36;1m")
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
    r"(?:(?:devlane_refusal|devlane_supervisor_refusal|dependency_preparation_refusal)"
    r"=(?:[a-z0-9-]{1,64}|node-snapshot-manifest-invalid:"
    r"(?:link-row-path|source-row-kind|manifest-open|manifest-metadata|manifest-race|"
    r"manifest-missing|manifest-shape|manifest-digest|unlisted-site)))\Z"
)
NETWORK_PROBE_SUPERVISOR_PREFIX = "devlane_supervisor_refusal=network-probe-refusal:"
NETWORK_PROBE_SUPERVISOR_CODES = {
    "devlane_supervisor_refusal=network-probe-command-failed": "probe-command-failed",
    "devlane_supervisor_refusal=network-probe-output-invalid": "probe-output-invalid",
    "devlane_supervisor_refusal=network-probe-stage-failed": "probe-stage-failed",
}
DECRYPT_REFUSAL_CODES = frozenset((
    "archive-invalid", "auth-tag", "binding-mismatch", "crypto-unavailable",
    "child-import-failed", "child-no-output", "child-output-invalid", "child-panic",
    "child-spawn-failed", "decrypt-failed", "decrypt-timeout", "expired",
    "invalid-envelope", "key-format", "request-invalid", "truncated",
))
DECRYPT_REFUSAL_CODES |= frozenset(
    "child-signal-" + name for name in
    ("SIGKILL", "SIGSEGV", "SIGABRT", "SIGSYS", "SIGXCPU", "SIGXFSZ", "SIGBUS", "SIGILL")
)
DECRYPT_REFUSAL_CODES |= frozenset(("child-signal-other", "child-exit-other"))
DECRYPT_REFUSAL_CODES |= frozenset("child-exit-" + str(code) for code in (1, 2, 120, 126, 127))
DECRYPT_CHILD_ERROR_CODES = frozenset((
    "ModuleNotFoundError", "ImportError", "PermissionError", "FileNotFoundError", "OSError",
    "MemoryError", "PanicException", "SystemError", "UnicodeDecodeError", "other",
))
DECRYPT_FAILURE_CODES = frozenset((
    "decrypt-key-unavailable", "decrypt-manifest-unavailable", "decrypt-rejected", "decrypt-timeout",
))
def cache_line_patterns(key, temp=TEMP, platform="linux"):
    """Output lines of the pinned cache actions, bound to the one key the step may use."""
    escaped = re.escape(key)
    common = (
        re.compile(r"Cache hit for: " + escaped + r"\Z"),
        re.compile(r"Cache restored from key: " + escaped + r"\Z"),
        re.compile(r"Cache restored successfully\Z"),
        re.compile(r"Cache saved with key: " + escaped + r"\Z"),
        re.compile(r"Cache saved successfully\Z"),
        re.compile(r"Cache not found for input keys: " + escaped + r"\Z"),
        re.compile(r"Cache Size: ~[0-9]+ MB \([0-9]+ B\)\Z"),
        re.compile(r"(?:Received|Sent) [0-9]+ of [0-9]+ \([0-9.]+%\), [0-9.]+ MBs/sec\Z"),
    )
    if platform == "windows":
        tar = r'"C:\\Program Files\\Git\\usr\\bin\\tar.exe"'
        workspace = r"D:/a/platform-ci/platform-ci"
        create = re.compile(
            r"(?:" + LOG_MARKER + r")?\[command\]" + tar
            + r" --posix -cf cache\.tzst --exclude cache\.tzst -P -C " + re.escape(workspace)
            + r" --files-from manifest\.txt --force-local --use-compress-program \"zstd -T0(?: --long=30)?\"\Z"
        )
        restore = re.compile(
            r"(?:" + LOG_MARKER + r")?\[command\]" + tar + r" -xf D:/a/_temp/" + UUID
            + r"/cache\.tzst -P -C " + re.escape(workspace)
            + r" --force-local --use-compress-program \"zstd -d(?: --long=30)?\"\Z"
        )
        return common + (create, restore)
    if platform == "macos":
        tar = re.escape(MACOS_GNU_TAR)
        workspace = re.escape(MACOS_RUNNER_HOME + "/work/platform-ci/platform-ci")
        create = re.compile(
            r"(?:" + LOG_MARKER + r")?\[command\]" + tar
            + r" --posix -cf cache\.tzst --exclude cache\.tzst -P -C " + workspace
            + r" --files-from manifest\.txt --delay-directory-restore --use-compress-program "
            + r"(?:zstdmt(?: --long=30)?)\Z"
        )
        restore = re.compile(
            r"(?:" + LOG_MARKER + r")?\[command\]" + tar + r" -xf " + re.escape(MACOS_TEMP) + "/" + UUID
            + r"/cache\.tzst -P -C " + workspace
            + r" --delay-directory-restore --use-compress-program (?:unzstd(?: --long=30)?)\Z"
        )
        return common + (create, restore)
    tar_command = re.compile(
        r"(?:" + LOG_MARKER + r")?\[command\]/usr/bin/tar (?:--posix -cf cache\.tzst|-xf "
        + re.escape(temp) + "/" + UUID + r"/cache\.tzst)(?: [A-Za-z0-9_./=:+ -]{0,300})?\Z"
    )
    return common + (tar_command,)


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
MACOS_NODE_LINES = (
    re.compile(r"Found in cache @ " + re.escape(MACOS_HOSTED_TOOL_CACHE) + r"\Z"),
    re.compile(r"Attempting to download 24\.22\.1\.\.\.\Z"),
    re.compile(r"Acquiring 24\.22\.1 - arm64 from https://github\.com/actions/node-versions/releases/download/"
               r"24\.22\.1-[0-9]+/node-24\.22\.1-darwin-arm64\.tar\.gz\Z"),
    re.compile(r"Extracting \.\.\.\Z"),
    re.compile(r"Adding to the cache \.\.\.\Z"),
    re.compile(r"Successfully cached node to " + re.escape(MACOS_HOSTED_TOOL_CACHE) + r"\Z"),
    re.compile(r"Added node to the tool cache\Z"),
    re.compile(r"(?:" + LOG_MARKER + r")?\[command\]/usr/bin/tar xz --strip 1 --warning=no-unknown-keyword --overwrite -C "
               + re.escape(MACOS_TEMP) + "/" + UUID + " -f " + re.escape(MACOS_TEMP) + "/" + UUID + r"\Z"),
    re.compile(r"Environment details\Z"),
    re.compile(r"(?:node: v24\.22\.1|npm: [0-9]+\.[0-9]+\.[0-9]+|yarn: [0-9]+\.[0-9]+\.[0-9]+)\Z"),
    re.compile(r"Finished\Z"),
    re.compile(r"Post job cleanup\.\Z"),
)
WINDOWS_NODE_LINES = (
    re.compile(r"Found in cache @ " + re.escape(WINDOWS_HOSTED_TOOL_CACHE) + r"\Z"),
    re.compile(r"Attempting to download 24\.22\.1\.\.\.\Z"),
    re.compile(r"Acquiring 24\.22\.1 - x64 from https:" + re.escape(chr(47) * 2)
               + r"github\.com/actions/node-versions/releases/download/24\.22\.1-[0-9]+/node-24\.22\.1-win32-x64\.7z\Z"),
    re.compile(r"Extracting \.\.\.\Z"),
    re.compile(r"Adding to the cache \.\.\.\Z"),
    re.compile(r"Successfully cached node to " + re.escape(WINDOWS_HOSTED_TOOL_CACHE) + r"\Z"),
    re.compile(r"Added node to the tool cache\Z"),
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
            jobs[job] = {"env": {}, "steps": [], "timeout_minutes": None,
                         "needs": [], "runner": None, "condition": None}
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
            if text.startswith("runs-on: "):
                jobs[job]["runner"] = text[len("runs-on: "):].strip()
            if text.startswith("if: "):
                jobs[job]["condition"] = text[len("if: "):].strip()
            if text.startswith("needs: [") and text.endswith("]"):
                jobs[job]["needs"] = [value.strip() for value in text[8:-1].split(",")]
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


def validate_workflow_job_graph(platform):
    """Keep the dispatch YAML, audited job names, conditions and reviewed runner labels exact."""
    if platform not in PLATFORM_RUN_JOBS:
        _refuse()
    try:
        workflow_text = (REPOSITORY_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    except OSError:
        _refuse()
    if re.search(r"(?m)^ {4}strategy:\s*$|^ {6}matrix:\s*$", workflow_text):
        _refuse()
    jobs = parse_workflow(WORKFLOW_PATH)
    if set(jobs) != set(EXECUTION_JOBS) | {AUDIT_JOB}:
        _refuse()
    for selected, name in PLATFORM_RUN_JOBS.items():
        job = jobs[name]
        if (job["runner"] != PLATFORM_RUNNERS[selected]
                or job["condition"] != "${{ inputs.platform == '" + selected + "' }}"
                or job.get("environment") != DECRYPT_ENVIRONMENT or job["needs"]):
            _refuse()
    audit = jobs[AUDIT_JOB]
    if (audit["runner"] != PLATFORM_RUNNERS["linux"]
            or audit["condition"] != "${{ always() }}"
            or audit["needs"] != list(EXECUTION_JOBS)):
        _refuse()
    return jobs


class _Grammar:
    """The closed set of lines one reviewed workflow job may legitimately write to its log."""

    def __init__(self, workflow_path, job_key, identity, kind):
        jobs = parse_workflow(workflow_path)
        if job_key not in jobs:
            _refuse()
        self.job = jobs[job_key]
        self.environment = self.job.get("environment")
        if self.environment != (DECRYPT_ENVIRONMENT if kind == "encrypted" and job_key in EXECUTION_JOBS else None):
            _refuse()
        self.steps = self.job["steps"]
        self.job_key = job_key
        self.platform = identity.get("platform", "linux")
        if kind == "encrypted" and job_key in EXECUTION_JOBS:
            if job_key != PLATFORM_RUN_JOBS.get(self.platform):
                _refuse()
            node_steps = [step for step in self.steps if step["uses"] and step["uses"].startswith("actions/setup-node@")]
            if self.platform == "windows":
                if (len(node_steps) != 1
                        or node_steps[0]["uses"] != "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1"
                        or node_steps[0]["with"] != {
                            "node-version": "24.22.1", "check-latest": "false", "package-manager-cache": "false",
                        }):
                    _refuse()
            elif self.platform == "macos":
                if (len(node_steps) != 1
                        or node_steps[0]["uses"] != "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1"
                        or node_steps[0]["with"] != {
                            "node-version": "24.22.1", "check-latest": "false", "cache": "",
                            "package-manager-cache": "false",
                        }):
                    _refuse()
            elif node_steps:
                _refuse()
        self.names = [step["name"] for step in self.steps]
        self.identity = identity
        self.kind = kind
        self.job_runner = (PLATFORM_RUNNERS["linux"] if kind == "encrypted" and job_key == AUDIT_JOB
                           else PLATFORM_RUNNERS.get(self.platform, PLATFORM_RUNNERS["linux"]))
        self.runner_home = (WINDOWS_RUNNER_HOME if self.job_runner == "windows-2025" else
                            MACOS_RUNNER_HOME if self.job_runner == "macos-15" else RUNNER_HOME)
        self.temp = (WINDOWS_TEMP if self.job_runner == "windows-2025" else
                     MACOS_TEMP if self.job_runner == "macos-15" else TEMP)
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

    def expected_env_names(self, step):
        names = set(self.job["env"]) | set(step["env"])
        if (self.kind == "encrypted" and self.job_key in EXECUTION_JOBS
                and step["name"] != self.names[0]):
            names = names | {"RUN_ROOT"}
        return names

    def env_value_ok(self, name, value):
        identity, kind = self.identity, self.kind
        run_id = identity.get("run_id", "")
        workspace = (r"D:\a\platform-ci\platform-ci" if self.job_runner == "windows-2025" else
                     self.runner_home + "/work/platform-ci/platform-ci")
        run_root = (self.temp + r"\devlane-" + str(run_id) if self.job_runner == "windows-2025" else
                    self.temp + "/devlane-" + str(run_id))
        fixed = {
            "CI_REPOSITORY": REPOSITORY, "CI_REPOSITORY_ID": str(REPOSITORY_ID),
            "CI_SERVER_URL": "https://github.com", "CI_EVENT_NAME": "workflow_dispatch",
            "CI_SHA": identity.get("control_sha"), "PYTHONDONTWRITEBYTECODE": "1",
            "CI_WORKSPACE": workspace,
            "CI_RUN_ID": run_id, "GITHUB_RUN_ID": run_id, "CI_RUN_ATTEMPT": "1", "GITHUB_RUN_ATTEMPT": "1",
        }
        if kind == "encrypted":
            fixed.update({
                "CI_REF": "refs/heads/main", "CI_CONTROL_RUN_ID": identity.get("control_run_id"),
                "DEVLANE_PROFILE": identity.get("profile"), "DEVLANE_WAVE_ID": identity.get("wave_id"),
                "DEVLANE_BUNDLE_ID": identity.get("bundle_id"),
                "DEVLANE_PLATFORM": self.platform,
                "DEVLANE_CACHE_BASELINE_SHA256": identity.get("cache_baseline_sha256"),
                "RUN_ROOT": run_root,
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
        if key == "token" and (step["uses"] or "").startswith("actions/setup-node@"):
            return value == "***"
        if ((step["uses"] or "").startswith("actions/cache/")
                and key in ("enableCrossOsArchive", "lookup-only", "fail-on-cache-miss")
                and key not in step["with"]):
            return value == "false"
        declared = step["with"].get(key)
        if declared is None:
            return False
        if "${{" not in declared:
            return value == declared.strip('"') or (declared == "" and value == "")
        identity = self.identity
        if key == "path":
            prefix = "${{ runner.temp }}"
            suffix = declared[len(prefix):] if declared.startswith(prefix) else None
            expected_suffix = ("/devlane-control-evidence/permit.json"
                               if step["name"] == "Restore exact source-free control evidence"
                               else "/devlane-bundle-permit/permit.json")
            actual_path = value.replace("\\", "/") if self.job_runner == "windows-2025" else value
            expected_path = self.temp.replace("\\", "/") + expected_suffix
            return suffix == expected_suffix and actual_path == expected_path
        if key == "key":
            return value == self.expected_cache_key(step)
        if key == "token" and "github.token" in declared:
            return value == "***"
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
            return key is not None and any(
                pattern.fullmatch(line) for pattern in cache_line_patterns(key, self.temp, self.platform)
            )
        if uses.startswith("actions/setup-node@") or step_name.startswith("Post Set up"):
            patterns = (WINDOWS_NODE_LINES if self.job_runner == "windows-2025" else
                        MACOS_NODE_LINES if self.job_runner == "macos-15" else NODE_LINES)
            return any(pattern.fullmatch(line) for pattern in patterns)
        if step_name == "Install pinned macOS npm runtime":
            return line == "macos_node_runtime=ready"
        exact = {
            "Fetch public control and validate dispatch": {"dispatch_context=validated"},
            "Prepare hosted runner isolation state": set(),
            "Prepare hosted Linux isolation state": {"devlane_swap=disabled"},
            "Verify exact source-free control evidence": {"devlane_permit=verify_control=pass"},
            "Claim this bundle for one run before decryption": {"devlane_permit=claim=pass"},
            "Install pinned Rust toolchain": {"rust_offline_tools=prepared"},
            "Install Tauri Linux build dependencies": {"tauri_linux_dependencies=installed"},
            "Prepare dependencies before the cut": {"dependency_preparation=complete"},
            "Prove public connectivity before the cut": {"network_positive_control=pass"},
            "Cut network and start the isolated supervisor": {"offline_supervisor=ready"},
            "Probe isolation before decryption": {"network_cut_probe=pass"},
            "Decrypt authenticated bundle": {"authenticated_decryption=pass"},
            "Shred runner-local workspace": {
                "cleanup_receipt=confirmed", "devlane_job=completed public_output=filtered cleanup=confirmed",
            },
            "Audit exact four-job graph and public surfaces": {
                "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed",
            },
            "Claim a synthetic bundle permit": {"devlane_cache_permit=claimed"},
            "Verify the restored permit and refuse a second claim": {"devlane_cache_permit=restored-and-single-use"},
            "Run full source-free production-path acceptance": {"devlane_acceptance=pass"},
            "Probe the loopback-only Linux network boundary": {"devlane_linux_probe=pass"},
        }.get(step_name, set())
        if step_name == "Install pinned Rust toolchain":
            exact = exact | {"rust_matrix_fixture=loaded committed_locks=3 matrix_coverage_ids=23"}
        if step_name == "Install fixed Rust acceptance toolchain":
            exact = exact | {"rust_matrix_fixture=loaded committed_locks=3 matrix_coverage_ids=23"}
        if step_name == "Prepare dependencies before the cut" and self.identity.get("profile") in RUST_PROFILES:
            exact = exact | {"rust_offline_tools=installed"}
        if step_name == "Install pinned Rust toolchain" and self.identity.get("profile") == "desktop":
            exact = {"rust_toolchain=prepared"}
        if (step_name == "Prepare hosted Linux isolation state" and self.kind == "encrypted"
                and self.identity.get("profile") in RUST_PROFILES):
            exact = exact | {"devlane_cgroup_v2=ready"}
        if line.startswith("network_probe_refusal="):
            if step_name != "Probe isolation before decryption":
                return False
            try:
                payload = (line + "\n").encode("ascii")
            except UnicodeError:
                return False
            if network_probe.refusal_code_from_result(2, b"", payload) is None:
                return False
            public_counts["network_probe_refusal"] = public_counts.get("network_probe_refusal", 0) + 1
            public_counts["network_probe_refusal_code"] = line[len("network_probe_refusal="):]
            return public_counts["network_probe_refusal"] == 1
        if line.startswith(NETWORK_PROBE_SUPERVISOR_PREFIX):
            if step_name != "Probe isolation before decryption":
                return False
            message = line[len(NETWORK_PROBE_SUPERVISOR_PREFIX):]
            try:
                payload = ("network_probe_refusal=" + message + "\n").encode("ascii")
            except UnicodeError:
                return False
            if network_probe.refusal_code_from_result(2, b"", payload) is None:
                return False
            public_counts["network_probe_supervisor_refusal"] = public_counts.get(
                "network_probe_supervisor_refusal", 0,
            ) + 1
            public_counts["network_probe_supervisor_refusal_code"] = message
            return public_counts["network_probe_supervisor_refusal"] == 1
        if line.startswith("decrypt_refusal="):
            if step_name != "Decrypt authenticated bundle":
                return False
            reason = line[len("decrypt_refusal="):]
            if reason not in DECRYPT_REFUSAL_CODES:
                return False
            public_counts["decrypt_refusal_detail"] = public_counts.get("decrypt_refusal_detail", 0) + 1
            return public_counts["decrypt_refusal_detail"] == 1
        if line.startswith("decrypt_child_error="):
            if (step_name != "Decrypt authenticated bundle"
                    or public_counts.get("decrypt_refusal_detail") != 1):
                return False
            label = line[len("decrypt_child_error="):]
            if label not in DECRYPT_CHILD_ERROR_CODES:
                return False
            public_counts["decrypt_child_error"] = public_counts.get("decrypt_child_error", 0) + 1
            return public_counts["decrypt_child_error"] == 1
        if line.startswith("devlane_supervisor_refusal="):
            code = line[len("devlane_supervisor_refusal="):]
            if code in DECRYPT_FAILURE_CODES:
                if step_name != "Decrypt authenticated bundle":
                    return False
                public_counts["decrypt_failure_marker"] = public_counts.get("decrypt_failure_marker", 0) + 1
                return public_counts["decrypt_failure_marker"] == 1
        if line in NETWORK_PROBE_SUPERVISOR_CODES:
            if step_name != "Probe isolation before decryption":
                return False
            public_counts["network_probe_supervisor_refusal"] = public_counts.get(
                "network_probe_supervisor_refusal", 0,
            ) + 1
            public_counts["network_probe_supervisor_refusal_code"] = NETWORK_PROBE_SUPERVISOR_CODES[line]
            return public_counts["network_probe_supervisor_refusal"] == 1
        if (step_name in ("Prepare hosted runner isolation state", "Prepare hosted Windows isolation state")
                and self.kind == "encrypted" and self.identity.get("profile") in RUST_PROFILES
                and self.job_runner != "windows-2025"):
            exact = exact | {"devlane_cgroup_v2=ready"}
        if step_name == "Prepare hosted runner isolation state":
            expected_preflight = "devlane_macos=preflight-ready" if self.job_runner == "macos-15" else "devlane_swap=disabled"
            exact = exact | {expected_preflight}
        if step_name == "Prepare hosted Windows isolation state" and self.job_runner == "windows-2025":
            exact = exact | {"windows_runner=hosted-admin verified=windows-2025"}
        if self.job_runner == "windows-2025":
            windows_exact = {
                "Prepare dependencies before the cut": {
                    "windows_prepare=complete lifecycle_scripts=disabled identity=lpac network=outbound-only",
                },
                "Prove public connectivity before the cut": {"windows_public_connectivity=proved"},
                "Cut network and start the isolated supervisor": {
                    "windows_sandbox_profile=created appcontainer=lpac capabilities=empty",
                    "windows_firewall=installed direction=outbound action=block package=verified remote=any",
                    "windows_network_cut=installed",
                },
                "Probe isolation before decryption": {
                    "windows_network_probe=pass ipv4=blocked ipv6=blocked dns=blocked loopback=blocked "
                    "local_listener=blocked named_pipe=blocked smb=blocked outside_read=blocked "
                    "outside_write=blocked other_drive_read=blocked other_drive_write=blocked firewall=verified",
                },
                "Decrypt authenticated bundle": {"windows_decrypt=accepted manifest=bound"},
                "Shred runner-local workspace": {
                    "windows_sandbox_cleanup=confirmed firewall=removed profile=deleted",
                    "cleanup_receipt=confirmed", "devlane_job=completed public_output=filtered cleanup=confirmed",
                },
            }
            exact = windows_exact.get(step_name, exact)
            if step_name == "Shred runner-local workspace" and re.fullmatch(
                    r"windows_runner_shred=confirmed files=[0-9]+ bytes=[0-9]+ reparse=[0-9]+", line):
                public_counts[line] = public_counts.get(line, 0) + 1
                return public_counts[line] == 1
        if line in exact:
            public_counts[line] = public_counts.get(line, 0) + 1
            return public_counts[line] == 1
        if line.startswith("decrypt_refusal="):
            return False
        if line.startswith("decrypt_child_error="):
            return False
        if step_name == "Run full source-free production-path acceptance":
            if diagnostic_contract.public_e2e_progress(line):
                public_counts["e2e_progress_lines"] = public_counts.get("e2e_progress_lines", 0) + 1
                return public_counts["e2e_progress_lines"] <= diagnostic_contract.E2E_PROGRESS_MAX_LINES
            if line.startswith("devlane_e2e_progress="):
                return False
            if line.startswith("devlane_acceptance=refused stage="):
                stage = line.removeprefix("devlane_acceptance=refused stage=")
                if stage not in diagnostic_contract.ACCEPTANCE_FAILURE_STAGES:
                    return False
                public_counts["acceptance_refused"] = public_counts.get("acceptance_refused", 0) + 1
                public_counts["acceptance_refusal_stage"] = stage
                return public_counts["acceptance_refused"] == 1
            if self.kind == "synthetic":
                if diagnostic_contract.public_e2e_vitest_diagnostic(line):
                    public_counts["e2e_vitest_diagnostic_lines"] = public_counts.get(
                        "e2e_vitest_diagnostic_lines", 0) + 1
                    return (public_counts["e2e_vitest_diagnostic_lines"]
                            <= diagnostic_contract.MAX_E2E_VITEST_DIAGNOSTIC_LINES)
                detail_stage = diagnostic_contract.acceptance_detail_stage(line)
                if (detail_stage is not None
                        and detail_stage == public_counts.get("acceptance_refusal_stage")):
                    public_counts["acceptance_detail_count"] = public_counts.get("acceptance_detail_count", 0) + 1
                    return True
                if line.startswith("devlane_acceptance_detail "):
                    return False
            return (diagnostic_contract.public_preparation_diagnostic(line)
                    or diagnostic_contract.public_e2e_runtime_diagnostic(line)
                    or diagnostic_contract.public_e2e_command_diagnostic(line))
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
            if (set(record) - {"kind", "stage", "status", "code", "subreason"}
                    or record.get("code") not in (None, *PUBLIC_CODES)
                    or "subreason" in record and (
                        record.get("stage") != "unit" or record.get("status") != "fail"
                        or type(record.get("subreason")) is not str
                        or record.get("subreason") not in PUBLIC_UNIT_FAILURE_SUBREASONS)):
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


def _hosted_preamble(lines, grammar, job_name, identity, workflow_path):
    """Validate the setup text and runner metadata emitted by a real GitHub job log."""
    index = 0
    job_runner = grammar.job_runner

    def take():
        nonlocal index
        if index >= len(lines):
            _refuse()
        value = lines[index]
        index += 1
        return value

    if not re.fullmatch(r"Current runner version: '[0-9]+\.[0-9]+\.[0-9]+'", take()):
        _refuse()

    def group(name):
        if take() != LOG_MARKER + "[group]" + name:
            _refuse()
        values = []
        while index < len(lines) and lines[index] != LOG_MARKER + "[endgroup]":
            if lines[index].startswith(LOG_MARKER + "["):
                _refuse()
            values.append(take())
        if take() != LOG_MARKER + "[endgroup]":
            _refuse()
        return values

    provisioner = group("Runner Image Provisioner")
    cloud_pattern = r"MacCloud" if job_runner == "macos-15" else r"(?:Azure|AWS|GCP)"
    provisioner_patterns = (
        r"Hosted Compute Agent",
        r"Version: [0-9]{8}\.[0-9]+",
        r"Commit: [a-f0-9]{40}",
        r"Build Date: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        r"Worker ID: \{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
        r"Region: [a-z0-9-]{2,32}",
        r"Cloud: " + cloud_pattern,
    )
    if len(provisioner) != len(provisioner_patterns) or any(
            not re.fullmatch(pattern, value)
            for pattern, value in zip(provisioner_patterns, provisioner)):
        _refuse()

    operating_system = group("Operating System")
    if job_runner == "macos-15":
        if (len(operating_system) != 3 or operating_system[0] != "macOS"
                or not re.fullmatch(r"15\.[0-9]+\.[0-9]+", operating_system[1])
                or not re.fullmatch(r"24[A-Z][A-Z0-9]+", operating_system[2])):
            _refuse()
    elif job_runner == "windows-2025":
        if (len(operating_system) != 3 or operating_system[0] != "Microsoft Windows Server 2025"
                or not re.fullmatch(r"10\.0\.26100", operating_system[1])
                or operating_system[2] != "Datacenter"):
            _refuse()
    elif (len(operating_system) != 3 or operating_system[0] != "Ubuntu"
            or not re.fullmatch(r"24\.04\.[0-9]+", operating_system[1])
            or operating_system[2] != "LTS"):
        _refuse()

    runner_image = group("Runner Image")
    if job_runner == "macos-15":
        image_patterns = (
            r"Image: macos-15-arm64",
            r"Version: [0-9]{8}\.[0-9]+\.[0-9]+",
            r"Included Software: https://github\.com/actions/runner-images/blob/macos-15-arm64/[0-9]{8}\.[0-9]+/images/macos/macos-15-arm64-Readme\.md",
            r"Image Release: https://github\.com/actions/runner-images/releases/tag/macos-15-arm64%2F[0-9]{8}\.[0-9]+",
        )
    elif job_runner == "windows-2025":
        image_patterns = (
            r"Image: windows-2025-vs2026",
            r"Version: [0-9]{8}\.[0-9]{3}",
            r"Included Software: https://github\.com/actions/runner-images/blob/win25-vs2026/[0-9]{8}\.[0-9]{3}/images/windows/Windows2025-VS2026-Readme\.md",
            r"Image Release: https://github\.com/actions/runner-images/releases/tag/win25-vs2026%2F[0-9]{8}\.[0-9]{3}",
        )
    else:
        image_patterns = (
            r"Image: ubuntu-24\.04",
            r"Version: [0-9]{8}\.[0-9]+\.[0-9]+",
            r"Included Software: https://github\.com/actions/runner-images/blob/ubuntu24/[0-9]{8}\.[0-9]+/images/ubuntu/Ubuntu2404-Readme\.md",
            r"Image Release: https://github\.com/actions/runner-images/releases/tag/ubuntu24%2F[0-9]{8}\.[0-9]+",
        )
    if len(runner_image) != len(image_patterns) or any(
            not re.fullmatch(pattern, value)
            for pattern, value in zip(image_patterns, runner_image)):
        _refuse()
    permissions = ["Metadata: read"]
    if grammar.kind == "encrypted" and job_name == AUDIT_JOB:
        permissions = ["Actions: read", "Checks: read", "Metadata: read"]
    if group("GITHUB_TOKEN Permissions") != permissions:
        _refuse()

    canonical = [LOG_MARKER + "[section]Starting: Set up job"]
    for name, values in (
            ("Runner Image Provisioner", provisioner),
            ("Operating System", operating_system),
            ("Runner Image", runner_image),
            ("GITHUB_TOKEN Permissions", permissions)):
        canonical.append(LOG_MARKER + "[group]" + name)
        canonical.extend(value for value in values if not value.startswith("Worker ID:"))
        canonical.append(LOG_MARKER + "[endgroup]")

    environment_seen = False

    def maybe_environment():
        nonlocal environment_seen
        if index < len(lines) and ENVIRONMENT_LINE.fullmatch(lines[index]):
            environment = take()
            if (environment_seen or grammar.environment is None or environment not in (
                    "Environment: " + DECRYPT_ENVIRONMENT,
                    "Deployment environment: " + DECRYPT_ENVIRONMENT)):
                _refuse()
            environment_seen = True
            canonical.append(environment)

    fixed_preamble = [
        "Secret source: Actions",
        "Prepare workflow directory",
        "Prepare all required actions",
    ]
    if any((step["uses"] or "") and not (step["uses"] or "").startswith("./")
           for step in grammar.steps):
        fixed_preamble.append("Getting action download info")
    maybe_environment()
    if take() != fixed_preamble[0]:
        _refuse()
    canonical.append(fixed_preamble[0])
    maybe_environment()
    if index < len(lines) and lines[index] == "Cache mode: write":
        canonical.append(take())
    maybe_environment()
    for expected in fixed_preamble[1:]:
        maybe_environment()
        if take() != expected:
            _refuse()
        canonical.append(expected)
        maybe_environment()

    expected_downloads = []
    seen_actions = set()
    for step in grammar.steps:
        uses = step["uses"] or ""
        if uses and not uses.startswith("./") and uses not in seen_actions:
            seen_actions.add(uses)
            action_path, separator, revision = uses.rpartition("@")
            if not separator or not re.fullmatch(r"[a-f0-9]{40}", revision):
                _refuse()
            repository = "/".join(action_path.split("/")[:2]) + "@" + revision
            if repository not in expected_downloads:
                expected_downloads.append(repository)
    expected_downloads = [
        "Download action repository '%s' (SHA:%s)" % (repository, repository.rsplit("@", 1)[1])
        for repository in expected_downloads
    ]
    for expected in expected_downloads:
        maybe_environment()
        if take() != expected:
            _refuse()
        canonical.append(expected)

    expected_workflow = None
    if grammar.kind == "synthetic":
        expected_workflow = (
            "Uses: keeldock-platform/platform-ci/%s@%s (%s)"
            % (workflow_path, identity.get("ref"), identity.get("control_sha"))
        )
    maybe_environment()
    if index < len(lines) and lines[index].startswith("Uses:"):
        if expected_workflow is None or take() != expected_workflow:
            _refuse()
        canonical.append(expected_workflow)
    elif expected_workflow is not None:
        _refuse()

    maybe_environment()
    if grammar.kind == "synthetic":
        expected_inputs = {"control_wave_id": identity.get("wave_id")}
    else:
        expected_inputs = {
            "profile": identity.get("profile"),
            "platform": identity.get("platform", "linux"),
            "control_run_id": identity.get("control_run_id"),
            "wave_id": identity.get("wave_id"),
            "bundle_id": identity.get("bundle_id"),
            "bundle_asset_id": None,
            "bundle_sha256": None,
            "bundle_size": None,
            "projection_asset_id": None,
            "projection_sha256": None,
            "projection_size": None,
            "expires": None,
            "cache_baseline_sha256": identity.get("cache_baseline_sha256"),
        }
    maybe_environment()
    input_group_present = index < len(lines) and lines[index] == LOG_MARKER + "[group] Inputs"
    if not input_group_present:
        if (grammar.kind != "encrypted" or job_runner != "ubuntu-24.04"
                or identity.get("platform", "linux") != "linux"):
            _refuse()
        expected_inputs = {}
    else:
        if take() != LOG_MARKER + "[group] Inputs":
            _refuse()
    observed_inputs = {}
    input_lines = []
    if input_group_present:
        while index < len(lines) and lines[index] != LOG_MARKER + "[endgroup]":
            line = take()
            if not line.startswith("  "):
                _refuse()
            key, separator, value = line[2:].partition(": ")
            if not separator or key in observed_inputs or key not in expected_inputs:
                _refuse()
            expected = expected_inputs[key]
            if expected is not None:
                valid = value == str(expected)
            elif key.endswith("_asset_id") or key.endswith("_size") or key == "expires":
                valid = DECIMAL.fullmatch(value) is not None
            elif key.endswith("_sha256"):
                valid = SHA256.fullmatch(value) is not None
            else:
                valid = False
            if not valid:
                _refuse()
            observed_inputs[key] = value
            input_lines.append(line)
    if input_group_present:
        if take() != LOG_MARKER + "[endgroup]" or set(observed_inputs) != set(expected_inputs):
            _refuse()
        canonical.append(LOG_MARKER + "[group] Inputs")
        canonical.extend(input_lines)
        canonical.append(LOG_MARKER + "[endgroup]")

    expected_job_name = ("devlane-synthetic / devlane-synthetic"
                         if grammar.kind == "synthetic" else job_name)
    job_line = take()
    if job_line != "Complete job name: " + expected_job_name:
        _refuse()
    canonical.append(job_line)
    maybe_environment()
    if index >= len(lines) or not lines[index].startswith(LOG_MARKER + "[group]Run "):
        _refuse()
    canonical.append(LOG_MARKER + "[section]Finishing: Set up job")
    return canonical, index


def _parse_hosted_step_block(block, step, grammar):
    run = step["run"]
    expected_env = grammar.expected_env_names(step)
    canonical = []
    if run:
        shell_options = (
            "shell: /bin/bash --noprofile --norc -e -o pipefail {0}",
            "shell: /bin/bash -e {0}",
            "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}",
            "shell: /usr/bin/bash -e {0}",
        )
        if grammar.job_runner == "windows-2025":
            shell_index = next((index for index, line in enumerate(block) if line == WINDOWS_PWSH), None)
        else:
            shell_index = next((index for index, line in enumerate(block) if line in shell_options), None)
        if shell_index is None:
            _refuse()
        script = [line for line in block[:shell_index] if line]
        if script != run:
            _refuse()
        canonical.extend(run)
        canonical.append(block[shell_index])
        remainder = block[shell_index + 1:]
        expected_with = {}
    else:
        if not step["uses"] or not block or block[0] != "with:":
            _refuse()
        canonical.append("with:")
        remainder = block[1:]
        expected_with = step["with"]

    observed_with = {}
    observed_env = {}
    mode = None
    for line in remainder:
        if line == "env:":
            if mode == "env":
                _refuse()
            mode = "env"
            canonical.append(line)
            continue
        if not line.startswith("  "):
            _refuse()
        key, separator, value = line[2:].partition(": ")
        if not separator:
            _refuse()
        if mode == "env":
            if key in observed_env or key not in expected_env or not grammar.env_value_ok(key, value):
                _refuse()
            observed_env[key] = value
        elif not run:
            uses = step["uses"] or ""
            implicit_input = (
                key == "token" and uses.startswith("actions/setup-node@")
                or key in ("enableCrossOsArchive", "lookup-only", "fail-on-cache-miss")
                and uses.startswith("actions/cache/")
            )
            if (key in observed_with or not implicit_input and key not in expected_with
                    or not grammar.with_value_ok(step, key, value)):
                _refuse()
            observed_with[key] = value
        else:
            _refuse()
        canonical.append(line)
    if set(observed_env) != set(expected_env):
        _refuse()
    if not run:
        required_with = {key for key, value in expected_with.items() if value != ""}
        if not required_with <= set(observed_with):
            _refuse()
    return canonical


def _canonicalize_github_hosted_log(text, grammar, job_name, identity, workflow_path):
    lines = [TIME_PREFIX.sub("", line, count=1).rstrip() for line in text.splitlines()]
    if len(lines) > 20_000 or any(len(line) > 16_384 for line in lines):
        _refuse()
    canonical, index = _hosted_preamble(lines, grammar, job_name, identity, workflow_path)
    position = -1
    post_output = []
    cleanup_seen = False
    while index < len(lines):
        header = lines[index]
        if not header.startswith(LOG_MARKER + "[group]Run "):
            _refuse()
        description = header[len(LOG_MARKER + "[group]Run "):]
        index += 1
        block = []
        while index < len(lines) and lines[index] != LOG_MARKER + "[endgroup]":
            if lines[index].startswith(LOG_MARKER + "[group]"):
                _refuse()
            block.append(lines[index])
            index += 1
        if index >= len(lines):
            _refuse()
        index += 1

        matches = []
        for candidate_index in range(position + 1, len(grammar.steps)):
            step = grammar.steps[candidate_index]
            uses = step["uses"] or ""
            run = step["run"]
            if ((uses and uses == description)
                    or (run and run[0].strip() == description)):
                matches.append((candidate_index, step))
        if not matches:
            _refuse()

        parsed = None
        step = None
        for candidate_index, candidate in matches:
            try:
                parsed = _parse_hosted_step_block(block, candidate, grammar)
                position, step = candidate_index, candidate
                break
            except AuditRefusal:
                continue
        if parsed is None or step is None:
            _refuse()
        canonical.extend((
            LOG_MARKER + "[section]Starting: " + step["name"],
            LOG_MARKER + "[group]Run " + description,
        ))
        canonical.extend(parsed)
        canonical.append(LOG_MARKER + "[endgroup]")

        output = []
        while index < len(lines) and not lines[index].startswith(LOG_MARKER + "[group]Run "):
            line = lines[index]
            if line == "Cleaning up orphan processes":
                cleanup_seen = True
                index += 1
                break
            if line == "Post job cleanup.":
                post_output.append(line)
                index += 1
                continue
            if re.fullmatch(LOG_MARKER + r"\[error\]Process completed with exit code [0-9]+\.", line):
                output.append(line)
                index += 1
                continue
            if line == LOG_MARKER + "[group]Environment details":
                index += 1
                env_details = []
                while index < len(lines) and lines[index] != LOG_MARKER + "[endgroup]":
                    if lines[index].startswith(LOG_MARKER + "["):
                        _refuse()
                    env_details.append(lines[index])
                    index += 1
                if grammar.job_runner == "macos-15":
                    details_valid = (
                        len(env_details) == 4 and env_details[0] == "node: v24.22.1"
                        and re.fullmatch(r"npm: [0-9]+\.[0-9]+\.[0-9]+", env_details[1]) is not None
                        and re.fullmatch(r"yarn: [0-9]+\.[0-9]+\.[0-9]+", env_details[2]) is not None
                        and env_details[3] == "Finished"
                    )
                else:
                    details_valid = env_details == ["node: v24.22.1", "npm: 11.19.1", "yarn: 1.22.22"]
                if index >= len(lines) or not details_valid:
                    _refuse()
                output.extend(env_details)
                index += 1
                continue
            if (line.startswith(LOG_MARKER + "[command]")
                    and (step["uses"] or "").startswith("actions/cache/")
                    and grammar.step_output_ok(step["name"], line, {})):
                output.append(line)
                index += 1
                continue
            if line.startswith(LOG_MARKER + "["):
                _refuse()
            output.append(line)
            index += 1
        canonical.extend(output)
        canonical.append(LOG_MARKER + "[section]Finishing: " + step["name"])
        if cleanup_seen:
            break

    if post_output:
        if len(post_output) != 1 or not grammar.post:
            _refuse()
        post_name = next(iter(grammar.post))
        canonical.extend((
            LOG_MARKER + "[section]Starting: " + post_name,
            post_output[0],
            LOG_MARKER + "[section]Finishing: " + post_name,
        ))
    if not cleanup_seen or index != len(lines):
        _refuse()
    canonical.extend((
        LOG_MARKER + "[section]Starting: Complete job",
        "Cleaning up orphan processes",
        LOG_MARKER + "[section]Finishing: Complete job",
    ))
    return "\n".join(canonical) + "\n"


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
    if type(log) is not bytes or len(log) > MAX_LOG_BYTES:
        _refuse()
    for sequence in ANSI_SGR:
        log = log.replace(sequence, b"")
    if any(byte < 32 and byte != 10 or byte == 127 for byte in log) or b"\x1b" in log:
        _refuse()
    try:
        text = log.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _refuse()
    if text.startswith("﻿"):
        text = text[1:]
    if any(ord(char) < 32 and char != "\n" or 127 <= ord(char) <= 159 for char in text):
        _refuse()
    kind = "synthetic" if workflow == "synthetic" else "encrypted"
    legacy_workflow = _legacy_encrypted_workflow_path(identity) if kind == "encrypted" else None
    workflow_path = (".github/workflows/devlane-synthetic.yml" if kind == "synthetic"
                     else str(REPOSITORY_ROOT / legacy_workflow) if legacy_workflow
                     else ".github/workflows/devlane-encrypted.yml")
    job_key = job_name if kind == "encrypted" else "devlane-synthetic"
    grammar = _Grammar(workflow_path, job_key, identity, kind)
    first_line = text.splitlines()[0] if text else ""
    if TIME_PREFIX.sub("", first_line, count=1).startswith("Current runner version: "):
        text = _canonicalize_github_hosted_log(text, grammar, job_name, identity, workflow_path)
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
                        "Set up job", "Prepare all required actions", " Inputs"}:
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
            if (grammar.job_runner == "windows-2025" and normalized == WINDOWS_PWSH):
                mode = None
                continue
            if normalized in (
                    "shell: /bin/bash -e {0}", "shell: /bin/bash --noprofile --norc -e -o pipefail {0}",
                    "shell: /usr/bin/bash -e {0}", "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}"):
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
                if separator and mode == "env" and key in grammar.expected_env_names(step) \
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
        if normalized == LOG_MARKER + "[error]Process completed with exit code 2.":
            if step_name == "Probe isolation before decryption":
                if not (counts.get("network_probe_refusal")
                        or counts.get("network_probe_supervisor_refusal")):
                    _refuse()
                counts["network_probe_failed_exit"] = counts.get("network_probe_failed_exit", 0) + 1
                if counts["network_probe_failed_exit"] != 1:
                    _refuse()
            elif step_name == "Decrypt authenticated bundle":
                if counts.get("decrypt_failure_marker") != 1 or counts.get("authenticated_decryption=pass"):
                    _refuse()
                counts["decrypt_failed_exit"] = counts.get("decrypt_failed_exit", 0) + 1
                if counts["decrypt_failed_exit"] != 1:
                    _refuse()
            else:
                _refuse()
            continue
        if normalized.startswith(LOG_MARKER + "[error]"):
            _refuse()
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
        if profile not in ENCRYPTED_PROFILES:
            _refuse()
        validate_summary_records(records, profile)
    if kind == "encrypted" and job_name in EXECUTION_JOBS:
        windows_job = grammar.job_runner == "windows-2025"
        if (counts.get("network_probe_refusal_code") is not None
                and counts.get("network_probe_supervisor_refusal_code") is not None
                and counts["network_probe_refusal_code"] != counts["network_probe_supervisor_refusal_code"]):
            _refuse()
        if counts.get("dispatch") != 1 or counts.get("permit") != 1:
            _refuse()
        probe_refusal_count = counts.get("network_probe_refusal", 0) + (
            1 if counts.get("network_probe_supervisor_refusal")
            and not counts.get("network_probe_refusal") else 0
        )
        windows_probe_success = (
            "windows_network_probe=pass ipv4=blocked ipv6=blocked dns=blocked loopback=blocked "
            "local_listener=blocked named_pipe=blocked smb=blocked outside_read=blocked "
            "outside_write=blocked other_drive_read=blocked other_drive_write=blocked firewall=verified"
        )
        probe_success_count = counts.get(windows_probe_success, 0) if windows_job else counts.get("network_cut_probe=pass", 0)
        if probe_success_count + probe_refusal_count != 1:
            _refuse()
        if probe_refusal_count != counts.get("network_probe_failed_exit", 0):
            _refuse()
        decrypt_failure_count = counts.get("decrypt_failure_marker", 0)
        if probe_refusal_count:
            if (counts.get("authenticated_decryption=pass") or counts.get("windows_decrypt=accepted manifest=bound")
                    or decrypt_failure_count
                    or counts.get("decrypt_failed_exit") or counts.get("decrypt_refusal_detail")
                    or "Decrypt authenticated bundle" in seen_steps
                    or "Execute offline profile and filter public summary" in seen_steps):
                _refuse()
        else:
            decrypt_success_count = (counts.get("windows_decrypt=accepted manifest=bound", 0)
                                     if windows_job else counts.get("authenticated_decryption=pass", 0))
            if decrypt_success_count + decrypt_failure_count != 1:
                _refuse()
            if decrypt_failure_count:
                if (counts.get("decrypt_failed_exit") != 1 or records
                        or "Execute offline profile and filter public summary" in seen_steps):
                    _refuse()
            elif counts.get("decrypt_failed_exit") or counts.get("decrypt_refusal_detail"):
                _refuse()
        if counts.get("decrypt_refusal_detail", 0) > 1:
            _refuse()
        cleanup_line = "cleanup_receipt=confirmed"
        if counts.get(cleanup_line) != 1 or (completed and counts.get(
                "devlane_job=completed public_output=filtered cleanup=confirmed") != 1):
            _refuse()
    elif kind == "encrypted":
        if counts.get("dispatch") or counts.get("permit") or records:
            _refuse()
        audit_line = "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed"
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


def _expected_step_names(profile, identity=None):
    platform = identity.get("platform", "linux") if type(identity) is dict else "linux"
    legacy_workflow = _legacy_encrypted_workflow_path(identity) if type(identity) is dict else None
    if legacy_workflow and platform == "linux" and profile in ("core-node", "core-rust"):
        legacy = parse_workflow(REPOSITORY_ROOT / legacy_workflow)
        return [step["name"] for step in legacy[RUN_JOB]["steps"]]
    jobs = validate_workflow_job_graph(platform)
    return [step["name"] for step in jobs[PLATFORM_RUN_JOBS[platform]]["steps"]]


def validate_job_contract(jobs, identity, profile):
    platform = identity.get("platform", "linux")
    legacy = _legacy_encrypted_workflow_path(identity) is not None
    if platform not in PLATFORM_RUN_JOBS or (platform == "windows" and profile != "core-node"):
        _refuse()
    if not legacy:
        validate_workflow_job_graph(platform)
    expected_names = ({RUN_JOB, AUDIT_JOB} if legacy else set(EXECUTION_JOBS) | {AUDIT_JOB})
    expected_count = 2 if legacy else 4
    if type(jobs) is not list or len(jobs) != expected_count:
        _refuse()
    by_name = {}
    for job in jobs:
        if type(job) is not dict or type(job.get("name")) is not str or job["name"] in by_name:
            _refuse()
        by_name[job["name"]] = job
    if set(by_name) != expected_names:
        _refuse()
    active_name = RUN_JOB if legacy else PLATFORM_RUN_JOBS[platform]
    run_job, audit_job = by_name[active_name], by_name[AUDIT_JOB]
    for job in by_name.values():
        if (job.get("run_id") != int(identity["run_id"])
                or job.get("run_attempt") != 1 or job.get("head_sha") != identity["control_sha"]
                or type(job.get("id")) is not int or job["id"] < 1):
            _refuse()
    for inactive_name in (() if legacy else set(EXECUTION_JOBS) - {active_name}):
        inactive_job = by_name[inactive_name]
        inactive_platform = next(key for key, name in PLATFORM_RUN_JOBS.items() if name == inactive_name)
        if (inactive_job.get("labels") != [PLATFORM_RUNNERS[inactive_platform]]
                or inactive_job.get("status") != "completed" or inactive_job.get("conclusion") != "skipped"
                or _steps(inactive_job)):
            _refuse()
    if run_job.get("status") != "completed" or run_job.get("conclusion") not in {
        "success", "failure", "cancelled", "timed_out",
    }:
        _refuse()
    expected_runner = identity.get("runner", PLATFORM_RUNNERS[platform])
    if (run_job.get("labels") != [expected_runner]
            or audit_job.get("labels") != [PLATFORM_RUNNERS["linux"]]):
        _refuse()
    if audit_job.get("status") != "in_progress" or audit_job.get("conclusion") is not None:
        _refuse()
    audit_steps = _steps(audit_job)
    legacy_audit_names = None
    if legacy:
        legacy_audit_names = [step["name"] for step in parse_workflow(
            REPOSITORY_ROOT / _legacy_encrypted_workflow_path(identity))[AUDIT_JOB]["steps"]]
    if [step.get("name") for step in audit_steps] != (legacy_audit_names or list(AUDIT_STEP_NAMES)):
        _refuse()
    if (audit_steps[0].get("status") != "completed" or audit_steps[0].get("conclusion") != "success"
            or audit_steps[1].get("status") != "in_progress" or audit_steps[1].get("conclusion") is not None):
        _refuse()
    steps = _steps(run_job)
    expected_names = _expected_step_names(profile, identity)
    if [step.get("name") for step in steps] != expected_names:
        _refuse()
    step_by_name = {step["name"]: step for step in steps}
    expected_tool_step = "Prepare dependencies before the cut" if profile == "core-node" else "Install pinned Rust toolchain"
    skipped_tool_step = "Install pinned Rust toolchain" if profile == "core-node" else None
    skipped_desktop_dependency_step = (
        "Install Tauri Linux build dependencies"
        if "Install Tauri Linux build dependencies" in step_by_name
        and (profile != "desktop" or platform != "linux") else None
    )
    cleanup_step = step_by_name["Shred runner-local workspace"]
    if cleanup_step.get("status") != "completed" or cleanup_step.get("conclusion") != "success":
        _refuse()
    probe_failure = step_by_name["Probe isolation before decryption"]
    decrypt_step = step_by_name["Decrypt authenticated bundle"]
    execute_step = step_by_name["Execute offline profile and filter public summary"]
    failed_before_decrypt = (
        run_job.get("conclusion") == "failure"
        and probe_failure.get("status") == "completed" and probe_failure.get("conclusion") == "failure"
        and decrypt_step.get("status") == "completed" and decrypt_step.get("conclusion") == "skipped"
        and execute_step.get("status") == "completed" and execute_step.get("conclusion") == "skipped"
    )
    failed_at_decrypt = (
        run_job.get("conclusion") == "failure"
        and probe_failure.get("status") == "completed" and probe_failure.get("conclusion") == "success"
        and decrypt_step.get("status") == "completed" and decrypt_step.get("conclusion") == "failure"
        and execute_step.get("status") == "completed" and execute_step.get("conclusion") == "skipped"
    )
    cancelled = run_job["conclusion"] in ("cancelled", "timed_out")
    for name, step in step_by_name.items():
        if failed_before_decrypt and name == "Probe isolation before decryption":
            if step.get("status") != "completed" or step.get("conclusion") != "failure":
                _refuse()
            continue
        if failed_before_decrypt and name in (
                "Decrypt authenticated bundle", "Execute offline profile and filter public summary"):
            if step.get("status") != "completed" or step.get("conclusion") != "skipped":
                _refuse()
            continue
        if failed_at_decrypt and name in (
                "Decrypt authenticated bundle", "Execute offline profile and filter public summary"):
            expected = "failure" if name == "Decrypt authenticated bundle" else "skipped"
            if step.get("status") != "completed" or step.get("conclusion") != expected:
                _refuse()
            continue
        if ((skipped_tool_step is not None and name == skipped_tool_step)
                or (skipped_desktop_dependency_step is not None and name == skipped_desktop_dependency_step)):
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
            "failure" if failed_before_decrypt or failed_at_decrypt
            or execute_step.get("conclusion") == "failure"
            else "success"
        )
        if run_job.get("conclusion") != expected_run_conclusion:
            _refuse()
    for job in by_name.values():
        url = job.get("check_run_url")
        parsed = urlsplit(url) if type(url) is str else None
        if (parsed is None or parsed.scheme != "https" or parsed.netloc != "api.github.com"
                or not re.fullmatch(r"/repos/keeldock-platform/platform-ci/check-runs/[1-9][0-9]{0,18}", parsed.path)
                or parsed.query or parsed.fragment):
            _refuse()
    return by_name


def validate_terminal_job_contract(jobs, identity, profile):
    """Validate final job identities and return whether the in-run audit passed."""
    legacy = _legacy_encrypted_workflow_path(identity) is not None
    expected = ({RUN_JOB, AUDIT_JOB} if legacy else set(EXECUTION_JOBS) | {AUDIT_JOB})
    expected_count = 2 if legacy else 4
    if type(jobs) is not list or len(jobs) != expected_count:
        _refuse()
    by_name = {job.get("name"): job for job in jobs if type(job) is dict}
    if len(by_name) != expected_count or set(by_name) != expected:
        _refuse()
    audit_job = by_name[AUDIT_JOB]
    audit_steps = _steps(audit_job)
    legacy_audit_names = None
    if legacy:
        legacy_audit_names = [step["name"] for step in parse_workflow(
            REPOSITORY_ROOT / _legacy_encrypted_workflow_path(identity))[AUDIT_JOB]["steps"]]
    if [step.get("name") for step in audit_steps] != (legacy_audit_names or list(AUDIT_STEP_NAMES)):
        _refuse()
    if audit_steps[0].get("status") != "completed" or audit_steps[0].get("conclusion") != "success":
        _refuse()
    if audit_job.get("status") != "completed" or audit_job.get("conclusion") not in {
        "success", "failure", "cancelled", "timed_out",
    }:
        _refuse()
    if (audit_job["conclusion"] == "success"
            and any(step.get("status") != "completed" or step.get("conclusion") != "success"
                    for step in audit_steps)):
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
        "GITHUB_TOKEN", "DEVLANE_PLATFORM",
    )
    if any(type(env.get(key)) is not str or not env.get(key) for key in required):
        _refuse()
    if (env["CI_REPOSITORY"] != REPOSITORY or env["CI_REPOSITORY_ID"] != str(REPOSITORY_ID)
            or env.get("CI_SERVER_URL") != "https://github.com"
            or env["CI_EVENT_NAME"] != "workflow_dispatch" or env["CI_REF"] != "refs/heads/main"
            or not re.fullmatch(r"[a-f0-9]{40}", env["CI_SHA"])
            or not DECIMAL.fullmatch(env["CI_CONTROL_RUN_ID"])
            or not DECIMAL.fullmatch(env["GITHUB_RUN_ID"]) or env["GITHUB_RUN_ATTEMPT"] != "1"
            or env["DEVLANE_PROFILE"] not in ENCRYPTED_PROFILES
            or env["DEVLANE_PLATFORM"] not in PLATFORM_RUNNERS
            or env["DEVLANE_PLATFORM"] == "windows" and env["DEVLANE_PROFILE"] != "core-node"
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{7,63}", env["DEVLANE_WAVE_ID"])
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{7,63}", env["DEVLANE_BUNDLE_ID"])
            or not SHA256.fullmatch(env["DEVLANE_CACHE_BASELINE_SHA256"])):
        _refuse()
    return {
        "repository": env["CI_REPOSITORY"], "repository_id": REPOSITORY_ID,
        "event": env["CI_EVENT_NAME"], "ref": env["CI_REF"], "control_sha": env["CI_SHA"],
        "run_id": env["GITHUB_RUN_ID"], "run_attempt": 1, "profile": env["DEVLANE_PROFILE"],
        "platform": env["DEVLANE_PLATFORM"],
        "control_run_id": env["CI_CONTROL_RUN_ID"],
        "wave_id": env["DEVLANE_WAVE_ID"], "bundle_id": env["DEVLANE_BUNDLE_ID"],
        "cache_baseline_sha256": env["DEVLANE_CACHE_BASELINE_SHA256"],
    }


def run_audit(api, identity):
    prefix = "/repos/" + REPOSITORY + "/actions/runs/" + identity["run_id"]
    run, _ = api.json(prefix)
    validate_run_record(run, identity)
    response, headers = api.json(prefix + "/jobs?filter=all&per_page=100&page=1")
    expected_count = 2 if _legacy_encrypted_workflow_path(identity) else 4
    if (type(response) is not dict or type(response.get("jobs")) is not list
            or response.get("total_count") != expected_count or len(response["jobs"]) != expected_count
            or headers.get("Link")):
        _refuse()
    jobs = validate_job_contract(response["jobs"], identity, identity["profile"])
    active_name = (RUN_JOB if expected_count == 2
                   else PLATFORM_RUN_JOBS[identity.get("platform", "linux")])
    run_job = jobs[active_name]
    log = api.log_text(run_job["id"])
    validate_dispatch_marker(log, identity)
    validate_job_log_surface(log, active_name, identity, completed=True)
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
    """Recheck the active execution and audit logs plus all four check outputs."""
    if type(jobs) is not list or len(jobs) > 100:
        _refuse()
    collected, collection_failed = {}, False
    active_name = PLATFORM_RUN_JOBS.get(identity.get("platform", "linux"))
    for job in jobs:
        if type(job) is not dict or job.get("status") != "completed":
            continue
        if job.get("name") not in (active_name, AUDIT_JOB):
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
    active_name = PLATFORM_RUN_JOBS[identity.get("platform", "linux")]
    for job_name in (active_name, AUDIT_JOB):
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
        print("devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed")
        return 0
    except Exception:
        print("devlane_audit=refused")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
