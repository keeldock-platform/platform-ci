"""Mutation tests for the workflow dispatch and exact auditor contracts."""

import copy
import json
import re
import unittest
from pathlib import Path
from unittest.mock import patch

import public_audit as audit
import control_audit
import acceptance_diagnostics
import diagnostic_contract


SHA = "a" * 40
IDENTITY = {
    "repository": audit.REPOSITORY,
    "repository_id": audit.REPOSITORY_ID,
    "event": "workflow_dispatch",
    "ref": "refs/heads/main",
    "control_sha": SHA,
    "run_id": "12345",
    "run_attempt": 1,
    "control_run_id": "9876",
    "profile": "core-node",
    "wave_id": "wave-test-0001",
    "bundle_id": "bundle-test-0001",
    "cache_baseline_sha256": "b" * 64,
}


MARK = chr(35) * 2
RUNNER_HOME = chr(47) + "home" + chr(47) + "runner"
TMP = RUNNER_HOME + "/work/_temp"


def _env_value(name, identity=IDENTITY, kind="encrypted"):
    values = {
        "CI_REPOSITORY": audit.REPOSITORY, "CI_REPOSITORY_ID": str(audit.REPOSITORY_ID),
        "CI_REF": "refs/heads/main", "CI_SHA": identity["control_sha"], "CI_SERVER_URL": "https://github.com",
        "CI_EVENT_NAME": "workflow_dispatch", "CI_RUN_ID": identity["run_id"], "CI_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": identity["run_id"], "GITHUB_RUN_ATTEMPT": "1",
        "CI_CONTROL_RUN_ID": identity.get("control_run_id", ""), "DEVLANE_PROFILE": identity["profile"],
        "DEVLANE_WAVE_ID": identity["wave_id"], "DEVLANE_BUNDLE_ID": identity["bundle_id"],
        "DEVLANE_BUNDLE_ASSET_ID": "111", "DEVLANE_BUNDLE_SHA256": "c" * 64, "DEVLANE_BUNDLE_SIZE": "4096",
        "DEVLANE_PROJECTION_ASSET_ID": "222", "DEVLANE_PROJECTION_SHA256": "d" * 64,
        "DEVLANE_PROJECTION_SIZE": "512", "DEVLANE_EXPIRES": "2000000000",
        "DEVLANE_CACHE_BASELINE_SHA256": identity["cache_baseline_sha256"],
        "RUN_ROOT": TMP + "/devlane-" + identity["run_id"], "PYTHONDONTWRITEBYTECODE": "1",
        "DEVLANE_DECRYPT_KEY": "***", "GITHUB_TOKEN": "***",
        "CI_WORKSPACE": RUNNER_HOME + "/work/platform-ci/platform-ci",
    }
    if kind == "synthetic":
        values["CI_REF"] = identity.get("ref", "refs/heads/develop")
    return values[name]


def _with_value(step, key, identity, kind):
    declared = step["with"][key]
    if "${{" not in declared:
        return declared
    if key == "path":
        return {"Restore exact source-free control evidence": TMP + "/devlane-control-evidence/permit.json"}.get(
            step["name"], TMP + "/devlane-bundle-permit/permit.json")
    if kind == "synthetic":
        return "devlane-permit-v1-synthetic-bundle-" + identity["run_id"]
    return ("devlane-control-v1-" + identity["control_run_id"]
            if "control" in declared else "devlane-permit-v1-" + identity["bundle_id"])


def _step_outputs(step, identity, kind, records):
    name, uses = step["name"], step.get("uses") or ""
    if name == "Install Tauri Linux build dependencies" and identity["profile"] == "desktop":
        return ["tauri_linux_dependencies=installed"]
    if name == "Install pinned Rust toolchain" and identity["profile"] == "desktop":
        return ["rust_toolchain=prepared"]
    if name == "Install pinned Rust toolchain" and identity["profile"] in audit.RUST_PROFILES:
        return ["rust_offline_tools=prepared"]
    if name == "Prepare dependencies before the cut" and identity["profile"] in audit.RUST_PROFILES:
        return ["dependency_preparation=complete", "rust_offline_tools=installed"]
    key = None
    if uses.startswith("actions/cache/restore"):
        key = _with_value(step, "key", identity, kind)
        return ["Cache hit for: " + key, "Cache Size: ~0 MB (160 B)", "Cache restored successfully",
                "Cache restored from key: " + key] if "fail-on-cache-miss" in step["with"] else [
                "Cache not found for input keys: " + _with_value(step, "key", identity, kind)]
    if uses.startswith("actions/cache/save"):
        key = _with_value(step, "key", identity, kind)
        return ["Cache saved with key: " + key, "Cache saved successfully"]
    if uses.startswith("actions/setup-node"):
        return ["Found in cache @ " + audit.HOSTED_TOOL_CACHE, "Environment details", "node: v24.22.1", "npm: 11.19.1",
                "yarn: 1.22.22"]
    outputs = {
        "Fetch public control and validate dispatch": ["dispatch_context=validated"] if kind == "encrypted" else [],
        "Prepare hosted Linux isolation state": ["devlane_swap=disabled"] + (
            ["devlane_cgroup_v2=ready"] if kind == "encrypted" and identity["profile"] in audit.RUST_PROFILES else []
        ),
        "Verify exact source-free control evidence": ["devlane_permit=verify_control=pass"],
        "Claim this bundle for one run before decryption": ["devlane_permit=claim=pass"],
        "Verify permit and emit bound dispatch marker": [
            "devlane_permit=consumed run-id=%s run-attempt=1" % identity["run_id"],
            "KD-DEVLANE-DISPATCH schema=1 wave-id=%s bundle-id=%s control-sha=%s run-id=%s run-attempt=1" % (
                identity["wave_id"], identity["bundle_id"], identity["control_sha"], identity["run_id"])],
        "Fetch ciphertext and sanitized dependency projection": [
            "public_asset_verified=true bytes=4096", "public_asset_verified=true bytes=512",
            "fetch_projection_valid=true"],
        "Prepare dependencies before the cut": ["dependency_preparation=complete"],
        "Prove public connectivity before the cut": ["network_positive_control=pass"],
        "Cut network and start the isolated supervisor": ["offline_supervisor=ready"],
        "Probe isolation before decryption": ["network_cut_probe=pass"],
        "Decrypt authenticated bundle": ["authenticated_decryption=pass"],
        "Execute offline profile and filter public summary": list(records),
        "Shred runner-local workspace": ["cleanup_receipt=confirmed",
                                         "devlane_job=completed public_output=filtered cleanup=confirmed"],
        "Audit exact two-job graph and public surfaces": [
            "devlane_audit=accepted jobs=2 artifacts=0 cache=unchanged cleanup=confirmed"],
        "Claim a synthetic bundle permit": ["devlane_cache_permit=claimed"],
        "Verify the restored permit and refuse a second claim": ["devlane_cache_permit=restored-and-single-use"],
        "Run full source-free production-path acceptance": ["devlane_acceptance=pass"],
        "Probe the loopback-only Linux network boundary": ["devlane_linux_probe=pass"],
    }
    return outputs.get(name, [])


def _render_log(job_key, identity=None, *, records=(), kind="encrypted", skip=("Install pinned Rust toolchain",)):
    """A hosted-shaped log generated from the reviewed workflow itself."""
    identity = identity or IDENTITY
    workflow = ".github/workflows/devlane-synthetic.yml" if kind == "synthetic" else ".github/workflows/devlane-encrypted.yml"
    job = audit.parse_workflow(workflow)[job_key]
    stamp = "2026-11-10T12:00:00.1234567Z "
    lines = [MARK + "[section]Starting: Set up job",
             MARK + "[group]Runner Image Provisioner", "Hosted Compute Agent", "Version: 20251030.1",
             "Commit: 0123456789abcdef0123456789abcdef01234567", MARK + "[endgroup]",
             MARK + "[group]Operating System", "Ubuntu", "24.04.3", "LTS", MARK + "[endgroup]",
             MARK + "[group]Runner Image", "Image: ubuntu-24.04", "Version: 20251105.93.1",
             "Included Software: https:" + chr(47) * 2 + "github.com/actions/runner-images/blob/ubuntu24/20251105.93/images/ubuntu/Ubuntu2404-Readme.md",
             MARK + "[endgroup]", MARK + "[group]GITHUB_TOKEN Permissions", "Metadata: read", MARK + "[endgroup]",
             "Secret source: Actions", "Prepare workflow directory", "Prepare all required actions",
             "Getting action download info", "Complete job name: " + job_key,
             MARK + "[section]Finishing: Set up job"]
    skipped = set(skip)
    if identity["profile"] == "desktop":
        skipped.discard("Install pinned Rust toolchain")
    else:
        skipped.add("Install Tauri Linux build dependencies")
    for step in job["steps"]:
        if step["name"] in skipped or (step["uses"] and "setup-node" in step["uses"] and identity["profile"] in audit.RUST_PROFILES):
            continue
        lines.append(MARK + "[section]Starting: " + step["name"])
        if step["run"]:
            lines.append(MARK + "[group]Run " + step["run"][0].strip())
            lines.extend(step["run"])
            lines.append("shell: /usr/bin/bash -e {0}")
        else:
            lines.append(MARK + "[group]Run " + step["uses"])
            lines.append("with:")
            for key in step["with"]:
                lines.append("  %s: %s" % (key, _with_value(step, key, identity, kind)))
        env = dict(job["env"])
        env.update(step["env"])
        if kind == "encrypted" and job_key == audit.RUN_JOB and step["name"] != audit.STEP_NAMES[0]:
            env["RUN_ROOT"] = "${{ runner.temp }}/devlane-" + identity["run_id"]
        if env:
            lines.append("env:")
            lines.extend("  %s: %s" % (name, _env_value(name, identity, kind)) for name in env)
        lines.append(MARK + "[endgroup]")
        lines.extend(_step_outputs(step, identity, kind, records))
        lines.append(MARK + "[section]Finishing: " + step["name"])
    if any(step["uses"] and "setup-node" in step["uses"] for step in job["steps"]) and identity["profile"] == "core-node":
        lines += [MARK + "[section]Starting: Post Set up pinned Node toolchain",
                  MARK + "[section]Finishing: Post Set up pinned Node toolchain"]
    lines += [MARK + "[section]Starting: Complete job", "Cleaning up orphan processes",
              MARK + "[section]Finishing: Complete job"]
    return "".join(stamp + line + "\n" for line in lines).encode("utf-8")


def _render_real_runner_encrypted_log(identity, job_key=audit.RUN_JOB):
    grammar = audit._Grammar(
        ".github/workflows/devlane-encrypted.yml", job_key, identity, "encrypted",
    )
    marker = audit.LOG_MARKER
    lines = ["Current runner version: '2.338.2'"]

    def group(name, values):
        lines.extend([marker + "[group]" + name, *values, marker + "[endgroup]"])

    runner_images = "https://" + "github.com" + "/actions/runner-images"
    group("Runner Image Provisioner", [
        "Hosted Compute Agent", "Version: 20261028.624", "Commit: " + "0" * 40,
        "Build Date: 2026-10-28T21:51:42Z", "Worker ID: {279bda81-5141-421a-9d8d-864e1958a8d7}",
        "Region: centralus", "Cloud: Azure",
    ])
    group("Operating System", ["Ubuntu", "24.04.5", "LTS"])
    group("Runner Image", [
        "Image: ubuntu-24.04", "Version: 20261101.360.1",
        "Included Software: %s/blob/ubuntu24/20261101.360/images/ubuntu/Ubuntu2404-Readme.md" % runner_images,
        "Image Release: %s/releases/tag/ubuntu24%%2F20261101.360" % runner_images,
    ])
    permissions = ["Metadata: read"]
    if job_key == audit.AUDIT_JOB:
        permissions = ["Actions: read", "Checks: read", "Metadata: read"]
    group("GITHUB_TOKEN Permissions", permissions)
    lines.append("Secret source: Actions")
    if job_key == audit.RUN_JOB:
        lines.append("Deployment environment: devlane-decrypt")
    lines.extend(("Cache mode: write", "Prepare workflow directory", "Prepare all required actions"))
    if any((step["uses"] or "") and not (step["uses"] or "").startswith("./")
           for step in grammar.steps):
        lines.append("Getting action download info")
    seen = set()
    for step in grammar.steps:
        uses = step["uses"] or ""
        if uses and not uses.startswith("./"):
            action, _, revision = uses.rpartition("@")
            repository = "/".join(action.split("/")[:2]) + "@" + revision
            if repository not in seen:
                seen.add(repository)
                lines.append("Download action repository '%s' (SHA:%s)" % (repository, revision))
    lines.append("Complete job name: " + job_key)

    for step in grammar.steps:
        if step["name"] == "Install pinned Rust toolchain":
            continue
        uses = step["uses"] or ""
        run = step["run"]
        lines.append(marker + "[group]Run " + (run[0].strip() if run else uses))
        if run:
            lines.extend("\x1b[36;1m" + line + "\x1b[0m" for line in run)
            lines.append("shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}")
        else:
            lines.append("with:")
            for key in step["with"]:
                value = _with_value(step, key, identity, "encrypted")
                if value != "":
                    lines.append("  %s: %s" % (key, value))
            if uses.startswith("actions/cache/"):
                lines.append("  enableCrossOsArchive: false")
                if "/restore@" in uses:
                    lines.append("  lookup-only: false")
        env_names = grammar.expected_env_names(step)
        if env_names:
            lines.append("env:")
            lines.extend("  %s: %s" % (key, _env_value(key, identity, "encrypted"))
                         for key in sorted(env_names))
        lines.append(marker + "[endgroup]")
        lines.extend(_step_outputs(step, identity, "encrypted", ()))
    lines.append("Cleaning up orphan processes")
    stamp = "2026-11-10T12:00:00.1234567Z "
    return "".join(stamp + line + "\n" for line in lines).encode("utf-8")


def _record(**fields):
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def _encrypted_jobs(profile="core-node"):
    names = audit._expected_step_names("core-node")
    steps = []
    for name in names:
        conclusion = "success"
        if ((name == "Install pinned Rust toolchain" and profile == "core-node")
                or (name == "Install Tauri Linux build dependencies" and profile != "desktop")):
            conclusion = "skipped"
        steps.append({"name": name, "status": "completed", "conclusion": conclusion})
    return [
        {
            "id": 100, "name": audit.RUN_JOB, "run_id": 12345, "run_attempt": 1,
            "head_sha": SHA, "status": "completed", "conclusion": "success",
            "check_run_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/500",
            "steps": steps,
        },
        {
            "id": 101, "name": audit.AUDIT_JOB, "run_id": 12345, "run_attempt": 1,
            "head_sha": SHA, "status": "in_progress", "conclusion": None,
            "check_run_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/501",
            "steps": [
                {"name": "Set up job", "status": "completed", "conclusion": "success"},
                {"name": audit.AUDIT_STEP_NAMES[0], "status": "completed", "conclusion": "success"},
                {"name": audit.AUDIT_STEP_NAMES[1], "status": "in_progress", "conclusion": None},
                {"name": "Complete job", "status": "in_progress", "conclusion": None},
            ],
        },
    ]


def _control_jobs():
    output = []
    for index, name in enumerate(sorted(control_audit.CONTROL_JOB_NAMES), 1):
        value = {
            "id": index, "name": name, "run_id": 12345, "run_attempt": 1,
            "head_sha": SHA,
            "check_run_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/%d" % (800 + index),
        }
        if name == control_audit.RUN_JOB:
            value.update({
                "status": "in_progress", "conclusion": None,
                "steps": [
                    {"name": "Set up job", "status": "completed", "conclusion": "success"},
                    {"name": "Fetch public control and validate manual protected-branch dispatch",
                     "status": "completed", "conclusion": "success"},
                    {"name": "Audit the exact 18-job control graph",
                     "status": "in_progress", "conclusion": None},
                    {"name": control_audit.CONTROL_AUDIT_FINAL_STEPS[2],
                     "status": "queued", "conclusion": None},
                    {"name": "Complete job", "status": "in_progress", "conclusion": None},
                ],
            })
        else:
            steps = []
            for step_name in control_audit.CONTROL_STEP_NAMES[name]:
                skipped = (name.startswith("development-feedback-smoke / feedback-smoke-producer ")
                           and not name.endswith("macos-15")
                           and step_name in ("Upload the single macOS ciphertext fixture", "Record uploader identity"))
                steps.append({"name": step_name, "status": "completed",
                              "conclusion": "skipped" if skipped else "success"})
            value.update({"status": "completed", "conclusion": "success", "steps": steps})
        output.append(value)
    return output


def _terminal_control_jobs(require_main=True):
    jobs = copy.deepcopy(_control_jobs())
    for job in jobs:
        if job["name"] == control_audit.RUN_JOB:
            job["steps"] = [
                {"name": name, "status": "completed",
                 "conclusion": "skipped" if name == control_audit.CONTROL_AUDIT_FINAL_STEPS[2] and not require_main else "success"}
                for name in control_audit.CONTROL_AUDIT_FINAL_STEPS
            ]
        job["status"] = "completed"
        job["conclusion"] = "success"
    return jobs


class EncryptedAuditorMutationTests(unittest.TestCase):
    def test_two_job_contract_accepts_exact_names_steps_attempt_and_cleanup(self):
        jobs = _encrypted_jobs()
        result = audit.validate_job_contract(jobs, IDENTITY, "core-node")
        self.assertEqual(set(result), {audit.RUN_JOB, audit.AUDIT_JOB})

    def test_desktop_contract_runs_tauri_dependencies_and_pinned_rust_setup(self):
        identity = dict(IDENTITY, profile="desktop")
        jobs = _encrypted_jobs("desktop")
        result = audit.validate_job_contract(jobs, identity, "desktop")
        self.assertEqual(set(result), {audit.RUN_JOB, audit.AUDIT_JOB})
        grammar = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, identity, "encrypted",
        )
        self.assertTrue(grammar.step_output_ok(
            "Install Tauri Linux build dependencies", "tauri_linux_dependencies=installed", {}))
        self.assertTrue(grammar.step_output_ok(
            "Install pinned Rust toolchain", "rust_toolchain=prepared", {}))

    def test_extra_job_wrong_attempt_wrong_step_and_missing_cleanup_are_rejected(self):
        mutations = []
        jobs = _encrypted_jobs()
        mutations.append(jobs + [dict(jobs[0], name="unexpected-job")])
        changed = copy.deepcopy(jobs)
        changed[1]["run_attempt"] = 2
        mutations.append(changed)
        changed = copy.deepcopy(jobs)
        changed[0]["steps"][0]["name"] = "Fetch PR source"
        mutations.append(changed)
        changed = copy.deepcopy(jobs)
        changed[0]["steps"][-2]["conclusion"] = "failure"
        mutations.append(changed)
        for mutation in mutations:
            with self.subTest(names=[job["name"] for job in mutation]):
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_contract(mutation, IDENTITY, "core-node")

    def test_log_marker_must_bind_one_wave_and_cleanup_receipt(self):
        log = (
            b"2026-11-10T12:00:00Z KD-DEVLANE-DISPATCH schema=1 wave-id=wave-test-0001 "
            b"bundle-id=bundle-test-0001 control-sha=" + SHA.encode("ascii")
            + b" run-id=12345 run-attempt=1\ndevlane_permit=consumed run-id=12345 run-attempt=1\ncleanup_receipt=confirmed\n"
        )
        audit.validate_dispatch_marker(log, IDENTITY)
        for changed in (log.replace(b"run-attempt=1", b"run-attempt=2"),
                        log.replace(b"cleanup_receipt=confirmed", b"cleanup_receipt=unconfirmed")):
            with self.assertRaises(audit.AuditRefusal):
                audit.validate_dispatch_marker(changed, IDENTITY)

    RECORDS = (
        _record(code="TS2322", file="file_0001", kind="diagnostic", level="error", line=7, stage="unit"),
        _record(kind="test", stage="unit", test="case_0001"),
    )

    def _valid_run_log(self, records=None):
        return _render_log(audit.RUN_JOB, records=self.RECORDS if records is None else records)

    def test_ordinary_hosted_scaffolding_with_a_valid_summary_is_accepted(self):
        """Fails on the old auditor, which rejected env blocks, cache action output and provider notices that every normal Actions run prints."""
        result = audit.validate_job_log_surface(self._valid_run_log(), audit.RUN_JOB, IDENTITY)
        self.assertEqual(len(result["records"]), 2)
        audit.validate_job_log_surface(
            _render_log(audit.AUDIT_JOB), audit.AUDIT_JOB, IDENTITY)
        rust = dict(IDENTITY, profile="core-rust")
        audit.validate_job_log_surface(
            _render_log(audit.RUN_JOB, rust, skip=("Set up pinned Node toolchain",)), audit.RUN_JOB, rust)
        desktop = dict(IDENTITY, profile="desktop")
        audit.validate_job_log_surface(
            _render_log(audit.RUN_JOB, desktop), audit.RUN_JOB, desktop)

    def test_known_github_sgr_is_accepted_on_the_encrypted_lane_log_path(self):
        log = self._valid_run_log()
        colored = log.replace(
            b"Run set -euo pipefail",
            b"Run \x1b[36;1mset -euo pipefail\x1b[0m",
            1,
        )
        audit.validate_job_log_surface(colored, audit.RUN_JOB, IDENTITY)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(colored.replace(b"set -euo pipefail", b"set \x1b[2J -euo pipefail", 1),
                                           audit.RUN_JOB, IDENTITY)

    def test_github_runner_shaped_encrypted_log_accepts_its_environment_and_sgr(self):
        log = _render_real_runner_encrypted_log(IDENTITY)
        audit.validate_job_log_surface(log, audit.RUN_JOB, IDENTITY)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(log.replace(b"\x1b[36;1m", b"\x1b[31m", 1),
                                           audit.RUN_JOB, IDENTITY)

    def test_real_encrypted_rehearsal_logs_and_two_job_graph_match_github_output(self):
        fixtures = Path(__file__).resolve().parent / "fixtures"
        identity = json.loads((fixtures / "encrypted-run-43284558151-identity.json").read_text(
            encoding="utf-8"))
        run_log = bytes.fromhex((fixtures / "encrypted-run-43284558151.log.hex").read_text(
            encoding="ascii"))
        audit_log = bytes.fromhex((fixtures / "encrypted-audit-43284558151.log.hex").read_text(
            encoding="ascii"))
        run_result = audit.validate_job_log_surface(run_log, audit.RUN_JOB, identity, completed=True)
        self.assertEqual(run_result["records"], [])
        audit.validate_dispatch_marker(run_log, identity)
        stage_diagnostic_log = run_log.replace(
            b"devlane_supervisor_refusal=network-probe-command-failed\n",
            b"network_probe_refusal=probe-stage-failed\n"
            b"devlane_supervisor_refusal=network-probe-stage-failed\n",
            1,
        )
        audit.validate_job_log_surface(stage_diagnostic_log, audit.RUN_JOB, identity, completed=True)

        run_jobs = json.loads(bytes.fromhex(
            (fixtures / "encrypted-run-43284558151-jobs.json.hex").read_text(
                encoding="ascii"),
        ).decode("utf-8"))["jobs"]
        jobs, audit_passed = audit.validate_terminal_job_contract(run_jobs, identity, "core-node")
        self.assertFalse(audit_passed)
        run_job = jobs[audit.RUN_JOB]
        audit_job = jobs[audit.AUDIT_JOB]
        step_by_name = {step["name"]: step for step in run_job["steps"]}
        self.assertEqual(run_job["conclusion"], "failure")
        self.assertEqual(step_by_name["Probe isolation before decryption"]["conclusion"], "failure")
        self.assertEqual(step_by_name["Decrypt authenticated bundle"]["conclusion"], "skipped")
        self.assertEqual(step_by_name["Execute offline profile and filter public summary"]["conclusion"], "skipped")
        self.assertEqual(step_by_name["Shred runner-local workspace"]["conclusion"], "success")
        self.assertEqual(audit_job["conclusion"], "failure")
        self.assertEqual(audit_job["steps"][-2]["conclusion"], "failure")
        inconsistent_audit_jobs = copy.deepcopy(run_jobs)
        inconsistent_audit_jobs[1]["conclusion"] = "success"
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_terminal_job_contract(inconsistent_audit_jobs, identity, "core-node")

        raw_audit = audit_log.decode("utf-8-sig")
        for sequence in audit.ANSI_SGR:
            raw_audit = raw_audit.replace(sequence.decode("ascii"), "")
        audit_lines = [audit.TIME_PREFIX.sub("", line, count=1).rstrip() for line in raw_audit.splitlines()]
        workflow_path = audit.REPOSITORY_ROOT / audit.LEGACY_ENCRYPTED_WORKFLOW_PATH
        grammar = audit._Grammar(workflow_path, audit.AUDIT_JOB, identity, "encrypted")
        _canonical, position = audit._hosted_preamble(
            audit_lines, grammar, audit.AUDIT_JOB, identity, str(workflow_path),
        )
        self.assertTrue(audit_lines[position].startswith(audit.LOG_MARKER + "[group]Run "))
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(audit_log, audit.AUDIT_JOB, identity, completed=True)

        success_log = _render_real_runner_encrypted_log(IDENTITY)
        success_audit_log = _render_real_runner_encrypted_log(IDENTITY, job_key=audit.AUDIT_JOB)
        audit.validate_job_log_surface(success_log, audit.RUN_JOB, IDENTITY, completed=True)
        audit.validate_job_log_surface(success_audit_log, audit.AUDIT_JOB, IDENTITY, completed=True)
        success_jobs = _encrypted_jobs()
        success_jobs[1]["status"] = "completed"
        success_jobs[1]["conclusion"] = "success"
        success_jobs[1]["steps"][-2].update({"status": "completed", "conclusion": "success"})
        success_jobs[1]["steps"][-1].update({"status": "completed", "conclusion": "success"})
        _success_by_name, success_audit_passed = audit.validate_terminal_job_contract(
            success_jobs, IDENTITY, "core-node",
        )
        self.assertTrue(success_audit_passed)

        for label, changed in (
                ("free text", run_log.replace(b"devlane_swap=disabled",
                                               b"devlane_swap=disabled\nfree text injected", 1)),
                ("path", run_log.replace(
                    b"devlane_swap=disabled",
                    b"devlane_swap=disabled\n" + bytes((47,)).join(
                        (b"home", b"runner", b"work", b"foreign", b"private"),
                    ), 1)),
                ("unknown escape", run_log.replace(b"devlane_swap=disabled",
                                                    b"devlane_swap=disabled\x1b[2J", 1)),
                ("wrong process exit code", run_log.replace(
                    b"Process completed with exit code 2.",
                    b"Process completed with exit code 3.", 1)),
                ("missing process exit code", run_log.replace(
                    audit.LOG_MARKER.encode("ascii") + b"[error]Process completed with exit code 2.\n",
                    b"", 1)),
                ("mismatched probe diagnosis", run_log.replace(
                    b"devlane_supervisor_refusal=network-probe-command-failed",
                    b"network_probe_refusal=probe-command-failed\n"
                    b"devlane_supervisor_refusal=network-probe-output-invalid", 1))):
            with self.subTest(label=label), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, audit.RUN_JOB, identity, completed=True)

    def test_real_github_synthetic_log_fixture_is_accepted_and_closed(self):
        fixture = Path(__file__).resolve().parent / "fixtures/control-synthetic-43245798187.log.hex"
        log = bytes.fromhex(fixture.read_text(encoding="ascii"))
        identity = {
            "run_id": "43245798187",
            "control_sha": "bda18e03c451a00ec91bb7c34d616a55295a7eee",
            "ref": "refs/heads/devlane/d211-1110",
            "wave_id": "control-20261112T151518Z-082fe3",
        }
        audit.validate_job_log_surface(log, "devlane-synthetic", identity, workflow="synthetic")
        mutations = {
            "free text": log.replace(
                b"devlane_swap=disabled",
                b"devlane_swap=disabled\nfree text injected",
                1,
            ),
            "path": log.replace(
                b"devlane_swap=disabled",
                b"devlane_swap=disabled\n" + (chr(47) + "home" + chr(47) + "runner/work/foreign/private").encode("ascii"),
                1,
            ),
            "unknown escape": log.replace(
                b"devlane_swap=disabled",
                b"devlane_swap=disabled\x1b[2J",
                1,
            ),
        }
        for label, changed in mutations.items():
            with self.subTest(label), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, "devlane-synthetic", identity, workflow="synthetic")

        local_sync = dict(IDENTITY, profile="local-sync-rust")
        profile = json.loads((Path(__file__).resolve().parents[2] / "ci/devlane-profiles.json").read_text())[
            "profiles"]["local-sync-rust"]
        rows = [
            _record(kind="coverage", stage=stage, suite=suite,
                    total=1, passed=1, failed=0, ignored=0)
            for suite in profile["rust_matrix"]["coverage_ids"]
            for stage in ["format" if suite.startswith("fmt-") else "audit" if suite.startswith("audit-") else "unit"]
        ]
        rows.sort()
        audit.validate_job_log_surface(
            _render_log(audit.RUN_JOB, local_sync, records=rows), audit.RUN_JOB, local_sync)

    def test_host_preflight_receipts_are_bound_to_the_right_step_and_profile(self):
        rust = dict(IDENTITY, profile="core-rust")
        grammar = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, rust, "encrypted",
        )
        counts = {}
        step = "Prepare hosted Linux isolation state"
        self.assertTrue(grammar.step_output_ok(step, "devlane_swap=disabled", counts))
        self.assertTrue(grammar.step_output_ok(step, "devlane_cgroup_v2=ready", counts))
        self.assertFalse(grammar.step_output_ok(step, "devlane_cgroup_v2=ready", counts))
        self.assertFalse(grammar.step_output_ok("Probe isolation before decryption", "devlane_swap=disabled", {}))
        node = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, IDENTITY, "encrypted",
        )
        self.assertFalse(node.step_output_ok(step, "devlane_cgroup_v2=ready", {}))
        synthetic_identity = dict(IDENTITY, ref="refs/heads/devlane/d211-1110")
        synthetic = audit._Grammar(
            ".github/workflows/devlane-synthetic.yml", "devlane-synthetic", synthetic_identity, "synthetic",
        )
        self.assertTrue(synthetic.step_output_ok(step, "devlane_swap=disabled", {}))
        self.assertFalse(synthetic.step_output_ok(step, "devlane_cgroup_v2=ready", {}))

    def test_environment_lines_are_accepted_only_for_the_reviewed_environment_and_job(self):
        log = self._valid_run_log().decode("utf-8")
        anchor = "Secret source: Actions\n"
        stamp = "2026-11-10T12:00:00.1234567Z "
        self.assertIn(anchor, log.replace(stamp + "Secret source: Actions\n", anchor))
        def with_line(text, line):
            return text.replace(stamp + "Secret source: Actions\n", stamp + "Secret source: Actions\n" + stamp + line + "\n", 1).encode("utf-8")
        audit.validate_job_log_surface(with_line(log, "Environment: devlane-decrypt"), audit.RUN_JOB, IDENTITY)
        audit.validate_job_log_surface(with_line(log, "Deployment environment: devlane-decrypt"), audit.RUN_JOB, IDENTITY)
        for refused in ("Environment: production", "Deployment environment: devlane-decrypt-2", "Environment: devlane-decrypt extra"):
            with self.subTest(line=refused), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(with_line(log, refused), audit.RUN_JOB, IDENTITY)
        audit_log = _render_log(audit.AUDIT_JOB).decode("utf-8")
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(with_line(audit_log, "Environment: devlane-decrypt"), audit.AUDIT_JOB, IDENTITY)
        synthetic = _render_log("devlane-synthetic", dict(IDENTITY), kind="synthetic").decode("utf-8")
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(with_line(synthetic, "Environment: devlane-decrypt"), "devlane-synthetic",
                                           dict(IDENTITY), workflow="synthetic")

    def test_auditor_refuses_a_workflow_that_loses_or_changes_the_environment(self):
        import tempfile
        log = self._valid_run_log()
        source = (self.root_for_tests() / ".github/workflows/devlane-encrypted.yml").read_text(encoding="utf-8")
        for name, broken in (("lost", source.replace("    environment: devlane-decrypt\n", "")),
                             ("renamed", source.replace("environment: devlane-decrypt", "environment: other-environment"))):
            with self.subTest(change=name), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / ".github/workflows/devlane-encrypted.yml"
                target.parent.mkdir(parents=True)
                target.write_text(broken, encoding="utf-8")
                with patch.object(audit, "REPOSITORY_ROOT", Path(temporary)), self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_log_surface(log, audit.RUN_JOB, IDENTITY)

    @staticmethod
    def root_for_tests():
        return Path(__file__).resolve().parents[2]

    def test_closed_public_log_rejects_disguised_plaintext_and_excess_records(self):
        valid = self._valid_run_log()
        stamp = b"2026-11-10T12:00:00.1234567Z "
        tool_line = b"dependency_preparation=complete"
        mutations = {
            "canary in preparation output": valid.replace(
                tool_line, b"dependency_preparation=complete /PRIVATE_SOURCE_CANARY/PRIVATE_KEY_CANARY"),
            "plaintext line": valid + stamp + b"PRIVATE_SOURCE_CANARY=unfiltered-plaintext\n",
            "plaintext inside a step": valid.replace(
                b"dependency_preparation=complete", b"dependency_preparation=complete\n" + stamp + b"PRIVATE_SOURCE_CANARY"),
            "foreign env value": valid.replace(b"CI_RUN_ATTEMPT: 1", b"CI_RUN_ATTEMPT: PRIVATE_SOURCE_CANARY", 1),
            "unknown env name": valid.replace(b"CI_RUN_ATTEMPT: 1", b"PRIVATE_SOURCE_CANARY: 1", 1),
            "wrong cache key": valid.replace(b"Cache saved with key: devlane-permit-v1-bundle-test-0001",
                                             b"Cache saved with key: devlane-permit-v1-PRIVATE_SOURCE_CANARY"),
            "record outside the execute step": valid.replace(
                b"authenticated_decryption=pass", b"authenticated_decryption=pass\n" + stamp + self.RECORDS[1].encode()),
            "bad diagnostic code": self._valid_run_log([self.RECORDS[0].replace("TS2322", "DEVLANE_PRIVATE_SOURCE"),
                                                         self.RECORDS[1]]),
            "private file id": self._valid_run_log([self.RECORDS[0].replace("file_0001", "private/path.rs"),
                                                     self.RECORDS[1]]),
            "free-text record field": self._valid_run_log([self.RECORDS[0].replace('"line":7', '"message":"source"'),
                                                            self.RECORDS[1]]),
            "section injection": valid + stamp + (MARK + "[section]PRIVATE_SOURCE_CANARY\n").encode(),
            "group injection": valid + stamp + (MARK + "[group]PRIVATE_SOURCE_CANARY\n").encode(),
            "workflow command": valid + stamp + b"::add-mask::PRIVATE_SOURCE_CANARY\n",
            "orphan process line": valid.replace(b"Cleaning up orphan processes",
                                                 b"Terminate orphan process: pid 12 (private)"),
            "unsorted records": self._valid_run_log(list(reversed(self.RECORDS))),
            "duplicate records": self._valid_run_log([self.RECORDS[1], self.RECORDS[1]]),
            "marker printed twice": valid.replace(
                b"authenticated_decryption=pass", b"authenticated_decryption=pass\n" + stamp + b"authenticated_decryption=pass"),
        }
        for label, payload in mutations.items():
            with self.subTest(label), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(payload, audit.RUN_JOB, IDENTITY)

    def test_the_summary_is_validated_as_one_unit_not_record_by_record(self):
        """Fails on the old auditor: 101 individually valid records passed."""
        many = [_record(kind="test", stage="unit", test="case_%04d" % index) for index in range(1, 102)]
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(self._valid_run_log(many), audit.RUN_JOB, IDENTITY)
        within = [_record(kind="test", stage="unit", test="case_%04d" % index) for index in range(1, 101)]
        audit.validate_job_log_surface(self._valid_run_log(within), audit.RUN_JOB, IDENTITY)
        unknown_stage = [_record(kind="control", stage="cleanup", status="fail")]
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(self._valid_run_log(unknown_stage), audit.RUN_JOB,
                                           dict(IDENTITY, profile="core-node") | {"profile": "core-bad"})

    def test_completed_check_output_accepts_documented_fields_and_rejects_text(self):
        job = _encrypted_jobs()[0]
        check = {
            "head_sha": SHA, "name": audit.RUN_JOB, "status": "completed",
            "output": {
                "title": None, "summary": None, "text": None, "annotations_count": 0,
                "annotations_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/500/annotations",
            },
        }
        audit.validate_check_output(check, job, IDENTITY, completed=True)
        audit.validate_check_output({**check, "output": {**check["output"], "title": audit.RUN_JOB}},
                                    job, IDENTITY, completed=True)
        for changed in (
            {**check, "output": {**check["output"], "summary": "PRIVATE_SOURCE_CANARY"}},
            {**check, "output": {**check["output"], "text": "unexpected diagnostic text"}},
            {**check, "output": {**check["output"], "annotations_count": 1}},
            {**check, "output": {**check["output"], "annotations_url": "https://example.invalid/x"}},
            {**check, "output": {**check["output"], "unexpected": 1}},
        ):
            with self.subTest(changed=changed["output"]), self.assertRaises(audit.AuditRefusal):
                audit.validate_check_output(changed, job, IDENTITY, completed=True)

    def test_synthetic_job_log_satisfies_the_same_closed_contract_in_the_control(self):
        identity = {"run_id": "12345", "control_sha": SHA, "ref": "refs/heads/devlane/d211-1110"}
        log_identity = dict(IDENTITY)
        log_identity["ref"] = identity["ref"]
        log = _render_log("devlane-synthetic", log_identity, kind="synthetic",
                          skip=("Install fixed Rust acceptance toolchain",))
        control_audit.validate_synthetic_log(log, identity)
        workflow_group = (chr(35) * 2 + "[group]KEYCANARY-73A10X\n").encode("ascii")
        failure_lines = acceptance_diagnostics.failure_tail(
            "production-path-e2e", b"\x1b[31mFAILED::error::SYNTHETIC_SOURCE_CANARY_7f8c\n" + workflow_group,
        )
        failure = "devlane_acceptance=refused stage=production-path-e2e\n" + "\n".join(failure_lines)
        before, after = log.rsplit(b"devlane_acceptance=pass", 1)
        refused = before + failure.encode("ascii") + after.replace(
            b"2026-11-10T12:00:00.1234567Z devlane_linux_probe=pass\n", b"",
        )
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_synthetic_log(refused, identity)
        control_audit.validate_synthetic_log(refused, identity, failed_acceptance=True)
        wrong_stage = refused.replace(
            b"devlane_acceptance_detail stage=production-path-e2e",
            b"devlane_acceptance_detail stage=rust-v2-public-runtime", 1,
        )
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_synthetic_log(wrong_stage, identity, failed_acceptance=True)
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_synthetic_log(
                log, {**identity, "ref": "refs/heads/main"},
            )
        for label, payload in {
            "canary": log + b"2026-11-10T12:00:00.1234567Z PRIVATE_SOURCE_CANARY\n",
            "noisy test output": log.replace(b"devlane_acceptance=pass", b"Ran 31 tests in 1.2s\nOK\ndevlane_acceptance=pass"),
            "missing probe": log.replace(b"devlane_linux_probe=pass", b"devlane_linux_probe=skipped"),
            "missing cache restore": log.replace(b"Cache restored successfully", b"Cache not found for input keys: x"),
        }.items():
            with self.subTest(label), self.assertRaises(control_audit.ControlAuditRefusal):
                control_audit.validate_synthetic_log(payload, identity)

    def test_source_free_failure_tail_is_bounded_redacted_and_workflow_safe(self):
        workflow_group = (chr(35) * 2 + "[group]KEYCANARY-73A10X\n").encode("ascii")
        payload = (b"earliest\n" + b"ordinary diagnostic\n" * 205
                   + b"\x1b[31m::error::SYNTHETIC_SOURCE_CANARY_7f8c\x1b[0m\n"
                   + workflow_group + b"x" * 400 + b"\n")
        details = acceptance_diagnostics.failure_tail("production-path-e2e", payload)
        self.assertLessEqual(len(details), 202)
        joined = "\n".join(details)
        self.assertIn("earlier lines omitted", joined)
        self.assertIn("[synthetic-canary-redacted]", joined)
        self.assertNotIn("SYNTHETIC_SOURCE_CANARY_7f8c", joined)
        self.assertNotIn("KEYCANARY-73A10X", joined)
        self.assertNotIn("::", joined)
        self.assertNotIn(chr(35) * 2 + "[", joined)
        self.assertNotIn("\x1b", joined)
        canary_tail = acceptance_diagnostics.failure_tail(
            "production-path-e2e",
            b"PRIVATE_SOURCE_CANARY SYNTHETIC_KEY_CANARY PRIVATE_KEY_CANARY "
            + b"KEYCANARY-73A10X" + bytes(range(16)),
        )
        canary_text = "\n".join(canary_tail)
        for marker in ("PRIVATE_SOURCE_CANARY", "SYNTHETIC_KEY_CANARY", "PRIVATE_KEY_CANARY", "KEYCANARY"):
            self.assertNotIn(marker, canary_text)
        self.assertTrue(all(diagnostic_contract.public_acceptance_detail(line) for line in details))
        self.assertTrue(all(diagnostic_contract.public_acceptance_detail(line) for line in canary_tail))
        self.assertTrue(all(len(line) <= diagnostic_contract.MAX_ACCEPTANCE_DETAIL_BYTES for line in details))
        with self.assertRaises(ValueError):
            acceptance_diagnostics.failure_tail("private-stage", b"detail")

    def test_source_free_failure_tail_preserves_vitest_diagnostics_before_the_general_tail(self):
        raw_log = "devlane_e2e_vitest_diag=log name=unit.log line=1 text=Error%3A%20spawn%20EPERM"
        payload = (raw_log + "\n" + "ordinary diagnostic\n" * 250).encode("ascii")
        details = acceptance_diagnostics.failure_tail("production-path-e2e", payload)
        self.assertIn(raw_log, details)
        self.assertLessEqual(len(details), 202)
        self.assertTrue(all(diagnostic_contract.public_e2e_vitest_diagnostic(line)
                            or diagnostic_contract.public_acceptance_detail(line) for line in details))

    def test_production_failure_tail_keeps_only_the_current_scenario_raw_logs(self):
        previous = "devlane_e2e_failure_diag=log name=unit.log line=1 text=previous-node-output"
        current = (
            "devlane_e2e_failure_diag=log name=compile-listener-all-features.stdout "
            "line=1 text=current-rust-output"
        )
        payload = (previous + "\n"
                   "devlane_e2e_progress=scenario=synthetic-rust-v1-refusal\n"
                   + current + "\n"
                   + "ordinary diagnostic\n" * 250).encode("ascii")
        details = acceptance_diagnostics.failure_tail("production-path-e2e", payload)
        self.assertIn(current, details)
        self.assertNotIn(previous, details)
        self.assertLessEqual(len(details), 202)
        self.assertTrue(all(diagnostic_contract.public_e2e_vitest_diagnostic(line)
                            or diagnostic_contract.public_acceptance_detail(line) for line in details))

    def test_preparation_refusal_diagnostics_are_allowlisted_and_never_count_as_acceptance(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        line = (
            "devlane_production_e2e=refused stage=prepare-node-toolchain-validation "
            "exception=node-toolchain-owner"
        )
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance", line, {},
        ))
        refusal_counts = {}
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance",
            "devlane_acceptance=refused stage=production-path-e2e", refusal_counts,
        ))
        detail = "devlane_acceptance_detail stage=production-path-e2e index=1 text=ModuleNotFoundError: test fixture import failed"
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance", detail, refusal_counts,
        ))
        self.assertFalse(grammar.step_output_ok(
            "Run full source-free production-path acceptance",
            detail.replace("production-path-e2e", "rust-v2-public-runtime"), refusal_counts,
        ))
        for invalid in (
            line.replace("node-toolchain-owner", "private-path"),
            line.replace("prepare-node-toolchain-validation", "private-path"),
            line + " cleanup=confirmed",
            line.replace("node-toolchain-owner", "node-toolchain-owner") + " KEYCANARY-73A10X",
            detail.replace("production-path-e2e", "private-stage"),
            detail.replace("ModuleNotFoundError", "::error::"),
            detail + " KEYCANARY-73A10X",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(grammar.step_output_ok(
                    "Run full source-free production-path acceptance", invalid, {},
                ))
        self.assertFalse(grammar.step_output_ok(
            "Set up pinned Node toolchain", line, {},
        ))
        encrypted = audit._Grammar(
            Path(__file__).resolve().parents[2] / ".github/workflows/devlane-encrypted.yml",
            audit.RUN_JOB, IDENTITY, "encrypted",
        )
        self.assertFalse(encrypted.step_output_ok("Prepare dependencies before the cut", detail, {}))

    def test_e2e_progress_markers_use_fixed_phase_and_scenario_vocabulary(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        for line in (
            "devlane_e2e_progress=phase=variant-supervisor-probe-check",
            "devlane_e2e_progress=scenario=real-browser",
        ):
            self.assertTrue(diagnostic_contract.public_e2e_progress(line))
            self.assertTrue(grammar.step_output_ok(
                "Run full source-free production-path acceptance", line, {},
            ))
        for line in (
            "devlane_e2e_progress=phase=private-path",
            "devlane_e2e_progress=scenario=private-scenario",
            "devlane_e2e_progress=scenario=real-browser/path",
        ):
            self.assertFalse(diagnostic_contract.public_e2e_progress(line))
            self.assertFalse(grammar.step_output_ok(
                "Run full source-free production-path acceptance", line, {},
            ))
        self.assertFalse(grammar.step_output_ok(
            "Prepare dependencies before the cut", "devlane_e2e_progress=phase=fixture-load", {},
        ))

    def test_variant_execute_runtime_frame_uses_a_fixed_audited_grammar(self):
        lines = [
            ("devlane_production_e2e=refused stage=variant-execute exception=runtime-error "
             "class=RuntimeError frame=supervisor.py:1824:_execute code=summary-schema-invalid"),
            ("devlane_production_e2e=refused stage=variant-summary-validate exception=runtime-error "
             "class=RuntimeError frame=test_e2e.py:1717:_require code=rust-matrix-summary-coverage-set"),
        ]
        for line in lines:
            self.assertTrue(diagnostic_contract.public_e2e_runtime_diagnostic(line))
            self.assertFalse(diagnostic_contract.public_preparation_diagnostic(line))
        details = acceptance_diagnostics.failure_tail(
            "production-path-e2e", ("\n".join(lines) + "\n").encode("ascii"),
        )
        self.assertEqual(details, lines)

        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        private_frame_path = chr(47) + "private/supervisor.py"
        for line in lines:
            self.assertTrue(grammar.step_output_ok(
                "Run full source-free production-path acceptance", line, {},
            ))
        for invalid in (
            lines[0].replace("supervisor.py", private_frame_path),
            lines[0].replace("supervisor.py", "../supervisor.py"),
            lines[0].replace("runtime-error", "type-error"),
            lines[0].replace("variant-execute", "variant-decrypt"),
            lines[0].replace(":1824:", ":0:"),
            lines[0].replace("code=summary-schema-invalid", "code=private-runtime-detail"),
            lines[0] + " KEYCANARY-73A10X",
            lines[1].replace("variant-summary-validate", "variant-decrypt"),
        ):
            with self.subTest(line=invalid):
                self.assertFalse(diagnostic_contract.public_e2e_runtime_diagnostic(invalid))
                self.assertFalse(grammar.step_output_ok(
                    "Run full source-free production-path acceptance", invalid, {},
                ))

    def test_execute_command_diagnostic_uses_a_fixed_audited_grammar(self):
        command = "devlane_e2e_command=failed call=supervisor-client:execute returncode=1"
        refusal = "devlane_supervisor_refusal=execution-order"
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        for line in (command, refusal,
                     "typescript_reporter_refusal=typescript-unavailable",
                     "rust_matrix=refused code=advisory-database-missing",
                     "rust_matrix=refused code=matrix-runner-failed",
                     "rust_test_adapter=refused",
                     "typescript_reporter_refusal=source-root-invalid",
                     "typescript_reporter_refusal=usage"):
            with self.subTest(line=line):
                self.assertTrue(diagnostic_contract.public_e2e_command_diagnostic(line))
                self.assertTrue(grammar.step_output_ok(
                    "Run full source-free production-path acceptance", line, {},
                ))
        details = acceptance_diagnostics.failure_tail(
            "production-path-e2e", (command + "\n" + refusal + "\nraw npm output\n").encode("ascii"),
        )
        self.assertEqual(details, [command, refusal,
                                   "devlane_acceptance_detail stage=production-path-e2e index=3 text=raw npm output"])
        for invalid in (
            command.replace("supervisor-client:execute", "private:execute"),
            command.replace("returncode=1", "returncode=01"),
            refusal.replace("execution-order", "private/path"),
            "typescript_reporter_refusal=private/path",
            "rust_matrix=refused",
            "rust_matrix=refused code=private/path",
            "rust_matrix=refused code=unlisted-reason",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(diagnostic_contract.public_e2e_command_diagnostic(invalid))
                self.assertFalse(grammar.step_output_ok(
                    "Run full source-free production-path acceptance", invalid, {},
                ))

    def test_vitest_raw_log_diagnostics_are_bounded_to_the_synthetic_acceptance_step(self):
        log_line = (
            "devlane_e2e_vitest_diag=log name=unit.stderr.log line=120 "
            "text=Error%3A%20spawn%20EPERM"
        )
        report_line = "devlane_e2e_vitest_diag=report name=vitest.json kind=file bytes=2048"
        rust_log_line = "devlane_e2e_failure_diag=log name=compile-root-default.stdout line=1 text=cargo%20test%20failed"
        rust_refusal_log_line = (
            "devlane_e2e_failure_diag=log name=rust-matrix-adapter.log line=1 "
            "text=rust_matrix=refused code=advisory-database-missing"
        )
        bare_rust_refusal_log_line = (
            "devlane_e2e_failure_diag=log name=rust-matrix-adapter.log line=1 "
            "text=rust_matrix=refused"
        )
        unknown_rust_refusal_log_line = (
            "devlane_e2e_failure_diag=log name=rust-matrix-adapter.log line=1 "
            "text=rust_matrix=refused code=private/path"
        )
        rust_report_line = "devlane_e2e_failure_diag=report name=rust-matrix.jsonl kind=file bytes=128"
        self.assertTrue(diagnostic_contract.public_e2e_vitest_diagnostic(log_line))
        self.assertTrue(diagnostic_contract.public_e2e_vitest_diagnostic(report_line))
        self.assertTrue(diagnostic_contract.public_e2e_failure_diagnostic(rust_log_line))
        self.assertTrue(diagnostic_contract.public_e2e_failure_diagnostic(rust_refusal_log_line))
        self.assertFalse(diagnostic_contract.public_e2e_failure_diagnostic(bare_rust_refusal_log_line))
        self.assertFalse(diagnostic_contract.public_e2e_failure_diagnostic(unknown_rust_refusal_log_line))
        self.assertTrue(diagnostic_contract.public_e2e_failure_diagnostic(rust_report_line))
        long_browser_line = (
            "devlane_e2e_failure_diag=log name=browser.stderr.log line=1 text=" + ("x" * 500)
        )
        long_non_browser_line = long_browser_line.replace("browser.stderr.log", "unit.stderr.log")
        self.assertTrue(diagnostic_contract.public_e2e_failure_diagnostic(long_browser_line))
        self.assertFalse(diagnostic_contract.public_e2e_failure_diagnostic(long_non_browser_line))
        self.assertFalse(diagnostic_contract.public_e2e_failure_diagnostic(
            long_browser_line + "x" * diagnostic_contract.MAX_E2E_BROWSER_DIAGNOSTIC_BYTES
        ))
        self.assertEqual(acceptance_diagnostics.failure_tail(
            "production-path-e2e", (log_line + "\n" + report_line + "\n" + rust_log_line + "\n"
                                     + rust_refusal_log_line + "\n" + rust_report_line + "\n").encode("ascii"),
        ), [log_line, report_line, rust_log_line, rust_refusal_log_line, rust_report_line])
        root = Path(__file__).resolve().parents[2]
        synthetic = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        counts = {}
        self.assertTrue(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", log_line, counts,
        ))
        self.assertTrue(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", report_line, counts,
        ))
        self.assertTrue(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", rust_log_line, counts,
        ))
        self.assertTrue(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", rust_report_line, counts,
        ))
        for invalid in (
            log_line.replace("line=120", "line=0120"),
            log_line.replace("unit.stderr.log", "../unit.log"),
            log_line.replace("EPERM", "EPERM::error::"),
            log_line.replace("EPERM", "SYNTHETIC_SOURCE_CANARY_7f8c"),
            log_line.replace("EPERM", "EPERM%2g"),
            report_line.replace("kind=file", "kind=private"),
            report_line + " KEYCANARY-73A10X",
        ):
            with self.subTest(line=invalid):
                self.assertFalse(diagnostic_contract.public_e2e_vitest_diagnostic(invalid))
                self.assertFalse(synthetic.step_output_ok(
                    "Run full source-free production-path acceptance", invalid, {},
                ))
        self.assertFalse(synthetic.step_output_ok("Set up pinned Node toolchain", log_line, {}))

        encrypted = audit._Grammar(
            root / ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB,
            IDENTITY, "encrypted",
        )
        self.assertFalse(encrypted.step_output_ok(
            "Run full source-free production-path acceptance", log_line, {},
        ))

        bounded = {}
        for _ in range(diagnostic_contract.MAX_E2E_VITEST_DIAGNOSTIC_LINES):
            self.assertTrue(synthetic.step_output_ok(
                "Run full source-free production-path acceptance", log_line, bounded,
            ))
        self.assertFalse(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", log_line, bounded,
        ))

    def test_cleanup_incomplete_diagnostic_requires_a_fixed_subreason(self):
        for reason in diagnostic_contract.CLEANUP_SUBREASONS:
            line = ("devlane_production_e2e=refused stage=prepare-cleanup "
                    "exception=cleanup-incomplete reason=" + reason + " cleanup=unconfirmed")
            self.assertTrue(diagnostic_contract.public_preparation_diagnostic(line))
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(
            "devlane_production_e2e=refused stage=prepare-cleanup exception=prepare-os-error "
            "reason=process-alive cleanup=unconfirmed",
        ))
        invalid = (
            "devlane_production_e2e=refused stage=prepare-cleanup exception=cleanup-incomplete cleanup=unconfirmed",
            "devlane_production_e2e=refused stage=prepare-cleanup exception=cleanup-incomplete reason=private-path cleanup=unconfirmed",
            "devlane_production_e2e=refused stage=prepare-cleanup exception=cleanup-incomplete reason=umount-busy cleanup=confirmed",
        )
        for line in invalid:
            self.assertFalse(diagnostic_contract.public_preparation_diagnostic(line))

        synthetic = _render_log(
            "devlane-synthetic", {**IDENTITY, "ref": "refs/heads/devlane/d211-1110"}, kind="synthetic",
            skip=("Install fixed Rust acceptance toolchain",),
        )
        refused = synthetic.replace(
            b"devlane_acceptance=pass", line.encode("ascii"), 1,
        )
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_synthetic_log(
                refused, {"run_id": "12345", "control_sha": SHA, "ref": "refs/heads/devlane/d211-1110"},
            )

    def test_network_probe_refusals_are_bounded_and_auditor_allowlisted(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, IDENTITY, "encrypted",
        )
        for code in sorted(audit.network_probe.REFUSAL_CODES):
            supervisor_line = "devlane_supervisor_refusal=network-probe-refusal:" + code
            self.assertTrue(grammar.step_output_ok(
                "Probe isolation before decryption", supervisor_line, {},
            ))
            self.assertTrue(grammar.step_output_ok(
                "Probe isolation before decryption", "network_probe_refusal=" + code, {},
            ))
            self.assertFalse(audit.REFUSAL_LINE.fullmatch("network_probe_refusal=" + code))
            self.assertFalse(grammar.step_output_ok("Prepare hosted Linux isolation state",
                                                    "network_probe_refusal=" + code, {}))
        valid = (
            "devlane_production_e2e=refused stage=variant-supervisor-probe-check "
            "exception=network-probe-refusal:network-address-unexpected"
        )
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(valid))
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance", valid, {},
        ))
        for invalid in (
            valid.replace("network-address-unexpected", "private-path"),
            valid.replace("variant-supervisor-probe-check", "variant-decrypt"),
            "devlane_supervisor_refusal=network-probe-refusal:private-path",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(diagnostic_contract.public_preparation_diagnostic(invalid))
                self.assertFalse(grammar.step_output_ok("Probe isolation before decryption", invalid, {}))
        self.assertFalse(audit.REFUSAL_LINE.fullmatch("network_probe_refusal=private-path"))

        structure_refusal = "network-structure-invalid:netlink-message-port-id"
        self.assertTrue(grammar.step_output_ok(
            "Probe isolation before decryption", "network_probe_refusal=" + structure_refusal, {},
        ))
        self.assertTrue(grammar.step_output_ok(
            "Probe isolation before decryption", "devlane_supervisor_refusal=network-probe-refusal:"
            + structure_refusal, {},
        ))
        structure_line = (
            "devlane_production_e2e=refused stage=variant-supervisor-probe-check "
            "exception=network-probe-refusal:" + structure_refusal
        )
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(structure_line))
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance", structure_line, {},
        ))
        self.assertFalse(diagnostic_contract.public_preparation_diagnostic(
            structure_line.replace("netlink-message-port-id", "private-path"),
        ))

        route_detail = (
            "route[table=main,type=unicast,family=4,dst=0.0.0.0/0,"
            "oif=lo,proto=boot,scope=universe]"
        )
        route_refusal = "network-route-unexpected " + route_detail
        route_line = (
            "devlane_production_e2e=refused stage=variant-supervisor-probe-check "
            "exception=network-probe-refusal:" + route_refusal
        )
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(route_line))
        self.assertTrue(grammar.step_output_ok(
            "Probe isolation before decryption", "network_probe_refusal=" + route_refusal, {},
        ))
        self.assertTrue(grammar.step_output_ok(
            "Probe isolation before decryption", "devlane_supervisor_refusal=network-probe-refusal:"
            + route_refusal, {},
        ))
        for malformed in (
                route_line.replace("oif=lo", "oif=private/path"),
                route_line.replace("network-route-unexpected", "network-address-unexpected")):
            self.assertFalse(diagnostic_contract.public_preparation_diagnostic(malformed))

    def test_reviewed_step_name_lists_match_the_workflow_files(self):
        root = Path(__file__).resolve().parents[2]
        encrypted = audit.parse_workflow(root / ".github/workflows/devlane-encrypted.yml")
        self.assertEqual([step["name"] for step in encrypted[audit.RUN_JOB]["steps"]], list(audit.STEP_NAMES))
        self.assertEqual([step["name"] for step in encrypted[audit.AUDIT_JOB]["steps"]], list(audit.AUDIT_STEP_NAMES))
        synthetic = audit.parse_workflow(root / ".github/workflows/devlane-synthetic.yml")
        self.assertEqual([step["name"] for step in synthetic["devlane-synthetic"]["steps"]],
                         list(control_audit.SYNTHETIC_STEP_NAMES))

    def test_final_audit_collects_every_completed_log_and_check_before_refusal(self):
        jobs = _encrypted_jobs()
        audit_job = jobs[1]
        audit_job["status"] = "completed"
        audit_job["conclusion"] = "success"
        audit_job["steps"][2].update({"status": "completed", "conclusion": "success"})
        audit_job["steps"][3].update({"status": "completed", "conclusion": "success"})

        class API:
            def __init__(self):
                self.logs = []
                self.checks = []

            def log_text(self, identifier):
                self.logs.append(identifier)
                return b"PRIVATE_SOURCE_CANARY"

            def json(self, endpoint):
                self.checks.append(endpoint)
                identifier = int(endpoint.rsplit("/", 1)[1])
                job = next(item for item in jobs if int(item["check_run_url"].rsplit("/", 1)[1]) == identifier)
                return ({"head_sha": SHA, "name": job["name"], "status": "completed", "output": {
                    "title": job["name"], "summary": None, "text": None, "annotations_count": 0,
                }}, {})

        api_client = API()
        with patch.object(audit, "_read_annotations", return_value=[]), \
                self.assertRaises(audit.AuditRefusal):
            audit.validate_final_public_surfaces(api_client, jobs, IDENTITY, "core-node")
        self.assertEqual(api_client.logs, [100, 101])
        self.assertEqual(len(api_client.checks), 2)

    def test_terminal_coordinator_contract_rechecks_final_audit_and_job_steps(self):
        jobs = _encrypted_jobs()
        jobs[1]["status"] = "completed"
        jobs[1]["conclusion"] = "success"
        jobs[1]["steps"][2]["status"] = "completed"
        jobs[1]["steps"][2]["conclusion"] = "success"
        jobs[1]["steps"][3]["status"] = "completed"
        jobs[1]["steps"][3]["conclusion"] = "success"
        result, accepted = audit.validate_terminal_job_contract(jobs, IDENTITY, "core-node")
        self.assertTrue(accepted)
        self.assertEqual(set(result), {audit.RUN_JOB, audit.AUDIT_JOB})
        jobs[1]["conclusion"] = "failure"
        result, accepted = audit.validate_terminal_job_contract(jobs, IDENTITY, "core-node")
        self.assertFalse(accepted)
        self.assertEqual(set(result), {audit.RUN_JOB, audit.AUDIT_JOB})
        jobs[1]["steps"][1]["name"] = "Audit an unexpected graph"
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_terminal_job_contract(jobs, IDENTITY, "core-node")


class ControlAuditorMutationTests(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "repository": control_audit.REPOSITORY, "repository_id": control_audit.REPOSITORY_ID,
            "ref": "refs/heads/main", "control_sha": SHA, "event": "workflow_dispatch",
            "wave_id": "control-wave-0001", "run_id": "12345", "attempt": 1,
        }

    def test_exact_18_job_graph_and_self_running_contract(self):
        self.assertEqual(len(control_audit.CONTROL_JOB_NAMES), 18)
        result = control_audit.validate_jobs(_control_jobs(), self.identity)
        self.assertEqual(len(result), 18)

    def test_unit_failure_subreason_is_audited_as_a_fixed_public_enum(self):
        accepted = '{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit","status":"fail","subreason":"filter-refused"}'
        self.assertTrue(audit._record_ok(accepted))
        audit.validate_summary_records([accepted], "core-node")
        for changed in (
            accepted.replace("filter-refused", "private-filter-error"),
            accepted.replace('"stage":"unit"', '"stage":"typecheck"'),
            accepted.replace('"status":"fail"', '"status":"pass"'),
            accepted.replace('"subreason":"filter-refused"', '"subreason":"filter-refused","detail":"private"'),
        ):
            with self.subTest(changed=changed):
                self.assertFalse(audit._record_ok(changed))
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_summary_records([changed], "core-node")

    def test_control_audit_final_step_may_still_be_pending_while_the_audit_runs(self):
        """GitHub reports a later step as pending until the runner reaches it."""
        cases = (
            ("refs/heads/main", "pending", None, True), ("refs/heads/main", "queued", None, True),
            ("refs/heads/main", "completed", "skipped", False), ("refs/heads/main", "completed", "success", False),
            ("refs/heads/devlane/x", "pending", None, True), ("refs/heads/devlane/x", "queued", None, True),
            ("refs/heads/devlane/x", "completed", "skipped", True),
            ("refs/heads/devlane/x", "completed", "success", False),
            ("refs/heads/devlane/x", "in_progress", None, False), ("refs/heads/devlane/x", "pending", "skipped", False),
        )
        for ref, status, conclusion, accepted in cases:
            with self.subTest(ref=ref, status=status, conclusion=conclusion):
                identity = dict(self.identity, ref=ref)
                jobs = _control_jobs()
                audit_job = next(job for job in jobs if job["name"] == control_audit.RUN_JOB)
                final = [step for step in audit_job["steps"]
                         if step["name"] == control_audit.CONTROL_AUDIT_FINAL_STEPS[2]][0]
                final.update({"status": status, "conclusion": conclusion})
                if accepted:
                    self.assertEqual(len(control_audit.validate_jobs(jobs, identity)), 18)
                else:
                    with self.assertRaises(control_audit.ControlAuditRefusal):
                        control_audit.validate_jobs(jobs, identity)

    def test_control_graph_mutations_are_rejected(self):
        jobs = _control_jobs()
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(jobs[:-1], self.identity)
        changed = copy.deepcopy(jobs)
        changed[0]["name"] = "unexpected-control-job"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)
        changed = copy.deepcopy(jobs)
        changed[-1]["head_sha"] = "c" * 40
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)
        changed = copy.deepcopy(jobs)
        changed[-1]["steps"][0]["name"] = "Unexpected child step"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)
        changed = copy.deepcopy(jobs)
        changed[-1]["steps"][-2]["status"] = "in_progress"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)

    def test_control_graph_accepts_only_the_diagnosed_synthetic_acceptance_failure(self):
        jobs = _control_jobs()
        synthetic = next(job for job in jobs if job["name"] == control_audit.SYNTHETIC_JOB)
        synthetic["conclusion"] = "failure"
        steps = {step["name"]: step for step in synthetic["steps"]}
        steps["Run full source-free production-path acceptance"]["conclusion"] = "failure"
        steps["Probe the loopback-only Linux network boundary"]["conclusion"] = "skipped"
        result = control_audit.validate_jobs(jobs, self.identity)
        self.assertEqual(result[control_audit.SYNTHETIC_JOB]["conclusion"], "failure")

        changed = copy.deepcopy(jobs)
        changed_synthetic = next(job for job in changed if job["name"] == control_audit.SYNTHETIC_JOB)
        changed_steps = {step["name"]: step for step in changed_synthetic["steps"]}
        changed_steps["Run full source-free production-path acceptance"]["conclusion"] = "success"
        changed_steps["Probe the loopback-only Linux network boundary"]["conclusion"] = "failure"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)

    def test_terminal_graph_checks_all_child_steps_and_branch_specific_cache_step(self):
        run = {
            "id": 12345, "path": control_audit.WORKFLOW_PATH, "event": "workflow_dispatch",
            "display_title": "public control=control-wave-0001",
            "head_branch": "main", "head_sha": SHA, "run_attempt": 1,
            "status": "completed", "conclusion": "success",
            "repository": {"full_name": control_audit.REPOSITORY, "id": control_audit.REPOSITORY_ID},
            "head_repository": {"full_name": control_audit.REPOSITORY, "id": control_audit.REPOSITORY_ID},
        }
        control_audit.validate_terminal_control_run(
            run, _terminal_control_jobs(), "12345", SHA, expected_wave_id="control-wave-0001")
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_terminal_control_run(
                dict(run, display_title="public control=control-wave-0002"),
                _terminal_control_jobs(), "12345", SHA, expected_wave_id="control-wave-0001")
        in_progress = dict(run, status="in_progress", conclusion=None)
        control_audit.validate_run_record(in_progress, self.identity)
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_run_record(
                dict(in_progress, display_title="public control=control-wave-0002"), self.identity)
        develop_run = dict(run, head_branch="develop")
        jobs = _terminal_control_jobs(require_main=False)
        control_audit.validate_terminal_control_run(develop_run, jobs, "12345", SHA, require_main=False)
        feature_run = dict(run, head_branch="devlane/d211-1110")
        control_audit.validate_terminal_control_run(feature_run, jobs, "12345", SHA, require_main=False)
        for refused in ("a b", "", None, 7, "x" * 201):
            with self.subTest(branch=refused), self.assertRaises(control_audit.ControlAuditRefusal):
                control_audit.validate_terminal_control_run(
                    dict(run, head_branch=refused), jobs, "12345", SHA, require_main=False)
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_terminal_control_run(feature_run, _terminal_control_jobs(), "12345", SHA)
        jobs[0]["steps"][0]["conclusion"] = "failure"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_terminal_control_run(develop_run, jobs, "12345", SHA, require_main=False)

    def test_composed_provider_annotations_accept_only_the_bounded_exact_macos_notice(self):
        job = "development-feedback-smoke / feedback-smoke-producer macos-15"
        macos_jobs = (
            "policy-macos-15",
            "node-lock-smoke / node-lock-smoke-macos-15",
            job,
        )
        notice = control_audit._macos_capacity_notice(SHA)
        for name in macos_jobs:
            control_audit.validate_control_annotations(name, SHA, 1, [notice])
            control_audit.validate_control_annotations(name, SHA, 64, [notice] * 64)
        for name, count, annotations in (
                (job, 65, [notice] * 65),
                (job, 1, [dict(notice, message="unexpected annotation")]),
                (job, 2, [notice])):
            with self.subTest(name=name, count=count):
                with self.assertRaises(control_audit.ControlAuditRefusal):
                    control_audit.validate_control_annotations(name, SHA, count, annotations)
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_control_annotations("policy-ubuntu-24.04", SHA, 1, [notice])

    def test_refusal_output_contains_only_a_fixed_stage_code(self):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with patch.object(control_audit, "control_identity", side_effect=control_audit.ControlAuditRefusal()):
            with redirect_stdout(output):
                self.assertEqual(control_audit.main(), 1)
        self.assertEqual(output.getvalue(), "control_audit=refused stage=identity\n")

    def test_control_status_is_posted_once_after_the_accepted_audit_on_any_branch(self):
        from contextlib import redirect_stdout
        from io import StringIO
        identity = dict(self.identity, ref="refs/heads/devlane/d211-1110")
        events = []
        output = StringIO()
        with patch.object(control_audit, "control_identity", return_value=identity), \
                patch.object(control_audit, "GitHubAPI", return_value=object()), \
                patch.object(control_audit, "run_audit", side_effect=lambda api, value: events.append("audit")), \
                patch.object(control_audit, "post_control_status", side_effect=lambda api, value: events.append("status")) as post, \
                patch.dict("os.environ", {"GITHUB_TOKEN": "x"}, clear=False), \
                redirect_stdout(output):
            self.assertEqual(control_audit.main(), 0)
        self.assertEqual(events, ["audit", "status"])
        post.assert_called_once()
        self.assertEqual(output.getvalue(), "control_audit=accepted jobs=18 synthetic_artifacts=1\n")

    def test_control_status_post_uses_exact_sha_context_body_and_actions_bot_response(self):
        from email.message import Message
        from unittest.mock import Mock

        class Response:
            status = 201

            def __init__(self, value):
                self.headers = Message()
                self.headers["Content-Type"] = "application/json"
                self.value = value

            def read(self, limit):
                return self.value

            def close(self):
                pass

        target_url = "https://github.com/" + control_audit.REPOSITORY + "/actions/runs/12345"
        value = {
            "url": "https://api.github.com/repos/" + control_audit.REPOSITORY + "/statuses/" + SHA,
            "context": control_audit.CONTROL_STATUS_CONTEXT,
            "state": "success",
            "description": control_audit.CONTROL_STATUS_DESCRIPTION,
            "target_url": target_url,
            "creator": {"login": control_audit.CONTROL_STATUS_CREATOR, "type": "Bot"},
        }
        opener = Mock()
        opener.open.return_value = Response(json.dumps(value).encode("utf-8"))
        api = type("API", (), {"_token": "token-never-printed", "_opener": opener})()
        control_audit.post_control_status(api, self.identity)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/" + control_audit.REPOSITORY + "/statuses/" + SHA)
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer token-never-printed")
        self.assertEqual(json.loads(request.data), {
            "context": control_audit.CONTROL_STATUS_CONTEXT,
            "state": "success",
            "description": control_audit.CONTROL_STATUS_DESCRIPTION,
            "target_url": target_url,
        })

    def test_control_status_post_failure_has_only_the_fixed_reason(self):
        from unittest.mock import Mock
        opener = Mock()
        opener.open.side_effect = OSError("secret-bearing API error")
        api = type("API", (), {"_token": "token-never-printed", "_opener": opener})()
        with self.assertRaisesRegex(control_audit.ControlAuditRefusal, "status-post"):
            control_audit.post_control_status(api, self.identity)

    def test_audit_refusal_never_posts_the_control_status(self):
        from contextlib import redirect_stdout
        from io import StringIO
        identity = dict(self.identity, ref="refs/heads/devlane/d211-1110")
        output = StringIO()
        with patch.object(control_audit, "control_identity", return_value=identity), \
                patch.object(control_audit, "GitHubAPI", return_value=object()), \
                patch.object(control_audit, "run_audit", side_effect=control_audit.ControlAuditRefusal("job-graph")), \
                patch.object(control_audit, "post_control_status") as post, \
                patch.dict("os.environ", {"GITHUB_TOKEN": "x"}, clear=False), \
                redirect_stdout(output):
            self.assertEqual(control_audit.main(), 1)
        post.assert_not_called()
        self.assertEqual(output.getvalue(), "control_audit=refused stage=job-graph\n")

    def test_control_marker_and_synthetic_artifact_are_bound(self):
        log = (
            b"KD-PLATFORM-CONTROL schema=1 wave-id=control-wave-0001 control-sha="
            + SHA.encode("ascii") + b" run-id=12345 attempt=1 runner=Linux\n"
        )
        control_audit.validate_control_marker(log, self.identity, "Linux")
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_control_marker(log, self.identity, "Windows")
        windows_log = (b"\x1b[36;1munrelated hosted script echo\x1b[0m\r\n"
                       + log.replace(b"\n", b"\r\n"))
        control_audit.validate_control_marker(windows_log, self.identity, "Linux")
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_control_marker(windows_log.replace(b"\x1b[0m", b"\x1b[2J", 1),
                                                  self.identity, "Linux")
        artifact = {
            "total_count": 1,
            "artifacts": [{
                "id": 7, "name": "development-feedback-smoke-12345-1", "expired": False,
                "size_in_bytes": 100,
                "workflow_run": {"id": 12345, "head_sha": SHA},
            }],
        }
        control_audit.validate_artifacts(artifact, self.identity)
        artifact["artifacts"][0]["name"] = "private-source-artifact"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_artifacts(artifact, self.identity)


class WorkflowStaticAcceptanceTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[2]

    def _workflow(self, name):
        return (self.root / ".github/workflows" / name).read_text(encoding="utf-8")

    def test_encrypted_and_control_entrypoints_are_manual_only_and_sha_pinned(self):
        encrypted = self._workflow("devlane-encrypted.yml")
        trigger = encrypted.split("jobs:", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:", trigger)
        for forbidden in ("pull_request", "pull_request_target", "repository_dispatch", "workflow_run", "  push:"):
            self.assertNotIn(forbidden, trigger)
        self.assertIn("permissions: {}", trigger)
        self.assertIn("group: devlane-encrypted", trigger)
        concurrency = trigger.split("concurrency:", 1)[1]
        self.assertNotIn("inputs.wave_id", concurrency)
        self.assertIn("run-name: devlane wave=${{ inputs.wave_id }} bundle=${{ inputs.bundle_id }}", trigger)
        self.assertEqual(encrypted.count("secrets.DEVLANE_DECRYPT_KEY"), 1)
        self.assertLess(encrypted.index("Probe isolation before decryption"), encrypted.index("secrets.DEVLANE_DECRYPT_KEY"))
        self.assertLess(encrypted.index("secrets.DEVLANE_DECRYPT_KEY"), encrypted.index("Execute offline profile"))
        pinned = re.findall(r"(?m)^\s*uses:\s*(\S+)", encrypted)
        external = [use for use in pinned if use.startswith("actions/") or not use.startswith("./")]
        self.assertTrue(external)
        self.assertTrue(all(re.search(r"@[a-f0-9]{40}(?:\s|$)", use) for use in external))
        self.assertIn("actions/cache/restore@3edfce9056124e459a23f683a21433670d47daca", encrypted)
        self.assertIn("actions/cache/save@3edfce9056124e459a23f683a21433670d47daca", encrypted)
        self.assertIn("control_run_id", encrypted)
        self.assertNotIn("upload-artifact", encrypted)
        control = self._workflow("public-policy.yml").split("jobs:", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:", control)
        self.assertIn("permissions: {}", control)
        self.assertIn("group: public-control-${{ github.ref }}\n", control)
        self.assertNotIn("group: public-control\n", control)
        self.assertIn("run-name: public control=${{ inputs.control_wave_id }}", control)
        self.assertIn("inputs.control_wave_id", control)
        self.assertNotIn("pull_request", control)
        self.assertNotIn("  push:", control)

    def test_cache_authorization_paths_and_keys_are_run_independent_and_identical(self):
        """Fails on the old workflow: the saved and restored records used different, run-specific paths, so the Actions cache version (derived from the path) never matched."""
        encrypted = audit.parse_workflow(self.root / ".github/workflows/devlane-encrypted.yml")[audit.RUN_JOB]
        steps = {step["name"]: step for step in encrypted["steps"]}
        permit_paths = {steps[name]["with"]["path"] for name in (
            "Restore one-run bundle permit", "Save one-run bundle permit", "Restore and verify persisted one-run permit")}
        self.assertEqual(permit_paths, {"${{ runner.temp }}/devlane-bundle-permit/permit.json"})
        permit_keys = {steps[name]["with"]["key"] for name in (
            "Restore one-run bundle permit", "Save one-run bundle permit", "Restore and verify persisted one-run permit")}
        self.assertEqual(permit_keys, {"devlane-permit-v1-${{ inputs.bundle_id }}"})
        control_restore = steps["Restore exact source-free control evidence"]["with"]
        saved = audit.parse_workflow(self.root / ".github/workflows/public-policy.yml")["control-audit"]["steps"][-1]["with"]
        self.assertEqual(control_restore["path"], saved["path"])
        self.assertEqual(control_restore["path"], "${{ runner.temp }}/devlane-control-evidence/permit.json")
        self.assertEqual(control_restore["fail-on-cache-miss"], "true")
        self.assertEqual(steps["Restore and verify persisted one-run permit"]["with"]["fail-on-cache-miss"], "true")
        self.assertNotIn("fail-on-cache-miss", steps["Restore one-run bundle permit"]["with"])
        for step in encrypted["steps"]:
            for value in step["with"].values():
                self.assertNotIn("github.run_id", value)
        names = [step["name"] for step in encrypted["steps"]]
        self.assertLess(names.index("Save one-run bundle permit"),
                        names.index("Discard local permit copy before persisted verification"))
        self.assertLess(names.index("Discard local permit copy before persisted verification"),
                        names.index("Restore and verify persisted one-run permit"))
        self.assertLess(names.index("Restore and verify persisted one-run permit"),
                        names.index("Verify permit and emit bound dispatch marker"))
        self.assertLess(names.index("Claim this bundle for one run before decryption"),
                        names.index("Fetch ciphertext and sanitized dependency projection"))

    def test_synthetic_control_exercises_the_cache_claim_restore_sequence_for_real(self):
        steps = audit.parse_workflow(self.root / ".github/workflows/devlane-synthetic.yml")["devlane-synthetic"]["steps"]
        names = [step["name"] for step in steps]
        save = steps[names.index("Save the synthetic permit through the Actions cache")]
        restore = steps[names.index("Restore the synthetic permit with the encrypted-lane path and key shape")]
        self.assertEqual(save["with"]["path"], restore["with"]["path"])
        self.assertEqual(save["with"]["key"], restore["with"]["key"])
        self.assertEqual(restore["with"]["fail-on-cache-miss"], "true")
        verify = "\n".join(steps[names.index("Verify the restored permit and refuse a second claim")]["run"])
        self.assertIn("verify-claim", verify)
        self.assertIn("then\n  exit 1", verify)

    def test_no_step_summary_or_artifact_surface_is_written_by_the_encrypted_lane(self):
        encrypted = self._workflow("devlane-encrypted.yml")
        self.assertNotIn("GITHUB_STEP_SUMMARY", encrypted)
        self.assertNotIn("upload-artifact", encrypted)

    def test_five_automatic_workflows_are_reusable_only_and_called_at_same_commit(self):
        names = (
            "node-lock-smoke.yml", "linux-confinement.yml", "windows-confinement.yml",
            "windows-handoff-synthetic.yml", "development-feedback-smoke.yml",
        )
        for name in names:
            with self.subTest(workflow=name):
                workflow = self._workflow(name)
                trigger = workflow.split("jobs:", 1)[0]
                self.assertIn("on:\n  workflow_call:", trigger)
                for forbidden in ("pull_request", "pull_request_target", "workflow_dispatch", "  push:"):
                    self.assertNotIn(forbidden, trigger)
        control = self._workflow("public-policy.yml")
        for name in names:
            self.assertIn("uses: ./.github/workflows/" + name, control)
        self.assertIn("uses: ./.github/workflows/devlane-synthetic.yml", control)
        self.assertEqual(len(control_audit.CONTROL_JOB_NAMES), 18)

    def test_synthetic_reusable_workflow_has_no_secret_and_linux_probe(self):
        workflow = self._workflow("devlane-synthetic.yml")
        self.assertIn("on:\n  workflow_call:", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertIn("kit/devlane/test_acceptance.py", workflow)
        self.assertIn("kit/devlane/test_linux_runtime.py", workflow)
        self.assertIn("kit/devlane/test_e2e.py", workflow)
        self.assertRegex(workflow, r're.fullmatch\(r"refs/heads/\[A-Za-z0-9\._/-\]\{1,200\}"')
        self.assertNotIn("(develop|uat|main)", workflow)
        self.assertNotIn("environment:", workflow)

    def test_branch_policy_matches_the_reusable_synthetic_child(self):
        policy = self._workflow("public-policy.yml")
        synthetic = self._workflow("devlane-synthetic.yml")
        expression = r"^refs/heads/[A-Za-z0-9._/-]{1,200}$"
        self.assertIn(expression, policy)
        self.assertRegex(synthetic, r're.fullmatch\(r"refs/heads/\[A-Za-z0-9\._/-\]\{1,200\}"')
        self.assertEqual(control_audit.SOURCE_FREE_BRANCH_REF.pattern, expression[1:-1] + r"\Z")

    def test_control_and_lane_workflows_request_no_write_permission(self):
        for relative in ("devlane-synthetic.yml", "devlane-encrypted.yml", "node-lock-smoke.yml",
                         "linux-confinement.yml", "windows-confinement.yml", "windows-handoff-synthetic.yml",
                         "development-feedback-smoke.yml"):
            with self.subTest(workflow=relative):
                self.assertIsNone(re.search(r"(?m)^\s+[a-z-]+: write\s*$", self._workflow(relative)))
        control = self._workflow("public-policy.yml")
        control_job = control.split("  control-audit:\n", 1)[1]
        self.assertRegex(control_job, r"(?m)^      actions: read$")
        self.assertRegex(control_job, r"(?m)^      checks: read$")
        self.assertRegex(control_job, r"(?m)^      statuses: write$")
        self.assertNotRegex(control.split("  control-audit:\n", 1)[0], r"(?m)^\s+[a-z-]+: write$")
        self.assertEqual(control.count("statuses: write"), 1)

    def test_the_acceptance_step_runs_the_rehearsal_builders(self):
        self.assertIn("kit/devlane/test_rehearsal.py", self._workflow("devlane-synthetic.yml"))
        self.assertTrue((self.root / "kit/devlane/test_rehearsal.py").is_file())

    def test_decryption_key_is_an_environment_secret_limited_to_the_run_job(self):
        encrypted = self._workflow("devlane-encrypted.yml")
        jobs = audit.parse_workflow(self.root / ".github/workflows/devlane-encrypted.yml")
        self.assertEqual(jobs[audit.RUN_JOB]["environment"], "devlane-decrypt")
        self.assertEqual(jobs[audit.AUDIT_JOB].get("environment"), None)
        self.assertEqual(encrypted.count("environment: devlane-decrypt"), 1)
        self.assertEqual(encrypted.count("environment:"), 1)
        run_block = encrypted.split("  devlane-encrypted-audit:", 1)[0]
        self.assertIn("    environment: devlane-decrypt\n", run_block)
        self.assertEqual(encrypted.count("secrets."), 1)
        holders = [step["name"] for step in jobs[audit.RUN_JOB]["steps"] if "DEVLANE_DECRYPT_KEY" in step["env"]]
        self.assertEqual(holders, ["Decrypt authenticated bundle"])
        for relative in ("public-policy.yml", "devlane-synthetic.yml", "node-lock-smoke.yml", "linux-confinement.yml"):
            self.assertNotIn("environment:", self._workflow(relative))


if __name__ == "__main__":
    unittest.main()
