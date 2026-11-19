"""Setup-node post metadata and native-platform early failure contracts."""
import copy
import unittest
from unittest.mock import patch
from test_audit_contracts import (
    audit, IDENTITY, _encrypted_jobs, _render_real_runner_encrypted_log,
    _replace_output_line, _sync_setup_posts,
)


class MacosAuditPostTests(unittest.TestCase):
    def test_macos_hosted_permissions_match_only_the_declared_contents_read(self):
        identity = dict(IDENTITY, platform="macos")
        log = _render_real_runner_encrypted_log(identity)
        audit.validate_job_log_surface(log, audit.MACOS_RUN_JOB, identity, completed=True)
        for permissions in (b"Contents: write", b"Actions: read", b"Metadata: read"):
            changed = log.replace(b"Contents: read", permissions, 1)
            with self.subTest(permissions=permissions), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, audit.MACOS_RUN_JOB, identity, completed=True)


    def test_diagnostics_are_step_bound_and_collected_without_other_log_bytes(self):
        row = audit.refusal_codes.macos_diagnostic_line({
            "schema": "macos-diagnostic-v1", "kind": "probe", "check": "outside_read", "result": "fail", "exit": 1})
        identity = dict(IDENTITY, platform="macos")
        log = _render_real_runner_encrypted_log(identity)
        changed = log.replace(b"network_cut_probe=pass", row.encode() + b"\nnetwork_cut_probe=pass", 1)
        audit.validate_job_log_surface(changed, audit.MACOS_RUN_JOB, identity, completed=True)
        self.assertEqual(audit.collect_macos_diagnostics(b"private file\n2026-11-19T00:00:00Z " + row.encode()), [row.encode()])
        for bad in (row + " ", row.replace('"outside_read"', '"private-file"'), row.replace('"exit":1', '"exit":true')):
            with self.subTest(bad=bad), self.assertRaises(audit.AuditRefusal):
                audit.collect_macos_diagnostics(bad.encode())
        grammar = audit._Grammar(".github/workflows/devlane-encrypted.yml", audit.MACOS_RUN_JOB, identity, "encrypted")
        self.assertFalse(grammar.step_output_ok(audit.MACOS_CLEANUP_STEP, row, {}))

    def test_macos_prepare_failure_with_real_setup_node_post_metadata(self):
        identity = dict(IDENTITY, platform="macos")
        jobs = _encrypted_jobs(platform="macos")
        run = next(job for job in jobs if job["name"] == audit.MACOS_RUN_JOB)
        run["conclusion"] = "failure"
        failed = False
        for step in run["steps"]:
            if step["name"] == audit.MACOS_PREPARE_STEP:
                failed = True
                step["conclusion"] = "failure"
            elif step["name"] == "Shred runner-local workspace":
                step["conclusion"] = "success"
            elif failed:
                step["conclusion"] = "skipped"
        _sync_setup_posts(run)
        post = {"name": "Post Set up pinned macOS Node runtime", "status": "completed", "conclusion": "skipped"}
        run["steps"][-1] = post
        audit.validate_job_contract(jobs, identity, "core-node")
        for change in ({"name": "Post arbitrary action"}, {"conclusion": "failure"}, {"status": "in_progress"}):
            changed = copy.deepcopy(jobs)
            candidate = next(job for job in changed if job["name"] == audit.MACOS_RUN_JOB)
            candidate["steps"][-1].update(change)
            with self.subTest(change=change), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_contract(changed, identity, "core-node")
        changed = copy.deepcopy(jobs)
        candidate = next(job for job in changed if job["name"] == audit.MACOS_RUN_JOB)
        candidate["steps"].pop()
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_contract(changed, identity, "core-node")
        changed = copy.deepcopy(jobs)
        candidate = next(job for job in changed if job["name"] == audit.MACOS_RUN_JOB)
        next(s for s in candidate["steps"] if s["name"] == "Set up pinned macOS Node runtime")["conclusion"] = "skipped"
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_contract(changed, identity, "core-node")
        run["steps"].insert(2, run["steps"].pop())
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_contract(jobs, identity, "core-node")


    def test_skipped_setup_forbids_even_a_skipped_post(self):
        identity = dict(IDENTITY, platform="macos")
        jobs = _encrypted_jobs(platform="macos")
        run = next(job for job in jobs if job["name"] == audit.MACOS_RUN_JOB)
        run["conclusion"] = "failure"
        failed = False
        for step in run["steps"]:
            if step["name"] == "Fetch public control and validate dispatch":
                failed = True
                step["conclusion"] = "failure"
            elif step["name"] == "Shred runner-local workspace":
                step["conclusion"] = "success"
            elif failed:
                step["conclusion"] = "skipped"
        _sync_setup_posts(run)
        audit.validate_job_contract(jobs, identity, "core-node")
        run["steps"].append({"name": "Post Set up pinned macOS Node runtime",
                             "status": "completed", "conclusion": "skipped"})
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_contract(jobs, identity, "core-node")


    def test_macos_and_windows_early_failures_are_audited_with_fixed_dispositions(self):
        scenarios = (
            ("macos", "Prepare hosted runner isolation state",
             "devlane_macos_preflight_refusal=macos-user-attribute-set", 2,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-macos-preflight"),
            ("linux", "Fetch public control and validate dispatch",
             "devlane_bootstrap_refusal=bootstrap-command-failed", 1,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-bootstrap"),
            ("macos", "Fetch public control and validate dispatch",
             "devlane_bootstrap_refusal=bootstrap-command-failed", 1,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-bootstrap"),
            ("windows", "Fetch public control and validate dispatch",
             "devlane_deadline_refusal=deadline-start-invalid", 1,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-bootstrap"),
            ("windows", "Prepare hosted Windows isolation state",
             "devlane_windows_preflight_refusal=windows-admin-required", 1,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-windows-preflight"),
        )
        for platform_name, failed_step, marker, exit_code, outcome in scenarios:
            with self.subTest(platform=platform_name):
                identity = dict(IDENTITY, platform=platform_name)
                jobs = _encrypted_jobs(platform=platform_name)
                by_name = {job["name"]: job for job in jobs}
                run_job = by_name[audit.PLATFORM_RUN_JOBS[platform_name]]
                run_job["conclusion"] = "failure"
                names = [step["name"] for step in run_job["steps"]]
                failed_index = names.index(failed_step)
                for index, step in enumerate(run_job["steps"]):
                    if step["name"] == "Shred runner-local workspace":
                        step["conclusion"] = "success"
                    elif step["name"] == "Install pinned Rust toolchain" and platform_name == "macos":
                        step["conclusion"] = "skipped"
                    elif index < failed_index:
                        step["conclusion"] = "success"
                    elif index == failed_index:
                        step["conclusion"] = "failure"
                    else:
                        step["conclusion"] = "skipped"
                _sync_setup_posts(run_job)
                audit_job = by_name[audit.AUDIT_JOB]

                logs = _render_real_runner_encrypted_log(
                    identity, early_failure={"step": failed_step, "marker": marker, "exit_code": exit_code},
                )
                surface = audit.validate_job_log_surface(logs, audit.PLATFORM_RUN_JOBS[platform_name], identity,
                                                          completed=True)
                self.assertEqual(surface["early_failure"], failed_step)
                audit.validate_job_log_metadata_binding(surface, run_job, identity)
                self.assertFalse(audit.validate_dispatch_marker(logs, identity, allow_missing=True))
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_log_surface(
                        _replace_output_line(logs, marker, "devlane_bootstrap_refusal=private-path"),
                        audit.PLATFORM_RUN_JOBS[platform_name], identity, completed=True,
                    )

                class API:
                    def __init__(self, candidate_jobs=None, candidate_log=None):
                        self.jobs = jobs if candidate_jobs is None else candidate_jobs
                        self.log = logs if candidate_log is None else candidate_log

                    def json(self, endpoint):
                        if endpoint.endswith("/actions/runs/" + identity["run_id"]):
                            repository = {"full_name": audit.REPOSITORY, "id": audit.REPOSITORY_ID}
                            return ({
                                "id": int(identity["run_id"]), "path": audit.WORKFLOW_PATH,
                                "event": "workflow_dispatch", "head_branch": "main",
                                "head_sha": identity["control_sha"], "run_attempt": 1,
                                "status": "in_progress", "conclusion": None,
                                "repository": repository, "head_repository": repository,
                            }, {})
                        if "/jobs?" in endpoint:
                            return ({"total_count": 4, "jobs": self.jobs}, {})
                        if "/artifacts?" in endpoint:
                            return ({"total_count": 0, "artifacts": []}, {})
                        return ({}, {})

                    def log_text(self, identifier):
                        self.assert_run_id = identifier
                        return self.log

                permit_key = "devlane-permit-v1-" + identity["bundle_id"]
                control_key = "devlane-control-v1-" + identity["control_run_id"]
                with patch.object(audit, "_fetch_cache_entries", return_value=[
                        {"key": permit_key, "size_in_bytes": 1}, {"key": control_key, "size_in_bytes": 1}]), \
                        patch.object(audit, "cache_inventory_digest", return_value=identity["cache_baseline_sha256"]), \
                        patch.object(audit, "validate_check_output"), \
                        patch.object(audit, "_read_annotations", return_value=[]):
                    self.assertEqual(audit.run_audit(API(), identity), outcome)
                    with self.assertRaises(audit.AuditRefusal):
                        audit.run_audit(API(_encrypted_jobs(platform=platform_name), logs), identity)
                terminal_jobs = copy.deepcopy(jobs)
                terminal_audit = next(job for job in terminal_jobs if job["name"] == audit.AUDIT_JOB)
                terminal_audit["status"] = "completed"
                terminal_audit["conclusion"] = "success"
                for step in terminal_audit["steps"]:
                    step.update({"status": "completed", "conclusion": "success"})
                _terminal, audit_passed = audit.validate_terminal_job_contract(
                    terminal_jobs, identity, "core-node",
                )
                self.assertTrue(audit_passed)
                for mutation in ("cleanup", "downstream", "failed-step"):
                    changed = copy.deepcopy(jobs)
                    changed_run = next(job for job in changed
                                       if job["name"] == audit.PLATFORM_RUN_JOBS[platform_name])
                    changed_steps = {step["name"]: step for step in changed_run["steps"]}
                    if mutation == "cleanup":
                        changed_steps["Shred runner-local workspace"]["conclusion"] = "failure"
                    elif mutation == "downstream":
                        changed_steps["Decrypt authenticated bundle"]["conclusion"] = "success"
                    else:
                        changed_steps[failed_step]["conclusion"] = "success"
                    with self.subTest(platform=platform_name, mutation=mutation), \
                            self.assertRaises(audit.AuditRefusal):
                        audit.validate_job_log_metadata_binding(surface, changed_run, identity)


if __name__ == "__main__":
    unittest.main()
