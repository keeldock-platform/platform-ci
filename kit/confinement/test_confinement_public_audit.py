"""Tests for the independent source-free confinement run auditor."""

import base64
import copy
import hashlib
import io
import json
import re
import unittest
import urllib.parse
from unittest import mock

import confinement_public_audit as subject
import confinement_verdict as verdict
import log_canary


REPO = "example-org/example-ci"
CONTROL = "ab" * 20
RUN_ID = 5000123456
WORKFLOW = ".github/workflows/linux-source-admission.yml"
TITLE = "linux source admission"
SETTINGS_JOB = "linux-settings"
BUILD_JOB = "linux-source-build"
AUDITOR_JOB = "linux-audit"
SETTINGS_STEPS = ("Set up job", "Check settings", "Complete job")
BUILD_STEPS = ("Set up job", "Prepare", "Run boundary", "Post cleanup", "Complete job")
VERDICT_STEP = "Run boundary"
MARK = chr(35) * 2
CANARY = hashlib.sha256(b"audit synthetic canary").hexdigest()
CONFIG = log_canary.compute_config(CANARY)
STAMP = b"2026-10-28T10:00:00.1234567Z "
ACCEPTED = (
    "KD-CONFINEMENT-AUDIT schema=1 status=accepted os=linux mode=candidate control-sha=" + CONTROL
    + " run-id=5000123456 run-attempt=1 verdict=accepted log-canary=absent artifacts=expected"
    " caches=unchanged"
)
ANNOTATION = {
    "path": "ci", "start_line": 1, "end_line": 1, "start_column": None, "end_column": None,
    "annotation_level": "warning", "title": None, "message": "plain notice", "raw_details": None,
    "blob_href": "ref",
}


def verdict_record(os_name="linux", **updates):
    record = {
        "os": os_name,
        "boundary": verdict.BOUNDARIES[os_name],
        "control_sha": CONTROL,
        "run_id": RUN_ID,
        "run_attempt": 1,
        "channels": {
            name: {"status": "blocked", "before": True, "after": True} for name in verdict.CHANNELS
        },
        "memory_canary": "absent",
        "readable_file_canary": "absent",
        "handoff": "not-applicable" if os_name == "linux" else "verified",
        "project_execution": "completed",
        "gates": 13,
        "failed": 0,
        "token_revocation": "confirmed",
    }
    record.update(updates)
    return record


def noise_log(label):
    lines = [STAMP + b"line " + str(index).encode("ascii") + b" of " + label for index in range(40)]
    lines.append(STAMP + hashlib.sha256(label).hexdigest().encode("ascii"))
    return b"\n".join(lines) + b"\n"


def stamped_verdict(record):
    return STAMP + verdict.encode_line(record).encode("ascii") + b"\n"


def _plain(text):
    return STAMP + text.encode("ascii")


def _marker(text):
    return _plain(MARK + "[" + text + "]")


def _group(title):
    return _plain(MARK + "[group]" + title)


def _run_step(command, output):
    """One plain step as the runner writes it: a run header, the echoed command, then output."""
    return (
        [_group("Run " + command),
         _plain(command), _plain("env:"), _marker("endgroup")]
        + [_plain(text) for text in output]
    )


def _composite_step():
    """A composite action step: nested run headers with start and end action markers."""
    ident = "__self.__run"
    return (
        [_group("Run ./composite"),
         _plain("with:"), _marker("endgroup"),
         _marker("start-action display=Inner one;id=" + ident),
         _group("Run inner command"),
         _plain("inner command"), _marker("endgroup"), _plain("inner output"),
         _marker("end-action id=" + ident + ";outcome=success;conclusion=success;duration_ms=19")]
    )


def build_log(line, where="boundary", extra_runs=0, tail=("Cleaning up orphan processes",),
              composite=False, boundary_lines=(), forged=()):
    """A raw job log laid out like the runner writes it, with the verdict line in one place.

    The layout follows downloaded raw logs: image information groups, a line naming the job,
    one run header per step, no per-step footer, and plain cleanup lines as the job tail.
    """
    verdict_line = line.rstrip(b"\n")
    out = []
    if where == "before":
        out.append(verdict_line)
    for title in ("Runner Image Provisioner", "Operating System", "Runner Image"):
        out.extend([_group(title), _plain("Version: fixture"), _marker("endgroup")])
    out.extend(_plain(text) for text in (
        "Prepare workflow directory", "Prepare all required actions",
        "Complete job name: linux-source-build",
    ))
    if where == "setup":
        out.append(verdict_line)
    if composite:
        out.extend(_composite_step())
    else:
        out.extend(_run_step("prepare command", ["prepared"]))
    if where == "prepare":
        out.append(verdict_line)
    out.extend(_run_step("boundary command", ["probing"]))
    out.extend(_plain(text) for text in boundary_lines)
    if where == "boundary":
        out.append(verdict_line)
    for index in range(extra_runs):
        out.extend(_run_step("forged " + str(index), []))
    out.extend(forged)
    out.extend(_plain(text) for text in tail)
    if where == "tail":
        out.append(verdict_line)
    return b"\n".join(out) + b"\n"


def make_job(job_id, check_id, name, steps, status, conclusion):
    return {
        "id": job_id,
        "run_id": RUN_ID,
        "run_attempt": 1,
        "name": name,
        "head_sha": CONTROL,
        "status": status,
        "conclusion": conclusion,
        "check_run_url": "https://api.github.com/repos/" + REPO + "/check-runs/" + str(check_id),
        "steps": [
            {"number": number, "name": step, "status": "completed", "conclusion": "success"}
            for number, step in enumerate(steps, start=1)
        ],
    }


def make_check(check_id):
    return {
        "id": check_id,
        "head_sha": CONTROL,
        "status": "completed",
        "conclusion": "success",
        "output": {"title": "Result", "summary": "Plain summary", "text": None, "annotations_count": 0},
    }


def make_artifact(identifier, name):
    return {
        "id": identifier, "name": name, "size_in_bytes": 10, "expired": False,
        "workflow_run": {"id": RUN_ID, "head_sha": CONTROL},
    }


def make_cache(identifier):
    return {
        "id": identifier, "key": "key-" + str(identifier), "ref": "refs/heads/main", "version": "v1",
        "size_in_bytes": 5 + identifier, "created_at": "2026-10-28T10:00:00Z",
        "last_accessed_at": "2026-10-28T11:00:00Z",
    }


class FakeApi:
    def __init__(self, os_name="linux", mode="candidate"):
        self.expected = {
            "repository": REPO, "os": os_name, "mode": mode, "control_sha": CONTROL,
            "run_id": RUN_ID, "run_attempt": 1, "workflow_path": WORKFLOW, "ci_ref": "untrusted",
            "display_title": TITLE,
            "jobs": {
                SETTINGS_JOB: {"steps": SETTINGS_STEPS, "optional_steps": ()},
                BUILD_JOB: {"steps": BUILD_STEPS, "optional_steps": ("Post cleanup",)},
            },
            "verdict_job": BUILD_JOB, "verdict_step": VERDICT_STEP, "auditor_job": AUDITOR_JOB,
            "artifact_names": (),
            "cache_digest": subject.cache_inventory_digest([]),
        }
        self.run = {
            "id": RUN_ID, "run_attempt": 1, "head_sha": CONTROL, "path": WORKFLOW,
            "head_branch": "untrusted", "event": "workflow_dispatch", "display_title": TITLE,
            "status": "in_progress", "conclusion": None, "repository": {"full_name": REPO},
        }
        self.jobs = [
            make_job(101, 201, SETTINGS_JOB, SETTINGS_STEPS, "completed", "success"),
            make_job(102, 202, BUILD_JOB, BUILD_STEPS, "completed", "success"),
            make_job(103, 203, AUDITOR_JOB, (), "in_progress", None),
        ]
        self.checks = {201: make_check(201), 202: make_check(202)}
        self.annotations = {201: [], 202: []}
        record = (
            verdict_record(os_name) if mode == "candidate"
            else verdict_record(
                os_name, project_execution="not_started", gates=0, failed=0,
                token_revocation="not-applicable",
            )
        )
        self.logs = {
            101: noise_log(b"settings"),
            102: build_log(stamped_verdict(record)),
            103: b"unused",
        }
        self.artifacts = []
        self.caches = []
        self.total_override = {}
        self.fail_paths = set()
        self.log_failures = set()
        self.calls = []

    def set_verdict(self, record):
        self.logs[102] = build_log(stamped_verdict(record))

    def set_annotations(self, check_id, items, count=None):
        self.annotations[check_id] = items
        self.checks[check_id]["output"]["annotations_count"] = len(items) if count is None else count

    def sync_cache_digest(self):
        self.expected["cache_digest"] = subject.cache_inventory_digest(self.caches)

    def _page(self, key, items, page):
        total = self.total_override.get(key, len(items))
        return {"total_count": total, key: items[(page - 1) * 100:page * 100]}

    def json(self, path):
        self.calls.append(path)
        parts = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qs(parts.query)
        page = int(query["page"][0]) if "page" in query else 1
        base = parts.path
        if base in self.fail_paths:
            raise OSError("unavailable")
        prefix = "/repos/" + REPO
        run_path = prefix + "/actions/runs/" + str(RUN_ID)
        if base == run_path:
            body = self.run
        elif base == run_path + "/attempts/1/jobs":
            body = self._page("jobs", self.jobs, page)
        elif base == run_path + "/artifacts":
            body = self._page("artifacts", self.artifacts, page)
        elif base == prefix + "/actions/caches":
            if query.get("sort") != ["created_at"] or query.get("direction") != ["asc"]:
                raise KeyError("unstable cache order")
            body = self._page("actions_caches", self.caches, page)
        else:
            matched = re.fullmatch(re.escape(prefix) + r"/check-runs/([0-9]+)(/annotations)?", base)
            if matched is None:
                raise KeyError(base)
            check_id = int(matched.group(1))
            if matched.group(2):
                body = self.annotations[check_id][(page - 1) * 100:page * 100]
            else:
                body = self.checks[check_id]
        return copy.deepcopy(body), {}

    def log_text(self, job_id):
        if job_id in self.log_failures:
            raise OSError("unavailable")
        return self.logs[job_id]


class AuditCase(unittest.TestCase):
    def assert_refused(self, api, phase, config=CONFIG, expected=None):
        subject_expected = api.expected if expected is None else expected
        with self.assertRaises(subject.AuditRefusal) as caught:
            subject.audit(api, subject_expected, config)
        self.assertEqual(caught.exception.phase, phase)
        self.assertEqual(caught.exception.reason, "confinement_audit_invalid")
        accepted, line = subject.audit_line(api, subject_expected, config)
        self.assertFalse(accepted)
        self.assertEqual(line, subject.refusal_line(phase))
        self.assertNotIn(CANARY, line)
        self.assertNotIn(chr(35), line)

    def assert_accepted(self, api, config=CONFIG):
        line = subject.audit(api, api.expected, config)
        self.assertEqual(subject.audit_line(api, api.expected, config), (True, line))
        return line


class AcceptanceTests(AuditCase):
    def test_complete_consistent_evidence_is_accepted_with_the_fixed_line(self):
        api = FakeApi()
        self.assertEqual(self.assert_accepted(api), ACCEPTED)
        self.assertEqual(
            subject.decode_audit_line(ACCEPTED),
            {
                "status": "accepted", "os": "linux", "mode": "candidate",
                "control_sha": CONTROL, "run_id": RUN_ID, "run_attempt": 1,
            },
        )

    def test_every_expected_surface_is_read(self):
        api = FakeApi()
        subject.audit(api, api.expected, CONFIG)
        prefix = "/repos/" + REPO
        run_path = prefix + "/actions/runs/" + str(RUN_ID)
        query = "?per_page=100&page=1"
        self.assertEqual(
            api.calls,
            [
                run_path,
                run_path + "/attempts/1/jobs" + query,
                prefix + "/check-runs/201",
                prefix + "/check-runs/201/annotations" + query,
                prefix + "/check-runs/202",
                prefix + "/check-runs/202/annotations" + query,
                run_path + "/artifacts" + query,
                prefix + "/actions/caches?sort=created_at&direction=asc&per_page=100&page=1",
            ],
        )

    def test_default_configuration_is_the_pinned_one(self):
        api = FakeApi()
        with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
            self.assertEqual(subject.audit(api, api.expected), ACCEPTED)

    def test_windows_candidate_is_accepted(self):
        api = FakeApi("windows")
        line = self.assert_accepted(api)
        self.assertIn("os=windows", line)

    def test_synthetic_mode_accepts_a_boundary_proof_without_project_gates(self):
        api = FakeApi("linux", "synthetic")
        line = self.assert_accepted(api)
        self.assertIn("mode=synthetic", line)
        candidate = copy.deepcopy(api.expected)
        candidate["mode"] = "candidate"
        self.assert_refused(api, "verdict", expected=candidate)

    def test_expected_caches_and_optional_steps_are_accepted(self):
        api = FakeApi()
        api.caches = [make_cache(7)]
        api.sync_cache_digest()
        api.jobs[1]["steps"][3]["conclusion"] = "skipped"
        self.assert_accepted(api)

    def test_cache_digest_ignores_access_times_only(self):
        api = FakeApi()
        api.caches = [make_cache(7), make_cache(8)]
        api.sync_cache_digest()
        api.caches[0]["last_accessed_at"] = "2026-10-29T00:00:00Z"
        self.assert_accepted(api)
        api.caches[0]["size_in_bytes"] += 1
        self.assert_refused(api, "cache_inventory")

    def test_many_pages_are_read_completely(self):
        api = FakeApi()
        api.caches = [make_cache(number) for number in range(1, 251)]
        api.sync_cache_digest()
        self.assertEqual(subject.audit(api, api.expected, CONFIG), ACCEPTED)
        self.assertEqual(len([call for call in api.calls if "/actions/caches?" in call]), 3)

    def test_exactly_one_full_page_of_annotations_is_accepted(self):
        api = FakeApi()
        api.set_annotations(202, [dict(ANNOTATION, message="note " + str(number)) for number in range(100)])
        self.assert_accepted(api)
        api.set_annotations(201, [dict(ANNOTATION, message="note " + str(number)) for number in range(150)])
        self.assert_accepted(api)


class RunTests(AuditCase):
    def test_wrong_run_identity_is_refused(self):
        updates = (
            {"id": RUN_ID + 1}, {"run_attempt": 2}, {"run_attempt": True}, {"head_sha": "cd" * 20},
            {"path": ".github/workflows/other.yml"}, {"head_branch": "main"}, {"head_branch": "feature/x"},
            {"event": "push"}, {"display_title": "other title"}, {"status": "completed"},
            {"status": "queued"}, {"conclusion": "success"}, {"conclusion": "cancelled"},
            {"repository": {"full_name": "other-org/example-ci"}}, {"repository": None},
            {"repository": {}}, {"id": str(RUN_ID)},
        )
        for change in updates:
            api = FakeApi()
            api.run.update(change)
            with self.subTest(change=change):
                self.assert_refused(api, "run")

    def test_missing_run_fields_are_refused(self):
        for field in ("id", "run_attempt", "head_sha", "path", "head_branch", "event", "display_title", "status", "repository"):
            api = FakeApi()
            del api.run[field]
            with self.subTest(field=field):
                self.assert_refused(api, "run")
        api = FakeApi()
        api.run = []
        self.assert_refused(api, "run")

    def test_untrusted_and_main_refs_are_each_bound(self):
        api = FakeApi()
        api.run["head_branch"] = "main"
        api.expected["ci_ref"] = "main"
        self.assert_accepted(api)
        api.run["head_branch"] = "untrusted"
        self.assert_refused(api, "run")


class JobTests(AuditCase):
    def test_missing_extra_duplicate_and_unnamed_jobs_are_refused(self):
        cases = {}
        missing = FakeApi()
        del missing.jobs[0]
        cases["missing"] = missing
        no_auditor = FakeApi()
        del no_auditor.jobs[2]
        cases["no_auditor"] = no_auditor
        extra = FakeApi()
        extra.jobs.append(make_job(104, 204, "extra", ("Set up job",), "completed", "success"))
        cases["extra"] = extra
        duplicate = FakeApi()
        duplicate.jobs[0] = make_job(104, 204, BUILD_JOB, BUILD_STEPS, "completed", "success")
        cases["duplicate_name"] = duplicate
        same_id = FakeApi()
        same_id.jobs[0]["id"] = 102
        cases["duplicate_id"] = same_id
        renamed = FakeApi()
        renamed.jobs[0]["name"] = "other"
        cases["renamed"] = renamed
        for name, api in cases.items():
            with self.subTest(case=name):
                self.assert_refused(api, "jobs")

    def test_job_identity_mismatches_are_refused(self):
        for field, value in (
            ("run_id", RUN_ID + 1), ("run_attempt", 2), ("head_sha", "cd" * 20),
            ("check_run_url", 5), ("steps", None), ("id", 0), ("id", "101"),
        ):
            api = FakeApi()
            api.jobs[1][field] = value
            with self.subTest(field=field, value=value):
                self.assert_refused(api, "jobs")

    def test_cancelled_skipped_failed_and_unfinished_jobs_never_count(self):
        for status, conclusion in (
            ("completed", "cancelled"), ("completed", "skipped"), ("completed", "failure"),
            ("completed", "timed_out"), ("completed", None), ("in_progress", None),
            ("queued", None), ("completed", "neutral"),
        ):
            for index in (0, 1):
                api = FakeApi()
                api.jobs[index]["status"] = status
                api.jobs[index]["conclusion"] = conclusion
                with self.subTest(status=status, conclusion=conclusion, index=index):
                    self.assert_refused(api, "jobs")

    def test_the_auditor_job_must_be_live(self):
        api = FakeApi()
        api.jobs[2]["status"] = "completed"
        api.jobs[2]["conclusion"] = "success"
        self.assert_refused(api, "jobs")
        api = FakeApi()
        api.jobs[2]["conclusion"] = "success"
        self.assert_refused(api, "jobs")

    def test_step_outcomes_must_be_exactly_as_expected(self):
        def mutate(change):
            api = FakeApi()
            change(api.jobs[1]["steps"])
            return api

        cases = {
            "skipped_required": lambda steps: steps[1].update(conclusion="skipped"),
            "failed_optional": lambda steps: steps[3].update(conclusion="failure"),
            "cancelled_optional": lambda steps: steps[3].update(conclusion="cancelled"),
            "unfinished": lambda steps: steps[1].update(status="in_progress"),
            "no_conclusion": lambda steps: steps[1].update(conclusion=None),
            "renamed": lambda steps: steps[1].update(name="Run other"),
            "renumbered": lambda steps: steps[1].update(number=9),
            "missing": lambda steps: steps.pop(1),
            "extra": lambda steps: steps.append({"number": 5, "name": "Extra", "status": "completed", "conclusion": "success"}),
            "not_dict": lambda steps: steps.__setitem__(1, "step"),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                self.assert_refused(mutate(change), "job_steps")

    def test_pagination_gaps_in_jobs_are_refused(self):
        api = FakeApi()
        api.total_override["jobs"] = 4
        self.assert_refused(api, "pagination")
        api = FakeApi()
        api.total_override["jobs"] = 2
        self.assert_refused(api, "pagination")
        api = FakeApi()
        api.total_override["jobs"] = 10 ** 6
        self.assert_refused(api, "pagination")


class VerdictTests(AuditCase):
    def test_missing_duplicate_misplaced_and_echoed_verdict_lines_are_refused(self):
        line = stamped_verdict(verdict_record())
        missing = FakeApi()
        missing.logs[102] = build_log(b"no verdict here")
        duplicate = FakeApi()
        duplicate.logs[102] += line
        misplaced = FakeApi()
        misplaced.logs[101] += line
        echoed = FakeApi()
        echoed.logs[102] += b"echo " + line
        embedded = FakeApi()
        embedded.logs[102] = build_log(b"prefix " + line)
        for name, api in (
            ("missing", missing), ("duplicate", duplicate), ("misplaced", misplaced),
            ("echoed", echoed), ("embedded", embedded),
        ):
            with self.subTest(case=name):
                self.assert_refused(api, "verdict")

    def test_verdict_must_be_bound_to_the_expected_identity(self):
        for updates in (
            {"control_sha": "cd" * 20}, {"run_id": RUN_ID + 1}, {"run_attempt": 2},
        ):
            api = FakeApi()
            api.set_verdict(verdict_record(**updates))
            with self.subTest(updates=updates):
                self.assert_refused(api, "verdict")
        api = FakeApi("windows")
        api.expected["os"] = "linux"
        self.assert_refused(api, "verdict")
        api = FakeApi("linux")
        api.expected["os"] = "windows"
        self.assert_refused(api, "verdict")

    def test_an_honest_refusal_or_a_weakened_verdict_never_admits(self):
        for channel in verdict.CHANNELS:
            api = FakeApi()
            record = verdict_record()
            record["channels"][channel] = {"status": "observed-leak", "before": True, "after": True}
            api.set_verdict(record)
            with self.subTest(channel=channel):
                self.assert_refused(api, "verdict")
        for field, value in (("memory_canary", "present"), ("readable_file_canary", "not-run")):
            api = FakeApi()
            api.set_verdict(verdict_record(**{field: value}))
            with self.subTest(field=field):
                self.assert_refused(api, "verdict")
        for updates in (
            {"gates": 12}, {"failed": 1}, {"project_execution": "failed"},
            {"project_execution": "not_started", "gates": 0},
            {"token_revocation": "unconfirmed"},
        ):
            api = FakeApi()
            api.set_verdict(verdict_record(**updates))
            with self.subTest(updates=updates):
                self.assert_refused(api, "verdict")
        api = FakeApi("windows")
        api.set_verdict(verdict_record("windows", handoff="failed"))
        self.assert_refused(api, "verdict")

    def test_malformed_verdict_lines_are_refused(self):
        text = verdict.encode_line(verdict_record())
        for broken in (
            text.replace(" dns=blocked/1/1", ""), text + " extra=1", text + " failed=0",
            text.replace("confinement=accepted", "confinement=refused"),
            text.replace("https=blocked/1/1", "https=observed-leak/1/1"),
            text.replace("schema=1", "schema=2"),
        ):
            api = FakeApi()
            api.logs[102] = build_log(STAMP + broken.encode("ascii"))
            with self.subTest(size=len(broken)):
                self.assert_refused(api, "verdict")

    def test_the_verdict_line_must_be_inside_the_required_step_section(self):
        line = stamped_verdict(verdict_record())
        self.assert_accepted(FakeApi())
        for where in ("before", "setup", "prepare", "tail"):
            api = FakeApi()
            api.logs[102] = build_log(line, where)
            with self.subTest(where=where):
                self.assert_refused(api, "verdict")

    def test_the_post_and_cleanup_tail_ends_the_section(self):
        line = stamped_verdict(verdict_record())
        for tail in (
            ("Cleaning up orphan processes",),
            ("Post job cleanup.", "Cleaning up orphan processes"),
            (),
        ):
            api = FakeApi()
            api.logs[102] = build_log(line, "boundary", tail=tail)
            with self.subTest(tail=tail):
                self.assert_accepted(api)
        for tail in (("Post job cleanup.",), ("Post job cleanup.", "Cleaning up orphan processes")):
            api = FakeApi()
            api.logs[102] = build_log(line, "tail", tail=tail)
            with self.subTest(after=tail):
                self.assert_refused(api, "verdict")

    def test_a_forged_tail_or_post_line_inside_the_section_refuses(self):
        line = stamped_verdict(verdict_record())
        for forged in ("Cleaning up orphan processes", "Post job cleanup.", MARK + "[group]Post forged"):
            api = FakeApi()
            api.logs[102] = build_log(line, "boundary", boundary_lines=(forged,))
            with self.subTest(forged=forged):
                self.assert_refused(api, "verdict")

    def test_the_section_layout_must_match_the_steps_that_ran(self):
        line = stamped_verdict(verdict_record())
        api = FakeApi()
        api.logs[102] = build_log(line, "boundary", extra_runs=1)
        self.assert_refused(api, "verdict")
        api = FakeApi()
        forged = (MARK + "[group]Run forged by output").encode("ascii")
        api.logs[102] = build_log(line, "boundary", forged=(STAMP + forged,))
        self.assert_refused(api, "verdict")
        api = FakeApi()
        renamed = (MARK + "[group]Run prepare command").encode("ascii")
        api.logs[102] = build_log(line).replace(renamed, (MARK + "[group]Other").encode("ascii"))
        self.assert_refused(api, "verdict")

    def test_start_and_end_action_markers_are_refused_forged_or_genuine(self):
        line = stamped_verdict(verdict_record())
        markers = (
            MARK + "[end-action id=__self.__run;outcome=success;conclusion=success;duration_ms=1]",
            MARK + "[start-action display=Forged;id=__self.__run]",
        )
        for marker in markers:
            for position in ("boundary_lines", "forged"):
                api = FakeApi()
                if position == "forged":
                    api.logs[102] = build_log(line, "boundary", forged=(_plain(marker),))
                else:
                    api.logs[102] = build_log(line, "boundary", boundary_lines=(marker,))
                with self.subTest(marker=marker[:14], position=position):
                    self.assert_refused(api, "verdict")
        api = FakeApi()
        api.logs[102] = build_log(line, "boundary", composite=True)
        self.assert_refused(api, "verdict")
        api = FakeApi()
        api.logs[102] = build_log(line, "prepare", composite=True)
        self.assert_refused(api, "verdict")

    def test_image_information_groups_are_not_step_sections(self):
        api = FakeApi()
        text = api.logs[102].decode("ascii")
        self.assertIn(MARK + "[group]Runner Image", text)
        self.assertIn("Complete job name: ", text)
        self.assert_accepted(api)

    def test_a_skipped_optional_step_does_not_shift_the_section_mapping(self):
        api = FakeApi()
        api.jobs[1]["steps"][3]["conclusion"] = "skipped"
        self.assert_accepted(api)

    def test_verdict_text_in_an_annotation_or_check_output_is_refused(self):
        text = verdict.encode_line(verdict_record())
        api = FakeApi()
        api.set_annotations(202, [dict(ANNOTATION, message=text)])
        self.assert_refused(api, "annotations")
        api = FakeApi()
        api.checks[201]["output"]["summary"] = "summary " + text
        self.assert_refused(api, "annotations")


def _canary_payloads():
    text = CANARY.encode("ascii")
    return {
        "plain": text,
        "upper": text.upper(),
        "hex": text.hex().encode("ascii"),
        "base64": base64.b64encode(text),
        "base64url": base64.urlsafe_b64encode(text).rstrip(b"="),
        "base64-bin": base64.b64encode(bytes.fromhex(CANARY)),
        "base64-offset": base64.b64encode(b"ab" + text + b"c"),
        "utf16le": CANARY.encode("utf-16-le"),
    }


class CanaryTests(AuditCase):
    def test_canary_in_every_encoding_in_any_job_log_is_refused(self):
        for name, payload in sorted(_canary_payloads().items()):
            for job_id in (101, 102):
                api = FakeApi()
                api.logs[job_id] += b"\n" + STAMP + b"leak " + payload + b" end\n"
                with self.subTest(form=name, job=job_id):
                    self.assert_refused(api, "log_canary")

    def test_canary_in_check_output_or_any_annotation_field_is_refused(self):
        payload = CANARY
        for field in ("title", "summary", "text"):
            api = FakeApi()
            api.checks[202]["output"][field] = "see " + payload
            with self.subTest(output=field):
                self.assert_refused(api, "log_canary")
        for field in ("path", "title", "message", "raw_details", "blob_href"):
            api = FakeApi()
            api.set_annotations(201, [dict(ANNOTATION, **{field: "x " + payload})])
            with self.subTest(annotation=field):
                self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.set_annotations(201, [dict(ANNOTATION, message=base64.b64encode(payload.encode("ascii")).decode("ascii"))])
        self.assert_refused(api, "log_canary")

    def test_a_canary_split_across_log_slices_is_refused(self):
        api = FakeApi()
        filler = b" " * log_canary.SLICE_BYTES
        api.logs[101] = filler[:-30] + CANARY.encode("ascii") + b"\n"
        self.assert_refused(api, "log_canary")

    def test_unpinned_or_invalid_configuration_fails_before_any_request(self):
        api = FakeApi()
        with mock.patch.object(log_canary, "PINNED_CONFIG", None):
            with self.assertRaises(subject.AuditRefusal) as caught:
                subject.audit(api, api.expected)
        self.assertEqual(caught.exception.phase, "log_canary")
        self.assertEqual(api.calls, [])
        for bad in ({}, {"digests": {}, "text_length": 64}, "config", 5):
            with self.subTest(config=repr(bad)[:30]):
                self.assert_refused(api, "log_canary", config=bad)
                self.assertEqual(api.calls, [])

    def test_canary_in_a_failed_or_cancelled_producer_log_wins_over_every_other_refusal(self):
        leak = b"\n" + STAMP + b"leak " + CANARY.encode("ascii") + b"\n"
        for conclusion in ("failure", "cancelled", "timed_out", "skipped", "neutral"):
            for index, job_id in ((0, 101), (1, 102)):
                api = FakeApi()
                api.jobs[index]["conclusion"] = conclusion
                api.logs[job_id] += leak
                with self.subTest(conclusion=conclusion, job=job_id):
                    self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.jobs[1]["conclusion"] = "failure"
        api.jobs[1]["steps"][2]["conclusion"] = "failure"
        api.checks[202]["conclusion"] = "failure"
        api.logs[102] = build_log(b"no verdict here") + leak
        self.assert_refused(api, "log_canary")

    def test_canary_wins_over_an_invalid_verdict_and_other_phases(self):
        api = FakeApi()
        api.set_verdict(verdict_record(gates=12))
        api.set_annotations(201, [dict(ANNOTATION, message="x " + CANARY)])
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.jobs[1]["steps"][1]["conclusion"] = "skipped"
        api.logs[101] += b"\n" + CANARY.encode("ascii") + b"\n"
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        del api.jobs[0]
        api.logs[102] += b"\n" + CANARY.encode("ascii") + b"\n"
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.checks[202]["output"]["summary"] = "bad " + CANARY
        api.checks[201]["head_sha"] = "cd" * 20
        self.assert_refused(api, "log_canary")

    def test_logs_that_are_not_valid_utf8_are_still_scanned_as_bytes(self):
        api = FakeApi()
        api.logs[101] += b"\n" + bytes((255, 254, 250)) + b" binary tail\n"
        self.assert_accepted(api)
        api = FakeApi()
        api.logs[101] += b"\n" + bytes((255, 254, 250)) + CANARY.encode("ascii") + bytes((200,)) + b"\n"
        self.assert_refused(api, "log_canary")

    def test_scanner_budget_exhaustion_fails_closed(self):
        api = FakeApi()
        api.logs[101] = b"a" * 1000
        with mock.patch.object(log_canary, "MAX_WINDOWS", 5):
            self.assert_refused(api, "log_canary")


class SurfaceTests(AuditCase):
    def test_check_runs_must_be_the_completed_successful_check_of_the_same_commit(self):
        cases = (
            {"id": 999}, {"head_sha": "cd" * 20}, {"status": "in_progress"},
            {"conclusion": "failure"},
        )
        for change in cases:
            api = FakeApi()
            api.checks[202].update(change)
            with self.subTest(change=change):
                self.assert_refused(api, "annotations")

    def test_unreadable_or_unparsable_check_output_cannot_prove_the_canary_absent(self):
        cases = (
            {"output": None}, {"output": {"annotations_count": -1}},
            {"output": {"annotations_count": "0"}}, {"output": {"annotations_count": 5000}},
            {"output": {"annotations_count": 0, "summary": 5}},
        )
        for change in cases:
            api = FakeApi()
            api.checks[202].update(change)
            with self.subTest(change=change):
                self.assert_refused(api, "log_canary")

    def test_a_mismatched_check_still_has_its_output_scanned(self):
        api = FakeApi()
        api.checks[202]["head_sha"] = "cd" * 20
        api.checks[202]["output"]["summary"] = "leak " + CANARY
        self.assert_refused(api, "log_canary")

    def test_check_urls_must_point_at_this_repository_over_https(self):
        for url in (
            "https://api.github.com/repos/other-org/example-ci/check-runs/202",
            "http://api.github.com/repos/" + REPO + "/check-runs/202",
            "https://example.com/repos/" + REPO + "/check-runs/202",
            "https://api.github.com/repos/" + REPO + "/check-runs/202?x=1",
            "https://api.github.com/repos/" + REPO + "/check-runs/0",
            "https://api.github.com/repos/" + REPO + "/other/202",
        ):
            api = FakeApi()
            api.jobs[1]["check_run_url"] = url
            with self.subTest(url=url):
                self.assert_refused(api, "annotations")

    def test_annotation_count_mismatches_and_nested_values_are_refused(self):
        api = FakeApi()
        api.set_annotations(202, [dict(ANNOTATION)] * 3, count=5)
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.set_annotations(202, [dict(ANNOTATION)] * 2, count=1)
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.set_annotations(202, [], count=1)
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.set_annotations(202, [dict(ANNOTATION, message={"nested": "value"})])
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.set_annotations(202, ["text"])
        self.assert_refused(api, "log_canary")

    def test_oversized_check_text_is_refused_and_still_scanned(self):
        api = FakeApi()
        api.checks[201]["output"]["text"] = "a" * (subject.MAX_CHECK_TEXT + 1)
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.checks[201]["output"]["text"] = CANARY + "a" * (subject.MAX_CHECK_TEXT + 1)
        self.assert_refused(api, "log_canary")

    def test_an_oversized_annotation_set_is_refused_but_every_job_is_still_scanned(self):
        api = FakeApi()
        api.set_annotations(201, [dict(ANNOTATION, message="a" * 50)] * 4)
        with mock.patch.object(subject, "MAX_ANNOTATION_TEXT", 100):
            self.assert_refused(api, "log_canary")
            api.logs[102] += b"\n" + STAMP + b"leak " + CANARY.encode("ascii") + b"\n"
            self.assert_refused(api, "log_canary")
        self.assert_accepted(FakeApi())

    def test_an_oversized_log_is_refused_with_the_canary_phase_and_still_scanned(self):
        api = FakeApi()
        with mock.patch.object(subject, "MAX_LOG_BYTES", 10):
            self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.logs[101] += b"\n" + CANARY.encode("ascii") + b"\n"
        with mock.patch.object(subject, "MAX_LOG_BYTES", 10):
            self.assert_refused(api, "log_canary")

    def test_a_cap_overrun_on_one_job_does_not_hide_a_leak_in_a_later_job(self):
        api = FakeApi()
        api.set_annotations(201, [dict(ANNOTATION, message="a" * 50)] * 4)
        api.set_annotations(202, [dict(ANNOTATION, message="late " + CANARY)])
        with mock.patch.object(subject, "MAX_ANNOTATION_TEXT", 100):
            with self.assertRaises(subject.AuditRefusal) as caught:
                subject.audit(api, api.expected, CONFIG)
            logs, texts, pending, unscanned = subject._gather(api, api.jobs, api.expected)
        self.assertEqual(caught.exception.phase, "log_canary")
        self.assertTrue(unscanned)
        self.assertTrue(any(CANARY in text for text in texts))
        self.assertEqual(sorted(logs), [101, 102])
        self.assertEqual(pending, [])

    def test_any_artifact_is_refused_because_contents_are_not_scanned(self):
        for items in (
            [make_artifact(1, "unexpected")],
            [make_artifact(1, "capsule"), make_artifact(2, "capsule")],
            [dict(make_artifact(1, "capsule"), expired=True)],
            [dict(make_artifact(1, "capsule"), workflow_run=None)],
        ):
            api = FakeApi()
            api.artifacts = items
            self.assert_refused(api, "artifact_inventory")

    def test_a_non_empty_expected_artifact_set_cannot_be_configured(self):
        for names in (("capsule",), ("a", "b"), ["capsule"], (5,), "capsule"):
            api = FakeApi()
            api.expected["artifact_names"] = names
            api.artifacts = [make_artifact(1, "capsule")]
            with self.subTest(names=names):
                self.assert_refused(api, "request")
                self.assertEqual(api.calls, [])

    def test_artifact_pagination_gaps_are_refused(self):
        api = FakeApi()
        api.total_override["artifacts"] = 3
        self.assert_refused(api, "pagination")

    def test_cache_changes_and_gaps_are_refused(self):
        api = FakeApi()
        api.caches = [make_cache(7)]
        self.assert_refused(api, "cache_inventory")
        api = FakeApi()
        api.caches = [make_cache(7)]
        api.sync_cache_digest()
        api.caches = []
        self.assert_refused(api, "cache_inventory")
        api = FakeApi()
        api.caches = [make_cache(7)]
        api.sync_cache_digest()
        api.caches[0]["key"] = "changed"
        self.assert_refused(api, "cache_inventory")
        api = FakeApi()
        api.caches = [make_cache(number) for number in range(1, 251)]
        api.sync_cache_digest()
        api.total_override["actions_caches"] = 251
        self.assert_refused(api, "pagination")
        api = FakeApi()
        bad = make_cache(7)
        del bad["version"]
        api.caches = [bad]
        self.assert_refused(api, "cache_inventory")

    def test_cache_digest_is_order_independent_and_snapshot_matches(self):
        entries = [make_cache(number) for number in range(1, 6)]
        self.assertEqual(
            subject.cache_inventory_digest(entries), subject.cache_inventory_digest(list(reversed(entries))),
        )
        api = FakeApi()
        api.caches = entries
        self.assertEqual(subject.snapshot_cache_digest(api, REPO), subject.cache_inventory_digest(entries))
        for repository in ("", "no-slash", None, 5):
            with self.assertRaises(subject.AuditRefusal) as caught:
                subject.snapshot_cache_digest(api, repository)
            self.assertEqual(caught.exception.phase, "request")


class FailureTests(AuditCase):
    def test_api_failures_map_to_their_phase(self):
        run_path = "/repos/" + REPO + "/actions/runs/" + str(RUN_ID)
        cases = (
            (run_path, "run"),
            (run_path + "/attempts/1/jobs", "jobs"),
            ("/repos/" + REPO + "/check-runs/202", "log_canary"),
            ("/repos/" + REPO + "/check-runs/202/annotations", "log_canary"),
            (run_path + "/artifacts", "artifact_inventory"),
            ("/repos/" + REPO + "/actions/caches", "cache_inventory"),
        )
        for path, phase in cases:
            api = FakeApi()
            api.fail_paths.add(path)
            with self.subTest(path=path):
                self.assert_refused(api, phase)

    def test_log_failures_and_bad_log_bodies_are_refused(self):
        api = FakeApi()
        api.log_failures.add(102)
        self.assert_refused(api, "log_canary")
        for body in ("text", None, b"", bytearray(b"abc"), 5):
            api = FakeApi()
            api.logs[101] = body
            with self.subTest(kind=type(body).__name__):
                self.assert_refused(api, "log_canary")

    def test_a_truncated_fetch_cannot_prove_the_canary_absent(self):
        class Truncating(FakeApi):
            def log_text(self, job_id):
                raise ValueError("log")

        api = Truncating()
        self.assert_refused(api, "log_canary")
        api = FakeApi()
        api.logs[102] = api.logs[102][:50]
        self.assert_refused(api, "verdict")

    def test_unexpected_client_exceptions_are_contained(self):
        class Broken:
            def json(self, path):
                raise RuntimeError("secret " + CANARY)

            def log_text(self, job_id):
                raise RuntimeError("secret " + CANARY)

        api = FakeApi()
        accepted, line = subject.audit_line(Broken(), api.expected, CONFIG)
        self.assertFalse(accepted)
        self.assertEqual(line, subject.refusal_line("run"))
        self.assertNotIn(CANARY, line)

    def test_incomplete_evidence_is_never_accepted(self):
        for attribute in ("jobs", "artifacts", "caches"):
            api = FakeApi()
            api.total_override[{"jobs": "jobs", "artifacts": "artifacts", "caches": "actions_caches"}[attribute]] = 7
            with self.subTest(attribute=attribute):
                accepted, line = subject.audit_line(api, api.expected, CONFIG)
                self.assertFalse(accepted)
                self.assertIn("status=refused", line)


class ExpectedTests(AuditCase):
    def test_invalid_expected_descriptions_are_refused_before_any_request(self):
        def changed(**updates):
            api = FakeApi()
            api.expected.update(updates)
            return api

        spec = {"steps": ("Set up job",), "optional_steps": ()}
        cases = [
            changed(repository="no-slash"), changed(repository="a/b/c"), changed(repository=5),
            changed(os="macos"), changed(os=None), changed(mode="other"),
            changed(control_sha="AB" * 20), changed(control_sha="ab" * 19), changed(run_id=0),
            changed(run_id=True), changed(run_id=str(RUN_ID)), changed(run_attempt=0),
            changed(run_attempt=2), changed(run_attempt=100),
            changed(workflow_path="other.yml"), changed(workflow_path=".github/workflows/x/y.yml"),
            changed(ci_ref="develop"), changed(ci_ref=None), changed(display_title=""),
            changed(display_title="line\nbreak"), changed(jobs={}), changed(jobs=[]),
            changed(verdict_job="missing-job"), changed(verdict_job=None),
            changed(auditor_job=SETTINGS_JOB), changed(auditor_job=""),
            changed(artifact_names=["capsule"]), changed(artifact_names=("a", "a")),
            changed(artifact_names=("bad name",)), changed(artifact_names=(5,)),
            changed(artifact_names=tuple("a" + str(number) for number in range(21))),
            changed(cache_digest="0" * 63), changed(cache_digest=None),
            changed(jobs={SETTINGS_JOB: {"steps": (), "optional_steps": ()}}, verdict_job=SETTINGS_JOB),
            changed(jobs={SETTINGS_JOB: {"steps": ("a",), "optional_steps": ("b",)}}, verdict_job=SETTINGS_JOB),
            changed(jobs={SETTINGS_JOB: {"steps": ["a"], "optional_steps": ()}}, verdict_job=SETTINGS_JOB),
            changed(jobs={SETTINGS_JOB: {"steps": ("a",)}}, verdict_job=SETTINGS_JOB),
            changed(jobs={SETTINGS_JOB: dict(spec, extra=())}, verdict_job=SETTINGS_JOB),
            changed(jobs={SETTINGS_JOB: "spec"}, verdict_job=SETTINGS_JOB),
            changed(jobs={5: spec}, verdict_job=5),
        ]
        extra = FakeApi()
        extra.expected["extra"] = 1
        cases.append(extra)
        absent = FakeApi()
        del absent.expected["cache_digest"]
        cases.append(absent)
        for index, api in enumerate(cases):
            with self.subTest(case=index):
                self.assert_refused(api, "request")
                self.assertEqual(api.calls, [])
        self.assert_refused(FakeApi(), "request", expected=[])

    def test_attempt_other_than_one_is_refused_in_every_mode(self):
        for mode in ("candidate", "synthetic"):
            for attempt in (2, 3, 99):
                api = FakeApi("linux", mode)
                api.expected["run_attempt"] = attempt
                with self.subTest(mode=mode, attempt=attempt):
                    self.assert_refused(api, "request")
                    self.assertEqual(api.calls, [])

    def test_the_verdict_step_is_required_and_must_be_a_mandatory_sectioned_step(self):
        def with_build_spec(steps, optional):
            api = FakeApi()
            api.expected["jobs"] = dict(api.expected["jobs"])
            api.expected["jobs"][BUILD_JOB] = {"steps": steps, "optional_steps": optional}
            return api

        cases = [
            with_build_spec(BUILD_STEPS, ("Post cleanup", VERDICT_STEP)),
            with_build_spec(("Set up job", VERDICT_STEP, VERDICT_STEP, "Complete job"), ()),
        ]
        for step in ("Post cleanup", "Set up job", "Complete job", "Missing step", None, 5):
            api = FakeApi()
            api.expected["verdict_step"] = step
            cases.append(api)
        absent = FakeApi()
        del absent.expected["verdict_step"]
        cases.append(absent)
        for index, api in enumerate(cases):
            with self.subTest(case=index):
                self.assert_refused(api, "request")
                self.assertEqual(api.calls, [])


class LineTests(unittest.TestCase):
    def test_refusal_lines_use_only_closed_phases(self):
        for phase in sorted(subject.PHASES):
            line = subject.refusal_line(phase)
            self.assertEqual(
                line,
                "KD-CONFINEMENT-AUDIT schema=1 status=refused phase=" + phase
                + " reason=confinement_audit_invalid",
            )
            self.assertEqual(subject.decode_audit_line(line), {"status": "refused", "phase": phase})
            self.assertEqual(subject.decode_audit_line(line.encode("ascii") + b"\n")["phase"], phase)
        self.assertEqual(subject.refusal_line(CANARY), subject.refusal_line("unavailable"))
        self.assertEqual(subject.refusal_line(None), subject.refusal_line("unavailable"))
        self.assertEqual(subject.AuditRefusal(CANARY).phase, "unavailable")
        self.assertNotIn(CANARY, str(subject.AuditRefusal(CANARY)))

    def test_decoder_accepts_only_the_two_fixed_forms(self):
        refusal = subject.refusal_line("run")
        bad = (
            "", "\n", ACCEPTED + " extra=1", ACCEPTED + "\n\n", ACCEPTED.replace("status=accepted", "status=ok"),
            ACCEPTED.replace("log-canary=absent", "log-canary=present"),
            ACCEPTED.replace("caches=unchanged", "caches=changed"),
            ACCEPTED.replace("run-attempt=1", "run-attempt=0"),
            ACCEPTED.replace("mode=candidate", "mode=other"),
            ACCEPTED.replace("os=linux", "os=macos"),
            refusal.replace("phase=run", "phase=other"), refusal.replace("phase=run", "phase=RUN"),
            refusal + " extra=1", refusal.replace("confinement_audit_invalid", "x"),
            "KD-CONFINEMENT-AUDIT schema=1", None, 5, ACCEPTED + " " + "a" * 600,
        )
        for raw in bad:
            with self.subTest(raw=repr(raw)[:50]):
                with self.assertRaises(subject.AuditRefusal) as caught:
                    subject.decode_audit_line(raw)
                self.assertEqual(caught.exception.phase, "unavailable")

    def test_public_lines_carry_no_plan_identifier_or_comment_character(self):
        for line in [ACCEPTED] + [subject.refusal_line(phase) for phase in subject.PHASES]:
            self.assertEqual(re.findall(r"(?<![A-Za-z0-9])[A-Z][0-9]{2,3}(?![0-9])", line), [])
            self.assertNotIn(chr(35), line)


class ParseAndMainTests(AuditCase):
    def environment(self, api, **updates):
        env = {
            subject.EXPECTED_ENV: json.dumps(api.expected),
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_RUN_ID": str(RUN_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": CONTROL,
            "GITHUB_TOKEN": "token-value",
        }
        env.update(updates)
        return env

    def test_expected_json_round_trips_to_the_validated_shape(self):
        api = FakeApi()
        self.assertEqual(subject.parse_expected(json.dumps(api.expected)), api.expected)

    def test_malformed_expected_json_is_refused(self):
        api = FakeApi()
        valid = json.dumps(api.expected)
        duplicate = valid[:-1] + ', "os": "linux"}'
        bad = (
            "", "[]", "null", "{", duplicate, valid.replace('"run_id": 5000123456', '"run_id": NaN'),
            valid.replace('"linux"', '"macos"', 1), "x" * (subject.MAX_EXPECTED_BYTES + 1), None, 5,
        )
        for raw in bad:
            with self.subTest(raw=repr(raw)[:40]):
                with self.assertRaises(subject.AuditRefusal) as caught:
                    subject.parse_expected(raw)
                self.assertEqual(caught.exception.phase, "request")

    def test_main_prints_the_accepted_line_and_exits_zero(self):
        api = FakeApi()
        output = io.StringIO()
        with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
            status = subject.main([], self.environment(api), lambda token, repository: api, output)
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), ACCEPTED + "\n")

    def test_main_refuses_on_identity_mismatch_without_calling_the_api(self):
        for updates in (
            {"GITHUB_RUN_ID": "1"}, {"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_SHA": "cd" * 20},
            {"GITHUB_REPOSITORY": "other-org/example-ci"}, {subject.EXPECTED_ENV: "{}"},
        ):
            api = FakeApi()
            output = io.StringIO()
            with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
                status = subject.main([], self.environment(api, **updates), lambda token, repository: api, output)
            with self.subTest(updates=sorted(updates)):
                self.assertEqual(status, 1)
                self.assertEqual(output.getvalue(), subject.refusal_line("request") + "\n")
                self.assertEqual(api.calls, [])

    def test_main_refuses_with_a_closed_line_when_the_audit_or_client_fails(self):
        api = FakeApi()
        api.log_failures.add(102)
        output = io.StringIO()
        with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
            status = subject.main([], self.environment(api), lambda token, repository: api, output)
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), subject.refusal_line("log_canary") + "\n")

        def broken(token, repository):
            raise RuntimeError("secret " + CANARY)

        output = io.StringIO()
        status = subject.main([], self.environment(api), broken, output)
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), subject.refusal_line("unavailable") + "\n")
        self.assertNotIn(CANARY, output.getvalue())

    def test_main_builds_the_client_for_the_expected_repository(self):
        api = FakeApi()
        seen = []

        def factory(token, repository):
            seen.append((token, repository))
            return api

        output = io.StringIO()
        with mock.patch.object(log_canary, "PINNED_CONFIG", CONFIG):
            subject.main([], self.environment(api), factory, output)
        self.assertEqual(seen, [("token-value", REPO)])

    def test_default_client_reads_logs_of_the_expected_repository_as_undecoded_bytes(self):
        client = subject._default_api_factory("t" * 24, REPO)
        requests = []
        body = bytes((255, 254, 250)) + b" not utf8 " + CANARY.encode("ascii")

        class Headers:
            def __init__(self, values):
                self.values = values

            def get(self, name, default=None):
                return self.values.get(name, default)

            def get_content_type(self):
                return self.values.get("type", "text/plain")

        blob_headers = {"Content-Length": str(len(body))}

        def fake_open(request, limit, allow_redirect=False):
            requests.append((request.full_url, limit, allow_redirect))
            if allow_redirect:
                location = "https://productionresultssa7.blob.core.windows.net/logs/x?sig=1"
                return None, Headers({"Location": location})
            return body, Headers(blob_headers)

        client._open = fake_open
        self.assertEqual(client.log_text(42), body)
        self.assertEqual(
            requests[0][0], "https://api.github.com/repos/" + REPO + "/actions/jobs/42/logs",
        )
        self.assertTrue(requests[0][2])
        self.assertEqual(requests[1][0], "https://productionresultssa7.blob.core.windows.net/logs/x?sig=1")
        self.assertEqual(requests[1][1], subject.MAX_LOG_BYTES)
        for bad in (0, -1, True, "5", None):
            with self.assertRaises(Exception):
                client.log_text(bad)
        truncated = (
            {},
            {"Content-Length": str(len(body) + 1)},
            {"Content-Length": str(len(body) - 1)},
            {"Content-Length": "x" + str(len(body))},
            {"Content-Length": "-" + str(len(body))},
            {"Content-Length": str(len(body)), "type": "text/html"},
            {"Content-Length": str(len(body)), "Content-Encoding": "gzip"},
        )
        for values in truncated:
            blob_headers.clear()
            blob_headers.update(values)
            with self.subTest(headers=sorted(values)):
                with self.assertRaises(ValueError):
                    client.log_text(42)
        blob_headers.clear()
        blob_headers["Content-Length"] = str(len(body))
        self.assertEqual(client.log_text(42), body)
        for repository in ("", "no-slash", None, 5):
            with self.assertRaises(subject.AuditRefusal) as caught:
                subject._default_api_factory("t" * 24, repository)
            self.assertEqual(caught.exception.phase, "request")

    def test_main_refuses_arguments(self):
        api = FakeApi()
        output = io.StringIO()
        self.assertEqual(subject.main(["--flag"], self.environment(api), lambda token, repository: api, output), 2)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
