import base64
import copy
import contextlib
import datetime
import hashlib
from email.message import Message
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.parse
import unittest
import zipfile
from unittest.mock import patch

try:
    from . import feedback_api
    from . import feedback_public_audit as subject
    from . import feedback_request
    from . import macos_public_audit
    from . import node_lock_receipt
except ImportError:
    import feedback_api
    import feedback_public_audit as subject
    import feedback_request
    import macos_public_audit
    import node_lock_receipt


NOW = 1793160000
CONTROL_SHA = "c" * 40
def _request(profile_name="core-rust-format-return"):
    profile = feedback_request.PROFILES[profile_name]
    key = b"synthetic-public-recipient-key"
    fields = {
        "kind": profile["kind"],
        "concern": profile["concern"],
        "ci_repository_id": "1",
        "workflow_path": profile["workflow_path"],
        "workflow_ref": feedback_request.WORKFLOW_REF,
        "repository_id": "2",
        "source_sha": "a" * 40,
        "base_sha": "b" * 40,
        "control_sha": CONTROL_SHA,
        "base_branch": "develop",
        "reviewed_diff_sha256": "d" * 64,
        "recipient_fingerprint": hashlib.sha256(key).hexdigest(),
        "nonce": "f" * 64,
        "expiry": NOW + 3600,
    }
    request = feedback_request.create_request(fields, now=NOW)
    return request, key


def _environment(request, key, job_name):
    profile = feedback_request.PROFILES[request["concern"]]
    return {
        feedback_api.REQUEST_ENV: base64.b64encode(
            feedback_request.encode_request(request, now=NOW)
        ).decode("ascii"),
        feedback_api.RECIPIENT_ENV: base64.b64encode(key).decode("ascii"),
        "KD_FEEDBACK_REQUEST_ID": request["request_id"],
        "CI_REPOSITORY": macos_public_audit.REPOSITORY,
        "CI_REF": "refs/heads/main",
        "CI_SHA": CONTROL_SHA,
        "CI_SERVER_URL": "https://github.com",
        "CI_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": macos_public_audit.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": CONTROL_SHA,
        "GITHUB_WORKFLOW_REF": macos_public_audit.REPOSITORY + "/"
            + profile["workflow_path"] + "@refs/heads/main",
        "GITHUB_JOB": job_name,
        "GITHUB_RUN_ID": "8123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_ACTOR": "fixture-actor",
        "GITHUB_REPOSITORY_ID": "1",
        "SOURCE_REPOSITORY_ID": "2",
        "CORE_CONTRACT_ALLOWED_SHA": request["source_sha"],
        "CORE_CONTRACT_ALLOWED_CONTROL_SHA": CONTROL_SHA,
        "CORE_CONTRACT_REVIEWED_SOURCE_SHA": request["source_sha"],
        "CORE_CONTRACT_REVIEWED_BASE_SHA": request["base_sha"],
        "CORE_CONTRACT_REVIEWED_BASE_BRANCH": request["base_branch"],
        "CORE_CONTRACT_REVIEWED_DIFF_SHA256": request["reviewed_diff_sha256"],
        "CORE_CONTRACT_REVIEWED_CANDIDATE_REF": "refs/heads/fix/feedback-fixture",
        "REQUESTED_SOURCE_SHA": request["source_sha"],
        "REQUESTED_BASE_SHA": request["base_sha"],
        "REQUESTED_BASE_BRANCH": request["base_branch"],
    }


class SurfaceAPI:
    def __init__(self, control_sha, annotations):
        self.control_sha = control_sha
        self.annotations = annotations

    def json(self, path):
        if "/annotations?" in path:
            return self.annotations, {}
        return {
            "id": 88,
            "head_sha": self.control_sha,
            "status": "completed",
            "conclusion": "success",
            "output": {"annotations_count": len(self.annotations), "summary": None, "text": None, "title": None},
        }, {}


class LiveAuditProvider(macos_public_audit.GitHubAPI):
    def __init__(self, request, *, failed_producer=False, now=NOW):
        super().__init__("A" * 24)
        self.request = request
        self.now = now
        self.run_id = 8123
        self.workflow_id = 912
        self.actor = "fixture-actor"
        self.artifact_id = 701
        self.failed_producer = failed_producer
        self.calls = []
        self.log_calls = []
        self.download_calls = 0
        notice = {
            "annotation_level": "notice",
            "blob_href": "https://github.com/" + macos_public_audit.REPOSITORY
                + "/blob/" + request["control_sha"] + "/.github",
            "end_column": None,
            "end_line": 1,
            "message": feedback_api.CAPACITY_NOTICE,
            "path": feedback_api.CAPACITY_NOTICE_PATH,
            "raw_details": "",
            "start_column": None,
            "start_line": 1,
            "title": "",
        }
        self.annotations = {202: [copy.deepcopy(notice) for _ in range(3)],
                            203: [copy.deepcopy(notice) for _ in range(2)]}
        self.archive = self._archive(request)
        self.jobs = self._make_jobs()
        self.details = self._make_details()
        self.logs = self._make_logs()

    @staticmethod
    def _archive(request):
        profile = feedback_request.PROFILES[request["concern"]]
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo(profile["member_name"])
            info.create_system = 3
            info.external_attr = 0o600 << 16
            archive.writestr(info, b"KDLEfixture-ciphertext")
        return output.getvalue()

    def _make_jobs(self):
        profile = feedback_request.PROFILES[self.request["concern"]]
        names = (
            profile["producer_job"] + "-settings",
            profile["producer_job"] + "-prepare",
            profile["producer_job"],
            profile["auditor_job"],
        )
        jobs = []
        for index, name in enumerate(names):
            auditor = name == profile["auditor_job"]
            failed = name == profile["producer_job"] and self.failed_producer
            jobs.append({
                "id": 101 + index,
                "name": name,
                "run_id": self.run_id,
                "run_attempt": 1,
                "head_sha": self.request["control_sha"],
                "status": "in_progress" if auditor else "completed",
                "conclusion": None if auditor else ("failure" if failed else "success"),
                "check_run_url": (
                    "https://api.github.com/repos/" + macos_public_audit.REPOSITORY
                    + "/check-runs/" + str(201 + index)
                ),
            })
        return jobs

    def _make_details(self):
        details = {}
        for job in self.jobs:
            if job["status"] != "completed":
                continue
            conclusion = job["conclusion"]
            steps = [{
                "number": 1,
                "name": "Set up job",
                "status": "completed",
                "conclusion": conclusion,
            }]
            profile = feedback_request.PROFILES[self.request["concern"]]
            if job["name"] == profile["producer_job"] and conclusion == "success":
                steps.extend([
                    {"number": 8, "name": "Run and publish encrypted feedback",
                     "status": "completed", "conclusion": "success"},
                    {"number": 12, "name": feedback_api.PRODUCER_TOKEN_FALLBACK_STEP,
                     "status": "completed", "conclusion": "skipped"},
                    {"number": 13, "name": "Remove staged ciphertext",
                     "status": "completed", "conclusion": "success"},
                ])
            details[job["id"]] = {
                **job,
                "steps": steps,
            }
        return details

    def _make_logs(self):
        profile = feedback_request.PROFILES[self.request["concern"]]
        context_fields = (
            node_lock_receipt.CONTEXT_FIELDS
            if profile["profile_id"] == 1 else node_lock_receipt.FEEDBACK_CONTEXT_FIELDS
        )
        context = {name: self.request[name] for name in context_fields if name in self.request}
        context.update({
            "run_id": str(self.run_id),
            "producer_job": profile["producer_job"],
            "run_attempt": 1,
        })
        timestamp = b"2026-10-28T04:00:00Z "
        digest = macos_public_audit.cache_inventory_digest([])
        logs = {}
        logs[101] = (
            timestamp
            + ("KD-FEEDBACK-CACHE-SNAPSHOT schema=1 control-sha=" + self.request["control_sha"]
               + " run-id=" + str(self.run_id) + " run-attempt=1 digest=" + digest + "\n").encode("ascii")
            + timestamp
            + ("KD-FEEDBACK-SETTINGS schema=1 request-id=" + self.request["request_id"]
               + " profile=" + profile["kind"] + " status=verified\n").encode("ascii")
        )
        logs[102] = (
            timestamp
            + ("KD-FEEDBACK-PREPARE schema=1 request-id=" + self.request["request_id"]
               + " profile=" + profile["kind"] + " status=passed\n").encode("ascii")
        )
        if self.failed_producer:
            logs[103] = timestamp + b"KD-FEEDBACK-CLEANUP schema=1 token-revocation=confirmed\n"
            return logs
        member = b"KDLEfixture-ciphertext"
        producer = {
            **context,
            "schema_version": 1,
            "status": "encrypted",
            "job_name": profile["producer_job"],
            "member_name": profile["member_name"],
            "ciphertext_digest": hashlib.sha256(member).hexdigest(),
            "member_size": len(member),
        }
        archive_digest = hashlib.sha256(self.archive).hexdigest()
        logs[103] = (
            timestamp + b"KD-FEEDBACK-PRODUCER "
            + json.dumps(producer, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
            + b"\n" + timestamp
            + ("KD-FEEDBACK-UPLOAD schema=1 request-id=" + self.request["request_id"]
               + " artifact-id=" + str(self.artifact_id) + " archive-digest=" + archive_digest + "\n").encode("ascii")
            + timestamp
            + ("KD-FEEDBACK-PRODUCER-SUMMARY schema=1 request-id=" + self.request["request_id"]
               + " profile=" + profile["kind"] + " status=encrypted\n").encode("ascii")
        )
        return logs

    def _artifact(self):
        profile = feedback_request.PROFILES[self.request["concern"]]
        created = datetime.datetime.fromtimestamp(self.now - 30, datetime.timezone.utc)
        expires = created + datetime.timedelta(
            seconds=feedback_api.MAX_ARTIFACT_AGE_SECONDS - 1,
        )
        created_text = created.isoformat(timespec="seconds").replace("+00:00", "Z")
        expires_text = expires.isoformat(timespec="seconds").replace("+00:00", "Z")
        return {
            "id": self.artifact_id,
            "node_id": "ART_fixture_701",
            "name": "feedback-" + profile["kind"] + "-" + self.request["request_id"],
            "size_in_bytes": len(self.archive),
            "url": "https://api.github.com/repos/" + macos_public_audit.REPOSITORY
                + "/actions/artifacts/" + str(self.artifact_id),
            "archive_download_url": "https://api.github.com/repos/" + macos_public_audit.REPOSITORY
                + "/actions/artifacts/" + str(self.artifact_id) + "/zip",
            "expired": False,
            "created_at": created_text,
            "updated_at": created_text,
            "expires_at": expires_text,
            "digest": "sha256:" + hashlib.sha256(self.archive).hexdigest(),
            "workflow_run": {
                "id": self.run_id,
                "repository_id": 1,
                "head_repository_id": 1,
                "head_branch": "main",
                "head_sha": self.request["control_sha"],
            },
        }

    def json(self, path):
        self.calls.append(path)
        parsed = urllib.parse.urlsplit(path)
        route = parsed.path
        headers = Message()
        run_path = "/repos/" + macos_public_audit.REPOSITORY + "/actions/runs/" + str(self.run_id)
        if route == run_path:
            return {
                "id": self.run_id,
                "head_sha": self.request["control_sha"],
                "path": self.request["workflow_path"],
                "head_branch": "main",
                "event": "workflow_dispatch",
                "status": "in_progress",
                "conclusion": None,
                "display_title": feedback_api.RUN_TITLE_PREFIX + self.request["request_id"],
                "actor": {"login": self.actor},
                "repository": {"id": 1, "full_name": macos_public_audit.REPOSITORY},
                "run_attempt": 1,
                "workflow_id": self.workflow_id,
            }, headers
        if route.endswith("/actions/workflows/" + str(self.workflow_id)):
            return {"id": self.workflow_id, "path": self.request["workflow_path"], "state": "active"}, headers
        if route.endswith("/actions/workflows/" + str(self.workflow_id) + "/runs"):
            runs = [{
                "id": self.run_id,
                "run_attempt": 1,
                "display_title": feedback_api.RUN_TITLE_PREFIX + self.request["request_id"],
                "head_sha": self.request["control_sha"],
                "path": self.request["workflow_path"],
                "event": "workflow_dispatch",
                "head_branch": "main",
                "status": "in_progress",
                "conclusion": None,
            }]
            return {"total_count": len(runs), "workflow_runs": runs}, headers
        if route.endswith("/actions/runs/" + str(self.run_id) + "/attempts/1/jobs"):
            return {"total_count": len(self.jobs), "jobs": self.jobs}, headers
        if "/actions/jobs/" in route:
            return self.details[int(route.rsplit("/", 1)[1])], headers
        if route.endswith("/actions/caches"):
            return {"total_count": 0, "actions_caches": []}, headers
        if route.endswith("/actions/runs/" + str(self.run_id) + "/artifacts"):
            return {"total_count": 1, "artifacts": [self._artifact()]}, headers
        if "/check-runs/" in route and route.endswith("/annotations"):
            check_id = int(route.split("/check-runs/", 1)[1].split("/", 1)[0])
            return self.annotations.get(check_id, []), headers
        if "/check-runs/" in route:
            check_id = int(route.rsplit("/", 1)[1])
            index = check_id - 201
            job = self.jobs[index]
            return {
                "id": check_id,
                "head_sha": self.request["control_sha"],
                "status": job["status"],
                "conclusion": job["conclusion"],
                "output": {
                    "annotations_count": len(self.annotations.get(check_id, [])),
                    "summary": None,
                    "text": None,
                    "title": None,
                },
            }, headers
        raise AssertionError("unexpected live audit route")

    def log_text(self, job_id):
        self.log_calls.append(job_id)
        return self.logs[job_id]

    def _open(self, request, limit, allow_redirect=False):
        if request.full_url.endswith("/actions/artifacts/701/zip"):
            self.download_calls += 1
            response = Message()
            response["Location"] = "https://productionresultssa1.blob.core.windows.net/archive?token=fixture"
            return None, response
        if request.full_url.startswith("https://productionresultssa1.blob.core.windows.net/"):
            if request.has_header("Authorization"):
                raise AssertionError("authorization must not follow artifact redirect")
            response = Message()
            response.set_type("application/zip")
            response["Content-Length"] = str(len(self.archive))
            return self.archive, response
        raise AssertionError("unexpected live audit download")


class PreflightTests(unittest.TestCase):
    def test_all_registered_profiles_bind_exact_protected_source_fields(self):
        for profile_name in feedback_request.PROFILES:
            request, key = _request(profile_name)
            job_name = feedback_request.PROFILES[profile_name]["producer_job"] + "-settings"
            env = _environment(request, key, job_name)
            parsed, profile = subject._request_from_environment(env, now=NOW)
            self.assertEqual(parsed, request)
            self.assertEqual(profile, feedback_request.PROFILES[profile_name])
            subject._validate_identity(env, request, profile, job_name=job_name)
            subject._validate_protected_binding(env, request)
            subject._decode_recipient(env, request)

    def test_settings_accepts_public_request_without_protected_source_values(self):
        request, key = _request()
        profile = feedback_request.PROFILES[request["concern"]]
        env = _environment(request, key, profile["producer_job"] + "-settings")
        env["GITHUB_TOKEN"] = "A" * 24
        for name in (
            "SOURCE_REPOSITORY_ID", "CORE_CONTRACT_ALLOWED_SHA",
            "CORE_CONTRACT_ALLOWED_CONTROL_SHA", "CORE_CONTRACT_REVIEWED_SOURCE_SHA",
            "CORE_CONTRACT_REVIEWED_BASE_SHA", "CORE_CONTRACT_REVIEWED_BASE_BRANCH",
            "CORE_CONTRACT_REVIEWED_DIFF_SHA256", "CORE_CONTRACT_REVIEWED_CANDIDATE_REF",
        ):
            env.pop(name, None)

        class EmptyCacheAPI:
            def __init__(self, unused_token):
                pass

            def json(self, path):
                if "/actions/caches?" not in path:
                    raise AssertionError("unexpected settings API route")
                return {"total_count": 0, "actions_caches": []}, {}

        with patch.object(subject, "_write_outputs") as output_writer:
            marker = subject.settings(env, api_factory=EmptyCacheAPI, now=NOW)
        self.assertTrue(marker.startswith("KD-FEEDBACK-CACHE-SNAPSHOT schema=1 "))
        self.assertEqual(output_writer.call_args.args[1]["source_sha"], request["source_sha"])
        self.assertEqual(output_writer.call_args.args[1]["base_sha"], request["base_sha"])

    def test_producer_preflight_binds_public_request_to_all_protected_values(self):
        for profile_name in feedback_request.PROFILES:
            request, key = _request(profile_name)
            profile = feedback_request.PROFILES[profile_name]
            env = _environment(request, key, profile["producer_job"])
            line = subject.producer_preflight(env, now=NOW)
            self.assertEqual(
                line,
                "KD-FEEDBACK-BINDING schema=1 request-id=" + request["request_id"]
                + " profile=" + profile["kind"] + " status=verified",
            )
            for name, changed in (
                ("CORE_CONTRACT_REVIEWED_DIFF_SHA256", "e" * 64),
                ("SOURCE_REPOSITORY_ID", "3"),
                ("CORE_CONTRACT_REVIEWED_SOURCE_SHA", "e" * 40),
                ("CORE_CONTRACT_REVIEWED_BASE_SHA", "e" * 40),
                ("CORE_CONTRACT_REVIEWED_BASE_BRANCH", "main"),
                ("CORE_CONTRACT_REVIEWED_CANDIDATE_REF", "refs/heads/main"),
                ("REQUESTED_SOURCE_SHA", "e" * 40),
                ("REQUESTED_BASE_SHA", "e" * 40),
                ("REQUESTED_BASE_BRANCH", "main"),
            ):
                with self.subTest(profile=profile_name, name=name):
                    altered = dict(env, **{name: changed})
                    with self.assertRaises(subject.FeedbackAuditRefusal):
                        subject.producer_preflight(altered, now=NOW)
            altered = dict(
                env,
                **{feedback_api.RECIPIENT_ENV: base64.b64encode(b"wrong-key").decode("ascii")},
            )
            with self.subTest(profile=profile_name, name="recipient"):
                with self.assertRaises(subject.FeedbackAuditRefusal):
                    subject.producer_preflight(altered, now=NOW)

    def test_unbound_candidate_or_recipient_is_refused(self):
        request, key = _request()
        env = _environment(request, key, "core-rust-format-return-settings")
        changed = dict(env, CORE_CONTRACT_REVIEWED_CANDIDATE_REF="refs/heads/main")
        with self.assertRaises(subject.FeedbackAuditRefusal):
            subject._validate_protected_binding(changed, request)
        changed = dict(env, **{feedback_api.RECIPIENT_ENV: base64.b64encode(b"changed").decode("ascii")})
        with self.assertRaises(subject.FeedbackAuditRefusal):
            subject._decode_recipient(changed, request)


class CapacityAnnotationTests(unittest.TestCase):
    @staticmethod
    def _notice():
        return {
            "annotation_level": "notice",
            "blob_href": "https://github.com/" + macos_public_audit.REPOSITORY
                + "/blob/" + CONTROL_SHA + "/.github",
            "end_column": None,
            "end_line": 1,
            "message": feedback_api.CAPACITY_NOTICE,
            "path": feedback_api.CAPACITY_NOTICE_PATH,
            "raw_details": "",
            "start_column": None,
            "start_line": 1,
            "title": "",
        }

    def _scan(self, runner, annotations):
        api = SurfaceAPI(CONTROL_SHA, annotations)
        job = {"check_run_url": "https://api.github.com/repos/"
               + macos_public_audit.REPOSITORY + "/check-runs/88", "conclusion": "success"}
        run = {"head_sha": CONTROL_SHA}
        return subject._check_surface(
            api, job, run, allow_capacity=(runner == "macos-15"),
        )[0]

    def test_mac_capacity_notice_may_repeat_within_the_closed_cap(self):
        notice = self._notice()
        self.assertTrue(self._scan("macos-15", [copy.deepcopy(notice) for _ in range(3)]))
        self.assertTrue(self._scan(
            "macos-15", [copy.deepcopy(notice) for _ in range(feedback_api.MAX_CAPACITY_NOTICES)],
        ))

    def test_changed_mixed_excess_and_non_mac_notices_refuse(self):
        notice = self._notice()
        changed = copy.deepcopy(notice)
        changed["message"] = "different"
        self.assertFalse(self._scan("macos-15", [copy.deepcopy(notice), changed]))
        self.assertFalse(self._scan(
            "macos-15", [copy.deepcopy(notice) for _ in range(feedback_api.MAX_CAPACITY_NOTICES + 1)],
        ))
        self.assertFalse(self._scan("ubuntu-24.04", [copy.deepcopy(notice)]))
        self.assertTrue(self._scan("ubuntu-24.04", []))


class FakeClock:
    def __init__(self, step_multiplier=1):
        self.now = 0.0
        self.sleeps = []
        self.step_multiplier = step_multiplier

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds * self.step_multiplier

    def monotonic(self):
        return self.now


class LiveProviderPipelineTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        patcher = patch.object(
            subject, "_default_clock", return_value=(self.clock.sleep, self.clock.monotonic),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _live(self, profile_name="core-rust-format-return", **provider_options):
        request, key = _request(profile_name)
        profile = feedback_request.PROFILES[request["concern"]]
        environment = _environment(request, key, profile["auditor_job"])
        environment["GITHUB_TOKEN"] = "A" * 24
        return environment, LiveAuditProvider(request, **provider_options)

    @staticmethod
    def _tamper(api, hook):
        original = api.json
        counters = {}

        def wrapped(path):
            result, headers = original(path)
            parsed_path = urllib.parse.urlsplit(path).path
            counters[parsed_path] = counters.get(parsed_path, 0) + 1
            return hook(parsed_path, copy.deepcopy(result), counters[parsed_path]), headers

        api.json = wrapped
        return counters

    def _run_path(self, api):
        return "/repos/" + macos_public_audit.REPOSITORY + "/actions/runs/" + str(api.run_id)

    def _audit(self, environment, api):
        return subject.audit_live(environment, api_factory=lambda unused_token: api, now=NOW)

    def test_readiness_bounds_are_fifteen_attempts_ten_seconds_apart_within_150_seconds(self):
        self.assertEqual(subject.READINESS_ATTEMPTS, 15)
        self.assertEqual(subject.READINESS_INTERVAL_SECONDS, 10)
        self.assertEqual(subject.READINESS_MAX_SECONDS, 150)

    def test_consistent_view_passes_without_any_sleep(self):
        environment, api = self._live()
        line = self._audit(environment, api)
        self.assertTrue(line.startswith("KD-FEEDBACK-AUDIT {"))
        self.assertEqual(self.clock.sleeps, [])

    def test_stale_queued_run_status_that_later_turns_in_progress_passes(self):
        environment, api = self._live()
        run_path = self._run_path(api)

        def hook(path, result, count):
            if path == run_path and count <= 3:
                result["status"] = "queued"
            return result

        self._tamper(api, hook)
        line = self._audit(environment, api)
        self.assertTrue(line.startswith("KD-FEEDBACK-AUDIT {"))
        self.assertEqual(self.clock.sleeps, [10, 10, 10])

    def test_in_progress_step_that_later_completes_passes(self):
        environment, api = self._live()

        def hook(path, result, count):
            if path.endswith("/actions/jobs/103") and count <= 2:
                result["steps"][0]["status"] = "in_progress"
                result["steps"][0]["conclusion"] = None
            return result

        self._tamper(api, hook)
        line = self._audit(environment, api)
        self.assertTrue(line.startswith("KD-FEEDBACK-AUDIT {"))
        self.assertEqual(self.clock.sleeps, [10, 10])

    def test_pending_step_that_later_completes_passes(self):
        environment, api = self._live()

        def hook(path, result, count):
            if path.endswith("/actions/jobs/101") and count <= 1:
                result["steps"][0]["status"] = "pending"
                result["steps"][0]["conclusion"] = None
            return result

        self._tamper(api, hook)
        line = self._audit(environment, api)
        self.assertTrue(line.startswith("KD-FEEDBACK-AUDIT {"))
        self.assertEqual(self.clock.sleeps, [10])

    def test_non_audit_job_listed_as_in_progress_that_later_completes_passes(self):
        environment, api = self._live()

        def hook(path, result, count):
            if path.endswith("/attempts/1/jobs") and count <= 2:
                result["jobs"][2]["status"] = "in_progress"
                result["jobs"][2]["conclusion"] = None
            return result

        self._tamper(api, hook)
        line = self._audit(environment, api)
        self.assertTrue(line.startswith("KD-FEEDBACK-AUDIT {"))
        self.assertEqual(self.clock.sleeps, [10, 10])

    def test_errors_during_readiness_count_as_not_ready_and_are_retried(self):
        environment, api = self._live()
        run_path = self._run_path(api)

        def hook(path, result, count):
            if path == run_path and count <= 2:
                raise RuntimeError("canary-private-value")
            return result

        self._tamper(api, hook)
        line = self._audit(environment, api)
        self.assertTrue(line.startswith("KD-FEEDBACK-AUDIT {"))
        self.assertEqual(self.clock.sleeps, [10, 10])

    def test_persistent_queued_run_refuses_with_the_run_phase_after_the_bound(self):
        environment, api = self._live()
        run_path = self._run_path(api)

        def hook(path, result, count):
            if path == run_path:
                result["status"] = "queued"
            return result

        counters = self._tamper(api, hook)
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            self._audit(environment, api)
        self.assertEqual(caught.exception.phase, "run")
        self.assertEqual(self.clock.sleeps, [10] * 14)
        self.assertLessEqual(self.clock.now, 150)
        self.assertEqual(counters[run_path], 16)

    def test_persistent_unfinished_step_refuses_with_the_job_steps_phase_after_the_bound(self):
        environment, api = self._live()

        def hook(path, result, count):
            if path.endswith("/actions/jobs/102"):
                result["steps"][0]["status"] = "in_progress"
                result["steps"][0]["conclusion"] = None
            return result

        self._tamper(api, hook)
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            self._audit(environment, api)
        self.assertEqual(caught.exception.phase, "job_steps")
        self.assertEqual(self.clock.sleeps, [10] * 14)

    def test_persistently_incomplete_job_listing_refuses_with_the_jobs_phase(self):
        environment, api = self._live()

        def hook(path, result, count):
            if path.endswith("/attempts/1/jobs"):
                result["jobs"][0]["status"] = "in_progress"
                result["jobs"][0]["conclusion"] = None
            return result

        self._tamper(api, hook)
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            self._audit(environment, api)
        self.assertEqual(caught.exception.phase, "job_surfaces")
        self.assertEqual(self.clock.sleeps, [10] * 14)

    def test_no_readiness_reads_happen_after_the_deadline(self):
        environment, api = self._live()
        run_path = self._run_path(api)
        self.clock.step_multiplier = 10

        def hook(path, result, count):
            if path == run_path:
                result["status"] = "queued"
            return result

        counters = self._tamper(api, hook)
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            self._audit(environment, api)
        self.assertEqual(caught.exception.phase, "run")
        self.assertEqual(self.clock.sleeps, [10, 10])
        self.assertEqual(counters[run_path], 3)

    def test_failed_producer_is_ready_at_once_and_still_refuses(self):
        environment, api = self._live(failed_producer=True)
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            self._audit(environment, api)
        self.assertEqual(caught.exception.phase, "job_surfaces")
        self.assertEqual(self.clock.sleeps, [])

    def test_wrong_head_sha_still_refuses_after_the_bound(self):
        environment, api = self._live()
        run_path = self._run_path(api)

        def hook(path, result, count):
            if path == run_path:
                result["head_sha"] = "e" * 40
            return result

        self._tamper(api, hook)
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            self._audit(environment, api)
        self.assertEqual(caught.exception.phase, "run")
        self.assertEqual(self.clock.sleeps, [10] * 14)

    def test_live_audit_accepts_provider_shaped_in_progress_auditor_pipeline(self):
        for profile_name in feedback_request.PROFILES:
            with self.subTest(profile=profile_name):
                request, key = _request(profile_name)
                profile = feedback_request.PROFILES[request["concern"]]
                environment = _environment(request, key, profile["auditor_job"])
                environment["GITHUB_TOKEN"] = "A" * 24
                api = LiveAuditProvider(request)
                line = subject.audit_live(
                    environment, api_factory=lambda unused_token: api, now=NOW,
                )
                self.assertTrue(line.startswith("KD-FEEDBACK-AUDIT {"))
                receipt = json.loads(line[len("KD-FEEDBACK-AUDIT "):])
                self.assertEqual(receipt["status"], "passed")
                self.assertEqual(receipt["job_name"], profile["producer_job"])
                self.assertEqual(receipt["artifact_id"], api.artifact_id)
                combined_calls = " ".join(api.calls)
                self.assertIn("/repos/" + macos_public_audit.REPOSITORY + "/actions/caches?per_page=", combined_calls)
                self.assertIn("/actions/runs/" + str(api.run_id) + "/artifacts?per_page=", combined_calls)
                self.assertEqual(set(api.log_calls), {101, 102, 103})
                self.assertGreaterEqual(api.download_calls, 1)
                for check_id in range(201, 205):
                    self.assertTrue(any("/check-runs/" + str(check_id) + "/annotations?" in call
                                        for call in api.calls))
                history_queries = [
                    urllib.parse.parse_qs(urllib.parse.urlsplit(call).query)
                    for call in api.calls
                    if "/actions/workflows/" + str(api.workflow_id) + "/runs?" in call
                ]
                self.assertEqual(len(history_queries), 1)
                self.assertTrue(all("status" not in query and "filter" not in query
                                    for query in history_queries))
                self.assertEqual(
                    set(history_queries[0]) - {"per_page", "page"},
                    {"branch", "created", "event", "head_sha"},
                )
                self.assertEqual(history_queries[0]["branch"], ["main"])
                self.assertEqual(history_queries[0]["event"], ["workflow_dispatch"])
                self.assertEqual(history_queries[0]["head_sha"], [CONTROL_SHA])
                self.assertEqual(history_queries[0]["created"], ["2026-10-27..2026-10-28"])
                self.assertEqual(history_queries[0]["page"], ["1"])

    def test_failed_producer_still_scans_jobs_checks_annotations_artifact_and_cache(self):
        request, key = _request()
        profile = feedback_request.PROFILES[request["concern"]]
        environment = _environment(request, key, profile["auditor_job"])
        environment["GITHUB_TOKEN"] = "A" * 24
        api = LiveAuditProvider(request, failed_producer=True)
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            subject.audit_live(
                environment, api_factory=lambda unused_token: api, now=NOW,
            )
        self.assertEqual(caught.exception.phase, "job_surfaces")
        combined_calls = " ".join(api.calls)
        self.assertIn("/actions/runs/" + str(api.run_id) + "/artifacts?per_page=", combined_calls)
        self.assertIn("/repos/" + macos_public_audit.REPOSITORY + "/actions/caches?per_page=", combined_calls)
        self.assertEqual(set(api.log_calls), {101, 102, 103})
        for check_id in range(201, 205):
            self.assertTrue(any("/check-runs/" + str(check_id) in call for call in api.calls))
            self.assertTrue(any("/check-runs/" + str(check_id) + "/annotations?" in call
                                for call in api.calls))
        self.assertGreaterEqual(api.download_calls, 1)
        history_queries = [
            urllib.parse.parse_qs(urllib.parse.urlsplit(call).query)
            for call in api.calls
            if "/actions/workflows/" + str(api.workflow_id) + "/runs?" in call
        ]
        self.assertEqual(len(history_queries), 1)
        self.assertTrue(all("status" not in query and "filter" not in query
                            for query in history_queries))
        self.assertEqual(
            set(history_queries[0]) - {"per_page", "page"},
            {"branch", "created", "event", "head_sha"},
        )
        self.assertEqual(history_queries[0]["branch"], ["main"])
        self.assertEqual(history_queries[0]["event"], ["workflow_dispatch"])
        self.assertEqual(history_queries[0]["head_sha"], [CONTROL_SHA])
        self.assertEqual(history_queries[0]["created"], ["2026-10-27..2026-10-28"])
        self.assertEqual(history_queries[0]["page"], ["1"])

    def test_live_audit_rejects_unknown_producer_skip_even_with_success_summary(self):
        request, key = _request()
        profile = feedback_request.PROFILES[request["concern"]]
        environment = _environment(request, key, profile["auditor_job"])
        environment["GITHUB_TOKEN"] = "A" * 24
        api = LiveAuditProvider(request)
        fallback = next(step for step in api.details[103]["steps"]
                        if step["name"] == feedback_api.PRODUCER_TOKEN_FALLBACK_STEP)
        fallback["name"] = "Unexpected skipped cleanup"
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            subject.audit_live(
                environment, api_factory=lambda unused_token: api, now=NOW,
            )
        self.assertEqual(caught.exception.phase, "job_steps")
        self.assertEqual(set(api.log_calls), {101, 102, 103})
        self.assertTrue(any("/actions/runs/" + str(api.run_id) + "/artifacts?per_page=" in call
                            for call in api.calls))
        self.assertTrue(any("/actions/caches?per_page=" in call for call in api.calls))

    def test_live_audit_requires_producer_success_summary_for_skipped_fallback(self):
        request, key = _request()
        profile = feedback_request.PROFILES[request["concern"]]
        environment = _environment(request, key, profile["auditor_job"])
        environment["GITHUB_TOKEN"] = "A" * 24
        api = LiveAuditProvider(request)
        api.logs[103] = api.logs[103].replace(
            b"KD-FEEDBACK-PRODUCER-SUMMARY ", b"KD-FEEDBACK-OTHER-SUMMARY ",
        )
        with self.assertRaises(subject.FeedbackAuditRefusal):
            subject.audit_live(
                environment, api_factory=lambda unused_token: api, now=NOW,
            )

    def test_timestamped_cache_snapshot_log_uses_actual_provider_line_shape(self):
        digest = macos_public_audit.cache_inventory_digest([])
        log = (
            "2026-10-28T04:00:00Z KD-FEEDBACK-CACHE-SNAPSHOT schema=1 control-sha="
            + CONTROL_SHA + " run-id=8123 run-attempt=1 digest=" + digest + "\n"
        ).encode("ascii")
        self.assertEqual(subject._read_cache_snapshot(log, CONTROL_SHA, "8123"), digest)

    def test_early_audit_refusals_identify_fixed_validation_phase(self):
        request, key = _request()
        profile = feedback_request.PROFILES[request["concern"]]
        environment = _environment(request, key, profile["auditor_job"])
        environment["GITHUB_TOKEN"] = "A" * 24
        invalid_request = dict(environment, **{feedback_api.REQUEST_ENV: "not-canonical"})
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            subject.audit_live(invalid_request, api_factory=lambda unused_token: self.fail(), now=NOW)
        self.assertEqual(caught.exception.phase, "request")

        invalid_identity = dict(environment, GITHUB_ACTOR="canary_private_value")
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            subject.audit_live(invalid_identity, api_factory=lambda unused_token: self.fail(), now=NOW)
        self.assertEqual(caught.exception.phase, "identity")
        self.assertNotIn("canary_private_value", str(caught.exception))

        api = LiveAuditProvider(request)
        original_json = api.json

        def wrong_run(path):
            result, headers = original_json(path)
            if path == "/repos/" + macos_public_audit.REPOSITORY + "/actions/runs/" + str(api.run_id):
                result = dict(result, head_sha="e" * 40)
            return result, headers

        api.json = wrong_run
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            subject.audit_live(environment, api_factory=lambda unused_token: api, now=NOW)
        self.assertEqual(caught.exception.phase, "run")

        api = LiveAuditProvider(request)
        original_json = api.json

        def inactive_workflow(path):
            result, headers = original_json(path)
            if path.endswith("/actions/workflows/" + str(api.workflow_id)):
                result = dict(result, state="disabled")
            return result, headers

        api.json = inactive_workflow
        with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
            subject.audit_live(environment, api_factory=lambda unused_token: api, now=NOW)
        self.assertEqual(caught.exception.phase, "workflow")

        api = LiveAuditProvider(request)
        with patch.object(subject, "_history_for_live_run", side_effect=RuntimeError("canary")):
            with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
                subject.audit_live(environment, api_factory=lambda unused_token: api, now=NOW)
        self.assertEqual(caught.exception.phase, "history")
        self.assertNotIn("canary", str(caught.exception))

    def test_job_collection_failure_has_fixed_phase_and_no_dynamic_details(self):
        request, key = _request()
        profile = feedback_request.PROFILES[request["concern"]]
        environment = _environment(request, key, profile["auditor_job"])
        environment["GITHUB_TOKEN"] = "A" * 24
        api = LiveAuditProvider(request)
        original_reader = subject.public_audit._read_counted_collection

        def fail_jobs(api_client, path, *args, **kwargs):
            if path.endswith("/attempts/1/jobs"):
                raise RuntimeError("canary-private-value")
            return original_reader(api_client, path, *args, **kwargs)

        with patch.object(subject.public_audit, "_read_counted_collection", side_effect=fail_jobs):
            with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
                subject.audit_live(environment, api_factory=lambda unused_token: api, now=NOW)
        self.assertEqual(caught.exception.phase, "jobs")
        self.assertNotIn("canary-private-value", str(caught.exception))

    def test_history_collection_diagnostics_stay_closed_through_live_audit(self):
        for api_reason, expected_phase in (
            ("api_status", "history_all_api_status"),
            ("api_schema", "history_all_api_schema"),
            ("pagination_incomplete", "history_all_api_pagination"),
            ("api_unavailable", "history_all_api_unavailable"),
        ):
            with self.subTest(reason=api_reason):
                request, key = _request()
                profile = feedback_request.PROFILES[request["concern"]]
                environment = _environment(request, key, profile["auditor_job"])
                environment["GITHUB_TOKEN"] = "A" * 24
                api = LiveAuditProvider(request)
                original_reader = subject.public_audit._read_counted_collection

                def fail_history(client, path, *args, **kwargs):
                    if "/actions/workflows/" in path and path.endswith("/runs"):
                        raise macos_public_audit.AuditRefusal(api_reason)
                    return original_reader(client, path, *args, **kwargs)

                with patch.object(
                    subject.public_audit, "_read_counted_collection", side_effect=fail_history,
                ):
                    with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
                        subject.audit_live(
                            environment, api_factory=lambda unused_token: api, now=NOW,
                        )
                self.assertEqual(caught.exception.phase, expected_phase)
                self.assertEqual(caught.exception.reason, "feedback_audit_invalid")
                self.assertNotIn(api_reason, str(caught.exception))

        request, key = _request()
        profile = feedback_request.PROFILES[request["concern"]]
        environment = _environment(request, key, profile["auditor_job"])
        environment["GITHUB_TOKEN"] = "A" * 24
        api = LiveAuditProvider(request)
        with patch.object(
            subject.public_audit, "_read_counted_collection",
            side_effect=RuntimeError("private provider response"),
        ):
            with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
                subject.audit_live(environment, api_factory=lambda unused_token: api, now=NOW)
        self.assertEqual(caught.exception.phase, "history_all_api_unavailable")
        self.assertNotIn("private provider response", str(caught.exception))

    def test_late_failures_keep_first_phase_while_audit_scans_remaining_surfaces(self):
        for expected_phase in (
            "check_surfaces", "job_logs", "artifact_inventory", "artifact_download",
            "cache_snapshot", "summary_markers", "producer_evidence",
        ):
            with self.subTest(phase=expected_phase):
                request, key = _request()
                profile = feedback_request.PROFILES[request["concern"]]
                environment = _environment(request, key, profile["auditor_job"])
                environment["GITHUB_TOKEN"] = "A" * 24
                api = LiveAuditProvider(request)
                stack = contextlib.ExitStack()

                if expected_phase == "check_surfaces":
                    original_check = subject._check_surface

                    def failed_check(client, job, run, **kwargs):
                        valid, check_id = original_check(client, job, run, **kwargs)
                        if check_id == 201:
                            return False, check_id
                        return valid, check_id

                    stack.enter_context(patch.object(subject, "_check_surface", side_effect=failed_check))
                elif expected_phase == "job_logs":
                    original_log = api.log_text

                    def failed_log(job_id):
                        if job_id == 103:
                            api.log_calls.append(job_id)
                            raise RuntimeError("canary-private-value")
                        return original_log(job_id)

                    api.log_text = failed_log
                elif expected_phase == "artifact_inventory":
                    original_reader = subject.public_audit._read_counted_collection

                    def failed_inventory(client, path, *args, **kwargs):
                        if path.endswith("/actions/runs/" + str(api.run_id) + "/artifacts"):
                            api.calls.append(path + "?per_page=100&page=1")
                            raise RuntimeError("canary-private-value")
                        return original_reader(client, path, *args, **kwargs)

                    stack.enter_context(patch.object(
                        subject.public_audit, "_read_counted_collection", side_effect=failed_inventory,
                    ))
                elif expected_phase == "artifact_download":
                    stack.enter_context(patch.object(
                        feedback_api, "_download_archive", side_effect=RuntimeError("canary-private-value"),
                    ))
                elif expected_phase == "cache_snapshot":
                    def failed_cache_snapshot(client, control_sha):
                        api.calls.append(
                            "/repos/" + macos_public_audit.REPOSITORY
                            + "/actions/caches?per_page=100&page=1",
                        )
                        raise RuntimeError("canary-private-value")

                    stack.enter_context(patch.object(
                        subject, "_snapshot_cache", side_effect=failed_cache_snapshot,
                    ))
                elif expected_phase == "summary_markers":
                    api.logs[101] = api.logs[101].replace(
                        b"KD-FEEDBACK-SETTINGS ", b"KD-FEEDBACK-OTHER-SETTINGS ",
                    )
                elif expected_phase == "producer_evidence":
                    api.logs[103] = api.logs[103].replace(b"KD-FEEDBACK-UPLOAD ", b"KD-FEEDBACK-OTHER-UPLOAD ")

                with stack:
                    with self.assertRaises(subject.FeedbackAuditRefusal) as caught:
                        subject.audit_live(environment, api_factory=lambda unused_token: api, now=NOW)
                self.assertEqual(caught.exception.phase, expected_phase)
                combined_calls = " ".join(api.calls)
                self.assertIn("/actions/runs/" + str(api.run_id) + "/artifacts?per_page=", combined_calls)
                self.assertIn("/actions/caches?per_page=", combined_calls)
                self.assertEqual(set(api.log_calls), {101, 102, 103})
                self.assertTrue(any("/check-runs/" + str(check_id) + "/annotations?" in call
                                    for check_id in range(201, 205) for call in api.calls))

    def test_audit_refusal_command_emits_only_fixed_phase_record(self):
        with patch.object(subject, "audit_live", side_effect=subject.FeedbackAuditRefusal("history")):
            with patch("builtins.print") as printer:
                status = subject.main(["audit"], {})
        self.assertEqual(status, 2)
        printer.assert_called_once_with(subject._failure_record("history"))

        with patch.object(subject, "audit_live", side_effect=subject.FeedbackAuditRefusal("private-value")):
            with patch("builtins.print") as printer:
                status = subject.main(["audit"], {})
        self.assertEqual(status, 2)
        printer.assert_called_once_with(subject._failure_record("unavailable"))

    def test_refusal_normalizer_accepts_only_canonical_closed_phase_records(self):
        prefix = b"KD-FEEDBACK-AUDIT-REFUSAL "
        valid = prefix + b'{"phase":"history","reason":"feedback_audit_invalid","schema_version":1}\n'
        expected = prefix + b'{"phase":"history","reason":"feedback_audit_invalid","schema_version":1}'
        self.assertEqual(subject.normalize_refusal(valid), expected.decode("ascii"))
        for phase in feedback_api.HISTORY_FAILURE_PHASES:
            record = json.dumps(
                {"phase": phase, "reason": "feedback_audit_invalid", "schema_version": 1},
                ensure_ascii=True, separators=(",", ":"), sort_keys=True,
            ).encode("ascii")
            self.assertEqual(
                subject.normalize_refusal(prefix + record),
                (prefix + record).decode("ascii"),
            )
        unavailable = subject._failure_record("unavailable")
        invalid_records = (
            prefix + b'{"phase":"canary-private-value","reason":"feedback_audit_invalid","schema_version":1}',
            prefix + b'{"phase":"history","reason":"canary-private-value","schema_version":1}',
            prefix + b'{"phase":"history","reason":"feedback_audit_invalid","schema_version":1,"extra":"canary-private-value"}',
            prefix + b'{"phase":"history","phase":"run","reason":"feedback_audit_invalid","schema_version":1}',
            valid + b"unexpected trailing record\n",
            b"canary-private-value",
            b"KD-FEEDBACK-AUDIT-REFUSAL " + b"x" * subject.MAX_RECORD_BYTES,
        )
        for raw in invalid_records:
            with self.subTest(raw_length=len(raw)):
                normalized = subject.normalize_refusal(raw)
                self.assertEqual(normalized, unavailable)
                self.assertNotIn("canary-private-value", normalized)

    def test_normalize_refusal_cli_reads_bounded_stdin_and_emits_only_safe_record(self):
        raw = (
            b'KD-FEEDBACK-AUDIT-REFUSAL {"phase":"artifact_download",'
            b'"reason":"feedback_audit_invalid","schema_version":1}\n'
        )

        class BoundedInput:
            def __init__(self, value):
                self.value = value
                self.requested_size = None

            def read(self, size):
                self.requested_size = size
                return self.value[:size]

        buffer = BoundedInput(raw)
        stream = type("InputStream", (), {"buffer": buffer})()
        with patch.object(subject.sys, "stdin", stream):
            with patch("builtins.print") as printer:
                status = subject.main(["normalize-refusal"], {})
        self.assertEqual(status, 0)
        self.assertEqual(buffer.requested_size, subject.MAX_RECORD_BYTES + 1)
        printer.assert_called_once_with(subject._failure_record("artifact_download"))


class AuditWorkflowShellSyntaxTests(unittest.TestCase):
    @staticmethod
    def _audit_script(workflow_path):
        lines = Path(workflow_path).read_text(encoding="utf-8").splitlines()
        step_line = "      - name: Audit completed producer and public surfaces"
        matches = [index for index, line in enumerate(lines) if line == step_line]
        if len(matches) != 1:
            raise AssertionError("expected one audit workflow step")
        run_index = None
        for index in range(matches[0] + 1, len(lines)):
            if lines[index].startswith("      - name:"):
                break
            if lines[index] == "        run: |":
                run_index = index
                break
        if run_index is None:
            raise AssertionError("audit workflow step has no literal run block")
        body_indent = len(lines[run_index]) - len(lines[run_index].lstrip(" ")) + 2
        body = []
        for line in lines[run_index + 1:]:
            if not line.strip():
                body.append("")
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent < body_indent:
                break
            body.append(line[body_indent:])
        script = "\n".join(body).rstrip() + "\n"
        if not script.strip():
            raise AssertionError("audit workflow run block is empty")
        return script

    def test_all_return_workflow_audit_blocks_parse_with_bash(self):
        bash = shutil.which("bash")
        if os.name == "nt" and bash is None:
            self.skipTest("Windows runner has no Bash executable available")
        self.assertIsNotNone(bash, "Bash is required on POSIX workflow test runners")
        repository_root = Path(__file__).resolve().parents[2]
        workflow_paths = (
            repository_root / ".github/workflows/node-lock-return.yml",
            repository_root / ".github/workflows/core-rust-format-return.yml",
            repository_root / ".github/workflows/core-build-diagnostic-return.yml",
        )
        scripts = [self._audit_script(path) for path in workflow_paths]
        self.assertEqual(len(scripts), 3)
        for script in scripts:
            result = subprocess.run(
                [bash, "-n"], input=script, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, "audit workflow shell must parse")


if __name__ == "__main__":
    unittest.main()
