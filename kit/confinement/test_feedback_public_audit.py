import base64
import copy
import datetime
import hashlib
from email.message import Message
import io
import json
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
            details[job["id"]] = {
                **job,
                "steps": [{
                    "number": 1,
                    "name": "Set up job",
                    "status": "completed",
                    "conclusion": conclusion,
                }],
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
        query = urllib.parse.parse_qs(parsed.query)
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
            status = query["status"][0]
            runs = []
            if status == "in_progress":
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


class LiveProviderPipelineTests(unittest.TestCase):
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
                self.assertEqual(len(history_queries), 6)
                self.assertEqual(
                    {query["status"][0] for query in history_queries},
                    {"completed", "queued", "in_progress", "waiting", "pending", "requested"},
                )
                self.assertTrue(all(query.get("filter") == ["all"] for query in history_queries))

    def test_failed_producer_still_scans_jobs_checks_annotations_artifact_and_cache(self):
        request, key = _request()
        profile = feedback_request.PROFILES[request["concern"]]
        environment = _environment(request, key, profile["auditor_job"])
        environment["GITHUB_TOKEN"] = "A" * 24
        api = LiveAuditProvider(request, failed_producer=True)
        with self.assertRaises(subject.FeedbackAuditRefusal):
            subject.audit_live(
                environment, api_factory=lambda unused_token: api, now=NOW,
            )
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
        self.assertEqual(len(history_queries), 6)
        self.assertEqual(
            {query["status"][0] for query in history_queries},
            {"completed", "queued", "in_progress", "waiting", "pending", "requested"},
        )
        self.assertTrue(all(query.get("filter") == ["all"] for query in history_queries))

    def test_timestamped_cache_snapshot_log_uses_actual_provider_line_shape(self):
        digest = macos_public_audit.cache_inventory_digest([])
        log = (
            "2026-10-28T04:00:00Z KD-FEEDBACK-CACHE-SNAPSHOT schema=1 control-sha="
            + CONTROL_SHA + " run-id=8123 run-attempt=1 digest=" + digest + "\n"
        ).encode("ascii")
        self.assertEqual(subject._read_cache_snapshot(log, CONTROL_SHA, "8123"), digest)


if __name__ == "__main__":
    unittest.main()
