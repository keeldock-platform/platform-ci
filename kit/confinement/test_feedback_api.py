import datetime
import hashlib
from email.message import Message
import io
import json
import urllib.parse
import zipfile
import unittest
from unittest.mock import patch

try:
    from . import feedback_api
    from . import feedback_request
    from . import macos_public_audit
except ImportError:
    import feedback_api
    import feedback_request
    import macos_public_audit


class ProviderShapedAPI(macos_public_audit.GitHubAPI):
    def __init__(self, request, now):
        super().__init__("A" * 24)
        self.request_record = request
        self.now = now
        self.run_id = 8123
        self.actor = "fixture-actor"
        self.workflow_id = 912
        self.archive = self._archive(request)
        self.artifact_id = 701
        self.jobs = self._jobs()
        self.details = self._details()
        self.logs = self._logs()
        self.status_override = {}
        self.run_override = {}
        self.extra_artifacts = []
        self.duplicate_history = []
        self.history_records = {status: [] for status in (
            "completed", "queued", "in_progress", "waiting", "pending", "requested",
        )}
        self.history_records["completed"] = [self._history_record("completed", "success")]
        self.redirect_override = None
        self.retention_delta_seconds = -2
        self.created_offset_seconds = 0
        self.annotations = {}

    @staticmethod
    def _archive(request):
        profile = feedback_request.PROFILES[request["concern"]]
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo(profile["member_name"])
            info.create_system = 3
            info.external_attr = 0o600 << 16
            archive.writestr(info, b"KDLEfixture-ciphertext")
        return result.getvalue()

    def _job_names(self):
        profile = feedback_request.PROFILES[self.request_record["concern"]]
        return (
            profile["producer_job"] + "-settings",
            profile["producer_job"] + "-prepare",
            profile["producer_job"],
            profile["auditor_job"],
        )

    def _jobs(self):
        return [
            {
                "id": 101 + index,
                "name": name,
                "run_id": self.run_id,
                "run_attempt": 1,
                "head_sha": self.request_record["control_sha"],
                "status": "completed",
                "conclusion": "success",
                "check_run_url": (
                    "https://api.github.com/repos/" + macos_public_audit.REPOSITORY
                    + "/check-runs/" + str(201 + index)
                ),
            }
            for index, name in enumerate(self._job_names())
        ]

    def _details(self):
        profile = feedback_request.PROFILES[self.request_record["concern"]]
        details = {}
        for index, job in enumerate(self.jobs):
            steps = [{
                "number": 1, "name": "Set up job", "status": "completed", "conclusion": "success",
            }]
            if job["name"] == profile["producer_job"]:
                steps.extend([
                    {"number": 8, "name": "Run and publish encrypted feedback",
                     "status": "completed", "conclusion": "success"},
                    {"number": 12, "name": feedback_api.PRODUCER_TOKEN_FALLBACK_STEP,
                     "status": "completed", "conclusion": "skipped"},
                    {"number": 13, "name": "Remove staged ciphertext",
                     "status": "completed", "conclusion": "success"},
                ])
            details[101 + index] = {**job, "steps": steps}
        return details

    def _logs(self):
        profile = feedback_request.PROFILES[self.request_record["concern"]]
        context_fields = (
            feedback_api.node_lock_receipt.CONTEXT_FIELDS
            if profile["profile_id"] == 1
            else feedback_api.node_lock_receipt.FEEDBACK_CONTEXT_FIELDS
        )
        context = {name: self.request_record[name] for name in context_fields if name in self.request_record}
        context.update({
            "run_id": str(self.run_id), "producer_job": profile["producer_job"], "run_attempt": 1,
        })
        member = self._archive_member()
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
        receipt = {
            **context,
            "schema_version": 1,
            "status": "passed",
            "job_name": profile["producer_job"],
            "artifact_id": self.artifact_id,
            "ciphertext_digest": producer["ciphertext_digest"],
            "archive_digest": archive_digest,
            "job_id": 103,
            "size": len(self.archive),
            "retention": 1,
            "member_size": len(member),
            "archive_size": len(self.archive),
        }
        producer_line = json.dumps(producer, sort_keys=True, separators=(",", ":"))
        receipt_line = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        upload_line = (
            "KD-FEEDBACK-UPLOAD schema=1 request-id=" + self.request_record["request_id"]
            + " artifact-id=" + str(self.artifact_id) + " archive-digest=" + archive_digest
        )
        logs = {101 + index: b"trusted fixed job summary\n" for index in range(4)}
        logs[103] = (
            "KD-FEEDBACK-PRODUCER " + producer_line + "\n" + upload_line + "\n"
            + "KD-FEEDBACK-PRODUCER-SUMMARY schema=1 request-id="
            + self.request_record["request_id"] + " profile=" + profile["kind"]
            + " status=encrypted\n"
        ).encode("ascii")
        logs[104] = ("KD-FEEDBACK-AUDIT " + receipt_line + "\n").encode("ascii")
        return logs

    def _archive_member(self):
        with zipfile.ZipFile(io.BytesIO(self.archive), "r") as archive:
            return archive.read(archive.infolist()[0])

    def _history_record(self, status, conclusion):
        return {
            "id": self.run_id,
            "run_attempt": 1,
            "display_title": feedback_api.RUN_TITLE_PREFIX + self.request_record["request_id"],
            "head_sha": self.request_record["control_sha"],
            "path": self.request_record["workflow_path"],
            "event": "workflow_dispatch",
            "head_branch": "main",
            "status": status,
            "conclusion": conclusion,
        }

    def json(self, path):
        parsed = urllib.parse.urlsplit(path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        headers = Message()
        if route.endswith("/actions/runs/" + str(self.run_id)):
            record = {
                "id": self.run_id,
                "head_sha": self.request_record["control_sha"],
                "path": self.request_record["workflow_path"],
                "head_branch": "main",
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "display_title": feedback_api.RUN_TITLE_PREFIX + self.request_record["request_id"],
                "actor": {"login": self.actor},
                "repository": {"id": 1, "full_name": macos_public_audit.REPOSITORY},
                "run_attempt": 1,
                "workflow_id": self.workflow_id,
            }
            record.update(self.run_override)
            return record, headers
        if route.endswith("/actions/workflows/" + str(self.workflow_id)):
            return {"id": self.workflow_id, "path": self.request_record["workflow_path"], "state": "active"}, headers
        if route.endswith("/actions/workflows/" + str(self.workflow_id) + "/runs"):
            status = query["status"][0]
            matches = list(self.history_records[status])
            if status == "completed":
                matches.extend(self.duplicate_history)
            return {"total_count": len(matches), "workflow_runs": matches}, headers
        if route.endswith("/actions/runs/" + str(self.run_id) + "/attempts/1/jobs"):
            return {"total_count": len(self.jobs), "jobs": self.jobs}, headers
        if "/actions/jobs/" in route:
            job_id = int(route.rsplit("/", 1)[1])
            return self.details[job_id], headers
        if "/check-runs/" in route and route.endswith("/annotations"):
            check_id = int(route.split("/check-runs/", 1)[1].split("/", 1)[0])
            return self.annotations.get(check_id, []), headers
        if "/check-runs/" in route:
            check_id = int(route.rsplit("/", 1)[1])
            index = check_id - 201
            return {
                "id": check_id,
                "head_sha": self.request_record["control_sha"],
                "status": "completed",
                "conclusion": self.jobs[index]["conclusion"],
                "output": {
                    "annotations_count": len(self.annotations.get(check_id, [])),
                    "annotations_url": "https://api.github.com/repos/"
                        + macos_public_audit.REPOSITORY + "/check-runs/" + str(check_id) + "/annotations",
                    "summary": None,
                    "text": None,
                    "title": None,
                },
            }, headers
        if route.endswith("/actions/runs/" + str(self.run_id) + "/artifacts"):
            artifacts = [self._artifact()]
            artifacts.extend(self.extra_artifacts)
            return {"total_count": len(artifacts), "artifacts": artifacts}, headers
        raise AssertionError("unexpected provider route")

    def _artifact(self):
        created = datetime.datetime.fromtimestamp(
            self.now + self.created_offset_seconds - 30, datetime.timezone.utc,
        )
        expires = created + datetime.timedelta(
            seconds=feedback_api.MAX_ARTIFACT_AGE_SECONDS + self.retention_delta_seconds,
        )
        created_text = created.isoformat(timespec="seconds").replace("+00:00", "Z")
        expires_text = expires.isoformat(timespec="seconds").replace("+00:00", "Z")
        profile = feedback_request.PROFILES[self.request_record["concern"]]
        return {
            "id": self.artifact_id,
            "node_id": "ART_fixture_701",
            "name": "feedback-" + profile["kind"] + "-" + self.request_record["request_id"],
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
                "head_sha": self.request_record["control_sha"],
            },
        }

    def log_text(self, job_id):
        return self.logs[job_id]

    def _open(self, request, limit, allow_redirect=False):
        if request.full_url.endswith("/actions/artifacts/701/zip"):
            headers = Message()
            headers["Location"] = (
                self.redirect_override
                if self.redirect_override is not None
                else "https://productionresultssa1.blob.core.windows.net/archive?token=fixture"
            )
            return None, headers
        if request.full_url.startswith("https://productionresultssa1.blob.core.windows.net/"):
            if request.has_header("Authorization"):
                raise AssertionError("authorization must not follow the redirect")
            headers = Message()
            headers.set_type("application/zip")
            headers["Content-Length"] = str(len(self.archive))
            return self.archive, headers
        raise AssertionError("unexpected download request")


class FeedbackAPIProviderShapeTests(unittest.TestCase):
    def setUp(self):
        self.now = 1793160000
        profile = feedback_request.PROFILES["core-rust-format-return"]
        self.fields = {
            "kind": profile["kind"],
            "concern": profile["concern"],
            "ci_repository_id": "1",
            "workflow_path": profile["workflow_path"],
            "workflow_ref": feedback_request.WORKFLOW_REF,
            "repository_id": "2",
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "control_sha": "c" * 40,
            "base_branch": "develop",
            "reviewed_diff_sha256": "d" * 64,
            "recipient_fingerprint": "e" * 64,
            "nonce": "f" * 64,
            "expiry": self.now + 3600,
        }
        self.request = feedback_request.create_request(self.fields, now=self.now)
        self.api = ProviderShapedAPI(self.request, self.now)

    def _collect(self):
        return feedback_api.collect_feedback_evidence(
            self.api, self.request,
            expected_actor_login="fixture-actor",
            run_id=str(self.api.run_id), run_attempt=1, now=self.now,
        )

    def _history(self, *, live=False):
        profile = feedback_request.PROFILES[self.request["concern"]]
        run = {"id": self.api.run_id, "workflow_id": self.api.workflow_id}
        return feedback_api._history(
            self.api, self.request, profile, run, "fixture-actor", self.now, live=live,
        )

    def test_history_collection_refusals_are_mapped_to_closed_reasons(self):
        for api_reason, expected in (
            ("api_status", "history_completed_api_status"),
            ("api_schema", "history_completed_api_schema"),
            ("pagination_incomplete", "history_completed_api_pagination"),
            ("api_unavailable", "history_completed_api_unavailable"),
        ):
            with self.subTest(reason=api_reason):
                with patch.object(
                    macos_public_audit, "_read_counted_collection",
                    side_effect=macos_public_audit.AuditRefusal(api_reason),
                ):
                    with self.assertRaises(feedback_api.HistoryRefusal) as caught:
                        self._history()
                self.assertEqual(caught.exception.diagnostic, expected)
                self.assertNotIn(api_reason, str(caught.exception))

        with patch.object(
            macos_public_audit, "_read_counted_collection",
            side_effect=RuntimeError("private response text"),
        ):
            with self.assertRaises(feedback_api.HistoryRefusal) as caught:
                self._history()
        self.assertEqual(caught.exception.diagnostic, "history_completed_api_unavailable")
        self.assertNotIn("private response text", str(caught.exception))

    def test_history_api_failure_phase_names_the_fixed_query_status(self):
        original_reader = macos_public_audit._read_counted_collection
        for status in feedback_api.HISTORY_COLLECTION_STATUSES:
            with self.subTest(status=status):
                def fail_selected(client, path, *args, **kwargs):
                    if kwargs.get("fixed_query", {}).get("status") == status:
                        raise macos_public_audit.AuditRefusal("api_status")
                    return original_reader(client, path, *args, **kwargs)

                with patch.object(
                    macos_public_audit, "_read_counted_collection", side_effect=fail_selected,
                ):
                    with self.assertRaises(feedback_api.HistoryRefusal) as caught:
                        self._history()
                self.assertEqual(caught.exception.diagnostic, "history_" + status + "_api_status")

    def test_history_aggregate_limit_reports_the_status_that_exceeded_it(self):
        self.api.history_records["completed"] = [
            dict(self.api._history_record("completed", "success"), id=8124, display_title="older run"),
            dict(self.api._history_record("completed", "success"), id=8125, display_title="another run"),
        ]
        self.api.history_records["queued"] = [
            dict(self.api._history_record("queued", None), id=8126, display_title="queued run"),
        ]
        with patch.object(feedback_api, "MAX_HISTORY_RUNS", 2):
            with self.assertRaises(feedback_api.HistoryRefusal) as caught:
                self._history()
        self.assertEqual(caught.exception.diagnostic, "history_queued_api_pagination")

    def test_history_match_and_identity_refusals_are_distinct(self):
        self.api.history_records["completed"] = []
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history()
        self.assertEqual(caught.exception.diagnostic, "history_match_zero")

        self.api.history_records["completed"] = [self.api._history_record("completed", "success")]
        self.api.duplicate_history = [dict(
            self.api._history_record("completed", "success"), id=self.api.run_id + 1,
        )]
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history()
        self.assertEqual(caught.exception.diagnostic, "history_match_multiple")

        self.api.duplicate_history = []
        self.api.history_records["completed"] = [
            self.api._history_record("completed", "success"),
            dict(self.api._history_record("completed", "success"), display_title="unrelated run"),
        ]
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history()
        self.assertEqual(caught.exception.diagnostic, "history_duplicate_ids")

        self.api.history_records["completed"] = [dict(
            self.api._history_record("completed", "success"), id=self.api.run_id + 1,
        )]
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history()
        self.assertEqual(caught.exception.diagnostic, "history_identity_mismatch")

        self.api.history_records["completed"] = [self.api._history_record("completed", "success")]
        self.api.history_records["queued"] = [dict(
            self.api._history_record("completed", "success"),
            display_title="unrelated run",
        )]
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history()
        self.assertEqual(caught.exception.diagnostic, "history_duplicate_ids")

    def test_malformed_history_entry_has_only_the_fixed_schema_diagnostic(self):
        self.api.history_records["completed"] = [{"id": self.api.run_id}]
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history()
        self.assertEqual(caught.exception.diagnostic, "history_completed_api_schema")

    def test_history_status_mismatch_is_distinct_from_identity(self):
        self.api.history_records["completed"] = []
        self.api.history_records["in_progress"] = [self.api._history_record("in_progress", None)]
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history()
        self.assertEqual(caught.exception.diagnostic, "history_status_mismatch")

        self.api.history_records["in_progress"] = []
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history(live=True)
        self.assertEqual(caught.exception.diagnostic, "history_match_zero")

        self.api.history_records["in_progress"] = []
        self.api.history_records["completed"] = [self.api._history_record("completed", "success")]
        with self.assertRaises(feedback_api.HistoryRefusal) as caught:
            self._history(live=True)
        self.assertEqual(caught.exception.diagnostic, "history_status_mismatch")

    def test_realistic_completed_provider_shape_is_accepted(self):
        result = self._collect()
        self.assertEqual(result["actor_login"], "fixture-actor")
        self.assertEqual(result["artifact_name"], "feedback-rust_patch-" + self.request["request_id"])
        self.assertEqual(len(result["api_evidence"]["jobs"]), 4)
        self.assertEqual(len(result["archive_bytes"]), result["receipt"]["archive_size"])

    def test_confirmed_producer_may_skip_only_its_token_fallback(self):
        self.assertEqual(len(self._collect()["api_evidence"]["jobs"]), 4)

        producer_steps = self.api.details[103]["steps"]
        fallback = next(step for step in producer_steps
                        if step["name"] == feedback_api.PRODUCER_TOKEN_FALLBACK_STEP)
        fallback["name"] = "Unexpected skipped cleanup"
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_skipped_fallback_requires_the_exact_producer_success_summary(self):
        self.api.logs[103] = self.api.logs[103].replace(
            b"KD-FEEDBACK-PRODUCER-SUMMARY ", b"KD-FEEDBACK-OTHER-SUMMARY ",
        )
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_conflicting_producer_summary_records_are_refused(self):
        profile = feedback_request.PROFILES[self.request["concern"]]
        wrong_records = (
            "KD-FEEDBACK-PRODUCER-SUMMARY schema=1 request-id="
            + self.request["request_id"] + " profile=wrong_profile status=encrypted\n",
            "KD-FEEDBACK-PRODUCER-SUMMARY schema=1 request-id="
            + ("0" * 64) + " profile=" + profile["kind"] + " status=encrypted\n",
            "KD-FEEDBACK-PRODUCER-SUMMARY schema=1 request-id="
            + self.request["request_id"] + " profile=" + profile["kind"]
            + " status=encrypted extra=1\n",
        )
        for wrong_record in wrong_records:
            with self.subTest(record=wrong_record):
                self.api = ProviderShapedAPI(self.request, self.now)
                self.api.logs[103] += wrong_record.encode("ascii")
                with self.assertRaises(feedback_api.FeedbackAPIRefusal):
                    self._collect()

    def test_producer_summary_shell_echo_is_not_a_second_record(self):
        self.api.logs[103] = (
            b'2026-10-28T04:00:00Z line="KD-FEEDBACK-PRODUCER-SUMMARY schema=1"\n'
            + self.api.logs[103]
        )
        self.assertEqual(len(self._collect()["api_evidence"]["jobs"]), 4)

    def test_producer_success_always_requires_its_exact_success_summary(self):
        fallback = next(step for step in self.api.details[103]["steps"]
                        if step["name"] == feedback_api.PRODUCER_TOKEN_FALLBACK_STEP)
        fallback["conclusion"] = "success"
        self.api.logs[103] = self.api.logs[103].replace(
            b"KD-FEEDBACK-PRODUCER-SUMMARY ", b"KD-FEEDBACK-OTHER-SUMMARY ",
        )
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_duplicate_or_noncompleted_fallback_steps_are_refused(self):
        producer_steps = self.api.details[103]["steps"]
        fallback = next(step for step in producer_steps
                        if step["name"] == feedback_api.PRODUCER_TOKEN_FALLBACK_STEP)
        producer_steps.append({**fallback, "number": 14})
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

        self.api = ProviderShapedAPI(self.request, self.now)
        fallback = next(step for step in self.api.details[103]["steps"]
                        if step["name"] == feedback_api.PRODUCER_TOKEN_FALLBACK_STEP)
        fallback["status"] = "in_progress"
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_successful_duplicate_fallback_name_cannot_accompany_allowed_skip(self):
        producer_steps = self.api.details[103]["steps"]
        fallback = next(step for step in producer_steps
                        if step["name"] == feedback_api.PRODUCER_TOKEN_FALLBACK_STEP)
        producer_steps.append({**fallback, "number": 14, "conclusion": "success"})
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_fallback_rejects_every_other_status_and_conclusion(self):
        for status, conclusion in (
            ("queued", "success"),
            ("in_progress", "success"),
            ("completed", "failure"),
            ("completed", "cancelled"),
        ):
            with self.subTest(status=status, conclusion=conclusion):
                self.api = ProviderShapedAPI(self.request, self.now)
                fallback = next(step for step in self.api.details[103]["steps"]
                                if step["name"] == feedback_api.PRODUCER_TOKEN_FALLBACK_STEP)
                fallback["status"] = status
                fallback["conclusion"] = conclusion
                with self.assertRaises(feedback_api.FeedbackAPIRefusal):
                    self._collect()

    def test_nonproducer_job_cannot_use_the_producer_fallback_skip(self):
        self.api.details[101]["steps"] = list(self.api.details[103]["steps"])
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_closed_capacity_notices_are_allowed_only_on_macos_jobs(self):
        notice = {
            "annotation_level": "notice",
            "blob_href": "https://github.com/" + macos_public_audit.REPOSITORY
                + "/blob/" + self.request["control_sha"] + "/.github",
            "end_column": None,
            "end_line": 1,
            "message": feedback_api.CAPACITY_NOTICE,
            "path": feedback_api.CAPACITY_NOTICE_PATH,
            "raw_details": "",
            "start_column": None,
            "start_line": 1,
            "title": "",
        }
        self.api.annotations = {
            202: [dict(notice) for _ in range(3)],
            203: [dict(notice) for _ in range(2)],
        }
        self._collect()
        self.api.annotations[201] = [dict(notice)]
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()
        self.api.annotations = {203: [dict(notice) for _ in range(feedback_api.MAX_CAPACITY_NOTICES + 1)]}
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()
        changed = dict(
            notice,
            blob_href=("https://" + "github.com/" + "other/repo/blob/"
                       + self.request["control_sha"] + "/.github"),
        )
        self.api.annotations = {203: [dict(notice), changed]}
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_wrong_actor_is_refused(self):
        self.api.actor = "different-actor"
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_oversized_provider_identifier_is_refused(self):
        self.api.run_override = {"workflow_id": 10 ** 30}
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_duplicate_request_history_is_refused(self):
        self.api.duplicate_history = [{
            "id": 8124,
            "run_attempt": 1,
            "display_title": feedback_api.RUN_TITLE_PREFIX + self.request["request_id"],
            "head_sha": self.request["control_sha"],
            "path": self.request["workflow_path"],
            "event": "workflow_dispatch",
            "head_branch": "main",
            "status": "completed",
            "conclusion": "success",
        }]
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_extra_artifact_is_refused(self):
        extra = dict(self.api._artifact())
        extra["id"] = 702
        self.api.extra_artifacts = [extra]
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_oversized_redirect_location_is_refused(self):
        self.api.redirect_override = (
            "https://productionresultssa1.blob.core.windows.net/"
            + "a" * 9000 + "?token=x"
        )
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()

    def test_artifact_expiry_accepts_any_live_duration_up_to_one_day(self):
        for delta in (-3600, -60, -2, 0):
            with self.subTest(delta=delta):
                self.api.retention_delta_seconds = delta
                self.assertEqual(self._collect()["receipt"]["retention"], 1)
        for delta in (1, -86400, -86401, -86370):
            with self.subTest(delta=delta):
                self.api.retention_delta_seconds = delta
                with self.assertRaises(feedback_api.FeedbackAPIRefusal):
                    self._collect()
        self.api.retention_delta_seconds = 60
        self.api.created_offset_seconds = 31
        with self.assertRaises(feedback_api.FeedbackAPIRefusal):
            self._collect()


if __name__ == "__main__":
    unittest.main()
