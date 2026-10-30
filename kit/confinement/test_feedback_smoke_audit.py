import copy
import hashlib
import io
import re
import stat
import unittest
import zipfile
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from email.message import Message
from unittest import mock

import feedback_smoke_audit as subject


CONTROL_SHA = "a" * 40
RUN_ID = "24680"
REPOSITORY_ID = 123456789
ARTIFACT_ID = 97531
JOB_IDS = {"ubuntu-24.04": 101, "macos-15": 102, "windows-2025": 103}
CHECK_IDS = {"ubuntu-24.04": 201, "macos-15": 202, "windows-2025": 203}
CAPACITY_NOTICE = subject._macos_capacity_notice(CONTROL_SHA)


def _ciphertext(runner):
    return b"KDLE" + runner.encode("ascii").ljust(124, b"-")


def _archive(member):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo(subject.ZIP_MEMBER)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o600) << 16
        archive.writestr(info, member)
    return stream.getvalue()


def _cipher_marker(runner, digest, size=128):
    return (
        "KD-FEEDBACK-CIPHERTEXT schema=1 control-sha={sha} run-id={run_id} "
        "run-attempt=1 member=lock-return-v1.enc ciphertext-sha256={digest} "
        "ciphertext-size={size} roundtrip=passed source=synthetic"
    ).format(sha=CONTROL_SHA, run_id=RUN_ID, digest=digest, size=size).encode("ascii")


def _upload_marker(digest, archive_digest, size=128):
    return (
        "KD-FEEDBACK-UPLOAD schema=1 control-sha={sha} run-id={run_id} "
        "run-attempt=1 artifact-id={artifact_id} artifact-digest={archive_digest} "
        "artifact-name=development-feedback-smoke-{run_id}-1 "
        "ciphertext-sha256={digest} ciphertext-size={size}"
    ).format(
        sha=CONTROL_SHA, run_id=RUN_ID, artifact_id=ARTIFACT_ID,
        archive_digest=archive_digest, digest=digest, size=size,
    ).encode("ascii")


def _fixture(*, retention_seconds=24 * 60 * 60 - 2, created_offset_seconds=-300, now=None):
    member = _ciphertext("macos-15")
    archive = _archive(member)
    cipher_digests = {
        runner: hashlib.sha256(_ciphertext(runner)).hexdigest()
        for runner in subject.RUNNERS
    }
    archive_digest = hashlib.sha256(archive).hexdigest()
    current = datetime.now(timezone.utc).replace(microsecond=0) if now is None else now
    created = current + timedelta(seconds=created_offset_seconds)
    expires = created + timedelta(seconds=retention_seconds)
    jobs = []
    checks = {}
    annotations = {}
    logs = {}
    for index, runner in enumerate(subject.RUNNERS):
        job_id = JOB_IDS[runner]
        check_id = CHECK_IDS[runner]
        jobs.append({
            "id": job_id,
            "name": subject.PRODUCER_PREFIX + runner,
            "run_id": int(RUN_ID),
            "run_attempt": 1,
            "head_sha": CONTROL_SHA,
            "status": "completed",
            "conclusion": "success",
            "check_run_url": (
                "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/"
                + str(check_id)
            ),
        })
        annotations[check_id] = [copy.deepcopy(CAPACITY_NOTICE)] if runner == "macos-15" else []
        checks[check_id] = {
            "id": check_id,
            "head_sha": CONTROL_SHA,
            "status": "completed",
            "conclusion": "success",
            "output": {
                "title": None,
                "summary": None,
                "text": None,
                "annotations_count": len(annotations[check_id]),
            },
        }
        log = _cipher_marker(runner, cipher_digests[runner])
        if runner == "macos-15":
            log += b"\n" + _upload_marker(cipher_digests[runner], archive_digest)
        logs[job_id] = log + b"\n"
    jobs.append({
        "id": 104,
        "name": subject.AUDITOR_JOB,
        "run_id": int(RUN_ID),
        "run_attempt": 1,
        "head_sha": CONTROL_SHA,
        "status": "in_progress",
        "conclusion": None,
    })
    record = {
        "id": ARTIFACT_ID,
        "name": "development-feedback-smoke-24680-1",
        "size_in_bytes": len(archive),
        "expired": False,
        "digest": "sha256:" + archive_digest,
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workflow_run": {
            "id": int(RUN_ID),
            "repository_id": REPOSITORY_ID,
            "head_sha": CONTROL_SHA,
        },
    }
    state = {
        "run": {
            "id": int(RUN_ID),
            "path": subject.WORKFLOW_PATH,
            "head_branch": "main",
            "head_sha": CONTROL_SHA,
            "event": "push",
            "run_attempt": 1,
            "status": "in_progress",
            "conclusion": None,
            "repository": {"id": REPOSITORY_ID, "full_name": subject.REPOSITORY},
            "head_repository": {"id": REPOSITORY_ID, "full_name": subject.REPOSITORY},
        },
        "jobs": jobs,
        "checks": checks,
        "annotations": annotations,
        "logs": logs,
        "artifacts": [record],
        "archive": archive,
    }
    env = {
        "CI_REPOSITORY": subject.REPOSITORY,
        "CI_REF": "refs/heads/main",
        "CI_SHA": CONTROL_SHA,
        "CI_SERVER_URL": "https://github.com",
        "CI_EVENT_NAME": "push",
        "GITHUB_RUN_ID": RUN_ID,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID),
        "GITHUB_WORKFLOW": "development-feedback-smoke",
        "GITHUB_TOKEN": "ghs_" + "x" * 32,
    }
    return state, env


class FakeAPI:
    def __init__(self, state):
        self.state = state
        self._token = "ghs_" + "x" * 32
        self.calls = []
        self.requests = []
        self.log_calls = []

    def json(self, path):
        self.calls.append(path)
        if path.endswith("/actions/runs/24680"):
            return self.state["run"], {}
        if path.endswith("/actions/runs/24680/jobs?filter=all&per_page=100&page=1"):
            return {"total_count": len(self.state["jobs"]), "jobs": self.state["jobs"]}, {}
        if "/check-runs/" in path and path.endswith("/annotations?per_page=100&page=1"):
            check_id = int(path.split("/check-runs/")[1].split("/")[0])
            return self.state["annotations"][check_id], {}
        if "/check-runs/" in path:
            check_id = int(path.rsplit("/", 1)[1])
            return self.state["checks"][check_id], {}
        if path.endswith("/actions/runs/24680/artifacts?per_page=100&page=1"):
            artifacts = self.state["artifacts"]
            return {"total_count": len(artifacts), "artifacts": artifacts}, {}
        raise AssertionError("unexpected API path")

    def log_text(self, job_id):
        self.log_calls.append(job_id)
        return self.state["logs"][job_id]

    def _open(self, request, limit, allow_redirect=False):
        self.requests.append(request)
        if allow_redirect:
            headers = Message()
            headers["Location"] = (
                "https://productionresultssa0.blob.core.windows.net/actions-results/archive.zip?sig=synthetic"
            )
            return None, headers
        archive = self.state["archive"]
        headers = Message()
        headers["Content-Type"] = "application/zip"
        headers["Content-Length"] = str(len(archive))
        headers["Content-Encoding"] = "identity"
        return archive, headers


class Clock:
    def __init__(self, hook=None):
        self.now = 0.0
        self.sleeps = []
        self.hook = hook

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds
        if self.hook is not None:
            self.hook(len(self.sleeps))

    def monotonic(self):
        return self.now


class LogGateAPI(FakeAPI):
    def __init__(self, state, failures=0, blocked=()):
        super().__init__(state)
        self.failures = failures
        self.blocked = set(blocked)

    def log_text(self, job_id):
        if job_id in self.blocked:
            raise OSError("synthetic log unavailable")
        if self.failures > 0:
            self.failures -= 1
            raise OSError("synthetic log unavailable")
        return super().log_text(job_id)


class PartialLogAPI(FakeAPI):
    def __init__(self, state, job_id, partial_log, partial_reads):
        super().__init__(state)
        self.job_id = job_id
        self.partial_log = partial_log
        self.partial_reads = partial_reads

    def log_text(self, job_id):
        if job_id == self.job_id and self.partial_reads != 0:
            if self.partial_reads > 0:
                self.partial_reads -= 1
            return self.partial_log
        return super().log_text(job_id)


class FaultAPI(FakeAPI):
    def __init__(self, state, suffix, mode, count):
        super().__init__(state)
        self.suffix = suffix
        self.mode = mode
        self.count = count

    def json(self, path):
        if path.endswith(self.suffix) and self.count != 0:
            if self.count > 0:
                self.count -= 1
            if self.mode == "raise":
                self.calls.append(path)
                raise OSError("synthetic server error")
            value, headers = super().json(path)
            return dict(value, total_count=value["total_count"] - 1), headers
        return super().json(path)


def _audit(state, env, clock=None, api=None):
    clock = Clock() if clock is None else clock
    api = FakeAPI(state) if api is None else api
    result = subject.audit_feedback_smoke(
        env, lambda _token: api, clock.sleep, clock.monotonic
    )
    return result, api


class MarkerTests(unittest.TestCase):
    def test_ciphertext_and_upload_markers_are_bounded_and_canonical(self):
        cipher = _cipher_marker("macos-15", hashlib.sha256(_ciphertext("macos-15")).hexdigest())
        upload = _upload_marker(
            hashlib.sha256(_ciphertext("macos-15")).hexdigest(),
            hashlib.sha256(_archive(_ciphertext("macos-15"))).hexdigest(),
        )
        self.assertEqual(subject.parse_ciphertext_marker(cipher)["run_id"], RUN_ID)
        self.assertEqual(subject.parse_upload_marker(upload)["artifact_id"], ARTIFACT_ID)
        for raw in (
            cipher + b"\n" + cipher,
            cipher + b"\n" + subject.CANARY,
            cipher.replace(b"roundtrip=passed", b"roundtrip=skipped"),
        ):
            with self.subTest(prefix=raw[:40]), self.assertRaises(subject.SmokeAuditRefusal):
                subject.parse_ciphertext_marker(raw)

    def test_marker_lines_do_not_count_shell_assignments_as_public_records(self):
        marker = _cipher_marker("ubuntu-24.04", hashlib.sha256(_ciphertext("ubuntu-24.04")).hexdigest())
        log = b'  marker="KD-FEEDBACK-CIPHERTEXT shell text"\n' + marker + b"\n"
        self.assertEqual(subject.parse_ciphertext_marker(log)["control_sha"], CONTROL_SHA)


class ProviderShapeTests(unittest.TestCase):
    def test_full_provider_shaped_run_audits_one_mac_upload_and_all_matrix_jobs(self):
        state, env = _fixture()
        created = subject._parse_api_time(state["artifacts"][0]["created_at"])
        expires = subject._parse_api_time(state["artifacts"][0]["expires_at"])
        self.assertEqual(expires - created, timedelta(days=1) - timedelta(seconds=2))
        marker, api = _audit(state, env)
        self.assertIn("status=passed", marker)
        self.assertIn("producers=3 ciphertexts=3", marker)
        self.assertIn("/actions/artifacts/97531/zip", api.requests[0].full_url)
        self.assertEqual(api.requests[0].get_header("Authorization"), "Bearer " + api._token)
        self.assertIsNone(api.requests[1].get_header("Authorization"))

    def test_artifact_expiry_accepts_live_short_lifetimes_and_rejects_out_of_bounds(self):
        now = datetime(2026, 10, 28, 4, 0, 0, tzinfo=timezone.utc)
        identity = {"run_id": RUN_ID, "repository_id": REPOSITORY_ID, "sha": CONTROL_SHA}
        for lifetime in (2, 60, 3600, 24 * 60 * 60 - 2, 24 * 60 * 60):
            with self.subTest(lifetime=lifetime):
                state, unused_env = _fixture(
                    retention_seconds=lifetime, created_offset_seconds=-1, now=now,
                )
                self.assertEqual(
                    subject._validate_artifact_record(
                        state["artifacts"][0], identity, None, now=now,
                    ),
                    state["artifacts"][0]["size_in_bytes"],
                )
        for lifetime, created_offset in ((0, -1), (-1, -1), (24 * 60 * 60 + 1, -1), (60, 1), (60, -61)):
            with self.subTest(lifetime=lifetime, created_offset=created_offset):
                state, unused_env = _fixture(
                    retention_seconds=lifetime, created_offset_seconds=created_offset, now=now,
                )
                with self.assertRaises(subject.SmokeAuditRefusal):
                    subject._validate_artifact_record(
                        state["artifacts"][0], identity, None, now=now,
                    )

    def test_archive_redirect_rejects_untrusted_blob_host(self):
        class RedirectAPI:
            _token = "ghs_" + "x" * 32

            def _open(self, _request, _limit, allow_redirect=False):
                headers = Message()
                headers["Location"] = "https://attacker.invalid/archive.zip?sig=synthetic"
                return None, headers

        with self.assertRaises(subject.AuditRefusal):
            subject._download_archive(RedirectAPI(), ARTIFACT_ID)

    def test_run_identity_source_attempt_and_branch_mismatches_refuse(self):
        mutations = (
            lambda state, env: state["run"].update(head_sha="b" * 40),
            lambda state, env: state["run"].update(path=".github/workflows/other.yml"),
            lambda state, env: state["run"].update(head_branch="other"),
            lambda state, env: state["run"].update(id=24681),
            lambda state, env: state["run"].update(run_attempt=2),
            lambda state, env: env.update(CI_SHA="c" * 40),
            lambda state, env: env.update(CI_REF="refs/heads/other"),
        )
        for mutate in mutations:
            state, env = _fixture()
            mutate(state, env)
            with self.subTest(change=mutate), self.assertRaises(subject.SmokeAuditRefusal):
                _audit(state, env)

    def test_job_set_run_binding_and_completion_are_exact(self):
        mutations = (
            lambda state: state["jobs"].pop(0),
            lambda state: state["jobs"].append(copy.deepcopy(state["jobs"][0])),
            lambda state: state["jobs"][0].update(name="unexpected-job"),
            lambda state: state["jobs"][0].update(run_id=24681),
            lambda state: state["jobs"][0].update(conclusion="failure"),
            lambda state: state["jobs"][1].update(status="in_progress", conclusion=None),
            lambda state: state["jobs"][-1].update(run_id=24681),
            lambda state: state["jobs"][-1].update(run_attempt=2),
            lambda state: state["jobs"][-1].update(head_sha="b" * 40),
            lambda state: state["jobs"][-1].update(id=JOB_IDS["ubuntu-24.04"]),
        )
        for mutate in mutations:
            state, env = _fixture()
            mutate(state)
            with self.subTest(change=mutate), self.assertRaises(subject.SmokeAuditRefusal):
                _audit(state, env)

    def test_failed_terminal_producer_still_scans_all_known_surfaces_before_refusing(self):
        state, env = _fixture()
        state["jobs"][0]["conclusion"] = "failure"
        state["checks"][CHECK_IDS["ubuntu-24.04"]]["conclusion"] = "failure"
        api = FakeAPI(state)
        with self.assertRaises(subject.SmokeAuditRefusal):
            _audit(state, env, api=api)
        self.assertEqual(set(api.log_calls), set(JOB_IDS.values()))
        self.assertEqual(
            sum("/annotations?per_page=100&page=1" in path for path in api.calls),
            2 * len(subject.RUNNERS),
        )
        self.assertTrue(any(path.endswith("/actions/runs/24680/artifacts?per_page=100&page=1")
                            for path in api.calls))
        self.assertEqual(len(api.requests), 2)

    def test_artifact_digest_count_expiry_and_archive_content_are_bound(self):
        mutations = (
            lambda state: state["artifacts"][0].update(digest="sha256:" + "d" * 64),
            lambda state: state["artifacts"].append(copy.deepcopy(state["artifacts"][0])),
            lambda state: state["artifacts"][0].update(expires_at="2030-01-01T00:00:00Z"),
            lambda state: state["artifacts"][0]["workflow_run"].update(id=24681),
            lambda state: state["artifacts"][0].update(created_at="not-a-time"),
            lambda state: state.update(archive=b"not a zip archive"),
        )
        for mutate in mutations:
            state, env = _fixture()
            mutate(state)
            with self.subTest(change=mutate), self.assertRaises(subject.SmokeAuditRefusal):
                _audit(state, env)

    def test_canary_and_annotations_outside_the_optional_notice_shape_refuse(self):
        mutations = (
            lambda state: state["logs"].__setitem__(JOB_IDS["ubuntu-24.04"],
                state["logs"][JOB_IDS["ubuntu-24.04"]] + subject.CANARY),
            lambda state: state["annotations"][CHECK_IDS["macos-15"]][0].update(path=".github/workflows/other.yml"),
            lambda state: state["annotations"][CHECK_IDS["macos-15"]][0].update(message="another notice"),
            lambda state: state["annotations"][CHECK_IDS["macos-15"]][0].update(
                blob_href=CAPACITY_NOTICE["blob_href"].replace(subject.REPOSITORY, "other/repo")
            ),
            lambda state: state["annotations"][CHECK_IDS["macos-15"]][0].update(start_column=1),
            lambda state: state["annotations"][CHECK_IDS["macos-15"]].append(copy.deepcopy(CAPACITY_NOTICE)),
            lambda state: state["checks"][CHECK_IDS["windows-2025"]]["output"].update(summary=subject.CANARY.decode()),
        )
        for mutate in mutations:
            state, env = _fixture()
            mutate(state)
            with self.subTest(change=mutate), self.assertRaises(subject.SmokeAuditRefusal):
                _audit(state, env)

    def test_macos_capacity_notice_is_optional_when_api_reports_none(self):
        state, env = _fixture()
        state["annotations"][CHECK_IDS["macos-15"]].clear()
        state["checks"][CHECK_IDS["macos-15"]]["output"]["annotations_count"] = 0
        marker, _ = _audit(state, env)
        self.assertIn("status=passed", marker)

    def test_repeated_exact_macos_capacity_notice_is_bounded(self):
        for count in (3, subject.MAX_MACOS_CAPACITY_NOTICES):
            state, env = _fixture()
            state["annotations"][CHECK_IDS["macos-15"]] = [
                copy.deepcopy(CAPACITY_NOTICE) for _ in range(count)
            ]
            state["checks"][CHECK_IDS["macos-15"]]["output"]["annotations_count"] = count
            with self.subTest(count=count):
                marker, _ = _audit(state, env)
                self.assertIn("status=passed", marker)

    def test_excess_or_mixed_repeated_capacity_notices_refuse(self):
        state, env = _fixture()
        count = subject.MAX_MACOS_CAPACITY_NOTICES + 1
        state["annotations"][CHECK_IDS["macos-15"]] = [
            copy.deepcopy(CAPACITY_NOTICE) for _ in range(count)
        ]
        state["checks"][CHECK_IDS["macos-15"]]["output"]["annotations_count"] = count
        with self.assertRaises(subject.SmokeAuditRefusal):
            _audit(state, env)

        state, env = _fixture()
        state["annotations"][CHECK_IDS["macos-15"]] = [
            copy.deepcopy(CAPACITY_NOTICE) for _ in range(3)
        ]
        state["annotations"][CHECK_IDS["macos-15"]][1]["message"] = "unexpected notice"
        state["checks"][CHECK_IDS["macos-15"]]["output"]["annotations_count"] = 3
        with self.assertRaises(subject.SmokeAuditRefusal):
            _audit(state, env)

        state, env = _fixture()
        state["annotations"][CHECK_IDS["ubuntu-24.04"]] = [copy.deepcopy(CAPACITY_NOTICE)]
        state["checks"][CHECK_IDS["ubuntu-24.04"]]["output"]["annotations_count"] = 1
        with self.assertRaises(subject.SmokeAuditRefusal):
            _audit(state, env)

    def test_encrypted_archive_must_not_contain_the_fixture_canary(self):
        state, env = _fixture()
        tainted_member = subject.CANARY + b"-" + b"x" * (128 - len(subject.CANARY) - 1)
        state["archive"] = _archive(tainted_member)
        archive_digest = hashlib.sha256(state["archive"]).hexdigest()
        ciphertext_digest = hashlib.sha256(tainted_member).hexdigest()
        state["artifacts"][0]["size_in_bytes"] = len(state["archive"])
        state["artifacts"][0]["digest"] = "sha256:" + archive_digest
        state["logs"][JOB_IDS["macos-15"]] = (
            _cipher_marker("macos-15", ciphertext_digest) + b"\n"
            + _upload_marker(ciphertext_digest, archive_digest) + b"\n"
        )
        with self.assertRaises(subject.SmokeAuditRefusal):
            _audit(state, env)


EXPECTED_VOCABULARY = frozenset((
    "run", "jobs", "upload_marker", "artifact",
    "check_run:ubuntu-24.04", "check_run:macos-15", "check_run:windows-2025",
    "annotations:ubuntu-24.04", "annotations:macos-15", "annotations:windows-2025",
    "log_fetch:ubuntu-24.04", "log_fetch:macos-15", "log_fetch:windows-2025",
    "log_markers:ubuntu-24.04", "log_markers:macos-15", "log_markers:windows-2025",
))


def _fail_check(runner):
    return lambda state: state["checks"][CHECK_IDS[runner]].update(conclusion="failure")


def _fail_annotations(runner):
    def mutate(state):
        check_id = CHECK_IDS[runner]
        if runner == "macos-15":
            state["annotations"][check_id][0]["message"] = "unexpected notice"
        else:
            state["annotations"][check_id] = [copy.deepcopy(CAPACITY_NOTICE)]
            state["checks"][check_id]["output"]["annotations_count"] = 1
    return mutate


def _fail_log_fetch(runner):
    return lambda state: state["logs"].pop(JOB_IDS[runner])


def _fail_log_markers(runner):
    return lambda state: state["logs"].__setitem__(
        JOB_IDS[runner], state["logs"][JOB_IDS[runner]] + subject.CANARY
    )


def _detail_cases():
    cases = [
        ("run", lambda state: state["run"].update(head_sha="b" * 40)),
        ("jobs", lambda state: state["jobs"][0].update(name="unexpected-job")),
        ("upload_marker", lambda state: state["logs"].__setitem__(
            JOB_IDS["ubuntu-24.04"],
            state["logs"][JOB_IDS["ubuntu-24.04"]] + _upload_marker("e" * 64, "f" * 64) + b"\n",
        )),
        ("artifact", lambda state: state["artifacts"][0].update(digest="sha256:" + "d" * 64)),
    ]
    for runner in subject.RUNNERS:
        cases.append(("check_run:" + runner, _fail_check(runner)))
        cases.append(("annotations:" + runner, _fail_annotations(runner)))
        cases.append(("log_fetch:" + runner, _fail_log_fetch(runner)))
        cases.append(("log_markers:" + runner, _fail_log_markers(runner)))
    return cases


def _stderr_for(error):
    stream = io.StringIO()
    with mock.patch.object(subject, "audit_feedback_smoke", side_effect=error), \
            redirect_stderr(stream):
        status = subject.main()
    return status, stream.getvalue()


class ReadinessAndDetailTests(unittest.TestCase):
    def test_vocabulary_is_closed_and_exact(self):
        self.assertEqual(subject.DETAIL_STAGES, EXPECTED_VOCABULARY)
        self.assertEqual({token for token, _ in _detail_cases()}, EXPECTED_VOCABULARY)

    def test_readiness_succeeding_on_the_third_attempt_then_validates_once(self):
        state, env = _fixture()
        api = LogGateAPI(state, failures=2 * len(subject.RUNNERS))
        clock = Clock()
        marker, _ = _audit(state, env, clock=clock, api=api)
        self.assertIn("status=passed", marker)
        self.assertEqual(clock.sleeps, [10, 10])
        jobs_path = "/actions/runs/24680/jobs?filter=all&per_page=100&page=1"
        self.assertEqual(sum(path.endswith(jobs_path) for path in api.calls), 4)
        self.assertEqual(sum(path.endswith("/actions/runs/24680") for path in api.calls), 4)

    def test_readiness_waits_for_completed_check_runs_and_matching_annotation_counts(self):
        state, env = _fixture()
        mac = CHECK_IDS["macos-15"]
        ubuntu = CHECK_IDS["ubuntu-24.04"]
        state["checks"][mac]["status"] = "in_progress"
        state["checks"][ubuntu]["output"]["annotations_count"] = 4

        def heal(count):
            if count == 2:
                state["checks"][mac]["status"] = "completed"
                state["checks"][ubuntu]["output"]["annotations_count"] = 0

        clock = Clock(hook=heal)
        marker, _ = _audit(state, env, clock=clock)
        self.assertIn("status=passed", marker)
        self.assertEqual(clock.sleeps, [10, 10])

    def test_readiness_is_bounded_and_the_validation_then_refuses_with_detail(self):
        state, env = _fixture()
        api = LogGateAPI(state, blocked=(JOB_IDS["macos-15"],))
        clock = Clock()
        with self.assertRaises(subject.SmokeAuditRefusal) as caught:
            _audit(state, env, clock=clock, api=api)
        self.assertEqual(caught.exception.reason, "producer_failed")
        self.assertEqual(caught.exception.detail, "log_fetch:macos-15")
        self.assertEqual(clock.sleeps, [10] * 5)
        self.assertLessEqual(clock.now, 60)
        jobs_path = "/actions/runs/24680/jobs?filter=all&per_page=100&page=1"
        self.assertEqual(sum(path.endswith(jobs_path) for path in api.calls), 7)
        self.assertEqual(sum(path.endswith("/actions/runs/24680") for path in api.calls), 7)

    def test_readiness_stops_when_the_clock_bound_is_reached(self):
        state, env = _fixture()
        api = LogGateAPI(state, blocked=(JOB_IDS["windows-2025"],))
        clock = Clock()
        clock.now = 0.0
        real_sleep = clock.sleep

        def slow_sleep(seconds):
            real_sleep(seconds * 3)

        with self.assertRaises(subject.SmokeAuditRefusal):
            subject.audit_feedback_smoke(
                env, lambda _token: api, slow_sleep, clock.monotonic
            )
        self.assertLessEqual(len(clock.sleeps), 5)
        self.assertLessEqual(clock.now, 90)

    def test_readiness_waits_for_the_ciphertext_marker_in_a_fetchable_log(self):
        state, env = _fixture()
        api = PartialLogAPI(state, JOB_IDS["ubuntu-24.04"], b"partial log without marker\n", 2)
        clock = Clock()
        marker, _ = _audit(state, env, clock=clock, api=api)
        self.assertIn("status=passed", marker)
        self.assertEqual(clock.sleeps, [10, 10])

    def test_readiness_waits_for_the_macos_upload_marker(self):
        state, env = _fixture()
        digest = hashlib.sha256(_ciphertext("macos-15")).hexdigest()
        api = PartialLogAPI(
            state, JOB_IDS["macos-15"], _cipher_marker("macos-15", digest) + b"\n", 2
        )
        clock = Clock()
        marker, _ = _audit(state, env, clock=clock, api=api)
        self.assertIn("status=passed", marker)
        self.assertEqual(clock.sleeps, [10, 10])

    def test_marker_that_never_appears_exhausts_the_bound_and_refuses_with_detail(self):
        state, env = _fixture()
        api = PartialLogAPI(state, JOB_IDS["ubuntu-24.04"], b"partial log without marker\n", -1)
        clock = Clock()
        with self.assertRaises(subject.SmokeAuditRefusal) as caught:
            _audit(state, env, clock=clock, api=api)
        self.assertEqual(clock.sleeps, [10] * 5)
        self.assertEqual(caught.exception.reason, "producer_failed")
        self.assertEqual(caught.exception.detail, "log_markers:ubuntu-24.04")

    def test_failed_producer_without_a_marker_is_ready_at_once(self):
        state, env = _fixture()
        state["jobs"][0]["conclusion"] = "failure"
        state["checks"][CHECK_IDS["ubuntu-24.04"]]["conclusion"] = "failure"
        api = PartialLogAPI(state, JOB_IDS["ubuntu-24.04"], b"partial log without marker\n", -1)
        clock = Clock()
        with self.assertRaises(subject.SmokeAuditRefusal) as caught:
            _audit(state, env, clock=clock, api=api)
        self.assertEqual(clock.sleeps, [])
        self.assertEqual(caught.exception.reason, "producer_failed")

    def test_readiness_waits_for_a_consistent_run_record(self):
        state, env = _fixture()
        state["run"]["status"] = "queued"

        def settle(count):
            if count == 2:
                state["run"]["status"] = "in_progress"

        clock = Clock(hook=settle)
        marker, _ = _audit(state, env, clock=clock)
        self.assertIn("status=passed", marker)
        self.assertEqual(clock.sleeps, [10, 10])

    def test_readiness_retries_a_server_error_on_the_run_read(self):
        state, env = _fixture()
        api = FaultAPI(state, "/actions/runs/24680", "raise", 1)
        clock = Clock()
        marker, _ = _audit(state, env, clock=clock, api=api)
        self.assertIn("status=passed", marker)
        self.assertEqual(clock.sleeps, [10])

    def test_readiness_waits_for_the_jobs_total_to_reach_four(self):
        state, env = _fixture()
        jobs_suffix = "/actions/runs/24680/jobs?filter=all&per_page=100&page=1"
        api = FaultAPI(state, jobs_suffix, "short", 2)
        clock = Clock()
        marker, _ = _audit(state, env, clock=clock, api=api)
        self.assertIn("status=passed", marker)
        self.assertEqual(clock.sleeps, [10, 10])

    def test_jobs_that_never_become_consistent_refuse_with_the_jobs_stage(self):
        state, env = _fixture()
        jobs_suffix = "/actions/runs/24680/jobs?filter=all&per_page=100&page=1"
        api = FaultAPI(state, jobs_suffix, "short", -1)
        clock = Clock()
        with self.assertRaises(subject.SmokeAuditRefusal) as caught:
            _audit(state, env, clock=clock, api=api)
        self.assertEqual(clock.sleeps, [10] * 5)
        self.assertEqual(caught.exception.reason, "producer_failed")
        self.assertEqual(caught.exception.detail, "jobs")

    def test_each_detail_token_is_emitted_for_its_failing_sub_check(self):
        for token, mutate in _detail_cases():
            state, env = _fixture()
            mutate(state)
            with self.subTest(token=token), self.assertRaises(subject.SmokeAuditRefusal) as caught:
                _audit(state, env)
            self.assertEqual(caught.exception.detail, token)
            self.assertEqual(
                caught.exception.reason,
                "artifact_invalid" if token == "artifact" else "producer_failed",
            )

    def test_detail_line_is_one_stderr_line_inside_the_vocabulary(self):
        pattern = re.compile(r"KD-FEEDBACK-AUDIT-DETAIL stage=([a-z_]+(?::[a-z0-9.-]+)?)\Z")
        for token, mutate in _detail_cases():
            state, env = _fixture()
            mutate(state)
            with self.assertRaises(subject.SmokeAuditRefusal) as caught:
                _audit(state, env)
            status, text = _stderr_for(caught.exception)
            lines = text.splitlines()
            with self.subTest(token=token):
                self.assertEqual(status, 1)
                self.assertEqual(len(lines), 2)
                self.assertTrue(lines[0].startswith("KD-FEEDBACK-AUDIT-REFUSAL reason="))
                match = pattern.fullmatch(lines[1])
                self.assertIsNotNone(match)
                self.assertEqual(match.group(1), token)
                self.assertIn(match.group(1), EXPECTED_VOCABULARY)

    def test_free_text_or_unknown_detail_is_never_printed(self):
        for detail in ("free text sig=secret", "log_fetch:other-runner",
                       "annotations", "", None, "run extra"):
            with self.subTest(detail=detail):
                error = subject.SmokeAuditRefusal("producer_failed", detail)
                self.assertIsNone(error.detail)
                status, text = _stderr_for(error)
                self.assertEqual(status, 1)
                self.assertEqual(text, "KD-FEEDBACK-AUDIT-REFUSAL reason=producer_failed\n")

    def test_genuinely_failing_producer_refuses_even_when_readiness_succeeds(self):
        for mutate, token in (
            (_fail_check("windows-2025"), "check_run:windows-2025"),
            (lambda state: state["jobs"][1].update(conclusion="failure"), "jobs"),
        ):
            state, env = _fixture()
            mutate(state)
            clock = Clock()
            with self.subTest(token=token), self.assertRaises(subject.SmokeAuditRefusal) as caught:
                _audit(state, env, clock=clock)
            self.assertEqual(clock.sleeps, [])
            self.assertEqual(caught.exception.reason, "producer_failed")
            self.assertEqual(caught.exception.detail, token)


if __name__ == "__main__":
    unittest.main()
