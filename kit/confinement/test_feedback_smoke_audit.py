import copy
import hashlib
import io
import stat
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from email.message import Message

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


def _audit(state, env):
    api = FakeAPI(state)
    result = subject.audit_feedback_smoke(env, lambda _token: api)
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
            subject.audit_feedback_smoke(env, lambda _token: api)
        self.assertEqual(set(api.log_calls), set(JOB_IDS.values()))
        self.assertEqual(
            sum("/annotations?per_page=100&page=1" in path for path in api.calls),
            len(subject.RUNNERS),
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


if __name__ == "__main__":
    unittest.main()
