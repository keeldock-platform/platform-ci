import base64
import contextlib
import email.message
import io
import json
import tempfile
import urllib.error
import unittest
from pathlib import Path
from unittest import mock

import macos_public_audit as audit


CONTROL_SHA = "0123456789abcdef" * 2 + "01234567"
RUN_ID = "123456789"
RUN_ATTEMPT = "2"


def receipt_value():
    return {
        "schema_version": 2,
        "run_id": int(RUN_ID),
        "run_attempt": int(RUN_ATTEMPT),
        "control_sha": CONTROL_SHA,
        "boundary": "seatbelt-deny-default",
        "macos_product_version": "15.7.9",
        "runner_image_os": "macos-15-arm64",
        "runner_image_version": "20260907.0337.1",
        "developer_mode": "disabled",
        "pf": "enforced",
        "sandbox_selftest": "enforced",
        "positive_build": "passed",
        "channels": dict(audit.EXPECTED_CHANNELS),
        "private_source_executed": False,
    }


def encode_receipt(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class FakeHeaders(dict):
    def get_content_type(self):
        return self.get("Content-Type", "application/json").split(";", 1)[0].strip().lower()


class FakeAPI:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def json(self, path):
        self.calls.append(path)
        if path not in self.pages:
            raise AssertionError("unexpected API path")
        body, headers = self.pages[path]
        return body, FakeHeaders(headers)


class FakeAuditAPI(FakeAPI):
    def __init__(self, pages, log_bytes=b"macos-native=complete\n"):
        super().__init__(pages)
        self.log_bytes = log_bytes
        self.log_calls = []

    def log_text(self, job_id):
        self.log_calls.append(job_id)
        return self.log_bytes


class FakeMultiAuditAPI(FakeAPI):
    def __init__(self, pages, logs):
        super().__init__(pages)
        self.logs = logs
        self.log_calls = []

    def log_text(self, job_id):
        self.log_calls.append(job_id)
        if job_id not in self.logs:
            raise audit.AuditRefusal("log_unavailable")
        return self.logs[job_id]


class FakeCleanupAPI(FakeAPI):
    def __init__(self, pages, cache_items):
        super().__init__(pages)
        self.cache_items = list(cache_items)
        self.deleted_cache_ids = []

    def json(self, path):
        cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        if path == cache_path:
            self.calls.append(path)
            return {"total_count": len(self.cache_items), "actions_caches": list(self.cache_items)}, FakeHeaders({})
        return super().json(path)

    def delete_cache(self, cache_id):
        self.deleted_cache_ids.append(cache_id)
        self.cache_items = [item for item in self.cache_items if item["id"] != cache_id]


class FakeResponse:
    def __init__(self, body, headers):
        self.status = 200
        self.headers = FakeHeaders(headers)
        self._body = body

    def read(self, size):
        result, self._body = self._body[:size], self._body[size:]
        return result

    def close(self):
        return None


class CanaryTests(unittest.TestCase):
    def test_canary_is_bound_to_exact_control_sha(self):
        first = audit.derive_canary(CONTROL_SHA)
        self.assertTrue(first.startswith(b"KD-MACOS-CI-CANARY-v1:"))
        self.assertTrue(first == audit.derive_canary(CONTROL_SHA))
        self.assertTrue(first != audit.derive_canary("f" * 40))

    def test_public_capture_with_no_canary_is_accepted(self):
        audit.inspect_public_bytes(b"native-probe=complete\n", CONTROL_SHA)

    def test_canary_in_public_capture_refuses_without_echoing_it(self):
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_public_bytes(b"prefix" + audit.derive_canary(CONTROL_SHA) + b"suffix", CONTROL_SHA)
        self.assertEqual(caught.exception.reason, "canary_exposed")

    def test_workflow_command_and_canary_refuse_as_a_command(self):
        marker = audit.CANARY_COMMANDS[0] + audit.derive_canary(CONTROL_SHA)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_public_bytes(marker, CONTROL_SHA)
        self.assertEqual(caught.exception.reason, "workflow_command_exposed")
        self.assertEqual(str(caught.exception), "")
        self.assertEqual(caught.exception.args, ())
        sanitized = audit.AuditRefusal("opaque-untrusted-value")
        self.assertEqual(sanitized.args, ())

    def test_any_workflow_command_marker_refuses_without_a_canary(self):
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_public_bytes(b"step output ::warning::unexpected", CONTROL_SHA)
        self.assertEqual(caught.exception.reason, "workflow_command_exposed")

    def test_encoded_canary_is_checked(self):
        needle = base64.b64encode(audit.derive_canary(CONTROL_SHA))
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_public_bytes(b"prefix=" + needle, CONTROL_SHA)
        self.assertEqual(caught.exception.reason, "canary_exposed")

    def test_reviewed_canary_common_encodings_are_scanned_without_changing_legacy_scan(self):
        marker = audit.derive_reviewed_canary(CONTROL_SHA)
        self.assertEqual(marker, b"KD-RB-CANARY-" + CONTROL_SHA[:16].encode("ascii"))
        audit.inspect_public_bytes(marker, CONTROL_SHA)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_reviewed_public_bytes(marker, CONTROL_SHA)
        self.assertEqual(caught.exception.reason, "canary_exposed")
        for needle in audit._reviewed_canary_variants(CONTROL_SHA):
            with self.subTest(encoding=needle[:12]):
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.inspect_reviewed_public_bytes(b"prefix=" + needle, CONTROL_SHA)
                self.assertEqual(caught.exception.reason, "canary_exposed")

    def test_reviewed_summary_direct_write_canary_and_encodings_are_reviewed_only(self):
        marker = b"KD-RB-SUMMARY-DIRECT-WRITE-CANARY-v1"
        self.assertEqual(marker, audit.REVIEWED_SUMMARY_DIRECT_CANARY)
        variants = audit._reviewed_summary_canary_variants()
        self.assertIn(marker, variants)
        for needle in variants:
            with self.subTest(encoding=needle[:12]):
                audit.inspect_public_bytes(b"prefix=" + needle, CONTROL_SHA)
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.inspect_reviewed_public_bytes(b"prefix=" + needle, CONTROL_SHA)
                self.assertEqual(caught.exception.reason, "canary_exposed")


class InventoryTests(unittest.TestCase):
    def test_cache_digest_is_order_independent_and_metadata_sensitive(self):
        one = {
            "id": 11,
            "ref": "refs/heads/main",
            "key": "cache-a",
            "version": "v1",
            "last_accessed_at": None,
            "created_at": "2026-10-25T00:00:00Z",
            "size_in_bytes": 19,
        }
        two = dict(one, id=12, key="cache-b")
        expected = audit.cache_inventory_digest([one, two])
        self.assertEqual(expected, audit.cache_inventory_digest([two, one]))
        changed = dict(two, size_in_bytes=20)
        self.assertNotEqual(expected, audit.cache_inventory_digest([one, changed]))

    def test_cache_digest_rejects_duplicate_ids_and_unexpected_fields(self):
        item = {
            "id": 11,
            "ref": "refs/heads/main",
            "key": "cache-a",
            "version": "v1",
            "last_accessed_at": None,
            "created_at": "2026-10-25T00:00:00Z",
            "size_in_bytes": 19,
        }
        with self.assertRaises(audit.AuditRefusal):
            audit.cache_inventory_digest([item, dict(item)])
        with self.assertRaises(audit.AuditRefusal):
            audit.cache_inventory_digest([dict(item, unreviewed="value")])

    def test_counted_collection_checks_each_next_link(self):
        path = "/repos/keeldock-platform/platform-ci/actions/caches"
        first = {"total_count": 2, "actions_caches": [{"id": 1}, {"id": 2}]}
        pages = {path + "?per_page=100&page=1": (first, {})}
        api = FakeAPI(pages)
        result = audit._read_counted_collection(api, path, "actions_caches", 10, lambda item: None)
        self.assertEqual(result, first["actions_caches"])

    def test_counted_collection_refuses_missing_next_page(self):
        path = "/repos/keeldock-platform/platform-ci/actions/caches"
        first = {"total_count": 101, "actions_caches": [{"id": n} for n in range(100)]}
        api = FakeAPI({path + "?per_page=100&page=1": (first, {})})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit._read_counted_collection(api, path, "actions_caches", 200, lambda item: None)
        self.assertEqual(caught.exception.reason, "pagination_incomplete")

    def test_annotations_follow_complete_exact_pages(self):
        path = "/repos/keeldock-platform/platform-ci/check-runs/9/annotations"
        next_url = "https://api.github.com" + path + "?per_page=100&page=2"
        last_url = "https://api.github.com" + path + "?per_page=100&page=2"
        first_headers = {
            "Link": f'<{next_url}>; rel="next", <{last_url}>; rel="last"'
        }
        page_one = [{"message": "safe"}] * 100
        page_two = [{"message": "also-safe"}]
        final_headers = {
            "Link": f'<https://api.github.com{path}?per_page=100&page=1>; rel="prev", '
            f'<{last_url}>; rel="last"'
        }
        api = FakeAPI({
            path + "?per_page=100&page=1": (page_one, first_headers),
            path + "?per_page=100&page=2": (page_two, final_headers),
        })
        self.assertEqual(len(audit._read_annotations(api, path)), 101)
        self.assertEqual(len(api.calls), 2)

    def test_annotations_refuse_unrelated_query_link(self):
        path = "/repos/keeldock-platform/platform-ci/check-runs/9/annotations"
        wrong = "https://api.github.com" + path + "?per_page=100&page=2&other=1"
        headers = {"Link": f'<{wrong}>; rel="next", <{wrong}>; rel="last"'}
        api = FakeAPI({path + "?per_page=100&page=1": ([{"message": "safe"}] * 100, headers)})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit._read_annotations(api, path)
        self.assertEqual(caught.exception.reason, "pagination_incomplete")

    def test_annotation_count_must_match_complete_collection(self):
        check_path = "/repos/keeldock-platform/platform-ci/check-runs/9"
        annotation_path = check_path + "/annotations?per_page=100&page=1"
        check = {
            "id": 9,
            "head_sha": CONTROL_SHA,
            "status": "completed",
            "conclusion": "success",
            "output": {"annotations_count": 1},
        }
        api = FakeAPI({check_path: (check, {}), annotation_path: ([], {})})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit._scan_annotations(api, {"conclusion": "success"}, 9, CONTROL_SHA)
        self.assertEqual(caught.exception.reason, "pagination_incomplete")

    def test_annotation_count_schema_is_required(self):
        check_path = "/repos/keeldock-platform/platform-ci/check-runs/9"
        check = {
            "id": 9,
            "head_sha": CONTROL_SHA,
            "status": "completed",
            "conclusion": "success",
        }
        api = FakeAPI({check_path: (check, {})})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit._scan_annotations(api, {"conclusion": "success"}, 9, CONTROL_SHA)
        self.assertEqual(caught.exception.reason, "api_schema")


class ReceiptTests(unittest.TestCase):
    def test_valid_native_receipt_is_bound_to_attempt_and_control(self):
        self.assertEqual(
            audit.validate_receipt(encode_receipt(receipt_value()), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)["schema_version"],
            2,
        )

    def test_receipt_rejects_missing_or_extra_fields(self):
        missing = receipt_value()
        missing.pop("positive_build")
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_receipt(encode_receipt(missing), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
        extra = receipt_value()
        extra["result"] = "success"
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_receipt(encode_receipt(extra), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)

    def test_receipt_rejects_success_without_per_channel_proof(self):
        value = receipt_value()
        value["channels"]["https"] = "passed"
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_receipt(encode_receipt(value), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)

    def test_receipt_rejects_wrong_attempt_and_boolean_integer(self):
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_receipt(encode_receipt(receipt_value()), CONTROL_SHA, RUN_ID, "3")
        value = receipt_value()
        value["run_attempt"] = True
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_receipt(encode_receipt(value), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)

    def test_receipt_rejects_noncanonical_base64url(self):
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_receipt(encode_receipt(receipt_value()) + "=", CONTROL_SHA, RUN_ID, RUN_ATTEMPT)


class ApiIdentityTests(unittest.TestCase):
    def test_api_url_must_be_exact_https_check_run_endpoint(self):
        path = "/repos/keeldock-platform/platform-ci/check-runs/9"
        audit._validate_api_url("https://api.github.com" + path, path)
        for url in (
            "http://api.github.com" + path,
            "https://api.github.com.attacker.invalid" + path,
            "https://api.github.com" + path + "?page=1",
        ):
            with self.subTest(url=url), self.assertRaises(audit.AuditRefusal):
                audit._validate_api_url(url, path)

    def test_log_redirect_is_limited_to_expected_https_blob_host(self):
        audit._validate_log_location(
            "https://productionresultssa0.blob.core.windows.net/actions-results/run/log.txt?sig=opaque"
        )
        for url in (
            "http://productionresultssa0.blob.core.windows.net/actions-results/log?sig=opaque",
            "https://productionresultssa0.blob.core.windows.net.attacker.invalid/log?sig=opaque",
            "https://user@productionresultssa0.blob.core.windows.net/log?sig=opaque",
            "https://productionresultssa0.blob.core.windows.net:443/log?sig=opaque",
            "https://productionresultssa0.blob.core.windows.net/log?sig=opaque" + chr(35) + "fragment",
            "https://attacker.invalid/log?sig=opaque",
        ):
            with self.subTest(url=url), self.assertRaises(audit.AuditRefusal):
                audit._validate_log_location(url)

    def test_job_log_download_does_not_forward_api_token_to_blob(self):
        class RedirectAndBlob:
            def __init__(self):
                self.requests = []

            def open(self, request, timeout):
                self.requests.append(request)
                if len(self.requests) == 1:
                    headers = email.message.Message()
                    headers["Location"] = (
                        "https://productionresultssa0.blob.core.windows.net/"
                        "actions-results/run/log.txt?sig=opaque"
                    )
                    raise urllib.error.HTTPError(
                        request.full_url, 302, "Found", headers, io.BytesIO(b"")
                    )
                body = b"macos-native=complete\n"
                return FakeResponse(body, {
                    "Content-Type": "text/plain; charset=utf-8",
                    "Content-Length": str(len(body)),
                    "Content-Encoding": "identity",
                })

        api = audit.GitHubAPI.__new__(audit.GitHubAPI)
        api._token = "t" * 32
        fake = RedirectAndBlob()
        api._opener = fake
        self.assertEqual(api.log_text(99), b"macos-native=complete\n")
        self.assertEqual(len(fake.requests), 2)
        self.assertTrue(fake.requests[0].get_header("Authorization").startswith("Bearer "))
        self.assertIsNone(fake.requests[1].get_header("Authorization"))

    def test_annotations_are_bound_to_native_check_sha_and_conclusion(self):
        job = {"conclusion": "success"}
        check_path = "/repos/keeldock-platform/platform-ci/check-runs/9"
        annotation_path = check_path + "/annotations"
        check = {
            "id": 9,
            "head_sha": CONTROL_SHA,
            "status": "completed",
            "conclusion": "success",
            "output": {"annotations_count": 0},
        }
        api = FakeAPI({check_path: (check, {}), annotation_path + "?per_page=100&page=1": ([], {})})
        audit._scan_annotations(api, job, 9, CONTROL_SHA)

        mismatched = dict(check, head_sha="f" * 40)
        api = FakeAPI({check_path: (mismatched, {})})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit._scan_annotations(api, job, 9, CONTROL_SHA)
        self.assertEqual(caught.exception.reason, "run_identity_mismatch")


def audit_fixture():
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
    jobs_path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
    )
    native_check_url = "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/303"
    other_check_url = "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/304"
    native_job = {
        "id": 202,
        "run_id": int(RUN_ID),
        "run_attempt": int(RUN_ATTEMPT),
        "head_sha": CONTROL_SHA,
        "name": audit.NATIVE_JOB_NAME,
        "status": "completed",
        "conclusion": "success",
        "check_run_url": native_check_url,
    }
    other_job = {
        "id": 204,
        "run_id": int(RUN_ID),
        "run_attempt": int(RUN_ATTEMPT),
        "head_sha": CONTROL_SHA,
        "name": "macos-public-surface-audit",
        "status": "in_progress",
        "conclusion": "success",
        "check_run_url": other_check_url,
    }
    native_detail = dict(native_job, steps=[{
        "number": 1,
        "name": "Run source-free proof",
        "status": "completed",
        "conclusion": "success",
    }])
    check_path = "/repos/keeldock-platform/platform-ci/check-runs/303"
    annotation_path = check_path + "/annotations?per_page=100&page=1"
    artifact_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID + "/artifacts?per_page=100&page=1"
    cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
    pages = {
        run_path: ({
            "id": int(RUN_ID),
            "run_attempt": int(RUN_ATTEMPT),
            "head_sha": CONTROL_SHA,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": audit.WORKFLOW_PATH,
            "repository": {"full_name": audit.REPOSITORY},
        }, {}),
        jobs_path: ({"total_count": 2, "jobs": [native_job, other_job]}, {}),
        "/repos/keeldock-platform/platform-ci/actions/jobs/202": (native_detail, {}),
        check_path: ({
            "id": 303,
            "head_sha": CONTROL_SHA,
            "status": "completed",
            "conclusion": "success",
            "output": {"annotations_count": 0},
        }, {}),
        annotation_path: ([], {}),
        artifact_path: ({"total_count": 0, "artifacts": []}, {}),
        cache_path: ({"total_count": 0, "actions_caches": []}, {}),
    }
    env = {
        "GITHUB_REPOSITORY": audit.REPOSITORY,
        "GITHUB_RUN_ID": RUN_ID,
        "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
        "CI_SHA": CONTROL_SHA,
        "GITHUB_TOKEN": "t" * 32,
        "MACOS_CACHE_SNAPSHOT": audit.cache_inventory_digest([]),
        "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(receipt_value()),
    }
    return pages, env, native_job, native_detail


def reviewed_audit_fixture():
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
    jobs_path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
    )
    snapshot_check_url = "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/303"
    smoke_check_url = "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/305"
    audit_check_url = "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/304"
    snapshot_job = {
        "id": 202,
        "run_id": int(RUN_ID),
        "run_attempt": int(RUN_ATTEMPT),
        "head_sha": CONTROL_SHA,
        "name": audit.REVIEWED_SNAPSHOT_JOB_NAME,
        "status": "completed",
        "conclusion": "success",
        "check_run_url": snapshot_check_url,
    }
    smoke_job = {
        "id": 203,
        "run_id": int(RUN_ID),
        "run_attempt": int(RUN_ATTEMPT),
        "head_sha": CONTROL_SHA,
        "name": audit.REVIEWED_SMOKE_JOB_NAME,
        "status": "completed",
        "conclusion": "success",
        "check_run_url": smoke_check_url,
    }
    audit_job = {
        "id": 204,
        "run_id": int(RUN_ID),
        "run_attempt": int(RUN_ATTEMPT),
        "head_sha": CONTROL_SHA,
        "name": audit.REVIEWED_AUDIT_JOB_NAME,
        "status": "in_progress",
        "conclusion": None,
        "check_run_url": audit_check_url,
    }
    snapshot_detail = dict(snapshot_job, steps=[{
        "number": 1,
        "name": "Snapshot cache inventory",
        "status": "completed",
        "conclusion": "success",
    }])
    smoke_detail = dict(smoke_job, steps=[
        {
            "number": 1,
            "name": "Set up job",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "number": 2,
            "name": "Fetch reviewed main control",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "number": 3,
            "name": "Validate source-free control tree",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "number": 4,
            "name": "Prove source-free network observer",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "number": 5,
            "name": "Run source-free reviewed build smoke",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "number": 6,
            "name": "Write trusted summary visibility control",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "number": 7,
            "name": "Complete job",
            "status": "completed",
            "conclusion": "success",
        },
    ])
    snapshot_check = "/repos/keeldock-platform/platform-ci/check-runs/303"
    smoke_check = "/repos/keeldock-platform/platform-ci/check-runs/305"
    snapshot_annotations = snapshot_check + "/annotations?per_page=100&page=1"
    smoke_annotations = smoke_check + "/annotations?per_page=100&page=1"
    artifact_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID + "/artifacts?per_page=100&page=1"
    cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
    pages = {
        run_path: ({
            "id": int(RUN_ID),
            "run_attempt": int(RUN_ATTEMPT),
            "head_sha": CONTROL_SHA,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": audit.REVIEWED_WORKFLOW_PATH,
            "repository": {"full_name": audit.REPOSITORY},
        }, {}),
        jobs_path: ({"total_count": 3, "jobs": [snapshot_job, smoke_job, audit_job]}, {}),
        "/repos/keeldock-platform/platform-ci/actions/jobs/202": (snapshot_detail, {}),
        "/repos/keeldock-platform/platform-ci/actions/jobs/203": (smoke_detail, {}),
        snapshot_check: ({
            "id": 303,
            "head_sha": CONTROL_SHA,
            "status": "completed",
            "conclusion": "success",
            "output": {"title": "snapshot", "summary": "snapshot complete", "annotations_count": 0},
        }, {}),
        smoke_check: ({
            "id": 305,
            "head_sha": CONTROL_SHA,
            "status": "completed",
            "conclusion": "success",
            "output": {"title": "smoke", "summary": "smoke complete", "annotations_count": 0},
        }, {}),
        snapshot_annotations: ([], {}),
        smoke_annotations: ([], {}),
        artifact_path: ({"total_count": 0, "artifacts": []}, {}),
        cache_path: ({"total_count": 0, "actions_caches": []}, {}),
    }
    marker = (
        "macos-build=synthetic-smoke-passed schema=1 source=none control-sha=" + CONTROL_SHA
        + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
        + " image-os=macos-15-arm64 image-version=20260907.0337.1 macos-version=15.7.9"
        + " architecture=arm64 xcode=not-used xcode-build=not-used"
        + " compiler-origin=command-line-tools clang=17.0.0 sdk=26.0"
        + " developer-mode=disabled privilege=separate-nonadmin sudo=denied"
        + " compile=passed link=passed load-test=passed capture=passed"
        + " summary-standin=write-denied real-summary=write-denied"
        + " cleanup=complete seatbelt=not-run pf=not-run\n"
    ).encode("ascii")
    summary_control = (
        "2026-10-26T12:34:56.1234567Z "
        + "macos-summary-control=trusted-write schema=1 control-sha=" + CONTROL_SHA
        + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT + "\n"
    ).encode("ascii")
    network_selftest = (
        "2026-10-26T12:34:56.1234567Z macos-network-observer=selftest-passed schema=1"
        + " mode=host-level control-sha=" + CONTROL_SHA + " run-id=" + RUN_ID
        + " run-attempt=" + RUN_ATTEMPT + " source-sha=none interface-count=1"
        + " dns-query-count=1 tcp-syn-count=1 dns-name-hashes=" + "1" * 64
        + " tcp-destination-hashes=" + "2" * 64
        + " hashes-truncated=false capture=private capture-limited=false cleanup=complete"
        + " worker-attribution=not-claimed completeness=not-claimed"
        + " network-blocking=not-claimed\n"
    ).encode("ascii")
    env = {
        "GITHUB_REPOSITORY": audit.REPOSITORY,
        "GITHUB_RUN_ID": RUN_ID,
        "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
        "CI_SHA": CONTROL_SHA,
        "GITHUB_TOKEN": "t" * 32,
        "MACOS_CACHE_SNAPSHOT": audit.cache_inventory_digest([]),
    }
    logs = {
        202: b"macos-public-surface-audit=snapshot-ready\n",
        203: marker + network_selftest + summary_control,
    }
    return pages, env, logs


def cache_proof_keys():
    suffix = RUN_ID + "-" + RUN_ATTEMPT
    return (
        audit.CACHE_PROOF_SEED_KEY_PREFIX + suffix,
        audit.CACHE_PROOF_NONE_WRITE_KEY_PREFIX + suffix,
    )


def cache_proof_audit_fixture():
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
    jobs_path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
    )
    artifact_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID + "/artifacts?per_page=100&page=1"
    cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
    job_specs = (
        (audit.CACHE_PROOF_SNAPSHOT_JOB_NAME, 402, 502, "completed", "success", (
            "Fetch reviewed main control", "Snapshot cache inventory",
        )),
        (audit.CACHE_PROOF_SEED_JOB_NAME, 403, 503, "completed", "success", (
            "Fetch reviewed main control", "Prepare public cache fixture", "Save public cache fixture",
            "Confirm seed step completed",
        )),
        (audit.CACHE_PROOF_POSITIVE_JOB_NAME, 404, 504, "completed", "success", (
            "Fetch reviewed main control", "Restore the known public cache fixture",
            "Verify exact fixture bytes after a cache hit",
        )),
        (audit.CACHE_PROOF_NONE_JOB_NAME, 405, 505, "completed", "success", (
            "Fetch reviewed main control", "Fetch the exact pinned public cache client",
            "Require fixture is absent before the denied read",
            "Request the known fixture through the pinned cache client",
            "Verify the none-scoped read did not restore bytes", "Prepare a distinct public write probe",
            "Request a save through the pinned cache client", "Confirm save request completed",
        )),
        (audit.CACHE_PROOF_AUDIT_JOB_NAME, 406, 506, "in_progress", None, ()),
        (audit.CACHE_PROOF_CLEANUP_JOB_NAME, 407, 507, "queued", None, ()),
    )
    pages = {
        run_path: ({
            "id": int(RUN_ID),
            "run_attempt": int(RUN_ATTEMPT),
            "head_sha": CONTROL_SHA,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": audit.CACHE_PROOF_WORKFLOW_PATH,
            "repository": {"full_name": audit.REPOSITORY},
        }, {}),
    }
    jobs = []
    logs = {}
    cache_items = [{
        "id": 901,
        "ref": "refs/heads/main",
        "key": cache_proof_keys()[0],
        "version": "fixture-version-v1",
        "last_accessed_at": "2026-10-26T00:01:00Z",
        "created_at": "2026-10-26T00:00:00Z",
        "size_in_bytes": 128,
    }]
    seed_key, write_key = cache_proof_keys()
    logs_by_name = {
        audit.CACHE_PROOF_SNAPSHOT_JOB_NAME: b"macos-cache-proof=snapshot-ready\n",
        audit.CACHE_PROOF_SEED_JOB_NAME: (
            b"Cache saved with key: " + seed_key.encode("ascii")
            + b"\nmacos-cache-seed=step-complete schema=1 run-id=" + RUN_ID.encode("ascii")
            + b" run-attempt=" + RUN_ATTEMPT.encode("ascii") + b"\n"
        ),
        audit.CACHE_PROOF_POSITIVE_JOB_NAME: (
            b"Cache restored from key: " + seed_key.encode("ascii")
            + b"\nmacos-cache-positive=restored schema=1 run-id=" + RUN_ID.encode("ascii")
            + b" run-attempt=" + RUN_ATTEMPT.encode("ascii") + b"\n"
        ),
        audit.CACHE_PROOF_NONE_JOB_NAME: (
            b"macos-cache-client-source=verified schema=1 action-sha="
            + audit.CACHE_PROOF_ACTION_SHA.encode("ascii") + b"\n"
            b"macos-cache-client=read-denied schema=1 action-sha="
            + audit.CACHE_PROOF_ACTION_SHA.encode("ascii") + b" key=" + seed_key.encode("ascii")
            + b" control-sha=" + CONTROL_SHA.encode("ascii") + b" run-id=" + RUN_ID.encode("ascii")
            + b" run-attempt=" + RUN_ATTEMPT.encode("ascii") + b" node=24.0.0\n"
            b"macos-cache-none-read=local-absent schema=1 run-id=" + RUN_ID.encode("ascii")
            + b" run-attempt=" + RUN_ATTEMPT.encode("ascii")
            + b"\nmacos-cache-client=write-denied schema=1 action-sha="
            + audit.CACHE_PROOF_ACTION_SHA.encode("ascii") + b" key=" + write_key.encode("ascii")
            + b" control-sha=" + CONTROL_SHA.encode("ascii") + b" run-id=" + RUN_ID.encode("ascii")
            + b" run-attempt=" + RUN_ATTEMPT.encode("ascii") + b" node=24.0.0\n"
            b"macos-cache-none-save=request-finished schema=1 run-id=" + RUN_ID.encode("ascii")
            + b" run-attempt=" + RUN_ATTEMPT.encode("ascii") + b"\n"
        ),
    }
    for name, job_id, check_id, status, conclusion, step_names in job_specs:
        check_url = "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
        record = {
            "id": job_id,
            "run_id": int(RUN_ID),
            "run_attempt": int(RUN_ATTEMPT),
            "head_sha": CONTROL_SHA,
            "name": name,
            "status": status,
            "conclusion": conclusion,
            "check_run_url": check_url,
        }
        jobs.append(record)
        if status == "completed":
            detail = dict(record, steps=[{
                "number": index,
                "name": step_name,
                "status": "completed",
                "conclusion": "success",
            } for index, step_name in enumerate(step_names, 1)])
            pages["/repos/keeldock-platform/platform-ci/actions/jobs/" + str(job_id)] = (detail, {})
            check_path = "/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
            pages[check_path] = ({
                "id": check_id,
                "head_sha": CONTROL_SHA,
                "status": "completed",
                "conclusion": "success",
                "output": {"title": name, "summary": "cache proof fixture", "annotations_count": 0},
            }, {})
            pages[check_path + "/annotations?per_page=100&page=1"] = ([], {})
            logs[job_id] = logs_by_name[name]
    pages[jobs_path] = ({"total_count": len(jobs), "jobs": jobs}, {})
    pages[artifact_path] = ({"total_count": 0, "artifacts": []}, {})
    pages[cache_path] = ({"total_count": len(cache_items), "actions_caches": cache_items}, {})
    env = {
        "GITHUB_REPOSITORY": audit.REPOSITORY,
        "GITHUB_RUN_ID": RUN_ID,
        "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
        "CI_SHA": CONTROL_SHA,
        "GITHUB_TOKEN": "t" * 32,
        "MACOS_CACHE_SNAPSHOT": audit.cache_inventory_digest([]),
    }
    return pages, env, logs, cache_items


def source_reader_settings_fixture(kind):
    configuration = audit.SOURCE_READER_CONFIGURATIONS[kind]
    environment_path = (
        "/repos/keeldock-platform/platform-ci/environments/"
        + configuration["environment_name"]
    )
    policies_path = environment_path + "/deployment-branch-policies?per_page=100&page=1"
    return {
        environment_path: ({
            "id": configuration["environment_id"],
            "name": configuration["environment_name"],
            "deployment_branch_policy": {
                "custom_branch_policies": True,
                "protected_branches": False,
            },
        }, {}),
        policies_path: ({
            "total_count": 1,
            "branch_policies": [{
                "id": configuration["branch_policy_id"],
                "name": "main",
                "type": "branch",
            }],
        }, {}),
    }


def bootstrap_dispatch_run(kind, run_id=RUN_ID, sha=CONTROL_SHA, status="in_progress"):
    configuration = audit.SOURCE_READER_CONFIGURATIONS[kind]
    return {
        "id": int(run_id),
        "run_attempt": int(RUN_ATTEMPT),
        "head_sha": sha,
        "workflow_id": 987654321,
        "path": configuration["workflow_path"],
        "event": "workflow_dispatch",
        "head_branch": "main",
        "status": status,
        "repository": {"full_name": audit.REPOSITORY},
    }


def bootstrap_dispatch_settings_fixture(kind, runs=None, total_count=None, link=None):
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
    current_run = bootstrap_dispatch_run(kind)
    workflow_runs_path = (
        "/repos/keeldock-platform/platform-ci/actions/workflows/987654321/runs"
    )
    collection_path = (
        workflow_runs_path
        + "?branch=main&event=workflow_dispatch&per_page=100&page=1"
    )
    if runs is None:
        runs = [dict(current_run)]
    response = {"total_count": len(runs) if total_count is None else total_count,
                "workflow_runs": runs}
    headers = {} if link is None else {"Link": link}
    pages = source_reader_settings_fixture(kind)
    pages[run_path] = (current_run, {})
    pages[collection_path] = (response, headers)
    env = {
        "GITHUB_REPOSITORY": audit.REPOSITORY,
        "GITHUB_RUN_ID": RUN_ID,
        "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
        "CI_SHA": CONTROL_SHA,
        "GITHUB_TOKEN": "t" * 32,
    }
    return pages, env, workflow_runs_path


def source_reader_audit_fixture(kind):
    configuration = audit.SOURCE_READER_CONFIGURATIONS[kind]
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
    jobs_path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
    )
    artifact_path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/artifacts?per_page=100&page=1"
    )
    cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
    settings_check_id = 702
    token_check_id = 703
    settings_job_id = 602
    token_job_id = 603
    job_specs = (
        (audit.SOURCE_READER_SETTINGS_JOB_NAME, settings_job_id, settings_check_id, "completed", "success", (
            "Fetch reviewed main control", "Validate source-free control tree",
            "Verify exact protected environment settings", "Snapshot public surfaces",
        )),
        (audit.SOURCE_READER_TOKEN_JOB_NAME, token_job_id, token_check_id, "completed", "success", (
            "Fetch reviewed main control", "Validate source-reader scope configuration",
            "Mint scoped source-reader token", "Verify selected installation identity",
            "Verify one-repository read scope and revoke token",
            "Write trusted summary visibility control",
        )),
        (audit.SOURCE_READER_AUDIT_JOB_NAME, 604, 704, "in_progress", "success", ()),
    )
    pages = {
        run_path: ({
            "id": int(RUN_ID),
            "run_attempt": int(RUN_ATTEMPT),
            "head_sha": CONTROL_SHA,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": configuration["workflow_path"],
            "repository": {"full_name": audit.REPOSITORY},
        }, {}),
        artifact_path: ({"total_count": 0, "artifacts": []}, {}),
        cache_path: ({"total_count": 0, "actions_caches": []}, {}),
    }
    pages.update(source_reader_settings_fixture(kind))
    jobs = []
    logs = {}
    environment_marker = (
        "macos-source-environment=verified schema=1 kind=" + kind
        + " name=" + configuration["environment_name"]
        + " environment-id=" + str(configuration["environment_id"])
        + " policy-id=" + str(configuration["branch_policy_id"])
        + " custom-branch-policies=true protected-branches=false branch=main branch-type=branch"
        + " control-sha=" + CONTROL_SHA + " run-id=" + RUN_ID
        + " run-attempt=" + RUN_ATTEMPT + "\n"
    ).encode("ascii")
    snapshot_marker = (
        "macos-source-reader-snapshot=ready schema=1 control-sha=" + CONTROL_SHA
        + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT + "\n"
    ).encode("ascii")
    installation_id = b"7654321"
    repository_id = b"246813579"
    settings_log = environment_marker + snapshot_marker
    token_log = (
        b"macos-source-reader-installation=verified schema=1 control-sha="
        + CONTROL_SHA.encode("ascii") + b" run-id=" + RUN_ID.encode("ascii")
        + b" run-attempt=" + RUN_ATTEMPT.encode("ascii")
        + b" installation-id=" + installation_id + b"\n"
        + audit.SOURCE_READER_SUCCESS_RECORD + b"\n"
        + b"macos-source-reader-scope=verified schema=1 action-sha="
        + audit.SOURCE_READER_ACTION_SHA.encode("ascii") + b" control-sha="
        + CONTROL_SHA.encode("ascii") + b" run-id=" + RUN_ID.encode("ascii")
        + b" run-attempt=" + RUN_ATTEMPT.encode("ascii")
        + b" installation-id=" + installation_id + b" repository-id=" + repository_id
        + b" repositories=1 permission=contents-read metadata=verified revocation=confirmed "
        + b"source-content=not-read\n"
        + b"macos-summary-control=trusted-write schema=1 control-sha="
        + CONTROL_SHA.encode("ascii") + b" run-id=" + RUN_ID.encode("ascii")
        + b" run-attempt=" + RUN_ATTEMPT.encode("ascii") + b"\n"
    )
    for name, job_id, check_id, status, conclusion, step_names in job_specs:
        check_url = "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
        record = {
            "id": job_id,
            "run_id": int(RUN_ID),
            "run_attempt": int(RUN_ATTEMPT),
            "head_sha": CONTROL_SHA,
            "name": name,
            "status": status,
            "conclusion": conclusion,
            "check_run_url": check_url,
        }
        jobs.append(record)
        if status == "completed":
            detail = dict(record, steps=[{
                "number": index,
                "name": step_name,
                "status": "completed",
                "conclusion": "success",
            } for index, step_name in enumerate(step_names, 1)])
            pages["/repos/keeldock-platform/platform-ci/actions/jobs/" + str(job_id)] = (detail, {})
            check_path = "/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
            pages[check_path] = ({
                "id": check_id,
                "head_sha": CONTROL_SHA,
                "status": "completed",
                "conclusion": "success",
                "output": {"title": name, "summary": "source reader fixture", "annotations_count": 0},
            }, {})
            pages[check_path + "/annotations?per_page=100&page=1"] = ([], {})
            logs[job_id] = settings_log if name == audit.SOURCE_READER_SETTINGS_JOB_NAME else token_log
    pages[jobs_path] = ({"total_count": len(jobs), "jobs": jobs}, {})
    env = {
        "GITHUB_REPOSITORY": audit.REPOSITORY,
        "GITHUB_RUN_ID": RUN_ID,
        "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
        "CI_SHA": CONTROL_SHA,
        "GITHUB_TOKEN": "t" * 32,
        "MACOS_CACHE_SNAPSHOT": audit.cache_inventory_digest([]),
    }
    return pages, env, logs


def bootstrap_audit_fixture(kind):
    configuration = audit.SOURCE_READER_CONFIGURATIONS[kind]
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
    jobs_path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
    )
    artifact_path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/artifacts?per_page=100&page=1"
    )
    cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
    source_sha = "b" * 40
    base_sha = "c" * 40
    reviewed_diff = "d" * 64
    if kind == "rules-bootstrap":
        snapshot_name = audit.RULES_BOOTSTRAP_SETTINGS_JOB_NAME
        producer_name = audit.RULES_BOOTSTRAP_PRODUCER_JOB_NAME
        audit_name = audit.RULES_BOOTSTRAP_AUDIT_JOB_NAME
        snapshot_id, snapshot_check = 802, 902
        producer_id, producer_check = 803, 903
        audit_id, audit_check = 804, 904
        snapshot_steps = (
            "Fetch reviewed main control", "Validate source-free control tree",
            "Validate requested source identity", "Verify exact protected environment settings",
            "Snapshot public surfaces",
        )
        producer_steps = (
            "Fetch reviewed main control", "Validate source-free control tree",
            "Seal exact control signer inventory", "Prepare pinned public dash before token mint",
            "Preflight protected bootstrap and review binding",
            "Validate source-reader scope configuration", "Mint scoped source-reader token",
            "Verify selected installation identity", "Run fixed rules bootstrap",
            "Revoke token if bootstrap did not confirm", "Clean prepared dash",
            "Write trusted summary visibility control",
        )
        preflight = (
            "macos-rules-bootstrap=preflight-passed schema=1 control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " source-sha=" + source_sha + " base-sha=" + base_sha
            + " base-branch=develop dash-version=0.5.13.5"
            + " dash-bottle-sha256=0e104457d0d188129596ee04e4f88ab6039baf9a03e183820caf0aa333d581d0"
            + " dash-binary-sha256=" + "e" * 64 + " reviewed-diff-sha256=" + reviewed_diff
        ).encode("ascii")
        success = (
            "macos-rules-bootstrap=passed schema=1 control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " source-sha=" + source_sha + " base-sha=" + base_sha
            + " base-branch=develop candidate-class=signed-descendant"
            + " suites=rules.hooks,rules.sync,rules.static,rules.public,plan-ids"
            + " token-revocation=confirmed-before-execution lease-cleanup=complete"
            + " process-cleanup=complete identity-cleanup=complete"
            + " summary-guard=append-sibling-create-readback-restore source-tree=uid-read-only"
            + " dash-version=0.5.13.5"
            + " dash-bottle-sha256=0e104457d0d188129596ee04e4f88ab6039baf9a03e183820caf0aa333d581d0"
            + " dash-binary-sha256=" + "e" * 64 + " reviewed-diff-sha256=" + reviewed_diff
            + " same-job-memory=not-verified"
        ).encode("ascii")
        summary = (
            "macos-rules-summary-control=trusted-write schema=1 control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " source-sha=" + source_sha + " base-sha=" + base_sha
            + " reviewed-diff-sha256=" + reviewed_diff
        ).encode("ascii")
        source_binding = (
            "macos-rules-source-binding=verified schema=1 control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " repository-id=" + audit.BOOTSTRAP_SOURCE_REPOSITORY_IDS["rules-bootstrap"]
        ).encode("ascii")
        network = (
            "2026-10-26T12:34:56.1234567Z macos-rules-network=observed schema=1 mode=host-level control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " source-sha=" + source_sha + " interface-count=2 dns-query-count=1 tcp-syn-count=1"
            + " dns-name-hashes=" + "1" * 64 + " tcp-destination-hashes=" + "2" * 64
            + " hashes-truncated=false capture-limited=false capture=private cleanup=complete"
            + " worker-attribution=not-claimed completeness=not-claimed"
            + " network-blocking=not-claimed"
        ).encode("ascii")
        producer_log = (
            preflight + b"\n" + source_binding + b"\n" + network + b"\n"
            + success + b"\n" + summary + b"\n"
        )
        env = {
            "REQUESTED_SOURCE_SHA": source_sha,
            "REQUESTED_BASE_SHA": base_sha,
            "REQUESTED_BASE_BRANCH": "develop",
            "REVIEWED_DIFF_SHA256": reviewed_diff,
        }
        skipped_step = "Revoke token if bootstrap did not confirm"
    elif kind == "core-bootstrap":
        snapshot_name = audit.CORE_BOOTSTRAP_SNAPSHOT_JOB_NAME
        producer_name = audit.CORE_BOOTSTRAP_PRODUCER_JOB_NAME
        audit_name = audit.CORE_BOOTSTRAP_AUDIT_JOB_NAME
        snapshot_id, snapshot_check = 812, 912
        producer_id, producer_check = 813, 913
        audit_id, audit_check = 814, 914
        source_sha = "b" * 40
        snapshot_steps = ("Fetch control", "Audit source-read settings", "Snapshot cache")
        producer_steps = (
            "Fetch control", "Test control", "Run reviewed smoke", "Protect inventory",
            "Core preflight", "Write trusted summary visibility control",
            "Validate reader settings", "Mint reader token", "Validate core bootstrap",
        )
        smoke = (
            "macos-build=synthetic-smoke-passed schema=1 source=none control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " image-os=macos-15 image-version=20261026.0337.1 macos-version=15.7.9"
            + " architecture=arm64 xcode=not-used xcode-build=not-used"
            + " compiler-origin=command-line-tools clang=16.0.0 sdk=15.0"
            + " developer-mode=disabled privilege=separate-nonadmin sudo=denied"
            + " compile=passed link=passed load-test=passed capture=passed"
            + " summary-standin=write-denied real-summary=write-denied"
            + " cleanup=complete seatbelt=not-run pf=not-run"
        ).encode("ascii")
        preflight = (
            "macos-core-bootstrap=preflight-passed schema=1 control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " source-sha=" + source_sha + " runner-summary=append-denied"
            + " summary-sibling=create-denied summary-standin=write-denied cleanup=complete"
        ).encode("ascii")
        source_binding = (
            "macos-core-source-binding=verified schema=1 control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " repository-id=" + audit.BOOTSTRAP_SOURCE_REPOSITORY_IDS["core-bootstrap"]
        ).encode("ascii")
        summary_control = (
            "2026-10-26T12:34:56.1234567Z macos-summary-control=trusted-write schema=1 control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
        ).encode("ascii")
        success = (
            "macos-core-bootstrap=verified schema=1 control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " image-os=macos-15 image-version=20261026.0337.1"
            + " source-repository-id=1430959909 source-sha=" + source_sha
            + " base-branch=main base-sha=" + source_sha + " concern=core-bootstrap"
            + " source-signature=verified token-revocation=confirmed-before-execution"
            + " rules-lock=present rules-lock-signature=declared-verified"
            + " lock-format=3 manifest=matched signers-hash=well-formed fragment-hash=well-formed"
            + " source-execution=not-run app-build=not-run worker-access=not-applicable cleanup=complete"
            + " summary-control=append-denied summary-sibling=create-denied"
            + " summary-standin=write-denied summary-sentinel=written"
        ).encode("ascii")
        binding_command_echo = b'source_binding_prefix="macos-core-source-binding="'
        bootstrap_command_echo = (
            b"marker_prefix='macos-core-bootstrap='\n"
            b"success_state='verified'\nrefusal_state='refused'\n"
        )
        producer_log = (
            smoke + b"\n" + preflight + b"\n" + summary_control + b"\n" + bootstrap_command_echo + b"\n"
            + binding_command_echo + b"\n"
            + source_binding + b"\n" + success + b"\n"
        )
        env = {"SOURCE_SHA": source_sha}
        skipped_step = None
    else:
        raise AssertionError("unknown bootstrap fixture kind")

    settings_marker = (
        "macos-source-environment=verified schema=1 kind=" + kind
        + " name=" + configuration["environment_name"]
        + " environment-id=" + str(configuration["environment_id"])
        + " policy-id=" + str(configuration["branch_policy_id"])
        + " custom-branch-policies=true protected-branches=false branch=main branch-type=branch"
        + " control-sha=" + CONTROL_SHA + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
    ).encode("ascii")
    snapshot_marker = (
        "macos-" + kind + "-snapshot=ready schema=1 control-sha=" + CONTROL_SHA
        + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
    ).encode("ascii")
    dispatch_marker = audit._bootstrap_dispatch_marker(kind, CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
    snapshot_log = dispatch_marker + b"\n" + settings_marker + b"\n" + snapshot_marker + b"\n"
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
    pages = {
        run_path: ({
            "id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT), "head_sha": CONTROL_SHA,
            "event": "workflow_dispatch", "head_branch": "main",
            "path": configuration["workflow_path"],
            "repository": {"full_name": audit.REPOSITORY},
        }, {}),
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/artifacts?per_page=100&page=1": ({"total_count": 0, "artifacts": []}, {}),
        "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1": (
            {"total_count": 0, "actions_caches": []}, {}
        ),
    }
    pages.update(source_reader_settings_fixture(kind))
    jobs = []
    logs = {}
    job_specs = (
        (snapshot_name, snapshot_id, snapshot_check, "completed", "success", snapshot_steps),
        (producer_name, producer_id, producer_check, "completed", "success", producer_steps),
        (audit_name, audit_id, audit_check, "in_progress", "success", ()),
    )
    for name, job_id, check_id, status, conclusion, step_names in job_specs:
        check_url = "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
        record = {
            "id": job_id, "run_id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT),
            "head_sha": CONTROL_SHA, "name": name, "status": status,
            "conclusion": conclusion, "check_run_url": check_url,
        }
        jobs.append(record)
        if status == "completed":
            step_records = []
            post_names = (
                ("Post Mint scoped source-reader token",)
                if name == producer_name and kind == "rules-bootstrap"
                else ("Post Mint reader token",)
                if name == producer_name and kind == "core-bootstrap"
                else ()
            )
            actual_step_names = ("Set up job", *step_names, *post_names, "Complete job")
            for index, step_name in enumerate(actual_step_names, 1):
                step_conclusion = "skipped" if step_name == skipped_step else "success"
                step_records.append({
                    "number": index, "name": step_name, "status": "completed",
                    "conclusion": step_conclusion,
                })
            detail = dict(record, steps=step_records)
            pages["/repos/keeldock-platform/platform-ci/actions/jobs/" + str(job_id)] = (detail, {})
            check_path = "/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
            pages[check_path] = ({
                "id": check_id, "head_sha": CONTROL_SHA, "status": "completed",
                "conclusion": "success",
                "output": {"title": name, "summary": "bootstrap fixture", "annotations_count": 0},
            }, {})
            pages[check_path + "/annotations?per_page=100&page=1"] = ([], {})
            logs[job_id] = snapshot_log if name == snapshot_name else producer_log
    jobs_path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
        + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
    )
    pages[jobs_path] = ({"total_count": len(jobs), "jobs": jobs}, {})
    env.update({
        "GITHUB_REPOSITORY": audit.REPOSITORY,
        "GITHUB_RUN_ID": RUN_ID,
        "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
        "CI_SHA": CONTROL_SHA,
        "GITHUB_TOKEN": "t" * 32,
        "MACOS_CACHE_SNAPSHOT": audit.cache_inventory_digest([]),
    })
    return pages, env, logs


class SourceReaderSettingsTests(unittest.TestCase):
    def test_settings_require_exact_environment_and_one_main_branch_policy(self):
        for kind in ("core", "rules", "core-bootstrap", "rules-bootstrap"):
            with self.subTest(kind=kind):
                pages = source_reader_settings_fixture(kind)
                api = FakeAPI(pages)
                marker = audit._verify_source_reader_environment(
                    api, kind, CONTROL_SHA, RUN_ID, RUN_ATTEMPT
                )
                self.assertIn(b"branch=main branch-type=branch", marker)
                self.assertIn(b"custom-branch-policies=true protected-branches=false", marker)
                self.assertEqual(len(api.calls), 2)

    def test_settings_refuse_missing_or_ambiguous_branch_policy_metadata(self):
        for kind, mutate in (
            ("rules", lambda env, policies: policies["branch_policies"][0].pop("type")),
            ("rules-bootstrap", lambda env, policies: policies["branch_policies"][0].pop("type")),
            ("rules", lambda env, policies: policies["branch_policies"][0].update(type="tag")),
            ("rules", lambda env, policies: policies["branch_policies"][0].update(name="release/*")),
            ("rules", lambda env, policies: policies.update(
                total_count=2,
                branch_policies=policies["branch_policies"] + [{
                    "id": 991122,
                    "name": "release/*",
                    "type": "branch",
                }],
            )),
            ("core", lambda env, policies: env.update(
                deployment_branch_policy={
                    "custom_branch_policies": False,
                    "protected_branches": True,
                }
            )),
            ("core", lambda env, policies: env.update(id=1)),
        ):
            with self.subTest(kind=kind, mutation=mutate.__code__.co_firstlineno):
                pages = source_reader_settings_fixture(kind)
                environment_path = (
                    "/repos/keeldock-platform/platform-ci/environments/"
                    + audit.SOURCE_READER_CONFIGURATIONS[kind]["environment_name"]
                )
                policy_path = environment_path + "/deployment-branch-policies?per_page=100&page=1"
                mutate(pages[environment_path][0], pages[policy_path][0])
                with self.assertRaises(audit.AuditRefusal):
                    audit._verify_source_reader_environment(
                        FakeAPI(pages), kind, CONTROL_SHA, RUN_ID, RUN_ATTEMPT
                    )


class BootstrapDispatchGuardTests(unittest.TestCase):
    def _run_settings(self, kind, pages, env):
        output = io.StringIO()
        api = FakeAPI(pages)
        with contextlib.redirect_stdout(output):
            result = audit.run(kind + "-settings", env, api)
        return result, output.getvalue(), api

    def test_settings_guard_allows_current_and_completed_runs(self):
        kind = "core-bootstrap"
        current = bootstrap_dispatch_run(kind)
        completed = bootstrap_dispatch_run(
            kind, run_id="765432101", sha="f" * 40, status="completed"
        )
        pages, env, collection_path = bootstrap_dispatch_settings_fixture(
            kind, [current, completed]
        )
        result, output, api = self._run_settings(kind, pages, env)
        self.assertEqual(result, 0)
        self.assertIn(
            "macos-bootstrap-dispatch=single-active-verified schema=1 kind=core-bootstrap",
            output,
        )
        self.assertEqual(api.calls[0], "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID)
        self.assertEqual(api.calls[1], collection_path + "?branch=main&event=workflow_dispatch&per_page=100&page=1")
        self.assertTrue(api.calls[2].endswith("/environments/source-read"))

    def test_settings_guard_refuses_other_active_main_dispatch_even_at_an_older_sha(self):
        kind = "rules-bootstrap"
        current = bootstrap_dispatch_run(kind)
        for status in ("queued", "in_progress", "waiting", "pending", "requested"):
            with self.subTest(status=status):
                other = bootstrap_dispatch_run(
                    kind, run_id="765432101", sha="f" * 40, status=status
                )
                pages, env, _ = bootstrap_dispatch_settings_fixture(kind, [current, other])
                api = FakeAPI(pages)
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.run(kind + "-settings", env, api)
                self.assertEqual(caught.exception.reason, "run_identity_mismatch")
                self.assertEqual(len(api.calls), 2)
                self.assertFalse(any("/environments/" in path for path in api.calls))

    def test_settings_guard_requires_exact_current_run_identity(self):
        for field, value in (
            ("head_sha", "f" * 40),
            ("run_attempt", 3),
            ("path", ".github/workflows/other.yml"),
            ("head_branch", "develop"),
            ("event", "push"),
            ("workflow_id", 123456),
            ("repository", {"full_name": "other/repository"}),
        ):
            with self.subTest(field=field):
                kind = "core-bootstrap"
                current = bootstrap_dispatch_run(kind)
                listed_current = dict(current)
                listed_current[field] = value
                pages, env, _ = bootstrap_dispatch_settings_fixture(kind, [listed_current])
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.run(kind + "-settings", env, FakeAPI(pages))
                expected = "api_schema" if field in {
                    "path", "head_branch", "event", "workflow_id", "repository"
                } else "run_identity_mismatch"
                self.assertEqual(caught.exception.reason, expected)

    def test_settings_guard_refuses_unknown_status_and_missing_current_run(self):
        kind = "core-bootstrap"
        current = bootstrap_dispatch_run(kind)
        unknown = dict(current, status="suspended")
        pages, env, _ = bootstrap_dispatch_settings_fixture(kind, [unknown])
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run(kind + "-settings", env, FakeAPI(pages))
        self.assertEqual(caught.exception.reason, "api_schema")

        pages, env, _ = bootstrap_dispatch_settings_fixture(kind, [])
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run(kind + "-settings", env, FakeAPI(pages))
        self.assertEqual(caught.exception.reason, "run_identity_mismatch")

        pages, env, _ = bootstrap_dispatch_settings_fixture(kind, [current, dict(current)])
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run(kind + "-settings", env, FakeAPI(pages))
        self.assertEqual(caught.exception.reason, "api_schema")

    def test_settings_guard_requires_complete_pagination_for_all_runs(self):
        kind = "rules-bootstrap"
        first_page = [bootstrap_dispatch_run(kind)] + [
            bootstrap_dispatch_run(
                kind, run_id=str(700000000 + index), sha="f" * 40, status="completed"
            )
            for index in range(99)
        ]
        pages, env, list_path = bootstrap_dispatch_settings_fixture(
            kind, first_page, total_count=101
        )
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run(kind + "-settings", env, FakeAPI(pages))
        self.assertEqual(caught.exception.reason, "pagination_incomplete")

        second_path = list_path + "?branch=main&event=workflow_dispatch&per_page=100&page=2"
        first_url = "https://api.github.com" + list_path + "?branch=main&event=workflow_dispatch&per_page=100&page=1"
        second_url = "https://api.github.com" + second_path
        pages[list_path + "?branch=main&event=workflow_dispatch&per_page=100&page=1"] = (
            {"total_count": 101, "workflow_runs": first_page},
            {"Link": "<" + second_url + ">; rel=\"next\", <" + second_url + ">; rel=\"last\""},
        )
        pages[second_path] = (
            {"total_count": 101, "workflow_runs": [bootstrap_dispatch_run(
                kind, run_id="700000999", sha="f" * 40, status="completed"
            )]},
            {"Link": "<" + first_url + ">; rel=\"first\", <" + first_url + ">; rel=\"prev\", <" + second_url + ">; rel=\"last\""},
        )
        result, _, api = self._run_settings(kind, pages, env)
        self.assertEqual(result, 0)
        self.assertIn(second_path, api.calls)

    def test_bootstrap_snapshot_audit_requires_one_run_bound_dispatch_guard_marker(self):
        for kind, snapshot_job_id in (
            ("rules-bootstrap", 802),
            ("core-bootstrap", 812),
        ):
            with self.subTest(kind=kind):
                _, _, logs = bootstrap_audit_fixture(kind)
                raw = logs[snapshot_job_id]
                audit._inspect_bootstrap_settings_snapshot(
                    raw, kind, CONTROL_SHA, RUN_ID, RUN_ATTEMPT
                )
                marker = audit._bootstrap_dispatch_marker(
                    kind, CONTROL_SHA, RUN_ID, RUN_ATTEMPT
                )
                for changed in (
                    raw.replace(marker + b"\n", b"", 1),
                    raw + marker + b"\n",
                    raw.replace(CONTROL_SHA.encode("ascii"), b"f" * 40, 1),
                ):
                    with self.assertRaises(audit.AuditRefusal) as caught:
                        audit._inspect_bootstrap_settings_snapshot(
                            changed, kind, CONTROL_SHA, RUN_ID, RUN_ATTEMPT
                        )
                    self.assertEqual(caught.exception.reason, "receipt_invalid")


class SourceReaderAuditTests(unittest.TestCase):
    def test_audit_requires_scope_revocation_summary_and_all_public_surfaces(self):
        for kind in ("core", "rules"):
            with self.subTest(kind=kind):
                pages, env, logs = source_reader_audit_fixture(kind)
                api = FakeMultiAuditAPI(pages, logs)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    result = audit.run("source-reader-audit-" + kind, env, api)
                self.assertEqual(result, 0)
                self.assertEqual(
                    output.getvalue(),
                    "macos-source-reader-audit=verified schema=1 kind=" + kind
                    + " control-sha=" + CONTROL_SHA + " run-id=" + RUN_ID
                    + " run-attempt=" + RUN_ATTEMPT
                    + " scope=one-private-repository-read revocation=confirmed source-content=not-read\n",
                )
                self.assertEqual(api.log_calls, [602, 603])
                self.assertTrue(any(path.endswith("/artifacts?per_page=100&page=1") for path in api.calls))
                self.assertTrue(any(path.endswith("/actions/caches?per_page=100&page=1") for path in api.calls))
                self.assertTrue(any(path.endswith("/deployment-branch-policies?per_page=100&page=1") for path in api.calls))

    def test_audit_refuses_missing_identity_revocation_or_summary_evidence(self):
        mutations = (
            lambda logs: logs.__setitem__(603, logs[603].replace(
                b"revocation=confirmed", b"revocation=unconfirmed", 1
            )),
            lambda logs: logs.__setitem__(603, logs[603].replace(
                audit.SOURCE_READER_SUCCESS_RECORD, b"", 1
            )),
            lambda logs: logs.__setitem__(603, logs[603].replace(
                b"macos-summary-control=trusted-write", b"macos-summary-control=missing", 1
            )),
            lambda logs: logs.__setitem__(603, logs[603].replace(
                b"run-attempt=" + RUN_ATTEMPT.encode("ascii"), b"run-attempt=3", 1
            )),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                pages, env, logs = source_reader_audit_fixture("rules")
                mutate(logs)
                with self.assertRaises(audit.AuditRefusal):
                    audit.run("source-reader-audit-rules", env, FakeMultiAuditAPI(pages, logs))

    def test_audit_refuses_failed_jobs_artifacts_cache_changes_and_wrong_branch_policy(self):
        pages, env, logs = source_reader_audit_fixture("core")
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )
        token_job = next(
            job for job in pages[jobs_path][0]["jobs"]
            if job["name"] == audit.SOURCE_READER_TOKEN_JOB_NAME
        )
        token_job["conclusion"] = "failure"
        token_detail_path = "/repos/keeldock-platform/platform-ci/actions/jobs/603"
        pages[token_detail_path][0]["conclusion"] = "failure"
        pages["/repos/keeldock-platform/platform-ci/check-runs/703"][0]["conclusion"] = "failure"
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("source-reader-audit-core", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "native_job_failed")

        pages, env, logs = source_reader_audit_fixture("core")
        artifact_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/artifacts?per_page=100&page=1"
        )
        pages[artifact_path] = ({"total_count": 1, "artifacts": [{
            "id": 909,
            "name": "unexpected",
            "size_in_bytes": 1,
            "expired": False,
        }]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("source-reader-audit-core", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "artifact_found")

        pages, env, logs = source_reader_audit_fixture("core")
        cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        pages[cache_path] = ({"total_count": 1, "actions_caches": [{
            "id": 808,
            "ref": "refs/heads/main",
            "key": "unexpected-public-cache-v1",
            "version": "v1",
            "last_accessed_at": None,
            "created_at": "2026-10-26T00:00:00Z",
            "size_in_bytes": 1,
        }]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("source-reader-audit-core", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "inventory_changed")

        pages, env, logs = source_reader_audit_fixture("core")
        env_path = "/repos/keeldock-platform/platform-ci/environments/source-read"
        pages[env_path][0]["deployment_branch_policy"]["custom_branch_policies"] = False
        with self.assertRaises(audit.AuditRefusal):
            audit.run("source-reader-audit-core", env, FakeMultiAuditAPI(pages, logs))


class BootstrapAuditTests(unittest.TestCase):
    def test_rules_and_core_bootstrap_require_settings_snapshot_and_producer_evidence(self):
        for kind, expected_output, expected_logs in (
            (
                "rules-bootstrap",
                "macos-rules-bootstrap-audit=verified schema=1",
                [802, 803],
            ),
            (
                "core-bootstrap",
                "macos-core-bootstrap-audit=verified schema=1",
                [812, 813],
            ),
        ):
            with self.subTest(kind=kind):
                pages, env, logs = bootstrap_audit_fixture(kind)
                api = FakeMultiAuditAPI(pages, logs)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    result = audit.run(kind + "-audit", env, api)
                self.assertEqual(result, 0)
                self.assertTrue(output.getvalue().startswith(expected_output))
                self.assertIn("summary-ui=required source-admission=not-authorized", output.getvalue())
                self.assertEqual(api.log_calls, expected_logs)
                self.assertTrue(any(path.endswith("/artifacts?per_page=100&page=1") for path in api.calls))
                self.assertTrue(any(path.endswith("/actions/caches?per_page=100&page=1") for path in api.calls))
                self.assertTrue(any(path.endswith("/deployment-branch-policies?per_page=100&page=1") for path in api.calls))

    def test_rules_audit_refuses_missing_or_mismatched_run_bindings_and_fallback(self):
        def change_network(old, new):
            def mutate(pages, env, logs):
                lines = logs[803].splitlines()
                index = next(i for i, line in enumerate(lines) if b"macos-rules-network=" in line)
                lines[index] = lines[index].replace(old, new, 1)
                logs[803] = b"\n".join(lines) + b"\n"
            return mutate

        def duplicate_network(pages, env, logs):
            line = next(
                line for line in logs[803].splitlines()
                if b"macos-rules-network=" in line
            )
            logs[803] += line + b"\n"

        mutations = (
            lambda pages, env, logs: logs.__setitem__(803, logs[803].replace(
                b"reviewed-diff-sha256=" + b"d" * 64,
                b"reviewed-diff-sha256=" + b"f" * 64,
                1,
            )),
            lambda pages, env, logs: logs.__setitem__(803, logs[803].replace(
                b"macos-rules-summary-control=trusted-write", b"macos-rules-summary-control=missing", 1
            )),
            lambda pages, env, logs: logs.__setitem__(803, logs[803].replace(
                b"dash-binary-sha256=" + b"e" * 64,
                b"dash-binary-sha256=" + b"f" * 64,
                1,
            )),
            lambda pages, env, logs: env.__setitem__("REQUESTED_SOURCE_SHA", "f" * 40),
            lambda pages, env, logs: logs.__setitem__(803, logs[803].replace(
                b"repository-id=" + audit.BOOTSTRAP_SOURCE_REPOSITORY_IDS["rules-bootstrap"].encode("ascii"),
                b"repository-id=999999", 1,
            )),
            lambda pages, env, logs: next(
                step for step in pages[
                    "/repos/keeldock-platform/platform-ci/actions/jobs/803"
                ][0]["steps"] if step["name"] == "Revoke token if bootstrap did not confirm"
            ).update(conclusion="success"),
            change_network(b"macos-rules-network=observed", b"macos-rules-network=missing"),
            change_network(b"source-sha=" + b"b" * 40, b"source-sha=" + b"f" * 40),
            change_network(b"interface-count=2", b"interface-count=0"),
            change_network(b"dns-query-count=1", b"dns-query-count=65536"),
            change_network(b"capture-limited=false", b"capture-limited=unknown"),
            change_network(b"worker-attribution=not-claimed", b"worker-attribution=claimed"),
            change_network(b"network-blocking=not-claimed", b"network-blocking=blocked"),
            change_network(
                b"dns-name-hashes=" + b"1" * 64,
                b"dns-name-hashes=" + b"2" * 64 + b"," + b"1" * 64,
            ),
            change_network(
                b"dns-name-hashes=" + b"1" * 64,
                b"dns-name-hashes=" + b",".join([b"3" * 64] * 17),
            ),
            duplicate_network,
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                pages, env, logs = bootstrap_audit_fixture("rules-bootstrap")
                mutate(pages, env, logs)
                with self.assertRaises(audit.AuditRefusal):
                    audit.run(
                        "rules-bootstrap-audit", env, FakeMultiAuditAPI(pages, logs)
                    )

    def test_core_audit_refuses_missing_summary_marker_wrong_sha_and_failed_step(self):
        mutations = (
            lambda pages, env, logs: logs.__setitem__(813, logs[813].replace(
                b"macos-core-bootstrap=verified", b"macos-core-bootstrap=refused", 1
            )),
            lambda pages, env, logs: logs.__setitem__(813, logs[813] + b"macos-core-bootstrap=refused schema=1\n"),
            lambda pages, env, logs: logs.__setitem__(813, logs[813].replace(
                b"source-repository-id=1430959909", b"source-repository-id=999999", 1
            )),
            lambda pages, env, logs: logs.__setitem__(813, logs[813].replace(
                b"summary-sentinel=written", b"summary-sentinel=not-written", 1
            )),
            lambda pages, env, logs: logs.__setitem__(813, logs[813].replace(
                b"macos-summary-control=trusted-write",
                b"macos-summary-control=missing", 1
            )),
            lambda pages, env, logs: logs.__setitem__(813, logs[813] + b"\n" + next(
                line for line in logs[813].splitlines() if b"macos-summary-control=" in line
            ) + b"\n"),
            lambda pages, env, logs: logs.__setitem__(813, logs[813].replace(
                b"macos-summary-control=trusted-write schema=1 control-sha=" + CONTROL_SHA.encode("ascii"),
                b"macos-summary-control=trusted-write schema=1 control-sha=" + b"f" * 40,
                1,
            )),
            lambda pages, env, logs: logs.__setitem__(813, logs[813].replace(
                b"macos-summary-control=trusted-write schema=1 control-sha=" + CONTROL_SHA.encode("ascii")
                + b" run-id=" + RUN_ID.encode("ascii"),
                b"macos-summary-control=trusted-write schema=1 control-sha=" + CONTROL_SHA.encode("ascii")
                + b" run-id=1",
                1,
            )),
            lambda pages, env, logs: env.__setitem__("SOURCE_SHA", "f" * 40),
            lambda pages, env, logs: pages[
                "/repos/keeldock-platform/platform-ci/actions/jobs/813"
            ][0]["steps"][9].update(conclusion="failure"),
            lambda pages, env, logs: logs.__setitem__(813, logs[813].replace(
                b"macos-core-source-binding=verified", b"macos-core-source-binding=missing", 1
            )),
            lambda pages, env, logs: logs.__setitem__(813, logs[813].replace(
                b"repository-id=1430959909", b"repository-id=999999", 1
            )),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                pages, env, logs = bootstrap_audit_fixture("core-bootstrap")
                mutate(pages, env, logs)
                with self.assertRaises(audit.AuditRefusal):
                    audit.run(
                        "core-bootstrap-audit", env, FakeMultiAuditAPI(pages, logs)
                    )

    def test_bootstrap_audit_refuses_wrong_job_topology_artifacts_and_changed_caches(self):
        pages, env, logs = bootstrap_audit_fixture("core-bootstrap")
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )
        pages[jobs_path][0]["jobs"].append(dict(pages[jobs_path][0]["jobs"][0], id=999, name="extra"))
        pages[jobs_path][0]["total_count"] += 1
        with self.assertRaises(audit.AuditRefusal):
            audit.run("core-bootstrap-audit", env, FakeMultiAuditAPI(pages, logs))

        pages, env, logs = bootstrap_audit_fixture("rules-bootstrap")
        artifact_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/artifacts?per_page=100&page=1"
        )
        pages[artifact_path] = ({"total_count": 1, "artifacts": [{
            "id": 99, "name": "unexpected", "size_in_bytes": 1, "expired": False,
        }]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("rules-bootstrap-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "artifact_found")

        pages, env, logs = bootstrap_audit_fixture("core-bootstrap")
        cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        pages[cache_path] = ({"total_count": 1, "actions_caches": [{
            "id": 101, "ref": "refs/heads/main", "key": "unexpected-public-cache",
            "version": "v1", "last_accessed_at": None,
            "created_at": "2026-10-26T00:00:00Z", "size_in_bytes": 1,
        }]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("core-bootstrap-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "inventory_changed")

    def test_bootstrap_audit_requires_only_the_exact_github_implicit_job_steps(self):
        mutations = (
            lambda steps: steps.pop(0),
            lambda steps: steps[-1].update(name="Unexpected final step"),
            lambda steps: next(
                step for step in steps if step["name"] == "Post Mint reader token"
            ).update(name="Unexpected post step"),
            lambda steps: steps.pop(next(
                index for index, step in enumerate(steps)
                if step["name"] == "Post Mint reader token"
            )),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                pages, env, logs = bootstrap_audit_fixture("core-bootstrap")
                steps = pages["/repos/keeldock-platform/platform-ci/actions/jobs/813"][0]["steps"]
                mutate(steps)
                with self.assertRaises(audit.AuditRefusal):
                    audit.run("core-bootstrap-audit", env, FakeMultiAuditAPI(pages, logs))

    def test_bootstrap_audit_scans_surfaces_then_refuses_pre_mint_failures(self):
        for kind, producer_id, check_id, mint_name, post_name in (
            (
                "rules-bootstrap", 803, 903,
                "Mint scoped source-reader token", "Post Mint scoped source-reader token",
            ),
            (
                "core-bootstrap", 813, 913,
                "Mint reader token", "Post Mint reader token",
            ),
        ):
            with self.subTest(kind=kind):
                pages, env, logs = bootstrap_audit_fixture(kind)
                detail_path = "/repos/keeldock-platform/platform-ci/actions/jobs/" + str(producer_id)
                detail = pages[detail_path][0]
                steps = detail["steps"]
                mint = next(step for step in steps if step["name"] == mint_name)
                mint["conclusion"] = "skipped"
                steps.remove(next(step for step in steps if step["name"] == post_name))
                for step in steps:
                    if step["number"] > mint["number"] and step["name"] != "Complete job":
                        step["conclusion"] = "skipped"
                detail["conclusion"] = "failure"
                pages[detail_path] = (detail, {})
                jobs_path = (
                    "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
                    + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
                )
                producer_name = (
                    audit.RULES_BOOTSTRAP_PRODUCER_JOB_NAME
                    if kind == "rules-bootstrap"
                    else audit.CORE_BOOTSTRAP_PRODUCER_JOB_NAME
                )
                producer_job = next(
                    job for job in pages[jobs_path][0]["jobs"]
                    if job["name"] == producer_name
                )
                producer_job["conclusion"] = "failure"
                check_path = "/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
                pages[check_path][0]["conclusion"] = "failure"
                if kind == "rules-bootstrap":
                    logs[producer_id] = (
                        "2026-10-26T12:34:56.1234567Z macos-rules-bootstrap=refused schema=1 "
                        "reason=dash_bottle_invalid stage=dash_archive_content control-sha=" + CONTROL_SHA
                        + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
                        + " token-revocation=not-read\n"
                    ).encode("ascii")
                else:
                    logs[producer_id] = b"macos-bootstrap=refused schema=1 reason=preflight_failed\n"
                api = FakeMultiAuditAPI(pages, logs)
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.run(kind + "-audit", env, api)
                self.assertEqual(caught.exception.reason, "native_job_failed")
                self.assertEqual(api.log_calls, [802 if kind == "rules-bootstrap" else 812, producer_id])
                self.assertTrue(any(path.endswith("/annotations?per_page=100&page=1") for path in api.calls))
                self.assertTrue(any(path.endswith("/artifacts?per_page=100&page=1") for path in api.calls))
                self.assertTrue(any(path.endswith("/actions/caches?per_page=100&page=1") for path in api.calls))

    def test_rules_source_lease_refusal_without_observer_is_scanned_then_refused(self):
        self.assertEqual(
            set(audit.RULES_BOOTSTRAP_EARLY_SOURCE_REASONS),
            {
                "invalid_input", "context_unavailable", "configuration_unavailable",
                "source_reader_unavailable", "repository_scope_invalid", "source_fetch_unavailable",
                "revocation_unconfirmed", "base_invalid", "signature_invalid",
                "revocation_policy_invalid", "bootstrap_snapshot_invalid", "bootstrap_not_approved",
                "internal_error",
            },
        )

        def failed_fixture(reason="bootstrap_snapshot_invalid", token_state="confirmed"):
            pages, env, logs = bootstrap_audit_fixture("rules-bootstrap")
            detail_path = "/repos/keeldock-platform/platform-ci/actions/jobs/803"
            detail = pages[detail_path][0]
            steps = detail["steps"]
            run_step = next(step for step in steps if step["name"] == "Run fixed rules bootstrap")
            run_step.update(status="completed", conclusion="failure")
            next(
                step for step in steps
                if step["name"] == "Write trusted summary visibility control"
            ).update(conclusion="skipped")
            detail["conclusion"] = "failure"
            pages[detail_path] = (detail, {})
            jobs_path = (
                "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
                + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
            )
            producer_job = next(
                job for job in pages[jobs_path][0]["jobs"]
                if job["name"] == audit.RULES_BOOTSTRAP_PRODUCER_JOB_NAME
            )
            producer_job["conclusion"] = "failure"
            pages["/repos/keeldock-platform/platform-ci/check-runs/903"][0]["conclusion"] = "failure"
            old_lines = logs[803].splitlines()
            preflight = next(line for line in old_lines if b"macos-rules-bootstrap=preflight-passed" in line)
            source_binding = next(line for line in old_lines if b"macos-rules-source-binding=verified" in line)
            refusal = (
                "2026-10-26T12:34:56.1234567Z macos-rules-bootstrap=refused schema=1 reason="
                + reason + " stage=source_lease control-sha=" + CONTROL_SHA
                + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
                + " token-revocation=" + token_state
            ).encode("ascii")
            logs[803] = preflight + b"\n" + source_binding + b"\n" + refusal + b"\n"
            return pages, env, logs

        def change_refusal(logs, old, new):
            lines = logs[803].splitlines()
            index = next(i for i, line in enumerate(lines) if b"macos-rules-bootstrap=refused" in line)
            lines[index] = lines[index].replace(old, new, 1)
            logs[803] = b"\n".join(lines) + b"\n"

        pages, env, logs = failed_fixture()
        api = FakeMultiAuditAPI(pages, logs)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("rules-bootstrap-audit", env, api)
        self.assertEqual(caught.exception.reason, "native_job_failed")
        self.assertEqual(api.log_calls, [802, 803])
        self.assertTrue(any(path.endswith("/annotations?per_page=100&page=1") for path in api.calls))
        self.assertTrue(any(path.endswith("/artifacts?per_page=100&page=1") for path in api.calls))
        self.assertTrue(any(path.endswith("/actions/caches?per_page=100&page=1") for path in api.calls))

        mutations = (
            lambda logs: logs.__setitem__(803, logs[803] + logs[803].splitlines()[-1] + b"\n"),
            lambda logs: change_refusal(
                logs, b"control-sha=" + CONTROL_SHA.encode("ascii"), b"control-sha=" + b"f" * 40
            ),
            lambda logs: change_refusal(
                logs, b"run-id=" + RUN_ID.encode("ascii"), b"run-id=999"
            ),
            lambda logs: change_refusal(
                logs, b"run-attempt=" + RUN_ATTEMPT.encode("ascii"), b"run-attempt=999"
            ),
            lambda logs: logs.__setitem__(803, logs[803].replace(
                b"repository-id=1428198872", b"repository-id=999999", 1
            )),
            lambda logs: logs.__setitem__(803, logs[803].replace(
                b"reason=bootstrap_snapshot_invalid", b"reason=source_lease_unavailable", 1
            )),
            lambda logs: logs.__setitem__(803, logs[803].replace(
                b"token-revocation=confirmed", b"token-revocation=unconfirmed", 1
            )),
            lambda logs: logs.__setitem__(803, logs[803] + b"macos-rules-network=unexpected\n"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                pages, env, logs = failed_fixture()
                mutate(logs)
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.run(
                        "rules-bootstrap-audit", env, FakeMultiAuditAPI(pages, logs)
                    )
                self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = failed_fixture()
        detail = pages["/repos/keeldock-platform/platform-ci/actions/jobs/803"][0]
        next(step for step in detail["steps"] if step["name"] == "Mint scoped source-reader token").update(
            conclusion="failure"
        )
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run(
                "rules-bootstrap-audit", env, FakeMultiAuditAPI(pages, logs)
            )
        self.assertEqual(caught.exception.reason, "receipt_invalid")

    def test_rules_failed_suite_observation_is_still_bound_after_surface_scan(self):
        pages, env, logs = bootstrap_audit_fixture("rules-bootstrap")
        detail_path = "/repos/keeldock-platform/platform-ci/actions/jobs/803"
        detail = pages[detail_path][0]
        next(step for step in detail["steps"] if step["name"] == "Run fixed rules bootstrap").update(
            conclusion="failure"
        )
        detail["conclusion"] = "failure"
        pages[detail_path] = (detail, {})
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )
        producer_job = next(
            job for job in pages[jobs_path][0]["jobs"]
            if job["name"] == audit.RULES_BOOTSTRAP_PRODUCER_JOB_NAME
        )
        producer_job["conclusion"] = "failure"
        pages["/repos/keeldock-platform/platform-ci/check-runs/903"][0]["conclusion"] = "failure"
        lines = logs[803].splitlines()
        preflight = next(line for line in lines if b"macos-rules-bootstrap=preflight-passed" in line)
        source_binding = next(line for line in lines if b"macos-rules-source-binding=verified" in line)
        network = next(line for line in lines if b"macos-rules-network=" in line)
        refusal = (
            "2026-10-26T12:34:56.1234567Z macos-rules-bootstrap=refused schema=1 "
            "reason=suite_failed stage=rules.hooks control-sha=" + CONTROL_SHA
            + " run-id=" + RUN_ID + " run-attempt=" + RUN_ATTEMPT
            + " token-revocation=confirmed"
        ).encode("ascii")
        logs[803] = preflight + b"\n" + source_binding + b"\n" + network + b"\n" + refusal + b"\n"
        api = FakeMultiAuditAPI(pages, logs)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("rules-bootstrap-audit", env, api)
        self.assertEqual(caught.exception.reason, "native_job_failed")
        self.assertEqual(api.log_calls, [802, 803])

        pages, env, logs = bootstrap_audit_fixture("rules-bootstrap")
        detail_path = "/repos/keeldock-platform/platform-ci/actions/jobs/803"
        detail = pages[detail_path][0]
        next(step for step in detail["steps"] if step["name"] == "Run fixed rules bootstrap").update(
            conclusion="failure"
        )
        detail["conclusion"] = "failure"
        pages[detail_path] = (detail, {})
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )
        producer_job = next(
            job for job in pages[jobs_path][0]["jobs"]
            if job["name"] == audit.RULES_BOOTSTRAP_PRODUCER_JOB_NAME
        )
        producer_job["conclusion"] = "failure"
        pages["/repos/keeldock-platform/platform-ci/check-runs/903"][0]["conclusion"] = "failure"
        lines = logs[803].splitlines()
        network_index = next(i for i, line in enumerate(lines) if b"macos-rules-network=" in line)
        lines[network_index] = lines[network_index].replace(
            b"source-sha=" + b"b" * 40,
            b"source-sha=" + b"f" * 40,
            1,
        )
        logs[803] = b"\n".join(lines) + b"\n"
        api = FakeMultiAuditAPI(pages, logs)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("rules-bootstrap-audit", env, api)
        self.assertEqual(caught.exception.reason, "receipt_invalid")
        self.assertEqual(api.log_calls, [802, 803])

        pages, env, logs = bootstrap_audit_fixture("rules-bootstrap")
        detail_path = "/repos/keeldock-platform/platform-ci/actions/jobs/803"
        detail = pages[detail_path][0]
        next(step for step in detail["steps"] if step["name"] == "Run fixed rules bootstrap").update(
            conclusion="failure"
        )
        detail["conclusion"] = "failure"
        pages[detail_path] = (detail, {})
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )
        producer_job = next(
            job for job in pages[jobs_path][0]["jobs"]
            if job["name"] == audit.RULES_BOOTSTRAP_PRODUCER_JOB_NAME
        )
        producer_job["conclusion"] = "failure"
        pages["/repos/keeldock-platform/platform-ci/check-runs/903"][0]["conclusion"] = "failure"
        logs[803] = b"\n".join(
            line for line in logs[803].splitlines()
            if b"macos-rules-network=" not in line
        ) + b"\n"
        api = FakeMultiAuditAPI(pages, logs)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("rules-bootstrap-audit", env, api)
        self.assertEqual(caught.exception.reason, "receipt_invalid")
        self.assertEqual(api.log_calls, [802, 803])


class CacheProofAuditTests(unittest.TestCase):
    def test_cache_probe_log_scanner_only_allows_fixed_client_markers(self):
        allowed = (
            b"macos-cache-client=read-denied schema=1\n"
            b"macos-cache-client=write-denied schema=1\n"
        )
        audit.inspect_cache_probe_public_bytes(allowed, CONTROL_SHA)

        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_cache_probe_public_bytes(
                b"::warning::unrelated cache read denied: notice\n", CONTROL_SHA
            )
        self.assertEqual(caught.exception.reason, "workflow_command_exposed")

        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_cache_probe_public_bytes(
                b"Cache restore skipped because cache access is unavailable\n", CONTROL_SHA
            )
        self.assertEqual(caught.exception.reason, "workflow_command_exposed")

        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_cache_probe_public_bytes(
                b"cache read denied: scope none\n", CONTROL_SHA
            )
        self.assertEqual(caught.exception.reason, "workflow_command_exposed")

        canary = audit.derive_reviewed_canary(CONTROL_SHA)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.inspect_cache_probe_public_bytes(
                b"macos-cache-client=read-denied schema=1 " + canary + b"\n", CONTROL_SHA
            )
        self.assertEqual(caught.exception.reason, "canary_exposed")

    def test_cache_proof_snapshot_requires_empty_fixture_scope_and_writes_inventory_baseline(self):
        pages, env, _, _ = cache_proof_audit_fixture()
        cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        pages[cache_path] = ({"total_count": 0, "actions_caches": []}, {})
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "github-output"
            output_path.write_text("", encoding="ascii")
            env["GITHUB_OUTPUT"] = str(output_path)
            with contextlib.redirect_stdout(io.StringIO()):
                result = audit.run("cache-proof-snapshot", env, FakeAPI(pages))
            self.assertEqual(result, 0)
            self.assertEqual(
                output_path.read_text(encoding="ascii"),
                "cache_snapshot=" + audit.cache_inventory_digest([]) + "\n",
            )

        pages, env, _, cache_items = cache_proof_audit_fixture()
        pages[cache_path] = ({"total_count": 1, "actions_caches": cache_items}, {})
        with tempfile.TemporaryDirectory() as temporary:
            env["GITHUB_OUTPUT"] = str(Path(temporary) / "github-output")
            with self.assertRaises(audit.AuditRefusal) as caught:
                audit.run("cache-proof-snapshot", env, FakeAPI(pages))
        self.assertEqual(caught.exception.reason, "inventory_changed")

    def test_cache_proof_requires_seed_hit_and_both_explicit_service_denials(self):
        pages, env, logs, _ = cache_proof_audit_fixture()
        api = FakeMultiAuditAPI(pages, logs)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = audit.run("cache-proof-audit", env, api)
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "macos-cache-proof=seeded-positive-and-none-denials-audited\n")
        self.assertEqual(api.log_calls, [402, 403, 404, 405])
        self.assertIn(
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/artifacts?per_page=100&page=1",
            api.calls,
        )
        self.assertIn(
            "/repos/keeldock-platform/platform-ci/check-runs/505/annotations?per_page=100&page=1",
            api.calls,
        )

        pages, env, logs, _ = cache_proof_audit_fixture()
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )
        pages[jobs_path][0]["jobs"] = [
            item for item in pages[jobs_path][0]["jobs"]
            if item["name"] != audit.CACHE_PROOF_CLEANUP_JOB_NAME
        ]
        pages[jobs_path][0]["total_count"] = 5
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.run("cache-proof-audit", env, FakeMultiAuditAPI(pages, logs)), 0)

        cases = (
            ("positive miss", lambda logs, pages: logs.__setitem__(404, logs[404].replace(
                b"Cache restored from key:", b"Cache not found for input keys:")), "receipt_invalid"),
            ("read denial missing", lambda logs, pages: logs.__setitem__(405, logs[405].replace(
                b"macos-cache-client=read-denied", b"macos-cache-client=read-missed")), "receipt_invalid"),
            ("write denial missing", lambda logs, pages: logs.__setitem__(405, logs[405].replace(
                b"macos-cache-client=write-denied", b"macos-cache-client=write-missed")), "receipt_invalid"),
            ("wrong action pin", lambda logs, pages: logs.__setitem__(405, logs[405].replace(
                audit.CACHE_PROOF_ACTION_SHA.encode("ascii"), b"0" * 40, 1)), "receipt_invalid"),
            ("wrong run identity", lambda logs, pages: logs.__setitem__(405, logs[405].replace(
                b"run-attempt=" + RUN_ATTEMPT.encode("ascii"), b"run-attempt=9", 1)), "receipt_invalid"),
            ("node outside action runtime", lambda logs, pages: logs.__setitem__(405, logs[405].replace(
                b"node=24.0.0", b"node=22.0.0", 1)), "receipt_invalid"),
            ("read unexpectedly succeeded", lambda logs, pages: logs.__setitem__(405, logs[405] +
                b"Cache restored from key: " + cache_proof_keys()[0].encode("ascii")), "workflow_command_exposed"),
        )
        for label, mutate, reason in cases:
            with self.subTest(case=label):
                pages, env, logs, _ = cache_proof_audit_fixture()
                mutate(logs, pages)
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.run("cache-proof-audit", env, FakeMultiAuditAPI(pages, logs))
                self.assertEqual(caught.exception.reason, reason)

    def test_cache_proof_requires_known_seed_metadata_and_no_write_entry(self):
        pages, env, logs, cache_items = cache_proof_audit_fixture()
        pages[
            "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        ] = ({"total_count": 0, "actions_caches": []}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("cache-proof-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "inventory_changed")

        pages, env, logs, cache_items = cache_proof_audit_fixture()
        _, write_key = cache_proof_keys()
        write_cache = dict(cache_items[0], id=902, key=write_key)
        pages[
            "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        ] = ({"total_count": 2, "actions_caches": cache_items + [write_cache]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("cache-proof-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "inventory_changed")

        pages, env, logs, cache_items = cache_proof_audit_fixture()
        cache_items[0]["ref"] = "refs/heads/another-branch"
        pages[
            "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        ] = ({"total_count": 1, "actions_caches": cache_items}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("cache-proof-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "inventory_changed")

    def test_cache_proof_cleanup_deletes_only_the_run_attempt_fixture_keys(self):
        pages, env, _, cache_items = cache_proof_audit_fixture()
        _, write_key = cache_proof_keys()
        write_cache = dict(cache_items[0], id=902, key=write_key)
        unrelated_cache = dict(
            cache_items[0],
            id=903,
            key="unrelated-public-cache-v1",
        )
        api = FakeCleanupAPI(pages, cache_items + [write_cache, unrelated_cache])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = audit.run("cache-proof-cleanup", env, api)
        self.assertEqual(result, 0)
        self.assertEqual(sorted(api.deleted_cache_ids), [901, 902])
        self.assertEqual([item["key"] for item in api.cache_items], ["unrelated-public-cache-v1"])
        self.assertEqual(
            output.getvalue(),
            "macos-cache-cleanup=complete schema=1 run-id=" + RUN_ID
            + " run-attempt=" + RUN_ATTEMPT + "\n",
        )

        pages, env, _, cache_items = cache_proof_audit_fixture()
        other_ref_entry = dict(cache_items[0], id=904, ref="refs/heads/other")
        api = FakeCleanupAPI(pages, cache_items + [other_ref_entry])
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("cache-proof-cleanup", env, api)
        self.assertEqual(caught.exception.reason, "inventory_changed")
        self.assertEqual(api.deleted_cache_ids, [])


class AuditRunTests(unittest.TestCase):
    def test_audit_passes_only_after_all_surfaces_and_receipt(self):
        pages, env, _, _ = audit_fixture()
        api = FakeAuditAPI(pages)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = audit.run("audit", env, api)
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "macos-public-surface-audit=passed\n")
        self.assertEqual(api.log_calls, [202])
        self.assertIn(
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID + "/artifacts?per_page=100&page=1",
            api.calls,
        )
        self.assertIn(
            "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1",
            api.calls,
        )

    def test_native_failure_still_scans_logs_and_all_public_surfaces(self):
        pages, env, native_job, native_detail = audit_fixture()
        native_job["conclusion"] = "failure"
        native_detail["conclusion"] = "failure"
        native_detail["steps"][0]["conclusion"] = "failure"
        pages["/repos/keeldock-platform/platform-ci/check-runs/303"][0]["conclusion"] = "failure"
        api = FakeAuditAPI(pages)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("audit", env, api)
        self.assertEqual(caught.exception.reason, "native_job_failed")
        self.assertEqual(api.log_calls, [202])
        self.assertTrue(any(path.endswith("/annotations?per_page=100&page=1") for path in api.calls))
        self.assertTrue(any(path.endswith("/artifacts?per_page=100&page=1") for path in api.calls))
        self.assertTrue(any(path.endswith("/actions/caches?per_page=100&page=1") for path in api.calls))
        self.assertEqual(output.getvalue(), "")

    def test_canary_exposure_refuses_before_any_success_output(self):
        pages, env, _, _ = audit_fixture()
        api = FakeAuditAPI(pages, b"captured=" + audit.derive_canary(CONTROL_SHA))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("audit", env, api)
        self.assertEqual(caught.exception.reason, "canary_exposed")
        self.assertEqual(output.getvalue(), "")

    def test_missing_snapshot_and_receipt_refuse(self):
        pages, env, _, _ = audit_fixture()
        env["MACOS_CACHE_SNAPSHOT"] = ""
        api = FakeAuditAPI(pages)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("audit", env, api)
        self.assertEqual(caught.exception.reason, "inventory_changed")

        pages, env, _, _ = audit_fixture()
        env["MACOS_NATIVE_RECEIPT_B64URL"] = ""
        api = FakeAuditAPI(pages)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("audit", env, api)
        self.assertEqual(caught.exception.reason, "receipt_invalid")

    def test_wrong_run_attempt_sha_and_duplicate_native_job_refuse(self):
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )

        def change_native(field, value):
            def mutate(pages):
                pages[jobs_path][0]["jobs"][0][field] = value
            return mutate

        def duplicate_native(pages):
            body = pages[jobs_path][0]
            body["jobs"].append(dict(body["jobs"][0], id=205))
            body["total_count"] += 1

        mutations = (
            ("run-sha", lambda pages: pages["/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID][0].update(head_sha="f" * 40), "run_identity_mismatch"),
            ("native-run", change_native("run_id", int(RUN_ID) + 1), "run_identity_mismatch"),
            ("native-attempt", change_native("run_attempt", 3), "run_identity_mismatch"),
            ("native-sha", change_native("head_sha", "f" * 40), "run_identity_mismatch"),
            ("duplicate", duplicate_native, "api_schema"),
        )
        for name, mutate, reason in mutations:
            with self.subTest(case=name):
                pages, env, _, _ = audit_fixture()
                mutate(pages)
                api = FakeAuditAPI(pages)
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.run("audit", env, api)
                self.assertEqual(caught.exception.reason, reason)

    def test_artifact_or_changed_cache_prevents_success(self):
        pages, env, _, _ = audit_fixture()
        artifact_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID + "/artifacts?per_page=100&page=1"
        pages[artifact_path] = ({"total_count": 1, "artifacts": [{
            "id": 707,
            "name": "unexpected",
            "size_in_bytes": 1,
            "expired": False,
        }]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("audit", env, FakeAuditAPI(pages))
        self.assertEqual(caught.exception.reason, "artifact_found")

        pages, env, _, _ = audit_fixture()
        cache_path = "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        pages[cache_path] = ({"total_count": 1, "actions_caches": [{
            "id": 808,
            "ref": "refs/heads/main",
            "key": "new-entry",
            "version": "v1",
            "last_accessed_at": None,
            "created_at": "2026-10-25T00:00:00Z",
            "size_in_bytes": 1,
        }]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("audit", env, FakeAuditAPI(pages))
        self.assertEqual(caught.exception.reason, "inventory_changed")

    def test_reviewed_audit_requires_both_producers_and_audits_each_named_surface(self):
        pages, env, logs = reviewed_audit_fixture()
        api = FakeMultiAuditAPI(pages, logs)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = audit.run("reviewed-audit", env, api)
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "macos-public-surface-audit=synthetic-smoke-audited\n")
        self.assertEqual(api.log_calls, [202, 203])
        self.assertIn(
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/artifacts?per_page=100&page=1",
            api.calls,
        )
        self.assertIn(
            "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1",
            api.calls,
        )
        self.assertIn(
            "/repos/keeldock-platform/platform-ci/check-runs/303/annotations?per_page=100&page=1",
            api.calls,
        )
        self.assertIn(
            "/repos/keeldock-platform/platform-ci/check-runs/305/annotations?per_page=100&page=1",
            api.calls,
        )

    def test_reviewed_audit_requires_exact_observer_step_topology(self):
        for mutation in (
            lambda steps: steps.pop(next(
                index for index, step in enumerate(steps)
                if step["name"] == "Prove source-free network observer"
            )),
            lambda steps: next(
                step for step in steps
                if step["name"] == "Prove source-free network observer"
            ).update(name="Other observer"),
        ):
            pages, env, logs = reviewed_audit_fixture()
            steps = pages["/repos/keeldock-platform/platform-ci/actions/jobs/203"][0]["steps"]
            mutation(steps)
            with self.assertRaises(audit.AuditRefusal) as caught:
                audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
            self.assertEqual(caught.exception.reason, "api_schema")

    def test_reviewed_audit_requires_exact_run_bound_network_selftest(self):
        pages, env, logs = reviewed_audit_fixture()
        marker = next(
            line for line in logs[203].splitlines()
            if b"macos-network-observer=" in line
        )
        mutations = (
            b"",
            marker.replace(CONTROL_SHA.encode("ascii"), b"f" * 40),
            marker.replace(b"run-id=" + RUN_ID.encode("ascii"), b"run-id=1"),
            marker.replace(
                b"run-attempt=" + RUN_ATTEMPT.encode("ascii"), b"run-attempt=1"
            ),
            marker.replace(b"source-sha=none", b"source-sha=" + b"b" * 40),
            marker.replace(b"interface-count=1", b"interface-count=0"),
            marker.replace(b"dns-query-count=1", b"dns-query-count=0"),
            marker.replace(b"tcp-syn-count=1", b"tcp-syn-count=65536"),
            marker.replace(b"hashes-truncated=false", b"hashes-truncated=unknown"),
            marker.replace(b"capture=private", b"capture=public"),
            marker.replace(b"capture-limited=false", b"capture-limited=true"),
            marker.replace(b"cleanup=complete", b"cleanup=incomplete"),
            marker.replace(b"worker-attribution=not-claimed", b"worker-attribution=claimed"),
            marker.replace(b"completeness=not-claimed", b"completeness=complete"),
            marker.replace(b"network-blocking=not-claimed", b"network-blocking=blocked"),
            marker.replace(
                b"dns-name-hashes=" + b"1" * 64,
                b"dns-name-hashes=" + b"2" * 64 + b"," + b"1" * 64,
            ),
            marker.replace(
                b"tcp-destination-hashes=" + b"2" * 64,
                b"tcp-destination-hashes=" + b",".join([b"2" * 64] * 2),
            ),
            b"untrusted-prefix " + marker,
        )
        for index, replacement in enumerate(mutations):
            with self.subTest(mutation=index):
                pages, env, logs = reviewed_audit_fixture()
                logs[203] = logs[203].replace(marker, replacement)
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
                self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        logs[203] += marker + b"\n"
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        many_hashes = b",".join([b"3" * 64] * 17)
        logs[203] = logs[203].replace(b"1" * 64, many_hashes, 1)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

    def test_reviewed_audit_requires_exact_summary_control_identity(self):
        control = (
            b"macos-summary-control=trusted-write schema=1 control-sha="
            + CONTROL_SHA.encode("ascii")
            + b" run-id=" + RUN_ID.encode("ascii")
            + b" run-attempt=" + RUN_ATTEMPT.encode("ascii") + b"\n"
        )
        for replacement in (
            b"",
            control.replace(CONTROL_SHA.encode("ascii"), b"f" * 40),
            control.replace(b"run-id=" + RUN_ID.encode("ascii"), b"run-id=1"),
            control.replace(b"run-attempt=" + RUN_ATTEMPT.encode("ascii"), b"run-attempt=1"),
            b"prefixed " + control,
            control[:-1] + b" extra\n",
            control + control,
        ):
            with self.subTest(replacement=replacement):
                pages, env, logs = reviewed_audit_fixture()
                self.assertIn(control, logs[203])
                logs[203] = logs[203].replace(control, replacement)
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
                self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        pages["/repos/keeldock-platform/platform-ci/actions/jobs/203"][0]["steps"].pop()
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "api_schema")

    def test_reviewed_audit_accepts_selected_xcode_toolchain_origin(self):
        pages, env, logs = reviewed_audit_fixture()
        logs[203] = logs[203].replace(
            b"xcode=not-used xcode-build=not-used compiler-origin=command-line-tools",
            b"xcode=26.0 xcode-build=17A324 compiler-origin=xcode",
        )
        with contextlib.redirect_stdout(io.StringIO()):
            result = audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(result, 0)

    def test_reviewed_audit_refuses_missing_cache_annotation_or_job_evidence(self):
        pages, env, logs = reviewed_audit_fixture()
        env["MACOS_CACHE_SNAPSHOT"] = ""
        api = FakeMultiAuditAPI(pages, logs)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, api)
        self.assertEqual(caught.exception.reason, "inventory_changed")
        self.assertEqual(api.log_calls, [202, 203])

        pages, env, logs = reviewed_audit_fixture()
        pages[
            "/repos/keeldock-platform/platform-ci/check-runs/305/annotations?per_page=100&page=1"
        ] = ([], {})
        pages["/repos/keeldock-platform/platform-ci/check-runs/305"][0]["output"]["annotations_count"] = 1
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "pagination_incomplete")

        pages, env, logs = reviewed_audit_fixture()
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )
        pages[jobs_path][0]["jobs"].pop(1)
        pages[jobs_path][0]["total_count"] = 2
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "api_schema")

        pages, env, logs = reviewed_audit_fixture()
        logs.pop(203)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "log_unavailable")

    def test_reviewed_audit_refuses_marker_identity_cache_artifact_and_job_failures(self):
        pages, env, logs = reviewed_audit_fixture()
        logs[203] = logs[203].replace(CONTROL_SHA.encode("ascii"), b"f" * 40)
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        logs[203] = logs[203].replace(b" real-summary=write-denied", b"")
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        logs[203] = logs[203].replace(b"image-os=macos-15-arm64", b"image-os=macos-latest")
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        logs[203] = logs[203].replace(
            b"compiler-origin=command-line-tools",
            b"compiler-origin=unknown",
        )
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        logs[203] = logs[203].replace(
            b"xcode=not-used xcode-build=not-used compiler-origin=command-line-tools",
            b"xcode=26.0 xcode-build=17A324 compiler-origin=command-line-tools",
        )
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        logs[203] = logs[203].replace(
            b"xcode=not-used xcode-build=not-used compiler-origin=command-line-tools",
            b"xcode=not-used xcode-build=not-used compiler-origin=xcode",
        )
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        logs[203] += b"macos-build=unexpected\n"
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "receipt_invalid")

        pages, env, logs = reviewed_audit_fixture()
        pages[
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/artifacts?per_page=100&page=1"
        ] = ({"total_count": 1, "artifacts": [{
            "id": 707,
            "name": "unexpected",
            "size_in_bytes": 1,
            "expired": False,
        }]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "artifact_found")

        pages, env, logs = reviewed_audit_fixture()
        pages[
            "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        ] = ({"total_count": 1, "actions_caches": [{
            "id": 808,
            "ref": "refs/heads/main",
            "key": "changed-entry",
            "version": "v1",
            "last_accessed_at": None,
            "created_at": "2026-10-25T00:00:00Z",
            "size_in_bytes": 1,
        }]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "inventory_changed")

        pages, env, logs = reviewed_audit_fixture()
        jobs_path = (
            "/repos/keeldock-platform/platform-ci/actions/runs/" + RUN_ID
            + "/attempts/" + RUN_ATTEMPT + "/jobs?per_page=100&page=1"
        )
        pages[jobs_path][0]["jobs"][1]["conclusion"] = "failure"
        pages["/repos/keeldock-platform/platform-ci/actions/jobs/203"][0]["conclusion"] = "failure"
        pages["/repos/keeldock-platform/platform-ci/check-runs/305"][0]["conclusion"] = "failure"
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "native_job_failed")

    def test_reviewed_audit_scans_runtime_canary_in_logs_check_outputs_annotations_and_caches(self):
        canary = audit.derive_reviewed_canary(CONTROL_SHA)

        pages, env, logs = reviewed_audit_fixture()
        logs[203] += b"\n" + canary
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "canary_exposed")

        pages, env, logs = reviewed_audit_fixture()
        pages["/repos/keeldock-platform/platform-ci/check-runs/305"][0]["output"]["summary"] = canary.decode("ascii")
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "canary_exposed")

        pages, env, logs = reviewed_audit_fixture()
        pages["/repos/keeldock-platform/platform-ci/check-runs/305"][0]["output"]["annotations_count"] = 1
        pages[
            "/repos/keeldock-platform/platform-ci/check-runs/305/annotations?per_page=100&page=1"
        ] = ([{"id": 1, "message": canary.decode("ascii")}], {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "canary_exposed")

        pages, env, logs = reviewed_audit_fixture()
        cache = {
            "id": 808,
            "ref": "refs/heads/main",
            "key": "synthetic-" + canary.decode("ascii"),
            "version": "v1",
            "last_accessed_at": None,
            "created_at": "2026-10-25T00:00:00Z",
            "size_in_bytes": 1,
        }
        env["MACOS_CACHE_SNAPSHOT"] = audit.cache_inventory_digest([cache])
        pages[
            "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        ] = ({"total_count": 1, "actions_caches": [cache]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "canary_exposed")

    def test_reviewed_audit_scans_static_summary_canary_in_logs_checks_annotations_and_caches(self):
        canary = audit.REVIEWED_SUMMARY_DIRECT_CANARY

        pages, env, logs = reviewed_audit_fixture()
        logs[203] += b"\n" + canary
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "canary_exposed")

        pages, env, logs = reviewed_audit_fixture()
        pages["/repos/keeldock-platform/platform-ci/check-runs/305"][0]["output"]["summary"] = canary.decode("ascii")
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "canary_exposed")

        pages, env, logs = reviewed_audit_fixture()
        pages["/repos/keeldock-platform/platform-ci/check-runs/305"][0]["output"]["annotations_count"] = 1
        pages[
            "/repos/keeldock-platform/platform-ci/check-runs/305/annotations?per_page=100&page=1"
        ] = ([{"id": 1, "message": canary.decode("ascii")}], {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "canary_exposed")

        pages, env, logs = reviewed_audit_fixture()
        cache = {
            "id": 808,
            "ref": "refs/heads/main",
            "key": "synthetic-" + canary.decode("ascii"),
            "version": "v1",
            "last_accessed_at": None,
            "created_at": "2026-10-25T00:00:00Z",
            "size_in_bytes": 1,
        }
        env["MACOS_CACHE_SNAPSHOT"] = audit.cache_inventory_digest([cache])
        pages[
            "/repos/keeldock-platform/platform-ci/actions/caches?per_page=100&page=1"
        ] = ({"total_count": 1, "actions_caches": [cache]}, {})
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.run("reviewed-audit", env, FakeMultiAuditAPI(pages, logs))
        self.assertEqual(caught.exception.reason, "canary_exposed")

    def test_api_403_is_a_fixed_refusal_without_response_text(self):
        class DeniedOpener:
            def open(self, request, timeout):
                raise urllib.error.HTTPError(
                    request.full_url, 403, "forbidden-token-value", email.message.Message(), io.BytesIO(b"")
                )

        api = audit.GitHubAPI.__new__(audit.GitHubAPI)
        api._token = "t" * 32
        api._total_json_bytes = 0
        api._opener = DeniedOpener()
        with self.assertRaises(audit.AuditRefusal) as caught:
            api.json("/repos/keeldock-platform/platform-ci/actions/caches")
        self.assertEqual(caught.exception.reason, "api_status")
        self.assertEqual(caught.exception.args, ())

    def test_unknown_log_redirect_fails_with_fixed_reason(self):
        class UnknownRedirect:
            def open(self, request, timeout):
                headers = email.message.Message()
                headers["Location"] = "https://attacker.invalid/log?token=untrusted-value"
                raise urllib.error.HTTPError(
                    request.full_url, 302, "Found", headers, io.BytesIO(b"")
                )

        api = audit.GitHubAPI.__new__(audit.GitHubAPI)
        api._token = "t" * 32
        api._opener = UnknownRedirect()
        with self.assertRaises(audit.AuditRefusal) as caught:
            api.log_text(99)
        self.assertEqual(caught.exception.reason, "log_unavailable")
        self.assertEqual(caught.exception.args, ())

    def test_cli_403_emits_only_fixed_reason(self):
        pages, env, _, _ = audit_fixture()

        class DeniedAPI:
            def json(self, path):
                raise audit.AuditRefusal("api_status")

        output = io.StringIO()
        with mock.patch.dict("os.environ", env, clear=True):
            with mock.patch.object(audit, "GitHubAPI", return_value=DeniedAPI()):
                with contextlib.redirect_stdout(output):
                    result = audit.main(["audit"])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), "macos-public-surface-audit=refused reason=api_status\n")


if __name__ == "__main__":
    unittest.main()
