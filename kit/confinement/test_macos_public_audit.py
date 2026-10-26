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
            "name": "Validate source-free control tree",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "number": 2,
            "name": "Run source-free reviewed build smoke",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "number": 3,
            "name": "Write trusted summary visibility control",
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
        203: marker + summary_control,
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
