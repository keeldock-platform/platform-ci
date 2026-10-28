import hashlib
import unittest
from pathlib import Path

from api_budget import BudgetError, check_api_budget, load_budget_document
from kit_revocation import RevocationError, check_kit_not_revoked, parse_revocations
from public_tree import PINNED_FILE_SHA256


ROOT = Path(__file__).resolve().parents[2]
GOOD_SHA = "a" * 40


def budget_document(per_run=4, per_workflow=6, per_hour=10):
    return {
        "schema_version": 1,
        "window_seconds": 3600,
        "watcher": {"maximum_per_run": 1, "minimum_interval_seconds": 300},
        "credentials": {
            scope: {"per_run": per_run, "per_workflow": per_workflow, "per_hour": per_hour}
            for scope in (
                "repository_token", "source_reader", "settings_auditor", "source_auditor", "pin_writer"
            )
        },
    }


def request(request_id, run_id=10, workflow="public-policy", timestamp=1000,
            status_code=200, remaining=9, reset=3600, scope="repository_token",
            credential_id="repository-token"):
    return {
        "request_id": request_id,
        "run_id": run_id,
        "workflow": workflow,
        "credential_scope": scope,
        "credential_id": credential_id,
        "timestamp": timestamp,
        "status_code": status_code,
        "rate_limit": {"resource": "core", "limit": 10, "remaining": remaining, "reset": reset},
    }


def ledger(requests, watchers=None):
    run_ids = sorted({item["run_id"] for item in requests})
    return {
        "schema_version": 1,
        "complete": True,
        "repository": "fixture-owner/fixture-repo",
        "round_id": "round-1",
        "watchers": watchers if watchers is not None else [
            {"run_id": run_id, "interval_seconds": 300} for run_id in run_ids
        ],
        "requests": requests,
    }


class BudgetDocumentTests(unittest.TestCase):
    def test_checked_in_budget_data_is_strict_and_complete(self):
        value = load_budget_document(ROOT / "ci/api-budgets.json")
        self.assertEqual(value["window_seconds"], 3600)
        self.assertEqual(set(value["credentials"]), {
            "repository_token", "source_reader", "settings_auditor", "source_auditor", "pin_writer"
        })

    def test_missing_scope_invalid_watcher_or_boolean_limit_refuses(self):
        value = budget_document()
        del value["credentials"]["pin_writer"]
        with self.assertRaises(BudgetError):
            check_api_budget(ledger([]), value)
        value = budget_document()
        value["watcher"]["maximum_per_run"] = 2
        with self.assertRaises(BudgetError):
            check_api_budget(ledger([]), value)
        value = budget_document()
        value["credentials"]["repository_token"]["per_run"] = True
        with self.assertRaises(BudgetError):
            check_api_budget(ledger([]), value)


class RequestLedgerTests(unittest.TestCase):
    def test_counts_requests_by_run_workflow_and_rate_window(self):
        value = ledger([
            request("r1", remaining=9),
            request("r2", timestamp=1001, remaining=8),
            request("r3", run_id=11, timestamp=1002, remaining=7),
        ])
        report = check_api_budget(value, budget_document())
        self.assertEqual(report["requests"], 3)
        self.assertEqual(report["runs"], 2)
        self.assertEqual(report["workflows"], 1)
        self.assertEqual(report["resume_at"], ())

    def test_run_with_no_requests_can_still_have_one_watcher(self):
        value = ledger([], watchers=[{"run_id": 10, "interval_seconds": 300}])
        report = check_api_budget(value, budget_document())
        self.assertEqual(report["requests"], 0)
        self.assertEqual(report["runs"], 0)

    def test_run_workflow_and_hour_caps_refuse(self):
        cases = (
            (ledger([request("r1"), request("r2", timestamp=1001),
                     request("r3", timestamp=1002), request("r4", timestamp=1003),
                     request("r5", timestamp=1004)]), budget_document(per_run=4)),
            (ledger([request("r1"), request("r2", timestamp=1001),
                     request("r3", timestamp=1002), request("r4", timestamp=1003),
                     request("r5", timestamp=1004), request("r6", timestamp=1005),
                     request("r7", timestamp=1006)]), budget_document(per_workflow=6)),
            (ledger([request("r1"), request("r2", timestamp=1001),
                     request("r3", timestamp=1002)]), budget_document(per_hour=2)),
        )
        for value, budgets in cases:
            with self.subTest(requests=len(value["requests"])):
                with self.assertRaises(BudgetError):
                    check_api_budget(value, budgets)

    def test_missing_headers_duplicate_ids_or_an_unwatched_run_refuse(self):
        value = ledger([request("r1")])
        del value["requests"][0]["rate_limit"]
        with self.assertRaises(BudgetError):
            check_api_budget(value, budget_document())
        value = ledger([request("r1")])
        value["complete"] = False
        with self.assertRaises(BudgetError):
            check_api_budget(value, budget_document())
        value = ledger([request("r1"), request("r1", timestamp=1001)])
        with self.assertRaises(BudgetError):
            check_api_budget(value, budget_document())
        value = ledger([request("r1")], watchers=[])
        with self.assertRaises(BudgetError):
            check_api_budget(value, budget_document())

    def test_forbidden_response_stops_until_reset_and_rejects_early_resume(self):
        refused = ledger([
            request("r1", status_code=403, remaining=0, reset=1500),
            request("r2", timestamp=1499, remaining=0, reset=1500),
        ])
        with self.assertRaisesRegex(BudgetError, "request-before-reset"):
            check_api_budget(refused, budget_document())
        accepted = ledger([request("r1", status_code=403, remaining=0, reset=1500)])
        report = check_api_budget(accepted, budget_document())
        self.assertEqual(report["resume_at"], (1500,))


class RevocationListTests(unittest.TestCase):
    def test_checked_in_empty_list_is_content_pinned_and_current_sha_is_allowed(self):
        self.assertEqual(
            PINNED_FILE_SHA256["ci/revoked-kit-versions"],
            hashlib.sha256(b"").hexdigest(),
        )
        self.assertTrue(check_kit_not_revoked(ROOT, GOOD_SHA))

    def test_strict_pinned_parser_reads_versions_and_shas(self):
        payload = (
            b"kit-revocations-v1\n"
            b"sha\t" + b"b" * 40 + b"\n"
            b"version\tv1.2.3\n"
        )
        result = parse_revocations(payload, hashlib.sha256(payload).hexdigest())
        self.assertIn("b" * 40, result["shas"])
        self.assertIn("v1.2.3", result["versions"])
        for invalid in (
            b"kit-revocations-v1\r\n",
            b"kit-revocations-v1\nsha\tABC\n",
            b"kit-revocations-v1\nsha\t" + b"b" * 40,
            b"kit-revocations-v1\nversion\tv1.2.3\nversion\tv1.2.3\n",
        ):
            with self.subTest(payload=invalid):
                with self.assertRaises(RevocationError):
                    parse_revocations(invalid, hashlib.sha256(invalid).hexdigest())

    def test_pin_mismatch_and_revoked_identity_refuse(self):
        payload = b"kit-revocations-v1\nsha\t" + b"b" * 40 + b"\n"
        with self.assertRaisesRegex(RevocationError, "revocation-pin-mismatch"):
            parse_revocations(payload, "0" * 64)
        with self.assertRaisesRegex(RevocationError, "kit-revoked"):
            from tempfile import TemporaryDirectory
            from pathlib import Path
            import kit_revocation
            import public_tree

            with TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "ci").mkdir()
                (root / "ci/revoked-kit-versions").write_bytes(payload)
                original = public_tree.PINNED_FILE_SHA256["ci/revoked-kit-versions"]
                public_tree.PINNED_FILE_SHA256["ci/revoked-kit-versions"] = hashlib.sha256(payload).hexdigest()
                try:
                    kit_revocation.check_kit_not_revoked(root, "b" * 40)
                finally:
                    public_tree.PINNED_FILE_SHA256["ci/revoked-kit-versions"] = original
        version_payload = b"kit-revocations-v1\nversion\tv1.2.3\n"
        with self.assertRaisesRegex(RevocationError, "kit-revoked"):
            import kit_revocation
            import public_tree

            with TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "ci").mkdir()
                (root / "ci/revoked-kit-versions").write_bytes(version_payload)
                original = public_tree.PINNED_FILE_SHA256["ci/revoked-kit-versions"]
                public_tree.PINNED_FILE_SHA256["ci/revoked-kit-versions"] = hashlib.sha256(version_payload).hexdigest()
                try:
                    kit_revocation.check_kit_not_revoked(root, "c" * 40, "v1.2.3")
                finally:
                    public_tree.PINNED_FILE_SHA256["ci/revoked-kit-versions"] = original


if __name__ == "__main__":
    unittest.main()
