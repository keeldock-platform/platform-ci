import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from api_budget import (
    MAX_BUDGET_BYTES,
    MAX_LEDGER_BYTES,
    BudgetError,
    check_api_budget,
    check_api_budget_files,
    load_budget_document,
    main,
)


ROOT = Path(__file__).resolve().parents[2]


def budget_document():
    return {
        "schema_version": 1,
        "window_seconds": 3600,
        "watcher": {"maximum_per_run": 1, "minimum_interval_seconds": 300},
        "credentials": {
            scope: {
                "per_run": None,
                "per_workflow": None,
                "per_hour": 1000 if scope == "repository_token" else None,
            }
            for scope in (
                "repository_token", "source_reader", "settings_auditor", "source_auditor", "pin_writer"
            )
        },
    }


def request(request_id, run_id=10, workflow="public-policy", timestamp=1000,
            status_code=200, remaining=9, reset=3600, scope="repository_token",
            credential_id="repository-token", installation_id=None):
    return {
        "request_id": request_id,
        "run_id": run_id,
        "workflow": workflow,
        "credential_scope": scope,
        "credential_id": credential_id,
        "installation_id": installation_id,
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


def hourly_requests():
    requests = []
    for index in range(1001):
        entry = request(
            "r%d" % index,
            run_id=10 + index // 100,
            workflow="workflow-%d" % (index // 100),
            timestamp=1000 + index,
            credential_id="token-a" if index % 2 else "token-b",
        )
        entry["rate_limit"]["limit"] = 5000
        entry["rate_limit"]["remaining"] = 5000 - index
        requests.append(entry)
    return requests


class BudgetDocumentTests(unittest.TestCase):
    def test_checked_in_budget_data_is_strict_and_complete(self):
        value = load_budget_document(ROOT / "ci/api-budgets.json")
        self.assertEqual(value["window_seconds"], 3600)
        self.assertEqual(set(value["credentials"]), {
            "repository_token", "source_reader", "settings_auditor", "source_auditor", "pin_writer"
        })
        for scope, limits in value["credentials"].items():
            self.assertIsNone(limits["per_run"])
            self.assertIsNone(limits["per_workflow"])
            self.assertEqual(limits["per_hour"], 1000 if scope == "repository_token" else None)

    def test_missing_scope_invalid_watcher_or_set_unplanned_limit_refuses(self):
        value = budget_document()
        del value["credentials"]["pin_writer"]
        with self.assertRaises(BudgetError):
            check_api_budget(ledger([]), value)
        value = budget_document()
        value["watcher"]["maximum_per_run"] = 2
        with self.assertRaises(BudgetError):
            check_api_budget(ledger([]), value)
        value = budget_document()
        value["credentials"]["repository_token"]["per_run"] = 1
        with self.assertRaisesRegex(BudgetError, "limit-unset-required"):
            check_api_budget(ledger([]), value)
        value = budget_document()
        value["credentials"]["source_reader"]["per_hour"] = 1
        with self.assertRaisesRegex(BudgetError, "app-limit-unset-required"):
            check_api_budget(ledger([]), value)
        value = budget_document()
        value["credentials"]["repository_token"]["per_hour"] = True
        with self.assertRaisesRegex(BudgetError, "repository-token-limit"):
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
        self.assertEqual(report["requests_per_run"], {10: 2, 11: 1})
        self.assertEqual(report["requests_per_workflow"], {"public-policy": 3})
        self.assertEqual(report["resume_at"], ())

    def test_run_with_no_requests_can_still_have_one_watcher(self):
        value = ledger([], watchers=[{"run_id": 10, "interval_seconds": 300}])
        report = check_api_budget(value, budget_document())
        self.assertEqual(report["requests"], 0)
        self.assertEqual(report["runs"], 0)

    def test_shadow_collects_watcher_and_header_violations_with_counts(self):
        value = ledger([
            request("r1", remaining=9),
            request("r2", timestamp=1001, remaining=10),
        ], watchers=[{"run_id": 10, "interval_seconds": 250}])
        report = check_api_budget(value, budget_document(), shadow=True)
        self.assertEqual(report["requests"], 2)
        self.assertEqual(report["violations"], ("rate-limit-increased", "watcher-interval"))

    def test_repository_hour_cap_aggregates_token_ids_across_runs_and_workflows(self):
        requests = hourly_requests()
        self.assertEqual(check_api_budget(ledger(requests[:1000]), budget_document())["requests"], 1000)
        with self.assertRaisesRegex(BudgetError, "hour-budget-exceeded"):
            check_api_budget(ledger(requests), budget_document())

    def test_unset_app_caps_do_not_reject_and_installation_is_required(self):
        value = ledger([
            request("r1", scope="source_reader", credential_id="app-a", installation_id=42),
            request("r2", timestamp=1001, scope="source_reader", credential_id="app-b",
                    installation_id=42),
        ])
        self.assertEqual(check_api_budget(value, budget_document())["requests_per_run"], {10: 2})
        value["requests"][1]["rate_limit"]["remaining"] = 10
        with self.assertRaisesRegex(BudgetError, "rate-limit-increased"):
            check_api_budget(value, budget_document())
        value["requests"][1]["rate_limit"]["remaining"] = 9
        value["requests"][1]["installation_id"] = None
        with self.assertRaisesRegex(BudgetError, "app-installation"):
            check_api_budget(value, budget_document())
        value["requests"][1]["installation_id"] = 42
        value["requests"][1]["credential_scope"] = "pin_writer"
        with self.assertRaisesRegex(BudgetError, "installation-scope-changed"):
            check_api_budget(value, budget_document())

    def test_repository_token_cannot_claim_app_installation(self):
        value = ledger([request("r1", installation_id=42)])
        with self.assertRaisesRegex(BudgetError, "repository-installation"):
            check_api_budget(value, budget_document())

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
            request("r2", timestamp=1499, remaining=0, reset=1500,
                    credential_id="renewed-repository-token"),
        ])
        with self.assertRaisesRegex(BudgetError, "request-before-reset"):
            check_api_budget(refused, budget_document())
        accepted = ledger([request("r1", status_code=403, remaining=0, reset=1500)])
        report = check_api_budget(accepted, budget_document())
        self.assertEqual(report["resume_at"], (1500,))


class SerializedInputTests(unittest.TestCase):
    def test_shadow_cli_reports_round_run_and_workflow_from_coordinator_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            budget_path = root / "budgets.json"
            budget_path.write_bytes(json.dumps(budget_document()).encode("ascii"))
            ledger_path = root / "ledger.json"
            ledger_path.write_bytes(json.dumps(ledger([request("r1")])).encode("ascii"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["--shadow", "--ledger", str(ledger_path),
                               "--budgets", str(budget_path)])
        self.assertEqual(result, 0)
        self.assertIn("ci.rate-budget=shadow round=round-1 requests=1", output.getvalue())
        self.assertIn("ci.rate-budget=run run=10 requests=1", output.getvalue())
        self.assertIn("ci.rate-budget=workflow workflow=public-policy requests=1", output.getvalue())
        action = (ROOT / "kit/bootstrap/action.yml").read_text(encoding="ascii")
        self.assertIn("if ! \"$python_bin\" -B \"$CI_ACTION_PATH/api_budget.py\" --shadow", action)
        self.assertIn("--ledger \"$CI_RATE_LEDGER_PATH\"", action)
        self.assertIn("ci.rate-budget=unavailable code=reporter-failed", action)

    def test_serialized_hour_boundary_reports_violation_without_shadow_failure(self):
        requests = hourly_requests()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            budget_path = root / "budgets.json"
            budget_path.write_bytes(json.dumps(budget_document()).encode("ascii"))
            ledger_path = root / "ledger.json"
            accepted = json.dumps(ledger(requests[:1000])).encode("ascii")
            self.assertGreater(len(accepted), MAX_BUDGET_BYTES)
            self.assertLessEqual(len(accepted), MAX_LEDGER_BYTES)
            ledger_path.write_bytes(accepted)
            self.assertEqual(check_api_budget_files(ledger_path, budget_path)["requests"], 1000)
            exceeded = json.dumps(ledger(requests)).encode("ascii")
            self.assertLessEqual(len(exceeded), MAX_LEDGER_BYTES)
            ledger_path.write_bytes(exceeded)
            with self.assertRaisesRegex(BudgetError, "hour-budget-exceeded"):
                check_api_budget_files(ledger_path, budget_path)
            strict_output = io.StringIO()
            with contextlib.redirect_stdout(strict_output):
                strict_result = main(["--ledger", str(ledger_path),
                                      "--budgets", str(budget_path)])
            self.assertEqual(strict_result, 1)
            self.assertEqual(strict_output.getvalue(),
                             "ci.rate-budget=refused code=hour-budget-exceeded\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["--shadow", "--ledger", str(ledger_path),
                               "--budgets", str(budget_path)])
        self.assertEqual(result, 0)
        self.assertIn("ci.rate-budget=shadow round=round-1 requests=1001", output.getvalue())
        self.assertIn("ci.rate-budget=violation code=hour-budget-exceeded", output.getvalue())
        self.assertIn("ci.rate-budget=shadow-complete violations=1 pending-resets=0",
                      output.getvalue())

    def test_shadow_pending_reset_and_early_request_report_without_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            budget_path = root / "budgets.json"
            budget_path.write_bytes(json.dumps(budget_document()).encode("ascii"))
            ledger_path = root / "ledger.json"
            ledger_path.write_bytes(json.dumps(ledger([
                request("r1", status_code=403, remaining=0, reset=1500),
            ])).encode("ascii"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["--shadow", "--ledger", str(ledger_path),
                               "--budgets", str(budget_path)])
            self.assertEqual(result, 0)
            self.assertIn("ci.rate-budget=shadow round=round-1 requests=1", output.getvalue())
            self.assertIn("ci.rate-budget=paused pending-resets=1 resume-after=1500",
                          output.getvalue())
            strict_output = io.StringIO()
            with contextlib.redirect_stdout(strict_output):
                strict_result = main(["--ledger", str(ledger_path),
                                      "--budgets", str(budget_path)])
            self.assertEqual(strict_result, 2)
            self.assertIn("ci.rate-budget=paused requests=1", strict_output.getvalue())
            ledger_path.write_bytes(json.dumps(ledger([
                request("r1", status_code=403, remaining=0, reset=1500),
                request("r2", timestamp=1499, remaining=0, reset=1500),
            ])).encode("ascii"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["--shadow", "--ledger", str(ledger_path),
                               "--budgets", str(budget_path)])
        self.assertEqual(result, 0)
        self.assertIn("ci.rate-budget=shadow round=round-1 requests=2", output.getvalue())
        self.assertIn("ci.rate-budget=violation code=request-before-reset", output.getvalue())

    def test_shadow_invalid_ledger_is_unavailable_without_gating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            budget_path = root / "budgets.json"
            budget_path.write_bytes(json.dumps(budget_document()).encode("ascii"))
            ledger_path = root / "ledger.json"
            ledger_path.write_bytes(b"{")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["--shadow", "--ledger", str(ledger_path),
                               "--budgets", str(budget_path)])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "ci.rate-budget=unavailable code=document-invalid\n")

    def test_strict_budget_json_rejects_duplicate_nonfinite_and_non_ascii(self):
        invalid = (
            b'{"schema_version":1,"schema_version":1}',
            b'{"value":NaN}',
            b'{"value":"\xff"}',
            b'{"value":1} trailing',
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "budgets.json"
                    path.write_bytes(payload)
                    with self.assertRaises(BudgetError):
                        load_budget_document(path)

    def test_strict_ledger_json_rejects_duplicate_nonfinite_and_trailing_data(self):
        invalid = (
            b'{"schema_version":1,"schema_version":1}',
            b'{"value":Infinity}',
            b'{"value":1} trailing',
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            budget_path = root / "budgets.json"
            budget_path.write_bytes(json.dumps(budget_document()).encode("ascii"))
            ledger_path = root / "ledger.json"
            for payload in invalid:
                with self.subTest(payload=payload):
                    ledger_path.write_bytes(payload)
                    with self.assertRaises(BudgetError):
                        check_api_budget_files(ledger_path, budget_path)


if __name__ == "__main__":
    unittest.main()
