import json
import contextlib
import io
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kit/baselines"))
sys.path.insert(0, str(ROOT / "kit/confinement"))

import baselines_prepare
import confinement_public_audit
import future_stage as subject


INVENTORY = ROOT / "kit/ci/future-stage-inventory.json"
SOURCE_SHA = "a" * 40
REPOSITORY = "owner/project"


class FakeResponse:
    def __init__(self, payload, *, status=201, url=None):
        self.payload = payload
        self.status = status
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def geturl(self):
        return self.url

    def read(self, maximum):
        return self.payload[:maximum]


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return self.response


class FutureStageTests(unittest.TestCase):
    def test_static_matrix_is_closed_and_includes_cp1_to_cp3_ci27_to_ci31_and_appium(self):
        result = subject.matrix(INVENTORY)
        entries = result["include"]
        identifiers = [item["job_id"] for item in entries]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for identifier in (
            "cp1-api-mock-demo", "cp2-sqlite-store", "cp3-sync", "ci27-core-feature-states",
            "ci29-sdk-compatibility", "ci30-extension-isolation", "ci31-test-key-catalogue",
            "appium-linux-android", "appium-macos-ios", "appium-windows-native",
        ):
            self.assertIn(identifier, identifiers)
        appium = subject.matrix(INVENTORY, ("appium",))["include"]
        self.assertEqual(
            [item["job_id"] for item in appium],
            ["appium-linux-android", "appium-macos-ios", "appium-windows-native"],
        )

    def test_inventory_probe_is_forbidden_gate_evidence_even_when_every_path_is_present(self):
        source, _ = subject._read_inventory(INVENTORY)
        row = source["jobs"][0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in row["required_paths"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("inventory stub\n", encoding="ascii")
            result = subject.probe_job(INVENTORY, row["job_id"], root, SOURCE_SHA)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "future-stage")
        self.assertEqual(result["gate_evidence"], "forbidden")
        self.assertEqual(result["present_count"], result["required_count"])
        self.assertEqual(result["missing_count"], 0)
        encoded = subject.encode_result(result)
        self.assertIn("future-stage:", encoded)
        self.assertIn('"gate_evidence":"forbidden"', encoded)
        self.assertNotIn("neutral", encoded)
        self.assertNotIn("passed", encoded)
        self.assertNotIn("success", encoded)
        for field, value in (("status", "success"), ("gate_evidence", "allowed")):
            with self.subTest(field=field):
                forged = dict(result)
                forged[field] = value
                with self.assertRaisesRegex(subject.FutureStageError, "result-invalid"):
                    subject.encode_result(forged)

    def test_probe_cli_records_blocked_evidence_but_returns_the_reserved_nonpass_code(self):
        source, _ = subject._read_inventory(INVENTORY)
        row = source["jobs"][0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            output = Path(temporary) / "future-stage.json"
            stdout = io.StringIO()
            arguments = [
                "probe", "--inventory", str(INVENTORY), "--job", row["job_id"],
                "--root", str(root), "--source-sha", SOURCE_SHA, "--output", str(output),
            ]
            with contextlib.redirect_stdout(stdout):
                exit_code = subject.main(arguments, environ={})
            result = json.loads(output.read_text(encoding="ascii"))
        self.assertEqual(exit_code, subject.FUTURE_STAGE_JOB_EXIT_CODE)
        self.assertEqual(subject.FUTURE_STAGE_JOB_EXIT_CODE, 78)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["gate_evidence"], "forbidden")
        self.assertEqual(result["missing_count"], len(row["required_paths"]))
        self.assertEqual(json.loads(stdout.getvalue()), result)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            for name in row["required_paths"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("inventory stub\n", encoding="ascii")
            output = Path(temporary) / "future-stage.json"
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = subject.main([
                    "probe", "--inventory", str(INVENTORY), "--job", row["job_id"],
                    "--root", str(root), "--source-sha", SOURCE_SHA, "--output", str(output),
                ], environ={})
            result = json.loads(output.read_text(encoding="ascii"))
        self.assertEqual(exit_code, subject.FUTURE_STAGE_JOB_EXIT_CODE)
        self.assertEqual(result["missing_count"], 0)

    def test_actions_job_and_status_context_consumers_get_a_nonzero_result(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is required to exercise workflow status handling")
        marker = '          if [[ "$probe_status" -eq 0 || "$probe_status" -eq 78 ]]; then\n'
        for relative in (".github/workflows/ci-future-stages.yml", ".github/workflows/appium-ci.yml"):
            workflow = (ROOT / relative).read_text(encoding="ascii")
            self.assertEqual(workflow.count(marker), 1)
            block = textwrap.dedent(workflow.split(marker, 1)[1])
            script = marker.lstrip() + block
            for probe_status, expected_status in ((0, 78), (78, 78), (1, 1)):
                with self.subTest(workflow=relative, probe_status=probe_status):
                    result = subprocess.run(
                        [bash, "-c", "probe_status=%d\n%s" % (probe_status, script)],
                        capture_output=True, text=True, timeout=5, check=False,
                    )
                    self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)

    def test_missing_and_symlinked_inventory_paths_remain_blocked_and_are_not_followed(self):
        source, _ = subject._read_inventory(INVENTORY)
        row = source["jobs"][0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in row["required_paths"][:-1]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("inventory stub\n", encoding="ascii")
            external = root.parent / (root.name + "-external")
            external.write_text("outside\n", encoding="ascii")
            link = root / row["required_paths"][-1]
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(external)
            result = subject.probe_job(INVENTORY, row["job_id"], root, SOURCE_SHA)
            external.unlink()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["present_count"], len(row["required_paths"]) - 1)
        self.assertEqual(result["missing_count"], 1)

    def test_inventory_and_job_selection_refuse_duplicate_or_unlisted_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text(
                '{"schema_version":1,"jobs":[{"job_id":"one","checkpoint":"CP1",'
                '"required_paths":["a/file"]},{"job_id":"one","checkpoint":"CP1",'
                '"required_paths":["b/file"]}]}\n',
                encoding="ascii",
            )
            with self.assertRaisesRegex(subject.FutureStageError, "inventory-invalid"):
                subject.matrix(path)
            path.write_text(
                '{"schema_version":1,"jobs":[{"job_id":"one","checkpoint":[],"'
                'required_paths":["a/file"]}]}\n',
                encoding="ascii",
            )
            with self.assertRaisesRegex(subject.FutureStageError, "inventory-invalid"):
                subject.matrix(path)
        with self.assertRaisesRegex(subject.FutureStageError, "job-unknown"):
            subject.probe_job(INVENTORY, "not-listed", ROOT, SOURCE_SHA)
        with self.assertRaisesRegex(subject.FutureStageError, "checkpoint-invalid"):
            subject.matrix(INVENTORY, (["nested"],))

    def test_check_run_publisher_emits_failure_and_refuses_other_conclusions(self):
        job = subject.probe_job(INVENTORY, "cp1-api-mock-demo", ROOT, SOURCE_SHA)
        url = subject.API_ROOT + "/repos/" + REPOSITORY + "/check-runs"
        response = {
            "name": job["check_name"], "head_sha": SOURCE_SHA,
            "status": "completed", "conclusion": "failure",
        }
        opener = FakeOpener(FakeResponse(json.dumps(response).encode("ascii"), url=url))
        result = subject.publish_nonpassing_check(
            job, repository=REPOSITORY, token="token-value", opener=opener,
        )
        self.assertEqual(result["conclusion"], "failure")
        self.assertEqual(opener.request.full_url, url)
        self.assertNotIn("/statuses", opener.request.full_url)
        self.assertEqual(opener.request.method, "POST")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer token-value")
        self.assertEqual(opener.timeout, 10)
        body = json.loads(opener.request.data.decode("ascii"))
        self.assertEqual(body["conclusion"], "failure")
        self.assertIn("gate-evidence=forbidden", body["output"]["summary"])

        for conclusion in ("success", "neutral", "skipped"):
            with self.subTest(conclusion=conclusion):
                response["conclusion"] = conclusion
                wrong = FakeOpener(FakeResponse(json.dumps(response).encode("ascii"), url=url))
                with self.assertRaisesRegex(subject.FutureStageError, "check-api-refused"):
                    subject.publish_nonpassing_check(
                        job, repository=REPOSITORY, token="token-value", opener=wrong,
                    )

    def test_summary_parser_refuses_the_future_stage_record_as_admission_evidence(self):
        result = subject.probe_job(INVENTORY, "cp1-api-mock-demo", ROOT, SOURCE_SHA)
        summary = subject.encode_result(result)
        with self.assertRaisesRegex(baselines_prepare.BaselinesRefusal, "summary_markers"):
            baselines_prepare.audit_summary(summary, SOURCE_SHA, 1, 1, "linux")
        self.assertIn('"gate_evidence":"forbidden"', summary)

    def test_admission_script_rejects_the_future_stage_conclusion_as_pass_evidence(self):
        result = subject.probe_job(INVENTORY, "cp1-api-mock-demo", ROOT, SOURCE_SHA)
        expected = {
            "run_id": 17,
            "run_attempt": 1,
            "control_sha": SOURCE_SHA,
            "jobs": {result["check_name"]: {"steps": [], "optional_steps": set()}},
            "auditor_job": "audit",
        }
        check_url = "https://api.github.com/repos/" + REPOSITORY + "/check-runs/301"
        producer = {
            "id": 301,
            "name": result["check_name"],
            "run_id": 17,
            "run_attempt": 1,
            "head_sha": SOURCE_SHA,
            "status": "completed",
            "conclusion": "failure",
            "check_run_url": check_url,
            "steps": [],
        }
        auditor = dict(producer)
        auditor.update({
            "id": 302,
            "name": "audit",
            "status": "in_progress",
            "conclusion": None,
            "check_run_url": "https://api.github.com/repos/" + REPOSITORY + "/check-runs/302",
        })
        with self.assertRaisesRegex(confinement_public_audit.AuditRefusal, "confinement_audit_invalid"):
            confinement_public_audit._check_jobs([producer, auditor], expected)


if __name__ == "__main__":
    unittest.main()
