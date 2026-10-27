import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parent / "macos_feedback_producer.py"
SPEC = importlib.util.spec_from_file_location("macos_feedback_producer", MODULE_PATH)
producer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = producer
SPEC.loader.exec_module(producer)
requests = producer.feedback_request

NOW = 1_798_000_000
SOURCE_SHA = "a" * 40
BASE_SHA = "b" * 40
CONTROL_SHA = "c" * 40
DIFF_SHA = "d" * 64
SPKI = b"synthetic-public-key-der"


def _dispatch(kind="build_diagnostics"):
    profile = producer.PROFILE_BY_KIND[kind]
    fingerprint = hashlib.sha256(SPKI).hexdigest()
    fields = {
        "kind": kind,
        "concern": profile["concern"],
        "ci_repository_id": "1234",
        "workflow_path": profile["workflow_path"],
        "workflow_ref": "refs/heads/main",
        "repository_id": "5678",
        "source_sha": SOURCE_SHA,
        "base_sha": BASE_SHA,
        "control_sha": CONTROL_SHA,
        "base_branch": "develop",
        "reviewed_diff_sha256": DIFF_SHA,
        "recipient_fingerprint": fingerprint,
        "nonce": "e" * 64,
        "expiry": NOW + 3600,
    }
    request = requests.create_request(fields, now=NOW)
    environment = {
        producer.REQUEST_ENV: base64.b64encode(requests.encode_request(request, now=NOW)).decode("ascii"),
        producer.RECIPIENT_ENV: base64.b64encode(SPKI).decode("ascii"),
        "CI_SHA": CONTROL_SHA,
        "GITHUB_SHA": CONTROL_SHA,
        "GITHUB_REPOSITORY": "public/ci",
        "GITHUB_REPOSITORY_ID": "1234",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": "public/ci/" + profile["workflow_path"] + "@refs/heads/main",
        "GITHUB_JOB": profile["producer_job"],
        "GITHUB_RUN_ID": "9876",
        "GITHUB_RUN_ATTEMPT": "1",
        "SOURCE_REPOSITORY_ID": "5678",
        "CORE_CONTRACT_REVIEWED_SOURCE_SHA": SOURCE_SHA,
        "CORE_CONTRACT_REVIEWED_BASE_SHA": BASE_SHA,
        "CORE_CONTRACT_REVIEWED_BASE_BRANCH": "develop",
        "CORE_CONTRACT_REVIEWED_DIFF_SHA256": DIFF_SHA,
    }
    return request, environment


def _validated_dispatch(kind):
    _request, environment = _dispatch(kind)
    return producer.validate_dispatch(kind, environment, now=NOW)


class MacosFeedbackProducerTests(unittest.TestCase):
    def test_dispatch_binds_each_closed_profile_and_omits_lock_kind_from_context(self):
        for kind in producer.PROFILE_BY_KIND:
            request, environment = _dispatch(kind)
            result = producer.validate_dispatch(kind, environment, now=NOW)
            self.assertEqual(result["request"], request)
            self.assertEqual(result["context"]["concern"], request["concern"])
            self.assertEqual(result["context"]["run_id"], "9876")
            self.assertEqual(result["context"]["producer_job"],
                             producer.PROFILE_BY_KIND[kind]["producer_job"])
            self.assertEqual("kind" in result["context"], kind != "lock")

    def test_dispatch_rejects_run_profile_binding_and_recipient_mismatches(self):
        _, environment = _dispatch("build_diagnostics")
        for name, value in (
            ("GITHUB_JOB", "other-job"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_SHA", "f" * 40),
            ("SOURCE_REPOSITORY_ID", "0009"),
        ):
            changed = dict(environment)
            changed[name] = value
            with self.subTest(name=name), self.assertRaises(producer.FeedbackRefusal):
                producer.validate_dispatch("build_diagnostics", changed, now=NOW)

        changed = dict(environment)
        changed[producer.RECIPIENT_ENV] = base64.b64encode(b"different-key").decode("ascii")
        with self.assertRaises(producer.FeedbackRefusal):
            producer.validate_dispatch("build_diagnostics", changed, now=NOW)

    def test_source_manifest_parser_rejects_duplicate_keys_and_derives_expectation(self):
        with self.assertRaises(producer.FeedbackRefusal):
            producer._strict_json(b'{"name":"x","name":"y"}', 128)

        root = {
            "name": "synthetic-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        }
        workspace = {"name": "@synthetic/host-api", "version": "1.0.0"}
        source = Path("/synthetic-source")
        files = {
            source / "package.json": json.dumps(root).encode("utf-8"),
            source / "packages/host-api/package.json": json.dumps(workspace).encode("utf-8"),
        }
        with patch.object(producer, "_read_file", side_effect=lambda path, **unused: files[path]):
            expected = producer._expected_manifest(source)
        self.assertEqual(expected["root"], {
            "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        })
        self.assertEqual(expected["workspaces"], [{
            "path": "packages/host-api", "name": "@synthetic/host-api", "version": "1.0.0",
        }])

    def test_producer_receipt_is_canonical_context_only_and_profile_closed(self):
        _, environment = _dispatch("rust_patch")
        dispatch = producer.validate_dispatch("rust_patch", environment, now=NOW)
        receipt = producer.producer_receipt(dispatch, {
            "member_name": "rust-format-return-v1.enc",
            "ciphertext_digest": "a" * 64,
            "member_size": 128,
        })
        record = json.loads(receipt)
        self.assertEqual(receipt, json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        self.assertEqual(record["status"], "encrypted")
        self.assertEqual(record["job_name"], "core-rust-format-return")
        self.assertEqual(record["member_name"], "rust-format-return-v1.enc")
        self.assertNotIn("path", record)
        self.assertNotIn("stdout", record)
        self.assertNotIn("stderr", record)

    def test_publisher_receipt_parser_requires_exact_single_profile_and_context(self):
        _, environment = _dispatch("build_diagnostics")
        dispatch = producer.validate_dispatch("build_diagnostics", environment, now=NOW)
        receipt = producer.producer_receipt(dispatch, {
            "member_name": "build-diagnostic-return-v1.enc",
            "ciphertext_digest": "b" * 64,
            "member_size": 256,
        })
        line = ("KD-FEEDBACK-PRODUCER " + receipt + "\n").encode("ascii")
        with patch.object(producer.time, "time", return_value=NOW):
            checked, record, canonical = producer._parse_producer_line(
                line, "build_diagnostics", environment,
            )
            self.assertEqual(checked["context"], dispatch["context"])
            self.assertEqual(record["member_size"], 256)
            self.assertEqual(canonical, receipt)
            for altered, kind in (
                (line + line, "build_diagnostics"),
                (line, "rust_patch"),
                (line.replace(b"b" * 64, b"g" * 64), "build_diagnostics"),
            ):
                with self.subTest(kind=kind, size=len(altered)), self.assertRaises(producer.FeedbackRefusal):
                    producer._parse_producer_line(altered, kind, environment)

    def test_build_diagnostic_payload_marks_truncated_streams_and_keeps_failure_stage(self):
        stdout_prefix = b"bounded stdout\n" + (b"x" * (32_768 - len(b"bounded stdout\n")))
        stderr_prefix = b"bounded stderr\n" + (b"y" * (32_768 - len(b"bounded stderr\n")))
        payload = producer.build_diagnostic_payload({
            "failed_stage": "workspace_tests",
            "returncode": 9,
            "stdout": stdout_prefix,
            "stderr": stderr_prefix,
            "stdout_truncated": True,
            "stderr_truncated": True,
        })
        self.assertTrue(payload.startswith(
            b"KD-BUILD-DIAGNOSTICS schema=1 stage=workspace_tests stdout_truncated=true "
            b"stderr_truncated=true exit=9\n"
        ))
        self.assertIn(stdout_prefix, payload)
        self.assertIn(stderr_prefix, payload)
        self.assertLessEqual(len(payload), 512 * 1024)
        with self.assertRaises(producer.FeedbackRefusal):
            producer.build_diagnostic_payload({
                "failed_stage": "workspace_tests", "returncode": 9,
                "stdout": b"x", "stderr": b"y", "stdout_truncated": "yes",
                "stderr_truncated": False,
            })

    def test_worker_refuses_invalid_capture_framing_without_publishing_output(self):
        error = RuntimeError("synthetic malformed frame")
        error.reason = "capture_invalid"

        def refuse(*unused_args, **unused_kwargs):
            raise error

        rust = SimpleNamespace(_run_worker_command=refuse)
        with self.assertRaises(producer.FeedbackRefusal) as raised:
            producer._run_worker(
                rust, ("cargo", "fmt", "--check"), 501, {}, "/trusted/python", object(),
                "feedback_format", 10**12, allow_nonzero_capture=True,
            )
        self.assertEqual(raised.exception.reason, "capture_invalid")

    def test_lock_profile_uses_fixed_script_disabled_registry_command_and_restores_cwd(self):
        dispatch = _validated_dispatch("lock")
        calls = []
        command_result = SimpleNamespace(returncode=0, stdout=b"quiet", stderr=b"")
        worker_home = str(Path(tempfile.gettempdir()) / "worker-home")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            worker_storage = root / "worker"
            worker_storage.mkdir()
            (worker_storage / "tmp").mkdir()

            def create_worker_directory(path, *args):
                path = Path(path)
                calls.append(("directory", (path, *args)))
                if path.exists():
                    raise producer.FeedbackRefusal("output_unavailable")

            with patch.object(producer, "_expected_manifest", return_value={"root": {}, "workspaces": []}):
                with patch.object(producer, "_copy_reviewed_files", side_effect=lambda *args:
                        calls.append(("copy", args))):
                    with patch.object(producer, "_make_worker_directory", side_effect=create_worker_directory):
                        with patch.object(producer, "_run_worker", side_effect=lambda *args, **kwargs:
                                calls.append(("command", args, kwargs)) or command_result):
                            with patch.object(producer, "_read_worker_file", return_value=b"lock-bytes"):
                                with patch.object(producer.os, "chdir", side_effect=lambda path:
                                        calls.append(("cwd", path))):
                                    result = producer.run_source_profile(
                                        dispatch, source, worker_storage, 501, {"HOME": worker_home},
                                        {}, {"python": "/trusted/python"},
                                        SimpleNamespace(PROBE_PRIMARY_GID=20), object(), object(),
                                        10**12, Path("/trusted/node"), Path("/trusted/npm-cli.js"),
                                    )
        command = next(call for call in calls if call[0] == "command")
        argv = command[1][1]
        self.assertIn("--package-lock-only", argv)
        self.assertIn("--ignore-scripts", argv)
        self.assertIn("--registry=https://registry.npmjs.org/", argv)
        self.assertNotIn("--offline", argv)
        self.assertTrue(command[2]["allow_nonzero_capture"])
        directories = [call[1][0] for call in calls if call[0] == "directory"]
        self.assertIn(worker_storage / producer.FEEDBACK_TEMP_DIRECTORY, directories)
        self.assertNotIn(worker_storage / "tmp", directories)
        self.assertEqual(command[1][3]["TMPDIR"], str(worker_storage / producer.FEEDBACK_TEMP_DIRECTORY))
        self.assertEqual([call[1] for call in calls if call[0] == "cwd"], [
            worker_storage / "feedback-node-lock", source,
        ])
        self.assertEqual(result["payload_bytes"], b"lock-bytes")
        self.assertEqual(result["source_result"], "command_completed")

    def test_lock_profile_refuses_unavailable_dedicated_tmp_before_command(self):
        dispatch = _validated_dispatch("lock")
        calls = []
        worker_storage = Path("/synthetic-worker")
        worker_home = str(Path(tempfile.gettempdir()) / "worker-home")

        def refuse_feedback_tmp(path, *unused_args):
            path = Path(path)
            calls.append(path)
            if path == worker_storage / producer.FEEDBACK_TEMP_DIRECTORY:
                raise producer.FeedbackRefusal("output_unavailable")

        with patch.object(producer, "_expected_manifest", return_value={"root": {}, "workspaces": []}):
            with patch.object(producer, "_copy_reviewed_files", return_value=None):
                with patch.object(producer, "_make_worker_directory", side_effect=refuse_feedback_tmp):
                    with patch.object(producer, "_run_worker", side_effect=lambda *args, **kwargs:
                            calls.append("command")):
                        with self.assertRaises(producer.FeedbackRefusal) as raised:
                            producer.run_source_profile(
                                dispatch, Path("/synthetic-source"), worker_storage, 501,
                                {"HOME": worker_home}, {}, {"python": "/trusted/python"},
                                SimpleNamespace(PROBE_PRIMARY_GID=20), object(), object(),
                                10**12, Path("/trusted/node"), Path("/trusted/npm-cli.js"),
                            )
        self.assertEqual(raised.exception.reason, "output_unavailable")
        self.assertNotIn("command", calls)

    def test_source_profile_failure_restores_source_cwd_and_never_returns_payload(self):
        dispatch = _validated_dispatch("rust_patch")
        calls = []

        def reject_command(*unused_args, **unused_kwargs):
            calls.append("command")
            raise producer.FeedbackRefusal("command_failed")

        with patch.object(producer, "_reviewed_rust_paths", return_value=("crates/host/api/src/lib.rs",)):
            with patch.object(producer, "_source_root_files", return_value=("Cargo.toml",)):
                with patch.object(producer, "_copy_reviewed_files", return_value=None):
                    with patch.object(producer, "_run_worker", side_effect=reject_command):
                        with patch.object(producer.os, "chdir", side_effect=lambda path: calls.append(path)):
                            with self.assertRaises(producer.FeedbackRefusal):
                                producer.run_source_profile(
                                    dispatch, Path("/synthetic-source"), Path("/synthetic-worker"), 501,
                                    {}, {"cargo": Path("/trusted/cargo")}, {"python": "/trusted/python"},
                                    SimpleNamespace(PROBE_PRIMARY_GID=20), object(), object(),
                                    10**12, Path("/trusted/node"), None,
                                )
        self.assertEqual(calls[0], Path("/synthetic-worker/feedback-rust-format"))
        self.assertEqual(calls[-1], Path("/synthetic-source"))
        self.assertIn("command", calls)

    def test_cli_accepts_only_fixed_run_and_publisher_shapes(self):
        kind, core_args = producer._parse_cli([
            "run", "--profile", "lock", "--token-stdin", "--source-sha", SOURCE_SHA,
            "--base-sha", BASE_SHA, "--base-branch", "develop",
        ])
        self.assertEqual(kind, "lock")
        self.assertEqual(core_args[0:2], ["run", "--token-stdin"])
        self.assertEqual(producer._parse_cli(["run", "--profile", "invalid"]), ("invalid", []))


if __name__ == "__main__":
    unittest.main()
