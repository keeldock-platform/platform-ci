"""Hosted-only orchestration tests for the fixed Node contract stages."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest

try:
    from . import macos_node_contract as subject
except ImportError:
    import macos_node_contract as subject


def _identity(seed):
    return {
        "source_sha": seed * 40,
        "base_sha": chr(ord(seed) + 1) * 40,
        "control_sha": chr(ord(seed) + 2) * 40,
        "reviewed_diff_sha256": chr(ord(seed) + 3) * 64,
    }


def _manifest():
    return {
        "root": {
            "name": "fixture-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        },
        "workspaces": [{
            "path": "packages/client-api",
            "name": "@fixture/client-api",
            "version": "1.0.0",
        }],
    }


def _lock_bytes():
    lock = {
        "name": "fixture-root",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "fixture-root",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "devDependencies": {"typescript": "6.0.3"},
            },
            "packages/client-api": {"name": "@fixture/client-api", "version": "1.0.0"},
            "node_modules/@fixture/client-api": {"resolved": "packages/client-api", "link": True},
            "node_modules/typescript": {
                "version": "6.0.3",
                "resolved": "https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz",
                "integrity": "sha512-" + ("A" * 86) + "==",
            },
        },
    }
    return (json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _manifest_sha256(manifest):
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _provenance(lock_bytes, policy_epoch_ms, accepted_identity, generation_identity):
    return {
        "schema_version": 1,
        "status": "accepted",
        "generation_identity": generation_identity,
        "accepted_source_identity": accepted_identity,
        "lock_sha256": _sha256(lock_bytes),
        "manifest_sha256": _manifest_sha256(_manifest()),
        "node_version": subject.NODE_VERSION,
        "npm_version": subject.NPM_VERSION,
        "release_age_days": subject.RELEASE_AGE_DAYS,
        "policy_epoch_ms": policy_epoch_ms,
        "cutoff_epoch_ms": policy_epoch_ms - subject.RELEASE_AGE_DAYS * subject.DAY_MS,
        "age_status": "passed",
        "generation_attempts": 1,
        "audit_endpoint": subject.AUDIT_ENDPOINT,
        "audit_status": "passed",
        "accepted_at_ms": policy_epoch_ms + 1000,
    }


def _finding(policy_epoch_ms, **overrides):
    finding = {
        "name": "minimatch",
        "version": "10.2.6",
        "severity": "moderate",
        "advisory_id": "1244012",
        "range": "<10.2.7",
        "allow_justification_sha256": "e" * 64,
        "allow_expires_at_ms": policy_epoch_ms + 60 * subject.DAY_MS,
        "allow_removal_condition": "upstream-release",
    }
    finding.update(overrides)
    return finding


def _allowed_provenance(lock_bytes, policy_epoch_ms, accepted_identity, generation_identity, findings):
    record = _provenance(lock_bytes, policy_epoch_ms, accepted_identity, generation_identity)
    record.update({
        "schema_version": 2,
        "audit_status": "allowed_findings",
        "allowed_findings": findings,
    })
    return record


class WorkerHarness:
    def __init__(self, project, *, lock_bytes=None, failure=None, audit_reason=None,
                 mutate_config_after=None, finding_count=0, allowed_count=0, audit_status=None):
        self.project = Path(project)
        self.lock_bytes = lock_bytes or _lock_bytes()
        self.failure = failure
        self.audit_reason = audit_reason
        self.mutate_config_after = mutate_config_after
        self.finding_count = finding_count
        self.allowed_count = allowed_count
        self.audit_status = audit_status or ("allowed_findings" if allowed_count else "passed")
        self.calls = []
        self.requests = []

    def __call__(self, argv, *, stage, substage, cwd, env, deadline, timeout,
                 allow_nonzero_capture=True):
        self.calls.append({
            "argv": tuple(argv), "stage": stage, "substage": substage,
            "cwd": Path(cwd), "env": dict(env), "timeout": timeout,
            "allow_nonzero_capture": allow_nonzero_capture,
        })
        command = tuple(argv)
        if command[-1:] == ("--version",):
            stdout = (f"v{subject.NODE_VERSION}\n" if len(command) == 2
                      else f"{subject.NPM_VERSION}\n").encode("ascii")
            return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"",
                                   stdout_truncated=False, stderr_truncated=False)
        if substage == "lock_generation":
            if self.failure == substage:
                return self._result(1, b"fixture generation failure")
            self._write_lock()
            return self._result()
        if substage == "bulk_audit":
            request_path = Path(command[-1])
            request = json.loads(request_path.read_bytes())
            self.requests.append(request)
            if self.audit_reason:
                output = {"schema_version": 1, "status": "refused", "reason": self.audit_reason}
                return self._result(stdout=(json.dumps(output) + "\n").encode("ascii"))
            policy_epoch_ms = (request["policy_epoch_ms"] if request["mode"] == "bootstrap"
                               else request["accepted_provenance"]["policy_epoch_ms"])
            result = {
                "schema_version": 1,
                "status": "passed",
                "mode": request["mode"],
                "lock_sha256": _sha256(base64.b64decode(request["lock_base64"])),
                "manifest_sha256": _manifest_sha256(request["expected_manifest"]),
                "node_version": subject.NODE_VERSION,
                "npm_version": subject.NPM_VERSION,
                "release_age_days": subject.RELEASE_AGE_DAYS,
                "policy_epoch_ms": policy_epoch_ms,
                "cutoff_epoch_ms": policy_epoch_ms - subject.RELEASE_AGE_DAYS * subject.DAY_MS,
                "age_status": "passed",
                "generation_attempts": 1,
                "audit_endpoint": subject.AUDIT_ENDPOINT,
                "audit_status": self.audit_status,
                "package_count": 4,
                "remote_package_count": 1,
                "remote_version_count": 1,
                "advisory_count": self.finding_count,
                "finding_count": self.finding_count,
                "allowed_count": self.allowed_count,
            }
            output = {"schema_version": 1, "status": "passed", "result": result}
            return self._result(stdout=(json.dumps(output, separators=(",", ":")) + "\n").encode("ascii"))
        if substage == self.failure:
            return self._result(1, b"fixture stage failure")
        if substage == self.mutate_config_after:
            Path(env["npm_config_globalconfig"]).write_bytes(b"changed\n")
        return self._result()

    def _result(self, returncode=0, stdout=b"", stderr=b""):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr,
                               stdout_truncated=False, stderr_truncated=False)

    def _write_lock(self):
        path = self.project / "package-lock.json"
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        try:
            os.write(descriptor, self.lock_bytes)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "getuid") and hasattr(os, "O_NOFOLLOW"),
                     "Node contract filesystem tests require POSIX ownership and no-follow semantics")
class MacOSNodeContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.project = self.root / "project"
        self.storage = self.root / "worker-storage"
        self.project.mkdir(mode=0o700)
        self.storage.mkdir(mode=0o700)
        self.cache = self.root / "tool-cache"
        self.node_root = self.cache / "node" / subject.NODE_VERSION / "arm64"
        node_bin = self.node_root / "bin"
        npm_bin = self.node_root / "lib/node_modules/npm/bin"
        node_bin.mkdir(parents=True, mode=0o700)
        npm_bin.mkdir(parents=True, mode=0o700)
        self.node = node_bin / "node"
        self.npm = npm_bin / "npm-cli.js"
        self.node.write_bytes(b"synthetic pinned runtime executable")
        self.npm.write_bytes(b"synthetic pinned npm entry point")
        self.node.chmod(0o500)
        self.npm.chmod(0o400)
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self):
        self.temporary.cleanup()

    def call(self, mode, runner, **extra):
        return subject.run_node_contract(
            mode,
            project=self.project,
            worker_storage=self.storage,
            worker_uid=self.uid,
            worker_gid=self.gid,
            node_executable=self.node,
            npm_cli=self.npm,
            tool_cache_root=self.cache,
            expected_manifest=_manifest(),
            source_identity=_identity("1"),
            run_worker=runner,
            deadline=time.monotonic() + 600,
            **extra,
        )

    def install_committed_lock(self, lock_bytes):
        path = self.project / "package-lock.json"
        path.write_bytes(lock_bytes)
        path.chmod(0o644)

    def test_bootstrap_generates_once_audits_before_return_and_does_not_run_source_tests(self):
        runner = WorkerHarness(self.project)
        policy_epoch_ms = int(time.time() * 1000) - 10_000
        output = self.call("bootstrap", runner, policy_epoch_ms=policy_epoch_ms)
        self.assertEqual(output["status"], "passed")
        self.assertEqual(output["stages"], ("node_dependency_prepare", "node_dependency_audit"))
        self.assertEqual(output["provenance_candidate"]["policy_epoch_ms"], policy_epoch_ms)
        self.assertEqual(output["provenance_candidate"]["generation_attempts"], 1)
        environment = runner.calls[0]["env"]
        user_config = Path(environment["npm_config_userconfig"])
        global_config = Path(environment["npm_config_globalconfig"])
        self.assertNotEqual(user_config, global_config)
        self.assertEqual(user_config.parent, self.storage)
        self.assertEqual(global_config.parent, self.storage)
        for config_path in (user_config, global_config):
            info = config_path.stat()
            self.assertEqual(config_path.read_bytes(), b"\n")
            self.assertEqual(info.st_uid, self.uid)
            self.assertEqual(info.st_gid, self.gid)
            self.assertEqual(info.st_mode & 0o777, 0o600)
        commands = [entry["argv"] for entry in runner.calls]
        generation = [command for command in commands if "--package-lock-only" in command]
        self.assertEqual(len(generation), 1)
        self.assertIn("--min-release-age=7", generation[0])
        self.assertTrue(any(item.startswith("--before=") for item in generation[0]))
        self.assertIn("--userconfig=" + str(user_config), generation[0])
        self.assertIn("--globalconfig=" + str(global_config), generation[0])
        self.assertFalse(any("ci" in command for command in commands))
        self.assertFalse(any("typecheck" in command or "test" == command[-1] for command in commands))
        self.assertTrue(any("--request" in command for command in commands))

    def test_worker_environment_carries_the_fixed_title_option_on_every_command(self):
        runner = WorkerHarness(self.project)
        self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        self.assertTrue(runner.calls)
        for entry in runner.calls:
            self.assertEqual(entry["env"]["NODE_OPTIONS"], subject.NODE_OPTIONS_VALUE)

    def test_fixed_title_option_decodes_to_the_exact_module_source(self):
        source = 'let kdTitle = String(process.title);Object.defineProperty(process,"title",{get(){return kdTitle;},set(value){kdTitle = String(value);},configurable:true,enumerable:true});'
        self.assertEqual(subject.NODE_TITLE_MODULE_SOURCE, source)
        prefix = "--import=data:text/javascript;base64,"
        self.assertTrue(subject.NODE_OPTIONS_VALUE.startswith(prefix))
        encoded = subject.NODE_OPTIONS_VALUE[len(prefix):]
        self.assertEqual(base64.b64decode(encoded, validate=True), source.encode("ascii"))
        self.assertEqual(base64.b64encode(source.encode("ascii")).decode("ascii"), encoded)
        self.assertFalse(any(character in subject.NODE_OPTIONS_VALUE for character in " \t\"'\\"))

    def test_bootstrap_refuses_generation_failure_without_retry_or_audit(self):
        runner = WorkerHarness(self.project, failure="lock_generation")
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        self.assertEqual(caught.exception.substage, "lock_generation")
        self.assertEqual(caught.exception.completed_stages, ())
        self.assertEqual(sum(entry["substage"] == "lock_generation" for entry in runner.calls), 1)
        self.assertFalse(any(entry["substage"] == "bulk_audit" for entry in runner.calls))

    def test_bootstrap_never_returns_a_lock_when_advisory_audit_refuses(self):
        runner = WorkerHarness(self.project, audit_reason="vulnerable_dependency")
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        self.assertEqual(caught.exception.reason, "vulnerable_dependency")
        self.assertEqual(caught.exception.completed_stages, ("node_dependency_prepare",))

    def _audit_harness(self, returncode, stdout, stderr=b""):
        class AuditHarness(WorkerHarness):
            def __call__(inner, argv, *, stage, substage, **kwargs):
                if substage == "bulk_audit":
                    inner.calls.append({"substage": substage})
                    return inner._result(returncode, stdout, stderr)
                return WorkerHarness.__call__(inner, argv, stage=stage, substage=substage, **kwargs)

        return AuditHarness(self.project)

    def _expect_failed_audit_helper(self, stdout):
        runner = self._audit_harness(1, stdout, b"helper crashed")
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        refusal = caught.exception
        self.assertEqual(refusal.reason, "audit_response_invalid")
        self.assertEqual((refusal.stage, refusal.substage), ("node_dependency_audit", "bulk_audit"))
        self.assertEqual(refusal.completed_stages, ("node_dependency_prepare",))
        self.assertEqual((refusal.returncode, refusal.stderr), (1, b"helper crashed"))
        self.assertFalse((self.storage / "node-contract-request.json").exists())

    def test_audit_helper_crash_with_empty_output_names_the_audit_stage_and_keeps_stderr(self):
        self._expect_failed_audit_helper(b"")

    def test_audit_helper_non_zero_exit_with_unparseable_output_is_not_parsed(self):
        self._expect_failed_audit_helper(b"not json\n")

    def test_audit_helper_non_zero_exit_with_a_passed_document_is_still_a_failed_helper(self):
        self._expect_failed_audit_helper(b'{"schema_version":1,"status":"passed"}\n')

    def test_audit_helper_refusal_document_still_supplies_the_reason_on_a_non_zero_exit(self):
        refusal_document = b'{"reason":"vulnerable_dependency","schema_version":1,"status":"refused"}\n'
        runner = self._audit_harness(1, refusal_document)
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        self.assertEqual(caught.exception.reason, "vulnerable_dependency")
        self.assertEqual(caught.exception.stage, "node_dependency_audit")
        self.assertEqual(caught.exception.completed_stages, ("node_dependency_prepare",))

    def test_unparseable_audit_output_on_a_zero_exit_is_a_staged_capture_failure(self):
        runner = self._audit_harness(0, b"not json\n")
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        refusal = caught.exception
        self.assertEqual(refusal.reason, "capture_invalid")
        self.assertEqual((refusal.stage, refusal.substage), ("node_dependency_audit", "bulk_audit"))
        self.assertEqual(refusal.completed_stages, ("node_dependency_prepare",))

    def test_audit_request_preparation_refusals_belong_to_the_audit_stage_after_prepare(self):
        (self.storage / "node-contract-request.json").write_bytes(b"stale")
        runner = WorkerHarness(self.project)
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        self.assertEqual(caught.exception.reason, "lock_already_present")
        self.assertEqual(caught.exception.stage, "node_dependency_audit")
        self.assertEqual(caught.exception.completed_stages, ("node_dependency_prepare",))
        self.assertFalse(any(entry["substage"] == "bulk_audit" for entry in runner.calls))

    def test_refusals_before_prepare_completes_keep_the_prepare_stage(self):
        self.install_committed_lock(_lock_bytes())
        runner = WorkerHarness(self.project)
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        self.assertEqual(caught.exception.reason, "lock_already_present")
        self.assertEqual(caught.exception.stage, "node_dependency_prepare")
        self.assertEqual(caught.exception.completed_stages, ())

    def test_node_environment_is_identical_to_the_foundation_adapter_environment(self):
        spec = importlib.util.spec_from_file_location(
            "foundation_node_feedback_environment",
            Path(__file__).resolve().parent / "foundation_node_feedback.py",
        )
        foundation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(foundation)
        environment = subject._node_environment(self.node, self.storage, self.uid, self.gid)
        self.assertEqual(foundation._node_environment(self.storage, self.node, subject), environment)
        self.assertEqual(environment["NO_COLOR"], "1")

    def test_node_environment_forbids_colour_on_every_command(self):
        runner = WorkerHarness(self.project)
        self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        for entry in runner.calls:
            if "env" in entry:
                self.assertEqual(entry["env"]["NO_COLOR"], "1")
                self.assertNotIn("FORCE_COLOR", entry["env"])

    def test_verify_uses_accepted_lock_without_regenerating_and_orders_audit_install_and_checks(self):
        lock_bytes = _lock_bytes()
        now_ms = int(time.time() * 1000)
        policy_epoch_ms = now_ms - (30 * subject.DAY_MS)
        current_identity = _identity("5")
        generation_identity = _identity("a")
        provenance = _provenance(lock_bytes, policy_epoch_ms, current_identity, generation_identity)
        self.install_committed_lock(lock_bytes)
        runner = WorkerHarness(self.project, lock_bytes=lock_bytes)
        output = subject.run_node_contract(
            "verify",
            project=self.project,
            worker_storage=self.storage,
            worker_uid=self.uid,
            worker_gid=self.gid,
            node_executable=self.node,
            npm_cli=self.npm,
            tool_cache_root=self.cache,
            expected_manifest=_manifest(),
            source_identity=current_identity,
            run_worker=runner,
            deadline=time.monotonic() + 600,
            accepted_lock=lock_bytes,
            accepted_provenance=provenance,
        )
        self.assertEqual(output["stages"], (
            "node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests",
        ))
        self.assertIsNone(runner.requests[0]["policy_epoch_ms"])
        commands = [entry["argv"] for entry in runner.calls]
        helper_index = next(index for index, command in enumerate(commands) if "--request" in command)
        ci_index = next(index for index, command in enumerate(commands) if "ci" in command)
        typecheck_index = next(index for index, command in enumerate(commands) if "typecheck" in command)
        tests_index = next(index for index, command in enumerate(commands)
                           if "test" in command and "--ignore-scripts" in command)
        self.assertLess(helper_index, ci_index)
        self.assertLess(ci_index, typecheck_index)
        self.assertLess(typecheck_index, tests_index)
        self.assertFalse(any("--package-lock-only" in command for command in commands))
        self.assertTrue(any("--ignore-scripts" in command for command in commands if "ci" in command))
        ci_command = commands[ci_index]
        ci_environment = runner.calls[ci_index]["env"]
        self.assertIn("--userconfig=" + ci_environment["npm_config_userconfig"], ci_command)
        self.assertIn("--globalconfig=" + ci_environment["npm_config_globalconfig"], ci_command)

    def test_verify_failure_reports_completed_prefix_and_does_not_claim_later_stages(self):
        lock_bytes = _lock_bytes()
        now_ms = int(time.time() * 1000)
        policy_epoch_ms = now_ms - (30 * subject.DAY_MS)
        current_identity = _identity("5")
        provenance = _provenance(lock_bytes, policy_epoch_ms, current_identity, _identity("a"))
        self.install_committed_lock(lock_bytes)
        runner = WorkerHarness(self.project, lock_bytes=lock_bytes, failure="typecheck")
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            subject.run_node_contract(
                "verify", project=self.project, worker_storage=self.storage,
                worker_uid=self.uid, worker_gid=self.gid, node_executable=self.node,
                npm_cli=self.npm, tool_cache_root=self.cache, expected_manifest=_manifest(),
                source_identity=current_identity, run_worker=runner, deadline=time.monotonic() + 600,
                accepted_lock=lock_bytes, accepted_provenance=provenance,
            )
        self.assertEqual(caught.exception.stage, "typescript_typecheck")
        self.assertEqual(caught.exception.completed_stages,
                         ("node_dependency_prepare", "node_dependency_audit"))

    def test_changed_empty_config_stops_before_the_next_project_command(self):
        lock_bytes = _lock_bytes()
        now_ms = int(time.time() * 1000)
        policy_epoch_ms = now_ms - (30 * subject.DAY_MS)
        current_identity = _identity("5")
        provenance = _provenance(lock_bytes, policy_epoch_ms, current_identity, _identity("a"))
        self.install_committed_lock(lock_bytes)
        runner = WorkerHarness(self.project, lock_bytes=lock_bytes, mutate_config_after="typecheck")
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            subject.run_node_contract(
                "verify", project=self.project, worker_storage=self.storage,
                worker_uid=self.uid, worker_gid=self.gid, node_executable=self.node,
                npm_cli=self.npm, tool_cache_root=self.cache, expected_manifest=_manifest(),
                source_identity=current_identity, run_worker=runner, deadline=time.monotonic() + 600,
                accepted_lock=lock_bytes, accepted_provenance=provenance,
            )
        self.assertEqual(caught.exception.reason, "command_failed")
        self.assertEqual(caught.exception.stage, "typescript_tests")
        self.assertEqual(caught.exception.substage, "tests")
        self.assertEqual(caught.exception.completed_stages, (
            "node_dependency_prepare", "node_dependency_audit", "typescript_typecheck",
        ))
        self.assertEqual(runner.calls[-1]["substage"], "typecheck")

    def test_rejects_provenance_drift_before_running_the_worker(self):
        lock_bytes = _lock_bytes()
        now_ms = int(time.time() * 1000)
        policy_epoch_ms = now_ms - (30 * subject.DAY_MS)
        current_identity = _identity("5")
        provenance = _provenance(lock_bytes, policy_epoch_ms, current_identity, _identity("a"))
        provenance["manifest_sha256"] = "0" * 64
        runner = WorkerHarness(self.project, lock_bytes=lock_bytes)
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            subject.run_node_contract(
                "verify", project=self.project, worker_storage=self.storage,
                worker_uid=self.uid, worker_gid=self.gid, node_executable=self.node,
                npm_cli=self.npm, tool_cache_root=self.cache, expected_manifest=_manifest(),
                source_identity=current_identity, run_worker=runner, deadline=time.monotonic() + 600,
                accepted_lock=lock_bytes, accepted_provenance=provenance,
            )
        self.assertEqual(caught.exception.reason, "accepted_provenance_invalid")
        self.assertEqual(runner.calls, [])

    def _verify(self, provenance, runner, lock_bytes):
        self.install_committed_lock(lock_bytes)
        return subject.run_node_contract(
            "verify", project=self.project, worker_storage=self.storage,
            worker_uid=self.uid, worker_gid=self.gid, node_executable=self.node,
            npm_cli=self.npm, tool_cache_root=self.cache, expected_manifest=_manifest(),
            source_identity=_identity("5"), run_worker=runner, deadline=time.monotonic() + 600,
            accepted_lock=lock_bytes, accepted_provenance=provenance,
        )

    def _allow_case(self, findings=None):
        lock_bytes = _lock_bytes()
        policy_epoch_ms = int(time.time() * 1000) - 30 * subject.DAY_MS
        if findings is None:
            findings = [_finding(policy_epoch_ms)]
        provenance = _allowed_provenance(lock_bytes, policy_epoch_ms, _identity("5"), _identity("a"),
                                         findings)
        return lock_bytes, policy_epoch_ms, provenance

    def test_verify_passes_recorded_allows_verbatim_to_the_helper_and_accepts_counts(self):
        lock_bytes, unused, provenance = self._allow_case()
        (self.project / "dependency-policy.json").write_bytes(b'{"development_advisory_allows":[]}\n')
        runner = WorkerHarness(self.project, lock_bytes=lock_bytes, finding_count=1, allowed_count=1)
        output = self._verify(provenance, runner, lock_bytes)
        self.assertEqual(output["status"], "passed")
        self.assertEqual(output["accepted_provenance"], provenance)
        self.assertEqual(runner.requests[0]["accepted_provenance"], provenance)
        self.assertEqual(set(runner.requests[0]), {
            "schema_version", "mode", "lock_base64", "expected_manifest", "source_identity",
            "npm_cli_path", "generation_proof", "accepted_provenance", "policy_epoch_ms", "now_ms",
            "deadline_ms",
        })
        self.assertEqual(set(output["audit_summary"]), {
            "package_count", "remote_package_count", "remote_version_count", "advisory_count",
        })

    def test_verify_refuses_malformed_or_widened_allow_records_before_any_command(self):
        lock_bytes, policy_epoch_ms, provenance = self._allow_case()
        finding = _finding(policy_epoch_ms)
        variants = []
        for overrides in (
            {"allow_expires_at_ms": policy_epoch_ms + subject.MAX_ALLOW_TTL_MS + 1},
            {"allow_expires_at_ms": policy_epoch_ms},
            {"allow_expires_at_ms": True},
            {"severity": "high"},
            {"severity": "critical"},
            {"version": "^10.2.6"},
            {"name": "Minimatch"},
            {"advisory_id": ""},
            {"allow_justification_sha256": "E" * 64},
            {"allow_removal_condition": "has space"},
            {"range": ""},
        ):
            variants.append([_finding(policy_epoch_ms, **overrides)])
        variants.append([dict(finding, consumers=["fixture"])])
        variants.append([finding, dict(finding)])
        variants.append([])
        variants.append([_finding(policy_epoch_ms, advisory_id=str(index)) for index in range(1, 18)])
        records = [
            _allowed_provenance(lock_bytes, policy_epoch_ms, _identity("5"), _identity("a"), item)
            for item in variants
        ]
        records.append(dict(provenance, audit_status="passed"))
        records.append(dict(provenance, schema_version=1))
        records.append(dict(_provenance(lock_bytes, policy_epoch_ms, _identity("5"), _identity("a")),
                            allowed_findings=[finding]))
        records.append({key: value for key, value in provenance.items() if key != "allowed_findings"})
        for record in records:
            with self.subTest(record=record):
                self.storage = Path(tempfile.mkdtemp(dir=self.root)).resolve(strict=True)
                runner = WorkerHarness(self.project, lock_bytes=lock_bytes)
                with self.assertRaises(subject.NodeContractRefusal) as caught:
                    self._verify(record, runner, lock_bytes)
                self.assertEqual(caught.exception.reason, "accepted_provenance_invalid")
                self.assertEqual(runner.calls, [])

    def test_helper_allowed_counts_must_fit_the_recorded_allows(self):
        lock_bytes, policy_epoch_ms, provenance = self._allow_case()
        plain = _provenance(lock_bytes, policy_epoch_ms, _identity("5"), _identity("a"))
        for record, counts in (
            (plain, {"finding_count": 1, "allowed_count": 1}),
            (provenance, {"finding_count": 2, "allowed_count": 2}),
            (provenance, {"finding_count": 0, "allowed_count": 1}),
            (provenance, {"finding_count": 1, "allowed_count": 0}),
            (provenance, {"finding_count": 1, "allowed_count": 1, "audit_status": "passed"}),
            (provenance, {"finding_count": 0, "allowed_count": 0, "audit_status": "allowed_findings"}),
        ):
            with self.subTest(counts=counts, schema=record["schema_version"]):
                self.storage = Path(tempfile.mkdtemp(dir=self.root)).resolve(strict=True)
                runner = WorkerHarness(self.project, lock_bytes=lock_bytes, **counts)
                with self.assertRaises(subject.NodeContractRefusal) as caught:
                    self._verify(record, runner, lock_bytes)
                self.assertEqual(caught.exception.reason, "capture_invalid")
                self.assertEqual(caught.exception.substage, "bulk_audit")

    def test_bootstrap_never_accepts_allowed_findings_from_the_helper(self):
        runner = WorkerHarness(self.project, finding_count=1, allowed_count=1)
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        self.assertEqual(caught.exception.reason, "capture_invalid")

    def test_unrecorded_finding_refusal_keeps_the_vulnerable_dependency_reason(self):
        lock_bytes, unused, provenance = self._allow_case()
        runner = WorkerHarness(self.project, lock_bytes=lock_bytes, audit_reason="vulnerable_dependency")
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self._verify(provenance, runner, lock_bytes)
        self.assertEqual(caught.exception.reason, "vulnerable_dependency")
        self.assertEqual(caught.exception.completed_stages, ("node_dependency_prepare",))

    def _bootstrap_with_worker_error(self, error, at):
        self.storage = Path(tempfile.mkdtemp(dir=self.root)).resolve(strict=True)
        runner = RaisingWorkerHarness(self.project, error, at)
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        return caught.exception

    def test_worker_exception_carries_only_a_closed_command_check_onto_the_refusal(self):
        for check in sorted(subject.COMMAND_CHECKS):
            for at in ("runtime_version", "npm_version", "lock_generation"):
                with self.subTest(check=check, substage=at):
                    refusal = self._bootstrap_with_worker_error(WorkerError(command_check=check), at)
                    self.assertEqual(refusal.reason, "command_failed")
                    self.assertEqual(refusal.substage, at)
                    self.assertEqual(refusal.command_check, check)
        for unlisted in ("private-" + "value", "", 7, None, b"timeout"):
            with self.subTest(unlisted=unlisted):
                refusal = self._bootstrap_with_worker_error(
                    WorkerError(command_check=unlisted), "lock_generation",
                )
                self.assertEqual(
                    (refusal.reason, refusal.substage, refusal.command_check),
                    ("command_failed", "lock_generation", None),
                )

    def test_cleanup_and_deadline_worker_exceptions_keep_their_reason_without_a_check(self):
        for reason in ("cleanup_incomplete", "deadline_exceeded"):
            with self.subTest(reason=reason):
                refusal = self._bootstrap_with_worker_error(
                    WorkerError(reason=reason, command_check="timeout"), "lock_generation",
                )
                self.assertEqual(refusal.reason, reason)
                self.assertIsNone(refusal.command_check)

    def test_nonzero_stage_exit_is_command_failed_without_a_command_check(self):
        runner = WorkerHarness(self.project, failure="lock_generation")
        with self.assertRaises(subject.NodeContractRefusal) as caught:
            self.call("bootstrap", runner, policy_epoch_ms=int(time.time() * 1000) - 10_000)
        self.assertEqual(caught.exception.reason, "command_failed")
        self.assertIsNone(caught.exception.command_check)

    def test_refusal_constructor_drops_an_unlisted_command_check(self):
        self.assertEqual(
            subject.NodeContractRefusal("command_failed", command_check="spawn_failure").command_check,
            "spawn_failure",
        )
        for unlisted in ("other", 3, None, ("timeout",)):
            with self.subTest(unlisted=unlisted):
                self.assertIsNone(
                    subject.NodeContractRefusal("command_failed", command_check=unlisted).command_check,
                )


class WorkerError(Exception):
    def __init__(self, reason="version_mismatch", command_check=None):
        self.reason = reason
        self.command_check = command_check
        super().__init__(reason)


class RaisingWorkerHarness(WorkerHarness):
    def __init__(self, project, error, at):
        super().__init__(project)
        self.error = error
        self.at = at

    def __call__(self, argv, *, stage, substage, **options):
        if substage == self.at:
            raise self.error
        return super().__call__(argv, stage=stage, substage=substage, **options)


if __name__ == "__main__":
    unittest.main()
