"""Hosted-only orchestration tests for the fixed Node contract stages."""

import base64
import hashlib
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


class WorkerHarness:
    def __init__(self, project, *, lock_bytes=None, failure=None, audit_reason=None,
                 mutate_config_after=None):
        self.project = Path(project)
        self.lock_bytes = lock_bytes or _lock_bytes()
        self.failure = failure
        self.audit_reason = audit_reason
        self.mutate_config_after = mutate_config_after
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
                "audit_status": "passed",
                "package_count": 4,
                "remote_package_count": 1,
                "remote_version_count": 1,
                "advisory_count": 0,
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
            self.call("verify", runner, accepted_lock=lock_bytes, accepted_provenance=provenance)
        self.assertEqual(caught.exception.reason, "tool_unavailable")
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


if __name__ == "__main__":
    unittest.main()
