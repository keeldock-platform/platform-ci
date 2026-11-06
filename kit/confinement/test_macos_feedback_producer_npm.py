import importlib.util
import hashlib
import io
import json
import os
import re
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import npm_admission_bootstrap as bootstrap
import test_confinement_npm_admission_bootstrap as fixtures


MODULE_PATH = Path(__file__).resolve().parent / "macos_feedback_producer.py"
SPEC = importlib.util.spec_from_file_location("macos_feedback_producer_npm_under_test", str(MODULE_PATH))
producer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(producer)

SOURCE = Path("/s")
STORAGE = Path("/w")
NODE = Path("/n/bin/node")
NPM_CLI = Path("/n/lib/node_modules/npm/bin/npm-cli.js")
CONTRACT = SimpleNamespace(
    USER_CONFIG_NAME="npm-user-empty.npmrc", GLOBAL_CONFIG_NAME="npm-global-empty.npmrc",
    EMPTY_CONFIG_BYTES=b"\n", NODE_OPTIONS_VALUE="--import=synthetic",
)


def _dispatch(expiry_offset=3600, **request_changes):
    now = int(time.time())
    request = {
        "source_sha": "a" * 40, "base_sha": "b" * 40, "base_branch": "develop",
        "reviewed_diff_sha256": "c" * 64, "control_sha": "d" * 40, "expiry": now + expiry_offset,
    }
    request.update(request_changes)
    return {
        "profile": producer.PROFILE_BY_KIND["npm_admission"],
        "request": request,
        "context": {"run_id": "9876"},
    }


class ContractRefusal(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@unittest.skipUnless(sys.platform != "win32", "the macOS npm admission producer tests require POSIX paths")
class NpmAdmissionProducerTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.config_calls = []
        self.config_failures = set()
        self.lock_state = None
        self.runner_failures = {}
        self.lock_failure = None
        self.read_failure = None

        def validate(environment, storage, uid, gid, *, stage, substage):
            self.events.append("config")
            self.config_calls.append((dict(environment), Path(storage).as_posix(), uid, gid))
            if len(self.config_calls) in self.config_failures:
                raise ContractRefusal("tool_unavailable")

        def lock_path(project):
            return Path(project) / "package-lock.json"

        def ensure_absent(path, *, reason):
            self.events.append("absent:" + Path(path).as_posix())
            if self.lock_state is not None:
                raise ContractRefusal(self.lock_state)

        self.contract = SimpleNamespace(
            **vars(CONTRACT), _validate_npm_config_files=validate, _lock_path=lock_path,
            _ensure_absent=ensure_absent,
        )
        self.world = fixtures.World(policy_epoch_ms=(int(time.time()) - 3600) * 1000)
        self.written = []
        self.directories = []
        self.commands = []
        self.chdirs = []
        self.version = SimpleNamespace(returncode=0, stdout=(bootstrap.NPM_VERSION + "\n").encode("ascii"))
        self.resolve = SimpleNamespace(returncode=0, stdout=b"")
        self.fetcher = self.world.fetcher()
        self.files = dict(self.world.files)
        self.candidate_file_transform = None

    def test_core_and_runtime_returns_use_the_lock_paths_written_by_npm(self):
        for selector, relative in (
            (bootstrap.CORE_WAVE_70A_FILING, "package-lock.json"),
            (bootstrap.RUNTIME_WAVE_70A_FILING, "runtime/package-lock.json"),
        ):
            with self.subTest(selector=selector), tempfile.TemporaryDirectory() as temporary:
                project = Path(temporary)
                expected = project / relative
                expected.parent.mkdir(parents=True, exist_ok=True)
                expected.write_bytes(b"production lock\n")
                resolved = producer._npm_root_lock_path(
                    project, bootstrap.filing_for(selector),
                )
                self.assertEqual(resolved, expected)
                self.assertEqual(resolved.read_bytes(), b"production lock\n")
                if selector == bootstrap.RUNTIME_WAVE_70A_FILING:
                    self.assertNotEqual(resolved, project / "runtime/runtime/package-lock.json")
                    with self.assertRaises(FileNotFoundError):
                        (project / "runtime/runtime/package-lock.json").read_bytes()

    def run_worker(self, rust, argv, uid, environment, python, capability, stage, deadline, **keywords):
        self.commands.append((tuple(argv), dict(environment), stage, keywords))
        self.events.append("probe" if tuple(argv)[-1] == "--version" else "resolve")
        failure = self.runner_failures.get(self.events[-1])
        if failure is not None:
            raise failure
        return self.version if tuple(argv)[-1] == "--version" else self.resolve

    def read_file(self, path, *, maximum, owner=0):
        if self.read_failure is not None:
            raise self.read_failure
        return self.files[path.relative_to(SOURCE).as_posix()]

    def execute(self, dispatch=None, *, lock=None, **overrides):
        arguments = dict(
            dispatch=dispatch or _dispatch(), source=SOURCE, worker_storage=STORAGE, worker_uid=501,
            environment={"HOME": "/h"}, host_toolchain={"python": "/p"},
            capability=SimpleNamespace(PROBE_PRIMARY_GID=20), rust=SimpleNamespace(), deadline=10 ** 12,
            bootstrap=bootstrap, contract=self.contract, node=NODE, npm_cli=NPM_CLI,
            source_environ={"SOURCE_REPOSITORY_OWNER": "owner", "SOURCE_REPOSITORY_NAME": "name"},
        )
        arguments.update(overrides)

        def read_lock(path, uid, maximum):
            if self.lock_failure is not None:
                raise self.lock_failure
            return lock if lock is not None else self.world.lock_bytes

        def candidate_files(unused_source, unused_sha):
            result = {
                path: (
                    "100644",
                    hashlib.sha1(
                        b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload,
                    ).hexdigest(),
                )
                for path, payload in self.files.items()
            }
            if self.candidate_file_transform is not None:
                self.candidate_file_transform(result)
            return result

        with patch.object(producer, "_read_file", self.read_file), \
                patch.object(producer, "_authenticated_candidate_files", side_effect=candidate_files), \
                patch.object(producer, "_make_worker_directory",
                             lambda path, uid, gid: self.directories.append(Path(path).as_posix())), \
                patch.object(producer, "_write_worker_file",
                             lambda path, payload, uid, gid: self.written.append((Path(path).as_posix(), payload))), \
                patch.object(producer, "_run_worker", self.run_worker), \
                patch.object(producer, "_read_worker_file", read_lock), \
                patch.object(producer.os, "chdir", lambda path: self.chdirs.append(Path(path).as_posix())), \
                patch.object(bootstrap, "RegistryFetcher", lambda deadline=None: self.fetcher):
            return producer.run_npm_admission_profile(**arguments)

    def refusal(self, **keywords):
        with self.assertRaises(producer.FeedbackRefusal) as raised:
            self.execute(**keywords)
        return raised.exception.reason

    def test_a_good_run_resolves_once_and_returns_one_verified_bundle(self):
        result = self.execute()
        self.assertEqual(set(result), {"payload_bytes", "expected_manifest", "reviewed_rust_paths", "source_result"})
        self.assertEqual(result["source_result"], "command_completed")
        self.assertIsNone(result["expected_manifest"])
        lock_bytes, receipt_bytes, evidence_bytes = bootstrap.decode_bundle(result["payload_bytes"])
        self.assertEqual(lock_bytes, self.world.lock_bytes)
        receipt = json.loads(receipt_bytes.decode("ascii"))
        self.assertEqual(receipt["context"]["repository"], "owner/name")
        self.assertEqual(receipt["context"]["filing"], bootstrap.DEFAULT_FILING)
        self.assertEqual(receipt["context"]["source_sha"], "a" * 40)
        self.assertEqual(receipt["context"]["reviewed_diff_fingerprint"], "c" * 64)
        evidence = json.loads(evidence_bytes.decode("ascii"))
        self.assertEqual(evidence["run_id"], "9876")
        self.assertEqual(evidence["totals"]["packages"], 4)
        self.assertEqual(self.chdirs, [(STORAGE / "feedback-npm-admission").as_posix(), SOURCE.as_posix()])

    def test_candidate_input_blob_mismatch_refuses_before_npm_executes(self):
        self.candidate_file_transform = lambda entries: entries.update({
            "package.json": ("100644", "0" * 40),
        })
        self.assertEqual(self.refusal(), "manifest_invalid")
        self.assertEqual(self.commands, [])

    def test_candidate_input_symlink_refuses_before_npm_executes(self):
        self.candidate_file_transform = lambda entries: entries.update({
            "package.json": ("120000", entries["package.json"][1]),
        })
        self.assertEqual(self.refusal(), "manifest_invalid")
        self.assertEqual(self.commands, [])
        self.assertEqual(self.written, [])

    def test_the_fixture_filing_and_the_fixture_repository_id_must_agree_before_any_read(self):
        base = {"SOURCE_REPOSITORY_OWNER": "owner", "SOURCE_REPOSITORY_NAME": "name"}
        env_name = producer.NPM_FIXTURE_REPOSITORY_ID_ENV
        self.assertEqual(env_name, "NPM_FIXTURE_REPOSITORY_ID")
        self.assertEqual(bootstrap.FIXTURE_FILING, "quick-fixture")
        cases = (
            ({"workspace": "quick-fixture"}, {}),
            ({"workspace": "quick-fixture", "repository_id": "5"}, {env_name: ""}),
            ({"workspace": "quick-fixture", "repository_id": "5"}, {env_name: "6"}),
            ({"repository_id": "5"}, {env_name: "5"}),
            ({"workspace": bootstrap.DEFAULT_FILING, "repository_id": "5"}, {env_name: "5"}),
        )
        self.read_failure = producer.FeedbackRefusal("manifest_invalid")
        for changes, extra in cases:
            with self.subTest(changes=changes, extra=extra):
                self.events = []
                self.assertEqual(
                    self.refusal(dispatch=_dispatch(**changes), source_environ={**base, **extra}),
                    "request_invalid",
                )
                self.assertEqual(self.events, [])
        for changes, extra in (
            ({"workspace": "quick-fixture", "repository_id": "5"}, {env_name: "5"}),
            ({"repository_id": "5"}, {env_name: "6"}),
            ({"repository_id": "5"}, {}),
        ):
            with self.subTest(accepted=changes, extra=extra):
                self.assertEqual(
                    self.refusal(dispatch=_dispatch(**changes), source_environ={**base, **extra}),
                    "manifest_invalid",
                )

    def test_only_the_inert_inputs_reach_the_worker_and_never_the_request_table(self):
        self.execute()
        project = STORAGE / "feedback-npm-admission"
        names = sorted(path[len(project.as_posix()) + 1:] for path, payload in self.written if path.startswith(project.as_posix()))
        self.assertEqual(names, sorted(bootstrap.project_paths(bootstrap.DEFAULT_FILING)))
        for path, payload in self.written:
            if path.startswith(project.as_posix()):
                self.assertEqual(payload, self.files[path[len(project.as_posix()) + 1:]])
        request_doc = bootstrap.FILINGS[bootstrap.DEFAULT_FILING]["request_doc"]
        self.assertFalse([path for path, payload in self.written if path.endswith(request_doc)])
        config_payloads = [payload for path, payload in self.written if path.startswith((STORAGE / "npm-admission-home").as_posix())]
        self.assertEqual(config_payloads, [b"\n", b"\n"])

    def test_one_version_probe_then_one_resolver_command_in_a_fixed_environment(self):
        self.execute()
        self.assertEqual(len(self.commands), 2)
        (probe, probe_environment, probe_stage, probe_options), (command, environment, stage, options) = self.commands
        self.assertEqual(probe, (str(NODE), str(NPM_CLI), "--version"))
        self.assertEqual((probe_stage, stage), ("feedback_lock", "feedback_lock"))
        self.assertEqual(options["timeout"], producer.NPM_RESOLVE_SECONDS)
        self.assertEqual(probe_options["timeout"], producer.NPM_VERSION_SECONDS)
        self.assertTrue(options["allow_nonzero_capture"])
        self.assertEqual(command[:2], (str(NODE), str(NPM_CLI)))
        for flag in ("--ignore-scripts", "--strict-peer-deps", "--package-lock-only", "--min-release-age=7"):
            self.assertIn(flag, command)
        self.assertEqual(len([part for part in command if part.startswith("--before=")]), 1)
        self.assertEqual(environment, probe_environment)
        self.assertEqual(environment["npm_config_registry"], bootstrap.REGISTRY_URL)
        self.assertEqual(environment["NODE_OPTIONS"], CONTRACT.NODE_OPTIONS_VALUE)
        self.assertEqual(environment["npm_config_ignore_scripts"], "true")
        self.assertNotIn("HOME_INHERITED", environment)
        self.assertEqual(environment["HOME"], str(STORAGE / "npm-admission-home" / "home"))

    def test_the_empty_npm_settings_are_rechecked_around_every_worker_command(self):
        self.execute()
        lock_path = (STORAGE / "feedback-npm-admission" / "package-lock.json").as_posix()
        self.assertEqual(
            self.events, ["config", "probe", "config", "absent:" + lock_path, "resolve", "config"],
        )
        home = STORAGE / "npm-admission-home"
        for environment, storage, uid, gid in self.config_calls:
            self.assertEqual(storage, home.as_posix())
            self.assertEqual((uid, gid), (501, 20))
            self.assertEqual(environment["npm_config_userconfig"], str(home / CONTRACT.USER_CONFIG_NAME))
            self.assertEqual(environment["npm_config_globalconfig"], str(home / CONTRACT.GLOBAL_CONFIG_NAME))

    def test_a_changed_npm_setting_stops_the_run_at_that_point(self):
        lock_path = (STORAGE / "feedback-npm-admission" / "package-lock.json").as_posix()
        full = ["config", "probe", "config", "absent:" + lock_path, "resolve", "config"]
        for failing, expected in ((1, full[:1]), (2, full[:3]), (3, full)):
            with self.subTest(failing=failing):
                self.events = []
                self.config_calls = []
                self.config_failures = {failing}
                self.assertEqual(self.refusal(), "tool_unavailable")
                self.assertEqual(self.events, expected)
                self.assertEqual(self.chdirs[-1], SOURCE.as_posix())
                self.assertEqual(self.fetcher.calls, [])

    def test_an_existing_lock_stops_the_run_before_the_resolver(self):
        self.lock_state = "lock_already_present"
        self.assertEqual(self.refusal(), "manifest_invalid")
        self.assertNotIn("resolve", self.events)
        self.assertEqual(self.fetcher.calls, [])
        self.lock_state = "tool_unavailable"
        self.events = []
        self.assertEqual(self.refusal(), "tool_unavailable")
        self.assertNotIn("resolve", self.events)
        self.assertEqual(self.chdirs[-1], SOURCE.as_posix())

    def test_a_wrong_profile_or_missing_tools_refuse_before_anything_runs(self):
        wrong = dict(_dispatch(), profile=producer.PROFILE_BY_KIND["cargo_lock"])
        self.assertEqual(self.refusal(dispatch=wrong), "request_invalid")
        self.assertEqual(self.refusal(node=None), "request_invalid")
        self.assertEqual(self.refusal(npm_cli=None), "request_invalid")
        self.assertEqual(self.refusal(source_environ=None), "request_invalid")
        self.assertEqual(self.commands, [])
        self.assertEqual(self.written, [])

    def test_bad_inputs_refuse_before_the_worker_or_the_network(self):
        self.files["package.json"] = b'{"name":"other"}'
        self.assertEqual(self.refusal(), "manifest_invalid")
        self.assertEqual(self.commands, [])
        self.assertEqual(self.fetcher.calls, [])
        self.files = dict(self.world.files)
        self.files[".npmrc"] = b"registry=other\n"
        self.assertEqual(self.refusal(), "manifest_invalid")
        self.files = dict(self.world.files)
        self.assertEqual(self.refusal(dispatch=_dispatch(workspace="other-filing")), "manifest_invalid")
        self.assertEqual(self.commands, [])
        self.assertEqual(self.written, [])

    def test_resolver_failures_map_to_fixed_producer_reasons(self):
        self.resolve = SimpleNamespace(returncode=1, stdout=b"")
        self.assertEqual(self.refusal(), "command_failed")
        self.assertEqual(self.chdirs[-1], SOURCE.as_posix())
        self.resolve = SimpleNamespace(returncode=0, stdout=b"")
        self.version = SimpleNamespace(returncode=0, stdout=b"11.0.0\n")
        self.assertEqual(self.refusal(), "tool_unavailable")
        self.version = SimpleNamespace(returncode=1, stdout=b"11.19.1\n")
        self.assertEqual(self.refusal(), "tool_unavailable")
        self.assertEqual(self.chdirs[-1], SOURCE.as_posix())

    def test_lock_and_evidence_failures_map_to_fixed_producer_reasons(self):
        other = json.loads(self.world.lock_bytes.decode("ascii"))
        other["packages"][""]["devDependencies"] = {"alpha-pkg": "1.0.0"}
        self.assertEqual(self.refusal(lock=fixtures._json(other) + b"\n"), "payload_invalid")
        self.assertEqual(self.refusal(lock=b"not a lock"), "payload_invalid")

    def test_network_and_clock_failures_are_command_failures(self):
        def failing(name):
            raise bootstrap.BootstrapRefusal("npm_network_refused")

        self.fetcher.packument = failing
        self.assertEqual(self.refusal(), "command_failed")
        self.fetcher = self.world.fetcher()
        self.assertEqual(self.refusal(dispatch=_dispatch(expiry_offset=10 ** 6)), "command_failed")

    def test_advisory_and_age_failures_are_payload_failures(self):
        self.fetcher.advisory = json.dumps({"alpha-pkg": [
            {"id": 1, "severity": "critical", "vulnerable_versions": "<2.0.0"},
        ]}).encode("ascii")
        self.assertEqual(self.refusal(), "payload_invalid")
        self.fetcher = self.world.fetcher()
        self.fetcher.packuments["beta-pkg"] = self.fetcher.packuments["beta-pkg"].replace(
            b"2026-06-01T12:00:00.000Z", fixtures._iso(int(time.time()) - 86400).encode("ascii"),
        )
        self.assertEqual(self.refusal(), "payload_invalid")

    def tags(self, **keywords):
        with self.assertRaises(producer.FeedbackRefusal) as raised:
            self.execute(**keywords)
        error = raised.exception
        return error.reason, getattr(error, "source_gates_step", None), getattr(error, "source_gates_key", None)

    @staticmethod
    def runner_refusal(reason, check=None):
        error = producer.FeedbackRefusal(reason)
        if check is not None:
            error.command_check = check
        return error

    def test_input_and_config_steps_are_tagged_with_the_original_reason(self):
        self.files["package.json"] = b'{"name":"other"}'
        reason, step, key = self.tags()
        self.assertEqual((reason, step), ("manifest_invalid", "npm_inputs"))
        self.assertIn(key, bootstrap.REASONS)
        self.files = dict(self.world.files)
        self.files[".npmrc"] = b"registry=other\n"
        self.assertEqual(self.tags()[:2], ("manifest_invalid", "npm_inputs"))
        self.files = dict(self.world.files)
        self.assertEqual(
            self.tags(dispatch=_dispatch(workspace="other-filing"))[:2], ("manifest_invalid", "npm_inputs"),
        )
        self.read_failure = producer.FeedbackRefusal("manifest_invalid")
        self.assertEqual(self.tags(), ("manifest_invalid", "npm_inputs", "manifest_invalid"))
        self.read_failure = None
        with patch.object(producer, "_write_project_files", side_effect=producer.FeedbackRefusal("output_unavailable")):
            self.assertEqual(self.tags(), ("output_unavailable", "npm_config", "output_unavailable"))
        for failing_call in (1, 2, 3):
            self.config_calls = []
            self.config_failures = {failing_call}
            self.assertEqual(self.tags(), ("tool_unavailable", "npm_config", "tool_unavailable"))
        self.config_failures = set()
        self.lock_state = "lock_already_present"
        self.assertEqual(self.tags(), ("manifest_invalid", "npm_config", "manifest_invalid"))
        self.lock_state = "tool_unavailable"
        self.assertEqual(self.tags(), ("tool_unavailable", "npm_config", "tool_unavailable"))

    def test_the_stale_filing_is_an_inputs_step_refusal(self):
        stale = bootstrap.BootstrapRefusal("npm_stale")
        with patch.object(bootstrap, "check_policy_time", side_effect=stale):
            self.assertEqual(self.tags(), ("command_failed", "npm_inputs", "npm_stale"))
        self.assertEqual(self.commands, [])
        self.assertEqual(self.written, [])

    def test_the_version_probe_step_is_tagged(self):
        self.version = SimpleNamespace(returncode=1, stdout=b"11.19.1\n")
        self.assertEqual(self.tags(), ("tool_unavailable", "npm_version", "nonzero_exit"))
        self.version = SimpleNamespace(returncode=0, stdout=b"11.0.0\n")
        self.assertEqual(self.tags(), ("tool_unavailable", "npm_version", "mismatch"))
        self.version = SimpleNamespace(returncode=0, stdout=(bootstrap.NPM_VERSION + "\n").encode("ascii"))
        cases = (
            ("command_failed", "timeout", "timeout"), ("command_failed", "spawn_failure", "spawn"),
            ("command_failed", None, "runner"), ("command_failed", "helper_failure", "runner"),
            ("capture_invalid", None, "capture_invalid"),
        )
        for reason, check, key in cases:
            with self.subTest(reason=reason, check=check):
                self.runner_failures = {"probe": self.runner_refusal(reason, check)}
                self.assertEqual(self.tags(), (reason, "npm_version", key))
        self.runner_failures = {"probe": self.runner_refusal("cleanup_incomplete")}
        self.assertEqual(self.tags()[0], "cleanup_incomplete")

    def test_the_real_runner_wrapper_carries_only_a_timeout_or_spawn_check(self):
        for check, expected in (("timeout", "timeout"), ("spawn_failure", "spawn_failure"),
                                ("nonzero_exit", None), ("private", None), (7, None), (None, None)):
            error = ContractRefusal("version_mismatch")
            error.command_check = check
            rust = SimpleNamespace(_run_worker_command=lambda *a, **k: (_ for _ in ()).throw(error))
            with self.subTest(check=check), self.assertRaises(producer.FeedbackRefusal) as raised:
                producer._run_worker(
                    rust, ("a",), 501, {}, "/p", SimpleNamespace(), "feedback_lock", 10 ** 12,
                )
            self.assertEqual(raised.exception.reason, "command_failed")
            self.assertEqual(getattr(raised.exception, "command_check", None), expected)

    def test_resolve_failures_map_allowlisted_npm_codes_to_lowercase_tokens(self):
        for code in producer.NPM_ERROR_CODES:
            stderr = b"npm error code " + code.encode("ascii") + b"\nnpm error detail text\n"
            with self.subTest(code=code):
                self.resolve = SimpleNamespace(returncode=1, stdout=b"", stderr=stderr)
                self.assertEqual(self.tags(), ("command_failed", "npm_resolve", code.lower()))
        self.resolve = SimpleNamespace(
            returncode=1, stdout=b"", stderr=b"npm warn x\r\nnpm ERR! code ETARGET\r\nnpm error code E404\n",
        )
        self.assertEqual(self.tags(), ("command_failed", "npm_resolve", "etarget"))

    def test_resolve_failures_with_unknown_or_missing_codes_map_to_other(self):
        for stderr in (
            b"", b"boom", b"npm error code EWEIRD\n", b"npm error code " + b"E" * 33 + b"\n",
            b"npm error code eresolve\n", b"prefix npm error code ERESOLVE\n",
            b"npm error code ERESOLVE trailing\n", b"npm error code \xff\xfe\n", b"\x00" * 64,
        ):
            with self.subTest(stderr=stderr[:20]):
                self.resolve = SimpleNamespace(returncode=2, stdout=b"", stderr=stderr)
                self.assertEqual(self.tags(), ("command_failed", "npm_resolve", "other"))
        for stderr in (None, "npm error code ERESOLVE\n", bytearray(b"npm error code ERESOLVE\n")):
            self.resolve = SimpleNamespace(returncode=1, stdout=b"", stderr=stderr)
            self.assertEqual(self.tags(), ("command_failed", "npm_resolve", "other"))

    def test_resolve_runner_failures_are_tagged(self):
        cases = (
            ("command_failed", "timeout", "timeout"), ("command_failed", "spawn_failure", "spawn"),
            ("command_failed", None, "runner"), ("capture_invalid", None, "capture_invalid"),
        )
        for reason, check, key in cases:
            with self.subTest(reason=reason, check=check):
                self.runner_failures = {"resolve": self.runner_refusal(reason, check)}
                self.assertEqual(self.tags(), (reason, "npm_resolve", key))

    def test_hostile_resolver_output_never_reaches_the_published_tags(self):
        canary = "hostile-canary-7f3a-secret-token"
        stderr = (
            "npm error code ERESOLVE\nnpm error " + canary + "\nnpm error code " + canary.upper().replace("-", "_")
            + "\nnpm error path /private/" + canary + "\n"
        ).encode("ascii")
        self.resolve = SimpleNamespace(returncode=1, stdout=canary.encode("ascii"), stderr=stderr)
        with self.assertRaises(producer.FeedbackRefusal) as raised:
            self.execute()
        error = raised.exception
        published = repr((error.reason, error.detail, error.source_gates_step, error.source_gates_key,
                          str(error), sorted(vars(error))))
        self.assertNotIn(canary, published)
        self.assertNotIn(canary.upper().replace("-", "_"), published)
        self.assertEqual(error.source_gates_key, "eresolve")
        self.assertEqual(self.resolve_token(b"npm error code " + canary.upper().replace("-", "_").encode("ascii")), "other")
        import macos_core_contract as core

        self.assertIn((error.source_gates_step, error.source_gates_key), core.SOURCE_GATES_STEP_DIAGNOSTICS_BY_KEY)
        for diagnostic in core.SOURCE_GATES_STEP_DIAGNOSTICS:
            self.assertNotIn("hostile", diagnostic)
            self.assertRegex(diagnostic, r"\Asource_gates_[a-z0-9_]+\Z")

    def resolve_token(self, stderr):
        return producer._npm_resolve_reason(SimpleNamespace(stderr=stderr))

    def test_the_lock_step_is_tagged_with_the_original_reason(self):
        other = json.loads(self.world.lock_bytes.decode("ascii"))
        other["packages"][""]["devDependencies"] = {"alpha-pkg": "1.0.0"}
        self.assertEqual(
            self.tags(lock=fixtures._json(other) + b"\n"), ("payload_invalid", "npm_lock", "npm_lock_refused"),
        )
        reason, step, key = self.tags(lock=b"not a lock")
        self.assertEqual((reason, step), ("payload_invalid", "npm_lock"))
        self.assertIn(key, ("npm_lock_refused", "npm_payload_too_large"))
        self.assertEqual(self.fetcher.calls, [])
        self.lock_failure = producer.FeedbackRefusal("capture_invalid")
        self.assertEqual(self.tags(), ("capture_invalid", "npm_lock", "capture_invalid"))

    def test_the_bundle_step_keeps_the_original_bootstrap_reason(self):
        def failing(name):
            raise bootstrap.BootstrapRefusal("npm_network_refused")

        self.fetcher.packument = failing
        self.assertEqual(self.tags(), ("command_failed", "npm_bundle", "npm_network_refused"))
        self.fetcher = self.world.fetcher()
        self.assertEqual(
            self.tags(dispatch=_dispatch(expiry_offset=10 ** 6))[:2], ("command_failed", "npm_bundle"),
        )
        self.fetcher = self.world.fetcher()
        self.fetcher.advisory = json.dumps({"alpha-pkg": [
            {"id": 1, "severity": "critical", "vulnerable_versions": "<2.0.0"},
        ]}).encode("ascii")
        reason, step, key = self.tags()
        self.assertEqual((reason, step), ("payload_invalid", "npm_bundle"))
        self.assertIn(key, bootstrap.REASONS)

    def test_bootstrap_reasons_are_preserved_in_the_tag_and_untagged_without_a_step(self):
        import macos_core_contract as core

        self.assertEqual(set(core.SOURCE_GATES_NPM_BUNDLE_REASONS), set(bootstrap.REASONS))
        for reason in sorted(bootstrap.REASONS):
            with self.subTest(reason=reason):
                self.assertIn(("npm_bundle", reason), core.SOURCE_GATES_STEP_DIAGNOSTICS_BY_KEY)
                with self.assertRaises(producer.FeedbackRefusal) as raised:
                    producer._npm_bootstrap_refusal(bootstrap.BootstrapRefusal(reason), "npm_bundle")
                self.assertEqual(raised.exception.source_gates_step, "npm_bundle")
                self.assertEqual(raised.exception.source_gates_key, reason)
                with self.assertRaises(producer.FeedbackRefusal) as plain:
                    producer._npm_bootstrap_refusal(bootstrap.BootstrapRefusal(reason))
                self.assertIsNone(getattr(plain.exception, "source_gates_step", None))
                self.assertEqual(plain.exception.reason, raised.exception.reason)
        with self.assertRaises(producer.FeedbackRefusal) as unknown:
            producer._npm_bootstrap_refusal(Exception("hostile-text"), "npm_bundle")
        self.assertEqual((unknown.exception.reason, getattr(unknown.exception, "source_gates_step", None)),
                         ("payload_invalid", None))

    def test_the_producer_tokens_equal_the_core_vocabulary(self):
        import macos_core_contract as core

        self.assertEqual(
            core.SOURCE_GATES_NPM_RESOLVE_CODES,
            tuple(code.lower() for code in producer.NPM_ERROR_CODES) + ("other",),
        )
        self.assertEqual(
            [step for step, keys in core.SOURCE_GATES_NPM_KEYS_BY_STEP],
            ["npm_inputs", "npm_config", "npm_version", "npm_resolve", "npm_lock", "npm_bundle"],
        )

    def test_reason_mapping_covers_every_bootstrap_reason_with_a_producer_reason(self):
        allowed = {"manifest_invalid", "tool_unavailable", "command_failed", "payload_invalid"}
        for reason in sorted(bootstrap.REASONS):
            with self.subTest(reason=reason):
                with self.assertRaises(producer.FeedbackRefusal) as raised:
                    producer._npm_bootstrap_refusal(bootstrap.BootstrapRefusal(reason))
                self.assertIn(raised.exception.reason, allowed)

    def failure(self, **keywords):
        with self.assertRaises(producer.FeedbackRefusal) as raised:
            self.execute(**keywords)
        return raised.exception

    @staticmethod
    def sections(payload):
        lines = payload.decode("utf-8").split("\n")
        tail = lines.pop()
        assert tail == ""
        index = lines.index("report:")
        return lines[0], lines[2:index], lines[index + 1:]

    def test_a_resolve_failure_carries_one_bounded_diagnostic_and_converts_to_a_producer_result(self):
        self.resolve = SimpleNamespace(returncode=1, stdout=b"", stderr=(
            b"npm warn peer x@1.0.0\nnpm error code ERESOLVE\nnpm error While resolving: a@1.0.0\n"
            b"npm error Found: b@2.0.0\nnpm error Could not resolve dependency:\nunrelated line\n"
            b"npm error Conflicting peer dependency: c@3.0.0\n"
        ))
        with patch.object(producer, "_npm_read_report", return_value=b"While resolving: a@1.0.0\nFound: b@2.0.0\n"):
            error = self.failure()
        self.assertEqual(
            (error.reason, error.source_gates_step, error.source_gates_key),
            ("command_failed", "npm_resolve", "eresolve"),
        )
        header, stderr, report = self.sections(error.npm_diagnostic)
        self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=eresolve")
        self.assertEqual(stderr, [
            "  npm warn peer x@1.0.0", "  npm error code ERESOLVE", "  npm error While resolving: a@1.0.0",
            "  npm error Found: b@2.0.0", "  npm error Could not resolve dependency:",
            "  npm error Conflicting peer dependency: c@3.0.0",
        ])
        self.assertEqual(report, ["  While resolving: a@1.0.0", "  Found: b@2.0.0"])
        result = producer.npm_diagnostic_result(error)
        self.assertEqual(set(result), {
            "payload_bytes", "expected_manifest", "reviewed_rust_paths", "source_result", "npm_diagnostic",
        })
        self.assertEqual(result["payload_bytes"], error.npm_diagnostic)
        self.assertEqual(result["source_result"], "npm_diagnostic")
        self.assertEqual(result["npm_diagnostic"], ("npm_resolve", "eresolve"))
        self.assertIsNone(result["expected_manifest"])
        self.assertIsNone(result["reviewed_rust_paths"])
        self.assertEqual(self.chdirs[-1], SOURCE.as_posix())

    def test_the_diagnostic_is_read_from_this_runs_own_npm_cache_logs_directory(self):
        self.resolve = SimpleNamespace(returncode=1, stdout=b"", stderr=b"npm error code ERESOLVE\n")
        with patch.object(producer, "_npm_read_report", return_value=None) as reader:
            self.failure()
        reader.assert_called_once_with(STORAGE / "npm-admission-home", 501)

    def test_hostile_resolver_output_is_screened_escaped_and_bounded_in_the_diagnostic(self):
        stderr = b"".join(line + b"\n" for line in (
            b"npm error code ERESOLVE",
            b"npm error token: " + b"a" * 16,
            b"npm error ghp_" + b"A" * 24,
            b"npm error https://user:pw@host.example/x",
            b"npm error path /var/folders/xx",
            b"npm error see ~/.npmrc here",
            b"npm error \x1b[31mred\x00\x85 end",
            b"npm error " + b"x" * 5000,
            b"npm warn bad \xff\xfe bytes",
            "npm error bidi \u202e text".encode("utf-8"),
            b"this is not an npm line",
            b"  npm error indented does not match",
        ))
        self.resolve = SimpleNamespace(returncode=1, stdout=b"", stderr=stderr)
        report = b"Found: a@1\ntoken: abcdefghijklmnop\nnote /mnt/someone/project\nfine line\n"
        with patch.object(producer, "_npm_read_report", return_value=report):
            error = self.failure()
        text = error.npm_diagnostic.decode("utf-8")
        for leaked in ("ghp_", "token: a", "/var/folders", ".npmrc", "user:pw", "/mnt/someone", "\u202e", "\x1b",
                       "\x00", "\x85", "not an npm line", "indented does not match", "abcdefghijklmnop"):
            self.assertNotIn(leaked, text)
        self.assertIn("\\u{1b}", text)
        self.assertIn("\\u{00}", text)
        self.assertIn("\\u{202e}", text)
        header, stderr_lines, report_lines = self.sections(error.npm_diagnostic)
        self.assertEqual(max(len(line) for line in stderr_lines), 2002)
        self.assertEqual(stderr_lines[-2:], ["  [omitted 5 lines]", "  [truncated]"])
        self.assertEqual(report_lines, ["  Found: a@1", "  fine line", "  [omitted 2 lines]"])
        self.assertLessEqual(len(error.npm_diagnostic), producer.NPM_DIAGNOSTIC_MAX_BYTES)
        self.assertLessEqual(text.count("\n"), producer.NPM_DIAGNOSTIC_MAX_LINES)
        published = repr((error.reason, error.detail, error.source_gates_step, error.source_gates_key, str(error)))
        self.assertNotIn("ghp_", published)

    def test_a_credential_split_across_lines_fails_closed_to_the_plain_refusal(self):
        self.resolve = SimpleNamespace(returncode=1, stdout=b"", stderr=b"npm error code ERESOLVE\n")
        with patch.object(producer, "_npm_read_report", return_value=b"token:\nabcdefghijklmnop\n"):
            error = self.failure()
        self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                         ("command_failed", "npm_resolve", "eresolve"))
        self.assertIsNone(getattr(error, "npm_diagnostic", None))
        with self.assertRaises(producer.FeedbackRefusal) as raised:
            producer.npm_diagnostic_result(error)
        self.assertIs(raised.exception, error)

    def test_a_failing_diagnostic_builder_leaves_the_plain_refusal_unchanged(self):
        self.resolve = SimpleNamespace(returncode=1, stdout=b"", stderr=b"npm error code ERESOLVE\n")
        with patch.object(producer, "build_npm_diagnostic_payload", side_effect=RuntimeError("hostile")):
            error = self.failure()
        self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                         ("command_failed", "npm_resolve", "eresolve"))
        self.assertFalse(hasattr(error, "npm_diagnostic"))

    def test_a_good_run_has_no_diagnostic_and_never_reads_the_report(self):
        with patch.object(producer, "_npm_read_report", side_effect=AssertionError("unused")):
            result = self.execute()
        self.assertEqual(result["source_result"], "command_completed")
        self.assertNotIn("npm_diagnostic", result)
        self.assertTrue(result["payload_bytes"].startswith(b"{"))
        self.assertFalse(result["payload_bytes"].startswith(b"KD-NPM-DIAGNOSTICS"))
        lock_bytes, receipt_bytes, evidence_bytes = bootstrap.decode_bundle(result["payload_bytes"])
        self.assertEqual(lock_bytes, self.world.lock_bytes)

    def test_the_lock_step_failure_carries_a_diagnostic_with_the_resolver_warnings(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"npm warn deprecated a@1.0.0: old\nnoise\n")
        other = json.loads(self.world.lock_bytes.decode("ascii"))
        other["packages"][""]["devDependencies"] = {"alpha-pkg": "1.0.0"}
        with patch.object(producer, "_npm_read_report", return_value=None):
            error = self.failure(lock=fixtures._json(other) + b"\n")
        self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                         ("payload_invalid", "npm_lock", "npm_lock_refused"))
        header, stderr, report = self.sections(error.npm_diagnostic)
        self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_lock reason=npm_lock_refused")
        self.assertEqual(len(stderr), 2)
        self.assertTrue(stderr[0].startswith("  kd-check "))
        self.assertEqual(stderr[1], "  npm warn deprecated a@1.0.0: old")
        self.assertEqual(report, [])
        self.assertEqual(producer.npm_diagnostic_result(error)["npm_diagnostic"], ("npm_lock", "npm_lock_refused"))
        self.lock_failure = producer.FeedbackRefusal("capture_invalid")
        error = self.failure()
        self.assertEqual((error.reason, error.source_gates_key), ("capture_invalid", "capture_invalid"))
        self.assertEqual(self.sections(error.npm_diagnostic)[0],
                         "KD-NPM-DIAGNOSTICS schema=1 step=npm_lock reason=capture_invalid")

    def test_the_lock_step_diagnostic_carries_the_check_as_its_first_stderr_line(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"npm warn deprecated a@1.0.0: old\n")
        other = json.loads(self.world.lock_bytes.decode("ascii"))
        other["packages"].pop("node_modules/alpha-pkg")
        with patch.object(producer, "_npm_read_report", return_value=None):
            error = self.failure(lock=fixtures._json(other) + b"\n")
        self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                         ("payload_invalid", "npm_lock", "npm_lock_refused"))
        header, stderr, report = self.sections(error.npm_diagnostic)
        self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_lock reason=npm_lock_refused")
        self.assertEqual(stderr, ["  kd-check direct_missing:alpha-pkg", "  npm warn deprecated a@1.0.0: old"])
        self.assertEqual(report, [])
        result = producer.npm_diagnostic_result(error)
        self.assertEqual(result["npm_diagnostic"], ("npm_lock", "npm_lock_refused"))
        self.assertEqual(result["payload_bytes"], error.npm_diagnostic)

    def test_a_lock_refusal_with_an_unsafe_check_keeps_the_diagnostic_without_the_check(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"npm warn deprecated a@1.0.0: old\n")
        for hostile in ("bad\nline", "caf" + chr(233), "x" * 600, "direct_missing:a b c", "direct_missing:x found:"):
            with self.subTest(check=hostile):
                refusal = bootstrap.BootstrapRefusal("npm_lock_refused", "lock_empty")
                refusal.detail = hostile
                with patch.object(bootstrap, "check_lock", side_effect=refusal):
                    error = self.failure()
                self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                                 ("payload_invalid", "npm_lock", "npm_lock_refused"))
                header, stderr, report = self.sections(error.npm_diagnostic)
                self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_lock reason=npm_lock_refused")
                self.assertEqual(stderr, ["  npm warn deprecated a@1.0.0: old"])
                self.assertNotIn(b"kd-check", error.npm_diagnostic)
                self.assertEqual(producer.npm_diagnostic_result(error)["npm_diagnostic"], ("npm_lock", "npm_lock_refused"))

    def test_the_public_outcome_does_not_depend_on_whether_the_check_was_kept(self):
        outcomes = []
        for check in ("direct_missing:alpha-pkg", "bad\nline"):
            refusal = bootstrap.BootstrapRefusal("npm_lock_refused", "lock_empty")
            refusal.detail = check
            with patch.object(bootstrap, "check_lock", side_effect=refusal):
                error = self.failure()
            outcomes.append((
                error.reason, error.detail, error.source_gates_step, error.source_gates_key, str(error),
                producer.npm_diagnostic_result(error)["npm_diagnostic"],
            ))
        self.assertEqual(outcomes[0], outcomes[1])

    def test_the_capture_retries_once_without_a_rejected_check_and_keeps_the_stderr(self):
        with patch.object(producer, "_npm_read_report", return_value=None):
            payload = producer._npm_capture_diagnostic(
                "npm_lock", "npm_lock_refused", _stderr(b"npm warn peer b@2"), "/s", 501, "bad\nline",
            )
        self.assertIsNotNone(payload)
        self.assertNotIn(b"kd-check", payload)
        self.assertIn(b"  npm warn peer b@2\n", payload)
        with patch.object(producer, "_npm_read_report", return_value=None):
            payload = producer._npm_capture_diagnostic(
                "npm_lock", "npm_lock_refused", _stderr(b"npm warn peer b@2"), "/s", 501, "lock_empty",
            )
        self.assertIn(b"  kd-check lock_empty\n", payload)
        with patch.object(producer, "_npm_read_report", side_effect=OSError("x")):
            self.assertIsNone(producer._npm_capture_diagnostic("npm_lock", "npm_lock_refused", None, "/s", 501, "lock_empty"))
        with patch.object(producer, "_npm_read_report", return_value=None):
            self.assertIsNone(producer._npm_capture_diagnostic("npm_lock", "BAD KEY", None, "/s", 501, "lock_empty"))

    def test_only_the_lock_step_carries_a_check_and_a_refusal_without_one_adds_no_line(self):
        refusal = bootstrap.BootstrapRefusal("npm_lock_refused")
        with patch.object(bootstrap, "check_lock", side_effect=refusal):
            error = self.failure()
        self.assertEqual(self.sections(error.npm_diagnostic)[1], [])
        refusal = bootstrap.BootstrapRefusal("npm_payload_too_large", "lock_empty")
        with patch.object(bootstrap, "check_lock", side_effect=refusal):
            error = self.failure()
        self.assertNotIn(b"kd-check", error.npm_diagnostic)

    def test_the_bundle_step_failure_carries_a_diagnostic_with_the_bootstrap_reason(self):
        def failing(name):
            raise bootstrap.BootstrapRefusal("npm_network_refused")

        self.fetcher.packument = failing
        error = self.failure()
        self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                         ("command_failed", "npm_bundle", "npm_network_refused"))
        self.assertEqual(self.sections(error.npm_diagnostic)[0],
                         "KD-NPM-DIAGNOSTICS schema=1 step=npm_bundle reason=npm_network_refused")
        self.assertEqual(producer.npm_diagnostic_result(error)["npm_diagnostic"],
                         ("npm_bundle", "npm_network_refused"))

    def bundle_refusal(self, detail, reason="npm_network_refused"):
        refusal = bootstrap.BootstrapRefusal(reason)
        refusal.detail = detail

        def failing(name):
            raise refusal

        self.fetcher.packument = failing

    def test_the_bundle_step_diagnostic_carries_the_check_as_its_first_stderr_line(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"npm warn deprecated a@1.0.0: old\n")
        check = bootstrap.bundle_detail("fetch", "alpha-pkg", "404")
        self.assertEqual(check, "fetch:alpha-pkg:404")
        self.bundle_refusal(check)
        with patch.object(producer, "_npm_read_report", return_value=None):
            error = self.failure()
        self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                         ("command_failed", "npm_bundle", "npm_network_refused"))
        header, stderr, report = self.sections(error.npm_diagnostic)
        self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_bundle reason=npm_network_refused")
        self.assertEqual(stderr[0], "  kd-check fetch:alpha-pkg:404")
        self.assertEqual(report, [])
        self.assertEqual(producer.npm_diagnostic_result(error)["npm_diagnostic"],
                         ("npm_bundle", "npm_network_refused"))

    def test_the_bundle_public_outcome_does_not_depend_on_whether_the_check_was_kept(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"npm warn deprecated a@1.0.0: old\n")
        outcomes = []
        for check in ("fetch:alpha-pkg:404", "bad\nline", None):
            self.fetcher = self.world.fetcher()
            self.bundle_refusal(check)
            with patch.object(producer, "_npm_read_report", return_value=None):
                error = self.failure()
            outcomes.append((
                error.reason, error.detail, error.source_gates_step, error.source_gates_key, str(error),
                error.args, producer.npm_diagnostic_result(error)["npm_diagnostic"],
            ))
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertEqual(outcomes[0], outcomes[2])
        self.assertNotIn("alpha-pkg", repr(outcomes[0]))

    def test_an_unsafe_bundle_check_keeps_the_diagnostic_without_the_check(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"npm warn deprecated a@1.0.0: old\n")
        for hostile in ("bad\nline", "caf" + chr(233), "x" * 600, "fetch:a b", "fetch:x found:", 7, b"fetch"):
            with self.subTest(check=hostile):
                self.fetcher = self.world.fetcher()
                self.bundle_refusal(hostile)
                with patch.object(producer, "_npm_read_report", return_value=None):
                    error = self.failure()
                header, stderr, report = self.sections(error.npm_diagnostic)
                self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_bundle reason=npm_network_refused")
                self.assertEqual(stderr, ["  npm warn deprecated a@1.0.0: old"])

    def bundle_refusal_details(self, details, reason="npm_archive_refused"):
        refusal = bootstrap.BootstrapRefusal(reason, details[0])
        refusal.details = tuple(details)

        def failing(name):
            raise refusal

        self.fetcher.packument = failing

    def test_every_collected_bundle_check_reaches_the_diagnostic_in_order(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"npm warn deprecated a@1.0.0: old\n")
        details = [
            "shared_parser:npm_archive_invalid:archive_root:" + "pkg-%02d@1.0.0" % index + ":aria-query index:0"
            for index in range(20)
        ]
        self.bundle_refusal_details(details)
        with patch.object(producer, "_npm_read_report", return_value=None):
            error = self.failure()
        self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                         ("payload_invalid", "npm_bundle", "npm_archive_refused"))
        header, stderr, report = self.sections(error.npm_diagnostic)
        self.assertEqual(stderr[:20], ["  kd-check " + detail for detail in details])
        self.assertEqual(stderr[20:], ["  npm warn deprecated a@1.0.0: old"])
        self.assertEqual(error.npm_diagnostic.count(b"kd-check"), 20)

    def test_a_collected_bundle_check_list_that_is_refused_drops_every_check_line(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"npm warn deprecated a@1.0.0: old\n")
        outcomes = []
        for details in (
            ["fetch:alpha-pkg:404", "bad\nline"], ["fetch:alpha-pkg:404", "fetch:a b"],
            ["fetch:alpha-pkg:404", "x" * 600],
            ["fetch:alpha-pkg:404", "licence:gamma-pkg@3.1.0:not_allowed id:npm_" + "A" * 24],
            ["fetch:alpha-pkg:404"],
        ):
            self.fetcher = self.world.fetcher()
            refusal =bootstrap.BootstrapRefusal("npm_archive_refused", "fetch:alpha-pkg:404")
            refusal.details = tuple(details)

            def failing(name, refusal=refusal):
                raise refusal

            self.fetcher.packument = failing
            with patch.object(producer, "_npm_read_report", return_value=None):
                error = self.failure()
            header, stderr, report = self.sections(error.npm_diagnostic)
            if details == ["fetch:alpha-pkg:404"]:
                self.assertEqual(stderr[0], "  kd-check fetch:alpha-pkg:404")
            else:
                self.assertEqual(stderr, ["  npm warn deprecated a@1.0.0: old"])
            outcomes.append((
                error.reason, error.detail, error.source_gates_step, error.source_gates_key, str(error),
                error.args, producer.npm_diagnostic_result(error)["npm_diagnostic"],
            ))
        self.assertEqual(len(set(outcomes)), 1)

    def test_the_payload_validator_accepts_a_check_list_only_for_the_bundle_step(self):
        checks = ["fetch:alpha-pkg:404", "deprecated:beta-pkg@2.0.0"]
        payload = producer.build_npm_diagnostic_payload("npm_bundle", "npm_archive_refused", None, None, checks)
        self.assertEqual(self.sections(payload)[1], ["  kd-check " + item for item in checks])
        many = ["deprecated:pkg-%02d@1.0.0" % index for index in range(producer.NPM_CHECK_MAX_LINES)]
        payload = producer.build_npm_diagnostic_payload("npm_bundle", "npm_archive_refused", None, None, many)
        self.assertEqual(self.sections(payload)[1], ["  kd-check " + item for item in many])
        for step, hostile in (
            ("npm_bundle", []), ("npm_bundle", many + ["deprecated:extra@1.0.0"]),
            ("npm_bundle", ["fetch:a", 7]), ("npm_bundle", ["fetch:a", "bad\nline"]),
            ("npm_bundle", ["fetch:a", ["fetch:b"]]), ("npm_lock", ["lock_empty"]),
            ("npm_resolve", ["lock_empty"]), ("npm_bundle", ("fetch:a",)),
        ):
            with self.subTest(step=step, check=hostile):
                with self.assertRaises(producer.FeedbackRefusal):
                    producer.build_npm_diagnostic_payload(step, "npm_archive_refused", None, None, hostile)

    def test_the_check_list_keeps_the_payload_inside_every_bound(self):
        subject_text = bootstrap.adm.package_subject("a" * 214, "1.0.0-" + "b" * 100)
        longest = bootstrap.adm.build_detail(
            "archive_member_type", (subject_text, "gnu_longname", "d" * 50 + "/" + "e" * 49),
            fields=(("index", 99999),),
        )
        combined = "shared_parser:npm_archive_invalid:" + longest
        checks = [combined] * producer.NPM_CHECK_MAX_LINES
        stderr = b"".join(b"npm warn " + (b"w" * 100) + b" " + str(index).encode("ascii") + b"\n" for index in range(600))
        report = b"".join(b"report line " + str(index).encode("ascii") + b"\n" for index in range(2000))
        payload = producer.build_npm_diagnostic_payload("npm_bundle", "npm_archive_refused", stderr, report, checks)
        text = payload.decode("ascii")
        self.assertLessEqual(len(payload), producer.NPM_DIAGNOSTIC_MAX_BYTES)
        self.assertLessEqual(text.count("\n"), producer.NPM_DIAGNOSTIC_MAX_LINES)
        self.assertEqual(text.splitlines()[2:22], ["  kd-check " + combined] * 20)
        self.assertEqual(text.count("kd-check"), 20)
        for line in text.splitlines():
            self.assertLessEqual(len(line) - len(producer.NPM_CHECK_LINE_PREFIX), producer.NPM_CHECK_MAX_BYTES)

    def test_a_check_is_allowed_for_every_bundle_reason_and_a_list_only_there(self):
        self.assertTrue(producer._npm_check_allowed("npm_bundle", "npm_network_refused"))
        self.assertTrue(producer._npm_check_allowed("npm_bundle", "npm_archive_refused", ["fetch:a"]))
        self.assertTrue(producer._npm_check_allowed("npm_lock", "npm_lock_refused"))
        self.assertFalse(producer._npm_check_allowed("npm_lock", "npm_lock_refused", ["fetch:a"]))
        self.assertFalse(producer._npm_check_allowed("npm_lock", "npm_archive_refused"))
        self.assertFalse(producer._npm_check_allowed("npm_resolve", "npm_lock_refused"))

    def test_a_real_bundle_refusal_reaches_the_diagnostic_with_its_package_and_check(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        self.fetcher.advisory = json.dumps({"alpha-pkg": [
            {"id": 9, "severity": "high", "vulnerable_versions": "<2.0.0"},
        ]}).encode("ascii")
        with patch.object(producer, "_npm_read_report", return_value=None):
            error = self.failure()
        self.assertEqual((error.reason, error.source_gates_step, error.source_gates_key),
                         ("payload_invalid", "npm_bundle", "npm_advisory_blocked"))
        header, stderr, report = self.sections(error.npm_diagnostic)
        self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_bundle reason=npm_advisory_blocked")
        self.assertEqual(stderr, ["  kd-check advisory:alpha-pkg@1.0.0:9 severity:high dev:yes consumers:alpha-pkg unreached:0"])
        self.assertEqual(report, [])

    def test_a_hostile_archive_member_name_reaches_the_diagnostic_only_as_its_index(self):
        self.resolve = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        check = bootstrap.bundle_detail(
            "archive_path", "sample@1.0.0", "non_ascii", "unrepresentable", fields=(("index", 4),),
        )
        self.assertEqual(check, "archive_path:sample@1.0.0:non_ascii:unrepresentable index:4")
        self.bundle_refusal(check, "npm_archive_refused")
        with patch.object(producer, "_npm_read_report", return_value=None):
            error = self.failure()
        header, stderr, report = self.sections(error.npm_diagnostic)
        self.assertEqual(stderr, ["  kd-check " + check])
        self.assertEqual((error.reason, str(error)), ("payload_invalid", "payload_invalid"))
        self.assertNotIn("sample", repr((error.reason, error.detail, str(error), error.args)))

    def test_a_resolve_capture_failure_keeps_the_report_but_other_runner_failures_carry_nothing(self):
        self.runner_failures = {"resolve": self.runner_refusal("capture_invalid")}
        with patch.object(producer, "_npm_read_report", return_value=b"Found: a@1\n"):
            error = self.failure()
        header, stderr, report = self.sections(error.npm_diagnostic)
        self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=capture_invalid")
        self.assertEqual((stderr, report), ([], ["  Found: a@1"]))
        for reason, check in (("command_failed", "timeout"), ("command_failed", "spawn_failure"),
                              ("command_failed", None), ("cleanup_incomplete", None)):
            with self.subTest(reason=reason, check=check):
                self.runner_failures = {"resolve": self.runner_refusal(reason, check)}
                error = self.failure()
                self.assertEqual(error.reason, reason)
                self.assertFalse(hasattr(error, "npm_diagnostic"))
                with self.assertRaises(producer.FeedbackRefusal) as raised:
                    producer.npm_diagnostic_result(error)
                self.assertIs(raised.exception, error)

    def test_failures_before_the_resolve_step_and_config_failures_carry_no_diagnostic(self):
        self.files["package.json"] = b'{"name":"other"}'
        self.assertFalse(hasattr(self.failure(), "npm_diagnostic"))
        self.files = dict(self.world.files)
        self.version = SimpleNamespace(returncode=1, stdout=b"11.19.1\n")
        self.assertFalse(hasattr(self.failure(), "npm_diagnostic"))
        self.version = SimpleNamespace(returncode=0, stdout=(bootstrap.NPM_VERSION + "\n").encode("ascii"))
        for failing_call in (1, 2, 3):
            self.config_calls = []
            self.config_failures = {failing_call}
            self.assertFalse(hasattr(self.failure(), "npm_diagnostic"))
        self.config_failures = set()
        self.lock_state = "lock_already_present"
        self.assertFalse(hasattr(self.failure(), "npm_diagnostic"))

    def test_the_diagnostic_result_converts_only_a_captured_closed_producer_failure(self):
        good = b"KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=eresolve\nstderr:\nreport:\n"

        def refusal(reason="command_failed", step="npm_resolve", key="eresolve", payload=good):
            error = producer.FeedbackRefusal(reason)
            error.source_gates_step = step
            error.source_gates_key = key
            error.npm_diagnostic = payload
            return error

        self.assertEqual(producer.npm_diagnostic_result(refusal())["payload_bytes"], good)
        hostile = (
            refusal(reason="cleanup_incomplete"), refusal(step="npm_version"), refusal(step="npm_inputs"),
            refusal(key="timeout"), refusal(key="ERESOLVE"), refusal(key=None), refusal(payload=None),
            refusal(payload=b""), refusal(payload=bytearray(good)), refusal(payload=good.replace(b"eresolve", b"e404")),
            refusal(payload=b"{}"), refusal(payload=b" " + good),
            ValueError("hostile"),
        )
        for error in hostile:
            with self.subTest(error=repr(error)[:60]):
                if not isinstance(error, producer.FeedbackRefusal):
                    error.npm_diagnostic = good
                with self.assertRaises(Exception) as raised:
                    producer.npm_diagnostic_result(error)
                self.assertIs(raised.exception, error)


def _stderr(*lines):
    return b"".join(line + b"\n" for line in lines)


class NpmDiagnosticPayloadTests(unittest.TestCase):
    def sections(self, payload):
        lines = payload.decode("utf-8").split("\n")
        self.assertEqual(lines.pop(), "")
        self.assertEqual(lines[1], "stderr:")
        self.assertEqual(lines.count("report:"), 1)
        index = lines.index("report:")
        for line in lines[2:index] + lines[index + 1:]:
            self.assertTrue(line.startswith("  "), line)
        return lines[0], lines[2:index], lines[index + 1:]

    def test_the_header_is_closed_and_only_npm_error_and_warn_lines_are_kept(self):
        payload = producer.build_npm_diagnostic_payload(
            "npm_resolve", "eresolve",
            _stderr(b"npm error code ERESOLVE", b"npm error While resolving: a@1.0.0", b"unrelated", b"npm warn peer b@2",
                    b"npm ERR! legacy", b"npm info chatter"),
            b"While resolving: a@1.0.0\nFound: b@2.0.0\n",
        )
        header, stderr, report = self.sections(payload)
        self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=eresolve")
        self.assertEqual(stderr, ["  npm error code ERESOLVE", "  npm error While resolving: a@1.0.0", "  npm warn peer b@2"])
        self.assertEqual(report, ["  While resolving: a@1.0.0", "  Found: b@2.0.0"])

    def test_the_lock_check_is_the_first_stderr_line_and_the_header_stays_closed(self):
        payload = producer.build_npm_diagnostic_payload(
            "npm_lock", "npm_lock_refused", _stderr(b"npm warn peer b@2"), None,
            "singleton_duplicate:@scope/pkg count:2 found:1.0.0,2.0.0-rc.1+build",
        )
        header, stderr, report = self.sections(payload)
        self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_lock reason=npm_lock_refused")
        self.assertEqual(stderr, [
            "  kd-check singleton_duplicate:@scope/pkg count:2 found:1.0.0,2.0.0-rc.1+build",
            "  npm warn peer b@2",
        ])
        self.assertEqual(report, [])
        self.assertEqual(
            producer.build_npm_diagnostic_payload("npm_lock", "npm_lock_refused", None, None, None),
            b"KD-NPM-DIAGNOSTICS schema=1 step=npm_lock reason=npm_lock_refused\nstderr:\nreport:\n",
        )

    def test_every_bootstrap_check_shape_is_accepted_by_the_payload_validator(self):
        for check in (
            "lock_empty", "entry_count count:0", "root_identity:engines", "root_group:optionalDependencies",
            "workspace:packages/host-api", "direct_missing:alpha-pkg", "direct_missing:alpha-pkg found:1.0.1",
            "singleton_duplicate:alpha_pkg count:2 found:1.0.0,1.0.0", "override_mismatch:lightningcss count:0",
            "shrinkwrap:node_modules/a/node_modules/@s/b", "shared_parser:npm_lock_invalid",
        ):
            with self.subTest(check=check):
                self.assertIsNotNone(bootstrap.lock_detail(check.split(":")[0].split(" ")[0]))
                payload = producer.build_npm_diagnostic_payload("npm_lock", "npm_lock_refused", None, None, check)
                self.assertEqual(self.sections(payload)[1], ["  kd-check " + check])

    def test_the_producer_and_the_bootstrap_share_one_check_grammar(self):
        self.assertEqual(producer.NPM_CHECK_GRAMMAR, bootstrap.LOCK_DETAIL_GRAMMAR)
        self.assertEqual(producer.NPM_CHECK_GRAMMAR, bootstrap.adm.DETAIL_GRAMMAR)
        self.assertEqual(producer.NPM_CHECK_RE.pattern, bootstrap.LOCK_DETAIL_RE.pattern)
        self.assertEqual(producer.NPM_CHECK_MAX_BYTES, bootstrap.LOCK_DETAIL_MAX_BYTES)

    def test_every_bootstrap_output_including_truncated_ones_is_accepted_by_the_producer(self):
        for name_length in (1, 2, 50, 150, 200, 213, 214):
            for count in (0, 1, 7, 8, 9, 12, 99999):
                for version_length in (1, 2, 30, 63, 64, 65):
                    check = bootstrap.lock_detail(
                        "singleton_duplicate", "a" * name_length,
                        ["1." + "9" * max(version_length - 2, 0)] * min(count, 12), count=count,
                    )
                    self.assertIsNotNone(check)
                    self.assertLessEqual(len(check), producer.NPM_CHECK_MAX_BYTES)
                    self.assertIsNotNone(producer.NPM_CHECK_RE.match(check))
                    payload = producer.build_npm_diagnostic_payload("npm_lock", "npm_lock_refused", None, None, check)
                    self.assertEqual(self.sections(payload)[1], ["  kd-check " + check])

    def test_every_parser_detail_shape_is_accepted_by_the_payload_validator(self):
        for check in (
            "shared_parser:npm_lock_invalid:root_fields",
            "shared_parser:npm_lock_invalid:entry_key:node_modules/a/node_modules/@s/b:bogus",
            "shared_parser:npm_lock_invalid:dep_spec:node_modules/@isaacs/cliui:dependencies:string-width-cjs scheme:npm",
            "shared_parser:npm_lock_invalid:engines_shape:node_modules/a",
            "shared_parser:npm_lock_invalid:resolved_url:node_modules/a",
            "shared_parser:npm_lock_invalid:entry_name:node_modules/string-width-cjs",
            "shared_parser:npm_lock_invalid:entry_key:root:invalid_name",
            "shared_parser:npm_lock_invalid:workspace_entry:packages/host-api",
        ):
            with self.subTest(check=check):
                self.assertIsNotNone(bootstrap.LOCK_DETAIL_RE.match(check))
                payload = producer.build_npm_diagnostic_payload("npm_lock", "npm_lock_refused", None, None, check)
                self.assertEqual(self.sections(payload)[1], ["  kd-check " + check])

    def test_the_check_is_refused_for_other_steps_and_for_anything_outside_the_closed_shapes(self):
        for step in ("npm_resolve",):
            with self.subTest(step=step):
                with self.assertRaises(producer.FeedbackRefusal):
                    producer.build_npm_diagnostic_payload(step, "other", None, None, "lock_empty")
        for hostile in (
            "", "bad\nline", "two\nlines:x", "caf\u00e9", "a\u202eb", "x" * 513, "Lock_Empty", "a b",
            "direct_missing:a b", "direct_missing:" + "a" * 215, "direct_missing:a\x00", "root_group:a$b",
            "direct_missing:x found:1;rm", "direct_missing:x found:", b"lock_empty", 7, ["lock_empty"],
        ):
            with self.subTest(check=hostile):
                with self.assertRaises(producer.FeedbackRefusal):
                    producer.build_npm_diagnostic_payload("npm_lock", "npm_lock_refused", None, None, hostile)

    def test_every_bundle_check_shape_is_accepted_by_the_payload_validator(self):
        for check in (
            "fetch:alpha-pkg:404", "fetch:advisories:connect", "too_young:beta-pkg@2.0.0 age:2",
            "deprecated:alpha-pkg@1.0.0", "licence:gamma-pkg@3.1.0:not_allowed id:GPL-2.0+",
            "licence:gamma-pkg@3.1.0:election_missing id:_MIT_OR_CC0-1.0_",
            "advisory:alpha-pkg@1.0.0:9 severity:high", "advisory_invalid:alpha-pkg:severity",
            "request_mismatch:bundle:unmatched_rows count:1", "request_mismatch:alpha-pkg@1.0.0:published",
            "peer:a@1.0.0:react:range", "integrity_mismatch:gamma-pkg@3.1.0:dist_integrity",
            "shared_parser:npm_archive_invalid:archive_path:sample@1.0.0:tilde:package/a~b.js index:2",
            "shared_parser:npm_archive_invalid:archive_member_type:sample@1.0.0:symlink:package/link index:1",
            "shared_parser:npm_archive_invalid:archive_path:sample@1.0.0:non_ascii:unrepresentable index:4",
            "shared_parser:npm_archive_invalid:integrity_mismatch:gamma-pkg@3.1.0:archive",
            "archive_manifest:sample@1.0.0:json_decode", "archive_root:sample@1.0.0:other index:2",
            "archive_size:alpha-pkg@1.0.0:total_compressed", "archive_count:gamma-pkg@3.1.0:total_files",
            "package_step:alpha-pkg@1.0.0:npm_network_refused", "stale:bundle:times",
            "payload_size:bundle:lock", "bundle_input:bundle:context_value:repository",
            "evidence:alpha-pkg@1.0.0:item_sha256",
        ):
            with self.subTest(check=check):
                self.assertIsNotNone(bootstrap.LOCK_DETAIL_RE.match(check))
                payload = producer.build_npm_diagnostic_payload("npm_bundle", "npm_archive_refused", None, None, check)
                header, stderr, report = self.sections(payload)
                self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_bundle reason=npm_archive_refused")
                self.assertEqual(stderr, ["  kd-check " + check])

    def test_the_long_advisory_check_with_reach_fields_is_accepted_by_the_payload_validator(self):
        consumers = ",".join("@scope-%02d/%s" % (index, "c" * 40) for index in range(5))
        maximal = bootstrap.bundle_detail(
            "advisory", "n" * 60 + "@1.0.0", "x" * 64,
            fields=(
                ("severity", "moderate"), ("dev", "yes"), ("consumers", consumers), ("more", "99"),
                ("unreached", "0"),
            ),
        )
        self.assertIsNotNone(maximal)
        self.assertLessEqual(len(maximal), producer.NPM_CHECK_MAX_BYTES)
        checks = (
            "advisory:alpha-pkg@1.0.0:GHSA-aaaa-bbbb-cccc severity:high dev:yes consumers:alpha-pkg,beta-pkg more:3 unreached:0",
            "advisory:alpha-pkg@1.0.0:9 severity:moderate dev:no consumers:none unreached:2",
            maximal,
        )
        for check in checks:
            with self.subTest(check=check[:60]):
                self.assertIsNotNone(bootstrap.LOCK_DETAIL_RE.match(check))
                self.assertIsNotNone(producer.NPM_CHECK_RE.match(check))
                payload = producer.build_npm_diagnostic_payload("npm_bundle", "npm_advisory_blocked", None, None, check)
                header, stderr, report = self.sections(payload)
                self.assertEqual(header, "KD-NPM-DIAGNOSTICS schema=1 step=npm_bundle reason=npm_advisory_blocked")
                self.assertEqual(stderr, ["  kd-check " + check])

    def test_the_longest_bundle_check_fits_the_shared_bound_and_the_payload_bounds(self):
        subject_text = bootstrap.adm.package_subject("a" * 214, "1.0.0-" + "b" * 100)
        longest = bootstrap.adm.build_detail(
            "archive_member_type", (subject_text, "gnu_longname", "d" * 50 + "/" + "e" * 49),
            fields=(("index", 99999),),
        )
        combined = "shared_parser:npm_archive_invalid:" + longest
        self.assertLessEqual(len(combined), producer.NPM_CHECK_MAX_BYTES)
        self.assertIsNotNone(producer.NPM_CHECK_RE.match(combined))
        stderr = b"".join(b"npm warn " + (b"w" * 100) + b" " + str(index).encode("ascii") + b"\n" for index in range(600))
        report = b"".join(b"report line " + str(index).encode("ascii") + b"\n" for index in range(2000))
        payload = producer.build_npm_diagnostic_payload("npm_bundle", "npm_archive_refused", stderr, report, combined)
        text = payload.decode("ascii")
        self.assertLessEqual(len(payload), producer.NPM_DIAGNOSTIC_MAX_BYTES)
        self.assertLessEqual(text.count("\n"), producer.NPM_DIAGNOSTIC_MAX_LINES)
        self.assertEqual(text.splitlines()[2], "  kd-check " + combined)
        self.assertEqual(text.count("kd-check"), 1)

    def test_the_bundle_check_is_refused_outside_the_closed_shapes(self):
        for hostile in (
            "", "bad\nline", "archive_path:sample@1.0.0:tilde:package/a" + chr(233), "x" * 513,
            "archive_path:sample@1.0.0:tilde:package/a b", "archive_path:p:r:a" + chr(0x202E) + "b",
            "archive_path:p:r:a|b", "Archive_Path:p", b"archive_path:p", 7, ("a",),
            "archive_path:" + "a" * 215, "a:b:c:d:e:f:g:h", "archive_path:p index:1;2",
        ):
            with self.subTest(check=hostile):
                with self.assertRaises(producer.FeedbackRefusal):
                    producer.build_npm_diagnostic_payload("npm_bundle", "npm_archive_refused", None, None, hostile)

    def test_the_check_keeps_the_payload_inside_every_bound(self):
        check = bootstrap.lock_detail(
            "singleton_duplicate", "@scope/" + "a" * 200, ["1." + "9" * 60] * 40, count=40,
        )
        self.assertLessEqual(len(check), producer.NPM_CHECK_MAX_BYTES)
        stderr = b"".join(b"npm warn " + (b"w" * 100) + b" " + str(index).encode("ascii") + b"\n" for index in range(600))
        report = b"".join(b"report line " + str(index).encode("ascii") + b"\n" for index in range(2000))
        payload = producer.build_npm_diagnostic_payload("npm_lock", "npm_lock_refused", stderr, report, check)
        text = payload.decode("ascii")
        self.assertLessEqual(len(payload), producer.NPM_DIAGNOSTIC_MAX_BYTES)
        self.assertLessEqual(text.count("\n"), producer.NPM_DIAGNOSTIC_MAX_LINES)
        self.assertEqual(text.splitlines()[2], "  kd-check " + check)
        self.assertEqual(text.count("kd-check"), 1)
        self.assertTrue(all(len(line) <= producer.NPM_DIAGNOSTIC_LINE_UNITS for line in text.splitlines()))

    def test_missing_inputs_give_the_bare_fixed_layout(self):
        for stderr, report in ((None, None), (b"", b""), ("text", "text"), (bytearray(b"npm error x\n"), None)):
            with self.subTest(stderr=stderr):
                self.assertEqual(
                    producer.build_npm_diagnostic_payload("npm_lock", "npm_lock_refused", stderr, report),
                    b"KD-NPM-DIAGNOSTICS schema=1 step=npm_lock reason=npm_lock_refused\nstderr:\nreport:\n",
                )

    def test_the_step_and_reason_must_be_closed_tokens(self):
        for step, key in (
            ("npm_inputs", "eresolve"), ("npm_version", "mismatch"), ("resolve", "eresolve"), ("npm_resolve", ""),
            ("npm_resolve", "ERESOLVE"), ("npm_resolve", "a" * 41), ("npm_resolve", "x y"), ("npm_resolve", "a\nb"),
            (None, "eresolve"), ("npm_resolve", None), ("npm_resolve", b"eresolve"), (b"npm_resolve", "eresolve"),
        ):
            with self.subTest(step=step, key=key):
                with self.assertRaises(producer.FeedbackRefusal) as raised:
                    producer.build_npm_diagnostic_payload(step, key, b"", b"")
                self.assertEqual(raised.exception.reason, "payload_invalid")

    def test_every_section_is_capped_by_lines_and_bytes_and_marked_truncated(self):
        many = _stderr(*[b"npm error line " + str(index).encode("ascii") for index in range(1000)])
        payload = producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", many, None)
        header, stderr, report = self.sections(payload)
        self.assertEqual(len(stderr), producer.NPM_DIAGNOSTIC_STDERR_LINES + 1)
        self.assertEqual(stderr[-1], "  [truncated]")
        wide = _stderr(*[b"npm error " + b"y" * 1500 for unused in range(100)])
        stderr = self.sections(producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", wide, None))[1]
        self.assertLessEqual(sum(len(line.encode("utf-8")) + 1 for line in stderr), producer.NPM_DIAGNOSTIC_STDERR_BYTES)
        self.assertEqual(stderr[-1], "  [truncated]")
        for report in (
            b"".join(b"Found: package-" + str(index).encode("ascii") + b"@1.0.0 needs a peer\n" for index in range(20000)),
            b"".join(b"a" * 1900 + b"\n" for unused in range(100)),
            b"line without newline " * 10000,
        ):
            payload = producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", many, report)
            self.assertLessEqual(len(payload), producer.NPM_DIAGNOSTIC_MAX_BYTES)
            self.assertLessEqual(payload.count(b"\n"), producer.NPM_DIAGNOSTIC_MAX_LINES)
            self.assertEqual(self.sections(payload)[2][-1], "  [truncated]")

    def test_the_existing_sanitiser_escapes_every_kept_line(self):
        with patch.object(producer, "sanitize_diagnostic_stream", wraps=producer.sanitize_diagnostic_stream) as spy:
            payload = producer.build_npm_diagnostic_payload(
                "npm_bundle", "npm_peer_refused", _stderr(b"npm error a\x1bb"), b"c\x7fd\n",
            )
        self.assertEqual(spy.call_count, 2)
        self.assertEqual(self.sections(payload)[1:], (["  npm error a\\u{1b}b"], ["  c\\u{7f}d"]))

    def test_a_credential_that_spans_lines_is_refused_whole(self):
        for report in (b"token:\nabcdefghijklmnop\n", b"password =\n  hunter2hunter2\n"):
            with self.subTest(report=report):
                with self.assertRaises(producer.FeedbackRefusal) as raised:
                    producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", b"", report)
                self.assertEqual(raised.exception.reason, "payload_invalid")

    def test_credential_and_path_screens_match_the_encryptor_screen_shapes(self):
        samples = (
            b"npm error " + b"ghp_" + b"A" * 24, b"npm error github_pat_" + b"B" * 24, b"npm error xoxb-" + b"c" * 16,
            b"npm error npm_" + b"D" * 20, b"npm error AKIA" + b"E" * 16, b"npm error Authorization: Bearer abcdefgh",
            b"npm error Bearer " + b"f" * 24, b"npm error -----BEGIN RSA PRIVATE KEY-----",
            b"npm error //registry.example/:_authToken=x", b"npm error https://u:p@host/",
            b"npm error password=hunter2hunter2", b"npm error api_key: abcdefghij",
        )
        for sample in samples:
            with self.subTest(sample=sample[:24]):
                payload = producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", _stderr(sample), None)
                self.assertEqual(self.sections(payload)[1], ["  [omitted 1 lines]"])
        paths = (b"npm error at /etc/passwd", b"npm error in ~/x", b"npm error (/tmp/a)", b'npm error "/var/x"')
        for sample in paths:
            with self.subTest(sample=sample):
                payload = producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", _stderr(sample), None)
                self.assertEqual(self.sections(payload)[1], ["  [omitted 1 lines]"])
        public = (
            b'npm error   peer react@"^18.0.0" from react-dom@18.2.0', b"npm error node_modules/@scope/pkg",
            b"npm error See https://registry.npmjs.org/pkg for details", b"npm error Fix the upstream dependency conflict",
        )
        for sample in public:
            with self.subTest(sample=sample):
                payload = producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", _stderr(sample), None)
                self.assertEqual(self.sections(payload)[1], ["  " + sample.decode("ascii")])

    def test_the_path_screen_also_drops_file_urls_and_escape_prefixed_paths(self):
        dropped = (
            b"npm error at file:///etc/passwd", b"npm error FILE:///tmp/x", b"npm error url=file:///var/x",
            b"npm error at \x1b/etc/passwd", b"npm error \x1b[31m/etc/passwd\x1b[0m",
            b"npm error \x1b[1;31m~/secret", b"npm error \x01/etc/passwd",
        )
        for sample in dropped:
            with self.subTest(sample=sample):
                payload = producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", _stderr(sample), None)
                self.assertEqual(self.sections(payload)[1], ["  [omitted 1 lines]"])
        kept = (
            b"npm error profile: see the docs", b"npm error file: a relative name", b"npm error a/b/c",
            b"npm error https://registry.npmjs.org/pkg",
        )
        for sample in kept:
            with self.subTest(kept=sample):
                payload = producer.build_npm_diagnostic_payload("npm_resolve", "eresolve", _stderr(sample), None)
                self.assertEqual(self.sections(payload)[1], ["  " + sample.decode("ascii")])

    def test_the_python_credential_screen_is_the_javascript_screen_plus_the_npm_config_keys(self):
        source = (Path(__file__).resolve().parent / "development_feedback.mjs").read_text(encoding="utf-8")
        names = ("TOKEN_SHAPE", "PRIVATE_KEY_HEADER", "CREDENTIAL_ASSIGNMENT", "BEARER_TOKEN", "CREDENTIAL_URL")
        shared = producer.NPM_CREDENTIAL_PATTERNS[:len(names)]
        self.assertEqual(len(producer.NPM_CREDENTIAL_PATTERNS), len(names) + 1)
        for name, pattern in zip(names, shared):
            with self.subTest(name=name):
                found = re.findall(r"(?m)^const " + name + r" = /(.+)/([a-z]*);$", source)
                self.assertEqual(len(found), 1)
                body, flags = found[0]
                self.assertEqual(body.replace("\\/", "/"), pattern.pattern)
                self.assertEqual("i" in flags, bool(pattern.flags & re.IGNORECASE))
                self.assertIn("u", flags)
        extra = producer.NPM_CREDENTIAL_PATTERNS[-1]
        self.assertIsNotNone(extra.search("//registry.example/:_authToken=x"))
        self.assertIsNotNone(extra.search("_password = x"))
        self.assertIsNone(extra.search("password manager"))

    def test_the_shared_credential_vectors_are_screened_by_every_shared_pattern_set(self):
        vectors = (
            ("ghp_" + "A" * 24, True), ("github_pat_" + "B" * 24, True), ("xoxb-" + "c" * 16, True),
            ("npm_" + "D" * 20, True), ("AKIA" + "E" * 16, True), ("ASIA" + "F" * 16, True),
            ("Authorization: Bearer abcdefgh", True), ("Bearer " + "f" * 24, True),
            ("-----BEGIN RSA PRIVATE KEY-----", True), ("https://u:p@host/", True),
            ("password=hunter2hunter2", True), ("api_key: abcdefghij", True),
            ("token = abcdefgh", True), ("client-secret:abcdefgh", True),
            ("ghp_short", False), ("password=short", False), ("https://host/path", False),
            ("Bearer short", False), ("mytoken=abcdefghij", False), ("AKIA" + "E" * 15, False),
            ("npm_" + "D" * 19, False), ("BEGIN PRIVATE KEY", False),
        )
        for text, expected in vectors:
            with self.subTest(text=text):
                self.assertEqual(
                    any(pattern.search(text) is not None for pattern in producer.NPM_CREDENTIAL_PATTERNS[:5]),
                    expected,
                )


@unittest.skipUnless(sys.platform != "win32", "the eresolve report reader requires POSIX ownership checks")
class NpmEresolveReportReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.storage = Path(os.path.realpath(self.temporary.name)) / "home"
        self.logs = self.storage / "cache" / "_logs"
        self.logs.mkdir(parents=True)
        self.uid = os.getuid()

    def write(self, name, data):
        path = self.logs / name
        path.write_bytes(data)
        return path

    def test_the_newest_eresolve_report_by_name_is_read_and_other_logs_are_ignored(self):
        self.write("2026-11-01T10_00_00_000Z-eresolve-report.txt", b"old report\n")
        self.write("2026-11-02T10_00_00_000Z-eresolve-report.txt", b"new report\n")
        self.write("2026-11-03T10_00_00_000Z-debug-0.log", b"debug log\n")
        self.write("2026-11-04T10_00_00_000Z-eresolve-report.txt.bak", b"backup\n")
        self.assertEqual(producer._npm_read_report(self.storage, self.uid), b"new report\n")

    def test_no_report_or_no_logs_directory_gives_nothing(self):
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid))
        self.write("2026-11-02T10_00_00_000Z-debug-0.log", b"debug log\n")
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid))
        self.assertIsNone(producer._npm_read_report(self.storage / "missing", self.uid))

    def test_wrong_owner_empty_linked_or_symlinked_files_and_directories_are_not_read(self):
        name = "2026-11-02T10_00_00_000Z-eresolve-report.txt"
        self.write(name, b"report\n")
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid + 1))
        (self.logs / name).unlink()
        self.write(name, b"")
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid))
        (self.logs / name).unlink()
        target = self.write("target.txt", b"secret outside the report\n")
        os.symlink(str(target), str(self.logs / name))
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid))
        (self.logs / name).unlink()
        self.write(name, b"report\n")
        os.link(str(self.logs / name), str(self.logs / "other-name.txt"))
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid))
        (self.logs / "other-name.txt").unlink()
        self.assertEqual(producer._npm_read_report(self.storage, self.uid), b"report\n")
        real = self.storage / "cache" / "_real"
        (self.storage / "cache" / "_logs").rename(real)
        os.symlink(str(real), str(self.storage / "cache" / "_logs"))
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid))

    def test_a_symlinked_or_foreign_cache_directory_is_not_read(self):
        self.write("2026-11-02T10_00_00_000Z-eresolve-report.txt", b"report\n")
        cache = self.storage / "cache"
        self.assertEqual(producer._npm_read_report(self.storage, self.uid), b"report\n")
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid + 1))
        real = self.storage / "real-cache"
        cache.rename(real)
        os.symlink(str(real), str(cache))
        self.assertIsNone(producer._npm_read_report(self.storage, self.uid))

    def test_the_report_is_opened_without_blocking_so_a_swapped_in_pipe_cannot_hang_the_run(self):
        self.write("2026-11-02T10_00_00_000Z-eresolve-report.txt", b"report\n")
        flags = []
        real_open = os.open

        def spy(path, flag, *arguments, **keywords):
            flags.append(flag)
            return real_open(path, flag, *arguments, **keywords)

        with patch.object(producer.os, "open", spy):
            self.assertEqual(producer._npm_read_report(self.storage, self.uid), b"report\n")
        self.assertEqual(len(flags), 1)
        self.assertTrue(flags[0] & os.O_NONBLOCK)
        self.assertTrue(flags[0] & os.O_NOFOLLOW)

    def test_a_large_report_is_read_only_up_to_the_fixed_prefix_bound(self):
        name = "2026-11-02T10_00_00_000Z-eresolve-report.txt"
        self.write(name, b"a" * (producer.NPM_DIAGNOSTIC_REPORT_READ_BYTES + 5000))
        data = producer._npm_read_report(self.storage, self.uid)
        self.assertEqual(len(data), producer.NPM_DIAGNOSTIC_REPORT_READ_BYTES)


@unittest.skipUnless(sys.platform != "win32", "the macOS core contract tests require POSIX paths")
class NpmDiagnosticPublicLineTests(unittest.TestCase):
    ARGUMENTS = [
        "run", "--token-stdin", "--source-sha", "a" * 40, "--base-sha", "b" * 40, "--base-branch", "develop",
    ]

    def run_main(self, diagnostic, kind="npm_admission"):
        import macos_core_contract as core

        def execute(arguments, environ, token, lifecycle, feedback_kind=None):
            lifecycle["token_revocation"] = "confirmed_before_execution"
            if diagnostic is not None:
                lifecycle["npm_diagnostic"] = diagnostic
            return b'{"status":"encrypted"}'

        out, err = io.StringIO(), io.StringIO()
        with patch.object(core, "_execute", execute):
            status = core.main(
                arguments=list(self.ARGUMENTS), environ={}, stdin=io.BytesIO(b"fixture-token\n"),
                stdout=out, stderr=err, feedback_kind=kind,
            )
        return status, out.getvalue(), err.getvalue()

    def test_one_closed_diagnostic_line_follows_the_receipt_on_the_producer_stderr_only(self):
        status, out, err = self.run_main(("npm_resolve", "eresolve"))
        self.assertEqual(status, 0)
        self.assertEqual(out, 'KD-FEEDBACK-PRODUCER {"status":"encrypted"}\n')
        self.assertEqual(err.splitlines(), [
            "KD-PRODUCER-TOKEN-REVOCATION confirmed",
            "KD-FEEDBACK-NPM-DIAGNOSTIC schema=1 step=npm_resolve reason=eresolve",
        ])

    def test_no_diagnostic_means_no_extra_line(self):
        status, out, err = self.run_main(None)
        self.assertEqual((status, err), (0, "KD-PRODUCER-TOKEN-REVOCATION confirmed\n"))

    def test_only_closed_step_reason_pairs_of_the_npm_admission_kind_are_ever_published(self):
        for diagnostic, kind in (
            (("npm_resolve", "bogus"), "npm_admission"), (("npm_inputs", "npm_stale"), "npm_admission"),
            (("npm_version", "mismatch"), "npm_admission"), (("npm_config", "tool_unavailable"), "npm_admission"),
            (["npm_resolve", "eresolve"], "npm_admission"), (("npm_resolve",), "npm_admission"),
            (("npm_resolve", b"eresolve"), "npm_admission"), (("npm_resolve", "eresolve\nforged"), "npm_admission"),
            ("npm_resolve eresolve", "npm_admission"), (("npm_resolve", "eresolve"), "cargo_lock"),
            (("npm_resolve", "eresolve"), "build_diagnostics"),
        ):
            with self.subTest(diagnostic=diagnostic, kind=kind):
                status, out, err = self.run_main(diagnostic, kind)
                self.assertEqual(err, "KD-PRODUCER-TOKEN-REVOCATION confirmed\n")

    def test_every_closed_core_pair_of_the_three_steps_is_a_valid_public_line_and_a_payload_header(self):
        import macos_core_contract as core

        self.assertEqual(core.NPM_DIAGNOSTIC_STEPS, producer.NPM_DIAGNOSTIC_STEPS)
        checked = 0
        for step, keys in core.SOURCE_GATES_NPM_KEYS_BY_STEP:
            if step not in core.NPM_DIAGNOSTIC_STEPS:
                continue
            for key in keys:
                status, out, err = self.run_main((step, key))
                self.assertEqual(err.splitlines()[-1], core.NPM_DIAGNOSTIC_LINE_PREFIX + step + " reason=" + key)
                payload = producer.build_npm_diagnostic_payload(step, key, None, None)
                self.assertTrue(payload.startswith(producer.NPM_DIAGNOSTIC_PREFIX.encode("ascii") + step.encode("ascii")))
                checked += 1
        self.assertEqual(checked, 10 + 4 + 3 + 19)


if __name__ == "__main__":
    unittest.main()
