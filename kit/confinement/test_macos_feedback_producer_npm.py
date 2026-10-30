import importlib.util
import json
from pathlib import Path
import sys
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

    def run_worker(self, rust, argv, uid, environment, python, capability, stage, deadline, **keywords):
        self.commands.append((tuple(argv), dict(environment), stage, keywords))
        self.events.append("probe" if tuple(argv)[-1] == "--version" else "resolve")
        return self.version if tuple(argv)[-1] == "--version" else self.resolve

    def read_file(self, path, *, maximum, owner=0):
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
        with patch.object(producer, "_read_file", self.read_file), \
                patch.object(producer, "_make_worker_directory",
                             lambda path, uid, gid: self.directories.append(Path(path).as_posix())), \
                patch.object(producer, "_write_worker_file",
                             lambda path, payload, uid, gid: self.written.append((Path(path).as_posix(), payload))), \
                patch.object(producer, "_run_worker", self.run_worker), \
                patch.object(producer, "_read_worker_file",
                             lambda path, uid, maximum: lock if lock is not None else self.world.lock_bytes), \
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

    def test_reason_mapping_covers_every_bootstrap_reason_with_a_producer_reason(self):
        allowed = {"manifest_invalid", "tool_unavailable", "command_failed", "payload_invalid"}
        for reason in sorted(bootstrap.REASONS):
            with self.subTest(reason=reason):
                with self.assertRaises(producer.FeedbackRefusal) as raised:
                    producer._npm_bootstrap_refusal(bootstrap.BootstrapRefusal(reason))
                self.assertIn(raised.exception.reason, allowed)


if __name__ == "__main__":
    unittest.main()
