import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import macos_private_validation as validation


MODULE_PATH = Path(__file__).resolve().parent / "foundation_node_feedback.py"
SPEC = importlib.util.spec_from_file_location("foundation_node_feedback", MODULE_PATH)
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)

NOW = 1_798_000_000
SOURCE_SHA = "a" * 40
BASE_SHA = "b" * 40
CONTROL_SHA = "c" * 40
DIFF_SHA = "d" * 64
NODE_OPTIONS_EXPECTED = (
    "--import=data:text/javascript;base64,"
    "bGV0IGtkVGl0bGUgPSBTdHJpbmcocHJvY2Vzcy50aXRsZSk7T2JqZWN0LmRlZmluZVByb3BlcnR5KHByb2Nlc3MsInRpdGxlIix7Z2V0KCl7cmV0dXJuIGtkVGl0bGU7fSxzZXQodmFsdWUpe2tkVGl0bGUgPSBTdHJpbmcodmFsdWUpO30sY29uZmlndXJhYmxlOnRydWUsZW51bWVyYWJsZTp0cnVlfSk7"
)


class FeedbackRefusal(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class NodeContractRefusal(Exception):
    def __init__(self, reason, *, stage, substage=None, returncode=None, stdout=b"", stderr=b"",
                 stdout_truncated=False, stderr_truncated=False, completed_stages=()):
        self.reason = reason
        self.stage = stage
        self.substage = substage
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated
        self.completed_stages = completed_stages
        super().__init__(reason)


class CleanupRefusal(Exception):
    def __init__(self, **attributes):
        self.reason = "cleanup_incomplete"
        for name, value in attributes.items():
            setattr(self, name, value)
        super().__init__(self.reason)


class FakeProducer:
    def __init__(self):
        self.PROFILE_BY_KIND = {
            "lock": {"kind": "lock", "concern": "core-node-lock-return"},
            "rust_patch": {"kind": "rust_patch", "concern": "core-rust-format-return"},
            "build_diagnostics": {
                "kind": "build_diagnostics", "concern": "core-build-diagnostic-return",
            },
        }
        self.feedback_request = SimpleNamespace(MAX_REQUEST_TTL_SECONDS=86_400)
        self.directories = []
        self.copies = []
        self.writes = []
        self.reads = []
        self.worker_files = {}

    def _refuse(self, reason):
        raise FeedbackRefusal(reason)

    def _expected_manifest(self, source):
        return {
            "root": {"name": "fixture-root", "version": "1.0.0", "workspaces": ["packages/*"]},
            "workspaces": [{"path": "packages/host-api", "name": "@fixture/host-api", "version": "1.0.0"}],
        }

    def _read_file(self, path, *, maximum, owner=0):
        self.reads.append((Path(path), maximum, owner))
        payload = Path(path).read_bytes()
        if not 0 < len(payload) <= maximum:
            self._refuse("manifest_invalid")
        return payload

    def _make_worker_directory(self, path, worker_uid, worker_gid):
        self.directories.append((Path(path), worker_uid, worker_gid))

    def _copy_reviewed_files(self, source, destination, paths, worker_uid, worker_gid):
        self.copies.append((Path(source), Path(destination), tuple(paths), worker_uid, worker_gid))

    def _write_worker_file(self, path, payload, worker_uid, worker_gid):
        self.writes.append((Path(path), payload, worker_uid, worker_gid))
        self.worker_files[Path(path)] = payload

    def _read_worker_file(self, path, worker_uid, maximum):
        payload = self.worker_files[Path(path)]
        if len(payload) > maximum:
            self._refuse("capture_invalid")
        return payload


class FakeContract:
    MAX_LOCK_BYTES = 4 * 1024 * 1024 - 64 * 1024
    REGISTRY_URL = "https://registry.npmjs.org/"
    NODE_VERSION = "24.22.1"
    NPM_VERSION = "11.19.1"
    AUDIT_ENDPOINT = "npm-bulk-advisory-v1"
    USER_CONFIG_NAME = "npm-user-empty.npmrc"
    GLOBAL_CONFIG_NAME = "npm-global-empty.npmrc"
    NODE_OPTIONS_VALUE = NODE_OPTIONS_EXPECTED
    RELEASE_AGE_DAYS = 7
    DAY_MS = 86_400_000
    STAGES = frozenset(subject.NODE_GATE_NAMES)
    NodeContractRefusal = NodeContractRefusal
    __file__ = str(Path(__file__).resolve().parent / "macos_node_contract.py")

    def __init__(self, mode, expected_result=None):
        self.mode = mode
        self.expected_result = expected_result
        self.contract_error = None
        self.real_worker_result = None
        self.call = None
        self.callback_mutation = None

    def _command_prefix(self, node, npm_cli, cutoff_ms, environment):
        return (str(node), str(npm_cli), "--registry=" + self.REGISTRY_URL,
                "--userconfig=" + environment["npm_config_userconfig"],
                "--globalconfig=" + environment["npm_config_globalconfig"], "--ignore-scripts",
                "--audit=false", "--fund=false", "--fetch-retries=0", "--fetch-timeout=30000",
                "--no-update-notifier", "--min-release-age=7", "--before=" + str(cutoff_ms))

    def _validate_expectation(self, value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def run_node_contract(self, mode, **kwargs):
        self.call = (mode, kwargs)
        node = Path(kwargs["node_executable"])
        storage = Path(kwargs["worker_storage"])
        env = subject._node_environment(storage, node, self)
        command = (str(node), "--version")
        cwd = kwargs["project"]
        if self.callback_mutation == "argv":
            command = ("unapproved-command",)
        elif self.callback_mutation == "cwd":
            cwd = Path(cwd) / "unexpected"
        elif self.callback_mutation == "env":
            env = dict(env)
            env["LANG"] = "C.UTF-8"
        elif self.callback_mutation == "node_options_changed":
            env = dict(env)
            env["NODE_OPTIONS"] = env["NODE_OPTIONS"] + " --no-warnings"
        elif self.callback_mutation == "node_options_removed":
            env = dict(env)
            del env["NODE_OPTIONS"]
        elif self.callback_mutation == "extra_key":
            env = dict(env)
            env["NODE_PATH"] = "/unexpected"
        if self.contract_error is not None:
            raise self.contract_error
        if self.real_worker_result is not None:
            self.real_worker_result(
                kwargs["run_worker"], command, stage="node_dependency_prepare",
                substage="runtime_version", project=cwd, environment=env,
                deadline=kwargs["deadline"], timeout=10,
            )
        kwargs["run_worker"](
            command, stage="node_dependency_prepare", substage="runtime_version",
            cwd=cwd, env=env, deadline=kwargs["deadline"], timeout=10,
            allow_nonzero_capture=True,
        )
        return self.expected_result


def _dispatch(kind):
    profiles = FakeProducer().PROFILE_BY_KIND
    profile = profiles[kind]
    request = {
        "kind": kind,
        "concern": profile["concern"],
        "source_sha": SOURCE_SHA,
        "base_sha": BASE_SHA,
        "control_sha": CONTROL_SHA,
        "reviewed_diff_sha256": DIFF_SHA,
        "expiry": NOW + 3600,
    }
    return {"profile": profile, "request": request, "context": dict(request)}


def _runtime():
    return SimpleNamespace(
        CORE_CONTRACT_FEEDBACK_FILES=validation.CORE_CONTRACT_FEEDBACK_FILES,
        _core_contract_pattern_paths=validation._core_contract_pattern_paths,
        MAX_CORE_CONTRACT_TS_SOURCES=validation.MAX_CORE_CONTRACT_TS_SOURCES,
        MAX_CORE_CONTRACT_TS_TESTS=validation.MAX_CORE_CONTRACT_TS_TESTS,
        CORE_CONTRACT_TREE_BY_CONCERN={"core-node-lock-return": "core_node_lock_return"},
        CORE_CONTRACT_PACKAGE_LOCK_TREE=subject.PACKAGE_LOCK_TREE,
    )


def _audit_summary():
    return {"package_count": 3, "remote_package_count": 2,
            "remote_version_count": 2, "advisory_count": 0}


def _bootstrap_result(contract, identity, expected_manifest, policy_epoch):
    lock_bytes = b'{"lockfileVersion":3,"packages":{}}\n'
    manifest_sha = hashlib.sha256(contract._validate_expectation(expected_manifest)).hexdigest()
    candidate = {
        "schema_version": 1, "status": "validated_candidate", "generation_identity": identity,
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(), "manifest_sha256": manifest_sha,
        "node_version": contract.NODE_VERSION, "npm_version": contract.NPM_VERSION,
        "release_age_days": contract.RELEASE_AGE_DAYS, "policy_epoch_ms": policy_epoch,
        "cutoff_epoch_ms": policy_epoch - contract.RELEASE_AGE_DAYS * contract.DAY_MS,
        "age_status": "passed", "generation_attempts": 1,
        "audit_endpoint": "npm-bulk-advisory-v1", "audit_status": "passed",
    }
    return {
        "schema_version": 1, "mode": "bootstrap", "status": "passed", "lock_bytes": lock_bytes,
        "lock_sha256": candidate["lock_sha256"], "provenance_candidate": candidate,
        "stages": subject.NODE_BOOTSTRAP_GATES, "audit_summary": _audit_summary(),
    }


def _verify_result(lock_bytes, provenance):
    return {
        "schema_version": 1, "mode": "verify", "status": "passed", "lock_bytes": lock_bytes,
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "accepted_provenance": provenance, "audit_summary": _audit_summary(),
        "stages": subject.NODE_GATE_NAMES,
    }


class FoundationNodeFeedbackTests(unittest.TestCase):
    def test_npm_arguments_use_distinct_empty_config_paths_from_clean_environment(self):
        contract = FakeContract("bootstrap")
        storage = Path("/fixed/worker-storage")
        node = Path("/fixed/node/bin/node")
        environment = subject._node_environment(storage, node, contract)
        command = contract._command_prefix(node, Path("/fixed/npm-cli.js"), 1234, environment)
        user_config = environment["npm_config_userconfig"]
        global_config = environment["npm_config_globalconfig"]
        self.assertNotEqual(user_config, global_config)
        self.assertEqual(user_config, str(storage / contract.USER_CONFIG_NAME))
        self.assertEqual(global_config, str(storage / contract.GLOBAL_CONFIG_NAME))
        self.assertIn("--userconfig=" + user_config, command)
        self.assertIn("--globalconfig=" + global_config, command)

    def test_node_environment_carries_exactly_the_fixed_title_option_and_no_other_keys(self):
        environment = subject._node_environment(
            Path("/fixed/worker-storage"), Path("/fixed/node/bin/node"), FakeContract("bootstrap"),
        )
        self.assertEqual(environment["NODE_OPTIONS"], NODE_OPTIONS_EXPECTED)
        self.assertEqual(set(environment), {
            "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "NODE_OPTIONS", "npm_config_cache",
            "npm_config_registry", "npm_config_userconfig", "npm_config_globalconfig",
            "npm_config_ignore_scripts", "npm_config_audit", "npm_config_fund",
            "npm_config_fetch_retries", "npm_config_fetch_timeout", "npm_config_update_notifier",
        })

    def _run(self, mode, kind, *, validated_tree, accepted_provenance=None, lock_bytes=None,
             callback_mutation=None, fail_census=False, fail_restore=False,
             census_error=None, command_error=None, contract_error=None,
             real_node_contract=None, new_ts_paths=()):
        producer = FakeProducer()
        profile = producer.PROFILE_BY_KIND[kind]
        dispatch = _dispatch(kind)
        identity = {name: dispatch["request"][name] for name in subject.SOURCE_IDENTITY_KEYS}
        expected_manifest = producer._expected_manifest(Path("/source"))
        policy_epoch = (dispatch["request"]["expiry"] - producer.feedback_request.MAX_REQUEST_TTL_SECONDS) * 1000 \
            if mode == "bootstrap" else None
        contract = FakeContract(mode)
        if mode == "bootstrap":
            contract.expected_result = _bootstrap_result(contract, identity, expected_manifest, policy_epoch)
        else:
            contract.expected_result = _verify_result(lock_bytes, accepted_provenance)
        contract.callback_mutation = callback_mutation
        contract.contract_error = contract_error
        if real_node_contract is not None:
            contract.NodeContractRefusal = real_node_contract.NodeContractRefusal
            contract.real_worker_result = real_node_contract._worker_result
        events = []
        rust_result = SimpleNamespace(returncode=0, stdout=b"v24.22.1\n", stderr=b"",
                                      stdout_truncated=False, stderr_truncated=False)
        def worker_census(*args):
            events.append(("census", args[-1]))
            if census_error is not None:
                raise census_error
            if fail_census:
                raise OSError

        def run_worker_command(argv, uid, env, python, capability, **kwargs):
            events.append(("worker", tuple(argv), uid, dict(env), kwargs))
            if command_error is not None:
                raise command_error
            return rust_result

        reviewed = SimpleNamespace(_worker_census=worker_census)
        rust = SimpleNamespace(
            _run_worker_command=run_worker_command,
            _load_control_sibling=lambda name: reviewed if name == "macos_reviewed_build" else None,
        )
        capability = SimpleNamespace(PROBE_PRIMARY_GID=20)
        host_toolchain = {"python": "/trusted/python"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            baseline = validation._core_contract_pattern_paths(validation.CORE_CONTRACT_FEEDBACK_FILES)
            for relative in sorted(baseline["ts_sources"] | baseline["ts_tests"] | set(new_ts_paths)):
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.touch()
            storage_root = root / "worker"
            storage_root.mkdir()
            if lock_bytes is not None:
                (source / subject.PACKAGE_LOCK_PATH).write_bytes(lock_bytes)
            cwd_changes = []
            original_cwd = Path.cwd()

            def change_directory(path):
                target = Path(path)
                cwd_changes.append(target)
                if fail_restore and target == original_cwd:
                    raise OSError

            try:
                with patch.object(subject.os, "chdir", side_effect=change_directory):
                    result = subject.run_node_profile(
                        mode, dispatch=dispatch, source=source, worker_storage=storage_root,
                        worker_uid=501, environment={"CARGO_NET_OFFLINE": "true"},
                        host_toolchain=host_toolchain, capability=capability, rust=rust,
                        deadline=NOW + 10_000, node=root / "node/24.22.1/bin/node",
                        npm_cli=root / "node/24.22.1/lib/node_modules/npm/bin/npm-cli.js",
                        contract=contract, producer=producer, source_runtime=_runtime(),
                        tool_cache_root=root / "node", accepted_provenance=accepted_provenance,
                        validated_tree=validated_tree,
                    )
            except Exception as error:
                error.worker_events = tuple(events)
                raise
            self.assertEqual(cwd_changes[0], storage_root / "foundation-node-contract/project")
            self.assertEqual(cwd_changes[-1], Path.cwd())
            self.assertEqual(events[0][0], "worker")
            self.assertEqual(events[0][4]["stage"], "node_dependency_prepare")
            self.assertTrue(events[0][4]["allow_nonzero_capture"])
            self.assertEqual(set(events[0][3]), set(subject._node_environment(
                storage_root / "foundation-node-contract", root / "node/24.22.1/bin/node", contract,
            )))
            self.assertEqual(events[-1], ("census", "feedback-node"))
            self.assertTrue(producer.copies)
            self.assertEqual(contract.call[0], mode)
            self.assertEqual(contract.call[1]["source_identity"], identity)
            if lock_bytes is not None:
                self.assertEqual((source / subject.PACKAGE_LOCK_PATH).read_bytes(), lock_bytes)
            return result, producer, contract

    def test_bootstrap_copies_only_two_manifests_and_derives_epoch_from_request(self):
        result, producer, contract = self._run(
            "bootstrap", "lock", validated_tree="core_node_lock_return",
        )
        self.assertEqual(producer.copies[0][2], subject.BOOTSTRAP_MANIFESTS)
        self.assertIsNone(contract.call[1]["accepted_lock"])
        self.assertIsNone(contract.call[1]["accepted_provenance"])
        self.assertEqual(contract.call[1]["policy_epoch_ms"],
                         (NOW + 3600 - 86_400) * 1000)
        self.assertEqual(result["stages"], subject.NODE_BOOTSTRAP_GATES)

    def test_verify_copies_exact_source_lock_and_only_reviewed_typescript_files(self):
        lock_bytes = b'{"lockfileVersion":3,"packages":{"fixture":{}}}\n'
        provenance = {"status": "accepted", "policy_epoch_ms": NOW * 1000}
        result, producer, contract = self._run(
            "verify", "build_diagnostics", validated_tree=subject.PACKAGE_LOCK_TREE,
            accepted_provenance=provenance, lock_bytes=lock_bytes,
        )
        copied = producer.copies[0][2]
        baseline = validation._core_contract_pattern_paths(validation.CORE_CONTRACT_FEEDBACK_FILES)
        expected = subject.NODE_FIXED_FILES | baseline["ts_sources"] | baseline["ts_tests"]
        self.assertEqual(copied, tuple(sorted(expected)))
        self.assertNotIn(".npmrc", copied)
        self.assertFalse(any("README" in path or "CONTRACT" in path or "CHANGELOG" in path for path in copied))
        self.assertEqual(producer.writes[0][1], lock_bytes)
        self.assertEqual(contract.call[1]["accepted_lock"], lock_bytes)
        self.assertIs(contract.call[1]["accepted_provenance"], provenance)
        self.assertEqual(result["stages"], subject.NODE_GATE_NAMES)
        self.assertEqual(result["node_reviewed_file_count"], len(copied))
        self.assertEqual(result["node_reviewed_paths_sha256"], hashlib.sha256(
            "".join(path + "\n" for path in copied).encode("ascii")
        ).hexdigest())

    def test_verify_copies_new_source_and_test_files_into_worker(self):
        additions = (
            "packages/host-api/src/new-module.ts",
            "packages/host-api/tests/new-module.test.ts",
        )
        result, producer, unused_contract = self._run(
            "verify", "build_diagnostics", validated_tree=subject.PACKAGE_LOCK_TREE,
            accepted_provenance={"status": "accepted"}, lock_bytes=b"lock",
            new_ts_paths=additions,
        )
        copied = producer.copies[0][2]
        self.assertTrue(set(additions).issubset(copied))
        self.assertEqual(result["node_reviewed_file_count"], len(copied))

    def test_verify_refuses_wrong_profile_or_unadmitted_tree_before_copy(self):
        producer = FakeProducer()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / subject.PACKAGE_LOCK_PATH).write_bytes(b"lock")
            with self.assertRaises(FeedbackRefusal):
                subject.run_node_profile(
                    "verify", dispatch=_dispatch("rust_patch"), source=source,
                    worker_storage=root, worker_uid=501, environment={}, host_toolchain={"python": "/python"},
                    capability=SimpleNamespace(PROBE_PRIMARY_GID=20), rust=SimpleNamespace(),
                    deadline=NOW + 10_000, node=root / "node", npm_cli=root / "npm",
                    contract=FakeContract("verify"), producer=producer, source_runtime=_runtime(),
                    tool_cache_root=root / "cache", accepted_provenance={"status": "accepted"},
                    validated_tree="core_rust_format_return",
                )
        self.assertEqual(producer.copies, [])

    def test_worker_rejects_changed_callback_command_environment_and_cwd_before_spawn(self):
        for mutation in ("argv", "env", "cwd", "node_options_changed", "node_options_removed", "extra_key"):
            with self.subTest(mutation=mutation):
                with self.assertRaises(FeedbackRefusal) as caught:
                    self._run(
                        "bootstrap", "lock", validated_tree="core_node_lock_return",
                        callback_mutation=mutation,
                    )
                self.assertEqual(caught.exception.reason, "capture_invalid")
                self.assertEqual(caught.exception.worker_events, ())

    def test_worker_census_or_cwd_restore_failure_refuses_cleanup(self):
        for failure in ("census", "restore"):
            with self.subTest(failure=failure):
                with self.assertRaises(FeedbackRefusal) as caught:
                    self._run(
                        "bootstrap", "lock", validated_tree="core_node_lock_return",
                        fail_census=failure == "census", fail_restore=failure == "restore",
                    )
                self.assertEqual(caught.exception.reason, "cleanup_incomplete")
                self.assertEqual(caught.exception.worker_events[0][0], "worker")
                self.assertEqual(caught.exception.worker_events[-1][0], "census")

    def _cleanup_diagnostic(self, **options):
        with self.assertRaises(Exception) as caught:
            self._run("bootstrap", "lock", validated_tree="core_node_lock_return", **options)
        self.assertEqual(caught.exception.reason, "cleanup_incomplete")
        return caught.exception.cleanup_diagnostic

    def test_census_survivor_class_selects_the_matching_fixed_diagnostic(self):
        for survivor in sorted(subject.SURVIVOR_CLASSES):
            with self.subTest(survivor=survivor):
                diagnostic = self._cleanup_diagnostic(
                    census_error=CleanupRefusal(survivor_classes=(survivor,)),
                )
                self.assertEqual(diagnostic, "source_gates_survivor_" + survivor)
        self.assertEqual(
            self._cleanup_diagnostic(
                census_error=CleanupRefusal(survivor_classes=("python", "ps")),
            ),
            "source_gates_survivor_multiple",
        )

    def test_unclassified_survivors_and_missing_class_data_use_distinct_values(self):
        self.assertEqual(
            self._cleanup_diagnostic(census_error=CleanupRefusal(survivor_classes="unclassified")),
            "source_gates_survivor_unknown",
        )
        for classes in (("private-process-name",), (), ("python", 7)):
            with self.subTest(classes=classes):
                self.assertEqual(
                    self._cleanup_diagnostic(census_error=CleanupRefusal(survivor_classes=classes)),
                    "source_gates_cleanup_unclassified",
                )

    def test_unreadable_census_selects_the_census_diagnostic(self):
        for census_error in (
            CleanupRefusal(survivor_classes="unavailable"), OSError(), CleanupRefusal(),
        ):
            with self.subTest(census_error=type(census_error).__name__):
                self.assertEqual(
                    self._cleanup_diagnostic(census_error=census_error), "source_gates_census",
                )

    def test_command_timeout_selects_the_timeout_diagnostic(self):
        for attributes in (
            {"probe_check": "probe_process_timeout", "command_check": "timeout"},
            {"command_check": "timeout"},
        ):
            with self.subTest(attributes=attributes):
                self.assertEqual(
                    self._cleanup_diagnostic(command_error=CleanupRefusal(**attributes)),
                    "source_gates_timeout",
                )

    def test_command_cleanup_failure_classifies_survivor_census_and_group_checks(self):
        cases = (
            ({"probe_check": "probe_process_survivor", "survivor_classes": ("helper_security",)},
             "source_gates_survivor_helper_security"),
            ({"probe_check": "probe_process_survivor", "survivor_classes": ()},
             "source_gates_cleanup_unclassified"),
            ({"probe_check": "probe_process_census"}, "source_gates_census"),
            ({"probe_check": "probe_process_group_cleanup"}, "source_gates_group_cleanup"),
            ({"probe_check": "probe_process_capture_cleanup"}, "source_gates_capture_cleanup"),
            ({"probe_check": "untrusted-private-check"}, "source_gates_cleanup_unclassified"),
            ({}, "source_gates_cleanup_unclassified"),
            ({"probe_check": "probe_process_timeout", "command_check": "helper_failure"},
             "source_gates_wait_uncertain"),
            ({"probe_check": "probe_process_timeout"}, "source_gates_cleanup_unclassified"),
        )
        for attributes, expected in cases:
            with self.subTest(attributes=attributes):
                self.assertEqual(
                    self._cleanup_diagnostic(command_error=CleanupRefusal(**attributes)), expected,
                )

    def test_command_cleanup_failure_keeps_the_first_cause_over_a_later_census_failure(self):
        diagnostic = self._cleanup_diagnostic(
            command_error=CleanupRefusal(
                probe_check="probe_process_timeout", command_check="timeout",
            ),
            census_error=CleanupRefusal(survivor_classes=("python",)),
        )
        self.assertEqual(diagnostic, "source_gates_timeout")

    def test_census_refines_a_fallback_command_diagnostic_but_not_a_specific_one(self):
        census_error = CleanupRefusal(survivor_classes=("python",))
        self.assertEqual(
            self._cleanup_diagnostic(command_error=CleanupRefusal(), census_error=census_error),
            "source_gates_survivor_python",
        )
        self.assertEqual(
            self._cleanup_diagnostic(
                command_error=CleanupRefusal(
                    probe_check="probe_process_timeout", command_check="helper_failure",
                ),
                census_error=census_error,
            ),
            "source_gates_wait_uncertain",
        )

    def test_diagnostic_classifier_failure_keeps_cleanup_control_flow(self):
        with patch.object(subject, "_census_diagnostic", side_effect=RuntimeError):
            self.assertEqual(
                self._cleanup_diagnostic(census_error=CleanupRefusal(survivor_classes=("ps",))),
                "source_gates_cleanup_unclassified",
            )
        with patch.object(subject, "_command_cleanup_diagnostic", side_effect=RuntimeError):
            self.assertEqual(
                self._cleanup_diagnostic(command_error=CleanupRefusal(probe_check="probe_process_census")),
                "source_gates_cleanup_unclassified",
            )

    def test_survivor_class_list_matches_the_census_class_order(self):
        path = Path(__file__).resolve().parent / "macos_capability.py"
        spec = importlib.util.spec_from_file_location("macos_capability_drift_check", path)
        capability = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capability)
        self.assertEqual(subject.SURVIVOR_CLASSES, frozenset(capability.SURVIVOR_CLASS_ORDER))

    def test_cwd_restore_failure_selects_the_restore_diagnostic(self):
        self.assertEqual(self._cleanup_diagnostic(fail_restore=True), "source_gates_restore")

    def test_non_cleanup_command_failure_carries_no_cleanup_diagnostic(self):
        with self.assertRaises(Exception) as caught:
            self._run(
                "bootstrap", "lock", validated_tree="core_node_lock_return",
                command_error=FeedbackRefusal("command_failed"),
            )
        self.assertEqual(caught.exception.reason, "command_failed")
        self.assertFalse(hasattr(caught.exception, "cleanup_diagnostic"))

    def test_rust_failure_selects_thirteen_stages_without_running_node(self):
        failed = "parser_clippy"
        completed = subject.RUST_FOUNDATION_GATES[:subject.RUST_FOUNDATION_GATES.index(failed)]
        rust_outcome = {
            "selected_gates": subject.RUST_FOUNDATION_GATES, "completed": completed,
            "failed_stage": failed, "returncode": 4, "stdout": b"rust out", "stderr": b"rust err",
            "stdout_truncated": False, "stderr_truncated": False,
        }
        outcome = subject.extend_diagnostic_outcome(rust_outcome, lambda: self.fail("Node ran"), FakeContract("verify"))
        self.assertEqual(outcome["selected_gates"], subject.FULL_FOUNDATION_GATES)
        self.assertEqual(outcome["completed"], completed)
        self.assertEqual(outcome["failed_stage"], failed)

    def test_node_failure_merges_ordered_prefix_and_bounds_reason_streams(self):
        rust_outcome = {
            "selected_gates": subject.RUST_FOUNDATION_GATES,
            "completed": subject.RUST_FOUNDATION_GATES, "failed_stage": None,
            "returncode": 0, "stdout": b"", "stderr": b"",
            "stdout_truncated": False, "stderr_truncated": False,
        }
        refusal = NodeContractRefusal(
            "vulnerable_dependency", stage="typescript_typecheck", substage="typecheck",
            stdout=b"typecheck output", stderr=b"bounded diagnostic", completed_stages=subject.NODE_GATE_NAMES[:2],
        )
        def fail_node():
            raise refusal

        outcome = subject.extend_diagnostic_outcome(rust_outcome, fail_node, FakeContract("verify"))
        self.assertEqual(outcome["selected_gates"], subject.FULL_FOUNDATION_GATES)
        self.assertEqual(outcome["completed"], subject.RUST_FOUNDATION_GATES + subject.NODE_GATE_NAMES[:2])
        self.assertEqual(outcome["failed_stage"], "typescript_typecheck")
        self.assertEqual(outcome["returncode"], 1)
        self.assertTrue(outcome["stderr"].startswith(b"node_reason=vulnerable_dependency node_substage=typecheck\n"))
        self.assertIn(b"bounded diagnostic", outcome["stderr"])

    def test_node_success_completes_all_thirteen_fixed_stages(self):
        rust_outcome = {
            "selected_gates": subject.RUST_FOUNDATION_GATES,
            "completed": subject.RUST_FOUNDATION_GATES, "failed_stage": None,
            "returncode": 0, "stdout": b"", "stderr": b"",
            "stdout_truncated": False, "stderr_truncated": False,
        }
        node_result = {
            "mode": "verify", "status": "passed", "stages": subject.NODE_GATE_NAMES,
            "node_reviewed_file_count": 24, "node_reviewed_paths_sha256": "a" * 64,
        }
        outcome = subject.extend_diagnostic_outcome(rust_outcome, lambda: node_result, FakeContract("verify"))
        self.assertEqual(outcome["selected_gates"], subject.FULL_FOUNDATION_GATES)
        self.assertEqual(outcome["completed"], subject.FULL_FOUNDATION_GATES)
        self.assertIsNone(outcome["failed_stage"])
        self.assertEqual(outcome["node_reviewed_file_count"], 24)
        self.assertEqual(outcome["node_reviewed_paths_sha256"], "a" * 64)

    def test_node_cleanup_refusal_propagates_without_diagnostic_payload(self):
        rust_outcome = {
            "selected_gates": subject.RUST_FOUNDATION_GATES,
            "completed": subject.RUST_FOUNDATION_GATES, "failed_stage": None,
            "returncode": 0, "stdout": b"", "stderr": b"",
            "stdout_truncated": False, "stderr_truncated": False,
        }
        refusal = NodeContractRefusal("cleanup_incomplete", stage="typescript_tests", substage="tests",
                                      completed_stages=subject.NODE_GATE_NAMES[:3])
        def fail_node():
            raise refusal

        with self.assertRaises(NodeContractRefusal) as caught:
            subject.extend_diagnostic_outcome(rust_outcome, fail_node, FakeContract("verify"))
        self.assertIs(caught.exception, refusal)


if __name__ == "__main__":
    unittest.main()
