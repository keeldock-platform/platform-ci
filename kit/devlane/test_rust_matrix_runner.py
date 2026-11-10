"""Source-free regressions for the closed Core PR1 Rust matrix."""

import argparse
import contextlib
import io
import json
import inspect
import os
import signal
import sys
import subprocess
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import public_audit
import filter as output_filter
import rust_matrix_runner
import rust_tooling
import deadline as deadline_budget
import supervisor
import test_e2e


def _term_split_group(marker):
    marker = Path(marker)
    child_code = (
        "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "pathlib.Path(sys.argv[1] + '.ready').write_text('ready'); time.sleep(30)"
    )
    leader_code = (
        "import pathlib,signal,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]]); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
        "pathlib.Path(sys.argv[1] + '.leader').write_text(str(__import__('os').getpid())); "
        "ready=pathlib.Path(sys.argv[1] + '.ready'); "
        "exec('while not ready.exists(): time.sleep(0.005)'); "
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); time.sleep(30)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", leader_code, str(marker), child_code],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    end = time.monotonic() + 4
    while time.monotonic() < end:
        if marker.exists() and Path(str(marker) + ".ready").exists():
            return process, int(marker.read_text(encoding="ascii"))
        time.sleep(0.01)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)
    raise AssertionError("descendant fixture did not become ready")


def _assert_pid_gone(test, pid):
    end = time.monotonic() + 4
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    test.fail("TERM-ignoring descendant survived group cleanup")


def _coverage(records, suite):
    total = 1
    records.append({
        "kind": "coverage", "stage": rust_matrix_runner._stage_for(suite),
        "suite": suite, "total": total, "passed": total, "failed": 0, "ignored": 0,
    })
    return True


class RustMatrixRunnerTests(unittest.TestCase):
    def _summary_scenario(self):
        return {
            "profile": "core-rust", "allowed_files": {},
            "allowed_tests": test_e2e.RUST_FIXTURE_TESTS, "frames": {},
        }

    def _summary_payload(self, records):
        profile_root = json.loads((Path(__file__).resolve().parents[2] / "ci/devlane-profiles.json").read_text())
        profile = profile_root["profiles"]["core-rust"]
        allowlists = {
            "files": {}, "tests": {item: item for item in test_e2e.RUST_FIXTURE_TESTS.values()},
            "frames": {}, "stages": profile["stages"],
            "codes": sorted(set(profile["diagnostic_codes"] + ["DEVLANE_FAILURE"])),
            "max_lines": {}, "suites": sorted(profile["rust_matrix"]["coverage_ids"]),
        }
        return output_filter.filter_records(
            [json.dumps(row, sort_keys=True, separators=(",", ":")).encode() for row in records],
            allowlists,
        )

    def _coverage_rows(self):
        rows = []
        for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]:
            total = 2 if suite.startswith("fuzz-replay-") else 1
            rows.append({
                "kind": "coverage", "stage": rust_matrix_runner._stage_for(suite),
                "suite": suite, "total": total, "passed": total, "failed": 0, "ignored": 0,
            })
        return rows

    def test_harness_parses_complete_producer_shaped_rust_summary(self):
        payload = self._summary_payload(self._coverage_rows())
        records = test_e2e._summary_records(payload, self._summary_scenario())
        self.assertEqual({row["suite"] for row in records if row["kind"] == "coverage"},
                         set(rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]))

    def test_harness_rejects_every_incomplete_or_nonpassing_rust_summary_shape(self):
        rows = self._coverage_rows()
        mutations = {
            "missing-suite": rows[:-1],
            "extra-suite": rows + [{
                "kind": "coverage", "stage": "unit", "suite": "unexpected-suite",
                "total": 1, "passed": 1, "failed": 0, "ignored": 0,
            }],
            "duplicate-suite": rows + [dict(rows[0]), {
                "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
            }],
            "skipped-suite": rows + [{
                "kind": "control", "stage": "unit", "status": "skip",
            }],
            "failure-record-in-pass-summary": rows + [{
                "kind": "test", "stage": "unit",
                "test": next(iter(test_e2e.RUST_FIXTURE_TESTS.values())),
            }],
            "invalid-counts": [dict(rows[0], ignored=1)] + rows[1:],
            "invalid-total-type": [dict(rows[0], total=True)] + rows[1:],
        }
        for label, changed in mutations.items():
            with self.subTest(label=label):
                try:
                    payload = self._summary_payload(changed)
                except output_filter.FilterRefusal:
                    continue
                with self.assertRaises((RuntimeError, output_filter.FilterRefusal)):
                    test_e2e._summary_records(payload, self._summary_scenario())

    def test_startup_negative_requires_the_intended_projection_refusal(self):
        good = subprocess.CompletedProcess(
            ["supervisor.py", "start"], 2, b"",
            b"devlane_supervisor_refusal=projection-binding-mismatch\n",
        )
        self.assertIsNone(test_e2e._assert_startup_projection_refusal(good))

        refusals = test_e2e.STARTUP_REFUSAL_CODES - {"projection-binding-mismatch"}
        failures = [
            ("unexpected-success", subprocess.CompletedProcess(["supervisor.py", "start"], 0, b"", b""),
             "startup-unexpected-success"),
            ("exit-one", subprocess.CompletedProcess(["supervisor.py", "start"], 1, b"", b""),
             "startup-exit-one"),
            ("signal", subprocess.CompletedProcess(["supervisor.py", "start"], -9, b"", b""),
             "startup-exit-signal"),
            ("unexpected-exit", subprocess.CompletedProcess(["supervisor.py", "start"], 3, b"", b""),
             "startup-exit-unexpected"),
            ("parser", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             b"usage: supervisor.py start --deadline-file DEADLINE_FILE\n"), "startup-parser-refusal"),
            ("import", subprocess.CompletedProcess(["supervisor.py", "start"], 1, b"",
             b"Traceback (most recent call last):\nModuleNotFoundError: private-path\n"),
             "startup-import-failure"),
            ("traceback", subprocess.CompletedProcess(["supervisor.py", "start"], 1, b"",
             b"Traceback (most recent call last):\nRuntimeError: private-canary\n"), "startup-traceback"),
            ("stdout", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"private-path", b""),
             "startup-stdout-unexpected"),
            ("canary", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             b"devlane_supervisor_refusal=KEYCANARY-73A10X\n"), "startup-output-canary"),
            ("empty-stderr", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"", b""),
             "startup-stderr-empty"),
            ("malformed-stderr", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             b"private path and raw diagnostic\n"), "startup-stderr-invalid"),
            ("unknown-refusal", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             b"devlane_supervisor_refusal=unknown-private-code\n"), "startup-refusal-unlisted"),
        ]
        failures.extend(
            (code, subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             ("devlane_supervisor_refusal=" + code + "\n").encode("ascii")), code)
            for code in sorted(refusals)
        )
        for name, result, category in failures:
            with self.subTest(result=name):
                with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                    test_e2e._assert_startup_projection_refusal(result)
                self.assertEqual(caught.exception.category, category)
                state = test_e2e._DiagnosticState()
                state.capture("variant-startup-refusal-check", caught.exception)
                line = state.refusal_line(caught.exception)
                self.assertRegex(line, r"stage=variant-startup-refusal-check exception=[a-z0-9-]{1,32}$")
                for marker in ("private-path", "private-canary", "KEYCANARY-73A10X", "unknown-private-code"):
                    self.assertNotIn(marker, line)

    def _write_projection_startup_fixture(self, root):
        workspace = root / "workspace"
        prepared = root / "prepared"
        workspace.mkdir()
        prepared.mkdir()
        bundle_path = root / "bundle.enc"
        bundle_bytes = b"source-free encrypted envelope placeholder"
        bundle_path.write_bytes(bundle_bytes)
        projection_path = root / "projection.json"
        _projection, projection_bytes = test_e2e._node_projection(
            test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
        )
        projection_path.write_bytes(projection_bytes + b" ")
        now = int(time.time())
        context = {
            "repository": test_e2e.fetch.REPOSITORY, "repository_id": test_e2e.fetch.REPOSITORY_ID,
            "server_url": "https://github.com", "event": "workflow_dispatch", "ref": "refs/heads/main",
            "control_sha": "a" * 40, "control_run_id": "123456", "workflow_path": test_e2e.fetch.WORKFLOW_PATH,
            "run_attempt": 1, "profile": "core-node", "wave_id": "startup-wave-0001",
            "bundle_id": "startup-bundle-0001", "bundle_asset_id": "1234567",
            "bundle_sha256": test_e2e.hashlib.sha256(bundle_bytes).hexdigest(), "bundle_size": len(bundle_bytes),
            "projection_asset_id": "1234568", "projection_sha256": test_e2e.hashlib.sha256(projection_bytes).hexdigest(),
            "projection_size": len(projection_bytes), "expires": now + 1800,
        }
        context_path = root / "context.json"
        context_path.write_bytes(test_e2e.bundle.canonical_json(context) + b"\n")
        positive_path = root / "positive-control.json"
        positive_path.write_bytes(test_e2e.bundle.canonical_json(
            {"connected": True, "target": "public-tls-control"}
        ) + b"\n")
        deadline_path = root / "deadline.json"
        deadline_budget.create(deadline_path, 60, 5, 65)
        return argparse.Namespace(
            state_dir=str(root / "state"), context=str(context_path), workspace=str(workspace),
            prepared=str(prepared), bundle=str(bundle_path), projection=str(projection_path),
            positive_control=str(positive_path), deadline_file=str(deadline_path),
            node_path="", npm_path="", cargo_path="", rustc_path="",
        )

    def _bind_projection_payload(self, args, value):
        payload = test_e2e.bundle.canonical_json(value)
        Path(args.projection).write_bytes(payload)
        context = json.loads(Path(args.context).read_text(encoding="ascii"))
        context["projection_sha256"] = test_e2e.hashlib.sha256(payload).hexdigest()
        context["projection_size"] = len(payload)
        Path(args.context).write_bytes(test_e2e.bundle.canonical_json(context) + b"\n")

    def test_actual_start_refuses_a_tampered_projection_before_state_or_child_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            command = ["start"]
            for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                         "positive_control", "deadline_file"):
                command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(supervisor.sys, "platform", "linux"), \
                    patch.object(supervisor.subprocess, "Popen") as spawn:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = supervisor.main(command)
            self.assertEqual(result, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "devlane_supervisor_refusal=projection-binding-mismatch\n")
            self.assertIsNone(test_e2e._assert_startup_projection_refusal(subprocess.CompletedProcess(
                ["supervisor.py", *command], result, stdout.getvalue().encode(), stderr.getvalue().encode(),
            )))
            self.assertFalse(Path(args.state_dir).exists())
            spawn.assert_not_called()

    def test_actual_service_prepare_binds_projection_before_root_swap_firewall_or_mounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            try:
                service = supervisor.Service(
                    args.state_dir, args.context, args.workspace, args.prepared, args.bundle,
                    args.projection, 1, os.getuid(), {}, args.deadline_file,
                )
                with patch.object(supervisor, "_require_linux_root") as linux_root, \
                        patch.object(supervisor, "_require_swap_disabled") as swap, \
                        patch.object(supervisor, "_mount_private") as private_mount, \
                        patch.object(supervisor, "_configure_firewall") as firewall, \
                        patch.object(supervisor, "_mount_minimal_root") as minimal_root, \
                        patch.object(supervisor, "_mount_bind") as bind:
                    with self.assertRaises(supervisor.SupervisorRefusal) as caught:
                        service.prepare()
                self.assertEqual(caught.exception.code, "projection-binding-mismatch")
                for setup in (linux_root, swap, private_mount, firewall, minimal_root, bind):
                    setup.assert_not_called()
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file

    def test_invalid_bound_projection_has_a_fixed_refusal_before_service_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            projection["playwright"] = [{}]
            self._bind_projection_payload(args, projection)
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            try:
                service = supervisor.Service(
                    args.state_dir, args.context, args.workspace, args.prepared, args.bundle,
                    args.projection, 1, os.getuid(), {}, args.deadline_file,
                )
                with patch.object(supervisor, "_require_linux_root") as linux_root, \
                        patch.object(supervisor, "_require_swap_disabled") as swap, \
                        patch.object(supervisor, "_mount_private") as private_mount, \
                        patch.object(supervisor, "_configure_firewall") as firewall, \
                        patch.object(supervisor, "_mount_minimal_root") as minimal_root:
                    with self.assertRaises(supervisor.SupervisorRefusal) as caught:
                        service.prepare()
                self.assertEqual(caught.exception.code, "projection-invalid")
                for setup in (linux_root, swap, private_mount, firewall, minimal_root):
                    setup.assert_not_called()

                command = ["start"]
                for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                             "positive_control", "deadline_file"):
                    command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(supervisor.sys, "platform", "linux"), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = supervisor.main(command)
                self.assertEqual(result, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "devlane_supervisor_refusal=projection-invalid\n")
                with self.assertRaises(test_e2e.StartupRefusalMismatch) as mismatch:
                    test_e2e._assert_startup_projection_refusal(subprocess.CompletedProcess(
                        ["supervisor.py", *command], result, stdout.getvalue().encode(), stderr.getvalue().encode(),
                    ))
                self.assertEqual(mismatch.exception.category, "projection-invalid")
                self.assertFalse(Path(args.state_dir).exists())
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file

    def test_isolated_rust_runner_launch_imports_only_the_trusted_control_siblings(self):
        root = Path(__file__).resolve().parents[2]
        supervisor_source = inspect.getsource(supervisor)
        self.assertIn('"/usr/bin/python3", "-B", "-I", "-S", "/control/devlane/rust_matrix_runner.py"',
                      supervisor_source)
        self.assertIn('control_root / "kit/devlane", root / "control/devlane", readonly=True',
                      supervisor_source)
        self.assertNotIn("/workspace/source/rust_matrix_runner.py", supervisor_source)
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-S", str(root / "kit/devlane/rust_matrix_runner.py")],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr.decode("utf-8", "replace"))
        self.assertIn(b"the following arguments are required", result.stderr)
        self.assertNotIn(b"ModuleNotFoundError", result.stderr)

    def test_deny_policy_and_offline_tool_argv_match_pinned_contracts(self):
        deny_policy = tomllib.loads(test_e2e.RUST_FIXTURE_SOURCES["deny.toml"].decode("ascii"))
        advisories = deny_policy["advisories"]
        self.assertEqual(advisories["yanked"], "deny")
        self.assertEqual(advisories["unmaintained"], "workspace")
        self.assertEqual(advisories["ignore"], [])
        self.assertNotIn("yanked", deny_policy)
        self.assertNotIn("unmaintained", deny_policy)

        checks = []

        def simple(records, suite, argv, deadline, timeout=1800):
            checks.append((suite, argv))
            return _coverage(records, suite)

        def rust_arm(records, scope, manifest, workspace_mode, mode, config, deadline):
            suffix = "all-features" if mode == "all" else "default"
            records.append({
                "kind": "coverage", "stage": "unit", "suite": scope + "-" + suffix,
                "total": 1, "passed": 1, "failed": 0, "ignored": 0,
            })
            return True

        def replay(records, mode, deadline):
            suffix = "all-features" if mode == "all" else "default"
            records.append({
                "kind": "coverage", "stage": "unit", "suite": "fuzz-replay-" + suffix,
                "total": 1, "passed": 1, "failed": 0, "ignored": 0,
            })
            return True

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check", side_effect=simple), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=rust_arm), \
                    patch.object(rust_matrix_runner, "_fuzz_replay", side_effect=replay):
                result = rust_matrix_runner.run(
                    rust_matrix_runner.EXPECTED_MATRIX, "fixed-test-map", str(report), time.monotonic() + 60,
                )
        self.assertEqual(result, 0)

        deny = next(argv for suite, argv in checks if suite == "deny-root")
        self.assertEqual(deny[1:], [
            "--manifest-path", "/workspace/source/Cargo.toml", "--config", "/workspace/source/deny.toml",
            "--workspace", "--all-features", "--offline", "--locked", "check",
        ])
        self.assertEqual(deny[3], "--config")
        self.assertEqual(deny[5:8], ["--workspace", "--all-features", "--offline"])
        self.assertEqual(deny[8:], ["--locked", "check"])

        audit = next(argv for suite, argv in checks if suite == "audit-root")
        self.assertEqual(audit[1:6], ["audit", "--deny", "unsound", "--no-fetch", "--db"])
        self.assertEqual(audit[6], "/scratch/cargo-home/advisory-dbs/" +
                         rust_matrix_runner.ADVISORY_DB_DIRECTORY)
        self.assertEqual(audit[7:], ["--file", "/workspace/source/Cargo.lock"])

        vet = next(argv for suite, argv in checks if suite == "vet-root")
        self.assertEqual(vet[1:3], ["vet", "check"])
        self.assertEqual(vet[-2:], ["--locked", "--frozen"])

    def test_standalone_cargo_vet_child_receives_the_trusted_cargo_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Mock(pid=321, wait=Mock(return_value=0))
            with patch.object(rust_matrix_runner, "RAW", temporary), \
                    patch.object(rust_matrix_runner, "_remaining", return_value=30), \
                    patch.object(rust_matrix_runner.subprocess, "Popen", return_value=process) as spawn:
                code, _ = rust_matrix_runner._run(
                    "fixed-vet-environment",
                    ["/prepared/devlane-tools/cargo-vet", "vet", "check", "--locked", "--frozen"],
                    time.monotonic() + 30,
                )
            self.assertEqual(code, 0)
            child_env = spawn.call_args.kwargs["env"]
            self.assertEqual(child_env["CARGO"], "/tools/rust/bin/cargo")
            self.assertEqual(child_env["CARGO_HOME"], "/scratch/cargo-home")
            self.assertEqual(child_env["CARGO_NET_OFFLINE"], "true")

    def test_advisory_database_copy_matches_cargo_deny_default_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            source = tools / "advisory-db" / "crates" / "fixture"
            source.mkdir(parents=True)
            (source / "RUSTSEC-2026-0001.md").write_text("source-free advisory", encoding="ascii")
            cargo_home = root / "cargo-home"
            cargo_home.mkdir()
            with patch.object(rust_matrix_runner, "TOOLS_ROOT", str(tools)), \
                    patch.object(rust_matrix_runner, "_remaining", return_value=30):
                rust_matrix_runner._copy_advisory_database(30, cargo_home=str(cargo_home))
            expected = cargo_home / "advisory-dbs" / rust_matrix_runner.ADVISORY_DB_DIRECTORY
            self.assertEqual((expected / "crates/fixture/RUSTSEC-2026-0001.md").read_text(encoding="ascii"),
                             "source-free advisory")
            self.assertFalse((cargo_home / "advisory-db").exists())

    def test_shared_harness_deadline_caps_repeated_phase_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            deadline_budget.create(path, 45, 5, 50)
            with patch.object(test_e2e, "DEADLINE_FILE", str(path)):
                self.assertLessEqual(test_e2e._bounded_timeout(3600), 45)
                self.assertLessEqual(test_e2e._bounded_timeout(2400), 45)
        source = inspect.getsource(test_e2e._run_variant)
        self.assertIn('"--deadline-file", DEADLINE_FILE', source)

    def test_prepared_readonly_database_cleanup_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous_temp = test_e2e.RUNNER_TEMP
            try:
                test_e2e.RUNNER_TEMP = root.resolve()
                prepared = root / "devlane-e2e-owned"
                database = prepared / "devlane-tools/advisory-db/crates"
                database.mkdir(parents=True)
                (database / "public.md").write_text("synthetic advisory", encoding="ascii")
                os.chmod(database, 0o555)
                external = root / "outside"
                external.mkdir()
                outside_mode = external.stat().st_mode & 0o777
                outside_file = external / "must-remain"
                outside_file.write_text("outside", encoding="ascii")
                (prepared / "escape").symlink_to(external, target_is_directory=True)
                test_e2e._remove_owned_prepared_tree(prepared)
                self.assertFalse(prepared.exists())
                self.assertTrue(outside_file.exists())
                self.assertEqual(external.stat().st_mode & 0o777, outside_mode)
            finally:
                test_e2e.RUNNER_TEMP = previous_temp

    def test_key_unlink_failure_still_tears_down_and_preserves_original_error(self):
        for failure_phase in ("start", "decrypt"):
            with self.subTest(phase=failure_phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                scenario = {"profile": "core-node", "name": "unlink-negative",
                            "files": lambda **_kwargs: {}, "allowed_files": {},
                            "allowed_tests": {}, "frames": {}}
                lifecycle = test_e2e._SupervisorLifecycle(root / "devlane-unlink-negative")
                original_unlink = Path.unlink
                def refuse_key(path, *args, **kwargs):
                    if path.name == "synthetic-key.hex":
                        raise PermissionError("synthetic-unlink-failure")
                    return original_unlink(path, *args, **kwargs)
                def run(command, **kwargs):
                    if failure_phase in command:
                        raise RuntimeError("original-" + failure_phase + "-failure")
                    return subprocess.CompletedProcess(command, 0, b"", b"")
                with patch.object(test_e2e, "RUNNER_TEMP", root), \
                        patch.object(test_e2e, "RUN_ID", "unlink-negative"), \
                        patch.object(test_e2e, "_archive", return_value=b"archive"), \
                        patch.object(test_e2e.bundle, "build_envelope", return_value=b"envelope"), \
                        patch.object(test_e2e.bundle, "write_private_key"), \
                        patch.object(test_e2e.bundle, "read_key_file", return_value=b"key"), \
                        patch.object(test_e2e.fetch, "validate_dispatch"), \
                        patch.object(test_e2e, "_positive_control"), \
                        patch.object(test_e2e, "_run", side_effect=run), \
                        patch.object(Path, "unlink", refuse_key), \
                        patch.object(test_e2e.host_cleanup, "clean") as clean, \
                        patch.object(lifecycle, "confirm_teardown") as confirm:
                    with self.assertRaisesRegex(RuntimeError, "original-" + failure_phase + "-failure"):
                        test_e2e._run_variant(scenario, b"{}", root / "prepared",
                                              {name: "" for name in ("node", "npm", "cargo", "rustc")},
                                              b"k" * 32, "accept", lifecycle)
                    clean.assert_called_once()
                    confirm.assert_called_once()
                    self.assertTrue(lifecycle.start_attempted)
                    self.assertFalse(lifecycle.cleanup_confirmed)

    def test_prepared_tree_is_preserved_when_supervisor_teardown_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            previous_temp, previous_run = test_e2e.RUNNER_TEMP, test_e2e.RUN_ID
            test_e2e.RUNNER_TEMP = root
            test_e2e.RUN_ID = "lifecycle-negative"
            scenario = {
                "name": "lifecycle-negative", "profile": "core-node", "payload": b"{}",
                "variants": ("accept",),
            }
            prepared = root / "devlane-e2e-lifecycle-negative-lifecycle-negative"
            marker = prepared / "readonly.db"

            def prepare_fixture(_profile, _projection, destination):
                destination.mkdir()
                (destination / marker.name).write_text("source-free database", encoding="ascii")
                os.chmod(marker, 0o444)
                os.chmod(destination, 0o555)
                return {name: "" for name in ("node", "npm", "cargo", "rustc")}

            evidence = []

            def fail_after_start_attempt(*args):
                lifecycle = args[-1]
                evidence.append(lifecycle)
                lifecycle.note_start_attempt()
                raise RuntimeError("original-execution-failure")

            try:
                with patch.object(test_e2e, "_prepare", side_effect=prepare_fixture), \
                        patch.object(test_e2e, "_run_variant", side_effect=fail_after_start_attempt), \
                        patch.object(test_e2e, "_remove_owned_prepared_tree") as remove_tree:
                    with self.assertRaisesRegex(RuntimeError, "original-execution-failure"):
                        test_e2e._run_scenario(scenario)
                    remove_tree.assert_not_called()
                self.assertEqual(len(evidence), 1)
                self.assertTrue(evidence[0].start_attempted)
                self.assertFalse(evidence[0].cleanup_confirmed)
                self.assertTrue(prepared.is_dir())
                self.assertEqual(prepared.stat().st_mode & 0o777, 0o555)
                self.assertEqual(marker.stat().st_mode & 0o777, 0o444)
            finally:
                if prepared.exists():
                    os.chmod(prepared, 0o700)
                    os.chmod(marker, 0o600)
                    marker.unlink()
                    prepared.rmdir()
                test_e2e.RUNNER_TEMP, test_e2e.RUN_ID = previous_temp, previous_run

    def test_prepared_rust_tool_verification_refuses_a_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            prepared = base / "prepared"
            tools = prepared / "devlane-tools"
            source = base / "source"
            tools.mkdir(parents=True)
            source.mkdir()
            outside = base / "outside-tool"
            outside.write_text("outside", encoding="ascii")
            for name in rust_tooling.TOOLS:
                (tools / name).symlink_to(outside) if name == "cargo-deny" else (tools / name).write_text("tool")
                (source / name).write_text("tool")
            (tools / "advisory-db").mkdir()
            (tools / "advisory-db-revision").write_text("0" * 40, encoding="ascii")
            for entry in rust_tooling.TOOLS:
                (source / entry).write_text("tool")
            outside_mode = outside.stat().st_mode & 0o777
            with self.assertRaisesRegex(RuntimeError, "rust-matrix-tool-layout"):
                test_e2e._verify_prepared_rust_tools(prepared, source)
            self.assertEqual(outside.stat().st_mode & 0o777, outside_mode)

    def test_public_fixture_contract_covers_the_production_matrix_without_static_locks(self):
        root = Path(__file__).resolve().parents[2]
        profile = json.loads((root / "ci/devlane-profiles.json").read_text(encoding="utf-8"))["profiles"]["core-rust"]
        matrix = rust_matrix_runner.EXPECTED_MATRIX
        self.assertEqual(profile["rust_matrix"], matrix)
        self.assertEqual(matrix["toolchain"], "1.99.1")
        self.assertEqual(matrix["tool_versions"], {
            "cargo_deny": "0.20.2", "cargo_audit": "0.22.2", "cargo_vet": "0.10.3",
        })
        self.assertEqual(set(test_e2e.RUST_LOCKFILES), {
            "Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock",
        })
        self.assertEqual(len(matrix["coverage_ids"]), 22)
        self.assertEqual(set(test_e2e.RUST_FIXTURE_TESTS), {
            "root::Cargo.toml::tests::child_has_no_control_secrets_or_sockets",
            "runtime::runtime/crates/services/listener/Cargo.toml::tests::listener_fixture_is_reachable",
            "fuzz::fuzz/Cargo.toml::tests::corpus_fixture_is_present",
            "listener::runtime/crates/services/listener/Cargo.toml::tests::listener_fixture_is_reachable",
        })
        self.assertIn("fuzz/corpus/valid-object.json", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertIn("fuzz/corpus/valid-array.json", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertIn("runtime/crates/services/listener/Cargo.toml", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertIn("supply-chain/audits.toml", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertIn("supply-chain/config.toml", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertIn("runtime/supply-chain/audits.toml", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertIn("runtime/supply-chain/config.toml", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertNotIn("supply-chain/imports.lock", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertNotIn("runtime/supply-chain/imports.lock", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertNotIn("Cargo.lock", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertNotIn("fuzz/Cargo.lock", test_e2e.RUST_FIXTURE_SOURCES)
        self.assertNotIn("runtime/Cargo.lock", test_e2e.RUST_FIXTURE_SOURCES)
        tooling_versions = {name: row[3].rsplit(" ", 1)[-1] for name, row in rust_tooling.TOOLS.items()}
        self.assertEqual(tooling_versions, {
            "cargo-deny": "0.20.2", "cargo-audit": "0.22.2", "cargo-vet": "0.10.3",
        })
        generator = inspect.getsource(test_e2e._write_rust_fixture)
        self.assertIn("generate-lockfile", generator)
        contract = inspect.getsource(test_e2e._validate_rust_fixture)
        self.assertIn("fetch.validate_projection", contract)
        self.assertIn("fetch.project_cargo_lock", contract)
        self.assertIn("bundle.inspect_archive", contract)
        install = inspect.getsource(test_e2e._run_scenario)
        self.assertIn("rust_tooling.install", install)
        self.assertIn('_phase_call("scenario-tool-verify", _verify_prepared_rust_tools, prepared, rust_tool_cache)',
                      install)
        self.assertLess(install.index("rust_tooling.install"), install.index('_phase_call("scenario-variant-run"'))
        main = inspect.getsource(test_e2e.main)
        self.assertLess(main.index("rust_tooling.fetch_tools"), main.index('_phase_call("scenario-run", _run_scenario'))
        prepared_tools = inspect.getsource(test_e2e._verify_prepared_rust_tools)
        self.assertIn("hashlib.sha256(path.read_bytes())", prepared_tools)
        self.assertIn('"advisory-db"', prepared_tools)
        self.assertIn('"advisory-db-revision"', prepared_tools)
        self.assertIn("advisory-database-binding", prepared_tools)
        rustfmt = inspect.getsource(test_e2e._verify_rust_toolchain)
        self.assertIn('"which", "--toolchain", RUST_VERSION, "rustfmt"', rustfmt)

    def test_trusted_profile_is_exactly_the_runner_contract_and_has_no_commands(self):
        root = Path(__file__).resolve().parents[2]
        profile_path = root / "ci/devlane-profiles.json"
        document = json.loads(profile_path.read_text(encoding="utf-8"))
        profile = document["profiles"]["core-rust"]
        self.assertEqual(profile["rust_matrix"], rust_matrix_runner.EXPECTED_MATRIX)
        self.assertEqual(profile["commands"], [])
        self.assertEqual(profile["stages"], ["format", "deny", "audit", "vet", "unit"])
        self.assertEqual(profile["budget_seconds"], 8700)

    def test_fixed_matrix_runs_each_tool_and_every_workspace_feature_arm(self):
        checks = []
        arms = []

        def simple(records, suite, argv, deadline, timeout=1800):
            checks.append((suite, argv))
            return _coverage(records, suite)

        def rust_arm(records, scope, manifest, workspace_mode, feature_set, config, deadline):
            arms.append((scope, manifest, workspace_mode, feature_set))
            suffix = "all-features" if feature_set == "all" else "default"
            return _coverage(records, scope + "-" + suffix)

        def replay(records, feature_set, deadline):
            suffix = "all-features" if feature_set == "all" else "default"
            return _coverage(records, "fuzz-replay-" + suffix)

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check", side_effect=simple), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=rust_arm), \
                    patch.object(rust_matrix_runner, "_fuzz_replay", side_effect=replay):
                result = rust_matrix_runner.run(
                    rust_matrix_runner.EXPECTED_MATRIX, "fixed-test-map", str(report), time.monotonic() + 60,
                )
            self.assertEqual(result, 0)
            records = [json.loads(line) for line in report.read_text(encoding="ascii").splitlines()]
            suites = [row["suite"] for row in records if row["kind"] == "coverage"]
            self.assertEqual(suites, rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"])
            self.assertEqual(len(checks), 12)
            self.assertEqual(len(arms), 8)
            self.assertEqual(
                {(scope, workspace_mode, mode) for scope, _, workspace_mode, mode in arms},
                {(scope, workspace_mode, mode)
                 for scope, workspace_mode in (("root", "workspace"), ("runtime", "workspace"),
                                                ("fuzz", "package"), ("listener", "package"))
                 for mode in ("default", "all")},
            )
            self.assertEqual(
                {manifest for scope, manifest, _, _ in arms if scope == "listener"},
                {"/workspace/source/runtime/crates/services/listener/Cargo.toml"},
            )
            self.assertEqual(
                [row["suite"] for row in records if row["kind"] == "coverage"][-2:],
                ["fuzz-replay-default", "fuzz-replay-all-features"],
            )
            self.assertTrue(all(row["ignored"] == 0 for row in records))
            fmt_argv = {suite: argv for suite, argv in checks if suite.startswith("fmt-")}
            self.assertIn("--all", fmt_argv["fmt-root"])
            self.assertIn("--all", fmt_argv["fmt-runtime"])
            self.assertNotIn("--all", fmt_argv["fmt-fuzz"])

    def test_cargo_test_uses_only_workspace_flag_for_actual_workspaces(self):
        for scope, mode, manifest, expected_workspace_flag in (
            ("root", "workspace", "/workspace/source/Cargo.toml", True),
            ("runtime", "workspace", "/workspace/source/runtime/Cargo.toml", True),
            ("fuzz", "package", "/workspace/source/fuzz/Cargo.toml", False),
            ("listener", "package", "/workspace/source/runtime/crates/services/listener/Cargo.toml", False),
        ):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temporary:
                captured = []
                compile_log = Path(temporary) / "compile.jsonl"
                compile_log.write_text("", encoding="ascii")
                with patch.object(rust_matrix_runner, "_run", return_value=(1, compile_log)) as run:
                    records = []
                    result = rust_matrix_runner._rust_test_arm(
                        records, scope, manifest, mode, "default", "fixed-map", time.monotonic() + 30,
                    )
                    captured.extend(run.call_args.args[1])
                self.assertFalse(result)
                self.assertEqual("--workspace" in captured, expected_workspace_flag)
                self.assertIn("--all-targets", captured)
                self.assertIn("--locked", captured)
                self.assertIn("--offline", captured)
                self.assertIn("--no-run", captured)

    def test_fuzz_replay_requires_a_valid_positive_corpus_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "captured.stdout"
            calls = []
            counts = iter((87, 0))

            def command(label, argv, deadline, timeout=1800, cwd=None, json_stdout=False):
                calls.append((label, argv))
                output.write_text("Replayed %d parser corpus seeds.\n" % next(counts), encoding="ascii")
                return 0, output

            records = []
            with patch.object(rust_matrix_runner, "_run", side_effect=command):
                self.assertTrue(rust_matrix_runner._fuzz_replay(records, "all", time.monotonic() + 30))
            self.assertEqual(records[0]["suite"], "fuzz-replay-all-features")
            self.assertEqual((records[0]["total"], records[0]["passed"], records[0]["ignored"]), (87, 87, 0))
            self.assertIn("--all-features", calls[0][1])
            with patch.object(rust_matrix_runner, "_run", side_effect=command):
                records = []
                self.assertFalse(rust_matrix_runner._fuzz_replay(records, "default", time.monotonic() + 30))
            self.assertEqual(records, [{
                "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
            }])

    def test_empty_fuzz_test_coverage_refuses_the_matrix(self):
        def simple(records, suite, argv, deadline, timeout=1800):
            records.append(rust_matrix_runner._coverage(suite, 1, 0))
            return True

        def rust_arm(records, scope, manifest, workspace_mode, feature_set, config, deadline):
            suite = scope + ("-all-features" if feature_set == "all" else "-default")
            total = 0 if scope == "fuzz" else 1
            records.append(rust_matrix_runner._coverage(suite, total, 0))
            return True

        def replay(records, feature_set, deadline):
            suffix = "all-features" if feature_set == "all" else "default"
            records.append(rust_matrix_runner._coverage("fuzz-replay-" + suffix, 17, 0))
            return True

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check", side_effect=simple), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=rust_arm), \
                    patch.object(rust_matrix_runner, "_fuzz_replay", side_effect=replay):
                result = rust_matrix_runner.run(
                    rust_matrix_runner.EXPECTED_MATRIX, "fixed-map", str(report), time.monotonic() + 60,
                )
            self.assertEqual(result, 1)
            self.assertIn(b'"status":"fail"', report.read_bytes())

    def test_every_workspace_audit_denies_unsound_without_ignores(self):
        audit_calls = {}
        def simple(records, suite, argv, deadline, timeout=1800):
            if suite.startswith("audit-"):
                audit_calls[suite] = argv
            return _coverage(records, suite)
        def arm(records, scope, manifest, workspace_mode, feature_set, config, deadline):
            return _coverage(records, scope + ("-all-features" if feature_set == "all" else "-default"))
        def replay(records, feature_set, deadline):
            return _coverage(records, "fuzz-replay-" + ("all-features" if feature_set == "all" else "default"))
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check", side_effect=simple), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=arm), \
                    patch.object(rust_matrix_runner, "_fuzz_replay", side_effect=replay):
                result = rust_matrix_runner.run(rust_matrix_runner.EXPECTED_MATRIX, "fixed-map",
                                               str(Path(temporary) / "report.jsonl"), time.monotonic() + 60)
        self.assertEqual(result, 0)
        self.assertEqual(set(audit_calls), {"audit-root", "audit-runtime", "audit-fuzz"})
        for argv in audit_calls.values():
            self.assertEqual(argv[1:6], ["audit", "--deny", "unsound", "--no-fetch", "--db"])
            self.assertIn("--file", argv)
            self.assertFalse(any(arg == "--ignore" or arg.startswith("--ignore=") for arg in argv))

    def test_candidate_matrix_mutation_is_rejected_before_execution(self):
        matrix = json.loads(json.dumps(rust_matrix_runner.EXPECTED_MATRIX))
        matrix["workspaces"][0]["manifest"] = "/workspace/source/other/Cargo.toml"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            with patch.object(rust_matrix_runner, "_copy_advisory_database") as copy_db:
                with self.assertRaisesRegex(rust_matrix_runner.MatrixRefusal, "matrix-profile-mismatch"):
                    rust_matrix_runner.run(matrix, "fixed-test-map", str(report), time.monotonic() + 30)
            copy_db.assert_not_called()
            self.assertFalse(report.exists())

    def test_deadline_exhaustion_before_every_fixed_matrix_arm_refuses_without_spawning(self):
        expired = time.monotonic() - 1
        for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"][:12]:
            with self.subTest(suite=suite):
                records = []
                with patch.object(rust_matrix_runner.subprocess, "Popen") as spawn:
                    self.assertFalse(rust_matrix_runner._simple_check(
                        records, suite, ["fixed-tool"], expired,
                    ))
                    spawn.assert_not_called()
                self.assertTrue(any(row.get("kind") == "control" for row in records))
        arms = [(item["id"], item["manifest"], item["mode"])
                for item in rust_matrix_runner.EXPECTED_MATRIX["workspaces"]]
        listener = rust_matrix_runner.EXPECTED_MATRIX["listener"]
        arms.append((listener["id"], listener["manifest"], listener["mode"]))
        for scope, manifest, workspace_mode in arms:
            for feature_set in rust_matrix_runner.EXPECTED_MATRIX["feature_sets"]:
                with self.subTest(scope=scope, feature_set=feature_set):
                    records = []
                    with patch.object(rust_matrix_runner.subprocess, "Popen") as spawn:
                        self.assertFalse(rust_matrix_runner._rust_test_arm(
                            records, scope, manifest, workspace_mode, feature_set,
                            "fixed-test-map", expired,
                        ))
                        spawn.assert_not_called()
                    self.assertTrue(any(row.get("kind") == "control" for row in records))
        for feature_set in rust_matrix_runner.EXPECTED_MATRIX["feature_sets"]:
            with self.subTest(fuzz_replay=feature_set):
                records = []
                with patch.object(rust_matrix_runner.subprocess, "Popen") as spawn:
                    self.assertFalse(rust_matrix_runner._fuzz_replay(records, feature_set, expired))
                    spawn.assert_not_called()
                self.assertTrue(any(row.get("kind") == "control" for row in records))

    def test_deadline_expiry_inside_each_matrix_process_class_kills_child_group(self):
        cases = ("fixed-check", "cargo-test-build", "fuzz-replay")
        with tempfile.TemporaryDirectory() as temporary:
            for index, kind in enumerate(cases, start=1):
                with self.subTest(process_class=kind):
                    process = Mock(pid=320 + index, wait=Mock(side_effect=[
                        subprocess.TimeoutExpired(kind, 10), 0, 0,
                    ]))
                    records = []
                    deadline = time.monotonic() + 60
                    with patch.object(rust_matrix_runner, "RAW", temporary), \
                            patch.object(rust_matrix_runner, "_remaining", side_effect=[10, 0]), \
                            patch.object(rust_matrix_runner.subprocess, "Popen", return_value=process), \
                            patch.object(rust_matrix_runner.os, "killpg") as kill:
                        if kind == "fixed-check":
                            self.assertFalse(rust_matrix_runner._simple_check(
                                records, "fmt-root", ["fixed-tool"], deadline,
                            ))
                        elif kind == "cargo-test-build":
                            self.assertFalse(rust_matrix_runner._rust_test_arm(
                                records, "root", "/workspace/source/Cargo.toml", "workspace", "default",
                                "fixed-test-map", deadline,
                            ))
                        else:
                            self.assertFalse(rust_matrix_runner._fuzz_replay(records, "default", deadline))
                    self.assertEqual([call.args for call in kill.call_args_list], [
                        (process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL),
                    ])
                    self.assertTrue(any(row.get("kind") == "control" for row in records))

    def test_real_term_exiting_leader_does_not_leave_term_ignoring_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            process, descendant = _term_split_group(Path(temporary) / "descendant.pid")
            try:
                with patch.object(rust_matrix_runner, "TERM_GRACE_SECONDS", 0.05):
                    rust_matrix_runner._kill(process)
                self.assertIsNotNone(process.poll())
                _assert_pid_gone(self, descendant)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)

    def test_total_deadline_exhausted_during_fixed_check_kills_the_child_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Mock(
                pid=321,
                wait=Mock(side_effect=[
                    subprocess.TimeoutExpired("fixed-cargo-check", 10), 0, 0,
                ]),
            )
            with patch.object(rust_matrix_runner, "RAW", temporary), \
                    patch.object(rust_matrix_runner, "_remaining", side_effect=[10, 0]), \
                    patch.object(rust_matrix_runner.subprocess, "Popen", return_value=process), \
                    patch.object(rust_matrix_runner.os, "killpg") as kill, \
                    patch.object(rust_matrix_runner.time, "sleep"):
                with self.assertRaisesRegex(rust_matrix_runner.MatrixRefusal, "total-deadline-exhausted"):
                    rust_matrix_runner._run("fixed-deadline-check", ["cargo", "check"], time.monotonic() + 60)
            self.assertEqual([call.args for call in kill.call_args_list], [
                (process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL),
            ])

    def test_zero_exit_without_complete_coverage_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            original = rust_matrix_runner._rust_test_arm

            def missing_listener_arm(records, scope, manifest, workspace_mode, feature_set, config, deadline):
                if scope == "listener" and feature_set == "all":
                    return True
                return original(records, scope, manifest, workspace_mode, feature_set, config, deadline)

            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check",
                                 side_effect=lambda records, suite, argv, deadline, timeout=1800:
                                 _coverage(records, suite)), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=missing_listener_arm):
                result = rust_matrix_runner.run(
                    rust_matrix_runner.EXPECTED_MATRIX, "fixed-test-map", str(report), time.monotonic() + 60,
                )
            self.assertEqual(result, 1)
            records = [json.loads(line) for line in report.read_text(encoding="ascii").splitlines()]
            self.assertNotIn("listener-all-features", [row.get("suite") for row in records])
            self.assertTrue(any(row.get("kind") == "control" and row.get("status") == "fail"
                                for row in records))

    def test_public_audit_accepts_only_complete_opaque_core_coverage_records(self):
        records = []
        for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]:
            total = 1
            if suite.startswith("fuzz-replay-"):
                total = 87
            records.append({
                "kind": "coverage", "stage": rust_matrix_runner._stage_for(suite),
                "suite": suite, "total": total, "passed": total, "failed": 0, "ignored": 0,
            })
        canonical = sorted([
            json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            for row in records
        ])
        public_audit.validate_summary_records(canonical, "core-rust")
        changed = list(canonical)
        row = json.loads(changed[-1])
        row["suite"] = "private-workspace-name"
        changed[-1] = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self.assertRaises(public_audit.AuditRefusal):
            public_audit.validate_summary_records(changed, "core-rust")


if __name__ == "__main__":
    unittest.main()
