"""Source-free regressions for the closed Core PR1 Rust matrix."""

import json
import os
import signal
import sys
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import public_audit
import rust_matrix_runner


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
