"""Portable source-free mutation tests for the Rust test result adapter.

The libtest and cargo message shapes below were captured from a real toolchain
(`cargo test --no-run --message-format=json`, and the terse libtest output of a
compiled test binary) rather than invented from the parser's own assumptions.
"""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import rust_test_runner


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


"""Captured libtest terse output for `--exact --format terse <name>`."""
LIBTEST_PASS = (b"\nrunning 1 test\n.\ntest result: ok. 1 passed; 0 failed; 0 ignored; "
                b"0 measured; 3 filtered out; finished in 0.02s\n\n")
LIBTEST_FAIL = (b"\nrunning 1 test\ntests::fail_one --- FAILED\n\nfailures:\n\n---- tests::fail_one stdout ----\n"
                b"SYNTHETIC_SOURCE_CANARY SYNTHETIC_KEY_CANARY\n\nthread 'tests::fail_one' panicked at t.rs:4:48:\n"
                b"assertion failed\n\n\nfailures:\n    tests::fail_one\n\ntest result: FAILED. 0 passed; "
                b"1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n\n")
LIBTEST_IGNORED = (b"\nrunning 1 test\ni\ntest result: ok. 0 passed; 0 failed; 1 ignored; "
                   b"0 measured; 3 filtered out; finished in 0.00s\n\n")
LIBTEST_NONE = (b"\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; "
                b"0 measured; 4 filtered out; finished in 0.00s\n\n")
LIBTEST_LIST = b"tests::fail_one: test\ntests::ign: test\ntests::nested_mod_x: test\ntests::ok_one: test\n"


def _artifact(kind, target_test, profile_test, executable):
    return json.dumps({
        "reason": "compiler-artifact", "package_id": "devlane-fixture 0.0.0",
            "manifest_path": "/workspace/source/crates/fixture/Cargo.toml",
        "target": {"kind": [kind], "crate_types": ["lib"], "name": "devlane_fixture",
                   "src_path": "/workspace/source/src/lib.rs", "edition": "2021",
                   "doc": True, "doctest": True, "test": target_test},
        "profile": {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                    "overflow_checks": True, "test": profile_test},
        "features": [], "filenames": [], "executable": executable, "fresh": False,
    })


class RustTestRunnerTests(unittest.TestCase):

    def test_deadline_expiring_at_exact_test_spawn_refuses_and_kills_spawned_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "descendant.pid"
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
            real_popen = subprocess.Popen
            started = []

            def spawn(*_args, **kwargs):
                process = real_popen(
                    [sys.executable, "-c", leader_code, str(marker), child_code],
                    stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"],
                    env=kwargs["env"], close_fds=kwargs["close_fds"],
                    start_new_session=kwargs["start_new_session"],
                )
                started.append(process)
                end = time.monotonic() + 4
                while time.monotonic() < end:
                    if marker.exists() and Path(str(marker) + ".ready").exists():
                        return process
                    time.sleep(0.01)
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                raise AssertionError("exact-test child fixture did not become ready")

            with patch.object(rust_test_runner, "_remaining", side_effect=[
                    10, rust_test_runner.Refusal("total-deadline-exhausted")]) as remaining, \
                    patch.object(rust_test_runner.subprocess, "Popen", side_effect=spawn) as spawn_call, \
                    patch.object(rust_test_runner, "TERM_GRACE_SECONDS", 0.05):
                with self.assertRaisesRegex(rust_test_runner.Refusal, "total-deadline-exhausted"):
                    rust_test_runner._run_one("synthetic-test-executable", "tests::one", time.monotonic() + 10)
            self.assertEqual(remaining.call_count, 2)
            spawn_call.assert_called_once()
            process = started[0]
            descendant = int(marker.read_text(encoding="ascii"))
            leader = int(Path(str(marker) + ".leader").read_text(encoding="ascii"))
            self.assertIsNotNone(process.poll())
            _assert_pid_gone(self, leader)
            _assert_pid_gone(self, descendant)

    def test_real_term_exiting_leader_does_not_leave_term_ignoring_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            process, descendant = _term_split_group(Path(temporary) / "descendant.pid")
            try:
                with patch.object(rust_test_runner, "TERM_GRACE_SECONDS", 0.05):
                    rust_test_runner._kill_process(process)
                self.assertIsNotNone(process.poll())
                _assert_pid_gone(self, descendant)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)

    def _fixture(self, status):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        executable = root / "fake-rust-test"
        executable.write_text(
            chr(35) + "!" + sys.executable + "\n"
            "import sys\n"
            "if '--ignored' in sys.argv:\n"
            "    pass\n"
            "elif '--list' in sys.argv:\n"
            "    sys.stdout.buffer.write(" + repr(LIBTEST_LIST.replace(b"tests::fail_one", b"tests::fixture_case")
                                                    .replace(b"tests::ign: test\n", b"")
                                                    .replace(b"tests::nested_mod_x: test\n", b"")
                                                    .replace(b"tests::ok_one: test\n", b"")) + ")\n"
            "else:\n"
            "    sys.stdout.write('SYNTHETIC_SOURCE_CANARY SYNTHETIC_KEY_CANARY\\n')\n"
            + ("    sys.stdout.buffer.write(" + repr(LIBTEST_FAIL.replace(b"tests::fail_one", b"tests::fixture_case")) + ")\n"
               "    raise SystemExit(101)\n" if status == "FAILED" else
               "    sys.stdout.buffer.write(" + repr(LIBTEST_PASS) + ")\n")
        )
        executable.chmod(0o755)
        config = root / "adapter-config.json"
        config.write_text(json.dumps({"tests": [
            ["root::crates/fixture/Cargo.toml::tests::fixture_case", "case_0001"]
        ]}), encoding="utf-8")
        output = root / "records.jsonl"
        return temporary, executable, config, output

    def test_failed_rust_test_emits_only_its_opaque_id(self):
        temporary, executable, config, output = self._fixture("FAILED")
        with temporary:
            with patch.object(rust_test_runner, "_cargo_test_executables",
                              return_value=[(str(executable), "crates/fixture/Cargo.toml")]):
                self.assertEqual(rust_test_runner.collect("unused", str(config), str(output),
                                                          "root", "root-default", time.monotonic() + 30), 1)
            payload = output.read_bytes()
            self.assertIn(b'{"kind":"test","stage":"unit","test":"case_0001"}\n', payload)
            self.assertIn(b'"failed":1,"ignored":0,"kind":"coverage","passed":0,"stage":"unit","suite":"root-default","total":1', payload)
            self.assertNotIn(b"SYNTHETIC_SOURCE_CANARY", payload)
            self.assertNotIn(b"SYNTHETIC_KEY_CANARY", payload)

    def test_passing_rust_test_emits_no_records(self):
        temporary, executable, config, output = self._fixture("ok")
        with temporary:
            with patch.object(rust_test_runner, "_cargo_test_executables",
                              return_value=[(str(executable), "crates/fixture/Cargo.toml")]):
                self.assertEqual(rust_test_runner.collect("unused", str(config), str(output),
                                                          "root", "root-default", time.monotonic() + 30), 0)
            self.assertIn(b'"failed":0,"ignored":0,"kind":"coverage","passed":1,"stage":"unit","suite":"root-default","total":1', output.read_bytes())

    def test_missing_identity_or_duplicate_json_fails_closed(self):
        temporary, executable, config, output = self._fixture("ok")
        with temporary:
            config.write_text('{"tests":[["private::unknown","case_0001"]]}', encoding="ascii")
            with patch.object(rust_test_runner, "_cargo_test_executables",
                              return_value=[(str(executable), "crates/fixture/Cargo.toml")]):
                self.assertEqual(rust_test_runner.collect("unused", str(config), str(output),
                                                          "root", "root-default", time.monotonic() + 30), 2)
            self.assertEqual(output.read_bytes(), rust_test_runner.FIXED_FAILURE)
            with self.assertRaisesRegex(rust_test_runner.Refusal, "json-invalid"):
                rust_test_runner._strict_json(b'{"tests":[],"tests":[]}', 128)

    def test_empty_required_fuzz_inventory_refuses_instead_of_passing_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "empty.json"
            output = Path(temporary) / "report.jsonl"
            config.write_text('{"tests":[]}', encoding="ascii")
            with patch.object(rust_test_runner, "_cargo_test_executables", return_value=[]):
                result = rust_test_runner.collect(
                    "unused", str(config), str(output), "fuzz", "fuzz-default", time.monotonic() + 30,
                )
            self.assertEqual(result, 2)
            self.assertEqual(output.read_bytes(), rust_test_runner.FIXED_FAILURE)

    def test_captured_libtest_terse_results_are_classified_by_summary_and_exit_code(self):
        """Fails on the old parser, which expected a pretty-format "test <name> ... ok" row."""
        self.assertTrue(rust_test_runner._classify(0, LIBTEST_PASS))
        self.assertFalse(rust_test_runner._classify(101, LIBTEST_FAIL))
        with self.assertRaisesRegex(rust_test_runner.Refusal, "rust-test-ignored"):
            rust_test_runner._classify(0, LIBTEST_IGNORED)
        for code, payload in ((0, LIBTEST_NONE), (0, LIBTEST_FAIL), (101, LIBTEST_PASS), (0, b""),
                              (0, LIBTEST_PASS + LIBTEST_PASS), (101, LIBTEST_NONE), (1, LIBTEST_FAIL),
                              (0, b"test result: ok. 1 passed; 0 failed\n"), (0, b"\xff")):
            with self.subTest(code=code, payload=payload[:30]), self.assertRaises(rust_test_runner.Refusal):
                rust_test_runner._classify(code, payload)

    def test_listing_accepts_the_captured_list_and_rejects_foreign_lines(self):
        temporary = tempfile.TemporaryDirectory()
        with temporary:
            executable = Path(temporary.name) / "lister"
            executable.write_text(chr(35) + "!" + sys.executable + "\nimport sys\nsys.stdout.buffer.write(" + repr(LIBTEST_LIST) + ")\n")
            executable.chmod(0o755)
            deadline = time.monotonic() + 30
            self.assertEqual(rust_test_runner._listed_tests(str(executable), deadline),
                             ["tests::fail_one", "tests::ign", "tests::nested_mod_x", "tests::ok_one"])
            executable.write_text(chr(35) + "!" + sys.executable + "\nprint('SYNTHETIC_SOURCE_CANARY')\n")
            with self.assertRaisesRegex(rust_test_runner.Refusal, "rust-test-list-invalid"):
                rust_test_runner._listed_tests(str(executable), deadline)
            executable.write_text(chr(35) + "!" + sys.executable + "\nprint('bench::x: benchmark')\n")
            with self.assertRaisesRegex(rust_test_runner.Refusal, "rust-test-list-invalid"):
                rust_test_runner._listed_tests(str(executable), deadline)

    def test_total_deadline_exhaustion_during_exact_test_kills_child_group(self):
        process = Mock(pid=654, wait=Mock(side_effect=[
            subprocess.TimeoutExpired("fixed-test", 10), 0, 0,
        ]))
        with patch.object(rust_test_runner, "_remaining", side_effect=[10, 0]), \
                patch.object(rust_test_runner.subprocess, "Popen", return_value=process), \
                patch.object(rust_test_runner.os, "killpg") as kill, \
                patch.object(rust_test_runner.time, "sleep"):
            with self.assertRaisesRegex(rust_test_runner.Refusal, "total-deadline-exhausted"):
                rust_test_runner._run_bounded(
                    ["fixed-test-executable", "case_0001"], list_output=False,
                    deadline=time.monotonic() + 60,
                )
        self.assertEqual([call.args for call in kill.call_args_list], [
            (process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL),
        ])

    def test_cargo_artifacts_select_test_profile_executables_only(self):
        """Captured shapes: a library built for dependants has target.test true but profile.test false and a null executable. The old code required an executable for it and refused."""
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary).resolve() / "target"
            deps = prefix / "debug" / "deps"
            deps.mkdir(parents=True)
            unit = deps / "devlane_fixture-1"
            integ = deps / "integ-2"
            for item in (unit, integ):
                item.write_bytes(b"binary")
                item.chmod(0o755)
            log = Path(temporary) / "unit.log"
            lines = [
                _artifact("custom-build", False, False, None),
                json.dumps({"reason": "build-script-executed"}),
                _artifact("lib", True, False, None),
                _artifact("test", True, True, str(integ)),
                _artifact("lib", True, True, str(unit)),
                json.dumps({"reason": "build-finished", "success": True}),
            ]
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with patch.object(rust_test_runner, "TARGET_PREFIX", str(prefix) + "/"):
                self.assertEqual(
                    rust_test_runner._cargo_test_executables(str(log)),
                    sorted([(str(unit), "crates/fixture/Cargo.toml"),
                            (str(integ), "crates/fixture/Cargo.toml")]),
                )
                broken = lines[:4] + [_artifact("lib", True, True, None)] + lines[5:]
                log.write_text("\n".join(broken) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(rust_test_runner.Refusal, "cargo-test-path-invalid"):
                    rust_test_runner._cargo_test_executables(str(log))
                unfinished = lines[:-1] + [json.dumps({"reason": "build-finished", "success": False})]
                log.write_text("\n".join(unfinished) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(rust_test_runner.Refusal, "cargo-build-incomplete"):
                    rust_test_runner._cargo_test_executables(str(log))


if __name__ == "__main__":
    unittest.main()
