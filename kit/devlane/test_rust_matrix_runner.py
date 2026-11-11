"""Source-free regressions for the closed Core PR1 Rust matrix."""

import argparse
import ast
import contextlib
import io
import json
import inspect
import os
import re
import signal
import sys
import subprocess
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
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

    def _write_node_toolchain_fixture(self, root):
        root = Path(root)
        anchor = root / "trusted-system-anchor"
        cache = anchor / "hostedtoolcache"
        node_root = cache / "node" / "24.22.1" / "x64"
        node_bin = node_root / "bin"
        npm_root = node_root / "lib/node_modules/npm"
        npm_cli = node_root / "lib/node_modules/npm/bin/npm-cli.js"
        npm_link = node_bin / "npm"
        log_path = root / "node-fixture-log.jsonl"
        for directory in (
            anchor, cache, cache / "node", cache / "node/24.22.1", node_root,
            node_bin, node_root / "lib", node_root / "lib/node_modules",
            npm_root, npm_root / "bin", npm_root / "node_modules",
        ):
            directory.mkdir(mode=0o755, parents=True, exist_ok=True)
            directory.chmod(0o700 if directory == anchor else 0o755)
        node = node_bin / "node"
        node.write_text(
            chr(35) + "!" + sys.executable + "\n"
            "import json, os, sys\n"
            "log_path = " + repr(str(log_path)) + "\n"
            "with open(log_path, 'a', encoding='utf-8') as output:\n"
            "    output.write(json.dumps({'executable': sys.argv[0], 'argv': sys.argv[1:], "
            "'path': os.environ.get('PATH', ''), "
            "'node_options': os.environ.get('NODE_OPTIONS', ''), "
            "'npm_userconfig': os.environ.get('NPM_CONFIG_USERCONFIG', '')}) + '\\n')\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('v24.22.1')\n"
            "elif len(sys.argv[1:]) == 2 and sys.argv[1].endswith('npm-cli.js') and sys.argv[2] == '--version':\n"
            "    print('11.19.1')\n"
            "else:\n"
            "    raise SystemExit(97)\n",
            encoding="utf-8",
        )
        node.chmod(0o755)
        npm_cli.write_text(chr(35) + "!/usr/bin/env node\n", encoding="ascii")
        npm_cli.chmod(0o755)
        npm_shared = npm_root / "node_modules/shared.js"
        npm_shared.write_text("synthetic shared npm module fixture\n", encoding="ascii")
        npm_shared.chmod(0o644)
        (npm_root / "node_modules/shared-link.js").symlink_to("shared.js")
        npm_link.symlink_to("../lib/node_modules/npm/bin/npm-cli.js")
        return {
            "anchor": anchor, "cache": cache, "node_root": node_root, "node": node,
            "npm": npm_link, "npm_cli": npm_cli, "npm_root": npm_root,
            "log": log_path,
            "paths": {"node": str(node), "npm": str(npm_link), "cargo": "", "rustc": ""},
        }

    @contextlib.contextmanager
    def _node_fixture_policy(self, fixture):
        node_tool_prepare = supervisor.node_tool_prepare
        with patch.object(node_tool_prepare, "NODE_TOOL_CACHE_ROOT", fixture["cache"]), \
                patch.object(node_tool_prepare, "NODE_TOOL_ROOT", fixture["node_root"]), \
                patch.object(node_tool_prepare, "NODE_TOOL_SYSTEM_ANCHORS",
                             ((fixture["anchor"], os.getuid()),)):
            yield

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

    def test_positive_supervisor_status_and_refusal_results_are_finite(self):
        passing = (
            (test_e2e._assert_supervisor_start_ready, b"offline_supervisor=ready\n"),
            (test_e2e._assert_supervisor_probe_pass, b"network_cut_probe=pass\n"),
            (test_e2e._assert_supervisor_decrypt_pass, b"authenticated_decryption=pass\n"),
        )
        for check, marker in passing:
            with self.subTest(success=marker):
                result = subprocess.CompletedProcess(["supervisor.py"], 0, marker, b"")
                self.assertIsNone(check(result))

        errors = (
            (subprocess.CompletedProcess(["supervisor.py"], 0, b"", b""), "startup-success-output-missing"),
            (subprocess.CompletedProcess(["supervisor.py"], 0, b"wrong marker", b""),
             "startup-success-output-invalid"),
            (subprocess.CompletedProcess(["supervisor.py"], 0, b"offline_supervisor=ready\n", b"private path"),
             "startup-success-stderr"),
            (subprocess.CompletedProcess(["supervisor.py"], 1, b"", b""), "startup-exit-one"),
            (subprocess.CompletedProcess(["supervisor.py"], -9, b"", b""), "startup-exit-signal"),
            (subprocess.CompletedProcess(["supervisor.py"], 3, b"", b""), "startup-exit-unexpected"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"", b""), "startup-stderr-empty"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"", b"private diagnostic\n"),
             "startup-stderr-invalid"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"unexpected", b""),
             "startup-stdout-unexpected"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"", b"devlane_supervisor_refusal=KEYCANARY-73A10X\n"),
             "startup-output-canary"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"", b"usage: supervisor.py start\n"),
             "startup-parser-refusal"),
            (subprocess.CompletedProcess(["supervisor.py"], 1, b"",
             b"Traceback (most recent call last):\nModuleNotFoundError: private path\n"),
             "startup-import-failure"),
            (subprocess.CompletedProcess(["supervisor.py"], 1, b"",
             b"Traceback (most recent call last):\nRuntimeError: private path\n"), "startup-traceback"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"",
             b"devlane_supervisor_refusal=unknown-private-code\n"), "startup-refusal-unlisted"),
        )
        refusals = sorted(test_e2e.SUPERVISOR_REFUSAL_CODES)
        for code in refusals:
            errors += ((subprocess.CompletedProcess(
                ["supervisor.py"], 2, b"", ("devlane_supervisor_refusal=" + code + "\n").encode("ascii"),
            ), code),)

        for result, category in errors:
            with self.subTest(category=category):
                with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                    test_e2e._assert_supervisor_start_ready(result)
                self.assertEqual(caught.exception.category,
                                 test_e2e._REFUSAL_CATEGORY_ALIASES.get(category, category))
                if category in test_e2e.SUPERVISOR_REFUSAL_CODES:
                    self.assertEqual(caught.exception.refusal_code, category)
                state = test_e2e._DiagnosticState()
                state.capture("variant-supervisor-start-check", caught.exception)
                line = state.refusal_line(caught.exception)
                self.assertRegex(line, r"stage=variant-supervisor-start-check exception=[a-z0-9-]{1,32}$")
                for marker in ("private path", "private diagnostic", "KEYCANARY-73A10X", "unknown-private-code"):
                    self.assertNotIn(marker, line)

    def test_supervisor_refusal_registry_covers_literal_production_refusals(self):
        source = Path(supervisor.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        literal_codes = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            name = function.id if isinstance(function, ast.Name) else (
                function.attr if isinstance(function, ast.Attribute) else ""
            )
            if name not in ("_refuse", "SupervisorRefusal"):
                continue
            value = node.args[0]
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                literal_codes.add(value.value)
        self.assertTrue(literal_codes)
        self.assertLessEqual(literal_codes, supervisor.REFUSAL_CODES)
        self.assertLessEqual(supervisor.STARTUP_REFUSAL_CODES, supervisor.REFUSAL_CODES)
        self.assertTrue(supervisor.STARTUP_DIAGNOSTIC_CODES)
        self.assertTrue(all(re.fullmatch(r"child-[a-z0-9-]{1,26}", code)
                            and len(code) <= 32 for code in supervisor.STARTUP_DIAGNOSTIC_CODES))

    def test_actual_supervisor_start_parser_requires_deadline_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            command = ["start"]
            for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                         "positive_control"):
                command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    supervisor.main(command)
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("--deadline-file", stderr.getvalue())
            self.assertFalse(Path(args.state_dir).exists())

    def test_actual_supervisor_startup_exceptions_keep_finite_child_stage_and_class(self):
        known = (
            ("firewall", RuntimeError("private path and canary"), "child-firewall-runtime"),
            ("tools", PermissionError("private path"), "child-tools-permission"),
            ("versions", FileNotFoundError("private path"), "child-versions-file-missing"),
            ("profile", TypeError("private path"), "child-profile-type"),
            ("ready", ValueError("private path"), "child-ready-value"),
        )
        for phase, error, code in known:
            with self.subTest(phase=phase, code=code):
                self.assertEqual(supervisor._startup_exception_code(phase, error), code)
                self.assertIn(code, supervisor.STARTUP_DIAGNOSTIC_CODES)
                self.assertLessEqual(len(code), 32)
        self.assertEqual(supervisor._startup_exception_code("not-a-phase", RuntimeError("private")),
                         "child-serve-runtime")
        self.assertEqual(supervisor._startup_exception_code("tools", Exception("private")),
                         "child-tools-unclassified")
        for phase in supervisor.STARTUP_DIAGNOSTIC_PHASES:
            for exception_type, label in supervisor._STARTUP_EXCEPTION_LABELS.items():
                if exception_type is subprocess.TimeoutExpired:
                    error = exception_type("source-free", 1)
                elif exception_type is subprocess.CalledProcessError:
                    error = exception_type(1, "source-free")
                elif exception_type is UnicodeDecodeError:
                    error = exception_type("ascii", b"source-free", 0, 1, "fixture")
                elif exception_type is json.JSONDecodeError:
                    error = exception_type("source-free", "fixture", 0)
                else:
                    error = exception_type("source-free")
                code = supervisor._startup_exception_code(phase, error)
                self.assertEqual(code, "child-" + phase + "-" + label)
                self.assertIn(code, supervisor.STARTUP_DIAGNOSTIC_CODES)
                self.assertLessEqual(len(code), 32)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            args = ["_serve", "--state-dir", str(state), "--context", str(root / "context"),
                    "--workspace", str(root), "--prepared", str(root), "--bundle", str(root / "bundle"),
                    "--projection", str(root / "projection"), "--deadline-file", str(root / "deadline"),
                    "--host-net-inode", "193847", "--owner-uid", str(os.getuid())]

            class FailingService:
                startup_phase = "firewall"

                def prepare(self):
                    raise RuntimeError("private path KEYCANARY-73A10X")

                def _cleanup(self):
                    return None

            with patch.object(supervisor, "Service", return_value=FailingService()), \
                    patch.object(supervisor, "_kill_workload_descendants"), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = supervisor.main(args)
            receipt = (state / supervisor.STARTUP_REFUSAL_NAME).read_bytes()
            self.assertEqual(result, 2)
            self.assertEqual(receipt, b'{"code":"child-firewall-runtime"}')
            self.assertNotIn(b"private path", receipt)
            self.assertNotIn(b"KEYCANARY-73A10X", receipt)

    def test_actual_supervisor_parent_maps_only_allowlisted_child_start_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            node_fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            args.node_path = node_fixture["paths"]["node"]
            args.npm_path = node_fixture["paths"]["npm"]
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(args, projection)
            command = ["start"]
            for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                         "positive_control", "deadline_file"):
                command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
            command.extend(("--node-path", args.node_path, "--npm-path", args.npm_path))
            real_stat = os.stat

            def stat_with_control_namespace(path, *positional, **keywords):
                if os.fspath(path) == "/proc/self/ns/net":
                    return SimpleNamespace(st_ino=193847)
                return real_stat(path, *positional, **keywords)

            for receipt_code, expected in (
                ("child-firewall-runtime", "child-firewall-runtime"),
                ("node-toolchain-version", "node-toolchain-version"),
                ("private-path-and-key", "supervisor-start-failed"),
            ):
                with self.subTest(receipt=receipt_code):
                    state = Path(args.state_dir)
                    state.mkdir(mode=0o700)

                    def fake_spawn(argv, **_kwargs):
                        child_state = Path(argv[argv.index("--state-dir") + 1])
                        (child_state / supervisor.STARTUP_REFUSAL_NAME).write_text(
                            json.dumps({"code": receipt_code}), encoding="ascii",
                        )
                        return SimpleNamespace(pid=48124, poll=lambda: 0)

                    stdout, stderr = io.StringIO(), io.StringIO()
                    with self._node_fixture_policy(node_fixture), \
                            patch.object(supervisor.sys, "platform", "linux"), \
                            patch.object(supervisor.os, "stat", side_effect=stat_with_control_namespace), \
                            patch.object(supervisor.subprocess, "Popen", side_effect=fake_spawn), \
                            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        result_code = supervisor.main(command)
                    result = subprocess.CompletedProcess(
                        ["supervisor.py", *command], result_code,
                        stdout.getvalue().encode(), stderr.getvalue().encode(),
                    )
                    with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                        test_e2e._assert_supervisor_start_ready(result)
                    self.assertEqual(caught.exception.category, expected)
                    self.assertNotIn("private-path-and-key", stderr.getvalue())
                    self.assertFalse((state / supervisor.PID_NAME).exists())
                    self.assertFalse((state / supervisor.STARTUP_REFUSAL_NAME).is_symlink())
                    (state / supervisor.STARTUP_REFUSAL_NAME).unlink()
                    state.rmdir()

    def test_actual_positive_supervisor_parent_launch_uses_the_fixed_ready_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            node_fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            args.node_path = node_fixture["paths"]["node"]
            args.npm_path = node_fixture["paths"]["npm"]
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(args, projection)
            command = ["start"]
            for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                         "positive_control", "deadline_file"):
                command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
            command.extend(("--node-path", args.node_path, "--npm-path", args.npm_path))
            spawned = []

            def fake_spawn(argv, **kwargs):
                spawned.append((argv, kwargs))
                state = Path(argv[argv.index("--state-dir") + 1])
                (state / supervisor.READY_NAME).write_text('{"ready":true}', encoding="ascii")
                return SimpleNamespace(pid=48123, poll=lambda: None)

            real_stat = os.stat

            def stat_with_control_namespace(path, *positional, **keywords):
                if os.fspath(path) == "/proc/self/ns/net":
                    return SimpleNamespace(st_ino=193847)
                return real_stat(path, *positional, **keywords)

            stdout, stderr = io.StringIO(), io.StringIO()
            with self._node_fixture_policy(node_fixture), \
                    patch.object(supervisor.sys, "platform", "linux"), \
                    patch.object(supervisor.os, "stat", side_effect=stat_with_control_namespace), \
                    patch.object(supervisor.subprocess, "Popen", side_effect=fake_spawn), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = supervisor.main(command)
            result = subprocess.CompletedProcess(
                ["supervisor.py", *command], code, stdout.getvalue().encode(), stderr.getvalue().encode(),
            )
            self.assertIsNone(test_e2e._assert_supervisor_start_ready(result), stderr.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(len(spawned), 1)
            argv, options = spawned[0]
            self.assertEqual(argv[:10], ["sudo", "-n", "unshare", "--net", "--mount", "--pid", "--ipc",
                                         "--fork", "--mount-proc", "--kill-child"])
            self.assertEqual(argv[10], sys.executable)
            self.assertEqual(argv[11], str(Path(supervisor.__file__).resolve()))
            self.assertEqual(argv[12], "_serve")
            self.assertEqual(argv[argv.index("--deadline-file") + 1], str(Path(args.deadline_file).resolve()))
            self.assertEqual(argv[argv.index("--node-path") + 1], args.node_path)
            self.assertEqual(argv[argv.index("--npm-path") + 1], args.npm_path)
            self.assertEqual(options["stdin"], subprocess.DEVNULL)
            self.assertEqual(options["stdout"], subprocess.DEVNULL)
            self.assertEqual(options["stderr"], subprocess.DEVNULL)
            self.assertTrue(options["close_fds"])
            self.assertTrue(options["start_new_session"])
            self.assertEqual(options["env"], {
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
            })

    def test_actual_service_prepare_positive_platform_seams_follow_validated_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            node_fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(args, projection)
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            real_run = subprocess.run
            version_calls = []
            events = []

            def record(name, value=None):
                def call(*_args, **_kwargs):
                    events.append(name)
                    return value
                return call

            def recording_run(argv, **kwargs):
                version_calls.append((list(argv), dict(kwargs)))
                return real_run(argv, **kwargs)

            try:
                service = supervisor.Service(
                    args.state_dir, args.context, args.workspace, args.prepared, args.bundle,
                    args.projection, 193847, os.getuid(),
                    node_fixture["paths"],
                    args.deadline_file,
                )
                with self._node_fixture_policy(node_fixture), \
                        patch.dict(os.environ, {"PATH": "/ambient-poison", "NODE_OPTIONS": "--require ignored",
                                                "NPM_CONFIG_USERCONFIG": "/ambient-poison/npmrc"}), \
                        patch.object(supervisor, "_require_linux_root", side_effect=record("root")), \
                        patch.object(supervisor, "_require_swap_disabled", side_effect=record("swap")), \
                        patch.object(supervisor, "_mount_private", side_effect=record("private-mount")), \
                        patch.object(supervisor, "_configure_firewall", side_effect=record("firewall")), \
                        patch.object(supervisor, "_mount_minimal_root", side_effect=record("minimal-root")), \
                        patch.object(supervisor, "_mount_bind", side_effect=record("bundle-bind")), \
                        patch.object(supervisor, "_read_profiles", side_effect=record("profile-read", {"schema": 1})), \
                        patch.object(supervisor.subprocess, "run", side_effect=recording_run):
                    self.assertTrue(service.prepare())
                self.assertEqual(events, ["root", "swap", "private-mount", "firewall", "minimal-root",
                                          "bundle-bind", "bundle-bind", "profile-read"])
                self.assertEqual(service.projection_value, projection)
                self.assertEqual(service.startup_phase, "ready")
                self.assertEqual(service.tool_info["node_root"], str(node_fixture["node_root"]))
                self.assertEqual(supervisor._worker_environment("unit", service.root, service.tool_info)["PATH"],
                                 "/tools/node/bin:/usr/bin:/bin")
                expected_commands = [
                    [str(node_fixture["node"]), "--version"],
                    [str(node_fixture["node"]), str(node_fixture["npm_cli"]), "--version"],
                ] * 2
                self.assertEqual([call[0] for call in version_calls], expected_commands)
                for _argv, kwargs in version_calls:
                    self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                fixture_rows = [json.loads(line) for line in node_fixture["log"].read_text().splitlines()]
                self.assertEqual([(row["executable"], row["argv"]) for row in fixture_rows], [
                    (str(node_fixture["node"]), ["--version"]),
                    (str(node_fixture["node"]), [str(node_fixture["npm_cli"]), "--version"]),
                    (str(node_fixture["node"]), ["--version"]),
                    (str(node_fixture["node"]), [str(node_fixture["npm_cli"]), "--version"]),
                ])
                self.assertTrue(all(row["path"] == "/usr/bin:/bin" for row in fixture_rows))
                self.assertTrue(all(row["node_options"] == "" and row["npm_userconfig"] == ""
                                    for row in fixture_rows))
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file

    def test_node_preflight_uses_exact_node_for_resolved_npm_cli_without_ambient_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            poison = root / "ambient-poison"
            poison.mkdir()
            poison_node = poison / "node"
            poison_node.write_text(chr(35) + "!" + sys.executable + "\nraise SystemExit('ambient-node-ran')\n", encoding="utf-8")
            poison_node.chmod(0o755)
            projection = {"tools": {"node": "24.22.1", "npm": "11.19.1"}}
            real_run = subprocess.run
            calls = []

            def recording_run(argv, **kwargs):
                calls.append((list(argv), dict(kwargs)))
                return real_run(argv, **kwargs)

            with self._node_fixture_policy(fixture), \
                    patch.object(supervisor.subprocess, "run", side_effect=recording_run), \
                    patch.dict(os.environ, {"PATH": str(poison), "NODE_OPTIONS": "--require ambient-canary",
                                            "NPM_CONFIG_USERCONFIG": str(poison / "npmrc")}):
                info = supervisor._preflight_tools("core-node", projection, fixture["paths"], os.getuid())
            self.assertEqual([argv for argv, _kwargs in calls], [
                [str(fixture["node"]), "--version"],
                [str(fixture["node"]), str(fixture["npm_cli"]), "--version"],
            ])
            for _argv, kwargs in calls:
                self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.assertEqual(info["node_root"], str(fixture["node_root"]))
            self.assertEqual(info["paths"]["npm"], str(fixture["npm"]))
            self.assertEqual(info["paths"]["npm_cli"], str(fixture["npm_cli"]))
            fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
            self.assertEqual([(row["executable"], row["argv"]) for row in fixture_rows], [
                (str(fixture["node"]), ["--version"]),
                (str(fixture["node"]), [str(fixture["npm_cli"]), "--version"]),
            ])
            self.assertTrue(all(row["path"] == "/usr/bin:/bin" for row in fixture_rows))
            self.assertTrue(all(row["node_options"] == "" and row["npm_userconfig"] == ""
                                for row in fixture_rows))

    def test_service_prepare_rechecks_tool_permissions_before_second_version_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(args, projection)
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            real_preflight = supervisor._preflight_tools
            real_run = subprocess.run
            calls = []

            def preflight_then_make_bin_untrusted(profile, value, paths, owner_uid):
                result = real_preflight(profile, value, paths, owner_uid)
                (fixture["node_root"] / "bin").chmod(0o777)
                return result

            def recording_run(argv, **kwargs):
                calls.append(list(argv))
                return real_run(argv, **kwargs)

            try:
                service = supervisor.Service(
                    args.state_dir, args.context, args.workspace, args.prepared, args.bundle,
                    args.projection, 193847, os.getuid(), fixture["paths"], args.deadline_file,
                )
                with self._node_fixture_policy(fixture), \
                        patch.object(supervisor, "_require_linux_root"), \
                        patch.object(supervisor, "_require_swap_disabled"), \
                        patch.object(supervisor, "_mount_private"), \
                        patch.object(supervisor, "_configure_firewall"), \
                        patch.object(supervisor, "_mount_minimal_root"), \
                        patch.object(supervisor, "_mount_bind"), \
                        patch.object(supervisor, "_preflight_tools", side_effect=preflight_then_make_bin_untrusted), \
                        patch.object(supervisor, "_read_profiles", return_value={"schema": 1}), \
                        patch.object(supervisor.subprocess, "run", side_effect=recording_run):
                    with self.assertRaises(supervisor.SupervisorRefusal) as caught:
                        service.prepare()
                self.assertEqual(caught.exception.code, "node-toolchain-permissions")
                self.assertEqual(calls, [
                    [str(fixture["node"]), "--version"],
                    [str(fixture["node"]), str(fixture["npm_cli"]), "--version"],
                ])
                self.assertEqual(len(fixture["log"].read_text().splitlines()), 2)
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file
                (fixture["node_root"] / "bin").chmod(0o755)

    def test_prepare_node_version_path_uses_the_validated_node_and_npm_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 5, 65)
            real_run = subprocess.run
            calls = []

            def recording_run(argv, **kwargs):
                calls.append((list(argv), dict(kwargs)))
                return real_run(argv, **kwargs)

            with self._node_fixture_policy(fixture), \
                    patch.object(supervisor.node_tool_prepare, "DEADLINE_FILE", str(deadline_path)), \
                    patch.object(supervisor.subprocess, "run", side_effect=recording_run):
                validated, results = supervisor.node_tool_prepare.verify_node_toolchain_versions(
                    fixture["paths"], os.getuid(),
                )
            self.assertEqual(validated["node"], str(fixture["node"]))
            self.assertEqual(validated["npm_cli"], str(fixture["npm_cli"]))
            self.assertEqual(results["node"].stdout.strip(), b"v24.22.1")
            self.assertEqual(results["npm"].stdout.strip(), b"11.19.1")
            self.assertEqual([argv for argv, _kwargs in calls], [
                [str(fixture["node"]), "--version"],
                [str(fixture["node"]), str(fixture["npm_cli"]), "--version"],
            ])
            self.assertTrue(all(kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
                                for _argv, kwargs in calls))
            fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
            self.assertTrue(all(row["node_options"] == "" and row["npm_userconfig"] == ""
                                for row in fixture_rows))

    def test_prepare_main_parser_uses_explicit_node_paths_before_mount_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            _projection, payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            projection_path = root / "projection.json"
            projection_path.write_bytes(payload)
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 5, 65)
            preparation = supervisor.node_tool_prepare
            expected = [
                [str(fixture["node"]), "--version"],
                [str(fixture["node"]), str(fixture["npm_cli"]), "--version"],
            ]
            real_run = subprocess.run
            calls = []
            stderr = io.StringIO()

            def record_then_stop(argv, **kwargs):
                command = list(argv)
                calls.append((command, dict(kwargs)))
                if command in expected:
                    return real_run(argv, **kwargs)
                raise supervisor.bundle.Refusal("synthetic-preparation-stop")

            arguments = [
                "--projection", str(projection_path), "--output", str(root / "prepared"),
                "--profile", "core-node", "--owner-uid", str(os.getuid()),
                "--owner-gid", str(os.getgid()), "--deadline-file", str(deadline_path),
                "--node-path", str(fixture["node"]), "--npm-path", str(fixture["npm"]),
            ]
            with self._node_fixture_policy(fixture), \
                    patch.object(preparation.sys, "platform", "linux"), \
                    patch.object(preparation.os, "geteuid", return_value=0), \
                    patch.object(preparation.subprocess, "run", side_effect=record_then_stop), \
                    patch.object(preparation, "_kill_children"), \
                    patch.object(preparation, "MOUNT_TARGETS", []), \
                    contextlib.redirect_stderr(stderr):
                result = preparation.main(arguments)

            self.assertEqual(result, 2)
            self.assertEqual(stderr.getvalue(),
                             "dependency_preparation_refusal=synthetic-preparation-stop\n", calls)
            self.assertEqual([command for command, _kwargs in calls], expected + [[
                "mount", "--make-rprivate", "/",
            ]])
            self.assertTrue(all(kwargs.get("env") == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
                                for _command, kwargs in calls[:2]))
            fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
            self.assertEqual([(row["executable"], row["argv"]) for row in fixture_rows], [
                (str(fixture["node"]), ["--version"]),
                (str(fixture["node"]), [str(fixture["npm_cli"]), "--version"]),
            ])

    def test_npm_shebang_sibling_is_not_used_by_fixed_node_version_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            poison = root / "ambient-poison"
            poison.mkdir()
            (poison / "node").write_text(
                chr(35) + "!" + sys.executable + "\nprint('wrong-sibling-node')\n", encoding="utf-8",
            )
            (poison / "node").chmod(0o755)
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 5, 65)

            sibling_result = subprocess.run(
                [str(fixture["npm"]), "--version"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=5,
                env={"PATH": str(poison) + os.pathsep + str(fixture["node_root"] / "bin")},
                check=False,
            )
            self.assertEqual(sibling_result.returncode, 0)
            self.assertEqual(sibling_result.stdout.strip(), b"wrong-sibling-node")

            with self._node_fixture_policy(fixture), \
                    patch.object(supervisor.node_tool_prepare, "DEADLINE_FILE", str(deadline_path)), \
                    patch.dict(os.environ, {"PATH": str(poison), "NODE_OPTIONS": "--require ambient-canary"}):
                validated, results = supervisor.node_tool_prepare.verify_node_toolchain_versions(
                    fixture["paths"], os.getuid(),
                )
            self.assertEqual(validated["node"], str(fixture["node"]))
            self.assertEqual(results["node"].stdout.strip(), b"v24.22.1")
            self.assertEqual(results["npm"].stdout.strip(), b"11.19.1")
            fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
            self.assertEqual([(row["executable"], row["argv"]) for row in fixture_rows], [
                (str(fixture["node"]), ["--version"]),
                (str(fixture["node"]), [str(fixture["npm_cli"]), "--version"]),
            ])
            self.assertTrue(all(row["path"] == "/usr/bin:/bin" for row in fixture_rows))
            self.assertTrue(all(row["node_options"] == "" for row in fixture_rows))

    def test_node_toolchain_rejects_untrusted_owners_permissions_and_layouts_before_execution(self):
        cases = (
            ("world-writable-cache", "node-toolchain-permissions"),
            ("world-writable-bin", "node-toolchain-permissions"),
            ("world-writable-node", "node-toolchain-permissions"),
            ("world-writable-npm-parent", "node-toolchain-permissions"),
            ("bad-owner-cache", "node-toolchain-owner"),
            ("bad-owner-bin", "node-toolchain-owner"),
            ("bad-owner-node", "node-toolchain-owner"),
            ("bad-owner-npm-link", "node-toolchain-owner"),
            ("bad-owner-npm-cli", "node-toolchain-owner"),
            ("bad-owner-npm-dependency", "node-toolchain-owner"),
            ("missing-node", "node-toolchain-missing"),
            ("missing-npm-cli", "node-toolchain-missing"),
            ("non-executable-node", "node-toolchain-executable"),
            ("owner-only-node", "node-toolchain-executable"),
            ("owner-only-npm-cli", "node-toolchain-permissions"),
            ("owner-only-npm-dependency-dir", "node-toolchain-permissions"),
            ("symlinked-node", "node-tool-layout"),
            ("alternate-node-name", "node-tool-layout"),
            ("npm-escape-link", "node-tool-layout"),
            ("npm-nested-escape-link", "node-tool-layout"),
            ("world-writable-npm-dependency-dir", "node-toolchain-permissions"),
            ("world-writable-npm-dependency-file", "node-toolchain-permissions"),
            ("npm-cli-writable", "node-toolchain-permissions"),
        )
        for label, expected_code in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = self._write_node_toolchain_fixture(root / "node-fixture")
                paths = dict(fixture["paths"])
                owner_target = None
                if label == "world-writable-cache":
                    fixture["cache"].chmod(0o777)
                elif label == "world-writable-bin":
                    (fixture["node_root"] / "bin").chmod(0o777)
                elif label == "world-writable-node":
                    fixture["node"].chmod(0o777)
                elif label == "world-writable-npm-parent":
                    (fixture["node_root"] / "lib/node_modules/npm/bin").chmod(0o777)
                elif label == "bad-owner-cache":
                    owner_target = fixture["cache"]
                elif label == "bad-owner-bin":
                    owner_target = fixture["node_root"] / "bin"
                elif label == "bad-owner-node":
                    owner_target = fixture["node"]
                elif label == "bad-owner-npm-link":
                    owner_target = fixture["npm"]
                elif label == "bad-owner-npm-cli":
                    owner_target = fixture["npm_cli"]
                elif label == "bad-owner-npm-dependency":
                    owner_target = fixture["npm_root"] / "node_modules/shared.js"
                elif label == "missing-node":
                    fixture["node"].unlink()
                elif label == "missing-npm-cli":
                    fixture["npm_cli"].unlink()
                elif label == "non-executable-node":
                    fixture["node"].chmod(0o644)
                elif label == "owner-only-node":
                    fixture["node"].chmod(0o700)
                elif label == "owner-only-npm-cli":
                    fixture["npm_cli"].chmod(0o600)
                elif label == "owner-only-npm-dependency-dir":
                    (fixture["npm_root"] / "node_modules").chmod(0o700)
                elif label == "symlinked-node":
                    real_node = fixture["node_root"] / "bin/node-real"
                    fixture["node"].rename(real_node)
                    fixture["node"].symlink_to(real_node.name)
                elif label == "alternate-node-name":
                    alternate = fixture["node_root"] / "bin/validated-node"
                    alternate.write_bytes(fixture["node"].read_bytes())
                    alternate.chmod(0o755)
                    fixture["node"].write_text(
                        chr(35) + "!" + sys.executable + "\nprint('wrong-sibling-node')\n", encoding="utf-8",
                    )
                    fixture["node"].chmod(0o755)
                    paths["node"] = str(alternate)
                elif label == "npm-escape-link":
                    fixture["npm"].unlink()
                    outside = root / "outside-npm-cli.js"
                    outside.write_text("outside synthetic npm cli fixture\n", encoding="ascii")
                    fixture["npm"].symlink_to(outside)
                elif label == "npm-nested-escape-link":
                    nested_link = fixture["npm_root"] / "node_modules/shared-link.js"
                    nested_link.unlink()
                    outside = root / "outside-npm-module.js"
                    outside.write_text("outside synthetic npm module fixture\n", encoding="ascii")
                    nested_link.symlink_to(outside)
                elif label == "world-writable-npm-dependency-dir":
                    (fixture["npm_root"] / "node_modules").chmod(0o777)
                elif label == "world-writable-npm-dependency-file":
                    (fixture["npm_root"] / "node_modules/shared.js").chmod(0o666)
                elif label == "npm-cli-writable":
                    fixture["npm_cli"].chmod(0o666)

                with self._node_fixture_policy(fixture):
                    if owner_target is None:
                        with patch.object(supervisor.subprocess, "run",
                                          side_effect=AssertionError("version command ran before trust refusal")):
                            with self.assertRaises(supervisor.SupervisorRefusal) as caught:
                                supervisor._preflight_tools(
                                    "core-node", {"tools": {"node": "24.22.1", "npm": "11.19.1"}},
                                    paths, os.getuid(),
                                )
                    else:
                        original_lstat = os.lstat

                        def lstat_with_untrusted_owner(path, *args, **kwargs):
                            metadata = original_lstat(path, *args, **kwargs)
                            if Path(path) == owner_target:
                                return SimpleNamespace(st_mode=metadata.st_mode, st_uid=os.getuid() + 1)
                            return metadata

                        with patch.object(supervisor.node_tool_prepare.os, "lstat",
                                          side_effect=lstat_with_untrusted_owner), \
                                patch.object(supervisor.subprocess, "run",
                                             side_effect=AssertionError("version command ran before owner refusal")):
                            with self.assertRaises(supervisor.SupervisorRefusal) as caught:
                                supervisor._preflight_tools(
                                    "core-node", {"tools": {"node": "24.22.1", "npm": "11.19.1"}},
                                    paths, os.getuid(),
                                )
                self.assertEqual(caught.exception.code, expected_code)

    def test_actual_start_requires_explicit_canonical_node_paths_without_system_fallback(self):
        for case in ("missing-node", "alternate-node-name"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = self._write_projection_startup_fixture(root)
                fixture = self._write_node_toolchain_fixture(root / "node-fixture")
                args.npm_path = fixture["paths"]["npm"]
                if case == "alternate-node-name":
                    alternate = fixture["node_root"] / "bin/validated-node"
                    alternate.write_bytes(fixture["node"].read_bytes())
                    alternate.chmod(0o755)
                    args.node_path = str(alternate)
                    expected = "node-tool-layout"
                else:
                    args.node_path = ""
                    expected = "node-toolchain-missing"
                projection, _payload = test_e2e._node_projection(
                    test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
                )
                self._bind_projection_payload(args, projection)
                command = ["start"]
                for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                             "positive_control", "deadline_file"):
                    command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
                command.extend(("--npm-path", args.npm_path))
                if args.node_path:
                    command.extend(("--node-path", args.node_path))
                stdout, stderr = io.StringIO(), io.StringIO()
                with self._node_fixture_policy(fixture), \
                        patch.object(supervisor.sys, "platform", "linux"), \
                        patch.object(supervisor.shutil, "which") as which, \
                        patch.object(supervisor.subprocess, "Popen") as spawn, \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = supervisor.main(command)
                self.assertEqual(result, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "devlane_supervisor_refusal=" + expected + "\n")
                which.assert_not_called()
                spawn.assert_not_called()
                Path(args.state_dir).rmdir()

    def test_actual_supervisor_probe_and_decrypt_clients_emit_only_fixed_success_markers(self):
        with patch.object(supervisor, "_rpc", return_value={"ok": True}) as rpc:
            probe_out, probe_err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(probe_out), contextlib.redirect_stderr(probe_err):
                probe_code = supervisor.main(["probe", "--state-dir", "/source-free/state"])
            probe = subprocess.CompletedProcess(
                ["supervisor.py", "probe"], probe_code, probe_out.getvalue().encode(), probe_err.getvalue().encode(),
            )
            self.assertIsNone(test_e2e._assert_supervisor_probe_pass(probe))
            rpc.assert_called_once_with("/source-free/state", {"op": "probe"})

        rpc.reset_mock()
        rpc.return_value = {"ok": True}
        with patch.dict(os.environ, {"DEVLANE_DECRYPT_KEY": "a" * 64}):
            decrypt_out, decrypt_err = io.StringIO(), io.StringIO()
            with patch.object(supervisor, "_rpc", rpc), \
                    contextlib.redirect_stdout(decrypt_out), contextlib.redirect_stderr(decrypt_err):
                decrypt_code = supervisor.main(["decrypt", "--state-dir", "/source-free/state"])
            self.assertNotIn("DEVLANE_DECRYPT_KEY", os.environ)
        decrypt = subprocess.CompletedProcess(
            ["supervisor.py", "decrypt"], decrypt_code,
            decrypt_out.getvalue().encode(), decrypt_err.getvalue().encode(),
        )
        self.assertIsNone(test_e2e._assert_supervisor_decrypt_pass(decrypt))
        rpc.assert_called_once_with("/source-free/state", {"op": "decrypt", "key": "a" * 64})

        class RefusingSocket:
            def __init__(self):
                response = json.dumps({"ok": False, "code": "decrypt-rejected"},
                                      separators=(",", ":")).encode("ascii")
                self.buffer = len(response).to_bytes(4, "big") + response
                self.sent = b""

            def settimeout(self, _timeout):
                return None

            def connect(self, _path):
                return None

            def sendall(self, value):
                self.sent += value

            def recv(self, amount):
                value, self.buffer = self.buffer[:amount], self.buffer[amount:]
                return value

            def close(self):
                return None

        refusing_socket = RefusingSocket()
        with patch.dict(os.environ, {"DEVLANE_DECRYPT_KEY": "b" * 64}):
            refused_out, refused_err = io.StringIO(), io.StringIO()
            with patch.object(supervisor.socket, "socket", return_value=refusing_socket), \
                    contextlib.redirect_stdout(refused_out), contextlib.redirect_stderr(refused_err):
                refused_code = supervisor.main(["decrypt", "--state-dir", "/source-free/state"])
            self.assertNotIn("DEVLANE_DECRYPT_KEY", os.environ)
        refused = subprocess.CompletedProcess(
            ["supervisor.py", "decrypt"], refused_code,
            refused_out.getvalue().encode(), refused_err.getvalue().encode(),
        )
        self.assertIsNone(test_e2e._assert_supervisor_refusal(refused, "decrypt-rejected"))
        self.assertNotIn(b"b" * 64, refused.stdout + refused.stderr)
        self.assertTrue(refusing_socket.sent.startswith((len(b'{"op":"decrypt","key":"' + b"b" * 64 + b'"}')).to_bytes(4, "big")))

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
        runner_source = (root / "kit/devlane/rust_matrix_runner.py").read_text(encoding="utf-8")
        self.assertIn('"/usr/bin/python3", "-B", "-I", "-S", "/control/devlane/rust_matrix_runner.py"',
                      supervisor_source)
        self.assertIn('control_root / "kit/devlane", root / "control/devlane", readonly=True',
                      supervisor_source)
        self.assertNotIn("/workspace/source/rust_matrix_runner.py", supervisor_source)
        self.assertIn("sys.path.insert(0, str(Path(__file__).resolve().parent))", runner_source)
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            (candidate / "bundle.py").write_text(
                "raise RuntimeError('candidate-import-canary')\n", encoding="ascii",
            )
            (candidate / "rust_test_runner.py").write_text(
                "raise RuntimeError('candidate-import-canary')\n", encoding="ascii",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(candidate)
            result = subprocess.run(
                [sys.executable, "-B", "-I", "-S", str(root / "kit/devlane/rust_matrix_runner.py")],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=candidate, env=environment, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr.decode("utf-8", "replace"))
            self.assertIn(b"the following arguments are required", result.stderr)
            self.assertNotIn(b"ModuleNotFoundError", result.stderr)
            self.assertNotIn(b"candidate-import-canary", result.stderr)

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
                def process_run(command, **kwargs):
                    if failure_phase in command:
                        raise RuntimeError("original-" + failure_phase + "-failure")
                    marker = (b"offline_supervisor=ready\n" if "start" in command else
                              b"network_cut_probe=pass\n" if "probe" in command else b"")
                    return subprocess.CompletedProcess(command, 0, marker, b"")
                with patch.object(test_e2e, "RUNNER_TEMP", root), \
                        patch.object(test_e2e, "RUN_ID", "unlink-negative"), \
                        patch.object(test_e2e, "_archive", return_value=b"archive"), \
                        patch.object(test_e2e.bundle, "build_envelope", return_value=b"envelope"), \
                        patch.object(test_e2e.bundle, "write_private_key"), \
                        patch.object(test_e2e.bundle, "read_key_file", return_value=b"key"), \
                        patch.object(test_e2e.fetch, "validate_dispatch"), \
                        patch.object(test_e2e, "_positive_control"), \
                        patch.object(test_e2e, "_process_run", side_effect=process_run), \
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
