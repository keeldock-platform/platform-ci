"""Source-free tests for the shared outer deadline and reserved cleanup budget."""

import ast
import contextlib
import io
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import Mock, patch

import deadline
import fetch
import host_cleanup
import network_probe
import permit
import prepare
import public_audit
import rust_tooling
import supervisor
import test_e2e


WORKFLOW_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_SCRIPT = re.compile(r"(?=\bpython3\s+-B\s+(kit/devlane/[A-Za-z0-9_.-]+\.py)\b([^\n]*))")


def _workflow_script_invocations():
    calls = []
    for workflow_name in ("devlane-synthetic.yml", "devlane-encrypted.yml"):
        path = WORKFLOW_ROOT / ".github/workflows" / workflow_name
        jobs = public_audit.parse_workflow(path)
        for job_name, job in jobs.items():
            for step in job["steps"]:
                body = re.sub(r"\\\n[ \t]*", " ", "\n".join(step["run"]))
                for line in body.splitlines():
                    for match in WORKFLOW_SCRIPT.finditer(line):
                        script = Path(match.group(1)).name
                        raw_arguments = match.group(2)
                        if script == "deadline.py" and raw_arguments.lstrip().startswith("run "):
                            raw_arguments = raw_arguments.split(" -- ", 1)[0]
                            arguments = shlex.split(raw_arguments) + ["--", "fixed-child"]
                        else:
                            try:
                                arguments = shlex.split(raw_arguments)
                            except ValueError:
                                arguments = shlex.split(raw_arguments + "'")
                        calls.append((workflow_name, job_name, step["name"],
                                      script, arguments))
    return calls


def _bootstrap_deadline_create_arguments(job):
    lines = job["steps"][0]["run"]
    start = next(index for index, line in enumerate(lines) if "python3 -B - <<'PY'" in line)
    end = next(index for index in range(start + 1, len(lines)) if lines[index].strip() == "PY")
    module = ast.parse(textwrap.dedent("\n".join(lines[start + 1:end])))
    matches = []
    for node in ast.walk(module):
        if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name)
                or node.func.id != "run" or not node.args or not isinstance(node.args[0], ast.List)):
            continue
        vector = node.args[0].elts
        if not any(isinstance(item, ast.Name) and item.id == "deadline_script" for item in vector):
            continue
        values = []
        for item in vector:
            if isinstance(item, ast.Constant):
                values.append(item.value)
            elif isinstance(item, ast.Name) and item.id in {"deadline_file", "start_file"}:
                values.append({"deadline_file": "/tmp/deadline.json", "start_file": "/tmp/deadline-start"}[item.id])
            elif (isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name)
                    and item.value.id == "sys" and item.attr == "executable"):
                values.append(sys.executable)
            elif isinstance(item, ast.Name) and item.id == "deadline_script":
                values.append("/trusted/kit/devlane/deadline.py")
            else:
                raise AssertionError("unexpected bootstrap deadline argv expression: " + ast.dump(item))
        matches.append(values[3:])
    if len(matches) != 1:
        raise AssertionError("bootstrap must have one deadline create argv")
    return matches[0]


def _without_option(arguments, option):
    index = arguments.index(option)
    return arguments[:index] + arguments[index + 2:]


def _cli_arguments(arguments):
    """Remove shell redirection/control suffixes from the inventoried argv."""
    cleaned = []
    for value in arguments:
        if value == ";" or value in ("then", "fi") or value.startswith(">") or value.startswith("2>&"):
            break
        cleaned.append(value)
    return cleaned


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


class DeadlineTests(unittest.TestCase):
    def test_mark_start_binds_the_job_deadline_before_setup_elapsed(self):
        with tempfile.TemporaryDirectory() as temporary:
            started = Path(temporary) / "started"
            path = Path(temporary) / "deadline.json"
            self.assertEqual(deadline.main(["mark-start", "--file", str(started)]), 0)
            start = float(started.read_text(encoding="ascii"))
            self.assertEqual(deadline.main([
                "create", "--file", str(path), "--budget-seconds", "5100",
                "--cleanup-reserve-seconds", "300", "--job-seconds", "5400",
                "--started-at-file", str(started),
            ]), 0)
            value = deadline._read(path)
            self.assertEqual(value["work_deadline"], start + 5100)
            reap_reserve = min(deadline.KILL_REAP_SECONDS, value["cleanup_reserve"])
            self.assertAlmostEqual(deadline.cleanup_remaining(path),
                                   value["work_deadline"] + 300 - reap_reserve - time.monotonic(), places=3)

    def test_cleanup_budget_ends_at_job_deadline_after_setup_elapsed(self):
        start = 1000.0
        payload = {
            "schema": 1, "work_deadline": start + 50,
            "cleanup_reserve": 10, "job_seconds": 60,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            path.write_text(json.dumps(payload), encoding="ascii")
            self.assertEqual(deadline.cleanup_remaining(path, now=1055), 2)
            with self.assertRaisesRegex(deadline.DeadlineRefusal, "total-deadline-exhausted"):
                deadline.cleanup_remaining(path, now=1057)

    def test_action_guard_charges_the_full_provider_cap_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            start = time.monotonic()
            deadline.create(path, 600, 300, 900, now=start)
            self.assertAlmostEqual(deadline.guard_action(path, 120, 60, now=start + 419), 181, places=8)
            with self.assertRaisesRegex(deadline.DeadlineRefusal, "action-work-budget-insufficient"):
                deadline.guard_action(path, 120, 60, now=start + 421)

    def test_supervisor_subprocess_timeout_uses_work_and_cleanup_windows(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            start = time.monotonic()
            deadline.create(path, 45, 5, 50, now=start)
            previous = supervisor.ACTIVE_DEADLINE_FILE
            supervisor.ACTIVE_DEADLINE_FILE = str(path)
            try:
                with patch.object(deadline.time, "monotonic", return_value=start + 4):
                    self.assertAlmostEqual(supervisor._bounded_timeout(2400), 41, places=8)
                    self.assertEqual(supervisor._bounded_timeout(8, cleanup=True), 8)
                with patch.object(deadline.time, "monotonic", return_value=start + 46):
                    self.assertAlmostEqual(supervisor._bounded_timeout(8, cleanup=True), 1, places=8)
                with patch.object(deadline.time, "monotonic", return_value=start + 47):
                    with self.assertRaisesRegex(supervisor.SupervisorRefusal, "total-deadline-exhausted"):
                        supervisor._bounded_timeout(8)
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous

    def test_budget_and_cleanup_reserve_must_fit_outer_job(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            start = time.monotonic()
            with patch.object(deadline.time, "monotonic", return_value=start):
                with self.assertRaisesRegex(deadline.DeadlineRefusal, "deadline-budget-invalid"):
                    deadline.create(path, 9910, 900, 10800, now=start)
                deadline.create(path, 9900, 900, 10800, now=start)
            self.assertAlmostEqual(deadline.remaining(path, now=start + 2), 9898, places=8)
            with self.assertRaisesRegex(deadline.DeadlineRefusal, "total-deadline-exhausted"):
                deadline.remaining(path, now=start + 9900)

    def test_phase_is_refused_before_spawn_when_outer_budget_is_exhausted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            start = time.monotonic()
            with patch.object(deadline.time, "monotonic", return_value=start):
                deadline.create(path, 1, 1, 2, now=start)
            with patch.object(deadline.time, "monotonic", return_value=start + 1):
                with patch.object(deadline.subprocess, "Popen") as spawn:
                    with self.assertRaisesRegex(deadline.DeadlineRefusal, "total-deadline-exhausted"):
                        deadline.run(path, ["fixed-command"])
                    spawn.assert_not_called()

    def test_process_timeout_inside_phase_kills_group_and_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            start = time.monotonic()
            with patch.object(deadline.time, "monotonic", return_value=start):
                deadline.create(path, 10, 2, 12, now=start)
            process = Mock(pid=123, wait=Mock(side_effect=[
                subprocess.TimeoutExpired("fixed-command", 10), 0, 0,
            ]))
            with patch.object(deadline.time, "monotonic", return_value=start + 1):
                with patch.object(deadline.subprocess, "Popen", return_value=process):
                    with patch.object(deadline.os, "killpg") as kill, \
                            patch.object(deadline.time, "sleep"):
                        self.assertEqual(deadline.run(path, ["fixed-command"]), 124)
                        self.assertEqual([call.args[1] for call in kill.call_args_list],
                                         [signal.SIGTERM, signal.SIGKILL])
                        self.assertEqual([call.kwargs["timeout"] for call in process.wait.call_args_list],
                                         [9, 0, 2])

    def test_default_watchdog_exits_quickly_so_encrypted_host_cleanup_can_use_its_reserve(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            start = time.monotonic()
            deadline.create(path, 10, 300, 310, now=start)
            process = Mock(pid=123, wait=Mock(side_effect=[
                subprocess.TimeoutExpired("fixed-command", 9),
                subprocess.TimeoutExpired("fixed-command", 2),
                0,
            ]))
            with patch.object(deadline.time, "monotonic", return_value=start + 1), \
                    patch.object(deadline.subprocess, "Popen", return_value=process), \
                    patch.object(deadline.os, "killpg"):
                self.assertEqual(deadline.run(path, ["fixed-command"]), 124)
            self.assertEqual([call.kwargs["timeout"] for call in process.wait.call_args_list], [9, 2, 3])

    def test_outer_watchdog_leaves_only_final_reap_inside_reserved_cleanup_window(self):
        process = Mock(pid=123, wait=Mock(side_effect=[
            subprocess.TimeoutExpired("fixed-command", 2097), 0,
        ]))
        with patch.object(deadline.os, "killpg") as kill:
            deadline._terminate_group(process, reserve=2100)
        self.assertEqual([call.args[1] for call in kill.call_args_list],
                         [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual([call.kwargs["timeout"] for call in process.wait.call_args_list], [2097, 3])

    def test_deadline_watchdog_uses_assigned_cleanup_reserve_before_final_reap(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            start = time.monotonic()
            deadline.create(path, 1, 300, 301, now=start)
            process = Mock(pid=123, wait=Mock(side_effect=[
                subprocess.TimeoutExpired("fixed-command", 0.5),
                subprocess.TimeoutExpired("fixed-command", 297),
                0,
            ]))
            with patch.object(deadline.time, "monotonic", return_value=start + 0.5), \
                    patch.object(deadline.subprocess, "Popen", return_value=process), \
                    patch.object(deadline.os, "killpg") as kill:
                self.assertEqual(deadline.run(path, ["fixed-command"], timeout_cleanup_reserve=300), 124)
            self.assertEqual([call.kwargs["timeout"] for call in process.wait.call_args_list], [0.5, 297, 3])
            self.assertEqual([call.args[1] for call in kill.call_args_list], [signal.SIGTERM, signal.SIGKILL])

    def test_watchdog_cleanup_reserve_cannot_exceed_the_bound_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            deadline.create(path, 60, 30, 90)
            with patch.object(deadline.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(deadline.DeadlineRefusal, "deadline-cleanup-reserve-invalid"):
                    deadline.run(path, ["fixed-command"], timeout_cleanup_reserve=31)
                spawn.assert_not_called()

    def test_real_term_exiting_leader_does_not_leave_term_ignoring_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "descendant.pid"
            path = Path(temporary) / "deadline.json"
            path.write_text(json.dumps({
                "schema": 1,
                "work_deadline": time.monotonic() + 0.5,
                "cleanup_reserve": 1,
                "job_seconds": 2,
            }), encoding="ascii")
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
            with patch.object(deadline, "TERM_GRACE_SECONDS", 0.05):
                self.assertEqual(deadline.run(path, [sys.executable, "-c", leader_code,
                                                      str(marker), child_code]), 124)
            descendant = int(marker.read_text(encoding="ascii"))
            leader = int(Path(str(marker) + ".leader").read_text(encoding="ascii"))
            _assert_pid_gone(self, leader)
            _assert_pid_gone(self, descendant)

    def test_malformed_deadline_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            path.write_text(json.dumps({"schema": 1, "work_deadline": 20}), encoding="ascii")
            with self.assertRaisesRegex(deadline.DeadlineRefusal, "deadline-file-invalid"):
                deadline.remaining(path, now=10)

    def test_start_time_precedes_network_bootstrap_and_symlink_inputs_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = root / "started"
            deadline_path = root / "deadline.json"
            start = time.monotonic()
            started.write_text(repr(start), encoding="ascii")
            with patch.object(deadline.time, "monotonic", return_value=start):
                deadline.create(deadline_path, 20, 5, 30, started_at_file=started)
            self.assertAlmostEqual(deadline.remaining(deadline_path, now=start + 4), 16, places=12)
            link = root / "deadline-link"
            link.symlink_to(deadline_path)
            with self.assertRaises(OSError):
                deadline.remaining(link, now=start + 4)

    def test_deadline_creation_rejects_expiry_that_passed_during_fetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            with self.assertRaisesRegex(deadline.DeadlineRefusal, "total-deadline-exhausted"):
                deadline.create(path, 1, 1, 2, now=time.monotonic() - 5)

    def test_workflow_shares_one_deadline_across_tool_setup_e2e_and_runtime_probe(self):
        workflow = (WORKFLOW_ROOT / ".github/workflows/devlane-synthetic.yml").read_text(encoding="utf-8")
        start = workflow.index("started_at = time.monotonic()")
        fetch = workflow.index('["git", "-C", workspace, "fetch"')
        create = workflow.index('"create", "--file", deadline_file')
        node_setup = workflow.index("uses: actions/setup-node@")
        rust_install = workflow.index("deadline.py run", node_setup)
        e2e_run = workflow.index("deadline.py run", workflow.index("Run full source-free production-path acceptance"))
        probe = workflow.index("deadline.py run", workflow.index("Probe the loopback-only Linux network boundary"))
        self.assertLess(start, fetch)
        self.assertLess(fetch, create)
        self.assertLess(create, node_setup)
        self.assertLess(node_setup, rust_install)
        self.assertLess(e2e_run, probe)
        self.assertIn("timeout-minutes: 90", workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn('"--budget-seconds", "5100"', workflow)
        self.assertIn('"--cleanup-reserve-seconds", "300"', workflow)
        self.assertIn('"--job-seconds", "5400"', workflow)
        self.assertEqual(workflow.count("deadline.py run"), 5)
        self.assertEqual(workflow.count("quiet bounded "), 9)
        self.assertIn('test_e2e.py --deadline-file "$RUNNER_TEMP/devlane-deadline.json"', workflow)
        self.assertIn('bounded() { python3 -B kit/devlane/deadline.py run', workflow)
        self.assertIn("--timeout-cleanup-reserve-seconds 300", workflow)
        harness = (WORKFLOW_ROOT / "kit/devlane/test_e2e.py").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--deadline-file", required=True)', harness)
        prepare = (WORKFLOW_ROOT / "kit/devlane/prepare.py").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--deadline-file", required=True)', prepare)
        tooling = (WORKFLOW_ROOT / "kit/devlane/rust_tooling.py").read_text(encoding="utf-8")
        self.assertIn('fetch_parser.add_argument("--deadline-file", required=True)', tooling)
        self.assertIn('install_parser.add_argument("--deadline-file", required=True)', tooling)
        cleanup = (WORKFLOW_ROOT / "kit/devlane/host_cleanup.py").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--deadline-file", required=True)', cleanup)

    def test_encrypted_run_keeps_host_cleanup_outside_the_default_short_watchdog(self):
        workflow = (WORKFLOW_ROOT / ".github/workflows/devlane-encrypted.yml").read_text(encoding="utf-8")
        self.assertNotIn("--timeout-cleanup-reserve-seconds", workflow)
        cleanup = workflow.split("- name: Shred runner-local workspace", 1)[1].split(
            "  devlane-encrypted-audit:", 1,
        )[0]
        self.assertIn("if: ${{ always() }}", cleanup)
        self.assertIn("timeout-minutes: 15", cleanup)
        self.assertIn('host_cleanup.py --root "$RUN_ROOT" --runner-temp "$RUNNER_TEMP"', cleanup)
        self.assertIn('--deadline-file "$RUN_ROOT/deadline.json"', cleanup)

    def test_both_workflow_bootstraps_bound_git_and_teardown_to_the_initial_monotonic_cutoff(self):
        expectations = {
            "devlane-synthetic.yml": ("devlane-synthetic", 5100, 300, 5400),
            "devlane-encrypted.yml": ("devlane-encrypted-run", 8700, 2100, 10800),
            "devlane-encrypted.yml" + chr(35) + "audit": ("devlane-encrypted-audit", 480, 120, 600),
        }
        for filename, (job_name, work_seconds, cleanup_seconds, job_seconds) in expectations.items():
            workflow_name, _, suffix = filename.partition(chr(35))
            with self.subTest(workflow=filename):
                jobs = public_audit.parse_workflow(WORKFLOW_ROOT / ".github/workflows" / workflow_name)
                job = jobs[job_name]
                bootstrap = job["steps"][0]
                source = "\n".join(bootstrap["run"])
                git_fetch = source.index('["git", "-C", workspace, "fetch"')
                self.assertLess(source.index("started_at = time.monotonic()"), git_fetch)
                self.assertLess(source.index("os.open(start_file"), git_fetch)
                self.assertLess(source.index("dispatch-identity"), git_fetch)
                self.assertGreaterEqual(source.count("remaining = work_deadline - time.monotonic()"), 2)
                self.assertIn(f"work_deadline = started_at + {work_seconds}", source)
                self.assertIn("timeout = min(540, remaining - reap_seconds)", source)
                self.assertIn("timeout = min(timeout, 540, remaining - reap_seconds)", source)
                self.assertIn("stdout=subprocess.PIPE if capture else subprocess.DEVNULL", source)
                self.assertIn('refuse("bootstrap-work-deadline")', source)
                self.assertIn("start_new_session=True", source)
                self.assertIn("os.killpg(process.pid, signal.SIGTERM)", source)
                self.assertIn("process.communicate(timeout=2)", source)
                self.assertIn("os.killpg(process.pid, signal.SIGKILL)", source)
                self.assertIn("process.communicate(timeout=3)", source)
                self.assertIn('"remote", "get-url", "origin"', source)
                self.assertIn("bootstrap-origin-mismatch", source)
                self.assertIn('"--started-at-file", start_file', source)
                self.assertIn(f'"--budget-seconds", "{work_seconds}"', source)
                self.assertIn(f'"--cleanup-reserve-seconds", "{cleanup_seconds}"', source)
                self.assertIn(f'"--job-seconds", "{job_seconds}"', source)
                self.assertEqual(job["timeout_minutes"] * 60, job_seconds)
                self.assertEqual(job["env"]["CI_WORKSPACE"], "${{ github.workspace }}")
                create_arguments = _bootstrap_deadline_create_arguments(job)
                self.assertEqual(create_arguments, [
                    "create", "--file", "/tmp/deadline.json", "--budget-seconds", str(work_seconds),
                    "--cleanup-reserve-seconds", str(cleanup_seconds), "--job-seconds", str(job_seconds),
                    "--started-at-file", "/tmp/deadline-start",
                ])
                with patch.object(deadline, "create") as create_call:
                    self.assertEqual(deadline.main(create_arguments), 0)
                    create_call.assert_called_once()
                self.assertFalse(any(re.match(r"\s*git\s+(fetch|checkout)\b", line)
                                     for line in bootstrap["run"]))

    def test_action_caps_are_accounted_from_the_deadline_origin_without_claiming_action_awareness(self):
        cases = {
            ("devlane-synthetic.yml", "devlane-synthetic"): {
                "job_seconds": 5400,
                "actions": {
                    "Set up pinned Node toolchain": 10,
                    "Save the synthetic permit through the Actions cache": 2,
                    "Restore the synthetic permit with the encrypted-lane path and key shape": 2,
                },
            },
            ("devlane-encrypted.yml", "devlane-encrypted-run"): {
                "job_seconds": 10800,
                "actions": {
                    "Restore exact source-free control evidence": 1,
                    "Restore one-run bundle permit": 1,
                    "Save one-run bundle permit": 1,
                    "Restore and verify persisted one-run permit": 1,
                    "Set up pinned Node toolchain": 5,
                },
            },
            ("devlane-encrypted.yml", "devlane-encrypted-audit"): {
                "job_seconds": 600,
                "actions": {},
            },
        }
        for (filename, job_name), expected in cases.items():
            with self.subTest(workflow=filename):
                job = public_audit.parse_workflow(WORKFLOW_ROOT / ".github/workflows" / filename)[job_name]
                action_caps = {step["name"]: step["timeout_minutes"]
                               for step in job["steps"] if step["uses"]}
                self.assertEqual(action_caps, expected["actions"])
                self.assertTrue(all(type(value) is int and value > 0 for value in action_caps.values()))
                self.assertLessEqual(sum(action_caps.values()), job["timeout_minutes"])
                for index, step in enumerate(job["steps"]):
                    if not step["uses"]:
                        continue
                    guard = job["steps"][index - 1]
                    self.assertIn("Reserve work time", guard["name"])
                    guard_source = "\n".join(guard["run"])
                    self.assertIn("deadline.py guard-action", guard_source)
                    self.assertIn("--step-timeout-seconds %d" % (step["timeout_minutes"] * 60), guard_source)
                    self.assertIn("--margin-seconds 60", guard_source)
                bootstrap = job["steps"][0]
                self.assertEqual(bootstrap["timeout_minutes"], job["timeout_minutes"])
                self.assertIn("started_at = time.monotonic()", "\n".join(bootstrap["run"]))
                if action_caps:
                    first_action = min(index for index, step in enumerate(job["steps"]) if step["uses"])
                    self.assertLess(job["steps"].index(bootstrap), first_action)
                else:
                    self.assertIn("deadline.py run", "\n".join(job["steps"][-1]["run"]))
                work, cleanup, job_seconds = {
                    5400: (5100, 300, 5400), 10800: (8700, 2100, 10800),
                    600: (480, 120, 600),
                }[expected["job_seconds"]]
                self.assertEqual(work + cleanup, job_seconds)
                self.assertEqual(job["timeout_minutes"] * 60, job_seconds)

    def test_all_actual_python_child_argv_are_inventoried_and_deadline_consumers_reach_their_real_parsers(self):
        calls = _workflow_script_invocations()
        expected_counts = Counter({
            ("devlane-synthetic.yml", "devlane-synthetic", "deadline.py"): 8,
            ("devlane-synthetic.yml", "devlane-synthetic", "permit.py"): 3,
            ("devlane-synthetic.yml", "devlane-synthetic", "test_acceptance.py"): 1,
            ("devlane-synthetic.yml", "devlane-synthetic", "test_audit_contracts.py"): 1,
            ("devlane-synthetic.yml", "devlane-synthetic", "test_coordinator.py"): 1,
            ("devlane-synthetic.yml", "devlane-synthetic", "test_e2e.py"): 2,
            ("devlane-synthetic.yml", "devlane-synthetic", "test_linux_runtime.py"): 1,
            ("devlane-synthetic.yml", "devlane-synthetic", "test_rehearsal.py"): 1,
            ("devlane-synthetic.yml", "devlane-synthetic", "test_rust_report.py"): 1,
            ("devlane-synthetic.yml", "devlane-synthetic", "test_rust_test_runner.py"): 1,
            ("devlane-encrypted.yml", "devlane-encrypted-run", "deadline.py"): 26,
            ("devlane-encrypted.yml", "devlane-encrypted-audit", "deadline.py"): 1,
            ("devlane-encrypted.yml", "devlane-encrypted-run", "fetch.py"): 4,
            ("devlane-encrypted.yml", "devlane-encrypted-run", "host_cleanup.py"): 1,
            ("devlane-encrypted.yml", "devlane-encrypted-run", "network_probe.py"): 1,
            ("devlane-encrypted.yml", "devlane-encrypted-run", "permit.py"): 3,
            ("devlane-encrypted.yml", "devlane-encrypted-run", "prepare.py"): 1,
            ("devlane-encrypted.yml", "devlane-encrypted-run", "rust_tooling.py"): 2,
            ("devlane-encrypted.yml", "devlane-encrypted-run", "supervisor.py"): 4,
            ("devlane-encrypted.yml", "devlane-encrypted-audit", "public_audit.py"): 1,
        })
        self.assertEqual(Counter((workflow, job, script) for workflow, job, _step, script, _args in calls),
                         expected_counts)

        for workflow, _job, _step, script, arguments in calls:
            with self.subTest(workflow=workflow, script=script, arguments=arguments):
                arguments = _cli_arguments(arguments)
                if script == "deadline.py":
                    self.assertIn("--file", arguments)
                    self._assert_required_argument(deadline.main, arguments, "--file")
                    operation = arguments[0]
                    if operation == "create":
                        with patch.object(deadline, "create") as create_call:
                            self.assertEqual(deadline.main(arguments), 0)
                            create_call.assert_called_once()
                    elif operation == "check":
                        with patch.object(deadline, "remaining", return_value=1):
                            self.assertEqual(deadline.main(arguments), 0)
                    elif operation == "guard-action":
                        with patch.object(deadline, "remaining", return_value=3600):
                            self.assertEqual(deadline.main(arguments), 0)
                    else:
                        self.assertEqual(operation, "run")
                        with patch.object(deadline, "run", return_value=0) as run_call:
                            self.assertEqual(deadline.main(arguments), 0)
                            run_call.assert_called_once()
                            if "--timeout-cleanup-reserve-seconds" in arguments:
                                self.assertEqual(run_call.call_args.kwargs["timeout_cleanup_reserve"], 300)
                elif script == "test_e2e.py":
                    self.assertIn("--deadline-file", arguments)
                    self._assert_required_argument(test_e2e.main, arguments, "--deadline-file")
                    with patch.object(test_e2e, "DEADLINE_FILE", ""), \
                            patch.object(deadline, "remaining",
                                         side_effect=deadline.DeadlineRefusal("total-deadline-exhausted")):
                        with self.assertRaisesRegex(deadline.DeadlineRefusal, "total-deadline-exhausted"):
                            test_e2e.main(arguments)
                elif script == "prepare.py":
                    self.assertIn("--deadline-file", arguments)
                    safe_arguments = [value.replace("$DEVLANE_PROFILE", "core-node")
                                      .replace("$owner_uid", "1000")
                                      .replace("$owner_gid", "1000") for value in arguments]
                    for option in ("--projection", "--output", "--profile", "--owner-uid", "--owner-gid",
                                   "--deadline-file"):
                        self._assert_required_argument(prepare.main, safe_arguments, option)
                    errors = io.StringIO()
                    with patch.object(prepare.deadline_budget, "remaining",
                                      side_effect=deadline.DeadlineRefusal("total-deadline-exhausted")), \
                            contextlib.redirect_stderr(errors):
                        self.assertEqual(prepare.main(safe_arguments), 2)
                    self.assertIn("dependency_preparation_refusal=total-deadline-exhausted", errors.getvalue())
                elif script == "rust_tooling.py":
                    self.assertIn("--deadline-file", arguments)
                    required = (("--output", "--deadline-file") if arguments[0] == "fetch" else
                                ("--source", "--prepared", "--deadline-file"))
                    for option in required:
                        self._assert_required_argument(rust_tooling.main, arguments, option)
                    errors = io.StringIO()
                    with patch.object(deadline, "remaining",
                                      side_effect=deadline.DeadlineRefusal("total-deadline-exhausted")), \
                            contextlib.redirect_stderr(errors):
                        self.assertEqual(rust_tooling.main(arguments), 2)
                    self.assertIn("rust_tooling_refusal=tooling-failed", errors.getvalue())
                elif script == "host_cleanup.py":
                    self.assertIn("--deadline-file", arguments)
                    with tempfile.TemporaryDirectory() as temporary:
                        base = Path(temporary).resolve()
                        run_id = "parser-run-0001"
                        run_root = base / ("devlane-" + run_id)
                        safe_arguments = [value.replace("$RUN_ROOT", str(run_root)).replace(
                            "$RUNNER_TEMP", str(base)) for value in arguments]
                        for option in ("--root", "--runner-temp", "--deadline-file"):
                            self._assert_required_argument(host_cleanup.main, safe_arguments, option)
                        output = io.StringIO()
                        with patch.dict(os.environ, {"GITHUB_RUN_ID": run_id}), \
                                patch.object(host_cleanup, "_confirm_supervisor_absent"), \
                                contextlib.redirect_stdout(output):
                            self.assertEqual(host_cleanup.main(safe_arguments), 0)
                        self.assertEqual(output.getvalue().strip(), "cleanup_receipt=confirmed")
                        self.assertFalse(run_root.exists())
                elif script == "supervisor.py":
                    required = {
                        "start": ("--state-dir", "--context", "--workspace", "--prepared", "--bundle",
                                  "--projection", "--positive-control", "--deadline-file"),
                        "probe": ("--state-dir",), "decrypt": ("--state-dir",),
                        "execute": ("--state-dir", "--context"),
                    }[arguments[0]]
                    for option in required:
                        self._assert_required_argument(supervisor.main, arguments, option)
                    with patch.object(supervisor, "_start", return_value=0), \
                            patch.object(supervisor, "_client", return_value=0):
                        self.assertEqual(supervisor.main(arguments), 0)
                elif script == "fetch.py":
                    safe_arguments = [value.replace("$DEVLANE_BUNDLE_SIZE", "4096")
                                      .replace("$DEVLANE_PROJECTION_SIZE", "512") for value in arguments]
                    required = {
                        "context": ("--output",),
                        "download": ("--asset-id", "--size", "--sha256", "--output"),
                        "check-projection": ("--file", "--profile"),
                    }[safe_arguments[0]]
                    for option in required:
                        self._assert_required_argument(fetch.main, safe_arguments, option)
                elif script == "permit.py":
                    required = (("--file", "--control-sha", "--run-id") if arguments[0] == "verify-control"
                                else ("--file",))
                    for option in required:
                        self._assert_required_argument(permit.main, arguments, option)
                elif script == "network_probe.py":
                    self._assert_required_argument(network_probe.main, arguments, "--output")
                elif script == "public_audit.py":
                    self.assertEqual(arguments, [])
                    self.assertEqual(public_audit.main.__code__.co_argcount, 0)
                elif script.startswith("test_"):
                    self.assertEqual(arguments, [])
                else:
                    self.fail("unreviewed workflow Python child argv: " + script)

    def _assert_required_argument(self, parser_main, arguments, option):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            with self.assertRaises(SystemExit) as raised:
                parser_main(_without_option(arguments, option))
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("required: " + option, errors.getvalue())

    def test_host_cleanup_removes_owned_readonly_database_only_after_absence_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            run_id = "readonly-cleanup-0001"
            run_root = base / ("devlane-" + run_id)
            prepared = run_root / "prepared"
            database = prepared / "devlane-tools/advisory-db/crates/fixture"
            database.mkdir(parents=True)
            public_db = database / "RUSTSEC-public-fixture.md"
            public_db.write_text("source-free advisory fixture", encoding="ascii")
            external = base / "external"
            external.mkdir()
            outside_file = external / "must-remain"
            outside_file.write_text("outside", encoding="ascii")
            outside_mode = external.stat().st_mode & 0o777
            (prepared / "escape").symlink_to(external, target_is_directory=True)
            for directory in (database, database.parent, database.parent.parent, prepared):
                os.chmod(directory, 0o555)
            proc_root = base / "proc-fixture"
            proc_root.mkdir()
            deadline_path = base / "deadline.json"
            deadline.create(deadline_path, 120, 60, 180)
            output = io.StringIO()
            try:
                with patch.dict(os.environ, {"GITHUB_RUN_ID": run_id}), \
                        patch.object(host_cleanup, "PROC_ROOT", proc_root), \
                        contextlib.redirect_stdout(output):
                    host_cleanup.clean(str(run_root), str(base), deadline_file=str(deadline_path))
                self.assertEqual(output.getvalue().strip(), "cleanup_receipt=confirmed")
                self.assertFalse(run_root.exists())
                self.assertTrue(outside_file.exists())
                self.assertEqual(external.stat().st_mode & 0o777, outside_mode)
            finally:
                if prepared.exists():
                    os.chmod(prepared, 0o700)
                    for directory in (database.parent.parent, database.parent, database):
                        if directory.exists():
                            os.chmod(directory, 0o700)

    def test_host_cleanup_preserves_readonly_database_when_teardown_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            run_id = "readonly-preserve-0001"
            run_root = base / ("devlane-" + run_id)
            prepared = run_root / "prepared"
            database = prepared / "devlane-tools/advisory-db/crates"
            database.mkdir(parents=True)
            public_db = database / "RUSTSEC-public-fixture.md"
            public_db.write_text("source-free advisory fixture", encoding="ascii")
            run_root.mkdir(exist_ok=True)
            state = run_root / "state"
            state.mkdir()
            os.chmod(database, 0o555)
            os.chmod(prepared, 0o555)
            proc_root = base / "proc-fixture"
            proc_root.mkdir()
            deadline_path = base / "deadline.json"
            deadline.create(deadline_path, 120, 60, 180)
            errors = io.StringIO()
            try:
                with patch.dict(os.environ, {"GITHUB_RUN_ID": run_id}), \
                        patch.object(host_cleanup, "PROC_ROOT", proc_root), \
                        patch.object(host_cleanup, "_confirm_supervisor_absent",
                                     side_effect=RuntimeError("cleanup-incomplete")), \
                        patch.object(host_cleanup.owned_tree_cleanup, "remove_owned_tree") as remove_tree, \
                        contextlib.redirect_stderr(errors):
                    result = host_cleanup.main([
                        "--root", str(run_root), "--runner-temp", str(base),
                        "--deadline-file", str(deadline_path),
                    ])
                self.assertEqual(result, 2)
                self.assertIn("cleanup_receipt=unconfirmed", errors.getvalue())
                remove_tree.assert_not_called()
                self.assertTrue(prepared.is_dir())
                self.assertEqual(prepared.stat().st_mode & 0o777, 0o555)
                self.assertEqual(database.stat().st_mode & 0o777, 0o555)
                self.assertTrue(public_db.exists())
            finally:
                if prepared.exists():
                    os.chmod(prepared, 0o700)
                    if (prepared / "devlane-tools").exists():
                        os.chmod(prepared / "devlane-tools", 0o700)
                    if (prepared / "devlane-tools/advisory-db").exists():
                        os.chmod(prepared / "devlane-tools/advisory-db", 0o700)
                    if database.exists():
                        os.chmod(database, 0o700)

    def test_host_cleanup_does_not_confirm_missing_root_while_supervisor_remains(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            run_id = "missing-root-supervisor-0001"
            run_root = base / ("devlane-" + run_id)
            proc_root = base / "proc-fixture"
            process = proc_root / "4242"
            process.mkdir(parents=True)
            (process / "cmdline").write_bytes(b"python3 kit/devlane/supervisor.py _serve\0")
            deadline_path = base / "deadline.json"
            deadline.create(deadline_path, 120, 60, 180)
            errors = io.StringIO()
            with patch.dict(os.environ, {"GITHUB_RUN_ID": run_id}), \
                    patch.object(host_cleanup, "PROC_ROOT", proc_root), \
                    contextlib.redirect_stderr(errors):
                result = host_cleanup.main([
                    "--root", str(run_root), "--runner-temp", str(base),
                    "--deadline-file", str(deadline_path),
                ])
            self.assertEqual(result, 2)
            self.assertIn("cleanup_receipt=unconfirmed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
