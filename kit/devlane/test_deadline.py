"""Source-free tests for the shared outer deadline and reserved cleanup budget."""

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

import deadline


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
    def test_budget_and_cleanup_reserve_must_fit_outer_job(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            start = time.monotonic()
            with patch.object(deadline.time, "monotonic", return_value=start):
                with self.assertRaisesRegex(deadline.DeadlineRefusal, "deadline-budget-invalid"):
                    deadline.create(path, 9910, 900, 10800, now=start)
                deadline.create(path, 9900, 900, 10800, now=start)
            self.assertEqual(deadline.remaining(path, now=start + 2), 9898)
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


if __name__ == "__main__":
    unittest.main()
