import subprocess
import unittest
from unittest.mock import patch

import macos_capability


CLEAN_ROWS = b"1 0 0 0\n2 501 501 501\n"
SURVIVOR_ROWS = b"1 0 0 0\n20 502 502 502\n"
CONTROL_CLEAN_ROWS = b"1 1 S 0 0 0\n"


def _completed(returncode, stdout, stderr=b""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def _census_timeout():
    return macos_capability.ProbeFailure(
        "native_preflight_unavailable", cleanup_complete=False, check="probe_process_census"
    )


class CensusRetryTests(unittest.TestCase):
    def _run_patch(self, **kwargs):
        return patch.object(macos_capability, "_run", **kwargs)

    def test_transient_nonzero_exit_then_success_returns_the_clean_verdict(self):
        results = (_completed(1, b""), _completed(0, CLEAN_ROWS))
        with self._run_patch(side_effect=results) as command:
            with patch.object(macos_capability.time, "sleep") as pause:
                self.assertFalse(macos_capability._probe_uid_processes_present(502))
        self.assertEqual(command.call_count, 2)
        pause.assert_called_once_with(macos_capability.CENSUS_READ_RETRY_SECONDS)

    def test_transient_timeout_then_success_returns_the_clean_verdict(self):
        results = (_census_timeout(), _completed(0, CLEAN_ROWS))
        with self._run_patch(side_effect=results) as command:
            with patch.object(macos_capability.time, "sleep"):
                self.assertFalse(macos_capability._probe_uid_processes_present(502))
        self.assertEqual(command.call_count, 2)

    def test_truncated_or_exited_mid_read_rows_then_success_are_reread(self):
        transient = (
            _completed(0, b"1 0 0 0\n2 501 5"),
            _completed(0, b"1 0 0 0\n2 501 501\n"),
            _completed(0, b"1 0 0 0\n1 0 0 0\n"),
            _completed(0, b"1 0 0 0\n", b"ps: warning\n"),
            _completed(0, b""),
        )
        for first in transient:
            with self.subTest(first=first.stdout, stderr=first.stderr):
                with self._run_patch(side_effect=(first, _completed(0, CLEAN_ROWS))) as command:
                    with patch.object(macos_capability.time, "sleep"):
                        self.assertFalse(macos_capability._probe_uid_processes_present(502))
                self.assertEqual(command.call_count, 2)

    def test_two_transient_failures_then_success_stays_within_the_attempt_bound(self):
        results = (_completed(1, b""), _census_timeout(), _completed(0, CLEAN_ROWS))
        self.assertEqual(macos_capability.CENSUS_READ_ATTEMPTS, 3)
        with self._run_patch(side_effect=results) as command:
            with patch.object(macos_capability.time, "sleep") as pause:
                self.assertFalse(macos_capability._probe_uid_processes_present(502))
        self.assertEqual(command.call_count, 3)
        self.assertEqual(pause.call_count, 2)

    def test_control_snapshot_transient_then_success_keeps_its_verdict(self):
        results = (_completed(0, b"1 1 S 0 0"), _completed(0, CONTROL_CLEAN_ROWS))
        with self._run_patch(side_effect=results) as command:
            with patch.object(macos_capability.time, "sleep"):
                result = macos_capability._probe_uid_process_snapshot(502, launched_pgid=10)
        self.assertEqual(result, (False, None))
        self.assertEqual(command.call_count, 2)

    def test_persistent_failure_still_refuses_with_the_same_diagnostic(self):
        failures = (
            _completed(1, b"1 0 0 0\n"),
            _completed(0, b"1 0 0 0"),
            _completed(0, b"1 0 0 0\n", b"warning\n"),
            _census_timeout(),
        )
        for failure in failures:
            with self.subTest(failure=repr(failure)):
                with self._run_patch(side_effect=(failure,) * 3) as command:
                    with patch.object(macos_capability.time, "sleep") as pause:
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            macos_capability._probe_uid_processes_present(502)
                self.assertEqual(command.call_count, macos_capability.CENSUS_READ_ATTEMPTS)
                self.assertEqual(pause.call_count, macos_capability.CENSUS_READ_ATTEMPTS - 1)
                self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)

    def test_persistent_control_snapshot_failure_still_refuses(self):
        with self._run_patch(return_value=_completed(0, b"1 1 Q 0 0 0\n")) as command:
            with patch.object(macos_capability.time, "sleep"):
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    macos_capability._probe_uid_process_snapshot(502, launched_pgid=10)
        self.assertEqual(command.call_count, macos_capability.CENSUS_READ_ATTEMPTS)
        self.assertEqual(raised.exception.check, "probe_process_census")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_real_unexpected_process_refuses_on_the_first_read_without_retry(self):
        with self._run_patch(return_value=_completed(0, SURVIVOR_ROWS)) as command:
            with patch.object(macos_capability.time, "sleep") as pause:
                self.assertTrue(macos_capability._probe_uid_processes_present(502))
        command.assert_called_once()
        pause.assert_not_called()

    def test_oversize_output_and_invalid_arguments_are_never_retried(self):
        oversize = _completed(0, b"1 0 0 0\n" + b"0" * (macos_capability.MAX_CAPTURE_BYTES + 1))
        with self._run_patch(return_value=oversize) as command:
            with patch.object(macos_capability.time, "sleep") as pause:
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    macos_capability._probe_uid_processes_present(502)
        command.assert_called_once()
        pause.assert_not_called()
        self.assertEqual(raised.exception.check, "probe_process_census")
        for uid, pgid in ((0, None), (502, 0)):
            with self.subTest(uid=uid, pgid=pgid):
                with self._run_patch() as command:
                    with self.assertRaises(macos_capability.ProbeFailure):
                        macos_capability._probe_uid_process_snapshot(uid, launched_pgid=pgid)
                command.assert_not_called()

    def test_retry_applies_only_to_census_failures(self):
        other = macos_capability.ProbeFailure("native_preflight_unavailable", check="probe_process_launch")
        with patch.object(macos_capability, "_probe_uid_process_snapshot_attempt", side_effect=other) as attempt:
            with patch.object(macos_capability.time, "sleep") as pause:
                with self.assertRaises(macos_capability.ProbeFailure):
                    macos_capability._probe_uid_process_snapshot(502)
        attempt.assert_called_once()
        pause.assert_not_called()


if __name__ == "__main__":
    unittest.main()
