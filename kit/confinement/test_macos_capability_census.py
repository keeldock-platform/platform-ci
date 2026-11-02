import io
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

import macos_capability


TEST_TOOLCHAIN = {
    "python": "/Applications/ToolchainFixture.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9",
    "clang": "/Applications/ToolchainFixture.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
    "linker": "/Applications/ToolchainFixture.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld",
    "sdk": "/Applications/ToolchainFixture.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
    "developer_directory": "/Applications/ToolchainFixture.app/Contents/Developer",
}


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

    def test_an_interrupt_or_system_exit_is_never_converted_or_retried(self):
        for signal_error in (KeyboardInterrupt(), SystemExit(1)):
            with self.subTest(signal=type(signal_error).__name__):
                with self._run_patch(side_effect=signal_error) as command:
                    with patch.object(macos_capability.time, "sleep") as pause:
                        with self.assertRaises(type(signal_error)):
                            macos_capability._probe_uid_processes_present(502)
                command.assert_called_once()
                pause.assert_not_called()

    def test_retries_are_charged_to_the_caller_deadline_and_the_internal_budget(self):
        self.assertGreater(
            macos_capability.CENSUS_READ_BUDGET_SECONDS,
            macos_capability.CENSUS_READ_ATTEMPTS * macos_capability.CENSUS_ATTEMPT_TIMEOUT_SECONDS
            + (macos_capability.CENSUS_READ_ATTEMPTS - 1) * macos_capability.CENSUS_READ_RETRY_SECONDS,
        )
        for label, keywords, budget in (
            ("deadline", {"deadline": time.monotonic() + 1.0}, macos_capability.CENSUS_READ_BUDGET_SECONDS),
            ("budget", {}, 0.0),
        ):
            with self.subTest(label=label):
                with patch.object(macos_capability, "CENSUS_READ_BUDGET_SECONDS", budget):
                    with self._run_patch(side_effect=(_completed(1, b""),) * 3) as command:
                        with patch.object(macos_capability.time, "sleep") as pause:
                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                macos_capability._probe_uid_processes_present(502, **keywords)
                command.assert_called_once()
                pause.assert_not_called()
                self.assertEqual(raised.exception.check, "probe_process_census")
        with patch.object(macos_capability.time, "sleep") as pause:
            with self._run_patch(side_effect=(_completed(1, b""), _completed(0, CLEAN_ROWS))) as command:
                self.assertFalse(macos_capability._probe_uid_processes_present(
                    502, deadline=time.monotonic() + 60.0,
                ))
        self.assertEqual(command.call_count, 2)
        pause.assert_called_once()

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


class ProbeUidCensusTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(macos_capability.time, "sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_census_checks_real_effective_and_saved_uid_fields(self):
        rows = b"10 0 0 0\n11 502 0 0\n12 0 502 0\n13 0 0 502\n"
        with patch.object(
            macos_capability,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, rows, b""),
        ) as command:
            self.assertTrue(macos_capability._probe_uid_processes_present(502))
        command.assert_called_once_with(
            ["/bin/ps", "-A", "-o", "pid=,ruid=,uid=,svuid="],
            env={"LANG": "C", "LC_ALL": "C"},
            timeout=5,
            timeout_check="probe_process_census",
        )

    def test_census_accepts_clean_snapshot_but_only_as_a_snapshot(self):
        with patch.object(
            macos_capability,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, b"1 0 0 0\n2 501 501 501\n", b""),
        ):
            self.assertFalse(macos_capability._probe_uid_processes_present(502))

    def test_census_malformed_or_failed_readback_is_incomplete(self):
        invalid_outputs = (b"", b"1 0 0 0", b"1 0 0 unknown\n", b"1 0 0 0\n1 1 1 1\n1 1 1 1\n")
        results = [subprocess.CompletedProcess([], 0, output, b"") for output in invalid_outputs]
        results.extend((
            subprocess.CompletedProcess([], 1, b"1 0 0 0\n", b""),
            subprocess.CompletedProcess([], 0, b"1 0 0 0\n", b"warning\n"),
        ))
        for result in results:
            with self.subTest(result=result):
                with patch.object(macos_capability, "_run", return_value=result):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._probe_uid_processes_present(502)
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)
        with patch.object(macos_capability, "_run", side_effect=macos_capability.ProbeFailure("native_preflight_unavailable", cleanup_complete=False)):
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                macos_capability._probe_uid_processes_present(502)
        self.assertEqual(raised.exception.check, "probe_process_census")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_control_uid_snapshot_classifies_count_and_group_from_one_process_table(self):
        cases = (
            (b"1 1 S 0 0 0\n", (False, None)),
            (b"1 1 S 0 0 0\n20 10 R 502 502 502\n", (True, "probe_process_survivor_controls_same_group")),
            (b"1 1 S 0 0 0\n20 11 R 502 0 0\n", (True, "probe_process_survivor_controls_other_group")),
            (b"1 1 S 0 0 0\n20 2 Z 0 502 0\n", (True, "probe_process_survivor_controls_zombie")),
            (b"1 1 S 0 0 0\n20 0 Z 0 502 0\n", (True, "probe_process_survivor_controls_zombie")),
            (b"1 1 S 0 0 0\n20 2 R 0 502 0\n21 3 R 502 0 0\n", (True, "probe_process_survivor_controls_multiple")),
            (b"1 1 S 0 0 0\n20 0 R 0 502 0\n21 3 R 502 0 0\n", (True, "probe_process_survivor_controls_multiple")),
            (b"1 1 S 0 0 0\n20 0 R 502 502 502\n", (True, "probe_process_survivor_controls_unattributed")),
        )
        for output, expected in cases:
            with self.subTest(expected=expected):
                with patch.object(
                    macos_capability,
                    "_run",
                    return_value=subprocess.CompletedProcess([], 0, output, b""),
                ) as command:
                    self.assertEqual(
                        macos_capability._probe_uid_process_snapshot(502, launched_pgid=10), expected
                    )
                command.assert_called_once_with(
                    ["/bin/ps", "-A", "-o", "pid=,pgid=,state=,ruid=,uid=,svuid="],
                    env={"LANG": "C", "LC_ALL": "C"},
                    timeout=5,
                    timeout_check="probe_process_census",
                )

    def test_control_uid_snapshot_refuses_malformed_or_ambiguous_rows(self):
        invalid_outputs = (
            b"",
            b"1 1 S 0 0 0",
            b"1 1 Q 0 0 0\n",
            b"1 1 S 0 0 0\n1 1 S 0 0 0\n",
            b"1 1 S 0 0 0\ninvalid\n",
            b"\xff\n",
        )
        for output in invalid_outputs:
            with self.subTest(output_size=len(output)):
                with patch.object(
                    macos_capability,
                    "_run",
                    return_value=subprocess.CompletedProcess([], 0, output, b""),
                ):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._probe_uid_process_snapshot(502, launched_pgid=10)
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)

    def test_control_uid_snapshot_preserves_strict_command_failures(self):
        outputs = (
            subprocess.CompletedProcess([], 1, b"1 1 S 0 0 0\n", b""),
            subprocess.CompletedProcess([], 0, b"1 1 S 0 0 0\n", b"warning\n"),
            subprocess.CompletedProcess([], 0, b"1 1 S 0 0 0\n" + b"0" * (macos_capability.MAX_CAPTURE_BYTES + 1), b""),
        )
        for result in outputs:
            with self.subTest(returncode=result.returncode, stderr=bool(result.stderr)):
                with patch.object(macos_capability, "_run", return_value=result):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._probe_uid_process_snapshot(502, launched_pgid=10)
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)

    def test_noncontrol_survivor_snapshot_can_attach_bounded_classes(self):
        initial = b"20 502 0 0\n"
        recheck = b"20 502 0 0\n"
        with patch.object(
            macos_capability,
            "_run",
            side_effect=(
                subprocess.CompletedProcess([], 0, initial, b""),
                subprocess.CompletedProcess([], 0, recheck, b""),
            ),
        ):
            with patch.object(
                macos_capability,
                "_process_executable",
                return_value=PurePosixPath(TEST_TOOLCHAIN["python"]),
            ):
                result = macos_capability._probe_uid_process_snapshot(
                    502,
                    include_survivor_classes=True,
                    python_executable=TEST_TOOLCHAIN["python"],
                )
        self.assertEqual(result, (True, None, ("python",)))

    def test_survivor_diagnostic_uses_kernel_paths_and_revalidates_the_uid_rows(self):
        initial = b"1 1 S 0 0 0\n20 2 R 0 502 0\n21 3 R 502 0 0\n"
        readback = b"20 0 502 0\n21 502 0 0\n"
        with patch.object(
            macos_capability,
            "_run",
            side_effect=(
                subprocess.CompletedProcess([], 0, initial, b""),
                subprocess.CompletedProcess([], 0, readback, b""),
            ),
        ) as command:
            with patch.object(
                macos_capability,
                "_process_executable",
                side_effect=(PurePosixPath(TEST_TOOLCHAIN["python"]), PurePosixPath("/bin/ps")),
            ) as process_path:
                result = macos_capability._probe_uid_process_snapshot(
                    502,
                    launched_pgid=10,
                    include_survivor_classes=True,
                    python_executable=TEST_TOOLCHAIN["python"],
                )
        self.assertEqual(
            result,
            (True, "probe_process_survivor_controls_multiple", ("python", "ps")),
        )
        self.assertEqual(process_path.call_args_list[0].args, (20,))
        self.assertEqual(process_path.call_args_list[1].args, (21,))
        self.assertEqual(command.call_args_list[1].args[0], ["/bin/ps", "-p", "20,21", "-o", "pid=,ruid=,uid=,svuid="])

    def test_ambiguous_survivor_readback_adds_unknown_without_clearing_refusal(self):
        initial = b"1 1 S 0 0 0\n20 2 R 0 502 0\n21 3 R 502 0 0\n"
        changed = b"20 0 502 0\n"
        with patch.object(
            macos_capability,
            "_run",
            side_effect=(
                subprocess.CompletedProcess([], 0, initial, b""),
                subprocess.CompletedProcess([], 0, changed, b""),
            ),
        ):
            with patch.object(
                macos_capability,
                "_process_executable",
                side_effect=(PurePosixPath(TEST_TOOLCHAIN["python"]), PurePosixPath("/bin/ps")),
            ):
                result = macos_capability._probe_uid_process_snapshot(
                    502,
                    launched_pgid=10,
                    include_survivor_classes=True,
                    python_executable=TEST_TOOLCHAIN["python"],
                )
        self.assertEqual(
            result,
            (True, "probe_process_survivor_controls_multiple", ("unknown",)),
        )

    def test_survivor_path_classes_use_exact_namespaces_and_never_process_text(self):
        cases = (
            (PurePosixPath(TEST_TOOLCHAIN["python"]), "python"),
            (PurePosixPath("/bin/ps"), "ps"),
            (PurePosixPath("/usr/bin/clang"), "developer_shim"),
            (PurePosixPath("/usr/libexec/cfprefsd"), "helper_preferences"),
            (PurePosixPath("/usr/libexec/distnoted"), "helper_notifications"),
            (PurePosixPath("/usr/libexec/lsd"), "helper_launch_services"),
            (
                PurePosixPath("/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsd"),
                "helper_launch_services",
            ),
            (PurePosixPath("/usr/libexec/secd"), "helper_security"),
            (PurePosixPath("/usr/libexec/trustd"), "helper_trust"),
            (PurePosixPath("/usr/libexec/containermanagerd"), "helper_containers"),
            (
                PurePosixPath("/System/Library/PrivateFrameworks/ContainerManager.framework/Support/containermanagerd"),
                "helper_containers",
            ),
            (PurePosixPath("/usr/libexec/example-agent"), "apple_system_path"),
            (PurePosixPath("/opt/example-agent"), "other"),
            (PurePosixPath("/tmp/cfprefsd-copy"), "other"),
            (None, "unknown"),
        )
        for path, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    macos_capability._survivor_path_class(path, TEST_TOOLCHAIN["python"]), expected
                )

    def test_macos_path_classification_uses_posix_semantics_on_every_host(self):
        path = PurePosixPath("/usr/libexec/distnoted")
        self.assertTrue(path.is_absolute())
        self.assertEqual(
            macos_capability._survivor_path_class(path, TEST_TOOLCHAIN["python"]),
            "helper_notifications",
        )
        self.assertTrue(all(isinstance(root, PurePosixPath) for root in macos_capability.APPLE_SYSTEM_PATH_ROOTS))

    def test_survivor_path_readback_is_bounded_and_marks_unread_rows_as_additional(self):
        pids = tuple(range(100, 117))
        readback = "".join(f"{pid} 502 0 0\n" for pid in pids[:macos_capability.MAX_SURVIVOR_PATH_READBACKS])
        with patch.object(
            macos_capability,
            "_process_executable",
            return_value=PurePosixPath("/bin/ps"),
        ) as process_path:
            with patch.object(
                macos_capability,
                "_run",
                return_value=subprocess.CompletedProcess([], 0, readback.encode("ascii"), b""),
            ) as command:
                categories = macos_capability._survivor_process_classes(
                    pids, 502, TEST_TOOLCHAIN["python"], additional=True
                )
        self.assertEqual(categories, ("ps", "additional"))
        self.assertEqual(process_path.call_count, macos_capability.MAX_SURVIVOR_PATH_READBACKS)
        selected = ",".join(str(pid) for pid in pids[:macos_capability.MAX_SURVIVOR_PATH_READBACKS])
        self.assertEqual(command.call_args.args[0][2], selected)


class ProbeTeardownTests(unittest.TestCase):
    def setUp(self):
        self.toolchain_patcher = patch.object(
            macos_capability, "_resolve_trusted_toolchain", return_value=TEST_TOOLCHAIN
        )
        self.toolchain_patcher.start()
        self.addCleanup(self.toolchain_patcher.stop)
        for name, value in (
            ("_resolve_sandbox_exec", macos_capability.SANDBOX_EXEC_PATH),
            ("_write_seatbelt_profile", Path("/tmp/capability.sb")),
            ("_prepare_storage_directory", None),
            ("_verify_storage_directory", None),
        ):
            patcher = patch.object(macos_capability, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def observe_probe(self, *args):
        return macos_capability._observe_probe(
            *args,
            sandbox_exec=macos_capability.SANDBOX_EXEC_PATH,
            profile="/tmp/capability.sb",
            storage_directory="/tmp/storage",
            python_executable=TEST_TOOLCHAIN["python"],
            compiler_executable=TEST_TOOLCHAIN["clang"],
            linker_executable=TEST_TOOLCHAIN["linker"],
            sdk_root=TEST_TOOLCHAIN["sdk"],
            storage_identity=("/tmp/storage", (1, 2, 502, macos_capability.PROBE_PRIMARY_GID, stat.S_IFDIR | 0o700)),
        )

    def test_bootstrap_and_later_mismatched_root_rows_cannot_supply_probe_roles(self):
        class StubProcess:
            pid = 12340
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(macos_capability.PROBE_IDENTITY_VERIFIED)
            returncode = None

            def __init__(self):
                self.poll_calls = 0

            def poll(self):
                self.poll_calls += 1
                return None if self.poll_calls < 4 else 0

            def wait(self, timeout):
                self.returncode = 0
                return 0

        process = StubProcess()
        uid = 502
        bootstrap_rows = {
            process.pid: (1, uid, "/usr/bin/python3"),
            12341: (process.pid, uid, "/bin/ps"),
        }
        signed_probe_rows = {
            process.pid: (1, uid, chr(47) + "private/tmp/CapabilityProbe"),
            12342: (process.pid, uid, "CapabilityChild"),
            12343: (process.pid, uid, "/bin/sh"),
            12344: (process.pid, uid, "/bin/sleep"),
            12345: (process.pid, uid, "capability-child"),
            12346: (process.pid, uid, "capability-child"),
            12347: (process.pid, uid, "/usr/bin/clang"),
        }
        later_mismatch_rows = dict(signed_probe_rows)
        later_mismatch_rows[process.pid] = (1, uid, "/usr/bin/python3")
        later_mismatch_rows[12348] = (process.pid, uid, "/usr/bin/python3")

        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=(bootstrap_rows, signed_probe_rows, later_mismatch_rows),
            ) as table:
                with patch.object(macos_capability, "_descriptor_snapshot", return_value={}) as descriptors:
                    with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                            with patch.object(macos_capability.time, "sleep"):
                                with self.assertRaisesRegex(
                                    macos_capability.ProbeFailure,
                                    "descriptor_readback_unavailable",
                                ):
                                    self.observe_probe(
                                        "/tmp/CapabilityProbe", "/tmp/marker", "/tmp/outside", uid, "/tmp/home"
                                    )

        self.assertEqual(table.call_count, 3)
        descriptors.assert_called_once()
        sampled_pids = descriptors.call_args.args[0]
        self.assertEqual(set(sampled_pids), set(signed_probe_rows))

    def run_observer(self, polls, snapshot, python_name="/x/Python.app/Contents/MacOS/Python", trusted=True):
        uid = 502

        class StubProcess:
            pid = 12340
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(macos_capability.PROBE_IDENTITY_VERIFIED)
            returncode = None
            calls = 0

            def poll(self):
                self.calls += 1
                return None if self.calls <= polls else 0

            def wait(self, timeout):
                self.returncode = 0
                return 0

        process = StubProcess()
        rows = {process.pid: (1, uid, chr(47) + "private/tmp/CapabilityProbe")}
        for pid, name in enumerate(
            ("CapabilityChild", "/bin/sh", "/bin/sleep", "capability-child", "capability-child", "/usr/bin/clang", python_name),
            start=12342,
        ):
            rows[pid] = (process.pid, uid, name)
        with patch.object(macos_capability, "_terminate_probe_tree", return_value=True) as teardown:
            with patch.object(macos_capability.subprocess, "Popen", return_value=process):
                with patch.object(macos_capability, "_process_table", return_value=rows):
                    with patch.object(macos_capability, "_descriptor_snapshot", side_effect=snapshot), patch.object(
                        macos_capability, "_image_is_trusted", return_value=trusted
                    ):
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                            with patch.object(macos_capability.time, "sleep"):
                                self.observe_probe("/tmp/CapabilityProbe", "/tmp/marker", "/tmp/outside", uid, "/tmp/home")
        return teardown

    def test_every_role_observed_on_verified_pids_completes_the_observation(self):
        calls = []

        def snapshot(pids, policy=None, agreed=None):
            calls.append(policy)
            return {pid: {} for pid in pids}

        self.run_observer(7, snapshot)
        self.assertEqual(len(calls), 7)
        policy = calls[0]
        canonical = macos_capability._canonical_path
        self.assertEqual(policy.images, frozenset((canonical(TEST_TOOLCHAIN["clang"]), canonical(TEST_TOOLCHAIN["linker"]))))
        self.assertEqual(policy.storage, canonical("/tmp/storage"))
        self.assertIn(canonical(TEST_TOOLCHAIN["sdk"]), policy.read_roots)

    def test_a_clang_named_process_with_an_untrusted_image_earns_no_clang_role(self):
        with self.assertRaises(macos_capability.ProbeFailure) as raised:
            self.run_observer(4, lambda pids, policy=None, agreed=None: {pid: {} for pid in pids}, trusted=False)
        self.assertEqual(raised.exception.missing_roles, ("clang",))

    def test_unverified_pids_supply_no_roles_and_the_refusal_names_the_missing_ones(self):
        def snapshot(pids, policy=None, agreed=None):
            return {pid: {} for pid in pids if pid not in {12343, 12347}}

        with self.assertRaises(macos_capability.ProbeFailure) as raised:
            self.run_observer(3, snapshot)
        refusal = raised.exception
        self.assertEqual((refusal.reason, refusal.missing_roles, refusal.snapshot_rejections),
                         ("descriptor_readback_unavailable", ("sh", "clang"), "some"))

    def test_a_failed_snapshot_counts_as_a_rejection_and_supplies_no_roles(self):
        def snapshot(pids, policy=None, agreed=None):
            raise macos_capability.ProbeFailure("descriptor_readback_unavailable")

        with self.assertRaises(macos_capability.ProbeFailure) as raised:
            self.run_observer(12, snapshot)
        self.assertEqual(raised.exception.missing_roles, macos_capability.PROBE_ROLE_ORDER)
        self.assertEqual(raised.exception.snapshot_rejections, "many")

    def test_a_channel_verdict_refuses_at_once_even_after_every_role_was_seen(self):
        calls = []

        def snapshot(pids, policy=None, agreed=None):
            calls.append(1)
            if len(calls) > 3:
                raise macos_capability.ProbeFailure("descriptor_channel_unexpected")
            return {pid: {} for pid in pids}

        with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                self.run_observer(12, snapshot)
        self.assertEqual((raised.exception.reason, raised.exception.cleanup_complete), ("descriptor_channel_unexpected", True))
        self.assertEqual(len(calls), 4)

    def test_observe_census_detects_detached_child_after_group_cleanup(self):
        process = type(
            "CompletedProcess",
            (),
            {"pid": 12344, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": 0},
        )()
        process.poll = lambda: process.returncode
        process.wait = lambda timeout: process.returncode
        with patch.object(macos_capability.subprocess, "Popen", return_value=process) as popen:
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(True, ())) as census:
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        self.observe_probe("/tmp/unused", "unused", "unused", 502, "unused")
        self.assertEqual(raised.exception.check, "probe_process_survivor_probe_tree")
        self.assertFalse(raised.exception.cleanup_complete)
        census.assert_called_once_with(
            502, include_survivor_classes=True, python_executable=TEST_TOOLCHAIN["python"]
        )
        command = popen.call_args.args[0]
        self.assertEqual(command[:5], [TEST_TOOLCHAIN["python"], "-I", "-S", "-B", "-c"])
        self.assertNotIn("/usr/bin/sudo", command)
        self.assertEqual(popen.call_args.kwargs["user"], 502)
        self.assertEqual(popen.call_args.kwargs["group"], macos_capability.PROBE_PRIMARY_GID)
        self.assertEqual(popen.call_args.kwargs["extra_groups"], ())
        self.assertEqual(popen.call_args.kwargs["cwd"], "/tmp")

    def test_observe_timeout_is_never_cleanup_complete(self):
        process = type(
            "TimedOutProcess",
            (),
            {"pid": 12343, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": None},
        )()
        process.poll = lambda: None

        def wait(timeout):
            raise subprocess.TimeoutExpired("stub-probe", timeout)

        process.wait = wait
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "MAX_PROBE_SECONDS", 0):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            self.observe_probe("/tmp/unused", "unused", "unused", 502, "unused")
        self.assertEqual(raised.exception.reason, "probe_timeout")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_observe_wait_error_is_never_cleanup_complete(self):
        process = type(
            "WaitErrorProcess",
            (),
            {"pid": 12342, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": None},
        )()
        process.poll = lambda: None

        def wait(timeout):
            raise OSError("private wait detail")

        process.wait = wait
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "MAX_PROBE_SECONDS", 0):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            self.observe_probe("/tmp/unused", "unused", "unused", 502, "unused")
        self.assertEqual(raised.exception.check, "probe_process_observation")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_process_table_error_terminates_and_reaps_injected_probe_group(self):
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": None},
        )()
        process.poll = lambda: process.returncode
        group = {process.pid}

        def terminate_group(process_to_stop):
            self.assertIs(process_to_stop, process)
            group.discard(process_to_stop.pid)
            process_to_stop.returncode = -15
            return not group and process_to_stop.poll() is not None

        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", side_effect=terminate_group) as teardown:
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                            with self.assertRaisesRegex(
                                macos_capability.ProbeFailure,
                                "descriptor_readback_unavailable",
                            ):
                                self.observe_probe(
                                    "/tmp/unused",
                                    "/tmp/unused",
                                    "unused",
                                    501,
                                    "unused",
                                )
        self.assertIsNotNone(process.poll(), "probe root process was not reaped")
        self.assertFalse(group, "probe process group was not terminated")
        teardown.assert_called_once_with(process)

    def test_terminate_probe_tree_escalates_with_injected_group_operations(self):
        class StubProcess:
            pid = 12345

            def __init__(self):
                self.returncode = None
                self.wait_calls = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired("stub-probe", timeout)
                self.returncode = -9
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.os, "killpg", create=True) as killpg:
            with patch.object(macos_capability.signal, "SIGKILL", 9, create=True):
                with patch.object(
                    macos_capability,
                    "_wait_probe_group_gone",
                    side_effect=(False, True),
                ) as group_gone:
                    self.assertTrue(macos_capability._terminate_probe_tree(process))
        self.assertEqual(
            [(call.args[0], call.args[1]) for call in killpg.call_args_list],
            [(process.pid, macos_capability.signal.SIGTERM), (process.pid, 9)],
        )
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(group_gone.call_count, 2)

    def test_process_table_error_runs_teardown_contract_on_every_platform(self):
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "poll": lambda self: None},
        )()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True) as teardown:
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                            with self.assertRaisesRegex(
                                macos_capability.ProbeFailure,
                                "descriptor_readback_unavailable",
                            ):
                                self.observe_probe(
                                    "/tmp/unused",
                                    "unused",
                                    "unused",
                                    501,
                                    "unused",
                                )
        teardown.assert_called_once_with(process)

    def test_unproven_teardown_does_not_close_stream_under_live_capture(self):
        class LockedStream:
            def __init__(self):
                self.closed = False
                self.close_calls = 0

            def close(self):
                self.close_calls += 1
                raise RuntimeError("close blocked behind active capture read")

        stdout = LockedStream()
        stderr = LockedStream()
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": stdout, "stderr": stderr, "poll": lambda self: None},
        )()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                        with patch.object(macos_capability._Capture, "start"):
                            with patch.object(macos_capability._Capture, "join", return_value=False):
                                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                                    with self.assertRaisesRegex(
                                        macos_capability.ProbeFailure,
                                        "native_preflight_unavailable",
                                    ) as raised:
                                        self.observe_probe(
                                            "/tmp/unused",
                                            "/tmp/unused",
                                            "unused",
                                            501,
                                            "unused",
                                        )
        self.assertFalse(raised.exception.cleanup_complete)
        self.assertEqual(raised.exception.check, "probe_process_capture_cleanup")
        self.assertEqual(stdout.close_calls, 0)
        self.assertEqual(stderr.close_calls, 0)

    def test_unproven_teardown_keeps_account_and_scratch_state(self):
        with tempfile.TemporaryDirectory(prefix="macos-probe-cleanup-guard-") as directory:
            root = os.path.join(directory, "workspace")
            marker = os.path.join(root, "kit", "confinement", "macos_capability.swift")
            os.makedirs(os.path.dirname(marker))
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write("// public synthetic probe\n")
            home_parent = os.path.join(directory, "home-parent")
            home = os.path.join(home_parent, "home")
            os.mkdir(home_parent)
            os.mkdir(home)
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = os.path.join(directory, prefix + str(len(scratch_paths)))
                os.mkdir(path)
                scratch_paths.append(path)
                return path

            failure = macos_capability.ProbeFailure("sandbox_behavior_unavailable", cleanup_complete=False)
            with patch.dict(os.environ, {"CI_WORKSPACE": root}):
                with patch.object(macos_capability, "_check_context", return_value=Path(root)):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(macos_capability, "_run_as_probe_user"):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe", side_effect=failure):
                                                    with patch.object(macos_capability, "_run") as run:
                                                        with self.assertRaisesRegex(
                                                            macos_capability.ProbeFailure,
                                                            "sandbox_behavior_unavailable",
                                                        ):
                                                            macos_capability.run_native_probe("a" * 40)
            self.assertTrue(os.path.isdir(home_parent))
            self.assertTrue(os.path.isdir(home))
            self.assertTrue(all(os.path.isdir(path) for path in scratch_paths))
            run.assert_not_called()
            shutil.rmtree(home_parent, ignore_errors=True)
            for path in scratch_paths:
                shutil.rmtree(path, ignore_errors=True)

    def test_probe_process_cleanup_ambiguity_refuses_before_probe_build(self):
        with tempfile.TemporaryDirectory(prefix="macos-probe-command-cleanup-") as directory:
            root = Path(directory) / "workspace"
            marker = root / "kit" / "confinement" / "macos_capability.swift"
            marker.parent.mkdir(parents=True)
            marker.write_text("// public synthetic probe\n", encoding="utf-8")
            home_parent = Path(directory) / "home-parent"
            home = home_parent / "home"
            home_parent.mkdir()
            home.mkdir()
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = Path(directory) / (prefix + str(len(scratch_paths)))
                path.mkdir()
                scratch_paths.append(path)
                return str(path)

            failure = macos_capability.ProbeFailure(
                "native_preflight_unavailable", cleanup_complete=False, check="probe_process_cleanup"
            )
            with patch.dict(os.environ, {"CI_WORKSPACE": str(root)}):
                with patch.object(macos_capability, "_check_context", return_value=root):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(macos_capability, "_run_as_probe_user", side_effect=failure):
                                            with patch.object(macos_capability, "_build_signed_probe") as build:
                                                with patch.object(macos_capability, "_observe_probe") as observe:
                                                    with patch.object(macos_capability, "_run") as command:
                                                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                                            macos_capability.run_native_probe("a" * 40)
            self.assertEqual(raised.exception.check, "probe_process_cleanup")
            self.assertFalse(raised.exception.cleanup_complete)
            build.assert_not_called()
            observe.assert_not_called()
            command.assert_not_called()
            self.assertTrue(home_parent.is_dir())
            self.assertTrue(all(path.is_dir() for path in scratch_paths))
            shutil.rmtree(home_parent, ignore_errors=True)
            for path in scratch_paths:
                shutil.rmtree(path, ignore_errors=True)

    def test_account_deletion_is_refused_when_uid_census_finds_escaped_child(self):
        with tempfile.TemporaryDirectory(prefix="macos-account-census-") as directory:
            root = Path(directory) / "workspace"
            marker = root / "kit" / "confinement" / "macos_capability.swift"
            marker.parent.mkdir(parents=True)
            marker.write_text("// public synthetic probe\n", encoding="utf-8")
            home_parent = Path(directory) / "home-parent"
            home = home_parent / "home"
            home_parent.mkdir()
            home.mkdir()
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = Path(directory) / (prefix + str(len(scratch_paths)))
                path.mkdir()
                scratch_paths.append(path)
                return str(path)

            with patch.dict(os.environ, {"CI_WORKSPACE": str(root)}):
                with patch.object(macos_capability, "_check_context", return_value=root):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(macos_capability, "_run_as_probe_user", return_value=subprocess.CompletedProcess([], 0, b"", b"")):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe"):
                                                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(True, ())) as census:
                                                        with patch.object(macos_capability, "_run") as command:
                                                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                                                macos_capability.run_native_probe("a" * 40)
            self.assertEqual(raised.exception.check, "probe_process_survivor_final_census")
            self.assertFalse(raised.exception.cleanup_complete)
            census.assert_called_once_with(
                502, include_survivor_classes=True, python_executable=TEST_TOOLCHAIN["python"]
            )
            command.assert_not_called()
            self.assertTrue(home_parent.is_dir())
            self.assertTrue(all(path.is_dir() for path in scratch_paths))
            shutil.rmtree(home_parent, ignore_errors=True)
            for path in scratch_paths:
                shutil.rmtree(path, ignore_errors=True)

    def test_final_cleanup_refuses_when_home_removal_errors_and_checks_remaining_paths(self):
        with tempfile.TemporaryDirectory(prefix="macos-final-home-cleanup-") as directory:
            root = Path(directory) / "workspace"
            marker = root / "kit" / "confinement" / "macos_capability.swift"
            marker.parent.mkdir(parents=True)
            marker.write_text("// public synthetic probe\n", encoding="utf-8")
            marker.chmod(0o644)
            home_parent = Path(directory) / "home-parent"
            home = home_parent / "home"
            home_parent.mkdir()
            home.mkdir()
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = Path(directory) / (prefix + str(len(scratch_paths)))
                path.mkdir()
                scratch_paths.append(path)
                return str(path)

            real_rmtree = shutil.rmtree

            def fail_home_remove(path):
                if Path(path) == home_parent:
                    raise PermissionError("home-delete-error")
                real_rmtree(path)

            with patch.dict(os.environ, {"CI_WORKSPACE": str(root)}):
                with patch.object(macos_capability, "_check_context", return_value=root):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(
                                            macos_capability,
                                            "_run_as_probe_user",
                                            return_value=subprocess.CompletedProcess([], 0, b"", b""),
                                        ):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe"):
                                                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                                                        with patch.object(
                                                            macos_capability,
                                                            "_run",
                                                            return_value=subprocess.CompletedProcess([], 0, b"", b""),
                                                        ) as command:
                                                            with patch.object(
                                                                macos_capability.shutil,
                                                                "rmtree",
                                                                side_effect=fail_home_remove,
                                                            ):
                                                                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                                                    macos_capability.run_native_probe("a" * 40)
            self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
            self.assertEqual(raised.exception.check, "probe_identity_cleanup")
            self.assertFalse(raised.exception.cleanup_complete)
            self.assertTrue(home_parent.is_dir())
            self.assertTrue(home.is_dir())
            self.assertTrue(all(not path.exists() for path in scratch_paths))
            command.assert_not_called()
            real_rmtree(home_parent)

    def test_final_cleanup_removes_every_tree_before_deleting_identity(self):
        with tempfile.TemporaryDirectory(prefix="macos-final-cleanup-order-") as directory:
            root = Path(directory) / "workspace"
            marker = root / "kit" / "confinement" / "macos_capability.swift"
            marker.parent.mkdir(parents=True)
            marker.write_text("// public synthetic probe\n", encoding="utf-8")
            marker.chmod(0o644)
            home_parent = Path(directory) / "home-parent"
            home_parent.mkdir()
            (home_parent / "home").mkdir()
            scratch_paths = []
            events = []

            def make_scratch(prefix, dir):
                path = Path(directory) / prefix
                path.mkdir()
                scratch_paths.append(path)
                return str(path)

            def command(argv, **kwargs):
                events.append(("dscl-delete", all(not path.exists() for path in [home_parent, *scratch_paths])))
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            with patch.dict(os.environ, {"CI_WORKSPACE": str(root)}):
                with patch.object(macos_capability, "_check_context", return_value=root):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(
                                macos_capability,
                                "_create_probe_identity",
                                return_value=(502, home_parent, home_parent / "home"),
                            ):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(
                                            macos_capability,
                                            "_run_as_probe_user",
                                            return_value=subprocess.CompletedProcess([], 0, b"", b""),
                                        ):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe"):
                                                    with patch.object(
                                                        macos_capability,
                                                        "_probe_uid_processes_present",
                                                        return_value=(False, ()),
                                                    ) as census:
                                                        with patch.object(macos_capability, "_run", side_effect=command) as run:
                                                            macos_capability.run_native_probe("a" * 40)

            self.assertEqual(events, [("dscl-delete", True)])
            self.assertEqual(run.call_args.args[0], ["/usr/bin/dscl", ".", "-delete", "/Users/" + macos_capability.USERNAME])
            census.assert_called_once_with(
                502, include_survivor_classes=True, python_executable=TEST_TOOLCHAIN["python"]
            )


if __name__ == "__main__":
    unittest.main()
