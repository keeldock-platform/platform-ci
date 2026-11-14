"""Mac-runnable validation for the hosted Windows adapter's fixed inputs."""

import json
import contextlib
import io
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import sandbox_windows as windows


class WindowsSandboxValidationTests(unittest.TestCase):
    def test_only_the_core_node_profile_is_enabled(self):
        self.assertEqual(windows.validate_profile("core-node"), "core-node")
        for profile in ("core-rust", "desktop", "", None):
            with self.subTest(profile=profile), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows.validate_profile(profile)

    def test_appcontainer_names_and_sids_are_closed(self):
        self.assertEqual(windows.validate_profile_name("KDDevLane" + "a" * 32), "KDDevLane" + "a" * 32)
        self.assertEqual(windows.validate_package_sid("S-1-15-2-1-2-3-4-5-6-7"),
                         "S-1-15-2-1-2-3-4-5-6-7")
        for value in ("KDDevLane../../x", "KDDevLane" + "A" * 32, "S-1-15-2-1-2-3-4-5-6-7-8", "S-1-15-2-x"):
            with self.subTest(value=value), self.assertRaises(windows.WindowsBoundaryRefusal):
                (windows.validate_profile_name if value.startswith("KD") else windows.validate_package_sid)(value)

    def test_decrypt_refusals_keep_public_diagnostic_categories(self):
        self.assertEqual(windows._public_decrypt_refusal(windows.WindowsBoundaryRefusal("key-invalid")),
                         "key-format")
        self.assertEqual(windows._public_decrypt_refusal(windows.WindowsBoundaryRefusal("bundle-binding")),
                         "binding-mismatch")
        self.assertEqual(windows._public_decrypt_refusal(windows.bundle.Refusal("authentication-failed")),
                         "auth-tag")
        self.assertEqual(windows._public_decrypt_refusal(windows.fetch.Refusal("projection-invalid")),
                         "binding-mismatch")

    def test_workload_environment_must_be_offline_and_cannot_carry_credentials(self):
        entries = [
            "PATH=C:\\node;C:\\Windows\\System32", "NPM_CONFIG_IGNORE_SCRIPTS=true",
            "NPM_CONFIG_OFFLINE=true", "TEMP=D:\\scratch",
        ]
        self.assertEqual(len(windows.validate_environment(entries)), len(entries))
        for bad in (
            entries + ["DEVLANE_DECRYPT_KEY=" + "a" * 64],
            entries + ["GITHUB_TOKEN=secret"],
            [entry for entry in entries if not entry.startswith("NPM_CONFIG_OFFLINE=")],
            [entry.replace("IGNORE_SCRIPTS=true", "IGNORE_SCRIPTS=false") for entry in entries],
        ):
            with self.subTest(bad=bad), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows.validate_environment(bad)

    def test_prepare_process_snapshot_reduces_image_names_to_fixed_classes(self):
        with mock.patch.object(windows.sys, "platform", "win32"), \
                mock.patch.object(windows.ctypes, "WinDLL", side_effect=OSError, create=True):
            self.assertEqual(windows._windows_process_summary(123), (0, "other"))

    def test_npm_preparation_error_class_uses_bounded_fixed_log_vocabulary(self):
        with tempfile.TemporaryDirectory() as temporary:
            logs = Path(temporary)
            for error_class in sorted(windows.refusal_codes.WINDOWS_PREPARATION_ERROR_CLASSES - {"other"}):
                (logs / "npm-debug.log").write_bytes(
                    ("42 error code " + error_class + "\r\n").encode("ascii")
                )
                with self.subTest(error_class=error_class):
                    self.assertEqual(windows._npm_preparation_error_class(logs), error_class)
            log = logs / "npm-debug.log"
            log.write_bytes(b"12 verbose stack npm error code EACCES\n43 error code ETIMEDOUT\n")
            self.assertEqual(windows._npm_preparation_error_class(logs), "ETIMEDOUT")
            for malformed in (
                b"43 error code ETIMEDOUT extra\r\n",
                b"43 error code etimedout\n",
                b"43 error code \n",
                (b"43 error code E" + b"A" * 256 + b"\r\n"),
                b"unclassified diagnostic\n",
            ):
                with self.subTest(malformed=malformed[:48]):
                    log.write_bytes(malformed)
                    self.assertEqual(windows._npm_preparation_error_class(logs), "other")

    def test_npm_debug_log_classifier_reads_only_the_bounded_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            logs = Path(temporary)
            log = logs / "npm-debug.log"
            log.write_bytes(b"x" * (1024 * 1024 + 256) + b"\n43 error code ENOTFOUND\r\n")
            self.assertEqual(windows._npm_preparation_error_class(logs), "ENOTFOUND")

    def test_profile_commands_map_only_fixed_workspace_and_scratch_paths(self):
        node = r"C:\hostedtoolcache\windows\node\24.22.1\x64\node.exe"
        npm = r"C:\hostedtoolcache\windows\node\24.22.1\x64\node_modules\npm\bin\npm-cli.js"
        source = r"D:\a\_temp\devlane-123\workspace\source"
        scratch = r"D:\a\_temp\devlane-123\scratch"
        executable, arguments = windows.validate_command(
            ["npm", "--prefix", "/workspace/source", "run", "typecheck"],
            node=node, npm_cli=npm, source=source, scratch=scratch, stages=["typecheck"],
        )
        self.assertEqual(executable, node)
        self.assertEqual(arguments, [npm, "--prefix", source, "run", "typecheck"])
        for command in (
            ["npm", "--prefix", "/workspace/source/../other", "run", "typecheck"],
            ["node", "--eval", "require('fs').writeFileSync('/workspace/private', 'x')"],
            ["powershell.exe", "-Command", "exit 0"],
        ):
            with self.subTest(command=command), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows.validate_command(command, node=node, npm_cli=npm, source=source,
                                         scratch=scratch, stages=["unit"])

    def test_profile_command_translation_consumes_embedded_path_suffixes(self):
        node = r"C:\hostedtoolcache\windows\node\24.22.1\x64\node.exe"
        npm = r"C:\hostedtoolcache\windows\node\24.22.1\x64\node_modules\npm\bin\npm-cli.js"
        source = r"D:\a\_temp\devlane-123\workspace\source"
        scratch = r"D:\a\_temp\devlane-123\scratch"
        executable, arguments = windows.validate_command(
            ["npm", "--prefix", "/workspace/source", "run", "unit", "--", "--config=/workspace/source/vitest.config.ts",
             "--outputFile=/scratch/reports/vitest.json"],
            node=node, npm_cli=npm, source=source, scratch=scratch, stages=["unit"],
        )
        self.assertEqual(executable, node)
        self.assertEqual(arguments[-2], "--config=" + str(windows.PureWindowsPath(source) / "vitest.config.ts"))
        self.assertEqual(arguments[-1], "--outputFile=" + str(windows.PureWindowsPath(scratch) / "reports" / "vitest.json"))

    def test_native_launcher_terminates_a_created_process_on_assignment_failure(self):
        source = (Path(windows.__file__).with_name("sandbox_windows_native.cs")).read_text(encoding="utf-8")
        self.assertIn("TerminateProcess(process, JobExitCode)", source)
        self.assertIn("WaitForSingleObject(process, 10000) != WaitObject0", source)
        self.assertIn("JobObjectLimitKillOnJobClose", source)
        self.assertIn("WaitForEmptyJob(job, 10000)", source)
        self.assertIn("System.Threading.Thread.Sleep(50 << attempt)", source)
        self.assertIn("for (int attempt = 0; attempt < 4; attempt++)", source)
        self.assertIn("private static string CleanupReason(int status)", source)
        self.assertLess(source.index("TerminateJobObject(job, JobExitCode);\n                if (!WaitForEmptyJob(job, 10000))"),
                        source.index("return result;", source.index("TerminateJobObject(job, JobExitCode);\n                if (!WaitForEmptyJob(job, 10000)")))
        self.assertLess(source.index("TerminateProcess(process, JobExitCode)"), source.index("Close(process)"))

    def test_profile_cleanup_reason_is_emitted_from_only_the_bounded_native_vocabulary(self):
        result = mock.Mock(returncode=1, stdout=(
            b"windows_cleanup_reason=sharing-violation\nwindows_sandbox=refused code=boundary\n"
        ))
        with mock.patch.object(windows.subprocess, "run", return_value=result), \
                mock.patch("builtins.print") as output:
            with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                windows._run_powershell("delete", "sandbox.json", failure_prefix="windows-prepare")
        self.assertEqual(caught.exception.code, "windows-prepare-powershell-nonzero")
        self.assertEqual(caught.exception.reason, "sharing-violation")
        output.assert_called_once_with("windows_prepare_cleanup_reason=sharing-violation", flush=True)

    def test_prepare_refusal_is_emitted_before_cleanup_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            projection = root / "projection.json"
            projection.write_text("{}", encoding="ascii")
            state = root / "runner" / "state.json"
            output = io.StringIO()

            def fail_cleanup(*_args, **_kwargs):
                print("windows_prepare_cleanup_reason=access-denied", flush=True)
                raise windows.WindowsBoundaryRefusal(
                    "windows-prepare-powershell-nonzero", reason="access-denied",
                )

            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": [],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(Path("node.exe"), Path("npm-cli.js"))), \
                    mock.patch.object(windows, "create_profile"), \
                    mock.patch.object(windows, "_deadline_remaining", return_value=100), \
                    mock.patch.object(windows, "_native_run", return_value={"status": "fail"}), \
                    mock.patch.object(windows, "_npm_preparation_error_class", return_value="ENOTFOUND"), \
                    mock.patch.object(windows, "delete_profile", side_effect=fail_cleanup), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = windows.main([
                    "prepare", "--projection", str(projection), "--output", str(root / "output"),
                    "--deadline", str(root / "deadline"), "--state", str(state),
                ])

        text = output.getvalue()
        first = "devlane_refusal=windows-prepare-npm-failed-ENOTFOUND"
        cleanup = "devlane_refusal=windows-prepare-profile-cleanup-failed"
        self.assertEqual(result, 1)
        self.assertLess(text.index(first), text.index(cleanup))
        self.assertEqual(text.count("devlane_refusal="), 2)
        self.assertIn("windows_prepare_cleanup_reason=access-denied", text)

    def test_large_node_modules_cleanup_uses_a_fixed_number_of_child_processes(self):
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text(encoding="utf-8")
        body = script.split("function Restore-RunnerAccessTree", 1)[1].split(
            "function Clear-AppContainerStorage", 1,
        )[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "node_modules"
            started = time.perf_counter()
            for package in range(200):
                package_root = root / ("package-%03d" % package) / "lib"
                package_root.mkdir(parents=True)
                for entry in range(100):
                    (package_root / ("module-%03d.js" % entry)).touch()
            generation_seconds = time.perf_counter() - started
            item_count = sum(1 for _ in root.rglob("*")) + 1
            self.assertGreaterEqual(item_count, 20000)
            self.assertLessEqual(item_count, 250000)
            self.assertGreater(generation_seconds, 0)

        self.assertEqual(body.count("& $takeown"), 1)
        self.assertEqual(body.count("& $icacls"), 2)
        self.assertIn("while ($pending.Count -gt 0)", body)
        self.assertLess(body.index("while ($pending.Count -gt 0)"), body.index("& $takeown"))
        self.assertIn("'/R'", body)
        self.assertIn("'/T'", body)
        scan = body[:body.index("& $takeown")]
        self.assertNotIn("& $takeown", scan)
        self.assertNotIn("& $icacls", scan)

    def test_shred_failure_prints_a_fixed_failed_cleanup_receipt(self):
        output = io.StringIO()
        errors = io.StringIO()
        with mock.patch.object(windows, "cleanup_runner", side_effect=windows.WindowsBoundaryRefusal(
                "windows-cleanup-shred-overwrite-failed", reason="sharing-violation")), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = windows.main(["shred", "--state", "state.json", "--root", "run-root", "--workspace", "source"])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), (
            "windows_sandbox_cleanup=failed stage=shred\n"
            "cleanup_receipt=failed stage=windows-shred reason=sharing-violation\n"
            "devlane_job=completed public_output=filtered cleanup=failed\n"
        ))
        self.assertEqual(errors.getvalue(), "devlane_refusal=windows-cleanup-shred-overwrite-failed\n")

    def test_cleanup_retry_is_bounded_and_retries_only_sharing_violations(self):
        sharing = OSError("sharing")
        sharing.winerror = 32
        with mock.patch.object(windows.time, "sleep") as sleep:
            operation = mock.Mock(side_effect=[sharing, sharing, "done"])
            self.assertEqual(windows._retry_windows_cleanup(operation), "done")
        self.assertEqual(operation.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.05, 0.1])
        access_denied = PermissionError(13, "denied")
        with mock.patch.object(windows.time, "sleep") as sleep:
            operation = mock.Mock(side_effect=access_denied)
            with self.assertRaises(PermissionError):
                windows._retry_windows_cleanup(operation)
        operation.assert_called_once()
        sleep.assert_not_called()

    def test_cleanup_error_classes_are_fixed_and_shred_reports_the_final_class(self):
        self.assertEqual(windows._windows_cleanup_error_reason(PermissionError(13, "denied")), "access-denied")
        self.assertEqual(windows._windows_cleanup_error_reason(FileNotFoundError(2, "missing")), "not-found")
        self.assertEqual(windows._windows_cleanup_error_reason(OSError(95, "other")), "other")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            file = root / "private.txt"
            file.write_text("private", encoding="ascii")
            sharing = OSError("sharing")
            sharing.winerror = 32
            with mock.patch.object(Path, "open", side_effect=sharing), \
                    mock.patch.object(windows.time, "sleep"), \
                    mock.patch("builtins.print") as output:
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.shred_tree(root)
            self.assertEqual(caught.exception.code, "shred-overwrite-failed")
            self.assertEqual(caught.exception.reason, "sharing-violation")
            output.assert_called_once_with("windows_cleanup_reason=sharing-violation", flush=True)

    def test_shred_tree_removes_oversize_and_reparse_entries_after_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            source = root / "workspace" / "source"
            scratch = root / "scratch"
            source.mkdir(parents=True)
            scratch.mkdir()
            clear = Path(temporary) / "outside-canary"
            clear.write_text("preserve", encoding="ascii")
            (source / "private.txt").write_text("plaintext", encoding="ascii")
            huge = scratch / "hostile.bin"
            with huge.open("wb") as output:
                output.truncate(1024 * 1024 * 1024 + 1)
            (scratch / "outside-link").symlink_to(clear)
            receipt = windows.shred_tree(root, plaintext_root=source, overwrite_limit=1024)
            self.assertIn("reparse=1", receipt)
            self.assertFalse(root.exists())
            self.assertEqual(clear.read_text(encoding="ascii"), "preserve")

    def test_cleanup_attempts_plaintext_wipe_after_firewall_and_profile_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            state = root / "state.json"
            state.write_text("{}", encoding="ascii")
            with mock.patch.object(windows, "remove_firewall", side_effect=windows.WindowsBoundaryRefusal()), \
                    mock.patch.object(windows, "delete_profile", side_effect=windows.WindowsBoundaryRefusal()), \
                    mock.patch.object(windows, "shred_tree", return_value="wiped\n") as wipe, \
                    self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                windows.cleanup_runner(state, root)
            self.assertEqual(caught.exception.code, "windows-cleanup-firewall-failed")
            wipe.assert_called_once_with(root, plaintext_root=None)

    def test_windows_archive_names_reject_aliases_and_path_escapes(self):
        self.assertEqual(windows._windows_archive_name("packages/core/src/index.js"),
                         "packages/core/src/index.js")
        for value in (
            "../outside.txt", "folder/../outside.txt", "CON.txt", "nul", "file:stream", "bad?.js",
            "trailing.", "trailing ", "folder//entry.js",
        ):
            with self.subTest(value=value), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows._windows_archive_name(value)

    def test_predecrypt_probe_uses_fresh_dns_and_both_ip_families(self):
        script = windows.probe_script(
            r"D:\\scratch\\probe.txt", listener_port=54321,
            outside_canary=r"D:\\a\\_temp\\canary", outside_write=r"D:\\a\\_temp\\write",
            other_drive_canary=r"C:\\Windows\\Temp\\canary", other_drive_write=r"C:\\Windows\\Temp\\write",
            pipe_path=r"\\.\pipe\spoolss",
        )
        self.assertIn("attempt('1.1.1.1',443,4)", script)
        self.assertIn("attempt('2606:4700:4700::1111',443,6)", script)
        self.assertIn("attempt('127.0.0.1',54321,4)", script)
        self.assertIn("attempt('127.0.0.1',445,4)", script)
        self.assertIn("pipe\\\\spoolss", script)
        self.assertIn("dns.resolve4('example.com'", script)
        self.assertNotIn("dns.lookup", script)
        self.assertIn("readProbe", script)
        self.assertIn("writeProbe", script)

    def test_dependency_preparation_runs_downloaded_code_in_network_capable_lpac(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            state_dir = root / "state"
            state_dir.mkdir(parents=True)
            state = state_dir / "preparation.json"
            projection = root / "projection.json"
            projection.write_text("{}", encoding="ascii")
            output = root / "prepared-root"
            node = root / "node.exe"
            npm = root / "npm-cli.js"
            node.write_text("", encoding="ascii")
            npm.write_text("", encoding="ascii")
            requests = []

            def isolated(_state, request, _run_root, **_kwargs):
                requests.append(dict(request))
                project = Path(request["working_directory"])
                modules = project / "node_modules"
                modules.mkdir(exist_ok=True)
                (modules / "playwright").mkdir(exist_ok=True)
                (modules / "playwright" / "cli.js").write_text("", encoding="ascii")
                return {"status": "pass", "exit_code": 0, "token": "lpac=verified", "job": "assigned kill_on_close=enabled breakaway=disabled"}

            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": ["chromium"],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                    mock.patch.object(windows, "_deadline_remaining", return_value=600), \
                    mock.patch.object(windows, "create_profile", return_value={}), \
                    mock.patch.object(windows, "delete_profile"), \
                    mock.patch.object(windows, "_native_run", side_effect=isolated), \
                    mock.patch("builtins.print") as stage_output:
                windows.prepare_dependencies(projection, output, root / "deadline.json", state)

            self.assertEqual(len(requests), 2)
            for request in requests:
                self.assertTrue(request["internet_client"])
                self.assertIn(str(output / "project"), request["write_paths"])
                self.assertIn(str(output / "npm-cache"), request["write_paths"])
                self.assertIn(str(output / "prepared" / "ms-playwright"), request["write_paths"])
                self.assertEqual(request["environment"][0].startswith("PATH="), True)
                self.assertIn("NPM_CONFIG_IGNORE_SCRIPTS=true", request["environment"])
                self.assertIn("NPM_CONFIG_OFFLINE=false", request["environment"])
                self.assertIn("NPM_CONFIG_LOGS_DIR=" + str(output / "npm-cache" / "_logs"), request["environment"])
                self.assertIn("NPM_CONFIG_PREFIX=" + str(output / "project"), request["environment"])
                self.assertIn("NPM_CONFIG_YES=true", request["environment"])
                self.assertIn("NPM_CONFIG_PROMPT=false", request["environment"])
                self.assertIn("GIT_TERMINAL_PROMPT=0", request["environment"])
                if request["arguments"][0] == str(npm):
                    self.assertIn("--yes", request["arguments"])
            self.assertTrue((output / "prepared" / "toolchain.json").is_file())
            self.assertEqual(
                [call.args[0] for call in stage_output.call_args_list],
                ["windows_prepare_stage_start=profile-create", "windows_prepare_stage=none",
                 "windows_prepare_stage_start=npm-ci", "windows_prepare_job=empty",
                 "windows_prepare_stage=npm-ci", "windows_prepare_stage_start=playwright",
                 "windows_prepare_job=empty", "windows_prepare_stage=playwright", "windows_prepare_stage=done",
                 "windows_prepare_stage_start=profile-cleanup", "windows_prepare_stage_start=copy"],
            )

    def test_prepare_timeout_emits_the_selected_child_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            state = root / "state" / "sandbox.json"
            state.parent.mkdir(parents=True)
            projection = root / "projection.json"
            projection.write_text("{}", encoding="ascii")
            node = root / "node.exe"
            npm = root / "npm-cli.js"
            node.write_text("", encoding="ascii")
            npm.write_text("", encoding="ascii")
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": [],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                    mock.patch.object(windows, "_deadline_remaining", return_value=7200), \
                    mock.patch.object(windows, "create_profile", return_value={}), \
                    mock.patch.object(windows, "delete_profile"), \
                    mock.patch.object(windows, "_native_run", return_value={
                        "status": "timeout", "exit_code": 0, "token": "", "job": "",
                    }), \
                    mock.patch("builtins.print") as output:
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.prepare_dependencies(projection, root / "prepared", root / "deadline", state)
            self.assertEqual(caught.exception.code, "windows-prepare-npm-child-timeout-3600s")
            output.assert_any_call("windows_prepare_timeout limit=npm-child seconds=3600", flush=True)

    def test_prepare_powershell_monitor_reports_allowlisted_heartbeat_and_timeout(self):
        process = mock.Mock(pid=123, returncode=0)
        process.communicate.side_effect = [
            windows.subprocess.TimeoutExpired("pwsh", 0.01), (b"{\"status\":\"pass\"}", None),
        ]
        with mock.patch.object(windows.subprocess, "Popen", return_value=process), \
                mock.patch.object(windows, "_windows_process_summary", return_value=(2, "node")), \
                mock.patch.object(windows.time, "monotonic", side_effect=(0, 60.1, 60.1, 60.1)), \
                mock.patch("builtins.print") as output:
            result = windows._run_powershell(
                "run", "sandbox.json", timeout=600, failure_prefix="windows-prepare", monitor_stage="npm-ci",
            )
        self.assertEqual(result, '{"status":"pass"}')
        output.assert_called_once_with(
            "windows_prepare_heartbeat stage=npm-ci elapsed=60 children=2 top=node", flush=True,
        )

        hung = mock.Mock(pid=456)
        hung.communicate.return_value = (b"", None)
        with mock.patch.object(windows.subprocess, "Popen", return_value=hung), \
                mock.patch.object(windows.time, "monotonic", side_effect=(0, 1.1)), \
                mock.patch("builtins.print") as output:
            with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                windows._run_powershell(
                    "run", "sandbox.json", timeout=1, failure_prefix="windows-prepare", monitor_stage="npm-ci",
                )
        self.assertEqual(caught.exception.code, "windows-prepare-powershell-timeout")
        output.assert_called_once_with("windows_prepare_timeout limit=powershell seconds=1", flush=True)

    def test_prepare_maps_native_process_start_and_timeout_to_distinct_fixed_codes(self):
        for status, expected in (
            ("process-start-failed", "windows-prepare-npm-process-start-failed"),
            ("timeout", "windows-prepare-npm-work-deadline"),
        ):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "run"
                state = root / "state" / "sandbox.json"
                state.parent.mkdir(parents=True)
                projection = root / "projection.json"
                projection.write_text("{}", encoding="ascii")
                node = root / "node.exe"
                npm = root / "npm-cli.js"
                node.write_text("", encoding="ascii")
                npm.write_text("", encoding="ascii")
                with mock.patch.object(windows.sys, "platform", "win32"), \
                        mock.patch.object(windows.fetch, "validate_projection", return_value={
                            "npm_package": {}, "npm_lock": {}, "playwright": [],
                        }), \
                        mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                        mock.patch.object(windows, "_deadline_remaining", return_value=120), \
                        mock.patch.object(windows, "create_profile", return_value={}), \
                        mock.patch.object(windows, "delete_profile"), \
                        mock.patch.object(windows, "_native_run", return_value={
                            "status": status, "exit_code": 0, "token": "", "job": "",
                        }):
                    with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                        windows.prepare_dependencies(projection, root / "prepared", root / "deadline", state)
                self.assertEqual(caught.exception.code, expected)

    def test_prepare_reports_projection_output_and_profile_creation_sites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            state = root / "state" / "sandbox.json"
            state.parent.mkdir(parents=True)
            projection = root / "projection.json"
            projection.write_text("{}", encoding="ascii")
            node = root / "node.exe"
            npm = root / "npm-cli.js"
            node.write_text("", encoding="ascii")
            npm.write_text("", encoding="ascii")
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", side_effect=windows.fetch.Refusal("invalid")):
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.prepare_dependencies(projection, root / "projection-failed", root / "deadline", state)
            self.assertEqual(caught.exception.code, "windows-prepare-projection-invalid")

            existing = root / "existing-output"
            existing.mkdir()
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": [],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)):
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.prepare_dependencies(projection, existing, root / "deadline", state)
            self.assertEqual(caught.exception.code, "windows-prepare-output-invalid")

            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": [],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                    mock.patch.object(windows, "create_profile", side_effect=windows.WindowsBoundaryRefusal("profile-state")):
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.prepare_dependencies(projection, root / "profile-failed", root / "deadline", state)
            self.assertEqual(caught.exception.code, "windows-prepare-profile-create-failed")

    def test_filtered_summary_carries_diagnostic_test_and_browser_records(self):
        manifest = {
            "allowed_files": {},
            "allowed_tests": {"private test title": "case_0001"},
            "frames": {"private frame title": "frame_0001"},
        }
        summary = windows.filtered_summary(
            manifest, "core-node", [("typecheck", "pass"), ("unit", "fail"), ("browser", "pass")],
            extra_records=[
                {"kind": "diagnostic", "stage": "typecheck", "code": "TS2322", "level": "error"},
                {"kind": "test", "stage": "unit", "test": "case_0001"},
                {"kind": "frame", "frame": "frame_0001", "status": "fail"},
            ], unit_failure_subreason="vitest-failed",
        )
        records = [json.loads(line) for line in summary.splitlines()]
        self.assertIn({"kind": "test", "stage": "unit", "test": "case_0001"}, records)
        self.assertIn({"kind": "frame", "frame": "frame_0001", "status": "fail"}, records)
        self.assertIn({"kind": "diagnostic", "stage": "typecheck", "code": "TS2322", "level": "error"}, records)
        self.assertIn({"kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE"}, records)
        self.assertIn({"kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
                       "subreason": "vitest-failed"}, records)

    def test_missing_adapter_outputs_and_report_directories_are_handled_without_following_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            absent = root / "reports" / "adapter.jsonl"
            windows._remove_adapter_output(absent)
            self.assertFalse(windows._browser_media_outputs_present(root))
            with self.assertRaises(windows.WindowsBoundaryRefusal):
                windows._read_adapter_records(absent)

    def test_adapter_records_must_be_bounded_canonical_json_lines(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "adapter.jsonl"
            report.write_text('{"kind":"frame","frame":"frame_0001","status":"pass"}\n', encoding="ascii")
            self.assertEqual(windows._read_adapter_records(report), [
                {"kind": "frame", "frame": "frame_0001", "status": "pass"},
            ])
            report.write_text('{"kind":"frame"}', encoding="ascii")
            with self.assertRaises(windows.WindowsBoundaryRefusal):
                windows._read_adapter_records(report)


if __name__ == "__main__":
    unittest.main()
