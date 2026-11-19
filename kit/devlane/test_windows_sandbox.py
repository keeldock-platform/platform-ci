"""Mac-runnable validation for the hosted Windows adapter's fixed inputs."""

import json
import contextlib
import ctypes
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sandbox_windows as windows
import test_audit_contracts as audit_fixtures


class WindowsSandboxValidationTests(unittest.TestCase):
    @staticmethod
    def _toolchain_fixture(root):
        root = Path(root)
        node = root / "host-toolcache" / "node.exe"
        npm_cli = root / "host-npm" / "node_modules" / "npm" / "bin" / "npm-cli.js"
        cmd = root / "system" / "cmd.exe"
        node.parent.mkdir(parents=True, exist_ok=True)
        npm_cli.parent.mkdir(parents=True, exist_ok=True)
        cmd.parent.mkdir(parents=True, exist_ok=True)
        node.write_bytes(b"pinned-node-fixture")
        npm_cli.write_bytes(b"pinned-npm-fixture")
        (npm_cli.parent.parent / "package.json").write_bytes(b"{}")
        cmd.write_bytes(b"pinned-cmd-fixture")
        return node, npm_cli, cmd

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

    def test_pinned_toolchain_copy_is_hash_verified_and_stays_under_the_owned_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run-root"
            prepared = run_root / "prepared"
            prepared.mkdir(parents=True)
            node, npm_cli, cmd = self._toolchain_fixture(Path(temporary))
            copied_node, copied_npm_cli, copied_cmd, hashes = windows._copy_pinned_windows_toolchain(
                node, npm_cli, prepared / "toolchain", cmd_path=cmd,
            )
            record_path = prepared / "toolchain.json"
            record = {"node": str(copied_node), "npm_cli": str(copied_npm_cli), "cmd": str(copied_cmd),
                      "hashes": hashes}
            record_path.write_text(json.dumps(record), encoding="ascii")
            self.assertEqual(copied_node.read_bytes(), node.read_bytes())
            self.assertEqual(copied_npm_cli.read_bytes(), npm_cli.read_bytes())
            self.assertEqual(copied_cmd.read_bytes(), cmd.read_bytes())
            self.assertEqual(windows._validate_windows_toolchain(record_path, prepared, run_root), record)
            self.assertTrue(windows._owned_path_within(copied_node, run_root))
            self.assertFalse(windows._owned_path_within(node, run_root))

    def test_execute_requires_the_hashed_owned_toolchain_record(self):
        source = Path(windows.__file__).read_text(encoding="utf-8")
        execute = source.split('elif args.operation == "execute":', 1)[1]
        self.assertIn("_validate_windows_toolchain(", execute)
        self.assertIn('set(toolchain) != {"node", "npm_cli", "cmd", "hashes"}', execute)

    def test_native_launcher_terminates_a_created_process_on_assignment_failure(self):
        source = (Path(windows.__file__).with_name("sandbox_windows_native.cs")).read_text(encoding="utf-8")
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text(encoding="utf-8")
        self.assertIn("Write-LauncherPhase 'types-load'", script)
        self.assertIn("Write-LauncherPhase 'acl-grant'", script)
        for phase in (
            "appcontainer-sid", "token-create", "job-create", "process-create-suspended",
            "job-assign", "resume", "wait", "exit",
        ):
            with self.subTest(phase=phase):
                self.assertIn('Phase("' + phase + '")', source)
        self.assertIn("TerminateProcess(process, JobExitCode)", source)
        self.assertIn("WaitForSingleObject(process, 10000) != WaitObject0", source)
        self.assertRegex(
            source,
            r'\[DllImport\("kernel32\.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet\.Unicode,\s*'
            r'ExactSpelling = true, SetLastError = true\)\]\s*private static extern IntPtr CreateJobObjectW',
        )
        self.assertIn("RunNamedCleanupJobLifecycleFixture(string profileName, string packageSid)", source)
        self.assertIn("JobObjectLimitKillOnJobClose", source)
        self.assertIn("WaitForEmptyJob(job, 10000)", source)
        self.assertIn("System.Threading.Thread.Sleep(50 << attempt)", source)
        self.assertIn("for (int attempt = 0; attempt < 4; attempt++)", source)
        self.assertIn("private static string CleanupReason(int status)", source)
        terminate = source.index("TerminateAndConfirmEmptyJob(job);")
        self.assertIn("private static void TerminateAndConfirmEmptyJob(IntPtr job)", source)
        self.assertLess(terminate, source.index("return result;", terminate))
        terminate_process = source.index("TerminateProcess(process, JobExitCode)")
        self.assertLess(terminate_process, source.index("Close(process)", terminate_process))
        self.assertIn("TokenPrivilegesInformation = 3", source)
        self.assertIn('HasEnabledPrivilege(token, "SeChangeNotifyPrivilege")', source)
        self.assertIn("LookupPrivilegeValueW(null, privilegeName, out expected)", source)
        verify = source.split("private static string VerifyToken", 1)[1].split(
            "private static IntPtr QueryToken", 1,
        )[0]
        self.assertLess(verify.index("HasEnabledPrivilege"), verify.index("bypass_traverse="))
        self.assertLess(source.index("VerifyToken(process, sid, internetClient"), source.index("ResumeThread(thread)"))
        refusal = source.index('result.Failure = "token-bypass-traverse-absent"')
        self.assertLess(source.index("TerminateAndConfirmEmptyJob(job);", source.index("bool bypassTraverse")), refusal)
        self.assertLess(refusal, source.index("ResumeThread(thread)"))

    def test_prepare_reports_and_refuses_missing_bypass_traverse_privilege(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            state = root / "state" / "preparation.json"
            state.parent.mkdir(parents=True)
            projection = root / "projection.json"
            projection.write_text("{}", encoding="ascii")
            node, npm, cmd = self._toolchain_fixture(root)
            output = io.StringIO()
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": [],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                    mock.patch.object(windows, "_system_cmd_path", return_value=cmd), \
                    mock.patch.object(windows, "_deadline_remaining", return_value=120), \
                    mock.patch.object(windows, "create_profile", return_value={}), \
                    mock.patch.object(windows, "delete_profile"), \
                    mock.patch.object(windows, "_native_run", return_value={
                        "status": "token-bypass-traverse-absent", "exit_code": 0,
                        "token": "lpac=verified bypass_traverse=absent",
                        "job": "assigned kill_on_close=enabled breakaway=disabled terminated=confirmed empty=confirmed",
                    }), \
                    contextlib.redirect_stdout(output):
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.prepare_dependencies(projection, root / "prepared", root / "deadline", state)
            self.assertEqual(caught.exception.code, "windows-prepare-token-bypass-traverse-absent")
            self.assertEqual(windows._token_bypass_traverse_status("lpac=verified bypass_traverse=absent"), "absent")
            self.assertEqual(windows._token_bypass_traverse_status("lpac=verified bypass_traverse=present"), "present")
            self.assertIsNone(windows._token_bypass_traverse_status("lpac=verified"))
            self.assertIn("windows_token_bypass_traverse=absent\n", output.getvalue())
            self.assertIn(caught.exception.code, windows.refusal_codes.WINDOWS_PREPARE_REFUSAL_CODES)

    def test_boundary_failure_probe_is_closed_and_does_not_print_exception_text(self):
        diagnostic = b"windows_boundary_failure operation=state-save code=argument-types win32=other\n"
        self.assertTrue(windows._boundary_failure_line(diagnostic))
        self.assertTrue(windows._boundary_failure_line(
            b"windows_boundary_failure operation=icacls code=icacls-exit-5 win32=other\n"))
        for bad in (diagnostic.replace(b"state-save", b"private-path"),
                    diagnostic.replace(b"argument-types", b"private-message"),
                    diagnostic.replace(b"other", b"12345"), diagnostic + b"private content"):
            self.assertFalse(windows._boundary_failure_line(bad))
        process = mock.Mock(returncode=1)
        process.stdout = io.BytesIO(diagnostic + b"windows_sandbox=refused code=boundary\n")
        with mock.patch.object(windows.subprocess, "Popen", return_value=process), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(windows.WindowsBoundaryRefusal):
                windows._run_powershell("run", "sandbox.json", failure_prefix="windows-prepare")
        self.assertEqual(output.getvalue(), diagnostic.decode())

    def test_failed_prepare_cleanup_uses_only_the_validated_surviving_preparation_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = root / "state" / "sandbox.json"
            state.parent.mkdir()
            preparation = state.with_name("preparation.json")
            preparation.write_text(json.dumps({"schema": 1, "owned_roots": [str(root)],
                "acl_grants": [], "integrity_grants": [], "job_state": "none"}))
            with mock.patch.object(windows, "quiesce_run") as quiesce, \
                    mock.patch.object(windows, "delete_profile") as delete, \
                    mock.patch.object(windows, "shred_tree", return_value="shred-fixture\n") as shred:
                result = windows.cleanup_runner(state, root)
            quiesce.assert_called_once_with(preparation)
            delete.assert_called_once_with(preparation)
            shred.assert_called_once()
            self.assertIn("profile=deleted", result)
            state.write_text("{}")
            with mock.patch.object(windows, "quiesce_run") as quiesce:
                with self.assertRaises(windows.WindowsBoundaryRefusal):
                    windows.cleanup_runner(state, root)
            quiesce.assert_not_called()
            state.unlink()
            preparation.write_text(json.dumps({"schema": 1, "owned_roots": [str(root)],
                "acl_grants": [{"path": str(root.parent / "outside")}], "integrity_grants": [],
                "job_state": "none"}))
            with mock.patch.object(windows, "quiesce_run") as quiesce, \
                    mock.patch.object(windows, "shred_tree") as shred:
                with self.assertRaises(windows.WindowsBoundaryRefusal):
                    windows.cleanup_runner(state, root)
            quiesce.assert_not_called()
            shred.assert_not_called()
            preparation.unlink()
            preparation.symlink_to(root / "outside.json")
            with self.assertRaises(windows.WindowsBoundaryRefusal):
                windows.cleanup_runner(state, root)

    def test_launcher_journal_uses_explicit_arrays_before_any_acl_write(self):
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text()
        journal = script.split("function Save-State {", 1)[1].split("function Add-TrackedIntegrityGrant", 1)[0]
        self.assertIn("$state.acl_grants = $grants.ToArray()", journal)
        self.assertIn("$state.integrity_grants = $integrityGrants.ToArray()", journal)
        self.assertNotIn("@($grants)", script)
        tracked = script.split("function Add-TrackedGrant", 1)[1].split("function Save-State", 1)[0]
        self.assertLess(tracked.index("$grants.Add("), tracked.index("Save-State"))
        self.assertLess(tracked.index("Save-State"), tracked.index("Set-Acl"))
        self.assertIn("Write-BoundaryFailure $_", script)

    @unittest.skipUnless(sys.platform == "win32", "Windows PowerShell runtime fixture")
    def test_actual_state_serializer_roundtrips_empty_and_nonempty_grant_journals(self):
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text()
        function = "function Save-State {" + script.split("function Save-State {", 1)[1].split(
            "        function Add-TrackedIntegrityGrant", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            source = (
                "$ErrorActionPreference='Stop'; $statePath=" + "'" + str(state_path).replace("'", "''") + "';\n"
                "$script:BoundaryOperation='acl-rule'; $script:OwnedRoots=@('C:\\fixture');\n"
                "$state=[pscustomobject]@{owned_roots=@();acl_grants=@();integrity_grants=@()};\n"
                "$grants=[Collections.Generic.List[object]]::new();\n"
                "$integrityGrants=[Collections.Generic.List[string]]::new();\n" + function + "\n"
                "for ($i=0; $i -lt 3; $i++) { Save-State; "
                "$saved=Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json; "
                "if ($null -eq $saved.acl_grants -or $saved.acl_grants.Count -ne $i) { throw }; "
                "$grants.Add([pscustomobject]@{path='C:\\fixture';rights='Modify';inheritance=3}) }; 'journal=pass'"
            )
            result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", source],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout.strip(), b"journal=pass")

    def test_profile_cleanup_reason_is_emitted_from_only_the_bounded_native_vocabulary(self):
        process = mock.Mock(returncode=1)
        process.stdout = io.BytesIO(
            b"windows_launcher_phase=acl-grant\r\nwindows_cleanup_reason=sharing-violation\n"
            b"windows_sandbox=refused code=boundary\n"
        )
        with mock.patch.object(windows.subprocess, "Popen", return_value=process), \
                contextlib.redirect_stdout(io.StringIO()) as streamed:
            with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                windows._run_powershell("delete", "sandbox.json", failure_prefix="windows-prepare")
        self.assertEqual(caught.exception.code, "windows-prepare-powershell-nonzero")
        self.assertEqual(caught.exception.reason, "sharing-violation")
        self.assertEqual(streamed.getvalue(), (
            "windows_launcher_phase=acl-grant\r\nwindows_prepare_cleanup_reason=sharing-violation\n"
        ))

    def test_prepare_refusal_is_emitted_before_cleanup_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            projection = root / "projection.json"
            projection.write_text("{}", encoding="ascii")
            state = root / "runner" / "state.json"
            node, npm, cmd = self._toolchain_fixture(root)
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
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                    mock.patch.object(windows, "_system_cmd_path", return_value=cmd), \
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

    def test_acl_grant_cleanup_removes_only_tracked_rules_without_recursive_runner_repair(self):
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text(encoding="utf-8")
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs").read_text(encoding="utf-8")
        run = script.split("if ($Mode -eq 'run')", 1)[1].split("if ($Mode -eq 'delete')", 1)[0]
        cleanup = script.split("if ($Mode -eq 'delete')", 1)[1].split("\n    throw\n} catch {", 1)[0]
        tracked_grant = run.split("function Add-TrackedGrant", 1)[1].split("function Save-State", 1)[0]
        tracked_integrity = run.split("function Add-TrackedIntegrityGrant", 1)[1].split(
            "Write-LauncherPhase 'acl-grant'", 1,
        )[0]
        storage_access = script.split("function Set-CleanupStorageAccess", 1)[1].split("try {", 1)[0]
        self.assertIn("Write-LauncherPhase 'acl-grant'", run)
        self.assertIn("$script:OwnedRoots = @($baseInfo.Path)", run)
        self.assertIn("$state.owned_roots = @($script:OwnedRoots)", run)
        self.assertIn("if ($item.PSIsContainer) { 3 } else { 0 }", run)
        self.assertIn("$grants.Add([pscustomobject]@{ path = $path; rights = $rightsName; inheritance = $inheritanceValue })", run)
        self.assertIn("$integrityGrants = [Collections.Generic.List[string]]::new()", run)
        self.assertIn("Add-TrackedIntegrityGrant $path", run)
        self.assertIn("foreach ($path in @($state.integrity_grants))", cleanup)
        self.assertIn("Invoke-CleanupIcacls $pathInfo.Path @('/remove:g'", cleanup)
        self.assertIn("Invoke-CleanupIcacls $pathInfo.Path @('/setintegritylevel', '(OI)(CI)M')", cleanup)
        self.assertIn("function Clear-AppContainerStorage", cleanup)
        self.assertIn("Set-CleanupStorageAccess $entry.Path", cleanup)
        self.assertIn("[IO.Directory]::Delete($entry.Path, $false)", cleanup)
        self.assertIn("[IO.File]::SetAttributes($entry.Path, $writableAttributes)", cleanup)
        self.assertIn("Boundary]::AssertCleanupQuiescent(", cleanup)
        self.assertLess(cleanup.index("AssertCleanupQuiescent"), cleanup.index("Remove-NetFirewallRule"))
        self.assertEqual(cleanup.count("AssertCleanupQuiescent"), 1)
        self.assertLess(cleanup.index("AssertCleanupQuiescent"), cleanup.index("Clear-AppContainerStorage"))
        self.assertNotIn("Remove-Item -LiteralPath $statePath", cleanup)
        self.assertIn("if ($Mode -eq 'quiesce')", script)
        self.assertIn("$state.job_state = 'pending'", run)
        self.assertIn("$state.job_state = 'terminated-empty'", run)
        self.assertIn("empty=confirmed", run)
        self.assertNotIn("Set-Acl", cleanup)
        self.assertNotIn("takeown", cleanup.lower())
        self.assertNotRegex(cleanup, r"(?i)'/T'|\"/T\"|Remove-Item.*-Recurse")
        self.assertNotIn("$modifiedPaths", cleanup)
        self.assertNotIn("Restore-RunnerAccessTree", cleanup)
        self.assertIn("Assert-CleanupTreeSafe $pathInfo.Path", cleanup)
        self.assertLess(tracked_grant.index("Assert-OwnedPath"), tracked_grant.index("Set-Acl"))
        self.assertLess(tracked_integrity.index("Assert-OwnedPath"), tracked_integrity.index("Invoke-CleanupIcacls"))
        self.assertLess(cleanup.index("Assert-CleanupTreeSafe $pathInfo.Path"),
                        cleanup.index("Invoke-CleanupIcacls $pathInfo.Path @('/remove:g'"))
        self.assertNotIn("(OI)(CI)", storage_access)
        self.assertIn("Add-CleanupBudgetEntry", script)
        self.assertIn("if ($name -eq '.' -or $name -eq '..') { continue }", script)
        self.assertIn("& $icacls $Path @Arguments '/L' '/Q'", script)
        self.assertNotRegex(cleanup, r"(?i)'/T'|\"/T\"")
        self.assertNotRegex(script, r"(?i)'/T'|\"/T\"")
        self.assertNotIn("SetSecurityInfo", native)
        self.assertNotIn("GetFileInformationByHandleEx", native)
        self.assertNotIn("DeleteHandleEntry", native)
        self.assertIn("UnprotectedDaclSecurityInformation = 0x20000000", native)
        self.assertIn("FileFlagOpenReparsePoint = 0x00200000", native)
        self.assertIn("FileFlagBackupSemantics = 0x02000000", native)
        self.assertIn("FileShareRead | FileShareWrite", native)
        self.assertIn("AssertCleanupEntry(", native)
        self.assertIn("GetFileInformationByHandle(handle, out information)", native)
        self.assertIn("FileAttributeReparsePoint) != 0", native)
        self.assertIn("if (!requireDirectory && information.NumberOfLinks != 1)", native)
        self.assertIn("$script:WindowsCleanupEntries -ge 250000", script)
        self.assertIn("$PendingCount -ge 250000", script)
        self.assertIn("$script:WindowsCleanupTimer.ElapsedMilliseconds -gt 300000", script)
        self.assertIn("[void](Clear-AppContainerStorage", cleanup)
        python_source = Path(windows.__file__).read_text(encoding="utf-8")
        self.assertIn("timeout=WINDOWS_PROFILE_CLEANUP_TIMEOUT_SECONDS", python_source)

    def test_acl_mutations_are_confined_to_recorded_owned_roots(self):
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text(encoding="utf-8")
        run = script.split("if ($Mode -eq 'run')", 1)[1].split("if ($Mode -eq 'delete')", 1)[0]
        cleanup = script.split("if ($Mode -eq 'delete')", 1)[1].split("\n    throw\n} catch {", 1)[0]
        icacls_writer = script.split("function Invoke-CleanupIcacls", 1)[1].split(
            "function Set-CleanupStorageAccess", 1,
        )[0]
        self.assertNotIn("Add-TrackedTraverseGrant", script)
        self.assertNotIn(":(X,S)", script)
        self.assertNotIn("$ancestor", run)
        self.assertNotIn("[IO.DirectoryInfo]", run)
        self.assertIn("function Assert-OwnedPath", script)
        self.assertIn("$Path = Assert-OwnedPath $Path", icacls_writer)
        self.assertIn("$path = Assert-OwnedPath $path", run)
        self.assertIn("$script:OwnedRoots = @($state.owned_roots", cleanup)
        self.assertIn("$state.owned_roots = @($script:OwnedRoots)", cleanup)
        self.assertIn("$actual, $expected", cleanup)
        self.assertIn("Set-CleanupStorageAccess $entry.Path", cleanup)
        self.assertIn("Assert-OwnedPath $Path", script.split("function Set-CleanupStorageAccess", 1)[1].split("try {", 1)[0])
        self.assertIn("'/L'", icacls_writer)
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/devlane-encrypted.yml").read_text(
            encoding="utf-8",
        )
        workflow_acl = workflow.split("function Protect-PrivateDirectory", 1)[1].split(
            "try {\n            $runRoot", 1,
        )[0]
        acl_call_sites = re.findall(r"Protect-PrivateDirectory\s+(\$[A-Za-z][A-Za-z0-9]*)", workflow)
        self.assertEqual(acl_call_sites, ["$runRoot", "$cryptoTarget"])
        self.assertIn("New-Item -ItemType Directory -Path $runRoot", workflow)
        self.assertIn("Join-Path -Path $runRoot -ChildPath 'control-python-deps'", workflow)
        self.assertIn("SetAccessControl([IO.DirectoryInfo]$Path, $security)", workflow_acl)
        self.assertNotRegex(workflow, r"(?i)icacls|Set-Acl|SetSecurityDescriptor")
        with tempfile.TemporaryDirectory() as temporary:
            owned = Path(temporary) / "run-root"
            child = owned / "toolchain" / "node.exe"
            child.parent.mkdir(parents=True)
            outsider = owned.parent / "hostedtoolcache" / "node.exe"
            self.assertTrue(windows._owned_path_within(child, owned))
            self.assertFalse(windows._owned_path_within(owned.parent, owned))
            self.assertFalse(windows._owned_path_within(outsider, owned))
        python_source = Path(windows.__file__).read_text(encoding="utf-8")
        self.assertIn("if not any(_owned_path_within(value, owned_root) for owned_root in owned_roots)", python_source)
        self.assertIn("not _path_within(value, owned_root)", python_source)

    def test_cleanup_discovery_budget_refuses_a_generated_wide_directory(self):
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text(encoding="utf-8")
        budget = script.split("function Start-CleanupBudget", 1)[1].split("function Get-CleanupPathInfo", 1)[0]
        preflight = script.split("function Assert-CleanupTreeSafe", 1)[1].split(
            "function Invoke-CleanupIcacls", 1,
        )[0]
        cleanup = script.split("if ($Mode -eq 'delete') {", 1)[1].split("\n    throw\n} catch {", 1)[0]
        storage = cleanup.split("function Clear-AppContainerStorage", 1)[1].split(
            "Write-LauncherPhase 'acl-grant'", 1,
        )[0]
        self.assertIn("$PendingCount -ge 250000", budget)
        self.assertIn("$script:WindowsCleanupEntries -ge 250000", budget)
        self.assertIn("$script:cleanupReason = 'other'", budget)
        self.assertIn("Assert-CleanupBudgetTime", budget)
        for walker in (preflight, storage):
            self.assertLess(walker.index("Add-CleanupBudgetEntry $pending.Count"), walker.index("$pending.Push($child)"))
            self.assertIn("Assert-CleanupBudgetTime", walker)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "wide"
            fixture.mkdir()
            for index in range(70):
                (fixture / ("entry-" + str(index))).touch()
            def discover_with_contract(entry_limit, pending_limit):
                entries = 0
                pending = []

                class BudgetRefusal(Exception):
                    def __init__(self):
                        self.reason = "other"
                        self.entries = entries
                        self.pending = len(pending)

                def charge():
                    nonlocal entries
                    if entries >= entry_limit or len(pending) >= pending_limit:
                        raise BudgetRefusal()
                    entries += 1

                try:
                    charge()
                    pending.append(fixture)
                    while pending:
                        current = pending.pop()
                        if current.is_dir():
                            with os.scandir(current) as children:
                                for child in children:
                                    charge()
                                    pending.append(Path(child.path))
                except BudgetRefusal as refusal:
                    return refusal.reason, refusal.entries, refusal.pending
                return "accepted", entries, len(pending)

            self.assertEqual(discover_with_contract(64, 64), ("other", 64, 63))
            self.assertEqual(discover_with_contract(128, 4), ("other", 5, 4))

    def test_cleanup_refuses_an_unreaped_job_or_live_appcontainer_process(self):
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text(encoding="utf-8")
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs").read_text(encoding="utf-8")
        delete = script.split("if ($Mode -eq 'delete') {", 1)[1].split("\n    throw\n} catch {", 1)[0]
        check = native.split("public static void AssertCleanupQuiescent", 1)[1].split(
            "private static bool IsProcessGone", 1,
        )[0]
        self.assertIn('jobState != "none" && jobState != "pending" && jobState != "terminated-empty"', check)
        self.assertIn("TerminateCleanupJob(profileName)", check)
        self.assertIn("VerifyCleanupJobEmpty(profileName)", check)
        self.assertIn("Process.GetProcesses()", check)
        self.assertGreaterEqual(check.count("totalTimer.ElapsedMilliseconds > CleanupDeadlineMilliseconds"), 3)
        self.assertIn("item.SessionId", check)
        self.assertIn("GetProcessInformation(process, ProcessProtectionLevelInfo", check)
        self.assertIn("ClassifyCleanupProcessFixture", check)
        self.assertIn("OpenProcessToken(process, TokenQuery, out token)", check)
        self.assertIn("EqualSid(Marshal.ReadIntPtr(app), expectedSid)", check)
        self.assertIn('throw new InvalidOperationException("cleanup_process_alive")', check)
        self.assertIn("TerminateAndReapCleanupProcess(process)", check)
        self.assertIn('throw new InvalidOperationException("cleanup_process_terminate")', native)
        self.assertIn('throw new InvalidOperationException("cleanup_process_reap")', native)
        self.assertLess(delete.index("AssertCleanupQuiescent"), delete.index("Remove-NetFirewallRule"))
        self.assertIn("WaitForEmptyJob(job, 10000)", native)
        self.assertIn("WaitForEmptyJob(job, 0, 10)", native)
        wait_empty = native.split("private static bool WaitForEmptyJob", 1)[1].split(
            "private static uint WaitForProcess", 1,
        )[0]
        self.assertIn("if (!firstQuery && timer.ElapsedMilliseconds > timeoutMilliseconds) return false;", wait_empty)
        self.assertIn("if (Marshal.ReadInt32(buffer, 4) == 0) return true;", wait_empty)
        self.assertIn('result.Job += " terminated=confirmed empty=confirmed"', native)
        self.assertIn('"Local\\\\KeelDock.DevLane."', native)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "sandbox.json"
            state.write_text(json.dumps({
                "schema": 1, "profile_name": "KDDevLane" + "a" * 32,
                "package_sid": "S-1-15-2-1-2-3-4-5-6-7", "firewall_rule": "KD-DevLane-123",
                "owned_roots": [], "acl_grants": [], "integrity_grants": [], "job_state": "pending",
            }), encoding="ascii")
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows, "_run_powershell",
                                      return_value="windows_processes=terminated verified=empty") as powershell:
                self.assertEqual(windows.quiesce_run(state),
                                 "windows_processes=terminated verified=empty\n")
                powershell.assert_called_once()
                self.assertEqual(powershell.call_args.args[0], "quiesce")

    def test_waited_process_handles_request_synchronize_and_separate_wait_failure_from_timeout(self):
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs").read_text(encoding="utf-8")
        check = native.split("public static void AssertCleanupQuiescent", 1)[1].split(
            "private static bool IsProcessGone", 1,
        )[0]
        process_open = native.split("private static IntPtr OpenCleanupProcessHandle", 1)[1].split(
            "public static string RunCleanupProcessHandleFixture", 1,
        )[0]
        wait = native.split("private static uint WaitForProcess", 1)[1].split(
            "private static string VerifyToken", 1,
        )[0]
        self.assertIn("private const uint ProcessSynchronize = 0x00100000", native)
        self.assertIn("OpenCleanupProcessHandle(processId, verificationPass)", check)
        self.assertRegex(
            process_open,
            r"uint access = ProcessQueryLimitedInformation\s*\| ProcessSynchronize\s*"
            r"\| \(verificationPass \? 0U : ProcessTerminate\)",
        )
        self.assertIn("RunCleanupProcessHandleFixture()", native)
        self.assertIn("OpenCleanupProcessHandle(child.ProcessId, false)", native)
        self.assertIn("RequireCleanupProcessReaped(child.Process, 0)", native)
        self.assertIn("WaitForProcess(IntPtr.Zero, 0)", native)
        self.assertIn("OpenCleanupProcessHandle(4, false)", native)
        self.assertIn("private const uint WaitFailed = UInt32.MaxValue", native)
        self.assertIn('throw new InvalidOperationException("cleanup_process_wait_failed")', wait)
        self.assertIn("result != WaitObject0 && result != WaitTimeout", wait)
        self.assertIn("RequireCleanupProcessReaped(process, 10000)", native)
        self.assertIn('throw new InvalidOperationException("cleanup_process_reap")', native)

    @unittest.skipUnless(sys.platform == "win32", "requires native Windows process and job APIs")
    def test_native_named_job_is_reopened_terminated_and_reaped(self):
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs")
        profile_name = "KDDevLane" + "e" * 32
        package_sid = "S-1-15-2-1-2-3-4-5-6-7"
        command = (
            "$ErrorActionPreference='Stop'; "
            "Add-Type -Path $env:DEVLANE_NATIVE_CS; "
            "$process = [KeelDock.Platform.DevLaneWindows.Boundary]::RunCleanupProcessHandleFixture(); "
            "if ($process -notmatch 'wait-failed=refused inaccessible=refused unreaped=refused terminated=reaped') { throw 'native-process-lifecycle-incomplete' }; "
            "$process; "
            "[KeelDock.Platform.DevLaneWindows.Boundary]::RunNamedCleanupJobLifecycleFixture("
            "$env:DEVLANE_FIXTURE_NAME, $env:DEVLANE_FIXTURE_SID)"
        )
        environment = os.environ.copy()
        environment.update({
            "DEVLANE_NATIVE_CS": str(native),
            "DEVLANE_FIXTURE_NAME": profile_name,
            "DEVLANE_FIXTURE_SID": package_sid,
        })
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=45, check=False, env=environment,
        )
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode("utf-8", "replace"))
        self.assertIn(b"windows_native_process_wait=synchronize timeout-distinguished wait-failed=refused "
                      b"inaccessible=refused unreaped=refused terminated=reaped", result.stdout)
        self.assertIn(b"windows_native_job_lifecycle=created empty-first-query-delayed pending reopened terminated reaped",
                      result.stdout)

    @unittest.skipUnless(sys.platform == "win32", "requires native Windows process and job APIs")
    def test_native_quiescence_refusal_preserves_state_and_prevents_shredding(self):
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs")
        command = (
            "$ErrorActionPreference='Stop'; "
            "Add-Type -Path $env:DEVLANE_NATIVE_CS; "
            "[KeelDock.Platform.DevLaneWindows.Boundary]::RunCleanupProcessHandleFixture()"
        )
        environment = os.environ.copy()
        environment["DEVLANE_NATIVE_CS"] = str(native)

        native_results = []

        def native_refusal(state_path):
            native_results.append(subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=45, check=False, env=environment,
            ))
            raise windows.WindowsBoundaryRefusal("windows-cleanup-profile-failed", reason="other")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            marker = root / "private.bin"
            marker.write_bytes(b"private")
            outside = Path(temporary) / "outside-canary.bin"
            outside.write_bytes(b"outside-stays")
            state = root / "state.json"
            state.write_text("{}", encoding="ascii")
            with mock.patch.object(windows, "quiesce_run", side_effect=native_refusal) as quiesce, \
                    mock.patch.object(windows, "delete_profile") as delete_profile, \
                    mock.patch.object(windows, "shred_tree") as shred:
                with self.assertRaises(windows.WindowsBoundaryRefusal):
                    windows.cleanup_runner(state, root)
            quiesce.assert_called_once_with(state)
            self.assertEqual(len(native_results), 1, "native Windows probe did not run")
            native_result = native_results[0]
            self.assertEqual(
                native_result.returncode, 0,
                (native_result.stdout + native_result.stderr).decode("utf-8", "replace"),
            )
            self.assertIn(
                b"windows_native_process_wait=synchronize timeout-distinguished wait-failed=refused "
                b"inaccessible=refused unreaped=refused terminated=reaped",
                native_result.stdout,
            )
            delete_profile.assert_not_called()
            shred.assert_not_called()
            self.assertTrue(state.exists())
            self.assertEqual(marker.read_bytes(), b"private")
            self.assertEqual(outside.read_bytes(), b"outside-stays")

    @unittest.skipUnless(sys.platform == "win32", "requires native Windows file cleanup APIs")
    def test_native_shred_removes_readonly_file_and_directory_on_nonoverwrite_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            readonly_directory = root / "readonly-directory"
            readonly_directory.mkdir(parents=True)
            readonly_file = root / "readonly-large-file.bin"
            readonly_file.write_bytes(b"private")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetFileAttributesW.argtypes = (ctypes.c_wchar_p,)
            kernel.GetFileAttributesW.restype = ctypes.c_uint32
            kernel.SetFileAttributesW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32)
            kernel.SetFileAttributesW.restype = ctypes.c_int
            for path in (readonly_file, readonly_directory):
                attributes = kernel.GetFileAttributesW(str(path))
                self.assertNotEqual(attributes, 0xffffffff)
                self.assertTrue(kernel.SetFileAttributesW(str(path), attributes | 0x1))
            receipt = windows.shred_tree(root, overwrite_limit=0)
            self.assertIn("files=1 bytes=7", receipt)
            self.assertFalse(root.exists())

    def test_cleanup_uses_bounded_reparse_refusal_and_noninheriting_path_mutations(self):
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs").read_text(encoding="utf-8")
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text(encoding="utf-8")
        cleanup = script.split("if ($Mode -eq 'delete') {", 1)[1].split("\n    throw\n} catch {", 1)[0]
        self.assertIn("Get-CleanupPathInfo", script)
        self.assertIn("Boundary]::AssertCleanupEntry", script)
        self.assertIn("Assert-CleanupTreeSafe", cleanup)
        self.assertIn("Set-CleanupStorageAccess", cleanup)
        self.assertIn("'/L'", script)
        self.assertNotIn("CleanupPathLease", native)
        self.assertNotIn("EnumerateCleanupChildren", native)
        self.assertNotIn("RestoreStorageEntry", native)
        self.assertNotIn("DeleteHandleEntry", native)
        self.assertNotIn("SetSecurityInfo", native)
        self.assertNotIn("takeown", native.lower())

    def test_protected_process_fixture_does_not_block_identity_scan(self):
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs").read_text(encoding="utf-8")
        classifier = native.split("public static string ClassifyCleanupProcessFixture", 1)[1].split(
            "public static string RemoveTrackedGrant", 1,
        )[0] if "public static string RemoveTrackedGrant" in native else native.split(
            "public static string ClassifyCleanupProcessFixture", 1,
        )[1].split("public static string Run", 1)[0]
        self.assertIn("processSession != currentSession", classifier)
        self.assertIn("protectionLevel != ProtectionLevelNone", classifier)
        self.assertIn("IsSystemAccountSid(accountSid)", classifier)
        self.assertIn("sid.StartsWith(\"S-1-5-80-\"", native)
        self.assertIn("ClassifyCleanupProcessAccessFailureFixture", native)
        self.assertIn('openError == ErrorAccessDenied', native)
        self.assertIn('String.Equals(processName, "csrss", StringComparison.OrdinalIgnoreCase)', native)
        self.assertIn("if (!inspected) return \"refuse\"", classifier)
        self.assertIn("GetProcessInformation(process, ProcessProtectionLevelInfo", native)
        fixtures = [
            (0, 3, 0, "S-1-5-18", True, "skip-session"),
            (3, 3, 8, "S-1-5-21-1-2-3-1001", True, "skip-protected"),
            (3, 3, 0xfffffffe, "S-1-5-18", True, "skip-system"),
            (3, 3, 0xfffffffe, "S-1-5-80-123456", True, "skip-system"),
            (3, 3, 0xfffffffe, "S-1-5-21-1-2-3-1001", False, "refuse"),
            (3, 3, 0xfffffffe, "S-1-5-21-1-2-3-1001", True, "inspect-identity"),
        ]
        for session, current, protection, account, inspected, expected in fixtures:
            with self.subTest(expected=expected, session=session, protection=protection):
                if not inspected:
                    result = "refuse"
                elif session != current:
                    result = "skip-session"
                elif protection != 0xfffffffe:
                    result = "skip-protected"
                elif account in {"S-1-5-18", "S-1-5-19", "S-1-5-20"} or account.startswith("S-1-5-80-"):
                    result = "skip-system"
                else:
                    result = "inspect-identity"
                self.assertEqual(result, expected)
        access_fixtures = [
            (5, "csrss", False, "skip-protected-system"),
            (5, "worker", False, "refuse"),
            (5, "worker", True, "skip-gone"),
        ]
        for error, process_name, process_gone, expected in access_fixtures:
            with self.subTest(expected=expected, process_name=process_name):
                if process_gone:
                    result = "skip-gone"
                elif error == 5 and process_name.lower() == "csrss":
                    result = "skip-protected-system"
                else:
                    result = "refuse"
                self.assertEqual(result, expected)

    def test_native_constant_values_are_pinned_to_windows_sdk_definitions(self):
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs").read_text(encoding="utf-8")
        observed = {
            name: value.strip()
            for name, value in re.findall(
                r"private const (?:uint|int|ulong|byte) ([A-Za-z_]\w*) = ([^;]+);",
                native,
            )
        }
        expected = {
            "ProcThreadAttributeHandleList": "0x00020002",
            "ProcThreadAttributeSecurityCapabilities": "0x00020009",
            "ProcThreadAttributeAllApplicationPackagesPolicy": "0x0002000f",
            "CreateSuspended": "0x00000004",
            "CreateUnicodeEnvironment": "0x00000400",
            "ExtendedStartupInfoPresent": "0x00080000",
            "StartfUseStdHandles": "0x00000100",
            "JobObjectExtendedLimitInformation": "9",
            "JobObjectBasicProcessIdList": "3",
            "JobObjectLimitActiveProcess": "0x00000008",
            "JobObjectLimitProcessMemory": "0x00000100",
            "JobObjectLimitJobMemory": "0x00000200",
            "JobObjectLimitKillOnJobClose": "0x00002000",
            "JobLimitFlags": "JobObjectLimitActiveProcess | JobObjectLimitProcessMemory | JobObjectLimitJobMemory | JobObjectLimitKillOnJobClose",
            "TokenQuery": "0x0008",
            "TokenPrivilegesInformation": "3",
            "TokenIntegrityLevel": "25",
            "TokenIsAppContainer": "29",
            "TokenCapabilities": "30",
            "TokenAppContainerSid": "31",
            "TokenUser": "1",
            "TokenIsLessPrivilegedAppContainer": "46",
            "ErrorInsufficientBuffer": "122",
            "ErrorMoreData": "234",
            "WaitObject0": "0",
            "WaitTimeout": "0x00000102",
            "WaitFailed": "UInt32.MaxValue",
            "JobExitCode": "0x4b44574b",
            "ProcessMemoryLimit": "4294967296UL",
            "JobMemoryLimit": "12884901888UL",
            "ActiveProcessLimit": "256",
            "CreateNewConsole": "0x00000010",
            "FileAttributeNormal": "0x00000080",
            "OpenExisting": "3",
            "GenericRead": "0x80000000",
            "GenericWrite": "0x40000000",
            "FileShareRead": "1",
            "FileShareWrite": "2",
            "FileFlagOpenReparsePoint": "0x00200000",
            "FileFlagBackupSemantics": "0x02000000",
            "FileReadAttributes": "0x00000080",
            "FileAttributeDirectory": "0x00000010",
            "FileAttributeReparsePoint": "0x00000400",
            "ProcessQueryLimitedInformation": "0x1000",
            "ProcessTerminate": "0x0001",
            "ProcessSynchronize": "0x00100000",
            "JobObjectQueryAccess": "0x0004",
            "JobObjectTerminateAccess": "0x0008",
            "TokenAdjustPrivileges": "0x0020",
            "SePrivilegeEnabled": "0x00000002",
            "UnprotectedDaclSecurityInformation": "0x20000000",
            "ProcessProtectionLevelInfo": "7",
            "ProtectionLevelNone": "0xfffffffe",
            "ErrorInvalidParameter": "87",
            "ErrorAccessDenied": "5",
            "ErrorNotFound": "1168",
            "ErrorAlreadyExists": "183",
            "ErrorFileNotFound": "2",
            "ErrorPathNotFound": "3",
            "ErrorNotAllAssigned": "1300",
            "CleanupEntryLimit": "250000",
            "CleanupDeadlineMilliseconds": "300000",
            "SecurityEnabled": "0x00000004",
        }
        self.assertEqual(observed, expected)

    def test_substituted_cleanup_root_is_refused_before_powershell_acl_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "outside"
            target.mkdir()
            writable = base / "writable"
            writable.symlink_to(target, target_is_directory=True)
            state = base / "sandbox.json"
            state.write_text(json.dumps({
                "schema": 1,
                "owned_roots": [str(base)],
                "acl_grants": [{"path": str(writable), "rights": "Modify", "inheritance": 3}],
                "integrity_grants": [str(writable)],
                "job_state": "none",
            }), encoding="ascii")
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows, "_run_powershell") as powershell:
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.delete_profile(state)
            self.assertEqual(caught.exception.reason, "other")
            powershell.assert_not_called()

    def test_cleanup_contract_refuses_root_or_ancestor_swapped_after_python_preflight(self):
        for swap_ancestor in (False, True):
            with self.subTest(swap_ancestor=swap_ancestor), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                parent = base / "runner"
                writable = parent / "writable"
                writable.mkdir(parents=True)
                outside = base / "outside"
                outside.mkdir()
                state = base / "sandbox.json"
                state.write_text(json.dumps({
                    "schema": 1,
                    "owned_roots": [str(parent)],
                    "acl_grants": [{"path": str(writable), "rights": "Modify", "inheritance": 3}],
                    "integrity_grants": [str(writable)],
                    "job_state": "none",
                }), encoding="ascii")
                mutation = []

                def swap_then_open_cleanup_handle(*_args, **_kwargs):
                    if swap_ancestor:
                        saved = base / "runner-saved"
                        parent.rename(saved)
                        parent.symlink_to(outside, target_is_directory=True)
                    else:
                        saved = base / "writable-saved"
                        writable.rename(saved)
                        writable.symlink_to(outside, target_is_directory=True)
                    windows._validate_cleanup_roots(state)
                    mutation.append("would-have-mutated")
                    return "removed"

                with mock.patch.object(windows.sys, "platform", "win32"), \
                        mock.patch.object(windows, "_run_powershell", side_effect=swap_then_open_cleanup_handle):
                    with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                        windows.delete_profile(state)
                self.assertEqual(caught.exception.reason, "other")
                self.assertEqual(mutation, [])

    def test_profile_cleanup_child_cap_leaves_the_shred_reserve_inside_the_step(self):
        self.assertEqual(windows.WINDOWS_CLEANUP_STEP_SECONDS, 900)
        self.assertEqual(windows.WINDOWS_SHRED_RESERVE_SECONDS, 300)
        self.assertEqual(windows.WINDOWS_QUIESCE_TIMEOUT_SECONDS, 120)
        self.assertEqual(windows.WINDOWS_PROFILE_CLEANUP_TIMEOUT_SECONDS, 360)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "sandbox.json"
            state.write_text(json.dumps({
                "schema": 1, "owned_roots": [], "acl_grants": [], "integrity_grants": [], "job_state": "none",
            }), encoding="ascii")
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows, "_run_powershell", return_value="removed") as powershell:
                windows.delete_profile(state)
            self.assertEqual(powershell.call_args.kwargs["timeout"], 360)

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
            with mock.patch.object(windows, "_windows_cleanup_identity", side_effect=self._portable_cleanup_identity), \
                    mock.patch.object(windows, "_windows_remove_entry", side_effect=sharing) as remove, \
                    mock.patch.object(windows.time, "sleep"), \
                    mock.patch("builtins.print") as output:
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.shred_tree(root)
            self.assertEqual(caught.exception.code, "shred-overwrite-failed")
            self.assertEqual(caught.exception.reason, "sharing-violation")
            output.assert_called_once_with("windows_cleanup_reason=sharing-violation", flush=True)
            self.assertTrue(file.exists())
            self.assertTrue(any(call.kwargs.get("overwrite") is True for call in remove.call_args_list))

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
            with mock.patch.object(windows, "_windows_cleanup_identity", side_effect=self._portable_cleanup_identity), \
                    mock.patch.object(windows, "_windows_remove_entry",
                                      side_effect=self._portable_cleanup_remove):
                receipt = windows.shred_tree(root, plaintext_root=source, overwrite_limit=1024)
            self.assertIn("reparse=1", receipt)
            self.assertFalse(root.exists())
            self.assertEqual(clear.read_text(encoding="ascii"), "preserve")

    def test_cleanup_shreds_after_profile_failure_only_when_quiescence_is_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            state = root / "state.json"
            state.write_text("{}", encoding="ascii")
            with mock.patch.object(windows, "delete_profile", side_effect=windows.WindowsBoundaryRefusal()), \
                    mock.patch.object(windows, "quiesce_run",
                                      return_value="windows_processes=terminated verified=empty\n") as quiesce, \
                    mock.patch.object(windows, "shred_tree", return_value="wiped\n") as wipe, \
                    self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                windows.cleanup_runner(state, root)
            self.assertEqual(caught.exception.code, "windows-cleanup-profile-failed")
            self.assertEqual(quiesce.call_count, 2)
            self.assertEqual([call.args[0] for call in quiesce.call_args_list], [state, state])
            wipe.assert_called_once_with(root, plaintext_root=None)

    def test_failed_job_termination_preserves_state_and_never_shreds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            marker = root / "private.bin"
            marker.write_bytes(b"private")
            outside = Path(temporary) / "outside-canary.bin"
            outside.write_bytes(b"outside-stays")
            state = root / "state.json"
            state.write_text(json.dumps({
                "schema": 1, "profile_name": "KDDevLane" + "b" * 32,
                "package_sid": "S-1-15-2-1-2-3-4-5-6-7", "firewall_rule": "KD-DevLane-123",
                "owned_roots": [], "acl_grants": [], "integrity_grants": [], "job_state": "pending",
            }), encoding="ascii")
            refusal = windows.WindowsBoundaryRefusal("windows-cleanup-profile-failed", reason="other")
            with mock.patch.object(windows, "delete_profile") as delete_profile, \
                    mock.patch.object(windows, "quiesce_run", side_effect=refusal) as quiesce, \
                    mock.patch.object(windows, "shred_tree") as shred:
                with self.assertRaises(windows.WindowsBoundaryRefusal):
                    windows.cleanup_runner(state, root)
            quiesce.assert_called_once_with(state)
            delete_profile.assert_not_called()
            shred.assert_not_called()
            self.assertTrue(state.exists())
            self.assertEqual(marker.read_bytes(), b"private")
            self.assertEqual(outside.read_bytes(), b"outside-stays")

    def test_live_matching_appcontainer_refusal_preserves_outside_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            marker = root / "private.bin"
            marker.write_bytes(b"private")
            outside = Path(temporary) / "outside-canary.bin"
            outside.write_bytes(b"outside-stays")
            state = root / "state.json"
            state.write_text(json.dumps({
                "schema": 1, "profile_name": "KDDevLane" + "c" * 32,
                "package_sid": "S-1-15-2-1-2-3-4-5-6-7", "firewall_rule": "KD-DevLane-456",
                "owned_roots": [], "acl_grants": [], "integrity_grants": [], "job_state": "pending",
            }), encoding="ascii")
            refusal = windows.WindowsBoundaryRefusal(
                "windows-cleanup-profile-failed", reason="process-alive",
            )
            with mock.patch.object(windows, "delete_profile") as delete_profile, \
                    mock.patch.object(windows, "quiesce_run", side_effect=refusal) as quiesce, \
                    mock.patch.object(windows, "shred_tree") as shred:
                with self.assertRaises(windows.WindowsBoundaryRefusal):
                    windows.cleanup_runner(state, root)
            quiesce.assert_called_once_with(state)
            delete_profile.assert_not_called()
            shred.assert_not_called()
            self.assertTrue(state.exists())
            self.assertEqual(marker.read_bytes(), b"private")
            self.assertEqual(outside.read_bytes(), b"outside-stays")

    @staticmethod
    def _portable_cleanup_identity(path, *, require_directory=False, allow_reparse=False):
        path = Path(path)
        metadata = path.lstat()
        reparse = stat.S_ISLNK(metadata.st_mode)
        directory = stat.S_ISDIR(metadata.st_mode) or (reparse and path.is_dir())
        identity = {
            "volume": metadata.st_dev, "file_id": metadata.st_ino, "size": metadata.st_size,
            "links": metadata.st_nlink, "attributes": 0, "directory": directory, "reparse": reparse,
        }
        if (require_directory and not directory) or (reparse and not allow_reparse):
            raise windows.WindowsBoundaryRefusal("shred-entry-inspection-failed")
        return identity

    @classmethod
    def _portable_cleanup_remove(cls, path, expected, ancestors, *, overwrite=False, allow_reparse=False):
        path = Path(path)
        for parent, parent_identity in ancestors:
            actual_parent = cls._portable_cleanup_identity(parent, require_directory=True)
            if not windows._same_windows_identity(actual_parent, parent_identity, directory=True):
                raise windows.WindowsBoundaryRefusal("shred-entry-inspection-failed")
        actual = cls._portable_cleanup_identity(path, allow_reparse=True)
        if not windows._same_windows_identity(
                actual, expected, directory=bool(expected["directory"] or actual["directory"])):
            raise windows.WindowsBoundaryRefusal("shred-entry-inspection-failed")
        if actual["reparse"]:
            path.unlink()
            return
        if actual["directory"]:
            path.rmdir()
            return
        if actual["links"] != 1:
            raise windows.WindowsBoundaryRefusal("shred-hardlink-refused")
        if overwrite:
            with path.open("r+b") as handle:
                handle.write(os.urandom(actual["size"]))
                handle.flush()
                os.fsync(handle.fileno())
        path.unlink()

    def test_native_remove_handle_requests_write_attributes_for_readonly_file_and_directory(self):
        class NativeCall:
            def __init__(self, function):
                self.function = function

            def __call__(self, *arguments):
                return self.function(*arguments)

        for name, is_directory, size, attributes in (
            ("large-readonly-file", False, 1024 * 1024 * 1024 + 1, 0x81),
            ("readonly-directory", True, 0, 0x11),
        ):
            with self.subTest(name=name):
                parent = Path(r"C:\run")
                path = parent / name
                parent_identity = {
                    "volume": 7, "file_id": 10, "size": 0, "links": 1,
                    "attributes": 0x10, "directory": True, "reparse": False,
                }
                entry_identity = {
                    "volume": 7, "file_id": 11, "size": size, "links": 1,
                    "attributes": attributes, "directory": is_directory, "reparse": False,
                }
                handles = {}
                access_by_handle = {}
                cleared_attributes = []
                next_handle = [100]

                def create_file(_name, access, _share, _security, _creation, _flags, _template):
                    handle = next_handle[0]
                    next_handle[0] += 1
                    identity = parent_identity if not handles else entry_identity
                    handles[handle] = identity
                    access_by_handle[handle] = access
                    return handle

                def get_information(handle, information_pointer):
                    identity = handles[handle]
                    information = ctypes.cast(
                        information_pointer, ctypes.POINTER(windows._CleanupByHandleInfo),
                    ).contents
                    information.attributes = identity["attributes"]
                    information.volume = identity["volume"]
                    information.size_high = identity["size"] >> 32
                    information.size_low = identity["size"] & 0xffffffff
                    information.links = identity["links"]
                    information.file_high = identity["file_id"] >> 32
                    information.file_low = identity["file_id"] & 0xffffffff
                    return 1

                def set_information(handle, information_class, information_pointer, _size):
                    access = access_by_handle[handle]
                    if information_class == 0:
                        if not access & windows._WINDOWS_FILE_WRITE_ATTRIBUTES:
                            return 0
                        basic = ctypes.cast(
                            information_pointer, ctypes.POINTER(windows._CleanupBasicInfo),
                        ).contents
                        cleared_attributes.append(basic.attributes)
                        return int((basic.attributes & 0x1) == 0)
                    if information_class == 4:
                        return int(bool(access & windows._WINDOWS_DELETE))
                    return 0

                kernel = type("FakeKernel", (), {})()
                kernel.CreateFileW = NativeCall(create_file)
                kernel.GetFileInformationByHandle = NativeCall(get_information)
                kernel.SetFileInformationByHandle = NativeCall(set_information)
                kernel.WriteFile = NativeCall(lambda *_arguments: 1)
                kernel.FlushFileBuffers = NativeCall(lambda *_arguments: 1)
                kernel.CloseHandle = NativeCall(lambda *_arguments: 1)
                with mock.patch.object(windows.sys, "platform", "win32"), \
                        mock.patch.object(windows.ctypes, "WinDLL", return_value=kernel, create=True):
                    windows._windows_remove_entry(
                        path, entry_identity, [(parent, parent_identity)], overwrite=False,
                    )
                entry_handle = max(access_by_handle)
                self.assertTrue(access_by_handle[entry_handle] & windows._WINDOWS_FILE_WRITE_ATTRIBUTES)
                self.assertTrue(access_by_handle[entry_handle] & windows._WINDOWS_DELETE)
                self.assertEqual(len(cleared_attributes), 1)
                self.assertFalse(cleared_attributes[0] & 0x1)

    def test_shred_refuses_external_hardlink_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            outside = Path(temporary) / "outside.bin"
            outside.write_bytes(b"outside-stays")
            (root / "linked.bin").hardlink_to(outside)
            with mock.patch.object(windows, "_windows_cleanup_identity", side_effect=self._portable_cleanup_identity), \
                    mock.patch.object(windows, "_windows_remove_entry",
                                      side_effect=self._portable_cleanup_remove) as remove:
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.shred_tree(root)
            self.assertEqual(caught.exception.code, "shred-hardlink-refused")
            remove.assert_not_called()
            self.assertEqual(outside.read_bytes(), b"outside-stays")
            self.assertEqual((root / "linked.bin").read_bytes(), b"outside-stays")

    def test_shred_unlinks_junction_without_following_external_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            canary = outside / "canary.txt"
            canary.write_text("preserve", encoding="ascii")
            (root / "junction").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(windows, "_windows_cleanup_identity", side_effect=self._portable_cleanup_identity), \
                    mock.patch.object(windows, "_windows_remove_entry",
                                      side_effect=self._portable_cleanup_remove):
                receipt = windows.shred_tree(root)
            self.assertIn("reparse=1", receipt)
            self.assertFalse(root.exists())
            self.assertEqual(canary.read_text(encoding="ascii"), "preserve")

    def test_shred_rejects_junction_substitution_by_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            canary = outside / "canary.txt"
            canary.write_text("preserve", encoding="ascii")
            junction = root / "junction"
            junction.symlink_to(outside, target_is_directory=True)
            original_remove = self._portable_cleanup_remove
            substituted = [False]

            def substitute_then_remove(path, expected, ancestors, **kwargs):
                if Path(path) == junction and not substituted[0]:
                    junction.unlink()
                    replacement = Path(temporary) / "replacement"
                    replacement.mkdir()
                    junction.symlink_to(replacement, target_is_directory=True)
                    substituted[0] = True
                return original_remove(path, expected, ancestors, **kwargs)

            with mock.patch.object(windows, "_windows_cleanup_identity", side_effect=self._portable_cleanup_identity), \
                    mock.patch.object(windows, "_windows_remove_entry", side_effect=substitute_then_remove):
                with self.assertRaises(windows.WindowsBoundaryRefusal):
                    windows.shred_tree(root)
            self.assertTrue(substituted[0])
            self.assertEqual(canary.read_text(encoding="ascii"), "preserve")

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
            node, npm, cmd = self._toolchain_fixture(root)
            requests = []

            def isolated(_state, request, _run_root, **_kwargs):
                requests.append(dict(request))
                project = Path(request["working_directory"])
                modules = project / "node_modules"
                modules.mkdir(exist_ok=True)
                (modules / "playwright").mkdir(exist_ok=True)
                (modules / "playwright" / "cli.js").write_text("", encoding="ascii")
                return {"status": "pass", "exit_code": 0,
                        "token": "lpac=verified bypass_traverse=present",
                        "job": "assigned kill_on_close=enabled breakaway=disabled"}

            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": ["chromium"],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                    mock.patch.object(windows, "_system_cmd_path", return_value=cmd), \
                    mock.patch.object(windows, "_deadline_remaining", return_value=600), \
                    mock.patch.object(windows, "create_profile", return_value={}), \
                    mock.patch.object(windows, "delete_profile"), \
                    mock.patch.object(windows, "_native_run", side_effect=isolated), \
                    mock.patch("builtins.print") as stage_output:
                windows.prepare_dependencies(projection, output, root / "deadline.json", state)

            self.assertEqual(len(requests), 2)
            copied_node = output / "prepared" / "toolchain" / "node.exe"
            copied_npm = output / "prepared" / "toolchain" / "node_modules" / "npm" / "bin" / "npm-cli.js"
            for request in requests:
                self.assertTrue(request["internet_client"])
                self.assertIn(str(output / "prepared" / "toolchain"), request["read_paths"])
                self.assertNotIn(str(node), request["read_paths"])
                self.assertNotIn(str(npm.parent.parent), request["read_paths"])
                self.assertNotIn(str(Path("C:/Windows/System32")), request["read_paths"])
                self.assertIn(str(output / "project"), request["write_paths"])
                self.assertIn(str(output / "npm-cache"), request["write_paths"])
                self.assertIn(str(output / "prepared" / "ms-playwright"), request["write_paths"])
                self.assertTrue(request["environment"][0].startswith("PATH=" + str(copied_node.parent)))
                self.assertIn("ComSpec=" + str(copied_node.parent / "cmd.exe"), request["environment"])
                self.assertIn("NPM_CONFIG_IGNORE_SCRIPTS=true", request["environment"])
                self.assertIn("NPM_CONFIG_OFFLINE=false", request["environment"])
                self.assertIn("NPM_CONFIG_LOGS_DIR=" + str(output / "npm-cache" / "_logs"), request["environment"])
                self.assertIn("NPM_CONFIG_PREFIX=" + str(output / "project"), request["environment"])
                self.assertIn("NPM_CONFIG_YES=true", request["environment"])
                self.assertIn("NPM_CONFIG_PROMPT=false", request["environment"])
                self.assertIn("GIT_TERMINAL_PROMPT=0", request["environment"])
                self.assertEqual(request["executable"], str(copied_node))
                if request["arguments"][0] == str(copied_npm):
                    self.assertIn("--yes", request["arguments"])
            self.assertTrue((output / "prepared" / "toolchain.json").is_file())
            self.assertEqual((output / "prepared" / "toolchain.json").exists(), True)
            self.assertEqual(
                [call.args[0] for call in stage_output.call_args_list],
                ["windows_prepare_stage_start=profile-create", "windows_prepare_stage=none",
                 "windows_prepare_stage_start=npm-ci",
                 "windows_prepare_limit stage=npm-ci limit=work-deadline seconds=600 powershell-seconds=630",
                 "windows_token_bypass_traverse=present",
                 "windows_prepare_job=empty",
                 "windows_prepare_stage=npm-ci", "windows_prepare_stage_start=playwright",
                 "windows_prepare_limit stage=playwright limit=work-deadline seconds=600 powershell-seconds=630",
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
            node, npm, cmd = self._toolchain_fixture(root)
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": [],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                    mock.patch.object(windows, "_system_cmd_path", return_value=cmd), \
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
            output.assert_any_call(
                "windows_prepare_limit stage=npm-ci limit=npm-child seconds=3600 powershell-seconds=3630",
                flush=True,
            )

    def test_prepare_powershell_monitor_reports_allowlisted_heartbeat_and_timeout(self):
        process = mock.Mock(pid=123, returncode=0)
        process.stdout = io.BytesIO(b'{"status":"pass"}\r\n')
        process.wait.side_effect = [windows.subprocess.TimeoutExpired("pwsh", 60), None]
        with mock.patch.object(windows.subprocess, "Popen", return_value=process), \
                mock.patch.object(windows, "_windows_process_summary", return_value=(2, "node")), \
                mock.patch.object(windows.time, "monotonic", side_effect=(0, 0, 60.1, 60.1)), \
                mock.patch("builtins.print") as output:
            result = windows._run_powershell(
                "run", "sandbox.json", timeout=600, failure_prefix="windows-prepare", monitor_stage="npm-ci",
            )
        self.assertEqual(result, '{"status":"pass"}')
        output.assert_called_once_with(
            "windows_prepare_heartbeat stage=npm-ci elapsed=60 children=2 top=node", flush=True,
        )

        hung = mock.Mock(pid=456)
        hung.stdout = io.BytesIO(b"")
        hung.wait.side_effect = [windows.subprocess.TimeoutExpired("pwsh", 1), None]
        with mock.patch.object(windows.subprocess, "Popen", return_value=hung), \
                mock.patch.object(windows.time, "monotonic", side_effect=(0, 0, 1.1)), \
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
                node, npm, cmd = self._toolchain_fixture(root)
                with mock.patch.object(windows.sys, "platform", "win32"), \
                        mock.patch.object(windows.fetch, "validate_projection", return_value={
                            "npm_package": {}, "npm_lock": {}, "playwright": [],
                        }), \
                        mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                        mock.patch.object(windows, "_system_cmd_path", return_value=cmd), \
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
            node, npm, cmd = self._toolchain_fixture(root)
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
                    mock.patch.object(windows, "_system_cmd_path", return_value=cmd), \
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



class WindowsRehearsalRegressionTests(unittest.TestCase):
    def setUp(self):
        self.identity = {"ref": "refs/heads/main", "control_sha": audit_fixtures.SHA, "run_id": "12345"}

    def test_successful_graph_snapshot_retains_all_public_names_attempts_and_conclusions(self):
        control = audit_fixtures.control_audit
        rows = audit_fixtures._control_jobs()
        api = mock.Mock()
        api.json.return_value = ({"total_count": 18, "jobs": rows}, {})
        with contextlib.redirect_stdout(io.StringIO()) as output:
            control.read_control_graph(api, "/fixture", self.identity)
        lines = [line for line in output.getvalue().splitlines() if line.startswith("control_graph_row ")]
        self.assertEqual(len(lines), 18)
        for row in rows:
            self.assertTrue(any("name=" + row["name"] + " occurrence=1 attempt=1" in line
                                and "conclusion=" + str(row["conclusion"]).lower() in line
                                for line in lines))

    def test_detailed_exception_probe_survives_fake_powershell_and_requires_refusal(self):
        diagnostic = (b"windows_boundary_failure operation=acl-write code=other win32=5 "
                      b"hresult=-2147024891 target=read-0 principal=package-sid\n")
        for exit_code in (0, 1):
            process = mock.Mock(returncode=exit_code)
            process.stdout = io.BytesIO(diagnostic + b"windows_sandbox=refused code=boundary\n")
            with mock.patch.object(windows.subprocess, "Popen", return_value=process), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(windows.WindowsBoundaryRefusal):
                    windows._run_powershell("run", "sandbox.json", failure_prefix="windows-prepare")
            self.assertEqual(output.getvalue(), diagnostic.decode())
        for bad in (diagnostic.replace(b"read-0", b"private/path"),
                    diagnostic.replace(b"package-sid", b"secret"),
                    diagnostic.replace(b"code=other", b"code=private-message")):
            self.assertFalse(windows._boundary_failure_line(bad))

    def test_windows_boundary_probe_is_failure_bound_and_has_no_free_text(self):
        identity = dict(audit_fixtures.IDENTITY, platform="windows")
        diagnostic = ("windows_boundary_failure operation=state-save code=argument-types win32=other "
                      "hresult=-2146233087 target=owned-root principal=package-sid")
        failure = {
            "step": audit_fixtures.audit.WINDOWS_PREPARE_STEP,
            "marker": "devlane_refusal=windows-prepare-powershell-nonzero", "exit_code": 1,
            "outputs": ["windows_prepare_stage=none", "windows_prepare_stage_start=npm-ci",
                        diagnostic, "devlane_refusal=windows-prepare-powershell-nonzero",
                        "windows_prepare_stage_start=profile-cleanup"],
        }
        log = audit_fixtures._render_real_runner_encrypted_log(identity, early_failure=failure)
        audit_fixtures.audit.validate_job_log_surface(log, audit_fixtures.audit.PLATFORM_RUN_JOBS["windows"], identity, completed=True)
        for changed in (log.replace(b"code=argument-types", b"code=private-content"),
                        log.replace(b"operation=state-save", b"operation=private-path"),
                        log.replace(diagnostic.encode(), (diagnostic + "\n") .encode() * 3),
                        audit_fixtures._render_real_runner_encrypted_log(identity).replace(
                            b"windows_prepare_stage_start=npm-ci", (diagnostic + "\nwindows_prepare_stage_start=npm-ci").encode())):
            with self.assertRaises(audit_fixtures.audit.AuditRefusal):
                audit_fixtures.audit.validate_job_log_surface(changed, audit_fixtures.audit.PLATFORM_RUN_JOBS["windows"], identity, completed=True)

    def test_recorded_windows_image_patch_version_is_audited_with_closed_metadata(self):
        identity = dict(audit_fixtures.IDENTITY, platform="windows")
        log = audit_fixtures._render_real_runner_encrypted_log(identity)
        before, image = log.split(b"Image: windows-2025-vs2026", 1)
        log = before + b"Image: windows-2025-vs2026" + image.replace(
            b"Version: 20261103.629", b"Version: 20261116.315.1", 1)
        log = log.replace(b"/20261103.629/images/windows/", b"/20261116.315/images/windows/")
        log = log.replace(b"win25-vs2026%2F20261103.629", b"win25-vs2026%2F20261116.315")
        self.assertIn(b"Version: 20261116.315.1", log)
        audit_fixtures.audit.validate_job_log_surface(log, audit_fixtures.audit.PLATFORM_RUN_JOBS["windows"], identity, completed=True)
        for changed in (
                log.replace(b"20261116.315.1\n", b"20261116.315.2\n"),
                log.replace(b"20261116.315.1\n", b"20261116.315.1 injected\n"),
                log.replace(b"Image: windows-2025-vs2026", b"Image: unknown"),
                log.replace(b"github.com/actions/runner-images/blob/win25-vs2026", b"example.com/runner-images")):
            with self.subTest(changed=changed[:60]), self.assertRaises(audit_fixtures.audit.AuditRefusal):
                audit_fixtures.audit.validate_job_log_surface(changed, audit_fixtures.audit.PLATFORM_RUN_JOBS["windows"], identity, completed=True)

    def test_live_graph_api_lag_is_reread_without_relaxing_the_contract(self):
        stale = audit_fixtures._control_jobs()
        own = next(job for job in stale if job["name"] == audit_fixtures.control_audit.RUN_JOB)
        own["steps"][2].update(status="pending", conclusion=None)
        api = type("API", (), {})()
        api.json = unittest.mock.Mock(side_effect=[
            ({"total_count": 18, "jobs": stale}, {}),
            ({"total_count": 18, "jobs": audit_fixtures._control_jobs()}, {}),
        ])
        with mock.patch.object(audit_fixtures.control_audit.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()) as output:
            result = audit_fixtures.control_audit.read_control_graph(api, "/recorded-run", self.identity)
        self.assertEqual(len(result), 18)
        sleep.assert_called_once_with(2)
        self.assertIn("snapshot=1 reason=self-audit", output.getvalue())
        self.assertIn("snapshot=2 reason=valid", output.getvalue())
        self.assertEqual(api.json.call_count, 2)

    def test_graph_probe_distinguishes_persistent_failures_and_never_accepts_them(self):
        mutations = []
        for reason in ("count", "pagination", "names", "attempt", "identity", "child-live", "child-conclusion",
                       "self-status", "self-step-names", "self-fetch", "self-audit", "self-cache-skipped"):
            jobs, headers = audit_fixtures._control_jobs(), {}
            own = next(job for job in jobs if job["name"] == audit_fixtures.control_audit.RUN_JOB)
            child = next(job for job in jobs if job["name"] != audit_fixtures.control_audit.RUN_JOB)
            if reason == "count": jobs.pop()
            elif reason == "pagination": headers["Link"] = "untrusted header is never printed"
            elif reason == "names": child["name"] = "untrusted job name is never printed"
            elif reason == "attempt": child["run_attempt"] = 2
            elif reason == "identity": child["head_sha"] = "e" * 40
            elif reason == "child-live": child["status"] = "in_progress"
            elif reason == "child-conclusion": child["conclusion"] = "neutral"
            elif reason == "self-status": own["status"] = "queued"
            elif reason == "self-step-names": own["steps"].pop(3)
            elif reason == "self-fetch": own["steps"][1]["status"] = "in_progress"
            elif reason == "self-audit": own["steps"][2]["status"] = "pending"
            elif reason == "self-cache-skipped": own["steps"][3].update(status="completed", conclusion="skipped")
            record = {"total_count": 18, "jobs": jobs}
            with self.subTest(reason=reason):
                self.assertEqual(audit_fixtures.control_audit.control_graph_probe(record, headers, self.identity), reason)
                api = type("API", (), {})()
                api.json = unittest.mock.Mock(return_value=(record, headers))
                with mock.patch.object(audit_fixtures.control_audit.time, "sleep"), contextlib.redirect_stdout(io.StringIO()) as output:
                    with self.assertRaises(audit_fixtures.control_audit.ControlAuditRefusal) as caught:
                        audit_fixtures.control_audit.read_control_graph(api, "/recorded-run", self.identity)
                self.assertEqual(caught.exception.stage, "job-graph")
                self.assertEqual(api.json.call_count, 4)
                self.assertNotIn("untrusted", output.getvalue())


class NativeFailurePreservationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "requires hosted Windows PowerShell")
    def test_icacls_native_status_survives_formatter(self):
        script = Path(windows.__file__).with_suffix(".ps1").read_text()
        function = script.split("function Invoke-CleanupIcacls", 1)[1].split("function Set-CleanupStorageAccess", 1)[0]
        probe = """$ErrorActionPreference='Stop'
function Assert-OwnedPath([string]$Path) { return $Path }
function Join-Path { return 'Invoke-FakeIcacls' }
function Invoke-FakeIcacls { $global:LASTEXITCODE=87 }
function Invoke-CleanupIcacls""" + function + """
try { Invoke-CleanupIcacls 'fixture' @('/setintegritylevel','(OI)(CI)L'); exit 2 }
catch { if ($_.Exception.HResult -ne 87) { exit 3 }; exit 0 }
"""
        import base64
        result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                                 base64.b64encode(probe.encode("utf-16le")).decode("ascii")],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 0)

    def test_quiescence_wrapper_preserves_diagnostic_exception(self):
        native = Path(windows.__file__).with_name("sandbox_windows_native.cs").read_text()
        method = native.split("private static void AssertCleanupQuiescent", 1)[1].split("private static bool IsProcessGone", 1)[0]
        self.assertEqual(method.count('new InvalidOperationException("cleanup_processes", error)'), 2)
        self.assertIn("catch (Exception error)", method)

if __name__ == "__main__":
    unittest.main()
