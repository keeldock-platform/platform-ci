"""Mac-runnable validation for the hosted Windows adapter's fixed inputs."""

import json
import contextlib
import io
import os
import re
import tempfile
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
        self.assertIn("$system32Path", run)
        self.assertIn("[StringComparison]::OrdinalIgnoreCase)) { continue }", run)
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
        self.assertLess(cleanup.index("AssertCleanupQuiescent", cleanup.index("Clear-AppContainerStorage")),
                        cleanup.index("DeleteProfile"))
        self.assertIn("$state.job_state = 'pending'", run)
        self.assertIn("$state.job_state = 'terminated-empty'", run)
        self.assertIn("empty=confirmed", run)
        self.assertNotIn("Set-Acl", cleanup)
        self.assertNotIn("takeown", cleanup.lower())
        self.assertNotRegex(cleanup, r"(?i)'/T'|\"/T\"|Remove-Item.*-Recurse")
        self.assertNotIn("$modifiedPaths", cleanup)
        self.assertNotIn("Restore-RunnerAccessTree", cleanup)
        self.assertIn("Assert-CleanupTreeSafe $pathInfo.Path", cleanup)
        self.assertLess(tracked_grant.index("Assert-CleanupTreeSafe"), tracked_grant.index("Set-Acl"))
        self.assertLess(tracked_integrity.index("Assert-CleanupTreeSafe"), tracked_integrity.index("'/setintegritylevel'"))
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
        self.assertIn("$script:WindowsCleanupTimer.ElapsedMilliseconds -gt 600000", script)
        self.assertIn("[void](Clear-AppContainerStorage", cleanup)
        python_source = Path(windows.__file__).read_text(encoding="utf-8")
        self.assertIn("timeout=WINDOWS_PROFILE_CLEANUP_TIMEOUT_SECONDS", python_source)

    def test_ancestor_traverse_grant_uses_a_direct_nonpropagating_setter(self):
        script = Path(windows.__file__).with_name("sandbox_windows.ps1").read_text(encoding="utf-8")
        run = script.split("if ($Mode -eq 'run')", 1)[1].split("if ($Mode -eq 'delete')", 1)[0]
        self.assertEqual(run.count("Add-TrackedTraverseGrant $ancestor.FullName"), 2)
        traverse = "function Add-TrackedTraverseGrant" + run.split(
            "function Add-TrackedTraverseGrant", 1,
        )[1].split("function Add-TrackedIntegrityGrant", 1)[0]
        self.assertNotRegex(traverse, r"\bGet-Acl\b|\bSet-Acl\b")
        self.assertIn("@('/grant:r', ('*' + [string]$sid + ':(X,S)'))", traverse)
        self.assertNotRegex(traverse, r"(?i)\(OI\)|\(CI\)|'/T'|\"/T\"")
        self.assertIn("'/L'", script.split("function Invoke-CleanupIcacls", 1)[1].split("function Set-CleanupStorageAccess", 1)[0])
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "ancestor" / "child" / "leaf"
            fixture.mkdir(parents=True)
            ancestors = []
            current = fixture
            while current != current.parent:
                ancestors.append(current)
                current = current.parent
            sid = "S-1-15-2-1-2-3-4-5-6-7"
            writes = [(str(path), "/grant:r", "*" + sid + ":(X,S)", "/L", "/Q") for path in ancestors]
            self.assertGreaterEqual(len(writes), 4)
            self.assertTrue(all("(OI)" not in " ".join(write) and "(CI)" not in " ".join(write)
                                and "/T" not in write for write in writes))
            self.assertTrue(all(write[1:] == ("/grant:r", "*" + sid + ":(X,S)", "/L", "/Q")
                                for write in writes))

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
        self.assertIn('jobState != "none" && jobState != "terminated-empty"', check)
        self.assertIn("Process.GetProcesses()", check)
        self.assertIn("item.SessionId", check)
        self.assertIn("GetProcessInformation(process, ProcessProtectionLevelInfo", check)
        self.assertIn("ClassifyCleanupProcessFixture", check)
        self.assertIn("OpenProcessToken(process, TokenQuery, out token)", check)
        self.assertIn("EqualSid(Marshal.ReadIntPtr(app), expectedSid)", check)
        self.assertIn('throw new InvalidOperationException("cleanup_process_alive")', check)
        self.assertLess(delete.index("AssertCleanupQuiescent"), delete.index("Remove-NetFirewallRule"))
        self.assertIn("WaitForEmptyJob(job, 10000)", native)
        self.assertIn('result.Job += " terminated=confirmed empty=confirmed"', native)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "sandbox.json"
            state.write_text(json.dumps({
                "schema": 1, "acl_grants": [], "integrity_grants": [], "job_state": "pending",
            }), encoding="ascii")
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows, "_run_powershell") as powershell:
                with self.assertRaises(windows.WindowsBoundaryRefusal) as caught:
                    windows.delete_profile(state)
            self.assertEqual(caught.exception.reason, "other")
            powershell.assert_not_called()

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
            "TokenAdjustPrivileges": "0x0020",
            "SePrivilegeEnabled": "0x00000002",
            "UnprotectedDaclSecurityInformation": "0x20000000",
            "ProcessProtectionLevelInfo": "7",
            "ProtectionLevelNone": "0xfffffffe",
            "ErrorInvalidParameter": "87",
            "ErrorAccessDenied": "5",
            "ErrorNotFound": "1168",
            "ErrorFileNotFound": "2",
            "ErrorPathNotFound": "3",
            "ErrorNotAllAssigned": "1300",
            "CleanupEntryLimit": "250000",
            "CleanupDeadlineMilliseconds": "600000",
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
        self.assertEqual(windows.WINDOWS_PROFILE_CLEANUP_TIMEOUT_SECONDS, 600)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "sandbox.json"
            state.write_text(json.dumps({
                "schema": 1, "acl_grants": [], "integrity_grants": [], "job_state": "none",
            }), encoding="ascii")
            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows, "_run_powershell", return_value="removed") as powershell:
                windows.delete_profile(state)
            self.assertEqual(powershell.call_args.kwargs["timeout"], 600)

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
                self.assertIn(str(node), request["read_paths"])
                self.assertIn(str(npm.parent.parent), request["read_paths"])
                self.assertNotIn(str(Path("C:/Windows/System32")), request["read_paths"])
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
                 "windows_prepare_stage_start=npm-ci",
                 "windows_prepare_limit stage=npm-ci limit=work-deadline seconds=600 powershell-seconds=630",
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
