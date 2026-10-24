import base64
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "kit/confinement/windows_native_preflight.cs"
WRAPPER = ROOT / "kit/confinement/windows_native_preflight.ps1"


class WindowsNativePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HARNESS.read_text(encoding="utf-8")
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")

    def test_native_source_contract_is_manual_public_and_synthetic(self):
        for required in (
            "CreateAppContainerProfile",
            "ProcThreadAttributeSecurityCapabilities",
            "ProcThreadAttributeAllApplicationPackagesPolicy",
            "ProcessCreationAllApplicationPackagesOptOut",
            "CreateSuspended",
            "CreateProcessW(executable, commandLine",
            "AssignProcessToJobObject(job, process)",
            "OpenProcessToken(process, TokenQuery",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.source)
        self.assertNotIn("ResumeThread", self.source)
        self.assertNotIn("Process.Start", self.source)
        self.assertNotIn("ProcessStartInfo", self.source)
        self.assertIn('Path.Combine(systemDirectory.ToString(), "cmd.exe")', self.source)
        self.assertIn('new StringBuilder("\\\"" + executable + "\\\" /d /c exit 0")', self.source)
        self.assertRegex(
            self.source,
            re.compile(
                r'\[DllImport\("kernel32\.dll", CharSet = CharSet\.Unicode, ExactSpelling = true, SetLastError = true\)\]\s+'
                r'internal static extern uint GetSystemDirectoryW\(StringBuilder buffer, uint size\);'
            ),
        )

    def test_actual_token_properties_are_read_before_acceptance(self):
        for expected in (
            "private const int TokenIntegrityLevel = 25;",
            "private const int TokenIsAppContainer = 29;",
            "private const int TokenCapabilities = 30;",
            "private const int TokenAppContainerSid = 31;",
            "private const int TokenIsLessPrivilegedAppContainer = 46;",
            "ReadTokenDword(childToken, TokenIsAppContainer) != 1",
            "ReadTokenDword(childToken, TokenIsLessPrivilegedAppContainer) != 1",
            "if (length != 4)",
            "Marshal.ReadInt32(capabilityInformation) != 0",
            "Native.EqualSid(actualSid, profileSid)",
            "0x00001000",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.source)
        self.assertIn("TokenCapabilities", self.source)
        self.assertIn("TokenAppContainerSid", self.source)

    def test_job_assignment_limits_readback_and_termination_are_required(self):
        for expected in (
            "JobObjectLimitActiveProcess = 0x00000008",
            "JobObjectLimitProcessMemory = 0x00000100",
            "JobObjectLimitKillOnJobClose = 0x00002000",
            "ActiveProcessLimit = 1",
            "ProcessMemoryLimit = new UIntPtr(ProcessMemoryLimit)",
            "QueryInformationJobObject(job, JobObjectExtendedLimitInformation",
            "TerminateJobObject(job, 0x4b444e50)",
            "WaitForSingleObject(process, 5000)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.source)

    def test_cng_private_key_export_policy_acl_and_destruction_are_read_back(self):
        for expected in (
            '"Microsoft Software Key Storage Provider"',
            '"ECDH_P256"',
            '"Export Policy"',
            '"Key Type"',
            '"Length"',
            '"Security Descr Support"',
            '"Security Descr"',
            "NCryptSilentFlag = 0x00000040",
            "Native.GetSecurityDescriptorOwner",
            "Native.GetSecurityDescriptorDacl",
            'Native.NCryptExportKey(key, IntPtr.Zero, "ECCPRIVATEBLOB"',
            "status != NtePermissionDenied",
            "Native.NCryptDeleteKey(key, NCryptSilentFlag)",
            "Native.NCryptOpenKey(provider, out reopened, keyName, 0, NCryptSilentFlag)",
            "status == NteBadKeyset",
            "Native.DeleteAppContainerProfile(profileName)",
            "Native.FreeSid(profileSid)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.source)
        self.assertIn("ReadKeyDword(\"Export Policy\", NCryptSilentFlag) != 0", self.source)
        self.assertIn("Native.EqualSid(ownerSid, currentUserSid)", self.source)
        self.assertNotIn("BCRYPT_ECCPRIVATE_BLOB", self.source)

    def test_cng_collision_never_grants_ownership_or_deletes_existing_key(self):
        create_key = self.source.index("status = Native.NCryptCreatePersistedKey")
        failure_check = self.source.index("if (status != 0)", create_key)
        ownership_mark = self.source.index("keyOwned = true;", create_key)
        self.assertLess(create_key, failure_check)
        self.assertLess(failure_check, ownership_mark)
        self.assertIn("if (keyOwned && provider != IntPtr.Zero && keyName != null)", self.source)
        self.assertNotIn("keyCreationAttempted", self.source)
        self.assertNotIn("NCRYPT_OVERWRITE_KEY_FLAG", self.source)

    def test_failed_profile_creation_requires_cleanup_or_collision_refusal(self):
        self.assertIn("private bool profileFailureNeedsCleanup;", self.source)
        self.assertIn("private bool profileNameCollision;", self.source)
        self.assertIn("if (result == HresultAlreadyExists)", self.source)
        self.assertIn("profileNameCollision = true;", self.source)
        self.assertIn("profileFailureNeedsCleanup = true;", self.source)
        self.assertIn("else if (profileFailureNeedsCleanup && profileName != null)", self.source)
        self.assertIn("Native.DeleteAppContainerProfile(profileName)", self.source)
        self.assertIn("if (profileNameCollision)", self.source)

    def test_failed_process_creation_captures_any_returned_handles_before_refusal(self):
        create_call = self.source.index("bool created = Native.CreateProcessW(")
        process_capture = self.source.index("process = processInformation.Process;", create_call)
        thread_capture = self.source.index("thread = processInformation.Thread;", create_call)
        failure_check = self.source.index(
            "if (!created)\n                {\n                    childProcessCreateError = createProcessError;",
            create_call,
        )
        handle_check = self.source.index("if (!processCreated || thread == IntPtr.Zero)", create_call)
        self.assertLess(create_call, process_capture)
        self.assertLess(process_capture, thread_capture)
        self.assertLess(thread_capture, failure_check)
        self.assertLess(failure_check, handle_check)
        self.assertIn("Native.ProcessInformation processInformation = new Native.ProcessInformation();", self.source)
        self.assertIn("ref startup, ref processInformation);", self.source)
        self.assertIn("ref ProcessInformation processInformation", self.source)
        cleanup = self.source.index("internal bool Cleanup()")
        self.assertIn("if (process != IntPtr.Zero)", self.source[cleanup:])
        self.assertIn("SafeCloseHandle(ref process, complete)", self.source[cleanup:])
        self.assertIn("SafeCloseHandle(ref thread, complete)", self.source[cleanup:])

    def test_refusal_output_is_bounded_and_cleanup_failures_refuse(self):
        success = (
            "windows-native-preflight=observed appcontainer=lpac token=verified capabilities=empty "
            "integrity=low job=assigned limits=verified termination=verified cng=p256-user "
            "nonexportable=verified acl=verified destruction=verified cleanup=verified"
        )
        self.assertIn(success, self.source)
        self.assertIn('"windows-native-preflight=refused check=" + check + errorField + " reason=native_preflight_unavailable cleanup="', self.source)
        self.assertIn('" win32_createprocess_error=" + win32CreateProcessError.Value.ToString(CultureInfo.InvariantCulture)', self.source)
        self.assertIn(
            'win32CreateProcessError.HasValue\n                ? " win32_createprocess_error=" + win32CreateProcessError.Value.ToString(CultureInfo.InvariantCulture)',
            self.source,
        )
        self.assertIn("if (!cleanupComplete)", self.source)
        self.assertIn("catch\n            {\n                cleanupComplete = false;", self.source)
        self.assertNotIn("exception.Message", self.source)
        self.assertNotIn("Exception.ToString", self.source)
        allowed_checks = (
            "lpac_profile",
            "job_setup",
            "child_attribute_list",
            "child_security_capabilities",
            "child_lpac_policy",
            "child_system_executable",
            "child_process_create_other",
            "child_job_assignment",
            "child_job_readback",
            "token_readback",
            "job_readback",
            "cng_key",
            "cng_acl",
            "cng_export",
            "cleanup",
            "runtime",
        )
        self.assertRegex(
            self.wrapper,
            re.compile(
                r"\^windows-native-preflight=refused check=\("
                + r"\|".join(allowed_checks)
                + r"\)"
            ),
        )
        self.assertIn("$createProcessFailurePrefix = 'windows-native-preflight=refused check=child_process_create win32_createprocess_error='", self.wrapper)
        self.assertIn("$result.Length -le 256", self.wrapper)
        self.assertIn("[UInt64]::TryParse(", self.wrapper)
        self.assertIn("[System.Globalization.NumberStyles]::None", self.wrapper)
        self.assertIn("[System.Globalization.CultureInfo]::InvariantCulture", self.wrapper)
        self.assertIn("$errorValue -le [UInt32]::MaxValue", self.wrapper)
        self.assertIn("cleanup=verified\\z'", self.wrapper)
        self.assertIn("cleanup=(verified|incomplete)\\z'", self.wrapper)
        self.assertIn("check=child_process_create_other reason=native_preflight_unavailable cleanup=", self.wrapper)
        self.assertLess(
            self.wrapper.index("$errorValue -le [UInt32]::MaxValue"),
            self.wrapper.index("Write-Output $result", self.wrapper.index("$createProcessFailurePrefix")),
        )
        self.assertIn("if ($phase -eq 'native') { $cleanup = 'incomplete' }", self.wrapper)
        self.assertNotIn("$_.Exception", self.wrapper)

    def test_child_launch_failures_use_fixed_allowlisted_subphases(self):
        stages = (
            ("child_attribute_list", "Native.InitializeProcThreadAttributeList"),
            ("child_security_capabilities", "Native.UpdateProcThreadAttribute(attributeList, 0, ProcThreadAttributeSecurityCapabilities"),
            ("child_lpac_policy", "Native.UpdateProcThreadAttribute(attributeList, 0, ProcThreadAttributeAllApplicationPackagesPolicy"),
            ("child_system_executable", "Native.GetSystemDirectoryW"),
            ("child_process_create", "Native.CreateProcessW(executable, commandLine"),
            ("child_job_assignment", "Native.AssignProcessToJobObject(job, process)"),
            ("child_job_readback", "Native.IsProcessInJob(process, job, out inJob)"),
        )
        create_child = self.source[
            self.source.index("internal void CreateSuspendedChild()"):
            self.source.index("internal void VerifyToken()")
        ]
        previous = -1
        for label, operation in stages:
            with self.subTest(label=label):
                marker = f'childLaunchCheck = "{label}";'
                self.assertIn(marker, create_child)
                self.assertIn(label, self.wrapper)
                stage_position = create_child.index(marker)
                operation_position = create_child.index(operation)
                self.assertGreater(stage_position, previous)
                self.assertLess(stage_position, operation_position)
                previous = stage_position
        self.assertIn('if (check == "child_launch")', self.source)
        self.assertIn("check = state.ChildLaunchCheck;", self.source)
        self.assertNotIn("Exception.Message", self.source)
        refusal = self.source[
            self.source.index("private static string Refusal("):
            self.source.index("private sealed class State")
        ]
        self.assertNotIn("GetLastWin32Error", refusal)
        self.assertNotIn("Exception", refusal)

    def test_createprocess_failure_captures_only_the_unsigned_win32_error(self):
        create_child = self.source[
            self.source.index("internal void CreateSuspendedChild()"):
            self.source.index("internal void VerifyToken()")
        ]
        create_call = create_child.index("bool created = Native.CreateProcessW(")
        error_capture = create_child.index("createProcessError = unchecked((uint)Marshal.GetLastWin32Error());", create_call)
        process_capture = create_child.index("process = processInformation.Process;", create_call)
        thread_capture = create_child.index("thread = processInformation.Thread;", create_call)
        failure_branch = create_child.index(
            "if (!created)\n                {\n                    childProcessCreateError = createProcessError;",
            process_capture,
        )
        self.assertLess(create_call, error_capture)
        self.assertLess(error_capture, process_capture)
        self.assertLess(process_capture, thread_capture)
        self.assertLess(thread_capture, failure_branch)
        self.assertIn("uint? createProcessError = null;", create_child)
        self.assertIn("childProcessCreateError = createProcessError;", create_child)
        self.assertIn("private uint? childProcessCreateError;", self.source)
        self.assertIn("internal uint? ChildProcessCreateError", self.source)
        self.assertIn('check = "child_process_create_other";', self.source)
        self.assertNotIn("ChildProcessFailureCheck", self.source)
        self.assertNotIn("FormatMessage", self.source)
        self.assertRegex(
            self.source,
            re.compile(
                r'\[DllImport\("kernel32\.dll", CharSet = CharSet\.Unicode, SetLastError = true\)\]\s+'
                r'\[return: MarshalAs\(UnmanagedType\.Bool\)\]\s+'
                r'internal static extern bool CreateProcessW\('
            ),
        )
        self.assertNotIn("createProcessError +", self.source)

    def test_createprocess_output_schema_accepts_only_canonical_uint32_values(self):
        schema_match = re.search(
            r"\$createProcessFailurePattern = '([^']+)'",
            self.wrapper,
        )
        self.assertIsNotNone(schema_match)
        schema = re.compile(schema_match.group(1).replace(r"\z", r"\Z"))
        prefix = "windows-native-preflight=refused check=child_process_create win32_createprocess_error="
        suffix = " reason=native_preflight_unavailable cleanup=verified"

        for text, expected in (
            ("0", True),
            ("1", True),
            ("4294967295", True),
            ("4294967296", False),
            ("18446744073709551616", False),
            ("00", False),
            ("-1", False),
            ("+1", False),
            (" 1", False),
            ("١", False),
            ("1 extra", False),
        ):
            with self.subTest(text=text):
                line = prefix + text + suffix
                match = schema.fullmatch(line)
                canonical = text == "0" or re.fullmatch(r"[1-9][0-9]*", text) is not None
                accepted = (
                    len(line) <= 256
                    and match is not None
                    and canonical
                    and int(text) <= 4294967295
                )
                self.assertEqual(accepted, expected)

    def test_powershell_wrapper_applies_the_numeric_schema_to_refusal_lines(self):
        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable for wrapper parser fixtures")
        parser_start = self.wrapper.index("    $createProcessFailurePrefix =")
        parser_end = self.wrapper.index("    if ($result -match '^windows-native-preflight=refused check=", parser_start)
        parser = self.wrapper[parser_start:parser_end]
        prefix = "windows-native-preflight=refused check=child_process_create win32_createprocess_error="
        suffix = " reason=native_preflight_unavailable cleanup=verified"
        fallback_incomplete = "windows-native-preflight=refused check=child_process_create_other reason=native_preflight_unavailable cleanup=incomplete"
        for value, ending, expected in (
            ("0", "", prefix + "0" + suffix),
            ("4294967295", "", prefix + "4294967295" + suffix),
            ("4294967296", "", "windows-native-preflight=refused check=child_process_create_other reason=native_preflight_unavailable cleanup=verified"),
            ("00", "", "windows-native-preflight=refused check=child_process_create_other reason=native_preflight_unavailable cleanup=verified"),
            ("-1", "", fallback_incomplete),
            ("١", "", fallback_incomplete),
            ("9" * 300, "", fallback_incomplete),
            ("7", "\n", fallback_incomplete),
            ("7", "\r\n", fallback_incomplete),
        ):
            line = prefix + value + suffix + ending
            encoded = base64.b64encode(line.encode("utf-8")).decode("ascii")
            command = (
                "$result = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('"
                + encoded
                + "'))\n"
                + parser
            )
            with self.subTest(value=value[:24], ending=repr(ending)):
                completed = subprocess.run(
                    [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                    check=False,
                    capture_output=True,
                    text=False,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, expected.encode("utf-8") + os.linesep.encode("ascii"))
                self.assertEqual(completed.stderr, b"")

    def test_powershell_fixed_refusal_allowlist_rejects_trailing_newlines(self):
        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable for wrapper parser fixtures")
        parser_start = self.wrapper.index("    if ($result -match '^windows-native-preflight=refused check=(")
        parser_end = self.wrapper.index("} catch {", parser_start)
        parser = self.wrapper[parser_start:parser_end]
        fixed_line = "windows-native-preflight=refused check=lpac_profile reason=native_preflight_unavailable cleanup=verified"
        generic_fallback = "windows-native-preflight=refused check=runtime reason=native_preflight_unavailable cleanup=incomplete"
        for ending, expected in (
            ("", fixed_line),
            ("\n", generic_fallback),
            ("\r\n", generic_fallback),
        ):
            line = fixed_line + ending
            encoded = base64.b64encode(line.encode("utf-8")).decode("ascii")
            command = (
                "$result = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('"
                + encoded
                + "'))\n"
                + parser
            )
            with self.subTest(ending=repr(ending)):
                completed = subprocess.run(
                    [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                    check=False,
                    capture_output=True,
                    text=False,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, expected.encode("utf-8") + os.linesep.encode("ascii"))
                self.assertEqual(completed.stderr, b"")


if __name__ == "__main__":
    unittest.main()
