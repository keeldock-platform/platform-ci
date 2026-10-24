import re
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
        failure_check = self.source.index("if (!created || !processCreated || thread == IntPtr.Zero)", create_call)
        self.assertLess(create_call, process_capture)
        self.assertLess(process_capture, thread_capture)
        self.assertLess(thread_capture, failure_check)
        self.assertIn("Native.ProcessInformation processInformation = new Native.ProcessInformation();", self.source)
        self.assertIn("ref startup, ref processInformation);", self.source)
        self.assertIn("ref ProcessInformation processInformation", self.source)
        cleanup = self.source.index("internal bool Cleanup()")
        self.assertIn("if (process != IntPtr.Zero)", self.source[cleanup:])
        self.assertIn("SafeCloseHandle(ref process, complete)", self.source[cleanup:])
        self.assertIn("SafeCloseHandle(ref thread, complete)", self.source[cleanup:])

    def test_only_fixed_status_lines_are_emitted_and_cleanup_failures_refuse(self):
        success = (
            "windows-native-preflight=observed appcontainer=lpac token=verified capabilities=empty "
            "integrity=low job=assigned limits=verified termination=verified cng=p256-user "
            "nonexportable=verified acl=verified destruction=verified cleanup=verified"
        )
        self.assertIn(success, self.source)
        self.assertIn('"windows-native-preflight=refused check=" + check + " reason=native_preflight_unavailable cleanup="', self.source)
        self.assertIn("if (!cleanupComplete)", self.source)
        self.assertIn("catch\n            {\n                cleanupComplete = false;", self.source)
        self.assertNotIn("exception.Message", self.source)
        self.assertNotIn("Exception.ToString", self.source)
        self.assertRegex(
            self.wrapper,
            re.compile(
                r"\^windows-native-preflight=refused check=\(lpac_profile\|job_setup\|child_launch\|token_readback\|job_readback\|cng_key\|cng_acl\|cng_export\|cleanup\|runtime\)"
            ),
        )
        self.assertIn("if ($phase -eq 'native') { $cleanup = 'incomplete' }", self.wrapper)
        self.assertNotIn("$_.Exception", self.wrapper)


if __name__ == "__main__":
    unittest.main()
