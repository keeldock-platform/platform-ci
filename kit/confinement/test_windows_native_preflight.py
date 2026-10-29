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

    def test_child_environment_block_is_profile_scoped_sorted_and_bounded(self):
        for required in (
            '"LOCALAPPDATA=" + localAppDataPath',
            '"TEMP=" + tempPath',
            '"TMP=" + tempPath',
            '"KD_NATIVE_PREFLIGHT=1"',
            '"=" + char.ToUpperInvariant(currentDirectory[0]) + ":=" + currentDirectory',
            'Array.Sort(entries, StringComparer.OrdinalIgnoreCase)',
            'string.Join("\\0", entries) + "\\0\\0"',
            "MaxChildEnvironmentEntryCharacters",
            "MaxChildEnvironmentBlockCharacters",
            "GetAppContainerFolderPath",
            "ConvertSidToStringSidW",
            "Marshal.FreeCoTaskMem(memory)",
            "Native.LocalFree(memory)",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.source)
        for forbidden in (
            "Environment.GetEnvironmentVariable",
            "GetEnvironmentStrings",
            "CreateEnvironmentBlock",
            "$env:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.source)

        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable for environment-block fixtures")
        encoded_source_path = base64.b64encode(str(HARNESS).encode("utf-8")).decode("ascii")
        command = f"""
$sourcePath = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded_source_path}'))
Add-Type -Path $sourcePath -ErrorAction Stop
$flags = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
$method = [KeelDock.Platform.WindowsNativePreflight.Probe].GetMethod('BuildChildEnvironmentBlock', $flags)
if ($null -eq $method) {{ exit 2 }}
$local = 'C:\\Users\\Fixture\\AppData\\Local\\Packages\\KDN123\\AC'
$current = 'C:\\Windows\\System32'
$block = [string]$method.Invoke($null, [object[]]@($local, $current))
$expectedEntries = [string[]]@(
    '=C:=C:\\Windows\\System32',
    'KD_NATIVE_PREFLIGHT=1',
    'LOCALAPPDATA=C:\\Users\\Fixture\\AppData\\Local\\Packages\\KDN123\\AC',
    'TEMP=C:\\Users\\Fixture\\AppData\\Local\\Packages\\KDN123\\AC\\Temp',
    'TMP=C:\\Users\\Fixture\\AppData\\Local\\Packages\\KDN123\\AC\\Temp'
)
$expected = [string]::Join([char]0, $expectedEntries) + [char]0 + [char]0
if (-not [string]::Equals($block, $expected, [System.StringComparison]::Ordinal)) {{ exit 3 }}
if ($block.Length -gt 131072 -or $block[$block.Length - 1] -ne [char]0 -or $block[$block.Length - 2] -ne [char]0) {{ exit 4 }}
$newlinePath = [string]::Concat('C:\\Users\\Fixture', [char]10, '\\AC')
$rejected = $false
try {{ [void]$method.Invoke($null, [object[]]@($newlinePath, $current)) }} catch {{ $rejected = $true }}
if (-not $rejected) {{ exit 5 }}
$longPath = 'C:\\' + ('x' * 32760)
$rejected = $false
try {{ [void]$method.Invoke($null, [object[]]@($longPath, $current)) }} catch {{ $rejected = $true }}
if (-not $rejected) {{ exit 6 }}
"""
        completed = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=False,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(completed.stdout, b"")

    def test_actual_token_properties_are_read_before_acceptance(self):
        for expected in (
            "private const int TokenIntegrityLevel = 25;",
            "private const int TokenIsAppContainer = 29;",
            "private const int TokenCapabilities = 30;",
            "private const int TokenAppContainerSid = 31;",
            "uint isAppContainer = ReadTokenDword(childToken, TokenIsAppContainer);",
            "if (isAppContainer != 1)",
            "childLpacPolicyConfigured = true;",
            "if (!childLpacPolicyConfigured || !processCreated || process == IntPtr.Zero)",
            "if (length != 4)",
            "Marshal.ReadInt32(capabilityInformation) != 0",
            "Native.EqualSid(actualSid, profileSid)",
            "0x00001000",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.source)
        self.assertNotIn("TokenIsLessPrivilegedAppContainer", self.source)
        self.assertIn("TokenCapabilities", self.source)
        self.assertIn("TokenAppContainerSid", self.source)

    def test_token_readback_failures_use_fixed_ordered_subphases(self):
        stages = (
            ("token_open", "Native.OpenProcessToken(process, TokenQuery"),
            ("token_appcontainer_read", "ReadTokenDword(childToken, TokenIsAppContainer)"),
            ("token_appcontainer_check", "if (isAppContainer != 1)"),
            ("token_lpac_check", "if (!childLpacPolicyConfigured || !processCreated || process == IntPtr.Zero)"),
            ("token_capabilities_read", "QueryTokenInformation(childToken, TokenCapabilities"),
            ("token_capabilities_check", "capabilityLength < 4 || Marshal.ReadInt32(capabilityInformation) != 0"),
            ("token_sid_read", "QueryTokenInformation(childToken, TokenAppContainerSid"),
            ("token_sid_check", "appContainerLength < (uint)IntPtr.Size"),
            ("token_integrity_read", "QueryTokenInformation(childToken, TokenIntegrityLevel"),
            ("token_integrity_check", "integrityLength < (uint)IntPtr.Size"),
        )
        verify = self.source[
            self.source.index("internal void VerifyToken()"):
            self.source.index("internal void VerifyJob()")
        ]
        previous = -1
        for label, operation in stages:
            with self.subTest(label=label):
                marker = f'tokenReadbackCheck = "{label}";'
                self.assertIn(marker, verify)
                self.assertIn(label, self.wrapper)
                phase_position = verify.index(marker)
                operation_position = verify.index(operation)
                self.assertGreater(phase_position, previous)
                self.assertLess(phase_position, operation_position)
                previous = phase_position

        catch_transition = 'else if (check == "token_readback")\n                {\n                    check = state.TokenReadbackCheck;'
        self.assertIn(catch_transition, self.source)
        self.assertIn('private string tokenReadbackCheck = "token_open";', self.source)
        self.assertIn("internal string TokenReadbackCheck", self.source)
        self.assertNotIn("Marshal.GetLastWin32Error", verify)
        self.assertNotIn("GetTokenInformation", verify)
        self.assertNotIn("Console.", verify)
        self.assertNotIn("ToString(", verify)
        self.assertEqual(
            re.findall(r'tokenReadbackCheck = "([a-z_]+)";', verify),
            [label for label, _ in stages],
        )

    def test_lpac_policy_is_applied_to_the_suspended_child_before_token_readback(self):
        launch = self.source[
            self.source.index("internal void CreateSuspendedChild()"):
            self.source.index("internal void VerifyToken()")
        ]
        policy_update = launch.index("Native.UpdateProcThreadAttribute(attributeList, 0, ProcThreadAttributeAllApplicationPackagesPolicy")
        policy_confirmed = launch.index("childLpacPolicyConfigured = true;", policy_update)
        startup = launch.index("startup.AttributeList = attributeList;", policy_confirmed)
        create = launch.index("Native.CreateProcessW(executable, commandLine", startup)
        created = launch.index("processCreated = process != IntPtr.Zero;", create)
        self.assertLess(policy_update, policy_confirmed)
        self.assertLess(policy_confirmed, startup)
        self.assertLess(startup, create)
        self.assertLess(create, created)
        self.assertIn("CreateSuspended", launch)
        self.assertIn("ExtendedStartupInfoPresent", launch)
        self.assertIn("ProcessCreationAllApplicationPackagesOptOut", launch)
        self.assertIn("if (!childLpacPolicyConfigured || !processCreated || process == IntPtr.Zero)", self.source)
        self.assertNotIn("ResumeThread", self.source)

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
            "NCryptPersistFlag = 0x80000000",
            "NCryptSilentFlag = 0x00000040",
            "Native.InitializeSecurityDescriptor",
            "Native.SetSecurityDescriptorOwner",
            "Native.InitializeAcl",
            "Native.AddAce",
            "Native.SetSecurityDescriptorDacl",
            "Native.GetSecurityDescriptorOwner",
            "Native.GetSecurityDescriptorDacl",
            'Native.NCryptSetProperty(\n                        key,\n                        "Export Policy",\n                        exportPolicy,\n                        4,\n                        NCryptPersistFlag | NCryptSilentFlag)',
            'ReadCngDword(verificationKey, "Export Policy", NCryptSilentFlag)',
            "Native.NCryptDeleteKey(key, NCryptSilentFlag)",
            "Native.NCryptOpenKey(provider, out reopened, keyName, 0, NCryptSilentFlag)",
            "status == NteBadKeyset",
            "Native.DeleteAppContainerProfile(profileName)",
            "Native.FreeSid(profileSid)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.source)
        self.assertIn("RequireExportPolicySet(status);", self.source)
        self.assertIn("RequireZeroExportPolicy(exportPolicy);", self.source)
        self.assertIn("ValidateDwordRead(status, returned, buffer)", self.source)
        self.assertNotIn("NCryptExportKey", self.source)
        self.assertNotIn("ECCPRIVATEBLOB", self.source)
        self.assertNotIn("nonexportable=verified", self.source)
        self.assertIn("OwnerSecurityInformation | NCryptSilentFlag", self.source)
        self.assertIn("Native.EqualSid(ownerSid, currentUserSid)", self.source)

    def test_export_policy_is_persisted_before_finalize_and_read_back_from_reopened_key(self):
        run = self.source[
            self.source.index("public static string Run()"):self.source.index("private static string Refusal(")
        ]
        calls = (
            "state.CreateKey();",
            "state.SetKeyExportPolicy();",
            "state.SetKeyOwnerToCurrentUser();",
            "state.FinalizeKey();",
            "state.TightenKeyDacl();",
            "state.VerifyKeyAcl();",
            "state.VerifyPersistedKeyExportPolicy();",
        )
        positions = [run.index(call) for call in calls]
        self.assertEqual(positions, sorted(positions))

        setter = self.source[
            self.source.index("internal void SetKeyExportPolicy()"):
            self.source.index("internal void SetKeyOwnerToCurrentUser()")
        ]
        self.assertLess(setter.index('cngExportCheck = "cng_export_policy_set";'), setter.index("NCryptSetProperty("))
        self.assertLess(setter.index("Marshal.WriteInt32(exportPolicy, 0)"), setter.index("NCryptSetProperty("))
        self.assertIn("NCryptPersistFlag | NCryptSilentFlag", setter)
        self.assertIn("RequireExportPolicySet(status);", setter)
        self.assertNotIn("ReadKeyDword(\"Export Policy\"", self.source)

        verify = self.source[
            self.source.index("internal void VerifyPersistedKeyExportPolicy()"):
            self.source.index("internal bool Cleanup()")
        ]
        self.assertLess(
            verify.index('cngExportCheck = "cng_export_policy_read";'),
            verify.index('ReadCngDword(verificationKey, "Export Policy", NCryptSilentFlag)'),
        )
        self.assertLess(verify.index('cngExportCheck = "cng_export_policy_nonzero";'), verify.index("RequireZeroExportPolicy(exportPolicy);"))
        self.assertIn('else if (check == "cng_export")\n                {\n                    check = state.CngExportCheck;', self.source)
        self.assertIn('private string cngExportCheck = "cng_export_policy_set";', self.source)
        self.assertNotIn("NCryptExportKey", self.source)
        self.assertNotIn("ClassifyExportStatus", self.source)
        self.assertNotIn("ECCPRIVATEBLOB", self.source)

    def test_export_policy_and_exact_dword_helpers_fail_closed(self):
        self.assertIn("internal static void RequireExportPolicySet(int status)", self.source)
        self.assertIn("if (status != 0)\n            {\n                throw new InvalidOperationException();", self.source)
        self.assertIn("internal static void RequireZeroExportPolicy(uint exportPolicy)", self.source)
        self.assertIn("if (exportPolicy != 0)", self.source)
        self.assertIn("internal static uint ValidateDwordRead(int status, uint returned, IntPtr buffer)", self.source)
        self.assertIn("status != 0 || returned != 4 || buffer == IntPtr.Zero", self.source)

        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable for native policy helper fixtures")
        encoded_source_path = base64.b64encode(str(HARNESS).encode("utf-8")).decode("ascii")
        command = f"""
$sourcePath = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded_source_path}'))
Add-Type -Path $sourcePath -ErrorAction Stop
$type = [KeelDock.Platform.WindowsNativePreflight.Probe]
$flags = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
$setMethod = $type.GetMethod('RequireExportPolicySet', $flags)
$zeroMethod = $type.GetMethod('RequireZeroExportPolicy', $flags)
$readMethod = $type.GetMethod('ValidateDwordRead', $flags)
if ($null -eq $setMethod -or $null -eq $zeroMethod -or $null -eq $readMethod) {{ exit 2 }}
$setMethod.Invoke($null, [object[]]@([int]0)) | Out-Null
foreach ($status in @([int]1, [int]-1, [int]-2146893785)) {{
    $rejected = $false
    try {{ $setMethod.Invoke($null, [object[]]@($status)) | Out-Null }} catch {{ $rejected = $true }}
    if (-not $rejected) {{ exit 3 }}
}}
$zeroMethod.Invoke($null, [object[]]@([uint32]0)) | Out-Null
foreach ($policy in @([uint32]1, [uint32]8, [uint32]4294967295)) {{
    $rejected = $false
    try {{ $zeroMethod.Invoke($null, [object[]]@($policy)) | Out-Null }} catch {{ $rejected = $true }}
    if (-not $rejected) {{ exit 4 }}
}}
$buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
try {{
    [System.Runtime.InteropServices.Marshal]::WriteInt32($buffer, [int]0)
    $value = [uint32]$readMethod.Invoke($null, [object[]]@([int]0, [uint32]4, $buffer))
    if ($value -ne [uint32]0) {{ exit 5 }}
    [System.Runtime.InteropServices.Marshal]::WriteInt32($buffer, [int]-2147483648)
    $value = [uint32]$readMethod.Invoke($null, [object[]]@([int]0, [uint32]4, $buffer))
    if ($value -ne [uint32]2147483648) {{ exit 6 }}
    $badReads = @(
        [object[]]@([int]1, [uint32]4, $buffer),
        [object[]]@([int]0, [uint32]0, [IntPtr]::Zero),
        [object[]]@([int]0, [uint32]3, [IntPtr]::Zero),
        [object[]]@([int]0, [uint32]5, [IntPtr]::Zero),
        [object[]]@([int]0, [uint32]4294967295, [IntPtr]::Zero),
        [object[]]@([int]0, [uint32]4, [IntPtr]::Zero)
    )
    foreach ($args in $badReads) {{
        $rejected = $false
        try {{ $readMethod.Invoke($null, $args) | Out-Null }} catch {{ $rejected = $true }}
        if (-not $rejected) {{ exit 7 }}
    }}
}} finally {{
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
}}
"""
        completed = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=False,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(completed.stdout, b"")

    def test_cng_key_owner_is_set_from_token_user_before_finalize_and_readback(self):
        run = self.source[self.source.index("public static string Run()"):self.source.index("private static string Refusal(")]
        calls = (
            "state.CreateKey();",
            "state.SetKeyOwnerToCurrentUser();",
            "state.FinalizeKey();",
            "state.TightenKeyDacl();",
            "state.VerifyKeyAcl();",
        )
        positions = [run.index(call) for call in calls]
        self.assertEqual(positions, sorted(positions))

        set_owner = self.source[
            self.source.index("internal void SetKeyOwnerToCurrentUser()"):
            self.source.index("internal void FinalizeKey()")
        ]
        stages = (
            ("cng_acl_support_read", 'ReadProviderDword("Security Descr Support")'),
            ("cng_acl_token_open", "Native.OpenProcessToken(Native.GetCurrentProcess()"),
            ("cng_acl_user_read", "QueryTokenInformation(currentToken, TokenUser"),
            ("cng_acl_user_check", "if (userLength < (uint)IntPtr.Size)"),
            ("cng_acl_owner_set", '"Security Descr",'),
        )
        previous = -1
        for label, operation in stages:
            marker = f'cngAclCheck = "{label}";'
            self.assertIn(marker, set_owner)
            self.assertIn(label, self.wrapper)
            phase_position = set_owner.index(marker)
            operation_position = set_owner.index(operation)
            self.assertGreater(phase_position, previous)
            self.assertLess(phase_position, operation_position)
            previous = phase_position
        self.assertIn("Native.InitializeSecurityDescriptor(descriptor, SecurityDescriptorRevision)", set_owner)
        self.assertIn("Native.IsValidSecurityDescriptor(descriptor)", set_owner)
        self.assertIn("OwnerSecurityInformation | NCryptSilentFlag", set_owner)
        self.assertNotIn("DaclSecurityInformation", set_owner)
        self.assertIn("keyOwned = true;", self.source[:self.source.index("internal void SetKeyOwnerToCurrentUser()")])
        verify = self.source[
            self.source.index("internal void VerifyKeyAcl()"):
            self.source.index("internal void VerifyPersistedKeyExportPolicy()")
        ]
        self.assertIn("Native.EqualSid(ownerSid, currentUserSid)", verify)
        self.assertIn('cngAclCheck = "cng_acl_dacl_read";', verify)
        self.assertIn("ReadSecurityDescriptor(verificationKey, DaclSecurityInformation | NCryptSilentFlag)", verify)

    def test_disposable_key_dacl_is_filtered_and_verified_after_finalize(self):
        run = self.source[self.source.index("public static string Run()"):self.source.index("private static string Refusal(")]
        calls = (
            "state.FinalizeKey();",
            "state.TightenKeyDacl();",
            "state.VerifyKeyAcl();",
            "state.VerifyPersistedKeyExportPolicy();",
        )
        positions = [run.index(call) for call in calls]
        self.assertEqual(positions, sorted(positions))
        tighten = self.source[
            self.source.index("internal void TightenKeyDacl()"):
            self.source.index("internal void VerifyKeyAcl()")
        ]
        stages = (
            ("cng_acl_dacl_tighten_user_read", "QueryTokenInformation(currentToken, TokenUser"),
            ("cng_acl_dacl_tighten_user_check", "if (userLength < (uint)IntPtr.Size)"),
            ("cng_acl_dacl_tighten_system_sid", 'Native.ConvertStringSidToSidW("S-1-5-18"'),
            ("cng_acl_dacl_tighten_owner_rights", "Native.CreateWellKnownSid(WinCreatorOwnerRightsSid"),
            ("cng_acl_dacl_tighten_source_read", "ReadSecurityDescriptor(key, DaclSecurityInformation"),
            ("cng_acl_dacl_tighten_source_check", "Native.GetSecurityDescriptorDacl(sourceDescriptor"),
            ("cng_acl_dacl_tighten_source_count", "Native.GetAclInformation(sourceDacl"),
            ("cng_acl_dacl_tighten_build", "Native.InitializeAcl(targetDacl"),
            ("cng_acl_dacl_tighten_source_ace", "Native.GetAce(sourceDacl, index"),
            ("cng_acl_dacl_tighten_source_shape", "if ((type != AccessAllowedAceType"),
            ("cng_acl_dacl_tighten_inherited", "if (IsInheritedDaclAce(aceFlags))"),
            ("cng_acl_dacl_tighten_source_sid", "if (!Native.IsValidSid(aceSid))"),
            ("cng_acl_dacl_tighten_user_allow", "if (!currentUserAllowed || expectedAceCount == 0)"),
            ("cng_acl_dacl_tighten_descriptor", "Native.SetSecurityDescriptorDacl(setDescriptor, true, targetDacl, false)"),
            ("cng_acl_dacl_tighten_apply", "Native.NCryptSetProperty("),
            ("cng_acl_dacl_tighten_reopen", "Native.NCryptOpenKey(provider, out verificationKey, keyName"),
            ("cng_acl_dacl_tighten_readback", "readbackDescriptor = ReadSecurityDescriptor(verificationKey, DaclSecurityInformation"),
            ("cng_acl_dacl_tighten_compare", "Native.GetAclInformation(readbackDacl"),
        )
        previous = -1
        for label, operation in stages:
            with self.subTest(label=label):
                marker = f'cngAclCheck = "{label}";'
                self.assertIn(marker, tighten)
                self.assertIn(label, self.wrapper)
                phase_position = tighten.index(marker)
                operation_position = tighten.index(operation)
                self.assertGreater(phase_position, previous)
                self.assertLess(phase_position, operation_position)
                previous = phase_position

        self.assertIn("private const byte InheritedAceFlag = 0x10;", self.source)
        self.assertIn("private const byte InheritOnlyAceFlag = 0x08;", self.source)
        self.assertIn("private const byte UnsupportedDaclAceFlags = 0xe0;", self.source)
        self.assertIn("if ((type != AccessAllowedAceType && type != AccessDeniedAceType)", tighten)
        self.assertIn("!IsSupportedDaclAceFlags(aceFlags)", tighten)
        self.assertIn("sourceAclSize - sourceInformation.AclBytesInUse != sourceInformation.AclBytesFree", tighten)
        self.assertIn("readbackAclSize - readbackInformation.AclBytesInUse != readbackInformation.AclBytesFree", tighten)
        self.assertIn("aceSize < 16 || (aceSize & 3)", tighten)
        self.assertIn("bool retainAce = ShouldRetainDaclAce(type, isUser, isSystem, isOwnerRights);", tighten)
        self.assertIn("isUser = Native.EqualSid(aceSid, currentUserSid);", tighten)
        self.assertIn("isSystem = Native.EqualSid(aceSid, systemSid);", tighten)
        self.assertIn("isOwnerRights = Native.EqualSid(aceSid, ownerRightsSid);", tighten)
        self.assertIn("type == AccessAllowedAceType && isUser && (aceFlags & InheritOnlyAceFlag) == 0", tighten)
        policy = self.source[
            self.source.index("internal static bool ShouldRetainDaclAce("):
            self.source.index("internal void VerifyKeyAcl()")
        ]
        self.assertIn("if (type == AccessDeniedAceType)", policy)
        self.assertIn("if (type != AccessAllowedAceType || isOwnerRights)", policy)
        self.assertIn("return isUser || isSystem;", policy)
        self.assertIn("Native.AddAce(targetDacl, aclRevision, uint.MaxValue, ace, aceSize)", tighten)
        self.assertIn("Marshal.Copy(ace, expectedAceBytes", tighten)
        self.assertIn("DaclSecurityInformation | NCryptSilentFlag", tighten)
        self.assertIn("Marshal.ReadByte(ace, checked((int)byteIndex)) != expectedAceBytes", tighten)
        self.assertNotIn("ToString(", tighten)
        self.assertNotIn("Console.", tighten)
        self.assertNotIn("Environment.GetEnvironmentVariable", tighten)

        loop_start = tighten.index("for (uint index = 0; index < sourceInformation.AceCount; index++)")
        owner_rights_check = tighten.index("Native.EqualSid(aceSid, ownerRightsSid)", loop_start)
        retain_policy_check = tighten.index("ShouldRetainDaclAce(type, isUser, isSystem, isOwnerRights)", loop_start)
        loop_end = tighten.index("sourceBytesRead += aceSize;", loop_start)
        apply_call = tighten.index("Native.NCryptSetProperty(")
        self.assertLess(loop_start, owner_rights_check)
        self.assertLess(owner_rights_check, apply_call)
        self.assertLess(retain_policy_check, loop_end)
        self.assertNotIn("break;", tighten[loop_start:loop_end])
        self.assertNotIn("continue;", tighten[loop_start:loop_end])
        self.assertNotIn("return;", tighten[loop_start:loop_end])
        self.assertLess(tighten.index("bool retainAce = ShouldRetainDaclAce("), apply_call)
        self.assertLess(loop_end, apply_call)
        self.assertIn("if (IsInheritedDaclAce(aceFlags))", tighten)
        self.assertLess(tighten.index("if (IsInheritedDaclAce(aceFlags))"), apply_call)
        self.assertIn("finally", tighten)
        self.assertIn("Marshal.FreeHGlobal(targetDacl);", tighten)
        self.assertIn("internal static bool IsInheritedDaclAce(byte flags)", self.source)
        self.assertIn("internal static bool IsSupportedDaclAceFlags(byte flags)", self.source)
        self.assertIn("ReadSecurityDescriptor(verificationKey, OwnerSecurityInformation", self.source)
        self.assertIn("ReadSecurityDescriptor(verificationKey, DaclSecurityInformation", self.source)
        self.assertLess(
            self.source.index("complete = SafeFreeCngObject(ref verificationKey, complete);"),
            self.source.index("int deleteStatus = Native.NCryptDeleteKey(key, NCryptSilentFlag)"),
        )
        self.assertIn("if (!cleanupComplete)", self.source)

    def test_dacl_policy_drops_other_allow_then_refuses_later_owner_rights(self):
        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable for managed DACL policy fixtures")
        encoded_source_path = base64.b64encode(str(HARNESS).encode("utf-8")).decode("ascii")
        command = f"""
$sourcePath = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded_source_path}'))
Add-Type -Path $sourcePath -ErrorAction Stop
$typeFlags = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public
$state = [KeelDock.Platform.WindowsNativePreflight.Probe].GetNestedType('State', $typeFlags)
if ($null -eq $state) {{ exit 2 }}
$methodFlags = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
$method = $state.GetMethod('ShouldRetainDaclAce', $methodFlags)
if ($null -eq $method) {{ exit 2 }}
$firstAceRetained = [bool]$method.Invoke($null, [object[]]@([byte]0, $false, $false, $false))
if ($firstAceRetained) {{ exit 3 }}
try {{ [void]$method.Invoke($null, [object[]]@([byte]0, $false, $false, $true)); exit 4 }} catch {{ }}
$deniedAceRetained = [bool]$method.Invoke($null, [object[]]@([byte]1, $false, $false, $false))
if (-not $deniedAceRetained) {{ exit 5 }}
$userAceRetained = [bool]$method.Invoke($null, [object[]]@([byte]0, $true, $false, $false))
if (-not $userAceRetained) {{ exit 6 }}
$inheritedMethod = $state.GetMethod('IsInheritedDaclAce', $methodFlags)
if ($null -eq $inheritedMethod) {{ exit 7 }}
if (-not [bool]$inheritedMethod.Invoke($null, [object[]]@([byte]16))) {{ exit 8 }}
if ([bool]$inheritedMethod.Invoke($null, [object[]]@([byte]1))) {{ exit 9 }}
try {{ [void]$method.Invoke($null, [object[]]@([byte]2, $false, $false, $false)); exit 10 }} catch {{ }}
$flagsMethod = $state.GetMethod('IsSupportedDaclAceFlags', $methodFlags)
if ($null -eq $flagsMethod) {{ exit 11 }}
if (-not [bool]$flagsMethod.Invoke($null, [object[]]@([byte]15))) {{ exit 12 }}
if ([bool]$flagsMethod.Invoke($null, [object[]]@([byte]32))) {{ exit 13 }}
"""
        completed = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=False,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(completed.stdout, b"")

    def test_security_descriptor_absolute_abi_matches_native_pointer_layout(self):
        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable for native structure layout fixtures")
        encoded_source_path = base64.b64encode(str(HARNESS).encode("utf-8")).decode("ascii")
        command = f"""
$sourcePath = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded_source_path}'))
Add-Type -Path $sourcePath -ErrorAction Stop
$flags = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public
$native = [KeelDock.Platform.WindowsNativePreflight.Probe].GetNestedType('Native', $flags)
if ($null -eq $native) {{ exit 2 }}
$descriptor = $native.GetNestedType('SecurityDescriptor', $flags)
if ($null -eq $descriptor) {{ exit 3 }}
$pointerSize = [IntPtr]::Size
$expectedOwnerOffset = [int]([Math]::Ceiling(4.0 / $pointerSize) * $pointerSize)
$expectedSize = $expectedOwnerOffset + 4 * $pointerSize
$instance = [System.Activator]::CreateInstance($descriptor)
if ([System.Runtime.InteropServices.Marshal]::SizeOf($instance) -ne $expectedSize) {{ exit 4 }}
if ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$descriptor, 'Owner') -ne $expectedOwnerOffset) {{ exit 5 }}
if ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$descriptor, 'Group') -ne ($expectedOwnerOffset + $pointerSize)) {{ exit 6 }}
if ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$descriptor, 'Sacl') -ne ($expectedOwnerOffset + 2 * $pointerSize)) {{ exit 7 }}
if ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$descriptor, 'Dacl') -ne ($expectedOwnerOffset + 3 * $pointerSize)) {{ exit 8 }}
"""
        completed = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=False,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(completed.stdout, b"")

    def test_cng_acl_failures_use_fixed_ordered_subphases(self):
        stages = (
            ("cng_acl_user_read", "QueryTokenInformation(currentToken, TokenUser"),
            ("cng_acl_user_check", "if (userLength < (uint)IntPtr.Size)"),
            ("cng_acl_system_sid", 'Native.ConvertStringSidToSidW("S-1-5-18"'),
            ("cng_acl_owner_rights_sid", "Native.CreateWellKnownSid(WinCreatorOwnerRightsSid"),
            ("cng_acl_owner_read", "ReadSecurityDescriptor(verificationKey, OwnerSecurityInformation"),
            ("cng_acl_owner_extract", "Native.GetSecurityDescriptorOwner(ownerDescriptor"),
            ("cng_acl_owner_absent", "if (ownerSid == IntPtr.Zero)"),
            ("cng_acl_owner_validate", "if (!Native.IsValidSid(ownerSid))"),
            ("cng_acl_owner_user_match", "if (!Native.EqualSid(ownerSid, currentUserSid))"),
            ("cng_acl_owner_default_read", "QueryTokenInformation(currentToken, TokenOwner"),
            ("cng_acl_owner_default_validate", "if (ownerLength < (uint)IntPtr.Size)"),
            ("cng_acl_owner_default_compare", "bool ownerMatchesTokenDefault = Native.EqualSid(ownerSid, tokenOwnerSid)"),
            ("cng_acl_dacl_read", "ReadSecurityDescriptor(verificationKey, DaclSecurityInformation"),
            ("cng_acl_dacl_check", "Native.GetSecurityDescriptorDacl(daclDescriptor"),
            ("cng_acl_count_read", "Native.GetAclInformation(dacl"),
            ("cng_acl_ace_read", "Native.GetAce(dacl, index"),
            ("cng_acl_ace_shape", "if ((type != AccessAllowedAceType"),
            ("cng_acl_ace_sid", "Native.IsValidSid(aceSid)"),
            ("cng_acl_ace_policy", "bool isUser = Native.EqualSid(aceSid"),
            ("cng_acl_ace_owner_rights_check", "bool isOwnerRights = Native.EqualSid(aceSid, ownerRightsSid)"),
            ("cng_acl_user_allow_check", "if (!currentUserAllowed)"),
        )
        verify = self.source[
            self.source.index("internal void VerifyKeyAcl()"):
            self.source.index("internal void VerifyPersistedKeyExportPolicy()")
        ]
        previous = -1
        for label, operation in stages:
            with self.subTest(label=label):
                marker = f'cngAclCheck = "{label}";'
                self.assertIn(marker, verify)
                self.assertIn(label, self.wrapper)
                phase_position = verify.index(marker)
                operation_position = verify.index(operation)
                self.assertGreater(phase_position, previous)
                self.assertLess(phase_position, operation_position)
                previous = phase_position
        self.assertIn('private string cngAclCheck = "cng_acl_support_read";', self.source)
        self.assertIn("internal string CngAclCheck", self.source)
        assigned_labels = re.findall(r'cngAclCheck\s*=\s*"([a-z0-9_]+)";', verify)
        self.assertEqual(set(assigned_labels), {label for label, _ in stages})
        self.assertEqual(len(re.findall(r"cngAclCheck\s*=", verify)), len(assigned_labels) + 2)
        self.assertIn(
            'cngAclCheck = ownerMatchesTokenDefault ? "cng_acl_owner_matches_token_default" : "cng_acl_owner_matches_other";',
            verify,
        )
        self.assertIn('cngAclCheck = isOwnerRights ? "cng_acl_ace_owner_rights_allow" : "cng_acl_ace_other_allow";', verify)

    def test_owner_rights_allow_ace_is_distinguished_but_still_refused(self):
        verify = self.source[
            self.source.index("internal void VerifyKeyAcl()"):
            self.source.index("internal void VerifyPersistedKeyExportPolicy()")
        ]
        self.assertIn("private const int MaxSidSize = 68;", self.source)
        self.assertIn("private const int WinCreatorOwnerRightsSid = 71;", self.source)
        self.assertIn(
            "Native.CreateWellKnownSid(WinCreatorOwnerRightsSid, IntPtr.Zero, ownerRightsSid, ref ownerRightsSidLength)",
            verify,
        )
        self.assertIn("ownerRightsSidLength > MaxSidSize", verify)
        self.assertIn("Native.GetLengthSid(ownerRightsSid) != ownerRightsSidLength", verify)
        branch = verify[verify.index("if (!isUser && !isSystem)"):]
        classification = 'cngAclCheck = isOwnerRights ? "cng_acl_ace_owner_rights_allow" : "cng_acl_ace_other_allow";'
        self.assertLess(branch.index(classification), branch.index("throw new InvalidOperationException();"))
        self.assertLess(branch.index("throw new InvalidOperationException();"), branch.index("if (isUser)"))
        self.assertNotIn("currentUserAllowed = true", branch[:branch.index("throw new InvalidOperationException();")])
        self.assertIn("Marshal.FreeHGlobal(ownerRightsSid);", verify)
        self.assertNotIn("ConvertSidToStringSidW", verify)
        self.assertNotIn("ToString(", verify)
        self.assertRegex(
            self.source,
            re.compile(
                r'\[DllImport\("advapi32\.dll", SetLastError = true\)\]\s+'
                r'\[return: MarshalAs\(UnmanagedType\.Bool\)\]\s+'
                r'internal static extern bool CreateWellKnownSid\(int wellKnownSidType, IntPtr domainSid, IntPtr sid, ref uint sidSize\);'
            ),
        )
        owner_mismatch = verify[
            verify.index("if (!Native.EqualSid(ownerSid, currentUserSid))"):
            verify.index('cngAclCheck = "cng_acl_dacl_read";')
        ]
        self.assertIn("QueryTokenInformation(currentToken, TokenOwner", owner_mismatch)
        self.assertIn("throw new InvalidOperationException();", owner_mismatch)
        self.assertIn("cng_acl_owner_matches_token_default", self.wrapper)
        self.assertIn("cng_acl_owner_matches_other", self.wrapper)
        self.assertIn(
            'else if (check == "cng_acl")\n                {\n                    check = state.CngAclCheck;',
            self.source,
        )
        self.assertNotIn("Console.", verify)
        self.assertNotIn("ToString(", verify)

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
            "export_policy=zero_persisted acl=verified destruction=verified cleanup=verified"
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
            "child_environment",
            "child_process_create_other",
            "child_job_assignment",
            "child_job_readback",
            "token_open",
            "token_appcontainer_read",
            "token_appcontainer_check",
            "token_lpac_check",
            "token_capabilities_read",
            "token_capabilities_check",
            "token_sid_read",
            "token_sid_check",
            "token_integrity_read",
            "token_integrity_check",
            "job_readback",
            "cng_key",
            "cng_acl",
            "cng_acl_support_read",
            "cng_acl_token_open",
            "cng_acl_user_read",
            "cng_acl_user_check",
            "cng_acl_owner_set",
            "cng_acl_system_sid",
            "cng_acl_owner_rights_sid",
            "cng_acl_owner_read",
            "cng_acl_owner_check",
            "cng_acl_owner_extract",
            "cng_acl_owner_absent",
            "cng_acl_owner_validate",
            "cng_acl_owner_user_match",
            "cng_acl_owner_default_read",
            "cng_acl_owner_default_validate",
            "cng_acl_owner_default_compare",
            "cng_acl_owner_matches_token_default",
            "cng_acl_owner_matches_other",
            "cng_acl_dacl_read",
            "cng_acl_dacl_check",
            "cng_acl_count_read",
            "cng_acl_ace_read",
            "cng_acl_ace_shape",
            "cng_acl_ace_sid",
            "cng_acl_ace_policy",
            "cng_acl_ace_owner_rights_check",
            "cng_acl_ace_owner_rights_allow",
            "cng_acl_ace_other_allow",
            "cng_acl_user_allow_check",
            "cng_acl_dacl_tighten_user_read",
            "cng_acl_dacl_tighten_user_check",
            "cng_acl_dacl_tighten_system_sid",
            "cng_acl_dacl_tighten_owner_rights",
            "cng_acl_dacl_tighten_source_read",
            "cng_acl_dacl_tighten_source_check",
            "cng_acl_dacl_tighten_source_count",
            "cng_acl_dacl_tighten_build",
            "cng_acl_dacl_tighten_source_ace",
            "cng_acl_dacl_tighten_source_shape",
            "cng_acl_dacl_tighten_inherited",
            "cng_acl_dacl_tighten_source_sid",
            "cng_acl_dacl_tighten_user_allow",
            "cng_acl_dacl_tighten_descriptor",
            "cng_acl_dacl_tighten_apply",
            "cng_acl_dacl_tighten_reopen",
            "cng_acl_dacl_tighten_readback",
            "cng_acl_dacl_tighten_compare",
            "cng_export_policy_set",
            "cng_export_policy_read",
            "cng_export_policy_nonzero",
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
        self.assertNotIn("win32_gettokeninformation_error", self.source)
        self.assertNotIn("win32_gettokeninformation_error", self.wrapper)
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
            ("child_environment", "BuildChildEnvironmentBlock("),
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
            self.source.index("internal static string BuildChildEnvironmentBlock(")
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
            ("\u0661", False),
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
            ("\u0661", "", fallback_incomplete),
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
        fixed_lines = (
            "windows-native-preflight=refused check=lpac_profile reason=native_preflight_unavailable cleanup=verified",
            "windows-native-preflight=refused check=child_environment reason=native_preflight_unavailable cleanup=verified",
            "windows-native-preflight=refused check=cng_export_policy_set reason=native_preflight_unavailable cleanup=verified",
            "windows-native-preflight=refused check=cng_export_policy_read reason=native_preflight_unavailable cleanup=verified",
            "windows-native-preflight=refused check=cng_export_policy_nonzero reason=native_preflight_unavailable cleanup=verified",
        )
        generic_fallback = "windows-native-preflight=refused check=runtime reason=native_preflight_unavailable cleanup=incomplete"
        for fixed_line in fixed_lines:
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
                with self.subTest(check=fixed_line.split("check=")[1].split()[0], ending=repr(ending)):
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

        raw_status_line = "windows-native-preflight=refused check=cng_export_policy_extra reason=native_preflight_unavailable cleanup=verified"
        encoded = base64.b64encode(raw_status_line.encode("utf-8")).decode("ascii")
        command = (
            "$result = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('"
            + encoded
            + "'))\n"
            + parser
        )
        completed = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, generic_fallback.encode("utf-8") + os.linesep.encode("ascii"))
        self.assertEqual(completed.stderr, b"")

    def test_powershell_token_subphase_refusals_are_exact_and_fail_closed(self):
        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable for wrapper parser fixtures")
        parser_start = self.wrapper.index("    if ($result -match '^windows-native-preflight=refused check=(")
        parser_end = self.wrapper.index("} catch {", parser_start)
        parser = self.wrapper[parser_start:parser_end]
        checks = (
            "token_open",
            "token_appcontainer_read",
            "token_appcontainer_check",
            "token_lpac_check",
            "token_capabilities_read",
            "token_capabilities_check",
            "token_sid_read",
            "token_sid_check",
            "token_integrity_read",
            "token_integrity_check",
        )
        fallback = "windows-native-preflight=refused check=runtime reason=native_preflight_unavailable cleanup=incomplete"
        lines = [
            "windows-native-preflight=refused check="
            + check
            + " reason=native_preflight_unavailable cleanup=verified"
            for check in checks
        ]
        fixtures = [(line, line) for line in lines]
        fixtures.extend((lines[-1] + ending, fallback) for ending in ("\n", "\r\n"))
        for line, expected in fixtures:
            encoded = base64.b64encode(line.encode("utf-8")).decode("ascii")
            command = (
                "$result = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('"
                + encoded
                + "'))\n"
                + parser
            )
            with self.subTest(check=line.split("check=")[1].split()[0], length=len(line)):
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

    def test_powershell_cng_acl_subphase_refusals_are_exact_and_fail_closed(self):
        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable for wrapper parser fixtures")
        parser_start = self.wrapper.index("    if ($result -match '^windows-native-preflight=refused check=(")
        parser_end = self.wrapper.index("} catch {", parser_start)
        parser = self.wrapper[parser_start:parser_end]
        checks = (
            "cng_acl_support_read",
            "cng_acl_token_open",
            "cng_acl_user_read",
            "cng_acl_user_check",
            "cng_acl_owner_set",
            "cng_acl_owner_rights_sid",
            "cng_acl_system_sid",
            "cng_acl_owner_read",
            "cng_acl_owner_check",
            "cng_acl_owner_extract",
            "cng_acl_owner_absent",
            "cng_acl_owner_validate",
            "cng_acl_owner_user_match",
            "cng_acl_owner_default_read",
            "cng_acl_owner_default_validate",
            "cng_acl_owner_default_compare",
            "cng_acl_owner_matches_token_default",
            "cng_acl_owner_matches_other",
            "cng_acl_dacl_read",
            "cng_acl_dacl_check",
            "cng_acl_count_read",
            "cng_acl_ace_read",
            "cng_acl_ace_shape",
            "cng_acl_ace_sid",
            "cng_acl_ace_policy",
            "cng_acl_ace_owner_rights_check",
            "cng_acl_ace_owner_rights_allow",
            "cng_acl_ace_other_allow",
            "cng_acl_user_allow_check",
            "cng_acl_dacl_tighten_user_read",
            "cng_acl_dacl_tighten_user_check",
            "cng_acl_dacl_tighten_system_sid",
            "cng_acl_dacl_tighten_owner_rights",
            "cng_acl_dacl_tighten_source_read",
            "cng_acl_dacl_tighten_source_check",
            "cng_acl_dacl_tighten_source_count",
            "cng_acl_dacl_tighten_build",
            "cng_acl_dacl_tighten_source_ace",
            "cng_acl_dacl_tighten_source_shape",
            "cng_acl_dacl_tighten_inherited",
            "cng_acl_dacl_tighten_source_sid",
            "cng_acl_dacl_tighten_user_allow",
            "cng_acl_dacl_tighten_descriptor",
            "cng_acl_dacl_tighten_apply",
            "cng_acl_dacl_tighten_reopen",
            "cng_acl_dacl_tighten_readback",
            "cng_acl_dacl_tighten_compare",
        )
        fallback = "windows-native-preflight=refused check=runtime reason=native_preflight_unavailable cleanup=incomplete"
        lines = [
            "windows-native-preflight=refused check="
            + check
            + " reason=native_preflight_unavailable cleanup=verified"
            for check in checks
        ]
        fixtures = [(line, line) for line in lines]
        fixtures.extend((lines[-1] + ending, fallback) for ending in ("\n", "\r\n"))
        for line, expected in fixtures:
            encoded = base64.b64encode(line.encode("utf-8")).decode("ascii")
            command = (
                "$result = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('"
                + encoded
                + "'))\n"
                + parser
            )
            with self.subTest(check=line.split("check=")[1].split()[0], length=len(line)):
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
