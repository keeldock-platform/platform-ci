using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace KeelDock.Platform.WindowsNativePreflight
{
    public static class Probe
    {
        private const int ErrorInsufficientBuffer = 122;
        private const uint TokenQuery = 0x0008;
        private const int TokenUser = 1;
        private const int TokenOwner = 4;
        private const int TokenIntegrityLevel = 25;
        private const int TokenIsAppContainer = 29;
        private const int TokenCapabilities = 30;
        private const int TokenAppContainerSid = 31;
        private const int MaxChildEnvironmentEntryCharacters = 32767;
        private const int MaxChildEnvironmentBlockCharacters = 131072;
        private const uint ProcThreadAttributeSecurityCapabilities = 0x00020009;
        private const uint ProcThreadAttributeAllApplicationPackagesPolicy = 0x0002000f;
        private const uint ProcessCreationAllApplicationPackagesOptOut = 0x00000001;
        private const uint CreateSuspended = 0x00000004;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint CreateNoWindow = 0x08000000;
        private const uint JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectLimitActiveProcess = 0x00000008;
        private const uint JobObjectLimitProcessMemory = 0x00000100;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private const uint JobLimitFlags = JobObjectLimitActiveProcess | JobObjectLimitProcessMemory | JobObjectLimitKillOnJobClose;
        private const uint ProcessMemoryLimit = 67108864;
        private const uint WaitObject0 = 0;
        private const uint AccessAllowedAceType = 0;
        private const uint AccessDeniedAceType = 1;
        private const byte InheritedAceFlag = 0x10;
        private const byte InheritOnlyAceFlag = 0x08;
        private const byte UnsupportedDaclAceFlags = 0xe0;
        private const uint AclSizeInformation = 2;
        private const uint AclRevision = 2;
        private const uint AclRevisionDs = 4;
        private const uint AclHeaderSize = 8;
        private const uint MaxAclBytes = 65535;
        private const int MaxSidSize = 68;
        private const int WinCreatorOwnerRightsSid = 71;
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint DaclSecurityInformation = 0x00000004;
        private const uint NCryptPersistFlag = 0x80000000;
        private const uint NCryptSilentFlag = 0x00000040;
        private const uint SecurityDescriptorRevision = 1;
        private const int NteBadKeyset = unchecked((int)0x80090016);
        private const int HresultAlreadyExists = unchecked((int)0x800700b7);

        private const string SuccessLine = "windows-native-preflight=observed appcontainer=lpac token=verified capabilities=empty integrity=low job=assigned limits=verified termination=verified cng=p256-user export_policy=zero_persisted acl=verified destruction=verified cleanup=verified";

        public static string Run()
        {
            State state = new State();
            string check = "lpac_profile";
            bool completed = false;
            try
            {
                state.CreateProfile();
                check = "job_setup";
                state.CreateJob();
                check = "child_launch";
                state.CreateSuspendedChild();
                check = "token_readback";
                state.VerifyToken();
                check = "job_readback";
                state.VerifyJob();
                check = "cng_key";
                state.CreateKey();
                check = "cng_export";
                state.SetKeyExportPolicy();
                check = "cng_acl";
                state.SetKeyOwnerToCurrentUser();
                check = "cng_key";
                state.FinalizeKey();
                check = "cng_acl";
                state.TightenKeyDacl();
                check = "cng_acl";
                state.VerifyKeyAcl();
                check = "cng_export";
                state.VerifyPersistedKeyExportPolicy();
                completed = true;
            }
            catch
            {
                if (check == "child_launch")
                {
                    check = state.ChildLaunchCheck;
                }
                else if (check == "token_readback")
                {
                    check = state.TokenReadbackCheck;
                }
                else if (check == "cng_acl")
                {
                    check = state.CngAclCheck;
                }
                else if (check == "cng_export")
                {
                    check = state.CngExportCheck;
                }
                completed = false;
            }

            bool cleanupComplete;
            try
            {
                cleanupComplete = state.Cleanup();
            }
            catch
            {
                cleanupComplete = false;
            }
            if (!cleanupComplete)
            {
                return Refusal("cleanup", false);
            }
            if (!completed)
            {
                if (state.ChildProcessCreateError.HasValue)
                {
                    return Refusal("child_process_create", true, state.ChildProcessCreateError.Value);
                }
                if (check == "child_process_create")
                {
                    check = "child_process_create_other";
                }
                return Refusal(check, true);
            }
            return SuccessLine;
        }

        private static string Refusal(string check, bool cleanupComplete, uint? win32CreateProcessError = null)
        {
            string errorField = win32CreateProcessError.HasValue
                ? " win32_createprocess_error=" + win32CreateProcessError.Value.ToString(CultureInfo.InvariantCulture)
                : string.Empty;
            return "windows-native-preflight=refused check=" + check + errorField + " reason=native_preflight_unavailable cleanup=" + (cleanupComplete ? "verified" : "incomplete");
        }

        internal static string BuildChildEnvironmentBlock(string localAppDataPath, string currentDirectory)
        {
            ValidateWindowsDirectory(localAppDataPath, MaxChildEnvironmentEntryCharacters - "LOCALAPPDATA=".Length);
            ValidateWindowsDirectory(currentDirectory, MaxChildEnvironmentEntryCharacters - "=C:=".Length);
            string tempPath = AppendWindowsPath(localAppDataPath, "Temp");
            string[] entries = new string[]
            {
                "=" + char.ToUpperInvariant(currentDirectory[0]) + ":=" + currentDirectory,
                "KD_NATIVE_PREFLIGHT=1",
                "LOCALAPPDATA=" + localAppDataPath,
                "TEMP=" + tempPath,
                "TMP=" + tempPath
            };
            Array.Sort(entries, StringComparer.OrdinalIgnoreCase);
            for (int index = 0; index < entries.Length; ++index)
            {
                if (entries[index].Length > MaxChildEnvironmentEntryCharacters)
                {
                    throw new InvalidOperationException();
                }
            }
            string block = string.Join("\0", entries) + "\0\0";
            if (block.Length > MaxChildEnvironmentBlockCharacters)
            {
                throw new InvalidOperationException();
            }
            return block;
        }

        internal static void RequireExportPolicySet(int status)
        {
            if (status != 0)
            {
                throw new InvalidOperationException();
            }
        }

        internal static void RequireZeroExportPolicy(uint exportPolicy)
        {
            if (exportPolicy != 0)
            {
                throw new InvalidOperationException();
            }
        }

        internal static uint ValidateDwordRead(int status, uint returned, IntPtr buffer)
        {
            if (status != 0 || returned != 4 || buffer == IntPtr.Zero)
            {
                throw new InvalidOperationException();
            }
            return unchecked((uint)Marshal.ReadInt32(buffer));
        }

        private static void ValidateWindowsDirectory(string path, int maximumCharacters)
        {
            if (string.IsNullOrEmpty(path) || path.Length < 3 || path.Length > maximumCharacters
                || !IsAsciiDriveLetter(path[0]) || path[1] != ':' || path[2] != '\\')
            {
                throw new InvalidOperationException();
            }
            for (int index = 0; index < path.Length; ++index)
            {
                char value = path[index];
                if (char.IsControl(value) || value == '"' || value == '<' || value == '>'
                    || value == '|' || value == '?' || value == '*' || (index != 1 && value == ':'))
                {
                    throw new InvalidOperationException();
                }
            }
        }

        private static bool IsAsciiDriveLetter(char value)
        {
            return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
        }

        private static string AppendWindowsPath(string directory, string child)
        {
            return directory.EndsWith("\\", StringComparison.Ordinal)
                ? directory + child
                : directory + "\\" + child;
        }

        private sealed class State
        {
            private string profileName;
            private IntPtr profileSid = IntPtr.Zero;
            private bool profileCreated;
            private bool profileFailureNeedsCleanup;
            private bool profileNameCollision;
            private IntPtr attributeListBuffer = IntPtr.Zero;
            private IntPtr attributeList = IntPtr.Zero;
            private bool attributeListInitialized;
            private IntPtr securityCapabilitiesBuffer = IntPtr.Zero;
            private IntPtr appPackagesPolicyBuffer = IntPtr.Zero;
            private IntPtr environmentBlock = IntPtr.Zero;
            private IntPtr appContainerSidString = IntPtr.Zero;
            private IntPtr appContainerLocalAppDataPath = IntPtr.Zero;
            private IntPtr job = IntPtr.Zero;
            private IntPtr process = IntPtr.Zero;
            private IntPtr thread = IntPtr.Zero;
            private IntPtr childToken = IntPtr.Zero;
            private IntPtr currentToken = IntPtr.Zero;
            private bool processCreated;
            private bool processAssigned;
            private bool childLpacPolicyConfigured;
            private string childLaunchCheck = "child_attribute_list";
            private uint? childProcessCreateError;
            private string tokenReadbackCheck = "token_open";
            private string cngAclCheck = "cng_acl_support_read";
            private string cngExportCheck = "cng_export_policy_set";
            private IntPtr provider = IntPtr.Zero;
            private IntPtr key = IntPtr.Zero;
            private IntPtr verificationKey = IntPtr.Zero;
            private string keyName;
            private bool keyOwned;

            internal string ChildLaunchCheck
            {
                get { return childLaunchCheck; }
            }

            internal uint? ChildProcessCreateError
            {
                get { return childProcessCreateError; }
            }

            internal string TokenReadbackCheck
            {
                get { return tokenReadbackCheck; }
            }

            internal string CngAclCheck
            {
                get { return cngAclCheck; }
            }

            internal string CngExportCheck
            {
                get { return cngExportCheck; }
            }

            internal void CreateProfile()
            {
                profileName = "KDN" + Guid.NewGuid().ToString("N");
                int result = Native.CreateAppContainerProfile(profileName, "Synthetic", "Synthetic", IntPtr.Zero, 0, out profileSid);
                if (result != 0)
                {
                    if (result == HresultAlreadyExists)
                    {
                        profileNameCollision = true;
                    }
                    else
                    {
                        profileFailureNeedsCleanup = true;
                    }
                    throw new InvalidOperationException();
                }
                profileCreated = true;
                if (profileSid == IntPtr.Zero || !Native.IsValidSid(profileSid))
                {
                    throw new InvalidOperationException();
                }
            }

            internal void CreateJob()
            {
                job = Native.CreateJobObjectW(IntPtr.Zero, null);
                if (job == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                Native.ExtendedLimitInformation information = new Native.ExtendedLimitInformation();
                information.BasicLimitInformation.LimitFlags = JobLimitFlags;
                information.BasicLimitInformation.ActiveProcessLimit = 1;
                information.ProcessMemoryLimit = new UIntPtr(ProcessMemoryLimit);
                int size = Marshal.SizeOf(typeof(Native.ExtendedLimitInformation));
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    Marshal.StructureToPtr(information, buffer, false);
                    if (!Native.SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size))
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            internal void CreateSuspendedChild()
            {
                childLaunchCheck = "child_attribute_list";
                IntPtr requiredSize = IntPtr.Zero;
                bool firstCall = Native.InitializeProcThreadAttributeList(IntPtr.Zero, 2, IntPtr.Zero, ref requiredSize);
                if (firstCall || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || requiredSize.ToInt64() <= 0 || requiredSize.ToInt64() > 65536)
                {
                    throw new InvalidOperationException();
                }
                attributeListBuffer = Marshal.AllocHGlobal(checked((int)requiredSize.ToInt64()));
                if (!Native.InitializeProcThreadAttributeList(attributeListBuffer, 2, IntPtr.Zero, ref requiredSize))
                {
                    throw new InvalidOperationException();
                }
                attributeList = attributeListBuffer;
                attributeListInitialized = true;

                childLaunchCheck = "child_security_capabilities";
                Native.SecurityCapabilities capabilities = new Native.SecurityCapabilities();
                capabilities.AppContainerSid = profileSid;
                capabilities.Capabilities = IntPtr.Zero;
                capabilities.CapabilityCount = 0;
                capabilities.Reserved = 0;
                int capabilitiesSize = Marshal.SizeOf(typeof(Native.SecurityCapabilities));
                securityCapabilitiesBuffer = Marshal.AllocHGlobal(capabilitiesSize);
                Marshal.StructureToPtr(capabilities, securityCapabilitiesBuffer, false);
                if (!Native.UpdateProcThreadAttribute(attributeList, 0, ProcThreadAttributeSecurityCapabilities, securityCapabilitiesBuffer, new UIntPtr((uint)capabilitiesSize), IntPtr.Zero, IntPtr.Zero))
                {
                    throw new InvalidOperationException();
                }

                childLaunchCheck = "child_lpac_policy";
                appPackagesPolicyBuffer = Marshal.AllocHGlobal(4);
                Marshal.WriteInt32(appPackagesPolicyBuffer, unchecked((int)ProcessCreationAllApplicationPackagesOptOut));
                if (!Native.UpdateProcThreadAttribute(attributeList, 0, ProcThreadAttributeAllApplicationPackagesPolicy, appPackagesPolicyBuffer, new UIntPtr(4), IntPtr.Zero, IntPtr.Zero))
                {
                    throw new InvalidOperationException();
                }
                childLpacPolicyConfigured = true;

                childLaunchCheck = "child_system_executable";
                StringBuilder systemDirectory = new StringBuilder(32768);
                uint systemDirectoryLength = Native.GetSystemDirectoryW(systemDirectory, (uint)systemDirectory.Capacity);
                if (systemDirectoryLength == 0 || systemDirectoryLength >= systemDirectory.Capacity)
                {
                    throw new InvalidOperationException();
                }
                string executable = Path.Combine(systemDirectory.ToString(), "cmd.exe");
                if (!File.Exists(executable))
                {
                    throw new InvalidOperationException();
                }
                childLaunchCheck = "child_environment";
                string localAppDataPath = GetAppContainerLocalAppDataPath();
                string childEnvironmentBlock = BuildChildEnvironmentBlock(localAppDataPath, systemDirectory.ToString());
                environmentBlock = Marshal.StringToHGlobalUni(childEnvironmentBlock);
                Native.StartupInfoEx startup = new Native.StartupInfoEx();
                startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(Native.StartupInfoEx));
                startup.AttributeList = attributeList;
                StringBuilder commandLine = new StringBuilder("\"" + executable + "\" /d /c exit 0");
                Native.ProcessInformation processInformation = new Native.ProcessInformation();
                uint flags = ExtendedStartupInfoPresent | CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow;
                childLaunchCheck = "child_process_create";
                bool created = Native.CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, false, flags, environmentBlock, systemDirectory.ToString(), ref startup, ref processInformation);
                uint? createProcessError = null;
                if (!created)
                {
                    createProcessError = unchecked((uint)Marshal.GetLastWin32Error());
                }
                process = processInformation.Process;
                thread = processInformation.Thread;
                processCreated = process != IntPtr.Zero;
                if (!created)
                {
                    childProcessCreateError = createProcessError;
                    throw new InvalidOperationException();
                }
                if (!processCreated || thread == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                childLaunchCheck = "child_job_assignment";
                if (!Native.AssignProcessToJobObject(job, process))
                {
                    throw new InvalidOperationException();
                }
                processAssigned = true;
                childLaunchCheck = "child_job_readback";
                bool inJob;
                if (!Native.IsProcessInJob(process, job, out inJob) || !inJob)
                {
                    throw new InvalidOperationException();
                }
            }

            internal void VerifyToken()
            {
                tokenReadbackCheck = "token_open";
                if (!Native.OpenProcessToken(process, TokenQuery, out childToken) || childToken == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }

                tokenReadbackCheck = "token_appcontainer_read";
                uint isAppContainer = ReadTokenDword(childToken, TokenIsAppContainer);
                tokenReadbackCheck = "token_appcontainer_check";
                if (isAppContainer != 1)
                {
                    throw new InvalidOperationException();
                }

                tokenReadbackCheck = "token_lpac_check";
                if (!childLpacPolicyConfigured || !processCreated || process == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }

                tokenReadbackCheck = "token_capabilities_read";
                IntPtr capabilityInformation = QueryTokenInformation(childToken, TokenCapabilities, out uint capabilityLength);
                try
                {
                    tokenReadbackCheck = "token_capabilities_check";
                    if (capabilityLength < 4 || Marshal.ReadInt32(capabilityInformation) != 0)
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(capabilityInformation);
                }

                tokenReadbackCheck = "token_sid_read";
                IntPtr appContainerInformation = QueryTokenInformation(childToken, TokenAppContainerSid, out uint appContainerLength);
                try
                {
                    tokenReadbackCheck = "token_sid_check";
                    if (appContainerLength < (uint)IntPtr.Size)
                    {
                        throw new InvalidOperationException();
                    }
                    IntPtr actualSid = Marshal.ReadIntPtr(appContainerInformation);
                    if (actualSid == IntPtr.Zero || !Native.IsValidSid(actualSid) || !Native.EqualSid(actualSid, profileSid))
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(appContainerInformation);
                }

                tokenReadbackCheck = "token_integrity_read";
                IntPtr integrityInformation = QueryTokenInformation(childToken, TokenIntegrityLevel, out uint integrityLength);
                try
                {
                    tokenReadbackCheck = "token_integrity_check";
                    if (integrityLength < (uint)IntPtr.Size)
                    {
                        throw new InvalidOperationException();
                    }
                    IntPtr integritySid = Marshal.ReadIntPtr(integrityInformation);
                    if (integritySid == IntPtr.Zero || !Native.IsValidSid(integritySid))
                    {
                        throw new InvalidOperationException();
                    }
                    IntPtr subAuthorityCount = Native.GetSidSubAuthorityCount(integritySid);
                    if (subAuthorityCount == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    byte count = Marshal.ReadByte(subAuthorityCount);
                    if (count == 0)
                    {
                        throw new InvalidOperationException();
                    }
                    IntPtr integrityRid = Native.GetSidSubAuthority(integritySid, (uint)(count - 1));
                    if (integrityRid == IntPtr.Zero || unchecked((uint)Marshal.ReadInt32(integrityRid)) != 0x00001000)
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(integrityInformation);
                }
            }

            internal void VerifyJob()
            {
                if (!processCreated || !processAssigned || job == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                bool inJob;
                if (!Native.IsProcessInJob(process, job, out inJob) || !inJob)
                {
                    throw new InvalidOperationException();
                }
                int size = Marshal.SizeOf(typeof(Native.ExtendedLimitInformation));
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint returned;
                    if (!Native.QueryInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size, out returned) || returned < size)
                    {
                        throw new InvalidOperationException();
                    }
                    Native.ExtendedLimitInformation information = (Native.ExtendedLimitInformation)Marshal.PtrToStructure(buffer, typeof(Native.ExtendedLimitInformation));
                    if (information.BasicLimitInformation.LimitFlags != JobLimitFlags)
                    {
                        throw new InvalidOperationException();
                    }
                    if (information.BasicLimitInformation.ActiveProcessLimit != 1)
                    {
                        throw new InvalidOperationException();
                    }
                    if (information.ProcessMemoryLimit.ToUInt64() != ProcessMemoryLimit)
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            internal void CreateKey()
            {
                int status = Native.NCryptOpenStorageProvider(out provider, "Microsoft Software Key Storage Provider", 0);
                if (status != 0 || provider == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                keyName = "KDN" + Guid.NewGuid().ToString("N");
                status = Native.NCryptCreatePersistedKey(provider, out key, "ECDH_P256", keyName, 0, 0);
                if (status != 0)
                {
                    throw new InvalidOperationException();
                }
                keyOwned = true;
                if (key == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
            }

            internal void SetKeyExportPolicy()
            {
                cngExportCheck = "cng_export_policy_set";
                IntPtr exportPolicy = Marshal.AllocHGlobal(4);
                try
                {
                    Marshal.WriteInt32(exportPolicy, 0);
                    int status = Native.NCryptSetProperty(
                        key,
                        "Export Policy",
                        exportPolicy,
                        4,
                        NCryptPersistFlag | NCryptSilentFlag);
                    RequireExportPolicySet(status);
                }
                finally
                {
                    Marshal.FreeHGlobal(exportPolicy);
                }
            }

            internal void SetKeyOwnerToCurrentUser()
            {
                cngAclCheck = "cng_acl_support_read";
                if (ReadProviderDword("Security Descr Support") != 1)
                {
                    throw new InvalidOperationException();
                }
                cngAclCheck = "cng_acl_token_open";
                if (!Native.OpenProcessToken(Native.GetCurrentProcess(), TokenQuery, out currentToken) || currentToken == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                IntPtr userInformation = IntPtr.Zero;
                IntPtr descriptor = IntPtr.Zero;
                try
                {
                    cngAclCheck = "cng_acl_user_read";
                    userInformation = QueryTokenInformation(currentToken, TokenUser, out uint userLength);
                    cngAclCheck = "cng_acl_user_check";
                    if (userLength < (uint)IntPtr.Size)
                    {
                        throw new InvalidOperationException();
                    }
                    IntPtr currentUserSid = Marshal.ReadIntPtr(userInformation);
                    if (currentUserSid == IntPtr.Zero || !Native.IsValidSid(currentUserSid))
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_owner_set";
                    int descriptorSize = Marshal.SizeOf(typeof(Native.SecurityDescriptor));
                    descriptor = Marshal.AllocHGlobal(descriptorSize);
                    if (!Native.InitializeSecurityDescriptor(descriptor, SecurityDescriptorRevision) ||
                        !Native.SetSecurityDescriptorOwner(descriptor, currentUserSid, false) ||
                        !Native.IsValidSecurityDescriptor(descriptor))
                    {
                        throw new InvalidOperationException();
                    }
                    int status = Native.NCryptSetProperty(
                        key,
                        "Security Descr",
                        descriptor,
                        checked((uint)descriptorSize),
                        OwnerSecurityInformation | NCryptSilentFlag);
                    if (status != 0)
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    if (descriptor != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(descriptor);
                    }
                    if (userInformation != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(userInformation);
                    }
                }
            }

            internal void FinalizeKey()
            {
                int status = Native.NCryptFinalizeKey(key, NCryptSilentFlag);
                if (status != 0)
                {
                    throw new InvalidOperationException();
                }
                if (ReadKeyDword("Key Type", NCryptSilentFlag) != 0 || ReadKeyDword("Length", NCryptSilentFlag) != 256)
                {
                    throw new InvalidOperationException();
                }
            }

            internal void TightenKeyDacl()
            {
                IntPtr userInformation = IntPtr.Zero;
                IntPtr systemSid = IntPtr.Zero;
                IntPtr ownerRightsSid = IntPtr.Zero;
                IntPtr sourceDescriptor = IntPtr.Zero;
                IntPtr targetDacl = IntPtr.Zero;
                IntPtr setDescriptor = IntPtr.Zero;
                IntPtr readbackDescriptor = IntPtr.Zero;
                try
                {
                    cngAclCheck = "cng_acl_dacl_tighten_user_read";
                    userInformation = QueryTokenInformation(currentToken, TokenUser, out uint userLength);
                    cngAclCheck = "cng_acl_dacl_tighten_user_check";
                    if (userLength < (uint)IntPtr.Size)
                    {
                        throw new InvalidOperationException();
                    }
                    IntPtr currentUserSid = Marshal.ReadIntPtr(userInformation);
                    if (currentUserSid == IntPtr.Zero || !Native.IsValidSid(currentUserSid))
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_dacl_tighten_system_sid";
                    if (!Native.ConvertStringSidToSidW("S-1-5-18", out systemSid) || systemSid == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_dacl_tighten_owner_rights";
                    ownerRightsSid = Marshal.AllocHGlobal(MaxSidSize);
                    uint ownerRightsSidLength = MaxSidSize;
                    if (ownerRightsSid == IntPtr.Zero ||
                        !Native.CreateWellKnownSid(WinCreatorOwnerRightsSid, IntPtr.Zero, ownerRightsSid, ref ownerRightsSidLength) ||
                        ownerRightsSidLength == 0 || ownerRightsSidLength > MaxSidSize ||
                        !Native.IsValidSid(ownerRightsSid) ||
                        Native.GetLengthSid(ownerRightsSid) != ownerRightsSidLength)
                    {
                        throw new InvalidOperationException();
                    }

                    cngAclCheck = "cng_acl_dacl_tighten_source_read";
                    sourceDescriptor = ReadSecurityDescriptor(key, DaclSecurityInformation | NCryptSilentFlag);
                    cngAclCheck = "cng_acl_dacl_tighten_source_check";
                    bool daclPresent;
                    bool daclDefaulted;
                    IntPtr sourceDacl;
                    if (!Native.GetSecurityDescriptorDacl(sourceDescriptor, out daclPresent, out sourceDacl, out daclDefaulted) ||
                        !daclPresent || sourceDacl == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }

                    Native.AclSizeInformation sourceInformation = new Native.AclSizeInformation();
                    cngAclCheck = "cng_acl_dacl_tighten_source_count";
                    if (!Native.GetAclInformation(sourceDacl, ref sourceInformation, (uint)Marshal.SizeOf(typeof(Native.AclSizeInformation)), AclSizeInformation) ||
                        sourceInformation.AceCount == 0 || sourceInformation.AceCount > 64 ||
                        sourceInformation.AclBytesInUse < AclHeaderSize || sourceInformation.AclBytesInUse > MaxAclBytes)
                    {
                        throw new InvalidOperationException();
                    }
                    byte aclRevision = Marshal.ReadByte(sourceDacl);
                    ushort sourceAclSize = unchecked((ushort)Marshal.ReadInt16(sourceDacl, 2));
                    if ((aclRevision != AclRevision && aclRevision != AclRevisionDs) ||
                        sourceAclSize < sourceInformation.AclBytesInUse ||
                        sourceAclSize - sourceInformation.AclBytesInUse != sourceInformation.AclBytesFree)
                    {
                        throw new InvalidOperationException();
                    }

                    cngAclCheck = "cng_acl_dacl_tighten_build";
                    byte[] expectedAceBytes = new byte[checked((int)(sourceInformation.AclBytesInUse - AclHeaderSize))];
                    uint[] expectedAceSizes = new uint[sourceInformation.AceCount];
                    targetDacl = Marshal.AllocHGlobal(checked((int)sourceInformation.AclBytesInUse));
                    if (targetDacl == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_dacl_tighten_build";
                    if (!Native.InitializeAcl(targetDacl, sourceInformation.AclBytesInUse, aclRevision))
                    {
                        throw new InvalidOperationException();
                    }

                    uint sourceBytesRead = AclHeaderSize;
                    uint expectedBytesWritten = 0;
                    uint expectedAceCount = 0;
                    bool currentUserAllowed = false;
                    for (uint index = 0; index < sourceInformation.AceCount; index++)
                    {
                        IntPtr ace;
                        cngAclCheck = "cng_acl_dacl_tighten_source_ace";
                        if (!Native.GetAce(sourceDacl, index, out ace) || ace == IntPtr.Zero)
                        {
                            throw new InvalidOperationException();
                        }
                        byte type = Marshal.ReadByte(ace, 0);
                        byte aceFlags = Marshal.ReadByte(ace, 1);
                        uint aceSize = unchecked((ushort)Marshal.ReadInt16(ace, 2));
                        cngAclCheck = "cng_acl_dacl_tighten_source_shape";
                        if ((type != AccessAllowedAceType && type != AccessDeniedAceType) ||
                            !IsSupportedDaclAceFlags(aceFlags) || aceSize < 16 || (aceSize & 3) != 0 ||
                            aceSize > sourceInformation.AclBytesInUse - sourceBytesRead)
                        {
                            throw new InvalidOperationException();
                        }
                        cngAclCheck = "cng_acl_dacl_tighten_inherited";
                        if (IsInheritedDaclAce(aceFlags))
                        {
                            throw new InvalidOperationException();
                        }
                        IntPtr aceSid = IntPtr.Add(ace, 8);
                        cngAclCheck = "cng_acl_dacl_tighten_source_sid";
                        if (!Native.IsValidSid(aceSid))
                        {
                            throw new InvalidOperationException();
                        }
                        uint sidLength = Native.GetLengthSid(aceSid);
                        if (sidLength == 0 || aceSize < 8 + sidLength)
                        {
                            throw new InvalidOperationException();
                        }

                        bool isUser = false;
                        bool isSystem = false;
                        bool isOwnerRights = false;
                        if (type == AccessAllowedAceType)
                        {
                            isUser = Native.EqualSid(aceSid, currentUserSid);
                            isSystem = Native.EqualSid(aceSid, systemSid);
                            if (!isUser && !isSystem)
                            {
                                cngAclCheck = "cng_acl_dacl_tighten_owner_rights";
                                isOwnerRights = Native.EqualSid(aceSid, ownerRightsSid);
                            }
                        }
                        bool retainAce = ShouldRetainDaclAce(type, isUser, isSystem, isOwnerRights);
                        if (type == AccessAllowedAceType && isUser && (aceFlags & InheritOnlyAceFlag) == 0)
                        {
                            currentUserAllowed = true;
                        }

                        if (retainAce)
                        {
                            cngAclCheck = "cng_acl_dacl_tighten_build";
                            if (expectedAceCount >= (uint)expectedAceSizes.Length ||
                                aceSize > (uint)expectedAceBytes.Length - expectedBytesWritten ||
                                !Native.AddAce(targetDacl, aclRevision, uint.MaxValue, ace, aceSize))
                            {
                                throw new InvalidOperationException();
                            }
                            Marshal.Copy(ace, expectedAceBytes, checked((int)expectedBytesWritten), checked((int)aceSize));
                            expectedAceSizes[expectedAceCount] = aceSize;
                            expectedBytesWritten += aceSize;
                            expectedAceCount++;
                        }
                        sourceBytesRead += aceSize;
                    }
                    cngAclCheck = "cng_acl_dacl_tighten_source_count";
                    if (sourceBytesRead != sourceInformation.AclBytesInUse)
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_dacl_tighten_user_allow";
                    if (!currentUserAllowed || expectedAceCount == 0)
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_dacl_tighten_build";
                    Array.Resize(ref expectedAceBytes, checked((int)expectedBytesWritten));

                    Native.AclSizeInformation targetInformation = new Native.AclSizeInformation();
                    cngAclCheck = "cng_acl_dacl_tighten_build";
                    if (!Native.GetAclInformation(targetDacl, ref targetInformation, (uint)Marshal.SizeOf(typeof(Native.AclSizeInformation)), AclSizeInformation) ||
                        targetInformation.AceCount != expectedAceCount || targetInformation.AclBytesInUse != AclHeaderSize + expectedBytesWritten)
                    {
                        throw new InvalidOperationException();
                    }

                    cngAclCheck = "cng_acl_dacl_tighten_descriptor";
                    int descriptorSize = Marshal.SizeOf(typeof(Native.SecurityDescriptor));
                    setDescriptor = Marshal.AllocHGlobal(descriptorSize);
                    if (setDescriptor == IntPtr.Zero ||
                        !Native.InitializeSecurityDescriptor(setDescriptor, SecurityDescriptorRevision) ||
                        !Native.SetSecurityDescriptorDacl(setDescriptor, true, targetDacl, false) ||
                        !Native.IsValidSecurityDescriptor(setDescriptor))
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_dacl_tighten_apply";
                    int status = Native.NCryptSetProperty(
                        key,
                        "Security Descr",
                        setDescriptor,
                        checked((uint)descriptorSize),
                        DaclSecurityInformation | NCryptSilentFlag);
                    if (status != 0)
                    {
                        throw new InvalidOperationException();
                    }

                    cngAclCheck = "cng_acl_dacl_tighten_reopen";
                    int openStatus = Native.NCryptOpenKey(provider, out verificationKey, keyName, 0, NCryptSilentFlag);
                    if (openStatus != 0 || verificationKey == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_dacl_tighten_readback";
                    readbackDescriptor = ReadSecurityDescriptor(verificationKey, DaclSecurityInformation | NCryptSilentFlag);
                    bool readbackDaclPresent;
                    bool readbackDaclDefaulted;
                    IntPtr readbackDacl;
                    if (!Native.GetSecurityDescriptorDacl(readbackDescriptor, out readbackDaclPresent, out readbackDacl, out readbackDaclDefaulted) ||
                        !readbackDaclPresent || readbackDacl == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    Native.AclSizeInformation readbackInformation = new Native.AclSizeInformation();
                    cngAclCheck = "cng_acl_dacl_tighten_compare";
                    if (!Native.GetAclInformation(readbackDacl, ref readbackInformation, (uint)Marshal.SizeOf(typeof(Native.AclSizeInformation)), AclSizeInformation))
                    {
                        throw new InvalidOperationException();
                    }
                    ushort readbackAclSize = unchecked((ushort)Marshal.ReadInt16(readbackDacl, 2));
                    if (Marshal.ReadByte(readbackDacl) != aclRevision ||
                        readbackAclSize < readbackInformation.AclBytesInUse ||
                        readbackAclSize - readbackInformation.AclBytesInUse != readbackInformation.AclBytesFree ||
                        readbackInformation.AceCount != expectedAceCount ||
                        readbackInformation.AclBytesInUse != AclHeaderSize + expectedBytesWritten)
                    {
                        throw new InvalidOperationException();
                    }
                    uint expectedOffset = 0;
                    for (uint index = 0; index < expectedAceCount; index++)
                    {
                        IntPtr ace;
                        if (!Native.GetAce(readbackDacl, index, out ace) || ace == IntPtr.Zero ||
                            unchecked((ushort)Marshal.ReadInt16(ace, 2)) != expectedAceSizes[index])
                        {
                            throw new InvalidOperationException();
                        }
                        for (uint byteIndex = 0; byteIndex < expectedAceSizes[index]; byteIndex++)
                        {
                            if (Marshal.ReadByte(ace, checked((int)byteIndex)) != expectedAceBytes[checked((int)(expectedOffset + byteIndex))])
                            {
                                throw new InvalidOperationException();
                            }
                        }
                        expectedOffset += expectedAceSizes[index];
                    }
                    if (expectedOffset != expectedBytesWritten)
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    if (sourceDescriptor != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(sourceDescriptor);
                    }
                    if (targetDacl != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(targetDacl);
                    }
                    if (setDescriptor != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(setDescriptor);
                    }
                    if (readbackDescriptor != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(readbackDescriptor);
                    }
                    if (userInformation != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(userInformation);
                    }
                    if (systemSid != IntPtr.Zero)
                    {
                        Native.LocalFree(systemSid);
                    }
                    if (ownerRightsSid != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(ownerRightsSid);
                    }
                }
            }

            internal static bool ShouldRetainDaclAce(byte type, bool isUser, bool isSystem, bool isOwnerRights)
            {
                if (type == AccessDeniedAceType)
                {
                    return true;
                }
                if (type != AccessAllowedAceType || isOwnerRights)
                {
                    throw new InvalidOperationException();
                }
                return isUser || isSystem;
            }

            internal static bool IsInheritedDaclAce(byte flags)
            {
                return (flags & InheritedAceFlag) != 0;
            }

            internal static bool IsSupportedDaclAceFlags(byte flags)
            {
                return (flags & UnsupportedDaclAceFlags) == 0;
            }

            internal void VerifyKeyAcl()
            {
                IntPtr currentUserSid = IntPtr.Zero;
                IntPtr systemSid = IntPtr.Zero;
                IntPtr ownerRightsSid = IntPtr.Zero;
                IntPtr ownerDescriptor = IntPtr.Zero;
                IntPtr daclDescriptor = IntPtr.Zero;
                IntPtr userInformation = IntPtr.Zero;
                try
                {
                    cngAclCheck = "cng_acl_user_read";
                    userInformation = QueryTokenInformation(currentToken, TokenUser, out uint userLength);
                    cngAclCheck = "cng_acl_user_check";
                    if (userLength < (uint)IntPtr.Size)
                    {
                        throw new InvalidOperationException();
                    }
                    currentUserSid = Marshal.ReadIntPtr(userInformation);
                    if (currentUserSid == IntPtr.Zero || !Native.IsValidSid(currentUserSid))
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_system_sid";
                    if (!Native.ConvertStringSidToSidW("S-1-5-18", out systemSid) || systemSid == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_owner_rights_sid";
                    ownerRightsSid = Marshal.AllocHGlobal(MaxSidSize);
                    uint ownerRightsSidLength = MaxSidSize;
                    if (ownerRightsSid == IntPtr.Zero ||
                        !Native.CreateWellKnownSid(WinCreatorOwnerRightsSid, IntPtr.Zero, ownerRightsSid, ref ownerRightsSidLength) ||
                        ownerRightsSidLength == 0 || ownerRightsSidLength > MaxSidSize ||
                        !Native.IsValidSid(ownerRightsSid) ||
                        Native.GetLengthSid(ownerRightsSid) != ownerRightsSidLength)
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_owner_read";
                    ownerDescriptor = ReadSecurityDescriptor(verificationKey, OwnerSecurityInformation | NCryptSilentFlag);
                    cngAclCheck = "cng_acl_owner_extract";
                    IntPtr ownerSid = IntPtr.Zero;
                    bool ownerDefaulted;
                    if (!Native.GetSecurityDescriptorOwner(ownerDescriptor, out ownerSid, out ownerDefaulted))
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_owner_absent";
                    if (ownerSid == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_owner_validate";
                    if (!Native.IsValidSid(ownerSid))
                    {
                        throw new InvalidOperationException();
                    }
                    cngAclCheck = "cng_acl_owner_user_match";
                    if (!Native.EqualSid(ownerSid, currentUserSid))
                    {
                        cngAclCheck = "cng_acl_owner_default_read";
                        IntPtr ownerInformation = QueryTokenInformation(currentToken, TokenOwner, out uint ownerLength);
                        try
                        {
                            cngAclCheck = "cng_acl_owner_default_validate";
                            if (ownerLength < (uint)IntPtr.Size)
                            {
                                throw new InvalidOperationException();
                            }
                            IntPtr tokenOwnerSid = Marshal.ReadIntPtr(ownerInformation);
                            if (tokenOwnerSid == IntPtr.Zero || !Native.IsValidSid(tokenOwnerSid))
                            {
                                throw new InvalidOperationException();
                            }
                            cngAclCheck = "cng_acl_owner_default_compare";
                            bool ownerMatchesTokenDefault = Native.EqualSid(ownerSid, tokenOwnerSid);
                            cngAclCheck = ownerMatchesTokenDefault ? "cng_acl_owner_matches_token_default" : "cng_acl_owner_matches_other";
                            throw new InvalidOperationException();
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(ownerInformation);
                        }
                    }
                    cngAclCheck = "cng_acl_dacl_read";
                    daclDescriptor = ReadSecurityDescriptor(verificationKey, DaclSecurityInformation | NCryptSilentFlag);
                    cngAclCheck = "cng_acl_dacl_check";
                    bool daclPresent;
                    bool daclDefaulted;
                    IntPtr dacl;
                    if (!Native.GetSecurityDescriptorDacl(daclDescriptor, out daclPresent, out dacl, out daclDefaulted) || !daclPresent || dacl == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    Native.AclSizeInformation aclInformation = new Native.AclSizeInformation();
                    cngAclCheck = "cng_acl_count_read";
                    if (!Native.GetAclInformation(dacl, ref aclInformation, (uint)Marshal.SizeOf(typeof(Native.AclSizeInformation)), AclSizeInformation) || aclInformation.AceCount == 0 || aclInformation.AceCount > 64)
                    {
                        throw new InvalidOperationException();
                    }
                    bool currentUserAllowed = false;
                    for (uint index = 0; index < aclInformation.AceCount; index++)
                    {
                        IntPtr ace;
                        cngAclCheck = "cng_acl_ace_read";
                        if (!Native.GetAce(dacl, index, out ace) || ace == IntPtr.Zero)
                        {
                            throw new InvalidOperationException();
                        }
                        byte type = Marshal.ReadByte(ace, 0);
                        ushort aceSize = unchecked((ushort)Marshal.ReadInt16(ace, 2));
                        cngAclCheck = "cng_acl_ace_shape";
                        if ((type != AccessAllowedAceType && type != AccessDeniedAceType) || aceSize < 16)
                        {
                            throw new InvalidOperationException();
                        }
                        IntPtr aceSid = IntPtr.Add(ace, 8);
                        cngAclCheck = "cng_acl_ace_sid";
                        if (!Native.IsValidSid(aceSid))
                        {
                            throw new InvalidOperationException();
                        }
                        uint sidLength = Native.GetLengthSid(aceSid);
                        if (sidLength == 0 || aceSize < 8 + sidLength)
                        {
                            throw new InvalidOperationException();
                        }
                        if (type == AccessAllowedAceType)
                        {
                            cngAclCheck = "cng_acl_ace_policy";
                            bool isUser = Native.EqualSid(aceSid, currentUserSid);
                            bool isSystem = Native.EqualSid(aceSid, systemSid);
                            if (!isUser && !isSystem)
                            {
                                cngAclCheck = "cng_acl_ace_owner_rights_check";
                                bool isOwnerRights = Native.EqualSid(aceSid, ownerRightsSid);
                                cngAclCheck = isOwnerRights ? "cng_acl_ace_owner_rights_allow" : "cng_acl_ace_other_allow";
                                throw new InvalidOperationException();
                            }
                            if (isUser)
                            {
                                currentUserAllowed = true;
                            }
                        }
                    }
                    cngAclCheck = "cng_acl_user_allow_check";
                    if (!currentUserAllowed)
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    if (ownerDescriptor != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(ownerDescriptor);
                    }
                    if (daclDescriptor != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(daclDescriptor);
                    }
                    if (userInformation != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(userInformation);
                    }
                    if (systemSid != IntPtr.Zero)
                    {
                        Native.LocalFree(systemSid);
                    }
                    if (ownerRightsSid != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(ownerRightsSid);
                    }
                }
            }

            internal void VerifyPersistedKeyExportPolicy()
            {
                cngExportCheck = "cng_export_policy_read";
                uint exportPolicy = ReadCngDword(verificationKey, "Export Policy", NCryptSilentFlag);
                if (exportPolicy != 0)
                {
                    cngExportCheck = "cng_export_policy_nonzero";
                }
                RequireZeroExportPolicy(exportPolicy);
            }

            internal bool Cleanup()
            {
                bool complete = true;
                try
                {
                    if (process != IntPtr.Zero)
                    {
                        bool terminated;
                        if (processAssigned && job != IntPtr.Zero)
                        {
                            terminated = Native.TerminateJobObject(job, 0x4b444e50);
                        }
                        else
                        {
                            terminated = Native.TerminateProcess(process, 0x4b444e50);
                        }
                        if (!terminated)
                        {
                            complete = false;
                            Native.TerminateProcess(process, 0x4b444e50);
                        }
                        uint wait = Native.WaitForSingleObject(process, 5000);
                        if (wait != WaitObject0)
                        {
                            Native.TerminateProcess(process, 0x4b444e50);
                            wait = Native.WaitForSingleObject(process, 5000);
                        }
                        if (wait != WaitObject0)
                        {
                            complete = false;
                        }
                    }
                }
                catch
                {
                    complete = false;
                }
                complete = SafeCloseHandle(ref childToken, complete);
                complete = SafeCloseHandle(ref currentToken, complete);

                if (attributeListInitialized && attributeList != IntPtr.Zero)
                {
                    try
                    {
                        Native.DeleteProcThreadAttributeList(attributeList);
                    }
                    catch
                    {
                        complete = false;
                    }
                    attributeListInitialized = false;
                }
                complete = FreeMemory(ref securityCapabilitiesBuffer, complete);
                complete = FreeMemory(ref appPackagesPolicyBuffer, complete);
                complete = FreeMemory(ref environmentBlock, complete);
                complete = FreeCoTaskMemory(ref appContainerLocalAppDataPath, complete);
                complete = SafeLocalFree(ref appContainerSidString, complete);
                complete = FreeMemory(ref attributeListBuffer, complete);
                attributeList = IntPtr.Zero;

                if (job != IntPtr.Zero)
                {
                    try
                    {
                        if (!Native.CloseHandle(job))
                        {
                            complete = false;
                        }
                    }
                    catch
                    {
                        complete = false;
                    }
                    job = IntPtr.Zero;
                }
                complete = SafeCloseHandle(ref process, complete);
                complete = SafeCloseHandle(ref thread, complete);
                complete = SafeFreeCngObject(ref verificationKey, complete);

                if (keyOwned && provider != IntPtr.Zero && keyName != null)
                {
                    try
                    {
                        if (key != IntPtr.Zero)
                        {
                            int deleteStatus = Native.NCryptDeleteKey(key, NCryptSilentFlag);
                            if (deleteStatus == 0)
                            {
                                key = IntPtr.Zero;
                            }
                            else
                            {
                                complete = FreeCngObject(ref key, complete);
                            }
                        }
                        complete = EnsureKeyAbsent(complete);
                    }
                    catch
                    {
                        complete = false;
                        complete = SafeFreeCngObject(ref key, complete);
                    }
                }
                else if (key != IntPtr.Zero)
                {
                    complete = SafeFreeCngObject(ref key, complete);
                }
                if (provider != IntPtr.Zero)
                {
                    complete = SafeFreeCngObject(ref provider, complete);
                }

                if (profileCreated && profileName != null)
                {
                    try
                    {
                        int result = Native.DeleteAppContainerProfile(profileName);
                        if (result != 0)
                        {
                            result = Native.DeleteAppContainerProfile(profileName);
                            if (result != 0)
                            {
                                complete = false;
                            }
                        }
                    }
                    catch
                    {
                        complete = false;
                    }
                    profileCreated = false;
                }
                else if (profileFailureNeedsCleanup && profileName != null)
                {
                    try
                    {
                        int result = Native.DeleteAppContainerProfile(profileName);
                        if (result != 0)
                        {
                            result = Native.DeleteAppContainerProfile(profileName);
                            if (result != 0)
                            {
                                complete = false;
                            }
                        }
                    }
                    catch
                    {
                        complete = false;
                    }
                    profileFailureNeedsCleanup = false;
                }
                if (profileNameCollision)
                {
                    complete = false;
                    profileNameCollision = false;
                }
                if (profileSid != IntPtr.Zero)
                {
                    try
                    {
                        if (Native.FreeSid(profileSid) != IntPtr.Zero)
                        {
                            complete = false;
                        }
                    }
                    catch
                    {
                        complete = false;
                    }
                    profileSid = IntPtr.Zero;
                }
                return complete;
            }

            private bool EnsureKeyAbsent(bool complete)
            {
                IntPtr reopened = IntPtr.Zero;
                int status = Native.NCryptOpenKey(provider, out reopened, keyName, 0, NCryptSilentFlag);
                if (status == NteBadKeyset)
                {
                    return complete;
                }
                if (status != 0 || reopened == IntPtr.Zero)
                {
                    if (reopened != IntPtr.Zero)
                    {
                        Native.NCryptFreeObject(reopened);
                    }
                    return false;
                }
                int deleteStatus = Native.NCryptDeleteKey(reopened, NCryptSilentFlag);
                if (deleteStatus != 0)
                {
                    Native.NCryptFreeObject(reopened);
                    return false;
                }
                reopened = IntPtr.Zero;
                status = Native.NCryptOpenKey(provider, out reopened, keyName, 0, NCryptSilentFlag);
                if (status == NteBadKeyset)
                {
                    return complete;
                }
                if (reopened != IntPtr.Zero)
                {
                    Native.NCryptFreeObject(reopened);
                }
                return false;
            }

            private uint ReadKeyDword(string property, uint flags)
            {
                return ReadCngDword(key, property, flags);
            }

            private uint ReadProviderDword(string property)
            {
                return ReadCngDword(provider, property, 0);
            }

            private uint ReadCngDword(IntPtr handle, string property, uint flags)
            {
                IntPtr buffer = Marshal.AllocHGlobal(4);
                try
                {
                    uint returned;
                    int status = Native.NCryptGetProperty(handle, property, buffer, 4, out returned, flags | NCryptSilentFlag);
                    return ValidateDwordRead(status, returned, buffer);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            private IntPtr ReadSecurityDescriptor(IntPtr handle, uint information)
            {
                uint required;
                int status = Native.NCryptGetProperty(handle, "Security Descr", IntPtr.Zero, 0, out required, information | NCryptSilentFlag);
                if (status != 0 || required == 0 || required > 65536)
                {
                    throw new InvalidOperationException();
                }
                IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
                uint returned;
                status = Native.NCryptGetProperty(handle, "Security Descr", buffer, required, out returned, information | NCryptSilentFlag);
                if (status != 0 || returned == 0 || returned > required || !Native.IsValidSecurityDescriptor(buffer))
                {
                    Marshal.FreeHGlobal(buffer);
                    throw new InvalidOperationException();
                }
                return buffer;
            }

            private static uint ReadTokenDword(IntPtr token, int informationClass)
            {
                IntPtr buffer = QueryTokenInformation(token, informationClass, out uint length);
                try
                {
                    if (length != 4)
                    {
                        throw new InvalidOperationException();
                    }
                    return unchecked((uint)Marshal.ReadInt32(buffer));
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            private static IntPtr QueryTokenInformation(IntPtr token, int informationClass, out uint returnedLength)
            {
                uint required = 0;
                bool first = Native.GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out required);
                if (first || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || required == 0 || required > 65536)
                {
                    throw new InvalidOperationException();
                }
                IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
                if (!Native.GetTokenInformation(token, informationClass, buffer, required, out returnedLength) || returnedLength == 0 || returnedLength > required)
                {
                    Marshal.FreeHGlobal(buffer);
                    throw new InvalidOperationException();
                }
                return buffer;
            }

            private static bool CloseHandle(ref IntPtr handle, bool complete)
            {
                if (handle != IntPtr.Zero)
                {
                    if (!Native.CloseHandle(handle))
                    {
                        complete = false;
                    }
                    handle = IntPtr.Zero;
                }
                return complete;
            }

            private static bool SafeCloseHandle(ref IntPtr handle, bool complete)
            {
                try
                {
                    return CloseHandle(ref handle, complete);
                }
                catch
                {
                    handle = IntPtr.Zero;
                    return false;
                }
            }

            private static bool FreeMemory(ref IntPtr memory, bool complete)
            {
                if (memory != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(memory);
                    memory = IntPtr.Zero;
                }
                return complete;
            }

            private static bool FreeCoTaskMemory(ref IntPtr memory, bool complete)
            {
                if (memory != IntPtr.Zero)
                {
                    try
                    {
                        Marshal.FreeCoTaskMem(memory);
                    }
                    catch
                    {
                        complete = false;
                    }
                    memory = IntPtr.Zero;
                }
                return complete;
            }

            private static bool SafeLocalFree(ref IntPtr memory, bool complete)
            {
                if (memory != IntPtr.Zero)
                {
                    try
                    {
                        if (Native.LocalFree(memory) != IntPtr.Zero)
                        {
                            complete = false;
                        }
                    }
                    catch
                    {
                        complete = false;
                    }
                    memory = IntPtr.Zero;
                }
                return complete;
            }

            private string GetAppContainerLocalAppDataPath()
            {
                if (!Native.ConvertSidToStringSidW(profileSid, out appContainerSidString) || appContainerSidString == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                int sidLength = Native.lstrlenW(appContainerSidString);
                if (sidLength < 1 || sidLength > 184)
                {
                    throw new InvalidOperationException();
                }
                string sidText = Marshal.PtrToStringUni(appContainerSidString, sidLength);
                if (string.IsNullOrEmpty(sidText) || Native.GetAppContainerFolderPath(sidText, out appContainerLocalAppDataPath) != 0
                    || appContainerLocalAppDataPath == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                int pathLength = Native.lstrlenW(appContainerLocalAppDataPath);
                if (pathLength < 1 || pathLength > MaxChildEnvironmentEntryCharacters - "LOCALAPPDATA=".Length)
                {
                    throw new InvalidOperationException();
                }
                return Marshal.PtrToStringUni(appContainerLocalAppDataPath, pathLength);
            }

            private static bool FreeCngObject(ref IntPtr handle, bool complete)
            {
                if (handle != IntPtr.Zero)
                {
                    if (Native.NCryptFreeObject(handle) != 0)
                    {
                        complete = false;
                    }
                    handle = IntPtr.Zero;
                }
                return complete;
            }

            private static bool SafeFreeCngObject(ref IntPtr handle, bool complete)
            {
                try
                {
                    return FreeCngObject(ref handle, complete);
                }
                catch
                {
                    handle = IntPtr.Zero;
                    return false;
                }
            }
        }

        private static class Native
        {
            [StructLayout(LayoutKind.Sequential)]
            internal struct SecurityCapabilities
            {
                internal IntPtr AppContainerSid;
                internal IntPtr Capabilities;
                internal uint CapabilityCount;
                internal uint Reserved;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal struct StartupInfo
            {
                internal uint cb;
                internal IntPtr lpReserved;
                internal IntPtr lpDesktop;
                internal IntPtr lpTitle;
                internal uint dwX;
                internal uint dwY;
                internal uint dwXSize;
                internal uint dwYSize;
                internal uint dwXCountChars;
                internal uint dwYCountChars;
                internal uint dwFillAttribute;
                internal uint dwFlags;
                internal ushort wShowWindow;
                internal ushort cbReserved2;
                internal IntPtr lpReserved2;
                internal IntPtr hStdInput;
                internal IntPtr hStdOutput;
                internal IntPtr hStdError;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct StartupInfoEx
            {
                internal StartupInfo StartupInfo;
                internal IntPtr AttributeList;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct ProcessInformation
            {
                internal IntPtr Process;
                internal IntPtr Thread;
                internal uint ProcessId;
                internal uint ThreadId;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct JobBasicLimitInformation
            {
                internal long PerProcessUserTimeLimit;
                internal long PerJobUserTimeLimit;
                internal uint LimitFlags;
                internal UIntPtr MinimumWorkingSetSize;
                internal UIntPtr MaximumWorkingSetSize;
                internal uint ActiveProcessLimit;
                internal UIntPtr Affinity;
                internal uint PriorityClass;
                internal uint SchedulingClass;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct IoCounters
            {
                internal ulong ReadOperationCount;
                internal ulong WriteOperationCount;
                internal ulong OtherOperationCount;
                internal ulong ReadTransferCount;
                internal ulong WriteTransferCount;
                internal ulong OtherTransferCount;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct ExtendedLimitInformation
            {
                internal JobBasicLimitInformation BasicLimitInformation;
                internal IoCounters IoInfo;
                internal UIntPtr ProcessMemoryLimit;
                internal UIntPtr JobMemoryLimit;
                internal UIntPtr PeakProcessMemoryUsed;
                internal UIntPtr PeakJobMemoryUsed;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct AclSizeInformation
            {
                internal uint AceCount;
                internal uint AclBytesInUse;
                internal uint AclBytesFree;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct SecurityDescriptor
            {
                internal byte Revision;
                internal byte Sbz1;
                internal ushort Control;
                internal IntPtr Owner;
                internal IntPtr Group;
                internal IntPtr Sacl;
                internal IntPtr Dacl;
            }

            [DllImport("userenv.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
            internal static extern int CreateAppContainerProfile(string appContainerName, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);

            [DllImport("userenv.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
            internal static extern int DeleteAppContainerProfile(string appContainerName);

            [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = true)]
            internal static extern int GetAppContainerFolderPath(string appContainerSid, out IntPtr path);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetTokenInformation(IntPtr tokenHandle, int informationClass, IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsValidSid(IntPtr sid);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool EqualSid(IntPtr sid1, IntPtr sid2);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CreateWellKnownSid(int wellKnownSidType, IntPtr domainSid, IntPtr sid, ref uint sidSize);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern uint GetLengthSid(IntPtr sid);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern IntPtr FreeSid(IntPtr sid);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);

            [DllImport("kernel32.dll")]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            internal static extern uint GetSystemDirectoryW(StringBuilder buffer, uint size);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string name);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool SetInformationJobObject(IntPtr job, uint informationClass, IntPtr information, uint informationLength);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool QueryInformationJobObject(IntPtr job, uint informationClass, IntPtr information, uint informationLength, out uint returnLength);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool TerminateJobObject(IntPtr job, uint exitCode);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool TerminateProcess(IntPtr process, uint exitCode);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseHandle(IntPtr handle);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, IntPtr flags, ref IntPtr size);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, uint attribute, IntPtr value, UIntPtr size, IntPtr previousValue, IntPtr returnSize);

            [DllImport("kernel32.dll")]
            internal static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInfoEx startupInfo, ref ProcessInformation processInformation);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetSecurityDescriptorOwner(IntPtr securityDescriptor, out IntPtr owner, [MarshalAs(UnmanagedType.Bool)] out bool ownerDefaulted);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetSecurityDescriptorDacl(IntPtr securityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool daclPresent, out IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] out bool daclDefaulted);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetAclInformation(IntPtr acl, ref AclSizeInformation information, uint informationLength, uint informationClass);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool InitializeAcl(IntPtr acl, uint aclLength, uint aclRevision);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool AddAce(IntPtr acl, uint aceRevision, uint startingAceIndex, IntPtr aceList, uint aceListLength);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool SetSecurityDescriptorDacl(IntPtr securityDescriptor, [MarshalAs(UnmanagedType.Bool)] bool daclPresent, IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] bool daclDefaulted);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetAce(IntPtr acl, uint aceIndex, out IntPtr ace);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsValidSecurityDescriptor(IntPtr securityDescriptor);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool InitializeSecurityDescriptor(IntPtr securityDescriptor, uint revision);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool SetSecurityDescriptorOwner(IntPtr securityDescriptor, IntPtr owner, [MarshalAs(UnmanagedType.Bool)] bool ownerDefaulted);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr LocalFree(IntPtr memory);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            internal static extern int lstrlenW(IntPtr stringPointer);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptOpenStorageProvider(out IntPtr provider, string providerName, uint flags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptCreatePersistedKey(IntPtr provider, out IntPtr key, string algorithm, string keyName, uint legacyKeySpec, uint flags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptSetProperty(IntPtr handle, string property, IntPtr input, uint inputLength, uint flags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptGetProperty(IntPtr handle, string property, IntPtr output, uint outputLength, out uint resultLength, uint flags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptFinalizeKey(IntPtr key, uint flags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptDeleteKey(IntPtr key, uint flags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptOpenKey(IntPtr provider, out IntPtr key, string keyName, uint legacyKeySpec, uint flags);

            [DllImport("ncrypt.dll")]
            internal static extern int NCryptFreeObject(IntPtr handle);
        }
    }
}
