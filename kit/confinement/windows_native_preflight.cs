using System;
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
        private const int TokenIntegrityLevel = 25;
        private const int TokenIsAppContainer = 29;
        private const int TokenCapabilities = 30;
        private const int TokenAppContainerSid = 31;
        private const int TokenIsLessPrivilegedAppContainer = 46;
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
        private const uint AclSizeInformation = 2;
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint DaclSecurityInformation = 0x00000004;
        private const uint NCryptSilentFlag = 0x00000040;
        private const int NtePermissionDenied = unchecked((int)0x80090010);
        private const int NteBadKeyset = unchecked((int)0x80090016);
        private const int HresultAlreadyExists = unchecked((int)0x800700b7);

        private const string SuccessLine = "windows-native-preflight=observed appcontainer=lpac token=verified capabilities=empty integrity=low job=assigned limits=verified termination=verified cng=p256-user nonexportable=verified acl=verified destruction=verified cleanup=verified";

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
                check = "cng_acl";
                state.VerifyKeyAcl();
                check = "cng_export";
                state.VerifyKeyExportDenial();
                completed = true;
            }
            catch
            {
                if (check == "child_launch")
                {
                    check = state.ChildLaunchCheck;
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
                return Refusal(check, true);
            }
            return SuccessLine;
        }

        private static string Refusal(string check, bool cleanupComplete)
        {
            return "windows-native-preflight=refused check=" + check + " reason=native_preflight_unavailable cleanup=" + (cleanupComplete ? "verified" : "incomplete");
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
            private IntPtr job = IntPtr.Zero;
            private IntPtr process = IntPtr.Zero;
            private IntPtr thread = IntPtr.Zero;
            private IntPtr childToken = IntPtr.Zero;
            private IntPtr currentToken = IntPtr.Zero;
            private bool processCreated;
            private bool processAssigned;
            private string childLaunchCheck = "child_attribute_list";
            private IntPtr provider = IntPtr.Zero;
            private IntPtr key = IntPtr.Zero;
            private string keyName;
            private bool keyOwned;

            internal string ChildLaunchCheck
            {
                get { return childLaunchCheck; }
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
                environmentBlock = Marshal.StringToHGlobalUni("KD_NATIVE_PREFLIGHT=1\0\0");
                Native.StartupInfoEx startup = new Native.StartupInfoEx();
                startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(Native.StartupInfoEx));
                startup.AttributeList = attributeList;
                StringBuilder commandLine = new StringBuilder("\"" + executable + "\" /d /c exit 0");
                Native.ProcessInformation processInformation = new Native.ProcessInformation();
                uint flags = ExtendedStartupInfoPresent | CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow;
                childLaunchCheck = "child_process_create";
                bool created = Native.CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, false, flags, environmentBlock, systemDirectory.ToString(), ref startup, ref processInformation);
                process = processInformation.Process;
                thread = processInformation.Thread;
                processCreated = process != IntPtr.Zero;
                if (!created || !processCreated || thread == IntPtr.Zero)
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
                if (!Native.OpenProcessToken(process, TokenQuery, out childToken) || childToken == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                if (ReadTokenDword(childToken, TokenIsAppContainer) != 1)
                {
                    throw new InvalidOperationException();
                }
                if (ReadTokenDword(childToken, TokenIsLessPrivilegedAppContainer) != 1)
                {
                    throw new InvalidOperationException();
                }

                IntPtr capabilityInformation = QueryTokenInformation(childToken, TokenCapabilities, out uint capabilityLength);
                try
                {
                    if (capabilityLength < 4 || Marshal.ReadInt32(capabilityInformation) != 0)
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(capabilityInformation);
                }

                IntPtr appContainerInformation = QueryTokenInformation(childToken, TokenAppContainerSid, out uint appContainerLength);
                try
                {
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

                IntPtr integrityInformation = QueryTokenInformation(childToken, TokenIntegrityLevel, out uint integrityLength);
                try
                {
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
                IntPtr exportPolicy = Marshal.AllocHGlobal(4);
                try
                {
                    Marshal.WriteInt32(exportPolicy, 0);
                    status = Native.NCryptSetProperty(key, "Export Policy", exportPolicy, 4, NCryptSilentFlag);
                    if (status != 0)
                    {
                        throw new InvalidOperationException();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(exportPolicy);
                }
                status = Native.NCryptFinalizeKey(key, NCryptSilentFlag);
                if (status != 0)
                {
                    throw new InvalidOperationException();
                }
                if (ReadKeyDword("Export Policy", NCryptSilentFlag) != 0 || ReadKeyDword("Key Type", NCryptSilentFlag) != 0 || ReadKeyDword("Length", NCryptSilentFlag) != 256)
                {
                    throw new InvalidOperationException();
                }
            }

            internal void VerifyKeyAcl()
            {
                if (ReadProviderDword("Security Descr Support") != 1)
                {
                    throw new InvalidOperationException();
                }
                IntPtr currentUserSid = IntPtr.Zero;
                IntPtr systemSid = IntPtr.Zero;
                IntPtr ownerDescriptor = IntPtr.Zero;
                IntPtr daclDescriptor = IntPtr.Zero;
                IntPtr userInformation = IntPtr.Zero;
                try
                {
                    if (!Native.OpenProcessToken(Native.GetCurrentProcess(), TokenQuery, out currentToken) || currentToken == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    userInformation = QueryTokenInformation(currentToken, TokenUser, out uint userLength);
                    if (userLength < (uint)IntPtr.Size)
                    {
                        throw new InvalidOperationException();
                    }
                    currentUserSid = Marshal.ReadIntPtr(userInformation);
                    if (currentUserSid == IntPtr.Zero || !Native.IsValidSid(currentUserSid))
                    {
                        throw new InvalidOperationException();
                    }
                    if (!Native.ConvertStringSidToSidW("S-1-5-18", out systemSid) || systemSid == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                ownerDescriptor = ReadSecurityDescriptor(key, OwnerSecurityInformation | NCryptSilentFlag);
                    IntPtr ownerSid;
                    bool ownerDefaulted;
                    if (!Native.GetSecurityDescriptorOwner(ownerDescriptor, out ownerSid, out ownerDefaulted) || ownerSid == IntPtr.Zero || !Native.EqualSid(ownerSid, currentUserSid))
                    {
                        throw new InvalidOperationException();
                    }
                    daclDescriptor = ReadSecurityDescriptor(key, DaclSecurityInformation | NCryptSilentFlag);
                    bool daclPresent;
                    bool daclDefaulted;
                    IntPtr dacl;
                    if (!Native.GetSecurityDescriptorDacl(daclDescriptor, out daclPresent, out dacl, out daclDefaulted) || !daclPresent || dacl == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    Native.AclSizeInformation aclInformation = new Native.AclSizeInformation();
                    if (!Native.GetAclInformation(dacl, ref aclInformation, (uint)Marshal.SizeOf(typeof(Native.AclSizeInformation)), AclSizeInformation) || aclInformation.AceCount == 0 || aclInformation.AceCount > 64)
                    {
                        throw new InvalidOperationException();
                    }
                    bool currentUserAllowed = false;
                    for (uint index = 0; index < aclInformation.AceCount; index++)
                    {
                        IntPtr ace;
                        if (!Native.GetAce(dacl, index, out ace) || ace == IntPtr.Zero)
                        {
                            throw new InvalidOperationException();
                        }
                        byte type = Marshal.ReadByte(ace, 0);
                        ushort aceSize = unchecked((ushort)Marshal.ReadInt16(ace, 2));
                        if ((type != AccessAllowedAceType && type != AccessDeniedAceType) || aceSize < 16)
                        {
                            throw new InvalidOperationException();
                        }
                        IntPtr aceSid = IntPtr.Add(ace, 8);
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
                            bool isUser = Native.EqualSid(aceSid, currentUserSid);
                            bool isSystem = Native.EqualSid(aceSid, systemSid);
                            if (!isUser && !isSystem)
                            {
                                throw new InvalidOperationException();
                            }
                            if (isUser)
                            {
                                currentUserAllowed = true;
                            }
                        }
                    }
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
                }
            }

            internal void VerifyKeyExportDenial()
            {
                if (ReadKeyDword("Export Policy", NCryptSilentFlag) != 0)
                {
                    throw new InvalidOperationException();
                }
                uint requiredBytes;
                int status = Native.NCryptExportKey(key, IntPtr.Zero, "ECCPRIVATEBLOB", IntPtr.Zero, IntPtr.Zero, 0, out requiredBytes, NCryptSilentFlag);
                if (status != NtePermissionDenied)
                {
                    throw new InvalidOperationException();
                }
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
                    if (status != 0 || returned != 4)
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

            [DllImport("userenv.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
            internal static extern int CreateAppContainerProfile(string appContainerName, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);

            [DllImport("userenv.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
            internal static extern int DeleteAppContainerProfile(string appContainerName);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetTokenInformation(IntPtr tokenHandle, int informationClass, IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsValidSid(IntPtr sid);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool EqualSid(IntPtr sid1, IntPtr sid2);

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
            internal static extern bool GetAce(IntPtr acl, uint aceIndex, out IntPtr ace);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsValidSecurityDescriptor(IntPtr securityDescriptor);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr LocalFree(IntPtr memory);

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
            internal static extern int NCryptExportKey(IntPtr key, IntPtr exportKey, string blobType, IntPtr parameters, IntPtr output, uint outputLength, out uint resultLength, uint flags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptDeleteKey(IntPtr key, uint flags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            internal static extern int NCryptOpenKey(IntPtr provider, out IntPtr key, string keyName, uint legacyKeySpec, uint flags);

            [DllImport("ncrypt.dll")]
            internal static extern int NCryptFreeObject(IntPtr handle);
        }
    }
}
