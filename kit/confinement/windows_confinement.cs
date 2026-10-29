using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace KeelDock.Platform.WindowsConfinement
{
    public static class NativeRegistryProbe
    {
        private const uint KeyQueryValue = 0x0001;
        private const uint ObjectCaseInsensitive = 0x00000040;

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            internal uint Length;
            internal IntPtr RootDirectory;
            internal IntPtr ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        public static bool IsKnownProbeId(string probeId)
        {
            try
            {
                ResolvePath(probeId);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string Probe(string probeId)
        {
            string path = ResolvePath(probeId);
            IntPtr pathBuffer = IntPtr.Zero;
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr attributesBuffer = IntPtr.Zero;
            IntPtr key = IntPtr.Zero;
            try
            {
                pathBuffer = Marshal.StringToHGlobalUni(path);
                UnicodeString name = new UnicodeString();
                name.Length = checked((ushort)(path.Length * 2));
                name.MaximumLength = checked((ushort)(name.Length + 2));
                name.Buffer = pathBuffer;
                nameBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(name, nameBuffer, false);
                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes));
                attributes.ObjectName = nameBuffer;
                attributes.Attributes = ObjectCaseInsensitive;
                attributesBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ObjectAttributes)));
                Marshal.StructureToPtr(attributes, attributesBuffer, false);
                uint status = Native.NtOpenKey(out key, KeyQueryValue, attributesBuffer);
                if (status == 0)
                {
                    if (key != IntPtr.Zero)
                    {
                        Native.NtClose(key);
                        key = IntPtr.Zero;
                    }
                    return "native-registry-probe id=" + probeId + " status=ok";
                }
                return "native-registry-probe id=" + probeId + " status=" + StatusName(status) + " ntstatus=0x" + status.ToString("X" + "8");
            }
            finally
            {
                if (key != IntPtr.Zero)
                {
                    Native.NtClose(key);
                }
                if (attributesBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(attributesBuffer);
                }
                if (nameBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(nameBuffer);
                }
                if (pathBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pathBuffer);
                }
            }
        }

        private static string ResolvePath(string probeId)
        {
            if (string.Equals(probeId, "winsock_parameters", StringComparison.Ordinal)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters"; }
            if (string.Equals(probeId, "winsock_protocol_catalog", StringComparison.Ordinal)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9"; }
            if (string.Equals(probeId, "winsock_namespace_catalog", StringComparison.Ordinal)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5"; }
            if (string.Equals(probeId, "winsock_protocol_entries", StringComparison.Ordinal)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries"; }
            if (string.Equals(probeId, "winsock_protocol_entries64", StringComparison.Ordinal)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64"; }
            if (string.Equals(probeId, "winsock_namespace_entries", StringComparison.Ordinal)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries"; }
            if (string.Equals(probeId, "winsock_namespace_entries64", StringComparison.Ordinal)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64"; }
            if (HasNumericSuffix(probeId, "winsock_protocol_entry_", 12)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\" + probeId.Substring("winsock_protocol_entry_".Length); }
            if (HasNumericSuffix(probeId, "winsock_protocol_entry64_", 12)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64\\" + probeId.Substring("winsock_protocol_entry64_".Length); }
            if (HasNumericSuffix(probeId, "winsock_namespace_entry_", 12)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\" + probeId.Substring("winsock_namespace_entry_".Length); }
            if (HasNumericSuffix(probeId, "winsock_namespace_entry64_", 12)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64\\" + probeId.Substring("winsock_namespace_entry64_".Length); }
            if (HasHexSuffix(probeId, "lpac_discriminator_arap_", 32)) { return "\\REGISTRY\\MACHINE\\SOFTWARE\\KeelDock\\ConfinementRecoveryTest\\" + probeId.Substring("lpac_discriminator_arap_".Length); }
            if (HasHexSuffix(probeId, "lpac_discriminator_aap_", 32)) { return "\\REGISTRY\\MACHINE\\SOFTWARE\\KeelDock\\ConfinementRecoveryTest\\" + probeId.Substring("lpac_discriminator_aap_".Length); }
            if (string.Equals(probeId, "lpac_default_key_control", StringComparison.Ordinal)) { return "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage"; }
            throw new InvalidOperationException("registry_probe_id");
        }

        private static bool HasNumericSuffix(string value, string prefix, int length)
        {
            if (string.IsNullOrEmpty(value) || !value.StartsWith(prefix, StringComparison.Ordinal) || value.Length != prefix.Length + length) { return false; }
            for (int index = prefix.Length; index < value.Length; ++index)
            {
                if (value[index] < '0' || value[index] > '9') { return false; }
            }
            return true;
        }

        private static bool HasHexSuffix(string value, string prefix, int length)
        {
            if (string.IsNullOrEmpty(value) || !value.StartsWith(prefix, StringComparison.Ordinal) || value.Length != prefix.Length + length) { return false; }
            for (int index = prefix.Length; index < value.Length; ++index)
            {
                char item = value[index];
                if (!((item >= '0' && item <= '9') || (item >= 'a' && item <= 'f'))) { return false; }
            }
            return true;
        }

        private static string StatusName(uint status)
        {
            switch (status)
            {
                case 0xC000000D: return "invalid_parameter";
                case 0xC0000022: return "access_denied";
                case 0xC0000034: return "object_name_not_found";
                case 0xC000003A: return "object_path_not_found";
                case 0xC000003B: return "object_path_syntax_bad";
                default: return "ntstatus";
            }
        }

        private static class Native
        {
            [DllImport("ntdll.dll", ExactSpelling = true)]
            internal static extern uint NtOpenKey(out IntPtr keyHandle, uint desiredAccess, IntPtr objectAttributes);

            [DllImport("ntdll.dll", ExactSpelling = true)]
            internal static extern uint NtClose(IntPtr handle);
        }
    }

    public sealed class RunResult
    {
        public string Failure = "";
        public string Detail = "";
        public bool Created;
        public uint CreateError;
        public bool TimedOut;
        public bool Exited;
        public uint ExitCode;
        public long ElapsedMs;
        public string Token = "none";
        public string Job = "none";
        public bool Truncated;
        public string Stdout = "";
        public string Stderr = "";
    }

    public static class NonPropagatingDacl
    {
        private const uint DaclSecurityInformation = 0x00000004;

        public static byte[] Read(string path)
        {
            uint needed = 0;
            bool first = GetFileSecurityW(path, DaclSecurityInformation, null, 0, out needed);
            int error = Marshal.GetLastWin32Error();
            if (first || error != 122 || needed == 0 || needed > 65536)
            {
                throw new InvalidOperationException("dacl_read_size error=" + error.ToString());
            }
            byte[] buffer = new byte[needed];
            if (!GetFileSecurityW(path, DaclSecurityInformation, buffer, needed, out needed))
            {
                throw new InvalidOperationException("dacl_read error=" + Marshal.GetLastWin32Error().ToString());
            }
            return buffer;
        }

        public static void Write(string path, byte[] descriptor)
        {
            if (descriptor == null || descriptor.Length == 0)
            {
                throw new InvalidOperationException("dacl_write_empty");
            }
            if (!SetFileSecurityW(path, DaclSecurityInformation, descriptor))
            {
                throw new InvalidOperationException("dacl_write error=" + Marshal.GetLastWin32Error().ToString());
            }
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileSecurityW(string fileName, uint requestedInformation, byte[] securityDescriptor, uint length, out uint lengthNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileSecurityW(string fileName, uint securityInformation, byte[] securityDescriptor);
    }

    public sealed class Sandbox : IDisposable
    {
        private const int ErrorInsufficientBuffer = 122;
        private const int HresultAlreadyExists = unchecked((int)0x800700b7);
        private const int MaxCaptureBytes = 262144;
        private const int MaxEnvironmentCharacters = 131072;
        private const int MaxCommandLineCharacters = 32767;
        private const uint TokenQuery = 0x0008;
        private const bool SpikeAllowUnreadableLpac = true;
        private const int TokenGroups = 2;
        private const int TokenRestrictedSids = 11;
        private const int TokenAppContainerSid = 31;
        private const string AllApplicationPackagesSid = "S-1-15-2-1";
        private const string AllRestrictedApplicationPackagesSid = "S-1-15-2-2";
        private const uint GroupEnabled = 0x00000004;
        private const int TokenIntegrityLevel = 25;
        private const int TokenIsAppContainer = 29;
        private const int TokenCapabilities = 30;
        private const int TokenIsLessPrivilegedAppContainer = 46;
        private const uint LowIntegrityRid = 0x00001000;
        private const uint ProcThreadAttributeHandleList = 0x00020002;
        private const uint ProcThreadAttributeSecurityCapabilities = 0x00020009;
        private const uint ProcThreadAttributeAllApplicationPackagesPolicy = 0x0002000f;
        private const uint ProcessCreationAllApplicationPackagesOptOut = 0x00000001;
        private const uint CreateSuspended = 0x00000004;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint CreateNoWindow = 0x08000000;
        private const uint StartfUseStdHandles = 0x00000100;
        private const uint HandleFlagInherit = 0x00000001;
        private const uint JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectLimitActiveProcess = 0x00000008;
        private const uint JobObjectLimitProcessMemory = 0x00000100;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private const uint JobObjectLimitBreakawayOk = 0x00000800;
        private const uint JobObjectLimitSilentBreakawayOk = 0x00001000;
        private const uint JobLimitFlags = JobObjectLimitActiveProcess | JobObjectLimitProcessMemory | JobObjectLimitKillOnJobClose;
        private const ulong ProcessMemoryLimitBytes = 3221225472UL;
        private const uint WaitObject0 = 0;
        private const uint WaitTimeout = 0x00000102;
        private const uint JobKillExitCode = 0x4b44574b;

        private string profileName;
        private IntPtr profileSid = IntPtr.Zero;
        private string sidText = "";
        private bool profileCreated;
        private bool cleanupComplete = true;

        public string SidText
        {
            get { return sidText; }
        }

        public static Sandbox Create()
        {
            Sandbox box = new Sandbox();
            try
            {
                box.CreateProfile();
            }
            catch
            {
                box.Dispose();
                throw;
            }
            return box;
        }

        public bool CleanupComplete
        {
            get { return cleanupComplete; }
        }

        public void Dispose()
        {
            if (profileCreated)
            {
                int result = Native.DeleteAppContainerProfile(profileName);
                if (result != 0)
                {
                    Thread.Sleep(250);
                    result = Native.DeleteAppContainerProfile(profileName);
                }
                if (result != 0)
                {
                    cleanupComplete = false;
                }
                profileCreated = false;
            }
            if (profileSid != IntPtr.Zero)
            {
                Native.FreeSid(profileSid);
                profileSid = IntPtr.Zero;
            }
        }

        private void CreateProfile()
        {
            profileName = "KDW" + Guid.NewGuid().ToString("N");
            int result = Native.CreateAppContainerProfile(profileName, "Synthetic", "Synthetic", IntPtr.Zero, 0, out profileSid);
            if (result != 0)
            {
                throw new InvalidOperationException("profile_create hresult=" + result.ToString("x8"));
            }
            profileCreated = true;
            if (profileSid == IntPtr.Zero || !Native.IsValidSid(profileSid))
            {
                throw new InvalidOperationException("profile_sid_invalid");
            }
            IntPtr text;
            if (!Native.ConvertSidToStringSidW(profileSid, out text) || text == IntPtr.Zero)
            {
                throw new InvalidOperationException("profile_sid_text");
            }
            try
            {
                sidText = Marshal.PtrToStringUni(text);
            }
            finally
            {
                Native.LocalFree(text);
            }
            if (string.IsNullOrEmpty(sidText) || !sidText.StartsWith("S-1-15-2-", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("profile_sid_shape");
            }
        }

        public RunResult Run(bool confined, string executable, string commandLine, string workingDirectory, string[] environment, int timeoutMs, uint maxProcesses)
        {
            RunResult result = new RunResult();
            IntPtr job = IntPtr.Zero;
            IntPtr process = IntPtr.Zero;
            IntPtr thread = IntPtr.Zero;
            IntPtr outRead = IntPtr.Zero;
            IntPtr outWrite = IntPtr.Zero;
            IntPtr errRead = IntPtr.Zero;
            IntPtr errWrite = IntPtr.Zero;
            IntPtr attributeBuffer = IntPtr.Zero;
            IntPtr capabilitiesBuffer = IntPtr.Zero;
            IntPtr policyBuffer = IntPtr.Zero;
            IntPtr handleBuffer = IntPtr.Zero;
            IntPtr environmentBlock = IntPtr.Zero;
            bool attributeListInitialized = false;
            bool assigned = false;
            Capture outCapture = new Capture();
            Capture errCapture = new Capture();
            Thread outThread = null;
            Thread errThread = null;
            Stopwatch clock = Stopwatch.StartNew();
            try
            {
                result.Failure = "arguments";
                if (string.IsNullOrEmpty(executable) || string.IsNullOrEmpty(commandLine) || string.IsNullOrEmpty(workingDirectory)
                    || commandLine.Length > MaxCommandLineCharacters || environment == null || timeoutMs < 1 || maxProcesses < 1)
                {
                    throw new InvalidOperationException();
                }
                string[] entries = (string[])environment.Clone();
                Array.Sort(entries, StringComparer.OrdinalIgnoreCase);
                string block = string.Join("\0", entries) + "\0\0";
                if (block.Length > MaxEnvironmentCharacters)
                {
                    throw new InvalidOperationException();
                }

                result.Failure = "job";
                job = CreateJob(maxProcesses);

                result.Failure = "pipes";
                CreateCapturePipe(out outRead, out outWrite);
                CreateCapturePipe(out errRead, out errWrite);

                result.Failure = "attributes";
                int attributeCount = confined ? 3 : 1;
                IntPtr requiredSize = IntPtr.Zero;
                bool first = Native.InitializeProcThreadAttributeList(IntPtr.Zero, attributeCount, IntPtr.Zero, ref requiredSize);
                if (first || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || requiredSize.ToInt64() <= 0 || requiredSize.ToInt64() > 65536)
                {
                    throw new InvalidOperationException();
                }
                attributeBuffer = Marshal.AllocHGlobal(checked((int)requiredSize.ToInt64()));
                if (!Native.InitializeProcThreadAttributeList(attributeBuffer, attributeCount, IntPtr.Zero, ref requiredSize))
                {
                    throw new InvalidOperationException();
                }
                attributeListInitialized = true;

                handleBuffer = Marshal.AllocHGlobal(IntPtr.Size * 2);
                Marshal.WriteIntPtr(handleBuffer, 0, outWrite);
                Marshal.WriteIntPtr(handleBuffer, IntPtr.Size, errWrite);
                if (!Native.UpdateProcThreadAttribute(attributeBuffer, 0, ProcThreadAttributeHandleList, handleBuffer, new UIntPtr((uint)(IntPtr.Size * 2)), IntPtr.Zero, IntPtr.Zero))
                {
                    throw new InvalidOperationException();
                }
                if (confined)
                {
                    Native.SecurityCapabilities capabilities = new Native.SecurityCapabilities();
                    capabilities.AppContainerSid = profileSid;
                    capabilities.Capabilities = IntPtr.Zero;
                    capabilities.CapabilityCount = 0;
                    capabilities.Reserved = 0;
                    int capabilitiesSize = Marshal.SizeOf(typeof(Native.SecurityCapabilities));
                    capabilitiesBuffer = Marshal.AllocHGlobal(capabilitiesSize);
                    Marshal.StructureToPtr(capabilities, capabilitiesBuffer, false);
                    if (!Native.UpdateProcThreadAttribute(attributeBuffer, 0, ProcThreadAttributeSecurityCapabilities, capabilitiesBuffer, new UIntPtr((uint)capabilitiesSize), IntPtr.Zero, IntPtr.Zero))
                    {
                        throw new InvalidOperationException();
                    }
                    policyBuffer = Marshal.AllocHGlobal(4);
                    Marshal.WriteInt32(policyBuffer, unchecked((int)ProcessCreationAllApplicationPackagesOptOut));
                    if (!Native.UpdateProcThreadAttribute(attributeBuffer, 0, ProcThreadAttributeAllApplicationPackagesPolicy, policyBuffer, new UIntPtr(4), IntPtr.Zero, IntPtr.Zero))
                    {
                        throw new InvalidOperationException();
                    }
                }

                result.Failure = "create";
                environmentBlock = Marshal.StringToHGlobalUni(block);
                Native.StartupInfoEx startup = new Native.StartupInfoEx();
                startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(Native.StartupInfoEx));
                startup.StartupInfo.dwFlags = StartfUseStdHandles;
                startup.StartupInfo.hStdInput = IntPtr.Zero;
                startup.StartupInfo.hStdOutput = outWrite;
                startup.StartupInfo.hStdError = errWrite;
                startup.AttributeList = attributeBuffer;
                StringBuilder mutableCommandLine = new StringBuilder(commandLine, commandLine.Length + 1);
                Native.ProcessInformation information = new Native.ProcessInformation();
                uint flags = ExtendedStartupInfoPresent | CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow;
                bool created = Native.CreateProcessW(executable, mutableCommandLine, IntPtr.Zero, IntPtr.Zero, true, flags, environmentBlock, workingDirectory, ref startup, ref information);
                if (!created)
                {
                    result.CreateError = unchecked((uint)Marshal.GetLastWin32Error());
                    throw new InvalidOperationException();
                }
                process = information.Process;
                thread = information.Thread;
                result.Created = true;
                CloseOne(ref outWrite);
                CloseOne(ref errWrite);

                result.Failure = "assign";
                if (!Native.AssignProcessToJobObject(job, process))
                {
                    result.CreateError = unchecked((uint)Marshal.GetLastWin32Error());
                    throw new InvalidOperationException();
                }
                assigned = true;

                result.Failure = "job_readback";
                result.Job = ReadJob(job, process, maxProcesses);

                result.Failure = "token";
                result.Token = ReadToken(process, confined, profileSid);

                result.Failure = "readers";
                outThread = new Thread(Pump);
                outThread.IsBackground = true;
                outThread.Start(new PumpState(outRead, outCapture));
                errThread = new Thread(Pump);
                errThread.IsBackground = true;
                errThread.Start(new PumpState(errRead, errCapture));

                result.Failure = "resume";
                if (Native.ResumeThread(thread) == uint.MaxValue)
                {
                    throw new InvalidOperationException();
                }

                result.Failure = "wait";
                uint wait = Native.WaitForSingleObject(process, (uint)timeoutMs);
                if (wait == WaitTimeout)
                {
                    result.TimedOut = true;
                    Native.TerminateJobObject(job, JobKillExitCode);
                    Native.WaitForSingleObject(process, 10000);
                }
                else if (wait != WaitObject0)
                {
                    throw new InvalidOperationException();
                }
                uint exitCode;
                if (!Native.GetExitCodeProcess(process, out exitCode))
                {
                    throw new InvalidOperationException();
                }
                result.ExitCode = exitCode;
                result.Exited = true;
                Native.TerminateJobObject(job, JobKillExitCode);
                result.Failure = "";
            }
            catch (Exception failure)
            {
                if (result.Failure.Length == 0)
                {
                    result.Failure = "internal";
                }
                string message = failure.Message == null ? "" : failure.Message;
                result.Detail = message.Length > 200 ? message.Substring(0, 200) : message;
            }
            finally
            {
                if (job != IntPtr.Zero)
                {
                    Native.TerminateJobObject(job, JobKillExitCode);
                }
                else if (process != IntPtr.Zero)
                {
                    Native.TerminateProcess(process, JobKillExitCode);
                }
                if (process != IntPtr.Zero && !assigned && job != IntPtr.Zero)
                {
                    Native.TerminateProcess(process, JobKillExitCode);
                }
                CloseOne(ref outWrite);
                CloseOne(ref errWrite);
                bool outJoined = JoinReader(outThread);
                bool errJoined = JoinReader(errThread);
                if (outJoined)
                {
                    CloseOne(ref outRead);
                }
                if (errJoined)
                {
                    CloseOne(ref errRead);
                }
                if (!outJoined || !errJoined)
                {
                    result.Failure = "reader_join";
                }
                CloseOne(ref thread);
                CloseOne(ref process);
                CloseOne(ref job);
                if (attributeListInitialized)
                {
                    Native.DeleteProcThreadAttributeList(attributeBuffer);
                }
                FreeOne(ref attributeBuffer);
                FreeOne(ref capabilitiesBuffer);
                FreeOne(ref policyBuffer);
                FreeOne(ref handleBuffer);
                FreeOne(ref environmentBlock);
                clock.Stop();
            }
            result.ElapsedMs = clock.ElapsedMilliseconds;
            result.Stdout = outCapture.Text();
            result.Stderr = errCapture.Text();
            result.Truncated = outCapture.Truncated || errCapture.Truncated;
            return result;
        }

        private static IntPtr CreateJob(uint maxProcesses)
        {
            IntPtr job = Native.CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                throw new InvalidOperationException();
            }
            Native.ExtendedLimitInformation information = new Native.ExtendedLimitInformation();
            information.BasicLimitInformation.LimitFlags = JobLimitFlags;
            information.BasicLimitInformation.ActiveProcessLimit = maxProcesses;
            information.ProcessMemoryLimit = new UIntPtr(ProcessMemoryLimitBytes);
            int size = Marshal.SizeOf(typeof(Native.ExtendedLimitInformation));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(information, buffer, false);
                if (!Native.SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size))
                {
                    Native.CloseHandle(job);
                    throw new InvalidOperationException();
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return job;
        }

        private static string ReadJob(IntPtr job, IntPtr process, uint maxProcesses)
        {
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
                Native.ExtendedLimitInformation actual = (Native.ExtendedLimitInformation)Marshal.PtrToStructure(buffer, typeof(Native.ExtendedLimitInformation));
                bool killOnClose = (actual.BasicLimitInformation.LimitFlags & JobObjectLimitKillOnJobClose) != 0;
                bool breakaway = (actual.BasicLimitInformation.LimitFlags & (JobObjectLimitBreakawayOk | JobObjectLimitSilentBreakawayOk)) != 0;
                bool exact = actual.BasicLimitInformation.LimitFlags == JobLimitFlags
                    && actual.BasicLimitInformation.ActiveProcessLimit == maxProcesses
                    && actual.ProcessMemoryLimit.ToUInt64() == ProcessMemoryLimitBytes;
                if (!killOnClose || breakaway || !exact)
                {
                    throw new InvalidOperationException();
                }
                return "assigned breakaway=disabled kill_on_close=enabled limits=verified";
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string ReadToken(IntPtr process, bool confined, IntPtr expectedSid)
        {
            IntPtr token;
            if (!Native.OpenProcessToken(process, TokenQuery, out token) || token == IntPtr.Zero)
            {
                throw new InvalidOperationException();
            }
            try
            {
                uint isAppContainer = ReadTokenDword(token, TokenIsAppContainer);
                uint integrity = ReadIntegrityRid(token);
                if (!confined)
                {
                    if (isAppContainer != 0)
                    {
                        throw new InvalidOperationException();
                    }
                    return "appcontainer=0 integrity=0x" + integrity.ToString("x4");
                }
                uint capabilityCount = ReadCapabilityCount(token);
                string lpac = "unreadable";
                try
                {
                    lpac = ReadTokenDword(token, TokenIsLessPrivilegedAppContainer) == 1 ? "1" : "0";
                }
                catch
                {
                    lpac = "unreadable";
                }
                string sidState = ReadContainerSidMatches(token, expectedSid) ? "match" : "mismatch";
                string restrictedApplicationPackages = ReadAllRestrictedApplicationPackagesState(token);
                string applicationPackages = ReadAllApplicationPackagesState(token);
                string reported = lpac;
                if (lpac != "1" && SpikeAllowUnreadableLpac && lpac == "unreadable" && sidState == "match"
                    && applicationPackages == "absent")
                {
                    reported = "aap_only";
                }
                string text = "appcontainer=" + isAppContainer.ToString() + " capabilities=" + capabilityCount.ToString()
                    + " integrity=0x" + integrity.ToString("x4") + " lpac=" + reported + " sid=" + sidState
                    + " arap=" + restrictedApplicationPackages + " aap=" + applicationPackages;
                if (isAppContainer != 1 || capabilityCount != 0 || integrity != LowIntegrityRid || (lpac != "1" && reported != "aap_only")
                    || sidState != "match" || (lpac == "1" && restrictedApplicationPackages != "present") || applicationPackages != "absent")
                {
                    throw new InvalidOperationException(text);
                }
                return text;
            }
            finally
            {
                Native.CloseHandle(token);
            }
        }

        private static bool ReadContainerSidMatches(IntPtr token, IntPtr expectedSid)
        {
            uint length;
            IntPtr buffer = QueryTokenInformation(token, TokenAppContainerSid, out length);
            try
            {
                if (length < (uint)IntPtr.Size)
                {
                    return false;
                }
                IntPtr actual = Marshal.ReadIntPtr(buffer);
                return actual != IntPtr.Zero && Native.IsValidSid(actual) && Native.EqualSid(actual, expectedSid);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string ReadAllApplicationPackagesState(IntPtr token)
        {
            bool inGroups = ReadSidInTokenSet(token, TokenGroups, AllApplicationPackagesSid, false);
            bool inRestrictedSids = ReadSidInTokenSet(token, TokenRestrictedSids, AllApplicationPackagesSid, false);
            return inGroups || inRestrictedSids ? "present" : "absent";
        }

        private static string ReadAllRestrictedApplicationPackagesState(IntPtr token)
        {
            bool inGroups = ReadSidInTokenSet(token, TokenGroups, AllRestrictedApplicationPackagesSid, true);
            bool inRestrictedSids = ReadSidInTokenSet(token, TokenRestrictedSids, AllRestrictedApplicationPackagesSid, false);
            return inGroups || inRestrictedSids ? "present" : "absent";
        }

        private static bool ReadSidInTokenSet(IntPtr token, int informationClass, string expectedSid, bool requireEnabled)
        {
            uint length;
            IntPtr buffer = QueryTokenInformation(token, informationClass, out length);
            try
            {
                int groupOffset = IntPtr.Size;
                int entrySize = IntPtr.Size * 2;
                if (length < 4)
                {
                    throw new InvalidOperationException();
                }
                uint count = unchecked((uint)Marshal.ReadInt32(buffer));
                if (count > 1024 || (ulong)length < (ulong)groupOffset + (ulong)count * (ulong)entrySize)
                {
                    throw new InvalidOperationException();
                }
                for (uint index = 0; index < count; ++index)
                {
                    int offset = groupOffset + (int)index * entrySize;
                    IntPtr sid = Marshal.ReadIntPtr(buffer, offset);
                    uint attributes = unchecked((uint)Marshal.ReadInt32(buffer, offset + IntPtr.Size));
                    if (sid == IntPtr.Zero || (requireEnabled && (attributes & GroupEnabled) == 0))
                    {
                        continue;
                    }
                    IntPtr text;
                    if (!Native.ConvertSidToStringSidW(sid, out text) || text == IntPtr.Zero)
                    {
                        throw new InvalidOperationException();
                    }
                    string value;
                    try
                    {
                        value = Marshal.PtrToStringUni(text);
                    }
                    finally
                    {
                        Native.LocalFree(text);
                    }
                    if (string.Equals(value, expectedSid, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static uint ReadCapabilityCount(IntPtr token)
        {
            uint length;
            IntPtr buffer = QueryTokenInformation(token, TokenCapabilities, out length);
            try
            {
                if (length < 4)
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

        private static uint ReadIntegrityRid(IntPtr token)
        {
            uint length;
            IntPtr buffer = QueryTokenInformation(token, TokenIntegrityLevel, out length);
            try
            {
                if (length < (uint)IntPtr.Size)
                {
                    throw new InvalidOperationException();
                }
                IntPtr sid = Marshal.ReadIntPtr(buffer);
                if (sid == IntPtr.Zero || !Native.IsValidSid(sid))
                {
                    throw new InvalidOperationException();
                }
                IntPtr countPointer = Native.GetSidSubAuthorityCount(sid);
                if (countPointer == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                byte count = Marshal.ReadByte(countPointer);
                if (count == 0)
                {
                    throw new InvalidOperationException();
                }
                IntPtr rid = Native.GetSidSubAuthority(sid, (uint)(count - 1));
                if (rid == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                return unchecked((uint)Marshal.ReadInt32(rid));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static uint ReadTokenDword(IntPtr token, int informationClass)
        {
            uint length;
            IntPtr buffer = QueryTokenInformation(token, informationClass, out length);
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
            returnedLength = 0;
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

        private static void CreateCapturePipe(out IntPtr read, out IntPtr write)
        {
            Native.SecurityAttributes attributes = new Native.SecurityAttributes();
            attributes.Length = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes));
            attributes.SecurityDescriptor = IntPtr.Zero;
            attributes.InheritHandle = 1;
            if (!Native.CreatePipe(out read, out write, ref attributes, 65536))
            {
                read = IntPtr.Zero;
                write = IntPtr.Zero;
                throw new InvalidOperationException();
            }
            if (!Native.SetHandleInformation(read, HandleFlagInherit, 0))
            {
                throw new InvalidOperationException();
            }
        }

        private sealed class Capture
        {
            private readonly byte[] buffer = new byte[MaxCaptureBytes];
            private int length;
            private bool truncated;

            internal bool Truncated
            {
                get { return truncated; }
            }

            internal void Append(byte[] chunk, int count)
            {
                int room = buffer.Length - length;
                int take = count < room ? count : room;
                if (take > 0)
                {
                    Buffer.BlockCopy(chunk, 0, buffer, length, take);
                    length += take;
                }
                if (take < count)
                {
                    truncated = true;
                }
            }

            internal string Text()
            {
                return Encoding.UTF8.GetString(buffer, 0, length);
            }
        }

        private sealed class PumpState
        {
            internal readonly IntPtr Handle;
            internal readonly Capture Target;

            internal PumpState(IntPtr handle, Capture target)
            {
                Handle = handle;
                Target = target;
            }
        }

        private static void Pump(object state)
        {
            PumpState pump = (PumpState)state;
            byte[] chunk = new byte[4096];
            try
            {
                using (FileStream stream = new FileStream(new SafeFileHandle(pump.Handle, false), FileAccess.Read, 4096, false))
                {
                    while (true)
                    {
                        int count = stream.Read(chunk, 0, chunk.Length);
                        if (count <= 0)
                        {
                            break;
                        }
                        pump.Target.Append(chunk, count);
                    }
                }
            }
            catch
            {
            }
        }

        private static bool JoinReader(Thread reader)
        {
            return reader == null || reader.Join(15000);
        }

        private static void CloseOne(ref IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                Native.CloseHandle(handle);
                handle = IntPtr.Zero;
            }
        }

        private static void FreeOne(ref IntPtr buffer)
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }
        }

        private static class Native
        {
            [StructLayout(LayoutKind.Sequential)]
            internal struct SecurityAttributes
            {
                internal uint Length;
                internal IntPtr SecurityDescriptor;
                internal int InheritHandle;
            }

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
            internal static extern IntPtr FreeSid(IntPtr sid);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool EqualSid(IntPtr sid1, IntPtr sid2);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr LocalFree(IntPtr memory);

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
            internal static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern uint ResumeThread(IntPtr thread);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseHandle(IntPtr handle);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SecurityAttributes attributes, uint size);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

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
        }
    }
}
