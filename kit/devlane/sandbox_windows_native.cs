using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace KeelDock.Platform.DevLaneWindows
{
    public sealed class RunResult
    {
        public bool Created;
        public bool Exited;
        public bool TimedOut;
        public uint ExitCode;
        public string AppContainer;
        public string Job;
    }

    public static class Boundary
    {
        private const uint ProcThreadAttributeHandleList = 0x00020002;
        private const uint ProcThreadAttributeSecurityCapabilities = 0x00020009;
        private const uint ProcThreadAttributeAllApplicationPackagesPolicy = 0x0002000f;
        private const uint CreateSuspended = 0x00000004;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint StartfUseStdHandles = 0x00000100;
        private const uint JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectBasicProcessIdList = 3;
        private const uint JobObjectLimitActiveProcess = 0x00000008;
        private const uint JobObjectLimitProcessMemory = 0x00000100;
        private const uint JobObjectLimitJobMemory = 0x00000200;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private const uint JobLimitFlags = JobObjectLimitActiveProcess | JobObjectLimitProcessMemory | JobObjectLimitJobMemory | JobObjectLimitKillOnJobClose;
        private const uint TokenQuery = 0x0008;
        private const int TokenIntegrityLevel = 25;
        private const int TokenIsAppContainer = 29;
        private const int TokenCapabilities = 30;
        private const int TokenAppContainerSid = 31;
        private const int TokenIsLessPrivilegedAppContainer = 46;
        private const uint ErrorInsufficientBuffer = 122;
        private const int ErrorMoreData = 234;
        private const uint WaitObject0 = 0;
        private const uint WaitTimeout = 0x00000102;
        private const uint JobExitCode = 0x4b44574b;
        private const ulong ProcessMemoryLimit = 4294967296UL;
        private const ulong JobMemoryLimit = 12884901888UL;
        private const uint ActiveProcessLimit = 256;
        private const uint CreateNewConsole = 0x00000010;
        private const uint FileAttributeNormal = 0x00000080;
        private const uint OpenExisting = 3;
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint FileShareRead = 1;
        private const uint FileShareWrite = 2;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr AttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr Process;
            public IntPtr Thread;
            public uint ProcessId;
            public uint ThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityCapabilities
        {
            public IntPtr AppContainerSid;
            public IntPtr Capabilities;
            public uint CapabilityCount;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SidAndAttributes
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenAppContainerInformation
        {
            public IntPtr TokenAppContainer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation
        {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int CreateAppContainerProfile(string appContainerName, string displayName, string description,
            IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int DeriveAppContainerSidFromAppContainerName(string appContainerName, out IntPtr appContainerSid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int DeleteAppContainerProfile(string appContainerName);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsValidSid(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string name, uint access, uint share, ref SecurityAttributes security,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateJobObjectW(IntPtr security, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(IntPtr job, uint informationClass, IntPtr information, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(IntPtr job, uint informationClass, IntPtr information, uint length, out uint returned);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, IntPtr flags, ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, uint attribute, IntPtr value,
            UIntPtr size, IntPtr previous, IntPtr returned);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes,
            IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory,
            ref StartupInfoEx startup, out ProcessInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(IntPtr token, int informationClass, IntPtr information,
            int length, out int returned);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(IntPtr token, int informationClass, byte[] information,
            int length, out int returned);

        public static string CreateProfile(string name)
        {
            if (String.IsNullOrEmpty(name) || name.Length > 64) throw new InvalidOperationException("profile_name");
            IntPtr sid = IntPtr.Zero;
            int status = CreateAppContainerProfile(name, name, name, IntPtr.Zero, 0, out sid);
            if (status != 0 && unchecked((uint)status) != 0x800700b7) throw new InvalidOperationException("profile_create");
            if (sid == IntPtr.Zero && DeriveAppContainerSidFromAppContainerName(name, out sid) != 0) throw new InvalidOperationException("profile_lookup");
            try
            {
                if (sid == IntPtr.Zero || !IsValidSid(sid)) throw new InvalidOperationException("profile_sid");
                return SidText(sid);
            }
            finally { LocalFree(sid); }
        }

        public static bool DeleteProfile(string name)
        {
            int status = DeleteAppContainerProfile(name);
            return status == 0 || unchecked((uint)status) == 0x80070002;
        }

        public static RunResult Run(string profileName, string appContainerSid, string executable, string[] arguments,
            string workingDirectory, string[] environment, int timeoutMilliseconds)
        {
            if (String.IsNullOrEmpty(profileName) || String.IsNullOrEmpty(appContainerSid) || String.IsNullOrEmpty(executable)
                || String.IsNullOrEmpty(workingDirectory) || arguments == null || environment == null
                || timeoutMilliseconds < 1000 || timeoutMilliseconds > 10800000) throw new InvalidOperationException("run_arguments");
            IntPtr sid = IntPtr.Zero;
            IntPtr nul = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            IntPtr attributes = IntPtr.Zero;
            IntPtr capabilities = IntPtr.Zero;
            IntPtr policy = IntPtr.Zero;
            IntPtr handleList = IntPtr.Zero;
            IntPtr environmentBlock = IntPtr.Zero;
            IntPtr process = IntPtr.Zero;
            IntPtr thread = IntPtr.Zero;
            bool attributesReady = false;
            RunResult result = new RunResult();
            try
            {
                if (DeriveAppContainerSidFromAppContainerName(profileName, out sid) != 0
                    || sid == IntPtr.Zero || SidText(sid) != appContainerSid) throw new InvalidOperationException("profile_sid_mismatch");
                SecurityAttributes security = new SecurityAttributes();
                security.Length = Marshal.SizeOf(typeof(SecurityAttributes));
                security.InheritHandle = true;
                nul = CreateFileW("NUL", GenericRead | GenericWrite, FileShareRead | FileShareWrite, ref security,
                    OpenExisting, FileAttributeNormal, IntPtr.Zero);
                if (nul == IntPtr.Zero || nul.ToInt64() == -1) throw new InvalidOperationException("nul_handle");

                job = CreateJobObjectW(IntPtr.Zero, null);
                if (job == IntPtr.Zero) throw new InvalidOperationException("job_create");
                SetJobLimits(job);

                IntPtr required = IntPtr.Zero;
                if (InitializeProcThreadAttributeList(IntPtr.Zero, 3, IntPtr.Zero, ref required)
                    || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || required.ToInt64() < 1 || required.ToInt64() > 65536)
                    throw new InvalidOperationException("attribute_size");
                attributes = Marshal.AllocHGlobal(checked((int)required.ToInt64()));
                if (!InitializeProcThreadAttributeList(attributes, 3, IntPtr.Zero, ref required)) throw new InvalidOperationException("attribute_init");
                attributesReady = true;
                handleList = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(handleList, nul);
                if (!UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributeHandleList, handleList,
                        new UIntPtr((uint)IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) throw new InvalidOperationException("attribute_handles");
                SecurityCapabilities securityCapabilities = new SecurityCapabilities();
                securityCapabilities.AppContainerSid = sid;
                securityCapabilities.Capabilities = IntPtr.Zero;
                securityCapabilities.CapabilityCount = 0;
                capabilities = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityCapabilities)));
                Marshal.StructureToPtr(securityCapabilities, capabilities, false);
                if (!UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributeSecurityCapabilities, capabilities,
                        new UIntPtr((uint)Marshal.SizeOf(typeof(SecurityCapabilities))), IntPtr.Zero, IntPtr.Zero))
                    throw new InvalidOperationException("attribute_capabilities");
                policy = Marshal.AllocHGlobal(4);
                Marshal.WriteInt32(policy, 1);
                if (!UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributeAllApplicationPackagesPolicy, policy,
                        new UIntPtr(4), IntPtr.Zero, IntPtr.Zero)) throw new InvalidOperationException("attribute_lpac");

                StringBuilder block = BuildEnvironment(environment);
                environmentBlock = Marshal.StringToHGlobalUni(block.ToString());
                StartupInfoEx startup = new StartupInfoEx();
                startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(StartupInfoEx));
                startup.StartupInfo.dwFlags = StartfUseStdHandles;
                startup.StartupInfo.hStdInput = nul;
                startup.StartupInfo.hStdOutput = nul;
                startup.StartupInfo.hStdError = nul;
                startup.AttributeList = attributes;
                StringBuilder commandLine = new StringBuilder(Quote(executable));
                foreach (string argument in arguments) commandLine.Append(" ").Append(Quote(argument));
                if (commandLine.Length > 30000) throw new InvalidOperationException("command_size");
                ProcessInformation information;
                uint flags = ExtendedStartupInfoPresent | CreateSuspended | CreateUnicodeEnvironment;
                if (!CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true, flags,
                        environmentBlock, workingDirectory, ref startup, out information))
                    throw new InvalidOperationException("process_create");
                process = information.Process;
                thread = information.Thread;
                result.Created = true;
                if (!AssignProcessToJobObject(job, process)) throw new InvalidOperationException("job_assign");
                result.Job = VerifyJob(job, process);
                result.AppContainer = VerifyToken(process, sid);
                if (ResumeThread(thread) == UInt32.MaxValue) throw new InvalidOperationException("thread_resume");
                uint wait = WaitForSingleObject(process, (uint)timeoutMilliseconds);
                if (wait == WaitTimeout)
                {
                    result.TimedOut = true;
                    TerminateJobObject(job, JobExitCode);
                    if (WaitForSingleObject(process, 10000) != WaitObject0 || !WaitForEmptyJob(job, 10000))
                        throw new InvalidOperationException("job_reap");
                }
                else if (wait != WaitObject0) throw new InvalidOperationException("process_wait");
                if (!GetExitCodeProcess(process, out result.ExitCode)) throw new InvalidOperationException("process_exit_code");
                result.Exited = true;
                TerminateJobObject(job, JobExitCode);
                if (!WaitForEmptyJob(job, 10000)) throw new InvalidOperationException("job_reap");
                return result;
            }
            finally
            {
                if (job != IntPtr.Zero) TerminateJobObject(job, JobExitCode);
                Close(thread);
                Close(process);
                Close(job);
                Close(nul);
                if (attributesReady) DeleteProcThreadAttributeList(attributes);
                Free(attributes);
                Free(capabilities);
                Free(policy);
                Free(handleList);
                Free(environmentBlock);
                Free(sid);
            }
        }

        private static void SetJobLimits(IntPtr job)
        {
            ExtendedLimitInformation value = new ExtendedLimitInformation();
            value.BasicLimitInformation.LimitFlags = JobLimitFlags;
            value.BasicLimitInformation.ActiveProcessLimit = ActiveProcessLimit;
            value.ProcessMemoryLimit = new UIntPtr(ProcessMemoryLimit);
            value.JobMemoryLimit = new UIntPtr(JobMemoryLimit);
            int size = Marshal.SizeOf(typeof(ExtendedLimitInformation));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(value, buffer, false);
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size)) throw new InvalidOperationException("job_configure");
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static string VerifyJob(IntPtr job, IntPtr process)
        {
            bool inJob;
            if (!IsProcessInJob(process, job, out inJob) || !inJob) throw new InvalidOperationException("job_membership");
            int size = Marshal.SizeOf(typeof(ExtendedLimitInformation));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint returned;
                if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size, out returned) || returned < size)
                    throw new InvalidOperationException("job_readback");
                ExtendedLimitInformation actual = (ExtendedLimitInformation)Marshal.PtrToStructure(buffer, typeof(ExtendedLimitInformation));
                uint flags = actual.BasicLimitInformation.LimitFlags;
                if (flags != JobLimitFlags || actual.BasicLimitInformation.ActiveProcessLimit != ActiveProcessLimit
                    || actual.ProcessMemoryLimit.ToUInt64() != ProcessMemoryLimit || actual.JobMemoryLimit.ToUInt64() != JobMemoryLimit)
                    throw new InvalidOperationException("job_limits_mismatch");
                return "assigned kill_on_close=enabled breakaway=disabled active_processes=256 process_memory=4294967296 job_memory=12884901888";
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static bool WaitForEmptyJob(IntPtr job, int timeoutMilliseconds)
        {
            Stopwatch timer = Stopwatch.StartNew();
            int size = 8 + IntPtr.Size * (int)ActiveProcessLimit;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                while (timer.ElapsedMilliseconds <= timeoutMilliseconds)
                {
                    for (int offset = 0; offset < size; offset += IntPtr.Size)
                        Marshal.WriteIntPtr(buffer, offset, IntPtr.Zero);
                    uint returned;
                    if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (uint)size, out returned))
                    {
                        if (Marshal.GetLastWin32Error() != ErrorMoreData) return false;
                    }
                    else if (returned < 8 || Marshal.ReadInt32(buffer, 4) < 0) return false;
                    else if (Marshal.ReadInt32(buffer, 4) == 0) return true;
                    System.Threading.Thread.Sleep(100);
                }
                return false;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static string VerifyToken(IntPtr process, IntPtr expectedSid)
        {
            IntPtr token;
            if (!OpenProcessToken(process, TokenQuery, out token) || token == IntPtr.Zero) throw new InvalidOperationException("token_open");
            try
            {
                if (ReadTokenDword(token, TokenIsAppContainer) != 1
                    || ReadTokenDword(token, TokenIsLessPrivilegedAppContainer) != 1) throw new InvalidOperationException("token_lpac");
                IntPtr capabilities = QueryToken(token, TokenCapabilities, out int capabilitiesLength);
                try
                {
                    if (capabilitiesLength < 4 || Marshal.ReadInt32(capabilities) != 0) throw new InvalidOperationException("token_capabilities");
                }
                finally { Marshal.FreeHGlobal(capabilities); }
                IntPtr app = QueryToken(token, TokenAppContainerSid, out int appLength);
                try
                {
                    if (appLength < IntPtr.Size || Marshal.ReadIntPtr(app) == IntPtr.Zero
                        || !IsValidSid(Marshal.ReadIntPtr(app)) || SidText(Marshal.ReadIntPtr(app)) != SidText(expectedSid))
                        throw new InvalidOperationException("token_sid");
                }
                finally { Marshal.FreeHGlobal(app); }
                IntPtr integrity = QueryToken(token, TokenIntegrityLevel, out int integrityLength);
                try
                {
                    if (integrityLength < Marshal.SizeOf(typeof(SidAndAttributes))) throw new InvalidOperationException("token_integrity");
                    SidAndAttributes label = (SidAndAttributes)Marshal.PtrToStructure(integrity, typeof(SidAndAttributes));
                    IntPtr countAddress = GetSidSubAuthorityCount(label.Sid);
                    if (countAddress == IntPtr.Zero) throw new InvalidOperationException("token_integrity");
                    byte count = Marshal.ReadByte(countAddress);
                    if (count < 1) throw new InvalidOperationException("token_integrity");
                    IntPtr ridAddress = GetSidSubAuthority(label.Sid, (uint)(count - 1));
                    if (ridAddress == IntPtr.Zero || Marshal.ReadInt32(ridAddress) != 0x1000) throw new InvalidOperationException("token_integrity");
                }
                finally { Marshal.FreeHGlobal(integrity); }
                return "lpac=verified capabilities=empty integrity=low sid=verified";
            }
            finally { Close(token); }
        }

        private static IntPtr QueryToken(IntPtr token, int kind, out int length)
        {
            length = 0;
            GetTokenInformation(token, kind, IntPtr.Zero, 0, out length);
            if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || length < 4 || length > 65536)
                throw new InvalidOperationException("token_query");
            IntPtr buffer = Marshal.AllocHGlobal(length);
            if (!GetTokenInformation(token, kind, buffer, length, out length))
            {
                Marshal.FreeHGlobal(buffer);
                throw new InvalidOperationException("token_read");
            }
            return buffer;
        }

        private static uint ReadTokenDword(IntPtr token, int kind)
        {
            byte[] buffer = new byte[4];
            int returned;
            if (!GetTokenInformation(token, kind, buffer, buffer.Length, out returned) || returned != 4)
                throw new InvalidOperationException("token_read");
            return BitConverter.ToUInt32(buffer, 0);
        }

        private static StringBuilder BuildEnvironment(string[] entries)
        {
            if (entries.Length > 128) throw new InvalidOperationException("environment_count");
            List<string> sorted = new List<string>(entries);
            sorted.Sort(StringComparer.OrdinalIgnoreCase);
            StringBuilder block = new StringBuilder();
            foreach (string entry in sorted)
            {
                int separator = entry.IndexOf('=');
                if (separator < 1 || entry.IndexOf('\0') >= 0 || entry.IndexOf('\n') >= 0 || entry.IndexOf('\r') >= 0)
                    throw new InvalidOperationException("environment_entry");
                block.Append(entry).Append('\0');
            }
            block.Append('\0');
            if (block.Length > 131072) throw new InvalidOperationException("environment_size");
            return block;
        }

        private static string Quote(string value)
        {
            StringBuilder result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char character in value)
            {
                if (character == '\\') { slashes++; continue; }
                if (character == '"')
                {
                    result.Append('\\', slashes * 2 + 1).Append('"');
                    slashes = 0;
                    continue;
                }
                result.Append('\\', slashes).Append(character);
                slashes = 0;
            }
            result.Append('\\', slashes * 2).Append('"');
            return result.ToString();
        }

        private static string SidText(IntPtr sid)
        {
            IntPtr text;
            if (!ConvertSidToStringSidW(sid, out text) || text == IntPtr.Zero) throw new InvalidOperationException("sid_text");
            try { return Marshal.PtrToStringUni(text); }
            finally { LocalFree(text); }
        }

        private static void Close(IntPtr value)
        {
            if (value != IntPtr.Zero && value.ToInt64() != -1) CloseHandle(value);
        }

        private static void Free(IntPtr value)
        {
            if (value != IntPtr.Zero) Marshal.FreeHGlobal(value);
        }
    }
}
