using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

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
        public string Failure;
    }

    public static class Boundary
    {
        private static void Phase(string name)
        {
            Console.Out.WriteLine("windows_launcher_phase=" + name);
            Console.Out.Flush();
        }

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
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileListDirectory = 0x00000001;
        private const uint ReadControl = 0x00020000;
        private const uint WriteDac = 0x00040000;
        private const uint WriteOwner = 0x00080000;
        private const uint DeleteAccess = 0x00010000;
        private const uint AccessSystemSecurity = 0x01000000;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileAttributeReadOnly = 0x00000001;
        private const uint FileAllAccess = 0x001F01FF;
        private const uint ProcessQueryLimitedInformation = 0x1000;
        private const uint TokenAdjustPrivileges = 0x0020;
        private const uint SePrivilegeEnabled = 0x00000002;
        private const uint DaclSecurityInformation = 0x00000004;
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint LabelSecurityInformation = 0x00000010;
        private const uint UnprotectedDaclSecurityInformation = 0x2000;
        private const int SeFileObject = 1;
        private const uint AclSizeInformationClass = 2;
        private const uint AclRevision = 2;
        private const byte AccessAllowedAceType = 0;
        private const byte ObjectInheritAceFlag = 0x01;
        private const byte ContainerInheritAceFlag = 0x02;
        private const uint SystemMandatoryLabelNoWriteUp = 0x01;
        private const int FileBasicInfoClass = 0;
        private const int FileDispositionInfoClass = 4;
        private const int FileIdBothDirectoryInfoClass = 10;
        private const int ErrorNoMoreFiles = 18;
        private const int ErrorInvalidParameter = 87;
        private const int ErrorNotFound = 1168;
        private const int ErrorFileNotFound = 2;
        private const int ErrorPathNotFound = 3;
        private const int ErrorNotAllAssigned = 1300;
        private const int CleanupEntryLimit = 250000;
        private const int CleanupDeadlineMilliseconds = 600000;
        private const uint SecurityEnabled = 0x00000004;

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
        private struct FileTime
        {
            public uint Low;
            public uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public FileTime CreationTime;
            public FileTime LastAccessTime;
            public FileTime LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct AclSizeInformation
        {
            public uint AceCount;
            public uint AclBytesInUse;
            public uint AclBytesFree;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Luid
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LuidAndAttributes
        {
            public Luid Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenPrivileges
        {
            public uint PrivilegeCount;
            public LuidAndAttributes Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileBasicInformation
        {
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public long ChangeTime;
            public uint FileAttributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileDispositionInformation
        {
            public int DeleteFile;
        }

        private sealed class CleanupPathLease : IDisposable
        {
            public readonly List<SafeFileHandle> Handles;
            public readonly string FullPath;
            public readonly uint Attributes;
            public SafeFileHandle Target { get { return Handles[Handles.Count - 1]; } }

            public CleanupPathLease(List<SafeFileHandle> handles, string fullPath, uint attributes)
            {
                Handles = handles;
                FullPath = fullPath;
                Attributes = attributes;
            }

            public void Dispose()
            {
                for (int index = Handles.Count - 1; index >= 0; index--)
                    if (Handles[index] != null) Handles[index].Dispose();
            }
        }

        private sealed class CleanupTreeFrame
        {
            public string Path;
            public SafeFileHandle Handle;
            public uint Attributes;
            public List<string> Children;
            public int NextChild;
        }

        private sealed class PrivilegeScope : IDisposable
        {
            private readonly IntPtr token;
            private TokenPrivileges previous;

            public PrivilegeScope(IntPtr tokenHandle, TokenPrivileges previousState)
            {
                token = tokenHandle;
                previous = previousState;
            }

            public void Dispose()
            {
                if (token == IntPtr.Zero) return;
                if (!RestoreTokenPrivileges(token, false, ref previous, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    Close(token);
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                Close(token);
            }
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

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetAppContainerFolderPath(string appContainerSid, out IntPtr path);

        [DllImport("ole32.dll")]
        private static extern void CoTaskMemFree(IntPtr memory);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsValidSid(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string name, uint access, uint share, ref SecurityAttributes security,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateFileW", SetLastError = true)]
        private static extern SafeFileHandle CreateCleanupFile(string name, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass,
            IntPtr information, uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int informationClass,
            ref FileBasicInformation information, uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetFileInformationByHandle")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileDispositionByHandle(SafeFileHandle handle, int informationClass,
            ref FileDispositionInformation information, uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
            out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint SetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetAclInformation(IntPtr acl, out AclSizeInformation information,
            uint informationLength, uint informationClass);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetAce(IntPtr acl, uint index, out IntPtr ace);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeAcl(IntPtr acl, uint length, uint revision);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AddAce(IntPtr acl, uint revision, uint startingAceIndex,
            IntPtr aceList, uint aceListLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AddAccessAllowedAceEx(IntPtr acl, uint revision, uint aceFlags,
            uint accessMask, IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AddMandatoryAce(IntPtr acl, uint revision, uint aceFlags,
            uint policy, IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EqualSid(IntPtr first, IntPtr second);

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
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

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

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValueW(string systemName, string name, out Luid luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges newState,
            uint bufferLength, out TokenPrivileges previousState, out uint returnLength);

        [DllImport("advapi32.dll", EntryPoint = "AdjustTokenPrivileges", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RestoreTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges newState,
            uint bufferLength, IntPtr previousState, IntPtr returnLength);

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
            Phase("appcontainer-sid");
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

        public static string DeleteProfile(string name)
        {
            for (int attempt = 0; attempt < 4; attempt++)
            {
                int status = DeleteAppContainerProfile(name);
                if (status == 0 || unchecked((uint)status) == 0x80070002) return "deleted";
                string reason = CleanupReason(status);
                if (reason != "sharing-violation" || attempt == 3) return reason;
                System.Threading.Thread.Sleep(50 << attempt);
            }
            return "other";
        }

        public static string GetProfileFolderPath(string packageSid)
        {
            if (String.IsNullOrEmpty(packageSid)) throw new InvalidOperationException("profile_sid");
            IntPtr path = IntPtr.Zero;
            int status = GetAppContainerFolderPath(packageSid, out path);
            if (status != 0) Marshal.ThrowExceptionForHR(status);
            if (path == IntPtr.Zero) throw new InvalidOperationException("profile_path");
            try
            {
                string value = Marshal.PtrToStringUni(path);
                if (String.IsNullOrEmpty(value)) throw new InvalidOperationException("profile_path");
                return value;
            }
            finally { CoTaskMemFree(path); }
        }

        private static PrivilegeScope EnablePrivilege(string name)
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), TokenQuery | TokenAdjustPrivileges, out token)
                    || token == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                Luid luid;
                if (!LookupPrivilegeValueW(null, name, out luid)) throw new Win32Exception(Marshal.GetLastWin32Error());
                TokenPrivileges requested = new TokenPrivileges();
                requested.PrivilegeCount = 1;
                requested.Privileges.Luid = luid;
                requested.Privileges.Attributes = SePrivilegeEnabled;
                TokenPrivileges previous;
                uint returned;
                if (!AdjustTokenPrivileges(token, false, ref requested,
                    (uint)Marshal.SizeOf(typeof(TokenPrivileges)), out previous, out returned))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                int status = Marshal.GetLastWin32Error();
                if (status == ErrorNotAllAssigned) throw new Win32Exception(status);
                PrivilegeScope scope = new PrivilegeScope(token, previous);
                token = IntPtr.Zero;
                return scope;
            }
            finally
            {
                if (token != IntPtr.Zero) Close(token);
            }
        }

        public static void AssertCleanupQuiescent(string packageSid, string jobState)
        {
            if (jobState != "none" && jobState != "terminated-empty")
                throw new InvalidOperationException("cleanup_job_state");
            IntPtr expectedSid = IntPtr.Zero;
            try
            {
                if (String.IsNullOrEmpty(packageSid) || !ConvertStringSidToSidW(packageSid, out expectedSid)
                    || expectedSid == IntPtr.Zero || !IsValidSid(expectedSid))
                    throw new InvalidOperationException("cleanup_identity_sid");
                using (PrivilegeScope debugPrivilege = EnablePrivilege("SeDebugPrivilege"))
                {
                    Process[] processes = Process.GetProcesses();
                    if (processes == null || processes.Length > CleanupEntryLimit)
                        throw new InvalidOperationException("cleanup_process_enumeration");
                    Stopwatch timer = Stopwatch.StartNew();
                    try
                    {
                        foreach (Process item in processes)
                        {
                            if (timer.ElapsedMilliseconds > CleanupDeadlineMilliseconds)
                                throw new InvalidOperationException("cleanup_process_timeout");
                            uint processId;
                            try { processId = unchecked((uint)item.Id); }
                            catch { throw new InvalidOperationException("cleanup_process_enumeration"); }
                            if (processId == 0) continue;
                            IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
                            if (process == IntPtr.Zero)
                            {
                                int openError = Marshal.GetLastWin32Error();
                                if (openError == ErrorInvalidParameter || openError == ErrorNotFound
                                    || openError == ErrorFileNotFound || openError == ErrorPathNotFound) continue;
                                throw new InvalidOperationException("cleanup_process_inspection");
                            }
                            try
                            {
                                IntPtr token = IntPtr.Zero;
                                if (!OpenProcessToken(process, TokenQuery, out token) || token == IntPtr.Zero)
                                {
                                    if (WaitForSingleObject(process, 0) == WaitObject0) continue;
                                    throw new InvalidOperationException("cleanup_process_token");
                                }
                                try
                                {
                                    if (ReadTokenDword(token, TokenIsAppContainer) != 1) continue;
                                    IntPtr app = QueryToken(token, TokenAppContainerSid, out int appLength);
                                    try
                                    {
                                        if (appLength < IntPtr.Size || Marshal.ReadIntPtr(app) == IntPtr.Zero
                                            || !IsValidSid(Marshal.ReadIntPtr(app)))
                                            throw new InvalidOperationException("cleanup_process_identity");
                                        if (EqualSid(Marshal.ReadIntPtr(app), expectedSid))
                                        {
                                            if (ReadTokenDword(token, TokenIsLessPrivilegedAppContainer) != 1)
                                                throw new InvalidOperationException("cleanup_process_identity");
                                            throw new InvalidOperationException("cleanup_process_alive");
                                        }
                                    }
                                    finally { Marshal.FreeHGlobal(app); }
                                }
                                finally { Close(token); }
                            }
                            finally { Close(process); }
                        }
                    }
                    finally
                    {
                        foreach (Process item in processes) item.Dispose();
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("cleanup_processes");
            }
            finally
            {
                LocalFree(expectedSid);
            }
        }

        public static string RemoveTrackedGrant(string path, string packageSid, int accessMask, int inheritance,
            bool requireDirectory)
        {
            if (inheritance < 0 || inheritance > 3 || String.IsNullOrEmpty(packageSid))
                throw new InvalidOperationException("cleanup_grant_arguments");
            IntPtr sid = IntPtr.Zero;
            try
            {
                if (!ConvertStringSidToSidW(packageSid, out sid) || sid == IntPtr.Zero || !IsValidSid(sid))
                    throw new InvalidOperationException("cleanup_grant_sid");
                uint targetAccess = ReadControl | WriteDac | FileReadAttributes;
                CleanupPathLease lease;
                try { lease = OpenCleanupPath(path, targetAccess, requireDirectory); }
                catch (Win32Exception error)
                {
                    if (error.NativeErrorCode == ErrorFileNotFound || error.NativeErrorCode == ErrorPathNotFound)
                        return "missing";
                    throw;
                }
                using (lease)
                    RemoveAccessRuleFromHandle(lease.Target, sid, unchecked((uint)accessMask), (byte)inheritance);
                return "updated";
            }
            finally { LocalFree(sid); }
        }

        public static string RestoreIntegrityMedium(string path)
        {
            IntPtr mediumSid = IntPtr.Zero;
            IntPtr acl = IntPtr.Zero;
            try
            {
                if (!ConvertStringSidToSidW("S-1-16-8192", out mediumSid) || mediumSid == IntPtr.Zero
                    || !IsValidSid(mediumSid)) throw new InvalidOperationException("cleanup_integrity_sid");
                using (PrivilegeScope securityPrivilege = EnablePrivilege("SeSecurityPrivilege"))
                {
                    CleanupPathLease lease;
                    try { lease = OpenCleanupPath(path, ReadControl | WriteDac | AccessSystemSecurity | FileReadAttributes, true); }
                    catch (Win32Exception error)
                    {
                        if (error.NativeErrorCode == ErrorFileNotFound || error.NativeErrorCode == ErrorPathNotFound)
                            return "missing";
                        throw;
                    }
                    using (lease)
                    {
                        acl = Marshal.AllocHGlobal(1024);
                        if (!InitializeAcl(acl, 1024, AclRevision)) throw new Win32Exception(Marshal.GetLastWin32Error());
                        uint flags = (lease.Attributes & FileAttributeDirectory) != 0
                            ? (uint)(ObjectInheritAceFlag | ContainerInheritAceFlag) : 0U;
                        if (!AddMandatoryAce(acl, AclRevision, flags, SystemMandatoryLabelNoWriteUp, mediumSid))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        uint status = SetSecurityInfo(lease.Target, SeFileObject, LabelSecurityInformation,
                            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, acl);
                        if (status != 0) throw new Win32Exception((int)status);
                    }
                }
                return "updated";
            }
            finally
            {
                if (acl != IntPtr.Zero) Marshal.FreeHGlobal(acl);
                LocalFree(mediumSid);
            }
        }

        public static string RestoreAndDeleteAppContainerStorage(string root)
        {
            Stopwatch timer = Stopwatch.StartNew();
            IntPtr administratorsSid = IntPtr.Zero;
            try
            {
                if (!ConvertStringSidToSidW("S-1-5-32-544", out administratorsSid)
                    || administratorsSid == IntPtr.Zero || !IsValidSid(administratorsSid))
                    throw new InvalidOperationException("cleanup_admin_sid");
                CleanupPathLease rootLease;
                try
                {
                    rootLease = OpenCleanupPath(root,
                        ReadControl | WriteDac | WriteOwner | DeleteAccess | FileReadAttributes | FileListDirectory,
                        true);
                }
                catch (Win32Exception error)
                {
                    if (error.NativeErrorCode == ErrorFileNotFound || error.NativeErrorCode == ErrorPathNotFound)
                        return "missing";
                    throw;
                }
                using (rootLease)
                using (PrivilegeScope restorePrivilege = EnablePrivilege("SeRestorePrivilege"))
                {
                    Stack<CleanupTreeFrame> pending = new Stack<CleanupTreeFrame>();
                    CleanupTreeFrame rootFrame = new CleanupTreeFrame();
                    rootFrame.Path = rootLease.FullPath;
                    rootFrame.Handle = rootLease.Target;
                    rootFrame.Attributes = rootLease.Attributes;
                    pending.Push(rootFrame);
                    int entries = 0;
                    while (pending.Count > 0)
                    {
                        if (timer.ElapsedMilliseconds > CleanupDeadlineMilliseconds || entries > CleanupEntryLimit)
                            throw new InvalidOperationException("cleanup_tree_limit");
                        CleanupTreeFrame frame = pending.Peek();
                        if (frame.Children == null)
                        {
                            RestoreStorageEntry(frame.Handle, administratorsSid, frame.Attributes);
                            frame.Children = (frame.Attributes & FileAttributeDirectory) != 0
                                ? EnumerateCleanupChildren(frame.Handle, timer) : new List<string>();
                        }
                        if (frame.NextChild < frame.Children.Count)
                        {
                            string name = frame.Children[frame.NextChild++];
                            entries++;
                            if (entries > CleanupEntryLimit) throw new InvalidOperationException("cleanup_tree_limit");
                            string childPath = System.IO.Path.Combine(frame.Path, name);
                            SafeFileHandle child = OpenCleanupHandle(childPath,
                                ReadControl | WriteDac | WriteOwner | DeleteAccess | FileReadAttributes | FileListDirectory,
                                out uint attributes);
                            if ((attributes & FileAttributeReparsePoint) != 0)
                            {
                                child.Dispose();
                                throw new InvalidOperationException("cleanup_tree_reparse");
                            }
                            if ((attributes & FileAttributeDirectory) != 0)
                            {
                                if (pending.Count >= 1024)
                                {
                                    child.Dispose();
                                    throw new InvalidOperationException("cleanup_tree_depth");
                                }
                                CleanupTreeFrame childFrame = new CleanupTreeFrame();
                                childFrame.Path = childPath;
                                childFrame.Handle = child;
                                childFrame.Attributes = attributes;
                                pending.Push(childFrame);
                            }
                            else
                            {
                                RejectMultipleFileLinks(child);
                                RestoreStorageEntry(child, administratorsSid, attributes);
                                DeleteHandleEntry(child, attributes);
                                child.Dispose();
                            }
                        }
                        else
                        {
                            DeleteHandleEntry(frame.Handle, frame.Attributes);
                            pending.Pop();
                            if (pending.Count > 0) frame.Handle.Dispose();
                        }
                    }
                }
                return "deleted";
            }
            finally { LocalFree(administratorsSid); }
        }

        private static CleanupPathLease OpenCleanupPath(string path, uint targetAccess, bool requireDirectory)
        {
            if (String.IsNullOrWhiteSpace(path) || path.Length > 4096 || !System.IO.Path.IsPathRooted(path))
                throw new InvalidOperationException("cleanup_path");
            string fullPath = System.IO.Path.GetFullPath(path);
            string root = System.IO.Path.GetPathRoot(fullPath);
            if (String.IsNullOrEmpty(root) || root.Length != 3 || fullPath.StartsWith("\\\\", StringComparison.Ordinal)
                || fullPath.StartsWith("\\\\?\\", StringComparison.Ordinal)
                || fullPath.StartsWith("\\\\.\\", StringComparison.Ordinal))
                throw new InvalidOperationException("cleanup_path");
            List<SafeFileHandle> handles = new List<SafeFileHandle>();
            try
            {
                string remainder = fullPath.Substring(root.Length);
                string[] components = remainder.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                uint rootAccess = components.Length == 0 ? targetAccess : FileReadAttributes;
                SafeFileHandle rootHandle = OpenCleanupHandle(root, rootAccess, out uint rootAttributes);
                ValidateCleanupHandle(rootHandle, rootAttributes, true);
                handles.Add(rootHandle);
                string current = root;
                uint attributes = rootAttributes;
                for (int index = 0; index < components.Length; index++)
                {
                    current = System.IO.Path.Combine(current, components[index]);
                    bool final = index == components.Length - 1;
                    SafeFileHandle next = OpenCleanupHandle(current, final ? targetAccess : FileReadAttributes,
                        out attributes);
                    try { ValidateCleanupHandle(next, attributes, !final || requireDirectory); }
                    catch { next.Dispose(); throw; }
                    handles.Add(next);
                }
                return new CleanupPathLease(handles, fullPath, attributes);
            }
            catch
            {
                for (int index = handles.Count - 1; index >= 0; index--) handles[index].Dispose();
                throw;
            }
        }

        private static SafeFileHandle OpenCleanupHandle(string path, uint access, out uint attributes)
        {
            string extendedPath = path.StartsWith("\\\\?\\", StringComparison.Ordinal) ? path : "\\\\?\\" + path;
            SafeFileHandle handle = CreateCleanupFile(extendedPath, access, FileShareRead | FileShareWrite,
                IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint | FileFlagBackupSemantics, IntPtr.Zero);
            if (handle == null || handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                if (handle != null) handle.Dispose();
                throw new Win32Exception(error);
            }
            try
            {
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information)) throw new Win32Exception(Marshal.GetLastWin32Error());
                attributes = information.FileAttributes;
                ValidateCleanupHandle(handle, attributes, false);
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        private static void ValidateCleanupHandle(SafeFileHandle handle, uint attributes, bool requireDirectory)
        {
            if (handle == null || handle.IsInvalid || (attributes & FileAttributeReparsePoint) != 0
                || (requireDirectory && (attributes & FileAttributeDirectory) == 0))
                throw new InvalidOperationException("cleanup_reparse_or_type");
        }

        private static void RemoveAccessRuleFromHandle(SafeFileHandle handle, IntPtr targetSid,
            uint accessMask, byte inheritance)
        {
            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr securityDescriptor;
            uint status = GetSecurityInfo(handle, SeFileObject, DaclSecurityInformation,
                out owner, out group, out dacl, out sacl, out securityDescriptor);
            if (status != 0) throw new Win32Exception((int)status);
            IntPtr replacement = IntPtr.Zero;
            try
            {
                if (dacl == IntPtr.Zero) return;
                AclSizeInformation aclInfo;
                if (!GetAclInformation(dacl, out aclInfo, (uint)Marshal.SizeOf(typeof(AclSizeInformation)),
                    AclSizeInformationClass)) throw new Win32Exception(Marshal.GetLastWin32Error());
                int oldLength = unchecked((ushort)Marshal.ReadInt16(dacl, 2));
                if (oldLength < 8 || oldLength > 65535 || aclInfo.AceCount > 65535)
                    throw new InvalidOperationException("cleanup_acl_size");
                replacement = Marshal.AllocHGlobal(oldLength);
                uint revision = Marshal.ReadByte(dacl);
                if (revision < AclRevision) revision = AclRevision;
                if (!InitializeAcl(replacement, (uint)oldLength, revision))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                bool changed = false;
                for (uint index = 0; index < aclInfo.AceCount; index++)
                {
                    IntPtr ace;
                    if (!GetAce(dacl, index, out ace)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    int aceLength = unchecked((ushort)Marshal.ReadInt16(ace, 2));
                    if (aceLength < 8 || aceLength > oldLength) throw new InvalidOperationException("cleanup_ace_size");
                    byte[] bytes = new byte[aceLength];
                    Marshal.Copy(ace, bytes, 0, aceLength);
                    bool matching = bytes[0] == AccessAllowedAceType && bytes[1] == inheritance
                        && aceLength >= 16 && EqualSid(IntPtr.Add(ace, 8), targetSid);
                    if (matching)
                    {
                        uint existing = unchecked((uint)Marshal.ReadInt32(ace, 4));
                        uint remaining = existing & ~accessMask;
                        if (remaining != existing)
                        {
                            changed = true;
                            if (remaining == 0) continue;
                            Buffer.BlockCopy(BitConverter.GetBytes(remaining), 0, bytes, 4, 4);
                        }
                    }
                    IntPtr rawAce = Marshal.AllocHGlobal(aceLength);
                    try
                    {
                        Marshal.Copy(bytes, 0, rawAce, aceLength);
                        if (!AddAce(replacement, revision, UInt32.MaxValue, rawAce, (uint)aceLength))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    finally { Marshal.FreeHGlobal(rawAce); }
                }
                if (changed)
                {
                    status = SetSecurityInfo(handle, SeFileObject, DaclSecurityInformation,
                        IntPtr.Zero, IntPtr.Zero, replacement, IntPtr.Zero);
                    if (status != 0) throw new Win32Exception((int)status);
                }
            }
            finally
            {
                if (replacement != IntPtr.Zero) Marshal.FreeHGlobal(replacement);
                if (securityDescriptor != IntPtr.Zero) LocalFree(securityDescriptor);
            }
        }

        private static void RestoreStorageEntry(SafeFileHandle handle, IntPtr administratorsSid, uint attributes)
        {
            uint status = SetSecurityInfo(handle, SeFileObject, OwnerSecurityInformation,
                administratorsSid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (status != 0) throw new Win32Exception((int)status);
            IntPtr acl = Marshal.AllocHGlobal(1024);
            try
            {
                if (!InitializeAcl(acl, 1024, AclRevision)) throw new Win32Exception(Marshal.GetLastWin32Error());
                uint flags = (attributes & FileAttributeDirectory) != 0
                    ? (uint)(ObjectInheritAceFlag | ContainerInheritAceFlag) : 0U;
                if (!AddAccessAllowedAceEx(acl, AclRevision, flags, FileAllAccess, administratorsSid))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                status = SetSecurityInfo(handle, SeFileObject,
                    DaclSecurityInformation | UnprotectedDaclSecurityInformation,
                    IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                if (status != 0) throw new Win32Exception((int)status);
            }
            finally { Marshal.FreeHGlobal(acl); }
        }

        private static void RejectMultipleFileLinks(SafeFileHandle handle)
        {
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (information.NumberOfLinks != 1)
                throw new InvalidOperationException("cleanup_file_link_count");
        }

        private static List<string> EnumerateCleanupChildren(SafeFileHandle directory, Stopwatch timer)
        {
            List<string> children = new List<string>();
            IntPtr buffer = Marshal.AllocHGlobal(65536);
            try
            {
                while (true)
                {
                    if (timer.ElapsedMilliseconds > CleanupDeadlineMilliseconds)
                        throw new InvalidOperationException("cleanup_tree_timeout");
                    if (!GetFileInformationByHandleEx(directory, FileIdBothDirectoryInfoClass, buffer, 65536))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ErrorNoMoreFiles) break;
                        throw new Win32Exception(error);
                    }
                    int offset = 0;
                    while (true)
                    {
                        uint nextOffset = unchecked((uint)Marshal.ReadInt32(buffer, offset));
                        uint attributes = unchecked((uint)Marshal.ReadInt32(buffer, offset + 56));
                        int nameLength = Marshal.ReadInt32(buffer, offset + 60);
                        if (nameLength < 0 || (nameLength & 1) != 0 || nameLength > 65500)
                            throw new InvalidOperationException("cleanup_child_name");
                        string name = Marshal.PtrToStringUni(IntPtr.Add(buffer, offset + 104), nameLength / 2);
                        if (String.IsNullOrEmpty(name) || name == "." || name == ".."
                            || name.IndexOfAny(new char[] { '\\', '/', '\0' }) >= 0)
                            throw new InvalidOperationException("cleanup_child_name");
                        if ((attributes & FileAttributeReparsePoint) != 0)
                            throw new InvalidOperationException("cleanup_tree_reparse");
                        children.Add(name);
                        if (children.Count > CleanupEntryLimit || timer.ElapsedMilliseconds > CleanupDeadlineMilliseconds)
                            throw new InvalidOperationException("cleanup_tree_limit");
                        if (nextOffset == 0) break;
                        if (nextOffset < 104 || nextOffset > 65536 - offset)
                            throw new InvalidOperationException("cleanup_directory_entry");
                        offset = checked(offset + (int)nextOffset);
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return children;
        }

        private static void DeleteHandleEntry(SafeFileHandle handle, uint attributes)
        {
            if ((attributes & FileAttributeReadOnly) != 0)
            {
                FileBasicInformation basic = new FileBasicInformation();
                basic.FileAttributes = attributes & ~FileAttributeReadOnly;
                if (!SetFileInformationByHandle(handle, FileBasicInfoClass, ref basic,
                    (uint)Marshal.SizeOf(typeof(FileBasicInformation))))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            FileDispositionInformation disposition = new FileDispositionInformation();
            disposition.DeleteFile = 1;
            if (!SetFileDispositionByHandle(handle, FileDispositionInfoClass, ref disposition,
                (uint)Marshal.SizeOf(typeof(FileDispositionInformation))))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        private static string CleanupReason(int status)
        {
            uint value = unchecked((uint)status);
            uint code = (value & 0xffff0000U) == 0x80070000U ? value & 0xffffU : value;
            if (code == 32U || code == 33U) return "sharing-violation";
            if (code == 5U) return "access-denied";
            if (code == 2U || code == 3U) return "not-found";
            return "other";
        }

        public static RunResult Run(string profileName, string appContainerSid, string executable, string[] arguments,
            string workingDirectory, string[] environment, int timeoutMilliseconds, bool internetClient)
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
            IntPtr internetClientSid = IntPtr.Zero;
            IntPtr capabilityArray = IntPtr.Zero;
            IntPtr process = IntPtr.Zero;
            IntPtr thread = IntPtr.Zero;
            bool attributesReady = false;
            bool jobReaped = false;
            RunResult result = new RunResult();
            try
            {
                Phase("appcontainer-sid");
                if (DeriveAppContainerSidFromAppContainerName(profileName, out sid) != 0
                    || sid == IntPtr.Zero || SidText(sid) != appContainerSid) throw new InvalidOperationException("profile_sid_mismatch");
                SecurityAttributes security = new SecurityAttributes();
                security.Length = Marshal.SizeOf(typeof(SecurityAttributes));
                security.InheritHandle = true;
                nul = CreateFileW("NUL", GenericRead | GenericWrite, FileShareRead | FileShareWrite, ref security,
                    OpenExisting, FileAttributeNormal, IntPtr.Zero);
                if (nul == IntPtr.Zero || nul.ToInt64() == -1) throw new InvalidOperationException("nul_handle");

                Phase("job-create");
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
                Phase("token-create");
                SecurityCapabilities securityCapabilities = new SecurityCapabilities();
                securityCapabilities.AppContainerSid = sid;
                if (internetClient)
                {
                    if (!ConvertStringSidToSidW("S-1-15-3-1", out internetClientSid) || internetClientSid == IntPtr.Zero)
                        throw new InvalidOperationException("internet_capability_sid");
                    SidAndAttributes capability = new SidAndAttributes();
                    capability.Sid = internetClientSid;
                    capability.Attributes = SecurityEnabled;
                    capabilityArray = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SidAndAttributes)));
                    Marshal.StructureToPtr(capability, capabilityArray, false);
                    securityCapabilities.Capabilities = capabilityArray;
                    securityCapabilities.CapabilityCount = 1;
                }
                else
                {
                    securityCapabilities.Capabilities = IntPtr.Zero;
                    securityCapabilities.CapabilityCount = 0;
                }
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
                Phase("process-create-suspended");
                if (!CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true, flags,
                        environmentBlock, workingDirectory, ref startup, out information))
                {
                    result.Failure = "process-start-failed";
                    return result;
                }
                process = information.Process;
                thread = information.Thread;
                result.Created = true;
                Phase("job-assign");
                if (!AssignProcessToJobObject(job, process)) throw new InvalidOperationException("job_assign");
                result.Job = VerifyJob(job, process);
                result.AppContainer = VerifyToken(process, sid, internetClient);
                Phase("resume");
                if (ResumeThread(thread) == UInt32.MaxValue) throw new InvalidOperationException("thread_resume");
                Phase("wait");
                uint wait = WaitForSingleObject(process, (uint)timeoutMilliseconds);
                if (wait == WaitTimeout)
                {
                    result.TimedOut = true;
                    TerminateAndConfirmEmptyJob(job);
                    jobReaped = true;
                    if (WaitForSingleObject(process, 10000) != WaitObject0)
                        throw new InvalidOperationException("job_reap");
                }
                else if (wait != WaitObject0) throw new InvalidOperationException("process_wait");
                Phase("exit");
                if (!GetExitCodeProcess(process, out result.ExitCode)) throw new InvalidOperationException("process_exit_code");
                result.Exited = true;
                if (!jobReaped)
                {
                    TerminateAndConfirmEmptyJob(job);
                    jobReaped = true;
                }
                result.Job += " terminated=confirmed empty=confirmed";
                return result;
            }
            finally
            {
                string reapFailure = null;
                if (process != IntPtr.Zero && !result.Exited)
                {
                    if (job != IntPtr.Zero) TerminateJobObject(job, JobExitCode);
                    if (!TerminateProcess(process, JobExitCode) && WaitForSingleObject(process, 0) != WaitObject0)
                        reapFailure = "process_terminate";
                    if (WaitForSingleObject(process, 10000) != WaitObject0) reapFailure = "process_reap";
                }
                if (job != IntPtr.Zero && !jobReaped)
                {
                    bool terminated = TerminateJobObject(job, JobExitCode);
                    bool empty = WaitForEmptyJob(job, 10000);
                    if (!terminated || !empty) reapFailure = "job_reap";
                    else jobReaped = true;
                }
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
                Free(capabilityArray);
                if (internetClientSid != IntPtr.Zero) LocalFree(internetClientSid);
                Free(sid);
                if (reapFailure != null) throw new InvalidOperationException(reapFailure);
            }
        }

        private static void TerminateAndConfirmEmptyJob(IntPtr job)
        {
            if (job == IntPtr.Zero || !TerminateJobObject(job, JobExitCode))
                throw new InvalidOperationException("job_terminate");
            if (!WaitForEmptyJob(job, 10000)) throw new InvalidOperationException("job_reap");
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

        private static string VerifyToken(IntPtr process, IntPtr expectedSid, bool internetClient)
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
                    int expectedCount = internetClient ? 1 : 0;
                    if (capabilitiesLength < 4 || Marshal.ReadInt32(capabilities) != expectedCount)
                        throw new InvalidOperationException("token_capabilities");
                    if (internetClient)
                    {
                        int entryOffset = IntPtr.Size == 8 ? 8 : 4;
                        if (capabilitiesLength < entryOffset + Marshal.SizeOf(typeof(SidAndAttributes)))
                            throw new InvalidOperationException("token_capability_size");
                        SidAndAttributes entry = (SidAndAttributes)Marshal.PtrToStructure(
                            IntPtr.Add(capabilities, entryOffset), typeof(SidAndAttributes));
                        if (entry.Sid == IntPtr.Zero || SidText(entry.Sid) != "S-1-15-3-1"
                            || (entry.Attributes & SecurityEnabled) == 0)
                            throw new InvalidOperationException("token_capability_mismatch");
                    }
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
                return internetClient
                    ? "lpac=verified capabilities=internetClient integrity=low sid=verified"
                    : "lpac=verified capabilities=empty integrity=low sid=verified";
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
