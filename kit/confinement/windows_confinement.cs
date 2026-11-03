using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace KeelDock.Platform.WindowsConfinement
{
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
        public ulong PeakProcessMemory;
        public ulong PeakJobMemory;
        public ulong CpuMs;
        public uint HandleCount;
        public string Class46 = "unreadable";
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

    public sealed class DeviceLease
    {
        private const string NulPath = "\\\\.\\NUL";
        private const uint NulMask = 0x0012019F;
        private const string MountManagerPath = "\\\\.\\MountPointManager";
        private const uint MountManagerMask = 0x00120089;
        private const string VolumePrefix = "\\\\.\\";
        private const uint VolumeMask = 0x00100080;
        private const string GlobalDirectoryPath = "\\GLOBAL??";
        private const string MountManagerLinkPath = "\\GLOBAL??\\MountPointManager";
        private const uint LinkQueryMask = 0x00020001;
        private const uint DirectoryQueryMask = 0x00020003;
        private const uint ReadControl = 0x00020000;
        private const uint WriteDac = 0x00040000;
        private const uint ShareReadWrite = 0x00000003;
        private const uint OpenExisting = 3;
        private const uint SeFileObject = 1;
        private const uint SeKernelObject = 6;
        private const uint ObjectCaseInsensitive = 0x00000040;
        private const uint DaclInformation = 0x00000004;
        private const uint LabelInformation = 0x00000010;
        private const uint ProtectedDacl = 0x80000000;
        private const uint UnprotectedDacl = 0x20000000;
        private const int DaclFieldOffset = 16;
        private const int MaxDescriptorBytes = 65536;
        private const int KindFile = 0;
        private const int KindLink = 1;
        private const int KindDirectory = 2;
        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        private readonly string packageSid;
        private readonly string objectPath;
        private readonly uint leaseMask;
        private readonly int objectKind;
        private byte[] original;
        private bool applied;
        private uint lastError;

        private DeviceLease(string packageSid, string objectPath, uint leaseMask, int objectKind)
        {
            this.packageSid = packageSid;
            this.objectPath = objectPath;
            this.leaseMask = leaseMask;
            this.objectKind = objectKind;
        }

        public static DeviceLease Open(string kind, string packageSid, string drive)
        {
            if (string.IsNullOrEmpty(packageSid) || !packageSid.StartsWith("S-1-15-2-", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("lease_sid");
            }
            if (kind == null || drive == null)
            {
                throw new InvalidOperationException("lease_kind");
            }
            DeviceLease lease;
            if (kind == "nul" && drive.Length == 0)
            {
                lease = new DeviceLease(packageSid, NulPath, NulMask, KindFile);
            }
            else if (kind == "mountmgr" && drive.Length == 0)
            {
                lease = new DeviceLease(packageSid, MountManagerPath, MountManagerMask, KindFile);
            }
            else if (kind == "volume" && IsDriveLetter(drive))
            {
                lease = new DeviceLease(packageSid, VolumePrefix + drive.ToUpperInvariant() + ":", VolumeMask, KindFile);
            }
            else if (kind == "drive_link" && IsDriveLetter(drive))
            {
                lease = new DeviceLease(packageSid, GlobalDirectoryPath + "\\" + drive.ToUpperInvariant() + ":", LinkQueryMask, KindLink);
            }
            else if (kind == "mpm_link" && drive.Length == 0)
            {
                lease = new DeviceLease(packageSid, MountManagerLinkPath, LinkQueryMask, KindLink);
            }
            else if (kind == "global_dir" && drive.Length == 0)
            {
                lease = new DeviceLease(packageSid, GlobalDirectoryPath, DirectoryQueryMask, KindDirectory);
            }
            else
            {
                throw new InvalidOperationException("lease_kind");
            }
            lease.original = lease.ReadDescriptor();
            return lease;
        }

        public bool Applied
        {
            get { return applied; }
        }

        public uint Error
        {
            get { return lastError; }
        }

        public string Apply()
        {
            IntPtr sid = IntPtr.Zero;
            IntPtr handle = IntPtr.Zero;
            IntPtr descriptor = IntPtr.Zero;
            IntPtr newAcl = IntPtr.Zero;
            try
            {
                if (!Native.ConvertStringSidToSidW(packageSid, out sid) || sid == IntPtr.Zero)
                {
                    lastError = (uint)Marshal.GetLastWin32Error();
                    return "failed";
                }
                handle = OpenHandle(ReadControl | WriteDac);
                IntPtr dacl;
                uint status = QuerySecurity(handle, out descriptor, out dacl);
                if (status != 0 || dacl == IntPtr.Zero)
                {
                    lastError = status;
                    return "failed";
                }
                Native.ExplicitAccess entry = new Native.ExplicitAccess();
                entry.AccessPermissions = leaseMask;
                entry.AccessMode = 1;
                entry.Inheritance = 0;
                entry.Trustee.MultipleTrustee = IntPtr.Zero;
                entry.Trustee.MultipleTrusteeOperation = 0;
                entry.Trustee.TrusteeForm = 0;
                entry.Trustee.TrusteeType = 0;
                entry.Trustee.Name = sid;
                status = Native.SetEntriesInAclW(1, ref entry, dacl, out newAcl);
                if (status != 0 || newAcl == IntPtr.Zero)
                {
                    lastError = status;
                    return "failed";
                }
                applied = true;
                status = Native.SetSecurityInfo(handle, SecurityObjectType, DaclInformation, IntPtr.Zero, IntPtr.Zero, newAcl, IntPtr.Zero);
                if (status != 0)
                {
                    lastError = status;
                    return "failed";
                }
                return "applied";
            }
            catch
            {
                return "failed";
            }
            finally
            {
                if (newAcl != IntPtr.Zero)
                {
                    Native.LocalFree(newAcl);
                }
                if (descriptor != IntPtr.Zero)
                {
                    Native.LocalFree(descriptor);
                }
                if (sid != IntPtr.Zero)
                {
                    Native.LocalFree(sid);
                }
                if (handle != IntPtr.Zero)
                {
                    Native.CloseHandle(handle);
                }
            }
        }

        public string Readback()
        {
            try
            {
                List<byte[]> before = ReadAceBlobs(original);
                List<byte[]> after = ReadAceBlobs(ReadDescriptor());
                if (after.Count != before.Count + 1)
                {
                    return "mismatch";
                }
                int found = -1;
                for (int index = 0; index < after.Count; ++index)
                {
                    if (IsLeaseAce(after[index]))
                    {
                        if (found >= 0)
                        {
                            return "mismatch";
                        }
                        found = index;
                    }
                }
                if (found < 0)
                {
                    return "mismatch";
                }
                after.RemoveAt(found);
                for (int index = 0; index < after.Count; ++index)
                {
                    if (!SameBytes(after[index], before[index]))
                    {
                        return "mismatch";
                    }
                }
                return "match";
            }
            catch
            {
                return "mismatch";
            }
        }

        public string Restore()
        {
            if (!applied)
            {
                return "not_applied";
            }
            string state = "failed";
            for (int attempt = 0; attempt < 2 && state != "verified"; ++attempt)
            {
                try
                {
                    WriteOriginal(attempt == 1);
                    if (SameBytes(ReadDescriptor(), original))
                    {
                        state = "verified";
                    }
                }
                catch
                {
                    state = "failed";
                }
            }
            return state;
        }

        private uint SecurityObjectType
        {
            get { return objectKind == KindFile ? SeFileObject : SeKernelObject; }
        }

        private static bool IsDriveLetter(string drive)
        {
            return drive.Length == 1 && ((drive[0] >= 'A' && drive[0] <= 'Z') || (drive[0] >= 'a' && drive[0] <= 'z'));
        }

        private bool IsLeaseAce(byte[] ace)
        {
            if (ace == null || ace.Length < 12 || ace[0] != 0 || ace[1] != 0)
            {
                return false;
            }
            int sidLength = 8 + (ace[9] * 4);
            if (BitConverter.ToUInt16(ace, 2) != ace.Length || ace.Length != 8 + sidLength)
            {
                return false;
            }
            return BitConverter.ToUInt32(ace, 4) == leaseMask && string.Equals(SidText(ace, 8), packageSid, StringComparison.Ordinal);
        }

        private void WriteOriginal(bool kernelStyle)
        {
            IntPtr copy = Marshal.AllocHGlobal(original.Length);
            IntPtr handle = IntPtr.Zero;
            try
            {
                Marshal.Copy(original, 0, copy, original.Length);
                handle = OpenHandle(WriteDac);
                if (kernelStyle)
                {
                    if (!Native.SetKernelObjectSecurity(handle, DaclInformation, copy))
                    {
                        throw new InvalidOperationException("restore_kernel error=" + Marshal.GetLastWin32Error().ToString());
                    }
                    return;
                }
                int present;
                IntPtr dacl;
                int defaulted;
                if (!Native.GetSecurityDescriptorDacl(copy, out present, out dacl, out defaulted))
                {
                    throw new InvalidOperationException("restore_dacl");
                }
                if (present == 0)
                {
                    dacl = IntPtr.Zero;
                }
                uint control = BitConverter.ToUInt16(original, 2);
                uint protection = (control & 0x1000) != 0 ? ProtectedDacl : UnprotectedDacl;
                uint status = Native.SetSecurityInfo(handle, SecurityObjectType, DaclInformation | protection, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                if (status != 0)
                {
                    throw new InvalidOperationException("restore_set error=" + status.ToString());
                }
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    Native.CloseHandle(handle);
                }
                Marshal.FreeHGlobal(copy);
            }
        }

        private IntPtr OpenHandle(uint access)
        {
            if (objectKind != KindFile)
            {
                return OpenObject(access);
            }
            IntPtr handle = Native.CreateFileW(objectPath, access, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (handle == InvalidHandle || handle == IntPtr.Zero)
            {
                lastError = (uint)Marshal.GetLastWin32Error();
                throw new InvalidOperationException("device_open error=" + lastError.ToString());
            }
            return handle;
        }

        private IntPtr OpenObject(uint access)
        {
            IntPtr text = Marshal.StringToHGlobalUni(objectPath);
            IntPtr name = IntPtr.Zero;
            try
            {
                Native.UnicodeString unicode = new Native.UnicodeString();
                unicode.Length = (ushort)(objectPath.Length * 2);
                unicode.MaximumLength = (ushort)(objectPath.Length * 2 + 2);
                unicode.Buffer = text;
                name = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.UnicodeString)));
                Marshal.StructureToPtr(unicode, name, false);
                Native.ObjectAttributes attributes = new Native.ObjectAttributes();
                attributes.Length = (uint)Marshal.SizeOf(typeof(Native.ObjectAttributes));
                attributes.RootDirectory = IntPtr.Zero;
                attributes.ObjectName = name;
                attributes.Attributes = ObjectCaseInsensitive;
                attributes.SecurityDescriptor = IntPtr.Zero;
                attributes.SecurityQualityOfService = IntPtr.Zero;
                IntPtr handle;
                int status = objectKind == KindDirectory
                    ? Native.NtOpenDirectoryObject(out handle, access, ref attributes)
                    : Native.NtOpenSymbolicLinkObject(out handle, access, ref attributes);
                if (status < 0 || handle == IntPtr.Zero)
                {
                    lastError = Native.RtlNtStatusToDosError(status);
                    throw new InvalidOperationException("object_open error=" + lastError.ToString());
                }
                return handle;
            }
            finally
            {
                if (name != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(name);
                }
                Marshal.FreeHGlobal(text);
            }
        }

        private uint QuerySecurity(IntPtr handle, out IntPtr descriptor, out IntPtr dacl)
        {
            IntPtr owner;
            IntPtr group;
            IntPtr sacl;
            uint status = Native.GetSecurityInfo(handle, SecurityObjectType, DaclInformation | LabelInformation, out owner, out group, out dacl, out sacl, out descriptor);
            if (status == 0 && descriptor != IntPtr.Zero)
            {
                return status;
            }
            if (descriptor != IntPtr.Zero)
            {
                Native.LocalFree(descriptor);
            }
            descriptor = IntPtr.Zero;
            return Native.GetSecurityInfo(handle, SecurityObjectType, DaclInformation, out owner, out group, out dacl, out sacl, out descriptor);
        }

        private byte[] ReadDescriptor()
        {
            IntPtr handle = OpenHandle(ReadControl);
            IntPtr descriptor = IntPtr.Zero;
            try
            {
                IntPtr dacl;
                uint status = QuerySecurity(handle, out descriptor, out dacl);
                if (status != 0 || descriptor == IntPtr.Zero)
                {
                    throw new InvalidOperationException("device_read error=" + status.ToString());
                }
                uint length = Native.GetSecurityDescriptorLength(descriptor);
                if (length < 20 || length > MaxDescriptorBytes)
                {
                    throw new InvalidOperationException("device_length");
                }
                byte[] bytes = new byte[length];
                Marshal.Copy(descriptor, bytes, 0, (int)length);
                return bytes;
            }
            finally
            {
                if (descriptor != IntPtr.Zero)
                {
                    Native.LocalFree(descriptor);
                }
                Native.CloseHandle(handle);
            }
        }

        private static bool SameBytes(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length)
            {
                return false;
            }
            for (int index = 0; index < left.Length; ++index)
            {
                if (left[index] != right[index])
                {
                    return false;
                }
            }
            return true;
        }

        private static string SidText(byte[] data, int offset)
        {
            if (offset < 0 || offset + 8 > data.Length)
            {
                return "";
            }
            int count = data[offset + 1];
            if (offset + 8 + count * 4 > data.Length)
            {
                return "";
            }
            ulong authority = 0;
            for (int index = 2; index < 8; ++index)
            {
                authority = (authority << 8) | data[offset + index];
            }
            StringBuilder text = new StringBuilder("S-" + data[offset].ToString() + "-" + authority.ToString());
            for (int index = 0; index < count; ++index)
            {
                text.Append("-" + BitConverter.ToUInt32(data, offset + 8 + index * 4).ToString());
            }
            return text.ToString();
        }

        private static List<byte[]> ReadAceBlobs(byte[] data)
        {
            List<byte[]> result = new List<byte[]>();
            if (data == null || data.Length < 20)
            {
                return result;
            }
            int aclOffset = BitConverter.ToInt32(data, DaclFieldOffset);
            if (aclOffset <= 0 || aclOffset + 8 > data.Length)
            {
                return result;
            }
            int count = BitConverter.ToUInt16(data, aclOffset + 4);
            if (count > 256)
            {
                throw new InvalidOperationException("acl_count");
            }
            int cursor = aclOffset + 8;
            for (int index = 0; index < count; ++index)
            {
                if (cursor + 8 > data.Length)
                {
                    throw new InvalidOperationException("ace_shape");
                }
                int size = BitConverter.ToUInt16(data, cursor + 2);
                if (size < 8 || cursor + size > data.Length)
                {
                    throw new InvalidOperationException("ace_shape");
                }
                byte[] blob = new byte[size];
                Buffer.BlockCopy(data, cursor, blob, 0, size);
                result.Add(blob);
                cursor += size;
            }
            return result;
        }

        private static class Native
        {
            [StructLayout(LayoutKind.Sequential)]
            internal struct Trustee
            {
                internal IntPtr MultipleTrustee;
                internal uint MultipleTrusteeOperation;
                internal uint TrusteeForm;
                internal uint TrusteeType;
                internal IntPtr Name;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct ExplicitAccess
            {
                internal uint AccessPermissions;
                internal uint AccessMode;
                internal uint Inheritance;
                internal Trustee Trustee;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct UnicodeString
            {
                internal ushort Length;
                internal ushort MaximumLength;
                internal IntPtr Buffer;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct ObjectAttributes
            {
                internal uint Length;
                internal IntPtr RootDirectory;
                internal IntPtr ObjectName;
                internal uint Attributes;
                internal IntPtr SecurityDescriptor;
                internal IntPtr SecurityQualityOfService;
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            internal static extern IntPtr CreateFileW(string fileName, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseHandle(IntPtr handle);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr LocalFree(IntPtr memory);

            [DllImport("advapi32.dll", ExactSpelling = true)]
            internal static extern uint GetSecurityInfo(IntPtr handle, uint objectType, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

            [DllImport("advapi32.dll", ExactSpelling = true)]
            internal static extern uint SetSecurityInfo(IntPtr handle, uint objectType, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

            [DllImport("advapi32.dll", ExactSpelling = true)]
            internal static extern uint SetEntriesInAclW(uint count, ref ExplicitAccess entries, IntPtr oldAcl, out IntPtr newAcl);

            [DllImport("advapi32.dll", ExactSpelling = true)]
            internal static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out int present, out IntPtr dacl, out int defaulted);

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool SetKernelObjectSecurity(IntPtr handle, uint information, IntPtr descriptor);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool ConvertStringSidToSidW(string text, out IntPtr sid);

            [DllImport("ntdll.dll", ExactSpelling = true)]
            internal static extern int NtOpenSymbolicLinkObject(out IntPtr handle, uint access, ref ObjectAttributes attributes);

            [DllImport("ntdll.dll", ExactSpelling = true)]
            internal static extern int NtOpenDirectoryObject(out IntPtr handle, uint access, ref ObjectAttributes attributes);

            [DllImport("ntdll.dll", ExactSpelling = true)]
            internal static extern uint RtlNtStatusToDosError(int status);
        }
    }

    public static class HandleRemover
    {
        private const uint Delete = 0x00010000;
        private const uint Synchronize = 0x00100000;
        private const uint FileListDirectory = 0x00000001;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileWriteAttributes = 0x00000100;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FlagBackupSemantics = 0x02000000;
        private const uint FlagOpenReparsePoint = 0x00200000;
        private const uint AttributeReadOnly = 0x00000001;
        private const uint AttributeDirectory = 0x00000010;
        private const uint AttributeReparsePoint = 0x00000400;
        private const int ClassBasicInfo = 0;
        private const int ClassDispositionInfo = 4;
        private const int ClassFullDirectoryInfo = 14;
        private const int ClassFullDirectoryRestartInfo = 15;
        private const int ClassDispositionInfoEx = 21;
        private const uint DispositionDeletePosixIgnoreReadOnly = 0x13;
        private const uint DispositionDeleteIgnoreReadOnly = 0x11;
        private const int ErrorSharingViolation = 32;
        private const int ErrorAccessDenied = 5;
        private const int FinalPathChars = 32768;
        private const int ErrorNoMoreFiles = 18;
        private const int MaxDepth = 1024;
        private const int MaxPathChars = 32000;
        private static readonly List<string> AllowedRoots = new List<string>();
        private static readonly object RootLock = new object();
        private const int MaxOpenRetries = 25;
        private const int DirectoryBufferBytes = 65536;
        private const int NameOffset = 68;
        private const int NameLengthOffset = 60;
        private const int AttributesOffset = 56;

        public static void Remove(string path)
        {
            RemoveEntry(Extend(path), null, 0, false);
        }

        public static void RemoveLinks(string path)
        {
            RemoveEntry(Extend(path), null, 0, true);
        }

        public static void AllowRoot(string path)
        {
            string lowered = Shape(path).ToLowerInvariant();
            RefuseSystemRoot(lowered);
            lock (RootLock)
            {
                if (!AllowedRoots.Contains(lowered))
                {
                    AllowedRoots.Add(lowered);
                }
            }
        }

        private static void RefuseSystemRoot(string lowered)
        {
            string system = Environment.GetEnvironmentVariable("SystemRoot");
            if (string.IsNullOrEmpty(system) || system.Length < 4)
            {
                throw new InvalidOperationException("remove_path");
            }
            string systemLowered = system.TrimEnd('\\').ToLowerInvariant();
            if (lowered == systemLowered || lowered.StartsWith(systemLowered + "\\", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("remove_path");
            }
        }

        private static void RequireAllowed(string trimmed)
        {
            string lowered = trimmed.ToLowerInvariant();
            RefuseSystemRoot(lowered);
            lock (RootLock)
            {
                foreach (string root in AllowedRoots)
                {
                    if (lowered == root || lowered.StartsWith(root + "\\", StringComparison.Ordinal))
                    {
                        return;
                    }
                }
            }
            throw new InvalidOperationException("remove_path");
        }

        private static string Extend(string path)
        {
            string trimmed = Shape(path);
            RequireAllowed(trimmed);
            return "\\\\?\\" + trimmed;
        }

        private static string Shape(string path)
        {
            if (string.IsNullOrEmpty(path) || path.Length < 4 || path.Length > 32000 || path[1] != ':' || path[2] != '\\')
            {
                throw new InvalidOperationException("remove_path");
            }
            string trimmed = path.TrimEnd('\\');
            string[] parts = trimmed.Substring(3).Split('\\');
            if (parts.Length < 2)
            {
                throw new InvalidOperationException("remove_path");
            }
            foreach (string part in parts)
            {
                if (part.Length == 0 || part == "." || part == "..")
                {
                    throw new InvalidOperationException("remove_path");
                }
            }
            return trimmed;
        }


        private static IntPtr ReopenDirectory(string path, string expectedFinal)
        {
            uint[] tiers = new uint[]
            {
                Delete | Synchronize | FileListDirectory | FileReadAttributes | FileWriteAttributes,
                Delete | Synchronize | FileListDirectory | FileReadAttributes
            };
            uint flags = FlagBackupSemantics | FlagOpenReparsePoint;
            int error = 0;
            foreach (uint access in tiers)
            {
                for (int attempt = 0; attempt < MaxOpenRetries; ++attempt)
                {
                    IntPtr handle = Native.CreateFileW(path, access, ShareRead, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
                    if (handle != new IntPtr(-1))
                    {
                        bool good = false;
                        try
                        {
                            uint attributes;
                            uint links;
                            ReadInformation(handle, out attributes, out links);
                            good = (attributes & AttributeDirectory) != 0 && (attributes & AttributeReparsePoint) == 0
                                && string.Equals(FinalPath(handle), expectedFinal, StringComparison.OrdinalIgnoreCase);
                        }
                        finally
                        {
                            if (!good)
                            {
                                Native.CloseHandle(handle);
                            }
                        }
                        if (!good)
                        {
                            throw new InvalidOperationException("remove_failed step=verify error=reopen");
                        }
                        return handle;
                    }
                    error = Marshal.GetLastWin32Error();
                    if (error != ErrorSharingViolation)
                    {
                        break;
                    }
                    Thread.Sleep(200);
                }
                if (error != ErrorAccessDenied)
                {
                    break;
                }
            }
            throw new InvalidOperationException("remove_failed step=reopen error=" + error.ToString());
        }

        private static IntPtr OpenEntry(string path)
        {
            uint[] tiers = new uint[]
            {
                Delete | Synchronize | FileListDirectory | FileReadAttributes | FileWriteAttributes,
                Delete | Synchronize | FileListDirectory | FileReadAttributes,
                Delete | Synchronize | FileReadAttributes
            };
            uint flags = FlagBackupSemantics | FlagOpenReparsePoint;
            int error = 0;
            foreach (uint access in tiers)
            {
                for (int attempt = 0; attempt < MaxOpenRetries; ++attempt)
                {
                    IntPtr handle = Native.CreateFileW(path, access, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
                    if (handle != new IntPtr(-1))
                    {
                        return handle;
                    }
                    error = Marshal.GetLastWin32Error();
                    if (error != ErrorSharingViolation)
                    {
                        break;
                    }
                    Thread.Sleep(200);
                }
                if (error != ErrorAccessDenied)
                {
                    break;
                }
            }
            throw new InvalidOperationException("remove_failed step=open error=" + error.ToString());
        }

        private static string FinalPath(IntPtr handle)
        {
            StringBuilder buffer = new StringBuilder(FinalPathChars);
            uint length = Native.GetFinalPathNameByHandleW(handle, buffer, (uint)FinalPathChars, 0);
            if (length == 0 || length >= FinalPathChars)
            {
                throw new InvalidOperationException("remove_failed step=verify error=" + Marshal.GetLastWin32Error().ToString());
            }
            return buffer.ToString();
        }

        private static void ReadInformation(IntPtr handle, out uint attributes, out uint links)
        {
            IntPtr buffer = Marshal.AllocHGlobal(52);
            try
            {
                if (!Native.GetFileInformationByHandle(handle, buffer))
                {
                    throw new InvalidOperationException("remove_failed step=query error=" + Marshal.GetLastWin32Error().ToString());
                }
                attributes = unchecked((uint)Marshal.ReadInt32(buffer, 0));
                links = unchecked((uint)Marshal.ReadInt32(buffer, 40));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void ListEntries(IntPtr handle, List<string> names, List<uint> attributes)
        {
            IntPtr buffer = Marshal.AllocHGlobal(DirectoryBufferBytes);
            try
            {
                int infoClass = ClassFullDirectoryRestartInfo;
                while (true)
                {
                    if (!Native.GetFileInformationByHandleEx(handle, infoClass, buffer, (uint)DirectoryBufferBytes))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ErrorNoMoreFiles)
                        {
                            return;
                        }
                        throw new InvalidOperationException("remove_failed step=list error=" + error.ToString());
                    }
                    infoClass = ClassFullDirectoryInfo;
                    int offset = 0;
                    while (true)
                    {
                        int next = Marshal.ReadInt32(buffer, offset);
                        int nameBytes = Marshal.ReadInt32(buffer, offset + NameLengthOffset);
                        if (nameBytes < 0 || nameBytes > 1024 || offset + NameOffset + nameBytes > DirectoryBufferBytes)
                        {
                            throw new InvalidOperationException("remove_failed step=list error=shape");
                        }
                        string name = Marshal.PtrToStringUni(new IntPtr(buffer.ToInt64() + offset + NameOffset), nameBytes / 2);
                        if (name != "." && name != "..")
                        {
                            names.Add(name);
                            attributes.Add(unchecked((uint)Marshal.ReadInt32(buffer, offset + AttributesOffset)));
                        }
                        if (next == 0)
                        {
                            break;
                        }
                        offset += next;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static int SetDisposition(IntPtr handle, uint flags)
        {
            IntPtr buffer = Marshal.AllocHGlobal(4);
            try
            {
                Marshal.WriteInt32(buffer, 0, unchecked((int)flags));
                if (Native.SetFileInformationByHandle(handle, ClassDispositionInfoEx, buffer, 4))
                {
                    return 0;
                }
                return Marshal.GetLastWin32Error();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static int ClearReadOnly(IntPtr handle, uint attributes)
        {
            IntPtr buffer = Marshal.AllocHGlobal(40);
            try
            {
                for (int offset = 0; offset < 40; offset += 8)
                {
                    Marshal.WriteInt64(buffer, offset, 0L);
                }
                uint updated = attributes & ~AttributeReadOnly;
                if (updated == 0)
                {
                    updated = 0x80;
                }
                Marshal.WriteInt32(buffer, 32, unchecked((int)updated));
                if (Native.SetFileInformationByHandle(handle, ClassBasicInfo, buffer, 40))
                {
                    return 0;
                }
                return Marshal.GetLastWin32Error();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static int SetClassicDisposition(IntPtr handle)
        {
            IntPtr buffer = Marshal.AllocHGlobal(8);
            try
            {
                Marshal.WriteInt64(buffer, 0, 1L);
                if (Native.SetFileInformationByHandle(handle, ClassDispositionInfo, buffer, 1))
                {
                    return 0;
                }
                return Marshal.GetLastWin32Error();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void DeleteByHandle(IntPtr handle, uint attributes, uint links)
        {
            int error = SetDisposition(handle, DispositionDeletePosixIgnoreReadOnly);
            if (error == 0)
            {
                return;
            }
            error = SetDisposition(handle, DispositionDeleteIgnoreReadOnly);
            if (error == 0)
            {
                return;
            }
            if ((attributes & AttributeReadOnly) != 0 && links <= 1 && (attributes & AttributeReparsePoint) == 0)
            {
                error = ClearReadOnly(handle, attributes);
                if (error == 0)
                {
                    error = SetClassicDisposition(handle);
                    if (error == 0)
                    {
                        return;
                    }
                }
            }
            throw new InvalidOperationException("remove_failed step=delete error=" + error.ToString());
        }

        private static void RemoveEntry(string path, string expectedFinal, int depth, bool linksOnly)
        {
            if (depth > MaxDepth)
            {
                throw new InvalidOperationException("remove_failed step=depth error=0");
            }
            if (path.Length > MaxPathChars)
            {
                throw new InvalidOperationException("remove_failed step=depth error=path");
            }
            if (expectedFinal == null && depth == 0)
            {
                expectedFinal = path;
            }
            IntPtr handle = OpenEntry(path);
            try
            {
                string here = FinalPath(handle);
                if (expectedFinal != null && !string.Equals(here, expectedFinal, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("remove_failed step=verify error=redirected");
                }
                uint attributes;
                uint links;
                ReadInformation(handle, out attributes, out links);
                if ((attributes & AttributeReparsePoint) != 0)
                {
                    DeleteByHandle(handle, attributes, links);
                    return;
                }
                if ((attributes & AttributeDirectory) != 0)
                {
                    Native.CloseHandle(handle);
                    handle = IntPtr.Zero;
                    handle = ReopenDirectory(path, here);
                    List<string> names = new List<string>();
                    List<uint> kinds = new List<uint>();
                    ListEntries(handle, names, kinds);
                    for (int index = 0; index < names.Count; ++index)
                    {
                        bool plain = (kinds[index] & (AttributeDirectory | AttributeReparsePoint)) == 0;
                        if (linksOnly && plain)
                        {
                            continue;
                        }
                        RemoveEntry(path + "\\" + names[index], here + "\\" + names[index], depth + 1, linksOnly);
                    }
                    if (!linksOnly)
                    {
                        DeleteByHandle(handle, attributes, links);
                    }
                    return;
                }
                if (!linksOnly)
                {
                    DeleteByHandle(handle, attributes, links);
                }
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    Native.CloseHandle(handle);
                }
            }
        }

        private static class Native
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            internal static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetFileInformationByHandle(IntPtr handle, IntPtr information);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetFileInformationByHandleEx(IntPtr handle, int informationClass, IntPtr buffer, uint size);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool SetFileInformationByHandle(IntPtr handle, int informationClass, IntPtr buffer, uint size);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            internal static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint length, uint flags);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseHandle(IntPtr handle);
        }
    }

    public sealed class Sandbox : IDisposable
    {
        private const int ErrorInsufficientBuffer = 122;
        private const int HresultAlreadyExists = unchecked((int)0x800700b7);
        private const int MaxCaptureBytes = 262144;
        private const int MaxEnvironmentCharacters = 131072;
        private const int MaxCommandLineCharacters = 32767;
        private const uint TokenQuery = 0x0008;
        private const int TokenSecurityAttributes = 39;
        private const string RegistryReadCapability = "registryRead";
        private const int TokenGroups = 2;
        private const int TokenRestrictedSids = 11;
        private const int TokenAppContainerSid = 31;
        private const string AllApplicationPackagesSid = "S-1-15-2-1";
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
        private const uint JobObjectBasicProcessIdList = 3;
        private const int ErrorMoreData = 234;
        private const int JobListSlots = 64;

        private string profileName;
        private IntPtr profileSid = IntPtr.Zero;
        private string sidText = "";
        private bool profileCreated;
        private bool cleanupComplete = true;
        private readonly List<IntPtr> retainedJobs = new List<IntPtr>();
        private readonly object jobLock = new object();

        public string SidText
        {
            get { return sidText; }
        }

        public string ProfileName
        {
            get { return profileName; }
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
            lock (jobLock)
            {
                foreach (IntPtr retained in retainedJobs)
                {
                    Native.CloseHandle(retained);
                }
                retainedJobs.Clear();
            }
        }

        private void RetainJob(ref IntPtr job)
        {
            if (job != IntPtr.Zero)
            {
                lock (jobLock)
                {
                    retainedJobs.Add(job);
                }
                job = IntPtr.Zero;
            }
        }

        public string JobState(int waitMs)
        {
            Stopwatch clock = Stopwatch.StartNew();
            while (true)
            {
                string state = ScanJobs();
                if (state != "alive" || clock.ElapsedMilliseconds >= waitMs)
                {
                    return state;
                }
                Thread.Sleep(100);
            }
        }

        private string ScanJobs()
        {
            IntPtr[] jobs;
            lock (jobLock)
            {
                jobs = retainedJobs.ToArray();
            }
            bool alive = false;
            foreach (IntPtr job in jobs)
            {
                int assigned = ReadAssignedProcesses(job);
                if (assigned < 0)
                {
                    return "unreadable";
                }
                if (assigned > 0)
                {
                    alive = true;
                }
            }
            return alive ? "alive" : "none";
        }

        private static int ReadAssignedProcesses(IntPtr job)
        {
            int size = 8 + IntPtr.Size * JobListSlots;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                for (int offset = 0; offset < size; offset += 8)
                {
                    Marshal.WriteInt64(buffer, offset, 0L);
                }
                uint returned;
                if (!Native.QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (uint)size, out returned))
                {
                    if (Marshal.GetLastWin32Error() != ErrorMoreData)
                    {
                        return -1;
                    }
                }
                return Marshal.ReadInt32(buffer, 0);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
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

        private static IntPtr DeriveRegistryReadSid()
        {
            IntPtr groupSids = IntPtr.Zero;
            IntPtr capabilitySids = IntPtr.Zero;
            uint groupCount = 0;
            uint capabilityCount = 0;
            if (!Native.DeriveCapabilitySidsFromName(RegistryReadCapability, out groupSids, out groupCount, out capabilitySids, out capabilityCount))
            {
                throw new InvalidOperationException("derive_failed error=" + Marshal.GetLastWin32Error().ToString());
            }
            try
            {
                if (capabilityCount != 1 || capabilitySids == IntPtr.Zero)
                {
                    throw new InvalidOperationException("derive_count");
                }
                IntPtr source = Marshal.ReadIntPtr(capabilitySids);
                if (source == IntPtr.Zero || !Native.IsValidSid(source))
                {
                    throw new InvalidOperationException("derive_sid");
                }
                uint length = Native.GetLengthSid(source);
                if (length == 0 || length > 256)
                {
                    throw new InvalidOperationException("derive_length");
                }
                IntPtr copy = Marshal.AllocHGlobal((int)length);
                if (!Native.CopySid(length, copy, source))
                {
                    Marshal.FreeHGlobal(copy);
                    throw new InvalidOperationException("derive_copy");
                }
                return copy;
            }
            finally
            {
                FreeDerived(groupSids, groupCount);
                FreeDerived(capabilitySids, capabilityCount);
            }
        }

        private static void FreeDerived(IntPtr sids, uint count)
        {
            if (sids == IntPtr.Zero)
            {
                return;
            }
            for (uint index = 0; index < count && index < 16; ++index)
            {
                IntPtr sid = Marshal.ReadIntPtr(sids, (int)index * IntPtr.Size);
                if (sid != IntPtr.Zero)
                {
                    Native.LocalFree(sid);
                }
            }
            Native.LocalFree(sids);
        }

        private static string SidToText(IntPtr sid)
        {
            IntPtr text;
            if (!Native.ConvertSidToStringSidW(sid, out text) || text == IntPtr.Zero)
            {
                throw new InvalidOperationException("sid_text");
            }
            try
            {
                return Marshal.PtrToStringUni(text);
            }
            finally
            {
                Native.LocalFree(text);
            }
        }

        public RunResult Run(bool confined, string executable, string commandLine, string workingDirectory, string[] environment, int timeoutMs, uint maxProcesses)
        {
            RunResult result = new RunResult();
            IntPtr job = IntPtr.Zero;
            IntPtr process = IntPtr.Zero;
            IntPtr thread = IntPtr.Zero;
            IntPtr inRead = IntPtr.Zero;
            IntPtr outRead = IntPtr.Zero;
            IntPtr outWrite = IntPtr.Zero;
            IntPtr errRead = IntPtr.Zero;
            IntPtr errWrite = IntPtr.Zero;
            IntPtr attributeBuffer = IntPtr.Zero;
            IntPtr capabilitiesBuffer = IntPtr.Zero;
            IntPtr capabilityArray = IntPtr.Zero;
            IntPtr capabilitySid = IntPtr.Zero;
            string registryReadSidText = "";
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
                CreateEofStdin(out inRead);

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

                handleBuffer = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handleBuffer, 0, inRead);
                Marshal.WriteIntPtr(handleBuffer, IntPtr.Size, outWrite);
                Marshal.WriteIntPtr(handleBuffer, IntPtr.Size * 2, errWrite);
                uint handleListSize = (uint)(IntPtr.Size * 3);
                IntPtr[] handleListExpected = new IntPtr[] { inRead, outWrite, errWrite };
                if (!Native.UpdateProcThreadAttribute(attributeBuffer, 0, ProcThreadAttributeHandleList, handleBuffer, new UIntPtr(handleListSize), IntPtr.Zero, IntPtr.Zero))
                {
                    throw new InvalidOperationException();
                }
                if (confined)
                {
                    capabilitySid = DeriveRegistryReadSid();
                    registryReadSidText = SidToText(capabilitySid);
                    capabilityArray = Marshal.AllocHGlobal(IntPtr.Size * 2);
                    Marshal.WriteIntPtr(capabilityArray, 0, capabilitySid);
                    Marshal.WriteInt32(capabilityArray, IntPtr.Size, unchecked((int)GroupEnabled));
                    Native.SecurityCapabilities capabilities = new Native.SecurityCapabilities();
                    capabilities.AppContainerSid = profileSid;
                    capabilities.Capabilities = capabilityArray;
                    capabilities.CapabilityCount = 1;
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
                startup.StartupInfo.hStdInput = inRead;
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
                result.HandleCount = MeasureHandleList(handleBuffer, handleListSize, handleListExpected);
                CloseOne(ref outWrite);
                CloseOne(ref errWrite);
                CloseOne(ref inRead);

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
                result.Token = ReadToken(process, confined, profileSid, registryReadSidText, result);

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
                ReadPeaks(job, result);
                ReadCpu(job, result);
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
                CloseOne(ref inRead);
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
                RetainJob(ref job);
                if (attributeListInitialized)
                {
                    Native.DeleteProcThreadAttributeList(attributeBuffer);
                }
                FreeOne(ref attributeBuffer);
                FreeOne(ref capabilitiesBuffer);
                FreeOne(ref capabilityArray);
                FreeOne(ref capabilitySid);
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

        private static void ReadPeaks(IntPtr job, RunResult result)
        {
            int size = Marshal.SizeOf(typeof(Native.ExtendedLimitInformation));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint returned;
                if (Native.QueryInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size, out returned) && returned >= size)
                {
                    Native.ExtendedLimitInformation actual = (Native.ExtendedLimitInformation)Marshal.PtrToStructure(buffer, typeof(Native.ExtendedLimitInformation));
                    result.PeakProcessMemory = actual.PeakProcessMemoryUsed.ToUInt64();
                    result.PeakJobMemory = actual.PeakJobMemoryUsed.ToUInt64();
                }
            }
            catch
            {
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void ReadCpu(IntPtr job, RunResult result)
        {
            IntPtr buffer = Marshal.AllocHGlobal(48);
            try
            {
                uint returned;
                if (Native.QueryInformationJobObject(job, 1, buffer, 48, out returned) && returned >= 16)
                {
                    long user = Marshal.ReadInt64(buffer, 0);
                    long kernel = Marshal.ReadInt64(buffer, 8);
                    if (user >= 0 && kernel >= 0)
                    {
                        result.CpuMs = (ulong)((user + kernel) / 10000);
                    }
                }
            }
            catch
            {
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static uint MeasureHandleList(IntPtr buffer, uint sizeBytes, IntPtr[] expected)
        {
            if (buffer == IntPtr.Zero || expected == null || sizeBytes == 0 || (sizeBytes % (uint)IntPtr.Size) != 0)
            {
                return 0;
            }
            uint count = sizeBytes / (uint)IntPtr.Size;
            if (count != (uint)expected.Length)
            {
                return count;
            }
            for (int index = 0; index < expected.Length; ++index)
            {
                IntPtr entry = Marshal.ReadIntPtr(buffer, index * IntPtr.Size);
                uint flags;
                if (entry == IntPtr.Zero || entry == new IntPtr(-1) || entry != expected[index])
                {
                    return 0;
                }
                for (int other = 0; other < index; ++other)
                {
                    if (expected[other] == entry)
                    {
                        return 0;
                    }
                }
                if (!Native.GetHandleInformation(entry, out flags) || (flags & HandleFlagInherit) == 0)
                {
                    return 0;
                }
            }
            return count;
        }

        private static void CreateEofStdin(out IntPtr read)
        {
            IntPtr write;
            Native.SecurityAttributes attributes = new Native.SecurityAttributes();
            attributes.Length = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes));
            attributes.SecurityDescriptor = IntPtr.Zero;
            attributes.InheritHandle = 1;
            if (!Native.CreatePipe(out read, out write, ref attributes, 4096))
            {
                read = IntPtr.Zero;
                throw new InvalidOperationException();
            }
            bool cleared = Native.SetHandleInformation(write, HandleFlagInherit, 0);
            Native.CloseHandle(write);
            if (!cleared)
            {
                Native.CloseHandle(read);
                read = IntPtr.Zero;
                throw new InvalidOperationException();
            }
        }

        private static string ReadNoAllAppPkgAttribute(IntPtr token)
        {
            if (IntPtr.Size != 8)
            {
                return "unreadable";
            }
            uint length = 0;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                buffer = QueryTokenInformation(token, TokenSecurityAttributes, out length);
                if (length < 16)
                {
                    return "unreadable";
                }
                long start = buffer.ToInt64();
                long end = start + length;
                uint count = unchecked((uint)Marshal.ReadInt32(buffer, 4));
                if (count == 0)
                {
                    return "absent";
                }
                if (count > 64)
                {
                    return "unreadable";
                }
                long array = Marshal.ReadIntPtr(buffer, 8).ToInt64();
                if (array < start || array + (long)count * 40 > end)
                {
                    return "unreadable";
                }
                for (uint index = 0; index < count; ++index)
                {
                    IntPtr attribute = new IntPtr(array + (long)index * 40);
                    int nameBytes = (ushort)Marshal.ReadInt16(attribute, 0);
                    long namePointer = Marshal.ReadIntPtr(attribute, 8).ToInt64();
                    if (nameBytes == 0 || nameBytes > 512 || (nameBytes % 2) != 0 || namePointer < start || namePointer + nameBytes > end)
                    {
                        return "unreadable";
                    }
                    string name = Marshal.PtrToStringUni(new IntPtr(namePointer), nameBytes / 2);
                    if (string.Equals(name, "WIN://NOALLAPPPKG", StringComparison.OrdinalIgnoreCase))
                    {
                        return "present";
                    }
                }
                return "absent";
            }
            catch
            {
                return "unreadable";
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private static string ReadToken(IntPtr process, bool confined, IntPtr expectedSid, string expectedCapabilitySid, RunResult result)
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
                bool capabilityMatches = capabilityCount == 1 && !string.IsNullOrEmpty(expectedCapabilitySid)
                    && ReadSidInTokenSet(token, TokenCapabilities, expectedCapabilitySid, false);
                string class46 = "unreadable";
                try
                {
                    class46 = ReadTokenDword(token, TokenIsLessPrivilegedAppContainer) == 1 ? "1" : "0";
                }
                catch
                {
                    class46 = "unreadable";
                }
                result.Class46 = class46;
                string attribute = ReadNoAllAppPkgAttribute(token);
                string sidState = ReadContainerSidMatches(token, expectedSid) ? "match" : "mismatch";
                string applicationPackages = ReadAllApplicationPackagesState(token);
                string text = "appcontainer=" + isAppContainer.ToString() + " capabilities=" + capabilityCount.ToString()
                    + " integrity=0x" + integrity.ToString("x4") + " lpac=" + (attribute == "present" ? "attr" : "none")
                    + " cap=" + (capabilityMatches ? RegistryReadCapability : "mismatch") + " sid=" + sidState
                    + " aap=" + applicationPackages;
                if (isAppContainer != 1 || capabilityCount != 1 || !capabilityMatches || integrity != LowIntegrityRid
                    || attribute != "present" || sidState != "match" || applicationPackages != "absent")
                {
                    throw new InvalidOperationException(text + " attr=" + attribute);
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

            [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool DeriveCapabilitySidsFromName(string capabilityName, out IntPtr capabilityGroupSids, out uint capabilityGroupSidCount, out IntPtr capabilitySids, out uint capabilitySidCount);

            [DllImport("advapi32.dll", ExactSpelling = true)]
            internal static extern uint GetLengthSid(IntPtr sid);

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CopySid(uint destinationLength, IntPtr destination, IntPtr source);

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
            internal static extern bool GetHandleInformation(IntPtr handle, out uint flags);

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

    public static class JunctionMaker
    {
        private const uint GenericWrite = 0x40000000;
        private const uint FileReadData = 0x00000001;
        private const uint FileReadAttributes = 0x00000080;
        private const uint Synchronize = 0x00100000;
        private const uint ReadControl = 0x00020000;
        private const uint WriteDac = 0x00040000;
        private const uint DaclSecurityInformation = 0x00000004;
        private const int MaxDescriptorBytes = 65536;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FlagBackupSemantics = 0x02000000;
        private const uint FlagOpenReparsePoint = 0x00200000;
        private const uint AttributeDirectory = 0x00000010;
        private const uint AttributeReparsePoint = 0x00000400;
        private const uint ReparseTagMountPoint = 0xA0000003;
        private const uint FsctlSetReparsePoint = 0x000900A4;
        private const uint FsctlGetReparsePoint = 0x000900A8;
        private const int ErrorFileNotFound = 2;
        private const int ErrorPathNotFound = 3;
        private const int MaxReparseBytes = 16384;
        private const int MaxComponents = 8;
        private const int MaxComponentChars = 100;
        private const int FinalPathChars = 32768;
        private const int InformationBytes = 52;
        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        public static string Create(string projectRoot, string linkRelative, string targetRelative)
        {
            string root = Root(projectRoot);
            string[] linkParts = Parts(linkRelative);
            string[] targetParts = Parts(targetRelative);
            string target = Join(root, targetParts, targetParts.Length);
            string link = Join(root, linkParts, linkParts.Length);
            if (target.StartsWith(link + "\\", StringComparison.OrdinalIgnoreCase) || link.StartsWith(target + "\\", StringComparison.OrdinalIgnoreCase)
                || string.Equals(link, target, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("npm_link step=overlap error=0");
            }
            List<IntPtr> held = new List<IntPtr>();
            IntPtr handle = IntPtr.Zero;
            try
            {
                held.Add(OpenVerified(root, false));
                for (int index = 1; index <= targetParts.Length; ++index)
                {
                    held.Add(OpenVerified(Join(root, targetParts, index), false));
                }
                for (int index = 1; index < linkParts.Length; ++index)
                {
                    held.Add(OpenVerified(Join(root, linkParts, index), true));
                }
                if (!Native.CreateDirectoryW("\\\\?\\" + link, IntPtr.Zero))
                {
                    throw new InvalidOperationException("npm_link step=mkdir error=" + Marshal.GetLastWin32Error().ToString());
                }
                handle = Native.CreateFileW("\\\\?\\" + link, GenericWrite | FileReadAttributes | Synchronize, 0, IntPtr.Zero, OpenExisting, FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
                if (handle == InvalidHandle || handle == IntPtr.Zero)
                {
                    handle = IntPtr.Zero;
                    throw new InvalidOperationException("npm_link step=open error=" + Marshal.GetLastWin32Error().ToString());
                }
                RequirePlainDirectory(handle, link);
                string substitute = "\\??\\" + target;
                byte[] data = MountPointData(substitute, target);
                uint returned;
                if (!Native.DeviceIoControl(handle, FsctlSetReparsePoint, data, (uint)data.Length, null, 0, out returned, IntPtr.Zero))
                {
                    throw new InvalidOperationException("npm_link step=fsctl error=" + Marshal.GetLastWin32Error().ToString());
                }
                if (!ReadsBack(handle, substitute))
                {
                    throw new InvalidOperationException("npm_link step=readback error=0");
                }
                return "verified";
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    Native.CloseHandle(handle);
                }
                foreach (IntPtr item in held)
                {
                    Native.CloseHandle(item);
                }
            }
        }

        public static bool Verify(string projectRoot, string linkRelative, string targetRelative)
        {
            List<IntPtr> held = new List<IntPtr>();
            IntPtr handle = IntPtr.Zero;
            try
            {
                string root = Root(projectRoot);
                string[] linkParts = Parts(linkRelative);
                string[] targetParts = Parts(targetRelative);
                string target = Join(root, targetParts, targetParts.Length);
                string link = Join(root, linkParts, linkParts.Length);
                held.Add(OpenVerified(root, false));
                for (int index = 1; index < linkParts.Length; ++index)
                {
                    held.Add(OpenVerified(Join(root, linkParts, index), false));
                }
                handle = Native.CreateFileW("\\\\?\\" + link, FileReadAttributes | Synchronize, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
                if (handle == InvalidHandle || handle == IntPtr.Zero)
                {
                    handle = IntPtr.Zero;
                    return false;
                }
                uint attributes;
                uint links;
                ulong size;
                ReadInformation(handle, out attributes, out links, out size);
                if ((attributes & AttributeDirectory) == 0 || (attributes & AttributeReparsePoint) == 0)
                {
                    return false;
                }
                return ReadsBack(handle, "\\??\\" + target);
            }
            catch
            {
                return false;
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    Native.CloseHandle(handle);
                }
                foreach (IntPtr item in held)
                {
                    Native.CloseHandle(item);
                }
            }
        }

        public static byte[] ReadLinkDacl(string projectRoot, string linkRelative, string targetRelative)
        {
            List<IntPtr> held = new List<IntPtr>();
            IntPtr handle = IntPtr.Zero;
            try
            {
                handle = OpenLink(projectRoot, linkRelative, targetRelative, ReadControl, held);
                uint needed;
                bool first = Native.GetKernelObjectSecurity(handle, DaclSecurityInformation, null, 0, out needed);
                int error = Marshal.GetLastWin32Error();
                if (first || error != 122 || needed < 20 || needed > MaxDescriptorBytes)
                {
                    throw new InvalidOperationException("npm_link_lease step=read_size error=" + error.ToString());
                }
                byte[] buffer = new byte[needed];
                if (!Native.GetKernelObjectSecurity(handle, DaclSecurityInformation, buffer, needed, out needed))
                {
                    throw new InvalidOperationException("npm_link_lease step=read error=" + Marshal.GetLastWin32Error().ToString());
                }
                return buffer;
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    Native.CloseHandle(handle);
                }
                foreach (IntPtr item in held)
                {
                    Native.CloseHandle(item);
                }
            }
        }

        public static void WriteLinkDacl(string projectRoot, string linkRelative, string targetRelative, byte[] descriptor)
        {
            if (descriptor == null || descriptor.Length < 20 || descriptor.Length > MaxDescriptorBytes)
            {
                throw new InvalidOperationException("npm_link_lease step=write_shape error=0");
            }
            List<IntPtr> held = new List<IntPtr>();
            IntPtr handle = IntPtr.Zero;
            try
            {
                handle = OpenLink(projectRoot, linkRelative, targetRelative, ReadControl | WriteDac, held);
                if (!Native.SetKernelObjectSecurity(handle, DaclSecurityInformation, descriptor))
                {
                    throw new InvalidOperationException("npm_link_lease step=write error=" + Marshal.GetLastWin32Error().ToString());
                }
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    Native.CloseHandle(handle);
                }
                foreach (IntPtr item in held)
                {
                    Native.CloseHandle(item);
                }
            }
        }

        public static int OpenNoFollowError(string projectRoot, string linkRelative)
        {
            string root = Root(projectRoot);
            string[] linkParts = Parts(linkRelative);
            string link = Join(root, linkParts, linkParts.Length);
            IntPtr held = OpenVerified(root, false);
            try
            {
                IntPtr handle = Native.CreateFileW("\\\\?\\" + link, FileReadAttributes | Synchronize, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
                if (handle == InvalidHandle || handle == IntPtr.Zero)
                {
                    return Marshal.GetLastWin32Error();
                }
                Native.CloseHandle(handle);
                return 0;
            }
            finally
            {
                Native.CloseHandle(held);
            }
        }

        private static IntPtr OpenLink(string projectRoot, string linkRelative, string targetRelative, uint access, List<IntPtr> held)
        {
            string root = Root(projectRoot);
            string[] linkParts = Parts(linkRelative);
            string[] targetParts = Parts(targetRelative);
            string target = Join(root, targetParts, targetParts.Length);
            string link = Join(root, linkParts, linkParts.Length);
            held.Add(OpenVerified(root, false));
            for (int index = 1; index < linkParts.Length; ++index)
            {
                held.Add(OpenVerified(Join(root, linkParts, index), false));
            }
            IntPtr handle = Native.CreateFileW("\\\\?\\" + link, access | FileReadAttributes | Synchronize, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
            if (handle == InvalidHandle || handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("npm_link_lease step=open error=" + Marshal.GetLastWin32Error().ToString());
            }
            try
            {
                uint attributes;
                uint links;
                ulong size;
                ReadInformation(handle, out attributes, out links, out size);
                if ((attributes & AttributeDirectory) == 0 || (attributes & AttributeReparsePoint) == 0 || !ReadsBack(handle, "\\??\\" + target))
                {
                    throw new InvalidOperationException("npm_link_lease step=shape error=0");
                }
            }
            catch
            {
                Native.CloseHandle(handle);
                throw;
            }
            return handle;
        }

        public static byte[] ReadNoFollow(string path, int maxBytes)
        {
            if (string.IsNullOrEmpty(path) || path.Length < 4 || path[1] != ':' || path[2] != '\\' || maxBytes < 1)
            {
                throw new InvalidOperationException("read_path");
            }
            IntPtr handle = Native.CreateFileW("\\\\?\\" + path, FileReadData | FileReadAttributes | Synchronize, ShareRead, IntPtr.Zero, OpenExisting, FlagOpenReparsePoint, IntPtr.Zero);
            if (handle == InvalidHandle || handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("read_open error=" + Marshal.GetLastWin32Error().ToString());
            }
            try
            {
                uint attributes;
                uint links;
                ulong size;
                ReadInformation(handle, out attributes, out links, out size);
                if ((attributes & (AttributeDirectory | AttributeReparsePoint)) != 0 || links != 1 || size > (ulong)maxBytes)
                {
                    throw new InvalidOperationException("read_shape");
                }
                byte[] buffer = new byte[(int)size];
                int offset = 0;
                while (offset < buffer.Length)
                {
                    uint got;
                    if (!Native.ReadFile(handle, buffer, offset, (uint)(buffer.Length - offset), out got) || got == 0)
                    {
                        throw new InvalidOperationException("read_data");
                    }
                    offset += (int)got;
                }
                byte[] extra = new byte[1];
                uint more;
                if (!Native.ReadFile(handle, extra, 0, 1, out more) || more != 0)
                {
                    throw new InvalidOperationException("read_grew");
                }
                return buffer;
            }
            finally
            {
                Native.CloseHandle(handle);
            }
        }

        private static string Root(string projectRoot)
        {
            if (string.IsNullOrEmpty(projectRoot) || projectRoot.Length < 4 || projectRoot.Length > 400 || projectRoot[1] != ':' || projectRoot[2] != '\\' || projectRoot.EndsWith("\\", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("npm_link step=root error=0");
            }
            char drive = projectRoot[0];
            if (!((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')))
            {
                throw new InvalidOperationException("npm_link step=root error=0");
            }
            foreach (string part in projectRoot.Substring(3).Split('\\'))
            {
                if (part.Length == 0 || part == "." || part == ".." || !SafeText(part, "_.-"))
                {
                    throw new InvalidOperationException("npm_link step=root error=0");
                }
            }
            return projectRoot;
        }

        private static string[] Parts(string relative)
        {
            if (string.IsNullOrEmpty(relative) || relative.Length > 200)
            {
                throw new InvalidOperationException("npm_link step=path error=0");
            }
            string[] parts = relative.Split('/');
            if (parts.Length > MaxComponents)
            {
                throw new InvalidOperationException("npm_link step=path error=0");
            }
            foreach (string part in parts)
            {
                if (part.Length == 0 || part.Length > MaxComponentChars || part.StartsWith(".", StringComparison.Ordinal) || part.EndsWith(".", StringComparison.Ordinal) || !SafeText(part, "@._-"))
                {
                    throw new InvalidOperationException("npm_link step=path error=0");
                }
            }
            return parts;
        }

        private static bool SafeText(string text, string extra)
        {
            foreach (char value in text)
            {
                bool plain = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9');
                if (!plain && extra.IndexOf(value) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        private static string Join(string root, string[] parts, int count)
        {
            StringBuilder text = new StringBuilder(root);
            for (int index = 0; index < count; ++index)
            {
                text.Append('\\');
                text.Append(parts[index]);
            }
            return text.ToString();
        }

        private static IntPtr OpenVerified(string path, bool create)
        {
            string extended = "\\\\?\\" + path;
            IntPtr handle = Native.CreateFileW(extended, FileReadAttributes | Synchronize, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
            if (handle == InvalidHandle || handle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (!create || (error != ErrorFileNotFound && error != ErrorPathNotFound))
                {
                    throw new InvalidOperationException("npm_link step=open_parent error=" + error.ToString());
                }
                if (!Native.CreateDirectoryW(extended, IntPtr.Zero))
                {
                    throw new InvalidOperationException("npm_link step=mkdir_parent error=" + Marshal.GetLastWin32Error().ToString());
                }
                handle = Native.CreateFileW(extended, FileReadAttributes | Synchronize, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
                if (handle == InvalidHandle || handle == IntPtr.Zero)
                {
                    throw new InvalidOperationException("npm_link step=open_parent error=" + Marshal.GetLastWin32Error().ToString());
                }
            }
            try
            {
                RequirePlainDirectory(handle, path);
            }
            catch
            {
                Native.CloseHandle(handle);
                throw;
            }
            return handle;
        }

        private static void RequirePlainDirectory(IntPtr handle, string path)
        {
            uint attributes;
            uint links;
            ulong size;
            ReadInformation(handle, out attributes, out links, out size);
            if ((attributes & AttributeDirectory) == 0 || (attributes & AttributeReparsePoint) != 0)
            {
                throw new InvalidOperationException("npm_link step=shape error=0");
            }
            if (!string.Equals(FinalPath(handle), "\\\\?\\" + path, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("npm_link step=redirected error=0");
            }
        }

        private static string FinalPath(IntPtr handle)
        {
            StringBuilder buffer = new StringBuilder(FinalPathChars);
            uint length = Native.GetFinalPathNameByHandleW(handle, buffer, (uint)FinalPathChars, 0);
            if (length == 0 || length >= FinalPathChars)
            {
                throw new InvalidOperationException("npm_link step=final error=" + Marshal.GetLastWin32Error().ToString());
            }
            return buffer.ToString();
        }

        private static void ReadInformation(IntPtr handle, out uint attributes, out uint links, out ulong size)
        {
            IntPtr buffer = Marshal.AllocHGlobal(InformationBytes);
            try
            {
                if (!Native.GetFileInformationByHandle(handle, buffer))
                {
                    throw new InvalidOperationException("npm_link step=query error=" + Marshal.GetLastWin32Error().ToString());
                }
                attributes = unchecked((uint)Marshal.ReadInt32(buffer, 0));
                ulong high = unchecked((uint)Marshal.ReadInt32(buffer, 32));
                ulong low = unchecked((uint)Marshal.ReadInt32(buffer, 36));
                size = (high << 32) | low;
                links = unchecked((uint)Marshal.ReadInt32(buffer, 40));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static byte[] MountPointData(string substitute, string print)
        {
            byte[] substituteBytes = Encoding.Unicode.GetBytes(substitute);
            byte[] printBytes = Encoding.Unicode.GetBytes(print);
            int pathBytes = substituteBytes.Length + 2 + printBytes.Length + 2;
            if (16 + pathBytes > MaxReparseBytes)
            {
                throw new InvalidOperationException("npm_link step=length error=0");
            }
            byte[] data = new byte[16 + pathBytes];
            WriteUInt32(data, 0, ReparseTagMountPoint);
            WriteUInt16(data, 4, 8 + pathBytes);
            WriteUInt16(data, 6, 0);
            WriteUInt16(data, 8, 0);
            WriteUInt16(data, 10, substituteBytes.Length);
            WriteUInt16(data, 12, substituteBytes.Length + 2);
            WriteUInt16(data, 14, printBytes.Length);
            Buffer.BlockCopy(substituteBytes, 0, data, 16, substituteBytes.Length);
            Buffer.BlockCopy(printBytes, 0, data, 16 + substituteBytes.Length + 2, printBytes.Length);
            return data;
        }

        private static bool ReadsBack(IntPtr handle, string substitute)
        {
            byte[] output = new byte[MaxReparseBytes];
            uint returned;
            if (!Native.DeviceIoControl(handle, FsctlGetReparsePoint, null, 0, output, (uint)output.Length, out returned, IntPtr.Zero))
            {
                return false;
            }
            if (returned < 16 || returned > output.Length || BitConverter.ToUInt32(output, 0) != ReparseTagMountPoint)
            {
                return false;
            }
            int offset = BitConverter.ToUInt16(output, 8);
            int length = BitConverter.ToUInt16(output, 10);
            if ((offset % 2) != 0 || (length % 2) != 0 || 16 + offset + length > (int)returned)
            {
                return false;
            }
            string found = Encoding.Unicode.GetString(output, 16 + offset, length);
            return string.Equals(found, substitute, StringComparison.Ordinal);
        }

        private static void WriteUInt32(byte[] data, int offset, uint value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            Buffer.BlockCopy(bytes, 0, data, offset, 4);
        }

        private static void WriteUInt16(byte[] data, int offset, int value)
        {
            if (value < 0 || value > 65535)
            {
                throw new InvalidOperationException("npm_link step=length error=0");
            }
            byte[] bytes = BitConverter.GetBytes((ushort)value);
            Buffer.BlockCopy(bytes, 0, data, offset, 2);
        }

        private static class Native
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            internal static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CreateDirectoryW(string name, IntPtr security);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool DeviceIoControl(IntPtr handle, uint code, byte[] input, uint inputSize, byte[] output, uint outputSize, out uint returned, IntPtr overlapped);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetFileInformationByHandle(IntPtr handle, IntPtr information);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            internal static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint length, uint flags);

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetKernelObjectSecurity(IntPtr handle, uint information, byte[] descriptor, uint length, out uint needed);

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool SetKernelObjectSecurity(IntPtr handle, uint information, byte[] descriptor);

            [DllImport("kernel32.dll", EntryPoint = "ReadFile", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool ReadFileCore(IntPtr handle, IntPtr buffer, uint count, out uint read, IntPtr overlapped);

            internal static bool ReadFile(IntPtr handle, byte[] buffer, int offset, uint count, out uint read)
            {
                GCHandle pinned = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                try
                {
                    IntPtr start = new IntPtr(pinned.AddrOfPinnedObject().ToInt64() + offset);
                    return ReadFileCore(handle, start, count, out read, IntPtr.Zero);
                }
                finally
                {
                    pinned.Free();
                }
            }

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseHandle(IntPtr handle);
        }
    }
}
