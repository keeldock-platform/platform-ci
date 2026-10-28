using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace KeelDock.Platform.CapsuleFrame
{
    public static class RefusalCode
    {
        public const string Downgrade = "downgrade_refused";
        public const string Length = "length_out_of_bounds";
        public const string Noncanonical = "noncanonical_encoding";
        public const string ChunkIndex = "chunk_index_invalid";
        public const string Trailing = "trailing_data";
        public const string ManifestLimit = "manifest_limit";
        public const string Point = "invalid_point";
        public const string Structure = "invalid_structure";
        public const string Crypto = "crypto_refused";

        public static readonly IList<string> All = Array.AsReadOnly(new string[]
        {
            Downgrade, Length, Noncanonical, ChunkIndex, Trailing,
            ManifestLimit, Point, Structure, Crypto
        });
    }

    public sealed class CapsuleRefusal : Exception
    {
        public string Reason { get; private set; }

        public CapsuleRefusal(string reason) : base(reason)
        {
            Reason = RefusalCode.All.Contains(reason, StringComparer.Ordinal)
                ? reason
                : RefusalCode.Structure;
        }
    }

    public sealed class KeyRecord
    {
        public ulong ControlRepositoryId;
        public byte[] ControlSha;
        public ulong RunId;
        public uint Attempt;
        public byte[] TransferId;
        public byte[] ReceiverPublicPoint;
        public byte[] WorkflowRefSha256;
        public ulong CreatedAt;
        public ulong ExpiresAt;

        public byte[] KeyId
        {
            get { return CapsuleCodec.Sha256(ReceiverPublicPoint); }
        }
    }

    public sealed class CapsuleHeader
    {
        public ulong ControlRepositoryId;
        public byte[] ControlSha;
        public ulong RunId;
        public uint Attempt;
        public byte[] TransferId;
        public byte[] ReceiverKeyId;
        public byte[] KeyRecordSha256;
        public byte[] SenderPublicPoint;
        public byte[] HkdfSalt;
        public byte[] NoncePrefix;
        public ulong CreatedAt;
        public ulong ExpiresAt;
        public byte[] WorkflowRefSha256;
        public byte[] IntendedJobSha256;
    }

    public sealed class ChunkRecord
    {
        public uint Index;
        public byte Kind;
        public byte[] Ciphertext;
        public byte[] Tag;
    }

    public sealed class ManifestEntry
    {
        public string Path;
        public uint Mode;
        public byte[] BlobId;
        public ulong Size;
        public byte[] Sha256;
    }

    public sealed class Manifest
    {
        public ulong SourceRepositoryId;
        public byte[] SourceSha;
        public byte[] TreeId;
        public byte[] BundleSha256;
        public ulong BundleLength;
        public IList<ManifestEntry> Entries;
    }

    public sealed class Capsule
    {
        public CapsuleHeader Header;
        public IList<ChunkRecord> ManifestChunks;
        public IList<ChunkRecord> BundleChunks;
        public byte[] Trailer;
    }

    public sealed class CapsuleView
    {
        private readonly byte[] data;
        public CapsuleHeader Header { get; private set; }

        internal CapsuleView(byte[] capsuleBytes, CapsuleHeader header)
        {
            data = capsuleBytes;
            Header = header;
        }

        public ChunkRecord GetChunk(uint index)
        {
            byte kind = CapsuleCodec.ChunkKind(index);
            int offset = CapsuleCodec.ChunkOffset(index);
            byte[] ciphertext = new byte[CapsuleCodec.ChunkPlaintextBytes];
            byte[] tag = new byte[CapsuleCodec.ChunkTagBytes];
            Buffer.BlockCopy(data, offset, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(data, offset + ciphertext.Length, tag, 0, tag.Length);
            return new ChunkRecord { Index = index, Kind = kind, Ciphertext = ciphertext, Tag = tag };
        }

        public byte[] GetManifestCiphertextRegion()
        {
            byte[] region = new byte[CapsuleCodec.ManifestRegionLength];
            Buffer.BlockCopy(data, CapsuleCodec.CapsuleHeaderLength, region, 0, region.Length);
            return region;
        }

        public byte[] GetTrailer()
        {
            byte[] trailer = new byte[CapsuleCodec.TrailerLength];
            Buffer.BlockCopy(data, CapsuleCodec.TrailerStart, trailer, 0, trailer.Length);
            return trailer;
        }
    }

    public static class CapsuleCodec
    {
        public const int KeyRecordLength = 320;
        public const int CapsuleHeaderLength = 65536;
        public const int CapsuleLength = 286261248;
        public const int ChunkPlaintextBytes = 1048576;
        public const int ChunkTagBytes = 16;
        public const int ChunkRecordLength = ChunkPlaintextBytes + ChunkTagBytes;
        public const int ManifestChunkCount = 16;
        public const int BundleChunkCount = 256;
        public const int ChunkCount = ManifestChunkCount + BundleChunkCount;
        public const int ManifestRegionLength = ManifestChunkCount * ChunkRecordLength;
        public const int BundleRegionLength = BundleChunkCount * ChunkRecordLength;
        public const int BundleRegionStart = CapsuleHeaderLength + ManifestRegionLength;
        public const int TrailerStart = BundleRegionStart + BundleRegionLength;
        public const int TrailerLength = CapsuleLength - TrailerStart;
        public const int ManifestPlaintextLength = ManifestChunkCount * ChunkPlaintextBytes;
        public const int BundlePlaintextLength = BundleChunkCount * ChunkPlaintextBytes;
        public const int MaximumManifestBodyBytes = ManifestPlaintextLength - 8;
        public const int MaximumBundleBodyBytes = BundlePlaintextLength - 8;
        public const int MaximumManifestEntries = 10000;
        public const ulong MaximumEntryBytes = 64UL * 1024UL * 1024UL;
        public const ulong MaximumTreeBytes = 1024UL * 1024UL * 1024UL;
        public const int MaximumPathUtf16Units = 240;
        public const ushort Version = 1;
        public const ushort Suite = 1;

        private static readonly byte[] KeyMagic = Encoding.ASCII.GetBytes("KDWHKEY1");
        private static readonly byte[] CapsuleMagic = Encoding.ASCII.GetBytes("KDWHCAP1");
        private static readonly byte[] HkdfDomain = Encoding.ASCII.GetBytes("KDWH-v1/HKDF-AES256GCM");
        private static readonly byte[] AadDomain = Encoding.ASCII.GetBytes("KDWH-v1/GCM-CHUNK");
        private static readonly byte[] ReceiverJobSha256 = Sha256(Encoding.ASCII.GetBytes("windows-receiver"));
        private static readonly byte[] RunnerLabelSha256 = Sha256(Encoding.ASCII.GetBytes("windows-2025"));
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private static void Refuse(string reason)
        {
            throw new CapsuleRefusal(reason);
        }

        private static void Require(bool condition, string reason)
        {
            if (!condition) Refuse(reason);
        }

        private static void CheckBytes(byte[] value, int length, string reason)
        {
            Require(value != null && value.Length == length, reason);
        }

        private static void CheckPositive(ulong value)
        {
            Require(value != 0, RefusalCode.Structure);
        }

        public static string ToHex(byte[] value)
        {
            if (value == null) Refuse(RefusalCode.Structure);
            StringBuilder result = new StringBuilder(value.Length * 2);
            for (int i = 0; i < value.Length; i++) result.Append(value[i].ToString("x2", CultureInfo.InvariantCulture));
            return result.ToString();
        }

        public static byte[] Sha256(byte[] value)
        {
            if (value == null) Refuse(RefusalCode.Structure);
            using (SHA256 hash = SHA256.Create()) return hash.ComputeHash(value);
        }

        private static byte[] UInt16(ushort value)
        {
            return new byte[] { (byte)(value >> 8), (byte)value };
        }

        private static byte[] UInt32(uint value)
        {
            return new byte[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };
        }

        private static byte[] UInt64(ulong value)
        {
            return new byte[]
            {
                (byte)(value >> 56), (byte)(value >> 48), (byte)(value >> 40), (byte)(value >> 32),
                (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value
            };
        }

        private static ushort ReadUInt16(byte[] value, int offset)
        {
            return (ushort)((value[offset] << 8) | value[offset + 1]);
        }

        private static uint ReadUInt32(byte[] value, int offset)
        {
            return ((uint)value[offset] << 24) | ((uint)value[offset + 1] << 16) |
                ((uint)value[offset + 2] << 8) | value[offset + 3];
        }

        private static ulong ReadUInt64(byte[] value, int offset)
        {
            ulong result = 0;
            for (int i = 0; i < 8; i++) result = (result << 8) | value[offset + i];
            return result;
        }

        private static void Put(byte[] target, int offset, byte[] value)
        {
            Buffer.BlockCopy(value, 0, target, offset, value.Length);
        }

        private static byte[] Slice(byte[] value, int start, int end)
        {
            int length = end - start;
            byte[] result = new byte[length];
            Buffer.BlockCopy(value, start, result, 0, length);
            return result;
        }

        private static bool IsZero(byte[] value, int start, int end)
        {
            for (int i = start; i < end; i++) if (value[i] != 0) return false;
            return true;
        }

        private static bool Equal(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            int different = 0;
            for (int i = 0; i < left.Length; i++) different |= left[i] ^ right[i];
            return different == 0;
        }

        public static byte[] ValidatePublicPoint(byte[] point)
        {
            CheckBytes(point, 65, RefusalCode.Point);
            Require(point[0] == 4, RefusalCode.Point);
            try
            {
                ECParameters parameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = Slice(point, 1, 33), Y = Slice(point, 33, 65) }
                };
                using (ECDsa key = ECDsa.Create()) key.ImportParameters(parameters);
            }
            catch { Refuse(RefusalCode.Point); }
            return (byte[])point.Clone();
        }

        private static void ValidateKeyRecord(KeyRecord record)
        {
            Require(record != null, RefusalCode.Structure);
            CheckPositive(record.ControlRepositoryId);
            CheckBytes(record.ControlSha, 20, RefusalCode.Structure);
            CheckPositive(record.RunId);
            CheckPositive(record.Attempt);
            CheckBytes(record.TransferId, 16, RefusalCode.Structure);
            ValidatePublicPoint(record.ReceiverPublicPoint);
            CheckBytes(record.WorkflowRefSha256, 32, RefusalCode.Structure);
            Require(record.ExpiresAt > record.CreatedAt, RefusalCode.Structure);
        }

        public static byte[] EncodeKeyRecord(KeyRecord record)
        {
            ValidateKeyRecord(record);
            byte[] output = new byte[KeyRecordLength];
            Put(output, 0, KeyMagic);
            Put(output, 8, UInt16(Version));
            Put(output, 10, UInt16(Suite));
            Put(output, 12, UInt64(record.ControlRepositoryId));
            Put(output, 20, record.ControlSha);
            Put(output, 40, UInt64(record.RunId));
            Put(output, 48, UInt32(record.Attempt));
            Put(output, 52, record.TransferId);
            Put(output, 68, record.KeyId);
            Put(output, 100, record.ReceiverPublicPoint);
            Put(output, 165, record.WorkflowRefSha256);
            Put(output, 197, ReceiverJobSha256);
            Put(output, 229, UInt64(record.CreatedAt));
            Put(output, 237, UInt64(record.ExpiresAt));
            Put(output, 245, UInt64(CapsuleLength));
            Put(output, 253, RunnerLabelSha256);
            return output;
        }

        public static KeyRecord DecodeKeyRecord(byte[] data)
        {
            try { return DecodeKeyRecordCore(data); }
            catch (CapsuleRefusal) { throw; }
            catch { Refuse(RefusalCode.Structure); throw; }
        }

        private static KeyRecord DecodeKeyRecordCore(byte[] data)
        {
            Require(data != null, RefusalCode.Structure);
            if (data.Length > KeyRecordLength) Refuse(RefusalCode.Trailing);
            Require(data.Length == KeyRecordLength, RefusalCode.Length);
            Require(Equal(Slice(data, 0, 8), KeyMagic), RefusalCode.Downgrade);
            Require(ReadUInt16(data, 8) == Version && ReadUInt16(data, 10) == Suite, RefusalCode.Downgrade);
            Require(Equal(Slice(data, 197, 229), ReceiverJobSha256), RefusalCode.Structure);
            Require(ReadUInt64(data, 245) == CapsuleLength, RefusalCode.Length);
            Require(Equal(Slice(data, 253, 285), RunnerLabelSha256), RefusalCode.Structure);
            Require(IsZero(data, 285, KeyRecordLength), RefusalCode.Structure);
            KeyRecord record = new KeyRecord
            {
                ControlRepositoryId = ReadUInt64(data, 12),
                ControlSha = Slice(data, 20, 40),
                RunId = ReadUInt64(data, 40),
                Attempt = ReadUInt32(data, 48),
                TransferId = Slice(data, 52, 68),
                ReceiverPublicPoint = Slice(data, 100, 165),
                WorkflowRefSha256 = Slice(data, 165, 197),
                CreatedAt = ReadUInt64(data, 229),
                ExpiresAt = ReadUInt64(data, 237)
            };
            ValidateKeyRecord(record);
            Require(Equal(Slice(data, 68, 100), record.KeyId), RefusalCode.Structure);
            return record;
        }

        private static void ValidateHeader(CapsuleHeader header)
        {
            Require(header != null, RefusalCode.Structure);
            CheckPositive(header.ControlRepositoryId);
            CheckBytes(header.ControlSha, 20, RefusalCode.Structure);
            CheckPositive(header.RunId);
            CheckPositive(header.Attempt);
            CheckBytes(header.TransferId, 16, RefusalCode.Structure);
            CheckBytes(header.ReceiverKeyId, 32, RefusalCode.Structure);
            CheckBytes(header.KeyRecordSha256, 32, RefusalCode.Structure);
            ValidatePublicPoint(header.SenderPublicPoint);
            CheckBytes(header.HkdfSalt, 32, RefusalCode.Structure);
            CheckBytes(header.NoncePrefix, 4, RefusalCode.Structure);
            Require(header.ExpiresAt > header.CreatedAt, RefusalCode.Structure);
            CheckBytes(header.WorkflowRefSha256, 32, RefusalCode.Structure);
            CheckBytes(header.IntendedJobSha256, 32, RefusalCode.Structure);
            Require(Equal(header.IntendedJobSha256, ReceiverJobSha256), RefusalCode.Structure);
        }

        public static byte[] EncodeCapsuleHeader(CapsuleHeader header)
        {
            ValidateHeader(header);
            byte[] output = new byte[CapsuleHeaderLength];
            Put(output, 0, CapsuleMagic);
            Put(output, 8, UInt16(Version));
            Put(output, 10, UInt16(Suite));
            Put(output, 16, UInt64(header.ControlRepositoryId));
            Put(output, 24, header.ControlSha);
            Put(output, 44, UInt64(header.RunId));
            Put(output, 52, UInt32(header.Attempt));
            Put(output, 56, header.TransferId);
            Put(output, 72, header.ReceiverKeyId);
            Put(output, 104, header.KeyRecordSha256);
            Put(output, 136, header.SenderPublicPoint);
            Put(output, 201, header.HkdfSalt);
            Put(output, 233, header.NoncePrefix);
            Put(output, 237, UInt64(header.CreatedAt));
            Put(output, 245, UInt64(header.ExpiresAt));
            Put(output, 253, header.WorkflowRefSha256);
            Put(output, 285, header.IntendedJobSha256);
            Put(output, 317, UInt32(ManifestChunkCount));
            Put(output, 321, UInt32(BundleChunkCount));
            Put(output, 325, UInt32(ChunkPlaintextBytes));
            Put(output, 329, UInt64(CapsuleLength));
            return output;
        }

        public static CapsuleHeader DecodeCapsuleHeader(byte[] data)
        {
            try { return DecodeCapsuleHeaderCore(data); }
            catch (CapsuleRefusal) { throw; }
            catch { Refuse(RefusalCode.Structure); throw; }
        }

        private static CapsuleHeader DecodeCapsuleHeaderCore(byte[] data)
        {
            Require(data != null, RefusalCode.Structure);
            if (data.Length > CapsuleHeaderLength) Refuse(RefusalCode.Trailing);
            Require(data.Length == CapsuleHeaderLength, RefusalCode.Length);
            Require(Equal(Slice(data, 0, 8), CapsuleMagic), RefusalCode.Downgrade);
            Require(ReadUInt16(data, 8) == Version && ReadUInt16(data, 10) == Suite, RefusalCode.Downgrade);
            Require(IsZero(data, 12, 16), RefusalCode.Structure);
            Require(ReadUInt32(data, 317) == ManifestChunkCount, RefusalCode.Structure);
            Require(ReadUInt32(data, 321) == BundleChunkCount, RefusalCode.Structure);
            Require(ReadUInt32(data, 325) == ChunkPlaintextBytes, RefusalCode.Structure);
            Require(ReadUInt64(data, 329) == CapsuleLength, RefusalCode.Length);
            Require(IsZero(data, 337, CapsuleHeaderLength), RefusalCode.Structure);
            CapsuleHeader header = new CapsuleHeader
            {
                ControlRepositoryId = ReadUInt64(data, 16),
                ControlSha = Slice(data, 24, 44),
                RunId = ReadUInt64(data, 44),
                Attempt = ReadUInt32(data, 52),
                TransferId = Slice(data, 56, 72),
                ReceiverKeyId = Slice(data, 72, 104),
                KeyRecordSha256 = Slice(data, 104, 136),
                SenderPublicPoint = Slice(data, 136, 201),
                HkdfSalt = Slice(data, 201, 233),
                NoncePrefix = Slice(data, 233, 237),
                CreatedAt = ReadUInt64(data, 237),
                ExpiresAt = ReadUInt64(data, 245),
                WorkflowRefSha256 = Slice(data, 253, 285),
                IntendedJobSha256 = Slice(data, 285, 317)
            };
            ValidateHeader(header);
            return header;
        }

        public static bool ValidateHeaderKeyBinding(CapsuleHeader header, byte[] keyRecordBytes)
        {
            ValidateHeader(header);
            KeyRecord record = DecodeKeyRecord(keyRecordBytes);
            Require(header.ControlRepositoryId == record.ControlRepositoryId &&
                Equal(header.ControlSha, record.ControlSha) && header.RunId == record.RunId &&
                header.Attempt == record.Attempt && Equal(header.TransferId, record.TransferId) &&
                Equal(header.ReceiverKeyId, record.KeyId) &&
                Equal(header.KeyRecordSha256, Sha256(keyRecordBytes)) &&
                header.CreatedAt == record.CreatedAt && header.ExpiresAt == record.ExpiresAt &&
                Equal(header.WorkflowRefSha256, record.WorkflowRefSha256) &&
                Equal(header.IntendedJobSha256, ReceiverJobSha256), RefusalCode.Structure);
            return true;
        }

        public static byte ChunkKind(uint index)
        {
            Require(index < ChunkCount, RefusalCode.ChunkIndex);
            return index < ManifestChunkCount ? (byte)0 : (byte)1;
        }

        public static int ChunkOffset(uint index)
        {
            ChunkKind(index);
            return CapsuleHeaderLength + checked((int)index * ChunkRecordLength);
        }

        public static byte[] EncodeChunk(uint index, byte[] ciphertext, byte[] tag, byte? kind)
        {
            byte expected = ChunkKind(index);
            Require(!kind.HasValue || kind.Value == expected, RefusalCode.ChunkIndex);
            CheckBytes(ciphertext, ChunkPlaintextBytes, RefusalCode.Length);
            CheckBytes(tag, ChunkTagBytes, RefusalCode.Length);
            byte[] output = new byte[ChunkRecordLength];
            Put(output, 0, ciphertext);
            Put(output, ChunkPlaintextBytes, tag);
            return output;
        }

        public static ChunkRecord DecodeChunk(byte[] data, uint index, byte? kind)
        {
            byte expected = ChunkKind(index);
            Require(!kind.HasValue || kind.Value == expected, RefusalCode.ChunkIndex);
            Require(data != null, RefusalCode.Structure);
            if (data.Length > ChunkRecordLength) Refuse(RefusalCode.Trailing);
            Require(data.Length == ChunkRecordLength, RefusalCode.Length);
            return new ChunkRecord
            {
                Index = index,
                Kind = expected,
                Ciphertext = Slice(data, 0, ChunkPlaintextBytes),
                Tag = Slice(data, ChunkPlaintextBytes, ChunkRecordLength)
            };
        }

        public static void ValidateChunkSequence(IList<ChunkRecord> chunks)
        {
            Require(chunks != null && chunks.Count == ChunkCount, RefusalCode.ChunkIndex);
            for (int i = 0; i < chunks.Count; i++)
            {
                ChunkRecord chunk = chunks[i];
                Require(chunk != null && chunk.Index == (uint)i && chunk.Kind == ChunkKind((uint)i), RefusalCode.ChunkIndex);
                CheckBytes(chunk.Ciphertext, ChunkPlaintextBytes, RefusalCode.Length);
                CheckBytes(chunk.Tag, ChunkTagBytes, RefusalCode.Length);
            }
        }

        public static byte[] EncodeTrailer(byte[] trailer)
        {
            CheckBytes(trailer, TrailerLength, RefusalCode.Length);
            return (byte[])trailer.Clone();
        }

        public static byte[] DecodeTrailer(byte[] trailer)
        {
            Require(trailer != null, RefusalCode.Structure);
            if (trailer.Length > TrailerLength) Refuse(RefusalCode.Trailing);
            CheckBytes(trailer, TrailerLength, RefusalCode.Length);
            return (byte[])trailer.Clone();
        }

        private static int CompareBytes(byte[] left, byte[] right)
        {
            int length = Math.Min(left.Length, right.Length);
            for (int i = 0; i < length; i++)
            {
                if (left[i] < right[i]) return -1;
                if (left[i] > right[i]) return 1;
            }
            return left.Length.CompareTo(right.Length);
        }

        private static string CaseFoldAlias(string value)
        {
            return value.ToLowerInvariant();
        }

        private static bool IsPathSafe(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length > MaximumPathUtf16Units) return false;
            try
            {
                if (!String.Equals(path.Normalize(NormalizationForm.FormC), path, StringComparison.Ordinal)) return false;
                byte[] encoded = StrictUtf8.GetBytes(path);
                if (encoded.Length == 0 || path.StartsWith("/", StringComparison.Ordinal) || path.IndexOf('\\') >= 0) return false;
            }
            catch { return false; }
            foreach (char item in path)
            {
                if (item < 32 || item > 126 || "<>:\"|?*".IndexOf(item) >= 0) return false;
            }
            string[] components = path.Split('/');
            foreach (string component in components)
            {
                if (component.Length == 0 || component == "." || component == ".." ||
                    component.EndsWith(".", StringComparison.Ordinal) || component.EndsWith(" ", StringComparison.Ordinal)) return false;
                string baseName = component.Split('.')[0].ToUpperInvariant();
                if (new string[] { "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$" }.Contains(baseName, StringComparer.Ordinal)) return false;
                if (baseName.Length == 4 && (baseName.Substring(0, 3) == "COM" || baseName.Substring(0, 3) == "LPT") &&
                    "123456789\u00b9\u00b2\u00b3".IndexOf(baseName[3]) >= 0) return false;
            }
            return true;
        }

        private static void ValidateManifest(Manifest manifest)
        {
            Require(manifest != null, RefusalCode.Structure);
            CheckPositive(manifest.SourceRepositoryId);
            CheckBytes(manifest.SourceSha, 20, RefusalCode.Structure);
            CheckBytes(manifest.TreeId, 20, RefusalCode.Structure);
            CheckBytes(manifest.BundleSha256, 32, RefusalCode.Structure);
            Require(manifest.BundleLength <= (ulong)MaximumBundleBodyBytes, RefusalCode.ManifestLimit);
            Require(manifest.Entries != null, RefusalCode.Structure);
            Require(manifest.Entries.Count <= MaximumManifestEntries, RefusalCode.ManifestLimit);
            byte[] previousPath = null;
            HashSet<string> aliases = new HashSet<string>(StringComparer.Ordinal);
            SortedSet<string> sortedAliases = new SortedSet<string>(StringComparer.Ordinal);
            ulong totalSize = 0;
            for (int i = 0; i < manifest.Entries.Count; i++)
            {
                ManifestEntry entry = manifest.Entries[i];
                Require(entry != null, RefusalCode.Structure);
                if (!IsPathSafe(entry.Path)) Refuse(RefusalCode.ManifestLimit);
                byte[] pathBytes;
                try { pathBytes = StrictUtf8.GetBytes(entry.Path); }
                catch { Refuse(RefusalCode.ManifestLimit); throw; }
                Require(previousPath == null || CompareBytes(pathBytes, previousPath) > 0, RefusalCode.ManifestLimit);
                previousPath = pathBytes;
                string alias = CaseFoldAlias(entry.Path);
                Require(aliases.Add(alias), RefusalCode.ManifestLimit);
                string[] components = alias.Split('/');
                for (int part = 1; part < components.Length; part++)
                {
                    string parent = String.Join("/", components, 0, part);
                    Require(!aliases.Contains(parent), RefusalCode.ManifestLimit);
                }
                string prefix = alias + "/";
                if (sortedAliases.Count > 0)
                {
                    string upperBound = prefix + new String('\uffff', MaximumPathUtf16Units + 1);
                    string candidate = sortedAliases.GetViewBetween(prefix, upperBound).FirstOrDefault();
                    Require(candidate == null, RefusalCode.ManifestLimit);
                }
                sortedAliases.Add(alias);
                Require(entry.Mode == 33188U || entry.Mode == 33261U, RefusalCode.ManifestLimit);
                CheckBytes(entry.BlobId, 20, RefusalCode.Structure);
                CheckBytes(entry.Sha256, 32, RefusalCode.Structure);
                Require(entry.Size <= MaximumEntryBytes, RefusalCode.ManifestLimit);
                Require(UInt64.MaxValue - totalSize >= entry.Size, RefusalCode.ManifestLimit);
                totalSize += entry.Size;
                Require(totalSize <= MaximumTreeBytes, RefusalCode.ManifestLimit);
            }
        }

        private static void CborLength(List<byte> output, byte major, ulong value)
        {
            if (value < 24) output.Add((byte)((major << 5) | (byte)value));
            else if (value <= Byte.MaxValue)
            {
                output.Add((byte)((major << 5) | 24)); output.Add((byte)value);
            }
            else if (value <= UInt16.MaxValue)
            {
                output.Add((byte)((major << 5) | 25)); output.Add((byte)(value >> 8)); output.Add((byte)value);
            }
            else if (value <= UInt32.MaxValue)
            {
                output.Add((byte)((major << 5) | 26));
                output.AddRange(UInt32((uint)value));
            }
            else
            {
                output.Add((byte)((major << 5) | 27)); output.AddRange(UInt64(value));
            }
        }

        private static void CborUInt(List<byte> output, ulong value) { CborLength(output, 0, value); }

        private static void CborBytes(List<byte> output, byte[] value)
        {
            CborLength(output, 2, (ulong)value.Length);
            output.AddRange(value);
        }

        private static void CborText(List<byte> output, string value)
        {
            byte[] encoded = StrictUtf8.GetBytes(value);
            CborLength(output, 3, (ulong)encoded.Length);
            output.AddRange(encoded);
        }

        public static byte[] EncodeManifest(Manifest manifest)
        {
            ValidateManifest(manifest);
            List<byte> output = new List<byte>();
            CborLength(output, 5, 8);
            CborUInt(output, 1); CborText(output, "KDWH-v1/manifest");
            CborUInt(output, 2); CborUInt(output, manifest.SourceRepositoryId);
            CborUInt(output, 3); CborBytes(output, manifest.SourceSha);
            CborUInt(output, 4); CborText(output, "sha1");
            CborUInt(output, 5); CborBytes(output, manifest.TreeId);
            CborUInt(output, 6); CborBytes(output, manifest.BundleSha256);
            CborUInt(output, 7); CborUInt(output, manifest.BundleLength);
            CborUInt(output, 8); CborLength(output, 4, (ulong)manifest.Entries.Count);
            foreach (ManifestEntry entry in manifest.Entries)
            {
                CborLength(output, 4, 5);
                CborText(output, entry.Path);
                CborUInt(output, entry.Mode);
                CborBytes(output, entry.BlobId);
                CborUInt(output, entry.Size);
                CborBytes(output, entry.Sha256);
            }
            Require(output.Count <= MaximumManifestBodyBytes, RefusalCode.ManifestLimit);
            return output.ToArray();
        }

        private sealed class CborReader
        {
            private readonly byte[] data;
            public int Offset;

            public CborReader(byte[] value) { data = value; Offset = 0; }

            private byte[] Take(int count)
            {
                Require(count >= 0 && count <= data.Length - Offset, RefusalCode.Length);
                byte[] result = Slice(data, Offset, Offset + count);
                Offset += count;
                return result;
            }

            private ulong Argument(byte additional)
            {
                if (additional < 24) return additional;
                if (additional == 24)
                {
                    ulong value = Take(1)[0];
                    Require(value >= 24, RefusalCode.Noncanonical);
                    return value;
                }
                if (additional == 25)
                {
                    byte[] raw = Take(2);
                    ulong value = ((ulong)raw[0] << 8) | raw[1];
                    Require(value > Byte.MaxValue, RefusalCode.Noncanonical);
                    return value;
                }
                if (additional == 26)
                {
                    byte[] raw = Take(4);
                    ulong value = ((ulong)raw[0] << 24) | ((ulong)raw[1] << 16) | ((ulong)raw[2] << 8) | raw[3];
                    Require(value > UInt16.MaxValue, RefusalCode.Noncanonical);
                    return value;
                }
                if (additional == 27)
                {
                    byte[] raw = Take(8);
                    ulong value = ReadUInt64(raw, 0);
                    Require(value > UInt32.MaxValue, RefusalCode.Noncanonical);
                    return value;
                }
                Refuse(RefusalCode.Noncanonical);
                return 0;
            }

            public object Read(int depth)
            {
                Require(depth <= 8, RefusalCode.Structure);
                byte initial = Take(1)[0];
                byte major = (byte)(initial >> 5);
                byte additional = (byte)(initial & 31);
                if (major == 0) return Argument(additional);
                if (major == 2 || major == 3)
                {
                    ulong length = Argument(additional);
                    Require(length <= (ulong)MaximumManifestBodyBytes && length <= Int32.MaxValue, RefusalCode.ManifestLimit);
                    byte[] raw = Take((int)length);
                    if (major == 2) return raw;
                    try { return StrictUtf8.GetString(raw); }
                    catch { Refuse(RefusalCode.Noncanonical); throw; }
                }
                if (major == 4)
                {
                    ulong length = Argument(additional);
                    Require(length <= MaximumManifestEntries, RefusalCode.ManifestLimit);
                    List<object> result = new List<object>();
                    for (ulong i = 0; i < length; i++) result.Add(Read(depth + 1));
                    return result;
                }
                if (major == 5)
                {
                    ulong length = Argument(additional);
                    Require(length == 8, RefusalCode.Structure);
                    SortedDictionary<ulong, object> result = new SortedDictionary<ulong, object>();
                    ulong previous = 0;
                    for (ulong i = 0; i < length; i++)
                    {
                        object keyValue = Read(depth + 1);
                        Require(keyValue is ulong, RefusalCode.Noncanonical);
                        ulong key = (ulong)keyValue;
                        Require(key > previous, RefusalCode.Noncanonical);
                        previous = key;
                        result.Add(key, Read(depth + 1));
                    }
                    return result;
                }
                Refuse(RefusalCode.Structure);
                return null;
            }
        }

        private static ulong CborNumber(object value)
        {
            Require(value is ulong, RefusalCode.Structure);
            return (ulong)value;
        }

        private static byte[] CborByteString(object value)
        {
            Require(value is byte[], RefusalCode.Structure);
            return (byte[])value;
        }

        private static string CborString(object value)
        {
            Require(value is string, RefusalCode.Structure);
            return (string)value;
        }

        public static Manifest DecodeManifest(byte[] data)
        {
            try { return DecodeManifestCore(data); }
            catch (CapsuleRefusal) { throw; }
            catch { Refuse(RefusalCode.Structure); throw; }
        }

        private static Manifest DecodeManifestCore(byte[] data)
        {
            Require(data != null, RefusalCode.Structure);
            Require(data.Length <= MaximumManifestBodyBytes, RefusalCode.ManifestLimit);
            CborReader reader = new CborReader(data);
            object value = reader.Read(0);
            Require(reader.Offset == data.Length, RefusalCode.Trailing);
            Require(value is SortedDictionary<ulong, object>, RefusalCode.Structure);
            SortedDictionary<ulong, object> map = (SortedDictionary<ulong, object>)value;
            Require(map.Count == 8, RefusalCode.Structure);
            for (ulong key = 1; key <= 8; key++) Require(map.ContainsKey(key), RefusalCode.Structure);
            Require(CborString(map[1]) == "KDWH-v1/manifest", RefusalCode.Structure);
            ulong repositoryId = CborNumber(map[2]);
            byte[] sourceSha = CborByteString(map[3]);
            Require(CborString(map[4]) == "sha1", RefusalCode.Structure);
            byte[] treeId = CborByteString(map[5]);
            byte[] bundleSha = CborByteString(map[6]);
            ulong bundleLength = CborNumber(map[7]);
            Require(map[8] is List<object>, RefusalCode.Structure);
            List<object> values = (List<object>)map[8];
            List<ManifestEntry> entries = new List<ManifestEntry>();
            foreach (object item in values)
            {
                Require(item is List<object>, RefusalCode.Structure);
                List<object> fields = (List<object>)item;
                Require(fields.Count == 5, RefusalCode.Structure);
                entries.Add(new ManifestEntry
                {
                    Path = CborString(fields[0]),
                    Mode = checked((uint)CborNumber(fields[1])),
                    BlobId = CborByteString(fields[2]),
                    Size = CborNumber(fields[3]),
                    Sha256 = CborByteString(fields[4])
                });
            }
            Manifest manifest = new Manifest
            {
                SourceRepositoryId = repositoryId,
                SourceSha = sourceSha,
                TreeId = treeId,
                BundleSha256 = bundleSha,
                BundleLength = bundleLength,
                Entries = entries
            };
            ValidateManifest(manifest);
            return manifest;
        }

        public static byte[] EncodeLengthPrefixedRegion(byte[] body, byte[] padding, int capacity, int maximumBody)
        {
            Require(body != null && padding != null, RefusalCode.Structure);
            Require(capacity >= 8 && maximumBody >= 0, RefusalCode.Structure);
            Require(body.Length <= maximumBody && body.Length <= capacity - 8, RefusalCode.Length);
            Require(padding.Length == capacity - 8 - body.Length, RefusalCode.Length);
            byte[] output = new byte[capacity];
            Put(output, 0, UInt64((ulong)body.Length));
            Put(output, 8, body);
            Put(output, 8 + body.Length, padding);
            return output;
        }

        public static Tuple<byte[], byte[]> DecodeLengthPrefixedRegion(byte[] data, int capacity, int maximumBody)
        {
            Require(data != null, RefusalCode.Structure);
            Require(capacity >= 8 && maximumBody >= 0, RefusalCode.Structure);
            Require(data.Length >= 8, RefusalCode.Length);
            ulong bodyLength = ReadUInt64(data, 0);
            Require(bodyLength <= (ulong)maximumBody && bodyLength <= (ulong)(capacity - 8), RefusalCode.Length);
            if (data.Length > capacity) Refuse(RefusalCode.Trailing);
            Require(data.Length == capacity, RefusalCode.Length);
            int end = checked(8 + (int)bodyLength);
            return Tuple.Create(Slice(data, 8, end), Slice(data, end, data.Length));
        }

        public static byte[] EncodeManifestRegion(Manifest manifest, byte[] padding)
        {
            return EncodeLengthPrefixedRegion(EncodeManifest(manifest), padding, ManifestPlaintextLength, MaximumManifestBodyBytes);
        }

        public static Tuple<Manifest, byte[]> DecodeManifestRegion(byte[] data)
        {
            Tuple<byte[], byte[]> parts = DecodeLengthPrefixedRegion(data, ManifestPlaintextLength, MaximumManifestBodyBytes);
            return Tuple.Create(DecodeManifest(parts.Item1), parts.Item2);
        }

        public static byte[] EncodeBundleRegion(byte[] bundle, byte[] padding)
        {
            return EncodeLengthPrefixedRegion(bundle, padding, BundlePlaintextLength, MaximumBundleBodyBytes);
        }

        public static Tuple<byte[], byte[]> DecodeBundleRegion(byte[] data)
        {
            return DecodeLengthPrefixedRegion(data, BundlePlaintextLength, MaximumBundleBodyBytes);
        }

        public static byte[] HeaderDigest(byte[] headerBytes)
        {
            CheckBytes(headerBytes, CapsuleHeaderLength, RefusalCode.Length);
            return Sha256(headerBytes);
        }

        public static byte[] ManifestCiphertextDigest(byte[] region)
        {
            CheckBytes(region, ManifestRegionLength, RefusalCode.Length);
            return Sha256(region);
        }

        public static byte[] MakeNonce(byte[] prefix, uint index)
        {
            CheckBytes(prefix, 4, RefusalCode.Structure);
            ChunkKind(index);
            byte[] output = new byte[12];
            Put(output, 0, prefix);
            Put(output, 4, UInt64(index));
            return output;
        }

        private static byte[] MakeAadFromManifestDigest(byte[] headerSha256, uint index, byte kind, byte[] manifestSha256)
        {
            CheckBytes(headerSha256, 32, RefusalCode.Structure);
            byte expectedKind = ChunkKind(index);
            Require(kind == expectedKind, RefusalCode.ChunkIndex);
            using (MemoryStream stream = new MemoryStream())
            {
                stream.Write(AadDomain, 0, AadDomain.Length);
                stream.WriteByte(0);
                stream.Write(headerSha256, 0, headerSha256.Length);
                byte[] number = UInt64(index);
                stream.Write(number, 0, number.Length);
                stream.WriteByte(kind);
                number = UInt32(ChunkCount);
                stream.Write(number, 0, number.Length);
                if (kind == 1)
                {
                    CheckBytes(manifestSha256, 32, RefusalCode.Length);
                    stream.Write(manifestSha256, 0, manifestSha256.Length);
                }
                return stream.ToArray();
            }
        }

        public static byte[] MakeAad(byte[] headerSha256, uint index, byte kind, byte[] manifestCiphertextRegion)
        {
            byte expectedKind = ChunkKind(index);
            Require(kind == expectedKind, RefusalCode.ChunkIndex);
            byte[] manifestSha = null;
            if (kind == 1)
            {
                CheckBytes(manifestCiphertextRegion, ManifestRegionLength, RefusalCode.Length);
                manifestSha = ManifestCiphertextDigest(manifestCiphertextRegion);
            }
            else Require(manifestCiphertextRegion == null, RefusalCode.Structure);
            return MakeAadFromManifestDigest(headerSha256, index, kind, manifestSha);
        }

        public static byte[] HkdfSha256(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength)
        {
            Require(inputKeyMaterial != null && salt != null && info != null, RefusalCode.Structure);
            Require(outputLength >= 0 && outputLength <= 255 * 32, RefusalCode.Structure);
            byte[] prk;
            using (HMACSHA256 extract = new HMACSHA256(salt)) prk = extract.ComputeHash(inputKeyMaterial);
            List<byte> output = new List<byte>();
            byte[] previous = new byte[0];
            try
            {
                for (int counter = 1; output.Count < outputLength; counter++)
                {
                    byte[] blockInput = new byte[previous.Length + info.Length + 1];
                    Buffer.BlockCopy(previous, 0, blockInput, 0, previous.Length);
                    Buffer.BlockCopy(info, 0, blockInput, previous.Length, info.Length);
                    blockInput[blockInput.Length - 1] = (byte)counter;
                    using (HMACSHA256 expand = new HMACSHA256(prk)) previous = expand.ComputeHash(blockInput);
                    output.AddRange(previous);
                    Array.Clear(blockInput, 0, blockInput.Length);
                }
                return output.Take(outputLength).ToArray();
            }
            finally
            {
                Array.Clear(prk, 0, prk.Length);
                Array.Clear(previous, 0, previous.Length);
            }
        }

        public static byte[] DeriveAesKey(byte[] sharedX, byte[] salt, byte[] headerSha256)
        {
            CheckBytes(sharedX, 32, RefusalCode.Structure);
            CheckBytes(salt, 32, RefusalCode.Structure);
            CheckBytes(headerSha256, 32, RefusalCode.Structure);
            byte[] info = new byte[HkdfDomain.Length + 1 + headerSha256.Length];
            Put(info, 0, HkdfDomain);
            Put(info, HkdfDomain.Length + 1, headerSha256);
            return HkdfSha256(sharedX, salt, info, 32);
        }

        public static byte[] DeriveCapsuleAesKey(byte[] sharedX, byte[] headerBytes)
        {
            CapsuleHeader header = DecodeCapsuleHeader(headerBytes);
            return DeriveAesKey(sharedX, header.HkdfSalt, HeaderDigest(headerBytes));
        }

        internal static Tuple<byte[], byte[]> SealAesGcm(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
        {
            CheckBytes(key, 32, RefusalCode.Crypto);
            CheckBytes(nonce, 12, RefusalCode.Crypto);
            CheckBytes(plaintext, ChunkPlaintextBytes, RefusalCode.Length);
            Require(aad != null, RefusalCode.Crypto);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[ChunkTagBytes];
            try
            {
                using (AesGcm aes = new AesGcm(key, ChunkTagBytes)) aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            }
            catch { Refuse(RefusalCode.Crypto); }
            return Tuple.Create(ciphertext, tag);
        }

        internal static byte[] OpenAesGcm(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] aad)
        {
            CheckBytes(key, 32, RefusalCode.Crypto);
            CheckBytes(nonce, 12, RefusalCode.Crypto);
            CheckBytes(ciphertext, ChunkPlaintextBytes, RefusalCode.Length);
            CheckBytes(tag, ChunkTagBytes, RefusalCode.Length);
            Require(aad != null, RefusalCode.Crypto);
            byte[] plaintext = new byte[ciphertext.Length];
            try
            {
                using (AesGcm aes = new AesGcm(key, ChunkTagBytes)) aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            }
            catch { Refuse(RefusalCode.Crypto); }
            return plaintext;
        }

        public static void ValidateChunkRecord(ChunkRecord chunk)
        {
            Require(chunk != null, RefusalCode.Structure);
            Require(chunk.Kind == ChunkKind(chunk.Index), RefusalCode.ChunkIndex);
            CheckBytes(chunk.Ciphertext, ChunkPlaintextBytes, RefusalCode.Length);
            CheckBytes(chunk.Tag, ChunkTagBytes, RefusalCode.Length);
        }

        public static byte[] EncodeCapsule(Capsule capsule, byte[] keyRecordBytes)
        {
            Require(capsule != null, RefusalCode.Structure);
            ValidateHeaderKeyBinding(capsule.Header, keyRecordBytes);
            Require(capsule.ManifestChunks != null && capsule.ManifestChunks.Count == ManifestChunkCount, RefusalCode.ChunkIndex);
            Require(capsule.BundleChunks != null && capsule.BundleChunks.Count == BundleChunkCount, RefusalCode.ChunkIndex);
            CheckBytes(capsule.Trailer, TrailerLength, RefusalCode.Length);
            byte[] output = new byte[CapsuleLength];
            byte[] header = EncodeCapsuleHeader(capsule.Header);
            Put(output, 0, header);
            int outputOffset = CapsuleHeaderLength;
            for (int i = 0; i < ManifestChunkCount; i++)
            {
                ChunkRecord chunk = capsule.ManifestChunks[i];
                ValidateChunkRecord(chunk);
                Require(chunk.Index == (uint)i, RefusalCode.ChunkIndex);
                Put(output, outputOffset, chunk.Ciphertext);
                outputOffset += ChunkPlaintextBytes;
                Put(output, outputOffset, chunk.Tag);
                outputOffset += ChunkTagBytes;
            }
            for (int i = 0; i < BundleChunkCount; i++)
            {
                ChunkRecord chunk = capsule.BundleChunks[i];
                ValidateChunkRecord(chunk);
                Require(chunk.Index == (uint)(ManifestChunkCount + i), RefusalCode.ChunkIndex);
                Put(output, outputOffset, chunk.Ciphertext);
                outputOffset += ChunkPlaintextBytes;
                Put(output, outputOffset, chunk.Tag);
                outputOffset += ChunkTagBytes;
            }
            Put(output, TrailerStart, capsule.Trailer);
            Require(outputOffset == TrailerStart, RefusalCode.Length);
            return output;
        }

        public static CapsuleView DecodeCapsule(byte[] data, byte[] keyRecordBytes)
        {
            try
            {
                Require(data != null, RefusalCode.Structure);
                if (data.Length > CapsuleLength) Refuse(RefusalCode.Trailing);
                Require(data.Length == CapsuleLength, RefusalCode.Length);
                byte[] headerBytes = Slice(data, 0, CapsuleHeaderLength);
                CapsuleHeader header = DecodeCapsuleHeader(headerBytes);
                ValidateHeaderKeyBinding(header, keyRecordBytes);
                return new CapsuleView(data, header);
            }
            catch (CapsuleRefusal) { throw; }
            catch { Refuse(RefusalCode.Structure); throw; }
        }

        internal static byte[] ReceiverJobDigest { get { return (byte[])ReceiverJobSha256.Clone(); } }
    }

    public static class VectorGenerator
    {
        private static byte[] Repeat(byte value, int count)
        {
            byte[] output = new byte[count];
            for (int i = 0; i < count; i++) output[i] = value;
            return output;
        }

        private static byte[] Sequence(int count, byte start)
        {
            byte[] output = new byte[count];
            for (int i = 0; i < count; i++) output[i] = unchecked((byte)(start + i));
            return output;
        }

        private static string JsonString(string value)
        {
            StringBuilder output = new StringBuilder("\"");
            foreach (char item in value)
            {
                if (item == '"') output.Append("\\\"");
                else if (item == '\\') output.Append("\\\\");
                else if (item < 32) output.Append("\\u").Append(((int)item).ToString("x4", CultureInfo.InvariantCulture));
                else output.Append(item);
            }
            output.Append('"');
            return output.ToString();
        }

        private static string PairJson(byte[] ciphertext, byte[] tag)
        {
            return "{\"ciphertext_sha256\":" + JsonString(CapsuleCodec.ToHex(CapsuleCodec.Sha256(ciphertext))) +
                ",\"tag\":" + JsonString(CapsuleCodec.ToHex(tag)) + "}";
        }

        private static void WriteDigest(IncrementalHash hash, byte[] value)
        {
            hash.AppendData(value);
        }

        public static string GenerateJson()
        {
            VerifyPrimitiveFixtures();
            byte[] basePoint = HexBasePoint();
            KeyRecord record = new KeyRecord
            {
                ControlRepositoryId = 1,
                ControlSha = Sequence(20, 0),
                RunId = 2,
                Attempt = 3,
                TransferId = Sequence(16, 0),
                ReceiverPublicPoint = basePoint,
                WorkflowRefSha256 = Repeat(0x66, 32),
                CreatedAt = 4,
                ExpiresAt = 5
            };
            byte[] recordBytes = CapsuleCodec.EncodeKeyRecord(record);
            if (!CapsuleCodec.EncodeKeyRecord(CapsuleCodec.DecodeKeyRecord(recordBytes)).SequenceEqual(recordBytes))
                throw new CapsuleRefusal(RefusalCode.Structure);
            CapsuleHeader header = new CapsuleHeader
            {
                ControlRepositoryId = record.ControlRepositoryId,
                ControlSha = (byte[])record.ControlSha.Clone(),
                RunId = record.RunId,
                Attempt = record.Attempt,
                TransferId = (byte[])record.TransferId.Clone(),
                ReceiverKeyId = record.KeyId,
                KeyRecordSha256 = CapsuleCodec.Sha256(recordBytes),
                SenderPublicPoint = basePoint,
                HkdfSalt = Sequence(32, 0),
                NoncePrefix = new byte[] { 0xa1, 0xb2, 0xc3, 0xd4 },
                CreatedAt = record.CreatedAt,
                ExpiresAt = record.ExpiresAt,
                WorkflowRefSha256 = (byte[])record.WorkflowRefSha256.Clone(),
                IntendedJobSha256 = CapsuleCodec.ReceiverJobDigest
            };
            byte[] headerBytes = CapsuleCodec.EncodeCapsuleHeader(header);
            if (!CapsuleCodec.EncodeCapsuleHeader(CapsuleCodec.DecodeCapsuleHeader(headerBytes)).SequenceEqual(headerBytes))
                throw new CapsuleRefusal(RefusalCode.Structure);
            byte[] headerSha = CapsuleCodec.HeaderDigest(headerBytes);
            byte[] sharedX = Repeat(1, 32);
            byte[] aesKey = CapsuleCodec.DeriveCapsuleAesKey(sharedX, headerBytes);
            Manifest manifest = new Manifest
            {
                SourceRepositoryId = 1,
                SourceSha = Sequence(20, 0),
                TreeId = Repeat(0x11, 20),
                BundleSha256 = Repeat(0x22, 32),
                BundleLength = 0,
                Entries = new List<ManifestEntry>
                {
                    new ManifestEntry
                    {
                        Path = "src/vector.txt",
                        Mode = 33188,
                        BlobId = Repeat(0x33, 20),
                        Size = 4,
                        Sha256 = Repeat(0x44, 32)
                    }
                }
            };
            VerifyPathRefusals(manifest);
            byte[] manifestCbor = CapsuleCodec.EncodeManifest(manifest);
            if (!CapsuleCodec.EncodeManifest(CapsuleCodec.DecodeManifest(manifestCbor)).SequenceEqual(manifestCbor))
                throw new CapsuleRefusal(RefusalCode.Structure);
            byte[] manifestPadding = new byte[CapsuleCodec.ManifestPlaintextLength - 8 - manifestCbor.Length];
            byte[] manifestPlaintext = CapsuleCodec.EncodeLengthPrefixedRegion(
                manifestCbor, manifestPadding, CapsuleCodec.ManifestPlaintextLength, CapsuleCodec.MaximumManifestBodyBytes);
            Tuple<byte[], byte[]> manifestParts = CapsuleCodec.DecodeLengthPrefixedRegion(
                manifestPlaintext, CapsuleCodec.ManifestPlaintextLength, CapsuleCodec.MaximumManifestBodyBytes);
            if (!manifestParts.Item1.SequenceEqual(manifestCbor) || !manifestParts.Item2.SequenceEqual(manifestPadding))
                throw new CapsuleRefusal(RefusalCode.Structure);

            byte[] capsuleSha;
            byte[] manifestRegion = new byte[CapsuleCodec.ManifestRegionLength];
            Dictionary<uint, string> selected = new Dictionary<uint, string>();
            using (IncrementalHash capsuleHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                WriteDigest(capsuleHash, headerBytes);
                for (uint index = 0; index < CapsuleCodec.ManifestChunkCount; index++)
                {
                    byte[] plain = new byte[CapsuleCodec.ChunkPlaintextBytes];
                    Buffer.BlockCopy(manifestPlaintext, checked((int)index * CapsuleCodec.ChunkPlaintextBytes), plain, 0, plain.Length);
                    byte[] nonce = CapsuleCodec.MakeNonce(header.NoncePrefix, index);
                    byte[] aad = CapsuleCodec.MakeAad(headerSha, index, 0, null);
                    Tuple<byte[], byte[]> pair = CapsuleCodec.SealAesGcm(aesKey, nonce, plain, aad);
                    if (index == 0 || index == 15)
                    {
                        byte[] encodedChunk = CapsuleCodec.EncodeChunk(index, pair.Item1, pair.Item2, 0);
                        ChunkRecord decodedChunk = CapsuleCodec.DecodeChunk(encodedChunk, index, 0);
                        if (!CapsuleCodec.EncodeChunk(decodedChunk.Index, decodedChunk.Ciphertext, decodedChunk.Tag, decodedChunk.Kind).SequenceEqual(encodedChunk))
                            throw new CapsuleRefusal(RefusalCode.Structure);
                    }
                    int offset = checked((int)index * CapsuleCodec.ChunkRecordLength);
                    Buffer.BlockCopy(pair.Item1, 0, manifestRegion, offset, pair.Item1.Length);
                    Buffer.BlockCopy(pair.Item2, 0, manifestRegion, offset + pair.Item1.Length, pair.Item2.Length);
                    WriteDigest(capsuleHash, pair.Item1);
                    WriteDigest(capsuleHash, pair.Item2);
                    if (index == 0 || index == 15) selected[index] = PairJson(pair.Item1, pair.Item2);
                }
                byte[] manifestSha = CapsuleCodec.ManifestCiphertextDigest(manifestRegion);
                for (uint index = CapsuleCodec.ManifestChunkCount; index < CapsuleCodec.ChunkCount; index++)
                {
                    byte[] plain = new byte[CapsuleCodec.ChunkPlaintextBytes];
                    byte[] nonce = CapsuleCodec.MakeNonce(header.NoncePrefix, index);
                    byte[] aad = CapsuleCodec.MakeAad(headerSha, index, 1, manifestRegion);
                    Tuple<byte[], byte[]> pair = CapsuleCodec.SealAesGcm(aesKey, nonce, plain, aad);
                    if (index == 16 || index == 271)
                    {
                        byte[] encodedChunk = CapsuleCodec.EncodeChunk(index, pair.Item1, pair.Item2, 1);
                        ChunkRecord decodedChunk = CapsuleCodec.DecodeChunk(encodedChunk, index, 1);
                        if (!CapsuleCodec.EncodeChunk(decodedChunk.Index, decodedChunk.Ciphertext, decodedChunk.Tag, decodedChunk.Kind).SequenceEqual(encodedChunk))
                            throw new CapsuleRefusal(RefusalCode.Structure);
                    }
                    if (index == 16)
                    {
                        byte[] corruptTag = (byte[])pair.Item2.Clone();
                        corruptTag[0] ^= 1;
                        RequireCryptoRefusal(aesKey, nonce, pair.Item1, corruptTag, aad);
                        RequireCryptoRefusal(aesKey, CapsuleCodec.MakeNonce(header.NoncePrefix, 0),
                            pair.Item1, pair.Item2, CapsuleCodec.MakeAad(headerSha, 0, 0, null));
                    }
                    WriteDigest(capsuleHash, pair.Item1);
                    WriteDigest(capsuleHash, pair.Item2);
                    if (index == 16 || index == 271) selected[index] = PairJson(pair.Item1, pair.Item2);
                }
                byte[] trailer = Repeat(0xab, CapsuleCodec.TrailerLength);
                if (!CapsuleCodec.DecodeTrailer(CapsuleCodec.EncodeTrailer(trailer)).SequenceEqual(trailer))
                    throw new CapsuleRefusal(RefusalCode.Structure);
                WriteDigest(capsuleHash, trailer);
                capsuleSha = capsuleHash.GetHashAndReset();
                string nonces = "{\"0\":" + JsonString(CapsuleCodec.ToHex(CapsuleCodec.MakeNonce(header.NoncePrefix, 0))) +
                    ",\"15\":" + JsonString(CapsuleCodec.ToHex(CapsuleCodec.MakeNonce(header.NoncePrefix, 15))) +
                    ",\"16\":" + JsonString(CapsuleCodec.ToHex(CapsuleCodec.MakeNonce(header.NoncePrefix, 16))) +
                    ",\"271\":" + JsonString(CapsuleCodec.ToHex(CapsuleCodec.MakeNonce(header.NoncePrefix, 271))) + "}";
                string aad0 = CapsuleCodec.ToHex(CapsuleCodec.MakeAad(headerSha, 0, 0, null));
                string aad15 = CapsuleCodec.ToHex(CapsuleCodec.MakeAad(headerSha, 15, 0, null));
                string aad16 = CapsuleCodec.ToHex(CapsuleCodec.MakeAad(headerSha, 16, 1, manifestRegion));
                string aad271 = CapsuleCodec.ToHex(CapsuleCodec.MakeAad(headerSha, 271, 1, manifestRegion));
                byte[] hkdfInfo = HkdfInfo(headerSha);
                byte[] prk;
                using (HMACSHA256 extract = new HMACSHA256(header.HkdfSalt)) prk = extract.ComputeHash(sharedX);
                StringBuilder output = new StringBuilder();
                output.Append("{\"format\":\"KDWH-v1-protocol-vectors\"");
                output.Append(",\"producer\":\"independent-csharp\"");
                output.Append(",\"status\":\"generated\"");
                output.Append(",\"key_record_hex\":").Append(JsonString(CapsuleCodec.ToHex(recordBytes)));
                output.Append(",\"header_hex\":").Append(JsonString(CapsuleCodec.ToHex(headerBytes)));
                output.Append(",\"header_sha256\":").Append(JsonString(CapsuleCodec.ToHex(headerSha)));
                output.Append(",\"shared_x\":").Append(JsonString(CapsuleCodec.ToHex(sharedX)));
                output.Append(",\"hkdf_salt\":").Append(JsonString(CapsuleCodec.ToHex(header.HkdfSalt)));
                output.Append(",\"hkdf_info\":").Append(JsonString(CapsuleCodec.ToHex(hkdfInfo)));
                output.Append(",\"hkdf_prk\":").Append(JsonString(CapsuleCodec.ToHex(prk)));
                output.Append(",\"aes_key\":").Append(JsonString(CapsuleCodec.ToHex(aesKey)));
                output.Append(",\"manifest_cbor_hex\":").Append(JsonString(CapsuleCodec.ToHex(manifestCbor)));
                output.Append(",\"manifest_ciphertext_sha256\":").Append(JsonString(CapsuleCodec.ToHex(manifestSha)));
                output.Append(",\"capsule_length\":").Append(CapsuleCodec.CapsuleLength.ToString(CultureInfo.InvariantCulture));
                output.Append(",\"capsule_sha256\":").Append(JsonString(CapsuleCodec.ToHex(capsuleSha)));
                output.Append(",\"nonces\":").Append(nonces);
                output.Append(",\"aad_manifest_0\":").Append(JsonString(aad0));
                output.Append(",\"aad_manifest_15\":").Append(JsonString(aad15));
                output.Append(",\"aad_bundle_16\":").Append(JsonString(aad16));
                output.Append(",\"aad_bundle_271\":").Append(JsonString(aad271));
                output.Append(",\"selected_chunks\":{\"0\":").Append(selected[0]);
                output.Append(",\"15\":").Append(selected[15]).Append(",\"16\":").Append(selected[16]);
                output.Append(",\"271\":").Append(selected[271]).Append("}}");
                Array.Clear(aesKey, 0, aesKey.Length);
                Array.Clear(sharedX, 0, sharedX.Length);
                return output.ToString();
            }
        }

        private static byte[] HexBasePoint()
        {
            return FromHex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        }

        private static void VerifyPrimitiveFixtures()
        {
            byte[] point = HexBasePoint();
            if (!CapsuleCodec.ValidatePublicPoint(point).SequenceEqual(point) ||
                !point.Skip(1).Take(32).SequenceEqual(FromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")))
                throw new CapsuleRefusal(RefusalCode.Point);
            byte[] privateOne = new byte[32];
            privateOne[31] = 1;
            ECParameters parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateOne,
                Q = new ECPoint
                {
                    X = point.Skip(1).Take(32).ToArray(),
                    Y = point.Skip(33).Take(32).ToArray()
                }
            };
            using (ECDiffieHellman local = ECDiffieHellman.Create(parameters))
            using (ECDiffieHellman peer = ECDiffieHellman.Create(parameters))
            {
                byte[] derivedHash = local.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256);
                if (!derivedHash.SequenceEqual(CapsuleCodec.Sha256(parameters.Q.X)))
                    throw new CapsuleRefusal(RefusalCode.Crypto);
            }
            byte[] ikm = Repeat(0x0b, 22);
            byte[] salt = FromHex("000102030405060708090a0b0c");
            byte[] info = FromHex("f0f1f2f3f4f5f6f7f8f9");
            byte[] expectedPrk = FromHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
            byte[] expectedOkm = FromHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
            using (HMACSHA256 extract = new HMACSHA256(salt))
            {
                if (!extract.ComputeHash(ikm).SequenceEqual(expectedPrk))
                    throw new CapsuleRefusal(RefusalCode.Crypto);
            }
            if (!CapsuleCodec.HkdfSha256(ikm, salt, info, 42).SequenceEqual(expectedOkm))
                throw new CapsuleRefusal(RefusalCode.Crypto);
            byte[] emptyCiphertext = new byte[0];
            byte[] emptyTag = new byte[16];
            using (AesGcm aes = new AesGcm(new byte[32], 16))
                aes.Encrypt(new byte[12], new byte[0], emptyCiphertext, emptyTag, new byte[0]);
            if (!emptyTag.SequenceEqual(FromHex("530f8afbc74536b9a963b4f1c4cb738b")))
                throw new CapsuleRefusal(RefusalCode.Crypto);
        }

        private static void RequireCryptoRefusal(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] aad)
        {
            try { CapsuleCodec.OpenAesGcm(key, nonce, ciphertext, tag, aad); }
            catch (CapsuleRefusal error)
            {
                if (error.Reason == RefusalCode.Crypto) return;
                throw;
            }
            throw new CapsuleRefusal(RefusalCode.Structure);
        }

        private static void VerifyPathRefusals(Manifest template)
        {
            foreach (string[] paths in new string[][]
            {
                new string[] { "A", "a" },
                new string[] { "A", "a/b" },
                new string[] { "\u00b5.txt" },
                new string[] { "\u03bc.txt" }
            })
            {
                Manifest mutated = new Manifest
                {
                    SourceRepositoryId = template.SourceRepositoryId,
                    SourceSha = template.SourceSha,
                    TreeId = template.TreeId,
                    BundleSha256 = template.BundleSha256,
                    BundleLength = template.BundleLength,
                    Entries = paths.Select(path => new ManifestEntry
                    {
                        Path = path,
                        Mode = 33188,
                        BlobId = Repeat(0x33, 20),
                        Size = 4,
                        Sha256 = Repeat(0x44, 32)
                    }).ToList()
                };
                try { CapsuleCodec.EncodeManifest(mutated); }
                catch (CapsuleRefusal error)
                {
                    if (error.Reason == RefusalCode.ManifestLimit) continue;
                    throw;
                }
                throw new CapsuleRefusal(RefusalCode.Structure);
            }
        }

        private static byte[] FromHex(string value)
        {
            byte[] output = new byte[value.Length / 2];
            for (int i = 0; i < output.Length; i++) output[i] = Byte.Parse(value.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return output;
        }

        private static byte[] HkdfInfo(byte[] headerSha)
        {
            byte[] domain = Encoding.ASCII.GetBytes("KDWH-v1/HKDF-AES256GCM");
            byte[] info = new byte[domain.Length + 1 + headerSha.Length];
            Buffer.BlockCopy(domain, 0, info, 0, domain.Length);
            Buffer.BlockCopy(headerSha, 0, info, domain.Length + 1, headerSha.Length);
            return info;
        }

    }
}
