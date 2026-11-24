// .NET Framework 4.x, built x64. Does not execute the candidate or contact a URL.
// Microsoft contracts:
// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data
// https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust
// https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

internal static partial class WindowsAuthenticode
{
    private const string Product = "Claude Browser";
    private const string EmbeddedInstallPins = ""; // BUILD_INSTALL_PINS
    private static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    private sealed class Rejected : Exception
    {
        internal readonly string Code;
        internal readonly string TrustStatus;
        internal Rejected(string code) : this(code, null) { }
        internal Rejected(string code, string status) : base(code) { Code = code; TrustStatus = status; }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WintrustFile
    {
        internal uint Size;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Path;
        internal IntPtr Handle;
        internal IntPtr KnownSubject;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SignatureSettings
    {
        internal uint Size, Index, Flags, SecondaryCount, VerifiedIndex;
        internal IntPtr CryptoPolicy;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WintrustData
    {
        internal uint Size;
        internal IntPtr PolicyCallback, SipClient;
        internal uint UIChoice, RevocationChecks, UnionChoice;
        internal IntPtr File;
        internal uint StateAction;
        internal IntPtr StateData, URLReference;
        internal uint ProviderFlags, UIContext;
        internal IntPtr SignatureSettings;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProviderSigner
    {
        internal uint Size;
        internal System.Runtime.InteropServices.ComTypes.FILETIME VerifyAsOf;
        internal uint CertificateCount;
        internal IntPtr Certificates;
        internal uint SignerType;
        internal IntPtr Signer;
        internal uint Error, CounterSignerCount;
        internal IntPtr CounterSigners, ChainContext;
    }
    // Only the documented prefix is required to obtain the verified leaf context.
    [StructLayout(LayoutKind.Sequential)]
    private struct ProviderCertificatePrefix
    {
        internal uint Size;
        internal IntPtr Certificate;
    }
    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(IntPtr window, [In] ref Guid action, ref WintrustData data);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr data, uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint counterSignerIndex);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint certificateIndex);

    private static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
    private static string Status(int result) { return "0x" + unchecked((uint)result).ToString("X8"); }
    private static void Require(bool condition, string code) { if (!condition) throw new Rejected(code); }
    private static bool IsPin(string pin) { return pin != null && Regex.IsMatch(pin, @"\A[0-9a-fA-F]{64}\z"); }

    private static string VerifyArchitecture(FileStream stream)
    {
        Require(stream.Length >= 64, "INVALID_PE");
        var reader = new BinaryReader(stream);
        Require(reader.ReadUInt16() == 0x5a4d, "INVALID_PE");
        stream.Position = 60;
        long header = reader.ReadUInt32();
        Require(header >= 64 && header <= stream.Length - 26, "INVALID_PE");
        stream.Position = header;
        Require(reader.ReadUInt32() == 0x00004550, "INVALID_PE");
        ushort machine = reader.ReadUInt16();
        Require(machine == 0x8664 || machine == 0x014c, "WRONG_ARCHITECTURE");
        stream.Position = header + 22;
        ushort flags = reader.ReadUInt16();
        Require((flags & 0x0002) != 0 && (flags & 0x2000) == 0, "INVALID_EXECUTABLE");
        Require(reader.ReadUInt16() == (machine == 0x8664 ? 0x020b : 0x010b), "WRONG_ARCHITECTURE");
        return machine == 0x8664 ? "amd64" : "i386";
    }

    private sealed class VersionNode
    {
        internal string Key, Value;
        internal int End;
        internal readonly List<VersionNode> Children = new List<VersionNode>();
    }
    private static int Align4(int value) { return (value + 3) & ~3; }
    private static VersionNode ReadVersionNode(byte[] bytes, int start, int limit, int depth)
    {
        Require(depth <= 4 && start >= 0 && start <= limit - 6, "INVALID_VERSION_RESOURCE");
        int length = BitConverter.ToUInt16(bytes, start);
        int valueLength = BitConverter.ToUInt16(bytes, start + 2);
        int type = BitConverter.ToUInt16(bytes, start + 4);
        Require(length >= 6 && length <= limit - start && type <= 1, "INVALID_VERSION_RESOURCE");
        int end = start + length, cursor = start + 6, keyStart = cursor;
        while (cursor <= end - 2 && BitConverter.ToUInt16(bytes, cursor) != 0) cursor += 2;
        Require(cursor <= end - 2 && cursor - keyStart <= 512, "INVALID_VERSION_RESOURCE");
        string key = Encoding.Unicode.GetString(bytes, keyStart, cursor - keyStart);
        cursor = Align4(cursor + 2);
        int valueBytes = type == 1 ? valueLength * 2 : valueLength;
        Require(cursor <= end && valueBytes <= end - cursor, "INVALID_VERSION_RESOURCE");
        var node = new VersionNode { Key = key, End = end };
        if (type == 1 && valueBytes > 0)
        {
            Require(BitConverter.ToUInt16(bytes, cursor + valueBytes - 2) == 0, "INVALID_VERSION_RESOURCE");
            node.Value = Encoding.Unicode.GetString(bytes, cursor, valueBytes - 2);
        }
        cursor = Align4(cursor + valueBytes);
        while (cursor < end)
        {
            Require(node.Children.Count < 256, "INVALID_VERSION_RESOURCE");
            if (end - cursor < 2 || BitConverter.ToUInt16(bytes, cursor) == 0)
            {
                for (int i = cursor; i < end; i++) Require(bytes[i] == 0, "INVALID_VERSION_RESOURCE");
                break;
            }
            var child = ReadVersionNode(bytes, cursor, end, depth + 1);
            node.Children.Add(child);
            cursor = Align4(child.End);
        }
        return node;
    }
    private static void VerifyVersionBytes(byte[] bytes, string version, string edition, bool installedApplication)
    {
        var root = ReadVersionNode(bytes, 0, bytes.Length, 0);
        Require(root.Key == "VS_VERSION_INFO", "INVALID_VERSION_RESOURCE");
        string packagedVersion = installedApplication && Regex.IsMatch(version, @"\A\d+\.\d+\.\d+\z")
            ? version + ".0" : null;
        int tables = 0;
        foreach (var group in root.Children)
        {
            if (group.Key != "StringFileInfo") continue;
            foreach (var table in group.Children)
            {
                bool hasProduct = false, hasVersion = false;
                string declaredEdition = null;
                foreach (var item in table.Children)
                {
                    if (item.Key == "ProductName") { Require(item.Value == Product, "PRODUCT_MISMATCH"); hasProduct = true; }
                    if (item.Key == "ProductVersion")
                    {
                        // Electron Builder stores a stable Windows app version with a zero PE revision.
                        Require(item.Value == version || (packagedVersion != null && item.Value == packagedVersion),
                            "VERSION_MISMATCH");
                        hasVersion = true;
                    }
                    if (item.Key == "ClaudeUpdateEdition") { Require(declaredEdition == null, "EDITION_MISMATCH"); declaredEdition = item.Value; }
                }
                Require(hasProduct && hasVersion, "INVALID_VERSION_RESOURCE");
                if (edition != null) Require((declaredEdition ?? "") == edition, "EDITION_MISMATCH");
                tables++;
            }
        }
        Require(tables > 0, "INVALID_VERSION_RESOURCE");
    }
    private static byte[] ReadAt(FileStream stream, long offset, int count)
    {
        Require(offset >= 0 && count >= 0 && offset <= stream.Length - count, "INVALID_VERSION_RESOURCE");
        stream.Position = offset;
        byte[] bytes = new BinaryReader(stream).ReadBytes(count);
        Require(bytes.Length == count, "INVALID_VERSION_RESOURCE");
        return bytes;
    }
    private static long RvaOffset(FileStream stream, long sections, int count, uint rva, uint size)
    {
        Require(count > 0 && count <= 96, "INVALID_VERSION_RESOURCE");
        for (int i = 0; i < count; i++)
        {
            byte[] section = ReadAt(stream, sections + i * 40L, 40);
            uint address = BitConverter.ToUInt32(section, 12), rawSize = BitConverter.ToUInt32(section, 16);
            if (rva < address || (ulong)rva - address >= rawSize) continue;
            ulong delta = (ulong)rva - address;
            Require(delta + size <= rawSize, "INVALID_VERSION_RESOURCE");
            long offset = BitConverter.ToUInt32(section, 20) + (long)delta;
            Require(offset <= stream.Length - size, "INVALID_VERSION_RESOURCE");
            return offset;
        }
        throw new Rejected("INVALID_VERSION_RESOURCE");
    }
    private static List<uint> ResourceEntries(FileStream stream, long resourceBase, uint resourceSize, uint directory, int id)
    {
        Require(directory <= resourceSize && resourceSize - directory >= 16, "INVALID_VERSION_RESOURCE");
        byte[] header = ReadAt(stream, resourceBase + directory, 16);
        int named = BitConverter.ToUInt16(header, 12), count = named + BitConverter.ToUInt16(header, 14);
        Require(count <= 256 && (ulong)directory + 16 + (ulong)count * 8 <= resourceSize, "INVALID_VERSION_RESOURCE");
        var entries = new List<uint>();
        for (int i = named; i < count; i++)
        {
            byte[] entry = ReadAt(stream, resourceBase + directory + 16 + i * 8L, 8);
            if (id == -1 || BitConverter.ToUInt32(entry, 0) == (uint)id) entries.Add(BitConverter.ToUInt32(entry, 4));
        }
        return entries;
    }
    private static void VerifyVersion(FileStream stream, string version, string edition = null, bool installedApplication = false)
    {
        // Parse the authenticated PE itself: GetFileVersionInfo/FileVersionInfo can
        // merge strings from an external .mui file, outside this asset's signature.
        byte[] dos = ReadAt(stream, 0, 64);
        uint pe = BitConverter.ToUInt32(dos, 60);
        byte[] coff = ReadAt(stream, pe + 4, 20);
        int count = BitConverter.ToUInt16(coff, 2), optionalSize = BitConverter.ToUInt16(coff, 16);
        int directoryOffset = BitConverter.ToUInt16(coff, 0) == 0x8664 ? 112 : 96;
        Require(optionalSize >= directoryOffset + 24, "INVALID_VERSION_RESOURCE");
        byte[] optional = ReadAt(stream, pe + 24, optionalSize);
        Require(BitConverter.ToUInt32(optional, directoryOffset - 4) > 2, "INVALID_VERSION_RESOURCE");
        uint resourceRva = BitConverter.ToUInt32(optional, directoryOffset + 16);
        uint resourceSize = BitConverter.ToUInt32(optional, directoryOffset + 20);
        Require(resourceRva != 0 && resourceSize >= 16, "INVALID_VERSION_RESOURCE");
        long sections = (long)pe + 24 + optionalSize;
        long resourceBase = RvaOffset(stream, sections, count, resourceRva, resourceSize);
        var roots = ResourceEntries(stream, resourceBase, resourceSize, 0, 16); // RT_VERSION
        Require(roots.Count == 1 && (roots[0] & 0x80000000) != 0, "INVALID_VERSION_RESOURCE");
        int resources = 0;
        foreach (uint name in ResourceEntries(stream, resourceBase, resourceSize, roots[0] & 0x7fffffff, -1))
        {
            Require((name & 0x80000000) != 0, "INVALID_VERSION_RESOURCE");
            foreach (uint language in ResourceEntries(stream, resourceBase, resourceSize, name & 0x7fffffff, -1))
            {
                Require(++resources <= 64 && (language & 0x80000000) == 0 && language <= resourceSize
                    && resourceSize - language >= 16, "INVALID_VERSION_RESOURCE");
                byte[] entry = ReadAt(stream, resourceBase + language, 16);
                uint dataRva = BitConverter.ToUInt32(entry, 0), size = BitConverter.ToUInt32(entry, 4);
                Require(size >= 6 && size <= 1048576, "INVALID_VERSION_RESOURCE");
                VerifyVersionBytes(ReadAt(stream, RvaOffset(stream, sections, count, dataRva, size), (int)size), version, edition, installedApplication);
            }
        }
        Require(resources > 0, "INVALID_VERSION_RESOURCE");
    }

    private static string VerifySignature(string path, FileStream stream, HashSet<string> pins)
    {
        var file = new WintrustFile { Size = (uint)Marshal.SizeOf(typeof(WintrustFile)),
            Path = path, Handle = stream.SafeFileHandle.DangerousGetHandle() };
        // Verify exactly the primary signature; never inspect an unrelated embedded
        // certificate or a timestamp countersigner to satisfy the publisher pin.
        var settings = new SignatureSettings { Size = (uint)Marshal.SizeOf(typeof(SignatureSettings)), Flags = 1, Index = 0 };
        IntPtr fileMemory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WintrustFile)));
        IntPtr settingsMemory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SignatureSettings)));
        Marshal.StructureToPtr(file, fileMemory, false);
        Marshal.StructureToPtr(settings, settingsMemory, false);
        var data = new WintrustData { Size = (uint)Marshal.SizeOf(typeof(WintrustData)), UIChoice = 2,
            RevocationChecks = 1, UnionChoice = 1, File = fileMemory, StateAction = 1,
            // CHAIN_EXCLUDE_ROOT | CACHE_ONLY_URL_RETRIEVAL | DISABLE_MD2_MD4.
            // No online fallback, no REVOCATION_CHECK_NONE / HASH_ONLY policy.
            ProviderFlags = 0x00000080 | 0x00001000 | 0x00002000, SignatureSettings = settingsMemory };
        Guid action = GenericVerifyV2;
        try
        {
            int result = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            if (result != 0)
            {
                uint value = unchecked((uint)result);
                if (value == 0x80092013 || value == 0x80092012 || value == 0x800B010E)
                    throw new Rejected("REVOCATION_CACHE_UNAVAILABLE", Status(result));
                if (value == 0x800B0100) throw new Rejected("UNSIGNED_ARTIFACT", Status(result));
                throw new Rejected("AUTHENTICODE_UNTRUSTED", Status(result));
            }
            var verified = (SignatureSettings)Marshal.PtrToStructure(settingsMemory, typeof(SignatureSettings));
            Require(verified.VerifiedIndex == 0, "UNEXPECTED_VERIFIED_SIGNATURE");
            IntPtr provider = WTHelperProvDataFromStateData(data.StateData);
            Require(provider != IntPtr.Zero, "VERIFIED_SIGNER_UNAVAILABLE");
            IntPtr signerPointer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
            Require(signerPointer != IntPtr.Zero, "VERIFIED_SIGNER_UNAVAILABLE");
            var signer = (ProviderSigner)Marshal.PtrToStructure(signerPointer, typeof(ProviderSigner));
            Require(signer.Error == 0 && signer.CertificateCount > 0 && (signer.SignerType & 0x10) == 0,
                "VERIFIED_SIGNER_UNAVAILABLE");
            IntPtr certificatePointer = WTHelperGetProvCertFromChain(signerPointer, 0);
            Require(certificatePointer != IntPtr.Zero, "VERIFIED_SIGNER_UNAVAILABLE");
            var certificate = (ProviderCertificatePrefix)Marshal.PtrToStructure(certificatePointer, typeof(ProviderCertificatePrefix));
            Require(certificate.Certificate != IntPtr.Zero, "VERIFIED_SIGNER_UNAVAILABLE");
            using (var leaf = new X509Certificate2(certificate.Certificate))
            using (var hash = SHA256.Create())
            {
                string pin = Hex(hash.ComputeHash(leaf.RawData));
                Require(pins.Contains(pin), "SIGNER_PIN_MISMATCH");
                return pin;
            }
        }
        finally
        {
            // Provider-owned signer/certificate pointers are valid only until CLOSE.
            if (data.StateData != IntPtr.Zero) { data.StateAction = 2; WinVerifyTrust(new IntPtr(-1), ref action, ref data); }
            Marshal.DestroyStructure(fileMemory, typeof(WintrustFile));
            Marshal.FreeHGlobal(fileMemory);
            Marshal.FreeHGlobal(settingsMemory);
        }
    }

    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--install") return RunInstall(args);
        if (args.Length > 0 && args[0] == "--install-setup") return RunSetupInstall(args);
        var json = new JavaScriptSerializer();
        try
        {
            Require(Environment.Is64BitProcess && (args.Length == 3 || args.Length == 4), "INVALID_ARGUMENTS");
            string edition = args.Length == 4 ? args[3] : null;
            Require(edition == null || edition == "portable" || edition == "setup" || edition == "application", "INVALID_ARGUMENTS");
            string path = Path.GetFullPath(args[0]);
            string version = args[1];
            Require(Path.IsPathRooted(args[0]) && version.Length <= 128 && Regex.IsMatch(version,
                @"\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z"), "INVALID_ARGUMENTS");
            string[] suppliedPins = args[2].Split(',');
            Require(suppliedPins.Length > 0 && suppliedPins.Length <= 16, "INVALID_ARGUMENTS");
            var pins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string pin in suppliedPins) { Require(IsPin(pin), "INVALID_ARGUMENTS"); pins.Add(pin); }
            // Hold one read-only handle throughout policy, resource and hash reads.
            // FileShare.Read rejects simultaneous writers, replacement and deletion.
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                // NSIS may use an i386 portable launcher for an AMD64 payload.
                // This reads only the outer PE. The signed manifest binds the x64
                // target to this digest; release tooling must inspect its payload.
                string outerMachine = VerifyArchitecture(stream);
                bool installedApplication = edition == "application";
                if (installedApplication) Require(outerMachine == "amd64", "WRONG_ARCHITECTURE");
                VerifyVersion(stream, version, installedApplication ? null : edition == "portable" ? "" : edition,
                    installedApplication);
                string signer = VerifySignature(path, stream, pins);
                stream.Position = 0;
                string digest;
                using (var hash = SHA256.Create()) digest = Hex(hash.ComputeHash(stream));
                Console.WriteLine(json.Serialize(new { schema = 1, ok = true, offline = true,
                    platform = "win32", outerMachine = outerMachine, architectureScope = "outer-pe-only",
                    product = Product, version = version,
                    signerSha256 = signer, sha256 = digest, trustStatus = "0x00000000" }));
            }
            return 0;
        }
        catch (Rejected failure)
        {
            Console.WriteLine(json.Serialize(new { schema = 1, ok = false, code = failure.Code, trustStatus = failure.TrustStatus }));
            return 1;
        }
        catch (Exception)
        {
            // Missing native API / Framework / file permission must never bypass trust.
            Console.WriteLine(json.Serialize(new { schema = 1, ok = false, code = "VERIFIER_UNAVAILABLE" }));
            return 1;
        }
    }
}
