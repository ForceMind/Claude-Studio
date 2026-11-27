using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

// Minimal FlatBuffer writer strictly for ProcessSecurityEnvironment.fbs v1.0:
//   version = {1, 0}, capabilities = "networkLoopback",
//   fs_read_write = [scratchDir], fs_read_only = [sealedDir],
//   network_policy = { egress = { default_action = deny }, allowed_appcontainer_peer = "MXC-Loopback" }.
public static class PsecFlatBufferBuilder {
    sealed class Builder {
        byte[] buf = new byte[4096];
        int head = 4096;

        void Ensure(int needed) {
            if (head >= needed) return;
            int newSize = buf.Length * 2;
            while (newSize - (buf.Length - head) < needed) newSize *= 2;
            var next = new byte[newSize];
            int used = buf.Length - head;
            Buffer.BlockCopy(buf, head, next, newSize - used, used);
            head = newSize - used;
            buf = next;
        }

        public int Offset { get { return buf.Length - head; } }

        public void Pad(int align) {
            int mod = Offset % align;
            if (mod != 0) {
                int pad = align - mod;
                Ensure(pad);
                head -= pad;
                Array.Clear(buf, head, pad);
            }
        }

        public void PutByte(byte v) { Ensure(1); buf[--head] = v; }
        public void PutUInt16(ushort v) {
            Pad(2); Ensure(2);
            head -= 2;
            buf[head] = (byte)(v & 0xFF);
            buf[head + 1] = (byte)((v >> 8) & 0xFF);
        }
        public void PutUInt32(uint v) {
            Pad(4); Ensure(4);
            head -= 4;
            buf[head] = (byte)(v & 0xFF);
            buf[head + 1] = (byte)((v >> 8) & 0xFF);
            buf[head + 2] = (byte)((v >> 16) & 0xFF);
            buf[head + 3] = (byte)((v >> 24) & 0xFF);
        }
        public void PutInt32(int v) { PutUInt32(unchecked((uint)v)); }

        public void PutOffset(int targetOffset) {
            Pad(4);
            int rel = (Offset + 4) - targetOffset;
            PutUInt32(unchecked((uint)rel));
        }

        public int CreateString(string text) {
            var utf8 = Encoding.UTF8.GetBytes(text);
            int total = utf8.Length + 1;
            int pad = (4 - ((Offset + total) % 4)) % 4;
            if (pad > 0) {
                Ensure(pad);
                head -= pad;
                Array.Clear(buf, head, pad);
            }
            PutByte(0);
            Ensure(utf8.Length);
            head -= utf8.Length;
            Buffer.BlockCopy(utf8, 0, buf, head, utf8.Length);
            PutUInt32((uint)utf8.Length);
            return Offset;
        }

        public int CreateStringVector(string[] items) {
            var offsets = new int[items.Length];
            for (int i = 0; i < items.Length; i++) offsets[i] = CreateString(items[i]);
            Pad(4);
            for (int i = items.Length - 1; i >= 0; i--) PutOffset(offsets[i]);
            PutUInt32((uint)items.Length);
            return Offset;
        }

        public int BuildTable(int numSlots, Action<int[]> writeFields) {
            Pad(4);
            int tableEnd = Offset;
            var fieldPos = new int[numSlots];
            writeFields(fieldPos);
            Pad(4);
            int tableStart = Offset + 4;
            int tableSize = tableStart - tableEnd;
            // Reserve 4 bytes for soffset_t to vtable
            Ensure(4);
            head -= 4;
            int soffsetPos = head;

            // Write vtable immediately before tableStart (at lower address)
            Pad(2);
            for (int i = numSlots - 1; i >= 0; i--) {
                ushort rel = fieldPos[i] == 0 ? (ushort)0 : (ushort)(tableStart - fieldPos[i]);
                PutUInt16(rel);
            }
            PutUInt16((ushort)tableSize);
            PutUInt16((ushort)(4 + 2 * numSlots));
            int vtablePos = Offset;

            // Patch soffset_t = vtablePos - tableStart (positive since vtable is at lower address -> larger Offset)
            int soffset = vtablePos - tableStart;
            buf[soffsetPos] = (byte)(soffset & 0xFF);
            buf[soffsetPos + 1] = (byte)((soffset >> 8) & 0xFF);
            buf[soffsetPos + 2] = (byte)((soffset >> 16) & 0xFF);
            buf[soffsetPos + 3] = (byte)((soffset >> 24) & 0xFF);
            return tableStart;
        }

        public byte[] FinishWithIdentifier(int rootTableOffset, string ident4) {
            if (ident4.Length != 4) throw new ArgumentException("Expected 4-byte file identifier");
            Pad(4);
            Ensure(8);
            head -= 4;
            for (int i = 0; i < 4; i++) buf[head + i] = (byte)ident4[i];
            PutOffset(rootTableOffset);
            var outBytes = new byte[buf.Length - head];
            Buffer.BlockCopy(buf, head, outBytes, 0, outBytes.Length);
            return outBytes;
        }
    }

    public static byte[] BuildLoopbackOnlyPsecV1(string scratchDir, string sealedDir, bool disallowWin32k) {
        return BuildLoopbackOnlyPsecV1Multi(new[] { scratchDir }, new[] { sealedDir }, disallowWin32k);
    }

    public static byte[] BuildLoopbackOnlyPsecV1Multi(string[] rwDirs, string[] roDirs, bool disallowWin32k) {
        return BuildLoopbackOnlyPsecV1Full(rwDirs, roDirs, null, disallowWin32k);
    }

    public static byte[] BuildLoopbackOnlyPsecV1Full(string[] rwDirs, string[] roDirs, string[] enumDirs, bool disallowWin32k) {
        var b = new Builder();

        // 1. EndpointPolicy { default_action = deny (0), allow = null, deny = null }
        int egressOffset = b.BuildTable(3, slots => { /* all default/absent */ });

        // 2. NetworkPolicy { proxy = null (0), egress = egressOffset (1), allowed_appcontainer_peer = "MXC-Loopback" (2), ingress = null (3) }
        int peerOffset = b.CreateString("MXC-Loopback");
        int networkOffset = b.BuildTable(4, slots => {
            b.PutOffset(peerOffset); slots[2] = b.Offset;
            b.PutOffset(egressOffset); slots[1] = b.Offset;
        });

        // 3. ProcessSecurityEnvironment:
        //   0: version: SchemaVersion (4 bytes inline: major=1, minor=0)
        //   1: capabilities: string ("networkLoopback")
        //   2: disallow_win32k_system_calls: bool (default false)
        //   3: ui_restrictions: uint64 (default 0)
        //   4: fs_read_write: [string]
        //   5: fs_read_only: [string]
        //   6: fs_deny: [string] (absent)
        //   7: network_policy: NetworkPolicy
        //   8: fs_enumerate: [string]
        int capsOffset = b.CreateString("networkLoopback");
        int rwVecOffset = b.CreateStringVector(rwDirs);
        int roVecOffset = b.CreateStringVector(roDirs);
        int enumVecOffset = (enumDirs != null && enumDirs.Length > 0) ? b.CreateStringVector(enumDirs) : 0;

        int rootOffset = b.BuildTable(9, slots => {
            if (enumVecOffset != 0) { b.PutOffset(enumVecOffset); slots[8] = b.Offset; }
            b.PutOffset(networkOffset); slots[7] = b.Offset;
            b.PutOffset(roVecOffset); slots[5] = b.Offset;
            b.PutOffset(rwVecOffset); slots[4] = b.Offset;
            b.PutOffset(capsOffset); slots[1] = b.Offset;
            if (disallowWin32k) {
                b.PutByte(1);
                slots[2] = b.Offset;
            }
            // SchemaVersion { major=1, minor=(1 if fs_enumerate used else 0) } written back-to-front: minor first, then major
            b.Pad(2);
            b.PutUInt16((ushort)(enumVecOffset != 0 ? 1 : 0)); // minor
            b.PutUInt16(1); // major = 1
            slots[0] = b.Offset;
        });

        return b.FinishWithIdentifier(rootOffset, "PSEC");
    }
}

public sealed partial class StudioLabWfp {
    public static int CountFiltersReferencingPackage(string containerSid) {
        ValidateContainerSid(containerSid);
        int found = 0;
        using (var reader = CreateStaticGuard()) {
            IntPtr enumeration;
            Check(FwpmFilterCreateEnumHandle0(reader.engine, IntPtr.Zero, out enumeration), "enumerate residual package filters");
            try {
                uint count;
                do {
                    IntPtr entries;
                    Check(FwpmFilterEnum0(reader.engine, enumeration, 256, out entries, out count), "read residual package filters");
                    try {
                        for (int i = 0; i < count; i++) {
                            var f = (Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries, i * IntPtr.Size), typeof(Filter));
                            for (int j = 0; j < f.ConditionCount; j++) {
                                var c = (Condition)Marshal.PtrToStructure(IntPtr.Add(f.Conditions, j * 40), typeof(Condition));
                                if (c.Field == Package && c.Value.Type == SidValue && c.Value.Data != 0) {
                                    string val = new SecurityIdentifier(new IntPtr(unchecked((long)c.Value.Data))).Value;
                                    if (val == containerSid) { found++; break; }
                                }
                            }
                        }
                    } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                } while (count != 0);
            } finally { FwpmFilterDestroyEnumHandle0(reader.engine, enumeration); }
        }
        return found;
    }
}

public sealed class LoopbackSentinels : IDisposable {
    readonly TcpListener tcpListener;
    readonly UdpClient udpClient;
    readonly List<string> tcpMarkers = new List<string>();
    readonly List<string> udpMarkers = new List<string>();
    readonly object sync = new object();
    volatile bool stopping;
    readonly Thread tcpThread, udpThread;

    public int TcpPort { get; private set; }
    public int UdpPort { get; private set; }

    public LoopbackSentinels() {
        tcpListener = new TcpListener(IPAddress.Loopback, 0);
        tcpListener.Server.ExclusiveAddressUse = true;
        tcpListener.Start(8);
        TcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;

        udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        UdpPort = ((IPEndPoint)udpClient.Client.LocalEndPoint).Port;

        tcpThread = new Thread(RunTcp) { IsBackground = true };
        udpThread = new Thread(RunUdp) { IsBackground = true };
        tcpThread.Start();
        udpThread.Start();
    }

    void RunTcp() {
        while (!stopping) {
            try {
                var client = tcpListener.AcceptTcpClient();
                using (client) {
                    client.ReceiveTimeout = 1000;
                    var stream = client.GetStream();
                    var buf = new byte[128];
                    int n = stream.Read(buf, 0, buf.Length);
                    if (n > 0) {
                        string m = Encoding.ASCII.GetString(buf, 0, n);
                        lock (sync) tcpMarkers.Add(m);
                    }
                }
            } catch { if (stopping) break; }
        }
    }

    void RunUdp() {
        var ep = new IPEndPoint(IPAddress.Any, 0);
        while (!stopping) {
            try {
                byte[] data = udpClient.Receive(ref ep);
                if (data != null && data.Length > 0) {
                    string m = Encoding.ASCII.GetString(data);
                    lock (sync) udpMarkers.Add(m);
                }
            } catch { if (stopping) break; }
        }
    }

    public object DrainMarkers() {
        lock (sync) {
            var t = tcpMarkers.ToArray();
            var u = udpMarkers.ToArray();
            tcpMarkers.Clear();
            udpMarkers.Clear();
            return new { tcpCount = t.Length, tcpMarkers = t, udpCount = u.Length, udpMarkers = u };
        }
    }

    public void Dispose() {
        stopping = true;
        try { tcpListener.Stop(); } catch { }
        try { udpClient.Close(); } catch { }
        tcpThread.Join(1000);
        udpThread.Join(1000);
    }
}

internal static partial class StudioN4Preflight {
    static readonly Dictionary<string, uint> ExtraProcessRights = new Dictionary<string, uint> {
        {"PROCESS_TERMINATE", 0x0001},
        {"PROCESS_QUERY_LIMITED_INFORMATION", 0x1000},
        {"READ_CONTROL", 0x20000}
    };
    static readonly Dictionary<string, uint> ExtraThreadRights = new Dictionary<string, uint> {
        {"THREAD_TERMINATE", 0x0001},
        {"THREAD_QUERY_LIMITED_INFORMATION", 0x0800},
        {"READ_CONTROL", 0x20000}
    };

    internal static int NativeThreadId() { return GetCurrentThreadId(); }

    internal static Dictionary<string, object> DescribeHostCreation(IntPtr process, int pid) {
        var result = Describe(process, pid);
        IntPtr token;
        if (!OpenProcessToken(process, 8, out token)) throw new Win32Exception();
        try {
            result["tokenType"] = ReadToken(token, 8, p => Marshal.ReadInt32(p));
            result["integrity"] = ReadToken(token, 25, p => new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
            result["logonSids"] = ReadToken(token, 2, ReadGroupSids).FindAll(s => s.StartsWith("S-1-5-5-", StringComparison.Ordinal));
            return result;
        } finally { CloseHandle(token); }
    }

    internal static object InspectExtraRights(int id, bool thread) {
        var rows = new List<object>();
        foreach (var requested in thread ? ExtraThreadRights : ExtraProcessRights) {
            IntPtr h = thread ? OpenThread(requested.Value, false, id) : OpenProcess(requested.Value, false, id);
            int error = h == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
            if (h != IntPtr.Zero) CloseHandle(h);
            rows.Add(new { right = requested.Key, granted = h != IntPtr.Zero, error = error });
        }
        return rows;
    }

    internal static object ObserveTargetsAsCurrentThread(Target[] targets, IntPtr rawToken) {
        using (var identity = WindowsIdentity.GetCurrent(true)) {
            if (identity == null || identity.ImpersonationLevel < TokenImpersonationLevel.Impersonation)
                throw new IOException("Impersonation access probe requires a live impersonation token");
            var groups = ReadToken(rawToken, 2, ReadGroupSids);
            var results = new List<object>();
            foreach (var target in targets) {
                results.Add(new {
                    role = target.role,
                    pid = target.pid,
                    tid = target.tid,
                    processRights = InspectRights(target.pid, false),
                    threadRights = InspectRights(target.tid, true),
                    extraProcessRights = InspectExtraRights(target.pid, false),
                    extraThreadRights = InspectExtraRights(target.tid, true)
                });
            }
            return new {
                auditor = new {
                    userSid = identity.User.Value,
                    admin = groups.Contains("S-1-5-32-544"),
                    logonSids = groups.FindAll(s => s.StartsWith("S-1-5-5-", StringComparison.Ordinal))
                },
                targets = results
            };
        }
    }

    static int AuditHostCreate(string requestFile) { return 0; }
}

public sealed class StudioPsecGuardHost : IDisposable {
    const uint CreateSuspended = 0x00000004;
    const uint CreateUnicodeEnvironment = 0x00000400;
    const uint CreateNoWindow = 0x08000000;
    const uint OwnerAndDacl = 5;
    const uint WaitSignaled = 0;
    const uint WaitTimeout = 258;
    const uint KillOnJobClose = 0x00002000;
    const uint CleanupExit = 0x4e34;

    IntPtr job = IntPtr.Zero, process = IntPtr.Zero, thread = IntPtr.Zero;
    public int Pid { get; private set; }
    public int Tid { get; private set; }
    public long StartTicks { get; private set; }

    [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
        public int Count; public IntPtr Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        public short ShowWindow, ReservedLength;
        public IntPtr ReservedBytes, StdIn, StdOut, StdErr;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public int Pid, Tid; }
    [StructLayout(LayoutKind.Sequential)] struct JobBasicLimits {
        public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcesses; public UIntPtr Affinity; public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters {
        public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] struct JobExtendedLimits {
        public JobBasicLimits Basic; public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct ProfileInfo {
        public int Size, Flags;
        public string UserName, ProfilePath, DefaultPath, ServerName, PolicyPath;
        public IntPtr Profile;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LoadUserProfileW(IntPtr token, ref ProfileInfo profileInfo);
    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool UnloadUserProfile(IntPtr token, IntPtr profile);
    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern bool LogonUserW(string username, string domain, IntPtr password, int logonType, int provider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess, IntPtr attributes, int impersonationLevel, int tokenType, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string application, StringBuilder command,
        uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo info);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern bool CreateProcessWithLogonW(string username, string domain, IntPtr password, uint logonFlags,
        string application, StringBuilder command, uint flags, IntPtr environment, string directory,
        ref StartupInfo startup, out ProcessInfo info);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr handle, int kind, ref JobExtendedLimits limits, int length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetThreadTimes(IntPtr handle, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint access, bool inherit, int tid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint GetProcessIdOfThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern bool QueryPerformanceCounter(out long counter);
    [DllImport("kernel32.dll")] static extern bool QueryPerformanceFrequency(out long freq);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityInfo(IntPtr handle, int objectType, uint fields, out IntPtr owner, out IntPtr group,
        out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    static extern uint SetSecurityInfo(IntPtr handle, int objectType, uint fields, IntPtr owner, IntPtr group,
        IntPtr dacl, IntPtr sacl);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenDesktopW(string name, uint flags, bool inherit, int access);
    [DllImport("user32.dll", SetLastError = true)] static extern bool CloseDesktop(IntPtr value);
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool GetUserObjectSecurity(IntPtr obj, ref uint fields, byte[] result, uint size, out uint needed);

    static void Require(bool ok, string op) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), op); }

    public static long QpcNow() { long v; QueryPerformanceCounter(out v); return v; }
    public static long QpcFreq() { long v; QueryPerformanceFrequency(out v); return v; }

    static void ValidateLabUser(string user) {
        if (user != "ClaudeStudioLabA" && user != "ClaudeStudioLabB")
            throw new ArgumentException("Expected only ClaudeStudioLabA or ClaudeStudioLabB");
    }

    public static IntPtr AcquireSeclogonSeedToken(string user, string domain, SecureString password) {
        ValidateLabUser(user);
        // Acquire a standard seclogon primary token for ClaudeStudioLabA/B carrying the active interactive
        // session Logon SID without modifying WinSta0 or WinSta0\Default DACLs. The seed process is created
        // CREATE_SUSPENDED, never resumed (0 instructions / 0 CPU time), and immediately terminated.
        IntPtr pw = Marshal.SecureStringToGlobalAllocUnicode(password);
        ProcessInfo info = new ProcessInfo();
        IntPtr rawTok = IntPtr.Zero, dupTok = IntPtr.Zero;
        try {
            string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string cmdExe = Path.Combine(sysDir, "cmd.exe");
            var startup = new StartupInfo { Count = Marshal.SizeOf(typeof(StartupInfo)), Desktop = IntPtr.Zero };
            var cmd = new StringBuilder("\"" + cmdExe + "\" /c exit 0");
            Require(CreateProcessWithLogonW(user, domain, pw, 1, cmdExe, cmd,
                CreateSuspended | CreateNoWindow, IntPtr.Zero, sysDir, ref startup, out info),
                "CreateProcessWithLogonW(seed)");
            long c, e, k, u;
            Require(GetThreadTimes(info.Thread, out c, out e, out k, out u), "GetThreadTimes(seed)");
            if (k != 0 || u != 0) throw new IOException("Seed process unexpectedly executed");
            Require(OpenProcessToken(info.Process, 0x0002000A, out rawTok), "OpenProcessToken(seed)");
            Require(DuplicateTokenEx(rawTok, 0x000F01FF, IntPtr.Zero, 2, 1, out dupTok), "DuplicateTokenEx(seed)");
            return dupTok;
        } catch {
            if (dupTok != IntPtr.Zero) CloseHandle(dupTok);
            throw;
        } finally {
            if (rawTok != IntPtr.Zero) CloseHandle(rawTok);
            if (info.Process != IntPtr.Zero) {
                TerminateProcess(info.Process, CleanupExit);
                WaitForSingleObject(info.Process, 3000);
                CloseHandle(info.Process);
            }
            if (info.Thread != IntPtr.Zero) CloseHandle(info.Thread);
            Marshal.ZeroFreeGlobalAllocUnicode(pw);
        }
    }

    public static IntPtr LogonInteractive(string user, string domain, SecureString password) {
        ValidateLabUser(user);
        IntPtr pw = Marshal.SecureStringToGlobalAllocUnicode(password);
        IntPtr token = IntPtr.Zero;
        try { Require(LogonUserW(user, domain, pw, 2, 0, out token), "LogonUserW"); return token; }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(pw); }
    }

    public static string ReadPrimaryLogonSid(IntPtr token) {
        int needed;
        GetTokenInformation(token, 2, IntPtr.Zero, 0, out needed);
        if (needed < IntPtr.Size || needed > 65536) throw new IOException("Unexpected TokenGroups size");
        IntPtr buf = Marshal.AllocHGlobal(needed);
        try {
            int written;
            Require(GetTokenInformation(token, 2, buf, needed, out written), "GetTokenInformation(TokenGroups)");
            int count = Marshal.ReadInt32(buf);
            for (int i = 0; i < count; i++) {
                string sid = new SecurityIdentifier(Marshal.ReadIntPtr(buf, IntPtr.Size + i * IntPtr.Size * 2)).Value;
                if (sid.StartsWith("S-1-5-5-", StringComparison.Ordinal)) return sid;
            }
            throw new IOException("Token has no S-1-5-5-* Logon SID");
        } finally { Marshal.FreeHGlobal(buf); }
    }

    public static void CloseToken(IntPtr t) { if (t != IntPtr.Zero) CloseHandle(t); }

    public static IntPtr DuplicateHardened(IntPtr sourceToken, string hostSid) {
        var host = new SecurityIdentifier(hostSid);
        using (var me = WindowsIdentity.GetCurrent()) {
            if (!host.Equals(me.User)) throw new ArgumentException("Expected calling host as hostSid");
        }
        IntPtr copy = IntPtr.Zero, aclPtr = IntPtr.Zero, infoPtr = IntPtr.Zero;
        try {
            Require(DuplicateTokenEx(sourceToken, 0x000F01FF, IntPtr.Zero, 2, 1, out copy), "DuplicateTokenEx");
            var acl = new RawAcl(GenericAcl.AclRevision, 3);
            acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x10000000), host, false, null));
            acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x10000000), new SecurityIdentifier("S-1-5-18"), false, null));
            // OWNER RIGHTS (S-1-3-4) = 0x00121400 (SYNCHRONIZE | READ_CONTROL | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION)
            // Zero overlap with all 9 critical process rights, 5 critical thread rights, or PROCESS/THREAD_TERMINATE.
            acl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x00121400, new SecurityIdentifier("S-1-3-4"), false, null));
            var bytes = new byte[acl.BinaryLength];
            acl.GetBinaryForm(bytes, 0);
            aclPtr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, aclPtr, bytes.Length);
            infoPtr = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(infoPtr, aclPtr);
            Require(SetTokenInformation(copy, 6, infoPtr, IntPtr.Size), "SetTokenInformation(TokenDefaultDacl)");
            return copy;
        } catch { if (copy != IntPtr.Zero) CloseHandle(copy); throw; }
        finally {
            if (infoPtr != IntPtr.Zero) Marshal.FreeHGlobal(infoPtr);
            if (aclPtr != IntPtr.Zero) Marshal.FreeHGlobal(aclPtr);
        }
    }

    static object ReadSecurity(IntPtr handle, string hostSid, string accountSid, string expectedContainerSid = null) {
        IntPtr owner, group, dacl, sacl, descriptor;
        uint status = GetSecurityInfo(handle, 6, OwnerAndDacl, out owner, out group, out dacl, out sacl, out descriptor);
        if (status != 0) throw new Win32Exception((int)status, "GetSecurityInfo");
        try {
            var bytes = new byte[GetSecurityDescriptorLength(descriptor)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var actual = new RawSecurityDescriptor(bytes, 0);
            var entries = new List<object>();
            bool hasAccountAce = false, hasLogonSidAce = false, hasOwnerRightsZeroAce = false, hasHostAce = false, hasSystemAce = false, hasUnexpectedAce = false;
            if (actual.DiscretionaryAcl != null) {
                foreach (GenericAce item in actual.DiscretionaryAcl) {
                    var ace = item as CommonAce;
                    if (ace == null) { hasUnexpectedAce = true; continue; }
                    string sid = ace.SecurityIdentifier.Value;
                    uint mask = unchecked((uint)ace.AccessMask);
                    entries.Add(new { sid = sid, type = ace.AceType.ToString(), mask = mask, maskHex = "0x" + mask.ToString("X8"), flags = ace.AceFlags.ToString() });
                    if (sid == accountSid) { hasAccountAce = true; hasUnexpectedAce = true; }
                    else if (sid.StartsWith("S-1-5-5-", StringComparison.Ordinal)) { hasLogonSidAce = true; hasUnexpectedAce = true; }
                    else if (sid == "S-1-3-4" && ace.AceType == AceType.AccessAllowed && ace.AceFlags == AceFlags.None && (mask == 0 || (mask & ~0x00121400U) == 0)) hasOwnerRightsZeroAce = true;
                    else if (sid == hostSid && ace.AceType == AceType.AccessAllowed && ace.AceFlags == AceFlags.None && mask != 0) hasHostAce = true;
                    else if (sid == "S-1-5-18" && ace.AceType == AceType.AccessAllowed && ace.AceFlags == AceFlags.None && mask != 0) hasSystemAce = true;
                    else if (!String.IsNullOrEmpty(expectedContainerSid) && sid == expectedContainerSid && ace.AceType == AceType.AccessAllowed && ace.AceFlags == AceFlags.None) {
                        // Windows automatically grants the target AppContainer SID access on its own process/thread object.
                        // Ordinary A processes do NOT hold this AppContainer SID and cannot open the handle.
                    }
                    else hasUnexpectedAce = true;
                }
            }
            return new {
                owner = actual.Owner == null ? null : actual.Owner.Value,
                protectedDacl = (actual.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0,
                entries = entries,
                hardenedExpected = actual.DiscretionaryAcl != null && !hasAccountAce && !hasLogonSidAce &&
                    !hasUnexpectedAce && hasOwnerRightsZeroAce && hasHostAce && hasSystemAce
            };
        } finally { LocalFree(descriptor); }
    }

    public static object ReadDefaultDesktopDigest() {
        IntPtr desk = OpenDesktopW("Default", 0, false, 0x20000);
        if (desk == IntPtr.Zero) return new { readable = false, error = Marshal.GetLastWin32Error(), digest = (string)null };
        try {
            uint fields = 7, size;
            bool sized = GetUserObjectSecurity(desk, ref fields, null, 0, out size);
            int err = Marshal.GetLastWin32Error();
            if ((!sized && err != 122) || size < 20 || size > 65536) return new { readable = false, error = err, digest = (string)null };
            var bytes = new byte[size];
            if (!GetUserObjectSecurity(desk, ref fields, bytes, (uint)bytes.Length, out size)) return new { readable = false, error = Marshal.GetLastWin32Error(), digest = (string)null };
            using (var sha = System.Security.Cryptography.SHA256.Create())
                return new { readable = true, error = 0, digest = BitConverter.ToString(sha.ComputeHash(bytes, 0, (int)size)).Replace("-", "") };
        } finally { CloseDesktop(desk); }
    }

    public static IntPtr LoadLabProfile(IntPtr token, string userName) {
        ValidateLabUser(userName);
        var pi = new ProfileInfo { Size = Marshal.SizeOf(typeof(ProfileInfo)), Flags = 1, UserName = userName };
        Require(LoadUserProfileW(token, ref pi), "LoadUserProfileW");
        return pi.Profile;
    }

    public static void UnloadLabProfile(IntPtr token, IntPtr profileHandle) {
        if (token != IntPtr.Zero && profileHandle != IntPtr.Zero) UnloadUserProfile(token, profileHandle);
    }

    public static StudioPsecGuardHost StartSuspended(IntPtr token, string executable, string arguments, bool withProfile, string desktopName) {
        IntPtr desktop = IntPtr.Zero, env = IntPtr.Zero;
        bool envFromUserEnv = false;
        var holder = new StudioPsecGuardHost();
        try {
            holder.job = CreateJobObjectW(IntPtr.Zero, null);
            Require(holder.job != IntPtr.Zero, "CreateJobObjectW");
            var limits = new JobExtendedLimits { Basic = new JobBasicLimits { Flags = KillOnJobClose } };
            Require(SetInformationJobObject(holder.job, 9, ref limits, 144), "SetInformationJobObject");

            desktop = Marshal.StringToHGlobalUni(String.IsNullOrEmpty(desktopName) ? @"WinSta0\Default" : desktopName);
            var startup = new StartupInfo { Count = Marshal.SizeOf(typeof(StartupInfo)), Desktop = desktop };
            uint createFlags = CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow;
            if (withProfile) {
                Require(CreateEnvironmentBlock(out env, token, false), "CreateEnvironmentBlock");
                envFromUserEnv = true;
            } else {
                string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                env = Marshal.StringToHGlobalUni("SystemRoot=" + sysRoot + "\0\0");
            }
            var cmd = new StringBuilder("\"" + executable + "\" " + arguments);
            ProcessInfo info;
            Require(CreateProcessWithTokenW(token, withProfile ? 1U : 0U, executable, cmd,
                createFlags, env,
                Path.GetDirectoryName(executable), ref startup, out info), "CreateProcessWithTokenW");
            holder.process = info.Process;
            holder.thread = info.Thread;
            holder.Pid = info.Pid;
            holder.Tid = info.Tid;
            Require(AssignProcessToJobObject(holder.job, holder.process), "AssignProcessToJobObject");
            var id = StudioN4Preflight.DescribeHostCreation(holder.process, holder.Pid);
            holder.StartTicks = (long)id["startTicks"];
            return holder;
        } catch { holder.Dispose(); throw; }
        finally {
            if (desktop != IntPtr.Zero) Marshal.FreeHGlobal(desktop);
            if (env != IntPtr.Zero) {
                if (envFromUserEnv) DestroyEnvironmentBlock(env);
                else Marshal.FreeHGlobal(env);
            }
        }
    }

    public object RestoreTokenObjectDaclOnly(IntPtr referenceToken, string hostSid, string accountSid) {
        // Read referenceToken's TokenDefaultDacl (which grants ClaudeStudioLabA + SYSTEM + LogonSID)
        // and apply it ONLY to Layer-1's Primary Token object DACL (NOT to Layer-1's TokenDefaultDacl!).
        // This lets Layer-1 / Appinfo query/duplicate Layer-1's own token while keeping Layer-1's
        // Process SD, Thread SD, and TokenDefaultDacl (inherited by Layer-2!) completely hardened.
        int needed;
        GetTokenInformation(referenceToken, 6, IntPtr.Zero, 0, out needed);
        if (needed < IntPtr.Size || needed > 65536) throw new IOException("Unexpected reference TokenDefaultDacl size");
        IntPtr buf = Marshal.AllocHGlobal(needed);
        IntPtr procTok = IntPtr.Zero;
        try {
            int written;
            Require(GetTokenInformation(referenceToken, 6, buf, needed, out written), "GetTokenInformation(reference TokenDefaultDacl)");
            IntPtr refDefaultDacl = Marshal.ReadIntPtr(buf);
            if (refDefaultDacl == IntPtr.Zero) throw new IOException("Reference TokenDefaultDacl is null");
            Require(OpenProcessToken(process, 0x00040008, out procTok), "OpenProcessToken(layer1, WRITE_DAC|TOKEN_QUERY)");
            uint sStatus = SetSecurityInfo(procTok, 6, 4, IntPtr.Zero, IntPtr.Zero, refDefaultDacl, IntPtr.Zero);
            if (sStatus != 0) throw new Win32Exception((int)sStatus, "SetSecurityInfo(layer1 procTok DACL)");
            return new {
                restored = true,
                tokenObjectDaclOnly = true,
                processSecurityAfterRestore = ReadSecurity(process, hostSid, accountSid),
                threadSecurityAfterRestore = ReadSecurity(thread, hostSid, accountSid)
            };
        } finally {
            if (procTok != IntPtr.Zero) CloseHandle(procTok);
            Marshal.FreeHGlobal(buf);
        }
    }

    public uint ResumeMainThread() {
        uint prev = ResumeThread(thread);
        if (prev == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread(layer1)");
        return prev;
    }

    public object WaitExit(int timeoutMs) {
        uint w = WaitForSingleObject(process, (uint)timeoutMs);
        bool timedOut = w != WaitSignaled;
        if (timedOut) { TerminateProcess(process, CleanupExit); w = WaitForSingleObject(process, 3000); }
        uint code;
        Require(GetExitCodeProcess(process, out code), "GetExitCodeProcess");
        return new { exitCode = code, timedOut = timedOut, signaled = w == WaitSignaled };
    }

    public object TerminateNow() {
        if (WaitForSingleObject(process, 0) == WaitTimeout) {
            Require(TerminateProcess(process, CleanupExit), "TerminateProcess");
        }
        uint w = WaitForSingleObject(process, 3000);
        uint code;
        Require(GetExitCodeProcess(process, out code), "GetExitCodeProcess");
        return new { exitCode = code, signaled = w == WaitSignaled };
    }

    public static object InspectSuspendedPsecChild(int pid, int tid, string hostSid, string accountSid) {
        IntPtr p = OpenProcess(0x001F0FFF, false, pid);
        if (p == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Host OpenProcess(layer2)");
        IntPtr t = OpenThread(0x001F03FF, false, tid);
        if (t == IntPtr.Zero) { int e = Marshal.GetLastWin32Error(); CloseHandle(p); throw new Win32Exception(e, "Host OpenThread(layer2)"); }
        try {
            if (WaitForSingleObject(p, 0) != WaitTimeout) throw new IOException("Layer-2 process is not live");
            if (GetProcessIdOfThread(t) != (uint)pid) throw new IOException("Layer-2 thread PID mismatch");
            long c, e, k, u;
            Require(GetThreadTimes(t, out c, out e, out k, out u), "GetThreadTimes(layer2)");
            var identity = StudioN4Preflight.DescribeHostCreation(p, pid);
            string containerSid = identity.ContainsKey("containerSid") ? identity["containerSid"] as string : null;
            return new {
                pid = pid,
                tid = tid,
                identity = identity,
                processSecurity = ReadSecurity(p, hostSid, accountSid, containerSid),
                threadSecurity = ReadSecurity(t, hostSid, accountSid, containerSid),
                threadUserTime = u,
                threadKernelTime = k
            };
        } finally { CloseHandle(t); CloseHandle(p); }
    }

    public static void AllowSelfContainerDefaultDacl(int pid, string hostSid, string containerSid) {
        // Called while Layer-2 is STILL SUSPENDED (before A1/A2/cross-user handle audit and before WFP/ResumeThread):
        // 1. Layer-2's Process & Thread SDs remain untouched and hardened ([Host, SY, S-1-3-4(0x00121400), containerSid]),
        //    preserving 16/16 ERROR_ACCESS_DENIED for ordinary A (same & distinct logon) and cross-user B on startup gate.
        // 2. Layer-2's own Token object DACL grants strictly read-only TOKEN_READ|TOKEN_QUERY_SOURCE (0x00020018) to S-1-3-4
        //    plus TOKEN_ALL_ACCESS (0x000F01FF) to Host, SYSTEM, and containerSid.
        // 3. Layer-2's TokenDefaultDacl (used ONLY for internal objects and Layer-3 child processes created AFTER Layer-2 is
        //    resumed under active WFP) is set to [Host(GA), SYSTEM(GA), tokenUserSid(GA), containerSid(GA)] so Windows
        //    AppContainer SeAccessCheck (User/Groups & AppContainer) succeeds for Layer-3 Schannel/SSPI/CNG/Chromium/Node
        //    helpers while remaining isolated from cross-space users and non-owners.
        IntPtr p = OpenProcess(0x1000, false, pid);
        if (p == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess(layer2 for TokenDefaultDacl)");
        IntPtr tok = IntPtr.Zero, aclPtr = IntPtr.Zero, tokAclPtr = IntPtr.Zero, infoPtr = IntPtr.Zero, userBuf = IntPtr.Zero;
        try {
            Require(OpenProcessToken(p, 0x00040088 /* WRITE_DAC|TOKEN_ADJUST_DEFAULT|TOKEN_QUERY */, out tok), "OpenProcessToken(layer2)");
            int uNeed;
            GetTokenInformation(tok, 1 /* TokenUser */, IntPtr.Zero, 0, out uNeed);
            userBuf = Marshal.AllocHGlobal(uNeed);
            int uWritten;
            Require(GetTokenInformation(tok, 1, userBuf, uNeed, out uWritten), "GetTokenInformation(layer2 TokenUser)");
            var tokenUserSid = new SecurityIdentifier(Marshal.ReadIntPtr(userBuf));

            var acl = new RawAcl(GenericAcl.AclRevision, 4);
            acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x10000000), new SecurityIdentifier(hostSid), false, null));
            acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x10000000), new SecurityIdentifier("S-1-5-18"), false, null));
            acl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x10000000), tokenUserSid, false, null));
            acl.InsertAce(3, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x10000000), new SecurityIdentifier(containerSid), false, null));
            var bytes = new byte[acl.BinaryLength];
            acl.GetBinaryForm(bytes, 0);
            aclPtr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, aclPtr, bytes.Length);
            infoPtr = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(infoPtr, aclPtr);
            Require(SetTokenInformation(tok, 6, infoPtr, IntPtr.Size), "SetTokenInformation(layer2 TokenDefaultDacl)");

            var tokAcl = new RawAcl(GenericAcl.AclRevision, 4);
            tokAcl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x000F01FF, new SecurityIdentifier(hostSid), false, null));
            tokAcl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x000F01FF, new SecurityIdentifier("S-1-5-18"), false, null));
            tokAcl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x00020018, new SecurityIdentifier("S-1-3-4"), false, null));
            tokAcl.InsertAce(3, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x000F01FF, new SecurityIdentifier(containerSid), false, null));
            var tokBytes = new byte[tokAcl.BinaryLength];
            tokAcl.GetBinaryForm(tokBytes, 0);
            tokAclPtr = Marshal.AllocHGlobal(tokBytes.Length);
            Marshal.Copy(tokBytes, 0, tokAclPtr, tokBytes.Length);
            uint st = SetSecurityInfo(tok, 6, 4 | 0x80000000U, IntPtr.Zero, IntPtr.Zero, tokAclPtr, IntPtr.Zero);
            if (st != 0) throw new Win32Exception((int)st, "SetSecurityInfo(layer2 token object DACL)");
        } finally {
            if (userBuf != IntPtr.Zero) Marshal.FreeHGlobal(userBuf);
            if (infoPtr != IntPtr.Zero) Marshal.FreeHGlobal(infoPtr);
            if (tokAclPtr != IntPtr.Zero) Marshal.FreeHGlobal(tokAclPtr);
            if (aclPtr != IntPtr.Zero) Marshal.FreeHGlobal(aclPtr);
            if (tok != IntPtr.Zero) CloseHandle(tok);
            CloseHandle(p);
        }
    }

    public static void HostTerminatePid(int pid) {
        if (pid <= 0) return;
        IntPtr p = OpenProcess(0x00100001 /* SYNCHRONIZE | PROCESS_TERMINATE */, false, pid);
        if (p == IntPtr.Zero) return;
        try {
            if (WaitForSingleObject(p, 0) == WaitTimeout) {
                TerminateProcess(p, CleanupExit);
                WaitForSingleObject(p, 3000);
            }
        } finally { CloseHandle(p); }
    }

    public static object TryReadProcessState(int pid) {
        IntPtr p = OpenProcess(0x00101000, false, pid);
        if (p == IntPtr.Zero) return new { openable = false, error = Marshal.GetLastWin32Error() };
        try {
            bool alive = WaitForSingleObject(p, 0) == WaitTimeout;
            uint code = 0; GetExitCodeProcess(p, out code);
            return new { openable = true, alive = alive, exitCode = code, exitCodeHex = "0x" + code.ToString("X8") };
        } finally { CloseHandle(p); }
    }

    public static object HostResumeChildOnly(int pid, int tid) {
        IntPtr p = OpenProcess(0x00101400, false, pid);
        if (p == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Host OpenProcess for resume");
        IntPtr t = OpenThread(0x00100802, false, tid);
        if (t == IntPtr.Zero) { int e = Marshal.GetLastWin32Error(); CloseHandle(p); throw new Win32Exception(e, "Host OpenThread for resume"); }
        try {
            if (GetProcessIdOfThread(t) != (uint)pid) throw new IOException("Thread PID mismatch before resume");
            long c, e, k, u;
            Require(GetThreadTimes(t, out c, out e, out k, out u), "GetThreadTimes before resume");
            if (u != 0 || k != 0) throw new IOException("Layer-2 thread already ran before host ResumeThread");
            long qpcBefore = QpcNow();
            uint prev = ResumeThread(t);
            long qpcAfter = QpcNow();
            if (prev == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error(), "Host ResumeThread(layer2)");
            return new {
                previousSuspendCount = prev,
                qpcBeforeResume = qpcBefore,
                qpcAfterResume = qpcAfter
            };
        } finally { CloseHandle(t); CloseHandle(p); }
    }

    public static object HostResumeChildAndWait(int pid, int tid, int waitMs) {
        IntPtr p = OpenProcess(0x00101400, false, pid);
        if (p == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Host OpenProcess for resume");
        IntPtr t = OpenThread(0x00100802, false, tid);
        if (t == IntPtr.Zero) { int e = Marshal.GetLastWin32Error(); CloseHandle(p); throw new Win32Exception(e, "Host OpenThread for resume"); }
        try {
            if (GetProcessIdOfThread(t) != (uint)pid) throw new IOException("Thread PID mismatch before resume");
            long c, e, k, u;
            Require(GetThreadTimes(t, out c, out e, out k, out u), "GetThreadTimes before resume");
            if (u != 0 || k != 0) throw new IOException("Layer-2 thread already ran before host ResumeThread");
            long qpcBefore = QpcNow();
            uint prev = ResumeThread(t);
            long qpcAfter = QpcNow();
            if (prev == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error(), "Host ResumeThread(layer2)");
            uint wait = WaitForSingleObject(p, (uint)waitMs);
            uint code = 0;
            if (wait == WaitSignaled) GetExitCodeProcess(p, out code);
            return new {
                previousSuspendCount = prev,
                qpcBeforeResume = qpcBefore,
                qpcAfterResume = qpcAfter,
                exitedCleanly = wait == WaitSignaled,
                exitCode = code
            };
        } finally { CloseHandle(t); CloseHandle(p); }
    }

    public static object RunAudit(IntPtr token, int ordPid, int ordTid, long ordTicks, int l1Pid, int l1Tid, long l1Ticks, int l2Pid, int l2Tid, long l2Ticks) {
        var targets = new[] {
            new StudioN4Preflight.Target { role = "ordinary", pid = ordPid, tid = ordTid, startTicks = ordTicks },
            new StudioN4Preflight.Target { role = "layer1", pid = l1Pid, tid = l1Tid, startTicks = l1Ticks },
            new StudioN4Preflight.Target { role = "layer2", pid = l2Pid, tid = l2Tid, startTicks = l2Ticks }
        };
        Require(ImpersonateLoggedOnUser(token), "ImpersonateLoggedOnUser");
        try { return StudioN4Preflight.ObserveTargetsAsCurrentThread(targets, token); }
        finally { if (!RevertToSelf()) Environment.FailFast("RevertToSelf failed"); }
    }

    public void Dispose() {
        if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; }
        if (process != IntPtr.Zero) {
            if (WaitForSingleObject(process, 100) == WaitTimeout) TerminateProcess(process, CleanupExit);
            WaitForSingleObject(process, 3000);
            CloseHandle(process); process = IntPtr.Zero;
        }
        if (thread != IntPtr.Zero) { CloseHandle(thread); thread = IntPtr.Zero; }
    }
}
