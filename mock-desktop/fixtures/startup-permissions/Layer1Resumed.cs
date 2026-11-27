using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

// Verification harness for resumed Layer-1 native launcher -> suspended Layer-2 child.
// Resumes ONLY the verified Layer-1 launcher; NEVER resumes Layer-2 or ordinary control.
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

    internal static object DescribeTokenDefaultDacl(IntPtr token) {
        return ReadToken(token, 6, p => {
            IntPtr pacl = Marshal.ReadIntPtr(p);
            if (pacl == IntPtr.Zero) return new { isNull = true, aceCount = 0, entries = new List<object>() };
            ushort aclSize = unchecked((ushort)Marshal.ReadInt16(pacl, 2));
            if (aclSize < 8) throw new InvalidDataException("Unexpected ACL size: " + aclSize);
            var bytes = new byte[aclSize];
            Marshal.Copy(pacl, bytes, 0, aclSize);
            var acl = new RawAcl(bytes, 0);
            var entries = new List<object>();
            foreach (GenericAce item in acl) {
                var ace = item as CommonAce;
                if (ace == null) {
                    entries.Add(new { sid = (string)null, type = item.AceType.ToString(), mask = 0U, maskHex = "0x00000000", flags = item.AceFlags.ToString() });
                    continue;
                }
                uint mask = unchecked((uint)ace.AccessMask);
                entries.Add(new {
                    sid = ace.SecurityIdentifier.Value,
                    type = ace.AceType.ToString(),
                    mask = mask,
                    maskHex = "0x" + mask.ToString("X8"),
                    flags = ace.AceFlags.ToString()
                });
            }
            return new { isNull = false, aceCount = acl.Count, entries = entries };
        });
    }

    internal static Dictionary<string, object> DescribeHostCreation(IntPtr process, int pid) {
        var result = Describe(process, pid);
        IntPtr token;
        if (!OpenProcessToken(process, 8, out token)) throw new Win32Exception();
        try {
            result["tokenType"] = ReadToken(token, 8, p => Marshal.ReadInt32(p));
            result["integrity"] = ReadToken(token, 25, p => new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
            result["logonSids"] = ReadToken(token, 2, ReadGroupSids).FindAll(s => s.StartsWith("S-1-5-5-", StringComparison.Ordinal));
            result["tokenDefaultDacl"] = DescribeTokenDefaultDacl(token);
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
            var logonSids = groups.FindAll(s => s.StartsWith("S-1-5-5-", StringComparison.Ordinal));
            var integrity = ReadToken(rawToken, 25, p => new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
            bool admin = groups.Contains("S-1-5-32-544");
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
                    mode = "impersonation",
                    userSid = identity.User.Value,
                    admin = admin,
                    impersonationLevel = identity.ImpersonationLevel.ToString(),
                    integrity = integrity,
                    logonSids = logonSids
                },
                targets = results
            };
        }
    }

    static int AuditHostCreate(string requestFile) { return 0; }
}

public sealed class StudioLayer1Holder : IDisposable {
    const uint CreateSuspended = 0x00000004;
    const uint CreateUnicodeEnvironment = 0x00000400;
    const uint CreateNoWindow = 0x08000000;
    const uint OwnerAndDacl = 5;
    const uint WaitSignaled = 0;
    const uint WaitTimeout = 258;
    const uint KillOnJobClose = 0x00002000;
    const uint CleanupExit = 0x4e34;
    const int SecurityImpersonation = 2;
    const int TokenPrimary = 1;
    const int TokenDefaultDaclInfoClass = 6;

    IntPtr job = IntPtr.Zero;
    IntPtr process = IntPtr.Zero;
    IntPtr thread = IntPtr.Zero;
    public int Pid { get; private set; }
    public int Tid { get; private set; }
    public long StartTicks { get; private set; }
    public int ResumeCalls { get; private set; }
    public uint LastResumePreviousCount { get; private set; }

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

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern bool LogonUserW(string username, string domain, IntPtr password, int logonType, int provider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess, IntPtr attributes, int impersonationLevel, int tokenType, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string application, StringBuilder command,
        uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo info);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr handle, int kind, ref JobExtendedLimits limits, int length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetHandleInformation(IntPtr handle, out uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetThreadTimes(IntPtr handle, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint access, bool inherit, int tid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint GetProcessIdOfThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityInfo(IntPtr handle, int objectType, uint fields, out IntPtr owner, out IntPtr group,
        out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenDesktopW(string name, uint flags, bool inherit, int access);
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool CloseDesktop(IntPtr value);
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool GetUserObjectSecurity(IntPtr obj, ref uint fields, byte[] result, uint size, out uint needed);

    static void Require(bool ok, string operation) {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }

    public static IntPtr LogonInteractive(string user, string domain, SecureString password) {
        if (user != "ClaudeStudioLabA") throw new ArgumentException("Expected only ClaudeStudioLabA");
        IntPtr passwordPointer = Marshal.SecureStringToGlobalAllocUnicode(password);
        IntPtr token = IntPtr.Zero;
        try {
            Require(LogonUserW(user, domain, passwordPointer, 2, 0, out token), "LogonUserW");
            return token;
        } finally {
            Marshal.ZeroFreeGlobalAllocUnicode(passwordPointer);
        }
    }

    public static void CloseToken(IntPtr token) {
        if (token != IntPtr.Zero) CloseHandle(token);
    }

    public static object ReadTokenDefaultDacl(IntPtr token) {
        return StudioN4Preflight.DescribeTokenDefaultDacl(token);
    }

    public static IntPtr DuplicateWithHardenedDefaultDacl(IntPtr sourceToken, string hostSid) {
        var host = new SecurityIdentifier(hostSid);
        using (var me = WindowsIdentity.GetCurrent()) {
            if (!host.Equals(me.User)) throw new ArgumentException("Expected the calling host as hostSid");
        }
        IntPtr copy = IntPtr.Zero;
        IntPtr aclPtr = IntPtr.Zero;
        IntPtr infoPtr = IntPtr.Zero;
        try {
            Require(DuplicateTokenEx(sourceToken, 0, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out copy), "DuplicateTokenEx");
            var acl = new RawAcl(GenericAcl.AclRevision, 3);
            acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x10000000), host, false, null));
            acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x10000000), new SecurityIdentifier("S-1-5-18"), false, null));
            acl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0, new SecurityIdentifier("S-1-3-4"), false, null));
            var aclBytes = new byte[acl.BinaryLength];
            acl.GetBinaryForm(aclBytes, 0);

            aclPtr = Marshal.AllocHGlobal(aclBytes.Length);
            Marshal.Copy(aclBytes, 0, aclPtr, aclBytes.Length);
            infoPtr = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(infoPtr, aclPtr);
            Require(SetTokenInformation(copy, TokenDefaultDaclInfoClass, infoPtr, IntPtr.Size), "SetTokenInformation(TokenDefaultDacl)");
            return copy;
        } catch {
            if (copy != IntPtr.Zero) CloseHandle(copy);
            throw;
        } finally {
            if (infoPtr != IntPtr.Zero) Marshal.FreeHGlobal(infoPtr);
            if (aclPtr != IntPtr.Zero) Marshal.FreeHGlobal(aclPtr);
        }
    }

    static object ReadSecurity(IntPtr handle, string hostSid, string accountSid) {
        IntPtr owner, group, dacl, sacl, descriptor;
        uint status = GetSecurityInfo(handle, 6, OwnerAndDacl, out owner, out group, out dacl, out sacl, out descriptor);
        if (status != 0) throw new Win32Exception((int)status, "GetSecurityInfo");
        try {
            var bytes = new byte[GetSecurityDescriptorLength(descriptor)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var actual = new RawSecurityDescriptor(bytes, 0);
            bool protectedDacl = (actual.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
            var entries = new List<object>();
            bool hasAccountAce = false;
            bool hasLogonSidAce = false;
            bool hasOwnerRightsZeroAce = false;
            bool hasHostAce = false;
            bool hasSystemAce = false;
            bool hasUnexpectedAce = false;
            if (actual.DiscretionaryAcl != null) {
                foreach (GenericAce item in actual.DiscretionaryAcl) {
                    var ace = item as CommonAce;
                    if (ace == null) { hasUnexpectedAce = true; continue; }
                    string sid = ace.SecurityIdentifier.Value;
                    uint mask = unchecked((uint)ace.AccessMask);
                    entries.Add(new {
                        sid = sid,
                        type = ace.AceType.ToString(),
                        mask = mask,
                        maskHex = "0x" + mask.ToString("X8"),
                        flags = ace.AceFlags.ToString()
                    });
                    if (sid == accountSid) { hasAccountAce = true; hasUnexpectedAce = true; }
                    else if (sid.StartsWith("S-1-5-5-", StringComparison.Ordinal)) { hasLogonSidAce = true; hasUnexpectedAce = true; }
                    else if (sid == "S-1-3-4" && ace.AceType == AceType.AccessAllowed && ace.AceFlags == AceFlags.None && mask == 0) { hasOwnerRightsZeroAce = true; }
                    else if (sid == hostSid && ace.AceType == AceType.AccessAllowed && ace.AceFlags == AceFlags.None && mask != 0) { hasHostAce = true; }
                    else if (sid == "S-1-5-18" && ace.AceType == AceType.AccessAllowed && ace.AceFlags == AceFlags.None && mask != 0) { hasSystemAce = true; }
                    else { hasUnexpectedAce = true; }
                }
            }
            return new {
                owner = actual.Owner == null ? null : actual.Owner.Value,
                protectedDacl = protectedDacl,
                controlFlags = actual.ControlFlags.ToString(),
                entries = entries,
                hasAccountAce = hasAccountAce,
                hasLogonSidAce = hasLogonSidAce,
                hasOwnerRightsZeroAce = hasOwnerRightsZeroAce,
                hasHostAce = hasHostAce,
                hasSystemAce = hasSystemAce,
                hasUnexpectedAce = hasUnexpectedAce,
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
            if ((!sized && err != 122) || size < 20 || size > 65536)
                return new { readable = false, error = err, digest = (string)null };
            var bytes = new byte[size];
            if (!GetUserObjectSecurity(desk, ref fields, bytes, (uint)bytes.Length, out size))
                return new { readable = false, error = Marshal.GetLastWin32Error(), digest = (string)null };
            using (var sha = System.Security.Cryptography.SHA256.Create())
                return new { readable = true, error = 0, digest = BitConverter.ToString(sha.ComputeHash(bytes, 0, (int)size)).Replace("-", "") };
        } finally { CloseDesktop(desk); }
    }

    public static object BrokerIdentity() {
        using (var me = Process.GetCurrentProcess()) {
            return new {
                identity = StudioN4Preflight.DescribeHostCreation(me.Handle, me.Id),
                tid = StudioN4Preflight.NativeThreadId()
            };
        }
    }

    public static StudioLayer1Holder StartSuspended(IntPtr token, string executable, string arguments) {
        if (!String.Equals(Path.GetFileName(executable), "StudioALayer1Launcher.exe", StringComparison.OrdinalIgnoreCase) ||
            !Path.IsPathRooted(executable))
            throw new ArgumentException("Expected StudioALayer1Launcher.exe");
        IntPtr desktop = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        var holder = new StudioLayer1Holder();
        try {
            holder.job = CreateJobObjectW(IntPtr.Zero, null);
            Require(holder.job != IntPtr.Zero, "CreateJobObjectW");
            var limits = new JobExtendedLimits { Basic = new JobBasicLimits { Flags = KillOnJobClose } };
            Require(Marshal.SizeOf(typeof(JobExtendedLimits)) == 144, "Unexpected x64 Job ABI");
            Require(SetInformationJobObject(holder.job, 9, ref limits, 144), "SetInformationJobObject");

            desktop = Marshal.StringToHGlobalUni(@"WinSta0\Default");
            var startup = new StartupInfo { Count = Marshal.SizeOf(typeof(StartupInfo)), Desktop = desktop };
            string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            environment = Marshal.StringToHGlobalUni("SystemRoot=" + systemRoot + "\0\0");
            var cmd = new StringBuilder("\"" + executable + "\" " + arguments);
            ProcessInfo info;
            Require(CreateProcessWithTokenW(token, 0, executable, cmd,
                CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow, environment,
                Path.GetDirectoryName(executable), ref startup, out info), "CreateProcessWithTokenW");
            holder.process = info.Process;
            holder.thread = info.Thread;
            holder.Pid = info.Pid;
            holder.Tid = info.Tid;
            Require(AssignProcessToJobObject(holder.job, holder.process), "AssignProcessToJobObject");
            var identity = StudioN4Preflight.DescribeHostCreation(holder.process, holder.Pid);
            holder.StartTicks = (long)identity["startTicks"];
            return holder;
        } catch {
            holder.Dispose();
            throw;
        } finally {
            if (desktop != IntPtr.Zero) Marshal.FreeHGlobal(desktop);
            if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
        }
    }

    public uint ResumeMainThread() {
        if (thread == IntPtr.Zero) throw new IOException("No thread handle to resume");
        uint prev = ResumeThread(thread);
        if (prev == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread");
        ResumeCalls++;
        LastResumePreviousCount = prev;
        return prev;
    }

    public object Snapshot(string hostSid, string accountSid) {
        if (process == IntPtr.Zero || WaitForSingleObject(process, 0) != WaitTimeout)
            throw new IOException("Target process is not live");
        uint processFlags, threadFlags;
        bool inCleanupJob;
        Require(GetHandleInformation(process, out processFlags), "GetHandleInformation(process)");
        Require(GetHandleInformation(thread, out threadFlags), "GetHandleInformation(thread)");
        Require(IsProcessInJob(process, job, out inCleanupJob), "IsProcessInJob(cleanup)");
        long created, exit, kernel, user;
        Require(GetThreadTimes(thread, out created, out exit, out kernel, out user), "GetThreadTimes");
        return new {
            pid = Pid,
            tid = Tid,
            identity = StudioN4Preflight.DescribeHostCreation(process, Pid),
            processSecurity = ReadSecurity(process, hostSid, accountSid),
            threadSecurity = ReadSecurity(thread, hostSid, accountSid),
            processInheritable = (processFlags & 1) != 0,
            threadInheritable = (threadFlags & 1) != 0,
            inCleanupJob = inCleanupJob,
            threadUserTime = user,
            threadKernelTime = kernel,
            resumeCalls = ResumeCalls,
            lastResumePreviousCount = LastResumePreviousCount
        };
    }

    public static object HostInspectChild(int pid, int tid, string hostSid, string accountSid) {
        // Host opens Layer-2 by PID/TID relying on Host SID's GENERIC_ALL ACE in Layer-2's DACL.
        IntPtr p = OpenProcess(0x001F0FFF, false, pid);
        if (p == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Host OpenProcess(layer2)");
        IntPtr t = OpenThread(0x001F03FF, false, tid);
        if (t == IntPtr.Zero) {
            int err = Marshal.GetLastWin32Error();
            CloseHandle(p);
            throw new Win32Exception(err, "Host OpenThread(layer2)");
        }
        try {
            if (WaitForSingleObject(p, 0) != WaitTimeout) throw new IOException("Layer-2 child is not live");
            if (GetProcessIdOfThread(t) != (uint)pid) throw new IOException("Layer-2 thread does not belong to child PID");
            long created, exit, kernel, user;
            Require(GetThreadTimes(t, out created, out exit, out kernel, out user), "GetThreadTimes(layer2)");
            return new {
                pid = pid,
                tid = tid,
                hostOpenedFullAccess = true,
                identity = StudioN4Preflight.DescribeHostCreation(p, pid),
                processSecurity = ReadSecurity(p, hostSid, accountSid),
                threadSecurity = ReadSecurity(t, hostSid, accountSid),
                threadUserTime = user,
                threadKernelTime = kernel,
                resumeCalls = 0
            };
        } finally {
            CloseHandle(t);
            CloseHandle(p);
        }
    }

    public static bool IsPidAlive(int pid) {
        IntPtr p = OpenProcess(0x101000, false, pid);
        if (p == IntPtr.Zero) return false;
        try { return WaitForSingleObject(p, 0) == WaitTimeout; }
        finally { CloseHandle(p); }
    }

    public static object RunImpersonatedAudit4(IntPtr token,
        int ordinaryPid, int ordinaryTid, long ordinaryTicks,
        int layer1Pid, int layer1Tid, long layer1Ticks,
        int layer2Pid, int layer2Tid, long layer2Ticks,
        int brokerPid, int brokerTid, long brokerTicks) {
        var targets = new[] {
            new StudioN4Preflight.Target { role = "ordinary", pid = ordinaryPid, tid = ordinaryTid, startTicks = ordinaryTicks },
            new StudioN4Preflight.Target { role = "layer1", pid = layer1Pid, tid = layer1Tid, startTicks = layer1Ticks },
            new StudioN4Preflight.Target { role = "layer2", pid = layer2Pid, tid = layer2Tid, startTicks = layer2Ticks },
            new StudioN4Preflight.Target { role = "broker", pid = brokerPid, tid = brokerTid, startTicks = brokerTicks }
        };
        Require(ImpersonateLoggedOnUser(token), "ImpersonateLoggedOnUser");
        try {
            return StudioN4Preflight.ObserveTargetsAsCurrentThread(targets, token);
        } finally {
            if (!RevertToSelf()) Environment.FailFast("Could not restore host thread after impersonation");
        }
    }

    public object WaitForCleanExit(int timeoutMs) {
        if (process == IntPtr.Zero) throw new IOException("No held process");
        uint wait = WaitForSingleObject(process, (uint)timeoutMs);
        bool timedOut = (wait != WaitSignaled);
        if (timedOut) {
            TerminateProcess(process, CleanupExit);
            wait = WaitForSingleObject(process, 3000);
        }
        uint threadWait = WaitForSingleObject(thread, 1000);
        uint code;
        Require(GetExitCodeProcess(process, out code), "GetExitCodeProcess");
        return new {
            exitCode = code,
            timedOut = timedOut,
            processSignaled = wait == WaitSignaled,
            threadSignaled = threadWait == WaitSignaled,
            resumeCalls = ResumeCalls
        };
    }

    public object TerminateAndWait() {
        if (process == IntPtr.Zero) throw new IOException("No held process to terminate");
        if (WaitForSingleObject(process, 0) != WaitTimeout) {
            uint existingCode;
            GetExitCodeProcess(process, out existingCode);
            return new {
                exitCode = existingCode,
                expectedExitCode = CleanupExit,
                alreadyExited = true,
                processSignaled = true,
                threadSignaled = WaitForSingleObject(thread, 1000) == WaitSignaled,
                resumeCalls = ResumeCalls
            };
        }
        Require(TerminateProcess(process, CleanupExit), "TerminateProcess");
        uint wait = WaitForSingleObject(process, 3000);
        uint threadWait = WaitForSingleObject(thread, 1000);
        uint code;
        Require(GetExitCodeProcess(process, out code), "GetExitCodeProcess");
        return new {
            exitCode = code,
            expectedExitCode = CleanupExit,
            alreadyExited = false,
            processSignaled = wait == WaitSignaled,
            threadSignaled = threadWait == WaitSignaled,
            resumeCalls = ResumeCalls
        };
    }

    public void Dispose() {
        if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; }
        if (process != IntPtr.Zero) {
            if (WaitForSingleObject(process, 100) == WaitTimeout) TerminateProcess(process, CleanupExit);
            WaitForSingleObject(process, 3000);
            CloseHandle(process);
            process = IntPtr.Zero;
        }
        if (thread != IntPtr.Zero) { CloseHandle(thread); thread = IntPtr.Zero; }
    }
}
