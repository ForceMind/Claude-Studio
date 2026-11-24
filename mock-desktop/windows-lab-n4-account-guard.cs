using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

public sealed partial class StudioLabWfp
{
    const string AccountGuardName = "Studio mock N4 account guard";
    const string AccountLoopbackCapability = "S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225";

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct AccountProcessEntry
    {
        public uint Size, Usage, ProcessId;
        public UIntPtr HeapId;
        public uint ModuleId, Threads, ParentId;
        public int BasePriority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Executable;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint process);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Process32FirstW(IntPtr snapshot, ref AccountProcessEntry entry);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Process32NextW(IntPtr snapshot, ref AccountProcessEntry entry);

    public static Dictionary<int,int> ReadAccountProcessParents()
    {
        var parents = new Dictionary<int,int>();
        IntPtr snapshot = CreateToolhelp32Snapshot(2, 0);
        if (snapshot == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception();
        try {
            var entry = new AccountProcessEntry { Size = (uint)Marshal.SizeOf(typeof(AccountProcessEntry)) };
            if (!Process32FirstW(snapshot, ref entry)) throw new System.ComponentModel.Win32Exception();
            do { parents.Add((int)entry.ProcessId, (int)entry.ParentId); }
            while (Process32NextW(snapshot, ref entry));
            if (Marshal.GetLastWin32Error() != 18) throw new System.ComponentModel.Win32Exception();
            return parents;
        } finally { CloseHandle(snapshot); }
    }

    // Keep the process handle alive in the caller until it has consumed the observation.
    // The receipt selects a candidate, while the handle supplies the independent identity.
    public static void ValidateAccountProbe(Process process, long startTicks, int session,
        string executable, string account, string package)
    {
        if (process == null || startTicks <= 0 || session <= 0 || String.IsNullOrEmpty(executable) ||
            !new SecurityIdentifier(account).IsAccountSid()) throw new ArgumentException("Invalid expected N4 process identity");
        bool container = !String.IsNullOrEmpty(package);
        if (container) ValidateContainerSid(package);
        IntPtr handle = process.Handle;
        if (process.HasExited || process.StartTime.ToUniversalTime().Ticks != startTicks || process.SessionId != session ||
            !String.Equals(process.MainModule.FileName, executable, StringComparison.OrdinalIgnoreCase))
            throw new IOException("N4 live process identity changed");

        IntPtr token;
        if (!OpenProcessToken(handle, 8, out token)) throw new System.ComponentModel.Win32Exception();
        try {
            using (var identity = new WindowsIdentity(token)) {
                if (identity.User.Value != account || identity.Groups.Any(g => g.Value == "S-1-5-32-544"))
                    throw new IOException("N4 probe must use the exact standard A token");
            }
            IntPtr data = Marshal.AllocHGlobal(IntPtr.Size);
            try {
                int required;
                if (!GetTokenInformation(token, 29, data, IntPtr.Size, out required) ||
                    Marshal.ReadInt32(data) != (container ? 1 : 0)) throw new IOException("N4 AppContainer mode differs");
                if (container) {
                    if (!GetTokenInformation(token, 31, data, IntPtr.Size, out required) || Marshal.ReadIntPtr(data) == IntPtr.Zero ||
                        new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value != package) throw new IOException("N4 AppContainer SID differs");
                    VerifyAccountLoopbackCapabilities(token);
                }
            } finally { Marshal.FreeHGlobal(data); }
            if (process.HasExited) throw new IOException("N4 identity source exited during observation");
        } finally { CloseHandle(token); }
    }

    static void VerifyAccountLoopbackCapabilities(IntPtr token)
    {
        int bytes;
        if (GetTokenInformation(token, 30, IntPtr.Zero, 0, out bytes) || Marshal.GetLastWin32Error() != 122 ||
            bytes < IntPtr.Size || bytes > 65536) throw new IOException("Invalid N4 network capability size");
        IntPtr data = Marshal.AllocHGlobal(bytes);
        try {
            int read;
            if (!GetTokenInformation(token, 30, data, bytes, out read) || read < IntPtr.Size || read > bytes)
                throw new IOException("Cannot read N4 network capabilities");
            int count = Marshal.ReadInt32(data);
            if (count < 0 || count > (read - IntPtr.Size) / (2 * IntPtr.Size)) throw new IOException("Invalid N4 capability array");
            int loopback = 0;
            for (int i = 0; i < count; i++) {
                string sid = new SecurityIdentifier(Marshal.ReadIntPtr(data, IntPtr.Size + i * 2 * IntPtr.Size)).Value;
                if (sid == "S-1-15-3-1" || sid == "S-1-15-3-2" || sid == "S-1-15-3-3")
                    throw new IOException("N4 probe has an unapproved network capability");
                if (sid == AccountLoopbackCapability) loopback++;
            }
            if (loopback != 1) throw new IOException("N4 probe lacks the exact loopback network capability");
        } finally { Marshal.FreeHGlobal(data); }
    }

    public sealed class AccountGuardSpec
    {
        internal readonly SecurityIdentifier UserSid;
        internal readonly SecurityIdentifier PackageSid;
        internal readonly Guid SublayerKey;
        internal readonly Guid[] RuleKeys;
        internal readonly ushort SublayerWeight;
        internal readonly ushort ProxyPort;

        public AccountGuardSpec(string userSid, string packageSid, Guid sublayerKey,
            Guid[] ruleKeys, ushort sublayerWeight, ushort proxyPort)
        {
            UserSid = new SecurityIdentifier(userSid);
            if (!UserSid.IsAccountSid() || UserSid.Value != userSid)
                throw new ArgumentException("Expected a canonical account SID");
            if (!String.IsNullOrEmpty(packageSid)) {
                ValidateContainerSid(packageSid);
                PackageSid = new SecurityIdentifier(packageSid);
                if (PackageSid.Value != packageSid || proxyPort < 40000 || proxyPort >= 49152)
                    throw new ArgumentException("Expected an exact container SID and dedicated proxy port");
            } else if (proxyPort != 0) {
                throw new ArgumentException("A deny-only scope cannot name a proxy port");
            }
            if (ruleKeys == null || ruleKeys.Length != (PackageSid == null ? 4 : 5) ||
                sublayerKey == Guid.Empty || sublayerWeight == 0)
                throw new ArgumentException("Invalid account guard scope");
            var distinct = new HashSet<Guid> { Guid.Empty, sublayerKey };
            foreach (Guid key in ruleKeys)
                if (!distinct.Add(key)) throw new ArgumentException("Duplicate or empty object key");
            SublayerKey = sublayerKey;
            RuleKeys = (Guid[])ruleKeys.Clone();
            SublayerWeight = sublayerWeight;
            ProxyPort = proxyPort;
        }

        internal byte[] UserDescriptor()
        {
            var descriptor = new RawSecurityDescriptor("D:P(A;;0x1;;;" + UserSid.Value + ")");
            var bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            return bytes;
        }
    }

    static Condition[] AccountConditions(AccountGuardSpec spec, int index, IntPtr descriptor, IntPtr package)
    {
        var user = Match(User, Equal, SecurityDescriptor, unchecked((ulong)descriptor.ToInt64()));
        if (index < 4) return new[] { user };
        return new[] {
            user, Match(Package, Equal, SidValue, unchecked((ulong)package.ToInt64())),
            Match(Protocol, Equal, Byte, 6), Match(RemoteAddress, Equal, UInt, 0x7f000001),
            Match(RemotePort, Equal, UShort, spec.ProxyPort)
        };
    }

    static Filter AccountFilter(AccountGuardSpec spec, int index)
    {
        return new Filter {
            Key = spec.RuleKeys[index], Layer = StaticLayer(index), Sublayer = spec.SublayerKey,
            Display = new Display { Name = AccountGuardName + " " + StaticRuleNames[index] },
            Action = new Action { Type = index == 4 ? StaticPermit : ActionBlock },
            Flags = 0, ConditionCount = index == 4 ? 5U : 1U
        };
    }

    // Pure preview. It does not open an engine session or load a package.
    public static object PreviewAccountGuard(AccountGuardSpec spec)
    {
        var rows = new List<object>();
        for (int i = 0; i < spec.RuleKeys.Length; i++) {
            var filter = AccountFilter(spec, i);
            var conditions = AccountConditions(spec, i, IntPtr.Zero, IntPtr.Zero).Select(c => {
                object value = c.Value.Data;
                if (c.Field == User) value = Convert.ToBase64String(spec.UserDescriptor());
                if (c.Field == Package) value = spec.PackageSid.Value;
                return new { field = c.Field, match = c.Match, type = c.Value.Type, value = value };
            }).ToArray();
            rows.Add(new { key = filter.Key, layer = filter.Layer, sublayer = filter.Sublayer,
                flags = filter.Flags, action = filter.Action.Type,
                weight = i == 4 ? StaticAllowWeight : StaticDenyWeight,
                lifetime = i == 4 ? "dynamic-session" : "static", conditions = conditions });
        }
        return rows.ToArray();
    }

    void AddAccountRule(AccountGuardSpec spec, int index)
    {
        byte[] descriptor = spec.UserDescriptor();
        IntPtr sd = IntPtr.Zero, blob = IntPtr.Zero, package = IntPtr.Zero;
        IntPtr conditions = IntPtr.Zero, weight = IntPtr.Zero;
        try {
            sd = Marshal.AllocHGlobal(descriptor.Length);
            Marshal.Copy(descriptor, 0, sd, descriptor.Length);
            blob = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Blob)));
            Marshal.StructureToPtr(new Blob { Size = (uint)descriptor.Length, Data = sd }, blob, false);
            if (index == 4) package = AllocateStaticSid(spec.PackageSid.Value);
            Condition[] wanted = AccountConditions(spec, index, blob, package);
            int size = Marshal.SizeOf(typeof(Condition));
            conditions = Marshal.AllocHGlobal(wanted.Length * size);
            for (int i = 0; i < wanted.Length; i++)
                Marshal.StructureToPtr(wanted[i], IntPtr.Add(conditions, i * size), false);
            weight = Marshal.AllocHGlobal(sizeof(ulong));
            Marshal.WriteInt64(weight, (long)(index == 4 ? StaticAllowWeight : StaticDenyWeight));
            Filter filter = AccountFilter(spec, index);
            filter.Conditions = conditions;
            filter.Weight = new Value { Type = StaticUInt64, Data = unchecked((ulong)weight.ToInt64()) };
            ulong id;
            Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id), "add N4 account filter");
        } finally {
            foreach (IntPtr address in new[] { weight, conditions, package, blob, sd })
                if (address != IntPtr.Zero) Marshal.FreeHGlobal(address);
        }
    }

    void VerifyAccountFilter(Filter actual, AccountGuardSpec spec, int index)
    {
        Filter expected = AccountFilter(spec, index);
        ulong weight = index == 4 ? StaticAllowWeight : StaticDenyWeight;
        if (actual.Key != expected.Key || actual.Layer != expected.Layer || actual.Sublayer != expected.Sublayer ||
            actual.Display.Name != expected.Display.Name || !String.IsNullOrEmpty(actual.Display.Description) ||
            actual.Action.Type != expected.Action.Type || actual.Action.Key != Guid.Empty ||
            (actual.Flags & ~0x40U) != 0 || actual.Id == 0 ||
            actual.Provider != IntPtr.Zero || actual.ProviderData.Size != 0 || actual.ProviderData.Data != IntPtr.Zero ||
            actual.Context.Raw != 0 || actual.Reserved != IntPtr.Zero ||
            ReadStaticWeight(actual.Weight) != weight || ReadStaticWeight(actual.EffectiveWeight) != weight ||
            actual.ConditionCount != expected.ConditionCount || actual.Conditions == IntPtr.Zero)
            throw new IOException("N4 account filter differs from the manifest");

        var missing = AccountConditions(spec, index, IntPtr.Zero, IntPtr.Zero).ToList();
        int size = Marshal.SizeOf(typeof(Condition));
        for (int i = 0; i < actual.ConditionCount; i++) {
            var c = (Condition)Marshal.PtrToStructure(IntPtr.Add(actual.Conditions, i * size), typeof(Condition));
            int expectedIndex = missing.FindIndex(x => x.Field == c.Field && x.Match == c.Match && x.Value.Type == c.Value.Type);
            if (expectedIndex < 0) throw new IOException("Unexpected or duplicate N4 account condition");
            var want = missing[expectedIndex];
            missing.RemoveAt(expectedIndex);
            if (c.Field == User) {
                if (c.Value.Data == 0) throw new IOException("Missing account security descriptor");
                var blob = (Blob)Marshal.PtrToStructure(new IntPtr(unchecked((long)c.Value.Data)), typeof(Blob));
                byte[] sd = spec.UserDescriptor();
                if (blob.Size != sd.Length || blob.Data == IntPtr.Zero) throw new IOException("Wrong account descriptor size");
                var bytes = new byte[sd.Length];
                Marshal.Copy(blob.Data, bytes, 0, bytes.Length);
                if (!bytes.SequenceEqual(sd)) throw new IOException("Wrong account descriptor");
            } else if (c.Field == Package) {
                if (c.Value.Data == 0 || !spec.PackageSid.Equals(new SecurityIdentifier(new IntPtr(unchecked((long)c.Value.Data)))))
                    throw new IOException("Wrong package SID");
            } else {
                ulong mask = c.Value.Type == Byte ? 0xffUL : c.Value.Type == UShort ? 0xffffUL : 0xffffffffUL;
                if ((c.Value.Data & mask) != want.Value.Data) throw new IOException("Wrong proxy endpoint condition");
            }
        }
    }

    // Can be called from a separate read session. The caller owns the approved
    // lifecycle and must keep the host identity and run manifest outside A.
    bool[] ReadAccountGuard(AccountGuardSpec spec, bool requireBase, bool allowException)
    {
        Guid sublayer = spec.SublayerKey;
        IntPtr raw;
        uint status = FwpmSubLayerGetByKey0(engine, ref sublayer, out raw);
        bool present = status != SublayerMissing;
        try {
            if (present) {
                Check(status, "read N4 account sublayer");
                var layer = (Sublayer)Marshal.PtrToStructure(raw, typeof(Sublayer));
                if (layer.Key != sublayer || layer.Display.Name != AccountGuardName ||
                    !String.IsNullOrEmpty(layer.Display.Description) || layer.Flags != 0 ||
                    layer.Weight != spec.SublayerWeight || layer.Provider != IntPtr.Zero ||
                    layer.ProviderData.Size != 0 || layer.ProviderData.Data != IntPtr.Zero)
                    throw new IOException("N4 account sublayer differs from the manifest");
            } else if (requireBase) throw new IOException("N4 account sublayer missing");
        } finally { if (raw != IntPtr.Zero) FwpmFreeMemory0(ref raw); }

        var found = new bool[spec.RuleKeys.Length + 1];
        found[0] = present;
        for (int i = 0; i < spec.RuleKeys.Length; i++) {
            Guid key = spec.RuleKeys[i];
            status = FwpmFilterGetByKey0(engine, ref key, out raw);
            try {
                if (status == FilterMissing) {
                    if (requireBase && i < 4) throw new IOException("Required N4 account deny is missing");
                    continue;
                }
                Check(status, "read N4 account filter");
                if (!present || (i == 4 && !allowException)) throw new IOException("Unexpected N4 account rule present");
                VerifyAccountFilter((Filter)Marshal.PtrToStructure(raw, typeof(Filter)), spec, i);
                found[i + 1] = true;
            } finally { if (raw != IntPtr.Zero) FwpmFreeMemory0(ref raw); }
        }
        VerifyNoUnlistedStaticFilters(sublayer, spec.RuleKeys);
        return found;
    }

    public static bool[] InspectAccountGuard(AccountGuardSpec spec, bool requireBase, bool allowException)
    {
        using (var reader = CreateStaticGuard())
            return reader.StaticSnapshot(() => reader.ReadAccountGuard(spec, requireBase, allowException));
    }

    public static ushort ReadAccountGuardWeight()
    {
        // Advisory for preparation. Installation repeats this check inside its write transaction.
        using (var reader = CreateStaticGuard())
            return reader.SelectContainerWeight(null, null);
    }

    public static ushort[] ReadAccountBatchWeights(ushort[] ports)
    {
        if (ports == null || ports.Length != 4 || ports.Distinct().Count() != 4 ||
            ports.Any(port => port < 40000 || port >= 49152)) throw new ArgumentException("Expected four distinct batch ports");
        using (var reader = CreateStaticGuard()) {
            ushort account = reader.SelectContainerWeight(null, null);
            ushort bindF = reader.CheckBindPriority(Guid.Empty, 0, new[] { ports[0], ports[1] }, account);
            ushort bindX = reader.CheckBindPriority(Guid.Empty, 0, new[] { ports[2], ports[3] }, account);
            return new[] { account, bindF, bindX };
        }
    }

    public static ushort[] ReadAccountProxyStageWeights(ushort[] ports)
    {
        if (ports == null || ports.Length != 2 || ports[0] == ports[1] ||
            ports.Any(port => port < 40000 || port >= 49152)) throw new ArgumentException("Expected two distinct stage ports");
        using (var reader = CreateStaticGuard()) {
            ushort account = reader.SelectContainerWeight(null, null);
            return new[] { account, reader.CheckBindPriority(Guid.Empty, 0, ports, account) };
        }
    }

    public static object ReadAccountPriorityExplanation()
    {
        using (var reader = CreateStaticGuard()) {
            ushort? weight = null;
            string reason = null;
            try { weight = reader.SelectContainerWeight(null, null); }
            catch (InvalidOperationException exception) { reason = exception.Message; }
            var candidates = reader.PriorityEvidence.Where(row => (bool)row["requiresHigherPriority"]).ToArray();
            int maximum = candidates.Length == 0 ? 0 : candidates.Max(row => (int)(ushort)row["sublayerWeight"]);
            return new Dictionary<string,object> {
                {"candidateWeight",weight}, {"reason",reason}, {"highestCompetingWeight",maximum},
                {"highestCompetingCount",candidates.Count(row => (ushort)row["sublayerWeight"] == maximum)},
                {"highestCompetingFilters",candidates.Where(row => (ushort)row["sublayerWeight"] == maximum).Take(16).ToArray()}
            };
        }
    }

    static string ReadExactAccountAppId(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) throw new IOException("Missing application ID blob");
        var blob = (Blob)Marshal.PtrToStructure(pointer, typeof(Blob));
        if (blob.Size < 2 || blob.Size > 65536 || (blob.Size & 1) != 0 || blob.Data == IntPtr.Zero)
            throw new IOException("Invalid application ID blob size");
        var bytes = new byte[blob.Size];
        Marshal.Copy(blob.Data, bytes, 0, bytes.Length);
        string path = new System.Text.UnicodeEncoding(false, false, true).GetString(bytes).TrimEnd('\0');
        if (!path.StartsWith("\\device\\", StringComparison.OrdinalIgnoreCase) || path.IndexOf('\0') >= 0)
            throw new IOException("Application ID is not a single NT device path");
        return path;
    }

    public static string ReadAccountExecutableAppId(string executable)
    {
        IntPtr value;
        Check(FwpmGetAppIdFromFileName0(executable, out value), "read candidate application ID");
        try { return ReadExactAccountAppId(value); }
        finally { if (value != IntPtr.Zero) FwpmFreeMemory0(ref value); }
    }

    // Diagnostic only. This observation never excludes a rule from the priority gate.
    public static object[] ReadAccountPermitConditions(Guid[] filterKeys)
    {
        if (filterKeys == null || filterKeys.Length != 2 || filterKeys[0] == filterKeys[1] || filterKeys.Contains(Guid.Empty))
            throw new ArgumentException("Expected the two competing permit keys");
        var rows = new List<object>();
        using (var reader = CreateStaticGuard()) {
            foreach (Guid item in filterKeys) {
                Guid key = item;
                IntPtr stored;
                Check(FwpmFilterGetByKey0(reader.engine, ref key, out stored), "read exact competing permit");
                try {
                    var filter = (Filter)Marshal.PtrToStructure(stored, typeof(Filter));
                    if (filter.Key != key || !Connect.Contains(filter.Layer) || filter.Action.Type != StaticPermit ||
                        (filter.Flags & 8U) == 0 || filter.Display.Name != "sing-tun" || filter.ConditionCount != 1 ||
                        filter.Conditions == IntPtr.Zero) throw new IOException("Competing permit changed after enumeration");
                    var condition = (Condition)Marshal.PtrToStructure(filter.Conditions, typeof(Condition));
                    bool exactApp = condition.Field == ApplicationId && condition.Match == Equal && condition.Value.Type == 12;
                    rows.Add(new {
                        key, layer=filter.Layer, flags=filter.Flags, field=condition.Field, match=condition.Match, type=condition.Value.Type,
                        exactApp, devicePath=exactApp ? ReadExactAccountAppId(new IntPtr(unchecked((long)condition.Value.Data))) : null
                    });
                } finally { FwpmFreeMemory0(ref stored); }
            }
        }
        return rows.ToArray();
    }

    public void InstallAccountBase(AccountGuardSpec spec)
    {
        RequireStaticMode(2, 0);
        if (spec.RuleKeys.Length != 4) throw new ArgumentException("Install the base without a proxy exception");
        Transaction(() => {
            if (ReadAccountGuard(spec, false, false).Any(x => x)) throw new IOException("N4 account keys already exist");
            if (SelectContainerWeight(null, null) != spec.SublayerWeight)
                throw new IOException("Account-wide WFP priority changed after preparation");
            var layer = new Sublayer { Key = spec.SublayerKey, Weight = spec.SublayerWeight, Flags = 0,
                Display = new Display { Name = AccountGuardName } };
            Check(FwpmSubLayerAdd0(engine, ref layer, IntPtr.Zero), "add N4 account sublayer");
            for (int i = 0; i < 4; i++) AddAccountRule(spec, i);
        });
    }

    public void InstallAccountBindings(AccountGuardSpec spec, Guid[] exceptionKeys,
        Guid bindSublayer, Guid[] bindKeys, ushort[] bindPorts, ushort bindWeight)
    {
        RequireStaticMode(2, 0);
        ValidateAccountRecovery(spec, exceptionKeys, bindSublayer, bindKeys, bindPorts, bindWeight);
        if (bindSublayer == Guid.Empty) throw new ArgumentException("Binding is outside this account stage");
        Transaction(() => {
            ReadAccountGuard(spec, true, false);
            VerifyAccountExceptionsAbsent(exceptionKeys);
            VerifyStaticAbsentOnEngine(bindSublayer, bindKeys);
            CheckBindPriority(bindSublayer, bindWeight, bindPorts);
            var sub = new Sublayer { Key=bindSublayer, Weight=bindWeight, Display=new Display { Name=BindGuardName } };
            Check(FwpmSubLayerAdd0(engine, ref sub, IntPtr.Zero), "add N4 TCP binding sublayer");
            for (int i = 0; i < bindKeys.Length; i++) AddBindDeny(bindSublayer, bindKeys[i], bindPorts[i/2], i%2);
            ReadBindGuard(bindSublayer, bindKeys, bindPorts, bindWeight, 2, false);
        });
    }

    public static void ValidateBoundAccountProxy(AccountGuardSpec spec,
        Guid bindSublayer, Guid[] bindKeys, ushort[] bindPorts, ushort bindWeight)
    {
        if (spec.PackageSid == null || bindPorts == null || bindPorts.Length != 2 || spec.ProxyPort != bindPorts[0])
            throw new ArgumentException("Proxy requires runtime container identity and the reviewed entry port");
        var baseSpec = new AccountGuardSpec(spec.UserSid.Value, null, spec.SublayerKey,
            spec.RuleKeys.Take(4).ToArray(), spec.SublayerWeight, 0);
        ValidateAccountRecovery(baseSpec, new[] { spec.RuleKeys[4] }, bindSublayer, bindKeys, bindPorts, bindWeight);
    }

    public void OpenAccountProxy(AccountGuardSpec spec,
        Guid bindSublayer, Guid[] bindKeys, ushort[] bindPorts, ushort bindWeight)
    {
        RequireStaticMode(3, 1);
        ValidateBoundAccountProxy(spec, bindSublayer, bindKeys, bindPorts, bindWeight);
        Transaction(() => {
            ReadAccountGuard(spec, true, false);
            ReadBindGuard(bindSublayer, bindKeys, bindPorts, bindWeight, 2, false);
            AddAccountRule(spec, 4);
        });
    }

    public static void VerifyBoundAccountProxy(AccountGuardSpec spec,
        Guid bindSublayer, Guid[] bindKeys, ushort[] bindPorts, ushort bindWeight, bool opened)
    {
        if (ReadBoundAccountProxy(spec, bindSublayer, bindKeys, bindPorts, bindWeight) != opened)
            throw new IOException("N4 exception state differs");
    }

    public static bool ReadBoundAccountProxy(AccountGuardSpec spec,
        Guid bindSublayer, Guid[] bindKeys, ushort[] bindPorts, ushort bindWeight)
    {
        ValidateBoundAccountProxy(spec, bindSublayer, bindKeys, bindPorts, bindWeight);
        using (var reader = CreateStaticGuard()) {
            return reader.StaticSnapshot(() => {
                bool[] rows = reader.ReadAccountGuard(spec, true, true);
                reader.ReadBindGuard(bindSublayer, bindKeys, bindPorts, bindWeight, 2, false);
                return rows[5];
            });
        }
    }

    // Caller must verify the dynamic owner and all lab workloads have exited.
    public static void RemoveAccountBase(AccountGuardSpec spec)
    {
        RemoveAccountStage(spec, new Guid[0], Guid.Empty, null, null, 0);
    }

    static void ValidateAccountRecovery(AccountGuardSpec spec, Guid[] exceptionKeys,
        Guid bindSublayer, Guid[] bindKeys, ushort[] bindPorts, ushort bindWeight)
    {
        if (spec.PackageSid != null || exceptionKeys == null)
            throw new ArgumentException("Recovery requires a deny-only scope and every reserved exception key");
        var keys = new HashSet<Guid>(spec.RuleKeys) { Guid.Empty, spec.SublayerKey };
        if (bindSublayer == Guid.Empty) {
            if (bindKeys != null || bindPorts != null || bindWeight != 0 || exceptionKeys.Length != 0)
                throw new ArgumentException("Deny-only recovery does not own proxy rules");
        } else {
            ValidateBindGuard(bindSublayer, bindKeys, bindPorts);
            if (bindWeight == 0 || bindWeight == spec.SublayerWeight || bindPorts.Length != 2 || (exceptionKeys.Length != 1 && exceptionKeys.Length != 4) ||
                !keys.Add(bindSublayer) || bindKeys.Any(key => !keys.Add(key)))
                throw new ArgumentException("Invalid integrated recovery scope");
        }
        if (exceptionKeys.Any(key => !keys.Add(key)))
            throw new ArgumentException("Recovery object keys must be distinct");
    }

    void VerifyAccountExceptionsAbsent(Guid[] keys)
    {
        foreach (Guid item in keys) {
            Guid key = item;
            IntPtr value;
            uint result = FwpmFilterGetByKey0(engine, ref key, out value);
            if (value != IntPtr.Zero) FwpmFreeMemory0(ref value);
            if (result == FilterMissing) continue;
            Check(result, "read N4 reserved dynamic key");
            throw new IOException("N4 reserved exception still exists; keep the default deny");
        }
    }

    // No removal takes place until BOTH sublayers match and dynamic E is gone.
    public static void RemoveAccountStage(AccountGuardSpec spec, Guid[] exceptionKeys,
        Guid bindSublayer, Guid[] bindKeys, ushort[] bindPorts, ushort bindWeight)
    {
        ValidateAccountRecovery(spec, exceptionKeys, bindSublayer, bindKeys, bindPorts, bindWeight);
        using (var remover = CreateStaticGuard()) {
            remover.Transaction(() => {
                remover.VerifyAccountExceptionsAbsent(exceptionKeys);
                bool[] found = remover.ReadAccountGuard(spec, false, false);
                if (bindSublayer != Guid.Empty)
                    remover.ReadBindGuard(bindSublayer, bindKeys, bindPorts, bindWeight, 0, true);

                if (bindSublayer != Guid.Empty) {
                    foreach (Guid key in bindKeys) remover.DeleteAccountRecoveryFilter(key);
                    remover.DeleteAccountRecoveryLayer(bindSublayer);
                }
                for (int i = 0; i < 4; i++)
                    if (found[i + 1]) remover.DeleteAccountRecoveryFilter(spec.RuleKeys[i]);
                if (found[0]) remover.DeleteAccountRecoveryLayer(spec.SublayerKey);
            });
        }
        VerifyAccountStageAbsent(spec, exceptionKeys, bindSublayer, bindKeys, bindPorts, bindWeight);
    }

    public static void VerifyAccountStageAbsent(AccountGuardSpec spec, Guid[] exceptionKeys,
        Guid bindSublayer, Guid[] bindKeys, ushort[] bindPorts, ushort bindWeight)
    {
        ValidateAccountRecovery(spec, exceptionKeys, bindSublayer, bindKeys, bindPorts, bindWeight);
        using (var reader = CreateStaticGuard()) {
            reader.StaticSnapshot(() => {
                reader.VerifyStaticAbsentOnEngine(spec.SublayerKey, spec.RuleKeys);
                reader.VerifyAccountExceptionsAbsent(exceptionKeys);
                if (bindSublayer != Guid.Empty) reader.VerifyStaticAbsentOnEngine(bindSublayer, bindKeys);
                return true;
            });
        }
    }

    void DeleteAccountRecoveryFilter(Guid key)
    {
        uint result = FwpmFilterDeleteByKey0(engine, ref key);
        if (result != FilterMissing) Check(result, "delete listed N4 filter");
    }

    void DeleteAccountRecoveryLayer(Guid key)
    {
        uint result = FwpmSubLayerDeleteByKey0(engine, ref key);
        if (result != SublayerMissing) Check(result, "delete listed N4 sublayer");
    }
}
