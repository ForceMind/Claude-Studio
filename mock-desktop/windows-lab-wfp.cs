using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

// Windows SDK filter structures and constants from fwpmtypes.h, fwptypes.h and fwpmu.h.
public sealed partial class StudioLabWfp : IDisposable
{
    private static readonly Guid User = new Guid("af043a0a-b34d-4f86-979c-c90371af6e66");
    private static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    private static readonly Guid Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    private static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    private static readonly Guid LocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
    private static readonly Guid[] Connect = {new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")};
    private static readonly Guid[] Accept = {new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f")};
    private static readonly Guid[] Listen = {new Guid("88bb5dad-76d7-4227-9c71-df0a3ed7be7e"), new Guid("7ac9de24-17dd-4814-b4bd-a9fbc95a321b")};
    private const uint Persistent = 1, ActionBlock = 0x1001, FilterMissing = 0x80320003, SublayerMissing = 0x80320007;
    private const uint Equal = 0, NotEqual = 10, Byte = 1, UShort = 2, UInt = 3, Array16 = 11, SecurityDescriptor = 14;
    public const int FilterCount = 20;
    private IntPtr engine;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Display { public string Name, Description; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Value { public uint Type; public ulong Data; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Condition { public Guid Field; public uint Match; public Value Value; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Action { public uint Type; public Guid Key; }
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct Context { [FieldOffset(0)] public ulong Raw; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Filter {
        public Guid Key; public Display Display; public uint Flags; public IntPtr Provider;
        public Blob ProviderData; public Guid Layer, Sublayer; public Value Weight;
        public uint ConditionCount; public IntPtr Conditions; public Action Action;
        public Context Context; public IntPtr Reserved; public ulong Id; public Value EffectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Sublayer {
        public Guid Key; public Display Display; public uint Flags; public IntPtr Provider;
        public Blob ProviderData; public ushort Weight;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProviderDisplay { public Guid Key; public Display Display; }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string server, uint authentication, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer layer, IntPtr security);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr layer);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterGetById0(IntPtr engine, ulong id, out IntPtr filter);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmProviderGetByKey0(IntPtr engine, ref Guid key, out IntPtr provider);
    [DllImport("fwpuclnt.dll")] private static extern void FwpmFreeMemory0(ref IntPtr value);

    public StudioLabWfp() {
        if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(Filter)) != 200 || Marshal.SizeOf(typeof(Condition)) != 40)
            throw new InvalidOperationException("Unexpected Windows SDK ABI");
        Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine), "open WFP");
    }
    private static void Check(uint result, string operation) {
        if (result != 0) throw new IOException(operation + ": 0x" + result.ToString("X8"));
    }
    private void Transaction(System.Action action) {
        Check(FwpmTransactionBegin0(engine, 0), "begin WFP transaction");
        try { action(); Check(FwpmTransactionCommit0(engine), "commit WFP transaction"); }
        catch { FwpmTransactionAbort0(engine); throw; }
    }
    private static Condition Match(Guid field, uint match, uint type, ulong data) {
        return new Condition {Field = field, Match = match, Value = new Value {Type = type, Data = data}};
    }
    private void Block(Guid key, Guid layer, Guid sublayer, Condition[] conditions) {
        if (conditions.Length == 0 || conditions[0].Field != User)
            throw new InvalidOperationException("Refusing to install a rule without a lab identity");
        int size = Marshal.SizeOf(typeof(Condition));
        IntPtr native = Marshal.AllocHGlobal(size * conditions.Length);
        try {
            for (int i = 0; i < conditions.Length; i++) Marshal.StructureToPtr(conditions[i], IntPtr.Add(native, i * size), false);
            var filter = new Filter {Key = key, Layer = layer, Sublayer = sublayer, Flags = Persistent,
                Display = new Display {Name = "Claude Studio synthetic lab only"}, Action = new Action {Type = ActionBlock},
                ConditionCount = (uint)conditions.Length, Conditions = native};
            ulong id;
            Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id), "add lab block " + layer);
        } finally { Marshal.FreeHGlobal(native); }
    }
    public void Install(Guid sublayer, Guid[] keys, string[] accounts, ushort port) {
        if (accounts.Length != 2 || accounts[0] == accounts[1] || keys.Length != FilterCount || port < 49152)
            throw new ArgumentException("Expected two distinct lab SIDs and a dedicated ephemeral port");
        Transaction(() => {
            var sub = new Sublayer {Key = sublayer, Weight = 0x100, Flags = Persistent,
                Display = new Display {Name = "Claude Studio temporary two-account verification"}};
            Check(FwpmSubLayerAdd0(engine, ref sub, IntPtr.Zero), "add lab sublayer");
            IntPtr mapped = Marshal.AllocHGlobal(16);
            try {
                Marshal.Copy(IPAddress.Loopback.MapToIPv6().GetAddressBytes(), 0, mapped, 16);
                int index = 0;
                foreach (string account in accounts) {
                    var sid = new SecurityIdentifier(account);
                    if (!sid.IsAccountSid()) throw new ArgumentException("Expected a local account SID");
                    var descriptor = new RawSecurityDescriptor("D:P(A;;0x1;;;" + sid.Value + ")");
                    var bytes = new byte[descriptor.BinaryLength];
                    descriptor.GetBinaryForm(bytes, 0);
                    IntPtr sd = Marshal.AllocHGlobal(bytes.Length);
                    IntPtr blob = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Blob)));
                    try {
                        Marshal.Copy(bytes, 0, sd, bytes.Length);
                        Marshal.StructureToPtr(new Blob {Size = (uint)bytes.Length, Data = sd}, blob, false);
                        var user = Match(User, Equal, SecurityDescriptor, (ulong)blob.ToInt64());
                        for (int family = 0; family < 2; family++) {
                            var addr = Match(RemoteAddress, NotEqual, family == 0 ? UInt : Array16,
                                family == 0 ? 0x7f000001UL : (ulong)mapped.ToInt64());
                            // The OR of the three blocks is the complement of one TCP endpoint.
                            Block(keys[index++], Connect[family], sublayer, new[] {user, addr});
                            Block(keys[index++], Connect[family], sublayer, new[] {user, Match(Protocol, NotEqual, Byte, 6)});
                            Block(keys[index++], Connect[family], sublayer, new[] {user, Match(RemotePort, NotEqual, UShort, port)});
                            Block(keys[index++], Accept[family], sublayer, new[] {user});
                            Block(keys[index++], Listen[family], sublayer, new[] {user, Match(LocalPort, Equal, UShort, port)});
                        }
                    } finally { Marshal.FreeHGlobal(blob); Marshal.FreeHGlobal(sd); }
                }
            } finally { Marshal.FreeHGlobal(mapped); }
        });
    }
    public void Verify(Guid sublayer, Guid[] keys, bool present) {
        foreach (Guid item in keys) {
            Guid key = item; IntPtr value;
            uint status = FwpmFilterGetByKey0(engine, ref key, out value);
            if (!present && status == FilterMissing) continue;
            Check(status, "read back lab filter");
            try {
                var entry = (Filter)Marshal.PtrToStructure(value, typeof(Filter));
                var user = (Condition)Marshal.PtrToStructure(entry.Conditions, typeof(Condition));
                if (!present || entry.Sublayer != sublayer || entry.Action.Type != ActionBlock ||
                    (entry.Flags & Persistent) == 0 || user.Field != User || user.Value.Type != SecurityDescriptor)
                    throw new IOException("Unexpected lab filter: " + key);
            } finally { FwpmFreeMemory0(ref value); }
        }
        IntPtr sub;
        uint subStatus = FwpmSubLayerGetByKey0(engine, ref sublayer, out sub);
        if (!present && subStatus == SublayerMissing) return;
        Check(subStatus, "read back lab sublayer");
        FwpmFreeMemory0(ref sub);
        if (!present) throw new IOException("Lab sublayer is still installed");
    }
    public void Remove(Guid sublayer, Guid[] keys) {
        Transaction(() => {
            foreach (Guid item in keys) {
                Guid key = item;
                uint result = FwpmFilterDeleteByKey0(engine, ref key);
                if (result != FilterMissing) Check(result, "delete lab filter");
            }
            uint deleted = FwpmSubLayerDeleteByKey0(engine, ref sublayer);
            if (deleted != SublayerMissing) Check(deleted, "delete lab sublayer");
        });
        Verify(sublayer, keys, false);
    }
    public Dictionary<string,string> Describe(ulong id) {
        IntPtr filter;
        Check(FwpmFilterGetById0(engine, id, out filter), "look up WFP event filter");
        try {
            var rule = (Filter)Marshal.PtrToStructure(filter, typeof(Filter));
            var result = new Dictionary<string,string> {
                {"filterId", id.ToString()}, {"filterKey", rule.Key.ToString()}, {"name", rule.Display.Name},
                {"layer", rule.Layer.ToString()}, {"sublayerKey", rule.Sublayer.ToString()},
                {"action", "0x" + rule.Action.Type.ToString("X")}, {"actionKey", rule.Action.Key.ToString()},
                {"conditionCount", rule.ConditionCount.ToString()}
            };
            IntPtr layer;
            if (FwpmSubLayerGetByKey0(engine, ref rule.Sublayer, out layer) == 0) {
                try { result["sublayer"] = ((Sublayer)Marshal.PtrToStructure(layer, typeof(Sublayer))).Display.Name; }
                finally { FwpmFreeMemory0(ref layer); }
            }
            if (rule.Provider != IntPtr.Zero) {
                Guid key = (Guid)Marshal.PtrToStructure(rule.Provider, typeof(Guid));
                result["providerKey"] = key.ToString();
                IntPtr provider;
                if (FwpmProviderGetByKey0(engine, ref key, out provider) == 0) {
                    try { result["provider"] = ((ProviderDisplay)Marshal.PtrToStructure(provider, typeof(ProviderDisplay))).Display.Name; }
                    finally { FwpmFreeMemory0(ref provider); }
                }
            }
            return result;
        } finally { FwpmFreeMemory0(ref filter); }
    }
    public void Dispose() {
        if (engine != IntPtr.Zero) FwpmEngineClose0(engine);
        engine = IntPtr.Zero;
    }
}
