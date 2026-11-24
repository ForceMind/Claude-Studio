using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

public sealed partial class StudioLabWfp
{
    const string FixtureBindName = "Temporary A synthetic IPv4 bind verification";
    static byte[] FixtureDescriptor(string sid)
    {
        var user = new SecurityIdentifier(sid);
        if (!user.IsAccountSid() || user.Value != sid) throw new ArgumentException("Expected exact account SID");
        var descriptor = new RawSecurityDescriptor("D:P(A;;0x1;;;" + sid + ")");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    static byte[] FixtureReadBlob(IntPtr raw)
    {
        if (raw == IntPtr.Zero) throw new IOException("Missing condition blob");
        var blob = (Blob)Marshal.PtrToStructure(raw, typeof(Blob));
        if (blob.Size == 0 || blob.Size > 65536 || blob.Data == IntPtr.Zero)
            throw new IOException("Invalid condition blob");
        var bytes = new byte[blob.Size];
        Marshal.Copy(blob.Data, bytes, 0, bytes.Length);
        return bytes;
    }

    static ulong FixturePointer(IntPtr address) { return unchecked((ulong)address.ToInt64()); }

    public static StudioLabWfp OpenFixtureBindOwner() {
        return new StudioLabWfp(new ContainerSession {
            Flags = 1, TransactionWait = 2000, Display = new Display { Name = FixtureBindName }
        }) {containerMode=3};
    }

    public object InstallFixtureBind(Guid sub, Guid key, string sid, string executable)
    {
        RequireStaticMode(3, 1);
        if (sub == Guid.Empty || key == Guid.Empty || sub == key) throw new ArgumentException("Invalid fixture keys");
        byte[] descriptor = FixtureDescriptor(sid);
        IntPtr app = IntPtr.Zero, data = IntPtr.Zero, blob = IntPtr.Zero, conditions = IntPtr.Zero, filterWeight = IntPtr.Zero;
        ushort weight = 0;
        ulong id = 0;
        int existing = 0, competing = 0;
        try {
            Check(FwpmGetAppIdFromFileName0(executable, out app), "resolve exact synthetic application ID");
            ReadExactAccountAppId(app);
            data = Marshal.AllocHGlobal(descriptor.Length);
            Marshal.Copy(descriptor, 0, data, descriptor.Length);
            blob = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Blob)));
            Marshal.StructureToPtr(new Blob { Size = (uint)descriptor.Length, Data = data }, blob, false);
            var wanted = new[] { Match(User, Equal, SecurityDescriptor, FixturePointer(blob)),
                Match(ApplicationId, Equal, 12, FixturePointer(app)) };
            int stride = Marshal.SizeOf(typeof(Condition));
            conditions = Marshal.AllocHGlobal(wanted.Length * stride);
            for (int i = 0; i < wanted.Length; i++)
                Marshal.StructureToPtr(wanted[i], IntPtr.Add(conditions, i * stride), false);
            filterWeight = Marshal.AllocHGlobal(sizeof(ulong));
            Marshal.WriteInt64(filterWeight, (long)StaticDenyWeight);
            Transaction(() => {
                VerifyStaticAbsentOnEngine(sub, new[] { key });
                weight = ChooseFixtureBindWeight(out existing, out competing);
                var layer = new Sublayer { Key = sub, Display = new Display { Name = FixtureBindName }, Weight = weight };
                Check(FwpmSubLayerAdd0(engine, ref layer, IntPtr.Zero), "add temporary synthetic bind sublayer");
                var filter = new Filter {
                    Key = key, Layer = ResourceAssignment[0], Sublayer = sub, Display = layer.Display,
                    Action = new Action { Type = ActionBlock }, ConditionCount = (uint)wanted.Length, Conditions = conditions,
                    Weight = new Value { Type = StaticUInt64, Data = FixturePointer(filterWeight) }
                };
                Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id), "add temporary synthetic bind deny");
            });
            return new Dictionary<string, object> {
                {"id", id.ToString()}, {"weight", weight}, {"existingLayerFilters", existing}, {"highestPotentialCompetitor", competing}
            };
        } finally {
            if (app != IntPtr.Zero) FwpmFreeMemory0(ref app);
            foreach (IntPtr address in new[] { data, blob, conditions, filterWeight })
                if (address != IntPtr.Zero) Marshal.FreeHGlobal(address);
        }
    }

    public static string ReadFixtureBind(Guid sub, Guid key, string sid, string executable, ushort weight)
    {
        using (var reader = CreateStaticGuard()) return reader.StaticSnapshot(() => {
            IntPtr raw = IntPtr.Zero, app = IntPtr.Zero;
            try {
                Check(FwpmSubLayerGetByKey0(reader.engine, ref sub, out raw), "read temporary sublayer");
                var sublayer = (Sublayer)Marshal.PtrToStructure(raw, typeof(Sublayer));
                if (sublayer.Key != sub || sublayer.Weight != weight || sublayer.Flags != 0 ||
                    sublayer.Provider != IntPtr.Zero || sublayer.Display.Name != FixtureBindName)
                    throw new IOException("Unexpected synthetic bind sublayer");
                FwpmFreeMemory0(ref raw);
                Check(FwpmFilterGetByKey0(reader.engine, ref key, out raw), "read temporary filter");
                var filter = (Filter)Marshal.PtrToStructure(raw, typeof(Filter));
                if (filter.Key != key || filter.Sublayer != sub || filter.Layer != ResourceAssignment[0] ||
                    filter.Id == 0 || filter.Provider != IntPtr.Zero || filter.Display.Name != FixtureBindName ||
                    filter.Action.Type != ActionBlock || filter.Action.Key != Guid.Empty || (filter.Flags & ~0x40U) != 0 ||
                    filter.ConditionCount != 2 || filter.Conditions == IntPtr.Zero ||
                    ReadStaticWeight(filter.Weight) != StaticDenyWeight || ReadStaticWeight(filter.EffectiveWeight) != StaticDenyWeight)
                    throw new IOException("Unexpected synthetic bind filter");
                Check(FwpmGetAppIdFromFileName0(executable, out app), "resolve expected synthetic application ID");
                var expected = new Dictionary<Guid, byte[]> { { User, FixtureDescriptor(sid) }, { ApplicationId, FixtureReadBlob(app) } };
                int stride = Marshal.SizeOf(typeof(Condition));
                for (int i = 0; i < filter.ConditionCount; i++) {
                    var condition = (Condition)Marshal.PtrToStructure(IntPtr.Add(filter.Conditions, i * stride), typeof(Condition));
                    byte[] value;
                    if (!expected.TryGetValue(condition.Field, out value) || condition.Match != Equal ||
                        condition.Value.Type != (condition.Field == User ? SecurityDescriptor : 12U) ||
                        !value.SequenceEqual(FixtureReadBlob(new IntPtr(unchecked((long)condition.Value.Data)))))
                        throw new IOException("Unexpected bind match condition");
                    expected.Remove(condition.Field);
                }
                reader.VerifyNoUnlistedStaticFilters(sub, new[] { key });
                return filter.Id.ToString();
            } finally {
                if (raw != IntPtr.Zero) FwpmFreeMemory0(ref raw);
                if (app != IntPtr.Zero) FwpmFreeMemory0(ref app);
            }
        });
    }

    public static void VerifyFixtureBindAbsent(Guid sub, Guid key) {
        using (var reader = CreateStaticGuard())
            reader.StaticSnapshot(() => { reader.VerifyStaticAbsentOnEngine(sub, new[] { key }); return true; });
    }

    ushort ChooseFixtureBindWeight(out int existing, out int competing) {
        existing = 0; competing = 0;
        var occupied = new HashSet<ushort>();
        var weights = new Dictionary<Guid, ushort>();
        IntPtr enumeration;
        Check(FwpmSubLayerCreateEnumHandle0(engine,IntPtr.Zero,out enumeration), "enumerate bind sublayers");
        try {
            uint count;
            do {
                IntPtr entries;
                Check(FwpmSubLayerEnum0(engine,enumeration,256,out entries,out count), "read bind sublayers");
                try {
                    for (int i=0; i<count; i++) {
                        var sub = (Sublayer)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Sublayer));
                        weights.Add(sub.Key,sub.Weight);
                        occupied.Add(sub.Weight);
                    }
                } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
            } while(count != 0);
        } finally { FwpmSubLayerDestroyEnumHandle0(engine,enumeration); }

        int highest = 0;
        Check(FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out enumeration), "enumerate existing bind filters");
        try {
            uint count;
            do {
                IntPtr entries;
                Check(FwpmFilterEnum0(engine,enumeration,256,out entries,out count), "read existing bind filters");
                try {
                    for (int i=0; i<count; i++) {
                        var f = (Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Filter));
                        if (f.Layer != ResourceAssignment[0]) continue;
                        existing++;
                        if ((f.Flags & 0x20U) == 0 &&
                            ((f.Action.Type == StaticPermit && (f.Flags & 8U) != 0) || (f.Action.Type & 0x4000U) != 0))
                            highest = Math.Max(highest, weights[f.Sublayer]);
                    }
                } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
            } while(count != 0);
        } finally { FwpmFilterDestroyEnumHandle0(engine,enumeration); }

        competing = highest;
        int chosen = UInt16.MaxValue;
        while (chosen > highest && occupied.Contains((ushort)chosen)) chosen--;
        if (chosen <= highest) throw new IOException("No available IPv4 bind sublayer above potential competitors");
        return (ushort)chosen;
    }
}