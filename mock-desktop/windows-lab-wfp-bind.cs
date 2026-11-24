using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

public sealed partial class StudioLabWfp
{
    const string BindGuardName = "Studio mock N2 TCP bind guard";
    static readonly Guid[] ResourceAssignment = {
        new Guid("1247d66d-0b60-4a15-8d44-7155d0f53a0c"),
        new Guid("55a650e1-5f0a-4eca-a653-88f53b26aa8c")
    };

    public static void ValidateBindGuard(Guid sublayer, Guid[] keys, ushort[] ports) {
        if (sublayer == Guid.Empty || ports == null || ports.Length < 1 || ports.Length > 2 ||
            keys == null || keys.Length != ports.Length * 2)
            throw new ArgumentException("Expected one or two dedicated N2 TCP ports and two keys per port");
        var unique = new HashSet<Guid> { Guid.Empty, sublayer };
        foreach (Guid key in keys) if (!unique.Add(key)) throw new ArgumentException("Duplicate or empty N2 key");
        var distinctPorts = new HashSet<ushort>();
        foreach (ushort port in ports)
            if (port < 40000 || port >= 49152 || !distinctPorts.Add(port))
                throw new ArgumentException("Expected a distinct high N2 port below 49152");
    }

    static Condition[] BindConditions(ushort port) {
        return new[] { Match(Protocol, Equal, Byte, 6), Match(LocalPort, Equal, UShort, port) };
    }

    ushort CheckBindPriority(Guid ownSub, ushort requested, ushort[] ports, ushort plannedAccountWeight = 0) {
        PriorityEvidence = new List<Dictionary<string, object>>();
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
                        if (sub.Key != ownSub) occupied.Add(sub.Weight);
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
                        if (Array.IndexOf(ResourceAssignment,f.Layer) < 0 || f.Sublayer == ownSub) continue;
                        ushort weight = weights[f.Sublayer];
                        bool mayMatch = true;
                        for (int j=0; j<f.ConditionCount; j++) {
                            var c = (Condition)Marshal.PtrToStructure(IntPtr.Add(f.Conditions,j*40),typeof(Condition));
                            if (c.Match != Equal) continue;
                            if (c.Field == Protocol && c.Value.Type == Byte && (c.Value.Data & 0xff) != 6) mayMatch = false;
                            if (c.Field == LocalPort && c.Value.Type == UShort && Array.IndexOf(ports,(ushort)c.Value.Data) < 0) mayMatch = false;
                        }
                        bool requiresPriority = mayMatch && ((f.Action.Type == StaticPermit && (f.Flags & 8U) != 0) ||
                            f.Action.Type == 0x5003 || f.Action.Type == 0x4005);
                        if (requiresPriority) highest = Math.Max(highest,weight);
                        PriorityEvidence.Add(new Dictionary<string,object> {
                            {"key",f.Key.ToString()}, {"layer",f.Layer.ToString()}, {"sublayerWeight",weight},
                            {"action",f.Action.Type}, {"flags",f.Flags}, {"mayMatch",mayMatch}, {"requiresPriority",requiresPriority}
                        });
                    }
                } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
            } while(count != 0);
        } finally { FwpmFilterDestroyEnumHandle0(engine,enumeration); }

        if (plannedAccountWeight != 0) occupied.Add(plannedAccountWeight);
        int chosen = requested == 0 ? UInt16.MaxValue : requested;
        if (requested == 0) while (chosen > highest && occupied.Contains((ushort)chosen)) chosen--;
        if (chosen <= highest || occupied.Contains((ushort)chosen))
            throw new InvalidOperationException("No verified higher-priority bind sublayer available");
        return (ushort)chosen;
    }

    public ushort PrepareBindGuard(Guid sublayer, Guid[] keys, ushort[] ports) {
        ValidateBindGuard(sublayer,keys,ports);
        return StaticSnapshot(() => {
            VerifyStaticAbsentOnEngine(sublayer,keys);
            return CheckBindPriority(sublayer,0,ports);
        });
    }

    void AddBindDeny(Guid sublayer, Guid key, ushort port, int family) {
        Condition[] conditions = BindConditions(port);
        IntPtr native = Marshal.AllocHGlobal(conditions.Length*40);
        IntPtr weight = IntPtr.Zero;
        try {
            weight = Marshal.AllocHGlobal(8);
            Marshal.WriteInt64(weight,(long)StaticDenyWeight);
            for (int i=0; i<conditions.Length; i++) Marshal.StructureToPtr(conditions[i],IntPtr.Add(native,i*40),false);
            var f = new Filter {
                Key=key, Layer=ResourceAssignment[family], Sublayer=sublayer, Display=new Display { Name=BindGuardName },
                Action=new Action { Type=ActionBlock }, Weight=new Value { Type=StaticUInt64, Data=(ulong)weight.ToInt64() },
                ConditionCount=(uint)conditions.Length, Conditions=native
            };
            ulong id;
            Check(FwpmFilterAdd0(engine,ref f,IntPtr.Zero,out id), "add static TCP bind deny");
        } finally { Marshal.FreeHGlobal(native); if (weight != IntPtr.Zero) Marshal.FreeHGlobal(weight); }
    }

    object ReadBindGuard(Guid sublayer, Guid[] keys, ushort[] ports, ushort weight, int active, bool cleanup) {
        IntPtr pointer;
        uint status = FwpmSubLayerGetByKey0(engine,ref sublayer,out pointer);
        bool subPresent = status != SublayerMissing;
        try {
            if (subPresent) {
                Check(status,"read bind sublayer");
                var sub = (Sublayer)Marshal.PtrToStructure(pointer,typeof(Sublayer));
                if (sub.Key != sublayer || sub.Flags != 0 || sub.Weight != weight || sub.Provider != IntPtr.Zero ||
                    sub.ProviderData.Size != 0 || sub.ProviderData.Data != IntPtr.Zero || sub.Display.Name != BindGuardName ||
                    !String.IsNullOrEmpty(sub.Display.Description)) throw new IOException("Bind sublayer differs from manifest");
            } else if (active > 0 && !cleanup) throw new IOException("Bind sublayer missing");
        } finally { if (pointer != IntPtr.Zero) FwpmFreeMemory0(ref pointer); }

        var rows = new List<Dictionary<string,object>>();
        for (int i=0; i<keys.Length; i++) {
            Guid key = keys[i];
            status = FwpmFilterGetByKey0(engine,ref key,out pointer);
            try {
                if (status == FilterMissing) {
                    if (!cleanup && i < 2*active) throw new IOException("Expected bind filter missing");
                    continue;
                }
                Check(status,"read bind filter");
                var f = (Filter)Marshal.PtrToStructure(pointer,typeof(Filter));
                if (!subPresent || (!cleanup && i >= 2*active) || f.Key != key || f.Layer != ResourceAssignment[i%2] ||
                    f.Sublayer != sublayer || (f.Flags & ~0x40U) != 0 || f.Action.Type != ActionBlock ||
                    f.Action.Key != Guid.Empty || f.ConditionCount != 2 || f.Conditions == IntPtr.Zero ||
                    f.Id == 0 || f.Provider != IntPtr.Zero || f.ProviderData.Size != 0 || f.ProviderData.Data != IntPtr.Zero ||
                    f.Context.Raw != 0 || f.Reserved != IntPtr.Zero || f.Display.Name != BindGuardName ||
                    !String.IsNullOrEmpty(f.Display.Description) || ReadStaticWeight(f.Weight) != StaticDenyWeight ||
                    ReadStaticWeight(f.EffectiveWeight) != StaticDenyWeight)
                    throw new IOException("Bind filter differs from manifest");
                var expected = BindConditions(ports[i/2]);
                for (int j=0; j<2; j++) {
                    var condition = (Condition)Marshal.PtrToStructure(IntPtr.Add(f.Conditions,j*40),typeof(Condition));
                    ulong mask = j==0 ? 0xffUL : 0xffffUL;
                    if (condition.Field != expected[j].Field || condition.Match != Equal ||
                        condition.Value.Type != expected[j].Value.Type || (condition.Value.Data & mask) != expected[j].Value.Data)
                        throw new IOException("Bind filter condition differs from manifest");
                }
                rows.Add(new Dictionary<string,object> {
                    {"key",key.ToString()},{"id",f.Id},{"layer",f.Layer.ToString()},{"action",f.Action.Type},
                    {"flags",f.Flags},{"protocol",6},{"port",ports[i/2]},{"filterWeight",StaticDenyWeight}
                });
            } finally { if (pointer != IntPtr.Zero) FwpmFreeMemory0(ref pointer); }
        }
        VerifyNoUnlistedStaticFilters(sublayer,keys);
        return new Dictionary<string,object>{{"sublayer",sublayer.ToString()},{"weight",weight},{"rules",rows}};
    }

    public void InstallBindGuard(Guid sublayer, Guid[] keys, ushort[] ports, ushort weight, int index) {
        ValidateBindGuard(sublayer,keys,ports);
        if (weight == 0 || index < 0 || index >= ports.Length) throw new ArgumentException("Invalid bind guard generation");
        Transaction(() => {
            if (index == 0) VerifyStaticAbsentOnEngine(sublayer,keys);
            else ReadBindGuard(sublayer,keys,ports,weight,index,false);
            CheckBindPriority(sublayer,weight,ports);
            if (index == 0) {
                var sub = new Sublayer { Key=sublayer, Weight=weight, Display=new Display { Name=BindGuardName } };
                Check(FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero),"add static bind sublayer");
            }
            for (int family=0; family<2; family++) AddBindDeny(sublayer,keys[index*2+family],ports[index],family);
            ReadBindGuard(sublayer,keys,ports,weight,index+1,false);
        });
    }

    public static object VerifyBindGuard(Guid sublayer, Guid[] keys, ushort[] ports, ushort weight, int active) {
        ValidateBindGuard(sublayer,keys,ports);
        if (weight == 0 || active < 1 || active > ports.Length) throw new ArgumentException("Invalid bind guard readback");
        using (var reader = CreateStaticGuard())
            return reader.StaticSnapshot(() => reader.ReadBindGuard(sublayer,keys,ports,weight,active,false));
    }

    public static void RemoveBindGuard(Guid sublayer, Guid[] keys, ushort[] ports, ushort weight) {
        ValidateBindGuard(sublayer,keys,ports);
        using (var remover = CreateStaticGuard()) {
            if (weight != 0) remover.Transaction(() => {
                remover.ReadBindGuard(sublayer,keys,ports,weight,0,true);
                foreach (Guid item in keys) {
                    Guid key = item;
                    uint status = FwpmFilterDeleteByKey0(remover.engine,ref key);
                    if (status != FilterMissing) Check(status,"delete N2 bind filter");
                }
                uint result = FwpmSubLayerDeleteByKey0(remover.engine,ref sublayer);
                if (result != SublayerMissing) Check(result,"delete N2 bind sublayer");
            });
            remover.StaticSnapshot(() => { remover.VerifyStaticAbsentOnEngine(sublayer,keys); return true; });
        }
    }
}
