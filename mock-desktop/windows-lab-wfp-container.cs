using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

// Compile with windows-lab-wfp.cs for ABI declarations only. Never call its
// account-wide persistent Install method from the container experiment.
public sealed partial class StudioLabWfp {
    static readonly Guid Package = new Guid("71bc78fa-f17c-4997-a602-6abb261f351c");
    static readonly Guid ApplicationId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    const uint SidValue = 13;
    [StructLayout(LayoutKind.Sequential)]
    struct ContainerSession {
        public Guid Key; public Display Display; public uint Flags, TransactionWait, ProcessId;
        public IntPtr Sid, Username; public int KernelMode;
    }
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode, EntryPoint="FwpmEngineOpen0")]
    static extern uint OpenContainerSession(string server, uint auth, IntPtr identity, ref ContainerSession session, out IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr enumeration);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumeration, uint count, out IntPtr entries, out uint returned);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumeration);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerCreateEnumHandle0(IntPtr engine,IntPtr template,out IntPtr enumeration);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerEnum0(IntPtr engine,IntPtr enumeration,uint count,out IntPtr entries,out uint returned);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDestroyEnumHandle0(IntPtr engine,IntPtr enumeration);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file,out IntPtr appId);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int size, out int required);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool inJob);

    public static void ValidateContainerProcess(int pid, long startTicks, string account, string sid, int session, string executable) {
        ValidateContainerSid(sid);
        using (var process=Process.GetProcessById(pid)) {
            if (process.StartTime.ToUniversalTime().Ticks!=startTicks || process.SessionId!=session ||
                !String.Equals(process.MainModule.FileName, executable, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Container process identity changed");
            bool job;
            if (!IsProcessInJob(process.Handle,IntPtr.Zero,out job) || !job) throw new InvalidOperationException("Container process is outside its job");
            IntPtr token;
            if (!OpenProcessToken(process.Handle,8,out token)) throw new System.ComponentModel.Win32Exception();
            IntPtr data=Marshal.AllocHGlobal(1024);
            try {
                using (var identity=new WindowsIdentity(token)) {
                    if (identity.User.Value!=account) throw new InvalidOperationException("Not the verified A user");
                    foreach (IdentityReference group in identity.Groups)
                        if (group.Value=="S-1-5-32-544") throw new InvalidOperationException("Administrator group in A token");
                }
                int bytes;
                if (!GetTokenInformation(token,29,data,1024,out bytes) || Marshal.ReadInt32(data)!=1)
                    throw new InvalidOperationException("A is not an AppContainer");
                if (!GetTokenInformation(token,31,data,1024,out bytes) || new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value!=sid)
                    throw new InvalidOperationException("AppContainer SID does not match token");
            } finally { Marshal.FreeHGlobal(data); CloseHandle(token); }
        }
    }
    static void ValidateContainerSid(string sid) {
        if (!Regex.IsMatch(sid??"",@"^S-1-15-2(-[0-9]+){7}$")) throw new ArgumentException("Expected one complete AppContainer SID");
        new SecurityIdentifier(sid);
    }
    public static void ValidateContainerSpec(Guid sublayer, Guid[] keys, string sid, ushort port) {
        ValidateContainerSid(sid);
        var seen=new HashSet<Guid>(); seen.Add(sublayer);
        if (sublayer==Guid.Empty || keys==null || keys.Length!=7 || port<49152) throw new ArgumentException("Invalid container experiment manifest");
        foreach (var key in keys) if (key==Guid.Empty || !seen.Add(key)) throw new ArgumentException("Duplicate or empty object key");
    }
    private StudioLabWfp(ContainerSession session) {
        if(session.Flags!=0 && session.Flags!=1) throw new ArgumentException("Unsupported session flags");
        if (IntPtr.Size!=8 || Marshal.SizeOf(typeof(ContainerSession))!=72 || Marshal.SizeOf(typeof(Filter))!=200 ||
            Marshal.SizeOf(typeof(Condition))!=40 || Marshal.SizeOf(typeof(Sublayer))!=72)
            throw new InvalidOperationException("Unexpected WFP x64 ABI");
        Check(OpenContainerSession(null,10,IntPtr.Zero,ref session,out engine),"open container session");
        containerSessionFlags=session.Flags;
    }
    public static StudioLabWfp CreateContainerGuard() {
        return new StudioLabWfp(new ContainerSession {Flags=1,TransactionWait=2000,
            Display=new Display {Name="Temporary A container port guard"}}) {containerMode=1};
    }

    Guid containerSublayer;
    Guid[] containerKeys;
    string containerSid;
    ushort containerPort, containerWeight;
    bool containerInstalled, containerGate;
    uint containerSessionFlags;
    int containerMode; // 1: legacy dynamic seven-rule guard; 2: static N1; 3: dynamic N1 exception.
    public List<Dictionary<string,object>> PriorityEvidence {get; private set;}
    // Enumerate the four relevant layers. Existing blocks need not be outranked.
    // Conservatively include callouts and permits unless an exact package match
    // demonstrably excludes this container. Never alter another sublayer's weight.
    ushort SelectContainerWeight(string sid,string executable) {
        PriorityEvidence=new List<Dictionary<string,object>>();
        int highest=0;
        byte[] appBytes=null;
        if(executable!=null) {
            IntPtr app;
            Check(FwpmGetAppIdFromFileName0(executable,out app),"read simulator WFP application identity");
            try {var blob=(Blob)Marshal.PtrToStructure(app,typeof(Blob));appBytes=new byte[blob.Size];Marshal.Copy(blob.Data,appBytes,0,appBytes.Length);}
            finally {FwpmFreeMemory0(ref app);}
        }
        IntPtr enumeration;
        Check(FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out enumeration),"enumerate existing filters");
        try {
            uint count;
            do {
                IntPtr entries;
                Check(FwpmFilterEnum0(engine,enumeration,256,out entries,out count),"read existing filters");
                try {
                    for (int i=0;i<count;i++) {
                        var filter=(Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Filter));
                        if (filter.Layer!=Connect[0] && filter.Layer!=Connect[1] && filter.Layer!=Accept[0] && filter.Layer!=Accept[1]) continue;
                        bool excludes=false; bool explicitSid=false; bool excludesApplication=false;
                        for (int j=0;j<filter.ConditionCount;j++) {
                            var c=(Condition)Marshal.PtrToStructure(IntPtr.Add(filter.Conditions,j*40),typeof(Condition));
                            if (sid!=null && c.Field==Package && c.Match==Equal && c.Value.Type==SidValue && c.Value.Data!=0) {
                                string value=new SecurityIdentifier(new IntPtr(unchecked((long)c.Value.Data))).Value;
                                explicitSid=value==sid; excludes|=value!=sid;
                            }
                            if(appBytes!=null && c.Field==ApplicationId && c.Match==Equal && c.Value.Type==12 && c.Value.Data!=0) {
                                var blob=(Blob)Marshal.PtrToStructure(new IntPtr(unchecked((long)c.Value.Data)),typeof(Blob));
                                if(blob.Size>65536 || blob.Data==IntPtr.Zero) throw new IOException("Invalid application condition");
                                var bytes=new byte[blob.Size];Marshal.Copy(blob.Data,bytes,0,bytes.Length);
                                bool matches=bytes.Length==appBytes.Length;
                                if(matches) for(int k=0;k<bytes.Length;k++) if(bytes[k]!=appBytes[k]) {matches=false;break;}
                                excludesApplication|=!matches;
                            }
                        }
                        IntPtr native;
                        Check(FwpmSubLayerGetByKey0(engine,ref filter.Sublayer,out native),"read existing sublayer");
                        Sublayer sub;
                        try {sub=(Sublayer)Marshal.PtrToStructure(native,typeof(Sublayer));} finally {FwpmFreeMemory0(ref native);}
                        // Ordinary permits are overridable by a block in another
                        // sublayer. Only hard permits / potentially terminating
                        // callouts require us to precede them. Application-based
                        // exclusions are valid only for this simulator binary.
                        bool priorityRequired=!excludes && !excludesApplication &&
                            ((filter.Action.Type==0x1002 && (filter.Flags&8)!=0) ||
                             filter.Action.Type==0x5003 || filter.Action.Type==0x4005);
                        PriorityEvidence.Add(new Dictionary<string,object>{{"key",filter.Key.ToString()},{"layer",filter.Layer.ToString()},
                            {"sublayer",filter.Sublayer.ToString()},{"sublayerWeight",sub.Weight},{"action",filter.Action.Type},
                            {"flags",filter.Flags},{"exactContainerSid",explicitSid},{"excludedByPackage",excludes},
                            {"excludedByApplication",excludesApplication},{"requiresHigherPriority",priorityRequired},
                            {"filterName",filter.Display.Name},{"sublayerName",sub.Display.Name},{"conditionCount",filter.ConditionCount}});
                        if (priorityRequired && sub.Weight>highest) highest=sub.Weight;
                    }
                } finally {if (entries!=IntPtr.Zero) FwpmFreeMemory0(ref entries);}
            } while(count!=0);
        } finally {FwpmFilterDestroyEnumHandle0(engine,enumeration);}
        var occupied=new HashSet<ushort>();
        Check(FwpmSubLayerCreateEnumHandle0(engine,IntPtr.Zero,out enumeration),"enumerate occupied sublayer weights");
        try {
            uint count;
            do {
                IntPtr entries;Check(FwpmSubLayerEnum0(engine,enumeration,256,out entries,out count),"read occupied sublayer weights");
                try {for(int i=0;i<count;i++) occupied.Add(((Sublayer)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Sublayer))).Weight);}
                finally {if(entries!=IntPtr.Zero) FwpmFreeMemory0(ref entries);}
            } while(count!=0);
        } finally {FwpmSubLayerDestroyEnumHandle0(engine,enumeration);}
        int chosen=UInt16.MaxValue;
        while(chosen>highest && occupied.Contains((ushort)chosen)) chosen--;
        if(chosen<=highest) throw new InvalidOperationException("No unused higher priority available; leave existing policy unchanged (competing weight " + highest + ")");
        return (ushort)chosen;
    }
    Condition[] ContainerConditions(int index, IntPtr sid) {
        var identity=Match(Package,Equal,SidValue,(ulong)sid.ToInt64());
        if (index==0) return new[]{identity,Match(Protocol,NotEqual,Byte,6)};
        if (index==1) return new[]{identity,Match(RemoteAddress,NotEqual,UInt,0x7f000001)};
        if (index==2) return new[]{identity,Match(Protocol,Equal,Byte,6),Match(RemotePort,NotEqual,UShort,containerPort)};
        return new[]{identity};
    }
    Guid ContainerLayer(int index) {return index<3 || index==6 ? Connect[0] : index==3 ? Connect[1] : Accept[index-4];}
    void AddContainerRule(int index, IntPtr sid) {
        var conditions=ContainerConditions(index,sid);
        IntPtr native=Marshal.AllocHGlobal(conditions.Length*40);
        try {
            for(int i=0;i<conditions.Length;i++) Marshal.StructureToPtr(conditions[i],IntPtr.Add(native,i*40),false);
            var filter=new Filter {Key=containerKeys[index],Layer=ContainerLayer(index),Sublayer=containerSublayer,
                Display=new Display {Name="A-only port guard "+(index==6?"G":"R"+(index+1))},Action=new Action {Type=ActionBlock},
                Weight=new Value {Type=Byte,Data=(ulong)(index==6?15:8)},ConditionCount=(uint)conditions.Length,Conditions=native};
            ulong id; Check(FwpmFilterAdd0(engine,ref filter,IntPtr.Zero,out id),"add A container block");
        } finally {Marshal.FreeHGlobal(native);}
    }
    IntPtr AllocateContainerSid() {
        var sid=new SecurityIdentifier(containerSid); var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
        var native=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,native,bytes.Length);return native;
    }
    public void InstallContainer(Guid sublayer, Guid[] keys, string sid, ushort port, string executable) {
        if(containerMode!=1 || containerSessionFlags!=1) throw new InvalidOperationException("Expected legacy dynamic container session");
        if(containerInstalled) throw new InvalidOperationException("Guard already installed");
        ValidateContainerSpec(sublayer,keys,sid,port);
        containerSublayer=sublayer;containerKeys=(Guid[])keys.Clone();containerSid=sid;containerPort=port;
        containerWeight=SelectContainerWeight(sid,executable);
        IntPtr native=AllocateContainerSid();
        try {Transaction(()=>{
            var sub=new Sublayer {Key=sublayer,Weight=containerWeight,Display=new Display {Name="Temporary A container port guard"}};
            Check(FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero),"add A sublayer");
            for(int i=0;i<7;i++) AddContainerRule(i,native);
        });containerInstalled=true;containerGate=true;} finally {Marshal.FreeHGlobal(native);}
    }
    public void SetContainerGate(bool closed) {
        if(!containerInstalled) throw new InvalidOperationException("No container guard");
        if(closed==containerGate) return;
        IntPtr native=AllocateContainerSid();
        try {Transaction(()=>{if(closed) AddContainerRule(6,native); else {var key=containerKeys[6];Check(FwpmFilterDeleteByKey0(engine,ref key),"remove offline gate");}});containerGate=closed;}
        finally {Marshal.FreeHGlobal(native);}
    }
    public object VerifyContainer() {
        if(!containerInstalled) throw new InvalidOperationException("No installed guard");
        var results=new List<Dictionary<string,object>>();
        IntPtr expected=AllocateContainerSid();
        try {
            IntPtr subPointer;
            Check(FwpmSubLayerGetByKey0(engine,ref containerSublayer,out subPointer),"read A sublayer");
            try {var sub=(Sublayer)Marshal.PtrToStructure(subPointer,typeof(Sublayer));if(sub.Flags!=0 || sub.Weight!=containerWeight) throw new IOException("Wrong sublayer flags/weight: flags="+sub.Flags+", weight="+sub.Weight+", requested="+containerWeight);}
            finally {FwpmFreeMemory0(ref subPointer);}
            for(int i=0;i<7;i++) {
                Guid key=containerKeys[i];IntPtr pointer;
                uint status=FwpmFilterGetByKey0(engine,ref key,out pointer);
                if(i==6 && !containerGate) {if(pointer!=IntPtr.Zero) FwpmFreeMemory0(ref pointer);if(status!=FilterMissing) throw new IOException("Offline gate still present");continue;}
                Check(status,"read A filter");
                try {
                    var f=(Filter)Marshal.PtrToStructure(pointer,typeof(Filter));
                    var conditions=ContainerConditions(i,expected);
                    // BFE can add FWPM_FILTER_FLAG_INDEXED (0x40). It changes
                    // lookup performance, not matching scope or action rights.
                    if((f.Flags&~0x40U)!=0 || f.Layer!=ContainerLayer(i) || f.Sublayer!=containerSublayer || f.Action.Type!=ActionBlock ||
                        f.ConditionCount!=conditions.Length || f.Weight.Type!=Byte || (f.Weight.Data&0xff)!=(ulong)(i==6?15:8)) throw new IOException("Filter shape changed: index="+i+", flags="+f.Flags+", weightType="+f.Weight.Type+", weight="+f.Weight.Data);
                    var decoded=new List<Dictionary<string,object>>();
                    for(int j=0;j<conditions.Length;j++) {
                        var c=(Condition)Marshal.PtrToStructure(IntPtr.Add(f.Conditions,j*40),typeof(Condition));var want=conditions[j];
                        if(c.Field!=want.Field || c.Match!=want.Match || c.Value.Type!=want.Value.Type) throw new IOException("Unexpected filter condition");
                        ulong numeric=c.Value.Type==Byte ? c.Value.Data&0xff : c.Value.Type==UShort ? c.Value.Data&0xffff : c.Value.Type==UInt ? c.Value.Data&0xffffffff : c.Value.Data;
                        object value=numeric;
                        if(j==0) {value=new SecurityIdentifier(new IntPtr(unchecked((long)c.Value.Data))).Value;if((string)value!=containerSid) throw new IOException("Wrong container SID");}
                        else if(numeric!=want.Value.Data) throw new IOException("Wrong endpoint condition");
                        decoded.Add(new Dictionary<string,object>{{"field",c.Field.ToString()},{"match",c.Match},{"type",c.Value.Type},{"value",value}});
                    }
                    results.Add(new Dictionary<string,object>{{"rule",i==6?"G":"R"+(i+1)},{"key",key.ToString()},{"id",f.Id},
                        {"layer",f.Layer.ToString()},{"action",f.Action.Type},{"flags",f.Flags},{"conditions",decoded}});
                } finally {FwpmFreeMemory0(ref pointer);}
            }
        } finally {Marshal.FreeHGlobal(expected);}
        return new Dictionary<string,object>{{"sublayer",containerSublayer.ToString()},{"weight",containerWeight},{"gateClosed",containerGate},{"rules",results}};
    }
    public static void VerifyContainerAbsent(Guid sublayer, Guid[] keys) {
        using(var reader=new StudioLabWfp()) {
            foreach(Guid item in keys) {var key=item;IntPtr p;uint status=FwpmFilterGetByKey0(reader.engine,ref key,out p);if(p!=IntPtr.Zero) FwpmFreeMemory0(ref p);if(status!=FilterMissing) throw new IOException("Container rule remains");}
            IntPtr native;uint result=FwpmSubLayerGetByKey0(reader.engine,ref sublayer,out native);if(native!=IntPtr.Zero) FwpmFreeMemory0(ref native);if(result!=SublayerMissing) throw new IOException("Container sublayer remains");
        }
    }
    // N1 uses static (not persistent/boot-time) objects and a separately owned
    // dynamic soft permit. Session dynamic ownership is not a filter flag; the
    // factories and mode checks below enforce it at the only creation entrypoints.
    const uint StaticUInt64=4, StaticPermit=0x1002;
    const ulong StaticDenyWeight=0x1000000000000000UL, StaticAllowWeight=0x2000000000000000UL;
    const string StaticName="A-only N1 static guard";
    static readonly string[] StaticRuleNames={"D4","D6","I4","I6","E"};
    Guid staticSublayer;
    Guid[] staticKeys;
    string staticSid;
    ushort staticPort,staticWeight;
    bool staticAttached,staticException;

    public static void ValidateStaticSpec(Guid sublayer,Guid[] keys,string sid,ushort port) {
        ValidateContainerSid(sid);
        if(new SecurityIdentifier(sid).Value!=sid)throw new ArgumentException("Expected canonical exact AppContainer SID");
        var seen=new HashSet<Guid>();seen.Add(sublayer);
        if(sublayer==Guid.Empty || keys==null || keys.Length!=5 || port<40000)
            throw new ArgumentException("Expected static sublayer, five rule keys and high lab port");
        foreach(Guid key in keys) if(key==Guid.Empty || !seen.Add(key)) throw new ArgumentException("Duplicate or empty N1 object key");
        if(StaticAllowWeight<=StaticDenyWeight) throw new InvalidOperationException("N1 exception must outrank deny in the same sublayer");
    }
    static void ValidateStaticWeight(ushort weight) {
        if(weight==0) throw new ArgumentException("Expected explicit nonzero N1 sublayer weight");
    }
    public static StudioLabWfp CreateStaticGuard() {
        return new StudioLabWfp(new ContainerSession {Flags=0,TransactionWait=2000,
            Display=new Display {Name=StaticName}}) {containerMode=2};
    }
    public static StudioLabWfp CreateStaticExceptionGuard() {
        return new StudioLabWfp(new ContainerSession {Flags=1,TransactionWait=2000,
            Display=new Display {Name="A-only N1 dynamic exception owner"}}) {containerMode=3};
    }
    void RequireStaticMode(int mode,uint flags) {
        if(engine==IntPtr.Zero || containerMode!=mode || containerSessionFlags!=flags)
            throw new InvalidOperationException("Wrong N1 session lifecycle mode");
    }
    public ushort PrepareStatic(Guid sublayer,Guid[] keys,string sid,ushort port,string executable) {
        RequireStaticMode(2,0);ValidateStaticSpec(sublayer,keys,sid,port);
        return SelectContainerWeight(sid,executable);
    }
    static Guid StaticLayer(int index) {return index<2 ? Connect[index] : index<4 ? Accept[index-2] : Connect[0];}
    static Condition[] StaticConditions(int index,IntPtr sid,ushort port) {
        var identity=Match(Package,Equal,SidValue,unchecked((ulong)sid.ToInt64()));
        return index==4 ? new[]{identity,Match(Protocol,Equal,Byte,6),Match(RemoteAddress,Equal,UInt,0x7f000001),Match(RemotePort,Equal,UShort,port)} : new[]{identity};
    }
    static IntPtr AllocateStaticSid(string text) {
        var sid=new SecurityIdentifier(text);var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
        var native=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,native,bytes.Length);return native;
    }
    void AddStaticRule(Guid sublayer,Guid key,string sid,ushort port,int index) {
        IntPtr identity=AllocateStaticSid(sid),conditions=IntPtr.Zero,weight=IntPtr.Zero;
        try {
            var wanted=StaticConditions(index,identity,port);conditions=Marshal.AllocHGlobal(wanted.Length*40);
            for(int i=0;i<wanted.Length;i++) Marshal.StructureToPtr(wanted[i],IntPtr.Add(conditions,i*40),false);
            // FWP_UINT64's union member is UINT64*, never the inline integer.
            weight=Marshal.AllocHGlobal(8);Marshal.WriteInt64(weight,unchecked((long)(index==4?StaticAllowWeight:StaticDenyWeight)));
            var filter=new Filter {Key=key,Layer=StaticLayer(index),Sublayer=sublayer,
                Display=new Display {Name=StaticName+" "+StaticRuleNames[index]},Flags=0,
                Weight=new Value {Type=StaticUInt64,Data=unchecked((ulong)weight.ToInt64())},
                Action=new Action {Type=index==4?StaticPermit:ActionBlock},ConditionCount=(uint)wanted.Length,Conditions=conditions};
            ulong id;Check(FwpmFilterAdd0(engine,ref filter,IntPtr.Zero,out id),"add N1 "+StaticRuleNames[index]);
        } finally {if(weight!=IntPtr.Zero)Marshal.FreeHGlobal(weight);if(conditions!=IntPtr.Zero)Marshal.FreeHGlobal(conditions);Marshal.FreeHGlobal(identity);}
    }
    public void InstallStatic(Guid sublayer,Guid[] keys,string sid,ushort port,string executable,ushort weight) {
        RequireStaticMode(2,0);ValidateStaticSpec(sublayer,keys,sid,port);ValidateStaticWeight(weight);
        Transaction(()=>{
            VerifyStaticAbsentOnEngine(sublayer,keys);
            if(SelectContainerWeight(sid,executable)!=weight) throw new IOException("N1 priority changed after manifest preparation");
            var sub=new Sublayer {Key=sublayer,Weight=weight,Flags=0,Display=new Display {Name=StaticName}};
            Check(FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero),"add N1 static sublayer");
            for(int i=0;i<4;i++)AddStaticRule(sublayer,keys[i],sid,port,i);
        });
    }
    public void AttachStaticException(Guid sublayer,Guid[] keys,string sid,ushort port,ushort weight) {
        RequireStaticMode(3,1);ValidateStaticSpec(sublayer,keys,sid,port);ValidateStaticWeight(weight);
        if(staticAttached)throw new InvalidOperationException("N1 exception owner already attached");
        // Independent read handle proves the four denies, without installer state.
        VerifyStatic(sublayer,keys,sid,port,weight,false);
        staticSublayer=sublayer;staticKeys=(Guid[])keys.Clone();staticSid=sid;staticPort=port;staticWeight=weight;staticAttached=true;
    }
    public void SetStaticException(bool enabled) {
        RequireStaticMode(3,1);if(!staticAttached)throw new InvalidOperationException("No attached N1 manifest");
        if(enabled==staticException)return;
        Transaction(()=>{
            VerifyStaticOnEngine(staticSublayer,staticKeys,staticSid,staticPort,staticWeight,staticException,false);
            if(enabled)AddStaticRule(staticSublayer,staticKeys[4],staticSid,staticPort,4);
            else {Guid key=staticKeys[4];Check(FwpmFilterDeleteByKey0(engine,ref key),"remove N1 dynamic exception");}
        });
        staticException=enabled;
    }
    static ulong ReadStaticWeight(Value value) {
        if(value.Type!=StaticUInt64 || value.Data==0)throw new IOException("N1 weight is not explicit FWP_UINT64 pointer");
        return unchecked((ulong)Marshal.ReadInt64(new IntPtr(unchecked((long)value.Data))));
    }
    Dictionary<string,object> VerifyStaticRule(Filter f,Guid sublayer,Guid key,string sid,ushort port,int index) {
        ulong expectedWeight=index==4?StaticAllowWeight:StaticDenyWeight;
        ulong rawWeight=ReadStaticWeight(f.Weight),effectiveWeight=ReadStaticWeight(f.EffectiveWeight);
        if(f.Key!=key || f.Layer!=StaticLayer(index) || f.Sublayer!=sublayer || (f.Flags&~0x40U)!=0 ||
            f.Provider!=IntPtr.Zero || f.ProviderData.Size!=0 || f.ProviderData.Data!=IntPtr.Zero || f.Context.Raw!=0 || f.Reserved!=IntPtr.Zero ||
            f.Display.Name!=StaticName+" "+StaticRuleNames[index] || !String.IsNullOrEmpty(f.Display.Description) ||
            f.Action.Type!=(index==4?StaticPermit:ActionBlock) || f.Action.Key!=Guid.Empty ||
            rawWeight!=expectedWeight || effectiveWeight!=expectedWeight || f.Id==0 ||
            f.ConditionCount!=(index==4?4U:1U) || f.Conditions==IntPtr.Zero)
            throw new IOException("N1 filter differs from trusted manifest: "+StaticRuleNames[index]);
        var decoded=new List<Dictionary<string,object>>();
        var wanted=StaticConditions(index,IntPtr.Zero,port);
        for(int i=0;i<wanted.Length;i++) {
            var c=(Condition)Marshal.PtrToStructure(IntPtr.Add(f.Conditions,i*40),typeof(Condition));var want=wanted[i];
            if(c.Field!=want.Field || c.Match!=want.Match || c.Value.Type!=want.Value.Type)throw new IOException("N1 condition shape differs");
            object value;
            if(i==0) {
                if(c.Value.Data==0)throw new IOException("Missing N1 package SID");
                value=new SecurityIdentifier(new IntPtr(unchecked((long)c.Value.Data))).Value;
                if((string)value!=sid)throw new IOException("N1 package SID differs");
            } else {
                ulong numeric=c.Value.Type==Byte ? c.Value.Data&0xff : c.Value.Type==UShort ? c.Value.Data&0xffff : c.Value.Data&0xffffffff;
                if(numeric!=want.Value.Data)throw new IOException("N1 endpoint differs");value=numeric;
            }
            decoded.Add(new Dictionary<string,object>{{"field",c.Field.ToString()},{"match",c.Match},{"type",c.Value.Type},{"value",value}});
        }
        return new Dictionary<string,object>{{"rule",StaticRuleNames[index]},{"key",key.ToString()},{"present",true},{"id",f.Id},
            {"layer",f.Layer.ToString()},{"sublayer",f.Sublayer.ToString()},{"action",f.Action.Type},{"flags",f.Flags},
            {"weightType",f.Weight.Type},{"weight",rawWeight},{"effectiveWeightType",f.EffectiveWeight.Type},{"effectiveWeight",effectiveWeight},
            {"declaredLifetime",index==4?"dynamic-session":"static-until-explicit-delete-or-BFE-stop"},{"conditions",decoded}};
    }
    void VerifyNoUnlistedStaticFilters(Guid sublayer,Guid[] keys) {
        var allowed=new HashSet<Guid>(keys);IntPtr enumeration;
        Check(FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out enumeration),"enumerate N1 sublayer membership");
        try {
            uint count;
            do {
                IntPtr entries;Check(FwpmFilterEnum0(engine,enumeration,256,out entries,out count),"read N1 sublayer membership");
                try {for(int i=0;i<count;i++) {
                    var f=(Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Filter));
                    if(f.Sublayer==sublayer && !allowed.Contains(f.Key))throw new IOException("Unlisted filter in N1 sublayer; refusing deletion");
                }} finally {if(entries!=IntPtr.Zero)FwpmFreeMemory0(ref entries);}
            }while(count!=0);
        }finally {FwpmFilterDestroyEnumHandle0(engine,enumeration);}
    }
    Dictionary<string,object> VerifyStaticOnEngine(Guid sublayer,Guid[] keys,string sid,ushort port,ushort weight,bool exceptionPresent,bool partial) {
        ValidateStaticSpec(sublayer,keys,sid,port);ValidateStaticWeight(weight);
        var results=new List<Dictionary<string,object>>();IntPtr pointer;bool subPresent;
        uint status=FwpmSubLayerGetByKey0(engine,ref sublayer,out pointer);
        try {
            subPresent=status!=SublayerMissing;
            if(subPresent) {
                Check(status,"read N1 sublayer");var sub=(Sublayer)Marshal.PtrToStructure(pointer,typeof(Sublayer));
                if(sub.Key!=sublayer || sub.Flags!=0 || sub.Weight!=weight || sub.Provider!=IntPtr.Zero || sub.ProviderData.Size!=0 ||
                    sub.ProviderData.Data!=IntPtr.Zero || sub.Display.Name!=StaticName || !String.IsNullOrEmpty(sub.Display.Description))
                    throw new IOException("N1 sublayer differs from trusted manifest");
            }else if(!partial)throw new IOException("N1 static sublayer missing");
        }finally {if(pointer!=IntPtr.Zero)FwpmFreeMemory0(ref pointer);}
        for(int i=0;i<5;i++) {
            Guid key=keys[i];status=FwpmFilterGetByKey0(engine,ref key,out pointer);
            try {
                if(status==FilterMissing) {
                    if((i<4 && !partial) || (i==4 && exceptionPresent))throw new IOException("N1 expected rule missing: "+StaticRuleNames[i]);
                    results.Add(new Dictionary<string,object>{{"rule",StaticRuleNames[i]},{"key",key.ToString()},{"present",false}});continue;
                }
                Check(status,"read N1 filter");
                if(!subPresent || (i==4 && !exceptionPresent))throw new IOException("N1 unexpected rule present: "+StaticRuleNames[i]);
                results.Add(VerifyStaticRule((Filter)Marshal.PtrToStructure(pointer,typeof(Filter)),sublayer,key,sid,port,i));
            }finally {if(pointer!=IntPtr.Zero)FwpmFreeMemory0(ref pointer);}
        }
        VerifyNoUnlistedStaticFilters(sublayer,keys);
        return new Dictionary<string,object>{{"sublayer",sublayer.ToString()},{"sublayerPresent",subPresent},{"sublayerFlags",0U},
            {"weight",weight},{"exceptionPresent",exceptionPresent},{"rules",results},{"lifetimeEvidence","creation-session mode plus readback flags; session ownership is not exposed by filter get"}};
    }
    public static object VerifyStatic(Guid sublayer,Guid[] keys,string sid,ushort port,ushort weight,bool exceptionPresent) {
        ValidateStaticSpec(sublayer,keys,sid,port);ValidateStaticWeight(weight);
        using(var reader=CreateStaticGuard())return reader.StaticSnapshot<object>(()=>reader.VerifyStaticOnEngine(sublayer,keys,sid,port,weight,exceptionPresent,false));
    }
    T StaticSnapshot<T>(Func<T> read) {
        // Select presence and decode its full rule in one read-only transaction,
        // so a disappearing owner cannot produce a mixed polling snapshot.
        Check(FwpmTransactionBegin0(engine,1),"begin N1 read-only snapshot");
        try {T result=read();Check(FwpmTransactionCommit0(engine),"commit N1 read-only snapshot");return result;}
        catch {FwpmTransactionAbort0(engine);throw;}
    }
    public static bool StaticExceptionPresent(Guid sublayer,Guid[] keys,string sid,ushort port,ushort weight) {
        ValidateStaticSpec(sublayer,keys,sid,port);ValidateStaticWeight(weight);
        using(var reader=CreateStaticGuard()) {
            return reader.StaticSnapshot<bool>(()=>{
            IntPtr pointer;Guid key=keys[4];uint status=FwpmFilterGetByKey0(reader.engine,ref key,out pointer);
            if(pointer!=IntPtr.Zero)FwpmFreeMemory0(ref pointer);
            bool present=status!=FilterMissing;if(present)Check(status,"read N1 exception presence");
            reader.VerifyStaticOnEngine(sublayer,keys,sid,port,weight,present,false);return present;
            });
        }
    }
    void VerifyStaticAbsentOnEngine(Guid sublayer,Guid[] keys) {
        foreach(Guid item in keys) {
            Guid key=item;IntPtr pointer;uint status=FwpmFilterGetByKey0(engine,ref key,out pointer);
            if(pointer!=IntPtr.Zero)FwpmFreeMemory0(ref pointer);
            if(status!=FilterMissing)throw new IOException("N1 key not confirmed absent: "+key+" status=0x"+status.ToString("X8"));
        }
        IntPtr sub;uint result=FwpmSubLayerGetByKey0(engine,ref sublayer,out sub);if(sub!=IntPtr.Zero)FwpmFreeMemory0(ref sub);
        if(result!=SublayerMissing)throw new IOException("N1 sublayer not confirmed absent: 0x"+result.ToString("X8"));
    }
    public static void VerifyStaticAbsent(Guid sublayer,Guid[] keys,string sid,ushort port) {
        ValidateStaticSpec(sublayer,keys,sid,port);
        using(var reader=CreateStaticGuard())reader.StaticSnapshot<bool>(()=>{reader.VerifyStaticAbsentOnEngine(sublayer,keys);return true;});
    }
    public static void RemoveStatic(Guid sublayer,Guid[] keys,string sid,ushort port,ushort weight) {
        ValidateStaticSpec(sublayer,keys,sid,port);ValidateStaticWeight(weight);
        using(var remover=CreateStaticGuard()) {
            remover.Transaction(()=>{
                // Validate every surviving object and sublayer membership before
                // deleting any; E must have disappeared with its dynamic owner.
                remover.VerifyStaticOnEngine(sublayer,keys,sid,port,weight,false,true);
                for(int i=0;i<4;i++) {
                    Guid key=keys[i];uint status=FwpmFilterDeleteByKey0(remover.engine,ref key);
                    if(status!=FilterMissing)Check(status,"delete N1 static deny");
                }
                uint deleted=FwpmSubLayerDeleteByKey0(remover.engine,ref sublayer);
                if(deleted!=SublayerMissing)Check(deleted,"delete N1 static sublayer");
            });
        }
        VerifyStaticAbsent(sublayer,keys,sid,port);
    }
    public void RemoveContainer() {
        if(!containerInstalled) return;
        Transaction(()=>{foreach(Guid item in containerKeys){var key=item;uint result=FwpmFilterDeleteByKey0(engine,ref key);if(result!=FilterMissing)Check(result,"delete A rule");}
            Check(FwpmSubLayerDeleteByKey0(engine,ref containerSublayer),"delete A sublayer");});
        containerInstalled=false;VerifyContainerAbsent(containerSublayer,containerKeys);
    }
}
