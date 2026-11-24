using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

public sealed partial class StudioLabWfp
{
    private static readonly Guid RpcLayer = new Guid("75a89dda-95e4-40f3-adc7-7688a9c847e1");
    private static readonly Guid RpcInterfaceField = new Guid("7c9c7d9f-0075-4d35-a0d1-8311c4cf6af1");
    private static readonly Guid RpcUserField = new Guid("9bf0ee66-06c9-41b9-84da-288cb43af51f");
    private static readonly Guid DnsResolverInterface = new Guid("45776b01-5956-4485-9f80-f428f7d60129");

    [StructLayout(LayoutKind.Sequential)]
    private struct Session {
        public Guid Key;
        public Display Display;
        public uint Flags, TransactionWait, ProcessId;
        public IntPtr Sid, Username;
        public int KernelMode;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, EntryPoint = "FwpmEngineOpen0")]
    private static extern uint OpenDynamic(string server, uint auth, IntPtr identity, ref Session session, out IntPtr engine);

    private ulong InstallDnsRpc(Guid sublayer, Guid rule, SecurityIdentifier sid) {
        var descriptor = new RawSecurityDescriptor("D:P(A;;0x1;;;" + sid.Value + ")");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        IntPtr sd = IntPtr.Zero, blob = IntPtr.Zero, uuid = IntPtr.Zero, conditions = IntPtr.Zero;
        try {
            int size = Marshal.SizeOf(typeof(Condition));
            sd = Marshal.AllocHGlobal(bytes.Length);
            blob = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Blob)));
            uuid = Marshal.AllocHGlobal(16);
            conditions = Marshal.AllocHGlobal(2 * size);
            Marshal.Copy(bytes, 0, sd, bytes.Length);
            Marshal.Copy(DnsResolverInterface.ToByteArray(), 0, uuid, 16);
            Marshal.StructureToPtr(new Blob { Size = (uint)bytes.Length, Data = sd }, blob, false);
            Marshal.StructureToPtr(Match(RpcInterfaceField, Equal, Array16, (ulong)uuid.ToInt64()), conditions, false);
            Marshal.StructureToPtr(Match(RpcUserField, Equal, SecurityDescriptor, (ulong)blob.ToInt64()), IntPtr.Add(conditions, size), false);
            Transaction(() => {
                var sub = new Sublayer { Key = sublayer, Weight = 0x100,
                    Display = new Display { Name = "Temporary A DNS RPC validation" } };
                var filter = new Filter { Key = rule, Layer = RpcLayer, Sublayer = sublayer,
                    Display = new Display { Name = "Temporary A DNS RPC validation" }, Action = new Action { Type = ActionBlock },
                    ConditionCount = 2, Conditions = conditions };
                Check(FwpmSubLayerAdd0(engine, ref sub, IntPtr.Zero), "add dynamic RPC sublayer");
                ulong id;
                Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id), "add dynamic A DNS RPC filter");
            });
            return VerifyDnsRpc(sublayer, rule, sid);
        } finally {
            Marshal.FreeHGlobal(conditions);
            Marshal.FreeHGlobal(uuid);
            Marshal.FreeHGlobal(blob);
            Marshal.FreeHGlobal(sd);
        }
    }

    private ulong VerifyDnsRpc(Guid sublayer, Guid key, SecurityIdentifier sid) {
        IntPtr value;
        Check(FwpmSubLayerGetByKey0(engine, ref sublayer, out value), "read back dynamic RPC sublayer");
        try {
            if (((Sublayer)Marshal.PtrToStructure(value, typeof(Sublayer))).Flags != 0)
                throw new IOException("Unexpected RPC sublayer flags");
        } finally { FwpmFreeMemory0(ref value); }
        Check(FwpmFilterGetByKey0(engine, ref key, out value), "read back dynamic A DNS RPC filter");
        try {
            var entry = (Filter)Marshal.PtrToStructure(value, typeof(Filter));
            if (entry.Layer != RpcLayer || entry.Sublayer != sublayer || entry.Flags != 0 ||
                entry.Action.Type != ActionBlock || entry.ConditionCount != 2 || entry.Conditions == IntPtr.Zero)
                throw new IOException("Unexpected RPC block scope");
            bool hasInterface = false, hasSid = false;
            for (int i = 0; i < 2; i++) {
                var condition = (Condition)Marshal.PtrToStructure(
                    IntPtr.Add(entry.Conditions, i * Marshal.SizeOf(typeof(Condition))), typeof(Condition));
                var pointer = new IntPtr(unchecked((long)condition.Value.Data));
                if (condition.Match != Equal || pointer == IntPtr.Zero) throw new IOException("Invalid RPC match condition");
                if (condition.Field == RpcInterfaceField && condition.Value.Type == Array16) {
                    var bytes = new byte[16];
                    Marshal.Copy(pointer, bytes, 0, bytes.Length);
                    hasInterface = new Guid(bytes) == DnsResolverInterface;
                } else if (condition.Field == RpcUserField && condition.Value.Type == SecurityDescriptor) {
                    var blob = (Blob)Marshal.PtrToStructure(pointer, typeof(Blob));
                    if (blob.Size < 20 || blob.Size > 4096 || blob.Data == IntPtr.Zero)
                        throw new IOException("Invalid RPC caller descriptor");
                    var bytes = new byte[blob.Size];
                    Marshal.Copy(blob.Data, bytes, 0, bytes.Length);
                    var acl = new RawSecurityDescriptor(bytes, 0).DiscretionaryAcl;
                    var ace = acl != null && acl.Count == 1 ? acl[0] as CommonAce : null;
                    hasSid = ace != null && ace.AceQualifier == AceQualifier.AccessAllowed &&
                        ace.SecurityIdentifier.Equals(sid) && ace.AccessMask == 1;
                }
            }
            if (!hasInterface || !hasSid) throw new IOException("RPC match does not contain precisely the DNS interface and A");
            return entry.Id;
        } finally { FwpmFreeMemory0(ref value); }
    }

    private StudioLabWfp(Session requested) {
        if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(Session)) != 72 ||
            Marshal.SizeOf(typeof(Filter)) != 200 || Marshal.SizeOf(typeof(Condition)) != 40)
            throw new InvalidOperationException("Unexpected WFP x64 ABI");
        Check(OpenDynamic(null, 10, IntPtr.Zero, ref requested, out engine), "open dynamic RPC session");
    }

    private void VerifyDnsRpcAbsent(Guid sublayer, Guid rule) {
        IntPtr value;
        uint filterStatus = FwpmFilterGetByKey0(engine, ref rule, out value);
        if (value != IntPtr.Zero) FwpmFreeMemory0(ref value);
        uint layerStatus = FwpmSubLayerGetByKey0(engine, ref sublayer, out value);
        if (value != IntPtr.Zero) FwpmFreeMemory0(ref value);
        if (filterStatus != FilterMissing || layerStatus != SublayerMissing)
            throw new IOException("RPC objects were not both reported absent");
    }

    private static int Main(string[] args) {
        try {
            if (args.Length < 3) throw new ArgumentException("Expected RPC lab mode and two object IDs");
            var sublayer = Guid.Parse(args[1]);
            var rule = Guid.Parse(args[2]);
            if (sublayer == Guid.Empty || rule == Guid.Empty || sublayer == rule)
                throw new ArgumentException("Expected independent non-empty lab IDs");
            if (args.Length == 3 && args[0] == "absent") {
                using (var reader = new StudioLabWfp()) reader.VerifyDnsRpcAbsent(sublayer, rule);
                Console.WriteLine("ABSENT");
            } else if (args.Length == 4 && args[0] == "hold" && Console.IsInputRedirected) {
                var sid = new SecurityIdentifier(args[3]);
                if (!sid.IsAccountSid()) throw new ArgumentException("Expected the verified test account SID");
                var session = new Session { Flags = 1, TransactionWait = 2000,
                    Display = new Display { Name = "Temporary A DNS RPC validation" } };
                // Process exit also closes the dynamic session if its controller stalls.
                using (var expiry = new Timer(_ => Environment.Exit(124), null, 55000, Timeout.Infinite))
                using (var owner = new StudioLabWfp(session)) {
                    Console.WriteLine("READY " + owner.InstallDnsRpc(sublayer, rule, sid));
                    Console.Out.Flush();
                    Console.ReadLine();
                }
                Console.WriteLine("CLOSED");
            } else throw new ArgumentException("Unexpected RPC lab arguments");
            return 0;
        } catch (Exception error) {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }
}
