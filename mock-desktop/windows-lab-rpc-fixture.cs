using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Web.Script.Serialization;

// A private, single-operation RPC fixture. Its only payload is a four-byte marker.
public static class StudioRpcFixture {
    public static readonly Guid InterfaceId = new Guid("fd53aacc-6237-4a11-a9dc-093b984145af");
    [StructLayout(LayoutKind.Sequential)] struct Syntax { public Guid Id; public ushort Major, Minor; }
    [StructLayout(LayoutKind.Sequential)] struct Interface {
        public uint Length; public Syntax Id, Transfer; public IntPtr Dispatch;
        public uint EndpointCount; public IntPtr Endpoints, Reserved, Interpreter; public uint Flags;
    }
    [StructLayout(LayoutKind.Sequential)] struct Dispatch { public uint Count; public IntPtr Functions, Reserved; }
    [StructLayout(LayoutKind.Sequential)] struct Message {
        public IntPtr Handle; public uint DataRepresentation; public IntPtr Buffer;
        public uint BufferLength, ProcNum; public IntPtr Transfer, Interface, Reserved, Manager, Import;
        public uint Flags;
    }
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate void DispatchCall(IntPtr message);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint CheckCaller(IntPtr iface, IntPtr call);
    [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)] static extern uint RpcServerUseProtseqEpW(string protocol, uint max, string endpoint, IntPtr security);
    [DllImport("rpcrt4.dll")] static extern uint RpcServerRegisterIfEx(IntPtr iface, IntPtr type, IntPtr manager, uint flags, uint max, CheckCaller callback);
    [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)] static extern uint RpcServerRegisterAuthInfoW(string principal, uint auth, IntPtr callback, IntPtr arg);
    [DllImport("rpcrt4.dll")] static extern uint RpcServerListen(uint min, uint max, uint dontWait);
    [DllImport("rpcrt4.dll")] static extern uint RpcMgmtStopServerListening(IntPtr binding);
    [DllImport("rpcrt4.dll")] static extern uint RpcServerUnregisterIf(IntPtr iface, IntPtr manager, uint wait);
    [DllImport("rpcrt4.dll")] static extern uint RpcImpersonateClient(IntPtr binding);
    [DllImport("rpcrt4.dll")] static extern uint RpcRevertToSelf();
    [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)] static extern uint RpcBindingFromStringBindingW(string binding, out IntPtr handle);
    [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)] static extern uint RpcBindingSetAuthInfoW(IntPtr binding, string principal, uint level, uint auth, IntPtr identity, uint authz);
    [DllImport("rpcrt4.dll")] static extern uint RpcBindingSetOption(IntPtr binding, uint option, UIntPtr value);
    [DllImport("rpcrt4.dll")] static extern uint RpcBindingFree(ref IntPtr handle);
    [DllImport("rpcrt4.dll")] static extern uint I_RpcGetBuffer(ref Message message);
    [DllImport("rpcrt4.dll")] static extern uint I_RpcSendReceive(ref Message message);
    [DllImport("rpcrt4.dll")] static extern uint I_RpcFreeBuffer(ref Message message);
    static void Check(uint status) { if(status!=0) throw new InvalidOperationException("RPC status " + status); }
    static IntPtr Native(object value) { var p=Marshal.AllocHGlobal(Marshal.SizeOf(value)); Marshal.StructureToPtr(value,p,false); return p; }
    static Interface Description() { return new Interface { Length=(uint)Marshal.SizeOf(typeof(Interface)), Id=new Syntax {Id=InterfaceId,Major=1}, Transfer=new Syntax {Id=new Guid("8a885d04-1ceb-11c9-9fe8-08002b104860"),Major=2} }; }
    static string expectedSid;
    static uint Authorize(IntPtr iface, IntPtr call) {
        uint status=RpcImpersonateClient(call);
        if(status!=0) return 5;
        try { using(var identity=WindowsIdentity.GetCurrent()) { return identity.User.Value==expectedSid ? 0U : 5U; } }
        catch { return 5; }
        finally { RpcRevertToSelf(); }
    }
    static void Echo(IntPtr pointer) {
        var msg=(Message)Marshal.PtrToStructure(pointer,typeof(Message));
        uint requestLength=msg.BufferLength;
        int marker=msg.BufferLength>=4 ? Marshal.ReadInt32(msg.Buffer) : 0;
        msg.BufferLength=4;
        uint status=I_RpcGetBuffer(ref msg);
        if(status==0) Marshal.WriteInt32(msg.Buffer,marker ^ 0x13579);
        msg.BufferLength=4;
        Marshal.StructureToPtr(msg,pointer,false);
        Console.WriteLine("CALL " + marker + " LENGTH " + requestLength);
        Console.Out.Flush();
    }
    public static int Main(string[] args) {
        try {
            if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(Interface))!=96 || Marshal.SizeOf(typeof(Message))!=80) throw new Exception("Unexpected RPC ABI");
            expectedSid=WindowsIdentity.GetCurrent().User.Value;
            if(args[0]=="server") {
                var dispatch=new DispatchCall(Echo); var auth=new CheckCaller(Authorize);
                IntPtr table=Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(table,Marshal.GetFunctionPointerForDelegate(dispatch));
                IntPtr dispatchPointer=Native(new Dispatch {Count=1,Functions=table});
                var desc=Description(); desc.Dispatch=dispatchPointer;
                IntPtr iface=Native(desc);
                using(var deadline=new Timer(_=>Environment.Exit(124),null,120000,Timeout.Infinite)) {
                    Check(RpcServerRegisterAuthInfoW(null,10,IntPtr.Zero,IntPtr.Zero));
                    Check(RpcServerUseProtseqEpW(args[1],10,args[2],IntPtr.Zero));
                    Check(RpcServerRegisterIfEx(iface,IntPtr.Zero,IntPtr.Zero,0,10,auth));
                    Check(RpcServerListen(1,10,1));
                    Console.WriteLine("READY " + System.Diagnostics.Process.GetCurrentProcess().Id); Console.Out.Flush();
                    Console.ReadLine();
                    RpcMgmtStopServerListening(IntPtr.Zero); RpcServerUnregisterIf(iface,IntPtr.Zero,1);
                }
                GC.KeepAlive(dispatch); GC.KeepAlive(auth);
                Marshal.FreeHGlobal(iface); Marshal.FreeHGlobal(dispatchPointer); Marshal.FreeHGlobal(table);
            } else if(args[0]=="client") {
                IntPtr binding;
                string address=args[1]=="ncalrpc" ? "" : "127.0.0.1";
                Check(RpcBindingFromStringBindingW(args[1]+":"+address+"["+args[2]+"]",out binding));
                IntPtr iface=Native(Description());
                try {
                    Check(RpcBindingSetOption(binding,12,new UIntPtr(4000)));
                    Check(RpcBindingSetAuthInfoW(binding,null,6,10,IntPtr.Zero,0));
                    var msg=new Message {Handle=binding,DataRepresentation=0x10,BufferLength=4,Interface=iface};
                    Check(I_RpcGetBuffer(ref msg));
                    int marker=int.Parse(args[3]); Marshal.WriteInt32(msg.Buffer,marker);
                    msg.BufferLength=4;
                    string start=DateTime.UtcNow.ToString("o");
                    uint status=I_RpcSendReceive(ref msg);
                    int answer=status==0 && msg.BufferLength==4 ? Marshal.ReadInt32(msg.Buffer) : 0;
                    string finish=DateTime.UtcNow.ToString("o");
                    I_RpcFreeBuffer(ref msg);
                    Console.WriteLine(new JavaScriptSerializer().Serialize(new {status=status,reply=answer,marker=marker,userSid=expectedSid,pid=System.Diagnostics.Process.GetCurrentProcess().Id,startedUtc=start,finishedUtc=finish}));
                } finally { Marshal.FreeHGlobal(iface); RpcBindingFree(ref binding); }
            } else throw new Exception("Unexpected fixture mode");
            return 0;
        } catch(Exception error) {Console.Error.WriteLine(error.Message); return 1;}
    }
}
