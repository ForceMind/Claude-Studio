using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

// The preflight only opens and immediately closes handles. It never uses a
// requested right to mutate or control a different process or thread.
internal static partial class StudioN4Preflight {
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,int tid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessIdOfThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern int GetCurrentThreadId();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr value);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool result);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    static extern bool QueryFullProcessImageName(IntPtr process,int flags,StringBuilder path,ref int size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long created,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr value,int size,out int needed);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityInfo(IntPtr handle,int objectType,uint requested,out IntPtr owner,out IntPtr group,
        out IntPtr dacl,out IntPtr sacl,out IntPtr securityDescriptor);

    static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
    static readonly Dictionary<string,uint> ProcessRights=new Dictionary<string,uint> {
        {"PROCESS_CREATE_THREAD",0x0002},{"PROCESS_VM_OPERATION",0x0008},{"PROCESS_VM_WRITE",0x0020},
        {"PROCESS_DUP_HANDLE",0x0040},{"PROCESS_CREATE_PROCESS",0x0080},{"PROCESS_SET_INFORMATION",0x0200},
        {"PROCESS_SUSPEND_RESUME",0x0800},{"WRITE_DAC",0x40000},{"WRITE_OWNER",0x80000}
    };
    static readonly Dictionary<string,uint> ThreadRights=new Dictionary<string,uint> {
        {"THREAD_SUSPEND_RESUME",0x0002},{"THREAD_SET_CONTEXT",0x0010},{"THREAD_SET_INFORMATION",0x0020},
        {"WRITE_DAC",0x40000},{"WRITE_OWNER",0x80000}
    };
    static readonly HashSet<string> NetworkCapabilities=new HashSet<string> {
        "S-1-15-3-1","S-1-15-3-2","S-1-15-3-3",
        "S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225"
    };

    public sealed class Target {
        public string role {get;set;}
        public int pid {get;set;}
        public int tid {get;set;}
        public long startTicks {get;set;}
    }

    static T ReadToken<T>(IntPtr token,int kind,Func<IntPtr,T> read) {
        int size;
        GetTokenInformation(token,kind,IntPtr.Zero,0,out size);
        if(size<4 || size>65536)throw new InvalidDataException("Unexpected token field buffer size");
        IntPtr buffer=Marshal.AllocHGlobal(size);
        try {
            int written;
            if(!GetTokenInformation(token,kind,buffer,size,out written))throw new Win32Exception();
            return read(buffer);
        }finally{Marshal.FreeHGlobal(buffer);}
    }

    static List<string> ReadGroupSids(IntPtr data) {
        int count=Marshal.ReadInt32(data);
        if(count<0 || count>1024)throw new InvalidDataException("Unexpected token group count");
        var result=new List<string>(count);
        for(int i=0;i<count;i++)
            result.Add(new SecurityIdentifier(Marshal.ReadIntPtr(data,IntPtr.Size+i*(IntPtr.Size*2))).Value);
        return result;
    }

    static Dictionary<string,object> Describe(IntPtr handle,int processId) {
        int size=1024;var path=new StringBuilder(size);
        if(!QueryFullProcessImageName(handle,0,path,ref size))throw new Win32Exception();
        long created,exit,kernel,user;
        if(!GetProcessTimes(handle,out created,out exit,out kernel,out user))throw new Win32Exception();
        bool job;
        if(!IsProcessInJob(handle,IntPtr.Zero,out job))throw new Win32Exception();
        IntPtr token;
        if(!OpenProcessToken(handle,8,out token))throw new Win32Exception();
        try {
            // Token membership helpers can duplicate a token. Read the policy
            // fields directly through the existing TOKEN_QUERY handle instead.
            string account=ReadToken(token,1,p=>new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
            bool admin=ReadToken(token,2,ReadGroupSids).Contains("S-1-5-32-544");
            bool inContainer=ReadToken(token,29,p=>Marshal.ReadInt32(p)!=0);
            string containerSid=inContainer?ReadToken(token,31,p=>new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value):null;
            var caps=inContainer?ReadToken(token,30,ReadGroupSids).FindAll(NetworkCapabilities.Contains):new List<string>();
            int session=ReadToken(token,12,p=>Marshal.ReadInt32(p));
            return new Dictionary<string,object> {
                {"pid",processId},{"path",path.ToString()},{"startTicks",DateTime.FromFileTimeUtc(created).Ticks},
                {"session",session},{"userSid",account},{"admin",admin},
                {"appContainer",inContainer},{"containerSid",containerSid},{"inJob",job},{"networkCapabilities",caps}
            };
        }finally{CloseHandle(token);}
    }

    static object ReadOwner(int id,bool thread) {
        IntPtr h=thread?OpenThread(0x20000,false,id):OpenProcess(0x20000,false,id);
        if(h==IntPtr.Zero)return new {sid=(string)null,error=Marshal.GetLastWin32Error()};
        IntPtr owner,group,dacl,sacl,descriptor;
        try {
            uint status=GetSecurityInfo(h,6,1,out owner,out group,out dacl,out sacl,out descriptor);
            try {
                return new {sid=status==0 && owner!=IntPtr.Zero?new SecurityIdentifier(owner).Value:null,error=(int)status};
            }finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
        }finally{CloseHandle(h);}
    }

    static object InspectRights(int id,bool thread) {
        var rows=new List<object>();
        foreach(var requested in thread?ThreadRights:ProcessRights) {
            IntPtr h=thread?OpenThread(requested.Value,false,id):OpenProcess(requested.Value,false,id);
            int error=h==IntPtr.Zero?Marshal.GetLastWin32Error():0;
            if(h!=IntPtr.Zero)CloseHandle(h);
            rows.Add(new {right=requested.Key,granted=h!=IntPtr.Zero,error=error});
        }
        return rows;
    }

    static object Audit(Target target,string selfPath) {
        if(target.pid<1 || target.tid<1 || target.startTicks<1)throw new ArgumentException("Malformed preflight identity");
        string expected=target.role=="executor"?Path.Combine(Path.GetDirectoryName(selfPath),"wxc-exec.exe"):selfPath;
        if(target.role!="ordinary" && target.role!="bootstrap" && target.role!="executor")throw new ArgumentException("Unknown target role");
        IntPtr process=OpenProcess(0x1000,false,target.pid);
        if(process==IntPtr.Zero)throw new Win32Exception();
        try {
            var info=Describe(process,target.pid);
            if(!String.Equals((string)info["path"],expected,StringComparison.OrdinalIgnoreCase) || (long)info["startTicks"]!=target.startTicks)
                throw new InvalidDataException("Preflight process identity changed");
            IntPtr thread=OpenThread(0x0800,false,target.tid);
            if(thread==IntPtr.Zero)throw new Win32Exception();
            try {
                if(GetProcessIdOfThread(thread)!=(uint)target.pid)throw new InvalidDataException("Thread belongs to a different process");
                return new {role=target.role,identity=info,tid=target.tid,processOwner=ReadOwner(target.pid,false),
                    threadOwner=ReadOwner(target.tid,true),processRights=InspectRights(target.pid,false),threadRights=InspectRights(target.tid,true)};
            }finally{CloseHandle(thread);}
        }finally{CloseHandle(process);}
    }

    static int Main(string[] args) {
        try {
            Console.OutputEncoding=new UTF8Encoding(false);
#if N4_HOST_CREATE
            if(args.Length==2 && args[0]=="host-create-audit")return AuditHostCreate(args[1]);
            if(args.Length==1 && args[0]=="inert")return 0;
#endif
            using(var self=Process.GetCurrentProcess()) {
                if(args.Length==2 && args[0]=="audit") {
                    var targets=Json.Deserialize<Target[]>(File.ReadAllText(args[1]));
                    if(targets.Length!=3)throw new ArgumentException("Expected the three preflight targets");
                    var results=new List<object>();
                    foreach(var target in targets)results.Add(Audit(target,self.MainModule.FileName));
                    Console.WriteLine(Json.Serialize(new {auditor=Describe(self.Handle,self.Id),targets=results}));
                }else if(args.Length==3 && (args[0]=="ordinary" || args[0]=="bootstrap")) {
                    var info=Describe(self.Handle,self.Id);
                    if((bool)info["appContainer"]!=(args[0]=="bootstrap"))throw new InvalidOperationException("Unexpected preflight process token type");
                    info["tid"]=GetCurrentThreadId();info["role"]=args[0];
                    string sample=Path.Combine(Path.GetDirectoryName(self.MainModule.FileName),"preflight-control.txt");
                    info["controlReadable"]=File.ReadAllText(sample)=="host-owned-preflight";
                    try {
                        using(File.Open(sample,FileMode.Open,FileAccess.Write,FileShare.ReadWrite))info["controlWriteDenied"]=false;
                    }catch(UnauthorizedAccessException){info["controlWriteDenied"]=true;}
                    string ready=Path.GetFullPath(args[1]),stop=Path.GetFullPath(args[2]);
                    File.WriteAllText(ready+".tmp",Json.Serialize(info));File.Move(ready+".tmp",ready);
                    var deadline=Stopwatch.StartNew();
                    while(!File.Exists(stop) && deadline.ElapsedMilliseconds<24000)Thread.Sleep(25);
                    Console.WriteLine(Json.Serialize(new {role=args[0],pid=self.Id,stopped=File.Exists(stop)}));
                }else throw new ArgumentException("Expected closed-network preflight role");
            }
            return 0;
        }catch(Exception error){Console.Error.WriteLine(error.GetType().Name+": "+error.Message);return 2;}
    }
}
