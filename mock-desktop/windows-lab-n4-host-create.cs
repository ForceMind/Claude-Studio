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

internal static partial class StudioN4Preflight {
    internal static int NativeThreadId() { return GetCurrentThreadId(); }

    internal static object DescribeHostCreation(IntPtr process,int pid) {
        var result=Describe(process,pid);
        IntPtr token;
        if(!OpenProcessToken(process,8,out token))throw new Win32Exception();
        try {
            result["tokenType"]=ReadToken(token,8,p=>Marshal.ReadInt32(p));
            result["integrity"]=ReadToken(token,25,p=>new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
            result["logonSids"]=ReadToken(token,2,ReadGroupSids).FindAll(s=>s.StartsWith("S-1-5-5-",StringComparison.Ordinal));
            return result;
        }finally{CloseHandle(token);}
    }

    static object ObserveQuery(int pid) {
        IntPtr requested=OpenProcess(0x1000,false,pid);
        int error=requested==IntPtr.Zero?Marshal.GetLastWin32Error():0;
        if(requested!=IntPtr.Zero)CloseHandle(requested);
        return new {granted=requested!=IntPtr.Zero,error=error};
    }

    static int AuditHostCreate(string requestFile) {
        using(var me=Process.GetCurrentProcess()) {
            var targets=Json.Deserialize<Target[]>(File.ReadAllText(requestFile));
            if(targets.Length!=3 || targets[0].role!="ordinary" || targets[1].role!="suspended" || targets[2].role!="broker")
                throw new ArgumentException("Unexpected protected-creation audit targets");
            var seen=new HashSet<int>();
            var details=new List<object>();
            foreach(var target in targets) {
                if(target.pid<1 || target.tid<1 || target.startTicks<1 || !seen.Add(target.pid))throw new ArgumentException("Invalid audit target identity");
                // The host holds the real protected objects live across this
                // audit. A cannot read their identities through a denied open.
                object identity=null;
                if(target.role=="ordinary") {
                    IntPtr p=OpenProcess(0x1000,false,target.pid);
                    IntPtr t=OpenThread(0x0800,false,target.tid);
                    try {
                        if(p==IntPtr.Zero || t==IntPtr.Zero || GetProcessIdOfThread(t)!=(uint)target.pid)throw new IOException("Ordinary control query failed");
                        var current=Describe(p,target.pid);
                        if((long)current["startTicks"]!=target.startTicks ||
                            !String.Equals((string)current["path"],me.MainModule.FileName,StringComparison.OrdinalIgnoreCase))
                            throw new IOException("Ordinary control identity changed");
                        identity=DescribeHostCreation(p,target.pid);
                    }finally{if(p!=IntPtr.Zero)CloseHandle(p);if(t!=IntPtr.Zero)CloseHandle(t);}
                }
                details.Add(new {role=target.role,pid=target.pid,tid=target.tid,identity=identity,limitedQuery=ObserveQuery(target.pid),
                    processRights=InspectRights(target.pid,false),threadRights=InspectRights(target.tid,true)});
            }
            Console.WriteLine(Json.Serialize(new {auditor=DescribeHostCreation(me.Handle,me.Id),targets=details}));
        }
        return 0;
    }
}

// A fixed, suspended test fixture. No method in this type resumes a thread.
public sealed class StudioN4HostCreation : IDisposable {
    const uint CreateSuspended=0x00000004, CreateUnicodeEnvironment=0x00000400,
        ExtendedStartupInfoPresent=0x00080000, CreateNoWindow=0x08000000;
    const uint OwnerAndDacl=5, WaitSignaled=0, WaitTimeout=258;
    const uint KillOnJobClose=0x00002000, CleanupExit=0x4e34;
    IntPtr job,process,thread;
    int pid,tid;

    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
        public int Length;public IntPtr Descriptor;public int Inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
        public int Count;public IntPtr Reserved,Desktop,Title;
        public int X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
        public short ShowWindow,ReservedLength;
        public IntPtr ReservedBytes,StdIn,StdOut,StdErr;
    }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedStartupInfo {public StartupInfo Startup;public IntPtr List;}
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {public IntPtr Process,Thread;public int Pid,Tid;}
    [StructLayout(LayoutKind.Sequential)] struct JobBasicLimits {
        public long ProcessTime,JobTime;public uint Flags;public UIntPtr MinWorkingSet,MaxWorkingSet;
        public uint ActiveProcesses;public UIntPtr Affinity;public uint Priority,Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters {
        public ulong ReadOperations,WriteOperations,OtherOperations,ReadBytes,WriteBytes,OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] struct JobExtendedLimits {
        public JobBasicLimits Basic;public IoCounters Io;
        public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;
    }

    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]
    static extern bool LogonUserW(string username,string domain,IntPtr password,int logonType,int provider,out IntPtr token);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]
    static extern bool CreateProcessAsUserW(IntPtr token,string application,StringBuilder command,ref SecurityAttributes processSecurity,
        ref SecurityAttributes threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref ExtendedStartupInfo startup,out ProcessInfo info);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]
    static extern IntPtr CreateJobObjectW(IntPtr attributes,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr handle,int kind,ref JobExtendedLimits limits,int length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr bytes);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,
        IntPtr size,IntPtr previous,IntPtr resultSize);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetHandleInformation(IntPtr handle,out uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool result);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint ms);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetThreadTimes(IntPtr handle,out long creation,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityInfo(IntPtr handle,int objectType,uint fields,out IntPtr owner,out IntPtr group,
        out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);

    static void Require(bool ok,string operation) {if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),operation);}

    static object ReadSecurity(IntPtr handle,string ownerSid) {
        IntPtr owner,group,dacl,sacl,descriptor;
        uint status=GetSecurityInfo(handle,6,OwnerAndDacl,out owner,out group,out dacl,out sacl,out descriptor);
        if(status!=0)throw new Win32Exception((int)status,"GetSecurityInfo");
        try {
            var bytes=new byte[GetSecurityDescriptorLength(descriptor)];
            Marshal.Copy(descriptor,bytes,0,bytes.Length);
            var actual=new RawSecurityDescriptor(bytes,0);
            bool protectedDacl=(actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0;
            const string system="S-1-5-18";
            var wanted=new HashSet<string>{ownerSid,system};
            var entries=new List<object>();
            bool valid=protectedDacl && actual.Owner!=null && actual.Owner.Value==ownerSid && actual.DiscretionaryAcl!=null;
            if(actual.DiscretionaryAcl!=null)foreach(GenericAce item in actual.DiscretionaryAcl) {
                var ace=item as CommonAce;
                if(ace==null){valid=false;continue;}
                string sid=ace.SecurityIdentifier.Value;
                uint mask=unchecked((uint)ace.AccessMask);
                entries.Add(new {sid=sid,type=ace.AceType.ToString(),mask=mask,flags=ace.AceFlags.ToString()});
                if(!wanted.Remove(sid) || ace.AceType!=AceType.AccessAllowed || ace.AceFlags!=AceFlags.None || mask==0)valid=false;
            }
            return new {owner=actual.Owner==null?null:actual.Owner.Value,protectedDacl=protectedDacl,entries=entries,
                expected=valid && wanted.Count==0};
        }finally{LocalFree(descriptor);}
    }

    public static object BrokerIdentity() {
        using(var me=Process.GetCurrentProcess())return new {identity=StudioN4Preflight.DescribeHostCreation(me.Handle,me.Id),
            tid=StudioN4Preflight.NativeThreadId()};
    }

    public static StudioN4HostCreation Start(string executable,string user,string domain,SecureString password,string ownerSid) {
        if(!String.Equals(Path.GetFileName(executable),"StudioN4HostProbe.exe",StringComparison.OrdinalIgnoreCase) ||
            !Path.IsPathRooted(executable) || user!="ClaudeStudioLabA")throw new ArgumentException("Expected the single local A fixture");
        var host=new SecurityIdentifier(ownerSid);
        using(var me=WindowsIdentity.GetCurrent())if(!host.Equals(me.User))throw new ArgumentException("Expected the calling host as owner");
        string sddl="O:"+ownerSid+"D:P(A;;GA;;;"+ownerSid+")(A;;GA;;;SY)";
        var descriptor=new RawSecurityDescriptor(sddl);
        IntPtr token=IntPtr.Zero, passwordPointer=IntPtr.Zero, sd=IntPtr.Zero, environment=IntPtr.Zero, attributes=IntPtr.Zero, jobValue=IntPtr.Zero;
        bool initialized=false;
        var holder=new StudioN4HostCreation();
        try {
            passwordPointer=Marshal.SecureStringToGlobalAllocUnicode(password);
            try{Require(LogonUserW(user,domain,passwordPointer,2,0,out token),"LogonUserW");}
            finally{Marshal.ZeroFreeGlobalAllocUnicode(passwordPointer);passwordPointer=IntPtr.Zero;}

            holder.job=CreateJobObjectW(IntPtr.Zero,null);
            Require(holder.job!=IntPtr.Zero,"CreateJobObjectW");
            var limits=new JobExtendedLimits{Basic=new JobBasicLimits{Flags=KillOnJobClose}};
            Require(Marshal.SizeOf(typeof(JobExtendedLimits))==144,"Unexpected x64 Job ABI");
            Require(SetInformationJobObject(holder.job,9,ref limits,144),"SetInformationJobObject");
            IntPtr bytes=IntPtr.Zero;
            bool sized=InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);
            int sizeError=Marshal.GetLastWin32Error();
            if(sized || sizeError!=122 || bytes.ToInt64()<=0)throw new Win32Exception(sizeError,"Size job attribute list");
            attributes=Marshal.AllocHGlobal(bytes);
            Require(InitializeProcThreadAttributeList(attributes,1,0,ref bytes),"InitializeProcThreadAttributeList");initialized=true;
            jobValue=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobValue,holder.job);
            Require(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x0002000D),jobValue,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"Set only the cleanup Job launch attribute");
            var buffer=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(buffer,0);
            sd=Marshal.AllocHGlobal(buffer.Length);Marshal.Copy(buffer,0,sd,buffer.Length);
            var processSecurity=new SecurityAttributes {Length=Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=sd};
            var threadSecurity=processSecurity;
            var startup=new ExtendedStartupInfo{Startup=new StartupInfo{Count=Marshal.SizeOf(typeof(ExtendedStartupInfo))},List=attributes};
            string systemRoot=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            environment=Marshal.StringToHGlobalUni("SystemRoot="+systemRoot+"\0\0");
            var cmd=new StringBuilder("\""+executable+"\" inert");
            ProcessInfo info;
            Require(CreateProcessAsUserW(token,executable,cmd,ref processSecurity,ref threadSecurity,false,
                CreateSuspended|CreateUnicodeEnvironment|ExtendedStartupInfoPresent|CreateNoWindow,environment,
                Path.GetDirectoryName(executable),ref startup,out info),"CreateProcessAsUserW");
            holder.process=info.Process;holder.thread=info.Thread;holder.pid=info.Pid;holder.tid=info.Tid;
            return holder;
        }catch{holder.Dispose();throw;}
        finally {
            if(initialized)DeleteProcThreadAttributeList(attributes);
            if(attributes!=IntPtr.Zero)Marshal.FreeHGlobal(attributes);
            if(jobValue!=IntPtr.Zero)Marshal.FreeHGlobal(jobValue);
            if(sd!=IntPtr.Zero)Marshal.FreeHGlobal(sd);
            if(environment!=IntPtr.Zero)Marshal.FreeHGlobal(environment);
            if(token!=IntPtr.Zero)CloseHandle(token);
        }
    }

    public object Snapshot(string ownerSid) {
        if(process==IntPtr.Zero || WaitForSingleObject(process,0)!=WaitTimeout)throw new IOException("Suspended fixture is not live");
        uint processFlags,threadFlags;bool inCleanupJob;
        Require(GetHandleInformation(process,out processFlags),"GetHandleInformation(process)");
        Require(GetHandleInformation(thread,out threadFlags),"GetHandleInformation(thread)");
        Require(IsProcessInJob(process,job,out inCleanupJob),"IsProcessInJob(cleanup)");
        long created,exit,kernel,user;
        Require(GetThreadTimes(thread,out created,out exit,out kernel,out user),"GetThreadTimes");
        return new {pid=pid,tid=tid,identity=StudioN4Preflight.DescribeHostCreation(process,pid),
            processSecurity=ReadSecurity(process,ownerSid),threadSecurity=ReadSecurity(thread,ownerSid),
            processInheritable=(processFlags&1)!=0,threadInheritable=(threadFlags&1)!=0,inCleanupJob=inCleanupJob,
            threadUserTime=user,threadKernelTime=kernel,requestedSuspended=true,resumeCalls=0};
    }

    public object TerminateAndWait() {
        if(process==IntPtr.Zero)throw new IOException("No held fixture to terminate");
        if(WaitForSingleObject(process,0)!=WaitTimeout)throw new IOException("Fixture already exited before cleanup");
        Require(TerminateProcess(process,CleanupExit),"TerminateProcess(fixture)");
        uint wait=WaitForSingleObject(process,3000);
        uint threadWait=WaitForSingleObject(thread,1000);
        uint code;
        Require(GetExitCodeProcess(process,out code),"GetExitCodeProcess(fixture)");
        return new {exitCode=code,expectedExitCode=CleanupExit,processSignaled=wait==WaitSignaled,
            threadSignaled=threadWait==WaitSignaled,resumeCalls=0};
    }

    public void Dispose() {
        if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}
        if(process!=IntPtr.Zero){WaitForSingleObject(process,3000);CloseHandle(process);process=IntPtr.Zero;}
        if(thread!=IntPtr.Zero){CloseHandle(thread);thread=IntPtr.Zero;}
    }
}
