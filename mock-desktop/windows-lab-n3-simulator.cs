using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

internal static partial class StudioPsecSimulator {
    static readonly Regex N3Phase=new Regex(@"^(baseline|cold|healthy|outage|silent|crash|recovered)[1-9]?$");

    static object N3Read(string[] args,StudioN3.Settings config,string phase) {
        var http=Task.Run(() => StudioN3.Probe(config,"http",config.P,StudioN3.FreshMarker()));
        var tls=Task.Run(() => StudioN3.Probe(config,"tls",config.P,StudioN3.FreshMarker()));
        var system=SystemProbes(args[1],"a",phase,Port(args[5]),Port(args[6]));
        var ports=new Dictionary<string,object> {
            {"u",TryTcp(config.U)},{"http",TryTcp(config.Http)},{"tls",TryTcp(config.Tls)}
        };
        if(!Task.WaitAll(new Task[]{http,tls},3200))throw new TimeoutException("N3 proxy probe timed out");
        return new Dictionary<string,object> {{"system",system},{"http",http.Result},{"tls",tls.Result},{"directTargets",ports}};
    }

    static T N3Wait<T>(Task<T> pending,Stopwatch lifetime) {
        var timer=Stopwatch.StartNew();
        while(!pending.IsCompleted) {
            GuardCheckLifetime(lifetime);
            if(timer.ElapsedMilliseconds>=14000)throw new TimeoutException("N3 simulator task timeout");
            Application.DoEvents();Thread.Sleep(15);
        }
        return pending.GetAwaiter().GetResult();
    }

    static object N3Native(string[] args,string phase) {
        var changed=(string[])args.Clone();changed[3]=phase;
        using(var child=StartChild("n3native",changed)) {
            try {
                var stdout=child.StandardOutput.ReadToEndAsync();
                if(!child.WaitForExit(11000) || child.ExitCode!=0 || !stdout.Wait(1000))throw new IOException("N3 child failed");
                var result=Json.Deserialize<Dictionary<string,object>>(stdout.Result);
                result["launchedPid"]=child.Id;
                return result;
            } finally {if(!child.HasExited){child.Kill();child.WaitForExit(1500);}}
        }
    }

    static int RunN3Role(string[] args) {
        if(args[2]!="a" || !N3Phase.IsMatch(args[3]))throw new ArgumentException("N3 requires A and a bounded phase");
        StudioN3.ConfigureTls();
        var config=StudioN3.Settings.Read(Path.Combine(Application.StartupPath,"fixture.json"));
        if(config.P!=Port(args[4]) || config.Prefix!=args[1])throw new ArgumentException("N3 endpoint or prefix differs");
        if(args[0]=="n3native") {
            Console.WriteLine(Json.Serialize(N3Read(args,config,args[3])));
            return 0;
        }
        if(args[0]!="window")throw new ArgumentException("Expected N3 simulator window");
        var identity=Identity();
        if(!(bool)identity["container"] || !(bool)identity["inJob"])throw new InvalidOperationException("N3 window must be in A container and job");
        var lifetime=Stopwatch.StartNew();
        var label=new Label {Dock=DockStyle.Fill,Text="A · Synthetic HTTP and HTTPS\r\nWaiting for local test controls"};
        using(var form=new Form {Text="Claude Studio | N3 simulator | A",Width=440,Height=155}) {
            form.Controls.Add(label);form.Show();Application.DoEvents();
            identity["visible"]=IsWindowVisible(form.Handle);identity["windowHandle"]=form.Handle.ToInt64();
            GuardAtomicJson("sim-ready",identity);
            StudioN3.Held oldHttp=null,oldTls=null;
            try {
                for(int number=1;;number++) {
                    string path="n3cmd-"+number+".json";
                    var waiting=Stopwatch.StartNew();
                    while(!File.Exists(path)) {
                        GuardCheckLifetime(lifetime);
                        if(waiting.ElapsedMilliseconds>=25000)throw new TimeoutException("N3 command timeout");
                        Application.DoEvents();Thread.Sleep(15);
                    }
                    if(new FileInfo(path).Length>1024)throw new ArgumentException("N3 command length");
                    var command=Json.Deserialize<Dictionary<string,string>>(File.ReadAllText(path));
                    string action=command["action"],phase=command["phase"];
                    if(!N3Phase.IsMatch(phase))throw new ArgumentException("Unexpected N3 phase");
                    object result=null;
                    switch(action) {
                        case "probe": result=N3Wait(Task.Run(() => N3Read(args,config,phase)),lifetime);break;
                        case "native": result=N3Wait(Task.Run(() => N3Native(args,phase)),lifetime);break;
                        case "hold":
                            if(oldHttp!=null)oldHttp.Dispose();
                            if(oldTls!=null)oldTls.Dispose();
                            oldHttp=new StudioN3.Held(config,"http",config.P);
                            oldTls=new StudioN3.Held(config,"tls",config.P);
                            break;
                        case "held":
                            if(oldHttp==null || oldTls==null)throw new InvalidOperationException("No held streams");
                            result=new Dictionary<string,object> {{"http",oldHttp.Snapshot()},{"tls",oldTls.Snapshot()}};
                            break;
                        case "finish":
                            identity["finishSequence"]=number;
                            identity["finishPhase"]=phase;
                            break;
                        default: throw new ArgumentException("Unexpected N3 action");
                    }
                    // The final acknowledgement travels in the process output.
                    // The container can exit before the host observes a file.
                    if(action=="finish")break;
                    if(action=="probe")label.Text="A · Synthetic HTTP and HTTPS\r\nPhase "+phase;
                    GuardAtomicJson("n3result-"+number+".json",new Dictionary<string,object> {
                        {"number",number},{"action",action},{"phase",phase},{"data",result},
                        {"identity",identity},{"utc",DateTime.UtcNow.ToString("o")}
                    });
                }
            } finally {if(oldHttp!=null)oldHttp.Dispose();if(oldTls!=null)oldTls.Dispose();}
        }
        Console.WriteLine(Json.Serialize(identity));
        return 0;
    }
}
