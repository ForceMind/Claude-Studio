using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

internal static partial class StudioPsecSimulator
{
    static int RunAccountMatch(string[] args)
    {
        if (args.Length != 7 || !Regex.IsMatch(args[1], "^studio-[a-f0-9]{16}$") ||
            !Regex.IsMatch(args[2], "^(psec|ordinary|host)$") ||
            !Regex.IsMatch(args[3], "^(baseline|blocked|cold|restored|healthy[1-4]|fault[1-4])$") ||
            (args[3] == "cold" && args[2] == "ordinary") || !Regex.IsMatch(args[6], "^[a-f0-9]{32}$"))
            throw new ArgumentException("Expected one scoped N4 probe attempt");

        int tcpPort = Port(args[4]), udpPort = Port(args[5]);
        var identity = Identity();
        byte[] marker = Encoding.ASCII.GetBytes(args[6]);
        string name = args[1] + "-" + args[2] + "-" + args[3];
        long started = Stopwatch.GetTimestamp();
        var tcp = SendAccountMarker(tcpPort, marker, true);
        var udp = SendAccountMarker(udpPort, marker, false);
        // The caller starts trace/canaries before launching this process. The probe
        // never waits for a release signal before attempting either network path.
        var dns = ReadAccountDns(name + "-dns.test.", true);
        var addr = ReadAccountDns(name + "-addr.test.", false);
        Console.WriteLine("N4-PROBE:" + Json.Serialize(new {
            identity, phase=args[3], role=args[2], marker=args[6], firstProbeTick=started,
            tickFrequency=Stopwatch.Frequency, tcp, udp, dnsQueries=new[] { dns, addr }
        }));
        Console.Out.Flush();
        if (args[2] != "host") Thread.Sleep(4000); // Corroborate live token after network probes, never before them.
        return 0;
    }

    static object SendAccountMarker(int port, byte[] marker, bool tcp)
    {
        var endpoint = new IPEndPoint(IPAddress.Loopback, port);
        long started = Stopwatch.GetTimestamp();
        int sent = 0;
        int error = 0;
        using (var socket = new Socket(AddressFamily.InterNetwork,
            tcp ? SocketType.Stream : SocketType.Dgram, tcp ? ProtocolType.Tcp : ProtocolType.Udp)) {
            try {
                socket.SendTimeout = 1000;
                if (tcp) {
                    IAsyncResult connect = socket.BeginConnect(endpoint, null, null);
                    using (WaitHandle wait = connect.AsyncWaitHandle) {
                        if (!wait.WaitOne(1500)) throw new SocketException((int)SocketError.TimedOut);
                        socket.EndConnect(connect);
                    }
                    while (sent < marker.Length) {
                        int written = socket.Send(marker, sent, marker.Length - sent, SocketFlags.None);
                        if (written == 0) throw new SocketException((int)SocketError.ConnectionReset);
                        sent += written;
                    }
                } else {
                    sent = socket.SendTo(marker, endpoint);
                }
            } catch (SocketException exception) { error = exception.NativeErrorCode; }
        }
        return new { endpoint=endpoint.ToString(), submittedBytes=sent, nativeError=error,
            startedTick=started, completedTick=Stopwatch.GetTimestamp() };
    }

    static object ReadAccountDns(string name, bool dns)
    {
        long started = Stopwatch.GetTimestamp();
        int status = dns ? QueryDns(name) : QueryAddr(name);
        return new { name, api=dns ? "DnsQuery_W" : "GetAddrInfoW", status,
            tid=GetCurrentThreadId(), startedTick=started, completedTick=Stopwatch.GetTimestamp() };
    }

#if N3_PROTOCOL
    static void WriteN4ProxyFrame(string nonce, int sequence, string action, object identity, object data)
    {
        Console.WriteLine("N4-PROXY:" + Json.Serialize(new {
            nonce, sequence, action, identity, data, tick=Stopwatch.GetTimestamp(), frequency=Stopwatch.Frequency
        }));
        Console.Out.Flush();
    }

    static object RunN4ProxyPair(StudioN3.Settings config, string first, string second)
    {
        var a=Task.Run(() => StudioN3.Probe(config,first,config.P,StudioN3.FreshMarker(),1200));
        var b=Task.Run(() => StudioN3.Probe(config,second,config.P,StudioN3.FreshMarker(),1200));
        if(!Task.WaitAll(new Task[] {a,b},2000)) throw new TimeoutException("N4 synthetic protocol deadline");
        return new { http=a.Result, tls=b.Result };
    }

    static int RunN4ProxyControl(string[] args)
    {
        bool pipeTest=args[0]=="n4-proxy-pipe-test";
        bool auxiliary=args[0]=="n4-proxy-aux";
        bool ordinary=args[0]=="n4-proxy-ordinary";
        if (args.Length != (pipeTest?2:12) || !Regex.IsMatch(args[1],"^[a-f0-9]{32}$"))
            throw new ArgumentException("Invalid N4 proxy command-line scope");
        string nonce=args[1];
        var identity=Identity();
        StudioN3.Settings config=null;
        int tcp=0, udp=0;
        if (!pipeTest) {
            if ((bool)identity["container"]==ordinary || (!ordinary && !(bool)identity["inJob"]))
                throw new InvalidOperationException("N4 proxy probe requires its reviewed container and job");
            config=new StudioN3.Settings {
                Prefix=args[2], P=Port(args[5]), U=Port(args[6]), Http=Port(args[7]), Tls=Port(args[8]),
                Half=Port(args[9]), WrongCertificate=Port(args[10]), Pin=args[11]
            };
            config.Validate();
            tcp=Port(args[3]); udp=Port(args[4]);
            int[] ports={tcp,udp,config.P,config.U,config.Http,config.Tls,config.Half,config.WrongCertificate};
            if (ports.Distinct().Count()!=ports.Length) throw new ArgumentException("N4 synthetic endpoints overlap");
            if (ordinary || auxiliary) {
                StudioN3.ConfigureTls();
                WriteN4ProxyFrame(nonce,0,ordinary?"ordinary":"aux",identity,RunN4ProxyPair(config,"http","tls"));
                if (ordinary) Thread.Sleep(4000);
                else Console.ReadLine(); // The primary keeps stdin open while the host checks this token.
                return 0;
            }
            // First business paths run before any controller input or permission to open E.
            WriteN4ProxyFrame(nonce,0,"cold",identity,RunN4ProxyDirect(config,0,tcp,udp));
            StudioN3.ConfigureTls();
        } else WriteN4ProxyFrame(nonce,0,"ready",identity,null);

        StudioN3.Held http=null, tls=null;
        Process auxiliaryProcess=null;
        try {
            for (int sequence=1;sequence<=64;sequence++) {
                string line=Console.ReadLine();
                if (line==null) return 0;
                string[] frame=line.Length<=80?line.Split(' '):new string[0];
                if (frame.Length!=3 || frame[0]!=nonce || frame[1]!=sequence.ToString(CultureInfo.InvariantCulture))
                    throw new ArgumentException("N4 proxy command nonce or sequence differs");
                string action=frame[2];
                object data=null;
                if (action=="finish") {
                    WriteN4ProxyFrame(nonce,sequence,action,identity,null);
                    return 0;
                }
                if (pipeTest && action!="ping") throw new ArgumentException("Invalid host-only pipe test action");
                switch (action) {
                    case "ping": break;
                    case "probe": data=RunN4ProxyPair(config,"http","tls"); break;
                    case "trust": data=RunN4ProxyPair(config,"wrong-cert","wrong-host"); break;
                    case "direct": data=RunN4ProxyDirect(config,sequence,tcp,udp); break;
                    case "aux":
                        if (auxiliaryProcess!=null) throw new InvalidOperationException("N4 auxiliary probe is already running");
                        auxiliaryProcess=StartChild("n4-proxy-aux",args,true);
                        var reading=auxiliaryProcess.StandardOutput.ReadLineAsync();
                        if (!reading.Wait(3500) || reading.Result==null || auxiliaryProcess.HasExited ||
                            !reading.Result.StartsWith("N4-PROXY:",StringComparison.Ordinal))
                            throw new InvalidOperationException("N4 auxiliary probe did not return a live receipt");
                        data=new { launchedPid=auxiliaryProcess.Id, receipt=Json.DeserializeObject(reading.Result.Substring(9)) };
                        break;
                    case "aux-done":
                        if (auxiliaryProcess==null) throw new InvalidOperationException("No N4 auxiliary probe is active");
                        bool exited=EndN4Auxiliary(auxiliaryProcess);
                        auxiliaryProcess=null;
                        if (!exited) throw new InvalidOperationException("N4 auxiliary probe did not exit cleanly");
                        break;
                    case "hold":
                        if (http!=null) http.Dispose();
                        if (tls!=null) tls.Dispose();
                        http=new StudioN3.Held(config,"http",config.P);
                        tls=new StudioN3.Held(config,"tls",config.P);
                        break;
                    case "held":
                        if (http==null || tls==null) throw new InvalidOperationException("No N4 held flows");
                        data=new { http=http.Snapshot(), tls=tls.Snapshot() };
                        break;
                    default: throw new ArgumentException("Unknown N4 proxy action");
                }
                WriteN4ProxyFrame(nonce,sequence,action,identity,data);
            }
            throw new TimeoutException("N4 proxy command budget exhausted");
        } finally {
            if (http!=null) http.Dispose();
            if (tls!=null) tls.Dispose();
            if (auxiliaryProcess!=null) EndN4Auxiliary(auxiliaryProcess);
        }
    }

    static bool EndN4Auxiliary(Process child)
    {
        using (child) {
            if (!child.HasExited) {
                child.StandardInput.Close();
                if (!child.WaitForExit(900)) {
                    child.Kill();
                    child.WaitForExit(900);
                    return false;
                }
            }
            return child.ExitCode==0;
        }
    }

    static object RunN4ProxyDirect(StudioN3.Settings config,int sequence,int tcp,int udp)
    {
        long firstProbeTick=Stopwatch.GetTimestamp();
        string marker=Guid.NewGuid().ToString("N");
        byte[] bytes=Encoding.ASCII.GetBytes(marker);
        var tcpResult=SendAccountMarker(tcp,bytes,true);
        var udpResult=SendAccountMarker(udp,bytes,false);
        var targets=new[] {config.U,config.Http,config.Tls,config.Half,config.WrongCertificate}
            .Select(port => Task.Run(() => SendAccountMarker(port,bytes,true))).ToArray();
        if (!Task.WaitAll(targets,2200)) throw new TimeoutException("N4 direct-target deadline");
        string domain=config.Prefix+"-psec-cold"+sequence.ToString(CultureInfo.InvariantCulture);
        return new { firstProbeTick, marker, tcp=tcpResult, udp=udpResult, targets=targets.Select(probe=>probe.Result).ToArray(),
            dnsQueries=new[] { ReadAccountDns(domain+"-dns.test.",true), ReadAccountDns(domain+"-addr.test.",false) } };
    }
#endif
}
