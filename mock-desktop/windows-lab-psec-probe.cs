using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal static partial class StudioPsecSimulator {
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int size, out int required);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool inJob);
    [DllImport("kernel32.dll")]
    static extern int GetCurrentThreadId();
    [DllImport("user32.dll")]
    static extern bool IsWindowVisible(IntPtr window);
    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern int DnsQuery_W(string name, ushort type, uint options, IntPtr server,
                                 out IntPtr records, IntPtr reserved);
    [DllImport("dnsapi.dll")]
    static extern void DnsRecordListFree(IntPtr records, int freeType);
    [StructLayout(LayoutKind.Sequential)]
    struct AddrInfo {
        public int flags, family, socketType, protocol;
        public UIntPtr addrlen;
        public IntPtr canonname, addr, next;
    }
    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern int GetAddrInfoW(string node, string service, ref AddrInfo hints, out IntPtr results);
    [DllImport("ws2_32.dll", ExactSpelling = true)]
    static extern void FreeAddrInfoW(IntPtr results);
    // The Windows lab compiles this probe for x64.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct WsaData {
        public ushort version, highVersion, maxSockets, maxUdpDatagrams;
        public IntPtr vendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string description;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        public string systemStatus;
    }
    [DllImport("ws2_32.dll", ExactSpelling = true)]
    static extern int WSAStartup(ushort requestedVersion, out WsaData data);
    [DllImport("ws2_32.dll", ExactSpelling = true)]
    static extern int WSACleanup();

    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();

    // Verified locally with DeriveCapabilitySidsFromName("networkLoopback").
    const string NetworkLoopbackSid = "S-1-15-3-1024-820624432-2503302554-1536879699-4049119443-112573677-3799174643-950279649-4267032225";

    static string[] ReadCapabilitySids(IntPtr token) {
        const int tokenCapabilities = 30;
        int bytes;
        GetTokenInformation(token, tokenCapabilities, IntPtr.Zero, 0, out bytes);
        if (bytes < sizeof(int)) throw new System.ComponentModel.Win32Exception();
        IntPtr groups = Marshal.AllocHGlobal(bytes);
        try {
            if (!GetTokenInformation(token, tokenCapabilities, groups, bytes, out bytes))
                throw new System.ComponentModel.Win32Exception();
            var capabilities = new List<string>();
            int count = Marshal.ReadInt32(groups);
            if (count < 0 || count > (bytes - IntPtr.Size) / (2 * IntPtr.Size))
                throw new InvalidDataException("Invalid token capability count");
            for (int i = 0; i < count; i++) {
                var sid = new SecurityIdentifier(Marshal.ReadIntPtr(groups, IntPtr.Size + i * 2 * IntPtr.Size)).Value;
                capabilities.Add(sid);
            }
            return capabilities.ToArray();
        } finally { Marshal.FreeHGlobal(groups); }
    }

    static string[] SelectNetworkCapabilities(string[] capabilities) {
        return Array.FindAll(capabilities, sid => sid == "S-1-15-3-1" ||
            sid == "S-1-15-3-2" || sid == "S-1-15-3-3" || sid == NetworkLoopbackSid);
    }

    static Dictionary<string, object> Identity() {
        using (var id = WindowsIdentity.GetCurrent())
        using (var self = Process.GetCurrentProcess()) {
            int bytes;
            IntPtr field = Marshal.AllocHGlobal(1024);
            try {
                if (!GetTokenInformation(id.Token, 29, field, 1024, out bytes)) throw new System.ComponentModel.Win32Exception();
                bool container = Marshal.ReadInt32(field) != 0;
                string sid = null;
                if (container) {
                    if (!GetTokenInformation(id.Token, 31, field, 1024, out bytes)) throw new System.ComponentModel.Win32Exception();
                    sid = new SecurityIdentifier(Marshal.ReadIntPtr(field)).Value;
                }
                bool job;
                if (!IsProcessInJob(self.Handle, IntPtr.Zero, out job)) throw new System.ComponentModel.Win32Exception();
                var capabilities = container ? ReadCapabilitySids(id.Token) : new string[0];
                return new Dictionary<string,object> {{"pid",self.Id},{"session",self.SessionId},{"userSid",id.User.Value},
                    {"startTicks",self.StartTime.ToUniversalTime().Ticks},
                    {"container",container},{"containerSid",sid},{"inJob",job},
                    {"capabilitySids",capabilities},{"networkCapabilities",SelectNetworkCapabilities(capabilities)}};
            } finally { Marshal.FreeHGlobal(field); }
        }
    }

    static string TryTcp(int port, string address = null) {
        using (var socket = new TcpClient(AddressFamily.InterNetwork)) {
            try {
                var connect = socket.BeginConnect(address==null ? IPAddress.Loopback : IPAddress.Parse(address), port, null, null);
                using (var completed = connect.AsyncWaitHandle) {
                    if (!completed.WaitOne(1600)) return "timeout";
                    socket.EndConnect(connect);
                }
                socket.GetStream().WriteByte(85);
                return "sent";
            } catch (SocketException e) { return e.SocketErrorCode.ToString(); }
        }
    }
    static string TryUdp(int port) {
        using (var socket = new UdpClient(AddressFamily.InterNetwork)) {
            try {
                socket.Send(new byte[] {85}, 1, new IPEndPoint(IPAddress.Loopback,port));
                return "submitted";
            } catch (SocketException e) { return e.SocketErrorCode.ToString(); }
        }
    }
    static IDictionary<string,object> SystemProbes(string prefix, string role, string phase, int tcp, int udp) {
        var result = Identity();
        result["directTcp"] = TryTcp(tcp);
        result["directUdp"] = TryUdp(udp);
        if(File.Exists("guard-extra.json")) {
            var extra=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText("guard-extra.json"));
            result["directUdpProxy"]=TryUdp(Port(extra["proxyPort"].ToString()));
            result["directAlternate"]=TryTcp(Port(extra["alternatePort"].ToString()),"127.0.0.2");
            if(extra.ContainsKey("localAddress")) result["directLocal"]=TryTcp(Port(extra["localPort"].ToString()),(string)extra["localAddress"]);
        }
        result["dnsQueryStatus"] = QueryDns(ProbeName(prefix, role, "dns", phase));
        result["getAddrInfoStatus"] = QueryAddr(ProbeName(prefix, role, "addr", phase));
        return result;
    }

    static string ProbeName(string prefix, string role, string api, string phase) {
        return prefix + "-" + role + "-" + api + "-" + phase + ".test.";
    }

    static int QueryDns(string name) {
        IntPtr records;
        int status = DnsQuery_W(name, 1, 0x48, IntPtr.Zero, out records, IntPtr.Zero);
        if (records != IntPtr.Zero) DnsRecordListFree(records, 1);
        return status;
    }

    static int QueryAddr(string name) {
        WsaData sockets;
        int startup = WSAStartup(0x0202, out sockets);
        if (startup != 0) throw new SocketException(startup);
        try {
            var hints = new AddrInfo {family = (int)AddressFamily.InterNetwork};
            IntPtr addresses;
            int status = GetAddrInfoW(name, null, ref hints, out addresses);
            if (addresses != IntPtr.Zero) FreeAddrInfoW(addresses);
            return status;
        } finally { WSACleanup(); }
    }

    static IDictionary<string,object> ResolverProbe(string prefix, string role, string api, string phase) {
        var result = Identity();
        string name = ProbeName(prefix, role, api, phase);
        result["name"] = name;
        result["role"] = role;
        result["api"] = api;
        result["phase"] = phase;
        result["tid"] = GetCurrentThreadId();
        result["startedUtc"] = DateTime.UtcNow.ToString("o");
        result["status"] = api == "dns" ? QueryDns(name) : QueryAddr(name);
        result["finishedUtc"] = DateTime.UtcNow.ToString("o");
        return result;
    }
    static string WindowTarget(string prefix, string role, string phase) {
        return "http://" + prefix + "-" + role + "-window-" + phase + ".test/studio-probe?";
    }

    static string WindowHttp(string prefix, string role, string phase, int port, Dictionary<string,object> evidence = null) {
        var uri = new Uri(WindowTarget(prefix, role, phase) + phase);
        var request = (HttpWebRequest)WebRequest.Create(uri);
        request.Proxy = new WebProxy("http://127.0.0.1:" + port, false);
        request.AllowAutoRedirect = false;
        request.Timeout = 2300;
        request.ReadWriteTimeout = 2300;
        try {
            using (var response = (HttpWebResponse)request.GetResponse())
            using (var body = new StreamReader(response.GetResponseStream())) {
                return response.StatusCode == HttpStatusCode.OK && body.ReadToEnd() == prefix ? "matched" : "unexpected-response";
            }
        } catch (WebException error) {
            if (evidence != null) {
                evidence["operation"] = "HttpWebRequest.GetResponse";
                evidence["status"] = error.Status.ToString();
                for (Exception cause = error.InnerException; cause != null; cause = cause.InnerException) {
                    var socketError = cause as SocketException;
                    if (socketError != null) {
                        evidence["nativeError"] = socketError.NativeErrorCode;
                        evidence["socketError"] = socketError.SocketErrorCode.ToString();
                        break;
                    }
                }
            }
            return error.Status.ToString();
        }
    }

    static void RunLoopbackListener(string prefix, string role, string phase, int lifetime = 42000) {
        var ready = Identity();
        var result = new Dictionary<string,object>();
        Socket socket = null;
        string operation = "Socket";
        try {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            operation = "ExclusiveAddressUse";
            socket.ExclusiveAddressUse = true;
            operation = "Bind";
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)socket.LocalEndPoint).Port;
            Port(port.ToString());
            ready["port"] = port;
            ready["bound"] = true;
            operation = "Listen";
            socket.Listen(4);
            ready["listening"] = true;
        } catch (SocketException error) {
            ready["operation"] = operation;
            ready["nativeError"] = error.NativeErrorCode;
            ready["socketError"] = error.SocketErrorCode.ToString();
        }
        using (socket) {
            Console.WriteLine(Json.Serialize(ready));
            if (!ready.ContainsKey("listening")) {
                Console.WriteLine(Json.Serialize(result));
                return;
            }
            int accepted = 0, markerSent = 0, hostRequests = 0, windowRequests = 0;
            int readErrors = 0;
            var stop = System.Threading.Tasks.Task.Factory.StartNew(() => Console.In.ReadLine());
            string target = WindowTarget(prefix, role, phase);
            var timer = Stopwatch.StartNew();
            while (!stop.IsCompleted && timer.ElapsedMilliseconds < lifetime) {
                if (!socket.Poll(100000, SelectMode.SelectRead)) continue;
                using (var client = socket.Accept())
                using (var stream = new NetworkStream(client)) {
                    accepted++;
                    stream.ReadTimeout = 800;
                    stream.WriteTimeout = 800;
                    try {
                        string request = ReadHttpHeader(stream);
                        if (request.StartsWith("GET " + target + "host HTTP/1.", StringComparison.Ordinal)) hostRequests++;
                        else {
                            bool matched=false;
                            foreach(string candidate in lifetime>42000 ? new[]{"baseline","healthy","stopped","outage","recovered"} : new[]{phase})
                                if(request.StartsWith("GET "+WindowTarget(prefix,role,candidate)+candidate+" HTTP/1.",StringComparison.Ordinal)) {matched=true;break;}
                            if(!matched) continue;
                            windowRequests++;
                        }
                        var response = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " +
                            prefix.Length + "\r\n\r\n" + prefix);
                        stream.Write(response, 0, response.Length);
                        markerSent++;
                    } catch (IOException) { readErrors++; }
                }
            }
            result["accepted"] = accepted;
            result["windowRequests"] = windowRequests;
            result["hostRequests"] = hostRequests;
            result["markerSent"] = markerSent;
            result["readErrors"] = readErrors;
            result["stoppedByParent"] = stop.IsCompleted;
        }
        Console.WriteLine(Json.Serialize(result));
    }

    static string ReadHttpHeader(Stream stream) {
        var header = new StringBuilder();
        var buffer = new byte[512];
        var timer = Stopwatch.StartNew();
        while (header.Length < 4096 && timer.ElapsedMilliseconds < 1600) {
            int count = stream.Read(buffer, 0, buffer.Length);
            if (count == 0) break;
            header.Append(Encoding.ASCII.GetString(buffer, 0, count));
            if (header.ToString().Contains("\r\n\r\n")) return header.ToString();
        }
        return "";
    }

    static Process StartChild(string mode, string[] args, bool useInput = false) {
        using (var self = Process.GetCurrentProcess()) {
            var start = new ProcessStartInfo(self.MainModule.FileName, mode + " " + String.Join(" ", args, 1, args.Length - 1));
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardInput = useInput;
            return Process.Start(start);
        }
    }

    static IDictionary<string,object> ReadListenerLine(Process listener) {
        var line = listener.StandardOutput.ReadLineAsync();
        if (!line.Wait(4000) || line.Result == null) throw new InvalidOperationException("Listener did not produce evidence");
        return (IDictionary<string,object>)Json.DeserializeObject(line.Result);
    }
    static void WaitGuardSignal(string name) {
        var timer=Stopwatch.StartNew();
        while(!File.Exists(name)) {
            if(File.Exists("guard-abort")) throw new OperationCanceledException("Host aborted guard experiment");
            if(timer.ElapsedMilliseconds>25000) throw new TimeoutException("Guard signal timed out: "+name);
            Application.DoEvents();Thread.Sleep(40);
        }
        if(File.Exists("guard-abort")) throw new OperationCanceledException("Host aborted guard experiment");
    }
    static object RunGuardCheckpoint(string[] args,int port,string phase,string file) {
        var changed=(string[])args.Clone(); changed[3]=phase;
        var result=Identity();
        result["windowHttp"]=WindowHttp(args[1],args[2],phase,port);
        using(var child=StartChild("native",changed)) {
            var output=child.StandardOutput.ReadToEndAsync();
            if(!child.WaitForExit(14000)) {child.Kill();throw new TimeoutException("Guard child timed out");}
            if(child.ExitCode!=0 || !output.Wait(1500)) throw new IOException("Guard child failed");
            result["native"]=Json.DeserializeObject(output.Result);
        }
        File.WriteAllText(file+".tmp",Json.Serialize(result));File.Move(file+".tmp",file);
        return result;
    }
    static void RunWindow(string[] args, int proxyPort) {
        var result = Identity();
        if (!(bool)result["container"] || !(bool)result["inJob"]) throw new InvalidOperationException("Window is outside the test container");
        using (var form = new Form {Text="Claude Studio | ProcessContainer | " + args[2].ToUpperInvariant(), Width=440, Height=155}) {
            var label = new Label {Dock=DockStyle.Fill, Text="Claude Studio simulator   " + args[2].ToUpperInvariant() + "\r\nProxy test: " + args[3]};
            form.Controls.Add(label);
            form.Show();
            Application.DoEvents();
            result["visible"] = IsWindowVisible(form.Handle);
            result["configuredProxyMatches"] = String.Equals((Environment.GetEnvironmentVariable("HTTP_PROXY") ?? "").TrimEnd('/'),
                "http://127.0.0.1:" + proxyPort, StringComparison.OrdinalIgnoreCase);
            bool loopback = args.Length == 8 && args[7] == "loopback";
            bool guardMode=args.Length==8 && (args[7]=="portguard" || args[7]=="portguardflow");
            bool wantListener=loopback || guardMode;
            using (var listener = wantListener ? StartChild("listener", args, true) : null) {
                IDictionary<string,object> listenerReady = null;
                if (wantListener) {
                    listenerReady = ReadListenerLine(listener);
                    result["listenerReady"] = listenerReady;
                    result["windowHandle"] = form.Handle.ToInt64();
                }
                string cwd = Environment.CurrentDirectory;
                string readyPath = Path.Combine(cwd, "sim-ready");
                File.WriteAllText(readyPath + ".tmp", Json.Serialize(result));
                File.Move(readyPath + ".tmp", readyPath);
                if(guardMode) {
                    WaitGuardSignal("guard-baseline-go");
                    result["guardBaseline"]=RunGuardCheckpoint(args,proxyPort,"baseline","guard-baseline-result.json");
                    WaitGuardSignal("guard-gate-go");
                    result["guardGate"]=RunGuardCheckpoint(args,proxyPort,"stopped","guard-gate-result.json");
                }
                var readyTimer = Stopwatch.StartNew();
                while (!File.Exists(Path.Combine(cwd, "host-go"))) {
                    if(File.Exists("guard-abort")) throw new OperationCanceledException("Host aborted guard experiment");
                    if (readyTimer.ElapsedMilliseconds > 30000) throw new TimeoutException("Host control did not complete");
                    Application.DoEvents(); Thread.Sleep(60);
                }
                using (var child = StartChild("native", args)) {
                    var output = child.StandardOutput.ReadToEndAsync();
                    if (loopback && listenerReady.ContainsKey("listening")) {
                        var httpEvidence = new Dictionary<string,object>();
                        var http = WindowHttp(args[1], args[2], args[3], (int)listenerReady["port"], httpEvidence);
                        result["windowHttp"] = http;
                        result["windowHttpError"] = httpEvidence;
                        if (http == "matched") {
                            label.Text += "\r\nReceived: " + args[1];
                            result["displayedMarker"] = label.Text.EndsWith(args[1], StringComparison.Ordinal) && IsWindowVisible(form.Handle);
                        }
                    } else {
                        var httpEvidence = new Dictionary<string,object>();
                        result["windowHttp"] = loopback ? "listener-unavailable" :
                            (args.Length == 8 && args[7] != "hostloopback" && !guardMode ? "not-configured" : WindowHttp(args[1],args[2],args[3],proxyPort,httpEvidence));
                        result["windowHttpError"] = httpEvidence;
                    }
                    var timer=Stopwatch.StartNew();
                    while ((!child.HasExited || timer.ElapsedMilliseconds < 1200) && timer.ElapsedMilliseconds < 14000) {
                        Application.DoEvents(); Thread.Sleep(30);
                    }
                    if (!child.HasExited) { child.Kill(); throw new TimeoutException("Native child timed out"); }
                    if (child.ExitCode != 0 || !output.Wait(1500)) throw new InvalidOperationException("Native child failed: " + child.ExitCode);
                    result["native"] = Json.DeserializeObject(output.Result);
                }
                if(args.Length==8 && args[7]=="portguardflow") RunPortGuardFlow(args,proxyPort,result);
                if (wantListener) {
                    listener.StandardInput.Close();
                    result["listener"] = ReadListenerLine(listener);
                    if (!listener.WaitForExit(2000) || listener.ExitCode != 0)
                        throw new InvalidOperationException("Listener failed to exit cleanly");
                }
            }
        }
        Console.WriteLine(Json.Serialize(result));
    }
    static int Port(string text) {
        int value = Int32.Parse(text);
        if (value < 40000 || value > 65535) throw new ArgumentOutOfRangeException("port");
        return value;
    }
    [STAThread]
    static int Main(string[] args) {
        try {
#if N3_PROTOCOL
            if(args.Length==8 && args[7]=="n3protocol")return RunN3Role(args);
#endif
#if N4_ACCOUNT_MATCH
            if (args.Length > 0 && args[0] == "n4-account-match") return RunAccountMatch(args);
#if N3_PROTOCOL
            if (args.Length > 0 && (args[0] == "n4-account-proxy" || args[0] == "n4-proxy-aux" || args[0] == "n4-proxy-ordinary" ||
                args[0] == "n4-proxy-pipe-test")) return RunN4ProxyControl(args);
            if (args.Length == 3 && args[0] == "n4-proxy-bind-control" && Regex.IsMatch(args[1],"^[a-f0-9]{32}$")) {
                var identity=Identity();
                if ((bool)identity["container"]) throw new InvalidOperationException("Expected ordinary bind control");
                WriteN4ProxyFrame(args[1],0,"bind",identity,GuardBindProbe(args[2],"0.0.0.0","exclusive"));
                Thread.Sleep(4000);
                return 0;
            }
#endif
#endif
            if (args.Length == 4 && args[0] == "n2-bind") {
                Console.WriteLine(Json.Serialize(GuardBindProbe(args[1],args[2],args[3])));
                return 0;
            }
            if ((args.Length == 4 || args.Length == 5) && args[0] == "resolver" && Regex.IsMatch(args[1], "^studio-[a-f0-9]{16}$") &&
                Regex.IsMatch(args[2], "^[ah]$") && Regex.IsMatch(args[3], "^(dns|addr)$") &&
                (args.Length == 4 || Regex.IsMatch(args[4], "^(baseline|healthy|outage|recovered)$"))) {
                Console.WriteLine(Json.Serialize(ResolverProbe(args[1], args[2], args[3], args.Length == 4 ? "baseline" : args[4])));
                return 0;
            }
            if ((args.Length != 7 && (args.Length != 8 || (args[7] != "networkless" && args[7] != "loopback" && args[7] != "hostloopback" && args[7] != "portguard" && args[7] != "portguardflow"))) ||
                !Regex.IsMatch(args[1], "^studio-[a-f0-9]{16}$") ||
                !Regex.IsMatch(args[2], "^[abh]$") || !Regex.IsMatch(args[3], "^(baseline|healthy|outage|stopped|recovered|cold|crash|silent|fake)[1-9]?$")) {
                throw new ArgumentException("Expected lab arguments");
            }
            int proxy=args[0]=="guardproxy" && args[4]=="0" ? 0 : Port(args[4]), tcp=Port(args[5]), udp=Port(args[6]);
            if (args[0] == "native") {
                var result=SystemProbes(args[1],args[2],args[3],tcp,udp);
                if(args.Length==8 && (args[7]=="portguard" || args[7]=="portguardflow")) result["proxyHttp"]=WindowHttp(args[1],args[2],args[3],proxy);
                Console.WriteLine(Json.Serialize(result));
            }
            else if (args[0] == "window") RunWindow(args,proxy);
            else if (args[0] == "listener" && args.Length == 8 && (args[7] == "loopback" || args[7] == "portguard" || args[7] == "portguardflow")) RunLoopbackListener(args[1], args[2], args[3],args[7]=="portguardflow"?180000:42000);
            else if (args[0] == "hostproxy" && args.Length == 8 && args[7] == "hostloopback") RunLoopbackListener(args[1], args[2], args[3], 120000);
            else if (args[0] == "guardproxy" && args.Length == 8 && args[7] == "portguardflow") RunGuardHostProxy(args[1],proxy);
            else throw new ArgumentException("Unknown probe");
            return 0;
        } catch (Exception error) {
            Console.Error.WriteLine(error.GetType().Name + ": " + error.Message);
            return 1;
        }
    }
}
