using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

// A deliberately small fixture. Every socket is IPv4 loopback and every route
// comes from the synthetic topology, never from a caller-supplied destination.
internal static class StudioN3 {
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static readonly Regex PrefixFormat = new Regex(@"^studio-[a-f0-9]{16}$");
    static readonly Regex MarkerFormat = new Regex(@"^[a-f0-9]{16}$");
    static Dictionary<string,object> Row(params object[] pairs) {
        var row = new Dictionary<string,object>();
        for (int i=0; i<pairs.Length; i+=2) row.Add((string)pairs[i],pairs[i+1]);
        return row;
    }

    internal sealed class Settings {
        public string Prefix { get; set; }
        public int P { get; set; }
        public int U { get; set; }
        public int Http { get; set; }
        public int Tls { get; set; }
        public int Half { get; set; }
        public int WrongCertificate { get; set; }
        public string Pin { get; set; }
        public string Host { get { return Prefix + "-a-window-healthy.test"; } }
        public string WrongHost { get { return Prefix + "-a-window-fake.test"; } }
        public void Validate() {
            int[] ports = {P,U,Http,Tls,Half,WrongCertificate};
            if (Prefix == null || !PrefixFormat.IsMatch(Prefix) || ports.Any(p => p < 40000 || p > 65535) ||
                ports.Distinct().Count() != ports.Length || Pin == null || !Regex.IsMatch(Pin,@"^[A-Fa-f0-9]{64}$"))
                throw new ArgumentException("Invalid N3 fixture settings");
        }
        public static Settings Read(string path) {
            var settings = new JavaScriptSerializer().Deserialize<Settings>(File.ReadAllText(path));
            settings.Validate();
            return settings;
        }
    }

    sealed class Head {
        public string Method, Authority, Path, Marker;
        public int Destination;
        public bool Tunnel { get {return Method == "CONNECT";} }
    }

    static string ReadHeader(NetworkStream stream) {
        var bytes = new List<byte>();
        while (bytes.Count < 8192) {
            int value = stream.ReadByte();
            if (value < 0) throw new EndOfStreamException();
            if (value > 126 || (value < 32 && value != 13 && value != 10)) throw new InvalidDataException("Unexpected header byte");
            bytes.Add((byte)value);
            int n = bytes.Count;
            if (n >= 4 && bytes[n-4] == 13 && bytes[n-3] == 10 && bytes[n-2] == 13 && bytes[n-1] == 10)
                return Encoding.ASCII.GetString(bytes.ToArray(),0,n-4);
        }
        throw new InvalidDataException("N3 header too large");
    }

    static Head ParseHeader(string text, Settings config) {
        var lines = text.Split(new[]{"\r\n"},StringSplitOptions.None);
        var first = lines[0].Split(' ');
        if (first.Length != 3 || first[2] != "HTTP/1.1") throw new InvalidDataException("Invalid request line");
        var headers = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        for (int i=1; i<lines.Length; i++) {
            var line = lines[i]; int colon = line.IndexOf(':');
            if (colon <= 0 || line.IndexOfAny(new[]{'\r','\n'}) >= 0) throw new InvalidDataException("Malformed header");
            string key = line.Substring(0,colon).ToLowerInvariant(), value = line.Substring(colon+1).Trim();
            switch (key) {
                case "host": case "connection": case "proxy-connection": case "accept": case "user-agent": break;
                case "content-length": if (value != "0") throw new InvalidDataException("Body not supported"); break;
                default: throw new InvalidDataException("Unsupported header");
            }
            if (headers.ContainsKey(key)) throw new InvalidDataException("Duplicate header");
            headers.Add(key,value);
        }
        string host;
        if (!headers.TryGetValue("host",out host)) throw new InvalidDataException("Missing Host");
        if (first[0] == "CONNECT") {
            string authority = first[1];
            int target;
            if (authority == config.Host+":443" || authority == config.WrongHost+":443") target=config.Tls;
            else if (authority == config.Host+":9443") target=config.WrongCertificate;
            else if (authority == config.Host+":7443") target=config.Half;
            else throw new InvalidDataException("CONNECT authority outside fixture");
            if (host != authority && host != authority.Substring(0,authority.IndexOf(':')))
                throw new InvalidDataException("CONNECT Host differs");
            return new Head {Method="CONNECT",Authority=authority,Destination=target};
        }
        var match = Regex.Match(first[1],@"^http://([a-z0-9.\-]+)(/(?:n3|hold)/([a-f0-9]{16})|/studio-probe\?[a-z0-9]+)$");
        if (first[0]!="GET" || !match.Success || host!=match.Groups[1].Value ||
            !Regex.IsMatch(host,"^"+Regex.Escape(config.Prefix)+@"-a-window-(baseline|healthy|stopped|outage|recovered|cold|crash|silent|fake)[1-9]?\.test$"))
            throw new InvalidDataException("GET target outside fixture");
        return new Head {Method="GET",Authority=host,Path=match.Groups[2].Value,Marker=match.Groups[3].Value,Destination=config.Http};
    }

    static void Write(NetworkStream stream, string text) {
        var bytes=Encoding.ASCII.GetBytes(text);
        stream.Write(bytes,0,bytes.Length);
    }
    static void Reply(NetworkStream stream, string code) {
        Write(stream,"HTTP/1.1 "+code+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    static Socket Socket4() {
        return new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp) {NoDelay=true,SendTimeout=1400,ReceiveTimeout=1400};
    }
    static void Abort(Socket socket) {
        if (socket == null) return;
        try { socket.LingerState=new LingerOption(true,0); } catch (SocketException) {} catch (ObjectDisposedException) {}
        socket.Dispose();
    }
    static void Connect(Socket socket,int port,int timeout) {
        IAsyncResult pending=socket.BeginConnect(IPAddress.Loopback,port,null,null);
        using (var signal=pending.AsyncWaitHandle) {
            if (!signal.WaitOne(timeout)) throw new TimeoutException("Fixture TCP connect timed out");
            socket.EndConnect(pending);
        }
    }

    sealed class Pair : IDisposable {
        internal readonly Socket Client, Other;
        internal Pair(Socket client) { Client=client; Other=Socket4(); }
        internal void Finish() { Client.Dispose(); Other.Dispose(); }
        public void Dispose() { Abort(Client); Abort(Other); }
    }

    static void Pump(Socket reader, Socket writer, Pair pair) {
        var buffer=new byte[8192];
        try {
            while (true) {
                int count=reader.Receive(buffer);
                if (count==0) { writer.Shutdown(SocketShutdown.Send); return; }
                for (int sent=0; sent<count;) {
                    int n=writer.Send(buffer,sent,count-sent,SocketFlags.None);
                    if(n==0)throw new IOException("Socket stopped accepting tunnel bytes");
                    sent+=n;
                }
            }
        } catch (IOException) { pair.Dispose(); } catch (SocketException) { pair.Dispose(); } catch (ObjectDisposedException) {}
    }

    sealed class Relay : IDisposable {
        readonly Settings config;
        readonly bool entry, reviewedOwner;
        readonly string log;
        readonly string lease;
        readonly object gate=new object(), logging=new object();
        readonly HashSet<Pair> sessions=new HashSet<Pair>();
        readonly Socket listener=Socket4();
        volatile bool stopped;
        bool admitting, watching;
        int generation;
        string mode="serve";
        string lastHealthy;
        object lastProbe;
        long closedTick;
        string closeReason;
        Process exceptionOwner;
        int exceptionOwnerPid;
        long exceptionOwnerStartTicks;

        internal Relay(Settings settings,bool isEntry,string logFile,bool watchReviewedOwner) {
            config=settings;entry=isEntry;log=logFile;admitting=!entry;reviewedOwner=watchReviewedOwner;
            lease=Path.Combine(Path.GetDirectoryName(log),"n3-entry-state.json");
        }

        void Event(string kind,params object[] fields) {
            var row=Row(fields); row["kind"]=kind; row["utc"]=DateTime.UtcNow.ToString("o"); row["pid"]=Process.GetCurrentProcess().Id;
            lock (logging) File.AppendAllText(log,new JavaScriptSerializer().Serialize(row)+Environment.NewLine);
        }

        object Snapshot(string command) {
            lock(gate) return Row("command",command,"ok",true,"admitting",admitting,"mode",mode,"active",sessions.Count,
                "generation",generation,"lastHealthy",lastHealthy,"closedTick",closedTick,"lastProbe",lastProbe,
                "watching",watching,"exceptionOwnerPid",exceptionOwnerPid,"exceptionOwnerStartTicks",exceptionOwnerStartTicks,
                "closeReason",closeReason);
        }

        void PublishLease() {
            if(!entry)return;
            var state=Row("pid",Process.GetCurrentProcess().Id,"admitting",admitting,"watching",watching,
                "active",sessions.Count,"generation",generation,"lastHealthy",lastHealthy,"closedTick",closedTick,
                "exceptionOwnerPid",exceptionOwnerPid,"exceptionOwnerStartTicks",exceptionOwnerStartTicks,"closeReason",closeReason,
                "publishedTick",Stopwatch.GetTimestamp());
            string pending=lease+".tmp";
            File.WriteAllText(pending,new JavaScriptSerializer().Serialize(state));
            if(File.Exists(lease))File.Replace(pending,lease,null);
            else File.Move(pending,lease);
        }

        void Halt(string reason) {
            lock(gate) {
                admitting=false; watching=false; generation++;
                if(exceptionOwner!=null){exceptionOwner.Dispose();exceptionOwner=null;}
                foreach(var pair in sessions)pair.Dispose();
                sessions.Clear(); closedTick=Stopwatch.GetTimestamp(); closeReason=reason;
                PublishLease();
            }
        }

        bool CloseIfOwnerExited() {
            if(exceptionOwner==null || !exceptionOwner.HasExited)return false;
            Halt("exception-owner-exit");
            return true;
        }

        void Arm(string command) {
            Process candidate=null;
            try {
                if(command.StartsWith("arm-owner ",StringComparison.Ordinal)) {
                    string[] parts=command.Split(' ');
                    int pid; long ticks;
                    if(parts.Length!=3 || !Int32.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out pid) ||
                        !Int64.TryParse(parts[2],NumberStyles.None,CultureInfo.InvariantCulture,out ticks) || pid<=0 || ticks<=0)
                        throw new ArgumentException("Invalid reviewed exception owner identity");
                    candidate=Process.GetProcessById(pid);
                    if(candidate.Handle==IntPtr.Zero || candidate.HasExited ||
                        candidate.StartTime.ToUniversalTime().Ticks!=ticks || pid==Process.GetCurrentProcess().Id)
                        throw new InvalidOperationException("Reviewed exception owner identity changed");
                }
                var reading=(Dictionary<string,object>)Health();
                lock(gate) {
                    if(reviewedOwner && exceptionOwner!=null && !CloseIfOwnerExited())
                        throw new InvalidOperationException("A reviewed exception owner is already active");
                    lastProbe=reading;
                    if(!(bool)reading["ok"]){Halt("upstream-unhealthy");return;}
                    exceptionOwner=candidate; candidate=null;
                    exceptionOwnerPid=exceptionOwner==null?0:exceptionOwner.Id;
                    exceptionOwnerStartTicks=exceptionOwner==null?0:exceptionOwner.StartTime.ToUniversalTime().Ticks;
                    if(CloseIfOwnerExited())return;
                    lastHealthy=DateTime.UtcNow.ToString("o"); admitting=true;
                    watching=command!="arm-protocol";generation++;
                    closeReason=null;
                    PublishLease();
                }
            } finally {if(candidate!=null)candidate.Dispose();}
        }

        object Health() {
            // The health path starts inside P and uses the same fixed U and
            // target validation as the fixture clients. No public health URL.
            var http=Task.Run(() => Probe(config,"http",config.U,FreshMarker(),650));
            var tls=Task.Run(() => Probe(config,"tls",config.U,FreshMarker(),650));
            if (!Task.WaitAll(new Task[]{http,tls},950)) return Row("ok",false,"status","health-deadline");
            return Row("ok",(bool)http.Result["ok"] && (bool)tls.Result["ok"],"http",http.Result,"tls",tls.Result);
        }

        void Watch() {
            while(!stopped) {
                int epoch;
                lock(gate) epoch=watching && !CloseIfOwnerExited()?generation:-1;
                if(epoch>=0) {
                    var result=(Dictionary<string,object>)Health();
                    lock(gate) if(watching && epoch==generation && !CloseIfOwnerExited()) {
                        lastProbe=result;
                        if ((bool)result["ok"]) {lastHealthy=DateTime.UtcNow.ToString("o");PublishLease();}
                        else Halt("upstream-unhealthy");
                    }
                }
                Thread.Sleep(120);
            }
        }

        void Handle(Pair pair) {
            string state;
            lock(gate) state=entry?(admitting && !CloseIfOwnerExited()?"serve":"closed"):mode;
            try {
                pair.Client.SendTimeout=1400;pair.Client.ReceiveTimeout=1400;
                using(var client=new NetworkStream(pair.Client,false)) {
                    if (state=="closed" || state=="refuse") { Reply(client,"503 Fixture Offline"); return; }
                    string text;
                    Head header;
                    try { text=ReadHeader(client);header=ParseHeader(text,config); }
                    catch(InvalidDataException) { Event("rejected");Reply(client,"400 Fixture Rejected");return; }
                    if(state=="silent") { Thread.Sleep(4000);return; }
                    if(state=="no-tls" && header.Tunnel) {
                        Event("connect-without-target","authority",header.Authority,"peer",((IPEndPoint)pair.Client.RemoteEndPoint).Port);
                        Write(client,"HTTP/1.1 200 Connection Established\r\n\r\n");return;
                    }
                    Connect(pair.Other,entry?config.U:header.Destination,600);
                    Event("routed","method",header.Method,"authority",header.Authority,"marker",header.Marker,
                        "peer",((IPEndPoint)pair.Client.RemoteEndPoint).Port,"outbound",((IPEndPoint)pair.Other.LocalEndPoint).Port);
                    using(var other=new NetworkStream(pair.Other,false)) {
                        if (entry) {
                            Write(other,text+"\r\n\r\n");
                            if (header.Tunnel) {
                                string response=ReadHeader(other);
                                Write(client,response+"\r\n\r\n");
                                if(!response.StartsWith("HTTP/1.1 200 ",StringComparison.Ordinal))return;
                            }
                        }
                        else if (header.Tunnel) Write(client,"HTTP/1.1 200 Connection Established\r\n\r\n");
                        else Write(other,"GET "+header.Path+" HTTP/1.1\r\nHost: "+header.Authority+"\r\nConnection: close\r\n\r\n");
                        if (!header.Tunnel) { Pump(pair.Other,pair.Client,pair); return; }
                        pair.Client.ReceiveTimeout=7000;
                        pair.Other.ReceiveTimeout=7000;
                        var upload=new Thread(() => Pump(pair.Client,pair.Other,pair)) { IsBackground=true };
                        upload.Start();
                        Pump(pair.Other,pair.Client,pair);
                        if(!upload.Join(1600))pair.Dispose();
                    }
                }
            } catch (IOException) {} catch(SocketException error) {Event("socket-error","stage","connect-or-relay","nativeError",error.NativeErrorCode);}
            catch (ObjectDisposedException) {} catch(TimeoutException) { Event("relay-timeout"); }
            finally {pair.Finish();lock(gate)sessions.Remove(pair);}
        }

        internal void Run() {
            listener.ExclusiveAddressUse=true;
            int port=entry?config.P:config.U;
            listener.Bind(new IPEndPoint(IPAddress.Loopback,port));listener.Listen(24);
            lock(gate)PublishLease();
            Console.WriteLine(Json.Serialize(Row("kind","ready","pid",Process.GetCurrentProcess().Id,"port",port,"exclusive",true)));
            var accept=new Thread(() => {
                while(!stopped) {
                    Socket socket;
                    try {socket=listener.Accept();} catch(SocketException){return;}catch(ObjectDisposedException){return;}
                    lock(gate) {
                        if(sessions.Count>=24 || stopped) {Abort(socket);continue;}
                        var pair=new Pair(socket);sessions.Add(pair);
                        new Thread(() => Handle(pair)) {IsBackground=true}.Start();
                    }
                }
            }) {IsBackground=true};
            accept.Start();
            if(entry)new Thread(Watch){IsBackground=true}.Start();
            string command;
            while((command=Console.ReadLine())!=null && command!="exit") {
                if(command=="status") {}
                else if(entry && command=="halt") Halt("controller-halt");
                else if(entry && (command=="arm-protocol" || (!reviewedOwner && command=="arm") ||
                    (reviewedOwner && command.StartsWith("arm-owner ",StringComparison.Ordinal)))) Arm(command);
                else if(!entry && (command=="serve" || command=="refuse" || command=="silent" || command=="no-tls")) {
                    lock(gate)mode=command;
                } else throw new ArgumentException("Unexpected fixture command");
                Console.WriteLine(Json.Serialize(Snapshot(command)));
            }
        }
        public void Dispose() {stopped=true;listener.Dispose();Halt("relay-exit");}
    }

    internal static string FreshMarker() { return Guid.NewGuid().ToString("N").Substring(0,16); }
    static bool VerifyCertificate(Settings settings, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
        if (certificate==null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors)!=0) return false;
        using(var leaf=new X509Certificate2(certificate))
        using(var sha=SHA256.Create()) {
            string actual=BitConverter.ToString(sha.ComputeHash(leaf.RawData)).Replace("-","");
            DateTime now=DateTime.UtcNow;
            if(!String.Equals(actual,settings.Pin,StringComparison.OrdinalIgnoreCase) || now<leaf.NotBefore.ToUniversalTime() || now>leaf.NotAfter.ToUniversalTime())return false;
            return errors==SslPolicyErrors.None || (chain!=null && chain.ChainStatus.Length>0 &&
                chain.ChainStatus.All(item => item.Status==X509ChainStatusFlags.UntrustedRoot));
        }
    }

    static HttpWebRequest Request(Settings settings,string test,int port,string path,int timeout) {
        bool tls=test!="http";
        string address=(tls?"https://":"http://")+(test=="wrong-host"?settings.WrongHost:settings.Host)+(test=="wrong-cert"?":9443":"")+path;
        var request=(HttpWebRequest)WebRequest.Create(address);
        request.Proxy=new WebProxy("http://127.0.0.1:"+port.ToString(CultureInfo.InvariantCulture),false);
        request.Timeout=timeout;request.ReadWriteTimeout=timeout;request.AllowAutoRedirect=false;request.KeepAlive=false;
        if(tls)request.ServerCertificateValidationCallback=(sender,certificate,chain,errors)=>VerifyCertificate(settings,certificate,chain,errors);
        return request;
    }

    internal static Dictionary<string,object> Probe(Settings settings,string test,int port,string marker,int timeout=1500) {
        if(!MarkerFormat.IsMatch(marker))throw new ArgumentException("Bad marker");
        var result=Row("test",test,"marker",marker,"ok",false);
        HttpWebRequest request=Request(settings,test,port,"/n3/"+marker,timeout);
        try {
            using(var response=(HttpWebResponse)request.GetResponse())
            using(var reader=new StreamReader(response.GetResponseStream())) {
                var chars=new char[96];
                int count=reader.ReadBlock(chars,0,chars.Length);
                string text=new string(chars,0,count);
                result["status"]=(int)response.StatusCode;
                result["ok"]=response.StatusCode==HttpStatusCode.OK && text=="target:"+marker;
            }
        } catch(WebException error) {
            result["status"]=error.Status.ToString();
            result["detail"]=error.InnerException==null?null:error.InnerException.Message;
            if(error.Response!=null)error.Response.Dispose();
            for(Exception cause=error;cause!=null;cause=cause.InnerException) {
                var socket=cause as SocketException;
                if(socket!=null){result["nativeError"]=socket.NativeErrorCode;break;}
            }
        } catch(IOException error) { result["status"]=error.GetType().Name; }
        finally {request.Abort();}
        return result;
    }

    internal static void ConfigureTls() {
        // csc targets the .NET Framework's legacy defaults. Limit this synthetic
        // process to TLS 1.2 without changing Schannel or certificate policy.
        ServicePointManager.SecurityProtocol=(SecurityProtocolType)3072;
    }

    static object Raw(Settings config,string test,int port,string marker) {
        using(var socket=Socket4()) {
            Connect(socket,port,700);
            using(var stream=new NetworkStream(socket,false)) {
                string host=config.Host;
                if(test=="half") {
                    Write(stream,"CONNECT "+host+":7443 HTTP/1.1\r\nHost: "+host+":7443\r\n\r\n");
                    string status=ReadHeader(stream);
                    Write(stream,marker);socket.Shutdown(SocketShutdown.Send);
                    var bytes=new byte[128];int used=0,n;
                    while(used<bytes.Length && (n=stream.Read(bytes,used,bytes.Length-used))>0)used+=n;
                    return Row("test",test,"marker",marker,"status",status,"ok",status.StartsWith("HTTP/1.1 200 ") &&
                        Encoding.ASCII.GetString(bytes,0,used)=="half:"+marker);
                }
                string bad=test=="off-route"? "CONNECT never-outside.invalid:443 HTTP/1.1\r\nHost: never-outside.invalid:443\r\n\r\n" :
                    "GET http://"+host+"/n3/"+marker+" HTTP/1.1\r\nHost: "+host+"\r\nContent-Length: 0\r\nContent-Length: 9\r\n\r\n";
                Write(stream,bad);
                string answer=ReadHeader(stream);
                return Row("test",test,"marker",marker,"status",answer,"ok",answer.StartsWith("HTTP/1.1 400 "));
            }
        }
    }

    internal sealed class Held : IDisposable {
        readonly object gate=new object();
        readonly HttpWebRequest request;
        readonly List<string> marks=new List<string>();
        readonly List<long> receivedTicks=new List<long>();
        string status="starting";
        internal readonly string Marker;
        internal Held(Settings settings,string protocol,int port) {
            Marker=FreshMarker();
            request=Request(settings,protocol,port,"/hold/"+Marker,6000);
            new Thread(Read) {IsBackground=true}.Start();
        }
        void Read() {
            try {
                using(var response=request.GetResponse())
                using(var reader=new StreamReader(response.GetResponseStream())) {
                    string line;
                    while((line=reader.ReadLine())!=null)lock(gate) {
                        if(marks.Count>=160)break;
                        marks.Add(line);receivedTicks.Add(Stopwatch.GetTimestamp());status="active";
                    }
                    lock(gate)status="eof";
                }
            } catch(WebException error){lock(gate)status=error.Status.ToString();}
            catch(IOException){lock(gate)status="io-error";}
            catch(ObjectDisposedException){lock(gate)status="closed";}
        }
        internal object Snapshot() {
            lock(gate)return Row("marker",Marker,"state",status,"marks",marks.ToArray(),"receivedTicks",receivedTicks.ToArray());
        }
        public void Dispose() {request.Abort();}
    }

    internal static int Main(string[] args) {
        try {
            Console.OutputEncoding=new UTF8Encoding(false);
            ConfigureTls();
            if(args.Length<2)throw new ArgumentException("Expected fixture role and config");
            var config=Settings.Read(args[1]);
            if(args.Length==3 && (args[0]=="entry"||args[0]=="entry-n4"||args[0]=="upstream")) {
                using(var relay=new Relay(config,args[0]!="upstream",args[2],args[0]=="entry-n4"))relay.Run();
                return 0;
            }
            if(args.Length!=2)throw new ArgumentException("Unexpected fixture arguments");
            string test=args[0],marker=FreshMarker();
            object result;
            switch(test) {
                case "http": case "tls": case "wrong-host": case "wrong-cert": result=Probe(config,test,config.P,marker);break;
                case "half": case "ambiguous": case "off-route": result=Raw(config,test,config.P,marker);break;
                default: throw new ArgumentException("Unknown fixture probe");
            }
            Console.WriteLine(Json.Serialize(result));return 0;
        } catch(Exception error){Console.Error.WriteLine(error.GetType().Name+": "+error.Message);return 2;}
    }
}
