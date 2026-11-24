using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal static partial class StudioPsecSimulator {
    const int GuardEventLimit = 6000;
    static readonly Regex GuardPhase = new Regex("^(baseline|healthy|stopped|outage|recovered|cold|crash|silent|fake)[1-9]?$");
    static string GuardUtc() { return DateTime.UtcNow.ToString("o"); }
    static string GuardError(Exception error) {
        var socket = error as SocketException;
        if (socket == null && error.InnerException != null) socket = error.InnerException as SocketException;
        return socket == null ? error.GetType().Name + ": " + error.Message : socket.SocketErrorCode + ": " + socket.NativeErrorCode;
    }
    static bool GuardReadTimeout(IOException error) {
        var socket = error.InnerException as SocketException;
        return socket != null && (socket.SocketErrorCode == SocketError.TimedOut || socket.SocketErrorCode == SocketError.WouldBlock);
    }
    static void GuardClose(Socket socket) {
        if (socket == null) return;
        try { socket.LingerState = new LingerOption(true, 0); } catch { }
        try { socket.Close(); } catch { }
    }
    static void GuardAtomicJson(string path, object value) {
        string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try {
            File.WriteAllText(temporary, new JavaScriptSerializer { MaxJsonLength = 16000000 }.Serialize(value), new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(temporary, path, null);
            else File.Move(temporary, path);
        } finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    // All socket workers are background threads. Only RunGuardHostProxy writes stdout.
    sealed class GuardProxyState {
        internal readonly object Gate = new object();
        internal readonly List<Socket> Clients = new List<Socket>();
        internal readonly List<Dictionary<string, object>> Events = new List<Dictionary<string, object>>();
        internal Socket Listener;
        internal volatile bool Closing, Listening, Silent, Fake;
        internal long Dropped, Accepted, Requests, Replies;
        internal int Port;
        internal string Prefix;
        internal void Record(string kind, int connection, string detail, string sequence) {
            lock (Gate) {
                if (Events.Count >= GuardEventLimit) { Dropped++; return; }
                if (detail != null && detail.Length > 1024) detail = detail.Substring(0, 1024) + "[truncated]";
                Events.Add(new Dictionary<string, object> {{"kind",kind},{"utc",GuardUtc()},
                    {"connection",connection},{"detail",detail},{"seq",sequence}});
            }
        }
        internal object Snapshot(string action) {
            lock (Gate) return new Dictionary<string, object> {{"action",action},{"utc",GuardUtc()},
                {"listening",Listening},{"port",Port},{"activeConnections",Clients.Count},
                {"accepted",Accepted},{"requests",Requests},{"replies",Replies},{"silent",Silent},
                {"fake",Fake},{"events",Events.ToArray()},{"droppedEvents",Dropped}};
        }
        internal void StopListening() {
            lock (Gate) { Listening = false; GuardClose(Listener); Listener = null; }
        }
        internal void StopAll() {
            lock (Gate) {
                StopListening();
                foreach (var client in Clients) GuardClose(client);
                Clients.Clear();
            }
        }
    }
    static void GuardServe(GuardProxyState state, Socket socket, int connection) {
        try {
            socket.ReceiveTimeout = 300; socket.SendTimeout = 700; socket.NoDelay = true;
            using (var stream = new NetworkStream(socket, false)) {
                var header = new StringBuilder();
                while (!state.Closing) {
                    int next;
                    try { next = stream.ReadByte(); }
                    catch (IOException error) { if (GuardReadTimeout(error)) continue; throw; }
                    if (next < 0) break;
                    header.Append((char)next);
                    if (header.Length > 8192) throw new InvalidDataException("HTTP header limit");
                    if (header.Length < 4 || !header.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal)) continue;
                    string request = header.ToString(); header.Length = 0;
                    string line = request.Substring(0, request.IndexOf("\r\n", StringComparison.Ordinal));
                    string sequence = null;
                    bool recognized = false;
                    var parts = line.Split(' ');
                    if (parts.Length == 3 && parts[0] == "GET" && (parts[2] == "HTTP/1.1" || parts[2] == "HTTP/1.0")) {
                        string target = parts[1];
                        var match = Regex.Match(target, "^http://" + Regex.Escape(state.Prefix) + "\\.test/stream/([1-9][0-9]{0,10})$");
                        if (match.Success) { sequence = match.Groups[1].Value; recognized = true; }
                        else {
                            var phase = Regex.Match(target, "^http://" + Regex.Escape(state.Prefix) + "-a-window-((?:baseline|healthy|stopped|outage|recovered|cold|crash|silent|fake)[1-9]?)\\.test/studio-probe\\?([^ ]+)$");
                            recognized = phase.Success && phase.Groups[1].Value == phase.Groups[2].Value;
                        }
                    }
                    // No request body is accepted, including ambiguous framing.
                    if (Regex.IsMatch(request, "\\r\\n(?:Content-Length|Transfer-Encoding):", RegexOptions.IgnoreCase)) recognized = false;
                    lock (state.Gate) state.Requests++;
                    state.Record("request", connection, line, sequence);
                    if (state.Silent) { state.Record("suppressed", connection, line, sequence); continue; }
                    string body = recognized ? state.Prefix + (state.Fake ? "-fake" : "") + (sequence == null ? "" : "|" + sequence) : "rejected";
                    byte[] bodyBytes = Encoding.ASCII.GetBytes(body);
                    byte[] response = Encoding.ASCII.GetBytes("HTTP/1.1 " + (recognized ? "200 OK" : "403 Forbidden") +
                        "\r\nContent-Type: text/plain\r\nContent-Length: " + bodyBytes.Length + "\r\nConnection: keep-alive\r\n\r\n");
                    stream.Write(response, 0, response.Length); stream.Write(bodyBytes, 0, bodyBytes.Length);
                    lock (state.Gate) state.Replies++;
                    state.Record("reply", connection, body, sequence);
                    if (!recognized) break;
                }
            }
        } catch (Exception error) { state.Record("socket-error", connection, GuardError(error), null); }
        finally { GuardClose(socket); lock (state.Gate) state.Clients.Remove(socket); state.Record("closed", connection, null, null); }
    }
    internal static void RunGuardHostProxy(string prefix, int requestedPort) {
        if (!Regex.IsMatch(prefix, "^studio-[a-f0-9]{16}$")) throw new ArgumentException("Invalid guard prefix");
        if ((bool)Identity()["container"]) throw new InvalidOperationException("Guard proxy must run on the ordinary host");
        if (requestedPort != 0) Port(requestedPort.ToString());
        if (requestedPort == 10810) throw new ArgumentException("Reserved port");
        var state = new GuardProxyState { Prefix = prefix };
        var inputGate = new object(); var input = new Queue<string>(); bool inputEnded = false;
        var timer = Stopwatch.StartNew();
        try {
            state.Listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            state.Listener.ExclusiveAddressUse = true;
            state.Listener.Bind(new IPEndPoint(IPAddress.Loopback, requestedPort));
            state.Port = ((IPEndPoint)state.Listener.LocalEndPoint).Port;
            Port(state.Port.ToString());
            state.Listener.Listen(32); state.Listening = true;
            var ready = Identity(); ready["action"] = "ready"; ready["port"] = state.Port; ready["listening"] = true;
            ready["identity"] = Identity(); ready["activeConnections"] = 0;
            Console.WriteLine(new JavaScriptSerializer().Serialize(ready)); Console.Out.Flush();
            var accept = new Thread(() => {
                while (!state.Closing && state.Listening) {
                    try {
                        Socket listener; lock (state.Gate) listener = state.Listener;
                        if (listener == null) break;
                        var client = listener.Accept(); int id;
                        lock (state.Gate) {
                            if (!state.Listening || state.Closing || state.Clients.Count >= 32) { GuardClose(client); continue; }
                            state.Clients.Add(client); id = (int)++state.Accepted;
                        }
                        state.Record("accepted", id, null, null);
                        new Thread(() => GuardServe(state, client, id)) { IsBackground = true }.Start();
                    } catch (Exception error) {
                        if (state.Listening && !state.Closing) state.Record("accept-error", 0, GuardError(error), null);
                        break;
                    }
                }
            }) { IsBackground = true }; accept.Start();
            new Thread(() => {
                try {
                    string line;
                    while (!state.Closing && (line = Console.ReadLine()) != null) {
                        while (!state.Closing) {
                            bool queued = false;
                            lock (inputGate) { if (input.Count < 128) { input.Enqueue(line); queued = true; } }
                            if (queued) break;
                            Thread.Sleep(10);
                        }
                    }
                }
                catch (Exception error) { state.Record("stdin-error", 0, GuardError(error), null); }
                finally { lock (inputGate) inputEnded = true; }
            }) { IsBackground = true }.Start();
            while (timer.ElapsedMilliseconds < 179000) {
                string command = null; bool ended;
                lock (inputGate) { if (input.Count > 0) command = input.Dequeue(); ended = inputEnded; }
                if (command == null) { if (ended) break; Thread.Sleep(15); continue; }
                string action = "invalid"; string errorText = null;
                try {
                    if (command.Length > 8192) throw new ArgumentException("Command limit");
                    var parsed = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(command);
                    action = Convert.ToString(parsed["action"]);
                    switch (action) {
                        case "state": break;
                        case "silent": state.Silent = true; break;
                        case "stop-listening": state.StopListening(); break;
                        case "stop-all": state.StopAll(); break;
                        case "fake": state.Fake = true; state.Silent = false; break;
                        case "exit": state.Closing = true; state.StopAll(); break;
                        default: throw new ArgumentException("Unknown guard action");
                    }
                } catch (Exception error) { errorText = GuardError(error); }
                var ack = (Dictionary<string, object>)state.Snapshot(action); ack["ok"] = errorText == null; ack["error"] = errorText;
                Console.WriteLine(new JavaScriptSerializer { MaxJsonLength = 16000000 }.Serialize(ack)); Console.Out.Flush();
                if (action == "exit" && errorText == null) return;
            }
            state.Closing = true; state.StopAll();
            Console.WriteLine(new JavaScriptSerializer { MaxJsonLength = 16000000 }.Serialize(state.Snapshot("expired-or-eof"))); Console.Out.Flush();
        } finally { state.Closing = true; state.StopAll(); }
    }

    static object GuardBindProbe(string portText, string addressText, string option) {
        int port = Port(portText);
        if (port >= 49152 || (addressText != "127.0.0.1" && addressText != "0.0.0.0") ||
            (option != "default" && option != "reuse" && option != "exclusive"))
            throw new ArgumentException("Expected dedicated N2 port, IPv4 address and socket option");
        var result = Identity();
        result["port"] = port; result["address"] = addressText; result["option"] = option;
        result["stage"] = "bind"; result["nativeError"] = 0;
        using (var socket = new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)) {
            if (option == "exclusive") socket.ExclusiveAddressUse = true;
            if (option == "reuse") socket.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
            try {
                socket.Bind(new IPEndPoint(IPAddress.Parse(addressText),port));
                result["stage"] = "listen";
                socket.Listen(1);
                result["stage"] = "listening";
            } catch (SocketException error) { result["nativeError"] = error.NativeErrorCode; }
        }
        return result;
    }

    sealed class GuardFlowState {
        internal readonly object Gate = new object();
        internal readonly List<Dictionary<string, object>> Events = new List<Dictionary<string, object>>();
        internal readonly Queue<Dictionary<string, object>> Pending = new Queue<Dictionary<string, object>>();
        internal Socket Socket;
        internal NetworkStream Stream;
        internal Thread Sender, Reader;
        internal volatile bool Stop;
        internal string Prefix, Phase, SocketError;
        internal bool Started, Connected, Invalid;
        internal int StreamId;
        internal long Sequence, Dropped;
        internal string ConnectionId = Guid.NewGuid().ToString("N"), LocalEndpoint;
        internal void SetPhase(string phase) { lock (Gate) Phase = phase; }
        internal void Fail(Exception error) {
            lock (Gate) {
                SocketError = GuardError(error); Invalid = true;
                foreach (var item in Pending) { if ((string)item["status"] == "pending") { item["status"] = "failed"; item["completedUtc"] = GuardUtc(); item["error"] = SocketError; } }
            }
            GuardClose(Socket);
        }
        internal object Snapshot() {
            lock (Gate) {
                var copy = new List<Dictionary<string, object>>();
                var counts = new Dictionary<string, int>();
                foreach (var item in Events) {
                    copy.Add(new Dictionary<string, object>(item));
                    string status = (string)item["status"];
                    if (!counts.ContainsKey(status)) counts[status] = 0;
                    counts[status]++;
                }
                return new Dictionary<string, object> {{"streamId",StreamId},{"started",Started},{"connected",Connected},{"stopped",Stop},
                    {"sameSocket",Started},{"reconnects",0},{"connectionId",ConnectionId},{"localEndpoint",LocalEndpoint},
                    {"socketInvalid",Invalid},{"socketError",SocketError},{"phase",Phase},{"attempts",Sequence},
                    {"events",copy.ToArray()},{"statusCounts",counts},{"droppedEvents",Dropped}};
            }
        }
        internal void Start(int port) {
            if (Started || Stop) throw new InvalidOperationException("Stream already started or stopped; reconnection is forbidden");
            Started = true;
            Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Socket.NoDelay = true; Socket.SendTimeout = 600; Socket.ReceiveTimeout = 200;
            try {
                var connecting = Socket.BeginConnect(new IPEndPoint(IPAddress.Loopback, port), null, null);
                using (var wait = connecting.AsyncWaitHandle) { if (!wait.WaitOne(1200)) throw new TimeoutException("Stream connect timed out"); Socket.EndConnect(connecting); }
                Connected = true; LocalEndpoint = Socket.LocalEndPoint.ToString(); Stream = new NetworkStream(Socket, false);
            } catch (Exception error) { Fail(error); }
            Sender = new Thread(SendLoop) { IsBackground = true }; Sender.Start();
            if (Connected) { Reader = new Thread(ReadLoop) { IsBackground = true }; Reader.Start(); }
        }
        void SendLoop() {
            var cadence = Stopwatch.StartNew(); long due = 0;
            try {
                while (!Stop) {
                    Dictionary<string, object> item; long sequence; bool invalid;
                    lock (Gate) {
                        sequence = ++Sequence; invalid = Invalid;
                        item = new Dictionary<string, object> {{"seq",sequence},{"phase",Phase},{"attemptUtc",GuardUtc()},
                            {"status",invalid ? "socket-invalid" : "pending"},{"error",invalid ? SocketError : null},
                            {"sentUtc",null},{"completedUtc",invalid ? GuardUtc() : null},{"response",null},{"timeoutUtc",null}};
                        if (Events.Count < GuardEventLimit) Events.Add(item); else Dropped++;
                        if (!invalid) Pending.Enqueue(item);
                        foreach (var pending in Pending) {
                            if ((string)pending["status"] == "pending" && (DateTime.UtcNow - DateTime.Parse((string)pending["attemptUtc"]).ToUniversalTime()).TotalMilliseconds >= 900) {
                                pending["status"] = "timeout"; pending["timeoutUtc"] = GuardUtc();
                            }
                        }
                    }
                    if (!invalid) {
                        byte[] request = Encoding.ASCII.GetBytes("GET http://" + Prefix + ".test/stream/" + sequence + " HTTP/1.1\r\nHost: " + Prefix + ".test\r\nConnection: keep-alive\r\n\r\n");
                        try { Stream.Write(request, 0, request.Length); lock (Gate) item["sentUtc"] = GuardUtc(); }
                        catch (Exception error) { Fail(error); }
                    }
                    due += 100;
                    while (!Stop && cadence.ElapsedMilliseconds < due) Thread.Sleep(10);
                    if (cadence.ElapsedMilliseconds - due > 500) due = cadence.ElapsedMilliseconds;
                }
            } catch (Exception error) { if (!Stop) Fail(error); }
        }
        void ReadLoop() {
            var header = new StringBuilder(); int length = -1; var body = new List<byte>(); string statusLine = null;
            try {
                while (!Stop && !Invalid) {
                    int next;
                    try { next = Stream.ReadByte(); }
                    catch (IOException error) { if (GuardReadTimeout(error)) continue; throw; }
                    if (next < 0) throw new EndOfStreamException("Original stream closed");
                    if (length < 0) {
                        header.Append((char)next);
                        if (header.Length > 8192) throw new InvalidDataException("Response header limit");
                        if (header.Length < 4 || !header.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal)) continue;
                        string text = header.ToString(); statusLine = text.Substring(0, text.IndexOf("\r\n", StringComparison.Ordinal));
                        var matches = Regex.Matches(text, "\\r\\nContent-Length: *([0-9]+)\\r\\n", RegexOptions.IgnoreCase);
                        if (matches.Count != 1 || !Int32.TryParse(matches[0].Groups[1].Value, out length) || length < 0 || length > 1024 ||
                            Regex.IsMatch(text, "\\r\\nTransfer-Encoding:", RegexOptions.IgnoreCase)) throw new InvalidDataException("Invalid response framing");
                        if (length != 0) continue;
                    } else body.Add((byte)next);
                    if (body.Count != length) continue;
                    string response = Encoding.ASCII.GetString(body.ToArray());
                    lock (Gate) {
                        if (Pending.Count == 0) throw new InvalidDataException("Unsolicited stream response");
                        var item = Pending.Dequeue();
                        item["response"] = response; item["completedUtc"] = GuardUtc(); item["responsePhase"] = Phase;
                        bool matched = statusLine == "HTTP/1.1 200 OK" && response == Prefix + "|" + item["seq"];
                        item["status"] = matched ? "matched" : "unexpected-response";
                        if (!matched) item["error"] = "Response marker or HTTP status mismatch";
                    }
                    header.Length = 0; body.Clear(); length = -1;
                }
            } catch (Exception error) { if (!Stop) Fail(error); }
        }
        internal void Close() {
            Stop = true; GuardClose(Socket);
            if (Sender != null) Sender.Join(650);
            if (Reader != null) Reader.Join(650);
            lock (Gate) foreach (var item in Pending) {
                if ((string)item["status"] == "pending") { item["status"] = "stopped"; item["completedUtc"] = GuardUtc(); }
            }
        }
    }
    static void GuardCheckLifetime(Stopwatch lifetime) {
        if (File.Exists("guard-abort")) throw new OperationCanceledException("GUARD_FLOW_ABORT: host aborted flow experiment");
        if (lifetime.ElapsedMilliseconds >= 142000) throw new TimeoutException("GUARD_FLOW_LIFETIME: 142 second work limit");
    }
    static Dictionary<string, object> GuardNativeProbe(string[] args, string phase, int proxyPort, Stopwatch lifetime) {
        var timer = Stopwatch.StartNew();
        var value = new Dictionary<string, object> {{"readingsSource","native-child"},{"freshContainer",false},
            {"sameContainer",false},{"startedUtc",GuardUtc()},{"finishedUtc",null},{"childPid",null},
            {"exitCode",null},{"identity",null},{"system",null},{"windowHttp",null},{"windowHttpError",null},
            {"ok",false},{"error",null}};
        Process child = null;
        try {
            var changed = (string[])args.Clone(); changed[3] = phase; changed[4] = proxyPort.ToString();
            child = StartChild("native", changed);
            value["childPid"] = child.Id;
            var output = child.StandardOutput.ReadToEndAsync();
            while (!child.WaitForExit(20)) {
                GuardCheckLifetime(lifetime);
                if (timer.ElapsedMilliseconds >= 11000) throw new TimeoutException("GUARD_NATIVE_PROBE_TIMEOUT");
                Application.DoEvents();
            }
            value["exitCode"] = child.ExitCode;
            while (!output.IsCompleted) {
                GuardCheckLifetime(lifetime);
                if (timer.ElapsedMilliseconds >= 11000) throw new TimeoutException("GUARD_NATIVE_OUTPUT_TIMEOUT");
                Application.DoEvents(); Thread.Sleep(10);
            }
            if (child.ExitCode != 0) throw new IOException("Native probe exit code " + child.ExitCode);
            if (output.Result.Length > 65536) throw new InvalidDataException("Native probe output limit");
            var native = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(output.Result);
            var identity = new Dictionary<string, object>();
            foreach (string key in new [] {"pid","session","userSid","startTicks","container","containerSid","inJob","capabilitySids","networkCapabilities"})
                if (native.ContainsKey(key)) identity[key] = native[key];
            value["identity"] = identity; value["system"] = native;
            if (native.ContainsKey("proxyHttp")) value["windowHttp"] = native["proxyHttp"];
            var current = Identity();
            bool same = Convert.ToString(native["containerSid"]) == Convert.ToString(current["containerSid"]) &&
                Convert.ToBoolean(native["container"]) && Convert.ToBoolean(native["inJob"]) &&
                Convert.ToInt32(native["pid"]) == child.Id && child.Id != Convert.ToInt32(current["pid"]);
            value["sameContainer"] = same;
            if (!same) throw new InvalidDataException("Native child identity differs from the current container");
            value["ok"] = true;
        } catch (OperationCanceledException) { throw; }
        catch (Exception error) { value["error"] = GuardError(error); }
        finally {
            if (child != null) {
                try {
                    if (!child.HasExited) { child.Kill(); child.WaitForExit(500); }
                    if (child.HasExited) value["exitCode"] = child.ExitCode;
                } catch (Exception error) { value["cleanupError"] = GuardError(error); }
                child.Dispose();
            }
            value["finishedUtc"] = GuardUtc(); value["elapsedMilliseconds"] = timer.ElapsedMilliseconds;
        }
        return value;
    }
    internal static void RunPortGuardFlow(string[] args, int proxyPort, Dictionary<string, object> windowResult) {
        if (args.Length < 7 || args[2] != "a") throw new ArgumentException("Guard flow is A-only");
        Port(proxyPort.ToString());
        var lifetime = Stopwatch.StartNew();
        var flow = new GuardFlowState { Prefix = args[1], Phase = "healthy", StreamId = 1 };
        var archives = new List<object>();
        bool explicitlyStopped = false;
        GuardAtomicJson("guard-healthy-result.json", windowResult);
        try {
            for (int number = 1; ; number++) {
                string path = "flow-command-" + number + ".json";
                var waiting = Stopwatch.StartNew();
                while (!File.Exists(path)) {
                    GuardCheckLifetime(lifetime);
                    if (waiting.ElapsedMilliseconds >= 25000) throw new TimeoutException("GUARD_FLOW_COMMAND_TIMEOUT: " + path);
                    Application.DoEvents(); Thread.Sleep(25);
                }
                GuardCheckLifetime(lifetime);
                string action = "invalid", phase = flow.Phase; object probe = null; string errorText = null;
                object initialMatched = null;
                try {
                    var info = new FileInfo(path); if (info.Length > 8192) throw new InvalidDataException("Flow command limit");
                    var command = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(path));
                    action = Convert.ToString(command["action"]); phase = Convert.ToString(command["phase"]);
                    if (!GuardPhase.IsMatch(phase)) throw new ArgumentException("Invalid guard phase");
                    if (action != "start-stream") flow.SetPhase(phase);
                    switch (action) {
                        case "start-stream": {
                            if (flow.Started || flow.Stop) {
                                if (!explicitlyStopped) throw new InvalidOperationException("Explicit stop-stream is required before another stream");
                                int nextId = flow.Started ? flow.StreamId + 1 : flow.StreamId;
                                if (flow.Started) archives.Add(flow.Snapshot());
                                flow = new GuardFlowState { Prefix = args[1], Phase = phase, StreamId = nextId };
                            }
                            explicitlyStopped = false; flow.SetPhase(phase);
                            flow.Start(proxyPort);
                            var initial = Stopwatch.StartNew();
                            bool matched = false;
                            while (initial.ElapsedMilliseconds < 1800) {
                                GuardCheckLifetime(lifetime);
                                bool completed;
                                lock (flow.Gate) {
                                    completed = flow.Invalid || (flow.Events.Count > 0 &&
                                        ((string)flow.Events[0]["status"] == "matched" || (string)flow.Events[0]["status"] == "unexpected-response"));
                                    matched = flow.Events.Count > 0 && (string)flow.Events[0]["status"] == "matched";
                                }
                                if (completed) break;
                                Application.DoEvents(); Thread.Sleep(15);
                            }
                            initialMatched = matched;
                            break;
                        }
                        case "snapshot": break;
                        case "select-proxy": {
                            int selected = Port(Convert.ToString(command["port"]));
                            if (proxyPort >= 49152 || selected >= 49152 || selected == proxyPort || !flow.Invalid)
                                throw new InvalidOperationException("N2 requires a closed old flow and a fresh dedicated proxy port");
                            proxyPort = selected;
                            break;
                        }
                        case "stop-stream": flow.Close(); explicitlyStopped = true; break;
                        case "finish": flow.Close(); break;
                        case "native-probe": {
                            var reading = GuardNativeProbe(args, phase, proxyPort, lifetime);
                            probe = reading;
                            if (!(bool)reading["ok"]) errorText = Convert.ToString(reading["error"]);
                            break;
                        }
                        case "probe": {
                            object reading = null; Exception failure = null;
                            var worker = new Thread(() => {
                                try {
                                    var value = new Dictionary<string, object> {{"readingsSource","window-process-worker"},
                                        {"identity",Identity()},{"startedUtc",GuardUtc()}};
                                    value["system"] = SystemProbes(args[1], args[2], phase, Port(args[5]), Port(args[6]));
                                    var evidence = new Dictionary<string, object>();
                                    value["windowHttp"] = WindowHttp(args[1], args[2], phase, proxyPort, evidence);
                                    value["windowHttpError"] = evidence; value["finishedUtc"] = GuardUtc(); reading = value;
                                } catch (Exception error) { failure = error; }
                            }) { IsBackground = true };
                            worker.Start(); var probeTimer = Stopwatch.StartNew();
                            while (!worker.Join(20)) {
                                GuardCheckLifetime(lifetime);
                                if (probeTimer.ElapsedMilliseconds >= 24000) throw new TimeoutException("GUARD_FLOW_PROBE_TIMEOUT");
                                Application.DoEvents();
                            }
                            if (failure != null) throw failure;
                            probe = reading; break;
                        }
                        default: throw new ArgumentException("Unknown flow action");
                    }
                } catch (OperationCanceledException) { throw; }
                catch (Exception error) {
                    errorText = GuardError(error);
                    if (error is TimeoutException) { flow.Close(); }
                }
                GuardCheckLifetime(lifetime);
                GuardAtomicJson("flow-result-" + number + ".json", new Dictionary<string, object> {
                    {"number",number},{"action",action},{"phase",phase},{"port",proxyPort},{"utc",GuardUtc()},{"identity",Identity()},
                    {"ok",errorText == null},{"error",errorText},{"initialMatched",initialMatched},{"flow",flow.Snapshot()},
                    {"archives",archives.ToArray()},{"probe",probe}});
                if (action == "finish" || (errorText != null && errorText.IndexOf("GUARD_FLOW_PROBE_TIMEOUT", StringComparison.Ordinal) >= 0)) return;
            }
        } finally { flow.Close(); }
    }
}
