using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ClaudeStudio.ControlPlane {
    public sealed class ProxySpaceStats {
        public bool Admitting { get; set; }
        public int ActiveTunnels { get; set; }
        public long TotalConnections { get; set; }
        public string LastTarget { get; set; }
        public string HaltReason { get; set; }
    }

    // Pure-C# per-space IPv4 loopback HTTP/HTTPS CONNECT proxy relay embedded directly inside ClaudeStudioControlPlane.exe.
    // Zero Node.js or external runtime dependencies.
    // Supports:
    //   - Dedicated loopback entry port per space (127.0.0.1:Pa for A, 127.0.0.1:Pb for B)
    //   - Continuous upstream TCP health monitor + ProxyOwner PID watchdog
    //   - Instant fail-closed halt & forced close of all active tunnels on upstream fault or ProxyOwner exit
    //   - Optional ZeroEgressTestMode (logs CONNECT and replies 502 without touching external internet)
    public sealed class EmbeddedDualProxyRelay : IDisposable {
        sealed class TunnelPair : IDisposable {
            public readonly Socket Client;
            public readonly Socket Upstream;
            public TunnelPair(Socket client, Socket upstream) { Client = client; Upstream = upstream; }
            public void Dispose() {
                Abort(Client);
                Abort(Upstream);
            }
            static void Abort(Socket s) {
                if (s == null) return;
                try { s.LingerState = new LingerOption(true, 0); } catch { }
                try { s.Dispose(); } catch { }
            }
        }

        sealed class SpaceEntry {
            public SpaceId Space;
            public int Port;
            public TcpListener Listener;
            public Thread AcceptThread;
            public readonly object Gate = new object();
            public bool Admitting;
            public int OwnerPid;
            public long TotalConnections;
            public string LastTarget = "";
            public string HaltReason = "cold-blocked";
            public readonly HashSet<TunnelPair> Active = new HashSet<TunnelPair>();
        }

        readonly object cfgGate = new object();
        readonly Dictionary<SpaceId, SpaceEntry> entries = new Dictionary<SpaceId, SpaceEntry>();
        readonly Thread watchThread;
        volatile bool disposed;

        string upstreamHost = "127.0.0.1";
        int upstreamPort = 0;
        bool zeroEgressTestMode = false;
        bool upstreamHealthy = false;

        public event Action<SpaceId, string> SpaceHalted;

        public int PortA { get { return entries[SpaceId.A].Port; } }
        public int PortB { get { return entries[SpaceId.B].Port; } }
        public bool UpstreamHealthy { get { lock (cfgGate) return upstreamHealthy; } }
        public bool ZeroEgressTestMode { get { lock (cfgGate) return zeroEgressTestMode; } }

        public EmbeddedDualProxyRelay(int portA, int portB) {
            entries[SpaceId.A] = StartEntry(SpaceId.A, portA);
            entries[SpaceId.B] = StartEntry(SpaceId.B, portB);
            watchThread = new Thread(WatchLoop) { IsBackground = true, Name = "StudioProxyWatchdog" };
            watchThread.Start();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        SpaceEntry StartEntry(SpaceId id, int requestedPort) {
            var listener = new TcpListener(IPAddress.Loopback, requestedPort);
            listener.Server.ExclusiveAddressUse = true;
            listener.Start(32);
            // Prevent child processes (e.g., StudioProxyOwner.exe) from inheriting this listening socket handle!
            SetHandleInformation(listener.Server.Handle, 1 /* HANDLE_FLAG_INHERIT */, 0);
            int actualPort = ((IPEndPoint)listener.LocalEndpoint).Port;
            var e = new SpaceEntry { Space = id, Port = actualPort, Listener = listener, Admitting = false };
            e.AcceptThread = new Thread(() => AcceptLoop(e)) { IsBackground = true, Name = "StudioProxyAccept-" + id };
            e.AcceptThread.Start();
            return e;
        }

        public void ConfigureUpstream(string host, int port, bool zeroEgressMode) {
            lock (cfgGate) {
                upstreamHost = string.IsNullOrWhiteSpace(host) ? "127.0.0.1" : host.Trim();
                upstreamPort = port;
                zeroEgressTestMode = zeroEgressMode;
            }
            ProbeUpstreamNow();
        }

        public bool ProbeUpstreamNow() {
            string host; int port;
            lock (cfgGate) { host = upstreamHost; port = upstreamPort; }
            bool ok = false;
            if (port > 0) {
                try {
                    using (var tcp = new TcpClient(AddressFamily.InterNetwork)) {
                        var ar = tcp.BeginConnect(host, port, null, null);
                        if (ar.AsyncWaitHandle.WaitOne(350)) {
                            tcp.EndConnect(ar);
                            ok = true;
                        }
                    }
                } catch { ok = false; }
            }
            lock (cfgGate) { upstreamHealthy = ok; }
            return ok;
        }

        public bool ArmSpace(SpaceId id, int ownerPid, out string reason) {
            if (ownerPid <= 0 || !IsPidAlive(ownerPid)) {
                reason = "ProxyOwner PID not alive";
                return false;
            }
            if (!ProbeUpstreamNow()) {
                HaltSpace(id, "upstream-unhealthy");
                reason = "Upstream unhealthy";
                return false;
            }
            var e = entries[id];
            lock (e.Gate) {
                e.OwnerPid = ownerPid;
                e.Admitting = true;
                e.HaltReason = "";
            }
            reason = "armed";
            return true;
        }

        public void HaltSpace(SpaceId id, string reason) {
            var e = entries[id];
            bool wasAdmitting;
            lock (e.Gate) {
                wasAdmitting = e.Admitting;
                e.Admitting = false;
                e.OwnerPid = 0;
                e.HaltReason = reason ?? "halted";
                foreach (var p in e.Active) p.Dispose();
                e.Active.Clear();
            }
            if (wasAdmitting) {
                var cb = SpaceHalted;
                if (cb != null) { try { cb(id, reason); } catch { } }
            }
        }

        public ProxySpaceStats GetStats(SpaceId id) {
            var e = entries[id];
            lock (e.Gate) {
                return new ProxySpaceStats {
                    Admitting = e.Admitting,
                    ActiveTunnels = e.Active.Count,
                    TotalConnections = e.TotalConnections,
                    LastTarget = e.LastTarget,
                    HaltReason = e.HaltReason
                };
            }
        }

        static bool IsPidAlive(int pid) {
            if (pid <= 0) return false;
            try {
                using (var p = Process.GetProcessById(pid)) return !p.HasExited;
            } catch { return false; }
        }

        void WatchLoop() {
            while (!disposed) {
                try {
                    bool anyAdmitting;
                    lock (entries[SpaceId.A].Gate) anyAdmitting = entries[SpaceId.A].Admitting;
                    if (!anyAdmitting) { lock (entries[SpaceId.B].Gate) anyAdmitting = entries[SpaceId.B].Admitting; }

                    if (anyAdmitting) {
                        bool upOk = ProbeUpstreamNow();
                        foreach (SpaceId id in new[] { SpaceId.A, SpaceId.B }) {
                            var e = entries[id];
                            bool adm; int opid;
                            lock (e.Gate) { adm = e.Admitting; opid = e.OwnerPid; }
                            if (!adm) continue;
                            if (!upOk) HaltSpace(id, "upstream-unhealthy");
                            else if (!IsPidAlive(opid)) HaltSpace(id, "exception-owner-exit");
                        }
                    }
                } catch { }
                Thread.Sleep(150);
            }
        }

        void AcceptLoop(SpaceEntry e) {
            while (!disposed) {
                Socket client = null;
                try {
                    client = e.Listener.AcceptSocket();
                    var captured = client;
                    ThreadPool.QueueUserWorkItem(_ => HandleClient(e, captured));
                } catch {
                    if (client != null) { try { client.Dispose(); } catch { } }
                    if (disposed) return;
                    Thread.Sleep(30);
                }
            }
        }

        static string ReadHttpHead(NetworkStream ns) {
            var bytes = new List<byte>(512);
            while (bytes.Count < 16384) {
                int b = ns.ReadByte();
                if (b < 0) return null;
                bytes.Add((byte)b);
                int n = bytes.Count;
                if (n >= 4 && bytes[n - 4] == 13 && bytes[n - 3] == 10 && bytes[n - 2] == 13 && bytes[n - 1] == 10) {
                    return Encoding.ASCII.GetString(bytes.ToArray(), 0, n);
                }
            }
            return null;
        }

        void HandleClient(SpaceEntry e, Socket client) {
            TunnelPair pair = null;
            try {
                client.NoDelay = true;
                client.ReceiveTimeout = 6000;
                client.SendTimeout = 6000;

                bool adm; int opid;
                lock (e.Gate) { adm = e.Admitting; opid = e.OwnerPid; }
                if (!adm || !IsPidAlive(opid)) {
                    SendQuickReply(client, "HTTP/1.1 503 Space Proxy Halted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    client.Dispose();
                    return;
                }

                using (var cns = new NetworkStream(client, false)) {
                    string head = ReadHttpHead(cns);
                    if (string.IsNullOrEmpty(head)) { client.Dispose(); return; }
                    string firstLine = head.Split(new[] { "\r\n" }, StringSplitOptions.None)[0];
                    string[] parts = firstLine.Split(' ');
                    string target = parts.Length >= 2 ? parts[1] : "";

                    lock (e.Gate) {
                        e.TotalConnections++;
                        if (!string.IsNullOrEmpty(target)) e.LastTarget = target;
                    }

                    string uHost; int uPort; bool zeroEgress;
                    lock (cfgGate) { uHost = upstreamHost; uPort = upstreamPort; zeroEgress = zeroEgressTestMode; }
                    if (uPort <= 0) {
                        SendQuickReply(client, "HTTP/1.1 503 Upstream Unconfigured\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        client.Dispose();
                        return;
                    }

                    if (zeroEgress) {
                        // Still confirm local test upstream listener is alive, then return synthetic 502 (ZERO external internet egress!)
                        using (var probe = new TcpClient(AddressFamily.InterNetwork)) {
                            var ar = probe.BeginConnect(uHost, uPort, null, null);
                            if (!ar.AsyncWaitHandle.WaitOne(700)) {
                                SendQuickReply(client, "HTTP/1.1 503 Local Test Upstream Offline\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                                client.Dispose();
                                return;
                            }
                            probe.EndConnect(ar);
                            byte[] ping = Encoding.ASCII.GetBytes(firstLine + "\r\n\r\n");
                            probe.GetStream().Write(ping, 0, ping.Length);
                        }
                        SendQuickReply(client, "HTTP/1.1 502 Local Zero-Egress Upstream\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        client.Dispose();
                        return;
                    }

                    // Live forwarding mode: tunnel transparently to configured upstream HTTP proxy
                    var upSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    var connectAr = upSock.BeginConnect(uHost, uPort, null, null);
                    if (!connectAr.AsyncWaitHandle.WaitOne(2500)) {
                        upSock.Dispose();
                        SendQuickReply(client, "HTTP/1.1 504 Upstream Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        client.Dispose();
                        return;
                    }
                    upSock.EndConnect(connectAr);

                    pair = new TunnelPair(client, upSock);
                    lock (e.Gate) {
                        if (!e.Admitting) { pair.Dispose(); return; }
                        e.Active.Add(pair);
                    }

                    byte[] rawHead = Encoding.ASCII.GetBytes(head);
                    upSock.Send(rawHead, 0, rawHead.Length, SocketFlags.None);
                    client.ReceiveTimeout = 0; client.SendTimeout = 15000;
                    upSock.ReceiveTimeout = 0; upSock.SendTimeout = 15000;

                    var tUp = new Thread(() => Pump(client, upSock, pair)) { IsBackground = true };
                    tUp.Start();
                    Pump(upSock, client, pair);
                    tUp.Join(1500);
                }
            } catch {
                if (pair != null) pair.Dispose();
                else { try { client.Dispose(); } catch { } }
            } finally {
                if (pair != null) {
                    lock (e.Gate) { e.Active.Remove(pair); }
                    pair.Dispose();
                }
            }
        }

        static void SendQuickReply(Socket s, string ascii) {
            try { byte[] b = Encoding.ASCII.GetBytes(ascii); s.Send(b, 0, b.Length, SocketFlags.None); } catch { }
        }

        static void Pump(Socket src, Socket dst, TunnelPair pair) {
            byte[] buf = new byte[16384];
            try {
                while (true) {
                    int n = src.Receive(buf);
                    if (n <= 0) { try { dst.Shutdown(SocketShutdown.Send); } catch { } return; }
                    int off = 0;
                    while (off < n) {
                        int s = dst.Send(buf, off, n - off, SocketFlags.None);
                        if (s <= 0) { pair.Dispose(); return; }
                        off += s;
                    }
                }
            } catch { pair.Dispose(); }
        }

        public void Dispose() {
            disposed = true;
            foreach (SpaceId id in new[] { SpaceId.A, SpaceId.B }) {
                HaltSpace(id, "disposed");
                try { entries[id].Listener.Stop(); } catch { }
            }
        }
    }
}
