using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace ClaudeStudio.Twin {
    public sealed class IdentitySnapshot {
        public int pid;
        public int sessionId;
        public string userSid;
        public string containerSid;
        public bool isAppContainer;
        public string executableName;
    }

    public sealed class WinNativeTz {
        public uint id;
        public int biasMinutes;
        public string standardName;
        public string daylightName;
    }

    public sealed class ProxyHttpResponse {
        public bool ok;
        public int statusCode;
        public string body;
        public string error;
        public long elapsedMs;
    }

    public sealed class StreamHandle : IDisposable {
        readonly object gate = new object();
        readonly TcpClient tcp;
        readonly SslStream ssl;
        readonly Thread reader;
        volatile bool stopRequested;
        volatile bool ended;
        volatile string endReason = "open";
        readonly List<string> chunks = new List<string>();
        long firstChunkMs = -1;
        long endMs = -1;
        readonly Stopwatch sw = Stopwatch.StartNew();

        public StreamHandle(TcpClient client, SslStream stream, int initialReadTimeoutMs) {
            tcp = client;
            ssl = stream;
            ssl.ReadTimeout = initialReadTimeoutMs;
            reader = new Thread(ReadLoop) { IsBackground = true };
            reader.Start();
        }

        void ReadLoop() {
            try {
                using (var sr = new StreamReader(ssl, Encoding.UTF8, false, 1024, true)) {
                    // Read HTTP status line & headers
                    string statusLine = sr.ReadLine();
                    if (statusLine == null || !statusLine.Contains(" 200")) {
                        lock (gate) { endReason = "bad-status:" + (statusLine ?? "eof"); ended = true; endMs = sw.ElapsedMilliseconds; }
                        return;
                    }
                    string line;
                    while ((line = sr.ReadLine()) != null && line.Length > 0) { }
                    // Read SSE lines until stream drops or closes
                    while (!stopRequested && (line = sr.ReadLine()) != null) {
                        if (line.StartsWith("data:", StringComparison.Ordinal)) {
                            string payload = line.Substring(5).Trim();
                            lock (gate) {
                                if (firstChunkMs < 0) firstChunkMs = sw.ElapsedMilliseconds;
                                chunks.Add(payload);
                            }
                        }
                    }
                    lock (gate) {
                        if (!ended) {
                            endReason = stopRequested ? "closed-by-client" : "eof";
                            ended = true;
                            endMs = sw.ElapsedMilliseconds;
                        }
                    }
                }
            } catch (Exception ex) {
                lock (gate) {
                    endReason = stopRequested ? "closed-by-client" : ("io-error:" + ex.GetType().Name);
                    ended = true;
                    endMs = sw.ElapsedMilliseconds;
                }
            }
        }

        public Dictionary<string, object> Snapshot() {
            lock (gate) {
                return new Dictionary<string, object> {
                    { "ended", ended },
                    { "endReason", endReason },
                    { "chunkCount", chunks.Count },
                    { "lastChunk", chunks.Count > 0 ? chunks[chunks.Count - 1] : null },
                    { "firstChunkMs", firstChunkMs },
                    { "endMs", endMs },
                    { "elapsedMs", sw.ElapsedMilliseconds }
                };
            }
        }

        public void Dispose() {
            stopRequested = true;
            try { ssl.Dispose(); } catch { }
            try { tcp.Close(); } catch { }
            try { if (reader.IsAlive) reader.Join(400); } catch { }
        }
    }

    public static class TwinUtil {
        public static readonly JavaScriptSerializer Json = new JavaScriptSerializer();

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SystemTime { public ushort Y, M, Dow, D, H, Min, S, Ms; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct TimeZoneInformation {
            public int Bias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string StandardName;
            public SystemTime StandardDate;
            public int StandardBias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DaylightName;
            public SystemTime DaylightDate;
            public int DaylightBias;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern uint GetTimeZoneInformation(out TimeZoneInformation info);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buf, int len, out int retLen);

        [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)]
        static extern int DnsQuery_W(string name, ushort wType, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

        [DllImport("dnsapi.dll")]
        static extern void DnsRecordListFree(IntPtr recordList, int freeType);

        public static IdentitySnapshot ReadIdentity() {
            using (var proc = Process.GetCurrentProcess())
            using (var id = WindowsIdentity.GetCurrent()) {
                string cSid = null;
                bool isAc = false;
                int req = 0;
                if (!GetTokenInformation(id.Token, 29 /* TokenIsAppContainer */, IntPtr.Zero, 0, out req) && req >= 4) {
                    IntPtr b = Marshal.AllocHGlobal(req);
                    try { if (GetTokenInformation(id.Token, 29, b, req, out req)) isAc = Marshal.ReadInt32(b) != 0; }
                    finally { Marshal.FreeHGlobal(b); }
                }
                req = 0;
                if (!GetTokenInformation(id.Token, 31 /* TokenAppContainerSid */, IntPtr.Zero, 0, out req) && req >= IntPtr.Size) {
                    IntPtr b = Marshal.AllocHGlobal(req);
                    try {
                        if (GetTokenInformation(id.Token, 31, b, req, out req)) {
                            IntPtr pSid = Marshal.ReadIntPtr(b);
                            if (pSid != IntPtr.Zero) cSid = new SecurityIdentifier(pSid).Value;
                        }
                    } finally { Marshal.FreeHGlobal(b); }
                }
                return new IdentitySnapshot {
                    pid = proc.Id,
                    sessionId = proc.SessionId,
                    userSid = id.User != null ? id.User.Value : null,
                    containerSid = cSid,
                    isAppContainer = isAc,
                    executableName = Path.GetFileName(proc.MainModule.FileName)
                };
            }
        }

        public static WinNativeTz ReadNativeTimezone() {
            TimeZoneInformation tzi;
            uint id = GetTimeZoneInformation(out tzi);
            return new WinNativeTz {
                id = id,
                biasMinutes = tzi.Bias,
                standardName = tzi.StandardName ?? "",
                daylightName = tzi.DaylightName ?? ""
            };
        }

        public static string FormatFixedUtcWithOffset(string tzName) {
            int offsetMinutes = 0;
            if (string.Equals(tzName, "Asia/Shanghai", StringComparison.OrdinalIgnoreCase)) offsetMinutes = 480;
            else if (string.Equals(tzName, "America/Los_Angeles", StringComparison.OrdinalIgnoreCase)) offsetMinutes = -420;
            var baseUtc = new DateTimeOffset(2026, 7, 1, 12, 0, 0, TimeSpan.Zero);
            return baseUtc.ToOffset(TimeSpan.FromMinutes(offsetMinutes)).ToString("yyyy-MM-ddTHH:mm:sszzz");
        }

        // Exact Claude Code CLI CWD encoding: non-alphanumeric chars replaced by '-'
        public static string EncodeClaudeProjectPath(string cwd) {
            string full = Path.GetFullPath(cwd ?? Environment.CurrentDirectory).TrimEnd('\\', '/');
            var sb = new StringBuilder(full.Length);
            foreach (char ch in full) {
                if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) sb.Append(ch);
                else sb.Append('-');
            }
            return sb.ToString();
        }

        public static bool HasReparsePoint(string path) {
            if (string.IsNullOrEmpty(path) || (!Directory.Exists(path) && !File.Exists(path))) return false;
            var attrs = File.GetAttributes(path);
            return (attrs & FileAttributes.ReparsePoint) != 0;
        }

        public static string Sha256Hex(string text) {
            using (var sha = SHA256.Create()) {
                return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "").ToLowerInvariant();
            }
        }

        public static string Base64UrlSha256(string verifier) {
            using (var sha = SHA256.Create()) {
                byte[] hash = sha.ComputeHash(Encoding.ASCII.GetBytes(verifier));
                return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
        }

        public static string NewRandomHex(int bytesLen) {
            byte[] b = new byte[bytesLen];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();
        }

        public static int ParseProxyPort(string proxyUrl) {
            if (string.IsNullOrWhiteSpace(proxyUrl)) return 0;
            string s = proxyUrl.Trim();
            if (!s.Contains("://")) s = "http://" + s;
            Uri u;
            if (!Uri.TryCreate(s, UriKind.Absolute, out u)) return 0;
            return u.Port;
        }

        // Connects ONLY to IPv4 127.0.0.1:<proxyPort> -> HTTP CONNECT <apiHost>:443 -> TLS 1.2 (strict SHA-256 leaf cert pin).
        // Zero accidental system DNS calls!
        public static SslStream OpenProxiedTlsTunnel(int proxyPort, string apiHost, string expectedPinSha256, int timeoutMs, out TcpClient tcpOut) {
            tcpOut = null;
            if (proxyPort <= 0) throw new InvalidOperationException("Proxy port not configured");
            var tcp = new TcpClient(AddressFamily.InterNetwork);
            tcp.NoDelay = true;
            tcp.SendTimeout = timeoutMs;
            tcp.ReceiveTimeout = timeoutMs;
            try {
                var ar = tcp.BeginConnect(IPAddress.Loopback, proxyPort, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) throw new TimeoutException("Proxy connect timeout");
                tcp.EndConnect(ar);

                var ns = tcp.GetStream();
                string connectReq = string.Format("CONNECT {0}:443 HTTP/1.1\r\nHost: {0}:443\r\nProxy-Connection: keep-alive\r\n\r\n", apiHost);
                byte[] reqBytes = Encoding.ASCII.GetBytes(connectReq);
                ns.Write(reqBytes, 0, reqBytes.Length);
                ns.Flush();

                string respHead = ReadAsciiHttpHeader(ns);
                if (!respHead.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase) &&
                    !respHead.StartsWith("HTTP/1.0 200", StringComparison.OrdinalIgnoreCase)) {
                    throw new IOException("Proxy CONNECT rejected: " + respHead.Split('\r')[0]);
                }

                string pinClean = (expectedPinSha256 ?? "").Replace(":", "").Trim();
                var ssl = new SslStream(ns, false, (sender, cert, chain, errors) => {
                    if (cert == null) return false;
                    var x2 = new X509Certificate2(cert);
                    using (var sha = SHA256.Create()) {
                        string got = BitConverter.ToString(sha.ComputeHash(x2.RawData)).Replace("-", "");
                        if (!string.IsNullOrEmpty(pinClean)) {
                            return string.Equals(got, pinClean, StringComparison.OrdinalIgnoreCase);
                        }
                        return errors == SslPolicyErrors.None;
                    }
                });
                ssl.ReadTimeout = timeoutMs;
                ssl.WriteTimeout = timeoutMs;
                ssl.AuthenticateAsClient(apiHost, null, SslProtocols.Tls12, false);
                tcpOut = tcp;
                return ssl;
            } catch {
                try { tcp.Close(); } catch { }
                throw;
            }
        }

        static string ReadAsciiHttpHeader(Stream s) {
            var buf = new List<byte>();
            while (buf.Count < 16384) {
                int b = s.ReadByte();
                if (b < 0) throw new EndOfStreamException("EOF before HTTP header end");
                buf.Add((byte)b);
                int n = buf.Count;
                if (n >= 4 && buf[n - 4] == 13 && buf[n - 3] == 10 && buf[n - 2] == 13 && buf[n - 1] == 10) {
                    return Encoding.ASCII.GetString(buf.ToArray(), 0, n - 4);
                }
            }
            throw new InvalidDataException("HTTP header too large");
        }

        public static ProxyHttpResponse PostJsonViaProxy(int proxyPort, string apiHost, string tlsPin, string path,
            Dictionary<string, string> headers, object bodyObj, int timeoutMs = 4500) {
            var sw = Stopwatch.StartNew();
            TcpClient tcp = null;
            try {
                using (var ssl = OpenProxiedTlsTunnel(proxyPort, apiHost, tlsPin, timeoutMs, out tcp)) {
                    string jsonBody = Json.Serialize(bodyObj ?? new Dictionary<string, object>());
                    byte[] bodyBytes = Encoding.UTF8.GetBytes(jsonBody);
                    var sb = new StringBuilder();
                    sb.AppendFormat("POST {0} HTTP/1.1\r\n", path);
                    sb.AppendFormat("Host: {0}\r\n", apiHost);
                    sb.Append("Content-Type: application/json; charset=utf-8\r\n");
                    sb.AppendFormat("Content-Length: {0}\r\n", bodyBytes.Length);
                    sb.Append("Connection: close\r\n");
                    if (headers != null) {
                        foreach (var kv in headers) sb.AppendFormat("{0}: {1}\r\n", kv.Key, kv.Value);
                    }
                    sb.Append("\r\n");
                    byte[] headBytes = Encoding.ASCII.GetBytes(sb.ToString());
                    ssl.Write(headBytes, 0, headBytes.Length);
                    ssl.Write(bodyBytes, 0, bodyBytes.Length);
                    ssl.Flush();

                    string rawHead = ReadAsciiHttpHeader(ssl);
                    string[] lines = rawHead.Split(new[] { "\r\n" }, StringSplitOptions.None);
                    int statusCode = 0;
                    if (lines.Length > 0) {
                        string[] parts = lines[0].Split(' ');
                        if (parts.Length >= 2) int.TryParse(parts[1], out statusCode);
                    }
                    int contentLen = -1;
                    for (int i = 1; i < lines.Length; i++) {
                        if (lines[i].StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) {
                            int.TryParse(lines[i].Substring(15).Trim(), out contentLen);
                        }
                    }
                    string respBody;
                    if (contentLen >= 0) {
                        byte[] data = new byte[contentLen];
                        int off = 0;
                        while (off < contentLen) {
                            int r = ssl.Read(data, off, contentLen - off);
                            if (r <= 0) break;
                            off += r;
                        }
                        respBody = Encoding.UTF8.GetString(data, 0, off);
                    } else {
                        using (var ms = new MemoryStream()) {
                            byte[] tmp = new byte[4096];
                            int r;
                            while ((r = ssl.Read(tmp, 0, tmp.Length)) > 0) ms.Write(tmp, 0, r);
                            respBody = Encoding.UTF8.GetString(ms.ToArray());
                        }
                    }
                    return new ProxyHttpResponse {
                        ok = statusCode >= 200 && statusCode < 300,
                        statusCode = statusCode,
                        body = respBody,
                        elapsedMs = sw.ElapsedMilliseconds
                    };
                }
            } catch (Exception ex) {
                return new ProxyHttpResponse {
                    ok = false,
                    statusCode = 0,
                    error = ex.GetType().Name + ": " + ex.Message,
                    elapsedMs = sw.ElapsedMilliseconds
                };
            } finally {
                if (tcp != null) { try { tcp.Close(); } catch { } }
            }
        }

        public static StreamHandle StartSseStreamViaProxy(int proxyPort, string apiHost, string tlsPin, string path,
            Dictionary<string, string> headers, object bodyObj, int timeoutMs = 4500) {
            TcpClient tcp;
            var ssl = OpenProxiedTlsTunnel(proxyPort, apiHost, tlsPin, timeoutMs, out tcp);
            try {
                string jsonBody = Json.Serialize(bodyObj ?? new Dictionary<string, object>());
                byte[] bodyBytes = Encoding.UTF8.GetBytes(jsonBody);
                var sb = new StringBuilder();
                sb.AppendFormat("POST {0} HTTP/1.1\r\n", path);
                sb.AppendFormat("Host: {0}\r\n", apiHost);
                sb.Append("Content-Type: application/json; charset=utf-8\r\n");
                sb.Append("Accept: text/event-stream\r\n");
                sb.AppendFormat("Content-Length: {0}\r\n", bodyBytes.Length);
                sb.Append("Connection: keep-alive\r\n");
                if (headers != null) {
                    foreach (var kv in headers) sb.AppendFormat("{0}: {1}\r\n", kv.Key, kv.Value);
                }
                sb.Append("\r\n");
                byte[] headBytes = Encoding.ASCII.GetBytes(sb.ToString());
                ssl.Write(headBytes, 0, headBytes.Length);
                ssl.Write(bodyBytes, 0, bodyBytes.Length);
                ssl.Flush();
                return new StreamHandle(tcp, ssl, 12000);
            } catch {
                try { ssl.Dispose(); } catch { }
                try { tcp.Close(); } catch { }
                throw;
            }
        }

        public static Dictionary<string, object> ProbeDirectTcp(int port) {
            if (port <= 0) return new Dictionary<string, object> { { "skipped", true } };
            try {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
                    s.SendTimeout = 800; s.ReceiveTimeout = 800;
                    s.Connect(new IPEndPoint(IPAddress.Loopback, port));
                    byte[] ping = Encoding.ASCII.GetBytes("BYPASS-CHECK");
                    s.Send(ping);
                    return new Dictionary<string, object> { { "connected", true }, { "wsaError", 0 } };
                }
            } catch (SocketException se) {
                return new Dictionary<string, object> { { "connected", false }, { "wsaError", se.ErrorCode } };
            } catch (Exception ex) {
                return new Dictionary<string, object> { { "connected", false }, { "error", ex.Message } };
            }
        }

        public static Dictionary<string, object> ProbeDirectUdp(int port) {
            if (port <= 0) return new Dictionary<string, object> { { "skipped", true } };
            try {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) {
                    byte[] ping = Encoding.ASCII.GetBytes("UDP-BYPASS-CHECK");
                    int sent = s.SendTo(ping, new IPEndPoint(IPAddress.Loopback, port));
                    return new Dictionary<string, object> { { "sentBytes", sent }, { "wsaError", 0 } };
                }
            } catch (SocketException se) {
                return new Dictionary<string, object> { { "sentBytes", 0 }, { "wsaError", se.ErrorCode } };
            }
        }

        public static int ProbeDnsQuery(string hostName) {
            if (string.IsNullOrWhiteSpace(hostName)) return -1;
            IntPtr res = IntPtr.Zero;
            int rc = DnsQuery_W(hostName, 1 /* DNS_TYPE_A */, 0x00000008 /* DNS_QUERY_BYPASS_CACHE */, IntPtr.Zero, out res, IntPtr.Zero);
            if (res != IntPtr.Zero) DnsRecordListFree(res, 1);
            return rc;
        }

        public static void AtomicWriteJson(string path, object obj) {
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            string tmp = path + ".tmp-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            File.WriteAllText(tmp, Json.Serialize(obj), new UTF8Encoding(false));
            if (File.Exists(path)) File.Delete(path);
            File.Move(tmp, path);
        }
    }
}
