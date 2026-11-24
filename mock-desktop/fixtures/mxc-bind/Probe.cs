using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

static class StudioPsecBind
{
    static readonly string[] Phases = { "before", "during", "after" };

    static object Test(int protocol, bool explicitBind, int port, byte[] marker)
    {
        using (var socket = new Socket(AddressFamily.InterNetwork, protocol == 6 ? SocketType.Stream : SocketType.Dgram,
                                       protocol == 6 ? ProtocolType.Tcp : ProtocolType.Udp)) {
            bool wasBound = socket.IsBound || socket.LocalEndPoint != null;
            int error = 0, bytes = 0, localPort = 0;
            socket.SendTimeout = 1000;
            var target = new IPEndPoint(IPAddress.Loopback, port);
            try {
                if (explicitBind) {
                    socket.Bind(target);
                } else if (protocol == 6) {
                    var pending = socket.BeginConnect(target, null, null);
                    using (var wait = pending.AsyncWaitHandle) {
                        if (!wait.WaitOne(1500)) throw new TimeoutException("Synthetic TCP connect timed out");
                        socket.EndConnect(pending);
                    }
                    bytes = socket.Send(marker);
                } else {
                    bytes = socket.SendTo(marker, target);
                }
            } catch (SocketException exception) { error = exception.NativeErrorCode; }
            if (error == 0) {
                var local = socket.LocalEndPoint as IPEndPoint;
                if (local != null) localPort = local.Port;
            }
            return new { wasBound, error, bytes, localPort };
        }
    }

    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static void Emit(string role, string phase, int tcp, int udp, string marker)
    {
        using (var identity = WindowsIdentity.GetCurrent())
        using (var process = Process.GetCurrentProcess()) {
            object results = null;
            if (marker != null) {
                if (!Regex.IsMatch(marker, "^[0-9a-f]{32}$")) throw new IOException("Invalid phase marker");
                byte[] packet = Encoding.ASCII.GetBytes(marker);
                results = new {
                    explicitTcp = Test(6, true, 0, packet),
                    explicitUdp = Test(17, true, 0, packet),
                    implicitTcp = Test(6, false, tcp, packet),
                    implicitUdp = Test(17, false, udp, packet)
                };
            }
            Console.WriteLine("PSEC-BIND:" + Json.Serialize(new {
                role, phase, marker, sid = identity.User.Value, image = process.MainModule.FileName,
                pid = process.Id, startTicks = process.StartTime.ToUniversalTime().Ticks.ToString(),
                session = process.SessionId, results
            }));
            Console.Out.Flush();
        }
    }

    static string WaitForPhase(string directory, string name, Stopwatch watch)
    {
        string stop = Path.Combine(directory, "stop");
        string go = Path.Combine(directory, name);
        while (watch.Elapsed.TotalSeconds < 55) {
            if (File.Exists(stop)) return null;
            if (File.Exists(go)) return File.ReadAllText(go);
            Thread.Sleep(18);
        }
        throw new TimeoutException(name);
    }

    static int RunContainer(string role, string directory, int tcp, int udp)
    {
        var watch = Stopwatch.StartNew();
        Emit(role, "ready", tcp, udp, null);
        foreach (string phase in Phases) {
            string marker = WaitForPhase(directory, phase + "-" + role, watch);
            if (marker == null) return 0;
            Emit(role, phase, tcp, udp, marker);
        }
        WaitForPhase(directory, "stop", watch);
        return 0;
    }

    static int ParsePort(string value)
    {
        int port = Int32.Parse(value);
        if (port < 49152 || port > 65535) throw new ArgumentOutOfRangeException("port");
        return port;
    }

    static int Main(string[] args)
    {
        try {
            string role = args[0];
            int tcp = ParsePort(args[1]), udp = ParsePort(args[2]);
            if (tcp == udp) return 2;
            if (role == "host") {
                Emit(role, "direct", tcp, udp, args[3]);
                return 0;
            }
            string path = Path.GetFullPath(args[3]);
            if (role == "other") return RunContainer(role, path, tcp, udp);
            if (role != "exact") return 2;
            string childPath = Path.GetFullPath(args[4]);
            if (!String.Equals(Path.GetDirectoryName(childPath), path, StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(childPath) != "StudioMxcBindOther.exe") return 2;
            var start = new ProcessStartInfo(childPath, "other " + tcp + " " + udp + " \"" + path + "\"") {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = path,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            using (var child = Process.Start(start)) {
                child.OutputDataReceived += (s, e) => { if (e.Data != null) { Console.WriteLine(e.Data); Console.Out.Flush(); } };
                child.ErrorDataReceived += (s, e) => { if (e.Data != null) Console.Error.WriteLine(e.Data); };
                child.BeginOutputReadLine();
                child.BeginErrorReadLine();
                try {
                    int result = RunContainer(role, path, tcp, udp);
                    if (!child.WaitForExit(2000)) throw new TimeoutException("PSEC control image did not exit");
                    child.WaitForExit();
                    return result != 0 ? result : child.ExitCode;
                } finally {
                    if (!child.HasExited) { child.Kill(); child.WaitForExit(1500); }
                }
            }
        } catch (Exception exception) {
            Console.Error.WriteLine("PSEC-BIND-ERROR: " + exception);
            return 1;
        }
    }
}
