using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Web.Script.Serialization;

// Standalone short-lived process holding ONLY the FWPM_SESSION_FLAG_DYNAMIC exception E
// (TCP 127.0.0.1:Pa for exact ALE_PACKAGE_ID). When closed or hard-killed, Windows BFE
// automatically deletes E while the 4 Static BLOCK filters remain intact.
internal static class Phase1ProxyOwner {
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();

    static int Main(string[] args) {
        Console.OutputEncoding = new UTF8Encoding(false);
        try {
            if (args.Length != 8) throw new ArgumentException("Expected: <sublayer> <k0> <k1> <k2> <k3> <k4> <containerSid> <port:weight>");
            Guid sublayer = Guid.Parse(args[0]);
            Guid[] keys = new[] {
                Guid.Parse(args[1]), Guid.Parse(args[2]), Guid.Parse(args[3]), Guid.Parse(args[4]), Guid.Parse(args[5])
            };
            string containerSid = args[6];
            string[] pw = args[7].Split(':');
            if (pw.Length != 2) throw new ArgumentException("Expected port:weight");
            ushort port = ushort.Parse(pw[0], CultureInfo.InvariantCulture);
            ushort weight = ushort.Parse(pw[1], CultureInfo.InvariantCulture);

            using (var guard = StudioLabWfp.CreateStaticExceptionGuard()) {
                guard.AttachStaticException(sublayer, keys, containerSid, port, weight);
                var proc = Process.GetCurrentProcess();
                Console.WriteLine(Json.Serialize(new Dictionary<string, object> {
                    { "kind", "ready" },
                    { "pid", proc.Id },
                    { "startTicks", proc.StartTime.ToUniversalTime().Ticks },
                    { "port", port },
                    { "weight", weight }
                }));

                string line;
                while ((line = Console.ReadLine()) != null) {
                    string cmd = line.Trim();
                    if (cmd == "exit") {
                        guard.SetStaticException(false);
                        Console.WriteLine(Json.Serialize(new Dictionary<string, object> { { "cmd", "exit" }, { "ok", true }, { "open", false } }));
                        break;
                    } else if (cmd == "open") {
                        guard.SetStaticException(true);
                        Console.WriteLine(Json.Serialize(new Dictionary<string, object> { { "cmd", "open" }, { "ok", true }, { "open", true } }));
                    } else if (cmd == "close") {
                        guard.SetStaticException(false);
                        Console.WriteLine(Json.Serialize(new Dictionary<string, object> { { "cmd", "close" }, { "ok", true }, { "open", false } }));
                    } else if (cmd == "status") {
                        bool present = StudioLabWfp.StaticExceptionPresent(sublayer, keys, containerSid, port, weight);
                        Console.WriteLine(Json.Serialize(new Dictionary<string, object> { { "cmd", "status" }, { "ok", true }, { "open", present } }));
                    } else {
                        throw new ArgumentException("Unknown ProxyOwner command: " + cmd);
                    }
                }
            }
            return 0;
        } catch (Exception ex) {
            Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message);
            return 2;
        }
    }
}
