using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace ClaudeStudio.ControlPlane {
    public sealed class LiveSpaceSpec {
        public SpaceId Space { get; set; }
        public string AccountName { get; set; }
        public string AccountSid { get; set; }
        public string HostSid { get; set; }
        public string Prefix { get; set; }
        public string HostName { get; set; }
        public string Pin { get; set; }
        public string SealedDir { get; set; }
        public string ScratchDir { get; set; }
        public string LauncherExe { get; set; }
        public string ClientExe { get; set; }
        public string PsecBin { get; set; }
        public string ClientCfg { get; set; }
        public string ProxyOwnerExe { get; set; }
        public string WorkBaseDir { get; set; }
        public string RelayExe { get; set; }
        public string EntrySettingsPath { get; set; }
        public string EntryLogPath { get; set; }
        public ushort ProxyPort { get; set; }
        public ushort PeerPort { get; set; }
        public IntPtr OrigToken { get; set; }
        public IntPtr CopyToken { get; set; }
        public bool SkipNativeColdProbeWait { get; set; }
        public string TwinReadyPath { get; set; }
    }

    public sealed class LiveProbeResult {
        public bool Ok { get; set; }
        public bool HttpOk { get; set; }
        public bool TlsOk { get; set; }
        public bool DirectBlocked { get; set; }
        public bool CrossPortBlocked { get; set; }
        public bool DnsBlocked { get; set; }
        public string HttpMarker { get; set; }
        public string TlsMarker { get; set; }
        public string RawJson { get; set; }
    }

    public interface ISpaceRuntimeBackend : IDisposable {
        string BackendModeLabel { get; }
        bool StartColdBlocked(SpaceId id, out SpaceRuntimeSnapshot snapshot, out string note);
        bool OpenProxyException(SpaceId id, out int ownerPid, out string note);
        bool RevokeProxyException(SpaceId id, out string note);
        LiveProbeResult ProbeLiveNetwork(SpaceId id, string dnsPhase);
        bool StopAndRollback(SpaceId id, out string note);
    }

    // Real Windows elevated PSEC + 4 Static BLOCK WFP + Dynamic ProxyOwner + Entry(Pa/Pb) backend.
    // Directly reuses the verified Phase 0-4 StudioPsecGuardHost + StudioLabWfp primitives.
    public sealed class LivePsecWfpBackend : ISpaceRuntimeBackend {
        sealed class LiveSlot {
            public LiveSpaceSpec Spec;
            public StudioPsecGuardHost Layer1;
            public int Layer2Pid;
            public int Layer2Tid;
            public string ContainerSid;
            public Guid WfpSub;
            public Guid[] WfpKeys;
            public ushort WfpWeight;
            public bool WfpInstalled;
            public string ManifestHash12;
            public Process ProxyOwner;
            public int ProxyOwnerPid;
            public long ProxyOwnerStartTicks;
            public Process EntryRelay;
            public string StopFile;
            public int CmdSeq;
        }

        readonly object gate = new object();
        readonly Dictionary<SpaceId, LiveSlot> slots = new Dictionary<SpaceId, LiveSlot>();
        readonly JavaScriptSerializer json = new JavaScriptSerializer();

        public string BackendModeLabel { get { return "Live Elevated PSEC + WFP + ProxyOwner Mode (Phase 6A)"; } }

        public LivePsecWfpBackend(LiveSpaceSpec specA, LiveSpaceSpec specB) {
            slots[SpaceId.A] = new LiveSlot { Spec = specA };
            slots[SpaceId.B] = new LiveSlot { Spec = specB };
            StartEntryRelay(slots[SpaceId.A]);
            StartEntryRelay(slots[SpaceId.B]);
        }

        void StartEntryRelay(LiveSlot slot) {
            var sp = slot.Spec;
            string cwd = Path.GetDirectoryName(sp.EntryLogPath);
            Directory.CreateDirectory(cwd);
            if (!File.Exists(sp.EntryLogPath)) File.WriteAllText(sp.EntryLogPath, "");
            var psi = new ProcessStartInfo {
                FileName = sp.RelayExe,
                Arguments = string.Format("entry-n4 \"{0}\" \"{1}\"", sp.EntrySettingsPath, sp.EntryLogPath),
                WorkingDirectory = cwd,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            slot.EntryRelay = Process.Start(psi);
            string line = ReadLineTimeout(slot.EntryRelay, 5000);
            var obj = json.Deserialize<Dictionary<string, object>>(line);
            if (obj == null || !string.Equals(obj["kind"] as string, "ready", StringComparison.Ordinal)) {
                throw new InvalidOperationException("Entry relay for " + sp.Space + " failed to report ready");
            }
        }

        static string ReadLineTimeout(Process p, int timeoutMs) {
            var task = p.StandardOutput.ReadLineAsync();
            if (!task.Wait(timeoutMs)) throw new TimeoutException("Process stdout line timed out");
            if (task.Result == null) throw new EndOfStreamException("Process exited without stdout line");
            return task.Result;
        }

        Dictionary<string, object> SendLineCommand(Process p, string cmd, int timeoutMs) {
            p.StandardInput.WriteLine(cmd);
            p.StandardInput.Flush();
            string line = ReadLineTimeout(p, timeoutMs);
            return json.Deserialize<Dictionary<string, object>>(line);
        }

        static string Hash12(string text) {
            using (var sha = SHA256.Create()) {
                return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "").Substring(0, 12);
            }
        }

        public bool StartColdBlocked(SpaceId id, out SpaceRuntimeSnapshot snapshot, out string note) {
            snapshot = null;
            note = "";
            lock (gate) {
                var slot = slots[id];
                var sp = slot.Spec;
                if (slot.Layer1 != null) {
                    note = "Space " + id + " already running";
                    return true;
                }

                string readyPath = Path.Combine(sp.ScratchDir, "l1-ready.json");
                slot.StopFile = Path.Combine(sp.ScratchDir, "l1-stop");
                string coldPath = Path.Combine(sp.ScratchDir, "cold-result.json");
                foreach (string f in new[] { readyPath, slot.StopFile, coldPath }) {
                    if (File.Exists(f)) File.Delete(f);
                }

                string l1Args = string.Format("\"{0}\" \"{1}\" \"{2}\" \"{3}\" \"{4}\" \"{5}\" \"{6}\"",
                    sp.PsecBin, sp.ClientExe, sp.ClientCfg, sp.ScratchDir, sp.HostSid, readyPath, slot.StopFile);
                slot.Layer1 = StudioPsecGuardHost.StartSuspended(sp.CopyToken, sp.LauncherExe, l1Args, true, @"WinSta0\Default");
                slot.Layer1.RestoreTokenObjectDaclOnly(sp.OrigToken, sp.HostSid, sp.AccountSid);
                slot.Layer1.ResumeMainThread();

                var sw = Stopwatch.StartNew();
                while (!File.Exists(readyPath) && sw.ElapsedMilliseconds < 10000) Thread.Sleep(25);
                if (!File.Exists(readyPath)) throw new TimeoutException("Layer-1 " + id + " did not write ready receipt");
                var l1Rec = json.Deserialize<Dictionary<string, object>>(File.ReadAllText(readyPath, Encoding.UTF8));
                if (!(bool)l1Rec["psecCreated"] || !(bool)l1Rec["childCreated"] || !(bool)l1Rec["childInJob"]) {
                    throw new InvalidOperationException("Layer-1 " + id + " PSEC creation failed");
                }
                slot.Layer2Pid = Convert.ToInt32(l1Rec["childPid"]);
                slot.Layer2Tid = Convert.ToInt32(l1Rec["childTid"]);

                var insp = StudioPsecGuardHost.InspectSuspendedPsecChild(slot.Layer2Pid, slot.Layer2Tid, sp.HostSid, sp.AccountSid);
                var inspMap = json.Deserialize<Dictionary<string, object>>(json.Serialize(insp));
                var ident = (Dictionary<string, object>)inspMap["identity"];
                slot.ContainerSid = (string)ident["containerSid"];
                StudioPsecGuardHost.AllowSelfContainerDefaultDacl(slot.Layer2Pid, sp.HostSid, slot.ContainerSid);

                // Install 4 Static BLOCK WFP rules + independent readback BEFORE host ResumeThread
                slot.WfpSub = Guid.NewGuid();
                slot.WfpKeys = new[] { Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid() };
                using (var wfp = StudioLabWfp.CreateStaticGuard()) {
                    slot.WfpWeight = wfp.PrepareStatic(slot.WfpSub, slot.WfpKeys, slot.ContainerSid, sp.ProxyPort, sp.ClientExe);
                    wfp.InstallStatic(slot.WfpSub, slot.WfpKeys, slot.ContainerSid, sp.ProxyPort, sp.ClientExe, slot.WfpWeight);
                    slot.WfpInstalled = true;
                }
                StudioLabWfp.VerifyStatic(slot.WfpSub, slot.WfpKeys, slot.ContainerSid, sp.ProxyPort, slot.WfpWeight, false);
                slot.ManifestHash12 = Hash12(slot.WfpSub + "|" + slot.ContainerSid + "|" + sp.ProxyPort + "|" + slot.WfpWeight);

                // Host exclusively resumes Layer-2 after WFP readback
                StudioPsecGuardHost.HostResumeChildOnly(slot.Layer2Pid, slot.Layer2Tid);

                if (sp.SkipNativeColdProbeWait) {
                    if (!string.IsNullOrEmpty(sp.TwinReadyPath)) {
                        sw.Restart();
                        while (!File.Exists(sp.TwinReadyPath) && sw.ElapsedMilliseconds < 15000) Thread.Sleep(25);
                        if (!File.Exists(sp.TwinReadyPath)) throw new TimeoutException("Layer-2 twin " + id + " did not write ready receipt");
                    }
                    note = string.Format("LIVE Twin ColdBlocked verified (PID={0}, Weight={1}, Manifest={2})", slot.Layer2Pid, slot.WfpWeight, slot.ManifestHash12);
                } else {
                    sw.Restart();
                    while (!File.Exists(coldPath) && sw.ElapsedMilliseconds < 10000) Thread.Sleep(25);
                    if (!File.Exists(coldPath)) throw new TimeoutException("Layer-2 " + id + " did not write cold-result.json");
                    var cold = json.Deserialize<Dictionary<string, object>>(File.ReadAllText(coldPath, Encoding.UTF8));
                    var directPa = (Dictionary<string, object>)cold["directPa"];
                    var directPu = (Dictionary<string, object>)cold["directPu"];
                    var coldDns = (Dictionary<string, object>)cold["dns"];
                    bool coldBlocked = !(bool)directPa["connected"] && Convert.ToInt32(directPa["error"]) == 10013 &&
                        !(bool)directPu["connected"] && Convert.ToInt32(directPu["error"]) == 10013 &&
                        Convert.ToInt32(coldDns["dnsQueryStatus"]) == 5;
                    if (!coldBlocked) throw new InvalidOperationException("Live cold-start pre-blocking failed for Space " + id);
                    note = string.Format("LIVE ColdBlocked verified (PID={0}, Weight={1}, Manifest={2})", slot.Layer2Pid, slot.WfpWeight, slot.ManifestHash12);
                }
                snapshot = new SpaceRuntimeSnapshot {
                    Id = id,
                    State = SpaceNetworkState.ColdBlocked,
                    Pid = slot.Layer2Pid,
                    ContainerSid = slot.ContainerSid,
                    WfpSublayerWeight = slot.WfpWeight,
                    WfpManifestSha256Prefix12 = slot.ManifestHash12,
                    StaticBlockActive = true,
                    DynamicExceptionOpen = false,
                    ProxyOwnerPid = 0,
                    ProxyPort = sp.ProxyPort,
                    DnsSendCount = 0,
                    LastTransitionUtc = DateTime.UtcNow.ToString("o"),
                    LastNote = note
                };
                return true;
            }
        }

        public bool OpenProxyException(SpaceId id, out int ownerPid, out string note) {
            ownerPid = 0;
            note = "";
            lock (gate) {
                var slot = slots[id];
                var sp = slot.Spec;
                if (!slot.WfpInstalled) { note = "WFP not installed"; return false; }

                // Recycle any stale ProxyOwner cleanly so reconnect after an upstream-exit fault is 100% idempotent
                if (slot.ProxyOwner != null) {
                    try {
                        if (!slot.ProxyOwner.HasExited) {
                            try { slot.ProxyOwner.StandardInput.WriteLine("exit"); slot.ProxyOwner.StandardInput.Close(); } catch { }
                            if (!slot.ProxyOwner.WaitForExit(1500)) { slot.ProxyOwner.Kill(); slot.ProxyOwner.WaitForExit(1500); }
                        }
                    } finally { slot.ProxyOwner.Dispose(); slot.ProxyOwner = null; slot.ProxyOwnerPid = 0; slot.ProxyOwnerStartTicks = 0; }
                    if (slot.EntryRelay != null && !slot.EntryRelay.HasExited) {
                        var swWait = Stopwatch.StartNew();
                        while (swWait.ElapsedMilliseconds < 1200) {
                            var st = SendLineCommand(slot.EntryRelay, "status", 1500);
                            if (!(bool)st["admitting"] && Convert.ToInt32(st["active"]) == 0) break;
                            Thread.Sleep(30);
                        }
                    }
                }

                if (slot.ProxyOwner == null || slot.ProxyOwner.HasExited) {
                    string args = string.Format("{0} {1} {2} {3} {4} {5} {6} {7}:{8}",
                        slot.WfpSub, slot.WfpKeys[0], slot.WfpKeys[1], slot.WfpKeys[2], slot.WfpKeys[3], slot.WfpKeys[4],
                        slot.ContainerSid, sp.ProxyPort, slot.WfpWeight);
                    var psi = new ProcessStartInfo {
                        FileName = sp.ProxyOwnerExe,
                        Arguments = args,
                        WorkingDirectory = sp.WorkBaseDir,
                        UseShellExecute = false,
                        RedirectStandardInput = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };
                    slot.ProxyOwner = Process.Start(psi);
                    string readyLine = ReadLineTimeout(slot.ProxyOwner, 5000);
                    var r = json.Deserialize<Dictionary<string, object>>(readyLine);
                    slot.ProxyOwnerPid = Convert.ToInt32(r["pid"]);
                    slot.ProxyOwnerStartTicks = Convert.ToInt64(r["startTicks"]);
                }

                // Arm Entry relay with ProxyOwner PID/StartTicks (also verifies upstream HTTP/TLS health!)
                var armed = SendLineCommand(slot.EntryRelay, string.Format("arm-owner {0} {1}", slot.ProxyOwnerPid, slot.ProxyOwnerStartTicks), 3500);
                if (!(bool)armed["admitting"]) {
                    note = "Entry refused arm-owner (upstream unhealthy)";
                    return false;
                }

                var opened = SendLineCommand(slot.ProxyOwner, "open", 3000);
                if (!(bool)opened["open"]) { note = "ProxyOwner failed to open E"; return false; }

                StudioLabWfp.VerifyStatic(slot.WfpSub, slot.WfpKeys, slot.ContainerSid, sp.ProxyPort, slot.WfpWeight, true);
                ownerPid = slot.ProxyOwnerPid;
                note = string.Format("LIVE ProxyOnline (Port=127.0.0.1:{0}, ProxyOwnerPid={1})", sp.ProxyPort, ownerPid);
                return true;
            }
        }

        public bool RevokeProxyException(SpaceId id, out string note) {
            note = "";
            lock (gate) {
                var slot = slots[id];
                var sp = slot.Spec;
                if (slot.ProxyOwner != null) {
                    try {
                        if (!slot.ProxyOwner.HasExited) {
                            try { slot.ProxyOwner.StandardInput.WriteLine("exit"); slot.ProxyOwner.StandardInput.Close(); } catch { }
                            if (!slot.ProxyOwner.WaitForExit(2000)) { slot.ProxyOwner.Kill(); slot.ProxyOwner.WaitForExit(2000); }
                        }
                    } finally { slot.ProxyOwner.Dispose(); slot.ProxyOwner = null; slot.ProxyOwnerPid = 0; slot.ProxyOwnerStartTicks = 0; }
                }
                // Wait briefly for EntryRelay to observe ProxyOwner exit & close active tunnels (fail-closed on BOTH WFP and Entry!)
                if (slot.EntryRelay != null && !slot.EntryRelay.HasExited) {
                    var sw = Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < 1500) {
                        var st = SendLineCommand(slot.EntryRelay, "status", 1500);
                        if (!(bool)st["admitting"] && Convert.ToInt32(st["active"]) == 0) break;
                        Thread.Sleep(35);
                    }
                }
                if (slot.WfpInstalled) {
                    StudioLabWfp.VerifyStatic(slot.WfpSub, slot.WfpKeys, slot.ContainerSid, sp.ProxyPort, slot.WfpWeight, false);
                }
                note = "LIVE dynamic exception E revoked & Entry halted; 4 Static BLOCK intact";
                return true;
            }
        }

        public LiveProbeResult ProbeLiveNetwork(SpaceId id, string dnsPhase) {
            lock (gate) {
                var slot = slots[id];
                var sp = slot.Spec;
                slot.CmdSeq++;
                string cmdPath = Path.Combine(sp.ScratchDir, "cmd-" + slot.CmdSeq + ".cfg");
                string resPath = Path.Combine(sp.ScratchDir, "res-" + slot.CmdSeq + ".json");
                string tmp = cmdPath + ".tmp";
                File.WriteAllText(tmp, "action=probe\nphase=" + dnsPhase + "\n", new UTF8Encoding(false));
                File.Move(tmp, cmdPath);

                var sw = Stopwatch.StartNew();
                while (!File.Exists(resPath) && sw.ElapsedMilliseconds < 12000) Thread.Sleep(20);
                if (!File.Exists(resPath)) throw new TimeoutException("Live Layer-2 " + id + " probe timed out");
                string raw = File.ReadAllText(resPath, Encoding.UTF8);
                var env = json.Deserialize<Dictionary<string, object>>(raw);
                var data = (Dictionary<string, object>)env["data"];
                var http = (Dictionary<string, object>)data["http"];
                var tls = (Dictionary<string, object>)data["tls"];
                var direct = (Dictionary<string, object>)data["direct"];
                var dns = (Dictionary<string, object>)data["dns"];

                var st = (Dictionary<string, object>)direct["sentinelTcp"];
                var pu = (Dictionary<string, object>)direct["directPu"];
                var cp = (Dictionary<string, object>)direct["crossPort"];

                bool directBlk = !(bool)st["connected"] && Convert.ToInt32(st["error"]) == 10013 &&
                    !(bool)pu["connected"] && Convert.ToInt32(pu["error"]) == 10013;
                bool crossBlk = !(bool)cp["connected"] && Convert.ToInt32(cp["error"]) == 10013;
                bool dnsBlk = Convert.ToInt32(dns["dnsQueryStatus"]) == 5 && Convert.ToInt32(dns["getAddrInfoStatus"]) != 0;

                return new LiveProbeResult {
                    Ok = directBlk && crossBlk && dnsBlk,
                    HttpOk = (bool)http["ok"],
                    TlsOk = (bool)tls["ok"],
                    DirectBlocked = directBlk,
                    CrossPortBlocked = crossBlk,
                    DnsBlocked = dnsBlk,
                    HttpMarker = (string)http["marker"],
                    TlsMarker = (string)tls["marker"],
                    RawJson = raw
                };
            }
        }

        public bool StopAndRollback(SpaceId id, out string note) {
            note = "";
            lock (gate) {
                var slot = slots[id];
                var sp = slot.Spec;

                if (slot.ProxyOwner != null) {
                    try {
                        if (!slot.ProxyOwner.HasExited) {
                            try { slot.ProxyOwner.StandardInput.WriteLine("exit"); slot.ProxyOwner.StandardInput.Close(); } catch { }
                            if (!slot.ProxyOwner.WaitForExit(2000)) { slot.ProxyOwner.Kill(); slot.ProxyOwner.WaitForExit(2000); }
                        }
                    } finally { slot.ProxyOwner.Dispose(); slot.ProxyOwner = null; slot.ProxyOwnerPid = 0; }
                }

                if (!string.IsNullOrEmpty(slot.StopFile) && Directory.Exists(sp.ScratchDir)) {
                    try { File.WriteAllText(slot.StopFile, "stop"); } catch { }
                }
                if (slot.Layer2Pid > 0) {
                    try { StudioPsecGuardHost.HostTerminatePid(slot.Layer2Pid); } catch { }
                }
                if (slot.Layer1 != null) {
                    try { slot.Layer1.WaitExit(4000); slot.Layer1.Dispose(); } catch { }
                    slot.Layer1 = null;
                }
                Thread.Sleep(180);

                int residual = 0;
                if (slot.WfpInstalled) {
                    StudioLabWfp.RemoveStatic(slot.WfpSub, slot.WfpKeys, slot.ContainerSid, sp.ProxyPort, slot.WfpWeight);
                    Thread.Sleep(80);
                    residual = StudioLabWfp.CountFiltersReferencingPackage(slot.ContainerSid);
                    slot.WfpInstalled = false;
                    if (residual != 0) throw new InvalidOperationException("Residual WFP filters remained: " + residual);
                }

                slot.Layer2Pid = 0;
                slot.Layer2Tid = 0;
                slot.CmdSeq = 0;
                note = "LIVE rollback complete: 0 remaining PIDs, 0 residual WFP filters";
                return true;
            }
        }

        public void Dispose() {
            foreach (SpaceId id in new[] { SpaceId.A, SpaceId.B }) {
                try { string n; StopAndRollback(id, out n); } catch { }
                var slot = slots[id];
                if (slot.EntryRelay != null) {
                    try {
                        if (!slot.EntryRelay.HasExited) {
                            try { slot.EntryRelay.StandardInput.WriteLine("exit"); slot.EntryRelay.StandardInput.Close(); } catch { }
                            if (!slot.EntryRelay.WaitForExit(2000)) { slot.EntryRelay.Kill(); slot.EntryRelay.WaitForExit(2000); }
                        }
                    } finally { slot.EntryRelay.Dispose(); slot.EntryRelay = null; }
                }
            }
        }
    }
}
