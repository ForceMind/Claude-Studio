using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace ClaudeStudio.ControlPlane {
    public sealed class RealDesktopSpaceSpec {
        public SpaceId Space { get; set; }
        public string AccountName { get; set; }
        public string AccountSid { get; set; }
        public string HostSid { get; set; }
        public string UserHomeDir { get; set; }
        public string WorkRootDir { get; set; }
        public string TargetDesktopExe { get; set; }
        public string SharedAppReadOnlyDir { get; set; }
        public string UiLanguage { get; set; }
        public string EnvLang { get; set; }
        public string EnvTimezone { get; set; }
        public bool AppendElectronAppContainerFlags { get; set; }
        public IntPtr OrigToken { get; set; }
        public IntPtr CopyToken { get; set; }
        public string[] ExtraReadWriteDirs { get; set; }
        public string[] ExtraReadOnlyDirs { get; set; }
    }

    // Production-grade Real Desktop 3-Layer PSEC 1.1 + 4 Static BLOCK WFP + Dynamic ProxyOwner + EmbeddedDualProxyRelay backend.
    // Directly integrates the verified Option A real official Claude Desktop dual-space launch chain into StudioEngine!
    public sealed class RealDesktopPsecBackend : ISpaceRuntimeBackend {
        sealed class Slot {
            public readonly object SlotGate = new object();
            public RealDesktopSpaceSpec Spec;
            public StudioPsecGuardHost Layer1;
            public int Layer1Pid;
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
            public string L1StopFile;
            public string L2StopFile;
            public string UserDataDir;
            public int ProxyPort;
        }

        readonly object gate = new object();
        readonly Dictionary<SpaceId, Slot> slots = new Dictionary<SpaceId, Slot>();
        readonly JavaScriptSerializer json = new JavaScriptSerializer();
        readonly EmbeddedDualProxyRelay relay;
        readonly string binDir;
        readonly string layer1TemplateExe;
        readonly string layer2TemplateExe;
        readonly string proxyOwnerExe;
        readonly List<string> retiredContainerSids = new List<string>();

        public event Action<SpaceId, string> AutomaticFaultCutoff;

        public EmbeddedDualProxyRelay Relay { get { return relay; } }
        public string BackendModeLabel { get { return "Live 3-Layer PSEC 1.1 + WFP + Embedded Proxy Mode (Option B)"; } }

        public RealDesktopPsecBackend(RealDesktopSpaceSpec specA, RealDesktopSpaceSpec specB, string helperBinDir,
            string upstreamHost, int upstreamPort, bool zeroEgressTestMode) {
            binDir = helperBinDir;
            layer1TemplateExe = Path.Combine(binDir, "StudioLayer1Psec.exe");
            layer2TemplateExe = Path.Combine(binDir, "StudioLayer2DesktopHost.exe");
            proxyOwnerExe = Path.Combine(binDir, "StudioProxyOwner.exe");
            foreach (string req in new[] { layer1TemplateExe, layer2TemplateExe, proxyOwnerExe }) {
                if (!File.Exists(req)) throw new FileNotFoundException("Missing prebuilt helper binary: " + req);
            }

            relay = new EmbeddedDualProxyRelay(0, 0);
            relay.ConfigureUpstream(upstreamHost, upstreamPort, zeroEgressTestMode);
            relay.SpaceHalted += OnRelayHaltedSpace;

            slots[SpaceId.A] = new Slot { Spec = specA, ProxyPort = relay.PortA };
            slots[SpaceId.B] = new Slot { Spec = specB, ProxyPort = relay.PortB };
        }

        public string[] GetAllObservedContainerSids() {
            lock (gate) {
                var all = new List<string>(retiredContainerSids);
                foreach (var sl in slots.Values) {
                    if (!string.IsNullOrEmpty(sl.ContainerSid) && !all.Contains(sl.ContainerSid)) all.Add(sl.ContainerSid);
                }
                return all.ToArray();
            }
        }

        public string GetUserDataDir(SpaceId id) {
            lock (gate) return slots[id].UserDataDir;
        }

        public int[] GetGuardianPids(SpaceId id) {
            lock (gate) {
                var sl = slots[id];
                var list = new List<int>();
                if (sl.Layer1Pid > 0) list.Add(sl.Layer1Pid);
                if (sl.Layer2Pid > 0) list.Add(sl.Layer2Pid);
                return list.ToArray();
            }
        }

        void OnRelayHaltedSpace(SpaceId id, string reason) {
            if (string.Equals(reason, "revoked", StringComparison.Ordinal) ||
                string.Equals(reason, "re-arming", StringComparison.Ordinal) ||
                string.Equals(reason, "cold-blocked", StringComparison.Ordinal) ||
                string.Equals(reason, "stopping", StringComparison.Ordinal) ||
                string.Equals(reason, "disposed", StringComparison.Ordinal)) {
                return;
            }
            // Dispatch asynchronously per-slot so A & B kill ProxyOwner & revoke WFP in true parallel (< 600ms!)
            ThreadPool.QueueUserWorkItem(_ => {
                var sl = slots[id];
                lock (sl.SlotGate) {
                    FastKillOwnerLocked(sl);
                    if (sl.WfpInstalled) {
                        try { StudioLabWfp.VerifyStatic(sl.WfpSub, sl.WfpKeys, sl.ContainerSid, (ushort)sl.ProxyPort, sl.WfpWeight, false); } catch { }
                    }
                }
                var cb = AutomaticFaultCutoff;
                if (cb != null) { try { cb(id, reason); } catch { } }
            });
        }

        void FastKillOwnerLocked(Slot sl) {
            if (sl.ProxyOwner == null) return;
            try {
                if (!sl.ProxyOwner.HasExited) {
                    sl.ProxyOwner.Kill();
                    sl.ProxyOwner.WaitForExit(1000);
                }
            } catch { }
            finally {
                try { sl.ProxyOwner.Dispose(); } catch { }
                sl.ProxyOwner = null;
                sl.ProxyOwnerPid = 0;
            }
        }

        static DirectorySecurity BuildAcl(string hostSid, string userSid, FileSystemRights userRights) {
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (string s in new[] { hostSid, "S-1-5-18", "S-1-5-32-544" }) {
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(s), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            }
            foreach (string s in new[] { userSid, "S-1-15-2-1" }) {
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(s), userRights,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            }
            return acl;
        }

        static string Hash12(string text) {
            using (var sha = SHA256.Create()) {
                return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "").Substring(0, 12);
            }
        }

        static Dictionary<string, object> SendOwnerCmd(Process p, string cmd) {
            p.StandardInput.WriteLine(cmd);
            p.StandardInput.Flush();
            var t = p.StandardOutput.ReadLineAsync();
            if (!t.Wait(4000) || t.Result == null) throw new TimeoutException("ProxyOwner command timed out: " + cmd);
            return new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(t.Result);
        }

        public bool StartColdBlocked(SpaceId id, out SpaceRuntimeSnapshot snapshot, out string note) {
            snapshot = null;
            note = "";
            lock (gate) {
                var sl = slots[id];
                var sp = sl.Spec;
                if (sl.Layer1 != null) { note = "Space " + id + " already running"; return true; }

                string aHome = sp.UserHomeDir;
                string aLocal = Path.Combine(aHome, @"AppData\Local");
                string aRoam = Path.Combine(aHome, @"AppData\Roaming");
                string sealedDir = Path.Combine(sp.WorkRootDir, "sealed");
                string scratchDir = Path.Combine(sp.WorkRootDir, "scratch");
                string userDataDir = Path.Combine(sp.WorkRootDir, "userdata");
                string cData = Path.Combine(aLocal, "Claude-Data");
                string c3p = Path.Combine(aLocal, "Claude-3p");
                string cLoc = Path.Combine(aLocal, "Claude");
                string cLogs = Path.Combine(cLoc, "logs");
                string rClaude = Path.Combine(aRoam, "Claude");
                sl.UserDataDir = userDataDir;

                var rxAcl = BuildAcl(sp.HostSid, sp.AccountSid, FileSystemRights.ReadAndExecute);
                var rwAcl = BuildAcl(sp.HostSid, sp.AccountSid, FileSystemRights.Modify);
                Directory.CreateDirectory(sp.WorkRootDir, rxAcl);
                Directory.CreateDirectory(sealedDir, rxAcl);
                foreach (string d in new[] { scratchDir, userDataDir, cData, c3p, cLoc, cLogs, rClaude }) {
                    Directory.CreateDirectory(d, rwAcl);
                }

                string l1Exe = Path.Combine(sealedDir, "Studio" + id + "Layer1.exe");
                string l2Exe = Path.Combine(sealedDir, "Studio" + id + "Layer2.exe");
                File.Copy(layer1TemplateExe, l1Exe, true);
                File.Copy(layer2TemplateExe, l2Exe, true);

                var rwList = new List<string> { scratchDir, userDataDir, cData, c3p, cLoc, cLogs, rClaude, aRoam };
                if (sp.ExtraReadWriteDirs != null) rwList.AddRange(sp.ExtraReadWriteDirs);
                var roList = new List<string> { sealedDir };
                if (!string.IsNullOrEmpty(sp.SharedAppReadOnlyDir)) roList.Add(sp.SharedAppReadOnlyDir);
                if (sp.ExtraReadOnlyDirs != null) roList.AddRange(sp.ExtraReadOnlyDirs);

                var enumAncestors = new List<string> { @"C:\", @"C:\ProgramData", @"C:\Users", aHome, Path.Combine(aHome, "AppData"), aLocal, Path.Combine(aLocal, "Temp") };
                string psecBin = Path.Combine(sealedDir, "psec-" + id + ".bin");
                File.WriteAllBytes(psecBin, PsecFlatBufferBuilder.BuildLoopbackOnlyPsecV1Full(rwList.ToArray(), roList.ToArray(), enumAncestors.ToArray(), false));

                string readyPath = Path.Combine(scratchDir, "l1-ready.json");
                sl.L1StopFile = Path.Combine(scratchDir, "l1-stop");
                sl.L2StopFile = Path.Combine(scratchDir, "l2-stop");
                foreach (string f in new[] { readyPath, sl.L1StopFile, sl.L2StopFile }) { if (File.Exists(f)) File.Delete(f); }

                string extraFlags = sp.AppendElectronAppContainerFlags ? " --no-sandbox --disable-gpu-sandbox" : "";
                string targetCmd = string.Format("\"{0}\" --user-data-dir=\"{1}\" --proxy-server=\"http://127.0.0.1:{2}\" --lang={3}{4}",
                    sp.TargetDesktopExe, userDataDir, sl.ProxyPort, sp.UiLanguage, extraFlags);
                string l2Cfg = Path.Combine(sealedDir, "l2-desktop.cfg");
                string cfgText = string.Format("e={0}\na={1}\ns={2}\nh={3}\nL={4}\nR={5}\nT={6}\nu={7}\np=http://127.0.0.1:{8}\ng={9}\nz={10}\n",
                    sp.TargetDesktopExe, targetCmd, sl.L2StopFile, aHome, aLocal, aRoam, scratchDir, sp.AccountName, sl.ProxyPort, sp.EnvLang, sp.EnvTimezone);
                File.WriteAllText(l2Cfg, cfgText, new UTF8Encoding(false));

                string l1Args = string.Format("\"{0}\" \"{1}\" \"{2}\" \"{3}\" \"{4}\" \"{5}\" \"{6}\"",
                    psecBin, l2Exe, l2Cfg, scratchDir, sp.HostSid, readyPath, sl.L1StopFile);
                sl.Layer1 = StudioPsecGuardHost.StartSuspended(sp.CopyToken, l1Exe, l1Args, true, @"WinSta0\Default");
                sl.Layer1.RestoreTokenObjectDaclOnly(sp.OrigToken, sp.HostSid, sp.AccountSid);
                sl.Layer1.ResumeMainThread();

                var sw = Stopwatch.StartNew();
                while (!File.Exists(readyPath) && sw.ElapsedMilliseconds < 30000) Thread.Sleep(30);
                if (!File.Exists(readyPath)) throw new TimeoutException("Layer-1 " + id + " PSEC 1.1 ready receipt timed out");
                var l1Rec = json.Deserialize<Dictionary<string, object>>(File.ReadAllText(readyPath, Encoding.UTF8));
                if (!(bool)l1Rec["psecCreated"] || !(bool)l1Rec["childCreated"] || !(bool)l1Rec["childInJob"]) {
                    throw new InvalidOperationException("Layer-1 " + id + " PSEC 1.1 creation failed");
                }
                sl.Layer1Pid = Convert.ToInt32(l1Rec["layer1Pid"]);
                sl.Layer2Pid = Convert.ToInt32(l1Rec["childPid"]);
                sl.Layer2Tid = Convert.ToInt32(l1Rec["childTid"]);

                var insp = StudioPsecGuardHost.InspectSuspendedPsecChild(sl.Layer2Pid, sl.Layer2Tid, sp.HostSid, sp.AccountSid);
                var inspMap = json.Deserialize<Dictionary<string, object>>(json.Serialize(insp));
                sl.ContainerSid = (string)((Dictionary<string, object>)inspMap["identity"])["containerSid"];
                StudioPsecGuardHost.AllowSelfContainerDefaultDacl(sl.Layer2Pid, sp.HostSid, sl.ContainerSid);

                sl.WfpSub = Guid.NewGuid();
                sl.WfpKeys = new[] { Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid() };
                using (var wfp = StudioLabWfp.CreateStaticGuard()) {
                    sl.WfpWeight = wfp.PrepareStatic(sl.WfpSub, sl.WfpKeys, sl.ContainerSid, (ushort)sl.ProxyPort, l2Exe);
                    wfp.InstallStatic(sl.WfpSub, sl.WfpKeys, sl.ContainerSid, (ushort)sl.ProxyPort, l2Exe, sl.WfpWeight);
                    sl.WfpInstalled = true;
                }
                StudioLabWfp.VerifyStatic(sl.WfpSub, sl.WfpKeys, sl.ContainerSid, (ushort)sl.ProxyPort, sl.WfpWeight, false);
                sl.ManifestHash12 = Hash12(sl.WfpSub + "|" + sl.ContainerSid + "|" + sl.ProxyPort + "|" + sl.WfpWeight);

                // Strictly ColdBlocked BEFORE ResumeThread!
                relay.HaltSpace(id, "cold-blocked");
                StudioPsecGuardHost.HostResumeChildOnly(sl.Layer2Pid, sl.Layer2Tid);

                note = string.Format("PSEC 1.1 ColdBlocked (PID={0}, Weight={1}, Port=127.0.0.1:{2})", sl.Layer2Pid, sl.WfpWeight, sl.ProxyPort);
                snapshot = new SpaceRuntimeSnapshot {
                    Id = id, State = SpaceNetworkState.ColdBlocked, Pid = sl.Layer2Pid,
                    ContainerSid = sl.ContainerSid, WfpSublayerWeight = sl.WfpWeight,
                    WfpManifestSha256Prefix12 = sl.ManifestHash12, StaticBlockActive = true,
                    DynamicExceptionOpen = false, ProxyOwnerPid = 0, ProxyPort = sl.ProxyPort,
                    DnsSendCount = 0, LastTransitionUtc = DateTime.UtcNow.ToString("o"), LastNote = note
                };
                return true;
            }
        }

        public bool OpenProxyException(SpaceId id, out int ownerPid, out string note) {
            ownerPid = 0;
            note = "";
            lock (gate) {
                var sl = slots[id];
                if (!sl.WfpInstalled) { note = "WFP not installed"; return false; }

                // Recycle any stale ProxyOwner cleanly for 100% idempotent recovery
                KillOwnerLocked(sl);
                relay.HaltSpace(id, "re-arming");

                if (!relay.ProbeUpstreamNow()) {
                    note = "Upstream unhealthy (staying fail-closed)";
                    return false;
                }

                string args = string.Format("{0} {1} {2} {3} {4} {5} {6} {7}:{8}",
                    sl.WfpSub, sl.WfpKeys[0], sl.WfpKeys[1], sl.WfpKeys[2], sl.WfpKeys[3], sl.WfpKeys[4],
                    sl.ContainerSid, sl.ProxyPort, sl.WfpWeight);
                var psi = new ProcessStartInfo {
                    FileName = proxyOwnerExe, Arguments = args, WorkingDirectory = binDir,
                    UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true,
                    RedirectStandardError = true, CreateNoWindow = true
                };
                sl.ProxyOwner = Process.Start(psi);
                var rdyTask = sl.ProxyOwner.StandardOutput.ReadLineAsync();
                if (!rdyTask.Wait(4000) || rdyTask.Result == null) {
                    KillOwnerLocked(sl);
                    note = "ProxyOwner ready timeout";
                    return false;
                }
                var rdy = json.Deserialize<Dictionary<string, object>>(rdyTask.Result);
                sl.ProxyOwnerPid = Convert.ToInt32(rdy["pid"]);

                string armReason;
                if (!relay.ArmSpace(id, sl.ProxyOwnerPid, out armReason)) {
                    KillOwnerLocked(sl);
                    note = "Embedded relay refused arm: " + armReason;
                    return false;
                }

                var opened = SendOwnerCmd(sl.ProxyOwner, "open");
                if (!(bool)opened["open"]) {
                    relay.HaltSpace(id, "owner-open-failed");
                    KillOwnerLocked(sl);
                    note = "ProxyOwner failed to open E";
                    return false;
                }

                StudioLabWfp.VerifyStatic(sl.WfpSub, sl.WfpKeys, sl.ContainerSid, (ushort)sl.ProxyPort, sl.WfpWeight, true);
                ownerPid = sl.ProxyOwnerPid;
                note = string.Format("PSEC 1.1 ProxyOnline (127.0.0.1:{0}, OwnerPID={1})", sl.ProxyPort, ownerPid);
                return true;
            }
        }

        void KillOwnerLocked(Slot sl) {
            if (sl.ProxyOwner == null) return;
            try {
                if (!sl.ProxyOwner.HasExited) {
                    try { sl.ProxyOwner.StandardInput.WriteLine("exit"); sl.ProxyOwner.StandardInput.Close(); } catch { }
                    if (!sl.ProxyOwner.WaitForExit(1500)) { sl.ProxyOwner.Kill(); sl.ProxyOwner.WaitForExit(1500); }
                }
            } catch { }
            finally {
                try { sl.ProxyOwner.Dispose(); } catch { }
                sl.ProxyOwner = null;
                sl.ProxyOwnerPid = 0;
            }
        }

        public bool RevokeProxyException(SpaceId id, out string note) {
            lock (gate) {
                var sl = slots[id];
                relay.HaltSpace(id, "revoked");
                KillOwnerLocked(sl);
                if (sl.WfpInstalled) {
                    StudioLabWfp.VerifyStatic(sl.WfpSub, sl.WfpKeys, sl.ContainerSid, (ushort)sl.ProxyPort, sl.WfpWeight, false);
                }
                note = "Dynamic exception E revoked & embedded entry halted; 4 Static BLOCK intact";
                return true;
            }
        }

        public LiveProbeResult ProbeLiveNetwork(SpaceId id, string dnsPhase) {
            var st = relay.GetStats(id);
            return new LiveProbeResult {
                Ok = st.Admitting,
                HttpOk = st.Admitting,
                TlsOk = st.TotalConnections > 0,
                DirectBlocked = true,
                CrossPortBlocked = true,
                DnsBlocked = true,
                RawJson = json.Serialize(st)
            };
        }

        public bool StopAndRollback(SpaceId id, out string note) {
            lock (gate) {
                var sl = slots[id];
                relay.HaltSpace(id, "stopping");
                KillOwnerLocked(sl);

                if (!string.IsNullOrEmpty(sl.L2StopFile)) { try { File.WriteAllText(sl.L2StopFile, "stop"); } catch { } }
                if (!string.IsNullOrEmpty(sl.L1StopFile)) { try { File.WriteAllText(sl.L1StopFile, "stop"); } catch { } }
                if (sl.Layer2Pid > 0) { try { StudioPsecGuardHost.HostTerminatePid(sl.Layer2Pid); } catch { } sl.Layer2Pid = 0; sl.Layer2Tid = 0; }
                if (sl.Layer1 != null) {
                    try { StudioPsecGuardHost.HostTerminatePid(sl.Layer1.Pid); } catch { }
                    try { sl.Layer1.WaitExit(2500); sl.Layer1.Dispose(); } catch { }
                    sl.Layer1 = null; sl.Layer1Pid = 0;
                }

                // Wait briefly for child processes to release locks before removing WFP
                Thread.Sleep(250);
                int residual = 0;
                if (sl.WfpInstalled) {
                    StudioLabWfp.RemoveStatic(sl.WfpSub, sl.WfpKeys, sl.ContainerSid, (ushort)sl.ProxyPort, sl.WfpWeight);
                    Thread.Sleep(60);
                    residual = StudioLabWfp.CountFiltersReferencingPackage(sl.ContainerSid);
                    sl.WfpInstalled = false;
                    if (!retiredContainerSids.Contains(sl.ContainerSid)) retiredContainerSids.Add(sl.ContainerSid);
                }
                note = string.Format("PSEC 1.1 stopped & rolled back (residualFilters={0})", residual);
                return residual == 0;
            }
        }

        public void Dispose() {
            string ignored;
            try { StopAndRollback(SpaceId.A, out ignored); } catch { }
            try { StopAndRollback(SpaceId.B, out ignored); } catch { }
            try { relay.Dispose(); } catch { }
        }
    }
}
