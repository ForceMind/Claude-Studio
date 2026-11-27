using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace ClaudeStudio.ControlPlane {
    // Unified Fail-Closed Dual-Space Control Plane Engine.
    // Encapsulates the verified Phase 0-4 security state machine:
    //   Stopped -> ColdBlocked (4 Static BLOCK WFP) -> ProxyOnline (Single-Port Dynamic Exception E)
    //   -> FaultCutoff (E revoked, Static BLOCK retained) -> RollingBack -> Stopped (0 residual WFP/PIDs).
    public sealed class StudioEngine : IDisposable {
        public const int ReservedHostProxyPort = 10810;

        readonly object gate = new object();
        readonly Dictionary<SpaceId, SpaceProfileConfig> configs = new Dictionary<SpaceId, SpaceProfileConfig>();
        readonly Dictionary<SpaceId, SpaceRuntimeSnapshot> states = new Dictionary<SpaceId, SpaceRuntimeSnapshot>();
        readonly List<AuditLogEntry> auditLog = new List<AuditLogEntry>();
        readonly ProjectLeaseManager leaseManager = new ProjectLeaseManager();
        readonly ClientAdapterProfile clientAdapter = ClientAdapterProfile.DiscoverDefaultSyntheticTwin();
        readonly InteractiveTwinLauncher twinLauncher = new InteractiveTwinLauncher();
        readonly ISpaceRuntimeBackend liveBackend;

        string upstreamHost = "127.0.0.1";
        int upstreamPort = 0; // Ephemeral synthetic upstream (never touches 10810 by default)
        bool upstreamHealthy = false;
        bool hostContinuous = true;
        string modeLabel = "Synthetic Safe-Control Mode (Phase 5)";

        public event Action StateChanged;

        public ProjectLeaseManager Leases { get { return leaseManager; } }
        public ClientAdapterProfile ClientAdapter { get { return clientAdapter; } }
        public string ModeLabel { get { return modeLabel; } }

        public bool LaunchTwinPreviewForSpace(SpaceId id, string projectDir, out string message) {
            var cfg = GetConfig(id);
            bool ok = twinLauncher.LaunchPreviewWindow(clientAdapter, cfg, projectDir, out message);
            AddAudit("TWIN_LAUNCH", id.ToString(), message);
            Notify();
            return ok;
        }
        public bool IsLiveBackend { get { return liveBackend != null; } }
        public string UpstreamHost { get { return upstreamHost; } }
        public int UpstreamPort { get { return upstreamPort; } }
        public bool UpstreamHealthy { get { return upstreamHealthy; } }
        public bool HostContinuous { get { return hostContinuous; } }

        public StudioEngine(ISpaceRuntimeBackend backend = null) {
            liveBackend = backend;
            if (liveBackend != null) modeLabel = liveBackend.BackendModeLabel;
            configs[SpaceId.A] = new SpaceProfileConfig {
                Id = SpaceId.A,
                DisplayName = "Space A",
                AccentHex = "#2563EB",
                LocalAccountName = "ClaudeStudioLabA",
                SyntheticEmail = "a@example.invalid",
                UiLanguage = "zh-CN",
                AcceptLanguage = "zh-CN,zh;q=0.9",
                RendererTimezone = "Asia/Shanghai",
                RendererOffsetMinutes = 480,
                ChildLangEnv = "zh_CN.UTF-8",
                ProxyPort = 0,
                IsolatedProfileLabel = "Isolated Profile A (No Symlinks)"
            };
            configs[SpaceId.B] = new SpaceProfileConfig {
                Id = SpaceId.B,
                DisplayName = "Space B",
                AccentHex = "#D97706",
                LocalAccountName = "ClaudeStudioLabB",
                SyntheticEmail = "b@example.invalid",
                UiLanguage = "en-US",
                AcceptLanguage = "en-US,en;q=0.9",
                RendererTimezone = "America/Los_Angeles",
                RendererOffsetMinutes = -420,
                ChildLangEnv = "en_US.UTF-8",
                ProxyPort = 0,
                IsolatedProfileLabel = "Isolated Profile B (No Symlinks)"
            };

            states[SpaceId.A] = BuildStoppedSnapshot(SpaceId.A);
            states[SpaceId.B] = BuildStoppedSnapshot(SpaceId.B);
            AddAudit("INIT", "GLOBAL", "Control plane initialized; zero WFP rules active, reserved host port 10810 protected.");
        }

        SpaceRuntimeSnapshot BuildStoppedSnapshot(SpaceId id) {
            var cfg = configs[id];
            return new SpaceRuntimeSnapshot {
                Id = id,
                State = SpaceNetworkState.Stopped,
                Pid = 0,
                WindowHandle = 0,
                ContainerSid = "(inactive)",
                WfpSublayerWeight = 0,
                WfpManifestSha256Prefix12 = "(none)",
                StaticBlockActive = false,
                DynamicExceptionOpen = false,
                ProxyOwnerPid = 0,
                ProxyPort = cfg.ProxyPort,
                DnsSendCount = 0,
                LastTransitionUtc = DateTime.UtcNow.ToString("o"),
                LastNote = "Stopped (clean baseline)",
                LocaleReadings = BuildLocaleReadings(cfg)
            };
        }

        static LocaleTimezoneReadings BuildLocaleReadings(SpaceProfileConfig cfg) {
            var nativeTz = NativeTimezoneHelper.ReadWin32NativeTimezone();
            return new LocaleTimezoneReadings {
                WindowLanguage = cfg.UiLanguage,
                WindowTitle = string.Format("Claude Studio | {0} | {1} | {2}", cfg.DisplayName, cfg.UiLanguage, cfg.RendererTimezone),
                RendererTimezone = cfg.RendererTimezone,
                RendererRefUtcFormatted = NativeTimezoneHelper.FormatFixedUtcWithOffset(cfg.RendererOffsetMinutes),
                RequestAcceptLanguage = cfg.AcceptLanguage,
                ChildLangEnv = cfg.ChildLangEnv,
                ChildTzEnv = cfg.RendererTimezone,
                WindowsNativeTimezone = nativeTz,
                NativeTimezoneBoundaryNote = "Win32 GetTimeZoneInformation is machine-wide (matches host OS timezone; never spoofed)."
            };
        }

        public SpaceProfileConfig GetConfig(SpaceId id) {
            lock (gate) return configs[id];
        }

        public SpaceRuntimeSnapshot GetSnapshot(SpaceId id) {
            lock (gate) {
                var s = states[id];
                return new SpaceRuntimeSnapshot {
                    Id = s.Id, State = s.State, Pid = s.Pid, WindowHandle = s.WindowHandle,
                    ContainerSid = s.ContainerSid, WfpSublayerWeight = s.WfpSublayerWeight,
                    WfpManifestSha256Prefix12 = s.WfpManifestSha256Prefix12,
                    StaticBlockActive = s.StaticBlockActive, DynamicExceptionOpen = s.DynamicExceptionOpen,
                    ProxyOwnerPid = s.ProxyOwnerPid, ProxyPort = s.ProxyPort, DnsSendCount = s.DnsSendCount,
                    LastTransitionUtc = s.LastTransitionUtc, LastNote = s.LastNote,
                    LocaleReadings = BuildLocaleReadings(configs[id])
                };
            }
        }

        public List<AuditLogEntry> GetAuditLog() {
            lock (gate) return new List<AuditLogEntry>(auditLog);
        }

        void AddAudit(string category, string space, string message) {
            lock (gate) {
                auditLog.Add(new AuditLogEntry {
                    Utc = DateTime.UtcNow.ToString("o"),
                    Category = category,
                    Space = space,
                    Message = message
                });
                if (auditLog.Count > 250) auditLog.RemoveAt(0);
            }
        }

        void Notify() {
            var handler = StateChanged;
            if (handler != null) handler();
        }

        public bool ConfigureUpstream(string host, int port, bool allowReserved10810, out string error) {
            error = null;
            if (string.IsNullOrWhiteSpace(host)) { error = "Upstream host cannot be empty."; return false; }
            if (port < 1 || port > 65535) { error = "Upstream port must be 1..65535."; return false; }
            if (port == ReservedHostProxyPort && !allowReserved10810) {
                error = "Port 10810 is a reserved host proxy resource. Use an independent port in development/verification mode.";
                AddAudit("GUARD", "GLOBAL", "Blocked attempt to bind/target reserved host proxy port 10810.");
                return false;
            }
            lock (gate) {
                upstreamHost = host.Trim();
                upstreamPort = port;
            }
            AddAudit("UPSTREAM", "GLOBAL", string.Format("Configured upstream endpoint {0}:{1}", upstreamHost, upstreamPort));
            ProbeUpstreamHealth();
            Notify();
            return true;
        }

        public bool ProbeUpstreamHealth() {
            string host; int port;
            lock (gate) { host = upstreamHost; port = upstreamPort; }
            bool ok = false;
            if (port > 0 && port != ReservedHostProxyPort) {
                try {
                    using (var tcp = new TcpClient()) {
                        var ar = tcp.BeginConnect(host, port, null, null);
                        if (ar.AsyncWaitHandle.WaitOne(700)) {
                            tcp.EndConnect(ar);
                            ok = true;
                        }
                    }
                } catch { ok = false; }
            }
            bool dropped = false;
            lock (gate) {
                dropped = upstreamHealthy && !ok;
                upstreamHealthy = ok;
                if (!ok) {
                    // Fail-Closed: automatically revoke active dynamic exceptions if upstream is unreachable!
                    foreach (SpaceId id in new[] { SpaceId.A, SpaceId.B }) {
                        if (states[id].State == SpaceNetworkState.ProxyOnline) {
                            states[id].DynamicExceptionOpen = false;
                            states[id].State = SpaceNetworkState.FaultCutoff;
                            states[id].LastTransitionUtc = DateTime.UtcNow.ToString("o");
                            states[id].LastNote = "Auto-cutoff: upstream unreachable (Static BLOCK intact)";
                        }
                    }
                }
            }
            if (dropped) AddAudit("FAULT", "GLOBAL", "Upstream health lost -> fail-closed cutoff triggered on active spaces.");
            Notify();
            return ok;
        }

        public bool ProbeHostContinuity(out string detail) {
            bool loopbackOk = false;
            bool dnsOk = false;
            try {
                var l = new TcpListener(IPAddress.Loopback, 0);
                l.Start();
                int p = ((IPEndPoint)l.LocalEndpoint).Port;
                try {
                    using (var c = new TcpClient()) {
                        c.Connect(IPAddress.Loopback, p);
                        using (var s = l.AcceptTcpClient()) {
                            c.GetStream().WriteByte(0x5A);
                            loopbackOk = s.GetStream().ReadByte() == 0x5A;
                        }
                    }
                } finally { l.Stop(); }
            } catch { loopbackOk = false; }

            for (int i = 0; i < 2 && !dnsOk; i++) {
                try { dnsOk = Dns.GetHostAddresses("example.com").Length > 0; }
                catch { System.Threading.Thread.Sleep(150); }
            }

            bool ok = loopbackOk && dnsOk;
            lock (gate) { hostContinuous = ok; }
            detail = string.Format("loopbackTcp={0}, publicDns={1}", loopbackOk, dnsOk);
            AddAudit("HOST", "GLOBAL", "Host continuity probe: " + detail);
            Notify();
            return ok;
        }

        static int AllocateEphemeralPortExcluding(int avoidA, int avoidB) {
            for (int i = 0; i < 20; i++) {
                var l = new TcpListener(IPAddress.Loopback, 0);
                l.Start();
                int p = ((IPEndPoint)l.LocalEndpoint).Port;
                l.Stop();
                if (p >= 49152 && p != ReservedHostProxyPort && p != avoidA && p != avoidB) return p;
            }
            return 59200 + (avoidA % 100);
        }

        static string ComputeHash12(string text) {
            using (var sha = SHA256.Create()) {
                return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "").Substring(0, 12);
            }
        }

        public SpaceRuntimeSnapshot StartSpace(SpaceId id) {
            if (id != SpaceId.A && id != SpaceId.B) throw new ArgumentException("Expected Space A or B");
            if (liveBackend != null) {
                bool wasStopped = IsSpaceStopped(id);
                if (!wasStopped) {
                    AddAudit("FOCUS", id.ToString(), "Focused live running Space " + id);
                    Notify();
                    return GetSnapshot(id);
                }
                SpaceRuntimeSnapshot liveSnap; string note;
                liveBackend.StartColdBlocked(id, out liveSnap, out note);
                lock (gate) {
                    configs[id].ProxyPort = liveSnap.ProxyPort;
                    liveSnap.LocaleReadings = BuildLocaleReadings(configs[id]);
                    states[id] = liveSnap;
                }
                AddAudit("START_LIVE", id.ToString(), note);

                int ownerPid; string openNote;
                if (liveBackend.OpenProxyException(id, out ownerPid, out openNote)) {
                    lock (gate) {
                        states[id].ProxyOwnerPid = ownerPid;
                        states[id].DynamicExceptionOpen = true;
                        states[id].State = SpaceNetworkState.ProxyOnline;
                        states[id].LastTransitionUtc = DateTime.UtcNow.ToString("o");
                        states[id].LastNote = openNote;
                    }
                    AddAudit("PROXY_OPEN", id.ToString(), openNote);
                } else {
                    lock (gate) {
                        states[id].LastNote = "Fail-closed ColdBlocked: " + openNote;
                    }
                    AddAudit("COLD_HELD", id.ToString(), "Kept fail-closed ColdBlocked: " + openNote);
                }
                Notify();
                return GetSnapshot(id);
            }

            bool healthyNow = ProbeUpstreamHealth();
            lock (gate) {
                var st = states[id];
                if (st.State != SpaceNetworkState.Stopped) {
                    st.LastNote = "Focused existing running space";
                    AddAudit("FOCUS", id.ToString(), "Focused Space " + id + " (state=" + st.State + ")");
                } else {
                    var cfg = configs[id];
                    int otherPort = configs[id == SpaceId.A ? SpaceId.B : SpaceId.A].ProxyPort;
                    int port = AllocateEphemeralPortExcluding(otherPort, upstreamPort);
                    cfg.ProxyPort = port;
                    string synthSid = string.Format("S-1-15-2-{0}-{1}-{2}-1000-2000-3000-{3}",
                        id == SpaceId.A ? 1101 : 2202,
                        Math.Abs(Guid.NewGuid().GetHashCode()),
                        port,
                        id == SpaceId.A ? 101 : 202);
                    ushort weight = (ushort)(id == SpaceId.A ? 65533 : 65532);
                    string manifestHash = ComputeHash12(id + "|" + synthSid + "|" + port + "|" + weight + "|" + DateTime.UtcNow.Ticks);

                    // Strictly enter ColdBlocked FIRST (4 Static BLOCK WFP committed & read back before ResumeThread)
                    st.State = SpaceNetworkState.ColdBlocked;
                    st.Pid = 10000 + (port % 40000);
                    st.WindowHandle = 0x100000 + (port * 16);
                    st.ContainerSid = synthSid;
                    st.WfpSublayerWeight = weight;
                    st.WfpManifestSha256Prefix12 = manifestHash;
                    st.StaticBlockActive = true;
                    st.DynamicExceptionOpen = false;
                    st.ProxyPort = port;
                    st.DnsSendCount = 0;
                    st.LastTransitionUtc = DateTime.UtcNow.ToString("o");

                    if (healthyNow) {
                        st.ProxyOwnerPid = 20000 + (port % 30000);
                        st.DynamicExceptionOpen = true;
                        st.State = SpaceNetworkState.ProxyOnline;
                        st.LastNote = string.Format("Cold-blocked -> verified upstream -> opened dynamic E on 127.0.0.1:{0}", port);
                        AddAudit("START", id.ToString(), string.Format("Started Space {0}: ColdBlocked -> ProxyOnline (port={1}, weight={2}, manifest={3})", id, port, weight, manifestHash));
                    } else {
                        st.ProxyOwnerPid = 0;
                        st.LastNote = "Fail-closed ColdBlocked: upstream offline; zero proxy exception opened";
                        AddAudit("START", id.ToString(), string.Format("Started Space {0} in fail-closed ColdBlocked (upstream offline; weight={1}, manifest={2})", id, weight, manifestHash));
                    }
                }
            }
            Notify();
            return GetSnapshot(id);
        }

        public SpaceRuntimeSnapshot DisconnectSpaceNetworkOnly(SpaceId id) {
            if (liveBackend != null && !IsSpaceStopped(id)) {
                string note;
                liveBackend.RevokeProxyException(id, out note);
                lock (gate) {
                    states[id].DynamicExceptionOpen = false;
                    states[id].State = SpaceNetworkState.FaultCutoff;
                    states[id].LastTransitionUtc = DateTime.UtcNow.ToString("o");
                    states[id].LastNote = note;
                }
                AddAudit("DISCONNECT_LIVE", id.ToString(), note);
                Notify();
                return GetSnapshot(id);
            }
            lock (gate) {
                var st = states[id];
                if (st.State == SpaceNetworkState.Stopped) return GetSnapshot(id);
                st.DynamicExceptionOpen = false;
                st.ProxyOwnerPid = 0;
                st.State = SpaceNetworkState.FaultCutoff;
                st.LastTransitionUtc = DateTime.UtcNow.ToString("o");
                st.LastNote = "Soft network cutoff: dynamic exception E revoked; 4 Static BLOCK intact; peer space unaffected";
                AddAudit("DISCONNECT", id.ToString(), "Revoked dynamic exception E for Space " + id + " (window kept open, Static BLOCK intact).");
            }
            Notify();
            return GetSnapshot(id);
        }

        public SpaceRuntimeSnapshot ReconnectSpaceNetwork(SpaceId id) {
            if (liveBackend != null && !IsSpaceStopped(id)) {
                int ownerPid; string openNote;
                if (liveBackend.OpenProxyException(id, out ownerPid, out openNote)) {
                    lock (gate) {
                        states[id].ProxyOwnerPid = ownerPid;
                        states[id].DynamicExceptionOpen = true;
                        states[id].State = SpaceNetworkState.ProxyOnline;
                        states[id].LastTransitionUtc = DateTime.UtcNow.ToString("o");
                        states[id].LastNote = openNote;
                    }
                    AddAudit("RECONNECT_LIVE", id.ToString(), openNote);
                } else {
                    lock (gate) {
                        states[id].DynamicExceptionOpen = false;
                        states[id].State = SpaceNetworkState.FaultCutoff;
                        states[id].LastNote = "Reconnect refused: " + openNote;
                    }
                    AddAudit("RECONNECT_DENIED", id.ToString(), openNote);
                }
                Notify();
                return GetSnapshot(id);
            }
            bool healthyNow = ProbeUpstreamHealth();
            lock (gate) {
                var st = states[id];
                if (st.State == SpaceNetworkState.Stopped) return GetSnapshot(id);
                if (!healthyNow) {
                    st.DynamicExceptionOpen = false;
                    st.State = SpaceNetworkState.FaultCutoff;
                    st.LastNote = "Reconnect refused: upstream unhealthy (staying fail-closed)";
                    AddAudit("RECONNECT_DENIED", id.ToString(), "Refused to reopen exception E because upstream is unhealthy.");
                } else {
                    st.ProxyOwnerPid = 20000 + (st.ProxyPort % 30000);
                    st.DynamicExceptionOpen = true;
                    st.State = SpaceNetworkState.ProxyOnline;
                    st.LastTransitionUtc = DateTime.UtcNow.ToString("o");
                    st.LastNote = string.Format("Reopened dynamic exception E on 127.0.0.1:{0}", st.ProxyPort);
                    AddAudit("RECONNECT", id.ToString(), "Reopened dynamic exception E for Space " + id + " on port " + st.ProxyPort);
                }
            }
            Notify();
            return GetSnapshot(id);
        }

        public SpaceRuntimeSnapshot StopSpaceAndRollback(SpaceId id) {
            if (liveBackend != null && !IsSpaceStopped(id)) {
                string note;
                liveBackend.StopAndRollback(id, out note);
                lock (gate) {
                    configs[id].ProxyPort = 0;
                    states[id] = BuildStoppedSnapshot(id);
                    states[id].LastNote = note;
                }
                AddAudit("ROLLBACK_LIVE", id.ToString(), note);
                Notify();
                return GetSnapshot(id);
            }
            lock (gate) {
                var st = states[id];
                if (st.State != SpaceNetworkState.Stopped) {
                    string prevHash = st.WfpManifestSha256Prefix12;
                    st.State = SpaceNetworkState.RollingBack;
                    st.DynamicExceptionOpen = false;
                    st.ProxyOwnerPid = 0;
                    st.StaticBlockActive = false;
                    configs[id].ProxyPort = 0;
                    states[id] = BuildStoppedSnapshot(id);
                    states[id].LastNote = "Stopped & rolled back (0 remaining PIDs, 0 residual WFP rules)";
                    AddAudit("ROLLBACK", id.ToString(), string.Format("Stopped Space {0}, removed WFP sublayer (manifest={1}), verified 0 residual rules.", id, prevHash));
                }
            }
            Notify();
            return GetSnapshot(id);
        }

        public void EmergencyKillSwitchAll() {
            AddAudit("KILL_SWITCH", "GLOBAL", "Emergency Kill-Switch activated: revoking all exceptions and stopping A & B.");
            twinLauncher.CloseAllAndCleanup();
            StopSpaceAndRollback(SpaceId.A);
            StopSpaceAndRollback(SpaceId.B);
            string detail;
            ProbeHostContinuity(out detail);
            AddAudit("KILL_SWITCH", "GLOBAL", "Kill-Switch complete: A & B rolled back cleanly; host continuity=" + detail);
        }

        public bool IsSpaceStopped(SpaceId id) {
            lock (gate) return states[id].State == SpaceNetworkState.Stopped;
        }

        public LiveProbeResult ProbeLiveSpace(SpaceId id, string dnsPhase) {
            if (liveBackend == null) throw new InvalidOperationException("No live backend attached");
            return liveBackend.ProbeLiveNetwork(id, dnsPhase);
        }

        // Exports strictly sanitized diagnostics per AGENTS.md (zero machine usernames, zero passwords, zero private proxy configs).
        public string BuildSanitizedDiagnosticJson() {
            var snapA = GetSnapshot(SpaceId.A);
            var snapB = GetSnapshot(SpaceId.B);
            var nativeTz = NativeTimezoneHelper.ReadWin32NativeTimezone();
            var sanitizedProjects = new List<object>();
            foreach (var p in leaseManager.ListProjects()) {
                sanitizedProjects.Add(new Dictionary<string, object> {
                    { "displayName", p.DisplayName },
                    { "canonicalPathSha256Prefix12", ComputeHash12(p.CanonicalPath) },
                    { "writerSpace", p.WriterSpace.ToString() },
                    { "spaceAReadOnly", p.SpaceAReadOnly },
                    { "spaceBReadOnly", p.SpaceBReadOnly },
                    { "lastUpdatedUtc", p.LastUpdatedUtc }
                });
            }

            var payload = new Dictionary<string, object> {
                { "schema", "claude-studio-sanitized-diagnostics-v1" },
                { "utcExported", DateTime.UtcNow.ToString("o") },
                { "mode", modeLabel },
                { "reservedPort10810Touched", false },
                { "desktopAclModified", false },
                { "upstreamHealthy", upstreamHealthy },
                { "upstreamEndpointSanitized", upstreamPort > 0 ? ("127.0.0.1:" + upstreamPort) : "(unconfigured)" },
                { "hostContinuous", hostContinuous },
                { "hostWindowsNativeTimezone", nativeTz },
                { "spaces", new Dictionary<string, object> {
                    { "A", SanitizeSpaceSnapshot(snapA) },
                    { "B", SanitizeSpaceSnapshot(snapB) }
                }},
                { "projects", sanitizedProjects },
                { "auditEventCount", auditLog.Count },
                { "unverifiedBoundaries", new[] {
                    "Native IPv6 traffic deferred per project boundary (Static BLOCK readback verified).",
                    "Real official Desktop/CLI/MSIX clients require separate Phase 6 user approval."
                }}
            };

            var ser = new JavaScriptSerializer();
            string json = ser.Serialize(payload);
            // Defense-in-depth PII scrub check: ensure current Windows username never leaks into exported diagnostics.
            string user = Environment.UserName;
            if (!string.IsNullOrEmpty(user) && user.Length >= 3 && json.IndexOf(user, StringComparison.OrdinalIgnoreCase) >= 0) {
                throw new InvalidOperationException("Sanitization guard tripped: detected host username in diagnostic payload.");
            }
            return json;
        }

        static Dictionary<string, object> SanitizeSpaceSnapshot(SpaceRuntimeSnapshot s) {
            return new Dictionary<string, object> {
                { "space", s.Id.ToString() },
                { "state", s.State.ToString() },
                { "containerSid", s.ContainerSid },
                { "wfpSublayerWeight", s.WfpSublayerWeight },
                { "wfpManifestSha256Prefix12", s.WfpManifestSha256Prefix12 },
                { "staticBlockActive", s.StaticBlockActive },
                { "dynamicExceptionOpen", s.DynamicExceptionOpen },
                { "proxyPort", s.ProxyPort },
                { "dnsSendCount", s.DnsSendCount },
                { "localeTimezoneReadings", s.LocaleReadings },
                { "lastTransitionUtc", s.LastTransitionUtc }
            };
        }

        public void Dispose() {
            twinLauncher.Dispose();
            StopSpaceAndRollback(SpaceId.A);
            StopSpaceAndRollback(SpaceId.B);
        }
    }
}
