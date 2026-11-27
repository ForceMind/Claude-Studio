using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows;

namespace ClaudeStudio.ControlPlane {
    public static class Program {
        [STAThread]
        public static int Main(string[] args) {
            if (args != null && args.Length >= 2 && string.Equals(args[0], "--self-test", StringComparison.OrdinalIgnoreCase)) {
                return RunSelfTest(args[1]);
            }
            using (var engine = new StudioEngine()) {
                var app = new Application();
                var win = new MainWindow(engine);
                app.Run(win);
            }
            return 0;
        }

        static void RunCmd(string exe, string arguments) {
            var psi = new ProcessStartInfo {
                FileName = exe, Arguments = arguments, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
            };
            using (var p = Process.Start(psi)) {
                p.WaitForExit(10000);
                if (p.ExitCode != 0) throw new InvalidOperationException(exe + " " + arguments + " failed with " + p.ExitCode);
            }
        }

        static int RunSelfTest(string reportOutPath) {
            string tempRoot = Path.Combine(Path.GetTempPath(), "ClaudeStudioPhase5SelfTest-" + Guid.NewGuid().ToString("N").Substring(0, 12));
            string repoDir = Path.Combine(tempRoot, "demo-repo");
            string aliasDir = Path.Combine(tempRoot, "demo-alias");
            string tplSrcDir = Path.Combine(tempRoot, "tpl-src");
            string tplDstDir = Path.Combine(tempRoot, "tpl-dst");
            TcpListener mockUpstream = null;

            var checks = new Dictionary<string, bool>();
            var details = new Dictionary<string, object>();
            string errorMsg = null;

            try {
                Directory.CreateDirectory(repoDir);
                Directory.CreateDirectory(tplSrcDir);
                RunCmd("git.exe", "-C \"" + repoDir + "\" init -q");
                RunCmd("git.exe", "-C \"" + repoDir + "\" config user.name \"Synthetic Tester\"");
                RunCmd("git.exe", "-C \"" + repoDir + "\" config user.email \"lab@example.invalid\"");
                File.WriteAllText(Path.Combine(repoDir, "README.md"), "baseline\n", new UTF8Encoding(false));
                RunCmd("git.exe", "-C \"" + repoDir + "\" add README.md");
                RunCmd("git.exe", "-C \"" + repoDir + "\" commit -q -m \"init\"");
                File.WriteAllText(Path.Combine(repoDir, "README.md"), "baseline\nupdated in Space A\n", new UTF8Encoding(false));
                RunCmd("cmd.exe", "/c mklink /J \"" + aliasDir + "\" \"" + repoDir + "\"");

                using (var engine = new StudioEngine()) {
                    // 1. Reserved port 10810 hard guard
                    string err10810;
                    bool blocked10810 = !engine.ConfigureUpstream("127.0.0.1", 10810, false, out err10810);
                    checks["reservedPort10810Protected"] = blocked10810;

                    // 2. Cold-start Fail-Closed when upstream is offline
                    mockUpstream = new TcpListener(IPAddress.Loopback, 0);
                    mockUpstream.Start();
                    int upPort = ((IPEndPoint)mockUpstream.LocalEndpoint).Port;
                    mockUpstream.Stop(); // offline first!
                    string errUp;
                    engine.ConfigureUpstream("127.0.0.1", upPort, false, out errUp);
                    var coldA = engine.StartSpace(SpaceId.A);
                    checks["failClosedColdStartWhenUpstreamOffline"] = (coldA.State == SpaceNetworkState.ColdBlocked) && coldA.StaticBlockActive && !coldA.DynamicExceptionOpen;

                    // 3. Bring synthetic upstream online -> Reconnect A & Start B -> Soft Disconnect A only -> B stays online
                    mockUpstream = new TcpListener(IPAddress.Loopback, upPort);
                    mockUpstream.Start();
                    var onA = engine.ReconnectSpaceNetwork(SpaceId.A);
                    var onB = engine.StartSpace(SpaceId.B);
                    var cutA = engine.DisconnectSpaceNetworkOnly(SpaceId.A);
                    var stillB = engine.GetSnapshot(SpaceId.B);
                    checks["dualOnlineAndSoftDisconnectIsolation"] =
                        (onA.State == SpaceNetworkState.ProxyOnline) &&
                        (onB.State == SpaceNetworkState.ProxyOnline) &&
                        (onA.ProxyPort != onB.ProxyPort) &&
                        (onA.ContainerSid != onB.ContainerSid) &&
                        (cutA.State == SpaceNetworkState.FaultCutoff) && cutA.StaticBlockActive && !cutA.DynamicExceptionOpen &&
                        (stillB.State == SpaceNetworkState.ProxyOnline) && stillB.DynamicExceptionOpen;

                    // 4. Single-Writer Project Lease + Windows Junction Alias Conflict + Controlled Handoff
                    var grantA = engine.Leases.RequestMount(SpaceId.A, repoDir, ProjectAccessMode.ReadWrite);
                    var roB = engine.Leases.RequestMount(SpaceId.B, repoDir, ProjectAccessMode.ReadOnly);
                    var conflictDirect = engine.Leases.RequestMount(SpaceId.B, repoDir, ProjectAccessMode.ReadWrite);
                    var conflictJunction = engine.Leases.RequestMount(SpaceId.B, aliasDir, ProjectAccessMode.ReadWrite);
                    var handoffWhileARunning = engine.Leases.ControlledHandoffWriter(aliasDir, SpaceId.B, engine.IsSpaceStopped);
                    engine.StopSpaceAndRollback(SpaceId.A);
                    var handoffAfterAStopped = engine.Leases.ControlledHandoffWriter(aliasDir, SpaceId.B, engine.IsSpaceStopped);
                    checks["singleWriterJunctionAndControlledHandoff"] =
                        grantA.Ok && roB.Ok &&
                        (!conflictDirect.Ok && conflictDirect.Code == "WRITE_CONFLICT") &&
                        (!conflictJunction.Ok && conflictJunction.Code == "WRITE_CONFLICT") &&
                        (!handoffWhileARunning.Ok && handoffWhileARunning.Code == "WRITER_STILL_RUNNING") &&
                        handoffAfterAStopped.Ok && (handoffAfterAStopped.Holder == SpaceId.B);

                    // 5. Static Template Opt-In & Identity Artifact Hard-Block
                    string safeTpl = Path.Combine(tplSrcDir, "CLAUDE.md");
                    string credTpl = Path.Combine(tplSrcDir, ".credentials.json");
                    File.WriteAllText(safeTpl, "# Shared coding style\n", new UTF8Encoding(false));
                    File.WriteAllText(credTpl, "{\"token\":\"synthetic\"}\n", new UTF8Encoding(false));
                    var defaultOff = ProjectLeaseManager.SyncReadOnlyStaticTemplate(safeTpl, tplDstDir, false);
                    var blockedCred = ProjectLeaseManager.SyncReadOnlyStaticTemplate(credTpl, tplDstDir, true);
                    var allowedSafe = ProjectLeaseManager.SyncReadOnlyStaticTemplate(safeTpl, tplDstDir, true);
                    string syncedFile = Path.Combine(tplDstDir, "CLAUDE.md");
                    bool syncedReadOnly = File.Exists(syncedFile) && ((File.GetAttributes(syncedFile) & FileAttributes.ReadOnly) != 0);
                    checks["staticTemplateOptInAndIdentityBlocked"] =
                        (!defaultOff.Ok && defaultOff.Code == "OPT_IN_REQUIRED") &&
                        (!blockedCred.Ok && blockedCred.Code == "FORBIDDEN_IDENTITY_ARTIFACT") &&
                        allowedSafe.Ok && syncedReadOnly;

                    // 6. Sanitized Plain-Text HANDOFF.md Generation
                    string brief = HandoffGenerator.BuildSanitizedBrief(repoDir, SpaceId.A, SpaceId.B, "Completed Phase 5 engine", "Verify UI");
                    checks["sanitizedHandoffBriefGenerated"] =
                        brief.Contains("NOT migrated") &&
                        brief.Contains("Space A` -> `Space B") &&
                        brief.Contains("README.md") &&
                        brief.Contains("Completed Phase 5 engine");

                    // 7. Live WPF MainWindow Construction, Measure/Arrange Render Smoke & Tray/Hotkey Lifecycle
                    var win = new MainWindow(engine);
                    win.ShowActivated = false;
                    win.Left = -20000; // Render off-screen cleanly without stealing user focus
                    win.Show();
                    win.UpdateLayout();
                    bool wpfRendered = (win.ActualWidth >= 900) && (win.ActualHeight >= 600);
                    win.ExitCleanly();
                    checks["wpfWindowAndTrayLifecycleClean"] = wpfRendered;

                    // 8. Emergency Kill-Switch & Host Continuity & Sanitized Diagnostic Export (zero host username PII)
                    engine.StartSpace(SpaceId.A);
                    engine.StartSpace(SpaceId.B);
                    engine.EmergencyKillSwitchAll();
                    var postA = engine.GetSnapshot(SpaceId.A);
                    var postB = engine.GetSnapshot(SpaceId.B);
                    string diagJson = engine.BuildSanitizedDiagnosticJson();
                    bool zeroPii = string.IsNullOrEmpty(Environment.UserName) ||
                        diagJson.IndexOf(Environment.UserName, StringComparison.OrdinalIgnoreCase) < 0;
                    checks["killSwitchRollbackAndSanitizedDiagnostics"] =
                        (postA.State == SpaceNetworkState.Stopped) && !postA.StaticBlockActive && !postA.DynamicExceptionOpen &&
                        (postB.State == SpaceNetworkState.Stopped) && !postB.StaticBlockActive && !postB.DynamicExceptionOpen &&
                        engine.HostContinuous && zeroPii &&
                        diagJson.IndexOf("windowsNativeTimezone", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        diagJson.Contains("zh-CN,zh;q=0.9") && diagJson.Contains("en-US,en;q=0.9");

                    details["upstreamPort"] = upPort;
                    details["hostNativeTimezone"] = NativeTimezoneHelper.ReadWin32NativeTimezone();
                    details["diagnosticJsonBytes"] = diagJson.Length;
                }
            } catch (Exception ex) {
                errorMsg = ex.ToString();
            } finally {
                if (mockUpstream != null) { try { mockUpstream.Stop(); } catch { } }
                if (Directory.Exists(aliasDir)) { try { RunCmd("cmd.exe", "/c rmdir \"" + aliasDir + "\""); } catch { } }
                if (Directory.Exists(tempRoot)) {
                    try {
                        foreach (string f in Directory.GetFiles(tempRoot, "*", SearchOption.AllDirectories)) {
                            File.SetAttributes(f, FileAttributes.Normal);
                        }
                        Directory.Delete(tempRoot, true);
                    } catch { }
                }
            }

            checks["selfTestTempCleanup"] = !Directory.Exists(tempRoot);
            bool allOk = (errorMsg == null);
            foreach (var kv in checks) if (!kv.Value) allOk = false;

            var report = new Dictionary<string, object> {
                { "outcome", allOk ? "passed-phase5-control-plane-selftest" : "failed-phase5-control-plane-selftest" },
                { "utcFinished", DateTime.UtcNow.ToString("o") },
                { "error", errorMsg },
                { "checks", checks },
                { "details", details }
            };
            var ser = new JavaScriptSerializer();
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(reportOutPath)));
            File.WriteAllText(reportOutPath, ser.Serialize(report), new UTF8Encoding(false));
            return allOk ? 0 : 1;
        }
    }
}
