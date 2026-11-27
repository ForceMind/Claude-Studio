using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ClaudeStudio.ControlPlane {
    // Pluggable client runtime adapter:
    //   - During development: binds to high-fidelity ClaudeDesktopTwin.exe + ClaudeCliTwin.exe
    //   - Future production opt-in: binds to official Claude Desktop + Claude Code CLI via the EXACT same
    //     flags/env contract (--user-data-dir, --proxy-server, CLAUDE_CONFIG_DIR, HTTP_PROXY, HTTPS_PROXY, LANG, TZ)
    //     with zero control-plane redesign!
    public enum ClientAdapterKind {
        SyntheticTwin = 0,
        OfficialExternal = 1
    }

    public sealed class ClientAdapterProfile {
        public ClientAdapterKind Kind { get; set; }
        public string DisplayName { get; set; }
        public string DesktopExecutablePath { get; set; }
        public string CliExecutablePath { get; set; }
        public bool RequireIsolatedUserDataDir { get; set; }
        public bool ForbidSymlinkedConfigDir { get; set; }

        public static ClientAdapterProfile DiscoverDefaultSyntheticTwin() {
            string asmLoc = typeof(ClientAdapterProfile).Assembly.Location;
            string exeDir = !string.IsNullOrEmpty(asmLoc) ? Path.GetDirectoryName(asmLoc) : Environment.CurrentDirectory;
            // Search relative to studio-control-plane\bin -> ..\..\studio-twin-clients\bin
            string[] candidates = {
                Path.GetFullPath(Path.Combine(exeDir, @"..\..\studio-twin-clients\bin")),
                Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, @"studio-twin-clients\bin")),
                exeDir
            };
            string foundDir = candidates[0];
            foreach (string c in candidates) {
                if (File.Exists(Path.Combine(c, "ClaudeDesktopTwin.exe")) && File.Exists(Path.Combine(c, "ClaudeCliTwin.exe"))) {
                    foundDir = c;
                    break;
                }
            }
            return new ClientAdapterProfile {
                Kind = ClientAdapterKind.SyntheticTwin,
                DisplayName = "High-Fidelity Synthetic Twin (ClaudeDesktopTwin + ClaudeCliTwin)",
                DesktopExecutablePath = Path.Combine(foundDir, "ClaudeDesktopTwin.exe"),
                CliExecutablePath = Path.Combine(foundDir, "ClaudeCliTwin.exe"),
                RequireIsolatedUserDataDir = true,
                ForbidSymlinkedConfigDir = true
            };
        }

        public bool IsAvailable {
            get {
                return !string.IsNullOrEmpty(DesktopExecutablePath) && File.Exists(DesktopExecutablePath)
                    && !string.IsNullOrEmpty(CliExecutablePath) && File.Exists(CliExecutablePath);
            }
        }

        // Produces the exact Electron / Desktop CLI arguments shared by both SyntheticTwin and OfficialExternal.
        public string BuildDesktopLaunchArgs(SpaceProfileConfig cfg, string userDataDir, string cliConfigDir,
            string projectDir, string apiHost, string tlsPin) {
            var sb = new StringBuilder();
            sb.AppendFormat("--user-data-dir=\"{0}\" ", userDataDir);
            if (cfg.ProxyPort > 0) sb.AppendFormat("--proxy-server=\"http://127.0.0.1:{0}\" ", cfg.ProxyPort);
            sb.AppendFormat("--lang=\"{0}\" ", cfg.UiLanguage);
            if (Kind == ClientAdapterKind.SyntheticTwin) {
                sb.AppendFormat("--space=\"{0}\" --tz=\"{1}\" ", cfg.Id, cfg.RendererTimezone);
                if (!string.IsNullOrEmpty(projectDir)) sb.AppendFormat("--project-dir=\"{0}\" ", projectDir);
                if (!string.IsNullOrEmpty(CliExecutablePath)) sb.AppendFormat("--cli-exe=\"{0}\" ", CliExecutablePath);
                if (!string.IsNullOrEmpty(cliConfigDir)) sb.AppendFormat("--cli-config-dir=\"{0}\" ", cliConfigDir);
                if (!string.IsNullOrEmpty(apiHost)) sb.AppendFormat("--api-host=\"{0}\" ", apiHost);
                if (!string.IsNullOrEmpty(tlsPin)) sb.AppendFormat("--tls-pin=\"{0}\" ", tlsPin);
            }
            return sb.ToString().Trim();
        }

        // Produces the exact isolated environment variables shared by both ClaudeCliTwin and official Claude Code CLI.
        public Dictionary<string, string> BuildIsolatedCliEnvironment(SpaceProfileConfig cfg, string cliConfigDir,
            string apiHost, string tlsPin) {
            var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            env["CLAUDE_CONFIG_DIR"] = cliConfigDir;
            env["LANG"] = cfg.ChildLangEnv;
            env["TZ"] = cfg.RendererTimezone;
            env["NO_PROXY"] = "";
            if (cfg.ProxyPort > 0) {
                string proxyUrl = "http://127.0.0.1:" + cfg.ProxyPort;
                env["HTTP_PROXY"] = proxyUrl;
                env["HTTPS_PROXY"] = proxyUrl;
                env["ALL_PROXY"] = proxyUrl;
            }
            if (Kind == ClientAdapterKind.SyntheticTwin) {
                if (!string.IsNullOrEmpty(apiHost)) env["CLAUDE_TWIN_API_HOST"] = apiHost;
                if (!string.IsNullOrEmpty(tlsPin)) env["CLAUDE_TWIN_TLS_PIN"] = tlsPin;
            }
            return env;
        }
    }

    // Launches an isolated interactive ClaudeDesktopTwin window for visual walkthroughs in Safe-Control mode
    // (never touches official clients, never modifies system accounts/WFP/port 10810).
    public sealed class InteractiveTwinLauncher : IDisposable {
        readonly Dictionary<SpaceId, Process> activeWindows = new Dictionary<SpaceId, Process>();
        readonly string sandboxTempRoot;

        public InteractiveTwinLauncher() {
            sandboxTempRoot = Path.Combine(Path.GetTempPath(), "ClaudeStudioTwinPreview-" + Process.GetCurrentProcess().Id);
        }

        public bool LaunchPreviewWindow(ClientAdapterProfile adapter, SpaceProfileConfig cfg, string projectDir, out string message) {
            if (adapter == null || !adapter.IsAvailable) {
                message = "未找到模拟客户端二进制（请先运行 studio-twin-clients/build.ps1）。";
                return false;
            }
            if (adapter.Kind != ClientAdapterKind.SyntheticTwin) {
                message = "开发阶段安全拦截：仅允许启动合成模拟客户端，禁止启动官方客户端。";
                return false;
            }
            string spaceRoot = Path.Combine(sandboxTempRoot, "Space-" + cfg.Id);
            string userDataDir = Path.Combine(spaceRoot, "desktop-profile");
            string cliCfgDir = Path.Combine(spaceRoot, "cli-config");
            Directory.CreateDirectory(userDataDir);
            Directory.CreateDirectory(cliCfgDir);

            string args = adapter.BuildDesktopLaunchArgs(cfg, userDataDir, cliCfgDir, projectDir, "api.claude-twin.test", "");
            var psi = new ProcessStartInfo {
                FileName = adapter.DesktopExecutablePath,
                Arguments = args,
                UseShellExecute = false
            };
            foreach (var kv in adapter.BuildIsolatedCliEnvironment(cfg, cliCfgDir, "api.claude-twin.test", "")) {
                psi.EnvironmentVariables[kv.Key] = kv.Value;
            }
            var proc = Process.Start(psi);
            activeWindows[cfg.Id] = proc;
            message = string.Format("已启动 Space {0} 合成模拟窗口 (PID={1}, user-data-dir={2})", cfg.Id, proc.Id, userDataDir);
            return true;
        }

        public void CloseAllAndCleanup() {
            foreach (var kv in activeWindows) {
                try { if (kv.Value != null && !kv.Value.HasExited) { kv.Value.Kill(); kv.Value.WaitForExit(1500); } } catch { }
            }
            activeWindows.Clear();
            try { if (Directory.Exists(sandboxTempRoot)) Directory.Delete(sandboxTempRoot, true); } catch { }
        }

        public void Dispose() {
            CloseAllAndCleanup();
        }
    }
}
