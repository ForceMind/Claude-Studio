using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace ClaudeStudio.Twin {
    // High-fidelity synthetic Claude Desktop Twin (Electron-style multi-process GUI client).
    // Mirrors official Claude Desktop flags, directory structure, OAuth PKCE flow, SSE streaming,
    // MCP helper child process, and integrated Claude Code CLI spawning — with ZERO official binaries.
    public static class ClaudeDesktopTwinProgram {
        [DllImport("user32.dll")]
        static extern bool IsWindowVisible(IntPtr hWnd);

        sealed class DesktopOptions {
            public string Space = "A";
            public string UserDataDir;
            public string ProxyServer = "";
            public string Lang = "zh-CN";
            public string Tz = "Asia/Shanghai";
            public string ProjectDir = "";
            public string CliExe = "";
            public string CliConfigDir = "";
            public string ApiHost = "api.claude-twin.test";
            public string TlsPin = "";
            public string ProcessType = "main";
            public string ReceiptPath = "";
            public string AutomationDir = "";
            public int SentinelTcp;
            public int SentinelUdp;
            public int PeerProxy;
            public string DnsName = "";
        }

        static void ApplyJsonConfig(DesktopOptions opt, string cfgPath) {
            if (string.IsNullOrEmpty(cfgPath) || !File.Exists(cfgPath)) return;
            var d = TwinUtil.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(cfgPath, Encoding.UTF8));
            if (d == null) return;
            if (d.ContainsKey("space") && d["space"] != null) opt.Space = d["space"].ToString();
            if (d.ContainsKey("userDataDir") && d["userDataDir"] != null) opt.UserDataDir = d["userDataDir"].ToString();
            if (d.ContainsKey("proxyServer") && d["proxyServer"] != null) opt.ProxyServer = d["proxyServer"].ToString();
            if (d.ContainsKey("lang") && d["lang"] != null) opt.Lang = d["lang"].ToString();
            if (d.ContainsKey("tz") && d["tz"] != null) opt.Tz = d["tz"].ToString();
            if (d.ContainsKey("projectDir") && d["projectDir"] != null) opt.ProjectDir = d["projectDir"].ToString();
            if (d.ContainsKey("cliExe") && d["cliExe"] != null) opt.CliExe = d["cliExe"].ToString();
            if (d.ContainsKey("cliConfigDir") && d["cliConfigDir"] != null) opt.CliConfigDir = d["cliConfigDir"].ToString();
            if (d.ContainsKey("apiHost") && d["apiHost"] != null) opt.ApiHost = d["apiHost"].ToString();
            if (d.ContainsKey("tlsPin") && d["tlsPin"] != null) opt.TlsPin = d["tlsPin"].ToString();
            if (d.ContainsKey("automationDir") && d["automationDir"] != null) opt.AutomationDir = d["automationDir"].ToString();
            if (d.ContainsKey("sentinelTcp") && d["sentinelTcp"] != null) opt.SentinelTcp = Convert.ToInt32(d["sentinelTcp"]);
            if (d.ContainsKey("sentinelUdp") && d["sentinelUdp"] != null) opt.SentinelUdp = Convert.ToInt32(d["sentinelUdp"]);
            if (d.ContainsKey("peerProxy") && d["peerProxy"] != null) opt.PeerProxy = Convert.ToInt32(d["peerProxy"]);
            if (d.ContainsKey("dnsName") && d["dnsName"] != null) opt.DnsName = d["dnsName"].ToString();
        }

        static DesktopOptions ParseArgs(string[] args) {
            var opt = new DesktopOptions();
            if (args.Length == 1 && !args[0].StartsWith("--") && File.Exists(args[0])) {
                ApplyJsonConfig(opt, args[0]);
            }
            for (int i = 0; i < args.Length; i++) {
                string a = args[i];
                string k = a, v = null;
                int eq = a.IndexOf('=');
                if (eq > 0 && a.StartsWith("--")) { k = a.Substring(0, eq); v = a.Substring(eq + 1); }
                else if (a.StartsWith("--") && i + 1 < args.Length) { v = args[++i]; }
                if (v == null) continue;
                switch (k.ToLowerInvariant()) {
                    case "--config-file": ApplyJsonConfig(opt, v); break;
                    case "--space": opt.Space = v; break;
                    case "--user-data-dir": opt.UserDataDir = v; break;
                    case "--proxy-server": opt.ProxyServer = v; break;
                    case "--lang": opt.Lang = v; break;
                    case "--tz": opt.Tz = v; break;
                    case "--project-dir": opt.ProjectDir = v; break;
                    case "--cli-exe": opt.CliExe = v; break;
                    case "--cli-config-dir": opt.CliConfigDir = v; break;
                    case "--api-host": opt.ApiHost = v; break;
                    case "--tls-pin": opt.TlsPin = v; break;
                    case "--type": opt.ProcessType = v; break;
                    case "--receipt": opt.ReceiptPath = v; break;
                    case "--automation-dir": opt.AutomationDir = v; break;
                    case "--sentinel-tcp": int.TryParse(v, out opt.SentinelTcp); break;
                    case "--sentinel-udp": int.TryParse(v, out opt.SentinelUdp); break;
                    case "--peer-proxy": int.TryParse(v, out opt.PeerProxy); break;
                    case "--dns-name": opt.DnsName = v; break;
                }
            }
            if (string.IsNullOrWhiteSpace(opt.UserDataDir)) {
                opt.UserDataDir = Path.Combine(Path.GetTempPath(), "ClaudeDesktopTwin-" + opt.Space);
            }
            return opt;
        }

        static string AcceptLanguageFor(string lang) {
            return lang != null && lang.StartsWith("zh", StringComparison.OrdinalIgnoreCase)
                ? "zh-CN,zh;q=0.9" : "en-US,en;q=0.9";
        }

        static string ChildLangFor(string lang) {
            return lang != null && lang.StartsWith("zh", StringComparison.OrdinalIgnoreCase)
                ? "zh_CN.UTF-8" : "en_US.UTF-8";
        }

        // Electron-style child process mode: --type=mcp-helper
        static int RunMcpHelper(DesktopOptions opt) {
            var id = TwinUtil.ReadIdentity();
            int proxyPort = TwinUtil.ParseProxyPort(opt.ProxyServer);
            string acceptLang = AcceptLanguageFor(opt.Lang);
            var health = TwinUtil.PostJsonViaProxy(proxyPort, opt.ApiHost, opt.TlsPin, "/v1/health",
                new Dictionary<string, string> {
                    { "Accept-Language", acceptLang },
                    { "X-Client", "claude-desktop-twin-mcp-helper" }
                },
                new Dictionary<string, object> { { "role", "mcp-helper" }, { "space", opt.Space } });

            var receipt = new Dictionary<string, object> {
                { "ok", true },
                { "role", "mcp-helper" },
                { "space", opt.Space },
                { "identity", id },
                { "langEnv", Environment.GetEnvironmentVariable("LANG") ?? "" },
                { "tzEnv", Environment.GetEnvironmentVariable("TZ") ?? "" },
                { "httpsProxyEnv", Environment.GetEnvironmentVariable("HTTPS_PROXY") ?? "" },
                { "nativeTimezone", TwinUtil.ReadNativeTimezone() },
                { "apiViaProxyOk", health.ok },
                { "apiStatusCode", health.statusCode },
                { "apiError", health.error },
                { "directSentinelTcp", TwinUtil.ProbeDirectTcp(opt.SentinelTcp) },
                { "directSentinelUdp", TwinUtil.ProbeDirectUdp(opt.SentinelUdp) },
                { "peerProxyTcp", TwinUtil.ProbeDirectTcp(opt.PeerProxy) },
                { "dnsQueryRc", TwinUtil.ProbeDnsQuery(opt.DnsName) }
            };
            if (!string.IsNullOrEmpty(opt.ReceiptPath)) TwinUtil.AtomicWriteJson(opt.ReceiptPath, receipt);
            return 0;
        }

        sealed class DesktopSessionState {
            public string Email;
            public string AccountUuid;
            public string OrgUuid;
            public string AccessToken;
            public string DesktopSessionFile;
            public string CoworkSessionFile;
            public string PendingState;
            public string PendingVerifier;
            public string PendingChallenge;
        }

        static DesktopSessionState LoadSession(string userDataDir) {
            string p = Path.Combine(userDataDir, "account-session.json");
            var s = new DesktopSessionState();
            if (!File.Exists(p)) return s;
            try {
                var d = TwinUtil.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(p, Encoding.UTF8));
                if (d != null) {
                    s.Email = d.ContainsKey("email") ? d["email"] as string : null;
                    s.AccountUuid = d.ContainsKey("accountUuid") ? d["accountUuid"] as string : null;
                    s.OrgUuid = d.ContainsKey("orgUuid") ? d["orgUuid"] as string : null;
                    s.AccessToken = d.ContainsKey("accessToken") ? d["accessToken"] as string : null;
                    s.DesktopSessionFile = d.ContainsKey("desktopSessionFile") ? d["desktopSessionFile"] as string : null;
                    s.CoworkSessionFile = d.ContainsKey("coworkSessionFile") ? d["coworkSessionFile"] as string : null;
                }
            } catch { }
            return s;
        }

        static void SaveSession(string userDataDir, DesktopSessionState s, DesktopOptions opt) {
            Directory.CreateDirectory(userDataDir);
            // Exact Claude Desktop identity-bound layout:
            //   <userDataDir>/claude-code-sessions/<accountUuid>/<orgUuid>/local_<id>.json
            //   <userDataDir>/local-agent-mode-sessions/<accountUuid>/<orgUuid>/cowork_<id>.json
            //   <userDataDir>/claude_desktop_config.json
            string ccDir = Path.Combine(Path.Combine(Path.Combine(userDataDir, "claude-code-sessions"), s.AccountUuid), s.OrgUuid);
            string cwDir = Path.Combine(Path.Combine(Path.Combine(userDataDir, "local-agent-mode-sessions"), s.AccountUuid), s.OrgUuid);
            Directory.CreateDirectory(ccDir);
            Directory.CreateDirectory(cwDir);
            if (string.IsNullOrEmpty(s.DesktopSessionFile)) {
                s.DesktopSessionFile = Path.Combine(ccDir, "local_" + TwinUtil.NewRandomHex(6) + ".json");
            }
            if (string.IsNullOrEmpty(s.CoworkSessionFile)) {
                s.CoworkSessionFile = Path.Combine(cwDir, "cowork_" + TwinUtil.NewRandomHex(6) + ".json");
            }
            if (!File.Exists(s.DesktopSessionFile)) {
                TwinUtil.AtomicWriteJson(s.DesktopSessionFile, new Dictionary<string, object> {
                    { "accountUuid", s.AccountUuid }, { "orgUuid", s.OrgUuid },
                    { "email", s.Email }, { "space", opt.Space }, { "turns", new List<object>() }
                });
            }
            if (!File.Exists(s.CoworkSessionFile)) {
                TwinUtil.AtomicWriteJson(s.CoworkSessionFile, new Dictionary<string, object> {
                    { "accountUuid", s.AccountUuid }, { "orgUuid", s.OrgUuid }, { "mode", "local-agent-mode-isolated" }
                });
            }
            TwinUtil.AtomicWriteJson(Path.Combine(userDataDir, "claude_desktop_config.json"), new Dictionary<string, object> {
                { "mcpServers", new Dictionary<string, object> {
                    { "twin-helper-" + opt.Space.ToLowerInvariant(), new Dictionary<string, object> {
                        { "command", Application.ExecutablePath }, { "args", new[] { "--type=mcp-helper", "--space=" + opt.Space } }
                    }}
                }},
                { "isolatedSpace", opt.Space }
            });
            TwinUtil.AtomicWriteJson(Path.Combine(userDataDir, "account-session.json"), new Dictionary<string, object> {
                { "email", s.Email },
                { "accountUuid", s.AccountUuid },
                { "orgUuid", s.OrgUuid },
                { "accessToken", s.AccessToken },
                { "desktopSessionFile", s.DesktopSessionFile },
                { "coworkSessionFile", s.CoworkSessionFile },
                { "uiLanguage", opt.Lang },
                { "rendererTimezone", opt.Tz }
            });
        }

        static Dictionary<string, object> SpawnMcpHelperChild(DesktopOptions opt) {
            string receiptPath = Path.Combine(opt.UserDataDir, "mcp-helper-receipt-" + TwinUtil.NewRandomHex(4) + ".json");
            var psi = new ProcessStartInfo {
                FileName = Application.ExecutablePath,
                Arguments = string.Format(
                    "--type=mcp-helper --space=\"{0}\" --user-data-dir=\"{1}\" --proxy-server=\"{2}\" --lang=\"{3}\" --tz=\"{4}\" --api-host=\"{5}\" --tls-pin=\"{6}\" --receipt=\"{7}\" --sentinel-tcp={8} --sentinel-udp={9} --peer-proxy={10} --dns-name=\"{11}\"",
                    opt.Space, opt.UserDataDir, opt.ProxyServer, opt.Lang, opt.Tz, opt.ApiHost, opt.TlsPin, receiptPath,
                    opt.SentinelTcp, opt.SentinelUdp, opt.PeerProxy, opt.DnsName),
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.EnvironmentVariables["LANG"] = ChildLangFor(opt.Lang);
            psi.EnvironmentVariables["TZ"] = opt.Tz;
            psi.EnvironmentVariables["HTTP_PROXY"] = opt.ProxyServer;
            psi.EnvironmentVariables["HTTPS_PROXY"] = opt.ProxyServer;
            psi.EnvironmentVariables["NO_PROXY"] = "";
            using (var p = Process.Start(psi)) {
                if (!p.WaitForExit(12000)) { try { p.Kill(); } catch { } return new Dictionary<string, object> { { "ok", false }, { "error", "mcp-helper-timeout" } }; }
                if (!File.Exists(receiptPath)) return new Dictionary<string, object> { { "ok", false }, { "error", "missing-receipt" }, { "exitCode", p.ExitCode } };
                var obj = TwinUtil.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(receiptPath, Encoding.UTF8));
                obj["exitCode"] = p.ExitCode;
                return obj;
            }
        }

        static Dictionary<string, object> RunCliTwinChild(DesktopOptions opt, string cliArgs) {
            if (string.IsNullOrEmpty(opt.CliExe) || !File.Exists(opt.CliExe)) {
                return new Dictionary<string, object> { { "ok", false }, { "error", "cli-exe-missing" } };
            }
            string cfgDir = !string.IsNullOrEmpty(opt.CliConfigDir) ? opt.CliConfigDir : Path.Combine(opt.UserDataDir, "cli-config");
            Directory.CreateDirectory(cfgDir);
            var psi = new ProcessStartInfo {
                FileName = opt.CliExe,
                Arguments = cliArgs,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            psi.EnvironmentVariables["CLAUDE_CONFIG_DIR"] = cfgDir;
            psi.EnvironmentVariables["HTTP_PROXY"] = opt.ProxyServer;
            psi.EnvironmentVariables["HTTPS_PROXY"] = opt.ProxyServer;
            psi.EnvironmentVariables["NO_PROXY"] = "";
            psi.EnvironmentVariables["LANG"] = ChildLangFor(opt.Lang);
            psi.EnvironmentVariables["TZ"] = opt.Tz;
            psi.EnvironmentVariables["CLAUDE_TWIN_API_HOST"] = opt.ApiHost;
            psi.EnvironmentVariables["CLAUDE_TWIN_TLS_PIN"] = opt.TlsPin;
            using (var p = Process.Start(psi)) {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit(15000);
                Dictionary<string, object> parsed = null;
                try { parsed = TwinUtil.Json.Deserialize<Dictionary<string, object>>(stdout.Trim()); } catch { }
                return new Dictionary<string, object> {
                    { "exitCode", p.ExitCode },
                    { "parsed", parsed },
                    { "stdout", stdout.Trim() },
                    { "stderr", stderr.Trim() }
                };
            }
        }

        [STAThread]
        public static int Main(string[] args) {
            var opt = ParseArgs(args ?? new string[0]);
            if (string.Equals(opt.ProcessType, "mcp-helper", StringComparison.OrdinalIgnoreCase)) {
                return RunMcpHelper(opt);
            }

            Directory.CreateDirectory(opt.UserDataDir);
            var identity = TwinUtil.ReadIdentity();
            string mutexName = "Local\\ClaudeDesktopTwin-" + (identity.userSid ?? "u") + "-" + TwinUtil.Sha256Hex(Path.GetFullPath(opt.UserDataDir)).Substring(0, 12);

            bool createdNew;
            using (var singleInstanceMutex = new Mutex(true, mutexName, out createdNew)) {
                if (!createdNew) {
                    // Warm single-instance activation receipt (identical to real Claude Desktop single-window behavior!)
                    TwinUtil.AtomicWriteJson(Path.Combine(opt.UserDataDir, "warm-activation.json"), new Dictionary<string, object> {
                        { "warm", true }, { "space", opt.Space }, { "identity", identity }, { "utc", DateTime.UtcNow.ToString("o") }
                    });
                    return 0;
                }

                Application.EnableVisualStyles();
                int proxyPort = TwinUtil.ParseProxyPort(opt.ProxyServer);
                string acceptLang = AcceptLanguageFor(opt.Lang);
                var session = LoadSession(opt.UserDataDir);
                StreamHandle activeStream = null;

                bool isSpaceA = string.Equals(opt.Space, "A", StringComparison.OrdinalIgnoreCase);
                Color accent = isSpaceA ? Color.FromArgb(37, 99, 235) : Color.FromArgb(217, 119, 6);
                Color bgDark = Color.FromArgb(15, 23, 42);
                Color cardDark = Color.FromArgb(30, 41, 59);

                using (var form = new Form {
                    Text = string.Format("Claude Desktop Twin | Space {0} | {1} | {2}", opt.Space, opt.Lang, opt.Tz),
                    Width = 680, Height = 520, BackColor = bgDark, ForeColor = Color.White,
                    StartPosition = FormStartPosition.Manual,
                    Location = isSpaceA ? new Point(40, 60) : new Point(740, 60)
                }) {
                    var stripe = new Panel { Dock = DockStyle.Top, Height = 6, BackColor = accent };
                    var infoLabel = new Label {
                        Dock = DockStyle.Top, Height = 82, BackColor = cardDark, ForeColor = Color.FromArgb(226, 232, 240),
                        Padding = new Padding(12, 8, 12, 8), Font = new Font("Consolas", 9f)
                    };
                    var logBox = new TextBox {
                        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                        BackColor = bgDark, ForeColor = Color.FromArgb(226, 232, 240), BorderStyle = BorderStyle.None,
                        Font = new Font("Consolas", 9.5f)
                    };
                    var bottomPanel = new Panel { Dock = DockStyle.Bottom, Height = 74, BackColor = cardDark, Padding = new Padding(8) };
                    var promptInput = new TextBox {
                        Left = 10, Top = 8, Width = 440, BackColor = bgDark, ForeColor = Color.White,
                        Text = isSpaceA ? "请汇报当前 Space A 的身份与时区" : "Report Space B identity and timezone"
                    };
                    var sendBtn = new Button { Left = 460, Top = 6, Width = 96, Height = 26, Text = "发送消息", BackColor = accent, ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
                    var cliBtn = new Button { Left = 564, Top = 6, Width = 96, Height = 26, Text = "CLI 自检", BackColor = Color.FromArgb(51, 65, 85), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
                    var streamBtn = new Button { Left = 10, Top = 38, Width = 140, Height = 26, Text = "启动流式对话 (SSE)", BackColor = Color.FromArgb(4, 120, 87), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
                    var helperBtn = new Button { Left = 158, Top = 38, Width = 150, Height = 26, Text = "派生 MCP Helper 校验", BackColor = Color.FromArgb(51, 65, 85), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };

                    bottomPanel.Controls.AddRange(new Control[] { promptInput, sendBtn, cliBtn, streamBtn, helperBtn });
                    form.Controls.Add(logBox);
                    form.Controls.Add(bottomPanel);
                    form.Controls.Add(infoLabel);
                    form.Controls.Add(stripe);

                    Action refreshHeader = () => {
                        infoLabel.Text = string.Format(
                            "Space {0} ({1} / {2}) | Proxy: {3} | Container: {4}\r\n" +
                            "Account: {5} | AccountUUID: {6} | OrgUUID: {7}\r\n" +
                            "UserData: {8}",
                            opt.Space, opt.Lang, opt.Tz, opt.ProxyServer, identity.containerSid ?? "(non-PSEC demo)",
                            session.Email ?? "(未登录)", session.AccountUuid ?? "-", session.OrgUuid ?? "-",
                            opt.UserDataDir);
                    };
                    Action<string> appendUi = (msg) => {
                        logBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + "\r\n");
                    };

                    Func<string, string, string, Dictionary<string, object>> doChat = (promptText, spoofAcct, spoofOrg) => {
                        if (string.IsNullOrEmpty(session.AccessToken)) {
                            return new Dictionary<string, object> { { "ok", false }, { "code", "NOT_LOGGED_IN" } };
                        }
                        var hdrs = new Dictionary<string, string> {
                            { "Authorization", "Bearer " + session.AccessToken },
                            { "X-Account-Uuid", !string.IsNullOrEmpty(spoofAcct) ? spoofAcct : session.AccountUuid },
                            { "X-Org-Uuid", !string.IsNullOrEmpty(spoofOrg) ? spoofOrg : session.OrgUuid },
                            { "Accept-Language", acceptLang },
                            { "X-Client", "claude-desktop-twin" }
                        };
                        var resp = TwinUtil.PostJsonViaProxy(proxyPort, opt.ApiHost, opt.TlsPin, "/v1/messages", hdrs,
                            new Dictionary<string, object> {
                                { "model", "claude-twin-desktop" }, { "prompt", promptText }, { "stream", false }
                            });
                        if (resp.ok && !string.IsNullOrEmpty(session.DesktopSessionFile) && File.Exists(session.DesktopSessionFile)) {
                            var doc = TwinUtil.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(session.DesktopSessionFile, Encoding.UTF8));
                            var list = new List<object>();
                            if (doc.ContainsKey("turns") && doc["turns"] is object[]) list.AddRange((object[])doc["turns"]);
                            list.Add(new Dictionary<string, object> { { "utc", DateTime.UtcNow.ToString("o") }, { "prompt", promptText }, { "reply", resp.body } });
                            doc["turns"] = list;
                            TwinUtil.AtomicWriteJson(session.DesktopSessionFile, doc);
                        }
                        appendUi("Chat -> status=" + resp.statusCode + " ok=" + resp.ok + " " + (resp.ok ? resp.body : resp.error));
                        return new Dictionary<string, object> {
                            { "ok", resp.ok }, { "statusCode", resp.statusCode }, { "body", resp.body },
                            { "error", resp.error }, { "desktopSessionFile", session.DesktopSessionFile }
                        };
                    };

                    sendBtn.Click += (s, e) => { doChat(promptInput.Text, null, null); };
                    cliBtn.Click += (s, e) => {
                        var r = RunCliTwinChild(opt, "doctor");
                        appendUi("CLI doctor -> exit=" + r["exitCode"] + " " + r["stdout"]);
                    };
                    helperBtn.Click += (s, e) => {
                        var r = SpawnMcpHelperChild(opt);
                        appendUi("MCP Helper -> apiViaProxyOk=" + r["apiViaProxyOk"] + " container=" + ((Dictionary<string, object>)r["identity"])["containerSid"]);
                    };
                    streamBtn.Click += (s, e) => {
                        try {
                            if (activeStream != null) activeStream.Dispose();
                            activeStream = TwinUtil.StartSseStreamViaProxy(proxyPort, opt.ApiHost, opt.TlsPin, "/v1/messages",
                                new Dictionary<string, string> {
                                    { "Authorization", "Bearer " + (session.AccessToken ?? "") },
                                    { "X-Account-Uuid", session.AccountUuid ?? "" },
                                    { "X-Org-Uuid", session.OrgUuid ?? "" },
                                    { "Accept-Language", acceptLang },
                                    { "X-Client", "claude-desktop-twin-stream" }
                                },
                                new Dictionary<string, object> { { "prompt", "stream" }, { "stream", true } });
                            appendUi("SSE Stream opened via proxy 127.0.0.1:" + proxyPort);
                        } catch (Exception ex) {
                            appendUi("SSE Stream failed: " + ex.Message);
                        }
                    };

                    refreshHeader();
                    form.Show();
                    Application.DoEvents();

                    if (string.IsNullOrEmpty(opt.AutomationDir)) {
                        appendUi("Interactive Claude Desktop Twin ready. (No official binary touched)");
                        Application.Run(form);
                        if (activeStream != null) activeStream.Dispose();
                        return 0;
                    }

                    // Deterministic automation loop (keeps real visible WinForms GUI responsive!)
                    Directory.CreateDirectory(opt.AutomationDir);
                    TwinUtil.AtomicWriteJson(Path.Combine(opt.AutomationDir, "ready.json"), new Dictionary<string, object> {
                        { "ok", true },
                        { "space", opt.Space },
                        { "identity", identity },
                        { "visible", IsWindowVisible(form.Handle) },
                        { "windowHandle", form.Handle.ToInt64() },
                        { "windowTitle", form.Text },
                        { "windowLanguage", opt.Lang },
                        { "rendererTimezone", opt.Tz },
                        { "rendererRefUtcFormatted", TwinUtil.FormatFixedUtcWithOffset(opt.Tz) },
                        { "acceptLanguage", acceptLang },
                        { "nativeTimezone", TwinUtil.ReadNativeTimezone() },
                        { "userDataDir", opt.UserDataDir },
                        { "proxyPort", proxyPort }
                    });

                    var lifetime = Stopwatch.StartNew();
                    try {
                        for (int seq = 1; ; seq++) {
                            string cmdPath = Path.Combine(opt.AutomationDir, "cmd-" + seq + ".json");
                            string resPath = Path.Combine(opt.AutomationDir, "res-" + seq + ".json");
                            while (!File.Exists(cmdPath)) {
                                if (lifetime.ElapsedMilliseconds > 150000 || form.IsDisposed) return 0;
                                Application.DoEvents();
                                Thread.Sleep(15);
                            }
                            var cmd = TwinUtil.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(cmdPath, Encoding.UTF8));
                            string action = cmd["action"] as string;
                            object result = null;

                            if (action == "finish") {
                                TwinUtil.AtomicWriteJson(resPath, new Dictionary<string, object> { { "ok", true }, { "action", "finish" } });
                                break;
                            } else if (action == "status") {
                                result = new Dictionary<string, object> {
                                    { "ok", true }, { "loggedIn", !string.IsNullOrEmpty(session.AccessToken) },
                                    { "email", session.Email }, { "accountUuid", session.AccountUuid }, { "orgUuid", session.OrgUuid },
                                    { "desktopSessionFile", session.DesktopSessionFile }, { "coworkSessionFile", session.CoworkSessionFile },
                                    { "identity", identity }, { "windowLanguage", opt.Lang }, { "rendererTimezone", opt.Tz },
                                    { "rendererRefUtcFormatted", TwinUtil.FormatFixedUtcWithOffset(opt.Tz) },
                                    { "acceptLanguage", acceptLang }, { "nativeTimezone", TwinUtil.ReadNativeTimezone() }
                                };
                            } else if (action == "oauth-start") {
                                session.PendingState = TwinUtil.NewRandomHex(12);
                                session.PendingVerifier = TwinUtil.NewRandomHex(24);
                                session.PendingChallenge = TwinUtil.Base64UrlSha256(session.PendingVerifier);
                                result = new Dictionary<string, object> {
                                    { "ok", true }, { "state", session.PendingState }, { "codeChallenge", session.PendingChallenge }
                                };
                            } else if (action == "oauth-complete") {
                                string st = cmd.ContainsKey("state") ? cmd["state"] as string : "";
                                string code = cmd.ContainsKey("code") ? cmd["code"] as string : "";
                                if (string.IsNullOrEmpty(session.PendingState)) {
                                    result = new Dictionary<string, object> { { "ok", false }, { "code", "NO_PENDING_LOGIN" } };
                                } else if (!string.Equals(session.PendingState, st, StringComparison.Ordinal)) {
                                    result = new Dictionary<string, object> { { "ok", false }, { "code", "STATE_MISMATCH" } };
                                } else {
                                    var resp = TwinUtil.PostJsonViaProxy(proxyPort, opt.ApiHost, opt.TlsPin, "/oauth/token",
                                        new Dictionary<string, string> { { "Accept-Language", acceptLang }, { "X-Client", "claude-desktop-twin" } },
                                        new Dictionary<string, object> {
                                            { "grant_type", "authorization_code" }, { "code", code }, { "state", st },
                                            { "code_verifier", session.PendingVerifier }
                                        });
                                    if (!resp.ok) {
                                        result = new Dictionary<string, object> { { "ok", false }, { "code", "OAUTH_EXCHANGE_FAILED" }, { "statusCode", resp.statusCode }, { "body", resp.body }, { "error", resp.error } };
                                    } else {
                                        var tok = TwinUtil.Json.Deserialize<Dictionary<string, object>>(resp.body);
                                        session.AccessToken = tok["access_token"] as string;
                                        session.Email = tok["email"] as string;
                                        session.AccountUuid = tok["account_uuid"] as string;
                                        session.OrgUuid = tok["org_uuid"] as string;
                                        session.PendingState = null; session.PendingVerifier = null; session.PendingChallenge = null;
                                        SaveSession(opt.UserDataDir, session, opt);
                                        refreshHeader();
                                        appendUi("OAuth PKCE logged in as " + session.Email + " (" + session.AccountUuid + ")");
                                        result = new Dictionary<string, object> {
                                            { "ok", true }, { "email", session.Email }, { "accountUuid", session.AccountUuid },
                                            { "orgUuid", session.OrgUuid }, { "desktopSessionFile", session.DesktopSessionFile },
                                            { "coworkSessionFile", session.CoworkSessionFile }
                                        };
                                    }
                                }
                            } else if (action == "chat") {
                                string prompt = cmd.ContainsKey("prompt") ? cmd["prompt"] as string : "hello";
                                string spoofAcct = cmd.ContainsKey("spoofAccountUuid") ? cmd["spoofAccountUuid"] as string : null;
                                string spoofOrg = cmd.ContainsKey("spoofOrgUuid") ? cmd["spoofOrgUuid"] as string : null;
                                result = doChat(prompt, spoofAcct, spoofOrg);
                            } else if (action == "stream-start") {
                                try {
                                    if (activeStream != null) activeStream.Dispose();
                                    activeStream = TwinUtil.StartSseStreamViaProxy(proxyPort, opt.ApiHost, opt.TlsPin, "/v1/messages",
                                        new Dictionary<string, string> {
                                            { "Authorization", "Bearer " + (session.AccessToken ?? "") },
                                            { "X-Account-Uuid", session.AccountUuid ?? "" },
                                            { "X-Org-Uuid", session.OrgUuid ?? "" },
                                            { "Accept-Language", acceptLang },
                                            { "X-Client", "claude-desktop-twin-stream" }
                                        },
                                        new Dictionary<string, object> { { "prompt", "sse-stream" }, { "stream", true } });
                                    result = new Dictionary<string, object> { { "ok", true } };
                                } catch (Exception ex) {
                                    result = new Dictionary<string, object> { { "ok", false }, { "error", ex.Message } };
                                }
                            } else if (action == "stream-status") {
                                result = activeStream != null ? activeStream.Snapshot() : new Dictionary<string, object> { { "ok", false }, { "error", "no-stream" } };
                            } else if (action == "spawn-mcp-helper") {
                                result = SpawnMcpHelperChild(opt);
                            } else if (action == "run-cli") {
                                string cliArgs = cmd.ContainsKey("cliArgs") ? cmd["cliArgs"] as string : "auth status";
                                result = RunCliTwinChild(opt, cliArgs);
                            } else if (action == "cross-read") {
                                string target = cmd.ContainsKey("path") ? cmd["path"] as string : "";
                                try {
                                    string text = File.ReadAllText(target, Encoding.UTF8);
                                    result = new Dictionary<string, object> { { "readable", true }, { "length", text.Length } };
                                } catch (Exception ex) {
                                    result = new Dictionary<string, object> { { "readable", false }, { "errorType", ex.GetType().Name }, { "message", ex.Message } };
                                }
                            } else if (action == "bypass-check") {
                                string dnsName = cmd.ContainsKey("dnsName") ? cmd["dnsName"] as string : opt.DnsName;
                                var health = TwinUtil.PostJsonViaProxy(proxyPort, opt.ApiHost, opt.TlsPin, "/v1/health",
                                    new Dictionary<string, string> { { "Accept-Language", acceptLang }, { "X-Client", "claude-desktop-twin-check" } },
                                    new Dictionary<string, object> { { "ping", "desktop" } });
                                result = new Dictionary<string, object> {
                                    { "apiViaProxyOk", health.ok }, { "apiStatusCode", health.statusCode }, { "apiError", health.error },
                                    { "directSentinelTcp", TwinUtil.ProbeDirectTcp(opt.SentinelTcp) },
                                    { "directSentinelUdp", TwinUtil.ProbeDirectUdp(opt.SentinelUdp) },
                                    { "peerProxyTcp", TwinUtil.ProbeDirectTcp(opt.PeerProxy) },
                                    { "dnsQueryRc", TwinUtil.ProbeDnsQuery(dnsName) }
                                };
                            } else {
                                result = new Dictionary<string, object> { { "ok", false }, { "error", "unknown-action:" + action } };
                            }
                            TwinUtil.AtomicWriteJson(resPath, result);
                        }
                    } finally {
                        if (activeStream != null) activeStream.Dispose();
                    }
                }
            }
            return 0;
        }
    }
}
