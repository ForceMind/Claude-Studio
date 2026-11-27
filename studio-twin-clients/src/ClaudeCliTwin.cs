using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ClaudeStudio.Twin {
    // High-fidelity synthetic Claude Code CLI Twin.
    // Mirrors official Anthropic CLI contracts:
    //   - CLAUDE_CONFIG_DIR (strictly isolated per space; rejects symlinks!)
    //   - HTTPS_PROXY / HTTP_PROXY -> 127.0.0.1:<Pa|Pb>
    //   - LANG / TZ environment variables
    //   - .credentials.json + .claude.json + projects/<encoded-cwd>/<sessionUuid>.jsonl
    //   - Subcommands: auth status | auth start-oauth | auth complete-oauth | -p "<prompt>" | doctor
    public static class ClaudeCliTwinProgram {
        static string GetConfigDir() {
            string env = Environment.GetEnvironmentVariable("CLAUDE_CONFIG_DIR");
            if (!string.IsNullOrWhiteSpace(env)) return env.Trim();
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude-twin");
        }

        static string GetArg(string[] args, string flag, string defVal = null) {
            for (int i = 0; i < args.Length - 1; i++) {
                if (string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
            }
            return defVal;
        }

        static Dictionary<string, object> ReadJsonOrNull(string path) {
            if (!File.Exists(path)) return null;
            return TwinUtil.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
        }

        static int Emit(object payload, int exitCode = 0) {
            Console.OutputEncoding = new UTF8Encoding(false);
            Console.WriteLine(TwinUtil.Json.Serialize(payload));
            return exitCode;
        }

        public static int Main(string[] args) {
            try {
                if (args == null || args.Length == 0) {
                    return Emit(new { ok = false, error = "Usage: ClaudeCliTwin.exe <auth status|auth start-oauth|auth complete-oauth|-p ...|doctor>" }, 2);
                }
                string cfgDir = GetConfigDir();
                Directory.CreateDirectory(cfgDir);
                string projectsDir = Path.Combine(cfgDir, "projects");
                Directory.CreateDirectory(projectsDir);

                // Anti-ClaudeDock-pollution invariant: NEVER allow symlinked config/projects directories!
                bool cfgSymlink = TwinUtil.HasReparsePoint(cfgDir);
                bool projSymlink = TwinUtil.HasReparsePoint(projectsDir);
                if (cfgSymlink || projSymlink) {
                    return Emit(new { ok = false, code = "SYMLINK_CONFIG_FORBIDDEN", cfgSymlink, projSymlink }, 11);
                }

                string proxyUrl = GetArg(args, "--proxy")
                    ?? Environment.GetEnvironmentVariable("HTTPS_PROXY")
                    ?? Environment.GetEnvironmentVariable("HTTP_PROXY") ?? "";
                int proxyPort = TwinUtil.ParseProxyPort(proxyUrl);
                string apiHost = GetArg(args, "--api-host")
                    ?? Environment.GetEnvironmentVariable("CLAUDE_TWIN_API_HOST") ?? "api.claude-twin.test";
                string tlsPin = GetArg(args, "--tls-pin")
                    ?? Environment.GetEnvironmentVariable("CLAUDE_TWIN_TLS_PIN") ?? "";
                string langEnv = Environment.GetEnvironmentVariable("LANG") ?? "en_US.UTF-8";
                string tzEnv = Environment.GetEnvironmentVariable("TZ") ?? "UTC";
                string acceptLang = langEnv.StartsWith("zh", StringComparison.OrdinalIgnoreCase) ? "zh-CN,zh;q=0.9" : "en-US,en;q=0.9";

                string credPath = Path.Combine(cfgDir, ".credentials.json");
                string claudeJsonPath = Path.Combine(cfgDir, ".claude.json");
                string pendingPath = Path.Combine(cfgDir, ".pending-oauth.json");
                var identity = TwinUtil.ReadIdentity();

                if (string.Equals(args[0], "auth", StringComparison.OrdinalIgnoreCase) && args.Length >= 2) {
                    string sub = args[1].ToLowerInvariant();
                    if (sub == "status") {
                        var cred = ReadJsonOrNull(credPath);
                        return Emit(new Dictionary<string, object> {
                            { "ok", true },
                            { "loggedIn", cred != null },
                            { "email", cred != null && cred.ContainsKey("email") ? cred["email"] : null },
                            { "accountUuid", cred != null && cred.ContainsKey("accountUuid") ? cred["accountUuid"] : null },
                            { "orgUuid", cred != null && cred.ContainsKey("orgUuid") ? cred["orgUuid"] : null },
                            { "configDir", cfgDir },
                            { "symlinkCheckPassed", true },
                            { "langEnv", langEnv },
                            { "tzEnv", tzEnv },
                            { "nativeTimezone", TwinUtil.ReadNativeTimezone() },
                            { "identity", identity }
                        });
                    }
                    if (sub == "start-oauth") {
                        string state = TwinUtil.NewRandomHex(12);
                        string verifier = TwinUtil.NewRandomHex(24);
                        string challenge = TwinUtil.Base64UrlSha256(verifier);
                        var pending = new Dictionary<string, object> {
                            { "state", state },
                            { "codeVerifier", verifier },
                            { "codeChallenge", challenge },
                            { "createdUtc", DateTime.UtcNow.ToString("o") }
                        };
                        TwinUtil.AtomicWriteJson(pendingPath, pending);
                        return Emit(new Dictionary<string, object> {
                            { "ok", true },
                            { "state", state },
                            { "codeChallenge", challenge },
                            { "authorizeUrl", string.Format("https://{0}/oauth/authorize?state={1}&code_challenge={2}&method=S256", apiHost, state, challenge) },
                            { "identity", identity }
                        });
                    }
                    if (sub == "complete-oauth") {
                        string state = GetArg(args, "--state", "");
                        string code = GetArg(args, "--code", "");
                        var pending = ReadJsonOrNull(pendingPath);
                        if (pending == null) return Emit(new { ok = false, code = "NO_PENDING_LOGIN" }, 3);
                        if (!string.Equals(pending["state"] as string, state, StringComparison.Ordinal)) {
                            return Emit(new { ok = false, code = "STATE_MISMATCH" }, 4);
                        }
                        var resp = TwinUtil.PostJsonViaProxy(proxyPort, apiHost, tlsPin, "/oauth/token",
                            new Dictionary<string, string> { { "Accept-Language", acceptLang }, { "X-Client", "claude-cli-twin" } },
                            new Dictionary<string, object> {
                                { "grant_type", "authorization_code" },
                                { "code", code },
                                { "state", state },
                                { "code_verifier", pending["codeVerifier"] }
                            });
                        if (!resp.ok) {
                            return Emit(new { ok = false, code = "OAUTH_EXCHANGE_FAILED", statusCode = resp.statusCode, body = resp.body, error = resp.error }, 5);
                        }
                        var tok = TwinUtil.Json.Deserialize<Dictionary<string, object>>(resp.body);
                        var credObj = new Dictionary<string, object> {
                            { "accessToken", tok["access_token"] },
                            { "email", tok["email"] },
                            { "accountUuid", tok["account_uuid"] },
                            { "orgUuid", tok["org_uuid"] },
                            { "authenticatedUtc", DateTime.UtcNow.ToString("o") }
                        };
                        TwinUtil.AtomicWriteJson(credPath, credObj);
                        TwinUtil.AtomicWriteJson(claudeJsonPath, new Dictionary<string, object> {
                            { "oauthAccount", new Dictionary<string, object> {
                                { "emailAddress", tok["email"] },
                                { "accountUuid", tok["account_uuid"] },
                                { "organizationUuid", tok["org_uuid"] }
                            }},
                            { "isolatedConfigDir", cfgDir }
                        });
                        try { File.Delete(pendingPath); } catch { }
                        return Emit(new Dictionary<string, object> {
                            { "ok", true },
                            { "email", tok["email"] },
                            { "accountUuid", tok["account_uuid"] },
                            { "orgUuid", tok["org_uuid"] },
                            { "credPath", credPath },
                            { "identity", identity }
                        });
                    }
                    return Emit(new { ok = false, error = "Unknown auth subcommand: " + sub }, 2);
                }

                if (string.Equals(args[0], "doctor", StringComparison.OrdinalIgnoreCase)) {
                    int sTcp = int.Parse(GetArg(args, "--sentinel-tcp", "0"));
                    int sUdp = int.Parse(GetArg(args, "--sentinel-udp", "0"));
                    int peerP = int.Parse(GetArg(args, "--peer-proxy", "0"));
                    string dnsName = GetArg(args, "--dns-name", "");
                    var cred = ReadJsonOrNull(credPath);
                    var apiCheck = TwinUtil.PostJsonViaProxy(proxyPort, apiHost, tlsPin, "/v1/health",
                        new Dictionary<string, string> {
                            { "Accept-Language", acceptLang },
                            { "X-Client", "claude-cli-twin-doctor" }
                        },
                        new Dictionary<string, object> { { "ping", "doctor" } });
                    return Emit(new Dictionary<string, object> {
                        { "ok", true },
                        { "loggedIn", cred != null },
                        { "configDir", cfgDir },
                        { "symlinkCheckPassed", true },
                        { "proxyPort", proxyPort },
                        { "apiReachableViaProxy", apiCheck.ok },
                        { "apiStatusCode", apiCheck.statusCode },
                        { "apiError", apiCheck.error },
                        { "directSentinelTcp", TwinUtil.ProbeDirectTcp(sTcp) },
                        { "directSentinelUdp", TwinUtil.ProbeDirectUdp(sUdp) },
                        { "peerProxyTcp", TwinUtil.ProbeDirectTcp(peerP) },
                        { "dnsQueryRc", TwinUtil.ProbeDnsQuery(dnsName) },
                        { "langEnv", langEnv },
                        { "tzEnv", tzEnv },
                        { "acceptLanguage", acceptLang },
                        { "nativeTimezone", TwinUtil.ReadNativeTimezone() },
                        { "identity", identity }
                    });
                }

                // Prompt execution: -p "<prompt>" [--cwd <dir>] [--resume <sessionId>] [--write-file <rel> --content <txt>]
                string prompt = GetArg(args, "-p");
                if (prompt != null) {
                    var cred = ReadJsonOrNull(credPath);
                    if (cred == null) return Emit(new { ok = false, code = "NOT_LOGGED_IN" }, 6);
                    string cwd = GetArg(args, "--cwd", Environment.CurrentDirectory);
                    string sessionId = GetArg(args, "--resume", Guid.NewGuid().ToString("D"));
                    string writeFileRel = GetArg(args, "--write-file");
                    string writeContent = GetArg(args, "--content", "");
                    string readFileRel = GetArg(args, "--read-file");

                    string encodedProj = TwinUtil.EncodeClaudeProjectPath(cwd);
                    string projSessionDir = Path.Combine(projectsDir, encodedProj);
                    Directory.CreateDirectory(projSessionDir);
                    string jsonlPath = Path.Combine(projSessionDir, sessionId + ".jsonl");

                    string readResult = null;
                    string readError = null;
                    if (!string.IsNullOrEmpty(readFileRel)) {
                        try { readResult = File.ReadAllText(Path.Combine(cwd, readFileRel), Encoding.UTF8); }
                        catch (Exception ex) { readError = ex.GetType().Name + ": " + ex.Message; }
                    }

                    bool writeOk = false;
                    string writeError = null;
                    if (!string.IsNullOrEmpty(writeFileRel)) {
                        try {
                            string targetFile = Path.Combine(cwd, writeFileRel);
                            File.WriteAllText(targetFile, writeContent, new UTF8Encoding(false));
                            writeOk = true;
                        } catch (Exception ex) {
                            writeError = ex.GetType().Name + ": " + ex.Message;
                        }
                    }

                    var headers = new Dictionary<string, string> {
                        { "Authorization", "Bearer " + (cred["accessToken"] as string) },
                        { "X-Account-Uuid", cred["accountUuid"] as string },
                        { "X-Org-Uuid", cred["orgUuid"] as string },
                        { "Accept-Language", acceptLang },
                        { "X-Client", "claude-cli-twin" }
                    };
                    var apiResp = TwinUtil.PostJsonViaProxy(proxyPort, apiHost, tlsPin, "/v1/messages", headers,
                        new Dictionary<string, object> {
                            { "model", "claude-twin-sonnet" },
                            { "session_id", sessionId },
                            { "prompt", prompt },
                            { "cwd_encoded", encodedProj },
                            { "stream", false }
                        });

                    if (apiResp.ok) {
                        var turn = new Dictionary<string, object> {
                            { "utc", DateTime.UtcNow.ToString("o") },
                            { "sessionId", sessionId },
                            { "cwd", cwd },
                            { "accountUuid", cred["accountUuid"] },
                            { "prompt", prompt },
                            { "responseBody", apiResp.body },
                            { "writeFile", writeFileRel },
                            { "writeOk", writeOk }
                        };
                        File.AppendAllText(jsonlPath, TwinUtil.Json.Serialize(turn) + "\n", new UTF8Encoding(false));
                    }

                    return Emit(new Dictionary<string, object> {
                        { "ok", apiResp.ok },
                        { "statusCode", apiResp.statusCode },
                        { "apiBody", apiResp.body },
                        { "apiError", apiResp.error },
                        { "sessionId", sessionId },
                        { "encodedProjectDir", encodedProj },
                        { "jsonlPath", jsonlPath },
                        { "jsonlExists", File.Exists(jsonlPath) },
                        { "readResult", readResult },
                        { "readError", readError },
                        { "writeRequested", !string.IsNullOrEmpty(writeFileRel) },
                        { "writeOk", writeOk },
                        { "writeError", writeError },
                        { "langEnv", langEnv },
                        { "tzEnv", tzEnv },
                        { "acceptLanguage", acceptLang },
                        { "nativeTimezone", TwinUtil.ReadNativeTimezone() },
                        { "identity", identity }
                    }, apiResp.ok ? 0 : 7);
                }

                return Emit(new { ok = false, error = "Unsupported CLI arguments" }, 2);
            } catch (Exception ex) {
                return Emit(new { ok = false, error = ex.GetType().Name + ": " + ex.Message }, 1);
            }
        }
    }
}
