using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace ClaudeStudio.ControlPlane {
    public sealed class PersistedProjectEntry {
        public string CanonicalPath { get; set; }
        public string WriterSpace { get; set; }
        public bool SpaceAReadOnly { get; set; }
        public bool SpaceBReadOnly { get; set; }
    }

    // Sanitized user preference store (ZERO credentials, ZERO passwords, ZERO OAuth tokens, ZERO private proxy auth).
    public sealed class StudioUserConfig {
        public string Schema { get; set; }
        public string UpstreamHost { get; set; }
        public int UpstreamPort { get; set; }
        public bool StaticTemplateSyncOptIn { get; set; }
        public string SpaceALanguage { get; set; }
        public string SpaceATimezone { get; set; }
        public string SpaceBLanguage { get; set; }
        public string SpaceBTimezone { get; set; }
        public List<PersistedProjectEntry> Projects { get; set; }
        public string LastSavedUtc { get; set; }

        public StudioUserConfig() {
            Schema = "claude-studio-config-v1";
            UpstreamHost = "127.0.0.1";
            UpstreamPort = 0;
            StaticTemplateSyncOptIn = false;
            SpaceALanguage = "zh-CN";
            SpaceATimezone = "Asia/Shanghai";
            SpaceBLanguage = "en-US";
            SpaceBTimezone = "America/Los_Angeles";
            Projects = new List<PersistedProjectEntry>();
            LastSavedUtc = DateTime.UtcNow.ToString("o");
        }
    }

    public static class StudioConfigStore {
        public static string DefaultConfigPath {
            get {
                string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(localApp, "ClaudeStudioControlPlane", "config.json");
            }
        }

        public static StudioUserConfig Load(string customPath = null) {
            string path = string.IsNullOrWhiteSpace(customPath) ? DefaultConfigPath : customPath;
            if (!File.Exists(path)) return new StudioUserConfig();
            try {
                string raw = File.ReadAllText(path, Encoding.UTF8);
                var ser = new JavaScriptSerializer();
                var cfg = ser.Deserialize<StudioUserConfig>(raw);
                if (cfg == null) return new StudioUserConfig();
                if (cfg.Projects == null) cfg.Projects = new List<PersistedProjectEntry>();
                // Hard safety boundary: never auto-restore reserved host proxy port 10810 on startup.
                if (cfg.UpstreamPort == StudioEngine.ReservedHostProxyPort) cfg.UpstreamPort = 0;
                return cfg;
            } catch {
                return new StudioUserConfig();
            }
        }

        public static bool Save(StudioUserConfig cfg, out string error, string customPath = null) {
            error = null;
            if (cfg == null) { error = "Config object is null."; return false; }
            if (cfg.UpstreamPort == StudioEngine.ReservedHostProxyPort) {
                error = "Refused to persist reserved host proxy port 10810.";
                return false;
            }
            string path = string.IsNullOrWhiteSpace(customPath) ? DefaultConfigPath : customPath;
            try {
                cfg.Schema = "claude-studio-config-v1";
                cfg.LastSavedUtc = DateTime.UtcNow.ToString("o");
                string dir = Path.GetDirectoryName(Path.GetFullPath(path));
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                var ser = new JavaScriptSerializer();
                File.WriteAllText(path, ser.Serialize(cfg), new UTF8Encoding(false));
                return true;
            } catch (Exception ex) {
                error = ex.Message;
                return false;
            }
        }
    }
}
