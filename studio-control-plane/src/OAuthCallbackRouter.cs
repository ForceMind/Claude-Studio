using System;
using System.Text;

namespace ClaudeStudio.ControlPlane {
    // Validates and redacts `claude://` OAuth / deep-link callbacks before dispatching them
    // into a specific space's isolated PSEC 1.1 container via Layer-2 guardian IPC.
    // Because Windows registers `claude://` globally, explicit per-space routing prevents
    // Space A and Space B logins from ever cross-delivering or leaking outside their container.
    public static class OAuthCallbackRouter {
        public const int MaxUrlLength = 2048;

        public static bool ValidateAndSanitizeCallbackUrl(string rawUrl, out string normalizedUrl, out string error) {
            normalizedUrl = null;
            error = null;

            if (string.IsNullOrWhiteSpace(rawUrl)) {
                error = "Callback URL cannot be empty.";
                return false;
            }

            string trimmed = rawUrl.Trim();
            if (trimmed.Length > MaxUrlLength) {
                error = "Callback URL exceeds maximum safe length (2048).";
                return false;
            }

            if (!trimmed.StartsWith("claude://", StringComparison.OrdinalIgnoreCase)) {
                error = "Only claude:// protocol callbacks are permitted (rejected non-claude scheme).";
                return false;
            }

            for (int i = 0; i < trimmed.Length; i++) {
                char c = trimmed[i];
                if (char.IsControl(c) || c == '"' || c == '\'' || c == '`' || c == '<' || c == '>' || c == '|' || c == '^' || c == ' ') {
                    error = "Callback URL contains forbidden control, whitespace, or shell quote characters.";
                    return false;
                }
            }

            Uri parsed;
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out parsed) ||
                !string.Equals(parsed.Scheme, "claude", StringComparison.OrdinalIgnoreCase)) {
                error = "Malformed claude:// URI syntax.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(parsed.Host)) {
                error = "Callback URL must specify a non-empty claude:// host action.";
                return false;
            }

            normalizedUrl = trimmed;
            return true;
        }

        // Redacts sensitive OAuth query parameter values (code, state, token, verifier, etc.) for audit logs.
        public static string BuildRedactedPreview(string validClaudeUrl) {
            if (string.IsNullOrEmpty(validClaudeUrl)) return "(empty)";
            int q = validClaudeUrl.IndexOf('?');
            if (q < 0) return validClaudeUrl;

            string basePart = validClaudeUrl.Substring(0, q);
            string query = validClaudeUrl.Substring(q + 1);
            string[] pairs = query.Split('&');
            var sb = new StringBuilder(basePart);
            sb.Append('?');
            for (int i = 0; i < pairs.Length; i++) {
                if (i > 0) sb.Append('&');
                string kv = pairs[i];
                int eq = kv.IndexOf('=');
                if (eq <= 0) {
                    sb.Append(kv);
                    continue;
                }
                string key = kv.Substring(0, eq);
                sb.Append(key);
                sb.Append("=[REDACTED]");
            }
            return sb.ToString();
        }
    }
}
