using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ClaudeStudio.ControlPlane {
    // Generates human-reviewable, sanitized plain-text HANDOFF.md briefs.
    // Never touches native chat databases, account UUIDs, or OAuth credentials.
    public static class HandoffGenerator {
        static string RunGitReadOnly(string repoDir, string arguments) {
            try {
                var psi = new ProcessStartInfo {
                    FileName = "git.exe",
                    Arguments = "-C \"" + repoDir + "\" " + arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8
                };
                using (var p = Process.Start(psi)) {
                    if (p == null) return "(git unavailable)";
                    string output = p.StandardOutput.ReadToEnd();
                    if (!p.WaitForExit(3500)) {
                        try { p.Kill(); } catch { }
                        return "(git timeout)";
                    }
                    return p.ExitCode == 0 ? output.Trim() : "(not a git repository)";
                }
            } catch {
                return "(git unavailable)";
            }
        }

        public static string BuildSanitizedBrief(string projectDir, SpaceId fromSpace, SpaceId toSpace, string taskSummary, string nextSteps) {
            string repoName = string.IsNullOrWhiteSpace(projectDir) ? "(unspecified)" : Path.GetFileName(projectDir.TrimEnd('\\'));
            string branch = "(n/a)";
            string status = "(n/a)";
            string diffStat = "(n/a)";
            string recent = "(n/a)";

            if (!string.IsNullOrWhiteSpace(projectDir) && Directory.Exists(projectDir)) {
                branch = RunGitReadOnly(projectDir, "branch --show-current");
                if (string.IsNullOrWhiteSpace(branch)) branch = "(detached/initial)";
                status = RunGitReadOnly(projectDir, "status --short");
                if (string.IsNullOrWhiteSpace(status)) status = "(clean working tree)";
                diffStat = RunGitReadOnly(projectDir, "diff --stat");
                if (string.IsNullOrWhiteSpace(diffStat)) diffStat = "(no unstaged diff)";
                recent = RunGitReadOnly(projectDir, "log -n 5 --oneline");
                if (string.IsNullOrWhiteSpace(recent)) recent = "(no commits)";
            }

            var sb = new StringBuilder();
            sb.AppendLine("# Cross-Space Task Handoff Brief");
            sb.AppendLine();
            sb.AppendLine("> **Isolation Notice**: Native chat sessions, OAuth tokens, `.credentials.json`, `.claude.json`, and account/org UUIDs remain physically isolated per OS user space and are NOT migrated.");
            sb.AppendLine();
            sb.AppendLine("- **Generated (UTC)**: `" + DateTime.UtcNow.ToString("o") + "`");
            sb.AppendLine("- **Handoff Direction**: `Space " + fromSpace + "` -> `Space " + toSpace + "`");
            sb.AppendLine("- **Project**: `" + repoName + "`");
            sb.AppendLine("- **Git Branch**: `" + branch + "`");
            sb.AppendLine();
            sb.AppendLine("## Task Summary");
            sb.AppendLine(string.IsNullOrWhiteSpace(taskSummary) ? "(Fill in what was completed before handoff)" : taskSummary.Trim());
            sb.AppendLine();
            sb.AppendLine("## Recommended Next Steps for Space " + toSpace);
            sb.AppendLine(string.IsNullOrWhiteSpace(nextSteps) ? "(Fill in concrete next actions)" : nextSteps.Trim());
            sb.AppendLine();
            sb.AppendLine("## Working Tree Status (`git status --short`)");
            sb.AppendLine("```text");
            sb.AppendLine(status);
            sb.AppendLine("```");
            sb.AppendLine();
            sb.AppendLine("## Diff Summary (`git diff --stat`)");
            sb.AppendLine("```text");
            sb.AppendLine(diffStat);
            sb.AppendLine("```");
            sb.AppendLine();
            sb.AppendLine("## Recent Commits");
            sb.AppendLine("```text");
            sb.AppendLine(recent);
            sb.AppendLine("```");
            return sb.ToString();
        }
    }
}
