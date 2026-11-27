using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ClaudeStudio.ControlPlane {
    // Enforces Layer-0 architectural invariants:
    //  1. Single-Writer lease per canonicalized project path (resolving Junctions & symlinks via Win32 kernel).
    //  2. Controlled writer handoff requires the previous writer space to be stopped/released first.
    //  3. Static template sync is opt-in (default OFF) and hard-blocks all identity/session artifacts.
    public sealed class ProjectLeaseManager {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(IntPtr hFile, StringBuilder path, uint cch, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);

        static readonly IntPtr InvalidHandle = new IntPtr(-1);
        const uint FileFlagBackupSemantics = 0x02000000;

        // Hard denylist preventing ClaudeDock-style cross-account session / credential contamination.
        static readonly string[] ForbiddenIdentitySegments = {
            ".credentials.json",
            ".claude.json",
            "claude-code-sessions",
            "local-agent-mode-sessions",
            "file-history",
            "projects",
            "plans",
            "todos",
            "tasks",
            "cookies",
            "local storage",
            "session storage",
            "keychain",
            "login data"
        };

        readonly object gate = new object();
        readonly Dictionary<string, ProjectMountRecord> projects = new Dictionary<string, ProjectMountRecord>(StringComparer.OrdinalIgnoreCase);

        public static string CanonicalizeDirectoryPath(string rawPath) {
            if (string.IsNullOrWhiteSpace(rawPath)) throw new ArgumentException("Project path cannot be empty");
            string full = Path.GetFullPath(rawPath).TrimEnd('\\');
            if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Directory does not exist: " + full);

            IntPtr h = CreateFileW(full, 0, 7 /* R|W|D */, IntPtr.Zero, 3 /* OPEN_EXISTING */, FileFlagBackupSemantics, IntPtr.Zero);
            if (h == InvalidHandle) return full.ToLowerInvariant();
            try {
                var sb = new StringBuilder(1024);
                uint len = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0 /* FILE_NAME_NORMALIZED */);
                if (len == 0 || len >= sb.Capacity) return full.ToLowerInvariant();
                string resolved = sb.ToString();
                if (resolved.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) {
                    resolved = @"\\" + resolved.Substring(8);
                } else if (resolved.StartsWith(@"\\?\", StringComparison.Ordinal)) {
                    resolved = resolved.Substring(4);
                }
                return resolved.TrimEnd('\\').ToLowerInvariant();
            } finally {
                CloseHandle(h);
            }
        }

        public ProjectMountRecord RegisterProject(string rawPath, string displayName = null) {
            string canon = CanonicalizeDirectoryPath(rawPath);
            lock (gate) {
                ProjectMountRecord existing;
                if (projects.TryGetValue(canon, out existing)) return Clone(existing);
                var rec = new ProjectMountRecord {
                    DisplayName = string.IsNullOrWhiteSpace(displayName) ? Path.GetFileName(canon) : displayName.Trim(),
                    CanonicalPath = canon,
                    WriterSpace = SpaceId.None,
                    SpaceAReadOnly = false,
                    SpaceBReadOnly = false,
                    LastUpdatedUtc = DateTime.UtcNow.ToString("o")
                };
                projects[canon] = rec;
                return Clone(rec);
            }
        }

        public List<ProjectMountRecord> ListProjects() {
            lock (gate) {
                var list = new List<ProjectMountRecord>(projects.Count);
                foreach (var kv in projects) list.Add(Clone(kv.Value));
                return list;
            }
        }

        public LeaseOperationResult RequestMount(SpaceId space, string candidatePath, ProjectAccessMode mode) {
            if (space != SpaceId.A && space != SpaceId.B) {
                return new LeaseOperationResult { Ok = false, Code = "INVALID_SPACE", Message = "Space must be A or B" };
            }
            string canon;
            try { canon = CanonicalizeDirectoryPath(candidatePath); }
            catch (Exception ex) {
                return new LeaseOperationResult { Ok = false, Code = "INVALID_PATH", Message = ex.Message };
            }

            lock (gate) {
                ProjectMountRecord rec;
                if (!projects.TryGetValue(canon, out rec)) {
                    rec = new ProjectMountRecord {
                        DisplayName = Path.GetFileName(canon),
                        CanonicalPath = canon,
                        WriterSpace = SpaceId.None
                    };
                    projects[canon] = rec;
                }

                if (mode == ProjectAccessMode.ReadWrite) {
                    if (rec.WriterSpace != SpaceId.None && rec.WriterSpace != space) {
                        return new LeaseOperationResult {
                            Ok = false,
                            Code = "WRITE_CONFLICT",
                            Message = string.Format("Write conflict: Space {0} already holds single-writer lease on canonical path {1}", rec.WriterSpace, canon),
                            CanonicalPath = canon,
                            Holder = rec.WriterSpace
                        };
                    }
                    rec.WriterSpace = space;
                    if (space == SpaceId.A) rec.SpaceAReadOnly = false;
                    else rec.SpaceBReadOnly = false;
                    rec.LastUpdatedUtc = DateTime.UtcNow.ToString("o");
                    return new LeaseOperationResult {
                        Ok = true, Code = "OK", Message = "Single-writer R/W lease granted to Space " + space,
                        CanonicalPath = canon, Holder = space
                    };
                }

                if (mode == ProjectAccessMode.ReadOnly) {
                    if (rec.WriterSpace == space) rec.WriterSpace = SpaceId.None;
                    if (space == SpaceId.A) rec.SpaceAReadOnly = true;
                    else rec.SpaceBReadOnly = true;
                    rec.LastUpdatedUtc = DateTime.UtcNow.ToString("o");
                    return new LeaseOperationResult {
                        Ok = true, Code = "OK", Message = "Read-only R/O mount granted to Space " + space,
                        CanonicalPath = canon, Holder = rec.WriterSpace
                    };
                }

                // Denied / Unmount
                if (rec.WriterSpace == space) rec.WriterSpace = SpaceId.None;
                if (space == SpaceId.A) rec.SpaceAReadOnly = false;
                else rec.SpaceBReadOnly = false;
                rec.LastUpdatedUtc = DateTime.UtcNow.ToString("o");
                return new LeaseOperationResult {
                    Ok = true, Code = "OK", Message = "Project unmounted from Space " + space,
                    CanonicalPath = canon, Holder = rec.WriterSpace
                };
            }
        }

        public LeaseOperationResult ControlledHandoffWriter(string candidatePath, SpaceId targetSpace, Func<SpaceId, bool> isSpaceStopped) {
            if (targetSpace != SpaceId.A && targetSpace != SpaceId.B) {
                return new LeaseOperationResult { Ok = false, Code = "INVALID_SPACE", Message = "Target space must be A or B" };
            }
            string canon;
            try { canon = CanonicalizeDirectoryPath(candidatePath); }
            catch (Exception ex) {
                return new LeaseOperationResult { Ok = false, Code = "INVALID_PATH", Message = ex.Message };
            }

            lock (gate) {
                ProjectMountRecord rec;
                if (!projects.TryGetValue(canon, out rec)) {
                    return new LeaseOperationResult { Ok = false, Code = "NOT_REGISTERED", Message = "Project not registered", CanonicalPath = canon };
                }
                SpaceId prev = rec.WriterSpace;
                if (prev != SpaceId.None && prev != targetSpace) {
                    if (isSpaceStopped != null && !isSpaceStopped(prev)) {
                        return new LeaseOperationResult {
                            Ok = false,
                            Code = "WRITER_STILL_RUNNING",
                            Message = string.Format("Cannot hand off write lease: stop Space {0} first to release handles cleanly.", prev),
                            CanonicalPath = canon,
                            Holder = prev
                        };
                    }
                    // Demote previous writer to R/O and grant targetSpace R/W
                    if (prev == SpaceId.A) rec.SpaceAReadOnly = true;
                    else rec.SpaceBReadOnly = true;
                }
                rec.WriterSpace = targetSpace;
                if (targetSpace == SpaceId.A) rec.SpaceAReadOnly = false;
                else rec.SpaceBReadOnly = false;
                rec.LastUpdatedUtc = DateTime.UtcNow.ToString("o");
                return new LeaseOperationResult {
                    Ok = true,
                    Code = "OK",
                    Message = string.Format("Controlled writer handoff complete: Space {0} -> Space {1}", prev, targetSpace),
                    CanonicalPath = canon,
                    Holder = targetSpace
                };
            }
        }

        public static bool IsForbiddenIdentityPath(string path) {
            if (string.IsNullOrWhiteSpace(path)) return true;
            string norm = path.Replace('/', '\\').ToLowerInvariant();
            string[] parts = norm.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string part in parts) {
                foreach (string bad in ForbiddenIdentitySegments) {
                    if (part == bad || part.Contains(bad)) return true;
                }
            }
            return false;
        }

        public static TemplateSyncResult SyncReadOnlyStaticTemplate(string sourceFile, string targetDirectory, bool userExplicitlyOptedIn) {
            if (!userExplicitlyOptedIn) {
                return new TemplateSyncResult {
                    Ok = false,
                    Code = "OPT_IN_REQUIRED",
                    Message = "Static template sync is disabled by default; explicit opt-in is required."
                };
            }
            if (string.IsNullOrWhiteSpace(sourceFile) || !File.Exists(sourceFile)) {
                return new TemplateSyncResult { Ok = false, Code = "SOURCE_MISSING", Message = "Template source file does not exist." };
            }
            if (IsForbiddenIdentityPath(sourceFile)) {
                return new TemplateSyncResult {
                    Ok = false,
                    Code = "FORBIDDEN_IDENTITY_ARTIFACT",
                    Message = "Blocked: identity/session/credential files can NEVER be synced across spaces."
                };
            }
            string fileName = Path.GetFileName(sourceFile);
            if (IsForbiddenIdentityPath(fileName)) {
                return new TemplateSyncResult {
                    Ok = false,
                    Code = "FORBIDDEN_IDENTITY_ARTIFACT",
                    Message = "Blocked: forbidden filename."
                };
            }
            Directory.CreateDirectory(targetDirectory);
            string dest = Path.Combine(targetDirectory, fileName);
            if (File.Exists(dest)) {
                File.SetAttributes(dest, FileAttributes.Normal);
            }
            byte[] data = File.ReadAllBytes(sourceFile);
            File.WriteAllBytes(dest, data);
            File.SetAttributes(dest, FileAttributes.ReadOnly);
            string hash12;
            using (var sha = SHA256.Create()) {
                hash12 = BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").Substring(0, 12);
            }
            return new TemplateSyncResult {
                Ok = true,
                Code = "OK",
                Message = "Synced read-only static template " + fileName,
                SourceSha256Prefix12 = hash12
            };
        }

        static ProjectMountRecord Clone(ProjectMountRecord r) {
            return new ProjectMountRecord {
                DisplayName = r.DisplayName,
                CanonicalPath = r.CanonicalPath,
                WriterSpace = r.WriterSpace,
                SpaceAReadOnly = r.SpaceAReadOnly,
                SpaceBReadOnly = r.SpaceBReadOnly,
                LastUpdatedUtc = r.LastUpdatedUtc
            };
        }
    }
}
