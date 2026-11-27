using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ClaudeStudio.ControlPlane {
    // Applies deterministic Windows NTFS single-writer ACLs on an explicitly approved project directory:
    //   - Host + SYSTEM + Administrators: FullControl
    //   - Writer Space OS SID: Modify
    //   - Reader Space OS SID: ReadAndExecute (write attempts fail with OS AccessDenied / error=5)
    //   - ALL APPLICATION PACKAGES (S-1-15-2-1): Modify (actual write permission is intersected with User SID + PSEC!)
    public static class NtfsSingleWriterEnforcer {
        public static string CaptureOriginalSddl(string directoryPath) {
            return Directory.GetAccessControl(directoryPath).GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        }

        public static void ApplySingleWriterAcl(string directoryPath, string hostSid, string writerUserSid, string readerUserSid) {
            if (string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath)) {
                throw new DirectoryNotFoundException("Project directory not found: " + directoryPath);
            }
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (string adminSid in new[] { hostSid, "S-1-5-18", "S-1-5-32-544" }) {
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(adminSid), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }
            if (!string.IsNullOrEmpty(writerUserSid)) {
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(writerUserSid), FileSystemRights.Modify,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }
            if (!string.IsNullOrEmpty(readerUserSid)) {
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(readerUserSid), FileSystemRights.ReadAndExecute,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }
            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier("S-1-15-2-1"), FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

            Directory.SetAccessControl(directoryPath, acl);
            // Reset inheritance on child entries so swapped writer/reader permissions propagate immediately
            foreach (string child in Directory.GetFileSystemEntries(directoryPath, "*", SearchOption.AllDirectories)) {
                try {
                    if (Directory.Exists(child)) {
                        var dSec = Directory.GetAccessControl(child);
                        dSec.SetAccessRuleProtection(false, false);
                        Directory.SetAccessControl(child, dSec);
                    } else if (File.Exists(child)) {
                        var fSec = File.GetAccessControl(child);
                        fSec.SetAccessRuleProtection(false, false);
                        File.SetAccessControl(child, fSec);
                    }
                } catch { }
            }
        }
    }
}
