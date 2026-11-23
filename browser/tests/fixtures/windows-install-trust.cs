// Compiled ONLY by the native synthetic test with CLAUDE_INSTALL_NATIVE_TEST.
// Production compileWindowsVerifier exposes no define/test switch.
using System.IO;
internal static partial class WindowsAuthenticode
{
    private static void VerifyInstallTestArtifact(string path, FileStream stream, string version)
    {
        stream.Position = 0;
        string hash;
        using (var sha = System.Security.Cryptography.SHA256.Create()) hash = Hex(sha.ComputeHash(stream));
        Require(hash == "SYNTHETIC_CURRENT_HASH" || hash == "SYNTHETIC_CANDIDATE_HASH", "SYNTHETIC_TRUST_REJECTED");
    }
    private static void InstallTestBeforeReplace(string job)
    {
        Require(!File.Exists(Path.Combine(job, "fail-before-replace")), "SYNTHETIC_REPLACE_FAILURE");
    }
    private static void InstallTestAfterReplace(string job)
    {
        Require(!File.Exists(Path.Combine(job, "fail-after-replace")), "SYNTHETIC_POST_REPLACE_FAILURE");
    }
}
