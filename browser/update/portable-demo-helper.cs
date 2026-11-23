using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

internal static class PortableDemoHelper
{
    private const string TargetName = "ClaudeBrowser-UpdateDemo.exe";
    private const string StageName = "candidate.pending";
    private const string BackupName = "previous.exe";
    private const int MoveReplaceExisting = 0x1;
    private const int MoveWriteThrough = 0x8;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string source, string destination, int flags);

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length != 4 || !IsHash(args[1]) || !IsHash(args[2]))
                throw new ArgumentException("Invalid demo update arguments.");
            string root = Path.GetFullPath(args[0]);
            if (!Regex.IsMatch(Path.GetFileName(root), @"^claude-update-demo-[A-Za-z0-9_-]+$"))
                throw new ArgumentException("The target must be an isolated update demo directory.");
            ValidatePath(root);
            string lockFile = Path.Combine(root, "update.lock");
            ValidatePath(lockFile);
            using (new FileStream(lockFile, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                Apply(root, args[1], args[2], Int32.Parse(args[3]));
            }
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static void Apply(string root, string previousHash, string nextHash, int pid)
    {
        string target = Path.Combine(root, TargetName);
        string stage = Path.Combine(root, StageName);
        string backup = Path.Combine(root, BackupName);
        ValidatePath(target);
        ValidatePath(stage);
        ValidatePath(backup);

        // Recover a replacement that stopped after the original was moved to the backup.
        if (!File.Exists(target) && File.Exists(backup))
        {
            if (Hash(backup) != previousHash) throw new IOException("Unexpected backup; recovery stopped.");
            File.Move(backup, target);
        }

        if (Hash(target) != previousHash) throw new IOException("The current demo has changed.");
        if (Hash(stage) != nextHash) throw new IOException("The staged demo hash is invalid.");
        WaitForTarget(target, pid);
        ValidatePath(target);
        ValidatePath(stage);
        ValidatePath(backup);
        if (Hash(target) != previousHash) throw new IOException("The current demo changed while waiting.");

        using (var staged = new FileStream(stage, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        {
            if (Hash(staged) != nextHash) throw new IOException("The staged demo changed while waiting.");
            SaveBackup(target, backup, previousHash);
            try
            {
                // Same-directory rename requires delete sharing but can keep staged bytes open and deny writers.
                if (!MoveFileEx(stage, target, MoveReplaceExisting | MoveWriteThrough))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (Hash(target) != nextHash) throw new IOException("The installed demo hash is invalid.");
            }
            catch
            {
                if (File.Exists(backup) && Hash(backup) == previousHash)
                {
                    if (!File.Exists(target)) File.Move(backup, target);
                    else if (Hash(target) != previousHash) File.Replace(backup, target, null, false);
                }
                throw;
            }
        }
    }

    private static void SaveBackup(string target, string backup, string previousHash)
    {
        if (!File.Exists(backup))
        {
            string pending = backup + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var source = File.OpenRead(target))
                using (var copy = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    source.CopyTo(copy);
                    copy.Flush(true);
                }
                if (Hash(pending) != previousHash) throw new IOException("The current demo changed while backing up.");
                File.Move(pending, backup);
            }
            finally { File.Delete(pending); }
        }
        if (Hash(backup) != previousHash) throw new IOException("Unexpected backup; replacement stopped.");
    }

    private static void WaitForTarget(string target, int pid)
    {
        if (pid == 0) return;
        Process process;
        try { process = Process.GetProcessById(pid); }
        catch (ArgumentException) { return; }
        using (process)
        {
            if (process.HasExited) return;
            if (!String.Equals(process.MainModule.FileName, target, StringComparison.OrdinalIgnoreCase))
                throw new IOException("The running process is not the demo being updated.");
            if (!process.WaitForExit(15000)) throw new IOException("The demo is still running.");
        }
    }

    private static bool IsHash(string value)
    {
        return Regex.IsMatch(value, @"\A[a-f0-9]{64}\z");
    }

    private static string Hash(string file)
    {
        using (var stream = File.OpenRead(file)) return Hash(stream);
    }

    private static string Hash(Stream stream)
    {
        using (var sha256 = SHA256.Create())
            return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    private static void ValidatePath(string file)
    {
        for (string current = file; current != null; current = Path.GetDirectoryName(current))
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("The demo update refuses reparse points.");
            }
            catch (FileNotFoundException) {}
        }
    }
}
