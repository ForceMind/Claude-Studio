// Production installer, compiled together with windows-authenticode.cs.
// No network, process termination, registry changes, elevation or automatic restart.
// A same-user actor already allowed to rename installation files is outside the
// namespace-concurrency boundary; immutable candidate bytes and IDs remain checked.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

internal static partial class WindowsAuthenticode
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdentity
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        internal string Key { get { return Volume.ToString("X8") + ":" + IndexHigh.ToString("X8") + IndexLow.ToString("X8"); } }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInfo
    {
        internal IntPtr Reserved1, Peb, Reserved2a, Reserved2b, ProcessId, ParentId;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileIdentity info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveType(string root);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, uint kind, ref ProcessBasicInfo info, int length, out int returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind, IntPtr buffer, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string existing, string replacement, uint flags);

    private static long NowMs() { return (DateTime.UtcNow.Ticks - 621355968000000000L) / 10000; }
    private static bool SamePath(string left, string right) { return String.Equals(left, right, StringComparison.OrdinalIgnoreCase); }
    private static void Deadline(long expiry)
    {
        Require(NowMs() < expiry, "INSTALL_EXPIRED");
    }
    private static string LocalPath(string input)
    {
        Require(input != null && input.Length >= 4 && input.Length < 260
            && Regex.IsMatch(input, @"\A[A-Za-z]:\\") && input.IndexOf('/') < 0
            && input.IndexOf(':', 2) < 0 && !Regex.IsMatch(input, @"[\x00-\x1F]"), "UNSAFE_PATH");
        string full = Path.GetFullPath(input);
        Require(SamePath(full, input) && GetDriveType(full.Substring(0, 3)) == 3, "UNSAFE_PATH");
        string[] parts = full.Substring(3).Split('\\');
        foreach (string part in parts)
        {
            Require(part.Length > 0 && part != "." && part != ".." && !part.EndsWith(".") && !part.EndsWith(" ")
                && !Regex.IsMatch(part, @"\A(?:\$Recycle\.Bin|RECYCLER|RECYCLED|CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\z", RegexOptions.IgnoreCase), "UNSAFE_PATH");
        }
        return full;
    }
    private static FileIdentity Identity(SafeFileHandle handle, bool directory)
    {
        FileIdentity info = new FileIdentity();
        Require(!handle.IsInvalid && GetFileInformationByHandle(handle, out info), "FILE_ID_UNAVAILABLE");
        Require((info.Attributes & 0x400) == 0, "REPARSE_PATH");
        Require(((info.Attributes & 0x10) != 0) == directory, "WRONG_FILE_TYPE");
        if (!directory) Require(info.Links == 1, "HARD_LINK_REJECTED");
        return info;
    }
    private static void FinalName(SafeFileHandle handle, string expected)
    {
        var name = new StringBuilder(32768);
        uint size = GetFinalPathNameByHandle(handle, name, (uint)name.Capacity, 0);
        Require(size > 0 && size < name.Capacity, "FILE_ID_UNAVAILABLE");
        string actual = name.ToString();
        if (actual.StartsWith(@"\\?\")) actual = actual.Substring(4);
        Require(SamePath(actual, expected), "PATH_IDENTITY_CHANGED");
    }
    private sealed class DirectoryGuards : IDisposable
    {
        private readonly Dictionary<string, SafeFileHandle> handles = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
        internal void Hold(string path)
        {
            string root = path.Substring(0, 3), cursor = root;
            HoldOne(cursor);
            foreach (string part in path.Substring(3).Split('\\')) { cursor = Path.Combine(cursor, part); HoldOne(cursor); }
        }
        private void HoldOne(string path)
        {
            if (handles.ContainsKey(path)) return;
            // Deny directory deletion/renaming while allowing normal child IO.
            var handle = CreateFile(path, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            try { Identity(handle, true); FinalName(handle, path); handles.Add(path, handle); }
            catch { handle.Dispose(); throw; }
        }
        public void Dispose() { foreach (var handle in handles.Values) handle.Dispose(); }
    }
    private sealed class LockedFile : IDisposable
    {
        internal readonly string Path;
        internal readonly FileStream Stream;
        internal readonly FileIdentity Initial;
        internal LockedFile(string path, bool rename, uint share, bool createLock)
        {
            Path = path;
            uint access = createLock ? 0xc0000000 : (rename ? 0x80010000 : 0x80000000);
            var handle = CreateFile(path, access, share, IntPtr.Zero, createLock ? 4u : 3u, 0x00200000, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error(); handle.Dispose();
                throw new Rejected(createLock && (error == 32 || error == 33) ? "INSTALL_BUSY" : "FILE_OPEN_FAILED");
            }
            try
            {
                Initial = Identity(handle, false); FinalName(handle, path);
                Stream = new FileStream(handle, createLock ? FileAccess.ReadWrite : FileAccess.Read);
            }
            catch { handle.Dispose(); throw; }
        }
        internal string Hash()
        {
            Stream.Position = 0;
            using (var hash = SHA256.Create()) return Hex(hash.ComputeHash(Stream));
        }
        internal void StillAt(string path)
        {
            using (var check = CreateFile(path, 0, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
            {
                var info = Identity(check, false);
                Require(info.Key == Initial.Key, "PATH_IDENTITY_CHANGED"); FinalName(check, path);
            }
        }
        public void Dispose() { Stream.Dispose(); }
    }
    private sealed class PinnedProcess : IDisposable
    {
        internal readonly IntPtr Handle;
        internal readonly uint Id, ParentId;
        internal readonly long Created;
        internal PinnedProcess(uint id, string image)
        {
            Id = id; Handle = OpenProcess(0x00101000, false, id); // SYNCHRONIZE | QUERY_LIMITED_INFORMATION
            Require(Handle != IntPtr.Zero, "PROCESS_UNAVAILABLE");
            try
            {
                Require(WaitForSingleObject(Handle, 0) == 0x102, "PROCESS_ALREADY_EXITED");
                var name = new StringBuilder(32768); uint size = (uint)name.Capacity;
                Require(QueryFullProcessImageName(Handle, 0, name, ref size) && SamePath(LocalPath(name.ToString()), image), "PROCESS_IMAGE_MISMATCH");
                long exited, kernel, user, created;
                Require(GetProcessTimes(Handle, out created, out exited, out kernel, out user), "PROCESS_UNAVAILABLE");
                Created = created;
                var basic = new ProcessBasicInfo(); int returned;
                Require(NtQueryInformationProcess(Handle, 0, ref basic, Marshal.SizeOf(typeof(ProcessBasicInfo)), out returned) == 0
                    && basic.ProcessId.ToInt64() == id, "PROCESS_UNAVAILABLE");
                ParentId = checked((uint)basic.ParentId.ToInt64());
            }
            catch { CloseHandle(Handle); throw; }
        }
        internal bool Exited() { uint state = WaitForSingleObject(Handle, 0); Require(state == 0 || state == 0x102, "PROCESS_UNAVAILABLE"); return state == 0; }
        public void Dispose() { CloseHandle(Handle); }
    }
    private static void VerifyInstallFile(LockedFile file, string version, HashSet<string> pins,
        string edition = null, bool installedApplication = false)
    {
        file.Stream.Position = 0;
        string machine = VerifyArchitecture(file.Stream);
        if (installedApplication) Require(machine == "amd64", "WRONG_ARCHITECTURE");
        VerifyVersion(file.Stream, version, edition, installedApplication);
#if CLAUDE_INSTALL_NATIVE_TEST
        // Included only in a separately compiled, hash-pinned synthetic fixture.
        VerifyInstallTestArtifact(file.Path, file.Stream, version);
#else
        VerifySignature(file.Path, file.Stream, pins);
#endif
    }
    private static void VersionOrder(string current, string candidate)
    {
        Require(Regex.IsMatch(current, @"\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\z")
            && Regex.IsMatch(candidate, @"\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\z"), "INVALID_VERSION");
        var left = new Version(current); var right = new Version(candidate);
        Require(right > left, "DOWNGRADE_REJECTED");
    }
    private static void Line(string value) { try { Console.WriteLine(value); Console.Out.Flush(); } catch (IOException) { } catch (ObjectDisposedException) { } }
    private static string ReadCommit(long expiry)
    {
        // Read char by char with a fixed bound, never unbounded ReadLine input.
        var input = Task.Factory.StartNew<string>(delegate {
            var value = new StringBuilder();
            for (int i = 0; i < 80; i++)
            {
                int ch = Console.In.Read(); if (ch < 0) return null;
                if (ch == '\n') return value.ToString();
                if (ch == '\r') return Console.In.Read() == '\n' ? value.ToString() : "INVALID";
                value.Append((char)ch);
            }
            return "INVALID";
        });
        long limit = Math.Min(expiry, NowMs() + 30000);
        while (!input.IsCompleted) { Require(NowMs() < limit, "COMMIT_TIMEOUT"); Thread.Sleep(20); }
        Deadline(expiry);
        return input.Result;
    }
    private static void WaitForExit(PinnedProcess process, long limit, long expiry)
    {
        while (!process.Exited()) { Require(NowMs() < limit, "PROCESS_EXIT_TIMEOUT"); Thread.Sleep(25); }
        Deadline(expiry);
    }
    private static string RenameExact(LockedFile source, string destination, LockedFile expectedTarget)
    {
        // FILE_RENAME_INFO x64: Flags@0, RootDirectory@8, length@16, name@20.
        // One same-volume namespace operation: never move the old launcher away.
        byte[] name = Encoding.Unicode.GetBytes(destination);
        IntPtr buffer = Marshal.AllocHGlobal(24 + name.Length);
        try
        {
            for (int i = 0; i < 24 + name.Length; i++) Marshal.WriteByte(buffer, i, 0);
            Marshal.WriteInt32(buffer, 0, 3); // REPLACE_IF_EXISTS | POSIX_SEMANTICS
            Marshal.WriteInt32(buffer, 16, name.Length); Marshal.Copy(name, 0, IntPtr.Add(buffer, 20), name.Length);
            source.StillAt(source.Path); expectedTarget.StillAt(destination);
            if (SetFileInformationByHandle(source.Stream.SafeFileHandle, 22, buffer, (uint)(24 + name.Length)))
            {
                try { source.StillAt(destination); return "handle-rename"; }
                catch (Rejected)
                {
                    // A filesystem broker may acknowledge an unsupported operation
                    // without publishing it. Retry only if BOTH original names are
                    // still bound to their original immutable file objects.
                    source.StillAt(source.Path); expectedTarget.StillAt(destination);
                }
            }
                // Older filesystems may reject FileRenameInfoEx. This fallback is
                // still a single same-volume replacement, with both byte streams
                // write-locked and both names rechecked immediately before it.
                // As documented above, same-user malicious namespace writers are
                // outside this guarantee; no claim of namespace CAS is made.
                source.StillAt(source.Path); expectedTarget.StillAt(destination);
                Require(MoveFileEx(source.Path, destination, 0x1 | 0x8), "ATOMIC_REPLACE_FAILED");
                return "movefileex";
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private static void CopyBackup(LockedFile current, string path, string expected)
    {
        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            current.Stream.Position = 0; current.Stream.CopyTo(output); output.Flush(true);
        }
        using (var backup = new LockedFile(path, false, 5, false)) Require(backup.Hash() == expected, "BACKUP_HASH_MISMATCH");
    }
    private static bool WriteInstallResult(string job, object result)
    {
        string text = new JavaScriptSerializer().Serialize(result);
        bool persisted = false;
        if (job != null)
        {
            string pending = Path.Combine(job, "result.pending.json"), final = Path.Combine(job, "result.json");
            try
            {
                using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(text); output.Write(bytes, 0, bytes.Length); output.Flush(true);
                }
                File.Move(pending, final);
                persisted = true;
            }
            catch (Exception) { /* Cannot turn a committed installation into success without a result. stdout also reports it. */ }
        }
        Line("RESULT " + text);
        return persisted;
    }
    private static string SetupInstallDirectory()
    {
        // This GUID is the existing NSIS UUIDv5 computed from the Windows app ID.
        using (var user = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64))
        using (var key = user.OpenSubKey(@"Software\00fd1675-490e-51ee-9bc3-830a0cb76a96"))
        {
            string directory = key == null ? null : key.GetValue("InstallLocation") as string;
            Require(!String.IsNullOrEmpty(directory), "CURRENT_USER_INSTALLATION_MISSING");
            return LocalPath(directory.TrimEnd('\\'));
        }
    }

    private static int RunSetupInstall(string[] args)
    {
        string resultJob = null, currentVersion = null, candidateVersion = null;
        string staged = null;
        bool launched = false, setupExited = false;
        try
        {
            Require(Environment.Is64BitProcess && EmbeddedInstallPins.Length > 0, "INSTALL_DISABLED");
            Require(args.Length == 8, "INVALID_ARGUMENTS");
            string job = LocalPath(args[1]), appImage = LocalPath(args[2]);
            string installDir = SetupInstallDirectory();
            string data = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string work = LocalPath(Path.Combine(data, "Claude Browser", "update-install-setup"));
            Require(SamePath(appImage, Path.Combine(installDir, "ClaudeBrowser.exe"))
                && SamePath(Path.GetDirectoryName(job), work)
                && Regex.IsMatch(Path.GetFileName(job), @"\Ajob-[a-f0-9]{16,64}\z"), "UNSAFE_INSTALL_LAYOUT");
            uint appPid = 0; long expiry = 0;
            Require(UInt32.TryParse(args[3], out appPid) && appPid > 0 &&
                Int64.TryParse(args[7], out expiry) && IsPin(args[6]), "INVALID_ARGUMENTS");
            currentVersion = args[4]; candidateVersion = args[5]; VersionOrder(currentVersion, candidateVersion);
            string expectedHash = args[6].ToLowerInvariant();
            Deadline(expiry); Require(expiry <= NowMs() + 600000, "INVALID_EXPIRY");

            using (var guards = new DirectoryGuards())
            {
                guards.Hold(job);
                string helper = LocalPath(Process.GetCurrentProcess().MainModule.FileName);
                Require(SamePath(helper, Path.Combine(job, "windows-authenticode.exe")), "HELPER_LOCATION_MISMATCH");
                Require(!File.Exists(Path.Combine(job, "result.json")) && !File.Exists(Path.Combine(job, "result.pending.json")), "STALE_JOB");
                using (var installLock = new LockedFile(Path.Combine(work, "install.lock"), false, 0, true))
                using (var caller = new PinnedProcess(appPid, appImage))
                using (var self = new PinnedProcess((uint)Process.GetCurrentProcess().Id, helper))
                using (var helperImage = new LockedFile(helper, false, 5, false))
                using (var candidate = new LockedFile(Path.Combine(job, "candidate.exe"), false, 1, false))
                {
                    resultJob = job;
                    staged = candidate.Path;
                    Require(self.ParentId == appPid && caller.Created <= self.Created, "CALLER_PROCESS_MISMATCH");
                    var pins = new HashSet<string>(EmbeddedInstallPins.Split(','), StringComparer.OrdinalIgnoreCase);
                    foreach (string pin in pins) Require(IsPin(pin), "INSTALL_DISABLED");
                    VerifySignature(helper, helperImage.Stream, pins);
                    VerifyInstallFile(candidate, candidateVersion, pins, "setup");
                    Require(candidate.Hash() == expectedHash, "CANDIDATE_HASH_MISMATCH");
                    using (var installedGuards = new DirectoryGuards())
                    {
                        installedGuards.Hold(installDir);
                        using (var current = new LockedFile(appImage, false, 5, false))
                        {
                            VerifyInstallFile(current, currentVersion, pins, installedApplication: true);
                            string beforeHash = current.Hash(), nonce;
                            using (var random = RandomNumberGenerator.Create())
                            { byte[] bytes = new byte[32]; random.GetBytes(bytes); nonce = Hex(bytes); }
                            Deadline(expiry); Require(!caller.Exited(), "PROCESS_ALREADY_EXITED");
                            Line("READY " + nonce);
                            Require(ReadCommit(expiry) == "COMMIT " + nonce, "COMMIT_REJECTED");
                            current.StillAt(appImage); candidate.StillAt(staged);
                            Require(current.Hash() == beforeHash && candidate.Hash() == expectedHash, "FILE_CONTENT_CHANGED");
                            Line("COMMITTED " + nonce);
                            WaitForExit(caller, Math.Min(expiry, NowMs() + 60000), expiry);
                            current.StillAt(appImage);
                            Require(current.Hash() == beforeHash, "FILE_CONTENT_CHANGED");
                        }
                    }
                    // NSIS must be able to replace its own installed files. Keep
                    // the independently signed installer immutable until it exits.
                    Require(SamePath(SetupInstallDirectory(), installDir), "INSTALL_DIRECTORY_CHANGED");
                    candidate.StillAt(staged);
                    Require(candidate.Hash() == expectedHash, "FILE_CONTENT_CHANGED");
                    Deadline(expiry);
                    var options = new ProcessStartInfo(staged, "/S --updated /currentuser") {
                        UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = job
                    };
                    using (var setup = Process.Start(options))
                    {
                        Require(setup != null, "SETUP_LAUNCH_FAILED");
                        launched = true;
                        setupExited = setup.WaitForExit(15 * 60 * 1000);
                        Require(setupExited, "SETUP_TIMEOUT");
                        Require(setup.ExitCode == 0, "SETUP_FAILED");
                    }
                    Require(SamePath(SetupInstallDirectory(), installDir), "INSTALL_DIRECTORY_CHANGED");
                    using (var installed = new LockedFile(appImage, false, 1, false))
                    {
                        VerifyInstallFile(installed, candidateVersion, pins, installedApplication: true);
                        installed.StillAt(appImage);
                        Require(WriteInstallResult(resultJob, new { schema = 1, status = "installed", code = "INSTALLED",
                            currentVersion = currentVersion, candidateVersion = candidateVersion, completedAt = NowMs() }), "RESULT_WRITE_FAILED");
                        try
                        {
                            using (var reopened = Process.Start(new ProcessStartInfo(appImage) {
                                UseShellExecute = false, WorkingDirectory = installDir })) { }
                        }
                        catch (Exception) { /* Successful upgrade can also be opened from the existing shortcut. */ }
                    }
                }
            }
            return 0;
        }
        catch (Exception failure)
        {
            string code = failure is Rejected ? ((Rejected)failure).Code : "INSTALL_UNAVAILABLE";
            WriteInstallResult(resultJob, new { schema = 1, status = launched ? "recovery-required" : "failed", code = code,
                currentVersion = currentVersion, candidateVersion = candidateVersion, completedAt = NowMs() });
            return 1;
        }
        finally
        {
            if (staged != null && (!launched || setupExited))
            {
                try { File.Delete(staged); } catch (Exception) { }
            }
        }
    }

    private static int RunInstall(string[] args)
    {
        string resultJob = null, currentVersion = null, candidateVersion = null;
        bool changed = false, recovered = false;
        var guards = new DirectoryGuards();
        var innerGuards = new DirectoryGuards();
        LockedFile installLock = null, current = null, candidate = null, inner = null, backup = null, helperImage = null;
        PinnedProcess caller = null, launcherProcess = null, self = null;
        string launcher = null, beforeHash = null, replaceMethod = null;
        try
        {
            Require(Environment.Is64BitProcess && EmbeddedInstallPins.Length > 0, "INSTALL_DISABLED");
            Require(args.Length == 10, "INVALID_ARGUMENTS");
            string job = LocalPath(args[1]); launcher = LocalPath(args[2]); string innerImage = LocalPath(args[3]);
            string installDir = Path.GetDirectoryName(launcher), work = Path.Combine(installDir, ".browser-local", "update-install");
            Require(SamePath(Path.GetFileName(launcher), "ClaudeBrowser.exe") && SamePath(Path.GetFileName(innerImage), "ClaudeBrowser.exe")
                && !SamePath(launcher, innerImage) && SamePath(Path.GetDirectoryName(job), work)
                && Regex.IsMatch(Path.GetFileName(job), @"\Ajob-[a-f0-9]{16,64}\z"), "UNSAFE_INSTALL_LAYOUT");
            uint appPid = 0, launcherPid = 0; long expiry = 0;
            Require(UInt32.TryParse(args[4], out appPid) && appPid > 0 && UInt32.TryParse(args[5], out launcherPid)
                && launcherPid > 0 && appPid != launcherPid && Int64.TryParse(args[9], out expiry), "INVALID_ARGUMENTS");
            currentVersion = args[6]; candidateVersion = args[7]; VersionOrder(currentVersion, candidateVersion);
            Require(IsPin(args[8]), "INVALID_ARGUMENTS"); string expectedHash = args[8].ToLowerInvariant();
            Deadline(expiry); Require(expiry <= NowMs() + 600000, "INVALID_EXPIRY");
            guards.Hold(job); innerGuards.Hold(Path.GetDirectoryName(innerImage));
            string helper = LocalPath(Process.GetCurrentProcess().MainModule.FileName);
            Require(SamePath(helper, Path.Combine(job, "windows-authenticode.exe")), "HELPER_LOCATION_MISMATCH");
            Require(!File.Exists(Path.Combine(job, "result.json")) && !File.Exists(Path.Combine(job, "result.pending.json"))
                && !File.Exists(Path.Combine(job, "previous.exe")), "STALE_JOB");
            installLock = new LockedFile(Path.Combine(work, "install.lock"), false, 0, true);
            resultJob = job;
            var pins = new HashSet<string>(EmbeddedInstallPins.Split(','), StringComparer.OrdinalIgnoreCase);
            foreach (string pin in pins) Require(IsPin(pin), "INSTALL_DISABLED");
#if !CLAUDE_INSTALL_NATIVE_TEST
            helperImage = new LockedFile(helper, false, 5, false);
            VerifySignature(helper, helperImage.Stream, pins);
#endif
            caller = new PinnedProcess(appPid, innerImage); launcherProcess = new PinnedProcess(launcherPid, launcher);
            self = new PinnedProcess((uint)Process.GetCurrentProcess().Id, helper);
            Require(self.ParentId == appPid && caller.ParentId == launcherPid && launcherProcess.Created <= caller.Created
                && caller.Created <= self.Created, "CALLER_PROCESS_MISMATCH");
            current = new LockedFile(launcher, false, 5, false); inner = new LockedFile(innerImage, false, 5, false);
            candidate = new LockedFile(Path.Combine(job, "candidate.exe"), true, 5, false);
            Require(current.Initial.Volume == candidate.Initial.Volume, "CROSS_VOLUME_REJECTED");
            Require(current.Initial.Key != candidate.Initial.Key && current.Initial.Key != inner.Initial.Key, "FILE_IDENTITY_COLLISION");
            VerifyInstallFile(current, currentVersion, pins); VerifyInstallFile(inner, currentVersion, pins, installedApplication: true);
            VerifyInstallFile(candidate, candidateVersion, pins, "");
            beforeHash = current.Hash(); Require(candidate.Hash() == expectedHash, "CANDIDATE_HASH_MISMATCH");
            string nonce;
            using (var random = RandomNumberGenerator.Create()) { byte[] bytes = new byte[32]; random.GetBytes(bytes); nonce = Hex(bytes); }
            Deadline(expiry); Require(!caller.Exited() && !launcherProcess.Exited(), "PROCESS_ALREADY_EXITED");
            Line("READY " + nonce);
            Require(ReadCommit(expiry) == "COMMIT " + nonce, "COMMIT_REJECTED");
            current.StillAt(launcher); candidate.StillAt(candidate.Path);
            Require(candidate.Hash() == expectedHash && current.Hash() == beforeHash, "FILE_CONTENT_CHANGED");
            Line("COMMITTED " + nonce);
            long exitLimit = Math.Min(expiry, NowMs() + 60000);
            WaitForExit(caller, exitLimit, expiry);
            // Keep the extracted app file locked until its exact process has exited.
            inner.Dispose(); inner = null;
            innerGuards.Dispose(); innerGuards = null;
            WaitForExit(launcherProcess, exitLimit, expiry);
            current.StillAt(launcher); candidate.StillAt(candidate.Path);
            Require(current.Hash() == beforeHash && candidate.Hash() == expectedHash, "FILE_CONTENT_CHANGED");
            CopyBackup(current, Path.Combine(job, "previous.exe"), beforeHash);
            backup = new LockedFile(Path.Combine(job, "previous.exe"), true, 5, false);
            Require(backup.Initial.Volume == current.Initial.Volume, "CROSS_VOLUME_REJECTED");
            VerifyInstallFile(backup, currentVersion, pins);
            Require(backup.Hash() == beforeHash, "BACKUP_HASH_MISMATCH");
            Deadline(expiry); current.StillAt(launcher); candidate.StillAt(candidate.Path);
#if CLAUDE_INSTALL_NATIVE_TEST
            InstallTestBeforeReplace(job);
#endif
            // Once the kernel operation starts, even an error during the following
            // identity read is an uncertain commit and must enter recovery checks.
            changed = true;
            replaceMethod = RenameExact(candidate, launcher, current);
#if CLAUDE_INSTALL_NATIVE_TEST
            InstallTestAfterReplace(job);
#endif
            candidate.StillAt(launcher);
            using (var installed = new LockedFile(launcher, false, 5, false))
            {
                Require(installed.Initial.Key == candidate.Initial.Key && installed.Hash() == expectedHash, "POST_REPLACE_MISMATCH");
                VerifyInstallFile(installed, candidateVersion, pins);
            }
            Require(WriteInstallResult(resultJob, new { schema = 1, status = "installed", code = "INSTALLED", currentVersion = currentVersion,
                candidateVersion = candidateVersion, completedAt = NowMs(), backupName = "previous.exe", sha256 = expectedHash,
                replaceMethod = replaceMethod }), "RESULT_WRITE_FAILED");
            return 0;
        }
        catch (Exception failure)
        {
            string code = failure is Rejected ? ((Rejected)failure).Code : "INSTALL_UNAVAILABLE";
            if (changed && backup != null)
            {
                try
                {
                    bool oldStillPresent = false;
                    try { current.StillAt(launcher); oldStillPresent = current.Hash() == beforeHash; } catch (Exception) { }
                    if (!oldStillPresent)
                    {
                        // Restore only while the target is still the exact candidate
                        // we put there; an unknown concurrent file is never replaced.
                        candidate.StillAt(launcher); RenameExact(backup, launcher, candidate); backup.StillAt(launcher);
                        using (var restored = new LockedFile(launcher, false, 5, false))
                            Require(restored.Initial.Key == backup.Initial.Key && restored.Hash() == beforeHash, "RECOVERY_FAILED");
                    }
                    recovered = true;
                }
                catch (Exception) { code = "RECOVERY_REQUIRED"; }
            }
            WriteInstallResult(resultJob, new { schema = 1, status = changed && !recovered ? "recovery-required" : "failed", code = code,
                currentVersion = currentVersion, candidateVersion = candidateVersion, completedAt = NowMs(), recovered = recovered });
            return 1;
        }
        finally
        {
            if (self != null) self.Dispose(); if (caller != null) caller.Dispose(); if (launcherProcess != null) launcherProcess.Dispose();
            if (inner != null) inner.Dispose(); if (backup != null) backup.Dispose(); if (candidate != null) candidate.Dispose();
            if (helperImage != null) helperImage.Dispose();
            if (current != null) current.Dispose(); if (installLock != null) installLock.Dispose();
            if (innerGuards != null) innerGuards.Dispose(); guards.Dispose();
        }
    }
}
