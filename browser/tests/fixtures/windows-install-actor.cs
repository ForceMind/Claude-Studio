// Synthetic launcher/app only. It forwards the native handshake, then exits.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
[assembly: AssemblyProduct("Claude Browser")]
[assembly: AssemblyInformationalVersion("SYNTHETIC_VERSION")]
internal static class InstallActor
{
    private static string Args(params string[] args)
    {
        return String.Join(" ", Array.ConvertAll(args, value => "\"" + value.Replace("\"", "\\\"") + "\""));
    }
    private static Process Child(string image, string arguments)
    {
        return Process.Start(new ProcessStartInfo(image, arguments) { UseShellExecute = false,
            CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true });
    }
    private static void Forward(string line) { if (line != null) { Console.WriteLine(line); Console.Out.Flush(); } }
    private static int Main(string[] args)
    {
        if (args.Length == 0) return 17; // The installer must never launch the new EXE.
        if (args[0] == "--launcher")
        {
            // inner, helper, job, sha256, expiry, scenario, current, candidate
            using (var app = Child(args[1], Args("--app", Assembly.GetExecutingAssembly().Location,
                args[2], args[3], args[4], args[5], args[6], Process.GetCurrentProcess().Id.ToString(), args[7], args[8])))
            {
                string first = app.StandardOutput.ReadLine(); Forward(first);
                if (first != null && first.StartsWith("READY "))
                {
                    string commit = Console.ReadLine();
                    if (commit != null) { app.StandardInput.WriteLine(commit); app.StandardInput.Flush(); }
                    else app.StandardInput.Close();
                    Forward(app.StandardOutput.ReadLine());
                }
                app.WaitForExit();
                if (args[6] == "hold-launcher") Thread.Sleep(3000);
                return app.ExitCode;
            }
        }
        if (args[0] == "--app")
        {
            // launcher, helper, job, sha256, expiry, scenario, launcherPid, current, candidate
            using (var helper = Child(args[2], Args("--install", args[3], args[1], Assembly.GetExecutingAssembly().Location,
                Process.GetCurrentProcess().Id.ToString(), args[7], args[8], args[9], args[4], args[5])))
            {
                string first = helper.StandardOutput.ReadLine(); Forward(first);
                if (first == null || !first.StartsWith("READY ")) { helper.WaitForExit(); return helper.ExitCode; }
                string commit = Console.ReadLine();
                if (commit == null) helper.StandardInput.Close();
                else { helper.StandardInput.WriteLine(commit); helper.StandardInput.Flush(); }
                string acknowledgement = helper.StandardOutput.ReadLine(); Forward(acknowledgement);
                if (acknowledgement != null && acknowledgement.StartsWith("COMMITTED "))
                {
                    if (args[6] == "hold-app") Thread.Sleep(3000);
                    // Never wait for helper here; it must observe this process exit.
                    return 0;
                }
                helper.WaitForExit(); return helper.ExitCode;
            }
        }
        return 18;
    }
}
