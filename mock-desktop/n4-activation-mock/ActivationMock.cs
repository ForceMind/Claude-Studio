using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

static class ActivationMock
{
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    static extern int GetCurrentPackageFullName(ref int length, StringBuilder name);

    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int length, out int required);

    static string ReadPackageName()
    {
        int length = 0;
        int status = GetCurrentPackageFullName(ref length, null);
        if (status == 15700) return null;
        if (status != 122 || length <= 0) throw new Win32Exception(status);
        var name = new StringBuilder(length);
        status = GetCurrentPackageFullName(ref length, name);
        if (status != 0) throw new Win32Exception(status);
        return name.ToString();
    }

    static string ReadContainerSid(IntPtr token)
    {
        int size;
        if (GetTokenInformation(token, 31, IntPtr.Zero, 0, out size) || Marshal.GetLastWin32Error() != 122 || size < IntPtr.Size)
            throw new InvalidOperationException("Could not size the AppContainer SID field");
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try {
            if (!GetTokenInformation(token, 31, buffer, size, out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr sid = Marshal.ReadIntPtr(buffer);
            return sid == IntPtr.Zero ? null : new SecurityIdentifier(sid).Value;
        } finally { Marshal.FreeHGlobal(buffer); }
    }

    [STAThread]
    static void Main()
    {
        using (var process = Process.GetCurrentProcess())
        using (var identity = WindowsIdentity.GetCurrent()) {
            string role = Path.GetFileNameWithoutExtension(Application.ExecutablePath);
            bool window = role == "StudioActivationWindow";
            string mutexName = "Local\\StudioN4ActivationMock-" + identity.User.Value;
            using (var mutex = window ? new Mutex(false, mutexName) : null) {
                // A second invocation records its own identity before applying the fixture's single-window rule.
                bool warm = window && !WaitForWindowOwnership(mutex);
                string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StudioN4ActivationMock");
                Directory.CreateDirectory(directory);
                var receipt = new { role, pid=process.Id, startedUtc=process.StartTime.ToUniversalTime(), session=process.SessionId,
                    userSid=identity.User.Value, package=ReadPackageName(), containerSid=ReadContainerSid(identity.Token), warm };
                string file = Path.Combine(directory, "activation-" + Guid.NewGuid().ToString("N") + ".json");
                File.WriteAllText(file, new JavaScriptSerializer().Serialize(receipt));
                if (!window || warm) return;
                try {
                    using (var form = new Form { Text="Studio activation simulator", Width=430, Height=130 })
                    using (var label = new Label { Text="Synthetic activation window", Dock=DockStyle.Fill, TextAlign=System.Drawing.ContentAlignment.MiddleCenter }) {
                        form.Controls.Add(label);
                        Application.Run(form);
                    }
                } finally { mutex.ReleaseMutex(); }
            }
        }
    }

    static bool WaitForWindowOwnership(Mutex mutex)
    {
        try { return mutex.WaitOne(0); }
        catch (AbandonedMutexException) { return true; }
    }
}
