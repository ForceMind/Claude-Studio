using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

public sealed partial class StudioLabWfp
{
    static T ReadFixtureToken<T>(IntPtr token, int field, int minimum, Func<IntPtr,T> read)
    {
        int required;
        if (GetTokenInformation(token, field, IntPtr.Zero, 0, out required) ||
            Marshal.GetLastWin32Error() != 122 || required < minimum || required > 65536)
            throw new IOException("Unexpected token field length: " + field);
        IntPtr data = Marshal.AllocHGlobal(required);
        try {
            int readSize;
            if (!GetTokenInformation(token, field, data, required, out readSize))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not read token field " + field);
            if (readSize < minimum || readSize > required) throw new IOException("Invalid token output size");
            return read(data);
        } finally { Marshal.FreeHGlobal(data); }
    }

    public static string ReadLivePsecBindIdentity(Process process, long ticks, int session, string image, string sid)
    {
        if (process.HasExited || process.StartTime.ToUniversalTime().Ticks != ticks || process.SessionId != session ||
            !String.Equals(process.MainModule.FileName,image,StringComparison.OrdinalIgnoreCase))
            throw new IOException("The selected process identity has changed");
        IntPtr token;
        if (!OpenProcessToken(process.Handle, 8, out token)) throw new Win32Exception();
        try {
            string user = ReadFixtureToken(token, 1, IntPtr.Size, p => new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
            bool inContainer = ReadFixtureToken(token, 29, 4, p => Marshal.ReadInt32(p) != 0);
            if (sid != user || !inContainer) throw new IOException("Expected the exact A token in an AppContainer");
            ReadFixtureToken(token, 2, IntPtr.Size, p => {
                int count = Marshal.ReadInt32(p);
                if (count < 1 || count > 1024) throw new IOException("Invalid token group count");
                for (int i = 0; i < count; i++) {
                    string group = new SecurityIdentifier(Marshal.ReadIntPtr(p,IntPtr.Size+i*2*IntPtr.Size)).Value;
                    if (group == "S-1-5-32-544") throw new IOException("A must have a standard user token");
                }
                return true;
            });
            string package = ReadFixtureToken(token, 31, IntPtr.Size, p => {
                IntPtr value = Marshal.ReadIntPtr(p);
                if (value == IntPtr.Zero) throw new IOException("Synthetic process lacks a container SID");
                return new SecurityIdentifier(value).Value;
            });
            ValidateContainerSid(package);
            VerifyAccountLoopbackCapabilities(token);
            if (process.HasExited) throw new IOException("Process exited during identity readback");
            return package;
        } finally { CloseHandle(token); }
    }
}
