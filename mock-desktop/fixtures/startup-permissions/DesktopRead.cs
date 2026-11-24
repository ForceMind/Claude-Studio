using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class StudioReadDesktop
{
    const int Name = 2;
    const int ReadControl = 0x20000;
    [DllImport("user32.dll", SetLastError=true)] static extern IntPtr GetProcessWindowStation();
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", SetLastError=true)] static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool GetUserObjectInformationW(IntPtr obj,int index,StringBuilder value,uint bytes,out uint needed);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenWindowStationW(string name,bool inherit,int access);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenDesktopW(string name,uint flags,bool inherit,int access);
    [DllImport("user32.dll", SetLastError=true)] static extern bool CloseWindowStation(IntPtr value);
    [DllImport("user32.dll", SetLastError=true)] static extern bool CloseDesktop(IntPtr value);
    [DllImport("user32.dll", SetLastError=true)] static extern bool GetUserObjectSecurity(IntPtr obj,ref uint fields,byte[] result,uint size,out uint needed);

    static string ObjectName(IntPtr handle)
    {
        if (handle == IntPtr.Zero) throw new Win32Exception();
        var text = new StringBuilder(256);
        uint required;
        if (!GetUserObjectInformationW(handle,Name,text,512,out required)) throw new Win32Exception();
        return text.ToString();
    }

    static string DescriptorDigest(IntPtr handle)
    {
        if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(),"missing security query handle");
        uint fields = 7, size;
        bool sized = GetUserObjectSecurity(handle,ref fields,null,0,out size);
        int error = Marshal.GetLastWin32Error();
        if ((!sized && error != 122) || size < 20 || size > 65536)
            throw new Win32Exception(error, "GetUserObjectSecurity sizing bytes=" + size + " succeeded=" + sized);
        var bytes = new byte[size];
        if (!GetUserObjectSecurity(handle,ref fields,bytes,(uint)bytes.Length,out size)) throw new Win32Exception();
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes,0,(int)size)).Replace("-","");
    }

    public static object Read()
    {
        IntPtr w = GetProcessWindowStation();
        IntPtr d = GetThreadDesktop(GetCurrentThreadId());
        return new { station = ObjectName(w), desktop = ObjectName(d),
            stationOwnerGroupDacl = DescriptorDigest(w), desktopOwnerGroupDacl = DescriptorDigest(d) };
    }
}