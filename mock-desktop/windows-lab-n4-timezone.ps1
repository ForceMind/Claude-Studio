[CmdletBinding()]
param([switch]$ReadChild)
$ErrorActionPreference = 'Stop'
$winter = [DateTimeOffset]::Parse('2026-01-15T12:00:00Z')
$summer = [DateTimeOffset]::Parse('2026-07-15T12:00:00Z')

if ($ReadChild) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class StudioTimeZoneReadings {
    [StructLayout(LayoutKind.Sequential)]
    struct SystemTime {
        public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Tm {
        public int Second, Minute, Hour, Day, Month, Year, WeekDay, YearDay, IsDst;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SystemTimeToTzSpecificLocalTimeEx(IntPtr zone, ref SystemTime utc, out SystemTime local);
    [DllImport("ucrtbase.dll", CallingConvention=CallingConvention.Cdecl)]
    static extern void _tzset();
    [DllImport("ucrtbase.dll", CallingConvention=CallingConvention.Cdecl)]
    static extern int _localtime64_s(out Tm local, ref long seconds);

    public static int Win32Offset(DateTimeOffset value) {
        DateTime stamp = value.UtcDateTime;
        var utc = new SystemTime { Year=(ushort)stamp.Year, Month=(ushort)stamp.Month, Day=(ushort)stamp.Day,
            Hour=(ushort)stamp.Hour, Minute=(ushort)stamp.Minute, Second=(ushort)stamp.Second };
        SystemTime local;
        if (!SystemTimeToTzSpecificLocalTimeEx(IntPtr.Zero, ref utc, out local))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return (int)(new DateTime(local.Year, local.Month, local.Day, local.Hour, local.Minute, local.Second) - stamp).TotalMinutes;
    }

    public static int CrtOffset(DateTimeOffset value) {
        long seconds = value.ToUnixTimeSeconds();
        Tm local;
        _tzset();
        int error = _localtime64_s(out local, ref seconds);
        if (error != 0) throw new InvalidOperationException("_localtime64_s: " + error);
        var wall = new DateTime(local.Year + 1900, local.Month + 1, local.Day, local.Hour, local.Minute, local.Second);
        return (int)(wall - value.UtcDateTime).TotalMinutes;
    }
}
'@
    [ordered]@{ pid = $PID; tz = [Environment]::GetEnvironmentVariable('TZ');
        dotNetLocal = [TimeZoneInfo]::Local.Id;
        dotNetMinutes = @($winter,$summer | ForEach-Object { [int][TimeZoneInfo]::Local.GetUtcOffset($_).TotalMinutes });
        win32Minutes = @($winter,$summer | ForEach-Object { [StudioTimeZoneReadings]::Win32Offset($_) });
        ucrtMinutes = @($winter,$summer | ForEach-Object { [StudioTimeZoneReadings]::CrtOffset($_) }) } | ConvertTo-Json -Compress
    return
}

function Read-ProcessJson([string]$Executable, [string[]]$Arguments, [string]$Zone) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($Zone) { $start.Environment['TZ'] = $Zone }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit(10000)) {
            $process.Kill()
            throw 'Synthetic preference probe timed out'
        }
        if ($process.ExitCode -ne 0) { throw ('Synthetic preference probe failed: ' + $stderr.GetAwaiter().GetResult()) }
        $output.GetAwaiter().GetResult() | ConvertFrom-Json
    } finally { $process.Dispose() }
}

if ($PSVersionTable.PSEdition -ne 'Core') { throw 'Use PowerShell 7 for this read-only parent probe' }
$desktop = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$node = (Get-Command node.exe -CommandType Application | Select-Object -First 1).Source
$script = '& ' + "'" + $PSCommandPath.Replace("'", "''") + "' -ReadChild"
$childArgs = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script)))
$nodeCode = @'
const stamps = ['2026-01-15T12:00:00Z', '2026-07-15T12:00:00Z'];
console.log(JSON.stringify({pid:process.pid, resolvedZone:new Intl.DateTimeFormat().resolvedOptions().timeZone,
  minutes:stamps.map(t => -new Date(t).getTimezoneOffset())}));
'@
$hostBefore = Read-ProcessJson $desktop $childArgs
$results = [ordered]@{}
foreach ($zone in @('Asia/Shanghai','America/Los_Angeles')) {
    $results[$zone] = @{ node = (Read-ProcessJson $node @('-e',$nodeCode) $zone);
        native = (Read-ProcessJson $desktop $childArgs $zone) }
}
$crtControls = [ordered]@{}
foreach ($zone in @('CST-8','PST8PDT')) {
    $crtControls[$zone] = Read-ProcessJson $desktop $childArgs $zone
}
$hostAfter = Read-ProcessJson $desktop $childArgs
[ordered]@{ mode = 'same-host-synthetic-child-processes'; hostBefore = $hostBefore;
    zones = $results; crtControls = $crtControls; hostAfter = $hostAfter; systemWrites = 0 }
