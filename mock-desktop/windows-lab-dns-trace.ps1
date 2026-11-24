function Get-LabDnsServicePid {
    return [int](Get-CimInstance Win32_Service -Filter "Name = 'Dnscache'").ProcessId
}

function Start-LabDnsTrace([string]$RunDirectory, [string]$Prefix, [switch]$AccountMatch) {
    if ($Prefix -cnotmatch '^studio-[0-9a-f]{16}$') { throw 'Unexpected DNS canary prefix' }
    $trace = @{name=$Prefix; prefix=$Prefix; file=(Join-Path $RunDirectory ($Prefix + '.etl')); servicePid=(Get-LabDnsServicePid);
        accountMatch=[bool]$AccountMatch}
    if (!$trace.servicePid) { throw 'The DNS Client service is unavailable' }
    $result = & logman.exe create trace $trace.name -o $trace.file -p 'Microsoft-Windows-DNS-Client' 0xffffffffffffffff 5 -ets
    if ($LASTEXITCODE -ne 0) { throw ('Unable to start temporary DNS ETW trace: ' + ($result -join ' ')) }
    return $trace
}

function Convert-LabDnsEvent($Event, [string]$Prefix, [bool]$AccountMatch) {
    if ($Event.Id -notin 3006,3008,3009,3010,3011 -or !$Event.Properties.Count) { return }
    $name = [string]$Event.Properties[0].Value
    if ($AccountMatch) {
        if (!$name.StartsWith($Prefix+'-',[StringComparison]::OrdinalIgnoreCase)) { return }
        $case = [ordered]@{name=$name.TrimEnd('.').ToLowerInvariant();event=$Event.Id;emitterPid=$Event.ProcessId}
        if ($name -imatch ('^' + [regex]::Escape($Prefix) + '-(psec|ordinary|host)-(baseline|blocked|cold[0-9]{0,2}|restored|healthy[1-4]|fault[1-4])-(dns|addr)\.test\.?$')) {
            $case.role=$Matches[1].ToLowerInvariant(); $case.phase=$Matches[2].ToLowerInvariant(); $case.probe=$Matches[3].ToLowerInvariant()
        }
    } else {
        if ($name -inotmatch ('^' + [regex]::Escape($Prefix) + '-([abh])-(?:(dns|addr|window)-)?((?:baseline|healthy|outage|stopped|recovered|cold|crash|silent|fake)[1-9]?)\.test\.?$')) { return }
        $case = [ordered]@{profile=$Matches[1].ToUpperInvariant();phase=$Matches[3].ToLowerInvariant();event=$Event.Id;emitterPid=$Event.ProcessId}
        if ($Matches[2]) { $case.probe = $Matches[2].ToLowerInvariant() }
    }
    if ($Event.Id -in 3010,3011) {
        if ($Event.Properties.Count -gt 2) { $case.server = [string]$Event.Properties[2].Value }
        $index = if ($Event.Id -eq 3010) { 3 } else { 4 }
        if ($Event.Properties.Count -gt $index) { $case.clientPid = [int]$Event.Properties[$index].Value }
    }
    return $case
}

function Stop-LabDnsTrace($Trace, [switch]$MeasureLoss) {
    $loss = $null
    $lossError = $null
    if ($MeasureLoss) {
        try { $loss = Get-LabDnsTraceLoss $Trace.name } catch { $lossError = $_.Exception.Message }
    }
    $result = & logman.exe stop $Trace.name -ets
    if ($LASTEXITCODE -ne 0) { throw ('Unable to stop temporary DNS ETW trace: ' + ($result -join ' ')) }
    $cases = @()
    try {
        foreach ($event in Get-WinEvent -Path $Trace.file -Oldest) {
            $case = Convert-LabDnsEvent $event $Trace.prefix ([bool]$Trace.accountMatch)
            if ($case) { $cases += $case }
        }
        $pidAfter = Get-LabDnsServicePid
        $report = @{servicePid=$Trace.servicePid; servicePidAfter=$pidAfter; events=$cases; stopped=$true}
        if ($MeasureLoss) { $report.lossBeforeStop=$loss; $report.lossError=$lossError }
        return $report
    } finally {
        if (Test-Path -LiteralPath $Trace.file) { Remove-Item -LiteralPath $Trace.file }
    }
}

function Get-LabDnsTraceLoss([string]$Name) {
    if (-not ('StudioTraceStats' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class StudioTraceStats {
    [StructLayout(LayoutKind.Sequential)]
    struct Properties {
        public uint size, provider; public ulong context; public long timestamp; public Guid guid; public uint client, flags;
        public uint buffer, min, max, fileSize, mode, flush, enables; public int age;
        public uint buffers, free, eventsLost, written, logBuffersLost, realtimeBuffersLost;
        public IntPtr thread; public uint fileOffset, nameOffset;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    static extern uint ControlTraceW(ulong session, string name, IntPtr properties, uint command);
    public static uint[] Read(string name) {
        int size=Marshal.SizeOf(typeof(Properties));
        var data=new byte[size+8192];
        var handle=GCHandle.Alloc(data,GCHandleType.Pinned);
        try {
            IntPtr buffer=handle.AddrOfPinnedObject();
            var p=new Properties {size=(uint)data.Length, nameOffset=(uint)size, fileOffset=(uint)size+4096};
            Marshal.StructureToPtr(p,buffer,false);
            uint error=ControlTraceW(0,name,buffer,0);
            if (error!=0) throw new Win32Exception((int)error);
            p=(Properties)Marshal.PtrToStructure(buffer,typeof(Properties));
            return new uint[]{p.eventsLost,p.logBuffersLost,p.realtimeBuffersLost};
        } finally { handle.Free(); }
    }
}
'@
    }
    $stats = [StudioTraceStats]::Read($Name)
    return @{eventsLost=$stats[0]; logBuffersLost=$stats[1]; realtimeBuffersLost=$stats[2]}
}
