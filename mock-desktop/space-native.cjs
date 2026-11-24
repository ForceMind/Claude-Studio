const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);

const query = `
$ErrorActionPreference = 'Stop'
Add-Type -Namespace Simulator -Name Focus -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern System.IntPtr GetForegroundWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern uint GetWindowThreadProcessId(System.IntPtr window, out uint owner);
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetForegroundWindow(System.IntPtr window);
'@
function WindowOwner([IntPtr] $window) {
  [uint32] $owner = 0
  [void] [Simulator.Focus]::GetWindowThreadProcessId($window, [ref] $owner)
  $owner
}
$window = [Simulator.Focus]::GetForegroundWindow()
if ($env:SPACE_FOCUS_OWNER -and (WindowOwner $window) -eq [uint32] $env:SPACE_FOCUS_OWNER) {
  $hex = $env:SPACE_FOCUS_HANDLE
  [byte[]] $bytes = for ($i = 0; $i -lt 16; $i += 2) { [Convert]::ToByte($hex.Substring($i, 2), 16) }
  $target = [IntPtr] [BitConverter]::ToInt64($bytes, 0)
  if ((WindowOwner $target) -eq [uint32] $env:SPACE_FOCUS_PID) {
    [void] [Simulator.Focus]::SetForegroundWindow($target)
  }
}
$window = [Simulator.Focus]::GetForegroundWindow()
@{
  pid = WindowOwner $window
  handle = -join ([BitConverter]::GetBytes($window.ToInt64()) | ForEach-Object { $_.ToString('x2') })
} | ConvertTo-Json -Compress
`;

async function foregroundWindow(target) {
  const env = {...process.env, SPACE_FOCUS_OWNER: '', SPACE_FOCUS_HANDLE: '', SPACE_FOCUS_PID: ''};
  if (target) {
    if (!Number.isInteger(target.pid) || !/^[0-9a-f]{16}$/.test(target.handle)) throw new Error('Invalid simulator window');
    env.SPACE_FOCUS_OWNER = String(process.pid);
    env.SPACE_FOCUS_PID = String(target.pid);
    env.SPACE_FOCUS_HANDLE = target.handle;
  }
  const {stdout} = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', query], {
    timeout: 8000, windowsHide: true, env
  });
  return JSON.parse(stdout);
}

module.exports = { foregroundWindow };
