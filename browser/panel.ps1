$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$root = Split-Path -Parent $PSScriptRoot
$hash = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($root.ToLowerInvariant()))
$mutex = [Threading.Mutex]::new($false, 'Local\ClaudeBrowser-' + [BitConverter]::ToString($hash, 0, 12))
try { $owns = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owns = $true }
if (!$owns) {
    [Windows.Forms.MessageBox]::Show('请使用此工作树已经打开的管理窗口。', 'Claude 浏览器') | Out-Null
    $mutex.Dispose()
    return
}

$worker = $null
try {
    $node = (Get-Command node.exe -ErrorAction Stop).Source
    if (!(Test-Path -LiteralPath (Join-Path $root 'node_modules\playwright-core\package.json'))) {
        throw '请先在浏览器工作树中运行 npm.cmd ci。'
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $node
    $start.WorkingDirectory = $root
    $start.Arguments = 'browser/controller.mjs'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $worker = [Diagnostics.Process]::Start($start)
    # A UTF-8 writer keeps non-ASCII mailbox paths intact in Windows PowerShell.
    $writer = [IO.StreamWriter]::new($worker.StandardInput.BaseStream, [Text.UTF8Encoding]::new($false), 1024, $true)
    $writer.AutoFlush = $true
    $script:incoming = $worker.StandardOutput.ReadLineAsync()
    $script:config = $null
    $script:states = $null
    $script:waiting = $true

    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Claude 浏览器'
    $form.Font = [Drawing.Font]::new('Microsoft YaHei UI', 10)
    $form.ClientSize = [Drawing.Size]::new(580, 366)
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.StartPosition = 'CenterScreen'
    $form.AutoScaleMode = 'Dpi'

    function New-Field($control, $x, $y, $width, $height) {
        $control.SetBounds($x, $y, $width, $height)
        $form.Controls.Add($control)
        return $control
    }
    function Add-Label($caption, $x, $y) {
        $label = New-Field ([Windows.Forms.Label]::new()) $x $y 138 26
        $label.Text = $caption
    }
    function Add-Button($caption, $x, $width, $action) {
        $button = New-Field ([Windows.Forms.Button]::new()) $x 253 $width 38
        $button.Text = $caption
        $button.Tag = $action
        $button.Add_Click({ param($sender, $eventArgs) Send-Action $sender.Tag })
        return $button
    }
    function Add-Choices($x, $y, $options) {
        $combo = New-Field ([Windows.Forms.ComboBox]::new()) $x $y 378 30
        $combo.Items.AddRange([object[]]$options)
        return $combo
    }

    Add-Label '账户空间' 22 23
    $account = Add-Choices 165 18 @('A', 'B')
    $account.DropDownStyle = 'DropDownList'
    $account.SelectedIndex = 0
    Add-Label '本地代理端口' 22 63
    $portBox = New-Field ([Windows.Forms.TextBox]::new()) 165 59 378 30
    $portBox.MaxLength = 5
    Add-Label '网页语言' 22 104
    $language = Add-Choices 165 99 @('system', 'zh-CN', 'zh-TW', 'en-US', 'ja-JP')
    Add-Label '网页时区' 22 144
    $zone = Add-Choices 165 139 @('system', 'Asia/Shanghai', 'Asia/Tokyo', 'America/Los_Angeles', 'UTC')
    Add-Label '邮箱主页' 22 184
    $mail = New-Field ([Windows.Forms.TextBox]::new()) 165 179 378 30
    $mail.AccessibleName = '本账户的 HTTPS 邮箱主页'
    $hint = New-Field ([Windows.Forms.Label]::new()) 165 214 400 25
    $hint.Text = '本机 HTTP / mixed 端口 · system 表示跟随系统'
    $hint.ForeColor = [Drawing.Color]::DimGray
    $buttons = @(
        (Add-Button '打开 Claude' 22 145 'claude')
        (Add-Button '打开邮箱' 177 117 'mail')
        (Add-Button '保存设置' 304 117 'save')
        (Add-Button '停止空间' 431 112 'stop')
    )
    $status = New-Field ([Windows.Forms.Label]::new()) 22 306 535 45
    $status.Text = '正在读取设置…'

    function Set-Busy([bool]$value) {
        $script:waiting = $value
        foreach ($control in (@($account, $portBox, $language, $zone, $mail) + $buttons)) {
            $control.Enabled = !$value
        }
    }
    function Show-Profile {
        if (!$script:config) { return }
        $entry = $script:config.profiles.($account.Text)
        $portBox.Text = [string]$script:config.port
        $language.Text = $entry.language
        $zone.Text = $entry.zone
        $mail.Text = $entry.mail
    }
    function Show-Status {
        if ($script:states) { $status.Text = 'A · ' + $script:states.A + '       B · ' + $script:states.B }
    }
    function Send-Action($action) {
        if ($script:waiting) { return }
        $portNumber = 0
        if ($action -ne 'stop' -and (![int]::TryParse($portBox.Text, [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535)) {
            $status.Text = '请输入 1–65535 的本地代理端口。'
            return
        }
        $command = @{ action = $action; id = $account.Text; port = $portNumber
            profile = @{ language = $language.Text.Trim(); zone = $zone.Text.Trim(); mail = $mail.Text.Trim() } }
        Set-Busy $true
        $status.Text = '正在处理账户 ' + $account.Text + '…'
        $writer.WriteLine(($command | ConvertTo-Json -Compress))
    }

    $account.Add_SelectedIndexChanged({ Show-Profile; Show-Status })
    $timer = [Windows.Forms.Timer]::new()
    $timer.Interval = 150
    $timer.Add_Tick({
        try {
            while ($script:incoming.IsCompleted) {
                $line = $script:incoming.GetAwaiter().GetResult()
                if ($null -eq $line) { throw '管理进程已退出。请关闭此窗口后重新打开。' }
                $message = $line | ConvertFrom-Json
                if ($message.event -eq 'fatal') { throw $message.message }
                $script:states = $message.states
                if ($message.settings) { $script:config = $message.settings }
                if ($message.event -eq 'ready') { Show-Profile }
                if ($message.event -ne 'status') { Set-Busy $false }
                Show-Status
                if ($message.event -eq 'failure') { $status.Text = $message.message }
                $script:incoming = $worker.StandardOutput.ReadLineAsync()
            }
        } catch {
            $timer.Stop()
            Set-Busy $true
            $status.Text = $_.Exception.Message
        }
    })
    Set-Busy $true
    $timer.Start()
    [Windows.Forms.Application]::Run($form)
    $timer.Dispose()
} catch {
    [Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Claude 浏览器') | Out-Null
} finally {
    if ($worker) {
        if (!$worker.HasExited) {
            try { $writer.WriteLine('{"action":"quit"}'); $writer.Dispose() } catch {}
            $worker.StandardInput.Close()
            $worker.WaitForExit()
        }
        $worker.Dispose()
    }
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
