param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$ClientExe = "",
    [string]$WorkingDirectory = "",
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Resolve-DefaultClientExe {
    $candidates = @(
        (Join-Path $ProjectRoot "dist\client-bin\windows-x64\porthoneypot-client.exe"),
        (Join-Path $ProjectRoot "build-target\x86_64-pc-windows-msvc\release\porthoneypot-client.exe"),
        (Join-Path $ProjectRoot "client\target\release\porthoneypot-client.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }
    return $candidates[0]
}

if ([string]::IsNullOrWhiteSpace($ClientExe)) {
    $ClientExe = Resolve-DefaultClientExe
}
if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $WorkingDirectory = Split-Path -Parent $ClientExe
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory) -or -not (Test-Path $WorkingDirectory)) {
        $WorkingDirectory = $ProjectRoot
    }
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $WorkingDirectory "client_config.json"
}

$script:ClientExe = $ClientExe
$script:WorkingDirectory = $WorkingDirectory
$script:ConfigPath = $ConfigPath
$script:ClientProcess = $null
$script:Form = $null
$script:NotifyIcon = $null
$script:Controls = @{}

function New-DefaultConfig {
    return [ordered]@{
        server_host = "127.0.0.1"
        server_port = 9443
        shared_key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        node_id = ""
        listen_ports = @(21, 22, 23, 80, 445, 3389)
        stealth_mode = $true
        stealth_fallback_to_tcp = $true
        autostart = $true
        hidden = $true
        heartbeat_interval_secs = 20
        flush_interval_secs = 10
        max_payload_bytes = 1024
        spool_path = "data/client_spool.jsonl"
        log_path = "logs/client.log"
        log_max_bytes = 2097152
        log_backup_count = 5
        update_enabled = $false
        update_interval_secs = 300
        update_base_url = ""
    }
}

function Read-ClientConfig {
    $source = $script:ConfigPath
    if (-not (Test-Path $source)) {
        $embedded = Join-Path $ProjectRoot "client\config\default_client.json"
        if (Test-Path $embedded) {
            $source = $embedded
        }
    }
    if (Test-Path $source) {
        return Get-Content -Raw -Encoding UTF8 $source | ConvertFrom-Json
    }
    return [pscustomobject](New-DefaultConfig)
}

function Save-ClientConfig {
    $ports = @()
    foreach ($raw in ($script:Controls.Ports.Text -split ",")) {
        $value = $raw.Trim()
        if ($value.Length -eq 0) { continue }
        $port = [int]$value
        if ($port -le 0 -or $port -ge 65536) {
            throw "Invalid port: $port"
        }
        $ports += $port
    }
    if ($ports.Count -eq 0) {
        throw "At least one listen port is required."
    }
    $config = [ordered]@{
        server_host = $script:Controls.ServerHost.Text.Trim()
        server_port = [int]$script:Controls.ServerPort.Text
        shared_key_hex = $script:Controls.SharedKey.Text.Trim()
        node_id = $script:Controls.NodeId.Text.Trim()
        listen_ports = @($ports | Sort-Object -Unique)
        stealth_mode = [bool]$script:Controls.Stealth.Checked
        stealth_fallback_to_tcp = [bool]$script:Controls.Fallback.Checked
        autostart = [bool]$script:Controls.Autostart.Checked
        hidden = [bool]$script:Controls.Hidden.Checked
        heartbeat_interval_secs = [int]$script:Controls.Heartbeat.Text
        flush_interval_secs = [int]$script:Controls.Flush.Text
        max_payload_bytes = 1024
        spool_path = $script:Controls.SpoolPath.Text.Trim()
        log_path = $script:Controls.LogPath.Text.Trim()
        log_max_bytes = [int64]$script:Controls.LogMaxBytes.Text
        log_backup_count = [int]$script:Controls.LogBackups.Text
        update_enabled = [bool]$script:Controls.UpdateEnabled.Checked
        update_interval_secs = 300
        update_base_url = $script:Controls.UpdateUrl.Text.Trim()
    }
    $parent = Split-Path -Parent $script:ConfigPath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $config | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $script:ConfigPath
    Show-Balloon "Port Honeypot Client" "Configuration saved."
    Refresh-Status
}

function Load-ConfigToUi {
    $config = Read-ClientConfig
    $script:Controls.ServerHost.Text = [string]$config.server_host
    $script:Controls.ServerPort.Text = [string]$config.server_port
    $script:Controls.SharedKey.Text = [string]$config.shared_key_hex
    $script:Controls.NodeId.Text = [string]$config.node_id
    $script:Controls.Ports.Text = (($config.listen_ports | ForEach-Object { [string]$_ }) -join ",")
    $script:Controls.Stealth.Checked = [bool]$config.stealth_mode
    $script:Controls.Fallback.Checked = [bool]$config.stealth_fallback_to_tcp
    $script:Controls.Autostart.Checked = [bool]$config.autostart
    $script:Controls.Hidden.Checked = [bool]$config.hidden
    $script:Controls.Heartbeat.Text = [string]$config.heartbeat_interval_secs
    $script:Controls.Flush.Text = [string]$config.flush_interval_secs
    $script:Controls.SpoolPath.Text = [string]$config.spool_path
    $script:Controls.LogPath.Text = [string]$config.log_path
    $logMaxBytes = 2097152
    if ($null -ne $config.log_max_bytes) { $logMaxBytes = $config.log_max_bytes }
    $logBackups = 5
    if ($null -ne $config.log_backup_count) { $logBackups = $config.log_backup_count }
    $script:Controls.LogMaxBytes.Text = [string]$logMaxBytes
    $script:Controls.LogBackups.Text = [string]$logBackups
    $script:Controls.UpdateEnabled.Checked = [bool]$config.update_enabled
    $script:Controls.UpdateUrl.Text = [string]$config.update_base_url
}

function Get-ClientProcess {
    if ($script:ClientProcess -and -not $script:ClientProcess.HasExited) {
        return $script:ClientProcess
    }
    $name = [IO.Path]::GetFileNameWithoutExtension($script:ClientExe)
    $candidate = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) {
        $script:ClientProcess = $candidate
        return $candidate
    }
    return $null
}

function Start-Client {
    if (Get-ClientProcess) {
        Show-Balloon "Port Honeypot Client" "Client is already running."
        return
    }
    if (-not (Test-Path $script:ClientExe)) {
        [System.Windows.Forms.MessageBox]::Show("Client executable not found:`n$script:ClientExe", "Start failed", "OK", "Error") | Out-Null
        return
    }
    Save-ClientConfig
    $script:ClientProcess = Start-Process -FilePath $script:ClientExe -ArgumentList @("run") -WorkingDirectory $script:WorkingDirectory -WindowStyle Hidden -PassThru
    Show-Balloon "Port Honeypot Client" "Client started."
    Refresh-Status
}

function Stop-Client {
    $process = Get-ClientProcess
    if (-not $process) {
        Show-Balloon "Port Honeypot Client" "Client is not running."
        Refresh-Status
        return
    }
    $process.CloseMainWindow() | Out-Null
    Start-Sleep -Milliseconds 500
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
    }
    $script:ClientProcess = $null
    Show-Balloon "Port Honeypot Client" "Client stopped."
    Refresh-Status
}

function Invoke-ClientCommand {
    param([string]$Command)
    if (-not (Test-Path $script:ClientExe)) {
        return "Client executable not found: $script:ClientExe"
    }
    $output = & $script:ClientExe $Command 2>&1
    return ($output | Out-String).Trim()
}

function Install-Autostart {
    $result = Invoke-ClientCommand "install-autostart"
    Show-Balloon "Port Honeypot Client" "Autostart install command finished."
    Set-OutputText $result
}

function Uninstall-Autostart {
    $result = Invoke-ClientCommand "uninstall-autostart"
    Show-Balloon "Port Honeypot Client" "Autostart uninstall command finished."
    Set-OutputText $result
}

function Show-ClientStatus {
    $result = Invoke-ClientCommand "status"
    Set-OutputText $result
    Show-MainWindow
}

function Resolve-ClientPath {
    param([string]$RelativeOrAbsolute)
    if ([IO.Path]::IsPathRooted($RelativeOrAbsolute)) {
        return $RelativeOrAbsolute
    }
    return Join-Path $script:WorkingDirectory $RelativeOrAbsolute
}

function Refresh-LogView {
    $path = Resolve-ClientPath $script:Controls.LogPath.Text
    if (-not (Test-Path $path)) {
        $script:Controls.LogText.Text = "Log file not found: $path"
        return
    }
    $lines = Get-Content -Encoding UTF8 -Tail 180 $path
    $script:Controls.LogText.Text = ($lines -join [Environment]::NewLine)
}

function Set-OutputText {
    param([string]$Text)
    $script:Controls.Output.Text = $Text
}

function Refresh-Status {
    $process = Get-ClientProcess
    if ($process) {
        $script:Controls.Status.Text = "Running, PID $($process.Id)"
        $script:Controls.Status.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 80)
    } else {
        $script:Controls.Status.Text = "Stopped"
        $script:Controls.Status.ForeColor = [System.Drawing.Color]::FromArgb(170, 70, 30)
    }
    $script:Controls.ExePath.Text = $script:ClientExe
    $script:Controls.WorkDir.Text = $script:WorkingDirectory
    $script:Controls.ConfigPath.Text = $script:ConfigPath
}

function Show-Balloon {
    param(
        [string]$Title,
        [string]$Message,
        [System.Windows.Forms.ToolTipIcon]$Icon = [System.Windows.Forms.ToolTipIcon]::Info
    )
    if ($script:NotifyIcon) {
        $script:NotifyIcon.BalloonTipTitle = $Title
        $script:NotifyIcon.BalloonTipText = $Message
        $script:NotifyIcon.BalloonTipIcon = $Icon
        $script:NotifyIcon.ShowBalloonTip(3500)
    }
}

function Show-MainWindow {
    $script:Form.Show()
    $script:Form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    $script:Form.Activate()
}

function Hide-MainWindow {
    $script:Form.Hide()
    Show-Balloon "Port Honeypot Client" "Client manager is still running in the tray."
}

function Confirm-Exit {
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Exit the client manager?`n`nChoose Yes to stop the running client as well.",
        "Exit confirmation",
        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($answer -eq [System.Windows.Forms.DialogResult]::Cancel) {
        return
    }
    if ($answer -eq [System.Windows.Forms.DialogResult]::Yes) {
        Stop-Client
    }
    $script:NotifyIcon.Visible = $false
    $script:NotifyIcon.Dispose()
    [System.Windows.Forms.Application]::Exit()
}

function New-Label {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 120)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($W, 22)
    return $label
}

function New-TextBox {
    param([int]$X, [int]$Y, [int]$W = 220)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point($X, $Y)
    $box.Size = New-Object System.Drawing.Size($W, 24)
    return $box
}

function Build-Ui {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Port Honeypot Client Manager"
    $form.Size = New-Object System.Drawing.Size(920, 720)
    $form.MinimumSize = New-Object System.Drawing.Size(860, 660)
    $form.StartPosition = "CenterScreen"
    $form.add_FormClosing({
        if ($_.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) {
            $_.Cancel = $true
            Hide-MainWindow
        }
    })
    $script:Form = $form

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = [System.Windows.Forms.DockStyle]::Fill
    $form.Controls.Add($tabs)

    $statusTab = New-Object System.Windows.Forms.TabPage
    $statusTab.Text = "Status"
    $configTab = New-Object System.Windows.Forms.TabPage
    $configTab.Text = "Config"
    $logTab = New-Object System.Windows.Forms.TabPage
    $logTab.Text = "Logs"
    $tabs.TabPages.AddRange(@($statusTab, $configTab, $logTab))

    $script:Controls.Status = New-Object System.Windows.Forms.Label
    $script:Controls.Status.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $script:Controls.Status.Location = New-Object System.Drawing.Point(24, 24)
    $script:Controls.Status.Size = New-Object System.Drawing.Size(420, 42)
    $statusTab.Controls.Add($script:Controls.Status)

    $buttons = @(
        @("Start client", { Start-Client }),
        @("Stop client", { Stop-Client }),
        @("Status command", { Show-ClientStatus }),
        @("Install autostart", { Install-Autostart }),
        @("Uninstall autostart", { Uninstall-Autostart }),
        @("Hide to tray", { Hide-MainWindow })
    )
    $x = 24
    $y = 82
    foreach ($entry in $buttons) {
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $entry[0]
        $button.Location = New-Object System.Drawing.Point($x, $y)
        $button.Size = New-Object System.Drawing.Size(132, 34)
        $button.Add_Click($entry[1])
        $statusTab.Controls.Add($button)
        $x += 142
        if ($x -gt 760) { $x = 24; $y += 44 }
    }

    $statusTab.Controls.Add((New-Label "Client executable" 24 150 130))
    $script:Controls.ExePath = New-TextBox 160 148 570
    $script:Controls.ExePath.ReadOnly = $true
    $statusTab.Controls.Add($script:Controls.ExePath)
    $browseExe = New-Object System.Windows.Forms.Button
    $browseExe.Text = "Browse"
    $browseExe.Location = New-Object System.Drawing.Point(742, 146)
    $browseExe.Size = New-Object System.Drawing.Size(88, 28)
    $browseExe.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Filter = "Honeypot client|porthoneypot-client.exe|Executable|*.exe"
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:ClientExe = $dialog.FileName
            Refresh-Status
        }
    })
    $statusTab.Controls.Add($browseExe)

    $statusTab.Controls.Add((New-Label "Working directory" 24 190 130))
    $script:Controls.WorkDir = New-TextBox 160 188 570
    $script:Controls.WorkDir.ReadOnly = $true
    $statusTab.Controls.Add($script:Controls.WorkDir)
    $statusTab.Controls.Add((New-Label "Config path" 24 230 130))
    $script:Controls.ConfigPath = New-TextBox 160 228 570
    $script:Controls.ConfigPath.ReadOnly = $true
    $statusTab.Controls.Add($script:Controls.ConfigPath)

    $script:Controls.Output = New-Object System.Windows.Forms.TextBox
    $script:Controls.Output.Location = New-Object System.Drawing.Point(24, 280)
    $script:Controls.Output.Size = New-Object System.Drawing.Size(810, 320)
    $script:Controls.Output.Multiline = $true
    $script:Controls.Output.ScrollBars = "Both"
    $script:Controls.Output.ReadOnly = $true
    $statusTab.Controls.Add($script:Controls.Output)

    $rows = @(
        @("Server host", "ServerHost", 24, 28, 170),
        @("Server port", "ServerPort", 470, 28, 110),
        @("Shared key hex", "SharedKey", 24, 68, 620),
        @("Node ID", "NodeId", 24, 108, 260),
        @("Listen ports", "Ports", 470, 108, 260),
        @("Heartbeat seconds", "Heartbeat", 24, 188, 110),
        @("Flush seconds", "Flush", 270, 188, 110),
        @("Spool path", "SpoolPath", 24, 228, 260),
        @("Log path", "LogPath", 470, 228, 260),
        @("Log max bytes", "LogMaxBytes", 24, 268, 160),
        @("Log backups", "LogBackups", 270, 268, 110),
        @("Update base URL", "UpdateUrl", 24, 348, 420)
    )
    foreach ($row in $rows) {
        $configTab.Controls.Add((New-Label $row[0] $row[2] $row[3] 130))
        $script:Controls[$row[1]] = New-TextBox ($row[2] + 138) ($row[3] - 2) $row[4]
        $configTab.Controls.Add($script:Controls[$row[1]])
    }

    $script:Controls.Stealth = New-Object System.Windows.Forms.CheckBox
    $script:Controls.Stealth.Text = "Stealth mode"
    $script:Controls.Stealth.Location = New-Object System.Drawing.Point(24, 148)
    $script:Controls.Stealth.Size = New-Object System.Drawing.Size(130, 26)
    $configTab.Controls.Add($script:Controls.Stealth)

    $script:Controls.Fallback = New-Object System.Windows.Forms.CheckBox
    $script:Controls.Fallback.Text = "Fallback to TCP"
    $script:Controls.Fallback.Location = New-Object System.Drawing.Point(170, 148)
    $script:Controls.Fallback.Size = New-Object System.Drawing.Size(150, 26)
    $configTab.Controls.Add($script:Controls.Fallback)

    $script:Controls.Autostart = New-Object System.Windows.Forms.CheckBox
    $script:Controls.Autostart.Text = "Autostart"
    $script:Controls.Autostart.Location = New-Object System.Drawing.Point(340, 148)
    $script:Controls.Autostart.Size = New-Object System.Drawing.Size(110, 26)
    $configTab.Controls.Add($script:Controls.Autostart)

    $script:Controls.Hidden = New-Object System.Windows.Forms.CheckBox
    $script:Controls.Hidden.Text = "Hidden run"
    $script:Controls.Hidden.Location = New-Object System.Drawing.Point(470, 148)
    $script:Controls.Hidden.Size = New-Object System.Drawing.Size(120, 26)
    $configTab.Controls.Add($script:Controls.Hidden)

    $script:Controls.UpdateEnabled = New-Object System.Windows.Forms.CheckBox
    $script:Controls.UpdateEnabled.Text = "Auto update"
    $script:Controls.UpdateEnabled.Location = New-Object System.Drawing.Point(24, 312)
    $script:Controls.UpdateEnabled.Size = New-Object System.Drawing.Size(130, 26)
    $configTab.Controls.Add($script:Controls.UpdateEnabled)

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = "Save config"
    $saveButton.Location = New-Object System.Drawing.Point(24, 400)
    $saveButton.Size = New-Object System.Drawing.Size(120, 34)
    $saveButton.Add_Click({
        try { Save-ClientConfig } catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Save failed", "OK", "Error") | Out-Null }
    })
    $configTab.Controls.Add($saveButton)

    $reloadButton = New-Object System.Windows.Forms.Button
    $reloadButton.Text = "Reload"
    $reloadButton.Location = New-Object System.Drawing.Point(154, 400)
    $reloadButton.Size = New-Object System.Drawing.Size(100, 34)
    $reloadButton.Add_Click({ Load-ConfigToUi })
    $configTab.Controls.Add($reloadButton)

    $refreshLogButton = New-Object System.Windows.Forms.Button
    $refreshLogButton.Text = "Refresh logs"
    $refreshLogButton.Location = New-Object System.Drawing.Point(24, 22)
    $refreshLogButton.Size = New-Object System.Drawing.Size(120, 32)
    $refreshLogButton.Add_Click({ Refresh-LogView })
    $logTab.Controls.Add($refreshLogButton)

    $script:Controls.LogText = New-Object System.Windows.Forms.TextBox
    $script:Controls.LogText.Location = New-Object System.Drawing.Point(24, 66)
    $script:Controls.LogText.Size = New-Object System.Drawing.Size(810, 540)
    $script:Controls.LogText.Multiline = $true
    $script:Controls.LogText.ScrollBars = "Both"
    $script:Controls.LogText.ReadOnly = $true
    $logTab.Controls.Add($script:Controls.LogText)
}

function Build-Tray {
    $script:NotifyIcon = New-Object System.Windows.Forms.NotifyIcon
    $script:NotifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
    $script:NotifyIcon.Text = "Port Honeypot Client"
    $script:NotifyIcon.Visible = $true

    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $open = $menu.Items.Add("Open client manager")
    $open.add_Click({ Show-MainWindow })
    $hide = $menu.Items.Add("Hide window")
    $hide.add_Click({ Hide-MainWindow })
    $menu.Items.Add("-") | Out-Null
    $start = $menu.Items.Add("Start client")
    $start.add_Click({ Start-Client })
    $stop = $menu.Items.Add("Stop client")
    $stop.add_Click({ Stop-Client })
    $status = $menu.Items.Add("Show status")
    $status.add_Click({ Show-ClientStatus })
    $menu.Items.Add("-") | Out-Null
    $install = $menu.Items.Add("Install autostart")
    $install.add_Click({ Install-Autostart })
    $uninstall = $menu.Items.Add("Uninstall autostart")
    $uninstall.add_Click({ Uninstall-Autostart })
    $menu.Items.Add("-") | Out-Null
    $exit = $menu.Items.Add("Exit")
    $exit.add_Click({ Confirm-Exit })
    $script:NotifyIcon.ContextMenuStrip = $menu
    $script:NotifyIcon.add_DoubleClick({ Show-MainWindow })
}

Build-Ui
Build-Tray
Load-ConfigToUi
Refresh-Status

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 4000
$timer.Add_Tick({ Refresh-Status })
$timer.Start()

Show-Balloon "Port Honeypot Client" "Client manager is running."
[System.Windows.Forms.Application]::Run($script:Form)
