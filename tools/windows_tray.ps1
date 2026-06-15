param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$DashboardUrl = "http://127.0.0.1:8088",
    [int]$WebPort = 8088
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-Balloon {
    param(
        [string]$Title,
        [string]$Message,
        [System.Windows.Forms.ToolTipIcon]$Icon = [System.Windows.Forms.ToolTipIcon]::Info
    )
    $script:NotifyIcon.BalloonTipTitle = $Title
    $script:NotifyIcon.BalloonTipText = $Message
    $script:NotifyIcon.BalloonTipIcon = $Icon
    $script:NotifyIcon.ShowBalloonTip(4000)
}

function Invoke-JsonPost {
    param([string]$Path)
    try {
        Invoke-RestMethod -Method Post -Uri "$DashboardUrl$Path" -ContentType "application/json" -Body "{}" -TimeoutSec 3 | Out-Null
        return $true
    } catch {
        Show-Balloon "Port Honeypot" "Request failed: $($_.Exception.Message)" ([System.Windows.Forms.ToolTipIcon]::Warning)
        return $false
    }
}

function Test-Web {
    try {
        Invoke-RestMethod -Method Get -Uri "$DashboardUrl/api/status" -TimeoutSec 2 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Start-ServerProcess {
    if (Test-Web) {
        Show-Balloon "Port Honeypot" "Server is already running."
        return
    }
    $python = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $python) {
        Show-Balloon "Port Honeypot" "python was not found in PATH." ([System.Windows.Forms.ToolTipIcon]::Error)
        return
    }
    Start-Process -FilePath $python.Source -ArgumentList @("-m", "server.porthoneypot") -WorkingDirectory $ProjectRoot -WindowStyle Hidden | Out-Null
    Start-Sleep -Seconds 2
    if (Test-Web) {
        Show-Balloon "Port Honeypot" "Server process started."
    } else {
        Show-Balloon "Port Honeypot" "Server process did not respond yet." ([System.Windows.Forms.ToolTipIcon]::Warning)
    }
}

function Open-Dashboard {
    Start-Process $DashboardUrl | Out-Null
}

$script:NotifyIcon = New-Object System.Windows.Forms.NotifyIcon
$script:NotifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
$script:NotifyIcon.Text = "Port Honeypot"
$script:NotifyIcon.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip

$openItem = $menu.Items.Add("Open dashboard")
$openItem.add_Click({ Open-Dashboard })

$startProcessItem = $menu.Items.Add("Start server process")
$startProcessItem.add_Click({ Start-ServerProcess })

$startTcpItem = $menu.Items.Add("Start TCP service")
$startTcpItem.add_Click({
    if (Invoke-JsonPost "/api/service/start") {
        Show-Balloon "Port Honeypot" "TCP service started."
    }
})

$stopTcpItem = $menu.Items.Add("Stop TCP service")
$stopTcpItem.add_Click({
    if (Invoke-JsonPost "/api/service/stop") {
        Show-Balloon "Port Honeypot" "TCP service stopped."
    }
})

$testAlertItem = $menu.Items.Add("Test alert")
$testAlertItem.add_Click({
    if (Invoke-JsonPost "/api/alerts/test") {
        Show-Balloon "Port Honeypot" "Test alert sent."
    }
})

$stopSoundItem = $menu.Items.Add("Stop sound")
$stopSoundItem.add_Click({
    if (Invoke-JsonPost "/api/alerts/stop") {
        Show-Balloon "Port Honeypot" "Sound stop requested."
    }
})

$menu.Items.Add("-") | Out-Null

$exitItem = $menu.Items.Add("Exit tray")
$exitItem.add_Click({
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Exit the Port Honeypot tray controller?",
        "Exit confirmation",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) {
        return
    }
    $script:NotifyIcon.Visible = $false
    $script:NotifyIcon.Dispose()
    [System.Windows.Forms.Application]::Exit()
})

$script:NotifyIcon.ContextMenuStrip = $menu
$script:NotifyIcon.add_DoubleClick({ Open-Dashboard })

Show-Balloon "Port Honeypot" "Tray controller is running."
[System.Windows.Forms.Application]::Run()
