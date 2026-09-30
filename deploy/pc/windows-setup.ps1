<#
.SYNOPSIS
    Keeps WSL, and the LG-SOTF dev/uat stacks inside it, running on this PC
    whether or not anyone is signed in (docs/self-hosting-pc.md, step 4).

.DESCRIPTION
    Run it in an ELEVATED Windows PowerShell (Run as administrator), signed in
    as the Windows account that owns the WSL distribution. Safe to run again.

    * Registers, or updates, the scheduled task 'LG-SOTF WSL keepalive'. It
      runs "wsl.exe -d <Distro> --exec /bin/true" one minute after every boot
      and every 5 minutes, whether you are signed in or not (S4U: no password
      is stored), without administrator rights, on battery too, never twice at
      once, and it is stopped after 5 minutes. With instanceIdleTimeout=-1 in
      .wslconfig the distribution then keeps running, and systemd inside it
      starts Docker, Tailscale and SSH.
    * Power, on AC only: closing the lid does nothing, never sleep, never
      hibernate. Then 'powercfg /hibernate off', which deletes hiberfil.sys
      (about 40% of the RAM size on C:) and turns off Fast Startup, so the boot
      trigger fires on every start. -KeepHibernation skips this.
    * Windows Update active hours: 18 hours starting at -ActiveHoursStart
      (default 06:00-00:00), with the documented policy registry values, so
      update restarts happen only at night. -SkipActiveHours skips this.
    * Prints a status report and the commands to restart WSL. It never
      restarts or shuts down WSL itself.

.PARAMETER Distro
    WSL distribution to keep running (default Ubuntu; 'wsl -l -v' lists them).

.PARAMETER KeepHibernation
    Leave hibernation and Fast Startup on. After a shutdown with Fast Startup
    the boot trigger does not fire; the 5-minute trigger still starts WSL.

.PARAMETER ActiveHoursStart
    First hour (0-23) of the 18-hour Windows Update active hours (default 6).

.PARAMETER SkipActiveHours
    Do not change the Windows Update active hours.

.PARAMETER Status
    Only print the status report. Needs no administrator rights.

.PARAMETER Uninstall
    Remove the scheduled task and the active-hours policy. Power settings are
    left as they are (the report says how to restore them). Works even when
    the WSL distribution, or WSL itself, is already gone.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\lgsotf-windows-setup.ps1"

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\lgsotf-windows-setup.ps1" -Status

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\lgsotf-windows-setup.ps1" -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Distro = 'Ubuntu',
    [switch]$KeepHibernation,
    [ValidateRange(0, 23)]
    [int]$ActiveHoursStart = 6,
    [switch]$SkipActiveHours,
    [switch]$Status,
    [switch]$Uninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'LG-SOTF WSL keepalive'
$ActiveHoursLength = 18
$MinFreeGB = 10
$PolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$LxssKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
$PowerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
$SessionPowerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'

function Write-Line([string]$Level, [string]$Text) {
    $colors = @{ 'OK' = 'Green'; 'WARN' = 'Yellow'; 'FAIL' = 'Red'; '--' = 'Gray' }
    Write-Host ('  {0,-5} {1}' -f $Level, $Text) -ForegroundColor $colors[$Level]
}

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegValue([string]$Path, [string]$Name) {
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

# Runs a native program without letting its stderr become a terminating error.
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $global:LASTEXITCODE = 0
        $output = @(& $Exe @Arguments 2>&1 | ForEach-Object { "$_" })
        $code = $global:LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    return New-Object PSObject -Property @{ ExitCode = $code; Output = $output }
}

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    $result = Invoke-Native $Exe $Arguments
    if ($result.ExitCode -ne 0) {
        throw ('{0} {1} failed ({2}): {3}' -f $Exe, ($Arguments -join ' '), $result.ExitCode, ($result.Output -join ' '))
    }
}

function Get-WslExe {
    $programFiles = $env:ProgramW6432
    if (-not $programFiles) { $programFiles = $env:ProgramFiles }
    $preferred = Join-Path $programFiles 'WSL\wsl.exe'
    $inbox = Join-Path $env:WINDIR 'System32\wsl.exe'
    if (Test-Path -LiteralPath $preferred) { return $preferred }
    if (Test-Path -LiteralPath $inbox) { return $inbox }
    if (Test-Path -LiteralPath (Join-Path $env:WINDIR 'Sysnative\wsl.exe')) { return $inbox }
    throw 'wsl.exe was not found; install WSL first (wsl --install).'
}

function Get-DistroRegistration([string]$Name) {
    if (-not (Test-Path -LiteralPath $LxssKey)) { return $null }
    foreach ($key in @(Get-ChildItem -LiteralPath $LxssKey)) {
        if ((Get-RegValue $key.PSPath 'DistributionName') -eq $Name) {
            $vhd = Get-RegValue $key.PSPath 'VhdFileName'
            if (-not $vhd) { $vhd = 'ext4.vhdx' }
            $base = [string](Get-RegValue $key.PSPath 'BasePath')
            if ($base.StartsWith('\\?\')) { $base = $base.Substring(4) }
            return New-Object PSObject -Property @{ Name = $Name; VhdPath = (Join-Path $base $vhd) }
        }
    }
    return $null
}

# AC value of a power setting in the active plan (hidden settings included),
# or $null. powercfg prints the AC and then the DC index as the last two hex
# numbers, whatever the display language.
function Get-PowerAcIndex([string]$SubGroup, [string]$Setting) {
    $result = Invoke-Native 'powercfg.exe' @('/qh', 'SCHEME_CURRENT', $SubGroup, $Setting)
    if ($result.ExitCode -ne 0) { return $null }
    $hex = @([regex]::Matches(($result.Output -join "`n"), '0x[0-9a-fA-F]{8}') | ForEach-Object { $_.Value })
    if ($hex.Count -lt 2) { return $null }
    return [Convert]::ToUInt32($hex[$hex.Count - 2], 16)
}

function Format-Seconds($Seconds) {
    if ($null -eq $Seconds) { return 'unknown' }
    if ($Seconds -eq 0) { return 'never' }
    return ('after {0} min' -f [math]::Round($Seconds / 60))
}

function Test-TaskDefinition($Task) {
    $problems = @()
    if ("$($Task.Principal.LogonType)" -ne 'S4U') { $problems += 'logon type is not S4U' }
    if ("$($Task.Principal.RunLevel)" -ne 'Limited') { $problems += 'run level is not Limited' }
    $boot = @($Task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' })
    if ($boot.Count -ne 1 -or "$($boot[0].Delay)" -ne 'PT1M') { $problems += 'no boot trigger with a 1-minute delay' }
    $repeat = @($Task.Triggers | Where-Object { "$($_.Repetition.Interval)" -eq 'PT5M' -and -not "$($_.Repetition.Duration)" })
    if ($repeat.Count -lt 1) { $problems += 'no trigger repeating every 5 minutes indefinitely' }
    $s = $Task.Settings
    if ($s.DisallowStartIfOnBatteries) { $problems += 'does not start on battery' }
    if ($s.StopIfGoingOnBatteries) { $problems += 'stops on battery' }
    if (-not $s.StartWhenAvailable) { $problems += 'StartWhenAvailable is off' }
    if ("$($s.MultipleInstances)" -ne 'IgnoreNew') { $problems += 'MultipleInstances is not IgnoreNew' }
    if ("$($s.ExecutionTimeLimit)" -ne 'PT5M') { $problems += 'execution time limit is not 5 minutes' }
    $action = @($Task.Actions)[0]
    if (-not ("$($action.Execute)" -like '*\wsl.exe') -or "$($action.Arguments)" -ne "-d $Distro --exec /bin/true") {
        $problems += "action is not: wsl.exe -d $Distro --exec /bin/true"
    }
    return $problems
}

function Format-TaskResult($Code) {
    switch ([int64]$Code) {
        0 { return '0 (success)' }
        267009 { return '0x41301 (running)' }
        267011 { return '0x41303 (has not run yet)' }
        2147943785 { return '0x80070569 (the account lacks "Log on as a batch job")' }
        default { return ('0x{0:X8}' -f [int64]$Code) }
    }
}

function Show-Status([string]$WslExe) {
    Write-Host ''
    Write-Host 'LG-SOTF host status (Windows side)'

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        Write-Line 'FAIL' "Scheduled task '$TaskName' is not registered"
    } else {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        $summary = "state $($task.State), runs as $($task.Principal.UserId) ($($task.Principal.LogonType)), last result $(Format-TaskResult $info.LastTaskResult), next run $($info.NextRunTime)"
        $problems = @(Test-TaskDefinition $task)
        if ($problems.Count -gt 0) {
            Write-Line 'WARN' "Task '$TaskName': $($problems -join '; '). Run this script again (elevated)."
        } elseif ("$($task.State)" -eq 'Disabled') {
            Write-Line 'WARN' "Task '$TaskName' is disabled (maintenance mode). Enable-ScheduledTask -TaskName '$TaskName'"
        } elseif (@(0, 267009, 267011) -notcontains [int64]$info.LastTaskResult) {
            Write-Line 'WARN' "Task '$TaskName': $summary"
        } else {
            Write-Line 'OK' "Task '$TaskName': $summary"
        }
    }

    $lid = Get-PowerAcIndex 'SUB_BUTTONS' 'LIDACTION'
    $lidNames = @('do nothing', 'sleep', 'hibernate', 'shut down')
    if ($lid -eq 0) { Write-Line 'OK' 'Closing the lid on AC power: do nothing' }
    elseif ($null -eq $lid) { Write-Line 'WARN' 'Could not read the lid action' }
    else { Write-Line 'WARN' "Closing the lid on AC power: $($lidNames[[int]$lid]) (the PC stops serving)" }
    $sleep = Get-PowerAcIndex 'SUB_SLEEP' 'STANDBYIDLE'
    $hibernate = Get-PowerAcIndex 'SUB_SLEEP' 'HIBERNATEIDLE'
    $level = 'OK'
    if ($sleep -ne 0 -or $hibernate -ne 0) { $level = 'WARN' }
    Write-Line $level "On AC power: sleep $(Format-Seconds $sleep), hibernate $(Format-Seconds $hibernate)"
    # 'powercfg /hibernate' writes HibernateEnabled; until then only the default exists.
    $hibernation = Get-RegValue $PowerKey 'HibernateEnabled'
    if ($null -eq $hibernation) { $hibernation = Get-RegValue $PowerKey 'HibernateEnabledDefault' }
    $fastStartup = Get-RegValue $SessionPowerKey 'HiberbootEnabled'
    if ($hibernation -eq 0) {
        Write-Line 'OK' 'Hibernation off (no hiberfil.sys; Fast Startup cannot run)'
    } elseif ($fastStartup -eq 1) {
        Write-Line 'WARN' 'Hibernation and Fast Startup are on: after a shutdown the boot trigger does not fire (the 5-minute trigger still starts WSL)'
    } else {
        Write-Line 'WARN' 'Hibernation is on (hiberfil.sys uses space on C:)'
    }

    if ((Get-RegValue $PolicyKey 'SetActiveHours') -eq 1) {
        Write-Line 'OK' ('Windows Update active hours (policy): {0:00}:00-{1:00}:00; update restarts happen outside them' -f `
            (Get-RegValue $PolicyKey 'ActiveHoursStart'), (Get-RegValue $PolicyKey 'ActiveHoursEnd'))
    } else {
        Write-Line 'WARN' 'Windows Update active hours are not set by this script: an update may restart the PC during the day'
    }

    $version = (Get-Item -LiteralPath $WslExe).VersionInfo.ProductVersion
    if ("$version" -like '3.0.1*') {
        Write-Line 'WARN' "WSL $version has a known session-0 regression (microsoft/WSL#41110) affecting this task; use 2.5.9 or 2.7.14"
    } else {
        Write-Line 'OK' "WSL $version ($WslExe)"
    }
    $env:WSL_UTF8 = '1'
    $running = Invoke-Native $WslExe @('--list', '--running', '--quiet')
    $names = @($running.Output | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ })
    if ($names -contains $Distro) { Write-Line 'OK' "Distribution '$Distro' is running" }
    else { Write-Line 'WARN' "Distribution '$Distro' is not running (the task starts it within 5 minutes)" }

    $wslconfig = Join-Path $env:USERPROFILE '.wslconfig'
    $idle = $null
    if (Test-Path -LiteralPath $wslconfig) {
        $section = ''
        foreach ($line in Get-Content -LiteralPath $wslconfig) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^\[(.+)\]$') { $section = $Matches[1].Trim().ToLowerInvariant(); continue }
            if ($section -eq 'general' -and $trimmed -match '^instanceIdleTimeout\s*=\s*(\S+)') { $idle = $Matches[1] }
        }
    }
    if ($idle -eq '-1') { Write-Line 'OK' "$wslconfig has [general] instanceIdleTimeout=-1" }
    else { Write-Line 'FAIL' "$wslconfig needs [general] instanceIdleTimeout=-1 (docs/self-hosting-pc.md, prerequisites)" }

    $drive = Get-PSDrive -Name C
    $freeGB = [math]::Round($drive.Free / 1GB, 1)
    if ($freeGB -lt $MinFreeGB) { Write-Line 'FAIL' "C: has only $freeGB GB free: keep at least $MinFreeGB GB (the WSL disk lives there)" }
    else { Write-Line 'OK' "C: has $freeGB GB free (keep at least $MinFreeGB GB)" }
    $registration = Get-DistroRegistration $Distro
    if ($null -ne $registration -and (Test-Path -LiteralPath $registration.VhdPath)) {
        $vhdGB = [math]::Round((Get-Item -LiteralPath $registration.VhdPath).Length / 1GB, 1)
        Write-Line '--' "WSL disk $($registration.VhdPath): $vhdGB GB"
    }

    $service = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
    if ($null -eq $service) { Write-Line 'OK' 'Tailscale for Windows is not installed' }
    elseif ("$($service.Status)" -eq 'Running') {
        Write-Line 'WARN' "Tailscale for Windows is running: quit it and run: Set-Service -Name Tailscale -StartupType Manual; Stop-Service Tailscale"
    } else { Write-Line 'OK' 'Tailscale for Windows is installed but not running (keep it that way)' }
}

function Register-KeepaliveTask([string]$WslExe) {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute $WslExe -Argument ('-d {0} --exec /bin/true' -f $Distro)
    $atStartup = New-ScheduledTaskTrigger -AtStartup
    $atStartup.Delay = 'PT1M'
    $watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $description = "Starts WSL ($Distro) at boot and every 5 minutes so LG-SOTF dev/uat keep running without a signed-in user (docs/self-hosting-pc.md)."
    if ($PSCmdlet.ShouldProcess($TaskName, "Register scheduled task for $user (S4U; at startup + 1 min, every 5 min)")) {
        Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Action $action -Trigger @($atStartup, $watchdog) `
            -Principal $principal -Settings $settings -Description $description -Force | Out-Null
        Write-Line 'OK' "Registered '$TaskName' for $user"
    }
    if ($PSCmdlet.ShouldProcess($TaskName, 'Run the task once now (WSL already runs, so this only proves the task works)')) {
        Start-ScheduledTask -TaskName $TaskName
        $deadline = (Get-Date).AddSeconds(90)
        do {
            Start-Sleep -Seconds 3
            $result = [int64](Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
        } while ((@(267009, 267011) -contains $result) -and (Get-Date) -lt $deadline)
        if ($result -eq 0) { Write-Line 'OK' 'Test run of the task: success' }
        else { Write-Line 'WARN' "Test run of the task: $(Format-TaskResult $result) (docs/self-hosting-pc.md, troubleshooting)" }
    }
}

function Set-PowerSettings {
    $changes = @(
        @('SUB_BUTTONS', 'LIDACTION', 'Closing the lid on AC power: do nothing'),
        @('SUB_SLEEP', 'STANDBYIDLE', 'Sleep on AC power: never'),
        @('SUB_SLEEP', 'HIBERNATEIDLE', 'Hibernate on AC power: never')
    )
    foreach ($change in $changes) {
        if ($PSCmdlet.ShouldProcess('active power plan', $change[2])) {
            Invoke-Checked 'powercfg.exe' @('/setacvalueindex', 'SCHEME_CURRENT', $change[0], $change[1], '0')
        }
    }
    if ($PSCmdlet.ShouldProcess('active power plan', 'Apply the changed settings')) {
        Invoke-Checked 'powercfg.exe' @('/setactive', 'SCHEME_CURRENT')
        Write-Line 'OK' 'On AC power: lid does nothing, never sleep, never hibernate'
    }
    if ($KeepHibernation) {
        Write-Line '--' 'Hibernation left on (-KeepHibernation)'
    } elseif ($PSCmdlet.ShouldProcess('hibernation', 'powercfg /hibernate off (deletes hiberfil.sys, turns off Fast Startup)')) {
        Invoke-Checked 'powercfg.exe' @('/hibernate', 'off')
        Write-Line 'OK' 'Hibernation off: hiberfil.sys deleted, Fast Startup off'
    }
}

function Set-ActiveHours {
    $end = ($ActiveHoursStart + $ActiveHoursLength) % 24
    $window = '{0:00}:00-{1:00}:00' -f $ActiveHoursStart, $end
    if ($PSCmdlet.ShouldProcess($PolicyKey, "Windows Update active hours $window")) {
        if (-not (Test-Path -LiteralPath $PolicyKey)) { New-Item -Path $PolicyKey -Force | Out-Null }
        New-ItemProperty -LiteralPath $PolicyKey -Name 'SetActiveHours' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -LiteralPath $PolicyKey -Name 'ActiveHoursStart' -PropertyType DWord -Value $ActiveHoursStart -Force | Out-Null
        New-ItemProperty -LiteralPath $PolicyKey -Name 'ActiveHoursEnd' -PropertyType DWord -Value $end -Force | Out-Null
        Write-Line 'OK' "Windows Update active hours $window (Settings shows them as managed by your organization)"
    }
}

function Remove-Setup {
    if ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Line 'OK' "Removed the task '$TaskName'"
        }
    } else {
        Write-Line '--' "No task '$TaskName'"
    }
    if ($null -ne (Get-RegValue $PolicyKey 'SetActiveHours')) {
        if ($PSCmdlet.ShouldProcess($PolicyKey, 'Remove the active-hours policy values')) {
            Remove-ItemProperty -LiteralPath $PolicyKey -Name 'SetActiveHours', 'ActiveHoursStart', 'ActiveHoursEnd' -ErrorAction SilentlyContinue
            Write-Line 'OK' 'Removed the Windows Update active-hours policy'
        }
    }
    Write-Host ''
    Write-Host 'Power settings were left as they are. To restore them:'
    Write-Host '  powercfg /hibernate on'
    Write-Host '  Settings > System > Power & battery > Lid & power button controls / Screen, sleep & hibernate timeouts'
}

function Show-NextSteps {
    Write-Host ''
    Write-Host 'Next. This script did not restart WSL; do it now to check that WSL comes back without you:'
    Write-Host '  1. Save your work in WSL. Close Claude Code and the Ubuntu terminals, then in this window:'
    Write-Host '       wsl --shutdown'
    Write-Host '  2. Start WSL the way the PC will after a reboot, with no terminal:'
    Write-Host "       Start-ScheduledTask -TaskName '$TaskName'; Start-Sleep -Seconds 20; wsl -l -v"
    Write-Host "     '$Distro' must show Running. Without step 2 the task starts it within 5 minutes."
    Write-Host '  3. Close every terminal, wait 2 minutes, open a new PowerShell: wsl -l -v   (still Running)'
    Write-Host '  4. Reboot and do not sign in. After about 3 minutes your phone should show lgsotf-pc as'
    Write-Host '     Connected at https://login.tailscale.com/admin/machines (and, once deployed, the app loads).'
    Write-Host '  5. Open Ubuntu again and resume:  cd ~/SOC; claude --continue'
    Write-Host "  Maintenance: Disable-ScheduledTask -TaskName '$TaskName' before 'wsl --shutdown', Enable-ScheduledTask after."
}

# ------------------------------------------------------------------ main
# Load these modules before -WhatIf is in effect: importing them under -WhatIf
# prints a "What if: Set Alias" line per alias.
$whatIfRequested = $WhatIfPreference
$WhatIfPreference = $false
Import-Module ScheduledTasks, CimCmdlets -ErrorAction SilentlyContinue
$WhatIfPreference = $whatIfRequested

if ($Status) {
    Show-Status (Get-WslExe)
    exit 0
}
if (-not (Test-Elevated)) {
    if ($WhatIfPreference) {
        Write-Line 'WARN' 'Not elevated: showing what would change (-WhatIf); nothing is changed.'
    } else {
        Write-Host 'Run this in an elevated PowerShell (right-click Windows PowerShell > Run as administrator),' -ForegroundColor Red
        Write-Host 'or add -Status for a read-only report.' -ForegroundColor Red
        exit 1
    }
}
# Removing the task needs neither wsl.exe nor the distribution: both may be
# gone already (unregistered, renamed, or another Windows account).
if ($Uninstall) {
    Remove-Setup
    exit 0
}
$wslExe = Get-WslExe
if ($null -eq (Get-DistroRegistration $Distro)) {
    throw ("WSL distribution '{0}' is not registered for {1}. Run this as the Windows account that owns it (see 'wsl -l -v'), or pass -Distro." -f `
        $Distro, [Security.Principal.WindowsIdentity]::GetCurrent().Name)
}

Write-Host "LG-SOTF: keeping WSL ($Distro) running on this PC"
Register-KeepaliveTask $wslExe
Set-PowerSettings
if ($SkipActiveHours) { Write-Line '--' 'Windows Update active hours left unchanged (-SkipActiveHours)' }
else { Set-ActiveHours }
Show-Status $wslExe
Show-NextSteps
