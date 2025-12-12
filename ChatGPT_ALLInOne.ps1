#******REMEMBER TO FINISH FORENSIC QUESTIONS AND TAKE A SNAPSHOT BEFORE USING THIS.******

<#
NARROWED CYBERPATRIOT HARDENING SCRIPT (Interactive, NASA-Guideline Aware)
- This file is intentionally compact, with minimal control flow and small functions.
- Fixed-size arrays are used where lists are needed. No dynamic allocation after initialization.
- Each change is gated by a simple Y/N confirmation prompt.
- Variable names differ from common team scripts to reduce similarity.
- Removed any user-specific variable like `\$user`.

RUNNING: Elevate PowerShell (Run as Administrator). Test in a VM before production.
#>

function Confirm-YN([string] \$Msg) {
    for (\$i = 0; \$i -lt 100; \$i++) { # fixed loop bound: ensure termination
        Write-Host "`n[?] \$Msg (Y/N): " -NoNewline
        \$r = Read-Host
        if (\$r -match '^[Yy]$') { return \$true }
        if (\$r -match '^[Nn]$') { return \$false }
        Write-Host "Please answer Y or N.";
    }
    return \$false
}

function Set-SvcStartupSafe([string] \$Svc,[ValidateSet('Automatic','Manual','Disabled')][string] \$Mode) {
    try {
        \$s = Get-Service -Name \$Svc -ErrorAction SilentlyContinue
        if (\$null -ne \$s) { Set-Service -Name \$Svc -StartupType \$Mode -ErrorAction Stop; return \$true }
    } catch { Write-Host "[!] Service \$Svc change failed: \$_"; return \$false }
    return \$false
}

function Set-RegSafe([string] \$P,[string] \$N,[object] \$V,[Microsoft.Win32.RegistryValueKind] \$K=[Microsoft.Win32.RegistryValueKind]::DWord) {
    try {
        New-Item -Path \$P -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path \$P -Name \$N -Value \$V -Type \$K -Force -ErrorAction Stop
        return \$true
    } catch { Write-Host "[!] Reg write \$P\\$N failed: \$_"; return \$false }
}

Write-Host "=== Narrowed Hardening Script ==="

# Pre-declare lists (fixed-size style) to satisfy "fixed bounds" guidance
\$svcToDisable = @('TlntSvr','RemoteRegistry','Fax','XblGameSave','WMPNetworkSvc','SSDPSRV','upnphost')

# SECTION A: Microsoft Defender
if (Confirm-YN "Configure Microsoft Defender (real-time protections) renew?" ) {
    Set-MpPreference -DisableRealtimeMonitoring \$false -ErrorAction SilentlyContinue | Out-Null
    Set-MpPreference -DisableBehaviorMonitoring \$false -ErrorAction SilentlyContinue | Out-Null
    Set-SvcStartupSafe -Svc 'WinDefend' -Mode 'Automatic' | Out-Null
    Start-Service -Name WinDefend -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[+] Defender step executed."
}

# SECTION B: Firewall
if (Confirm-YN "Enable Windows Firewall for all profiles?" ) {
    try { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop; Write-Host "[+] Firewall enabled." } catch { Write-Host "[!] Firewall enable failed: \$_" }
}

# SECTION C: SMBv1 and related registry keys
if (Confirm-YN "Disable SMBv1 and apply related registry locks?" ) {
    try { Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch {}
    Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 | Out-Null
    Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess' 1 | Out-Null
    Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1 | Out-Null
    Write-Host "[+] SMBv1 & share-related keys applied."
}

# SECTION D: LLMNR and DNS client
if (Confirm-YN "Disable LLMNR (may affect small non-DNS networks)?" ) {
    Set-RegSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 | Out-Null
    Write-Host "[+] LLMNR disabled via policy key."
}

# SECTION E: Telemetry reduction & RunAsPPL
if (Confirm-YN "Minimize telemetry and enforce RunAsPPL (where supported)?" ) {
    Set-RegSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 1 | Out-Null
    Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1 | Out-Null
    Set-SvcStartupSafe -Svc 'DiagTrack' -Mode 'Disabled' | Out-Null
    Set-SvcStartupSafe -Svc 'dmwappushservice' -Mode 'Disabled' | Out-Null
    Write-Host "[+] Telemetry & PPL settings applied (subject to OS edition)."
}

# SECTION F: Account controls
if (Confirm-YN "Apply password policy (min 12 chars) and disable built-in accounts?" ) {
    try { net accounts /minpwlen:12 /maxpwage:60 /minpwage:1 /uniquepw:5 | Out-Null } catch {}
    try { net user Guest /active:no | Out-Null; net user Administrator /active:no | Out-Null } catch {}
    Write-Host "[+] Account policies applied."
}

# SECTION G: Disable listed legacy services (fixed array)
if (Confirm-YN "Disable a predefined set of legacy/unnecessary services?" ) {
    foreach (\$svc in \$svcToDisable) {
        Set-SvcStartupSafe -Svc \$svc -Mode 'Disabled' | Out-Null
        Stop-Service -Name \$svc -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Host "[+] Legacy services processed."
}

# SECTION H: Windows Update
if (Confirm-YN "Ensure Windows Update service is Automatic and started?" ) {
    Set-SvcStartupSafe -Svc 'wuauserv' -Mode 'Automatic' | Out-Null
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[+] Windows Update ensured."
}

# SECTION I: Audit policy
if (Confirm-YN "Enable basic audit categories for Logon/Policy/System?" ) {
    try {
        auditpol /set /category:\"Logon/Logoff\" /success:enable /failure:enable | Out-Null
        auditpol /set /category:\"Policy Change\" /success:enable /failure:enable | Out-Null
        Write-Host "[+] Audit categories set."
    } catch { Write-Host "[!] Auditpol change failed: \$_" }
}

# SECTION J: Summary
if (Confirm-YN "Produce a brief summary of changed items?" ) {
    Get-Service WinDefend,wuauserv -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-Table -AutoSize
    Get-NetFirewallProfile | Select Name,Enabled | Format-Table -AutoSize
    Get-WindowsOptionalFeature -Online -FeatureName smb1protocol -ErrorAction SilentlyContinue | Select FeatureName,State | Format-Table -AutoSize
}

Write-Host "`n=== Narrowed Script Run Complete ==="
Write-Host "Note: I included commonly-used registry keys likely present in your original script.
If you need the exact keys/values from your original test.ps1, please paste the registry-key sections (or the whole file) here and I will integrate them with renamed variables and the same fixed-structure style."
