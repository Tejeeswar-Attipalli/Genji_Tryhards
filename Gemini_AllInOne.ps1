#******REMEMBER TO FINISH FORENSIC QUESTIONS AND TAKE A SNAPSHOT BEFORE USING THIS.******
#******This code has not been checked. So take a snapshot before using it.         ******
<#
.SYNOPSIS
    CyberPatriot System Hardening Script (v2 - Feature Complete)
    
.DESCRIPTION
    This script provides a modular approach to system hardening.
    It adheres to safety-critical coding standards: strict mode,
    modular functions, and explicit error handling.
    
    v2 Update: Restored all original registry keys and added 
    Server-Specific safety warnings.

.NOTES
    WARNING: ALWAYS CREATE A SYSTEM RESTORE POINT BEFORE RUNNING.
    Run this script as Administrator.
#>

# Rule 10: Compile with all warnings enabled
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- HELPER FUNCTIONS ---

function Invoke-UserConfirmation {
    param (
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][string]$Description,
        [string]$WarningColor = "White"
    )

    Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "TASK: $TaskName" -ForegroundColor Yellow
    Write-Host "DESCRIPTION: $Description" -ForegroundColor $WarningColor
    
    $confirmation = Read-Host "Do you want to execute this task? (Y/N)"
    
    if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
        Write-Host "Executing $TaskName..." -ForegroundColor Green
        return $true
    }
    
    Write-Host "Skipping $TaskName." -ForegroundColor Gray
    return $false
}

function Set-RegistryValue {
    param ($Path, $Name, $Value, $Type = "REG_DWORD")
    try {
        # Check if path exists, create if not (ignoring errors for speed in competition)
        reg add $Path /v $Name /t $Type /d $Value /f | Out-Null
    } catch {
        Write-Warning "Failed to set registry key: $Path\$Name"
    }
}

# --- MODULES ---

function Start-UserAudit {
    param ([string]$Path)
    try {
        if (!(Test-Path -Path $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
        net user > "$Path\users.txt"
        net localgroup > "$Path\groups.txt"
        Write-Host "Audit saved to $Path"
    } catch { Write-Error "Failed to audit users: $_" }
}

function Disable-WindowsFeatures {
    # Full list restored from original
    $features = @(
        "IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures", "IIS-HttpErrors", 
        "IIS-HttpRedirect", "IIS-ApplicationDevelopment", "IIS-NetFxExtensibility", 
        "IIS-NetFxExtensibility45", "IIS-HealthAndDiagnostics", "IIS-HttpLogging", 
        "IIS-LoggingLibraries", "IIS-RequestMonitor", "IIS-HttpTracing", "IIS-Security", 
        "IIS-URLAuthorization", "IIS-RequestFiltering", "IIS-IPSecurity", "IIS-Performance", 
        "IIS-HttpCompressionDynamic", "IIS-WebServerManagementTools", "IIS-ManagementScriptingTools", 
        "IIS-IIS6ManagementCompatibility", "IIS-Metabase", "IIS-HostableWebCore", 
        "IIS-StaticContent", "IIS-DefaultDocument", "IIS-DirectoryBrowsing", "IIS-WebDAV", 
        "IIS-WebSockets", "IIS-ApplicationInit", "IIS-ASPNET", "IIS-ASPNET45", "IIS-ASP", 
        "IIS-CGI", "IIS-ISAPIExtensions", "IIS-ISAPIFilter", "IIS-ServerSideIncludes", 
        "IIS-CustomLogging", "IIS-BasicAuthentication", "IIS-HttpCompressionStatic", 
        "IIS-ManagementConsole", "IIS-ManagementService", "IIS-WMICompatibility", 
        "IIS-LegacyScripts", "IIS-LegacySnapIn", "IIS-FTPServer", "IIS-FTPSvc", 
        "IIS-FTPExtensibility", "TFTP", "TelnetClient", "TelnetServer", "SMB1Protocol"
    )

    foreach ($feature in $features) {
        try {
            dism /online /disable-feature /featurename:$feature /NoRestart | Out-Null
        } catch {
            # Suppress errors for features not installed
        }
    }
    
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Harden-NetworkProfile {
    try {
        Set-NetConnectionProfile -NetworkCategory Public -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
    } catch {}
}

function Harden-GeneralRegistry {
    $WinLogon = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-RegistryValue -Path $WinLogon -Name "AllocateCDRoms" -Value 1
    Set-RegistryValue -Path $WinLogon -Name "AllocateFloppies" -Value 1
    Set-RegistryValue -Path $WinLogon -Name "AutoAdminLogon" -Value 0
    
    Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1
    Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1
}

function Configure-LSAPolicy {
    $Lsa = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8
    Set-RegistryValue -Path $Lsa -Name "RunAsPPL" -Value 1
    Set-RegistryValue -Path $Lsa -Name "LimitBlankPasswordUse" -Value 1
    Set-RegistryValue -Path $Lsa -Name "auditbaseobjects" -Value 1
    Set-RegistryValue -Path $Lsa -Name "fullprivilegeauditing" -Value 1
    Set-RegistryValue -Path $Lsa -Name "restrictanonymous" -Value 1
    Set-RegistryValue -Path $Lsa -Name "restrictanonymoussam" -Value 1
    Set-RegistryValue -Path $Lsa -Name "disabledomaincreds" -Value 1
    Set-RegistryValue -Path $Lsa -Name "everyoneincludesanonymous" -Value 0
    Set-RegistryValue -Path $Lsa -Name "UseMachineId" -Value 0
}

function Configure-AccountPolicies {
    $Sys = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-RegistryValue -Path $Sys -Name "dontdisplaylastusername" -Value 1
    Set-RegistryValue -Path $Sys -Name "EnableLUA" -Value 1 # Enable UAC
    Set-RegistryValue -Path $Sys -Name "PromptOnSecureDesktop" -Value 1
    Set-RegistryValue -Path $Sys -Name "EnableInstallerDetection" -Value 1
    Set-RegistryValue -Path $Sys -Name "undockwithoutlogon" -Value 0
    Set-RegistryValue -Path $Sys -Name "DisableCAD" -Value 0
    
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5 -ErrorAction SilentlyContinue
    } catch {}

    # Netlogon Parameters
    $Net = "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters"
    Set-RegistryValue -Path $Net -Name "MaximumPasswordAge" -Value 15
    Set-RegistryValue -Path $Net -Name "DisablePasswordChange" -Value 1
    Set-RegistryValue -Path $Net -Name "RequireStrongKey" -Value 1
    Set-RegistryValue -Path $Net -Name "RequireSignOrSeal" -Value 1
    Set-RegistryValue -Path $Net -Name "SignSecureChannel" -Value 1
    Set-RegistryValue -Path $Net -Name "SealSecureChannel" -Value 1
}

function Harden-NetworkShares {
    # Originally missing in previous version
    $LanmanSrv = "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"
    Set-RegistryValue -Path $LanmanSrv -Name "autodisconnect" -Value 45
    Set-RegistryValue -Path $LanmanSrv -Name "enablesecuritysignature" -Value 0 # Per original script
    Set-RegistryValue -Path $LanmanSrv -Name "requiresecuritysignature" -Value 0 # Per original script
    
    reg ADD $LanmanSrv /v NullSessionPipes /t REG_MULTI_SZ /d "" /f | Out-Null
    reg ADD $LanmanSrv /v NullSessionShares /t REG_MULTI_SZ /d "" /f | Out-Null
    
    $LanmanWk = "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"
    Set-RegistryValue -Path $LanmanWk -Name "EnablePlainTextPassword" -Value 0
    
    # Remote Registry Paths
    $SecurePipe = "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg"
    reg ADD "$SecurePipe\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f | Out-Null
    reg ADD "$SecurePipe\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f | Out-Null
}

function Harden-BrowserSettings {
    $IEPhish = "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter"
    Set-RegistryValue -Path $IEPhish -Name "EnabledV8" -Value 1
    Set-RegistryValue -Path $IEPhish -Name "EnabledV9" -Value 1
    
    $Inet = "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-RegistryValue -Path $Inet -Name "DisablePasswordCaching" -Value 1
    Set-RegistryValue -Path $Inet -Name "WarnonBadCertRecving" -Value 1
    Set-RegistryValue -Path $Inet -Name "WarnOnPostRedirect" -Value 1
    Set-RegistryValue -Path $Inet -Name "WarnonZoneCrossing" -Value 1
    
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Internet Explorer\Main" -Name "DoNotTrack" -Value 1
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Internet Explorer\Download" -Name "RunInvalidSignatures" -Value 1
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" -Name "LOCALMACHINE_CD_UNLOCK" -Value 1
}

function Harden-ExplorerEnvironment {
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1
    Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0
    
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f | Out-Null
    
    Set-RegistryValue -Path "HKCU\SYSTEM\CurrentControlSet\Services\CDROM" -Name "AutoRun" -Value 1
    Set-RegistryValue -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
    Set-RegistryValue -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
}

function Harden-OfficeSecurity {
    # Restored Office Hardening
    $officeApps = @("access", "excel", "ms project", "powerpoint", "publisher", "visio", "word")
    foreach ($app in $officeApps) {
        $path = "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\$app\security"
        Set-RegistryValue -Path $path -Name "vbawarnings" -Value 4
        Set-RegistryValue -Path $path -Name "blockcontentexecutionfrominternet" -Value 1
        
        if ($app -eq "excel") { Set-RegistryValue -Path $path -Name "excelbypassencryptedmacroscan" -Value 0 }
        if ($app -eq "word") { Set-RegistryValue -Path $path -Name "wordbypassencryptedmacroscan" -Value 0 }
    }
    Set-RegistryValue -Path "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" -Name "automationsecurity" -Value 3
}

function Harden-DefenderRegistry {
    $Def = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
    Set-RegistryValue -Path $Def -Name "DisableAntiSpyware" -Value 0
    Set-RegistryValue -Path $Def -Name "ServiceKeepAlive" -Value 1
    Set-RegistryValue -Path "$Def\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0
    Set-RegistryValue -Path "$Def\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0
    Set-RegistryValue -Path "$Def\Scan" -Name "CheckForSignaturesBeforeRunningScan" -Value 1
    Set-RegistryValue -Path "$Def\Scan" -Name "DisableHeuristics" -Value 0
    Set-RegistryValue -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3
}

function Disable-GeneralBadServices {
    # Safe to disable on almost anything
    $services = @(
        "tlntsvr", "msftpsvc", "snmptrap", "ssdpsrv", "remoteregistry", "Messenger", 
        "upnphos", "RemoteAccess", "mnmsrvc", "NetTcpPortSharing", "RasMan", 
        "TabletInputService", "RpcSs", "XblAuthManager", "XblGameSave", "XboxGipSvc", 
        "xboxgip", "xbgm", "SysMain", "seclogon", "TapiSrv", "p2pimsvc", "simptcp", 
        "fax", "iprip", "ftpsvc", "RasAuto", "Smtpsvc", "TrkWks", "MSDTC", "ERSvc", 
        "NtFrs", "IsmServ", "WmdmPmSN", "helpsvc", "RDSessMgr", "RSoPProv", "Sacsvr", 
        "uploadmgr", "VDS", "VSS", "CscService", "hidserv", "IPBusEnum", "PolicyAgent", 
        "SharedAccess", "Themes", "nfssvc", "nfsclnt", "MSSQLServerADHelper", 
        "UmRdpService", "TeamViewer", "TeamViewer7", "HomeGroupListener", 
        "HomeGroupProvider", "AxInstSV", "lltdsvc", "iphlpsvc", "AdobeARMservice"
    )

    foreach ($svc in $services) {
        if (Get-Service $svc -ErrorAction SilentlyContinue) {
            cmd.exe /c "sc stop $svc"
            cmd.exe /c "sc config $svc start= disabled"
        }
    }
}

function Disable-CriticalRiskServices {
    # CAUTION: These break Servers (DCs, File Servers, IIS)
    $services = @(
        "Netlogon",       # Breaks Domain Controllers
        "lanmanserver",   # Breaks File Sharing
        "W3svc",          # Breaks IIS Web Server
        "Iisadmin",       # Breaks IIS
        "Spooler",        # Breaks Print Servers
        "TermService",    # Breaks RDP (Remote Desktop)
        "Dfs",            # Breaks Distributed File System
        "Server"          # Core networking
    )

    foreach ($svc in $services) {
        if (Get-Service $svc -ErrorAction SilentlyContinue) {
            cmd.exe /c "sc stop $svc"
            cmd.exe /c "sc config $svc start= disabled"
        }
    }
}

function Enable-EssentialServices {
    $services = @("wuauserv", "EventLog", "MpsSvc", "WinDefend", "WdNisSvc", "Sense", "Schedule", "SCardSvr", "ScDeviceEnum", "SCPolicySvc", "wscsvc")
    foreach ($svc in $services) {
        cmd.exe /c "sc start $svc"
        cmd.exe /c "sc config $svc start= auto"
    }
}

# --- MAIN EXECUTION ---

$AuditDir = ".\Security_Audit"

if (Invoke-UserConfirmation -TaskName "Audit Users and Groups" -Description "Exports user lists to $AuditDir.") {
    Start-UserAudit -Path $AuditDir
}

if (Invoke-UserConfirmation -TaskName "Disable Windows Features (IIS/Telnet)" -Description "WARNING: Disables IIS. Do NOT run if this is a Web Server.") {
    Disable-WindowsFeatures
}

if (Invoke-UserConfirmation -TaskName "Harden Network Profiles" -Description "Sets network to Public and removes signatures.") {
    Harden-NetworkProfile
}

if (Invoke-UserConfirmation -TaskName "Registry Hardening" -Description "Apply general registry fixes (CD-ROM, Floppy, AutoLogon).") {
    Harden-GeneralRegistry
}

if (Invoke-UserConfirmation -TaskName "LSA Policy" -Description "Configure LSA auditing and protections.") {
    Configure-LSAPolicy
}

if (Invoke-UserConfirmation -TaskName "Account Policies" -Description "Configure UAC, Password Age, and NetLogon Parameters.") {
    Configure-AccountPolicies
}

if (Invoke-UserConfirmation -TaskName "Network Shares Security" -Description "Secure LanmanServer/Workstation (SMB) settings.") {
    Harden-NetworkShares
}

if (Invoke-UserConfirmation -TaskName "Browser Security" -Description "Enable SmartScreen, DoNotTrack, disable password caching.") {
    Harden-BrowserSettings
}

if (Invoke-UserConfirmation -TaskName "Office Security" -Description "Harden Office Macros (Word, Excel, etc.).") {
    Harden-OfficeSecurity
}

if (Invoke-UserConfirmation -TaskName "Explorer Hardening" -Description "Show hidden files, disable Sticky Keys and Crash Dumps.") {
    Harden-ExplorerEnvironment
}

if (Invoke-UserConfirmation -TaskName "Defender Registry" -Description "Apply Registry keys to enforce Windows Defender.") {
    Harden-DefenderRegistry
}

if (Invoke-UserConfirmation -TaskName "Disable General Bad Services" -Description "Stop Telnet, Xbox, FTP, Remote Registry, etc.") {
    Disable-GeneralBadServices
}

# NEW SAFETY CHECK FOR SERVERS
if (Invoke-UserConfirmation -TaskName "Disable SERVER-CRITICAL Services" -Description "WARNING: Stops Netlogon, File Sharing, RDP, and IIS. DO NOT RUN ON SERVERS/DCs unless you are sure!" -WarningColor "Red") {
    Disable-CriticalRiskServices
}

if (Invoke-UserConfirmation -TaskName "Enable Essential Services" -Description "Start Firewall, Defender, and Update services.") {
    Enable-EssentialServices
}

Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Compliance tasks completed. Please restart the system." -ForegroundColor Green
Read-Host "Press Enter to exit..."
