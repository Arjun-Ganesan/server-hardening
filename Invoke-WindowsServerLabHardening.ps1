#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Audits or hardens a Windows Server lab VM (Domain Controller or standalone/member server)
using an explicit profile (server.config.json).
.DESCRIPTION
Server version of Invoke-Windows11LabHardening.ps1.
Default mode is Audit. Apply requires -Mode Apply. No automatic reboot, file
deletion, application uninstall, task deletion or scoring changes.
Use 64-bit Windows PowerShell 5.1 at the VM console. Take a VM snapshot first.

What changes versus the Windows 11 script:
  * Runs on Windows Server 2016/2019/2022/2025 (ProductType 2 = DC, 3 = server).
  * Domain Controller: users/groups via Active Directory, password/lockout via the
    Default Domain Policy, security options/user rights via the Default Domain
    Controllers Policy (so gpupdate does not undo them), DC hardening
    (Zerologon, LDAP signing/channel binding, secure channel, Print Spooler),
    privileged AD group cleanup, AD account-flag fixes, delegation cleanup.
  * Server roles/features removed with Uninstall-WindowsFeature, with a
    dependency check so a required role is never removed with them.
  * DNS hardening (secure-only updates, no zone transfers, SIGRed fix).
  * IIS/FTP hardening when they are critical (directory browsing, anonymous FTP).
  * RDP / WinRM can be marked critical; the script then secures them instead of
    disabling them.
  * IE Enhanced Security Configuration on; SYSVOL/NETLOGON never removed.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Audit', 'Apply')][string]$Mode = 'Audit',
    [string]$ConfigPath = '',
    [switch]$RotatePasswords,
    [switch]$ScanFiles,
    [switch]$UpdateApps,
    [switch]$InstallSecurityUpdates,
    [switch]$UpdateDefender,
    [switch]$QuickScan,
    [switch]$AdvancedAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Runner = $PSCmdlet
$script:Changes = New-Object 'System.Collections.Generic.List[object]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:RebootNeeded = $false
$script:CreatedNow = New-Object 'System.Collections.Generic.List[string]'

# Well-known GPO GUIDs present in every domain.
$script:DefaultDomainPolicyGuid = '31B2F340-016D-11D2-945F-00C04FB984F9'
$script:DefaultDcPolicyGuid = '6AC1786C-016F-11D2-945F-00C04fB984F9'

# Services a Windows Server must never lose (DC services included; they are absent on non-DCs).
$script:EssentialServices = @('RpcSs','DcomLaunch','SamSs','LSM','EventLog','WinDefend','WdNisSvc','mpssvc','BFE','wuauserv','BITS','CryptSvc','Dhcp','Dnscache','Winmgmt','wscsvc','SecurityHealthService','NTDS','Netlogon','Kdc','DFSR','NtFrs','ADWS','IsmServ','W32Time','LanmanServer','LanmanWorkstation','gpsvc','NlaSvc','Netman','ProfSvc','Schedule')
# Features that must never be removed (directly or as a dependent of another removal).
$script:ProtectedFeatures = @('AD-Domain-Services','GPMC','RSAT-AD-Tools','RSAT-AD-PowerShell','RSAT-ADDS','RSAT-ADDS-Tools','RSAT-AD-AdminCenter','RSAT-DNS-Server','FileAndStorage-Services','Storage-Services','NET-Framework-45-Features','NET-Framework-45-Core','PowerShellRoot','PowerShell','PowerShell-ISE','WoW64-Support','Windows-Defender','Windows-Defender-Features','Server-Gui-Mgmt-Infra','Server-Gui-Shell','User-Interfaces-Infra')
# Shares that must never be removed.
$script:AlwaysKeepShares = @('SYSVOL','NETLOGON','CertEnroll')

function Resolve-LabConfigPath {
    param([string]$Path, [string]$ScriptDirectory)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ([string]::IsNullOrWhiteSpace($ScriptDirectory)) {
            throw 'Cannot locate server.config.json. Save the complete .ps1 file and run it with powershell.exe -File, or provide -ConfigPath explicitly.'
        }
        $Path = Join-Path -Path $ScriptDirectory -ChildPath 'server.config.json'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Lab configuration file not found: $Path. Extract the entire package or provide -ConfigPath with the JSON file location."
    }
    $resolved = Resolve-Path -LiteralPath $Path
    if ($resolved.Provider.Name -ne 'FileSystem') { throw 'ConfigPath must identify a JSON file on the filesystem.' }
    return $resolved.ProviderPath
}

function Assert-ProfileProperties {
    param($Value, [string[]]$Names, [string]$Context)
    if ($null -eq $Value -or $Value -isnot [System.Management.Automation.PSCustomObject]) {
        throw "$Context must be a JSON object."
    }
    $missing = @($Names | Where-Object { -not $Value.PSObject.Properties[$_] })
    if ($missing.Count) { throw "${Context} is missing required fields: $($missing -join ', ')." }
    $unknown = @($Value.PSObject.Properties.Name | Where-Object { $_ -notin $Names })
    if ($unknown.Count) { throw "${Context} has unsupported fields (check spelling): $($unknown -join ', ')." }
}

function Assert-ProfileInteger {
    param($Value, [string]$Name)
    if ($Value -isnot [int] -and $Value -isnot [long]) { throw "$Name must be a JSON integer, not quoted text or a decimal." }
}

function Test-LabProfile {
    param($Profile)
    $lists = @('Administrators','Users','CreateUsers','ResetPasswordAccounts','RemoteDesktopUsers','RequiredServiceNames','DisableServiceNames','RequiredFeatureNames','RemoveFeatureNames','AllowedShareNames','ProtectedApplicationPatterns','ReviewApplicationPatterns','ApplicationPackageIds','AuditSubcategories','MediaExtensions','ReviewExecutableNames')
    Assert-ProfileProperties $Profile (@('SchemaVersion','PrimaryAccount','PasswordPolicy','RemoveNonSystemShares','LockAfterSeconds') + $lists) 'Profile'
    Assert-ProfileInteger $Profile.SchemaVersion 'SchemaVersion'
    if ($Profile.SchemaVersion -ne 1) { throw 'Unsupported profile schema.' }
    if ($Profile.PrimaryAccount -isnot [string] -or [string]::IsNullOrWhiteSpace($Profile.PrimaryAccount)) { throw 'PrimaryAccount must be a nonempty account name.' }
    if ($Profile.RemoveNonSystemShares -isnot [bool]) { throw 'RemoveNonSystemShares must be JSON true or false, without quotes.' }
    Assert-ProfileInteger $Profile.LockAfterSeconds 'LockAfterSeconds'
    if ($Profile.LockAfterSeconds -lt 1 -or $Profile.LockAfterSeconds -gt 599940) { throw 'LockAfterSeconds must be between 1 and 599940.' }
    foreach ($field in $lists) {
        if ($Profile.$field -isnot [array]) { throw "$field must be a JSON array, including when empty or containing one item." }
        foreach ($value in $Profile.$field) {
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value -ne $value.Trim()) { throw "$field entries must be nonempty strings without surrounding spaces." }
        }
        if (@($Profile.$field | Sort-Object -Unique).Count -ne @($Profile.$field).Count) { throw "$field contains repeated entries." }
    }
    $all = @($Profile.Administrators) + @($Profile.Users)
    if (@($all | Where-Object { $_ -like 'CHANGEME*' }).Count -or $Profile.PrimaryAccount -like 'CHANGEME*') {
        throw 'server.config.json still contains CHANGEME placeholder accounts. Fill in the authorized administrators and users from the README first.'
    }
    if (@($Profile.Administrators).Count -eq 0 -or $Profile.PrimaryAccount -notin $Profile.Administrators) {
        throw 'PrimaryAccount must be an authorized administrator.'
    }
    if (@($all | Sort-Object -Unique).Count -ne $all.Count) { throw 'Account names overlap or repeat.' }
    foreach ($name in $all) {
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,19}$') { throw "Invalid account name: $name" }
    }
    foreach ($name in @($Profile.CreateUsers) + @($Profile.ResetPasswordAccounts) + @($Profile.RemoteDesktopUsers)) {
        if ($name -notin $all) { throw "Account is not authorized: $name" }
    }
    $p = $Profile.PasswordPolicy
    $policyFields = @('MinimumLength','GeneratedLength','History','MinimumAgeDays','MaximumAgeDays','LockoutThreshold','LockoutMinutes','ResetCounterMinutes')
    Assert-ProfileProperties $p $policyFields 'PasswordPolicy'
    foreach ($field in $policyFields) { Assert-ProfileInteger $p.$field "PasswordPolicy.$field" }
    if ($p.MinimumLength -ne 14 -or $p.GeneratedLength -lt $p.MinimumLength -or $p.GeneratedLength -gt 128) {
        throw 'This profile requires MinimumLength 14 and generated passwords of 14-128 characters.'
    }
    if ($p.History -lt 1 -or $p.History -gt 24 -or $p.MinimumAgeDays -lt 0 -or $p.MaximumAgeDays -gt 999 -or $p.MaximumAgeDays -le $p.MinimumAgeDays) {
        throw 'Invalid password history or expiration interval.'
    }
    if ($p.LockoutThreshold -lt 1 -or $p.LockoutThreshold -gt 999 -or $p.ResetCounterMinutes -lt 1 -or $p.ResetCounterMinutes -gt 99999 -or $p.LockoutMinutes -lt $p.ResetCounterMinutes -or $p.LockoutMinutes -gt 99999) {
        throw 'Invalid account lockout policy.'
    }
    foreach ($name in @($Profile.DisableServiceNames) + @($Profile.RequiredServiceNames)) {
        if ($name -notmatch '^[A-Za-z0-9_.$-]+$') { throw 'Service entries must be simple exact names, not patterns.' }
    }
    foreach ($name in $Profile.DisableServiceNames) {
        if ($name -in $script:EssentialServices -or $name -match '(?i)ccs|cyberpatriot|vmtools|vbox') { throw "Protected service in disable list: $name" }
    }
    foreach ($name in @($Profile.RemoveFeatureNames) + @($Profile.RequiredFeatureNames)) {
        if ($name -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Feature entries must be simple exact names (Get-WindowsFeature Name column), not patterns.' }
    }
    foreach ($name in $Profile.RemoveFeatureNames) {
        if ($name -in $script:ProtectedFeatures) { throw "Protected feature in remove list: $name" }
    }
    foreach ($id in $Profile.ApplicationPackageIds) {
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.+-]*$') { throw "Invalid exact application package ID: $id" }
    }
    foreach ($extension in $Profile.MediaExtensions) {
        if ($extension -notmatch '^\.[A-Za-z0-9]+$') { throw "Invalid media extension: $extension" }
    }
    foreach ($name in $Profile.ReviewExecutableNames) {
        if ($name -notmatch '^[^\\/:*?"<>|]+\.exe$') { throw "ReviewExecutableNames must contain exact .exe filenames: $name" }
    }
    foreach ($name in $Profile.RequiredServiceNames) {
        $dependencies = switch ($name) {
            'W3SVC' { 'Web-Server' }
            'WAS' { 'Web-Server' }
            'FTPSVC' { 'Web-Server'; 'Web-Ftp-Server'; 'Web-Ftp-Service' }
            'WMSVC' { 'Web-Server'; 'Web-Mgmt-Service' }
            'DNS' { 'DNS' }
            'DHCPServer' { 'DHCP' }
            'Spooler' { 'Print-Services' }
            'SNMP' { 'SNMP-Service' }
            'TermService' { }
        }
        foreach ($feature in $dependencies) {
            if ($feature -in $Profile.RemoveFeatureNames -and $feature -notin $Profile.RequiredFeatureNames) {
                throw "Required service $name conflicts with removing feature $feature. Review the service and feature requirements together."
            }
        }
    }
    if (@($Profile.RemoteDesktopUsers).Count -and 'TermService' -notin $Profile.RequiredServiceNames) {
        throw 'RemoteDesktopUsers is filled in but TermService is not in RequiredServiceNames. Add TermService if RDP is a critical service, or empty RemoteDesktopUsers.'
    }
}

function Assert-LabCapabilities {
    param([string[]]$CommandNames)
    $missing = @(foreach ($name in $CommandNames | Sort-Object -Unique) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) { $name }
    })
    if ($missing.Count) { throw "Required commands are unavailable: $($missing -join ', '). Use elevated 64-bit Windows PowerShell 5.1 and verify the relevant Windows components (RSAT AD PowerShell on a DC) before Apply." }
}

function Get-AccountDisposition {
    param([string]$Name, [string]$Sid, $Profile, [string[]]$ProtectedNames)
    if ($Name -in $ProtectedNames) { return 'Protected' }
    $rid = [int64]($Sid.Split('-')[-1])
    if ($rid -eq 501) { return 'DisableGuest' }
    if ($rid -eq 500) { return 'DisableBuiltinAdministrator' }
    if ($rid -lt 1000) { return 'PreserveBuiltin' }   # includes krbtgt (502) on a DC
    if ($Name -in $Profile.Administrators) { return 'Administrator' }
    if ($Name -in $Profile.Users) { return 'StandardUser' }
    return 'DisableUnauthorized'
}

function Get-CryptoIndex {
    param([Security.Cryptography.RandomNumberGenerator]$Rng, [int]$Limit)
    $bytes = New-Object byte[] 4
    $range = [uint64][uint32]::MaxValue + 1
    $ceiling = $range - ($range % [uint64]$Limit)
    do { $Rng.GetBytes($bytes); $n = [uint64][BitConverter]::ToUInt32($bytes, 0) } while ($n -ge $ceiling)
    return [int]($n % [uint64]$Limit)
}

function New-LabPassword {
    param([int]$Length = 24)
    if ($Length -lt 14 -or $Length -gt 128) { throw 'Password length must be 14-128.' }
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ','abcdefghijkmnopqrstuvwxyz','23456789','!@#%+-_=')
    $alphabet = $sets -join ''
    $chars = New-Object char[] $Length
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        for ($i = 0; $i -lt $sets.Count; $i++) { $chars[$i] = $sets[$i][(Get-CryptoIndex $rng $sets[$i].Length)] }
        for ($i = $sets.Count; $i -lt $Length; $i++) { $chars[$i] = $alphabet[(Get-CryptoIndex $rng $alphabet.Length)] }
        for ($i = $Length - 1; $i -gt 0; $i--) {
            $j = Get-CryptoIndex $rng ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }
        $secure = New-Object Security.SecureString
        foreach ($char in $chars) { $secure.AppendChar($char) }
        $secure.MakeReadOnly()
        return $secure
    } finally { [Array]::Clear($chars, 0, $chars.Length); $rng.Dispose() }
}

function Write-LabWarning {
    param([string]$Message)
    $script:Warnings.Add($Message)
    Write-Warning $Message
}

function Save-Json {
    param([string]$Name, $Value)
    ConvertTo-Json -InputObject $Value -Depth 12 | Set-Content -LiteralPath (Join-Path $script:RunPath $Name) -Encoding UTF8
}

function Invoke-Native {
    param([string]$Program, [string[]]$Arguments, [string]$OutputPath = '')
    $command = Get-Command -Name $Program -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $savedPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 can turn redirected stderr into an error even
        # when a native tool succeeds. Preserve both streams and check its exit.
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = $null
        $output = & $command.Source @Arguments 2>&1
        $exitCode = $global:LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($OutputPath) { $output | Set-Content -LiteralPath $OutputPath -Encoding UTF8 }
    if ($null -eq $exitCode) { throw "$Program did not return a native exit code." }
    if ($exitCode -ne 0) { throw "$Program failed ($exitCode): $($output -join ' ')" }
    return $output
}

function Invoke-LabChange {
    param([string]$Id, [string]$Target, [string]$Description, [scriptblock]$Action)
    $status = 'Planned'; $detail = ''
    if ($Mode -eq 'Apply' -and $script:Runner.ShouldProcess($Target, $Description)) {
        Write-Host "[Applying] $Description : $Target"
        try { & $Action | Out-Null; $status = 'Applied' }
        catch { $status = 'Failed'; $detail = $_.Exception.Message; Write-LabWarning "$Id failed: $detail" }
    }
    $script:Changes.Add([pscustomobject]@{Id=$Id; Target=$Target; Description=$Description; Status=$status; Detail=$detail})
    Write-Host "[$status] $Description : $Target"
}

function Test-ServiceExists {
    param([string]$Name)
    return [bool](Get-Service -Name $Name -ErrorAction SilentlyContinue)
}

# ---------------------------------------------------------------- inventory

function Get-PrivilegedGroupSpecs {
    # Returns the privileged AD groups to inspect/correct on a DC.
    $d = $script:DomainSid
    @(
        [pscustomobject]@{Identity="$d-512"; Label='Domain Admins'; Tier='Admin'}
        [pscustomobject]@{Identity="$d-519"; Label='Enterprise Admins'; Tier='Admin'}
        [pscustomobject]@{Identity="$d-518"; Label='Schema Admins'; Tier='Admin'}
        [pscustomobject]@{Identity='S-1-5-32-544'; Label='Administrators'; Tier='Admin'}
        [pscustomobject]@{Identity="$d-520"; Label='Group Policy Creator Owners'; Tier='Empty'}
        [pscustomobject]@{Identity='S-1-5-32-548'; Label='Account Operators'; Tier='Empty'}
        [pscustomobject]@{Identity='S-1-5-32-549'; Label='Server Operators'; Tier='Empty'}
        [pscustomobject]@{Identity='S-1-5-32-550'; Label='Print Operators'; Tier='Empty'}
        [pscustomobject]@{Identity='S-1-5-32-551'; Label='Backup Operators'; Tier='Empty'}
        [pscustomobject]@{Identity='DnsAdmins'; Label='DnsAdmins'; Tier='Empty'}
        [pscustomobject]@{Identity='S-1-5-32-546'; Label='Guests'; Tier='Guests'}
        [pscustomobject]@{Identity='S-1-5-32-555'; Label='Remote Desktop Users'; Tier='Rdp'}
    )
}

function Save-Inventory {
    param([string]$Prefix)
    $collectors = [ordered]@{
        services = { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName }
        tasks = { Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author,@{n='User';e={$_.Principal.UserId}},@{n='Actions';e={@($_.Actions | Select-Object Execute,Arguments,WorkingDirectory)}} }
        startup = { Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User }
        listeners = { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess }
        udp = { Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess }
        processes = { Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath }
        shares = { Get-SmbShare | Select-Object Name,Path,Description,Special,@{n='Access';e={@(Get-SmbShareAccess -Name $_.Name | Select-Object AccountName,AccessControlType,AccessRight)}} }
        firewall = { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,LogBlocked,LogFileName }
        defender = { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected }
        eventlog = { Get-WinEvent -ListLog Security | Select-Object LogName,IsEnabled,MaximumSizeInBytes,LogMode }
        exclusions = { Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess,DisableRealtimeMonitoring,PUAProtection }
        features = { Get-WindowsFeature | Where-Object { $_.Installed } | Select-Object Name,DisplayName,FeatureType }
        logons = { Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625,4720,4728,4732,4740,4756;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 300 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message }
        dnszones = { if (Test-ServiceExists 'DNS') { Get-DnsServerZone | Select-Object ZoneName,ZoneType,IsDsIntegrated,IsAutoCreated,DynamicUpdate,SecureSecondaries } }
    }
    if ($script:IsDC) {
        $collectors['users'] = { Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,PasswordNotRequired,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,UseDESKeyOnly,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,PasswordLastSet,LastLogonDate,Description | Select-Object SamAccountName,Enabled,@{n='SID';e={$_.SID.Value}},DistinguishedName,PasswordNeverExpires,PasswordNotRequired,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,UseDESKeyOnly,TrustedForDelegation,TrustedToAuthForDelegation,@{n='SPNs';e={@($_.ServicePrincipalName)}},PasswordLastSet,LastLogonDate,Description }
        $collectors['groups'] = { foreach ($spec in Get-PrivilegedGroupSpecs) { try { foreach ($m in Get-ADGroupMember -Identity $spec.Identity) { [pscustomobject]@{Group=$spec.Label; Member=$m.SamAccountName; SID=$m.SID.Value; ObjectClass=$m.objectClass} } } catch { Write-LabWarning "Cannot read group $($spec.Label): $($_.Exception.Message)" } } }
        $collectors['gpos'] = { if (Get-Command Get-GPO -ErrorAction SilentlyContinue) { Get-GPO -All | Select-Object DisplayName,Id,GpoStatus,CreationTime,ModificationTime } }
        $collectors['gpolinks'] = { if (Get-Command Get-GPInheritance -ErrorAction SilentlyContinue) { (Get-GPInheritance -Target $script:Domain.DistinguishedName).GpoLinks | Select-Object DisplayName,GpoId,Enabled,Enforced,Order } }
        $collectors['delegation'] = { Get-ADComputer -Filter * -Properties TrustedForDelegation,TrustedToAuthForDelegation | Select-Object Name,DistinguishedName,TrustedForDelegation,TrustedToAuthForDelegation }
    } else {
        $collectors['users'] = { Get-LocalUser | Select-Object Name,Enabled,SID,PrincipalSource,PasswordRequired,PasswordExpires,PasswordLastSet,UserMayChangePassword,LastLogon }
        $collectors['groups'] = { foreach ($g in Get-LocalGroup) { try { foreach ($m in Get-LocalGroupMember -Group $g.Name) { [pscustomobject]@{Group=$g.Name; Member=$m.Name; SID=[string]$m.SID; ObjectClass=$m.ObjectClass} } } catch { Write-LabWarning "Cannot read group $($g.Name): $($_.Exception.Message)" } } }
    }
    foreach ($entry in $collectors.GetEnumerator()) {
        try { Save-Json "$Prefix-$($entry.Key).json" @(& $entry.Value) }
        catch { Write-LabWarning "Inventory $($entry.Key): $($_.Exception.Message)" }
    }
    Invoke-Native 'auditpol.exe' @('/get','/category:*','/r') | Set-Content (Join-Path $script:RunPath "$Prefix-audit.csv")
    Invoke-Native 'net.exe' @('accounts') | Set-Content (Join-Path $script:RunPath "$Prefix-password-policy.txt")
}

function Get-ApplicationInventory {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($path in $paths) {
        foreach ($app in Get-ItemProperty -Path $path -ErrorAction SilentlyContinue) {
            if (-not $app.PSObject.Properties['DisplayName'] -or -not $app.DisplayName) { continue }
            $protected = $false; $review = $false
            foreach ($pattern in $script:Profile.ProtectedApplicationPatterns) { if ($app.DisplayName -like $pattern) { $protected = $true } }
            foreach ($pattern in $script:Profile.ReviewApplicationPatterns) { if ($app.DisplayName -like $pattern) { $review = $true } }
            [pscustomobject]@{
                Name=$app.DisplayName
                Version=$(if ($app.PSObject.Properties['DisplayVersion']) {$app.DisplayVersion} else {''})
                RegistryPath=$app.PSPath
                Protected=$protected
                Review=($review -and -not $protected)
            }
        }
    }
}

# ---------------------------------------------------------------- registry

function Set-RegistrySetting {
    param($Setting)
    if (-not (Test-Path -LiteralPath $Setting.Path)) { New-Item -Path $Setting.Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Setting.Path -Name $Setting.Name -Value $Setting.Value -PropertyType $Setting.Type -Force | Out-Null
}

function New-RegistryPlan {
    $system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $netlogon = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $lmServer = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $lmWork = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $esc = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
    $settings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in @(
        @($system,'EnableLUA',1), @($system,'ConsentPromptBehaviorAdmin',2),
        @($system,'PromptOnSecureDesktop',1), @($system,'FilterAdministratorToken',1),
        @($system,'DisableCAD',0), @($system,'DontDisplayLastUserName',1),
        @($system,'InactivityTimeoutSecs',[int]$script:Profile.LockAfterSeconds),
        @($lsa,'RestrictAnonymous',1), @($lsa,'RestrictAnonymousSAM',1),
        @($lsa,'EveryoneIncludesAnonymous',0), @($lsa,'LimitBlankPasswordUse',1),
        @($lsa,'NoLMHash',1), @($lsa,'LmCompatibilityLevel',5), @($lsa,'DisableDomainCreds',1),
        @($lsa,'SCENoApplyLegacyAuditPolicy',1),
        @($lmServer,'RequireSecuritySignature',1), @($lmServer,'EnableSecuritySignature',1),
        @($lmWork,'RequireSecuritySignature',1), @($lmWork,'EnableSecuritySignature',1),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance','fAllowToGetHelp',0),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoDriveTypeAutoRun',255),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutorun',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer','NoAutoplayfornonVolume',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\System','EnableSmartScreen',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging','EnableModuleLogging',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','NoAutoUpdate',0),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','AUOptions',2),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','NoAutoRebootWithLoggedOnUsers',1),
        # IE Enhanced Security Configuration on for Administrators and Users
        @("$esc\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}",'IsInstalled',1),
        @("$esc\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}",'IsInstalled',1),
        @('HKLM:\SOFTWARE\Policies\Google\Chrome','SafeBrowsingProtectionLevel',1),
        @('HKLM:\SOFTWARE\Policies\Google\Chrome','DefaultPopupsSetting',2),
        @('HKLM:\SOFTWARE\Policies\Google\Chrome','DownloadRestrictions',4)
    )) { $settings.Add($s) }

    if ($script:RdpRequired) {
        # RDP is critical: keep it on but require NLA, TLS and high encryption.
        $settings.Add(@($ts,'fDenyTSConnections',0))
        $settings.Add(@($rdpTcp,'UserAuthentication',1))
        $settings.Add(@($rdpTcp,'SecurityLayer',2))
        $settings.Add(@($rdpTcp,'MinEncryptionLevel',3))
    } else {
        $settings.Add(@($ts,'fDenyTSConnections',1))
    }
    if ($script:IsDC) {
        $settings.Add(@($netlogon,'FullSecureChannelProtection',1))   # Zerologon (CVE-2020-1472)
        $settings.Add(@($netlogon,'RequireSignOrSeal',1))
        $settings.Add(@($netlogon,'SealSecureChannel',1))
        $settings.Add(@($netlogon,'SignSecureChannel',1))
        $settings.Add(@($netlogon,'RequireStrongKey',1))
        $settings.Add(@($ntds,'LDAPServerIntegrity',2))               # LDAP signing required
        $settings.Add(@($ntds,'LdapEnforceChannelBinding',2))         # LDAP channel binding always
        $settings.Add(@($lsa,'SubmitControl',0))                      # Server Operators cannot schedule tasks
    }
    if ($script:HasDnsServer) {
        $settings.Add(@('HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters','TcpReceivePacketSize',65280))  # SIGRed (CVE-2020-1350), 0xFF00
    }
    foreach ($s in $settings) { [pscustomobject]@{Path=$s[0];Name=$s[1];Value=$s[2];Type='DWord'} }
    [pscustomobject]@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';Name='ShellSmartScreenLevel';Value='Warn';Type='String'}
    [pscustomobject]@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames';Name='*';Value='*';Type='String'}
}

# Registry settings that are "Security Options". On a DC they are also written into the
# Default Domain Controllers Policy so Group Policy refresh does not revert them.
$script:GpoSecurityOptionNames = @('EnableLUA','ConsentPromptBehaviorAdmin','PromptOnSecureDesktop','FilterAdministratorToken','DisableCAD','DontDisplayLastUserName','InactivityTimeoutSecs','RestrictAnonymous','RestrictAnonymousSAM','EveryoneIncludesAnonymous','LimitBlankPasswordUse','NoLMHash','LmCompatibilityLevel','DisableDomainCreds','SCENoApplyLegacyAuditPolicy','SubmitControl','RequireSignOrSeal','SealSecureChannel','SignSecureChannel','RequireStrongKey','LDAPServerIntegrity','RequireSecuritySignature','EnableSecuritySignature')

function Get-GpoRegistryValues {
    param([object[]]$Plan)
    $values = [ordered]@{}
    foreach ($s in $Plan) {
        if ($s.Type -ne 'DWord' -or $s.Name -notin $script:GpoSecurityOptionNames) { continue }
        if ($s.Path -notmatch '^HKLM:\\(SYSTEM\\CurrentControlSet\\(Control\\Lsa|Services\\(Netlogon|NTDS|LanmanServer|LanmanWorkstation)\\Parameters)|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System)$') { continue }
        $key = ($s.Path -replace '^HKLM:\\', 'MACHINE\') + '\' + $s.Name
        $values[$key] = "4,$($s.Value)"
    }
    return $values
}

function Save-RegistryBefore {
    param([object[]]$Settings)
    $before = foreach ($s in $Settings) {
        $key = Get-Item -LiteralPath $s.Path -ErrorAction SilentlyContinue
        $exists = $null -ne $key -and $s.Name -in $key.GetValueNames()
        [pscustomobject]@{
            Path=$s.Path; Name=$s.Name; Exists=$exists
            Type=$(if ($exists) {[string]$key.GetValueKind($s.Name)} else {$null})
            Value=$(if ($exists) {$key.GetValue($s.Name)} else {$null})
        }
    }
    Save-Json 'registry-before.json' @($before)
}

function Save-LabBackups {
    Invoke-Native 'secedit.exe' @('/export','/cfg',(Join-Path $script:RunPath 'security-before.inf'),'/areas','SECURITYPOLICY','USER_RIGHTS','/log',(Join-Path $script:RunPath 'security-export.log'),'/quiet') | Out-Null
    Invoke-Native 'auditpol.exe' @('/backup',("/file:{0}" -f (Join-Path $script:RunPath 'audit-before.csv'))) | Out-Null
    Invoke-Native 'netsh.exe' @('advfirewall','export',(Join-Path $script:RunPath 'firewall-before.wfw')) | Out-Null
    foreach ($file in @('security-before.inf','audit-before.csv','firewall-before.wfw')) {
        if (-not (Test-Path (Join-Path $script:RunPath $file))) { throw "Required backup missing: $file" }
    }
    if ($script:IsDC) {
        foreach ($guid in @($script:DefaultDomainPolicyGuid, $script:DefaultDcPolicyGuid)) {
            $inf = Join-Path $script:SysvolPolicies "{$guid}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            if (Test-Path -LiteralPath $inf) { Copy-Item -LiteralPath $inf -Destination (Join-Path $script:RunPath "gpo-$guid-GptTmpl-before.inf") -Force }
        }
        if (Get-Command Backup-GPO -ErrorAction SilentlyContinue) {
            $gpoBackup = Join-Path $script:RunPath 'gpo-backup'
            New-Item -Path $gpoBackup -ItemType Directory -Force | Out-Null
            try { Backup-GPO -All -Path $gpoBackup | Out-Null } catch { Write-LabWarning "Backup-GPO failed (GptTmpl.inf copies were still saved): $($_.Exception.Message)" }
        }
    }
}

# ---------------------------------------------------------------- GPO template editing (DC)

function Set-InfLine {
    param($List, [string]$Key, [string]$Line)
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    for ($i = 0; $i -lt $List.Count; $i++) { if ($List[$i] -match $pattern) { $List[$i] = $Line; return } }
    $List.Add($Line)
}

function Update-GpoSecurityTemplate {
    <#
      Edits a GPO's GptTmpl.inf in SYSVOL and bumps the GPO version (GPT.INI and AD)
      so domain controllers pick up the change at the next gpupdate.
      SystemAccess    : @{ MinimumPasswordLength = 14 }
      RegistryValues  : @{ 'MACHINE\System\...\Name' = '4,1' }
      PrivilegeRemove : @{ SeNetworkLogonRight = @('*S-1-1-0') }
      PrivilegeAdd    : @{ SeDenyNetworkLogonRight = @('*S-1-5-32-546') }
    #>
    param([string]$Guid, [hashtable]$SystemAccess = @{}, $RegistryValues = @{}, [hashtable]$PrivilegeRemove = @{}, [hashtable]$PrivilegeAdd = @{})
    $root = Join-Path $script:SysvolPolicies "{$Guid}"
    if (-not (Test-Path -LiteralPath $root)) { throw "GPO folder not found: $root" }
    $secDir = Join-Path $root 'MACHINE\Microsoft\Windows NT\SecEdit'
    if (-not (Test-Path -LiteralPath $secDir)) { New-Item -Path $secDir -ItemType Directory -Force | Out-Null }
    $inf = Join-Path $secDir 'GptTmpl.inf'
    $lines = if (Test-Path -LiteralPath $inf) { @(Get-Content -LiteralPath $inf) } else { @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1') }

    $sections = [ordered]@{}
    $current = ''
    $sections[''] = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $lines) {
        if ($line -match '^\s*\[(.+)\]\s*$') {
            $current = $Matches[1]
            if (-not $sections.Contains($current)) { $sections[$current] = New-Object 'System.Collections.Generic.List[string]' }
            continue
        }
        $sections[$current].Add($line)
    }
    foreach ($name in @('System Access','Registry Values','Privilege Rights')) {
        if (-not $sections.Contains($name)) { $sections[$name] = New-Object 'System.Collections.Generic.List[string]' }
    }
    foreach ($key in $SystemAccess.Keys) { Set-InfLine $sections['System Access'] $key "$key = $($SystemAccess[$key])" }
    foreach ($key in $RegistryValues.Keys) { Set-InfLine $sections['Registry Values'] $key "$key=$($RegistryValues[$key])" }
    $rights = @(@($PrivilegeRemove.Keys) + @($PrivilegeAdd.Keys) | Sort-Object -Unique)
    foreach ($right in $rights) {
        $existing = @($sections['Privilege Rights'] | Where-Object { $_ -match ('^\s*' + [regex]::Escape($right) + '\s*=') }) | Select-Object -First 1
        $principals = @()
        if ($existing) { $principals = @((($existing -split '=', 2)[1] -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        if ($PrivilegeRemove.ContainsKey($right)) { $principals = @($principals | Where-Object { $_ -notin $PrivilegeRemove[$right] }) }
        if ($PrivilegeAdd.ContainsKey($right)) { $principals = @(@($principals) + @($PrivilegeAdd[$right])) }
        $principals = @($principals | Sort-Object -Unique)
        Set-InfLine $sections['Privilege Rights'] $right "$right = $($principals -join ',')"
    }
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in $sections.Keys) {
        $body = @($sections[$key] | Where-Object { $_.Trim() })
        if ($key -ne '') {
            if ($body.Count -eq 0 -and $key -in @('System Access','Registry Values','Privilege Rights')) { continue }
            $out.Add("[$key]")
        }
        foreach ($l in $body) { $out.Add($l) }
    }
    Set-Content -LiteralPath $inf -Value $out -Encoding Unicode

    # Bump the computer half of the GPO version in both AD and GPT.INI.
    $dn = "CN={$Guid},CN=Policies,CN=System,$($script:Domain.DistinguishedName)"
    $adVersion = [int64](Get-ADObject -Identity $dn -Properties versionNumber).versionNumber
    $gptIni = Join-Path $root 'GPT.INI'
    $iniLines = if (Test-Path -LiteralPath $gptIni) { @(Get-Content -LiteralPath $gptIni) } else { @('[General]') }
    $iniVersion = [int64]0
    foreach ($l in $iniLines) { if ($l -match '^\s*Version\s*=\s*(\d+)') { $iniVersion = [int64]$Matches[1] } }
    $newVersion = [Math]::Max($adVersion, $iniVersion) + 1
    $found = $false
    $iniLines = @(foreach ($l in $iniLines) { if ($l -match '^\s*Version\s*=') { $found = $true; "Version=$newVersion" } else { $l } })
    if (-not $found) { $iniLines += "Version=$newVersion" }
    Set-Content -LiteralPath $gptIni -Value $iniLines -Encoding ASCII
    Set-ADObject -Identity $dn -Replace @{versionNumber = [int]$newVersion}
}

# ---------------------------------------------------------------- passwords / policy

function Set-LabPassword {
    param([string]$Name, [switch]$Create)
    if ($Name -in $script:ProtectedNames) { throw "Refusing to reset protected account $Name" }
    $password = New-LabPassword -Length $script:Profile.PasswordPolicy.GeneratedLength
    try {
        $credential = [System.Management.Automation.PSCredential]::new($Name, $password)
        # Windows DPAPI binds this encrypted file to this user on this VM.
        $pending = Join-Path $script:RunPath "$Name.pending.credential.xml"
        $credential | Export-Clixml -LiteralPath $pending -Force
        if ($script:IsDC) {
            if ($Create) {
                New-ADUser -Name $Name -SamAccountName $Name -UserPrincipalName "$Name@$($script:Domain.DNSRoot)" -AccountPassword $password -Enabled $true -Description 'Authorized lab employee' | Out-Null
                $script:CreatedNow.Add($Name)
            } else {
                Set-ADAccountPassword -Identity $Name -Reset -NewPassword $password
            }
        } else {
            if ($Create) {
                New-LocalUser -Name $Name -Password $password -Description 'Authorized lab employee' -AccountNeverExpires | Out-Null
                $script:CreatedNow.Add($Name)
            } else {
                $u = Get-LocalUser -Name $Name
                if ([string]$u.PrincipalSource -ne 'Local') { throw 'Password rotation supports local SAM accounts only.' }
                Set-LocalUser -Name $Name -Password $password
            }
        }
        Move-Item -LiteralPath $pending -Destination (Join-Path $script:RunPath "$Name.credential.xml") -Force
    } finally { $password.Dispose() }
}

function Set-AccountPolicy {
    # Local (non-DC) servers: local security policy through secedit.
    $p = $script:Profile.PasswordPolicy
    $guest = Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'} | Select-Object -First 1
    $guestSid = if ($guest) { [string]$guest.SID } else { '' }
    $denyGuest = @('*S-1-5-32-546')
    if ($guestSid) { $denyGuest += "*$guestSid" }
    $denyLines = foreach ($right in @('SeDenyInteractiveLogonRight','SeDenyNetworkLogonRight','SeDenyRemoteInteractiveLogonRight')) {
        $existing = Select-String -LiteralPath (Join-Path $script:RunPath 'security-before.inf') -Pattern "^$right\s*=" | Select-Object -First 1
        $principals = @($denyGuest)
        if ($existing) { $principals += @((($existing.Line -split '=',2)[1] -split ',') | ForEach-Object {$_.Trim()} | Where-Object {$_}) }
        "$right = $((@($principals | Sort-Object -Unique)) -join ',')"
    }
    # Remote Desktop Users keep RDP logon rights when RDP is critical.
    $rdpRight = if ($script:RdpRequired) { 'SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555' } else { 'SeRemoteInteractiveLogonRight = *S-1-5-32-544' }
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordAge = $($p.MinimumAgeDays)
MaximumPasswordAge = $($p.MaximumAgeDays)
MinimumPasswordLength = $($p.MinimumLength)
PasswordComplexity = 1
PasswordHistorySize = $($p.History)
ClearTextPassword = 0
LockoutBadCount = $($p.LockoutThreshold)
ResetLockoutCount = $($p.ResetCounterMinutes)
LockoutDuration = $($p.LockoutMinutes)
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
$rdpRight
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-6,*S-1-5-19,*S-1-5-20
SeDebugPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
SeTakeOwnershipPrivilege = *S-1-5-32-544
$($denyLines -join "`r`n")
"@
    $path = Join-Path $script:RunPath 'security-target.inf'
    $inf | Set-Content -LiteralPath $path -Encoding Unicode
    Invoke-Native 'secedit.exe' @('/configure','/db',(Join-Path $script:RunPath 'security-target.sdb'),'/cfg',$path,'/overwrite','/areas','SECURITYPOLICY','USER_RIGHTS','/log',(Join-Path $script:RunPath 'security-apply.log'),'/quiet') | Out-Null
}

function Set-DomainAccountPolicy {
    # DC: domain password/lockout lives in the Default Domain Policy, not in local secpol.
    $p = $script:Profile.PasswordPolicy
    Set-ADDefaultDomainPasswordPolicy -Identity $script:Domain.DNSRoot `
        -MinPasswordLength $p.MinimumLength -PasswordHistoryCount $p.History -ComplexityEnabled $true -ReversibleEncryptionEnabled $false `
        -MinPasswordAge ([TimeSpan]::FromDays($p.MinimumAgeDays)) -MaxPasswordAge ([TimeSpan]::FromDays($p.MaximumAgeDays)) `
        -LockoutThreshold $p.LockoutThreshold -LockoutDuration ([TimeSpan]::FromMinutes($p.LockoutMinutes)) -LockoutObservationWindow ([TimeSpan]::FromMinutes($p.ResetCounterMinutes))
    # Write the same values into the Default Domain Policy GPO so a policy refresh does not revert them.
    Update-GpoSecurityTemplate -Guid $script:DefaultDomainPolicyGuid -SystemAccess @{
        MinimumPasswordAge = $p.MinimumAgeDays; MaximumPasswordAge = $p.MaximumAgeDays
        MinimumPasswordLength = $p.MinimumLength; PasswordComplexity = 1; PasswordHistorySize = $p.History
        ClearTextPassword = 0; LockoutBadCount = $p.LockoutThreshold; ResetLockoutCount = $p.ResetCounterMinutes; LockoutDuration = $p.LockoutMinutes
    }
}

function Set-DomainControllerPolicy {
    param([object[]]$Plan)
    # Security options + selected user rights go into the Default Domain Controllers Policy.
    Update-GpoSecurityTemplate -Guid $script:DefaultDcPolicyGuid -RegistryValues (Get-GpoRegistryValues $Plan) `
        -PrivilegeRemove @{ SeNetworkLogonRight = @('*S-1-1-0','*S-1-5-32-554') } `
        -PrivilegeAdd @{ SeDenyNetworkLogonRight = @('*S-1-5-32-546'); SeDenyInteractiveLogonRight = @('*S-1-5-32-546'); SeDenyRemoteInteractiveLogonRight = @('*S-1-5-32-546') }
}

# ---------------------------------------------------------------- account hardening

function Invoke-LocalAccountHardening {
    $allAuthorized = @($script:Profile.Administrators) + @($script:Profile.Users)
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
    foreach ($name in $script:Profile.CreateUsers) {
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
            Invoke-LabChange 'CreateUser' $name 'Create authorized employee with a unique encrypted-record password' { Set-LabPassword -Name $name -Create }
        }
    }
    foreach ($user in Get-LocalUser) {
        $name = $user.Name
        $disposition = Get-AccountDisposition $name ([string]$user.SID) $script:Profile $script:ProtectedNames
        if ($disposition -like 'Disable*') {
            if ($user.Enabled) { Invoke-LabChange 'DisableUser' $name $disposition { Disable-LocalUser -Name $name } }
            continue
        }
        if ($disposition -eq 'PreserveBuiltin') { continue }
        if ($name -notin $allAuthorized) { continue }
        $passwordReady = $true
        if ($name -notin $script:ProtectedNames -and ($RotatePasswords -or $name -in $script:Profile.ResetPasswordAccounts) -and $name -notin $script:CreatedNow) {
            Invoke-LabChange 'RotatePassword' $name 'Rotate to a unique random password; save a Windows DPAPI credential file' { Set-LabPassword -Name $name }
            if ($Mode -eq 'Apply' -and $script:Changes[$script:Changes.Count - 1].Status -eq 'Failed') { $passwordReady = $false }
        }
        if (-not $user.Enabled -and $passwordReady) { Invoke-LabChange 'EnableAuthorizedUser' $name 'Enable authorized account' { Enable-LocalUser -Name $name } }
        if (-not $passwordReady -and -not $user.Enabled) { Write-LabWarning "Account $name stays disabled because its password reset failed." }
        Invoke-LabChange 'UserFlags' $name 'Require a password, enable expiration and allow password changes' {
            Set-LocalUser -Name $name -PasswordNeverExpires $false -UserMayChangePassword $true
            Invoke-Native 'net.exe' @('user',$name,'/passwordreq:yes') | Out-Null
        }
        Invoke-LabChange 'UsersMembership' $name 'Ensure authorized account belongs to local Users' {
            $sid = [string](Get-LocalUser -Name $name).SID
            if ($sid -notin @(Get-LocalGroupMember $usersGroup.Name | ForEach-Object {[string]$_.SID})) { Add-LocalGroupMember -Group $usersGroup.Name -Member $name }
        }
        if ($name -in $script:Profile.Administrators) {
            Invoke-LabChange 'AdminMembership' $name 'Ensure authorized administrator membership' {
                $sid = [string](Get-LocalUser -Name $name).SID
                if ($sid -notin @(Get-LocalGroupMember $adminGroup.Name | ForEach-Object {[string]$_.SID})) { Add-LocalGroupMember -Group $adminGroup.Name -Member $name }
            }
        }
    }
    foreach ($name in $allAuthorized) {
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) -and $name -notin $script:Profile.CreateUsers) { Write-LabWarning "Authorized account $name is absent; review rather than inventing an account." }
    }
    foreach ($member in Get-LocalGroupMember -Group $adminGroup.Name) {
        if ([string]$member.SID -match '-500$') { continue }
        if ([string]$member.PrincipalSource -ne 'Local') { Write-LabWarning "Administrators contains non-local member $($member.Name); review it manually (domain groups are not removed automatically)."; continue }
        $shortName = $member.Name.Split('\')[-1]
        if ($shortName -notin $script:Profile.Administrators -and $shortName -notin $script:ProtectedNames) {
            Invoke-LabChange 'RemoveAdmin' $member.Name 'Remove unauthorized administrator membership' { Remove-LocalGroupMember -Group $adminGroup.Name -Member $member }
        }
    }
    # Power Users, Backup Operators and Guests are cleared; Remote Desktop Users follows the profile.
    foreach ($groupSid in @('S-1-5-32-547','S-1-5-32-551','S-1-5-32-546','S-1-5-32-555')) {
        $group = Get-LocalGroup -SID $groupSid -ErrorAction SilentlyContinue
        if (-not $group) { continue }
        foreach ($member in Get-LocalGroupMember -Group $group.Name) {
            if ([string]$member.SID -match '-501$' -and $groupSid -eq 'S-1-5-32-546') { continue }
            $shortName = $member.Name.Split('\')[-1]
            if ($groupSid -eq 'S-1-5-32-555' -and $shortName -in $script:Profile.RemoteDesktopUsers) { continue }
            Invoke-LabChange 'RemovePrivilege' "$($group.Name): $($member.Name)" 'Remove unneeded privileged/guest group membership' { Remove-LocalGroupMember -Group $group.Name -Member $member }
        }
    }
    $rdpGroup = Get-LocalGroup -SID 'S-1-5-32-555' -ErrorAction SilentlyContinue
    if ($rdpGroup) {
        foreach ($name in $script:Profile.RemoteDesktopUsers) {
            if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) { continue }
            Invoke-LabChange 'RdpMembership' $name 'Ensure README-authorized Remote Desktop user membership' {
                $sid = [string](Get-LocalUser -Name $name).SID
                if ($sid -notin @(Get-LocalGroupMember $rdpGroup.Name | ForEach-Object {[string]$_.SID})) { Add-LocalGroupMember -Group $rdpGroup.Name -Member $name }
            }
        }
    }
}

function Invoke-DomainAccountHardening {
    $allAuthorized = @($script:Profile.Administrators) + @($script:Profile.Users)
    $domainAdmins = "$($script:DomainSid)-512"
    foreach ($name in $script:Profile.CreateUsers) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue)) {
            Invoke-LabChange 'CreateUser' $name 'Create authorized AD user with a unique encrypted-record password' { Set-LabPassword -Name $name -Create }
        }
    }
    $adUsers = @(Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,PasswordNotRequired,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,UseDESKeyOnly,TrustedForDelegation,TrustedToAuthForDelegation,CannotChangePassword,ServicePrincipalName)
    foreach ($user in $adUsers) {
        $name = $user.SamAccountName
        $dn = $user.DistinguishedName
        $disposition = Get-AccountDisposition $name $user.SID.Value $script:Profile $script:ProtectedNames
        if ($disposition -like 'Disable*') {
            if ($user.Enabled) { Invoke-LabChange 'DisableUser' $name $disposition { Disable-ADAccount -Identity $dn } }
            continue
        }
        if ($disposition -eq 'PreserveBuiltin') { continue }   # krbtgt and other built-ins
        if ($name -notin $allAuthorized -and $disposition -ne 'Protected') { continue }
        $passwordReady = $true
        if ($name -notin $script:ProtectedNames -and ($RotatePasswords -or $name -in $script:Profile.ResetPasswordAccounts) -and $name -notin $script:CreatedNow) {
            Invoke-LabChange 'RotatePassword' $name 'Rotate to a unique random password; save a Windows DPAPI credential file' { Set-LabPassword -Name $name }
            if ($Mode -eq 'Apply' -and $script:Changes[$script:Changes.Count - 1].Status -eq 'Failed') { $passwordReady = $false }
        }
        if (-not $user.Enabled -and $passwordReady) { Invoke-LabChange 'EnableAuthorizedUser' $name 'Enable authorized account' { Enable-ADAccount -Identity $dn } }
        if (-not $passwordReady -and -not $user.Enabled) { Write-LabWarning "Account $name stays disabled because its password reset failed." }
        $bad = @()
        if ($user.PasswordNeverExpires) { $bad += 'PasswordNeverExpires' }
        if ($user.PasswordNotRequired) { $bad += 'PasswordNotRequired' }
        if ($user.AllowReversiblePasswordEncryption) { $bad += 'ReversibleEncryption' }
        if ($user.DoesNotRequirePreAuth) { $bad += 'NoKerberosPreAuth' }
        if ($user.UseDESKeyOnly) { $bad += 'DESOnly' }
        if ($user.TrustedForDelegation) { $bad += 'UnconstrainedDelegation' }
        if ($user.TrustedToAuthForDelegation) { $bad += 'ProtocolTransition' }
        if ($user.CannotChangePassword) { $bad += 'CannotChangePassword' }
        if ($bad.Count) {
            Invoke-LabChange 'UserFlags' $name "Clear insecure account flags: $($bad -join ', ')" {
                Set-ADAccountControl -Identity $dn -PasswordNeverExpires $false -PasswordNotRequired $false -AllowReversiblePasswordEncryption $false -DoesNotRequirePreAuth $false -UseDESKeyOnly $false -TrustedForDelegation $false -TrustedToAuthForDelegation $false -CannotChangePassword $false
            }
        }
        if (@($user.ServicePrincipalName).Count) { Write-LabWarning "AD user $name has SPNs ($(@($user.ServicePrincipalName) -join '; ')) - Kerberoastable; confirm it is a README service account with a strong password." }
        if ($name -in $script:Profile.Administrators) {
            Invoke-LabChange 'AdminMembership' $name 'Ensure authorized administrator is in Domain Admins' {
                $members = @(Get-ADGroupMember -Identity $domainAdmins | ForEach-Object { $_.SID.Value })
                if ($user.SID.Value -notin $members) { Add-ADGroupMember -Identity $domainAdmins -Members $dn }
            }
        }
    }
    foreach ($name in $allAuthorized) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue) -and $name -notin $script:Profile.CreateUsers) { Write-LabWarning "Authorized account $name is absent from AD; review rather than inventing an account." }
    }
    # Privileged group cleanup. Only USER members are removed automatically; nested groups are reported.
    $expectedNested = @("$($script:DomainSid)-512","$($script:DomainSid)-519","$($script:DomainSid)-514")
    foreach ($spec in Get-PrivilegedGroupSpecs) {
        try { $group = Get-ADGroup -Identity $spec.Identity } catch { continue }
        try { $members = @(Get-ADGroupMember -Identity $group) } catch { Write-LabWarning "Cannot read members of $($spec.Label): $($_.Exception.Message)"; continue }
        foreach ($member in $members) {
            $sid = $member.SID.Value
            if ($member.objectClass -ne 'user') {
                if ($member.objectClass -eq 'group' -and $sid -notin $expectedNested) { Write-LabWarning "$($spec.Label) contains nested group $($member.SamAccountName); review it manually." }
                continue
            }
            $short = $member.SamAccountName
            $allowed = switch ($spec.Tier) {
                'Admin' { ($short -in $script:Profile.Administrators) -or ($short -in $script:ProtectedNames) -or ($sid -match '-500$') }
                'Empty' { ($spec.Label -eq 'Group Policy Creator Owners' -and $sid -match '-500$') }
                'Guests' { $sid -match '-501$' }
                'Rdp' { $short -in $script:Profile.RemoteDesktopUsers }
            }
            if (-not $allowed) {
                Invoke-LabChange 'RemovePrivilege' "$($spec.Label): $short" 'Remove unauthorized privileged AD group membership' { Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false }
            }
        }
    }
    foreach ($name in $script:Profile.RemoteDesktopUsers) {
        Invoke-LabChange 'RdpMembership' $name 'Ensure README-authorized Remote Desktop user membership' {
            $u = Get-ADUser -Identity $name
            $members = @(Get-ADGroupMember -Identity 'S-1-5-32-555' | ForEach-Object { $_.SID.Value })
            if ($u.SID.Value -notin $members) { Add-ADGroupMember -Identity 'S-1-5-32-555' -Members $u }
        }
    }
    # Unconstrained delegation on non-DC computers.
    $dcDns = @(Get-ADDomainController -Filter * | ForEach-Object { $_.ComputerObjectDN })
    foreach ($computer in @(Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation)) {
        if ($computer.DistinguishedName -in $dcDns) { continue }
        $cdn = $computer.DistinguishedName
        Invoke-LabChange 'ComputerDelegation' $computer.Name 'Remove unconstrained delegation from non-DC computer' { Set-ADAccountControl -Identity $cdn -TrustedForDelegation $false }
    }
}

# ---------------------------------------------------------------- roles / features / services

function Get-FeatureImpact {
    # Every installed feature that would be removed together with $Name (sub-features and dependents).
    param([string]$Name, [hashtable]$All)
    $impact = New-Object 'System.Collections.Generic.HashSet[string]'
    $queue = New-Object 'System.Collections.Generic.Queue[string]'
    $queue.Enqueue($Name)
    while ($queue.Count) {
        $n = $queue.Dequeue()
        if (-not $impact.Add($n)) { continue }
        $f = $All[$n]
        if ($f -and $f.SubFeatures) { foreach ($s in $f.SubFeatures) { $queue.Enqueue($s) } }
        foreach ($other in $All.Values) {
            if ($other.Installed -and $other.DependsOn -and $n -in @($other.DependsOn)) { $queue.Enqueue($other.Name) }
        }
    }
    return @($impact | Where-Object { $All[$_] -and $All[$_].Installed })
}

function Invoke-FeatureRemoval {
    $all = @{}
    try { foreach ($f in Get-WindowsFeature) { $all[$f.Name] = $f } }
    catch { Write-LabWarning "Cannot enumerate Windows features: $($_.Exception.Message)"; return }
    $keep = @($script:ProtectedFeatures) + @($script:Profile.RequiredFeatureNames)
    if ($script:IsDC) { $keep += @('DNS','AD-Domain-Services') }
    foreach ($name in $script:Profile.RemoveFeatureNames) {
        if ($name -in $script:Profile.RequiredFeatureNames) { continue }
        $feature = $all[$name]
        if (-not $feature -or -not $feature.Installed) { continue }
        $impact = @(Get-FeatureImpact $name $all)
        $blocked = @($impact | Where-Object { $_ -in $keep })
        $impactServices = @($impact | ForEach-Object { @($all[$_].SystemService) } | Where-Object { $_ })
        $blockedServices = @($impactServices | Where-Object { $_ -in $script:Profile.RequiredServiceNames })
        if ($blocked.Count -or $blockedServices.Count) {
            Write-LabWarning "Skipped removing $name because it would also remove required/protected item(s): $(@($blocked + $blockedServices) -join ', ')."
            continue
        }
        Invoke-LabChange 'RemoveFeature' $name "Uninstall unneeded role/feature (also removes: $(@($impact | Where-Object { $_ -ne $name }) -join ', '))" {
            $result = Uninstall-WindowsFeature -Name $name
            if (-not $result.Success) { throw "Uninstall-WindowsFeature reported failure (ExitCode $($result.ExitCode))." }
            if ([string]$result.RestartNeeded -ne 'No') { $script:RebootNeeded = $true }
        }
    }
}

function Invoke-DnsHardening {
    try { Import-Module DnsServer -ErrorAction Stop } catch { Write-LabWarning "DnsServer module unavailable; harden DNS zones manually in dnsmgmt.msc."; return }
    foreach ($zone in @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and [string]$_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })) {
        $zoneName = $zone.ZoneName
        $isDs = [bool]$zone.IsDsIntegrated
        $wantUpdate = if ($isDs) { 'Secure' } else { 'None' }
        if ([string]$zone.DynamicUpdate -ne $wantUpdate) {
            Invoke-LabChange 'DnsDynamicUpdate' $zoneName "Set dynamic updates to $wantUpdate (Secure only is available for AD-integrated zones)" { Set-DnsServerPrimaryZone -Name $zoneName -DynamicUpdate $wantUpdate }
        }
        if ([string]$zone.SecureSecondaries -ne 'NoTransfer') {
            Invoke-LabChange 'DnsZoneTransfer' $zoneName 'Disable zone transfers' { Set-DnsServerPrimaryZone -Name $zoneName -SecureSecondaries NoTransfer }
        }
    }
    Invoke-LabChange 'DnsRestart' 'DNS' 'Restart DNS Server so the SIGRed TcpReceivePacketSize value takes effect' { Restart-Service -Name DNS -Force }
}

function Invoke-IisHardening {
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    if (-not (Test-Path -LiteralPath $appcmd)) { return }
    if ('W3SVC' -in $script:Profile.RequiredServiceNames) {
        Invoke-LabChange 'IisDirectoryBrowse' 'IIS (server level)' 'Disable directory browsing' { Invoke-Native $appcmd @('set','config','/section:system.webServer/directoryBrowse','/enabled:false','/commit:apphost') | Out-Null }
    }
    if ('FTPSVC' -in $script:Profile.RequiredServiceNames) {
        Invoke-LabChange 'FtpAnonymousDefault' 'FTP site defaults' 'Disable anonymous FTP authentication' { Invoke-Native $appcmd @('set','config','-section:system.applicationHost/sites','/siteDefaults.ftpServer.security.authentication.anonymousAuthentication.enabled:false','/commit:apphost') | Out-Null }
        try {
            $xml = [xml]((Invoke-Native $appcmd @('list','site','/xml')) -join "`n")
            foreach ($site in @($xml.appcmd.SITE)) {
                if ($null -eq $site) { continue }
                $siteName = $site.'SITE.NAME'
                if ([string]$site.bindings -match '(^|,)ftp/') {
                    Invoke-LabChange 'FtpAnonymousSite' $siteName 'Disable anonymous FTP authentication on this site' { Invoke-Native $appcmd @('set','site',$siteName,'/ftpServer.security.authentication.anonymousAuthentication.enabled:false') | Out-Null }
                }
            }
        } catch { Write-LabWarning "Could not enumerate IIS sites: $($_.Exception.Message)" }
        Write-LabWarning 'FTP SSL is NOT forced automatically (it breaks FTP without a certificate). Set FTP SSL Settings > Require SSL in IIS Manager if a certificate is bound.'
    }
}

function Find-ReviewFiles {
    $roots = @("$env:SystemDrive\Users", "$env:ProgramData", "$env:SystemRoot\Temp", "$env:SystemDrive\Temp", "$env:SystemDrive\inetpub")
    $webExtensions = @('.aspx','.asp','.ashx','.asmx','.php','.jsp','.cshtml','.ps1','.bat','.exe')
    $scanErrors = @()
    $findings = foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable +scanErrors |
            Where-Object {
                $_.FullName -notlike "$script:BasePath\*" -and (
                    $_.Extension.ToLowerInvariant() -in $script:Profile.MediaExtensions -or
                    $_.Name -in $script:Profile.ReviewExecutableNames -or
                    ($_.FullName -like "$env:SystemDrive\inetpub\*" -and $_.Extension.ToLowerInvariant() -in $webExtensions))
            } |
            Select-Object FullName,Length,LastWriteTime,@{n='Reason';e={
                if ($_.Name -in $script:Profile.ReviewExecutableNames) {'Review executable'}
                elseif ($_.FullName -like "$env:SystemDrive\inetpub\*") {'Review web content (possible webshell)'}
                else {'Review media'} }}
    }
    Save-Json 'review-files.json' @($findings)
    Write-LabWarning "File scan is a filename/extension inventory, not a malware verdict. Unreadable locations: $($scanErrors.Count). Nothing was deleted."
}

function Install-LabSecurityUpdates {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'WindowsServerHardeningLab'
    $searcher = $session.CreateUpdateSearcher()
    $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $allow = @('0fa1201d-4330-4fa8-8ae9-b877473b6441','e6cf1350-c01b-414d-a61f-263d14d133b4','e0789628-ce08-4437-be74-2495b842f43b')
    $block = @('3689bdc8-b205-4af4-8d4a-a63924c5e9d5','b54e7d24-7add-428f-8b75-90a396fa584f')
    $updates = New-Object -ComObject Microsoft.Update.UpdateColl
    $review = foreach ($u in $found.Updates) {
        $cats = @($u.Categories | ForEach-Object { $_.CategoryID.ToLowerInvariant() })
        $safe = @($cats | Where-Object { $_ -in $allow }).Count -gt 0 -and @($cats | Where-Object { $_ -in $block }).Count -eq 0
        $safe = $safe -and $u.Title -notmatch '(?i)\bpreview\b|\binsider\b|\bfeature update\b' -and -not $u.BrowseOnly -and [bool]$u.AutoSelectOnWebSites
        if ($safe -and $u.EulaAccepted) { $updates.Add($u) | Out-Null }
        [pscustomobject]@{Title=$u.Title;Selected=($safe -and $u.EulaAccepted);EulaAccepted=$u.EulaAccepted;Categories=$cats}
    }
    Save-Json 'windows-update-selection.json' @($review)
    if ($updates.Count -eq 0) { Write-LabWarning 'No already-approved security/critical/definition updates selected. Review Windows Update (or sconfig) manually.'; return }
    $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $updates
    $download = $downloader.Download()
    if ([int]$download.ResultCode -ne 2) { throw "Update download incomplete; result code $($download.ResultCode)." }
    $installer = $session.CreateUpdateInstaller(); $installer.Updates = $updates
    $installer.AllowSourcePrompts = $false; $installer.ForceQuiet = $true
    if ($installer.RebootRequiredBeforeInstallation) { throw 'A restart is already required. Restart manually before installing updates.' }
    $result = $installer.Install()
    Save-Json 'windows-update-result.json' ([pscustomobject]@{ResultCode=[int]$result.ResultCode;RebootRequired=$result.RebootRequired;HResult=$result.HResult})
    if ($result.RebootRequired) { $script:RebootNeeded = $true }
    if ([int]$result.ResultCode -ne 2) { throw "Update installation incomplete; result code $($result.ResultCode)." }
}

# ================================================================= preflight
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Use elevated 64-bit Windows PowerShell 5.1 inside the Windows Server VM.'
}
$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
if ($os.ProductType -notin @(2, 3)) { throw 'This profile supports Windows Server only. Use Invoke-Windows11LabHardening.ps1 on Windows 11.' }
if ([int]$os.BuildNumber -lt 14393) { throw 'Windows Server 2016 (build 14393) or newer is required.' }
$script:IsDC = ($os.ProductType -eq 2)
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
if ($env:SESSIONNAME -like 'RDP*' -or (Get-Variable PSSenderInfo -ErrorAction SilentlyContinue)) { throw 'Use the VM console; this profile can change RDP and remote management.' }
$ConfigPath = Resolve-LabConfigPath -Path $ConfigPath -ScriptDirectory $PSScriptRoot
$script:Profile = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
Test-LabProfile $script:Profile
$script:RdpRequired = 'TermService' -in $script:Profile.RequiredServiceNames
$script:WinRmRequired = 'WinRM' -in $script:Profile.RequiredServiceNames
$script:HasDnsServer = Test-ServiceExists 'DNS'
if ($script:IsDC -and $script:HasDnsServer -and 'DNS' -in $script:Profile.DisableServiceNames) { throw 'DNS is in DisableServiceNames but this is a domain controller. Remove it from the list - AD depends on DNS.' }

$requiredCommands = @('Get-NetFirewallProfile','Set-NetFirewallProfile','Get-NetFirewallRule','Disable-NetFirewallRule','Get-WindowsFeature','Uninstall-WindowsFeature','Get-SmbShare','Get-SmbShareAccess','Remove-SmbShare','Set-SmbServerConfiguration','Set-SmbClientConfiguration','auditpol.exe','net.exe','netsh.exe','secedit.exe','wevtutil.exe','gpupdate.exe')
if ($script:IsDC) {
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch { throw 'The ActiveDirectory PowerShell module is required on a DC (feature RSAT-AD-PowerShell).' }
    $requiredCommands += @('Get-ADUser','New-ADUser','Set-ADAccountPassword','Set-ADAccountControl','Enable-ADAccount','Disable-ADAccount','Get-ADGroup','Get-ADGroupMember','Add-ADGroupMember','Remove-ADGroupMember','Set-ADDefaultDomainPasswordPolicy','Get-ADDomain','Get-ADObject','Set-ADObject','Get-ADComputer','Get-ADDomainController')
    try { Import-Module GroupPolicy -ErrorAction SilentlyContinue } catch { }
} else {
    $requiredCommands += @('Get-LocalUser','New-LocalUser','Set-LocalUser','Enable-LocalUser','Disable-LocalUser','Get-LocalGroup','Get-LocalGroupMember','Add-LocalGroupMember','Remove-LocalGroupMember')
}
if ($UpdateApps) { $requiredCommands += 'winget.exe' }
if ($UpdateDefender) { $requiredCommands += 'Update-MpSignature' }
if ($QuickScan) { $requiredCommands += 'Start-MpScan' }
Assert-LabCapabilities $requiredCommands
$advancedAuditModule = Join-Path $PSScriptRoot 'modules\Lab.AdvancedAudit.psm1'
if ($AdvancedAudit -and -not (Test-Path -LiteralPath $advancedAuditModule -PathType Leaf)) {
    throw 'AdvancedAudit requires modules\Lab.AdvancedAudit.psm1. Extract the complete repository ZIP.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentName = $identity.Name.Split('\')[-1]
if ($script:IsDC) {
    $script:Domain = Get-ADDomain
    $script:DomainSid = $script:Domain.DomainSID.Value
    $sysvolRoot = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysVol
    $script:SysvolPolicies = Join-Path $sysvolRoot "$($script:Domain.DNSRoot)\Policies"
    if (-not (Test-Path -LiteralPath $script:SysvolPolicies)) { $script:SysvolPolicies = "\\$($script:Domain.DNSRoot)\SYSVOL\$($script:Domain.DNSRoot)\Policies" }
    if (-not (Test-Path -LiteralPath $script:SysvolPolicies)) { throw "Cannot find the SYSVOL Policies folder ($script:SysvolPolicies)." }
    $primary = Get-ADUser -Identity $script:Profile.PrimaryAccount -Properties Enabled
    $admins = @(Get-ADGroupMember -Identity 'S-1-5-32-544' -Recursive | ForEach-Object { $_.SID.Value })
    if (-not $primary.Enabled -or $primary.SID.Value -notin $admins) { throw 'The primary account must already be an enabled domain administrator.' }
} else {
    if ($computer.PartOfDomain) { Write-Warning 'This member server is domain-joined. Local policy changes apply to local accounts; domain GPOs can still override settings.' }
    $current = Get-LocalUser -SID $identity.User -ErrorAction SilentlyContinue
    if (-not $current) { throw 'Run as one of the authorized LOCAL administrators on a non-DC server.' }
    $currentName = $current.Name
    $initialMembers = @(Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name)
    $primary = Get-LocalUser -Name $script:Profile.PrimaryAccount
    if (-not $primary.Enabled -or [string]$primary.SID -notin @($initialMembers | ForEach-Object {[string]$_.SID})) { throw 'The primary account must already be an enabled local administrator.' }
}
if ($currentName -notin $script:Profile.Administrators) { throw 'Run as one of the authorized administrators listed in server.config.json.' }
$autoName = ''
$winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($winlogon.PSObject.Properties['AutoAdminLogon'] -and $winlogon.AutoAdminLogon -eq '1' -and $winlogon.PSObject.Properties['DefaultUserName']) {
    $autoName = ([string]$winlogon.DefaultUserName).Split('\')[-1]
    if ($autoName -and $autoName -notin (@($script:Profile.Administrators) + @($script:Profile.Users))) { throw 'Auto-login names an unauthorized account. Review it manually before applying this profile.' }
}
$script:ProtectedNames = @($currentName,$script:Profile.PrimaryAccount,$autoName) | Where-Object { $_ } | Sort-Object -Unique
$script:BasePath = Join-Path $env:ProgramData 'WindowsServerHardeningLab'
$script:RunPath = Join-Path $script:BasePath ("Runs\{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,8)))
New-Item -Path $script:RunPath -ItemType Directory -Force | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $script:RunPath -AclObject $acl
Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $script:RunPath 'profile-used.json')
Write-Host "Mode: $Mode. Role: $(if ($script:IsDC) {'Domain Controller'} else {'Server'}). Reports: $script:RunPath"
Write-Host "Passwords preserved for: $($script:ProtectedNames -join ', ')"

# ================================================================= main
try {
    Save-Json 'run-info.json' ([pscustomobject]@{
        StartedAtUtc=[DateTime]::UtcNow.ToString('o')
        PowerShellVersion=[string]$PSVersionTable.PSVersion
        WindowsBuild=[string]$os.BuildNumber
        Edition=$edition
        IsDomainController=$script:IsDC
        RdpRequired=$script:RdpRequired
        WinRmRequired=$script:WinRmRequired
        DnsServerPresent=$script:HasDnsServer
        ScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        ProfileSHA256=(Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
        AdvancedAuditModuleSHA256=$(if ($AdvancedAudit) {(Get-FileHash -LiteralPath $advancedAuditModule -Algorithm SHA256).Hash} else {$null})
        Options=[pscustomobject]@{Mode=$Mode;WhatIf=[bool]$WhatIfPreference;RotatePasswords=[bool]$RotatePasswords;ScanFiles=[bool]$ScanFiles;UpdateApps=[bool]$UpdateApps;InstallSecurityUpdates=[bool]$InstallSecurityUpdates;UpdateDefender=[bool]$UpdateDefender;QuickScan=[bool]$QuickScan;AdvancedAudit=[bool]$AdvancedAudit}
    })
    Save-Inventory 'before'
    Save-Json 'applications.json' @(Get-ApplicationInventory)
    $registryPlan = @(New-RegistryPlan)
    Save-Json 'registry-target.json' $registryPlan
    Save-RegistryBefore $registryPlan
    Save-LabBackups
    if ($AdvancedAudit) {
        try {
            Import-Module -Name $advancedAuditModule -Force -ErrorAction Stop
            Invoke-LabAdvancedAudit -OutputDirectory $script:RunPath -RegistryPlan $registryPlan
        } catch { Write-LabWarning "Advanced audit incomplete: $($_.Exception.Message). Check advanced reports and collected evidence manually." }
    }

    # --- accounts and policy
    if ($script:IsDC) {
        Invoke-DomainAccountHardening
        Invoke-LabChange 'DomainAccountPolicy' 'Default Domain Policy' 'Enforce domain password/lockout policy (AD + GPO template)' { Set-DomainAccountPolicy }
        Invoke-LabChange 'DcPolicy' 'Default Domain Controllers Policy' 'Write security options; remove Everyone/Pre-Windows 2000 from network logon; deny Guests logon' { Set-DomainControllerPolicy -Plan $registryPlan }
    } else {
        Invoke-LocalAccountHardening
        Invoke-LabChange 'AccountPolicy' 'Local security policy' 'Enforce password/lockout policy and restrict selected user rights while preserving service identities' { Set-AccountPolicy }
    }

    # --- registry
    foreach ($setting in $registryPlan) {
        Invoke-LabChange 'Registry' "$($setting.Path)\$($setting.Name)" "Set $($setting.Value)" { Set-RegistrySetting $setting }
    }

    # --- firewall
    Invoke-LabChange 'Firewall' 'All profiles' 'Enable firewall; block unsolicited inbound, allow outbound, preserve core rules and log dropped traffic' {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules True -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 32767
    }
    $rulePatterns = @('NETDIS-*','RemoteAssistance*')
    if (-not $script:IsDC -and @($script:Profile.AllowedShareNames).Count -eq 0) { $rulePatterns += 'FPS-*' }   # DCs need SMB for SYSVOL/NETLOGON
    if (-not $script:RdpRequired) { $rulePatterns += 'RemoteDesktop*' }
    if (-not $script:WinRmRequired) { $rulePatterns += @('WINRM-*') }
    foreach ($rule in Get-NetFirewallRule -Direction Inbound -Enabled True) {
        $disable = $false
        foreach ($pattern in $rulePatterns) { if ($rule.Name -like $pattern) { $disable = $true } }
        if ($disable -and $rule.DisplayName -notmatch '(?i)ccs|cyberpatriot') { Invoke-LabChange 'FirewallRule' $rule.Name 'Disable unnecessary inbound management/discovery/sharing rule' { Disable-NetFirewallRule -Name $rule.Name } }
    }

    # --- auditing
    $auditList = @($script:Profile.AuditSubcategories)
    if ($script:IsDC) {
        foreach ($s in @('Directory Service Access','Directory Service Changes','Kerberos Authentication Service','Kerberos Service Ticket Operations','Computer Account Management','Other Account Management Events','Distribution Group Management')) { if ($s -notin $auditList) { $auditList += $s } }
    }
    foreach ($subcategory in $auditList) {
        Invoke-LabChange 'Audit' $subcategory 'Enable success and failure auditing' { Invoke-Native 'auditpol.exe' @('/set',"/subcategory:$subcategory",'/success:enable','/failure:enable') | Out-Null }
    }
    Invoke-LabChange 'EventLogSize' 'Security log' 'Set a 128 MiB rolling log; do not clear existing events' { Invoke-Native 'wevtutil.exe' @('sl','Security','/ms:134217728','/rt:false') | Out-Null }

    # --- services
    foreach ($name in $script:Profile.RequiredServiceNames) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { Write-LabWarning "Required service $name is not installed; check the README and Server Manager roles."; continue }
        if ($svc.StartType -eq 'Disabled' -or $svc.Status -ne 'Running') {
            Invoke-LabChange 'RequiredService' $name 'Re-enable and start a README-critical service' {
                if ((Get-Service -Name $name).StartType -eq 'Disabled') { Set-Service -Name $name -StartupType Automatic }
                if ((Get-Service -Name $name).Status -ne 'Running') { Start-Service -Name $name }
            }
        }
    }
    foreach ($name in $script:Profile.DisableServiceNames) {
        if ($name -in $script:Profile.RequiredServiceNames) { continue }
        $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
        if ($service -and $service.PathName -notmatch '(?i)ccsclient|cyberpatriot' -and $service.StartMode -ne 'Disabled') {
            Invoke-LabChange 'DisableService' $name 'Stop and disable unnecessary optional service' {
                Set-Service -Name $name -StartupType Disabled
                if ((Get-Service -Name $name).Status -ne 'Stopped') { Stop-Service -Name $name -Force }
            }
        }
    }

    # --- role-specific hardening (before feature removal)
    if ($script:HasDnsServer) { Invoke-DnsHardening }
    Invoke-IisHardening

    # --- roles and features
    Invoke-FeatureRemoval

    # --- SMB and shares
    Invoke-LabChange 'SMBServer' 'SMB' 'Disable SMB1, require signing and encryption; retain SMB2/3' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSecuritySignature $true -RequireSecuritySignature $true -EncryptData $true -Force }
    Invoke-LabChange 'SMBClient' 'SMB' 'Reject insecure guest logons and require signing' {
        $params = @{ EnableSecuritySignature = $true; RequireSecuritySignature = $true; Force = $true }
        if ((Get-Command Set-SmbClientConfiguration).Parameters.ContainsKey('EnableInsecureGuestLogons')) { $params['EnableInsecureGuestLogons'] = $false }
        Set-SmbClientConfiguration @params
    }
    if ($script:Profile.RemoveNonSystemShares) {
        foreach ($share in Get-SmbShare | Where-Object { -not $_.Special -and $_.Name -notin $script:Profile.AllowedShareNames -and $_.Name -notin $script:AlwaysKeepShares }) {
            Invoke-LabChange 'RemoveShare' $share.Name 'Remove unauthorized non-system share; keep files, system shares and SYSVOL/NETLOGON' { Remove-SmbShare -Name $share.Name -Force }
        }
    }
    foreach ($share in Get-SmbShare | Where-Object { -not $_.Special }) {
        $everyoneFull = @(Get-SmbShareAccess -Name $share.Name | Where-Object { $_.AccountName -match '(?i)^everyone$' -and [string]$_.AccessRight -eq 'Full' -and [string]$_.AccessControlType -eq 'Allow' })
        if ($everyoneFull.Count) { Write-LabWarning "Share $($share.Name) grants Everyone Full Control; review share and NTFS permissions." }
    }

    # --- monitoring and Defender
    foreach ($name in @('EventLog','WinDefend','wscsvc','SecurityHealthService')) {
        if (-not (Test-ServiceExists $name)) { continue }
        Invoke-LabChange 'MonitoringService' $name 'Ensure security/event monitoring service is enabled and running' {
            $service = Get-Service -Name $name
            if ($service.StartType -ne 'Automatic' -and $service.StartType -ne 'Manual') { Set-Service -Name $name -StartupType Automatic }
            if ($service.Status -ne 'Running') { Start-Service -Name $name }
            $verified = Get-Service -Name $name
            if ($verified.Status -ne 'Running') { throw "Service $name did not reach Running (Status=$($verified.Status); StartType=$($verified.StartType))." }
        }
    }
    if ((Get-Command Set-MpPreference -ErrorAction SilentlyContinue) -and (Test-ServiceExists 'WinDefend')) {
        Invoke-LabChange 'Defender' 'Microsoft Defender' 'Enable realtime, behavior, downloaded-file, script and archive protection; block potentially unwanted apps' {
            Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -DisableArchiveScanning $false -PUAProtection Enabled
        }
        if ($UpdateDefender) { Invoke-LabChange 'DefenderUpdate' 'Signatures' 'Update Microsoft Defender definitions' { Update-MpSignature } }
        if ($QuickScan) { Invoke-LabChange 'DefenderScan' 'Quick scan' 'Run Defender quick scan; its configured remediation may quarantine detections' { Start-MpScan -ScanType QuickScan } }
    } else {
        Write-LabWarning 'Microsoft Defender is not installed. Check Server Manager > Add Roles and Features > Microsoft Defender Antivirus, or the README for an approved antivirus.'
    }

    # --- updates
    if ($UpdateApps) {
        foreach ($packageId in $script:Profile.ApplicationPackageIds) {
            Invoke-LabChange 'ApplicationUpdate' $packageId 'Upgrade this required application using its exact WinGet package ID' {
                Invoke-Native 'winget.exe' @('upgrade','--id',$packageId,'--exact','--source','winget','--silent','--disable-interactivity') -OutputPath (Join-Path $script:RunPath "$packageId-upgrade.txt") | Out-Null
            }
        }
    }
    if ($InstallSecurityUpdates) { Invoke-LabChange 'WindowsUpdates' 'Windows Update Agent' 'Install only classified security/critical/definition updates; exclude feature/preview builds; never reboot' { Install-LabSecurityUpdates } }
    if ($ScanFiles) { Find-ReviewFiles }

    # --- accessibility backdoor evidence (never overwritten)
    $accessibility = foreach ($exe in @('sethc.exe','utilman.exe','osk.exe','Narrator.exe','Magnify.exe')) {
        $file = Join-Path "$env:SystemRoot\System32" $exe
        $sig = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction SilentlyContinue
        $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
        $properties = Get-ItemProperty -LiteralPath $ifeo -ErrorAction SilentlyContinue
        [pscustomobject]@{File=$file;Signature=$(if ($sig) {[string]$sig.Status} else {'Unavailable'});SHA256=$(if (Test-Path $file) {(Get-FileHash $file -Algorithm SHA256).Hash} else {''});Debugger=$(if ($properties -and $properties.PSObject.Properties['Debugger']) {$properties.Debugger} else {''})}
    }
    Save-Json 'accessibility-review.json' @($accessibility)

    # --- apply Group Policy so GPO edits and registry values settle
    Invoke-LabChange 'GpUpdate' 'Computer policy' 'Refresh Group Policy (gpupdate /target:computer /force)' { Invoke-Native 'gpupdate.exe' @('/target:computer','/force') | Out-Null }

    if ($script:IsDC) {
        Write-LabWarning 'DC manual checks: Group Policy Management for unknown GPOs linked to the domain/OUs; AD Users and Computers with View > Advanced Features for hidden users/OUs; nested groups reported above; DNS records; AdminSDHolder and domain-root permissions (DCSync rights).'
    }
    Write-LabWarning 'Server Manager manual checks: Dashboard role tiles, Best Practices Analyzer scan on each role, File and Storage Services > Shares permissions.'
    Write-LabWarning 'Review applications, Defender exclusions, scheduled tasks, startup entries, shares, user rights and forensic evidence manually. File and malware findings are not automatically deleted.'
    Write-LabWarning 'Primary/current/auto-login passwords stay unchanged. Expiration is enabled for authorized accounts; an old password can become due at the next sign-in.'
    if ($Mode -eq 'Apply' -and -not $WhatIfPreference) { Save-Inventory 'after'; $script:RebootNeeded = $true }
} catch {
    $script:Changes.Add([pscustomobject]@{Id='Fatal';Target='Run';Description='Run stopped by a terminating error';Status='Failed';Detail=$_.Exception.Message})
    throw
} finally {
    Save-Json 'changes.json' ($script:Changes.ToArray())
    Save-Json 'warnings.json' ($script:Warnings.ToArray())
    Save-Json 'summary.json' ([pscustomobject]@{Mode=$Mode;WhatIf=[bool]$WhatIfPreference;IsDomainController=$script:IsDC;RebootNeeded=$script:RebootNeeded;Applied=@($script:Changes | Where-Object Status -eq 'Applied').Count;Planned=@($script:Changes | Where-Object Status -eq 'Planned').Count;Failed=@($script:Changes | Where-Object Status -eq 'Failed').Count;ProtectedAccounts=$script:ProtectedNames})
    $failedChanges = @($script:Changes | Where-Object Status -eq 'Failed')
    if ($failedChanges.Count -gt 0) {
        Write-Host 'Failed actions (also saved in changes.json):'
        $failedChanges | Format-List Id,Target,Detail | Out-Host
    }
    Write-Host "Reports saved to $script:RunPath"
    if ($script:RebootNeeded) { Write-Warning 'Restart may be needed. No restart was initiated.' }
}
if (@($script:Changes | Where-Object Status -eq 'Failed').Count -gt 0) { exit 2 }
