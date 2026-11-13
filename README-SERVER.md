# Windows Server version

`Invoke-WindowsServerLabHardening.ps1` + `server.config.json` are the Server version of the Windows 11 script. They work the same way (Audit first, then Apply; reports go to `C:\ProgramData\WindowsServerHardeningLab\Runs\...`) and reuse `modules\Lab.AdvancedAudit.psm1`. The Windows 11 files are unchanged.

## Before running

1. Take a VM snapshot and answer the forensics questions first.
2. Edit `server.config.json` from the README. The script refuses to run while `CHANGEME` names are still in it.
   - `Administrators` / `Users`: exact usernames from the README. On a DC, administrators are put in **Domain Admins**.
   - `RequiredServiceNames`: every critical service. Use the service names, for example:
     `DNS`, `W3SVC` (IIS), `FTPSVC` (FTP), `TermService` (RDP), `WinRM`, `DHCPServer`, `Spooler`.
     Anything listed here is never disabled, is restarted if it's stopped, and its feature is never removed.
   - `RemoteDesktopUsers`: only if RDP is critical (`TermService` must be listed too).
   - `RemoveFeatureNames`: names from `Get-WindowsFeature`. Take out `Web-Server` / `Web-Ftp-Server` if IIS or FTP is critical. The script will also refuse a conflicting combination.
   - `AllowedShareNames`: shares the README needs. SYSVOL, NETLOGON and the `$` admin shares are always kept.
3. Run as an authorized admin at the VM console in **Windows PowerShell 5.1 as Administrator**.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-WindowsServerLabHardening.ps1 -Mode Audit -ScanFiles
# read changes.json / warnings.json in the printed report folder, then:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-WindowsServerLabHardening.ps1 -Mode Apply
```

Optional flags are the same as the Windows 11 script: `-RotatePasswords -UpdateDefender -InstallSecurityUpdates -QuickScan -AdvancedAudit`. `-UpdateApps` needs winget, which Server usually doesn't have.

## What it does differently on Server

| Area | Domain Controller | Standalone / member server |
| --- | --- | --- |
| Users | AD users: disable unauthorized, enable authorized, clear *password never expires / not required / reversible encryption / no Kerberos pre-auth / DES only / delegation* flags, report SPN (Kerberoastable) accounts | Local users (same as Windows 11) |
| Groups | Domain/Enterprise/Schema Admins + Administrators keep only README admins; Account/Server/Print/Backup Operators, DnsAdmins, GPCO emptied of users; Guests; Remote Desktop Users follows the profile. Nested groups are reported, not removed | Local groups |
| Password/lockout | `Set-ADDefaultDomainPasswordPolicy` **and** the Default Domain Policy GPO (so gpupdate doesn't undo it) | secedit (local) |
| Security options / user rights | Written to the Default Domain Controllers Policy GPO too; removes Everyone + Pre-Windows 2000 from "Access this computer from the network"; denies Guests | secedit (local) |
| DC hardening | Zerologon (`FullSecureChannelProtection`), LDAP signing + channel binding, secure-channel signing/sealing, strong keys, unconstrained delegation removed from non-DC computers | - |
| DNS (if installed) | Secure-only dynamic updates, zone transfers off, SIGRed fix, DNS restart | same |
| IIS / FTP (only if critical) | Directory browsing off, anonymous FTP off | same |
| Roles/features | `Uninstall-WindowsFeature`, skipped if it would also remove a protected/required feature or service | same |
| RDP / WinRM | If critical: kept on with NLA + TLS + high encryption and firewall rules left open. Otherwise disabled | same |
| Other | IE Enhanced Security Configuration on, SMB1 off, SMB signing + encryption, firewall, auditing (extra DS/Kerberos audits on a DC), Defender, file/webshell scan of `C:\inetpub`, accessibility-backdoor report, `gpupdate /force` | same |

It does **not** automatically: delete files or apps, remove unknown GPOs, remove nested groups, require FTP SSL (that needs a certificate), or restart the server. Those are listed in `warnings.json` to check by hand.
