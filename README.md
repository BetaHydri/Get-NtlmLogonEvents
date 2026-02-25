# Get-NtlmLogonEvents

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg?logo=powershell)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6.svg?logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/github/license/BetaHydri/Get-NtlmLogonEvents)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/BetaHydri/Get-NtlmLogonEvents)](https://github.com/BetaHydri/Get-NtlmLogonEvents/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/BetaHydri/Get-NtlmLogonEvents)](https://github.com/BetaHydri/Get-NtlmLogonEvents/issues)
[![GitHub last commit](https://img.shields.io/github/last-commit/BetaHydri/Get-NtlmLogonEvents)](https://github.com/BetaHydri/Get-NtlmLogonEvents/commits/main)

A PowerShell script to query Windows Security event logs for NTLM authentication events (Event ID 4624 for successful logons, and optionally Event ID 4625 for failed logons). Designed for security auditing and identifying legacy NTLMv1 usage across your environment.

## Why This Matters

NTLM (including NTLMv1, NTLMv2, and LM) is a legacy authentication protocol that is vulnerable to relay, brute-force, and pass-the-hash attacks. Microsoft strongly recommends Kerberos authentication instead. This script helps you **find which users, workstations, and applications are still using NTLM** so you can remediate them before enforcing stronger authentication policies.

### Direct NTLM vs. Negotiate Fallback

Not all NTLM usage is the same. Understanding *why* NTLM was used is critical for choosing the right fix:

| Scenario | `AuthenticationPackageName` | `LogonProcessName` | Root Cause | Remediation |
|---|---|---|---|---|
| **Direct NTLM** | `NTLM` | `NtLmSsp` | App is hardcoded to NTLM | Change app config or code to use Negotiate/Kerberos |
| **Negotiate→NTLM fallback** | `Negotiate` | `Negotiate` | Kerberos was tried but failed | Fix SPNs, DNS, clock skew, or trust issues |

This script exposes both `AuthenticationPackageName` and `LogonProcessName` so you can tell these apart at a glance.

## Features

- Query NTLMv1-only or all NTLM (v1, v2, LM) logon events
- **Detect Negotiate→NTLM fallbacks** — `AuthenticationPackageName` and `LogonProcessName` fields reveal when Kerberos was attempted but fell back to NTLM
- **Include failed NTLM logon attempts** (Event ID 4625) for brute-force and relay attack detection
- Target localhost, a specific remote server, or all domain controllers
- Filter by date range (`-StartTime` / `-EndTime`)
- Exclude null sessions (ANONYMOUS LOGON)
- Alternate credential support for remote connections
- Translates impersonation level codes (`%%1831`–`%%1834`) to human-readable names (see [Impersonation Levels Reference](#impersonation-levels-reference))
- Outputs structured `PSCustomObject` — pipeable to `Export-Csv`, `ConvertTo-Json`, `Format-Table`, etc.

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later |
| Privileges | Must run elevated (Administrator) to read the Security event log |
| Remote targets | WinRM enabled on remote hosts (`winrm quickconfig`) |
| Domain Controllers | ActiveDirectory PowerShell module (RSAT) |

## Installation

No installation needed. Clone or download the script and run it directly:

```powershell
git clone https://github.com/BetaHydri/Get-NtlmLogonEvents.git
cd Get-NtlmLogonEvents
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-NumEvents` | Int | `30` | Maximum number of events to return per host |
| `-Target` | String | `.` (localhost) | Target: `.` for localhost, `DCs` for all domain controllers, or a hostname |
| `-OnlyNTLMv1` | Switch | Off | Return only NTLMv1 events (default: all NTLM versions) |
| `-ExcludeNullSessions` | Switch | Off | Filter out ANONYMOUS LOGON (null session) events |
| `-IncludeFailedLogons` | Switch | Off | Also query failed logon attempts (Event ID 4625) |
| `-Domain` | String | — | AD domain to query when using `-Target DCs` (passed as `-Server` to `Get-ADDomainController`) |
| `-StartTime` | DateTime | — | Only return events after this date/time |
| `-EndTime` | DateTime | — | Only return events before this date/time |
| `-Credential` | PSCredential | — | Alternate credentials for remote connections |

## Usage Examples

### Basic Usage

```powershell
# All NTLM events on localhost (last 30)
.\Get-NtlmLogonEvents.ps1

# Limit to 10 events
.\Get-NtlmLogonEvents.ps1 -NumEvents 10

# Query a remote server
.\Get-NtlmLogonEvents.ps1 -Target server.contoso.com

# Query all domain controllers
.\Get-NtlmLogonEvents.ps1 -Target DCs

# Query DCs in a specific domain (multi-domain forest or trusted domain)
.\Get-NtlmLogonEvents.ps1 -Target DCs -Domain child.contoso.com

# Query DCs in a trusted domain with alternate credentials
.\Get-NtlmLogonEvents.ps1 -Target DCs -Domain partner.fabrikam.com -Credential (Get-Credential)

# Use alternate credentials for remote connections
.\Get-NtlmLogonEvents.ps1 -Target server.contoso.com -Credential (Get-Credential)

# Verbose output for troubleshooting
.\Get-NtlmLogonEvents.ps1 -Target DCs -Verbose
```

### Filtering with Script Parameters

```powershell
# Only NTLMv1 events (most insecure — prioritize these)
.\Get-NtlmLogonEvents.ps1 -OnlyNTLMv1

# NTLMv1-only from a specific server
.\Get-NtlmLogonEvents.ps1 -Target server.contoso.com -OnlyNTLMv1

# Exclude null sessions (ANONYMOUS LOGON) to focus on real users
.\Get-NtlmLogonEvents.ps1 -ExcludeNullSessions

# Combine: NTLMv1 only, no null sessions
.\Get-NtlmLogonEvents.ps1 -OnlyNTLMv1 -ExcludeNullSessions

# Events from the last 7 days
.\Get-NtlmLogonEvents.ps1 -StartTime (Get-Date).AddDays(-7)

# Events within a specific date range
.\Get-NtlmLogonEvents.ps1 -StartTime '2026-02-01' -EndTime '2026-02-28'

# Include failed logon attempts (Event ID 4625)
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons

# Failed NTLMv1 attempts only
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons -OnlyNTLMv1 |
    Where-Object EventId -eq 4625
```

### Negotiate→NTLM Fallback Detection

When Kerberos negotiation fails (e.g., missing SPNs, clock skew, DNS issues), Windows silently falls back to NTLM via the Negotiate package. These events look like normal logons but indicate a Kerberos configuration problem.

```powershell
# Find all Negotiate→NTLM fallbacks (Kerberos was tried but failed)
.\Get-NtlmLogonEvents.ps1 -NumEvents 500 |
    Where-Object AuthenticationPackageName -eq 'Negotiate'

# Compare direct NTLM vs. Negotiate fallback — group by auth package
.\Get-NtlmLogonEvents.ps1 -NumEvents 1000 |
    Group-Object -Property AuthenticationPackageName |
    Select-Object Count, Name

# Show only fallbacks with workstation and user details
.\Get-NtlmLogonEvents.ps1 -NumEvents 500 |
    Where-Object AuthenticationPackageName -eq 'Negotiate' |
    Select-Object UserName, TargetDomainName, WorkstationName, LmPackageName, IPAddress

# Find fallbacks on domain controllers (likely SPN or trust issues)
.\Get-NtlmLogonEvents.ps1 -Target DCs -NumEvents 200 |
    Where-Object AuthenticationPackageName -eq 'Negotiate' |
    Sort-Object WorkstationName |
    Format-Table Time, UserName, WorkstationName, LmPackageName, IPAddress
```

### Failed Logon Analysis

```powershell
# Show only failed logon attempts
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons |
    Where-Object EventId -eq 4625

# Failed logons grouped by source IP (spot brute-force attacks)
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons -NumEvents 1000 |
    Where-Object EventId -eq 4625 |
    Group-Object -Property IPAddress |
    Sort-Object -Property Count -Descending |
    Select-Object Count, Name

# Failed logons from the last 24 hours with status codes
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons -StartTime (Get-Date).AddHours(-24) |
    Where-Object EventId -eq 4625 |
    Select-Object Time, UserName, IPAddress, WorkstationName, Status, SubStatus

# Compare successful vs. failed logons side by side
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons -NumEvents 500 |
    Group-Object EventId |
    Select-Object @{N='EventType';E={if($_.Name -eq '4624'){'Success'}else{'Failed'}}}, Count
```

### Security Audit Recipes

```powershell
# Top 10 users still using NTLM
.\Get-NtlmLogonEvents.ps1 -NumEvents 1000 -ExcludeNullSessions |
    Group-Object -Property UserName |
    Sort-Object -Property Count -Descending |
    Select-Object -First 10 Count, Name

# Find workstations still sending NTLMv1 (highest risk)
.\Get-NtlmLogonEvents.ps1 -OnlyNTLMv1 -NumEvents 500 |
    Select-Object -ExpandProperty WorkstationName -Unique

# Find unique source IPs using NTLM
.\Get-NtlmLogonEvents.ps1 -NumEvents 500 |
    Select-Object -ExpandProperty IPAddress -Unique

# Full audit: all NTLM events across DCs, last 7 days, no null sessions
.\Get-NtlmLogonEvents.ps1 -Target DCs -NumEvents 5000 `
    -ExcludeNullSessions `
    -StartTime (Get-Date).AddDays(-7) |
    Sort-Object Time

# Full audit of a child domain
.\Get-NtlmLogonEvents.ps1 -Target DCs -Domain child.contoso.com -NumEvents 5000 `
    -ExcludeNullSessions -IncludeFailedLogons `
    -StartTime (Get-Date).AddDays(-7) |
    Export-Csv -Path .\child_domain_ntlm_audit.csv -NoTypeInformation

# Full audit with failed logons included, exported to CSV
.\Get-NtlmLogonEvents.ps1 -Target DCs -NumEvents 5000 `
    -IncludeFailedLogons -ExcludeNullSessions `
    -StartTime (Get-Date).AddDays(-7) |
    Export-Csv -Path .\ntlm_audit.csv -NoTypeInformation

# Categorize each event: Direct NTLM vs. Negotiate Fallback vs. Failed
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons -NumEvents 500 |
    Select-Object Time, UserName, WorkstationName, IPAddress, LmPackageName,
        @{N='Category';E={
            if ($_.EventId -eq 4625) { 'Failed' }
            elseif ($_.AuthenticationPackageName -eq 'Negotiate') { 'Negotiate Fallback' }
            else { 'Direct NTLM' }
        }} |
    Format-Table -AutoSize
```

### Export Options

```powershell
# Export to CSV
.\Get-NtlmLogonEvents.ps1 -NumEvents 1000 |
    Export-Csv -Path .\ntlm_audit.csv -NoTypeInformation

# Export to JSON
.\Get-NtlmLogonEvents.ps1 |
    ConvertTo-Json -Depth 3 |
    Set-Content -Path .\ntlm_audit.json

# HTML report
.\Get-NtlmLogonEvents.ps1 -NumEvents 200 |
    ConvertTo-Html -Title 'NTLM Audit Report' |
    Set-Content -Path .\ntlm_report.html
```

## Sample Output

### Successful Logon (Event ID 4624)

```
EventId                   : 4624
Time                      : 2/25/2026 10:23:45 AM
UserName                  : jsmith
TargetDomainName          : CONTOSO
LogonType                 : 3
LogonProcessName          : NtLmSsp
AuthenticationPackageName : NTLM
WorkstationName           : WKS-PC042
LmPackageName             : NTLM V1
IPAddress                 : 192.168.1.50
TCPPort                   : 49832
ImpersonationLevel        : Impersonation
ProcessName               : -
Status                    :
FailureReason             :
SubStatus                 :
ComputerName              : DC01
```

### Negotiate→NTLM Fallback (Kerberos failed)

```
EventId                   : 4624
Time                      : 2/25/2026 10:25:03 AM
UserName                  : jsmith
TargetDomainName          : CONTOSO
LogonType                 : 3
LogonProcessName          : Negotiate
AuthenticationPackageName : Negotiate
WorkstationName           : WKS-PC042
LmPackageName             : NTLM V2
IPAddress                 : 192.168.1.50
TCPPort                   : 50112
ImpersonationLevel        : Impersonation
ProcessName               : -
Status                    :
FailureReason             :
SubStatus                 :
ComputerName              : DC01
```

### Failed Logon (Event ID 4625)

```
EventId                   : 4625
Time                      : 2/25/2026 10:24:12 AM
UserName                  : admin
TargetDomainName          : CONTOSO
LogonType                 : 3
LogonProcessName          : NtLmSsp
AuthenticationPackageName : NTLM
WorkstationName           : ATTACKER-PC
LmPackageName             : NTLM V1
IPAddress                 : 10.0.0.99
TCPPort                   : 55555
ImpersonationLevel        :
ProcessName               : -
Status                    : 0xC000006D
FailureReason             : %%2313
SubStatus                 : 0xC0000064
ComputerName              : DC01
```

## Output Fields

| Field | Description |
|---|---|
| `EventId` | Event ID (4624 = success, 4625 = failure) |
| `Time` | Timestamp of the logon event |
| `UserName` | Account name that logged on (or attempted to) |
| `TargetDomainName` | Domain of the target account |
| `LogonType` | Logon type (e.g., 3 = Network, 10 = RemoteInteractive) |
| `LogonProcessName` | Logon process (`NtLmSsp` = direct NTLM, `Negotiate` = SPNEGO negotiation) |
| `AuthenticationPackageName` | Auth package used (`NTLM` = direct, `Negotiate` = Kerberos attempted first → fell back to NTLM) |
| `WorkstationName` | Name of the source workstation |
| `LmPackageName` | NTLM version used (`NTLM V1`, `NTLM V2`, etc.) |
| `IPAddress` | Source IP address |
| `TCPPort` | Source TCP port |
| `ImpersonationLevel` | Impersonation level (4624 only: Anonymous, Identify, Impersonation, Delegation) |
| `ProcessName` | Process that initiated the logon |
| `Status` | Top-level NTSTATUS failure code (4625 only, e.g., `0xC000006D`) |
| `FailureReason` | Failure reason replacement string (4625 only, e.g., `%%2313`) |
| `SubStatus` | Detailed NTSTATUS failure code (4625 only, e.g., `0xC0000064`) |
| `ComputerName` | Computer where the event was logged |

## Logon Types Reference

| Value | Name | Description |
|---|---|---|
| 2 | Interactive | Local console logon |
| 3 | Network | Network logon (file shares, etc.) |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth, PowerShell with CredSSP |
| 9 | NewCredentials | RunAs with `/netonly` |
| 10 | RemoteInteractive | RDP / Terminal Services |
| 11 | CachedInteractive | Cached domain credentials |

## Impersonation Levels Reference

Windows stores impersonation levels in the Security event log as replacement strings (`%%18xx`). The script translates these to human-readable names automatically.

| Code | Name | Description |
|---|---|---|
| `%%1831` | Anonymous | The server cannot impersonate or identify the client |
| `%%1832` | Identify | The server can identify the client but cannot impersonate |
| `%%1833` | Impersonation | The server can impersonate the client's security context on the local system |
| `%%1834` | Delegation | The server can impersonate the client's security context on remote systems |

> **Note:** Failed logon events (4625) do not include an impersonation level — the field will be empty.

## NTSTATUS Codes Reference

Common failure status codes seen in Event ID 4625:

| Status / SubStatus | Meaning |
|---|---|
| `0xC000006D` | Logon failure — bad username or password |
| `0xC000006A` | Incorrect password |
| `0xC0000064` | User does not exist |
| `0xC0000072` | Account disabled |
| `0xC0000234` | Account locked out |
| `0xC0000193` | Account expired |
| `0xC0000071` | Password expired |
| `0xC0000133` | Clock skew too great between client and server |
| `0xC0000224` | User must change password at next logon |

## Troubleshooting

**"No events were found"**
- Ensure the Security log has Event ID 4624 (and/or 4625 with `-IncludeFailedLogons`) events with NTLM authentication
- Verify audit policy: `auditpol /get /subcategory:"Logon"` should show Success (and Failure) auditing enabled

**"Access denied" or permission errors**
- Run PowerShell as Administrator
- For remote targets, ensure your account has permissions on the remote Security log

**"WinRM cannot process the request"**
- Run `winrm quickconfig` on the remote host
- Ensure the remote host is in your TrustedHosts or domain-joined

**"ActiveDirectory module not found"**
- Install RSAT: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`

## Testing

The project includes a comprehensive Pester test suite with 88 tests covering:

- **XPath filter generation** — default behavior, NTLMv1 filtering, null session exclusion, time range filters, failed logon inclusion, structural validation
- **Event-to-object conversion** — field mapping for 4624 and 4625 events, impersonation level translation, Negotiate→NTLM fallback detection, pipeline input, output object shape
- **Failed logon (4625) mapping** — shifted property indices, Status/FailureReason/SubStatus extraction, mixed event type pipeline
- **Script parameters** — type checks, default values, validation rules, CmdletBinding support
- **Script execution (mocked)** — warning on no events, object output with mock events, ActiveDirectory module error handling
- **Script file quality** — help block, coding standards, absence of deprecated patterns

Run the tests:

```powershell
Invoke-Pester -Path .\Tests\Get-NtlmLogonEvents.Tests.ps1 -Output Detailed
```

## Version History

| Version | Date | Changes |
|---|---|---|
| 3.0 | 2026-02-25 | Added `-IncludeFailedLogons` switch for Event ID 4625; `-Domain` parameter for multi-domain/forest DC queries; `AuthenticationPackageName` and `LogonProcessName` output fields to identify Negotiate→NTLM fallbacks; EventId/Status/FailureReason/SubStatus fields; separate property mapping for 4624 vs 4625 layouts |
| 2.1 | 2026-02-25 | Fixed parameter splatting for optional DateTime parameters; relaxed pipeline type constraint for testability; added comprehensive Pester test suite (60 tests) |
| 2.0 | 2026-02-25 | Major rewrite: structured output objects, XPath filtering, date range support, credential support, impersonation level translation |

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

**Jan Tiedemann**

## Acknowledgments

- [Microsoft Security Auditing Reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630)
- [TechNet: The Most Misunderstood Windows Security Setting of All Time](http://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx)
