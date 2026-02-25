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

## Features

- Query NTLMv1-only or all NTLM (v1, v2, LM) logon events
- **Include failed NTLM logon attempts** (Event ID 4625) for brute-force and relay attack detection
- Target localhost, a specific remote server, or all domain controllers
- Filter by date range (`-StartTime` / `-EndTime`)
- Exclude null sessions (ANONYMOUS LOGON)
- Alternate credential support for remote connections
- Translates impersonation level codes (`%%1833`) to human-readable names
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
| `-StartTime` | DateTime | — | Only return events after this date/time |
| `-EndTime` | DateTime | — | Only return events before this date/time |
| `-Credential` | PSCredential | — | Alternate credentials for remote connections |

## Usage Examples

### Basic: All NTLM events on localhost

```powershell
.\Get-NtlmLogonEvents.ps1
```

### Limit to 10 events

```powershell
.\Get-NtlmLogonEvents.ps1 -NumEvents 10
```

### Query a remote server

```powershell
.\Get-NtlmLogonEvents.ps1 -Target server.contoso.com
```

### NTLMv1-only from a remote server

```powershell
.\Get-NtlmLogonEvents.ps1 -Target server.contoso.com -OnlyNTLMv1
```

### Query all domain controllers

```powershell
.\Get-NtlmLogonEvents.ps1 -Target DCs
```

### Exclude null sessions

```powershell
.\Get-NtlmLogonEvents.ps1 -ExcludeNullSessions
```

### Filter by date range (last 7 days)

```powershell
.\Get-NtlmLogonEvents.ps1 -StartTime (Get-Date).AddDays(-7)
```

### Use alternate credentials

```powershell
.\Get-NtlmLogonEvents.ps1 -Target server.contoso.com -Credential (Get-Credential)
```

### Export to CSV

```powershell
.\Get-NtlmLogonEvents.ps1 -NumEvents 1000 |
    Export-Csv -Path .\ntlm_audit.csv -NoTypeInformation
```

### Export to JSON

```powershell
.\Get-NtlmLogonEvents.ps1 |
    ConvertTo-Json -Depth 3 |
    Set-Content -Path .\ntlm_audit.json
```

### Pipeline: Group by user

```powershell
.\Get-NtlmLogonEvents.ps1 -NumEvents 500 |
    Group-Object -Property UserName |
    Sort-Object -Property Count -Descending |
    Select-Object Count, Name
```

### Pipeline: Find unique source IPs

```powershell
.\Get-NtlmLogonEvents.ps1 -NumEvents 500 |
    Select-Object -ExpandProperty IPAddress -Unique
```

### Verbose output for troubleshooting

```powershell
.\Get-NtlmLogonEvents.ps1 -Target DCs -Verbose
```

### Include failed NTLM logon attempts

```powershell
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons
```

### Failed NTLMv1 attempts only

```powershell
.\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons -OnlyNTLMv1 |
    Where-Object EventId -eq 4625
```

## Sample Output

### Successful Logon (Event ID 4624)

```
EventId            : 4624
Time               : 2/25/2026 10:23:45 AM
UserName           : jsmith
TargetDomainName   : CONTOSO
LogonType          : 3
WorkstationName    : WKS-PC042
LmPackageName      : NTLM V1
IPAddress          : 192.168.1.50
TCPPort            : 49832
ImpersonationLevel : Impersonation
ProcessName        : -
Status             :
FailureReason      :
SubStatus          :
ComputerName       : DC01
```

### Failed Logon (Event ID 4625)

```
EventId            : 4625
Time               : 2/25/2026 10:24:12 AM
UserName           : admin
TargetDomainName   : CONTOSO
LogonType          : 3
WorkstationName    : ATTACKER-PC
LmPackageName      : NTLM V1
IPAddress          : 10.0.0.99
TCPPort            : 55555
ImpersonationLevel :
ProcessName        : -
Status             : 0xC000006D
FailureReason      : %%2313
SubStatus          : 0xC0000064
ComputerName       : DC01
```

## Output Fields

| Field | Description |
|---|---|
| `EventId` | Event ID (4624 = success, 4625 = failure) |
| `Time` | Timestamp of the logon event |
| `UserName` | Account name that logged on (or attempted to) |
| `TargetDomainName` | Domain of the target account |
| `LogonType` | Logon type (e.g., 3 = Network, 10 = RemoteInteractive) |
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

The project includes a comprehensive Pester test suite with 60 tests covering:

- **XPath filter generation** — default behavior, NTLMv1 filtering, null session exclusion, time range filters, structural validation
- **Event-to-object conversion** — field mapping, impersonation level translation, pipeline input, output object shape
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
| 3.0 | 2026-02-25 | Added `-IncludeFailedLogons` switch for Event ID 4625 (failed logon attempts); EventId/Status/FailureReason/SubStatus output fields; separate property mapping for 4624 vs 4625 layouts |
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
