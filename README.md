# Get-NtlmLogonEvents

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg?logo=powershell)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6.svg?logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/github/license/BetaHydri/Get-NtlmLogonEvents)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/BetaHydri/Get-NtlmLogonEvents)](https://github.com/BetaHydri/Get-NtlmLogonEvents/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/BetaHydri/Get-NtlmLogonEvents)](https://github.com/BetaHydri/Get-NtlmLogonEvents/issues)
[![GitHub last commit](https://img.shields.io/github/last-commit/BetaHydri/Get-NtlmLogonEvents)](https://github.com/BetaHydri/Get-NtlmLogonEvents/commits/main)

A PowerShell script to query Windows Security event logs for NTLM authentication events (Event ID 4624 for successful logons, and optionally Event ID 4625 for failed logons). It can also correlate NTLM logons with Event ID 4672 to identify privileged sessions, query the NTLM Operational log for process-level detail (events 8001-8006/4001-4006), and check your NTLM audit/restriction GPO configuration. Designed for security auditing and identifying legacy NTLMv1 and NTLMv2 usage across your environment.

## Why This Matters

NTLM (including NTLMv1, NTLMv2, and LM) is a legacy authentication protocol that is vulnerable to relay, brute-force, and pass-the-hash attacks. Microsoft strongly recommends Kerberos authentication instead. This script helps you **find which users, workstations, and applications are still using NTLM** so you can remediate them before enforcing stronger authentication policies.

Privileged accounts using NTLM are especially dangerous — they are prime targets for relay and pass-the-hash attacks. The `-CorrelatePrivileged` switch cross-references Event ID 4672 (special privileges assigned to new logon) to flag these high-risk sessions, so you can prioritize them for Kerberos migration.

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
- **Correlate with privileged logons** — `-CorrelatePrivileged` cross-references Event ID 4672 to flag NTLM logons that received elevated privileges (high-value relay/pass-the-hash targets)
- Target localhost, a specific remote server, all domain controllers, or **all DCs across the entire AD forest**
- Filter by date range (`-StartTime` / `-EndTime`)
- Exclude null sessions (ANONYMOUS LOGON)
- Alternate credential support for remote connections
- **Query NTLM Operational log** — `-IncludeNtlmOperationalLog` queries the `Microsoft-Windows-NTLM/Operational` log for audit events (8001-8006) and block events (4001-4006) that capture process names, target server SPNs, and secure channel names
- **Check NTLM audit configuration** — `-CheckAuditConfig` reads the relevant registry values and reports whether recommended NTLM auditing GPO settings are enabled ([reference](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782))
- Translates impersonation level codes (`%%1831`–`%%1834`) to human-readable names (see [Impersonation Levels Reference](#impersonation-levels-reference))
- Outputs structured `PSCustomObject` — pipeable to `Export-Csv`, `ConvertTo-Json`, `Format-Table`, etc.

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later |
| Privileges | Must run elevated (Administrator) to read the Security event log |
| Remote targets | WinRM enabled on remote hosts (`winrm quickconfig`) |
| Domain Controllers | ActiveDirectory PowerShell module (RSAT) |
| NTLM Operational log | Requires NTLM auditing GPO policies to be configured first (see [Prerequisites for NTLM Operational Log](#prerequisites-for-ntlm-operational-log)). The log channel itself is enabled by default — no manual enablement needed. |

## Installation

No installation needed. Clone or download the script and run it directly:

```powershell
git clone https://github.com/BetaHydri/Get-NtlmLogonEvents.git
cd Get-NtlmLogonEvents
```

## Parameters

| Parameter | Type | Default | Parameter Sets | Description |
|---|---|---|---|---|
| `-Target` | String | `Localhost` | Default, AuditConfig | Target scope: `Localhost`, `DCs` (domain controllers), or `Forest` (all DCs across the AD forest). Constrained by `ValidateSet`. |
| `-ComputerName` | String[] | — | ComputerName, AuditConfigComputerName | One or more specific remote host(s) to query. Mandatory in its parameter sets. |
| `-NumEvents` | Int | `30` | Default, ComputerName | Maximum number of events to return per host |
| `-OnlyNTLMv1` | Switch | Off | Default, ComputerName | Return only NTLMv1 events (default: all NTLM versions) |
| `-ExcludeNullSessions` | Switch | Off | Default, ComputerName | Filter out ANONYMOUS LOGON (null session) events |
| `-IncludeFailedLogons` | Switch | Off | Default, ComputerName | Also query failed logon attempts (Event ID 4625) |
| `-CorrelatePrivileged` | Switch | Off | Default, ComputerName | Correlate with Event ID 4672 to identify privileged NTLM logon sessions |
| `-IncludeNtlmOperationalLog` | Switch | Off | Default, ComputerName | Also query `Microsoft-Windows-NTLM/Operational` log (events 8001-8006 audit + 4001-4006 block) |
| `-CheckAuditConfig` | Switch | — | AuditConfig, AuditConfigComputerName | Check NTLM audit/restriction GPO registry settings (standalone mode — no event queries). Mandatory in its parameter sets. |
| `-Domain` | String | — | Default, AuditConfig | AD domain to query when using `-Target DCs` (passed as `-Server` to `Get-ADDomainController`). Not used with `-Target Forest`. |
| `-StartTime` | DateTime | — | Default, ComputerName | Only return events after this date/time |
| `-EndTime` | DateTime | — | Default, ComputerName | Only return events before this date/time |
| `-Credential` | PSCredential | — | All | Alternate credentials for remote connections |

### Parameter Sets

| Parameter Set | Purpose | Key Parameters |
|---|---|---|
| **Default** | Event log queries using `-Target` scope | `-Target` (Localhost/DCs/Forest), event filters |
| **ComputerName** | Event log queries on specific host(s) | `-ComputerName` (mandatory), event filters |
| **AuditConfig** | Audit config check using `-Target` scope | `-CheckAuditConfig` (mandatory), `-Target` |
| **AuditConfigComputerName** | Audit config check on specific host(s) | `-CheckAuditConfig` (mandatory), `-ComputerName` (mandatory) |

## Usage Examples

### Basic Usage

```powershell
# All NTLM events on localhost (last 30)
.\Get-NtlmLogonEvents.ps1

# Limit to 10 events
.\Get-NtlmLogonEvents.ps1 -NumEvents 10

# Query a specific remote server
.\Get-NtlmLogonEvents.ps1 -ComputerName server.contoso.com

# Query multiple remote servers
.\Get-NtlmLogonEvents.ps1 -ComputerName server1.contoso.com, server2.contoso.com

# Query all domain controllers
.\Get-NtlmLogonEvents.ps1 -Target DCs

# Query all DCs across the entire AD forest
.\Get-NtlmLogonEvents.ps1 -Target Forest

# Query DCs in a specific domain (multi-domain forest or trusted domain)
.\Get-NtlmLogonEvents.ps1 -Target DCs -Domain child.contoso.com

# Query DCs in a trusted domain with alternate credentials
.\Get-NtlmLogonEvents.ps1 -Target DCs -Domain partner.fabrikam.com -Credential (Get-Credential)

# Use alternate credentials for remote connections
.\Get-NtlmLogonEvents.ps1 -ComputerName server.contoso.com -Credential (Get-Credential)

# Verbose output for troubleshooting
.\Get-NtlmLogonEvents.ps1 -Target DCs -Verbose
```

### Filtering with Script Parameters

```powershell
# Only NTLMv1 events (most insecure — prioritize these)
.\Get-NtlmLogonEvents.ps1 -OnlyNTLMv1

# NTLMv1-only from a specific server
.\Get-NtlmLogonEvents.ps1 -ComputerName server.contoso.com -OnlyNTLMv1

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

### Privileged Account Correlation

NTLM logons with elevated privileges are high-value targets for relay and pass-the-hash attacks. The `-CorrelatePrivileged` switch cross-references Event ID 4672 (special privileges assigned to new logon) to flag these sessions.

```powershell
# Find all NTLM logons and show which ones received elevated privileges
.\Get-NtlmLogonEvents.ps1 -CorrelatePrivileged

# Show only privileged NTLM logons (excluding null sessions)
.\Get-NtlmLogonEvents.ps1 -CorrelatePrivileged -ExcludeNullSessions |
    Where-Object IsPrivileged

# Privileged NTLMv1 logons — the highest risk combination
.\Get-NtlmLogonEvents.ps1 -CorrelatePrivileged -OnlyNTLMv1 |
    Where-Object IsPrivileged |
    Select-Object Time, UserName, TargetDomainName, WorkstationName, IPAddress, PrivilegeList

# Audit privileged NTLM usage across all DCs in the last 7 days
.\Get-NtlmLogonEvents.ps1 -Target DCs -CorrelatePrivileged -ExcludeNullSessions `
    -NumEvents 1000 -StartTime (Get-Date).AddDays(-7) |
    Where-Object IsPrivileged |
    Sort-Object UserName |
    Format-Table Time, UserName, WorkstationName, IPAddress, LmPackageName, ComputerName

# Count privileged vs. non-privileged NTLM logons
.\Get-NtlmLogonEvents.ps1 -CorrelatePrivileged -NumEvents 500 |
    Group-Object IsPrivileged |
    Select-Object @{N='Category';E={if($_.Name -eq 'True'){'Privileged'}else{'Standard'}}}, Count
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

### NTLM Audit Configuration Check

Before you can collect NTLM operational events (8001–8006), the corresponding GPO auditing policies must be enabled. The `-CheckAuditConfig` switch reads the relevant registry values and reports each policy’s current state against Microsoft’s recommended settings from the [AD Hardening Series – Part 8](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782).

```powershell
# Check NTLM audit configuration on the local machine
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig

# Check on all domain controllers
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -Target DCs

# Check on all DCs across the entire forest
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -Target Forest

# Check on a specific remote server
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -ComputerName server.contoso.com

# Check on multiple remote servers
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -ComputerName server1.contoso.com, server2.contoso.com

# Check on DCs in a trusted domain
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -Target DCs -Domain partner.fabrikam.com -Credential (Get-Credential)

# Show only policies that are NOT at the recommended setting
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig | Where-Object { -not $_.IsRecommended }
```

### NTLM Operational Log Events

The `Microsoft-Windows-NTLM/Operational` log provides process-level detail that Security log events (4624/4625) lack. Use `-IncludeNtlmOperationalLog` to query these events alongside the Security log results.

#### Prerequisites for NTLM Operational Log

The log channel (`Microsoft-Windows-NTLM/Operational`) is **enabled by default** on all Windows machines, including Domain Controllers — you do **not** need to manually enable it. However, **no events are written** unless the corresponding NTLM auditing GPO policies are configured:

| Events | Prerequisite GPO Settings |
|---|---|
| **8001–8006** (audit events) | _Restrict NTLM: Outgoing NTLM traffic_ set to **Audit all**, _Audit Incoming NTLM Traffic_ enabled, and/or _Audit NTLM authentication in this domain_ enabled (DCs) |
| **4001–4006** (block events) | _Restrict NTLM: Incoming/Outgoing NTLM traffic_ or _NTLM authentication in this domain_ set to a **Deny** value |

#### GPO Linkage Targets for Events 8001–8006

Each event is generated by a different GPO policy that must be linked to the correct OU or scope:

| Events | GPO Policy | Link GPO To |
|---|---|---|
| **8001** (outgoing NTLM, client-side) | _Restrict NTLM: Outgoing NTLM traffic to remote servers_ = **Audit all** | **Domain root** (or OUs containing workstations/member servers) — applies to all devices |
| **8002–8003** (incoming NTLM, server-side) | _Restrict NTLM: Audit Incoming NTLM Traffic_ = **Enable auditing for domain accounts** | **Domain root** (or OUs containing member servers/workstations) — applies to all devices |
| **8004–8006** (DC-side credential validation) | _Restrict NTLM: Audit NTLM authentication in this domain_ = **Enable all** | **Domain Controllers OU** only (`OU=Domain Controllers,DC=contoso,DC=com`) |

> **Key takeaway:** Events 8001–8003 require GPOs on **all devices** (workstations and member servers), while events 8004–8006 require a GPO linked exclusively to the **Domain Controllers OU**.

Use `-CheckAuditConfig` to verify whether these policies are configured on your target machines:

```powershell
# Verify audit policies are enabled before querying operational events
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig
.\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -Target DCs
```

If `-IncludeNtlmOperationalLog` returns no events, run `-CheckAuditConfig` first to identify which policies need to be enabled. See the [NTLM Audit GPO Settings Reference](#ntlm-audit-gpo-settings-reference) and [Recommended Blocking Strategy](#recommended-blocking-strategy) sections for details.

```powershell
# Get both Security log and NTLM operational events
.\Get-NtlmLogonEvents.ps1 -IncludeNtlmOperationalLog

# Get only the operational events (filter by PSTypeName)
.\Get-NtlmLogonEvents.ps1 -IncludeNtlmOperationalLog -NumEvents 500 |
    Where-Object { $_.PSObject.TypeNames -contains 'NtlmOperationalEvent' }

# Show which processes are using NTLM (from operational events)
.\Get-NtlmLogonEvents.ps1 -IncludeNtlmOperationalLog -NumEvents 1000 |
    Where-Object ProcessName |
    Group-Object ProcessName |
    Sort-Object Count -Descending |
    Select-Object Count, Name

# Check for NTLM block events (4001-4006) — indicates blocking is active
.\Get-NtlmLogonEvents.ps1 -IncludeNtlmOperationalLog -NumEvents 500 |
    Where-Object EventType -eq 'Block'

# Combined: operational events on all DCs, last 7 days
.\Get-NtlmLogonEvents.ps1 -Target DCs -IncludeNtlmOperationalLog -NumEvents 1000 `
    -StartTime (Get-Date).AddDays(-7) |
    Where-Object EventId -ge 8001 |
    Sort-Object Time |
    Format-Table Time, EventDescription, UserName, WorkstationName, ProcessName, ComputerName
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

### Privileged NTLM Logon (with `-CorrelatePrivileged`)

```
EventId                   : 4624
Time                      : 2/25/2026 10:23:45 AM
UserName                  : admin.jsmith
TargetDomainName          : CONTOSO
LogonType                 : 3
LogonProcessName          : NtLmSsp
AuthenticationPackageName : NTLM
WorkstationName           : WKS-PC042
LmPackageName             : NTLM V2
IPAddress                 : 192.168.1.50
TCPPort                   : 49832
ImpersonationLevel        : Impersonation
ProcessName               : -
Status                    :
FailureReason             :
SubStatus                 :
TargetLogonId             : 0x12cff454c
IsPrivileged              : True
PrivilegeList             : SeSecurityPrivilege
                            SeBackupPrivilege
                            SeRestorePrivilege
                            SeDebugPrivilege
ComputerName              : DC01
```

### NTLM Operational Event (with `-IncludeNtlmOperationalLog`)

```
EventId          : 8001
EventType        : Audit
EventDescription : Outgoing NTLM authentication (client-side)
Time             : 2/25/2026 10:25:10 AM
UserName         : jsmith
DomainName       : CONTOSO
TargetName       : HTTP/intranet.contoso.local
WorkstationName  :
SecureChannelName:
ProcessName      : C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
ProcessId        : 12456
ComputerName     : WKS-PC042
```

### Audit Configuration Check (with `-CheckAuditConfig`)

```
PolicyName    : Network security: Restrict NTLM: Audit Incoming NTLM Traffic
RegistryPath  : HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic
RawValue      : 1
Setting       : Enable auditing for domain accounts
Recommended   : Enable auditing for domain accounts
IsRecommended : True
Scope         : All devices
ComputerName  : DC01
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
| `TargetLogonId` | Logon session ID (4624 only) — used for correlation with Event ID 4672 |
| `IsPrivileged` | Whether the logon session received special privileges (only with `-CorrelatePrivileged`) |
| `PrivilegeList` | Privileges assigned to the logon session (only with `-CorrelatePrivileged`) |
| `ComputerName` | Computer where the event was logged |

### NTLM Operational Event Fields (with `-IncludeNtlmOperationalLog`)

| Field | Description |
|---|---|
| `EventId` | Event ID (8001-8006 = audit, 4001-4006 = block) |
| `EventType` | `Audit` or `Block` |
| `EventDescription` | Human-readable description of the event type |
| `Time` | Timestamp of the event |
| `UserName` | Authenticating user |
| `DomainName` | User’s domain |
| `TargetName` | Target server SPN (8001/4001 only, e.g. `HTTP/server.contoso.local`) |
| `WorkstationName` | Client device name (8002-8006/4002-4006) |
| `SecureChannelName` | Server being authenticated to via secure channel (8004-8006/4004-4006, DC events) |
| `ProcessName` | Process name initiating or receiving NTLM (8001-8003/4001-4003) |
| `ProcessId` | Process ID (8001-8003/4001-4003) |
| `ComputerName` | Computer where the event was logged |

### Audit Configuration Fields (with `-CheckAuditConfig`)

| Field | Description |
|---|---|
| `PolicyName` | GPO policy name |
| `RegistryPath` | Full registry path of the setting |
| `RawValue` | Raw DWORD value from the registry (`$null` if not configured) |
| `Setting` | Human-readable interpretation of the current value |
| `Recommended` | Recommended setting per Microsoft’s AD hardening guidance |
| `IsRecommended` | `$true` if the current setting meets or exceeds the recommendation |
| `Scope` | Whether the policy applies to all devices or domain controllers only |
| `ComputerName` | Computer where the configuration was read |

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

## NTLM Event ID Reference

This table summarizes all NTLM-related event IDs across different Windows logs. Based on guidance from Microsoft’s [Active Directory Hardening Series – Part 8 – Disabling NTLM](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782).

| Event ID | Log | Description | Pros | Cons |
|---|---|---|---|---|
| **4776** | Security | Credential Validation (DC) | Only requires DC log collection; baselines NTLM volume | Only captures client + user; not target server |
| **4624** | Security | Successful logon | Captures user, client, NTLM version, target server | Requires collection from all devices; no process name |
| **4625** | Security | Failed logon | Captures failed NTLM attempts with status codes | Requires collection from all devices |
| **4672** | Security | Special privileges assigned | Identifies privileged NTLM logon sessions | Must be correlated with 4624 by TargetLogonId |
| **8001** | NTLM Operational | Outgoing NTLM audit (client) | Captures target server SPN, process name, user | Requires GPO: _Outgoing NTLM traffic_ = Audit all |
| **8002** | NTLM Operational | Incoming NTLM audit (local/loopback) | Captures process name being accessed | Requires GPO: _Audit Incoming NTLM Traffic_ |
| **8003** | NTLM Operational | Incoming NTLM audit (domain account, server) | Captures client name + process on server | Requires GPO: _Audit NTLM auth in this domain_ (DC) |
| **8004** | NTLM Operational | NTLM credential validation (DC) | Client + server (secure channel) from DC only | Requires GPO: _Audit NTLM auth in this domain_ (DC) |
| **8005** | NTLM Operational | Direct NTLM auth to DC | Detects direct NTLM to DC | DC-only |
| **8006** | NTLM Operational | Cross-domain NTLM auth (DC) | Detects NTLM across trust boundaries | DC-only |
| **4001–4006** | NTLM Operational | NTLM **blocked** (mirrors 8001–8006) | Confirms blocking is working | Only logged when blocking policies are active |
| **4020,4022,4032** | NTLM Operational | Enhanced NTLM audit (Win11 24H2 / Server 2025+) | Includes fallback reason, SPN, negotiation flags, NTLM version | Only on newest OS; not yet widely available |

## NTLM Audit GPO Settings Reference

These Group Policy settings control NTLM auditing and restriction. Use `-CheckAuditConfig` to verify their state.

### Auditing Policies (enable first)

| GPO Setting | Registry Path | Recommended | Values |
|---|---|---|---|
| Restrict NTLM: Audit Incoming NTLM Traffic | `HKLM\SYSTEM\CCS\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic` | Enable auditing for domain accounts | 0=Disable, 1=Domain accounts, 2=All accounts |
| Restrict NTLM: Outgoing NTLM traffic to remote servers | `HKLM\SYSTEM\CCS\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic` | Audit all | 0=Allow all, 1=Audit all, 2=Deny all |
| Restrict NTLM: Audit NTLM authentication in this domain | `HKLM\SYSTEM\CCS\Services\Netlogon\Parameters\AuditNTLMInDomain` | Enable all (DCs only) | 0=Disable, 1=Domain→domain servers, 3=Domain accounts, 5=Domain servers, 7=All |

### Blocking Policies (enforce after remediation)

| GPO Setting | Registry Path | Recommended | Values |
|---|---|---|---|
| Restrict NTLM: Incoming NTLM traffic | `HKLM\SYSTEM\CCS\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic` | Deny all domain accounts | 0=Allow all, 1=Deny domain accounts, 2=Deny all |
| Restrict NTLM: NTLM authentication in this domain | `HKLM\SYSTEM\CCS\Services\Netlogon\Parameters\RestrictNTLMInDomain` | Deny all (final goal, DCs only) | 0=Disable, 1=Domain→domain servers, 3=Domain accounts, 5=Domain servers, 7=All |

### Exception Lists

| GPO Setting | Registry Path | Notes |
|---|---|---|
| Add remote server exceptions for NTLM authentication | `HKLM\...\MSV1_0\ClientAllowedNTLMServers` | Servers allowed for outbound NTLM (supports wildcards and SPN format) |
| Add server exceptions in this domain | `HKLM\...\Netlogon\Parameters\DCAllowedNTLMServers` | Servers exempted from domain-wide NTLM restrictions (DCs only) |

> **Path note:** `CCS` = `CurrentControlSet`. All settings are under `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`.

## NTLM Remediation Guide

Once you’ve identified NTLM usage with this script, investigate why NTLM was selected over Kerberos. Common root causes:

| Category | Cause | How to Detect | Fix |
|---|---|---|---|
| **SPN Issues** | Missing or duplicate SPNs | `setspn -x` (duplicates); Event 4769 failures; 4020 events on 24H2+ | Register correct SPNs; remove duplicates |
| **IP-based Access** | Client connected by IP (Kerberos needs DNS hostname) | 8001 events with IP in TargetName; 4020 events on 24H2+ | Use DNS names; or set `TryIPSPN` registry + register IP SPNs |
| **App Hardcoded NTLM** | Application explicitly requests NTLM instead of Negotiate | 8001 events showing the process; `AuthenticationPackageName=NTLM` in 4624 | Reconfigure app to use Negotiate; contact vendor |
| **Negotiate Fallback** | Kerberos tried but failed; NTLM used via SPNEGO | `AuthenticationPackageName=Negotiate` + `LogonProcessName=Negotiate` in 4624 | Fix SPNs, DNS, clock skew, or trust issues |
| **DC Connectivity** | Client can't reach DC in resource domain for Kerberos | Multi-domain environments with network segmentation | [KDC Proxy](https://syfuhs.net/kdc-proxy-for-remote-access) to tunnel Kerberos over HTTPS ([MS-KKDCP spec](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp)); IAKerb (future) |
| **Local Accounts** | Local account auth always uses NTLM | 8002 events; local account in 4624 | Use domain accounts; LocalKDC (Server 2025) |
| **RPC Endpoint Mapper** | GPO forces NTLM for RPC EPM authentication | 8001 events from System account for RPC | Disable _"Enable RPC Endpoint Mapper Client Authentication"_ GPO |
| **Loopback Auth** | System account connecting to itself | 8001 events from SYSTEM on same machine | Expected behavior; exempt if needed |
| **Print Spooler** | Named Pipe auth with bad SPN (`krbtgt/NT Authority`) | Kerberos errors in System log | Configure Print Spooler to use RPC over TCP |
| **External Trusts** | External trusts default to NTLM | Cross-domain 8006 events; 4624 from trusted domain | Convert to forest trusts |

### Recommended Blocking Strategy

1. **Baseline** — Enable auditing GPOs and collect 8001-8006 events for 2-4 weeks
2. **Protect privileged accounts** — Add admin accounts to [Protected Users Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
3. **Start with Tier 0** — Block NTLM on PAWs and management servers first
4. **Remediate applications** — Fix SPN issues, reconfigure apps from NTLM to Negotiate
5. **Block outbound** — Set _Outgoing NTLM traffic_ = Deny all (with exceptions as needed)
6. **Block inbound** — Set _Incoming NTLM traffic_ = Deny all domain accounts
7. **Block domain-wide** — Set _NTLM auth in this domain_ = Deny all (final goal)
8. **Monitor** — Watch for 4001-4006 block events and 4625 failures with SubStatus `0xC0000418`

> For the complete walkthrough see [Active Directory Hardening Series – Part 8 – Disabling NTLM](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782).

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

The project includes a comprehensive Pester test suite with 100+ tests covering:

- **XPath filter generation** — default behavior, NTLMv1 filtering, null session exclusion, time range filters, failed logon inclusion, structural validation
- **Event-to-object conversion** — field mapping for 4624 and 4625 events, impersonation level translation, Negotiate→NTLM fallback detection, TargetLogonId extraction, pipeline input, output object shape
- **NTLM Operational events** — `Build-NtlmOperationalXPathFilter` time range filters, `Convert-NtlmOperationalEventToObject` field mapping for 8001-8006/4001-4006, event type classification, pipeline input
- **NTLM Audit Configuration** — `Test-NtlmAuditConfiguration` registry reading, policy name mapping, IsRecommended evaluation, output object shape
- **Privileged logon correlation** — `Get-PrivilegedLogonLookup` time-range queries, `Merge-PrivilegedLogonData` property injection, IsPrivileged/PrivilegeList field mapping, handling of no matching 4672 events
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
| 4.2 | 2026-02-26 | `-Target Forest` now queries each domain's DCs separately instead of batching all forest DCs into a single `Invoke-Command` call; if one domain's DCs are unreachable (e.g. WinRM/DNS failure), the script emits a warning and continues with the remaining domains instead of failing entirely. Applies to event queries, NTLM operational log queries, and `-CheckAuditConfig`. |
| 4.1 | 2026-02-26 | Improved error handling for Azure AD-joined clients using `-Target DCs` or `-Target Forest` without line-of-sight to a domain controller; added KDC Proxy documentation references to remediation guide and acknowledgments |
| 4.0 | 2026-02-26 | **Breaking change:** Refactored to proper PowerShell parameter sets (`Default`, `ComputerName`, `AuditConfig`, `AuditConfigComputerName`); `-Target` now uses `[ValidateSet('Localhost', 'DCs', 'Forest')]` (default `Localhost`); new `-ComputerName` (`String[]`) parameter replaces `-Target <hostname>` for querying specific remote hosts; `-CheckAuditConfig` is mandatory in its own parameter sets; event-only parameters restricted to event query sets; `-Domain` restricted to Target-based sets |
| 3.3 | 2026-02-26 | Added `-Target Forest` to query all domain controllers across every domain in the AD forest; enumerates domains via `Get-ADForest` and collects DCs from each |
| 3.2 | 2026-02-26 | Added `-CheckAuditConfig` switch to verify NTLM audit/restriction GPO settings; `-IncludeNtlmOperationalLog` switch to query NTLM Operational log (events 8001-8006 audit + 4001-4006 block); `Build-NtlmOperationalXPathFilter`, `Convert-NtlmOperationalEventToObject`, and `Test-NtlmAuditConfiguration` helper functions; NTLM Event ID Reference, Audit GPO Settings Reference, and Remediation Guide in README; based on Microsoft's [AD Hardening Series – Part 8](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782) |
| 3.1 | 2026-02-25 | Added `-CorrelatePrivileged` switch for Event ID 4672 correlation; `TargetLogonId`, `IsPrivileged`, and `PrivilegeList` output fields; `Get-PrivilegedLogonLookup` and `Merge-PrivilegedLogonData` helper functions |
| 3.0 | 2026-02-25 | Added `-IncludeFailedLogons` switch for Event ID 4625; `-Domain` parameter for multi-domain/forest DC queries; `AuthenticationPackageName` and `LogonProcessName` output fields to identify Negotiate→NTLM fallbacks; EventId/Status/FailureReason/SubStatus fields; separate property mapping for 4624 vs 4625 layouts |
| 2.1 | 2023-05-25 | Fixed parameter splatting for optional DateTime parameters; relaxed pipeline type constraint for testability; added comprehensive Pester test suite (60 tests) |
| 2.0 | 2023-05-04 | Major rewrite: structured output objects, XPath filtering, date range support, credential support, impersonation level translation |

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

**Jan Tiedemann**

## Acknowledgments

- [Microsoft Security Auditing Reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630)
- [TechNet: The Most Misunderstood Windows Security Setting of All Time](http://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx)
- [Active Directory Hardening Series – Part 8 – Disabling NTLM](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782) by Jerry Devore
- [Overview of NTLM auditing enhancements in Windows 11 24H2 and Windows Server 2025](https://support.microsoft.com/en-us/topic/overview-of-ntlm-auditing-enhancements-in-windows-11-version-24h2-and-windows-server-2025-b7ead732-6fc5-46a3-a943-27a4571d9e7b)
- [The Evolution of Windows Authentication](https://techcommunity.microsoft.com/blog/windows-itpro-blog/the-evolution-of-windows-authentication/3926848)
- [Auditing and restricting NTLM usage guide](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/jj865674(v=ws.10))
- [KDC Proxy Server (MS-KKDCP) – Protocol specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp)
- [KDC Proxy for Remote Access – Deployment guide](https://syfuhs.net/kdc-proxy-for-remote-access) by Steve Syfuhs (Microsoft)
- [Configure SSO for Microsoft Entra joined devices](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-hybrid-aadj-sso)
