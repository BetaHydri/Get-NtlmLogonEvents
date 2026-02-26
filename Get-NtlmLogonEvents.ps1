#Requires -Version 5.1

<#
    .SYNOPSIS
    Retrieves NTLM logon events (NTLMv1, NTLMv2, LM) from the Windows Security event log.

    .DESCRIPTION
    This script queries the Windows Security event log for NTLM authentication events
    (Event ID 4624 for successful logons, and optionally Event ID 4625 for failed logons).
    It supports filtering by NTLM version, date range, and null sessions.

    Targets can be the local machine, a remote server (via WinRM), or all domain controllers
    (requires the ActiveDirectory PowerShell module).

    The output is structured objects suitable for pipeline processing, exporting to CSV/JSON,
    or display in the console.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1

    Gets the last 30 NTLM logon events (NTLMv1, NTLMv2, LM) from the localhost.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -NumEvents 10

    Gets the last 10 NTLM logon events from the localhost.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -ComputerName server.contoso.com

    Gets the last 30 NTLM logon events from server.contoso.com via WinRM.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -ComputerName server.contoso.com -OnlyNTLMv1

    Gets the last 30 NTLMv1-only logon events from server.contoso.com via WinRM.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -Target DCs

    Gets the last 30 NTLM logon events on each domain controller.
    Requires WinRM and the ActiveDirectory PowerShell module.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -Target DCs -Domain child.contoso.com

    Gets the last 30 NTLM logon events on each domain controller in the child.contoso.com domain.
    Requires a trust relationship or appropriate credentials.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -ExcludeNullSessions

    Gets the last 30 NTLM logon events excluding ANONYMOUS LOGON (null sessions).

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date)

    Gets NTLM logon events from the last 7 days.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -ComputerName server.contoso.com -Credential (Get-Credential)

    Connects to server.contoso.com using alternate credentials.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 | Export-Csv -Path .\ntlm_events.csv -NoTypeInformation

    Exports all NTLM logon events to a CSV file.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -OnlyNTLMv1 -ExcludeNullSessions

    Gets the last 30 NTLMv1-only logon events excluding null sessions.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons

    Gets the last 30 NTLM logon events including failed logon attempts (Event ID 4625).

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -IncludeFailedLogons -OnlyNTLMv1 | Where-Object EventId -eq 4625

    Gets only the failed NTLMv1 logon attempts.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -CorrelatePrivileged

    Gets the last 30 NTLM logon events and correlates with Event ID 4672 to identify
    privileged logon sessions. Adds IsPrivileged and PrivilegeList fields to the output.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -CorrelatePrivileged -ExcludeNullSessions | Where-Object IsPrivileged

    Finds NTLM logons that received special privileges (excluding null sessions).

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -ComputerName dc01.contoso.com, dc02.contoso.com -NumEvents 100

    Queries specific domain controllers (or any servers) by name. Accepts multiple hosts.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -CheckAuditConfig

    Checks the local machine's NTLM audit and restriction policy configuration.
    Reports whether recommended GPO settings from Microsoft's AD hardening guidance are enabled.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -Target DCs

    Checks NTLM audit configuration on all domain controllers in the current domain.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -ComputerName server.contoso.com

    Checks NTLM audit configuration on a specific remote server.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -Target Forest

    Gets the last 30 NTLM logon events on every domain controller across all domains
    in the AD forest. Requires WinRM, the ActiveDirectory PowerShell module, and
    appropriate trust/credentials for each domain.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -CheckAuditConfig -Target Forest

    Checks NTLM audit configuration on all domain controllers across the entire forest.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -IncludeNtlmOperationalLog

    Gets the last 30 NTLM logon events from the Security log AND up to 30 events from the
    Microsoft-Windows-NTLM/Operational log (events 8001-8006 audit, 4001-4006 block).

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -IncludeNtlmOperationalLog -NumEvents 500 |
        Where-Object { $_.PSObject.TypeNames -contains 'NtlmOperationalEvent' }

    Gets only the NTLM operational log events (includes process-level detail that 4624 lacks).

    .PARAMETER NumEvents
    Maximum number of events to return per host. Default is 30.
    Only available in event query mode (Default and ComputerName parameter sets).

    .PARAMETER Target
    Target scope for the query. Default is "Localhost".
    - "Localhost" — query the local machine (no WinRM required).
    - "DCs"      — query all domain controllers in the current domain (or the domain
                    specified by -Domain). Requires the ActiveDirectory module and WinRM.
    - "Forest"   — query all domain controllers across every domain in the AD forest.
                    Requires the ActiveDirectory module, WinRM, and network access to all domains.
    To query a specific remote server, use the -ComputerName parameter instead.

    .PARAMETER ComputerName
    One or more remote computer names to query via WinRM. Accepts an array of strings,
    allowing you to query multiple specific servers in one call.
    This parameter replaces the old pattern of passing a hostname to -Target.  
    Mutually exclusive with -Target (which only accepts Localhost, DCs, or Forest).

    .PARAMETER Domain
    Specifies the Active Directory domain to query when using -Target DCs.
    This value is passed as -Server to Get-ADDomainController.
    When omitted, the current user's domain is used.
    Useful for multi-domain forests or querying trusted domains.
    Not applicable when using -Target Forest (all domains are enumerated automatically).

    .PARAMETER ExcludeNullSessions
    When specified, filters out ANONYMOUS LOGON (null session) events.
    This makes it easier to identify real user accounts using NTLM.

    .PARAMETER OnlyNTLMv1
    When specified, returns only NTLMv1 events.
    By default, all NTLM events (NTLMv1, NTLMv2, and LM) are returned.

    .PARAMETER StartTime
    Optional start date/time to filter events. Only events after this time are returned.

    .PARAMETER EndTime
    Optional end date/time to filter events. Only events before this time are returned.

    .PARAMETER IncludeFailedLogons
    When specified, also queries for failed NTLM logon attempts (Event ID 4625).
    Failed logon events include additional fields: EventId, Status, FailureReason, and SubStatus.
    By default, only successful logons (Event ID 4624) are returned.

    .PARAMETER CorrelatePrivileged
    When specified, correlates NTLM logon events (Event ID 4624) with special privilege
    assignment events (Event ID 4672) by matching TargetLogonId. Adds IsPrivileged (boolean)
    and PrivilegeList (string) fields to the output, identifying which NTLM logons received
    elevated privileges. This is critical for detecting privileged accounts using NTLM,
    which are high-value targets for relay and pass-the-hash attacks.
    Note: Only applies to successful logons (4624). Failed logons (4625) show IsPrivileged=$false.

    .PARAMETER Credential
    Optional PSCredential object for authenticating to remote computers.

    .PARAMETER CheckAuditConfig
    When specified, checks the NTLM audit and restriction policy configuration on the target
    machine(s) by reading relevant registry values. Outputs NtlmAuditConfig objects showing
    each policy's current state and whether the recommended setting is applied.
    This is a standalone mode — no event log queries are performed.
    Uses the AuditConfig or AuditConfigComputerName parameter set.
    Reference: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782

    .PARAMETER IncludeNtlmOperationalLog
    When specified, also queries the Microsoft-Windows-NTLM/Operational log for NTLM audit
    events (8001-8006) and block events (4001-4006). These events capture process-level detail
    that Security log events (4624/4625) lack, including the process name, target server SPN,
    and secure channel name. Requires that NTLM auditing policies are configured via GPO
    (see -CheckAuditConfig). Note: -OnlyNTLMv1 and -ExcludeNullSessions do not apply to
    operational log events.

    .LINK
    TechNet - The Most Misunderstood Windows Security Setting of All Time
    http://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx

    .LINK
    Microsoft Security Auditing Reference
    https://www.microsoft.com/en-us/download/details.aspx?id=52630

    .NOTES
    Author:  Jan Tiedemann
    Version: 4.0
    Requires: PowerShell 5.1+, elevated privileges to read Security log.
    For remote targets: WinRM must be enabled (winrm quickconfig).
    For DCs/Forest target: ActiveDirectory PowerShell module required.

    Parameter Sets:
      Default                 — Event log queries using -Target (Localhost/DCs/Forest)
      ComputerName            — Event log queries using -ComputerName (specific host(s))
      AuditConfig             — Audit config check using -Target (Localhost/DCs/Forest)
      AuditConfigComputerName — Audit config check using -ComputerName
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'ComputerName')]
  [ValidateRange(1, [int]::MaxValue)]
  [int]$NumEvents = 30,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'AuditConfig')]
  [ValidateSet('Localhost', 'DCs', 'Forest')]
  [string]$Target = 'Localhost',

  [Parameter(Mandatory, ParameterSetName = 'ComputerName')]
  [Parameter(Mandatory, ParameterSetName = 'AuditConfigComputerName')]
  [ValidateNotNullOrEmpty()]
  [string[]]$ComputerName,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'ComputerName')]
  [switch]$ExcludeNullSessions,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'ComputerName')]
  [switch]$OnlyNTLMv1,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'ComputerName')]
  [switch]$IncludeFailedLogons,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'ComputerName')]
  [switch]$CorrelatePrivileged,

  [Parameter(Mandatory, ParameterSetName = 'AuditConfig')]
  [Parameter(Mandatory, ParameterSetName = 'AuditConfigComputerName')]
  [switch]$CheckAuditConfig,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'ComputerName')]
  [switch]$IncludeNtlmOperationalLog,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'AuditConfig')]
  [string]$Domain,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'ComputerName')]
  [datetime]$StartTime,

  [Parameter(ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'ComputerName')]
  [datetime]$EndTime,

  [System.Management.Automation.PSCredential]
  [System.Management.Automation.Credential()]
  $Credential = [System.Management.Automation.PSCredential]::Empty
)

#region Helper Functions

function Build-XPathFilter {
  <#
    .SYNOPSIS
    Builds the XPath filter string for querying Event ID 4624 (and optionally 4625) with NTLM constraints.
    #>
  [CmdletBinding()]
  param(
    [switch]$OnlyNTLMv1,
    [switch]$ExcludeNullSessions,
    [switch]$IncludeFailedLogons,
    [datetime]$StartTime,
    [datetime]$EndTime
  )

  # Base: Event ID filter
  if ($IncludeFailedLogons) {
    $systemFilters = @('(EventID=4624 or EventID=4625)')
  }
  else {
    $systemFilters = @('EventID=4624')
  }

  # Time range filters
  if ($StartTime) {
    $startUtc = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $systemFilters += "TimeCreated[@SystemTime>='$startUtc']"
  }
  if ($EndTime) {
    $endUtc = $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $systemFilters += "TimeCreated[@SystemTime<='$endUtc']"
  }

  $systemPart = "System[($( $systemFilters -join ' and ' ))]"

  # NTLM version filter
  if ($OnlyNTLMv1) {
    $ntlmPart = "EventData[Data[@Name='LmPackageName']='NTLM V1']"
  }
  else {
    $ntlmPart = "EventData[Data[@Name='LmPackageName']!='-']"
  }

  # Null session filter
  $parts = @("Event[$systemPart]", "Event[$ntlmPart]")
  if ($ExcludeNullSessions) {
    $parts += "Event[EventData[Data[@Name='TargetUserName']!='ANONYMOUS LOGON']]"
  }

  return ($parts -join ' and ')
}

function Convert-EventToObject {
  <#
    .SYNOPSIS
    Converts a raw Security event 4624 or 4625 into a structured PSCustomObject.
    #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [PSObject]$Event,

    [string]$ComputerName
  )

  process {
    # Map ImpersonationLevel replacement strings to human-readable names
    $impersonationMap = @{
      '%%1831' = 'Anonymous'
      '%%1832' = 'Identify'
      '%%1833' = 'Impersonation'
      '%%1834' = 'Delegation'
    }

    # Detect event type — 4624 and 4625 have different property layouts
    $eventId = $Event.Id
    $isFailed = ($eventId -eq 4625)

    if ($isFailed) {
      # Event ID 4625 property indices (Status/FailureReason/SubStatus at [7]-[9] shift everything)
      $logonType = $Event.Properties[10].Value
      $logonProcessName = $Event.Properties[11].Value
      $authPackageName = $Event.Properties[12].Value
      $workstationName = $Event.Properties[13].Value
      $lmPackageName = $Event.Properties[15].Value
      $processName = $Event.Properties[18].Value
      $ipAddress = $Event.Properties[19].Value
      $tcpPort = $Event.Properties[20].Value
      $impersonationLevel = $null  # 4625 does not have ImpersonationLevel
      $targetLogonId = $null       # 4625 does not have a logon session ID
      $status = $Event.Properties[7].Value
      $failureReason = $Event.Properties[8].Value
      $subStatus = $Event.Properties[9].Value
    }
    else {
      # Event ID 4624 property indices
      $logonType = $Event.Properties[8].Value
      $logonProcessName = $Event.Properties[9].Value
      $authPackageName = $Event.Properties[10].Value
      $workstationName = $Event.Properties[11].Value
      $lmPackageName = $Event.Properties[14].Value
      $processName = $Event.Properties[17].Value
      $ipAddress = $Event.Properties[18].Value
      $tcpPort = $Event.Properties[19].Value
      $targetLogonId = $Event.Properties[7].Value -as [string]
      $status = $null
      $failureReason = $null
      $subStatus = $null

      $rawImpersonation = $Event.Properties[20].Value -as [string]
      $impersonationLevel = if ($impersonationMap.ContainsKey($rawImpersonation)) {
        $impersonationMap[$rawImpersonation]
      }
      else {
        $rawImpersonation
      }
    }

    [PSCustomObject]@{
      PSTypeName                = 'NtlmLogonEvent'
      EventId                   = $eventId
      Time                      = $Event.TimeCreated
      UserName                  = $Event.Properties[5].Value
      TargetDomainName          = $Event.Properties[6].Value
      LogonType                 = $logonType
      LogonProcessName          = $logonProcessName
      AuthenticationPackageName = $authPackageName
      WorkstationName           = $workstationName
      LmPackageName             = $lmPackageName
      IPAddress                 = $ipAddress
      TCPPort                   = $tcpPort
      ImpersonationLevel        = $impersonationLevel
      ProcessName               = $processName
      Status                    = $status
      FailureReason             = $failureReason
      SubStatus                 = $subStatus
      TargetLogonId             = $targetLogonId
      ComputerName              = $ComputerName
    }
  }
}

function Get-PrivilegedLogonLookup {
  <#
    .SYNOPSIS
    Queries Event ID 4672 (special privileges assigned to new logon) and returns
    a hashtable mapping SubjectLogonId to the assigned privilege list.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [datetime]$StartTime,

    [Parameter(Mandatory)]
    [datetime]$EndTime
  )

  $startUtc = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $endUtc = $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

  $xpath4672 = "Event[System[EventID=4672 and TimeCreated[@SystemTime>='$startUtc'] and TimeCreated[@SystemTime<='$endUtc']]]"

  $lookup = @{}
  try {
    Get-WinEvent -LogName Security -FilterXPath $xpath4672 -ErrorAction Stop | ForEach-Object {
      $logonId = $_.Properties[3].Value -as [string]
      $privileges = ($_.Properties[4].Value -as [string]).Trim()
      if ($logonId -and -not $lookup.ContainsKey($logonId)) {
        $lookup[$logonId] = $privileges
      }
    }
  }
  catch {
    if ($_.Exception.Message -notmatch 'No events were found') {
      Write-Warning "Failed to query Event ID 4672 for privilege correlation: $_"
    }
  }

  return $lookup
}

function Merge-PrivilegedLogonData {
  <#
    .SYNOPSIS
    Correlates NTLM logon events with Event ID 4672 privilege data.
    Adds IsPrivileged and PrivilegeList properties to each event object.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [PSObject[]]$Events
  )

  # Only 4624 events have a valid TargetLogonId for correlation
  $successEvents = @($Events | Where-Object { $_.EventId -eq 4624 -and $_.TargetLogonId })

  if ($successEvents.Count -eq 0) {
    # No 4624 events to correlate — add empty properties
    foreach ($evt in $Events) {
      $evt | Add-Member -NotePropertyName IsPrivileged -NotePropertyValue $false -Force
      $evt | Add-Member -NotePropertyName PrivilegeList -NotePropertyValue $null -Force
    }
    return
  }

  $times = $successEvents | ForEach-Object { $_.Time }
  $earliest = ($times | Measure-Object -Minimum).Minimum.AddSeconds(-2)
  $latest = ($times | Measure-Object -Maximum).Maximum.AddSeconds(2)

  $lookup = Get-PrivilegedLogonLookup -StartTime $earliest -EndTime $latest

  foreach ($evt in $Events) {
    if ($evt.EventId -eq 4624 -and $evt.TargetLogonId -and $lookup.ContainsKey($evt.TargetLogonId)) {
      $evt | Add-Member -NotePropertyName IsPrivileged -NotePropertyValue $true -Force
      $evt | Add-Member -NotePropertyName PrivilegeList -NotePropertyValue $lookup[$evt.TargetLogonId] -Force
    }
    else {
      $evt | Add-Member -NotePropertyName IsPrivileged -NotePropertyValue $false -Force
      $evt | Add-Member -NotePropertyName PrivilegeList -NotePropertyValue $null -Force
    }
  }
}

function Build-NtlmOperationalXPathFilter {
  <#
    .SYNOPSIS
    Builds the XPath filter string for querying the Microsoft-Windows-NTLM/Operational log
    for NTLM audit events (8001-8006) and block events (4001-4006).
  #>
  [CmdletBinding()]
  param(
    [datetime]$StartTime,
    [datetime]$EndTime
  )

  # NTLM audit events (8001-8006) and block events (4001-4006)
  $eventIdFilter = '(EventID=8001 or EventID=8002 or EventID=8003 or EventID=8004 or EventID=8005 or EventID=8006 or EventID=4001 or EventID=4002 or EventID=4003 or EventID=4004 or EventID=4005 or EventID=4006)'
  $systemFilters = @($eventIdFilter)

  if ($StartTime) {
    $startUtc = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $systemFilters += "TimeCreated[@SystemTime>='$startUtc']"
  }
  if ($EndTime) {
    $endUtc = $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $systemFilters += "TimeCreated[@SystemTime<='$endUtc']"
  }

  return "*[System[$($systemFilters -join ' and ')]]"
}

function Convert-NtlmOperationalEventToObject {
  <#
    .SYNOPSIS
    Converts a raw NTLM Operational event (8001-8006, 4001-4006) into a structured PSCustomObject.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [PSObject]$Event,

    [string]$ComputerName
  )

  process {
    $eventId = $Event.Id
    $isBlock = ($eventId -ge 4001 -and $eventId -le 4006)
    $eventType = if ($isBlock) { 'Block' } else { 'Audit' }
    # Map block event IDs to their audit counterparts for property layout matching
    $baseId = if ($isBlock) { $eventId + 4000 } else { $eventId }

    $descMap = @{
      8001 = 'Outgoing NTLM authentication (client-side)'
      8002 = 'Incoming NTLM authentication (local account / loopback)'
      8003 = 'Incoming NTLM authentication (domain account, server-side)'
      8004 = 'NTLM credential validation (domain controller)'
      8005 = 'Direct NTLM authentication to domain controller'
      8006 = 'Cross-domain NTLM authentication (domain controller)'
      4001 = 'Outgoing NTLM blocked (client-side)'
      4002 = 'Incoming NTLM blocked (local account / loopback)'
      4003 = 'Incoming NTLM blocked (domain account, server-side)'
      4004 = 'NTLM credential validation blocked (domain controller)'
      4005 = 'Direct NTLM authentication blocked (domain controller)'
      4006 = 'Cross-domain NTLM authentication blocked (domain controller)'
    }

    switch ($baseId) {
      # 8001/4001: Client outgoing — TargetName[0], UserName[1], DomainName[2], ProcessName[3], ClientPID[4]
      8001 {
        [PSCustomObject]@{
          PSTypeName        = 'NtlmOperationalEvent'
          EventId           = $eventId
          EventType         = $eventType
          EventDescription  = $descMap[$eventId]
          Time              = $Event.TimeCreated
          UserName          = $Event.Properties[1].Value
          DomainName        = $Event.Properties[2].Value
          TargetName        = $Event.Properties[0].Value
          WorkstationName   = $null
          SecureChannelName = $null
          ProcessName       = if ($Event.Properties.Count -gt 3) { $Event.Properties[3].Value } else { $null }
          ProcessId         = if ($Event.Properties.Count -gt 4) { $Event.Properties[4].Value } else { $null }
          ComputerName      = $ComputerName
        }
      }
      # 8002-8003/4002-4003: Server incoming — UserName[0], DomainName[1], WorkstationName[2], ProcessName[3], ProcessPID[4]
      { $_ -in 8002, 8003 } {
        [PSCustomObject]@{
          PSTypeName        = 'NtlmOperationalEvent'
          EventId           = $eventId
          EventType         = $eventType
          EventDescription  = $descMap[$eventId]
          Time              = $Event.TimeCreated
          UserName          = $Event.Properties[0].Value
          DomainName        = $Event.Properties[1].Value
          TargetName        = $null
          WorkstationName   = $Event.Properties[2].Value
          SecureChannelName = $null
          ProcessName       = if ($Event.Properties.Count -gt 3) { $Event.Properties[3].Value } else { $null }
          ProcessId         = if ($Event.Properties.Count -gt 4) { $Event.Properties[4].Value } else { $null }
          ComputerName      = $ComputerName
        }
      }
      # 8004-8006/4004-4006: DC — UserName[0], DomainName[1], WorkstationName[2], SecureChannelName[3]
      { $_ -in 8004, 8005, 8006 } {
        [PSCustomObject]@{
          PSTypeName        = 'NtlmOperationalEvent'
          EventId           = $eventId
          EventType         = $eventType
          EventDescription  = $descMap[$eventId]
          Time              = $Event.TimeCreated
          UserName          = $Event.Properties[0].Value
          DomainName        = $Event.Properties[1].Value
          TargetName        = $null
          WorkstationName   = $Event.Properties[2].Value
          SecureChannelName = $Event.Properties[3].Value
          ProcessName       = $null
          ProcessId         = $null
          ComputerName      = $ComputerName
        }
      }
    }
  }
}

function Test-NtlmAuditConfiguration {
  <#
    .SYNOPSIS
    Checks the local NTLM audit and restriction policy configuration by reading registry values.
    Returns NtlmAuditConfig objects showing each policy's current state.
    Reference: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782
  #>
  [CmdletBinding()]
  param()

  $msv1_0Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
  $netlogonPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

  # Helper to safely read a registry value
  function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
      $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
      return $item.$Name
    }
    catch { return $null }
  }

  # Define all policy settings to check
  $policies = @(
    @{
      PolicyName   = 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic'
      RegistryPath = "$msv1_0Path\AuditReceivingNTLMTraffic"
      RegPath      = $msv1_0Path
      ValueName    = 'AuditReceivingNTLMTraffic'
      ValueMap     = @{ 0 = 'Disable'; 1 = 'Enable auditing for domain accounts'; 2 = 'Enable auditing for all accounts' }
      Recommended  = 'Enable auditing for domain accounts'
      RecTest      = { param($v) $null -ne $v -and [int]$v -ge 1 }
      Scope        = 'All devices'
    }
    @{
      PolicyName   = 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'
      RegistryPath = "$msv1_0Path\RestrictSendingNTLMTraffic"
      RegPath      = $msv1_0Path
      ValueName    = 'RestrictSendingNTLMTraffic'
      ValueMap     = @{ 0 = 'Allow all'; 1 = 'Audit all'; 2 = 'Deny all' }
      Recommended  = 'Audit all'
      RecTest      = { param($v) $null -ne $v -and [int]$v -ge 1 }
      Scope        = 'All devices'
    }
    @{
      PolicyName   = 'Network security: Restrict NTLM: Incoming NTLM traffic'
      RegistryPath = "$msv1_0Path\RestrictReceivingNTLMTraffic"
      RegPath      = $msv1_0Path
      ValueName    = 'RestrictReceivingNTLMTraffic'
      ValueMap     = @{ 0 = 'Allow all'; 1 = 'Deny all domain accounts'; 2 = 'Deny all accounts' }
      Recommended  = 'Deny all domain accounts'
      RecTest      = { param($v) $null -ne $v -and [int]$v -ge 1 }
      Scope        = 'All devices'
    }
    @{
      PolicyName   = 'Network security: Restrict NTLM: Audit NTLM authentication in this domain'
      RegistryPath = "$netlogonPath\AuditNTLMInDomain"
      RegPath      = $netlogonPath
      ValueName    = 'AuditNTLMInDomain'
      ValueMap     = @{ 0 = 'Disable'; 1 = 'Enable for domain accounts to domain servers'; 3 = 'Enable for domain accounts'; 5 = 'Enable for domain servers'; 7 = 'Enable all' }
      Recommended  = 'Enable all'
      RecTest      = { param($v) $null -ne $v -and [int]$v -eq 7 }
      Scope        = 'Domain Controllers only'
    }
    @{
      PolicyName   = 'Network security: Restrict NTLM: NTLM authentication in this domain'
      RegistryPath = "$netlogonPath\RestrictNTLMInDomain"
      RegPath      = $netlogonPath
      ValueName    = 'RestrictNTLMInDomain'
      ValueMap     = @{ 0 = 'Disable'; 1 = 'Deny for domain accounts to domain servers'; 3 = 'Deny for domain accounts'; 5 = 'Deny for domain servers'; 7 = 'Deny all' }
      Recommended  = 'Deny all (final goal)'
      RecTest      = { param($v) $null -ne $v -and [int]$v -ge 1 }
      Scope        = 'Domain Controllers only'
    }
  )

  foreach ($policy in $policies) {
    $rawValue = Get-RegValue -Path $policy.RegPath -Name $policy.ValueName
    $settingText = if ($null -eq $rawValue) {
      'Not configured'
    }
    elseif ($policy.ValueMap.ContainsKey([int]$rawValue)) {
      $policy.ValueMap[[int]$rawValue]
    }
    else {
      "Unknown ($rawValue)"
    }

    [PSCustomObject]@{
      PSTypeName    = 'NtlmAuditConfig'
      PolicyName    = $policy.PolicyName
      RegistryPath  = $policy.RegistryPath
      RawValue      = $rawValue
      Setting       = $settingText
      Recommended   = $policy.Recommended
      IsRecommended = (& $policy.RecTest $rawValue)
      Scope         = $policy.Scope
      ComputerName  = $env:COMPUTERNAME
    }
  }

  # Check exception lists
  $clientExceptions = Get-RegValue -Path $msv1_0Path -Name 'ClientAllowedNTLMServers'
  if ($clientExceptions) {
    [PSCustomObject]@{
      PSTypeName    = 'NtlmAuditConfig'
      PolicyName    = 'Network security: Restrict NTLM: Add remote server exceptions'
      RegistryPath  = "$msv1_0Path\ClientAllowedNTLMServers"
      RawValue      = $null
      Setting       = ($clientExceptions -join ', ')
      Recommended   = 'Minimize exceptions'
      IsRecommended = $false
      Scope         = 'All devices'
      ComputerName  = $env:COMPUTERNAME
    }
  }

  $dcExceptions = Get-RegValue -Path $netlogonPath -Name 'DCAllowedNTLMServers'
  if ($dcExceptions) {
    [PSCustomObject]@{
      PSTypeName    = 'NtlmAuditConfig'
      PolicyName    = 'Network security: Restrict NTLM: Add server exceptions in this domain'
      RegistryPath  = "$netlogonPath\DCAllowedNTLMServers"
      RawValue      = $null
      Setting       = ($dcExceptions -join ', ')
      Recommended   = 'Minimize exceptions'
      IsRecommended = $false
      Scope         = 'Domain Controllers only'
      ComputerName  = $env:COMPUTERNAME
    }
  }
}

#endregion

#region Main Logic

# --- CheckAuditConfig standalone mode ---
if ($CheckAuditConfig) {
  $auditConfigOutputProperties = @(
    'PolicyName', 'RegistryPath', 'RawValue', 'Setting',
    'Recommended', 'IsRecommended', 'Scope', 'ComputerName'
  )

  # Remote script block embeds the same logic as Test-NtlmAuditConfiguration
  $checkAuditConfigScriptBlock = {
    $msv1_0Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $netlogonPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

    function Get-RegValue {
      param([string]$Path, [string]$Name)
      try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
      catch { $null }
    }

    $policies = @(
      @{
        Policy = 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic'
        RegPath = "$msv1_0Path\AuditReceivingNTLMTraffic"
        Path = $msv1_0Path; Name = 'AuditReceivingNTLMTraffic'
        Map = @{ 0 = 'Disable'; 1 = 'Enable auditing for domain accounts'; 2 = 'Enable auditing for all accounts' }
        Rec = 'Enable auditing for domain accounts'
        RecTest = { param($v) $null -ne $v -and [int]$v -ge 1 }
        Scope = 'All devices'
      }
      @{
        Policy = 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'
        RegPath = "$msv1_0Path\RestrictSendingNTLMTraffic"
        Path = $msv1_0Path; Name = 'RestrictSendingNTLMTraffic'
        Map = @{ 0 = 'Allow all'; 1 = 'Audit all'; 2 = 'Deny all' }
        Rec = 'Audit all'
        RecTest = { param($v) $null -ne $v -and [int]$v -ge 1 }
        Scope = 'All devices'
      }
      @{
        Policy = 'Network security: Restrict NTLM: Incoming NTLM traffic'
        RegPath = "$msv1_0Path\RestrictReceivingNTLMTraffic"
        Path = $msv1_0Path; Name = 'RestrictReceivingNTLMTraffic'
        Map = @{ 0 = 'Allow all'; 1 = 'Deny all domain accounts'; 2 = 'Deny all accounts' }
        Rec = 'Deny all domain accounts'
        RecTest = { param($v) $null -ne $v -and [int]$v -ge 1 }
        Scope = 'All devices'
      }
      @{
        Policy = 'Network security: Restrict NTLM: Audit NTLM authentication in this domain'
        RegPath = "$netlogonPath\AuditNTLMInDomain"
        Path = $netlogonPath; Name = 'AuditNTLMInDomain'
        Map = @{ 0 = 'Disable'; 1 = 'Enable for domain accounts to domain servers'; 3 = 'Enable for domain accounts'; 5 = 'Enable for domain servers'; 7 = 'Enable all' }
        Rec = 'Enable all'
        RecTest = { param($v) $null -ne $v -and [int]$v -eq 7 }
        Scope = 'Domain Controllers only'
      }
      @{
        Policy = 'Network security: Restrict NTLM: NTLM authentication in this domain'
        RegPath = "$netlogonPath\RestrictNTLMInDomain"
        Path = $netlogonPath; Name = 'RestrictNTLMInDomain'
        Map = @{ 0 = 'Disable'; 1 = 'Deny for domain accounts to domain servers'; 3 = 'Deny for domain accounts'; 5 = 'Deny for domain servers'; 7 = 'Deny all' }
        Rec = 'Deny all (final goal)'
        RecTest = { param($v) $null -ne $v -and [int]$v -ge 1 }
        Scope = 'Domain Controllers only'
      }
    )

    foreach ($p in $policies) {
      $raw = Get-RegValue -Path $p.Path -Name $p.Name
      $setting = if ($null -eq $raw) { 'Not configured' }
      elseif ($p.Map.ContainsKey([int]$raw)) { $p.Map[[int]$raw] }
      else { "Unknown ($raw)" }
      [PSCustomObject]@{
        PolicyName    = $p.Policy
        RegistryPath  = $p.RegPath
        RawValue      = $raw
        Setting       = $setting
        Recommended   = $p.Rec
        IsRecommended = (& $p.RecTest $raw)
        Scope         = $p.Scope
        ComputerName  = $env:COMPUTERNAME
      }
    }

    # Exception lists
    $cEx = Get-RegValue -Path $msv1_0Path -Name 'ClientAllowedNTLMServers'
    if ($cEx) {
      [PSCustomObject]@{
        PolicyName    = 'Network security: Restrict NTLM: Add remote server exceptions'
        RegistryPath  = "$msv1_0Path\ClientAllowedNTLMServers"
        RawValue      = $null
        Setting       = ($cEx -join ', ')
        Recommended   = 'Minimize exceptions'
        IsRecommended = $false
        Scope         = 'All devices'
        ComputerName  = $env:COMPUTERNAME
      }
    }

    $dEx = Get-RegValue -Path $netlogonPath -Name 'DCAllowedNTLMServers'
    if ($dEx) {
      [PSCustomObject]@{
        PolicyName    = 'Network security: Restrict NTLM: Add server exceptions in this domain'
        RegistryPath  = "$netlogonPath\DCAllowedNTLMServers"
        RawValue      = $null
        Setting       = ($dEx -join ', ')
        Recommended   = 'Minimize exceptions'
        IsRecommended = $false
        Scope         = 'Domain Controllers only'
        ComputerName  = $env:COMPUTERNAME
      }
    }
  }

  $checkInvokeParams = @{
    ScriptBlock = $checkAuditConfigScriptBlock
    ErrorAction = 'Stop'
  }
  if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
    $checkInvokeParams['Credential'] = $Credential
  }

  if ($Target -eq 'Localhost' -and -not $PSBoundParameters.ContainsKey('ComputerName')) {
    Write-Verbose 'Checking NTLM audit configuration on local host...'
    Test-NtlmAuditConfiguration
  }
  elseif ($Target -eq 'DCs') {
    Write-Verbose 'Loading ActiveDirectory module to enumerate domain controllers...'
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
      Write-Error "The ActiveDirectory PowerShell module is required for -Target DCs. Install RSAT or run from a DC. Error: $_"
      return
    }
    $domainControllers = if ($Domain) {
      Get-ADDomainController -Filter * -Server $Domain | Select-Object -ExpandProperty HostName
    }
    else {
      Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    }
    $domainLabel = if ($Domain) { " in domain '$Domain'" } else { '' }
    Write-Verbose "Checking NTLM audit configuration on DCs${domainLabel}: $($domainControllers -join ', ')"

    $checkInvokeParams['ComputerName'] = $domainControllers
    try {
      Invoke-Command @checkInvokeParams | Select-Object $auditConfigOutputProperties
    }
    catch {
      Write-Error "Failed to check audit configuration on domain controllers: $_"
    }
  }
  elseif ($Target -eq 'Forest') {
    Write-Verbose 'Loading ActiveDirectory module to enumerate all forest domain controllers...'
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
      Write-Error "The ActiveDirectory PowerShell module is required for -Target Forest. Install RSAT or run from a DC. Error: $_"
      return
    }
    $forestDomains = (Get-ADForest).Domains
    Write-Verbose "Forest domains: $($forestDomains -join ', ')"
    $allDCs = foreach ($dom in $forestDomains) {
      try {
        Get-ADDomainController -Filter * -Server $dom | Select-Object -ExpandProperty HostName
      }
      catch {
        Write-Warning "Failed to enumerate DCs in domain '${dom}': $_"
      }
    }
    if (-not $allDCs) {
      Write-Error 'No domain controllers could be enumerated across the forest.'
      return
    }
    Write-Verbose "Checking NTLM audit configuration on forest DCs: $($allDCs -join ', ')"

    $checkInvokeParams['ComputerName'] = $allDCs
    try {
      Invoke-Command @checkInvokeParams | Select-Object $auditConfigOutputProperties
    }
    catch {
      Write-Error "Failed to check audit configuration on forest domain controllers: $_"
    }
  }
  elseif ($PSBoundParameters.ContainsKey('ComputerName')) {
    Write-Verbose "Checking NTLM audit configuration on remote host(s): $($ComputerName -join ', ')"
    $checkInvokeParams['ComputerName'] = $ComputerName
    try {
      Invoke-Command @checkInvokeParams | Select-Object $auditConfigOutputProperties
    }
    catch {
      Write-Error "Failed to check audit configuration on $($ComputerName -join ', '): $_"
    }
  }
  return
}

# Build the XPath filter
$filterParams = @{
  OnlyNTLMv1          = $OnlyNTLMv1
  ExcludeNullSessions = $ExcludeNullSessions
  IncludeFailedLogons = $IncludeFailedLogons
}
if ($PSBoundParameters.ContainsKey('StartTime')) {
  $filterParams['StartTime'] = $StartTime
}
if ($PSBoundParameters.ContainsKey('EndTime')) {
  $filterParams['EndTime'] = $EndTime
}
$xpathFilter = Build-XPathFilter @filterParams

$ntlmVersionLabel = if ($OnlyNTLMv1) { 'NTLMv1' } else { 'NTLM (v1, v2, LM)' }

# Output properties for consistent column ordering
$outputProperties = @(
  'EventId', 'Time', 'UserName', 'TargetDomainName', 'LogonType',
  'LogonProcessName', 'AuthenticationPackageName', 'WorkstationName',
  'LmPackageName', 'IPAddress', 'TCPPort', 'ImpersonationLevel',
  'ProcessName', 'Status', 'FailureReason', 'SubStatus', 'TargetLogonId'
)
if ($CorrelatePrivileged) {
  $outputProperties += 'IsPrivileged', 'PrivilegeList'
}
$outputProperties += 'ComputerName'

# Build the remote script block (shared for DCs and single remote host)
$remoteScriptBlock = {
  param($Filter, $MaxEvents, $DoCorrelatePrivileged)

  # Re-declare the converter inside the remote session
  function Convert-RemoteEvent {
    param(
      [Parameter(Mandatory)]$Event,
      [string]$ComputerName
    )

    $impersonationMap = @{
      '%%1831' = 'Anonymous'
      '%%1832' = 'Identify'
      '%%1833' = 'Impersonation'
      '%%1834' = 'Delegation'
    }

    $eventId = $Event.Id
    $isFailed = ($eventId -eq 4625)

    if ($isFailed) {
      $logonType = $Event.Properties[10].Value
      $logonProcessName = $Event.Properties[11].Value
      $authPackageName = $Event.Properties[12].Value
      $workstationName = $Event.Properties[13].Value
      $lmPackageName = $Event.Properties[15].Value
      $processName = $Event.Properties[18].Value
      $ipAddress = $Event.Properties[19].Value
      $tcpPort = $Event.Properties[20].Value
      $impersonationLevel = $null
      $targetLogonId = $null
      $status = $Event.Properties[7].Value
      $failureReason = $Event.Properties[8].Value
      $subStatus = $Event.Properties[9].Value
    }
    else {
      $logonType = $Event.Properties[8].Value
      $logonProcessName = $Event.Properties[9].Value
      $authPackageName = $Event.Properties[10].Value
      $workstationName = $Event.Properties[11].Value
      $lmPackageName = $Event.Properties[14].Value
      $processName = $Event.Properties[17].Value
      $ipAddress = $Event.Properties[18].Value
      $tcpPort = $Event.Properties[19].Value
      $targetLogonId = $Event.Properties[7].Value -as [string]
      $status = $null
      $failureReason = $null
      $subStatus = $null

      $rawImpersonation = $Event.Properties[20].Value -as [string]
      $impersonationLevel = if ($impersonationMap.ContainsKey($rawImpersonation)) {
        $impersonationMap[$rawImpersonation]
      }
      else {
        $rawImpersonation
      }
    }

    [PSCustomObject]@{
      EventId                   = $eventId
      Time                      = $Event.TimeCreated
      UserName                  = $Event.Properties[5].Value
      TargetDomainName          = $Event.Properties[6].Value
      LogonType                 = $logonType
      LogonProcessName          = $logonProcessName
      AuthenticationPackageName = $authPackageName
      WorkstationName           = $workstationName
      LmPackageName             = $lmPackageName
      IPAddress                 = $ipAddress
      TCPPort                   = $tcpPort
      ImpersonationLevel        = $impersonationLevel
      ProcessName               = $processName
      Status                    = $status
      FailureReason             = $failureReason
      SubStatus                 = $subStatus
      TargetLogonId             = $targetLogonId
      ComputerName              = $env:COMPUTERNAME
    }
  }

  $events = @(Get-WinEvent -LogName Security -MaxEvents $MaxEvents -FilterXPath $Filter -ErrorAction Stop |
    ForEach-Object { Convert-RemoteEvent -Event $_ -ComputerName $env:COMPUTERNAME })

  if ($DoCorrelatePrivileged -and $events.Count -gt 0) {
    # Correlate with Event ID 4672 (special privileges assigned to new logon)
    $successEvents = @($events | Where-Object { $_.EventId -eq 4624 -and $_.TargetLogonId })
    if ($successEvents.Count -gt 0) {
      $times = $successEvents | ForEach-Object { $_.Time }
      $earliest = ($times | Measure-Object -Minimum).Minimum.AddSeconds(-2)
      $latest = ($times | Measure-Object -Maximum).Maximum.AddSeconds(2)
      $startUtc = $earliest.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
      $endUtc = $latest.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
      $xpath4672 = "Event[System[EventID=4672 and TimeCreated[@SystemTime>='$startUtc'] and TimeCreated[@SystemTime<='$endUtc']]]"

      $lookup = @{}
      try {
        Get-WinEvent -LogName Security -FilterXPath $xpath4672 -ErrorAction Stop | ForEach-Object {
          $logonId = $_.Properties[3].Value -as [string]
          $privileges = ($_.Properties[4].Value -as [string]).Trim()
          if ($logonId -and -not $lookup.ContainsKey($logonId)) {
            $lookup[$logonId] = $privileges
          }
        }
      }
      catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
          Write-Warning "Failed to query Event ID 4672: $_"
        }
      }

      foreach ($evt in $events) {
        if ($evt.EventId -eq 4624 -and $evt.TargetLogonId -and $lookup.ContainsKey($evt.TargetLogonId)) {
          $evt | Add-Member -NotePropertyName IsPrivileged -NotePropertyValue $true -Force
          $evt | Add-Member -NotePropertyName PrivilegeList -NotePropertyValue $lookup[$evt.TargetLogonId] -Force
        }
        else {
          $evt | Add-Member -NotePropertyName IsPrivileged -NotePropertyValue $false -Force
          $evt | Add-Member -NotePropertyName PrivilegeList -NotePropertyValue $null -Force
        }
      }
    }
    else {
      foreach ($evt in $events) {
        $evt | Add-Member -NotePropertyName IsPrivileged -NotePropertyValue $false -Force
        $evt | Add-Member -NotePropertyName PrivilegeList -NotePropertyValue $null -Force
      }
    }
  }

  $events
}

# Build Invoke-Command splat (add credential only when provided)
$invokeParams = @{
  ScriptBlock  = $remoteScriptBlock
  ArgumentList = @($xpathFilter, $NumEvents, $CorrelatePrivileged.IsPresent)
  ErrorAction  = 'Stop'
}
if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
  $invokeParams['Credential'] = $Credential
}

# NTLM Operational log setup (if requested)
if ($IncludeNtlmOperationalLog) {
  $ntlmOpFilterParams = @{}
  if ($PSBoundParameters.ContainsKey('StartTime')) { $ntlmOpFilterParams['StartTime'] = $StartTime }
  if ($PSBoundParameters.ContainsKey('EndTime')) { $ntlmOpFilterParams['EndTime'] = $EndTime }
  $ntlmOpFilter = Build-NtlmOperationalXPathFilter @ntlmOpFilterParams

  $ntlmOpOutputProperties = @(
    'EventId', 'EventType', 'EventDescription', 'Time',
    'UserName', 'DomainName', 'TargetName', 'WorkstationName',
    'SecureChannelName', 'ProcessName', 'ProcessId', 'ComputerName'
  )

  # Remote script block for NTLM Operational log queries
  $ntlmOpRemoteScriptBlock = {
    param($Filter, $MaxEvents)

    $descMap = @{
      8001 = 'Outgoing NTLM authentication (client-side)'
      8002 = 'Incoming NTLM authentication (local account / loopback)'
      8003 = 'Incoming NTLM authentication (domain account, server-side)'
      8004 = 'NTLM credential validation (domain controller)'
      8005 = 'Direct NTLM authentication to domain controller'
      8006 = 'Cross-domain NTLM authentication (domain controller)'
      4001 = 'Outgoing NTLM blocked (client-side)'
      4002 = 'Incoming NTLM blocked (local account / loopback)'
      4003 = 'Incoming NTLM blocked (domain account, server-side)'
      4004 = 'NTLM credential validation blocked (domain controller)'
      4005 = 'Direct NTLM authentication blocked (domain controller)'
      4006 = 'Cross-domain NTLM authentication blocked (domain controller)'
    }

    try {
      Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents $MaxEvents -FilterXPath $Filter -ErrorAction Stop | ForEach-Object {
        $eventId = $_.Id
        $isBlock = ($eventId -ge 4001 -and $eventId -le 4006)
        $eventType = if ($isBlock) { 'Block' } else { 'Audit' }
        $baseId = if ($isBlock) { $eventId + 4000 } else { $eventId }

        switch ($baseId) {
          8001 {
            [PSCustomObject]@{
              EventId           = $eventId
              EventType         = $eventType
              EventDescription  = $descMap[$eventId]
              Time              = $_.TimeCreated
              UserName          = $_.Properties[1].Value
              DomainName        = $_.Properties[2].Value
              TargetName        = $_.Properties[0].Value
              WorkstationName   = $null
              SecureChannelName = $null
              ProcessName       = if ($_.Properties.Count -gt 3) { $_.Properties[3].Value } else { $null }
              ProcessId         = if ($_.Properties.Count -gt 4) { $_.Properties[4].Value } else { $null }
              ComputerName      = $env:COMPUTERNAME
            }
          }
          { $_ -in 8002, 8003 } {
            [PSCustomObject]@{
              EventId           = $eventId
              EventType         = $eventType
              EventDescription  = $descMap[$eventId]
              Time              = $_.TimeCreated
              UserName          = $_.Properties[0].Value
              DomainName        = $_.Properties[1].Value
              TargetName        = $null
              WorkstationName   = $_.Properties[2].Value
              SecureChannelName = $null
              ProcessName       = if ($_.Properties.Count -gt 3) { $_.Properties[3].Value } else { $null }
              ProcessId         = if ($_.Properties.Count -gt 4) { $_.Properties[4].Value } else { $null }
              ComputerName      = $env:COMPUTERNAME
            }
          }
          { $_ -in 8004, 8005, 8006 } {
            [PSCustomObject]@{
              EventId           = $eventId
              EventType         = $eventType
              EventDescription  = $descMap[$eventId]
              Time              = $_.TimeCreated
              UserName          = $_.Properties[0].Value
              DomainName        = $_.Properties[1].Value
              TargetName        = $null
              WorkstationName   = $_.Properties[2].Value
              SecureChannelName = $_.Properties[3].Value
              ProcessName       = $null
              ProcessId         = $null
              ComputerName      = $env:COMPUTERNAME
            }
          }
        }
      }
    }
    catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        Write-Warning "Failed to query NTLM Operational log: $_"
      }
    }
  }
}

if ($Target -eq 'Localhost' -and -not $PSBoundParameters.ContainsKey('ComputerName')) {
  # --- Local host ---
  $eventIdLabel = if ($IncludeFailedLogons) { 'Event ID 4624+4625' } else { 'Event ID 4624' }
  Write-Verbose "Querying Security log for $ntlmVersionLabel events ($eventIdLabel) on $env:COMPUTERNAME"

  try {
    $events = @(Get-WinEvent -LogName Security -MaxEvents $NumEvents -FilterXPath $xpathFilter -ErrorAction Stop |
      Convert-EventToObject -ComputerName $env:COMPUTERNAME)

    if ($CorrelatePrivileged -and $events.Count -gt 0) {
      Write-Verbose 'Correlating with Event ID 4672 (special privileges assigned to new logon)...'
      Merge-PrivilegedLogonData -Events $events
    }

    $events
  }
  catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
      Write-Warning "No matching $ntlmVersionLabel logon events found on $env:COMPUTERNAME."
    }
    else {
      Write-Error "Failed to query $env:COMPUTERNAME : $_"
    }
  }

  # NTLM Operational log (process-level detail)
  if ($IncludeNtlmOperationalLog) {
    Write-Verbose 'Querying Microsoft-Windows-NTLM/Operational log for NTLM audit/block events...'
    try {
      Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents $NumEvents -FilterXPath $ntlmOpFilter -ErrorAction Stop |
      Convert-NtlmOperationalEventToObject -ComputerName $env:COMPUTERNAME
    }
    catch {
      if ($_.Exception.Message -match 'No events were found') {
        Write-Warning "No NTLM operational events found on $env:COMPUTERNAME. Ensure NTLM auditing policies are configured (use -CheckAuditConfig to verify)."
      }
      else {
        Write-Warning "Failed to query NTLM Operational log on ${env:COMPUTERNAME}: $_"
      }
    }
  }
}
elseif ($Target -eq 'DCs') {
  # --- All Domain Controllers ---
  Write-Verbose "Loading ActiveDirectory module to enumerate domain controllers..."

  try {
    Import-Module ActiveDirectory -ErrorAction Stop
  }
  catch {
    Write-Error "The ActiveDirectory PowerShell module is required for -Target DCs. Install RSAT or run from a DC. Error: $_"
    return
  }

  $domainControllers = if ($Domain) {
    Get-ADDomainController -Filter * -Server $Domain | Select-Object -ExpandProperty HostName
  }
  else {
    Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
  }
  $domainLabel = if ($Domain) { " in domain '$Domain'" } else { '' }
  Write-Verbose "Querying Security log for $ntlmVersionLabel events on DCs${domainLabel}: $($domainControllers -join ', ')"

  $invokeParams['ComputerName'] = $domainControllers

  try {
    Invoke-Command @invokeParams |
    Select-Object $outputProperties
  }
  catch {
    Write-Error "Failed to query domain controllers: $_"
  }

  # NTLM Operational log on DCs
  if ($IncludeNtlmOperationalLog) {
    Write-Verbose "Querying Microsoft-Windows-NTLM/Operational log on DCs${domainLabel}..."
    $ntlmOpInvokeParams = @{
      ScriptBlock  = $ntlmOpRemoteScriptBlock
      ComputerName = $domainControllers
      ArgumentList = @($ntlmOpFilter, $NumEvents)
      ErrorAction  = 'Stop'
    }
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
      $ntlmOpInvokeParams['Credential'] = $Credential
    }
    try {
      Invoke-Command @ntlmOpInvokeParams |
      Select-Object $ntlmOpOutputProperties
    }
    catch {
      if ($_.Exception.Message -match 'No events were found') {
        Write-Warning 'No NTLM operational events found on domain controllers. Ensure NTLM auditing policies are configured.'
      }
      else {
        Write-Warning "Failed to query NTLM Operational log on domain controllers: $_"
      }
    }
  }
}
elseif ($Target -eq 'Forest') {
  # --- All Domain Controllers across the Forest ---
  Write-Verbose "Loading ActiveDirectory module to enumerate all forest domain controllers..."

  try {
    Import-Module ActiveDirectory -ErrorAction Stop
  }
  catch {
    Write-Error "The ActiveDirectory PowerShell module is required for -Target Forest. Install RSAT or run from a DC. Error: $_"
    return
  }

  $forestDomains = (Get-ADForest).Domains
  Write-Verbose "Forest domains: $($forestDomains -join ', ')"
  $allDCs = foreach ($dom in $forestDomains) {
    try {
      Get-ADDomainController -Filter * -Server $dom | Select-Object -ExpandProperty HostName
    }
    catch {
      Write-Warning "Failed to enumerate DCs in domain '${dom}': $_"
    }
  }
  if (-not $allDCs) {
    Write-Error 'No domain controllers could be enumerated across the forest.'
    return
  }
  Write-Verbose "Querying Security log for $ntlmVersionLabel events on forest DCs: $($allDCs -join ', ')"

  $invokeParams['ComputerName'] = $allDCs

  try {
    Invoke-Command @invokeParams |
    Select-Object $outputProperties
  }
  catch {
    Write-Error "Failed to query forest domain controllers: $_"
  }

  # NTLM Operational log on all forest DCs
  if ($IncludeNtlmOperationalLog) {
    Write-Verbose 'Querying Microsoft-Windows-NTLM/Operational log on all forest DCs...'
    $ntlmOpInvokeParams = @{
      ScriptBlock  = $ntlmOpRemoteScriptBlock
      ComputerName = $allDCs
      ArgumentList = @($ntlmOpFilter, $NumEvents)
      ErrorAction  = 'Stop'
    }
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
      $ntlmOpInvokeParams['Credential'] = $Credential
    }
    try {
      Invoke-Command @ntlmOpInvokeParams |
      Select-Object $ntlmOpOutputProperties
    }
    catch {
      if ($_.Exception.Message -match 'No events were found') {
        Write-Warning 'No NTLM operational events found on forest domain controllers. Ensure NTLM auditing policies are configured.'
      }
      else {
        Write-Warning "Failed to query NTLM Operational log on forest domain controllers: $_"
      }
    }
  }
}
elseif ($PSBoundParameters.ContainsKey('ComputerName')) {
  # --- Specific remote host(s) ---
  $eventIdLabel = if ($IncludeFailedLogons) { 'Event ID 4624+4625' } else { 'Event ID 4624' }
  Write-Verbose "Querying Security log for $ntlmVersionLabel events ($eventIdLabel) on remote host(s): $($ComputerName -join ', ')"

  $invokeParams['ComputerName'] = $ComputerName

  try {
    Invoke-Command @invokeParams |
    Select-Object $outputProperties
  }
  catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
      Write-Warning "No matching $ntlmVersionLabel logon events found on $($ComputerName -join ', ')."
    }
    else {
      Write-Error "Failed to query $($ComputerName -join ', '): $_"
    }
  }

  # NTLM Operational log on remote host(s)
  if ($IncludeNtlmOperationalLog) {
    Write-Verbose "Querying Microsoft-Windows-NTLM/Operational log on remote host(s): $($ComputerName -join ', ')"
    $ntlmOpInvokeParams = @{
      ScriptBlock  = $ntlmOpRemoteScriptBlock
      ComputerName = $ComputerName
      ArgumentList = @($ntlmOpFilter, $NumEvents)
      ErrorAction  = 'Stop'
    }
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
      $ntlmOpInvokeParams['Credential'] = $Credential
    }
    try {
      Invoke-Command @ntlmOpInvokeParams |
      Select-Object $ntlmOpOutputProperties
    }
    catch {
      if ($_.Exception.Message -match 'No events were found') {
        Write-Warning "No NTLM operational events found on $($ComputerName -join ', '). Ensure NTLM auditing policies are configured."
      }
      else {
        Write-Warning "Failed to query NTLM Operational log on $($ComputerName -join ', '): $_"
      }
    }
  }
}

#endregion

###############################################################################
# Reference: Properties (EventData) fields of Event ID 4624 (Successful Logon)
###############################################################################
# Index  Property                   Example Value
# -----  -------------------------  -------------------------------------------
# [0]    SubjectUserSid             S-1-0-0
# [1]    SubjectUserName            -
# [2]    SubjectDomainName          -
# [3]    SubjectLogonId             0x0
# [4]    TargetUserSid              S-1-5-7
# [5]    TargetUserName             ANONYMOUS LOGON
# [6]    TargetDomainName           NT AUTHORITY
# [7]    TargetLogonId              0x12cff454c
# [8]    LogonType                  3
# [9]    LogonProcessName           NtLmSsp
# [10]   AuthenticationPackageName  NTLM
# [11]   WorkstationName            WORKSTATION01
# [12]   LogonGuid                  {00000000-0000-0000-0000-000000000000}
# [13]   TransmittedServices        -
# [14]   LmPackageName              NTLM V1
# [15]   KeyLength                  128
# [16]   ProcessId                  0x0
# [17]   ProcessName                -
# [18]   IpAddress                  192.168.1.100
# [19]   IpPort                     58560
# [20]   ImpersonationLevel         %%1833  (Anonymous/Identify/Impersonation/Delegation)

###############################################################################
# Reference: Properties (EventData) fields of Event ID 4625 (Failed Logon)
###############################################################################
# Index  Property                   Example Value
# -----  -------------------------  -------------------------------------------
# [0]    SubjectUserSid             S-1-0-0
# [1]    SubjectUserName            -
# [2]    SubjectDomainName          -
# [3]    SubjectLogonId             0x0
# [4]    TargetUserSid              S-1-0-0
# [5]    TargetUserName             jsmith
# [6]    TargetDomainName           CONTOSO
# [7]    Status                     0xC000006D  (top-level NTSTATUS code)
# [8]    FailureReason              %%2313      (reason string replacement)
# [9]    SubStatus                  0xC0000064  (detailed NTSTATUS code)
# [10]   LogonType                  3
# [11]   LogonProcessName           NtLmSsp
# [12]   AuthenticationPackageName  NTLM
# [13]   WorkstationName            WORKSTATION01
# [14]   TransmittedServices        -
# [15]   LmPackageName              NTLM V1
# [16]   KeyLength                  0
# [17]   ProcessId                  0x0
# [18]   ProcessName                -
# [19]   IpAddress                  192.168.1.100
# [20]   IpPort                     58560

###############################################################################
# Reference: Properties (EventData) fields of Event ID 4672
#            (Special Privileges Assigned to New Logon)
###############################################################################
# Index  Property                   Example Value
# -----  -------------------------  -------------------------------------------
# [0]    SubjectUserSid             S-1-5-21-...
# [1]    SubjectUserName            Administrator
# [2]    SubjectDomainName          CONTOSO
# [3]    SubjectLogonId             0x12345  (matches TargetLogonId in Event 4624)
# [4]    PrivilegeList              SeDebugPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\t...

###############################################################################
# Reference: Properties (EventData) fields of NTLM Operational Events
#            (Microsoft-Windows-NTLM/Operational log)
#            Audit events: 8001-8006 | Block events: 4001-4006
###############################################################################
#
# Event 8001/4001 — Client outgoing NTLM (audit/block)
# Index  Property         Description
# -----  ---------------  -------------------------------------------
# [0]    TargetName       Target server SPN or name (e.g., HTTP/server.contoso.local)
# [1]    UserName         Authenticating user
# [2]    DomainName       User's domain
# [3]    ProcessName      Process initiating the authentication (e.g., msedge.exe)
# [4]    ClientPID        Process ID of the client process
#
# Event 8002/4002 — Server incoming NTLM, local account/loopback (audit/block)
# Event 8003/4003 — Server incoming NTLM, domain account (audit/block)
# Index  Property         Description
# -----  ---------------  -------------------------------------------
# [0]    UserName         Authenticating user
# [1]    DomainName       User's domain
# [2]    WorkstationName  Client device name
# [3]    ProcessName      Process being accessed (e.g., w3wp.exe)
# [4]    ProcessPID       Process ID of the server process
#
# Event 8004/4004 — DC credential validation (audit/block)
# Event 8005/4005 — DC direct NTLM authentication (audit/block)
# Event 8006/4006 — DC cross-domain NTLM authentication (audit/block)
# Index  Property            Description
# -----  ------------------  -------------------------------------------
# [0]    UserName            Authenticating user
# [1]    DomainName          User's domain
# [2]    WorkstationName     Client device name
# [3]    SecureChannelName   Server being authenticated to (secure channel)
