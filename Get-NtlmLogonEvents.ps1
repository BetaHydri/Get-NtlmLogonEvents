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
    .\Get-NtlmLogonEvents.ps1 -Target server.contoso.com

    Gets the last 30 NTLM logon events from server.contoso.com via WinRM.

    .EXAMPLE
    .\Get-NtlmLogonEvents.ps1 -Target server.contoso.com -OnlyNTLMv1

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
    .\Get-NtlmLogonEvents.ps1 -Target server.contoso.com -Credential (Get-Credential)

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

    .PARAMETER NumEvents
    Maximum number of events to return per host. Default is 30.

    .PARAMETER Target
    Target computer(s). Default is localhost (".").
    Use "DCs" to query all domain controllers (requires ActiveDirectory module and WinRM).
    Use a fully qualified hostname to query a specific remote server (requires WinRM).

    .PARAMETER Domain
    Specifies the Active Directory domain to query when using -Target DCs.
    This value is passed as -Server to Get-ADDomainController.
    When omitted, the current user's domain is used.
    Useful for multi-domain forests or querying trusted domains.

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

    .PARAMETER Credential
    Optional PSCredential object for authenticating to remote computers.

    .LINK
    TechNet - The Most Misunderstood Windows Security Setting of All Time
    http://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx

    .LINK
    Microsoft Security Auditing Reference
    https://www.microsoft.com/en-us/download/details.aspx?id=52630

    .NOTES
    Author:  Jan Tiedemann
    Version: 3.0
    Requires: PowerShell 5.1+, elevated privileges to read Security log.
    For remote targets: WinRM must be enabled (winrm quickconfig).
    For DCs target: ActiveDirectory PowerShell module required.
#>

[CmdletBinding()]
param(
  [ValidateRange(1, [int]::MaxValue)]
  [int]$NumEvents = 30,

  [ValidateNotNullOrEmpty()]
  [string]$Target = '.',

  [switch]$ExcludeNullSessions,

  [switch]$OnlyNTLMv1,

  [switch]$IncludeFailedLogons,

  [string]$Domain,

  [datetime]$StartTime,

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
      ComputerName              = $ComputerName
    }
  }
}

#endregion

#region Main Logic

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
  'ProcessName', 'Status', 'FailureReason', 'SubStatus', 'ComputerName'
)

# Build the remote script block (shared for DCs and single remote host)
$remoteScriptBlock = {
  param($Filter, $MaxEvents)

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
      ComputerName              = $env:COMPUTERNAME
    }
  }

  Get-WinEvent -LogName Security -MaxEvents $MaxEvents -FilterXPath $Filter -ErrorAction Stop |
  ForEach-Object { Convert-RemoteEvent -Event $_ -ComputerName $env:COMPUTERNAME }
}

# Build Invoke-Command splat (add credential only when provided)
$invokeParams = @{
  ScriptBlock  = $remoteScriptBlock
  ArgumentList = @($xpathFilter, $NumEvents)
  ErrorAction  = 'Stop'
}
if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
  $invokeParams['Credential'] = $Credential
}

if ($Target -eq '.') {
  # --- Local host ---
  $eventIdLabel = if ($IncludeFailedLogons) { 'Event ID 4624+4625' } else { 'Event ID 4624' }
  Write-Verbose "Querying Security log for $ntlmVersionLabel events ($eventIdLabel) on $env:COMPUTERNAME"

  try {
    Get-WinEvent -LogName Security -MaxEvents $NumEvents -FilterXPath $xpathFilter -ErrorAction Stop |
    Convert-EventToObject -ComputerName $env:COMPUTERNAME
  }
  catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
      Write-Warning "No matching $ntlmVersionLabel logon events found on $env:COMPUTERNAME."
    }
    else {
      Write-Error "Failed to query $env:COMPUTERNAME : $_"
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
}
else {
  # --- Single remote host ---
  $eventIdLabel = if ($IncludeFailedLogons) { 'Event ID 4624+4625' } else { 'Event ID 4624' }
  Write-Verbose "Querying Security log for $ntlmVersionLabel events ($eventIdLabel) on remote host: $Target"

  $invokeParams['ComputerName'] = $Target

  try {
    Invoke-Command @invokeParams |
    Select-Object $outputProperties
  }
  catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
      Write-Warning "No matching $ntlmVersionLabel logon events found on $Target."
    }
    else {
      Write-Error "Failed to query ${Target}: $_"
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
