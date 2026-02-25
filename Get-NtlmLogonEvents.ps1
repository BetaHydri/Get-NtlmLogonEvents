#Requires -Version 5.1

<#
    .SYNOPSIS
    Retrieves NTLM logon events (NTLMv1, NTLMv2, LM) from the Windows Security event log.

    .DESCRIPTION
    This script queries the Windows Security event log for NTLM authentication events
    (Event ID 4624). It supports filtering by NTLM version, date range, and null sessions.

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

    .PARAMETER NumEvents
    Maximum number of events to return per host. Default is 30.

    .PARAMETER Target
    Target computer(s). Default is localhost (".").
    Use "DCs" to query all domain controllers (requires ActiveDirectory module and WinRM).
    Use a fully qualified hostname to query a specific remote server (requires WinRM).

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
    Version: 2.1
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
    Builds the XPath filter string for querying Event ID 4624 with NTLM constraints.
    #>
  [CmdletBinding()]
  param(
    [switch]$OnlyNTLMv1,
    [switch]$ExcludeNullSessions,
    [datetime]$StartTime,
    [datetime]$EndTime
  )

  # Base: Event ID 4624
  $systemFilters = @('EventID=4624')

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
    Converts a raw Security event 4624 into a structured PSCustomObject.
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

    $rawImpersonation = $Event.Properties[20].Value -as [string]
    $impersonationLevel = if ($impersonationMap.ContainsKey($rawImpersonation)) {
      $impersonationMap[$rawImpersonation]
    }
    else {
      $rawImpersonation
    }

    [PSCustomObject]@{
      PSTypeName         = 'NtlmLogonEvent'
      Time               = $Event.TimeCreated
      UserName           = $Event.Properties[5].Value
      TargetDomainName   = $Event.Properties[6].Value
      LogonType          = $Event.Properties[8].Value
      WorkstationName    = $Event.Properties[11].Value
      LmPackageName      = $Event.Properties[14].Value
      IPAddress          = $Event.Properties[18].Value
      TCPPort            = $Event.Properties[19].Value
      ImpersonationLevel = $impersonationLevel
      ProcessName        = $Event.Properties[17].Value
      ComputerName       = $ComputerName
    }
  }
}

#endregion

#region Main Logic

# Build the XPath filter
$filterParams = @{
  OnlyNTLMv1          = $OnlyNTLMv1
  ExcludeNullSessions = $ExcludeNullSessions
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
  'Time', 'UserName', 'TargetDomainName', 'LogonType', 'WorkstationName',
  'LmPackageName', 'IPAddress', 'TCPPort', 'ImpersonationLevel',
  'ProcessName', 'ComputerName'
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
    $rawImpersonation = $Event.Properties[20].Value -as [string]
    $impersonationLevel = if ($impersonationMap.ContainsKey($rawImpersonation)) {
      $impersonationMap[$rawImpersonation]
    }
    else {
      $rawImpersonation
    }

    [PSCustomObject]@{
      Time               = $Event.TimeCreated
      UserName           = $Event.Properties[5].Value
      TargetDomainName   = $Event.Properties[6].Value
      LogonType          = $Event.Properties[8].Value
      WorkstationName    = $Event.Properties[11].Value
      LmPackageName      = $Event.Properties[14].Value
      IPAddress          = $Event.Properties[18].Value
      TCPPort            = $Event.Properties[19].Value
      ImpersonationLevel = $impersonationLevel
      ProcessName        = $Event.Properties[17].Value
      ComputerName       = $env:COMPUTERNAME
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
  Write-Verbose "Querying Security log for $ntlmVersionLabel events (Event ID 4624) on $env:COMPUTERNAME"

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

  $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
  Write-Verbose "Querying Security log for $ntlmVersionLabel events on DCs: $($domainControllers -join ', ')"

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
  Write-Verbose "Querying Security log for $ntlmVersionLabel events (Event ID 4624) on remote host: $Target"

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
# Reference: Properties (EventData) fields of Event ID 4624
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
