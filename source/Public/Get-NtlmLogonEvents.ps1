function Get-NtlmLogonEvents
{
  <#
    .SYNOPSIS
    Retrieves NTLM logon events (NTLMv1, NTLMv2, LM) from the Windows Security event log.

    .DESCRIPTION
    This function queries the Windows Security event log for NTLM authentication events
    (Event ID 4624 for successful logons, and optionally Event ID 4625 for failed logons).
    It supports filtering by NTLM version, date range, and null sessions.

    Targets can be the local machine, a remote server (via WinRM), or all domain controllers
    (requires the ActiveDirectory PowerShell module).

    The output is structured objects suitable for pipeline processing, exporting to CSV/JSON,
    or display in the console.

    .EXAMPLE
    Get-NtlmLogonEvents

    Gets the last 30 NTLM logon events (NTLMv1, NTLMv2, LM) from the localhost.

    .EXAMPLE
    Get-NtlmLogonEvents -NumEvents 10

    Gets the last 10 NTLM logon events from the localhost.

    .EXAMPLE
    Get-NtlmLogonEvents -ComputerName server.contoso.com

    Gets the last 30 NTLM logon events from server.contoso.com via WinRM.

    .EXAMPLE
    Get-NtlmLogonEvents -ComputerName server.contoso.com -OnlyNTLMv1

    Gets the last 30 NTLMv1-only logon events from server.contoso.com via WinRM.

    .EXAMPLE
    Get-NtlmLogonEvents -Target DCs

    Gets the last 30 NTLM logon events on each domain controller.
    Requires WinRM and the ActiveDirectory PowerShell module.

    .EXAMPLE
    Get-NtlmLogonEvents -Target DCs -Domain child.contoso.com

    Gets the last 30 NTLM logon events on each domain controller in the child.contoso.com domain.
    Requires a trust relationship or appropriate credentials.

    .EXAMPLE
    Get-NtlmLogonEvents -ExcludeNullSessions

    Gets the last 30 NTLM logon events excluding ANONYMOUS LOGON (null sessions).

    .EXAMPLE
    Get-NtlmLogonEvents -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date)

    Gets NTLM logon events from the last 7 days.

    .EXAMPLE
    Get-NtlmLogonEvents -ComputerName server.contoso.com -Credential (Get-Credential)

    Connects to server.contoso.com using alternate credentials.

    .EXAMPLE
    Get-NtlmLogonEvents -ComputerName server.contoso.com -Authentication Negotiate

    Connects to server.contoso.com forcing Negotiate authentication (Kerberos with NTLM fallback).
    Useful when Kerberos alone fails due to clock skew, missing SPNs, or workgroup scenarios.

    .EXAMPLE
    Get-NtlmLogonEvents -ComputerName server.contoso.com -Credential (Get-Credential) -Authentication Negotiate

    Connects with explicit credentials and Negotiate authentication (NTLM fallback enabled).

    .EXAMPLE
    Get-NtlmLogonEvents | Export-Csv -Path .\ntlm_events.csv -NoTypeInformation

    Exports all NTLM logon events to a CSV file.

    .EXAMPLE
    Get-NtlmLogonEvents -OnlyNTLMv1 -ExcludeNullSessions

    Gets the last 30 NTLMv1-only logon events excluding null sessions.

    .EXAMPLE
    Get-NtlmLogonEvents -IncludeFailedLogons

    Gets the last 30 NTLM logon events including failed logon attempts (Event ID 4625).

    .EXAMPLE
    Get-NtlmLogonEvents -IncludeFailedLogons -OnlyNTLMv1 | Where-Object EventId -eq 4625

    Gets only the failed NTLMv1 logon attempts.

    .EXAMPLE
    Get-NtlmLogonEvents -CorrelatePrivileged

    Gets the last 30 NTLM logon events and correlates with Event ID 4672 to identify
    privileged logon sessions. Adds IsPrivileged and PrivilegeList fields to the output.

    .EXAMPLE
    Get-NtlmLogonEvents -CorrelatePrivileged -ExcludeNullSessions | Where-Object IsPrivileged

    Finds NTLM logons that received special privileges (excluding null sessions).

    .EXAMPLE
    Get-NtlmLogonEvents -ComputerName dc01.contoso.com, dc02.contoso.com -NumEvents 100

    Queries specific domain controllers (or any servers) by name. Accepts multiple hosts.

    .EXAMPLE
    Get-NtlmLogonEvents -CheckAuditConfig

    Checks the local machine's NTLM audit and restriction policy configuration.
    Reports whether recommended GPO settings from Microsoft's AD hardening guidance are enabled.

    .EXAMPLE
    Get-NtlmLogonEvents -CheckAuditConfig -Target DCs

    Checks NTLM audit configuration on all domain controllers in the current domain.

    .EXAMPLE
    Get-NtlmLogonEvents -CheckAuditConfig -ComputerName server.contoso.com

    Checks NTLM audit configuration on a specific remote server.

    .EXAMPLE
    Get-NtlmLogonEvents -Target Forest

    Gets the last 30 NTLM logon events on every domain controller across all domains
    in the AD forest. Requires WinRM, the ActiveDirectory PowerShell module, and
    appropriate trust/credentials for each domain.

    .EXAMPLE
    Get-NtlmLogonEvents -CheckAuditConfig -Target Forest

    Checks NTLM audit configuration on all domain controllers across the entire forest.

    .EXAMPLE
    Get-NtlmLogonEvents -IncludeNtlmOperationalLog

    Gets the last 30 NTLM logon events from the Security log AND up to 30 events from the
    Microsoft-Windows-NTLM/Operational log (events 8001-8006 audit, 4001-4006 block).

    .EXAMPLE
    Get-NtlmLogonEvents -IncludeNtlmOperationalLog -NumEvents 500 |
        Where-Object { $_.PSObject.TypeNames -contains 'NtlmOperationalEvent' }

    Gets only the NTLM operational log events (includes process-level detail that 4624 lacks).

    .EXAMPLE
    Get-NtlmLogonEvents -IncludeMessage

    Gets the last 30 NTLM logon events and includes the full event Message text in the output.
    Useful for detailed forensic review or exporting human-readable event descriptions.

    .EXAMPLE
    Get-NtlmLogonEvents -IncludeNtlmOperationalLog -IncludeMessage | Format-List

    Includes the Message text from both Security log and NTLM Operational log events.

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
    When specified, filters out ANONYMOUS LOGON (null session) events from the Security log
    (Event ID 4624/4625) and null-credential events from the NTLM Operational log
    (events where UserName is empty or '(NULL)').
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

    .PARAMETER Authentication
    Specifies the authentication mechanism for WinRM connections to remote computers.
    Valid values: Default, Negotiate, Kerberos, NegotiateWithImplicitCredential.
    When omitted, WinRM uses its default (typically Negotiate, which tries Kerberos first
    and falls back to NTLM). Use 'Negotiate' or 'NegotiateWithImplicitCredential' when
    Kerberos is unavailable (e.g., workgroup machines, clock skew, missing SPNs).
    Works independently of -Credential — you can force NTLM fallback with or without
    explicit credentials.

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
    (see -CheckAuditConfig). When -ExcludeNullSessions is also specified, null-credential
    operational events (UserName empty or '(NULL)') are filtered out.

    .PARAMETER IncludeMessage
    When specified, includes the full event Message text in the output for both Security log
    events (4624/4625) and NTLM Operational log events (8001-8006, 4001-4006). The Message
    property contains the human-readable event description rendered by Windows.
    By default, Message is omitted to keep output compact.

    .LINK
    TechNet - The Most Misunderstood Windows Security Setting of All Time
    http://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx

    .LINK
    Microsoft Security Auditing Reference
    https://www.microsoft.com/en-us/download/details.aspx?id=52630

    .NOTES
    Author:  Jan Tiedemann
    Version: 4.6
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
    [Parameter(ParameterSetName = 'ComputerName')]
    [switch]$IncludeMessage,

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'AuditConfig')]
    [string]$Domain,

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'ComputerName')]
    [datetime]$StartTime,

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'ComputerName')]
    [datetime]$EndTime,

    [ValidateSet('Default', 'Negotiate', 'Kerberos', 'NegotiateWithImplicitCredential')]
    [string]$Authentication,

    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty
  )

  # --- CheckAuditConfig standalone mode ---
  if ($CheckAuditConfig)
  {
    $auditConfigOutputProperties = @(
      'PolicyName', 'RegistryPath', 'RawValue', 'Setting',
      'Recommended', 'IsRecommended', 'Scope', 'ComputerName'
    )

    # Remote script block embeds the same logic as Test-NtlmAuditConfiguration
    $checkAuditConfigScriptBlock = {
      $msv1_0Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
      $netlogonPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

      function Get-RegValue
      {
        param([string]$Path, [string]$Name)
        try
        {
          (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name 
        }
        catch
        {
          $null 
        }
      }

      $policies = @(
        @{
          Policy = 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic'
          RegPath = "$msv1_0Path\AuditReceivingNTLMTraffic"
          Path = $msv1_0Path; Name = 'AuditReceivingNTLMTraffic'
          Map = @{ 0 = 'Disable'; 1 = 'Enable auditing for domain accounts'; 2 = 'Enable auditing for all accounts' }
          Rec = 'Enable auditing for domain accounts (safe to enable)'
          RecTest = { param($v) $null -ne $v -and [int]$v -ge 1 }
          Scope = 'All devices'
        }
        @{
          Policy = 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'
          RegPath = "$msv1_0Path\RestrictSendingNTLMTraffic"
          Path = $msv1_0Path; Name = 'RestrictSendingNTLMTraffic'
          Map = @{ 0 = 'Allow all'; 1 = 'Audit all'; 2 = 'Deny all' }
          Rec = 'Audit all (safe — audit only)'
          RecTest = { param($v) $null -ne $v -and [int]$v -ge 1 }
          Scope = 'All devices'
        }
        @{
          Policy = 'Network security: Restrict NTLM: Incoming NTLM traffic'
          RegPath = "$msv1_0Path\RestrictReceivingNTLMTraffic"
          Path = $msv1_0Path; Name = 'RestrictReceivingNTLMTraffic'
          Map = @{ 0 = 'Allow all'; 1 = 'Deny all domain accounts'; 2 = 'Deny all accounts' }
          Rec = 'Deny all domain accounts (final goal — configure only after auditing is complete)'
          RecTest = { param($v) $null -ne $v -and [int]$v -ge 1 }
          Scope = 'All devices'
        }
        @{
          Policy = 'Network security: Restrict NTLM: Audit NTLM authentication in this domain'
          RegPath = "$netlogonPath\AuditNTLMInDomain"
          Path = $netlogonPath; Name = 'AuditNTLMInDomain'
          Map = @{ 0 = 'Disable'; 1 = 'Enable for domain accounts to domain servers'; 3 = 'Enable for domain accounts'; 5 = 'Enable for domain servers'; 7 = 'Enable all' }
          Rec = 'Enable all (safe to enable)'
          RecTest = { param($v) $null -ne $v -and [int]$v -eq 7 }
          Scope = 'Domain Controllers only'
        }
        @{
          Policy = 'Network security: Restrict NTLM: NTLM authentication in this domain'
          RegPath = "$netlogonPath\RestrictNTLMInDomain"
          Path = $netlogonPath; Name = 'RestrictNTLMInDomain'
          Map = @{ 0 = 'Disable'; 1 = 'Deny for domain accounts to domain servers'; 3 = 'Deny for domain accounts'; 5 = 'Deny for domain servers'; 7 = 'Deny all' }
          Rec = 'Deny all (final goal — configure only after auditing is complete)'
          RecTest = { param($v) $null -ne $v -and [int]$v -ge 1 }
          Scope = 'Domain Controllers only'
        }
      )

      foreach ($p in $policies)
      {
        $raw = Get-RegValue -Path $p.Path -Name $p.Name
        $setting = if ($null -eq $raw)
        {
          'Not configured' 
        }
        elseif ($p.Map.ContainsKey([int]$raw))
        {
          $p.Map[[int]$raw] 
        }
        else
        {
          "Unknown ($raw)" 
        }
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
      if ($cEx)
      {
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
      if ($dEx)
      {
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
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
    {
      $checkInvokeParams['Credential'] = $Credential
    }
    if ($PSBoundParameters.ContainsKey('Authentication'))
    {
      $checkInvokeParams['Authentication'] = $Authentication
    }

    if ($Target -eq 'Localhost' -and -not $PSBoundParameters.ContainsKey('ComputerName'))
    {
      Write-Verbose 'Checking NTLM audit configuration on local host...'
      Test-NtlmAuditConfiguration
    }
    elseif ($Target -eq 'DCs')
    {
      Write-Verbose 'Loading ActiveDirectory module to enumerate domain controllers...'
      try
      {
        Import-Module ActiveDirectory -ErrorAction Stop
      }
      catch
      {
        Write-Error "The ActiveDirectory PowerShell module is required for -Target DCs. Install RSAT or run from a DC. Error: $_"
        return
      }
      try
      {
        $domainControllers = if ($Domain)
        {
          Get-ADDomainController -Filter * -Server $Domain -ErrorAction Stop | Select-Object -ExpandProperty HostName
        }
        else
        {
          Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
        }
      }
      catch
      {
        Write-Error "Failed to enumerate domain controllers. Ensure this machine can reach Active Directory Web Services (ADWS). Azure AD-joined clients without line-of-sight to a domain controller cannot use -Target DCs. Error: $_"
        return
      }
      if (-not $domainControllers)
      {
        Write-Error 'No domain controllers were found. Verify the domain name and network connectivity.'
        return
      }
      $domainLabel = if ($Domain)
      {
        " in domain '$Domain'" 
      }
      else
      {
        '' 
      }
      Write-Verbose "Checking NTLM audit configuration on DCs${domainLabel}: $($domainControllers -join ', ')"

      $checkInvokeParams['ComputerName'] = $domainControllers
      try
      {
        Invoke-Command @checkInvokeParams | Select-Object $auditConfigOutputProperties
      }
      catch
      {
        Write-Error "Failed to check audit configuration on domain controllers: $_"
      }
    }
    elseif ($Target -eq 'Forest')
    {
      Write-Verbose 'Loading ActiveDirectory module to enumerate all forest domain controllers...'
      try
      {
        Import-Module ActiveDirectory -ErrorAction Stop
      }
      catch
      {
        Write-Error "The ActiveDirectory PowerShell module is required for -Target Forest. Install RSAT or run from a DC. Error: $_"
        return
      }
      try
      {
        $forestDomains = (Get-ADForest -ErrorAction Stop).Domains
      }
      catch
      {
        Write-Error "Failed to enumerate forest domains. Ensure this machine can reach Active Directory Web Services (ADWS). Azure AD-joined clients without line-of-sight to a domain controller cannot use -Target Forest. Error: $_"
        return
      }
      Write-Verbose "Forest domains: $($forestDomains -join ', ')"
      $domainDCMap = @{}
      $allDCs = foreach ($dom in $forestDomains)
      {
        try
        {
          $dcs = @(Get-ADDomainController -Filter * -Server $dom -ErrorAction Stop | Select-Object -ExpandProperty HostName)
          $domainDCMap[$dom] = $dcs
          $dcs
        }
        catch
        {
          Write-Warning "Failed to enumerate DCs in domain '${dom}': $_"
        }
      }
      if (-not $allDCs)
      {
        Write-Error 'No domain controllers could be enumerated across the forest.'
        return
      }
      Write-Verbose "Checking NTLM audit configuration on forest DCs: $($allDCs -join ', ')"

      foreach ($dom in $domainDCMap.Keys)
      {
        $domDCs = $domainDCMap[$dom]
        Write-Verbose "Checking NTLM audit configuration on DCs in domain '${dom}': $($domDCs -join ', ')"
        $checkInvokeParams['ComputerName'] = $domDCs
        try
        {
          Invoke-Command @checkInvokeParams | Select-Object $auditConfigOutputProperties
        }
        catch
        {
          Write-Warning "Failed to check audit configuration on DCs in domain '${dom}': $_"
        }
      }
    }
    elseif ($PSBoundParameters.ContainsKey('ComputerName'))
    {
      Write-Verbose "Checking NTLM audit configuration on remote host(s): $($ComputerName -join ', ')"
      $checkInvokeParams['ComputerName'] = $ComputerName
      try
      {
        Invoke-Command @checkInvokeParams | Select-Object $auditConfigOutputProperties
      }
      catch
      {
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
  if ($PSBoundParameters.ContainsKey('StartTime'))
  {
    $filterParams['StartTime'] = $StartTime
  }
  if ($PSBoundParameters.ContainsKey('EndTime'))
  {
    $filterParams['EndTime'] = $EndTime
  }
  $xpathFilter = Build-XPathFilter @filterParams

  $ntlmVersionLabel = if ($OnlyNTLMv1)
  {
    'NTLMv1' 
  }
  else
  {
    'NTLM (v1, v2, LM)' 
  }

  # Output properties for consistent column ordering
  $outputProperties = @(
    'EventId', 'Time', 'UserName', 'TargetDomainName', 'LogonType',
    'LogonProcessName', 'AuthenticationPackageName', 'WorkstationName',
    'LmPackageName', 'IPAddress', 'TCPPort', 'ImpersonationLevel',
    'ProcessName', 'Status', 'FailureReason', 'SubStatus', 'TargetLogonId'
  )
  if ($CorrelatePrivileged)
  {
    $outputProperties += 'IsPrivileged', 'PrivilegeList'
  }
  if ($IncludeMessage)
  {
    $outputProperties += 'Message'
  }
  $outputProperties += 'ComputerName'

  # Build the remote script block (shared for DCs and single remote host)
  $remoteScriptBlock = {
    param($Filter, $MaxEvents, $DoCorrelatePrivileged)

    # Re-declare the converter inside the remote session
    function Convert-RemoteEvent
    {
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

      $logonTypeMap = @{
        0  = 'System'
        2  = 'Interactive'
        3  = 'Network'
        4  = 'Batch'
        5  = 'Service'
        7  = 'Unlock'
        8  = 'NetworkCleartext'
        9  = 'NewCredentials'
        10 = 'RemoteInteractive'
        11 = 'CachedInteractive'
        12 = 'CachedRemoteInteractive'
        13 = 'CachedUnlock'
      }

      $failureReasonMap = @{
        '%%2304' = 'An error occurred during logon'
        '%%2305' = 'The specified user account has expired'
        '%%2306' = 'The NetLogon component is not active'
        '%%2307' = 'Account locked out'
        '%%2308' = 'The user has not been granted the requested logon type at this machine'
        '%%2309' = 'The specified account password has expired'
        '%%2310' = 'Account currently disabled'
        '%%2311' = 'Account logon time restriction violation'
        '%%2312' = 'User not allowed to logon at this computer'
        '%%2313' = 'Unknown user name or bad password'
      }

      $ntStatusMap = @{
        '0xC000005E' = 'No logon servers available'
        '0xC0000064' = 'User logon with misspelled or bad user account'
        '0xC000006A' = 'User logon with misspelled or bad password'
        '0xC000006D' = 'Logon failure: unknown user name or bad password'
        '0xC000006E' = 'User logon with account restriction'
        '0xC000006F' = 'User logon outside authorized hours'
        '0xC0000070' = 'User logon from unauthorized workstation'
        '0xC0000071' = 'User logon with expired password'
        '0xC0000072' = 'User logon to account disabled by administrator'
        '0xC00000DC' = 'SAM server is in the wrong state'
        '0xC0000133' = 'Clocks between DC and other computer too far out of sync'
        '0xC000015B' = 'The user has not been granted the requested logon type at this machine'
        '0xC000018C' = 'The trust relationship between the primary domain and the trusted domain failed'
        '0xC0000192' = 'NetLogon service was not started'
        '0xC0000193' = 'User logon with expired account'
        '0xC0000224' = 'User is required to change password at next logon'
        '0xC0000225' = 'Windows bug — not a risk'
        '0xC0000234' = 'User logon with account locked'
        '0xC00002EE' = 'An error occurred during logon'
        '0xC0000413' = 'Authentication Firewall — logon condition not met'
      }

      $eventId = $Event.Id
      $isFailed = ($eventId -eq 4625)

      if ($isFailed)
      {
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
      else
      {
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
        $impersonationLevel = if ($impersonationMap.ContainsKey($rawImpersonation))
        {
          $impersonationMap[$rawImpersonation]
        }
        else
        {
          $rawImpersonation
        }
      }

      $rawLogonType = $logonType -as [int]
      $logonType = if ($logonTypeMap.ContainsKey($rawLogonType))
      {
        "$rawLogonType ($($logonTypeMap[$rawLogonType]))"
      }
      else
      {
        $logonType
      }

      if ($failureReason)
      {
        $rawFailureReason = $failureReason -as [string]
        $failureReason = if ($failureReasonMap.ContainsKey($rawFailureReason))
        {
          $failureReasonMap[$rawFailureReason]
        }
        else
        {
          $rawFailureReason
        }
      }

      if ($status)
      {
        $rawStatus = $status -as [string]
        $status = if ($ntStatusMap.ContainsKey($rawStatus))
        {
          "$rawStatus ($($ntStatusMap[$rawStatus]))"
        }
        else
        {
          $rawStatus
        }
      }

      if ($subStatus)
      {
        $rawSubStatus = $subStatus -as [string]
        $subStatus = if ($ntStatusMap.ContainsKey($rawSubStatus))
        {
          "$rawSubStatus ($($ntStatusMap[$rawSubStatus]))"
        }
        else
        {
          $rawSubStatus
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
        Message                   = $Event.Message
        ComputerName              = $env:COMPUTERNAME
      }
    }

    $events = @(Get-WinEvent -LogName Security -MaxEvents $MaxEvents -FilterXPath $Filter -ErrorAction Stop |
        ForEach-Object { Convert-RemoteEvent -Event $_ -ComputerName $env:COMPUTERNAME })

    if ($DoCorrelatePrivileged -and $events.Count -gt 0)
    {
      # Correlate with Event ID 4672 (special privileges assigned to new logon)
      $successEvents = @($events | Where-Object { $_.EventId -eq 4624 -and $_.TargetLogonId })
      if ($successEvents.Count -gt 0)
      {
        $times = $successEvents | ForEach-Object { $_.Time }
        $earliest = ($times | Measure-Object -Minimum).Minimum.AddSeconds(-2)
        $latest = ($times | Measure-Object -Maximum).Maximum.AddSeconds(2)
        $startUtc = $earliest.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $endUtc = $latest.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $xpath4672 = "Event[System[EventID=4672 and TimeCreated[@SystemTime>='$startUtc'] and TimeCreated[@SystemTime<='$endUtc']]]"

        $lookup = @{}
        try
        {
          Get-WinEvent -LogName Security -FilterXPath $xpath4672 -ErrorAction Stop | ForEach-Object {
            $logonId = $_.Properties[3].Value -as [string]
            $privileges = ($_.Properties[4].Value -as [string]).Trim()
            if ($logonId -and -not $lookup.ContainsKey($logonId))
            {
              $lookup[$logonId] = $privileges
            }
          }
        }
        catch
        {
          if ($_.Exception.Message -notmatch 'No events were found')
          {
            Write-Warning "Failed to query Event ID 4672: $_"
          }
        }

        foreach ($evt in $events)
        {
          if ($evt.EventId -eq 4624 -and $evt.TargetLogonId -and $lookup.ContainsKey($evt.TargetLogonId))
          {
            $evt | Add-Member -NotePropertyName IsPrivileged -NotePropertyValue $true -Force
            $evt | Add-Member -NotePropertyName PrivilegeList -NotePropertyValue $lookup[$evt.TargetLogonId] -Force
          }
          else
          {
            $evt | Add-Member -NotePropertyName IsPrivileged -NotePropertyValue $false -Force
            $evt | Add-Member -NotePropertyName PrivilegeList -NotePropertyValue $null -Force
          }
        }
      }
      else
      {
        foreach ($evt in $events)
        {
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
  if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
  {
    $invokeParams['Credential'] = $Credential
  }
  if ($PSBoundParameters.ContainsKey('Authentication'))
  {
    $invokeParams['Authentication'] = $Authentication
  }

  # NTLM Operational log setup (if requested)
  if ($IncludeNtlmOperationalLog)
  {
    $ntlmOpFilterParams = @{}
    if ($PSBoundParameters.ContainsKey('StartTime'))
    {
      $ntlmOpFilterParams['StartTime'] = $StartTime 
    }
    if ($PSBoundParameters.ContainsKey('EndTime'))
    {
      $ntlmOpFilterParams['EndTime'] = $EndTime 
    }
    $ntlmOpFilter = Build-NtlmOperationalXPathFilter @ntlmOpFilterParams

    $ntlmOpOutputProperties = @(
      'EventId', 'EventType', 'EventDescription', 'Time',
      'UserName', 'DomainName', 'TargetName', 'WorkstationName',
      'SecureChannelName', 'ProcessName', 'ProcessId'
    )
    if ($IncludeMessage)
    {
      $ntlmOpOutputProperties += 'Message'
    }
    $ntlmOpOutputProperties += 'ComputerName'

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

      try
      {
        Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents $MaxEvents -FilterXPath $Filter -ErrorAction Stop | ForEach-Object {
          $eventId = $_.Id
          $p = $_.Properties
          $timeCreated = $_.TimeCreated
          if (-not $p -or $p.Count -eq 0)
          {
            return 
          }
          $isBlock = ($eventId -ge 4001 -and $eventId -le 4006)
          $eventType = if ($isBlock)
          {
            'Block' 
          }
          else
          {
            'Audit' 
          }
          $baseId = if ($isBlock)
          {
            $eventId + 4000 
          }
          else
          {
            $eventId 
          }

          switch ($baseId)
          {
            '8001'
            {
              [PSCustomObject]@{
                EventId           = $eventId
                EventType         = $eventType
                EventDescription  = $descMap[$eventId]
                Time              = $timeCreated
                UserName          = if ($p.Count -gt 1)
                {
                  $p[1].Value 
                }
                else
                {
                  $null 
                }
                DomainName        = if ($p.Count -gt 2)
                {
                  $p[2].Value 
                }
                else
                {
                  $null 
                }
                TargetName        = if ($p.Count -gt 0)
                {
                  $p[0].Value 
                }
                else
                {
                  $null 
                }
                WorkstationName   = $null
                SecureChannelName = $null
                ProcessName       = if ($p.Count -gt 3)
                {
                  $p[3].Value 
                }
                else
                {
                  $null 
                }
                ProcessId         = if ($p.Count -gt 4)
                {
                  $p[4].Value 
                }
                else
                {
                  $null 
                }
                Message           = $_.Message
                ComputerName      = $env:COMPUTERNAME
              }
            }
            { $_ -in 8002, 8003 }
            {
              [PSCustomObject]@{
                EventId           = $eventId
                EventType         = $eventType
                EventDescription  = $descMap[$eventId]
                Time              = $timeCreated
                UserName          = if ($p.Count -gt 0)
                {
                  $p[0].Value 
                }
                else
                {
                  $null 
                }
                DomainName        = if ($p.Count -gt 1)
                {
                  $p[1].Value 
                }
                else
                {
                  $null 
                }
                TargetName        = $null
                WorkstationName   = if ($p.Count -gt 2)
                {
                  $p[2].Value 
                }
                else
                {
                  $null 
                }
                SecureChannelName = $null
                ProcessName       = if ($p.Count -gt 3)
                {
                  $p[3].Value 
                }
                else
                {
                  $null 
                }
                ProcessId         = if ($p.Count -gt 4)
                {
                  $p[4].Value 
                }
                else
                {
                  $null 
                }
                Message           = $_.Message
                ComputerName      = $env:COMPUTERNAME
              }
            }
            { $_ -in 8004, 8005, 8006 }
            {
              [PSCustomObject]@{
                EventId           = $eventId
                EventType         = $eventType
                EventDescription  = $descMap[$eventId]
                Time              = $timeCreated
                UserName          = if ($p.Count -gt 0)
                {
                  $p[0].Value 
                }
                else
                {
                  $null 
                }
                DomainName        = if ($p.Count -gt 1)
                {
                  $p[1].Value 
                }
                else
                {
                  $null 
                }
                TargetName        = $null
                WorkstationName   = if ($p.Count -gt 2)
                {
                  $p[2].Value 
                }
                else
                {
                  $null 
                }
                SecureChannelName = if ($p.Count -gt 3)
                {
                  $p[3].Value 
                }
                else
                {
                  $null 
                }
                ProcessName       = $null
                ProcessId         = $null
                Message           = $_.Message
                ComputerName      = $env:COMPUTERNAME
              }
            }
          }
        }
      }
      catch
      {
        if ($_.Exception.Message -notmatch 'No events were found')
        {
          Write-Warning "Failed to query NTLM Operational log: $_"
        }
      }
    }
  }

  if ($Target -eq 'Localhost' -and -not $PSBoundParameters.ContainsKey('ComputerName'))
  {
    # --- Local host ---
    $eventIdLabel = if ($IncludeFailedLogons)
    {
      'Event ID 4624+4625' 
    }
    else
    {
      'Event ID 4624' 
    }
    Write-Verbose "Querying Security log for $ntlmVersionLabel events ($eventIdLabel) on $env:COMPUTERNAME"

    try
    {
      $events = @(Get-WinEvent -LogName Security -MaxEvents $NumEvents -FilterXPath $xpathFilter -ErrorAction Stop |
          Convert-EventToObject -ComputerName $env:COMPUTERNAME)

      if ($CorrelatePrivileged -and $events.Count -gt 0)
      {
        Write-Verbose 'Correlating with Event ID 4672 (special privileges assigned to new logon)...'
        Merge-PrivilegedLogonData -Events $events
      }

      $events | Select-Object $outputProperties
    }
    catch [Exception]
    {
      if ($_.Exception.Message -match 'No events were found')
      {
        Write-Warning "No matching $ntlmVersionLabel logon events found on $env:COMPUTERNAME."
      }
      else
      {
        Write-Error "Failed to query $env:COMPUTERNAME : $_"
      }
    }

    # NTLM Operational log (process-level detail)
    if ($IncludeNtlmOperationalLog)
    {
      Write-Verbose 'Querying Microsoft-Windows-NTLM/Operational log for NTLM audit/block events...'
      try
      {
        $ntlmOpEvents = Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents $NumEvents -FilterXPath $ntlmOpFilter -ErrorAction Stop |
          Convert-NtlmOperationalEventToObject -ComputerName $env:COMPUTERNAME
        if ($ExcludeNullSessions)
        {
          $ntlmOpEvents | Where-Object { $_.UserName -and $_.UserName -ne '(NULL)' } |
            Select-Object $ntlmOpOutputProperties
        }
        else
        {
          $ntlmOpEvents | Select-Object $ntlmOpOutputProperties
        }
      }
      catch
      {
        if ($_.Exception.Message -match 'No events were found')
        {
          Write-Warning "No NTLM operational events found on $env:COMPUTERNAME. Ensure NTLM auditing policies are configured (use -CheckAuditConfig to verify)."
        }
        else
        {
          Write-Warning "Failed to query NTLM Operational log on ${env:COMPUTERNAME}: $_"
        }
      }
    }
  }
  elseif ($Target -eq 'DCs')
  {
    # --- All Domain Controllers ---
    Write-Verbose "Loading ActiveDirectory module to enumerate domain controllers..."

    try
    {
      Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch
    {
      Write-Error "The ActiveDirectory PowerShell module is required for -Target DCs. Install RSAT or run from a DC. Error: $_"
      return
    }

    try
    {
      $domainControllers = if ($Domain)
      {
        Get-ADDomainController -Filter * -Server $Domain -ErrorAction Stop | Select-Object -ExpandProperty HostName
      }
      else
      {
        Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
      }
    }
    catch
    {
      Write-Error "Failed to enumerate domain controllers. Ensure this machine can reach Active Directory Web Services (ADWS). Azure AD-joined clients without line-of-sight to a domain controller cannot use -Target DCs. Error: $_"
      return
    }
    if (-not $domainControllers)
    {
      Write-Error 'No domain controllers were found. Verify the domain name and network connectivity.'
      return
    }
    $domainLabel = if ($Domain)
    {
      " in domain '$Domain'" 
    }
    else
    {
      '' 
    }
    Write-Verbose "Querying Security log for $ntlmVersionLabel events on DCs${domainLabel}: $($domainControllers -join ', ')"

    $invokeParams['ComputerName'] = $domainControllers

    try
    {
      Invoke-Command @invokeParams |
        Select-Object $outputProperties
    }
    catch
    {
      if ($_.Exception.Message -match 'No events were found')
      {
        Write-Warning "No matching $ntlmVersionLabel logon events found on domain controllers$domainLabel."
      }
      else
      {
        Write-Error "Failed to query domain controllers: $_"
      }
    }

    # NTLM Operational log on DCs
    if ($IncludeNtlmOperationalLog)
    {
      Write-Verbose "Querying Microsoft-Windows-NTLM/Operational log on DCs${domainLabel}..."
      $ntlmOpInvokeParams = @{
        ScriptBlock  = $ntlmOpRemoteScriptBlock
        ComputerName = $domainControllers
        ArgumentList = @($ntlmOpFilter, $NumEvents)
        ErrorAction  = 'Stop'
      }
      if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
      {
        $ntlmOpInvokeParams['Credential'] = $Credential
      }
      if ($PSBoundParameters.ContainsKey('Authentication'))
      {
        $ntlmOpInvokeParams['Authentication'] = $Authentication
      }
      try
      {
        $ntlmOpResults = Invoke-Command @ntlmOpInvokeParams |
          Select-Object $ntlmOpOutputProperties
        if ($ExcludeNullSessions)
        {
          $ntlmOpResults | Where-Object { $_.UserName -and $_.UserName -ne '(NULL)' }
        }
        else
        {
          $ntlmOpResults
        }
      }
      catch
      {
        if ($_.Exception.Message -match 'No events were found')
        {
          Write-Warning 'No NTLM operational events found on domain controllers. Ensure NTLM auditing policies are configured.'
        }
        else
        {
          Write-Warning "Failed to query NTLM Operational log on domain controllers: $_"
        }
      }
    }
  }
  elseif ($Target -eq 'Forest')
  {
    # --- All Domain Controllers across the Forest ---
    Write-Verbose "Loading ActiveDirectory module to enumerate all forest domain controllers..."

    try
    {
      Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch
    {
      Write-Error "The ActiveDirectory PowerShell module is required for -Target Forest. Install RSAT or run from a DC. Error: $_"
      return
    }

    try
    {
      $forestDomains = (Get-ADForest -ErrorAction Stop).Domains
    }
    catch
    {
      Write-Error "Failed to enumerate forest domains. Ensure this machine can reach Active Directory Web Services (ADWS). Azure AD-joined clients without line-of-sight to a domain controller cannot use -Target Forest. Error: $_"
      return
    }
    Write-Verbose "Forest domains: $($forestDomains -join ', ')"
    $domainDCMap = @{}
    $allDCs = foreach ($dom in $forestDomains)
    {
      try
      {
        $dcs = @(Get-ADDomainController -Filter * -Server $dom -ErrorAction Stop | Select-Object -ExpandProperty HostName)
        $domainDCMap[$dom] = $dcs
        $dcs
      }
      catch
      {
        Write-Warning "Failed to enumerate DCs in domain '${dom}': $_"
      }
    }
    if (-not $allDCs)
    {
      Write-Error 'No domain controllers could be enumerated across the forest.'
      return
    }
    Write-Verbose "Querying Security log for $ntlmVersionLabel events on forest DCs: $($allDCs -join ', ')"

    foreach ($dom in $domainDCMap.Keys)
    {
      $domDCs = $domainDCMap[$dom]
      Write-Verbose "Querying Security log on DCs in domain '${dom}': $($domDCs -join ', ')"
      $invokeParams['ComputerName'] = $domDCs
      try
      {
        Invoke-Command @invokeParams |
          Select-Object $outputProperties
      }
      catch
      {
        if ($_.Exception.Message -match 'No events were found')
        {
          Write-Warning "No matching $ntlmVersionLabel logon events found on DCs in domain '${dom}'."
        }
        else
        {
          Write-Warning "Failed to query DCs in domain '${dom}': $_"
        }
      }

      # NTLM Operational log per domain
      if ($IncludeNtlmOperationalLog)
      {
        Write-Verbose "Querying Microsoft-Windows-NTLM/Operational log on DCs in domain '${dom}'..."
        $ntlmOpInvokeParams = @{
          ScriptBlock  = $ntlmOpRemoteScriptBlock
          ComputerName = $domDCs
          ArgumentList = @($ntlmOpFilter, $NumEvents)
          ErrorAction  = 'Stop'
        }
        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
        {
          $ntlmOpInvokeParams['Credential'] = $Credential
        }
        if ($PSBoundParameters.ContainsKey('Authentication'))
        {
          $ntlmOpInvokeParams['Authentication'] = $Authentication
        }
        try
        {
          $ntlmOpResults = Invoke-Command @ntlmOpInvokeParams |
            Select-Object $ntlmOpOutputProperties
          if ($ExcludeNullSessions)
          {
            $ntlmOpResults | Where-Object { $_.UserName -and $_.UserName -ne '(NULL)' }
          }
          else
          {
            $ntlmOpResults
          }
        }
        catch
        {
          if ($_.Exception.Message -match 'No events were found')
          {
            Write-Warning "No NTLM operational events found on DCs in domain '${dom}'. Ensure NTLM auditing policies are configured."
          }
          else
          {
            Write-Warning "Failed to query NTLM Operational log on DCs in domain '${dom}': $_"
          }
        }
      }
    }
  }
  elseif ($PSBoundParameters.ContainsKey('ComputerName'))
  {
    # --- Specific remote host(s) ---
    $eventIdLabel = if ($IncludeFailedLogons)
    {
      'Event ID 4624+4625' 
    }
    else
    {
      'Event ID 4624' 
    }
    Write-Verbose "Querying Security log for $ntlmVersionLabel events ($eventIdLabel) on remote host(s): $($ComputerName -join ', ')"

    $invokeParams['ComputerName'] = $ComputerName

    try
    {
      Invoke-Command @invokeParams |
        Select-Object $outputProperties
    }
    catch [Exception]
    {
      if ($_.Exception.Message -match 'No events were found')
      {
        Write-Warning "No matching $ntlmVersionLabel logon events found on $($ComputerName -join ', ')."
      }
      else
      {
        Write-Error "Failed to query $($ComputerName -join ', '): $_"
      }
    }

    # NTLM Operational log on remote host(s)
    if ($IncludeNtlmOperationalLog)
    {
      Write-Verbose "Querying Microsoft-Windows-NTLM/Operational log on remote host(s): $($ComputerName -join ', ')"
      $ntlmOpInvokeParams = @{
        ScriptBlock  = $ntlmOpRemoteScriptBlock
        ComputerName = $ComputerName
        ArgumentList = @($ntlmOpFilter, $NumEvents)
        ErrorAction  = 'Stop'
      }
      if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
      {
        $ntlmOpInvokeParams['Credential'] = $Credential
      }
      if ($PSBoundParameters.ContainsKey('Authentication'))
      {
        $ntlmOpInvokeParams['Authentication'] = $Authentication
      }
      try
      {
        $ntlmOpResults = Invoke-Command @ntlmOpInvokeParams |
          Select-Object $ntlmOpOutputProperties
        if ($ExcludeNullSessions)
        {
          $ntlmOpResults | Where-Object { $_.UserName -and $_.UserName -ne '(NULL)' }
        }
        else
        {
          $ntlmOpResults
        }
      }
      catch
      {
        if ($_.Exception.Message -match 'No events were found')
        {
          Write-Warning "No NTLM operational events found on $($ComputerName -join ', '). Ensure NTLM auditing policies are configured."
        }
        else
        {
          Write-Warning "Failed to query NTLM Operational log on $($ComputerName -join ', '): $_"
        }
      }
    }
  }

  #endregion
}
