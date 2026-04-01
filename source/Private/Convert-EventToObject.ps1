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

    # Map LogonType numeric values to human-readable descriptions
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

    # Map FailureReason replacement strings (%%23xx) to human-readable descriptions
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

    # Map common NTSTATUS codes (Status/SubStatus) to human-readable descriptions
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

    # Enrich LogonType with human-readable name
    $rawLogonType = $logonType -as [int]
    $logonType = if ($logonTypeMap.ContainsKey($rawLogonType)) {
      "$rawLogonType ($($logonTypeMap[$rawLogonType]))"
    }
    else {
      $logonType
    }

    # Enrich FailureReason replacement string with human-readable text
    if ($failureReason) {
      $rawFailureReason = $failureReason -as [string]
      $failureReason = if ($failureReasonMap.ContainsKey($rawFailureReason)) {
        $failureReasonMap[$rawFailureReason]
      }
      else {
        $rawFailureReason
      }
    }

    # Enrich Status NTSTATUS code with human-readable description
    if ($status) {
      $rawStatus = $status -as [string]
      $status = if ($ntStatusMap.ContainsKey($rawStatus)) {
        "$rawStatus ($($ntStatusMap[$rawStatus]))"
      }
      else {
        $rawStatus
      }
    }

    # Enrich SubStatus NTSTATUS code with human-readable description
    if ($subStatus) {
      $rawSubStatus = $subStatus -as [string]
      $subStatus = if ($ntStatusMap.ContainsKey($rawSubStatus)) {
        "$rawSubStatus ($($ntStatusMap[$rawSubStatus]))"
      }
      else {
        $rawSubStatus
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
      Message                   = $Event.Message
      ComputerName              = $ComputerName
    }
  }
}

