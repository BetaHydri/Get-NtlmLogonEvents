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
    $props = $Event.Properties
    if (-not $props -or $props.Count -eq 0) {
      Write-Warning "Skipping Event ID $eventId at $($Event.TimeCreated) — event Properties collection is empty or null."
      return
    }
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

    # Capture the event message text (contains policy guidance from Windows)
    $messageText = $Event.Message

    switch ($baseId) {
      # 8001/4001: Client outgoing — TargetName[0], UserName[1], DomainName[2], CallerPID[3], ProcessName[4]
      '8001' {
        [PSCustomObject]@{
          PSTypeName        = 'NtlmOperationalEvent'
          EventId           = $eventId
          EventType         = $eventType
          EventDescription  = $descMap[$eventId]
          Time              = $Event.TimeCreated
          UserName          = if ($props.Count -gt 1) { $props[1].Value } else { $null }
          DomainName        = if ($props.Count -gt 2) { $props[2].Value } else { $null }
          TargetName        = if ($props.Count -gt 0) { $props[0].Value } else { $null }
          WorkstationName   = $null
          SecureChannelName = $null
          ProcessName       = if ($props.Count -gt 4) { $props[4].Value } else { $null }
          ProcessId         = if ($props.Count -gt 3) { $props[3].Value } else { $null }
          Message           = $messageText
          ComputerName      = $ComputerName
        }
      }
      # 8002/4002: Incoming NTLM (local/loopback) — CallerPID[0], ProcessName[1], ClientLUID[2], ClientUserName[3], ClientDomainName[4]
      '8002' {
        [PSCustomObject]@{
          PSTypeName        = 'NtlmOperationalEvent'
          EventId           = $eventId
          EventType         = $eventType
          EventDescription  = $descMap[$eventId]
          Time              = $Event.TimeCreated
          UserName          = if ($props.Count -gt 3) { $props[3].Value } else { $null }
          DomainName        = if ($props.Count -gt 4) { $props[4].Value } else { $null }
          TargetName        = $null
          WorkstationName   = $null
          SecureChannelName = $null
          ProcessName       = if ($props.Count -gt 1) { $props[1].Value } else { $null }
          ProcessId         = if ($props.Count -gt 0) { $props[0].Value } else { $null }
          Message           = $messageText
          ComputerName      = $ComputerName
        }
      }
      # 8003/4003: Server incoming (domain account) — UserName[0], DomainName[1], Workstation[2], CallerPID[3], ProcessName[4]
      '8003' {
        [PSCustomObject]@{
          PSTypeName        = 'NtlmOperationalEvent'
          EventId           = $eventId
          EventType         = $eventType
          EventDescription  = $descMap[$eventId]
          Time              = $Event.TimeCreated
          UserName          = if ($props.Count -gt 0) { $props[0].Value } else { $null }
          DomainName        = if ($props.Count -gt 1) { $props[1].Value } else { $null }
          TargetName        = $null
          WorkstationName   = if ($props.Count -gt 2) { $props[2].Value } else { $null }
          SecureChannelName = $null
          ProcessName       = if ($props.Count -gt 4) { $props[4].Value } else { $null }
          ProcessId         = if ($props.Count -gt 3) { $props[3].Value } else { $null }
          Message           = $messageText
          ComputerName      = $ComputerName
        }
      }
      # 8004-8006/4004-4006: DC — SChannelName[0], UserName[1], DomainName[2], WorkstationName[3], SChannelType[4]
      { $_ -in 8004, 8005, 8006 } {
        [PSCustomObject]@{
          PSTypeName        = 'NtlmOperationalEvent'
          EventId           = $eventId
          EventType         = $eventType
          EventDescription  = $descMap[$eventId]
          Time              = $Event.TimeCreated
          UserName          = if ($props.Count -gt 1) { $props[1].Value } else { $null }
          DomainName        = if ($props.Count -gt 2) { $props[2].Value } else { $null }
          TargetName        = $null
          WorkstationName   = if ($props.Count -gt 3) { $props[3].Value } else { $null }
          SecureChannelName = if ($props.Count -gt 0) { $props[0].Value } else { $null }
          ProcessName       = $null
          ProcessId         = $null
          Message           = $messageText
          ComputerName      = $ComputerName
        }
      }
    }
  }
}

