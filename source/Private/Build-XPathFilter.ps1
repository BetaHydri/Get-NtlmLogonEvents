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
