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

