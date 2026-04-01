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

