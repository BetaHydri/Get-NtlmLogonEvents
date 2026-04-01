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

