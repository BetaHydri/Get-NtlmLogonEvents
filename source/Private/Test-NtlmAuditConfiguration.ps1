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
      Recommended  = 'Enable auditing for domain accounts (safe to enable)'
      RecTest      = { param($v) $null -ne $v -and [int]$v -ge 1 }
      Scope        = 'All devices'
    }
    @{
      PolicyName   = 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'
      RegistryPath = "$msv1_0Path\RestrictSendingNTLMTraffic"
      RegPath      = $msv1_0Path
      ValueName    = 'RestrictSendingNTLMTraffic'
      ValueMap     = @{ 0 = 'Allow all'; 1 = 'Audit all'; 2 = 'Deny all' }
      Recommended  = 'Audit all (safe — audit only)'
      RecTest      = { param($v) $null -ne $v -and [int]$v -ge 1 }
      Scope        = 'All devices'
    }
    @{
      PolicyName   = 'Network security: Restrict NTLM: Incoming NTLM traffic'
      RegistryPath = "$msv1_0Path\RestrictReceivingNTLMTraffic"
      RegPath      = $msv1_0Path
      ValueName    = 'RestrictReceivingNTLMTraffic'
      ValueMap     = @{ 0 = 'Allow all'; 1 = 'Deny all domain accounts'; 2 = 'Deny all accounts' }
      Recommended  = 'Deny all domain accounts (final goal — configure only after auditing is complete)'
      RecTest      = { param($v) $null -ne $v -and [int]$v -ge 1 }
      Scope        = 'All devices'
    }
    @{
      PolicyName   = 'Network security: Restrict NTLM: Audit NTLM authentication in this domain'
      RegistryPath = "$netlogonPath\AuditNTLMInDomain"
      RegPath      = $netlogonPath
      ValueName    = 'AuditNTLMInDomain'
      ValueMap     = @{ 0 = 'Disable'; 1 = 'Enable for domain accounts to domain servers'; 3 = 'Enable for domain accounts'; 5 = 'Enable for domain servers'; 7 = 'Enable all' }
      Recommended  = 'Enable all (safe to enable)'
      RecTest      = { param($v) $null -ne $v -and [int]$v -eq 7 }
      Scope        = 'Domain Controllers only'
    }
    @{
      PolicyName   = 'Network security: Restrict NTLM: NTLM authentication in this domain'
      RegistryPath = "$netlogonPath\RestrictNTLMInDomain"
      RegPath      = $netlogonPath
      ValueName    = 'RestrictNTLMInDomain'
      ValueMap     = @{ 0 = 'Disable'; 1 = 'Deny for domain accounts to domain servers'; 3 = 'Deny for domain accounts'; 5 = 'Deny for domain servers'; 7 = 'Deny all' }
      Recommended  = 'Deny all (final goal — configure only after auditing is complete)'
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

