# System Patterns

## Architecture
- **Sampler-based PowerShell module** using ModuleBuilder for compilation
- Single public function (`Get-NtlmLogonEvents`) with 7 private helpers
- ModuleBuilder compiles `source/Public/*.ps1` and `source/Private/*.ps1` into a single `.psm1`

## Project Structure
```
source/
  Public/Get-NtlmLogonEvents.ps1      # Main exported function (1214 lines)
  Private/
    Build-XPathFilter.ps1              # XPath filter for Security log (4624/4625)
    Build-NtlmOperationalXPathFilter.ps1  # XPath filter for NTLM Operational log
    Convert-EventToObject.ps1          # Converts 4624/4625 events to PSCustomObjects
    Convert-NtlmOperationalEventToObject.ps1  # Converts 8001-8006/4001-4006 events
    Get-PrivilegedLogonLookup.ps1      # Queries 4672 events for privilege correlation
    Merge-PrivilegedLogonData.ps1      # Correlates logon events with 4672 privilege data
    Test-NtlmAuditConfiguration.ps1   # Reads registry for NTLM audit/restriction policies
  Get-NtlmLogonEvents.psd1            # Module manifest
  Get-NtlmLogonEvents.psm1            # Empty placeholder (ModuleBuilder fills it)
Tests/
  Unit/
    Public/Get-NtlmLogonEvents.Tests.ps1
    Private/<FunctionName>.Tests.ps1   # One test file per private function
```

## Key Design Patterns
- **Parameter sets**: Default, ComputerName, AuditConfig, AuditConfigComputerName
- **Remote execution**: Uses `Invoke-Command` with embedded script blocks that re-declare helper functions (because WinRM sessions don't have the module loaded)
- **PSCustomObject output**: All output objects have PSTypeName (`NtlmLogonEvent`, `NtlmOperationalEvent`, `NtlmAuditConfig`)
- **Enrichment maps**: Hash tables translate raw event property codes to human-readable text (impersonation levels, logon types, NTSTATUS codes, failure reasons)

## Testing Patterns
- Tests use `InModuleScope 'Get-NtlmLogonEvents'` to access private functions
- Mock `Get-WinEvent` and `Invoke-Command` to avoid requiring Security log access
- Mock EventLogRecord objects using PSCustomObjects with type name injection
- `-ModuleName 'Get-NtlmLogonEvents'` on all mocks for the public function tests

## Build & CI
- Sampler framework: `build.ps1` → InvokeBuild → ModuleBuilder
- GitVersion for semantic versioning
- Azure Pipelines: Build → Unit Test → Code Coverage → Deploy
- Code coverage published to Azure DevOps (JaCoCo format)
- Pester code coverage threshold: 85%
