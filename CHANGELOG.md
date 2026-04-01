# Changelog for Get-NtlmLogonEvents

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Sampler module structure.

## [5.1.0] - 2026-04-01

### Changed

- **Breaking:** Converted monolithic script (v4.6) to Sampler-based PowerShell module.
  Install via `Install-Module Get-NtlmLogonEvents` instead of dot-sourcing the script.

### Added

- Sampler build framework with ModuleBuilder, InvokeBuild, and Pester 5.
- Public function `Get-NtlmLogonEvents` with full parameter set support.
- 7 private helper functions: `Build-XPathFilter`, `Build-NtlmOperationalXPathFilter`,
  `Convert-EventToObject`, `Convert-NtlmOperationalEventToObject`,
  `Get-PrivilegedLogonLookup`, `Merge-PrivilegedLogonData`, `Test-NtlmAuditConfiguration`.
- 165 Pester 5 unit tests across 8 test files.
- Azure Pipelines CI/CD with PowerShell 5.1 and 7.x matrix.
- Code coverage reporting to Azure DevOps.
- All features from script v4.6 preserved: NTLM logon events (4624/4625),
  NTLM Operational log (8001-8006, 4001-4006), Target modes (Localhost/DCs/Forest),
  ComputerName, CheckAuditConfig, CorrelatePrivileged, OnlyNTLMv1,
  ExcludeNullSessions, IncludeFailedLogons, StartTime/EndTime,
  Credential, Authentication, Domain, IncludeMessage.
- Azure Pipelines CI/CD with PowerShell 5.1 and 7.x matrix.
- Code coverage reporting to Azure DevOps.

