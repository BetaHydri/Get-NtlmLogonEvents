# Changelog for Get-NtlmLogonEvents

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Sampler module structure.

## [1.0.0] - 2026-04-01

### Added

- Converted monolithic script to Sampler-based PowerShell module.
- Public function `Get-NtlmLogonEvents` with full parameter set support.
- 7 private helper functions: `Build-XPathFilter`, `Build-NtlmOperationalXPathFilter`,
  `Convert-EventToObject`, `Convert-NtlmOperationalEventToObject`,
  `Get-PrivilegedLogonLookup`, `Merge-PrivilegedLogonData`, `Test-NtlmAuditConfiguration`.
- Support for querying NTLM logon events (4624/4625) from Security log.
- Support for NTLM Operational log events (8001-8006, 4001-4006).
- Target modes: Localhost, DCs (domain controllers), Forest (all DCs across forest).
- ComputerName parameter set for querying specific remote hosts.
- `-CheckAuditConfig` mode to verify NTLM auditing policy configuration.
- `-CorrelatePrivileged` to correlate logon events with Event ID 4672.
- `-OnlyNTLMv1`, `-ExcludeNullSessions`, `-IncludeFailedLogons` filters.
- `-StartTime` / `-EndTime` date range filtering.
- `-Credential` and `-Authentication` for cross-domain/remote scenarios.
- 165 Pester 5 unit tests across 8 test files.
- Azure Pipelines CI/CD with PowerShell 5.1 and 7.x matrix.
- Code coverage reporting to Azure DevOps.

