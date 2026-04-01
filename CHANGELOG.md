# Changelog for Get-NtlmLogonEvents

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [4.6.0] - 2026-03-04

### Changed

- Enriched `LogonType` output with human-readable descriptions — now shows
  `3 (Network)` instead of just `3`. Covers all standard logon types (0, 2–5, 7–13).
  Unknown types pass through unchanged. Applied in both local and remote (WinRM)
  code paths.

### Added

- Comprehensive Pester tests for all logon type mappings.

## [4.5.0] - 2026-03-04

### Added

- `-IncludeMessage` switch — includes the full human-readable event `Message` text
  in output for both Security log events (4624/4625) and NTLM Operational log events
  (8001-8006/4001-4006). Useful for detailed forensic review or exporting
  human-readable event descriptions.

## [4.4.0] - 2026-03-03

### Changed

- `-ExcludeNullSessions` now also filters NTLM Operational log events
  (8001-8006/4001-4006) where UserName is empty or `(NULL)` — i.e.
  anonymous/null-credential NTLM probes (e.g. SMB null sessions, DFS referrals,
  GPO processing by IP). Previously the switch only applied to Security log events
  (4624/4625).

## [4.3.0] - 2026-03-03

### Fixed

- Misleading `Write-Error` when no NTLM events exist on domain controllers — now
  emits a clear `Write-Warning` instead (matching localhost/remote-host behavior).
- `Cannot index into a null array` crash in NTLM Operational log parsing when event
  `Properties` collection is null or empty — added null guards in both
  `Convert-NtlmOperationalEventToObject` and the remote script block, with safe
  per-index bounds checks.

## [4.2.0] - 2026-02-26

### Changed

- `-Target Forest` now queries each domain's DCs separately instead of batching all
  forest DCs into a single `Invoke-Command` call; if one domain's DCs are unreachable
  (e.g. WinRM/DNS failure), the module emits a warning and continues with the
  remaining domains instead of failing entirely. Applies to event queries, NTLM
  operational log queries, and `-CheckAuditConfig`.

## [4.1.0] - 2026-02-26

### Fixed

- Error handling for Azure AD-joined clients using `-Target DCs` or `-Target Forest`
  without line-of-sight to a domain controller.

### Added

- KDC Proxy documentation references to remediation guide and acknowledgments.

## [4.0.0] - 2026-02-26

### Changed

- **Breaking:** Refactored to proper PowerShell parameter sets (`Default`,
  `ComputerName`, `AuditConfig`, `AuditConfigComputerName`).
- `-Target` now uses `[ValidateSet('Localhost', 'DCs', 'Forest')]`
  (default `Localhost`).
- `-CheckAuditConfig` is mandatory in its own parameter sets.
- Event-only parameters restricted to event query sets.
- `-Domain` restricted to Target-based sets.

### Added

- `-ComputerName` (`String[]`) parameter replaces `-Target <hostname>` for querying
  specific remote hosts.

## [3.3.0] - 2026-02-26

### Added

- `-Target Forest` to query all domain controllers across every domain in the AD
  forest; enumerates domains via `Get-ADForest` and collects DCs from each.

## [3.2.0] - 2026-02-26

### Added

- `-CheckAuditConfig` switch to verify NTLM audit/restriction GPO settings.
- `-IncludeNtlmOperationalLog` switch to query NTLM Operational log (events
  8001-8006 audit + 4001-4006 block).
- `Build-NtlmOperationalXPathFilter`, `Convert-NtlmOperationalEventToObject`, and
  `Test-NtlmAuditConfiguration` helper functions.
- NTLM Event ID Reference, Audit GPO Settings Reference, and Remediation Guide in
  README.

## [3.1.0] - 2026-02-25

### Added

- `-CorrelatePrivileged` switch for Event ID 4672 correlation.
- `TargetLogonId`, `IsPrivileged`, and `PrivilegeList` output fields.
- `Get-PrivilegedLogonLookup` and `Merge-PrivilegedLogonData` helper functions.

## [3.0.0] - 2026-02-25

### Added

- `-IncludeFailedLogons` switch for Event ID 4625.
- `-Domain` parameter for multi-domain/forest DC queries.
- `AuthenticationPackageName` and `LogonProcessName` output fields to identify
  Negotiate→NTLM fallbacks.
- `EventId`, `Status`, `FailureReason`, and `SubStatus` fields.
- Separate property mapping for 4624 vs 4625 layouts.

## [2.1.0] - 2023-05-25

### Fixed

- Parameter splatting for optional DateTime parameters.
- Relaxed pipeline type constraint for testability.

### Added

- Comprehensive Pester test suite (60 tests).

## [2.0.0] - 2023-05-04

### Changed

- Major rewrite: structured output objects, XPath filtering, date range support,
  credential support, impersonation level translation.
