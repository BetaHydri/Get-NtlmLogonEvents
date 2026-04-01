# Project Brief: Get-NtlmLogonEvents

## Core Purpose
PowerShell module to audit NTLM authentication events from Windows Security and NTLM Operational logs.

## Goals
- Provide a single command (`Get-NtlmLogonEvents`) that queries NTLM logon events (4624/4625) from Security logs
- Support filtering by NTLMv1/v2, failed logons, privileged sessions (4672), date ranges, and null sessions
- Validate NTLM audit GPO settings via `-CheckAuditConfig`
- Target localhost, remote servers (WinRM), domain controllers, or entire AD forest
- Query NTLM Operational log (8001-8006, 4001-4006) for process-level detail
- Publish as a PowerShell module to PSGallery via Sampler build framework
- CI/CD via Azure Pipelines at https://dev.azure.com/fam-tiedemann/
- Source published to https://github.com/BetaHydri/Get-NtlmLogonEvents

## Scope
- Single public function: `Get-NtlmLogonEvents`
- 7 private helper functions
- PowerShell 5.1+ compatibility
- No DSC resources (DSC scaffolding removed)

## Out of Scope
- DSC resources, wiki generation, HQRM tests
- Integration tests (no lab environment in CI)
