# Product Context

## Why This Exists
Organizations hardening Active Directory need visibility into NTLM authentication usage before disabling NTLM.
This module provides the tooling to audit, filter, and correlate NTLM events across single hosts, domain controllers, or entire forests.

## Problems Solved
1. **NTLM audit gap**: Windows logs NTLM events but they are hard to query and correlate manually
2. **NTLMv1 identification**: Quickly finds insecure NTLMv1 usage that must be eliminated
3. **Privileged NTLM detection**: Correlates NTLM logons with special privilege events (4672) to find admin accounts using NTLM (high-value attack targets)
4. **Audit readiness**: Validates GPO audit configuration before NTLM restriction rollout
5. **Process-level detail**: NTLM Operational log (8001-8006) reveals which process initiated NTLM auth

## Target Users
- AD administrators hardening their environments
- Security teams auditing NTLM usage
- Consultants assessing AD forest security posture

## UX Goals
- Single command with intuitive parameter sets
- Pipeline-friendly structured output (PSCustomObjects with type names)
- Works locally without admin (for testing), or remotely via WinRM
- Rich help with many examples
