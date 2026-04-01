# Tech Context

## Tech Stack
- PowerShell 5.1+ (Windows-only due to Windows Event Log dependency)
- Sampler build framework (ModuleBuilder, InvokeBuild, Pester 5, GitVersion)
- Azure Pipelines CI/CD at https://dev.azure.com/fam-tiedemann/
- GitHub repo: https://github.com/BetaHydri/Get-NtlmLogonEvents

## Dependencies (Build-time only)
- InvokeBuild, PSScriptAnalyzer, Pester, ModuleBuilder, ChangelogManagement
- Sampler, Sampler.GitHubTasks

## Runtime Dependencies
- None (no RequiredModules in manifest)
- Optional: ActiveDirectory module (for -Target DCs/Forest)
- WinRM for remote queries

## Dev Setup
```powershell
# First build (resolves dependencies)
./build.ps1 -ResolveDependency -Tasks build

# Subsequent builds (skip dependency resolution)
./build.ps1 -Tasks build

# Run tests
./build.ps1 -Tasks test

# Full pipeline (build + test)
./build.ps1 -Tasks .
```

## Constraints
- OneDrive sync can lock DLLs in output/RequiredModules/ — pause OneDrive before builds, or close VS Code
- Build must run in a detached pwsh process (Start-Process) to avoid freezing VS Code
- Tests must use InModuleScope for private function access
- Windows Event Log APIs are Windows-only

## Key Config Files
- `build.yaml` — Sampler/ModuleBuilder/Pester configuration
- `RequiredModules.psd1` — Build-time dependencies
- `GitVersion.yml` — Semantic versioning rules
- `azure-pipelines.yml` — CI/CD pipeline (Build → Test → Code Coverage → Deploy)
- `source/Get-NtlmLogonEvents.psd1` — Module manifest
