BeforeAll {
    $script:moduleName = 'Get-NtlmLogonEvents'
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module -Name $script:moduleName -Force -ErrorAction Stop
}

Describe 'Get-NtlmLogonEvents Function Parameters' {

    BeforeAll {
        $command = Get-Command -Name 'Get-NtlmLogonEvents' -Module 'Get-NtlmLogonEvents'
    }

    Context 'Parameter definitions' {
        It 'Should have a NumEvents parameter of type Int32' {
            $command.Parameters['NumEvents'].ParameterType.Name | Should -Be 'Int32'
        }

        It 'Should have a Target parameter of type String' {
            $command.Parameters['Target'].ParameterType.Name | Should -Be 'String'
        }

        It 'Should have Target parameter with ValidateSet Localhost, DCs, Forest' {
            $validateSet = $command.Parameters['Target'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'Localhost'
            $validateSet.ValidValues | Should -Contain 'DCs'
            $validateSet.ValidValues | Should -Contain 'Forest'
            $validateSet.ValidValues | Should -HaveCount 3
        }

        It 'Should have a ComputerName parameter of type String[]' {
            $command.Parameters['ComputerName'].ParameterType.Name | Should -Be 'String[]'
        }

        It 'Should have ExcludeNullSessions as a switch' {
            $command.Parameters['ExcludeNullSessions'].SwitchParameter | Should -BeTrue
        }

        It 'Should have OnlyNTLMv1 as a switch' {
            $command.Parameters['OnlyNTLMv1'].SwitchParameter | Should -BeTrue
        }

        It 'Should have IncludeFailedLogons as a switch' {
            $command.Parameters['IncludeFailedLogons'].SwitchParameter | Should -BeTrue
        }

        It 'Should have CorrelatePrivileged as a switch' {
            $command.Parameters['CorrelatePrivileged'].SwitchParameter | Should -BeTrue
        }

        It 'Should have CheckAuditConfig as a switch' {
            $command.Parameters['CheckAuditConfig'].SwitchParameter | Should -BeTrue
        }

        It 'Should have IncludeNtlmOperationalLog as a switch' {
            $command.Parameters['IncludeNtlmOperationalLog'].SwitchParameter | Should -BeTrue
        }

        It 'Should have IncludeMessage as a switch' {
            $command.Parameters['IncludeMessage'].SwitchParameter | Should -BeTrue
        }

        It 'Should have Domain parameter of type String' {
            $command.Parameters['Domain'].ParameterType.Name | Should -Be 'String'
        }

        It 'Should have StartTime parameter of type DateTime' {
            $command.Parameters['StartTime'].ParameterType.Name | Should -Be 'DateTime'
        }

        It 'Should have EndTime parameter of type DateTime' {
            $command.Parameters['EndTime'].ParameterType.Name | Should -Be 'DateTime'
        }

        It 'Should have Credential parameter of type PSCredential' {
            $command.Parameters['Credential'].ParameterType.Name | Should -Be 'PSCredential'
        }

        It 'Should have Authentication parameter of type String' {
            $command.Parameters['Authentication'].ParameterType.Name | Should -Be 'String'
        }

        It 'Should have Authentication parameter with ValidateSet Default, Negotiate, Kerberos, NegotiateWithImplicitCredential' {
            $validateSet = $command.Parameters['Authentication'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'Default'
            $validateSet.ValidValues | Should -Contain 'Negotiate'
            $validateSet.ValidValues | Should -Contain 'Kerberos'
            $validateSet.ValidValues | Should -Contain 'NegotiateWithImplicitCredential'
            $validateSet.ValidValues | Should -HaveCount 4
        }

        It 'Should support CmdletBinding (Verbose, etc.)' {
            $command.CmdletBinding | Should -BeTrue
        }
    }

    Context 'Parameter validation' {
        It 'Should reject NumEvents of 0' {
            { Get-NtlmLogonEvents -NumEvents 0 } | Should -Throw
        }

        It 'Should reject negative NumEvents' {
            { Get-NtlmLogonEvents -NumEvents -5 } | Should -Throw
        }

        It 'Should reject invalid Target values' {
            { Get-NtlmLogonEvents -Target 'server.contoso.com' } | Should -Throw
        }

        It 'Should reject invalid Authentication values' {
            { Get-NtlmLogonEvents -Authentication 'Basic' } | Should -Throw
        }
    }

    Context 'Parameter sets' {
        It 'Should have Default as the default parameter set' {
            $cmdletBinding = $command.ScriptBlock.Attributes |
            Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
            $cmdletBinding.DefaultParameterSetName | Should -Be 'Default'
        }

        It 'Should have ComputerName mandatory in the ComputerName parameter set' {
            $paramAttrs = $command.Parameters['ComputerName'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.ParameterSetName -eq 'ComputerName' }
            $paramAttrs.Mandatory | Should -BeTrue
        }

        It 'Should have ComputerName mandatory in the AuditConfigComputerName parameter set' {
            $paramAttrs = $command.Parameters['ComputerName'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.ParameterSetName -eq 'AuditConfigComputerName' }
            $paramAttrs.Mandatory | Should -BeTrue
        }

        It 'Should have CheckAuditConfig mandatory in the AuditConfig parameter set' {
            $paramAttrs = $command.Parameters['CheckAuditConfig'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.ParameterSetName -eq 'AuditConfig' }
            $paramAttrs.Mandatory | Should -BeTrue
        }

        It 'Should have CheckAuditConfig mandatory in the AuditConfigComputerName parameter set' {
            $paramAttrs = $command.Parameters['CheckAuditConfig'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.ParameterSetName -eq 'AuditConfigComputerName' }
            $paramAttrs.Mandatory | Should -BeTrue
        }

        It 'Should NOT have event-only parameters in AuditConfig sets' {
            $eventOnlyParams = @('NumEvents', 'ExcludeNullSessions', 'OnlyNTLMv1',
                'IncludeFailedLogons', 'CorrelatePrivileged',
                'IncludeNtlmOperationalLog', 'IncludeMessage',
                'StartTime', 'EndTime')
            foreach ($paramName in $eventOnlyParams) {
                $paramSets = $command.Parameters[$paramName].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.ParameterSetName }
                $paramSets | Should -Not -Contain 'AuditConfig' -Because "$paramName should not be in AuditConfig set"
                $paramSets | Should -Not -Contain 'AuditConfigComputerName' -Because "$paramName should not be in AuditConfigComputerName set"
            }
        }

        It 'Should have Domain only in Default and AuditConfig parameter sets' {
            $paramSets = $command.Parameters['Domain'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            ForEach-Object { $_.ParameterSetName }
            $paramSets | Should -Contain 'Default'
            $paramSets | Should -Contain 'AuditConfig'
            $paramSets | Should -Not -Contain 'ComputerName'
            $paramSets | Should -Not -Contain 'AuditConfigComputerName'
        }
    }
}

Describe 'Get-NtlmLogonEvents Function Execution (mocked)' {

    BeforeAll {
        Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue

        Mock Get-WinEvent {
            throw [System.Exception]::new('No events were found that match the specified selection criteria.')
        } -ModuleName 'Get-NtlmLogonEvents'
        Mock Invoke-Command { } -ModuleName 'Get-NtlmLogonEvents'
    }

    Context 'Local host - no events found' {
        BeforeEach {
            Mock Get-WinEvent {
                throw [System.Exception]::new('No events were found that match the specified selection criteria.')
            } -ModuleName 'Get-NtlmLogonEvents'
        }

        It 'Should emit a warning when no events are found' {
            $result = Get-NtlmLogonEvents 3>&1
            $warnings = $result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }
            $warnings | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Local host - events found' {
        BeforeEach {
            Mock Get-WinEvent {
                $mockProps = @(
                    [PSCustomObject]@{ Value = 'S-1-0-0' }
                    [PSCustomObject]@{ Value = '-' }
                    [PSCustomObject]@{ Value = '-' }
                    [PSCustomObject]@{ Value = '0x0' }
                    [PSCustomObject]@{ Value = 'S-1-5-21-123' }
                    [PSCustomObject]@{ Value = 'testuser' }
                    [PSCustomObject]@{ Value = 'TESTDOMAIN' }
                    [PSCustomObject]@{ Value = '0xABC' }
                    [PSCustomObject]@{ Value = 3 }
                    [PSCustomObject]@{ Value = 'NtLmSsp' }
                    [PSCustomObject]@{ Value = 'NTLM' }
                    [PSCustomObject]@{ Value = 'TESTPC' }
                    [PSCustomObject]@{ Value = '{00000000-0000-0000-0000-000000000000}' }
                    [PSCustomObject]@{ Value = '-' }
                    [PSCustomObject]@{ Value = 'NTLM V2' }
                    [PSCustomObject]@{ Value = 128 }
                    [PSCustomObject]@{ Value = '0x0' }
                    [PSCustomObject]@{ Value = '-' }
                    [PSCustomObject]@{ Value = '10.0.0.1' }
                    [PSCustomObject]@{ Value = 50000 }
                    [PSCustomObject]@{ Value = '%%1833' }
                )
                $evt = [PSCustomObject]@{
                    Id          = 4624
                    TimeCreated = [datetime]'2026-02-25 10:00:00'
                    Properties  = $mockProps
                    Message     = 'An account was successfully logged on.'
                }
                $evt.PSObject.TypeNames.Insert(0, 'System.Diagnostics.Eventing.Reader.EventLogRecord')
                return $evt
            } -ModuleName 'Get-NtlmLogonEvents'
        }

        It 'Should return objects when events exist' {
            $result = Get-NtlmLogonEvents -NumEvents 1
            $result | Should -Not -BeNullOrEmpty
            $result.UserName | Should -Be 'testuser'
            $result.LmPackageName | Should -Be 'NTLM V2'
            $result.ImpersonationLevel | Should -Be 'Impersonation'
        }
    }

    Context 'DCs target without ActiveDirectory module' {
        BeforeEach {
            Mock Import-Module { throw 'Module not found' } -ParameterFilter {
                $Name -eq 'ActiveDirectory'
            } -ModuleName 'Get-NtlmLogonEvents'
        }

        It 'Should emit an error if ActiveDirectory module is not available' {
            $result = Get-NtlmLogonEvents -Target DCs 2>&1
            $errors = $result | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
            $errors | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Forest target without ActiveDirectory module' {
        BeforeEach {
            Mock Import-Module { throw 'Module not found' } -ParameterFilter {
                $Name -eq 'ActiveDirectory'
            } -ModuleName 'Get-NtlmLogonEvents'
        }

        It 'Should emit an error if ActiveDirectory module is not available for Forest target' {
            $result = Get-NtlmLogonEvents -Target Forest 2>&1
            $errors = $result | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
            $errors | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Module quality' {

    BeforeAll {
        $moduleInfo = Get-Module -Name 'Get-NtlmLogonEvents'
        $sourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\..\source\Public\Get-NtlmLogonEvents.ps1'
        if (Test-Path $sourcePath) {
            $scriptContent = Get-Content -Path $sourcePath -Raw
        }
    }

    It 'Should export the Get-NtlmLogonEvents function' {
        $moduleInfo.ExportedFunctions.Keys | Should -Contain 'Get-NtlmLogonEvents'
    }

    It 'Should have CmdletBinding attribute' {
        $scriptContent | Should -Match '\[CmdletBinding\('
    }

    It 'Should have comment-based help with SYNOPSIS' {
        $scriptContent | Should -Match '\.SYNOPSIS'
    }

    It 'Should have comment-based help with DESCRIPTION' {
        $scriptContent | Should -Match '\.DESCRIPTION'
    }

    It 'Should have comment-based help with EXAMPLE' {
        $scriptContent | Should -Match '\.EXAMPLE'
    }

    It 'Should have comment-based help with PARAMETER entries' {
        $scriptContent | Should -Match '\.PARAMETER NumEvents'
        $scriptContent | Should -Match '\.PARAMETER Target'
        $scriptContent | Should -Match '\.PARAMETER ExcludeNullSessions'
        $scriptContent | Should -Match '\.PARAMETER OnlyNTLMv1'
        $scriptContent | Should -Match '\.PARAMETER IncludeFailedLogons'
        $scriptContent | Should -Match '\.PARAMETER CorrelatePrivileged'
        $scriptContent | Should -Match '\.PARAMETER Domain'
        $scriptContent | Should -Match '\.PARAMETER StartTime'
        $scriptContent | Should -Match '\.PARAMETER EndTime'
        $scriptContent | Should -Match '\.PARAMETER Credential'
        $scriptContent | Should -Match '\.PARAMETER Authentication'
        $scriptContent | Should -Match '\.PARAMETER CheckAuditConfig'
        $scriptContent | Should -Match '\.PARAMETER IncludeNtlmOperationalLog'
        $scriptContent | Should -Match '\.PARAMETER IncludeMessage'
        $scriptContent | Should -Match '\.PARAMETER ComputerName'
    }

    It 'Should NOT contain Write-Host' {
        $scriptContent | Should -Not -Match 'Write-Host'
    }

    It 'Should NOT contain $error.Clear()' {
        $scriptContent | Should -Not -Match '\$error\.Clear\(\)'
    }
}
