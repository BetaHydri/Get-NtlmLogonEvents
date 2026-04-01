BeforeAll {
    $script:moduleName = 'Get-NtlmLogonEvents'
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module -Name $script:moduleName -Force -ErrorAction Stop
}

InModuleScope 'Get-NtlmLogonEvents' {

Describe 'Test-NtlmAuditConfiguration' {

    Context 'Registry reading' {
        It 'Should return NtlmAuditConfig objects' {
            # Mock Get-ItemProperty to simulate registry values
            Mock Get-ItemProperty { throw 'Not found' }
            $results = Test-NtlmAuditConfiguration
            $results | Should -Not -BeNullOrEmpty
            $results[0].PSObject.TypeNames | Should -Contain 'NtlmAuditConfig'
        }

        It 'Should return at least 5 policy entries' {
            Mock Get-ItemProperty { throw 'Not found' }
            $results = @(Test-NtlmAuditConfiguration)
            $results.Count | Should -BeGreaterOrEqual 5
        }

        It 'Should show Not configured when registry values are missing' {
            Mock Get-ItemProperty { throw 'Not found' }
            $results = Test-NtlmAuditConfiguration
            $results | Where-Object Setting -EQ 'Not configured' | Should -Not -BeNullOrEmpty
        }

        It 'Should include PolicyName, Setting, Recommended, and IsRecommended properties' {
            Mock Get-ItemProperty { throw 'Not found' }
            $results = Test-NtlmAuditConfiguration
            $first = $results[0]
            $first.PSObject.Properties.Name | Should -Contain 'PolicyName'
            $first.PSObject.Properties.Name | Should -Contain 'Setting'
            $first.PSObject.Properties.Name | Should -Contain 'Recommended'
            $first.PSObject.Properties.Name | Should -Contain 'IsRecommended'
            $first.PSObject.Properties.Name | Should -Contain 'ComputerName'
        }

        It 'Should set ComputerName to local host name' {
            Mock Get-ItemProperty { throw 'Not found' }
            $results = Test-NtlmAuditConfiguration
            $results[0].ComputerName | Should -Be $env:COMPUTERNAME
        }
    }
}


} # InModuleScope
