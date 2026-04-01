BeforeAll {
    $script:moduleName = 'Get-NtlmLogonEvents'
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module -Name $script:moduleName -Force -ErrorAction Stop
}

InModuleScope 'Get-NtlmLogonEvents' {

Describe 'Build-NtlmOperationalXPathFilter' {

    Context 'Default behavior (all NTLM operational events)' {
        It 'Should include all audit event IDs (8001-8006)' {
            $filter = Build-NtlmOperationalXPathFilter
            $filter | Should -Match 'EventID=8001'
            $filter | Should -Match 'EventID=8002'
            $filter | Should -Match 'EventID=8003'
            $filter | Should -Match 'EventID=8004'
            $filter | Should -Match 'EventID=8005'
            $filter | Should -Match 'EventID=8006'
        }

        It 'Should include all block event IDs (4001-4006)' {
            $filter = Build-NtlmOperationalXPathFilter
            $filter | Should -Match 'EventID=4001'
            $filter | Should -Match 'EventID=4002'
            $filter | Should -Match 'EventID=4003'
            $filter | Should -Match 'EventID=4004'
            $filter | Should -Match 'EventID=4005'
            $filter | Should -Match 'EventID=4006'
        }

        It 'Should NOT include time filters by default' {
            $filter = Build-NtlmOperationalXPathFilter
            $filter | Should -Not -Match 'TimeCreated'
        }
    }

    Context '-StartTime parameter' {
        It 'Should add TimeCreated >= filter' {
            $filter = Build-NtlmOperationalXPathFilter -StartTime ([datetime]'2026-01-01')
            $filter | Should -Match "TimeCreated\[@SystemTime>="
        }
    }

    Context '-EndTime parameter' {
        It 'Should add TimeCreated <= filter' {
            $filter = Build-NtlmOperationalXPathFilter -EndTime ([datetime]'2026-02-28')
            $filter | Should -Match "TimeCreated\[@SystemTime<="
        }
    }

    Context 'StartTime and EndTime combined' {
        It 'Should include both time filters' {
            $filter = Build-NtlmOperationalXPathFilter -StartTime ([datetime]'2026-01-01') -EndTime ([datetime]'2026-02-01')
            $filter | Should -Match 'SystemTime>='
            $filter | Should -Match 'SystemTime<='
        }
    }

    Context 'XPath structure validation' {
        It 'Should wrap in *[System[...]]' {
            $filter = Build-NtlmOperationalXPathFilter
            $filter | Should -Match '\*\[System\['
        }

        It 'Should use "or" between event IDs' {
            $filter = Build-NtlmOperationalXPathFilter
            $filter | Should -Match ' or '
        }
    }
}


} # InModuleScope
