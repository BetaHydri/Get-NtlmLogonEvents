BeforeAll {
    $script:moduleName = 'Get-NtlmLogonEvents'

    # Remove all versions of the module from the session
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue

    # Re-import the built module
    Import-Module -Name $script:moduleName -Force -ErrorAction Stop
}

InModuleScope 'Get-NtlmLogonEvents' {

Describe 'Build-XPathFilter' {

    Context 'Default behavior (all NTLM versions)' {
        It 'Should return XPath that matches all NTLM packages (not equal to dash)' {
            $filter = Build-XPathFilter
            $filter | Should -Match "LmPackageName.*!=.*'-'"
            $filter | Should -Not -Match "NTLM V1"
        }

        It 'Should include EventID=4624' {
            $filter = Build-XPathFilter
            $filter | Should -Match 'EventID=4624'
        }

        It 'Should NOT include ANONYMOUS LOGON filter by default' {
            $filter = Build-XPathFilter
            $filter | Should -Not -Match 'ANONYMOUS LOGON'
        }
    }

    Context '-OnlyNTLMv1 switch' {
        It 'Should filter for NTLM V1 specifically' {
            $filter = Build-XPathFilter -OnlyNTLMv1
            $filter | Should -Match "NTLM V1"
            $filter | Should -Not -Match "!=.*'-'"
        }
    }

    Context '-ExcludeNullSessions switch' {
        It 'Should add ANONYMOUS LOGON exclusion filter' {
            $filter = Build-XPathFilter -ExcludeNullSessions
            $filter | Should -Match "TargetUserName.*!='ANONYMOUS LOGON'"
        }

        It 'Should combine with OnlyNTLMv1' {
            $filter = Build-XPathFilter -OnlyNTLMv1 -ExcludeNullSessions
            $filter | Should -Match "NTLM V1"
            $filter | Should -Match "ANONYMOUS LOGON"
        }
    }

    Context '-StartTime parameter' {
        It 'Should add TimeCreated >= filter' {
            $startTime = [datetime]'2026-01-01 00:00:00'
            $filter = Build-XPathFilter -StartTime $startTime
            $filter | Should -Match "TimeCreated\[@SystemTime>="
        }

        It 'Should format time as UTC ISO 8601' {
            $startTime = [datetime]::new(2026, 6, 15, 12, 0, 0, [System.DateTimeKind]::Local)
            $filter = Build-XPathFilter -StartTime $startTime
            $filter | Should -Match "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"
        }
    }

    Context '-EndTime parameter' {
        It 'Should add TimeCreated <= filter' {
            $endTime = [datetime]'2026-02-25 23:59:59'
            $filter = Build-XPathFilter -EndTime $endTime
            $filter | Should -Match "TimeCreated\[@SystemTime<="
        }
    }

    Context 'StartTime and EndTime combined' {
        It 'Should include both time filters in the System part' {
            $start = [datetime]'2026-01-01'
            $end = [datetime]'2026-02-01'
            $filter = Build-XPathFilter -StartTime $start -EndTime $end
            $filter | Should -Match "SystemTime>="
            $filter | Should -Match "SystemTime<="
        }
    }

    Context 'All parameters combined' {
        It 'Should produce a valid compound filter' {
            $filter = Build-XPathFilter -OnlyNTLMv1 -ExcludeNullSessions `
                -StartTime ([datetime]'2026-01-01') -EndTime ([datetime]'2026-02-01')
            $filter | Should -Match 'EventID=4624'
            $filter | Should -Match 'NTLM V1'
            $filter | Should -Match 'ANONYMOUS LOGON'
            $filter | Should -Match 'SystemTime>='
            $filter | Should -Match 'SystemTime<='
        }
    }

    Context '-IncludeFailedLogons switch' {
        It 'Should include both EventID 4624 and 4625' {
            $filter = Build-XPathFilter -IncludeFailedLogons
            $filter | Should -Match 'EventID=4624'
            $filter | Should -Match 'EventID=4625'
        }

        It 'Should use "or" between event IDs' {
            $filter = Build-XPathFilter -IncludeFailedLogons
            $filter | Should -Match 'EventID=4624 or EventID=4625'
        }

        It 'Should NOT include EventID 4625 by default' {
            $filter = Build-XPathFilter
            $filter | Should -Not -Match '4625'
        }

        It 'Should combine with OnlyNTLMv1 and ExcludeNullSessions' {
            $filter = Build-XPathFilter -IncludeFailedLogons -OnlyNTLMv1 -ExcludeNullSessions
            $filter | Should -Match 'EventID=4624 or EventID=4625'
            $filter | Should -Match 'NTLM V1'
            $filter | Should -Match 'ANONYMOUS LOGON'
        }
    }

    Context 'XPath structure validation' {
        It 'Should wrap System filters in Event[System[...]]' {
            $filter = Build-XPathFilter
            $filter | Should -Match 'Event\[System\['
        }

        It 'Should wrap EventData filters in Event[EventData[...]]' {
            $filter = Build-XPathFilter
            $filter | Should -Match 'Event\[EventData\['
        }

        It 'Should join parts with " and "' {
            $filter = Build-XPathFilter
            $filter | Should -Match ' and '
        }
    }
}

} # InModuleScope
