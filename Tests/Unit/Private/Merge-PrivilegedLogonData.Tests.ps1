BeforeAll {
    $script:moduleName = 'Get-NtlmLogonEvents'
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module -Name $script:moduleName -Force -ErrorAction Stop
}

InModuleScope 'Get-NtlmLogonEvents' {

Describe 'Merge-PrivilegedLogonData' {

    BeforeAll {
        # Helper: create a mock NTLM logon event object (as output by Convert-EventToObject)
        function New-MockNtlmResult {
            param(
                [int]$EventId = 4624,
                [string]$UserName = 'testuser',
                [string]$TargetLogonId = '0xABC',
                [datetime]$Time = (Get-Date)
            )

            [PSCustomObject]@{
                PSTypeName                = 'NtlmLogonEvent'
                EventId                   = $EventId
                Time                      = $Time
                UserName                  = $UserName
                TargetDomainName          = 'CONTOSO'
                LogonType                 = 3
                LogonProcessName          = 'NtLmSsp'
                AuthenticationPackageName = 'NTLM'
                WorkstationName           = 'WKS01'
                LmPackageName             = 'NTLM V2'
                IPAddress                 = '10.0.0.1'
                TCPPort                   = 49832
                ImpersonationLevel        = 'Impersonation'
                ProcessName               = '-'
                Status                    = $null
                FailureReason             = $null
                SubStatus                 = $null
                TargetLogonId             = $TargetLogonId
                ComputerName              = 'SRV01'
            }
        }
    }

    Context 'Privileged logon correlation' {
        It 'Should add IsPrivileged=true when 4672 matches TargetLogonId' {
            $event = New-MockNtlmResult -TargetLogonId '0xABC'

            Mock Get-PrivilegedLogonLookup { return @{ '0xABC' = 'SeDebugPrivilege' } }

            Merge-PrivilegedLogonData -Events @($event)

            $event.IsPrivileged | Should -BeTrue
            $event.PrivilegeList | Should -Be 'SeDebugPrivilege'
        }

        It 'Should add IsPrivileged=false when no 4672 match exists' {
            $event = New-MockNtlmResult -TargetLogonId '0xABC'

            Mock Get-PrivilegedLogonLookup { return @{} }

            Merge-PrivilegedLogonData -Events @($event)

            $event.IsPrivileged | Should -BeFalse
            $event.PrivilegeList | Should -BeNullOrEmpty
        }

        It 'Should set IsPrivileged=false for 4625 events regardless of lookup' {
            $event = New-MockNtlmResult -EventId 4625 -TargetLogonId $null

            Mock Get-PrivilegedLogonLookup { return @{ '0xABC' = 'SeDebugPrivilege' } }

            # Need at least one 4624 event to trigger the lookup
            $event4624 = New-MockNtlmResult -TargetLogonId '0xABC'
            Merge-PrivilegedLogonData -Events @($event4624, $event)

            $event.IsPrivileged | Should -BeFalse
            $event.PrivilegeList | Should -BeNullOrEmpty
        }

        It 'Should handle mixed privileged and non-privileged events' {
            $eventPriv = New-MockNtlmResult -UserName 'admin' -TargetLogonId '0x111'
            $eventNorm = New-MockNtlmResult -UserName 'user1' -TargetLogonId '0x222'

            Mock Get-PrivilegedLogonLookup { return @{ '0x111' = 'SeDebugPrivilege' } }

            Merge-PrivilegedLogonData -Events @($eventPriv, $eventNorm)

            $eventPriv.IsPrivileged | Should -BeTrue
            $eventPriv.PrivilegeList | Should -Be 'SeDebugPrivilege'
            $eventNorm.IsPrivileged | Should -BeFalse
            $eventNorm.PrivilegeList | Should -BeNullOrEmpty
        }

        It 'Should handle events array with only 4625 events (no 4624 to correlate)' {
            $event = New-MockNtlmResult -EventId 4625 -TargetLogonId $null

            # Should not call Get-PrivilegedLogonLookup when there are no 4624 events
            Mock Get-PrivilegedLogonLookup { return @{} }

            Merge-PrivilegedLogonData -Events @($event)

            $event.IsPrivileged | Should -BeFalse
            $event.PrivilegeList | Should -BeNullOrEmpty
            Should -Not -Invoke Get-PrivilegedLogonLookup
        }

        It 'Should use the time range of events for the 4672 query' {
            $event1 = New-MockNtlmResult -TargetLogonId '0x111' -Time ([datetime]'2026-02-25 10:00:00')
            $event2 = New-MockNtlmResult -TargetLogonId '0x222' -Time ([datetime]'2026-02-25 11:00:00')

            Mock Get-PrivilegedLogonLookup {
                # Verify time parameters are approximately correct
                $StartTime | Should -BeLessOrEqual ([datetime]'2026-02-25 10:00:00')
                $EndTime | Should -BeGreaterOrEqual ([datetime]'2026-02-25 11:00:00')
                return @{}
            }

            Merge-PrivilegedLogonData -Events @($event1, $event2)

            Should -Invoke Get-PrivilegedLogonLookup -Times 1
        }
    }
}


} # InModuleScope
