BeforeAll {
    $script:moduleName = 'Get-NtlmLogonEvents'
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module -Name $script:moduleName -Force -ErrorAction Stop
}

InModuleScope 'Get-NtlmLogonEvents' {

Describe 'Get-PrivilegedLogonLookup' {

    Context 'Basic behavior' {
        It 'Should return an empty hashtable when no 4672 events are found' {
            Mock Get-WinEvent {
                throw [System.Exception]::new('No events were found that match the specified selection criteria.')
            }

            $result = Get-PrivilegedLogonLookup -StartTime ([datetime]'2026-01-01') -EndTime ([datetime]'2026-02-01')
            $result | Should -BeOfType [hashtable]
            $result.Count | Should -Be 0
        }

        It 'Should build a lookup hashtable from 4672 events' {
            Mock Get-WinEvent {
                $evt1 = [PSCustomObject]@{
                    Id         = 4672
                    Properties = @(
                        [PSCustomObject]@{ Value = 'S-1-5-21-123' }     # [0] SubjectUserSid
                        [PSCustomObject]@{ Value = 'admin' }            # [1] SubjectUserName
                        [PSCustomObject]@{ Value = 'CONTOSO' }          # [2] SubjectDomainName
                        [PSCustomObject]@{ Value = '0xABC' }            # [3] SubjectLogonId
                        [PSCustomObject]@{ Value = 'SeDebugPrivilege' } # [4] PrivilegeList
                    )
                }
                $evt2 = [PSCustomObject]@{
                    Id         = 4672
                    Properties = @(
                        [PSCustomObject]@{ Value = 'S-1-5-21-456' }
                        [PSCustomObject]@{ Value = 'svcaccount' }
                        [PSCustomObject]@{ Value = 'CONTOSO' }
                        [PSCustomObject]@{ Value = '0xDEF' }
                        [PSCustomObject]@{ Value = "SeBackupPrivilege`n`t`t`tSeRestorePrivilege" }
                    )
                }
                return @($evt1, $evt2)
            }

            $result = Get-PrivilegedLogonLookup -StartTime ([datetime]'2026-01-01') -EndTime ([datetime]'2026-02-01')
            $result.Count | Should -Be 2
            $result['0xABC'] | Should -Be 'SeDebugPrivilege'
            $result.ContainsKey('0xDEF') | Should -BeTrue
        }

        It 'Should use the first occurrence when duplicate LogonIds exist' {
            Mock Get-WinEvent {
                $evt1 = [PSCustomObject]@{
                    Id         = 4672
                    Properties = @(
                        [PSCustomObject]@{ Value = 'S-1-5-21-123' }
                        [PSCustomObject]@{ Value = 'admin' }
                        [PSCustomObject]@{ Value = 'CONTOSO' }
                        [PSCustomObject]@{ Value = '0xABC' }
                        [PSCustomObject]@{ Value = 'SeDebugPrivilege' }
                    )
                }
                $evt2 = [PSCustomObject]@{
                    Id         = 4672
                    Properties = @(
                        [PSCustomObject]@{ Value = 'S-1-5-21-123' }
                        [PSCustomObject]@{ Value = 'admin' }
                        [PSCustomObject]@{ Value = 'CONTOSO' }
                        [PSCustomObject]@{ Value = '0xABC' }
                        [PSCustomObject]@{ Value = 'SeBackupPrivilege' }
                    )
                }
                return @($evt1, $evt2)
            }

            $result = Get-PrivilegedLogonLookup -StartTime ([datetime]'2026-01-01') -EndTime ([datetime]'2026-02-01')
            $result.Count | Should -Be 1
            $result['0xABC'] | Should -Be 'SeDebugPrivilege'
        }

        It 'Should write a warning on non-"no events found" errors' {
            Mock Get-WinEvent {
                throw [System.Exception]::new('Access denied')
            }

            $result = Get-PrivilegedLogonLookup -StartTime ([datetime]'2026-01-01') -EndTime ([datetime]'2026-02-01') 3>&1
            $warnings = $result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }
            $warnings | Should -Not -BeNullOrEmpty
        }
    }
}


} # InModuleScope
