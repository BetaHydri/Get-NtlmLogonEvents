BeforeAll {
    $script:moduleName = 'Get-NtlmLogonEvents'
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module -Name $script:moduleName -Force -ErrorAction Stop
}

InModuleScope 'Get-NtlmLogonEvents' {

Describe 'Convert-EventToObject' {

    BeforeAll {
        # Create a mock EventLogRecord-like object
        function New-MockEvent {
            param(
                [string]$UserName = 'testuser',
                [string]$Domain = 'CONTOSO',
                [int]$LogonType = 3,
                [string]$Workstation = 'WKS01',
                [string]$LmPackage = 'NTLM V1',
                [string]$IpAddress = '192.168.1.100',
                [int]$IpPort = 49832,
                [string]$Impersonation = '%%1833',
                [string]$ProcessName = '-',
                [datetime]$TimeCreated = (Get-Date)
            )

            # Build a properties array matching 4624 field layout (indices 0-20)
            $props = @(
                [PSCustomObject]@{ Value = 'S-1-0-0' }          # [0] SubjectUserSid
                [PSCustomObject]@{ Value = '-' }                  # [1] SubjectUserName
                [PSCustomObject]@{ Value = '-' }                  # [2] SubjectDomainName
                [PSCustomObject]@{ Value = '0x0' }                # [3] SubjectLogonId
                [PSCustomObject]@{ Value = 'S-1-5-21-123' }      # [4] TargetUserSid
                [PSCustomObject]@{ Value = $UserName }            # [5] TargetUserName
                [PSCustomObject]@{ Value = $Domain }              # [6] TargetDomainName
                [PSCustomObject]@{ Value = '0x12345' }            # [7] TargetLogonId
                [PSCustomObject]@{ Value = $LogonType }           # [8] LogonType
                [PSCustomObject]@{ Value = 'NtLmSsp' }           # [9] LogonProcessName
                [PSCustomObject]@{ Value = 'NTLM' }              # [10] AuthenticationPackageName
                [PSCustomObject]@{ Value = $Workstation }         # [11] WorkstationName
                [PSCustomObject]@{ Value = '{00000000-0000-0000-0000-000000000000}' } # [12] LogonGuid
                [PSCustomObject]@{ Value = '-' }                  # [13] TransmittedServices
                [PSCustomObject]@{ Value = $LmPackage }           # [14] LmPackageName
                [PSCustomObject]@{ Value = 128 }                  # [15] KeyLength
                [PSCustomObject]@{ Value = '0x0' }                # [16] ProcessId
                [PSCustomObject]@{ Value = $ProcessName }         # [17] ProcessName
                [PSCustomObject]@{ Value = $IpAddress }           # [18] IpAddress
                [PSCustomObject]@{ Value = $IpPort }              # [19] IpPort
                [PSCustomObject]@{ Value = $Impersonation }       # [20] ImpersonationLevel
            )

            # Create a mock object that looks like EventLogRecord
            $mockEvent = [PSCustomObject]@{
                Id          = 4624
                TimeCreated = $TimeCreated
                Properties  = $props
                Message     = 'An account was successfully logged on.'
            }

            # Add the type name so it satisfies type checks when cast loosely
            $mockEvent.PSObject.TypeNames.Insert(0, 'System.Diagnostics.Eventing.Reader.EventLogRecord')

            return $mockEvent
        }
    }

    Context 'Basic field mapping' {
        It 'Should map UserName from Properties[5]' {
            $event = New-MockEvent -UserName 'jsmith'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.UserName | Should -Be 'jsmith'
        }

        It 'Should map TargetDomainName from Properties[6]' {
            $event = New-MockEvent -Domain 'FABRIKAM'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.TargetDomainName | Should -Be 'FABRIKAM'
        }

        It 'Should map LogonType from Properties[8]' {
            $event = New-MockEvent -LogonType 10
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '10 (RemoteInteractive)'
        }

        It 'Should map WorkstationName from Properties[11]' {
            $event = New-MockEvent -Workstation 'DESKTOP-ABC'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.WorkstationName | Should -Be 'DESKTOP-ABC'
        }

        It 'Should map LmPackageName from Properties[14]' {
            $event = New-MockEvent -LmPackage 'NTLM V2'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LmPackageName | Should -Be 'NTLM V2'
        }

        It 'Should map IPAddress from Properties[18]' {
            $event = New-MockEvent -IpAddress '10.0.0.5'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.IPAddress | Should -Be '10.0.0.5'
        }

        It 'Should map TCPPort from Properties[19]' {
            $event = New-MockEvent -IpPort 12345
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.TCPPort | Should -Be 12345
        }

        It 'Should map ProcessName from Properties[17]' {
            $event = New-MockEvent -ProcessName 'C:\Windows\System32\lsass.exe'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ProcessName | Should -Be 'C:\Windows\System32\lsass.exe'
        }

        It 'Should set ComputerName from the parameter' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'DC01'
            $result.ComputerName | Should -Be 'DC01'
        }

        It 'Should set Time from TimeCreated' {
            $timestamp = [datetime]'2026-02-25 14:30:00'
            $event = New-MockEvent -TimeCreated $timestamp
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.Time | Should -Be $timestamp
        }
    }

    Context 'Impersonation level translation' {
        It 'Should translate %%1831 to Anonymous' {
            $event = New-MockEvent -Impersonation '%%1831'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ImpersonationLevel | Should -Be 'Anonymous'
        }

        It 'Should translate %%1832 to Identify' {
            $event = New-MockEvent -Impersonation '%%1832'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ImpersonationLevel | Should -Be 'Identify'
        }

        It 'Should translate %%1833 to Impersonation' {
            $event = New-MockEvent -Impersonation '%%1833'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ImpersonationLevel | Should -Be 'Impersonation'
        }

        It 'Should translate %%1834 to Delegation' {
            $event = New-MockEvent -Impersonation '%%1834'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ImpersonationLevel | Should -Be 'Delegation'
        }

        It 'Should pass through unknown impersonation values unchanged' {
            $event = New-MockEvent -Impersonation '%%9999'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ImpersonationLevel | Should -Be '%%9999'
        }

        It 'Should handle empty impersonation value' {
            $event = New-MockEvent -Impersonation ''
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ImpersonationLevel | Should -Be ''
        }
    }

    Context 'LogonType enrichment' {
        It 'Should enrich LogonType 2 as "2 (Interactive)"' {
            $event = New-MockEvent -LogonType 2
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '2 (Interactive)'
        }

        It 'Should enrich LogonType 3 as "3 (Network)"' {
            $event = New-MockEvent -LogonType 3
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '3 (Network)'
        }

        It 'Should enrich LogonType 4 as "4 (Batch)"' {
            $event = New-MockEvent -LogonType 4
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '4 (Batch)'
        }

        It 'Should enrich LogonType 5 as "5 (Service)"' {
            $event = New-MockEvent -LogonType 5
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '5 (Service)'
        }

        It 'Should enrich LogonType 7 as "7 (Unlock)"' {
            $event = New-MockEvent -LogonType 7
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '7 (Unlock)'
        }

        It 'Should enrich LogonType 8 as "8 (NetworkCleartext)"' {
            $event = New-MockEvent -LogonType 8
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '8 (NetworkCleartext)'
        }

        It 'Should enrich LogonType 9 as "9 (NewCredentials)"' {
            $event = New-MockEvent -LogonType 9
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '9 (NewCredentials)'
        }

        It 'Should enrich LogonType 10 as "10 (RemoteInteractive)"' {
            $event = New-MockEvent -LogonType 10
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '10 (RemoteInteractive)'
        }

        It 'Should enrich LogonType 11 as "11 (CachedInteractive)"' {
            $event = New-MockEvent -LogonType 11
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '11 (CachedInteractive)'
        }

        It 'Should enrich LogonType 12 as "12 (CachedRemoteInteractive)"' {
            $event = New-MockEvent -LogonType 12
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '12 (CachedRemoteInteractive)'
        }

        It 'Should enrich LogonType 13 as "13 (CachedUnlock)"' {
            $event = New-MockEvent -LogonType 13
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '13 (CachedUnlock)'
        }

        It 'Should pass through unknown LogonType values unchanged' {
            $event = New-MockEvent -LogonType 99
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be 99
        }
    }

    Context 'Output object properties' {
        It 'Should have all expected properties' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'

            $expectedProps = @(
                'EventId', 'Time', 'UserName', 'TargetDomainName', 'LogonType',
                'LogonProcessName', 'AuthenticationPackageName', 'WorkstationName',
                'LmPackageName', 'IPAddress', 'TCPPort',
                'ImpersonationLevel', 'ProcessName', 'Status', 'FailureReason',
                'SubStatus', 'TargetLogonId', 'Message', 'ComputerName'
            )

            foreach ($prop in $expectedProps) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }

        It 'Should have PSTypeName NtlmLogonEvent' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.PSObject.TypeNames | Should -Contain 'NtlmLogonEvent'
        }

        It 'Should set EventId to 4624 for successful logon events' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.EventId | Should -Be 4624
        }

        It 'Should set Status, FailureReason, SubStatus to null for 4624 events' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.Status | Should -BeNullOrEmpty
            $result.FailureReason | Should -BeNullOrEmpty
            $result.SubStatus | Should -BeNullOrEmpty
        }

        It 'Should map TargetLogonId from Properties[7] for 4624' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.TargetLogonId | Should -Be '0x12345'
        }

        It 'Should map LogonProcessName from Properties[9] for 4624' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonProcessName | Should -Be 'NtLmSsp'
        }

        It 'Should map AuthenticationPackageName from Properties[10] for 4624' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.AuthenticationPackageName | Should -Be 'NTLM'
        }

        It 'Should include Message from the event' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.Message | Should -Be 'An account was successfully logged on.'
        }
    }

    Context 'Pipeline input' {
        It 'Should process multiple events via pipeline' {
            $events = @(
                (New-MockEvent -UserName 'user1')
                (New-MockEvent -UserName 'user2')
                (New-MockEvent -UserName 'user3')
            )

            $results = $events | Convert-EventToObject -ComputerName 'SRV01'
            $results | Should -HaveCount 3
            $results[0].UserName | Should -Be 'user1'
            $results[1].UserName | Should -Be 'user2'
            $results[2].UserName | Should -Be 'user3'
        }
    }

    Context 'Negotiate to NTLM fallback detection' {
        It 'Should show AuthenticationPackageName=Negotiate when Negotiate falls back to NTLM' {
            # Simulate a Negotiate→NTLM fallback event (Negotiate tried Kerberos, fell back)
            $props = @(
                [PSCustomObject]@{ Value = 'S-1-0-0' }          # [0] SubjectUserSid
                [PSCustomObject]@{ Value = '-' }                  # [1] SubjectUserName
                [PSCustomObject]@{ Value = '-' }                  # [2] SubjectDomainName
                [PSCustomObject]@{ Value = '0x0' }                # [3] SubjectLogonId
                [PSCustomObject]@{ Value = 'S-1-5-21-123' }      # [4] TargetUserSid
                [PSCustomObject]@{ Value = 'jsmith' }             # [5] TargetUserName
                [PSCustomObject]@{ Value = 'CONTOSO' }            # [6] TargetDomainName
                [PSCustomObject]@{ Value = '0x12345' }            # [7] TargetLogonId
                [PSCustomObject]@{ Value = 3 }                    # [8] LogonType
                [PSCustomObject]@{ Value = 'Negotiate' }          # [9] LogonProcessName
                [PSCustomObject]@{ Value = 'Negotiate' }          # [10] AuthenticationPackageName
                [PSCustomObject]@{ Value = 'WKS01' }             # [11] WorkstationName
                [PSCustomObject]@{ Value = '{00000000-0000-0000-0000-000000000000}' } # [12] LogonGuid
                [PSCustomObject]@{ Value = '-' }                  # [13] TransmittedServices
                [PSCustomObject]@{ Value = 'NTLM V2' }           # [14] LmPackageName
                [PSCustomObject]@{ Value = 128 }                  # [15] KeyLength
                [PSCustomObject]@{ Value = '0x0' }                # [16] ProcessId
                [PSCustomObject]@{ Value = '-' }                  # [17] ProcessName
                [PSCustomObject]@{ Value = '10.0.0.5' }           # [18] IpAddress
                [PSCustomObject]@{ Value = 49832 }                # [19] IpPort
                [PSCustomObject]@{ Value = '%%1833' }             # [20] ImpersonationLevel
            )
            $event = [PSCustomObject]@{ Id = 4624; TimeCreated = (Get-Date); Properties = $props; Message = 'An account was successfully logged on.' }
            $event.PSObject.TypeNames.Insert(0, 'System.Diagnostics.Eventing.Reader.EventLogRecord')

            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.AuthenticationPackageName | Should -Be 'Negotiate'
            $result.LogonProcessName | Should -Be 'Negotiate'
            $result.LmPackageName | Should -Be 'NTLM V2'
        }

        It 'Should show AuthenticationPackageName=NTLM for direct NTLM usage' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.AuthenticationPackageName | Should -Be 'NTLM'
            $result.LogonProcessName | Should -Be 'NtLmSsp'
        }
    }
}

Describe 'Convert-EventToObject (Event ID 4625 - Failed Logon)' {

    BeforeAll {
        # Create a mock failed logon event (4625) with different property layout
        function New-MockFailedEvent {
            param(
                [string]$UserName = 'testuser',
                [string]$Domain = 'CONTOSO',
                [string]$Status = '0xC000006D',
                [string]$FailureReason = '%%2313',
                [string]$SubStatus = '0xC0000064',
                [int]$LogonType = 3,
                [string]$Workstation = 'WKS01',
                [string]$LmPackage = 'NTLM V1',
                [string]$IpAddress = '192.168.1.100',
                [int]$IpPort = 49832,
                [string]$ProcessName = '-',
                [datetime]$TimeCreated = (Get-Date)
            )

            # Build a properties array matching 4625 field layout (indices 0-20)
            $props = @(
                [PSCustomObject]@{ Value = 'S-1-0-0' }          # [0] SubjectUserSid
                [PSCustomObject]@{ Value = '-' }                  # [1] SubjectUserName
                [PSCustomObject]@{ Value = '-' }                  # [2] SubjectDomainName
                [PSCustomObject]@{ Value = '0x0' }                # [3] SubjectLogonId
                [PSCustomObject]@{ Value = 'S-1-0-0' }           # [4] TargetUserSid
                [PSCustomObject]@{ Value = $UserName }            # [5] TargetUserName
                [PSCustomObject]@{ Value = $Domain }              # [6] TargetDomainName
                [PSCustomObject]@{ Value = $Status }              # [7] Status
                [PSCustomObject]@{ Value = $FailureReason }       # [8] FailureReason
                [PSCustomObject]@{ Value = $SubStatus }           # [9] SubStatus
                [PSCustomObject]@{ Value = $LogonType }           # [10] LogonType
                [PSCustomObject]@{ Value = 'NtLmSsp' }           # [11] LogonProcessName
                [PSCustomObject]@{ Value = 'NTLM' }              # [12] AuthenticationPackageName
                [PSCustomObject]@{ Value = $Workstation }         # [13] WorkstationName
                [PSCustomObject]@{ Value = '-' }                  # [14] TransmittedServices
                [PSCustomObject]@{ Value = $LmPackage }           # [15] LmPackageName
                [PSCustomObject]@{ Value = 0 }                    # [16] KeyLength
                [PSCustomObject]@{ Value = '0x0' }                # [17] ProcessId
                [PSCustomObject]@{ Value = $ProcessName }         # [18] ProcessName
                [PSCustomObject]@{ Value = $IpAddress }           # [19] IpAddress
                [PSCustomObject]@{ Value = $IpPort }              # [20] IpPort
            )

            $mockEvent = [PSCustomObject]@{
                Id          = 4625
                TimeCreated = $TimeCreated
                Properties  = $props
                Message     = 'An account failed to log on.'
            }
            $mockEvent.PSObject.TypeNames.Insert(0, 'System.Diagnostics.Eventing.Reader.EventLogRecord')
            return $mockEvent
        }
    }

    Context 'Failed logon field mapping' {
        It 'Should set EventId to 4625' {
            $event = New-MockFailedEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.EventId | Should -Be 4625
        }

        It 'Should map UserName from Properties[5]' {
            $event = New-MockFailedEvent -UserName 'baduser'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.UserName | Should -Be 'baduser'
        }

        It 'Should map TargetDomainName from Properties[6]' {
            $event = New-MockFailedEvent -Domain 'FABRIKAM'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.TargetDomainName | Should -Be 'FABRIKAM'
        }

        It 'Should map LogonType from Properties[10] (not [8])' {
            $event = New-MockFailedEvent -LogonType 10
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonType | Should -Be '10 (RemoteInteractive)'
        }

        It 'Should map WorkstationName from Properties[13] (not [11])' {
            $event = New-MockFailedEvent -Workstation 'ATTACKER-PC'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.WorkstationName | Should -Be 'ATTACKER-PC'
        }

        It 'Should map LmPackageName from Properties[15] (not [14])' {
            $event = New-MockFailedEvent -LmPackage 'NTLM V2'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LmPackageName | Should -Be 'NTLM V2'
        }

        It 'Should map IPAddress from Properties[19] (not [18])' {
            $event = New-MockFailedEvent -IpAddress '10.0.0.99'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.IPAddress | Should -Be '10.0.0.99'
        }

        It 'Should map TCPPort from Properties[20] (not [19])' {
            $event = New-MockFailedEvent -IpPort 55555
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.TCPPort | Should -Be 55555
        }

        It 'Should map ProcessName from Properties[18] (not [17])' {
            $event = New-MockFailedEvent -ProcessName 'C:\Windows\System32\lsass.exe'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ProcessName | Should -Be 'C:\Windows\System32\lsass.exe'
        }

        It 'Should map and enrich Status from Properties[7]' {
            $event = New-MockFailedEvent -Status '0xC000006D'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.Status | Should -Be '0xC000006D (Logon failure: unknown user name or bad password)'
        }

        It 'Should map and enrich FailureReason from Properties[8]' {
            $event = New-MockFailedEvent -FailureReason '%%2313'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.FailureReason | Should -Be 'Unknown user name or bad password'
        }

        It 'Should map and enrich SubStatus from Properties[9]' {
            $event = New-MockFailedEvent -SubStatus '0xC0000064'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.SubStatus | Should -Be '0xC0000064 (User logon with misspelled or bad user account)'
        }

        It 'Should set ImpersonationLevel to null for failed logons' {
            $event = New-MockFailedEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.ImpersonationLevel | Should -BeNullOrEmpty
        }

        It 'Should set TargetLogonId to null for failed logons' {
            $event = New-MockFailedEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.TargetLogonId | Should -BeNullOrEmpty
        }

        It 'Should map LogonProcessName from Properties[11] for 4625' {
            $event = New-MockFailedEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.LogonProcessName | Should -Be 'NtLmSsp'
        }

        It 'Should map AuthenticationPackageName from Properties[12] for 4625' {
            $event = New-MockFailedEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.AuthenticationPackageName | Should -Be 'NTLM'
        }
    }

    Context 'FailureReason enrichment' {
        It 'Should translate %%2307 to Account locked out' {
            $event = New-MockFailedEvent -FailureReason '%%2307'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.FailureReason | Should -Be 'Account locked out'
        }

        It 'Should translate %%2310 to Account currently disabled' {
            $event = New-MockFailedEvent -FailureReason '%%2310'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.FailureReason | Should -Be 'Account currently disabled'
        }

        It 'Should translate %%2305 to The specified user account has expired' {
            $event = New-MockFailedEvent -FailureReason '%%2305'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.FailureReason | Should -Be 'The specified user account has expired'
        }

        It 'Should translate %%2309 to The specified account password has expired' {
            $event = New-MockFailedEvent -FailureReason '%%2309'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.FailureReason | Should -Be 'The specified account password has expired'
        }

        It 'Should pass through unknown FailureReason codes unchanged' {
            $event = New-MockFailedEvent -FailureReason '%%9999'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.FailureReason | Should -Be '%%9999'
        }
    }

    Context 'Status/SubStatus NTSTATUS enrichment' {
        It 'Should enrich Status 0xC0000234 as account locked' {
            $event = New-MockFailedEvent -Status '0xC0000234'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.Status | Should -Be '0xC0000234 (User logon with account locked)'
        }

        It 'Should enrich SubStatus 0xC000006A as bad password' {
            $event = New-MockFailedEvent -SubStatus '0xC000006A'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.SubStatus | Should -Be '0xC000006A (User logon with misspelled or bad password)'
        }

        It 'Should enrich Status 0xC0000072 as account disabled' {
            $event = New-MockFailedEvent -Status '0xC0000072'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.Status | Should -Be '0xC0000072 (User logon to account disabled by administrator)'
        }

        It 'Should enrich SubStatus 0xC0000193 as expired account' {
            $event = New-MockFailedEvent -SubStatus '0xC0000193'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.SubStatus | Should -Be '0xC0000193 (User logon with expired account)'
        }

        It 'Should pass through unknown Status codes unchanged' {
            $event = New-MockFailedEvent -Status '0xDEADBEEF'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.Status | Should -Be '0xDEADBEEF'
        }

        It 'Should pass through unknown SubStatus codes unchanged' {
            $event = New-MockFailedEvent -SubStatus '0xCAFEBABE'
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'
            $result.SubStatus | Should -Be '0xCAFEBABE'
        }
    }

    Context 'Pipeline with mixed event types' {
        It 'Should process mixed 4624 and 4625 events via pipeline' {
            # Need New-MockEvent from the outer scope too
            function New-MockEvent4624 {
                param([string]$UserName = 'gooduser')
                $props = @(
                    [PSCustomObject]@{ Value = 'S-1-0-0' }
                    [PSCustomObject]@{ Value = '-' }
                    [PSCustomObject]@{ Value = '-' }
                    [PSCustomObject]@{ Value = '0x0' }
                    [PSCustomObject]@{ Value = 'S-1-5-21-123' }
                    [PSCustomObject]@{ Value = $UserName }
                    [PSCustomObject]@{ Value = 'CONTOSO' }
                    [PSCustomObject]@{ Value = '0x12345' }
                    [PSCustomObject]@{ Value = 3 }
                    [PSCustomObject]@{ Value = 'NtLmSsp' }
                    [PSCustomObject]@{ Value = 'NTLM' }
                    [PSCustomObject]@{ Value = 'WKS01' }
                    [PSCustomObject]@{ Value = '{00000000-0000-0000-0000-000000000000}' }
                    [PSCustomObject]@{ Value = '-' }
                    [PSCustomObject]@{ Value = 'NTLM V2' }
                    [PSCustomObject]@{ Value = 128 }
                    [PSCustomObject]@{ Value = '0x0' }
                    [PSCustomObject]@{ Value = '-' }
                    [PSCustomObject]@{ Value = '10.0.0.1' }
                    [PSCustomObject]@{ Value = 49832 }
                    [PSCustomObject]@{ Value = '%%1833' }
                )
                $e = [PSCustomObject]@{ Id = 4624; TimeCreated = (Get-Date); Properties = $props; Message = 'An account was successfully logged on.' }
                $e.PSObject.TypeNames.Insert(0, 'System.Diagnostics.Eventing.Reader.EventLogRecord')
                return $e
            }

            $events = @(
                (New-MockEvent4624 -UserName 'gooduser')
                (New-MockFailedEvent -UserName 'baduser')
            )

            $results = $events | Convert-EventToObject -ComputerName 'SRV01'
            $results | Should -HaveCount 2
            $results[0].EventId | Should -Be 4624
            $results[0].UserName | Should -Be 'gooduser'
            $results[0].Status | Should -BeNullOrEmpty
            $results[1].EventId | Should -Be 4625
            $results[1].UserName | Should -Be 'baduser'
            $results[1].Status | Should -Not -BeNullOrEmpty
        }
    }
}


Describe 'Realistic Scenario: Domain Admin NTLM logon from VPN client' {

    It 'Should correctly parse a CONTOSO\Administrator NTLMv2 logon from VPN01 (172.16.1.10) on DC01' {
        # Simulate a real-world 4624 event: domain admin authenticates via NTLM from a VPN client
        $timestamp = [datetime]'2026-03-04 04:51:15'

        $props = @(
            [PSCustomObject]@{ Value = 'S-1-0-0' }                                    # [0]  SubjectUserSid
            [PSCustomObject]@{ Value = '-' }                                            # [1]  SubjectUserName
            [PSCustomObject]@{ Value = '-' }                                            # [2]  SubjectDomainName
            [PSCustomObject]@{ Value = '0x0' }                                          # [3]  SubjectLogonId
            [PSCustomObject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-500' }# [4]  TargetUserSid (built-in Administrator RID 500)
            [PSCustomObject]@{ Value = 'Administrator' }                                # [5]  TargetUserName
            [PSCustomObject]@{ Value = 'CONTOSO' }                                      # [6]  TargetDomainName
            [PSCustomObject]@{ Value = '12255534' }                                     # [7]  TargetLogonId
            [PSCustomObject]@{ Value = 3 }                                              # [8]  LogonType (Network)
            [PSCustomObject]@{ Value = 'NtLmSsp' }                                     # [9]  LogonProcessName
            [PSCustomObject]@{ Value = 'NTLM' }                                        # [10] AuthenticationPackageName
            [PSCustomObject]@{ Value = 'VPN01' }                                        # [11] WorkstationName
            [PSCustomObject]@{ Value = '{00000000-0000-0000-0000-000000000000}' }       # [12] LogonGuid
            [PSCustomObject]@{ Value = '-' }                                            # [13] TransmittedServices
            [PSCustomObject]@{ Value = 'NTLM V2' }                                     # [14] LmPackageName
            [PSCustomObject]@{ Value = 128 }                                            # [15] KeyLength
            [PSCustomObject]@{ Value = '0x0' }                                          # [16] ProcessId
            [PSCustomObject]@{ Value = '-' }                                            # [17] ProcessName
            [PSCustomObject]@{ Value = '172.16.1.10' }                                  # [18] IpAddress
            [PSCustomObject]@{ Value = 0 }                                              # [19] IpPort
            [PSCustomObject]@{ Value = '%%1833' }                                       # [20] ImpersonationLevel
        )

        $mockEvent = [PSCustomObject]@{
            Id          = 4624
            TimeCreated = $timestamp
            Properties  = $props
            Message     = 'An account was successfully logged on.'
        }
        $mockEvent.PSObject.TypeNames.Insert(0, 'System.Diagnostics.Eventing.Reader.EventLogRecord')

        $result = Convert-EventToObject -Event $mockEvent -ComputerName 'DC01'

        $result.EventId | Should -Be 4624
        $result.Time | Should -Be $timestamp
        $result.UserName | Should -Be 'Administrator'
        $result.TargetDomainName | Should -Be 'CONTOSO'
        $result.LogonType | Should -Be '3 (Network)'
        $result.LogonProcessName | Should -Be 'NtLmSsp'
        $result.AuthenticationPackageName | Should -Be 'NTLM'
        $result.WorkstationName | Should -Be 'VPN01'
        $result.LmPackageName | Should -Be 'NTLM V2'
        $result.IPAddress | Should -Be '172.16.1.10'
        $result.TCPPort | Should -Be 0
        $result.ImpersonationLevel | Should -Be 'Impersonation'
        $result.ProcessName | Should -Be '-'
        $result.Status | Should -BeNullOrEmpty
        $result.FailureReason | Should -BeNullOrEmpty
        $result.SubStatus | Should -BeNullOrEmpty
        $result.TargetLogonId | Should -Be '12255534'
        $result.ComputerName | Should -Be 'DC01'
    }

    It 'Should identify the VPN logon as privileged when correlated with Event ID 4672' {
        $timestamp = [datetime]'2026-03-04 04:51:15'

        # Build the 4624 result object as Merge-PrivilegedLogonData expects
        $logonEvent = [PSCustomObject]@{
            PSTypeName                = 'NtlmLogonEvent'
            EventId                   = 4624
            Time                      = $timestamp
            UserName                  = 'Administrator'
            TargetDomainName          = 'CONTOSO'
            LogonType                 = 3
            LogonProcessName          = 'NtLmSsp'
            AuthenticationPackageName = 'NTLM'
            WorkstationName           = 'VPN01'
            LmPackageName             = 'NTLM V2'
            IPAddress                 = '172.16.1.10'
            TCPPort                   = 0
            ImpersonationLevel        = 'Impersonation'
            ProcessName               = '-'
            Status                    = $null
            FailureReason             = $null
            SubStatus                 = $null
            TargetLogonId             = '12255534'
            ComputerName              = 'DC01'
        }

        $privilegeList = 'SeSecurityPrivilege
		SeBackupPrivilege
		SeRestorePrivilege
		SeTakeOwnershipPrivilege
		SeDebugPrivilege
		SeSystemEnvironmentPrivilege
		SeLoadDriverPrivilege
		SeImpersonatePrivilege
		SeEnableDelegationPrivilege'

        Mock Get-PrivilegedLogonLookup {
            return @{ '12255534' = $privilegeList }
        }

        Merge-PrivilegedLogonData -Events @($logonEvent)

        $logonEvent.IsPrivileged | Should -BeTrue
        $logonEvent.PrivilegeList | Should -Match 'SeDebugPrivilege'
        $logonEvent.PrivilegeList | Should -Match 'SeBackupPrivilege'
    }
}

} # InModuleScope
