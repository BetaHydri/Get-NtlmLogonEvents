#Requires -Module @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

<#
    Pester tests for Get-NtlmLogonEvents.ps1
    These tests use mocking to avoid requiring Security event log access or admin privileges.
#>

BeforeAll {
    $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-NtlmLogonEvents.ps1'

    # Dot-source is not appropriate for a script with param() block.
    # Instead, we extract the helper functions by parsing the script.
    # We'll create a wrapper module to expose Build-XPathFilter and Convert-EventToObject.

    $scriptContent = Get-Content -Path $scriptPath -Raw

    # Extract the helper functions from the script
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptContent, [ref]$null, [ref]$null)
    $functions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)

    foreach ($func in $functions) {
        # Relax [EventLogRecord] type constraint so mock PSCustomObjects are accepted
        $funcText = $func.Extent.Text -replace '\[System\.Diagnostics\.Eventing\.Reader\.EventLogRecord\]', '[PSObject]'
        # Define each helper function in the test scope
        Invoke-Expression $funcText
    }
}

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
            # Should contain a Z-terminated timestamp
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

Describe 'Get-NtlmLogonEvents.ps1 Script Parameters' {

    BeforeAll {
        $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-NtlmLogonEvents.ps1'
        $command = Get-Command $scriptPath
    }

    Context 'Parameter definitions' {
        It 'Should have a NumEvents parameter of type Int32' {
            $command.Parameters['NumEvents'].ParameterType.Name | Should -Be 'Int32'
        }

        It 'Should default NumEvents to 30' {
            $command.Parameters['NumEvents'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            Should -Not -BeNullOrEmpty
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
            $command.ScriptBlock.Attributes |
            Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] } |
            Should -Not -BeNullOrEmpty
        }
    }

    Context 'Parameter validation' {
        It 'Should reject NumEvents of 0' {
            { & $scriptPath -NumEvents 0 } | Should -Throw
        }

        It 'Should reject negative NumEvents' {
            { & $scriptPath -NumEvents -5 } | Should -Throw
        }

        It 'Should reject invalid Target values' {
            { & $scriptPath -Target 'server.contoso.com' } | Should -Throw
        }

        It 'Should reject invalid Authentication values' {
            { & $scriptPath -Authentication 'Basic' } | Should -Throw
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

Describe 'Get-NtlmLogonEvents.ps1 Script Execution (mocked)' {

    BeforeAll {
        $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-NtlmLogonEvents.ps1'
        Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue

        # Safety-net: prevent any real Get-WinEvent / Invoke-Command call from
        # reaching the Security log or remote hosts if context-level mocks fail.
        Mock Get-WinEvent {
            throw [System.Exception]::new('No events were found that match the specified selection criteria.')
        }
        Mock Invoke-Command { }
    }

    Context 'Local host - no events found' {
        BeforeEach {
            Mock Get-WinEvent {
                throw [System.Exception]::new('No events were found that match the specified selection criteria.')
            }
        }

        It 'Should emit a warning when no events are found' {
            $result = & $scriptPath 3>&1
            # The warning stream should contain our message
            $warnings = $result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }
            $warnings | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Local host - events found' {
        BeforeEach {
            # Build the mock event inline so it is available inside the mock
            # scriptblock (Pester v5 mock blocks run in a separate session state,
            # so $script: references from BeforeAll are not visible).
            Mock Get-WinEvent {
                $mockProps = @(
                    [PSCustomObject]@{ Value = 'S-1-0-0' }          # [0]  SubjectUserSid
                    [PSCustomObject]@{ Value = '-' }                 # [1]  SubjectUserName
                    [PSCustomObject]@{ Value = '-' }                 # [2]  SubjectDomainName
                    [PSCustomObject]@{ Value = '0x0' }               # [3]  SubjectLogonId
                    [PSCustomObject]@{ Value = 'S-1-5-21-123' }     # [4]  TargetUserSid
                    [PSCustomObject]@{ Value = 'testuser' }          # [5]  TargetUserName
                    [PSCustomObject]@{ Value = 'TESTDOMAIN' }        # [6]  TargetDomainName
                    [PSCustomObject]@{ Value = '0xABC' }             # [7]  TargetLogonId
                    [PSCustomObject]@{ Value = 3 }                   # [8]  LogonType
                    [PSCustomObject]@{ Value = 'NtLmSsp' }          # [9]  LogonProcessName
                    [PSCustomObject]@{ Value = 'NTLM' }             # [10] AuthenticationPackageName
                    [PSCustomObject]@{ Value = 'TESTPC' }            # [11] WorkstationName
                    [PSCustomObject]@{ Value = '{00000000-0000-0000-0000-000000000000}' } # [12] LogonGuid
                    [PSCustomObject]@{ Value = '-' }                 # [13] TransmittedServices
                    [PSCustomObject]@{ Value = 'NTLM V2' }          # [14] LmPackageName
                    [PSCustomObject]@{ Value = 128 }                 # [15] KeyLength
                    [PSCustomObject]@{ Value = '0x0' }               # [16] ProcessId
                    [PSCustomObject]@{ Value = '-' }                 # [17] ProcessName
                    [PSCustomObject]@{ Value = '10.0.0.1' }          # [18] IpAddress
                    [PSCustomObject]@{ Value = 50000 }               # [19] IpPort
                    [PSCustomObject]@{ Value = '%%1833' }            # [20] ImpersonationLevel
                )
                $evt = [PSCustomObject]@{
                    Id          = 4624
                    TimeCreated = [datetime]'2026-02-25 10:00:00'
                    Properties  = $mockProps
                    Message     = 'An account was successfully logged on.'
                }
                $evt.PSObject.TypeNames.Insert(0, 'System.Diagnostics.Eventing.Reader.EventLogRecord')
                return $evt
            }
        }

        It 'Should return objects when events exist' {
            $result = & $scriptPath -NumEvents 1
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
            }
        }

        It 'Should emit an error if ActiveDirectory module is not available' {
            $result = & $scriptPath -Target DCs 2>&1
            $errors = $result | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
            $errors | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Forest target without ActiveDirectory module' {
        BeforeEach {
            Mock Import-Module { throw 'Module not found' } -ParameterFilter {
                $Name -eq 'ActiveDirectory'
            }
        }

        It 'Should emit an error if ActiveDirectory module is not available for Forest target' {
            $result = & $scriptPath -Target Forest 2>&1
            $errors = $result | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
            $errors | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Script file quality' {

    BeforeAll {
        $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-NtlmLogonEvents.ps1'
        $scriptContent = Get-Content -Path $scriptPath -Raw
    }

    It 'Should have #Requires statement for PowerShell 5.1' {
        $scriptContent | Should -Match '#Requires -Version 5\.1'
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

    It 'Should NOT contain the old -IncludeAllNtlm parameter' {
        $scriptContent | Should -Not -Match 'IncludeAllNtlm'
    }

    It 'Should NOT contain the old -NullSession boolean parameter' {
        $scriptContent | Should -Not -Match '\[boolean\]\$NullSession'
    }

    It 'Should NOT contain the IPAdress typo' {
        $scriptContent | Should -Not -Match 'IPAdress'
    }

    It 'Should NOT contain Write-Host (use Write-Verbose/Warning/Error instead)' {
        $scriptContent | Should -Not -Match 'Write-Host'
    }

    It 'Should NOT contain $error.Clear()' {
        $scriptContent | Should -Not -Match '\$error\.Clear\(\)'
    }

    It 'Should parse without syntax errors' {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
        $errors | Should -HaveCount 0
    }
}

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

Describe 'Convert-NtlmOperationalEventToObject' {

    BeforeAll {
        # Helper: create a mock NTLM operational event
        function New-MockNtlmOpEvent {
            param(
                [int]$EventId = 8001,
                [PSObject[]]$Properties,
                [datetime]$TimeCreated = (Get-Date)
            )
            $mockEvent = [PSCustomObject]@{
                Id          = $EventId
                TimeCreated = $TimeCreated
                Properties  = $Properties
                Message     = "Mock NTLM operational event message for Event ID $EventId"
            }
            return $mockEvent
        }
    }

    Context 'Event 8001 (Client outgoing audit)' {
        It 'Should map TargetName from Properties[0]' {
            # 8001 layout: TargetName[0], UserName[1], DomainName[2], CallerPID[3], ProcessName[4]
            $props = @(
                [PSCustomObject]@{ Value = 'HTTP/server.contoso.local' }
                [PSCustomObject]@{ Value = 'jsmith' }
                [PSCustomObject]@{ Value = 'CONTOSO' }
                [PSCustomObject]@{ Value = 1234 }
                [PSCustomObject]@{ Value = 'msedge.exe' }
            )
            $event = New-MockNtlmOpEvent -EventId 8001 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'WKS01'
            $result.TargetName | Should -Be 'HTTP/server.contoso.local'
            $result.UserName | Should -Be 'jsmith'
            $result.DomainName | Should -Be 'CONTOSO'
            $result.ProcessName | Should -Be 'msedge.exe'
            $result.ProcessId | Should -Be 1234
            $result.EventType | Should -Be 'Audit'
            $result.EventId | Should -Be 8001
        }

        It 'Should set WorkstationName and SecureChannelName to null' {
            # 8001 layout: TargetName[0], UserName[1], DomainName[2], CallerPID[3], ProcessName[4]
            $props = @(
                [PSCustomObject]@{ Value = 'HTTP/server' }
                [PSCustomObject]@{ Value = 'user1' }
                [PSCustomObject]@{ Value = 'DOMAIN' }
                [PSCustomObject]@{ Value = 5678 }
                [PSCustomObject]@{ Value = 'app.exe' }
            )
            $event = New-MockNtlmOpEvent -EventId 8001 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'WKS01'
            $result.WorkstationName | Should -BeNullOrEmpty
            $result.SecureChannelName | Should -BeNullOrEmpty
        }

        It 'Should handle events with fewer than 5 properties gracefully' {
            $props = @(
                [PSCustomObject]@{ Value = 'HTTP/server' }
                [PSCustomObject]@{ Value = 'user1' }
                [PSCustomObject]@{ Value = 'DOMAIN' }
            )
            $event = New-MockNtlmOpEvent -EventId 8001 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'WKS01'
            $result.ProcessName | Should -BeNullOrEmpty
            $result.ProcessId | Should -BeNullOrEmpty
        }
    }

    Context 'Event 8002 (Incoming NTLM, local/loopback)' {
        It 'Should map ClientUserName to UserName and CallerPID to ProcessId' {
            # 8002 layout: CallerPID[0], ProcessName[1], ClientLUID[2], ClientUserName[3], ClientDomainName[4]
            $props = @(
                [PSCustomObject]@{ Value = 700 }
                [PSCustomObject]@{ Value = 'C:\Windows\System32\svchost.exe' }
                [PSCustomObject]@{ Value = '0x3e4' }
                [PSCustomObject]@{ Value = 'MACHINE$' }
                [PSCustomObject]@{ Value = 'CONTOSO' }
            )
            $event = New-MockNtlmOpEvent -EventId 8002 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'SRV01'
            $result.UserName | Should -Be 'MACHINE$'
            $result.DomainName | Should -Be 'CONTOSO'
            $result.ProcessName | Should -Be 'C:\Windows\System32\svchost.exe'
            $result.ProcessId | Should -Be 700
            $result.TargetName | Should -BeNullOrEmpty
            $result.WorkstationName | Should -BeNullOrEmpty
            $result.SecureChannelName | Should -BeNullOrEmpty
            $result.EventType | Should -Be 'Audit'
            $result.EventId | Should -Be 8002
        }
    }

    Context 'Event 8003 (Server incoming domain account)' {
        It 'Should map UserName from Properties[0] and WorkstationName from Properties[2]' {
            # 8003 layout: UserName[0], DomainName[1], Workstation[2], CallerPID[3], ProcessName[4]
            $props = @(
                [PSCustomObject]@{ Value = 'joe_user' }
                [PSCustomObject]@{ Value = 'CONTOSO' }
                [PSCustomObject]@{ Value = 'CONTOSO-PC1' }
                [PSCustomObject]@{ Value = 9876 }
                [PSCustomObject]@{ Value = 'w3wp.exe' }
            )
            $event = New-MockNtlmOpEvent -EventId 8003 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'FS01'
            $result.UserName | Should -Be 'joe_user'
            $result.DomainName | Should -Be 'CONTOSO'
            $result.WorkstationName | Should -Be 'CONTOSO-PC1'
            $result.ProcessName | Should -Be 'w3wp.exe'
            $result.ProcessId | Should -Be 9876
            $result.TargetName | Should -BeNullOrEmpty
            $result.SecureChannelName | Should -BeNullOrEmpty
            $result.EventType | Should -Be 'Audit'
        }
    }

    Context 'Event 8004 (DC credential validation)' {
        It 'Should map SecureChannelName from Properties[0]' {
            # 8004 layout: SChannelName[0], UserName[1], DomainName[2], WorkstationName[3], SChannelType[4]
            $props = @(
                [PSCustomObject]@{ Value = 'CONTOSO-FS2' }
                [PSCustomObject]@{ Value = 'joe_user' }
                [PSCustomObject]@{ Value = 'CONTOSO' }
                [PSCustomObject]@{ Value = 'CONTOSO-PC1' }
            )
            $event = New-MockNtlmOpEvent -EventId 8004 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'DC01'
            $result.UserName | Should -Be 'joe_user'
            $result.DomainName | Should -Be 'CONTOSO'
            $result.WorkstationName | Should -Be 'CONTOSO-PC1'
            $result.SecureChannelName | Should -Be 'CONTOSO-FS2'
            $result.ProcessName | Should -BeNullOrEmpty
            $result.ProcessId | Should -BeNullOrEmpty
            $result.EventType | Should -Be 'Audit'
        }
    }

    Context 'Block events (4001-4006)' {
        It 'Should set EventType to Block for event 4001' {
            # 4001 layout (same as 8001): TargetName[0], UserName[1], DomainName[2], CallerPID[3], ProcessName[4]
            $props = @(
                [PSCustomObject]@{ Value = 'HTTP/server' }
                [PSCustomObject]@{ Value = 'user1' }
                [PSCustomObject]@{ Value = 'DOMAIN' }
                [PSCustomObject]@{ Value = 1111 }
                [PSCustomObject]@{ Value = 'app.exe' }
            )
            $event = New-MockNtlmOpEvent -EventId 4001 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'WKS01'
            $result.EventType | Should -Be 'Block'
            $result.EventId | Should -Be 4001
            $result.TargetName | Should -Be 'HTTP/server'
        }

        It 'Should use same layout as 8002 for event 4002' {
            # 4002 layout (same as 8002): CallerPID[0], ProcessName[1], ClientLUID[2], ClientUserName[3], ClientDomainName[4]
            $props = @(
                [PSCustomObject]@{ Value = 500 }
                [PSCustomObject]@{ Value = 'lsass.exe' }
                [PSCustomObject]@{ Value = '0x3e7' }
                [PSCustomObject]@{ Value = 'SVC$' }
                [PSCustomObject]@{ Value = 'CORP' }
            )
            $event = New-MockNtlmOpEvent -EventId 4002 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'SRV01'
            $result.EventType | Should -Be 'Block'
            $result.UserName | Should -Be 'SVC$'
            $result.ProcessName | Should -Be 'lsass.exe'
            $result.ProcessId | Should -Be 500
        }

        It 'Should use same layout as 8003 for event 4003' {
            # 4003 layout (same as 8003): UserName[0], DomainName[1], Workstation[2], CallerPID[3], ProcessName[4]
            $props = @(
                [PSCustomObject]@{ Value = 'user2' }
                [PSCustomObject]@{ Value = 'CORP' }
                [PSCustomObject]@{ Value = 'CLIENT-PC' }
                [PSCustomObject]@{ Value = 2222 }
                [PSCustomObject]@{ Value = 'svchost.exe' }
            )
            $event = New-MockNtlmOpEvent -EventId 4003 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'SRV01'
            $result.EventType | Should -Be 'Block'
            $result.UserName | Should -Be 'user2'
            $result.WorkstationName | Should -Be 'CLIENT-PC'
            $result.ProcessName | Should -Be 'svchost.exe'
            $result.ProcessId | Should -Be 2222
        }

        It 'Should use same layout as 8004 for event 4004' {
            # 4004 layout (same as 8004): SChannelName[0], UserName[1], DomainName[2], WorkstationName[3]
            $props = @(
                [PSCustomObject]@{ Value = 'FS01' }
                [PSCustomObject]@{ Value = 'admin' }
                [PSCustomObject]@{ Value = 'CONTOSO' }
                [PSCustomObject]@{ Value = 'WKS01' }
            )
            $event = New-MockNtlmOpEvent -EventId 4004 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'DC01'
            $result.EventType | Should -Be 'Block'
            $result.SecureChannelName | Should -Be 'FS01'
            $result.UserName | Should -Be 'admin'
            $result.WorkstationName | Should -Be 'WKS01'
        }
    }

    Context 'Output object properties' {
        It 'Should have all expected properties' {
            # 8001 layout: TargetName[0], UserName[1], DomainName[2], CallerPID[3], ProcessName[4]
            $props = @(
                [PSCustomObject]@{ Value = 'HTTP/server' }
                [PSCustomObject]@{ Value = 'user1' }
                [PSCustomObject]@{ Value = 'DOMAIN' }
                [PSCustomObject]@{ Value = 1234 }
                [PSCustomObject]@{ Value = 'app.exe' }
            )
            $event = New-MockNtlmOpEvent -EventId 8001 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'SRV01'

            $expectedProps = @(
                'EventId', 'EventType', 'EventDescription', 'Time',
                'UserName', 'DomainName', 'TargetName', 'WorkstationName',
                'SecureChannelName', 'ProcessName', 'ProcessId', 'Message', 'ComputerName'
            )
            foreach ($prop in $expectedProps) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }

        It 'Should have PSTypeName NtlmOperationalEvent' {
            # 8001 layout: TargetName[0], UserName[1], DomainName[2], CallerPID[3], ProcessName[4]
            $props = @(
                [PSCustomObject]@{ Value = 'HTTP/server' }
                [PSCustomObject]@{ Value = 'user1' }
                [PSCustomObject]@{ Value = 'DOMAIN' }
                [PSCustomObject]@{ Value = 1234 }
                [PSCustomObject]@{ Value = 'app.exe' }
            )
            $event = New-MockNtlmOpEvent -EventId 8001 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'SRV01'
            $result.PSObject.TypeNames | Should -Contain 'NtlmOperationalEvent'
        }

        It 'Should have EventDescription populated' {
            # 8001 layout: TargetName[0], UserName[1], DomainName[2], CallerPID[3], ProcessName[4]
            $props = @(
                [PSCustomObject]@{ Value = 'HTTP/server' }
                [PSCustomObject]@{ Value = 'user1' }
                [PSCustomObject]@{ Value = 'DOMAIN' }
                [PSCustomObject]@{ Value = 1234 }
                [PSCustomObject]@{ Value = 'app.exe' }
            )
            $event = New-MockNtlmOpEvent -EventId 8001 -Properties $props
            $result = Convert-NtlmOperationalEventToObject -Event $event -ComputerName 'SRV01'
            $result.EventDescription | Should -Be 'Outgoing NTLM authentication (client-side)'
        }
    }

    Context 'Pipeline input' {
        It 'Should process multiple events via pipeline' {
            $events = @(
                (New-MockNtlmOpEvent -EventId 8001 -Properties @(
                    [PSCustomObject]@{ Value = 'HTTP/srv1' }
                    [PSCustomObject]@{ Value = 'user1' }
                    [PSCustomObject]@{ Value = 'DOM' }
                ))
                (New-MockNtlmOpEvent -EventId 8003 -Properties @(
                    [PSCustomObject]@{ Value = 'user2' }
                    [PSCustomObject]@{ Value = 'DOM' }
                    [PSCustomObject]@{ Value = 'PC1' }
                ))
            )
            $results = $events | Convert-NtlmOperationalEventToObject -ComputerName 'SRV01'
            $results | Should -HaveCount 2
            $results[0].EventId | Should -Be 8001
            $results[1].EventId | Should -Be 8003
        }
    }
}

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
