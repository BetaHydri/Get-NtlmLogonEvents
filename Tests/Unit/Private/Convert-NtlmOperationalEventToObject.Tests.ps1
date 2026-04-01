BeforeAll {
    $script:moduleName = 'Get-NtlmLogonEvents'
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module -Name $script:moduleName -Force -ErrorAction Stop
}

InModuleScope 'Get-NtlmLogonEvents' {

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


} # InModuleScope
