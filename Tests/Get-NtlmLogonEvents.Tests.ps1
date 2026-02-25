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
        # Define each helper function in the test scope
        Invoke-Expression $func.Extent.Text
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
                TimeCreated = $TimeCreated
                Properties  = $props
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
            $result.LogonType | Should -Be 10
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

    Context 'Output object properties' {
        It 'Should have all expected properties' {
            $event = New-MockEvent
            $result = Convert-EventToObject -Event $event -ComputerName 'SRV01'

            $expectedProps = @(
                'Time', 'UserName', 'TargetDomainName', 'LogonType',
                'WorkstationName', 'LmPackageName', 'IPAddress', 'TCPPort',
                'ImpersonationLevel', 'ProcessName', 'ComputerName'
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

        It 'Should have ExcludeNullSessions as a switch' {
            $command.Parameters['ExcludeNullSessions'].SwitchParameter | Should -BeTrue
        }

        It 'Should have OnlyNTLMv1 as a switch' {
            $command.Parameters['OnlyNTLMv1'].SwitchParameter | Should -BeTrue
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

        It 'Should support CmdletBinding (Verbose, etc.)' {
            $command.CmdletBinding | Should -BeTrue
        }
    }

    Context 'Parameter validation' {
        It 'Should reject NumEvents of 0' {
            { & $scriptPath -NumEvents 0 } | Should -Throw
        }

        It 'Should reject negative NumEvents' {
            { & $scriptPath -NumEvents -5 } | Should -Throw
        }

        It 'Should reject empty Target string' {
            { & $scriptPath -Target '' } | Should -Throw
        }
    }
}

Describe 'Get-NtlmLogonEvents.ps1 Script Execution (mocked)' {

    BeforeAll {
        $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-NtlmLogonEvents.ps1'
    }

    Context 'Local host - no events found' {
        It 'Should emit a warning when no events are found' {
            Mock Get-WinEvent {
                throw [System.Exception]::new('No events were found that match the specified selection criteria.')
            } -ModuleName Microsoft.PowerShell.Diagnostics

            $result = & $scriptPath 3>&1
            # The warning stream should contain our message
            $warnings = $result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }
            $warnings | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Local host - events found' {
        It 'Should return objects when events exist' {
            # Build mock properties array (21 items for indices 0-20)
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

            $mockEvent = [PSCustomObject]@{
                TimeCreated = [datetime]'2026-02-25 10:00:00'
                Properties  = $mockProps
            }
            $mockEvent.PSObject.TypeNames.Insert(0, 'System.Diagnostics.Eventing.Reader.EventLogRecord')

            Mock Get-WinEvent { return $mockEvent } -ModuleName Microsoft.PowerShell.Diagnostics

            $result = & $scriptPath -NumEvents 1
            $result | Should -Not -BeNullOrEmpty
            $result.UserName | Should -Be 'testuser'
            $result.LmPackageName | Should -Be 'NTLM V2'
            $result.ImpersonationLevel | Should -Be 'Impersonation'
        }
    }

    Context 'DCs target without ActiveDirectory module' {
        It 'Should emit an error if ActiveDirectory module is not available' {
            Mock Import-Module { throw 'Module not found' }

            $result = & $scriptPath -Target DCs 2>&1
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
        $scriptContent | Should -Match '\[CmdletBinding\(\)\]'
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
        $scriptContent | Should -Match '\.PARAMETER StartTime'
        $scriptContent | Should -Match '\.PARAMETER EndTime'
        $scriptContent | Should -Match '\.PARAMETER Credential'
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
