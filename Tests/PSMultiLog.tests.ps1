$ParentPath = Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) -Parent
Import-Module -Name (Join-Path -Path $ParentPath -ChildPath 'PSMultiLog.psm1')


#-------------------------------------------------------------------------------
# File Logging
#-------------------------------------------------------------------------------
Describe Start-FileLog {
    It 'Enables File Logging' {
        InModuleScope PSMultiLog {
            Mock Test-Path { return $false }
            Mock New-Item {}
            Stop-FileLog
            $Script:Settings['File'].Enabled | Should Be $false

            Start-FileLog -FilePath 'C:\NotARealFile.log'
            $Script:Settings['File'].Enabled | Should Be $true

            Stop-FileLog
        }
    }

    It 'Creates log file' {
        InModuleScope PSMultiLog {
            Mock Test-Path { return $false }
            Mock New-Item {}

            Start-FileLog -FilePath 'C:\NotARealFile.log'
            Assert-MockCalled -Scope It New-Item -Exactly 1

            Stop-FileLog
        }
    }

    It 'Removes existing file' {
        InModuleScope PSMultiLog {
            Mock Test-Path { return $true }
            Mock Remove-Item {}
            Mock New-Item {}

            Start-FileLog -FilePath 'C:\NotARealFile.log'
            Assert-MockCalled -Scope It Remove-Item -Exactly 1

            Stop-FileLog
        }
    }
}

Describe Stop-FileLog {
    It 'Disables File Logging' {
        InModuleScope PSMultiLog {
            Mock Test-Path { return $false }
            Mock New-Item {}
            Start-FileLog -FilePath 'C:\NotARealFile.log'
            $Script:Settings['File'].Enabled | Should Be $true

            Stop-FileLog
            $Script:Settings['File'].Enabled | Should Be $false
        }
    }
}

Describe Write-FileLog {
    It 'Writes to a file' {
        InModuleScope PSMultiLog {
            $Timestamp = Get-Date
            $TimestampString = $Timestamp.ToString('u')
            $InfoEntry = New-Object -TypeName psobject -Property @{
                Timestamp = $Timestamp
                EntryType = 'Information'
                LogLevel  = 2
                Message   = 'Hello, World!'
                Exception = $null
                EventId   = 1000
            }

            Mock Out-File {}

            Write-FileLog -Entry $InfoEntry -FilePath 'C:\NotARealFile.log'
            Assert-MockCalled -Scope It Out-File -Exactly 1
        }
    }
}

#-------------------------------------------------------------------------------
# E-mail Logging
#-------------------------------------------------------------------------------
Describe Start-EmailLog {
    InModuleScope PSMultiLog {
        It 'Enables E-mail Logging' {
            $Script:Settings['Email'].Enabled | Should Be $false
            Start-EmailLog
            $Script:Settings['Email'].Enabled | Should Be $true
            Stop-EmailLog
        }

        It 'Clears the entry cache' {
            $Script:LogEntries.Count | Should Be 0
            Start-EmailLog
            Write-Log -EntryType Information -Message 'Test'
            Stop-EmailLog -RetainEntryCache
            $Script:LogEntries.Count | Should Be 1
            Start-EmailLog -ClearEntryCache
            $Script:LogEntries.Count | Should Be 0
            Stop-EmailLog
        }
    }
}

Describe Stop-EmailLog {
    InModuleScope PSMultiLog {
        It 'Disables Email Logging' {
            Start-EmailLog
            $Script:Settings['Email'].Enabled | Should Be $true
            Stop-EmailLog
            $Script:Settings['Email'].Enabled | Should Be $false

        }

        It 'Clears the entry cache' {
            Start-EmailLog -ClearEntryCache
            Write-Log -EntryType Information -Message 'Test'
            $Script:LogEntries.Count | Should Be 1

            Stop-EmailLog
            $Script:LogEntries.Count | Should Be 0
        }

        It 'Retains the entry cache' {
            Start-EmailLog -ClearEntryCache
            Write-Log -EntryType Information -Message 'Test'
            $Script:LogEntries.Count | Should Be 1

            Stop-EmailLog -RetainEntryCache
            $Script:LogEntries.Count | Should Be 1

            # Just to make sure the entry cache is cleared.
            Stop-EmailLog
        }
    }
}

Describe Send-EmailLog {
    $SmtpServer = 'Fake'
    $To = 'Fake'
    $From = 'Fake'
    $Subject = 'Fake'

    Mock -ModuleName PSMultiLog Send-MailMessage {}

    It 'Sends e-mail' {
        Start-EmailLog
        Write-Log -EntryType Error -Message 'Test message'    

        Send-EmailLog -SmtpServer $SmtpServer -To $To -From $From -Subject $Subject
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Send-MailMessage -Exactly 1

        Stop-EmailLog
    }

    It 'Sends on empty' {
        Send-EmailLog -SmtpServer $SmtpServer -To $To -From $From -Subject $Subject -SendOnEmpty
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Send-MailMessage -Exactly 1
    }

    It 'Does not send on empty' {
        Send-EmailLog -SmtpServer $SmtpServer -To $To -From $From -Subject $Subject
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Send-MailMessage -Exactly 0
    }

    It 'Triggers based on log level' {
        Start-EmailLog -ClearEntryCache
        Write-Log -EntryType Warning -Message 'Test message'

        Send-EmailLog -SmtpServer $SmtpServer -To $To -From $From -Subject $Subject
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Send-MailMessage 0

        Write-Log -EntryType Warning -Message 'Test message'
        Send-EmailLog -SmtpServer $SmtpServer -To $To -From $From -Subject $Subject -TriggerLogLevel Warning -SendLogLevel Information
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Send-MailMessage -Exactly 1

        Stop-EmailLog
    }

    It 'Retains log entry cache' {
        Start-EmailLog -ClearEntryCache

        Write-Log -EntryType Warning -Message 'Test message'
        Send-EmailLog -SmtpServer $SmtpServer -To $To -From $From -Subject $Subject -RetainEntryCache

        InModuleScope PSMultiLog {
            $Script:LogEntries.Count | Should Be 1
        }

        Stop-EmailLog
    }

    It 'Empties log entry cache' {
        Start-EmailLog -ClearEntryCache

        Write-Log -EntryType Warning -Message 'Test message'
        Send-EmailLog -SmtpServer $SmtpServer -To $To -From $From -Subject $Subject

        InModuleScope PSMultiLog {
            $Script:LogEntries.Count | Should Be 0
        }

        Stop-EmailLog
    }
}

Describe Write-EmailLog {
    InModuleScope PSMultiLog {
        It 'Writes to the entry cache' {
            Start-EmailLog -ClearEntryCache
            $Script:LogEntries.Count | Should Be 0

            Write-EmailLog -Entry 'Dummy Entry'
            $Script:LogEntries.Count | Should Be 1

            Stop-EmailLog
        }
    }
}

#-------------------------------------------------------------------------------
# Event Log Logging
#-------------------------------------------------------------------------------
Describe Start-EventLogLog {
    Mock -ModuleName PSMultiLog New-EventLog {}
    Mock -ModuleName PSMultiLog Test-EventLogSource { return $true }
    Mock -ModuleName PSMultiLog Get-LogName { return 'Application' }

    It 'Enables Event Log Logging' {
        InModuleScope PSMultiLog {
            $Script:Settings['EventLog'].Enabled | Should Be $false

            Start-EventLogLog -Source 'Fake'
            $Script:Settings['EventLog'].Enabled | Should Be $true

            Stop-EventLogLog
        }
    }

    
    It 'Writes an error if source is in wrong log' {
        Mock -ModuleName PSMultiLog Write-Error {}
        Start-EventLogLog -Source 'Fake' -LogName 'Fake'
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-Error -Exactly 1
    }

    It 'Creates a new log if necessary' {
        Mock -ModuleName PSMultiLog Test-EventLogSource { return $false }
        Start-EventLogLog -Source 'Fake'
        Assert-MockCalled -ModuleName PSMultiLog -Scope It New-EventLog -Exactly 1
    }
}

Describe Stop-EventLogLog {
    Mock -ModuleName PSMultiLog New-EventLog {}
    Mock -ModuleName PSMultiLog Test-EventLogSource { return $true }
    Mock -ModuleName PSMultiLog Get-LogName { return 'Application' }

    It 'Disables Event Log Logging' {
        InModuleScope PSMultiLog {
            Start-EventLogLog -Source 'Fake'
            $Script:Settings['EventLog'].Enabled | Should Be $true

            Stop-EventLogLog
            $Script:Settings['EventLog'].Enabled | Should Be $false
        }
    }
}

Describe Write-EventLogLog {
    It 'Writes to the Event Log' {
        InModuleScope PSMultiLog {
            Mock Write-EventLog

            $Timestamp = Get-Date
            $TimestampString = $Timestamp.ToString('u')
            $InfoEntry = New-Object -TypeName psobject -Property @{
                Timestamp = $Timestamp
                EntryType = 'Information'
                LogLevel  = 2
                Message   = 'Hello, World!'
                Exception = $null
                EventId   = 1000
            }

            Write-EventLogLog -Entry $InfoEntry -LogName 'Fake' -Source 'Fake'
            Assert-MockCalled -Scope It Write-EventLog -Exactly 1
        }
    }
}

#-------------------------------------------------------------------------------
# Host Logging
#-------------------------------------------------------------------------------
Describe Start-HostLog {
    InModuleScope PSMultiLog {
        It 'Enables Host Logging' {
            $Script:Settings['Host'].Enabled | Should Be $false
            Start-HostLog
            $Script:Settings['Host'].Enabled | Should Be $true
        }

        It 'Sets the log level' {
            Start-HostLog
            $Script:Settings['Host'].LogLevel | Should Be 0

            Start-HostLog -LogLevel 'Error'
            $Script:Settings['Host'].LogLevel | Should Be 0

            Start-HostLog -LogLevel 'Warning'
            $Script:Settings['Host'].LogLevel | Should Be 1

            Start-HostLog -LogLevel 'Information'
            $Script:Settings['Host'].LogLevel | Should Be 2
        }
    }
}

Describe Stop-HostLog {
    InModuleScope PSMultiLog {
        It 'Disables Host Logging' {
            Start-HostLog
            $Script:Settings['Host'].Enabled | Should Be $true

            Stop-HostLog
            $Script:Settings['Host'].Enabled | Should Be $false
        }
    }
}

Describe Write-HostLog {
    InModuleScope PSMultiLog {
        $Timestamp = Get-Date
        $TimestampString = $Timestamp.ToString('u')
        $Entry = New-Object -TypeName psobject -Property @{
            Timestamp = $Timestamp
            EntryType = 'Information'
            LogLevel  = 2
            Message   = 'Hello, World!'
            Exception = $null
            EventId   = 1000
        }

        It 'Writes to the host' {
            Mock Write-Host {}
            Write-HostLog -Entry $Entry
            Assert-MockCalled -Scope It Write-Host -Exactly 3
        }
    }
}

#-------------------------------------------------------------------------------
# PassThru Logging
#-------------------------------------------------------------------------------
Describe Start-PassThruLog {
    InModuleScope PSMultiLog {
        It 'Enables PassThru Logging' {
            $Script:Settings['PassThru'].Enabled | Should Be $false
            Start-PassThruLog
            $Script:Settings['PassThru'].Enabled | Should Be $true
        }

        It 'Sets the log level' {
            Start-PassThruLog
            $Script:Settings['PassThru'].LogLevel | Should Be 0

            Start-PassThruLog -LogLevel 'Error'
            $Script:Settings['PassThru'].LogLevel | Should Be 0

            Start-PassThruLog -LogLevel 'Warning'
            $Script:Settings['PassThru'].LogLevel | Should Be 1

            Start-PassThruLog -LogLevel 'Information'
            $Script:Settings['PassThru'].LogLevel | Should Be 2
        }
    }
}

Describe Stop-PassThruLog {
    InModuleScope PSMultiLog {
        It 'Disables PassThru Logging' {
            Start-PassThruLog
            $Script:Settings['PassThru'].Enabled | Should Be $true

            Stop-PassThruLog
            $Script:Settings['PassThru'].Enabled | Should Be $false
        }
    }
}

Describe Write-PassThruLog {
    InModuleScope PSMultiLog {
        $Timestamp = Get-Date
        $TimestampString = $Timestamp.ToString('u')
        $InfoEntry = New-Object -TypeName psobject -Property @{
            Timestamp = $Timestamp
            EntryType = 'Information'
            LogLevel  = 2
            Message   = 'Hello, World!'
            Exception = $null
            EventId   = 1000
        }

        $WarningEntry = New-Object -TypeName psobject -Property @{
            Timestamp = $Timestamp
            EntryType = 'Warning'
            LogLevel  = 1
            Message   = 'This is a warning.'
            Exception = $null
            EventId   = 1000
        }

        $ErrorEntry = New-Object -TypeName psobject -Property @{
            Timestamp = $Timestamp
            EntryType = 'Error'
            LogLevel  = 0
            Message   = 'This is an error.'
            Exception = New-Object -TypeName Exception -ArgumentList 'Exception message.'
            EventId   = 1000
        }

        $ErrorEntryNoException = New-Object -TypeName psobject -Property @{
            Timestamp = $Timestamp
            EntryType = 'Error'
            LogLevel  = 0
            Message   = 'This is an error.'
            Exception = $null
            EventId   = 1000
        }

        It 'Writes to the Verbose or Information stream' {
            Mock Write-Verbose {}
            Mock Write-Information {}
            Write-PassThruLog -Entry $InfoEntry

            if ($PSVersionTable -and $PSVersionTable.PSVersion.Major -ge 5) {
                Assert-MockCalled -Scope It Write-Information -Exactly 1
                Assert-MockCalled -Scope It Write-Verbose -Exactly 0
            }
            else {
                Assert-MockCalled -Scope It Write-Information -Exactly 0
                Assert-MockCalled -Scope It Write-Verbose -Exactly 1
            }
        }

        It 'Writes to the Warning stream' {
            Mock Write-Warning {}
            Write-PassThruLog -Entry $WarningEntry
            Assert-MockCalled -Scope It Write-Warning -Exactly 1
        }

        It 'Writes to the Error stream' {
            Mock Write-Error {}
            Write-PassThruLog -Entry $ErrorEntry
            Assert-MockCalled -Scope It Write-Error -Exactly 1
        }

        It 'Writes to the Error stream when no Exception is included' {
            Mock Write-Error {}
            Write-PassThruLog -Entry $ErrorEntryNoException
            Assert-MockCalled -Scope It Write-Error -Exactly 1
        }
    }
}

#-------------------------------------------------------------------------------
# Slack Logging
#-------------------------------------------------------------------------------
Describe Start-SlackLog {
    It 'Enables Slack Logging' {
        InModuleScope PSMultiLog {
            Stop-SlackLog
            $Script:Settings['Slack'].Enabled | Should Be $false

            Start-SlackLog -Uri 'https://FakeUrl'
            $Script:Settings['Slack'].Enabled | Should Be $true
        }
    }
}

Describe Stop-SlackLog {
    It 'Disables Slack Logging' {
        InModuleScope PSMultiLog {
            Start-SlackLog -Uri 'https://FakeUrl'
            $Script:Settings['Slack'].Enabled | Should Be $true

            Stop-SlackLog
            $Script:Settings['Slack'].Enabled | Should Be $false
        }
    }
}

Describe Write-SlackLog {
    It 'Calls the Slack webhook' {
        InModuleScope PSMultiLog {
            Mock Invoke-WebRequest {}

            Start-SlackLog -Uri 'https://FakeUrl'

            Write-Log -EntryType Error -Message 'Test Error'
            Assert-MockCalled -Scope It Invoke-WebRequest -Exactly 1

            Stop-SlackLog
        }
    }
}

#-------------------------------------------------------------------------------
# Write-Log, the main event
#-------------------------------------------------------------------------------
Describe Write-Log {
    Mock -ModuleName PSMultiLog Write-FileLog {}
    Mock -ModuleName PSMultiLog Write-EventLogLog {}
    Mock -ModuleName PSMultiLog Write-EmailLog {}
    Mock -ModuleName PSMultiLog Write-HostLog {}
    Mock -ModuleName PSMultiLog Write-PassThruLog {}

    It 'Calls Write- Cmdlet for enable logging methods' {
        Write-Log -EntryType Information -Message 'Test message'
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-FileLog 0
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-EventLogLog 0
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-EmailLog 0
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-HostLog 0
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-PassThruLog 0

        Mock -ModuleNae PSMultiLog Write-Verbose {}
        Mock -ModuleName PSMultiLog Write-Host {}
        Start-EmailLog
        Start-HostLog -LogLevel Information
        Start-PassThruLog -LogLevel Information

        Write-Log -EntryType Information -Message 'Test message'
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-FileLog 0
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-EventLogLog 0
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-EmailLog -Exactly 1
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-HostLog -Exactly 1
        Assert-MockCalled -ModuleName PSMultiLog -Scope It Write-PassThruLog -Exactly 1
    }
}

#-------------------------------------------------------------------------------
# Internal Functions
#-------------------------------------------------------------------------------
Describe Get-LogLevel {
    InModuleScope PSMultiLog {
        It 'Returns expected values' {
            Get-LogLevel -EntryType 'Information' | Should Be 2
            Get-LogLevel -EntryType 'Warning' | Should Be 1
            Get-LogLevel -EntryType 'Error' | Should Be 0
            Get-LogLevel -EntryType 'None' | Should Be -1
        }

        It 'Throws on invalid EntryType' {
            { Get-LogLevel -EntryType 'Foo' } | Should Throw
        }
    }
}

Describe Format-LogMessage {
    InModuleScope PSMultiLog {
        $Timestamp = Get-Date
        $TimestampString = $Timestamp.ToString('u')
        $InfoEntry = New-Object -TypeName psobject -Property @{
            Timestamp = $Timestamp
            EntryType = 'Information'
            LogLevel  = 2
            Message   = 'Hello, World!'
            Exception = $null
            EventId   = 1000
        }

        $ErrorEntry = New-Object -TypeName psobject -Property @{
            Timestamp = $Timestamp
            EntryType = 'Error'
            LogLevel  = 0
            Message   = 'This is an error.'
            Exception = New-Object -TypeName Exception -ArgumentList 'Exception message.'
            EventId   = 1000
        }

    
        It 'Formats a message' {
            Format-LogMessage -Entry $InfoEntry | Should BeExactly "[$TimestampString] - Hello, World!"
        }

        It 'Includes Exception information' {
            Format-LogMessage -Entry $ErrorEntry -Exception | Should BeExactly "[$TimestampString] - This is an error. - Exception: Exception message."
        }

        It 'Includes type information' {
            Format-LogMessage -Entry $InfoEntry -Type | Should BeExactly "[$TimestampString] - INFO - Hello, World!"
        }

        It 'Includes type and Exception information' {
            Format-LogMessage -Entry $ErrorEntry -Type -Exception | Should BeExactly "[$TimestampString] - ERRR - This is an error. - Exception: Exception message."
        }
    }
}

Describe ConvertTo-HtmlUnorderedList {
    InModuleScope PSMultiLog {
        $Objects = @('One', 'Two', 'Three')

        It 'Performs basic formatting' {
            ConvertTo-HtmlUnorderedList -InputObject $Objects | Should BeExactly "<ul>`n<li>One</li>`n<li>Two</li>`n<li>Three</li>`n</ul>`n"
        }

        It 'Executes a ScriptBlock to perform formatting' {
            ConvertTo-HtmlUnorderedList -FormatScript { Param($s) "TEST! $s" } -InputObject $Objects | Should BeExactly "<ul>`n<li>TEST! One</li>`n<li>TEST! Two</li>`n<li>TEST! Three</li>`n</ul>`n"
        }
    }
}

Remove-Module PSMultiLog