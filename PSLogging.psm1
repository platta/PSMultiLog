<#
.DESCRIPTION
A module that provides a single entry point to output a log to multiple sources.

.EXAMPLE
C:\PS> Import-Module PSLogging

C:\PS> Enable-FileLog -FilePath c:\ps\info.log

C:\PS> Write-Log -EntryType Information -Message "Test Log Entry"
#>

# Load strings file
$CurrentPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
Import-LocalizedData -BindingVariable r -FileName Strings.psd1 -BaseDirectory (Join-Path -Path $CurrentPath -ChildPath "I18n")
$Script:r = $r

# Array to hold log entries that will be e-mailed when using e-mail logging.
$Script:LogEntries = @()

# Settings for each of the log types.
$Script:Settings = @{
    File = New-Object -TypeName psobject -Property @{
        Enabled = $false
        LogLevel = 0
        FilePath = $null
    }

    Email = New-Object -TypeName psobject -Property @{
        Enabled = $false
    }

    EventLog = New-Object -TypeName psobject -Property @{
        Enabled = $false
        LogLevel = 0
        LogName = $null
        Source = $null
    }

    Host = New-Object -TypeName psobject -Property @{
        Enabled = $false
        LogLevel = 0
    }

    PassThru = New-Object -TypeName psobject -Property @{
        Enabled = $false
        LogLevel = 0
    }
}

Function Get-LogLevel {
    <#
    .SYNOPSIS
    Gets the integer representation of the specified entry type.

    .DESCRIPTION
    Gets the integer representation of the specified entry type.
    Used for filtering log output.

    .PARAMETER EntryType
    Specifies the entry type to evaluate.

    .OUTPUTS
    Integer.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$EntryType
    )

    Process {
        switch ($EntryType) {
            "Information" {
                return 2
            }

            "Warning" {
                return 1
            }

            "Error" {
                return 0
            }
        }
    }
}

Function Enable-FileLog {
    <#
    .SYNOPSIS
    Enables log output to file.

    .DESCRIPTION
    Enables log output to file. Only entries with a severity at or above the specified level will be written.

    .PARAMETER FilePath
    Specifies the path and name of the log file that will be written.

    .PARAMETER LogLevel
    Specifies the minimum log entry severity to include in the file log. The default value is "Error".
    
    .PARAMETER Append
    Specifies that the file at <FilePath> should not be deleted if it already exists. New entries will be appended to the end of the file.

    .EXAMPLE
    C:\PS> Enable-FileLog -FilePath c:\ps\data.log

    -----------

    This command shows the minimum requirements for enabling file logging. It will replace any existing log file of the same name and will only log entries of type "Error".

    .EXAMPLE
    C:\PS> Enable-FileLog -FilePath c:\ps\data.log -Append

    -----------

    This command will leave an existing log file in place if it exists and append new log entries of type "Error" to the end of the file.

    .EXAMPLE
    C:\PS> Enable-FileLog -FilePath c:\ps\data.log -LogLevel Warning -Append

    -----------

    This command will leave an existing log file in place if it exists and append new log entries of type "Warning" or type "Error" to the end of the file.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$LogLevel = "Error",

        [Parameter()]
        [switch]$Append
    )

    Process {
        $Script:Settings["File"].Enabled = $false

        # First attempt to remove existing file if necessary
        if (!$Append -and (Test-Path -LiteralPath $FilePath)) {
            try {
                Remove-Item -LiteralPath $FilePath -Force -ErrorAction Stop
            } catch {
                Write-Error -Exception $_.Exception -Message $Script:r.FileLogUnableToRemoveExistingFile
                return
            }
        }

        # Create file if necessary
        if (!(Test-Path -LiteralPath $FilePath)) {
            try {
                New-Item -Path $FilePath -ItemType File -Force -ErrorAction Stop | Out-Null
            } catch {
                Write-Error -Exception $_.Exception -Message $Script:r.FileLogUnableToCreateFile
                return
            }
        }

        $Script:Settings["File"].Enabled = $true
        $Script:Settings["File"].LogLevel = Get-LogLevel -EntryType $LogLevel
        $Script:Settings["File"].FilePath = $FilePath
    }
}

Function Disable-FileLog {
    <#
    .SYNOPSIS
    Disables log output to file.

    .DESCRIPTION
    Disables log output to file. Any log data that has already been written will remain.

    .EXAMPLE
    C:\PS> Disable-FileLog

    -----------

    This command disables file logging.
    #>
    [CmdletBinding()]
    Param ()

    Process {
        $Script:Settings["File"].Enabled = $false
        $Script:Settings["File"].FilePath = $null
    }
}

Function Enable-EmailLog {
    <#
    .SYNOPSIS
    Enables the recording of log events so that they can be e-mailed.

    .DESCRIPTION
    Enables the recording of log events so that they can be e-mailed. A separate command must be issued to actually send an e-mail.

    .PARAMETER ClearEntryCache
    Specifies whether any recorded log entries from the cache of entries to be e-mailed should be removed.

    .EXAMPLE
    C:\PS> Enable-EmailLog

    -----------

    This command enables the recording of log events so that they can be e-mailed. If any entries were already in the cache, they will remain there.

    .EXAMPLE
    C:\PS> Enable-EmailLog -ClearEntryCache

    -----------

    This command enables the recording of log events so that they can be e-mailed and clears the cache of recorded entries
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [switch]$ClearEntryCache
    )

    Process {
        $Script:Settings["Email"].Enabled = $true

        if ($ClearEntryCache) {
            $Script:LogEntries = @()
        }
    }
}

Function Disable-EmailLog {
    <#
    .SYNOPSIS
    Disables the recording of log events to the e-mail cache.

    .DESCRIPTION
    Disables the recording of log events to the e-mail cache. By default, the cache is also cleared.

    .PARAMETER RetainEntryCache
    Specifies whether any log entries that have already been recorded should be kept or discarded.

    .EXAMPLE
    C:\PS> Disable-EmailLog

    -----------

    This command disables the recording of log entries and clears the e-mail cache.

    .EXAMPLE
    C:\PS> Disable-EmailLog -RetainEntryCache

    -----------

    This command disables the recording of log entries but retains any that were already recorded.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [switch]$RetainEntryCache
    )

    Process {
        $Script:Settings["Email"].Enabled = $false

        if (!$RetainEntryCache) {
            $Script:LogEntries = @()
        }
    }
}

Function Enable-EventLogLog {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Source

    .PARAMETER LogLevel

    .PARAMETER LogName

    .EXAMPLE
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$LogLevel = "Error",

        [Parameter()]
        [string]$LogName = "Application"
    )

    Process {
        $Script:Settings["EventLog"].Enabled = $false

        # Check if the source exists.
        try {
            if ([System.Diagnostics.EventLog]::SourceExists($Source)) {
                # It does exist, make sure it points at the right log.
                if ([System.Diagnostics.EventLog]::LogNameFromSourceName($Source, ".") -ne $LogName) {
                    # Source exists but points to a different log. Not good!
                    Write-Error -Message $Script:r.EventLogLogSourceInWrongLog
                    return
                }
            } else {
                # Source does not exist, try to create it.
                try {
                    New-EventLog -LogName $LogName -Source $Source
                } catch [System.Exception] {
                    Write-Error -Exception $_.Exception -Message $Script:r.EventLogLogUnableToCreateLogOrSource
                    return
                }
            }
        } catch [System.Exception] {
            Write-Error -Exception $_.Exception -Message $Script:r.EventLogLogUnableToReadLogSources
            return
        }

        $Script:Settings["EventLog"].Enabled = $true
        $Script:Settings["EventLog"].LogLevel = Get-LogLevel -EntryType $LogLevel
        $Script:Settings["EventLog"].LogName = $LogName
        $Script:Settings["EventLog"].Source = $Source
    }
}

Function Disable-EventLogLog {
    [CmdletBinding()]
    Param ()

    Process {
        $Script:Settings["EventLog"].Enabled = $false
        $Script:Settings["EventLog"].LogName = $null
        $Script:Settings["EventLog"].Source = $null
    }
}

Function Enable-HostLog {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$LogLevel = "Error"
    )

    Process {
        $Script:Settings["Host"].Enabled = $true
        $Script:Settings["Host"].LogLevel = Get-LogLevel -EntryType $LogLevel
    }
}

Function Disable-HostLog {
    [CmdletBinding()]
    Param ()

    Process {
        $Script:Settings["Host"].Enabled = $false
    }
}

Function Enable-PassThruLog {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$LogLevel = "Error"
    )

    Process {
        $Script:Settings["PassThru"].Enabled = $true
        $Script:Settings["PassThru"].LogLevel = Get-LogLevel -EntryType $LogLevel
    }
}

Function Disable-PassThruLog {
    [CmdletBinding()]
    Param ()

    Process {
        $Script:Settings["PassThru"].Enabled = $false
    }
}

Function Write-Log {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$EntryType,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [System.Exception]$Exception,

        [Parameter()]
        [int]$EventId = 1000
    )

    Process {
        $NewEntry = New-Object -TypeName psobject -Property @{
            Timestamp = Get-Date
            EntryType = $EntryType
            LogLevel = Get-LogLevel -EntryType $EntryType
            Message = $Message
            Exception = $Exception
            EventId = $EventId
        }

        # Log to File
        if ($Script:Settings["File"].Enabled -and $NewEntry.LogLevel -le $Script:Settings["File"].LogLevel) {
            Write-FileLog -Entry $NewEntry -FilePath $Script:Settings["File"].FilePath
        }

        # Log to EventLog
        if ($Script:Settings["EventLog"].Enabled -and $NewEntry.LogLevel -le $Script:Settings["EventLog"].LogLevel) {
            Write-EventLogLog -Entry $NewEntry -LogName $Script:Settings["EventLog"].LogName -Source $Script:Settings["EventLog"].Source
        }

        # Record entry for e-mailing later
        if ($Script:Settings["Email"].Enabled) {
            Write-EmailLog -Entry $NewEntry
        }

        # Write to host
        if ($Script:Settings["Host"].Enabled -and $NewEntry.LogLevel -le $Script:Settings["Host"].LogLevel) {
            Write-HostLog -Entry $NewEntry
        }

        # Pass through to verbose/warning/error streams
        if ($Script:Settings["PassThru"].Enabled -and $NewEntry.LogLevel -le $Script:Settings["PassThru"].LogLevel) {
            Write-PassThruLog -Entry $NewEntry
        }
    }
}

Function Format-LogMessage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry,

        [Parameter()]
        [switch]$Type,

        [Parameter()]
        [switch]$Exception
    )

    Process {
        $ReturnString = "[$($Entry.Timestamp.ToString("u"))]"

        if ($Type) {
            $TypeString = ""
            switch($Entry.EntryType) {
                "Information" {
                    $TypeString = $Script:r.Info
                }

                "Warning" {
                    $TypeString = $Script:r.Warn
                }

                "Error" {
                    $TypeString = $Script:r.Errr
                }
            }

            $ReturnString += " - $TypeString"
        }

        $ReturnString += " - $($Entry.Message)"

        if ($Exception -and $Entry.Exception) {
            $ReturnString += " - $($Script:r.Exception): $($Entry.Exception.Message)"
        }

        return $ReturnString
    }
}

Function Write-FileLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    Process {
        Format-LogMessage -Entry $Entry -Type -Exception | Out-File -FilePath $FilePath -Append -Encoding ascii
    }
}

Function Write-EventLogLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry,

        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    Process {
        $EventLogMessage = $Entry.Message

        if ($Entry.Exception) {
            $EventLogMessage += "`n`n$($Script:r.ExceptionInformation)" + `
            "`n$($Script:r.Message): $($Entry.Exception.Message)" + `
            "`n$($Script:r.Source): $($Entry.Exception.Source)" + `
            "`n$($Script:r.StackTrace): $($Entry.Exception.StackTrace)" + `
            "`n$($Script:r.TargetSite): $($Entry.Exception.TargetSite)"
        }

        Write-EventLog -LogName $LogName -Source $Source -EntryType $Entry.EntryType -EventId $Entry.EventId -Message $EventLogMessage
    }
}

Function Write-EmailLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry
    )

    Process {
        $Script:LogEntries += $Entry
    }
}

Function Write-HostLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry
    )

    Process {
        Write-Host -Object "[$($Entry.Timestamp.ToString("u"))] - " -NoNewline

        switch ($Entry.EntryType) {
            "Information" {
                Write-Host -Object $Script:r.Info -ForegroundColor Cyan -NoNewline
            }

            "Warning" {
                Write-Host -Object $Script:r.Warn -ForegroundColor Yellow -NoNewline
            }

            "Error" {
                Write-Host -Object $Script:r.Errr -ForegroundColor Red -NoNewline
            }
        }

        $Message = $Entry.Message
        
        if ($Entry.Exception) {
            $Message += " - $($Script:r.Exception): $($Entry.Exception.Message)"
        }

        Write-Host -Object " - $Message"
    }
}

Function Write-PassThruLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry
    )

    Process {
        switch ($Entry.EntryType) {
            "Information" {
                Write-Verbose -Message (Format-LogMessage -Entry $Entry)
            }

            "Warning" {
                Write-Warning -Message (Format-LogMessage -Entry $Entry)
            }

            "Error" {
                if ($Entry.Exception) {
                    Write-Error -Message (Format-LogMessage -Entry $Entry) -Exception $Entry.Exception
                } else {
                    Write-Error -Message (Format-LogMessage -Entry $Entry)
                }
            }
        }
    }
}


Function ConvertTo-HtmlUnorderedList {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [scriptblock]$FormatScript,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        $InputObject
    )

    Begin {
        $OutputText = "<ul>`n"
    }

    Process {
        @($InputObject) | ForEach-Object -Process {
            $OutputText += "<li>"

            if ($FormatScript) {
                $OutputText += Invoke-Command -ScriptBlock $FormatScript
            } else {
                $OutputText += $_
            }

            $OutputText += "</li>`n"
        }
    }

    End {
        $OutputText += "</ul>`n"
        $OutputText
    }
}

Function Send-EmailLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$SmtpServer,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$To,

        [Parameter(Mandatory = $true)]
        [string]$From,

        [Parameter()]
        [string]$Subject,

        [Parameter()]
        [string]$Message,

        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$LogLevel,

        [Parameter()]
        [switch]$RetainEntryCache,

        [Parameter()]
        [switch]$SendOnEmpty
    )

    Begin {
        if (!$Subject) {
            $Subject = $Script:r.EmailLogSubject
        }
        $EmailBody = "<style>.log-entries {font-family: `"Lucida Console`", Monaco, monospace;font-size: 10pt;}</style><body>"

        if ($Message) {
            $EmailBody += "<p>$Message</p>"
        }

        $LogLevelNumber = Get-LogLevel -EntryType $LogLevel
        $Entries = $Script:LogEntries | Where-Object -FilterScript { $_.LogLevel -le $LogLevelNumber }
        $Empty = $false
        if ($Entries) {
            $EmailBody += "<div class=`"log-entries`">"

            $EmailBody += $Entries | ConvertTo-HtmlUnorderedList -FormatScript {
                $Line = "[$($_.Timestamp.ToString("u"))] - "

                switch ($_.EntryType) {
                    "Information" {
                        $Line += "<span style=`"color: Teal`">$($Script:r.Info)</span>"
                    }

                    "Warning" {
                        $Line += "<span style=`"color: GoldenRod`">$($Script:r.Warn)</span>"
                    }

                    "Error" {
                        $Line += "<span style=`"color: Red`">$($Script:r.Errr)</span>"
                    }
                }

                $Line += ": $($_.Message)"

                if ($_.Exception) {
                    $Line += "<ul><li>$($Script:r.Message): $($_.Exception.Message)</li><li>$($Script:r.Source): $($_.Exception.Source)</li><li>$($Script:r.StackTrace):"

                    if ($_.Exception.StackTrace -and $_.Exception.StackTrace.Count -gt 0) {
                        $Line += "<ul>"
                        foreach ($Stack in $_.Exception.StackTrace) {
                            $Line += "<li>$Stack</li>"
                        }
                        $Line += "</ul>"
                    }

                    $Line += "</li><li>$($Script:r.TargetSite): $($_.Exception.TargetSite)</li></ul>"
                }

                $Line
            }

            $EmailBody += "</div>"
        } else {
            $Empty = $true
            $EmailBody += "<p>$($Script:r.NoEntriesToReport)</p>"
        }

        $EmailBody += "</body>"
    }

    Process {
        if (!$Empty -or $SendOnEmpty) {
            Send-MailMessage -From $From -To $To -Subject $Subject -Body $EmailBody -SmtpServer $SmtpServer -BodyAsHtml
        }
    }

    End {
        if (!$RetainEntryCache) {
            $Script:LogEntries = @()
        }
    }
}

Export-ModuleMember -Function Enable-*, Disable-*, Write-Log, Send-EmailLog