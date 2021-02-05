<#
.DESCRIPTION
A module that provides a single entry point to output a log to multiple sources.

.EXAMPLE
C:\PS> Import-Module PSMultiLog

C:\PS> Start-FileLog -FilePath c:\ps\info.log

C:\PS> Write-Log -EntryType Information -Message "Test Log Entry"
#>

# Determine if the Write-Information Cmdlet is available.
$Script:WriteInformation = $PSVersionTable -ne $null -and $PSVersionTable.PSVersion.Major -ge 5

# Load strings file
$CurrentPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
Import-LocalizedData -BindingVariable r -FileName Strings.psd1 -BaseDirectory (Join-Path -Path $CurrentPath -ChildPath "Localized")
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
        AnsiEscColor = $false
    }

    PassThru = New-Object -TypeName psobject -Property @{
        Enabled = $false
        LogLevel = 0
    }

    Slack = New-Object -TypeName psobject -Property @{
        Enabled = $false
        LogLevel = 0
        Uri = ""
        Channel = ""
        Username = ""
        InformationIcon = ""
        WarningIcon = ""
        ErrorIcon = ""
        IncludeTimestamp = $false
        ChannelAlertLevel = -1
    }
}

#-------------------------------------------------------------------------------
# Public Cmdlets
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# File Logging
Function Start-FileLog {
    <#
    .SYNOPSIS
    Begins to log output to file.

    .DESCRIPTION
    Begins to log output to file. Only entries with a severity at or above the
    specified level will be written.

    .PARAMETER FilePath
    Specifies the path and name of the log file that will be written.

    .PARAMETER LogLevel
    Specifies the minimum log entry severity to include in the file log. The
    default value is "Error".
    
    .PARAMETER Append
    Specifies that the file at <FilePath> should not be deleted if it already
    exists. New entries will be appended to the end of the file.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Start-FileLog -FilePath c:\ps\data.log

    -----------

    This command shows the minimum requirements for enabling file logging. It
    will replace any existing log file of the same name and will only log
    entries of type "Error".

    .EXAMPLE
    C:\PS> Start-FileLog -FilePath c:\ps\data.log -Append

    -----------

    This command will leave an existing log file in place if it exists and
    append new log entries of type "Error" to the end of the file.

    .EXAMPLE
    C:\PS> Start-FileLog -FilePath c:\ps\data.log -LogLevel Warning -Append

    -----------

    This command will leave an existing log file in place if it exists and
    append new log entries of type "Warning" or type "Error" to the end of the
    file.
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

Function Stop-FileLog {
    <#
    .SYNOPSIS
    Stops writing log output to file.

    .DESCRIPTION
    Stops writing log output to file. Any log data that has already been written
    will remain.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Stop-FileLog

    -----------

    This command turns off file logging.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param ()

    Process {
        if ($PSCmdlet.ShouldProcess($Script:r.CurrentSession)) {
            $Script:Settings["File"].Enabled = $false
            $Script:Settings["File"].FilePath = $null
        }
    }
}


#-------------------------------------------------------------------------------
# E-mail Logging
Function Start-EmailLog {
    <#
    .SYNOPSIS
    Starts recording log events so that they can be e-mailed.

    .DESCRIPTION
    Starts recording log events so that they can be e-mailed. A separate Cmdlet
    (Send-EmailLog) must be issued to actually send an e-mail.

    .PARAMETER ClearEntryCache
    Specifies whether any existing recorded log entries from the cache of
    entries to be e-mailed should be removed.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Start-EmailLog

    -----------

    This command begins the recording of log events so that they can be
    e-mailed. If any entries were already in the cache, they will remain there.

    .EXAMPLE
    C:\PS> Start-EmailLog -ClearEntryCache

    -----------

    This command begins the recording of log events so that they can be e-mailed
    and clears the cache of recorded entries.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [switch]$ClearEntryCache = $false
    )

    Process {
        $Script:Settings["Email"].Enabled = $true

        if ($ClearEntryCache) {
            $Script:LogEntries = @()
        }
    }
}

Function Stop-EmailLog {
    <#
    .SYNOPSIS
    Stops the recording of log events to the e-mail cache.

    .DESCRIPTION
    Stops the recording of log events to the e-mail cache. By default, the cache
    is also cleared.

    .PARAMETER RetainEntryCache
    Specifies whether any log entries that have already been recorded should be
    kept or discarded.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Stop-EmailLog

    -----------

    This command stops the recording of log entries and clears the e-mail cache.

    .EXAMPLE
    C:\PS> Stop-EmailLog -RetainEntryCache

    -----------

    This command stops the recording of log entries but retains any that were
    already recorded.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param (
        [Parameter()]
        [switch]$RetainEntryCache = $false
    )

    Process {
        if ($PSCmdlet.ShouldProcess($Script:r.CurrentSession)) {
            $Script:Settings["Email"].Enabled = $false

            if (!$RetainEntryCache) {
                $Script:LogEntries = @()
            }
        }
    }
}

Function Send-EmailLog {
    <#
    .SYNOPSIS
    Sends an e-mail containing one or more of the log messages collected since
    e-mail logging was enabled.

    .DESCRIPTION
    Sends an e-mail containing one or more of the log messages collected since
    e-mail logging was enabled in the current session. Parameters can be used to
    control the severity of log message required to trigger sending an e-mail
    and also what levels are sent when an e-mail is triggered.

    .PARAMETER SmtpServer
    Specifies the SMTP server to use to send e-mail.

    .PARAMETER To
    Specifies one or more recipients for the e-mail.

    .PARAMETER From
    Specifies a from address to use when sending the e-mail. Note that some SMTP
    servers require this to be a valid mailbox.

    .PARAMETER Subject
    Specifies the subject of the e-mail message.

    .PARAMETER Message
    Specifies additional text to include in the e-mail message before the log
    data.

    .PARAMETER TriggerLogLevel
    Specifies the condition for sending an e-mail. A log entry at or above the
    specified level must have been recorded for an e-mail to be sent.

    .PARAMETER SendLogLevel
    Specifies what log events to include when sending an e-mail. This can be
    different than the TriggerLogLevel.

    .PARAMETER RetainEntryCache
    Specifies whether or not to keep the log entries that have been recorded.
    The default behavior is to clear them.

    .PARAMETER SendOnEmpty
    Specifies whether or not to send an e-mail if there are no log events that
    match the SendLogLevel parameter.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Send-EmailLog -SmtpServer smtp.contoso.com -To ellen@contoso.com -From info@contoso.com

    -----------

    This command shows the minimum requirements for e-mailing a log. A default
    subject will be used and no extra message will be added. Because the
    TriggerLogLevel parameter was not provided, the module will try to send an
    e-mail no matter what, using the default SendLogLevel of Error.

    .EXAMPLE
    C:\PS> Send-EmailLog -SmtpServer smtp.contoso.com -To ellen@contoso.com -From info@contoso.com -TriggerLogLevel Error -SendLogLevel Information

    -----------

    This command will cause the module only to send an e-mail if any errors were
    encountered, but when sending an e-mail it will send the full log.
    #>
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
        [string]$Subject = "",

        [Parameter()]
        [string]$Message = "",

        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$TriggerLogLevel = "Error",

        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$SendLogLevel = "Error",

        [Parameter()]
        [switch]$RetainEntryCache = $false,

        [Parameter()]
        [switch]$SendOnEmpty = $false,

        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$LogLevel = "Error"
    )

    Begin {

        $Bypass = $false

        if ($PSBoundParameters.ContainsKey("LogLevel")) {
            # Deprecated functionality.
            Write-Warning -Message ([string]::Format($Script:r.Parameter_F0_Deprecated_F1, "LogLevel", "TriggerLogLevel and SendLogLevel"))
            $TriggerLogLevel = $LogLevel
            $SendLogLevel = $LogLevel
        }

        # Start by checking if anything was logged that fits our trigger level.
        $TriggerLogLevelNumber = Get-LogLevel -EntryType $TriggerLogLevel
        if ((!$PSBoundParameters.ContainsKey("TriggerLogLevel") -and !$PSBoundParameters.ContainsKey("LogLevel")) -or ($Script:LogEntries | Where-Object -FilterScript { $_.LogLevel -le $TriggerLogLevelNumber })) {
            if (!$Subject) {
                $Subject = $Script:r.EmailLogSubject
            }
            $EmailBody = "<style>.log-entries {font-family: `"Lucida Console`", Monaco, monospace;font-size: 10pt;}</style><body>"

            if ($Message) {
                $EmailBody += "<p>$Message</p>"
            }

            $SendLogLevelNumber = Get-LogLevel -EntryType $SendLogLevel
            $Entries = $Script:LogEntries | Where-Object -FilterScript { $_.LogLevel -le $SendLogLevelNumber }
            $Empty = $false
            if ($Entries) {
                $EmailBody += "<div class=`"log-entries`">"

                $EmailBody += $Entries | ConvertTo-HtmlUnorderedList -FormatScript {
                    Param ($Entry)

                    $Line = "[$($Entry.Timestamp.ToString("u"))] - "

                    switch ($Entry.EntryType) {
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

                    $Line += ": $($Entry.Message)"

                    if ($Entry.Exception) {
                        $Line += "<ul><li>$($Script:r.Message): $($Entry.Exception.Message)</li><li>$($Script:r.Source): $($Entry.Exception.Source)</li><li>$($Script:r.StackTrace):"

                        if ($Entry.Exception.StackTrace -and $Entry.Exception.StackTrace.Count -gt 0) {
                            $Line += "<ul>"
                            foreach ($Stack in $Entry.Exception.StackTrace) {
                                $Line += "<li>$Stack</li>"
                            }
                            $Line += "</ul>"
                        }

                        $Line += "</li><li>$($Script:r.TargetSite): $($Entry.Exception.TargetSite)</li></ul>"
                    }

                    $Line
                }

                $EmailBody += "</div>"
            } else {
                $Empty = $true
                $EmailBody += "<p>$($Script:r.NoEntriesToReport)</p>"
            }

            $EmailBody += "</body>"
        } else {
            # No events occurred that would trigger us to send an e-mail.
            $Bypass = $true
        }
    }

    Process {
        if (!$Bypass -and (!$Empty -or $SendOnEmpty)) {
            Send-MailMessage -From $From -To $To -Subject $Subject -Body $EmailBody -SmtpServer $SmtpServer -BodyAsHtml
        }
    }

    End {
        if (!$Bypass -and !$RetainEntryCache) {
            $Script:LogEntries = @()
        }
    }
}


#-------------------------------------------------------------------------------
# Event Log Logging
Function Start-EventLogLog {
    <#
    .SYNOPSIS
    Starts recording log events to the Windows Event Log.

    .DESCRIPTION
    Starts recording log events to the Windows Event Log. Which log is written
    to and what source is used are configurable.

    .PARAMETER Source
    Specifies the Event Log source to record events under. If the source does
    not exist, the module will attempt to create it, but this requires
    administrative rights. You might need to run the script as an administrator
    the first time to create the source, but once it exists you should not need
    to.

    .PARAMETER LogLevel
    Specifies the minimum log entry severity to write to the Event Log. The
    default value is "Error".

    .PARAMETER LogName
    Specifies the Windows Event Log to write events to. The default is
    "Application"

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Start-EventLogLog -Source "MyScript"

    -----------

    This command shows the minimum required parameter set to enable Event Log
    logging. If the "MyScript" source does not exist in the Event Log, it will
    be created. Because the default LogLevel of "Error" is being used, only
    errors will be written to the Event Log.
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
            if (Test-EventLogSource -Source $Source) {
                # It does exist, make sure it points at the right log.
                if ((Get-LogName -Source $Source) -ne $LogName) {
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

Function Stop-EventLogLog {
    <#
    .SYNOPSIS
    Stops writing log output to the Windows Event Log.

    .DESCRIPTION
    Stops writing log output to the Windows Event Log.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Stop-EventLogLog

    -----------

    This command turns off Event Log logging.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param ()

    Process {
        if ($PSCmdlet.ShouldProcess($Script:r.CurrentSession)) {
            $Script:Settings["EventLog"].Enabled = $false
            $Script:Settings["EventLog"].LogName = $null
            $Script:Settings["EventLog"].Source = $null
        }
    }
}


#-------------------------------------------------------------------------------
# Host Logging
Function Start-HostLog {
    <#
    .SYNOPSIS
    Turns on writing formatted log events to the host display.

    .DESCRIPTION
    Starts writing formatted log events to the host display. Includes timestamp,
    color-coded entry type, and message text.

    .PARAMETER LogLevel
    Specifies the minimum log entry severity to write to the host. The default
    value is "Error".

    .PARAMETER AnsiEscColor
    Enables ANSI escape color.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Start-HostLog

    -----------

    This command turns on host logging.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$LogLevel = "Error",

        [Parameter()]
        [ValidateSet($true, $false)]
        [switch]$AnsiEscColor = $false
    )

    Process {
        $Script:Settings["Host"].Enabled = $true
        $Script:Settings["Host"].LogLevel = Get-LogLevel -EntryType $LogLevel
        $Script:Settings["Host"].AnsiEscColor = $AnsiEscColor
    }
}

Function Stop-HostLog {
    <#
    .SYNOPSIS
    Turns off writing log messages to the host display.

    .DESCRIPTION
    Turns off writing log messages to the host display.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Stop-HostLog

    -----------

    This command turns off host logging.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param ()

    Process {
        if ($PSCmdlet.ShouldProcess($Script:r.CurrentSession)) {
            $Script:Settings["Host"].Enabled = $false
        }
    }
}


#-------------------------------------------------------------------------------
# "Pass Thru" Logging
Function Start-PassThruLog {
    <#
    .SYNOPSIS
    Turns on "Pass Thru" display of log events by writing them to other streams.

    .DESCRIPTION
    Turns on "Pass Thru" display of log events by writing them to other streams.
    The streams used are:
        - Information - Verbose Stream
        - Warning - Warning Stream
        - Error - Error stream

    .PARAMETER LogLevel
    Specifies the minimum log entry severity to write to another stream. The
    default value is "Error".

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Start-PassThruLog

    -----------

    This command turns on "Pass Thru" logging.
    #>
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

Function Stop-PassThruLog {
    <#
    .SYNOPSIS
    Turns off "Pass Thru" logging.

    .DESCRIPTION
    Turns off "Pass Thru" logging.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Stop-PassThruLog

    -----------

    This command turns off "Pass Thru" logging.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param ()

    Process {
        if ($PSCmdlet.ShouldProcess($Script:r.CurrentSession)) {
            $Script:Settings["PassThru"].Enabled = $false
        }
    }
}


#-------------------------------------------------------------------------------
# Slack Channel Logging
Function Start-SlackLog {
    <#
    .SYNOPSIS
    Turns on Slack Channel logging.

    .DESCRIPTION
    Turns on Slack Channel logging using Slack custom webhook integrations.

    .PARAMETER LogLevel
    Specifies the minimum log entry severity to send to Slack. The default value
    is "Error".

    .PARAMETER Uri
    Specifies the webhook URI to use when sending events to Slack.

    .PARAMETER Channel
    Specifies the name of a Slack channel to post messages to. Do not include
    the hash (#) at the beginning of the channel name.

    .PARAMETER Username
    Specifies a custom username to display on messages sent from this process.

    .PARAMETER InformationIcon
    Specifies the name of an emoji icon to use for Information log messages. Do
    not surround the emoji name in colons (:).

    .PARAMETER WarningIcon
    Specifies the name of an emoji icon to use for Warning log messages. Do not
    surround the emoji name in colons (:).

    .PARAMETER ErrorIcon
    Specifies the name of an emoji icon to use for Error log messages. Do not
    surround the emoji name in colons (:).

    .PARAMETER IncludeTimestamp
    When included, this switch specifies that a timestamp should be written to
    the body of the message, instead of just relying on the time Slack received
    the entry.

    .PARAMETER ChannelAlertLevel
    Specifies the minimum log entry severity to include the @channel tag in.
    This tag will cause an alert to be sent to all members of the channel. The
    default value is for this to be disabled.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Start-SlackLog -Uri "https://hooks.slack.com/services/ABC123"

    ----------

    This command enables logging to Slack at the specified integration URL,
    using the default channel and username that were set up with the integration
    and the default icons for the different log entry levels.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$LogLevel = "Error",

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [string]$Channel,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$InformationIcon = "speech_balloon",

        [Parameter()]
        [string]$WarningIcon = "warning",

        [Parameter()]
        [string]$ErrorIcon = "rotating_light",

        [Parameter()]
        [switch]$IncludeTimestamp,

        [Parameter()]
        [ValidateSet("Information", "Warning", "Error", "None")]
        [string]$ChannelAlertLevel = "None"
    )

    Process {
        $Script:Settings["Slack"].Enabled = $true
        $Script:Settings["Slack"].LogLevel = Get-LogLevel -EntryType $LogLevel
        $Script:Settings["Slack"].Uri = $Uri
        $Script:Settings["Slack"].InformationIcon = $InformationIcon
        $Script:Settings["Slack"].WarningIcon = $WarningIcon
        $Script:Settings["Slack"].ErrorIcon = $ErrorIcon
        $Script:Settings["Slack"].ChannelAlertLevel = Get-LogLevel -EntryType $ChannelAlertLevel

        if ($Channel) {
            $Script:Settings["Slack"].Channel = $Channel
        } else {
            $Script:Settings["Slack"].Channel = ""
        }

        if ($Username) {
            $Script:Settings["Slack"].Username = $Username
        } else {
            $Script:Settings["Slack"].Username = ""
        }

        if ($IncludeTimestamp) {
            $Script:Settings["Slack"].IncludeTimestamp = $true
        } else {
            $Script:Settings["Slack"].IncludeTimestamp = $false
        }
    }
}

Function Stop-SlackLog {
    <#
    .SYNOPSIS
    Turns off Slack Channel logging.

    .DESCRIPTION
    Turns off Slack Channel logging.

    .OUTPUTS
    None.

    .Example
    C:\PS> Stop-SlackLog

    ----------

    This command turns off Slack Channel logging.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param ()

    Process {
        if ($PSCmdlet.ShouldProcess($Script:r.CurrentSession)) {
            $Script:Settings["Slack"].Enabled = $false
        }
    }
}


#-------------------------------------------------------------------------------
# Main logging method
Function Write-Log {
    <#
    .SYNOPSIS
    Writes a log entry to whichever output formats are currently enabled.
    
    .DESCRIPTION
    Writes a log entry to whichever output formats are currently enabled.

    .PARAMETER EntryType
    Specifies what type of log entry to write.

    .PARAMETER Message
    Specifies a descriptive message for the log entry. This is separate from
    the message that is attached to any exception that might be included in the
    log event.

    .PARAMETER Exception
    For error type entries, includes information about an actual exception that
    occurred.

    .PARAMETER EventId
    For Event Log entries, specifies the Event Id to write in the Event Log. The
    default is 1000.

    .OUTPUTS
    None.

    .EXAMPLE
    C:\PS> Write-Log -EntryType Information -Message "This is a sample log message."

    -----------

    This command writes a simple log message.

    .EXAMPLE
    C:\PS> Write-Log -EntryType Error -Message "An exception occurred." -Exception $_.Exception

    -----------

    This command, which might be used in a try/catch block, logs an error,
    including data about the exception that was caught.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$EntryType,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [System.Exception]$Exception = $null,

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

        # Slack channel logging.
        if ($Script:Settings["Slack"].Enabled -and $NewEntry.LogLevel -le $Script:Settings["Slack"].LogLevel) {
            Write-SlackLog -Entry $NewEntry
        }
    }
}


#-------------------------------------------------------------------------------
# Internal Cmdlets
#-------------------------------------------------------------------------------
Function Get-LogLevel {
    <#
    .SYNOPSIS
    Gets the integer representation of the specified entry type.

    .DESCRIPTION
    Gets the integer representation of the specified entry type. Used for
    filtering log output.

    .PARAMETER EntryType
    Specifies the entry type to evaluate.

    .OUTPUTS
    Integer.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Information", "Warning", "Error", "None")]
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

            "None" {
                return -1
            }
        }
    }
}

Function Format-LogMessage {
    <#
    .SYNOPSIS
    Formats a log entry for output and returns the formatted string.

    .DESCRIPTION
    Formats a log entry for output and returns the formatted string. Used by the
    File and PassThru logging methods.

    .PARAMETER Entry
    Specifies the log entry to format.

    .PARAMETER Type
    Specifies whether or not to include the log entry type in the formatted
    string.

    .PARAMETER Exception
    Specifies whether or not to include information about any exceptions
    included in the entry in the formatted string.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
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

Function ConvertTo-HtmlUnorderedList {
    <#
    .SYNOPSIS
    Builds an HTML UnorderedList from the supplied input and returns its string.

    .DESCRIPTION
    Builds an HTML UnorderedList from the supplied input and returns its string.

    .PARAMETER FormatScript
    Specifies a script block to invoke for each object passed into the Cmdlet.

    .PARAMETER InputObject
    Specifies one or more objects to write to the unordered list.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter()]

        [scriptblock]$FormatScript = $null,

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

Function Write-FileLog {
    <#
    .SYNOPSIS
    Writes a log message to a file.

    .DESCRIPTION
    Writes a log message to a file.

    .PARAMETER Entry
    Specifies the log entry to write.

    .PARAMETER FilePath
    Specifies the file to write the log entry to.

    .OUTPUTS
    None.
    #>
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
    <#
    .SYNOPSIS
    Creates a new Event Log object from a log message.

    .DESCRIPTION
    Creates a new Event Log object from a log message.

    .PARAMETER Entry
    Specifies the log entry which will be used to create the Event Log object.

    .PARAMETER LogName
    Specifies which log in the Windows Event Log to write to.

    .PARAMETER Source
    Specifies the source to use when creating the Event Log object.

    .OUTPUTS
    None.
    #>
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
    <#
    .SYNOPSIS
    Stores a log entry in the cache used when e-mailing log data.

    .DESCRIPTION
    Stores a log entry in the cache used when e-mailing log data.

    .PARAMETER Entry
    Specifies the log entry to record.

    .OUTPUTS
    None.
    #>
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
    <#
    .SYNOPSIS
    Writes a log entry to the host.

    .DESCRIPTION
    Writes a log entry to the host.

    .PARAMETER Entry
    Specifies the log entry to write to the host.

    .OUTPUTS
    None.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry
    )

    Process {
    $SGRESC="$([char]27)"
    $CLEAR="$SGRESC[0m"

        Write-Host -Object "[$($Entry.Timestamp.ToString("u"))] - " -NoNewline

        switch ($Entry.EntryType) {
            "Information" {
                if ($Script:Settings["Host"].AnsiEscColor) {
                    $CYAN="$SGRESC[96m"
                    Write-Host -Object ($CYAN + $Script:r.Info + $CLEAR) -NoNewline
                } else {
                    Write-Host -Object $Script:r.Info -ForegroundColor Cyan -NoNewline
                }
            }

            "Warning" {
                if ($Script:Settings["Host"].AnsiEscColor) {
                    $YELLOW="$SGRESC[33m"
                    Write-Host -Object ($YELLOW + $Script:r.Warn + $CLEAR) -NoNewline
                } else {
                    Write-Host -Object $Script:r.Warn -ForegroundColor Yellow -NoNewline
                }
            }

            "Error" {
                if ($Script:Settings["Host"].AnsiEscColor) {
                    $RED="$SGRESC[31m"
                    Write-Host -Object ($RED + $Script:r.Errr + $CLEAR) -NoNewline
                } else {
                    Write-Host -Object $Script:r.Errr -ForegroundColor Red -NoNewline
                }
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
    <#
    .SYNOPSIS
    Writes a log entry to one of the native PowerShell Streams.

    .DESCRIPTION
    Writes a log entry to one of the native PowerShell Streams.

    .PARAMETER Entry
    Specifies the log entry to write.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry
    )

    Process {
        switch ($Entry.EntryType) {
            "Information" {
                # Use the Write-Information Cmdlet introduced in PowerShell
                # version 5 if available. Otherwise Write-Verbose
                if ($Script:WriteInformation) {
                    Write-Information -MessageData (Format-LogMessage -Entry $Entry)
                } else {
                    Write-Verbose -Message (Format-LogMessage -Entry $Entry)
                }
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

Function Write-SlackLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$Entry
    )

    Process {
        $Message = ""

        if ($Entry.LogLevel -le $Script:Settings["Slack"].ChannelAlertLevel) {
            $Message += "<!channel>: "
        }

        if ($Script:Settings["Slack"].IncludeTimestamp) {
            $Message += "[$($Entry.Timestamp.ToString("u"))] - " | ConvertTo-SlackEncoding
        }

        $Message += $Entry.Message | ConvertTo-SlackEncoding

        if ($Entry.Exception) {
            $Message += "`n`n$($Script:r.ExceptionInformation)" + `
            "`n$($Script:r.Message): $($Entry.Exception.Message)" + `
            "`n$($Script:r.Source): $($Entry.Exception.Source)" + `
            "`n$($Script:r.StackTrace): $($Entry.Exception.StackTrace)" + `
            "`n$($Script:r.TargetSite): $($Entry.Exception.TargetSite)" | ConvertTo-SlackEncoding
        }

        switch ($Entry.EntryType) {
            "Information" {
                $Icon = $Script:Settings["Slack"].InformationIcon | ConvertTo-SlackEncoding
            }

            "Warning" {
                $Icon = $Script:Settings["Slack"].WarningIcon | ConvertTo-SlackEncoding
            }

            "Error" {
                $Icon = $Script:Settings["Slack"].ErrorIcon | ConvertTo-SlackEncoding
            }
        }

        $Elements = @()
        $Elements += '"text":"' + $Message + '"'
        $Elements += '"icon_emoji":":' + $Icon + ':"'

        if ($Script:Settings["Slack"].Channel) {
            $Elements += '"channel":"#' + ($Script:Settings["Slack"].Channel | ConvertTo-SlackEncoding) + '"'
        }

        if ($Script:Settings["Slack"].Username) {
            $Elements += '"username":"' + ($Script:Settings["Slack"].Username | ConvertTo-SlackEncoding) + '"'
        }

        $Body = "payload={$([string]::Join(',', $Elements))}"

        try {
            Invoke-WebRequest -Uri $Script:Settings["Slack"].Uri -Method Post -Body $Body -ErrorAction Stop | Out-Null
        } catch {
            Write-Error -Exception $_.Exception -Message "Exception while posting log to Slack. Message is '$($_.Exception.Message)'."
        }
    }
}


Function ConvertTo-SlackEncoding {
    <#
    .SYNOPSIS
    Encodes special characters for inclusion into a slack webhook request.

    .DESCRIPTION
    Encodes special characters for inclusion into a slack webhook request.

    .PARAMETER InputString
    Specifies the string to encode.

    .OUTPUTS
    String. The encoded value.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$InputString
    )

    Process {
        return $InputString.Replace('"', '\"').Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    }
}




Function ConvertTo-HtmlUnorderedList {
    <#
    .SYNOPSIS
    Builds an HTML UnorderedList from the supplied input and returns its string.

    .DESCRIPTION
    Builds an HTML UnorderedList from the supplied input and returns its string.

    .PARAMETER FormatScript
    Specifies a script block to invoke for each object passed into the Cmdlet.

    .PARAMETER InputObject
    Specifies one or more objects to write to the unordered list.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter()]

        [scriptblock]$FormatScript = $null,

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
                $OutputText += Invoke-Command -ScriptBlock $FormatScript -ArgumentList $_
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

Function Test-EventLogSource {
    [CmdletBinding()]
    [OutputType([bool])]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    Process {
        return [System.Diagnostics.EventLog]::SourceExists($Source)
    }
}

Function Get-LogName {
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    Process {
        return [System.Diagnostics.EventLog]::LogNameFromSourceName($Source, ".")
    }
}


#-------------------------------------------------------------------------------
# Deprecated Cmdlets
#-------------------------------------------------------------------------------
Function Enable-FileLog {
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
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Start-FileLog"))
        Start-FileLog -FilePath $FilePath -LogLevel $LogLevel -Append:$Append
    }
}

Function Disable-FileLog {
    [CmdletBinding()]
    Param ()

    Process {
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Stop-FileLog"))
        Stop-FileLog
    }   
}

Function Enable-EmailLog {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [switch]$ClearEntryCache
    )

    Process {
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Start-EmailLog"))
        Start-EmailLog -ClearEntryCache:$ClearEntryCache
    }
}

Function Disable-EmailLog {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [switch]$RetainEntryCache
    )

    Process {
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Stop-EmailLog"))
        Stop-EmailLog
    }
}

Function Enable-EventLogLog {
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
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Start-EventLogLog"))
        Start-EventLogLog -Source $Source -LogLevel $LogLevel -LogName $LogName
    }
}

Function Disable-EventLogLog {
    [CmdletBinding()]
    Param ()

    Process {
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Stop-EventLogLog"))
        Stop-EventLogLog
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
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Start-HostLog"))
        Enable-HostlLog -LogLevel $LogLevel
    }
}

Function Disable-HostLog {
    [CmdletBinding()]
    Param ()

    Process {
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Stop-HostLog"))
        Stop-HostLog
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
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Start-PassThruLog"))
        Start-PassThruLog -LogLevel $LogLevel
    }
}

Function Disable-PassThruLog {
    [CmdletBinding()]
    Param ()

    Process {
        Write-Warning -Message ([string]::Format($Script:r.CmdletDeprecated_F0, "Stop-PassThruLog"))
        Stop-PassThruLog
    }
}