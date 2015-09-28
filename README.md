# PSMultiLog
PSMultiLog is a multi-target logging module to simplify and centralize logging in your code. At the beginning of your code, turn on the log targets you want to use, and from the on just call the `Write-Log` Cmdlet to simultaneously write to all active targets.

## Log targets
The PSMultiLog module supports the following log targets:

- File
- Host (great for debugging, or when you're first building a script)
- PassThru (will write to the verbose, warning, and error streams)
- Event Log
- Email (log events are collected, and then the `Send-EmailLog` Cmdlet is used to send the actual e-mail)

## Compatibility
The PSMultiLog module is compatible with PowerShell v2.0 and up.

## Installation
Copy the module into a folder in your PowerShell Module Path. You can check `$env:PSModulePath` in a PowerShell session if unsure what paths are included, but starting in PowerShell v4.0 the standard is `C:\Program Files\WindowsPowerShell\Modules`. Don't put the code directly into the Modules folder, it must be in a subfolder named `PSMultiLog`.

## Usage
Here is a simple example of using multiple log targets. Note that when you enable a log target, you also specify what severity log entries to write to it. In the example below, we are everything to a log file, but only errors to the event log.

```powershell
# Import the module.
Import-Module PSMultiLog

# Turn on desired targets.
Start-FileLog -FilePath c:\ps\info.log -LogLevel Information # Log everything.
Start-EventLogLog -Source "SampleScript" # The default value for LogLevel is "Error".

# Write log entries.
Write-Log -EntryType Information -Message "This will only get logged to file."
Write-Log -EntryType Warning -Message "This will only get logged to file."
Write-Log -EntryType Error -Message "This will get logged both to file and to the Event Log."

# Turn off targets (this is sort of optional, since it won't matter once the script exits).
Stop-FileLog
Stop-EventLogLog
```
