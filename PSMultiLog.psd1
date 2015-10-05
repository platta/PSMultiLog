<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2015 v4.2.82
	 Created on:   	4/11/2015 5:32 PM
	 Created by:   	Adam Platt 
	 Organization: 	 
	 Filename:     	PSMultiLog.psd1
	 -------------------------------------------------------------------------
	 Module Manifest
	-------------------------------------------------------------------------
	 Module Name: PSMultiLog
	===========================================================================
#>

@{

# Script module or binary module file associated with this manifest
RootModule = 'PSMultiLog.psm1'

# Version number of this module.
ModuleVersion = '1.0.4'

# ID used to uniquely identify this module
GUID = '6792caca-e1b3-4a6b-b1bc-979f9935e95f'

# Author of this module
Author = 'Adam Platt'

# Company or vendor of this module
CompanyName = ' '

# Copyright statement for this module
Copyright = '(c) 2015. All rights reserved.'

# Description of the functionality provided by this module
Description = 'The PSMultiLog module is designed to simultaneously write log output to multiple log targets. Supported targets include logging to a file, to the Windows Event Log, and sending an e-mail. The module is used by turning on the desired log targets and then calling the Write-Log Cmdlet.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Name of the Windows PowerShell host required by this module
PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = ''

# Minimum version of the .NET Framework required by this module
DotNetFrameworkVersion = '2.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '2.0.50727'

# Processor architecture (None, X86, Amd64, IA64) required by this module
ProcessorArchitecture = 'None'

# Modules that must be imported into the global environment prior to importing
# this module
RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to
# importing this module
ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @()

# Modules to import as nested modules of the module specified in
# ModuleToProcess
NestedModules = @()

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
FileList = @()

# Private data to pass to the module specified in ModuleToProcess
PrivateData = ''

}







