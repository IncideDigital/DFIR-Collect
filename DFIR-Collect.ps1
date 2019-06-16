<#
.SYNOPSIS
   Get information about a Windows 10 system to perform a DFIR analysis.
.DESCRIPTION
   On systems with a restricted script execution policy, run: PowerShell.exe -ExecutionPolicy UnRestricted -File .\dfircollect.ps1
.PARAMETER EvidenceId
   A string identifying the evidence. The output directory and zip file will have this name. Default: "evidence"
.PARAMETER ExportHKLM
   Export HKEY_LOCAL_MACHINE from the registry.
.PARAMETER ListFiles
   List files in all mounted file systems.
.PARAMETER CollectLogs
   Collect logs.
.PARAMETER Complete
   Get all evidence from all sections.
.EXAMPLE
   ./dfircollect.ps1 -EvidenceId 12345
.EXAMPLE
   ./dfircollect.ps1 -EvidenceId 12345 -Complete
.NOTES
    Under the GPL license.

   (c) 2019, Juan Vera (juanvvc@gmail.com)
#>

# Configuration parameters from the command line
param(
    [string]$EvidenceId="evidence",
    [switch]$ExportHKLM,
    [switch]$ListFiles,
    [switch]$CollectLogs,
    [switch]$Complete
)

# Internal configuration

# If complete, activate these sections
if ( $Complete ) {
    $ExportHKLM = $true
    $ListFiles = $true
    $CollectLogs = $true
}

$OutputDirectory = $EvidenceId
$OutputZipFile = ( $EvidenceId + ".zip" )
$OutputHashFile = ( $EvidenceId + ".sha256" )
$TotalSections = 31

$now = Get-Date

Write-Host "Starting the collection process. Output directory: $OutputDirectory. Date: $now" -ForegroundColor Green

####################### Start the process

# Delete output directories and files if they exist
Remove-Item $OutputDirectory -Recurse -ErrorAction Ignore
Remove-Item $OutputZipFile -ErrorAction Ignore
Remove-Item $OutputHashFile -ErrorAction Ignore
# Create the output directory and change directory to it
mkdir $OutputDirectory | Out-Null
Set-Location $OutputDirectory
# Metadata: date and current user
Write-Host $now | Out-File METADATA
whoami /ALL >> METADATA
# Alternate command
# whoami /useraccount >> METADATA

####################### Machine and Operating system information

$CurrentSection = "01"
$CurrentSectionName = "$CurrentSection-Machine and Operating system information"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# Basic system information
Get-CimInstance Win32_OperatingSystem | Export-Clixml $CurrentSectionName\OperatingSystem.xml
# Windows product key
(Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey | Out-File $CurrentSectionName\OriginalProductKey.txt

####################### User accounts and current login information

$CurrentSection = "02"
$CurrentSectionName = "$CurrentSection-User accounts and current login information"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# information about the users locally registered in the system
Get-WmiObject win32_useraccount | Export-Clixml $CurrentSectionName\Users.xml
# Current users
whoami /ALL > $CurrentSectionName\CurrentUser.txt

####################### Network

$CurrentSection = "03"
$CurrentSectionName = "$CurrentSection-Network configuration and connectivity information"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# ipconfig
ipconfig /all >  $CurrentSectionName\ipconfig.txt
# netstat
netstat -nabo > $CurrentSectionName\NetStat.xml
$netstat = netstat -nao
$NetstatProcessed = New-Object System.Collections.Generic.List[System.Object]
Foreach ( $conn in $netstat[4..$netstat.count] ) {
    $data = $conn -replace '^\s+','' -split '\s+'
    $element = @{
        "Proto" = $data[0]
        "Local IP" = $data[1]
        "Remote IP" = $data[2]
        "Status" = $data[3]
        "Process PID" = $data[4]
        "Process Name" = ((Get-process | Where-Object {$_.ID -eq $data[4]})).Name
        "Process Path" = ((Get-process | Where-Object {$_.ID -eq $data[4]})).Path
        "Process StartTime" = ((Get-process | Where-Object {$_.ID -eq $data[4]})).StartTime
        "Process DLLs" = ((Get-process| Where-Object {$_.ID -eq $data[4]})).Modules |Select-Object @{Name='Modules';Expression={$_.filename -join'; '} }
    }
    $NetstatProcessed.Add((New-Object -TypeName PSObject -Property $element))
}
$NetstatProcessed | Export-Clixml $CurrentSectionName\ProcessedNetStat.xml
# network adapters
Get-NetAdapter | Export-Clixml  $CurrentSectionName\NetAdapter.xml
# IP addresses
Get-NetIPAddress| Export-Clixml  $CurrentSectionName\NetIPAddress.xml    
# ARP
Get-NetNeighbor | Export-Clixml  $CurrentSectionName\NetNeighbor.xml
# network routes
Get-NetRoute | Export-Clixml  $CurrentSectionName\NetRoute.xml

####################### Antivirus

$CurrentSection = "04"
$CurrentSectionName = "$CurrentSection-Anti-Virus application status and related logs"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

####################### Services, process and applications

$CurrentSection = "05"
$CurrentSectionName = "$CurrentSection-Startup applications"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# Services run when the system starts
Get-CimInstance win32_service -Filter "startmode = 'auto'" | Export-Clixml $CurrentSectionName\StartupServices.xml
# Applications run when the system starts
Get-CimInstance Win32_StartupCommand | Export-Clixml $CurrentSectionName\StartupCommands.xml

$CurrentSection = "06"
$CurrentSectionName = "$CurrentSection-Running process related information"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# Current processes
Get-Process | Export-Clixml $CurrentSectionName\Process.xml

$CurrentSection = "07"
$CurrentSectionName = "$CurrentSection-Running services related information"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# Current services
Get-Service | Export-Clixml $CurrentSectionName\Service.xml

####################### Some not implemented sections

$CurrentSection = "08"
$CurrentSectionName = "$CurrentSection-Drivers installed and running"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "09"
$CurrentSectionName = "$CurrentSection-DLLs created"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "10"
$CurrentSectionName = "$CurrentSection-Open files"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "11"
$CurrentSectionName = "$CurrentSection-Open shares"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

####################### File systems

$CurrentSection = "12"
$CurrentSectionName = "$CurrentSection-Mapped drives"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# Information about all disks
Get-Disk | Export-Clixml $CurrentSectionName\Disk.xml
# Information about all partitions
Get-Partition | Export-Clixml $CurrentSectionName\Partition.xml
# shared folders, two ways (they are supposed to be equals)
Get-WmiObject -class Win32_Share | Export-Clixml $CurrentSectionName\SharedFolders.xml
Get-SmbShare | Export-Clixml $CurrentSectionName\SmbShare.xml

####################### Scheduled jobs

$CurrentSection = "13"
$CurrentSectionName = "$CurrentSection-Scheduled jobs"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

####################### Active network connections and related process

$CurrentSection = "14"
$CurrentSectionName = "$CurrentSection-Active network connections and related process"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# active networks
Get-NetConnectionProfile | Export-Clixml  $CurrentSectionName\NetConnectionProfile.xml
# TCP connections (established, listening)
Get-NetTCPConnection | Export-Clixml  $CurrentSectionName\NetTCPConnection.xml
# UDP listeres
Get-NetUDPEndpoint | Export-Clixml  $CurrentSectionName\NetUDPEndpoint.xml

####################### Hotfix

$CurrentSection = "15"
$CurrentSectionName = "$CurrentSection-Hotfixes applied"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
Get-HotFix | Export-Clixml $CurrentSectionName\Hotfix.xml

####################### Installed applications

$CurrentSection = "16"
$CurrentSectionName = "$CurrentSection-Installed applications"
mkdir $CurrentSectionName | Out-Null
Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
# Installed applications according to wmic
# This list doesn't include "applets" in the starting menu, nor windows utilities such as the clock
Get-WmiObject -Class Win32_Product | Export-Clixml $CurrentSectionName\InstalledApplications.xml
# WARNING: you will find in the Internet references to this command.
# Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > C:\Users\Lori\Documents\InstalledPrograms\InstalledProgramsPS.txt
# In out experience, many installed applications are not listed using that command

####################### Some not implemented sections

$CurrentSection = "17"
$CurrentSectionName = "$CurrentSection-Link files created"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "18"
$CurrentSectionName = "$CurrentSection-Packed files"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "19"
$CurrentSectionName = "$CurrentSection-USB related"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "20"
$CurrentSectionName = "$CurrentSection-Shadow copies created"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "21"
$CurrentSectionName = "$CurrentSection-Prefetch files and timestamps"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "22"
$CurrentSectionName = "$CurrentSection-DNS cache"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "23"
$CurrentSectionName = "$CurrentSection-List of available logs and last write times"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "24"
$CurrentSectionName = "$CurrentSection-Firewall configuration"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "25"
$CurrentSectionName = "$CurrentSection-Audit policy"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "26"
$CurrentSectionName = "$CurrentSection-Temporary Internet filesand cookies"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

$CurrentSection = "27"
$CurrentSectionName = "$CurrentSection-Typed URLs"
Write-Host "($CurrentSection/$TotalSections) Not implemented: $CurrentSectionName." -ForegroundColor Yellow

####################### Important registry keys

$CurrentSection = "28"
$CurrentSectionName = "$CurrentSection-Important registry keys"
If ( $ExportHKLM ) {
    mkdir $CurrentSectionName | Out-Null
    Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
    # The HKEY_LOCAL_MACHINE from the registry
    Get-ChildItem HKLM: -recurse -ErrorAction Ignore | Export-Clixml $CurrentSectionName\HKLM.xml
    # Alternate command
    # C:\windows\system32\reg.exe export HKLM HKLM.txt
} else {
    Write-Host "($CurrentSection/$TotalSections) Skipping: $CurrentSectionName." -ForegroundColor Yellow
}

####################### File timeline

$CurrentSection = "29"
$CurrentSectionName = "$CurrentSection-File timeline"
If ( $ListFiles ) {
    mkdir $CurrentSectionName | Out-Null
    Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
    # List all files in the mounted filesystems
    # TODO: maybe you shouldn't list shared directories?
    $drives = (Get-PSDrive).Name -match '^[a-z]$'
    $drives | ForEach-Object { Get-ChildItem ($_ + ":") -Recurse -Force | Export-Clixml ("$CurrentSectionName\FileList" + $_ + ".xml") }
} else {
    Write-Host "($CurrentSection/$TotalSections) Skipping: $CurrentSectionName." -ForegroundColor Yellow
}

####################### Important event logs

$CurrentSection = "30"
$CurrentSectionName = "$CurrentSection-Important event logs"
If ( $CollectLogs ) {
    mkdir $CurrentSectionName | Out-Null
    Write-Host "($CurrentSection/$TotalSections) Collecting: $CurrentSectionName..."
    Get-EventLog Application | Export-Clixml $CurrentSectionName\EventLog-Application.xml
    Get-EventLog Security | Export-Clixml $CurrentSectionName\EventLog-Security.xml
    Get-EventLog System | Export-Clixml $CurrentSectionName\EventLog-System.xml
    Get-EventLog "Windows PowerShell" | Export-Clixml $CurrentSectionName\EventLog-PowerShell.xml
    # This command may include all logs, but it is very slow and triggers many encoding errors
    # Get-WinEvent | Export-Clixml WinEvent.xml
} else {
    Write-Host "($CurrentSection/$TotalSections) Skipping: $CurrentSectionName." -ForegroundColor Yellow
}

####################### Convert files and create zip

Write-Host "($TotalSections/$TotalSections) Converting files and closing..."
#Converts all XML files into CSV, for easy greps and rvt2
Get-ChildItem -File *xml -Recurse | ForEach-Object {Import-Clixml $_ | Export-Csv -NoTypeInformation ($_.FullName + ".csv") }
# Convert all XML files into human readable lists
Get-ChildItem -File *xml -Recurse | ForEach-Object {Import-Clixml $_ | Format-List * | Out-File ($_.FullName + ".txt") }
# Create ZIP and calculate its hash value
Set-Location ..
Compress-Archive -Path $OutputDirectory -DestinationPath $OutputZipFile
Get-FileHash -Algorithm SHA256 $OutputZipFile | Export-Clixml $OutputHashFile

$now = Get-Date
$hash = Import-Clixml $OutputHashFile
Write-Host "The collection process ended. Output file and hash: $hash. Date: $now" -ForegroundColor Green