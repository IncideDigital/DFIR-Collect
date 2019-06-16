<#
.SYNOPSIS
   Get information about a Windows 10 system to perform a DFIR analysis.
.DESCRIPTION
   On systems with a restricted script execution policy, run: PowerShell.exe -ExecutionPolicy UnRestricted -File .\dfircollect.ps1
.PARAMETER EvidenceId
   A string identifying the evidence. The output directory and zip file will have this name. Default: "evidence"
.PARAMETER NoSystemInformation
   Do not collect basic information about the system.
.PARAMETER ExportHKLM
   Export HKEY_LOCAL_MACHINE from the registry.
.PARAMETER NoFileSystemInformation
   Collect information about disks and partitions.
.PARAMETER ListFiles
   List files in all mounted file systems.
.PARAMETER CollectLogs
   Collect logs.
.PARAMETER NoProcessInformation
   Do not collect information about start-up services and applications, and running services and processes.
.PARAMETER NoUsersInformation
   Do not collect information about registered users.
.PARAMETER NoNetworkInformation
   Do not collect information about network interfaces, connections and listening ports.
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
    [switch]$NoSystemInformation,
    [switch]$ExportHKLM,
    [switch]$NoFileSystemInformation,
    [switch]$ListFiles,
    [switch]$CollectLogs,
    [switch]$NoProcessInformation,
    [switch]$NoUsersInformation,
    [switch]$NoNetworkInformation,
    [switch]$Complete
)

# Internal configuration

if ( $Complete ) {
    $NoSystemInformation = $false
    $ExportHKLM = $true
    $NoFileSystemInformation = $true
    $ListFiles = $true
    $CollectLogs = $true
    $NoProcessInformation = $false
    $NoUsersInformation = $false
    $NoNetworkInformation = $false
}

$OutputDirectory = $EvidenceId
$OutputZipFile = ( $EvidenceId + ".zip" )
$OutputHashFile = ( $EvidenceId + ".sha256" )
$TotalSections = 9
$CurrentSection = 1

$now = Get-Date

Write-Host "Starting the collection process. Output directory: $OutputDirectory. Date: $now" -ForegroundColor Green

####################### Start the process

# Delete output directories and files if they exist
Remove-Item $OutputDirectory -Recurse -ErrorAction Ignore
Remove-Item $OutputZipFile -ErrorAction Ignore
Remove-Item $OutputHashFile -ErrorAction Ignore
# Create the output directory and change directory to it
mkdir $OutputDirectory | Out-Null
cd $OutputDirectory
# Metadata: date and current user
Write-Host $now | Out-File METADATA
whoami /ALL >> METADATA
# Alternate command
# whoami /useraccount >> METADATA

####################### System information

if ( $NoSystemInformation ) {
    Write-Host "($CurrentSection/$TotalSections) Skipping basic system information." -ForegroundColor Yellow
} else {
    Write-Host "($CurrentSection/$TotalSections) Basic system information..."
    # Basic system information
    Get-CimInstance Win32_OperatingSystem | Export-Clixml OperatingSystem.xml
    # Windows product key
    (Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey | Out-File OriginalProductKey.txt
}
$CurrentSection = $CurrentSection + 1

####################### HKLM

If ( $ExportHKLM ) {
    Write-Host "($CurrentSection/$TotalSections) Exporting HKLM..."
    # The HKEY_LOCAL_MACHINE from the registry
    Get-ChildItem HKLM: -recurse -ErrorAction Ignore | Export-Clixml HKLM.xml
    # Alternate command
    # C:\windows\system32\reg.exe export HKLM HKLM.txt
} else {
    Write-Host "($CurrentSection/$TotalSections) Skipping HKLM." -ForegroundColor Yellow
}
$CurrentSection = $CurrentSection + 1

####################### File systems

If ( $NoFileSystemInformation ) {
    Write-Host "($CurrentSection/$TotalSections) Skipping disks and partitions." -ForegroundColor Yellow
} else {
    Write-Host "($CurrentSection/$TotalSections) Collection information about disks and partitions..."
    # Information about all disks
    Get-Disk | Export-Clixml Disk.xml
    # Information about all partitions
    Get-Partition | Export-Clixml Partition.xml
    # shared folders, two ways (they are supposed to be equals)
    Get-WmiObject -class Win32_Share | Export-Clixml SharedFolders.xml
    Get-SmbShare | Export-Clixml SmbShare.xml
}
$CurrentSection = $CurrentSection + 1

####################### List files

If ( $ListFiles ) {
    Write-Host "($CurrentSection/$TotalSections) Listing directories..."
    # List all files in the mounted filesystems
    # TODO: maybe you shouldn't list shared directories?
    $drives = (Get-PSDrive).Name -match '^[a-z]$'
    $drives | ForEach { Get-ChildItem ($_ + ":") -Recurse -Force | Export-Clixml ("FileList" + $_ + ".xml") }
} else {
    Write-Host "($CurrentSection/$TotalSections) Skipping listing directories." -ForegroundColor Yellow
}
$CurrentSection = $CurrentSection + 1

####################### Services, process and application

if ( $NoProcessInformation ) {
    Write-Host "($CurrentSection/$TotalSections) Skipping processes, services and applications." -ForegroundColor Yellow
} else {
    Write-Host "($CurrentSection/$TotalSections)  Processes, services and applications..."
    # Services run when the system starts
    Get-CimInstance win32_service -Filter "startmode = 'auto'" | Export-Clixml StartupServices.xml
    # Applications run when the system starts
    Get-CimInstance Win32_StartupCommand | Export-Clixml StartupCommands.xml
    # Current processes
    Get-Process | Export-Clixml Process.xml
    # Current services
    Get-Service | Export-Clixml Service.xml
    # Installed applications according to wmic
    # This list doesn't include "applets" in the starting menu, nor windows utilities such as the clock
    Get-WmiObject -Class Win32_Product | Export-Clixml InstalledApplications.xml
    # WARNING: you will find in the Internet references to this command.
    # Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > C:\Users\Lori\Documents\InstalledPrograms\InstalledProgramsPS.txt
    # In out experience, many installed applications are not listed using that command
}
$CurrentSection = $CurrentSection + 1

####################### Logs

if ( $CollectLogs ) {
    Write-Host "($CurrentSection/$TotalSections) Logs..."
    Get-EventLog Application | Export-Clixml EventLog-Application.xml
    Get-EventLog Security | Export-Clixml EventLog-Security.xml
    Get-EventLog System | Export-Clixml EventLog-System.xml
    Get-EventLog "Windows PowerShell" | Export-Clixml EventLog-PowerShell.xml
    # This command may include all logs, but it is very slow and triggers many encoding errors
    # Get-WinEvent | Export-Clixml WinEvent.xml
} else {
    Write-Host "($CurrentSection/$TotalSections) Skipping logs." -ForegroundColor Yellow
}
$CurrentSection = $CurrentSection + 1

####################### Users

if ( $NoUsersInformation ) {
    Write-Host "($CurrentSection/$TotalSections) Skipping users information." -ForegroundColor Yellow
} else {
    Write-Host "($CurrentSection/$TotalSections)  Users information..."
    # information about the users locally registered in the system
    Get-WmiObject win32_useraccount | Export-Clixml Users.xml
}
$CurrentSection = $CurrentSection + 1

####################### Network

if ( $NoNetworkInformation ) {
    Write-Host "($CurrentSection/$TotalSections) Skipping network information..." -ForegroundColor Yellow
} else {
    Write-Host "($CurrentSection/$TotalSections) Network information..."
    # traditional commands
    ipconfig /all > ipconfig.txt
    netstat -nabo > netstat.txt
    # network adapters
    Get-NetAdapter | Export-Clixml NetAdapter.xml
    # IP addresses
    Get-NetIPAddress| Export-Clixml NetIPAddress.xml
    # active networks
    Get-NetConnectionProfile | Export-Clixml NetConnectionProfile.xml
    # TCP connections (established, listening)
    Get-NetTCPConnection | Export-Clixml NetTCPConnection.xml
    # UDP listeres
    Get-NetUDPEndpoint | Export-Clixml NetUDPEndpoint.xml
    # ARP
    Get-NetNeighbor | Export-Clixml NetNeighbor.xml
    # network routes
    Get-NetRoute | Export-Clixml NetRoute.xml
}
$CurrentSection = $CurrentSection + 1


####################### Convert files and create zip

echo "($CurrentSection/$TotalSections) Converting files and closing..."
#Converts all XML files into CSV, for easy greps and rvt2
mkdir csv | Out-Null
Get-ChildItem -File *xml | Foreach {Import-Clixml $_ | Export-Csv -NoTypeInformation ("csv\" + $_.BaseName + ".csv") }
# Convert all XML files into human readable lists
mkdir list | Out-Null
Get-ChildItem -File *xml | Foreach {Import-Clixml $_ | Format-List * | Out-File ("list\" + $_.BaseName + ".txt") }
# Create ZIP and calculate its hash value
cd ..
Compress-Archive -Path $OutputDirectory -DestinationPath $OutputZipFile
Get-FileHash -Algorithm SHA256 $OutputZipFile | Export-Clixml $OutputHashFile

$now = Get-Date
$hash = Import-Clixml $OutputHashFile
Write-Host "The collection process ended. Output file and hash: $hash. Date: $now" -ForegroundColor Green