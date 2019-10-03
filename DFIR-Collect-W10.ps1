<#
.SYNOPSIS
   Get information about a Windows 10 system to perform a DFIR analysis.
.DESCRIPTION
   On systems with a restricted script execution policy, run: PowerShell.exe -ExecutionPolicy UnRestricted -File .\dfircollect.ps1

   This script needs at lesat PowerShell 2.0 (Windows 10)
.PARAMETER EvidenceId
   A string identifying the evidence. The output directory and zip file will have this name. Default: "evidence"
.PARAMETER ExportRegistry
   Export HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER from the registry.
.PARAMETER ExportMFT
   Export the MFT of all partitions. RawCopy.exe must be present alongside this script.
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
    [switch]$ExportRegistry,
    [switch]$ExportMFT,
    [switch]$CollectLogs,
    [switch]$Complete,
    [string]$RawCopyPath="$PSScriptRoot\RawCopy\RawCopy.exe",
    [string]$FlsPath="$PSScriptRoot\sleuthkit\bin\fls.exe",
    [string]$IcatPath="$PSScriptRoot\sleuthkit\bin\icat.exe"
)

Write-Host $RawCopyPath

# Internal configuration

# If complete, activate these sections
if ( $Complete ) {
    $ExportRegistry = $true
    $ExportMFT = $true
    $CollectLogs = $true
}

$OutputDirectory = $EvidenceId
$OutputZipFile = ( $EvidenceId + ".zip" )
$OutputHashFile = ( $EvidenceId + ".sha256" )
$TotalSections = 31

Function Prepare-Section {
    <#
    .DESCRIPTION
    Prepare the environment to run a section
    .PARAMETER Index
    A string identifying the index of the section. For example: "01", "15"...
    .PARAMETER Name
    The description of the section.
    .PARAMETER Run
    Whether the section will be run.
    .PARAMETER Log
    A message to log run.
    .NOTES
    Returns the $Run parameter. Use in an If expression to run the commands of the section or not.

    $SectionPreffix will be set to the preffix to add to output files. If it is a directory, it will be created.
    #>
    param(
        [string]$Index='',
        [string]$Name='',
        [switch]$Run=$true,
        [string]$Log=''
    )
    $SectionName = "$Index-$Name"
    Set-Variable -Name "SectionPreffix" -Value "$Index-" -Scope Global
    # mkdir $SectionPreffix | Out-Null
    If ( $Log -eq '' ) {
        If ( $Run ) {
            Write-Host "($Index/$TotalSections) Running: $SectionName..."
        } Else {
            Write-Host "($Index/$TotalSections) Skipping: $SectionName." -ForegroundColor yellow
        }
    } Else {
        If ( $Run ) {
            Write-Host "($Index/$TotalSections) ${Log}: $SectionName..."
        } Else {
            Write-Host "($Index/$TotalSections) ${Log}: $SectionName." -ForegroundColor yellow
        }
    }
    Return $Run
}


####################### Start the process

$now = Get-Date
Write-Host "Starting the collection process. Output directory: $OutputDirectory. Date: $now" -ForegroundColor Green

# Delete output directories and files if they exist
Remove-Item $OutputDirectory -Recurse -ErrorAction Ignore
Remove-Item $OutputZipFile -ErrorAction Ignore
Remove-Item $OutputHashFile -ErrorAction Ignore
# Create the output directory and change directory to it
mkdir $OutputDirectory | Out-Null
Set-Location $OutputDirectory
# Metadata: date and current user
Write-Output $now | Out-File METADATA
whoami /ALL >> METADATA
# Alternate command
# whoami /useraccount >> METADATA

####################### Machine and Operating system information

If ( Prepare-Section -Index "01" -Name "Machine and Operating system information" ) {
    # Basic system information
    Get-CimInstance Win32_OperatingSystem | Export-Clixml ${SectionPreffix}OperatingSystem.xml
    # Environment vars
    Get-ChildItem env: | Export-Clixml ${SectionPreffix}EnvironmentVars.xml
    # Windows product key
    (Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey | Out-File ${SectionPreffix}OriginalProductKey.txt
}

####################### User accounts and current login information

If ( Prepare-Section -Index "02" -Name "User accounts and current login information" ) {
    # information about the users locally registered in the system
    Get-WmiObject win32_useraccount | Export-Clixml ${SectionPreffix}Users.xml
    # Current users
    whoami /ALL > ${SectionPreffix}CurrentUser.txt
}

####################### Network

If ( Prepare-Section -Index "03" -Name "Network configuration and connectivity information" ) {
    # Traditional commands
    cmd /c "ipconfig /all >  ${SectionPreffix}ipconfig.txt"
    cmd /c "netstat -nabo > ${SectionPreffix}netstat.txt"
    cmd /c "ipconfig /displaydns > ${SectionPreffix}displaydns.txt"
    cmd /c "route PRINT > ${SectionPreffix}routes.txt"
    # netstat, parsing the output to include process information
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
    $NetstatProcessed | Export-Clixml ${SectionPreffix}ProcessedNetStat.xml
    # network adapters
    Get-NetAdapter | Export-Clixml  ${SectionPreffix}NetAdapter.xml
    # IP addresses
    Get-NetIPAddress| Export-Clixml  ${SectionPreffix}NetIPAddress.xml    
    # ARP
    Get-NetNeighbor | Export-Clixml  ${SectionPreffix}NetNeighbor.xml
    # network routes
    Get-NetRoute | Export-Clixml  ${SectionPreffix}NetRoute.xml
}

####################### Antivirus

#Prepare-Section -Index "04" -Name "Anti-Virus application status and related logs" -Log 'Not implemented' -Run:$false | Out-Null

If ( Prepare-Section -Index "04" -Name "Anti-Virus application status and related logs" ) {
    # AdwCleaner / Malwarebytes Logs and Quarantine
    if ( Test-Path -Path "C:\AdwCleaner" ) { Copy-Item "C:\AdwCleaner" ${SectionPreffix}AdwCleaner -Recurse }
    # McAfee. Log locations of several versions
    if ( Test-Path -Path "C:\${ProgramData}\McAfee\DesktopProtection\Logs" ) { Copy-Item "C:\${ProgramData}\McAfee\DesktopProtection\Logs" ${SectionPreffix}McAfee\DesktopProtection\Logs -Recurse -Force }
    if ( Test-Path -Path "C:\${ProgramData}\McAfee\Endpoint Security\Logs" ) { Copy-Item "C:\${ProgramData}\McAfee\Endpoint Security\Logs" ${SectionPreffix}McAfee\Endpoint Security\Logs -Recurse -Force }
    if ( Test-Path -Path "C:\${ProgramData}\McAfee\VirusScan" ) { Copy-Item "C:\${ProgramData}\McAfee\VirusScan" ${SectionPreffix}McAfee\VirusScan -Recurse -Force }
    if ( Test-Path -Path "C:\${ProgramData}\McAfee\MCLOGS" ) { Copy-Item "C:\${ProgramData}\McAfee\MCLOGS" ${SectionPreffix}McAfee\MCLOGS -Recurse -Force }
    if ( Test-Path -Path "C:\${ProgramData}\McAfee\msc\Logs" ) { Copy-Item "C:\${ProgramData}\McAfee\msc\Logs" ${SectionPreffix}McAfee\msc\Logs -Recurse -Force }
}

####################### Services, process and applications

If ( Prepare-Section -Index "05" -Name "Startup applications" ) {
    # Services run when the system starts
    Get-CimInstance win32_service -Filter "startmode = 'auto'" | Export-Clixml ${SectionPreffix}StartupServices.xml
    # Applications run when the system starts
    Get-CimInstance Win32_StartupCommand | Export-Clixml ${SectionPreffix}StartupCommands.xml
}

If ( Prepare-Section -Index "06" -Name "Running process related information" ) {
    # Current processes
    Get-Process | Export-Clixml ${SectionPreffix}Process.xml
}

If ( Prepare-Section -Index "07" -Name "Running services related information" ) {
    # Current services
    Get-Service | Export-Clixml ${SectionPreffix}Service.xml
}

####################### Some not implemented sections

Prepare-Section -Index "08" -Name "Drivers installed and running" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "09" -Name "DLLs created" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "10" -Name "Open files" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "11" -Name "Open shares" -Log 'Not implemented' -Run:$false | Out-Null

####################### File systems

If ( Prepare-Section -Index "12" -Name "Mapped drives" ) {
    # Information about all disks
    Get-Disk | Export-Clixml ${SectionPreffix}Disk.xml
    # Information about all partitions
    Get-Partition | Export-Clixml ${SectionPreffix}Partition.xml
    # shared folders, two ways (they are supposed to be equals)
    Get-WmiObject -class Win32_Share | Export-Clixml ${SectionPreffix}SharedFolders.xml
    Get-SmbShare | Export-Clixml ${SectionPreffix}SmbShare.xml
}

####################### Scheduled jobs

If ( Prepare-Section -Index "13" -Name "Scheduled jobs" ) {
    Get-ScheduledTask | Export-Clixml  ${SectionPreffix}ScheduledTask.xml
    Get-ScheduledJob | Export-Clixml  ${SectionPreffix}ScheduledJob.xml
    # Traditional commands
    cmd /c "schtasks /query > ${SectionPreffix}schtasks.txt"
    cmd /c "at > ${SectionPreffix}at.txt"
}

####################### Active network connections and related process

If ( Prepare-Section -Index "14" -Name "Active network connections and related process" ) {
    # active networks
    Get-NetConnectionProfile | Export-Clixml  ${SectionPreffix}NetConnectionProfile.xml
    # TCP connections (established, listening)
    Get-NetTCPConnection | Export-Clixml  ${SectionPreffix}NetTCPConnection.xml
    # UDP listeres
    Get-NetUDPEndpoint | Export-Clixml  ${SectionPreffix}NetUDPEndpoint.xml
}

####################### Hotfix

If ( Prepare-Section -Index "15" -Name "Hotfix" ) {
    Get-HotFix | Export-Clixml ${SectionPreffix}Hotfix.xml
}

####################### Installed applications

If ( Prepare-Section -Index "16" -Name "Installed applications" ) {
    # Installed applications according to wmic
    # This list doesn't include "applets" in the starting menu, nor windows utilities such as the clock
    Get-WmiObject -Class Win32_Product | Export-Clixml ${SectionPreffix}InstalledApplications.xml
    # WARNING: you will find in the Internet references to this command.
    # Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > C:\Users\Lori\Documents\InstalledPrograms\InstalledProgramsPS.txt
    # In our experience, many installed applications are not listed using that command
}

####################### Some not implemented sections

Prepare-Section -Index "17" -Name "Link files created" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "18" -Name "Packed files" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "19" -Name "USB related" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "20" -Name "Shadow copies created" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "21" -Name "Prefetch files and timestamps" -Log 'Not implemented' -Run:$false | Out-Null

####################### DNS cache

If ( Prepare-Section -Index "22" -Name "DNS cache" ) {
    # Save the DNS cache
    Get-DnsClientCache |  Export-Clixml ${SectionPreffix}DnsClientCache.xml
}

####################### Some not implemented sections

Prepare-Section -Index "23" -Name "List of available logs and last write times" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "24" -Name "Firewall configuration" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "25" -Name "Audit policy" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "26" -Name "Temporary Internet filesand cookies" -Log 'Not implemented' -Run:$false | Out-Null
Prepare-Section -Index "27" -Name "Typed URLs" -Log 'Not implemented' -Run:$false | Out-Null

####################### Important registry keys

If ( Prepare-Section -Index "28" -Name "Important registry keys" -Run:$ExportRegistry ) {
    # The HKEY_LOCAL_MACHINE from the registry
    Get-ChildItem HKLM: -recurse -ErrorAction Ignore | Export-Clixml ${SectionPreffix}HKLM.xml
    # The HKEY_CURRENT_USER from the registry
    Get-ChildItem HKCU: -recurse -ErrorAction Ignore | Export-Clixml ${SectionPreffix}HKCU.xml
    # Alternate command
    # C:\windows\system32\reg.exe export HKLM HKLM.txt
}

####################### File timeline

If ( Prepare-Section -Index "29" -Name "File timeline" -Run:$ExportMFT ) {
    # Get the MBR using an external tool
    $drives = (Get-PSDrive).Name -match '^[a-z]$'
    $drives | ForEach-Object {
        If ( Test-Path "$RawCopyPath" ) {
            # get the MFT using RawCopy.exe
            Invoke-Expression "${RawCopyPath} /FileNamePath:${_}:0 /OutputPath:. /OutputName:${SectionPreffix}MFT_${_}.rawcopy.bin"
        } ElseIf (  Test-Path "$IcatPath" )  {
            # if RawCopy is not found: get the MFT using icat from SleuthKit
            cmd.exe /c "${IcatPath} \\.\${_}: 0 > ${SectionPreffix}MFT_${_}.icat.bin"
        } Else {
            Write-Host "${RawCopyPath} or ${IcatPath} not present: MFT for drive $_ not exported" -ForegroundColor Red
        }
        # Get the body file using fls from SleuthKit
        if ( Test-Path "$FlsPath" ) {
            Write-Host "Collecting body file from volume ${_} using ${FlsPath}. This is going to take a while."
            cmd.exe /c "${FlsPath} -r -m ${_}: \\.\${_}: > ${SectionPreffix}fls_${_}.body"
        } Else {
            Write-Host "${FlsPath} not present: body file for drive $_ not exported" -ForegroundColor Red
        }
    }
}

####################### Important event logs

If ( Prepare-Section -Index "30" -Name "Important event logs" -Run:$CollectLogs ) {
    Get-EventLog Application | Export-Clixml ${SectionPreffix}EventLog-Application.xml
    Get-EventLog Security | Export-Clixml ${SectionPreffix}EventLog-Security.xml
    Get-EventLog System | Export-Clixml ${SectionPreffix}EventLog-System.xml
    Get-EventLog "Windows PowerShell" | Export-Clixml ${SectionPreffix}EventLog-PowerShell.xml
    # This command may include all logs, but it is very slow and triggers many encoding errors
    # Get-WinEvent | Export-Clixml WinEvent.xml
}

####################### Convert files and create zip

If ( Prepare-Section -Index $TotalSections -Name "Converting files" ) {
     #Converts all XML files into CSV, for easy greps and rvt2, and human readable lists
    Get-ChildItem -File *xml -Recurse | ForEach-Object {
        Import-Clixml $_ | Export-Csv -NoTypeInformation ($_.FullName + ".csv")
        Import-Clixml $_ | Format-List * | Out-File ($_.FullName + ".txt")
    }
}

# Create ZIP and calculate its hash value
Set-Location ..
Compress-Archive -Path $OutputDirectory -DestinationPath $OutputZipFile
Get-FileHash -Algorithm SHA256 $OutputZipFile | Export-Clixml $OutputHashFile

$now = Get-Date
$hash = Import-Clixml $OutputHashFile
Write-Host "The collection process ended. Output file and hash: $hash. Date: $now" -ForegroundColor Green
