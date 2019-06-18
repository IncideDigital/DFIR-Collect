'Incident Response information collection tool
'----------------------------------------------------------------------------

Set oShell = WScript.CreateObject("WScript.Shell")
Set fso = WScript.CreateObject("Scripting.Filesystemobject")
Set wshNetwork = WScript.CreateObject( "WScript.Network" )

'----------------------------------------------------------------------------
' Edit PATHS
'---------------------------------------------------------------------------
ARCH = 32
SERVER_SHARE = "\\192.168.5.148"
TOOLS_PATH = SERVER_SHARE + "\tools"
TOOLS_TEMP_PATH = "%TEMP%\tools"
RIP_PATH = TOOLS_TEMP_PATH + "\rip"
RAWCOPY = ""
RAWCOPY32 = TOOLS_PATH + "\RawCopy.exe"
RAWCOPY64 = TOOLS_PATH + "\RawCopy64.exe"
SEVENZIP = ""
SEVENZIP32 = TOOLS_PATH + "\7za-x86\7za.exe"
SEVENZIP64 = TOOLS_PATH + "\7za-x64\7za.exe"
ICAT = TOOLS_PATH + "\icat.exe"
BROWSING = TOOLS_PATH + "\BrowsingHistoryView.exe"
RIP = "cd " + RIP_PATH + " & rip.exe"
CMD = "%comspec%"
MACH_ID = wshNetwork.ComputerName
OUTPUT_PATH = SERVER_SHARE + "\share\" + MACH_ID

WINDOWS_PATH = ""
Set SystemSet = GetObject("winmgmts:").InstancesOf ("Win32_OperatingSystem")
for each System in SystemSet
 WINDOWS_PATH = System.WindowsDirectory
Next
USERS_PATH = ""

'''Comment if you want ALL users
'Dim userlist
'userlist = Array("imanol")
'''

'----------------------------------------------------------------------------
' Edit PATHS
'----------------------------------------------------------------------------

oShell.Run CMD + " /c mklink /d " + TOOLS_TEMP_PATH + " " + TOOLS_PATH, 0, True

ARCH = GetObject("winmgmts:root\cimv2:Win32_Processor='cpu0'").AddressWidth
if(ARCH = 64) Then
	'amd64
	RAWCOPY = RAWCOPY64
	SEVENZIP = SEVENZIP64
else
	'i386
	RAWCOPY = RAWCOPY32
	SEVENZIP = SEVENZIP32
End if

Set objWMI = GetObject("winmgmts://./root/cimv2")
Set colItems = objWMI.ExecQuery("Select * from Win32_OperatingSystem",,48)

For Each objItem in colItems
	OSVersion = Left(objItem.Version,3)
Next

OSVERMAJOR = Split(OSVersion,".")(0)
OSVERMINOR = Split(OSVersion,".")(1)

Set WSHShell = CreateObject("WScript.Shell")
USERS_PATH = WSHShell.ExpandEnvironmentStrings( WSHShell.RegRead( "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory" ))

If Not fso.FolderExists(OUTPUT_PATH) Then
  fso.CreateFolder OUTPUT_PATH
End If
If Not fso.FolderExists(OUTPUT_PATH + "\hives") Then
  fso.CreateFolder OUTPUT_PATH + "\hives"
End If
If Not fso.FolderExists(OUTPUT_PATH + "\mft") Then
  fso.CreateFolder OUTPUT_PATH + "\mft"
End If
If Not fso.FolderExists(OUTPUT_PATH + "\evts") Then
  fso.CreateFolder OUTPUT_PATH + "\evts"
End If

'''USERLIST, uncomment to get ALL users
Dim userlist()
numUsers = 0
For Each f In fso.GetFolder(USERS_PATH).SubFolders
	Do
		If f.name = "All Users" Then Exit Do
		If f.name = "Default" Then Exit Do
		If f.name = "Default User" Then Exit Do
		If f.name = "Public" Then Exit Do
		
		ReDim Preserve userlist(numUsers + 1)
		userlist(numUsers) = f.name
		numUsers = numUsers + 1
	Loop While False
Next

ReDim Preserve userlist(numUsers-1)
'''

For Each user in userlist
  If Not fso.FolderExists(OUTPUT_PATH + "\hives\" + user) Then
    fso.CreateFolder OUTPUT_PATH + "\hives\" + user
  End If
  If Not fso.FolderExists(OUTPUT_PATH + "\" + user) Then
	fso.CreateFolder OUTPUT_PATH + "\" + user
  End If
Next

'===========
'=== MFT ===
'===========

Dim drivelist()
numDrives = 0

Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set colItems = objWMIService.ExecQuery("Select * from Win32_Volume")
For Each objItem In colItems
  If objItem.DriveLetter <> "" Then
    If objItem.FileSystem = "NTFS" Then
	  ReDim Preserve drivelist(numDrives+1)
	  drivelist(numDrives) = objItem.DriveLetter
      numDrives = numDrives+1
    End If
  End If
Next

ReDim Preserve drivelist(numDrives-1)

For each drive in drivelist
  oShell.Run CMD + " /c " + ICAT + " \\.\" + drive + " 0 > " + OUTPUT_PATH + "\mft\" + Replace(drive,":","") + ".bin", 0, True
Next

'================
'=== PROFILES ===
'================

For each user in userlist
  oShell.Run CMD + " /c " + SEVENZIP + " a -r -mx1 " + OUTPUT_PATH + "\" + user + "\profile.7z " + USERS_PATH + "\" + user, 0, True
Next

'=============
'=== HIVES ===
'=============

oShell.Run CMD + " /c " + RAWCOPY + " /FileNamePath:" + WINDOWS_PATH + "\System32\config\SYSTEM /OutputPath:" + OUTPUT_PATH + "\hives", 0, True
oShell.Run CMD + " /c " + RAWCOPY + " /FileNamePath:" + WINDOWS_PATH + "\System32\config\SOFTWARE /OutputPath:" + OUTPUT_PATH + "\hives", 0, True
oShell.Run CMD + " /c " + RAWCOPY + " /FileNamePath:" + WINDOWS_PATH + "\System32\config\SECURITY /OutputPath:" + OUTPUT_PATH + "\hives", 0, True
oShell.Run CMD + " /c " + RAWCOPY + " /FileNamePath:" + WINDOWS_PATH + "\System32\config\SAM /OutputPath:" + OUTPUT_PATH + "\hives", 0, True

If ((OSVERMAJOR = 6) And (OSVERMINOR > 1)) Or (OSVERMAJOR > 6) Then
  oShell.Run CMD + " /c " + RAWCOPY + " /FileNamePath:" + WINDOWS_PATH + "\AppCompat\Programs\Amcache.hve /OutputPath:" + OUTPUT_PATH + "\hives", 0, True
End If

For each user in userlist
  oShell.Run CMD + " /c " + RAWCOPY + " /FileNamePath:" & chr(34) & USERS_PATH + "\" + user + "\NTUSER.DAT" & chr(34) & " /OutputPath:" & chr(34) & OUTPUT_PATH + "\hives\" + user + "\" & chr(34), 0, True
  oShell.Run CMD + " /c " + RAWCOPY + " /FileNamePath:" & chr(34) & USERS_PATH + "\" + user + "\AppData\Local\Microsoft\Windows\UsrClass.dat" & chr(34) & " /OutputPath:" & chr(34) & OUTPUT_PATH + "\hives\" + user + "\" & chr(34), 0, True
Next

'========================
'=== BROWSING HISTORY ===
'========================

For each user in userlist
	oShell.Run CMD + " /c " + BROWSING + " /SaveDirect /HistorySource 4 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /StopIECacheTask 1 /HistorySourceFolder " + USERS_PATH + "\" + user + " /scomma " + OUTPUT_PATH + "\" + user + "\history.csv", 0, True
Next

'=================
'=== LNK FILES ===
'=================

If OSVERMAJOR > 4 Then
  If OSVERMAJOR > 5 Then
    For Each user in userlist
	  oShell.Run CMD + " /c " + SEVENZIP + " a -r -mx1 " + OUTPUT_PATH + "\" + user + "\recents.7z " + USERS_PATH + "\" + user + "\AppData\Roaming\Microsoft\Windows\Recent", 0, True
    Next
  Else
    For Each user in userlist
	  oShell.Run CMD + " /c " + SEVENZIP + " a -r -mx1 " + OUTPUT_PATH + "\" + user + "\recents.7z " + USERS_PATH + "\Recent", 0, True
    Next
  End If
End If

'=================
'=== EVT FILES ===
'=================

If OSVERMAJOR > 4 Then
  If OSVERMAJOR > 5 Then
	  oShell.Run CMD + " /c copy " + WINDOWS_PATH + "\System32\winevt\Logs " + OUTPUT_PATH + "\evts\", 0, True
  Else
	  oShell.Run CMD + " /c copy " + WINDOWS_PATH + "\System32\config\*.evt " + OUTPUT_PATH + "\evts\", 0, True
  End If
End If

'==========================
'=== USERS AND PROFILES ===
'==========================

oShell.Run CMD + " /c " + RIP + " -p samparse -r " + OUTPUT_PATH + "\hives\SAM > " + OUTPUT_PATH + "\users.txt", 0, True
oShell.Run CMD + " /c " + RIP + " -p profilelist -r " + OUTPUT_PATH + "\hives\SOFTWARE > " + OUTPUT_PATH + "\profiles.txt", 0, True

'===========================
'=== NETWORK INFORMATION ===
'===========================

'IPConfig
oShell.Run CMD + " /c ipconfig /all > " + OUTPUT_PATH + "\ipconfig.txt", 0, True

'Routes
oShell.Run CMD + " /c route PRINT > " + OUTPUT_PATH + "\routes.txt", 0, True

'Netstat
oShell.Run CMD + " /c netstat -nabo > " + OUTPUT_PATH + "\netstat.txt", 0, True

'DNS servers
Set f = fso.OpenTextFile(OUTPUT_PATH + "\dns.txt", 2, True)

Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set colNicConfigs = objWMIService.ExecQuery ("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True")

For Each objNicConfig In colNicConfigs
	If Not IsNull(objNicConfig.DNSServerSearchOrder) Then
		For Each strDNSServer In objNicConfig.DNSServerSearchOrder
			f.WriteLine strDNSServer
		Next
	End If
Next
f.Close

'ARP cache
oShell.Run CMD + " /c arp -a > " + OUTPUT_PATH + "\arp.txt", 0, True

'DNS cache
oShell.Run CMD + " /c ipconfig /displaydns > " + OUTPUT_PATH + "\dnscache.txt", 0, True

'====================
'=== SERVICE LIST ===
'====================

On Error Resume Next
Set f = fso.OpenTextFile(OUTPUT_PATH + "\services.txt", 2, True)
Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set colListOfServices = objWMIService.ExecQuery ("Select * from Win32_Service")
f.WriteLine "---------------------"
For Each objService in colListOfServices
	f.WriteLine "Name: " & objService.Name
	f.WriteLine "DispName: " & objService.DisplayName
	f.WriteLine "Description: " & objService.Description
	f.WriteLine "State: " & objService.State
	f.WriteLine "Path: " & objService.PathName
	f.WriteLine "PID: " & objService.ProcessId
	f.WriteLine "---------------------"
Next
f.Close

'====================
'=== PROCESS LIST ===
'====================

On Error Resume Next
Set f = fso.OpenTextFile(OUTPUT_PATH + "\processes.txt", 2, True)
Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set colListOfServices = objWMIService.ExecQuery ("Select * from Win32_Process")
f.WriteLine "---------------------"
For Each objService in colListOfServices
	f.WriteLine "Name: " & objService.Name
	f.WriteLine "PID: " & objService.ProcessId
	f.WriteLine "CommandLine: " & objService.CommandLine
	f.WriteLine "Path: " & objService.ExecutablePath
	f.WriteLine "CreationDate: " & objService.CreationDate
	f.WriteLine "---------------------"
Next
f.Close


'===================
'=== GPO HISTORY ===
'===================

oShell.Run CMD + " /c " + RIP + " -p gpohist -r " + OUTPUT_PATH + "\hives\SOFTWARE > " + OUTPUT_PATH + "\gpohist.txt", 0, True

'=======================
'=== SCHEDULED TASKS ===
'=======================

oShell.Run CMD + " /c schtasks /query > " + OUTPUT_PATH + "\sched_tasks.txt", 0, True
oShell.Run CMD + " /c at > " + OUTPUT_PATH + "\at.txt", 0, True
oShell.Run CMD + " /c " + RIP + " -p at -r " + OUTPUT_PATH + "\hives\SOFTWARE > " + OUTPUT_PATH + "\at_rip.txt", 0, True

'================
'=== AUTORUNS ===
'================

oShell.Run CMD + " /c " + RIP + " -p soft_run -r " + OUTPUT_PATH + "\hives\SOFTWARE > " + OUTPUT_PATH + "\soft_run.txt", 0, True

For each user in userlist
    oShell.Run CMD + " /c " + RIP + " -p autorun -r " & chr(34) & OUTPUT_PATH + "\hives\" + user + "\NTUSER.DAT"  & chr(34) & " > " & chr(34) & OUTPUT_PATH + "\" + user + "\autorun.txt" & chr(34), 0, True
    oShell.Run CMD + " /c " + RIP + " -p user_run -r " & chr(34) & OUTPUT_PATH + "\hives\" + user + "\NTUSER.DAT"  & chr(34) & " > " & chr(34) & OUTPUT_PATH + "\" + user + "\user_run.txt" & chr(34), 0, True
    oShell.Run CMD + " /c " + RIP + " -p cmdproc -r " & chr(34) & OUTPUT_PATH + "\hives\" + user + "\NTUSER.DAT"  & chr(34) & " > " & chr(34) & OUTPUT_PATH + "\" + user + "\cmdproc_autorun.txt" & chr(34), 0, True
Next

'=====================
'=== LAST COMMANDS ===
'=====================

oShell.Run CMD + " /c " + RIP + " -p runmru -r " + OUTPUT_PATH + "\hives\SOFTWARE > " + OUTPUT_PATH + "\runmru.txt", 0, True

'==========================
'=== INSTALLED PROGRAMS ===
'==========================

oShell.Run CMD + " /c wmic product get name,version > " + OUTPUT_PATH + "\installed_programs.txt", 0, True

'FINISH

oShell.Run CMD + " /c rmdir " + TOOLS_TEMP_PATH, 0, True
oShell.Run CMD + " /c echo FINISHED > " + OUTPUT_PATH + "\FINISHED.TXT", 0, True

'===========================
'=== APPDATA EXECUTABLES ===
'===========================
For each user in userlist
    oShell.Run CMD + " /c cd " & USERS_PATH + "\" + user + "\AppData\Roaming\ & dir *.exe *.vbs *.ps1 *.com *.bat *.wsf /b/s > " + OUTPUT_PATH + "\" + user + "\executables_appdata.txt" , 0, True
Next

'TODO
'================
'=== PREFETCH ===
'================
'
' asdasdsdsd
'
