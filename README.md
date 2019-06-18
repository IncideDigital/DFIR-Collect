# DFIR-Collect

Get information about the Windows 10 system to perform a DFIR analysis.

On systems with a restricted script execution policy, run:

```
PowerShell.exe -ExecutionPolicy UnRestricted -File .\dfircollect.ps1
```

This script needs at lesat PowerShell 2.0 (Windows 10)

- Based on:  Sajeev Nair "Live Response Using PowerShell", SANS Institute 2013. <https://www.sans.org/reading-room/whitepapers/forensics/live-response-powershell-34302>
- Updated to out own needs.

Under the GPL license.

(c) 2019, Juan Vera (juanvvc@gmail.com)

# Install

Some modules need RawCopy.exe or the SleuthKit suite. Unzip them in the same directory than this script.

# Forensic artifacts

01. Machine and Operating system information.
02. User accounts and current login information.
03. Network configuration and connectivity information.
04. Anti-Virus application status and related logs.
05. Startup applications.
06. Running process related information.
07. Running services related information.
08. Drivers installed and running.
09. DLLs created.
10. Open files.
11. Open shares.
12. Mapped drives.
13. Scheduled jobs.
14. Active network connections and related process.
15. Hotfixes applied.
16. Installed applications.
17. Link files created.
18. Packed files.
19. USB related.
20. Shadow copies created.
21. Prefetch files and timestamps.
22. DNS cache.
23. List of available logs and last write times.
24. Firewall configuration.
25. Audit policy.
26. Temporary Internet filesand cookies.
27. Typed URLs.
28. Important registry keys.
29. File timeline.
30. Important event logs.