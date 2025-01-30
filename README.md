# Threat Hunt T1059 Report (Command and Scripting Interpreter: PowerShell)

**Detection of Command and Scripting Interpreter: PowerShell**

## Example Scenario:
A mid-sized company, TechCo, was operating within the financial services sector, providing software solutions for clients. The company maintained a robust IT infrastructure with an in-house security team dedicated to monitoring and responding to potential cyber threats. TechCo's security monitoring team noticed unusual activity on the network. An alert triggered from the SIEM system indicated multiple failed login attempts from an internal user account to a sensitive company database. However, the investigation into this event quickly led the security team to a surprising discovery: an employee’s machine was being used to execute suspicious PowerShell scripts that appeared to be obfuscated. The SIEM alert flagged unusual PowerShell activity executed from John’s machine. The PowerShell commands appeared to be obfuscated—seemingly innocent commands that were encoded using base64 and executed via the -EncodedCommand flag.

---

## High-Level TOR related IoC Discovery Plan:
1. Check DeviceProcessEvents for commands using the -EncodedCommand Flag.
2. Check DeviceFileEvents for source of downloaded file.
3. Check DeviceEvents for any signs of installation or usage. 
4. Check AlertEvidence to see if the antivirus prevented the file installation.

---

## Steps Taken

1. Searched the DeviceProcessEvents for any commands using the -EncodedCommand flag and discovered the device Windowsvm-ch25 had obfuscated commands ran in it's command line by user JohnDoe. These commands were execute via a script named "ScheduledUpdate.ps1". The script was ran six times. These events took place between 2025-01-29T17:03:59.3104497Z and 2025-01-29T17:54:17.4643989Z.

Query used to locate these events:

DeviceProcessEvents
| where DeviceName contains "windowsvm-ch25"
| where AccountDomain == "windowsvm-ch25"
| where ProcessCommandLine contains "EncodedCommand"
| where Timestamp >= datetime(2025-01-29T17:03:59.3104497Z) 
| sort by Timestamp desc  

2. Searched the DeviceFileEvents for the source of the malicous script "ScheduledUpdate.ps1". Learned that the malicious script was downlaoded by Johndoe via Github. The script was downloaded at 2025-01-29T16:30:02.2604543Z and again at 2025-01-29T17:03:33.7503363Z. 

Query used to locate these events:

DeviceFileEvents
| where FolderPath contains "ScheduledUpdate.ps1"

3. Checked DeviceEvents for any signs of installation or usage. Based on the logs between "2025-01-29T16:30:30.7973677Z" and "2025-01-29T17:54:23.8772818Z" the ScheduledUpdate.ps1 script was ran multiple times, followed by some obsuficated powershell code, and then appearence of the malicious file "eicar-test-file.com". It is likely thaat the script that was ran included the obfuscated code which was created to download the malicious file and infect the target computer.

Query used to locate these events:

DeviceEvents
| where DeviceName contains "windowsvm-ch25"
| where InitiatingProcessCommandLine contains "-EncodedCommand" or InitiatingProcessCommandLine contains "ScheduledUpdate.ps1"
| where InitiatingProcessAccountName contains "johndoe"
| sort by Timestamp desc 

4. Searched the AlertEvidence to check if the anti-virus flagged and blocked the malicious file. The logs indicated that file was recognized and catagerized as "malware". As a result the execution of the malicious file "eicar-test-file.com" was prevented by the anti-virus software.

Query used to locate these events:

AlertEvidence 
| where DeviceName contains "windowsvm-ch25"
| where Timestamp between (datetime(2025-01-29T17:01:55.4918458Z) .. datetime(2025-01-29T17:54:49.5524883Z))
| sort by Timestamp desc 
| project Timestamp, Title, Categories, DetectionSource

---

## Chronological Events

1. ...
2. ...
3. ...

---

## Summary

...

---

## Response Taken
TOR usage was confirmed on endpoint ______________. The device was isolated and the user's direct manager was notified.

---

## MDE Tables Referenced:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Detection Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Created By:
- **Author Name**: Josh Madakor
- **Author Contact**: https://www.linkedin.com/in/joshmadakor/
- **Date**: August 31, 2024

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  6, 2024`  | `Josh Madakor`   
