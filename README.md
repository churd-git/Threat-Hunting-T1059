![Command-and-Scripting-Interpreter-PowerShell-–-T1059 001-1](https://github.com/user-attachments/assets/a05b0159-1a02-49a3-a5f5-d6f432986001)


# Threat Hunt Report: Command and Scripting Interpreter: PowerShell (T1059.001)

**Detection of Command and Scripting Interpreter: PowerShell**

## Example Scenario:
A mid-sized company, TechCo, was operating within the financial services sector, providing software solutions for clients. The company maintained a robust IT infrastructure with an in-house security team dedicated to monitoring and responding to potential cyber threats. TechCo's security monitoring team noticed unusual activity on the network. An alert triggered from the SIEM system indicated multiple failed login attempts from an internal user account to a sensitive company database. However, the investigation into this event quickly led the security team to a surprising discovery: an employee’s machine was being used to execute suspicious PowerShell scripts that appeared to be obfuscated. The SIEM alert flagged unusual PowerShell activity executed from John’s machine. The PowerShell commands appeared to be obfuscated—seemingly innocent commands that were encoded using base64 and executed via the -EncodedCommand flag.

---

## High-Level Command and Scripting Interpreter: PowerShell related IoC Discovery Plan:
1. Check DeviceProcessEvents for commands using the -EncodedCommand Flag.
2. Check DeviceFileEvents for source of downloaded file.
3. Check DeviceEvents for any signs of installation or usage. 
4. Check AlertEvidence to see if the antivirus prevented the file installation.

---

## Steps Taken

1. Searched the DeviceProcessEvents for any commands using the -EncodedCommand flag and discovered the device Windowsvm-ch25 had obfuscated commands ran in it's command line by user JohnDoe. These commands were execute via a script named "ScheduledUpdate.ps1". The script was ran six times. These events took place between 2025-01-29T17:03:59.3104497Z and 2025-01-29T17:54:17.4643989Z.

Query used to locate these events:

```kql
DeviceProcessEvents
| where DeviceName contains "windowsvm-ch25"
| where AccountDomain == "windowsvm-ch25"
| where ProcessCommandLine contains "EncodedCommand"
| where Timestamp >= datetime(2025-01-29T17:03:59.3104497Z) 
| sort by Timestamp desc  
```
<img width="1460" alt="Screenshot 2025-01-30 at 12 20 13 AM" src="https://github.com/user-attachments/assets/eedf41a4-ad29-4381-8aa0-935d02cf8342" />

2. Searched the DeviceFileEvents for the source of the malicious script "ScheduledUpdate.ps1". Learned that the malicious script was downloaded by Johndoe via Github. The script was downloaded at 2025-01-29T16:30:02.2604543Z and again at 2025-01-29T17:03:33.7503363Z. 

Query used to locate these events:

```kql
DeviceFileEvents
| where FolderPath contains "ScheduledUpdate.ps1"
```
<img width="1469" alt="Screenshot 2025-01-30 at 12 20 41 AM" src="https://github.com/user-attachments/assets/63688990-c6b5-4c58-8993-90cdc21f2597" />

3. Checked DeviceEvents for any signs of installation or usage. Based on the logs between "2025-01-29T16:30:30.7973677Z" and "2025-01-29T17:54:23.8772818Z" the ScheduledUpdate.ps1 script was ran multiple times, followed by some obfuscated powershell code, and then appearance of the malicious file "eicar-test-file.com". It is likely that the script that was ran included the obfuscated code which was created to download the malicious file and infect the target computer.

Query used to locate these events:
```kql
DeviceEvents
| where DeviceName contains "windowsvm-ch25"
| where InitiatingProcessCommandLine contains "-EncodedCommand" or InitiatingProcessCommandLine contains "ScheduledUpdate.ps1"
| where InitiatingProcessAccountName contains "johndoe"
| sort by Timestamp desc 
```
<img width="1483" alt="Screenshot 2025-01-30 at 12 21 49 AM" src="https://github.com/user-attachments/assets/a7a4b0f7-aab2-494a-88c8-997c825a09b2" />

4. Searched the AlertEvidence to check if the antivirus flagged and blocked the malicious file. The logs indicated that the file was recognized and categorized as "malware". As a result the execution of the malicious file "eicar-test-file.com" was prevented by the anti-virus software.

Query used to locate these events:
```kql
AlertEvidence 
| where DeviceName contains "windowsvm-ch25"
| where Timestamp between (datetime(2025-01-29T17:01:55.4918458Z) .. datetime(2025-01-29T17:54:49.5524883Z))
| sort by Timestamp desc 
| project Timestamp, Title, Categories, DetectionSource
```
<img width="1512" alt="Screenshot 2025-01-30 at 12 22 16 AM" src="https://github.com/user-attachments/assets/35e3cd35-45f4-4d8e-9fae-06f52360ac00" />

---

## Chronological Events

Timeline Report for PowerShell-based Attack Simulation (T1059.001)

1. **Initial Suspicious Activity Detected**  
   **Timestamp:** 2025-01-29 16:30:02.2604543Z  
   **Event:** A download of the malicious script (`ScheduledUpdate.ps1`) was detected on the system. The file was downloaded by JohnDoe from GitHub.  
   **Source:** The script `ScheduledUpdate.ps1` was obtained from a suspicious GitHub link.  
   **Query:** `DeviceFileEvents | where FolderPath contains "ScheduledUpdate.ps1".`  
   **File Path:** `C:\Users\JohnDoe\Downloads\ScheduledUpdate.ps1`

2. **Malicious Script Execution**  
   **Timestamp:** 2025-01-29 17:03:33.7503363Z  
   **Event:** The `ScheduledUpdate.ps1` script was executed. It was found that the script was designed to execute obfuscated PowerShell commands using the `-EncodedCommand` flag.  
   **Command Line:** `powershell -EncodedCommand <Base64Command>.`  
   **Details:** This triggered the use of encoded PowerShell commands, marking the beginning of malicious activity on the system.  
   **Query:** `DeviceProcessEvents | where DeviceName contains "windowsvm-ch25" and AccountDomain == "windowsvm-ch25" and ProcessCommandLine contains "EncodedCommand".`

3. **Repeated Script Execution**  
   **Timestamp:** 2025-01-29 17:03:59.3104497Z  
   **Event:** The `ScheduledUpdate.ps1` script was executed multiple times by JohnDoe within the following minutes, running obfuscated PowerShell commands.  
   **Execution Time:** Multiple runs between 2025-01-29 17:03:59 and 2025-01-29 17:54:17.  
   **Command Details:** The obfuscated commands attempted to perform additional actions on the machine, likely aimed at file manipulation or system compromise.  
   **Query:** `DeviceProcessEvents | where DeviceName contains "windowsvm-ch25" and AccountDomain == "windowsvm-ch25" and ProcessCommandLine contains "EncodedCommand".`

4. **Download and Execution of the Malicious File**  
   **Timestamp:** 2025-01-29 17:03:33.7503363Z  
   **Event:** The EICAR test file (`malicious file`) was downloaded by the script executed earlier. The script used an encoded PowerShell command to download the file.  
   **File:** `eicar-test-file.com`  
   **File Path:** `C:\Users\JohnDoe\Downloads\eicar-test-file.com`  
   **Antivirus Action:** The Antivirus software flagged and blocked the file upon execution.  
   **Query:** `DeviceFileEvents | where FolderPath contains "eicar-test-file.com".`  
   **Antivirus Detection:** The file was flagged as malware by the antivirus.

5. **Antivirus Blocking of Malicious File**  
   **Timestamp:** 2025-01-29 17:54:49.5524883Z  
   **Event:** The antivirus software successfully blocked the execution of the `eicar-test-file.com`.  
   **Antivirus Action:** File was detected as malware, thus preventing the execution.  
   **Query:** `AlertEvidence | where DeviceName contains "windowsvm-ch25" and Timestamp between (datetime(2025-01-29T17:01:55) .. datetime(2025-01-29T17:54:49)).`  
   **Action Taken:** File execution was prevented, and the threat was neutralized.

6. **Final Investigation and Evidence Collection**  
   **Timestamp:** 2025-01-29 17:54:23.8772818Z  
   **Event:** Continued investigation of the system showed that the script `ScheduledUpdate.ps1` was executing obfuscated PowerShell commands, aiming to download malicious content.  
   **Process Analysis:** Logs revealed that PowerShell was used repeatedly to run obfuscated scripts that could be linked to malicious activity.  
   **Query:** `DeviceEvents | where DeviceName contains "windowsvm-ch25" and InitiatingProcessCommandLine contains "-EncodedCommand" or InitiatingProcessCommandLine contains "ScheduledUpdate.ps1".`
---

## Summary

On 2025-01-29, suspicious activity was detected on windowsvm-ch25 when a PowerShell script (ScheduledUpdate.ps1) containing obfuscated commands was executed by JohnDoe. The script, downloaded from GitHub, used the -EncodedCommand flag to execute base64 encoded PowerShell commands. These commands attempted to download and execute a malicious file (eicar-test-file.com), but the antivirus software flagged and blocked the file as malware. Despite the malware being blocked, the compromised system was deemed at risk. Following this, the system was isolated and re-imaged to a secure state prior to the initial brute-force attack. As part of the remediation process, JohnDoe was required to change his password to prevent further compromise.

---

## Response Taken
Command and Scripting Interpreter: PowerShell with obfuscated usage was confirmed on endpoint windowsvm-ch25. A malicious file was downloaded and executed resulting in the download of malware onto the machine however the anti-virus prevented the malware from being executed. The device was isolated and re-imaged to a state prior to the initial brute-force attempt which likely compromised the machine. The user was forced to change his password.  

---

## Created By:
- **Author Name**: Carlton Hurd
- **Author Contact**: https://www.linkedin.com/in/carlton-hurd-6069a5120/
- **Date**: January 29th, 2025

## Validated By:
- **Reviewer Name**: Carlton Hurd
- **Reviewer Contact**: 
- **Validation Date**: January 29th, 2025 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `January  29th, 2025`  | `Carlton Hurd`   
