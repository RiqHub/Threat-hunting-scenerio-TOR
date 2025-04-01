<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Pwncrypt Ransomeware Scenario
- [Scenario Creation Example](https://github.com/RiqHub/Threat-hunting-scenerio-TOR/blob/main/Threat%20hunting%20scenario%20event%20creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


##  Scenario

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the C:\Users\Public\Desktop, encrypting files and prepending a .pwncrypt extension to the original extension. For example, hello.txt becomes hello.pwncrypt.txt after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.


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
- **Timestamp:** 2025-04-01T00:13:53.1667264Z
- **Action:** File Created
- **Details:** User downloaded pwncrypt.ps1 to the ProgramData folder.
- **Process:** powershell.exe
- **Path:** C:\ProgramData\pwncrypt.ps1

## Event 2: TOR Browser Installation
- Timestamp: 2025-03-10T18:07:44.5228069Z
- Action: Process Created
- Details: User executed the TOR Browser installer..
- Command: tor-browser-windows-x86_64-portable-14.0.7.exe 
- Path: C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe
Event 3: TOR Browser Launch
- Timestamp: 2025-01-11T03:04:51.5564106Z
- Action: Process created
- Details: User launched the TOR Browser.
- Path: C:\Users\useruser\Desktop\Tor Browser
## Event 4: File Creation
- Timestamp: 2025-03-10T18:13:10.7259043Z
- Action: File Created
- Details: User created torshoppinglist.txt and later modified it using Notepad.
- Path: C:\Users\useruser\Desktop\torshoppinglist.txt
## Event 5: Network Connections Established
- Timestamp: 2025-03-10T18:13:41.5487141Z
- Action: Connection Success
- Details: TOR application established a connection to 12.0.0.1 on port 9051.




---

## Summary

The user "labuser" on the "endpoint endpoint-vm-ev" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `torshoppinglist.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on endpoint endpoint-vm-ev. The device was isolated and the user's direct manager was notified.

---
