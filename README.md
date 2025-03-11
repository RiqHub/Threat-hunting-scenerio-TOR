<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/RiqHub/Threat-hunting-scenerio-TOR/blob/main/Threat%20hunting%20scenario%20event%20creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the **DeviceFileEvents** table to see if there were any tor related files in it. What was discovered was the user “labuser” download of  the tor browser which created several tor related files on the desktop, including a file named “torshoppintlist.txt”. These events began at:



**Query used to locate events:**

```kql
DeviceFileEvents
|where DeviceName == "endpoint-vm-ev"
| where FileName startswith "tor"
| order by Timestamp desc
|project Timestamp, DeviceName, ActionType, FolderPath, SHA256, Account = InitiatingProcessAccountName
```


![image](https://github.com/user-attachments/assets/9175155e-6e70-4330-a85b-54c167356b56)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the command line for any string that contained “"tor-browser-windows-x86_64-portable-14.0.7.exe". Based on the log findings, at 2025-03-10T18:07:44.5228069Z the employee on the “endpoint-vm-ev” device ran the file to install the TOR browser.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "endpoint-vm-ev"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```


![image](https://github.com/user-attachments/assets/c4229d94-6321-4b5d-9e6c-a1d6d6e24172)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user opened the tor browser.There was evidence that they did open it at 2025-03-10T18:13:10.7259043Z. There were several other instances of firefox.exe and tor.exe spawned after.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "endpoint-vm-ev"
| where FileName has_any ("tor.exe", "firefox.exe")
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
|order by Timestamp desc
```


![image](https://github.com/user-attachments/assets/8574cc71-5094-4101-b78f-cf7343bb4fd5)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworksEvents table for any indication that any of the known TOR ports were used to establish a successful connection. At 2025-03-10T18:13:41.5487141Z, user “labuser” connected to the remote IP address 127.0.0.1 on port 9150. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
|where DeviceName == "endpoint-vm-ev"
|where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```


![image](https://github.com/user-attachments/assets/d4c73089-0ef9-473c-97dd-40bb79f33ac2)


---

## Event 1: File Download
- **Timestamp:** 2025-03-10T18:07:26.5307721Z
- **Action:** File Created
- **Details:** User downloaded tor-browser-windows-x86_64-portable-14.0.7.exe to the Downloads folder.
- **Process:** msedge.exe
- **Path:** C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe

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
