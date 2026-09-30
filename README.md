Enterprise Threat Detection & SOC Monitoring with Splunk & Sysmon

An end-to-end detection engineering and SOC monitoring project simulating endpoint threats, ingesting high-fidelity telemetry using Microsoft Sysmon, and establishing automated detection queries mapped to the **MITRE ATT&CK Framework.
Windows Endpoint / Monitored Host 

 Sysmon (Event ID 1: Process Creation, Event ID 3: Network Connections)Windows Security Event Logs (Event ID 4624 / 4625: Logon Telemetry)
 Ingestion & SIEM Engine 
 Splunk Enterprise (XML Normalization via Rex, SPL Detection, Triage Views)
 Threat Scenarios & Detection Engineering

Threat Scenarios & Detection Engineering

### Scenario 1: Living-off-the-Land Process Execution (T1059.001)
* **Objective:** Detect execution of administrative command shells (`cmd.exe`, `powershell.exe`) spawned via suspicious parent processes or system directories.
* **Telemetry Source:** `Microsoft-Windows-Sysmon/Operational` (Event ID 1).
* **Detection SPL:**
```spl
source="*Sysmon*"
| rex field=_raw "<Data Name="Image">(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name="CommandLine">(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name="ParentImage">(?<ParentImage>[^<]+)</Data>"
| search (Image="*\\powershell.exe" OR Image="*\\cmd.exe")
| table _time, ParentImage, Image, CommandLine
```
Scenario 2: Authentication Anomaly & Brute Force (T1110)
​Objective: Identify repeated logon failures across accounts within a defined threshold.
​Telemetry Source: WinEventLog:Security (Event Code 4625).
​Detection SPL:
```spl
source="*WinEventLog:Security*" EventCode=4625
| stats count by TargetUserName, src_ip
| where count >= 5
| sort - count
```
