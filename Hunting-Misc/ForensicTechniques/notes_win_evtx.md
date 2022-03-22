# Windows EVTX Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c](https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c)
* [https://medium.com/@lucideus/introduction-to-event-log-analysis-part-1-windows-forensics-manual-2018-b936a1a35d8a](https://medium.com/@lucideus/introduction-to-event-log-analysis-part-1-windows-forensics-manual-2018-b936a1a35d8a)
* [https://andreafortuna.org/2017/10/20/windows-event-logs-in-forensic-analysis/](https://andreafortuna.org/2017/10/20/windows-event-logs-in-forensic-analysis/)
* [https://secureservercdn.net/160.153.138.53/x27.24e.myftpupload.com/download/Windows-Event-Log-Analyst-Reference.pdf?time=1647785527](https://secureservercdn.net/160.153.138.53/x27.24e.myftpupload.com/download/Windows-Event-Log-Analyst-Reference.pdf?time=1647785527)
* [Microsoft's baseline audit policy](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
* [NSA guide for configuring event log data to detect adversary activity](https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf)

## Event Log Forensics
Serve as the primary source of evidence as the operating system logs every system activity. Saved in `C:\Windows\System32\winevt\Logs`. Three main components:
* Application
* System
* Security

### Main Event Logs
* System Log: records events that are logged by the OS segments. May contain data about hardware changes, device drivers, system changes and all activities related to the machine.
* Security Log: contains Logon/Logoff activity and other activities related to Windows security. Specified by the system's audit policy.
* Application Log: records errors that occur in an installed application, informational events and warnings from software applications.
* Other Logs:
    * Directory Service Events: DCs record any AD changes.
    * File Replication Service Events
    * DNS events

### Characteristics
* Possible to disable the service.
* Data can be modified.
* Event logs from one machine can be transplanted into another.
* Uses internal host clock which can affect logs inf inaccurate.
* Event Log settings are controlled via the Windows Registry: `HKLM\SYSTEM\CurrentControlSet\Services\EventLog`.

### Tools to parse Event Logs
* [LogParser](https://www.microsoft.com/en-us/download/details.aspx?id=24659)
```cmd
LogParser.exe" "SELECT * INTO <infile> FROM <event logs>" -stats:OFF -i:evt -o:csv
```
* [Event Log Explorer](https://eventlogxp.com/)
* [EvtxECmd](https://ericzimmerman.github.io/#!index.md)
```cmd
EvtxECmd.exe -d "<event logs>" --csv D:\ --csvf <outfile>
```

### Useful Event IDs for DFIR

| Event ID     (2000/XP/2003) | Event ID    (Vista/7/8/2008/2012) | Description                                                                           | Log Name |   |
|-----------------------------|-----------------------------------|---------------------------------------------------------------------------------------|----------|---|
| 528                         | 4624                              | Successful Logon                                                                      | Security |   |
| 529                         | 4625                              | Failed Login                                                                          | Security |   |
| 680                         | 4776                              | Successful /Failed Account Authentication                                             | Security |   |
| 624                         | 4720                              | A user account was created                                                            | Security |   |
| 636                         | 4732                              | A member was added to a security-enabled local group                                  | Security |   |
| 632                         | 4728                              | A member was added to a security-enabled global group                                 | Security |   |
| 2934                        | 7030                              | Service Creation Errors                                                               | System   |   |
| 2944                        | 7040                              | The start type of the IPSEC Services service was changed from disabled to auto start. | System   |   |
| 2949                        | 7045                              | Service Creation                                                                      | System   |   |

#### Logon type Event IDs

| Logon type | Logon title      | Description                                                                                                                                                                                                                                                                                                                    | Log Name |   |
|------------|------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---|
| 2          | Interactive      | A user logged on to this computer.                                                                                                                                                                                                                                                                                             | Security |   |
| 3          | Network          | A user or computer logged on to this computer from the network.                                                                                                                                                                                                                                                                | Security |   |
| 4          | Batch            | Batch logon type is used by batch servers, where  processes may be executing on behalf of a user without their direct  intervention.                                                                                                                                                                                           | Security |   |
| 5          | Service          | A service was started by the Service Control Manager.                                                                                                                                                                                                                                                                          | Security |   |
| 7          | Unlock           | This workstation was unlocked.                                                                                                                                                                                                                                                                                                 | Security |   |
| 8          | NetworkCleartext | A user logged on to this computer from the network. The  user's password was passed to the authentication package in its unhashed  form. The built-in authentication packages all hash credentials before  sending them across the network. The credentials do not traverse the  network in plaintext (also called cleartext). | Security |   |
| 2934       | 7030             | Service Creation Errors                                                                                                                                                                                                                                                                                                        | System   |   |
| 2944       | 7040             | The start type of the IPSEC Services service was changed from disabled to auto start.                                                                                                                                                                                                                                          | System   |   |
| 2949       | 7045             | Service Creation                                                                                                                                                                                                                                                                                                               | System   |   |

### Account-Related Events

Default protocol used within a Windows domain environment is Kerberos, but older protocols such as NTLMv2 may also be used. Kerberos requires a hostname to complete the authentication process. If a system is referenced by IP address NTLMv2 is used.

* NTLMv2 Authentication: For NTLMv2 the NT hash of the user's password acts as a shared secred between the authentication authority and the client seeking access. When a user enters the account password, the local system will calculate the corresponding NT hash for the password and encrypt a challenge that is sent by the remote system to be accessed. The authentication authority can use its copy of the shared secret (NT hash) to encrypt the same challenge and verify that the response is correct.
* Kerberos Authentication: user authentication in a domain environment using the password hash a shared secret. If correct, Kerberos issues a TGT that serves a proof of identity in the network. To access a remote resouce, the user presents the TGT to the DC and requests a service ticket for the requested resource. Service ticket lists the user's permission and is encrypted with a shared secret contained by the DC and the requested service.
    * Issuance of a TGT or service ticket results in the creation of an account logon event. Recorded in the DC issuing the tickets.
    * When the ticket is issued the system being accessed records a logon events.

#### Account logon events in DC
* 4768: Kerberos authentication ticket requested.
* 4769: Kerberos service ticket requested.
* 4770: Kerberos service ticket is renewed.
* 4771: Kerberos pre-authentication failed.
* 4776: The computer attempted to validate credentials for an account. Series of failed 4776 events may indicate password guessing.
* 4624: Account was succcessfully logged on.
* 4625: Failed logon attempt.
* 4634/4647: Account was logged off.
* 4648: A logon was attempted using explicit credentials. Also includes bypassUAC.
* 4672: Special privileges assigned to new logon.
* 4778: A session was reconnected to a Windows station.
* 4779: A session was disconnected from a Windows station.
* [Logon tracer tool](https://github.com/JPCERTCC/LogonTracer)

### Object Access

Useful to determine what data was accessed by an adversary. Capabilities are built into Windows but need to be enabled.

* Enable detailed file share auditing:
```cmd
Group Policy Management Console (Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Object Access -> Audit Detailed File Share)
```
* Enable Object access auditing
```cmd
Local Security Policy (Security Settings -> Local Policies -> Audit Policy -> Audit Object Access)
```
* Removable media logging
```cmd
Group Policy Management Console (Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Object Access -> Audit Removable Storage)
```

#### Network share event IDs
* 5140: A network share object was accessed.
* 5142: A network share object was added.
* 5143: A network share object was modified.
* 5144: A network share object was deleted.
* 5145: A network share object was checked to see whether the client can be granted desired access.

#### Scheduled task events
* 4698: A scheduled task was created.
* 4699: A scheduled task was deleted.
* 4700: A scheduled task was enabled.
* 4701: A scheduled task was disabled.
* 4702: A scheduled task was updated.

#### Object handle events

For a process to use a system object it must obtain a handle to the object. With auditing enabled generated event ids can track the issuance and use of handles to objects.

* 4656: A handle to an object was requested.
* 4657: A registry value was modified.
* 4658: A handle to an object was closed.
* 4660: An object was deleted.
* 4663: An attempt was made to access an object.

### Audit system configuration settings

#### Scheduled task activity events

Scheduled tasks are used by attacker to obtain persistence. To detect, first enable task schedule history (Task Scheduler -> Enable all Task History) or
```cmd
wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true
```

* 106: Scheduled Task Created
* 140: Scheduled Task Updated
* 141: Scheduled Task Deleted
* 200: Scheduled Task Executed
* 201: Scheduled Task Completed

#### Service events

Services are processes that run without interactive user involvement. Start automatically on boot so they are commonly used as persistence mechanisms.
* 7045: Service installed on the system. Saved in the System event log.
* 4697: Service installed. Saved in the Security event log. Needs to be explicitly enabled:
```cmd
Advanced Audity Policy Configuration -> System Audit Policies -> System -> Audit Security System Extension
```

#### WiFi Connection events

Windows maintains log for for WLAN activity: `C:\Windows\System32\winevt\Logs\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx`.

* 8001: WLAN service has successfully connected to wireless network.
* 8002: WLAN service failed to connect to a wireless network.

### Process Auditing

Can enable ability to log full command lines in process-creation events. Requires two seperate Group Policy settings:
```cmd
Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Audit Policy -> Audit Process Tracking

Computer Configuration -> Administrative Templates -> System -> Audit Process Creation -> Include Command Line In Process Creation Events.
```

#### Process events
* 4688: A new process has been created.
* Additional log entries from the Windows Filtering Platform
    * 5031: The Windows Firewall Service blocked an application from accepting incoming connections on the network.
    * 5152: WFP blocked a packet.
    * 5154: WFP has permitted an application or service to listen on a port for incoming connections.
    * 5156: WFP has allowed a connection.
    * 5157: WFP has blocked a connection.
    * 5158: WFP has permitted to bind to a local port.
    * 5159: WFP has blocked a bind to a local port.

#### Windows Defender events
* 1006: Malware or PUA.
* 1007: Action to protect the system from malware or PUA.
* 1008: Failed action to protect the system from malwre or PUA.
* 1013: Delete history of malware and PUA.
* 1015: Detected suspicious behavior.
* 1116: Detected malware or PUA.
* 1117: Performed an action to protect the system from malware or PUA.
* 1118: Failed action to protect the system from malware or PUA.
* 1119: Critical error when performing an action to protect from malware or PUA.
* 5001: Real-time protection is disabled.
* 5004: Real-time protection configuration changed.
* 5007: Antimalware platform configuration changed.
* 5010: Scanning for malware and PUA is disabled.
* 5012: Scanning for viruses is disabled.
* [Can also enable Windows exploit protection](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exploit-protection): when enabled logs activities in `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Security-Mitigations%4KernelMode.evtx` and `Microsoft-Windows-Security-Mitigations%4UserMode.evtx`.

#### Sysmon events

Free utlity by Sysinternals available at [https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). It creates a new category of logs at `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`.

* 1: Process creation.
* 2: A process changed a file creation time.
* 3: Network connection.
* 4: System service state changed.
* 5: Process terminated.
* 6: Driver loaded.
* 7: Image loaded.
* 8: Create Remote Thread.
* 9: RawAccessRead (raw access to drive data using \\.\ notation).
* 10: ProcessAccess
* 11: FileCreate
* 12: Registry key or value created or deleted.
* 13: Registry value modification.
* 14: Registry key or value renamed.
* 15: FileCreateStreamHash (creation of alternate data stream).
* 16: Sysmon configuration change.
* 17: Named pipe created.
* 18: Named pipe connected.
* 19: WMIEventFilter activity detected.
* 20: WMIEventConsumer activity detected.
* 21: WMIEventConsumerToFilter activity detected.
* 22: DNS query event (Windows 8 and later).
* 255: Sysmon error.
* Configuration:
    * [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
    * [https://github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
* Visualization:
    * [https://github.com/JPCERTCC/SysmonSearch](https://github.com/JPCERTCC/SysmonSearch)

### PowerShell

Can enable logging facilities via Group Policy:
```cmd
Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Windows PowerShell
```

#### PowerShell events
* `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`
    * 4103: Pipeline execution from module logging facility.
    * 4104: Script block logging entries. Captures the commands sent by PowerShell not by the output.
* `C:\Windows\System32\winevt\Logs\Windows Powershell.evtx`
    * 400: Start of command execution.
    * 800: Shows pipeline execution details.
* [Guide to securing PowerShell](https://www.cyber.gov.au/acsc/view-all-content/publications/securing-powershell-enterprise)

## EVTX Anti-Forensic techniques and detection

### Common Methods

#### Clear the Logs
```cmd
wevutil cl Security

Clear-EventLog
```

Detection:
* Security Event ID 1102
* System Event ID 104
* Command line usage of `wevutil`

#### Disable Event Log Service
```cmd
sc stop EventLog
```

Detection:
* Service Control Manager Event ID 7035
* Command line usage of `sc`

#### Change policy and Reduce size
```powershell
Get-EventLog -List ! %<Limit-EventLog -OverflowAction DoNotOverwrite -MaximumSize 64KB -LogName $_.log>
```

* Leaves event log indicating that logs were changed. Delete for further stealth.
* When done with operations:
```powershell
Get-EventLog -List ! %<Limit-EventLog -OverflowAction OverwriteAsNeeded -MaximumSize 20480KB -LogName $_.log>
```

Active Detection:
* Watch for modification to Event Log configuration registry keys (Retention and MaxSize).

Forensic Detection:
* Correlate registry modified timestamps to potential malicious activity.
* Carve EVTX chunks from slack space or recover from memory.

### Disrupting the EventLog Service

Impact the service responsible for Event Logging. Will result in no logs recorded. Leaves a hole in the timeline.

#### Service Host Thread Tampering

EventLog service is associated with an instance of `svchost.exe`. The goal is to target the worker threads of the service. Can be done with Invoke-Phant0m:
* [https://github.com/hlldz/Phant0m](https://github.com/hlldz/Phant0m)

Invoke-Phant0m steps [https://artofpwn.com/2017/06/05/phant0m-killing-windows-event-log.html] (https://artofpwn.com/2017/06/05/phant0m-killing-windows-event-log.html):
* Detect the process of Windows EventLog service in the target.
* Get thread list and id WinEvtx service threat IDs.
* Kill threads.

The technique is quieter than disabling the event service. When the threads are killed, the event logs can be cleared without leaving  `Security Event ID 1102`.

#### Patching the Event Service

Mimikatz module to patch the event log service and clear the log.

```cmd
privilege::debug

event::drop -> avoids new events
event::clear -> clear event log
```

Does not leave `Security Event ID 1102` behind. Mimikatz targets `wevtsvc.dll` that is loaded in svchost.exe and is responsible for the EventLog service.

Only a in-memory modification so once the service is restarted or computer is rebooted, the EventLog service will return to normal.

#### Downgrading Windows Components

Exploit the existence of the `MiniNT` registry key to trick Windows into thinking the environment is WinPE.

```cmd
reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MiniNt”

restart to load changes
```

When key is deleted and EventLog service restarted all the events in the period were populated. Windows stores them.

### Manipulating individual event logs

#### Manual Event Editing

EVTX file format:
* [https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc)

When editing, 3 main checksums will cause the event log to become corrupt if not updated correctly. Must recalculate all 3 checksums:
* File Header Checksum
* Chunk Header Checksum
* Event Record Checksum

Steps:
1. Stop the Event log service and copy the .evtx
2. Modify events
3. Recalculate the Event Record Checksum and update the Chunk Header:
    * Event record checksum = CRC32 of first event record to last event record for the chunk.
4. Recalculate the Chuck Header Checksum and update the Chunk Header:
    * Chunk Header Checksum = CRC32 of first 120 bytes of the header + the bytes between 128-512.
5. Recalculate the File Header Checksum and update the File Header.

Detection:
* Service Control Manager Event ID 7035
* Command-line usage of Service manipulation (sc.exe)
* File access to the .evtx.

#### Event Record Unreferencing

Manipulate headers to hide certain logs. Modify the size of the record headers of the preceding log to be deleted. By increasing the size of the previous log with the size of the target logs records can be successfully unreferenced by joining two records. Danderspritz technique in `eventlogedit`. [https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/](https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/)

Steps:
1. Edit the size of the previous Event Record to hide the target record.
2. Update all subsequent Event Record IDs.
3. Update and recalculate the following in Chunk Header:
    * Last event record number
    * Last event record identifier
    * Last event record data offset
    * Event Record checksum
    * Chunk Header Checksum
4. Update and recalculate the following in File Header:
    * Next Record Identifier
    * File Header Checksum

Detection:
* The logs are never deleted. Look for record signature `0x2a3a` and look for EventRecordId inconsistencies.
* Detection script: [https://github.com/fox-it/danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx)
* [EvtxECmd](https://ericzimmerman.github.io/#!index.md)

#### Rewriting Logs with WinAPI EvtExportLog

Use [DeleteRecord-EvtExportLog.cpp](https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecord-EvtExportLog.cpp) to create a query excluding any log that has the EventRecordID supplied to it.

It creates a `temp.evtx` excluding the EventRecordID that was supplied. Log is completely deletedhttps://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecord-EvtExportLog.cpp .

Detection:
* Look for non sequential EventRecordIDs (Not applicable for current version).
* `temp.evtx` will appear in MFT analysis.
* Log gap analysis.

### Combined Techniques

* [https://svch0st.medium.com/event-log-tampering-part-3-combining-techniques-ce6ead21ca49](https://svch0st.medium.com/event-log-tampering-part-3-combining-techniques-ce6ead21ca49)

#### EventCleaner
* [https://github.com/QAX-A-Team/EventCleaner](https://github.com/QAX-A-Team/EventCleaner)

Steps to execute:
```cmd
EventCleaner.exe suspend

EventCleaner.exe closehandle

EventCleaner.exe <event record id>

EventCleaner.exe normal
```

Detection:
* Cannot rely on closed service because the technique suspends threads only.
* Cannot detect with danderspritz method because the record is deleted and not hidden.
* Look for EventRecordID inconsistencies.
