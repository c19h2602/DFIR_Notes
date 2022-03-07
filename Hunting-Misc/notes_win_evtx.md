# Windows EVTX Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c](https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c)
* [https://medium.com/@lucideus/introduction-to-event-log-analysis-part-1-windows-forensics-manual-2018-b936a1a35d8a](https://medium.com/@lucideus/introduction-to-event-log-analysis-part-1-windows-forensics-manual-2018-b936a1a35d8a)
* [https://andreafortuna.org/2017/10/20/windows-event-logs-in-forensic-analysis/](https://andreafortuna.org/2017/10/20/windows-event-logs-in-forensic-analysis/)

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
