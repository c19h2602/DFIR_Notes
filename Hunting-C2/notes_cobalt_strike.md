# Hunting Notes - Cobalt Strike

> Paolo Coba | 04/03/2021

-------------------------------------------

# Resources
* [https://www.mandiant.com/resources/defining-cobalt-strike-components](https://www.mandiant.com/resources/defining-cobalt-strike-components)
* [https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b](https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b)
* [https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm#_Toc65482705](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm#_Toc65482705)
* [https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/](https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/)
* [https://go.recordedfuture.com/hubfs/reports/mtp-2021-0914.pdf](https://go.recordedfuture.com/hubfs/reports/mtp-2021-0914.pdf)
* [https://s3.amazonaws.com/talos-intelligence-site/production/document_files/files/000/095/031/original/Talos_Cobalt_Strike.pdf?1600694964](https://s3.amazonaws.com/talos-intelligence-site/production/document_files/files/000/095/031/original/Talos_Cobalt_Strike.pdf?1600694964)
* [https://github.com/rsmudge/Malleable-C2-Profiles](https://github.com/rsmudge/Malleable-C2-Profiles)
* [https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)
* [https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1](https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1)
* [https://blog.zsec.uk/cobalt-strike-profiles/](https://blog.zsec.uk/cobalt-strike-profiles/)
* [https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1](https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1)

# Characteristics
Commercial adversary simulation software. Actively used by a wide range of threat actors.

## Components
* Cobalt Strike: C2 application. Has two primary components that are differentiated by what arguments an operator uses to execute it:
    * Team server: C2 server portion. Accepts client connections, BEACON callbacks and general web requests. Accepts client connections on TCP port `50050`. Can only be run on Linux.
    * Client: how operator connect to a team server. Can be on same system as team server or connect remotely.
* BEACON: Cobalt Strike's default malware payload used to create connection to team server. Two types:
    * Stager: optional BEACON payload. Operators can stage the malware by sending an initial small BEACON shellcode payload that does some basic checks and then queries the C2 for the full backdoor.
    * Full backdoor: Can be executed by stager, by loader malware or by executing the default DLL export `ReflectiveLoader`. Runs in memory and establishes connection to C2 through several methods.
* Loaders: anything capable of running shellcode.
* Listeners: component that the payloads use to connect to the team server. Support for several protocols:
    * HTTP/HTTPS: the most common listener type. Default certificate is well known. Malleable profiles to configure how the BEACON network traffic will look.
    * DNS: sessions are established through DNS requests for domains that the team server is authoritative for. Two modes:
        * Hybrid (DNS+HTTP): default. DNS for beacon channel and HTTP for data channel.
        * Pure DNS: DNS for both beacon and data channels. Leverages regular A record requests to avoid using HTTPS and provide a stealthier but slower method of communication.
    * SMB: bind style listener. Used for chaining beacons. Open local port of target system and wait for incoming connection.
    * Raw TCP: can be used for chaining beacons.
    * Foreign listeners: allow connections from Metasploit's Meterpreter backdoor to simplify passing sessions between Metasploit and CS.
    * External C2: provide specification for connecting to a team server with a reverse TCP listener.
* Malleable Profile: modify how the CS installation works.
* Aggressor Scripts: macros that operators can write and load in their client to streamline the workflow. Don't create new BEACON functionality but are used to automate tasks. Are only loaded into an operator's local client.
* Execute-Assembly: BEACON command that allows operators to run a .NET executable in memory on a target host. BEACON runs the executable by spawning a temporary process and injecting the assembly into it. Allow to extend BEACON functionality.
* Beacon Object Files: extend BEACON post-exploitation functionality. Compiled C programs that are executed in memory on a target host. Loaded with a BEACON session and can create new BEACON capabilities. Stealthy as they run within a BEACON session and do not require process creation or injection.

## Concepts
* BEACON Spawn To: each BEACON payload is configured with two `spawn to` processes, 32-bit and 64-bit. Values indicate what the BEACON will spawn as temporary processes for various post-exploitation commands. The BEACON launches the process, injects into it, executes the post-exploitation task and terminates the process. Default: `rundll32.exe`. Can be modified by Malleable Profiles or through the client.
* Sleep Time: base time used for callback intervals. The BEACON will randomize callbacks within a range determined by the `jitter` percentage.

## Capabilities
| Capabilities                           | Documented features/commands                                                                                                                                                                                                                                                              |   |   |   |
|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|---|---|
| Upload and Download payloads and files |   Download <file>   Upload <file>                                                                                                                                                                                                                                                         |   |   |   |
| Running Commands                       |   shell <command>   run <command>   powershell <command>                                                                                                                                                                                                                                  |   |   |   |
| Process Injection                      |   inject <pid>   dllinject <pid> (for reflective dll injection)   dllload <pid> (for loading an on-disk DLL to memory)   spawnto <arch> <full-exe-path> (for process hollowing)                                                                                                           |   |   |   |
| SOCKS Proxy                            | socks <port number>                                                                                                                                                                                                                                                                       |   |   |   |
| Privilege Escalation                   |   getsystem (SYSTEM account impersonation using named pipes)   elevate svc-exe [listener] (creates a services that runs a payload as SYSTEM)                                                                                                                                              |   |   |   |
| Credential and Hash Harvesting         |   hashdump   logonpasswords (Using Mimikatz)   chromedump (Recover Google Chrome passwords from current user)                                                                                                                                                                             |   |   |   |
| Network Enumeration                    |   portscan [targets] [ports] [discovery method]   net <commands> (commands to find targets on the domain)                                                                                                                                                                                 |   |   |   |
| Lateral Movement                       |   jump psexec (Run service EXE on remote host)   jump psexec_psh (Run a PowerShell one-liner on remote host via a service)   jump winrm (Run a PowerShell script via WinRM on remote host)   remote-exec <any of the above> (Run a single command using the above methods on remote host) |   |   |   |
|                                        |                                                                                                                                                                                                                                                                                           |   |   |   |
## Malleable C2
Modify the behavior of the BEACON payload.

## Functionality

### Execution
Post-exploitation tools implemented as Windows DLLs. Every time a threat actors runs the built-in tools, CS spawns a temporary process and used rundll32.exe to inject the malicious code into it and communicates the results back to the beacon using named pipes.
**Watch for command line events that rundll32 is executing without arguments**

CS uses default unique pipe names (can be used for detection). Can be configured through Malleable C2 profiles. Default CS pipes:
* `\postex_*`
* `\postex_ssh_*`
* `\status_*`
* `\msagent_*`
* `\MSSE-*`
* `\*-server`
* `\dce_64`

Can be detected through System EVTX events `17` and `18`. Should be explicitly configured to log named pipes. Deep dive example illustrated [CS detection through named pipes](https://labs.f-secure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis/).

Three additional methods to execute CS beacons:
1. [Using PowerShell to load and inject shellcode directly into memory](https://newtonpaul.com/analysing-fileless-malware-cobalt-strike-beacon/#Injecting_into_memory_with_PowerShell)
2. [Download to disk and execute manually on the target](https://thedfirreport.com/2021/06/28/hancitor-continues-to-push-cobalt-strike/): usually as second stage to some other infection (ie TrickBot, Hancitor etc). CS beacon is loaded into memory by first stage process. Detection:
    * Sysmon
        * Event ID 11: File Creation
        * Event ID 7: Image Loaded
        * Event ID 1: Process Creation
        * Event ID 3: Network Connection
    * Security EVTX
        * Event ID 4663: File Creation
        * Event ID 4688: Process Creation
        * Event ID 5156: Network Connection
3. [Execute the beacon in memory via the initial malware infection](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/): Process injection (`CreateRemoteThread`)

### Defense Evasion
Main method is by `process injection`. Used to inject malicious code into a remote process or inject it into lsass.exe to extract credentials from memory. This spawns a new session in the user context that the injected process belongs to. [Interesting Resource](https://boschko.ca/cobalt-strike-process-injection/). Detection:
* Sysmon
    * Event ID 10: Process accessed
    * Event ID 8: CreateRemoteThread detected. Not present in other methods such as process hollowing.
    * Event ID 3/22: Network query/DNS query

### Discovery
Recon commands executed through the `shell` command. Native Windows tools are preferred. Other tools are AdFind, BloodHound and Powershell modules such as PowerSploit and PowerView.

### Privilege Escalation

#### GetSystem
[Most common technique is the `GetSystem` method via named-pipe impersonation](https://www.cobaltstrike.com/blog/what-happens-when-i-type-getsystem/). [Useful Resource](https://redcanary.com/blog/getsystem-offsec/)

Hunting methods:
* Technique 1 for GetSystem: named pipe impersonation by creating service.
    * Process monitoring
        * parent process is `services.exe`
        * process name is `cmd.exe`
        * command line includes `echo` and `\pipe\`
    * Windows System Event Logs
        * Event ID 7045:
            * ServiceFileName: contains `cmd.exe` or `%COMSPEC%`
            * ServiceFileName: contains `echo` and `\pipe\`
* Technique 2 for GetSystem: named pipe impersonation by dropping dll to disk.
    * Process monitoring
        * process name is `rundll32.exe`
        * command line includes `a /p`

#### Elevate
Uses two options to escalate privileges:
* `svc-exe`: attempts to drop an executable under `C:\Windows` and creates a service to run the payload as SYSTEM.
    * Detection:
        * Sysmon
            * Event ID 11 - File Created: dropped executable under `C:\Windows`
            * Event ID 1 - Process Create
            * Event ID 25 - Process Tampering
            * Event ID 12&13 - Registry value set
        * System EVTX:
            * Event ID 7045 - Service Installation
        * Security EVTX:
            * Event ID 4697 - Service Installation
            * Event ID 4688 - Process Creation
* `uac-token-duplication`: attempts to spawn a new elevated process under the context of a non-privileged user with a stolen token of an existed elevated process.

### Credential Access

#### Hashdump
Dump password hashes. Detection:
* Sysmon:
    * Event ID: 1,8,10,17
* Security EVTX:
    * Event ID 4688 - Process Creation: `rundll32.exe` loads the DLL payload
    * Event ID 4689 - Process Termination

#### Logonpasswords
Dump plaintext credentials and NTLM hashesh with Mimikatz.

### Lateral Movement
Cobalt Strike has several built-in modules for Lateral Movement, divided into `Jump` and `Remote-Exec` modules.
* Jump Modules

| Jump Module| Arch |  Description |
|------|--------|---|
| psexec | x86 | Use a service to run a service exe artifact |
| psexec64 |  x64 | Use a service to run a service exe artifact |
| psexec_sh | x86 | Use a service to run a PowerShell one liner |
| winrm | x86 | Run a PowerShell script via WinRM |
| winrm64 | x64 | Run a PowerShell script via WinRM |

* Remote-Exec Modules

| Remote-Exec Module | Description |
|------|---|
| psexec             | Remote execute via Service Control Manager |
| winrm              | Remote execute via WinRM (PowerShell)      |
| wmi                | Remote execute via WMI (PowerShell)        |

Most frequent techniques:
#### Cobalt Strike `remote-exec` modules
SMB/WMI executable transfer and exec: upload executable to the target host with the CS command `upload` and execute it with `remote-exec`. It can use psexec, winrm or wmi to execute a command/beacon. 

Detection:
* Security EVTX:
    * Event ID 4624 - Logon
        * Type 3
        * Elevated token
    * Event ID 4672 - Special Logon
    * Event ID 4673 - Sensitive Privilege Use
    * Event ID 4688 - Process Creation
    * Event ID 4697 - Security System Extension
        * Randomly named service
        * Running as SYSTEM
    * Event ID 4674 - Sensitive Privilege Use
    * Event ID 5140 - File Share

Built-In methods:
* `remote-exec wmi`: MITRE `T1047 : Windows Management Instrumentation`
    * `wmiprvse.exe` process is spawned with command line `C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding` and parent command line `C:\\Windows\\system32\\svchost.exe -k DcomLaunch`.
    * WMI-Activity Event ID 5857: report the start of WMI provider `cimwin32.dll`
    * Command executed within the context of `wmiprvse.exe`
    * Process Tree:
    ```cmd
    wininit.exe -> services.exe -> svchost.exe -> wmiprvse.exe
    ```
    * Dynamic port range for TCP selected: `49512-65535`
    * Full Telemetry and Detection

    | EID | Action | Provider |  Comment |
    |-----|--------|----------|----------|
    | 1   | Process Creation | Microsoft-Windows-Sysmon | Process Name: `wmiprvse.exe`, Process Command Line: `C:\Windows\System32\wbem\wmiprvse.exe -secured -Embedding`, Parent Process Name: `svchost.exe`, Parent Process Command Line: `C:\Windows\System32\svchost.exe -k DcomLaunch` |
    | 1   | Process Creation | Micorost-Windows-Sysmon  | Parent Process Name: `wmiprvse.exe`, LogonID: not `0x3E7` (Not a local system account) |
    | 3   | Network Connection| Microsoft-Windows-Sysmon | Network Direction: `ingress`, Image: `C:\Windows\system32\svchost.exe`, Source Port: `>= 49152`, Source IP: not `127.0.0.1` and not `::1` |
* `remote-exec winrm`: MITRE `T1021.006 Remote Services: Windows Remote Management`. Not made for creating and maintaining a remote session so `wsmprovhost.exe` terminates after execution.
    * Process Tree
    ```cmd
    wininit.exe -> services.exe -> wsmprovhost.exe (Terminated) -> [remote command].exe (Terminated) -> connhost.exe (Terminated)
    ```
    * Full Telemetry and Detection

    | EID | Action | Provider |  Comment |
    |-----|--------|----------|----------|
    | 1   | WSMan Session Creation | Microsoft-Windows-Sysmon | Process Name: `wsmprovhost.exe`, Process CMD: `C:\Windows\system32\wsmprovhost.exe -Embedding`, Process Parent Name: `svchost.exe`, Process Parent CMD: `C:\Windows\System32\svchost.exe -k DcomLaunch` |
    | 3   | WSMan Session Creation | Microsoft-Windows-Sysmon | Network Direction: `ingress`, Process Name: `System`, Destination Port: `5985` or `5986`, User: `NT AUTHORITY/SYSTEM` |
    | 17  | Pipe Created | Microsoft-Windows-Sysmon | Network Direction: `egress`, Infected Source Process Name, Destination Port: `5985` or `5986`, Pipe Name: `\PSHost.[%NUMBERS%].[%PID%].DefaultAppDomain.wsmprovhost`, Process Name: `wsmprovhost.exe` |
    | 4656| Process Access | Microsoft-Windows-Security-Auditing | Object Server: WS-Management Listener, Process Name: `C:\Windows\System32\svchost.exe` |
    | 400 | Process Session Start | PowerShell | Host Name: `ServerRemoteHost`, Engine Version, Host Application: `C:\Windows\System32\wsmprovhost.exe -Embedding` |
    | 91  | WSMan Session Creation | Microsoft-Windows-WinRM | |
    | 31  | WSMan Session Creation | Microsoft-Windows-WinRM | WSMan Session Created successfully |
    | 142 | WSMan Operation Failure | Microsoft-Windows-WinRM | |
* `remote-exec psexec`: MITRE `T1570 : Lateral Transfer Tool`. Creates and start a service remotely with random Service Name and the passed on command as Service File Name. Does not generate a service executable and upload it to the target. CS's service file name spawns `rundll32.exe` with no arguments.
    * Detection:
        * Monitor `services.exe` for malicious behavior like spawning system shells like `cmd.exe` and `powershell.exe` or other discovery binaries.


#### `pass the hash`

MITRE `T1550.002 Use Alternate Authentication Material: Pass the Hash`
Uses Mimikatz to generate and impersonate a token that can later be used to accomplish tasks in the context of that chosen user resource. The BEACON can also use this token to interact with network resources and run remote commands. Detection:
* Security EVTX:
    * Event ID 4624 - Logon
        * Type 9
        * Logon Process: seclogo
        * Authentication Package: Negotiate
CS will run cmd.exe to pass the token back to the beacon process via a named pipe:
```cmd
C:\Windows\system32\cmd.exe /c echo 0291f1e69dd > \\.\pipe\82afc1
``` 

#### Cobalt Strike `jump` modules
Creates a remote service and executes the service exe beacon. To do this it creates a service executable and transfers it to the target via SMB to the ADMIN$ share. Uses RPC calls to open handle to `svcctl` for remotely creating the new service.

Detection:
* Security EVTX:
    * Event ID 4624 - Logon
    * Event ID 4672 - Special Logon
    * Event ID 4673 - Sensitive Privilege Use
    * Event ID 4688 - Process creation
    * Event ID 5140 - File Share
    * Event ID 4674 - Sensitive Privilege Use
    * Event ID 4697 - A service was installed on the system.
* System EVTX:
    * Event ID 7045 - A service was installed on the system.
    * Event ID 7034 - A service terminated unexpectedly.

Built-In methods:
* `jump winrm`: Event IDs generated when using WinRM remotely. MITRE: `T1021.006 Remote Services: Windows Remote Management`
    * Source Events

    | EID | Action | Provider |  Comment |
    |-----|--------|----------|----------|
    | 6   | WSMan Session Creation | Microsoft-Windows-WinRM | Create WSMan session. Will give the PID that initiated the connection |
    | 31  | WSMan Session Creation | Microsoft-Windows-WinRM | WSMan session created successfully |
    | 3   | Network Connection | Microsoft-Windows-Sysmon | Network Direction: egress, Infected source process name, Destination port: 5985 or 5986 |

    * Destination Events

    | EID | Action | Provider |  Comment |
    |-----|--------|----------|----------|
    | 1   | WSMan Session Creation | Microsoft-Windows-Sysmon | Process Name: `wsmprovhost.exe`, Process CMD: `C:\Windows\System32\wsmprovhost.exe -e Embedding`, Process Parent Name: `svchost.exe`, Process Parent CMD: `C:\Windows\System32\svchost.exe -k DcomLaunch` |
    | 3  | WSMan Session Creation | Microsoft-Windows-Sysmon | Network Direction: ingress, Process Name: system, Destination port: 5985 or 5986, User: `NT AUTHORITY\SYSTEM`|
    | 17   | Pipe Created | Microsoft-Windows-Sysmon | Network Direction: egress, Infected source process name, Destination port: 5985 or 5986, Pipe Name: `.\PSHost.[%Numbers%].[%PID%].DefaultAppDomain.wsmprovhost`, Process Name: `wsmprovhost.exe` |
    | 4656 | Process Access | Microsoft-Windows-Security-Auditing | Object Server: WS-Management Listener, Process Name: `C:\Windows\System32\svchost.exe` |
    | 400 | PowerShell Session Start | PowerShell | Host Name: ServerRemoteHost (Remote PowerShell Session), Engine Version, Host Application: `C:\Windows\System32\wsmprovhost.exe -Embedding` |
    | 91 | WSMan Session Creation | Microsoft-Windows-WinRM | 
    | 31 | WSMan Session Creation | Microsoft-Windows-WinRM | WSMan session created successfully |
    | 142 | WSMan Operation Failure | Microsoft-Windows-WinRM | 
    
    The beacon runs under the context of the PowerShell instance invoked by wsmprovhost.exe. The powershell.exe instance will run via the commandline `C:\Windows\Syswow64\windowspowershell\v1.0\powershell.exe -Version 5.1 -s -NoLogo -NoProfile`.

    Process Tree
    ```cmd
    jump winrm -> svchost.exe (C:\Windows\System32\svchost.exe -k DcomLaunch) -> wsmprovhost.exe (C:\Windows\System32\wsmprovhost.exe -Embedding) -> powershell.exe (C:\Windows\Syswow64\windowspowershell\v1.0\powershell.exe -Version 5.1 -s -NoLogo -NoProfile) -> cmd.exe (C:\Windows\System32\cmd.exe /C [COMMAND]) -> target.exe
    ```

    [YARA rule for detecting stageless beacons](https://github.com/airbnb/binaryalert/blob/master/rules/public/hacktool/windows/hacktool_windows_cobaltstrike_beacon.yara)

    Events to look for:
    * Event ID 4103 - Module Logging
    * Event ID 4104 - Script Block Logging
    * Event ID 142 - WSMan operation CreateShell failed
    * Event ID 169 - User authenticated sucessfully
    * Event ID 81 - Processing client request for operation CreateShell (Start of remoting activity)
    * Event ID 134 - Sending Response for Operation DeleteShell (End of remoting)
    * Event ID 403 - Engine state changed from Available to Stopped

    Command to enumerate active WinRM sessions:
    ```powershell
    Get-WSManInstance -ComputerName localhost -ResourceURI shell -Enumerate
    ```
* `jump winrm64`: Executes within the context of a `wsmprovhost.exe` instance. The session is permanent with no termination of the process. Process Tree:
```cmd
jump winrm64 -> svchost.exe (C:\Windows\System32\svchost.exe -k DcomLaunch)-> wsmprovhost.exe (C:\Windows\System32\wsmprovhost.exe -Embedding) -> cmd.exe (C:\Windows\System32\cmd.exe /C [COMMAND]) -> target.exe
```
* `jump psexec && jump psexec64`: MITRE `T1570 : Lateral Transfer Tool`. Modules use named pipes (RPC/NP) method to interact with the service control manager RPC server. The server interface is identified by UUID `367ABB81-9844-35F1-AD32-98F038001003` and uses RPC endpoint `\\PIPE\\svcctl`. Operations and generated artifacts:
    * Operations on `svcctl` endpoint:
        * `OpenSCManagerW`
        * `CreateServiceWOW64A`
        * `StartServiceA`
        * `DeleteService`
        * `CloseServiceHandle`
    * On the target:
        * Security EVTX:
            * Event ID 5145: Network share object was checked to see whether client can be granted desired access. Relative Target Name is defined as `svcctl` and share name `\*\IPC$`.
            * Event ID 4697 - A new service was installed on the system: Calls `\\127.0.0.1\ADMIN$\[SERVICE_RANDOM_NAME].exe`, This is executed and invokes `rundll32.exe` with no arguments.
        * System EVTX:
            * Event ID 7045 - New service was installed
            
        * Process Tree
        ```cmd
        jump psexec -> services.exe (C:\Windows\System32\services.exe)-> random.exe (\\127.0.0.1\ADMIN$\random.exe) -> rundll32.exe (C:\Windows\System32\rundll32.exe) -> cmd.exe
        ```
    * Full Telemetry and Detection

    | EID | Action | Provider |  Comment |
    |-----|--------|----------|----------|
    | 5145| Network Share Access | Microsoft-Windows-Security-Auditing | Relative Target Name: `svcctl`, Share Name: `\*\IPC$` |
    | 7045| Service Creation | System | Service File Name: `\\127.0.0.1\ADMIN$\[SERVICE RANDOM NAME].exe` |
    | 4697| Service Creation | Microsoft-Windows-Security-Auditing | Service File Name: `\\127.0.0.1\ADMIN$\[SERVICE RANDOM NAME].exe` |
    | 1 | Process Creation | Microsoft-Windows-Sysmon | Command Line: `\\127.0.0.1\ADMIN$\[SERVICE RANDOM NAME].exe`, Parent Command Line: `C:\Windows\System32\services.exe` |
    | 1 | Process Creation | Microsoft-Windows-Sysmon | Command Line: `C:\Windows\System32\rundll32.exe`, Argument Count: 0, Parent Process: `\\127.0.0.1\ADMIN$\[SERVICE RANDOM NAME].exe` |
    | 13 | Registry Value Set | Microsoft-Windows-Sysmon | Image Path: `\\127.0.0.1\ADMIN$\[SERVICE RANDOM NAME].exe` |
* `jump psexec_psh`: PowerShell version of PsExec. Everything executed in memory via a one-liner.
    * Same operations as psexec and psexec64 on `svcctl` endpoint.
    * Service Creation:
        * Security Event ID 4697: `%COMSPEC%` and `powershell` in the `Service File Name`.
        * System Event ID 7045
    * PowerShell Event ID 400: `HostApplication` contains `powershell -nop -w -hidden -encodedcommand`
    * Pipe creation with regex pattern `status_[0-9a-f]{2}`.
        * Security Event ID 5145 - A network share object was checked to see whether client can be granted desired access.
    * Process Tree
    ```cmd
    jump psexec_psh -> services.exe (C:\Windows\System32\services.exe)-> cmd.exe (C:\Windows\System32\cmd.exe) -> powershell.exe (C:\Windows\System32\powershell.exe) -> cmd.exe
    ```
    * Full Telemetry and Detection

    | EID | Action | Provider |  Comment |
    |-----|--------|----------|----------|
    | 5145| Network Share Access | Microsoft-Windows-Security-Auditing | Relative Target Name: `status_[0-9a-f]{2}` |
    | 7045| Service Creation | System | Service File Name contains `%COMSPEC%` or `powershell` |
    | 4697| Service Creation | Microsoft-Windows-Security-Auditing | Service File Name contains `%COMSPEC%` or `powershell` |
    | 17  | Pipe Created     | Microsoft-Windows-Sysmon | Command Line: `\\127.0.0.1\ADMIN$\[SERVICE_RANDOM_NAME].exe`, Parent Command Line: `C:\Windows\System32\services.exe` |
    | 18  | Pipe Connected   | Microsoft-Windows-Sysmon | Image Path: `\\127.0.0.1\ADMIN$\[SERVICE_RANDOM_NAME].exe` | 
    | 1   | Process Creation | Microsoft-Windows-Sysmon | Command Line Arguments: `powershell, -nop, hidden, -encodedcommand`, Process Name: `powershell.exe`, Parent Process Name: `cmd.exe` |

# Named Pipe List

| Regex                                        | Source                                      |
|----------------------------------------------|---------------------------------------------|
| MSSE-[0-9a-f]{3}-server                      | Default Cobalt Strike Artifact Kit binaries |
| status_[0-9a-f]{2}                           | Default psexec_psh                          |
| postex_ssh_[0-9a-f]{4}                       | Default SSH beacon                          |
| msagent_[0-9a-f]{2}                          | Default SMB beacon                          |
| postex_[0-9a-f]{4}                           | Default Post Exploitation job (v4.2+)       |
| mojo.5688.8052.183894939787088877[0-9a-f]{2} | jquery-c2.4.2.profile                       |
| mojo.5688.8052.35780273329370473[0-9a-f]{2}  | jquery-c2.4.2.profile                       |
| wkssvc[0-9a-f]{2}                            | jquery-c2.4.2.profile                       |
| ntsvcs[0-9a-f]{2}                            | trick_ryuk.profile                          |
| DserNamePipe[0-9a-f]{2}                      | trick_ryuk.profile                          |
| SearchTextHarvester[0-9a-f]{2}               | trick_ryuk.profile                          |
| ntsvcs                                       | zloader.profile                             |
| scerpc                                       | zloader.profile                             |
| mypipe-f[0-9a-f]{2}                          | havex.profile                               |
| mypipe-h[0-9a-f]{2}                          | havex.profile                               |
| windows.update.manager[0-9a-f]{2}            | windows-updates.profile                     |
| windows.update.manager[0-9a-f]{3}            | windows-updates.profile                     |
| ntsvcs_[0-9a-f]{2}                           | salesforce_api.profile                      |
| scerpc_[0-9a-f]{2}                           | salesforce_api.profile                      |
| scerpc[0-9a-f]{2}                            | zoom.profile                                |
| ntsvcs[0-9a-f]{2}                            | zoom.profile                                |
