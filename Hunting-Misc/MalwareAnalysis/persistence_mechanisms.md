# Persistence Mechanisms

> Paolo Coba | 04/03/2021

-------------------------------------------

# Windows

## Resources
* [https://resources.infosecinstitute.com/topic/common-malware-persistence-mechanisms/](https://resources.infosecinstitute.com/topic/common-malware-persistence-mechanisms/)
* [https://github.com/Karneades/malware-persistence](https://github.com/Karneades/malware-persistence)
* [https://www.hexacorn.com/blog/category/autostart-persistence/](https://www.hexacorn.com/blog/category/autostart-persistence/)
* [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)
* [https://pentestlab.blog/tag/persistence/](https://pentestlab.blog/tag/persistence/)
* [http://www.fuzzysecurity.com/tutorials/19.html](http://www.fuzzysecurity.com/tutorials/19.html)
* [https://www.mandiant.com/resources/dissecting-one-ofap](https://www.mandiant.com/resources/dissecting-one-ofap)
* [https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96)

## Modify Registry keys

### Run/RunOnce keys
* User Level
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
    * `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* System Level
    * `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
    * `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
    * `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`

### BootExecute key
`smss.exe` launches before the Windows subsystem loads. It calls the configuration subsystem to load the hive present at `HKLM\System\CurrentControlSet\Control\hivelist`. Will also launch anything present in the BootExecute key in `HKLM\System\CurrentControlSet002\Control\SessionManager`. This should always have the value of `autocheck autochk*`.

### Keys used by WinLogon process
* UserInit key: used to launch login scripts. Located at `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`. Must point to `C:\Windows\System32\userinit.exe`.
* Notify key: Winlogon handles `Secure Attention Sequence`. Notify subkeys are used to notify event handles when SAS happens and loads a DLL. The DLL can be edited to launch whenever a SAS event occurs. The key is found at `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`.
* Explorer.exe: Pointed by key at `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`. Points to `explorer.exe`, not with the complete path since it launches from windows. The pointer is located in `HKLM\Software\Microsoft\Windows NT\CurrentVersion\InitFileMapping\system.ini\boot`.
* Startup Keys: any shortcut created to the location pointed by subkey Startup will launch the service during a logon.
    * User Level
        * `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
        * `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
    * System Level
        * `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
        * `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* Services: 
    * Several methods:
        * `HKLM\System\CurrentControlSet\Services`: Add to startup services.
        * Load a malicious file if a service fails to start by specifying Recovery options.
        * Launch background services:
            * `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
            * `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* Browser Helper Objects: dll module loaded when Internet Explorer starts up. Located at `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* AppInit_DLLs: key located at `HKLM\Software\Microsoft\Windows NT\CurrentVersion\WindowsAppInit_DLLs`. Will show the DLLs loaded by the `User32.dll`
* File Association keys: Located at `HKLM\Software\Classes` and `HKR`. Keys specify the action when a certain kind of file is opened.

## DLL Search Order Hijacking

Hijack the way the OS loads DLLs. Whenever an exe loads, it follows a certain path search to load the required DLLs. Since DLLs are loaded in the order the directories are parsed, it is possible to add a malicious DLL with the same name in a directory earlier than the directory where the legit DLL resides.

If Safe DLL search mode is enabled then the OS will check whether the DLL is already loaded in memory or if it is part of the Known DLLs registry key at `HKLM\System\CurrentControlSet\Control\SessionManager\KnownDLLs`

DLL search order:
* Directory from where the application was launched.
* C:\Windows\System32
* Windows Directory
* Current Working Directory
* Directories defined in the PATH variable.

## Shortcut Hijacking

Hijack the shortcut icons Target attribute. The shortcut icon can be forced to download content from an evil site.

## Scheduled Backdoors

Run tasks with different permission sets and trigger the task using events or at specific time intervals.

### Schtasks:
* Run daily tasks
```cmd
schtasks /create /tn <sometask> /tr <command> /sc daily /st <time>
```
* Run a task each time the user's session is idle for 5 minutes
```cmd
schtasks /create /tn <sometask> /tr <command> /sc onidle /i 5
```
* Run a task as SYSTEM each time a user logs in
```cmd
schtasks /create /run "NT AUTHORITY\SYSTEM" /rp "" /tn <sometask> /tr <command> /sc onlogon
```
* Run a task everytime a user logs off the system
```cmd
wevtutil qe Security /f:text /c:1 /q:"Event[System[(EventID=4647)]] //check last recorded User initiated Logoff

schtasks /create /tn OnLogOff /tr <command> /sc ONEVENT /ec Security /MO "*[System[(Level=4 or Level=10) and (EventID=4634)]]"
```


## WMI Permanent Event Subscription // Managed Object Formats (MOF)

MOFs are compiled scripts that describe CIM classes which are compiled into the WMI repository. A MOF file must consist of three components:
* `__EventFilter`: uses WMI Query Language to detect a specific event.
```cmd
instance of __EventFilter as $EventFilter
{
    Name = "Event Filter Name";
    EventNamespace = "Root\\Cimv2";
    Query = "WQL-Query";
    QueryLanguage = "WQL";
};
```
Example Query: 
```cmd
# Notice that we are checking for an instance creation where the event code is 4624 and the message
property contains "User32".
Query = "SELECT * FROM __InstanceCreationEvent Within 5"
    "Where TargetInstance Isa \"Win32_NTLogEvent\" "
    "And Targetinstance.EventCode = \"4624\" "
    "And Targetinstance.Message Like \"%User32%\" ";
```
* `Event Consumer Class`: defines actions.
    * `ActiveScriptEventConsumer`: allows the execution of VBS payloads
    ```cmd
    instance of ActiveScriptEventConsumer as $consumer
    {
        Name = "Event Consumer Name";
        ScriptingEngine = "VBScript";
        ScriptText = "<vbs payload>";
    };
    ```
    * `CommandLineEventConsumer`: executes terminal commands
    ```cmd
    instance of CommandLineEventConsumer as $consumer
    {
        Name = "Event Consumer Name";
        RunInteractively = false;
        CommandLineTemplate = "<payload>";
    };
    ```
* `__FilterToConsumerBinding`: binds an event and an action.
```cmd
instance of __FilterToConsumerBinding
{
    Filter = $filter;
    Consumer = $consumer;
}
```

MOF compilation
* Local: needs to have pragma namespace set: `("\\\\\\root\\subscription")`
```cmd
mofcomp.exe .\<mof file>
```

* Remote: namespace is specified in command line
```cmd
mofcomp.exe -N \\<Destination>\root\subscription .\<mof file>
```

To check succesfull deployment:
```powershell
Get-WmiObject -namespace root\subscription -Class __EventFilter -Filter "name=<Event Filter name>
```

To create with PowerShell: [https://gist.github.com/infosecn1nja/d9a42a68e9d3671e1fbadee5d7dc8964](https://gist.github.com/infosecn1nja/d9a42a68e9d3671e1fbadee5d7dc8964)

### Detection
* Sysmon: can be configured to log `WmiEventFilter`, `WmiEventConsumer` and `WmiEventConsumerToFilter`
    * Event ID 19
    * Event ID 20
    * Event ID 21
* Autorins: check `WMI` tab.
* PowerShell:
    * Event Filter
    ```powershell
    Get-WMIObject -namespace root\subscription -Class __EventFilter -Filter "Name=<Event filter name>
    ```
    * Event Consumer
    ```powershell
    Get-WMIObject -namespace root\subscription -Class CommandLineEventConsumer -Filter "Name=<Event Filter name>"
    ```
    * Binding
    ```powershell
    Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE <Event Filter name>"
    ```
