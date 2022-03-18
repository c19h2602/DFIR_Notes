# Malware Persistence Mechanisms

> Paolo Coba | 04/03/2021

-------------------------------------------

# Windows

## Resources
* [https://resources.infosecinstitute.com/topic/common-malware-persistence-mechanisms/](https://resources.infosecinstitute.com/topic/common-malware-persistence-mechanisms/)
* [https://github.com/Karneades/malware-persistence](https://github.com/Karneades/malware-persistence)
* [https://www.hexacorn.com/blog/category/autostart-persistence/](https://www.hexacorn.com/blog/category/autostart-persistence/)
* [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)
* [https://pentestlab.blog/tag/persistence/](https://pentestlab.blog/tag/persistence/)

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