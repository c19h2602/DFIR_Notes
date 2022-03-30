# Windows Shellbags Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://www.4n6k.com/2013/12/shellbags-forensics-addressing.html](https://www.4n6k.com/2013/12/shellbags-forensics-addressing.html)
* [https://www.youtube.com/watch?v=YvVemshnpKQ](https://www.youtube.com/watch?v=YvVemshnpKQ)
* [https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags//](https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags//)
* [https://www.sans.org/white-papers/34545/](https://www.sans.org/white-papers/34545/)

## Shellbag Forensics
Purpose is to help track views, sizes and positions of a folder window when viewed through Windows Explorer. Includes network folders and removable devices.

Provides insight into the folder, browsing history of a suspect as well as details for any folder that might no longer exist on a system. Information contains:
* Full path
* Type of object
* MAC timestamps
* Information on subfolders

Locations:
* Windows Vista and later:
    * `NTUSER.dat` registry hive:
        * `HKCU\Software\Microsoft\Windows\Shell\Bags`: Contains numbered subkeys for each hierarchical child subkey under BagMRU.
        * `HKCU\Software\Microsoft\Windows\Shell\BagMRU`: stored in hierarchical order similar to Windows Explorer. Each numbered folder represents a parent or child folder of the previous. Three keys:
            * `MRUListEx`: 4-byte value indicating the order in which each child folder under BagMRU hierarchy was last accessed.
            * `NodeSlot`: Bags key and the particular view setting that is stored there for that folder.
            * `NodeSlots`: only found in the root BagMRU subkey. Updated when a new shellbag is created.
    * `UsrClass.dat` hive:
        * `HKCU\Software\Classes`
        * Hive location: `C:\Users\<username>\AppData\Local\Microsoft\Windows`
        * `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
        * `Local Settings\Software\Microsoft\Windows\Shell\Bags`
* Windows XP:
    * Local Folders
        * `NTUSER.dat\Software\Microsoft\Windows\ShellNoRoam`
    * Network Folders
        * `NTUSER.dat\Software\Microsoft\Windows\Shell`
    * Removable Drives
        * `NTUSER.dat\Software\Microsoft\Windows\StreamMRU`

Provide the timestamp details including last accessed times of the folders being examined.

Exploring zip file also creates shellbag artifacts.

## Tools
* [Zimmerman's ShellbagExplorer](https://ericzimmerman.github.io/#!index.md)
    * `SBECmd.exe`: command line
    ```cmd
    SBECmd.exe (-l <liveregistry>) (-d <bags file location>) --csv <location>
    ```
    * `ShellBagsExplorer`: GUI version
