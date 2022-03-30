# Windows ShimCache Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://bromiley.medium.com/windows-wednesday-shim-cache-1997ba8b13e7](https://bromiley.medium.com/windows-wednesday-shim-cache-1997ba8b13e7)
* [https://www.mandiant.com/resources/caching-out-the-val](https://www.mandiant.com/resources/caching-out-the-val)

## Characteristics

Windows tracks information about programs that have recently been examined by the system for compatibility issues in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`. The data contained in the key reveals information about executables on the system:
* Path of the executable
* Last modified time from `$STANDARD_INFORMATION`
* Flag indicating whether the program has been executed.
Entries appear in chronological order based on the time the executable was run/examined.
The data in the `AppCompatCache` value is written to the registry hive file only upon system shutdown. The registry hive is found in `C:\Windows\System32\config\SYSTEM`.

## Tools
* [AppCompatCacheParser](https://ericzimmerman.github.io)
* [RegRipper](https://github.com/keydet89/RegRipper3.0)
* [Mandiant's ShimCacheParser](https://github.com/mandiant/ShimCacheParser)

### Usage
* ShimCacheParser
```cmd
python shimcacheparser.py -i <hive>
```
* RegRipper
```cmd
rip.exe -r <hive> -p <appcompatcache | appcompatcache_tln>
```
* AppCompatParser
```cmd
AppCompatParser.exe -f <hive> --csv <path> --csvf <filename>
```