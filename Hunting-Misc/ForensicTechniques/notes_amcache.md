# Windows AmCache Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://www.forensafe.com/blogs/amcache.html](https://www.forensafe.com/blogs/amcache.html)
* [https://commons.erau.edu/jdfsl/vol11/iss4/7/](https://commons.erau.edu/jdfsl/vol11/iss4/7/)

## Characteristics

Windows system file that stores information on program execution. Located in `C:\Windows\AppCompat\Program\AmCache.hve`. The stored information includes:
* Path of the executable
* File size
* First time the program was executed
* First installation time
* Time the program was uninstalled
* SHA1 hash value of the executable

## Tools
* [AmcacheParser](https://ericzimmerman.github.io)
* [RegRipper plugin](https://github.com/keydet89/RegRipper3.0)

### Usage
* RegRipper
```cmd
rip.exe -r <Amcache> -p amcache
```
* AmcacheParser
```cmd
AmcacheParser.exe -f <Amcache> --csv <path> --csvf <name>
```
