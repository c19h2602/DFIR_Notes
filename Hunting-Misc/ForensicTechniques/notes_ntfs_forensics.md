# NTFS Forensics Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://www.youtube.com/watch?v=_qElVZJqlGY](https://www.youtube.com/watch?v=_qElVZJqlGY)

## Tools
* [https://github.com/EricZimmerman/MFTECmd](https://github.com/EricZimmerman/MFTECmd)
* RSA's standalone MFT viewer.

## Filesystem Journaling

Transactional record of all changes made to a volume. Used by the OS to roll back or undo changes in the event of a crash or power failure. Goal is to maintain filesystem integrity and prevent catastrophic events from happening.

## Files
* `USNJOURNAL`
    * `$EXTEND\$USNJRNL`: Contains additional data attributes.
        * `$MAX`
        * `$J`: tracks changes to files and directories alongside the reason for the change. Stored as sparse file. Typical size is `32 MB`. Some example opcodes are:
            * FileCreate
            * FileDelete
            * RenameOldName
            * RenameNewName
            * DataOverwrite
* `LOGFILE`:
    * `$LOGFILE`: tracks changes to MFT metadata such as timestamps. Typical size is `32M`. Some example opcodes are:
        * AddIndexEntryAllocation
        * InitializeFileRecordSegment
        * DeleteIndexEntryAllocation

## Operations

* **Important**: when extracting Journal files remove `system` and `hidden` attributes:
```cmd
attrib -s -h <journal>
```
* Use `MFTECmd` to parse to csv
```cmd
MFTEcmd.exe -f <file> --csv <path> --csvf <outfile>
```
* Use `TimelineExplorer` to view results