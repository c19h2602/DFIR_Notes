# NTFS Forensics Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://www.youtube.com/watch?v=_qElVZJqlGY](https://www.youtube.com/watch?v=_qElVZJqlGY)
* [http://forensicinsight.org/wp-content/uploads/2013/07/F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf](http://forensicinsight.org/wp-content/uploads/2013/07/F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf)
* [https://community.netwitness.com/t5/netwitness-community-blog/do-you-mft-here-s-an-mft-overview/ba-p/519885](https://community.netwitness.com/t5/netwitness-community-blog/do-you-mft-here-s-an-mft-overview/ba-p/519885)

## Tools
* [https://github.com/EricZimmerman/MFTECmd](https://github.com/EricZimmerman/MFTECmd)
* RSA's standalone MFT viewer.
* [https://github.com/dkovar/analyzeMFT](https://github.com/dkovar/analyzeMFT)

## NTFS Filesystem

NTFS is the default filesystem on Windows systems. Important to extract as much state information as possible.

* $MFT: Master File Table of the NTFS filesystem. Keeps records of all file entries in the volume. There is at least one entry in the MFT for every file on an NTFS file system volume, including the MFT itself. All information about a file, including its size, time and date values, permissions, and data content, is stored either in MFT entries, or in space outside the MFT that is described by MFT entries.  Files and directories with size less than 512 bytes are written directly to the MFT.

* Journal Files: Transactional record of all changes made to a volume. Used by the OS to roll back or undo changes in the event of a crash or power failure. Goal is to maintain filesystem integrity and prevent catastrophic events from happening.

## MACB Timestamps
* M: Modification timestamp 
* A: Access
* C: MFT record changes: can also be E. Keeps track of changes made to the MFT record itself.
* B: Birth/Creation: can also be C

Stored in the $MFT file. More than one copy in the MFT:
* `$STANDARD_INFORMATION ($SI)`: stores file metadata such as flags, file SID, file owner and a set of MAC(b) timestamps. It is the timestamp collected by Windows Explorer, fls, mactime, timestomp and other utilities. Can be modified by user-level processes. Associated to the file object itself.
* `$FILE_NAME ($FN)`: only modifiable by the Windows Kernel. Associated with the filename of the object.

### Windows Time Rules
* File Creation:
    * $SI:
        * Changes all MACB: Time of file creation
    * $FN:
        * Changes all MACB: Time of file creation
* File Access:
    * $SI:
        * Changes A: Time of access
        * No changes to MCB
    * $FN:
        * No changes to MACB
* File Modification:
    * $SI:
        * Changes to MAC: Time of data modification
        * No changes to B
    * $FN:
        * No changes to MACB
* File Rename:
    * $SI:
        * Changes C: Time of rename
        * No changes to MAB
    * $FN
        * No changes to MACB
* File Copy:
    * $SI
        * No changes to M: Inherits time from original
        * Changes to ACB: Time of file copy
    * $FN
        * Changes to MACB: Time of file copy
* Local File Move
    * $SI:
        * No changes to MAB
        * Changes to C: Time of local file move.
    * $FN:
        * No changes to MACB
* Volume File Move via CLI
    * $SI:
        * No changes to MC: Inherited from the original
        * Changes to AB: Time of file move via cli.
    * $FN:
        * Changes to MACB: Time of file move via cli.
* Volume File Move (graphical)
    * $SI:
        * No changes to MCB: Inherited from the original
        * Changes to A: Time of cut/paste.
    * $FN:
        * Changes to MACB: Time of cut/paste.
* File Deletion:
    * $SI:
        * No changes to MACB
    * $FN:
        * No changes to MACB

## Journal Files
* `USNJOURNAL`
    * `$EXTEND\$USNJRNL`: Contains additional data attributes.
        * `$MAX`
        * `$J`: Begins life when the volume is created as an empty file. Tracks changes to files and directories alongside the reason for the change. Stored as sparse file. Typical size is `32 MB`. Contains valuable information such as:
            * USN ID: offset of the record within the file. Unique id of the USN record.
            * Timestamp: timestamp for file modification.
            * Reason for modification: some example opcodes are:
                * FileCreate
                * FileDelete
                * RenameOldName
                * RenameNewName
                * DataOverwrite
            * Filename of the file that is being affected.
            * Parent MFT ID that points to the parent record within the MFT.
        * **When is it useful**
            * Insight on when programs are run by seeing the modification of prefetch files giving the timestamp of execution.
            * File modification or creation of a particular file extension.
            * Provide time of initial infection: check when initial malware file was run.
            * Evidence of deleted files.
        
* `LOGFILE`:
    * `$LOGFILE`: tracks changes to MFT metadata such as timestamps. Typical size is `32M`. Some example opcodes are:
        * AddIndexEntryAllocation
        * InitializeFileRecordSegment
        * DeleteIndexEntryAllocation

### Forensic Operations on Journal Files

* **Important**: when extracting Journal files remove `system` and `hidden` attributes:
```cmd
attrib -s -h <journal>
```
* Use `MFTECmd` to parse to csv
```cmd
MFTEcmd.exe -f <file> --csv <path> --csvf <outfile>
```
* Use `TimelineExplorer` to view results

