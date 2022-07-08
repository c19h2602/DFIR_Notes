# Browser Forensics Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://resources.infosecinstitute.com/topic/browser-forensics-google-chrome/](https://resources.infosecinstitute.com/topic/browser-forensics-google-chrome/)
* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://book.hacktricks.xyz/forensics/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts](https://book.hacktricks.xyz/forensics/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts)
* [https://ohyicong.medium.com/how-to-hack-chrome-password-with-python-1bedc167be3d](https://ohyicong.medium.com/how-to-hack-chrome-password-with-python-1bedc167be3d)
* [https://medium.com/geekculture/how-to-hack-firefox-passwords-with-python-a394abf18016](https://medium.com/geekculture/how-to-hack-firefox-passwords-with-python-a394abf18016)

## Tools
* [DB Browser](https://sqlitebrowser.org/dl/)
* [Nirsoft Web Browser Tools](https://www.nirsoft.net/web_browser_tools.html)
* [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
* [Hindsight](https://github.com/obsidianforensics/hindsight)
* [libesedb](https://github.com/libyal/libesedb)


## Google Chrome

### Windows

* Profile Path: contains the majority of the artifacts and profile data.
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data`
* Downloads, Navigation History, Search History: stored in SQLite Database
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\History`
* Cookies: SQLite Database
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Cookies`
* Cache
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cache`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Cache`
* Bookmarks: Stored in JSON Format
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Bookmarks`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Bookmarks`
* Form History: Stored in SQLite Format
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Web Data`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Web Data`
* Favicons: Stored in SQLite Format
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Favicons`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Favicons`
* Logins: Stored in SQLite Format
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Login Data`
* Sessions Data
    * Combined
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Sessions`
    * Current Sessions/Tabs
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Current Session`
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Current Session`
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Current Tabs`
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Current Tabs`
    * Previous Sessions/Tabs
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Last Session`
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Last Session`
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Last Tabs`
        * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Last Tabs`
* Addons / Extensions: Stored as Folders
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Extensions`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Data\Extensions`
* Thumbnails: Stored in SQLite format
     `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Top Sites`
    * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Thumbnails`

#### Getting Saved Credentials

Chrome uses `AES GCM` encryption. It saves AES passwords in a file inside the AppData folder called `Local State`. Concatenates the IV with the ciphertext and saves them in a file inside the AppData folder named `Login Data`.
Four main steps to decrypt Chrome passwords:
1. Find encryption key
    * Stored in `C:\Users\<pc>\AppData\Local\Google\Chrome\User Data\Local State` in `os_crypt.encrypted_key`. Is is Base64 encoded.
        * Cannot be decrypted if user is not current user. Need to crack user Master Key.
            * Locate Master Key: `%AppData%\Microsoft\Protect\<SID>`. Will have both SID and master key file.
            * Extract user hash with [DPAPIlmk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) and crack it with john/hashcat.
            ```cmd
            python DPAPIlmk2john.py --sid=<sid> --masterkey=<path to mk file> --context="local"
            ```
            * Use `mimikatz` to decrypt the master key
            ```cmd
            dpapi::masterkey /in:<path to mk file> /sid:<sid> /password:<cracked password> /protected
            ```
            * Decrypt the encryption key with `mimikatz`
            ```cmd
            dpapi::blob /masterkey:<decrypted mk> /in:<encrypted key> /out:<decrypted key file>
            ```
2. Get ciphertext passwords from `Login Data` SQLite db (`C:\Users\<PC Name>\AppData\Local\Google\Chrome\User Data\Default\Login Data`)
3. AES parameters:
    * IV: ciphertext[3:15]
    * Encrypted Password: ciphertext[15:-16]
4. Use IV and decrypted key to decrypt password with [AES GCM](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'GCM','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D))

### Linux
* Profile:
    * `~/.config/google-chrome/`
* Rest same as Windows

## Mozilla Firefox

### Windows

* Profile Path
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default`
    * `C:\Users\<user>\AppData\Local\Mozilla\Firefox\Profiles\[profileID].default`
* Navigation History / Bookmarks: SQLite format
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\places.sqlite`
* Bookmarks Backup: Folder / .jsonlz4 Files
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\bookmarkbackups`
* Cookies: SQLite Database
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\cookies.sqlite`
* Cache:
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\cache2\entries`
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\startupCache`
* Form History: SQLite Database
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\formhistory.sqlite`
* Addons + Extensions: SQLite Database
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\addons.sqlite`
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\extensions.sqlite`
* Favicons: SQLite Database
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\favicons.sqlite`
* Settings and Preferences
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\prefs.js`
* Logins + Passwords: JSON file
    * Logins
        * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\logins.json`
    * Passwords:
        * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\key4.db`
        * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\key3.db`
* Sessions Data: jsonlz4 File
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\sessionstore.jsonlz4`
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\sessionstore-backups`
* Downloads: SQLite Database
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\downloads.sqlite`
* Thumbnails
    * `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\[profileID].default\thumbnails`

### Linux
* Profile
    * `~/.mozilla/firefox/`:
        * `profile.ini`: contains list of profiles
        * May contain multiple profiles
* History + bookmarks + downloads
    * `~/.mozilla/firefox/<profile>/places.sqlite`
        * history: `moz__places`
        * bookmarks: `moz__bookmarks`
        * downloads: `moz__annos`
* Others same as Windows

## Microsoft Edge
* Profile Path:
    * `C:\Users\<user>\AppData\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* History + Cookies + Downloads: ESE Database
    * `C:\Users\<user>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* Settings + Bookmarks + Reading List: ESE Database
    * `C:\Users\<user>\AppData\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Datastore\Data\nouser1\XXX\DBStore\spartan.edb`
* Cache
    * `C:\Users\<user>\AppData\Packages\Microsoft.MicrosoftEdge_XXX\AC\#!XXX\MicrosoftEdge\Cache`
* Sessions
    * Last Active Session
        * `C:\Users\<user>\AppData\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Internet Explorer 11

Stores data and metadata in different locations.
* metadata:  
    * `%userprofile%\AppData\Local\Microsoft\Windows\WebCache\WebCacheVX.data`: VX can be V01,V16 or V24.
    * `%userprofile%\AppData\Local\Microsoft\Windows\WebCache`: contains V01.log. If the modified time here is different from the ones in WebcacheVX.data run `esentutl /r V01 /d` to fix incompatibilities.
* Cache: snapshot of what the user was seeing. Size of 250 MB and timestamps indicate when the page was visited.
    * `%userprofile%\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5`
    * `%userprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low`
* Cookies: session cookies reside in meory and persistent cookies on disk.
    * `%userprofile\AppData\Roaming\Microsoft\Windows\Cookies`
    * `%userprofile\AppData\Local\Microsoft\Windows\Cookies\low`
* Downloads
    * `%userprofile\AppData\Local\Microsoft\Windows\IEDownloadHistory`
* History
    * `%userprofile%\AppData\Local\Microsoft\Windows\History\History.IE5`
    * `%userprofile%\AppData\Local\Microsoft\Windows\History\Low\History.IE5`
* Typed URLs: Can be found in NTUSER.DAT
    * `Software\Microsoft\InternetExplorer\TypedURLs`: last 50 typed URLs.
    * `Software\Microsoft\InternetExplorer\TypedURLsTime`: last time URL was typed.