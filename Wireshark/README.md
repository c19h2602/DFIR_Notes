# Wireshark Notes

> Paolo Coba | 01/03/2021

-------------------------------------------

## Check Statistics
* Protocol Hierarchy (Statistics > Protocol Hierarchy)

## Identifying hosts and users

* Resource:
    * [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)

### Host information from DHCP traffic

* Filter: `dhcp`
* Select `DHCP Request` frame
    * Bootstrap Protocol (Request):
        * Expand `Client Identifier` and `Hostname`

### Host information from NetBIOS Name Service (NBNS) traffic

* Filter: `nbns`: Info column displays hostname. Can correlate with IP and MAC addresses.

### Decice models and operating systems from HTTP traffic

* Filter: `http.request and !(ssdp)`:
    * Check `User-Agent` to determine device model. Not 100% sure.

### Windows user account from Kerberos traffic

Can find PC and account names.
* Filter: `kerberos.CNameString`
    * Open frame details
    * Expand `Kerberos`, `as-req`, `req-body`, `cname`, `cname-string`


## Display Filter Expressions

### Web-Based Infection Traffic

* Base filter: `http.request or ssl.handshake.type==1`
* Remove Simple Service Discovery Protocol: `(http.request or ssl.handshake.type==1) and !(ssdp)`
* Display all connection attempts. Include TCP SYN segments: `(http.request or ssl.handshake.type==1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Add dns traffic: `(http.request or ssl.handshake.type==1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`

### SMTP Traffic

For unencrypted smtp traffic. Search for email header lines:
* `smtp contains "From:"`
* `smtp contains "Message-ID"`
* `smtp contains "Subject:"`

### FTP
* FTP commands: `ftp.request.command`
* FTP data: `ftp-data`

