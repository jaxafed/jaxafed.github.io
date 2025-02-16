---
title: 'TryHackMe: Bypass'
author: jaxafed
categories: [TryHackMe]
tags: [web, nc, curl, ping, rce]
render_with_liquid: false
media_subpath: /images/tryhackme_bypass/
image:
  path: room_image.webp
---

Bypass begins with discovering a set of instructions and following these instructions to acquire a password. This password allowed us to login to a web application and get to another login page, where we discovered a way to execute remote commands. After using this to discover the hostname, which also works as the username, along with the same password from before to login on this new login page, we completed the room by discovering the last flag.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/bypass){: .center }


## Initial Enumeration

### Nmap Scan

```console
$  nmap -T4 -n -sC -sV -Pn -p- 10.10.202.170 
Nmap scan report for 10.10.202.170
Host is up (0.090s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6f:6d:af:46:cd:71:c8:41:10:4c:1d:8b:4a:75:c1:66 (RSA)
|   256 b2:15:eb:08:36:cf:7b:f2:af:1d:ac:bd:7a:78:37:41 (ECDSA)
|_  256 b3:5a:ff:d4:e8:a7:75:92:f1:0a:04:c7:31:80:4d:fe (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.41
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.41 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=cctv.thm/organizationName=cctv.thm/stateOrProvinceName=Tokyo/countryName=AU
| Not valid before: 2023-08-30T10:08:16
|_Not valid after:  2024-08-29T10:08:16
Service Info: Hosts: default, ip-10-10-202-170.eu-west-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are three ports open:
- 22/SSH
- 80/HTTP
- 443/HTTPS

We also discover the hostname: `cctv.thm`

Adding `cctv.thm` to our `/etc/hosts` file.

```
10.10.202.170 cctv.thm
```
{: file="/etc/hosts"}

### Port 80

Visiting port 80, we get a forbidden page.

![Web Server Port 80 Forbidden](web_80_ip_forbidden.webp){: width="600" height="300" }

### Port 443

Visiting port 443 by IP, we also get the same forbidden page as before.

![Web Server Port 443 Forbidden](web_443_ip_forbidden.webp){: width="600" height="300" }

Using the `cctv.thm` hostname, we get a login page.

![Web Server Port 443 Login Page](web_443_host_login_page.webp){: width="1200" height="600" }

Checking the source code for the login page, we discover the `/mail` endpoint in one of the comments.

![Web Server Port 443 Login Page Sourcecode](web_443_login_page_sourcecode.webp){: width="900" height="450" }

At `https://cctv.thm/mail/`, indexing is enabled and we discover the `dump.txt` file.

![Web Server Port 443 Mail Endpoint](web_443_mail_endpoint.webp){: width="600" height="300" }

Downloading the `https://cctv.thm/mail/dump.txt` file.

```console
$ curl -k -s 'https://cctv.thm/mail/dump.txt' -o dump.txt
```

`dump.txt` gives us instructions on how to get the first five flags. Along with informing us that we can concatenate these flags to obtain the password for the login page. 

```
From: steve@cctv.thm
To: mark@cctv.thm
Subject: Important Credentials

Hey Mark,

I have completed all the formalities for securing our CCTV web panel (cctv.thm:443). I have installed Suricata to automatically detect any invalid connection and enabled two-layer protection for the web panel. I will SMS you the passwords but incase if you misplace them, there is no possibility for recovery. 

We can recover the password only if we send some specially crafted packets 	
-	Make a UDP request to the machine with source port number 5000. Once done, you can fetch the flag through /fpassword.php?id=1
-	Make a TCP request to fpassword.php?id=2 with user-agent set as "I am Steve Friend". Once done, you can fetch the flag through /fpassword.php?id=2
-	Send a ping packet to the machine appearing as Mozilla browser (Hint: packet content with user agent set as Mozilla). Once done, you can fetch the flag through /fpassword.php?id=3
-	Attempt to login to the FTP server with content containing the word "user" in it. Once done, you can fetch the flag from /fpassword.php?id=4
-	Send TCP request to flagger.cgi endpoint with a host header containing more than 50 characters. Once done, you can fetch the flag from /fpassword.php?id=5

After receiving all the flags, you can visit the MACHINE IP that will ask you for the password. The first password will be concatenated values of all five flags you have received above.

For the second layer of security, I have enabled a wholly sandboxed login environment with no connection to the database and no possibility of command execution. The username is the computer's hostname, and the password is the same as the previous password. I will SMS you the details as well.


See ya soon

Steve
Dev Ops Engineer
```
{: file="dump.txt" .wrap }

## First Flag

For the first flag, our instruction is to make a UDP request where the source port is 5000.

> Make a UDP request to the machine with source port number 5000. Once done, you can fetch the flag through /fpassword.php?id=1

We can use `nc` for this, using the `-p` flag to specify the source port and the `-u` flag for the `UDP` protocol.

```console
$ nc -u -p 5000 cctv.thm 6666
test
^C
```

After our request, we get the first flag by visiting `https://cctv.thm/fpassword.php?id=1`.

![Web Server Port 443 First Flag](web_443_first_flag.webp){: width="900" height="300" }

## Second Flag

For the second flag, we need to make an HTTP request with `User-Agent` set to `I am Steve Friend`.

> Make a TCP request to fpassword.php?id=2 with user-agent set as "I am Steve Friend". Once done, you can fetch the flag through /fpassword.php?id=2

We can use `curl` for this.

```console
$ curl -s 'http://cctv.thm/' -H 'User-Agent: I am Steve Friend'              
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at cctv.thm Port 80</address>
</body></html>
```

Now, we can get the second flag by visiting `https://cctv.thm/fpassword.php?id=2`.

![Web Server Port 443 Second Flag](web_443_second_flag.webp){: width="900" height="300" }


## Third Flag

For the third flag, we need to send a ping packet where the data section includes the string `Mozilla`.

> Send a ping packet to the machine appearing as Mozilla browser (Hint: packet content with user agent set as Mozilla). Once done, you can fetch the flag through /fpassword.php?id=3

We can use the `ping` command with the `-p` flag for this. But first, we need to convert `Mozilla` to hex encoding.

Using `xxd` for this.

```console
$ echo -n Mozilla | xxd -p                                                                                   
4d6f7a696c6c61

$ ping -c 5 cctv.thm -p '4d6f7a696c6c61'
PATTERN: 0x4d6f7a696c6c61
PING cctv.thm (10.10.202.170) 56(84) bytes of data.
64 bytes from cctv.thm (10.10.202.170): icmp_seq=1 ttl=63 time=78.3 ms
64 bytes from cctv.thm (10.10.202.170): icmp_seq=2 ttl=63 time=77.2 ms
64 bytes from cctv.thm (10.10.202.170): icmp_seq=3 ttl=63 time=76.0 ms
64 bytes from cctv.thm (10.10.202.170): icmp_seq=4 ttl=63 time=76.1 ms
64 bytes from cctv.thm (10.10.202.170): icmp_seq=5 ttl=63 time=76.2 ms

--- cctv.thm ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4010ms
rtt min/avg/max/mdev = 76.016/76.774/78.318/0.877 ms
```

After the `ping` command, we can get the third flag by visiting `https://cctv.thm/fpassword.php?id=3`.

![Web Server Port 443 Third Flag](web_443_third_flag.webp){: width="900" height="300" }

## Fourth Flag

For the fourth flag, we need to send a packet containing the string `user` to port 21.

> Attempt to login to the FTP server with content containing the word "user" in it. Once done, you can fetch the flag from /fpassword.php?id=4

Using `nc` for this.

```console
$ nc cctv.thm 21             
user test
^C
```

After this, we get the fourth flag at `https://cctv.thm/fpassword.php?id=4`.

![Web Server Port 443 Fourth Flag](web_443_fourth_flag.webp){: width="900" height="300" }

## Fifth Flag

For the fifth flag, we need to send an HTTP request to the /flagger.cgi endpoint with a `Host` header longer than 50 characters.

> Send TCP request to flagger.cgi endpoint with a host header containing more than 50 characters. Once done, you can fetch the flag from /fpassword.php?id=5

Once again, using `curl` for this.

```console
$ curl -s 'http://cctv.thm/flagger.cgi' -H "Host: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Port 80</address>
</body></html>
```

After the request, we can get the fifth flag at `https://cctv.thm/fpassword.php?id=5`.

![Web Server Port 443 Fifth Flag](web_443_fifth_flag.webp){: width="900" height="300" }

## Sixth Flag

Now that we followed the instructions and got the first five flags, we can concatenate them to get the password like this:

- `THM{.....}THM{.....}THM{.....}THM{.....}THM{.....}`

Using this password to login at `https://cctv.thm/`, we get another login page, this time also requiring a username along with the password.

![Web Server Port 443 Second Login Page](web_443_second_login_page.webp){: width="900" height="300" }

From the `dump.txt`, we learn that the username will be the hostname, and for the password, we can use the same password as before.

> For the second layer of security, I have enabled a wholly sandboxed login environment with no connection to the database and no possibility of command execution. The username is the computer's hostname, and the password is the same as the previous password. I will SMS you the details as well.

Checking the source code for this page, we discover a form that makes a post request to the `/index.php` endpoint with the `commands` parameter's value set to `date`.

```html
...
 <form method="POST" id="myform" name="index.php">	
  	<div class="p-5" style="background: #ffffff">
	<div class="d-flex justify-content-between">
	<select name="commands" id="commands">
		<option value="date">
			Current Date Fri Apr  5 23:31:23 UTC 2024
		</option>
	</select>
</form>
...
```

By making the same request, we are able to execute commands.

![Web Server Port 443 Command Execution](web_443_command_execution.webp){: width="900" height="500" }

We can run the `lsb_release -r -s` command to get the answer to one of the questions in the room.

![Web Server Port 443 Lsb Release Command](web_443_lsb_release.webp){: width="900" height="500" }

Executing the `hostname` command, we can get the hostname for the device, which also works as the username.

![Web Server Port 443 Hostname Command](web_443_hostname.webp){: width="900" height="500" }

At last, we can use the hostname as the username along with the password from before to login on this second login page.

![Web Server Port 443 Second Login](web_443_second_login.webp){: width="1200" height="600" }

After logging in, we get redirected to `https://cctv.thm/dashboard.php`, where we get the last flag and complete the room.

![Web Server Port 443 Sixth Flag](web_443_sixth_flag.webp){: width="1200" height="600" }

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