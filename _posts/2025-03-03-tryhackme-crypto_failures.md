---
title: "TryHackMe: Crypto Failures"
author: jaxafed
categories: [TryHackMe]
tags: [web, php, crypto, hashing, python]
render_with_liquid: false
media_subpath: /images/tryhackme_crypto_failures/
image:
  path: room_image.webp
---

**Crypto Failures** began by discovering the source code of the web application and examining it to understand the authentication functionality, which we then used to log in as the admin user. Afterward, we leveraged the same authentication functionality to brute-force a secret key used within it to complete the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/cryptofailures){: .center }

## Initial Enumeration  

### Nmap Scan  

We start with an **`nmap`** scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.46.169
Nmap scan report for 10.10.46.169
Host is up (0.094s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 57:2c:43:78:0c:d3:13:5b:8d:83:df:63:cf:53:61:91 (ECDSA)
|_  256 45:e1:3c:eb:a6:2d:d7:c6:bb:43:24:7e:02:e9:11:39 (ED25519)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: Did not follow redirect to /
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:  

- **22** (`SSH`)  
- **80** (`HTTP`)

### Web 80  

Visiting `http://10.10.46.169/`, we are simply greeted with a **"logged in"** message.  

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}  

Checking the requests in **Burp**, we see that in our first request, the server sets the `secure_cookie` and `user` cookies, then redirects us back to the index using the `Location` header.  

![Web 80 Request](web_80_request.webp){: width="1100" height="600"}  

The second request is more interesting. Besides the **"logged in"** message, there is also a comment in the response:  
`<!-- TODO: remember to remove .bak files -->`  

![Web 80 Request Two](web_80_request2.webp){: width="1100" height="500"}

## Examining the Source Code  

The comment we discovered suggests that some `.bak` files were left on the web server. We can fuzz for them and discover the `index.php.bak` file.  

```console
$ ffuf -u 'http://10.10.46.169/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -e .php,.php.bak -t 100 -mc all -ic -fc 404
...
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 554ms]
index.php.bak           [Status: 200, Size: 1979, Words: 282, Lines: 96, Duration: 3569ms]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 121ms]
```
{: .wrap }

We can download the `index.php.bak` file using `wget`:  

```console
$ wget http://10.10.46.169/index.php.bak
```

Examining `index.php.bak`, it appears to contain the source code of the current web application:

```php
<?php
include "config.php";

function generate_cookie($user, $ENC_SECRET_KEY)
{
    $SALT = generatesalt(2);

    $secure_cookie_string = $user . ":" . $_SERVER["HTTP_USER_AGENT"] . ":" . $ENC_SECRET_KEY;

    $secure_cookie = make_secure_cookie($secure_cookie_string, $SALT);

    setcookie("secure_cookie", $secure_cookie, time() + 3600, "/", "", false);
    setcookie("user", "$user", time() + 3600, "/", "", false);
}

function cryptstring($what, $SALT)
{
    return crypt($what, $SALT);
}

function make_secure_cookie($text, $SALT)
{
    $secure_cookie = "";

    foreach (str_split($text, 8) as $el) {
        $secure_cookie .= cryptstring($el, $SALT);
    }

    return $secure_cookie;
}

function generatesalt($n)
{
    $randomString = "";
    $characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for ($i = 0; $i < $n; $i++) {
        $index = rand(0, strlen($characters) - 1);
        $randomString .= $characters[$index];
    }
    return $randomString;
}

function verify_cookie($ENC_SECRET_KEY)
{
    $crypted_cookie = $_COOKIE["secure_cookie"];
    $user = $_COOKIE["user"];
    $string = $user . ":" . $_SERVER["HTTP_USER_AGENT"] . ":" . $ENC_SECRET_KEY;

    $salt = substr($_COOKIE["secure_cookie"], 0, 2);

    if (make_secure_cookie($string, $salt) === $crypted_cookie) {
        return true;
    } else {
        return false;
    }
}

if (isset($_COOKIE["secure_cookie"]) && isset($_COOKIE["user"])) {
    $user = $_COOKIE["user"];

    if (verify_cookie($ENC_SECRET_KEY)) {
        if ($user === "admin") {
            echo "congrats: ******flag here******. Now I want the key.";
        } else {
            $length = strlen($_SERVER["HTTP_USER_AGENT"]);
            print "<p>You are logged in as " . $user . ":" . str_repeat("*", $length) . "\n";
            print "<p>SSO cookie is protected with traditional military grade en<b>crypt</b>ion\n";
        }
    } else {
        print "<p>You are not logged in\n";
    }
} else {
    generate_cookie("guest", $ENC_SECRET_KEY);

    header("Location: /");
}
?>
```
{: file="index.php.bak" }

- The application is fairly simple. It starts by including the `config.php` file. Since the application uses the `ENC_SECRET_KEY` variable, but it is not defined in `index.php`, we can infer that `config.php` contains its value.  

```php
include "config.php";
```

- Next, it checks whether the `secure_cookie` and `user` cookies are set. If not, it calls `generate_cookie` with `"guest"` and `ENC_SECRET_KEY`. If they are set, it calls `verify_cookie` with `ENC_SECRET_KEY`. If this function returns `true`, it checks the value of the `user` cookie. If it is `"admin"`, the flag is printed. Otherwise, a logged-in message with the current user is displayed. 

```php
if (isset($_COOKIE["secure_cookie"]) && isset($_COOKIE["user"])) {
    $user = $_COOKIE["user"];

    if (verify_cookie($ENC_SECRET_KEY)) {
        if ($user === "admin") {
            echo "congrats: ******flag here******. Now I want the key.";
        } else {
            $length = strlen($_SERVER["HTTP_USER_AGENT"]);
            print "<p>You are logged in as " . $user . ":" . str_repeat("*", $length) . "\n";
            print "<p>SSO cookie is protected with traditional military grade en<b>crypt</b>ion\n";
        }
    } else {
        print "<p>You are not logged in\n";
    }
} else {
    generate_cookie("guest", $ENC_SECRET_KEY);

    header("Location: /");
}
```

- Let's analyze the case where the cookies are not set and examine the `generate_cookie` function. First, it calls `generatesalt(2)`, which generates a random 2-byte salt from an alphanumeric character set. After that, it creates a string using the provided `user`, `User-Agent`, and `ENC_SECRET_KEY`, separated by `:`. This string is then passed to `make_secure_cookie` along with the generated salt. Finally, it sets the returned value as the `secure_cookie` cookie and the `user` in another cookie.  

```php
function generate_cookie($user, $ENC_SECRET_KEY)
{
    $SALT = generatesalt(2);

    $secure_cookie_string = $user . ":" . $_SERVER["HTTP_USER_AGENT"] . ":" . $ENC_SECRET_KEY;

    $secure_cookie = make_secure_cookie($secure_cookie_string, $SALT);

    setcookie("secure_cookie", $secure_cookie, time() + 3600, "/", "", false);
    setcookie("user", "$user", time() + 3600, "/", "", false);
}
```

- Checking `make_secure_cookie`, we see that it splits the input string into 8-byte chunks and calls `cryptstring` for each chunk, along with the provided salt. It then concatenates the return values and returns the final string.  

```php
function make_secure_cookie($text, $SALT)
{
    $secure_cookie = "";

    foreach (str_split($text, 8) as $el) {
        $secure_cookie .= cryptstring($el, $SALT);
    }

    return $secure_cookie;
}
```

- Examining `cryptstring`, we see that it simply calls PHP's [`crypt()`](https://www.php.net/manual/en/function.crypt.php) function to hash the string passed with the given salt.

```php
function cryptstring($what, $SALT)
{
    return crypt($what, $SALT);
}
```

- Now, let's also analyze what happens when the `secure_cookie` and `user` cookies are set by looking at the `verify_cookie` function. First, it retrieves the values of these cookies. It then reconstructs the original string using `user`, `User-Agent`, and `ENC_SECRET_KEY`. Since all hashes use the same salt and the first two bytes of each hash represent the salt, it extracts the salt from the first hash in `secure_cookie`. Finally, it calls `make_secure_cookie` with the reconstructed string and extracted salt, then compares the result with the value stored in `secure_cookie` and returns the result of the comparison.  

```php
function verify_cookie($ENC_SECRET_KEY)
{
    $crypted_cookie = $_COOKIE["secure_cookie"];
    $user = $_COOKIE["user"];
    $string = $user . ":" . $_SERVER["HTTP_USER_AGENT"] . ":" . $ENC_SECRET_KEY;

    $salt = substr($_COOKIE["secure_cookie"], 0, 2);

    if (make_secure_cookie($string, $salt) === $crypted_cookie) {
        return true;
    } else {
        return false;
    }
}
```

For example, in our case, `user` is `guest`, and the `User-Agent` is `Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0`.

So, the server constructs the string to hash as:  

```
guest:Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0:<ENC_SECRET_KEY>
```

And the server returns `secure_cookie` as:  

```
AdSleedEWCRK2Adyb8twq9SeTwAd1ewQQZ2hHRcAdxNnQGj8bSPMAdOz9pHkM6hjwAd1xuiZYw7z0wAdf7clVSfkhFQAdjjS2u2vogycAdBP8msSwLPn6AdcrIsmiZ7xcwAd4R54HxWvY/sAd507x3ic0BCwAdoWO7KprUNEIAdsF0KAF1noBkAdfGw5AZYSiawAdiESYxpdMbMwAdQOL4Bzw3FI6Add
```  

Since the server hashes the string in 8-byte blocks, we can see the hashes for each block:  

```
 "guest:Mo"       "zilla/5."       "0 (X11; "    ...:<ENC_SECRET_KEY>
     V                V               V
AdSleedEWCRK2   Adyb8twq9SeTw    Ad1ewQQZ2hHRc   ...
```

We can also confirm that these hashes match the blocks by hashing them manually:

```console
$ php -a
php > echo crypt("guest:Mo", "Ad");
AdSleedEWCRK2
php > echo crypt("zilla/5.", "Ad");
Adyb8twq9SeTw
php > echo crypt("0 (X11; ", "Ad");
Ad1ewQQZ2hHRc
```

## Logging in as Admin

Examining the source code, we notice that even though we don't know `ENC_SECRET_KEY`, the first 8-byte block to be hashed consists only of the `user` and the `User-Agent`. After hashing, it is directly compared to the first hash in the `secure_cookie` cookie. This means we can control both the plaintext (since `user` is read from the `user` cookie and `User-Agent` is set via the `User-Agent` header) and the hash it is compared to (by modifying `secure_cookie`), allowing us to log in as any user we want.

Since our goal is to capture the flag by logging in as `admin`, we can simply set the `user` cookie to `"admin"`. This changes the first block to be hashed from `"guest:Mo"` to `"admin:Mo"`.

Then, by replacing the first hash in `secure_cookie` with `AdBOdWNO.9Zps` (`crypt("admin:Mo", "Ad")`) instead of `AdSleedEWCRK2` (`crypt("guest:Mo", "Ad")`), we can also pass the check in `verify_cookie` and log in successfully.

```console
php > echo crypt("guest:Mo", "Ad");
AdSleedEWCRK2
php > echo crypt("admin:Mo", "Ad");
AdBOdWNO.9Zps
```

Modifying the `secure_cookie` and `user` cookies as mentioned, we can see that we are able to log in successfully and capture the first flag.

![Web 80 Flag](web_80_flag.webp){: width="1100" height="500"}

## Discovering the Key

We were able to log in as the `admin` user and obtain the first flag, but now it seems we need to find the `ENC_SECRET_KEY` for the next flag. One way to do this would be to simply brute-force each hash in the `secure_cookie`, but this would require brute-forcing 8 bytes for every hash, which would take a really long time.

Instead, we can leverage how the string is being hashed to make the process more efficient. Since the string to be hashed starts with our input and is hashed in 8-byte blocks, we can utilize this to make brute-forcing easier by using the `User-Agent` as padding and changing its length to always have a single 8-byte block where we know the first 7 bytes, allowing us to only brute-force the last character of that block.

For example, if we send an empty `User-Agent` to the server, the string to be hashed would be: `guest::<ENC_SECRET_KEY>`. Since it is hashed in 8-byte blocks, the first block that is hashed would end up as: `guest::<First character of ENC_SECRET_KEY>`. We can then simply iterate over all the characters and append them to the `guest::` string, hash it, and check the resulting hash against the first hash in the `secure_cookie` returned from the server. If they match, we can identify the first character of the `ENC_SECRET_KEY`. By repeating this process for the remaining characters, we can discover the key by brute-forcing one character at a time.

As we can see, making such a request to the server with an empty `User-Agent`, the first hash returned from the server is: `2c2QeitMw0e1g`.

![Web 80 Secret Key](web_80_secret_key.webp){: width="1100" height="500"}

Now, we can simply try appending every character to `guest::` and hash it, then compare it to the first hash from the `secure_cookie`. When we append `T` to `guest::`, we see that the hashes match, and thus we have found the first character of the `ENC_SECRET_KEY`.

```console
...
php > echo crypt("guest::S", "2c");
2cri//aAPLqkY
php > echo crypt("guest::T", "2c");
2c2QeitMw0e1g
php > echo crypt("guest::U", "2c");
2cYsF2IWJsvrE
...
```

Next, we can move on to the second character. This time, if we set the `User-Agent` as `AAAAAAA`, the string to be hashed would be: `guest:AAAAAAA:<ENC_SECRET_KEY>`. If we split it into 8-byte chunks, just like the server does, we can see that the first chunk would be `guest:AA`, which we don't care about. However, the second chunk would be: `AAAAA:<First two characters of ENC_SECRET_KEY>`. Since we already discovered the first character of the `ENC_SECRET_KEY`, the second block would be `AAAAA:T<Second character of ENC_SECRET_KEY>`. We can then once again append every character to `AAAAA:T` and compare it to the second hash from the `secure_cookie`. (We use the second hash since our block with 7 known bytes and 1 unknown byte is the second one now.)

If we make a request to the server with the `User-Agent` set to `AAAAAAA` as mentioned, we can see that the hash for the second block is `0gy7IR0MNsLPo`.

![Web 80 Secret Key Two](web_80_secret_key2.webp){: width="1100" height="500"}

Then, using the same method as before, we can try every character and see that when we append `H`, the hashes match. Therefore, the second character of the `ENC_SECRET_KEY` is `H`.

```console
...
php > echo crypt("AAAAA:TG", "0g");
0gjGaQws2eVs6
php > echo crypt("AAAAA:TH", "0g");
0gy7IR0MNsLPo
php > echo crypt("AAAAA:TI", "0g");
0gaQtrM9hmGDc
...
```

Next, we can modify the `User-Agent` to `AAAAAA`, so the string becomes: `guest:AAAAAA:<ENC_SECRET_KEY>`, with the second block to be hashed being: `AAAA:TH<Third character of ENC_SECRET_KEY>`. We can then brute-force the third character as before and continue discovering the secret key by using the `User-Agent` to always have a hashed block with 7 known bytes and 1 unknown byte to brute-force.

But instead of doing this manually for each character of the key, we can automate the process by writing a `Python` script, as shown below:

```py
#!/usr/bin/env python3
import crypt
import requests
import urllib.parse
import string

BASE_URL = "http://10.10.46.169/"
USERNAME = "guest:"
SEPARATOR = ":"
CHARSET = string.printable

def get_secure_cookie(user_agent: str) -> str:
    session = requests.Session()
    response = session.get(BASE_URL, headers={"User-Agent": user_agent})
    cookie = session.cookies.get("secure_cookie")
    return urllib.parse.unquote(cookie)

def main():
    discovered = ""

    while True:
        ua_padding_length = (7 - len(USERNAME + SEPARATOR + discovered)) % 8
        user_agent = "A" * ua_padding_length
        prefix = USERNAME + user_agent + SEPARATOR + discovered

        block_index = len(prefix) // 8

        secure_cookie = get_secure_cookie(user_agent)
        target_block = secure_cookie[block_index * 13:(block_index + 1) * 13]
        salt = target_block[:2]

        found_char = False
        for char in CHARSET:
            candidate = (prefix + char)[-8:]
            candidate_hash = crypt.crypt(candidate, salt)
            if candidate_hash == target_block:
                discovered += char
                print(char, end="", flush=True)
                found_char = True
                break

        if not found_char:
            break

    print()

if __name__ == "__main__":
    main()
```
{: file="solve.py" }

Running the script, we successfully discover the `ENC_SECRET_KEY`, which is the second flag and complete the room.

```console
$ python3 solve.py
THM{Tr[REDACTED]b9}
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