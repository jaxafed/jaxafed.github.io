---
title: 'TryHackMe: El Bandito'
author: jaxafed
categories: [TryHackMe]
tags: [web, request smuggling, websocket, proxy]
render_with_liquid: false
media_subpath: /images/tryhackme_el_bandito/
image:
  path: room_image.webp
---

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/elbandito){: .right }

El Bandito was a room dedicated to request smuggling, where we used two different methods of request smuggling to capture two flags.
<br/>
First, we abused a SSRF vulnerability to trick a NGINX frontend reverse proxy into believing we established a websocket connection to smuggle requests to endpoints restricted by the proxy and capture the first flag along with a set of credentials.
<br/>
Second, we will use another method of request smuggling along with found credentials to capture another user's request and get the flag from the user's cookies.
<br/>

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.189.186
Nmap scan report for 10.10.189.186
Host is up (0.079s latency).
Not shown: 65400 closed tcp ports (conn-refused), 131 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 86:0f:76:04:77:0f:a8:24:0f:49:a2:1e:04:41:49:9f (RSA)
|   256 6c:ea:de:0c:e9:fd:96:60:c9:10:4f:45:4a:22:d1:01 (ECDSA)
|_  256 21:21:99:f4:7b:bf:6c:dc:e5:59:b4:e1:5d:78:24:74 (ED25519)
80/tcp   open  ssl/http El Bandito Server
|_http-server-header: El Bandito Server
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Not valid before: 2021-04-10T06:51:56
|_Not valid after:  2031-04-08T06:51:56
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
...
631/tcp  open  ipp      CUPS 2.4
|_http-server-header: CUPS/2.4 IPP/2.1
|_http-title: Forbidden - CUPS v2.4.7
8080/tcp open  http     nginx
|_http-favicon: Spring Java Framework
|_http-title: Site doesn't have a title (application/json;charset=UTF-8).
```

There are four ports open:

- 22/SSH
- 80/HTTPS
- 631/HTTP
- 8080/HTTP

### Port 80

Checking the source code for `https://10.10.189.186:80/` we see a script included: `/static/messages.js`

![Web Server View Source](web_source_code.webp){: width="600" height="200" }

Looking at `https://10.10.189.186:80/static/messages.js`, we see it makes a request to two endpoints:

- A get request to `/getMessages` to receive messages.

```js
...
// Function to fetch messages from the server
function fetchMessages() {
  fetch("/getMessages")
    .then((response) => {
      if (!response.ok) {
        throw new Error("Failed to fetch messages");
      }
      return response.json();
    }
...
```
{: file="https://10.10.189.186:80/static/messages.js"}
- A post request to `/send_message` with the `data` parameter to send messages.

```js
...
fetch("/send_message", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: "data="+messageText
}
...
```
{: file="https://10.10.189.186:80/static/messages.js"}

Visiting `/getMessages`, we get a login page.

![Web Server Login Page](web_login_page.webp){: width="800" height="600" }

Trying to send a message using `/send_message`, we also get the same login page.

![Web Server Send Message Login Page](web_sendmessage_login_page.webp){: width="800" height="600" }

### Port 8080

Looking at the web server on port 8080, we get a page about Bandit-Coin.

![Web Server Index Page](web_8080_index.webp){: width="800" height="600" }

There are two interesting endpoints.

- `/burn.html`

![Web Server Burn Page](web_8080_burn.webp){: width="800" height="600" }

The form does not seem to be doing anything.

- `/services.html`

![Web Server Services Page](web_8080_services.webp){: width="800" height="600" }

It seems to be printing the status of different web servers.

Checking the source code for the page, we see that it does this by making a request to the `/isOnline` endpoint with the `url` parameter.

```js
const serviceURLs = [
  "http://bandito.websocket.thm",
  "http://bandito.public.thm"
];

async function checkServiceStatus() {
  for (let serviceUrl of serviceURLs) {
    try {
       const response = await fetch(`/isOnline?url=${serviceUrl}`, {
        method: 'GET', 
      });

      if (response.ok) {
        let existingContent = document.getElementById("output").innerHTML;
        document.getElementById("output").innerHTML = `${existingContent}<br/>${serviceUrl}: <strong>ONLINE</strong>`;
      } else {
        throw new Error('Service response not OK');
      }
    } catch (error) {
      let existingContent = document.getElementById("output").innerHTML;
      document.getElementById("output").innerHTML = `${existingContent}<br/>${serviceUrl}: <strong>OFFLINE</strong>`;
    }
  }
}
```

One interesting thing to note here is that from both endoints' `favicon`, we can see that the application uses the `Spring Java Framework`. Nmap also reports this.

We can also see this from the distinct 404 page.

![Web Server 404 Page](web_8080_404_page.webp){: width="800" height="600" }

## First Web Flag

Since we know that the application on port 8080 uses `Spring Java Framework`, we can try to access `Spring Actuators` like `/env` or `/mappings`.

Trying to reach `/env`, we get the `403 Forbidden` message, but this forbidden response comes from the NGINX frontend reverse proxy instead of the backend server.

![Web Server 404 Page](web_8080_actuator_forbidden.webp){: width="800" height="600" }

While we are not able to access `/env`, we are able to access `/mappings` actuator.

![Web Server Mappings Actuator](web_8080_mappings_actuator.webp){: width="800" height="600" }

From there, we discover two interesting endpoints.

- `/admin-flag`
- `/admin-creds`

Unfortunately, when we try to access these endpoints, we get the same forbidden message as before.

So, if we can figure out a way to bypass the proxy, we might be able to access these endpoints.

Testing the `/isOnline` endpoint we discovered before. We notice an SSRF vulnerability, and the server also returns the status of the response it received from the URL we supplied.

![Web Server SSRF for Existent Page](web_8080_ssrf_exists.webp){: width="800" height="600" }
![Web Server SSRF for Non-Existent Page](web_8080_ssrf_doesnotexist.webp){: width="800" height="600" }

```console
$ python3 -m http.server 80                                                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.189.186 - - [23/Mar/2024 13:48:57] "GET /exists HTTP/1.1" 200 -
10.10.189.186 - - [23/Mar/2024 13:50:50] code 404, message File not found
10.10.189.186 - - [23/Mar/2024 13:50:50] "GET /doesnotexist HTTP/1.1" 404 -
```

Naturally, we are able to control the request, but this SSRF vulnerability also allows us to control the status code of the response.
We can use this ability to trick `NGINX` into believing we established a websocket connection and smuggle requests to endpoints we could not reach before.

This method is detailed [here](https://github.com/0ang3el/websocket-smuggle#22-scenario-2) and also covered in another [TryHackMe room](https://tryhackme.com/r/room/wsrequestsmuggling).

To perform this exploit, we need to add the `Upgrade: WebSocket` header to our requests to make the proxy think we are performing a Websocket Upgrade. While just this is enough to trick some other proxies, `NGINX` also validates the response's status code before establishing a tunnel between the client and the backend server. So, when we send the request with the websocket upgrade header, the response to this request must have a valid status code (101 Switching Protocols), and to make the server return the valid status code, we will use the `SSRF` vulnerability.
After that, `NGINX` will establish the tunnel and send anything after our request using this tunnel without checking, believing it to be a part of websocket communication. Since we did not perform a valid websocket upgrade, the backend server will interpret the rest of our request as another HTTP request.

So, we need to an HTTP server that will return the `101 Switching Protocols` response to our SSRF payload on the `/isOnline` endpoint.

We can use this Python code for that.

```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <port>")
    exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.protocol_version = "HTTP/1.1"
       self.send_response(101)
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```
{: file="101_server.py"}

Now, after running the server and making the request, we see that we are able to smuggle requests.

> Do not forget to disable the `Update Content-Length` option in Repeater while dealing with request smuggling.
{: .prompt-warning }

![Web Server WebSocket Request Smuggling](web_8080_websocket_request_smuggling.webp){: width="800" height="500" }

```console
$ python3 101_server.py 80
10.10.189.186 - - [23/Mar/2024 15:39:00] "GET / HTTP/1.1" 101 -
```

Now that we are able to bypass the proxy and smuggle requests to the backend, we can make requests to `/admin-creds` and `/admin-flag` endpoints.

From `/admin-flag`, we get our first flag.

![Web Server First Flag](web_8080_first_flag.webp){: width="800" height="500" }

And from `/admin-creds`, we get a set of credentials.

![Web Server Admin Credentials](web_8080_admin_creds.webp){: width="800" height="500" }

## Second Web Flag

Now that we have a set of credentials, we can login to the web application on port 80.

After logging in, we see a chat and are able to send and receive messages.

![Web Server Chat Page](web_chat_page.webp){: width="800" height="500" }

Also from the headers, we notice the server uses a frontend reverse proxy for caching.

Trying different payloads for request smuggling, we have success with using `Content-Length: 0`.

![Web Server Request Smuggling Payload](web_request_smuggling_payload.webp){: width="800" height="500" }

As we can see from the below response, we were able to cause a desync, and our next request was appended to our smuggled request from before, and it was interpreted like this: 
```
GET /doesnotexist HTTP/1.1
Foo: GET / HTTP/1.1
Host: 10.10.189.186:80
...
```
Hence, we are getting `404 Not Found` for a request to the `/` endpoint.

![Web Server Request Smuggling Payload Response](web_request_smuggling_payload_response.webp){: width="800" height="500" }

Since the application allows us to store and retrieve text data via messages, we can use this to capture the requests of other users.

For this, we will smuggle an incomplete request to the `/send_message` endpoint with an overly long `Content-Length` header and our cookie, since authorization is needed for sending messages.

With this request, any other request that follows ours will be appended to our smuggled request and will be interpreted as the `data` parameter in a request to the `/send_message` endpoint.

![Web Server Request Smuggling Capture Payload](web_request_smuggling_capture.webp){: width="800" height="500" }

After sending the request and receiving the messages after a bit, we see that another user's request was indeed appended to our payload and stored as a message.

![Web Server Request Smuggling Captured Request](web_request_smuggling_captured_request.webp){: width="800" height="500" }

We get the flag from the cookies in the user's request.

> This might take a couple of attempts, and also, do not forget to unescape unicode encoding in the flag when submitting it.
{: .prompt-warning }
