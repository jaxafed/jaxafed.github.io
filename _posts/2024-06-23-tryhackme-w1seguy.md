---
title: 'TryHackMe: W1seGuy'
author: jaxafed
categories: [TryHackMe]
tags: [nc, xor, python]
render_with_liquid: false
math: true
media_subpath: /images/tryhackme_w1seguy/
image:
  path: room_image.webp
---

W1seGuy was a simple room, where we use known plaintext attack to discover a XOR key and use it to get the flags.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/w1seguy){: .center }

## Examining the Source Code

At the start of the room, we are given the source code for the application running on port 1337.

```python
import random
import socketserver 
import socket, os
import string

flag = open('flag.txt','r').read().strip()

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)
    hex_encoded = setup(server, key)
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
    
    send_message(server,"What is the encryption key? ")
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```
{: file="source-1705339805281.py" }

Looking at the source code, at the start it binds to port 1337 on all interfaces and sets the `RequestHandler` class to handle all incoming requests.

```python
if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```

`RequestHandler` class will simply call the `start` function with the request upon receiving one.

```python
class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)
```

The `start` function will first generate a random key of length `5` using the concatenation of `string.ascii_letters` (_`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`_) and `string.digits` (_`0123456789`_) as the character set.

```python
res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
key = str(res)
```

After that, it will call the `setup` function with the generated `key`.

```python
hex_encoded = setup(server, key)
```

The `setup` function will take the key and use it to `XOR` encrypt the first flag by iterating over all characters of the flag and `XOR`'ing it with `key`. After that, it will `hex` encode the result and return it.

```python
def setup(server, key):
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded
```

It also uses the `modulo` operator to index the character of the key to use, since due to the key being shorter, it will need to cycle through the key like this:

$$ Flag = F, Key = K, Encrypted flag = E $$

- $$F_{1} \oplus K_{1} = E_{1}$$ <x></x>
- $$F_{2} \oplus K_{2} = E_{2}$$ <x></x>
- $$F_{3} \oplus K_{3} = E_{3}$$ <x></x>
- $$F_{4} \oplus K_{4} = E_{4}$$ <x></x>
- $$F_{5} \oplus K_{5} = E_{5}$$ <x></x>
- $$F_{6} \oplus K_{1} = E_{6}$$ <x></x>
- $$F_{7} \oplus K_{2} = E_{7}$$ <x></x>
- $$...$$ <x></x>

Now, back to the `start` function. First, it will print the `XOR` encrypted and `hex` encoded flag returned from the `setup` function.

```python
send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
```

After that, it will ask for the encryption key and read our answer. If the `key` we answered matches the `key` randomly generated, it will print the second flag read from `flag.txt`.

```python
send_message(server,"What is the encryption key? ")
key_answer = server.recv(4096).decode().strip()

try:
    if key_answer == key:
        send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
        server.close()
    else:
        send_message(server, 'Close but no cigar' + "\n")
        server.close()
except:
    send_message(server, "Something went wrong. Please try again. :)\n")
    server.close()
```

## Recovering the Key

Connecting the machine on port `1337` using `nc`, we get the encrypted flag as expected.

```console
$ nc 10.10.51.17 1337
This XOR encoded text has flag 1: 1d037d3c32782a5c29360c334406363d7f532c2108254274232507492f173b3f4977373b337f353f
What is the encryption key?
```

After examining the source code, we get to know a couple of details that will help us recover the key and decrypt the encrypted flag.

First, the `XOR` key has a length of `5`.

```python
res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
```

Second, the flag has the format of `THM{...}`.

```python
flag = 'THM{thisisafakeflag}' 
```

One thing to note about `XOR` is that:

If $$ A \oplus B = C $$, then:
- $$ A \oplus C = B $$ <x></x>
- $$ B \oplus C = A $$ <x></x>

Knowing this, we can apply it to our current case to recover the first `4` characters of the `key`, since we know the first `4` characters of the flag (`'THM{'`) and the encrypted flag.

$$ Flag = F, Key = K, Encrypted flag = E $$

Since  $$ F_{1} \oplus K_{1} = E_{1} $$  then  $$ F_{1} \oplus E_{1} = K_{1} $$  will also be true, and we know the `first character of the flag` ($$F_{1}$$) and the `first character of the encrypted flag` ($$E_{1}$$), we can recover the `first character of the key` ($$K_{1}$$) with: 

- $$F_{1}$$ (`'T'`) $$\oplus$$  $$E_{1}$$ (`0x1d`) = $$K_{1}$$ (`'I'`)

We can also apply this to the next 3 characters to recover the first `4` characters of the key.

- Since $$F_{2} \oplus K_{2} = E_{2}$$, then $$ F_{2} \oplus E_{2} = K_{2} $$ (`'H'` $$\oplus$$ `0x03` = `'K'`)
- Since $$F_{3} \oplus K_{3} = E_{3}$$, then $$ F_{3} \oplus E_{3} = K_{3} $$ (`'M'` $$\oplus$$ `0x7d` = `'0'`)
- Since $$F_{4} \oplus K_{4} = E_{4}$$, then $$ F_{4} \oplus E_{4} = K_{4} $$ (`'{'` $$\oplus$$ `0x3c` = `'G'`)

Using `Python` to do this, we get the first `4` characters of the key by `XOR`'ing the first `4` characters of the flag with the first `4` characters of the encrypted flag.

```python
>>> from pwn import xor
>>> encrypted_flag = bytes.fromhex('1d037d3c32782a5c29360c334406363d7f532c2108254274232507492f173b3f4977373b337f353f')
>>> xor(encrypted_flag[:4], b"THM{")
b'IK0G'
```

This leaves us with not knowing only the last and fifth character of the `key`.

At this point, we can simply notice the flag has a length of `40`, which is a multiple of `5`.

```python
>>> len(encrypted_flag)
40
```

This means the last character of the flag will be `XOR`'ed with the fifth character of the key.

- $$F_{1} \oplus K_{1} = E_{1}$$ <x></x>
- $$F_{2} \oplus K_{2} = E_{2}$$ <x></x>
- $$F_{3} \oplus K_{3} = E_{3}$$ <x></x>
- $$F_{4} \oplus K_{4} = E_{4}$$ <x></x>
- $$F_{5} \oplus K_{5} = E_{5}$$ <x></x>
- $$F_{6} \oplus K_{1} = E_{6}$$ <x></x>
- $$...$$ <x></x>
- $$F_{40} \oplus K_{5} = E_{40}$$ <x></x>

We also know the `last character of the flag` (_`'}'`_) and the `last character of the encrypted flag` (_`0x3f`_), using this we can recover the `last character of the key` same way as before.

- Since $$F_{40} \oplus K_{5} = E_{40}$$, then $$ F_{40} \oplus E_{40} = K_{5} $$ (`'}'` $$\oplus$$ `0x3f` = `'B'`)

```python
>>> xor(encrypted_flag[-1], b"}")
b'B'
```

## Flag 1

Now that we know our key is `IK0GB`, we can use it to decrypt the flag.

```python
>>> xor(encrypted_flag, b"IK0GB")
b'THM{...}'
```

## Flag 2

Also, answering the question from the server with the `key` we recovered, we receive the second flag.

```console
What is the encryption key? IK0GB
Congrats! That is the correct key! Here is flag 2: THM{...}
```

## Extra

If the flag had a length that was not a multiple of the key length or we didn't know the last character of the flag, we could also use a `brute forcing` attack to recover the last character of the key with a script like this:

```python
from pwn import xor
import string

encrypted_flag = bytes.fromhex("1d037d3c32782a5c29360c334406363d7f532c2108254274232507492f173b3f4977373b337f353f")
key_start = xor(b"THM{", encrypted_flag[:4])
for i in string.ascii_letters + string.digits:
	key = key_start + i.encode()
	print(f"{key} : {xor(encrypted_flag, key)}")
```
{: file="xor_brute.py"}

```console
$ python3 xor_brute.py
...
b'IK0Gz' : b'THM{H1alnLExtALt4ck[Anr3YlLyhmrty0MrxOrE'
b'IK0GA' : b'THM{s1alnwExtAwt4ck`Anr3blLyhVrty0vrxOr~'
b'IK0GB' : b'THM{...}'
b'IK0GC' : b'THM{q1alnuExtAut4ckbAnr3`lLyhTrty0trxOr|'
b'IK0GD' : b'THM{v1alnrExtArt4ckeAnr3glLyhSrty0srxOr{'
...
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