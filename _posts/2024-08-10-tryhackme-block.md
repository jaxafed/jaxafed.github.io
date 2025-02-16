---
title: "TryHackMe: Block"
author: jaxafed
categories: [TryHackMe]
tags: [pcap, wireshark, lsass, pypykatz, python, smb]
render_with_liquid: false
media_subpath: /images/tryhackme_block/
image:
  path: room_image.webp
---

Block was a short room about extracting hashes from a given LSASS dump and using them to decrypt SMB3 traffic inside a given packet capture file.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/blockroom){: .center }

## Initial Enumeration

We are given a zip archive at the start of the room, which includes two files, a packet capture, and a memory dump of the LSASS process.

```console
$ zipinfo evidence-1697996360986.zip
Archive:  evidence-1697996360986.zip
Zip file size: 43679925 bytes, number of entries: 2
-rw-r--r--  3.0 unx    34544 bx defN 23-Oct-22 17:04 traffic.pcapng
-rw-r--r--  3.0 unx 171558408 bx defN 23-Oct-22 16:54 lsass.DMP
2 files, 171592952 bytes uncompressed, 43679601 bytes compressed:  74.5%
```

### PCAP File

Opening the `traffic.pcapng` file in `Wireshark` and checking the statistics, we see that it mainly includes SMB traffic.

![Wireshark Statistics](wireshark_statistics.webp){: width="1000" height="600" }

Looking at the traffic manually, first we see a login for the user `mrealman`.

![Wireshark SMB First Login](smb_first_login.webp){: width="1200" height="400" }

After that, we also see a login for the user `eshellstrop`.

![Wireshark SMB Second Login](smb_second_login.webp){: width="1200" height="400" }

Lastly, we also see some encrypted SMB3 traffic.

![Wireshark SMB Second Login](smb_encrypted_traffic.webp){: width="1200" height="400" }

### LSASS.DMP

Checking the `lsass.DMP` file, we can see that it is a minidump for a process; from the name, we can guess the process as `LSASS`.

```console
$ file lsass.DMP
lsass.DMP: Mini DuMP crash report, 16 streams, Sun Oct 22 16:54:50 2023, 0x421826 type
```

We can use `pypykatz` to extract some credentials from it.

```console
$ pypykatz lsa minidump lsass.DMP
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 1883004 (1cbb7c)
session_id 3
username mrealman
domainname BLOCK
logon_server WIN-2258HHCBNQR
logon_time 2023-10-22T16:53:54.168637+00:00
sid S-1-5-21-3761843758-2185005375-3584081457-1104
luid 1883004
        == MSV ==
                Username: mrealman
                Domain: BLOCK
                LM: NA
                NT: 1f9175a516211660c7a8143b0f36ab44
                SHA1: ccd27b4bf489ffda2251897ef86fdb488f248aef
                DPAPI: 3d618a1fffd6c879cd0b056910ec0c31
        == WDIGEST [1cbb7c]==
                username mrealman
                domainname BLOCK
                password None
                password (hex)
        == Kerberos ==
                Username: mrealman
                Domain: BLOCK.THM
        == WDIGEST [1cbb7c]==
                username mrealman
                domainname BLOCK
                password None
                password (hex)
...
== LogonSession ==
authentication_id 828825 (ca599)
session_id 2
username eshellstrop
domainname BLOCK
logon_server WIN-2258HHCBNQR
logon_time 2023-10-22T16:46:09.215626+00:00
sid S-1-5-21-3761843758-2185005375-3584081457-1103
luid 828825
        == MSV ==
                Username: eshellstrop
                Domain: BLOCK
                LM: NA
                NT: 3f29138a04aadc19214e9c04028bf381
                SHA1: 91374e6e58d7b523376e3b1eb04ae5440e678717
                DPAPI: 87c8e56bc4714d4c5659f254771559a8
        == WDIGEST [ca599]==
                username eshellstrop
                domainname BLOCK
                password None
                password (hex)
        == Kerberos ==
                Username: eshellstrop
                Domain: BLOCK.THM
        == WDIGEST [ca599]==
                username eshellstrop
                domainname BLOCK
                password None
                password (hex)
        == DPAPI [ca599]==
                luid 828825
                key_guid c03cf95e-ff22-4fe9-aac6-93b9586d37c8
                masterkey b0bf26e3ee42acb190007958d5514a966ba87f4425d14688566b9a31e0fd98687bf28c9b5a21bc47f53380967cd871d5b56023b7318cd04d9cf4ba6663cd4d9c
                sha1_masterkey c7bee2cb7cdd6eb62201adda6d034ea41a126c7c
...
```

With this, we get the NT hash of two users from the packet capture file:

- `mrealman:1f9175a516211660c7a8143b0f36ab44`
- `eshellstrop:3f29138a04aadc19214e9c04028bf381`

We are also able to crack the hash for `mrealman` using [CrackStation](https://crackstation.net/).

![CrackStation](crackstation.webp){: width="1000" height="400" }

## Decrypting the SMB3 Traffic

Going back to the packet capture and looking for ways to decrypt the SMB3 traffic, we came across [this article](https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2).

The article mentions that we can use the `Key Exchange Key` to decrypt the `Encrypted Session Key` and get the `Random Session Key` and use that to decrypt the `SMB3` traffic.

It also mentions that we can use `username`, `domain`, `NT hash or password`, and `NTProofStr` to calculate the `Key Exchange Key`.

Going over all the stuff we need, we already have all of them.

- `username` -> Found in `traffic.pcapng`
- `domain` -> Found in `traffic.pcapng`
- `NTProofStr` -> Found in `traffic.pcapng`
- `NT Hash or Password` -> Found in `lsass.DMP`

With these, we can calculate the `Key Exchange Key`.

At last, we need the `Encrypted Session Key`, which can also be found in the `traffic.pcapng` file.

Article also shares a `Python` script for calculating the `Key Exchange Key` and decrypting the `Encrypted Session Key`. But, it is written for `Python2`. So, I have updated it to `Python3` and also added functionality to accept `NTLM hash` as an argument instead of the password.

```python
import hashlib
import hmac
import argparse
from Cryptodome.Cipher import ARC4
from Cryptodome.Cipher import DES
from Cryptodome.Hash import MD4

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    sessionKey = cipher.encrypt(exportedSessionKey)
    return sessionKey

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-u", "--user", required=True, help="User name")
parser.add_argument("-d", "--domain", required=True, help="Domain name")
credential = parser.add_mutually_exclusive_group(required=True)
credential.add_argument("-p", "--password", help="Password of User")
credential.add_argument("-H", "--hash", help="NTLM Hash of User")
parser.add_argument("-n", "--ntproofstr", required=True, help="NTProofStr. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-k", "--key", required=True, help="Encrypted Session Key. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")

args = parser.parse_args()

#Upper Case User and Domain
user = args.user.upper().encode("utf-16le")
domain = args.domain.upper().encode("utf-16le")

if args.password:
  # If password is supplied create 'NTLM' hash of password
  passw = args.password.encode("utf-16le")
  hash1 = hashlib.new("md4", passw).digest()
else:
  hash1 = bytes.fromhex(args.hash)

# Calculate the ResponseNTKey
h = hmac.new(hash1, digestmod=hashlib.md5)
h.update(user + domain)
respNTKey = h.digest()

# Use NTProofSTR and ResponseNTKey to calculate Key Excahnge Key
NTproofStr = bytes.fromhex(args.ntproofstr)
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

# Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(KeyExchKey, bytes.fromhex(args.key))

if args.verbose:
    print("USER WORK: " + user.hex() + "" + domain.hex())
    print("PASS HASH: " + hash1.hex())
    print("RESP NT:   " + respNTKey.hex())
    print("NT PROOF:  " + NTproofStr.hex())
    print("KeyExKey:  " + KeyExchKey.hex())
print("Random SK: " + RsessKey.hex())
```
{: file="gen_rsk.py"}

Let's start by gathering the values we need for decrypting the session for `mrealman`.

What we need can be found inside the packet `11`.

![Mrealman Arguments](mrealman_arguments.webp){: width="1300" height="600" }

- Username: `mrealman`
- Domain: `WORKGROUP`
- NTProofStr: `16e816dead16d4ca7d5d6dee4a015c14`
- Encrypted Session Key: `fde53b54cb676b9bbf0fb1fbef384698`

And we already have the password for the user from cracking the hash found inside `lsass.DMP`.

- Password: `Blockbuster1`

We also make a note of `Session ID`, since we will need it in a minute.

![Mrealman Session ID](mrealman_session_id.webp){: width="1300" height="500" }

- Session ID: `0x0000100000000041`

Now that we have everything we need, we can run the script to get the `Random Session Key`.

```console
$ python3 gen_rsk.py -u 'mrealman' -d 'WORKGROUP' -p 'Blockbuster1' -n '16e816dead16d4ca7d5d6dee4a015c14' -k 'fde53b54cb676b9bbf0fb1fbef384698' -v
USER WORK: 4d005200450041004c004d0041004e0057004f0052004b00470052004f0055005000
PASS HASH: 1f9175a516211660c7a8143b0f36ab44
RESP NT:   110fd571fec8b2d44728e3d4d6f32f0a
NT PROOF:  16e816dead16d4ca7d5d6dee4a015c14
KeyExKey:  17e09b2c9b92045329a4382898f50159
Random SK: 20a642c086ef74eee26277bf1d0cff8c
```
{: .wrap }

We can add it to `Wireshark` to decrypt the traffic.

![SMB Add Session Key](smb_add_session_key.webp){: width="1300" height="500" }

We need to reverse the bytes on the session ID due to endianness.

![SMB First Session Key Added](smb_first_session_key_added.webp){: width="600" height="500" }

After adding the session key, we can see that the SMB3 traffic is now decrypted. We also see the user accessing the `clients156.csv` file.

![SMB Decrypted Traffic First](decrypted_smb3_traffic_first.webp){: width="1300" height="500" }

We can use `Wireshark` to export the file like so:

![Wireshark Export SMB](wireshark_export_smb.webp){: width="600" height="600" }

![Export Clients156 CSV](export_clients156_csv.webp){: width="750" height="500" }

Reading the `clients156.csv` file, we get the first flag.

```console
$ cat %5cclients156.csv
first_name,last_name,password
Jewell,Caseri,eS8/y*t?8$
Abey,Sigward,yB0{g_>KezO
Natassia,Freeth,tS2<1Fef9tiF
Verina,Wainscoat,kT8/2uEMH
Filia,Sommerling,oE9.2c?Sce
Farris,Busst,THM{[REDACTED]}
Bat,Oakes,gE0%f@'qw}s%
Verina,Jedrachowicz,wK4~4L\O
Caril,Wolfarth,yQ3$Ji0~f7aB>F{
Bordie,Baume,iM1}"x)yP'`2|S
,,
```

Now, we can do the same for the session of the user `eshellstrop`.

We find the values we need inside the packet `82`.

![Eeshellstrop Arguments](eshellstrop_arguments.webp){: width="1300" height="600" }

- Username: `eshellstrop`
- Domain: `WORKGROUP`
- NTProofStr: `0ca6227a4f00b9654a48908c4801a0ac`
- Encrypted Session Key: `c24f5102a22d286336aac2dfa4dc2e04`

And we already have the `NTLM` hash for the user.

- NTLM Hash: `3f29138a04aadc19214e9c04028bf381`

Once again, also noting the `Session ID`.

![Eeshellstrop Session ID](eshellstrop_session_id.webp){: width="1300" height="500" }

- Session Id: `0x0000100000000045`

Running the script to calculate the `Random Session Key`.

```console
$ python3 gen_rsk.py -u 'eshellstrop' -d 'WORKGROUP' -H '3f29138a04aadc19214e9c04028bf381' -n '0ca6227a4f00b9654a48908c4801a0ac' -k 'c24f5102a22d286336aac2dfa4dc2e04' -v
USER WORK: 45005300480045004c004c005300540052004f00500057004f0052004b00470052004f0055005000
PASS HASH: 3f29138a04aadc19214e9c04028bf381
RESP NT:   f48087e449d58b400e283a27914209b9
NT PROOF:  0ca6227a4f00b9654a48908c4801a0ac
KeyExKey:  9754d7acae384644b196c05cda5315df
Random SK: facfbdf010d00aa2574c7c41201099e8
```
{: .wrap }

Adding it to the list of SMB session keys on `Wireshark` the same way as before.

![SMB Second Session Key Added](smb_second_session_key_added.webp){: width="600" height="500" }

Once again, we see that the `SMB3` traffic is decrypted, and this time we see the user accessing the `clients978.csv` file.

![SMB Decrypted Traffic Second](decrypted_smb3_traffic_second.webp){: width="1300" height="500" }

Exporting it the same way as before.

![Export Clients978 CSV](export_clients978_csv.webp){: width="750" height="500" }

Reading the `clients978.csv` file, we find the second flag and complete the room.

```console
$ cat %5cclients978.csv
first_name,last_name,password
Fran,McCane,vP5{|r$IYDDu
Fredrika,Delea,qU2!&Bev
Josefa,Keir,hX0)gq54I"%d
Joannes,Greatham,vS1)N,z1X1rc
Courtenay,Keble,lV6|0aiSZL@@`bbM
Tonye,Risebrow,THM{[REDACTED]}
Joleen,Balog,tK9'ZapdU.'igGs
Clementia,Kilsby,uC6!Bx}`Xe
Mason,Woolvett,eL0$NO)FRY1IT
Rozele,Izachik,wA8>11$,'0,b+
,,
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