---
title: 'TryHackMe: Chrome'
author: jaxafed
categories: [TryHackMe]
tags: [pcap, smb, wireshark, dnspy, windows, chrome, dpapi, mimikatz]
render_with_liquid: false
media_subpath: /images/tryhackme_chrome/
image:
  path: room_image.webp
---

Chrome was a room all about decryption. As a start, we are given a packet capture file with SMB traffic. We are able to extract two files from this traffic: a .NET assembly file and a file encrypted with the mentioned assembly. By reverse engineering and modifying the assembly file, we are able to decrypt the encrypted file and get a zip archive. Inside the archive, we find some data belonging to Google Chrome along with a DPAPI masterkey. By cracking the masterkey, we are able to get the user’s password and use it to decrypt the masterkey. With the decrypted masterkey, we are also able to decrypt the encryption key used by Google Chrome to encrypt users’s saved passwords and decrypt those passwords.

![Tryhackme Room Link](room_card.webp){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/chrome>_

## Examining the packet capture

At the start of the room, we are given a zip archive with a single packet capture file inside.

```console
$ file chromefiles.zip    
chromefiles.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
                                                                                                                               
$ zipinfo chromefiles.zip 
Archive:  chromefiles.zip
Zip file size: 76020416 bytes, number of entries: 1
-rwxr-xr-x  3.0 unx 76349972 bx defN 23-Oct-22 05:26 traffic.pcapng
1 file, 76349972 bytes uncompressed, 76020238 bytes compressed:  0.4%
```

Extracting the packet capture and opening it in Wireshark.

First, checking out the statistics.

![Wireshark Opening Statistics](wireshark_opening_statistics.webp){: width="1000" height="400" }

We notice most of the traffic inside is from the SMB protocol.

![Wireshark Statistics](wireshark_statistics.webp){: width="1000" height="500" }

## Extracting the files

Checking for files transferred with the SMB protocol.

![Wireshark SMB Export](wireshark_smb_export.webp){: width="400" height="500" }

There are two interesting files:

![Wireshark SMB Files](wireshark_smb_files.webp){: width="700" height="500" }

- `transfer.exe`
- `encrypted_files`

Saving both of them.

While `transfer.exe` seems to a be .NET assembly, `encrypted_files` seems to be just random data.

```console
$ file transfer.exe   
transfer.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
                                                                                                                               
$ file encrypted_files 
encrypted_files: data
```

## Decrypting the encrypted_files

### Analyzing the transfer.exe

Since `transfer.exe` is .NET assembly, I will use `dnSpy` to analyze it.

Opening it in `dnSpy` and looking at the `main` function, we are able to see what it does.

![Transfer.exe In Dnspy](transfer_exe_dnspy.webp){: width="1300" height="600" }

- First, it declares two byte arrays, `bytes` and `bytes2`, and later uses them as key and IV for AES encryption.
- Reads the contents of the `C:\Users\hadri\Downloads\files.zip` file.
- Performs encryption on the file contents and writes the encrypted data to the `C:\Users\hadri\Downloads\encrypted_files` file.

### Modifying it to perform decryption

Since `dnSpy` allows us to modify .NET assemblies easily, we can modify it to perform decryption instead of encryption.

Opening the edit window.

![Dnspy Edit Method](dnspy_edit_method.webp){: width="600" height="400" }

Making the changes to perform decryption.

![Transfer.exe Edited](transfer_exe_edited.webp){: width="1000" height="500" }

We can now compile and save it with the edited changes.

### Running the new assembly

Running the new modified assembly, we perform the decryption and get the `files.zip` archive.

![Encrypted_files Decryption](encrypted_files_decryption.webp){: width="700" height="500" }

## Examining the extracted files

Extracting the archive, two things stand out.

- Google Chrome data at `/AppData/Local/Google/Chrome/`
- DPAPI masterkey at `/AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580`

Before moving on with trying to decrypt the passwords saved by `Google Chrome`, there are a couple of things we must know.

- Google Chrome stores saved passwords in the `/AppData/Local/Google/Chrome/User Data/Default/Login Data` sqlite database file in an encrypted state.
- The encryption key used to encrypt saved passwords stored in the `/AppData/Local/Google/Chrome/User Data/Local State` json file as `os_crypt.encrypted_key`. The encryption key is also stored in an encrypted state, and it is encrypted using `DPAPI`.
- `DPAPI` uses `masterkeys` to perform encryption and decryption, and they are also stored encrypted with a key derived from the user's password.

## Cracking the DPAPI masterkey

We need the password for the user to be able to decrypt the masterkey and since we don't have it, we can try using brute-forcing to find it.

First, using `DPAPImk2john` to convert the masterkey to a format `john` can work with.

```console
$ DPAPImk2john -mk AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580 -c local -S S-1-5-21-3854677062-280096443-3674533662-1001 > mkhash
```
{: .wrap }

Now, using `john` to crack the hash, we get the password for the user and able to answer the first question.

```console
$ john mkhash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (DPAPImk, DPAPI masterkey file v1 and v2 [SHA1/MD4 PBKDF2-(SHA1/SHA512)-DPAPI-variant 3DES/AES256 128/128 SSE2 4x])
Cost 1 (iteration count) is 8000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]         (?)     
1g 0:00:00:00 DONE (2024-03-03 00:54) 2.325g/s 111.6p/s 111.6c/s 111.6C/s purple..1234567890
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
{: .wrap }

## Decrypting the masterkey

Knowing the user's password, we can use `mimikatz`'s `dpapi::masterkey` module to decrypt the masterkey.

- `/in`: Path of the masterkey
- `/sid`: Security Identifier for the user; we can find it in the path for masterkey.
- `/password`: Password of the user.

```console
mimikatz # dpapi::masterkey /in:"AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580" /sid:S-1-5-21-3854677062-280096443-3674533662-1001 /password:[REDACTED]
...
[masterkey] with password: [REDACTED] (normal user)
  key : ca43[REDACTED]9840
  sha1: 217522c457cfe8a95da45da81d6b898080e2067d

```
{: .wrap }

## Decrypting the passwords

Now that we have the decrypted masterkey, we can use it to decrypt the encrypted key and use that to decrypt the passwords. I will also use `mimikatz` for this.

First, extracting the encrypted key from `Local State`.

```console
$ cat AppData/Local/Google/Chrome/User\ Data/Local\ State | jq .os_crypt.encrypted_key -r
RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAACHYWuMqo69SL4WmCEqRBWAAAAAAAIAAAAAABBmAAAAAQAAIAAAAHPuV6P/8jN+rng8E61Z0xxi2hUf4Q4oxa5gFqSnctqdAAAAAA6AAAAAAgAAIAAAAAEF9lst8zMKmCFJ3WmD46TZY/xJF+s5Xf9mTQ2wa16ZMAAAABFU2C2V+l6K3y7ROKkA0cIaWyuXB9i7zUwBBu6mt7vM2QGZtqmjhcX6ZSWrX8JUwkAAAADgBkMLAP19Rtax5T8aKAESgwV+ABz65DOgEGwwSkkQMbWrwz7p42SzpfJUj7jcyUSTOblLRNtB8YTwhm3wCQSi
```
{: .wrap }

We can use the `dpapi::chrome` module in `mimikatz` to retrieve the saved passwords. The module accomplishes this by first decrypting the key used to encrypt the passwords using the user's masterkey. Then, uses the decrypted key to decrypt the passwords inside `Login Data`.

- `/in`: Path of the `Login Data` database file.
- `/masterkey`: Masterkey used to encrypt the key.
- `/encryptedKey`: Encrypted key from `Local State` that is used for encrypting the passwords.

```console
mimikatz # dpapi::chrome /in:"AppData/Local/Google/Chrome/User Data/Default/Login Data" /masterkey:ca43[REDACTED]9840 /encryptedKey:RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAACHYWuMqo69SL4WmCEqRBWAAAAAAAIAAAAAABBmAAAAAQAAIAAAAHPuV6P/8jN+rng8E61Z0xxi2hUf4Q4oxa5gFqSnctqdAAAAAA6AAAAAAgAAIAAAAAEF9lst8zMKmCFJ3WmD46TZY/xJF+s5Xf9mTQ2wa16ZMAAAABFU2C2V+l6K3y7ROKkA0cIaWyuXB9i7zUwBBu6mt7vM2QGZtqmjhcX6ZSWrX8JUwkAAAADgBkMLAP19Rtax5T8aKAESgwV+ABz65DOgEGwwSkkQMbWrwz7p42SzpfJUj7jcyUSTOblLRNtB8YTwhm3wCQSi
> Encrypted Key seems to be protected by DPAPI
 * masterkey     : ca43[REDACTED]9840
> AES Key is: 9a30[REDACTED]192c

URL     : https://[REDACTED]/ ( https://[REDACTED]/ )
Username: Administrator
 * using BCrypt with AES-256-GCM
Password: [REDACTED]

URL     : https://[REDACTED]/ ( https://[REDACTED]/ )
Username: chrome
 * using BCrypt with AES-256-GCM
Password: [REDACTED]
```
{: .wrap }

With this, we can answer all of the remaining questions and complete the room.

<style>
.wrap pre{
	white-space: pre-wrap;
}
</style>

