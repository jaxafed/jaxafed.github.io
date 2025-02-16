---
title: "TryHackMe: Lo-Fi"
author: jaxafed
categories: [TryHackMe]
tags: [web, lfi, log poisoning, rce]
render_with_liquid: false
media_subpath: /images/tryhackme_lo-fi/
image:
  path: room_image.webp
---

**Lo-Fi** was a very simple room where we exploited a `Local File Inclusion (LFI)` vulnerability to read the flag. Although it was not necessary to complete the room, I will also demonstrate how we could have escalated this `LFI` vulnerability to `RCE` using log poisoning.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/lofi){: .center }

## The Flag

For the room, we are tasked with visiting the web application on the target and using it to read the flag located at the root of the filesystem.

Visiting the website at `http://10.10.17.128/`, we see some links to YouTube videos.

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}

Upon checking other links, we observe that the pages with the videos are included via the `/?page=` parameter.

![Web 80 Include](web_80_include.webp){: width="1200" height="600"}

Trying to use this parameter to read `/flag.txt` with a request like `http://10.10.17.128/?page=/flag.txt`, we encounter an interesting error.

![Web 80 Include Two](web_80_include2.webp){: width="1200" height="600"}

After some testing, we notice that this error only appears if the `page` parameter starts with the `/` character. So, instead of `/flag.txt`, we can use a directory traversal payload like `../../../flag.txt` and by visiting `http://10.10.17.128/?page=../../../flag.txt`, we are able to read the flag and complete the room.

![Web 80 Flag](web_80_flag.webp){: width="1200" height="600"}

## Extra - RCE

We were able to read the flag and complete the room, but we don't have to stop here. We can also look for ways to turn this `LFI` vulnerability into `RCE`. 

One of the most common methods for this is **log poisoning**, where our goal is to "poison" a log file by writing a `PHP` payload to it and then executing the payload by including the poisoned log file.

For this, when checking the log files we can poison, we notice that we are unable to include the `access.log` file directly.

![Web 80 Include Three](web_80_include3.webp){: width="1200" height="600"}

However, by checking the open file descriptors for the current process, we notice that we are able to include it via `/proc/self/fd/6`.

![Web 80 Include Four](web_80_include4.webp){: width="1200" height="600"}

Now that we are able to include the log file, we can see that our user agent is also logged in this file, which we can use to poison the log by changing our user agent to `<?php if(isset($_GET['cmd'])){system($_GET['cmd'] . ' 2>&1');} ?>` and making a request to the server.

![Web 80 Log Poison](web_80_log_poison.webp){: width="1000" height="600"}

After poisoning the log, if we include the log file again and send our command, we can see that we successfully execute commands.

![Web 80 Rce](web_80_rce.webp){: width="1200" height="600"}

> While it is possible to use this `RCE` vulnerability to get a shell inside the container and escalate privileges to the `root` user via the `DirtyPipe` vulnerability, I was not successful in escaping the container. If you can, please share with me how.  
{: .prompt-tip }

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


