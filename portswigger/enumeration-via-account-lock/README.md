# Username Enumeration via Account Locking

A Python script to enumerate valid usernames on web applications that use account locking as brute-force protection.

## Vulnerability

Some websites lock an account after several failed login attempts. This behavior itself leaks information — if an account gets locked, it means it **exists**. Non-existent accounts are never locked, so they always return the same generic error message.

By sending multiple rapid requests for each username, we can trigger the lock on valid accounts and identify them by the different error response.

## Why a Script Instead of Burp Suite Intruder?

Burp Suite Community Edition intentionally throttles Intruder to ~1 request per second. This makes the attack ineffective against account locking because:

- The server resets the failed attempt counter between requests
- By the time the 5th request is sent for a username, enough time has passed for the counter to reset
- The account never actually gets locked, so valid usernames look identical to invalid ones

A Python script sends all 5 requests for each username **as fast as possible**, ensuring the counter is not reset between them and triggering the lock reliably.

## How It Works

1. For each username in the wordlist, send 5 rapid POST requests with an invalid password
2. Check the last response for a lock message (e.g. `You have made too many incorrect login attempts`)
3. If the lock message appears — the username is valid

```
carlos  →  5 requests  →  "Invalid username or password"   →  does not exist
root    →  5 requests  →  "Invalid username or password"   →  does not exist
apps    →  5 requests  →  "You have made too many..."      →  VALID USERNAME ✓
```

## Usage

1. Navigate to the script directory:

```bash
cd portswigger/enumeration-via-account-lock
```

2. Install dependencies:

```bash
pip install requests
```

3. Edit the config at the top of `username_enum.py`:

```python
TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
SESSION_COOKIE = "YOUR_SESSION_COOKIE"
```

4. Run the script:

```bash
python3 username_enum.py
```

## Target

This script was written for the PortSwigger Web Security Academy lab: **"Username enumeration via account lock"**

> For educational purposes only. Only use against systems you have explicit permission to test.

## Requirements

- Python 3.10+
- requests