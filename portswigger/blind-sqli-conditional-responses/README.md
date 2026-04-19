# Blind SQL Injection with Conditional Responses

**Lab:** PortSwigger Web Security Academy — [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)  
**Difficulty:** Practitioner  
**Category:** SQL Injection  

---

## Overview

This lab contains a blind SQL injection vulnerability in a tracking cookie. The application does **not** return query results directly — instead, it changes behavior based on whether the query returns data. Specifically, a `Welcome back` message appears when the injected condition is **true**, and disappears when it is **false**.

The goal is to exploit this behavior to extract the `administrator` password one character at a time.

---

## How It Works

The application runs a query like this on every request:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = '<cookie_value>'
```

By injecting into the `TrackingId` cookie, we can append conditions:

```sql
-- True condition → "Welcome back" appears
TrackingId = 'xyz' AND '1'='1'

-- False condition → "Welcome back" disappears
TrackingId = 'xyz' AND '1'='2'
```

This gives us a **binary oracle** — we can ask yes/no questions about the database.

---

## Extracting the Password

Using `SUBSTRING()`, we test the password character by character:

```sql
' AND SUBSTRING((SELECT Password FROM Users WHERE username='administrator'), 1, 1) = 'a
```

- If `Welcome back` appears → character matches
- If not → try next character

We iterate over all positions and all possible characters (`a-z`, `A-Z`, `0-9`) until the full password is recovered.

---

## Lessons Learned

- **Table/column names are case-sensitive** on some databases. The table was `Users`, not `USERS` — worth fuzzing if queries return no results.
- **Username casing matters too** — `administrator` (lowercase) worked, `Administrator` did not.
- The `session` cookie causes `Welcome back` to appear regardless (logged-in state). The actual oracle is driven by `TrackingId` — always verify your true/false baseline before automating.
- Burp Intruder Community Edition is throttled — Python scripting is far more practical for this type of attack.

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