# Blind SQL Injection with Conditional Errors

**Lab:** PortSwigger Web Security Academy — [Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)  
**Difficulty:** Practitioner  
**Category:** SQL Injection  

---

## Overview

This lab contains a blind SQL injection vulnerability in a tracking cookie. Unlike the previous conditional responses lab, the application **does not** behave differently based on whether the query returns rows. Instead, it returns a custom error message when the SQL query causes an error.

The goal is to exploit this error-based behavior to extract the `administrator` password one character at a time.

---

## How It Works

The application runs a query on every request using the `TrackingId` cookie value. Since there is no visible difference in the response based on query results, we trigger a **database error** as our oracle signal instead.

We use a `CASE` expression to conditionally cause a division-by-zero error:

```sql
' AND (SELECT CASE WHEN (condition) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
```

- condition **true** → executes `1/0` → division by zero → **HTTP 500**
- condition **false** → executes `'a'` → no error → **HTTP 200**

This gives us the same binary oracle as before, just with a different signal.

---

## Database Fingerprinting

Initial testing revealed the backend is **Oracle** — identified by:
- Standard `SUBSTRING()` syntax causing errors
- `FROM dual` being required in `SELECT` statements
- `SUBSTR()` and `TO_CHAR()` working correctly

---

## Extracting the Password

Using `SUBSTR()` (Oracle syntax), we test the password character by character:

```sql
' AND (SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a
```

- HTTP 500 → character matches
- HTTP 200 → try next character

We iterate over all positions and all possible characters (`a-z`, `A-Z`, `0-9`) until the full password is recovered.

---

## Lessons Learned

- When there is no visible difference in responses, look for **error-based** oracles instead.
- Oracle requires `FROM dual` in `SELECT` statements that don't reference a table.
- Oracle uses `SUBSTR()` not `SUBSTRING()`, and `TO_CHAR(1/0)` to trigger a division-by-zero error.
- Always fingerprint the database first — syntax differences between Oracle, MySQL, PostgreSQL can break payloads entirely.

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