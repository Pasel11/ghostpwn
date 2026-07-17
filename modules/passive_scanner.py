#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Passive Scanner
فحص سلبي فقط - بدون إرسال payloads

يحلل فقط:
1. HTTP headers
2. Cookies
3. robots.txt / sitemap.xml
4. Certificate info
5. DNS records
6. Public information
7. JavaScript files
"""
import os
import sys
import re
import socket
import ssl
import json
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


class PassiveScanner:
    """فحص سلبي فقط"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None):
        self.client = http_client or HttpClient(timeout=15)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.findings = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[PASSIVE] {msg}", level)

    def _add_finding(self, ftype: str, severity: str, url: str,
                     title: str, description: str = "", **extra):
        finding = {
            "type": ftype,
            "severity": severity,
            "url": url,
            "title": title,
            "description": description,
        }
        finding.update(extra)
        self.findings.append(finding)

        # طباعة فورية
        sev_colors = {
            "critical": Colors.RED + Colors.BOLD,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.GRAY,
        }
        sev_labels = {
            "critical": "حرج",
            "high": "عالي",
            "medium": "متوسط",
            "low": "منخفض",
            "info": "معلومة",
        }
        color = sev_colors.get(severity, Colors.NC)
        label = sev_labels.get(severity, severity)

        print(f"\n  {color}┌─ [{label.upper()}] {ftype}{Colors.NC}")
        print(f"  {color}│{Colors.NC} {fix_display(title)}")
        if url:
            print(f"  {color}│{Colors.NC} URL: {url[:80]}")
        if description:
            print(f"  {color}│{Colors.NC} {fix_display(description[:100])}")
        print(f"  {color}└─{Colors.NC}")

    def scan(self, url: str) -> List[Dict]:
        """فحص سلبي كامل"""
        self._log(f"بدء الفحص السلبي لـ: {url}", "phase")

        # 1) تحليل HTTP headers
        self._analyze_headers(url)

        # 2) تحليل cookies
        self._analyze_cookies(url)

        # 3) فحص robots.txt
        self._check_robots(url)

        # 4) فحص sitemap.xml
        self._check_sitemap(url)

        # 5) تحليل SSL Certificate
        self._analyze_ssl(url)

        # 6) DNS records
        self._analyze_dns(url)

        # 7) فحص ملفات حساسة (passive - فقط HEAD requests)
        self._check_sensitive_files(url)

        self._log(f"اكتمل الفحص السلبي: {len(self.findings)} نتيجة", "success")

        return self.findings

    def _analyze_headers(self, url: str):
        """تحليل HTTP headers"""
        self._log("تحليل HTTP headers...", "info")
        resp = self.client.get(url)

        if resp["status"] == 0:
            return

        headers = {k.lower(): v for k, v in resp["headers"].items()}

        # Security headers مفقودة
        security_headers = {
            "strict-transport-security": ("HSTS", "حماية ضد downgrade attacks"),
            "content-security-policy": ("CSP", "حماية ضد XSS و injection"),
            "x-frame-options": ("X-Frame-Options", "حماية ضد clickjacking"),
            "x-content-type-options": ("X-Content-Type-Options", "منع MIME sniffing"),
            "x-xss-protection": ("X-XSS-Protection", "فلتر XSS في المتصفح"),
            "referrer-policy": ("Referrer-Policy", "تحكم في referrer header"),
            "permissions-policy": ("Permissions-Policy", "تحكم في API permissions"),
        }

        for header, (name, desc) in security_headers.items():
            if header not in headers:
                self._add_finding(
                    "missing_security_header", "low", url,
                    f"Header أمني مفقود: {name}",
                    desc,
                    header=name,
                )

        # Information disclosure
        info_headers = ["server", "x-powered-by", "x-aspnet-version",
                       "x-generator", "x-runtime", "via"]

        for header in info_headers:
            if header in headers:
                value = headers[header]
                self._add_finding(
                    "info_disclosure_header", "info", url,
                    f"كشف معلومات: {header}",
                    f"القيمة: {value}",
                    header=header,
                    value=value,
                )

    def _analyze_cookies(self, url: str):
        """تحليل cookies"""
        self._log("تحليل cookies...", "info")
        resp = self.client.get(url)

        set_cookie = resp["headers"].get("Set-Cookie", "")
        if not set_cookie:
            return

        cookies = set_cookie.split(",")
        for cookie in cookies:
            issues = []
            cookie_lower = cookie.lower()

            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite flag")

            if issues:
                cookie_name = cookie.split("=")[0].strip()
                self._add_finding(
                    "insecure_cookie", "low", url,
                    f"Cookie غير آمن: {cookie_name}",
                    "; ".join(issues),
                    cookie=cookie_name,
                )

    def _check_robots(self, url: str):
        """فحص robots.txt"""
        self._log("فحص robots.txt...", "info")
        robots_url = url.rstrip("/") + "/robots.txt"
        resp = self.client.get(robots_url)

        if resp["status"] == 200 and len(resp["body"]) > 10:
            # استخراج Disallow paths
            disallow_paths = re.findall(r"Disallow:\s*(.+)", resp["body"], re.IGNORECASE)
            if disallow_paths:
                self._add_finding(
                    "robots_disclosure", "info", robots_url,
                    "robots.txt يكشف مسارات حساسة",
                    f"مسارات: {', '.join(disallow_paths[:5])}",
                    paths=disallow_paths,
                )

    def _check_sitemap(self, url: str):
        """فحص sitemap.xml"""
        self._log("فحص sitemap.xml...", "info")
        sitemap_url = url.rstrip("/") + "/sitemap.xml"
        resp = self.client.get(sitemap_url)

        if resp["status"] == 200 and "<urlset" in resp["body"]:
            urls = re.findall(r"<loc>([^<]+)</loc>", resp["body"])
            if urls:
                self._add_finding(
                    "sitemap_disclosure", "info", sitemap_url,
                    f"sitemap.xml يكشف {len(urls)} URL",
                    f"أول 5: {', '.join(urls[:5])}",
                    urls=urls,
                )

    def _analyze_ssl(self, url: str):
        """تحليل SSL Certificate"""
        if not url.startswith("https://"):
            return

        self._log("تحليل SSL Certificate...", "info")

        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((hostname, port), timeout=10)
            ssock = ctx.wrap_socket(sock, server_hostname=hostname)
            cert = ssock.getpeercert()
            ssock.close()

            if cert:
                # فحص expiry
                import datetime
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.utcnow()).days

                    if days_left < 0:
                        self._add_finding(
                            "ssl_expired", "high", url,
                            "شهادة SSL منتهية",
                            f"انتهت منذ {abs(days_left)} يوم",
                        )
                    elif days_left < 30:
                        self._add_finding(
                            "ssl_expiring_soon", "medium", url,
                            f"شهادة SSL ستنتهي خلال {days_left} يوم",
                            f"تاريخ الانتهاء: {not_after}",
                        )

                # فحص weak signature
                sig_alg = cert.get("signatureAlgorithm", "")
                if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
                    self._add_finding(
                        "ssl_weak_signature", "medium", url,
                        f"توقيع SSL ضعيف: {sig_alg}",
                        "استخدم SHA-256 أو أقوى",
                    )

        except Exception as e:
            self._log(f"SSL analysis error: {e}", "warn")

    def _analyze_dns(self, url: str):
        """تحليل DNS records"""
        self._log("تحليل DNS records...", "info")

        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname

        try:
            # TXT records (قد تكشف SPF/DKIM)
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "TXT", hostname],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                txt_records = result.stdout.strip().split("\n")
                self._add_finding(
                    "dns_txt_records", "info", url,
                    f"TXT records: {len(txt_records)}",
                    f"أول 3: {', '.join(txt_records[:3])}",
                )
        except Exception:
            pass

    def _check_sensitive_files(self, url: str):
        """فحص ملفات حساسة (passive - HEAD فقط)"""
        self._log("فحص ملفات حساسة...", "info")

        sensitive_files = [
            "/.env", "/.git/config", "/.git/HEAD",
            "/wp-config.php.bak", "/config.php.bak",
            "/backup.sql", "/db.sql",
            "/phpinfo.php", "/info.php",
            "/server-status", "/actuator/env",
            "/swagger-ui", "/graphql",
        ]

        for filepath in sensitive_files:
            test_url = url.rstrip("/") + filepath
            resp = self.client.request(test_url, "HEAD")

            if resp["status"] == 200:
                self._add_finding(
                    "sensitive_file_exposed", "high", test_url,
                    f"ملف حساس مكشوف: {filepath}",
                    f"الحالة: {resp['status']}",
                    path=filepath,
                )

    def print_results(self):
        """عرض النتائج"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔍 تقرير الفحص السلبي{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        # إحصائيات حسب الخطورة
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info")
            if sev in sev_counts:
                sev_counts[sev] += 1

        print(f"\n  {Colors.BOLD}📊 النتائج:{Colors.NC}")
        labels = {"critical": "حرج", "high": "عالي", "medium": "متوسط",
                 "low": "منخفض", "info": "معلومة"}
        for sev, count in sev_counts.items():
            if count > 0:
                color = {
                    "critical": Colors.RED + Colors.BOLD,
                    "high": Colors.RED,
                    "medium": Colors.YELLOW,
                    "low": Colors.BLUE,
                    "info": Colors.GRAY,
                }.get(sev, Colors.NC)
                print(f"    {color}{labels[sev]:8s}: {count}{Colors.NC}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Passive Scanner")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    scanner = PassiveScanner()
    scanner.scan(args.url)
    scanner.print_results()
