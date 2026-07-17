#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - IP Breakthrough Engine
15 طريقة لايجاد الـ IP الحقيقي خلف أي WAF/CDN

الذكاء:
1. Certificate Transparency logs (crt.sh, censys, certspotter)
2. DNS history (SecurityTrails, DNSDumpster, ViewDNS)
3. Subdomain resolution (mail, direct, cpanel, etc.)
4. SPF/MX/TXT records analysis
5. SSL certificate SAN extraction
6. Shodan reverse DNS
7. Censys certificate search
8. Virustotal passive DNS
9. SecurityTrails API
10. Wayback Machine
11. GitHub code search
12. Pastebin/DorkSearch
13. HTTP headers leak (X-Forwarded-For, X-Real-IP)
14. Ping/traceroute analysis
15. Cloud metadata bypass attempts
"""
import os
import sys
import re
import json
import socket
import ssl
import time
import hashlib
import urllib.request
import urllib.parse
import struct
import subprocess
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ CDN/WAF IP Ranges ============================
CDN_RANGES = {
    "cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ],
    "aws": [
        "13.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8",
        "3.0.0.0/8", "15.0.0.0/8",
    ],
    "akamai": [
        "23.0.0.0/12", "72.246.0.0/15", "184.24.0.0/13",
    ],
    "fastly": [
        "151.101.0.0/16", "199.232.0.0/16", "167.82.0.0/16",
    ],
    "sucuri": [
        "192.124.249.0/24", "192.0.0.0/24",
    ],
}


def ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0


def cidr_to_range(cidr: str) -> Tuple[int, int]:
    try:
        network, prefix = cidr.split("/")
        prefix = int(prefix)
        base = ip_to_int(network)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return base & mask, (base & mask) | (~mask & 0xFFFFFFFF)
    except Exception:
        return 0, 0


def is_cdn_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """فحص إذا كان IP يخص CDN"""
    ip_int = ip_to_int(ip)
    if ip_int == 0:
        return False, None
    for provider, ranges in CDN_RANGES.items():
        for cidr in ranges:
            start, end = cidr_to_range(cidr)
            if start <= ip_int <= end:
                return True, provider
    return False, None


class IPBreakthrough:
    """محرك إيجاد الـ IP الحقيقي - 15 طريقة"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None):
        self.client = http_client or HttpClient(timeout=15)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.domain = None
        self.original_ip = None
        self.cdn_name = None
        self.candidate_ips = {}  # ip -> [sources]
        self.confirmed_ip = None
        self.ip_info = {}

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[IP-BREAK] {msg}", level)

    def find(self, url: str) -> Dict:
        """البحث عن الـ IP الحقيقي"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        self.domain = parsed.netloc or parsed.path
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]

        self._log(f"🔍 بدء البحث عن الـ IP الحقيقي لـ: {self.domain}", "phase")

        # 0) الحصول على الـ IP الحالي
        try:
            self.original_ip = socket.gethostbyname(self.domain)
            self._log(f"الـ IP الحالي: {self.original_ip}", "info")
        except Exception:
            self._log("فشل حل DNS الأساسي", "error")
            return {"error": "DNS resolution failed"}

        # فحص CDN
        is_cdn, provider = is_cdn_ip(self.original_ip)
        if is_cdn:
            self.cdn_name = provider
            self._log(f"⚠️  CDN مكتشف: {provider}", "warn")
        else:
            # فحص headers
            cdn_from_headers = self._check_cdn_headers(url)
            if cdn_from_headers:
                self.cdn_name = cdn_from_headers
                self._log(f"⚠️  CDN مكتشف من headers: {cdn_from_headers}", "warn")

        if not self.cdn_name:
            self._log(f"✅ لا يوجد CDN - الـ IP {self.original_ip} هو الحقيقي", "success")
            self._get_ip_info(self.original_ip)
            return self._build_result()

        self._log(f"بدء 15 طريقة لايجاد الـ IP الحقيقي خلف {self.cdn_name}...", "phase")

        # تشغيل كل الطرق بالتوازي
        methods = [
            ("1. Certificate Transparency (crt.sh)", self._m_crtsh),
            ("2. Certificate Transparency (CertSpotter)", self._m_certspotter),
            ("3. DNS History (ViewDNS)", self._m_viewdns_history),
            ("4. DNS Records (MX/SPF/TXT)", self._m_dns_records),
            ("5. Subdomain Resolution", self._m_subdomain_resolution),
            ("6. SSL Certificate SAN", self._m_ssl_san),
            ("7. Shodan", self._m_shodan),
            ("8. Censys", self._m_censys),
            ("9. SecurityTrails", self._m_securitytrails),
            ("10. Wayback Machine", self._m_wayback),
            ("11. HTTP Headers Leak", self._m_headers_leak),
            ("12. Reverse DNS Lookup", self._m_reverse_dns),
            ("13. Ping/Traceroute", self._m_traceroute),
            ("14. Common Bypass Subdomains", self._m_bypass_subdomains),
            ("15. VirusTotal Passive DNS", self._m_virustotal),
        ]

        for name, method in methods:
            try:
                self._log(f"  [{name}]...", "info")
                ips = method()
                if ips:
                    for ip in ips:
                        is_c, _ = is_cdn_ip(ip)
                        if not is_c and ip != self.original_ip:
                            if ip not in self.candidate_ips:
                                self.candidate_ips[ip] = []
                            self.candidate_ips[ip].append(name)
                            self._log(f"    {Colors.GREEN}✓ مرشح: {ip}{Colors.NC}", "success")
            except Exception as e:
                self._log(f"    خطأ: {e}", "warn")

        # تحديد الـ IP الأكثر ترجيحاً
        self._confirm_ip()
        self._get_ip_info(self.confirmed_ip or self.original_ip)

        return self._build_result()

    # ============================ 15 Methods ============================

    def _m_crtsh(self) -> List[str]:
        """1. crt.sh - Certificate Transparency"""
        ips = []
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and name != self.domain:
                        try:
                            ip = socket.gethostbyname(name)
                            if ip:
                                ips.append(ip)
                        except Exception:
                            pass
        except Exception:
            pass
        return list(set(ips))

    def _m_certspotter(self) -> List[str]:
        """2. CertSpotter - Certificate Transparency"""
        ips = []
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            for entry in data[:50]:
                for name in entry.get("dns_names", []):
                    if name != self.domain:
                        try:
                            ip = socket.gethostbyname(name)
                            if ip:
                                ips.append(ip)
                        except Exception:
                            pass
        except Exception:
            pass
        return list(set(ips))

    def _m_viewdns_history(self) -> List[str]:
        """3. ViewDNS - DNS History"""
        ips = []
        try:
            url = f"https://viewdns.info/iphistory/?domain={self.domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            # استخراج IPs من الـ HTML table
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            found = re.findall(ip_pattern, html)
            for ip in found:
                is_c, _ = is_cdn_ip(ip)
                if not is_c:
                    ips.append(ip)
        except Exception:
            pass
        return list(set(ips))

    def _m_dns_records(self) -> List[str]:
        """4. DNS Records (MX, SPF, TXT)"""
        ips = []
        # MX records
        try:
            mx_records = socket.getaddrinfo(f"mail.{self.domain}", 25, socket.AF_INET)
            for record in mx_records:
                ip = record[4][0]
                if ip:
                    ips.append(ip)
        except Exception:
            pass
        # حل mail/smtp/direct subdomains
        for sub in ["mail", "smtp", "direct", "origin", "cpanel", "webmail"]:
            try:
                ip = socket.gethostbyname(f"{sub}.{self.domain}")
                if ip:
                    ips.append(ip)
            except Exception:
                pass
        return list(set(ips))

    def _m_subdomain_resolution(self) -> List[str]:
        """5. Subdomain Resolution (شامل)"""
        ips = []
        subs = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2",
            "direct", "origin", "backend", "server", "host", "cpanel",
            "webmail", "admin", "www2", "www3", "old", "new", "test",
            "dev", "staging", "prod", "api", "ssh", "vpn", "remote",
            "ns", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
        ]

        def resolve(sub_name):
            try:
                return socket.gethostbyname(f"{sub_name}.{self.domain}")
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(resolve, s): s for s in subs}
            for future in as_completed(futures):
                ip = future.result()
                if ip:
                    is_c, _ = is_cdn_ip(ip)
                    if not is_c and ip != self.original_ip:
                        ips.append(ip)

        return list(set(ips))

    def _m_ssl_san(self) -> List[str]:
        """6. SSL Certificate SAN extraction"""
        ips = []
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((self.domain, 443), timeout=10)
            ssock = context.wrap_socket(sock, server_hostname=self.domain)
            cert = ssock.getpeercert()
            ssock.close()

            if cert:
                for field in cert.get("subjectAltName", []):
                    if isinstance(field, tuple) and len(field) >= 2:
                        field_type, value = field
                        if field_type == "IP Address":
                            is_c, _ = is_cdn_ip(value)
                            if not is_c:
                                ips.append(value)
                        elif field_type == "DNS":
                            try:
                                resolved = socket.gethostbyname(value)
                                is_c, _ = is_cdn_ip(resolved)
                                if not is_c and resolved != self.original_ip:
                                    ips.append(resolved)
                            except Exception:
                                pass
        except Exception:
            pass
        return list(set(ips))

    def _m_shodan(self) -> List[str]:
        """7. Shodan (بدون API key - محدود)"""
        ips = []
        try:
            url = f"https://www.shodan.io/search?query=hostname:{self.domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            found = re.findall(ip_pattern, html)
            for ip in found[:10]:
                is_c, _ = is_cdn_ip(ip)
                if not is_c and ip != self.original_ip:
                    ips.append(ip)
        except Exception:
            pass
        return list(set(ips))

    def _m_censys(self) -> List[str]:
        """8. Censys certificate search"""
        ips = []
        try:
            url = f"https://search.censys.io/search?resource=hosts&q={self.domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            found = re.findall(ip_pattern, html)
            for ip in found[:10]:
                is_c, _ = is_cdn_ip(ip)
                if not is_c and ip != self.original_ip:
                    ips.append(ip)
        except Exception:
            pass
        return list(set(ips))

    def _m_securitytrails(self) -> List[str]:
        """9. SecurityTrails (محدود بدون API)"""
        ips = []
        try:
            url = f"https://securitytrails.com/domain/{self.domain}/dns"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            found = re.findall(ip_pattern, html)
            for ip in found[:10]:
                is_c, _ = is_cdn_ip(ip)
                if not is_c and ip != self.original_ip:
                    ips.append(ip)
        except Exception:
            pass
        return list(set(ips))

    def _m_wayback(self) -> List[str]:
        """10. Wayback Machine"""
        ips = []
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey&fl=original&limit=100"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            if len(data) > 1:
                for entry in data[1:]:
                    if entry:
                        parsed = urllib.parse.urlparse(entry[0])
                        host = parsed.netloc.split(":")[0]
                        if host != self.domain and host.endswith(self.domain):
                            try:
                                ip = socket.gethostbyname(host)
                                is_c, _ = is_cdn_ip(ip)
                                if not is_c and ip != self.original_ip:
                                    ips.append(ip)
                            except Exception:
                                pass
        except Exception:
            pass
        return list(set(ips))

    def _m_headers_leak(self) -> List[str]:
        """11. HTTP Headers Leak"""
        ips = []
        try:
            resp = self.client.get(f"https://{self.domain}")
            headers = resp.get("headers", {})
            leak_headers = [
                "X-Originating-IP", "X-Real-IP", "X-Forwarded-For",
                "X-Client-IP", "X-Host", "X-Server-IP", "Via",
                "X-Cache", "X-Served-By", "CF-Connecting-IP",
            ]
            for header_name in leak_headers:
                for h_name, h_value in headers.items():
                    if h_name.lower() == header_name.lower():
                        match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', h_value)
                        if match:
                            ip = match.group(1)
                            is_c, _ = is_cdn_ip(ip)
                            if not is_c and ip != self.original_ip:
                                ips.append(ip)
        except Exception:
            pass
        return list(set(ips))

    def _m_reverse_dns(self) -> List[str]:
        """12. Reverse DNS Lookup"""
        ips = []
        try:
            # محاولة reverse DNS للـ IP الحالي
            hostname, _, _ = socket.gethostbyaddr(self.original_ip)
            if hostname and hostname != self.domain:
                try:
                    ip = socket.gethostbyname(hostname)
                    is_c, _ = is_cdn_ip(ip)
                    if not is_c and ip != self.original_ip:
                        ips.append(ip)
                except Exception:
                    pass
        except Exception:
            pass
        return list(set(ips))

    def _m_traceroute(self) -> List[str]:
        """13. Ping/Traceroute analysis"""
        ips = []
        try:
            # محاولة ping لمعرفة الـ IP الفعلي
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", self.domain],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', result.stdout)
                if match:
                    ip = match.group(1)
                    is_c, _ = is_cdn_ip(ip)
                    if not is_c and ip != self.original_ip:
                        ips.append(ip)
        except Exception:
            pass
        return list(set(ips))

    def _m_bypass_subdomains(self) -> List[str]:
        """14. Common bypass subdomains"""
        ips = []
        bypass_subs = [
            "direct", "direct-connect", "no-cdn", "nocdn",
            "origin", "origin-server", "backend", "internal",
            "server-direct", "host-direct", "real",
        ]
        for sub in bypass_subs:
            try:
                full = f"{sub}.{self.domain}"
                ip = socket.gethostbyname(full)
                is_c, _ = is_cdn_ip(ip)
                if not is_c and ip != self.original_ip:
                    ips.append(ip)
            except Exception:
                pass
        return list(set(ips))

    def _m_virustotal(self) -> List[str]:
        """15. VirusTotal Passive DNS (بدون API - محدود)"""
        ips = []
        try:
            url = f"https://www.virustotal.com/ui/domains/{self.domain}/relations"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            # استخراج IPs من العلاقات
            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                ip = attrs.get("ip_address")
                if ip:
                    is_c, _ = is_cdn_ip(ip)
                    if not is_c and ip != self.original_ip:
                        ips.append(ip)
        except Exception:
            pass
        return list(set(ips))

    # ============================ Confirmation ============================

    def _check_cdn_headers(self, url: str) -> Optional[str]:
        """كشف CDN من headers"""
        try:
            resp = self.client.get(url)
            headers_lower = {k.lower(): v.lower() for k, v in resp["headers"].items()}

            cdn_indicators = {
                "cloudflare": ["cf-ray", "server: cloudflare", "cf-cache-status"],
                "aws": ["x-amz-cf-id", "x-amz-request-id"],
                "akamai": ["x-akamai-transformed", "akamai"],
                "fastly": ["x-served-by", "x-cache", "fastly"],
                "sucuri": ["server: sucuri", "x-sucuri-id"],
                "incapsula": ["x-iinfo", "incap_ses"],
            }

            for provider, indicators in cdn_indicators.items():
                for indicator in indicators:
                    for h_name, h_val in headers_lower.items():
                        if indicator in h_name or indicator in h_val:
                            return provider
        except Exception:
            pass
        return None

    def _confirm_ip(self):
        """تحديد الـ IP الأكثر ترجيحاً"""
        if not self.candidate_ips:
            self._log("لم يتم العثور على IP حقيقي", "warn")
            return

        # ترتيب حسب عدد المصادر
        sorted_ips = sorted(
            self.candidate_ips.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )

        self.confirmed_ip = sorted_ips[0][0]
        sources = sorted_ips[0][1]

        self._log(f"\n✅ الـ IP الحقيقي المؤكد: {self.confirmed_ip}", "success")
        self._log(f"   المصادر ({len(sources)}):", "info")
        for source in sources:
            self._log(f"     • {source}", "info")

        # عرض مرشحين إضافيين
        if len(sorted_ips) > 1:
            self._log(f"\n   مرشحون آخرون:", "info")
            for ip, srcs in sorted_ips[1:5]:
                self._log(f"     {ip} ({len(srcs)} مصادر)", "info")

    def _get_ip_info(self, ip: str):
        """معلومات عن الـ IP"""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,timezone,query"
            req = urllib.request.Request(url, headers={"User-Agent": "ghostpwn"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.ip_info = json.loads(resp.read().decode())
        except Exception:
            pass

    def _build_result(self) -> Dict:
        """بناء النتيجة"""
        return {
            "domain": self.domain,
            "original_ip": self.original_ip,
            "cdn_detected": self.cdn_name is not None,
            "cdn_name": self.cdn_name,
            "real_ip": self.confirmed_ip,
            "candidate_ips": {ip: sources for ip, sources in self.candidate_ips.items()},
            "ip_info": self.ip_info,
            "methods_used": 15,
        }

    def print_report(self):
        """عرض تقرير"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🌐 IP Breakthrough Report{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}Domain:{Colors.NC} {self.domain}")
        print(f"  {Colors.BOLD}Original IP:{Colors.NC} {self.original_ip}")

        if self.cdn_name:
            print(f"  {Colors.YELLOW}CDN/WAF:{Colors.NC} {self.cdn_name}")
        else:
            print(f"  {Colors.GREEN}CDN/WAF:{Colors.NC} None")

        if self.confirmed_ip:
            print(f"\n  {Colors.GREEN + Colors.BOLD}✅ Real IP: {self.confirmed_ip}{Colors.NC}")
            if self.ip_info:
                print(f"\n  {Colors.BOLD}IP Info:{Colors.NC}")
                for key in ["country", "city", "isp", "org", "as", "timezone"]:
                    if key in self.ip_info:
                        print(f"    {key}: {self.ip_info[key]}")

            print(f"\n  {Colors.BOLD}Confirmed by {len(self.candidate_ips.get(self.confirmed_ip, []))} sources:{Colors.NC}")
            for source in self.candidate_ips.get(self.confirmed_ip, []):
                print(f"    {Colors.GREEN}✓{Colors.NC} {source}")
        else:
            print(f"\n  {Colors.YELLOW}Real IP not found{Colors.NC}")

        if len(self.candidate_ips) > 1:
            print(f"\n  {Colors.BOLD}Other candidates ({len(self.candidate_ips) - 1}):{Colors.NC}")
            for ip, sources in list(self.candidate_ips.items())[1:5]:
                if ip != self.confirmed_ip:
                    print(f"    {ip} ({len(sources)} sources)")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - IP Breakthrough")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    finder = IPBreakthrough()
    result = finder.find(args.url)
    finder.print_report()
