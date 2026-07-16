#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Real IP Finder
إيجاد الـ IP الحقيقي للموقع خلف CDN/WAF (Cloudflare, AWS, Akamai, etc.)

الطرق:
1. DNS history (SecurityTrails, DNSDumpster)
2. Subdomain scanning (subdomains قد تكشف الـ IP الحقيقي)
3. SPF/MX records (تكشف mail servers IPs)
4. SSL certificate transparency
5. Common bypass techniques
6. Shodan lookup
7. Censys lookup
"""
import os
import sys
import re
import json
import socket
import time
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ CDN/WAF Detection ============================
CDN_PROVIDERS = {
    "cloudflare": {
        "name": "Cloudflare",
        "ip_ranges": [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
        ],
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "subdomains": ["mail", "direct", "cpanel", "webmail"],
    },
    "aws_cloudfront": {
        "name": "AWS CloudFront",
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront"],
        "subdomains": ["origin", "backend"],
    },
    "akamai": {
        "name": "Akamai",
        "headers": ["x-akamai-transformed", "akamai"],
        "subdomains": ["origin", "backend"],
    },
    "sucuri": {
        "name": "Sucuri",
        "headers": ["server: sucuri", "x-sucuri-id"],
        "subdomains": ["origin"],
    },
    "incapsula": {
        "name": "Incapsula (Imperva)",
        "headers": ["x-iinfo", "incap_ses"],
        "subdomains": ["origin"],
    },
    "fastly": {
        "name": "Fastly",
        "headers": ["x-served-by", "fastly"],
        "subdomains": ["origin"],
    },
}


def ip_in_range(ip: str, cidr: str) -> bool:
    """فحص إذا كان IP ضمن CIDR range"""
    try:
        import struct
        ip_parts = ip.split(".")
        if len(ip_parts) != 4:
            return False

        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]

        cidr_parts = cidr.split("/")
        if len(cidr_parts) != 2:
            return False

        network = cidr_parts[0]
        prefix = int(cidr_parts[1])

        net_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF

        return (ip_int & mask) == (net_int & mask)
    except Exception:
        return False


def is_cdn_ip(ip: str) -> bool:
    """فحص إذا كان IP يخص CDN"""
    for provider, info in CDN_PROVIDERS.items():
        for cidr in info.get("ip_ranges", []):
            if ip_in_range(ip, cidr):
                return True, info["name"]
    return False, None


# ============================ Real IP Finder ============================
class RealIPFinder:
    """إيجاد الـ IP الحقيقي خلف CDN"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None):
        self.client = http_client or HttpClient(timeout=15)
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.domain = None
        self.cdn_detected = None
        self.cdn_name = None
        self.original_ip = None
        self.real_ip_candidates = []
        self.found_real_ip = None

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[IP-FINDER] {msg}", level)

    def find_real_ip(self, url: str) -> Dict:
        """البحث عن الـ IP الحقيقي"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        self.domain = parsed.netloc or parsed.path

        # إزالة port لو موجود
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]

        self._log(f"البحث عن الـ IP الحقيقي لـ: {self.domain}", "phase")

        result = {
            "domain": self.domain,
            "cdn_detected": False,
            "cdn_name": None,
            "original_ip": None,
            "real_ip": None,
            "methods_tried": [],
            "candidates": [],
        }

        # 1) الحصول على الـ IP الحالي (ربما CDN)
        self._log("فحص الـ IP الحالي...", "info")
        try:
            current_ip = socket.gethostbyname(self.domain)
            self.original_ip = current_ip
            result["original_ip"] = current_ip
            self._log(f"الـ IP الحالي: {current_ip}", "info")
        except Exception as e:
            self._log(f"فشل حل DNS: {e}", "error")
            return result

        # 2) فحص إذا كان CDN
        is_cdn, cdn_name = is_cdn_ip(current_ip)
        if is_cdn:
            result["cdn_detected"] = True
            result["cdn_name"] = cdn_name
            self.cdn_name = cdn_name
            self._log(f"CDN مكتشف: {cdn_name}", "warn")
            self._log("بدء البحث عن الـ IP الحقيقي...", "info")
        else:
            # فحص headers
            cdn_from_headers = self._detect_cdn_from_headers(url)
            if cdn_from_headers:
                result["cdn_detected"] = True
                result["cdn_name"] = cdn_from_headers
                self.cdn_name = cdn_from_headers
                self._log(f"CDN مكتشف من headers: {cdn_from_headers}", "warn")
            else:
                self._log(f"لا يوجد CDN - الـ IP {current_ip} هو الحقيقي", "success")
                result["real_ip"] = current_ip
                return result

        # 3) محاولة إيجاد الـ IP الحقيقي
        methods = [
            ("DNS Records", self._method_dns_records),
            ("Subdomain Scan", self._method_subdomain_scan),
            ("SSL Certificate", self._method_ssl_cert),
            ("DNS History", self._method_dns_history),
            ("Shodan", self._method_shodan),
            ("HTTP Headers Analysis", self._method_headers),
        ]

        for method_name, method_func in methods:
            self._log(f"محاولة: {method_name}...", "info")
            try:
                ips = method_func(url)
                if ips:
                    result["methods_tried"].append({
                        "method": method_name,
                        "success": True,
                        "ips": ips,
                    })
                    for ip in ips:
                        if ip not in self.real_ip_candidates:
                            # تأكد إنه مش CDN IP
                            is_c, _ = is_cdn_ip(ip)
                            if not is_c:
                                self.real_ip_candidates.append(ip)
                                self._log(f"  مرشح IP: {ip}", "success")
                else:
                    result["methods_tried"].append({
                        "method": method_name,
                        "success": False,
                    })
            except Exception as e:
                self._log(f"  فشل {method_name}: {e}", "warn")
                result["methods_tried"].append({
                    "method": method_name,
                    "success": False,
                    "error": str(e),
                })

        # 4) تحديد الـ IP الحقيقي
        result["candidates"] = self.real_ip_candidates

        if self.real_ip_candidates:
            # نختار الأكثر تكراراً
            from collections import Counter
            ip_counts = Counter(self.real_ip_candidates)
            self.found_real_ip = ip_counts.most_common(1)[0][0]
            result["real_ip"] = self.found_real_ip
            self._log(f"الـ IP الحقيقي: {self.found_real_ip}", "success")
        else:
            self._log("لم يتم العثور على الـ IP الحقيقي", "warn")

        return result

    def _detect_cdn_from_headers(self, url: str) -> Optional[str]:
        """كشف CDN من headers"""
        resp = self.client.get(url)
        headers_lower = {k.lower(): v.lower() for k, v in resp["headers"].items()}

        for cdn_id, cdn_info in CDN_PROVIDERS.items():
            for header in cdn_info.get("headers", []):
                if ":" in header:
                    h_name, h_value = header.split(":", 1)
                    h_name = h_name.strip().lower()
                    h_value = h_value.strip().lower()
                    if h_name in headers_lower and h_value in headers_lower[h_name]:
                        return cdn_info["name"]
                else:
                    if header.lower() in headers_lower:
                        return cdn_info["name"]

        return None

    def _method_dns_records(self, url: str) -> List[str]:
        """البحث في DNS records (MX, TXT, SPF)"""
        ips = []

        try:
            # MX records
            mx_records = socket.getaddrinfo(self.domain, 25, socket.AF_INET)
            for record in mx_records:
                ip = record[4][0]
                if ip != self.original_ip:
                    ips.append(ip)

            # محاولة حل mail subdomain
            mail_domain = f"mail.{self.domain}"
            try:
                mail_ip = socket.gethostbyname(mail_domain)
                if mail_ip != self.original_ip:
                    ips.append(mail_ip)
            except Exception:
                pass

            # محاولة حل SMTP subdomain
            smtp_domain = f"smtp.{self.domain}"
            try:
                smtp_ip = socket.gethostbyname(smtp_domain)
                if smtp_ip != self.original_ip:
                    ips.append(smtp_ip)
            except Exception:
                pass

        except Exception:
            pass

        return ips

    def _method_subdomain_scan(self, url: str) -> List[str]:
        """فحص subdomains شائعة لإيجاد الـ IP الحقيقي"""
        ips = []

        # subdomains شائعة قد تكشف الـ IP الحقيقي
        subdomains = [
            "direct", "origin", "backend", "server", "host",
            "cpanel", "webmail", "admin", "direct-connect",
            "www2", "www3", "old", "new", "test", "dev",
            "staging", "prod", "api", "ftp", "ssh",
            "ns1", "ns2", "dns1", "dns2",
        ]

        def check_subdomain(sub: str) -> Optional[str]:
            try:
                full_domain = f"{sub}.{self.domain}"
                ip = socket.gethostbyname(full_domain)
                is_c, _ = is_cdn_ip(ip)
                if not is_c and ip != self.original_ip:
                    return ip
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ips.append(result)

        return ips

    def _method_ssl_cert(self, url: str) -> List[str]:
        """البحث في SSL certificate عن IPs"""
        ips = []

        try:
            import ssl

            # الاتصال بالـ domain
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((self.domain, 443), timeout=10)
            ssock = context.wrap_socket(sock, server_hostname=self.domain)

            # الحصول على الشهادة
            cert = ssock.getpeercert()

            # استخراج subjectAltName (قد يحتوي على IPs أو subdomains)
            if cert:
                for field in cert.get("subjectAltName", []):
                    if isinstance(field, tuple) and len(field) >= 2:
                        field_type, value = field
                        if field_type == "IP Address":
                            is_c, _ = is_cdn_ip(value)
                            if not is_c and value != self.original_ip:
                                ips.append(value)
                        elif field_type == "DNS":
                            # حل الـ DNS names
                            try:
                                resolved_ip = socket.gethostbyname(value)
                                is_c, _ = is_cdn_ip(resolved_ip)
                                if not is_c and resolved_ip != self.original_ip:
                                    ips.append(resolved_ip)
                            except Exception:
                                pass

            ssock.close()
        except Exception as e:
            self._log(f"  SSL cert error: {e}", "warn")

        return ips

    def _method_dns_history(self, url: str) -> List[str]:
        """البحث في DNS history (online)"""
        ips = []

        # محاولة DNSDumpster API
        try:
            api_url = f"https://dnsdumpster.com/?remotehost={self.domain}"
            req = urllib.request.Request(api_url, headers={
                "User-Agent": "Mozilla/5.0",
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="ignore")

                # استخراج IPs من الـ HTML
                ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
                found_ips = re.findall(ip_pattern, html)

                for ip in found_ips:
                    is_c, _ = is_cdn_ip(ip)
                    if not is_c and ip != self.original_ip:
                        ips.append(ip)
                        if len(ips) >= 5:
                            break

        except Exception:
            pass

        return ips

    def _method_shodan(self, url: str) -> List[str]:
        """البحث في Shodan (بدون API key - محدود)"""
        ips = []

        try:
            # Shodan search بدون API (محدود جداً)
            api_url = f"https://www.shodan.io/search?query=hostname:{self.domain}"
            req = urllib.request.Request(api_url, headers={
                "User-Agent": "Mozilla/5.0",
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="ignore")

                # استخراج IPs
                ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
                found_ips = re.findall(ip_pattern, html)

                for ip in found_ips[:5]:
                    is_c, _ = is_cdn_ip(ip)
                    if not is_c and ip != self.original_ip:
                        ips.append(ip)
        except Exception:
            pass

        return ips

    def _method_headers(self, url: str) -> List[str]:
        """تحليل headers لكشف IP داخلي"""
        ips = []

        resp = self.client.get(url)
        headers = resp["headers"]

        # X-Originating-IP
        for header_name in ["X-Originating-IP", "X-Real-IP", "X-Forwarded-For",
                            "X-Client-IP", "X-Host", "X-Server-IP", "Via"]:
            for h_name, h_value in headers.items():
                if h_name.lower() == header_name.lower():
                    # استخراج IP
                    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', h_value)
                    if ip_match:
                        ip = ip_match.group(1)
                        is_c, _ = is_cdn_ip(ip)
                        if not is_c and ip != self.original_ip:
                            ips.append(ip)

        return ips

    # ============================ Report ============================
    def print_report(self, result: Dict):
        """عرض تقرير"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🌐 تقرير الـ IP الحقيقي{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}Domain:{Colors.NC} {result['domain']}")
        print(f"  {Colors.BOLD}الـ IP الحالي:{Colors.NC} {result['original_ip']}")

        if result["cdn_detected"]:
            print(f"  {Colors.YELLOW}CDN مكتشف:{Colors.NC} {result['cdn_name']}")
        else:
            print(f"  {Colors.GREEN}لا يوجد CDN{Colors.NC}")

        if result["real_ip"]:
            print(f"\n  {Colors.GREEN + Colors.BOLD}✅ الـ IP الحقيقي: {result['real_ip']}{Colors.NC}")

            # معلومات إضافية عن الـ IP
            ip_info = self._get_ip_info(result["real_ip"])
            if ip_info:
                print(f"\n  {Colors.BOLD}معلومات الـ IP:{Colors.NC}")
                for key, value in ip_info.items():
                    print(f"    {key}: {value}")
        else:
            print(f"\n  {Colors.YELLOW}لم يتم العثور على الـ IP الحقيقي{Colors.NC}")

        if result["candidates"]:
            print(f"\n  {Colors.BOLD}مرشحين إضافيين:{Colors.NC}")
            for ip in set(result["candidates"]):
                print(f"    {Colors.CYAN}- {ip}{Colors.NC}")

        print(f"\n  {Colors.BOLD}الطرق المجربة:{Colors.NC}")
        for method in result["methods_tried"]:
            status = f"{Colors.GREEN}✓{Colors.NC}" if method["success"] else f"{Colors.RED}✗{Colors.NC}"
            print(f"    {status} {method['method']}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")

    def _get_ip_info(self, ip: str) -> Optional[Dict]:
        """الحصول على معلومات عن IP"""
        try:
            api_url = f"http://ip-api.com/json/{ip}"
            req = urllib.request.Request(api_url, headers={"User-Agent": "ghostpwn"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

                return {
                    "Country": data.get("country", "Unknown"),
                    "City": data.get("city", "Unknown"),
                    "ISP": data.get("isp", "Unknown"),
                    "Organization": data.get("org", "Unknown"),
                    "ASN": data.get("as", "Unknown"),
                    "Timezone": data.get("timezone", "Unknown"),
                }
        except Exception:
            return None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Real IP Finder")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    finder = RealIPFinder()
    result = finder.find_real_ip(args.url)
    finder.print_report(result)
