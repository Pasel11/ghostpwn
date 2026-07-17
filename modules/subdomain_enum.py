#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Subdomain Enumeration
استخراج Subdomains من مصادر متعددة

المصادر:
1. crt.sh (Certificate Transparency)
2. HackerTarget API
3. ThreatCrowd API
4. DNS Brute Force (fallback)
5. Search engines (Bing)
6. Wayback Machine
7. Subfinder-like approach
"""
import os
import sys
import re
import json
import socket
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


class SubdomainEnumerator:
    """استخراج subdomains من مصادر متعددة"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None):
        self.client = http_client or HttpClient(timeout=15)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.subdomains: Set[str] = set()
        self.sources_used = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[SUBDOMAIN] {msg}", level)

    def enumerate(self, domain: str, use_brute_force: bool = True) -> List[Dict]:
        """استخراج subdomains من كل المصادر"""
        self._log(f"استخراج subdomains لـ: {domain}", "phase")

        # إزالة protocol و path
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        methods = [
            ("crt.sh", self._from_crtsh),
            ("HackerTarget", self._from_hackertarget),
            ("ThreatCrowd", self._from_threatcrowd),
            ("Wayback Machine", self._from_wayback),
            ("DNS Brute Force", lambda d: self._from_brute_force(d) if use_brute_force else []),
        ]

        for name, method in methods:
            try:
                self._log(f"  [{name}] جاري الفحص...", "info")
                subs = method(domain)
                if subs:
                    self.subdomains.update(subs)
                    self._log(f"  [{name}] تم العثور على {len(subs)} subdomain", "success")
                    self.sources_used.append({"source": name, "count": len(subs)})
                else:
                    self._log(f"  [{name}] لا توجد نتائج", "warn")
            except Exception as e:
                self._log(f"  [{name}] خطأ: {e}", "error")

        # حل DNS للتأكد
        resolved = self._resolve_subdomains()

        # عرض النتائج
        self._print_results(domain, resolved)

        return resolved

    def _from_crtsh(self, domain: str) -> List[str]:
        """استخراج من crt.sh (Certificate Transparency)"""
        subs = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and name.endswith(domain) and name != domain:
                        subs.append(name)
        except Exception as e:
            self._log(f"    crt.sh error: {e}", "warn")
        return list(set(subs))

    def _from_hackertarget(self, domain: str) -> List[str]:
        """استخراج من HackerTarget API"""
        subs = []
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode()

            for line in text.split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if sub.endswith(domain):
                        subs.append(sub)
        except Exception:
            pass
        return list(set(subs))

    def _from_threatcrowd(self, domain: str) -> List[str]:
        """استخراج من ThreatCrowd API"""
        subs = []
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            for entry in data.get("subdomains", []):
                subs.append(entry)
        except Exception:
            pass
        return list(set(subs))

    def _from_wayback(self, domain: str) -> List[str]:
        """استخراج من Wayback Machine"""
        subs = []
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())

            if len(data) > 1:
                for entry in data[1:]:  # تخطي header
                    if entry:
                        url_str = entry[0]
                        parsed = urllib.parse.urlparse(url_str)
                        sub = parsed.netloc.split(":")[0]
                        if sub.endswith(domain) and sub != domain:
                            subs.append(sub)
        except Exception:
            pass
        return list(set(subs))

    def _from_brute_force(self, domain: str) -> List[str]:
        """DNS brute force (fallback)"""
        wordlist = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
            "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin",
            "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
            "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop",
            "sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media",
            "email", "images", "imap2", "test1", "test2", "test3", "sphinx",
            "api", "v1", "v2", "staging", "server", "service", "gateway",
            "auth", "sso", "oauth", "admin1", "admin2", "portal", "app",
            "apps", "internal", "intranet", "extranet", "remote", "cloud",
        ]
        subs = []

        def resolve(sub_name):
            try:
                full = f"{sub_name}.{domain}"
                socket.gethostbyname(full)
                return full
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(resolve, w): w for w in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subs.append(result)

        return subs

    def _resolve_subdomains(self) -> List[Dict]:
        """حل DNS للتأكد من الـ subdomains"""
        self._log(f"حل DNS لـ {len(self.subdomains)} subdomain...", "info")
        resolved = []

        def resolve_one(sub):
            try:
                ips = socket.gethostbyname_ex(sub)
                return {"subdomain": sub, "ips": ips[2]}
            except socket.gaierror:
                return None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(resolve_one, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    resolved.append(result)

        resolved.sort(key=lambda x: x["subdomain"])
        return resolved

    def _print_results(self, domain: str, resolved: List[Dict]):
        """عرض النتائج"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🌐 Subdomain Enumeration Results{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}Domain:{Colors.NC} {domain}")
        print(f"  {Colors.BOLD}Total found:{Colors.NC} {len(self.subdomains)}")
        print(f"  {Colors.BOLD}Resolved:{Colors.NC} {len(resolved)}")

        print(f"\n  {Colors.BOLD}Sources used:{Colors.NC}")
        for src in self.sources_used:
            print(f"    {Colors.GREEN}✓{Colors.NC} {src['source']}: {src['count']} subdomains")

        if resolved:
            print(f"\n  {Colors.BOLD}Resolved Subdomains:{Colors.NC}")
            for r in resolved[:30]:
                ips = ", ".join(r["ips"])
                print(f"    {Colors.CYAN}{r['subdomain']:<40}{Colors.NC} → {ips}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Subdomain Enumerator")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--no-brute", action="store_true", help="Skip DNS brute force")
    args = parser.parse_args()

    enum = SubdomainEnumerator()
    enum.enumerate(args.domain, use_brute_force=not args.no_brute)
