#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - JavaScript Analyzer
يحلل ملفات JavaScript لاستخراج:
1. Endpoints / API Routes
2. Secrets المكشوفة (API keys, tokens, passwords)
3. DOM sinks (لـ DOM XSS)
4. Internal URLs
5. Cloud storage URLs
6. JWT tokens
7. WebSocket URLs
"""
import os
import sys
import re
import json
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Patterns ============================
SECRET_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?<![A-Z0-9])[A-Za-z0-9/+=]{40}(?![A-Z0-9])',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token": r'gh[pousr]_[A-Za-z0-9]{36}',
    "Slack Token": r'xox[baprs]-[A-Za-z0-9-]+',
    "Slack Webhook": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    "Stripe Key": r'(?:pk|sk)_(?:live|test)_[0-9a-zA-Z]{24}',
    "Twilio API Key": r'SK[0-9a-fA-F]{32}',
    "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
    "SendGrid API Key": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    "JWT Token": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*',
    "Private Key": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    "Generic API Key": r'(?:api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32,})',
    "Generic Secret": r'(?:secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})',
    "Firebase URL": r'https?://[a-z0-9-]+\.firebaseio\.com',
    "Firebase Config": r'apiKey:\s*["\']([A-Za-z0-9_-]{39})["\']',
    "Stripe Webhook": r'whsec_[a-zA-Z0-9]{24,}',
    "Facebook Access Token": r'EAACEdEose0cBA[0-9A-Za-z]+',
    "Twitter Access Token": r'[1-9][0-9]+-[0-9a-zA-Z]{40}',
    "Generic Bearer Token": r'Bearer\s+[A-Za-z0-9\-._~+\/]+=*',
    "Basic Auth": r'Basic\s+[A-Za-z0-9+/=]{16,}',
    "Connection String": r'(?:mongodb|postgres|mysql|redis)://[^\s"\']+',
    "Google OAuth ID": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
}

ENDPOINT_PATTERNS = [
    r'''["'](?:GET|POST|PUT|DELETE|PATCH)\s+([^"']+)["']''',  # HTTP methods in strings
    r'''(?:fetch|axios|ajax|open)\s*\(\s*["']([^"']+)["']''',  # fetch/axios calls
    r'''(?:url|endpoint|uri|path|route)\s*[:=]\s*["']([^"']+)["']''',  # URL variables
    r'''(?:action|href|src)\s*=\s*["']([^"']+)["']''',  # HTML attributes in JS
    r'''["'](/api/[v0-9]*/[^"']+)["']''',  # API routes
    r'''["'](/graphql|/query|/mutate)["']''',  # GraphQL endpoints
    r'''["'](ws|wss)://([^"']+)["']''',  # WebSocket URLs
    r'''["'](https?://[^"']+)["']''',  # Full URLs
    r'''\.get\s*\(\s*["']([^"']+)["']''',  # jQuery $.get
    r'''\.post\s*\(\s*["']([^"']+)["']''',  # jQuery $.post
    r'''XMLHttpRequest.*?open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']''',
]

DOM_SINK_PATTERNS = [
    r'document\.write\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(\s*["\']',
    r'setInterval\s*\(\s*["\']',
    r'new\s+Function\s*\(',
    r'\$\s*\(\s*["\'].*?\$\{.*?\}.*?["\']\s*\)',  # jQuery with template literals
    r'document\.location\s*=',
    r'window\.location\s*=',
    r'\.src\s*=\s*[^;]*\$\{',
    r'\.href\s*=\s*[^;]*\$\{',
]

CLOUD_URL_PATTERNS = {
    "S3 Bucket": r'["\'](https?://[a-z0-9-]+\.s3[a-z0-9-]*\.amazonaws\.com[^"\']*)["\']',
    "Google Cloud Storage": r'["\'](https?://storage\.googleapis\.com/[^"\']+)["\']',
    "Azure Blob": r'["\'](https?://[a-z0-9]+\.blob\.core\.windows\.net/[^"\']+)["\']',
    "DigitalOcean Spaces": r'["\'](https?://[a-z0-9-]+\.spaces\.digitalocean\.com[^"\']*)["\']',
}


class JSAnalyzer:
    """محلل JavaScript"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None):
        self.client = http_client or HttpClient(timeout=15)
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.results = {
            "endpoints": [],
            "api_routes": [],
            "secrets": [],
            "dom_sinks": [],
            "cloud_urls": [],
            "js_files": [],
        }

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[JS] {msg}", level)

    def analyze_url(self, url: str) -> Dict:
        """تحليل JavaScript من URL"""
        self._log(f"تحليل JavaScript لـ: {url}", "phase")

        # 1) جلب الصفحة الرئيسية
        resp = self.client.get(url)
        if resp["status"] == 0:
            return self.results

        html = resp["body"]

        # 2) استخراج روابط ملفات JS
        js_files = self._extract_js_urls(url, html)
        self._log(f"تم العثور على {len(js_files)} ملف JS", "info")

        # 3) تحليل الـ inline JavaScript
        inline_scripts = self._extract_inline_js(html)
        for script in inline_scripts:
            self._analyze_js_code(script, url, "inline")

        # 4) تحليل ملفات JS الخارجية
        for js_url in js_files[:15]:  # أول 15 ملف
            self._log(f"تحليل: {js_url[:60]}...", "info")
            js_resp = self.client.get(js_url)
            if js_resp["status"] == 200 and len(js_resp["body"]) > 50:
                self._analyze_js_code(js_resp["body"], js_url, "external")
                self.results["js_files"].append({
                    "url": js_url,
                    "size": len(js_resp["body"]),
                })

        # 5) عرض النتائج
        self._print_results()

        return self.results

    def _extract_js_urls(self, base_url: str, html: str) -> List[str]:
        """استخراج روابط ملفات JS"""
        js_urls = set()

        # <script src="...">
        pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            if not match.startswith("data:"):
                full_url = urljoin(base_url, match)
                js_urls.add(full_url)

        # import statements
        pattern = r'import\s+.*?\s+from\s+["\']([^"\']+)["\']'
        matches = re.findall(pattern, html)
        for match in matches:
            if match.startswith(".") or match.startswith("/"):
                full_url = urljoin(base_url, match)
                if not full_url.endswith(".js"):
                    full_url += ".js"
                js_urls.add(full_url)

        return list(js_urls)

    def _extract_inline_js(self, html: str) -> List[str]:
        """استخراج inline JavaScript"""
        scripts = []
        pattern = r'<script(?:\s[^>]*)?>(.*?)</script>'
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        for match in matches:
            if match.strip() and len(match.strip()) > 50:
                scripts.append(match.strip())
        return scripts

    def _analyze_js_code(self, code: str, source_url: str, source_type: str):
        """تحليل كود JavaScript"""
        # 1) استخراج secrets
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, code)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) > 5:
                    secret = {
                        "type": name,
                        "value": match[:50] + "..." if len(match) > 50 else match,
                        "source": source_url,
                        "source_type": source_type,
                    }
                    self.results["secrets"].append(secret)
                    self._log(f"  🔑 Secret: {name} - {match[:30]}...", "warn")

        # 2) استخراج endpoints
        for pattern in ENDPOINT_PATTERNS:
            matches = re.findall(pattern, code)
            for match in matches:
                if match and not match.startswith("javascript:") and not match.startswith("#"):
                    endpoint = {
                        "url": match,
                        "source": source_url,
                        "source_type": source_type,
                    }
                    if match not in [e["url"] for e in self.results["endpoints"]]:
                        self.results["endpoints"].append(endpoint)

                        # فحص لو API route
                        if "/api/" in match or "/graphql" in match or "/query" in match:
                            if match not in [e["url"] for e in self.results["api_routes"]]:
                                self.results["api_routes"].append(endpoint)
                                self._log(f"  🔌 API: {match[:60]}", "info")

        # 3) استخراج DOM sinks
        for pattern in DOM_SINK_PATTERNS:
            if re.search(pattern, code):
                # استخراج السطر
                lines = code.split("\n")
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        sink = {
                            "pattern": pattern[:30],
                            "code": line.strip()[:100],
                            "line": i + 1,
                            "source": source_url,
                        }
                        self.results["dom_sinks"].append(sink)
                        self._log(f"  ⚠️  DOM Sink: {line.strip()[:60]}...", "warn")
                        break

        # 4) استخراج cloud URLs
        for name, pattern in CLOUD_URL_PATTERNS.items():
            matches = re.findall(pattern, code)
            for match in matches:
                cloud_url = {
                    "type": name,
                    "url": match,
                    "source": source_url,
                }
                self.results["cloud_urls"].append(cloud_url)
                self._log(f"  ☁️  Cloud: {name} - {match[:50]}...", "info")

    def _print_results(self):
        """عرض النتائج"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  📜 تقرير تحليل JavaScript{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        r = self.results

        print(f"\n  {Colors.BOLD}📊 Summary:{Colors.NC}")
        print(f"    JS files analyzed: {len(r['js_files'])}")
        print(f"    Endpoints found: {len(r['endpoints'])}")
        print(f"    API routes: {len(r['api_routes'])}")
        print(f"    Secrets found: {len(r['secrets'])}")
        print(f"    DOM sinks: {len(r['dom_sinks'])}")
        print(f"    Cloud URLs: {len(r['cloud_urls'])}")

        if r["secrets"]:
            print(f"\n  {Colors.RED + Colors.BOLD}🔑 Secrets:{Colors.NC}")
            for s in r["secrets"]:
                print(f"    {Colors.RED}[{s['type']}]{Colors.NC} {s['value']}")

        if r["endpoints"]:
            print(f"\n  {Colors.CYAN}🔌 Endpoints:{Colors.NC}")
            for e in r["endpoints"][:20]:
                print(f"    - {e['url'][:80]}")

        if r["dom_sinks"]:
            print(f"\n  {Colors.YELLOW}⚠️  DOM Sinks:{Colors.NC}")
            for s in r["dom_sinks"]:
                print(f"    Line {s['line']}: {s['code'][:80]}")

        if r["cloud_urls"]:
            print(f"\n  {Colors.BLUE}☁️  Cloud URLs:{Colors.NC}")
            for c in r["cloud_urls"]:
                print(f"    [{c['type']}] {c['url'][:80]}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - JS Analyzer")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    analyzer = JSAnalyzer()
    analyzer.analyze_url(args.url)
