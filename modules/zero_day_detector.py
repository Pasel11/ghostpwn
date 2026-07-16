#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Zero-Day Detector
كشف ثغرات غير معروفة عبر تحليل السلوك

الذكاء:
1. يحلل الـ responses لاكتشاف patterns غير طبيعية
2. يكتشف ثغرات logic
3. يكتشف information disclosure
4. يكتشف configuration issues
5. يكتشف ثغرات غير موجودة في الـ signatures
"""
import sys
import os
import re
import json
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Information Disclosure Patterns ============================
INFO_DISCLOSURE_PATTERNS = {
    "email": {
        "pattern": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "severity": "low",
        "description": "Email address disclosed",
    },
    "phone": {
        "pattern": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        "severity": "low",
        "description": "Phone number disclosed",
    },
    "credit_card": {
        "pattern": r'\b(?:\d[ -]*?){13,16}\b',
        "severity": "high",
        "description": "Possible credit card number",
    },
    "ssn": {
        "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
        "severity": "critical",
        "description": "SSN disclosed",
    },
    "api_key": {
        "pattern": r'(?:api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{32,})',
        "severity": "critical",
        "description": "API key disclosed",
    },
    "aws_key": {
        "pattern": r'AKIA[0-9A-Z]{16}',
        "severity": "critical",
        "description": "AWS Access Key ID",
    },
    "github_token": {
        "pattern": r'gh[pousr]_[A-Za-z0-9]{36}',
        "severity": "critical",
        "description": "GitHub token disclosed",
    },
    "slack_token": {
        "pattern": r'xox[baprs]-[A-Za-z0-9-]+',
        "severity": "critical",
        "description": "Slack token disclosed",
    },
    "private_key": {
        "pattern": r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        "severity": "critical",
        "description": "Private key disclosed",
    },
    "jwt_token": {
        "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*',
        "severity": "medium",
        "description": "JWT token disclosed",
    },
    "password_in_html": {
        "pattern": r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})',
        "severity": "high",
        "description": "Password in HTML/JS",
    },
    "internal_ip": {
        "pattern": r'\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        "severity": "medium",
        "description": "Internal IP disclosed",
    },
    "version_disclosure": {
        "pattern": r'(?:version|ver|v)["\']?\s*[:=]\s*["\']?(\d+\.\d+\.\d+)',
        "severity": "low",
        "description": "Version information disclosed",
    },
    "stack_trace": {
        "pattern": r'(Traceback|at\s+\w+\.\w+\([^)]+\)|#\d+\s+\w+\([^)]+\))',
        "severity": "medium",
        "description": "Stack trace disclosed",
    },
    "comment_leak": {
        "pattern": r'<!--[^-]+-->',
        "severity": "low",
        "description": "HTML comments (may contain sensitive info)",
    },
    "debug_info": {
        "pattern": r'(DEBUG|debug_info|debug_mode|debug:true)',
        "severity": "medium",
        "description": "Debug information disclosed",
    },
}


# ============================ Logic Flaw Detectors ============================
class LogicFlawDetector:
    """كشف ثغرات الـ logic"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[LOGIC] {msg}", level)

    def detect_rate_limiting(self, url: str) -> Optional[Dict]:
        """فحص rate limiting"""
        self._log("فحص rate limiting...", "info")

        # إرسال 10 طلبات سريعة
        statuses = []
        for i in range(10):
            resp = self.client.get(url)
            statuses.append(resp["status"])

        # لو كلها 200 = مفيش rate limiting
        if all(s == 200 for s in statuses):
            self._log("لا يوجد rate limiting!", "warn")
            return {
                "type": "no_rate_limiting",
                "severity": "medium",
                "evidence": f"10 requests all returned 200",
            }
        # لو فيه 429 = فيه rate limiting
        elif 429 in statuses:
            self._log("Rate limiting detected (429)", "success")
            return None

        return None

    def detect_auth_bypass(self, url: str) -> List[Dict]:
        """فحص auth bypass"""
        self._log("فحص auth bypass...", "info")

        vulns = []

        # محاولة الوصول بدون auth
        resp = self.client.get(url)

        # فحص لو الموقع بيرجع authenticated content بدون cookies
        if resp["status"] == 200:
            body_lower = resp["body"].lower()
            auth_indicators = ["welcome", "dashboard", "logout", "my account", "profile"]

            for indicator in auth_indicators:
                if indicator in body_lower:
                    # ممكن auth bypass
                    self._log(f"Possible auth bypass - found '{indicator}' without auth", "warn")
                    vulns.append({
                        "type": "possible_auth_bypass",
                        "severity": "high",
                        "evidence": f"Found '{indicator}' without authentication",
                    })
                    break

        # محاولة مع JWT none algorithm
        none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        resp_with_token = self.client.get(url, headers={"Authorization": f"Bearer {none_token}"})

        if resp_with_token["status"] == 200 and resp_with_token["body"] != resp["body"]:
            self._log("JWT none algorithm bypass!", "warn")
            vulns.append({
                "type": "jwt_none_bypass",
                "severity": "critical",
                "evidence": "JWT with none algorithm accepted",
            })

        return vulns

    def detect_insecure_cookies(self, url: str) -> List[Dict]:
        """فحص cookies الآمنة"""
        self._log("فحص cookies الآمنة...", "info")

        vulns = []
        resp = self.client.get(url)

        set_cookie = resp["headers"].get("Set-Cookie", "")
        if not set_cookie:
            return vulns

        # فحص كل cookie
        cookies = set_cookie.split(",")
        for cookie in cookies:
            cookie_lower = cookie.lower()

            issues = []
            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite flag")

            if issues:
                cookie_name = cookie.split("=")[0].strip()
                vulns.append({
                    "type": "insecure_cookie",
                    "severity": "low",
                    "cookie": cookie_name,
                    "evidence": "; ".join(issues),
                })

        return vulns

    def detect_method_tampering(self, url: str) -> List[Dict]:
        """فحص method tampering"""
        self._log("فحص HTTP method tampering...", "info")

        vulns = []

        # تجربة methods مختلفة
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"]

        for method in methods:
            try:
                resp = self.client.request(url, method=method)

                # TRACE يجب أن يكون معطلاً
                if method == "TRACE" and resp["status"] == 200 and "TRACE" in resp["body"]:
                    self._log("TRACE method enabled!", "warn")
                    vulns.append({
                        "type": "trace_enabled",
                        "severity": "medium",
                        "evidence": "TRACE method returns echo",
                    })

                # PUT/DELETE لو مسموحين بدون auth
                if method in ["PUT", "DELETE"] and resp["status"] in [200, 201, 204]:
                    self._log(f"{method} method allowed without auth!", "warn")
                    vulns.append({
                        "type": "dangerous_method_allowed",
                        "severity": "medium",
                        "method": method,
                        "evidence": f"{method} returned {resp['status']}",
                    })

            except Exception:
                pass

        return vulns


# ============================ Zero-Day Detector ============================
class ZeroDayDetector:
    """كشف الثغرات غير المعروفة"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.logic_detector = LogicFlawDetector(http_client, audit_logger)

        self.findings = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[ZERO-DAY] {msg}", level)

    def scan(self, url: str) -> Dict:
        """فحص شامل للثغرات غير المعروفة"""
        self._log("بدء فحص الثغرات غير المعروفة...", "phase")

        result = {
            "info_disclosure": [],
            "logic_flaws": [],
            "config_issues": [],
            "behavioral_anomalies": [],
        }

        # 1) Information disclosure
        self._log("فحص information disclosure...", "info")
        result["info_disclosure"] = self._scan_info_disclosure(url)

        # 2) Logic flaws
        self._log("فحص logic flaws...", "info")
        result["logic_flaws"] = self.logic_detector.detect_auth_bypass(url)
        result["logic_flaws"].extend(self.logic_detector.detect_insecure_cookies(url))
        result["logic_flaws"].extend(self.logic_detector.detect_method_tampering(url))

        rate_limit = self.logic_detector.detect_rate_limiting(url)
        if rate_limit:
            result["logic_flaws"].append(rate_limit)

        # 3) Configuration issues
        self._log("فحص configuration issues...", "info")
        result["config_issues"] = self._scan_config_issues(url)

        # 4) Behavioral anomalies
        self._log("فحص behavioral anomalies...", "info")
        result["behavioral_anomalies"] = self._scan_behavioral_anomalies(url)

        # تجميع النتائج
        for category, findings in result.items():
            for finding in findings:
                finding["category"] = category
                self.findings.append(finding)

        return result

    def _scan_info_disclosure(self, url: str) -> List[Dict]:
        """فحص information disclosure"""
        findings = []

        resp = self.client.get(url)
        body = resp["body"]

        # فحص كل pattern
        for name, config in INFO_DISCLOSURE_PATTERNS.items():
            matches = re.findall(config["pattern"], body)

            if matches:
                # لو الـ match عبارة عن tuple (من groups)، ناخد الأول
                if isinstance(matches[0], tuple):
                    matches = [m[0] if m else "" for m in matches]

                # إزالة المكررات
                unique_matches = list(set(matches))[:5]  # أول 5

                findings.append({
                    "type": f"info_disclosure_{name}",
                    "severity": config["severity"],
                    "description": config["description"],
                    "matches": unique_matches,
                    "count": len(matches),
                })

                self._log(f"Found {name}: {len(matches)} occurrences", "warn")

        return findings

    def _scan_config_issues(self, url: str) -> List[Dict]:
        """فحص configuration issues"""
        findings = []

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # فحص ملفات حساسة
        sensitive_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.dev",
            "/.git/config", "/.git/HEAD",
            "/config.php", "/config.json", "/config.yml", "/config.yaml",
            "/wp-config.php", "/configuration.php",
            "/backup.sql", "/db.sql", "/database.sql",
            "/.htaccess", "/.htpasswd",
            "/web.config",
            "/package.json", "/composer.json", "/Gemfile",
            "/Dockerfile", "/docker-compose.yml",
            "/robots.txt", "/sitemap.xml",
            "/server-status", "/server-info",
            "/.svn/entries", "/.svn/wc.db",
            "/.DS_Store", "/Thumbs.db",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/actuator", "/actuator/health", "/actuator/env",
            "/api-docs", "/swagger.json", "/swagger-ui",
            "/graphql", "/graphiql",
            "/console", "/admin",
            "/phpinfo.php", "/info.php", "/test.php",
            "/.well-known/security.txt",
        ]

        for path in sensitive_paths:
            test_url = base_url + path
            resp = self.client.get(test_url)

            if resp["status"] == 200:
                # فحص لو المحتوى فعلاً مفيد
                if len(resp["body"]) > 50:
                    # فحص لو مش صفحة 404 مخصصة
                    if "404" not in resp["body"][:200] and "not found" not in resp["body"][:200].lower():
                        findings.append({
                            "type": "sensitive_file_exposed",
                            "severity": "high",
                            "path": path,
                            "url": test_url,
                            "size": len(resp["body"]),
                        })
                        self._log(f"Sensitive file: {path} ({len(resp['body'])} bytes)", "warn")

            elif resp["status"] in (301, 302):
                findings.append({
                    "type": "sensitive_path_redirect",
                    "severity": "medium",
                    "path": path,
                    "redirect_to": resp["headers"].get("Location", ""),
                })

        return findings

    def _scan_behavioral_anomalies(self, url: str) -> List[Dict]:
        """فحص behavioral anomalies"""
        findings = []

        # 1) فحص behavior مع user-agents مختلفة
        self._log("فحص behavior مع user-agents...", "info")

        ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148",
            "curl/7.68.0",
            "Googlebot/2.1",
            "sqlmap/1.5",
            "nikto/2.1",
        ]

        responses = []
        for ua in ua_list:
            resp = self.client.get(url, headers={"User-Agent": ua})
            responses.append({
                "ua": ua,
                "status": resp["status"],
                "length": len(resp["body"]),
            })

        # لو فيه اختلافات كبيرة = behavioral anomaly
        lengths = [r["length"] for r in responses]
        if max(lengths) - min(lengths) > 1000:
            findings.append({
                "type": "behavioral_anomaly_ua",
                "severity": "low",
                "description": "Different content for different User-Agents",
                "details": responses,
            })
            self._log("Behavioral anomaly: different content for different UAs", "warn")

        # 2) فحص behavior مع timestamps
        self._log("فحص behavior مع timestamps...", "info")
        resp1 = self.client.get(url)
        time.sleep(1)
        resp2 = self.client.get(url)

        if resp1["body"] != resp2["body"]:
            findings.append({
                "type": "dynamic_content",
                "severity": "info",
                "description": "Content changes between requests",
            })

        # 3) فحص HTTPS enforcement
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://")
            http_resp = self.client.get(http_url)
            if http_resp["status"] == 200:
                findings.append({
                    "type": "no_https_redirect",
                    "severity": "medium",
                    "description": "HTTP version accessible (no redirect to HTTPS)",
                })
                self._log("HTTP accessible without HTTPS redirect", "warn")

        return findings

    def print_findings(self, findings: Dict):
        """عرض النتائج"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔮 Zero-Day Detection Report{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        for category, items in findings.items():
            if not items:
                continue

            category_names = {
                "info_disclosure": "📊 Information Disclosure",
                "logic_flaws": "🧩 Logic Flaws",
                "config_issues": "⚙️  Configuration Issues",
                "behavioral_anomalies": "🎭 Behavioral Anomalies",
            }

            print(f"\n  {Colors.BOLD}{category_names.get(category, category)}:{Colors.NC}")

            for finding in items:
                sev_color = {
                    "critical": Colors.RED + Colors.BOLD,
                    "high": Colors.RED,
                    "medium": Colors.YELLOW,
                    "low": Colors.BLUE,
                    "info": Colors.GRAY,
                }.get(finding.get("severity", "info"), Colors.NC)

                print(f"\n    {sev_color}[{finding.get('severity', 'info').upper()}]{Colors.NC} {finding.get('type', 'unknown')}")

                if finding.get("description"):
                    print(f"      {fix_display(finding['description'])}")

                if finding.get("evidence"):
                    print(f"      {Colors.CYAN}Evidence:{Colors.NC} {finding['evidence']}")

                if finding.get("matches"):
                    for m in finding["matches"][:3]:
                        print(f"      {Colors.YELLOW}- {str(m)[:100]}{Colors.NC}")

                if finding.get("path"):
                    print(f"      {Colors.CYAN}Path:{Colors.NC} {finding['path']}")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Zero-Day Detector")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    client = HttpClient(timeout=15)
    detector = ZeroDayDetector(client)
    findings = detector.scan(args.url)
    detector.print_findings(findings)
