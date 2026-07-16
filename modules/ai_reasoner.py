#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - AI Reasoner
محرك استدلال ذكي - يحلل الموقع ويستنتج الثغرات المحتملة

الذكاء:
1. يحلل سلوك الموقع من responses بسيطة
2. يستنتج التقنيات المستخدمة
3. يتنبأ بالثغرات المحتملة
4. يبني hypothesis ويتحقق منها
5. يتعلم من النجاح والفشل
"""
import sys
import os
import re
import time
import json
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Knowledge Base ============================
TECH_INDICATORS = {
    # Frameworks
    "laravel": {
        "cookies": ["laravel_session", "xsrf_token"],
        "headers": ["X-Powered-By: Laravel"],
        "body": ["csrf-token", "laravel"],
        "common_vulns": ["sql_injection", "xss_reflected", "ssti_blade", "deserialization"],
        "common_paths": ["/.env", "/storage/logs/laravel.log", "/vendor/"],
    },
    "django": {
        "cookies": ["csrftoken", "sessionid"],
        "headers": ["X-Frame-Options: DENY"],
        "body": ["csrfmiddlewaretoken"],
        "common_vulns": ["sql_injection", "ssti_django", "debug_info_leak"],
        "common_paths": ["/admin/", "/static/", "/media/"],
    },
    "flask": {
        "headers": ["X-Powered-By: Werkzeug", "Server: Werkzeug"],
        "cookies": ["session"],
        "common_vulns": ["ssti_jinja2", "debug_console", "secret_key_leak"],
        "common_paths": ["/console", "/static/"],
    },
    "express": {
        "headers": ["X-Powered-By: Express"],
        "common_vulns": ["ssti_pug", "ssrf", "prototype_pollution"],
        "common_paths": ["/api/", "/static/"],
    },
    "rails": {
        "cookies": ["_session_id", "_rails_session"],
        "headers": ["X-Runtime", "X-Rack-Cors"],
        "common_vulns": ["ssti_erb", "deserialization", "sql_injection"],
        "common_paths": ["/rails/info", "/assets/"],
    },
    "aspnet": {
        "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
        "headers": ["X-AspNet-Version", "X-Powered-By: ASP.NET"],
        "body": ["__VIEWSTATE", "__EVENTVALIDATION"],
        "common_vulns": ["sql_injection", "xss_reflected", "viewstate_deserialization"],
        "common_paths": ["/Trace.axd", "/elmah.axd", "/aspnet_client/"],
    },
    "spring": {
        "headers": ["X-Application-Context"],
        "common_vulns": ["ssti_thymeleaf", "actuator_exposure", "spel_injection"],
        "common_paths": ["/actuator", "/actuator/health", "/actuator/env"],
    },
    "wordpress": {
        "body": ["wp-content", "wp-includes", "wp-json"],
        "common_vulns": ["sql_injection", "xss_reflected", "wp_xmlrpc", "wp_rest_api"],
        "common_paths": ["/wp-admin", "/wp-login.php", "/xmlrpc.php", "/wp-json/"],
    },
    "drupal": {
        "body": ["drupal.js", "Drupal.settings", "sites/default"],
        "common_vulns": ["sql_injection", "drupalgeddon", "xss_reflected"],
        "common_paths": ["/user/login", "/admin/", "/?q=user/login"],
    },
    "joomla": {
        "body": ["/components/com_", "Joomla"],
        "common_vulns": ["sql_injection", "xss_reflected"],
        "common_paths": ["/administrator/", "/components/"],
    },
}

# ============================ Vuln Hypotheses ============================
VULN_HYPOTHESES = {
    "sql_injection": {
        "indicators": [
            ("has_database_error", 0.8),
            ("param_reflects_exact", 0.6),
            ("param_reflects_with_quote", 0.7),
            ("response_length_varies", 0.5),
            ("numeric_param", 0.4),
            ("has_orm_detected", 0.3),
        ],
        "verify_payloads": ["'", "' OR '1'='1", "1 UNION SELECT NULL", "'; WAITFOR DELAY '0:0:3'--"],
        "confidence_threshold": 0.5,
    },
    "xss_reflected": {
        "indicators": [
            ("param_reflects_exact", 0.9),
            ("param_reflects_in_html", 0.8),
            ("no_output_encoding", 0.7),
            ("has_search_param", 0.5),
            ("has_query_param", 0.4),
        ],
        "verify_payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"],
        "confidence_threshold": 0.4,
    },
    "lfi": {
        "indicators": [
            ("param_name_file", 0.7),
            ("param_name_path", 0.7),
            ("param_name_page", 0.5),
            ("param_name_template", 0.6),
            ("param_name_include", 0.8),
            ("php_detected", 0.5),
        ],
        "verify_payloads": ["../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
        "confidence_threshold": 0.4,
    },
    "command_injection": {
        "indicators": [
            ("param_name_cmd", 0.9),
            ("param_name_exec", 0.8),
            ("param_name_command", 0.9),
            ("param_name_run", 0.7),
            ("param_name_ping", 0.8),
            ("param_name_test", 0.5),
            ("has_system_call", 0.7),
        ],
        "verify_payloads": [";id", "|id", "`id`", "$(id)"],
        "confidence_threshold": 0.5,
    },
    "ssti": {
        "indicators": [
            ("template_engine_detected", 0.8),
            ("param_name_template", 0.7),
            ("param_name_name", 0.3),
            ("framework_flask", 0.5),
            ("framework_spring", 0.4),
        ],
        "verify_payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        "confidence_threshold": 0.4,
    },
    "ssrf": {
        "indicators": [
            ("param_name_url", 0.8),
            ("param_name_image", 0.6),
            ("param_name_fetch", 0.7),
            ("param_name_callback", 0.6),
            ("param_name_webhook", 0.7),
            ("param_name_source", 0.5),
        ],
        "verify_payloads": ["http://169.254.169.254/latest/meta-data/", "http://localhost", "file:///etc/passwd"],
        "confidence_threshold": 0.4,
    },
    "open_redirect": {
        "indicators": [
            ("param_name_redirect", 0.9),
            ("param_name_url", 0.6),
            ("param_name_next", 0.7),
            ("param_name_return", 0.7),
            ("param_name_goto", 0.8),
        ],
        "verify_payloads": ["//evil.com", "https://evil.com", "javascript:alert(1)"],
        "confidence_threshold": 0.4,
    },
    "xxe": {
        "indicators": [
            ("accepts_xml", 0.7),
            ("soap_endpoint", 0.6),
            ("api_endpoint", 0.4),
        ],
        "verify_payloads": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
        "confidence_threshold": 0.3,
    },
    "deserialization": {
        "indicators": [
            ("java_detected", 0.5),
            ("php_serialized", 0.6),
            ("dotnet_detected", 0.4),
            ("viewstate_present", 0.7),
        ],
        "verify_payloads": [],  # يتطلب payloads معقدة
        "confidence_threshold": 0.6,
    },
    "file_upload": {
        "indicators": [
            ("has_file_input", 0.7),
            ("upload_endpoint", 0.8),
            ("multipart_form", 0.5),
        ],
        "verify_payloads": [],  # يتطلب رفع ملف فعلي
        "confidence_threshold": 0.5,
    },
}


# ============================ Site Behavior ============================
class SiteBehavior:
    """نموذج سلوك الموقع"""

    def __init__(self):
        self.tech_stack: Set[str] = set()
        self.framework: Optional[str] = None
        self.params_seen: Dict[str, Set[str]] = defaultdict(set)  # url -> params
        self.responses: List[Dict] = []
        self.baseline_response: Optional[Dict] = None
        self.error_patterns: Set[str] = set()
        self.endpoints_discovered: Set[str] = set()
        self.cookies_set: Set[str] = set()
        self.security_headers: Dict[str, str] = {}
        self.missing_headers: Set[str] = set()
        self.has_forms: bool = False
        self.has_ajax: bool = False
        self.has_api: bool = False
        self.has_file_upload: bool = False
        self.db_errors: List[str] = []
        self.php_errors: List[str] = []
        self.reflection_points: List[Dict] = []  # {url, param, reflected_value}


# ============================ AI Reasoner ============================
class AIReasoner:
    """محرك الاستدلال الذكي"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.behavior = SiteBehavior()
        self.hypotheses: Dict[str, float] = {}  # vuln_type -> confidence
        self.learned_patterns: Dict[str, any] = {}

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[AI] {msg}", level)

    def analyze(self, url: str) -> Dict:
        """تحليل الموقع واستنتاج الثغرات"""
        self._log("بدء التحليل الذكي للموقع...", "phase")

        # 1) جمع البيانات الأولية
        self._gather_initial_data(url)

        # 2) كشف التقنيات
        self._detect_technologies(url)

        # 3) استنتاج الثغرات
        self._generate_hypotheses(url)

        # 4) ترتيب الثغرات حسب الثقة
        sorted_hypotheses = sorted(
            self.hypotheses.items(),
            key=lambda x: x[1],
            reverse=True
        )

        # 5) عرض النتائج
        self._print_analysis(sorted_hypotheses)

        return {
            "behavior": self._behavior_to_dict(),
            "hypotheses": self.hypotheses,
            "sorted": sorted_hypotheses,
            "recommended_scans": self._get_recommended_scans(sorted_hypotheses),
        }

    def _gather_initial_data(self, url: str):
        """جمع البيانات الأولية"""
        self._log("جمع البيانات الأولية...", "info")

        # طلب baseline
        resp = self.client.get(url)
        self.behavior.baseline_response = resp
        self.behavior.responses.append(resp)

        if resp["status"] == 0:
            self._log("فشل الاتصال بالموقع", "error")
            return

        # تحليل الـ headers
        for header, value in resp["headers"].items():
            if header.lower() in ["x-frame-options", "content-security-policy",
                                   "strict-transport-security", "x-content-type-options",
                                   "x-xss-protection", "referrer-policy"]:
                self.behavior.security_headers[header] = value

        # فحص missing headers
        required_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                           "X-Frame-Options", "X-Content-Type-Options"]
        for h in required_headers:
            if h.lower() not in {k.lower() for k in resp["headers"].keys()}:
                self.behavior.missing_headers.add(h)

        # فحص cookies
        for header in resp["headers"].get("Set-Cookie", "").split(";"):
            if "=" in header:
                cookie_name = header.split("=")[0].strip()
                if cookie_name:
                    self.behavior.cookies_set.add(cookie_name)

        # فحص forms
        if "<form" in resp["body"].lower():
            self.behavior.has_forms = True
        if "xmlhttprequest" in resp["body"].lower() or "fetch(" in resp["body"].lower():
            self.behavior.has_ajax = True
        if "type='file'" in resp["body"].lower() or 'type="file"' in resp["body"].lower():
            self.behavior.has_file_upload = True

        # فحص API
        if "/api/" in resp["body"].lower() or "application/json" in resp["body"].lower():
            self.behavior.has_api = True

        # فحص reflection - نرسل param ونشوف هل بيرجع
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                for value in param_values:
                    if value in resp["body"]:
                        self.behavior.reflection_points.append({
                            "url": url,
                            "param": param_name,
                            "value": value,
                        })

        # فحص errors
        self._detect_errors(resp["body"])

    def _detect_errors(self, body: str):
        """كشف الأخطاء في الـ response"""
        error_patterns = {
            "sql_error": r"(SQL syntax|mysql_|mysqli_|SQLSTATE|Oracle error|ORA-|sqlite3)",
            "php_error": r"(PHP (Warning|Notice|Fatal error)|Parse error|Undefined)",
            "asp_error": r"(Server Error in|Runtime Error|System\.Exception)",
            "java_error": r"(java\.lang\.|NullPointerException|SQLException)",
            "python_error": r"(Traceback|Python|Django|Flask)",
        }

        for error_type, pattern in error_patterns.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                if error_type == "sql_error":
                    self.behavior.db_errors.extend(matches[:5])
                elif error_type == "php_error":
                    self.behavior.php_errors.extend(matches[:5])

    def _detect_technologies(self, url: str):
        """كشف التقنيات"""
        self._log("كشف التقنيات...", "info")

        resp = self.behavior.baseline_response
        if not resp:
            return

        content = resp["body"] + "\n" + "\n".join(f"{k}: {v}" for k, v in resp["headers"].items())
        content_lower = content.lower()

        for tech, indicators in TECH_INDICATORS.items():
            score = 0

            # فحص cookies
            for cookie in indicators.get("cookies", []):
                if cookie.lower() in content_lower:
                    score += 1

            # فحص headers
            for header in indicators.get("headers", []):
                if header.lower() in content_lower:
                    score += 1

            # فحص body
            for body_str in indicators.get("body", []):
                if body_str.lower() in content_lower:
                    score += 1

            if score >= 2:  # علامتين على الأقل
                self.behavior.tech_stack.add(tech)
                if not self.behavior.framework:
                    self.behavior.framework = tech
                self._log(f"تكنولوجيا مكتشفة: {tech} (score: {score})", "success")

    def _generate_hypotheses(self, url: str):
        """توليد hypotheses للثغرات"""
        self._log("توليد فرضيات الثغرات...", "info")

        # تحليل كل نوع ثغرة محتمل
        for vuln_type, config in VULN_HYPOTHESES.items():
            confidence = 0.0

            for indicator, weight in config["indicators"]:
                if self._check_indicator(indicator, url):
                    confidence += weight

            # فحص التقنيات المرتبطة
            for tech in self.behavior.tech_stack:
                tech_vulns = TECH_INDICATORS.get(tech, {}).get("common_vulns", [])
                if vuln_type in tech_vulns or any(v in vuln_type for v in tech_vulns):
                    confidence += 0.2

            if confidence >= config["confidence_threshold"]:
                self.hypotheses[vuln_type] = min(confidence, 1.0)
                self._log(f"فرضية: {vuln_type} (confidence: {confidence*100:.0f}%)", "info")

    def _check_indicator(self, indicator: str, url: str) -> bool:
        """فحص indicator معين"""
        if indicator == "has_database_error":
            return len(self.behavior.db_errors) > 0

        elif indicator == "param_reflects_exact":
            return len(self.behavior.reflection_points) > 0

        elif indicator == "param_reflects_in_html":
            for refl in self.behavior.reflection_points:
                if refl["value"] in self.behavior.baseline_response.get("body", ""):
                    return True
            return False

        elif indicator == "no_output_encoding":
            for refl in self.behavior.reflection_points:
                if "<" + refl["value"] in self.behavior.baseline_response.get("body", ""):
                    return True
            return False

        elif indicator == "response_length_varies":
            # فحص لو الـ responses ليهم أطوال مختلفة
            if len(self.behavior.responses) >= 2:
                lengths = [len(r["body"]) for r in self.behavior.responses]
                return max(lengths) - min(lengths) > 100
            return False

        elif indicator == "numeric_param":
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for values in params.values():
                    for v in values:
                        if v.isdigit():
                            return True
            return False

        elif indicator == "has_orm_detected":
            # ORM indicators
            return any(t in self.behavior.tech_stack for t in ["laravel", "django", "rails"])

        elif indicator.startswith("param_name_"):
            param_keyword = indicator.replace("param_name_", "")
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    if param_keyword in param_name.lower():
                        return True
            return False

        elif indicator == "php_detected":
            return "php" in self.behavior.tech_stack or "PHPSESSID" in self.behavior.cookies_set

        elif indicator == "has_search_param":
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                return any("search" in p.lower() or "q" == p.lower() for p in params.keys())
            return False

        elif indicator == "has_query_param":
            parsed = urlparse(url)
            return bool(parsed.query)

        elif indicator == "has_system_call":
            return False  # يحتاج فحص أعمق

        elif indicator == "template_engine_detected":
            return any(t in self.behavior.tech_stack for t in ["flask", "django", "spring", "laravel", "rails"])

        elif indicator == "framework_flask":
            return "flask" in self.behavior.tech_stack

        elif indicator == "framework_spring":
            return "spring" in self.behavior.tech_stack

        elif indicator == "accepts_xml":
            # فحص لو الموقع بيقبل XML
            resp = self.client.post(url, data="<?xml version='1.0'?><test/>",
                                   headers={"Content-Type": "application/xml"})
            return resp["status"] not in [400, 415, 0]

        elif indicator == "soap_endpoint":
            parsed = urlparse(url)
            return any(s in parsed.path.lower() for s in ["/soap", "/wsdl", "/api/soap"])

        elif indicator == "api_endpoint":
            return self.behavior.has_api

        elif indicator == "java_detected":
            return any(t in self.behavior.tech_stack for t in ["spring", "jsp"])

        elif indicator == "php_serialized":
            return "php" in self.behavior.tech_stack

        elif indicator == "dotnet_detected":
            return "aspnet" in self.behavior.tech_stack

        elif indicator == "viewstate_present":
            return "__VIEWSTATE" in self.behavior.baseline_response.get("body", "")

        elif indicator == "has_file_input":
            return self.behavior.has_file_upload

        elif indicator == "upload_endpoint":
            parsed = urlparse(url)
            return "upload" in parsed.path.lower()

        elif indicator == "multipart_form":
            return 'enctype="multipart/form-data"' in self.behavior.baseline_response.get("body", "").lower()

        return False

    def _get_recommended_scans(self, sorted_hypotheses: List[Tuple[str, float]]) -> List[Dict]:
        """الحصول على الفحوصات الموصى بها"""
        recommendations = []

        for vuln_type, confidence in sorted_hypotheses[:5]:
            config = VULN_HYPOTHESES.get(vuln_type, {})
            recommendations.append({
                "vuln_type": vuln_type,
                "confidence": confidence,
                "payloads": config.get("verify_payloads", []),
                "priority": "high" if confidence > 0.7 else "medium" if confidence > 0.4 else "low",
            })

        return recommendations

    def _behavior_to_dict(self) -> Dict:
        """تحويل الـ behavior لـ dict"""
        return {
            "tech_stack": list(self.behavior.tech_stack),
            "framework": self.behavior.framework,
            "cookies_set": list(self.behavior.cookies_set),
            "security_headers": self.behavior.security_headers,
            "missing_headers": list(self.behavior.missing_headers),
            "has_forms": self.behavior.has_forms,
            "has_ajax": self.behavior.has_ajax,
            "has_api": self.behavior.has_api,
            "has_file_upload": self.behavior.has_file_upload,
            "db_errors": self.behavior.db_errors,
            "php_errors": self.behavior.php_errors,
            "reflection_points": len(self.behavior.reflection_points),
        }

    def _print_analysis(self, sorted_hypotheses: List[Tuple[str, float]]):
        """عرض التحليل"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🧠 تحليل AI للموقع{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        # التقنيات
        print(f"\n  {Colors.BOLD}🛠️  التقنيات المكتشفة:{Colors.NC}")
        for tech in self.behavior.tech_stack:
            print(f"    {Colors.GREEN}✓{Colors.NC} {tech}")

        # Framework
        if self.behavior.framework:
            print(f"\n  {Colors.BOLD}📦 Framework:{Colors.NC} {self.behavior.framework}")

        # الأخطاء
        if self.behavior.db_errors:
            print(f"\n  {Colors.RED}{Colors.BOLD}⚠️  أخطاء DB مكتشفة:{Colors.NC}")
            for err in self.behavior.db_errors[:3]:
                print(f"    {Colors.RED}- {err}{Colors.NC}")

        if self.behavior.php_errors:
            print(f"\n  {Colors.YELLOW}⚠️  أخطاء PHP:{Colors.NC}")
            for err in self.behavior.php_errors[:3]:
                print(f"    - {err}")

        # Reflection
        if self.behavior.reflection_points:
            print(f"\n  {Colors.YELLOW}🔍 نقاط Reflection: {len(self.behavior.reflection_points)}{Colors.NC}")

        # الـ hypotheses
        if sorted_hypotheses:
            print(f"\n  {Colors.BOLD}🧠 الفرضيات (مرتبة حسب الثقة):{Colors.NC}")
            for vuln_type, confidence in sorted_hypotheses[:10]:
                if confidence > 0.7:
                    color = Colors.RED + Colors.BOLD
                    bar = "█" * 10
                elif confidence > 0.4:
                    color = Colors.YELLOW
                    bar = "█" * int(confidence * 10)
                else:
                    color = Colors.BLUE
                    bar = "█" * int(confidence * 10)

                print(f"    {color}{vuln_type:30s}{Colors.NC} {confidence*100:5.1f}% {bar}")

        # التوصيات
        recommendations = self._get_recommended_scans(sorted_hypotheses)
        if recommendations:
            print(f"\n  {Colors.BOLD}🎯 الفحوصات الموصى بها:{Colors.NC}")
            for rec in recommendations[:5]:
                priority_color = {
                    "high": Colors.RED,
                    "medium": Colors.YELLOW,
                    "low": Colors.BLUE,
                }.get(rec["priority"], Colors.NC)
                print(f"    {priority_color}[{rec['priority']}]{Colors.NC} {rec['vuln_type']} ({rec['confidence']*100:.0f}%)")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - AI Reasoner")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    client = HttpClient(timeout=15)
    reasoner = AIReasoner(client)
    analysis = reasoner.analyze(args.url)
