#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - False Positive Killer
يحلل النتائج ويزيل الـ false positives بذكاء

الذكاء:
1. Baseline comparison - يقارن مع response عادي
2. Content-Type awareness - JSON reflection ≠ XSS
3. HTTP reflection vs execution - reflection alone ≠ vuln
4. Timing analysis - يستبعد الأخرى
5. Pattern validation - يتأكد إن الناتج فعلاً ثغرة
6. Confidence scoring - يعطي درجة ثقة لكل نتيجة
7. Cross-validation - يتأكد من النتائج بطرق متعددة
"""
import os
import sys
import re
import time
import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


class FalsePositiveKiller:
    """إزالة الـ false positives"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None):
        self.client = http_client or HttpClient(timeout=15)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.baseline_cache = {}

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[FP-KILLER] {msg}", level)

    def filter_vulns(self, vulns: List[Dict], base_url: str) -> List[Dict]:
        """تصفية الثغرات وإزالة الـ false positives"""
        self._log(f"تصفية {len(vulns)} نتيجة...", "phase")

        verified = []
        removed = 0

        for vuln in vulns:
            vtype = vuln.get("type", "")

            # أنواع نثق فيها بدون تحقق
            trusted_types = [
                "missing_security_header", "info_disclosure_header",
                "insecure_cookie", "waf_detected", "no_waf",
                "info_disclosure_email", "info_disclosure_phone",
                "info_disclosure_api_key", "info_disclosure_aws_key",
                "info_disclosure_github_token", "info_disclosure_slack_token",
                "info_disclosure_private_key", "info_disclosure_jwt_token",
                "info_disclosure_internal_ip", "info_disclosure_version",
                "info_disclosure_stack_trace", "info_disclosure_comment",
                "info_disclosure_debug", "sensitive_file_exposed",
                "exposed_backup", "git_exposed", "git_config_exposed",
                "robots_disclosure", "sitemap_disclosure",
                "no_rate_limiting", "no_https_redirect",
                "insecure_cookie", "trace_enabled",
                "dangerous_http_methods", "cors_wildcard_credentials",
                "cors_reflected_credentials",
            ]

            if vtype in trusted_types:
                verified.append(vuln)
                continue

            # أنواع نحتاج تحققها
            needs_verification = [
                "sql_injection_error", "sql_injection_boolean", "sql_injection_time",
                "xss_reflected", "xss_reflected_partial",
                "ssti", "lfi", "lfi_php_filter", "lfi_log_file",
                "command_injection", "open_redirect",
                "cors_reflected", "clickjacking",
            ]

            if vtype in needs_verification:
                is_valid, confidence = self._verify_vuln(vuln, base_url)

                if is_valid:
                    vuln["confidence"] = confidence
                    verified.append(vuln)
                    self._log(f"  ✓ {vtype} - مؤكد ({confidence*100:.0f}%)", "success")
                else:
                    removed += 1
                    self._log(f"  ✗ {vtype} - false positive (تمت الإزالة)", "warn")
            else:
                # أنواع أخرى - نحتفظ بيها
                verified.append(vuln)

        self._log(f"\nالنتيجة: {len(verified)} مؤكدة | {removed} مُزالة", "success")
        return verified

    def _verify_vuln(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من ثغرة"""
        vtype = vuln.get("type", "")
        url = vuln.get("url", base_url)

        if vtype == "ssti":
            return self._verify_ssti(vuln, base_url)
        elif vtype.startswith("sql_injection"):
            return self._verify_sqli(vuln, base_url)
        elif vtype.startswith("xss"):
            return self._verify_xss(vuln, base_url)
        elif vtype.startswith("lfi"):
            return self._verify_lfi(vuln, base_url)
        elif vtype == "command_injection":
            return self._verify_cmd(vuln, base_url)
        elif vtype == "open_redirect":
            return self._verify_redirect(vuln, base_url)
        elif vtype == "clickjacking":
            return self._verify_clickjacking(vuln, base_url)
        elif vtype.startswith("cors"):
            return self._verify_cors(vuln, base_url)
        else:
            # افتراضي: نثق فيها
            return True, 0.7

    def _get_baseline(self, url: str) -> str:
        """الحصول على baseline response"""
        if url in self.baseline_cache:
            return self.baseline_cache[url]

        resp = self.client.get(url)
        baseline = resp.get("body", "")
        self.baseline_cache[url] = baseline
        return baseline

    def _verify_ssti(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من SSTI"""
        url = vuln.get("url", base_url)
        parsed = urlparse(url)

        if not parsed.query:
            return False, 0.0

        params = parse_qs(parsed.query)
        param_name = list(params.keys())[0] if params else "q"

        # إرسال قيمة عادية كـ baseline
        baseline_params = params.copy()
        baseline_params[param_name] = ["ghostpwn_baseline_12345"]
        baseline_query = urlencode(baseline_params, doseq=True)
        baseline_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, baseline_query, parsed.fragment))
        baseline_resp = self.client.get(baseline_url)
        baseline_body = baseline_resp.get("body", "")

        # إرسال {{7*7}}
        test_params = params.copy()
        test_params[param_name] = ["{{7*7}}"]
        test_query = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                              parsed.params, test_query, parsed.fragment))
        test_resp = self.client.get(test_url)
        test_body = test_resp.get("body", "")

        # فحص: هل "49" موجود في test لكن مش في baseline؟
        if "49" in test_body and "49" not in baseline_body:
            return True, 0.95
        elif "49" in test_body and "49" in baseline_body:
            # false positive - "49" موجود في الـ baseline
            return False, 0.0

        # فحص {{7*'7'}} = 7777777 (Jinja2)
        test_params[param_name] = ["{{7*'7'}}"]
        test_query = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                              parsed.params, test_query, parsed.fragment))
        test_resp = self.client.get(test_url)
        test_body = test_resp.get("body", "")

        if "7777777" in test_body and "7777777" not in baseline_body:
            return True, 0.95

        return False, 0.0

    def _verify_sqli(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من SQLi"""
        url = vuln.get("url", base_url)
        technique = vuln.get("technique", "")

        if technique == "error":
            # تحقق: هل الـ error موجود في baseline؟
            baseline = self._get_baseline(base_url)

            # إرسال payload خطأ
            resp = self.client.get(url)
            body = resp.get("body", "")

            # فحص لو فيه SQL errors في الـ response
            sql_errors = [
                r"SQL syntax.*MySQL", r"Warning.*mysql_",
                r"SQLSTATE", r"ORA-\d{5}",
                r"Microsoft SQL Server", r"sqlite3",
            ]

            for pattern in sql_errors:
                if re.search(pattern, body, re.IGNORECASE):
                    # تأكد إن الخطأ مش في baseline
                    if not re.search(pattern, baseline, re.IGNORECASE):
                        return True, 0.95
                    else:
                        return False, 0.0  # false positive

            return False, 0.0

        elif technique == "time":
            # تحقق: قارن التوقيت
            elapsed = vuln.get("elapsed", 0)
            if elapsed >= 4.5:
                # قارن مع طلب عادي
                normal_resp = self.client.get(base_url)
                normal_elapsed = normal_resp.get("elapsed", 0)

                if elapsed > normal_elapsed + 4:
                    return True, 0.90
                else:
                    return False, 0.0
            return False, 0.0

        elif technique == "boolean":
            # تحقق: هل الـ responses فعلاً مختلفة؟
            url_true = vuln.get("url", base_url)

            # بناء URL false
            parsed = urlparse(url_true)
            if not parsed.query:
                return False, 0.0

            params = parse_qs(parsed.query)
            param_name = vuln.get("param", list(params.keys())[0])

            false_params = params.copy()
            false_value = params[param_name][0].replace("'1'='1", "'1'='2").replace("1=1", "1=2")
            false_params[param_name] = [false_value]
            false_query = urlencode(false_params, doseq=True)
            url_false = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                    parsed.params, false_query, parsed.fragment))

            resp_true = self.client.get(url_true)
            resp_false = self.client.get(url_false)

            len_diff = abs(len(resp_true["body"]) - len(resp_false["body"]))

            if len_diff > 200:
                return True, 0.85
            else:
                return False, 0.0

        return True, 0.7  # افتراضي

    def _verify_xss(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من XSS"""
        url = vuln.get("url", base_url)

        resp = self.client.get(url)

        # 1) Content-Type check
        content_type = resp["headers"].get("Content-Type", "").lower()
        if "application/json" in content_type or "application/xml" in content_type:
            # JSON/XML reflection ≠ exploitable XSS
            return False, 0.0

        # 2) فحص هل الـ payload فعلاً reflected كـ HTML
        payload = vuln.get("payload", "")
        if not payload:
            return False, 0.0

        if payload in resp["body"]:
            # 3) فحص هل الـ payload محاط بـ HTML context
            # لو الـ payload ظهر داخل <script> tag = أخطر
            # لو ظهر داخل attribute = أقل خطورة
            # لو ظهر كنص = مش exploitable

            # فحص بسيط: هل فيه < في الـ payload المنعكس؟
            if "<" in payload and "<" in resp["body"]:
                return True, 0.90
            elif "javascript:" in payload.lower():
                return True, 0.85
            else:
                return True, 0.70

        return False, 0.0

    def _verify_lfi(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من LFI"""
        url = vuln.get("url", base_url)
        resp = self.client.get(url)
        body = resp.get("body", "")

        # فحص مؤشرات محددة
        indicators = {
            "root:": ":/bin/",
            "[fonts]": "extensions",
            "Mozilla": "GET /",
        }

        for ind1, ind2 in indicators.items():
            if ind1 in body and ind2 in body:
                # تأكد إنها مش في baseline
                baseline = self._get_baseline(base_url)
                if ind1 not in baseline or ind2 not in baseline:
                    return True, 0.95

        return False, 0.0

    def _verify_cmd(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من Command Injection"""
        url = vuln.get("url", base_url)
        resp = self.client.get(url)
        body = resp.get("body", "")

        # فحص uid= pattern
        uid_pattern = r'uid=\d+\([\w-]+\).*gid=\d+'
        if re.search(uid_pattern, body):
            baseline = self._get_baseline(base_url)
            if not re.search(uid_pattern, baseline):
                return True, 0.95

        return False, 0.0

    def _verify_redirect(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من Open Redirect"""
        url = vuln.get("url", base_url)

        # نمنع redirects
        old_setting = self.client.allow_redirects
        self.client.allow_redirects = False
        resp = self.client.get(url)
        self.client.allow_redirects = old_setting

        location = resp["headers"].get("Location", "")
        if "evil.com" in location:
            return True, 0.90

        return False, 0.0

    def _verify_clickjacking(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من Clickjacking"""
        url = vuln.get("url", base_url)
        resp = self.client.get(url)

        xfo = resp["headers"].get("X-Frame-Options", "").upper()
        csp = resp["headers"].get("Content-Security-Policy", "").lower()

        if xfo in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp:
            return False, 0.0  # محمي = false positive

        return True, 0.90

    def _verify_cors(self, vuln: Dict, base_url: str) -> Tuple[bool, float]:
        """تحقق من CORS"""
        url = vuln.get("url", base_url)
        parsed = urlparse(url)
        evil_origin = f"{parsed.scheme}://evil.com"

        resp = self.client.get(url, headers={"Origin": evil_origin})

        acao = resp["headers"].get("Access-Control-Allow-Origin", "")
        acac = resp["headers"].get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            return True, 0.95
        elif acao == evil_origin:
            if acac.lower() == "true":
                return True, 0.95
            else:
                return True, 0.80

        return False, 0.0


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - False Positive Killer")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--vulns-file", required=True, help="JSON file with vulns")
    parser.add_argument("--output", help="Output file for verified vulns")
    args = parser.parse_args()

    with open(args.vulns_file) as f:
        vulns = json.load(f)

    killer = FalsePositiveKiller()
    verified = killer.filter_vulns(vulns, args.url)

    output = args.output or "verified_vulns.json"
    with open(output, "w") as f:
        json.dump(verified, f, ensure_ascii=False, indent=2)

    print(f"\n[✓] {len(verified)}/{len(vulns)} vulns verified")
    print(f"    Saved: {output}")
