#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Advanced Vulnerability Detectors
فحوصات متقدمة إضافية: GraphQL, Host Header, Subdomain Takeover, IDOR, CSRF
"""
import sys
import os
import re
import socket
import json
import urllib.parse
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient


class AdvancedVulnDetector:
    """فحوصات ثغرات متقدمة"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.vulns_found = []

    def log(self, msg, level="info"):
        icons = {"info": "[*]", "success": "[✓]", "warn": "[!]", "error": "[✗]"}
        print(f"    {icons.get(level, '[*]')} {msg}")
        if self.audit:
            self.audit.log_event(msg, level)

    def add_vuln(self, vuln_type: str, severity: str, url: str,
                 evidence: str, module: str, **extra):
        vuln = {
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "evidence": evidence,
            "module": module,
        }
        vuln.update(extra)
        self.vulns_found.append(vuln)

    # ============================ GraphQL Testing ============================
    def detect_graphql(self, url: str) -> List[Dict]:
        """كشف وفحص GraphQL endpoints"""
        self.log("Testing GraphQL...", "info")

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        graphql_paths = [
            "/graphql", "/graphql/console", "/graphiql", "/api/graphql",
            "/v1/graphql", "/v2/graphql", "/query", "/api/query",
            "/playground", "/__graphql__", "/graphql.php",
        ]

        # introspection query
        introspection_query = json.dumps({
            "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name } } } }"
        })

        for path in graphql_paths:
            test_url = base_url + path

            # POST مع introspection
            resp = self.client.post(test_url, data=introspection_query,
                                   headers={"Content-Type": "application/json"})

            if resp["status"] == 200:
                body = resp["body"]

                # فحص introspection enabled
                if "__schema" in body or "__type" in body:
                    self.log(f"GraphQL endpoint with introspection: {test_url}", "warn")
                    self.add_vuln(
                        "graphql_introspection", "high", test_url,
                        "GraphQL introspection enabled - schema exposed",
                        "graphql"
                    )

                    # فحص batch queries (DoS)
                    batch_query = json.dumps([
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"}
                    ])
                    batch_resp = self.client.post(test_url, data=batch_query,
                                                 headers={"Content-Type": "application/json"})
                    if batch_resp["status"] == 200 and "data" in batch_resp["body"]:
                        self.log("GraphQL batch queries allowed (DoS risk)", "warn")
                        self.add_vuln(
                            "graphql_batch", "medium", test_url,
                            "GraphQL batch queries allowed - DoS possible",
                            "graphql"
                        )

                    return self.vulns_found

                # فحص error-based info disclosure
                elif "errors" in body and ("Cannot query" in body or "did you mean" in body):
                    self.log(f"GraphQL endpoint detected (info disclosure): {test_url}", "warn")
                    self.add_vuln(
                        "graphql_detected", "low", test_url,
                        "GraphQL endpoint leaks schema via error messages",
                        "graphql"
                    )
                    return self.vulns_found

        return self.vulns_found

    # ============================ Host Header Injection ============================
    def detect_host_header_injection(self, url: str) -> List[Dict]:
        """فحص Host Header Injection"""
        self.log("Testing Host Header Injection...", "info")

        evil_host = "evil.com"

        # طلب بـ Host header مزيف
        resp = self.client.get(url, headers={"Host": evil_host})

        if evil_host in resp["body"]:
            self.log(f"Host Header reflected in response: {evil_host}", "warn")
            self.add_vuln(
                "host_header_reflected", "high", url,
                f"Host header '{evil_host}' reflected in response body",
                "host_header"
            )

        # فحص password reset poisoning
        if "reset" in url.lower() or "password" in url.lower():
            if evil_host in resp["body"] or resp["status"] == 200:
                self.log("Host Header Injection on password reset!", "warn")
                self.add_vuln(
                    "host_header_reset_poisoning", "critical", url,
                    "Host header injection on password reset - account takeover possible",
                    "host_header"
                )

        # فحص X-Forwarded-Host
        resp2 = self.client.get(url, headers={"X-Forwarded-Host": evil_host})
        if evil_host in resp2["body"]:
            self.log(f"X-Forwarded-Host reflected: {evil_host}", "warn")
            self.add_vuln(
                "x_forwarded_host_reflected", "high", url,
                f"X-Forwarded-Host '{evil_host}' reflected in response",
                "host_header"
            )

        return self.vulns_found

    # ============================ Subdomain Takeover ============================
    TAKEOVER_FINGERPRINTS = {
        "AWS S3": ["The specified bucket does not exist", "NoSuchBucket"],
        "GitHub Pages": ["There isn't a GitHub Pages site here"],
        "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "Shopify": ["Sorry, this shop is currently unavailable"],
        "Tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
        "WordPress": ["Do you want to register"],
        "Pantheon": ["The gods are wise, but do not know of the site which you seek"],
        "Azure": ["404 Web Site not found", "Microsoft Azure"],
        "Fastly": ["Fastly error: unknown domain"],
        "Ghost": ["The thing you were looking for is no longer here"],
        "Surge.sh": ["project not found"],
        "Cargo": ["If you're moving your content to a new domain"],
        "Unbounce": ["The requested URL was not found on this server"],
        "Webflow": ["The page you are looking for doesn't exist"],
    }

    def detect_subdomain_takeover(self, subdomains: List[Dict]) -> List[Dict]:
        """فحص subdomain takeover"""
        self.log(f"Testing {len(subdomains)} subdomains for takeover...", "info")

        for sub_info in subdomains:
            subdomain = sub_info.get("subdomain", "")
            if not subdomain:
                continue

            self.log(f"Checking: {subdomain}", "info")

            # فحص HTTP
            try:
                resp = self.client.get(f"http://{subdomain}")
                body_lower = resp["body"].lower()

                for service, fingerprints in self.TAKEOVER_FINGERPRINTS.items():
                    for fp in fingerprints:
                        if fp.lower() in body_lower:
                            self.log(f"TAKEOVER: {subdomain} ({service})", "warn")
                            self.add_vuln(
                                "subdomain_takeover", "high", f"http://{subdomain}",
                                f"Subdomain takeover possible ({service})",
                                "subtake", subdomain=subdomain, service=service
                            )
                            break
            except Exception:
                pass

            # فحص HTTPS
            try:
                resp = self.client.get(f"https://{subdomain}")
                body_lower = resp["body"].lower()

                for service, fingerprints in self.TAKEOVER_FINGERPRINTS.items():
                    for fp in fingerprints:
                        if fp.lower() in body_lower:
                            self.log(f"TAKEOVER: {subdomain} ({service})", "warn")
                            self.add_vuln(
                                "subdomain_takeover", "high", f"https://{subdomain}",
                                f"Subdomain takeover possible ({service})",
                                "subtake", subdomain=subdomain, service=service
                            )
                            break
            except Exception:
                pass

        return self.vulns_found

    # ============================ IDOR (Insecure Direct Object Reference) ============================
    def detect_idor(self, url: str) -> List[Dict]:
        """فحص IDOR"""
        self.log("Testing IDOR...", "info")

        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return self.vulns_found

        params = urllib.parse.parse_qs(parsed.query)
        idor_param_names = ["id", "user", "user_id", "userid", "uid",
                           "account", "account_id", "doc", "file",
                           "order", "order_id", "product", "item"]

        for param_name in params.keys():
            if param_name.lower() not in idor_param_names:
                continue

            original_value = params[param_name][0]

            # إذا كان رقم، جرّب أرقام أخرى
            if original_value.isdigit():
                test_value = str(int(original_value) + 1)

                # الطلب الأصلي
                resp1 = self.client.get(url)

                # الطلب المعدّل
                test_params = params.copy()
                test_params[param_name] = [test_value]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                resp2 = self.client.get(test_url)

                # فحص لو الـ response مختلف والـ status 200
                if (resp1["status"] == 200 and resp2["status"] == 200
                    and resp1["body"] != resp2["body"]
                    and len(resp2["body"]) > 500
                    and "error" not in resp2["body"].lower()[:200]
                    and "unauthorized" not in resp2["body"].lower()[:200]
                    and "denied" not in resp2["body"].lower()[:200]):

                    self.log(f"Potential IDOR on param '{param_name}'", "warn")
                    self.add_vuln(
                        "idor", "high", test_url,
                        f"IDOR: accessing {param_name}={test_value} returns different valid data",
                        "idor", param=param_name,
                        original_value=original_value, test_value=test_value
                    )
                    break  # نكتفي بأول IDOR

        return self.vulns_found

    # ============================ CSRF (Cross-Site Request Forgery) ============================
    def detect_csrf(self, url: str) -> List[Dict]:
        """فحص CSRF - نحتاج forms من الـ crawler"""
        self.log("Testing CSRF...", "info")

        resp = self.client.get(url)
        body = resp["body"]

        # البحث عن forms state-changing (POST, PUT, DELETE)
        form_pattern = re.compile(
            r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*method=["\']?(post|put|delete)["\']?[^>]*>([\s\S]*?)</form>',
            re.IGNORECASE
        )

        for match in form_pattern.finditer(body):
            action = match.group(1)
            method = match.group(2).upper()
            form_html = match.group(3)

            # البحث عن CSRF token
            csrf_patterns = [
                r'<input[^>]*name=["\']?(csrf|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken)["\']?[^>]*>',
                r'<input[^>]*value=["\'][^"\']*token[^"\']*["\'][^>]*>',
                r'<meta[^>]*name=["\']?csrf["\'][^>]*>',
            ]

            has_csrf_token = False
            for pattern in csrf_patterns:
                if re.search(pattern, form_html, re.IGNORECASE):
                    has_csrf_token = True
                    break

            if not has_csrf_token:
                self.log(f"Form without CSRF token: {action} ({method})", "warn")
                self.add_vuln(
                    "csrf_no_token", "medium", url,
                    f"State-changing form ({method}) without CSRF token",
                    "csrf", form_action=action, form_method=method
                )

        return self.vulns_found

    # ============================ JWT Analysis ============================
    def detect_jwt_issues(self, url: str) -> List[Dict]:
        """فحص JWT tokens"""
        self.log("Testing JWT...", "info")

        resp = self.client.get(url)
        body = resp["body"]

        # البحث عن JWT pattern
        jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*')
        tokens = jwt_pattern.findall(body)

        import base64

        for token in set(tokens[:3]):  # أول 3 tokens
            try:
                parts = token.split(".")

                def decode_b64(s):
                    s += "=" * (4 - len(s) % 4)
                    return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")

                header = json.loads(decode_b64(parts[0]))
                payload = json.loads(decode_b64(parts[1]))
                algorithm = header.get("alg", "")

                self.log(f"Found JWT - alg: {algorithm}", "info")

                # فحص خوارزمية none
                if algorithm.lower() in ("none", ""):
                    self.log("JWT with 'none' algorithm!", "warn")
                    self.add_vuln(
                        "jwt_none_algorithm", "critical", url,
                        "JWT uses 'none' algorithm - signature bypass possible",
                        "jwt", header=header
                    )

                # فحص expiry
                if "exp" not in payload:
                    self.log("JWT without expiry", "warn")
                    self.add_vuln(
                        "jwt_no_expiry", "medium", url,
                        "JWT missing 'exp' claim - token never expires",
                        "jwt"
                    )

                # فحص بيانات حساسة في payload
                sensitive_keys = ["password", "secret", "ssn", "credit_card",
                                  "creditcard", "cvv", "pin"]
                for key in payload:
                    if key.lower() in sensitive_keys:
                        self.log(f"Sensitive data in JWT: {key}", "warn")
                        self.add_vuln(
                            "jwt_sensitive_data", "high", url,
                            f"Sensitive data '{key}' in JWT payload",
                            "jwt", key=key
                        )

            except Exception as e:
                continue

        return self.vulns_found

    # ============================ Backup Files ============================
    def detect_backup_files(self, url: str) -> List[Dict]:
        """كشف ملفات الـ backup المكشوفة"""
        self.log("Testing backup files...", "info")

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path if parsed.path != "/" else "/index"

        backup_extensions = [".bak", ".old", ".orig", ".backup", ".save",
                            ".swp", ".tmp", ".tar.gz", ".zip", ".sql"]

        backup_filenames = [
            "/backup.zip", "/backup.tar.gz", "/backup.sql",
            "/db.sql", "/database.sql", "/dump.sql",
            "/site.zip", "/www.zip", "/web.zip",
            "/.env.bak", "/.env.local", "/.env.production",
            "/wp-config.php.bak", "/config.php.bak",
        ]

        # فحص امتدادات backup للصفحة الحالية
        for ext in backup_extensions:
            test_url = base_url + path + ext
            resp = self.client.request(test_url, "HEAD")
            if resp["status"] == 200:
                content_length = resp["headers"].get("Content-Length", "0")
                if int(content_length) > 0:
                    self.log(f"Backup file exposed: {test_url}", "warn")
                    self.add_vuln(
                        "exposed_backup", "high", test_url,
                        f"Backup file accessible: {test_url}",
                        "backup"
                    )

        # فحص أسماء ملفات backup شائعة
        for backup_file in backup_filenames:
            test_url = base_url + backup_file
            resp = self.client.request(test_url, "HEAD")
            if resp["status"] == 200:
                content_length = resp["headers"].get("Content-Length", "0")
                if int(content_length) > 0:
                    self.log(f"Backup file exposed: {test_url}", "warn")
                    self.add_vuln(
                        "exposed_backup", "high", test_url,
                        f"Backup file accessible: {test_url}",
                        "backup"
                    )

        return self.vulns_found

    # ============================ Git Exposure ============================
    def detect_git_exposure(self, url: str) -> List[Dict]:
        """كشف تعرض مجلد .git"""
        self.log("Testing .git exposure...", "info")

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        git_files = [
            "/.git/HEAD",
            "/.git/config",
            "/.git/index",
            "/.git/logs/HEAD",
            "/.git/refs/heads/master",
            "/.git/refs/heads/main",
        ]

        for git_file in git_files:
            test_url = base_url + git_file
            resp = self.client.get(test_url)

            if resp["status"] == 200:
                if git_file == "/.git/HEAD" and "ref:" in resp["body"]:
                    self.log(f"Git repository exposed: {test_url}", "warn")
                    self.add_vuln(
                        "git_exposed", "critical", test_url,
                        ".git/HEAD accessible - full source code can be downloaded",
                        "git"
                    )
                    break

                elif git_file == "/.git/config" and "[core]" in resp["body"]:
                    self.log(f"Git config exposed: {test_url}", "warn")
                    self.add_vuln(
                        "git_config_exposed", "high", test_url,
                        ".git/config accessible - repo metadata exposed",
                        "git"
                    )
                    break

        return self.vulns_found

    # ============================ Cloud Storage ============================
    def detect_cloud_storage(self, url: str) -> List[Dict]:
        """كشف cloud storage مكشوف"""
        self.log("Testing cloud storage...", "info")

        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc
        bucket_name = hostname.split(".")[0]

        # S3
        s3_urls = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
        ]

        for s3_url in s3_urls:
            resp = self.client.get(s3_url)
            if resp["status"] == 200:
                if "<ListBucketResult" in resp["body"]:
                    self.log(f"S3 Bucket listing exposed: {s3_url}", "warn")
                    self.add_vuln(
                        "s3_bucket_listing", "high", s3_url,
                        "S3 bucket allows public listing",
                        "cloud"
                    )
                elif "<Code>Access Denied</Code>" not in resp["body"]:
                    self.log(f"S3 Bucket accessible: {s3_url}", "warn")
                    self.add_vuln(
                        "s3_bucket_accessible", "medium", s3_url,
                        "S3 bucket is accessible",
                        "cloud"
                    )

        # Azure Blob
        azure_url = f"https://{bucket_name}.blob.core.windows.net/"
        resp = self.client.get(azure_url)
        if resp["status"] == 200 and "EnumerationResults" in resp["body"]:
            self.log(f"Azure Blob listing exposed: {azure_url}", "warn")
            self.add_vuln(
                "azure_blob_listing", "high", azure_url,
                "Azure Blob container allows public listing",
                "cloud"
            )

        # GCS
        gcs_url = f"https://storage.googleapis.com/{bucket_name}/"
        resp = self.client.get(gcs_url)
        if resp["status"] == 200 and "<ListBucketResult" in resp["body"]:
            self.log(f"GCS Bucket listing exposed: {gcs_url}", "warn")
            self.add_vuln(
                "gcs_bucket_listing", "high", gcs_url,
                "Google Cloud Storage bucket allows public listing",
                "cloud"
            )

        return self.vulns_found

    # ============================ Run All ============================
    def run_all(self, url: str, subdomains: List[Dict] = None) -> List[Dict]:
        """تشغيل كل الفحوصات المتقدمة"""
        self.vulns_found = []

        self.detect_graphql(url)
        self.detect_host_header_injection(url)
        if subdomains:
            self.detect_subdomain_takeover(subdomains)
        self.detect_idor(url)
        self.detect_csrf(url)
        self.detect_jwt_issues(url)
        self.detect_backup_files(url)
        self.detect_git_exposure(url)
        self.detect_cloud_storage(url)

        return self.vulns_found
