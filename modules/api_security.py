#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - REST API Security Scanner
فحص أمان REST APIs

الميزات:
1.  كشف REST API endpoints (HTML + JS)
2.  فحص Authentication Bypass
3.  فحص Authorization / IDOR على API endpoints
4.  فحص Rate Limiting
5.  فحص API Versioning vulnerabilities
6.  فحص Mass Assignment
7.  فحص HTTP Method Tampering
8.  فحص HTTP Parameter Pollution (HPP)
9.  كشف Response Tampering / Cache poisoning hints
10. API Key Brute Force
11. كشف GraphQL endpoints
12. كشف Swagger / OpenAPI spec exposure
13. فحص CORS misconfiguration على API
"""
import os
import sys
import re
import json
import time
import string
import random
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# Common API base paths to probe
API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/",
    "/api/v3", "/api/v3/", "/api/users", "/api/user", "/api/account",
    "/api/accounts", "/api/login", "/api/auth", "/api/auth/login",
    "/api/admin", "/api/admin/users", "/api/me", "/api/profile",
    "/api/products", "/api/orders", "/api/items", "/api/data",
    "/rest", "/rest/v1", "/rest/api", "/service", "/services",
    "/backend", "/backend/api", "/internal/api", "/private/api",
]

# Swagger / OpenAPI spec file names
SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api/swagger.json",
    "/api/v1/swagger.json", "/api-docs", "/api/docs", "/apidocs",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger-ui/",
    "/swagger-resources", "/swagger-resources/configuration/ui",
    "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml",
    "/openapi", "/spec", "/spec.json", "/api-spec", "/api-spec.json",
    "/redoc", "/api/openapi.json", "/docs/swagger.json",
]

# GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
    "/v1/graphql", "/v2/graphql", "/query", "/api/query",
    "/graphiql", "/playground", "/api/playground", "/explorer",
    "/api/explorer", "/gql", "/api/gql", "/graphql.php",
]

# Common API key header names
API_KEY_HEADERS = [
    "X-API-Key", "Api-Key", "API-Key", "X-Apikey", "ApiKey",
    "Authorization", "X-Auth-Token", "X-Auth", "X-Token",
]

# Weak / common API key values for brute force (small, fast list)
COMMON_API_KEYS = [
    "test", "demo", "123456", "1234567890", "admin", "secret",
    "apikey", "api-key", "guest", "public", "internal", "dev",
    "development", "staging", "production", "default", "sample",
    "root", "master", "key", "testkey", "apikey123",
    "1234567890abcdef", "abcdef1234567890", "00000000",
    "11111111", "AAAAAAAA", "aaaaaaaa",
]

# Common HTTP methods to test for tampering
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
                "OPTIONS", "TRACE", "CONNECT", "PROPFIND"]

# Mass assignment fields that are commonly interesting
MASS_ASSIGNMENT_FIELDS = {
    "role": ["admin", "administrator", "root", "superuser"],
    "isAdmin": ["true", "1", "yes"],
    "is_admin": ["true", "1"],
    "admin": ["true", "1"],
    "role_id": ["1", "0"],
    "roleId": ["1", "0"],
    "permissions": ["*", "admin", "all"],
    "permissions[]": ["admin", "read,write,delete"],
    "verified": ["true", "1"],
    "is_verified": ["true", "1"],
    "active": ["true", "1"],
    "status": ["active", "approved", "verified"],
    "email_verified": ["true", "1"],
    "paid": ["true", "1"],
    "plan": ["premium", "pro", "enterprise", "unlimited"],
    "tier": ["premium", "gold", "platinum"],
    "balance": ["999999", "1000000"],
    "credit": ["999999"],
    "price": ["0", "0.01"],
}

# IDOR param names to look for
IDOR_PARAMS = ["id", "user_id", "userId", "uid", "account_id",
               "accountId", "order_id", "orderId", "doc_id", "docId",
               "resource_id", "resourceId", "item_id", "itemId",
               "file_id", "fileId", "profile_id", "profileId"]

# Versioned API prefixes to probe for old/unsupported versions
API_VERSIONS = ["v1", "v2", "v3", "v4", "v0", "v0.1", "v1.0", "v1.1",
                "v2.0", "v3.0", "beta", "alpha", "internal", "staging",
                "dev", "test", "old", "legacy"]

# Sensitive response fields that should not be leaked
SENSITIVE_FIELDS = ["password", "pwd", "passwd", "secret", "token",
                    "api_key", "apikey", "api_secret", "private_key",
                    "privateKey", "ssn", "credit_card", "creditCard",
                    "card_number", "cardNumber", "cvv", "pin"]


# ============================ Main Class ============================

class APISecurityScanner:
    """فاحص أمان REST APIs - يكتشف ويختبر ثغرات الـ APIs"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=12, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self.endpoints: Set[str] = set()
        self.spec_endpoints: List[Dict] = []
        self._scanned = set()  # dedupe URLs we've already touched

        # Tunable options
        self.max_endpoints = self.options.get("max_endpoints", 30)
        self.rate_limit_requests = self.options.get("rate_limit_requests", 25)
        self.rate_limit_window = self.options.get("rate_limit_window", 10.0)
        self.api_key_limit = self.options.get("api_key_limit", 30)
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[API-SEC] {msg}", level)

    def _add_finding(self, ftype: str, severity: str, url: str,
                     title: str, description: str, evidence: str,
                     **extra) -> Dict:
        """إضافة finding بصيغة موحّدة"""
        finding = {
            "type": ftype,
            "severity": severity,
            "url": url,
            "title": title,
            "description": description,
            "evidence": evidence,
        }
        finding.update(extra)
        self.findings.append(finding)
        self._log(f"  ⚠️  [{severity.upper()}] {title} @ {url}", "vuln")
        return finding

    @staticmethod
    def _looks_like_json(body: str) -> bool:
        if not body:
            return False
        b = body.lstrip()
        return b.startswith("{") or b.startswith("[")

    @staticmethod
    def _safe_json(body: str) -> Optional[Dict]:
        try:
            return json.loads(body)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _short(text: str, n: int = 200) -> str:
        if not text:
            return ""
        text = text.replace("\n", " ").strip()
        return text if len(text) <= n else text[:n] + "..."

    def _req(self, url: str, method: str = "GET",
             headers: Optional[Dict] = None, data=None,
             json_data: Optional[Dict] = None) -> Dict:
        """Wrapper for HTTP requests with safe-mode guard."""
        if self.safe_mode and method in ("DELETE", "PUT", "PATCH") and \
                not self.options.get("allow_destructive", False):
            # In safe mode we still allow read-only inspection of these methods
            # but we send an empty body to minimise impact.
            if data is None and json_data is None:
                pass
        try:
            return self.client.request(url, method=method, headers=headers,
                                       data=data, json_data=json_data)
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "",
                    "url": url, "elapsed": 0, "error": str(e)}

    # ============================================================
    #                       MAIN SCAN
    # ============================================================

    def scan(self, target: str) -> Dict:
        """نقطة الدخول الرئيسية - تشغّل كل الفحوصات"""
        if not target:
            self._log("Target URL فارغ", "error")
            return {"target": target, "findings": [], "endpoints": [],
                    "spec_endpoints": []}

        # normalize target
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        target = target.rstrip("/") + "/"

        self._log(f"بدء فحص أمان REST API: {target}", "phase")

        parsed = urlparse(target)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.target = target

        # ---------- Phase 1: Discovery ----------
        self._log("Phase 1: اكتشاف API endpoints", "phase")
        self._discover_api_endpoints(target)
        self._detect_swagger(self.base)
        self._detect_graphql(self.base)

        # ---------- Phase 2: Auth & Authz ----------
        self._log(f"Phase 2: Authentication & Authorization "
                  f"({len(self.endpoints)} endpoints)", "phase")
        self._test_auth_bypass()
        self._test_idor()
        self._test_api_key_brute()

        # ---------- Phase 3: API abuse ----------
        self._log("Phase 3: API abuse tests", "phase")
        self._test_rate_limiting()
        self._test_api_versioning()
        self._test_mass_assignment()
        self._test_http_method_tampering()
        self._test_parameter_pollution()
        self._test_response_tampering()

        # ---------- Phase 4: Configuration ----------
        self._log("Phase 4: Configuration & CORS", "phase")
        self._test_cors(self.base + "/api")
        if self.endpoints:
            # also test CORS on a discovered endpoint
            self._test_cors(next(iter(self.endpoints)))

        self._print_results()
        return self._build_report()

    # ============================================================
    #                  PHASE 1 — DISCOVERY
    # ============================================================

    def _discover_api_endpoints(self, url: str):
        """اكتشاف API endpoints عبر HTML + JS analysis"""
        self._log(f"  › تحليل الصفحة الرئيسية: {url}", "info")
        resp = self._req(url)
        if resp["status"] == 0 or not resp["body"]:
            self._log(f"  ✗ تعذّر الوصول للهدف: {resp.get('error')}", "warn")
            # Try direct probe of common paths
            self._probe_common_paths(self.base)
            return

        body = resp["body"]
        self._extract_endpoints_from_text(body, url)

        # Pull JS files referenced in the HTML and scan them
        js_files = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            body, re.IGNORECASE)
        js_files = js_files[:15]  # cap to keep it fast
        for js in js_files:
            js_url = urljoin(url, js)
            js_resp = self._req(js_url)
            if js_resp["status"] == 200 and js_resp["body"]:
                self._extract_endpoints_from_text(js_resp["body"], js_url)
                self._detect_secrets_in_text(js_resp["body"], js_url)

        # Also probe common API paths directly
        self._probe_common_paths(self.base)

        self._log(f"  ✓ إجمالي الـ endpoints المكتشفة: "
                  f"{len(self.endpoints)}", "success")

    def _extract_endpoints_from_text(self, text: str, source: str):
        """استخراج API endpoints من نص (HTML/JS)"""
        if not text:
            return
        patterns = [
            r'''["']((?:https?:)?[^"']*/api/[^"']+)["']''',
            r'''["'](/api/[^"']+)["']''',
            r'''["'](/rest/[^"']+)["']''',
            r'''["'](/graphql[^"']*)["']''',
            r'''(?:fetch|axios|ajax|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["'`]([^"'`]+)["'`]''',
            r'''(?:url|endpoint|uri|path|route)\s*[:=]\s*["'`]([^"'`]+)["'`]''',
        ]
        for pat in patterns:
            for match in re.findall(pat, text):
                if not match or match.startswith(("data:", "javascript:",
                                                  "mailto:", "tel:", "#")):
                    continue
                # Only keep things that look like API routes
                if "/api/" in match or "/rest/" in match or "/graphql" in match \
                        or match.startswith("/v") or match.startswith("/graphql"):
                    full = urljoin(source, match)
                    # strip fragment and excessive query
                    full = full.split("#")[0]
                    self._register_endpoint(full, source)

    def _register_endpoint(self, url: str, source: str = ""):
        """تسجيل endpoint مكتشف (مع dedupe)"""
        # normalise trailing slash but keep root paths
        norm = url.rstrip("/") if not url.endswith("/api") else url
        if norm in self.endpoints:
            return
        if len(self.endpoints) >= self.max_endpoints:
            return
        self.endpoints.add(norm)
        if self.verbose:
            self._log(f"    + endpoint: {norm}  (from {source})", "info")

    def _probe_common_paths(self, base: str):
        """تجربة المسارات الشائعة لاكتشاف API"""
        self._log("  › تجربة المسارات الشائعة...", "info")
        for path in API_PATHS:
            url = base + path
            resp = self._req(url)
            if resp["status"] == 0:
                continue
            # 200 / 401 / 403 indicate an API exists; 404 means absent
            if resp["status"] in (200, 201, 401, 403):
                self._register_endpoint(url, "probe")
                if resp["status"] in (401, 403):
                    # Good candidate for auth tests
                    self._auth_targets = getattr(self, "_auth_targets", set())
                    self._auth_targets.add(url)
            # Some APIs respond with 405 (method not allowed) when GET
            # is unsupported but the endpoint exists
            elif resp["status"] == 405:
                self._register_endpoint(url, "probe-405")

    # ---------------- Swagger / OpenAPI ----------------

    def _detect_swagger(self, base: str):
        """كشف ملفات Swagger/OpenAPI المكشوفة"""
        self._log("  › البحث عن Swagger/OpenAPI specs...", "info")
        for path in SWAGGER_PATHS:
            url = base + path
            resp = self._req(url)
            if resp["status"] != 200 or not resp["body"]:
                continue
            body = resp["body"]
            is_json = self._looks_like_json(body)
            is_yaml = ('openapi:' in body[:200] or 'swagger:' in body[:200])
            if not (is_json or is_yaml or 'swagger' in body.lower()[:500]
                    or 'openapi' in body.lower()[:500]):
                continue

            # Parse to count endpoints
            endpoints_count = 0
            parsed = self._safe_json(body) if is_json else None
            if parsed and isinstance(parsed, dict):
                paths = parsed.get("paths", {})
                if isinstance(paths, dict):
                    endpoints_count = len(paths)
                    for p in paths.keys():
                        self._register_endpoint(base + p, "swagger")
                # Check for security schemes exposed
                schemes = parsed.get("securitySchemes") or \
                    parsed.get("components", {}).get("securitySchemes", {})
                if schemes:
                    self._add_finding(
                        "swagger_security_scheme_exposure", "low", url,
                        "Swagger spec exposes auth schemes",
                        "OpenAPI spec exposes security scheme definitions "
                        "which can aid attackers in crafting authenticated "
                        "requests.",
                        f"schemes={list(schemes.keys())[:5]}",
                        spec_endpoints=endpoints_count,
                    )
                # Check for sensitive info in info/description
                info = parsed.get("info", {})
                desc = info.get("description", "") if isinstance(info, dict) else ""
                if any(s in desc.lower() for s in ("token", "key", "password",
                                                   "internal", "staging")):
                    self._add_finding(
                        "swagger_sensitive_info", "medium", url,
                        "Swagger spec contains sensitive info in description",
                        "The OpenAPI description appears to reference "
                        "sensitive tokens, keys or environment names.",
                        self._short(desc, 200),
                    )

            self._add_finding(
                "swagger_spec_exposed", "medium", url,
                "Swagger / OpenAPI specification exposed",
                "The API documentation (Swagger/OpenAPI) is publicly "
                "accessible without authentication. Attackers can use it to "
                "map every endpoint, parameter and expected response.",
                f"path={path} status=200 endpoints_found={endpoints_count} "
                f"format={'json' if is_json else 'yaml'}",
                spec_endpoints=endpoints_count,
            )
            self.spec_endpoints.append({
                "url": url,
                "endpoints": endpoints_count,
                "format": "json" if is_json else "yaml",
            })

    # ---------------- GraphQL ----------------

    def _detect_graphql(self, base: str):
        """كشف GraphQL endpoints"""
        self._log("  › البحث عن GraphQL endpoints...", "info")
        for path in GRAPHQL_PATHS:
            url = base + path
            # 1) Try introspection query
            introspection = {
                "query": (
                    "{__schema{types{name fields{name}}}"
                    " __typename}"
                )
            }
            resp = self._req(url, method="POST", json_data=introspection,
                             headers={"Content-Type": "application/json"})
            if resp["status"] == 0 or not resp["body"]:
                continue

            body = resp["body"].lower()
            is_gql = ("__schema" in body or "__typename" in body
                      or "graphql" in body or "data" in body and
                      "errors" in body)

            if resp["status"] in (200, 201) and is_gql:
                # Check if introspection actually worked
                if "__schema" in body and "types" in body:
                    self._add_finding(
                        "graphql_introspection_enabled", "high", url,
                        "GraphQL introspection enabled",
                        "The GraphQL endpoint allows introspection queries, "
                        "exposing the entire schema (types, fields, "
                        "mutations) to unauthenticated users.",
                        f"POST {url} -> 200, response contains __schema",
                    )
                else:
                    self._add_finding(
                        "graphql_endpoint_exposed", "medium", url,
                        "GraphQL endpoint exposed",
                        "A GraphQL endpoint is reachable. Even without "
                        "introspection, attackers can fuzz queries, "
                        "mutations and attempt batching/DoS attacks.",
                        f"POST {url} -> {resp['status']}, "
                        f"body={self._short(body, 100)}",
                    )

                # Suggest field suggestion leak
                if "did you mean" in body:
                    self._add_finding(
                        "graphql_suggestion_leak", "low", url,
                        "GraphQL field suggestion leak",
                        "The GraphQL server leaks field name suggestions "
                        "on errors, helping attackers guess valid fields.",
                        self._short(body, 200),
                    )

                # Check for GraphiQL / playground UI
                ui_resp = self._req(url, headers={"Accept": "text/html"})
                if ui_resp["status"] == 200 and (
                        "graphiql" in ui_resp["body"].lower()
                        or "playground" in ui_resp["body"].lower()):
                    self._add_finding(
                        "graphql_ui_exposed", "medium", url,
                        "GraphQL interactive UI exposed",
                        "A GraphQL IDE (GraphiQL/Playground) is publicly "
                        "accessible, simplifying exploration and exploitation.",
                        f"GET {url} -> 200 (HTML UI)",
                    )

    def _detect_secrets_in_text(self, text: str, source: str):
        """كشف مفاتيح/أسرار مكشوفة في JS للاستخدام في brute-force لاحقاً"""
        patterns = {
            "api_key": r'''(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']''',
            "bearer": r'''Bearer\s+([A-Za-z0-9\-._~+\/]+=*)''',
            "jwt": r'''(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)''',
        }
        for name, pat in patterns.items():
            for match in re.findall(pat, text):
                self._add_finding(
                    "api_secret_exposed_in_js", "high", source,
                    f"Sensitive {name} exposed in client-side JS",
                    "A hardcoded secret was found in JavaScript. Anyone "
                    "viewing the page can extract and abuse it.",
                    f"{name}={match[:40]}{'...' if len(match) > 40 else ''}",
                )

    # ============================================================
    #              PHASE 2 — AUTH & AUTHORIZATION
    # ============================================================

    def _test_auth_bypass(self):
        """فحص Authentication Bypass على endpoints المكتشفة"""
        self._log("  › فحص Authentication Bypass...", "info")
        auth_targets = list(getattr(self, "_auth_targets", set()))
        if not auth_targets:
            # use any endpoint that returned 401/403 in discovery
            for ep in list(self.endpoints)[:self.max_endpoints]:
                resp = self._req(ep)
                if resp["status"] in (401, 403):
                    auth_targets.append(ep)

        for url in auth_targets[:20]:
            # 1) Try with a fake/empty Authorization header
            for hdr_val in ["Bearer ", "Bearer null", "Bearer undefined",
                            "Bearer {}", "Bearer []", "Bearer admin",
                            "Basic YWRtaW46",  # admin:
                            ]:
                resp = self._req(url, headers={"Authorization": hdr_val})
                if self._is_auth_bypass(resp, url):
                    self._add_finding(
                        "auth_bypass", "critical", url,
                        "Authentication bypass via crafted Authorization header",
                        "An endpoint that initially returned 401/403 now "
                        "returns data when supplied with a malformed or "
                        "placeholder Authorization header.",
                        f"Authorization: {hdr_val} -> "
                        f"status={resp['status']}, "
                        f"len={len(resp['body'])}",
                    )
                    break

            # 2) Try with common API key headers + dummy values
            for hdr in API_KEY_HEADERS:
                resp = self._req(url, headers={hdr: "test"})
                if self._is_auth_bypass(resp, url):
                    self._add_finding(
                        "auth_bypass_apikey", "critical", url,
                        f"Auth bypass via {hdr} header",
                        "The endpoint accepted a dummy API key value and "
                        "returned data without proper authentication.",
                        f"{hdr}: test -> status={resp['status']}, "
                        f"len={len(resp['body'])}",
                    )
                    break

            # 3) Try with path traversal in auth context
            for payload in ["../../../", "..%2f..%2f", "/admin", "/../"]:
                test_url = url.rstrip("/") + payload
                resp = self._req(test_url)
                if resp["status"] == 200 and len(resp["body"]) > 50:
                    self._add_finding(
                        "auth_bypass_path_traversal", "high", test_url,
                        "Possible auth bypass via path traversal",
                        "Appending path traversal segments to a protected "
                        "endpoint returned a 200 with content.",
                        f"GET {test_url} -> status={resp['status']}, "
                        f"len={len(resp['body'])}",
                    )

    def _is_auth_bypass(self, resp: Dict, url: str) -> bool:
        """تحديد إذا كانت الاستجابة تعتبر bypass ناجح"""
        if resp["status"] not in (200, 201):
            return False
        body = resp["body"] or ""
        # Avoid false positives: error pages often return 200 with HTML
        if "<html" in body.lower()[:200]:
            return False
        if "error" in body.lower()[:50] and "unauthor" in body.lower():
            return False
        if len(body) < 5:
            return False
        return True

    def _test_idor(self):
        """فحص IDOR على endpoints المكتشفة"""
        self._log("  › فحص IDOR على API endpoints...", "info")
        # Build candidate URLs from endpoints that have a numeric-looking
        # path segment
        candidates = []
        id_re = re.compile(r"/(\d+)(?:/|$|\?)")
        for ep in self.endpoints:
            for m in id_re.finditer(ep):
                candidates.append((ep, m.start(1), m.end(1) - 1, m.group(1)))

        # Also try adding ?id= to endpoints that look like collections
        for ep in list(self.endpoints)[:10]:
            if ep.endswith(("users", "user", "orders", "items", "files",
                            "accounts", "docs", "profiles")):
                for param in IDOR_PARAMS:
                    candidates.append((ep + "?" + param + "=1",
                                       len(ep) + len(param) + 2,
                                       len(ep) + len(param) + 3, "1"))

        tested = 0
        for url, s, e, orig_id in candidates[:25]:
            tested += 1
            # Baseline: fetch with original id
            base_resp = self._req(url)
            if base_resp["status"] != 200:
                continue
            base_hash = hashlib.md5(
                (base_resp["body"] or "").encode("utf-8", "ignore")).hexdigest()
            base_len = len(base_resp["body"] or "")

            # Try other IDs
            for new_id in ["0", "1", "2", "999", "1000", "-1",
                           orig_id + "1" if orig_id.isdigit() else "2"]:
                if new_id == orig_id:
                    continue
                test_url = url[:s] + new_id + url[e:]
                resp = self._req(test_url)
                if resp["status"] != 200 or not resp["body"]:
                    continue
                resp_hash = hashlib.md5(
                    resp["body"].encode("utf-8", "ignore")).hexdigest()
                # Different content + reasonable size = potential IDOR
                if resp_hash != base_hash and \
                        abs(len(resp["body"]) - base_len) > 20:
                    # Sanity: must not be an obvious error page
                    if "<html" in resp["body"][:200].lower():
                        continue
                    self._add_finding(
                        "idor", "high", test_url,
                        "Potential IDOR (Insecure Direct Object Reference)",
                        "Changing the object identifier in the URL returns "
                        "different data without proper authorization checks. "
                        "An attacker can enumerate IDs to access other "
                        "users' resources.",
                        f"original_id={orig_id} -> tried={new_id}; "
                        f"len changed {base_len} -> "
                        f"{len(resp['body'])}",
                        original_url=url,
                    )
                    break

        self._log(f"  ✓ تم اختبار {tested} IDOR candidates", "info")

    def _test_api_key_brute(self):
        """فحص API key brute-force على endpoint محمي"""
        self._log("  › فحص API Key brute force...", "info")
        # Find a 401/403 endpoint to test
        target_url = None
        auth_targets = getattr(self, "_auth_targets", set())
        if auth_targets:
            target_url = next(iter(auth_targets))
        else:
            for ep in self.endpoints:
                resp = self._req(ep)
                if resp["status"] in (401, 403):
                    target_url = ep
                    break

        if not target_url:
            self._log("  • لا يوجد endpoint محمي لاختبار brute force", "info")
            return

        # Try each common key against each header
        attempts = 0
        accepted_key = None
        accepted_header = None
        for hdr in API_KEY_HEADERS[:5]:  # limit headers
            for key in COMMON_API_KEYS[:self.api_key_limit]:
                attempts += 1
                resp = self._req(target_url, headers={hdr: key})
                if self._is_auth_bypass(resp, target_url):
                    accepted_key = key
                    accepted_header = hdr
                    self._add_finding(
                        "weak_api_key", "critical", target_url,
                        "Weak/guessable API key accepted",
                        "A common/dictionary API key value was accepted "
                        "by the server, granting access to a protected "
                        "endpoint.",
                        f"header={hdr} value='{key}' -> "
                        f"status={resp['status']}, "
                        f"len={len(resp['body'])}",
                        attempts=attempts,
                    )
                    break
            if accepted_key:
                break

        if not accepted_key:
            self._log(f"  ✓ لم يتم قبول أي مفتاح ضعيف "
                      f"({attempts} attempts)", "success")

    # ============================================================
    #              PHASE 3 — API ABUSE
    # ============================================================

    def _test_rate_limiting(self):
        """فحص Rate Limiting على API endpoints"""
        self._log("  › فحص Rate Limiting...", "info")
        if not self.endpoints:
            return
        target = next(iter(self.endpoints))
        statuses = []
        start = time.time()
        for i in range(self.rate_limit_requests):
            resp = self._req(target)
            statuses.append(resp["status"])
            # tiny delay to be a polite tester
            if self.client.delay <= 0:
                time.sleep(0.05)
        elapsed = time.time() - start

        # If all requests succeeded (200-range) and none returned 429
        # then no rate limiting is enforced within our window
        success_count = sum(1 for s in statuses if 200 <= s < 400)
        rate_limited = sum(1 for s in statuses if s == 429)

        if rate_limited == 0 and success_count >= self.rate_limit_requests * 0.8:
            self._add_finding(
                "missing_rate_limit", "medium", target,
                "No API rate limiting detected",
                f"Sent {self.rate_limit_requests} requests in "
                f"{elapsed:.1f}s without receiving HTTP 429. The API "
                "appears to lack rate limiting, making it vulnerable to "
                "brute-force, scraping and DoS.",
                f"requests={self.rate_limit_requests} "
                f"success={success_count} "
                f"429={rate_limited} elapsed={elapsed:.2f}s",
            )
        elif rate_limited > 0:
            self._log(f"  ✓ Rate limiting مفعّل (got {rate_limited}x 429)",
                      "success")

    def _test_api_versioning(self):
        """فحص API versioning vulnerabilities"""
        self._log("  › فحص API versioning...", "info")
        base = self.base
        # First find which version(s) are live
        live_versions = []
        for v in API_VERSIONS[:6]:
            url = f"{base}/api/{v}/"
            resp = self._req(url)
            if resp["status"] in (200, 401, 403):
                live_versions.append((v, url, resp["status"]))

        if len(live_versions) <= 1:
            self._log("  • لم يتم العثور على عدة إصدارات API", "info")
            return

        # Compare: does an older version leak data that the newer one protects?
        # Sample endpoints per version
        sample_paths = ["users", "user", "me", "profile", "admin"]
        for v, vurl, vstatus in live_versions:
            for sp in sample_paths:
                url = vurl.rstrip("/") + "/" + sp
                resp = self._req(url)
                if resp["status"] != 200 or not resp["body"]:
                    continue
                # Check if sensitive fields are exposed
                body_lower = resp["body"].lower()
                leaked = [f for f in SENSITIVE_FIELDS if f in body_lower]
                if leaked:
                    self._add_finding(
                        "api_version_data_leak", "high", url,
                        f"API version /{v}/ leaks sensitive fields",
                        f"The /api/{v}/ version of the API exposes "
                        f"sensitive fields ({', '.join(leaked[:5])}). "
                        "Old API versions are often forgotten and "
                        "under-protected.",
                        f"version={v} path={sp} "
                        f"fields_leaked={leaked[:5]}",
                    )

        # Check if an old version is deprecated but still functional
        for v, vurl, vstatus in live_versions:
            # If multiple versions live, flag the older ones
            if v in ("v1", "v0", "v0.1", "v1.0", "beta", "alpha",
                     "legacy", "old"):
                self._add_finding(
                    "deprecated_api_version", "low", vurl,
                    f"Deprecated/old API version /{v}/ still reachable",
                    f"An older API version (/api/{v}/) is still "
                    "reachable and may not receive security patches.",
                    f"GET {vurl} -> {vstatus}",
                )

    def _test_mass_assignment(self):
        """فحص Mass Assignment على endpoints الـ POST/PUT/PATCH"""
        self._log("  › فحص Mass Assignment...", "info")
        # Find endpoints that look like user/profile update
        candidates = []
        for ep in self.endpoints:
            low = ep.lower()
            if any(k in low for k in ("user", "profile", "account",
                                       "update", "edit", "settings")):
                candidates.append(ep)

        if not candidates:
            candidates = list(self.endpoints)[:5]

        for url in candidates[:8]:
            # Try GET first to learn the schema
            get_resp = self._req(url)
            schema_keys = []
            if get_resp["status"] == 200:
                parsed = self._safe_json(get_resp["body"])
                if isinstance(parsed, dict):
                    schema_keys = list(parsed.keys())[:10]
                elif isinstance(parsed, list) and parsed:
                    if isinstance(parsed[0], dict):
                        schema_keys = list(parsed[0].keys())[:10]

            # Build a mass-assignment payload
            payload = {}
            for field, values in MASS_ASSIGNMENT_FIELDS.items():
                payload[field] = values[0]
                # also try the array/bool versions
                break  # one field per request to attribute the finding

            if not payload:
                continue

            for method in ("POST", "PUT", "PATCH"):
                resp = self._req(url, method=method, json_data=payload)
                if resp["status"] in (200, 201, 202):
                    # Check if the response reflects our injected field
                    body = resp["body"] or ""
                    for field in payload:
                        if field in body:
                            # And the value matches what we sent
                            sent_val = str(payload[field])
                            if sent_val in body:
                                self._add_finding(
                                    "mass_assignment", "high", url,
                                    "Mass assignment vulnerability",
                                    f"The server accepted the '{field}' "
                                    "parameter and reflected it in the "
                                    "response. Attackers can escalate "
                                    "privileges by injecting fields like "
                                    "role, isAdmin, etc.",
                                    f"method={method} field={field}="
                                    f"{sent_val} -> status="
                                    f"{resp['status']}, reflected=yes",
                                    schema_keys=schema_keys,
                                )
                                break
                elif resp["status"] == 400 and \
                        "unknown" not in (resp["body"] or "").lower():
                    # 400 with a generic error = also worth noting
                    pass

    def _test_http_method_tampering(self):
        """فحص HTTP Method Tampering على API endpoints"""
        self._log("  › فحص HTTP Method Tampering...", "info")
        for url in list(self.endpoints)[:12]:
            # First OPTIONS to see what methods are allowed
            opts = self._req(url, method="OPTIONS")
            allow_header = opts["headers"].get("Allow", "") or \
                opts["headers"].get("allow", "")

            for method in HTTP_METHODS:
                if method in ("OPTIONS",):
                    continue
                resp = self._req(url, method=method)
                # Skip if method returned 405 (properly rejected)
                if resp["status"] == 405:
                    continue
                # TRACE returning 200 with our headers reflected = XST hint
                if method == "TRACE" and resp["status"] == 200:
                    if "User-Agent" in (resp["body"] or "") or \
                            "ghostpwn" in (resp["body"] or ""):
                        self._add_finding(
                            "http_trace_enabled", "medium", url,
                            "HTTP TRACE method enabled (XST)",
                            "TRACE echoes back request data, enabling "
                            "Cross-Site Tracing (XST) attacks that can "
                            "steal HttpOnly cookies.",
                            f"TRACE {url} -> 200, body reflects request",
                        )
                        continue
                # A write method (PUT/DELETE) on a GET endpoint returning 200
                # without auth change is suspicious
                if method in ("PUT", "DELETE", "PATCH") and \
                        resp["status"] in (200, 201, 202, 204):
                    # Compare with GET status
                    get_resp = self._req(url, method="GET")
                    if get_resp["status"] in (200, 401, 403):
                        # If GET was protected (401/403) but PUT returned 200
                        if (get_resp["status"] in (401, 403)
                                and resp["status"] in (200, 201)):
                            self._add_finding(
                                "method_tampering_auth_bypass", "critical",
                                url,
                                f"HTTP method tampering bypasses auth "
                                f"({method})",
                                f"GET returned {get_resp['status']} "
                                f"(protected) but {method} returned "
                                f"{resp['status']} (success) on the same "
                                "endpoint, suggesting inconsistent auth "
                                "enforcement per HTTP method.",
                                f"GET={get_resp['status']} -> "
                                f"{method}={resp['status']}",
                                allow_header=allow_header,
                            )
                        elif self._looks_like_json(resp["body"]):
                            self._add_finding(
                                "unexpected_method_allowed", "low", url,
                                f"Unexpected {method} allowed on API endpoint",
                                f"The {method} method is accepted on an "
                                "endpoint that may not intend to support "
                                "it, potentially enabling data modification.",
                                f"{method} {url} -> {resp['status']}, "
                                f"len={len(resp['body'] or '')}",
                                allow_header=allow_header,
                            )

    def _test_parameter_pollution(self):
        """فحص HTTP Parameter Pollution (HPP)"""
        self._log("  › فحص HTTP Parameter Pollution...", "info")
        # Find endpoints with at least one query param
        candidates = []
        for ep in self.endpoints:
            if "?" in ep:
                candidates.append(ep)
        if not candidates:
            # Take the first few endpoints and inject a fake param
            for ep in list(self.endpoints)[:5]:
                candidates.append(ep + "?id=1")

        for url in candidates[:8]:
            # Extract the existing param name(s)
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if not qs:
                continue
            param_name = list(qs.keys())[0]
            base_url = parsed._replace(query=param_name + "=1").geturl()

            # Baseline
            base_resp = self._req(base_url)
            base_body = base_resp["body"] or ""
            base_len = len(base_body)

            # HPP: send the same param twice with different values
            hpp_url = parsed._replace(
                query=f"{param_name}=1&{param_name}=2").geturl()
            hpp_resp = self._req(hpp_url)
            hpp_body = hpp_resp["body"] or ""

            if hpp_resp["status"] == base_resp["status"] and \
                    abs(len(hpp_body) - base_len) > 50 and \
                    "<html" not in hpp_body[:200].lower():
                # Check which value the server used (1 or 2)
                used = "1" if "1" in hpp_body and "2" not in hpp_body else \
                       "2" if "2" in hpp_body and "1" not in hpp_body else "?"
                self._add_finding(
                    "hpp_parameter_pollution", "medium", hpp_url,
                    "HTTP Parameter Pollution (HPP) behavior observed",
                    f"Sending duplicate '{param_name}' parameters changes "
                    "the response, indicating the server processes "
                    "duplicate parameters in a way that may bypass input "
                    "validation or WAF rules.",
                    f"param={param_name} values=[1,2] server_used="
                    f"{used} len_change="
                    f"{base_len}->{len(hpp_body)}",
                )

            # Try HPP that could bypass a security check
            # e.g. ?role=user&role=admin
            sec_hpp_url = parsed._replace(
                query=f"{param_name}=1&role=user&role=admin").geturl()
            sec_resp = self._req(sec_hpp_url)
            if sec_resp["status"] == 200 and \
                    "admin" in (sec_resp["body"] or "").lower() and \
                    "admin" not in base_body.lower():
                self._add_finding(
                    "hpp_security_bypass", "high", sec_hpp_url,
                    "HPP may bypass security checks (role)",
                    "Injecting a duplicate 'role' parameter caused the "
                    "response to reference 'admin', suggesting the server "
                    "uses the last value (or first) and that may bypass "
                    "authorization checks.",
                    f"baseline: no 'admin' in body; HPP: 'admin' present",
                )

    def _test_response_tampering(self):
        """كشف response tampering indicators و security header issues"""
        self._log("  › فحص Response Tampering & headers...", "info")
        if not self.endpoints:
            return
        target = next(iter(self.endpoints))
        resp = self._req(target)
        headers = resp.get("headers", {})
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for missing security headers
        missing = []
        for h in ["X-Content-Type-Options", "X-Frame-Options",
                  "Strict-Transport-Security", "Content-Security-Policy"]:
            if h.lower() not in headers_lower:
                missing.append(h)
        if missing:
            self._add_finding(
                "missing_security_headers", "low", target,
                "API response missing security headers",
                "The API response is missing one or more security "
                "headers, making it more vulnerable to content-type "
                "sniffing, clickjacking and downgrade attacks.",
                f"missing={missing}",
            )

        # Check for cacheable sensitive responses
        cache_control = headers_lower.get("cache-control", "")
        ct = headers_lower.get("content-type", "")
        if ("no-store" not in cache_control and
                "no-cache" not in cache_control and
                "application/json" in ct and
                resp["status"] == 200):
            body_lower = (resp["body"] or "").lower()
            if any(s in body_lower for s in SENSITIVE_FIELDS):
                self._add_finding(
                    "cacheable_sensitive_response", "medium", target,
                    "Sensitive API response is cacheable",
                    "The API returns sensitive data (tokens/PII) but does "
                    "not set Cache-Control: no-store, allowing "
                    "intermediate proxies/browsers to cache it.",
                    f"cache-control='{cache_control}' content-type="
                    f"'{ct}' status={resp['status']}",
                )

        # Check for verbose error messages
        if resp["status"] >= 400 and resp["body"]:
            body = resp["body"]
            error_signatures = [
                ("stack trace", r"Traceback \(most recent call last\)"),
                ("file path", r"(?:/home/|/var/|/usr/|C:\\)[^\s\"']+"),
                ("SQL error", r"(?:SQL syntax|mysql_fetch|ORA-\d+)"),
                ("debug info", r"(?:DEBUG\b|debug_mode|stack_trace)"),
            ]
            for name, pat in error_signatures:
                if re.search(pat, body, re.IGNORECASE):
                    self._add_finding(
                        "verbose_error_disclosure", "medium", target,
                        f"Verbose error disclosure ({name})",
                        f"The API returns detailed error information "
                        f"({name}) which leaks internal implementation "
                        "details useful for further attacks.",
                        self._short(body, 200),
                    )
                    break

        # Check for response that reflects our input (reflected XSS hint)
        test_url = target + ("&" if "?" in target else "?") + \
            "ghostpwn_test=reflectionprobe123"
        reflect_resp = self._req(test_url)
        if "reflectionprobe123" in (reflect_resp["body"] or ""):
            # Check if content-type is HTML-ish (real XSS risk)
            rct = reflect_resp["headers"].get("Content-Type", "") or \
                reflect_resp["headers"].get("content-type", "")
            if "html" in rct.lower():
                self._add_finding(
                    "api_reflected_xss", "high", test_url,
                    "Reflected input in API response (potential XSS)",
                    "The API reflects user-supplied input back in an "
                    "HTML context without apparent sanitisation, "
                    "enabling reflected XSS.",
                    f"param=ghostpwn_test value=reflectionprobe123 "
                    f"reflected=yes content-type={rct}",
                )
            else:
                self._add_finding(
                    "api_input_reflection", "low", test_url,
                    "Input reflected in API response",
                    "The API reflects user input verbatim. Combined with "
                    "a missing X-Content-Type-Options header, this could "
                    "be exploitable.",
                    f"reflected=yes content-type={rct}",
                )

    # ============================================================
    #              PHASE 4 — CONFIGURATION & CORS
    # ============================================================

    def _test_cors(self, url: str):
        """فحص CORS misconfiguration على API"""
        self._log(f"  › فحص CORS على {url}...", "info")

        # 1) Wildcard origin with credentials
        evil_origin = "https://evil.example.com"
        resp = self._req(url, headers={"Origin": evil_origin})
        acao = resp["headers"].get("Access-Control-Allow-Origin") or \
            resp["headers"].get("access-control-allow-origin", "")
        acac = resp["headers"].get("Access-Control-Allow-Credentials") or \
            resp["headers"].get("access-control-allow-credentials", "")

        if acao == "*" and acac.lower() == "true":
            self._add_finding(
                "cors_wildcard_with_credentials", "critical", url,
                "CORS wildcard origin with credentials (critical)",
                "The API returns 'Access-Control-Allow-Origin: *' together "
                "with 'Access-Control-Allow-Credentials: true'. Browsers "
                "block this combination, but a misconfigured reverse proxy "
                "or fix may still expose it; any reflection of origin with "
                "credentials is a serious flaw.",
                f"ACAO={acao} ACAC={acac} origin_tested={evil_origin}",
            )
        elif acao == evil_origin:
            # Origin reflection
            if acac.lower() == "true":
                self._add_finding(
                    "cors_origin_reflection_credentials", "critical", url,
                    "CORS reflects arbitrary Origin with credentials",
                    "The API reflects any Origin header back in "
                    "Access-Control-Allow-Origin and allows credentials. "
                    "Any malicious site can read authenticated API "
                    "responses cross-origin.",
                    f"ACAO={acao} ACAC={acac} origin={evil_origin}",
                )
            else:
                self._add_finding(
                    "cors_origin_reflection", "medium", url,
                    "CORS reflects arbitrary Origin",
                    "The API reflects any Origin in the "
                    "Access-Control-Allow-Origin header. Without "
                    "credentials this is lower risk, but combined with "
                    "other flaws it can enable data theft.",
                    f"ACAO={acao} origin={evil_origin}",
                )

        # 2) Check null origin
        null_resp = self._req(url, headers={"Origin": "null"})
        null_acao = null_resp["headers"].get(
            "Access-Control-Allow-Origin") or \
            null_resp["headers"].get("access-control-allow-origin", "")
        if null_acao == "null":
            self._add_finding(
                "cors_null_origin", "medium", url,
                "CORS allows 'null' origin",
                "The API allows 'null' as a valid origin. Sandboxed "
                "iframes and local files send Origin: null, so attackers "
                "can use them to make authenticated cross-origin reads.",
                f"ACAO={null_acao} origin=null",
            )

        # 3) Check preflight handling
        preflight = self._req(url, method="OPTIONS", headers={
            "Origin": evil_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        })
        if preflight["status"] in (200, 204):
            p_acao = preflight["headers"].get(
                "Access-Control-Allow-Origin") or \
                preflight["headers"].get(
                    "access-control-allow-origin", "")
            p_acam = preflight["headers"].get(
                "Access-Control-Allow-Methods") or \
                preflight["headers"].get(
                    "access-control-allow-methods", "")
            if p_acao == evil_origin and "POST" in p_acam.upper():
                self._add_finding(
                    "cors_preflight_origin_reflection", "medium", url,
                    "CORS preflight reflects arbitrary Origin",
                    "The OPTIONS preflight handler reflects any Origin "
                    "and allows POST, enabling cross-origin writes from "
                    "malicious sites.",
                    f"preflight ACAO={p_acao} ACAM={p_acam}",
                )

    # ============================================================
    #                       REPORTING
    # ============================================================

    def _build_report(self) -> Dict:
        return {
            "target": self.target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "endpoints_discovered": sorted(self.endpoints),
            "swagger_specs": self.spec_endpoints,
            "findings": self.findings,
            "stats": {
                "total_endpoints": len(self.endpoints),
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings
                                if f["severity"] == "critical"),
                "high": sum(1 for f in self.findings
                            if f["severity"] == "high"),
                "medium": sum(1 for f in self.findings
                              if f["severity"] == "medium"),
                "low": sum(1 for f in self.findings
                           if f["severity"] == "low"),
            },
        }

    def _print_results(self):
        """عرض نتائج الفحص"""
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🌐 تقرير فحص أمان REST API{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")

        # Endpoints
        if self.endpoints:
            print(f"\n  {Colors.BOLD}Endpoints المكتشفة "
                  f"({len(self.endpoints)}):{Colors.NC}")
            for ep in sorted(self.endpoints)[:15]:
                print(f"    {Colors.GREEN}•{Colors.NC} {ep[:70]}")
            if len(self.endpoints) > 15:
                print(f"    {Colors.GRAY}... و {len(self.endpoints)-15} "
                      f"آخرين{Colors.NC}")

        # Swagger specs
        if self.spec_endpoints:
            print(f"\n  {Colors.BOLD}Swagger/OpenAPI specs:"
                  f"{Colors.NC}")
            for s in self.spec_endpoints:
                print(f"    {Colors.CYAN}📄{Colors.NC} {s['url']} "
                      f"({s['endpoints']} endpoints, {s['format']})")

        # Findings
        if self.findings:
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_f = sorted(self.findings,
                              key=lambda x: sev_order.get(x["severity"], 99))
            sev_color = {
                "critical": Colors.RED + Colors.BOLD,
                "high": Colors.RED,
                "medium": Colors.YELLOW,
                "low": Colors.GRAY,
            }
            print(f"\n  {Colors.RED + Colors.BOLD}🚨 Findings "
                  f"({len(self.findings)}):{Colors.NC}")
            for f in sorted_f:
                c = sev_color.get(f["severity"], Colors.NC)
                print(f"\n    {c}[{f['severity'].upper()}]{Colors.NC} "
                      f"{f['title']}")
                print(f"      {Colors.GRAY}type:{Colors.NC} {f['type']}")
                print(f"      {Colors.GRAY}url:{Colors.NC} {f['url'][:80]}")
                print(f"      {fix_display(f['description'])}")
                print(f"      {Colors.GRAY}evidence:{Colors.NC} "
                      f"{self._short(f['evidence'], 120)}")
        else:
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات واضحة مكتشفة{Colors.NC}")

        # Stats
        report = self._build_report()
        stats = report["stats"]
        print(f"\n  {Colors.BOLD}📊 الإحصائيات:{Colors.NC}")
        print(f"    Endpoints: {stats['total_endpoints']}")
        print(f"    Findings: {stats['total_findings']} "
              f"({Colors.RED}C:{stats['critical']} "
              f"H:{stats['high']} "
              f"{Colors.YELLOW}M:{stats['medium']} "
              f"{Colors.GRAY}L:{stats['low']}{Colors.NC})")
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")


# ============================ CLI ============================

def _build_demo_client(args) -> HttpClient:
    return HttpClient(
        timeout=args.timeout,
        user_agent=args.user_agent or "ghostpwn-api/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=not args.no_redirects,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="api_security",
        description="ghostpwn - REST API Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 api_security.py https://example.com\n"
            "  python3 api_security.py https://example.com --verbose\n"
            "  python3 api_security.py https://example.com "
            "--cookie 'session=abc' --delay 0.2\n"
            "  python3 api_security.py https://example.com "
            "--json-out report.json\n"
        ),
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=12,
                        help="HTTP request timeout in seconds (default 12)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests in seconds (default 0.1)")
    parser.add_argument("--user-agent", default=None,
                        help="Custom User-Agent string")
    parser.add_argument("--proxy", default=None,
                        help="HTTP(S) proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookie", default=None,
                        help="Cookie string to use for authenticated tests")
    parser.add_argument("--no-redirects", action="store_true",
                        help="Disable HTTP redirect following")
    parser.add_argument("--max-endpoints", type=int, default=30,
                        help="Maximum number of endpoints to discover")
    parser.add_argument("--rate-limit-requests", type=int, default=25,
                        help="Number of requests for rate-limit test")
    parser.add_argument("--api-key-limit", type=int, default=30,
                        help="Max API keys to try in brute force")
    parser.add_argument("--allow-destructive", action="store_true",
                        help="Allow destructive methods (PUT/DELETE/PATCH) "
                             "with bodies")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["discovery", "auth", "abuse",
                                            "config", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_demo_client(args)
    scanner = APISecurityScanner(
        http_client=client,
        options={
            "max_endpoints": args.max_endpoints,
            "rate_limit_requests": args.rate_limit_requests,
            "api_key_limit": args.api_key_limit,
            "allow_destructive": args.allow_destructive,
            "verbose": args.verbose,
            "safe_mode": not args.allow_destructive,
        },
    )

    report = scanner.scan(args.url)

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            print(f"\n{Colors.GREEN}[+]{Colors.NC} تم حفظ التقرير في: "
                  f"{args.json_out}")
        except Exception as e:
            print(f"{Colors.RED}[-]{Colors.NC} فشل حفظ التقرير: {e}")

    # Exit code based on severity
    if report["stats"]["critical"] > 0:
        sys.exit(2)
    elif report["stats"]["high"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
