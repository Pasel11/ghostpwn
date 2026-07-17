#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - GraphQL Security Scanner
فاحص أمان GraphQL APIs

الميزات:
1.  اكتشاف GraphQL endpoints (16+ مسار)
2.  فحص Introspection query
3.  استغلال Field suggestions
4.  فحص Batch query attack (DoS)
5.  فحص Query depth limiting
6.  تحليل Query complexity
7.  فحص Mutation testing
8.  فحص Subscription testing
9.  فحص Authentication bypass على GraphQL
10. فحص Authorization على مستوى الحقول (field-level)
11. فحص Alias-based DoS
12. فحص GraphQL injection
13. استخراج __schema و __type
14. كشف الحقول الحساسة (password, email, token, secret)
15. فحص CSRF على GraphQL mutations
16. فحص Persisted queries
"""
import os
import sys
import re
import json
import time
import hashlib
import urllib.parse
from typing import Dict, List, Optional, Set, Any, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# 16+ common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
    "/v1/graphql", "/v2/graphql", "/v3/graphql",
    "/query", "/api/query",
    "/graphiql", "/playground", "/api/playground",
    "/explorer", "/api/explorer",
    "/gql", "/api/gql",
    "/graphql.php", "/__graphql",
    "/public/graphql", "/private/graphql", "/internal/graphql",
    "/backend/graphql", "/graphql/console",
]

# Sensitive field name patterns (lowercase substrings to match)
SENSITIVE_FIELD_PATTERNS = [
    "password", "passwd", "pwd", "secret", "token", "apikey",
    "api_key", "apisecret", "api_secret", "privatekey", "private_key",
    "session", "cookie", "auth", "credential", "creditcard",
    "credit_card", "cardnumber", "card_number", "cvv", "ssn",
    "iban", "bic", "accountnumber", "account_number",
    "pin", "otp", "mfa", "totp", "backupcode", "backup_code",
    "private", "internal", "adminkey", "stripe", "paypal",
    "wallet", "balance", "salary", "taxid", "tax_id",
    "email", "phone", "mobile", "address",
    "dob", "birthdate", "birthday", "nationalid", "passport",
    "license", "cert",
]

# Field suggestion probes — intentionally misspelled versions of
# common sensitive fields. The GraphQL error often replies with
# "Did you mean 'password'?" leaking the real field name.
FIELD_SUGGESTION_PROBES = [
    "passwordd", "passwd", "passwords", "passwrd",
    "secretkey", "secrets", "secrett",
    "tokens", "tokenn", "accesstoken", "accesstokenn",
    "apikey", "apikeys", "api_keyy",
    "emaill", "emails", "emailaddress",
    "adminn", "admins", "administratorr",
    "rolee", "roless", "permissionss",
    "sessionid", "sessionkey", "sessionn",
    "privatekey", "private_keyy",
    "creditcard", "cardnumberr", "cvvv",
    "userid", "idd", "uuid",
]

# Common GraphQL root Query field names
COMMON_QUERY_FIELDS = [
    "user", "users", "me", "viewer", "currentUser", "account",
    "accounts", "profile", "profiles", "product", "products",
    "order", "orders", "item", "items", "post", "posts",
    "comment", "comments", "node", "nodes", "search",
    "admin", "adminUsers", "settings", "config",
    "organization", "organizations", "team", "teams",
    "project", "projects", "file", "files", "document", "documents",
]

# Common GraphQL Mutation root field names
COMMON_MUTATION_FIELDS = [
    "createUser", "updateUser", "deleteUser", "createAccount",
    "updateAccount", "deleteAccount", "login", "logout",
    "register", "signup", "signin", "resetPassword",
    "changePassword", "updateEmail", "verifyEmail",
    "createPost", "updatePost", "deletePost",
    "createOrder", "updateOrder", "cancelOrder",
    "adminCreateUser", "adminDeleteUser", "adminUpdateUser",
    "impersonateUser", "setRole", "grantPermission",
]

# Common Subscription root field names
COMMON_SUBSCRIPTION_FIELDS = [
    "messageAdded", "userJoined", "userLeft", "notification",
    "newMessage", "onUpdate", "postCreated", "commentAdded",
    "statusChanged", "userStatusChanged", "event", "events",
    "messageReceived", "itemUpdated", "dataChanged",
]

# Body markers strongly indicating a GraphQL endpoint
GRAPHQL_BODY_MARKERS = [
    "__schema", "__type", "data", "errors", "extensions",
    "locations", "path", "Did you mean", "persistedQuery",
    "IntrospectionError", "GraphQLError",
]

# Standard introspection query (full)
INTROSPECTION_QUERY = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}""".strip()

# Minimal introspection fallback (some servers reject the full query)
INTROSPECTION_MINIMAL = (
    "{ __schema { queryType { name } mutationType { name } "
    "subscriptionType { name } types { name kind } } }"
)

# Common type names to probe with __type when introspection is blocked
COMMON_TYPE_NAMES = [
    "User", "Account", "Admin", "Profile", "Session", "Token",
    "AuthPayload", "LoginPayload", "Order", "Product", "Post",
    "Comment", "Mutation", "Query", "Subscription",
    "UserConnection", "AccountConnection",
]


def _build_type_query(type_name: str) -> str:
    """Build a __type query for the given type name."""
    safe = type_name.replace('"', '\\"')
    return (
        '{ __type(name: "%s") { name kind description '
        "fields(includeDeprecated: true) { name description "
        "type { name kind ofType { name kind ofType { name kind } } } "
        "args { name } } inputFields { name } } }" % safe
    )


# ============================ Main Class ============================

class GraphQLSecurityScanner:
    """فاحص أمان GraphQL APIs - يكتشف ويختبر ثغرات GraphQL"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=15, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self.endpoints: Set[str] = set()
        self.schema: Optional[Dict] = None
        self.types: Dict[str, Dict] = {}
        self.query_root: str = "Query"
        self.mutation_root: Optional[str] = None
        self.subscription_root: Optional[str] = None
        self._scanned: Set[str] = set()
        # tunables
        self.max_endpoints = self.options.get("max_endpoints", 6)
        self.batch_size = self.options.get("batch_size", 50)
        self.alias_count = self.options.get("alias_count", 100)
        self.max_depth = self.options.get("max_depth", 20)
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[GQL] {msg}", level)

    def _add_finding(self, ftype: str, severity: str, url: str,
                     title: str, description: str, evidence: str,
                     **extra) -> Dict:
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
    def _safe_json(text: str) -> Optional[Any]:
        if not text:
            return None
        try:
            return json.loads(text)
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
        try:
            return self.client.request(url, method=method, headers=headers,
                                       data=data, json_data=json_data)
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "",
                    "url": url, "elapsed": 0, "error": str(e)}

    def _gql_post(self, url: str, query: Optional[str] = None,
                  variables: Optional[Dict] = None,
                  operation_name: Optional[str] = None,
                  extra_body: Optional[Dict] = None,
                  headers: Optional[Dict] = None,
                  use_get: bool = False,
                  raw_body: Optional[Any] = None) -> Dict:
        """Send a GraphQL request and return the HTTP response dict."""
        if raw_body is not None:
            body = raw_body
        else:
            body: Dict[str, Any] = {"query": query or ""}
            if variables:
                body["variables"] = variables
            if operation_name:
                body["operationName"] = operation_name
            if extra_body:
                body.update(extra_body)

        gql_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, application/graphql-response+json",
        }
        if headers:
            gql_headers.update(headers)

        if use_get:
            params = []
            if isinstance(body, dict):
                if "query" in body and body["query"]:
                    params.append("query=" + urllib.parse.quote(body["query"]))
                if "variables" in body:
                    params.append("variables=" + urllib.parse.quote(
                        json.dumps(body["variables"])))
                if "operationName" in body:
                    params.append("operationName=" + urllib.parse.quote(
                        str(body["operationName"])))
                if "extensions" in body:
                    params.append("extensions=" + urllib.parse.quote(
                        json.dumps(body["extensions"])))
            sep = "&" if "?" in url else "?"
            full_url = url + sep + "&".join(params)
            return self._req(full_url, method="GET", headers=gql_headers)
        return self._req(url, method="POST", headers=gql_headers,
                         json_data=body)

    @staticmethod
    def _is_graphql_response(resp: Dict) -> bool:
        """Heuristic: does this HTTP response look like GraphQL?"""
        if not resp:
            return False
        body = resp.get("body", "") or ""
        if not body:
            return False
        for marker in GRAPHQL_BODY_MARKERS:
            if marker in body:
                parsed = GraphQLSecurityScanner._safe_json(body)
                if isinstance(parsed, dict):
                    if any(k in parsed for k in ("data", "errors", "extensions")):
                        return True
                if marker in ("GraphQLError", "Did you mean", "persistedQuery"):
                    return True
        ctype = ""
        for h, v in (resp.get("headers") or {}).items():
            if h.lower() == "content-type":
                ctype = v.lower()
                break
        if "graphql" in ctype:
            return True
        return False

    @staticmethod
    def _is_graphql_ide(resp: Dict) -> bool:
        """Detect GraphiQL/Playground IDE HTML responses."""
        body = resp.get("body", "") or ""
        markers = ["GraphiQL", "graphiql", "GraphQL Playground",
                   "graphql-playground", "Apollo Explorer",
                   "<title>GraphiQL", "data-props", "graphql-explorer"]
        return any(m in body for m in markers) and resp.get("status") == 200

    @staticmethod
    def _unwrap_type(type_ref: Optional[Dict]) -> str:
        """Unwrap a GraphQL type reference (NON_NULL, LIST) to base type name."""
        if not type_ref:
            return ""
        seen = set()
        while type_ref.get("ofType") and id(type_ref) not in seen:
            seen.add(id(type_ref))
            type_ref = type_ref["ofType"]
        return type_ref.get("name", "") or ""

    # ============================================================
    #                       MAIN SCAN
    # ============================================================

    def scan(self, url: str) -> Dict:
        """نقطة الدخول الرئيسية - تشغّل كل الفحوصات"""
        if not url:
            self._log("Target URL فارغ", "error")
            return {"target": url, "findings": [], "endpoints": []}

        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.target = url.rstrip("/") + "/"

        self._log(f"بدء فحص أمان GraphQL: {self.target}", "phase")

        # ---------- Phase 1: Discovery ----------
        self._log("Phase 1: اكتشاف GraphQL endpoints", "phase")
        self._discover_endpoints()

        if not self.endpoints:
            self._log("لم يتم العثور على GraphQL endpoints", "warn")
            return self._build_report()

        # ---------- Phase 2: Schema & introspection ----------
        self._log(f"Phase 2: Introspection & schema "
                  f"({len(self.endpoints)} endpoints)", "phase")
        primary = sorted(self.endpoints)[0]
        self._test_introspection(primary)
        self._extract_schema_and_types(primary)
        self._test_field_suggestions(primary)
        self._detect_sensitive_fields(primary)

        # ---------- Phase 3: DoS & abuse ----------
        self._log("Phase 3: DoS & abuse tests", "phase")
        self._test_batch_queries(primary)
        self._test_query_depth(primary)
        self._test_query_complexity(primary)
        self._test_alias_dos(primary)

        # ---------- Phase 4: Auth & injection ----------
        self._log("Phase 4: Auth, authorization & injection", "phase")
        self._test_auth_bypass(primary)
        self._test_field_authorization(primary)
        self._test_injection(primary)
        self._test_mutations(primary)
        self._test_subscriptions(primary)
        self._test_csrf_mutations(primary)
        self._test_persisted_queries(primary)

        self._print_results()
        return self._build_report()

    # ============================================================
    #                  PHASE 1 — DISCOVERY
    # ============================================================

    def _discover_endpoints(self):
        """Probe common GraphQL endpoint paths."""
        probe_query = "{ __typename }"
        for path in GRAPHQL_PATHS:
            full_url = self.base + path
            if full_url in self._scanned:
                continue
            self._scanned.add(full_url)
            # Try POST with the probe query first
            resp = self._gql_post(full_url, probe_query)
            if self._is_graphql_response(resp):
                self.endpoints.add(full_url)
                self._log(f"  ✓ GraphQL endpoint: {full_url}", "success")
                self._add_finding(
                    "graphql_endpoint_exposed", "info", full_url,
                    "GraphQL endpoint discovered",
                    "A working GraphQL endpoint was discovered at this URL. "
                    "GraphQL APIs expose a single endpoint that accepts "
                    "arbitrary queries, making proper access control and "
                    "validation critical.",
                    f"status={resp['status']} path={path}",
                )
                if len(self.endpoints) >= self.max_endpoints:
                    break
                continue
            # Try GET as fallback (some servers only accept GET)
            resp_get = self._gql_post(full_url, probe_query, use_get=True)
            if self._is_graphql_response(resp_get):
                self.endpoints.add(full_url)
                self._log(f"  ✓ GraphQL endpoint (GET): {full_url}", "success")
                self._add_finding(
                    "graphql_endpoint_exposed", "info", full_url,
                    "GraphQL endpoint discovered (GET)",
                    "A working GraphQL endpoint was discovered at this URL "
                    "responding to GET requests. GraphQL-over-GET also "
                    "leaks queries in proxy/CDN logs.",
                    f"status={resp_get['status']} path={path}",
                )
                if len(self.endpoints) >= self.max_endpoints:
                    break
                continue
            # Check for IDE
            if self._is_graphql_ide(resp) or self._is_graphql_ide(resp_get):
                self.endpoints.add(full_url)
                self._log(f"  ✓ GraphQL IDE: {full_url}", "success")
                self._add_finding(
                    "graphql_ide_exposed", "medium", full_url,
                    "GraphQL IDE (GraphiQL/Playground) exposed",
                    "An interactive GraphQL IDE (GraphiQL, Playground, or "
                    "similar) is exposed to unauthenticated users. The IDE "
                    "lets attackers explore the schema, run arbitrary "
                    "queries, and quickly map the attack surface.",
                    f"path={path} status={resp.get('status') or resp_get.get('status')}",
                )
                if len(self.endpoints) >= self.max_endpoints:
                    break

        # Also scrape the homepage / common pages for graphql references
        self._scrape_graphql_from_html()

        self._log(f"  إجمالي GraphQL endpoints: {len(self.endpoints)}",
                  "info")

    def _scrape_graphql_from_html(self):
        """Scrape HTML and JS for graphql endpoint references."""
        resp = self._req(self.target)
        if resp["status"] == 0 or not resp["body"]:
            return
        body = resp["body"]
        patterns = [
            r'''["'`](/[^"'`]*graphql[^"'`]*)["'`]''',
            r'''["'`](/[^"'`]*gql[^"'`]*)["'`]''',
            r'''["'`](https?://[^"'`]*graphql[^"'`]*)["'`]''',
        ]
        for pat in patterns:
            for m in re.finditer(pat, body, re.IGNORECASE):
                ref = m.group(1)
                full = ref if ref.startswith("http") else self.base + ref
                if full in self.endpoints or full in self._scanned:
                    continue
                self._scanned.add(full)
                probe = self._gql_post(full, "{ __typename }")
                if self._is_graphql_response(probe):
                    self.endpoints.add(full)
                    self._log(f"  ✓ GraphQL (from HTML): {full}", "success")
                    self._add_finding(
                        "graphql_endpoint_exposed", "info", full,
                        "GraphQL endpoint discovered via HTML scraping",
                        "A GraphQL endpoint referenced in the page's "
                        "HTML/JS was discovered and is reachable.",
                        f"status={probe['status']} url={full}",
                    )
        # Scan referenced JS files
        js_files = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
        for js in js_files[:10]:
            js_url = urllib.parse.urljoin(self.target, js)
            js_resp = self._req(js_url)
            if js_resp["status"] != 200 or not js_resp["body"]:
                continue
            js_body = js_resp["body"]
            for pat in patterns:
                for m in re.finditer(pat, js_body, re.IGNORECASE):
                    ref = m.group(1)
                    full = ref if ref.startswith("http") else self.base + ref
                    if full in self.endpoints or full in self._scanned:
                        continue
                    self._scanned.add(full)
                    probe = self._gql_post(full, "{ __typename }")
                    if self._is_graphql_response(probe):
                        self.endpoints.add(full)
                        self._log(f"  ✓ GraphQL (from JS): {full}", "success")
                        self._add_finding(
                            "graphql_endpoint_exposed", "info", full,
                            "GraphQL endpoint discovered via JS scraping",
                            "A GraphQL endpoint referenced in a JavaScript "
                            "file was discovered and is reachable.",
                            f"status={probe['status']} url={full}",
                        )

    # ============================================================
    #              PHASE 2 — INTROSPECTION & SCHEMA
    # ============================================================

    def _test_introspection(self, url: str):
        """Test if GraphQL introspection is enabled."""
        self._log(f"  › فحص introspection على {url}...", "info")
        resp = self._gql_post(url, INTROSPECTION_QUERY,
                              operation_name="IntrospectionQuery")
        body = self._safe_json(resp["body"])
        if not body:
            return
        data = body.get("data") or {}
        schema = data.get("__schema")
        if schema and schema.get("types"):
            n_types = len(schema.get("types", []))
            self._add_finding(
                "graphql_introspection_enabled", "critical", url,
                "GraphQL introspection enabled",
                "The GraphQL endpoint allows full introspection queries. "
                "An attacker can dump the entire schema (types, fields, "
                "arguments, mutations) and use it to craft targeted "
                "attacks. Introspection should be disabled in production.",
                f"types_exposed={n_types} status={resp['status']}",
            )
            self.schema = schema
            return
        # Check errors for explicit "introspection disabled" message
        errors = body.get("errors") or []
        for e in errors:
            msg = str(e.get("message", "")).lower()
            if "introspection" in msg and ("disabled" in msg or "not allowed" in msg):
                self._log("  ✓ Introspection disabled", "success")
                return
        # Try minimal introspection
        resp_min = self._gql_post(url, INTROSPECTION_MINIMAL)
        body_min = self._safe_json(resp_min["body"]) or {}
        if (body_min.get("data") or {}).get("__schema"):
            self._add_finding(
                "graphql_introspection_enabled", "critical", url,
                "GraphQL introspection enabled (minimal query)",
                "The GraphQL endpoint allows introspection via a minimal "
                "__schema query. Full schema can be reconstructed.",
                f"status={resp_min['status']}",
            )
            self.schema = (body_min.get("data") or {}).get("__schema")

    def _extract_schema_and_types(self, url: str):
        """Extract types from introspection schema or probe __type directly."""
        if self.schema:
            self._log("  › استخراج الأنواع من الـ schema...", "info")
            for t in self.schema.get("types", []):
                name = t.get("name")
                if name:
                    self.types[name] = t
            qt = self.schema.get("queryType", {}).get("name")
            mt = self.schema.get("mutationType", {}).get("name")
            st = self.schema.get("subscriptionType", {}).get("name")
            if qt:
                self.query_root = qt
            self.mutation_root = mt
            self.subscription_root = st
            self._log(f"  ✓ تم استخراج {len(self.types)} نوع", "success")
            return
        # No schema — probe __type with common type names
        self._log("  › تجربة __type على أسماء أنواع شائعة...", "info")
        for tname in COMMON_TYPE_NAMES:
            q = _build_type_query(tname)
            resp = self._gql_post(url, q)
            body = self._safe_json(resp["body"]) or {}
            data = body.get("data") or {}
            t = data.get("__type")
            if t and t.get("name"):
                self.types[t["name"]] = t
                self._add_finding(
                    "graphql_type_extraction", "medium", url,
                    f"GraphQL type '{tname}' extracted via __type",
                    f"The __type query succeeded for type '{tname}' even "
                    "though full introspection appears disabled. Attackers "
                    "can enumerate types one by one to reconstruct the schema.",
                    f"type={tname} fields={len(t.get('fields') or [])}",
                )

    def _test_field_suggestions(self, url: str):
        """Exploit GraphQL field suggestion feature to leak field names."""
        self._log("  › فحص field suggestions...", "info")
        leaked: Dict[str, List[str]] = {}
        for probe in FIELD_SUGGESTION_PROBES:
            q = "{ " + probe + " }"
            resp = self._gql_post(url, q)
            body = self._safe_json(resp["body"]) or {}
            errors = body.get("errors") or []
            for e in errors:
                msg = e.get("message", "")
                # Match "Did you mean 'realName'?" (single or multiple)
                for m in re.finditer(
                        r"[Dd]id you mean ['\"]([^'\"]+)['\"]?", msg):
                    suggestion = m.group(1)
                    leaked.setdefault(probe, [])
                    if suggestion not in leaked[probe]:
                        leaked[probe].append(suggestion)
                # Also catch comma-separated: "Did you mean 'a' or 'b'?"
                for m in re.finditer(
                        r"'([^']+)'(?:\s+or\s+'([^']+)')?", msg):
                    for g in m.groups():
                        if g:
                            leaked.setdefault(probe, [])
                            if g not in leaked[probe]:
                                leaked[probe].append(g)
        if leaked:
            all_suggestions: Set[str] = set()
            for sug_list in leaked.values():
                all_suggestions.update(sug_list)
            sensitive_leaked = [
                s for s in all_suggestions
                if any(p in s.lower() for p in SENSITIVE_FIELD_PATTERNS)
            ]
            severity = "high" if sensitive_leaked else "medium"
            self._add_finding(
                "graphql_field_suggestion_leak", severity, url,
                "GraphQL field suggestions leak schema",
                "The GraphQL server responds to invalid field names with "
                "\"Did you mean 'X'?\" hints, leaking real field names. "
                "This allows attackers to reconstruct the schema even when "
                "introspection is disabled.",
                f"probes={len(leaked)} "
                f"leaked_fields={sorted(all_suggestions)[:30]}",
                leaked_fields=sorted(all_suggestions),
            )

    def _detect_sensitive_fields(self, url: str):
        """Walk the schema and flag sensitive fields."""
        if not self.types:
            return
        self._log("  › كشف الحقول الحساسة في الـ schema...", "info")
        sensitive_found: List[Dict] = []
        for type_name, type_def in self.types.items():
            if type_name.startswith("__"):
                continue
            kind = type_def.get("kind", "")
            if kind not in ("OBJECT", "INPUT_OBJECT"):
                continue
            fields = (type_def.get("fields")
                      or type_def.get("inputFields") or [])
            for field in fields:
                fname = (field.get("name") or "").lower()
                for pattern in SENSITIVE_FIELD_PATTERNS:
                    if pattern in fname:
                        sensitive_found.append({
                            "type": type_name,
                            "field": field.get("name"),
                            "pattern": pattern,
                        })
                        break
        if sensitive_found:
            sample = ", ".join(
                f"{s['type']}.{s['field']}" for s in sensitive_found[:10])
            self._add_finding(
                "graphql_sensitive_fields_in_schema", "high", url,
                f"Sensitive fields exposed in schema "
                f"({len(sensitive_found)} fields)",
                "The GraphQL schema exposes fields with sensitive names "
                "(password, token, secret, etc.). Even if these fields "
                "don't return data directly, their presence confirms the "
                "underlying data model and guides further attacks. Fields "
                "should be renamed or removed from the schema.",
                f"sample={sample}",
                sensitive_fields=sensitive_found,
            )

    # ============================================================
    #              PHASE 3 — DOS & ABUSE
    # ============================================================

    def _test_batch_queries(self, url: str):
        """Test if the server accepts batched queries (DoS amplifier)."""
        self._log(f"  › فحص batch queries (x{self.batch_size})...", "info")
        batch = [{"query": "{ __typename }"} for _ in range(self.batch_size)]
        resp = self._req(url, method="POST",
                         json_data=batch,
                         headers={"Content-Type": "application/json",
                                  "Accept": "application/json"})
        body = self._safe_json(resp["body"])
        if isinstance(body, list) and len(body) == self.batch_size:
            self._add_finding(
                "graphql_batch_queries_enabled", "high", url,
                "GraphQL batch queries enabled",
                f"The server accepted and processed a batch of "
                f"{self.batch_size} queries in a single HTTP request. "
                "Batching is a powerful DoS amplifier — an attacker can "
                "send thousands of queries per request, bypassing rate "
                "limits that count HTTP requests instead of GraphQL "
                "operations.",
                f"batch_size={self.batch_size} status={resp['status']} "
                f"elapsed={resp['elapsed']}s",
            )
        elif isinstance(body, list) and len(body) > 0:
            self._add_finding(
                "graphql_batch_queries_partial", "medium", url,
                "GraphQL batch queries partially processed",
                f"The server processed a batch query but returned "
                f"{len(body)} results instead of {self.batch_size}. Some "
                "batching may be enabled or partially limited.",
                f"sent={self.batch_size} received={len(body)}",
            )

    def _find_recursive_type(self) -> Optional[Tuple[str, str]]:
        """Find (type_name, field_name) where field type refers back to type."""
        for type_name, type_def in self.types.items():
            if type_def.get("kind") != "OBJECT":
                continue
            for field in type_def.get("fields") or []:
                base = self._unwrap_type(field.get("type"))
                if base == type_name:
                    return (type_name, field.get("name"))
        return None

    def _find_root_field_returning(self, target_type: str) -> Optional[str]:
        """Find a root Query field whose return type matches target_type."""
        root = self.types.get(self.query_root) or self.types.get("Query")
        if not root:
            return None
        for field in root.get("fields") or []:
            base = self._unwrap_type(field.get("type"))
            if base == target_type:
                return field.get("name")
        return None

    def _test_query_depth(self, url: str):
        """Test if query depth limiting is enforced."""
        self._log("  › فحص query depth limiting...", "info")
        recursive = self._find_recursive_type()
        tested_via_aliases = False
        for depth in [10, 15, 20, 30]:
            if recursive and depth <= self.max_depth:
                type_name, field_name = recursive
                root_field = self._find_root_field_returning(type_name)
                if root_field:
                    inner = "__typename"
                    for _ in range(depth):
                        inner = f"{field_name} {{ {inner} }}"
                    query = f"query {{ {root_field} {{ {inner} }} }}"
                else:
                    query = "{ " + " ".join(
                        f"a{i}: __typename" for i in range(depth)) + " }"
                    tested_via_aliases = True
            else:
                query = "{ " + " ".join(
                    f"a{i}: __typename" for i in range(depth)) + " }"
                tested_via_aliases = True
            resp = self._gql_post(url, query)
            body = self._safe_json(resp["body"]) or {}
            errors = body.get("errors") or []
            err_msg = " ".join(
                str(e.get("message", "")) for e in errors).lower()
            if "depth" in err_msg and ("limit" in err_msg
                                       or "maximum" in err_msg
                                       or "exceed" in err_msg
                                       or "max" in err_msg):
                self._log(f"  ✓ depth limit triggered at depth {depth}",
                          "success")
                return
            if "complexity" in err_msg:
                self._log(f"  ✓ complexity limit triggered at depth {depth}",
                          "success")
                return
            if depth >= 20 and "data" in body and not errors:
                self._add_finding(
                    "graphql_no_depth_limit", "high", url,
                    "GraphQL query depth not limited",
                    f"The server processed a query nested to depth {depth} "
                    "without error. Without depth limiting, attackers can "
                    "craft deeply nested queries (especially against "
                    "self-referential types) to exhaust CPU/memory (DoS).",
                    f"depth={depth} method="
                    f"{'aliases' if tested_via_aliases else 'recursive_type'} "
                    f"elapsed={resp['elapsed']}s",
                )
                return

    def _test_query_complexity(self, url: str):
        """Test if the server enforces query complexity limits."""
        self._log("  › فحص query complexity limits...", "info")
        aliases = " ".join(f"a{i}: __typename" for i in range(500))
        query = "{ " + aliases + " }"
        resp = self._gql_post(url, query)
        body = self._safe_json(resp["body"]) or {}
        errors = body.get("errors") or []
        err_msg = " ".join(str(e.get("message", "")) for e in errors).lower()
        if "complexity" in err_msg or "cost" in err_msg:
            self._log("  ✓ complexity limit triggered", "success")
            return
        if "data" in body and not errors:
            self._add_finding(
                "graphql_no_complexity_limit", "medium", url,
                "GraphQL query complexity not limited",
                "The server processed a query with 500 aliased fields "
                "without error. Without complexity/cost analysis, "
                "attackers can craft expensive queries to cause DoS.",
                f"aliases=500 status={resp['status']} "
                f"elapsed={resp['elapsed']}s",
            )

    def _test_alias_dos(self, url: str):
        """Test alias-based DoS — many aliases on the same field."""
        self._log(f"  › فحص alias DoS (x{self.alias_count})...", "info")
        aliases = " ".join(
            f"a{i}: __typename" for i in range(self.alias_count))
        query = "{ " + aliases + " }"
        start = time.time()
        resp = self._gql_post(url, query)
        elapsed = time.time() - start
        body = self._safe_json(resp["body"]) or {}
        errors = body.get("errors") or []
        err_msg = " ".join(str(e.get("message", "")) for e in errors).lower()
        if "alias" in err_msg and ("limit" in err_msg or "max" in err_msg):
            self._log("  ✓ alias limit triggered", "success")
            return
        if "data" in body and not errors:
            baseline = self._gql_post(url, "{ __typename }")
            baseline_time = baseline["elapsed"]
            amplification = elapsed / max(baseline_time, 0.001)
            severity = "high" if amplification > 5 else "medium"
            self._add_finding(
                "graphql_alias_dos", severity, url,
                "GraphQL alias DoS (no alias limit)",
                f"The server processed a query with {self.alias_count} "
                f"aliases on the same field. Response took {elapsed:.2f}s "
                f"vs {baseline_time:.2f}s for a single query "
                f"({amplification:.1f}x amplification). Without alias "
                "limits, attackers can multiply server load arbitrarily.",
                f"aliases={self.alias_count} elapsed={elapsed:.3f}s "
                f"baseline={baseline_time:.3f}s "
                f"amplification={amplification:.1f}x",
            )

    # ============================================================
    #          PHASE 4 — AUTH, AUTHORIZATION & INJECTION
    # ============================================================

    def _test_auth_bypass(self, url: str):
        """Test if the GraphQL endpoint requires authentication."""
        self._log("  › فحص authentication bypass...", "info")
        saved_cookie = self.client.cookie
        saved_session = dict(self.client.session_cookies)
        self.client.cookie = None
        self.client.session_cookies = {}
        try:
            resp_noauth = self._gql_post(url, "{ __typename }",
                                         headers={"Authorization": ""})
        finally:
            self.client.cookie = saved_cookie
            self.client.session_cookies = saved_session
        body = self._safe_json(resp_noauth["body"]) or {}
        if "data" in body and body["data"].get("__typename"):
            self._add_finding(
                "graphql_no_auth_required", "high", url,
                "GraphQL endpoint accessible without authentication",
                "The GraphQL endpoint responds to queries with valid data "
                "even when no authentication credentials (cookies, tokens) "
                "are provided. Any anonymous user can run arbitrary queries "
                "and mutations against the API.",
                f"status={resp_noauth['status']} __typename="
                f"{body['data'].get('__typename')}",
            )
        # Test invalid token
        resp_bad = self._gql_post(url, "{ __typename }",
                                  headers={"Authorization":
                                           "Bearer INVALID"})
        body_bad = self._safe_json(resp_bad["body"]) or {}
        if "data" in body_bad and body_bad["data"].get("__typename"):
            self._add_finding(
                "graphql_invalid_token_accepted", "high", url,
                "GraphQL endpoint accepts invalid auth token",
                "The GraphQL endpoint processes queries with an invalid "
                "Authorization header (Bearer INVALID). The server does "
                "not properly validate tokens, allowing auth bypass.",
                f"status={resp_bad['status']} "
                f"header=Authorization: Bearer INVALID",
            )

    def _test_field_authorization(self, url: str):
        """Test field-level authorization — try to read sensitive fields."""
        if not self.types:
            self._log("  › تخطي field authorization (لا يوجد schema)",
                      "info")
            return
        self._log("  › فحص field-level authorization...", "info")
        root = self.types.get(self.query_root) or self.types.get("Query")
        if not root:
            return
        for field in root.get("fields") or []:
            base_type = self._unwrap_type(field.get("type"))
            if not base_type:
                continue
            target_type = self.types.get(base_type)
            if not target_type:
                continue
            sensitive_fields: List[str] = []
            for tf in target_type.get("fields") or []:
                fname = (tf.get("name") or "").lower()
                if any(p in fname for p in SENSITIVE_FIELD_PATTERNS):
                    sensitive_fields.append(tf.get("name"))
            if not sensitive_fields:
                continue
            selection = " ".join(sensitive_fields[:5])
            query = f"{{ {field['name']} {{ {selection} }} }}"
            resp = self._gql_post(url, query)
            body = self._safe_json(resp["body"]) or {}
            data = body.get("data") or {}
            errors = body.get("errors") or []
            if data.get(field["name"]) and not any(
                    "authorized" in str(e.get("message", "")).lower()
                    or "forbidden" in str(e.get("message", "")).lower()
                    for e in errors):
                returned = data.get(field["name"])
                if isinstance(returned, dict):
                    leaked = {k: v for k, v in returned.items()
                              if v is not None and k in sensitive_fields}
                    if leaked:
                        self._add_finding(
                            "graphql_field_authz_bypass", "critical", url,
                            f"Sensitive field leaked via "
                            f"'{field['name']}' query",
                            f"The query '{field['name']}' returned values "
                            f"for sensitive fields without proper "
                            f"authorization: {list(leaked.keys())}. "
                            "Field-level authorization is missing or broken.",
                            f"query={self._short(query, 120)} "
                            f"leaked_keys={list(leaked.keys())}",
                        )

    def _test_injection(self, url: str):
        """Test GraphQL injection via arguments and variables."""
        self._log("  › فحص GraphQL injection...", "info")
        injection_payloads = [
            ("1 OR 1=1", "SQLi boolean"),
            ("' OR '1'='1", "SQLi string"),
            ("1; DROP TABLE users", "SQLi stacked"),
            ("${1+1}", "EL injection"),
            ("{{7*7}}", "SSTI"),
            ("admin'--", "SQLi comment"),
            ("1\x00", "null byte"),
            ("../../../../etc/passwd", "path traversal"),
            ('{"$gt":""}', "NoSQLi"),
            ("'; console.log('xss');//", "JS injection"),
        ]
        # Find a field with an argument via schema, else probe common ones
        target_field = None
        target_arg = None
        root = self.types.get(self.query_root) or self.types.get("Query")
        if root:
            for field in root.get("fields") or []:
                for arg in field.get("args") or []:
                    if arg.get("name") in ("id", "name", "email",
                                           "username", "query", "q",
                                           "search", "filter"):
                        target_field = field.get("name")
                        target_arg = arg.get("name")
                        break
                if target_field:
                    break
        if not target_field:
            for guess_field in COMMON_QUERY_FIELDS[:8]:
                for guess_arg in ["id", "name", "email", "q", "query"]:
                    q = (f'{{ {guess_field}({guess_arg}: "test") '
                         f'{{ __typename }} }}')
                    resp = self._gql_post(url, q)
                    body = self._safe_json(resp["body"]) or {}
                    errors = body.get("errors") or []
                    err_msg = " ".join(
                        str(e.get("message", "")) for e in errors).lower()
                    if ("cannot query field" not in err_msg
                            and "must have a selection" not in err_msg
                            and "did you mean" not in err_msg):
                        target_field = guess_field
                        target_arg = guess_arg
                        break
                if target_field:
                    break
        if not target_field:
            self._log("  › لم يتم العثور على حقل لحقن (skip injection)",
                      "info")
            return
        for payload, label in injection_payloads:
            query = (
                f"query Inj($input: String!) "
                f'{{ {target_field}({target_arg}: $input) '
                f'{{ __typename }} }}'
            )
            resp = self._gql_post(url, query, variables={"input": payload})
            body = self._safe_json(resp["body"]) or {}
            errors = body.get("errors") or []
            for e in errors:
                msg = str(e.get("message", ""))
                msg_low = msg.lower()
                if any(s in msg_low for s in [
                        "sql", "syntax error", "mysql", "postgres",
                        "sqlite", "oracle", "mariadb", "odbc",
                        "mongodb", "bson", "mongo",
                        "stack trace", "exception", "traceback",
                        "syntaxerror", "eval", "expression",
                        "template", "jinja", "nunjucks",
                        "passwd", "root:x:", "/bin/"]):
                    self._add_finding(
                        "graphql_injection_error_leak", "high", url,
                        f"GraphQL injection leaks backend error ({label})",
                        f"Injecting payload '{payload}' into argument "
                        f"'{target_arg}' of field '{target_field}' caused "
                        "the server to return a backend error message, "
                        "indicating the input is not sanitized and reaches "
                        "a downstream component (SQL/NoSQL/template engine).",
                        f"payload={payload!r} label={label} "
                        f"error={self._short(msg, 200)}",
                    )
                    break  # one finding per payload

    def _test_mutations(self, url: str):
        """Test if mutations are accessible and what they reveal."""
        self._log("  › فحص mutations...", "info")
        if self.mutation_root and self.types.get(self.mutation_root):
            mut_type = self.types[self.mutation_root]
            mut_fields = [f.get("name")
                          for f in (mut_type.get("fields") or [])]
        else:
            mut_fields = COMMON_MUTATION_FIELDS
        discovered_mutations: List[str] = []
        for mname in mut_fields[:20]:
            q = f"mutation {{ {mname} {{ __typename }} }}"
            resp = self._gql_post(url, q)
            body = self._safe_json(resp["body"]) or {}
            errors = body.get("errors") or []
            err_msg = " ".join(
                str(e.get("message", "")) for e in errors).lower()
            if "cannot query field" not in err_msg:
                discovered_mutations.append(mname)
            if "data" in body and not any(
                    "authorized" in str(e.get("message", "")).lower()
                    or "forbidden" in str(e.get("message", "")).lower()
                    or "unauthenticated" in str(e.get("message", "")).lower()
                    for e in errors):
                if ("cannot query field" not in err_msg
                        and "must have a selection" not in err_msg):
                    self._add_finding(
                        "graphql_mutation_accessible", "medium", url,
                        f"GraphQL mutation '{mname}' accessible without auth",
                        f"The mutation '{mname}' is present and the server "
                        "did not return an authentication/authorization "
                        "error when probing it. Attackers may be able to "
                        "invoke state-changing operations.",
                        f"mutation={mname} status={resp['status']} "
                        f"error={self._short(err_msg, 150)}",
                    )
        if discovered_mutations:
            self._log(f"  ✓ mutations discovered: "
                      f"{', '.join(discovered_mutations[:5])}", "success")

    def _test_subscriptions(self, url: str):
        """Test subscription support and detect the websocket endpoint."""
        self._log("  › فحص subscriptions...", "info")
        sub_fields = COMMON_SUBSCRIPTION_FIELDS
        if self.subscription_root and self.types.get(self.subscription_root):
            sub_type = self.types[self.subscription_root]
            sub_fields = [f.get("name")
                          for f in (sub_type.get("fields") or [])] or sub_fields
        for sname in sub_fields[:5]:
            q = f"subscription {{ {sname} {{ __typename }} }}"
            resp = self._gql_post(url, q)
            body = self._safe_json(resp["body"]) or {}
            errors = body.get("errors") or []
            err_msg = " ".join(
                str(e.get("message", "")) for e in errors).lower()
            if "subscription" in err_msg and (
                    "http" in err_msg or "websocket" in err_msg):
                self._log("  ✓ subscriptions require websocket (expected)",
                          "info")
                break
            if "data" in body and not errors:
                self._add_finding(
                    "graphql_subscription_over_http", "medium", url,
                    f"GraphQL subscription '{sname}' accepted over HTTP",
                    "The server accepted a subscription operation over "
                    "HTTP without requiring a WebSocket upgrade. This is "
                    "non-standard and may indicate the server processes "
                    "subscriptions incorrectly.",
                    f"subscription={sname} status={resp['status']}",
                )
                break
        # Look for the subscriptions websocket endpoint via OPTIONS upgrade
        ws_paths = ["/graphql", "/subscriptions", "/api/graphql",
                    "/api/subscriptions", "/ws", "/graphql/ws"]
        for ws_path in ws_paths:
            ws_url = self.base + ws_path
            resp = self._req(ws_url, method="OPTIONS", headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Origin": self.base,
            })
            upgrade = ""
            for h, v in (resp.get("headers") or {}).items():
                if h.lower() == "upgrade":
                    upgrade = v.lower()
            if upgrade == "websocket" or resp["status"] == 101:
                self._add_finding(
                    "graphql_subscription_endpoint", "low", ws_url,
                    "GraphQL subscription (WebSocket) endpoint detected",
                    "A WebSocket endpoint that may serve GraphQL "
                    "subscriptions was detected. Inspect it for auth and "
                    "injection issues.",
                    f"path={ws_path} status={resp['status']} "
                    f"upgrade={upgrade}",
                )
                break

    def _test_csrf_mutations(self, url: str):
        """Test CSRF protection on GraphQL mutations."""
        self._log("  › فحص CSRF على mutations...", "info")
        mutation_query = "mutation { __typename }"
        # 1) Form-encoded POST
        form_resp = self._req(url, method="POST",
                              data={"query": mutation_query},
                              headers={
                                  "Content-Type":
                                  "application/x-www-form-urlencoded"})
        body = self._safe_json(form_resp["body"]) or {}
        if form_resp["status"] in (200, 201) and "data" in body:
            self._add_finding(
                "graphql_csrf_form_encoded", "high", url,
                "GraphQL mutations accepted via form-encoded POST",
                "The GraphQL endpoint processes mutations sent as "
                "application/x-www-form-urlencoded. A malicious website "
                "can use a plain HTML <form> to trigger state-changing "
                "mutations when a victim visits the page (CSRF).",
                f"status={form_resp['status']} "
                f"body={self._short(form_resp['body'], 150)}",
            )
        # 2) text/plain POST
        text_resp = self._req(url, method="POST",
                              data=mutation_query,
                              headers={"Content-Type": "text/plain"})
        body = self._safe_json(text_resp["body"]) or {}
        if text_resp["status"] in (200, 201) and "data" in body:
            self._add_finding(
                "graphql_csrf_text_plain", "high", url,
                "GraphQL mutations accepted via text/plain POST",
                "The GraphQL endpoint processes mutations sent with "
                "Content-Type: text/plain. This bypasses CSRF protections "
                "that only allow application/json, enabling cross-site "
                "mutation attacks via simple HTML forms.",
                f"status={text_resp['status']} "
                f"body={self._short(text_resp['body'], 150)}",
            )

    def _test_persisted_queries(self, url: str):
        """Test Automatic Persisted Queries (APQ) support."""
        self._log("  › فحص persisted queries (APQ)...", "info")
        test_query = "{ __typename }"
        sha = hashlib.sha256(test_query.encode("utf-8")).hexdigest()
        extensions = {"persistedQuery": {"sha256Hash": sha, "version": 1}}
        # Step 1: hash-only GET — expect PersistedQueryNotFound
        resp1 = self._gql_post(url, query=None, use_get=True,
                               raw_body={"extensions": extensions})
        body1 = self._safe_json(resp1["body"]) or {}
        err_msg = " ".join(str(e.get("message", ""))
                           for e in (body1.get("errors") or [])).lower()
        err_code = " ".join(str(e.get("extensions", {}).get("code", ""))
                            for e in (body1.get("errors") or [])).lower()
        if "persistedquerynotfound" in err_msg.replace(" ", "") \
                or "persistedquerynotfound" in err_code.replace(" ", "") \
                or "persisted query not found" in err_msg:
            # Step 2: send full query + hash to register it
            resp2 = self._gql_post(url, query=test_query, use_get=True,
                                   extra_body={"extensions": extensions})
            body2 = self._safe_json(resp2["body"]) or {}
            if (body2.get("data") or {}).get("__typename"):
                # Step 3: re-send hash-only — should be cached now
                resp3 = self._gql_post(url, query=None, use_get=True,
                                       raw_body={"extensions": extensions})
                body3 = self._safe_json(resp3["body"]) or {}
                if (body3.get("data") or {}).get("__typename"):
                    self._add_finding(
                        "graphql_apq_enabled", "medium", url,
                        "GraphQL Automatic Persisted Queries (APQ) enabled",
                        "The server supports APQ. While APQ itself is a "
                        "performance feature, it expands the attack "
                        "surface: attackers can register arbitrary queries "
                        "by hash and trigger them later, and "
                        "persisted-query caches can be poisoned. Also, "
                        "APQ over GET leaks queries in proxy/CDN logs.",
                        f"sha256={sha} status={resp3['status']}",
                    )
        # Try sending a fabricated hash to detect cache-poisoning flaws
        fake_sha = "a" * 64
        fake_ext = {"persistedQuery":
                    {"sha256Hash": fake_sha, "version": 1}}
        resp_fake = self._gql_post(url, query=None, use_get=True,
                                   raw_body={"extensions": fake_ext})
        body_fake = self._safe_json(resp_fake["body"]) or {}
        if body_fake.get("data"):
            self._add_finding(
                "graphql_apq_cache_poisoning", "high", url,
                "GraphQL APQ accepts arbitrary hashes (cache poisoning)",
                "The server returned data for a fabricated "
                "persisted-query hash without the actual query text. This "
                "indicates the APQ cache trusts client-supplied hashes, "
                "allowing cache poisoning: an attacker can register a "
                "malicious query under any hash and have other clients "
                "execute it.",
                f"fake_sha={fake_sha} status={resp_fake['status']}",
            )

    # ============================================================
    #                       REPORTING
    # ============================================================

    def _build_report(self) -> Dict:
        return {
            "target": getattr(self, "target", ""),
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "endpoints_discovered": sorted(self.endpoints),
            "schema_extracted": bool(self.types),
            "types_count": len(self.types),
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
                "info": sum(1 for f in self.findings
                            if f["severity"] == "info"),
            },
        }

    def _print_results(self):
        """عرض نتائج الفحص"""
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔮 تقرير فحص أمان GraphQL{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")
        if self.endpoints:
            print(f"\n  {Colors.BOLD}GraphQL endpoints المكتشفة "
                  f"({len(self.endpoints)}):{Colors.NC}")
            for ep in sorted(self.endpoints)[:15]:
                print(f"    {Colors.GREEN}•{Colors.NC} {ep[:70]}")
        if self.types:
            print(f"\n  {Colors.BOLD}Schema:{Colors.NC} "
                  f"{len(self.types)} types extracted")
            if self.mutation_root:
                print(f"    Mutation root: {self.mutation_root}")
            if self.subscription_root:
                print(f"    Subscription root: {self.subscription_root}")
        if self.findings:
            sev_order = {"critical": 0, "high": 1,
                         "medium": 2, "low": 3, "info": 4}
            sorted_f = sorted(
                self.findings,
                key=lambda x: sev_order.get(x["severity"], 99))
            sev_color = {
                "critical": Colors.RED + Colors.BOLD,
                "high": Colors.RED,
                "medium": Colors.YELLOW,
                "low": Colors.GRAY,
                "info": Colors.CYAN,
            }
            print(f"\n  {Colors.RED + Colors.BOLD}🚨 Findings "
                  f"({len(self.findings)}):{Colors.NC}")
            for f in sorted_f:
                c = sev_color.get(f["severity"], Colors.NC)
                print(f"\n    {c}[{f['severity'].upper()}]{Colors.NC} "
                      f"{f['title']}")
                print(f"      {Colors.GRAY}type:{Colors.NC} {f['type']}")
                print(f"      {Colors.GRAY}url:{Colors.NC} {f['url'][:80]}")
                print(f"      "
                      f"{fix_display(self._short(f['description'], 250))}")
                print(f"      {Colors.GRAY}evidence:{Colors.NC} "
                      f"{self._short(f['evidence'], 150)}")
        else:
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات واضحة مكتشفة{Colors.NC}")
        report = self._build_report()
        stats = report["stats"]
        print(f"\n  {Colors.BOLD}📊 الإحصائيات:{Colors.NC}")
        print(f"    Endpoints: {stats['total_endpoints']}")
        print(f"    Types: {stats['types_count']}")
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
        user_agent=args.user_agent or "ghostpwn-gql/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=not args.no_redirects,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="graphql_security",
        description="ghostpwn - GraphQL Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 graphql_security.py https://example.com\n"
            "  python3 graphql_security.py https://example.com/graphql "
            "--verbose\n"
            "  python3 graphql_security.py https://example.com "
            "--cookie 'session=abc' --delay 0.2\n"
            "  python3 graphql_security.py https://example.com "
            "--json-out report.json\n"
        ),
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="HTTP request timeout in seconds (default 15)")
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
    parser.add_argument("--max-endpoints", type=int, default=6,
                        help="Maximum number of GraphQL endpoints to discover")
    parser.add_argument("--batch-size", type=int, default=50,
                        help="Number of queries to send in batch test")
    parser.add_argument("--alias-count", type=int, default=100,
                        help="Number of aliases to use in alias DoS test")
    parser.add_argument("--max-depth", type=int, default=20,
                        help="Maximum depth to test in depth-limit test")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["discovery", "schema", "dos",
                                           "auth", "all"],
                        default="all",
                        help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_demo_client(args)
    scanner = GraphQLSecurityScanner(
        http_client=client,
        options={
            "max_endpoints": args.max_endpoints,
            "batch_size": args.batch_size,
            "alias_count": args.alias_count,
            "max_depth": args.max_depth,
            "verbose": args.verbose,
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

    if report["stats"]["critical"] > 0:
        sys.exit(2)
    elif report["stats"]["high"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
