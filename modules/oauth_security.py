#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - OAuth 2.0 / OpenID Connect Security Scanner
فحص أمان OAuth و OpenID Connect

الفحوصات:
1.  اكتشاف OAuth/OIDC endpoints (well-known + heuristic probing)
2.  Authorization Code Flow testing
3.  Implicit Flow testing (response_type=token)
4.  Client Credentials Flow testing
5.  Redirect URI validation (open redirect + bypass techniques)
6.  State parameter validation (missing/weak/predictable)
7.  PKCE implementation testing (code_challenge presence)
8.  Scope manipulation testing (privilege escalation)
9.  Token leakage testing (URL fragment / Referer header)
10. Open redirect in OAuth callback
11. Account takeover via redirect_uri tampering
12. Token revocation endpoint testing
13. OIDC configuration exposure / weak config

ملاحظات:
- لا يستخدم مكتبات خارجية (Python stdlib فقط).
- يكتشف ويفحص دون تنفيذ هجمات خطيرة.
- يرسل فقط طلبات استطلاع وتعديل إضافي على redirect_uri/state/scope.
"""
import os
import sys
import re
import json
import time
import hashlib
import secrets
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import (urljoin, urlparse, parse_qs, urlencode,
                          urlsplit, urlunsplit)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# OIDC discovery paths
WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/oauth",
    "/oauth/.well-known/openid-configuration",
    "/.well-known/openid-configuration/oauth",
]

# Common OAuth endpoint paths (heuristic probe list)
OAUTH_ENDPOINT_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/authorize",
    "/oauth/auth", "/auth", "/oauth/login", "/connect/authorize",
    "/oauth/v2/authorize", "/oauth2/v2.authorize",
    "/oauth/token", "/oauth2/token", "/token", "/oauth/access_token",
    "/oauth/v2/token", "/connect/token",
    "/oauth/revoke", "/oauth2/revoke", "/revoke", "/oauth/logout",
    "/oauth/userinfo", "/oauth2/userinfo", "/userinfo",
    "/oauth/introspect", "/oauth2/introspect", "/introspect",
    "/oauth/device", "/oauth2/device", "/device",
    "/.well-known/jwks.json", "/oauth/jwks",
]

# Known public OAuth client_ids (for testing) — these are well-known
# examples from public documentation; only used to probe flows.
KNOWN_TEST_CLIENTS = [
    "test", "demo", "client", "web", "app", "mobile",
    "google", "facebook", "github", "microsoft",
    "00000000-0000-0000-0000-000000000000",
    "client_id", "oauth-client",
]

# Common scopes to test for escalation
ESCALATION_SCOPES = [
    "admin", "administrator", "root", "superuser", "sudo",
    "openid profile email admin", "profile admin",
    "*", "all", "read write delete", "read write admin",
    "user:admin", "users:write", "accounts:write",
    "offline_access admin", "openid profile email address phone "
    "offline_access admin",
]

# Attacker-controlled redirect hosts for testing
ATTACKER_HOSTS = [
    "evil.com", "attacker.example", "callback.evil.com",
    "ghostpwn-attacker.test",
]

# Redirect URI bypass techniques
REDIRECT_BYPASS_PAYLOADS = [
    # Open redirect via path traversal
    "{base}/../redirect?to=https://evil.com",
    "{base}/redirect?url=https://evil.com",
    "{base}/callback?next=https://evil.com",
    # Subdomain takeover / open redirect
    "https://evil.{host}",
    "https://{host}.evil.com",
    "https://evil.com@{host}",
    "https://{host}@evil.com",
    "https://evil.com#{path}",
    "https://evil.com?{path}",
    "javascript:alert(1)//{host}",
    "//evil.com/{path}",
    "https://evil.com\\@{host}",
    "https://evil.com%2F@{host}",
    "https://{host}%2eevil.com",
    "https://{host}\\.evil.com",
    "https://evil.com/{path}",
]

# Common response_type values
RESPONSE_TYPES = ["code", "token", "id_token", "code token",
                  "code id_token", "token id_token",
                  "code token id_token", "none"]


# ============================ Main Scanner ============================

class OAuthSecurityScanner:
    """فاحص أمان OAuth 2.0 / OIDC"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=12, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self.endpoints: Dict[str, str] = {}    # discovered endpoints
        self.oidc_config: Optional[Dict] = None
        self.scanned_urls: Set[str] = set()

        # Tunables
        self.max_endpoint_probes = self.options.get(
            "max_endpoint_probes", 30)
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)
        self.test_client_ids = self.options.get(
            "test_client_ids", KNOWN_TEST_CLIENTS[:6])

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[OAUTH] {msg}", level)

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
    def _short(text: str, n: int = 200) -> str:
        if not text:
            return ""
        text = text.replace("\n", " ").strip()
        return text if len(text) <= n else text[:n] + "..."

    @staticmethod
    def _safe_json(text: str) -> Optional[Dict]:
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return None

    def _req(self, url: str, method: str = "GET",
             headers: Optional[Dict] = None, data=None,
             json_data: Optional[Dict] = None,
             allow_redirects: bool = False) -> Dict:
        """Wrapper that disables redirects by default (to inspect Location)."""
        old_ar = self.client.allow_redirects
        self.client.allow_redirects = allow_redirects
        try:
            return self.client.request(url, method=method, headers=headers,
                                       data=data, json_data=json_data)
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "url": url,
                    "elapsed": 0, "error": str(e)}
        finally:
            self.client.allow_redirects = old_ar

    @staticmethod
    def _normalize_target(target: str) -> str:
        if not target:
            return ""
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target.rstrip("/") + "/"

    # ============================================================
    #                       MAIN SCAN
    # ============================================================

    def scan(self, target: str) -> Dict:
        if not target:
            self._log("Target URL فارغ", "error")
            return self._empty_report(target)

        target = self._normalize_target(target)
        self.target = target
        parsed = urlparse(target)
        self.base = f"{parsed.scheme}://{parsed.netloc}"

        self._log(f"بدء فحص أمان OAuth/OIDC: {self.base}", "phase")

        # ---------- Phase 1: Discovery ----------
        self._log("Phase 1: اكتشاف OAuth/OIDC endpoints", "phase")
        self._discover_oidc_config()
        self._probe_oauth_endpoints()

        if not self.endpoints:
            self._log("  ✗ لم يتم اكتشاف OAuth endpoints واضحة", "warn")
            self._print_results()
            return self._build_report()

        self._log(f"  ✓ endpoints مكتشفة: "
                  f"{list(self.endpoints.keys())}", "success")

        # ---------- Phase 2: Config analysis ----------
        self._log("Phase 2: تحليل إعدادات OIDC", "phase")
        self._analyze_oidc_config()

        # ---------- Phase 3: Authorization endpoint tests ----------
        self._log("Phase 3: فحص Authorization endpoint", "phase")
        self._test_auth_code_flow()
        self._test_implicit_flow()

        # ---------- Phase 4: Redirect URI validation ----------
        self._log("Phase 4: فحص التحقق من redirect_uri", "phase")
        self._test_redirect_uri_validation()

        # ---------- Phase 5: State & PKCE ----------
        self._log("Phase 5: فحص state parameter و PKCE", "phase")
        self._test_state_parameter()
        self._test_pkce_implementation()

        # ---------- Phase 6: Scope manipulation ----------
        self._log("Phase 6: فحص تلاعب الـ scope", "phase")
        self._test_scope_manipulation()

        # ---------- Phase 7: Token leakage ----------
        self._log("Phase 7: فحص تسرّب الـ tokens", "phase")
        self._test_token_leakage()

        # ---------- Phase 8: Open redirect in OAuth callback ----------
        self._log("Phase 8: فحص open redirect في OAuth callback", "phase")
        self._test_open_redirect_callback()

        # ---------- Phase 9: Account takeover via redirect_uri ----------
        self._log("Phase 9: فحص account takeover عبر redirect_uri", "phase")
        self._test_account_takeover_redirect()

        # ---------- Phase 10: Token revocation ----------
        self._log("Phase 10: فحص token revocation endpoint", "phase")
        self._test_token_revocation()
        self._test_client_credentials_flow()

        self._print_results()
        return self._build_report()

    # ============================================================
    #                PHASE 1 - DISCOVERY
    # ============================================================

    def _discover_oidc_config(self):
        """يجلب /.well-known/openid-configuration و sibling paths."""
        for path in WELL_KNOWN_PATHS:
            url = self.base + path.lstrip("/")
            if url in self.scanned_urls:
                continue
            self.scanned_urls.add(url)
            resp = self._req(url, allow_redirects=True)
            if resp["status"] == 200 and resp["body"]:
                cfg = self._safe_json(resp["body"])
                if cfg and isinstance(cfg, dict):
                    self.oidc_config = cfg
                    # استخراج endpoints من الـ config
                    for key in ("authorization_endpoint", "token_endpoint",
                                "userinfo_endpoint", "revocation_endpoint",
                                "introspection_endpoint", "device_authorization_endpoint",
                                "jwks_uri", "end_session_endpoint"):
                        val = cfg.get(key)
                        if val:
                            self.endpoints[key] = val
                    self._log(f"  ✓ تم العثور على OIDC config: {url}",
                              "success")
                    self._log(f"    issuer: {cfg.get('issuer', '?')}",
                              "info")
                    return
        self._log("  › لا يوجد OIDC discovery document", "info")

    def _probe_oauth_endpoints(self):
        """يبحث عن OAuth endpoints عبر probing heuristic."""
        # إن لم نكتشف config، نضيف paths افتراضية
        if not self.endpoints:
            for path in OAUTH_ENDPOINT_PATHS:
                url = self.base + path.lstrip("/")
                if url in self.scanned_urls:
                    continue
                self.scanned_urls.add(url)
                resp = self._req(url, allow_redirects=False)
                # نعتبر الـ endpoint موجوداً إن أعى 200/302/400 (وليس 404)
                if resp["status"] in (200, 301, 302, 303, 307, 400, 401, 405):
                    if path.endswith("/authorize") or "authorize" in path:
                        self.endpoints["authorization_endpoint"] = url
                    elif path.endswith("/token") or "token" in path:
                        self.endpoints["token_endpoint"] = url
                    elif "revoke" in path:
                        self.endpoints["revocation_endpoint"] = url
                    elif "userinfo" in path:
                        self.endpoints["userinfo_endpoint"] = url
                    elif "introspect" in path:
                        self.endpoints["introspection_endpoint"] = url
                    elif "jwks" in path:
                        self.endpoints["jwks_uri"] = url
                    elif "device" in path:
                        self.endpoints["device_authorization_endpoint"] = url

    # ============================================================
    #                PHASE 2 - CONFIG ANALYSIS
    # ============================================================

    def _analyze_oidc_config(self):
        """يفحص إعدادات OIDC بحثاً عن ضعف."""
        if not self.oidc_config:
            return
        cfg = self.oidc_config
        issuer = cfg.get("issuer", "")

        # 1. issuer غير مطابق للـ base
        if issuer and self.base not in issuer and issuer not in self.base:
            self._add_finding(
                "oauth_issuer_mismatch",
                "low",
                self.base + "/.well-known/openid-configuration",
                "OIDC Issuer Mismatch",
                "issuer في الـ OIDC config لا يطابق الـ base URL. قد يكشف "
                "عن misconfiguration أو host header injection في الـ discovery.",
                f"issuer='{issuer}', base='{self.base}'",
            )

        # 2. supported response types
        rts = cfg.get("response_types_supported", [])
        if rts:
            if "token" in rts or "token id_token" in rts:
                self._add_finding(
                    "oauth_implicit_flow_enabled",
                    "medium",
                    self.base + "/.well-known/openid-configuration",
                    "Implicit Flow Supported",
                    "الـ IdP يدعم implicit flow (response_type=token). هذا "
                    "الـ flow يضع الـ access_token في الـ URL fragment مما "
                    "يعرضه للتسريب عبر Referer أو browser history.",
                    f"response_types_supported={rts}",
                )

        # 3. token_endpoint_auth_methods - 'none' غير آمن لـ confidential client
        auth_methods = cfg.get("token_endpoint_auth_methods_supported", [])
        if auth_methods and "none" in auth_methods:
            self._add_finding(
                "oauth_public_client_only",
                "medium",
                self.base + "/.well-known/openid-configuration",
                "Token Endpoint Allows 'none' Auth Method",
                "الـ token endpoint يدعم طريقة المصادقة 'none' مما يعني "
                "أن public clients يمكنها طلب tokens دون client_secret. "
                "إن كان هناك mixed clients معتمدة بـ PKCE فقط، يجب التأكد "
                "أن لا clients سرية تستخدم 'none'.",
                f"token_endpoint_auth_methods_supported={auth_methods}",
            )

        # 4. scopes_supported — إن كان يدعم admin/openid wildcard
        scopes = cfg.get("scopes_supported", [])
        if scopes and any(s in ("*", "admin", "root") for s in scopes):
            self._add_finding(
                "oauth_dangerous_scopes_supported",
                "medium",
                self.base + "/.well-known/openid-configuration",
                    "Dangerous Scopes Advertised",
                "الـ IdP يعلن عن دعم scopes خطرة (admin/root/wildcard). "
                "قد يسمح بـ privilege escalation إن لم تُفحص الـ scopes "
                "على مستوى الـ resource server.",
                f"scopes_supported={scopes}",
            )

        # 5. require_pushed_authorization_requests / PKCE enforcement
        pkce_req = cfg.get("require_pushed_authorization_requests", False)
        code_challenge_methods = cfg.get(
            "code_challenge_methods_supported", [])
        if not code_challenge_methods:
            self._add_finding(
                "oauth_pkce_not_advertised",
                "low",
                self.base + "/.well-known/openid-configuration",
                "PKCE Methods Not Advertised",
                "إعدادات OIDC لا تعلن عن code_challenge_methods_supported. "
                "قد يعني أن PKCE غير مدعوم أو غير مُفعّل.",
                f"code_challenge_methods_supported={code_challenge_methods}",
            )
        elif "plain" in code_challenge_methods and \
                "S256" not in code_challenge_methods:
            self._add_finding(
                "oauth_pkce_plain_only",
                "medium",
                self.base + "/.well-known/openid-configuration",
                "PKCE Only 'plain' Method Supported",
                "IdP يدعم فقط 'plain' code_challenge_method مما يلغي "
                "الحماية التي يوفرها PKCE (لأن المهاجم يمكنه قراءة "
                "الـ verifier مباشرة).",
                f"code_challenge_methods_supported={code_challenge_methods}",
            )

        # 6. الـ jwks_uri خارج نطاق issuer
        jwks_uri = cfg.get("jwks_uri", "")
        if jwks_uri and self.base not in jwks_uri:
            self._add_finding(
                "oauth_external_jwks_uri",
                "low",
                self.base + "/.well-known/openid-configuration",
                "External JWKS URI",
                f"jwks_uri يشير لـ host خارجي: {jwks_uri}. إن اختُرق هذا "
                "الـ host يمكن تزوير ID tokens.",
                f"jwks_uri='{jwks_uri}'",
            )

    # ============================================================
    #                PHASE 3 - AUTH FLOWS
    # ============================================================

    def _test_auth_code_flow(self):
        """يختبر authorization code flow."""
        auth_ep = self.endpoints.get("authorization_endpoint")
        if not auth_ep:
            return
        url = auth_ep

        # طلب عادي
        params = {
            "response_type": "code",
            "client_id": self.test_client_ids[0],
            "redirect_uri": self.base + "callback",
            "state": secrets.token_hex(8),
            "scope": "openid profile",
        }
        full_url = f"{url}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        status = resp["status"]
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")
        body = resp["body"]

        if status == 302 and "code=" in loc:
            # قد يعيد code مباشرة دون consent - مشكلة
            self._add_finding(
                "oauth_auth_code_without_consent",
                "high",
                full_url,
                "Authorization Code Returned Without Consent",
                "الـ authorization endpoint أعاد code مباشرة في الـ redirect "
                "دون عرض صفحة consent أو login. هذا يسمح للمهاجم بالحصول "
                "على code نيابة عن المستخدم إن كان لديه جلسة نشطة.",
                f"status={status}, location={self._short(loc, 200)}",
            )
        elif status == 200 and "login" not in body.lower() and \
                "consent" not in body.lower() and "sign" not in body.lower():
            # رد 200 لكن بدون login/consent - غريب
            self._add_finding(
                "oauth_auth_endpoint_unexpected_response",
                "low",
                full_url,
                "Authorization Endpoint Unexpected 200 Response",
                "authorization endpoint أعاد 200 دون redirect أو login "
                "page. قد يشير لسلوك غير قياسي.",
                f"status={status}, body_excerpt={self._short(body, 150)}",
            )

    def _test_implicit_flow(self):
        """يختبر implicit flow (response_type=token)."""
        auth_ep = self.endpoints.get("authorization_endpoint")
        if not auth_ep:
            return

        params = {
            "response_type": "token",
            "client_id": self.test_client_ids[0],
            "redirect_uri": self.base + "callback",
            "state": secrets.token_hex(8),
            "scope": "openid profile",
            "nonce": secrets.token_hex(8),
        }
        full_url = f"{auth_ep}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        status = resp["status"]
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")

        if status == 302 and "access_token=" in loc:
            self._add_finding(
                "oauth_implicit_flow_active",
                "high",
                full_url,
                "Implicit Flow Issues Access Token in URL Fragment",
                "الـ IdP يصدر access_token مباشرة في URL fragment عند "
                "طلب response_type=token. هذا يعرّض الـ token للتسريب عبر "
                "browser history, Referer header, أو browser extensions.",
                f"status={status}, location={self._short(loc, 200)}",
            )

        # id_token في URL fragment
        if status == 302 and "id_token=" in loc:
            self._add_finding(
                "oauth_implicit_id_token_leak",
                "high",
                full_url,
                "ID Token Leaked via URL Fragment (Implicit Flow)",
                "ID token يُمرّر في URL fragment في implicit flow. هذا "
                "يسرب الـ token ويعرّضه لـ token substitution attacks.",
                f"status={status}, location={self._short(loc, 200)}",
            )

    def _test_client_credentials_flow(self):
        """يختبر client credentials flow للتأكد من عدم قبول client_id فقط."""
        token_ep = self.endpoints.get("token_endpoint")
        if not token_ep:
            return

        # محاولة بدون client_secret
        for cid in self.test_client_ids[:3]:
            data = {
                "grant_type": "client_credentials",
                "client_id": cid,
                "scope": "openid profile",
            }
            resp = self._req(token_ep, method="POST", data=data,
                             allow_redirects=False)
            status = resp["status"]
            body = resp["body"]
            j = self._safe_json(body)
            if j and "access_token" in j:
                self._add_finding(
                    "oauth_cc_no_secret",
                    "critical",
                    token_ep,
                    "Client Credentials Grant Without Secret",
                    f"تم إصدار access_token لـ client_id='{cid}' دون "
                    f"client_secret. هذا يعني أن أي شخص يعرف الـ client_id "
                    f"يمكنه الحصول على token للوصول لخدمات الـ backend.",
                    f"client_id='{cid}', status={status}, "
                    f"token_type={j.get('token_type','?')}, "
                    f"scope={j.get('scope','?')}",
                )
                break
            elif status == 200:
                # قد يعطي 200 لكن بدون token (مثلاً error في body)
                if j and j.get("error"):
                    self._log(f"  › {cid}: error={j.get('error')}", "info")

    # ============================================================
    #                PHASE 4 - REDIRECT URI VALIDATION
    # ============================================================

    def _test_redirect_uri_validation(self):
        """يختبر التحقق من redirect_uri عبر bypass techniques."""
        auth_ep = self.endpoints.get("authorization_endpoint")
        if not auth_ep:
            return

        parsed = urlparse(self.base)
        host = parsed.hostname or ""
        path = "/callback"

        # 1. redirect_uri لمضيف خارجي تماماً (يجب أن يُرفض)
        for attacker in ATTACKER_HOSTS:
            params = {
                "response_type": "code",
                "client_id": self.test_client_ids[0],
                "redirect_uri": f"https://{attacker}/callback",
                "state": secrets.token_hex(8),
            }
            full_url = f"{auth_ep}?{urlencode(params)}"
            resp = self._req(full_url, allow_redirects=False)
            status = resp["status"]
            loc = resp["headers"].get("Location") or resp["headers"].get(
                "location", "")

            if status == 302 and attacker in loc:
                # قبول redirect_uri خارجي بالكامل
                self._add_finding(
                    "oauth_redirect_uri_open_redirect",
                    "critical",
                    full_url,
                    "Redirect URI Open Redirect (External Host Accepted)",
                    f"تم قبول redirect_uri='https://{attacker}/callback' "
                    f"دون التحقق. هذا يسمح بـ authorization code theft و "
                    f"account takeover.",
                    f"attacker='{attacker}', status={status}, "
                    f"location={self._short(loc, 200)}",
                )
                break  # لا نكرر لكل attacker

        # 2. bypass techniques (subdomain, path traversal, etc.)
        bypasses_seen = []
        for tmpl in REDIRECT_BYPASS_PAYLOADS:
            try:
                payload = tmpl.format(base=self.base.rstrip("/"),
                                      host=host, path=path)
            except (KeyError, IndexError):
                continue
            params = {
                "response_type": "code",
                "client_id": self.test_client_ids[0],
                "redirect_uri": payload,
                "state": secrets.token_hex(8),
            }
            full_url = f"{auth_ep}?{urlencode(params)}"
            resp = self._req(full_url, allow_redirects=False)
            status = resp["status"]
            loc = resp["headers"].get("Location") or resp["headers"].get(
                "location", "")
            body = resp["body"]

            # إن أعى 302 إلى الموقع الخبيث أو 200 بدون اعتراض
            is_bypassed = False
            if status == 302:
                # لو الـ location يبدأ بـ evil.com أو يحتويه بدون issuer
                if "evil.com" in loc and host not in loc:
                    is_bypassed = True
                elif loc.startswith("//evil.com") or \
                        loc.startswith("javascript:"):
                    is_bypassed = True
            elif status == 200 and "error" not in body.lower() and \
                    "invalid" not in body.lower() and "redirect" not in body.lower():
                # قبل الـ redirect_uri دون خطأ
                is_bypassed = True

            if is_bypassed:
                bypasses_seen.append(payload)
                self._add_finding(
                    "oauth_redirect_uri_bypass",
                    "high",
                    full_url,
                    f"Redirect URI Bypass via '{self._short(payload, 60)}'",
                    "تم تجاوز التحقق من redirect_uri باستخدام تقنية bypass. "
                    "هذا يسمح بإعادة توجيه authorization code إلى موقع "
                    "متحكم به من قبل المهاجم.",
                    f"payload='{payload}', status={status}, "
                    f"location={self._short(loc, 150)}",
                )
                if len(bypasses_seen) >= 3:
                    break

    # ============================================================
    #                PHASE 5 - STATE & PKCE
    # ============================================================

    def _test_state_parameter(self):
        """يختبر إن كان state parameter إلزامياً."""
        auth_ep = self.endpoints.get("authorization_endpoint")
        if not auth_ep:
            return

        # طلب بدون state
        params = {
            "response_type": "code",
            "client_id": self.test_client_ids[0],
            "redirect_uri": self.base + "callback",
        }
        full_url = f"{auth_ep}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        status = resp["status"]
        body = resp["body"]
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")

        # إن لم يُرفض الطلب → state غير مُلزم
        # نتحقق إن لم يكن هناك error صريح في الـ redirect
        no_error = ("error=" not in loc) and ("error" not in body.lower()
                                              or "csrf" not in body.lower())
        if status in (200, 302) and no_error:
            self._add_finding(
                "oauth_state_not_required",
                "medium",
                full_url,
                "State Parameter Not Required (CSRF Risk)",
                "authorization endpoint يقبل الطلبات بدون state parameter. "
                "هذا يعرض لـ CSRF attacks على الـ authorization flow "
                "(login CSRF, session fixation).",
                f"status={status}, location={self._short(loc, 150)}",
            )

        # state ضعيف/قابل للتوقع (e.g., state=1, state=abc)
        weak_states = ["1", "0", "abc", "test", "12345", "static",
                       "fixedstate", "state"]
        for ws in weak_states:
            params = {
                "response_type": "code",
                "client_id": self.test_client_ids[0],
                "redirect_uri": self.base + "callback",
                "state": ws,
            }
            full_url = f"{auth_ep}?{urlencode(params)}"
            resp = self._req(full_url, allow_redirects=False)
            if resp["status"] == 302:
                loc = resp["headers"].get("Location") or resp["headers"].get(
                    "location", "")
                # إن أعاد state=ws في الـ redirect بدون complaint
                if f"state={ws}" in loc and "error=" not in loc:
                    self._add_finding(
                        "oauth_weak_state_accepted",
                        "low",
                        full_url,
                        f"Weak State Parameter Accepted: '{ws}'",
                        "authorization endpoint يقبل قيم state ضعيفة/ثابتة. "
                        "إن كان الـ client يولّد state ضعيفاً يصبح عرضة لـ "
                        "CSRF prediction.",
                        f"state='{ws}', location={self._short(loc, 150)}",
                    )
                    break

    def _test_pkce_implementation(self):
        """يختبر إن كان PKCE مطلوباً."""
        auth_ep = self.endpoints.get("authorization_endpoint")
        if not auth_ep:
            return

        # طلب بدون code_challenge
        params = {
            "response_type": "code",
            "client_id": self.test_client_ids[0],
            "redirect_uri": self.base + "callback",
            "state": secrets.token_hex(8),
            # بدون code_challenge و code_challenge_method
        }
        full_url = f"{auth_ep}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        status = resp["status"]
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")
        body = resp["body"]

        # إن قُبل الطلب (200 أو 302 بدون error) → PKCE غير مطلوب
        no_pkce_error = (
            "error=invalid_request" not in loc and
            "code_challenge" not in body.lower() and
            "pkce" not in body.lower()
        )
        if status in (200, 302) and no_pkce_error:
            self._add_finding(
                "oauth_pkce_not_required",
                "medium",
                full_url,
                "PKCE Not Required by Authorization Endpoint",
                "authorization endpoint يقبل الطلبات بدون code_challenge. "
                "PKCE ضروري لمنع authorization code interception على "
                "mobile/native apps ويُنصح به لكل clients.",
                f"status={status}, location={self._short(loc, 150)}",
            )

        # PKCE مع plain method
        params = {
            "response_type": "code",
            "client_id": self.test_client_ids[0],
            "redirect_uri": self.base + "callback",
            "state": secrets.token_hex(8),
            "code_challenge": secrets.token_hex(32),
            "code_challenge_method": "plain",
        }
        full_url = f"{auth_ep}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")
        if resp["status"] in (200, 302) and "error=" not in loc:
            self._add_finding(
                "oauth_pkce_plain_accepted",
                "low",
                full_url,
                "PKCE 'plain' Method Accepted",
                "authorization endpoint يقبل code_challenge_method='plain' "
                "الذي لا يوفر حماية فعلية لأن المهاجم الذي يقرأ "
                "الـ verifier يمكنه استخدامه مباشرة.",
                f"location={self._short(loc, 150)}",
            )

    # ============================================================
    #                PHASE 6 - SCOPE MANIPULATION
    # ============================================================

    def _test_scope_manipulation(self):
        """يختبر تلاعب الـ scope للـ privilege escalation."""
        auth_ep = self.endpoints.get("authorization_endpoint")
        if not auth_ep:
            return

        # نجرب طلب scope واسع/إداري
        for scope in ESCALATION_SCOPES[:5]:
            params = {
                "response_type": "code",
                "client_id": self.test_client_ids[0],
                "redirect_uri": self.base + "callback",
                "state": secrets.token_hex(8),
                "scope": scope,
            }
            full_url = f"{auth_ep}?{urlencode(params)}"
            resp = self._req(full_url, allow_redirects=False)
            status = resp["status"]
            loc = resp["headers"].get("Location") or resp["headers"].get(
                "location", "")
            body = resp["body"]

            # إن لم يرفض الـ scope (لا error=invalid_scope)
            if status in (200, 302) and "invalid_scope" not in loc and \
                    "invalid_scope" not in body.lower():
                self._add_finding(
                    "oauth_scope_escalation_accepted",
                    "medium",
                    full_url,
                    f"Escalation Scope Accepted: '{self._short(scope, 60)}'",
                    "authorization endpoint يقبل scope إداري/واسع دون "
                    "رفض. إن لم يُفحص الـ scope على مستوى الـ consent "
                    "والـ token endpoint قد يسمح بـ privilege escalation.",
                    f"scope='{scope}', status={status}, "
                    f"location={self._short(loc, 150)}",
                )
                break  # لا نكرر

        # scope=single wildcard
        params = {
            "response_type": "code",
            "client_id": self.test_client_ids[0],
            "redirect_uri": self.base + "callback",
            "state": secrets.token_hex(8),
            "scope": "*",
        }
        full_url = f"{auth_ep}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")
        if resp["status"] in (200, 302) and "invalid_scope" not in loc:
            self._add_finding(
                "oauth_wildcard_scope_accepted",
                "high",
                full_url,
                "Wildcard Scope '*' Accepted",
                "authorization endpoint يقبل scope='*' مما قد يمنح صلاحية "
                "كاملة. هذا خطر بالغ إن كان الـ resource server يحترم "
                "wildcard.",
                f"scope='*', location={self._short(loc, 150)}",
            )

    # ============================================================
    #                PHASE 7 - TOKEN LEAKAGE
    # ============================================================

    def _test_token_leakage(self):
        """يفحص تسرّب الـ tokens عبر URL fragment, query, Referer."""
        auth_ep = self.endpoints.get("authorization_endpoint")
        if not auth_ep:
            return

        # 1. implicit flow يضع token في fragment - نختبر
        params = {
            "response_type": "token",
            "client_id": self.test_client_ids[0],
            "redirect_uri": self.base + "callback",
            "state": secrets.token_hex(8),
            "scope": "openid profile",
        }
        full_url = f"{auth_ep}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")

        # Fragment (لا يصل للسيرفر لكنه يصل للمتصفح)
        if "#" in loc and ("access_token=" in loc or "id_token=" in loc):
            self._add_finding(
                "oauth_token_in_fragment",
                "medium",
                full_url,
                "Access Token in URL Fragment",
                "الـ token يُمرّر في URL fragment. هذا أقل خطورة من query "
                "ولكن لا يزال يُسجَّل في browser history ويمكن قراءته من "
                "browser extensions. يُفضّل استخدام authorization code flow "
                "مع PKCE.",
                f"location={self._short(loc, 200)}",
            )

        # Query string (أسوأ - يصل للسيرفر ويُسجَّل في كل logs)
        if "?" in loc and ("access_token=" in loc or "id_token=" in loc):
            self._add_finding(
                "oauth_token_in_query",
                "high",
                full_url,
                "Access Token in URL Query String",
                "الـ token يُمرّر في query string. هذا يُسجَّل في server "
                "logs, browser history, و Referer header. ثغرة خطيرة.",
                f"location={self._short(loc, 200)}",
            )

        # 2. نتحقق من سياسة Referrer-Policy على callback
        cb_url = self.base + "callback"
        resp_cb = self._req(cb_url, allow_redirects=True)
        rp = (resp_cb["headers"].get("Referrer-Policy") or
              resp_cb["headers"].get("referrer-policy") or "").lower()
        if not rp or rp in ("unsafe-url", "no-referrer-when-downgrade"):
            self._add_finding(
                "oauth_weak_referrer_policy",
                "low",
                cb_url,
                "Weak or Missing Referrer-Policy on Callback",
                "صفحة الـ callback لا تضع Referrer-Policy صارمة. إن كان "
                "الـ token في URL قد يتسرب عبر Referer header إلى "
                "موارد خارجية (analytics, CDNs).",
                f"Referrer-Policy='{rp}'",
            )

    # ============================================================
    #                PHASE 8 - OPEN REDIRECT IN CALLBACK
    # ============================================================

    def _test_open_redirect_callback(self):
        """يفحص وجود open redirect في صفحة callback المعتمدة."""
        cb_paths = ["/callback", "/oauth/callback", "/auth/callback",
                    "/login/callback", "/oauth2/callback", "/redirect",
                    "/return", "/cb"]
        parsed = urlparse(self.base)
        host = parsed.hostname or ""

        for cb in cb_paths:
            cb_url = self.base + cb.lstrip("/")
            # نرسل query parameters قد تستخدمها الصفحة للـ redirect
            for param in ("next", "url", "redirect", "redirect_uri",
                          "return", "returnTo", "returnUrl", "target",
                          "destination", "continue", "to"):
                test_url = f"{cb_url}?{param}=https://evil.com/"
                resp = self._req(test_url, allow_redirects=False)
                status = resp["status"]
                loc = resp["headers"].get("Location") or resp["headers"].get(
                    "location", "")
                if status in (301, 302, 303, 307) and "evil.com" in loc:
                    self._add_finding(
                        "oauth_callback_open_redirect",
                        "high",
                        test_url,
                        f"Open Redirect in OAuth Callback ({param}=)",
                        f"صفحة الـ callback '{cb}' تعيد التوجيه إلى موقع "
                        f"خارجي عبر parameter '{param}'. يمكن للمهاجم استغلال "
                        f"ذلك لسرقة authorization codes بعد تسجيل الدخول.",
                        f"param='{param}', status={status}, "
                        f"location={self._short(loc, 200)}",
                    )
                    return  # نكتفي بنتيجة واحدة

    # ============================================================
    #                PHASE 9 - ACCOUNT TAKEOVER VIA redirect_uri
    # ============================================================

    def _test_account_takeover_redirect(self):
        """
        يختبر إمكانية account takeover عبر redirect_uri:
        - إن قُبل redirect_uri خارجي كامل → المهاجم يمكنه اعتراض code.
        - نحاول redirect_uri بدون scheme (//evil.com)
        - نحاول redirect_uri مع @ (https://legit.com@evil.com)
        """
        auth_ep = self.endpoints.get("authorization_endpoint")
        if not auth_ep:
            return

        parsed = urlparse(self.base)
        host = parsed.hostname or ""

        # 1. //evil.com (protocol-relative)
        params = {
            "response_type": "code",
            "client_id": self.test_client_ids[0],
            "redirect_uri": "//evil.com/callback",
            "state": secrets.token_hex(8),
        }
        full_url = f"{auth_ep}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")
        if resp["status"] == 302 and ("evil.com" in loc) and \
                (host not in loc or loc.startswith("//evil.com") or
                 loc.startswith("https://evil.com")):
            self._add_finding(
                "oauth_account_takeover_protocol_relative",
                "critical",
                full_url,
                "Account Takeover via Protocol-Relative redirect_uri",
                "authorization endpoint يقبل '//evil.com/callback' كـ "
                "redirect_uri. هذا يسمح بإعادة توجيه authorization code "
                "إلى موقع المهاجم مما يؤدي لـ account takeover كامل.",
                f"redirect_uri='//evil.com/callback', location="
                f"{self._short(loc, 200)}",
            )

        # 2. https://legit.com@evil.com (user-info bypass)
        params = {
            "response_type": "code",
            "client_id": self.test_client_ids[0],
            "redirect_uri": f"https://{host}@evil.com/callback",
            "state": secrets.token_hex(8),
        }
        full_url = f"{auth_ep}?{urlencode(params)}"
        resp = self._req(full_url, allow_redirects=False)
        loc = resp["headers"].get("Location") or resp["headers"].get(
            "location", "")
        if resp["status"] == 302 and "evil.com" in loc:
            self._add_finding(
                "oauth_account_takeover_userinfo_bypass",
                "critical",
                full_url,
                "Account Takeover via User-Info Bypass in redirect_uri",
                "authorization endpoint يقبل redirect_uri بصيغة "
                "'https://legit@evil.com'. المتصفح يرسل الطلب إلى evil.com "
                "متجاهلاً user-info. هذا account takeover كامل.",
                f"location={self._short(loc, 200)}",
            )

    # ============================================================
    #                PHASE 10 - TOKEN REVOCATION
    # ============================================================

    def _test_token_revocation(self):
        """يفحص token revocation endpoint."""
        rev_ep = self.endpoints.get("revocation_endpoint")
        if not rev_ep:
            return

        # 1. إرسال token وهمي - يجب أن يعيد 200 دائماً (per RFC 7009)
        data = {
            "token": "invalid_token_ghostpwn_test",
            "token_type_hint": "access_token",
        }
        resp = self._req(rev_ep, method="POST", data=data,
                         allow_redirects=False)
        status = resp["status"]
        body = resp["body"]

        # RFC 7009: يجب أن يعيد 200 حتى لـ tokens غير الصالحة (لمنع information leak)
        if status == 200:
            self._log("  ✓ revocation endpoint يلتزم بـ RFC 7009", "success")
        elif status == 401:
            # قد يتطلب client auth - جيد
            self._log("  › revocation endpoint يتطلب مصادقة (401)", "info")
        elif status == 404:
            self._add_finding(
                "oauth_revocation_endpoint_404",
                "low",
                rev_ep,
                "Revocation Endpoint Returns 404",
                "revocation endpoint أعاد 404. قد يعني أن الـ endpoint غير "
                "موجود فعلياً أو أن المسار خاطئ - تحقق من الإعدادات.",
                f"status={status}, body_excerpt={self._short(body, 150)}",
            )
        elif status == 400:
            # قد يكون رداً صحيحاً لـ request غير صالح
            j = self._safe_json(body)
            if j and j.get("error") == "invalid_client":
                self._log("  › revocation endpoint يتطلب client_secret",
                          "info")

        # 2. نختبر إمكانية revoking tokens بدون مصادقة
        data = {
            "token": secrets.token_hex(16),  # token وهمي
        }
        resp = self._req(rev_ep, method="POST", data=data,
                         allow_redirects=False)
        if resp["status"] == 200:
            # قد يعني أن أي شخص يمكنه revoking tokens لأي شخص آخر
            self._add_finding(
                "oauth_revocation_no_auth",
                "medium",
                rev_ep,
                "Token Revocation Without Client Authentication",
                "revocation endpoint يقبل الطلبات بدون client_secret. "
                "هذا يسمح بـ denial of service عبر إلغاء tokens للمستخدمين "
                "الآخرين إن توفّر التخمين.",
                f"status=200, body_excerpt={self._short(resp['body'], 150)}",
            )

        # 3. introspection endpoint - هل يكشف معلومات بدون مصادقة؟
        intro_ep = self.endpoints.get("introspection_endpoint")
        if intro_ep:
            data = {"token": "ghostpwn_dummy_token"}
            resp = self._req(intro_ep, method="POST", data=data,
                             allow_redirects=False)
            j = self._safe_json(resp["body"])
            if resp["status"] == 200 and j and j.get("active") is False:
                # جيد - رد قياسي
                pass
            elif resp["status"] == 200 and j and "active" not in j:
                # قد يكشف معلومات token
                self._add_finding(
                    "oauth_introspect_info_leak",
                    "medium",
                    intro_ep,
                    "Token Introspection Leaks Token Metadata",
                    "introspection endpoint أعاد معلومات عن token وهمي "
                    "دون التحقق من active=false بشكل قياسي. قد يكشف معلومات "
                    "حساسة عن tokens الحقيقية.",
                    f"response_body={self._short(resp['body'], 200)}",
                )

    # ============================================================
    #                REPORT
    # ============================================================

    def _empty_report(self, target: str) -> Dict:
        return {
            "target": target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": [],
            "stats": self._stats_dict(),
        }

    def _stats_dict(self) -> Dict:
        return {
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings
                            if f["severity"] == "critical"),
            "high": sum(1 for f in self.findings
                        if f["severity"] == "high"),
            "medium": sum(1 for f in self.findings
                          if f["severity"] == "medium"),
            "low": sum(1 for f in self.findings
                       if f["severity"] == "low"),
        }

    def _build_report(self) -> Dict:
        return {
            "target": getattr(self, "target", ""),
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "endpoints": dict(self.endpoints),
            "oidc_config_present": self.oidc_config is not None,
            "findings": self.findings,
            "stats": self._stats_dict(),
        }

    def _print_results(self):
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔐 تقرير فحص أمان OAuth/OIDC"
              f"{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")

        if self.endpoints:
            print(f"\n  {Colors.BOLD}Endpoints المكتشفة:{Colors.NC}")
            for k, v in self.endpoints.items():
                print(f"    {Colors.CYAN}•{Colors.NC} {k}: {v[:60]}")

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
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات OAuth واضحة"
                  f"{Colors.NC}")

        stats = self._stats_dict()
        print(f"\n  {Colors.BOLD}📊 الإحصائيات:{Colors.NC}")
        print(f"    Findings: {stats['total_findings']} "
              f"({Colors.RED}C:{stats['critical']} H:{stats['high']} "
              f"{Colors.YELLOW}M:{stats['medium']} "
              f"{Colors.GRAY}L:{stats['low']}{Colors.NC})")
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")


# ============================ CLI ============================

def _build_demo_client(args) -> HttpClient:
    return HttpClient(
        timeout=args.timeout,
        user_agent=args.user_agent or "ghostpwn-oauth/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=False,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="oauth_security",
        description="ghostpwn - OAuth 2.0 / OIDC Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 oauth_security.py https://example.com\n"
            "  python3 oauth_security.py https://example.com --verbose\n"
            "  python3 oauth_security.py https://idp.example.com "
            "--client-id myclient\n"
            "  python3 oauth_security.py https://example.com "
            "--json-out oauth-report.json\n\n"
            "Note: يفحص الـ IdP/Authorization server بحثاً عن misconfigurations."
        ),
    )
    parser.add_argument("url", help="Target URL (OAuth issuer / IdP base)")
    parser.add_argument("--timeout", type=int, default=12,
                        help="HTTP timeout in seconds (default 12)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests (default 0.1)")
    parser.add_argument("--user-agent", default=None,
                        help="Custom User-Agent")
    parser.add_argument("--proxy", default=None,
                        help="HTTP(S) proxy URL")
    parser.add_argument("--cookie", default=None,
                        help="Cookie header (for authenticated tests)")
    parser.add_argument("--client-id", default=None,
                        help="Specific client_id to use in tests")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["discovery", "config", "auth",
                                            "redirect", "state", "pkce",
                                            "scope", "leakage", "callback",
                                            "takeover", "revocation", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_demo_client(args)
    test_client_ids = KNOWN_TEST_CLIENTS[:6]
    if args.client_id:
        test_client_ids = [args.client_id] + test_client_ids

    scanner = OAuthSecurityScanner(
        http_client=client,
        options={
            "verbose": args.verbose,
            "test_client_ids": test_client_ids,
        },
    )

    if args.only != "all":
        _patch_only(scanner, args.only)

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


def _patch_only(scanner: "OAuthSecurityScanner", only: str):
    """يخطّي كل الفحوصات ما عدا المطلوبة."""
    skip_map = {
        "discovery": ["_analyze_oidc_config", "_test_auth_code_flow",
                       "_test_implicit_flow", "_test_redirect_uri_validation",
                       "_test_state_parameter", "_test_pkce_implementation",
                       "_test_scope_manipulation", "_test_token_leakage",
                       "_test_open_redirect_callback",
                       "_test_account_takeover_redirect",
                       "_test_token_revocation",
                       "_test_client_credentials_flow"],
        "config": ["_test_auth_code_flow", "_test_implicit_flow",
                    "_test_redirect_uri_validation", "_test_state_parameter",
                    "_test_pkce_implementation", "_test_scope_manipulation",
                    "_test_token_leakage", "_test_open_redirect_callback",
                    "_test_account_takeover_redirect",
                    "_test_token_revocation",
                    "_test_client_credentials_flow"],
        "auth": ["_analyze_oidc_config",
                  "_test_redirect_uri_validation", "_test_state_parameter",
                  "_test_pkce_implementation", "_test_scope_manipulation",
                  "_test_token_leakage", "_test_open_redirect_callback",
                  "_test_account_takeover_redirect",
                  "_test_token_revocation",
                  "_test_client_credentials_flow"],
        "redirect": ["_analyze_oidc_config", "_test_auth_code_flow",
                      "_test_implicit_flow", "_test_state_parameter",
                      "_test_pkce_implementation", "_test_scope_manipulation",
                      "_test_token_leakage", "_test_open_redirect_callback",
                      "_test_account_takeover_redirect",
                      "_test_token_revocation",
                      "_test_client_credentials_flow"],
        "state": ["_analyze_oidc_config", "_test_auth_code_flow",
                   "_test_implicit_flow", "_test_redirect_uri_validation",
                   "_test_pkce_implementation", "_test_scope_manipulation",
                   "_test_token_leakage", "_test_open_redirect_callback",
                   "_test_account_takeover_redirect",
                   "_test_token_revocation",
                   "_test_client_credentials_flow"],
        "pkce": ["_analyze_oidc_config", "_test_auth_code_flow",
                  "_test_implicit_flow", "_test_redirect_uri_validation",
                  "_test_state_parameter", "_test_scope_manipulation",
                  "_test_token_leakage", "_test_open_redirect_callback",
                  "_test_account_takeover_redirect",
                  "_test_token_revocation",
                  "_test_client_credentials_flow"],
        "scope": ["_analyze_oidc_config", "_test_auth_code_flow",
                   "_test_implicit_flow", "_test_redirect_uri_validation",
                   "_test_state_parameter", "_test_pkce_implementation",
                   "_test_token_leakage", "_test_open_redirect_callback",
                   "_test_account_takeover_redirect",
                   "_test_token_revocation",
                   "_test_client_credentials_flow"],
        "leakage": ["_analyze_oidc_config", "_test_auth_code_flow",
                     "_test_implicit_flow", "_test_redirect_uri_validation",
                     "_test_state_parameter", "_test_pkce_implementation",
                     "_test_scope_manipulation",
                     "_test_open_redirect_callback",
                     "_test_account_takeover_redirect",
                     "_test_token_revocation",
                     "_test_client_credentials_flow"],
        "callback": ["_analyze_oidc_config", "_test_auth_code_flow",
                      "_test_implicit_flow", "_test_redirect_uri_validation",
                      "_test_state_parameter", "_test_pkce_implementation",
                      "_test_scope_manipulation", "_test_token_leakage",
                      "_test_account_takeover_redirect",
                      "_test_token_revocation",
                      "_test_client_credentials_flow"],
        "takeover": ["_analyze_oidc_config", "_test_auth_code_flow",
                      "_test_implicit_flow", "_test_redirect_uri_validation",
                      "_test_state_parameter", "_test_pkce_implementation",
                      "_test_scope_manipulation", "_test_token_leakage",
                      "_test_open_redirect_callback",
                      "_test_token_revocation",
                      "_test_client_credentials_flow"],
        "revocation": ["_analyze_oidc_config", "_test_auth_code_flow",
                        "_test_implicit_flow",
                        "_test_redirect_uri_validation",
                        "_test_state_parameter", "_test_pkce_implementation",
                        "_test_scope_manipulation", "_test_token_leakage",
                        "_test_open_redirect_callback",
                        "_test_account_takeover_redirect",
                        "_test_client_credentials_flow"],
    }
    for name in skip_map.get(only, []):
        def _noop(*a, **kw):
            return None
        setattr(scanner, name, _noop)


if __name__ == "__main__":
    main()
