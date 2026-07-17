#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Session Management Security Scanner
فحص أمان إدارة الجلسات (Sessions)

الفحوصات:
1.  تحليل session tokens (الطول، الـ entropy، الـ charset)
2.  فحص Session Fixation (تثبيت session ID قبل الـ login)
3.  فحص Session Hijacking (هل يعمل الـ token من عميل آخر؟)
4.  فحص Session Timeout (مدة صلاحية الـ token)
5.  تحليل سمات الـ Cookie (Secure, HttpOnly, SameSite, Domain, Path)
6.  فحص Session Regeneration (هل يُعاد توليد الـ token عند تغيير الصلاحيات؟)
7.  فحص Concurrent Sessions (هل تُسمح بجلسات متزامنة؟)
8.  فحص Token Prediction (هل الـ tokens قابلة للتنبؤ؟)
9.  فحص Logout (هل يُبطل الـ token فعلياً؟)
10. تحليل Remember-me tokens

ملاحظات:
- لا يستخدم مكتبات خارجية (Python stdlib فقط).
- يجمع الـ tokens عبر طلبات متعددة دون إجراء login فعلي.
- يحلل الـ entropy عبر Shannon entropy.
"""
import os
import sys
import re
import json
import time
import math
import hashlib
import secrets
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# Common session cookie names (cross-tech)
SESSION_COOKIE_NAMES = [
    "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "ASPSESSIONID",
    "sid", "session", "sessionid", "sessid", "_sid", "_session_id",
    "SSESS", "NSESS", "csrf_session", "_csrf",
    "connect.sid", "koa:sess", "express.sid",
    "laravel_session", "XSRF-TOKEN", "laravel_token",
    "session_token", "auth", "auth_token", "token", "user_session",
    "id", "uid", "user", "csrftoken",
]

# Common logout paths
LOGOUT_PATHS = [
    "/logout", "/signout", "/sign-out", "/logoff", "/log-out",
    "/auth/logout", "/auth/signout", "/account/logout",
    "/user/logout", "/users/logout", "/api/logout",
    "/session/destroy", "/session/end", "/end_session",
    "/login?logout", "/login?action=logout",
    "/oidc/logout", "/oauth/logout", "/connect/logout",
]

# Common login paths (for fixation tests)
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/auth/login",
    "/account/login", "/user/login", "/users/login",
    "/admin/login", "/admin", "/wp-login.php",
]

# Common remember-me cookie names
REMEMBER_ME_NAMES = [
    "remember_me", "rememberme", "remember", "rmb", "rmbtoken",
    "stay_logged_in", "stayloggedin", "autologin", "auto_login",
    "persistent", "persist", "device_token", "device",
]

# Cookie attributes we inspect
COOKIE_ATTRIBUTES = ["secure", "httponly", "samesite", "domain", "path",
                     "max-age", "expires"]

# Min acceptable session token length (bytes equivalent)
MIN_TOKEN_LENGTH = 16

# Min acceptable Shannon entropy (bits/char) for tokens
MIN_TOKEN_ENTROPY = 3.0


# ============================ Helpers ============================

def shannon_entropy(data: str) -> float:
    """يحسب Shannon entropy (bits per character)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def total_entropy_bits(data: str) -> float:
    """إجمالي الـ entropy بالـ bits (entropy per char * length)."""
    return shannon_entropy(data) * len(data)


def charset_class(data: str) -> str:
    """يحدد نوع charset المستخدم."""
    if not data:
        return "empty"
    has_lower = any(c.islower() for c in data)
    has_upper = any(c.isupper() for c in data)
    has_digit = any(c.isdigit() for c in data)
    has_special = any(not c.isalnum() for c in data)
    parts = []
    if has_lower:
        parts.append("lower")
    if has_upper:
        parts.append("upper")
    if has_digit:
        parts.append("digit")
    if has_special:
        parts.append("special")
    return "+".join(parts) if parts else "other"


def parse_set_cookie(set_cookie_str: str) -> Dict:
    """يفك ترميم Set-Cookie header إلى مكوناته."""
    if not set_cookie_str:
        return {}
    parts = [p.strip() for p in set_cookie_str.split(";")]
    if not parts or "=" not in parts[0]:
        return {}
    name, _, value = parts[0].partition("=")
    attrs = {}
    for attr in parts[1:]:
        if "=" in attr:
            k, _, v = attr.partition("=")
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[attr.lower()] = True
    return {
        "name": name.strip(),
        "value": value.strip(),
        "attrs": attrs,
        "raw": set_cookie_str,
    }


def extract_cookies_from_response(resp: Dict) -> List[Dict]:
    """يستخرج كل Set-Cookie headers من رد."""
    cookies = []
    headers = resp.get("headers", {})
    # قد تأتي في header واحد مفصول بفواصل أو في headers منفصلة
    raw_cookies = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    if not raw_cookies:
        return cookies
    # urllib قد يدمجها في string واحد
    if isinstance(raw_cookies, str):
        # نقسم على نمط يفصل بين cookies (Name= value; attrs, Name2= value)
        # الطريقة الأكثر أماناً: ننظر لـ " ," التي تلي سمة cookie
        # لكن قد تكون attrs نفسها تحتوي على comma (Expires=... GMT, ...)
        # الحل: regex بحث عن نمط name=...; ...; يبدأ سمة جديدة
        # نعتمد تقسيم بسيط: إذا وجدنا ', ' متبوعاً بحرف وليس رقم تاريخ
        parts = re.split(r',\s*(?=[A-Za-z0-9_\-]+=)', raw_cookies)
        for p in parts:
            c = parse_set_cookie(p.strip())
            if c and c.get("name"):
                cookies.append(c)
    return cookies


def looks_like_session_cookie(name: str) -> bool:
    """فحص إن كان اسم الـ cookie يحمل بصمة session."""
    name_lower = name.lower()
    for sn in SESSION_COOKIE_NAMES:
        if name_lower == sn.lower():
            return True
        if sn.lower() in name_lower and len(name_lower) < 40:
            return True
    # heuristic: يحوي 'sess', 'sid', 'token', 'auth'
    for kw in ("sess", "sid", "token", "auth", "jsession", "csrf"):
        if kw in name_lower:
            return True
    return False


def looks_like_remember_me(name: str) -> bool:
    name_lower = name.lower()
    for sn in REMEMBER_ME_NAMES:
        if sn in name_lower:
            return True
    return False


# ============================ Main Scanner ============================

class SessionSecurityScanner:
    """فاحص أمان إدارة الجلسات"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=12, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self.collected_tokens: List[Dict] = []
        self.session_cookies: List[Dict] = []

        # Tunables
        self.token_sample_size = self.options.get("token_sample_size", 8)
        self.timeout_test_seconds = self.options.get(
            "timeout_test_seconds", 0)  # 0 = skip
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[SESSION] {msg}", level)

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

    def _req(self, url: str, method: str = "GET",
             headers: Optional[Dict] = None, data=None,
             allow_redirects: bool = True,
             reset_cookies: bool = False) -> Dict:
        old_ar = self.client.allow_redirects
        old_cookies = dict(self.client.session_cookies)
        self.client.allow_redirects = allow_redirects
        if reset_cookies:
            self.client.session_cookies = {}
        try:
            return self.client.request(url, method=method, headers=headers,
                                       data=data)
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "url": url,
                    "elapsed": 0, "error": str(e)}
        finally:
            self.client.allow_redirects = old_ar
            if reset_cookies:
                self.client.session_cookies = old_cookies

    @staticmethod
    def _normalize_target(target: str) -> str:
        if not target:
            return ""
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target.rstrip("/") + "/"

    def _fresh_client_request(self, url: str) -> Tuple[Dict, List[Dict]]:
        """يجلب رداً بـ cookies جديدة (يفصل جلسة جديدة)."""
        # نخزن state الـ client ثم نطلق طلب بـ session جديد
        old_cookies = dict(self.client.session_cookies)
        self.client.session_cookies = {}
        try:
            resp = self.client.request(url)
            cookies = extract_cookies_from_response(resp)
        finally:
            self.client.session_cookies = old_cookies
        return resp, cookies

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
        self.is_https = (parsed.scheme == "https")

        self._log(f"بدء فحص أمان الجلسات: {self.base}", "phase")

        # ---------- Phase 1: Collect baseline + cookies ----------
        self._log("Phase 1: جمع الـ cookies الأساسية", "phase")
        self._collect_baseline_cookies()

        # ---------- Phase 2: Cookie attribute analysis ----------
        self._log("Phase 2: تحليل سمات الـ cookies", "phase")
        self._analyze_cookie_attributes()

        # ---------- Phase 3: Token collection + analysis ----------
        self._log("Phase 3: جمع وتحليل session tokens", "phase")
        self._collect_token_samples()
        self._analyze_token_quality()

        # ---------- Phase 4: Token prediction ----------
        self._log("Phase 4: فحص إمكانية التنبؤ بـ token", "phase")
        self._test_token_prediction()

        # ---------- Phase 5: Session fixation ----------
        self._log("Phase 5: فحص Session Fixation", "phase")
        self._test_session_fixation()

        # ---------- Phase 6: Session timeout ----------
        self._log("Phase 6: فحص Session Timeout", "phase")
        self._test_session_timeout()

        # ---------- Phase 7: Session regeneration ----------
        self._log("Phase 7: فحص Session Regeneration", "phase")
        self._test_session_regeneration()

        # ---------- Phase 8: Concurrent sessions ----------
        self._log("Phase 8: فحص Concurrent Sessions", "phase")
        self._test_concurrent_sessions()

        # ---------- Phase 9: Logout ----------
        self._log("Phase 9: فحص Logout", "phase")
        self._test_logout()

        # ---------- Phase 10: Remember-me ----------
        self._log("Phase 10: تحليل Remember-me tokens", "phase")
        self._test_remember_me()

        self._print_results()
        return self._build_report()

    # ============================================================
    #                PHASE 1 - BASELINE COOKIES
    # ============================================================

    def _collect_baseline_cookies(self):
        """يجلب الـ cookies من الصفحة الرئيسية."""
        resp, cookies = self._fresh_client_request(self.target)
        if resp["status"] == 0:
            self._log(f"  ✗ تعذّر الوصول للهدف: {resp.get('error')}", "warn")
            return

        if not cookies:
            self._log("  › لا توجد Set-Cookie headers في الرد", "info")
            return

        for c in cookies:
            if looks_like_session_cookie(c["name"]):
                self.session_cookies.append(c)
                self._log(f"  ✓ session cookie: {c['name']} "
                          f"(value len={len(c['value'])})", "info")

        if not self.session_cookies:
            # نأخذ كل cookies كاحتياط
            self.session_cookies = cookies
            self._log(f"  › لم نتعرّف على session cookie محدد - "
                      f"سنحلل كل {len(cookies)} cookies", "info")

    # ============================================================
    #                PHASE 2 - COOKIE ATTRIBUTES
    # ============================================================

    def _analyze_cookie_attributes(self):
        """يفحص سمات كل cookie."""
        if not self.session_cookies:
            return

        for c in self.session_cookies:
            attrs = c.get("attrs", {})
            name = c["name"]
            url = self.target
            issues = []

            # 1. Secure flag
            if self.is_https and not attrs.get("secure"):
                issues.append(("secure_missing",
                               "high",
                               "Cookie بدون سمة Secure - تُرسل عبر HTTP "
                               "غير المشفر فيمكن اعتراضها (MitM)."))

            # 2. HttpOnly flag
            if not attrs.get("httponly"):
                issues.append(("httponly_missing",
                               "medium",
                               "Cookie بدون سمة HttpOnly - يمكن قراءتها "
                               "عبر JavaScript فيمكن سرقتها عبر XSS."))

            # 3. SameSite
            samesite = attrs.get("samesite", "").lower() if isinstance(
                attrs.get("samesite"), str) else ""
            if not samesite:
                issues.append(("samesite_missing",
                               "medium",
                               "Cookie بدون سمة SameSite - يُرسل في "
                               "cross-site requests فيمكن استغلاله في "
                               "CSRF attacks."))
            elif samesite == "none":
                if not attrs.get("secure"):
                    issues.append(("samesite_none_insecure",
                                   "high",
                                   "SameSite=None بدون Secure - خطر "
                                   "بالغ: الـ cookie يُرسل في كل المواقع "
                                   "ويمكن اعتراضه."))
                else:
                    issues.append(("samesite_none",
                                   "low",
                                   "SameSite=None - الـ cookie يُرسل عبر "
                                   "cross-site (يحتاج مبرراً قوياً)."))

            # 4. Domain - overly broad
            domain = attrs.get("domain", "") if isinstance(
                attrs.get("domain"), str) else ""
            if domain:
                if domain.startswith("."):
                    issues.append(("domain_leading_dot",
                                   "low",
                                   f"Domain='{domain}' يبدأ بنقطة فيُرسل "
                                   "لكل subdomains - قد يُسرّب الـ cookie "
                                   "للتطبيقات الأقل أماناً."))
                parsed = urlparse(self.base)
                if domain not in parsed.netloc and \
                        domain.lstrip(".") not in parsed.netloc:
                    issues.append(("domain_external",
                                   "high",
                                   f"Domain='{domain}' لا يطابق الـ host - "
                                   "قد يكون misconfiguration خطير."))

            # 5. Path - overly broad
            path = attrs.get("path", "") if isinstance(
                attrs.get("path"), str) else ""
            if path == "/" or not path:
                issues.append(("path_root",
                               "low",
                               "Path='/' - الـ cookie متاح لكل مسارات "
                               "التطبيق (قد يكون ضرورياً لكنه يوسع نطاق "
                               "الـ XSS泄漏)."))

            # 6. Max-Age / Expires - too long for session cookie
            max_age = attrs.get("max-age")
            expires = attrs.get("expires")
            ttl_seconds = None
            if max_age and isinstance(max_age, str):
                try:
                    ttl_seconds = int(max_age)
                except ValueError:
                    pass
            if ttl_seconds is None and expires and isinstance(
                    expires, str):
                # parse expires date roughly
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(expires)
                    if dt:
                        ttl_seconds = int(
                            (dt.timestamp() - time.time()))
                except Exception:
                    pass

            if ttl_seconds is not None:
                if ttl_seconds <= 0:
                    issues.append(("cookie_expired",
                                   "info",
                                   "الـ cookie منتهية بالفعل (يُستخدم "
                                   "للحذف)."))
                elif ttl_seconds > 86400 * 30:  # > 30 days
                    issues.append(("ttl_too_long",
                                   "medium",
                                   f"عمر الـ cookie = {ttl_seconds} ثانية "
                                   f"(>30 يوماً) - طويل جداً لـ session "
                                   "cookie."))
                elif ttl_seconds > 86400 * 7:  # > 7 days
                    issues.append(("ttl_long",
                                   "low",
                                   f"عمر الـ cookie = {ttl_seconds} ثانية "
                                   f"(>7 أيام) - طويل نسبياً."))

            for code, sev, desc in issues:
                self._add_finding(
                    f"session_cookie_{code}",
                    sev,
                    url,
                    f"Cookie '{name}' - {code.replace('_', ' ').title()}",
                    desc,
                    f"cookie={name}, value_len={len(c['value'])}, "
                    f"attrs={attrs}",
                )

    # ============================================================
    #                PHASE 3 - TOKEN COLLECTION + ANALYSIS
    # ============================================================

    def _collect_token_samples(self):
        """يجمع عينات متعددة من session tokens لتحليلها."""
        if not self.session_cookies:
            return

        for i in range(self.token_sample_size):
            resp, cookies = self._fresh_client_request(self.target)
            for c in cookies:
                if looks_like_session_cookie(c["name"]):
                    self.collected_tokens.append({
                        "name": c["name"],
                        "value": c["value"],
                        "attrs": c.get("attrs", {}),
                        "index": i,
                    })
            time.sleep(0.1)

        self._log(f"  ✓ جمعت {len(self.collected_tokens)} عينة token",
                  "success" if self.collected_tokens else "info")

    def _analyze_token_quality(self):
        """يحلل جودة الـ tokens المجمّعة."""
        if not self.collected_tokens:
            return

        # نتائج لكل اسم cookie
        by_name: Dict[str, List[str]] = {}
        for t in self.collected_tokens:
            by_name.setdefault(t["name"], []).append(t["value"])

        for name, values in by_name.items():
            self._analyze_single_token_set(name, values)

    def _analyze_single_token_set(self, name: str, values: List[str]):
        """يحلل مجموعة tokens لاسم معين."""
        if not values:
            return

        lengths = [len(v) for v in values]
        avg_len = sum(lengths) / len(lengths)
        min_len = min(lengths)
        max_len = max(lengths)

        # entropies
        entropies = [shannon_entropy(v) for v in values]
        avg_ent = sum(entropies) / len(entropies) if entropies else 0
        charsets = set(charset_class(v) for v in values)

        # uniqueness
        unique = len(set(values))
        dup_count = len(values) - unique

        url = self.target

        # 1. Token length too short
        if min_len < MIN_TOKEN_LENGTH:
            self._add_finding(
                "session_token_short",
                "high",
                url,
                f"Session Cookie '{name}' Too Short",
                f"أقصر token = {min_len} حرفاً. الـ tokens القصيرة عرضة "
                "للـ brute force (e.g., < 16 char). يُنصح بـ 32+ حرفاً.",
                f"name='{name}', min_length={min_len}, "
                f"avg_length={avg_len:.1f}, sample={values[0][:30]}",
            )

        # 2. Low entropy
        if avg_ent < MIN_TOKEN_ENTROPY:
            self._add_finding(
                "session_token_low_entropy",
                "high",
                url,
                f"Session Cookie '{name}' Low Entropy",
                f"متوسط Shannon entropy = {avg_ent:.2f} bits/char. الـ "
                "tokens ضعيفة الـ entropy عرضة للـ prediction/brute force.",
                f"name='{name}', avg_entropy={avg_ent:.2f}, "
                f"charsets={charsets}, samples={[v[:20] for v in values[:3]]}",
            )

        # 3. Duplicate tokens (very bad)
        if dup_count > 0:
            sev = "critical" if dup_count > len(values) / 2 else "high"
            self._add_finding(
                "session_token_duplicates",
                sev,
                url,
                f"Session Cookie '{name}' Has Duplicate Values",
                f"{dup_count} من أصل {len(values)} token مكرّر. هذا يعني "
                "أن الـ server لا يولّد tokens فريدة لكل جلسة - ثغرة "
                "Session Fixation/Hijacking كاملة.",
                f"name='{name}', total={len(values)}, duplicates={dup_count}, "
                f"unique={unique}",
            )

        # 4. Variable length (suspicious)
        if max_len - min_len > 4:
            self._add_finding(
                "session_token_variable_length",
                "low",
                url,
                f"Session Cookie '{name}' Variable Length",
                f"أطوال الـ tokens تتراوح بين {min_len} و{max_len}. الـ "
                "tokens عالية الجودة لها طول ثابت. الطول المتغير قد يكشف "
                "عن بنية داخلية (e.g., user_id + timestamp + hmac).",
                f"name='{name}', lengths={lengths}",
            )

        # 5. Limited charset (e.g., numeric only)
        for cs in charsets:
            if cs in ("digit", "lower"):
                self._add_finding(
                    "session_token_limited_charset",
                    "medium",
                    url,
                    f"Session Cookie '{name}' Limited Charset",
                    f"الـ tokens تستخدم charset محدود ({cs}). هذا يقلل "
                    "الـ entropy الفعّالة ويسهّل الـ brute force.",
                    f"name='{name}', charset='{cs}', sample="
                    f"{values[0][:30]}",
                )
                break

    # ============================================================
    #                PHASE 4 - TOKEN PREDICTION
    # ============================================================

    def _test_token_prediction(self):
        """يفحص إن كانت الـ tokens قابلة للتنبؤ."""
        by_name: Dict[str, List[str]] = {}
        for t in self.collected_tokens:
            by_name.setdefault(t["name"], []).append(t["value"])

        for name, values in by_name.items():
            if len(values) < 3:
                continue
            url = self.target

            # 1. Sequential numeric patterns
            numeric_parts = []
            for v in values:
                # extract numeric substrings
                nums = re.findall(r'\d+', v)
                if nums:
                    numeric_parts.append(nums)
            if numeric_parts and len(numeric_parts) == len(values):
                # نتحقق إن كانت الأرقام متتالية
                first_nums = [int(n[0]) for n in numeric_parts
                              if n and n[0].isdigit()]
                if len(first_nums) >= 3:
                    diffs = [first_nums[i+1] - first_nums[i]
                             for i in range(len(first_nums)-1)]
                    if len(set(diffs)) == 1 and diffs[0] != 0:
                        self._add_finding(
                            "session_token_sequential",
                            "critical",
                            url,
                            f"Session Cookie '{name}' Sequential Numeric",
                            f"الـ tokens تحتوي أرقاماً متتالية بفارق "
                            f"ثابت ({diffs[0]}). هذا يعني إمكانية التنبؤ "
                            "بـ tokens الجلسات الأخرى عبر arithmetic.",
                            f"name='{name}', numeric_samples={first_nums[:5]},"
                            f" diff={diffs[0]}",
                        )

            # 2. Common prefix
            if len(values) >= 3:
                prefix = os.path.commonprefix(values)
                if prefix and len(prefix) > 4 and \
                        len(prefix) > len(values[0]) * 0.5:
                    self._add_finding(
                        "session_token_common_prefix",
                        "medium",
                        url,
                        f"Session Cookie '{name}' Common Prefix",
                        f"الـ tokens تشترك في prefix طويل: '{prefix}'. "
                        "هذا يكشف عن بنية داخلية ويسهّل targeted brute "
                        "force.",
                        f"name='{name}', prefix='{prefix}', "
                        f"prefix_len={len(prefix)}",
                    )

            # 3. Time-based component (Unix timestamp pattern)
            for v in values:
                # نبحث عن timestamps (10 digits starting with 1-2)
                ts_match = re.search(r'(?<!\d)(1[5-9]\d{8}|2\d{9})(?!\d)', v)
                if ts_match:
                    try:
                        ts = int(ts_match.group(1))
                        # verify it's plausible (2015-2030)
                        if 1420000000 <= ts <= 1950000000:
                            self._add_finding(
                                "session_token_time_based",
                                "medium",
                                url,
                                f"Session Cookie '{name}' Contains Timestamp",
                                f"الـ token يحوي Unix timestamp ({ts}). "
                                "إن كان مكوّناً أساسياً يقلل الـ entropy "
                                "ويسمح بالـ prediction.",
                                f"name='{name}', token_sample="
                                f"{v[:40]}, timestamp={ts}",
                            )
                            break
                    except ValueError:
                        pass

            # 4. Hash of predictable input (e.g., MD5(user_agent) + ts)
            # نتحقق إن كانت الـ tokens تبدو كـ hash (hex, 32 or 64 chars)
            if all(re.fullmatch(r'[a-f0-9]+', v) for v in values) and \
                    any(len(v) in (32, 40, 64) for v in values):
                self._add_finding(
                    "session_token_hash_like",
                    "low",
                    url,
                    f"Session Cookie '{name}' Hash-Like",
                    "الـ tokens تبدو كـ hex hashes (MD5/SHA1/SHA256). إن "
                    "كانت hash لمدخلات قابلة للتخمين (user agent, IP, "
                    "timestamp) يمكن كسرها.",
                    f"name='{name}', sample_lengths={[len(v) for v in values]}",
                )

    # ============================================================
    #                PHASE 5 - SESSION FIXATION
    # ============================================================

    def _test_session_fixation(self):
        """يختبر session fixation: هل يقبل الـ server session ID مخصصاً؟"""
        if not self.session_cookies:
            return
        url = self.target

        for c in self.session_cookies[:3]:  # نكتفي بأول 3
            name = c["name"]
            attacker_value = "ghostpwn fixation " + secrets.token_hex(8)

            # نرسل طلب بـ cookie محدد يدوياً
            old_cookies = dict(self.client.session_cookies)
            self.client.session_cookies = {}
            self.client.session_cookies[name] = attacker_value
            try:
                resp = self.client.request(url)
            finally:
                self.client.session_cookies = old_cookies

            # نتحقق من Set-Cookie في الرد
            new_cookies = extract_cookies_from_response(resp)
            new_value = None
            for nc in new_cookies:
                if nc["name"] == name:
                    new_value = nc["value"]
                    break

            # إن لم يصدر الـ server cookie جديد أو أصدر نفس القيمة المحددة
            # → fixation محتمل
            if new_value is None:
                self._add_finding(
                    "session_fixation_no_regeneration",
                    "medium",
                    url,
                    f"Session Cookie '{name}' Not Regenerated",
                    f"أرسلنا cookie مخصصة '{name}={attacker_value}' ولم "
                    "يصدر الـ server cookie بديل. هذا يعني أن الـ server "
                    "قد يقبل session ID يفرضه المهاجم.",
                    f"name='{name}', submitted_value='{attacker_value}', "
                    f"response_status={resp['status']}, "
                    f"set_cookie_returned={new_value is not None}",
                )
            elif new_value == attacker_value:
                self._add_finding(
                    "session_fixation_accepted",
                    "high",
                    url,
                    f"Session Cookie '{name}' Accepts Attacker-Supplied ID",
                    f"أرسلنا قيمة session مخصصة وأعادها الـ server كما هي "
                    "في Set-Cookie. هذا تأكيد لـ Session Fixation - يمكن "
                    "للمهازم تثبيت session ID معروف ثم إقناع الضحية بتسجيل "
                    "الدخول به.",
                    f"name='{name}', submitted='{attacker_value}', "
                    f"returned='{new_value}'",
                )
            else:
                self._log(f"  ✓ {name}: الـ server يولّد token جديد "
                          "(no fixation)", "success")

    # ============================================================
    #                PHASE 6 - SESSION TIMEOUT
    # ============================================================

    def _test_session_timeout(self):
        """يفحص مدة صلاحية الـ session token عبر Max-Age/Expires."""
        if not self.session_cookies:
            return
        url = self.target

        for c in self.session_cookies[:3]:
            attrs = c.get("attrs", {})
            name = c["name"]
            max_age = attrs.get("max-age")
            expires = attrs.get("expires")

            if max_age is None and expires is None:
                # لا TTL محدد → الـ session تبقى حتى إغلاق المتصفح
                self._add_finding(
                    "session_no_expiry",
                    "medium",
                    url,
                    f"Session Cookie '{name}' Has No Expiry",
                    "الـ cookie بدون Max-Age أو Expires - تبقى حتى إغلاق "
                    "المتصفح (session cookie). لا توجد إدارة TTL من جانب "
                    "الـ server في الـ cookie.",
                    f"name='{name}', attrs={attrs}",
                )
                continue

            # محاولة قراءة TTL
            ttl_seconds = None
            if max_age and isinstance(max_age, str):
                try:
                    ttl_seconds = int(max_age)
                except ValueError:
                    pass
            if ttl_seconds is None and expires and isinstance(expires, str):
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(expires)
                    if dt:
                        ttl_seconds = int(dt.timestamp() - time.time())
                except Exception:
                    pass

            if ttl_seconds is not None:
                if ttl_seconds > 86400 * 8:  # > 8 hours for session cookie
                    self._add_finding(
                        "session_timeout_too_long",
                        "medium",
                        url,
                        f"Session Cookie '{name}' TTL Too Long",
                        f"TTL = {ttl_seconds} ثانية ({ttl_seconds/3600:.1f}"
                        " ساعة). مدة صلاحية الـ session طويلة جداً تزيد "
                        "من نافذة الـ hijacking.",
                        f"name='{name}', ttl_seconds={ttl_seconds}, "
                        f"max_age={max_age}, expires={expires}",
                    )
                elif ttl_seconds < 60:
                    self._log(f"  › {name}: TTL قصير جداً ({ttl_seconds}s) - "
                              "قد يُرهق المستخدم", "info")
                else:
                    self._log(f"  ✓ {name}: TTL معقول ({ttl_seconds}s)",
                              "success")

        # اختياري: اختبار سلوكي للـ timeout عبر إعادة الطلب بعد انتظار
        if self.timeout_test_seconds > 0 and self.collected_tokens:
            self._log(f"  › اختبار سلوكي للـ timeout بعد انتظار "
                      f"{self.timeout_test_seconds}s...", "info")
            # خذ أول token وأعد اختباره بعد الانتظار
            t = self.collected_tokens[0]
            old_cookies = dict(self.client.session_cookies)
            self.client.session_cookies = {t["name"]: t["value"]}
            try:
                resp1 = self.client.request(self.target)
                time.sleep(self.timeout_test_seconds)
                resp2 = self.client.request(self.target)
            finally:
                self.client.session_cookies = old_cookies

            # إن تغيّر الرد بشكل كبير بعد الانتظار قد يعني انتهاء الصلاحية
            if resp1["status"] != resp2["status"] and \
                    resp1["status"] in (200, 302) and \
                    resp2["status"] in (401, 403, 302):
                self._log(f"  ✓ token انتهت صلاحيته بعد الانتظار", "success")
            else:
                self._log(f"  › token ما زال صالحاً بعد {self.timeout_test_seconds}s",
                          "info")

    # ============================================================
    #                PHASE 7 - SESSION REGENERATION
    # ============================================================

    def _test_session_regeneration(self):
        """يفحص إن كان الـ server يعيد توليد الـ token بين الطلبات."""
        if not self.session_cookies:
            return
        url = self.target

        # نجمع 5 عينات متتالية باستخدام نفس الـ client (cookies مستمرة)
        first_value = None
        regenerated = False
        old_cookies = dict(self.client.session_cookies)
        try:
            self.client.session_cookies = {}
            for i in range(5):
                resp = self.client.request(url)
                new_cookies = extract_cookies_from_response(resp)
                for nc in new_cookies:
                    if looks_like_session_cookie(nc["name"]):
                        if first_value is None:
                            first_value = nc["value"]
                        elif nc["value"] != first_value:
                            regenerated = True
                            self._log(f"  ✓ الـ token تغيّر بين الطلبات "
                                      f"(rotation#{i})", "success")
                            break
                if regenerated:
                    break
                time.sleep(0.2)
        finally:
            self.client.session_cookies = old_cookies

        if not regenerated and first_value:
            # الـ server لا ي.rotate تلقائياً
            # نتأكد عبر مقارنة عينات منفصلة
            self._log("  › الـ server لا يعيد توليد الـ token تلقائياً",
                      "info")
            # نتحقق إن كان نفس الـ value في كل مرة (potentially shared)
            # ملاحظة: هذا قد يكون سلوكاً صحيحاً (sticky session)
            # نضيف finding منخفض الخطورة فقط
            self._add_finding(
                "session_no_auto_rotation",
                "low",
                url,
                "Session Token Not Auto-Rotated",
                "الـ server يحافظ على نفس session token عبر الطلبات "
                "المتتالية. هذا قد يكون تصميماً صحيحاً لكنه يعني أن الـ "
                "token لا يُعاد توليده بعد عمليات حساسة تلقائياً.",
                f"sample_token='{first_value[:30]}', "
                f"requests_made=5",
            )

    # ============================================================
    #                PHASE 8 - CONCURRENT SESSIONS
    # ============================================================

    def _test_concurrent_sessions(self):
        """يفحص إن كان الـ server يسمح بجلسات متزامنة لنفس الـ client."""
        if not self.session_cookies:
            return
        url = self.target

        # نحصل على عينتين منفصلتين من نفس الـ client behavior
        resp1, cookies1 = self._fresh_client_request(url)
        time.sleep(0.5)
        resp2, cookies2 = self._fresh_client_request(url)

        session1 = None
        session2 = None
        for c in cookies1:
            if looks_like_session_cookie(c["name"]):
                session1 = c
                break
        for c in cookies2:
            if looks_like_session_cookie(c["name"]):
                session2 = c
                break

        if not session1 or not session2:
            return

        # إن كانت الـ tokens مختلفة وكلاهما صالح → concurrent sessions مسموحة
        # نتحقق بصلاحية token1 بعد توليد token2
        old_cookies = dict(self.client.session_cookies)
        self.client.session_cookies = {session1["name"]: session1["value"]}
        try:
            resp_check = self.client.request(url)
        finally:
            self.client.session_cookies = old_cookies

        if resp_check["status"] in (200, 302):
            # token1 ما زال صالحاً بعد توليد token2 → concurrent
            self._add_finding(
                "session_concurrent_allowed",
                "low",
                url,
                "Concurrent Sessions Allowed",
                "الـ server يسمح بجلسات متزامنة متعددة (الـ token القديم "
                "ما زال صالحاً بعد إصدار واحد جديد). قد يكون مقصوداً لكنه "
                "يزيد من نافذة الـ hijacking ويصعّب الـ logout الكامل.",
                f"token1='{session1['value'][:25]}', "
                f"token2='{session2['value'][:25]}', "
                f"token1_still_valid={resp_check['status'] in (200, 302)}",
            )
        else:
            self._log("  ✓ الـ server يبطل الجلسة السابقة عند إصدار واحدة "
                      "جديدة", "success")

    # ============================================================
    #                PHASE 9 - LOGOUT
    # ============================================================

    def _test_logout(self):
        """يفحص وظائف logout المتعددة."""
        if not self.session_cookies:
            return

        # نجمع عيّنة token للاختبار
        resp_init, cookies_init = self._fresh_client_request(self.target)
        session_token = None
        for c in cookies_init:
            if looks_like_session_cookie(c["name"]):
                session_token = c
                break
        if not session_token:
            return

        logout_tested = False
        for path in LOGOUT_PATHS:
            logout_url = self.base + path.lstrip("/")
            # نرسل الطلب بـ session cookie
            old_cookies = dict(self.client.session_cookies)
            self.client.session_cookies = {
                session_token["name"]: session_token["value"]
            }
            try:
                resp = self.client.request(logout_url, allow_redirects=False)
            finally:
                self.client.session_cookies = old_cookies

            if resp["status"] == 0:
                continue

            # إن وجدنا logout endpoint (200/302 وليس 404)
            if resp["status"] in (200, 301, 302, 303, 307):
                logout_tested = True
                self._log(f"  ✓ logout endpoint: {logout_url} "
                          f"(status={resp['status']})", "info")

                # نفحص إن أُبطلت الـ cookie
                new_cookies = extract_cookies_from_response(resp)
                invalidated = False
                for nc in new_cookies:
                    if nc["name"] == session_token["name"]:
                        # إما value فارغة أو Max-Age=0/Expires في الماضي
                        if not nc["value"] or \
                                nc["attrs"].get("max-age") == "0" or \
                                nc["attrs"].get("expires", "").lower() in (
                                    "thu, 01 jan 1970 00:00:00 gmt",
                                    "thu, 01 jan 1970 00:00:01 gmt"):
                            invalidated = True
                            break

                if not invalidated:
                    self._add_finding(
                        "session_logout_not_invalidated",
                        "medium",
                        logout_url,
                        "Logout Does Not Invalidate Session Cookie",
                        f"logout endpoint '{path}' لا يُبطل الـ session "
                        "cookie عبر Set-Cookie. الـ token القديم قد يبقى "
                        "صالحاً بعد الـ logout.",
                        f"path='{path}', status={resp['status']}, "
                        f"set_cookie_returned={len(new_cookies)}",
                    )

                # نعيد اختبار صلاحية الـ token بعد الـ logout
                old_cookies = dict(self.client.session_cookies)
                self.client.session_cookies = {
                    session_token["name"]: session_token["value"]
                }
                try:
                    resp_post = self.client.request(self.target)
                finally:
                    self.client.session_cookies = old_cookies

                if resp_post["status"] in (200, 302) and \
                        resp_post["status"] == resp_init["status"]:
                    self._add_finding(
                        "session_token_valid_after_logout",
                        "high",
                        logout_url,
                        "Session Token Still Valid After Logout",
                        f"بعد استدعاء logout endpoint '{path}'، الـ token "
                        "القديم ما زال يعمل. الـ logout لا يبطل الجلسة على "
                        "مستوى الـ server-side session store.",
                        f"path='{path}', post_logout_status="
                        f"{resp_post['status']}, pre_logout_status="
                        f"{resp_init['status']}",
                    )
                else:
                    self._log("  ✓ الـ token أُبطل بعد الـ logout", "success")

                break  # نكتفي بأول logout endpoint صالح

        if not logout_tested:
            self._log("  › لم يتم العثور على logout endpoint صريح",
                      "info")

    # ============================================================
    #                PHASE 10 - REMEMBER-ME
    # ============================================================

    def _test_remember_me(self):
        """يحلل remember-me tokens إن وُجدت."""
        # نجلب صفحة login (لأن remember-me عادة يُضبط بعد الـ login)
        remember_cookies = []
        for path in LOGIN_PATHS[:4]:
            login_url = self.base + path.lstrip("/")
            resp, cookies = self._fresh_client_request(login_url)
            if resp["status"] == 0:
                continue
            for c in cookies:
                if looks_like_remember_me(c["name"]):
                    remember_cookies.append(c)

        # أيضاً نفحص صفحة الـ target
        resp, cookies = self._fresh_client_request(self.target)
        for c in cookies:
            if looks_like_remember_me(c["name"]):
                remember_cookies.append(c)

        if not remember_cookies:
            self._log("  › لا توجد remember-me cookies", "info")
            return

        for c in remember_cookies:
            name = c["name"]
            value = c["value"]
            attrs = c.get("attrs", {})
            url = self.target

            # 1. بدون Secure
            if self.is_https and not attrs.get("secure"):
                self._add_finding(
                    "remember_me_no_secure",
                    "high",
                    url,
                    f"Remember-Me Cookie '{name}' Missing Secure",
                    "remember-me cookie بدون سمة Secure - تُرسل عبر HTTP "
                    "ويمكن اعتراضها. remember-me tokens طويلة العمر فيجب "
                    "أن تكون Secure دائماً.",
                    f"name='{name}', value_len={len(value)}, attrs={attrs}",
                )

            # 2. بدون HttpOnly
            if not attrs.get("httponly"):
                self._add_finding(
                    "remember_me_no_httponly",
                    "high",
                    url,
                    f"Remember-Me Cookie '{name}' Missing HttpOnly",
                    "remember-me cookie بدون HttpOnly - يمكن قراءتها عبر "
                    "JavaScript/XSS. الـ XSS هنا يعني account takeover "
                    "دائم.",
                    f"name='{name}', value_len={len(value)}",
                )

            # 3. TTL طويل جداً (> 90 يوم)
            max_age = attrs.get("max-age")
            if max_age and isinstance(max_age, str):
                try:
                    ma = int(max_age)
                    if ma > 86400 * 90:
                        self._add_finding(
                            "remember_me_long_ttl",
                            "medium",
                            url,
                            f"Remember-Me Cookie '{name}' TTL Too Long",
                            f"TTL = {ma} ثانية ({ma/86400:.0f} يوماً). "
                            "remember-me token طويل العمر يبقى خطراً لفترة "
                            "طويلة إن سُرق.",
                            f"name='{name}', ttl_seconds={ma}",
                        )
                except ValueError:
                    pass

            # 4. Entropy منخفضة
            ent = shannon_entropy(value)
            if value and (len(value) < 16 or ent < MIN_TOKEN_ENTROPY):
                self._add_finding(
                    "remember_me_weak_token",
                    "high",
                    url,
                    f"Remember-Me Cookie '{name}' Weak Token",
                    f"remember-me token قصيرة ({len(value)}) أو ضعيفة "
                    f"الـ entropy ({ent:.2f}). قد تكون قابلة للـ brute force "
                    "أو prediction.",
                    f"name='{name}', length={len(value)}, entropy={ent:.2f}, "
                    f"sample='{value[:30]}'",
                )

            # 5. تحليل بنية الـ token
            # إن كانت تحوي ':' أو '|' قد تكون user_id:hmac
            if ":" in value or "|" in value:
                parts = re.split(r'[:|]', value)
                if len(parts) >= 2:
                    self._add_finding(
                        "remember_me_structured",
                        "low",
                        url,
                        f"Remember-Me Cookie '{name}' Has Structure",
                        f"الـ token لها بنية (مفصولة بـ : أو |) قد تكشف "
                        "user_id أو timestamp. إن كان الجزء الأول قابل "
                        "للتخمين يمكن تزويرها.",
                        f"name='{name}', parts_count={len(parts)}, "
                        f"first_part_len={len(parts[0])}",
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
            "session_cookies": [
                {"name": c["name"], "value_len": len(c["value"]),
                 "attrs": c.get("attrs", {})}
                for c in self.session_cookies
            ],
            "collected_tokens": [
                {"name": t["name"], "value_len": len(t["value"]),
                 "entropy": round(shannon_entropy(t["value"]), 3),
                 "charset": charset_class(t["value"])}
                for t in self.collected_tokens
            ],
            "findings": self.findings,
            "stats": self._stats_dict(),
        }

    def _print_results(self):
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🍪 تقرير فحص أمان الجلسات"
              f"{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")

        if self.session_cookies:
            print(f"\n  {Colors.BOLD}Session cookies المكتشفة "
                  f"({len(self.session_cookies)}):{Colors.NC}")
            for c in self.session_cookies[:8]:
                attrs = c.get("attrs", {})
                sec = "🔒" if attrs.get("secure") else "⚠️"
                ht = "🛡️" if attrs.get("httponly") else "⚠️"
                ss = attrs.get("samesite", "?") if isinstance(
                    attrs.get("samesite"), str) else "?"
                print(f"    {Colors.CYAN}•{Colors.NC} {c['name']} "
                      f"({len(c['value'])} chars) "
                      f"{sec}{ht} SameSite={ss}")

        if self.collected_tokens:
            print(f"\n  {Colors.BOLD}Tokens تم تحليلها "
                  f"({len(self.collected_tokens)}):{Colors.NC}")
            by_name: Dict[str, List[str]] = {}
            for t in self.collected_tokens:
                by_name.setdefault(t["name"], []).append(t["value"])
            for name, vals in by_name.items():
                ent = sum(shannon_entropy(v) for v in vals) / len(vals)
                print(f"    {Colors.CYAN}•{Colors.NC} {name}: "
                      f"avg_len={sum(len(v) for v in vals)/len(vals):.1f}, "
                      f"avg_entropy={ent:.2f}, unique={len(set(vals))}/"
                      f"{len(vals)}")

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
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات جلسات واضحة"
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
        user_agent=args.user_agent or "ghostpwn-session/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=True,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="session_security",
        description="ghostpwn - Session Management Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 session_security.py https://example.com\n"
            "  python3 session_security.py https://example.com --verbose\n"
            "  python3 session_security.py https://example.com "
            "--samples 15\n"
            "  python3 session_security.py https://example.com "
            "--timeout-test 30 --json-out session-report.json\n\n"
            "Note: يحلل الـ cookies و الـ tokens دون إجراء login."
        ),
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--timeout", type=int, default=12,
                        help="HTTP timeout in seconds (default 12)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests (default 0.1)")
    parser.add_argument("--user-agent", default=None,
                        help="Custom User-Agent")
    parser.add_argument("--proxy", default=None,
                        help="HTTP(S) proxy URL")
    parser.add_argument("--cookie", default=None,
                        help="Cookie header (skip cookie collection)")
    parser.add_argument("--samples", type=int, default=8,
                        help="Number of token samples to collect (default 8)")
    parser.add_argument("--timeout-test", type=int, default=0,
                        help="Seconds to wait before re-testing token "
                             "validity (default 0 = skip)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["cookies", "tokens",
                                            "prediction", "fixation",
                                            "timeout", "regeneration",
                                            "concurrent", "logout",
                                            "rememberme", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_demo_client(args)
    scanner = SessionSecurityScanner(
        http_client=client,
        options={
            "verbose": args.verbose,
            "token_sample_size": args.samples,
            "timeout_test_seconds": args.timeout_test,
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


def _patch_only(scanner: "SessionSecurityScanner", only: str):
    """يخطّي كل الفحوصات ما عدا المطلوبة."""
    skip_map = {
        "cookies": ["_collect_token_samples", "_analyze_token_quality",
                     "_test_token_prediction", "_test_session_fixation",
                     "_test_session_timeout", "_test_session_regeneration",
                     "_test_concurrent_sessions", "_test_logout",
                     "_test_remember_me"],
        "tokens": ["_test_token_prediction", "_test_session_fixation",
                    "_test_session_timeout", "_test_session_regeneration",
                    "_test_concurrent_sessions", "_test_logout",
                    "_test_remember_me"],
        "prediction": ["_analyze_cookie_attributes",
                        "_test_session_fixation", "_test_session_timeout",
                        "_test_session_regeneration",
                        "_test_concurrent_sessions", "_test_logout",
                        "_test_remember_me"],
        "fixation": ["_analyze_cookie_attributes",
                      "_collect_token_samples", "_analyze_token_quality",
                      "_test_token_prediction", "_test_session_timeout",
                      "_test_session_regeneration",
                      "_test_concurrent_sessions", "_test_logout",
                      "_test_remember_me"],
        "timeout": ["_analyze_cookie_attributes",
                     "_collect_token_samples", "_analyze_token_quality",
                     "_test_token_prediction", "_test_session_fixation",
                     "_test_session_regeneration",
                     "_test_concurrent_sessions", "_test_logout",
                     "_test_remember_me"],
        "regeneration": ["_analyze_cookie_attributes",
                          "_collect_token_samples",
                          "_analyze_token_quality",
                          "_test_token_prediction", "_test_session_fixation",
                          "_test_session_timeout",
                          "_test_concurrent_sessions", "_test_logout",
                          "_test_remember_me"],
        "concurrent": ["_analyze_cookie_attributes",
                        "_collect_token_samples", "_analyze_token_quality",
                        "_test_token_prediction", "_test_session_fixation",
                        "_test_session_timeout",
                        "_test_session_regeneration", "_test_logout",
                        "_test_remember_me"],
        "logout": ["_analyze_cookie_attributes",
                    "_collect_token_samples", "_analyze_token_quality",
                    "_test_token_prediction", "_test_session_fixation",
                    "_test_session_timeout",
                    "_test_session_regeneration",
                    "_test_concurrent_sessions", "_test_remember_me"],
        "rememberme": ["_analyze_cookie_attributes",
                        "_collect_token_samples",
                        "_analyze_token_quality",
                        "_test_token_prediction", "_test_session_fixation",
                        "_test_session_timeout",
                        "_test_session_regeneration",
                        "_test_concurrent_sessions", "_test_logout"],
    }
    for name in skip_map.get(only, []):
        def _noop(*a, **kw):
            return None
        setattr(scanner, name, _noop)


if __name__ == "__main__":
    main()
