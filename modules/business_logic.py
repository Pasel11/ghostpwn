#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Business Logic Vulnerability Scanner
فحص ثغرات المنطق التجاري (Business Logic Vulnerabilities)

الفحوصات:
1.  Price manipulation testing
2.  Quantity manipulation testing (negative / zero / huge values)
3.  Discount / coupon abuse testing
4.  Workflow bypass testing (skipping steps)
5.  Trust boundary violation testing
6.  Rate limiting on business functions
7.  Negative value testing
8.  Integer overflow testing
9.  Currency manipulation
10. Tax calculation bypass
11. Shipping fee bypass
12. Free trial abuse detection
13. Refund / repeat operation testing

ملاحظات:
- لا يستخدم أي مكتبات خارجية (Python stdlib فقط).
- الفحوصات non-destructive قدر الإمكان: لا يكمل الطلبات الفعلية،
  بل يكتشف بوجود أو غياب التحقق من القيم.
- يكتشف ويفحص دون تنفيذ هجمات خطيرة (لا يُتمم عمليات شراء فعلية).
"""
import os
import sys
import re
import json
import time
import hashlib
import random
import string
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# Common cart / checkout / order endpoints to probe
CART_PATHS = [
    "/cart", "/cart/add", "/cart/update", "/cart/remove",
    "/checkout", "/checkout/cart", "/checkout/summary",
    "/order", "/orders", "/order/create", "/order/place",
    "/api/cart", "/api/cart/add", "/api/cart/update",
    "/api/order", "/api/orders", "/api/orders/create",
    "/api/checkout", "/api/checkout/cart",
    "/shop/cart", "/shop/checkout", "/shop/order",
    "/basket", "/basket/add", "/basket/update",
    "/add-to-cart", "/add_to_cart",
]

# Common coupon / discount endpoints
COUPON_PATHS = [
    "/coupon", "/coupons", "/coupon/apply", "/coupon/validate",
    "/discount", "/discounts", "/discount/apply",
    "/promo", "/promo/apply", "/promocode", "/promo-code",
    "/api/coupon", "/api/coupon/apply", "/api/coupon/validate",
    "/api/discount", "/api/discount/apply",
    "/api/promo", "/api/promo/apply",
    "/cart/coupon", "/checkout/coupon",
]

# Common refund / cancellation endpoints
REFUND_PATHS = [
    "/refund", "/refunds", "/refund/request", "/refund/create",
    "/order/refund", "/order/cancel", "/orders/cancel",
    "/api/refund", "/api/refunds", "/api/refund/create",
    "/api/order/refund", "/api/order/cancel",
    "/return", "/returns", "/return/create",
]

# Common trial / subscription endpoints
TRIAL_PATHS = [
    "/trial", "/trial/start", "/trial/signup", "/trial/extend",
    "/subscribe", "/subscription", "/subscriptions",
    "/subscribe/trial", "/api/subscribe", "/api/subscription",
    "/api/subscriptions", "/api/subscription/create",
    "/api/trial", "/api/trial/start",
    "/upgrade", "/api/upgrade",
    "/plan", "/api/plan", "/api/plans",
]

# Common business workflow endpoints (multi-step)
WORKFLOW_PATHS = [
    "/register", "/signup", "/api/register", "/api/signup",
    "/login", "/api/login", "/api/auth/login",
    "/verify", "/verify-email", "/api/verify",
    "/reset-password", "/api/reset-password", "/api/password/reset",
    "/mfa", "/mfa/setup", "/mfa/verify", "/api/mfa",
    "/onboarding", "/onboarding/step", "/api/onboarding",
    "/kyc", "/kyc/verify", "/api/kyc",
]

# Parameter names typically used for business logic
PRICE_PARAMS = ["price", "amount", "total", "subtotal", "cost",
                "fee", "fees", "value", "charge"]
QUANTITY_PARAMS = ["qty", "quantity", "count", "num", "number",
                   "items_count", "amount"]
DISCOUNT_PARAMS = ["discount", "coupon", "coupon_code", "promo",
                   "promo_code", "voucher", "voucher_code", "code"]
CURRENCY_PARAMS = ["currency", "curr", "currency_code", "ccy"]
TAX_PARAMS = ["tax", "tax_rate", "vat", "gst", "vat_rate"]
SHIPPING_PARAMS = ["shipping", "shipping_fee", "shipping_cost",
                   "delivery_fee", "shipping_method", "shipping_rate"]
USER_ID_PARAMS = ["user_id", "userId", "uid", "account_id", "accountId",
                  "customer_id", "customerId"]

# Test values for quantity / price manipulation
NEGATIVE_VALUES = ["-1", "-10", "-100", "-0.01", "-9999"]
ZERO_VALUES = ["0", "0.0", "0.00", "-0"]
HUGE_VALUES = ["999999999", "2147483647", "2147483648",
               "9999999999999", "1e10", "1e308"]
INT_OVERFLOW_VALUES = [
    "2147483647",         # INT_MAX (32-bit signed)
    "2147483648",         # INT_MAX + 1
    "4294967295",         # UINT_MAX (32-bit)
    "4294967296",         # UINT_MAX + 1
    "9223372036854775807",   # INT64_MAX
    "9223372036854775808",   # INT64_MAX + 1
    "18446744073709551615",  # UINT64_MAX
    "99999999999999999999999999",  # definitely overflows
]
DECIMAL_PRECISION_VALUES = ["0.001", "0.0001", "0.00001",
                            "1.999", "9.999999", "0.5"]

# Common coupon codes to try
COMMON_COUPONS = [
    "WELCOME", "WELCOME10", "FIRST10", "NEWUSER", "NEW10",
    "SAVE10", "SAVE20", "SAVE50", "DISCOUNT10", "DISCOUNT50",
    "FREE", "FREE100", "FREESHIP", "100OFF", "100PCT",
    "ADMIN", "TEST", "DEMO", "PROMO", "PROMO10",
    "BLACKFRIDAY", "CYBERMONDAY", "HOLIDAY", "XMAS",
    "VIP", "VVIP", "EMPLOYEE", "STAFF", "INTERNAL",
    "GHOSTPWN", "BUG", "BUG10", "TEST100",
]

# Severity
SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


# ============================ Main Class ============================

class BusinessLogicScanner:
    """فاحص ثغرات المنطق التجاري"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=12, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self._scanned: Set[str] = set()

        # Discovered endpoints / params
        self.cart_endpoints: List[str] = []
        self.coupon_endpoints: List[str] = []
        self.refund_endpoints: List[str] = []
        self.trial_endpoints: List[str] = []
        self.workflow_endpoints: List[str] = []
        self.discovered_params: Dict[str, Set[str]] = {}

        # Tunables
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)
        self.rate_limit_requests = self.options.get("rate_limit_requests", 20)
        self.max_coupon_attempts = self.options.get("max_coupon_attempts", 30)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[BIZLOGIC] {msg}", level)

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

    def _req(self, url: str, method: str = "GET",
             headers: Optional[Dict] = None, data=None,
             json_data: Optional[Dict] = None) -> Dict:
        try:
            return self.client.request(url, method=method, headers=headers,
                                       data=data, json_data=json_data)
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "",
                    "url": url, "elapsed": 0, "error": str(e)}

    @staticmethod
    def _short(text: str, n: int = 200) -> str:
        if not text:
            return ""
        text = text.replace("\n", " ").strip()
        return text if len(text) <= n else text[:n] + "..."

    @staticmethod
    def _safe_json(text: str):
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _looks_like_json(text: str) -> bool:
        if not text:
            return False
        b = text.lstrip()
        return b.startswith("{") or b.startswith("[")

    def _gen_token(self, n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    @staticmethod
    def _extract_amount(body: str, key: str = "total") -> Optional[float]:
        """Extract a numeric amount from a JSON response by key."""
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            # Try regex extraction
            m = re.search(rf'"{key}"\s*:\s*([0-9.]+)', body)
            if m:
                try:
                    return float(m.group(1))
                except ValueError:
                    return None
            return None
        if isinstance(data, dict):
            for k in [key, key.capitalize(), key.upper(),
                      key.lower(), f"order_{key}", f"cart_{key}"]:
                if k in data:
                    try:
                        return float(data[k])
                    except (ValueError, TypeError):
                        continue
            # nested
            for v in data.values():
                if isinstance(v, dict):
                    for k in [key, key.capitalize(), key.upper()]:
                        if k in v:
                            try:
                                return float(v[k])
                            except (ValueError, TypeError):
                                continue
        return None

    # ============================================================
    #                       MAIN SCAN
    # ============================================================
    def scan(self, target: str) -> Dict:
        """نقطة الدخول الرئيسية"""
        if not target:
            self._log("Target فارغ", "error")
            return {"target": target, "findings": [], "stats": {}}

        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        target = target.rstrip("/")
        self._log(f"بدء فحص ثغرات المنطق التجاري: {target}", "phase")

        parsed = urlparse(target)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.netloc.split(":")[0]
        self.target = target

        # ---------- Phase 0: Reconnaissance ----------
        self._log("Phase 0: اكتشاف business endpoints", "phase")
        self._discover_business_endpoints()

        # ---------- Phase 1: Price manipulation ----------
        self._log("Phase 1: Price manipulation", "phase")
        self._test_price_manipulation()

        # ---------- Phase 2: Quantity manipulation ----------
        self._log("Phase 2: Quantity manipulation", "phase")
        self._test_quantity_manipulation()

        # ---------- Phase 3: Discount / coupon abuse ----------
        self._log("Phase 3: Discount / coupon abuse", "phase")
        self._test_coupon_abuse()

        # ---------- Phase 4: Workflow bypass ----------
        self._log("Phase 4: Workflow bypass", "phase")
        self._test_workflow_bypass()

        # ---------- Phase 5: Trust boundary violations ----------
        self._log("Phase 5: Trust boundary violations", "phase")
        self._test_trust_boundary_violations()

        # ---------- Phase 6: Rate limiting ----------
        self._log("Phase 6: Rate limiting on business functions", "phase")
        self._test_rate_limiting()

        # ---------- Phase 7: Negative value testing ----------
        self._log("Phase 7: Negative value testing", "phase")
        self._test_negative_values()

        # ---------- Phase 8: Integer overflow ----------
        self._log("Phase 8: Integer overflow", "phase")
        self._test_integer_overflow()

        # ---------- Phase 9: Currency manipulation ----------
        self._log("Phase 9: Currency manipulation", "phase")
        self._test_currency_manipulation()

        # ---------- Phase 10: Tax bypass ----------
        self._log("Phase 10: Tax calculation bypass", "phase")
        self._test_tax_bypass()

        # ---------- Phase 11: Shipping fee bypass ----------
        self._log("Phase 11: Shipping fee bypass", "phase")
        self._test_shipping_bypass()

        # ---------- Phase 12: Free trial abuse ----------
        self._log("Phase 12: Free trial abuse", "phase")
        self._test_free_trial_abuse()

        # ---------- Phase 13: Refund / repeat operations ----------
        self._log("Phase 13: Refund / repeat operations", "phase")
        self._test_refund_repeat()

        self._print_results()
        return self._build_report()

    # ============================================================
    #        PHASE 0 — Endpoint discovery
    # ============================================================
    def _discover_business_endpoints(self):
        """Probe common business endpoints and record the ones that respond."""
        all_paths = {
            "cart": CART_PATHS,
            "coupon": COUPON_PATHS,
            "refund": REFUND_PATHS,
            "trial": TRIAL_PATHS,
            "workflow": WORKFLOW_PATHS,
        }
        for kind, paths in all_paths.items():
            self._log(f"  › استكشاف {kind} endpoints")
            for path in paths:
                url = self.base + path
                # Quick HEAD first
                r = self._req(url, method="GET")
                if r["status"] == 0:
                    continue
                # 200 / 302 / 401 / 403 means endpoint exists
                if r["status"] in (200, 301, 302, 401, 403, 405, 400, 422):
                    target_list = getattr(self, f"{kind}_endpoints")
                    target_list.append(url)
                    self._log(f"  • {kind} endpoint: {url} "
                              f"(HTTP {r['status']})", "info")
                    # Extract params from the response
                    self._extract_params_from_response(url, r)
                    # Stop after a few hits per kind to keep the scan fast
                    if len(target_list) >= 5:
                        break

    def _extract_params_from_response(self, url: str, resp: Dict):
        """Extract parameter names from HTML form / JSON response."""
        body = resp.get("body", "") or ""
        params = set()
        # HTML form fields
        for m in re.finditer(
            r'<(?:input|select|textarea)[^>]+name=["\']([^"\']+)["\']',
            body, re.IGNORECASE):
            params.add(m.group(1))
        # JSON keys
        if self._looks_like_json(body):
            data = self._safe_json(body)
            if isinstance(data, dict):
                params.update(data.keys())
        if params:
            self.discovered_params[url] = params

    # ============================================================
    #        PHASE 1 — Price manipulation
    # ============================================================
    def _test_price_manipulation(self):
        """Test if the server accepts a client-supplied price in
        cart / order requests (should always be server-calculated)."""
        self._log("  › اختبار price manipulation")
        for url in self.cart_endpoints[:5]:
            # Try POSTing price parameters directly
            for param in PRICE_PARAMS:
                test_value = "0.01"  # tiny price
                data = {param: test_value}
                r = self._req(url, method="POST", data=data)
                if r["status"] == 0:
                    continue
                # Check the response — does it accept our price?
                body = r["body"] or ""
                if self._looks_like_json(body):
                    data_resp = self._safe_json(body) or {}
                    # If the server echoes back the price we sent or
                    # computes a total based on it, the price is
                    # client-controlled — vulnerability.
                    for echo_key in [param, f"order_{param}",
                                     f"cart_{param}", "total", "subtotal"]:
                        if echo_key in data_resp:
                            try:
                                echoed = float(data_resp[echo_key])
                                if abs(echoed - float(test_value)) < 0.01:
                                    self._add_finding(
                                        ftype="price_manipulation",
                                        severity=SEV_CRITICAL,
                                        url=url,
                                        title=f"Server accepts client-supplied price (param '{param}')",
                                        description=(
                                            f"The endpoint at {url} accepted "
                                            f"a client-supplied '{param}' "
                                            f"parameter and used it to compute "
                                            f"the order total. An attacker "
                                            f"can place orders at any price "
                                            f"(e.g. 0.01) — direct financial "
                                            f"loss."
                                        ),
                                        evidence=f"sent {param}={test_value}, "
                                                 f"response echoed {echo_key}={echoed}",
                                        param=param,
                                    )
                                    break
                            except (ValueError, TypeError):
                                continue

                # Also try via JSON
                if "application/json" in (r["headers"].get("Content-Type", "") or
                                          r["headers"].get("content-type", "")):
                    r2 = self._req(url, method="POST",
                                   json_data={param: test_value})
                    if r2["status"] == 200 and self._looks_like_json(r2["body"]):
                        d = self._safe_json(r2["body"]) or {}
                        for ek in [param, "total", "subtotal"]:
                            if ek in d:
                                try:
                                    if abs(float(d[ek]) - float(test_value)) < 0.01:
                                        self._add_finding(
                                            ftype="price_manipulation",
                                            severity=SEV_CRITICAL,
                                            url=url,
                                            title=f"Server accepts JSON price (param '{param}')",
                                            description=(
                                                f"The endpoint at {url} "
                                                f"accepts '{param}' as JSON "
                                                f"and uses it for the total."
                                            ),
                                            evidence=f"JSON {param}={test_value} → echoed {ek}={d[ek]}",
                                            param=param,
                                        )
                                        break
                                except (ValueError, TypeError):
                                    continue

    # ============================================================
    #        PHASE 2 — Quantity manipulation
    # ============================================================
    def _test_quantity_manipulation(self):
        """Test if the server accepts negative / zero / huge quantity
        values without validation."""
        self._log("  › اختبار quantity manipulation")
        for url in self.cart_endpoints[:5]:
            for param in QUANTITY_PARAMS:
                # Negative quantity — could give money back or zero the cart
                for val in NEGATIVE_VALUES[:2]:
                    r = self._req(url, method="POST", data={param: val})
                    if r["status"] == 0:
                        continue
                    # A 200/201 response with no validation error suggests
                    # the negative value was accepted
                    body = r["body"] or ""
                    if r["status"] in (200, 201) and \
                            not self._indicates_error(body, "negative"):
                        # Try to confirm by extracting the total
                        total = self._extract_amount(body, "total")
                        if total is not None and total < 0:
                            self._add_finding(
                                ftype="negative_quantity",
                                severity=SEV_CRITICAL,
                                url=url,
                                title=f"Negative quantity accepted (param '{param}')",
                                description=(
                                    f"The endpoint at {url} accepted "
                                    f"quantity='{val}' and computed a "
                                    f"negative total ({total}). An attacker "
                                    f"can use this to receive money back or "
                                    f"to zero out the cart total."
                                ),
                                evidence=f"qty={val} → total={total}",
                                param=param,
                            )
                        else:
                            self._add_finding(
                                ftype="negative_quantity",
                                severity=SEV_HIGH,
                                url=url,
                                title=f"Negative quantity not rejected (param '{param}')",
                                description=(
                                    f"The endpoint at {url} accepted "
                                    f"quantity='{val}' without a 400 / "
                                    f"validation error. Even if the total "
                                    f"didn't go negative, this indicates "
                                    f"missing server-side validation."
                                ),
                                evidence=f"qty={val} → status={r['status']}",
                                param=param,
                            )
                        break  # one negative-value finding is enough per param

                # Huge quantity — integer overflow / DoS
                for val in HUGE_VALUES[:2]:
                    r = self._req(url, method="POST", data={param: val})
                    if r["status"] == 0:
                        continue
                    if r["status"] in (200, 201):
                        body = r["body"] or ""
                        total = self._extract_amount(body, "total")
                        # If total wrapped around (e.g. negative or 0), it's
                        # an integer overflow
                        if total is not None and (total < 0 or total == 0):
                            self._add_finding(
                                ftype="integer_overflow_quantity",
                                severity=SEV_CRITICAL,
                                url=url,
                                title=f"Integer overflow via quantity (param '{param}')",
                                description=(
                                    f"The endpoint at {url} accepted "
                                    f"quantity='{val}' and computed a "
                                    f"total of {total} — likely an "
                                    f"integer overflow. Attackers can use "
                                    f"this to bypass price checks or zero "
                                    f"out carts."
                                ),
                                evidence=f"qty={val} → total={total}",
                                param=param,
                            )
                            break

                # Zero quantity — should be rejected
                for val in ZERO_VALUES[:2]:
                    r = self._req(url, method="POST", data={param: val})
                    if r["status"] == 0:
                        continue
                    if r["status"] in (200, 201) and \
                            not self._indicates_error(r["body"] or "", "zero"):
                        self._add_finding(
                            ftype="zero_quantity",
                            severity=SEV_LOW,
                            url=url,
                            title=f"Zero quantity accepted (param '{param}')",
                            description=(
                                f"The endpoint at {url} accepted "
                                f"quantity='{val}'. Zero-quantity orders "
                                f"can be used to confuse inventory systems "
                                f"or to test fraud detection."
                            ),
                            evidence=f"qty={val} → status={r['status']}",
                            param=param,
                        )
                        break

    @staticmethod
    def _indicates_error(body: str, hint: str = "") -> bool:
        """Heuristic: does the response body indicate a validation error?"""
        if not body:
            return False
        low = body.lower()
        error_markers = ["error", "invalid", "not allowed", "denied",
                         "rejected", "validation", "required",
                         "must be", "cannot", "forbidden"]
        # Also hint-specific markers
        if hint == "negative":
            error_markers += ["negative", "must be positive",
                              "must be greater than", "at least 1",
                              "min ", "minimum"]
        elif hint == "zero":
            error_markers += ["zero", "must be greater than 0",
                              "at least 1", "min "]
        return any(m in low for m in error_markers)

    # ============================================================
    #        PHASE 3 — Coupon / discount abuse
    # ============================================================
    def _test_coupon_abuse(self):
        """Brute-force common coupon codes and test for re-use / stacking."""
        self._log("  › اختبار coupon abuse")
        for url in self.coupon_endpoints[:3]:
            # Try common coupons
            applied_coupons = []
            for code in COMMON_COUPONS[:self.max_coupon_attempts]:
                r = self._req(url, method="POST",
                              data={"code": code, "coupon": code,
                                    "coupon_code": code})
                if r["status"] == 0:
                    continue
                body = r["body"] or ""
                # Check if coupon was accepted (look for discount applied)
                if r["status"] in (200, 201):
                    data = self._safe_json(body) or {}
                    discount = 0
                    for k in ["discount", "discount_amount", "amount_off",
                              "discount_value"]:
                        if k in data:
                            try:
                                discount = float(data[k])
                                break
                            except (ValueError, TypeError):
                                continue
                    if discount > 0 or "applied" in body.lower() or \
                            "valid" in body.lower() and "invalid" not in body.lower():
                        applied_coupons.append(code)
                        self._add_finding(
                            ftype="coupon_brute_force",
                            severity=SEV_HIGH,
                            url=url,
                            title=f"Coupon code '{code}' accepted via brute force",
                            description=(
                                f"The endpoint at {url} accepted coupon "
                                f"'{code}' without rate limiting or "
                                f"CAPTCHA. An attacker can brute-force "
                                f"common coupon codes to apply unintended "
                                f"discounts."
                            ),
                            evidence=f"code={code} → discount={discount}",
                            coupon=code,
                        )

            # Test coupon re-use (apply same coupon twice)
            if applied_coupons:
                code = applied_coupons[0]
                r1 = self._req(url, method="POST",
                               data={"code": code, "coupon_code": code})
                r2 = self._req(url, method="POST",
                               data={"code": code, "coupon_code": code})
                if r1["status"] in (200, 201) and r2["status"] in (200, 201):
                    # Check if both succeeded
                    d1 = self._extract_amount(r1["body"], "discount") or 0
                    d2 = self._extract_amount(r2["body"], "discount") or 0
                    if d1 > 0 and d2 > 0:
                        self._add_finding(
                            ftype="coupon_reuse",
                            severity=SEV_HIGH,
                            url=url,
                            title=f"Coupon '{code}' can be applied multiple times",
                            description=(
                                f"The same coupon code '{code}' was "
                                f"accepted twice in a row. Coupon re-use "
                                f"can lead to stacking discounts beyond "
                                f"intended limits."
                            ),
                            evidence=f"first apply: discount={d1}, "
                                     f"second apply: discount={d2}",
                            coupon=code,
                        )

            # Test coupon stacking (multiple different coupons)
            if len(applied_coupons) >= 2:
                # Apply coupon 1, then coupon 2 to the same cart
                # (this requires session state — best-effort)
                self._log(f"  • {len(applied_coupons)} coupons تم تطبيقها — "
                          f"stacking test غير متاح بدون session", "info")

    # ============================================================
    #        PHASE 4 — Workflow bypass
    # ============================================================
    def _test_workflow_bypass(self):
        """Test if multi-step workflows (registration, checkout) can
        be skipped by directly hitting the final step."""
        self._log("  › اختبار workflow bypass")
        # Try common multi-step bypass: hit the final step directly
        # without completing prior steps.
        # Pattern: try /verify without /signup, or /reset-password without
        # /forgot-password, etc.
        bypass_tests = [
            # (skip-from, skip-to, expected-block)
            ("/signup", "/verify?token=any", "verify"),
            ("/register", "/verify-email?code=any", "verify-email"),
            ("/forgot-password", "/reset-password?token=any", "reset"),
            ("/cart", "/checkout/place", "place order"),
            ("/checkout/cart", "/checkout/confirm", "confirm"),
        ]
        for from_path, to_path, desc in bypass_tests:
            url = self.base + to_path
            r = self._req(url)
            if r["status"] == 0:
                continue
            # If the endpoint accepted the request (200) without redirecting
            # to the prior step, it's likely a workflow bypass.
            if r["status"] == 200 and \
                    not self._indicates_error(r["body"] or "", ""):
                # Heuristic: look for the action succeeding (e.g. "verified",
                # "order placed", "password reset")
                body_low = (r["body"] or "").lower()
                success_markers = ["verified", "success", "complete",
                                   "confirmed", "placed", "reset", "done",
                                   "thank you", "welcome", "activated"]
                if any(m in body_low for m in success_markers):
                    self._add_finding(
                        ftype="workflow_bypass",
                        severity=SEV_HIGH,
                        url=url,
                        title=f"Workflow bypass: '{desc}' without prior step",
                        description=(
                            f"The endpoint at {url} accepted a direct "
                            f"request without completing the prior step "
                            f"('{from_path}'). This indicates the server "
                            f"does not enforce workflow order — attackers "
                            f"can skip verification, payment, or KYC steps."
                        ),
                        evidence=f"direct GET {to_path} → status={r['status']}, "
                                 f"body suggests success",
                        skipped_step=from_path,
                    )

    # ============================================================
    #        PHASE 5 — Trust boundary violations
    # ============================================================
    def _test_trust_boundary_violations(self):
        """Test if user-supplied user_id / role parameters are trusted."""
        self._log("  › اختبار trust boundary violations")
        # Test user-supplied user_id parameters
        for url in self.cart_endpoints[:3] + self.workflow_endpoints[:3]:
            for param in USER_ID_PARAMS:
                # Try changing user_id to another user (1, 0, admin)
                for val in ["1", "0", "admin", "-1"]:
                    r = self._req(url, method="POST",
                                  data={param: val})
                    if r["status"] == 0:
                        continue
                    body = r["body"] or ""
                    # If response returns data for a different user, IDOR
                    if r["status"] in (200, 201):
                        data = self._safe_json(body) or {}
                        # Look for echo of user_id
                        for k in [param, "user", "customer", "owner"]:
                            if k in data:
                                try:
                                    if str(data[k]) == str(val):
                                        self._add_finding(
                                            ftype="trust_boundary_user_id",
                                            severity=SEV_HIGH,
                                            url=url,
                                            title=f"Client-supplied {param} trusted by server",
                                            description=(
                                                f"The endpoint at {url} "
                                                f"accepted a client-supplied "
                                                f"'{param}' parameter and "
                                                f"used it to identify the "
                                                f"user. This is a trust "
                                                f"boundary violation — "
                                                f"users can impersonate "
                                                f"each other by changing "
                                                f"the ID."
                                            ),
                                            evidence=f"sent {param}={val}, "
                                                     f"server used it as user identity",
                                            param=param,
                                        )
                                        break
                                except (ValueError, TypeError):
                                    continue
                        break  # one value is enough per param

        # Test role / isAdmin parameters
        for url in self.workflow_endpoints[:3]:
            for param in ["role", "isAdmin", "is_admin", "admin", "tier",
                          "plan", "permissions", "user_type", "userType"]:
                for val in ["admin", "true", "1", "root", "superuser",
                            "premium", "vip", "enterprise"]:
                    r = self._req(url, method="POST",
                                  data={param: val})
                    if r["status"] == 0:
                        continue
                    if r["status"] in (200, 201):
                        body_low = (r["body"] or "").lower()
                        # If the response suggests the role was applied
                        if val.lower() in body_low and \
                                ("admin" in body_low or "premium" in body_low
                                 or "vip" in body_low or "role" in body_low):
                            self._add_finding(
                                ftype="trust_boundary_role",
                                severity=SEV_HIGH,
                                url=url,
                                title=f"Client-supplied role parameter '{param}' trusted",
                                description=(
                                    f"The endpoint at {url} accepted "
                                    f"'{param}={val}' from the client. "
                                    f"If the server applies this role to "
                                    f"the user, an attacker can self-"
                                    f"escalate privileges."
                                ),
                                evidence=f"sent {param}={val} → status={r['status']}",
                                param=param,
                            )
                            break

    # ============================================================
    #        PHASE 6 — Rate limiting
    # ============================================================
    def _test_rate_limiting(self):
        """Test if business-critical endpoints enforce rate limits."""
        self._log("  › اختبار rate limiting")
        # Test on login, coupon, refund, trial endpoints
        test_endpoints = []
        for kind in ["workflow", "coupon", "refund", "trial"]:
            lst = getattr(self, f"{kind}_endpoints", [])
            test_endpoints.extend(lst[:2])

        for url in test_endpoints:
            self._log(f"  • rate-limit test على {url}")
            statuses = []
            start = time.time()
            for i in range(self.rate_limit_requests):
                r = self._req(url, method="POST",
                              data={"test": str(i), "_": str(i)})
                statuses.append(r["status"])
                if r["status"] == 429:
                    # Rate limited — good
                    break
            elapsed = time.time() - start
            # If we made all requests without 429, no rate limit
            if 429 not in statuses and len(statuses) == self.rate_limit_requests:
                self._add_finding(
                    ftype="missing_rate_limit",
                    severity=SEV_MEDIUM,
                    url=url,
                    title=f"No rate limiting on business endpoint: {url}",
                    description=(
                        f"The endpoint at {url} accepted "
                        f"{self.rate_limit_requests} rapid-fire requests "
                        f"in {elapsed:.1f}s without returning 429 Too Many "
                        f"Requests. Missing rate limits enable brute-force "
                        f"attacks (coupons, login), coupon abuse, and DoS."
                    ),
                    evidence=f"{len(statuses)} requests → no 429, "
                             f"elapsed={elapsed:.1f}s",
                    requests_made=len(statuses),
                )

    # ============================================================
    #        PHASE 7 — Negative value testing (general)
    # ============================================================
    def _test_negative_values(self):
        """Send negative values to numeric parameters across all
        discovered endpoints."""
        self._log("  › اختبار negative values (عام)")
        all_urls = (self.cart_endpoints + self.coupon_endpoints +
                    self.refund_endpoints + self.trial_endpoints)
        for url in all_urls[:8]:
            params = self.discovered_params.get(url, set())
            # Filter numeric-looking params
            numeric_params = [p for p in params if
                              any(np in p.lower() for np in
                                  PRICE_PARAMS + QUANTITY_PARAMS +
                                  TAX_PARAMS + SHIPPING_PARAMS +
                                  ["balance", "credit", "amount", "value"])]
            for param in numeric_params[:3]:
                for val in NEGATIVE_VALUES[:2]:
                    r = self._req(url, method="POST", data={param: val})
                    if r["status"] == 0:
                        continue
                    if r["status"] in (200, 201) and \
                            not self._indicates_error(r["body"] or "",
                                                       "negative"):
                        self._add_finding(
                            ftype="negative_value_accepted",
                            severity=SEV_HIGH,
                            url=url,
                            title=f"Negative value accepted for '{param}'",
                            description=(
                                f"The endpoint at {url} accepted "
                                f"{param}={val}. Negative values in "
                                f"financial parameters can be used for "
                                f"refunds-that-credit, free trials, or "
                                f"balance manipulation."
                            ),
                            evidence=f"{param}={val} → status={r['status']}",
                            param=param,
                        )
                        break

    # ============================================================
    #        PHASE 8 — Integer overflow
    # ============================================================
    def _test_integer_overflow(self):
        """Send values around INT_MAX boundaries to detect overflows."""
        self._log("  › اختبار integer overflow")
        all_urls = (self.cart_endpoints + self.trial_endpoints +
                    self.workflow_endpoints)
        for url in all_urls[:5]:
            params = self.discovered_params.get(url, set())
            numeric_params = [p for p in params if
                              any(np in p.lower() for np in
                                  PRICE_PARAMS + QUANTITY_PARAMS +
                                  ["balance", "credit", "days", "trial_days",
                                   "duration", "amount"])]
            for param in numeric_params[:2]:
                for val in INT_OVERFLOW_VALUES:
                    r = self._req(url, method="POST", data={param: val})
                    if r["status"] == 0:
                        continue
                    if r["status"] in (200, 201):
                        body = r["body"] or ""
                        # Check if the server stored the value as-is or
                        # wrapped it around
                        data = self._safe_json(body) or {}
                        for k in [param, "total", "subtotal", "balance"]:
                            if k in data:
                                try:
                                    sv = float(data[k])
                                    iv = float(val)
                                    # If sv is wildly different (e.g.
                                    # negative) from iv, likely overflow
                                    if sv < 0 and iv > 0:
                                        self._add_finding(
                                            ftype="integer_overflow",
                                            severity=SEV_CRITICAL,
                                            url=url,
                                            title=f"Integer overflow via '{param}'",
                                            description=(
                                                f"Sending {param}={val} "
                                                f"resulted in server-side "
                                                f"value {sv} (negative) — "
                                                f"this is a classic integer "
                                                f"overflow. Attackers can "
                                                f"use this to bypass checks "
                                                f"or compute negative totals."
                                            ),
                                            evidence=f"{param}={val} → {k}={sv}",
                                            param=param,
                                        )
                                        break
                                except (ValueError, TypeError):
                                    continue

    # ============================================================
    #        PHASE 9 — Currency manipulation
    # ============================================================
    def _test_currency_manipulation(self):
        """Test if changing the currency parameter affects pricing
        without proper conversion (e.g. price=$100, currency=JPY → still 100)."""
        self._log("  › اختبار currency manipulation")
        for url in self.cart_endpoints[:3]:
            # First fetch baseline in USD
            r_base = self._req(url, method="POST",
                               data={"currency": "USD"})
            if r_base["status"] == 0:
                continue
            base_total = self._extract_amount(r_base["body"] or "", "total")
            if base_total is None:
                continue
            # Try switching currency to a much weaker one (e.g. JPY, VND)
            # If the total stays at the same number, the conversion is missing
            for curr in ["JPY", "VND", "IDR", "KRW", "CLP"]:
                r = self._req(url, method="POST",
                              data={"currency": curr, "currency_code": curr})
                if r["status"] == 0:
                    continue
                new_total = self._extract_amount(r["body"] or "", "total")
                if new_total is not None and \
                        abs(new_total - base_total) < 0.01 and \
                        base_total > 0:
                    # Same total, different currency — no conversion
                    self._add_finding(
                        ftype="currency_manipulation",
                        severity=SEV_CRITICAL,
                        url=url,
                        title=f"No currency conversion (USD → {curr})",
                        description=(
                            f"The endpoint at {url} accepted currency "
                            f"change from USD to {curr} but kept the same "
                            f"total ({base_total}). Since 1 USD ≈ 150+ JPY, "
                            f"this means an attacker can pay 1/150th of "
                            f"the real price by switching currency."
                        ),
                        evidence=f"USD total={base_total}, "
                                 f"{curr} total={new_total} (no conversion)",
                        currency=curr,
                    )
                    break  # one finding is enough per endpoint

    # ============================================================
    #        PHASE 10 — Tax bypass
    # ============================================================
    def _test_tax_bypass(self):
        """Test if tax can be bypassed by manipulating tax parameters
        or by setting country/region to a tax-free location."""
        self._log("  › اختبار tax bypass")
        for url in self.cart_endpoints[:3]:
            # 1) Try sending tax_rate=0 directly
            for param in TAX_PARAMS:
                r = self._req(url, method="POST",
                              data={param: "0"})
                if r["status"] == 0:
                    continue
                if r["status"] in (200, 201):
                    tax = self._extract_amount(r["body"] or "", "tax") or \
                        self._extract_amount(r["body"] or "", "vat") or 0
                    if tax == 0:
                        # Compare with default tax
                        r_def = self._req(url, method="POST", data={})
                        tax_def = self._extract_amount(r_def["body"] or "",
                                                       "tax") or 0
                        if tax_def > 0:
                            self._add_finding(
                                ftype="tax_bypass",
                                severity=SEV_HIGH,
                                url=url,
                                title=f"Tax bypass via '{param}=0'",
                                description=(
                                    f"The endpoint at {url} accepted "
                                    f"{param}=0 and computed zero tax, "
                                    f"while the default would have charged "
                                    f"{tax_def}. Client-controlled tax "
                                    f"parameters let attackers evade tax."
                                ),
                                evidence=f"sent {param}=0 → tax=0, "
                                         f"default tax={tax_def}",
                                param=param,
                            )
                            break

            # 2) Try setting country/state to a tax-free location
            for country in ["US-OR", "US-DE", "US-MT", "US-NH", "AE",
                            "BHS", "BHR", "OMN"]:
                r = self._req(url, method="POST",
                              data={"country": country, "state": country,
                                    "country_code": country, "region": country})
                if r["status"] == 0:
                    continue
                if r["status"] in (200, 201):
                    tax = self._extract_amount(r["body"] or "", "tax") or 0
                    if tax == 0:
                        # OK — could be legitimate (some locations are tax-free)
                        # Flag only if the default tax was non-zero
                        r_def = self._req(url, method="POST", data={})
                        tax_def = self._extract_amount(r_def["body"] or "",
                                                       "tax") or 0
                        if tax_def > 0:
                            self._add_finding(
                                ftype="tax_bypass_location",
                                severity=SEV_MEDIUM,
                                url=url,
                                title=f"Tax zeroed by setting location to {country}",
                                description=(
                                    f"Setting country/region to '{country}' "
                                    f"zeroed the tax. While this is "
                                    f"legitimate for some locations, ensure "
                                    f"the server validates the country "
                                    f"against the shipping address to "
                                    f"prevent attackers from claiming "
                                    f"tax-free status."
                                ),
                                evidence=f"country={country} → tax=0, "
                                         f"default tax={tax_def}",
                                country=country,
                            )
                            break

    # ============================================================
    #        PHASE 11 — Shipping fee bypass
    # ============================================================
    def _test_shipping_bypass(self):
        """Test if shipping fee can be bypassed via parameter manipulation."""
        self._log("  › اختبار shipping fee bypass")
        for url in self.cart_endpoints[:3]:
            # 1) Try sending shipping=0 directly
            for param in SHIPPING_PARAMS:
                r = self._req(url, method="POST",
                              data={param: "0"})
                if r["status"] == 0:
                    continue
                if r["status"] in (200, 201):
                    ship = self._extract_amount(r["body"] or "",
                                                "shipping") or 0
                    if ship == 0:
                        # Compare with default
                        r_def = self._req(url, method="POST", data={})
                        ship_def = self._extract_amount(r_def["body"] or "",
                                                        "shipping") or 0
                        if ship_def > 0:
                            self._add_finding(
                                ftype="shipping_bypass",
                                severity=SEV_HIGH,
                                url=url,
                                title=f"Shipping fee bypassed via '{param}=0'",
                                description=(
                                    f"The endpoint at {url} accepted "
                                    f"{param}=0 and computed zero shipping, "
                                    f"while the default would have charged "
                                    f"{ship_def}. Attackers can get free "
                                    f"shipping by manipulating the parameter."
                                ),
                                evidence=f"sent {param}=0 → shipping=0, "
                                         f"default shipping={ship_def}",
                                param=param,
                            )
                            break

            # 2) Try negative shipping
            for param in SHIPPING_PARAMS:
                r = self._req(url, method="POST",
                              data={param: "-10"})
                if r["status"] == 0:
                    continue
                if r["status"] in (200, 201):
                    ship = self._extract_amount(r["body"] or "",
                                                "shipping")
                    if ship is not None and ship < 0:
                        self._add_finding(
                            ftype="shipping_negative",
                            severity=SEV_CRITICAL,
                            url=url,
                            title=f"Negative shipping fee accepted ('{param}')",
                            description=(
                                f"The endpoint at {url} accepted "
                                f"{param}=-10 and applied a negative "
                                f"shipping fee ({ship}). This effectively "
                                f"reduces the order total — financial loss."
                            ),
                            evidence=f"{param}=-10 → shipping={ship}",
                            param=param,
                        )
                        break

            # 3) Try invalid shipping method (e.g. "pickup" or "free")
            for method in ["pickup", "free", "digital", "download",
                           "instore", "self"]:
                r = self._req(url, method="POST",
                              data={"shipping_method": method})
                if r["status"] == 0:
                    continue
                if r["status"] in (200, 201):
                    ship = self._extract_amount(r["body"] or "",
                                                "shipping") or 0
                    if ship == 0:
                        r_def = self._req(url, method="POST", data={})
                        ship_def = self._extract_amount(r_def["body"] or "",
                                                        "shipping") or 0
                        if ship_def > 0:
                            self._add_finding(
                                ftype="shipping_method_bypass",
                                severity=SEV_MEDIUM,
                                url=url,
                                title=f"Shipping fee bypassed via method '{method}'",
                                description=(
                                    f"Setting shipping_method='{method}' "
                                    f"zeroed the shipping fee. If this "
                                    f"method should not be available "
                                    f"(e.g. 'free' for physical items), "
                                    f"the server is not validating the "
                                    f"method against the cart contents."
                                ),
                                evidence=f"shipping_method={method} → "
                                         f"shipping=0, default={ship_def}",
                                method=method,
                            )
                            break

    # ============================================================
    #        PHASE 12 — Free trial abuse
    # ============================================================
    def _test_free_trial_abuse(self):
        """Test if free trials can be repeatedly abused (no email /
        payment verification, or device fingerprinting)."""
        self._log("  › اختبار free trial abuse")
        for url in self.trial_endpoints[:3]:
            # Try signing up for a trial multiple times with different
            # email addresses
            token = self._gen_token()
            emails = [
                f"ghostpwn-test-{token}-1@ Mailnesia.com".replace(" ", ""),
                f"ghostpwn-test-{token}-2@mailinator.com",
                f"ghostpwn+{token}@example.com",
            ]
            success_count = 0
            for email in emails:
                r = self._req(url, method="POST",
                              data={"email": email, "plan": "trial",
                                    "trial": "true"})
                if r["status"] == 0:
                    continue
                if r["status"] in (200, 201):
                    body_low = (r["body"] or "").lower()
                    if "trial" in body_low and "start" in body_low:
                        success_count += 1
                    elif "success" in body_low:
                        success_count += 1

            if success_count >= 2:
                self._add_finding(
                    ftype="trial_abuse",
                    severity=SEV_HIGH,
                    url=url,
                    title=f"Free trial can be started multiple times ({success_count}/{len(emails)})",
                    description=(
                        f"The trial endpoint at {url} accepted "
                        f"{success_count} trial sign-ups with throwaway "
                        f"emails in rapid succession. Without email "
                        f"verification, payment-method binding, or device "
                        f"fingerprinting, attackers can abuse trials "
                        f"indefinitely."
                    ),
                    evidence=f"{success_count}/{len(emails)} trial signups succeeded",
                    success_count=success_count,
                )

            # Try extending a trial via direct parameter manipulation
            for param in ["trial_days", "days", "duration", "extend"]:
                for val in ["365", "9999", "-1"]:
                    r = self._req(url, method="POST",
                                  data={param: val})
                    if r["status"] == 0:
                        continue
                    if r["status"] in (200, 201):
                        # Check if trial was extended
                        body_low = (r["body"] or "").lower()
                        if "extended" in body_low or "updated" in body_low:
                            self._add_finding(
                                ftype="trial_extension_bypass",
                                severity=SEV_HIGH,
                                url=url,
                                title=f"Trial duration manipulated via '{param}'",
                                description=(
                                    f"The trial endpoint at {url} accepted "
                                    f"{param}={val} and updated the trial. "
                                    f"Attackers can extend trials "
                                    f"indefinitely or even set negative "
                                    f"durations to bypass billing."
                                ),
                                evidence=f"{param}={val} → status={r['status']}, "
                                         f"body suggests success",
                                param=param,
                            )
                            break

    # ============================================================
    #        PHASE 13 — Refund / repeat operation
    # ============================================================
    def _test_refund_repeat(self):
        """Test if refund / repeat operations can be replayed."""
        self._log("  › اختبار refund / repeat operations")
        for url in self.refund_endpoints[:3]:
            # Try sending the same refund request twice
            order_id = "1"  # likely-invalid but tests replay behavior
            payload = {"order_id": order_id, "amount": "1.00",
                       "reason": "ghostpwn-test"}
            r1 = self._req(url, method="POST", data=payload)
            if r1["status"] == 0:
                continue
            # If first request succeeded, immediately try the same refund again
            if r1["status"] in (200, 201):
                r2 = self._req(url, method="POST", data=payload)
                if r2["status"] in (200, 201):
                    # Both succeeded — likely a replay vulnerability
                    body1 = (r1["body"] or "").lower()
                    body2 = (r2["body"] or "").lower()
                    # Check if both responses suggest a refund was issued
                    if ("refund" in body1 and "refund" in body2) or \
                            ("success" in body1 and "success" in body2):
                        self._add_finding(
                            ftype="refund_replay",
                            severity=SEV_CRITICAL,
                            url=url,
                            title="Refund operation can be replayed",
                            description=(
                                f"The refund endpoint at {url} accepted "
                                f"the same refund request twice in a row "
                                f"and appeared to issue a refund both "
                                f"times. Without idempotency keys or "
                                f"state tracking, an attacker can drain "
                                f"merchant funds by replaying refund "
                                f"requests."
                            ),
                            evidence=f"first refund: status={r1['status']}, "
                                     f"second refund: status={r2['status']}",
                            order_id=order_id,
                        )

            # Also test idempotency via Idempotency-Key header
            key = "ghostpwn-" + self._gen_token()
            headers = {"Idempotency-Key": key}
            r1 = self._req(url, method="POST", data=payload, headers=headers)
            r2 = self._req(url, method="POST", data=payload, headers=headers)
            if r1["status"] in (200, 201) and r2["status"] in (200, 201):
                # Both requests with same idempotency key succeeded
                # If the server respects the key, the second should return
                # the cached response — but should NOT issue a second refund
                self._add_finding(
                    ftype="missing_idempotency",
                    severity=SEV_MEDIUM,
                    url=url,
                    title="Refund endpoint may not enforce idempotency",
                    description=(
                        f"The endpoint at {url} accepted two requests "
                        f"with the same Idempotency-Key and returned "
                        f"success for both. Verify the server actually "
                        f"deduplicates the underlying operation, not just "
                        f"the HTTP response."
                    ),
                    evidence=f"both requests with key={key} → "
                             f"status={r1['status']}, {r2['status']}",
                )

    # ============================================================
    #                       REPORTING
    # ============================================================
    def _build_report(self) -> Dict:
        return {
            "target": self.target,
            "scanner": "BusinessLogicScanner",
            "findings": self.findings,
            "endpoints": {
                "cart": self.cart_endpoints,
                "coupon": self.coupon_endpoints,
                "refund": self.refund_endpoints,
                "trial": self.trial_endpoints,
                "workflow": self.workflow_endpoints,
            },
            "stats": {
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
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")
        print(f"{Colors.MAGENTA}  💰 تقرير فحص ثغرات المنطق التجاري{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")

        # Endpoints
        total_eps = (len(self.cart_endpoints) + len(self.coupon_endpoints) +
                     len(self.refund_endpoints) + len(self.trial_endpoints) +
                     len(self.workflow_endpoints))
        if total_eps:
            print(f"\n  {Colors.BOLD}Endpoints المكتشفة ({total_eps}):"
                  f"{Colors.NC}")
            for kind in ["cart", "coupon", "refund", "trial", "workflow"]:
                lst = getattr(self, f"{kind}_endpoints")
                if lst:
                    print(f"    {Colors.CYAN}{kind}:{Colors.NC} "
                          f"{len(lst)} endpoint(s)")

        if self.findings:
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                         "info": 4}
            sorted_f = sorted(self.findings,
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
                print(f"      {fix_display(f['description'])}")
                print(f"      {Colors.GRAY}evidence:{Colors.NC} "
                      f"{self._short(f['evidence'], 120)}")
        else:
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات منطق تجاري واضحة مكتشفة"
                  f"{Colors.NC}")

        report = self._build_report()
        stats = report["stats"]
        print(f"\n  {Colors.BOLD}📊 الإحصائيات:{Colors.NC}")
        print(f"    Findings: {stats['total_findings']} "
              f"({Colors.RED}C:{stats['critical']} "
              f"H:{stats['high']} "
              f"{Colors.YELLOW}M:{stats['medium']} "
              f"{Colors.GRAY}L:{stats['low']}{Colors.NC})")
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")


# ============================ CLI ============================

def _build_client(args) -> HttpClient:
    return HttpClient(
        timeout=args.timeout,
        user_agent=args.user_agent or "ghostpwn-bizlogic/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=not args.no_redirects,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="business_logic",
        description="ghostpwn - Business Logic Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 business_logic.py https://shop.example.com\n"
            "  python3 business_logic.py https://shop.example.com "
            "--cookie 'session=abc'\n"
            "  python3 business_logic.py https://shop.example.com "
            "--json-out biz.json\n"
            "  python3 business_logic.py https://shop.example.com "
            "--rate-limit-requests 50\n"
        ),
    )
    parser.add_argument("url", help="Target URL (e.g. https://shop.example.com)")
    parser.add_argument("--timeout", type=int, default=12,
                        help="HTTP timeout (default 12)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests (default 0.1)")
    parser.add_argument("--user-agent", default=None,
                        help="Custom User-Agent")
    parser.add_argument("--proxy", default=None,
                        help="HTTP(S) proxy URL")
    parser.add_argument("--cookie", default=None,
                        help="Cookie string (essential for authenticated tests)")
    parser.add_argument("--no-redirects", action="store_true",
                        help="Disable HTTP redirect following")
    parser.add_argument("--rate-limit-requests", type=int, default=20,
                        help="Number of requests for rate-limit test")
    parser.add_argument("--max-coupon-attempts", type=int, default=30,
                        help="Max coupon codes to brute-force")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["price", "quantity", "coupon",
                                            "workflow", "trust", "rate",
                                            "negative", "overflow",
                                            "currency", "tax", "shipping",
                                            "trial", "refund", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_client(args)
    scanner = BusinessLogicScanner(
        http_client=client,
        options={
            "rate_limit_requests": args.rate_limit_requests,
            "max_coupon_attempts": args.max_coupon_attempts,
            "verbose": args.verbose,
            "safe_mode": True,
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
