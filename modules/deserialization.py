#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Deserialization Attack Detector
كشف ثغرات Deserialization في تطبيقات الويب

اللغات/التقنيات المفحوصة:
1.  PHP unserialize()  (a:N:{...} format)
2.  Java ObjectInputStream  (\xac\xed\x00\x05 magic)
3.  .NET ViewState / BinaryFormatter
4.  Python pickle  (\x80\x04 magic)
5.  Ruby Marshal  (\x04\x08 magic)
6.  Node.js funcster / serialize-to-cookies
7.  YAML.load (Ruby/Python unsafe loaders)
8.  كشف الـ serialized data في الـ parameters
9.  كشف gadget chain indicators (known classes)

ملاحظات:
- لا يستخدم مكتبات خارجية (Python stdlib فقط).
- لا يرسل payloads خطيرة (لا RCE) - فقط probes للكشف عن السلوك.
- يكتشف الـ deserialization عبر:
  * fingerprint للـ serialized data في الـ parameters
  * ردود أخطاء مميزة لكل لغة
  * اختلاف في الـ response عند إرسال probe
  * وجود gadget classes معروفة في classpath
"""
import os
import sys
import re
import json
import time
import base64
import binascii
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# PHP serialized data fingerprint
PHP_SERIAL_PATTERN = re.compile(
    r'(?:^|[^\w])([aosi]:\d+:[\{\(\[])', re.IGNORECASE)

# Java ObjectInputStream magic header (base64-encoded starts with rO0AB)
JAVA_MAGIC = b"\xac\xed\x00\x05"
JAVA_MAGIC_B64 = "rO0AB"

# Python pickle protocol bytes (we use proto 4: \x80\x04)
PICKLE_MAGIC = b"\x80"
PICKLE_PROTO_VERSIONS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]

# Ruby Marshal magic
RUBY_MAGIC = b"\x04\x08"

# .NET ViewState marker
VIEWSTATE_PATTERN = re.compile(
    r'name=["\']__VIEWSTATE["\']\s+value=["\']([^"\']+)["\']',
    re.IGNORECASE)

# .NET BinaryFormatter / LosFormatter header bytes
DOTNET_MAGIC_B64_PREFIXES = ["/wM", "AAEAAAD/////"]  # BinaryFormatter

# Node.js funcster / serialize.unserialize markers
NODE_SERIALIZE_MARKER = "_$ND_FUNC$$_"
NODE_FUNC_PREFIX = "function()"

# Common parameter names that often carry serialized data
SERIALIZED_PARAM_HINTS = [
    "data", "object", "obj", "state", "session", "s", "token",
    "viewstate", "__viewstate", "view_state", "vs",
    "pickle", "marshal", "serialized", "serial",
    "rdp", "redirect", "next", "return", "url",
    "payload", "p", "input", "value", "v",
    "cart", "order", "user", "profile", "config",
    "context", "ctx", "env", "attribute", "attr",
]

# Error signatures indicating deserialization attempts
ERROR_SIGNATURES = {
    "php": [
        "unserialize():", "Error at offset", "unserialize() expects",
        "Notice: unserialize()", "Warning: unserialize()",
    ],
    "java": [
        "ObjectInputStream", "readObject", "ClassNotFoundException",
        "InvalidClassException", "OptionalDataException",
        "StreamCorruptedException", "java.io.InvalidClassException",
        "could not deserialize", "deserialization",
        "serializable", "serialVersionUID",
        "HTTP Status 500 - Internal Server Error",
        "java.lang.ClassCastException",
    ],
    "dotnet": [
        "System.Runtime.Serialization", "BinaryFormatter",
        "LosFormatter", "ObjectStateFormatter",
        "ViewState", "__VIEWSTATE",
        "The state information is invalid for this page",
        "Validation of viewstate MAC failed",
        "MachineToApplication", "InvalidOperationException",
        "Could not load type",
    ],
    "python": [
        "pickle.loads", "_pickle.UnpicklingError",
        "pickle.UnpicklingError", "AttributeError: 'module'",
        "ImportStringError", "No module named",
    ],
    "ruby": [
        "Marshal.load", "TypeError: no implicit conversion",
        "in `load'", "ArgumentError: marshal data format too short",
        "RubyVM::InstructionSequence",
    ],
    "node": [
        "funcster", "serialize.unserialize",
        "SyntaxError: Unexpected token", "eval(<anonymous>)",
        "node-serialize", "_$ND_FUNC$$_",
    ],
}

# Known Java gadget chain classes (indicators in stack traces)
JAVA_GADGET_INDICATORS = [
    "org.apache.commons.collections.functors.InvokerTransformer",
    "org.apache.commons.collections4.functors.InvokerTransformer",
    "org.apache.commons.beanutils.PropertyUtils",
    "com.sun.rowset.JdbcRowSetImpl",
    "javax.management.BadAttributeValueExpException",
    "org.springframework.beans.factory.ObjectFactory",
    "org.codehaus.groovy.runtime.ConvertedClosure",
    "org.hibernate.property.access.spi.Getter",
    "org.jboss.interceptor.proxy.InterceptorMethodHandler",
    "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
    "org.mozilla.javascript.NativeJavaObject",
    "java.lang.Runtime", "java.lang.ProcessBuilder",
    "javassist.ClassPool",
]

# Common paths for Java apps that often have deserialization
JAVA_PROBE_PATHS = [
    "/invoker/readonly", "/invoker/JMXInvokerServlet",
    "/jmx-console", "/web-console", "/admin-console",
    "/manager/html", "/struts/devmode.action",
    "/struts/webconsole.html", "/api/jsonws/invoke",
    "/_/WEB-INF/_classpath",
    "/services", "/service", "/axis/services",
    "/rapi", "/xmlrpc.php",
]


# ============================ Probes ============================

def build_php_probe() -> Tuple[str, str]:
    """
    يبني payload PHP serialized آمن.
    نرسل بنية معطوبة قليلاً لإثارة unserialize() error.
    """
    # valid array + corrupted
    return ("a:1:{s:4:\"test\";s:4:\"test\";}",
            "a:1:{s:4:test;s:4:\"test\";}")


def build_java_probe() -> bytes:
    """
    يبني payload Java serialized آمن.
    نرسل magic header + stream version + null root tag.
    لا يحتوي أي gadget chain - فقط لإثارة ClassNotFoundException.
    """
    # \xac\xed\x00\x05 = magic + version 5
    # \x70 = TC_NULL (null root object)
    return b"\xac\xed\x00\x05\x70\x00\x00\x00\x01\x70"


def build_pickle_probe() -> bytes:
    """
    يبني pickle payload آمن (empty dict في proto 4).
    """
    # proto 4: \x80\x04 + frame + empty dict + stop
    # (\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}\x94.)
    return b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}\x94."


def build_ruby_probe() -> bytes:
    """
    يبني Ruby Marshal payload آمن (empty array).
    \x04\x08 + array header
    """
    return b"\x04\x08[\x00"


def build_dotnet_probe() -> str:
    """
    يبني .NET LosFormatter/BinaryFormatter payload آمن.
    نرسل magic + empty object.
    """
    raw = b"\x0a\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00"
    return base64.b64encode(raw).decode("ascii")


def build_node_probe() -> str:
    """
    يبني payload Node.js serialize-unserialize آمن (just a string).
    يحتوي _$ND_FUNC$$_ marker لكشف المكتبة.
    """
    return json.dumps({"rce": "_$ND_FUNC$$_function(){console.log(1)}"})


def base64_encode(data) -> str:
    """يرمز data إلى base64 ASCII string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


# ============================ Main Scanner ============================

class DeserializationScanner:
    """فاحص ثغرات Deserialization"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=12, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self.scanned_urls: Set[str] = set()
        self.serialized_params: List[Dict] = []

        # Tunables
        self.max_forms = self.options.get("max_forms", 15)
        self.max_params = self.options.get("max_params", 20)
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)
        self.baseline_responses: Dict[str, Dict] = {}

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[DESER] {msg}", level)

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
             json_data: Optional[Dict] = None,
             allow_redirects: bool = True) -> Dict:
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

    def _looks_like_serialized(self, value: str) -> List[str]:
        """يفحص إن كانت قيمة تحمل بصمة serialized data."""
        if not value or len(value) < 2:
            return []
        types = []
        # PHP
        if PHP_SERIAL_PATTERN.search(value):
            types.append("php")
        # Java (raw magic in URL-decoded)
        if JAVA_MAGIC_B64 in value or "\\xac\\xed" in value:
            types.append("java")
        # .NET ViewState
        if value.startswith(("/wM", "AAE")) or "__viewstate" in value.lower():
            types.append("dotnet")
        # Pickle base64 prefix (\x80 = base64 'gA' if first byte is 0x80)
        # pickle proto 0 starts with '(' (LP)
        if value.startswith("(") or "gAR9" in value:
            types.append("python")
        # Ruby Marshal (base64 starts with 'BA' for \x04\x08)
        if value.startswith("BA") and len(value) > 4:
            types.append("ruby")
        # Node.js
        if NODE_SERIALIZE_MARKER in value:
            types.append("node")
        return list(set(types))

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

        self._log(f"بدء فحص Deserialization: {self.base}", "phase")

        # ---------- Phase 1: Discovery ----------
        self._log("Phase 1: اكتشاف endpoints/parameters مع serialized data",
                  "phase")
        self._discover_serialized_inputs(target)

        # ---------- Phase 2: ViewState (.NET) ----------
        self._log("Phase 2: فحص .NET ViewState", "phase")
        self._test_dotnet_viewstate(target)

        # ---------- Phase 3: Java deserialization ----------
        self._log("Phase 3: فحص Java deserialization", "phase")
        self._test_java_deserialization()

        # ---------- Phase 4: PHP unserialize ----------
        self._log("Phase 4: فحص PHP unserialize()", "phase")
        self._test_php_unserialize()

        # ---------- Phase 5: Python pickle ----------
        self._log("Phase 5: فحص Python pickle", "phase")
        self._test_python_pickle()

        # ---------- Phase 6: Ruby Marshal ----------
        self._log("Phase 6: فحص Ruby Marshal", "phase")
        self._test_ruby_marshal()

        # ---------- Phase 7: Node.js ----------
        self._log("Phase 7: فحص Node.js serialize", "phase")
        self._test_node_deserialization()

        # ---------- Phase 8: Gadget chain indicators ----------
        self._log("Phase 8: كشف gadget chain indicators", "phase")
        self._detect_gadget_indicators()

        # ---------- Phase 9: Java probe paths ----------
        self._log("Phase 9: فحص Java invoker/servlet paths", "phase")
        self._probe_java_paths()

        self._print_results()
        return self._build_report()

    # ============================================================
    #                PHASE 1 - DISCOVERY
    # ============================================================

    def _discover_serialized_inputs(self, url: str):
        """يكتشف parameters/forms تحمل serialized data."""
        resp = self._req(url)
        if resp["status"] == 0 or not resp["body"]:
            self._log(f"  ✗ تعذّر الوصول للهدف: {resp.get('error')}", "warn")
            return

        body = resp["body"]

        # 1. اكتشاف forms
        forms = re.findall(
            r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>',
            body, re.IGNORECASE | re.DOTALL)
        forms = forms[:self.max_forms]
        for action, form_html in forms:
            self._extract_params_from_form(action, form_html, url)

        # 2. اكتشاف query params تحتوي serialized data (في links)
        links = re.findall(r'href=["\']([^"\']+)["\']', body,
                           re.IGNORECASE)[:30]
        for link in links:
            full = urljoin(url, link)
            parsed = urlparse(full)
            if not parsed.query:
                continue
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for pname, pvalues in qs.items():
                for v in pvalues:
                    types = self._looks_like_serialized(v)
                    if types:
                        self.serialized_params.append({
                            "url": full, "param": pname,
                            "value": v[:100], "types": types,
                            "method": "GET",
                        })
                        self._log(f"  • {pname} ({types}) في {full[:80]}",
                                  "info")

        # 3. JS endpoints with serialized-looking payloads
        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>',
                               body, re.IGNORECASE | re.DOTALL)
        for js in js_blocks[:5]:
            self._extract_serialized_from_js(js, url)

        self._log(f"  ✓ {len(self.serialized_params)} serialized inputs مكتشفة",
                  "success" if self.serialized_params else "info")

    def _extract_params_from_form(self, action: str, form_html: str,
                                   base_url: str):
        """يستخرج parameters من form HTML."""
        action_url = urljoin(base_url, action or "")
        method_match = re.search(r'method=["\']?(\w+)["\']?',
                                  form_html, re.IGNORECASE)
        method = (method_match.group(1).upper() if method_match else "POST")

        # استخراج input fields
        inputs = re.findall(
            r'<input[^>]+name=["\']?([^"\'>\s]+)["\']?[^>]*'
            r'(?:value=["\']([^"\']*)["\'])?',
            form_html, re.IGNORECASE)
        for name, value in inputs[:self.max_params]:
            if not name:
                continue
            v = value or ""
            types = self._looks_like_serialized(v)
            if types:
                self.serialized_params.append({
                    "url": action_url, "param": name,
                    "value": v[:100], "types": types,
                    "method": method,
                })
                self._log(f"  • form param '{name}' ({types}) "
                          f"@ {action_url[:60]}", "info")

    def _extract_serialized_from_js(self, js: str, base_url: str):
        """يكتشف serialized data في JS blocks."""
        # نبحث عن assignment of serialized values
        for pname in SERIALIZED_PARAM_HINTS:
            pattern = re.compile(
                r'(?:["\']' + re.escape(pname) + r'["\']\s*:\s*'
                r'["\'])([^"\']{8,200})(["\'])',
                re.IGNORECASE)
            for m in pattern.finditer(js):
                v = m.group(1)
                types = self._looks_like_serialized(v)
                if types:
                    self.serialized_params.append({
                        "url": base_url, "param": pname,
                        "value": v[:100], "types": types,
                        "method": "POST",
                    })

    # ============================================================
    #                PHASE 2 - .NET VIEWSTATE
    # ============================================================

    def _test_dotnet_viewstate(self, target: str):
        """يفحص .NET ViewState للتحقق من التوقيع/التشفير."""
        resp = self._req(target)
        if resp["status"] == 0 or not resp["body"]:
            return
        body = resp["body"]

        matches = VIEWSTATE_PATTERN.findall(body)
        if not matches:
            self._log("  › لا يوجد __VIEWSTATE في الصفحة", "info")
            return

        for vs_raw in matches:
            vs = vs_raw.strip()
            self._log(f"  ✓ __VIEWSTATE موجود ({len(vs)} chars)", "info")

            # 1. ViewState قصير جداً (قد لا يكون موقّعاً)
            if len(vs) < 20:
                self._add_finding(
                    "deser_dotnet_short_viewstate",
                    "low",
                    target,
                    ".NET ViewState Too Short (Possibly Unsigned)",
                    "قيمة __VIEWSTATE قصيرة جداً مما قد يعني أنها غير موقّعة "
                    "بـ HMAC. هذا يسمح بالـ tampering و ViewState "
                    "deserialization attacks.",
                    f"viewstate_length={len(vs)}, value='{vs[:50]}'",
                )
                continue

            # 2. فحص ViewState MAC
            # MAC-signed ViewState ينتهي بـ signature bytes.
            # نتحقق من وجود __VIEWSTATEGENERATOR و __EVENTVALIDATION
            has_generator = "__VIEWSTATEGENERATOR" in body
            has_eventval = "__EVENTVALIDATION" in body

            # 3. إرسال ViewState معطوب ورؤية الرد
            corrupted_vs = vs[:len(vs)//2] + "AAAA" + vs[len(vs)//2:]
            data = {
                "__VIEWSTATE": corrupted_vs,
                "__EVENTTARGET": "", "__EVENTARGUMENT": "",
            }
            if has_eventval:
                ev_match = re.search(
                    r'name=["\']__EVENTVALIDATION["\']\s+value=["\']([^"\']+)["\']',
                    body, re.IGNORECASE)
                if ev_match:
                    data["__EVENTVALIDATION"] = ev_match.group(1)

            resp2 = self._req(target, method="POST", data=data)
            err_body = (resp2["body"] or "").lower()
            # إن كان هناك Validation of viewstate MAC failed = signed (good)
            # إن لم يكن هناك خطأ MAC = unsigned (bad)
            mac_failure = any(s.lower() in err_body for s in
                              ["validation of viewstate mac failed",
                               "viewstate verification failed",
                               "machinekey"])
            tamper_accepted = (
                resp2["status"] == 200 and
                "error" not in err_body and
                "exception" not in err_body and
                not mac_failure)

            if tamper_accepted:
                self._add_finding(
                    "deser_dotnet_viewstate_unsigned",
                    "high",
                    target,
                    "Unsigned / Tampered ViewState Accepted",
                    "تم إرسال __VIEWSTATE معطوب وقبلته الصفحة دون خطأ MAC. "
                    "هذا يشير إلى أن ViewState غير موقّع بـ HMAC مما يسمح "
                    "بـ ViewState deserialization attacks (BinaryFormatter "
                    "gadget chains).",
                    f"original_vs_len={len(vs)}, corrupted_vs_len="
                    f"{len(corrupted_vs)}, response_status={resp2['status']}",
                )
            elif mac_failure:
                self._log("  ✓ ViewState موقّع بـ MAC (آمن)", "success")

            # 4. ViewState without generator (older .NET, may be vulnerable)
            if not has_generator:
                self._add_finding(
                    "deser_dotnet_no_viewstategenerator",
                    "low",
                    target,
                    "Missing __VIEWSTATEGENERATOR",
                    "الصفحة لا تحتوي __VIEWSTATEGENERATOR مما قد يشير لإصدار "
                    ".NET قديم لا يفحص ViewState بشكل صارم.",
                    f"has_eventvalidation={has_eventval}",
                )

            # نتكفي بأول viewstate
            break

    # ============================================================
    #                PHASE 3 - JAVA
    # ============================================================

    def _test_java_deserialization(self):
        """يرسل Java magic bytes لكل parameter معطى ويلاحظ الرد."""
        if not self.serialized_params:
            # نضيف targets عامة لو مفيش parameters مكتشفة
            self._add_default_target_params("java")
        probe = build_java_probe()
        probe_b64 = base64_encode(probe)

        tested = set()
        for sp in list(self.serialized_params):
            key = (sp["url"], sp["param"])
            if key in tested:
                continue
            tested.add(key)
            if not self._should_test_type(sp.get("types", []), "java"):
                # حتى لو لم نكتشف java type، نجرب (parameters may carry
                # base64-encoded java objects)
                pass
            self._send_java_probe(sp, probe, probe_b64)

    def _should_test_type(self, types: List[str], want: str) -> bool:
        return want in types if types else True

    def _add_default_target_params(self, lang: str):
        """يضيف parameters عامة للتجربة إن لم يكتشف شيئاً."""
        for pname in SERIALIZED_PARAM_HINTS[:8]:
            self.serialized_params.append({
                "url": self.target, "param": pname,
                "value": "", "types": [lang],
                "method": "POST", "synthetic": True,
            })

    def _send_java_probe(self, sp: Dict, probe: bytes, probe_b64: str):
        """يرسل Java probe ويفحص الرد."""
        url = sp["url"]
        param = sp["param"]
        method = sp.get("method", "POST").upper()

        # baseline
        baseline = self._get_baseline(url, method, param, "")
        # إرسال probe raw + base64
        probes = [("raw", probe), ("b64", probe_b64)]
        for label, payload in probes:
            if method == "GET":
                full_url = f"{url}?{urlencode({param: payload if isinstance(payload, str) else payload.decode('latin-1', errors='replace')})}"
                resp = self._req(full_url)
            else:
                resp = self._req(url, method="POST",
                                 data={param: payload if isinstance(payload, str) else payload.decode("latin-1", errors="replace")})

            err_sig = self._match_error_signature(resp["body"], "java")
            if err_sig:
                self._add_finding(
                    "deser_java_signature_detected",
                    "high",
                    url,
                    f"Java Deserialization Triggered ({param})",
                    f"إرسال Java ObjectInputStream magic bytes إلى parameter "
                    f"'{param}' أنتج ردّاً يحوي توقيع خطأ deserialization. "
                    "هذا يؤكد أن الـ backend يستقبل ويحاول deserialize بيانات "
                    "المستخدم، مما قد يسمح بـ RCE عبر gadget chain.",
                    f"param='{param}', probe={label}, error_sig='{err_sig}', "
                    f"status={resp['status']}, body_excerpt="
                    f"{self._short(resp['body'], 150)}",
                )
                return

            # إن اختلف الرد بشكل كبير عن baseline
            diff = self._response_diff(baseline, resp)
            if diff > 0.5:  # اختلاف كبير
                self._add_finding(
                    "deser_java_response_anomaly",
                    "medium",
                    url,
                    f"Java Probe Causes Response Anomaly ({param})",
                    f"إرسال Java serialized data إلى parameter '{param}' غيّر "
                    f"الرد بشكل ملحوظ عن baseline. قد يعني أن الـ backend "
                    f"يستجيب للـ serialized data (يحاول deserialize).",
                    f"param='{param}', probe={label}, diff_ratio={diff:.2f}, "
                    f"baseline_status={baseline.get('status')}, "
                    f"probe_status={resp['status']}",
                )
                return

    def _match_error_signature(self, body: str, lang: str) -> Optional[str]:
        """يطابق توقيع خطأ deserialization من قاموس التوقيعات."""
        if not body:
            return None
        body_lower = body.lower()
        for sig in ERROR_SIGNATURES.get(lang, []):
            if sig.lower() in body_lower:
                return sig
        return None

    def _response_diff(self, baseline: Dict, response: Dict) -> float:
        """يحسب نسبة اختلاف بين ردين (0-1)."""
        if not baseline or not response:
            return 0
        b1 = baseline.get("body", "") or ""
        b2 = response.get("body", "") or ""
        if not b1 and not b2:
            return 1.0 if baseline.get("status") != response.get("status") else 0
        # hash-based comparison
        h1 = hashlib.md5(b1.encode("utf-8", errors="ignore")).hexdigest()
        h2 = hashlib.md5(b2.encode("utf-8", errors="ignore")).hexdigest()
        if h1 == h2:
            return 0.0
        # rough char diff
        len_diff = abs(len(b1) - len(b2)) / max(len(b1), len(b2), 1)
        status_diff = 1.0 if baseline.get("status") != response.get("status") else 0.0
        return min(1.0, max(len_diff, status_diff))

    def _get_baseline(self, url: str, method: str, param: str,
                       value: str) -> Dict:
        """يجلب baseline response للـ param بقيمة معينة."""
        key = (url, method, param, value[:50])
        if key in self.baseline_responses:
            return self.baseline_responses[key]
        if method == "GET":
            full_url = f"{url}?{urlencode({param: value})}" if value else url
            resp = self._req(full_url)
        else:
            data = {param: value} if value else {}
            resp = self._req(url, method="POST", data=data)
        self.baseline_responses[key] = resp
        return resp

    # ============================================================
    #                PHASE 4 - PHP
    # ============================================================

    def _test_php_unserialize(self):
        """يرسل PHP serialized probes."""
        if not self.serialized_params:
            self._add_default_target_params("php")
        valid_probe, corrupt_probe = build_php_probe()

        tested = set()
        for sp in list(self.serialized_params):
            key = (sp["url"], sp["param"])
            if key in tested:
                continue
            tested.add(key)
            url = sp["url"]
            param = sp["param"]
            method = sp.get("method", "POST").upper()
            baseline = self._get_baseline(url, method, param, "")

            for label, payload in [("valid", valid_probe),
                                    ("corrupt", corrupt_probe)]:
                if method == "GET":
                    full_url = f"{url}?{urlencode({param: payload})}"
                    resp = self._req(full_url)
                else:
                    resp = self._req(url, method="POST",
                                     data={param: payload})
                err_sig = self._match_error_signature(resp["body"], "php")
                if err_sig:
                    self._add_finding(
                        "deser_php_unserialize_triggered",
                        "high",
                        url,
                        f"PHP unserialize() Triggered ({param})",
                        f"إرسال PHP serialized data إلى parameter '{param}' "
                        f"أنتج خطأ unserialize(). هذا يؤكد أن الـ backend "
                        f"يستدعي unserialize() على مدخلات المستخدم وقد يكون "
                        f"عرضة لـ POP chain attacks.",
                        f"param='{param}', probe={label}, "
                        f"error_sig='{err_sig}', status={resp['status']}, "
                        f"body_excerpt={self._short(resp['body'], 150)}",
                    )
                    break
                diff = self._response_diff(baseline, resp)
                if diff > 0.5:
                    self._add_finding(
                        "deser_php_response_anomaly",
                        "medium",
                        url,
                        f"PHP Probe Causes Response Anomaly ({param})",
                        f"إرسال PHP serialized probe إلى parameter '{param}' "
                        f"غيّر الرد بشكل ملحوظ. قد يعني استدعاء unserialize().",
                        f"param='{param}', probe={label}, diff_ratio="
                        f"{diff:.2f}",
                    )
                    break

    # ============================================================
    #                PHASE 5 - PYTHON PICKLE
    # ============================================================

    def _test_python_pickle(self):
        """يرسل pickle probes."""
        if not self.serialized_params:
            self._add_default_target_params("python")
        probe = build_pickle_probe()
        probe_b64 = base64_encode(probe)

        tested = set()
        for sp in list(self.serialized_params):
            key = (sp["url"], sp["param"])
            if key in tested:
                continue
            tested.add(key)
            url = sp["url"]
            param = sp["param"]
            method = sp.get("method", "POST").upper()
            baseline = self._get_baseline(url, method, param, "")

            for label, payload in [("raw", probe.decode("latin-1", "replace")),
                                    ("b64", probe_b64)]:
                if method == "GET":
                    full_url = f"{url}?{urlencode({param: payload})}"
                    resp = self._req(full_url)
                else:
                    resp = self._req(url, method="POST",
                                     data={param: payload})
                err_sig = self._match_error_signature(resp["body"], "python")
                if err_sig:
                    self._add_finding(
                        "deser_python_pickle_triggered",
                        "high",
                        url,
                        f"Python pickle.load() Triggered ({param})",
                        f"إرسال pickle data إلى parameter '{param}' أنتج "
                        f"خطأ pickle. الـ backend يستدعي pickle.loads() على "
                        f"مدخلات المستخدم وهو عرضة لـ RCE.",
                        f"param='{param}', probe={label}, "
                        f"error_sig='{err_sig}', status={resp['status']}",
                    )
                    break

    # ============================================================
    #                PHASE 6 - RUBY MARSHAL
    # ============================================================

    def _test_ruby_marshal(self):
        """يرسل Ruby Marshal probes."""
        if not self.serialized_params:
            self._add_default_target_params("ruby")
        probe = build_ruby_probe()
        probe_b64 = base64_encode(probe)

        tested = set()
        for sp in list(self.serialized_params):
            key = (sp["url"], sp["param"])
            if key in tested:
                continue
            tested.add(key)
            url = sp["url"]
            param = sp["param"]
            method = sp.get("method", "POST").upper()
            baseline = self._get_baseline(url, method, param, "")

            for label, payload in [("raw", probe.decode("latin-1", "replace")),
                                    ("b64", probe_b64)]:
                if method == "GET":
                    full_url = f"{url}?{urlencode({param: payload})}"
                    resp = self._req(full_url)
                else:
                    resp = self._req(url, method="POST",
                                     data={param: payload})
                err_sig = self._match_error_signature(resp["body"], "ruby")
                if err_sig:
                    self._add_finding(
                        "deser_ruby_marshal_triggered",
                        "high",
                        url,
                        f"Ruby Marshal.load() Triggered ({param})",
                        f"إرسال Ruby Marshal data إلى parameter '{param}' "
                        f"أنتج خطأ Marshal. الـ backend يستدعي Marshal.load() "
                        f"على مدخلات المستخدم وهو عرضة لـ RCE.",
                        f"param='{param}', probe={label}, "
                        f"error_sig='{err_sig}', status={resp['status']}",
                    )
                    break

    # ============================================================
    #                PHASE 7 - NODE.JS
    # ============================================================

    def _test_node_deserialization(self):
        """يرسل Node.js serialize-unserialize probes."""
        if not self.serialized_params:
            self._add_default_target_params("node")
        probe = build_node_probe()

        tested = set()
        for sp in list(self.serialized_params):
            key = (sp["url"], sp["param"])
            if key in tested:
                continue
            tested.add(key)
            url = sp["url"]
            param = sp["param"]
            method = sp.get("method", "POST").upper()
            baseline = self._get_baseline(url, method, param, "")

            if method == "GET":
                full_url = f"{url}?{urlencode({param: probe})}"
                resp = self._req(full_url)
            else:
                resp = self._req(url, method="POST",
                                 data={param: probe})
            err_sig = self._match_error_signature(resp["body"], "node")
            if err_sig:
                self._add_finding(
                    "deser_node_serialize_triggered",
                    "high",
                    url,
                    f"Node.js serialize.unserialize() Triggered ({param})",
                    f"إرسال Node.js funcster payload إلى parameter '{param}' "
                    f"أنتج خطأ متعلق بـ serialize.unserialize(). هذه المكتبة "
                    f"تسمح بـ RCE عبر _$ND_FUNC$$_ marker.",
                    f"param='{param}', error_sig='{err_sig}', "
                    f"status={resp['status']}",
                )
                continue

            # إن اختلف الرد بشكل كبير
            diff = self._response_diff(baseline, resp)
            if diff > 0.5:
                self._add_finding(
                    "deser_node_response_anomaly",
                    "medium",
                    url,
                    f"Node.js Probe Causes Response Anomaly ({param})",
                    f"إرسال Node.js serialize payload إلى parameter '{param}' "
                    f"غيّر الرد بشكل ملحوظ. قد يعني استدعاء unserialize().",
                    f"param='{param}', diff_ratio={diff:.2f}",
                )

    # ============================================================
    #                PHASE 8 - GADGET CHAIN INDICATORS
    # ============================================================

    def _detect_gadget_indicators(self):
        """يكتشف gadget chain classes في stack traces / responses."""
        # نعيد فحص الصفحة الرئيسية والـ baselines
        urls_to_check = [self.target]
        # نضيف آخر 5 URLs اختبرناها
        for sp in self.serialized_params[:5]:
            urls_to_check.append(sp["url"])

        checked = set()
        for url in urls_to_check:
            if url in checked:
                continue
            checked.add(url)
            resp = self._req(url)
            if not resp["body"]:
                continue
            body = resp["body"]
            found_gadgets = []
            for gadget in JAVA_GADGET_INDICATORS:
                if gadget in body:
                    found_gadgets.append(gadget)
            if found_gadgets:
                self._add_finding(
                    "deser_java_gadget_indicators",
                    "critical",
                    url,
                    f"Java Gadget Chain Classes in Classpath",
                    f"تم العثور على أسماء gadget classes معروفة في الـ "
                    f"response. وجودها في stack trace أو error message يشير "
                    f"إلى أنها في classpath التطبيق، مما يجعله عرضة لـ "
                    f"deserialization gadget chains (e.g. ysoserial).",
                    f"gadgets_found={found_gadgets[:5]}, "
                    f"total={len(found_gadgets)}",
                )

    # ============================================================
    #                PHASE 9 - JAVA PROBE PATHS
    # ============================================================

    def _probe_java_paths(self):
        """يفحص Java invoker/servlet paths الشائعة."""
        for path in JAVA_PROBE_PATHS:
            url = self.base + path.lstrip("/")
            if url in self.scanned_urls:
                continue
            self.scanned_urls.add(url)
            # نرسل probe Java على POST للـ path
            probe = build_java_probe()
            resp = self._req(url, method="POST",
                             data=probe.decode("latin-1", "replace"),
                             headers={"Content-Type":
                                      "application/x-java-serialized-object"})
            if resp["status"] == 0:
                continue
            err_sig = self._match_error_signature(resp["body"], "java")
            # إن أعى 200/500 مع Java signature → محتمل
            if resp["status"] in (200, 500) and \
                    (err_sig or "java" in resp["body"].lower()):
                self._add_finding(
                    "deser_java_invoker_exposed",
                    "high",
                    url,
                    f"Java Invoker/Servlet Endpoint Exposed ({path})",
                    f"Path '{path}' يستجيب لـ Java serialized POST. هذا "
                    f"نوعياً endpoint يستقبل Java objects مباشرة (e.g. "
                    f"JMXInvokerServlet) وهو هدف شائع لـ deserialization "
                    f"RCE.",
                    f"path='{path}', status={resp['status']}, "
                    f"error_sig='{err_sig}', body_excerpt="
                    f"{self._short(resp['body'], 150)}",
                )
            elif resp["status"] == 200 and not resp["body"]:
                # قد يكون silent - يعالج بدون رد
                self._add_finding(
                    "deser_java_invoker_silent",
                    "medium",
                    url,
                    f"Silent Java Invoker Endpoint ({path})",
                    f"Path '{path}' أعاد 200 فارغ على POST بـ Java serialized "
                    f"object. قد يكون يستقبل الـ object بصمت ويحاول "
                    f"deserialize.",
                    f"path='{path}', status={resp['status']}",
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
            "serialized_inputs": self.serialized_params,
            "findings": self.findings,
            "stats": self._stats_dict(),
        }

    def _print_results(self):
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🧬 تقرير فحص Deserialization"
              f"{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")

        if self.serialized_params:
            print(f"\n  {Colors.BOLD}Serialized inputs مكتشفة "
                  f"({len(self.serialized_params)}):{Colors.NC}")
            for sp in self.serialized_params[:10]:
                print(f"    {Colors.CYAN}•{Colors.NC} "
                      f"{sp['method']} {sp['param']} ({','.join(sp['types'])})"
                      f" @ {sp['url'][:55]}")

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
            print(f"\n  {Colors.GREEN}✓ لا توجد مؤشرات deserialization واضحة"
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
        user_agent=args.user_agent or "ghostpwn-deser/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=True,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="deserialization",
        description="ghostpwn - Deserialization Attack Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 deserialization.py https://example.com\n"
            "  python3 deserialization.py https://example.com --verbose\n"
            "  python3 deserialization.py https://example.com "
            "--cookie 'JSESSIONID=abc'\n"
            "  python3 deserialization.py https://example.com "
            "--json-out deser-report.json\n\n"
            "Note: يكتشف فقط - لا يرسل exploit payloads."
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
                        help="Cookie header (for authenticated tests)")
    parser.add_argument("--max-forms", type=int, default=15,
                        help="Max forms to discover (default 15)")
    parser.add_argument("--max-params", type=int, default=20,
                        help="Max params per form (default 20)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["discovery", "viewstate",
                                            "java", "php", "python",
                                            "ruby", "node", "gadgets",
                                            "paths", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_demo_client(args)
    scanner = DeserializationScanner(
        http_client=client,
        options={
            "verbose": args.verbose,
            "max_forms": args.max_forms,
            "max_params": args.max_params,
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


def _patch_only(scanner: "DeserializationScanner", only: str):
    """يخطّي كل الفحوصات ما عدا المطلوبة."""
    skip_map = {
        "discovery": ["_test_dotnet_viewstate", "_test_java_deserialization",
                       "_test_php_unserialize", "_test_python_pickle",
                       "_test_ruby_marshal", "_test_node_deserialization",
                       "_detect_gadget_indicators", "_probe_java_paths"],
        "viewstate": ["_test_java_deserialization", "_test_php_unserialize",
                       "_test_python_pickle", "_test_ruby_marshal",
                       "_test_node_deserialization",
                       "_detect_gadget_indicators", "_probe_java_paths"],
        "java": ["_test_dotnet_viewstate", "_test_php_unserialize",
                  "_test_python_pickle", "_test_ruby_marshal",
                  "_test_node_deserialization",
                  "_detect_gadget_indicators", "_probe_java_paths"],
        "php": ["_test_dotnet_viewstate", "_test_java_deserialization",
                 "_test_python_pickle", "_test_ruby_marshal",
                 "_test_node_deserialization",
                 "_detect_gadget_indicators", "_probe_java_paths"],
        "python": ["_test_dotnet_viewstate", "_test_java_deserialization",
                    "_test_php_unserialize", "_test_ruby_marshal",
                    "_test_node_deserialization",
                    "_detect_gadget_indicators", "_probe_java_paths"],
        "ruby": ["_test_dotnet_viewstate", "_test_java_deserialization",
                  "_test_php_unserialize", "_test_python_pickle",
                  "_test_node_deserialization",
                  "_detect_gadget_indicators", "_probe_java_paths"],
        "node": ["_test_dotnet_viewstate", "_test_java_deserialization",
                  "_test_php_unserialize", "_test_python_pickle",
                  "_test_ruby_marshal",
                  "_detect_gadget_indicators", "_probe_java_paths"],
        "gadgets": ["_test_dotnet_viewstate", "_test_java_deserialization",
                     "_test_php_unserialize", "_test_python_pickle",
                     "_test_ruby_marshal", "_test_node_deserialization",
                     "_probe_java_paths"],
        "paths": ["_test_dotnet_viewstate", "_test_java_deserialization",
                   "_test_php_unserialize", "_test_python_pickle",
                   "_test_ruby_marshal", "_test_node_deserialization",
                   "_detect_gadget_indicators"],
    }
    for name in skip_map.get(only, []):
        def _noop(*a, **kw):
            return None
        setattr(scanner, name, _noop)


if __name__ == "__main__":
    main()
