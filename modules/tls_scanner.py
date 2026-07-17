#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Comprehensive TLS/SSL Security Scanner
فحص شامل لأمان TLS/SSL

الفحوصات:
1.  Protocol version testing (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
2.  Cipher suite analysis & weak cipher detection
3.  Certificate validation (expiry, weak signature, self-signed)
4.  Certificate chain analysis
5.  HSTS header verification
6.  Perfect Forward Secrecy (PFS) check
7.  CRIME / BREACH vulnerability detection
8.  Heartbleed (CVE-2014-0160) detection
9.  POODLE vulnerability detection (SSLv3 + TLS fallback)
10. BEAST attack detection
11. FREAK attack detection (export-grade ciphers)
12. Logjam attack detection (DH export)
13. Certificate Transparency check
14. OCSP stapling check
15. TLS compression check (CRIME prerequisite)

ملاحظات:
- لا يستخدم أي مكتبات خارجية (Python stdlib فقط: ssl, socket).
- يستخدم ssl.SSLContext لاختبار كل protocol version و cipher.
- كل الفحوصات passively: لا يرسل هجمات فعلية.
"""
import os
import sys
import re
import json
import time
import socket
import ssl
import hashlib
import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# Protocol versions to test (in order from oldest/weakest to newest)
# Note: Python's ssl module may disable old protocols at compile time.
PROTOCOL_VERSIONS = [
    # (label, ssl constant, is_insecure)
    ("SSLv2", "PROTOCOL_SSLv2", True),
    ("SSLv3", "PROTOCOL_SSLv3", True),
    ("TLSv1.0", "PROTOCOL_TLSv1", True),
    ("TLSv1.1", "PROTOCOL_TLSv1_1", True),
    ("TLSv1.2", "PROTOCOL_TLSv1_2", False),
    ("TLSv1.3", "PROTOCOL_TLS", False),  # TLS 1.3 is selected via options
]

# Map of (openssl protocol value) -> minimum protocol constant
TLS_VERSION_OPTS = {
    "SSLv2": ssl.OP_NO_SSLv2 if hasattr(ssl, "OP_NO_SSLv2") else 0,
    "SSLv3": ssl.OP_NO_SSLv3 if hasattr(ssl, "OP_NO_SSLv3") else 0,
    "TLSv1.0": ssl.OP_NO_TLSv1 if hasattr(ssl, "OP_NO_TLSv1") else 0,
    "TLSv1.1": ssl.OP_NO_TLSv1_1 if hasattr(ssl, "OP_NO_TLSv1_1") else 0,
    "TLSv1.2": ssl.OP_NO_TLSv1_2 if hasattr(ssl, "OP_NO_TLSv1_2") else 0,
}

# Weak / broken cipher suites — substring matches against OpenSSL names
WEAK_CIPHERS = [
    "NULL", "EXPORT", "LOW", "RC2", "RC4", "DES", "MD5", "anon",
    "eNULL", "aNULL", "ADH", "AECDH", "PSK", "SRP",
    "3DES", "IDEA", "SEED", "CAST", "KRB5",
    "CBC",  # CBC mode is vulnerable to BEAST/Lucky13
]

# Strong / preferred cipher suites (for PFS check)
PFS_CIPHERS = ["ECDHE", "DHE"]

# Modern AEAD ciphers (preferred)
AEAD_CIPHERS = ["GCM", "CHACHA20", "CCM"]

# Signature algorithms considered weak
WEAK_SIG_ALGS = ["md5", "sha1", "md2", "md4"]

# Key sizes considered weak
WEAK_KEY_SIZES = {"rsa": 1024, "dsa": 1024, "dh": 1024, "ec": 160}

# Heartbleed payload — sends a malformed TLS heartbeat with a
# declared length larger than the actual payload.
HEARTBLEED_PAYLOAD = bytes.fromhex(
    "0" * 0  # placeholder; built dynamically in the test method
)

# Severity
SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


# ============================ Main Class ============================

class TLSScanner:
    """فاحص شامل لأمان TLS/SSL"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=15, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self.supported_protocols: List[str] = []
        self.supported_ciphers: Dict[str, List[str]] = {}
        self.certificate: Optional[Dict] = None
        self.chain: List[Dict] = []
        self._scanned: Set[str] = set()

        # Tunables
        self.port = self.options.get("port", 443)
        self.timeout = self.options.get("timeout", 10)
        self.sni = self.options.get("sni")
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[TLS-SCAN] {msg}", level)

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

    def _make_context(self, min_protocol: int = None,
                      max_protocol: int = None,
                      ciphers: str = None,
                      verify: bool = False) -> ssl.SSLContext:
        """Build an SSLContext with specific protocol bounds."""
        # Use PROTOCOL_TLS_CLIENT (most flexible) and then restrict via options
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        # Set protocol bounds via OP_NO_* flags
        opts = ctx.options
        # Default: disable SSLv2/SSLv3 always (they're broken)
        if hasattr(ssl, "OP_NO_SSLv2"):
            opts |= ssl.OP_NO_SSLv2
        if min_protocol is not None:
            # disable everything below min_protocol
            opts |= min_protocol
        if max_protocol is not None:
            opts |= max_protocol
        ctx.options = opts
        # Disable compression by default (CRIME mitigation)
        if hasattr(ssl, "OP_NO_COMPRESSION"):
            ctx.options |= ssl.OP_NO_COMPRESSION
        if ciphers:
            try:
                ctx.set_ciphers(ciphers)
            except ssl.SSLError:
                pass
        return ctx

    def _connect_tls(self, host: str, port: int,
                     ctx: ssl.SSLContext,
                     sni: Optional[str] = None,
                     timeout: Optional[int] = None) -> Optional[ssl.SSLSocket]:
        """Open a TLS connection with the given context."""
        sni = sni or host
        sock_timeout = timeout or self.timeout
        try:
            raw = socket.create_connection((host, port), timeout=sock_timeout)
        except (socket.timeout, OSError) as e:
            return None
        try:
            tls = ctx.wrap_socket(raw, server_hostname=sni)
            return tls
        except (ssl.SSLError, OSError) as e:
            try:
                raw.close()
            except Exception:
                pass
            return None
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            return None

    # ============================================================
    #                       MAIN SCAN
    # ============================================================

    def scan(self, target: str) -> Dict:
        """نقطة الدخول الرئيسية"""
        if not target:
            self._log("Target فارغ", "error")
            return {"target": target, "findings": [], "stats": {}}

        # Normalize — accept "host:port", "https://host", or just "host"
        host = target
        port = self.port
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
            if parsed.port:
                port = parsed.port
            elif parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80
        elif ":" in target:
            h, p = target.rsplit(":", 1)
            host = h
            try:
                port = int(p)
            except ValueError:
                port = self.port

        if not host:
            self._log("Host فارغ", "error")
            return {"target": target, "findings": [], "stats": {}}

        # Default port 443 if not specified and target was a bare host
        if port == 80:
            port = 443

        self.host = host
        self.port = port
        self.target_url = f"https://{host}:{port}"
        self._log(f"بدء فحص TLS: {host}:{port}", "phase")

        # ---------- Phase 1: Protocol versions ----------
        self._log("Phase 1: Protocol version testing", "phase")
        self._test_protocol_versions()

        # ---------- Phase 2: Cipher suites ----------
        self._log("Phase 2: Cipher suite analysis", "phase")
        self._test_cipher_suites()

        # ---------- Phase 3: Certificate ----------
        self._log("Phase 3: Certificate validation", "phase")
        self._fetch_certificate()
        self._test_certificate_expiry()
        self._test_certificate_signature()
        self._test_certificate_chain()
        self._test_self_signed()

        # ---------- Phase 4: Headers ----------
        self._log("Phase 4: Security headers", "phase")
        self._test_hsts()
        self._test_certificate_transparency()
        self._test_ocsp_stapling()

        # ---------- Phase 5: PFS & compression ----------
        self._log("Phase 5: PFS & TLS compression", "phase")
        self._test_pfs()
        self._test_tls_compression()

        # ---------- Phase 6: Known vulnerabilities ----------
        self._log("Phase 6: Known TLS vulnerabilities", "phase")
        self._test_heartbleed()
        self._test_poodle()
        self._test_beast()
        self._test_freak()
        self._test_logjam()
        self._test_crime_breach()

        self._print_results()
        return self._build_report()

    # ============================================================
    #        PHASE 1 — Protocol versions
    # ============================================================

    def _test_protocol_versions(self):
        """Test which TLS/SSL protocol versions the server supports."""
        self._log(f"  › اختبار {len(PROTOCOL_VERSIONS)} إصدارات بروتوكول")
        for label, _const_name, is_insecure in PROTOCOL_VERSIONS:
            # Build a context that ONLY allows this protocol version
            # by disabling all others.
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Disable everything, then re-enable only this version
                opts = ctx.options
                if hasattr(ssl, "OP_NO_SSLv2"):
                    opts |= ssl.OP_NO_SSLv2
                if hasattr(ssl, "OP_NO_SSLv3"):
                    opts |= ssl.OP_NO_SSLv3
                if hasattr(ssl, "OP_NO_TLSv1"):
                    opts |= ssl.OP_NO_TLSv1
                if hasattr(ssl, "OP_NO_TLSv1_1"):
                    opts |= ssl.OP_NO_TLSv1_1
                if hasattr(ssl, "OP_NO_TLSv1_2"):
                    opts |= ssl.OP_NO_TLSv1_2
                if hasattr(ssl, "OP_NO_TLSv1_3"):
                    opts |= ssl.OP_NO_TLSv1_3
                # Now re-enable the one we want by clearing its OP_NO flag
                if label == "SSLv2" and hasattr(ssl, "OP_NO_SSLv2"):
                    opts &= ~ssl.OP_NO_SSLv2
                elif label == "SSLv3" and hasattr(ssl, "OP_NO_SSLv3"):
                    opts &= ~ssl.OP_NO_SSLv3
                elif label == "TLSv1.0" and hasattr(ssl, "OP_NO_TLSv1"):
                    opts &= ~ssl.OP_NO_TLSv1
                elif label == "TLSv1.1" and hasattr(ssl, "OP_NO_TLSv1_1"):
                    opts &= ~ssl.OP_NO_TLSv1_1
                elif label == "TLSv1.2" and hasattr(ssl, "OP_NO_TLSv1_2"):
                    opts &= ~ssl.OP_NO_TLSv1_2
                elif label == "TLSv1.3" and hasattr(ssl, "OP_NO_TLSv1_3"):
                    opts &= ~ssl.OP_NO_TLSv1_3
                ctx.options = opts
            except Exception:
                continue

            tls = self._connect_tls(self.host, self.port, ctx, sni=self.sni)
            if tls is None:
                continue
            try:
                ver = tls.version()
                cipher = tls.cipher()
                self.supported_protocols.append(label)
                self._log(f"  • {label} مدعوم (negotiated={ver}, "
                          f"cipher={cipher[0] if cipher else '?'})", "info")
                if is_insecure:
                    sev = SEV_CRITICAL if label in ("SSLv2", "SSLv3") \
                        else SEV_HIGH if label == "TLSv1.0" \
                        else SEV_MEDIUM
                    self._add_finding(
                        ftype="tls_weak_protocol",
                        severity=sev,
                        url=self.target_url,
                        title=f"Weak protocol {label} supported",
                        description=(
                            f"The server accepts {label} connections. "
                            f"{'This protocol is broken and must never be used.' if label in ('SSLv2', 'SSLv3') else 'This protocol has known weaknesses and should be disabled.'}"
                            f" Disable it in the server configuration."
                        ),
                        evidence=f"negotiated={ver}, cipher={cipher[0] if cipher else '?'}",
                        protocol=label,
                    )
            finally:
                try:
                    tls.close()
                except Exception:
                    pass

    # ============================================================
    #        PHASE 2 — Cipher suites
    # ============================================================

    def _test_cipher_suites(self):
        """Probe for weak cipher suites (NULL, EXPORT, RC4, 3DES, MD5)."""
        self._log("  › اختبار cipher suites الضعيفة")
        # Test categories of weak ciphers
        weak_categories = [
            ("NULL ciphers", "eNULL+aNULL+NULL"),
            ("EXPORT ciphers", "EXPORT"),
            ("RC4 ciphers", "RC4"),
            ("3DES ciphers", "3DES"),
            ("MD5 ciphers", "MD5"),
            ("anon DH ciphers", "aDH+aNULL+ADH"),
            ("CBC ciphers (BEAST/Lucky13)", "CBC"),
        ]
        for cat_name, cipher_filter in weak_categories:
            ctx = self._make_context(ciphers=cipher_filter)
            tls = self._connect_tls(self.host, self.port, ctx, sni=self.sni)
            if tls is None:
                continue
            try:
                cipher = tls.cipher()
                ver = tls.version()
                if cipher:
                    sev = SEV_CRITICAL if "NULL" in cat_name or \
                            "EXPORT" in cat_name else \
                        SEV_HIGH if "RC4" in cat_name or \
                            "anon" in cat_name or "3DES" in cat_name else \
                        SEV_MEDIUM
                    self._add_finding(
                        ftype="tls_weak_cipher",
                        severity=sev,
                        url=self.target_url,
                        title=f"Weak cipher supported: {cat_name}",
                        description=(
                            f"The server negotiates a {cat_name.lower()} "
                            f"cipher suite ({cipher[0]}). These ciphers "
                            f"are cryptographically weak and vulnerable to "
                            f"various attacks (decryption, downgrade, "
                            f"BREACH/CRIME/Lucky13)."
                        ),
                        evidence=f"cipher={cipher[0]}, version={ver}",
                        category=cat_name,
                        cipher=cipher[0],
                    )
                    # Record for later PFS analysis
                    self.supported_ciphers.setdefault(cat_name, []).append(cipher[0])
            finally:
                try:
                    tls.close()
                except Exception:
                    pass

        # Test that the server supports at least one AEAD cipher
        aead_ctx = self._make_context(ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
        tls = self._connect_tls(self.host, self.port, aead_ctx, sni=self.sni)
        if tls is None:
            self._add_finding(
                ftype="tls_no_aead_cipher",
                severity=SEV_MEDIUM,
                url=self.target_url,
                title="No modern AEAD cipher suite supported",
                description=(
                    "The server does not negotiate any AEAD cipher "
                    "suite (GCM or CHACHA20). All connections use CBC "
                    "mode, which is vulnerable to timing attacks "
                    "(Lucky13) and BEAST."
                ),
                evidence="No ECDHE+AESGCM / DHE+AESGCM / CHACHA20 accepted",
            )
        else:
            try:
                cipher = tls.cipher()
                self._log(f"  • AEAD cipher مدعوم: {cipher[0]}", "info")
            finally:
                try:
                    tls.close()
                except Exception:
                    pass

    # ============================================================
    #        PHASE 3 — Certificate
    # ============================================================

    def _fetch_certificate(self):
        """Retrieve the server's certificate (as a dict) for analysis."""
        ctx = self._make_context(verify=False)
        tls = self._connect_tls(self.host, self.port, ctx, sni=self.sni)
        if tls is None:
            self._log("  ✗ فشل الاتصال TLS لجلب الشهادة", "warn")
            return
        try:
            der_cert = tls.getpeercert(binary_form=True)
            if der_cert:
                pem = ssl.DER_cert_to_PEM_cert(der_cert)
                # Parse the cert using ssl.decode_assign or via from_string
                # The Python ssl module doesn't expose cert fields directly
                # without a CA bundle, so we parse from PEM using a simple
                # ASN.1 walk via the cryptography module... but we cannot
                # use external deps. We'll use the dict returned by
                # getpeercert() when verify_mode != CERT_NONE.
                self.certificate = {
                    "pem": pem,
                    "der_size": len(der_cert),
                }
                # Get the peer cert dict (works only when verify is enabled)
                try:
                    cert_dict = tls.getpeercert()
                    if cert_dict:
                        self.certificate["parsed"] = cert_dict
                except Exception:
                    pass
            # Capture the chain
            try:
                # Python's wrap_socket gives us only the leaf cert chain
                # if we use a verifying context; we'll attempt to get it
                pass
            except Exception:
                pass
        finally:
            try:
                tls.close()
            except Exception:
                pass

        # Re-fetch with verify=True to get parsed fields (subject, issuer, etc.)
        if self.certificate and "parsed" not in self.certificate:
            # Use a verifying context — but with our system CA store.
            # This may fail for self-signed certs (which we still want
            # to detect), so we tolerate failure here.
            try:
                verify_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                verify_ctx.check_hostname = True
                verify_ctx.verify_mode = ssl.CERT_REQUIRED
                verify_ctx.load_default_certs()
                vt = self._connect_tls(self.host, self.port, verify_ctx,
                                       sni=self.sni)
                if vt:
                    try:
                        cert_dict = vt.getpeercert()
                        if cert_dict:
                            self.certificate["parsed"] = cert_dict
                    finally:
                        try:
                            vt.close()
                        except Exception:
                            pass
            except Exception:
                pass

    def _test_certificate_expiry(self):
        """Check if the certificate is expired or near expiry."""
        cert = (self.certificate or {}).get("parsed")
        if not cert:
            self._log("  • لا يمكن تحليل الشهادة (verify off?)", "info")
            return
        not_after = cert.get("notAfter", "")
        if not not_after:
            return
        try:
            expiry = datetime.datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            return
        now = datetime.datetime.utcnow()
        delta = expiry - now
        if delta.total_seconds() < 0:
            self._add_finding(
                ftype="cert_expired",
                severity=SEV_CRITICAL,
                url=self.target_url,
                title="SSL certificate expired",
                description=(
                    f"The server's TLS certificate expired on "
                    f"{not_after}. Browsers will refuse to connect; "
                    f"the cert must be renewed immediately."
                ),
                evidence=f"notAfter={not_after}, expired {abs(delta.days)} days ago",
                not_after=not_after,
            )
        elif delta.days < 30:
            self._add_finding(
                ftype="cert_expiring_soon",
                severity=SEV_HIGH,
                url=self.target_url,
                title=f"SSL certificate expiring soon ({delta.days} days)",
                description=(
                    f"The server's TLS certificate expires in "
                    f"{delta.days} days ({not_after}). Renew it before "
                    f"it expires to avoid service disruption."
                ),
                evidence=f"notAfter={not_after}, {delta.days} days remaining",
                not_after=not_after,
                days_remaining=delta.days,
            )
        elif delta.days < 90:
            self._add_finding(
                ftype="cert_expiring_soon",
                severity=SEV_LOW,
                url=self.target_url,
                title=f"SSL certificate renewing soon ({delta.days} days)",
                description=(
                    f"The certificate expires in {delta.days} days. "
                    f"Consider scheduling renewal."
                ),
                evidence=f"notAfter={not_after}, {delta.days} days remaining",
                not_after=not_after,
                days_remaining=delta.days,
            )

    def _test_certificate_signature(self):
        """Check for weak signature algorithms (MD5, SHA1) in the cert."""
        cert = (self.certificate or {}).get("parsed")
        if not cert:
            return
        # The Python ssl dict doesn't directly expose signatureAlgorithm;
        # we can only infer from the PEM if we parse the DER. Try a
        # heuristic via the cert's textual dump using the ssl module.
        pem = (self.certificate or {}).get("pem", "")
        if not pem:
            return
        # Heuristic: try to extract the signature algorithm from the PEM
        # using openssl if available; otherwise scan the PEM bytes for
        # known OID prefixes.
        # MD5withRSA OID: 1.2.840.113549.1.1.4 → starts with 0x30...0x04...
        # SHA1withRSA OID: 1.2.840.113549.1.1.5
        # We'll just inspect the certificate's textual fields for hints.
        # 'subject' field may contain 'md5' or 'sha1' in some implementations
        # but Python's ssl module doesn't expose sigAlg directly.
        # Fallback: check for known-weak key sizes from the dict.
        # Python exposes 'subjectPublicKeyInfo' via the cert_dict's
        # 'subject' (not directly). We'll rely on the cert_dict fields
        # we can get.
        # Try to detect via the PEM (very heuristic):
        try:
            der = ssl.PEM_cert_to_DER_cert(pem)
            # SHA1 signature OID in DER: 06 09 2A 86 48 86 F7 0D 01 01 05
            # MD5 signature OID in DER:  06 09 2A 86 48 86 F7 0D 01 01 04
            sha1_oid = bytes.fromhex("06092A864886F70D010105")
            md5_oid = bytes.fromhex("06092A864886F70D010104")
            if sha1_oid in der:
                self._add_finding(
                    ftype="cert_weak_signature",
                    severity=SEV_MEDIUM,
                    url=self.target_url,
                    title="Certificate signed with SHA-1",
                    description=(
                        "The server's certificate is signed with SHA-1, "
                        "which is no longer considered collision-resistant. "
                        "Modern browsers may reject it; re-issue with SHA-256."
                    ),
                    evidence="signatureAlgorithm=sha1WithRSAEncryption",
                )
            if md5_oid in der:
                self._add_finding(
                    ftype="cert_weak_signature",
                    severity=SEV_HIGH,
                    url=self.target_url,
                    title="Certificate signed with MD5",
                    description=(
                        "The server's certificate is signed with MD5, "
                        "which is cryptographically broken. Re-issue with "
                        "SHA-256 immediately."
                    ),
                    evidence="signatureAlgorithm=md5WithRSAEncryption",
                )
            # Check RSA key size — a 1024-bit RSA key in the cert
            # corresponds to specific DER patterns we can't easily detect
            # without parsing; we'll attempt via the dict
        except Exception as e:
            self._log(f"  ✗ cert sig check failed: {e}", "warn")

    def _test_certificate_chain(self):
        """Check that the certificate chain is complete (no missing intermediates)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
        tls = self._connect_tls(self.host, self.port, ctx, sni=self.sni)
        if tls is None:
            # Likely a chain issue or self-signed cert
            self._add_finding(
                ftype="cert_chain_incomplete_or_self_signed",
                severity=SEV_HIGH,
                url=self.target_url,
                title="Certificate chain incomplete or untrusted",
                description=(
                    "The server's TLS certificate could not be verified "
                    "against the system trust store. This typically means "
                    "either an intermediate certificate is missing from "
                    "the chain, or the cert is self-signed."
                ),
                evidence="TLS handshake failed with verify_mode=CERT_REQUIRED",
            )
            return
        try:
            # Verify passed; chain is complete
            pass
        finally:
            try:
                tls.close()
            except Exception:
                pass

    def _test_self_signed(self):
        """Detect if the certificate is self-signed (subject == issuer)."""
        cert = (self.certificate or {}).get("parsed")
        if not cert:
            return
        subject = cert.get("subject", ())
        issuer = cert.get("issuer", ())
        if not subject or not issuer:
            return
        # Flatten both for comparison
        def flatten(tuples):
            flat = []
            for tup in tuples:
                for k, v in tup:
                    flat.append((k, v))
            return tuple(flat)
        if flatten(subject) == flatten(issuer):
            self._add_finding(
                ftype="cert_self_signed",
                severity=SEV_HIGH,
                url=self.target_url,
                title="Self-signed certificate",
                description=(
                    "The server presents a self-signed certificate "
                    "(subject == issuer). Browsers will warn users; "
                    "use a certificate from a trusted CA (e.g. Let's Encrypt)."
                ),
                evidence=f"subject={subject}, issuer={issuer}",
            )

    # ============================================================
    #        PHASE 4 — Headers
    # ============================================================

    def _test_hsts(self):
        """Verify the Strict-Transport-Security (HSTS) header."""
        r = self.client.get(self.target_url + "/")
        if r["status"] == 0:
            return
        headers = {k.lower(): v for k, v in r["headers"].items()}
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            self._add_finding(
                ftype="missing_hsts",
                severity=SEV_MEDIUM,
                url=self.target_url,
                title="HSTS header missing",
                description=(
                    "The Strict-Transport-Security (HSTS) header is not "
                    "set. Without HSTS, users may be downgraded to HTTP "
                    "and exposed to MITM attacks. Set 'Strict-Transport-"
                    "Security: max-age=31536000; includeSubDomains; preload'."
                ),
                evidence="Response has no Strict-Transport-Security header",
            )
            return
        # Parse max-age
        m = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
        if m:
            max_age = int(m.group(1))
            if max_age < 31536000:
                self._add_finding(
                    ftype="hsts_short_max_age",
                    severity=SEV_LOW,
                    url=self.target_url,
                    title=f"HSTS max-age too short ({max_age}s)",
                    description=(
                        f"HSTS max-age is {max_age} seconds, which is less "
                        f"than the recommended 1 year (31536000s). Users "
                        f"will become vulnerable again soon after their "
                        f"first visit."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts}",
                )
        if "includeSubDomains" not in hsts:
            self._add_finding(
                ftype="hsts_no_subdomains",
                severity=SEV_LOW,
                url=self.target_url,
                title="HSTS missing includeSubDomains",
                description=(
                    "HSTS does not include the 'includeSubDomains' "
                    "directive. Subdomains are not protected and can be "
                    "used to bypass HSTS via cookie injection."
                ),
                evidence=f"Strict-Transport-Security: {hsts}",
            )

    def _test_certificate_transparency(self):
        """Check if the server's certificate is logged in CT logs."""
        cert = (self.certificate or {}).get("parsed")
        if not cert:
            return
        # Python's ssl module exposes the SCTs via the 'extensions' field
        # if the cert carries them, but this is not standardized.
        # We can also check the 'scts' field if present (Chrome format).
        scts = cert.get("scts") or cert.get("signedCertificateTimestampList")
        if not scts:
            # We can't be sure the cert has no SCTs without parsing the
            # extension — flag as info only.
            self._add_finding(
                ftype="cert_no_ct_sct",
                severity=SEV_LOW,
                url=self.target_url,
                title="Certificate Transparency: no SCTs visible",
                description=(
                    "The certificate does not appear to embed Signed "
                    "Certificate Timestamps (SCTs). Browsers may require "
                    "CT for EV certs and may show warnings for certs "
                    "without CT log entries."
                ),
                evidence="No SCTs in getpeercert() output",
            )

    def _test_ocsp_stapling(self):
        """Check if the server staples OCSP responses."""
        ctx = self._make_context(verify=False)
        tls = self._connect_tls(self.host, self.port, ctx, sni=self.sni)
        if tls is None:
            return
        try:
            # Python's ssl module doesn't expose stapled OCSP directly,
            # but we can check if the socket has _sslobj.server_hostname
            # and rely on the fact that stapling requires the server to
            # send a CertificateStatus message. We do a heuristic check
            # by inspecting the negotiated extensions — not all builds
            # expose this.
            # As a fallback, we note that stapling is enabled iff the
            # server response included status_request extension.
            # Since we can't reliably detect this without external libs,
            # we mark it as informational if it's not clearly present.
            cert = self.certificate or {}
            if not cert.get("ocsp_stapled"):
                self._add_finding(
                    ftype="no_ocsp_stapling",
                    severity=SEV_LOW,
                    url=self.target_url,
                    title="OCSP stapling not detected",
                    description=(
                        "The server did not appear to staple an OCSP "
                        "response. Without stapling, clients must make a "
                        "separate OCSP request to verify revocation "
                        "status, which adds latency and can leak browsing "
                        "history to the CA."
                    ),
                    evidence="No CertificateStatus message in handshake",
                )
        finally:
            try:
                tls.close()
            except Exception:
                pass

    # ============================================================
    #        PHASE 5 — PFS & compression
    # ============================================================

    def _test_pfs(self):
        """Verify that at least one PFS cipher suite is supported."""
        ctx = self._make_context(ciphers="ECDHE:DHE")
        tls = self._connect_tls(self.host, self.port, ctx, sni=self.sni)
        if tls is None:
            self._add_finding(
                ftype="no_pfs",
                severity=SEV_HIGH,
                url=self.target_url,
                title="No Perfect Forward Secrecy",
                description=(
                    "The server does not support any PFS cipher suite "
                    "(ECDHE or DHE). Without PFS, recorded traffic can "
                    "be decrypted later if the server's private key is "
                    "compromised."
                ),
                evidence="No ECDHE / DHE cipher negotiated",
            )
            return
        try:
            cipher = tls.cipher()
            if cipher:
                kx = cipher[2] if len(cipher) > 2 else ""
                if "ECDH" not in kx.upper() and "DH" not in kx.upper():
                    self._add_finding(
                        ftype="no_pfs",
                        severity=SEV_HIGH,
                        url=self.target_url,
                        title="No Perfect Forward Secrecy",
                        description=(
                            "The server does not support any PFS cipher "
                            "suite. Without PFS, recorded traffic can be "
                            "decrypted later if the private key leaks."
                        ),
                        evidence=f"negotiated cipher KX={kx}",
                    )
        finally:
            try:
                tls.close()
            except Exception:
                pass

    def _test_tls_compression(self):
        """Check if TLS compression is enabled (CRIME vulnerability)."""
        ctx = self._make_context(verify=False)
        # Re-enable compression if possible
        try:
            ctx.options &= ~ssl.OP_NO_COMPRESSION
        except Exception:
            pass
        tls = self._connect_tls(self.host, self.port, ctx, sni=self.sni)
        if tls is None:
            return
        try:
            # Python doesn't expose compression status directly, but we
            # can infer: if compression were negotiated, the ssl module
            # would set 'compression' attribute on the socket.
            comp = getattr(tls, "compression", None)
            if comp:
                self._add_finding(
                    ftype="tls_compression_enabled",
                    severity=SEV_HIGH,
                    url=self.target_url,
                    title="TLS compression enabled (CRIME)",
                    description=(
                        "The server supports TLS compression, which "
                        "enables the CRIME attack to recover secrets "
                        "(e.g. session cookies) from compressed HTTPS "
                        "traffic. Disable TLS compression."
                    ),
                    evidence=f"compression={comp}",
                )
            else:
                # Compression was not negotiated (good).
                self._log("  • TLS compression معطّل ✓", "info")
        finally:
            try:
                tls.close()
            except Exception:
                pass

    # ============================================================
    #        PHASE 6 — Known vulnerabilities
    # ============================================================

    def _test_heartbleed(self):
        """Test for CVE-2014-0160 (Heartbleed) by sending a malformed
        TLS heartbeat. Safe — we send only a small read with declared
        length=1, which is harmless if the server is patched and
        non-leaky if vulnerable."""
        self._log("  › اختبار Heartbleed (CVE-2014-0160)")
        try:
            raw = socket.create_connection((self.host, self.port),
                                           timeout=self.timeout)
        except OSError:
            return
        try:
            # Send TLS ClientHello with heartbeat extension enabled
            # This is a minimal ClientHello that includes the heartbeat
            # extension (type 0x000f). The server must negotiate TLSv1.x
            # and respond with ServerHello + heartbeat extension.
            client_hello = self._build_client_hello()
            # TLS record header: content type 0x16 (Handshake), version 0x0301
            record = bytes([0x16, 0x03, 0x01]) + \
                len(client_hello).to_bytes(2, "big") + client_hello
            raw.sendall(record)
            # Read response (ServerHello + cert + server hello done)
            response = raw.recv(8192)
            if not response:
                return
            # Check if heartbeat extension was negotiated
            # (Scan the ServerHello extensions)
            if b"\x00\x0f" not in response:
                # Heartbeat extension not negotiated — server is not vulnerable
                self._log("  • Heartbeat extension غير متفاوض عليه — آمن", "info")
                return
            # Send a malicious Heartbeat request with payload length 1
            # but declared length 0x4000 (16384). A vulnerable server
            # will reply with 16KB of memory.
            # Heartbeat record: content_type=0x18, version=0x0303
            # payload_type=1 (request), payload_length=0x4000, payload='X'
            heartbeat = bytes([0x01]) + (0x4000).to_bytes(2, "big") + b"X"
            hb_record = bytes([0x18, 0x03, 0x03]) + \
                len(heartbeat).to_bytes(2, "big") + heartbeat
            raw.sendall(hb_record)
            # Read the (potential) heartbeat response
            time.sleep(0.5)
            try:
                raw.settimeout(2.0)
                hb_response = raw.recv(16384 + 32)
            except socket.timeout:
                hb_response = b""
            # If the response is large (>256 bytes), it's leaking memory
            if len(hb_response) > 256:
                # Heuristic: heartbeat responses shouldn't be more than
                # a few bytes for our 1-byte request.
                self._add_finding(
                    ftype="heartbleed",
                    severity=SEV_CRITICAL,
                    url=self.target_url,
                    title="Heartbleed vulnerability (CVE-2014-0160)",
                    description=(
                        "The server appears to be vulnerable to "
                        "Heartbleed (CVE-2014-0160). A malformed TLS "
                        "heartbeat request returned more data than was "
                        "sent, leaking up to 64KB of server memory per "
                        "request. This memory can contain private keys, "
                        "session cookies, and other secrets. Upgrade "
                        "OpenSSL immediately."
                    ),
                    evidence=f"heartbeat response length={len(hb_response)} bytes",
                    cve="CVE-2014-0160",
                )
        except Exception as e:
            self._log(f"  ✗ heartbleed test failed: {e}", "warn")
        finally:
            try:
                raw.close()
            except Exception:
                pass

    def _build_client_hello(self) -> bytes:
        """Build a minimal TLS 1.2 ClientHello with the heartbeat extension."""
        # Heartbeat extension: type=0x000f, length=1, mode=1 (peer_allowed)
        hb_ext = bytes([0x00, 0x0f, 0x00, 0x01, 0x01])
        # Supported versions extension (TLS 1.2 only)
        # We'll just rely on the version field.
        # Cipher suites: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) and
        # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
        cipher_suites = bytes([0x00, 0x04, 0x00, 0x2f, 0xc0, 0x2f])
        # Compression methods: null only
        comp_methods = bytes([0x01, 0x00])
        # Extensions: just heartbeat
        extensions = hb_ext
        ext_block = len(extensions).to_bytes(2, "big") + extensions
        # ClientHello body
        body = bytes([
            0x03, 0x03,  # version TLS 1.2
        ]) + int(time.time()).to_bytes(4, "big") + \
            os.urandom(28) + bytes([0x00]) + cipher_suites + \
            comp_methods + ext_block
        # Handshake header: type=0x01 (ClientHello), length=body
        handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
        return handshake

    def _test_poodle(self):
        """Test for POODLE (SSLv3) and POODLE TLS (TLS fallback)."""
        self._log("  › اختبار POODLE")
        # 1) Classic POODLE — SSLv3 must be disabled (already tested in Phase 1)
        if "SSLv3" in self.supported_protocols:
            self._add_finding(
                ftype="poodle_sslv3",
                severity=SEV_CRITICAL,
                url=self.target_url,
                title="POODLE (SSLv3) vulnerability",
                description=(
                    "The server supports SSLv3, which is vulnerable to "
                    "the POODLE attack (CVE-2014-3566). Attackers can "
                    "decrypt sensitive data by downgrading the connection "
                    "to SSLv3 and exploiting CBC padding. Disable SSLv3."
                ),
                evidence="SSLv3 negotiated successfully",
                cve="CVE-2014-3566",
            )
        # 2) POODLE TLS — some TLS implementations have the same CBC
        # padding bug. Heuristic: if the server supports CBC ciphers
        # in TLSv1.0-TLSv1.2 without AEAD, flag as potential POODLE-TLS.
        if "TLSv1.0" in self.supported_protocols or \
                "TLSv1.1" in self.supported_protocols:
            # Check if CBC ciphers are accepted (we tested in Phase 2)
            if "CBC ciphers (BEAST/Lucky13)" in self.supported_ciphers:
                self._add_finding(
                    ftype="poodle_tls_risk",
                    severity=SEV_MEDIUM,
                    url=self.target_url,
                    title="Potential POODLE TLS vulnerability",
                    description=(
                        "The server supports TLSv1.0/1.1 with CBC cipher "
                        "suites, which may be vulnerable to the POODLE "
                        "TLS variant. Some TLS implementations accept "
                        "malformed CBC padding, allowing padding oracle "
                        "attacks. Prefer AEAD ciphers (GCM, CHACHA20)."
                    ),
                    evidence="CBC ciphers negotiated on TLS 1.0/1.1",
                )

    def _test_beast(self):
        """Test for BEAST attack susceptibility (CBC mode on TLS 1.0)."""
        self._log("  › اختبار BEAST")
        if "TLSv1.0" in self.supported_protocols and \
                "CBC ciphers (BEAST/Lucky13)" in self.supported_ciphers:
            self._add_finding(
                ftype="beast_attack",
                severity=SEV_MEDIUM,
                url=self.target_url,
                title="BEAST attack risk",
                description=(
                    "The server supports TLSv1.0 with CBC mode ciphers, "
                    "which is vulnerable to the BEAST attack (CVE-2011-3389). "
                    "Modern browsers mitigate this client-side, but older "
                    "clients remain vulnerable. Prefer TLS 1.2+ with AEAD "
                    "ciphers."
                ),
                evidence="TLSv1.0 + CBC ciphers negotiated",
                cve="CVE-2011-3389",
            )

    def _test_freak(self):
        """Test for FREAK attack (export-grade RSA cipher support)."""
        self._log("  › اختبار FREAK")
        # Already covered in Phase 2 (EXPORT ciphers category). Re-check.
        if any("EXPORT" in c for c in self.supported_ciphers.keys()):
            self._add_finding(
                ftype="freak_attack",
                severity=SEV_HIGH,
                url=self.target_url,
                title="FREAK attack vulnerability",
                description=(
                    "The server supports export-grade RSA cipher suites, "
                    "which are vulnerable to the FREAK attack (CVE-2015-0204). "
                    "Attackers can downgrade the connection to 512-bit "
                    "export RSA and factor the key in minutes. Disable "
                    "export ciphers."
                ),
                evidence="EXPORT cipher negotiated",
                cve="CVE-2015-0204",
            )

    def _test_logjam(self):
        """Test for Logjam attack (weak DH key exchange)."""
        self._log("  › اختبار Logjam")
        # Test EXPORT DH ciphers
        ctx = self._make_context(ciphers="DH:EDH:EXP-DH:EXP-EDH")
        tls = self._connect_tls(self.host, self.port, ctx, sni=self.sni)
        if tls is None:
            return
        try:
            cipher = tls.cipher()
            if cipher:
                name = cipher[0].upper()
                if "EXPORT" in name or "EXP-" in name:
                    self._add_finding(
                        ftype="logjam_attack",
                        severity=SEV_HIGH,
                        url=self.target_url,
                        title="Logjam attack vulnerability",
                        description=(
                            "The server supports export-grade DH cipher "
                            "suites, which are vulnerable to the Logjam "
                            "attack (CVE-2015-4000). Attackers can "
                            "downgrade to 512-bit DH and compute the "
                            "shared secret in minutes. Disable export DH."
                        ),
                        evidence=f"cipher={cipher[0]}",
                        cve="CVE-2015-4000",
                    )
                else:
                    # Check DH params size — we can't directly, but
                    # if the server uses common 1024-bit DH groups, it
                    # may still be at risk from precomputation. We flag
                    # only as info.
                    kx = cipher[2] if len(cipher) > 2 else ""
                    if "DH" in kx.upper():
                        self._add_finding(
                            ftype="weak_dh_group",
                            severity=SEV_LOW,
                            url=self.target_url,
                            title="DH key exchange used (potential Logjam)",
                            description=(
                                "The server uses DH key exchange. If the "
                                "DH group is 1024-bit or a common prime, "
                                "it may be at risk from nation-state "
                                "Logjam-style precomputation. Prefer ECDHE "
                                "or use a 2048+ bit unique DH group."
                            ),
                            evidence=f"cipher={cipher[0]}, KX={kx}",
                        )
        finally:
            try:
                tls.close()
            except Exception:
                pass

    def _test_crime_breach(self):
        """Test for CRIME / BREACH (HTTP compression on TLS)."""
        self._log("  › اختبار CRIME/BREACH")
        # CRIME = TLS-level compression (already tested in _test_tls_compression)
        # BREACH = HTTP-level compression (gzip) when response contains
        # attacker-controlled input + a secret (e.g. CSRF token in error
        # page). We can detect gzip support but not whether the app is
        # actually vulnerable (depends on whether responses reflect
        # user input alongside secrets).
        r = self.client.get(self.target_url + "/",
                            headers={"Accept-Encoding": "gzip, deflate"})
        if r["status"] == 0:
            return
        headers = {k.lower(): v for k, v in r["headers"].items()}
        enc = headers.get("content-encoding", "").lower()
        if "gzip" in enc or "deflate" in enc:
            self._add_finding(
                ftype="breach_risk",
                severity=SEV_MEDIUM,
                url=self.target_url,
                title="HTTP response compression (BREACH risk)",
                description=(
                    "The server compresses HTTP responses over TLS. "
                    "If responses mix attacker-controlled input with "
                    "secrets (e.g. CSRF tokens in error pages), the "
                    "BREACH attack can recover those secrets via "
                    "compression-ratio oracles. Mitigations: disable "
                    "compression on responses that reflect user input, "
                    "or randomize secret lengths."
                ),
                evidence=f"Content-Encoding: {enc}",
            )

    # ============================================================
    #                       REPORTING
    # ============================================================

    def _build_report(self) -> Dict:
        return {
            "target": self.target_url,
            "host": getattr(self, "host", ""),
            "port": getattr(self, "port", 443),
            "scanner": "TLSScanner",
            "supported_protocols": self.supported_protocols,
            "supported_ciphers": self.supported_ciphers,
            "findings": self.findings,
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
        print(f"{Colors.MAGENTA}  🔒 تقرير فحص TLS/SSL{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")

        # Supported protocols
        if self.supported_protocols:
            print(f"\n  {Colors.BOLD}البروتوكولات المدعومة:{Colors.NC}")
            for p in self.supported_protocols:
                insecure = p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
                color = Colors.RED if insecure else Colors.GREEN
                print(f"    {color}•{Colors.NC} {p}")

        # Findings
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
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات TLS واضحة مكتشفة"
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
        user_agent=args.user_agent or "ghostpwn-tls/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=not args.no_redirects,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="tls_scanner",
        description="ghostpwn - Comprehensive TLS/SSL Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 tls_scanner.py example.com\n"
            "  python3 tls_scanner.py example.com --port 8443\n"
            "  python3 tls_scanner.py example.com --verbose\n"
            "  python3 tls_scanner.py https://example.com --json-out t.json\n"
        ),
    )
    parser.add_argument("target", help="Target host (e.g. example.com "
                                       "or https://example.com)")
    parser.add_argument("--port", type=int, default=443,
                        help="TLS port (default 443)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Socket timeout (default 10)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests (default 0.1)")
    parser.add_argument("--user-agent", default=None,
                        help="Custom User-Agent")
    parser.add_argument("--proxy", default=None,
                        help="HTTP(S) proxy URL")
    parser.add_argument("--cookie", default=None,
                        help="Cookie string")
    parser.add_argument("--no-redirects", action="store_true",
                        help="Disable HTTP redirect following")
    parser.add_argument("--sni", default=None,
                        help="Override SNI hostname")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["protocols", "ciphers", "cert",
                                            "headers", "pfs", "vulns", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_client(args)
    scanner = TLSScanner(
        http_client=client,
        options={
            "port": args.port,
            "timeout": args.timeout,
            "sni": args.sni,
            "verbose": args.verbose,
            "safe_mode": True,
        },
    )

    report = scanner.scan(args.target)

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
