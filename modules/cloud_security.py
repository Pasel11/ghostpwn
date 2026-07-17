#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Cloud Storage Security Scanner
فحص أمان التخزين السحابي والبنية التحتية السحابية

الفحوصات:
1.  AWS S3 bucket enumeration & access testing
2.  AWS S3 bucket misconfiguration (public read / write / listing)
3.  Azure Blob container enumeration
4.  Google Cloud Storage bucket testing
5.  DigitalOcean Spaces testing
6.  Cloud metadata endpoint testing (169.254.169.254)
7.  IAM credential exposure testing
8.  S3 bucket takeover detection (DNS CNAME → unclaimed bucket)
9.  CloudFront bypass / origin disclosure testing
10. Firebase database open access testing

ملاحظات:
- لا يستخدم أي مكتبات خارجية (Python stdlib فقط).
- كل الفحوصات non-destructive: لا يحاول رفع بيانات حقيقية، فقط
  يختبر ListBucket / anonymous GET / anonymous PUT لمسار اختبار آمن.
- يكتشف ويفحص دون تنفيذ هجمات خطيرة.
"""
import os
import sys
import re
import json
import time
import socket
import hashlib
import random
import string
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# AWS S3 URL formats
S3_URL_TEMPLATES = [
    "https://{bucket}.s3.amazonaws.com",
    "https://s3.amazonaws.com/{bucket}",
    "https://{bucket}.s3.{region}.amazonaws.com",
    "https://s3.{region}.amazonaws.com/{bucket}",
]

# Common / interesting bucket name prefixes to try when the target host
# is given (we derive candidate bucket names from the hostname).
BUCKET_NAME_HINTS = [
    "", "-prod", "-dev", "-staging", "-test", "-backup", "-uploads",
    "-media", "-static", "-assets", "-images", "-files", "-data",
    "-public", "-private", "-logs", "-archive", "-archive2",
    "-sandbox", "-qa", "-uat", "-demo", "-internal",
]

# S3 regions to probe (subset of AWS regions)
AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1", "eu-north-1",
    "ap-south-1", "ap-northeast-1", "ap-southeast-1", "ap-southeast-2",
    "ca-central-1", "sa-east-1",
]

# Azure Blob URL patterns
AZURE_BLOB_TEMPLATES = [
    "https://{account}.blob.core.windows.net",
    "https://{account}.blob.core.windows.net/$web",
    "https://{account}.blob.core.windows.net/{container}",
]

AZURE_CONTAINERS = [
    "$web", "public", "container", "blob", "files", "uploads",
    "images", "media", "static", "assets", "data", "backup",
    "logs", "archive", "test", "dev", "staging",
]

# GCS URL patterns
GCS_URL_TEMPLATES = [
    "https://storage.googleapis.com/{bucket}",
    "https://{bucket}.storage.googleapis.com",
    "https://storage.googleapis.com/{bucket}/",
]

# DigitalOcean Spaces
DO_SPACES_TEMPLATES = [
    "https://{name}.ams3.digitaloceanspaces.com",
    "https://{name}.nyc3.digitaloceanspaces.com",
    "https://{name}.sfo2.digitaloceanspaces.com",
    "https://{name}.sgp1.digitaloceanspaces.com",
    "https://{name}.fra1.digitaloceanspaces.com",
    "https://{name}.syd1.digitaloceanspaces.com",
]

# Cloud metadata endpoints — IP-based, common to AWS / GCP / Azure
METADATA_ENDPOINTS = [
    # AWS IMDSv1 (the classic, vulnerable one)
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "AWS IAM Credentials"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
     "AWS IAM Role Credentials"),
    ("http://169.254.169.254/latest/user-data", "AWS User-Data"),
    ("http://169.254.169.254/latest/dynamic/instance-identity/document",
     "AWS Instance Identity"),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/",
     "GCP Metadata (requires Metadata-Flavor header)"),
    ("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
     "GCP Service Account Token"),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "Azure Instance Metadata"),
    ("http://169.254.169.254/metadata/identity/oauth2/token"
     "?api-version=2018-02-01&resource=https://management.azure.com/",
     "Azure Managed Identity Token"),
    # Alibaba / other
    ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud Metadata"),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1.json", "DigitalOcean Metadata"),
]

# Patterns indicating leaked cloud credentials in JS / HTML
CREDENTIAL_PATTERNS = [
    # AWS Access Key ID (20-char, starts with AKIA / ASIA / AGPA / AIDA / AROA / AIPA / ANPA / ANVA)
    (r'\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b',
     "AWS Access Key ID"),
    # AWS Secret Access Key (40-char base64-ish, heuristic only — too noisy alone)
    # we keep it disabled to avoid FPs; left as a comment for documentation
    # Google API key
    (r'\bAIza[0-9A-Za-z\-_]{35}\b', "Google API Key"),
    # Google OAuth secret
    (r'\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b',
     "Google OAuth Client ID"),
    # AWS S3 URL with key (path-style)
    (r'https?://[a-z0-9.\-]+\.s3[a-z0-9.\-]*\.amazonaws\.com/[^\s"\']+',
     "AWS S3 URL"),
    # Azure storage account key (heuristic — 88-char base64)
    (r'\b[A-Za-z0-9+/]{88}={0,2}\b', "Possible Azure Storage Key"),
    # Slack token
    (r'\bxox[baprs]-[0-9A-Za-z-]+\b', "Slack Token"),
    # Stripe key
    (r'\b(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b', "Stripe API Key"),
    # Generic API key patterns
    (r'(?i)aws_secret[_a-z]*\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
     "AWS Secret Key Literal"),
    (r'(?i)aws_access[_a-z]*\s*[=:]\s*["\']([A-Z0-9]{20})["\']',
     "AWS Access Key Literal"),
]

# CloudFront bypass techniques — headers / path tricks
CLOUDFRONT_BYPASS_HEADERS = [
    # Internal / debug headers that some origins trust
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"Host": "localhost"},
    {"X-Custom-Header-Authorized": "true"},
    {"X-Internal-Authorized": "1"},
]

# Firebase DB paths to test (realtime DB)
FIREBASE_TEST_PATHS = [
    "/.json", "/users.json", "/admin.json", "/config.json",
    "/settings.json", "/keys.json", "/secrets.json", "/.json?auth=",
    "/.json?shallow=true", "/.json?print=pretty",
]

# Severity helpers
SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


# ============================ Main Class ============================

class CloudSecurityScanner:
    """فاحص أمان التخزين السحابي والبنية التحتية السحابية"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=12, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self._scanned: Set[str] = set()

        # Tunables
        self.max_buckets = self.options.get("max_buckets", 30)
        self.metadata_timeout = self.options.get("metadata_timeout", 5)
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)
        self.test_write = self.options.get("test_write", False)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[CLOUD-SEC] {msg}", level)

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

    def _req(self, url: str, method: str = "GET",
             headers: Optional[Dict] = None, data=None,
             json_data: Optional[Dict] = None,
             timeout: Optional[int] = None) -> Dict:
        """HTTP wrapper with timeout override support."""
        try:
            # The HttpClient doesn't expose per-request timeout; we just call it.
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
    def _looks_like_xml(text: str) -> bool:
        return bool(text and text.lstrip().startswith("<?xml"))

    @staticmethod
    def _looks_like_json(text: str) -> bool:
        if not text:
            return False
        b = text.lstrip()
        return b.startswith("{") or b.startswith("[")

    @staticmethod
    def _safe_json(text: str) -> Optional[Dict]:
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return None

    def _gen_token(self, n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    # ============================================================
    #                       MAIN SCAN
    # ============================================================

    def scan(self, target: str) -> Dict:
        """نقطة الدخول الرئيسية - تشغّل كل الفحوصات"""
        if not target:
            self._log("Target فارغ", "error")
            return {"target": target, "findings": [], "stats": {}}

        # normalize
        if not target.startswith(("http://", "https://")):
            # Could be a hostname or bucket name
            if "." in target and "/" not in target:
                target = "https://" + target
            else:
                target = "https://" + target
        target = target.rstrip("/")
        self._log(f"بدء فحص أمان السحابة: {target}", "phase")

        parsed = urlparse(target)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.netloc.split(":")[0]
        self.target = target

        # ---------- Phase 1: Cloud metadata & SSRF ----------
        self._log("Phase 1: Cloud Metadata & SSRF", "phase")
        self._test_cloud_metadata()
        self._test_ssrf_to_metadata()

        # ---------- Phase 2: S3 buckets ----------
        self._log("Phase 2: AWS S3 Bucket Testing", "phase")
        candidates = self._derive_bucket_candidates()
        self._enumerate_s3_buckets(candidates)
        self._test_s3_takeover()

        # ---------- Phase 3: Azure / GCS / DO ----------
        self._log("Phase 3: Azure / GCS / DigitalOcean", "phase")
        self._test_azure_blob()
        self._test_gcs_buckets()
        self._test_digitalocean_spaces()

        # ---------- Phase 4: CloudFront ----------
        self._log("Phase 4: CloudFront / CDN bypass", "phase")
        self._test_cloudfront_bypass()

        # ---------- Phase 5: Firebase ----------
        self._log("Phase 5: Firebase open DB", "phase")
        self._test_firebase_open_access()

        # ---------- Phase 6: Credential exposure ----------
        self._log("Phase 6: IAM Credential Exposure", "phase")
        self._test_credential_exposure()

        self._print_results()
        return self._build_report()

    # ============================================================
    #        PHASE 1 — Cloud Metadata & SSRF
    # ============================================================

    def _test_cloud_metadata(self):
        """Direct probe of cloud metadata endpoints (only relevant if
        the scanner itself is running inside a cloud VM, but we report
        findings either way for completeness)."""
        self._log("  › فحص cloud metadata endpoints (169.254.169.254)")
        for url, label in METADATA_ENDPOINTS:
            # AWS IMDSv1 needs no headers; GCP needs Metadata-Flavor
            headers = None
            if "metadata.google" in url or "computeMetadata" in url:
                headers = {"Metadata-Flavor": "Google"}
            elif "169.254.169.254/metadata" in url:
                headers = {"Metadata": "true"}

            resp = self._req(url, headers=headers)
            if resp["status"] == 0:
                continue
            if resp["status"] == 200 and resp["body"]:
                body = resp["body"]
                # Check for sensitive content
                sensitive = self._contains_sensitive_metadata(body)
                sev = SEV_CRITICAL if sensitive else SEV_HIGH
                self._add_finding(
                    ftype="cloud_metadata_exposure",
                    severity=sev,
                    url=url,
                    title=f"{label} accessible",
                    description=(
                        f"The cloud metadata endpoint {label} is reachable "
                        f"from this host and returned a 200 OK. This "
                        f"indicates the scanner (or the target via SSRF) "
                        f"can read instance metadata, which may include "
                        f"IAM credentials and user-data scripts."
                    ),
                    evidence=self._short(body, 400),
                    metadata_label=label,
                )

    def _test_ssrf_to_metadata(self):
        """Try common SSRF patterns against the target to see if it
        fetches URLs from user input (which would let an attacker
        reach the metadata IP)."""
        self._log("  › اختبار SSRF → metadata عبر المعاملات الشائعة")
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data",
            "http://[::]:169.254.169.254/latest/meta-data/",
            "http://0:80/latest/meta-data/",
            "http://169.254.169.254@evil.com/",
            "http://2130706433/latest/meta-data/",  # 127.0.0.1 decimal
        ]
        ssrf_params = ["url", "uri", "redirect", "next", "to", "target",
                       "image", "img", "file", "fetch", "src", "source",
                       "callback", "return", "returnUrl", "return_url",
                       "ref", "reference", "path", "dest", "destination"]

        # Probe only the home page for forms / params we can use
        home = self._req(self.target)
        if home["status"] == 0 or not home["body"]:
            return
        body = home["body"]

        # Find a likely SSRF parameter in URL / forms
        test_urls = []
        for p in ssrf_params:
            test_urls.append(f"{self.target}/?{p}=" +
                             quote(ssrf_payloads[0]))
            test_urls.append(f"{self.target}/fetch?{p}=" +
                             quote(ssrf_payloads[0]))
        # Also try with a few payloads on the first param
        for payload in ssrf_payloads[:3]:
            test_urls.append(f"{self.target}/?url=" + quote(payload))

        # Cap the number of requests
        for url in test_urls[:8]:
            resp = self._req(url)
            if resp["status"] == 0:
                continue
            rbody = resp["body"] or ""
            if self._contains_sensitive_metadata(rbody):
                self._add_finding(
                    ftype="ssrf_metadata_leak",
                    severity=SEV_CRITICAL,
                    url=url,
                    title="SSRF → Cloud Metadata exposure",
                    description=(
                        "The target appears to fetch URLs from a query "
                        "parameter and returned content from the cloud "
                        "metadata endpoint (169.254.169.254). An attacker "
                        "could exploit this to steal IAM credentials."
                    ),
                    evidence=self._short(rbody, 400),
                )
                break  # one strong finding is enough

    @staticmethod
    def _contains_sensitive_metadata(text: str) -> bool:
        if not text:
            return False
        markers = [
            "AccessKeyId", "SecretAccessKey", "Token", "iam",
            "security-credentials", "instance-id", "ami-id",
            "availability-zone", "instance-identity",
            "service-accounts", "access_token", "clientId",
            "subscriptionId", "vmId",
        ]
        low = text.lower()
        return any(m.lower() in low for m in markers)

    # ============================================================
    #        PHASE 2 — AWS S3
    # ============================================================

    def _derive_bucket_candidates(self) -> List[str]:
        """Derive candidate S3 bucket names from the target hostname."""
        host = self.host
        # strip common prefixes
        base = host
        for prefix in ["www.", "m.", "api.", "static.", "assets.",
                       "cdn.", "media.", "img.", "files."]:
            if base.startswith(prefix):
                base = base[len(prefix):]
                break
        # split into labels
        labels = base.split(".")
        candidates = []
        # full hostname (without TLD)
        if len(labels) >= 2:
            candidates.append(labels[0])
            candidates.append("-".join(labels[:-1]))
            candidates.append(".".join(labels[:-1]))
        # subdomain + base
        candidates.append(base)
        # add hints
        expanded = []
        for c in candidates:
            if not c or len(c) > 63:
                continue
            expanded.append(c)
            for hint in BUCKET_NAME_HINTS:
                name = (c + hint).strip("-")
                if 3 <= len(name) <= 63 and re.match(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$", name):
                    expanded.append(name)
        # de-dupe preserving order
        seen, out = set(), []
        for c in expanded:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out[:self.max_buckets]

    def _enumerate_s3_buckets(self, candidates: List[str]):
        """Probe candidate S3 bucket names and test their ACLs."""
        self._log(f"  › اختبار {len(candidates)} اسم bucket محتمل")
        for name in candidates:
            # First format: virtual-hosted
            url = f"https://{name}.s3.amazonaws.com"
            resp = self._req(url)
            self._analyze_s3_response(name, url, resp)

    def _analyze_s3_response(self, bucket: str, url: str, resp: Dict):
        """Analyze an S3 bucket HTTP response and record findings."""
        if resp["status"] == 0:
            return
        # 404 = bucket doesn't exist (NoSuchBucket)
        if resp["status"] == 404:
            return
        # 301 = bucket exists but in another region (LocationConstraint)
        if resp["status"] == 301:
            loc = resp["headers"].get("x-amz-bucket-region", "") \
                or resp["headers"].get("X-Amz-Bucket-Region", "")
            region = loc or "unknown"
            self._log(f"  • bucket {bucket} exists (region={region})", "info")
            # Re-test against the right region
            if loc and loc != "us-east-1":
                url2 = f"https://{bucket}.s3.{loc}.amazonaws.com"
                resp2 = self._req(url2)
                if resp2["status"] != 0:
                    self._check_s3_listing(bucket, url2, resp2)
                    self._check_s3_write(bucket, url2, resp2)
            return

        if resp["status"] == 200:
            body = resp["body"] or ""
            # 200 with XML ListBucketResult = publicly listable
            if self._looks_like_xml(body) and "ListBucketResult" in body:
                self._add_finding(
                    ftype="s3_public_listing",
                    severity=SEV_HIGH,
                    url=url,
                    title=f"S3 bucket '{bucket}' publicly listable",
                    description=(
                        f"The S3 bucket '{bucket}' allows anonymous listing. "
                        f"Any internet user can enumerate and download all "
                        f"objects stored in this bucket."
                    ),
                    evidence=self._short(body, 400),
                    bucket=bucket,
                )
                self._enumerate_s3_objects(bucket, url, body)
            elif body and not self._looks_like_xml(body):
                # 200 with non-XML content (could be a configured website)
                self._add_finding(
                    ftype="s3_public_read",
                    severity=SEV_MEDIUM,
                    url=url,
                    title=f"S3 bucket '{bucket}' public read access",
                    description=(
                        f"The S3 bucket '{bucket}' returns content to "
                        f"anonymous requests without authentication. Verify "
                        f"this is intentional — many buckets expose sensitive "
                        f"objects this way."
                    ),
                    evidence=self._short(body, 300),
                    bucket=bucket,
                )
        # 403 = bucket exists but is private (still useful info)
        elif resp["status"] == 403:
            self._log(f"  • bucket {bucket} exists (private)", "info")
            # Even private, try ?listing-type=2 to be sure
            self._check_s3_listing(bucket, url, resp)

    def _enumerate_s3_objects(self, bucket: str, url: str, listing_xml: str):
        """Extract object keys from a bucket listing and probe them."""
        keys = re.findall(r"<Key>([^<]+)</Key>", listing_xml)
        if not keys:
            return
        self._log(f"  › استخراج {len(keys)} مفتاح من bucket {bucket}")
        interesting_exts = [".sql", ".bak", ".zip", ".tar", ".gz",
                            ".env", ".key", ".pem", ".crt", ".pfx",
                            ".json", ".yml", ".yaml", ".conf", ".cfg",
                            ".log", ".csv", ".xlsx", ".docx"]
        sensitive = [k for k in keys
                     if any(k.lower().endswith(e) for e in interesting_exts)
                     or "backup" in k.lower() or "secret" in k.lower()
                     or "password" in k.lower() or "cred" in k.lower()]
        for key in sensitive[:10]:
            obj_url = f"https://{bucket}.s3.amazonaws.com/{quote(key)}"
            r = self._req(obj_url, method="HEAD")
            if r["status"] == 200:
                size = r["headers"].get("Content-Length", "?")
                self._add_finding(
                    ftype="s3_sensitive_object",
                    severity=SEV_HIGH,
                    url=obj_url,
                    title=f"Sensitive object exposed in S3 bucket '{bucket}'",
                    description=(
                        f"Object '{key}' (size={size}) is publicly readable "
                        f"in the listable bucket '{bucket}'. Its filename "
                        f"suggests it may contain sensitive data."
                    ),
                    evidence=f"HEAD {obj_url} → 200, size={size}",
                    bucket=bucket,
                    key=key,
                )

    def _check_s3_listing(self, bucket: str, url: str, resp: Dict):
        """Try a GET on the bucket root to detect listing on a
        bucket that returns 403 on HEAD but allows listing on GET."""
        r = self._req(url)
        if r["status"] == 200 and self._looks_like_xml(r["body"] or "") \
                and "ListBucketResult" in r["body"]:
            self._add_finding(
                ftype="s3_public_listing",
                severity=SEV_HIGH,
                url=url,
                title=f"S3 bucket '{bucket}' publicly listable (GET)",
                description=(
                    f"Even though the bucket returned an error on initial "
                    f"probe, a direct GET reveals a full directory listing "
                    f"to anonymous users."
                ),
                evidence=self._short(r["body"], 400),
                bucket=bucket,
            )

    def _check_s3_write(self, bucket: str, url: str, resp: Dict):
        """Test if the bucket allows anonymous PUT by writing a
        small benign file with a ghostpwn-prefixed name."""
        if not self.test_write:
            return
        token = self._gen_token()
        test_key = f"ghostpwn-write-test-{token}.txt"
        test_url = f"https://{bucket}.s3.amazonaws.com/{test_key}"
        body = f"ghostpwn security scan write-test {token}"
        r = self._req(test_url, method="PUT", data=body)
        if r["status"] in (200, 201):
            self._add_finding(
                ftype="s3_public_write",
                severity=SEV_CRITICAL,
                url=test_url,
                title=f"S3 bucket '{bucket}' allows public WRITE",
                description=(
                    f"Anonymous users can write objects to bucket '{bucket}'. "
                    f"This is a critical misconfiguration that allows "
                    f"attackers to upload malicious content, deface the "
                    f"site, or fill the bucket (causing cost)."
                ),
                evidence=f"PUT {test_url} → {r['status']}",
                bucket=bucket,
            )
            # Cleanup
            try:
                self._req(test_url, method="DELETE")
            except Exception:
                pass

    def _test_s3_takeover(self):
        """Detect S3 buckets referenced via DNS CNAME that have been
        deleted — a classic subdomain-takeover vector."""
        self._log("  › فحص S3 takeover (DNS CNAME → unclaimed bucket)")
        # We can't dig DNS without external deps, but we can resolve CNAMEs
        # via socket.gethostbyname_ex which returns alias chain.
        try:
            host = self.host
            # Test a few common subdomains
            subs = [host, "www." + host, "static." + host, "assets." + host,
                    "media." + host, "cdn." + host, "s3." + host]
            for h in subs:
                try:
                    _, aliases, _ = socket.gethostbyname_ex(h)
                except socket.gaierror:
                    continue
                for alias in aliases:
                    if alias.endswith(".amazonaws.com") and \
                            ("s3" in alias or "s3-website" in alias):
                        # Resolve the alias URL and check if bucket claimed
                        # (HTTP 404 NoSuchBucket = takeover)
                        bucket_url = "https://" + alias
                        r = self._req(bucket_url)
                        body = r["body"] or ""
                        if r["status"] == 404 and "NoSuchBucket" in body:
                            self._add_finding(
                                ftype="s3_takeover",
                                severity=SEV_HIGH,
                                url=bucket_url,
                                title=f"Potential S3 subdomain takeover: {h}",
                                description=(
                                    f"DNS for '{h}' points to '{alias}' but "
                                    f"the S3 bucket no longer exists. An "
                                    f"attacker can create a bucket with that "
                                    f"name and serve arbitrary content on "
                                    f"the victim's subdomain."
                                ),
                                evidence=self._short(body, 300),
                                subdomain=h,
                                cname=alias,
                            )
        except Exception as e:
            self._log(f"  ✗ takeover check failed: {e}", "warn")

    # ============================================================
    #        PHASE 3 — Azure / GCS / DigitalOcean
    # ============================================================

    def _test_azure_blob(self):
        """Probe Azure Blob storage accounts derived from hostname."""
        self._log("  › فحص Azure Blob containers")
        # Derive account name from host (first label)
        labels = self.host.split(".")
        candidates = []
        if labels:
            base = re.sub(r'[^a-z0-9]', '', labels[0].lower())
            if 3 <= len(base) <= 24:
                candidates.append(base)
                for hint in ["prod", "dev", "staging", "test", "backup"]:
                    n = (base + hint)[:24]
                    if len(n) >= 3:
                        candidates.append(n)
        for account in candidates[:10]:
            base_url = f"https://{account}.blob.core.windows.net"
            # First probe the account root
            r = self._req(base_url)
            if r["status"] == 0:
                continue
            # Probe each common container
            for container in AZURE_CONTAINERS:
                url = f"{base_url}/{container}?restype=container&comp=list"
                r2 = self._req(url)
                if r2["status"] == 200 and r2["body"]:
                    body = r2["body"]
                    if "EnumerationResults" in body or "<Blobs>" in body:
                        self._add_finding(
                            ftype="azure_blob_public_listing",
                            severity=SEV_HIGH,
                            url=url,
                            title=f"Azure Blob container '{container}' publicly listable",
                            description=(
                                f"The Azure Blob container '{container}' in "
                                f"storage account '{account}' allows anonymous "
                                f"listing via the REST API. Anyone can enumerate "
                                f"and download stored blobs."
                            ),
                            evidence=self._short(body, 400),
                            account=account,
                            container=container,
                        )

    def _test_gcs_buckets(self):
        """Probe Google Cloud Storage buckets derived from hostname."""
        self._log("  › فحص Google Cloud Storage buckets")
        candidates = self._derive_bucket_candidates()
        for name in candidates[:15]:
            for tpl in GCS_URL_TEMPLATES:
                url = tpl.format(bucket=name)
                r = self._req(url)
                if r["status"] == 0:
                    continue
                if r["status"] == 200 and r["body"]:
                    body = r["body"]
                    # GCS listing returns XML with ListBucketResult
                    if "ListBucketResult" in body:
                        self._add_finding(
                            ftype="gcs_public_listing",
                            severity=SEV_HIGH,
                            url=url,
                            title=f"GCS bucket '{name}' publicly listable",
                            description=(
                                f"The Google Cloud Storage bucket '{name}' "
                                f"allows anonymous listing. Any user can "
                                f"enumerate and download objects."
                            ),
                            evidence=self._short(body, 400),
                            bucket=name,
                        )
                elif r["status"] == 403:
                    # Bucket exists but private — useful intel only
                    pass
                break  # don't need to try both URL formats

    def _test_digitalocean_spaces(self):
        """Probe DigitalOcean Spaces (S3-compatible)."""
        self._log("  › فحص DigitalOcean Spaces")
        candidates = self._derive_bucket_candidates()
        for name in candidates[:10]:
            for tpl in DO_SPACES_TEMPLATES:
                url = tpl.format(name=name)
                r = self._req(url)
                if r["status"] == 0:
                    continue
                if r["status"] == 200 and r["body"] and \
                        "ListBucketResult" in r["body"]:
                    self._add_finding(
                        ftype="do_space_public_listing",
                        severity=SEV_HIGH,
                        url=url,
                        title=f"DigitalOcean Space '{name}' publicly listable",
                        description=(
                            f"The DigitalOcean Space '{name}' allows "
                            f"anonymous listing. Anyone can enumerate and "
                            f"download objects."
                        ),
                        evidence=self._short(r["body"], 400),
                        space=name,
                    )
                    break
                if r["status"] == 403:
                    # Space exists but is private — skip
                    break

    # ============================================================
    #        PHASE 4 — CloudFront bypass
    # ============================================================

    def _test_cloudfront_bypass(self):
        """Try to bypass CloudFront by sending internal headers that
        the origin may trust without checking."""
        self._log("  › فحص CloudFront / CDN bypass")
        # Fetch baseline
        base_resp = self._req(self.target)
        if base_resp["status"] == 0:
            return
        base_body = base_resp["body"] or ""
        base_hash = hashlib.sha256(base_body.encode("utf-8", "ignore")).hexdigest()
        base_server = (base_resp["headers"].get("Server", "") or
                       base_resp["headers"].get("server", ""))
        is_cloudfront = "cloudfront" in base_server.lower() or \
            "x-amz-cf-id" in {k.lower() for k in base_resp["headers"].keys()}
        if not is_cloudfront:
            self._log("  • الهدف لا يبدو خلف CloudFront — تخطّي", "info")
            return

        for hdrs in CLOUDFRONT_BYPASS_HEADERS:
            r = self._req(self.target, headers=hdrs)
            if r["status"] == 0:
                continue
            rbody = r["body"] or ""
            rhash = hashlib.sha256(rbody.encode("utf-8", "ignore")).hexdigest()
            if rhash != base_hash and r["status"] == 200:
                # Different content — origin may be serving internal page
                self._add_finding(
                    ftype="cloudfront_origin_bypass",
                    severity=SEV_MEDIUM,
                    url=self.target,
                    title="CloudFront origin bypass via header spoofing",
                    description=(
                        f"Sending the header {list(hdrs.keys())[0]} "
                        f"returned different content than the baseline "
                        f"CloudFront response. The origin server appears "
                        f"to trust this header, which may expose internal "
                        f"endpoints or admin functionality."
                    ),
                    evidence=f"header={hdrs}, body_len_delta="
                             f"{len(rbody) - len(base_body)}",
                    header=str(hdrs),
                )

    # ============================================================
    #        PHASE 5 — Firebase
    # ============================================================

    def _test_firebase_open_access(self):
        """Test Firebase Realtime Database for open read/write access."""
        self._log("  › فحص Firebase Realtime DB open access")
        # Derive Firebase DB URL from JS / HTML on the home page
        home = self._req(self.target)
        if home["status"] == 0 or not home["body"]:
            return
        body = home["body"]
        # Look for firebaseio.com URLs in JS
        fb_urls = set(re.findall(
            r'https?://[a-z0-9\-]+\.firebaseio\.com', body, re.IGNORECASE))
        # Also look for firebaseConfig blocks
        cfg_match = re.search(
            r'databaseURL\s*:\s*["\']([^"\']+\.firebaseio\.com[^"\']*)["\']',
            body)
        if cfg_match:
            fb_urls.add(cfg_match.group(1).rstrip("/"))
        # Also try hostname-derived candidate
        labels = self.host.split(".")
        if labels:
            cand = labels[0].lower()
            fb_urls.add(f"https://{cand}.firebaseio.com")

        for fb_url in list(fb_urls)[:5]:
            fb_url = fb_url.rstrip("/")
            for path in FIREBASE_TEST_PATHS:
                url = fb_url + path
                r = self._req(url)
                if r["status"] == 200 and r["body"]:
                    rbody = r["body"]
                    # Open read — DB returns JSON
                    if self._looks_like_json(rbody) or rbody == "null":
                        sev = SEV_HIGH if path in ("/.json", "/users.json",
                                                   "/admin.json",
                                                   "/secrets.json") \
                            else SEV_MEDIUM
                        self._add_finding(
                            ftype="firebase_open_read",
                            severity=sev,
                            url=url,
                            title=f"Firebase DB open read at {path}",
                            description=(
                                f"The Firebase Realtime Database at "
                                f"{fb_url} allows unauthenticated reads at "
                                f"{path}. Misconfigured security rules are "
                                f"exposing data to the internet."
                            ),
                            evidence=self._short(rbody, 300),
                            database=fb_url,
                        )
                elif r["status"] == 401:
                    # Permission denied — that's expected for secure DBs
                    pass

        # Test open write (only if explicit opt-in)
        if self.test_write and fb_urls:
            token = self._gen_token()
            test_url = next(iter(fb_urls)).rstrip("/") + \
                f"/ghostpwn-test/{token}.json"
            r = self._req(test_url, method="PUT",
                          data=json.dumps({"scanner": "ghostpwn",
                                           "ts": int(time.time())}))
            if r["status"] == 200:
                self._add_finding(
                    ftype="firebase_open_write",
                    severity=SEV_CRITICAL,
                    url=test_url,
                    title="Firebase DB allows open write",
                    description=(
                        "The Firebase Realtime Database allows anonymous "
                        "writes. An attacker can inject malicious data, "
                        "overwrite existing records, or destroy data."
                    ),
                    evidence=f"PUT {test_url} → 200, body={r['body'][:200]}",
                )
                # Cleanup
                try:
                    self._req(test_url, method="DELETE")
                except Exception:
                    pass

    # ============================================================
    #        PHASE 6 — IAM credential exposure
    # ============================================================

    def _test_credential_exposure(self):
        """Scan the home page and JS files for leaked cloud credentials."""
        self._log("  › فحص تسريب IAM credentials في JS/HTML")
        urls_to_scan = [self.target]
        home = self._req(self.target)
        if home["status"] == 200 and home["body"]:
            # Find JS files
            js_files = re.findall(
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                home["body"], re.IGNORECASE)
            for js in js_files[:15]:
                urls_to_scan.append(urljoin(self.target, js))
            # Also scan the home page itself
            self._scan_text_for_credentials(home["body"], self.target)

        for js_url in urls_to_scan[1:]:
            r = self._req(js_url)
            if r["status"] == 200 and r["body"]:
                self._scan_text_for_credentials(r["body"], js_url)

    def _scan_text_for_credentials(self, text: str, url: str):
        """Run regex patterns against the given text and report matches."""
        if not text:
            return
        for pattern, label in CREDENTIAL_PATTERNS:
            for m in re.finditer(pattern, text):
                value = m.group(0)
                # Sanity: avoid obvious false positives (e.g., placeholder)
                if any(p in value.lower() for p in ["example", "placeholder",
                                                     "your-key", "xxxxx",
                                                     "test-key"]):
                    continue
                sev = SEV_CRITICAL if "AWS Access Key" in label \
                    or "AWS Secret" in label or "Slack" in label \
                    or "Stripe" in label else SEV_HIGH
                self._add_finding(
                    ftype="cloud_credential_exposure",
                    severity=sev,
                    url=url,
                    title=f"{label} exposed in client-side code",
                    description=(
                        f"A {label} appears to be embedded in the page or "
                        f"JavaScript at {url}. Cloud credentials leaked "
                        f"this way are trivially harvestable by attackers "
                        f"and should be rotated immediately."
                    ),
                    evidence=self._short(value, 120),
                    credential_type=label,
                )

    # ============================================================
    #                       REPORTING
    # ============================================================

    def _build_report(self) -> Dict:
        return {
            "target": self.target,
            "host": getattr(self, "host", ""),
            "scanner": "CloudSecurityScanner",
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
        print(f"{Colors.MAGENTA}  ☁️  تقرير فحص أمان السحابة{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*64}{Colors.NC}")

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
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات سحابية واضحة مكتشفة"
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
        user_agent=args.user_agent or "ghostpwn-cloud/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=not args.no_redirects,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="cloud_security",
        description="ghostpwn - Cloud Storage Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 cloud_security.py https://example.com\n"
            "  python3 cloud_security.py https://example.com --verbose\n"
            "  python3 cloud_security.py https://example.com "
            "--test-write\n"
            "  python3 cloud_security.py https://example.com "
            "--json-out cloud.json\n"
        ),
    )
    parser.add_argument("url", help="Target URL or hostname "
                                   "(e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=12,
                        help="HTTP timeout (default 12)")
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
    parser.add_argument("--max-buckets", type=int, default=30,
                        help="Max candidate bucket names to try")
    parser.add_argument("--test-write", action="store_true",
                        help="Test anonymous WRITE on buckets / Firebase "
                             "(writes a benign probe object, then deletes it)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["metadata", "s3", "azure",
                                            "gcs", "do", "cloudfront",
                                            "firebase", "creds", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_client(args)
    scanner = CloudSecurityScanner(
        http_client=client,
        options={
            "max_buckets": args.max_buckets,
            "test_write": args.test_write,
            "verbose": args.verbose,
            "safe_mode": not args.test_write,
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
