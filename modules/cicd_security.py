#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - CI/CD Pipeline Security Scanner
فحص أمان خطوط CI/CD (Continuous Integration / Continuous Deployment)

الفحوصات:
1.  Jenkins exposure & script console testing
2.  Jenkins credential enumeration
3.  GitLab CI exposure testing
4.  GitHub Actions security
5.  Build artifact exposure
6.  Secret scanning in CI configs
7.  Pipeline injection testing
8.  Deploy key enumeration
9.  Webhook secret testing
10. Container registry security (in CI context)

ملاحظات:
- لا يستخدم أي مكتبات خارجية (Python stdlib فقط).
- كل الفحوصات non-destructive: لا يحاول تنفيذ pipelines أو تعديلها.
- يكتشف ويفحص دون تنفيذ هجمات خطيرة.
"""
import os
import sys
import re
import json
import time
import hashlib
import hmac
import base64
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# Jenkins endpoints
JENKINS_PATHS = [
    "/", "/login", "/api/json", "/api/xml", "/asynchPeople/",
    "/people/", "/view/All/api/json", "/computer/api/json",
    "/credential-store/domain/_/", "/credentials/store/system/domain/_/",
    "/pluginManager/api/json", "/manage", "/manage/api/json",
    "/script", "/scriptText", "/jenkins-cli.sh",
    "/whoAmI/api/json", "/me/api/json",
    "/job/", "/view/All/builds", "/systemInfo",
    "/load-statistics/api/json", "/queue/api/json",
]

# Jenkins script console RCE test payload (read-only — just reads /etc/hostname)
JENKINS_SCRIPT_PAYLOAD = "println(new File('/etc/hostname').text)"

# GitLab endpoints
GITLAB_PATHS = [
    "/", "/users/sign_in", "/api/v4/version", "/api/v4/projects",
    "/api/v4/groups", "/api/v4/users", "/api/v4/namespaces",
    "/api/v4/runners", "/api/v4/runners/all", "/api/v4/jobs",
    "/api/v4/ci/runners", "/-/graphql", "/explore", "/explore/projects",
    "/api/v4/applications", "/api/v4/personal_access_tokens",
    "/-/profile", "/admin", "/admin/runners", "/admin/jobs",
]

# GitHub Enterprise endpoints (self-hosted GHES)
GITHUB_ENTERPRISE_PATHS = [
    "/api/v3/enterprise/stats/all", "/api/v3/enterprise/installation",
    "/api/v3/users", "/api/v3/repos", "/api/v3/orgs",
    "/api/v3/teams", "/api/v3/actions/runners",
    "/api/v3/actions/permissions",
    "/setup/api/configcheck", "/setup/api/maintenance",
    "/setup/api/settings", "/setup/api/hoststats",
]

# Common CI/CD config file paths exposed on web
CI_CONFIG_PATHS = [
    "/.gitlab-ci.yml", "/jenkinsfile", "/Jenkinsfile",
    "/.github/workflows/build.yml", "/.github/workflows/ci.yml",
    "/.github/workflows/deploy.yml", "/.drone.yml", "/circle.yml",
    "/.circleci/config.yml", "/azure-pipelines.yml", "/bitbucket-pipelines.yml",
    "/.travis.yml", "/appveyor.yml", "/teamcity.yml", "/build.yaml",
    "/build.yml", "/ci.yml", "/cd.yml", "/pipeline.yml",
    "/.gitlab-ci.yaml", "/Jenkinsfile.groovy", "/.github/actions/",
]

# Build artifact directories commonly exposed
ARTIFACT_PATHS = [
    "/artifacts/", "/builds/", "/dist/", "/target/", "/out/",
    "/bin/", "/release/", "/releases/", "/output/",
    "/artifacts/latest/", "/artifacts/master/", "/artifacts/main/",
    "/build/", "/build/latest/", "/build/master/", "/build/main/",
    "/.cache/", "/tmp/", "/reports/", "/coverage/",
    "/junit/", "/test-results/", "/test-results/xml/",
]

# Secret patterns to scan CI configs for
SECRET_PATTERNS = [
    (r'(?i)\baws[_\-]?access[_\-]?key[_\-]?id\s*[=:]\s*["\']?[A-Z0-9]{20}["\']?',
     "AWS Access Key ID"),
    (r'(?i)\baws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
     "AWS Secret Access Key"),
    (r'\bAKIA[A-Z0-9]{16}\b', "AWS Access Key ID (raw)"),
    (r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b', "GitHub Token"),
    (r'\bglpat-[A-Za-z0-9_\-]{20}\b', "GitLab Personal Access Token"),
    (r'\bxox[baprs]-[0-9A-Za-z\-]+\b', "Slack Token"),
    (r'\bAIza[0-9A-Za-z\-_]{35}\b', "Google API Key"),
    (r'\b(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b', "Stripe API Key"),
    (r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
     "Private Key"),
    (r'(?i)\b(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
     "Hardcoded Password"),
    (r'(?i)\b(?:secret|api[_\-]?key|token)\s*[=:]\s*["\']([^"\']{8,})["\']',
     "Hardcoded Secret"),
    (r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b',
     "JWT Token"),
    (r'(?i)\b(?:mysql|postgres|mongodb|redis)://[^:\s]+:[^@\s]+@',
     "Database URL with credentials"),
    (r'(?i)\b(?:npm|yarn)_[A-Za-z0-9]{36}\b', "NPM/Yarn Token"),
    (r'(?i)\bDocker[_\-]?Hub[_\-]?(?:Username|Password|Token)',
     "Docker Hub Credential Field"),
    (r'(?i)\bDD[_\-]?API[_\-]?KEY\s*[=:]\s*["\']?[A-Za-z0-9]{32}',
     "Datadog API Key"),
    (r'(?i)\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b',
     "SendGrid API Key"),
    (r'(?i)\b(?:azure|arm)_tenant_id\s*[=:]', "Azure Tenant ID Field"),
]

# Webhook signature header names (for testing)
WEBHOOK_HEADERS = [
    ("X-Hub-Signature-256", "GitHub"),
    ("X-Hub-Signature", "GitHub (sha1)"),
    ("X-Gitlab-Token", "GitLab"),
    ("X-GitHub-Event", "GitHub Event"),
    ("X-GitHub-Delivery", "GitHub Delivery"),
    ("X-Forwarded-For", "Reverse Proxy"),
    ("X-Request-Id", "Request ID"),
]

# Pipeline injection payloads — variables that, if attacker-controlled,
# would let an attacker inject commands into a pipeline
INJECTION_PATTERNS = [
    r'\$\{[^}]*\}',            # ${VAR}
    r'\$[A-Z][A-Z0-9_]*',       # $VAR
    r'%[A-Z][A-Z0-9_]*%',       # %VAR%
    r'`[^`]*`',                 # backticks
    r'\$\([^)]*\)',             # $(...)
]

# Common deploy key / SSH key endpoints (mostly on self-hosted GitLab/Forgejo)
DEPLOY_KEY_PATHS = [
    "/api/v4/projects", "/api/v4/projects?simple=true",
    "/api/v4/projects?membership=true",
    "/api/v4/projects?per_page=100",
    "/api/v1/repos/search",  # Forgejo / Gitea
    "/api/v1/user/repos",
]

# Container registry endpoints in CI context
REGISTRY_PATHS = [
    "/v2/", "/v2/_catalog", "/v2/_catalog?n=100",
    "/v1/repositories", "/v1/search",
]

# Severity
SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


# ============================ Main Class ============================

class CICDSecurityScanner:
    """فاحص أمان خطوط CI/CD"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=12, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self._scanned: Set[str] = set()
        self._ci_configs: List[Tuple[str, str]] = []  # (url, content)

        # Tunables
        self.test_script_console = self.options.get("test_script_console", False)
        self.max_artifacts = self.options.get("max_artifacts", 30)
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[CICD-SEC] {msg}", level)

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
        self._log(f"بدء فحص أمان CI/CD: {target}", "phase")

        parsed = urlparse(target)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.netloc.split(":")[0]
        self.target = target

        # Detect what CI/CD system this is
        self.system_type = self._detect_system_type()

        # ---------- Phase 1: Jenkins ----------
        if self.system_type in ("jenkins", "unknown"):
            self._log("Phase 1: Jenkins", "phase")
            self._test_jenkins()
            self._test_jenkins_credentials()

        # ---------- Phase 2: GitLab ----------
        if self.system_type in ("gitlab", "unknown"):
            self._log("Phase 2: GitLab CI", "phase")
            self._test_gitlab_ci()

        # ---------- Phase 3: GitHub ----------
        if self.system_type in ("github", "unknown"):
            self._log("Phase 3: GitHub Actions", "phase")
            self._test_github_actions()

        # ---------- Phase 4: Build artifacts ----------
        self._log("Phase 4: Build artifacts exposure", "phase")
        self._test_build_artifact_exposure()

        # ---------- Phase 5: Secret scanning ----------
        self._log("Phase 5: Secret scanning in CI configs", "phase")
        self._fetch_ci_configs()
        self._scan_secrets_in_configs()

        # ---------- Phase 6: Pipeline injection ----------
        self._log("Phase 6: Pipeline injection", "phase")
        self._test_pipeline_injection()

        # ---------- Phase 7: Deploy keys ----------
        self._log("Phase 7: Deploy key enumeration", "phase")
        self._test_deploy_keys()

        # ---------- Phase 8: Webhook secrets ----------
        self._log("Phase 8: Webhook secret testing", "phase")
        self._test_webhook_secrets()

        # ---------- Phase 9: Registry ----------
        self._log("Phase 9: Container registry security", "phase")
        self._test_ci_registry()

        self._print_results()
        return self._build_report()

    # ============================================================
    #        System detection
    # ============================================================

    def _detect_system_type(self) -> str:
        """Identify which CI/CD system the target is."""
        r = self._req(self.target)
        if r["status"] == 0 or not r["body"]:
            return "unknown"
        body = r["body"].lower()
        headers = {k.lower(): v.lower() for k, v in r["headers"].items()}
        server = headers.get("server", "") + " " + headers.get("x-powered-by", "")
        if "jenkins" in body or "jenkins" in server or \
                "x-jenkins" in headers or "jenkins-session" in body:
            return "jenkins"
        if "gitlab" in body or "gitlab" in server or \
                "x-gitlab" in headers:
            return "gitlab"
        if "github enterprise" in body or "github.com" in server or \
                "x-github" in headers:
            return "github"
        return "unknown"

    # ============================================================
    #        PHASE 1 — Jenkins
    # ============================================================

    def _test_jenkins(self):
        """Test Jenkins exposure and script console."""
        self._log("  › فحص Jenkins exposure")
        # Check the Jenkins version header
        r = self._req(self.target + "/")
        if r["status"] == 0:
            return
        # X-Jenkins header indicates Jenkins
        x_jenkins = r["headers"].get("X-Jenkins", "") or \
                    r["headers"].get("x-jenkins", "")
        if not x_jenkins:
            # Try the api/json endpoint
            r2 = self._req(self.target + "/api/json")
            if r2["status"] == 200 and self._looks_like_json(r2["body"]):
                data = self._safe_json(r2["body"]) or {}
                if "mode" in data and "nodeDescription" in data:
                    self._add_finding(
                        ftype="jenkins_exposed",
                        severity=SEV_HIGH,
                        url=self.target + "/api/json",
                        title="Jenkins instance exposed (anonymous read)",
                        description=(
                            "Jenkins /api/json is accessible without "
                            "authentication. Anonymous read access reveals "
                            "job names, build history, node configuration, "
                            "and can be a stepping-stone to deeper attacks."
                        ),
                        evidence=self._short(r2["body"], 300),
                    )
                    self._enumerate_jenkins_jobs()
                    return
            return

        # Jenkins version is exposed
        self._add_finding(
            ftype="jenkins_version_exposed",
            severity=SEV_MEDIUM,
            url=self.target + "/",
            title=f"Jenkins instance exposed (version {x_jenkins})",
            description=(
                f"Jenkins version {x_jenkins} is exposed. Version "
                f"disclosure helps attackers fingerprint the instance "
                f"and target known CVEs."
            ),
            evidence=f"X-Jenkins: {x_jenkins}",
            version=x_jenkins,
        )

        # Test api/json for anonymous access
        r2 = self._req(self.target + "/api/json")
        if r2["status"] == 200 and self._looks_like_json(r2["body"]):
            self._add_finding(
                ftype="jenkins_anonymous_read",
                severity=SEV_HIGH,
                url=self.target + "/api/json",
                title="Jenkins anonymous read access",
                description=(
                    "The Jenkins REST API is accessible without "
                    "authentication. Anonymous read access reveals job "
                    "names, build history, and node configuration."
                ),
                evidence=self._short(r2["body"], 300),
            )
            self._enumerate_jenkins_jobs()

        # Test script console (RCE) — only with explicit opt-in
        if self.test_script_console:
            self._test_jenkins_script_console()

    def _test_jenkins_script_console(self):
        """Test the Jenkins script console for unauthenticated RCE.
        DISABLED by default — this is an active exploit."""
        self._log("  › اختبار Jenkins script console (active test)")
        url = self.target + "/scriptText"
        try:
            r = self._req(url, method="POST",
                          data="script=" + quote(JENKINS_SCRIPT_PAYLOAD),
                          headers={"Content-Type":
                                   "application/x-www-form-urlencoded"})
            if r["status"] == 200 and "Result:" in (r["body"] or ""):
                self._add_finding(
                    ftype="jenkins_script_console_rce",
                    severity=SEV_CRITICAL,
                    url=url,
                    title="Jenkins script console RCE (unauthenticated)",
                    description=(
                        "The Jenkins script console is accessible without "
                        "authentication. An attacker can execute arbitrary "
                        "Groovy code on the Jenkins master — full server "
                        "compromise, credential theft, and lateral movement "
                        "to all build agents."
                    ),
                    evidence=self._short(r["body"], 300),
                )
        except Exception as e:
            self._log(f"  ✗ script console test failed: {e}", "warn")

    def _enumerate_jenkins_jobs(self):
        """List Jenkins jobs and probe their configs for secrets."""
        r = self._req(self.target + "/api/json?tree=jobs[name,url,color]")
        if r["status"] != 200 or not self._looks_like_json(r["body"]):
            return
        data = self._safe_json(r["body"]) or {}
        jobs = data.get("jobs", []) or []
        self._log(f"  • {len(jobs)} Jenkins job موجود", "info")
        for job in jobs[:30]:
            job_url = (job.get("url") or "").rstrip("/") + "/config.xml"
            r2 = self._req(job_url)
            if r2["status"] == 200 and r2["body"]:
                body = r2["body"]
                # Look for credentials / secrets in the config.xml
                self._scan_jenkins_job_config(job.get("name", "?"), job_url, body)

    def _scan_jenkins_job_config(self, job_name: str, url: str, body: str):
        """Scan a Jenkins job config.xml for hardcoded secrets."""
        # Jenkins stores secrets in <projectProperty> or <hudson.model.Password>
        # or as plaintext in shell/batch builders
        for pattern, label in SECRET_PATTERNS:
            for m in re.finditer(pattern, body):
                value = m.group(0)
                if any(p in value.lower() for p in ["example", "placeholder",
                                                     "your-", "xxxxx", "<secret>"]):
                    continue
                self._add_finding(
                    ftype="jenkins_job_secret",
                    severity=SEV_HIGH,
                    url=url,
                    title=f"Secret in Jenkins job '{job_name}': {label}",
                    description=(
                        f"Job '{job_name}' has a {label} in its config.xml. "
                        f"If anonymous read is enabled, anyone can read "
                        f"this secret."
                    ),
                    evidence=self._short(value, 120),
                    job=job_name,
                    secret_type=label,
                )

    def _test_jenkins_credentials(self):
        """Probe the Jenkins credential store for anonymous access."""
        url = self.target + "/credentials/store/system/domain/_/api/json"
        r = self._req(url)
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            data = self._safe_json(r["body"]) or {}
            if "credentials" in data or "description" in data:
                self._add_finding(
                    ftype="jenkins_credential_store_exposed",
                    severity=SEV_CRITICAL,
                    url=url,
                    title="Jenkins credential store exposed",
                    description=(
                        "The Jenkins system credential store is accessible "
                        "without authentication. This store typically holds "
                        "production deployment keys, database passwords, "
                        "and cloud credentials used by pipelines."
                    ),
                    evidence=self._short(r["body"], 300),
                )

    # ============================================================
    #        PHASE 2 — GitLab CI
    # ============================================================

    def _test_gitlab_ci(self):
        """Test GitLab CI exposure."""
        self._log("  › فحص GitLab CI")
        # Version endpoint
        r = self._req(self.target + "/api/v4/version")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            vdata = self._safe_json(r["body"]) or {}
            self._add_finding(
                ftype="gitlab_version_exposed",
                severity=SEV_HIGH,
                url=self.target + "/api/v4/version",
                title="GitLab version endpoint accessible (anonymous)",
                description=(
                    f"GitLab /api/v4/version is accessible without "
                    f"authentication. Version: "
                    f"{vdata.get('version', '?')} (rev "
                    f"{vdata.get('revision', '?')}). This indicates "
                    f"anonymous API access is enabled — attackers can "
                    f"enumerate users, projects, and runners."
                ),
                evidence=self._short(r["body"], 300),
                version=vdata.get("version"),
            )
            self._enumerate_gitlab_projects()

        # Test GraphQL endpoint (often leaks more than REST)
        g = self._req(self.target + "/-/graphql",
                      method="POST",
                      json_data={"query": "{ currentUser { username } }"})
        if g["status"] == 200 and self._looks_like_json(g["body"]):
            gdata = self._safe_json(g["body"]) or {}
            if "data" in gdata and gdata.get("data", {}).get("currentUser"):
                self._add_finding(
                    ftype="gitlab_graphql_anonymous",
                    severity=SEV_HIGH,
                    url=self.target + "/-/graphql",
                    title="GitLab GraphQL anonymous query",
                    description=(
                        "GitLab's GraphQL endpoint accepts queries "
                        "without authentication and returns current "
                        "user information."
                    ),
                    evidence=self._short(g["body"], 200),
                )

    def _enumerate_gitlab_projects(self):
        """List GitLab projects anonymously and look for CI/CD config."""
        r = self._req(self.target + "/api/v4/projects?per_page=20&simple=true")
        if r["status"] != 200 or not self._looks_like_json(r["body"]):
            return
        projects = self._safe_json(r["body"]) or []
        self._log(f"  • {len(projects)} GitLab project", "info")
        for p in projects[:20]:
            pid = p.get("id")
            pname = p.get("path_with_namespace", "?")
            # Fetch the .gitlab-ci.yml
            ci_url = self.target + \
                f"/api/v4/projects/{pid}/repository/files/.gitlab-ci.yml/raw"
            r2 = self._req(ci_url)
            if r2["status"] == 200 and r2["body"]:
                self._ci_configs.append((ci_url, r2["body"]))
                self._add_finding(
                    ftype="gitlab_ci_config_exposed",
                    severity=SEV_MEDIUM,
                    url=ci_url,
                    title=f"GitLab CI config exposed for '{pname}'",
                    description=(
                        f"The .gitlab-ci.yml for project '{pname}' is "
                        f"accessible. CI configs often contain deployment "
                        f"commands, secret references, and infrastructure "
                        f"details that should not be public."
                    ),
                    evidence=self._short(r2["body"], 200),
                    project=pname,
                )

            # Look at project CI/CD variables (often leaky)
            var_url = self.target + \
                f"/api/v4/projects/{pid}/variables"
            r3 = self._req(var_url)
            if r3["status"] == 200 and self._looks_like_json(r3["body"]):
                self._add_finding(
                    ftype="gitlab_ci_variables_exposed",
                    severity=SEV_CRITICAL,
                    url=var_url,
                    title=f"GitLab CI/CD variables exposed for '{pname}'",
                    description=(
                        f"Project '{pname}' exposes its CI/CD variables "
                        f"to anonymous requests. These typically contain "
                        f"deploy tokens, API keys, and cloud credentials."
                    ),
                    evidence=self._short(r3["body"], 300),
                    project=pname,
                )

    # ============================================================
    #        PHASE 3 — GitHub Actions
    # ============================================================

    def _test_github_actions(self):
        """Test GitHub Enterprise / Actions exposure."""
        self._log("  › فحص GitHub Actions / Enterprise")
        for path in GITHUB_ENTERPRISE_PATHS:
            url = self.target + path
            r = self._req(url)
            if r["status"] == 0:
                continue
            if r["status"] == 200 and self._looks_like_json(r["body"]):
                body = r["body"]
                if "login" in body or "total_private_repos" in body or \
                        "hooks" in body:
                    self._add_finding(
                        ftype="github_enterprise_exposed",
                        severity=SEV_HIGH,
                        url=url,
                        title=f"GitHub Enterprise endpoint exposed: {path}",
                        description=(
                            "The GitHub Enterprise endpoint is accessible "
                            "without authentication. This may leak user "
                            "lists, repository metadata, and runner "
                            "configuration."
                        ),
                        evidence=self._short(body, 300),
                        endpoint=path,
                    )
            # Setup API (GHES management console) — usually protected
            # but if exposed it's critical
            if "/setup/api/" in path and r["status"] == 200:
                self._add_finding(
                    ftype="github_setup_api_exposed",
                    severity=SEV_CRITICAL,
                    url=url,
                    title=f"GitHub Enterprise setup API exposed: {path}",
                    description=(
                        "The GitHub Enterprise Server management console "
                        "API is reachable. This is used for instance "
                        "configuration and should never be public — "
                        "attackers can reconfigure the instance, extract "
                        "secrets, or take over the entire GHES deployment."
                    ),
                    evidence=self._short(r["body"], 300),
                    endpoint=path,
                )

        # Test self-hosted runners exposure
        r = self._req(self.target + "/api/v3/actions/runners")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            data = self._safe_json(r["body"]) or {}
            runners = data.get("runners", []) or []
            for runner in runners:
                if runner.get("os") and runner.get("ip"):
                    self._add_finding(
                        ftype="github_self_hosted_runner_exposed",
                        severity=SEV_HIGH,
                        url=self.target + "/api/v3/actions/runners",
                        title=f"Self-hosted runner IP exposed: {runner.get('name')}",
                        description=(
                            f"Self-hosted runner '{runner.get('name')}' "
                            f"({runner.get('os')}) exposes its IP address "
                            f"({runner.get('ip')}). Self-hosted runners "
                            f"can be abused to run arbitrary code if a "
                            f"PR triggers a workflow."
                        ),
                        evidence=self._short(json.dumps(runner), 200),
                        runner=runner.get("name"),
                    )

    # ============================================================
    #        PHASE 4 — Build artifacts
    # ============================================================

    def _test_build_artifact_exposure(self):
        """Probe for exposed build artifact directories."""
        self._log("  › فحص build artifact exposure")
        for path in ARTIFACT_PATHS:
            url = self.target + path
            r = self._req(url)
            if r["status"] == 0:
                continue
            if r["status"] == 200 and r["body"]:
                body = r["body"]
                # Detect directory listing
                if "<title>Index of" in body or \
                        "Directory listing" in body or \
                        "<h1>Index of" in body:
                    self._add_finding(
                        ftype="build_artifact_listing",
                        severity=SEV_HIGH,
                        url=url,
                        title=f"Build artifact directory listing: {path}",
                        description=(
                            f"The path '{path}' exposes a directory "
                            f"listing of build artifacts. These often "
                            f"contain compiled binaries with embedded "
                            f"secrets, test reports, and intermediate "
                            f"build files."
                        ),
                        evidence=self._short(body, 300),
                        path=path,
                    )
                # Detect known artifact file types
                elif re.search(r'\.(jar|war|ear|apk|ipa|exe|dll|so|dylib|zip|tar|gz|tgz|whl|egg|nupkg|deb|rpm|msi)',
                               body, re.IGNORECASE):
                    self._add_finding(
                        ftype="build_artifact_exposed",
                        severity=SEV_MEDIUM,
                        url=url,
                        title=f"Build artifacts exposed at {path}",
                        description=(
                            f"The path '{path}' returns content with "
                            f"references to build artifacts (binaries / "
                            f"packages). These may be downloadable "
                            f"without authentication."
                        ),
                        evidence=self._short(body, 300),
                        path=path,
                    )

    # ============================================================
    #        PHASE 5 — Secret scanning in CI configs
    # ============================================================

    def _fetch_ci_configs(self):
        """Fetch CI/CD config files exposed on the web."""
        self._log("  › جلب CI/CD configs")
        for path in CI_CONFIG_PATHS:
            url = self.target + path
            r = self._req(url)
            if r["status"] == 200 and r["body"] and \
                    not self._looks_like_html_error(r["body"]):
                self._ci_configs.append((url, r["body"]))
                self._add_finding(
                    ftype="ci_config_exposed",
                    severity=SEV_MEDIUM,
                    url=url,
                    title=f"CI/CD config exposed: {path}",
                    description=(
                        f"The CI/CD configuration file at '{path}' is "
                        f"publicly downloadable. This often reveals "
                        f"deployment commands, infrastructure layout, "
                        f"and sometimes hardcoded secrets."
                    ),
                    evidence=self._short(r["body"], 200),
                    path=path,
                )

    @staticmethod
    def _looks_like_html_error(body: str) -> bool:
        """Detect 404-style error pages that return 200."""
        low = body.lower()
        return ("<title>404" in low or "not found" in low or
                "<html" in low and "jenkins" not in low and
                "gitlab" not in low and "workflow" not in low and
                "pipeline" not in low and "stages" not in low)

    def _scan_secrets_in_configs(self):
        """Run secret-pattern scanning across all collected CI configs."""
        self._log(f"  › فحص secrets في {len(self._ci_configs)} config")
        for url, content in self._ci_configs:
            for pattern, label in SECRET_PATTERNS:
                for m in re.finditer(pattern, content):
                    value = m.group(0)
                    # Filter obvious placeholders / examples
                    low = value.lower()
                    if any(p in low for p in ["example", "placeholder", "your-",
                                               "your_", "xxxxx", "<...>",
                                               "changeme", "replace_me",
                                               "todo", "fixme"]):
                        continue
                    sev = SEV_CRITICAL if label in (
                        "AWS Access Key ID", "AWS Secret Access Key",
                        "Private Key", "GitHub Token", "GitLab Personal Access Token",
                        "Slack Token", "Stripe API Key") else SEV_HIGH
                    self._add_finding(
                        ftype="ci_hardcoded_secret",
                        severity=sev,
                        url=url,
                        title=f"{label} hardcoded in CI config",
                        description=(
                            f"A {label} is hardcoded in the CI/CD config "
                            f"at {url}. Anyone with repository read access "
                            f"can extract and abuse this credential."
                        ),
                        evidence=self._short(value, 120),
                        secret_type=label,
                        config_url=url,
                    )

    # ============================================================
    #        PHASE 6 — Pipeline injection
    # ============================================================

    def _test_pipeline_injection(self):
        """Analyze CI configs for risky variable expansion that could
        allow pipeline injection if variables are attacker-controlled
        (e.g. PR titles, branch names, commit messages)."""
        self._log("  › فحص pipeline injection")
        risky_patterns = [
            # Shell-evaluated variable expansion without quoting
            (r'sh\s+-c\s+["\'].*\$\{?[^}]*\}?.*["\']', "sh -c with unquoted var"),
            (r'os\.system\s*\([^)]*\$\{?[^}]*\}?', "os.system with var"),
            (r'subprocess\.(?:run|call|Popen)\s*\([^)]*\$\{?[^}]*\}?',
             "subprocess with var"),
            (r'eval\s*\([^)]*\$\{?[^}]*\}?', "eval() with var"),
            # Bash unsafe patterns in CI configs
            (r'\beval\s+["\'].*\$',
             "eval with variable expansion"),
            (r'bash\s+-c\s+["\'].*\$\(',
             "bash -c with command substitution"),
            # GitHub Actions: ${{ ... }} is dangerous if it interpolates
            # user-controlled data (PR title, issue body) into a shell step
            (r'\$\{\{\s*github\.(event\.(head_commit|pull_request|issue|comment)\.[^}\s]+)\s*\}\}',
             "github.event interpolation in workflow"),
            (r'\$\{\{\s*github\.event\.pull_request\.(title|body|head|ref)\s*\}\}',
             "PR metadata in workflow interpolation"),
            # GitLab CI: using $CI_COMMIT_MESSAGE / $CI_MERGE_REQUEST_TITLE
            # in a script block directly
            (r'\$CI_(COMMIT_MESSAGE|MERGE_REQUEST_(TITLE|DESCRIPTION|SOURCE_BRANCH_NAME))',
             "GitLab user-controlled CI variable"),
        ]
        for url, content in self._ci_configs:
            for pattern, label in risky_patterns:
                for m in re.finditer(pattern, content):
                    self._add_finding(
                        ftype="pipeline_injection_risk",
                        severity=SEV_HIGH,
                        url=url,
                        title=f"Pipeline injection risk: {label}",
                        description=(
                            f"The CI config at {url} uses a pattern that "
                            f"can lead to pipeline injection ('{label}'). "
                            f"If the interpolated variable is attacker-"
                            f"controlled (e.g. PR title, commit message), "
                            f"an attacker can inject arbitrary commands "
                            f"into the build, leading to RCE on the runner "
                            f"and theft of CI secrets."
                        ),
                        evidence=self._short(m.group(0), 120),
                        risk=label,
                        config_url=url,
                    )

    # ============================================================
    #        PHASE 7 — Deploy keys
    # ============================================================

    def _test_deploy_keys(self):
        """Probe for deploy keys / SSH access enumeration via Git
        hosting API (mostly self-hosted GitLab / Forgejo / Gitea)."""
        self._log("  › فحص deploy key enumeration")
        # GitLab: list projects, then fetch deploy keys for each
        r = self._req(self.target + "/api/v4/projects?per_page=20&simple=true")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            projects = self._safe_json(r["body"]) or []
            for p in projects[:15]:
                pid = p.get("id")
                pname = p.get("path_with_namespace", "?")
                keys_url = self.target + \
                    f"/api/v4/projects/{pid}/deploy_keys"
                r2 = self._req(keys_url)
                if r2["status"] == 200 and self._looks_like_json(r2["body"]):
                    keys = self._safe_json(r2["body"]) or []
                    for k in keys:
                        if k.get("can_push"):
                            self._add_finding(
                                ftype="deploy_key_write_access",
                                severity=SEV_HIGH,
                                url=keys_url,
                                title=f"Write-capable deploy key on '{pname}'",
                                description=(
                                    f"Project '{pname}' has a deploy key "
                                    f"'{k.get('title')}' with write "
                                    f"access. If this key is leaked, an "
                                    f"attacker can push malicious commits "
                                    f"directly, bypassing MR/PR review."
                                ),
                                evidence=f"title={k.get('title')}, "
                                         f"can_push={k.get('can_push')}",
                                project=pname,
                            )

        # Forgejo / Gitea deploy keys
        r = self._req(self.target + "/api/v1/repos/search?limit=20")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            data = self._safe_json(r["body"]) or {}
            for repo in (data.get("data") or [])[:15]:
                rname = repo.get("full_name", "?")
                kurl = self.target + f"/api/v1/repos/{rname}/keys"
                r2 = self._req(kurl)
                if r2["status"] == 200 and self._looks_like_json(r2["body"]):
                    keys = self._safe_json(r2["body"]) or []
                    for k in keys:
                        if k.get("read_only") is False:
                            self._add_finding(
                                ftype="deploy_key_write_access",
                                severity=SEV_HIGH,
                                url=kurl,
                                title=f"Write deploy key on Forgejo repo '{rname}'",
                                description=(
                                    f"Repo '{rname}' has a write-capable "
                                    f"deploy key '{k.get('title')}'."
                                ),
                                evidence=f"title={k.get('title')}, "
                                         f"read_only={k.get('read_only')}",
                                repo=rname,
                            )

    # ============================================================
    #        PHASE 8 — Webhook secrets
    # ============================================================

    def _test_webhook_secrets(self):
        """Test if webhook receivers validate signature headers. If a
        receiver accepts requests without the proper signature, an
        attacker can forge webhooks and trigger pipelines / builds."""
        self._log("  › فحص webhook secret validation")
        # Common webhook receiver paths
        webhook_paths = [
            "/webhook", "/webhooks", "/hook", "/hooks",
            "/github/webhook", "/gitlab/webhook", "/bitbucket/webhook",
            "/api/webhook", "/api/v1/webhook", "/api/webhooks/github",
            "/api/webhooks/gitlab", "/api/hooks/github",
            "/github-hook", "/gitlab-hook",
            "/_/webhooks/github", "/-/webhooks/github",
        ]
        for path in webhook_paths:
            url = self.target + path
            # 1) Try a POST with no signature header — should be rejected
            r_no_sig = self._req(url, method="POST",
                                 data=json.dumps({"zen": "test", "hook_id": 1}),
                                 headers={"Content-Type": "application/json",
                                          "X-GitHub-Event": "ping"})
            if r_no_sig["status"] == 0:
                continue
            # If receiver returns 2xx without signature — that's bad
            if 200 <= r_no_sig["status"] < 300:
                self._add_finding(
                    ftype="webhook_no_signature_validation",
                    severity=SEV_HIGH,
                    url=url,
                    title=f"Webhook receiver accepts unsigned requests: {path}",
                    description=(
                        f"The webhook receiver at '{path}' accepted a POST "
                        f"without a signature header (X-Hub-Signature-256). "
                        f"An attacker can forge webhooks to trigger "
                        f"pipelines, builds, or deployments."
                    ),
                    evidence=f"POST without signature → {r_no_sig['status']}",
                    path=path,
                )

            # 2) Try a POST with a WRONG signature — should also be rejected
            r_bad_sig = self._req(url, method="POST",
                                  data=json.dumps({"zen": "test", "hook_id": 1}),
                                  headers={"Content-Type": "application/json",
                                           "X-GitHub-Event": "ping",
                                           "X-Hub-Signature-256":
                                               "sha256=0000000000000000000000000000000000000000000000000000000000000000"})
            if 200 <= r_bad_sig["status"] < 300:
                self._add_finding(
                    ftype="webhook_wrong_signature_accepted",
                    severity=SEV_CRITICAL,
                    url=url,
                    title=f"Webhook accepts invalid signature: {path}",
                    description=(
                        f"The webhook receiver at '{path}' accepted a "
                        f"POST with an invalid HMAC signature. Signature "
                        f"verification is broken or absent — full webhook "
                        f"spoofing is possible."
                    ),
                    evidence=f"POST with bad signature → {r_bad_sig['status']}",
                    path=path,
                )

    # ============================================================
    #        PHASE 9 — Container registry in CI context
    # ============================================================

    def _test_ci_registry(self):
        """Test container registry endpoints exposed alongside the CI."""
        self._log("  › فحص container registry")
        # Direct probe of /v2/ at the target
        for path in REGISTRY_PATHS:
            url = self.target + path
            r = self._req(url)
            if r["status"] == 0:
                continue
            if r["status"] == 200 and (
                    "Docker-Distribution" in str(r["headers"]) or
                    path == "/v2/" or self._looks_like_json(r["body"])):
                if path == "/v2/_catalog" and self._looks_like_json(r["body"]):
                    data = self._safe_json(r["body"]) or {}
                    repos = data.get("repositories", []) or []
                    self._add_finding(
                        ftype="ci_registry_catalog_exposed",
                        severity=SEV_HIGH,
                        url=url,
                        title=f"CI registry catalog exposed ({len(repos)} repos)",
                        description=(
                            "The container registry exposes its full "
                            "catalog (list of all image repositories) "
                            "without authentication. Attackers can pull "
                            "any image and extract embedded CI secrets."
                        ),
                        evidence=self._short(r["body"], 300),
                        repo_count=len(repos),
                    )
                elif path == "/v2/":
                    self._add_finding(
                        ftype="ci_registry_v2_exposed",
                        severity=SEV_MEDIUM,
                        url=url,
                        title="Container registry v2 API exposed",
                        description=(
                            "The Docker Registry v2 API base endpoint is "
                            "reachable. Verify it requires authentication."
                        ),
                        evidence=f"status={r['status']}",
                    )

    # ============================================================
    #                       REPORTING
    # ============================================================

    def _build_report(self) -> Dict:
        return {
            "target": self.target,
            "system_type": getattr(self, "system_type", "unknown"),
            "scanner": "CICDSecurityScanner",
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
        print(f"{Colors.MAGENTA}  🔧 تقرير فحص أمان CI/CD{Colors.NC}")
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
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات CI/CD واضحة مكتشفة"
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
        user_agent=args.user_agent or "ghostpwn-cicd/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=not args.no_redirects,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="cicd_security",
        description="ghostpwn - CI/CD Pipeline Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 cicd_security.py https://jenkins.example.com\n"
            "  python3 cicd_security.py https://gitlab.example.com\n"
            "  python3 cicd_security.py https://github.example.com\n"
            "  python3 cicd_security.py https://example.com "
            "--test-script-console\n"
            "  python3 cicd_security.py https://example.com --json-out r.json\n"
        ),
    )
    parser.add_argument("url", help="Target URL (e.g. https://jenkins.example.com)")
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
    parser.add_argument("--test-script-console", action="store_true",
                        help="Test Jenkins script console RCE (active test)")
    parser.add_argument("--max-artifacts", type=int, default=30,
                        help="Max artifact directories to probe")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["jenkins", "gitlab", "github",
                                            "artifacts", "secrets",
                                            "injection", "deploy-keys",
                                            "webhooks", "registry", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_client(args)
    scanner = CICDSecurityScanner(
        http_client=client,
        options={
            "test_script_console": args.test_script_console,
            "max_artifacts": args.max_artifacts,
            "verbose": args.verbose,
            "safe_mode": not args.test_script_console,
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
