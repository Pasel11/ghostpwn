#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Container / Docker / Kubernetes Security Scanner
فحص أمان الحاويات و Docker و Kubernetes

الفحوصات:
1.  Docker daemon socket exposure (/var/run/docker.sock over TCP)
2.  Docker API enumeration (containers, images, networks, volumes)
3.  Container escape detection (privileged mode, sensitive mounts)
4.  Privileged container detection
5.  Docker image vulnerability scanning (via image labels / metadata)
6.  Kubernetes API exposure (kube-apiserver, kubelet)
7.  Container capability analysis
8.  Mount namespace escape detection (sensitive host paths mounted)
9.  Docker registry exposure (v2 API, public listing)
10. Container secrets enumeration (env vars, mounted secret files)

ملاحظات:
- لا يستخدم أي مكتبات خارجية (Python stdlib فقط).
- يفحص عبر HTTP API فقط — لا يتطلب تثبيت docker client.
- كل الفحوصات non-destructive: لا يحاول إنشاء/حذف حاويات.
"""
import os
import sys
import re
import json
import time
import socket
import base64
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Constants ============================

# Common Docker daemon TCP endpoints (the socket itself can also be
# exposed on TCP — a classic misconfig)
DOCKER_API_PATHS = [
    "/version", "/info", "/containers/json", "/containers/json?all=1",
    "/images/json", "/networks", "/volumes", "/_ping",
    "/containers/json?all=true&size=true",
    "/nodes", "/services", "/tasks", "/secrets",
    "/swarm", "/plugins", "/distribution/json",
]

# Docker daemon TCP ports commonly seen exposed
DOCKER_PORTS = [2375, 2376, 2377, 4243, 9200]  # last one is elastic overlap

# Kubernetes API paths
K8S_API_PATHS = [
    "/api", "/api/v1", "/apis", "/apis/apps/v1",
    "/version", "/healthz", "/readyz", "/livez",
    "/metrics", "/api/v1/namespaces", "/api/v1/pods",
    "/api/v1/nodes", "/api/v1/secrets", "/api/v1/configmaps",
    "/api/v1/services", "/api/v1/persistentvolumes",
    "/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets",
    "/apis/apps/v1/statefulsets", "/apis/rbac.authorization.k8s.io/v1/roles",
    "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    "/openapi/v2", "/swagger.json", "/swagger-ui/",
]

# Kubelet endpoints (per-node API)
KUBELET_PATHS = [
    "/pods", "/runningpods", "/metrics", "/metrics/cadvisor",
    "/stats/summary", "/configz", "/healthz",
]

# Container registry (Docker Registry v2) endpoints
REGISTRY_PATHS = ["/v2/", "/v2/_catalog", "/v2/_catalog?n=100"]

# Container capability names (Linux capabilities)
SENSITIVE_CAPABILITIES = {
    "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_BOOT",
    "CAP_SYS_RAWIO", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE",
    "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_SETUID", "CAP_SETGID",
    "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
    "CAP_KILL", "CAP_LEASE", "CAP_MKNOD", "CAP_CHOWN", "CAP_FOWNER",
    "CAP_FSETID", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN",
    "CAP_AUDIT_CONTROL", "CAP_AUDIT_WRITE", "CAP_BLOCK_SUSPEND",
    "CAP_WAKE_ALARM", "CAP_SYS_CHROOT", "CAP_SYS_PACCT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE", "CAP_PERFMON",
}

DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN": "near-root; allows mount, namespace manipulation",
    "CAP_SYS_MODULE": "load kernel modules → kernel code execution",
    "CAP_SYS_PTRACE": "inject code into other processes",
    "CAP_SYS_RAWIO": "raw I/O on kernel memory / devices",
    "CAP_NET_ADMIN": "network configuration, iptables, ARP spoofing",
    "CAP_NET_RAW": "raw sockets → packet sniffing / spoofing",
    "CAP_DAC_READ_SEARCH": "bypass file permission checks",
    "CAP_DAC_OVERRIDE": "bypass file read/write/execute permission checks",
    "CAP_SETUID": "change process UID",
    "CAP_SETGID": "change process GID",
    "CAP_SETPCAP": "transfer capabilities to other processes",
    "CAP_SYS_BOOT": "reboot the system",
    "CAP_SYS_CHROOT": "call chroot() — escape via classic chroot tricks",
    "CAP_BPF": "load eBPF programs → kernel code execution",
    "CAP_PERFMON": "performance monitoring — info leak",
}

# Host paths whose mounting into a container is dangerous
DANGEROUS_MOUNTS = [
    "/", "/etc", "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/root", "/home", "/var", "/var/run/docker.sock",
    "/var/run", "/proc", "/proc/sys", "/sys", "/dev",
    "/boot", "/var/lib/docker", "/var/lib/kubelet",
    "/var/run/secrets", "/run/secrets", "/var/lib/rancher",
    "/etc/kubernetes", "/etc/kubernetes/pki", "/var/lib/etcd",
    "/.dockerenv", "/var/run/docker",
]

# Secret environment variable names to flag in container configs
SECRET_ENV_PATTERNS = [
    "PASSWORD", "PASSWD", "PWD", "SECRET", "TOKEN", "API_KEY",
    "APIKEY", "API_SECRET", "ACCESS_KEY", "SECRET_KEY", "PRIVATE_KEY",
    "CLIENT_SECRET", "DB_PASSWORD", "DATABASE_PASSWORD", "MYSQL_PASSWORD",
    "POSTGRES_PASSWORD", "REDIS_PASSWORD", "MONGO_PASSWORD", "AWS_SECRET",
    "AWS_ACCESS_KEY", "STRIPE_KEY", "STRIPE_SECRET", "JWT_SECRET",
    "ENCRYPTION_KEY", "ENCRYPT_KEY", "SIGNING_KEY", "MASTER_KEY",
    "OAUTH_SECRET", "SLACK_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN",
]

# Markers in container env vars / labels that suggest credentials
SECRET_VALUE_REGEXES = [
    r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+',
    r'(?i)(secret|token|api[_-]?key)\s*[=:]\s*\S+',
    r'\bAKIA[A-Z0-9]{16}\b',
    r'\bxox[baprs]-[0-9A-Za-z\-]+\b',
    r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b',
]

# Image labels that hint at vulnerabilities / outdated software
VULN_IMAGE_LABELS = [
    "version=latest", "tag=latest", "maintainer=", "deprecation",
    "end-of-life", "eol",
]

# Known vulnerable / EOL base images (substring match on image name)
VULN_BASE_IMAGES = [
    "ubuntu:14.04", "ubuntu:16.04", "ubuntu:18.04",
    "debian:jessie", "debian:stretch", "debian:buster",
    "centos:6", "centos:7",
    "alpine:3.7", "alpine:3.8", "alpine:3.9", "alpine:3.10",
    "python:2.", "python:3.5", "python:3.6", "python:3.7",
    "node:6.", "node:8.", "node:10.", "node:12.",
    "php:5.", "php:7.0", "php:7.1", "php:7.2",
    "ruby:2.3", "ruby:2.4", "ruby:2.5",
    "openjdk:7", "openjdk:8", "openjdk:11",
    "tomcat:7", "tomcat:8",
    "nginx:1.13", "nginx:1.14", "nginx:1.15",
    "httpd:2.2", "httpd:2.4.29",
    "mysql:5.5", "mysql:5.6", "mysql:5.7",
    "postgres:9.3", "postgres:9.4", "postgres:9.5", "postgres:9.6",
    "mongo:3.4", "mongo:3.6", "redis:3.", "redis:4.",
]

# Severity
SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


# ============================ Main Class ============================

class ContainerSecurityScanner:
    """فاحص أمان الحاويات و Docker و Kubernetes"""

    def __init__(self, http_client: Optional[HttpClient] = None,
                 audit_logger=None, options: Optional[Dict] = None):
        self.client = http_client or HttpClient(timeout=12, delay=0.1)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.options = options or {}
        self.findings: List[Dict] = []
        self._scanned: Set[str] = set()

        # Tunables
        self.max_containers = self.options.get("max_containers", 50)
        self.max_images = self.options.get("max_images", 50)
        self.probe_ports = self.options.get("probe_ports", True)
        self.safe_mode = self.options.get("safe_mode", True)
        self.verbose = self.options.get("verbose", False)

    # ---------------- helpers ----------------

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[CONTAINER-SEC] {msg}", level)

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

        # Normalize
        if not target.startswith(("http://", "https://")):
            # could be host:port or just host
            if ":" not in target:
                target = "http://" + target
            else:
                target = "http://" + target
        target = target.rstrip("/")
        self._log(f"بدء فحص أمان الحاويات: {target}", "phase")

        parsed = urlparse(target)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.hostname or ""
        self.port = parsed.port
        self.target = target

        # ---------- Phase 1: Docker daemon ----------
        self._log("Phase 1: Docker Daemon / API", "phase")
        self._test_docker_api(target)
        if self.probe_ports and not self.port:
            self._probe_docker_tcp_ports()

        # ---------- Phase 2: Container analysis ----------
        self._log("Phase 2: Container escape & privileges", "phase")
        self._test_container_escape()
        self._test_privileged_containers()
        self._test_container_capabilities()
        self._test_mount_namespace_escape()
        self._test_container_secrets()

        # ---------- Phase 3: Image vulnerabilities ----------
        self._log("Phase 3: Image vulnerability scanning", "phase")
        self._test_image_vulnerabilities()

        # ---------- Phase 4: Kubernetes ----------
        self._log("Phase 4: Kubernetes API", "phase")
        self._test_kubernetes_api(target)
        if self.probe_ports and not self.port:
            self._probe_k8s_ports()

        # ---------- Phase 5: Registry ----------
        self._log("Phase 5: Docker Registry exposure", "phase")
        self._test_docker_registry(target)

        self._print_results()
        return self._build_report()

    # ============================================================
    #        PHASE 1 — Docker Daemon / API
    # ============================================================

    def _test_docker_api(self, base_url: str):
        """Probe the Docker Engine REST API at the target URL."""
        self._log("  › فحص Docker Engine API")
        # Try _ping first (cheap check)
        ping = self._req(base_url + "/_ping")
        if ping["status"] == 200 and (ping["body"] or "").strip() == "OK":
            self._add_finding(
                ftype="docker_api_exposed",
                severity=SEV_CRITICAL,
                url=base_url + "/_ping",
                title="Docker daemon API publicly exposed",
                description=(
                    "The Docker daemon responds to /_ping with 'OK' over "
                    "TCP. This means the Docker Engine REST API is "
                    "reachable without TLS or authentication. An attacker "
                    "can enumerate containers, deploy malicious images, "
                    "and trivially escape to the host by mounting the "
                    "root filesystem into a new privileged container."
                ),
                evidence=ping["body"],
            )
            self._enumerate_docker_api(base_url)
            return

        # If ping didn't work, try direct /version
        v = self._req(base_url + "/version")
        if v["status"] == 200 and self._looks_like_json(v["body"]):
            vdata = self._safe_json(v["body"]) or {}
            if "Version" in vdata or "ApiVersion" in vdata:
                self._add_finding(
                    ftype="docker_api_exposed",
                    severity=SEV_CRITICAL,
                    url=base_url + "/version",
                    title="Docker daemon API exposed (version endpoint)",
                    description=(
                        f"The Docker Engine API version endpoint is "
                        f"reachable. Docker version: "
                        f"{vdata.get('Version', '?')}, API version: "
                        f"{vdata.get('ApiVersion', '?')}. This exposure "
                        f"allows full daemon control."
                    ),
                    evidence=self._short(v["body"], 300),
                )
                self._enumerate_docker_api(base_url)

    def _probe_docker_tcp_ports(self):
        """Quick TCP-connect probe of common Docker daemon ports."""
        self._log("  › فحص منافذ Docker TCP الشائعة")
        if not self.host:
            return
        for port in DOCKER_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((self.host, port))
                s.close()
                if result == 0:
                    url = f"http://{self.host}:{port}"
                    # Verify it's actually a Docker API
                    v = self._req(url + "/version")
                    if v["status"] == 200 and self._looks_like_json(v["body"]):
                        vdata = self._safe_json(v["body"]) or {}
                        if "ApiVersion" in vdata:
                            self._add_finding(
                                ftype="docker_api_port_exposed",
                                severity=SEV_CRITICAL,
                                url=url,
                                title=f"Docker API exposed on port {port}",
                                description=(
                                    f"Docker Engine REST API is reachable "
                                    f"on TCP port {port} without "
                                    f"authentication. Full daemon compromise "
                                    f"is trivially achievable."
                                ),
                                evidence=self._short(v["body"], 300),
                                port=port,
                            )
                            self._enumerate_docker_api(url)
            except Exception:
                continue

    def _enumerate_docker_api(self, base_url: str):
        """Enumerate containers, images, networks, volumes from a
        reachable Docker API."""
        self._log(f"  › استخراج بيانات Docker من {base_url}")
        # Containers
        r = self._req(base_url + "/containers/json?all=1")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            containers = self._safe_json(r["body"]) or []
            self._log(f"  • {len(containers)} container موجود", "info")
            for c in containers[:self.max_containers]:
                self._analyze_container(c, base_url)

        # Images
        r = self._req(base_url + "/images/json")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            images = self._safe_json(r["body"]) or []
            self._log(f"  • {len(images)} image موجودة", "info")
            for img in images[:self.max_images]:
                self._analyze_image(img, base_url)

        # Networks
        r = self._req(base_url + "/networks")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            nets = self._safe_json(r["body"]) or []
            for n in nets[:20]:
                if n.get("Driver") == "host" or n.get("Internal") is False:
                    self._add_finding(
                        ftype="docker_network_misconfig",
                        severity=SEV_LOW,
                        url=base_url + "/networks",
                        title=f"Docker network '{n.get('Name')}' uses host/bridge driver",
                        description=(
                            f"Network '{n.get('Name')}' has driver "
                            f"'{n.get('Driver')}' and may expose "
                            f"container services to the host network "
                            f"stack."
                        ),
                        evidence=self._short(json.dumps(n), 200),
                        network=n.get("Name"),
                    )

        # Volumes
        r = self._req(base_url + "/volumes")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            vols = (self._safe_json(r["body"]) or {}).get("Volumes", []) or []
            for v in vols[:20]:
                # Check for sensitive host paths mounted as volumes
                mnt = v.get("Mountpoint", "")
                if any(p in mnt for p in ["/etc", "/root", "/var/lib/docker",
                                          "/var/run"]):
                    self._add_finding(
                        ftype="docker_sensitive_volume",
                        severity=SEV_HIGH,
                        url=base_url + "/volumes",
                        title=f"Sensitive volume mount: {v.get('Name')}",
                        description=(
                            f"Volume '{v.get('Name')}' is mounted from "
                            f"'{mnt}' — a sensitive host path that could "
                            f"enable container escape if attached to a "
                            f"container."
                        ),
                        evidence=mnt,
                        volume=v.get("Name"),
                    )

    # ============================================================
    #        PHASE 2 — Container escape / privileges
    # ============================================================

    def _analyze_container(self, c: Dict, base_url: str):
        """Inspect a single container object for misconfigurations."""
        cid = c.get("Id", "")[:12]
        name = (c.get("Names") or ["?"])[0].lstrip("/")
        # Get the full inspect for detail (mode=full is default in v1.30+)
        insp_r = self._req(base_url + f"/containers/{cid}/json")
        insp = {}
        if insp_r["status"] == 200:
            insp = self._safe_json(insp_r["body"]) or {}

        # Privileged?
        host_cfg = insp.get("HostConfig", {}) or {}
        if host_cfg.get("Privileged"):
            self._add_finding(
                ftype="privileged_container",
                severity=SEV_CRITICAL,
                url=base_url + f"/containers/{cid}/json",
                title=f"Privileged container: {name}",
                description=(
                    f"Container '{name}' (id={cid}) is running in "
                    f"--privileged mode. This disables all kernel "
                    f"namespace/capability isolation and gives the "
                    f"container direct access to the host's devices, "
                    f"kernel, and filesystem — trivial escape to host."
                ),
                evidence=f"HostConfig.Privileged=true, image={c.get('Image')}",
                container=name,
                container_id=cid,
            )

        # Capabilities
        caps = host_cfg.get("CapAdd", []) or []
        for cap in caps:
            up = cap.upper()
            if not up.startswith("CAP_"):
                up = "CAP_" + up
            if up in DANGEROUS_CAPS:
                self._add_finding(
                    ftype="dangerous_capability",
                    severity=SEV_HIGH,
                    url=base_url + f"/containers/{cid}/json",
                    title=f"Container '{name}' has dangerous cap {up}",
                    description=(
                        f"Container '{name}' was granted capability {up} "
                        f"which {DANGEROUS_CAPS[up]}. This significantly "
                        f"weakens the container isolation boundary."
                    ),
                    evidence=f"CapAdd={caps}, image={c.get('Image')}",
                    container=name,
                    capability=up,
                )

        # Mounts
        binds = host_cfg.get("Binds", []) or []
        mounts = insp.get("Mounts", []) or []
        all_mounts = []
        for b in binds:
            all_mounts.append(("bind", b))
        for m in mounts:
            all_mounts.append((m.get("Type", "?"),
                               m.get("Source", "") + ":" + m.get("Destination", "")))
        for mtype, mspec in all_mounts:
            for danger in DANGEROUS_MOUNTS:
                if danger in mspec:
                    sev = SEV_CRITICAL if danger in (
                        "/var/run/docker.sock", "/", "/proc", "/sys",
                        "/var/lib/docker", "/etc/kubernetes",
                        "/var/lib/kubelet", "/var/lib/etcd") else SEV_HIGH
                    self._add_finding(
                        ftype="sensitive_mount",
                        severity=sev,
                        url=base_url + f"/containers/{cid}/json",
                        title=f"Container '{name}' mounts sensitive host path",
                        description=(
                            f"Container '{name}' mounts '{mspec}' "
                            f"(type={mtype}). Mounting sensitive host "
                            f"paths like '{danger}' enables container "
                            f"escape — the container can read/modify "
                            f"host files (e.g. /etc/shadow, docker.sock) "
                            f"or pivot to the host filesystem."
                        ),
                        evidence=f"mount={mspec}, type={mtype}, "
                                 f"image={c.get('Image')}",
                        container=name,
                        mount=mspec,
                    )
                    break

        # Network mode
        net_mode = host_cfg.get("NetworkMode", "")
        if net_mode == "host":
            self._add_finding(
                ftype="host_network_container",
                severity=SEV_MEDIUM,
                url=base_url + f"/containers/{cid}/json",
                title=f"Container '{name}' uses host network",
                description=(
                    f"Container '{name}' runs with NetworkMode=host, "
                    f"sharing the host's network stack. The container "
                    f"can bind to any host port and sniff host network "
                    f"traffic."
                ),
                evidence=f"NetworkMode=host, image={c.get('Image')}",
                container=name,
            )

        # PID mode
        pid_mode = host_cfg.get("PidMode", "")
        if pid_mode == "host":
            self._add_finding(
                ftype="host_pid_container",
                severity=SEV_HIGH,
                url=base_url + f"/containers/{cid}/json",
                title=f"Container '{name}' uses host PID namespace",
                description=(
                    f"Container '{name}' runs with PidMode=host, sharing "
                    f"the host's process namespace. The container can see "
                    f"and ptrace all host processes — combined with even "
                    f"one capability, this is a full escape."
                ),
                evidence=f"PidMode=host, image={c.get('Image')}",
                container=name,
            )

        # Environment variables (secrets)
        cfg = insp.get("Config", {}) or {}
        envs = cfg.get("Env", []) or []
        self._scan_env_vars(envs, base_url + f"/containers/{cid}/json",
                            container=name)

        # Root user
        user = cfg.get("User", "") or ""
        if user in ("", "0", "root"):
            self._add_finding(
                ftype="container_runs_as_root",
                severity=SEV_MEDIUM,
                url=base_url + f"/containers/{cid}/json",
                title=f"Container '{name}' runs as root",
                description=(
                    f"Container '{name}' runs as user '{user or 'root'}'. "
                    f"Running containers as root increases the blast "
                    f"radius of any escape — prefer a non-root user."
                ),
                evidence=f"User={user or 'root'}, image={c.get('Image')}",
                container=name,
            )

    def _scan_env_vars(self, envs: List[str], url: str, container: str = ""):
        """Look for secrets embedded in container env vars."""
        for env in envs:
            if "=" not in env:
                continue
            name, value = env.split("=", 1)
            upname = name.upper()
            if any(p in upname for p in SECRET_ENV_PATTERNS):
                # Don't log the actual value
                masked = value[:2] + "***" if len(value) > 2 else "***"
                sev = SEV_HIGH if any(k in upname for k in
                                      ("PASSWORD", "SECRET", "TOKEN",
                                       "PRIVATE_KEY", "API_KEY", "ACCESS_KEY",
                                       "AWS_SECRET", "STRIPE_SECRET",
                                       "JWT_SECRET", "MASTER_KEY")) \
                    else SEV_MEDIUM
                self._add_finding(
                    ftype="container_secret_env",
                    severity=sev,
                    url=url,
                    title=f"Secret exposed in env var '{name}'",
                    description=(
                        f"Container {container} defines environment "
                        f"variable '{name}' with a credential-like value. "
                        f"Docker inspect exposes this to any user with "
                        f"API access — secrets should be in mounted "
                        f"files or a secrets manager, not env vars."
                    ),
                    evidence=f"{name}={masked}",
                    container=container,
                    env_var=name,
                )

    def _test_container_escape(self):
        """Detect container-escape vectors via the docker.sock exposure
        and via runtime detection markers."""
        # We covered docker.sock via _test_docker_api; this is a stub
        # for additional logic-specific checks (e.g. nvidia runtime).
        pass

    def _test_privileged_containers(self):
        """Covered in _analyze_container; kept as separate phase name
        for reporting clarity."""
        pass

    def _test_container_capabilities(self):
        """Covered in _analyze_container; kept for phase clarity."""
        pass

    def _test_mount_namespace_escape(self):
        """Covered in _analyze_container via DANGEROUS_MOUNTS; kept for
        phase clarity."""
        pass

    def _test_container_secrets(self):
        """Covered in _analyze_container via _scan_env_vars; also check
        for /run/secrets mounts explicitly."""
        # Already mostly covered; nothing additional here.
        pass

    # ============================================================
    #        PHASE 3 — Image vulnerabilities
    # ============================================================

    def _analyze_image(self, img: Dict, base_url: str):
        """Inspect a Docker image for outdated base images and labels."""
        iid = (img.get("Id") or "")[:19]  # sha256:... → first 19 chars
        tags = img.get("RepoTags") or ["<none>:<none>"]
        for tag in tags:
            low = tag.lower()
            for vuln_base in VULN_BASE_IMAGES:
                if vuln_base in low:
                    self._add_finding(
                        ftype="vulnerable_base_image",
                        severity=SEV_HIGH,
                        url=base_url + "/images/json",
                        title=f"Outdated / vulnerable base image: {tag}",
                        description=(
                            f"Image '{tag}' uses base image "
                            f"'{vuln_base}' which is end-of-life or "
                            f"known-vulnerable. The base image no longer "
                            f"receives security patches and likely "
                            f"contains unpatched CVEs in its system "
                            f"libraries."
                        ),
                        evidence=f"RepoTags={tags}, base={vuln_base}",
                        image=tag,
                    )
                    break
            if ":latest" in low:
                self._add_finding(
                    ftype="image_uses_latest_tag",
                    severity=SEV_LOW,
                    url=base_url + "/images/json",
                    title=f"Image uses ':latest' tag: {tag}",
                    description=(
                        f"Image '{tag}' uses the mutable ':latest' tag. "
                        f"This makes builds non-reproducible and can "
                        f"silently pull a compromised or vulnerable "
                        f"version on next pull."
                    ),
                    evidence=f"RepoTags={tags}",
                    image=tag,
                )

    def _test_image_vulnerabilities(self):
        """If the Docker API is not reachable, scan the target's web
        content for image references (e.g. registry URLs) that hint at
        vulnerable images."""
        # Fetch home page to look for registry references in JS / configs
        home = self._req(self.target)
        if home["status"] != 200 or not home["body"]:
            return
        body = home["body"]
        # Find docker-pullable image refs in CI configs / docker-compose
        # exposed on the web
        image_refs = re.findall(
            r'(?:image|from)\s*[:=]\s*["\']?([a-z0-9.\-]+/[a-z0-9.\-]+:[a-z0-9.\-]+)',
            body, re.IGNORECASE)
        for ref in set(image_refs[:20]):
            low = ref.lower()
            for vuln_base in VULN_BASE_IMAGES:
                if vuln_base in low:
                    self._add_finding(
                        ftype="vulnerable_base_image_reference",
                        severity=SEV_MEDIUM,
                        url=self.target,
                        title=f"Vulnerable base image referenced: {ref}",
                        description=(
                            f"The target exposes a config referencing "
                            f"image '{ref}' which appears to use the "
                            f"vulnerable base '{vuln_base}'."
                        ),
                        evidence=ref,
                    )
                    break

    # ============================================================
    #        PHASE 4 — Kubernetes API
    # ============================================================

    def _test_kubernetes_api(self, base_url: str):
        """Probe the Kubernetes API server."""
        self._log("  › فحص Kubernetes API server")
        # /version is the cheapest signal
        v = self._req(base_url + "/version")
        if v["status"] == 200 and self._looks_like_json(v["body"]):
            vdata = self._safe_json(v["body"]) or {}
            if "gitVersion" in vdata:
                self._add_finding(
                    ftype="k8s_api_exposed",
                    severity=SEV_CRITICAL,
                    url=base_url + "/version",
                    title="Kubernetes API server exposed",
                    description=(
                        f"The Kubernetes API server at {base_url} is "
                        f"reachable without authentication. Version: "
                        f"{vdata.get('gitVersion', '?')}. An attacker "
                        f"can enumerate namespaces, pods, secrets, and "
                        f"deploy malicious workloads."
                    ),
                    evidence=self._short(v["body"], 300),
                )
                self._enumerate_k8s_api(base_url)
                return

        # /api (the unauthenticated root) is also a cheap signal
        a = self._req(base_url + "/api")
        if a["status"] == 200 and self._looks_like_json(a["body"]):
            adata = self._safe_json(a["body"]) or {}
            if "versions" in adata:
                # /api returns 200 even anonymously — that alone is fine.
                # The real risk is if /api/v1/namespaces is also 200.
                ns = self._req(base_url + "/api/v1/namespaces")
                if ns["status"] == 200 and self._looks_like_json(ns["body"]):
                    nsdata = self._safe_json(ns["body"]) or {}
                    if "items" in nsdata:
                        self._add_finding(
                            ftype="k8s_api_unauthenticated",
                            severity=SEV_CRITICAL,
                            url=base_url + "/api/v1/namespaces",
                            title="Kubernetes API allows unauthenticated access",
                            description=(
                                "The Kubernetes API server returns the "
                                "list of namespaces without authentication. "
                                "Full cluster takeover is likely possible."
                            ),
                            evidence=self._short(ns["body"], 300),
                        )
                        self._enumerate_k8s_api(base_url)

    def _probe_k8s_ports(self):
        """Probe common Kubernetes API ports."""
        if not self.host:
            return
        ports = [6443, 8443, 8080, 10250, 10255, 10256, 30000, 30001]
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                r = s.connect_ex((self.host, port))
                s.close()
                if r == 0:
                    url = f"https://{self.host}:{port}" \
                        if port in (6443, 8443, 10250) \
                        else f"http://{self.host}:{port}"
                    v = self._req(url + "/version")
                    if v["status"] == 200 and self._looks_like_json(v["body"]):
                        vdata = self._safe_json(v["body"]) or {}
                        if "gitVersion" in vdata:
                            self._add_finding(
                                ftype="k8s_api_port_exposed",
                                severity=SEV_CRITICAL,
                                url=url,
                                title=f"Kubernetes API exposed on port {port}",
                                description=(
                                    f"The Kubernetes API server is "
                                    f"reachable on port {port}. Version: "
                                    f"{vdata.get('gitVersion', '?')}."
                                ),
                                evidence=self._short(v["body"], 200),
                                port=port,
                            )
                            self._enumerate_k8s_api(url)
                    # Kubelet-specific endpoints
                    if port in (10250, 10255):
                        self._test_kubelet(url, port)
            except Exception:
                continue

    def _test_kubelet(self, base_url: str, port: int):
        """Probe kubelet endpoints (often exposed on worker nodes)."""
        for path in KUBELET_PATHS:
            r = self._req(base_url + path)
            if r["status"] == 200 and r["body"]:
                self._add_finding(
                    ftype="k8s_kubelet_exposed",
                    severity=SEV_HIGH,
                    url=base_url + path,
                    title=f"Kubelet endpoint exposed: {path}",
                    description=(
                        f"The kubelet on port {port} serves {path} "
                        f"without authentication. Kubelet exposure can "
                        f"allow command execution in pods (via "
                        f"/run, /exec, /attach) and full pod enumeration."
                    ),
                    evidence=self._short(r["body"], 200),
                    port=port,
                )

    def _enumerate_k8s_api(self, base_url: str):
        """Enumerate secrets, pods, and configmaps from a reachable
        K8s API."""
        # Secrets — the most critical
        r = self._req(base_url + "/api/v1/secrets")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            sdata = self._safe_json(r["body"]) or {}
            items = sdata.get("items", []) or []
            if items:
                self._add_finding(
                    ftype="k8s_secrets_enumerable",
                    severity=SEV_CRITICAL,
                    url=base_url + "/api/v1/secrets",
                    title=f"Kubernetes Secrets enumerable ({len(items)} secrets)",
                    description=(
                        f"The Kubernetes API returns {len(items)} "
                        f"secrets to anonymous requests. Each secret "
                        f"contains base64-encoded credentials (DB "
                        f"passwords, API keys, TLS certs)."
                    ),
                    evidence=self._short(r["body"], 400),
                    secret_count=len(items),
                )
                # Inspect a few secrets for sensitive types
                for s in items[:10]:
                    sname = (s.get("metadata") or {}).get("name", "?")
                    stype = s.get("type", "")
                    if stype in ("kubernetes.io/service-account-token",
                                 "kubernetes.io/tls", "kubernetes.io/dockerconfigjson",
                                 "kubernetes.io/basic-auth"):
                        self._add_finding(
                            ftype="k8s_sensitive_secret",
                            severity=SEV_CRITICAL,
                            url=base_url + f"/api/v1/secrets/{sname}",
                            title=f"Sensitive Kubernetes secret: {sname} ({stype})",
                            description=(
                                f"Secret '{sname}' of type '{stype}' is "
                                f"readable. This type typically holds "
                                f"high-value credentials."
                            ),
                            evidence=f"type={stype}",
                            secret=sname,
                        )

        # ConfigMaps (may contain env-injected secrets)
        r = self._req(base_url + "/api/v1/configmaps")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            cdata = self._safe_json(r["body"]) or {}
            for cm in (cdata.get("items", []) or [])[:20]:
                cmname = (cm.get("metadata") or {}).get("name", "?")
                data = cm.get("data", {}) or {}
                for k, v in data.items():
                    if any(p in k.upper() for p in SECRET_ENV_PATTERNS):
                        self._add_finding(
                            ftype="k8s_configmap_secret",
                            severity=SEV_HIGH,
                            url=base_url + f"/api/v1/configmaps/{cmname}",
                            title=f"Secret in ConfigMap '{cmname}' key '{k}'",
                            description=(
                                f"ConfigMap '{cmname}' contains key '{k}' "
                                f"with a credential-like name. ConfigMaps "
                                f"are not encrypted at rest — secrets "
                                f"should use the Secret resource type."
                            ),
                            evidence=f"key={k}, value_len={len(v)}",
                            configmap=cmname,
                        )

    # ============================================================
    #        PHASE 5 — Docker registry
    # ============================================================

    def _test_docker_registry(self, base_url: str):
        """Probe the Docker Registry v2 API."""
        self._log("  › فحص Docker Registry v2")
        # Try the standard /v2/ endpoint
        r = self._req(base_url + "/v2/")
        if r["status"] == 200:
            api_header = r["headers"].get("Docker-Distribution-API-Version", "") \
                or r["headers"].get("docker-distribution-api-version", "")
            if "registry" in api_header.lower() or r["status"] == 200:
                self._add_finding(
                    ftype="docker_registry_exposed",
                    severity=SEV_HIGH,
                    url=base_url + "/v2/",
                    title="Docker Registry v2 exposed",
                    description=(
                        "A Docker Registry v2 API is reachable. If it "
                        "allows anonymous access, attackers can enumerate "
                        "and pull all stored images — potentially "
                        "extracting embedded secrets, source code, and "
                        "internal application logic."
                    ),
                    evidence=f"status={r['status']}, header={api_header}",
                )
                self._enumerate_registry(base_url)

        # Also try common registry ports if no port was specified
        if self.probe_ports and not self.port:
            for port in [5000, 5001, 8443]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    rr = s.connect_ex((self.host, port))
                    s.close()
                    if rr == 0:
                        url = f"http://{self.host}:{port}"
                        r2 = self._req(url + "/v2/")
                        if r2["status"] == 200:
                            self._add_finding(
                                ftype="docker_registry_port_exposed",
                                severity=SEV_HIGH,
                                url=url + "/v2/",
                                title=f"Docker Registry exposed on port {port}",
                                description=(
                                    f"A Docker Registry v2 API is "
                                    f"reachable on port {port}."
                                ),
                                evidence=f"status={r2['status']}",
                                port=port,
                            )
                            self._enumerate_registry(url)
                except Exception:
                    continue

    def _enumerate_registry(self, base_url: str):
        """List repositories (images) from an open registry."""
        r = self._req(base_url + "/v2/_catalog?n=100")
        if r["status"] == 200 and self._looks_like_json(r["body"]):
            data = self._safe_json(r["body"]) or {}
            repos = data.get("repositories", []) or []
            if repos:
                self._add_finding(
                    ftype="docker_registry_catalog",
                    severity=SEV_HIGH,
                    url=base_url + "/v2/_catalog",
                    title=f"Registry catalog enumerable ({len(repos)} repos)",
                    description=(
                        f"The registry exposes its full catalog of "
                        f"{len(repos)} repositories to anonymous users. "
                        f"Repos: {', '.join(repos[:5])}"
                        f"{'...' if len(repos) > 5 else ''}"
                    ),
                    evidence=self._short(r["body"], 400),
                    repo_count=len(repos),
                )
                # For each repo, list tags and probe manifests
                for repo in repos[:10]:
                    t = self._req(base_url + f"/v2/{repo}/tags/list")
                    if t["status"] == 200:
                        tdata = self._safe_json(t["body"]) or {}
                        tags = tdata.get("tags", []) or []
                        # Try to fetch the manifest of the latest tag and
                        # decode a config layer for embedded secrets
                        for tag in tags[:3]:
                            m = self._req(
                                base_url + f"/v2/{repo}/manifests/{tag}",
                                headers={"Accept":
                                         "application/vnd.docker.distribution."
                                         "manifest.v2+json"})
                            if m["status"] == 200:
                                mdata = self._safe_json(m["body"]) or {}
                                cfg_digest = (mdata.get("config") or {}).get("digest", "")
                                if cfg_digest:
                                    blob = self._req(
                                        base_url + f"/v2/{repo}/blobs/{cfg_digest}")
                                    if blob["status"] == 200:
                                        bdata = self._safe_json(blob["body"]) or {}
                                        envs = ((bdata.get("config") or {})
                                                .get("Env") or [])
                                        if envs:
                                            self._scan_env_vars(
                                                envs,
                                                base_url + f"/v2/{repo}/blobs/{cfg_digest}",
                                                container=f"{repo}:{tag}")

    # ============================================================
    #                       REPORTING
    # ============================================================

    def _build_report(self) -> Dict:
        return {
            "target": self.target,
            "scanner": "ContainerSecurityScanner",
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
        print(f"{Colors.MAGENTA}  🐳 تقرير فحص أمان الحاويات{Colors.NC}")
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
            print(f"\n  {Colors.GREEN}✓ لا توجد ثغرات حاويات واضحة مكتشفة"
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
        user_agent=args.user_agent or "ghostpwn-container/1.0",
        proxy=args.proxy,
        cookie=args.cookie,
        allow_redirects=not args.no_redirects,
        verify_ssl=False,
        delay=args.delay,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="container_security",
        description="ghostpwn - Container / Docker / Kubernetes Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 container_security.py http://127.0.0.1:2375\n"
            "  python3 container_security.py https://k8s.example.com\n"
            "  python3 container_security.py http://registry.example.com:5000\n"
            "  python3 container_security.py https://example.com --verbose\n"
            "  python3 container_security.py http://target --json-out c.json\n"
        ),
    )
    parser.add_argument("url", help="Target URL (e.g. http://host:2375 "
                                    "or https://k8s.example.com)")
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
    parser.add_argument("--no-port-probe", action="store_true",
                        help="Skip probing common Docker/K8s TCP ports")
    parser.add_argument("--max-containers", type=int, default=50,
                        help="Max containers to inspect in detail")
    parser.add_argument("--max-images", type=int, default=50,
                        help="Max images to inspect in detail")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON report to this file")
    parser.add_argument("--only", choices=["docker", "containers", "images",
                                            "k8s", "registry", "all"],
                        default="all", help="Run only a specific phase")
    args = parser.parse_args()

    client = _build_client(args)
    scanner = ContainerSecurityScanner(
        http_client=client,
        options={
            "max_containers": args.max_containers,
            "max_images": args.max_images,
            "probe_ports": not args.no_port_probe,
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
