#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Crawler & Discovery (Zero-Dependency)
زاحف ويب + directory brute forcer + subdomain brute forcer
"""
import re
import socket
import urllib.parse
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional
from .http_client import HttpClient


# ============================ Link & Form Parser ============================
class LinkFormParser(HTMLParser):
    """استخراج الروابط والـ forms من HTML"""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict] = []
        self.current_form: Optional[Dict] = None
        self.js_endpoints: Set[str] = set()
        self.emails: Set[str] = set()
        self.comments: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        attrs_dict = dict(attrs)
        if tag == "a":
            href = attrs_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.add(href)
        elif tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
                "source_page": self.base_url,
            }
        elif tag in ("input", "textarea", "select"):
            if self.current_form is not None:
                name = attrs_dict.get("name", "")
                itype = attrs_dict.get("type", "text")
                value = attrs_dict.get("value", "")
                if name:
                    self.current_form["inputs"].append({
                        "name": name, "type": itype, "value": value
                    })
        elif tag == "script":
            src = attrs_dict.get("src", "")
            if src:
                self.links.add(src)
        elif tag == "link":
            href = attrs_dict.get("href", "")
            if href:
                self.links.add(href)
        elif tag == "iframe":
            src = attrs_dict.get("src", "")
            if src:
                self.links.add(src)

    def handle_data(self, data: str):
        """استخراج endpoints من JS + emails"""
        if self.current_form is None:
            # endpoints في JS
            for match in re.finditer(r'["\'](/[^"\']*\?[^"\']*)["\']', data):
                self.js_endpoints.add(match.group(1))
            for match in re.finditer(r'fetch\(["\']([^"\']+)["\']', data):
                self.js_endpoints.add(match.group(1))
            # emails
            for match in re.finditer(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', data):
                self.emails.add(match.group(0))

    def handle_comment(self, data: str):
        """استخراج HTML comments"""
        if len(data.strip()) > 5:
            self.comments.append(data.strip()[:200])

    def handle_endtag(self, tag: str):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def get_all_urls(self) -> Set[str]:
        """إرجاع كل الـ URLs مطلقة"""
        result = set()
        for link in self.links:
            abs_url = urllib.parse.urljoin(self.base_url, link)
            result.add(abs_url)
        for ep in self.js_endpoints:
            abs_url = urllib.parse.urljoin(self.base_url, ep)
            result.add(abs_url)
        return result


# ============================ Crawler ============================
class Crawler:
    """زاحف ويب شامل"""

    def __init__(self, http_client: HttpClient, max_depth: int = 2,
                 max_pages: int = 30):
        self.client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages

    def crawl(self, start_url: str) -> Dict:
        """زحف الموقع لاكتشاف الصفحات والـ forms"""
        visited = set()
        to_visit = [(start_url, 0)]
        all_forms = []
        all_urls = {start_url}
        all_emails = set()
        all_comments = []

        parsed_base = urllib.parse.urlparse(start_url)
        base_domain = parsed_base.netloc

        while to_visit and len(visited) < self.max_pages:
            current_url, depth = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            print(f"  [*] Crawl [{depth}]: {current_url[:80]}")

            resp = self.client.get(current_url)
            if resp["status"] == 0 or not resp["body"]:
                continue

            parser = LinkFormParser(current_url)
            try:
                parser.feed(resp["body"])
            except Exception:
                pass

            all_forms.extend(parser.forms)
            all_emails.update(parser.emails)
            all_comments.extend(parser.comments)

            if depth < self.max_depth:
                for link in parser.get_all_urls():
                    if link in all_urls:
                        continue
                    parsed = urllib.parse.urlparse(link)
                    if parsed.netloc and parsed.netloc != base_domain:
                        continue
                    all_urls.add(link)
                    to_visit.append((link, depth + 1))

        # URLs ببارامترات
        urls_with_params = []
        for u in all_urls:
            parsed = urllib.parse.urlparse(u)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                urls_with_params.append({
                    "url": u,
                    "params": list(params.keys()),
                })

        return {
            "crawled_pages": list(visited),
            "all_urls": sorted(all_urls),
            "urls_with_params": urls_with_params,
            "forms": all_forms,
            "emails": list(all_emails),
            "html_comments": all_comments,
            "stats": {
                "total_pages": len(visited),
                "total_urls": len(all_urls),
                "urls_with_params": len(urls_with_params),
                "total_forms": len(all_forms),
                "emails_found": len(all_emails),
            },
        }


# ============================ Directory Brute Forcer ============================
class DirectoryBruteForcer:
    """اكتشاف المجلدات والملفات المخفية - بدون dirb/ffuf"""

    DEFAULT_WORDLIST = [
        "admin", "login", "wp-admin", "administrator", "panel", "dashboard",
        "api", "api/v1", "api/v2", "config", "configuration", "backup",
        "backups", "db", "database", "sql", "dump", "test", "testing",
        "dev", "development", "staging", "prod", "production",
        ".git", ".git/HEAD", ".git/config", ".env", ".env.local",
        ".env.production", ".htaccess", ".htpasswd", "phpinfo.php",
        "info.php", "test.php", "debug.php", "phpmyadmin", "pma", "adminer",
        "manager", "console", "cp", "controlpanel", "wp-login.php",
        "wp-content", "wp-content/uploads", "wp-content/plugins",
        "wp-config.php", "wp-config.bak", "xmlrpc.php", "readme.html",
        "license.txt", "robots.txt", "sitemap.xml", "sitemap.xml.gz",
        "feed", "rss", "comments", "wp-json", "wp-json/wp/v2/users",
        "author", "user", "users", "account", "accounts", "register",
        "signup", "signin", "forgot", "reset", "password",
        "cart", "checkout", "order", "orders", "payment", "payments",
        "invoice", "invoices", "client", "clients", "customer", "customers",
        "vendor", "vendors", "partner", "partners", "reports", "report",
        "stats", "statistics", "analytics", "metrics", "monitor",
        "monitoring", "health", "status", "healthcheck", "ping", "pong",
        "version", "versions", "changelog", "release", "releases",
        "tags", "tag", "categories", "category", "search", "filter",
        "sort", "export", "exports", "import", "imports", "upload",
        "uploads", "download", "downloads", "files", "file", "docs",
        "doc", "documentation", "help", "support", "faq", "contact",
        "about", "terms", "privacy", "policy", "legal", "imprint",
        "assets", "static", "public", "private", "internal", "external",
        "img", "images", "image", "pics", "css", "js", "javascript",
        "fonts", "media", "video", "videos", "audio", "sounds",
        "legacy", "old", "new", "tmp", "temp", "temporary", "cache",
        "cached", "log", "logs", "logging", "error", "errors",
        "404", "403", "401", "500", "server-status", "server-info",
        "metrics", "actuator", "actuator/health", "actuator/env",
        "actuator/beans", "actuator/mappings", "management", "jmx-console",
        "web-console", "jenkins", "gitlab", "grafana", "kibana", "elastic",
        "soluri", "jenkins/script", "manage", "manager", "cgi-bin", "cgi",
        "scripts", "script", "include", "includes", "lib", "libs",
        "library", "libraries", "src", "source", "sources", "build",
        "builds", "dist", "node_modules", "bower_components", "vendor",
        "vendors", "composer.json", "composer.lock", "package.json",
        "package-lock.json", "yarn.lock", "Gemfile", "Gemfile.lock",
        "requirements.txt", "Dockerfile", "docker-compose.yml",
        "docker-compose.yaml", "Makefile", "README", "README.md",
        "README.txt", "CHANGELOG", "LICENSE", "NOTICE", "AUTHORS",
        "CONTRIBUTORS", "TODO", "BACKUP", "old", "archive", "archives",
        "zip", "tar", "tar.gz", "rar", "7z", "sql", "db", "backup.sql",
        "database.sql", "dump.sql", "data.sql", "config.php", "config.json",
        "config.yml", "config.yaml", "config.xml", "config.ini",
        "settings.php", "settings.json", "settings.yml", "local.json",
        "secrets", "secrets.json", "secrets.yml", "credentials",
        "credentials.json", ".keys", ".id_rsa", ".ssh", "ssh", "token",
        "tokens", "apikey", "api_key", "api_keys", "keys", "key",
        "private", "private.key", "public.key", "cert", "certs",
        "certificate", "ssl", "tls", "oauth", "oauth2", "openid", "saml",
        "sso", "jwt", "auth", "authentication", "authorize", "authorization",
        "session", "sessions", "csrf", "xss", "security", "secure",
        "protected", "restricted", "admin.php", "admin.html", "admin.aspx",
        "admin.jsp", "login.php", "login.html", "login.aspx", "login.jsp",
    ]

    def __init__(self, http_client: HttpClient, threads: int = 10):
        self.client = http_client
        self.threads = threads

    def brute(self, base_url: str, wordlist: Optional[List[str]] = None,
              extensions: Optional[List[str]] = None) -> List[Dict]:
        """تنفيذ directory brute force"""
        words = wordlist or self.DEFAULT_WORDLIST
        extensions = extensions or [""]  # بدون امتداد افتراضياً
        base_url = base_url.rstrip("/")

        found = []
        total = len(words) * len(extensions)
        checked = 0

        print(f"  [*] Testing {total} paths on {base_url}...")

        def check_path(word: str, ext: str) -> Optional[Dict]:
            nonlocal checked
            path = f"/{word}{ext}"
            url = base_url + path
            resp = self.client.request(url, "HEAD")
            checked += 1

            if resp["status"] in (200, 301, 302, 401, 403):
                return {
                    "url": url,
                    "status": resp["status"],
                    "path": path,
                    "content_length": resp["headers"].get("Content-Length", ""),
                }
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for word in words:
                for ext in extensions:
                    futures.append(executor.submit(check_path, word, ext))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    print(f"  [+] {result['status']} {result['path']}")

        found.sort(key=lambda x: x["path"])
        return found


# ============================ Subdomain Brute Forcer ============================
class SubdomainBruteForcer:
    """اكتشاف الـ subdomains عبر DNS brute force"""

    DEFAULT_WORDLIST = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
        "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
        "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin",
        "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
        "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop",
        "sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media",
        "email", "images", "imap2", "test1", "test2", "test3", "sphinx",
        "api", "v1", "v2", "staging", "server", "service", "gateway",
        "auth", "sso", "oauth", "admin1", "admin2", "portal", "app",
        "apps", "internal", "intranet", "extranet", "remote", "cloud",
        "aws", "azure", "gcp", "docker", "k8s", "kubernetes", "jenkins",
        "gitlab", "ci", "cd", "build", "deploy", "release", "monitor",
        "status", "grafana", "kibana", "elastic", "logstash", "prometheus",
        "console", "terminal", "shell", "ssh", "telnet", "vnc", "rdp",
        "backup", "backups", "archive", "archives", "old", "new", "v2",
        "search", "api-docs", "swagger", "graphql", "playground", "graphiql",
    ]

    def __init__(self, threads: int = 50):
        self.threads = threads

    def resolve_subdomain(self, subdomain: str) -> Optional[List[str]]:
        """حل subdomain عبر DNS"""
        try:
            ips = socket.gethostbyname_ex(subdomain)[2]
            return ips
        except socket.gaierror:
            return None
        except Exception:
            return None

    def brute(self, domain: str, wordlist: Optional[List[str]] = None) -> List[Dict]:
        """تنفيذ subdomain brute force"""
        words = wordlist or self.DEFAULT_WORDLIST
        found = []

        print(f"  [*] Brute forcing {len(words)} subdomains for {domain}...")

        def check_sub(word: str) -> Optional[Dict]:
            subdomain = f"{word}.{domain}"
            ips = self.resolve_subdomain(subdomain)
            if ips:
                return {
                    "subdomain": subdomain,
                    "ips": ips,
                }
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_sub, word): word for word in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    print(f"  [+] {result['subdomain']} -> {', '.join(result['ips'])}")

        found.sort(key=lambda x: x["subdomain"])
        return found


# ============================ Tech Stack Detector ============================
class TechDetector:
    """كشف تكنولوجيا الموقع"""

    TECH_SIGNATURES = {
        "WordPress": [r"wp-content", r"wp-includes", r"wp-json", r"/wp-admin"],
        "Drupal": [r"drupal\.js", r"sites/default", r"Drupal\.settings"],
        "Joomla": [r"/components/com_", r"/media/system/js/", r"Joomla"],
        "Magento": [r"skin/frontend", r"js/mage", r"Magento"],
        "Shopify": [r"cdn\.shopify\.com", r"shopify\.com"],
        "React": [r"react\.production", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"data-reactroot"],
        "Vue.js": [r"vue\.runtime", r"__INITIAL_STATE__", r"data-v-"],
        "Angular": [r"ng-version", r"angular\.min\.js", r"ng-app"],
        "jQuery": [r"jquery", r"jQuery v", r"\$\(document\)"],
        "Bootstrap": [r"bootstrap\.min", r"bootstrap\.css"],
        "Tailwind": [r"tailwind", r"tw-"],
        "Express.js": [r"X-Powered-By: Express"],
        "Django": [r"csrfmiddlewaretoken", r"X-Frame-Options"],
        "Flask": [r"X-Powered-By: Werkzeug"],
        "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
        "Rails": [r"csrf-param.*authenticity_token", r"X-Runtime"],
        "ASP.NET": [r"__VIEWSTATE", r"ASPXAUTH", r"X-AspNet-Version", r"X-Powered-By: ASP.NET"],
        "PHP": [r"X-Powered-By: PHP", r"PHPSESSID", r"\.php"],
        "Node.js": [r"X-Powered-By: Node"],
        "Nginx": [r"Server: nginx"],
        "Apache": [r"Server: Apache"],
        "IIS": [r"Server: Microsoft-IIS"],
        "Cloudflare": [r"Server: cloudflare", r"cf-ray"],
        "Amazon S3": [r"x-amz-request-id", r"Server: AmazonS3"],
        "Google Analytics": [r"google-analytics\.com", r"UA-\d+"],
        "Google Tag Manager": [r"googletagmanager\.com", r"GTM-"],
        "Cloudfront": [r"X-Amz-Cf-Id", r"cloudfront\.net"],
    }

    def __init__(self, http_client: HttpClient):
        self.client = http_client

    def detect(self, url: str) -> List[str]:
        """كشف التكنولوجيا المستخدمة"""
        resp = self.client.get(url)
        detected = []

        # فحص headers + body
        content = resp["body"] + "\n" + "\n".join(f"{k}: {v}" for k, v in resp["headers"].items())

        for tech, patterns in self.TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if tech not in detected:
                        detected.append(tech)
                    break

        return detected
