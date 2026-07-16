#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Component Analyzer
يحلل القوالب، الإضافات، والمسارات ويقارنها بقاعدة بيانات الثغرات
"""
import sys
import os
import re
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.vuln_database import VulnerabilityDatabase


class ComponentAnalyzer:
    """محلل المكونات - قوالب/إضافات/مسارات"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.db = VulnerabilityDatabase(audit_logger)

        self.components_found = {
            "wordpress_plugins": [],
            "wordpress_themes": [],
            "paths": [],
            "tech_stack": [],
        }
        self.vulnerabilities_found = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[COMPONENT] {msg}", level)

    def analyze(self, url: str) -> Dict:
        """تحليل شامل لمكونات الموقع"""
        self._log("بدء تحليل مكونات الموقع...", "phase")

        # 1) تحليل HTML الرئيسي
        resp = self.client.get(url)
        if resp["status"] == 0:
            self._log("فشل الاتصال بالموقع", "error")
            return self.components_found

        html = resp["body"]

        # 2) كشف WordPress plugins
        self._detect_wp_plugins(url, html)

        # 3) كشف WordPress themes
        self._detect_wp_themes(url, html)

        # 4) فحص paths حساسة
        self._check_sensitive_paths(url)

        # 5) كشف tech stack
        self._detect_tech_stack(html, resp["headers"])

        # 6) بناء التقرير
        result = {
            "components": self.components_found,
            "vulnerabilities": self.vulnerabilities_found,
            "summary": self._build_summary(),
        }

        return result

    def _detect_wp_plugins(self, url: str, html: str):
        """كشف WordPress plugins"""
        self._log("كشف WordPress plugins...", "info")

        plugins = set()

        # patterns شائعة
        patterns = [
            r'wp-content/plugins/([^/]+)/',
            r'plugins/([^/]+)/readme\.txt',
            r'plugins/([^/]+)/style\.css',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            plugins.update(matches)

        # فحص plugins شائعة عبر readme.txt
        common_plugins = list(self.db.wp_plugins.keys()) + [
            "contact-form-7", "yoast-seo", "elementor", "woocommerce",
            "wpforms-lite", "jetpack", "akismet", "all-in-one-seo-pack",
            "wordfence", "all-in-one-wp-security-and-firewall",
        ]

        base_url = url.rstrip("/")
        for plugin in common_plugins:
            if plugin in plugins:
                continue  # موجود بالفعل

            # محاولة قراءة readme.txt
            readme_url = f"{base_url}/wp-content/plugins/{plugin}/readme.txt"
            resp = self.client.get(readme_url)

            if resp["status"] == 200 and len(resp["body"]) > 50:
                plugins.add(plugin)

                # استخراج الإصدار
                version_match = re.search(r"Stable tag:\s*([\d.]+)", resp["body"])
                version = version_match.group(1) if version_match else None

                if version:
                    self._log(f"Plugin: {plugin} v{version}", "success")
                else:
                    self._log(f"Plugin: {plugin} (no version)", "success")

        # فحص كل plugin في قاعدة البيانات
        for plugin in plugins:
            # محاولة الحصول على الإصدار
            readme_url = f"{base_url}/wp-content/plugins/{plugin}/readme.txt"
            resp = self.client.get(readme_url)
            version = None
            if resp["status"] == 200:
                version_match = re.search(r"Stable tag:\s*([\d.]+)", resp["body"])
                version = version_match.group(1) if version_match else None

            # lookup في قاعدة البيانات
            vuln_info = self.db.lookup_wordpress_plugin(plugin, version)

            component_info = {
                "name": plugin,
                "version": version,
                "type": "wordpress_plugin",
                "found_in_db": vuln_info["found"],
                "is_outdated": vuln_info.get("is_outdated", False),
                "vulnerabilities": vuln_info.get("vulnerabilities", []),
            }

            self.components_found["wordpress_plugins"].append(component_info)

            # إضافة للثغرات لو موجودة
            if vuln_info.get("vulnerabilities"):
                for vuln in vuln_info["vulnerabilities"]:
                    self.vulnerabilities_found.append({
                        "type": "outdated_plugin",
                        "severity": vuln.get("severity", "medium"),
                        "component": plugin,
                        "version": version,
                        "title": vuln.get("title", ""),
                        "description": vuln.get("description", ""),
                        "cve": vuln.get("cve", ""),
                        "fix": vuln.get("fix", ""),
                        "url": url,
                    })

                    sev_color = {
                        "critical": Colors.RED + Colors.BOLD,
                        "high": Colors.RED,
                        "medium": Colors.YELLOW,
                        "low": Colors.BLUE,
                    }.get(vuln.get("severity", "medium"), Colors.NC)

                    self._log(
                        f"ثغرة في {plugin}: {vuln.get('title', '')} "
                        f"({vuln.get('severity', 'medium')})",
                        "warn"
                    )

    def _detect_wp_themes(self, url: str, html: str):
        """كشف WordPress themes"""
        self._log("كشف WordPress themes...", "info")

        themes = set()

        patterns = [
            r'wp-content/themes/([^/]+)/',
            r'themes/([^/]+)/style\.css',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            themes.update(matches)

        base_url = url.rstrip("/")
        for theme in themes:
            # محاولة قراءة style.css
            style_url = f"{base_url}/wp-content/themes/{theme}/style.css"
            resp = self.client.get(style_url)

            version = None
            if resp["status"] == 200:
                version_match = re.search(r"Version:\s*([\d.]+)", resp["body"])
                version = version_match.group(1) if version_match else None

            # lookup
            vuln_info = self.db.lookup_wordpress_theme(theme, version)

            component_info = {
                "name": theme,
                "version": version,
                "type": "wordpress_theme",
                "found_in_db": vuln_info["found"],
                "is_outdated": vuln_info.get("is_outdated", False),
                "vulnerabilities": vuln_info.get("vulnerabilities", []),
            }

            self.components_found["wordpress_themes"].append(component_info)

            if vuln_info.get("vulnerabilities"):
                for vuln in vuln_info["vulnerabilities"]:
                    self.vulnerabilities_found.append({
                        "type": "outdated_theme",
                        "severity": vuln.get("severity", "medium"),
                        "component": theme,
                        "version": version,
                        "title": vuln.get("title", ""),
                        "description": vuln.get("description", ""),
                        "cve": vuln.get("cve", ""),
                        "fix": vuln.get("fix", ""),
                        "url": url,
                    })

                    self._log(
                        f"ثغرة في theme {theme}: {vuln.get('title', '')}",
                        "warn"
                    )

            if version:
                self._log(f"Theme: {theme} v{version}", "success")
            else:
                self._log(f"Theme: {theme}", "success")

    def _check_sensitive_paths(self, url: str):
        """فحص المسارات الحساسة"""
        self._log("فحص المسارات الحساسة...", "info")

        base_url = url.rstrip("/")

        # فحص كل path في قاعدة البيانات
        for path in self.db.path_vulns.keys():
            test_url = base_url + path
            resp = self.client.get(test_url)

            if resp["status"] == 200:
                # تأكد إنها مش صفحة 404 مخصصة
                if "404" not in resp["body"][:200] and len(resp["body"]) > 50:
                    vuln_info = self.db.lookup_path(path)

                    self.components_found["paths"].append({
                        "path": path,
                        "url": test_url,
                        "status": resp["status"],
                        "vulnerable": True,
                        "info": vuln_info,
                    })

                    if vuln_info:
                        self.vulnerabilities_found.append({
                            "type": vuln_info.get("type", "sensitive_path"),
                            "severity": vuln_info.get("severity", "medium"),
                            "path": path,
                            "url": test_url,
                            "title": vuln_info.get("title", ""),
                            "description": vuln_info.get("description", ""),
                            "fix": vuln_info.get("fix", ""),
                        })

                        sev = vuln_info.get("severity", "medium")
                        self._log(
                            f"Path خطر: {path} ({vuln_info.get('title', '')})",
                            "warn"
                        )

    def _detect_tech_stack(self, html: str, headers: Dict):
        """كشف tech stack"""
        self._log("كشف tech stack...", "info")

        content = html + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        content_lower = content.lower()

        tech_indicators = {
            "WordPress": ["wp-content", "wp-includes", "wp-json"],
            "Drupal": ["drupal.js", "sites/default"],
            "Joomla": ["/components/com_", "joomla"],
            "Magento": ["skin/frontend", "magento"],
            "Shopify": ["cdn.shopify.com"],
            "React": ["react.production", "__react_devtools", "data-reactroot"],
            "Vue.js": ["vue.runtime", "data-v-"],
            "Angular": ["ng-version", "ng-app"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap.min"],
            "Tailwind": ["tailwind"],
            "Express.js": ["x-powered-by: express"],
            "Django": ["csrfmiddlewaretoken"],
            "Flask": ["x-powered-by: werkzeug"],
            "Laravel": ["laravel_session", "xsrftoken"],
            "Rails": ["csrf-param.*authenticity_token", "x-runtime"],
            "ASP.NET": ["__viewstate", "aspxauth"],
            "PHP": ["x-powered-by: php", "phpsessid"],
            "Node.js": ["x-powered-by: node"],
            "Nginx": ["server: nginx"],
            "Apache": ["server: apache"],
            "IIS": ["server: microsoft-iis"],
            "Cloudflare": ["server: cloudflare", "cf-ray"],
        }

        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content_lower:
                    self.components_found["tech_stack"].append(tech)
                    self._log(f"Tech: {tech}", "success")
                    break

    def _build_summary(self) -> Dict:
        """بناء ملخص"""
        return {
            "total_components": (
                len(self.components_found["wordpress_plugins"]) +
                len(self.components_found["wordpress_themes"]) +
                len(self.components_found["paths"]) +
                len(self.components_found["tech_stack"])
            ),
            "total_vulnerabilities": len(self.vulnerabilities_found),
            "outdated_components": sum(
                1 for c in self.components_found["wordpress_plugins"] +
                           self.components_found["wordpress_themes"]
                if c.get("is_outdated")
            ),
            "vulnerable_paths": sum(
                1 for p in self.components_found["paths"] if p.get("vulnerable")
            ),
        }

    def print_report(self, result: Dict):
        """عرض تقرير"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔍 Component Analysis Report{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        components = result["components"]
        vulns = result["vulnerabilities"]
        summary = result["summary"]

        # Summary
        print(f"\n  {Colors.BOLD}📊 Summary:{Colors.NC}")
        print(f"    Total components: {summary['total_components']}")
        print(f"    Total vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"    Outdated components: {summary['outdated_components']}")
        print(f"    Vulnerable paths: {summary['vulnerable_paths']}")

        # WordPress Plugins
        if components["wordpress_plugins"]:
            print(f"\n  {Colors.BOLD}🔌 WordPress Plugins ({len(components['wordpress_plugins'])}):{Colors.NC}")
            for plugin in components["wordpress_plugins"]:
                version_str = f" v{plugin['version']}" if plugin["version"] else ""
                outdated = " ⚠️ OUTDATED" if plugin.get("is_outdated") else ""
                vuln_count = len(plugin.get("vulnerabilities", []))
                vuln_str = f" ({vuln_count} vulns)" if vuln_count > 0 else " ✓"

                color = Colors.RED if plugin.get("is_outdated") else Colors.GREEN
                print(f"    {color}•{Colors.NC} {plugin['name']}{version_str}{outdated}{vuln_str}")

        # WordPress Themes
        if components["wordpress_themes"]:
            print(f"\n  {Colors.BOLD}🎨 WordPress Themes ({len(components['wordpress_themes'])}):{Colors.NC}")
            for theme in components["wordpress_themes"]:
                version_str = f" v{theme['version']}" if theme["version"] else ""
                outdated = " ⚠️ OUTDATED" if theme.get("is_outdated") else ""
                vuln_count = len(theme.get("vulnerabilities", []))
                vuln_str = f" ({vuln_count} vulns)" if vuln_count > 0 else " ✓"

                color = Colors.RED if theme.get("is_outdated") else Colors.GREEN
                print(f"    {color}•{Colors.NC} {theme['name']}{version_str}{outdated}{vuln_str}")

        # Vulnerable Paths
        if components["paths"]:
            print(f"\n  {Colors.BOLD}📂 Vulnerable Paths ({len(components['paths'])}):{Colors.NC}")
            for path_info in components["paths"]:
                info = path_info.get("info", {})
                sev = info.get("severity", "medium")
                color = {
                    "critical": Colors.RED + Colors.BOLD,
                    "high": Colors.RED,
                    "medium": Colors.YELLOW,
                    "low": Colors.BLUE,
                }.get(sev, Colors.NC)

                print(f"    {color}[{sev}]{Colors.NC} {path_info['path']}")
                if info.get("title"):
                    print(f"          {fix_display(info['title'])}")

        # Tech Stack
        if components["tech_stack"]:
            print(f"\n  {Colors.BOLD}🛠️  Tech Stack:{Colors.NC}")
            for tech in components["tech_stack"]:
                print(f"    {Colors.GREEN}•{Colors.NC} {tech}")

        # Vulnerabilities Details
        if vulns:
            print(f"\n  {Colors.RED + Colors.BOLD}🚨 Vulnerabilities Found:{Colors.NC}")
            for vuln in vulns:
                sev = vuln.get("severity", "medium")
                color = {
                    "critical": Colors.RED + Colors.BOLD,
                    "high": Colors.RED,
                    "medium": Colors.YELLOW,
                    "low": Colors.BLUE,
                }.get(sev, Colors.NC)

                print(f"\n    {color}[{sev.upper()}]{Colors.NC} {vuln.get('title', 'Unknown')}")
                if vuln.get("component"):
                    print(f"      Component: {vuln['component']}" +
                          (f" v{vuln['version']}" if vuln.get("version") else ""))
                if vuln.get("cve"):
                    print(f"      CVE: {vuln['cve']}")
                if vuln.get("description"):
                    print(f"      {fix_display(vuln['description'])}")
                if vuln.get("fix"):
                    print(f"      {Colors.GREEN}Fix:{Colors.NC} {fix_display(vuln['fix'])}")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Component Analyzer")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    client = HttpClient(timeout=15)
    analyzer = ComponentAnalyzer(client)
    result = analyzer.analyze(args.url)
    analyzer.print_report(result)
