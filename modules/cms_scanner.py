#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - CMS Scanner
كشف وفحص أنظمة إدارة المحتوى (WordPress, Joomla, Drupal)
"""
import sys
import os
import re
import urllib.parse
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient


class CMSScanner:
    """كشف وفحص CMS"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger

    def log(self, msg, level="info"):
        icons = {"info": "[*]", "success": "[✓]", "warn": "[!]", "error": "[✗]"}
        print(f"    {icons.get(level, '[*]')} {msg}")
        if self.audit:
            self.audit.log_event(msg, level)

    def detect_cms(self, url: str) -> Optional[str]:
        """كشف نوع الـ CMS"""
        resp = self.client.get(url)
        body = resp["body"]
        headers = resp["headers"]

        # WordPress
        wp_indicators = [
            "wp-content", "wp-includes", "wp-json", "/wp-admin",
            'name="generator" content="WordPress',
            "wp-login.php", "xmlrpc.php",
        ]
        for indicator in wp_indicators:
            if indicator in body:
                return "wordpress"

        # Drupal
        drupal_indicators = [
            "drupal.js", "sites/default", "Drupal.settings",
            'name="Generator" content="Drupal',
            "misc/drupal.js", "/core/misc/drupal.js",
        ]
        for indicator in drupal_indicators:
            if indicator in body:
                return "drupal"

        # Joomla
        joomla_indicators = [
            "/components/com_", "/media/system/js/",
            'name="generator" content="Joomla',
            "joomla!", "Joomla",
        ]
        for indicator in joomla_indicators:
            if indicator in body:
                return "joomla"

        # Magento
        magento_indicators = [
            "skin/frontend", "js/mage", "Magento",
            "/skin/frontend/default/",
        ]
        for indicator in magento_indicators:
            if indicator in body:
                return "magento"

        # Shopify
        if "cdn.shopify.com" in body or "shopify.com" in body:
            return "shopify"

        return None

    def scan(self, url: str) -> Dict:
        """فحص شامل للـ CMS"""
        result = {
            "url": url,
            "cms": None,
            "version": None,
            "plugins": [],
            "themes": [],
            "users": [],
            "vulnerabilities": [],
            "sensitive_files": [],
        }

        # 1) كشف الـ CMS
        self.log("Detecting CMS...", "info")
        cms = self.detect_cms(url)
        if not cms:
            self.log("No known CMS detected", "warn")
            return result

        result["cms"] = cms
        self.log(f"CMS detected: {cms}", "success")

        # 2) فحص حسب نوع الـ CMS
        if cms == "wordpress":
            wp_data = self._scan_wordpress(url)
            result.update(wp_data)
        elif cms == "drupal":
            drupal_data = self._scan_drupal(url)
            result.update(drupal_data)
        elif cms == "joomla":
            joomla_data = self._scan_joomla(url)
            result.update(joomla_data)
        elif cms == "magento":
            magento_data = self._scan_magento(url)
            result.update(magento_data)

        return result

    # ============================ WordPress Scanner ============================
    def _scan_wordpress(self, url: str) -> Dict:
        """فحص WordPress شامل"""
        result = {
            "version": None,
            "plugins": [],
            "themes": [],
            "users": [],
            "vulnerabilities": [],
            "sensitive_files": [],
        }

        self.log("Scanning WordPress...", "info")

        # 1) إصدار WordPress
        resp = self.client.get(url)
        version_match = re.search(r'content="WordPress ([\d.]+)"', resp["body"])
        if version_match:
            result["version"] = version_match.group(1)
            self.log(f"WordPress version: {result['version']}", "success")

        # 2) ملفات حساسة
        wp_sensitive_files = [
            "/wp-config.php", "/wp-config.bak", "/wp-config.txt",
            "/xmlrpc.php", "/wp-json/", "/wp-json/wp/v2/users",
            "/?author=1", "/?author=2", "/?author=3",
            "/wp-admin/", "/wp-login.php",
            "/wp-content/uploads/", "/wp-content/debug.log",
            "/readme.html", "/license.txt",
            "/wp-content/backup-db/",
            "/wp-content/uploads/wpallimport/",
            "/wp-content/plugins/", "/wp-content/themes/",
        ]

        self.log("Checking sensitive files...", "info")
        for file_path in wp_sensitive_files:
            file_url = url.rstrip("/") + file_path
            resp = self.client.get(file_url)
            if resp["status"] in (200, 301, 302, 401, 403):
                if resp["status"] == 200:
                    result["sensitive_files"].append({
                        "file": file_path,
                        "status": resp["status"],
                        "accessible": True,
                    })
                    self.log(f"Exposed: {file_path} [{resp['status']}]", "warn")

        # 3) كشف الـ plugins
        self.log("Detecting plugins...", "info")
        plugins = set()
        plugin_patterns = [
            r'wp-content/plugins/([^/]+)',
            r'plugins/([^/]+)/',
        ]
        for pattern in plugin_patterns:
            matches = re.findall(pattern, resp["body"])
            plugins.update(matches)

        # فحص plugins شائعة
        common_plugins = [
            "akismet", "contact-form-7", "yoast-seo", "jetpack",
            "elementor", "woocommerce", "wordfence", "all-in-one-seo-pack",
            "google-analytics-for-wordpress", "wpforms-lite",
        ]
        for plugin in common_plugins:
            plugin_url = url.rstrip("/") + f"/wp-content/plugins/{plugin}/readme.txt"
            resp = self.client.get(plugin_url)
            if resp["status"] == 200:
                plugins.add(plugin)
                # استخراج إصدار الـ plugin
                version_match = re.search(r"Stable tag:\s*([\d.]+)", resp["body"])
                plugin_info = {"name": plugin}
                if version_match:
                    plugin_info["version"] = version_match.group(1)
                    self.log(f"Plugin: {plugin} v{version_match.group(1)}", "success")
                else:
                    self.log(f"Plugin: {plugin} (no version)", "success")
                result["plugins"].append(plugin_info)

        # إضافة plugins من HTML
        for plugin in plugins:
            if not any(p["name"] == plugin for p in result["plugins"]):
                result["plugins"].append({"name": plugin})

        # 4) كشف الـ themes
        self.log("Detecting themes...", "info")
        theme_patterns = [
            r'wp-content/themes/([^/]+)',
            r'themes/([^/]+)/',
        ]
        themes = set()
        for pattern in theme_patterns:
            matches = re.findall(pattern, resp["body"])
            themes.update(matches)

        result["themes"] = list(themes)
        for theme in themes:
            self.log(f"Theme: {theme}", "info")

        # 5) استخراج users (user enumeration)
        self.log("Enumerating users...", "info")
        # عبر wp-json
        users_resp = self.client.get(url.rstrip("/") + "/wp-json/wp/v2/users")
        if users_resp["status"] == 200:
            try:
                import json
                users_data = json.loads(users_resp["body"])
                for user in users_data:
                    result["users"].append({
                        "id": user.get("id"),
                        "name": user.get("name"),
                        "slug": user.get("slug"),
                    })
                    self.log(f"User: {user.get('name')} (ID: {user.get('id')})", "success")
            except Exception:
                pass

        # عبر ?author=N
        for i in range(1, 6):
            author_url = url.rstrip("/") + f"/?author={i}"
            old_redirects = self.client.allow_redirects
            self.client.allow_redirects = False
            resp = self.client.get(author_url)
            self.client.allow_redirects = old_redirects

            if resp["status"] in (301, 302):
                location = resp["headers"].get("Location", "")
                user_match = re.search(r'/author/([^/]+)/', location)
                if user_match:
                    username = user_match.group(1)
                    if not any(u.get("slug") == username for u in result["users"]):
                        result["users"].append({
                            "id": i,
                            "slug": username,
                            "name": username,
                        })
                        self.log(f"User: {username} (ID: {i})", "success")

        # 6) فحص ثغرات شائعة
        if result["version"]:
            self.log(f"Checking version vulnerabilities...", "info")
            # WordPress < 5.0.1 - CVE-2018-20148
            if self._compare_versions(result["version"], "5.0.1") < 0:
                result["vulnerabilities"].append({
                    "type": "wp_old_version",
                    "severity": "high",
                    "description": f"WordPress {result['version']} is outdated (CVE-2018-20148+)",
                })
                self.log(f"Outdated WordPress: {result['version']}", "warn")

        # xmlrpc.php enabled = brute force possible
        xmlrpc_url = url.rstrip("/") + "/xmlrpc.php"
        resp = self.client.post(xmlrpc_url, data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>",
                               headers={"Content-Type": "text/xml"})
        if resp["status"] == 200 and "methodResponse" in resp["body"]:
            result["vulnerabilities"].append({
                "type": "wp_xmlrpc_enabled",
                "severity": "medium",
                "description": "XML-RPC enabled (brute force amplification possible)",
            })
            self.log("XML-RPC enabled (brute force possible)", "warn")

        return result

    # ============================ Drupal Scanner ============================
    def _scan_drupal(self, url: str) -> Dict:
        """فحص Drupal"""
        result = {
            "version": None,
            "modules": [],
            "themes": [],
            "vulnerabilities": [],
            "sensitive_files": [],
        }

        self.log("Scanning Drupal...", "info")

        # إصدار Drupal
        resp = self.client.get(url)
        version_match = re.search(r'Generator" content="Drupal ([\d.]+)', resp["body"])
        if version_match:
            result["version"] = version_match.group(1)
            self.log(f"Drupal version: {result['version']}", "success")

        # ملفات حساسة
        drupal_files = [
            "/CHANGELOG.txt", "/README.txt", "/core/CHANGELOG.txt",
            "/user/login", "/admin/", "/core/install.php",
            "/sites/default/settings.php",
        ]
        for file_path in drupal_files:
            file_url = url.rstrip("/") + file_path
            resp = self.client.get(file_url)
            if resp["status"] == 200:
                result["sensitive_files"].append({
                    "file": file_path,
                    "status": resp["status"],
                })
                self.log(f"Exposed: {file_path}", "warn")

                # استخراج إصدار من CHANGELOG.txt
                if "CHANGELOG" in file_path and not result["version"]:
                    version_match = re.search(r'Drupal ([\d.]+)', resp["body"])
                    if version_match:
                        result["version"] = version_match.group(1)
                        self.log(f"Drupal version (from CHANGELOG): {result['version']}", "success")

        return result

    # ============================ Joomla Scanner ============================
    def _scan_joomla(self, url: str) -> Dict:
        """فحص Joomla"""
        result = {
            "version": None,
            "components": [],
            "vulnerabilities": [],
            "sensitive_files": [],
        }

        self.log("Scanning Joomla...", "info")

        # إصدار Joomla
        resp = self.client.get(url)
        version_match = re.search(r'generator" content="Joomla! ([\d.]+)', resp["body"], re.I)
        if version_match:
            result["version"] = version_match.group(1)
            self.log(f"Joomla version: {result['version']}", "success")

        # ملفات حساسة
        joomla_files = [
            "/administrator/", "/README.txt", "/LICENSE.txt",
            "/configuration.php", "/components/", "/modules/",
            "/templates/", "/plugins/",
        ]
        for file_path in joomla_files:
            file_url = url.rstrip("/") + file_path
            resp = self.client.get(file_url)
            if resp["status"] == 200:
                result["sensitive_files"].append({
                    "file": file_path,
                    "status": resp["status"],
                })
                self.log(f"Exposed: {file_path}", "warn")

        return result

    # ============================ Magento Scanner ============================
    def _scan_magento(self, url: str) -> Dict:
        """فحص Magento"""
        result = {
            "version": None,
            "vulnerabilities": [],
            "sensitive_files": [],
        }

        self.log("Scanning Magento...", "info")

        # ملفات حساسة
        magento_files = [
            "/admin/", "/admin/admin/", "/downloader/",
            "/app/etc/local.xml", "/skin/frontend/",
            "/js/mage/", "/errors/",
        ]
        for file_path in magento_files:
            file_url = url.rstrip("/") + file_path
            resp = self.client.get(file_url)
            if resp["status"] == 200:
                result["sensitive_files"].append({
                    "file": file_path,
                    "status": resp["status"],
                })
                self.log(f"Exposed: {file_path}", "warn")

        return result

    # ============================ Helper ============================
    def _compare_versions(self, v1: str, v2: str) -> int:
        """مقارنة إصدارات (يرجع -1, 0, 1)"""
        v1_parts = [int(x) for x in v1.split(".")]
        v2_parts = [int(x) for x in v2.split(".")]

        # تطويل الأقصر
        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)

        for a, b in zip(v1_parts, v2_parts):
            if a < b:
                return -1
            elif a > b:
                return 1
        return 0
