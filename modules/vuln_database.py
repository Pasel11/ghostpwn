#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Vulnerability Database
قاعدة بيانات عالمية للثغرات - تحدد إذا كان القالب/الإضافة/المسار قديم أو به ثغرات

المصادر:
1. قاعدة بيانات محلية (built-in) لأشهر الثغرات
2. WordPress Plugin Vulnerabilities
3. Joomla Extensions
4. Drupal Modules
5. CVEs المعروفة
6. Path-based fingerprints
"""
import os
import sys
import json
import re
import time
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================ WordPress Plugin Vulnerabilities ============================
WORDPRESS_PLUGINS_DB = {
    # ===== Plugins شائعة مع ثغرات معروفة =====
    "contact-form-7": {
        "name": "Contact Form 7",
        "type": "form",
        "vulnerabilities": [
            {
                "version": "< 5.3.2",
                "severity": "high",
                "cve": "CVE-2020-35489",
                "title": "Unrestricted File Upload",
                "description": "يسمح برفع ملفات خبيثة",
                "fix": "حدّث إلى 5.3.2 أو أحدث",
            },
            {
                "version": "< 5.1.6",
                "severity": "medium",
                "cve": "CVE-2019-19985",
                "title": "XSS in contact form",
                "description": "ثغرة XSS مخزنة",
                "fix": "حدّث إلى 5.1.6 أو أحدث",
            },
        ],
    },
    "yoast-seo": {
        "name": "Yoast SEO",
        "type": "seo",
        "vulnerabilities": [
            {
                "version": "< 7.4.1",
                "severity": "high",
                "cve": "CVE-2018-1000272",
                "title": "SQL Injection",
                "description": "SQLi في meta description",
                "fix": "حدّث إلى 7.4.1 أو أحدث",
            },
        ],
    },
    "elementor": {
        "name": "Elementor Page Builder",
        "type": "builder",
        "vulnerabilities": [
            {
                "version": "< 2.7.3",
                "severity": "critical",
                "cve": "CVE-2019-15866",
                "title": "RCE via Elementor",
                "description": "تنفيذ أوامر عن بعد!",
                "fix": "حدّث إلى 2.7.3 أو أحدث",
            },
        ],
    },
    "woocommerce": {
        "name": "WooCommerce",
        "type": "ecommerce",
        "vulnerabilities": [
            {
                "version": "< 3.5.5",
                "severity": "high",
                "cve": "CVE-2019-6885",
                "title": "SQL Injection in REST API",
                "description": "SQLi في API",
                "fix": "حدّث إلى 3.5.5 أو أحدث",
            },
        ],
    },
    "wpforms-lite": {
        "name": "WPForms",
        "type": "form",
        "vulnerabilities": [
            {
                "version": "< 1.5.4",
                "severity": "medium",
                "cve": "CVE-2019-16200",
                "title": "XSS in forms",
                "description": "XSS مخزنة",
                "fix": "حدّث إلى 1.5.4 أو أحدث",
            },
        ],
    },
    "jetpack": {
        "name": "Jetpack by WordPress.com",
        "type": "utility",
        "vulnerabilities": [
            {
                "version": "< 7.3.1",
                "severity": "critical",
                "cve": "CVE-2018-15831",
                "title": "Authentication Bypass",
                "description": "تجاوز المصادقة!",
                "fix": "حدّث إلى 7.3.1 أو أحدث",
            },
        ],
    },
    "akismet": {
        "name": "Akismet Anti-Spam",
        "type": "security",
        "vulnerabilities": [
            {
                "version": "< 4.0.3",
                "severity": "medium",
                "cve": "CVE-2018-10719",
                "title": "SSRF",
                "description": "SSRF في فحص spam",
                "fix": "حدّث إلى 4.0.3 أو أحدث",
            },
        ],
    },
    "all-in-one-seo-pack": {
        "name": "All in One SEO Pack",
        "type": "seo",
        "vulnerabilities": [
            {
                "version": "< 2.10",
                "severity": "high",
                "cve": "CVE-2017-14821",
                "title": "SQL Injection",
                "description": "SQLi في meta",
                "fix": "حدّث إلى 2.10 أو أحدث",
            },
        ],
    },
    "google-analytics-for-wordpress": {
        "name": "Google Analytics for WordPress",
        "type": "analytics",
        "vulnerabilities": [
            {
                "version": "< 5.4.5",
                "severity": "medium",
                "cve": "CVE-2017-16808",
                "title": "XSS",
                "description": "XSS في settings",
                "fix": "حدّث إلى 5.4.5 أو أحدث",
            },
        ],
    },
    "wpdiscuz": {
        "name": "wpDiscuz",
        "type": "comments",
        "vulnerabilities": [
            {
                "version": "< 7.0.4",
                "severity": "critical",
                "cve": "CVE-2020-35934",
                "title": "Arbitrary File Upload",
                "description": "رفع أي ملف!",
                "fix": "حدّث إلى 7.0.4 أو أحدث",
            },
        ],
    },
    "duplicator": {
        "name": "Duplicator",
        "type": "backup",
        "vulnerabilities": [
            {
                "version": "< 1.2.40",
                "severity": "critical",
                "cve": "CVE-2018-17254",
                "title": "Arbitrary File Read",
                "description": "قراءة أي ملف على السيرفر",
                "fix": "حدّث إلى 1.2.40 أو أحدث",
            },
        ],
    },
    "wpbakery-page-builder": {
        "name": "WPBakery Page Builder",
        "type": "builder",
        "vulnerabilities": [
            {
                "version": "< 5.4.7",
                "severity": "high",
                "cve": "CVE-2018-19926",
                "title": "XSS",
                "description": "XSS في template",
                "fix": "حدّث إلى 5.4.7 أو أحدث",
            },
        ],
    },
    "revslider": {
        "name": "Slider Revolution (revslider)",
        "type": "slider",
        "vulnerabilities": [
            {
                "version": "< 4.2",
                "severity": "critical",
                "cve": "CVE-2014-4653",
                "title": "Arbitrary File Download",
                "description": "تحميل أي ملف من السيرفر!",
                "fix": "حدّث إلى 4.2 أو أحدث",
            },
        ],
    },
}


# ============================ WordPress Themes DB ============================
WORDPRESS_THEMES_DB = {
    "avada": {
        "name": "Avada",
        "vulnerabilities": [
            {
                "version": "< 5.1.6",
                "severity": "high",
                "cve": "CVE-2018-14054",
                "title": "XSS",
                "description": "XSS في search",
                "fix": "حدّث إلى 5.1.6 أو أحدث",
            },
        ],
    },
    "enfold": {
        "name": "Enfold",
        "vulnerabilities": [
            {
                "version": "< 4.5.7",
                "severity": "medium",
                "cve": "CVE-2018-18717",
                "title": "XSS",
                "description": "XSS في search",
                "fix": "حدّث إلى 4.5.7 أو أحدث",
            },
        ],
    },
    "divi": {
        "name": "Divi",
        "vulnerabilities": [
            {
                "version": "< 3.18",
                "severity": "high",
                "cve": "CVE-2018-18943",
                "title": "XSS",
                "description": "XSS في search",
                "fix": "حدّث إلى 3.18 أو أحدث",
            },
        ],
    },
}


# ============================ Path-based Vulnerabilities ============================
PATH_VULNERABILITIES = {
    "/wp-config.php.bak": {
        "severity": "critical",
        "type": "sensitive_file",
        "title": "WordPress config backup exposed",
        "description": "ملف config backup مكشوف - يحتوي على DB credentials",
        "fix": "احذف ملف الـ backup فوراً",
    },
    "/wp-config.php~": {
        "severity": "critical",
        "type": "sensitive_file",
        "title": "WordPress config editor backup",
        "description": "ملف config backup من محرر النصوص",
        "fix": "احذف الملف فوراً",
    },
    "/.env": {
        "severity": "critical",
        "type": "sensitive_file",
        "title": ".env file exposed",
        "description": "ملف .env مكشوف - يحتوي على secrets و API keys",
        "fix": "احذف أو احمِ ملف .env",
    },
    "/.git/config": {
        "severity": "critical",
        "type": "git_exposure",
        "title": "Git repository exposed",
        "description": "مجلد .git مكشوف - يمكن تحميل source code كامل",
        "fix": "احذف مجلد .git من webroot",
    },
    "/xmlrpc.php": {
        "severity": "medium",
        "type": "info_disclosure",
        "title": "XML-RPC enabled",
        "description": "XML-RPC مفعّل - يمكن استخدامه لـ brute force",
        "fix": "عطّل XML-RPC لو غير ضروري",
    },
    "/wp-json/wp/v2/users": {
        "severity": "medium",
        "type": "user_enum",
        "title": "User enumeration via REST API",
        "description": "يمكن استخراج قائمة المستخدمين",
        "fix": "عطّل REST API أو قيّده",
    },
    "/readme.html": {
        "severity": "low",
        "type": "info_disclosure",
        "title": "WordPress readme exposed",
        "description": "يكشف إصدار WordPress",
        "fix": "احذف readme.html",
    },
    "/license.txt": {
        "severity": "low",
        "type": "info_disclosure",
        "title": "WordPress license file",
        "description": "يكشف إصدار WordPress",
        "fix": "احذف license.txt",
    },
    "/wp-content/debug.log": {
        "severity": "high",
        "type": "info_disclosure",
        "title": "Debug log exposed",
        "description": "ملف debug log مكشوف - قد يحتوي على معلومات حساسة",
        "fix": "عطّل WP_DEBUG أو احمِ الملف",
    },
    "/phpinfo.php": {
        "severity": "high",
        "type": "info_disclosure",
        "title": "phpinfo() exposed",
        "description": "صفحة phpinfo مكشوفة - تكشف معلومات السيرفر",
        "fix": "احذف phpinfo.php",
    },
    "/server-status": {
        "severity": "high",
        "type": "info_disclosure",
        "title": "Apache server-status exposed",
        "description": "حالة السيرفر مكشوفة",
        "fix": "قيّد الوصول لـ server-status",
    },
    "/actuator/env": {
        "severity": "critical",
        "type": "info_disclosure",
        "title": "Spring Boot Actuator exposed",
        "description": "actuator/env مكشوف - يكشف secrets",
        "fix": "عطّل أو قيّد actuator endpoints",
    },
    "/swagger-ui": {
        "severity": "medium",
        "type": "info_disclosure",
        "title": "Swagger UI exposed",
        "description": "API documentation مكشوفة",
        "fix": "قيّد الوصول لـ swagger",
    },
    "/graphql": {
        "severity": "medium",
        "type": "info_disclosure",
        "title": "GraphQL endpoint exposed",
        "description": "GraphQL endpoint مكشوف",
        "fix": "قيّد الوصول لـ GraphQL",
    },
}


# ============================ CVE Database (Sample) ============================
CVE_DATABASE = {
    "CVE-2017-5638": {
        "title": "Apache Struts 2 RCE",
        "product": "Apache Struts",
        "versions": "2.3.5 - 2.3.32, 2.5 - 2.5.10.1",
        "severity": "critical",
        "description": "RCE عبر Content-Type header",
        "exploit": True,
    },
    "CVE-2014-6271": {
        "title": "Shellshock (Bash RCE)",
        "product": "GNU Bash",
        "versions": "1.14 - 4.3",
        "severity": "critical",
        "description": "RCE عبر environment variables",
        "exploit": True,
    },
    "CVE-2017-0144": {
        "title": "EternalBlue (MS17-010)",
        "product": "Microsoft Windows SMB",
        "versions": "Windows XP - 2016",
        "severity": "critical",
        "description": "RCE عبر SMB",
        "exploit": True,
    },
    "CVE-2019-0708": {
        "title": "BlueKeep",
        "product": "Microsoft Windows RDP",
        "versions": "Windows XP, 7, Server 2003, 2008",
        "severity": "critical",
        "description": "RCE عبر RDP",
        "exploit": True,
    },
    "CVE-2020-0796": {
        "title": "SMBGhost",
        "product": "Microsoft Windows SMBv3",
        "versions": "Windows 10, Server 2019",
        "severity": "critical",
        "description": "RCE عبر SMBv3",
        "exploit": True,
    },
    "CVE-2017-12617": {
        "title": "Apache Tomcat RCE",
        "product": "Apache Tomcat",
        "versions": "9.0.0.M1 - 9.0.3, 8.5.0 - 8.5.23, 8.0.0.RC1 - 8.0.47",
        "severity": "high",
        "description": "RCE عبر PUT method",
        "exploit": True,
    },
    "CVE-2018-11776": {
        "title": "Apache Struts 2 RCE (namespace)",
        "product": "Apache Struts",
        "versions": "2.0.4 - 2.5.16",
        "severity": "critical",
        "description": "RCE عبر namespace OGNL",
        "exploit": True,
    },
    "CVE-2019-0232": {
        "title": "Apache Tomcat CGI RCE",
        "product": "Apache Tomcat",
        "versions": "9.0.0.M1 - 9.0.17, 8.5.0 - 8.5.39, 7.0.0 - 7.0.93",
        "severity": "high",
        "description": "RCE عبر CGI",
        "exploit": True,
    },
}


# ============================ Version Comparison ============================
def parse_version(version_str: str) -> Tuple:
    """تحويل string إلى tuple للأ比較"""
    if not version_str:
        return (0,)
    parts = re.findall(r'\d+', version_str)
    return tuple(int(p) for p in parts)


def compare_versions(v1: str, v2: str) -> int:
    """مقارنة إصدارين. يرجع -1, 0, 1"""
    p1 = parse_version(v1)
    p2 = parse_version(v2)

    # تطويل الأقصر
    while len(p1) < len(p2):
        p1 = p1 + (0,)
    while len(p2) < len(p1):
        p2 = p2 + (0,)

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    else:
        return 0


def check_version_vulnerable(version: str, vulnerable_range: str) -> bool:
    """فحص إذا كان الإصدار مصاب"""
    # vulnerable_range مثل: "< 5.3.2" أو ">= 2.0, < 3.0"
    if not version:
        return False

    # فحص patterns
    patterns = [
        (r'<\s*([\d.]+)', lambda v, r: compare_versions(v, r) < 0),
        (r'<=\s*([\d.]+)', lambda v, r: compare_versions(v, r) <= 0),
        (r'>\s*([\d.]+)', lambda v, r: compare_versions(v, r) > 0),
        (r'>=\s*([\d.]+)', lambda v, r: compare_versions(v, r) >= 0),
        (r'=\s*([\d.]+)', lambda v, r: compare_versions(v, r) == 0),
    ]

    # تقسيم على فاصلة (للـ ranges)
    ranges = [r.strip() for r in vulnerable_range.split(",")]

    for range_part in ranges:
        matched = False
        for pattern, check_func in patterns:
            match = re.search(pattern, range_part)
            if match:
                threshold = match.group(1)
                if check_func(version, threshold):
                    matched = True
                    break
        if not matched:
            return False

    return True


# ============================ Vulnerability Database ============================
class VulnerabilityDatabase:
    """قاعدة بيانات الثغرات"""

    def __init__(self, audit_logger=None):
        self.audit = audit_logger

        # تحميل القاعدة المحلية
        self.wp_plugins = WORDPRESS_PLUGINS_DB
        self.wp_themes = WORDPRESS_THEMES_DB
        self.path_vulns = PATH_VULNERABILITIES
        self.cve_db = CVE_DATABASE

        # cache للـ online lookups
        self.online_cache = {}

    def lookup_wordpress_plugin(self, plugin_name: str, version: str = None) -> Dict:
        """فحص plugin في القاعدة"""
        result = {
            "found": False,
            "name": plugin_name,
            "version": version,
            "vulnerabilities": [],
            "is_outdated": False,
            "latest_known_version": None,
        }

        # فحص في القاعدة المحلية
        plugin_lower = plugin_name.lower()
        for db_name, db_data in self.wp_plugins.items():
            if db_name.lower() == plugin_lower:
                result["found"] = True
                result["name"] = db_data["name"]

                # فحص كل ثغرة
                for vuln in db_data["vulnerabilities"]:
                    if version:
                        if check_version_vulnerable(version, vuln["version"]):
                            result["vulnerabilities"].append(vuln)
                            result["is_outdated"] = True
                    else:
                        # لو مفيش version، نعتبر كل الثغرات محتملة
                        result["vulnerabilities"].append(vuln)
                        result["is_outdated"] = True

                break

        # محاولة online lookup (wpvulndb)
        if not result["found"]:
            online_result = self._online_lookup_plugin(plugin_name, version)
            if online_result:
                result.update(online_result)

        return result

    def lookup_wordpress_theme(self, theme_name: str, version: str = None) -> Dict:
        """فحص theme في القاعدة"""
        result = {
            "found": False,
            "name": theme_name,
            "version": version,
            "vulnerabilities": [],
            "is_outdated": False,
        }

        theme_lower = theme_name.lower()
        for db_name, db_data in self.wp_themes.items():
            if db_name.lower() == theme_lower:
                result["found"] = True
                result["name"] = db_data["name"]

                for vuln in db_data["vulnerabilities"]:
                    if version:
                        if check_version_vulnerable(version, vuln["version"]):
                            result["vulnerabilities"].append(vuln)
                            result["is_outdated"] = True
                    else:
                        result["vulnerabilities"].append(vuln)
                        result["is_outdated"] = True

                break

        return result

    def lookup_path(self, path: str) -> Optional[Dict]:
        """فحص مسار في القاعدة"""
        path_lower = path.lower()

        for db_path, vuln_data in self.path_vulns.items():
            if db_path.lower() == path_lower:
                return vuln_data

        # fuzzy matching
        for db_path, vuln_data in self.path_vulns.items():
            if db_path.lower() in path_lower or path_lower in db_path.lower():
                return vuln_data

        return None

    def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """فحص CVE في القاعدة"""
        cve_id = cve_id.upper()
        if cve_id in self.cve_db:
            return self.cve_db[cve_id]
        return None

    def _online_lookup_plugin(self, plugin_name: str, version: str = None) -> Optional[Dict]:
        """محاولة online lookup (wpvulndb API)"""
        try:
            # ملاحظة: wpvulndb API يتطلب auth الآن، نستخدم API بديل
            # نحاول GitHub advisory database
            url = f"https://api.github.com/advisories?ecosystem=npm&type:reviewed&keyword={plugin_name}"

            req = urllib.request.Request(url, headers={
                "User-Agent": "ghostpwn-vuln-checker",
                "Accept": "application/vnd.github.v3+json",
            })

            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

                if data and len(data) > 0:
                    vulns = []
                    for advisory in data[:5]:  # أول 5 نتائج
                        vulns.append({
                            "version": advisory.get("vulnerable_version_range", "unknown"),
                            "severity": advisory.get("severity", "medium").lower(),
                            "cve": advisory.get("cve_id", ""),
                            "title": advisory.get("summary", "Unknown")[:100],
                            "description": advisory.get("description", "")[:200],
                            "fix": advisory.get("patched_versions", "Update to latest"),
                        })

                    return {
                        "found": True,
                        "name": plugin_name,
                        "version": version,
                        "vulnerabilities": vulns,
                        "is_outdated": len(vulns) > 0,
                        "source": "github-advisory",
                    }

        except Exception:
            pass

        return None

    def get_stats(self) -> Dict:
        """إحصائيات قاعدة البيانات"""
        return {
            "wp_plugins_tracked": len(self.wp_plugins),
            "wp_themes_tracked": len(self.wp_themes),
            "path_vulnerabilities": len(self.path_vulns),
            "cves_tracked": len(self.cve_db),
        }


# ============================ Test ============================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Vulnerability Database")
    parser.add_argument("--plugin", help="WordPress plugin to check")
    parser.add_argument("--theme", help="WordPress theme to check")
    parser.add_argument("--path", help="Path to check")
    parser.add_argument("--cve", help="CVE ID to lookup")
    parser.add_argument("--version", help="Version to check against")
    parser.add_argument("--stats", action="store_true", help="Show database stats")
    args = parser.parse_args()

    db = VulnerabilityDatabase()

    if args.stats:
        print(f"\nDatabase Stats: {db.get_stats()}")
    elif args.plugin:
        result = db.lookup_wordpress_plugin(args.plugin, args.version)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.theme:
        result = db.lookup_wordpress_theme(args.theme, args.version)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.path:
        result = db.lookup_path(args.path)
        print(json.dumps(result, indent=2, ensure_ascii=False) if result else "Not found")
    elif args.cve:
        result = db.lookup_cve(args.cve)
        print(json.dumps(result, indent=2, ensure_ascii=False) if result else "Not found")
    else:
        parser.print_help()
